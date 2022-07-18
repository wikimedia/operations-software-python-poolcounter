"""Poolcounter client implementation."""
import logging
import socket

from enum import Enum
from typing import Callable, Dict, Optional

from poolcounter.ring import HashRing


class PoolcounterError(Exception):
    """Custom exception class."""


class PoolcounterQueueError(PoolcounterError):
    """Special exception class if poolcounter has too many workers in queue."""


class PoolcounterTimeoutError(PoolcounterError):
    """Special exception class if poolcounter returns a timeout."""


class RequestType(Enum):
    """Represents the different request types."""

    RELEASE = 'RELEASE %s\n'
    LOCK_EXC = 'ACQ4ME %s %d %d %d\n'
    LOCK_ANY = 'ACQ4ANY %s %d %d %d\n'

    @classmethod
    def command(cls, action: 'RequestType', key: str,
                concurrency: int, max_queue: int, timeout: int) -> str:
        """Formats a command, and returns it as a string.

        For parameter definitions, see the Request object signature.
        """
        if action == cls.RELEASE:
            return action.value % key
        return action.value % (key, concurrency, max_queue, timeout)


class Request:
    """Encapsulates a poolcounter request."""

    MAX_QUEUE = 1000
    CONCURRENCY = 1
    TIMEOUT = 1
    # Actions
    RELEASE = 0
    LOCK_EXC = 1
    LOCK_ANY = 2
    FMTS = [
        'RELEASE %s\n',
        'ACQ4ME %s %d %d %d\n',
        'ACQ4ANY %s %d %d %d\n'
    ]

    def __init__(
            self,
            action: RequestType,
            key: str,
            concurrency: Optional[int] = None,
            max_queue: Optional[int] = None,
            timeout: Optional[int] = None):
        """Initialize a request object.

        Arguments:
            action (poolcounter.client.RequestType): the command to send
            key (str): the key for the lock
            concurrency (int): the maximum number of workers allowed to run at the same time
            max_queue (int): the maximum number of objects that can wait in queue
            timeout (int): the maximum time to wait to acquire the lock.

        Raises:
            ValueError if the action is not recognized

        """
        self.key = key
        if concurrency is None:
            concurrency = self.CONCURRENCY
        if max_queue is None:
            max_queue = self.MAX_QUEUE
        if timeout is None:
            timeout = self.TIMEOUT
        try:
            self.command = RequestType.command(action, key, concurrency, max_queue, timeout)
        except AttributeError as exc:
            raise ValueError('Invalid action code requested: {}'.format(action)) from exc

    def wire(self) -> bytes:
        """Return the wire format of the request.

        Returns:
            bytes: the raw command to send over the socket

        """
        return bytes(self.command, 'utf-8')


class Response:
    """Describes a poolcounter response."""

    # Poolcounter response messages.
    LOCKED = 'LOCKED'
    NOT_LOCKED = 'NOT_LOCKED'
    DONE = 'DONE'
    QUEUE_FULL = 'QUEUE_FULL'
    TIMEOUT = 'TIMEOUT'
    LOCK_HELD = 'LOCK_HELD'
    RELEASED = 'RELEASED'

    def __init__(self, key: str, msg: str):
        """Initialize a response.

        Arguments:
            key (str): the key we've requested a lock for
            msg (str): the response we got from the server

        Raises:
            PoolCounterError: if an error is encountered.

        """
        self.key = key
        self.msg = msg
        # Catch errors early
        if self.msg.startswith('ERROR '):
            raise PoolcounterError('Error talking to poolcounter: {}'.format(self.msg[6:]))
        if self.msg == Response.TIMEOUT:
            raise PoolcounterTimeoutError(
                'Too much time waiting for the lock for {}'.format(key))
        if self.msg == Response.QUEUE_FULL:
            raise PoolcounterQueueError(
                'Too many workers trying to acquire a lock for {}'.format(key))

    def status_is(self, status: str) -> bool:
        """Checks the status of the response corresponds to the expected one.

        Arguments:
           status (str): The expected status

        Returns:
           bool: wether the status matches or not.

        """
        return self.msg == status


class Server:
    """Object encapsulating a poolcounter backend connection."""

    connection_timeout = 1

    def __init__(self, fqdn: str, port: int = 7531,
                 weight: int = 1, label: Optional[str] = None) -> None:
        """Initialize the server.

        Arguments:
            fqdn (str): the fully qualified domain name or IP of the server
            port (int): The port to connect to. The default (7531) should be ok.
            weight (int): The weight of the server in the consistent hash ring
            label (str): The identifier of the node in the consistent hash ring.
                         Defaults to the fqdn if none is provided.

        """
        if label is None:
            label = fqdn
        self.label = label
        self.fqdn = fqdn
        # This raises an exception if the fqdn can't be resolved
        self.ipaddr = socket.gethostbyname(fqdn)
        self.port = port
        self.weight = weight
        self._stream = None  # type: Optional[socket.socket]
        self.has_lock = False

    def __str__(self) -> str:
        """String representation of the server.

        Returns:
            str: the string "server.label (server.ip:server.port)"

        """
        return '{label} ({ip}:{port})'.format(label=self.label, ip=self.ipaddr, port=self.port)

    def get_lock(self, lock_type: RequestType, key: str, **kwargs) -> Response:
        """Get a lock, either exclusive or shared.

        Arguments:
            lock_type (poolcounter.client.RequestType): lock type, either RequestType.LOCK_EXC
                                                        or RequestType.LOCK_ANY
            key (str): the poolcounter key
            **kwargs: additional arguments to build the Request object

        Returns:
           poolcounter.client.Response the response object

        Raises:
            PoolcounterError: if an error is encountered in the response, or if a lock is held

        """
        if self.has_lock:
            raise PoolcounterError('You cannot acquire a new lock while holding one.')
        req = Request(lock_type, key, **kwargs)
        resp = self._command(req)
        if resp.status_is(Response.LOCKED):
            # Got the lock
            self.has_lock = True
        elif resp.status_is(Response.DONE):
            # The lock was acquired and completed by another instance
            self.has_lock = False
        elif resp.status_is(Response.LOCK_HELD):
            # We own another lock, not this one.
            self.has_lock = True
            raise PoolcounterError('You cannot acquire a new lock while holding one.')
        return resp

    def lock_release(self, key: str) -> Response:
        """Releases a lock if previously acquired.

        Arguments:
            key (str): the lock key to release

        Returns:
            poolcounter.Response: the response object

        Raises:
            PoolcounterError: if no connection is found, or if the response contains an error

        """
        # We can't release a lock from an nonexistent connection
        if not self._stream:
            raise PoolcounterError('Trying to release a lock without a connection')
        req = Request(RequestType.RELEASE, key)
        resp = self._command(req)
        if (resp.status_is(Response.RELEASED)
           or resp.status_is(Response.NOT_LOCKED)):
            self.has_lock = False
        return resp

    def shutdown(self) -> None:
        """Shuts down the connection to the server."""
        if self._stream is not None:
            self._stream.close()
            self._stream = None
        self.has_lock = False

    def _command(self, req: Request) -> Response:
        if self._stream is None:
            self._stream = self._connect()

        try:
            self._stream.send(req.wire())
            return Response(req.key, self._stream.recv(4096).decode('utf-8').strip())
        except socket.error as e:
            self.shutdown()
            raise PoolcounterError('Error communicating with the server: {}'.format(e)) from e

    def _connect(self) -> socket.socket:
        """Connect to the server, return the connection socket."""
        try:
            stream = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            stream.settimeout(self.connection_timeout)
            stream.connect((self.ipaddr, self.port))
            stream.settimeout(None)
            return stream
        except ConnectionRefusedError as e:
            stream.close()
            raise PoolcounterError("Cannot connect to server {fqdn}:{port}".format(
                fqdn=self.fqdn, port=self.port)) from e
        except TimeoutError as e:
            stream.close()
            raise PoolcounterTimeoutError("Connection to {fqdn}:{port} timed out".format(
                fqdn=self.fqdn, port=self.port)) from e


class PoolcounterClient:
    """Class used to interact with the Poolcounter server."""

    lock_release_retry = 4  # Number of times we'll try to release a lock before giving up.

    def __init__(self, logger: logging.Logger) -> None:
        """Initiate the instance.

        Arguments:
          logger (logging.Logger): the logger to use for this client.

        """
        self.logger = logger
        self.backends: Dict[str, 'Server'] = {}
        self.ring = HashRing()

    def add_backend(self, server: Server) -> None:
        """Add a backend server.

        Arguments:
            server (poolcounter.client.Server): a Server instance to add to the pool.

        Raises:
            poolcounter.client.PoolcounterError: if the label is already present.
            ValueError: if a collision is found in the hash ring.

        """
        if server.label in self.backends:
            raise PoolcounterError(
                "A server with label '{label}' is already present."
                " Please call remove_backend() first".format(
                    label=server.label
                )
            )
        self.backends[server.label] = server
        self.ring.add_node(server.label, server.weight)

    def remove_backend(self, label: str) -> None:
        """Remove a backend from the pool.

        Arguments:
            label (str): The label the node was added with.

        Raises:
            poolcounter.client.PoolcounterError: if the label can't be found.

        """
        if label not in self.backends:
            raise PoolcounterError("No backend with label '{label}'".format(label=label))
        del self.backends[label]
        self.ring.del_node(label)

    def default_errback(self, err) -> bool:
        """Default callback for errors.

        Returns:
            bool: False

        """
        self.logger.exception("Error running command with poolcounter: %s", err)
        return False

    def run(self, lock_type: RequestType, key: str, callback: Callable,
            *args, errback: Optional[Callable] = None, **kwargs) -> bool:
        """Run a callable when a lock is acquired.

        Example:
        # Make a post to a remote endpoint, limiting concurrency
        def callback(msg, priority):
            requests.post('https://example.com/some/endpoint',
                          params={'msg': msg, 'retcode': priority})

        if client.run(RequestType.LOCK_EXC, 'example.com::sendMsg', callback, 'test', 1,
                      concurrency: 2, max_queue: 1000):
            print('Message sent!')


        Arguments:
            lock_type (poolcounter.client.RequestType): lock type, either RequestType.LOCK_EXC
                                                        or RequestType.LOCK_ANY
            key (str): poolcounter key to use
            callback (Callable): callable to execute (with *args) if the lock is acquired
            *args: arguments to pass to the callback
            errback (Callable): callable to execute if the lock cannot be acquired (with the error
                                as argument)
            concurrency (int): the maximum number of workers allowed to run at the same time
            max_queue (int): the maximum number of objects that can wait in queue
            timeout (int): the maximum time to wait to acquire the lock.

        Returns:
            bool: True upon successful exection

        Raises:
            PoolcounterError if there was an error releasing the lock

        """
        if errback is None:
            errback = self.default_errback
        backend = self.backend_for(key)
        try:
            backend.get_lock(lock_type, key, **kwargs)
            callback(*args)
        except PoolcounterError as e:
            return errback(e)
        except Exception as e:  # pylint: disable=broad-except
            # Error in the callable
            return self.default_errback(e)
        finally:
            # Try to clear the lock.
            for _ in range(self.lock_release_retry):
                try:
                    if not backend.has_lock:
                        break
                    backend.lock_release(key)
                except PoolcounterError as e:
                    self.logger.info("Error trying to release the lock: %s", e)
            if backend.has_lock:
                raise PoolcounterError('Lock for key {} not released'.format(key))
        return True

    def backend_for(self, key: str) -> Server:
        """Return the backend server object for the specified key.

        Arguments:
            key (str): the key we want the backend for.

        """
        try:
            label = self.ring.get_node(key)
            return self.backends[label]
        except (KeyError, ValueError) as e:
            raise PoolcounterError(
                'Please add backends calling add_backend() before trying to get a lock') from e
