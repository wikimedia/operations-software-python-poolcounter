"""Tests for the client-related classes"""
import logging
import socket

from unittest import mock

import pytest  # type: ignore

from poolcounter import client


class TestRequest:

    def test_request_release(self):
        """Test a lock release request."""
        r = client.Request(client.RequestType.RELEASE, 'test')
        assert r.command == 'RELEASE test\n'

    def test_request_lock_default(self):
        """Test a lock acq4me request with default parameters."""
        r = client.Request(client.RequestType.LOCK_EXC, 'test')
        assert r.command == 'ACQ4ME test 1 1000 1\n'

    def test_request_lock_params(self):
        """Test non-default params are correctly injected."""
        r = client.Request(
            client.RequestType.LOCK_ANY,
            'test',
            concurrency=5,
            max_queue=6,
            timeout=10
        )
        assert r.command == 'ACQ4ANY test 5 6 10\n'

    def test_request_bad_action(self):
        """Test a request with a non-defined action."""
        with pytest.raises(ValueError, match='Invalid action code'):
            client.Request(9, 'test')

    def test_wire(self):
        """Test the wire format."""
        r = client.Request(client.RequestType.LOCK_EXC, 'test')
        assert isinstance(r.wire(), bytes)


class TestResponse:

    def test_response_ok(self):
        """Test an ok response."""
        r = client.Response('test', 'LOCKED')
        assert r.status_is(client.Response.LOCKED)
        assert r.key == 'test'

    def test_response_timeout(self):
        """Test a response sending a timeout."""
        with pytest.raises(client.PoolcounterTimeoutError):
            client.Response('test', 'TIMEOUT')

    def test_response_queue_full(self):
        """Test a queue full response."""
        with pytest.raises(client.PoolcounterQueueError):
            client.Response('test', 'QUEUE_FULL')

    def test_response_generic_error(self):
        with pytest.raises(client.PoolcounterError,
                           match="Error talking to poolcounter: unicorns"):
            client.Response('test', 'ERROR unicorns')


class TestServer:
    def setup_method(self):
        self.server = client.Server('localhost', weight=1, label='shard1')
        #  mock the socket via DI
        self.server._stream = mock.MagicMock()

    def test_init(self):
        """Test initialization."""
        with mock.patch('socket.gethostbyname') as mocker:
            s = client.Server('www.mediawiki.org', weight=1)
        assert s.label == 'www.mediawiki.org'
        assert s.port == 7531
        assert s._stream is None
        assert s.has_lock is False
        mocker.assert_called_with('www.mediawiki.org')

    def test_str(self):
        """Test the string representation."""
        assert str(self.server) == 'shard1 (127.0.0.1:7531)'

    def test_get_lock_connect(self):
        """Test connection is initiated when not present"""
        self.server._stream = None
        mock_stream = mock.MagicMock()
        mock_stream.recv.return_value = bytes(client.Response.LOCKED, 'utf-8')
        self.server._connect = mock.MagicMock(return_value=mock_stream)
        self.server.get_lock(client.RequestType.LOCK_ANY, 'test::app::key')
        assert self.server._stream == mock_stream
        self.server._connect.assert_called_with()

    def test_get_lock_ok(self):
        """Test successfully getting a lock"""
        self.server._stream.recv.return_value = bytes(client.Response.LOCKED, 'utf-8')
        assert self.server.get_lock(
            client.RequestType.LOCK_ANY, 'test::app::key'
        ).status_is(
            client.Response.LOCKED
        )
        assert self.server.has_lock is True
        self.server._stream.send.assert_called_with(b'ACQ4ANY test::app::key 1 1000 1\n')

    def test_get_lock_already_locked(self):
        """Test trying to get a lock while holding one."""
        self.server.has_lock = True
        with pytest.raises(client.PoolcounterError):
            self.server.get_lock(client.RequestType.LOCK_ANY, 'test::app::key')
        assert self.server._stream.send.call_count == 0

    def test_get_lock_done(self):
        """Test lock is done."""
        self.server._stream.recv.return_value = bytes(client.Response.DONE, 'utf-8')
        assert self.server.get_lock(
            client.RequestType.LOCK_ANY, 'test::app::key'
        ).status_is(
            client.Response.DONE
        )
        assert self.server.has_lock is False

    def test_get_lock_held(self):
        """Test what happens when the lock is already held server-side"""
        # This should never happen as we set server.has_lock to true when we get confirmation
        # we hold a lock. If for any reason that wasn't the case, we get the news from the server.
        self.server._stream.recv.return_value = bytes(client.Response.LOCK_HELD, 'utf-8')
        with pytest.raises(
            client.PoolcounterError,
            match="You cannot acquire a new lock while holding one."
        ):
            self.server.get_lock(
                client.RequestType.LOCK_ANY, 'test::app::key'
            )
        # First we fix the local information - we do have a lock
        assert self.server.has_lock is True

    def test_lock_release_ok(self):
        """Test lock release ok."""
        self.server.has_lock = True
        self.server._stream.recv.return_value = bytes(client.Response.RELEASED, 'utf-8')
        self.server.lock_release('test::app::key')
        # We called the server with the correct string
        self.server._stream.send.assert_called_with(b'RELEASE test::app::key\n')
        # The response has no errors
        assert self.server.has_lock is False

    def test_lock_release_no_connection(self):
        """Test release lock with no connection"""
        self.server._stream = None
        with pytest.raises(client.PoolcounterError, match='without a connection'):
            self.server.lock_release('test::app::key')

    def test_lock_release_no_lock(self):
        """Test releasing a lock when none is held"""
        self.server.has_lock = True
        self.server._stream.recv.return_value = bytes(client.Response.NOT_LOCKED, 'utf-8')
        self.server.lock_release('test::app::key')
        assert self.server.has_lock is False

    def test_lock_release_other_msg(self):
        """Test releasing a lock with strange response"""
        self.server.has_lock = True
        self.server._stream.recv.return_value = bytes(client.Response.LOCK_HELD, 'utf-8')
        self.server.lock_release('test::app::key')
        assert self.server.has_lock

    def test_shutdown(self):
        """Test shutdown."""
        mocker = self.server._stream
        self.server.shutdown()
        mocker.close.assert_called_with()
        assert self.server._stream is None
        assert self.server.has_lock is False

    def test_shutdown_no_stream(self):
        """Test shutdown when stream is none"""
        self.server.has_lock = True
        self.server._stream = None
        self.server.shutdown()
        assert self.server.has_lock is False

    def test_connect_ok(self):
        """Test successful connection."""
        self.server._stream = None
        with mock.patch('poolcounter.client.socket.socket') as sock:
            self.server._connect()
        sock.assert_called_with(socket.AF_INET, socket.SOCK_STREAM, 0)
        sock.return_value.settimeout.assert_has_calls(
            [
                mock.call(self.server.connection_timeout),
                mock.call(None)
            ]
        )

    @pytest.mark.parametrize('exc, raised, message', (
        (TimeoutError, client.PoolcounterTimeoutError, 'Connection to '),
        (ConnectionRefusedError, client.PoolcounterError, 'Cannot connect to server ')
    ))
    def test_connect_not_ok(self, exc, raised, message):
        """Test connection that times out/refuses connections."""
        self.server._stream = None
        with mock.patch('poolcounter.client.socket.socket') as sock:
            sock.return_value.connect.side_effect = exc('test')
            with pytest.raises(raised, match=message):
                self.server._connect()
        # check that the connection was correctly closed.
        sock.return_value.close.assert_called_with()

    def test_socket_error(self):
        """Test when a socket error happens."""
        self.server._stream.send.side_effect = socket.error('something')
        with pytest.raises(client.PoolcounterError, match='Error communicating with the server'):
            self.server.lock_release('test::app::key')


class TestPoolcounterClient:
    def setup_method(self):
        self.client = client.PoolcounterClient(logging.getLogger())
        self.client.add_backend(client.Server('localhost', label='node1', weight=10))
        self.client.add_backend(client.Server('localhost', port=8642, label='node2'))

    def test_add_backend(self):
        """Test adding a backend successfully."""
        s = client.Server('localhost', port=6667, label='node3')
        self.client.add_backend(s)
        assert self.client.backends['node3'] == s
        assert self.client.ring.has_node('node3')

    def test_add_existing_backend(self):
        """Test adding a backend twice."""
        with pytest.raises(client.PoolcounterError, match=' is already present. Please call'):
            self.client.add_backend(client.Server('localhost', label='node1', weight=10))

    def test_remove_backend(self):
        """Test removing a backend successfully."""
        self.client.remove_backend('node2')
        assert 'node2' not in self.client.backends
        assert self.client.ring.has_node('node2') is False

    def test_remove_not_found_backend(self):
        """Test removing a backend that doesn't exist."""
        with pytest.raises(client.PoolcounterError):
            self.client.remove_backend('test')

    def test_default_errback(self):
        """Test that the default errback returns False"""
        assert self.client.default_errback(Exception('test!')) is False

    def test_backend_for(self):
        """Test the correct backend is selected"""
        s = self.client.backend_for('test::goes::to::node1')
        assert s == self.client.backends['node1']

    def test_backend_for_no_backends(self):
        """Test failure scenario for backend_for."""
        cl = client.PoolcounterClient(logging.getLogger())
        with pytest.raises(client.PoolcounterError):
            cl.backend_for('test::goes::to::node1')

    def test_run_success(self):
        """Test a successful run"""
        def test_cb(arg1, arg2):
            assert arg1 == 5
            assert arg2 == 10

        key = 'test::goes::to::node1'
        responses = [
            client.Response(key, client.Response.LOCKED),
            client.Response(key, client.Response.RELEASED)
        ]
        backend = self.client.backends['node1']
        backend._stream = mock.MagicMock()
        backend._command = mock.MagicMock(side_effect=responses)
        assert self.client.run(client.RequestType.LOCK_EXC, key, test_cb, 5, 10, concurrency=10)
        assert backend._command.call_count == 2

    def test_run_lock_fail(self):
        """Test a run where locking fails."""
        key = 'test::goes::to::node1'
        self.client.lock_release_retry = 2
        err = client.PoolcounterError('some error')
        responses = [
            err,
            client.Response(key, client.Response.NOT_LOCKED)
        ]
        backend = self.client.backends['node1']
        backend._stream = mock.MagicMock()
        backend._command = mock.MagicMock(side_effect=responses)
        mock_cb = mock.MagicMock()
        mock_eb = mock.MagicMock(return_value=False)
        # Locking fails, so no call to the callback will happen.
        assert self.client.run(client.RequestType.LOCK_EXC, key, mock_cb, errback=mock_eb) is False
        assert mock_cb.call_count == 0
        mock_eb.assert_called_with(err)

    def test_run_release_fail(self):
        """Test a run where releasing the lock fails."""
        def null_cb():
            pass

        key = 'test::goes::to::node1'
        self.client.lock_release_retry = 2
        responses = [
            client.Response(key, client.Response.LOCKED),
            client.PoolcounterError('some error'),
            client.PoolcounterError('some error'),
            client.Response(key, client.Response.RELEASED)
        ]
        backend = self.client.backends['node1']
        backend._stream = mock.MagicMock()
        backend._command = mock.MagicMock(side_effect=responses)
        with pytest.raises(client.PoolcounterError, match='Lock for key'):
            self.client.run(client.RequestType.LOCK_EXC, key, null_cb)

    def test_run_cb_failure(self):
        """Test a run where the callback fails."""
        def err_cb():
            raise ValueError('I fail.')
        key = 'test::goes::to::node1'
        responses = [
            client.Response(key, client.Response.LOCKED),
            client.Response(key, client.Response.RELEASED)
        ]
        backend = self.client.backends['node1']
        backend._stream = mock.MagicMock()
        backend._command = mock.MagicMock(side_effect=responses)
        assert self.client.run(client.RequestType.LOCK_EXC, key, err_cb) is False

    @pytest.mark.parametrize('resp', (client.Response.LOCK_HELD, client.Response.QUEUE_FULL))
    def test_run_generic_failure(self, resp):
        """Test a run where an error is inserted"""
        mock_cb = mock.MagicMock()

        def mock_eb(err):
            assert isinstance(err, client.PoolcounterError)
            # this is not strictly correct, but makes the test fun.
            return 'unicorns'
        key = 'test::goes::to::node1'

        def _resp(response):
            try:
                return client.Response(key, response)
            except client.PoolcounterError as e:
                return e
        responses = [
            _resp(resp),
            client.Response(key, client.Response.RELEASED)
        ]
        backend = self.client.backends['node1']
        backend._stream = mock.MagicMock()
        backend._command = mock.MagicMock(side_effect=responses)
        assert self.client.run(client.RequestType.LOCK_EXC, key,
                               mock_cb, errback=mock_eb) == 'unicorns'
        # The callback wasn't called
        assert mock_cb.call_count == 0
