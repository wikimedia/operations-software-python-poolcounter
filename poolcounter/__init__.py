"""Wikimedia's Poolcounter client in pure python3.

Can be used to apply global rate-limiting to any work that needs to be done across production.

Also offers a consistent hash implementation.
"""
import logging

from typing import List, Tuple

import yaml


from .client import PoolcounterClient, Server


def from_yaml(filename: str, logger_name: str = 'poolcounter') -> PoolcounterClient:
    """Get a poolcounter client from a yaml configuration file.

    The file should contain a simple list of servers in "label:hostname:weight" form

    - "server1:pc1.example.com:10"
    - "server2:pc2.example.com:1"

    Arguments:
        filename (str): the name of the yaml file
        logger_name (str): the logger name. Default value: 'poolcounter'

    Returns:
        A PoolcounterClient instance with all the backends.

    """
    with open(filename, 'r', encoding='utf-8') as fh:
        servers = yaml.safe_load(fh)
    backends = [tuple(server.split(':')) for server in servers]
    return new(backends, logger_name)


def new(backends: List[Tuple], logger_name: str = 'poolcounter') -> PoolcounterClient:
    """Get a poolcounter client from a list of tuples.

    The tuples should be in the form

    (label, hostname, weight)

    Arguments:
        backends (list(tuple)): the list of backend tuples
        logger_name (str): the logger name. Default value: 'poolcounter'

    Returns:
        A PoolcounterClient instance with all the backends.

    """
    client = PoolcounterClient(logging.getLogger(logger_name))
    for label, fqdn, weight in backends:
        client.add_backend(Server(fqdn, weight=int(weight), label=label))
    return client
