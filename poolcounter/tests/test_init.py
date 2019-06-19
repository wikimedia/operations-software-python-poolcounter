from unittest import mock

import poolcounter
from poolcounter.client import PoolcounterClient

yaml_file = b"""
- foo:host1.example.com:5
- bar:host2.example.com:10
"""


class TestPoolcounter:

    @mock.patch('socket.gethostbyname')
    def test_new(self, gethost):
        gethost.return_value = '127.0.0.1'
        pc = poolcounter.new([('foo', 'host1.example.com', 5), ('bar', 'host2.example.com', 1)])
        assert isinstance(pc, PoolcounterClient)
        assert len(pc.backends) == 2

    @mock.patch('socket.gethostbyname')
    @mock.patch('poolcounter.open', mock.mock_open(read_data=yaml_file))
    def test_from_yaml(self, myopen):
        pc = poolcounter.from_yaml('some_test_file.yaml')
        assert isinstance(pc, PoolcounterClient)
        assert len(pc.backends) == 2
