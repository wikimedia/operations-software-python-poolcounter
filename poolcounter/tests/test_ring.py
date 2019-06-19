"""Ring module tests"""
from unittest import mock

import pytest  # type: ignore

from poolcounter import ring


class TestHashRing:
    """HashRing test class."""

    def setup_method(self):
        self.ring = ring.HashRing(vnodes=30)

    @pytest.fixture
    def default_ring(self):
        r = ring.HashRing()
        r.add_node('foo', 1)
        r.add_node('bar', 3)
        r.add_node('baz', 1)
        return r

    def test_init(self):
        """Test initialization."""
        assert self.ring.vnodes == 30

    def test_has_node(self, default_ring):
        """Test has_node"""
        assert default_ring.has_node('baz')
        assert default_ring.has_node('unicorn') is False

    def test_add_node_ok(self):
        """Test adding a node"""
        self.ring.add_node('test', 1)
        # We only have 1 node in the ring,
        # so that should be selected
        assert self.ring.get_node('some key') == 'test'
        # The right number of vnodes has been created
        assert len(self.ring._index) == self.ring.vnodes

    def test_add_node_ok_weight(self):
        """Test adding a node with weight != 1"""
        self.ring.add_node('test', 2)
        # We now have twice as many points in the ring.
        assert len(self.ring._index) == 2 * self.ring.vnodes

    def test_add_node_zero_weight(self):
        """Test adding a node with weight 0 adds no vnodes"""
        self.ring.add_node('test', 0)
        assert len(self.ring._index) == 0

    def test_add_node_duplicate(self, default_ring):
        """Test adding a node twice"""
        # Re-adding a node will cause collisions, and raise a value error
        with pytest.raises(ValueError, match='Node "foo" already present'):
            default_ring.add_node('foo', 3)

    def test_add_node_collision(self, default_ring):
        with mock.patch('poolcounter.ring._hash') as hashmock:
            hashmock.return_value = 10
            with pytest.raises(ValueError,
                               match='Collision detected when adding "unicorn"'):
                default_ring.add_node('unicorn', 4)

    def test_del_node_ok(self, default_ring):
        """Test removing a node"""
        default_ring.del_node('foo')
        assert default_ring.has_node('foo') is False

    def test_del_node_not_found(self):
        """Test removing a node that's not present"""
        # This shouldn't raise any error.
        self.ring.del_node('bar')

    def test_get_node_consistent(self, default_ring):
        """Test consistent hashing when removing servers"""
        key = 'this is a nice key that maps to bar'
        assert default_ring.get_node(key) == 'bar'
        # If a key maps to 1 node, it should keep mapping
        # to it if we remove 1 node from the ring.
        default_ring.del_node('foo')
        assert default_ring.get_node(key) == 'bar'
        # Re-adding the same node doesn't change mapping
        default_ring.add_node('foo', 1)
        assert default_ring.get_node(key) == 'bar'

    def test_get_node_consistent_distribution(self, default_ring):
        """Test keys get evenly distributed"""
        iterations = 100000
        scores = {'foo': 0, 'bar': 0, 'baz': 0}
        for i in range(iterations):
            key = 'org::app::namespace::keyname::{id}'.format(id=i)
            scores[default_ring.get_node(key)] += 1
        # A node with weight 3 should have more keys than the others
        assert scores['bar'] > (scores['foo'] + scores['baz'])
        # keys distribution over 100k keys is isotropic within 5%
        assert abs((scores['foo'] - scores['baz']) / iterations) < 0.05
