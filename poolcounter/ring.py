"""Very simple consistent hash implementation.

In the current implementation, removing one node will reshard only the keyspace corresponding
to that node. Adding one node will reshard at most the keys that move to that node, so

 node_weight / sum(weights)

of the total keyspace. Please note that while our use of md5 as a hashing function will guarantee
a decent uniformity in key distribution (and we perform some simple tests on it), that is not
rigorously tested.
"""
import bisect

from hashlib import md5
from typing import Dict, Iterator, List


def _hash(data: bytes) -> int:
    """Hashing function is md5. We use md5 as it's quite evenly distributed."""
    return int(md5(data).hexdigest(), 16)


class HashRing:
    """Manages a consistent hash ring."""

    def __init__(self, vnodes: int = 100) -> None:
        """Initializes the hash ring.

        Arguments:
            vnodes (int): the number of virtual nodes per label to create. Defaults to 100.

        """
        self.vnodes = vnodes
        self._ring: Dict[int, str] = {}
        self._index: List[int] = []

    def has_node(self, label: str) -> bool:
        """Check if a node is present."""
        return label in self._ring.values()

    def add_node(self, label, weight) -> None:
        """Add a node to the ring.

        Arguments:
            label (str): the label of the node.
            weight (int): the relative weight of the node

        """
        if self.has_node(label):
            raise ValueError('Node "{}" already present'.format(label))
        for point in self._node_iterator(label, weight):
            ring_pos = _hash(point)
            if ring_pos not in self._ring:
                self._ring[ring_pos] = label
            else:
                raise ValueError('Collision detected when adding "{}"'.format(label))
            # let's insert this new position in the
            # ring index
            bisect.insort(self._index, ring_pos)

    def del_node(self, label: str) -> None:
        """Remove a node from the ring.

        Arguments:
            label (str): the label of the node

        """
        ring_positions = [pos for pos, lbl in self._ring.items() if lbl == label]
        for ring_pos in ring_positions:
            del self._ring[ring_pos]
            idx = bisect.bisect_left(self._index, ring_pos)
            del self._index[idx]

    def get_node(self, key: str) -> str:
        """Get the node corresponding to our key.

        We will select the point on the ring nearest (but not less than) the
        hashed value of the key.

        Arguments:
            key (str): they key to place on the ring

        Returns:
            str: the label of the node the key belongs to

        """
        if not self._ring:
            raise ValueError('Cannot search the node on an empty ring. '
                             'Please add at least one node with non-zero weight.')
        hv = _hash(key.encode('utf-8'))
        idx = bisect.bisect(self._index, hv)
        if idx == len(self._index):
            idx = 0
        return self._ring[self._index[idx]]

    def _node_iterator(self, label: str, weight: int) -> Iterator[bytes]:
        for i in range(0, self.vnodes):
            for j in range(0, weight):
                yield '{label}:{vnode}:{weight}'.format(
                    label=label,
                    vnode=i,
                    weight=j
                ).encode('utf-8')
