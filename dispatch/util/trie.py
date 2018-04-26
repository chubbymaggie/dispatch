from ..constructs import Instruction

class Trie(object):
    BUCKET_LEN = 1
    BUCKET_MASK = (2**BUCKET_LEN)-1
    def __init__(self):
        self.children = [None for _ in range(2**Trie.BUCKET_LEN)]
        self.value = None

    def __setitem__(self, key, value):
        assert type(value) == Instruction

        node = self
        for bucket in [(key >> i) & Trie.BUCKET_MASK for \
                       i in range(64, -1, -Trie.BUCKET_LEN)]:
            if not node.children[bucket]:
                node.children[bucket] = Trie()
            node = node.children[bucket]

        node.value = value

    def __getitem__(self, item):
        if type(item) in (int, long):
            node = self
            for bucket in [(item >> i) & Trie.BUCKET_MASK for \
                           i in range(64, -1, -Trie.BUCKET_LEN)]:
                if not node.children[bucket]:
                    raise KeyError()
                node = node.children[bucket]

            return node.value

        elif type(item) == slice:
            start = item.start
            stop = item.stop
            if start is None:
                start = 0
            if stop is None:
                # 128 bits max address. Seems big enough for practical purposes
                stop = 0xFFFFFFFFFFFFFFFF
            uncommon_bits = (stop ^ start).bit_length()

            node = self
            for bucket in [(start >> i) & Trie.BUCKET_MASK for \
                           i in range(64, uncommon_bits, -Trie.BUCKET_LEN)]:
                if not node.children[bucket]:
                    raise KeyError()
                node = node.children[bucket]

            return [v for v in iter(node) if start <= v.address < stop][::item.step]

    def __iter__(self):
        if self.value:
            yield self.value
        for child in filter(None, self.children):
            for v in child:
                yield v

    def __contains__(self, item):
        node = self
        for bucket in [(item >> i) & Trie.BUCKET_MASK for \
                       i in range(64, -1, -Trie.BUCKET_LEN)]:
            if not node.children[bucket]:
                return False
            node = node.children[bucket]
        return True

    def __delitem__(self, key):
        node = self
        for bucket in [(key >> i) & Trie.BUCKET_MASK for \
                       i in range(64, -1, -Trie.BUCKET_LEN)]:
            if not node.children[bucket]:
                raise KeyError()
            node = node.children[bucket]

        node.value = None
