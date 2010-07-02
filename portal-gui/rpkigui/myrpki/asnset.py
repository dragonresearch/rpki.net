class asnset(object):
    """a set-like objet for containing sets of ASN values."""
    v = set()

    def __init__(self, init=None):
        """
        May be initialized from a comma separated list of positive integers.
        """
        if init:
            self.v = set(int(x) for x in init.split(',') if x.strip() != '')
            if any([x for x in self.v if x < 0]):
                raise ValueError, "can't contain negative values."

    def __str__(self):
        return ','.join(str(x) for x in sorted(self.v))

    def __iter__(self):
        return iter(self.v)

    def add(self, n):
        assert isinstance(n, int)
        assert n > 0
        self.v.add(n)
