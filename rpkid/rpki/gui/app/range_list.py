# Copyright (C) 2012  SPARTA, Inc. a Parsons Company
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

__version__ = '$Id$'

import bisect
import unittest

class RangeList(list):
    """A sorted list of ranges, which automatically merges adjacent ranges.

    Items in the list are expected to have ".min" and ".max" attributes."""

    def __init__(self, ini=None):
        list.__init__(self)
        if ini:
            self.extend(ini)

    def append(self, v):
        keys = [x.min for x in self]

        # lower bound
        i = bisect.bisect_left(keys, v.min)

        # upper bound
        j = bisect.bisect_right(keys, v.max, lo=i)

        # if the max value for the previous item is greater than v.min, include the previous item in the range to replace
        # and use its min value.  also include the previous item if the max value is 1 less than the min value for the
        # inserted item
        if i > 0 and self[i-1].max >= v.min - 1:
            i = i - 1
            vmin = self[i].min
        else:
            vmin = v.min

        # if the max value for the previous item is greater than the max value for the new item, use the previous item's max
        if j > 0 and self[j-1].max > v.max:
            vmax = self[j-1].max
        else:
            vmax = v.max

        # if the max value for the new item is 1 less than the min value for the next item, combine into a single item
        if j < len(self) and vmax+1 == self[j].min:
            vmax = self[j].max
            j = j+1

        # replace the range with a new object covering the entire range
        self[i:j] = [v.__class__(min=vmin, max=vmax)]

    def extend(self, args):
        for x in args:
            self.append(x)

    def difference(self, other):
        """Return a RangeList object which contains ranges in this object which are not in "other"."""
        it = iter(other)

        try:
            cur = it.next()
        except StopIteration:
            return self

        r = RangeList()

        for x in self:
            xmin = x.min

            def V(v):
                """convert the integer value to the appropriate type for this
                range"""
                return x.__class__.datum_type(v)

            try:
                while xmin <= x.max:
                    if xmin < cur.min:
                        r.append(x.__class__(min=V(xmin),
                                             max=V(min(x.max,cur.min-1))))
                        xmin = cur.max+1
                    elif xmin == cur.min:
                        xmin = cur.max+1
                    else: # xmin > cur.min
                        if xmin <= cur.max:
                            xmin = cur.max+1
                        else: # xmin > cur.max
                            cur = it.next()

            except StopIteration:
                r.append(x.__class__(min=V(xmin), max=x.max))

        return r

class TestRangeList(unittest.TestCase):
    class MinMax(object):
        def __init__(self, min, max):
            self.min = min
            self.max = max

        def __str__(self):
            return '(%d, %d)' % (self.min, self.max)

        def __repr__(self):
            return '<MinMax: (%d, %d)>' % (self.min, self.max)

        def __eq__(self, other):
            return self.min == other.min and self.max == other.max

    def setUp(self):
        self.v1 = TestRangeList.MinMax(1,2)
        self.v2 = TestRangeList.MinMax(4,5)
        self.v3 = TestRangeList.MinMax(7,8)
        self.v4 = TestRangeList.MinMax(3,4)
        self.v5 = TestRangeList.MinMax(2,3)
        self.v6 = TestRangeList.MinMax(1,10)

    def test_empty_append(self):
        s = RangeList()
        s.append(self.v1)
        self.assertTrue(len(s) == 1)
        self.assertEqual(s[0], self.v1)

    def test_no_overlap(self):
        s = RangeList()
        s.append(self.v1)
        s.append(self.v2)
        self.assertTrue(len(s) == 2)
        self.assertEqual(s[0], self.v1)
        self.assertEqual(s[1], self.v2)

    def test_no_overlap_prepend(self):
        s = RangeList()
        s.append(self.v2)
        s.append(self.v1)
        self.assertTrue(len(s) == 2)
        self.assertEqual(s[0], self.v1)
        self.assertEqual(s[1], self.v2)

    def test_insert_middle(self):
        s = RangeList()
        s.append(self.v1)
        s.append(self.v3)
        s.append(self.v2)
        self.assertTrue(len(s) == 3)
        self.assertEqual(s[0], self.v1)
        self.assertEqual(s[1], self.v2)
        self.assertEqual(s[2], self.v3)

    def test_append_overlap(self):
        s = RangeList()
        s.append(self.v1)
        s.append(self.v5)
        self.assertTrue(len(s) == 1)
        self.assertEqual(s[0], TestRangeList.MinMax(1,3))

    def test_combine_range(self):
        s = RangeList()
        s.append(self.v1)
        s.append(self.v4)
        self.assertTrue(len(s) == 1)
        self.assertEqual(s[0], TestRangeList.MinMax(1,4))

    def test_append_subset(self):
        s = RangeList()
        s.append(self.v6)
        s.append(self.v3)
        self.assertTrue(len(s) == 1)
        self.assertEqual(s[0], self.v6)

    def test_append_equal(self):
        s = RangeList()
        s.append(self.v6)
        s.append(self.v6)
        self.assertTrue(len(s) == 1)
        self.assertEqual(s[0], self.v6)

    def test_prepend_combine(self):
        s = RangeList()
        s.append(self.v4)
        s.append(self.v1)
        self.assertTrue(len(s) == 1)
        self.assertEqual(s[0], TestRangeList.MinMax(1,4))

    def test_append_aggregate(self):
        s = RangeList()
        s.append(self.v1)
        s.append(self.v2)
        s.append(self.v3)
        s.append(self.v6)
        self.assertTrue(len(s) == 1)
        self.assertEqual(s[0], self.v6)

    def test_diff_empty(self):
        s = RangeList()
        s.append(self.v1)
        self.assertEqual(s, s.difference([]))

    def test_diff_self(self):
        s = RangeList()
        s.append(self.v1)
        self.assertEqual(s.difference(s), [])

    def test_diff_middle(self):
        s1 = RangeList([self.v6])
        s2 = RangeList([self.v3])
        self.assertEqual(s1.difference(s2), RangeList([TestRangeList.MinMax(1,6), TestRangeList.MinMax(9, 10)]))

    def test_diff_overlap(self):
        s1 = RangeList([self.v2])
        s2 = RangeList([self.v4])
        self.assertEqual(s1.difference(s2), RangeList([TestRangeList.MinMax(5,5)]))

    def test_diff_overlap2(self):
        s1 = RangeList([self.v2])
        s2 = RangeList([self.v4])
        self.assertEqual(s2.difference(s1), RangeList([TestRangeList.MinMax(3,3)]))

    def test_diff_multi(self):
        s1 = RangeList([TestRangeList.MinMax(1,2), TestRangeList.MinMax(4,5)]) 
        s2 = RangeList([TestRangeList.MinMax(4,4)]) 
        self.assertEqual(s1.difference(s2), RangeList([TestRangeList.MinMax(1,2), TestRangeList.MinMax(5,5)]))

    def test_diff_multi_overlap(self):
        s1 = RangeList([TestRangeList.MinMax(1,2), TestRangeList.MinMax(3,4)])
        s2 = RangeList([TestRangeList.MinMax(2,3)])
        self.assertEqual(s1.difference(s2), RangeList([TestRangeList.MinMax(1,1), TestRangeList.MinMax(4,4)]))

    def test_diff_multi_overlap2(self):
        s1 = RangeList([TestRangeList.MinMax(1,2), TestRangeList.MinMax(3,4), TestRangeList.MinMax(6,7)])
        s2 = RangeList([TestRangeList.MinMax(2,3), TestRangeList.MinMax(6,6)])
        self.assertEqual(s1.difference(s2), RangeList([TestRangeList.MinMax(1,1), TestRangeList.MinMax(4,4), TestRangeList.MinMax(7,7)]))

if __name__ == '__main__':
    unittest.main()
