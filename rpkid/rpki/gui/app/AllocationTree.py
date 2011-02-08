# $Id$
"""
Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

from rpki.gui.app import misc, models
from rpki import resource_set

class AllocationTree(object):
    '''Virtual class representing a tree of unallocated resource ranges.
    Keeps track of which subsets of a resource range have been
    allocated.'''

    def __init__(self, resource):
        self.resource = resource
        self.range = resource.as_resource_range()
        self.need_calc = True

    def calculate(self):
        if self.need_calc:
            self.children = []
            self.alloc = self.__class__.set_type()
            self.unalloc = self.__class__.set_type()

            if self.is_allocated():
                self.alloc.append(self.range)
            else:
                for child in self.resource.children.all():
                    c = self.__class__(child)
                    if c.unallocated():
                        self.children.append(c)
                    self.alloc = self.alloc.union(c.alloc)
                total = self.__class__.set_type()
                total.append(self.range)
                self.unalloc = total.difference(self.alloc)
            self.need_calc=False

    def unallocated(self):
        self.calculate()
        return self.unalloc

    def as_ul(self):
        '''Returns a string of the tree as an unordered HTML list.'''
        s = []
        s.append('<a href="%s">%s</a>' % (self.resource.get_absolute_url(), self.resource))

        # when the unallocated range is a subset of the current range,
        # display the missing ranges
        u = self.unallocated()
        if len(u) != 1 or self.range != u[0]:
            s.append(' (missing: ')
            s.append(', '.join(str(x) for x in u))
            s.append(')')

        # quick access links
        if self.resource.parent:
            s.append(' | <a href="%s/delete">delete</a>' % (self.resource.get_absolute_url(),))
        s.append(' | <a href="%s/allocate">give</a>' % (self.resource.get_absolute_url(),))
        if self.range.min != self.range.max:
            s.append(' | <a href="%s/split">split</a>' % (self.resource.get_absolute_url(),))
        # add type-specific actions
        a = self.supported_actions()
        if a:
            s.extend(a)

        if self.children:
            s.append('\n<ul>\n')
            for c in self.children:
                s.append('<li>' + c.as_ul())
            s.append('\n</ul>')

        return ''.join(s)

    def supported_actions(self):
        '''Virtual method allowing subclasses to add actions to the HTML list.'''
        return None

    @classmethod
    def from_resource_range(cls, resource):
        if isinstance(resource, resource_set.resource_range_as):
            return AllocationTreeAS(resource)
        if isinstance(resource, resoute_set.resource_range_ip):
            return AllocationTreeIP(resource)
        raise ValueError, 'Unsupported resource range type'

class AllocationTreeAS(AllocationTree):
    set_type = resource_set.resource_set_as

    def __init__(self, *args, **kwargs):
        AllocationTree.__init__(self, *args, **kwargs)
        self.conf = misc.top_parent(self.resource).from_cert.all()[0].parent.conf

    def is_allocated(self):
        '''Returns true if this AS has been allocated to a child or
        used in a ROA request.'''
        # FIXME: detect use in ROA requests

        if self.resource.allocated:
            return True

        # for individual ASNs
        if self.range.min == self.range.max:
            # is this ASN used in any roa?
            if self.conf.roas.filter(asn=self.range.min):
                return True

        return False

class AllocationTreeIP(AllocationTree):
    '''virtual class representing a tree of IP address ranges.'''

    @classmethod
    def from_prefix(cls, prefix):
        r = prefix.as_resource_range()
        if isinstance(r, resource_set.resource_range_ipv4):
            return AllocationTreeIPv4(prefix)
        elif isinstance(r, resource_set.resource_range_ipv6):
            return AllocationTreeIPv6(prefix)
        raise ValueError, 'Unsupported IP range type'

    def supported_actions(self):
        '''add a link to issue a ROA for this IP range'''
        if self.resource.is_prefix():
            return [' | <a href="%s/roa">roa</a>' % self.resource.get_absolute_url()]
        else:
            return []

    def is_allocated(self):
        '''Return True if this IP range is allocated to a child or used
        in a ROA request.'''
        return self.resource.allocated or self.resource.roa_requests.count()

class AllocationTreeIPv4(AllocationTreeIP):
    set_type = resource_set.resource_set_ipv4

class AllocationTreeIPv6(AllocationTreeIP):
    set_type = resource_set.resource_set_ipv6

# vim:sw=4 ts=8 expandtab
