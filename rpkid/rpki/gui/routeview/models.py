# Copyright (C) 2010, 2011  SPARTA, Inc. dba Cobham Analytic Solutions
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

from django.db.models import PositiveIntegerField, permalink
import rpki.gui.models


class RouteOrigin(rpki.gui.models.PrefixV4):
    "Represents an IPv4 BGP routing table entry."

    asn = PositiveIntegerField(help_text='origin AS', null=False)

    def __unicode__(self):
        return u"AS%d's route origin for %s" % (self.asn,
                                                self.get_prefix_display())

    @property
    def roas(self):
        "Return a queryset of ROAs which cover this route."
        return cacheview.ROA.objects.filter(
            prefixes__prefix_min__lte=self.prefix_min,
            prefixes__prefix_max__gte=self.prefix_max
        )

    @property
    def roa_prefixes(self):
        "Return a queryset of ROA prefixes which cover this route."
        return cacheview.ROAPrefixV4.objects.filter(
            prefix_min__lte=self.prefix_min,
            prefix_max__gte=self.prefix_max
        )

    @property
    def status(self):
        "Returns the validation status of this route origin object."
        roas = self.roas
        # subselect exact match
        if self.asn != 0 and roas.filter(asid=self.asn, prefixes__max_length__gte=self.prefixlen).exists():
            return 'valid'
        elif roas.exists():
            return 'invalid'
        return 'unknown'

    @permalink
    def get_absolute_url(self):
        return ('rpki.gui.app.views.route_detail', [str(self.pk)])

    class Meta:
        # sort by increasing mask length (/16 before /24)
        ordering = ('prefix_min', '-prefix_max')


class RouteOriginV6(rpki.gui.models.PrefixV6):
    "Represents an IPv6 BGP routing table entry."

    asn = PositiveIntegerField(help_text='origin AS', null=False)

    def __unicode__(self):
        return u"AS%d's route origin for %s" % (self.asn,
                                                self.get_prefix_display())

    class Meta:
        ordering = ('prefix_min', '-prefix_max')


# this goes at the end of the file to avoid problems with circular imports
from rpki.gui.cacheview import models as cacheview
