# $Id$
"""
Copyright (C) 2011  SPARTA, Inc. dba Cobham Analytic Solutions

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

from django import forms

from rpki.gui.cacheview.misc import parse_ipaddr
from rpki.exceptions import BadIPResource
from rpki.resource_set import resource_range_as

class SearchForm(forms.Form):
    asn = forms.CharField(required=False, help_text='AS or range', label='AS')
    addr = forms.CharField(required=False, max_length=40, help_text='range/CIDR', label='IP Address')

    def clean(self):
        asn = self.cleaned_data.get('asn')
        addr = self.cleaned_data.get('addr')
        if (asn and addr) or ((not asn) and (not addr)):
            raise forms.ValidationError, 'Please specify either an AS or IP range, not both'

        if asn:
            try:
                resource_range_as.parse_str(asn)
            except ValueError:
                raise forms.ValidationError, 'invalid AS range'

        if addr:
            #try:
            parse_ipaddr(addr)
            #except BadIPResource:
            #    raise forms.ValidationError, 'invalid IP address range/prefix'

        return self.cleaned_data
