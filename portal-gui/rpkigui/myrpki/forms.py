# $Id$
"""
Copyright (C) 2010  SPARTA, Inc. dba Cobham Analytic Solutions

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

import rpki.ipaddrs

from rpkigui.myrpki import models, misc
from rpkigui.myrpki.asnset import asnset

class AddConfForm(forms.Form):
    handle = forms.CharField(required=True,
            help_text='your handle for your rpki instance')
    run_rpkid = forms.BooleanField(required=False, initial=True,
            label='Run rpkid?',
            help_text='do you want to run your own instance of rpkid?')
    rpkid_server_host = forms.CharField(initial='rpkid.example.org',
            label='rpkid hostname',
            help_text='publicly visible hostname for your rpkid instance')
    rpkid_server_port = forms.IntegerField(initial=4404,
            label='rpkid port')
    run_pubd = forms.BooleanField(required=False, initial=False,
            label='Run pubd?',
            help_text='do you want to run your own instance of pubd?')
    pubd_server_host = forms.CharField(initial='pubd.example.org',
            label='pubd hostname',
            help_text='publicly visible hostname for your pubd instance')
    pubd_server_port = forms.IntegerField(initial=4402, label='pubd port')
    pubd_contact_info = forms.CharField(initial='repo-man@rpki.example.org',
            label='Pubd contact',
            help_text='email address for the operator of your pubd instance')

class ImportForm(forms.Form):
    '''Form used for uploading parent/child identity xml files'''
    handle = forms.CharField()
    xml = forms.FileField()

def PrefixSplitForm(parent, *args, **kwargs):
    class _wrapper(forms.Form):
        prefix = forms.CharField(max_length=200, help_text='CIDR or range')

        def clean(self):
            p = self.cleaned_data.get('prefix')
            try:
                r = misc.parse_resource_range(p)
            except ValueError, err:
                print err
                raise forms.ValidationError, 'invalid prefix or range'
            # we get AssertionError is the range is misordered (hi before lo)
            except AssertionError, err:
                print err
                raise forms.ValidationError, 'invalid prefix or range'
            pr = parent.as_resource_range()
            if r.min < pr.min or r.max > pr.max:
                raise forms.ValidationError, \
                        'range is outside parent range'
            if r.min == pr.min and r.max == pr.max:
                raise forms.ValidationError, \
                        'range is equal to parent'
            if parent.allocated:
                raise forms.ValidationError, 'prefix is assigned to child'
            for p in parent.children.all():
                c = p.as_resource_range()
                if c.min <= r.min <= c.max or c.min <= r.max <= c.max:
                    raise forms.ValidationError, \
                            'overlap with another child prefix: %s' % (c,)

            return self.cleaned_data
    return _wrapper(*args, **kwargs)

def PrefixAllocateForm(iv, child_set, *args, **kwargs):
    class _wrapper(forms.Form):
        child = forms.ModelChoiceField(initial=iv, queryset=child_set,
                required=False)
    return _wrapper(*args, **kwargs)

def PrefixRoaForm(prefix, *args, **kwargs):
    prefix_range = prefix.as_resource_range()

    class _wrapper(forms.Form):
        asns = forms.CharField(max_length=200, required=False,
                help_text='Comma-separated list of ASNs')
        max_length = forms.IntegerField(required=False,
                min_value=prefix_range.prefixlen(),
                max_value=prefix_range.datum_type.bits)

        def clean_max_length(self):
            v = self.cleaned_data.get('max_length')
            if not v:
                v = prefix_range.prefixlen()
            return v

        def clean_asns(self):
            try:
                v = asnset(self.cleaned_data.get('asns'))
                return ','.join(str(x) for x in sorted(v))
            except ValueError:
                raise forms.ValidationError, \
                        'Must be a list of integers separated by commas.'
            return self.cleaned_data['asns']

        def clean(self):
            if not prefix.is_prefix():
                raise forms.ValidationError, \
                        '%s can not be represented as a prefix.' % (prefix,)
            if prefix.allocated:
                raise forms.ValidationError, \
                        'Prefix is allocated to a child.'
            return self.cleaned_data

    return _wrapper(*args, **kwargs)

def PrefixDeleteForm(prefix, *args, **kwargs):
    class _wrapped(forms.Form):
        delete = forms.BooleanField(label='Yes, I want to delete this prefix:')

        def clean(self):
            v = self.cleaned_data.get('delete')
            if v:
                if not prefix.parent:
                    raise forms.ValidationError, \
                            'Can not delete prefix received from parent'
                if prefix.allocated:
                    raise forms.ValidationError, 'Prefix is allocated to child'
                if prefix.roa_requests.all():
                    raise forms.ValidationError, 'Prefix is used in your ROAs'
                if prefix.children.all():
                    raise forms.ValidationError, 'Prefix has been subdivided'
            return self.cleaned_data

    return _wrapped(*args, **kwargs)

# vim:sw=4 ts=8 expandtab
