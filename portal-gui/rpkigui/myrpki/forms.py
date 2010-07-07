# $Id$

from django import forms

import rpki.ipaddrs

from rpkigui.myrpki import models
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

def PrefixSplitForm(prefix, *args, **kwargs):
    class _wrapper(forms.Form):
        lo = forms.IPAddressField()
        hi = forms.IPAddressField()

        def clean_lo(self):
            lo = self.cleaned_data.get('lo')
            # convert from string to long representation
            try:
                loaddr = rpki.ipaddrs.parse(lo)
            except socket.error:
                raise forms.ValidationError, 'Invalid IP address string'
            pfx_loaddr = rpki.ipaddrs.parse(prefix.lo)
            pfx_hiaddr = rpki.ipaddrs.parse(prefix.hi)
            if type(loaddr) != type(pfx_hiaddr):
                raise forms.ValidationError, \
                        'Not the same IP address type as parent'
            if loaddr < pfx_loaddr or loaddr > pfx_hiaddr:
                raise forms.ValidationError, \
                        'Value out of range of parent prefix'
            return lo

        def clean_hi(self):
            hi = self.cleaned_data.get('hi')
            # convert from string to long representation
            try:
                hiaddr = rpki.ipaddrs.parse(hi)
            except socket.error:
                raise forms.ValidationError, 'Invalid IP address string'
            pfx_loaddr = rpki.ipaddrs.parse(prefix.lo)
            pfx_hiaddr = rpki.ipaddrs.parse(prefix.hi)
            if type(hiaddr) != type(pfx_loaddr):
                raise forms.ValidationError, \
                        'Not the same IP address type as parent'
            if hiaddr < pfx_loaddr or hiaddr > pfx_hiaddr:
                raise forms.ValidationError, \
                        'Value out of range of parent prefix'
            return hi

        def clean(self):
            hi = self.cleaned_data.get('hi')
            lo = self.cleaned_data.get('lo')
            # hi or lo may be None if field validation failed
            if hi and lo:
                # convert from string to long representation
                hiaddr = rpki.ipaddrs.parse(hi)
                loaddr = rpki.ipaddrs.parse(lo)
                if hiaddr < loaddr:
                    raise forms.ValidationError, 'Hi value is smaller than Lo'
                if prefix.allocated:
                    raise forms.ValidationError, 'Prefix is assigned to child'
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
                if prefix.asns:
                    raise forms.ValidationError, 'Prefix is used in your ROAs'
                if prefix.children.all():
                    raise forms.ValidationError, 'Prefix has been subdivided'
            return self.cleaned_data

    return _wrapped(*args, **kwargs)

# vim:sw=4 ts=8 expandtab
