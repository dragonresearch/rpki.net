# $Id$

from django import forms
import models
from rpkigui.myrpki.misc import str_to_addr

def ConfCertForm(request):
    class CertForm(forms.ModelForm):
        class Meta:
            model = models.Cert
            exclude = ('conf')

        def save(self):
            obj = forms.ModelForm.save(self, commit=False)
            obj.conf = request.session['handle']
            obj.save()
            return obj

    return CertForm

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

class ChildImportForm(ImportForm):
    validity = forms.DateTimeField(help_text='YYYY-MM-DD')

def RangeForm(field_type, *args, **kwargs):
    '''Generic form with an upper and lower bound.'''
    class wrapped(forms.Form):
        lo = field_type(label='Lower Bound')
        hi = field_type(label='Upper Bound')

        def __init__(self, *inargs, **inkwargs):
            forms.Form.__init__(self, *inargs, **inkwargs)

        def clean(self):
            lo = self.cleaned_data.get('lo')
            hi = self.cleaned_data.get('hi')
            if lo > hi:
                # should we just fix it?
                raise forms.ValidationError, 'Lower bound is higher than upper.'
            return self.cleaned_data

    return wrapped(*args, **kwargs)

def AddressRangeForm(*args, **kwargs):
    '''Form used for entering address ranges.'''
    return RangeForm(forms.IPAddressField, *args, **kwargs)

class AsnField(forms.IntegerField):
    def __init__(self, *args, **kwargs):
        forms.IntegerField.__init__(self, *args, **kwargs)

    def clean(self, val):
        val = super(AsnField, self).clean(val)
        if val < 0:
            raise forms.ValidationError, 'Value out of range.'
        return val

def AsnRangeForm(*args, **kwargs):
    '''Form used for entering asn ranges.'''
    return RangeForm(AsnField, *args, **kwargs)
    
def get_pk(child):
    '''return the primary key or None if child is None'''
    return child.pk if child else None

def SubOrAssignForm(handle, addr, field_type, *args, **kwargs):
    '''Closure to select child of the specified handle.'''
    class Wrapper(forms.Form):
        '''Form for the address view to allow the user to subdivide or assign
    the block to a child.'''
        lo = field_type(required=False, label='Lower bound')
        hi = field_type(required=False, label='Upper bound')
        child = forms.ModelChoiceField(required=False, label='Assign to child',
                initial=get_pk(addr.allocated), queryset=handle.children.all())

        def clean_lo(self):
            '''validate the self.lo field to ensure it is within the
            parent's range.'''
            lo = self.cleaned_data['lo']
            if lo == '':
                lo = None
            if lo != None:
                if lo < addr.lo or lo > addr.hi:
                    raise forms.ValidationError, 'Value is out of range of parent.'
                # ensure there is no overlap with other children
                for c in addr.children.all():
                    if lo >= c.lo and lo <= c.hi:
                        raise forms.ValidationError, \
                                'Value overlaps another suballocation.'
            return lo

        def clean_hi(self):
            '''validate the self.hi field to ensure it is within the
            parent's range.'''
            hi = self.cleaned_data['hi']
            if hi == '':
                hi = None
            if hi != None:
                if hi < addr.lo or hi > addr.hi:
                    raise forms.ValidationError, \
                        'Value is out of range of parent.'
                # ensure there is no overlap with other children
                for c in addr.children.all():
                    if hi >= c.lo and hi <= c.hi:
                        raise forms.ValidationError, \
                                'Value overlaps another suballocation.'
            return hi

        def clean_child(self):
            if self.cleaned_data['child'] and addr.children.count():
                raise forms.ValidationError, \
                        "Can't allocate a subdivided address."
            return self.cleaned_data['child']

        def clean(self):
            clean_data = self.cleaned_data
            child = clean_data.get('child')
            lo = clean_data.get('lo')
            hi = clean_data.get('hi')
            loset = lo != '' and lo != None
            hiset = hi != '' and hi != None
            if (child and (loset or hiset)):
                raise forms.ValidationError, \
                        'Either a range or a child must be set, but not both.'
            elif (lo and not hi) or (hi and not lo):
                raise forms.ValidationError, \
                        'Both a high and low range must be specified.'
            return clean_data

    return Wrapper(*args, **kwargs)

def SubOrAssignAddressForm(handle, addr, *args, **kwargs):
    return SubOrAssignForm(handle, addr, forms.IPAddressField, *args, **kwargs)

def SubOrAssignAsnForm(handle, asn, *args, **kwargs):
    return SubOrAssignForm(handle, asn, forms.IntegerField, *args, **kwargs)

def RoaForm(handle, pk=None, initval=[], *args, **kwargs):
    vals = models.AddressRange.objects.filter(from_parent__in=handle.parents.all())

    class Wrapped(forms.Form):
        asn = AsnField(initial=pk)
        prefix = forms.ModelMultipleChoiceField(label='Prefixes',
                queryset=vals, initial=initval)

    return Wrapped(*args, **kwargs)

def PrefixSplitForm(prefix, *args, **kwargs):
    class _wrapper(forms.Form):
        lo = forms.IPAddressField()
        hi = forms.IPAddressField()

        def clean_lo(self):
            lo = self.cleaned_data.get('lo')
            # convert from string to long representation
            try:
                loaddr = str_to_addr(lo)
            except socket.error:
                raise forms.ValidationError, 'Invalid IP address string'
            pfx_loaddr = str_to_addr(prefix.lo)
            pfx_hiaddr = str_to_addr(prefix.hi)
            if type(loaddr) != type(pfx_hiaddr):
                raise forms.ValidationError, 'Not the same IP address type as parent'
            if loaddr < pfx_loaddr or loaddr > pfx_hiaddr:
                raise forms.ValidationError, 'Value out of range of parent prefix'
            return lo

        def clean_hi(self):
            hi = self.cleaned_data.get('hi')
            # convert from string to long representation
            try:
                hiaddr = str_to_addr(hi)
            except socket.error:
                raise forms.ValidationError, 'Invalid IP address string'
            pfx_loaddr = str_to_addr(prefix.lo)
            pfx_hiaddr = str_to_addr(prefix.hi)
            if type(hiaddr) != type(pfx_loaddr):
                raise forms.ValidationError, 'Not the same IP address type as parent'
            if hiaddr < pfx_loaddr or hiaddr > pfx_hiaddr:
                raise forms.ValidationError, 'Value out of range of parent prefix'
            return hi

        def clean(self):
            hi = self.cleaned_data.get('hi')
            lo = self.cleaned_data.get('lo')
            # hi or lo may be None if field validation failed
            if hi and lo:
                # convert from string to long representation
                hiaddr = str_to_addr(hi)
                loaddr = str_to_addr(lo)
                if hiaddr < loaddr:
                    raise forms.ValidationError, 'Hi value is smaller than Lo'
                if prefix.allocated:
                    raise forms.ValidationError, 'Prefix is assigned to child'
            return self.cleaned_data

    return _wrapper(*args, **kwargs)

def PrefixAllocateForm(iv, child_set, *args, **kwargs):
    class _wrapper(forms.Form):
        child = forms.ModelChoiceField(initial=iv, queryset=child_set, required=False)
    return _wrapper(*args, **kwargs)

class PrefixRoaForm(forms.Form):
    asns = forms.CharField(max_length=200, required=False)

    def clean_asns(self):
        try:
            v = [int(d) for d in self.cleaned_data['asns'].split(',') if d.strip() != '']
            if any([x for x in v if x < 0]):
                raise forms.ValidationError, 'must be a positive integer'
            return ','.join(str(x) for x in sorted(v))
        except ValueError:
            raise forms.ValidationError, 'must be a list of integers separated by commas'
        return self.cleaned_data['asns']

def PrefixDeleteForm(prefix, *args, **kwargs):
    class _wrapped(forms.Form):
        delete = forms.BooleanField(label='Yes, I want to delete this prefix:')

        def clean(self):
            v = self.cleaned_data.get('delete')
            if v:
                if not prefix.parent:
                    raise forms.ValidationError, 'Can not delete prefix received from parent'
                if prefix.allocated:
                    raise forms.ValidationError, 'Prefix is allocated to child'
                if prefix.asns:
                    raise forms.ValidationError, 'Prefix is used in your ROAs'
                if prefix.children.all():
                    raise forms.ValidationError, 'Prefix has been subdivided'
            return self.cleaned_data

    return _wrapped(*args, **kwargs)

# vim:sw=4 ts=8 expandtab
