from django import forms
from myrpki import models

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

        #def __init__(self, *inargs, **inkwargs):
        #   super(Wrapper, self).__init__(*inargs, **inkwargs)
        #   if isinstance(addr, models.AddressRange):
        #       self.asn = forms.ModelChoiceField(required=False,
        #               label='Issue ROA', queryset=models.Asn.objects.all())

        def clean_lo(self):
            '''validate the self.lo field to ensure it is within the
            parent's range.'''
            lo = self.cleaned_data['lo']
            if lo is not None:
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
            if hi is not None:
                if hi < addr.lo or hi > addr.hi:
                    raise forms.ValidationError, 'Value is out of range of parent.'
                # ensure there is no overlap with other children
                for c in addr.children.all():
                    if hi >= c.lo and hi <= c.hi:
                        raise forms.ValidationError, \
                                'Value overlaps another suballocation.'
            return hi

        def clean_child(self):
            if self.cleaned_data['child'] and addr.children.count():
                raise forms.ValidationError, "Can't allocate a subdivided address."
            return self.cleaned_data['child']

        def clean(self):
            clean_data = self.cleaned_data
            child = clean_data.get('child')
            lo = clean_data.get('lo')
            hi = clean_data.get('hi')
            if child and (lo or hi):
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

def RoaForm(handle, pk=None, initcomment=None, initval=[], *args, **kwargs):
    vals = models.AddressRange.objects.filter(from_parent__in=handle.parents.all())

    class Wrapped(forms.Form):
        asn = AsnField(initial=pk)
        prefix = forms.ModelMultipleChoiceField(label='Prefixes',
                queryset=vals, initial=initval)
        comments = forms.CharField(required=False, initial=initcomment)

    return Wrapped(*args, **kwargs)
