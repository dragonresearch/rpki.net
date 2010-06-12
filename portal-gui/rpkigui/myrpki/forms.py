from django import forms
from myrpki import models

def ConfCertForm( request ):
    class CertForm( forms.ModelForm ):
	class Meta:
	    model = models.Cert
	    exclude = ( 'conf' )

	def save( self ):
	    obj = forms.ModelForm.save( self, commit=False )
	    obj.conf = request.session[ 'handle' ]
	    obj.save()
	    return obj

    return CertForm

