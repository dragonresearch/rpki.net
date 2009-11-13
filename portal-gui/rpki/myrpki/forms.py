from django import forms
from myrpki import models

# TODO: Point the cert.conf to the handle from the session
class CertForm( forms.ModelForm ):
    class Meta:
	model = models.Cert

