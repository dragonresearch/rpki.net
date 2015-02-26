import django.contrib.auth.forms

class AuthenticationForm(django.contrib.auth.forms.AuthenticationForm):
  def __init__(self, *args, **kwargs):
    super(AuthenticationForm, self).__init__(*args, **kwargs)

    # add bootstrap css classes
    self.fields['username'].widget.attrs.update({'class': 'form-control'})
    self.fields['password'].widget.attrs.update({'class': 'form-control'})
