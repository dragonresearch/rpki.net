"""
$Id$

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

from django import forms
from django.contrib import admin
from rpki.gui.app import models

class ConfAdmin( admin.ModelAdmin ):
    pass

class ChildAdmin( admin.ModelAdmin ):
    pass

class AddressRangeAdmin( admin.ModelAdmin ):
    #list_display = ('__unicode__', 'lo', 'hi')
    pass

class AsnAdmin( admin.ModelAdmin ):
    #list_display = ('__unicode__',)
    pass

class ParentAdmin( admin.ModelAdmin ):
    pass

class RoaAdmin( admin.ModelAdmin ):
    pass

class ResourceCertAdmin(admin.ModelAdmin):
    pass

class RoaRequestAdmin(admin.ModelAdmin):
    pass

admin.site.register(models.Conf, ConfAdmin)
admin.site.register(models.Child, ChildAdmin)
admin.site.register(models.AddressRange, AddressRangeAdmin)
admin.site.register(models.Asn, AsnAdmin)
admin.site.register(models.Parent, ParentAdmin)
admin.site.register(models.Roa, RoaAdmin)
admin.site.register(models.RoaRequest, RoaRequestAdmin)
admin.site.register(models.ResourceCert, ResourceCertAdmin)
