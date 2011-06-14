"""
$Id$

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

from django.contrib import admin
from rpki.gui.cacheview import models

class ASRangeAdmin(admin.ModelAdmin):
    pass

class AddressRangeAdmin(admin.ModelAdmin):
    pass

class CertAdmin(admin.ModelAdmin):
    pass

class ROAPrefixAdmin(admin.ModelAdmin):
    pass

class ROAAdmin(admin.ModelAdmin):
    pass

class GhostbusterAdmin(admin.ModelAdmin):
    pass

class ValidationStatusAdmin(admin.ModelAdmin):
    pass

admin.site.register(models.AddressRange, AddressRangeAdmin)
admin.site.register(models.ASRange, AddressRangeAdmin)
admin.site.register(models.Cert, CertAdmin)
admin.site.register(models.Ghostbuster, GhostbusterAdmin)
admin.site.register(models.ROA, ROAAdmin)
admin.site.register(models.ROAPrefix, ROAPrefixAdmin)
admin.site.register(models.ValidationStatus, ValidationStatusAdmin)

# vim:sw=4 ts=8
