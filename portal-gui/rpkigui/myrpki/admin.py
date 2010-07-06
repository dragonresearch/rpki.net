from django import forms
from django.contrib import admin
from rpkigui.myrpki import models

class ConfAdmin( admin.ModelAdmin ):
    pass

class ChildAdmin( admin.ModelAdmin ):
    pass

class AddressRangeAdmin( admin.ModelAdmin ):
    pass

class AsnAdmin( admin.ModelAdmin ):
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
