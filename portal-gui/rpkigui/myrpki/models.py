from django.db import models
from django.contrib.auth.models import Group

class HandleField(models.CharField):
    def __init__(self, **kwargs):
        models.CharField.__init__(self, max_length=255, **kwargs)

class IPAddressField( models.CharField ):
    def __init__( self, **kwargs ):
        models.CharField.__init__(self, max_length=40, **kwargs)

class Conf(models.Model):
    '''This is the center of the universe, also known as a place to
    have a handle on a resource-holding entity.  It's the <self>
    in the rpkid schema.'''
    handle = HandleField(unique=True, db_index=True)
    owner = models.OneToOneField(Group)

    def __unicode__(self):
	return self.handle

class AddressRange(models.Model):
    '''An address range/prefix.'''
    lo = IPAddressField(blank=False)
    hi = IPAddressField(blank=False)
    # parent address range
    parent = models.ForeignKey('AddressRange', related_name='children',
            blank=True, null=True)
    allocated = models.ForeignKey('Child', related_name='address_range',
            blank=True, null=True)

    def __unicode__(self):
        if self.lo == self.hi:
            return u"address %s" % (self.lo,)
        else:
            return u"address range %s-%s" % (self.lo, self.hi)

    def get_absolute_url(self):
        return u'/myrpki/address/%d' % (self.pk,)

class Asn(models.Model):
    '''An ASN or range thereof.'''
    lo = models.IntegerField(blank=False)
    hi = models.IntegerField(blank=False)
    # parent asn range
    parent = models.ForeignKey('Asn', related_name='children',
            blank=True, null=True)
    allocated = models.ForeignKey('Child', related_name='asn',
            blank=True, null=True)

    def __unicode__(self):
	if self.lo == self.hi:
	    return u"ASN %d" % (self.lo,)
	else:
	    return u"ASNs %d-%d" % (self.lo, self.hi)

    def get_absolute_url(self):
        return u'/myrpki/asn/%d' % (self.pk,)

class Child(models.Model):
    conf = models.ForeignKey(Conf, related_name='children')
    handle = HandleField() # parent's name for child
    validity = models.DateTimeField()

    def __unicode__(self):
	return u"%s's child %s" % (self.conf, self.handle)

    def get_absolute_url(self):
        return u'/myrpki/child/%s' % (self.handle,)

    class Meta:
	verbose_name_plural = "children"
        # children of a specific configuration should be unique
        unique_together = ('conf', 'handle')

class Parent(models.Model):
    conf = models.ForeignKey(Conf, related_name='parents')
    handle = HandleField()
#    service_uri = models.URLField( verify_exists=False )
#    sia_base = models.URLField( verify_exists=False )

    #address_range = models.ManyToManyField(AddressRange, blank=True,
    #       related_name='from_parent')
    #asn = models.ManyToManyField(Asn, related_name='from_parent', blank=True)

    def __unicode__(self):
	return u"%s's parent %s" % (self.conf, self.handle)

    def get_absolute_url(self):
        return u'/myrpki/parent/%s' % (self.handle,)

    class Meta:
        # parents of a specific configuration should be unique
        unique_together = ('conf', 'handle')

class ResourceCert(models.Model):
    parent = models.ForeignKey(Parent, related_name='resources')

    # resources granted from my parent
    asn = models.ManyToManyField(Asn, related_name='from_cert', blank=True,
            null=True)
    address_range = models.ManyToManyField(AddressRange, related_name='from_cert',
            blank=True, null=True)

    # unique id for this resource certificate
    # FIXME: URLField(verify_exists=False) doesn't seem to work - the admin
    # editor won't accept a rsync:// scheme as valid
    uri = models.CharField(max_length=200)

    # certificate validity period
    not_before = models.DateTimeField()
    not_after = models.DateTimeField()

    def get_absolute_url(self):
        return u"/myrpki/resource/%d" % (self.pk,)
    
    def __unicode__(self):
        return u"%s's resource cert from parent %s" % (self.parent.conf.handle,
                self.parent.handle)

class Roa(models.Model):
    conf = models.ForeignKey(Conf, related_name='roas')
    prefix = models.ManyToManyField(AddressRange)
    max_len = models.IntegerField()
    asn = models.IntegerField()
    comments = models.TextField()
    active = models.BooleanField()

    def __unicode__(self):
	return u"%s's ROA for %d" % (self.conf, self.asn)

    def get_absolute_url(self):
        return u'/myrpki/roa/%d' % (self.pk, )

# vim:sw=4 ts=8 expandtab
