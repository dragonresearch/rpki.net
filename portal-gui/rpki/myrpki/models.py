from django.db import models
from django.contrib.auth.models import Group

# TO DO:
# URL: text?
class HandleField( models.CharField ):
    def __init__( self, **kwargs ):
        models.CharField.__init__( self, max_length=255, **kwargs )

class IPAddressField( models.CharField ):
    def __init__( self, **kwargs ):
        models.CharField.__init__( self, max_length=40, **kwargs )

class Cert( models.Model ):
    name = models.CharField( unique=True, max_length=255 )
    data = models.TextField()
    def __unicode__( self ):
	return self.name

class Conf( models.Model ):
    '''This is the center of the universe.
    '''
    handle = HandleField( unique=True, db_index=True )
    repository_bpki_cert = models.ForeignKey( Cert,
                                        related_name='conf_bpki_cert' )
    my_bpki_ta = models.ForeignKey( Cert, related_name='conf_my_ta' )
    repository_handle = HandleField()
    owner = models.OneToOneField( Group )
    def __unicode__( self ):
	return self.handle

class AddressRange( models.Model ):
    lo = IPAddressField()
    hi = IPAddressField()
    parent = models.ForeignKey( 'AddressRange', related_name='children',
    			        blank=True, null=True )
    def __unicode__( self ):
	return u"address range %s-%s" % ( self.lo, self.hi )

class Asn( models.Model ):
    min = models.IntegerField()
    max = models.IntegerField()
    parent = models.ForeignKey( 'Asn', related_name='children',
			        blank=True, null=True )
    def __unicode__( self ):
	if self.min == self.max:
	    return u"ASN %d" % ( self.min )
	else:
	    return u"ASNs %d-%d" % ( self.min, self.max )

class Child( models.Model ):
    conf = models.ForeignKey( Conf )
    handle = HandleField()
    validity = models.DateTimeField()
    bpki_cert = models.ForeignKey( Cert )
    address_range = models.ManyToManyField( AddressRange )
    asn = models.ManyToManyField( Asn )
    def __unicode__( self ):
	return u"%s's child %s" % ( self.conf, self.handle )

class Parent( models.Model ):
    conf = models.ForeignKey( Conf )
    handle = HandleField( unique=True )
    service_uri = models.URLField( verify_exists=False )
    cms_bpki_cert = models.ForeignKey( Cert, related_name='parent_cms' )
    https_bpki_cert = models.ForeignKey( Cert, related_name='parent_https' )
    my_handle = HandleField()
    sia_base = models.URLField( verify_exists=False )
    address_range = models.ManyToManyField( AddressRange,
					    related_name='from_parent' )
    asn = models.ManyToManyField( Asn, related_name='from_parent' )
    def __unicode__( self ):
	return u"%s's parent %s" % ( self.conf, self.handle )

# This table is really owned by the publication server.
#class PubClient( models.Model ):
#    handle = models.CharField( unique=True, max_length=255 )
#    bpki_cert = models.ForeignKey( Cert )
#    sia_base = models.URLField( verify_exists=False )

class Roa( models.Model ):
    conf = models.ForeignKey( Conf )
    prefix = models.ManyToManyField( AddressRange )
    max_len = models.IntegerField()
    asn = models.IntegerField()
    active =  models.BooleanField()
    comments = models.TextField()
    def __unicode__( self ):
	return u"%s's ROA for %d" % ( self.conf, self.asn )
