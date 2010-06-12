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
    '''A certificate, relating to a single configuration.'''
    conf = models.ForeignKey( 'Conf', related_name='certs' )
    name = models.CharField( unique=True, max_length=255 )
    data = models.TextField()
    def __unicode__( self ):
	return "%s's %s" % ( self.conf, self.name )

class Conf( models.Model ):
    '''This is the center of the universe, also known as a place to
    have a handle on a resource-holding entity.  It's the <self>
    in the rpkid schema.
    '''
    handle = HandleField( unique=True, db_index=True )
    repository_bpki_cert = models.ForeignKey( Cert,
                                        related_name='conf_bpki_cert',
					null=True, blank=True )
    my_bpki_ta = models.ForeignKey( Cert, related_name='conf_my_ta',
					  null=True, blank=True )
    repository_handle = HandleField()
    owner = models.OneToOneField( Group )
    def __unicode__( self ):
	return self.handle

class AddressRange( models.Model ):
    '''An address range / prefix.'''
    lo = IPAddressField()
    hi = IPAddressField()
    parent = models.ForeignKey( 'AddressRange', related_name='children',
    			        blank=True, null=True )
    def __unicode__( self ):
	return u"address range %s-%s" % ( self.lo, self.hi )

class Asn( models.Model ):
    '''An ASN or range thereof.'''
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
    conf = models.ForeignKey( Conf, related_name='children' )
    handle = HandleField()
    validity = models.DateTimeField()
    bpki_cert = models.ForeignKey( Cert, related_name='child_bpki' )
    # It may seem strange that the address_range and asn fields
    # are ManyToManyFields.  Why not simply a ForeignKey from an Asn
    # and an AddressRange?  This is for transition.  When a resource
    # is moving from one child to another, we may have to be delegating
    # it to both children at once.
    address_range = models.ManyToManyField( AddressRange, blank=True )
    asn = models.ManyToManyField( Asn, blank=True )
    def __unicode__( self ):
	return u"%s's child %s" % ( self.conf, self.handle )
    class Meta:
	verbose_name_plural = "children"


class Parent( models.Model ):
    conf = models.ForeignKey( Conf, related_name='parents' )
    handle = HandleField( unique=True )
    service_uri = models.URLField( verify_exists=False )
    cms_bpki_cert = models.ForeignKey( Cert, related_name='parent_cms' )
    https_bpki_cert = models.ForeignKey( Cert, related_name='parent_https' )
    my_handle = HandleField()
    sia_base = models.URLField( verify_exists=False )
    # It may seem strange that the address_range and asn fields
    # are ManyToManyFields.  Why not simply a ForeignKey from an Asn
    # and an AddressRange?  This is for transition.  When a resource
    # is moving from one parent to another, we may be receiving the
    # resource from both parents at once.
    address_range = models.ManyToManyField( AddressRange,
					    related_name='from_parent' )
    asn = models.ManyToManyField( Asn, related_name='from_parent' )
    def __unicode__( self ):
	return u"%s's parent %s" % ( self.conf, self.handle )

class Roa( models.Model ):
    conf = models.ForeignKey( Conf, related_name='roas' )
    prefix = models.ManyToManyField( AddressRange )
    max_len = models.IntegerField()
    asn = models.IntegerField()
    active =  models.BooleanField()
    comments = models.TextField()
    def __unicode__( self ):
	return u"%s's ROA for %d" % ( self.conf, self.asn )
