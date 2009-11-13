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
    conf = models.ForeignKey( 'Conf' )
    name = models.CharField( unique=True, max_length=255 )
    data = models.TextField()
    def __unicode__( self ):
	return self.name

class Conf( models.Model ):
    handle = HandleField( unique=True, db_index=True )
    repository_bpki_cert = models.ForeignKey( Cert,
                                        related_name='conf_bpki_cert' )
    my_bpki_ta = models.ForeignKey( Cert, related_name='conf_my_ta' )
    repository_handle = HandleField()
    owner = models.OneToOneField( Group )

class Child( models.Model ):
    conf = models.ForeignKey( Conf )
    handle = HandleField()
    validity = models.DateTimeField()
    bpki_cert = models.ForeignKey( Cert )

class Prefix( models.Model ):
    child = models.ForeignKey( Child )
    lo = IPAddressField()
    hi = IPAddressField()

class Asn( models.Model ):
    child = models.ForeignKey( Child )
    min = models.IntegerField()
    max = models.IntegerField()

class Parent( models.Model ):
    conf = models.ForeignKey( Conf )
    handle = HandleField( unique=True )
    service_uri = models.URLField( verify_exists=False )
    cms_bpki_cert = models.ForeignKey( Cert, related_name='parent_cms' )
    https_bpki_cert = models.ForeignKey( Cert, related_name='parent_https' )
    my_handle = HandleField()
    sia_base = models.URLField( verify_exists=False )

# This table is really owned by the publication server.
#class PubClient( models.Model ):
#    handle = models.CharField( unique=True, max_length=255 )
#    bpki_cert = models.ForeignKey( Cert )
#    sia_base = models.URLField( verify_exists=False )

class Roa( models.Model ):
    conf = models.ForeignKey( Conf )
    prefix = IPAddressField()
    len = models.IntegerField()
    max_len = models.IntegerField()
    asn = models.IntegerField()
    active =  models.BooleanField()
    comments = models.TextField()
    group = models.CharField( max_length=40 )
