import django.db.models
import rpki.gui.models

class RouteOrigin(rpki.gui.models.PrefixV4):
    "Represents a BGP routing table entry."

    asn = django.db.models.PositiveIntegerField(help_text='origin AS', null=False)
        
    def __unicode__(self):
        return u"AS%d's route origin for %s" % (self.asn, self.get_prefix_display())

# vim:sw=4 ts=8 expandtab
