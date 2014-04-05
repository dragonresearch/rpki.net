from rpki.gui.script_util import setup
setup()

from django.db import transaction
from django.db.models import Count
from rpki.gui.app.models import ROARequest
from rpki.irdb.zookeeper import Zookeeper

handles = set()


@transaction.commit_on_success
def flatten():
    for roa in ROARequest.objects.annotate(num_prefixes=Count('prefixes')).filter(num_prefixes__gt=1):
        print 'splitting roa for AS%d' % roa.asn
        for pfx in roa.prefixes.all():
            # create new roa objects for each prefix
            newroa = ROARequest.objects.create(
                issuer=roa.issuer,
                asn=roa.asn)
            newroa.prefixes.create(
                version=pfx.version,
                prefix=pfx.prefix,
                prefixlen=pfx.prefixlen,
                max_prefixlen=pfx.max_prefixlen
            )
        roa.delete()
        handles.add(roa.issuer.handle)

flatten()

if handles:
    # poke rpkid to run the cron job for each handle that had a roa change
    z = Zookeeper()
    for h in handles:
        z.reset_identity(h)
        z.run_rpkid_now()
