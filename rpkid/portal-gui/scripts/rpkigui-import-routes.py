import sys, itertools, re

from django.db import transaction

from rpki.gui.routeview import models
from rpki.resource_set import resource_range_ipv4, resource_range_ipv6

f = open(sys.argv[1])

prefixes = {}

ip_re = re.compile(r'^[0-9a-fA-F:.]+/\d{1,3}$')

class InvalidPrefix(Exception):
    pass

for row in itertools.islice(f, 5, None):
    try:
        cols = row.split()

        prefix = cols[1]

        # validate the prefix since the "sh ip bgp" output is sometimes corrupt
        # by no space between the prefix and the next hop IP address.
        if not ip_re.match(prefix):
            raise InvalidPrefix(prefix)

        # index -1 is i/e/? for igp/egp
        origin_as = cols[-2]

        # skip AS_SETs
        if origin_as[0] == '{':
            continue

        asns = prefixes.get(prefix)
        if not asns:
            asns = set()
            prefixes[prefix] = asns
        asns.add(int(origin_as))

        #print 'prefix=%s asns=%s' % (prefix, asns)
    except InvalidPrefix, e:
        print >>sys.stderr, 'skipping bad entry: ' + row,
        print >>sys.stderr, e

f.close()

@transaction.commit_on_success
def commit():
    print 'Deleting rows from table...'
    models.RouteOrigin.objects.all().delete()

    for prefix, asns in prefixes.iteritems():
        family = 6 if ':' in prefix else 4
        cls = resource_range_ipv6 if family == 6 else resource_range_ipv4
        rng = cls.parse_str(prefix)

        for asn in asns:
            print 'Creating row for prefix=%s asn=%d' % (prefix, asn)
            models.RouteOrigin.objects.create(prefix_min=rng.min, prefix_max=rng.max, family=family, asn=asn)

commit()
