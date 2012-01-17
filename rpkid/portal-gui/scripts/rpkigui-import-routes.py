import sys, itertools, re
import struct
import _mysql_exceptions

from django.db import transaction, connection

from rpki.resource_set import resource_range_ipv4, resource_range_ipv6
from rpki.gui.app.models import Timestamp

f = open(sys.argv[1])

prefixes = {}

ip_re = re.compile(r'^[0-9a-fA-F:.]+/\d{1,3}$')

class InvalidPrefix(Exception):
    pass

last_prefix = None
last_asn = None

for row in itertools.islice(f, 5, None):
    try:
        cols = row.split()

        prefix = cols[1]

        # index -1 is i/e/? for igp/egp
        origin_as = cols[-2]

        # FIXME: skip AS_SETs
        if origin_as[0] == '{':
            continue

        # the output may contain multiple paths to the same origin.
        # if this is the same prefix as the last entry, we don't need
        # to validate it again.
        if prefix != last_prefix:
            # validate the prefix since the "sh ip bgp" output is sometimes corrupt
            # by no space between the prefix and the next hop IP address.

            if not ip_re.match(prefix):
                net, bits = prefix.split('/')
                if len(bits) > 2 and int(bits[0]) <= 3:
                    print 'mask for %s looks fishy...' % prefix,
                    prefix = '%s/%s' % (net, bits[0:2])
                    print 'assuming it should be %s' % prefix
                if not ip_re.match(prefix):
                    raise InvalidPrefix(prefix)
            last_prefix = prefix
        elif origin_as == last_asn:
            # we are only interested in origins, so skip alternate paths
            # to same origin as last entry.
            continue
        last_asn = origin_as

        asns = prefixes.get(prefix)
        if not asns:
            asns = set()
            prefixes[prefix] = asns
        asns.add(int(origin_as))

    except InvalidPrefix, e:
        print >>sys.stderr, 'skipping bad entry: ' + row,
        print >>sys.stderr, e

f.close()

def commit():
    cursor = connection.cursor()

    try:
        print 'Dropping existing staging table...'
        cursor.execute('DROP TABLE IF EXISTS routeview_routeorigin_new')
    except _mysql_exceptions.Warning:
        pass

    print 'Creating staging table...'
    cursor.execute('CREATE TABLE routeview_routeorigin_new LIKE routeview_routeorigin')

    print 'Disabling autocommit...'
    cursor.execute('SET autocommit=0')

    print 'Adding rows to table...'
    for prefix, asns in prefixes.iteritems():
        family = 6 if ':' in prefix else 4
        cls = resource_range_ipv6 if family == 6 else resource_range_ipv4
        rng = cls.parse_str(prefix)

        if family == 4:
            xform = long
        else:
            xform = lambda v: struct.pack('!QQ', (long(v) >> 64) &0xffffffffffffffffL, long(v) & 0xFFFFFFFFFFFFFFFFL)

        cursor.executemany("INSERT INTO routeview_routeorigin_new SET asn=%s, prefix_min=%s, prefix_max=%s",
                    [(asn, xform(rng.min), xform(rng.max)) for asn in asns])

    print 'Committing...'
    cursor.execute('COMMIT')

    try:
        print 'Dropping old table...'
        cursor.execute('DROP TABLE IF EXISTS routeview_routeorigin_old')
    except _mysql_exceptions.Warning:
        pass

    print 'Swapping staging table with live table...'
    cursor.execute('RENAME TABLE routeview_routeorigin TO routeview_routeorigin_old, routeview_routeorigin_new TO routeview_routeorigin')

    transaction.commit_unless_managed()

commit()

print 'Updating timestamp metadata...'
ts, created = Timestamp.objects.get_or_create(name='bgp_v4_import')
if not created: ts.save()

sys.exit(0)
