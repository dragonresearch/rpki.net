import sys, itertools, re

from django.db import transaction, connection

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

def commit():
    cursor = connection.cursor()

    # an OperationalError exception is thrown when the index doesn't exist
    try:
        print 'Removing existing index...'
        cursor.execute('DROP INDEX routeview_routeorigin_idx ON routeview_routeorigin')
    except Exception, e:
        print type(e)
        print e
    cursor.execute('BEGIN')

    print 'Deleting rows from table...'
    cursor.execute('DELETE FROM routeview_routeorigin')

    print 'Adding rows to table...'
    for prefix, asns in prefixes.iteritems():
        family = 6 if ':' in prefix else 4
        cls = resource_range_ipv6 if family == 6 else resource_range_ipv4
        rng = cls.parse_str(prefix)

        cursor.executemany("INSERT INTO routeview_routeorigin SET family=%s, asn=%s, prefix_min=X%s, prefix_max=X%s",
                    [(family, asn, '%032x' % rng.min, '%032x' % rng.max) for asn in asns])

    print 'Committing...'
    cursor.execute('COMMIT')

    print 'Creating index on table...'
    cursor.execute('CREATE INDEX routeview_routeorigin_idx ON routeview_routeorigin (family, prefix_min, prefix_max)')

    transaction.commit_unless_managed()

commit()
