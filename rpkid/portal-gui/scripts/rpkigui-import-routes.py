# Copyright (C) 2012  SPARTA, Inc. a Parsons Company
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND SPARTA DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL SPARTA BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

__version__ = '$Id$'

import itertools
import _mysql_exceptions
import optparse
import os.path
import re
import sys
import struct
import subprocess

from django.db import transaction, connection

from rpki.resource_set import resource_range_ipv4, resource_range_ipv6
import rpki.gui.app.timestamp

# globals
DEBUG = False
VERBOSE = False
BGPDUMP = 'bgpdump'
PREFIXES = {}


class InvalidPrefix(Exception):
    pass


def debug(s):
    if DEBUG:
        print s


def log(s):
    if VERBOSE:
        print s


def parse_text(f):
    ip_re = re.compile(r'^[0-9a-fA-F:.]+/\d{1,3}$')
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
                # validate the prefix since the "sh ip bgp" output is sometimes
                # corrupt by no space between the prefix and the next hop IP
                # address.

                if not ip_re.match(prefix):
                    net, bits = prefix.split('/')
                    if len(bits) > 2 and int(bits[0]) <= 3:
                        s = ['mask for %s looks fishy...' % prefix]
                        prefix = '%s/%s' % (net, bits[0:2])
                        s.append('assuming it should be %s' % prefix)
                        log(' '.join(s))
                    if not ip_re.match(prefix):
                        raise InvalidPrefix(prefix)
                last_prefix = prefix
            elif origin_as == last_asn:
                # we are only interested in origins, so skip alternate paths
                # to same origin as last entry.
                continue
            last_asn = origin_as

            asns = PREFIXES.get(prefix)
            if not asns:
                asns = set()
                PREFIXES[prefix] = asns
            asns.add(int(origin_as))

        except InvalidPrefix:
            log('skipping bad entry: ' + row)


def parse_mrt(f):
    # filter input through bgpdump
    pipe = subprocess.Popen([BGPDUMP, '-m', '-v', '-'], stdin=f,
                            stdout=subprocess.PIPE)

    last_prefix = None
    last_as = None
    for e in pipe.stdout.readlines():
        a = e.split('|')
        prefix = a[5]
        try:
            origin_as = int(a[6].split()[-1])
        except ValueError:
            # skip AS_SETs
            continue

        if prefix != last_prefix:
            last_prefix = prefix
        elif last_as == origin_as:
            continue
        last_as = origin_as

        asns = PREFIXES.get(prefix)
        if not asns:
            asns = set()
            PREFIXES[prefix] = asns
        asns.add(origin_as)

    pipe.wait()
    if pipe.returncode:
        raise ProgException('bgpdump exited with code %d' % pipe.returncode)


def commit():
    "Write the PREFIXES dict into the appropriate database table."
    # auto-detect the IP version
    sample_ip = PREFIXES.iterkeys().next()
    if ':' in sample_ip:
        ip_version = 6
        range_class = resource_range_ipv6
        value_xform = lambda v: struct.pack('!QQ', (long(v) >> 64) & 0xffffffffffffffffL, long(v) & 0xFFFFFFFFFFFFFFFFL)
        table = 'routeview_routeoriginv6'
    else:
        ip_version = 4
        range_class = resource_range_ipv4
        value_xform = long
        table = 'routeview_routeorigin'

    log('Inserting data into table...')

    debug('auto-detected IP version %d prefixes' % ip_version)

    cursor = connection.cursor()

    try:
        debug('Dropping existing staging table...')
        cursor.execute('DROP TABLE IF EXISTS %s_new' % table)
    except _mysql_exceptions.Warning:
        pass

    debug('Creating staging table...')
    cursor.execute('CREATE TABLE %(table)s_new LIKE %(table)s' % {'table': table})

    debug('Disabling autocommit...')
    cursor.execute('SET autocommit=0')

    debug('Adding rows to table...')
    sql = "INSERT INTO %s_new SET asn=%%s, prefix_min=%%s, prefix_max=%%s" % table

    for prefix, asns in PREFIXES.iteritems():
        rng = range_class.parse_str(prefix)
        cursor.executemany(sql, [(asn, value_xform(rng.min),
            value_xform(rng.max)) for asn in asns])

    debug('Committing...')
    cursor.execute('COMMIT')

    try:
        debug('Dropping old table...')
        cursor.execute('DROP TABLE IF EXISTS %s_old' % table)
    except _mysql_exceptions.Warning:
        pass

    debug('Swapping staging table with live table...')
    cursor.execute('RENAME TABLE %(table)s TO %(table)s_old, %(table)s_new TO %(table)s' % {'table': table})

    transaction.commit_unless_managed()

    debug('Updating timestamp metadata...')
    rpki.gui.app.timestamp.update('bgp_v4_import' if ip_version == 4 else 'bgp_v6_import')


class ProgException(Exception):
    pass


class BadArgument(ProgException):
    pass


class UnknownInputType(ProgException):
    pass


class PipeFailed(ProgException):
    pass


if __name__ == '__main__':
    parser = optparse.OptionParser(usage='%prog [options] PATH',
            description="""This tool is used to import the IPv4/6 BGP table dumps
from routeviews.org into the RPKI Web Portal database.  If the
input file is a bzip2 compressed file, it will be decompressed
automatically.""")
    parser.add_option('-t', '--type', dest='filetype', metavar='TYPE',
                      help='Specify the input file type (auto, text, mrt) [Default: %default]')
    parser.add_option('-d', '--debug', dest='debug', action='store_true',
                      help='Enabling debugging output [Default: %default]')
    parser.add_option('-v', '--verbose', dest='verbose', action='store_true',
                      help='Enable verbose output [Default: %default]')
    parser.add_option('-u', '--bunzip2', dest='bunzip', metavar='PROG',
                      help='Specify bunzip2 program to use')
    parser.add_option('-b', '--bgpdump', dest='bgpdump', metavar='PROG',
                      help='Specify path to bgdump binary')
    parser.set_defaults(debug=False, verbose=False, filetype='auto')
    options, args = parser.parse_args()

    DEBUG = options.debug
    VERBOSE = options.verbose
    if options.bgpdump:
        BGPDUMP = os.path.expanduser(options.bgpdump)

    try:
        if len(args) != 1:
            raise BadArgument('no filename specified, or more than one filename specified')
        filename = args[0]

        if options.filetype == 'auto':
            # try to determine input type from filename, based on the default
            # filenames from archive.routeviews.org
            bname = os.path.basename(filename)
            if bname.startswith('oix-full-snapshot-latest'):
                filetype = 'text'
            elif bname.startswith('rib.'):
                filetype = 'mrt'
            else:
                raise UnknownInputType('unable to automatically determine input file type')
            debug('auto-detected import format as "%s"' % filetype)
        else:
            filetype = options.filetype

        pipe = None
        if filename.endswith('.bz2'):
            bunzip = 'bunzip2' if not options.bunzip else os.path.expanduser(options.bunzip)
            debug('Decompressing input file on the fly...')
            pipe = subprocess.Popen([bunzip, '--stdout', filename],
                                    stdout=subprocess.PIPE)
            input_file = pipe.stdout
        else:
            input_file = open(filename)

        try:
            log('Reading data...')
            dispatch = {'text': parse_text, 'mrt': parse_mrt}
            dispatch[filetype](input_file)
        except KeyError:
            raise UnknownInputType('"%s" is an unknown input file type' % filetype)

        if pipe:
            debug('Waiting for child to exit...')
            pipe.wait()
            if pipe.returncode:
                raise PipeFailed('Child exited code %d' % pipe.returncode)
            pipe = None
        else:
            input_file.close()

        commit()

        sys.exit(0)

    except ProgException, e:
        print >>sys.stderr, 'Error:', e
        sys.exit(1)
