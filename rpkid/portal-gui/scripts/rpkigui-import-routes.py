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
import time
import logging

from django.db import transaction, connection

from rpki.resource_set import resource_range_ipv4, resource_range_ipv6
from rpki.exceptions import BadIPResource
import rpki.gui.app.timestamp

# globals
BGPDUMP = 'bgpdump'
logger = logging.getLogger(__name__)


def parse_text(f):
    ip_re = re.compile(r'^[0-9a-fA-F:.]+/\d{1,3}$')
    last_prefix = None
    cursor = connection.cursor()
    range_class = resource_range_ipv4
    table = 'routeview_routeorigin'
    sql = "INSERT INTO %s_new SET asn=%%s, prefix_min=%%s, prefix_max=%%s" % table

    try:
        logger.info('Dropping existing staging table...')
        cursor.execute('DROP TABLE IF EXISTS %s_new' % table)
    except _mysql_exceptions.Warning:
        pass

    logger.info('Creating staging table...')
    cursor.execute('CREATE TABLE %(table)s_new LIKE %(table)s' % {'table': table})

    logger.info('Disabling autocommit...')
    cursor.execute('SET autocommit=0')

    logger.info('Adding rows to table...')
    for row in itertools.islice(f, 5, None):
        cols = row.split()

        # index -1 is i/e/? for igp/egp
        origin_as = cols[-2]
        # FIXME: skip AS_SETs
        if origin_as[0] == '{':
            continue

        prefix = cols[1]

        # validate the prefix since the "sh ip bgp" output is sometimes
        # corrupt by no space between the prefix and the next hop IP
        # address.
        net, bits = prefix.split('/')
        if len(bits) > 2:
            s = ['mask for %s looks fishy...' % prefix]
            prefix = '%s/%s' % (net, bits[0:2])
            s.append('assuming it should be %s' % prefix)
            logger.warning(' '.join(s))

        # the output may contain multiple paths to the same origin.
        # if this is the same prefix as the last entry, we don't need
        # to validate it again.
        #
        # prefixes are sorted, but the origin_as is not, so we keep a set to
        # avoid duplicates, and insert into the db once we've seen all the
        # origin_as values for a given prefix
        if prefix != last_prefix:
            # output routes for previous prefix
            if last_prefix is not None:
                try:
                    rng = range_class.parse_str(prefix)
                    rmin = long(rng.min)
                    rmax = long(rng.max)
                    cursor.executemany(sql, [(asn, rmin, rmax) for asn in asns])
                except BadIPResource:
                    logger.warning('skipping bad prefix: ' + prefix)

            asns = set()
            last_prefix = prefix

        asns.add(int(origin_as))

    logger.info('Committing...')
    cursor.execute('COMMIT')

    try:
        logger.info('Dropping old table...')
        cursor.execute('DROP TABLE IF EXISTS %s_old' % table)
    except _mysql_exceptions.Warning:
        pass

    logger.info('Swapping staging table with live table...')
    cursor.execute('RENAME TABLE %(table)s TO %(table)s_old, %(table)s_new TO %(table)s' % {'table': table})

    transaction.commit_unless_managed()

    logger.info('Updating timestamp metadata...')
    rpki.gui.app.timestamp.update('bgp_v4_import')


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


class ProgException(Exception):
    pass


class BadArgument(ProgException):
    pass


class UnknownInputType(ProgException):
    pass


class PipeFailed(ProgException):
    pass


if __name__ == '__main__':
    start_time = time.time()

    parser = optparse.OptionParser(usage='%prog [options] PATH',
            description="""This tool is used to import the IPv4/6 BGP table dumps
from routeviews.org into the RPKI Web Portal database.  If the
input file is a bzip2 compressed file, it will be decompressed
automatically.""")
    parser.add_option('-t', '--type', dest='filetype', metavar='TYPE',
                      help='Specify the input file type (auto, text, mrt) [Default: %default]')
    parser.add_option('-l', '--level', dest='log_level', default='INFO',
                      help='Set logging level [Default: %default]')
    parser.add_option('-u', '--bunzip2', dest='bunzip', metavar='PROG',
                      help='Specify bunzip2 program to use')
    parser.add_option('-b', '--bgpdump', dest='bgpdump', metavar='PROG',
                      help='Specify path to bgdump binary')
    parser.set_defaults(debug=False, verbose=False, filetype='auto')
    options, args = parser.parse_args()

    v = getattr(logging, options.log_level.upper())
    logger.setLevel(v)
    logging.basicConfig()
    logger.info('logging level set to ' + logging.getLevelName(v))

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
            logging.info('Detected import format as "%s"' % filetype)
        else:
            filetype = options.filetype

        pipe = None
        if filename.endswith('.bz2'):
            bunzip = 'bunzip2' if not options.bunzip else os.path.expanduser(options.bunzip)
            logging.info('Decompressing input file on the fly...')
            pipe = subprocess.Popen([bunzip, '--stdout', filename],
                                    stdout=subprocess.PIPE)
            input_file = pipe.stdout
        else:
            input_file = open(filename)

        try:
            dispatch = {'text': parse_text, 'mrt': parse_mrt}
            dispatch[filetype](input_file)
        except KeyError:
            raise UnknownInputType('"%s" is an unknown input file type' % filetype)

        if pipe:
            logging.debug('Waiting for child to exit...')
            pipe.wait()
            if pipe.returncode:
                raise PipeFailed('Child exited code %d' % pipe.returncode)
            pipe = None
        else:
            input_file.close()

        logger.info('Elapsed time %d secs' % (time.time() - start_time))
        rc = 0

    except ProgException, e:
        logger.exception(e)
        rc = 1

    logging.shutdown()
    sys.exit(rc)
