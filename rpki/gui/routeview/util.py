# Copyright (C) 2012, 2013  SPARTA, Inc. a Parsons Company
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
__all__ = ('import_routeviews_dump')

import itertools
import os.path
import subprocess
import time
import logging
import urlparse
import bz2
from urllib import urlretrieve, unquote

from django.db import transaction, connection
from django.conf import settings

from rpki.resource_set import resource_range_ipv4, resource_range_ipv6
from rpki.exceptions import BadIPResource
import rpki.gui.app.timestamp

try:
    import _mysql_exceptions
except ImportError:
    class MySQLWarning(Exception):
        "Dummy, nothing will ever raise this."
else:
    MySQLWarning = _mysql_exceptions.Warning

# globals
logger = logging.getLogger(__name__)

# Eventually this can be retrived from rpki.conf
DEFAULT_URL = 'http://archive.routeviews.org/oix-route-views/oix-full-snapshot-latest.dat.bz2'

class ParseError(Exception): pass

class RouteDumpParser(object):
    """Base class for parsing various route dump formats."""

    table = 'routeview_routeorigin'
    sql = "INSERT INTO %s_new SET asn=%%s, prefix_min=%%s, prefix_max=%%s" % table
    range_class = resource_range_ipv4

    def __init__(self, path, *args, **kwargs):
        self.path = path
        self.cursor = connection.cursor()
        self.last_prefix = None
        self.asns = set()

    def parse(self):
        try:
            logger.info('Dropping existing staging table...')
            self.cursor.execute('DROP TABLE IF EXISTS %s_new' % self.table)
        except MySQLWarning:
            pass

        logger.info('Creating staging table...')
        self.cursor.execute('CREATE TABLE %(table)s_new LIKE %(table)s' % {'table': self.table})

        logger.info('Disabling autocommit...')
        self.cursor.execute('SET autocommit=0')

        logger.info('Adding rows to table...')
        for line in self.input:
            try:
                prefix, origin_as = self.parse_line(line)
            except ParseError as e:
                logger.warning('error while parsing line: {} ({})'.format(line, str(e)))
                continue

            # the output may contain multiple paths to the same origin.
            # if this is the same prefix as the last entry, we don't need
            # to validate it again.
            #
            # prefixes are sorted, but the origin_as is not, so we keep a set to
            # avoid duplicates, and insert into the db once we've seen all the
            # origin_as values for a given prefix
            if prefix != self.last_prefix:
                self.ins_routes()
                self.last_prefix = prefix
            self.asns.add(origin_as)

        self.ins_routes() # process data from last line

        logger.info('Committing...')
        self.cursor.execute('COMMIT')

        try:
            logger.info('Dropping old table...')
            self.cursor.execute('DROP TABLE IF EXISTS %s_old' % self.table)
        except MySQLWarning:
            pass

        logger.info('Swapping staging table with live table...')
        self.cursor.execute('RENAME TABLE %(table)s TO %(table)s_old, %(table)s_new TO %(table)s' % {'table': self.table})

        self.cleanup()  # allow cleanup function to throw prior to COMMIT

        transaction.commit_unless_managed()

        logger.info('Updating timestamp metadata...')
        rpki.gui.app.timestamp.update('bgp_v4_import')

    def parse_line(self, row):
        "Parse one line of input. Return a (prefix, origin_as) tuple."
        return None

    def cleanup(self):
        pass

    def ins_routes(self):
        # output routes for previous prefix
        if self.last_prefix is not None:
            try:
                rng = self.range_class.parse_str(self.last_prefix)
                rmin = long(rng.min)
                rmax = long(rng.max)
                self.cursor.executemany(self.sql, [(asn, rmin, rmax) for asn in self.asns])
            except BadIPResource:
                logger.warning('skipping bad prefix: ' + self.last_prefix)
            self.asns = set() # reset


class TextDumpParser(RouteDumpParser):
    """Parses the RouteViews.org text dump."""

    def __init__(self, *args, **kwargs):
        super(TextDumpParser, self).__init__(*args, **kwargs)
        if self.path.endswith('.bz2'):
            logger.info('decompressing bz2 file')
            self.file = bz2.BZ2File(self.path, buffering=4096)
        else:
            self.file = open(self.path, buffering=-1)
        self.input = itertools.islice(self.file, 5, None)  # skip first 5 lines

    def parse_line(self, row):
        "Parse one line of input"
        cols = row.split()

        # index -1 is i/e/? for igp/egp
        try:
            origin_as = int(cols[-2])
        except IndexError:
            raise ParseError('unexpected format')
        except ValueError:
            raise ParseError('bad AS value')

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

        return prefix, origin_as

    def cleanup(self):
        self.file.close()


class MrtDumpParser(RouteDumpParser):
    def __init__(self, *args, **kwargs):
        super(MrtDumpParser, self).__init__(*args, **kwargs)
        # filter input through bgpdump
        # bgpdump can decompress bz2 files directly, no need to do it here
        self.pipe = subprocess.Popen(['bgpdump', '-m', '-v', self.path], stdout=subprocess.PIPE, bufsize=-1)
        self.input = self.pipe.stdout

    def parse_line(self, row):
        a = row.split('|')
        prefix = a[5]
        try:
            origin_as = int(a[6].split()[-1])
        except ValueError:
            raise ParseError('bad AS value')

        return prefix, origin_as

    def cleanup(self):
        logger.info('waiting for child process to terminate')
        self.pipe.wait()
        if self.pipe.returncode:
            raise PipeFailed('bgpdump exited with code %d' % self.pipe.returncode)


class ProgException(Exception):
    pass


class UnknownInputType(ProgException):
    pass


class PipeFailed(ProgException):
    pass


def import_routeviews_dump(filename=DEFAULT_URL, filetype='text'):
    """Load the oix-full-snapshot-latest.bz2 from routeview.org into the
    rpki.gui.routeview database.

    Arguments:

        filename [optional]: the full path to the downloaded file to parse

        filetype [optional]: 'text' or 'mrt'
    """

    start_time = time.time()
    tmpname = None

    try:
        if filename.startswith('http://'):
            #get filename from the basename of the URL
            u = urlparse.urlparse(filename)
            bname = os.path.basename(unquote(u.path))
            tmpname = os.path.join(settings.DOWNLOAD_DIRECTORY, bname)

            logger.info("Downloading %s to %s", filename, tmpname)
            if os.path.exists(tmpname):
                os.remove(tmpname)
            # filename is replaced with a local filename containing cached copy of
            # URL
            filename, headers = urlretrieve(filename, tmpname)

        try:
            dispatch = {'text': TextDumpParser, 'mrt': MrtDumpParser}
            dispatch[filetype](filename).parse()
        except KeyError:
            raise UnknownInputType('"%s" is an unknown input file type' % filetype)

    finally:
        # make sure to always clean up the temp download file
        if tmpname is not None:
            os.unlink(tmpname)

    logger.info('Elapsed time %d secs', (time.time() - start_time))
