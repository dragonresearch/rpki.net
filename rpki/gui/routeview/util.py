# Copyright (C) 2012, 2013, 2016  SPARTA, Inc. a Parsons Company
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

from django.db import transaction

from rpki.resource_set import resource_range_ipv4, resource_range_ipv6
from rpki.exceptions import BadIPResource
import rpki.gui.app.timestamp
from rpki.gui.routeview.models import RouteOrigin

# globals
logger = logging.getLogger(__name__)

class ParseError(Exception): pass

class RouteDumpParser(object):
    """Base class for parsing various route dump formats."""

    range_class = resource_range_ipv4

    def __init__(self, path, *args, **kwargs):
        transaction.set_autocommit(False)

        self.path = path
        self.last_prefix = None
        self.asns = set()

    def parse(self):
        RouteOrigin.objects.all().delete()

        logger.info('Adding rows to table...')
        for line in self.input:
            try:
                prefix, origin_as = self.parse_line(line)
            except ParseError as e:
                logger.warning('error while parsing line: {} ({})'.format(line, str(e)))
                continue

	    if prefix is None: # used when encountering AS sets that we skip over
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

        self.cleanup()  # allow cleanup function to throw prior to COMMIT

        logger.info('Updating timestamp metadata...')
        rpki.gui.app.timestamp.update('bgp_v4_import')

        transaction.commit() # not sure if requried, or if transaction.commit() will do it

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
                for asn in self.asns:
                    RouteOrigin.objects.create(asn=asn, prefix_min=rng.min, prefix_max=rng.max)
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
	    if cols[-2][0] == '{' and cols[-2][-1] == '}':
		# skip AS sets
		return None, None
            origin_as = int(cols[-2])
        except IndexError:
            raise ParseError('unexpected format')
        except ValueError:
            raise ParseError('bad AS value')

        # FIXME Django doesn't have a field for positive integers up to 2^32-1
	if origin_as < 0 or origin_as > 2147483647:
            logger.debug('AS value out of range: %d', origin_as)
            return None, None

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


def import_routeviews_dump(filename, filetype='text', download_dir='/var/tmp'):
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
            tmpname = os.path.join(download_dir, bname)

            logger.info("Downloading %s to %s", filename, tmpname)
            if os.path.exists(tmpname):
		os.remove(tmpname)
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
