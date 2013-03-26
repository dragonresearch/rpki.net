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

import optparse
import logging

# configure django ORM
from rpki.gui.script_util import setup
setup()

from rpki.gui.routeview.util import import_routeviews_dump


class BadArgument(Exception):
    pass


if __name__ == '__main__':
    parser = optparse.OptionParser(
        usage='%prog [options] PATH',
        description="""This tool is used to import the IPv4/6 BGP table dumps
from routeviews.org into the RPKI Web Portal database.  If the
input file is a bzip2 compressed file, it will be decompressed
automatically.""")
    parser.add_option('-t', '--type', dest='filetype', metavar='TYPE',
                      help='Specify the input file type (auto, text, mrt) [Default: %default]')
    parser.add_option('-l', '--level', dest='log_level', default='WARNING',
                      help='Set logging level [Default: %default]')
    parser.add_option('-u', '--bunzip2', dest='bunzip', metavar='PROG',
                      help='Specify bunzip2 program to use')
    parser.add_option('-b', '--bgpdump', dest='bgpdump', metavar='PROG',
                      help='Specify path to bgdump binary')
    parser.set_defaults(debug=False, verbose=False, filetype='auto')
    options, args = parser.parse_args()

    v = getattr(logging, options.log_level.upper())
    logging.basicConfig(level=v)
    logging.info('logging level set to ' + logging.getLevelName(v))

    if options.bgpdump:
        BGPDUMP = os.path.expanduser(options.bgpdump)

    try:
        if len(args) != 1:
            raise BadArgument('no filename specified, or more than one filename specified')
        filename = args[0]
        import_routeviews_dump(filename)

    except Exception as e:
        logging.exception(e)
        rc = 1

    logging.shutdown()
