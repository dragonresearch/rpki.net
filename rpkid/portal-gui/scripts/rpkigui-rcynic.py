# Copyright (C) 2011  SPARTA, Inc. dba Cobham
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

# probably should be exported from rpki.gui.cacheview.util
default_logfile = '/var/rcynic/data/rcynic.xml'
default_root = '/var/rcynic/data'

import logging

from rpki.gui.script_util import setup
setup()

from rpki.gui.cacheview.util import import_rcynic_xml

if __name__ == '__main__':
    import optparse

    parser = optparse.OptionParser()
    parser.add_option("-l", "--level", dest="log_level", default='WARNING',
                      help="specify the logging level [default: %default]")
    parser.add_option(
        "-f", "--file", dest="logfile",
        help="specify the rcynic XML file to parse [default: %default]",
        default=default_logfile)
    parser.add_option(
        "-r", "--root",
        help="specify the chroot directory for the rcynic jail [default: %default]",
        metavar="DIR", default=default_root)
    options, args = parser.parse_args(sys.argv)

    v = getattr(logging, options.log_level.upper())
    logging.basicConfig(level=v)
    logging.info('log level set to %s' % logging.getLevelName(v))

    import_rcynic_xml(options.root, options.logfile)

    logging.shutdown()
