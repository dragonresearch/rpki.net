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

from optparse import OptionParser
import logging
import sys

# configure django ORM
from rpki.gui.script_util import setup
setup()

from rpki.gui.app.check_expired import notify_expired

usage = '%prog [ -nV ] [ handle1 handle2... ]'

description = """Generate a report detailing all RPKI/BPKI certificates which
are due for impending expiration.  If no resource handles are specified, a
report about all resource handles hosted by the local rpkid instance will be
generated."""

parser = OptionParser(usage, description=description)
parser.add_option('-V', '--version', help='display script version',
                  action='store_true', dest='version', default=False)
parser.add_option('-f', '--from', metavar='ADDRESS', dest='from_email',
                  help='specify the return email address for notifications')
parser.add_option('-t', '--expire-time', dest='expire_days', metavar='DAYS',
                  help='specify the number of days in the future to check')
parser.add_option('-l', '--level', dest='log_level', default='WARNING',
                  help='Set logging level [Default: %default]')
(options, args) = parser.parse_args()
if options.version:
    print __version__
    sys.exit(0)

v = getattr(logging, options.log_level.upper())
logging.basicConfig(level=v)
logging.info('logging level set to ' + logging.getLevelName(v))

kwargs = {}
if options.from_email:
    kwargs['from_email'] = options.from_email
if options.expire_days:
    kwargs['expire_days'] = int(options.expire_days)
notify_expired(**kwargs)

sys.exit(0)
