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

# normally this would be a module docstring, but since this script is
# prepending with django boilerplate, that doesn't work
description = """
This script is used to reset all of the labuser* accounts on demo.rpki.net back
to a state suitable for a new workshop.  It removes all ROAs and Ghostbuster
issued by the labuser accounts.

"""

__version__ = '$Id$'

from optparse import OptionParser
import logging
from rpki.gui.app.models import ROARequest, GhostbusterRequest

if __name__ == '__main__':
    parser = OptionParser(description=description)
    (options, args) = parser.parse_args()

    for n in xrange(1, 32):
        username = 'labuser%02d' % n
        logging.info('removing objects for ' + username)
        for cls in (ROARequest, GhostbusterRequest):
            cls.objects.filter(issuer__handle=username).delete()
