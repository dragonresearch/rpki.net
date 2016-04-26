# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009-2013  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
RPKI-Router protocol implementation.  See RFC 6810 et sequalia in fine
RFC and Internet-Draft repositories near you.
"""

import os
import sys
import time
import logging

import rpki.config


def main():

    os.environ["TZ"] = "UTC"
    time.tzset()

    from rpki.rtr.server    import argparse_setup as argparse_setup_server
    from rpki.rtr.client    import argparse_setup as argparse_setup_client
    from rpki.rtr.generator import argparse_setup as argparse_setup_generator

    if "rpki.rtr.bgpdump" in sys.modules:
        from rpki.rtr.bgpdump import argparse_setup as argparse_setup_bgpdump
    else:
        def argparse_setup_bgpdump(ignored):
            pass

    cfg = rpki.config.argparser(section = "rpki-rtr", doc =  __doc__)
    cfg.argparser.add_argument("--debug", action = "store_true", help = "debugging mode")
    cfg.add_logging_arguments()
    subparsers = cfg.argparser.add_subparsers(title = "Commands", metavar = "", dest = "mode")
    argparse_setup_server(subparsers)
    argparse_setup_client(subparsers)
    argparse_setup_generator(subparsers)
    argparse_setup_bgpdump(subparsers)
    args = cfg.argparser.parse_args()

    cfg.configure_logging(args = args, ident = "rpki-rtr/" + args.mode)

    return args.func(args)
