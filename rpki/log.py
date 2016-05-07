# $Id$
#
# Copyright (C) 2015-2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2013-2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009-2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007-2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS, DRL, ISC, AND ARIN
# DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT
# SHALL PARSONS, DRL, ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
# RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF
# CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Logging facilities for RPKI libraries.
"""

import os
import sys
import time
import logging
import logging.handlers
import argparse
import traceback as tb

logger = logging.getLogger(__name__)

## @var show_python_ids
# Whether __repr__() methods should show Python id numbers

show_python_ids = False


def class_logger(module_logger, attribute = "logger"):
    """
    Class decorator to add a class-level Logger object as a class
    attribute.  This allows control of debugging messages at the class
    level rather than just the module level.

    This decorator takes the module logger as an argument.
    """

    def decorator(cls):
        setattr(cls, attribute, module_logger.getChild(cls.__name__))
        return cls
    return decorator


def log_repr(obj, *tokens):
    """
    Constructor for __repr__() strings, handles suppression of Python
    IDs as needed, includes tenant_handle when available.
    """

    words = ["%s.%s" % (obj.__class__.__module__, obj.__class__.__name__)]
    try:
        words.append("{%s}" % obj.tenant.tenant_handle)
    except:
        pass

    for token in tokens:
        if token is not None:
            try:
                s = str(token)
            except:
                s = "???"
                logger.exception("Failed to generate repr() string for object of type %r", type(token))
            if s:
                words.append(s)

    if show_python_ids:
        words.append(" at %#x" % id(obj))

    return "<" + " ".join(words) + ">"


def show_stack(stack_logger = None):
    """
    Log a stack trace.
    """

    if stack_logger is None:
        stack_logger = logger

    for frame in tb.format_stack():
        for line in frame.split("\n"):
            if line:
                stack_logger.debug("%s", line.rstrip())
