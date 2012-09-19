# $Id$
#
# Tool to write search C source code for "DECLARE_STACK_OF" macro
# calls and write corresponding type-safe "safestack" macros.
#
# You might want to look away now, this is nasty.  Then again, OpenSSL
# does the same thing, but in Perl, and mixing automatically generated
# code with code maintained by humans, so "nasty" is a relative term.
#
# Copyright (C) 2011-2012  Internet Systems Consortium ("ISC")
# 
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
# 
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import fileinput
import sys
import re

header = '''\
/*
 * Automatically generated, do not edit.
 * Generator $Id$
 */

#ifndef __%__DEFSTACK_H__
#define __%__DEFSTACK_H__
'''

footer = '''
#endif /* __%__DEFSTACK_H__ */
'''

template = '''
/*
 * Safestack macros for %.
 */
#define sk_%_new(st)                     SKM_sk_new(%, (st))
#define sk_%_new_null()                  SKM_sk_new_null(%)
#define sk_%_free(st)                    SKM_sk_free(%, (st))
#define sk_%_num(st)                     SKM_sk_num(%, (st))
#define sk_%_value(st, i)                SKM_sk_value(%, (st), (i))
#define sk_%_set(st, i, val)             SKM_sk_set(%, (st), (i), (val))
#define sk_%_zero(st)                    SKM_sk_zero(%, (st))
#define sk_%_push(st, val)               SKM_sk_push(%, (st), (val))
#define sk_%_unshift(st, val)            SKM_sk_unshift(%, (st), (val))
#define sk_%_find(st, val)               SKM_sk_find(%, (st), (val))
#define sk_%_find_ex(st, val)            SKM_sk_find_ex(%, (st), (val))
#define sk_%_delete(st, i)               SKM_sk_delete(%, (st), (i))
#define sk_%_delete_ptr(st, ptr)         SKM_sk_delete_ptr(%, (st), (ptr))
#define sk_%_insert(st, val, i)          SKM_sk_insert(%, (st), (val), (i))
#define sk_%_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(%, (st), (cmp))
#define sk_%_dup(st)                     SKM_sk_dup(%, st)
#define sk_%_pop_free(st, free_func)     SKM_sk_pop_free(%, (st), (free_func))
#define sk_%_shift(st)                   SKM_sk_shift(%, (st))
#define sk_%_pop(st)                     SKM_sk_pop(%, (st))
#define sk_%_sort(st)                    SKM_sk_sort(%, (st))
#define sk_%_is_sorted(st)               SKM_sk_is_sorted(%, (st))
'''

if len(sys.argv) < 2:
  sys.exit("Usage: %s source.c [source.c ...]" % sys.argv[0])

splitter = re.compile("[() \t]+").split

token = None

for line in fileinput.input():

  if token is None:
    token = "".join(c if c.isalnum() else "_" for c in fileinput.filename().upper())
    sys.stdout.write(header.replace("%", token))

  if "DECLARE_STACK_OF" in line:
    words = splitter(line)
    if len(words) > 1 and words[0] == "DECLARE_STACK_OF":
      sys.stdout.write(template.replace("%", words[1]))

if token is not None:
  sys.stdout.write(footer.replace("%", token))
