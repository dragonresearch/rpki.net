# $Id$
#
# Copyright (C) 2011  Internet Systems Consortium ("ISC")
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

function print_line(name, line)
{
  gsub(/%/, name, line);
  print line;
}

function define_stack(name)
{
  print_line(name, "/*");
  print_line(name, " * Safestack macros for %.");
  print_line(name, " */");
  print_line(name, "#define sk_%_new(st)                     SKM_sk_new(%, (st))");
  print_line(name, "#define sk_%_new_null()                  SKM_sk_new_null(%)");
  print_line(name, "#define sk_%_free(st)                    SKM_sk_free(%, (st))");
  print_line(name, "#define sk_%_num(st)                     SKM_sk_num(%, (st))");
  print_line(name, "#define sk_%_value(st, i)                SKM_sk_value(%, (st), (i))");
  print_line(name, "#define sk_%_set(st, i, val)             SKM_sk_set(%, (st), (i), (val))");
  print_line(name, "#define sk_%_zero(st)                    SKM_sk_zero(%, (st))");
  print_line(name, "#define sk_%_push(st, val)               SKM_sk_push(%, (st), (val))");
  print_line(name, "#define sk_%_unshift(st, val)            SKM_sk_unshift(%, (st), (val))");
  print_line(name, "#define sk_%_find(st, val)               SKM_sk_find(%, (st), (val))");
  print_line(name, "#define sk_%_find_ex(st, val)            SKM_sk_find_ex(%, (st), (val))");
  print_line(name, "#define sk_%_delete(st, i)               SKM_sk_delete(%, (st), (i))");
  print_line(name, "#define sk_%_delete_ptr(st, ptr)         SKM_sk_delete_ptr(%, (st), (ptr))");
  print_line(name, "#define sk_%_insert(st, val, i)          SKM_sk_insert(%, (st), (val), (i))");
  print_line(name, "#define sk_%_set_cmp_func(st, cmp)       SKM_sk_set_cmp_func(%, (st), (cmp))");
  print_line(name, "#define sk_%_dup(st)                     SKM_sk_dup(%, st)");
  print_line(name, "#define sk_%_pop_free(st, free_func)     SKM_sk_pop_free(%, (st), (free_func))");
  print_line(name, "#define sk_%_shift(st)                   SKM_sk_shift(%, (st))");
  print_line(name, "#define sk_%_pop(st)                     SKM_sk_pop(%, (st))");
  print_line(name, "#define sk_%_sort(st)                    SKM_sk_sort(%, (st))");
  print_line(name, "#define sk_%_is_sorted(st)               SKM_sk_is_sorted(%, (st))");
  print_line(name, "");
} 

BEGIN {
  print "/*";
  print " * Automatically generated, do not edit.";
  print " * Generator $Id$";
  print " */";
  print "";
  print "#ifndef __DEFSTACK_H__";
  print "#define __DEFSTACK_H__";
  print "";
  define_stack("HOST_MIB_COUNTER");
  define_stack("VALIDATION_STATUS");
  define_stack("FileAndHash");
  define_stack("ROAIPAddress");
  define_stack("ROAIPAddressFamily");
  define_stack("walk_ctx_t");
  print "#endif /* __DEFSTACK_H__ */";
}
