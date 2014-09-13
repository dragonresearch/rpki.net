# $Id$

# Copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Global Django ORM database router for the RPKI CA code.
"""

# Reference:
# https://docs.djangoproject.com/en/1.6/topics/db/multi-db/

class RPKIDBRouter(object):
  """
  Django ORM database router for RPKI code.  rpkid and pubd get their
  own databases, named "rpkidb" and "pubdb", respectively.  Everything
  else goes to the "default" database.
  """

  dedicated = ("rpkidb", "pubdb")

  def db_for_read(self, model, **hints):
    if model._meta.app_label in self.dedicated:
      return model._meta.app_label 
    else:
      return "default"

  def db_for_write(self, model, **hints):
    if model._meta.app_label in self.dedicated:
      return model._meta.app_label 
    else:
      return "default"

  def allow_relation(self, obj1, obj2, **hints):
    if obj1._meta.app_label in self.dedicated and obj1._meta.app_label == obj2._meta.app_label:
      return True
    elif obj1._meta.app_label not in self.dedicated and obj2._meta.app_label not in self.dedicated:
      return True
    else:
      return None

  def allow_syncdb(self, db, model):
    if model._meta.app_label in self.dedicated:
      return db == model._meta.app_label
    else:
      return db not in self.dedicated
