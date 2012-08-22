"""
Django-style "Database router".

For most programs, you don't need this.  Django's normal mode of
behavior is to use a single SQL database for the IRDB, which is
normally what we want.  For certain test scenarios, however, it's
useful to be able to use the same Django ORM models and managers with
multiple databases without having to complicate the interface by
passing database names everywhere.  Using a database router
accomplishes this.

$Id$

Copyright (C) 2012  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

class DBContextRouter(object):
  """
  A Django database router for use with multiple IRDBs.

  This router is designed to work in conjunction with the
  rpki.irdb.database context handler (q.v.).
  """

  verbose = False

  _app = "irdb"

  _database = None

  def __init__(self):
    if self.verbose:
      print "%r init" % self

  def db_for_read(self, model, **hints):
    if model._meta.app_label == self._app:
      result = self._database
    else:
      result = None
    if self.verbose:
      print "db_for_read() returning", result
    return result

  def db_for_write(self, model, **hints):
    if model._meta.app_label == self._app:
      result = self._database
    else:
      result = None
    if self.verbose:
      print "db_for_write() returning", result
    return result

  def allow_relation(self, obj1, obj2, **hints):
    if self._database is None:
      result = None
    elif obj1._meta.app_label == self._app and obj2._meta.app_label == self._app:
      result = True
    else:
      result = None
    if self.verbose:
      print "allow_relation() returning", result
    return result

  def allow_syncdb(self, db, model):
    if self.verbose:
      print "allow_syncdb(): db %r, model %r, self._database %r, model._meta.app_label %r, self._app %r" % (
        db, model, self._database, model._meta.app_label, self._app)
    if db == self._database and model._meta.app_label == self._app:
      result = True
    else:
      result = None
    if self.verbose:
      print "allow_syncdb(): returning", result
    return result

class database(object):
  """
  Context manager for use with DBContextRouter.  Use thusly:

    with rpki.irdb.database("blarg"):
      do_stuff()

  This binds IRDB operations to database blarg for the duration of
  the call to do_stuff(), then restores the prior state.
  """

  verbose = False

  def __init__(self, name):
    if not isinstance(name, str):
      raise ValueError("database name must be a string, not %r" % value)
    self.name = name

  def __enter__(self):
    self.former = DBContextRouter._database
    if self.verbose:
      print "Entering context manager: DBContextRouter.database %r => %r" % (self.former, self.name)
    DBContextRouter._database = self.name

  def __exit__(self, type, value, traceback):
    assert DBContextRouter._database is self.name
    if self.verbose:
      print "Exiting context manager: DBContextRouter.database %r => %r" % (DBContextRouter._database, self.former)
    DBContextRouter._database = self.former
