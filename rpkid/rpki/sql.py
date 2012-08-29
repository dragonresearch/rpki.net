"""
SQL interface code.

$Id$

Copyright (C) 2009  Internet Systems Consortium ("ISC")

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

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import weakref

from rpki.mysql_import import (MySQLdb, _mysql_exceptions)

import rpki.x509
import rpki.resource_set
import rpki.sundial
import rpki.log

class session(object):
  """
  SQL session layer.
  """

  ## @var ping_threshold
  # Timeout after which we should issue a ping command before the real
  # one.  Intent is to keep the MySQL connection alive without pinging
  # before every single command.

  ping_threshold = rpki.sundial.timedelta(seconds = 60)

  def __init__(self, cfg):

    self.username = cfg.get("sql-username")
    self.database = cfg.get("sql-database")
    self.password = cfg.get("sql-password")

    self.cache = weakref.WeakValueDictionary()
    self.dirty = set()

    self.connect()

  def connect(self):
    self.db = MySQLdb.connect(user = self.username, db = self.database, passwd = self.password)
    self.cur = self.db.cursor()
    self.db.autocommit(True)
    self.timestamp = rpki.sundial.now()

  def close(self):
    if self.cur:
      self.cur.close()
    self.cur = None
    if self.db:
      self.db.close()
    self.db = None

  def _wrap_execute(self, func, query, args):
    try:
      now = rpki.sundial.now()
      if now > self.timestamp + self.ping_threshold:
        self.db.ping(True)
      self.timestamp = now
      return func(query, args)
    except _mysql_exceptions.MySQLError:
      if self.dirty:
        rpki.log.warn("MySQL exception with dirty objects in SQL cache!")
      raise

  def execute(self, query, args = None):
    return self._wrap_execute(self.cur.execute, query, args)

  def executemany(self, query, args):
    return self._wrap_execute(self.cur.executemany, query, args)

  def fetchall(self):
    return self.cur.fetchall()

  def lastrowid(self):
    return self.cur.lastrowid

  def cache_clear(self):
    """
    Clear the SQL object cache.  Shouldn't be necessary now that the
    cache uses weak references, but should be harmless.
    """
    rpki.log.debug("Clearing SQL cache")
    self.assert_pristine()
    self.cache.clear()

  def assert_pristine(self):
    """
    Assert that there are no dirty objects in the cache.
    """
    assert not self.dirty, "Dirty objects in SQL cache: %s" % self.dirty

  def sweep(self):
    """
    Write any dirty objects out to SQL.
    """
    for s in self.dirty.copy():
      rpki.log.debug("Sweeping %r" % s)
      if s.sql_deleted:
        s.sql_delete()
      else:
        s.sql_store()
    self.assert_pristine()

class template(object):
  """
  SQL template generator.
  """

  def __init__(self, table_name, index_column, *data_columns):
    """
    Build a SQL template.
    """
    type_map     = dict((x[0], x[1]) for x in data_columns if isinstance(x, tuple))
    data_columns = tuple(isinstance(x, tuple) and x[0] or x for x in data_columns)
    columns      = (index_column,) + data_columns
    self.table   = table_name
    self.index   = index_column
    self.columns = columns
    self.map     = type_map
    self.select  = "SELECT %s FROM %s" % (", ".join("%s.%s" % (table_name, c) for c in columns), table_name)
    self.insert  = "INSERT %s (%s) VALUES (%s)" % (table_name,
                                                   ", ".join(data_columns),
                                                   ", ".join("%(" + s + ")s" for s in data_columns))
    self.update  = "UPDATE %s SET %s WHERE %s = %%(%s)s" % (table_name,
                                                            ", ".join(s + " = %(" + s + ")s" for s in data_columns),
                                                            index_column,
                                                            index_column)
    self.delete  = "DELETE FROM %s WHERE %s = %%s" % (table_name, index_column)

class sql_persistent(object):
  """
  Mixin for persistent class that needs to be stored in SQL.
  """

  ## @var sql_in_db
  # Whether this object is already in SQL or not.

  sql_in_db = False

  ## @var sql_deleted
  # Whether our cached copy of this object has been deleted.

  sql_deleted = False

  ## @var sql_debug
  # Enable logging of SQL actions

  sql_debug = False

  @classmethod
  def sql_fetch(cls, gctx, id):
    """
    Fetch one object from SQL, based on its primary key.

    Since in this one case we know that the primary index is also the
    cache key, we check for a cache hit directly in the hope of
    bypassing the SQL lookup entirely.

    This method is usually called via a one-line class-specific
    wrapper.  As a convenience, we also accept an id of None, and just
    return None in this case.
    """

    if id is None:
      return None
    assert isinstance(id, (int, long)), "id should be an integer, was %r" % type(id)
    key = (cls, id)
    if key in gctx.sql.cache:
      return gctx.sql.cache[key]
    else:
      return cls.sql_fetch_where1(gctx, "%s = %%s" % cls.sql_template.index, (id,))

  @classmethod
  def sql_fetch_where1(cls, gctx, where, args = None, also_from = None):
    """
    Fetch one object from SQL, based on an arbitrary SQL WHERE expression.
    """
    results = cls.sql_fetch_where(gctx, where, args, also_from)
    if len(results) == 0:
      return None
    elif len(results) == 1:
      return results[0]
    else:
      raise rpki.exceptions.DBConsistancyError, \
            "Database contained multiple matches for %s where %s: %r" % \
            (cls.__name__, where % tuple(repr(a) for a in args), results)

  @classmethod
  def sql_fetch_all(cls, gctx):
    """
    Fetch all objects of this type from SQL.
    """
    return cls.sql_fetch_where(gctx, None)

  @classmethod
  def sql_fetch_where(cls, gctx, where, args = None, also_from = None):
    """
    Fetch objects of this type matching an arbitrary SQL WHERE expression.
    """
    if where is None:
      assert args is None and also_from is None
      if cls.sql_debug:
        rpki.log.debug("sql_fetch_where(%r)" % cls.sql_template.select)
      gctx.sql.execute(cls.sql_template.select)
    else:
      query = cls.sql_template.select
      if also_from is not None:
        query += "," + also_from
      query += " WHERE " + where
      if cls.sql_debug:
        rpki.log.debug("sql_fetch_where(%r, %r)" % (query, args))
      gctx.sql.execute(query, args)
    results = []
    for row in gctx.sql.fetchall():
      key = (cls, row[0])
      if key in gctx.sql.cache:
        results.append(gctx.sql.cache[key])
      else:
        results.append(cls.sql_init(gctx, row, key))
    return results

  @classmethod
  def sql_init(cls, gctx, row, key):
    """
    Initialize one Python object from the result of a SQL query.
    """
    self = cls()
    self.gctx = gctx
    self.sql_decode(dict(zip(cls.sql_template.columns, row)))
    gctx.sql.cache[key] = self
    self.sql_in_db = True
    self.sql_fetch_hook()
    return self

  def sql_mark_dirty(self):
    """
    Mark this object as needing to be written back to SQL.
    """
    self.gctx.sql.dirty.add(self)

  def sql_mark_clean(self):
    """
    Mark this object as not needing to be written back to SQL.
    """
    self.gctx.sql.dirty.discard(self)

  def sql_is_dirty(self):
    """
    Query whether this object needs to be written back to SQL.
    """
    return self in self.gctx.sql.dirty

  def sql_mark_deleted(self):
    """
    Mark this object as needing to be deleted in SQL.
    """
    self.sql_deleted = True
    self.sql_mark_dirty()

  def sql_store(self):
    """
    Store this object to SQL.
    """
    args = self.sql_encode()
    if not self.sql_in_db:
      if self.sql_debug:
        rpki.log.debug("sql_fetch_store(%r, %r)" % (self.sql_template.insert, args))
      self.gctx.sql.execute(self.sql_template.insert, args)
      setattr(self, self.sql_template.index, self.gctx.sql.lastrowid())
      self.gctx.sql.cache[(self.__class__, self.gctx.sql.lastrowid())] = self
      self.sql_insert_hook()
    else:
      if self.sql_debug:
        rpki.log.debug("sql_fetch_store(%r, %r)" % (self.sql_template.update, args))
      self.gctx.sql.execute(self.sql_template.update, args)
      self.sql_update_hook()
    key = (self.__class__, getattr(self, self.sql_template.index))
    assert key in self.gctx.sql.cache and self.gctx.sql.cache[key] == self
    self.sql_mark_clean()
    self.sql_in_db = True

  def sql_delete(self):
    """
    Delete this object from SQL.
    """
    if self.sql_in_db:
      id = getattr(self, self.sql_template.index)
      if self.sql_debug:
        rpki.log.debug("sql_fetch_delete(%r, %r)" % (self.sql_template.delete, id))
      self.sql_delete_hook()
      self.gctx.sql.execute(self.sql_template.delete, id)
      key = (self.__class__, id)
      if self.gctx.sql.cache.get(key) == self:
        del self.gctx.sql.cache[key]
      self.sql_in_db = False
    self.sql_mark_clean()

  def sql_encode(self):
    """
    Convert object attributes into a dict for use with canned SQL
    queries.  This is a default version that assumes a one-to-one
    mapping between column names in SQL and attribute names in Python.
    If you need something fancier, override this.
    """
    d = dict((a, getattr(self, a, None)) for a in self.sql_template.columns)
    for i in self.sql_template.map:
      if d.get(i) is not None:
        d[i] = self.sql_template.map[i].to_sql(d[i])
    return d

  def sql_decode(self, vals):
    """
    Initialize an object with values returned by self.sql_fetch().
    This is a default version that assumes a one-to-one mapping
    between column names in SQL and attribute names in Python.  If you
    need something fancier, override this.
    """
    for a in self.sql_template.columns:
      if vals.get(a) is not None and a in self.sql_template.map:
        setattr(self, a, self.sql_template.map[a].from_sql(vals[a]))
      else:
        setattr(self, a, vals[a])

  def sql_fetch_hook(self):
    """
    Customization hook.
    """
    pass

  def sql_insert_hook(self):
    """
    Customization hook.
    """
    pass
  
  def sql_update_hook(self):
    """
    Customization hook.
    """
    self.sql_delete_hook()
    self.sql_insert_hook()

  def sql_delete_hook(self):
    """
    Customization hook.
    """
    pass


def cache_reference(func):
  """
  Decorator for use with property methods which just do an SQL lookup based on an ID.
  Check for an existing reference to the object, just return that if we find it,
  otherwise perform the SQL lookup.

  Not 100% certain this is a good idea, but I //think// it should work well with the
  current weak reference SQL cache, so long as we create no circular references.
  So don't do that.
  """

  attr_name = "_" + func.__name__

  def wrapped(self):
    try:
      value = getattr(self, attr_name)
      assert value is not None
    except AttributeError:
      value = func(self)
      if value is not None:
        setattr(self, attr_name, value)
    return value

  wrapped.__name__ = func.__name__
  wrapped.__doc__ = func.__doc__
  wrapped.__dict__.update(func.__dict__)

  return wrapped
