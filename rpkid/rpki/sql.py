# $Id$

# Copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import MySQLdb, time,  warnings, _mysql_exceptions
import rpki.x509, rpki.resource_set, rpki.sundial

def connect(cfg, throw_exception_on_warning = True):
  """Connect to a MySQL database using connection parameters from an
     rpki.config.parser object.
  """

  if throw_exception_on_warning:
    warnings.simplefilter("error", _mysql_exceptions.Warning)

  return MySQLdb.connect(user   = cfg.get("sql-username"),
                         db     = cfg.get("sql-database"),
                         passwd = cfg.get("sql-password"))

class sesssion(object):
  """SQL session layer."""

  def __init__(self, cfg):

    raise rpki.errorsNotImplementedYet, "This class is still under construction"

    warnings.simplefilter("error", _mysql_exceptions.Warning)

    self.username = cfg.get("sql-username")
    self.database = cfg.get("sql-database")
    self.password = cfg.get("sql-password")

    self.sql_cache = {}
    self.sql_dirty = set()

    self.connect()

  def connect(self):
    self.db = MySQLdb.connect(user = username, db = database, passwd = password)
    self.cur = self.db.cursor()

  def sql_cache_clear(self):
    """Clear the object cache."""
    self.sql_cache.clear()

  def sql_assert_pristine(self):
    """Assert that there are no dirty objects in the cache."""
    assert not self.sql_dirty, "Dirty objects in SQL cache: %s" % self.sql_dirty

  def sql_sweep(self):
    """Write any dirty objects out to SQL."""
    for s in self.sql_dirty.copy():
      rpki.log.debug("Sweeping %s" % repr(s))
      if s.sql_deleted:
        s.sql_delete()
      else:
        s.sql_store()
    self.sql_assert_pristine()

class template(object):
  """SQL template generator."""
  def __init__(self, table_name, index_column, *data_columns):
    """Build a SQL template."""
    type_map     = dict((x[0],x[1]) for x in data_columns if isinstance(x, tuple))
    data_columns = tuple(isinstance(x, tuple) and x[0] or x for x in data_columns)
    columns      = (index_column,) + data_columns
    self.table   = table_name
    self.index   = index_column
    self.columns = columns
    self.map     = type_map
    self.select  = "SELECT %s FROM %s" % (", ".join(columns), table_name)
    self.insert  = "INSERT %s (%s) VALUES (%s)" % (table_name, ", ".join(data_columns),
                                                   ", ".join("%(" + s + ")s" for s in data_columns))
    self.update  = "UPDATE %s SET %s WHERE %s = %%(%s)s" % \
                   (table_name, ", ".join(s + " = %(" + s + ")s" for s in data_columns),
                    index_column, index_column)
    self.delete  = "DELETE FROM %s WHERE %s = %%s" % (table_name, index_column)

class sql_persistant(object):
  """Mixin for persistant class that needs to be stored in SQL.
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
    """Fetch one object from SQL, based on its primary key.

    Since in this one case we know that the primary index is also the
    cache key, we check for a cache hit directly in the hope of
    bypassing the SQL lookup entirely.

    This method is usually called via a one-line class-specific
    wrapper.  As a convenience, we also accept an id of None, and just
    return None in this case.
    """

    if id is None:
      return None
    assert isinstance(id, (int, long)), "id should be an integer, was %s" % repr(type(id))
    key = (cls, id)
    if key in gctx.sql_cache:
      return gctx.sql_cache[key]
    else:
      return cls.sql_fetch_where1(gctx, "%s = %%s" % cls.sql_template.index, (id,))

  @classmethod
  def sql_fetch_where1(cls, gctx, where, args = None):
    """Fetch one object from SQL, based on an arbitrary SQL WHERE expression."""
    results = cls.sql_fetch_where(gctx, where, args)
    if len(results) == 0:
      return None
    elif len(results) == 1:
      return results[0]
    else:
      raise rpki.exceptions.DBConsistancyError, \
            "Database contained multiple matches for %s where %s" % \
            (cls.__name__, where % tuple(repr(a) for a in args))

  @classmethod
  def sql_fetch_all(cls, gctx):
    """Fetch all objects of this type from SQL."""
    return cls.sql_fetch_where(gctx, None)

  @classmethod
  def sql_fetch_where(cls, gctx, where, args = None):
    """Fetch objects of this type matching an arbitrary SQL WHERE expression."""
    if where is None:
      assert args is None
      if cls.sql_debug:
        rpki.log.debug("sql_fetch_where(%s)" % repr(cls.sql_template.select))
      gctx.cur.execute(cls.sql_template.select)
    else:
      query = cls.sql_template.select + " WHERE " + where
      if cls.sql_debug:
        rpki.log.debug("sql_fetch_where(%s, %s)" % (repr(query), repr(args)))
      gctx.cur.execute(query, args)
    results = []
    for row in gctx.cur.fetchall():
      key = (cls, row[0])
      if key in gctx.sql_cache:
        results.append(gctx.sql_cache[key])
      else:
        results.append(cls.sql_init(gctx, row, key))
    return results

  @classmethod
  def sql_init(cls, gctx, row, key):
    """Initialize one Python object from the result of a SQL query."""
    self = cls()
    self.gctx = gctx
    self.sql_decode(dict(zip(cls.sql_template.columns, row)))
    gctx.sql_cache[key] = self
    self.sql_in_db = True
    self.sql_fetch_hook()
    return self

  def sql_mark_dirty(self):
    """Mark this object as needing to be written back to SQL."""
    self.gctx.sql_dirty.add(self)

  def sql_mark_clean(self):
    """Mark this object as not needing to be written back to SQL."""
    self.gctx.sql_dirty.discard(self)

  def sql_is_dirty(self):
    """Query whether this object needs to be written back to SQL."""
    return self in self.gctx.sql_dirty

  def sql_mark_deleted(self):
    """Mark this object as needing to be deleted in SQL."""
    self.sql_deleted = True

  def sql_store(self):
    """Store this object to SQL."""
    if not self.sql_in_db:
      self.gctx.cur.execute(self.sql_template.insert, self.sql_encode())
      setattr(self, self.sql_template.index, self.gctx.cur.lastrowid)
      self.gctx.sql_cache[(self.__class__, self.gctx.cur.lastrowid)] = self
      self.sql_insert_hook()
    else:
      self.gctx.cur.execute(self.sql_template.update, self.sql_encode())
      self.sql_update_hook()
    key = (self.__class__, getattr(self, self.sql_template.index))
    assert key in self.gctx.sql_cache and self.gctx.sql_cache[key] == self
    self.sql_mark_clean()
    self.sql_in_db = True

  def sql_delete(self):
    """Delete this object from SQL."""
    if self.sql_in_db:
      id = getattr(self, self.sql_template.index)
      self.gctx.cur.execute(self.sql_template.delete, id)
      self.sql_delete_hook()
      key = (self.__class__, id)
      if self.gctx.sql_cache.get(key) == self:
        del self.gctx.sql_cache[key]
      self.sql_in_db = False
    self.sql_mark_clean()

  def sql_encode(self):
    """Convert object attributes into a dict for use with canned SQL
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
    """Initialize an object with values returned by self.sql_fetch().
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
    """Customization hook."""
    pass

  def sql_insert_hook(self):
    """Customization hook."""
    pass
  
  def sql_update_hook(self):
    """Customization hook."""
    self.sql_delete_hook()
    self.sql_insert_hook()

  def sql_delete_hook(self):
    """Customization hook."""
    pass

