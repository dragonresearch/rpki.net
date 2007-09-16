# $Id$

import MySQLdb

def connect(cfg, section="sql"):
  """Connect to a MySQL database using connection parameters from an
     rpki.config.parser object.
  """

  return MySQLdb.connect(user   = cfg.get(section, "sql-username"),
                         db     = cfg.get(section, "sql-database"),
                         passwd = cfg.get(section, "sql-password"))

class template(object):
  """SQL template generator."""
  def __init__(self, table_name, *columns):
    index_column = columns[0]
    data_columns = columns[1:]
    self.index   = index_column
    self.columns = columns
    self.select  = "SELECT %s FROM %s WHERE %s = %%s" % (", ".join(columns), table_name, index_column)
    self.insert  = "INSERT %s (%s) VALUES (%s)" % (table_name, ", ".join(data_columns), ", ".join("%(" + s + ")s" for s in data_columns))
    self.update  = "UPDATE %s SET %s WHERE %s = %%(%s)s" % (table_name, ", ".join(s + " = %(" + s + ")s" for s in data_columns), index_column, index_column)
    self.delete  = "DELETE FROM %s WHERE %s = %%s" % (table_name, index_column)

## @var sql_cache
# Cache of objects pulled from SQL.

sql_cache = {}

def cache_clear():
  """Clear the object cache."""

  sql_cache = {}


def get_column(db, cur, *query):
  """Pull a single column from SQL, return it as a list."""

  cur.execute(*query)
  return [x[0] for x in cur.fetchall()]


class sql_persistant(object):
  """Mixin for persistant class that needs to be stored in SQL.
  """

  ## @var sql_in_db
  # Whether this object is already in SQL or not.
  sql_in_db = False

  ## @var sql_dirty
  # Whether this object has been modified and needs to be written back
  # to SQL.
  sql_dirty = False

  @classmethod
  def sql_fetch(cls, db, cur, id):
    key = (cls, id)
    if key in sql_cache:
      return sql_cache[key]
    cur.execute(cls.sql_template.select, id)
    result = cur.fetchone()
    if result is None:
      return None
    data = dict(zip(cls.sql_template.columns, result))
    self = cls()
    self.sql_decode(data)
    sql_cache[key] = self
    self.sql_dirty = False
    self.sql_in_db = True
    self.sql_fetch_hook(db, cur)
    return self

  def sql_store(self, db, cur):
    if not self.sql_in_db:
      cur.execute(self.sql_template.insert, self.sql_encode())
      setattr(self, self.sql_template.index, cur.lastrowid)
      sql_cache[(self.__class__, cur.lastrowid)] = self
      self.sql_insert_hook(db, cur)
    elif self.sql_dirty:
      cur.execute(self.sql_template.update, self.sql_encode())
      self.sql_update_hook(db, cur)
    assert sql_cache[(self.__class__, getattr(self, self.sql_template.index))] == self
    self.sql_dirty = False
    self.sql_in_db = True

  def sql_delete(self, db, cur):
    if self.sql_in_db:
      cur.execute(self.sql_template.delete, self.sql_encode())
      self.sql_delete_hook(db, cur)
      key = (self.__class__, getattr(self, self.sql_template.index))
      if sql_cache.get(key) == self:
        del sql_cache[key]
      self.sql_in_db = False
      self.sql_dirty = False

  def sql_encode(self):
    """Convert object attributes into a dict for use with canned SQL
    queries.  This is a default version that assumes a one-to-one
    mapping between column names in SQL and attribute names in Python,
    with no datatype conversion.  If you need something fancier,
    override this.
    """
    return dict((a, getattr(self, a)) for a in self.sql_template.columns)

  def sql_decode(self, vals):
    """Initialize an object with values returned by self.sql_fetch().
    This is a default version that assumes a one-to-one mapping
    between column names in SQL and attribute names in Python, with no
    datatype conversion.  If you need something fancier, override this.
    """
    for a in self.sql_template.columns:
      setattr(self, a, vals[a])

  def sql_fetch_hook(self, db, cur):
    """Customization hook."""
    pass

  def sql_insert_hook(self, db, cur):
    """Customization hook."""
    pass
  
  def sql_update_hook(self, db, cur):
    """Customization hook."""
    self.delete_hook(db, cur)
    self.insert_hook(db, cur)

  def sql_delete_hook(self, db, cur):
    """Customization hook."""
    pass

# Some persistant objects are defined in rpki.left_right, since
# they're also left-right PDUs.  The rest are defined below, for now.

class ca_detail_obj(sql_persistant):
  """Internal CA detail object."""

  sql_template = template("ca", "ca_detail_id", "priv_key_handle", "pub_key", "latest_ca_cert_over_pubkey", "manifest_ee_priv_key_handle", "manifest_ee_pub_key",
                          "latest_manifest_ee_cert", "latest_manifest", "latest_crl", "ca_id")

  def __init__(self):
    self.certs = []

class ca_obj(sql_persistant):
  """Internal CA object."""

  sql_template = template("ca", "ca_id", "last_crl_sn", "next_crl_update", "last_issued_sn", "last_manifest_sn", "next_manifest_update", "sia_uri", "parent_id")

  def sql_fetch_hook(self, db, cur):
    self.children = get_column(db, cur, "SELECT child_id FROM child_ca_link WHERE ca_id = %s", self.ca_id)

  def sql_insert_hook(self, db, cur):
    if self.children:
      cur.executemany("INSERT child_ca_link (ca_id, child_id) VALUES (%s, %s)",
                      ((self.ca_id, x.child_id) for x in self.children))

  def sql_delete_hook(self, db, cur):
    cur.execute("DELETE FROM child_ca_link where ca_id = %s", self.ca_id)
