# $Id$

import MySQLdb

def connect(cfg, section="sql"):
  """Connect to a MySQL database using connection parameters from an
     rpki.config.parser object.
  """

  return MySQLdb.connect(user   = cfg.get(section, "sql-username"),
                         db     = cfg.get(section, "sql-database"),
                         passwd = cfg.get(section, "sql-password"))

class sql_persistant(object):
  """Mixin for persistant class that needs to be stored in SQL.
  """

  ## @var sql_children
  # Dictionary listing this class's children in the tree of SQL
  # tables.  Key the name of the attribute in this class at which a
  # list of the resulting child objects are stored; value is is the
  # class object of a child.
  sql_children = {}

  ## @var sql_in_db
  # Whether this object is already in SQL or not.  Perhaps this should
  # instead be a None value in the object's ID field?
  sql_in_db = False

  ## @var sql_dirty
  # Whether this object has been modified and needs to be written back
  # to SQL.
  sql_dirty = False

  ## @var sql_id_name
  # Name of the attribute in which to store the auto-increment ID
  # column for this table; None if it doesn't have an auto-increment
  # ID or we don't want to store it.
  sql_id_name = None

  ## @var sql_select_cmd
  # Command to SELECT this object from SQL
  sql_select_cmd = None

  ## @var sql_insert_cmd
  # Command to INSERT this object into SQL
  sql_insert_cmd = None

  ## @var sql_update_cmd
  # Command to UPDATE this object into SQL
  sql_update_cmd = None

  ## @var sql_delete_cmd
  # Command to DELETE this object from SQL
  sql_delete_cmd = None

  @classmethod
  def sql_fetch(cls, db, cur=None, select_dict=None, sql_parent=None):
    """Fetch rows from SQL based on a canned query and a set of
    keyword arguments, and instantiate them as objects, returning a
    list of the instantiated objects.

    This is a class method because in general we don't even know how
    many matches the SQL lookup will return until after we've
    performed it.
    """

    result = []
    if cur is None:
      cur = db.cursor()
    cur.execute(self.sql_select_cmd, select_dict)
    for row in cur.fetchall():
      self = cls()
      self.in_sql = True
      self.sql_decode(sql_parent, *row)
      result.append(self)
      self_dict = self.sql_encode()
      for kid_name,kid_type in self.sql_children.items():
        setattr(self, kid_name, kid_type.sql_fetch(db, cur, self_dict, self))
    return result

  def sql_store(self, db, cur=None):
    """Save an object and its descendents to SQL.
    """
    if cur is None:
      cur = db.cursor()
    if not self.sql_in_db:
      cur.execute(self.sql_insert_cmd, self.sql_encode())
      if self.sql_id_name is not None:
        setattr(self, self.sql_id_name, cur.lastrowid)
    elif self.sql_dirty:
      cur.execute(self.sql_update_cmd, self.sql_encode())
    self.sql_dirty = False
    self.sql_in_db = True
    for kids in self.sql_children:
      for kid in getattr(self, kids):
        kid.sql_store(db, cur)

  def sql_delete(self, db, cur=None):
    """Delete an object and its descendants from SQL.
    """
    if cur is None:
      cur = db.cursor()
    if self.sql_in_db:
      cur.execute(self.sql_delete_cmd, self.sql_encode())
      self.sql_in_db = False
    for kids in self.sql_children:
      for kid in getattr(self, kids):
        kid.sql_delete(db, cur)

  def sql_encode(self):
    """Convert object attributes into a dict for use with canned
    SQL queries.
    """
    raise NotImplementedError
    #return dict((a, getattr(self, a)) for a in self.sql_attributes)

  def sql_decode(self):
    """Initialize an object with values returned by self.sql_fetch().
    """
    raise NotImplementedError
