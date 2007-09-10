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

  ## @var sql_attributes
  # Tuple of attributes to translate between this Python object and its SQL representation.
  sql_attributes = None                 # Must be overriden by derived type

  @classmethod
  def sql_fetch(cls, db, cur=None, arg_dict=None, **kwargs):
    """Fetch rows from SQL based on a canned query and a set of
    keyword arguments, and instantiate them as objects, returning a
    list of the instantiated objects.

    This is a class method because in general we don't even know how
    many matches the SQL lookup will return until after we've
    performed it.
    """

    objs = []
    if cur is None:
      cur = db.cursor()
    if arg_dict is None:
      arg_dict = kwargs
    else:
      assert len(kwargs) == 0
    cur.execute(self.sql_select_cmd % arg_dict)
    for row in cur.fetchall()
      obj = cls()
      obj.in_sql = True
      obj.sql_objectify(*row)
      objs.append(obj)
      obj_dict = obj.sql_makedict()
      for kid_name,kid_type in obj.sql_children.items():
        setattr(obj, kid_name, kid_type.sql_fetch(db, cur, obj_dict))
    return objs
      
  def sql_objectify(self):
    """Initialize self with values returned by self.sql_fetch().
    """
    raise NotImplementedError

  def sql_store(self, db, cur=None):
    """Save an object and its descendents to SQL.
    """
    if cur is None:
      cur = db.cursor()
    if not self.sql_in_db:
      cur.execute(self.sql_insert_cmd % self.sql_makedict())
    elif self.sql_dirty:
      cur.execute(self.sql_update_cmd % self.sql_makedict())
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
      cur.execute(self.sql_delete_cmd % self.sql_makedict())
      self.sql_in_db = False
    for kids in self.sql_children:
      for kid in getattr(self, kids):
        kid.sql_delete(db, cur)

  def sql_makedict(self):
    """Copy attributes from this object into a dict for use with
    canned SQL queries.
    """
    return dict((a, getattr(self, a)) for a in self.sql_attributes)
