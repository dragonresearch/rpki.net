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
  # tables.  Key is the class object of a child, value is the name of
  # the attribute in this class at which a list of the resulting child
  # objects are stored.
  sql_children = {}

  @classmethod
  def sql_fetch(cls, db, **kwargs):
    """Fetch rows from SQL based on a canned query and a set of
    keyword arguments, and instantiate them as objects, returning a
    list of the instantiated objects.

    This is a class method because in general we don't even know how
    many matches the SQL lookup will return until after we've
    performed it.
    """

    cur = db.cursor()
    cur.execute(self.sql_fetch_cmd % kwargs)
    rows = cur.fetchall()
    cur.close()
    objs = []
    for row in rows:
      obj = cls()
      obj.sql_objectify(row)
      objs.append(obj)
      if isinstance(obj, sql_persistant):
        for kid in obj.sql_children:
          setattr(obj, obj.sql_children[kid], kid.sql_fetch(db))
    return objs
      
  def sql_objectify(self, row):
    """Initialize self with values returned by self.sql_fetch().

    This method is also responsible for performing the
    fetch/objectify() cycle on any of its children in the tree of
    classes representing SQL tables in this database.  But I'm trying
    to move that responsibility to self.sql_fetch()....    
    """

    raise NotImplementedError
