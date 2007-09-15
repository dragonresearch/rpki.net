# $Id$

import MySQLdb

def connect(cfg, section="sql"):
  """Connect to a MySQL database using connection parameters from an
     rpki.config.parser object.
  """

  return MySQLdb.connect(user   = cfg.get(section, "sql-username"),
                         db     = cfg.get(section, "sql-database"),
                         passwd = cfg.get(section, "sql-password"))

## @var sql_cache
# Cache of objects pulled from SQL.

sql_cache = {}

def cache_clear():
  """Clear the object cache."""

  sql_cache = {}


class sql_persistant(object):
  """Mixin for persistant class that needs to be stored in SQL.
  """

  ## @var sql_children
  # Tuple of tuples associating this class's children in the tree of
  # SQL tables with the attribute names by which this class refers to
  # them.  Conceptually, this is an ordered dictionary; not being able
  # to use a real Python dictionary here is a minor inconvenience.
  # Making this an ordered data structure allows us to defer the
  # objects with complex cross-linking until after the simpler objects
  # to which they link have already been loaded.
  #
  # "Key" is the name of the attribute in this class at which a list
  # of the resulting child objects are stored; "value" is is the class
  # object of a child.
  sql_children = ()

  ## @var sql_in_db
  # Whether this object is already in SQL or not.
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

  def sql_cache_add(self):
    """Add self to the object cache."""

    assert self.sql_id_name is not None
    sql_cache[(self.__class__, self.sql_id_name)] = self

  @classmethod
  def sql_cache_find(*keys):
    """Find an object in the object cache."""

    return sql_cache.get(keys)

  def cache_delete(*keys):
    """Delete self from the object cache."""
    
    assert self.sql_id_name is not None
    del sql_cache[(self.__class__, self.sql_id_name)]

  @classmethod
  def sql_fetch(cls, db, cur=None, select_dict=None, sql_parent=None):
    """Fetch rows from SQL based on a canned query and a set of
    keyword arguments, and instantiate them as objects, returning a
    list of the instantiated objects.  If the object definition
    indicates an index field (sql_id_name), this method instead
    returns as dictionary using the index field as the key.

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
      if self.sql_id_name is not None:
        self.sql_cache_add()
      self_dict = self.sql_encode()
      self.sql_fetch_hook(db, cur)
      result.append(self)
      for k,v in self.sql_children:
        setattr(self, k, v.sql_fetch(db, cur, self_dict, self))
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
        self.sql_cache_add()
      self.sql_insert_hook(db, cur)
    elif self.sql_dirty:
      cur.execute(self.sql_update_cmd, self.sql_encode())
      self.sql_update_hook(db, cur)
    self.sql_dirty = False
    self.sql_in_db = True
    for k,v in self.sql_children:
      for kid in getattr(self, k):
        kid.sql_store(db, cur)

  def sql_delete(self, db, cur=None):
    """Delete an object and its descendants from SQL.
    """
    if cur is None:
      cur = db.cursor()
    if self.sql_in_db:
      cur.execute(self.sql_delete_cmd, self.sql_encode())
      self.sql_delete_hook(db, cur)
      self.sql_in_db = False
    for k,v in self.sql_children:
      for kid in getattr(self, k):
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

  sql_select_cmd = """SELECT ca_detail_id, priv_key_handle, pub_key, latest_ca_cert_over_pubkey, manifest_ee_priv_key_handle, manifest_ee_pub_key,
                             latest_manifest_ee_cert, latest_manifest, latest_crl, ca_id
                      FROM ca_detail
                      WHERE ca_id = %(ca_id)s"""

  sql_insert_cmd = """INSERT ca_detail (priv_key_handle, pub_key, latest_ca_cert_over_pubkey, manifest_ee_priv_key_handle, manifest_ee_pub_key,
                                        latest_manifest_ee_cert, latest_manifest, latest_crl, ca_id)
                      VALUES (%(priv_key_handle)s, %(pub_key)s, %(latest_ca_cert_over_pubkey)s, %(manifest_ee_priv_key_handle)s,
                              %(manifest_ee_pub_key)s, %(latest_manifest_ee_cert)s, %(latest_manifest)s, %(latest_crl)s, %(ca_id)s)"""

  sql_update_cmd = """UPDATE ca
                      SET priv_key_handle = %(priv_key_handle)s, pub_key = %(pub_key)s, latest_ca_cert_over_pubkey = %(latest_ca_cert_over_pubkey)s,
                          manifest_ee_priv_key_handle = %(manifest_ee_priv_key_handle)s, manifest_ee_pub_key = %(manifest_ee_pub_key)s,
                          latest_manifest_ee_cert = %(latest_manifest_ee_cert)s, latest_manifest = %(latest_manifest)s, latest_crl = %(latest_crl)s, ca_id = %(ca_id)s
                      WHERE ca_detail_id = %(ca_detail_id)s"""

  sql_delete_cmd = """DELETE FROM ca_detail WHERE ca_detail_id = %(ca_detail_id)s"""


  def __init__(self):
    self.certs = []

  def sql_decode(self, sql_parent, ca_detail_id, priv_key_handle, pub_key, latest_ca_cert_over_pubkey,
                 manifest_ee_priv_key_handle, manifest_ee_pub_key, latest_manifest_ee_cert, latest_manifest, latest_crl, ca_id):
    assert isinstance(sql_parent, ca_obj)
    self.ca_obj = sql_parent
    self.ca_detail_id = ca_detail_id
    self.priv_key_handle = priv_key_handle
    self.pub_key = pub_key
    self.latest_ca_cert_over_pubkey = latest_ca_cert_over_pubkey
    self.manifest_ee_priv_key_handle = manifest_ee_priv_key_handle
    self.manifest_ee_pub_key = manifest_ee_pub_key
    self.latest_manifest_ee_cert = latest_manifest_ee_cert
    self.latest_manifest = latest_manifest
    self.latest_crl = latest_crl
    self.ca_id = ca_id

  def sql_encode(self):
    return { "ca_detail_id"                     : self.ca_detail_id,
             "priv_key_handle"                  : self.priv_key_handle,
             "pub_key"                          : self.pub_key,
             "latest_ca_cert_over_pubkey"       : self.latest_ca_cert_over_pubkey,
             "manifest_ee_priv_key_handle"      : self.manifest_ee_priv_key_handle,
             "manifest_ee_pub_key"              : self.manifest_ee_pub_key,
             "latest_manifest_ee_cert"          : self.latest_manifest_ee_cert,
             "latest_manifest"                  : self.latest_manifest,
             "latest_crl"                       : self.latest_crl,
             "ca_id"                            : self.ca_id }

class ca_obj(sql_persistant):
  """Internal CA object."""

  sql_select_cmd = """SELECT ca_id, last_crl_sn, next_crl_update, last_issued_sn, last_manifest_sn, next_manifest_update, sia_uri, parent_id
                      FROM ca
                      WHERE parent_id = %(parent_id)s"""
  sql_insert_cmd = """INSERT ca (last_crl_sn, next_crl_update, last_issued_sn, last_manifest_sn, next_manifest_update, sia_uri, parent_id)
                      VALUES (%(last_crl_sn)s, %(next_crl_update)s, %(last_issued_sn)s, %(last_manifest_sn)s, %(next_manifest_update)s, %(sia_uri)s, %(parent_id)s)"""
  sql_update_cmd = """UPDATE ca
                      SET last_crl_sn = %(last_crl_sn)s, next_crl_update = %(next_crl_update)s, last_issued_sn = %(last_issued_sn)s,
                          last_manifest_sn = %(last_manifest_sn)s, next_manifest_update = %(next_manifest_update)s, sia_uri = %(sia_uri)s, parent_id = %(parent_id)s
                      WHERE ca_id = %(ca_id)s"""
  sql_delete_cmd = """DELETE FROM ca WHERE ca_id = %(ca_id)s"""

  sql_children = (("ca_details", ca_detail_obj),)

  def __init__(self):
    self.children = []

  def sql_decode(self, sql_parent, ca_id, last_crl_sn, next_crl_update, last_issued_sn, last_manifest_sn, next_manifest_update, sia_uri, parent_id):
    assert isinstance(sql_parent, rpki.left_right.parent_elt)
    self.parent_obj = sql_parent
    self.ca_id = ca_id
    self.last_crl_sn = last_crl_sn
    self.next_crl_update = next_crl_update
    self.last_issued_sn = last_issued_sn
    self.last_manifest_sn = last_manifest_sn
    self.next_manifest_update = next_manifest_update
    self.sia_uri = sia_uri
    self.parent_id = parent_id

  def sql_encode(self):
    return { "ca_id"                    : self.ca_id,
             "last_crl_sn"              : self.last_crl_sn,
             "next_crl_update"          : self.next_crl_update,
             "last_issued_sn"           : self.last_issued_sn,
             "last_manifest_sn"         : self.last_manifest_sn,
             "next_manifest_update"     : self.next_manifest_update,
             "sia_uri"                  : self.sia_uri,
             "parent_id"                : self.parent_id }
