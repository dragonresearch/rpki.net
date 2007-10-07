# $Id$

import MySQLdb, rpki.x509

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
    self.table   = table_name
    self.index   = index_column
    self.columns = columns
    self.select  = "SELECT %s FROM %s" % (", ".join(columns), table_name)
    self.insert  = "INSERT %s (%s) VALUES (%s)" % (table_name, ", ".join(data_columns), ", ".join("%(" + s + ")s" for s in data_columns))
    self.update  = "UPDATE %s SET %s WHERE %s = %%(%s)s" % (table_name, ", ".join(s + " = %(" + s + ")s" for s in data_columns), index_column, index_column)
    self.delete  = "DELETE FROM %s WHERE %s = %%s" % (table_name, index_column)

## @var sql_cache
# Cache of objects pulled from SQL.

sql_cache = {}

## @var sql_dirty
# Set of objects that need to be written back to SQL.

sql_dirty = set()

def sql_cache_clear():
  """Clear the object cache."""
  sql_cache.clear()

def sql_assert_pristine():
  """Assert that there are no dirty objects in the cache."""
  assert not sql_dirty, "Dirty objects in SQL cache: %s" % sql_dirty

def sql_sweep(gctx):
  """Write any dirty objects out to SQL."""
  for s in sql_dirty:
    s.sql_store(gctx)

def fetch_column(gctx, *query):
  """Pull a single column from SQL, return it as a list."""
  gctx.cur.execute(*query)
  return [x[0] for x in gctx.cur.fetchall()]

class sql_persistant(object):
  """Mixin for persistant class that needs to be stored in SQL.
  """

  ## @var sql_in_db
  # Whether this object is already in SQL or not.
  sql_in_db = False

  @classmethod
  def sql_fetch(cls, gctx, id):
    results = cls.sql_fetch_where(gctx, "%s = %s" % (cls.sql_template.index, id))
    assert len(results) <= 1
    if len(results) == 0:
      return None
    elif len(results) == 1:
      return results[0]
    else:
      raise rpki.exceptions.DBConsistancyError, "Database contained multiple matches for %s.%s" % (cls.__name__, id)

  @classmethod
  def sql_fetch_all(cls, gctx):
    return cls.sql_fetch_where(gctx, None)

  @classmethod
  def sql_fetch_where(cls, gctx, where):
    if where is None:
      gctx.cur.execute(cls.sql_template.select)
    else:
      gctx.cur.execute(cls.sql_template.select + " WHERE " + where)
    results = []
    for row in gctx.cur.fetchall():
      key = (cls, row[0])
      if key in sql_cache:
        results.append(sql_cache[key])
      else:
        results.append(cls.sql_init(gctx, row, key))
    return results

  @classmethod
  def sql_init(cls, gctx, row, key):
    self = cls()
    self.sql_decode(dict(zip(cls.sql_template.columns, row)))
    sql_cache[key] = self
    self.sql_in_db = True
    self.sql_fetch_hook(gctx)
    return self

  def sql_mark_dirty(self):
    sql_dirty.add(self)

  def sql_mark_clean(self):
    sql_dirty.discard(self)

  def sql_is_dirty(self):
    return self in sql_dirty

  def sql_store(self, gctx):
    if not self.sql_in_db:
      gctx.cur.execute(self.sql_template.insert, self.sql_encode())
      setattr(self, self.sql_template.index, gctx.cur.lastrowid)
      sql_cache[(self.__class__, gctx.cur.lastrowid)] = self
      self.sql_insert_hook(gctx)
    elif self in sql_dirty:
      gctx.cur.execute(self.sql_template.update, self.sql_encode())
      self.sql_update_hook(gctx)
    key = (self.__class__, getattr(self, self.sql_template.index))
    assert key in sql_cache and sql_cache[key] == self
    self.sql_mark_clean()
    self.sql_in_db = True

  def sql_delete(self, gctx):
    if self.sql_in_db:
      id = getattr(self, self.sql_template.index)
      gctx.cur.execute(self.sql_template.delete, id)
      self.sql_delete_hook(gctx)
      key = (self.__class__, id)
      if sql_cache.get(key) == self:
        del sql_cache[key]
      self.sql_in_db = False
      self.sql_mark_clean()

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

  def sql_fetch_hook(self, gctx):
    """Customization hook."""
    pass

  def sql_insert_hook(self, gctx):
    """Customization hook."""
    pass
  
  def sql_update_hook(self, gctx):
    """Customization hook."""
    self.sql_delete_hook(gctx)
    self.sql_insert_hook(gctx)

  def sql_delete_hook(self, gctx):
    """Customization hook."""
    pass

# Some persistant objects are defined in rpki.left_right, since
# they're also left-right PDUs.  The rest are defined below, for now.

class ca_obj(sql_persistant):
  """Internal CA object."""

  sql_template = template("ca", "ca_id", "last_crl_sn", "next_crl_update", "last_issued_sn", "last_manifest_sn", "next_manifest_update", "sia_uri", "parent_id")

  def check_for_updates(self, gctx, parent, rc):
    """Parent has signaled continued existance of a resource class we
    already knew about, so we need to check for an updated
    certificate, changes in resource coverage, etc.

    If all certs in the resource class match existing active ca_detail
    certs, we have nothing to do.  Other cases:

    - Nothing changed but serial and dates (reissue due to
      expiration), no change to children needed.

    - Issuer-supplied values other than resources changed, probably no
      change needed to children either.

    - Resources changed (grow, shrink), will have to frob children.

    - Set of keys within this resource class for which child has certs
      does not match parent.  Can this happen?  Handle or raise exception?

    - Multiple certs (rollover in progress, probably) with resources
      that don't match.  This seems like an error, raise exception.

    - Other cases I've forgotten?
    """

    cert_map = dict((c.get_SKI(), c) for c in rc.certs)
    for ca_detail in ca_detail_obj.sql_fetch_where(gctx, "ca_id = %s AND latest_ca_cert IS NOT NULL", ca.ca_id):
      ski = ca_detail.latest_ca_cert.get_SKI()
      assert ski in cert_map, "Certificate in our database missing from list_response, SKI %s" % ":".join(("%02X" % ord(i) for i in ski))
      if ca_detail.latest_ca_cert != cert_map[ski]:
        ca_detail.update_latest_ca_cert(cert_map[ski])
      del cert_map[ski]
    assert not cert_map, "Certificates in list_response missing from our database, SKIs %s" % " ".join(":".join("%02X" % ord(i) for i in j) for j in cert_map.keys())

  @classmethod
  def create(cls, gctx, parent, rc):
    """Parent has signaled existance of a new resource class, so we
    need to create and set up a corresponding CA object.
    """
    self = cls()
    raise NotImplementedError

  def delete(self, gctx):
    """Parent's list of current resource classes doesn't include the
    class corresponding to this CA, so we need to delete it (and its
    little dog too...).
    """
    raise NotImplementedError

class ca_detail_obj(sql_persistant):
  """Internal CA detail object."""

  sql_template = template("ca", "ca_detail_id", "private_key_id", "public_key", "latest_ca_cert", "manifest_private_key_id",
                          "manifest_public_key", "latest_manifest_cert", "latest_manifest", "latest_crl", "state", "ca_cert_uri", "ca_id")

  def sql_decode(self, vals):
    sql_persistant.sql_decode(self, vals)
    self.private_key_id = rpki.x509.RSA(DER = self.private_key_id)
    assert self.public_key is None or self.private_key_id.get_public_DER() == self.public_key
    self.latest_ca_cert = rpki.x509.X509(DER = self.latest_ca_cert)
    self.manifest_private_key_id = rpki.x509.RSA(DER = self.manifest_private_key_id)
    assert self.manifest_public_key is None or self.manifest_private_key_id.get_public_DER() == self.manifest_public_key
    self.manifest_cert = rpki.x509.X509(DER = self.manifest_cert)
    raise NotImplementedError, "Still have to handle manifest and CRL"

  def sql_encode(self):
    d = sql_persistant.sql_encode(self)
    d["private_key_id"] = self.private_key_id.get_DER()
    d["latest_ca_cert"] = self.latest_ca_cert.get_DER()
    d["manifest_private_key_id"] = self.manifest_private_key_id.get_DER()
    d["manifest_cert"] = self.manifest_cert.get_DER()
    raise NotImplementedError, "Still have to handle manifest and CRL"
    return d

  @classmethod
  def sql_fetch_active(cls, gctx, ca_id):
    actives = cls.sql_fetch_where(gctx, "ca_id = %s AND state = 'active'" % ca_id)
    assert len(actives) < 2, "Found more than one 'active' ca_detail record, this should not happen!"
    if actives:
      return actives[0]
    else:
      return None

class child_cert_obj(sql_persistant):
  """Certificate that has been issued to a child."""

  sql_template = template("child_cert", "child_cert_id", "cert", "child_id", "ca_detail_id")

  def sql_decode(self, vals):
    sql_persistant.sql_decode(self, vals)
    self.cert = rpki.x509.X509(DER = self.cert)

  def sql_encode(self):
    d = sql_persistant.sql_encode(self)
    d["cert"] = self.cert.get_DER()
    return d
