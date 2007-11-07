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
    """Build a SQL template."""
    index_column = columns[0]
    data_columns = columns[1:]
    self.table   = table_name
    self.index   = index_column
    self.columns = columns
    self.select  = "SELECT %s FROM %s" % (", ".join(columns), table_name)
    self.insert  = "INSERT %s (%s) VALUES (%s)" % (table_name, ", ".join(data_columns),
                                                   ", ".join("%(" + s + ")s" for s in data_columns))
    self.update  = "UPDATE %s SET %s WHERE %s = %%(%s)s" % \
                   (table_name, ", ".join(s + " = %(" + s + ")s" for s in data_columns),
                    index_column, index_column)
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
  for s in sql_dirty.copy():
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
    """Fetch one object from SQL, based on its primary key."""
    return cls.sql_fetch_where1(gctx, "%s = %s" % (cls.sql_template.index, id))

  @classmethod
  def sql_fetch_where1(cls, gctx, where):
    """Fetch one object from SQL, based on an arbitrary SQL WHERE expression."""
    results = cls.sql_fetch_where(gctx, where)
    if len(results) == 0:
      return None
    elif len(results) == 1:
      return results[0]
    else:
      raise rpki.exceptions.DBConsistancyError, \
            "Database contained multiple matches for %s.%s" % (cls.__name__, id)

  @classmethod
  def sql_fetch_all(cls, gctx):
    """Fetch all objects of this type from SQL."""
    return cls.sql_fetch_where(gctx, None)

  @classmethod
  def sql_fetch_where(cls, gctx, where):
    """Fetch objects of this type matching an arbitrary SQL WHERE expression."""
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
    """Initialize one Python object from the result of a SQL query."""
    self = cls()
    self.sql_decode(dict(zip(cls.sql_template.columns, row)))
    sql_cache[key] = self
    self.sql_in_db = True
    self.sql_fetch_hook(gctx)
    return self

  def sql_mark_dirty(self):
    """Mark this object as needing to be written back to SQL."""
    sql_dirty.add(self)

  def sql_mark_clean(self):
    """Mark this object as not needing to be written back to SQL."""
    sql_dirty.discard(self)

  def sql_is_dirty(self):
    """Query whether this object needs to be written back to SQL."""
    return self in sql_dirty

  def sql_store(self, gctx):
    """Store this object to SQL."""
    if not self.sql_in_db:
      gctx.cur.execute(self.sql_template.insert, self.sql_encode())
      setattr(self, self.sql_template.index, gctx.cur.lastrowid)
      sql_cache[(self.__class__, gctx.cur.lastrowid)] = self
      self.sql_insert_hook(gctx)
    else:
      gctx.cur.execute(self.sql_template.update, self.sql_encode())
      self.sql_update_hook(gctx)
    key = (self.__class__, getattr(self, self.sql_template.index))
    assert key in sql_cache and sql_cache[key] == self
    self.sql_mark_clean()
    self.sql_in_db = True

  def sql_delete(self, gctx):
    """Delete this object from SQL."""
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
    return dict((a, getattr(self, a, None)) for a in self.sql_template.columns)

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

  sql_template = template("ca", "ca_id", "last_crl_sn", "next_crl_update", "last_issued_sn",
                          "last_manifest_sn", "next_manifest_update", "sia_uri", "parent_id",
                          "parent_resource_class")

  def construct_sia_uri(self, gctx, parent, rc):
    """Construct the sia_uri value for this CA given configured
    information and the parent's up-down protocol list_response PDU.
    """
    repository = rpki.left_right.repository_elt.sql_fetch(gctx, parent.repository_id)
    sia_uri = rc.suggested_sia_head and rc.suggested_sia_head.rsync()
    if not sia_uri or not sia_uri.startswith(parent.sia_base):
      sia_uri = parent.sia_base
    elif not sia_uri.endswith("/"):
      raise rpki.exceptions.BadURISyntax, "SIA URI must end with a slash: %s" % sia_uri
    return sia_uri + str(self.ca_id) + "/"

  def check_for_updates(self, gctx, parent, rc):
    """Parent has signaled continued existance of a resource class we
    already knew about, so we need to check for an updated
    certificate, changes in resource coverage, etc.

    If all certs in the resource class match existing active or
    pending ca_detail certs, we have nothing to do.  Otherwise, hand
    off to the affected ca_detail for processing.
    """
    cert_map = dict((c.cert.get_SKI(), c) for c in rc.certs)
    ca_details = ca_detail_obj.sql_fetch_where(gctx, "ca_id = %s AND latest_ca_cert IS NOT NULL" % self.ca_id)
    as, v4, v6 = ca_detail_obj.sql_fetch_active(gctx, self.ca_id).latest_ca_cert.get_3779resources()
    undersized = not rc.resource_set_as.issubset(as) or \
                 not rc.resource_set_ipv4.issubset(v4) or not rc.resource_set_ipv6.issubset(v6)
    oversized  = not as.issubset(rc.resource_set_as) or \
                 not v4.issubset(rc.resource_set_ipv4) or not v6.issubset(rc.resource_set_ipv6)
    sia_uri = self.construct_sia_uri(gctx, parent, rc)
    sia_uri_changed = self.sia_uri != sia_uri
    if sia_uri_changed:
      self.sia_uri = sia_uri
      self.sql_mark_dirty()
    for ca_detail in ca_details:
      assert ca_detail.state != "pending" or (as, v4, v6) == ca_detail.get_3779resources(), \
             "Resource mismatch for pending cert"
    for ca_detail in ca_details:
      ski = ca_detail.latest_ca_cert.get_SKI()
      assert ski in cert_map, \
             "Certificate in our database missing from list_response, SKI %s" % \
             ca_detail.latest_ca_cert.hSKI()
      if ca_detail.state != "deprecated" and \
           (undersized or oversized or sia_uri_changed or ca_detail.latest_ca_cert != cert_map[ski].cert):
        ca_detail.update(gctx, parent, self, rc, cert_map[ski].cert, undersized, oversized, sia_uri_changed,
                         as, v4, v6)
      del cert_map[ski]
    assert not cert_map, "Certificates in list_response missing from our database, SKIs %s" % \
           ", ".join(c.cert.hSKI() for c in cert_map.values())

  @classmethod
  def create(cls, gctx, parent, rc):
    """Parent has signaled existance of a new resource class, so we
    need to create and set up a corresponding CA object.
    """
    self = cls()
    self.parent_id = parent.parent_id
    self.parent_resource_class = rc.class_name
    self.sql_store(gctx)
    self.sia_uri = self.construct_sia_uri(gctx, parent, rc)
    ca_detail = ca_detail_obj.create(gctx, self)
    issue_response = rpki.up_down.issue_pdu.query(gctx, parent, self, ca_detail)
    issue_response.payload.check_syntax()
    ca_detail.latest_ca_cert = issue_response.payload.classes[0].certs[0].cert
    ca_detail.ca_cert_uri = issue_response.payload.classes[0].certs[0].cert_url.rsync()
    ca_detail.state = "active"
    ca_detail.sql_mark_dirty()

  def delete(self, gctx):
    """The list of current resource classes received from parent does
    not include the class corresponding to this CA, so we need to
    delete it (and its little dog too...).

    All certs published by this CA are now invalid, so need to
    withdraw them, the CRL, and the manifest from the repository,
    delete all child_cert and ca_detail records associated with this
    CA, then finally delete this CA itself.
    """

    repository = rpki.left_right.repository_elt.sql_fetch_where1(gctx, "repository.repository_id = parent.repository_id AND parent.parent_id = %s" % self.parent_id)

    for ca_detail in ca_detail_obj.sql_fetch_where(gctx, "ca_id = %s" % self.ca_id):
      for child_cert in child_cert_obj.sql_fetch_where(gctx, "ca_detail_id = %s" % ca_detail.ca_detail_id):
        repository.withdraw(child_cert.cert)
        child_cert.sql_delete(gctx)
      repository.withdraw(ca_detail.latest_crl, ca_detail.latest_manifest, ca_detail.latest_manifest_cert)
      ca_detail.sql_delete(gctx)
    self.sql_delete(gctx)

  def next_serial_number(self):
    """Allocate a certificate serial number."""
    self.last_issued_sn += 1
    self.sql_mark_dirty()
    return self.last_issued_sn

  def next_manifest_number(self):
    """Allocate a manifest serial number."""
    self.last_manifest_sn += 1
    self.sql_mark_dirty()
    return self.last_manifest_sn

  def next_crl_number(self):
    """Allocate a CRL serial number."""
    self.last_crl_sn += 1
    self.sql_mark_dirty()
    return self.last_crl_sn

class ca_detail_obj(sql_persistant):
  """Internal CA detail object."""

  sql_template = template("ca_detail", "ca_detail_id", "private_key_id", "public_key", "latest_ca_cert",
                          "manifest_private_key_id", "manifest_public_key", "latest_manifest_cert",
                          "latest_manifest", "latest_crl", "state", "ca_cert_uri", "ca_id")

  def sql_decode(self, vals):
    """Decode SQL representation of a ca_detail_obj."""
    sql_persistant.sql_decode(self, vals)
    for i,t in (("private_key_id",          rpki.x509.RSA),
                ("public_key",              rpki.x509.RSApublic),
                ("latest_ca_cert",          rpki.x509.X509),
                ("manifest_private_key_id", rpki.x509.RSA),
                ("manifest_public_key",     rpki.x509.RSApublic),
                ("latest_manifest_cert",    rpki.x509.X509),
                ("latest_manifest",         rpki.x509.SignedManifest),
                ("latest_crl",              rpki.x509.CRL)):
      if getattr(self, i, None) is not None:
        setattr(self, i, t(DER = getattr(self, i)))
    assert (self.public_key is None and self.private_key_id is None) or \
           self.public_key.get_DER() == self.private_key_id.get_public_DER()
    assert (self.manifest_public_key is None and self.manifest_private_key_id is None) or \
           self.manifest_public_key.get_DER() == self.manifest_private_key_id.get_public_DER()

  def sql_encode(self):
    """Encode SQL representation of a ca_detail_obj."""
    d = sql_persistant.sql_encode(self)
    for i in ("private_key_id", "public_key", "latest_ca_cert", "manifest_private_key_id",
              "manifest_public_key", "latest_manifest_cert", "latest_manifest", "latest_crl"):
      if d[i] is not None:
        d[i] = d[i].get_DER()
    return d

  @classmethod
  def sql_fetch_active(cls, gctx, ca_id):
    """Fetch the current active ca_detail_obj associated with a given ca_id."""
    actives = cls.sql_fetch_where(gctx, "ca_id = %s AND state = 'active'" % ca_id)
    assert len(actives) < 2, "Found more than one 'active' ca_detail record, this should not happen!"
    if actives:
      return actives[0]
    else:
      return None

  def update(self, gctx, parent, ca, rc, newcert, undersized, oversized, sia_uri_changed, as, v4, v6):
    """CA has received a cert for this ca_detail that doesn't match
    the current one, figure out what to do about it.  Cases:

    - Nothing changed but serial and dates (reissue due to
      expiration), no change to children needed.

    - Issuer-supplied values other than resources changed, probably no
      change needed to children either (but need to confirm this).

    - Resources changed, will need to frob any children affected by
      shrinkage.

    - ca.sia_uri changed, probably need to frob all children.
    """
    if undersized:
      issue_response = rpki.up_down.issue_pdu.query(gctx, parent, ca, self)
      issue_response.check()
      self.latest_ca_cert = issue_response.classes[0].certs[0]
      as, v4, v6 = self.latest_ca_cert.get_3779resources()
    if oversized or sia_uri_changed:
      for child_cert in child_cert_obj.sql_fetch_where(gctx, "ca_detail_id = %s" % self.ca_detail_id):
        child_as, child_v4, child_v6 = child_cert.cert.get_3779resources()
        if sia_uri_changed or not child_as.issubset(as) or \
             not child_v4.issubset(v4) or not child_v6.issubset(v6):
          child_cert.reissue(gctx, self, as, v4, v6)

  @classmethod
  def create(cls, gctx, ca):
    """Create a new ca_detail object for a specified CA."""
    keypair = rpki.x509.RSA()
    keypair.generate()
    self = cls()
    self.ca_id = ca.ca_id
    self.private_key_id = keypair
    self.public_key = keypair.get_RSApublic()
    self.state = "pending"
    self.sql_store(gctx)
    return self

  def issue(self, gctx, ca, child, subject_key, sia, as, v4, v6, child_cert = None):
    """Issue a new certificate to a child.

    Need to figure out how to share code between issuance of a new
    child_cert and reissuance of an existing child cert.  If I
    understand this correctly, the difference is that in the former
    case we're pulling stuff from a PKCS #10, in the latter we're
    pulling it from the previous cert.  If this theory is correct,
    then this method needs to take an extra optional argument which is
    a child_cert object to update, and we create a new one if none is
    given.  child_cert.reissue() becomes the routine that fishes all
    the right information out of the existing cert then calls this
    method to finish the job.
    """
    cert = self.latest_ca_cert.issue(keypair = self.private_key_id,
                                     subject_key = subject_key,
                                     serial = ca.next_serial_number(),
                                     aia = self.ca_cert_uri,
                                     crldp = ca.sia_uri + self.latest_ca_cert.gSKI() + ".crl",
                                     sia = sia,
                                     as = rc_as,
                                     v4 = rc_v4,
                                     v6 = rc_v6)

    manifest = self.generate_manifest()
    
    repository = rpki.left_right.repository_elt.sql_fetch_where1(gctx, """
                repository.repository_id = parent.repository_id AND
                parent.parent_id = ca.parent_id AND
                ca.ca_id = %s
                """ % self.ca_id)

    repository.publish(cert, manifest)

    if child_cert is None:
      return rpki.sql.child_cert_obj(child_id = child.child_id,
                                     ca_detail_id = self.ca_detail_id,
                                     cert = cert)
    else:
      assert child_cert.child_id == child.child_id and child_cert.ca_detail_id == self.ca_detail_id
      child_cert.cert = cert
      return child_cert

  def generate_crl(self, gctx):
    """Generate a new CRL for this ca_detail.  At the moment this is
    unconditional, that is, it is up to the caller to decide whether a
    new CRL is needed.
    """

    ca = ca_obj.sql_fetch(gctx, self.ca_id)
    self_obj = rpki.left_right.self_elt.sql_fetch_where1(gctx, """
                self.self_id = parent.self_id AND
                parent.parent_id = %s
      """ % ca.parent_id)
    now = time.time()
    then = now + self_obj.crl_interval
    certs = []
    for cert in child_cert_obj.sql_fetch_where(gctx, """
                        child_cert.ca_detail_id = %s AND
                        child_cert.revoked IS NOT NULL
                    """ % self.ca_detail_id):
      raise rpki.exceptions.NotImplementedYet
      # Extract expiration time, figure out whether we still need to list this cert.
      # If not, delete it from child_cert table.  Otherwise, we need to include this
      # cert, so: extract serial and revocation time, convert date to format
      # POW.pkix wants, and add to serial and revocation time to certs[] list.
      # Tuple of the form (serial, ("generalTime", timestamp), ())

    # Sort certs[] into serial order?  Not sure it's necessary, but should be simple and harmless.

    # Stuff result into crl structure

    crl = rpki.x509.CRL()

    # Sign crl

    raise rpki.exceptions.NotImplementedYet

  def generate_manifest(self, gctx):
    """Generate a new manifest for this ca_detail."""

    ca = ca_obj.sql_fetch(gctx, self.ca_id)
    self_obj = rpki.left_right.self_elt.sql_fetch_where1(gctx, """
                self.self_id = parent.self_id AND
                parent.parent_id = %s
      """ % ca.parent_id)
    certs = child_cert_obj.sql_fetch_where(gctx, """
                child_cert.ca_detail_id = %s AND
                child_cert.revoked IS NULL
      """ % self.ca_detail_id)

    m = rpki.x509.SignedManifest()
    m.build(serial = ca.next_manifest(),
            nextUpdate = time.time() + self_obj.crl_interval,
            names_and_objs = [(c.gSKI() + ".cer", c) for c in certs])
    m.sign(keypair = self.manifest_private_key_id,
           certs = rpki.x509.X509_chain(self.latest_manifest_cert))

    self.latest_manifest = m
    return m

class child_cert_obj(sql_persistant):
  """Certificate that has been issued to a child."""

  sql_template = template("child_cert", "child_cert_id", "cert", "child_id", "ca_detail_id", "revoked")

  def __init__(self, child_id = None, ca_detail_id = None, cert = None):
    """Initialize a child_cert_obj."""
    self.child_id = child_id
    self.ca_detail_id = ca_detail_id
    self.cert = cert
    self.revoked = None
    if child_id or ca_detail_id or cert:
      self.sql_mark_dirty()

  def sql_decode(self, vals):
    """Decode SQL representation of a child_cert_obj."""
    sql_persistant.sql_decode(self, vals)
    self.cert = rpki.x509.X509(DER = self.cert)

  def sql_encode(self):
    """Encode SQL representation of a child_cert_obj."""
    d = sql_persistant.sql_encode(self)
    d["cert"] = self.cert.get_DER()
    return d

  def reissue(self, gctx, ca_detail, as, v4, v6, sia = None):
    """Reissue an existing child_cert_obj."""
    if sia is None:
      sia = self.cert.get_SIA()
    return ca_detail.issue(gctx = gctx,
                           child = rpki.left_right.child_elt.sql_fetch(gctx, self.child_id),
                           subject_key = self.cert.getPublicKey(),
                           sia = sia,
                           as = as,
                           v4 = v4,
                           v6 = v6,
                           child_cert = self)
