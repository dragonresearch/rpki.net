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

  @classmethod
  def sql_fetch(cls, gctx, id):
    """Fetch one object from SQL, based on its primary key.  Since in
    this one case we know that the primary index is also the cache
    key, we check for a cache hit directly in the hope of bypassing the
    SQL lookup entirely.
    """
    key = (cls, id)
    if key in gctx.sql_cache:
      return gctx.sql_cache[key]
    else:
      return cls.sql_fetch_where1(gctx, "%s = %s", (cls.sql_template.index, id))

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
      gctx.cur.execute(cls.sql_template.select)
    else:
      gctx.cur.execute(cls.sql_template.select + " WHERE " + where, args)
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

# Some persistant objects are defined in rpki.left_right, since
# they're also left-right PDUs.  The rest are defined below, for now.

class ca_obj(sql_persistant):
  """Internal CA object."""

  sql_template = template(
    "ca", "ca_id", "last_crl_sn",
    ("next_crl_update", rpki.sundial.datetime),
    "last_issued_sn", "last_manifest_sn",
    ("next_manifest_update", rpki.sundial.datetime),
    "sia_uri", "parent_id", "parent_resource_class")

  last_crl_sn = 0
  last_issued_sn = 0
  last_manifest_sn = 0

  def parent(self):
    """Fetch parent object to which this CA object links."""
    return rpki.left_right.parent_elt.sql_fetch(self.gctx, self.parent_id)

  def ca_details(self):
    """Fetch all ca_detail objects that link to this CA object."""
    return ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s", (self.ca_id,))

  def fetch_pending(self):
    """Fetch the pending ca_details for this CA, if any."""
    return ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND state = 'pending'", (self.ca_id,))

  def fetch_active(self):
    """Fetch the active ca_detail for this CA, if any."""
    return ca_detail_obj.sql_fetch_where1(self.gctx, "ca_id = %s AND state = 'active'", (self.ca_id,))

  def fetch_deprecated(self):
    """Fetch deprecated ca_details for this CA, if any."""
    return ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND state = 'deprecated'", (self.ca_id,))

  def fetch_revoked(self):
    """Fetch revoked ca_details for this CA, if any."""
    return ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND state = 'revoked'", (self.ca_id,))

  def construct_sia_uri(self, parent, rc):
    """Construct the sia_uri value for this CA given configured
    information and the parent's up-down protocol list_response PDU.
    """

    repository = parent.repository()
    sia_uri = rc.suggested_sia_head and rc.suggested_sia_head.rsync()
    if not sia_uri or not sia_uri.startswith(parent.sia_base):
      sia_uri = parent.sia_base
    elif not sia_uri.endswith("/"):
      raise rpki.exceptions.BadURISyntax, "SIA URI must end with a slash: %s" % sia_uri
    return sia_uri + str(self.ca_id) + "/"

  def check_for_updates(self, parent, rc):
    """Parent has signaled continued existance of a resource class we
    already knew about, so we need to check for an updated
    certificate, changes in resource coverage, revocation and reissue
    with the same key, etc.
    """

    sia_uri = self.construct_sia_uri(parent, rc)
    sia_uri_changed = self.sia_uri != sia_uri
    if sia_uri_changed:
      self.sia_uri = sia_uri
      self.sql_mark_dirty()

    rc_resources = rc.to_resource_bag()
    cert_map = dict((c.cert.get_SKI(), c) for c in rc.certs)

    for ca_detail in ca_detail_obj.sql_fetch_where(self.gctx, "ca_id = %s AND latest_ca_cert IS NOT NULL AND state != 'revoked'", (self.ca_id,)):
      ski = ca_detail.latest_ca_cert.get_SKI()
      if ca_detail.state in ("pending", "active"):
        current_resources = ca_detail.latest_ca_cert.get_3779resources()
        if sia_uri_changed or \
             ca_detail.latest_ca_cert != cert_map[ski].cert or \
             current_resources.undersized(rc_resources) or \
             current_resources.oversized(rc_resources):
          ca_detail.update(
            parent           = parent,
            ca               = self,
            rc               = rc,
            sia_uri_changed  = sia_uri_changed,
            old_resources    = current_resources)
      del cert_map[ski]
    assert not cert_map, "Certificates in list_response missing from our database, SKIs %s" % ", ".join(c.cert.hSKI() for c in cert_map.values())

  @classmethod
  def create(cls, parent, rc):
    """Parent has signaled existance of a new resource class, so we
    need to create and set up a corresponding CA object.
    """

    self = cls()
    self.gctx = parent.gctx
    self.parent_id = parent.parent_id
    self.parent_resource_class = rc.class_name
    self.sql_store()
    self.sia_uri = self.construct_sia_uri(parent, rc)
    ca_detail = ca_detail_obj.create(self)

    # This will need a callback when we go event-driven
    issue_response = rpki.up_down.issue_pdu.query(parent, self, ca_detail)

    ca_detail.activate(
      ca   = self,
      cert = issue_response.payload.classes[0].certs[0].cert,
      uri  = issue_response.payload.classes[0].certs[0].cert_url)

  def delete(self, parent):
    """The list of current resource classes received from parent does
    not include the class corresponding to this CA, so we need to
    delete it (and its little dog too...).

    All certs published by this CA are now invalid, so need to
    withdraw them, the CRL, and the manifest from the repository,
    delete all child_cert and ca_detail records associated with this
    CA, then finally delete this CA itself.
    """

    repository = parent.repository()
    for ca_detail in self.ca_details():
      ca_detail.delete(ca, repository)
    self.sql_delete()

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

  def rekey(self):
    """Initiate a rekey operation for this ca.

    Tasks:

    - Generate a new keypair.

    - Request cert from parent using new keypair.

    - Mark result as our active ca_detail.

    - Reissue all child certs issued by this ca using the new ca_detail.
    """

    rpki.log.trace()

    parent = self.parent()
    old_detail = self.fetch_active()
    new_detail = ca_detail_obj.create(self)

    # This will need a callback when we go event-driven
    issue_response = rpki.up_down.issue_pdu.query(parent, self, new_detail)

    new_detail.activate(
      ca          = self,
      cert        = issue_response.payload.classes[0].certs[0].cert,
      uri         = issue_response.payload.classes[0].certs[0].cert_url,
      predecessor = old_detail)

  def revoke(self):
    """Revoke deprecated ca_detail objects associated with this ca."""

    rpki.log.trace()

    for ca_detail in self.fetch_deprecated():
      ca_detail.revoke()

class ca_detail_obj(sql_persistant):
  """Internal CA detail object."""

  sql_template = template(
    "ca_detail",
    "ca_detail_id",
    ("private_key_id",          rpki.x509.RSA),
    ("public_key",              rpki.x509.RSApublic),
    ("latest_ca_cert",          rpki.x509.X509),
    ("manifest_private_key_id", rpki.x509.RSA),
    ("manifest_public_key",     rpki.x509.RSApublic),
    ("latest_manifest_cert",    rpki.x509.X509),
    ("latest_manifest",         rpki.x509.SignedManifest),
    ("latest_crl",              rpki.x509.CRL),
    "state",
    "ca_cert_uri",
    "ca_id")
  
  def sql_decode(self, vals):
    """Extra assertions for SQL decode of a ca_detail_obj."""
    sql_persistant.sql_decode(self, vals)
    assert (self.public_key is None and self.private_key_id is None) or \
           self.public_key.get_DER() == self.private_key_id.get_public_DER()
    assert (self.manifest_public_key is None and self.manifest_private_key_id is None) or \
           self.manifest_public_key.get_DER() == self.manifest_private_key_id.get_public_DER()

  def ca(self):
    """Fetch CA object to which this ca_detail links."""
    return ca_obj.sql_fetch(self.gctx, self.ca_id)

  def child_certs(self, child = None, ski = None, unique = False):
    """Fetch all child_cert objects that link to this ca_detail."""
    return rpki.sql.child_cert_obj.fetch(self.gctx, child, self, ski, unique)

  def revoked_certs(self):
    """Fetch all revoked_cert objects that link to this ca_detail."""
    return revoked_cert_obj.sql_fetch_where(self.gctx, "ca_detail_id = %s", (self.ca_detail_id,))

  def route_origins(self):
    """Fetch all route_origin objects that link to this ca_detail."""
    return rpki.left_right.route_origin_elt.sql_fetch_where(self.gctx, "ca_detail_id = %s", (self.ca_detail_id,))

  def crl_uri(self, ca):
    """Return publication URI for this ca_detail's CRL."""
    return ca.sia_uri + self.public_key.gSKI() + ".crl"

  def manifest_uri(self, ca):
    """Return publication URI for this ca_detail's manifest."""
    return ca.sia_uri + self.public_key.gSKI() + ".mnf"

  def activate(self, ca, cert, uri, predecessor = None):
    """Activate this ca_detail."""

    self.latest_ca_cert = cert
    self.ca_cert_uri = uri.rsync()
    self.generate_manifest_cert(ca)
    self.generate_crl()
    self.generate_manifest()
    self.state = "active"
    self.sql_mark_dirty()

    if predecessor is not None:
      predecessor.state = "deprecated"
      predecessor.sql_mark_dirty()
      for child_cert in predecessor.child_certs():
        child_cert.reissue(self)
      for route_origin in predecessor.route_origins():
        if route_origin.roa:
          raise rpki.exceptions.NotImplementedYet, "Don't (yet) know how to reissue ROAs"

  def delete(self, ca, repository):
    """Delete this ca_detail and all of the certs it issued."""

    for child_cert in self.child_certs():
      repository.withdraw(child_cert.cert, child_cert.uri(ca))
      child_cert.sql_delete()
    for revoked__cert in self.revoked_certs():
      revoked_cert.sql_delete()
    for route_origin in self.route_origins():
      if route_origin.roa:
        raise rpki.exceptions.NotImplementedYet, "Don't (yet) know how to withdraw ROAs"
    repository.withdraw(self.latest_manifest, self.manifest_uri(ca))
    repository.withdraw(self.latest_crl, self.crl_uri())
    self.sql_delete()

  def revoke(self):
    """Request revocation of all certificates whose SKI matches the key for this ca_detail.

    Tasks:

    - Request revocation of old keypair by parent.

    - Revoke all child certs issued by the old keypair.

    - Generate a final CRL, signed with the old keypair, listing all
      the revoked certs, with a next CRL time after the last cert or
      CRL signed by the old keypair will have expired.

    - Destroy old keypair (and manifest keypair).

    - Leave final CRL in place until its next CRL time has passed.
    """

    # This will need a callback when we go event-driven
    r_msg = rpki.up_down.revoke_pdu.query(self)

    if r_msg.payload.ski != self.latest_ca_cert.gSKI():
      raise rpki.exceptions.SKIMismatch

    ca = self.ca()
    parent = ca.parent()
    crl_interval = rpki.sundial.timedelta(seconds = parent.self().crl_interval)

    nextUpdate = rpki.sundial.now()

    if self.latest_manifest is not None:
      nextUpdate = nextUpdate.later(self.latest_manifest.getNextUpdate())

    if self.latest_crl is not None:
      nextUpdate = nextUpdate.later(self.latest_crl.getNextUpdate())

    for child_cert in self.child_certs():
      nextUpdate = nextUpdate.later(child_cert.cert.getNotAfter())
      child_cert.revoke()

    nextUpdate += crl_interval

    self.generate_crl(nextUpdate)
    self.generate_manifest(nextUpdate)

    self.private_key_id = None
    self.manifest_private_key_id = None
    self.manifest_public_key = None
    self.latest_manifest_cert = None
    self.state = "revoked"
    self.sql_mark_dirty()

  def update(self, parent, ca, rc, sia_uri_changed, old_resources):
    """Need to get a new certificate for this ca_detail and perhaps
    frob children of this ca_detail.
    """

    # This will need a callback when we go event-driven
    issue_response = rpki.up_down.issue_pdu.query(parent, ca, self)

    self.latest_ca_cert = issue_response.payload.classes[0].certs[0].cert
    new_resources = self.latest_ca_cert.get_3779resources()

    if sia_uri_changed or old_resources.oversized(new_resources):
      for child_cert in self.child_certs():
        child_resources = child_cert.cert.get_3779resources()
        if sia_uri_changed or child_resources.oversized(new_resources):
          child_cert.reissue(
            ca_detail = self,
            resources = child_resources.intersection(new_resources))

  @classmethod
  def create(cls, ca):
    """Create a new ca_detail object for a specified CA."""
    self = cls()
    self.gctx = ca.gctx
    self.ca_id = ca.ca_id
    self.state = "pending"

    self.private_key_id = rpki.x509.RSA()
    self.private_key_id.generate()
    self.public_key = self.private_key_id.get_RSApublic()

    self.manifest_private_key_id = rpki.x509.RSA()
    self.manifest_private_key_id.generate()
    self.manifest_public_key = self.manifest_private_key_id.get_RSApublic()

    self.sql_store()
    return self

  def issue_ee(self, ca, resources, subject_key, sia = None):
    """Issue a new EE certificate."""

    return self.latest_ca_cert.issue(
      keypair     = self.private_key_id,
      subject_key = subject_key,
      serial      = ca.next_serial_number(),
      sia         = sia,
      aia         = self.ca_cert_uri,
      crldp       = self.crl_uri(ca),
      resources   = resources,
      notAfter    = self.latest_ca_cert.getNotAfter(),
      is_ca       = False)


  def generate_manifest_cert(self, ca):
    """Generate a new manifest certificate for this ca_detail."""

    resources = rpki.resource_set.resource_bag(
      as = rpki.resource_set.resource_set_as("<inherit>"),
      v4 = rpki.resource_set.resource_set_ipv4("<inherit>"),
      v6 = rpki.resource_set.resource_set_ipv6("<inherit>"))

    self.latest_manifest_cert = self.issue_ee(ca, resources, self.manifest_public_key)

  def issue(self, ca, child, subject_key, sia, resources, child_cert = None):
    """Issue a new certificate to a child.  Optional child_cert
    argument specifies an existing child_cert object to update in
    place; if not specified, we create a new one.  Returns the
    child_cert object containing the newly issued cert.
    """

    assert child_cert is None or (child_cert.child_id == child.child_id and
                                  child_cert.ca_detail_id == self.ca_detail_id)

    cert = self.latest_ca_cert.issue(
      keypair     = self.private_key_id,
      subject_key = subject_key,
      serial      = ca.next_serial_number(),
      aia         = self.ca_cert_uri,
      crldp       = self.crl_uri(ca),
      sia         = sia,
      resources   = resources,
      notAfter    = resources.valid_until)

    if child_cert is None:
      child_cert = rpki.sql.child_cert_obj(
        gctx         = child.gctx,
        child_id     = child.child_id,
        ca_detail_id = self.ca_detail_id,
        cert         = cert)
      rpki.log.debug("Created new child_cert %s" % repr(child_cert))
    else:
      child_cert.cert = cert
      rpki.log.debug("Reusing existing child_cert %s" % repr(child_cert))

    child_cert.ski = cert.get_SKI()

    child_cert.sql_store()

    ca.parent().repository().publish(child_cert.cert, child_cert.uri(ca))

    self.generate_manifest()
    
    return child_cert

  def generate_crl(self, nextUpdate = None):
    """Generate a new CRL for this ca_detail.  At the moment this is
    unconditional, that is, it is up to the caller to decide whether a
    new CRL is needed.
    """

    ca = self.ca()
    parent = ca.parent()
    repository = parent.repository()
    crl_interval = rpki.sundial.timedelta(seconds = parent.self().crl_interval)
    now = rpki.sundial.now()

    if nextUpdate is None:
      nextUpdate = now + crl_interval

    certlist = []
    for revoked_cert in self.revoked_certs():
      if now > revoked_cert.expires + crl_interval:
        revoked_cert.sql_delete()
      else:
        certlist.append((revoked_cert.serial, revoked_cert.revoked.toASN1tuple(), ()))
    certlist.sort()

    self.latest_crl = rpki.x509.CRL.generate(
      keypair             = self.private_key_id,
      issuer              = self.latest_ca_cert,
      serial              = ca.next_crl_number(),
      thisUpdate          = now,
      nextUpdate          = nextUpdate,
      revokedCertificates = certlist)

    repository.publish(self.latest_crl, self.crl_uri(ca))

  def generate_manifest(self, nextUpdate = None):
    """Generate a new manifest for this ca_detail."""

    ca = self.ca()
    parent = ca.parent()
    repository = parent.repository()
    crl_interval = rpki.sundial.timedelta(seconds = parent.self().crl_interval)
    now = rpki.sundial.now()

    if nextUpdate is None:
      nextUpdate = now + crl_interval

    certs = [(c.uri_tail(), c.cert) for c in self.child_certs()] + \
            [(r.ee_uri_tail(), r.cert) for r in self.route_origins() if r.cert is not None]

    self.latest_manifest = rpki.x509.SignedManifest.build(
      serial         = ca.next_manifest_number(),
      thisUpdate     = now,
      nextUpdate     = nextUpdate,
      names_and_objs = certs,
      keypair        = self.manifest_private_key_id,
      certs          = rpki.x509.X509_chain(self.latest_manifest_cert))

    repository.publish(self.latest_manifest, self.manifest_uri(ca))

class child_cert_obj(sql_persistant):
  """Certificate that has been issued to a child."""

  sql_template = template("child_cert", "child_cert_id", ("cert", rpki.x509.X509), "child_id", "ca_detail_id", "ski")

  def __init__(self, gctx = None, child_id = None, ca_detail_id = None, cert = None):
    """Initialize a child_cert_obj."""
    self.gctx = gctx
    self.child_id = child_id
    self.ca_detail_id = ca_detail_id
    self.cert = cert
    if child_id or ca_detail_id or cert:
      self.sql_mark_dirty()

  def child(self):
    """Fetch child object to which this child_cert object links."""
    return rpki.left_right.child_elt.sql_fetch(self.gctx, self.child_id)

  def ca_detail(self):
    """Fetch ca_detail object to which this child_cert object links."""
    return ca_detail_obj.sql_fetch(self.gctx, self.ca_detail_id)

  def uri_tail(self):
    """Return the tail (filename) portion of the URI for this child_cert."""
    return self.cert.gSKI() + ".cer"

  def uri(self, ca):
    """Return the publication URI for this child_cert."""
    return ca.sia_uri + self.uri_tail()

  def revoke(self):
    """Revoke a child cert."""
    rpki.log.debug("Revoking %s" % repr(self))
    ca_detail = self.ca_detail()
    ca = ca_detail.ca()
    revoked_cert_obj.revoke(cert = self.cert, ca_detail = ca_detail)
    repository = ca.parent().repository()
    repository.withdraw(self.cert, self.uri(ca))
    self.gctx.sql_sweep()
    self.sql_delete()

  def reissue(self, ca_detail, resources = None, sia = None):
    """Reissue an existing cert, reusing the public key.  If the cert
    we would generate is identical to the one we already have, we just
    return the one we already have.  If we have to revoke the old
    certificate when generating the new one, we have to generate a new
    child_cert_obj, so calling code that needs the updated
    child_cert_obj must use the return value from this method.
    """

    ca = ca_detail.ca()
    child = self.child()

    old_resources = self.cert.get_3779resources()
    old_sia       = self.cert.get_SIA()
    old_ca_detail = self.ca_detail()

    if resources is None:
      resources = old_resources

    if sia is None:
      sia = old_sia

    assert resources.valid_until is not None and old_resources.valid_until is not None

    if resources == old_resources and sia == old_sia and ca_detail == old_ca_detail:
      return self

    must_revoke = old_resources.oversized(resources) or old_resources.valid_until > resources.valid_until
    new_issuer  = ca_detail != old_ca_detail

    if resources.valid_until != old_resources.valid_until:
      rpki.log.debug("Validity changed: %s %s" % ( old_resources.valid_until, resources.valid_until))

    if must_revoke or new_issuer:
      child_cert = None
    else:
      child_cert = self

    child_cert = ca_detail.issue(
      ca          = ca,
      child       = child,
      subject_key = self.cert.getPublicKey(),
      sia         = sia,
      resources   = resources,
      child_cert  = child_cert)

    if must_revoke:
      for cert in child.child_certs(ca_detail = ca_detail, ski = self.ski):
        if cert is not child_cert:
          cert.revoke()

    return child_cert

  @classmethod
  def fetch(cls, gctx = None, child = None, ca_detail = None, ski = None, unique = False):
    """Fetch all child_cert objects matching a particular set of
    parameters.  This is a wrapper to consolidate various queries that
    would otherwise be inline SQL WHERE expressions.  In most cases
    code calls this indirectly, through methods in other classes.
    """

    args = []
    where = []

    if child:
      where.append("child_id = %s")
      args.append(child.child_id)

    if ca_detail:
      where.append("ca_detail_id = %s")
      args.append(ca_detail.ca_detail_id)

    if ski:
      where.append("ski = %s")
      args.append(ski)

    where = " AND ".join(where)

    gctx = gctx or (child and child.gctx) or (ca_detail and ca_detail.gctx) or None

    if unique:
      return cls.sql_fetch_where1(gctx, where, args)
    else:
      return cls.sql_fetch_where(gctx, where, args)

class revoked_cert_obj(sql_persistant):
  """Tombstone for a revoked certificate."""

  sql_template = template("revoked_cert", "revoked_cert_id",
                          "serial", "ca_detail_id",
                          ("revoked", rpki.sundial.datetime),
                          ("expires", rpki.sundial.datetime))

  def __init__(self, gctx = None, serial = None, revoked = None, expires = None, ca_detail_id = None):
    """Initialize a revoked_cert_obj."""
    self.gctx = gctx
    self.serial = serial
    self.revoked = revoked
    self.expires = expires
    self.ca_detail_id = ca_detail_id
    if serial or revoked or expires or ca_detail_id:
      self.sql_mark_dirty()

  def ca_detail(self):
    """Fetch ca_detail object to which this revoked_cert_obj links."""
    return ca_detail_obj.sql_fetch(self.gctx, self.ca_detail_id)

  @classmethod
  def revoke(cls, cert, ca_detail):
    """Revoke a certificate."""
    return cls(
      serial       = cert.getSerial(),
      expires      = cert.getNotAfter(),
      revoked      = rpki.sundial.now(),
      gctx         = ca_detail.gctx,
      ca_detail_id = ca_detail.ca_detail_id)
