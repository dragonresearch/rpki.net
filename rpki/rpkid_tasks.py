# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2012--2013  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
rpkid task objects.  Split out from rpki.left_right and rpki.rpkid
because interactions with rpkid scheduler were getting too complicated.
"""

import logging

import tornado.gen
import tornado.web
import tornado.locks
import tornado.ioloop
import tornado.httputil
import tornado.httpclient
import tornado.httpserver

import rpki.log
import rpki.rpkid
import rpki.up_down
import rpki.sundial
import rpki.publication
import rpki.exceptions

logger = logging.getLogger(__name__)

task_classes = ()

def queue_task(cls):
  """
  Class decorator to add a new task class to task_classes.
  """

  global task_classes
  task_classes += (cls,)
  return cls


class AbstractTask(object):
  """
  Abstract base class for rpkid scheduler task objects.
  """

  ## @var timeslice
  # How long before a task really should consider yielding the CPU to
  # let something else run.

  timeslice = rpki.sundial.timedelta(seconds = 15)

  def __init__(self, rpkid, tenant, description = None):
    self.rpkid       = rpkid
    self.tenant      = tenant
    self.description = description
    self.runnable    = tornado.locks.Event()
    self.done_this   = None
    self.done_next   = None
    self.due_date    = None
    self.started     = False
    self.runnable.set()
    self.clear()

    # This field belongs to the rpkid task_loop(), don't touch.
    self.future      = None

  def __repr__(self):
    return rpki.log.log_repr(self, self.description)

  @tornado.gen.coroutine
  def start(self):
    try:
      logger.debug("%r: Starting", self)
      self.due_date = rpki.sundial.now() + self.timeslice
      self.clear()
      self.started = True
      yield self.main()
    except:
      logger.exception("%r: Unhandled exception", self)
      #raise
    finally:
      logger.debug("%r: Exiting", self)
      self.due_date = None
      self.started  = False
      self.clear()
      if self.done_this is not None:
        self.done_this.notify_all()
      self.done_this = self.done_next
      self.done_next = None

  def wait(self):
    done = "done_next" if self.started else "done_this"
    condition = getattr(self, done)
    if condition is None:
      condition = tornado.locks.Condition()
      setattr(self, done, condition)
    future = condition.wait()
    return future

  def waiting(self):
    return self.done_this is not None

  @tornado.gen.coroutine
  def postpone(self):
    logger.debug("%r: Postponing", self)
    self.due_date = None
    self.runnable.clear()
    yield self.runnable.wait()
    logger.debug("%r: Resuming", self)
    self.due_date = rpki.sundial.now() + self.timeslice

  @property
  def overdue(self):
    return rpki.sundial.now() > self.due_date

  @tornado.gen.coroutine
  def main(self):
    raise NotImplementedError

  def clear(self):
    pass


@queue_task
class PollParentTask(AbstractTask):
  """
  Run the regular client poll cycle with each of this tenant's
  parents, in turn.
  """

  @tornado.gen.coroutine
  def main(self):
    logger.debug("%r: Polling parents", self)

    for parent in self.tenant.parents.all():
      try:
        logger.debug("%r: Executing list query", self)
        r_msg = yield parent.up_down_list_query(rpkid = self.rpkid)
      except:
        logger.exception("%r: Couldn't get resource class list from parent %r, skipping", self, parent)
        continue

      logger.debug("%r: Parsing list response", self)

      ca_map = dict((ca.parent_resource_class, ca) for ca in parent.cas.all())

      for rc in r_msg.getiterator(rpki.up_down.tag_class):
        try:
          class_name = rc.get("class_name")
          ca = ca_map.pop(class_name, None)
          if ca is None:
            logger.debug("%r: Creating new CA for resource class %r", self, class_name)
            yield rpki.rpkidb.models.CA.create(rpkid = self.rpkid, parent = parent, rc = rc)
          else:
            logger.debug("%r: Checking updates for existing CA %r for resource class %r", self, ca, class_name)
            yield ca.check_for_updates(rpkid = self.rpkid, parent = parent, rc = rc)
        except:
          logger.exception("Couldn't update resource class %r, skipping", class_name)

      for ca, class_name in ca_map.iteritems():
        logger.debug("%r: Destroying orphaned CA %r for resource class %r", self, ca, class_name)
        yield ca.destroy(parent)


@queue_task
class UpdateChildrenTask(AbstractTask):
  """
  Check for updated IRDB data for all of this tenant's children and
  issue new certs as necessary.  Must handle changes both in
  resources and in expiration date.
  """

  @tornado.gen.coroutine
  def main(self):
    logger.debug("%r: Updating children", self)
    now = rpki.sundial.now()
    rsn = now + rpki.sundial.timedelta(seconds = self.tenant.regen_margin)
    publisher = rpki.rpkid.publication_queue(self.rpkid)

    for child in self.tenant.children.all():
      try:
        if self.overdue:
          yield publisher.call_pubd()
          yield self.postpone()

        child_certs = list(child.child_certs.filter(ca_detail__state = "active"))

        if child_certs:
          irdb_resources = yield self.rpkid.irdb_query_child_resources(child.tenant.tenant_handle, child.child_handle)

          for child_cert in child_certs:
            ca_detail = child_cert.ca_detail
            old_resources = child_cert.cert.get_3779resources()
            new_resources = old_resources & irdb_resources & ca_detail.latest_ca_cert.get_3779resources()
            old_aia = child_cert.cert.get_AIA()[0]
            new_aia = ca_detail.ca_cert_uri

            if new_resources.empty():
              logger.debug("Resources shrank to the null set, revoking and withdrawing child %s certificate SKI %s", child.child_handle, child_cert.cert.gSKI())
              child_cert.revoke(publisher = publisher)
              ca_detail.generate_crl(publisher = publisher)
              ca_detail.generate_manifest(publisher = publisher)

            elif (old_resources != new_resources or old_aia != new_aia or (old_resources.valid_until < rsn and irdb_resources.valid_until > now and old_resources.valid_until != irdb_resources.valid_until)):
              logger.debug("Need to reissue child %s certificate SKI %s", child.child_handle, child_cert.cert.gSKI())
              if old_resources != new_resources:
                logger.debug("Child %s SKI %s resources changed: old %s new %s", child.child_handle, child_cert.cert.gSKI(), old_resources, new_resources)
              if old_resources.valid_until != irdb_resources.valid_until:
                logger.debug("Child %s SKI %s validity changed: old %s new %s", child.child_handle, child_cert.cert.gSKI(), old_resources.valid_until, irdb_resources.valid_until)

              new_resources.valid_until = irdb_resources.valid_until
              child_cert.reissue(ca_detail = ca_detail, resources = new_resources, publisher = publisher)

            elif old_resources.valid_until < now:
              logger.debug("Child %s certificate SKI %s has expired: cert.valid_until %s, irdb.valid_until %s", child.child_handle, child_cert.cert.gSKI(), old_resources.valid_until, irdb_resources.valid_until)
              child_cert.delete()
              publisher.queue(uri = child_cert.uri, old_obj = child_cert.cert, repository = ca_detail.ca.parent.repository)
              ca_detail.generate_manifest(publisher = publisher)

      except:
        logger.exception("%r: Couldn't update child %r, skipping", self, child)

    try:
      yield publisher.call_pubd()
    except:
      logger.exception("%r: Couldn't publish, skipping", self)


@queue_task
class UpdateROAsTask(AbstractTask):
  """
  Generate or update ROAs for this tenant.
  """

  def clear(self):
    self.publisher  = None
    self.ca_details = None

  @tornado.gen.coroutine
  def main(self):
    logger.debug("%r: Updating ROAs", self)

    try:
      r_msg = yield self.rpkid.irdb_query_roa_requests(self.tenant.tenant_handle)
    except:
      logger.exception("Could not fetch ROA requests for %s, skipping", self.tenant.tenant_handle)
      return

    logger.debug("%r: Received response to query for ROA requests: %r", self, r_msg)

    roas = {}
    seen = set()
    orphans = []
    updates = []
    self.publisher = rpki.rpkid.publication_queue(self.rpkid)
    self.ca_details = set()

    for roa in self.tenant.roas.all():
      k = (roa.asn, str(roa.ipv4), str(roa.ipv6))
      if k not in roas:
        roas[k] = roa
      elif (roa.roa is not None and roa.cert is not None and roa.ca_detail is not None and roa.ca_detail.state == "active" and (roas[k].roa is None or roas[k].cert is None or roas[k].ca_detail is None or roas[k].ca_detail.state != "active")):
        orphans.append(roas[k])
        roas[k] = roa
      else:
        orphans.append(roa)

    for r_pdu in r_msg:
      k = (r_pdu.get("asn"), r_pdu.get("ipv4"), r_pdu.get("ipv6"))
      if k in seen:
        logger.warning("%r: Skipping duplicate ROA request %r", self, r_pdu)
      else:
        seen.add(k)
        roa = roas.pop(k, None)
        if roa is None:
          roa = rpki.rpkidb.models.ROA(tenant = self.tenant, asn = long(r_pdu.get("asn")), ipv4 = r_pdu.get("ipv4"), ipv6 = r_pdu.get("ipv6"))
          logger.debug("%r: Created new %r", self, roa)
        else:
          logger.debug("%r: Found existing %r", self, roa)
        updates.append(roa)

    orphans.extend(roas.itervalues())

    while updates:
      if self.overdue:
        yield self.publish()
        yield self.postpone()
      roa = updates.pop(0)
      try:
        roa.update(publisher = self.publisher, fast = True)
        self.ca_details.add(roa.ca_detail)
      except rpki.exceptions.NoCoveringCertForROA:
        logger.warning("%r: No covering certificate for %r, skipping", self, roa)
      except:
        logger.exception("%r: Could not update %r, skipping", self, roa)

    for roa in orphans:
      try:
        self.ca_details.add(roa.ca_detail)
        roa.revoke(publisher = self.publisher, fast = True)
      except:
        logger.exception("%r: Could not revoke %r", self, roa)

    yield self.publish()

  @tornado.gen.coroutine
  def publish(self):
    if not self.publisher.empty():
      for ca_detail in self.ca_details:
        logger.debug("%r: Generating new CRL for %r", self, ca_detail)
        ca_detail.generate_crl(publisher = self.publisher)
        logger.debug("%r: Generating new manifest for %r", self, ca_detail)
        ca_detail.generate_manifest(publisher = self.publisher)
      yield self.publisher.call_pubd()
    self.ca_details.clear()


@queue_task
class UpdateGhostbustersTask(AbstractTask):
  """
  Generate or update Ghostbuster records for this tenant.

  This was originally based on the ROA update code.  It's possible
  that both could benefit from refactoring, but at this point the
  potential scaling issues for ROAs completely dominate structure of
  the ROA code, and aren't relevant here unless someone is being
  exceptionally silly.
  """

  @tornado.gen.coroutine
  def main(self):
    logger.debug("%r: Updating Ghostbuster records", self)
    parent_handles = set(p.parent_handle for p in self.tenant.parents.all())

    try:
      r_msg = yield self.rpkid.irdb_query_ghostbuster_requests(self.tenant.tenant_handle, parent_handles)

      ghostbusters = {}
      orphans = []
      publisher = rpki.rpkid.publication_queue(self.rpkid)
      ca_details = set()
      seen = set()

      for ghostbuster in self.tenant.ghostbusters.all():
        k = (ghostbuster.ca_detail.pk, ghostbuster.vcard)
        if ghostbuster.ca_detail.state != "active" or k in ghostbusters:
          orphans.append(ghostbuster)
        else:
          ghostbusters[k] = ghostbuster

      for r_pdu in r_msg:
        try:
          self.tenant.parents.get(parent_handle = r_pdu.get("parent_handle"))
        except rpki.rpkidb.models.Parent.DoesNotExist:
          logger.warning("%r: Unknown parent_handle %r in Ghostbuster request, skipping", self, r_pdu.get("parent_handle"))
          continue
        k = (r_pdu.get("parent_handle"), r_pdu.text)
        if k in seen:
          logger.warning("%r: Skipping duplicate Ghostbuster request %r", self, r_pdu)
          continue
        seen.add(k)
        for ca_detail in rpki.rpkidb.models.CADetail.objects.filter(ca__parent__parent_handle = r_pdu.get("parent_handle"), ca__parent__tenant = self.tenant, state = "active"):
          ghostbuster = ghostbusters.pop((ca_detail.pk, r_pdu.text), None)
          if ghostbuster is None:
            ghostbuster = rpki.rpkidb.models.Ghostbuster(tenant = self.tenant, ca_detail = ca_detail, vcard = r_pdu.text)
            logger.debug("%r: Created new %r for %r", self, ghostbuster, r_pdu.get("parent_handle"))
          else:
            logger.debug("%r: Found existing %r for %s", self, ghostbuster, r_pdu.get("parent_handle"))
          ghostbuster.update(publisher = publisher, fast = True)
          ca_details.add(ca_detail)

      orphans.extend(ghostbusters.itervalues())
      for ghostbuster in orphans:
        ca_details.add(ghostbuster.ca_detail)
        ghostbuster.revoke(publisher = publisher, fast = True)

      for ca_detail in ca_details:
        ca_detail.generate_crl(publisher = publisher)
        ca_detail.generate_manifest(publisher = publisher)

      yield publisher.call_pubd()

    except:
      logger.exception("Could not update Ghostbuster records for %s, skipping", self.tenant.tenant_handle)


@queue_task
class UpdateEECertificatesTask(AbstractTask):
  """
  Generate or update EE certificates for this self.

  Not yet sure what kind of scaling constraints this task might have,
  so keeping it simple for initial version, we can optimize later.
  """

  @tornado.gen.coroutine
  def main(self):
    logger.debug("%r: Updating EE certificates", self)

    try:
      r_msg = yield self.rpkid.irdb_query_ee_certificate_requests(self.tenant.tenant_handle)

      publisher = rpki.rpkid.publication_queue(self.rpkid)

      existing = dict()
      for ee in self.tenant.ee_certificates.all():
        gski = ee.gski
        if gski not in existing:
          existing[gski] = set()
        existing[gski].add(ee)

      ca_details = set()

      for r_pdu in r_msg:
        gski = r_pdu.get("gski")
        ees = existing.pop(gski, ())

        resources = rpki.resource_set.resource_bag(
          asn         = rpki.resource_set.resource_set_as(r_pdu.get("asn")),
          v4          = rpki.resource_set.resource_set_ipv4(r_pdu.get("ipv4")),
          v6          = rpki.resource_set.resource_set_ipv6(r_pdu.get("ipv6")),
          valid_until = rpki.sundial.datetime.fromXMLtime(r_pdu.get("valid_until")))
        covering = self.tenant.find_covering_ca_details(resources)
        ca_details.update(covering)

        for ee in ees:
          if ee.ca_detail in covering:
            logger.debug("Updating existing EE certificate for %s %s", gski, resources)
            ee.reissue(resources = resources, publisher = publisher)
            covering.remove(ee.ca_detail)
          else:
            logger.debug("Existing EE certificate for %s %s is no longer covered", gski, resources)
            ee.revoke(publisher = publisher)

        subject_name = rpki.x509.X501DN.from_cn(r_pdu.get("cn"), r_pdu.get("sn"))
        subject_key  = rpki.x509.PKCS10(Base64 = r_pdu[0].text).getPublicKey()

        for ca_detail in covering:
          logger.debug("No existing EE certificate for %s %s", gski, resources)
          rpki.rpkidb.models.EECertificate.create(      # sic: class method, not Django manager method (for now, anyway)
            ca_detail    = ca_detail,
            subject_name = subject_name,
            subject_key  = subject_key,
            resources    = resources,
            publisher    = publisher,
            eku          = r_pdu.get("eku", "").split(",") or None)

      # Anything left is an orphan
      for ees in existing.values():
        for ee in ees:
          ca_details.add(ee.ca_detail)
          ee.revoke(publisher = publisher)

      for ca_detail in ca_details:
        ca_detail.generate_crl(publisher = publisher)
        ca_detail.generate_manifest(publisher = publisher)

      yield publisher.call_pubd()

    except:
      logger.exception("Could not update EE certificates for %s, skipping", self.tenant.tenant_handle)


@queue_task
class RegenerateCRLsAndManifestsTask(AbstractTask):
  """
  Generate new CRLs and manifests as necessary for all of this tenant's
  CAs.  Extracting nextUpdate from a manifest is hard at the moment
  due to implementation silliness, so for now we generate a new
  manifest whenever we generate a new CRL

  This code also cleans up tombstones left behind by revoked ca_detail
  objects, since we're walking through the relevant portions of the
  database anyway.
  """

  @tornado.gen.coroutine
  def main(self):
    logger.debug("%r: Regenerating CRLs and manifests", self)

    try:
      now = rpki.sundial.now()
      crl_interval = rpki.sundial.timedelta(seconds = self.tenant.crl_interval)
      regen_margin = max(rpki.sundial.timedelta(seconds = self.rpkid.cron_period) * 2, crl_interval / 4)
      publisher = rpki.rpkid.publication_queue(self.rpkid)

      for ca in rpki.rpkidb.models.CA.objects.filter(parent__tenant = self.tenant):
        try:
          for ca_detail in ca.ca_details.filter(state = "revoked"):
            if now > ca_detail.latest_crl.getNextUpdate():
              ca_detail.destroy(ca = ca, publisher = publisher)
          for ca_detail in ca.ca_details.filter(state__in = ("active", "deprecated")):
            if now + regen_margin > ca_detail.latest_crl.getNextUpdate():
              ca_detail.generate_crl(publisher = publisher)
              ca_detail.generate_manifest(publisher = publisher)
        except:
          logger.exception("%r: Couldn't regenerate CRLs and manifests for CA %r, skipping", self, ca)

      yield publisher.call_pubd()

    except:
      logger.exception("%r: Couldn't publish updated CRLs and manifests, skipping", self)


@queue_task
class CheckFailedPublication(AbstractTask):
  """
  Periodic check for objects we tried to publish but failed (eg, due
  to pubd being down or unreachable).
  """

  @tornado.gen.coroutine
  def main(self):
    logger.debug("%r: Checking for failed publication actions", self)

    try:
      publisher = rpki.rpkid.publication_queue(self.rpkid)
      for ca_detail in rpki.rpkidb.models.CADetail.objects.filter(ca__parent__tenant = self.tenant, state = "active"):
        ca_detail.check_failed_publication(publisher)
      yield publisher.call_pubd()

    except:
      logger.exception("%r: Couldn't run failed publications, skipping", self)
