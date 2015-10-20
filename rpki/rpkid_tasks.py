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
import rpki.log
import rpki.rpkid
import rpki.async
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


class CompletionHandler(object):
  """
  Track one or more scheduled rpkid tasks and execute a callback when
  the last of them terminates.
  """

  ## @var debug
  # Debug logging.

  debug = False

  def __init__(self, cb):
    self.cb = cb
    self.tasks = set()

  def register(self, task):
    if self.debug:
      logger.debug("Completion handler %r registering task %r", self, task)
    self.tasks.add(task)
    task.register_completion(self.done)

  def done(self, task):
    try:
      self.tasks.remove(task)
    except KeyError:
      logger.warning("Completion handler %r called with unregistered task %r, blundering onwards", self, task)
    else:
      if self.debug:
        logger.debug("Completion handler %r called with registered task %r", self, task)
    if not self.tasks:
      if self.debug:
        logger.debug("Completion handler %r finished, calling %r", self, self.cb)
      self.cb()

  @property
  def count(self):
    return len(self.tasks)


class AbstractTask(object):
  """
  Abstract base class for rpkid scheduler task objects.  This just
  handles the scheduler hooks, real work starts in self.start.
  """

  ## @var timeslice
  # How long before a task really should consider yielding the CPU to
  # let something else run.

  timeslice = rpki.sundial.timedelta(seconds = 15)

  def __init__(self, rpkid, s, description = None):
    self.rpkid = rpkid
    self.tenant = s
    self.description = description
    self.completions = []
    self.continuation = None
    self.due_date = None
    self.clear()

  def __repr__(self):
    return rpki.log.log_repr(self, self.description)

  def register_completion(self, completion):
    self.completions.append(completion)

  def exit(self):
    while self.completions:
      self.completions.pop(0)(self)
    self.clear()
    self.due_date = None
    self.rpkid.task_next()

  def postpone(self, continuation):
    self.continuation = continuation
    self.due_date = None
    self.rpkid.task_add(self)
    self.rpkid.task_next()

  def __call__(self):
    self.due_date = rpki.sundial.now() + self.timeslice
    if self.continuation is None:
      logger.debug("Running task %r", self)
      self.clear()
      self.start()
    else:
      logger.debug("Restarting task %r at %r", self, self.continuation)
      continuation = self.continuation
      self.continuation = None
      continuation()

  @property
  def overdue(self):
    return rpki.sundial.now() > self.due_date

  def __getattr__(self, name):
    return getattr(self.tenant, name)

  def start(self):
    raise NotImplementedError

  def clear(self):
    pass


@queue_task
class PollParentTask(AbstractTask):
  """
  Run the regular client poll cycle with each of this self's
  parents, in turn.
  """

  def clear(self):
    logger.debug("PollParentTask.clear()")
    self.parent_iterator = None
    self.parent = None
    self.ca_map = None
    self.class_iterator = None
    self.started = False

  def start(self):
    logger.debug("PollParentTask.start()")
    self.rpkid.checkpoint()
    logger.debug("Self %s[%r] polling parents", self.tenant_handle, self)
    assert not self.started
    self.started = True
    rpki.async.iterator(self.parents.all(), self.parent_loop, self.exit)

  def parent_loop(self, parent_iterator, parent):
    logger.debug("PollParentTask.parent_loop()")
    self.parent_iterator = parent_iterator
    self.parent = parent
    parent.up_down_list_query(rpkid = self.rpkid, cb = self.got_list, eb = self.list_failed)

  def got_list(self, r_msg):
    logger.debug("PollParentTask.got_list()")
    self.ca_map = dict((ca.parent_resource_class, ca) for ca in self.parent.cas.all())
    self.rpkid.checkpoint()
    rpki.async.iterator(r_msg.getiterator(rpki.up_down.tag_class), self.class_loop, self.class_done)

  def list_failed(self, e):
    logger.debug("PollParentTask.list_failed()")
    logger.exception("Couldn't get resource class list from parent %r, skipping", self.parent)
    self.parent_iterator()

  def class_loop(self, class_iterator, rc):
    logger.debug("PollParentTask.class_loop()")
    self.rpkid.checkpoint()
    self.class_iterator = class_iterator
    try:
      ca = self.ca_map.pop(rc.get("class_name"))
    except KeyError:
      rpki.rpkidb.models.CA.create(rpkid = self.rpkid, parent = self.parent, rc = rc,
                                   cb = class_iterator, eb = self.class_create_failed)
    else:
      ca.check_for_updates(rpkid = self.rpkid, parent = self.parent, rc = rc, cb = class_iterator, eb = self.class_update_failed)

  def class_update_failed(self, e):
    logger.debug("PollParentTask.class_update_failed()")
    logger.exception("Couldn't update class, skipping")
    self.class_iterator()

  def class_create_failed(self, e):
    logger.debug("PollParentTask.class_create_failed()")
    logger.exception("Couldn't create class, skipping")
    self.class_iterator()

  def class_done(self):
    logger.debug("PollParentTask.class_done()")
    rpki.async.iterator(self.ca_map.values(), self.ca_loop, self.ca_done)

  def ca_loop(self, iterator, ca):
    logger.debug("PollParentTask.ca_loop()")
    self.rpkid.checkpoint()
    ca.destroy(self.parent, iterator)

  def ca_done(self):
    logger.debug("PollParentTask.ca_done()")
    self.rpkid.checkpoint()
    self.parent_iterator()


@queue_task
class UpdateChildrenTask(AbstractTask):
  """
  Check for updated IRDB data for all of this self's children and
  issue new certs as necessary.  Must handle changes both in
  resources and in expiration date.
  """

  def clear(self):
    self.now = None
    self.rsn = None
    self.publisher = None
    self.iterator = None
    self.child = None
    self.child_certs = None
    self.started = False

  def start(self):
    self.rpkid.checkpoint()
    logger.debug("Self %s[%r] updating children", self.tenant_handle, self)
    assert not self.started
    self.started = True
    self.now = rpki.sundial.now()
    self.rsn = self.now + rpki.sundial.timedelta(seconds = self.regen_margin)
    self.publisher = rpki.rpkid.publication_queue(self.rpkid)
    rpki.async.iterator(self.children.all(), self.loop, self.done)

  def loop(self, iterator, child):
    self.rpkid.checkpoint()
    self.iterator = iterator
    self.child = child
    self.child_certs = child.child_certs
    if self.overdue:
      self.publisher.call_pubd(lambda: self.postpone(self.do_child), self.publication_failed)
    else:
      self.do_child()

  def do_child(self):
    if self.child_certs:
      self.rpkid.irdb_query_child_resources(self.child.tenant.tenant_handle, self.child.child_handle,
                                           self.got_resources, self.lose)
    else:
      self.iterator()

  def lose(self, e):
    logger.exception("Couldn't update child %r, skipping", self.child)
    self.iterator()

  def got_resources(self, irdb_resources):
    try:
      for child_cert in self.child_certs.filter(ca_detail__state = "active"):
        ca_detail = child_cert.ca_detail
        old_resources = child_cert.cert.get_3779resources()
        new_resources = old_resources & irdb_resources & ca_detail.latest_ca_cert.get_3779resources()
        old_aia = child_cert.cert.get_AIA()[0]
        new_aia = ca_detail.ca_cert_uri

        if new_resources.empty():
          logger.debug("Resources shrank to the null set, revoking and withdrawing child %s certificate SKI %s",
                       self.child.child_handle, child_cert.cert.gSKI())
          child_cert.revoke(publisher = self.publisher)
          ca_detail.generate_crl(publisher = self.publisher)
          ca_detail.generate_manifest(publisher = self.publisher)

        elif (old_resources != new_resources or
              old_aia != new_aia or
              (old_resources.valid_until < self.rsn and
               irdb_resources.valid_until > self.now and
               old_resources.valid_until != irdb_resources.valid_until)):

          logger.debug("Need to reissue child %s certificate SKI %s",
                       self.child.child_handle, child_cert.cert.gSKI())
          if old_resources != new_resources:
            logger.debug("Child %s SKI %s resources changed: old %s new %s",
                         self.child.child_handle, child_cert.cert.gSKI(),
                         old_resources, new_resources)
          if old_resources.valid_until != irdb_resources.valid_until:
            logger.debug("Child %s SKI %s validity changed: old %s new %s",
                         self.child.child_handle, child_cert.cert.gSKI(),
                         old_resources.valid_until, irdb_resources.valid_until)

          new_resources.valid_until = irdb_resources.valid_until
          child_cert.reissue(
            ca_detail = ca_detail,
            resources = new_resources,
            publisher = self.publisher)

        elif old_resources.valid_until < self.now:
          logger.debug("Child %s certificate SKI %s has expired: cert.valid_until %s, irdb.valid_until %s",
                       self.child.child_handle, child_cert.cert.gSKI(),
                       old_resources.valid_until, irdb_resources.valid_until)
          child_cert.delete()
          self.publisher.queue(
            uri = child_cert.uri,
            old_obj = child_cert.cert,
            repository = ca_detail.ca.parent.repository)
          ca_detail.generate_manifest(publisher = self.publisher)

    except (SystemExit, rpki.async.ExitNow):
      raise
    except Exception, e:
      self.rpkid.checkpoint()
      self.lose(e)
    else:
      self.rpkid.checkpoint()
      self.iterator()

  def done(self):
    self.rpkid.checkpoint()
    self.publisher.call_pubd(self.exit, self.publication_failed)

  def publication_failed(self, e):
    logger.exception("Couldn't publish for %s, skipping", self.tenant_handle)
    self.rpkid.checkpoint()
    self.exit()


@queue_task
class UpdateROAsTask(AbstractTask):
  """
  Generate or update ROAs for this self.
  """

  def clear(self):
    self.orphans = None
    self.updates = None
    self.publisher = None
    self.ca_details = None
    self.count = None
    self.started = False

  def start(self):
    self.rpkid.checkpoint()
    logger.debug("Self %s[%r] updating ROAs", self.tenant_handle, self)
    assert not self.started
    self.started = True
    logger.debug("Issuing query for ROA requests")
    self.rpkid.irdb_query_roa_requests(self.tenant_handle, self.got_roa_requests, self.roa_requests_failed)

  def got_roa_requests(self, r_msg):
    self.rpkid.checkpoint()
    logger.debug("Received response to query for ROA requests")

    roas = {}
    seen = set()
    self.orphans = []
    self.updates = []
    self.publisher = rpki.rpkid.publication_queue(self.rpkid)
    self.ca_details = set()

    logger.debug("UpdateROAsTask.got_roa_requests(): setup done, self.orphans %r", self.orphans)
    assert isinstance(self.orphans, list) # XXX

    for roa in self.tenant.roas.all():
      logger.debug("UpdateROAsTask.got_roa_requests(): roa loop, self.orphans %r", self.orphans)
      assert isinstance(self.orphans, list) # XXX
      k = (roa.asn, str(roa.ipv4), str(roa.ipv6))
      if k not in roas:
        roas[k] = roa
      elif (roa.roa is not None and
            roa.cert is not None and
            roa.ca_detail is not None and
            roa.ca_detail.state == "active" and
            (roas[k].roa is None or
             roas[k].cert is None or
             roas[k].ca_detail is None or
             roas[k].ca_detail.state != "active")):
        self.orphans.append(roas[k])
        roas[k] = roa
      else:
        self.orphans.append(roa)

    logger.debug("UpdateROAsTask.got_roa_requests(): roa loop done, self.orphans %r", self.orphans)
    assert isinstance(self.orphans, list) # XXX

    for r_pdu in r_msg:
      logger.debug("UpdateROAsTask.got_roa_requests(): r_pdu loop, self.orphans %r", self.orphans)
      assert isinstance(self.orphans, list)
      k = (r_pdu.get("asn"), r_pdu.get("ipv4"), r_pdu.get("ipv6"))
      if k in seen:
        logger.warning("Skipping duplicate ROA request %r", r_pdu)
      else:
        seen.add(k)
        roa = roas.pop(k, None)
        if roa is None:
          roa = rpki.rpkidb.models.ROA(asn = long(r_pdu.get("asn")), ipv4 = r_pdu.get("ipv4"), ipv6 = r_pdu.get("ipv6"))
          roa.tenant = self.tenant
          logger.debug("Created new %r", roa)
        else:
          logger.debug("Found existing %r", roa)
        self.updates.append(roa)

    logger.debug("UpdateROAsTask.got_roa_requests(): r_pdu loop done, self.orphans %r", self.orphans)
    assert isinstance(self.orphans, list) # XXX

    self.orphans.extend(roas.itervalues())

    if self.overdue:
      self.postpone(self.begin_loop)
    else:
      self.begin_loop()

  def begin_loop(self):
    self.count = 0
    rpki.async.iterator(self.updates, self.loop, self.done, pop_list = True)

  def loop(self, iterator, roa):
    self.rpkid.checkpoint()
    try:
      roa.update(publisher = self.publisher, fast = True)
      self.ca_details.add(roa.ca_detail)
    except (SystemExit, rpki.async.ExitNow):
      raise
    except rpki.exceptions.NoCoveringCertForROA:
      logger.warning("No covering certificate for %r, skipping", roa)
    except Exception:
      logger.exception("Could not update %r, skipping", roa)
    self.count += 1
    if self.overdue:
      self.publish(lambda: self.postpone(iterator))
    else:
      iterator()

  def publish(self, done):
    if not self.publisher.empty():
      for ca_detail in self.ca_details:
        logger.debug("Generating new CRL for %r", ca_detail)
        ca_detail.generate_crl(publisher = self.publisher)
        logger.debug("Generating new manifest for %r", ca_detail)
        ca_detail.generate_manifest(publisher = self.publisher)
    self.ca_details.clear()
    self.rpkid.checkpoint()
    self.publisher.call_pubd(done, self.publication_failed)

  def publication_failed(self, e):
    logger.exception("Couldn't publish for %s, skipping", self.tenant_handle)
    self.rpkid.checkpoint()
    self.exit()

  def done(self):
    for roa in self.orphans:
      try:
        self.ca_details.add(roa.ca_detail)
        roa.revoke(publisher = self.publisher, fast = True)
      except (SystemExit, rpki.async.ExitNow):
        raise
      except Exception:
        logger.exception("Could not revoke %r", roa)
    self.rpkid.checkpoint()
    self.publish(self.exit)

  def roa_requests_failed(self, e):
    logger.exception("Could not fetch ROA requests for %s, skipping", self.tenant_handle)
    self.exit()


@queue_task
class UpdateGhostbustersTask(AbstractTask):
  """
  Generate or update Ghostbuster records for this self.

  This was originally based on the ROA update code.  It's possible
  that both could benefit from refactoring, but at this point the
  potential scaling issues for ROAs completely dominate structure of
  the ROA code, and aren't relevant here unless someone is being
  exceptionally silly.
  """

  def clear(self):
    self.started = False

  def start(self):
    self.rpkid.checkpoint()
    logger.debug("Self %s[%r] updating Ghostbuster records", self.tenant_handle, self)
    assert not self.started
    self.started = True
    parent_handles = set(p.parent_handle for p in self.tenant.parents.all())
    self.rpkid.irdb_query_ghostbuster_requests(self.tenant_handle, parent_handles,
                                               self.got_ghostbuster_requests,
                                               self.ghostbuster_requests_failed)

  def got_ghostbuster_requests(self, r_msg):

    try:
      self.rpkid.checkpoint()

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
          logger.warning("Unknown parent_handle %r in Ghostbuster request, skipping", r_pdu.get("parent_handle"))
          continue
        k = (r_pdu.get("parent_handle"), r_pdu.text)
        if k in seen:
          logger.warning("Skipping duplicate Ghostbuster request %r", r_pdu)
          continue
        seen.add(k)
        for ca_detail in rpki.rpkidb.models.CADetail.objects.filter(ca__parent__parent_handle = r_pdu.get("parent_handle"),
                                                                    ca__parent__tenant = self.tenant, state = "active"):
          ghostbuster = ghostbusters.pop((ca_detail.pk, r_pdu.text), None)
          if ghostbuster is None:
            ghostbuster = rpki.rpkidb.models.Ghostbuster(ca_detail = ca_detail, vcard = r_pdu.text)
            ghostbuster.tenant = self.tenant
            logger.debug("Created new %r for %r", ghostbuster, r_pdu.get("parent_handle"))
          else:
            logger.debug("Found existing %r for %s", ghostbuster, r_pdu.get("parent_handle"))
          ghostbuster.update(publisher = publisher, fast = True)
          ca_details.add(ca_detail)

      orphans.extend(ghostbusters.itervalues())
      for ghostbuster in orphans:
        ca_details.add(ghostbuster.ca_detail)
        ghostbuster.revoke(publisher = publisher, fast = True)

      for ca_detail in ca_details:
        ca_detail.generate_crl(publisher = publisher)
        ca_detail.generate_manifest(publisher = publisher)

      self.rpkid.checkpoint()
      publisher.call_pubd(self.exit, self.publication_failed)

    except (SystemExit, rpki.async.ExitNow):
      raise
    except Exception:
      logger.exception("Could not update Ghostbuster records for %s, skipping", self.tenant_handle)
      self.exit()

  def publication_failed(self, e):
    logger.exception("Couldn't publish Ghostbuster updates for %s, skipping", self.tenant_handle)
    self.rpkid.checkpoint()
    self.exit()

  def ghostbuster_requests_failed(self, e):
    logger.exception("Could not fetch Ghostbuster record requests for %s, skipping", self.tenant_handle)
    self.exit()


@queue_task
class UpdateEECertificatesTask(AbstractTask):
  """
  Generate or update EE certificates for this self.

  Not yet sure what kind of scaling constraints this task might have,
  so keeping it simple for initial version, we can optimize later.
  """

  def clear(self):
    self.started = False

  def start(self):
    self.rpkid.checkpoint()
    logger.debug("Self %s[%r] updating EE certificates", self.tenant_handle, self)
    assert not self.started
    self.started = True
    self.rpkid.irdb_query_ee_certificate_requests(self.tenant_handle,
                                                 self.got_requests,
                                                 self.get_requests_failed)

  def got_requests(self, r_msg):

    try:
      self.rpkid.checkpoint()

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
        covering = self.find_covering_ca_details(resources)
        ca_details.update(covering)

        for ee in ees:
          if ee.ca_detail in covering:
            logger.debug("Updating existing EE certificate for %s %s",
                         gski, resources)
            ee.reissue(
              resources = resources,
              publisher = publisher)
            covering.remove(ee.ca_detail)
          else:
            logger.debug("Existing EE certificate for %s %s is no longer covered",
                         gski, resources)
            ee.revoke(publisher = publisher)

        subject_name = rpki.x509.X501DN.from_cn(r_pdu.get("cn"), r_pdu.get("sn"))
        subject_key  = rpki.x509.PKCS10(Base64 = r_pdu[0].text).getPublicKey()

        for ca_detail in covering:
          logger.debug("No existing EE certificate for %s %s",
                       gski, resources)
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

      self.rpkid.checkpoint()
      publisher.call_pubd(self.exit, self.publication_failed)

    except (SystemExit, rpki.async.ExitNow):
      raise
    except Exception:
      logger.exception("Could not update EE certificates for %s, skipping", self.tenant_handle)
      self.exit()

  def publication_failed(self, e):
    logger.exception("Couldn't publish EE certificate updates for %s, skipping", self.tenant_handle)
    self.rpkid.checkpoint()
    self.exit()

  def get_requests_failed(self, e):
    logger.exception("Could not fetch EE certificate requests for %s, skipping", self.tenant_handle)
    self.exit()


@queue_task
class RegenerateCRLsAndManifestsTask(AbstractTask):
  """
  Generate new CRLs and manifests as necessary for all of this self's
  CAs.  Extracting nextUpdate from a manifest is hard at the moment
  due to implementation silliness, so for now we generate a new
  manifest whenever we generate a new CRL

  This code also cleans up tombstones left behind by revoked ca_detail
  objects, since we're walking through the relevant portions of the
  database anyway.
  """

  def clear(self):
    self.started = False

  def start(self):
    self.rpkid.checkpoint()
    logger.debug("Self %s[%r] regenerating CRLs and manifests", self.tenant_handle, self)
    assert not self.started
    self.started = True
    now = rpki.sundial.now()
    crl_interval = rpki.sundial.timedelta(seconds = self.crl_interval)
    regen_margin = max(self.rpkid.cron_period * 2, crl_interval / 4)
    publisher = rpki.rpkid.publication_queue(self.rpkid)

    logger.debug("RegenerateCRLsAndManifestsTask: setup complete") # XXX

    for ca in rpki.rpkidb.models.CA.objects.filter(parent__tenant = self.tenant):
      logger.debug("RegenerateCRLsAndManifestsTask: checking CA %r", ca) # XXX
      try:
        for ca_detail in ca.ca_details.filter(state = "revoked"):
          if now > ca_detail.latest_crl.getNextUpdate():
            ca_detail.destroy(ca = ca, publisher = publisher)
        for ca_detail in ca.ca_details.filter(state__in = ("active", "deprecated")):
          if now + regen_margin > ca_detail.latest_crl.getNextUpdate():
            ca_detail.generate_crl(publisher = publisher)
            ca_detail.generate_manifest(publisher = publisher)
      except (SystemExit, rpki.async.ExitNow):
        raise
      except Exception:
        logger.exception("Couldn't regenerate CRLs and manifests for CA %r, skipping", ca)

    logger.debug("RegenerateCRLsAndManifestsTask: CA loop complete") # XXX

    self.rpkid.checkpoint()
    publisher.call_pubd(self.done, self.lose)

  def done(self):
    logger.debug("RegenerateCRLsAndManifestsTask: publication complete") # XXX
    self.exit()

  def lose(self, e):
    logger.exception("Couldn't publish updated CRLs and manifests for self %r, skipping", self.tenant_handle)
    self.rpkid.checkpoint()
    self.exit()


@queue_task
class CheckFailedPublication(AbstractTask):
  """
  Periodic check for objects we tried to publish but failed (eg, due
  to pubd being down or unreachable).
  """

  def clear(self):
    self.started = False

  def start(self):
    assert not self.started
    logger.debug("CheckFailedPublication starting")
    self.started = True
    publisher = rpki.rpkid.publication_queue(self.rpkid)
    for ca_detail in rpki.rpkidb.models.CADetail.objects.filter(ca__parent__tenant = self.tenant, state = "active"):
      ca_detail.check_failed_publication(publisher)
      self.rpkid.checkpoint()
    publisher.call_pubd(self.done, self.publication_failed)

  def publication_failed(self, e):
    logger.exception("Couldn't publish for %s, skipping", self.tenant_handle)
    self.rpkid.checkpoint()
    self.exit()

  def done(self):
    logger.debug("CheckFailedPublication finished")
    self.exit()
