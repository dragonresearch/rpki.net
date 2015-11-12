"""
Django ORM models for rpkid.
"""

from __future__ import unicode_literals

import logging

import tornado.gen
import tornado.web
import tornado.ioloop
import tornado.httputil
import tornado.httpclient
import tornado.httpserver

from django.db import models

import rpki.left_right

from rpki.fields import (EnumField, SundialField,
                         CertificateField, RSAPrivateKeyField,
                         PublicKeyField, CRLField, PKCS10Field,
                         ManifestField, ROAField, GhostbusterField)

from lxml.etree import Element, SubElement, tostring as ElementToString

logger = logging.getLogger(__name__)

# pylint: disable=W5101


# XXX Temporary hack to help trace call chains so we can clear some of
# the historical clutter out of this module.

def trace_call_chain():
    if False:
        from traceback import extract_stack
        caller, callee = extract_stack(None, 3)[:2]
        caller_file, caller_line, caller_name = caller[:3]
        callee_file, callee_line, callee_name = callee[:3]
        logger.debug("<Call trace> %s() at %s:%s called by %s() at %s:%s",
                     callee_name, callee_file, callee_line,
                     caller_name, caller_file, caller_line)


# The objects available via the left-right protocol allow NULL values
# in places we wouldn't otherwise (eg, bpki_cert fields), to support
# existing protocol which allows back-end to build up objects
# gradually.  We may want to rethink this eventually, but that yak can
# wait for its shave, particularly since disallowing null should be a
# very simple change given migrations.

class XMLTemplate(object):
    """
    Encapsulate all the voodoo for transcoding between lxml and ORM.
    """

    # Whether to drop XMl into the log

    debug = False

    # Type map to simplify declaration of Base64 sub-elements.

    element_type = dict(bpki_cert        = rpki.x509.X509,
                        bpki_glue        = rpki.x509.X509,
                        pkcs10_request   = rpki.x509.PKCS10,
                        signing_cert     = rpki.x509.X509,
                        signing_cert_crl = rpki.x509.CRL)


    def __init__(self, name, attributes = (), booleans = (), elements = (), readonly = (), handles = ()):
        self.name       = name
        self.handles    = handles
        self.attributes = attributes
        self.booleans   = booleans
        self.elements   = elements
        self.readonly   = readonly


    def encode(self, obj, q_pdu, r_msg):
        """
        Encode an ORM object as XML.
        """

        r_pdu = SubElement(r_msg, rpki.left_right.xmlns + self.name, nsmap = rpki.left_right.nsmap, action = q_pdu.get("action"))
        if self.name != "tenant":
            r_pdu.set("tenant_handle", obj.tenant.tenant_handle)
        r_pdu.set(self.name + "_handle", getattr(obj, self.name + "_handle"))
        if q_pdu.get("tag"):
            r_pdu.set("tag", q_pdu.get("tag"))
        for h in self.handles:
            k = h.xml_template.name
            v = getattr(obj, k)
            if v is not None:
                r_pdu.set(k + "_handle", getattr(v, k + "_handle"))
        for k in self.attributes:
            v = getattr(obj, k)
            if v is not None:
                r_pdu.set(k, str(v))
        for k in self.booleans:
            if getattr(obj, k):
                r_pdu.set(k, "yes")
        for k in self.elements + self.readonly:
            v = getattr(obj, k)
            if v is not None and not v.empty():
                SubElement(r_pdu, rpki.left_right.xmlns + k).text = v.get_Base64()
        if self.debug:
            logger.debug("XMLTemplate.encode(): %s", ElementToString(r_pdu))


    def acknowledge(self, obj, q_pdu, r_msg):
        """
        Add an acknowledgement PDU in response to a create, set, or
        destroy action.

        This includes a bit of special-case code for BSC objects which has
        to go somewhere; we could handle it via some kind method of
        call-out to the BSC model, but it's not worth building a general
        mechanism for one case, so we do it inline and have done.
        """

        assert q_pdu.tag == rpki.left_right.xmlns + self.name
        action = q_pdu.get("action")
        r_pdu = SubElement(r_msg, rpki.left_right.xmlns + self.name, nsmap = rpki.left_right.nsmap, action = action)
        if self.name != "tenant":
            r_pdu.set("tenant_handle", obj.tenant.tenant_handle)
        r_pdu.set(self.name + "_handle", getattr(obj, self.name + "_handle"))
        if q_pdu.get("tag"):
            r_pdu.set("tag", q_pdu.get("tag"))
        if self.name == "bsc" and action != "destroy" and obj.pkcs10_request is not None:
            assert not obj.pkcs10_request.empty()
            SubElement(r_pdu, rpki.left_right.xmlns + "pkcs10_request").text = obj.pkcs10_request.get_Base64()
        if self.debug:
            logger.debug("XMLTemplate.acknowledge(): %s", ElementToString(r_pdu))


    def decode(self, obj, q_pdu):
        """
        Decode XML into an ORM object.
        """

        if self.debug:
            logger.debug("XMLTemplate.decode(): %r %s", obj, ElementToString(q_pdu))
        assert q_pdu.tag == rpki.left_right.xmlns + self.name
        for h in self.handles:
            k = h.xml_template.name
            v = q_pdu.get(k + "_handle")
            if v is not None:
                setattr(obj, k, h.objects.get(**{k + "_handle" : v, "tenant" : obj.tenant}))
        for k in self.attributes:
            v = q_pdu.get(k)
            if v is not None:
                v.encode("ascii")
                if v.isdigit():
                    v = long(v)
                setattr(obj, k, v)
        for k in self.booleans:
            v = q_pdu.get(k)
            if v is not None:
                setattr(obj, k, v == "yes")
        for k in self.elements:
            v = q_pdu.findtext(rpki.left_right.xmlns + k)
            if v and v.strip():
                setattr(obj, k, self.element_type[k](Base64 = v))


class XMLManager(models.Manager):
    """
    Add a few methods which locate or create an object or objects
    corresponding to the handles in an XML element, as appropriate.

    This assumes that models which use it have an "xml_template"
    class attribute holding an XMLTemplate object (above).
    """

    # Whether to blather about what we're doing

    debug = False

    # pylint: disable=E1101

    def xml_get_or_create(self, xml):
        name   = self.model.xml_template.name
        action = xml.get("action")
        assert xml.tag == rpki.left_right.xmlns + name and action in ("create", "set")
        d = { name + "_handle" : xml.get(name + "_handle") }
        if name != "tenant" and action != "create":
            d["tenant__tenant_handle"] = xml.get("tenant_handle")
        if self.debug:
            logger.debug("XMLManager.xml_get_or_create(): name %s action %s filter %r", name, action, d)
        result = self.model(**d) if action == "create" else self.get(**d)
        if name != "tenant" and action == "create":
            result.tenant = Tenant.objects.get(tenant_handle = xml.get("tenant_handle"))
        if self.debug:
            logger.debug("XMLManager.xml_get_or_create(): name %s action %s filter %r result %r", name, action, d, result)
        return result

    def xml_list(self, xml):
        name   = self.model.xml_template.name
        action = xml.get("action")
        assert xml.tag == rpki.left_right.xmlns + name and action in ("get", "list")
        d = {}
        if action == "get":
            d[name + "_handle"] = xml.get(name + "_handle")
        if name != "tenant":
            d["tenant__tenant_handle"] = xml.get("tenant_handle")
        if self.debug:
            logger.debug("XMLManager.xml_list(): name %s action %s filter %r", name, action, d)
        result = self.filter(**d) if d else self.all()
        if self.debug:
            logger.debug("XMLManager.xml_list(): name %s action %s filter %r result %r", name, action, d, result)
        return result

    def xml_get_for_delete(self, xml):
        name   = self.model.xml_template.name
        action = xml.get("action")
        assert xml.tag == rpki.left_right.xmlns + name and action == "destroy"
        d = { name + "_handle" : xml.get(name + "_handle") }
        if name != "tenant":
            d["tenant__tenant_handle"] = xml.get("tenant_handle")
        if self.debug:
            logger.debug("XMLManager.xml_get_for_delete(): name %s action %s filter %r", name, action, d)
        result = self.get(**d)
        if self.debug:
            logger.debug("XMLManager.xml_get_for_delete(): name %s action %s filter %r result %r", name, action, d, result)
        return result


def xml_hooks(cls):
    """
    Class decorator to add default XML hooks.
    """

    # Maybe inheritance from an abstract model would work here.  Then
    # again, maybe we could use this decorator to do something prettier
    # for the XMLTemplate setup.  Whatever.  Gussie up later.

    def default_xml_pre_save_hook(self, q_pdu):
        #logger.debug("default_xml_pre_save_hook()")
        pass

    @tornado.gen.coroutine
    def default_xml_post_save_hook(self, rpkid, q_pdu):
        #logger.debug("default_xml_post_save_hook()")
        pass

    @tornado.gen.coroutine
    def default_xml_pre_delete_hook(self, rpkid):
        #logger.debug("default_xml_pre_delete_hook()")
        pass

    for name, method in (("xml_pre_save_hook",   default_xml_pre_save_hook),
                         ("xml_post_save_hook",  default_xml_post_save_hook),
                         ("xml_pre_delete_hook", default_xml_pre_delete_hook)):
        if not hasattr(cls, name):
            setattr(cls, name, method)

    return cls


# Models.
#
# There's far too much random code hanging off of model methods, relic
# of the earlier implementation.  Clean up as time permits.

@xml_hooks
class Tenant(models.Model):
    tenant_handle = models.SlugField(max_length = 255)
    use_hsm = models.BooleanField(default = False)
    crl_interval = models.BigIntegerField(null = True)
    regen_margin = models.BigIntegerField(null = True)
    bpki_cert = CertificateField(null = True)
    bpki_glue = CertificateField(null = True)
    objects = XMLManager()

    xml_template = XMLTemplate(
        name       = "tenant",
        attributes = ("crl_interval", "regen_margin"),
        booleans   = ("use_hsm",),
        elements   = ("bpki_cert", "bpki_glue"))

    def __repr__(self):
        try:
            return "<Tenant: {}>".format(self.tenant_handle)
        except:
            return "<Tenant: Tenant object>"

    @tornado.gen.coroutine
    def xml_pre_delete_hook(self, rpkid):
        trace_call_chain()
        yield [parent.destroy(rpkid = rpkid) for parent in self.parents.all()]

    @tornado.gen.coroutine
    def xml_post_save_hook(self, rpkid, q_pdu):
        trace_call_chain()

        rekey             = q_pdu.get("rekey")
        revoke            = q_pdu.get("revoke")
        reissue           = q_pdu.get("reissue")
        revoke_forgotten  = q_pdu.get("revoke_forgotten")

        if q_pdu.get("clear_replay_protection"):
            for parent in self.parents.all():
                parent.clear_replay_protection()
            for child in self.children.all():
                child.clear_replay_protection()
            for repository in self.repositories.all():
                repository.clear_replay_protection()

        futures = []

        if rekey or revoke or reissue or revoke_forgotten:
            for parent in self.parents.all():
                if rekey:
                    futures.append(parent.serve_rekey(rpkid = rpkid))
                if revoke:
                    futures.append(parent.serve_revoke(rpkid = rpkid))
                if reissue:
                    futures.append(parent.serve_reissue(rpkid = rpkid))
                if revoke_forgotten:
                    futures.append(parent.serve_revoke_forgotten(rpkid = rpkid))

        if q_pdu.get("publish_world_now"):
            futures.append(self.serve_publish_world_now(rpkid = rpkid))
        if q_pdu.get("run_now"):
            futures.append(self.serve_run_now(rpkid = rpkid))

        yield futures


    @tornado.gen.coroutine
    def serve_publish_world_now(self, rpkid):
        trace_call_chain()

        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)
        objects = dict()

        for repository in self.repositories.all():
            q_msg = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                            type = "query", version = rpki.publication.version)
            SubElement(q_msg, rpki.publication.tag_list, tag = "list")
            r_msg = yield repository.call_pubd(rpkid, q_msg, length_check = False)
            if not all(r_pdu.tag == rpki.publication.tag_list for r_pdu in r_msg):
                raise rpki.exceptions.BadPublicationReply("Unexpected XML tag in publication response")
            objs = dict((r_pdu.get("uri"), (r_pdu.get("hash"), repository))
                        for r_pdu in r_msg if r_pdu.tag == rpki.publication.tag_list)
            if any(uri in objects for uri in objs):
                for uri in sorted(set(objects) & set(objs)):
                    logger.warning("Duplicated publication URI %s between %r and %r, this should not happen",
                                   uri, objects[uri][1], objs[uri][1])
            objects.update(objs)

        for ca_detail in CADetail.objects.filter(ca__parent__tenant = self, state = "active"):
            repository = ca_detail.ca.parent.repository
            objs = [(ca_detail.crl_uri,      ca_detail.latest_crl),
                    (ca_detail.manifest_uri, ca_detail.latest_manifest)]
            objs.extend((c.uri, c.cert)         for c in ca_detail.child_certs.all())
            objs.extend((r.uri, r.roa)          for r in ca_detail.roas.filter(roa__isnull = False))
            objs.extend((g.uri, g.ghostbuster)  for g in ca_detail.ghostbusters.all())
            objs.extend((c.uri, c.cert)         for c in ca_detail.ee_certificates.all())
            for uri, obj in objs:
                h, r = objects.get(uri, (None, None))
                if uri in objects and r == repository:
                    publisher.queue(uri = uri, new_obj = obj, repository = repository, old_hash = h)
                    del objects[uri]
                else:
                    publisher.queue(uri = uri, new_obj = obj, repository = repository)

        for u in objects:
            h, r = objects[u]
            publisher.queue(uri = u, old_hash = h, repository = r)

        yield publisher.call_pubd()


    @tornado.gen.coroutine
    def serve_run_now(self, rpkid):
        trace_call_chain()
        logger.debug("Forced immediate run of periodic actions for %r", self)
        tasks = self.cron_tasks(rpkid = rpkid)
        rpkid.task_add(tasks)
        futures = [task.wait() for task in tasks]
        rpkid.task_run()
        yield futures


    def cron_tasks(self, rpkid):
        trace_call_chain()
        # pylint: disable=W0201
        try:
            return self._cron_tasks
        except AttributeError:
            self._cron_tasks = tuple(task(rpkid, self) for task in rpki.rpkid_tasks.task_classes)
            return self._cron_tasks


    def find_covering_ca_details(self, resources):
        """
        Return all active CADetails for this <tenant/> which cover a
        particular set of resources.

        If we expected there to be a large number of CADetails, we
        could add index tables and write fancy SQL query to do this, but
        for the expected common case where there are only one or two
        active CADetails per <tenant/>, it's probably not worth it.  In
        any case, this is an optimization we can leave for later.
        """

        trace_call_chain()
        return set(ca_detail
                   for ca_detail in CADetail.objects.filter(ca__parent__tenant = self, state = "active")
                   if ca_detail.covers(resources))


@xml_hooks
class BSC(models.Model):
    bsc_handle = models.SlugField(max_length = 255)
    private_key_id = RSAPrivateKeyField()
    pkcs10_request = PKCS10Field()
    hash_alg = EnumField(choices = ("sha256",), default = "sha256")
    signing_cert = CertificateField(null = True)
    signing_cert_crl = CRLField(null = True)
    tenant = models.ForeignKey(Tenant, related_name = "bscs")
    objects = XMLManager()

    class Meta:
        unique_together = ("tenant", "bsc_handle")

    xml_template = XMLTemplate(
        name     = "bsc",
        elements = ("signing_cert", "signing_cert_crl"),
        readonly = ("pkcs10_request",))

    def __repr__(self):
        try:
            return "<BSC: {}.{}>".format(self.tenant.tenant_handle, self.bsc_handle)
        except:
            return "<BSC: BSC object>"

    def xml_pre_save_hook(self, q_pdu):
        # Handle key generation, only supports RSA with SHA-256 for now.
        if q_pdu.get("generate_keypair"):
            assert q_pdu.get("key_type") in (None, "rsa") and q_pdu.get("hash_alg") in (None, "sha256")
            self.private_key_id = rpki.x509.RSA.generate(keylength = int(q_pdu.get("key_length", 2048)))
            self.pkcs10_request = rpki.x509.PKCS10.create(keypair = self.private_key_id)


@xml_hooks
class Repository(models.Model):
    repository_handle = models.SlugField(max_length = 255)
    peer_contact_uri = models.TextField(null = True)
    rrdp_notification_uri = models.TextField(null = True)
    bpki_cert = CertificateField(null = True)
    bpki_glue = CertificateField(null = True)
    last_cms_timestamp = SundialField(null = True)
    bsc = models.ForeignKey(BSC, related_name = "repositories")
    tenant = models.ForeignKey(Tenant, related_name = "repositories")
    objects = XMLManager()

    class Meta:
        unique_together = ("tenant", "repository_handle")

    xml_template = XMLTemplate(
        name       = "repository",
        handles    = (BSC,),
        attributes = ("peer_contact_uri", "rrdp_notification_uri"),
        elements   = ("bpki_cert", "bpki_glue"))

    def __repr__(self):
        try:
            uri = " " + self.peer_contact_uri
        except:
            uri = ""
        try:
            return "<Repository: {}.{}{}>".format(self.tenant.tenant_handle, self.repository_handle, uri)
        except:
            return "<Repository: Repository object>"


    @tornado.gen.coroutine
    def xml_post_save_hook(self, rpkid, q_pdu):
        trace_call_chain()
        if q_pdu.get("clear_replay_protection"):
            self.clear_replay_protection()


    def clear_replay_protection(self):
        trace_call_chain()
        self.last_cms_timestamp = None
        self.save()


    @tornado.gen.coroutine
    def call_pubd(self, rpkid, q_msg, handlers = None, length_check = True):
        """
        Send a message to publication daemon and return the response.

        As a convenience, attempting to send an empty message returns
        immediate success without sending anything.

        handlers is a dict of handler functions to process the
        response PDUs.  If the uri value in the response PDU appears
        in the dict, the associated handler is called to process the
        PDU; otherwise, a default handler is called to check for
        errors.  A handler value of False suppresses calling of the
        default handler.
        """

        trace_call_chain()
        if len(q_msg) == 0:
            return
        if handlers is None:
            handlers = {}
        for q_pdu in q_msg:
            logger.info("Sending %r hash = %s uri = %s to pubd", q_pdu, q_pdu.get("hash"), q_pdu.get("uri"))
        http_request = tornado.httpclient.HTTPRequest(
            url     = self.peer_contact_uri,
            method  = "POST",
            body    = rpki.publication.cms_msg().wrap(q_msg, self.bsc.private_key_id,
                                                      self.bsc.signing_cert, self.bsc.signing_cert_crl),
            headers = { "Content-Type" : rpki.publication.content_type })
        http_response = yield rpkid.http_fetch(http_request)
        if http_response.headers.get("Content-Type") not in rpki.publication.allowed_content_types:
            raise rpki.exceptions.BadContentType("HTTP Content-Type %r, expected %r" % (
                rpki.publication.content_type, http_response.headers.get("Content-Type")))
        r_cms = rpki.publication.cms_msg(DER = http_response.body)
        r_msg = r_cms.unwrap((rpkid.bpki_ta, self.tenant.bpki_cert, self.tenant.bpki_glue, self.bpki_cert, self.bpki_glue))
        r_cms.check_replay_sql(self, self.peer_contact_uri)
        for r_pdu in r_msg:
            logger.info("Received %r hash = %s uri = %s from pubd", r_pdu, r_pdu.get("hash"), r_pdu.get("uri"))
            handler = handlers.get(r_pdu.get("uri"), rpki.publication.raise_if_error)
            if handler:
                logger.debug("Calling pubd handler %r", handler)
                handler(r_pdu)
        if length_check and len(q_msg) != len(r_msg):
            raise rpki.exceptions.BadPublicationReply("Wrong number of response PDUs from pubd: sent %r, got %r" % (q_msg, r_msg))
        raise tornado.gen.Return(r_msg)


@xml_hooks
class Parent(models.Model):
    parent_handle = models.SlugField(max_length = 255)
    bpki_cert = CertificateField(null = True)
    bpki_glue = CertificateField(null = True)
    peer_contact_uri = models.TextField(null = True)
    sia_base = models.TextField(null = True)
    sender_name = models.TextField(null = True)
    recipient_name = models.TextField(null = True)
    last_cms_timestamp = SundialField(null = True)
    tenant = models.ForeignKey(Tenant, related_name = "parents")
    bsc = models.ForeignKey(BSC, related_name = "parents")
    repository = models.ForeignKey(Repository, related_name = "parents")
    objects = XMLManager()

    class Meta:
        unique_together = ("tenant", "parent_handle")

    xml_template = XMLTemplate(
        name       = "parent",
        handles    = (BSC, Repository),
        attributes = ("peer_contact_uri", "sia_base", "sender_name", "recipient_name"),
        elements   = ("bpki_cert", "bpki_glue"))

    def __repr__(self):
        try:
            uri = " " + self.peer_contact_uri
        except:
            uri = ""
        try:
            return "<Parent: {}.{}{}>".format(self.tenant.tenant_handle, self.parent_handle, uri)
        except:
            return "<Parent: Parent object>"


    @tornado.gen.coroutine
    def xml_pre_delete_hook(self, rpkid):
        trace_call_chain()
        yield self.destroy(rpkid = rpkid, delete_parent = False)

    @tornado.gen.coroutine
    def xml_post_save_hook(self, rpkid, q_pdu):
        trace_call_chain()
        if q_pdu.get("clear_replay_protection"):
            self.clear_replay_protection()
        futures = []
        if q_pdu.get("rekey"):
            futures.append(self.serve_rekey(rpkid = rpkid))
        if q_pdu.get("revoke"):
            futures.append(self.serve_revoke(rpkid = rpkid))
        if q_pdu.get("reissue"):
            futures.append(self.serve_reissue(rpkid = rpkid))
        if q_pdu.get("revoke_forgotten"):
            futures.append(self.serve_revoke_forgotten(rpkid = rpkid))
        yield futures

    @tornado.gen.coroutine
    def serve_rekey(self, rpkid):
        trace_call_chain()
        yield [ca.rekey(rpkid = rpkid) for ca in self.cas.all()]

    @tornado.gen.coroutine
    def serve_revoke(self, rpkid):
        trace_call_chain()
        yield [ca.revoke(rpkid = rpkid) for ca in self.cas.all()]

    @tornado.gen.coroutine
    def serve_reissue(self, rpkid):
        trace_call_chain()
        yield [ca.reissue(rpkid = rpkid) for ca in self.cas.all()]

    def clear_replay_protection(self):
        trace_call_chain()
        self.last_cms_timestamp = None
        self.save()


    @tornado.gen.coroutine
    def get_skis(self, rpkid):
        """
        Fetch SKIs that this parent thinks we have.  In theory this should
        agree with our own database, but in practice stuff can happen, so
        sometimes we need to know what our parent thinks.

        Result is a dictionary with the resource class name as key and a
        set of SKIs as value.

        This, like everything else dealing with SKIs in the up-down
        protocol, is mis-named: we're really dealing with g(SKI) values,
        not raw SKI values.  Sorry.
        """

        trace_call_chain()
        r_msg = yield self.up_down_list_query(rpkid = rpkid)
        ski_map = {}
        for rc in r_msg.getiterator(rpki.up_down.tag_class):
            skis = set()
            for c in rc.getiterator(rpki.up_down.tag_certificate):
                skis.add(rpki.x509.X509(Base64 = c.text).gSKI())
            ski_map[rc.get("class_name")] = skis
        raise tornado.gen.Return(ski_map)


    @tornado.gen.coroutine
    def revoke_skis(self, rpkid, rc_name, skis_to_revoke):
        """
        Revoke a set of SKIs within a particular resource class.
        """

        trace_call_chain()
        for ski in skis_to_revoke:
            logger.debug("Asking parent %r to revoke class %r, g(SKI) %s", self, rc_name, ski)
            yield self.up_down_revoke_query(rpkid = rpkid, class_name = rc_name, ski = ski)


    @tornado.gen.coroutine
    def serve_revoke_forgotten(self, rpkid):
        """
        Handle a left-right revoke_forgotten action for this parent.

        This is a bit fiddly: we have to compare the result of an up-down
        list query with what we have locally and identify the SKIs of any
        certificates that have gone missing.  This should never happen in
        ordinary operation, but can arise if we have somehow lost a
        private key, in which case there is nothing more we can do with
        the issued cert, so we have to clear it.  As this really is not
        supposed to happen, we don't clear it automatically, instead we
        require an explicit trigger.
        """

        trace_call_chain()
        skis_from_parent = yield self.get_skis(rpkid = rpkid)
        for rc_name, skis_to_revoke in skis_from_parent.iteritems():
            for ca_detail in CADetail.objects.filter(ca__parent = self).exclude(state = "revoked"):
                skis_to_revoke.discard(ca_detail.latest_ca_cert.gSKI())
            yield self.revoke_skis(rpkid, rc_name, skis_to_revoke)


    @tornado.gen.coroutine
    def destroy(self, rpkid, delete_parent = True):
        """
        Delete all the CA stuff under this parent, and perhaps the parent
        itself.
        """

        trace_call_chain()
        yield [ca.destroy(rpkid = rpkid, parent = self) for ca in self.cas()] # pylint: disable=E1101
        yield self.serve_revoke_forgotten(rpkid = rpkid)
        if delete_parent:
            self.delete()


    def _compose_up_down_query(self, query_type):
        return Element(rpki.up_down.tag_message, nsmap = rpki.up_down.nsmap, version = rpki.up_down.version,
                       sender  = self.sender_name, recipient = self.recipient_name, type = query_type)


    @tornado.gen.coroutine
    def up_down_list_query(self, rpkid):
        trace_call_chain()
        q_msg = self._compose_up_down_query("list")
        r_msg = yield self.query_up_down(rpkid, q_msg)
        raise tornado.gen.Return(r_msg)


    @tornado.gen.coroutine
    def up_down_issue_query(self, rpkid, ca, ca_detail):
        trace_call_chain()
        logger.debug("Parent.up_down_issue_query(): caRepository %r rpkiManifest %r rpkiNotify %r",
                     ca.sia_uri, ca_detail.manifest_uri, ca.parent.repository.rrdp_notification_uri)
        pkcs10 = rpki.x509.PKCS10.create(
            keypair      = ca_detail.private_key_id,
            is_ca        = True,
            caRepository = ca.sia_uri,
            rpkiManifest = ca_detail.manifest_uri,
            rpkiNotify   = ca.parent.repository.rrdp_notification_uri)
        q_msg = self._compose_up_down_query("issue")
        q_pdu = SubElement(q_msg, rpki.up_down.tag_request, class_name = ca.parent_resource_class)
        q_pdu.text = pkcs10.get_Base64()
        r_msg = yield self.query_up_down(rpkid, q_msg)
        raise tornado.gen.Return(r_msg)

    @tornado.gen.coroutine
    def up_down_revoke_query(self, rpkid, class_name, ski):
        trace_call_chain()
        q_msg = self._compose_up_down_query("revoke")
        SubElement(q_msg, rpki.up_down.tag_key, class_name = class_name, ski = ski)
        r_msg = yield self.query_up_down(rpkid, q_msg)
        raise tornado.gen.Return(r_msg)


    @tornado.gen.coroutine
    def query_up_down(self, rpkid, q_msg):
        trace_call_chain()
        if self.bsc is None:
            raise rpki.exceptions.BSCNotFound("Could not find BSC")
        if self.bsc.signing_cert is None:
            raise rpki.exceptions.BSCNotReady("%r is not yet usable" % self.bsc)
        http_request = tornado.httpclient.HTTPRequest(
            url     = self.peer_contact_uri,
            method  = "POST",
            body    = rpki.up_down.cms_msg().wrap(q_msg, self.bsc.private_key_id,
                                                  self.bsc.signing_cert, self.bsc.signing_cert_crl),
            headers = { "Content-Type" : rpki.up_down.content_type })
        http_response = yield rpkid.http_fetch(http_request)
        if http_response.headers.get("Content-Type") not in rpki.up_down.allowed_content_types:
            raise rpki.exceptions.BadContentType("HTTP Content-Type %r, expected %r" % (
                rpki.up_down.content_type, http_response.headers.get("Content-Type")))
        r_cms = rpki.up_down.cms_msg(DER = http_response.body)
        r_msg = r_cms.unwrap((rpkid.bpki_ta, self.tenant.bpki_cert, self.tenant.bpki_glue, self.bpki_cert, self.bpki_glue))
        r_cms.check_replay_sql(self, self.peer_contact_uri)
        rpki.up_down.check_response(r_msg, q_msg.get("type"))
        raise tornado.gen.Return(r_msg)


    def construct_sia_uri(self, rc):
        """
        Construct the sia_uri value for a CA under this parent given
        configured information and the parent's up-down protocol
        list_response PDU.
        """

        trace_call_chain()
        sia_uri = rc.get("suggested_sia_head", "")
        if not sia_uri.startswith("rsync://") or not sia_uri.startswith(self.sia_base):
            sia_uri = self.sia_base
        if not sia_uri.endswith("/"):
            raise rpki.exceptions.BadURISyntax("SIA URI must end with a slash: %s" % sia_uri)
        return sia_uri


class CA(models.Model):
    last_crl_manifest_number = models.BigIntegerField(default = 1)
    last_issued_sn = models.BigIntegerField(default = 1)
    sia_uri = models.TextField(null = True)
    parent_resource_class = models.TextField(null = True)                 # Not sure this should allow NULL
    parent = models.ForeignKey(Parent, related_name = "cas")

    # So it turns out that there's always a 1:1 mapping between the
    # class_name we receive from our parent and the class_name we issue
    # to our children: in spite of the obfuscated way that we used to
    # handle class names, we never actually added a way for the back-end
    # to create new classes.  Not clear we want to encourage this, but
    # if we wanted to support it, simple approach would probably be an
    # optional class_name attribute in the left-right <list_resources/>
    # response; if not present, we'd use parent's class_name as now,
    # otherwise we'd use the supplied class_name.

    # ca_obj had a zillion properties encoding various specialized
    # ca_detail queries.  ORM query syntax renders this OBE, but need
    # to translate in existing code.
    #
    #def pending_ca_details(self):                  return self.ca_details.filter(state = "pending")
    #def active_ca_detail(self):                    return self.ca_details.get(state = "active")
    #def deprecated_ca_details(self):               return self.ca_details.filter(state = "deprecated")
    #def active_or_deprecated_ca_details(self):     return self.ca_details.filter(state__in = ("active", "deprecated"))
    #def revoked_ca_details(self):                  return self.ca_details.filter(state = "revoked")
    #def issue_response_candidate_ca_details(self): return self.ca_details.exclude(state = "revoked")

    def __repr__(self):
        try:
            return "<CA: {}.{} class {}>".format(self.parent.tenant.tenant_handle,
                                                 self.parent.parent_handle,
                                                 self.parent_resource_class)
        except:
            return "<CA: CA object>"


    @tornado.gen.coroutine
    def destroy(self, rpkid, parent):
        """
        The list of current resource classes received from parent does not
        include the class corresponding to this CA, so we need to delete
        it (and its little dog too...).

        All certs published by this CA are now invalid, so need to
        withdraw them, the CRL, and the manifest from the repository,
        delete all child_cert and ca_detail records associated with this
        CA, then finally delete this CA itself.
        """

        trace_call_chain()
        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)
        for ca_detail in self.ca_details.all():
            ca_detail.destroy(publisher = publisher, allow_failure = True)
        try:
            yield publisher.call_pubd()
        except:
            logger.exception("Could not destroy %r, skipping", self)
        else:
            logger.debug("Destroying %r", self)
            self.delete()


    def next_serial_number(self):
        """
        Allocate a certificate serial number.
        """

        trace_call_chain()
        self.last_issued_sn += 1
        self.save()
        return self.last_issued_sn


    def create_detail(self):
        """
        Create a new CADetail object for this CA.
        """

        trace_call_chain()
        cer_keypair = rpki.x509.RSA.generate()
        mft_keypair = rpki.x509.RSA.generate()
        return CADetail.objects.create(
            ca                      = self,
            state                   = "pending",
            private_key_id          = cer_keypair,
            public_key              = cer_keypair.get_public(),
            manifest_private_key_id = mft_keypair,
            manifest_public_key     = mft_keypair.get_public())


    @tornado.gen.coroutine
    def rekey(self, rpkid):
        """
        Initiate a rekey operation for this CA.  Generate a new keypair.
        Request cert from parent using new keypair.  Mark result as our
        active ca_detail.  Reissue all child certs issued by this CA using
        the new ca_detail.
        """

        trace_call_chain()
        try:
            old_detail = self.ca_details.get(state = "active")
        except CADetail.DoesNotExist:
            old_detail = None
        new_detail = self.create_detail()
        logger.debug("Sending issue request to %r from %r", self.parent, self.rekey)
        r_msg = yield self.parent.up_down_issue_query(rpkid = rpkid, ca = self, ca_detail = new_detail)
        c = r_msg[0][0]
        logger.debug("%r received certificate %s", self, c.get("cert_url"))
        yield new_detail.activate(
            rpkid       = rpkid,
            ca          = self,
            cert        = rpki.x509.X509(Base64 = c.text),
            uri         = c.get("cert_url"),
            predecessor = old_detail)


    @tornado.gen.coroutine
    def revoke(self, rpkid, revoke_all = False):
        """
        Revoke deprecated ca_detail objects associated with this CA, or
        all ca_details associated with this CA if revoke_all is set.

        For each CADetail, this involves: requesting revocation of the
        keypair by parent; revoking all issued certificates;
        generating final CRL and manifest covering the period one CRL
        cycle past the time that the last certificate would have
        expired; and destroying the keypair.  We leave final CRL and
        manifest in place until their nextupdate time has passed.
        """

        trace_call_chain()

        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)

        if revoke_all:
            ca_details = self.ca_details.all()
        else:
            ca_details = self.ca_details.filter(state = "deprecated")

        for ca_detail in ca_details:

            gski = ca_detail.latest_ca_cert.gSKI()
            logger.debug("Asking parent to revoke CA certificate matching g(SKI) = %s", gski)
            r_msg = yield self.parent.up_down_revoke_query(rpkid = rpkid, class_name = self.parent_resource_class, ski = gski)
            if r_msg[0].get("class_name") != self.parent_resource_class:
                raise rpki.exceptions.ResourceClassMismatch
            if r_msg[0].get("ski") != gski:
                raise rpki.exceptions.SKIMismatch
            logger.debug("Parent revoked g(SKI) %s, starting cleanup", gski)

            nextUpdate = rpki.sundial.now()
            if ca_detail.latest_manifest is not None:
                ca_detail.latest_manifest.extract_if_needed()
                nextUpdate = nextUpdate.later(ca_detail.latest_manifest.getNextUpdate())
            if ca_detail.latest_crl is not None:
                nextUpdate = nextUpdate.later(ca_detail.latest_crl.getNextUpdate())
            for child_cert in ca_detail.child_certs.all():
                nextUpdate = nextUpdate.later(child_cert.cert.getNotAfter())
                child_cert.revoke(publisher = publisher)
            for roa in ca_detail.roas.all():
                nextUpdate = nextUpdate.later(roa.cert.getNotAfter())
                roa.revoke(publisher = publisher)
            for ghostbuster in ca_detail.ghostbusters.all():
                nextUpdate = nextUpdate.later(ghostbuster.cert.getNotAfter())
                ghostbuster.revoke(publisher = publisher)
            for eecert in ca_detail.ee_certificates.all():
                nextUpdate = nextUpdate.later(eecert.cert.getNotAfter())
                eecert.revoke(publisher = publisher)
            nextUpdate += rpki.sundial.timedelta(seconds = self.parent.tenant.crl_interval)

            ca_detail.generate_crl_and_manifest(publisher = publisher, nextUpdate = nextUpdate)
            ca_detail.private_key_id = None
            ca_detail.manifest_private_key_id = None
            ca_detail.manifest_public_key = None
            ca_detail.state = "revoked"
            ca_detail.save()

        yield publisher.call_pubd()


    @tornado.gen.coroutine
    def reissue(self, rpkid):
        """
        Reissue all current certificates issued by this CA.
        """

        trace_call_chain()
        ca_detail = self.ca_details.get(state = "active")
        if ca_detail:
            yield ca_detail.reissue(rpkid = rpkid)


class CADetail(models.Model):
    public_key = PublicKeyField(null = True)
    private_key_id = RSAPrivateKeyField(null = True)
    latest_crl = CRLField(null = True)
    crl_published = SundialField(null = True)
    latest_ca_cert = CertificateField(null = True)
    manifest_private_key_id = RSAPrivateKeyField(null = True)
    manifest_public_key = PublicKeyField(null = True)
    latest_manifest = ManifestField(null = True)
    manifest_published = SundialField(null = True)
    next_crl_manifest_update = SundialField(null = True)
    state = EnumField(choices = ("pending", "active", "deprecated", "revoked"))
    ca_cert_uri = models.TextField(null = True)
    ca = models.ForeignKey(CA, related_name = "ca_details") # pylint: disable=C0103

    def __repr__(self):
        try:
            return "<CADetail: {}.{} class {} {} {}>".format(self.ca.parent.tenant.tenant_handle,
                                                             self.ca.parent.parent_handle,
                                                             self.ca.parent_resource_class,
                                                             self.state,
                                                             self.ca_cert_uri)
        except:
            return "<CADetail: CADetail object>"


    @property
    def crl_uri(self):
        """
        Return publication URI for this ca_detail's CRL.
        """

        return self.ca.sia_uri + self.crl_uri_tail


    @property
    def crl_uri_tail(self):
        """
        Return tail (filename portion) of publication URI for this ca_detail's CRL.
        """

        # pylint: disable=E1101
        return self.public_key.gSKI() + ".crl"


    @property
    def manifest_uri(self):
        """
        Return publication URI for this ca_detail's manifest.
        """

        # pylint: disable=E1101
        return self.ca.sia_uri + self.public_key.gSKI() + ".mft"


    def has_expired(self):
        """
        Return whether this ca_detail's certificate has expired.
        """

        return self.latest_ca_cert.getNotAfter() <= rpki.sundial.now()


    def covers(self, target):
        """
        Test whether this ca-detail covers a given set of resources.
        """

        assert not target.asn.inherit and not target.v4.inherit and not target.v6.inherit
        me = self.latest_ca_cert.get_3779resources()
        return target.asn <= me.asn and target.v4 <= me.v4 and target.v6  <= me.v6


    @tornado.gen.coroutine
    def activate(self, rpkid, ca, cert, uri, predecessor = None):
        """
        Activate this ca_detail.
        """

        trace_call_chain()
        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)
        self.latest_ca_cert = cert
        self.ca_cert_uri = uri
        self.state = "active"
        self.generate_crl_and_manifest(publisher = publisher)
        self.save()

        if predecessor is not None:
            predecessor.state = "deprecated"
            predecessor.save()
            for child_cert in predecessor.child_certs.all():
                child_cert.reissue(ca_detail = self, publisher = publisher)
            for roa in predecessor.roas.all():
                roa.regenerate(publisher = publisher)
            for ghostbuster in predecessor.ghostbusters.all():
                ghostbuster.regenerate(publisher = publisher)
            predecessor.generate_crl_and_manifest(publisher = publisher)

        yield publisher.call_pubd()


    def destroy(self, publisher, allow_failure = False):
        """
        Delete this ca_detail and all of the certs it issued.

        If allow_failure is true, we clean up as much as we can but don't
        raise an exception.
        """

        trace_call_chain()
        repository = self.ca.parent.repository
        handler = False if allow_failure else None
        for child_cert in self.child_certs.all():
            publisher.queue(uri = child_cert.uri, old_obj = child_cert.cert, repository = repository, handler = handler)
            child_cert.delete()
        for roa in self.roas.all():
            roa.revoke(publisher = publisher, allow_failure = allow_failure)
        for ghostbuster in self.ghostbusters.all():
            ghostbuster.revoke(publisher = publisher, allow_failure = allow_failure)
        if self.latest_manifest is not None:
            publisher.queue(uri = self.manifest_uri, old_obj = self.latest_manifest, repository = repository, handler = handler)
        if self.latest_crl is not None:
            publisher.queue(uri = self.crl_uri, old_obj = self.latest_crl, repository = repository, handler = handler)
        for cert in self.revoked_certs.all():     # + self.child_certs.all()
            logger.debug("Deleting %r", cert)
            cert.delete()
        logger.debug("Deleting %r", self)
        self.delete()


    @tornado.gen.coroutine
    def update(self, rpkid, parent, ca, rc, sia_uri_changed, old_resources):
        """
        Need to get a new certificate for this ca_detail and perhaps frob
        children of this ca_detail.
        """

        trace_call_chain()

        logger.debug("Sending issue request to %r from %r", parent, self.update)

        r_msg = yield parent.up_down_issue_query(rpkid = rpkid, ca = ca, ca_detail = self)

        c = r_msg[0][0]

        cert = rpki.x509.X509(Base64 = c.text)
        cert_url = c.get("cert_url")

        logger.debug("%r received certificate %s", self, cert_url)

        if self.state == "pending":
            yield self.activate(rpkid = rpkid, ca = ca, cert = cert, uri = cert_url)
            return

        validity_changed = self.latest_ca_cert is None or self.latest_ca_cert.getNotAfter() != cert.getNotAfter()

        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)

        if self.latest_ca_cert != cert:
            self.latest_ca_cert = cert
            self.save()
            self.generate_crl_and_manifest(publisher = publisher)

        new_resources = self.latest_ca_cert.get_3779resources()

        if sia_uri_changed or old_resources.oversized(new_resources):
            for child_cert in self.child_certs.all():
                child_resources = child_cert.cert.get_3779resources()
                if sia_uri_changed or child_resources.oversized(new_resources):
                    child_cert.reissue(ca_detail = self, resources = child_resources & new_resources, publisher = publisher)

        if sia_uri_changed or validity_changed or old_resources.oversized(new_resources):
            for roa in self.roas.all():
                roa.update(publisher = publisher)

        if sia_uri_changed or validity_changed:
            for ghostbuster in self.ghostbusters.all():
                ghostbuster.update(publisher = publisher)

        yield publisher.call_pubd()


    def issue_ee(self, ca, resources, subject_key, sia,
                 cn = None, sn = None, notAfter = None, eku = None):
        """
        Issue a new EE certificate.
        """

        trace_call_chain()
        if notAfter is None:
            notAfter = self.latest_ca_cert.getNotAfter()
        return self.latest_ca_cert.issue(
            keypair     = self.private_key_id,
            subject_key = subject_key,
            serial      = ca.next_serial_number(),
            sia         = sia,
            aia         = self.ca_cert_uri,
            crldp       = self.crl_uri,
            resources   = resources,
            notAfter    = notAfter,
            is_ca       = False,
            cn          = cn,
            sn          = sn,
            eku         = eku)


    def issue(self, ca, child, subject_key, sia, resources, publisher, child_cert = None):
        """
        Issue a new certificate to a child.  Optional child_cert argument
        specifies an existing child_cert object to update in place; if not
        specified, we create a new one.  Returns the child_cert object
        containing the newly issued cert.
        """

        trace_call_chain()
        self.check_failed_publication(publisher)
        cert = self.latest_ca_cert.issue(
            keypair     = self.private_key_id,
            subject_key = subject_key,
            serial      = ca.next_serial_number(),
            aia         = self.ca_cert_uri,
            crldp       = self.crl_uri,
            sia         = sia,
            resources   = resources,
            notAfter    = resources.valid_until)
        if child_cert is None:
            old_cert = None
            child_cert = ChildCert(child = child, ca_detail = self, cert = cert)
            logger.debug("Created new child_cert %r", child_cert)
        else:
            old_cert = child_cert.cert
            child_cert.cert = cert
            child_cert.ca_detail = self
            logger.debug("Reusing existing child_cert %r", child_cert)
        child_cert.gski = cert.gSKI()
        child_cert.published = rpki.sundial.now()
        child_cert.save()
        publisher.queue(
            uri        = child_cert.uri,
            old_obj    = old_cert,
            new_obj    = child_cert.cert,
            repository = ca.parent.repository,
            handler    = child_cert.published_callback)
        self.generate_crl_and_manifest(publisher = publisher)
        return child_cert


    def generate_crl_and_manifest(self, publisher, nextUpdate = None):
        """
        Generate a new CRL and a new manifest for this ca_detail.

        At the moment this is unconditional, that is, it is up to the
        caller to decide whether a new CRL is needed.

        We used to handle CRL and manifest as two separate operations,
        but there's no real point, and it's simpler to do them at once.
        """

        trace_call_chain()

        self.check_failed_publication(publisher)

        crl_interval = rpki.sundial.timedelta(seconds = self.ca.parent.tenant.crl_interval)
        now = rpki.sundial.now()
        if nextUpdate is None:
            nextUpdate = now + crl_interval

        old_crl      = self.latest_crl
        old_manifest = self.latest_manifest
        crl_uri      = self.crl_uri
        manifest_uri = self.manifest_uri

        manifest_cert = self.issue_ee(
            ca          = self.ca,
            resources   = rpki.resource_set.resource_bag.from_inheritance(),
            subject_key = self.manifest_public_key,
            sia         = (None, None, manifest_uri, self.ca.parent.repository.rrdp_notification_uri))

        self.ca.last_crl_manifest_number += 1
        self.ca.save()

        certlist = []
        for revoked_cert in self.revoked_certs.all():
            if now > revoked_cert.expires + crl_interval:
                revoked_cert.delete()
            else:
                certlist.append((revoked_cert.serial, revoked_cert.revoked))
        certlist.sort()

        self.latest_crl = rpki.x509.CRL.generate(
            keypair             = self.private_key_id,
            issuer              = self.latest_ca_cert,
            serial              = self.ca.last_crl_manifest_number,
            thisUpdate          = now,
            nextUpdate          = nextUpdate,
            revokedCertificates = certlist)

        objs = [(self.crl_uri_tail, self.latest_crl)]
        objs.extend((c.uri_tail, c.cert)        for c in self.child_certs.all())
        objs.extend((r.uri_tail, r.roa)         for r in self.roas.filter(roa__isnull = False))
        objs.extend((g.uri_tail, g.ghostbuster) for g in self.ghostbusters.all())
        objs.extend((e.uri_tail, e.cert)        for e in self.ee_certificates.all())

        self.latest_manifest = rpki.x509.SignedManifest.build(
            serial         = self.ca.last_crl_manifest_number,
            thisUpdate     = now,
            nextUpdate     = nextUpdate,
            names_and_objs = objs,
            keypair        = self.manifest_private_key_id,
            certs          = manifest_cert)

        self.crl_published      = now
        self.manifest_published = now
        self.next_crl_manifest_update = nextUpdate
        self.save()

        publisher.queue(
            uri        = crl_uri,
            old_obj    = old_crl,
            new_obj    = self.latest_crl,
            repository = self.ca.parent.repository,
            handler    = self.crl_published_callback)

        publisher.queue(
            uri        = manifest_uri,
            old_obj    = old_manifest,
            new_obj    = self.latest_manifest,
            repository = self.ca.parent.repository,
            handler    = self.manifest_published_callback)


    def crl_published_callback(self, pdu):
        """
        Check result of CRL publication.
        """

        trace_call_chain()
        rpki.publication.raise_if_error(pdu)
        self.crl_published = None
        self.save()

    def manifest_published_callback(self, pdu):
        """
        Check result of manifest publication.
        """

        trace_call_chain()
        rpki.publication.raise_if_error(pdu)
        self.manifest_published = None
        self.save()


    @tornado.gen.coroutine
    def reissue(self, rpkid):
        """
        Reissue all current certificates issued by this ca_detail.
        """

        trace_call_chain()
        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)
        self.check_failed_publication(publisher)
        for roa in self.roas.all():
            roa.regenerate(publisher)
        for ghostbuster in self.ghostbusters.all():
            ghostbuster.regenerate(publisher)
        for ee_certificate in self.ee_certificates.all():
            ee_certificate.reissue(publisher, force = True)
        for child_cert in self.child_certs.all():
            child_cert.reissue(self, publisher, force = True)
        self.generate_crl_and_manifest(publisher = publisher)
        self.save()
        yield publisher.call_pubd()


    def check_failed_publication(self, publisher, check_all = True):
        """
        Check for failed publication of objects issued by this ca_detail.

        All publishable objects have timestamp fields recording time of
        last attempted publication, and callback methods which clear these
        timestamps once publication has succeeded.  Our task here is to
        look for objects issued by this ca_detail which have timestamps
        set (indicating that they have not been published) and for which
        the timestamps are not very recent (for some definition of very
        recent -- intent is to allow a bit of slack in case pubd is just
        being slow).  In such cases, we want to retry publication.

        As an optimization, we can probably skip checking other products
        if manifest and CRL have been published, thus saving ourselves
        several complex SQL queries.  Not sure yet whether this
        optimization is worthwhile.

        For the moment we check everything without optimization, because
        it simplifies testing.

        For the moment our definition of staleness is hardwired; this
        should become configurable.
        """

        trace_call_chain()

        logger.debug("Checking for failed publication for %r", self)

        stale = rpki.sundial.now() - rpki.sundial.timedelta(seconds = 60)
        repository = self.ca.parent.repository
        if self.latest_crl is not None and self.crl_published is not None and self.crl_published < stale:
            logger.debug("Retrying publication for %s", self.crl_uri)
            publisher.queue(uri = self.crl_uri,
                            new_obj = self.latest_crl,
                            repository = repository,
                            handler = self.crl_published_callback)
        if self.latest_manifest is not None and self.manifest_published is not None and self.manifest_published < stale:
            logger.debug("Retrying publication for %s", self.manifest_uri)
            publisher.queue(uri = self.manifest_uri,
                            new_obj = self.latest_manifest,
                            repository = repository,
                            handler = self.manifest_published_callback)
        if not check_all:
            return
        for child_cert in self.child_certs.filter(published__isnull = False, published__lt = stale):
            logger.debug("Retrying publication for %s", child_cert)
            publisher.queue(
                uri        = child_cert.uri,
                new_obj    = child_cert.cert,
                repository = repository,
                handler    = child_cert.published_callback)
        for roa in self.roas.filter(published__isnull = False, published__lt = stale):
            logger.debug("Retrying publication for %s", roa)
            publisher.queue(
                uri        = roa.uri,
                new_obj    = roa.roa,
                repository = repository,
                handler    = roa.published_callback)
        for ghostbuster in self.ghostbusters.filter(published__isnull = False, published__lt = stale):
            logger.debug("Retrying publication for %s", ghostbuster)
            publisher.queue(
                uri        = ghostbuster.uri,
                new_obj    = ghostbuster.ghostbuster,
                repository = repository,
                handler    = ghostbuster.published_callback)
        for ee_cert in self.ee_certificates.filter(published__isnull = False, published__lt = stale):
            logger.debug("Retrying publication for %s", ee_cert)
            publisher.queue(
                uri        = ee_cert.uri,
                new_obj    = ee_cert.cert,
                repository = repository,
                handler    = ee_cert.published_callback)


@xml_hooks
class Child(models.Model):
    child_handle = models.SlugField(max_length = 255)
    bpki_cert = CertificateField(null = True)
    bpki_glue = CertificateField(null = True)
    last_cms_timestamp = SundialField(null = True)
    tenant = models.ForeignKey(Tenant, related_name = "children")
    bsc = models.ForeignKey(BSC, related_name = "children")
    objects = XMLManager()

    class Meta:
        unique_together = ("tenant", "child_handle")

    xml_template = XMLTemplate(
        name     = "child",
        handles  = (BSC,),
        elements = ("bpki_cert", "bpki_glue"))

    def __repr__(self):
        try:
            return "<Child: {}.{}>".format(self.tenant.tenant_handle, self.child_handle)
        except:
            return "<Child: Child object>"


    @tornado.gen.coroutine
    def xml_pre_delete_hook(self, rpkid):
        trace_call_chain()
        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)
        for child_cert in self.child_certs.all():
            child_cert.revoke(publisher = publisher, generate_crl_and_manifest = True)
        yield publisher.call_pubd()


    @tornado.gen.coroutine
    def xml_post_save_hook(self, rpkid, q_pdu):
        trace_call_chain()
        if q_pdu.get("clear_replay_protection"):
            self.clear_replay_protection()
        if q_pdu.get("reissue"):
            yield self.serve_reissue(rpkid = rpkid)


    def serve_reissue(self, rpkid):
        trace_call_chain()
        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)
        for child_cert in self.child_certs.all():
            child_cert.reissue(child_cert.ca_detail, publisher, force = True)
        yield publisher.call_pubd()


    def clear_replay_protection(self):
        trace_call_chain()
        self.last_cms_timestamp = None
        self.save()


    @tornado.gen.coroutine
    def up_down_handle_list(self, rpkid, q_msg, r_msg):

        trace_call_chain()
        irdb_resources = yield rpkid.irdb_query_child_resources(self.tenant.tenant_handle, self.child_handle)
        if irdb_resources.valid_until < rpki.sundial.now():
            logger.debug("Child %s's resources expired %s", self.child_handle, irdb_resources.valid_until)
        else:
            for ca_detail in CADetail.objects.filter(ca__parent__tenant = self.tenant, state = "active"):
                resources = ca_detail.latest_ca_cert.get_3779resources() & irdb_resources
                if resources.empty():
                    logger.debug("No overlap between received resources and what child %s should get ([%s], [%s])",
                                 self.child_handle, ca_detail.latest_ca_cert.get_3779resources(), irdb_resources)
                    continue
                rc = SubElement(r_msg, rpki.up_down.tag_class,
                                class_name = ca_detail.ca.parent_resource_class,
                                cert_url = ca_detail.ca_cert_uri,
                                resource_set_as   = str(resources.asn),
                                resource_set_ipv4 = str(resources.v4),
                                resource_set_ipv6 = str(resources.v6),
                                resource_set_notafter = str(resources.valid_until))
                for child_cert in self.child_certs.filter(ca_detail = ca_detail):
                    c = SubElement(rc, rpki.up_down.tag_certificate, cert_url = child_cert.uri)
                    c.text = child_cert.cert.get_Base64()
                SubElement(rc, rpki.up_down.tag_issuer).text = ca_detail.latest_ca_cert.get_Base64()


    @tornado.gen.coroutine
    def up_down_handle_issue(self, rpkid, q_msg, r_msg):

        trace_call_chain()

        req = q_msg[0]
        assert req.tag == rpki.up_down.tag_request

        # Subsetting not yet implemented, this is the one place where we have to handle it, by reporting that we're lame.

        if any(req.get(a) for a in ("req_resource_set_as", "req_resource_set_ipv4", "req_resource_set_ipv6")):
            raise rpki.exceptions.NotImplementedYet("req_* attributes not implemented yet, sorry")

        class_name = req.get("class_name")
        pkcs10 = rpki.x509.PKCS10(Base64 = req.text)
        pkcs10.check_valid_request_ca()
        ca_detail = CADetail.objects.get(ca__parent__tenant = self.tenant, state = "active",
                                         ca__parent_resource_class = class_name)

        irdb_resources = yield rpkid.irdb_query_child_resources(self.tenant.tenant_handle, self.child_handle)

        if irdb_resources.valid_until < rpki.sundial.now():
            raise rpki.exceptions.IRDBExpired("IRDB entry for child %s expired %s" % (
                self.child_handle, irdb_resources.valid_until))

        resources = irdb_resources & ca_detail.latest_ca_cert.get_3779resources()
        resources.valid_until = irdb_resources.valid_until
        req_key = pkcs10.getPublicKey()
        req_sia = pkcs10.get_SIA()

        # Generate new cert or regenerate old one if necessary

        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)

        try:
            child_cert = self.child_certs.get(ca_detail = ca_detail, gski = req_key.gSKI())

        except ChildCert.DoesNotExist:
            child_cert = ca_detail.issue(
                ca          = ca_detail.ca,
                child       = self,
                subject_key = req_key,
                sia         = req_sia,
                resources   = resources,
                publisher   = publisher)

        else:
            child_cert = child_cert.reissue(
                ca_detail = ca_detail,
                sia       = req_sia,
                resources = resources,
                publisher = publisher)

        yield publisher.call_pubd()

        rc = SubElement(r_msg, rpki.up_down.tag_class,
                        class_name = class_name,
                        cert_url = ca_detail.ca_cert_uri,
                        resource_set_as   = str(resources.asn),
                        resource_set_ipv4 = str(resources.v4),
                        resource_set_ipv6 = str(resources.v6),
                        resource_set_notafter = str(resources.valid_until))
        c = SubElement(rc, rpki.up_down.tag_certificate, cert_url = child_cert.uri)
        c.text = child_cert.cert.get_Base64()
        SubElement(rc, rpki.up_down.tag_issuer).text = ca_detail.latest_ca_cert.get_Base64()


    @tornado.gen.coroutine
    def up_down_handle_revoke(self, rpkid, q_msg, r_msg):
        trace_call_chain()
        key = q_msg[0]
        assert key.tag == rpki.up_down.tag_key
        class_name = key.get("class_name")
        publisher = rpki.rpkid.publication_queue(rpkid = rpkid)
        for child_cert in ChildCert.objects.filter(ca_detail__ca__parent__tenant = self.tenant,
                                                   ca_detail__ca__parent_resource_class = class_name,
                                                   gski = key.get("ski")):
            child_cert.revoke(publisher = publisher)
        yield publisher.call_pubd()
        SubElement(r_msg, key.tag, class_name = class_name, ski = key.get("ski"))


    @tornado.gen.coroutine
    def serve_up_down(self, rpkid, q_der):
        """
        Outer layer of server handling for one up-down PDU from this child.
        """

        trace_call_chain()

        if self.bsc is None:
            raise rpki.exceptions.BSCNotFound("Could not find BSC")

        q_cms = rpki.up_down.cms_msg(DER = q_der)
        q_msg = q_cms.unwrap((rpkid.bpki_ta, self.tenant.bpki_cert, self.tenant.bpki_glue, self.bpki_cert, self.bpki_glue))
        q_cms.check_replay_sql(self, "child", self.child_handle)
        q_type = q_msg.get("type")

        logger.info("Serving %s query from child %s [sender %s, recipient %s]",
                    q_type, self.child_handle, q_msg.get("sender"), q_msg.get("recipient"))

        if rpki.up_down.enforce_strict_up_down_xml_sender and q_msg.get("sender") != self.child_handle:
            raise rpki.exceptions.BadSender("Unexpected XML sender %s" % q_msg.get("sender"))

        r_msg = Element(rpki.up_down.tag_message, nsmap = rpki.up_down.nsmap, version = rpki.up_down.version,
                        sender = q_msg.get("recipient"), recipient = q_msg.get("sender"), type = q_type + "_response")

        try:
            yield getattr(self, "up_down_handle_" + q_type)(rpkid, q_msg, r_msg)

        except Exception, e:
            logger.exception("Unhandled exception serving child %r", self)
            rpki.up_down.generate_error_response_from_exception(r_msg, e, q_type)

        r_der = rpki.up_down.cms_msg().wrap(r_msg, self.bsc.private_key_id, self.bsc.signing_cert, self.bsc.signing_cert_crl)
        raise tornado.gen.Return(r_der)

class ChildCert(models.Model):
    cert = CertificateField()
    published = SundialField(null = True)
    gski = models.CharField(max_length = 27)      # Assumes SHA-1 -- SHA-256 would be 43, SHA-512 would be 86, etc.
    child = models.ForeignKey(Child, related_name = "child_certs")
    ca_detail = models.ForeignKey(CADetail, related_name = "child_certs")

    def __repr__(self):
        try:
            return "<ChildCert: {}.{} {}>".format(self.child.tenant.tenant_handle,
                                                  self.child.child_handle,
                                                  self.uri)
        except:
            return "<ChildCert: ChildCert object>"


    @property
    def uri_tail(self):
        """
        Return the tail (filename) portion of the URI for this child_cert.
        """

        return self.gski + ".cer"


    @property
    def uri(self):
        """
        Return the publication URI for this child_cert.
        """

        return self.ca_detail.ca.sia_uri + self.uri_tail


    def revoke(self, publisher, generate_crl_and_manifest = True):
        """
        Revoke a child cert.
        """

        trace_call_chain()
        ca_detail = self.ca_detail
        logger.debug("Revoking %r", self)
        RevokedCert.revoke(cert = self.cert, ca_detail = ca_detail)
        publisher.queue(uri = self.uri, old_obj = self.cert, repository = ca_detail.ca.parent.repository)
        self.delete()
        if generate_crl_and_manifest:
            ca_detail.generate_crl_and_manifest(publisher = publisher)


    def reissue(self, ca_detail, publisher, resources = None, sia = None, force = False):
        """
        Reissue an existing child cert, reusing the public key.  If
        the child cert we would generate is identical to the one we
        already have, we just return the one we already have.  If we
        have to revoke the old child cert when generating the new one,
        we have to generate a new ChildCert, so calling code that
        needs the updated ChildCert must use the return value from
        this method.
        """

        trace_call_chain()
        # pylint: disable=E1101
        ca = ca_detail.ca
        child = self.child
        old_resources = self.cert.get_3779resources()
        old_sia       = self.cert.get_SIA()
        old_aia       = self.cert.get_AIA()[0]
        old_ca_detail = self.ca_detail
        needed = False
        if resources is None:
            resources = old_resources
        if sia is None:
            sia = old_sia
        assert resources.valid_until is not None and old_resources.valid_until is not None
        if resources.asn != old_resources.asn or resources.v4 != old_resources.v4 or resources.v6 != old_resources.v6:
            logger.debug("Resources changed for %r: old %s new %s", self, old_resources, resources)
            needed = True
        if resources.valid_until != old_resources.valid_until:
            logger.debug("Validity changed for %r: old %s new %s",
                         self, old_resources.valid_until, resources.valid_until)
            needed = True
        if sia != old_sia:
            logger.debug("SIA changed for %r: old %r new %r", self, old_sia, sia)
            needed = True
        if ca_detail != old_ca_detail:
            logger.debug("Issuer changed for %r: old %r new %r", self, old_ca_detail, ca_detail)
            needed = True
        if ca_detail.ca_cert_uri != old_aia:
            logger.debug("AIA changed for %r: old %r new %r", self, old_aia, ca_detail.ca_cert_uri)
            needed = True
        must_revoke = old_resources.oversized(resources) or old_resources.valid_until > resources.valid_until
        if must_revoke:
            logger.debug("Must revoke any existing cert(s) for %r", self)
            needed = True
        if not needed and force:
            logger.debug("No change needed for %r, forcing reissuance anyway", self)
            needed = True
        if not needed:
            logger.debug("No change to %r", self)
            return self
        if must_revoke:
            for child_cert in child.child_certs.filter(ca_detail = ca_detail, gski = self.gski):
                logger.debug("Revoking %r", child_cert)
                child_cert.revoke(publisher = publisher)
            ca_detail.generate_crl_and_manifest(publisher = publisher)
        child_cert = ca_detail.issue(
            ca          = ca,
            child       = child,
            subject_key = self.cert.getPublicKey(),
            sia         = sia,
            resources   = resources,
            child_cert  = None if must_revoke else self,
            publisher   = publisher)
        logger.debug("New %r", child_cert)
        return child_cert


    def published_callback(self, pdu):
        """
        Publication callback: check result and mark published.
        """

        trace_call_chain()
        rpki.publication.raise_if_error(pdu)
        self.published = None
        self.save()


class EECertificate(models.Model):
    gski = models.CharField(max_length = 27)      # Assumes SHA-1 -- SHA-256 would be 43, SHA-512 would be 86, etc.
    cert = CertificateField()
    published = SundialField(null = True)
    tenant = models.ForeignKey(Tenant, related_name = "ee_certificates")
    ca_detail = models.ForeignKey(CADetail, related_name = "ee_certificates")

    def __repr__(self):
        try:
            return "<EECertificate: {} {}>".format(self.tenant.tenant_handle,
                                                   self.uri)
        except:
            return "<EECertificate: EECertificate object>"


    @property
    def uri(self):
        """
        Return the publication URI for this EECertificate.
        """

        return self.ca_detail.ca.sia_uri + self.uri_tail


    @property
    def uri_tail(self):
        """
        Return the tail (filename portion) of the publication URI for this
        EECertificate.
        """

        return self.gski + ".cer"


    def revoke(self, publisher, generate_crl_and_manifest = True):
        """
        Revoke and withdraw an EE certificate.
        """

        trace_call_chain()
        ca_detail = self.ca_detail
        logger.debug("Revoking %r", self)
        RevokedCert.revoke(cert = self.cert, ca_detail = ca_detail)
        publisher.queue(uri = self.uri, old_obj = self.cert, repository = ca_detail.ca.parent.repository)
        self.delete()
        if generate_crl_and_manifest:
            ca_detail.generate_crl_and_manifest(publisher = publisher)


    def reissue(self, publisher, ca_detail = None, resources = None, force = False):
        """
        Reissue an existing EE cert, reusing the public key.  If the EE
        cert we would generate is identical to the one we already have, we
        just return; if we need to reissue, we reuse this EECertificate and
        just update its contents, as the publication URI will not have
        changed.
        """

        trace_call_chain()
        needed = False
        old_cert = self.cert
        old_ca_detail = self.ca_detail
        if ca_detail is None:
            ca_detail = old_ca_detail
        assert ca_detail.ca is old_ca_detail.ca
        old_resources = old_cert.get_3779resources()
        if resources is None:
            resources = old_resources
        assert resources.valid_until is not None and old_resources.valid_until is not None
        assert ca_detail.covers(resources)
        if ca_detail != self.ca_detail:
            logger.debug("ca_detail changed for %r: old %r new %r", self, self.ca_detail, ca_detail)
            needed = True
        if ca_detail.ca_cert_uri != old_cert.get_AIA()[0]:
            logger.debug("AIA changed for %r: old %s new %s", self, old_cert.get_AIA()[0], ca_detail.ca_cert_uri)
            needed = True
        if resources.valid_until != old_resources.valid_until:
            logger.debug("Validity changed for %r: old %s new %s", self, old_resources.valid_until, resources.valid_until)
            needed = True
        if resources.asn != old_resources.asn or resources.v4 != old_resources.v4 or resources.v6 != old_resources.v6:
            logger.debug("Resources changed for %r: old %s new %s", self, old_resources, resources)
            needed = True
        must_revoke = old_resources.oversized(resources) or old_resources.valid_until > resources.valid_until
        if must_revoke:
            logger.debug("Must revoke existing cert(s) for %r", self)
            needed = True
        if not needed and force:
            logger.debug("No change needed for %r, forcing reissuance anyway", self)
            needed = True
        if not needed:
            logger.debug("No change to %r", self)
            return
        cn, sn = self.cert.getSubject().extract_cn_and_sn()
        self.cert = ca_detail.issue_ee(
            ca          = ca_detail.ca,
            subject_key = self.cert.getPublicKey(),
            eku         = self.cert.get_EKU(),
            sia         = (None, None, self.uri, ca_detail.ca.parent.repository.rrdp_notification_uri),
            resources   = resources,
            notAfter    = resources.valid_until,
            cn          = cn,
            sn          = sn)
        self.save()
        publisher.queue(
            uri        = self.uri,
            old_obj    = old_cert,
            new_obj    = self.cert,
            repository = ca_detail.ca.parent.repository,
            handler    = self.published_callback)
        if must_revoke:
            RevokedCert.revoke(cert = old_cert.cert, ca_detail = old_ca_detail)
        ca_detail.generate_crl_and_manifest(publisher = publisher)


    def published_callback(self, pdu):
        """
        Publication callback: check result and mark published.
        """

        trace_call_chain()
        rpki.publication.raise_if_error(pdu)
        self.published = None
        self.save()



class Ghostbuster(models.Model):
    vcard = models.TextField()
    cert = CertificateField()
    ghostbuster = GhostbusterField()
    published = SundialField(null = True)
    tenant = models.ForeignKey(Tenant, related_name = "ghostbusters")
    ca_detail = models.ForeignKey(CADetail, related_name = "ghostbusters")

    def __repr__(self):
        try:
            uri = " " + self.uri
        except:
            uri = ""
        try:
            return "<Ghostbuster: {}{}>".format(self.tenant.tenant_handle, uri)
        except:
            return "<Ghostbuster: Ghostbuster object>"


    def update(self, publisher):
        """
        Bring this Ghostbuster up to date if necesssary.
        """

        trace_call_chain()

        if self.ghostbuster is None:
            logger.debug("Ghostbuster record doesn't exist, generating")
            return self.generate(publisher = publisher)

        now = rpki.sundial.now()
        regen_time = self.cert.getNotAfter() - rpki.sundial.timedelta(seconds = self.tenant.regen_margin)

        if now > regen_time and self.cert.getNotAfter() < self.ca_detail.latest_ca_cert.getNotAfter():
            logger.debug("%r past threshold %s, regenerating", self, regen_time)
            return self.regenerate(publisher = publisher)

        if now > regen_time:
            logger.warning("%r is past threshold %s but so is issuer %r, can't regenerate", self, regen_time, self.ca_detail)

        if self.cert.get_AIA()[0] != self.ca_detail.ca_cert_uri:
            logger.debug("%r AIA changed, regenerating", self)
            return self.regenerate(publisher = publisher)


    def generate(self, publisher):
        """
        Generate a Ghostbuster record

        As with ROAs, we generate a new keypair every time.
        """

        trace_call_chain()
        resources = rpki.resource_set.resource_bag.from_inheritance()
        keypair = rpki.x509.RSA.generate()
        self.cert = self.ca_detail.issue_ee(
            ca          = self.ca_detail.ca,
            resources   = resources,
            subject_key = keypair.get_public(),
            sia         = (None, None, self.uri_from_key(keypair),
                           self.ca_detail.ca.parent.repository.rrdp_notification_uri))
        self.ghostbuster = rpki.x509.Ghostbuster.build(self.vcard, keypair, (self.cert,))
        self.published = rpki.sundial.now()
        self.save()
        logger.debug("Generating %r", self)
        publisher.queue(
            uri        = self.uri,
            new_obj    = self.ghostbuster,
            repository = self.ca_detail.ca.parent.repository,
            handler    = self.published_callback)


    def published_callback(self, pdu):
        """
        Check publication result.
        """

        trace_call_chain()
        rpki.publication.raise_if_error(pdu)
        self.published = None
        self.save()


    def revoke(self, publisher, regenerate = False, allow_failure = False):
        """
        Withdraw Ghostbuster associated with this Ghostbuster.

        In order to preserve make-before-break properties without
        duplicating code, this method also handles generating a
        replacement ghostbuster when requested.

        If allow_failure is set, failing to withdraw the ghostbuster will not be
        considered an error.
        """

        trace_call_chain()
        ca_detail = self.ca_detail
        logger.debug("%s %r", "Regenerating" if regenerate else "Not regenerating", self)
        old_obj = self.ghostbuster
        old_cer = self.cert
        old_uri = self.uri
        if regenerate:
            self.generate(publisher = publisher)
        logger.debug("Withdrawing %r and revoking its EE cert", self)
        RevokedCert.revoke(cert = old_cer, ca_detail = ca_detail)
        publisher.queue(
            uri        = old_uri,
            old_obj    = old_obj,
            repository = ca_detail.ca.parent.repository,
            handler    = False if allow_failure else None)
        if not regenerate:
            self.delete()


    def regenerate(self, publisher):
        """
        Reissue Ghostbuster associated with this Ghostbuster.
        """

        trace_call_chain()
        if self.ghostbuster is None:
            self.generate(publisher = publisher)
        else:
            self.revoke(publisher = publisher, regenerate = True)


    def uri_from_key(self, key):
        """
        Return publication URI for a public key.
        """

        trace_call_chain()
        return self.ca_detail.ca.sia_uri + key.gSKI() + ".gbr"


    @property
    def uri(self):
        """
        Return the publication URI for this Ghostbuster.
        """

        return self.ca_detail.ca.sia_uri + self.uri_tail


    @property
    def uri_tail(self):
        """
        Return the tail (filename portion) of the publication URI for this
        Ghostbuster.
        """

        return self.cert.gSKI() + ".gbr"


class RevokedCert(models.Model):
    serial = models.BigIntegerField()
    revoked = SundialField()
    expires = SundialField()
    ca_detail = models.ForeignKey(CADetail, related_name = "revoked_certs")

    def __repr__(self):
        try:
            return "<RevokedCert: {}.{} class {} {} serial {} revoked {} expires {}>".format(
                self.ca_detail.ca.parent.tenant.tenant_handle,
                self.ca_detail.ca.parent.parent_handle,
                self.ca_detail.ca.parent_resource_class,
                self.ca_detail.crl_uri,
                self.serial,
                self.revoked,
                self.expires)
        except:
            return "<RevokedCert: RevokedCert object>"


    @classmethod
    def revoke(cls, cert, ca_detail):
        """
        Revoke a certificate.
        """

        trace_call_chain()
        return cls.objects.create(
            serial    = cert.getSerial(),
            expires   = cert.getNotAfter(),
            revoked   = rpki.sundial.now(),
            ca_detail = ca_detail)


class ROA(models.Model):
    asn = models.BigIntegerField()
    ipv4 = models.TextField(null = True)
    ipv6 = models.TextField(null = True)
    cert = CertificateField()
    roa = ROAField()
    published = SundialField(null = True)
    tenant = models.ForeignKey(Tenant, related_name = "roas")
    ca_detail = models.ForeignKey(CADetail, related_name = "roas")

    def __repr__(self):
        try:
            resources = " " + ",".join(str(ip) for ip in (self.ipv4, self.ipv6) if ip is not None)
        except:
            resources = ""
        try:
            uri = " " + self.uri
        except:
            uri = ""
        try:
            return "<ROA: {}{}{}>".format(self.tenant.tenant_handle, resources, uri)
        except:
            return "<ROA: ROA object>"


    def update(self, publisher):
        """
        Bring ROA up to date if necesssary.
        """

        trace_call_chain()

        if self.roa is None:
            logger.debug("%r doesn't exist, generating", self)
            return self.generate(publisher = publisher)

        if self.ca_detail is None:
            logger.debug("%r has no associated ca_detail, generating", self)
            return self.generate(publisher = publisher)

        if self.ca_detail.state != "active":
            logger.debug("ca_detail associated with %r not active (state %s), regenerating", self, self.ca_detail.state)
            return self.regenerate(publisher = publisher)

        now = rpki.sundial.now()
        regen_time = self.cert.getNotAfter() - rpki.sundial.timedelta(seconds = self.tenant.regen_margin)

        if now > regen_time and self.cert.getNotAfter() < self.ca_detail.latest_ca_cert.getNotAfter():
            logger.debug("%r past threshold %s, regenerating", self, regen_time)
            return self.regenerate(publisher = publisher)

        if now > regen_time:
            logger.warning("%r is past threshold %s but so is issuer %r, can't regenerate", self, regen_time, self.ca_detail)

        ca_resources = self.ca_detail.latest_ca_cert.get_3779resources()
        ee_resources = self.cert.get_3779resources()

        if ee_resources.oversized(ca_resources):
            logger.debug("%r oversized with respect to CA, regenerating", self)
            return self.regenerate(publisher = publisher)

        v4 = rpki.resource_set.resource_set_ipv4(self.ipv4)
        v6 = rpki.resource_set.resource_set_ipv6(self.ipv6)

        if ee_resources.v4 != v4 or ee_resources.v6 != v6:
            logger.debug("%r resources do not match EE, regenerating", self)
            return self.regenerate(publisher = publisher)

        if self.cert.get_AIA()[0] != self.ca_detail.ca_cert_uri:
            logger.debug("%r AIA changed, regenerating", self)
            return self.regenerate(publisher = publisher)


    def generate(self, publisher):
        """
        Generate a ROA.

        At present we have no way of performing a direct lookup from a
        desired set of resources to a covering certificate, so we have to
        search.  This could be quite slow if we have a lot of active
        ca_detail objects.  Punt on the issue for now, revisit if
        profiling shows this as a hotspot.

        Once we have the right covering certificate, we generate the ROA
        payload, generate a new EE certificate, use the EE certificate to
        sign the ROA payload, publish the result, then throw away the
        private key for the EE cert, all per the ROA specification.  This
        implies that generating a lot of ROAs will tend to thrash
        /dev/random, but there is not much we can do about that.
        """

        trace_call_chain()

        if self.ipv4 is None and self.ipv6 is None:
            raise rpki.exceptions.EmptyROAPrefixList

        v4 = rpki.resource_set.resource_set_ipv4(self.ipv4)
        v6 = rpki.resource_set.resource_set_ipv6(self.ipv6)

        # http://stackoverflow.com/questions/26270042/how-do-you-catch-this-exception
        # "Django is amazing when its not terrifying."
        try:
            ca_detail = self.ca_detail
        except CADetail.DoesNotExist:
            ca_detail = None

        if ca_detail is not None and ca_detail.state == "active" and not ca_detail.has_expired():
            logger.debug("Keeping old ca_detail %r for ROA %r", ca_detail, self)
        else:
            logger.debug("Searching for new ca_detail for ROA %r", self)
            for ca_detail in CADetail.objects.filter(ca__parent__tenant = self.tenant, state = "active"):
                resources = ca_detail.latest_ca_cert.get_3779resources()
                if not ca_detail.has_expired() and v4.issubset(resources.v4) and v6.issubset(resources.v6):
                    logger.debug("Using %r for ROA %r", ca_detail, self)
                    self.ca_detail = ca_detail
                    break
            else:
                raise rpki.exceptions.NoCoveringCertForROA("Could not find a certificate covering %r" % self)

        resources = rpki.resource_set.resource_bag(v4 = v4, v6 = v6)
        keypair = rpki.x509.RSA.generate()

        self.cert = self.ca_detail.issue_ee(
            ca          = self.ca_detail.ca,
            resources   = resources,
            subject_key = keypair.get_public(),
            sia         = (None, None, self.uri_from_key(keypair),
                           self.ca_detail.ca.parent.repository.rrdp_notification_uri))
        self.roa = rpki.x509.ROA.build(self.asn,
                                       rpki.resource_set.roa_prefix_set_ipv4(self.ipv4),
                                       rpki.resource_set.roa_prefix_set_ipv6(self.ipv6),
                                       keypair,
                                       (self.cert,))
        self.published = rpki.sundial.now()
        self.save()

        logger.debug("Generating %r", self)
        publisher.queue(uri = self.uri, new_obj = self.roa,
                        repository = self.ca_detail.ca.parent.repository,
                        handler = self.published_callback)


    def published_callback(self, pdu):
        """
        Check publication result.
        """

        trace_call_chain()
        rpki.publication.raise_if_error(pdu)
        self.published = None
        self.save()


    def revoke(self, publisher, regenerate = False, allow_failure = False):
        """
        Withdraw this ROA.

        In order to preserve make-before-break properties without
        duplicating code, this method also handles generating a
        replacement ROA when requested.

        If allow_failure is set, failing to withdraw the ROA will not be
        considered an error.
        """

        trace_call_chain()
        ca_detail = self.ca_detail
        logger.debug("%s %r", "Regenerating" if regenerate else "Not regenerating", self)
        old_obj = self.roa
        old_cer = self.cert
        old_uri = self.uri
        if regenerate:
            self.generate(publisher = publisher)
        logger.debug("Withdrawing %r and revoking its EE cert", self)
        RevokedCert.revoke(cert = old_cer, ca_detail = ca_detail)
        publisher.queue(
            uri        = old_uri,
            old_obj    = old_obj,
            repository = ca_detail.ca.parent.repository,
            handler    = False if allow_failure else None)
        if not regenerate:
            self.delete()


    def regenerate(self, publisher):
        """
        Reissue this ROA.
        """

        trace_call_chain()
        if self.ca_detail is None:
            self.generate(publisher = publisher)
        else:
            self.revoke(publisher = publisher, regenerate = True)


    def uri_from_key(self, key):
        """
        Return publication URI for a public key.
        """

        trace_call_chain()
        return self.ca_detail.ca.sia_uri + key.gSKI() + ".roa"


    @property
    def uri(self):
        """
        Return the publication URI for this ROA.
        """

        return self.ca_detail.ca.sia_uri + self.uri_tail


    @property
    def uri_tail(self):
        """
        Return the tail (filename portion) of the publication URI for this
        ROA.
        """

        return self.cert.gSKI() + ".roa"
