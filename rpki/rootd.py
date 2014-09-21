# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009--2012  Internet Systems Consortium ("ISC")
# Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL, ISC, AND ARIN DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL,
# ISC, OR ARIN BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
Trivial RPKI up-down protocol root server.
"""

import os
import sys
import time
import logging
import httplib
import argparse
import urlparse
import rpki.resource_set
import rpki.up_down
import rpki.left_right
import rpki.x509
import rpki.http
import rpki.http_simple
import rpki.config
import rpki.exceptions
import rpki.relaxng
import rpki.sundial
import rpki.log
import rpki.daemonize

from lxml.etree import Element, SubElement

logger = logging.getLogger(__name__)


class main(object):


  def root_newer_than_subject(self):
    return self.rpki_root_cert.mtime > os.stat(self.rpki_subject_cert_file).st_mtime


  def get_subject_cert(self):
    try:
      x = rpki.x509.X509(Auto_file = self.rpki_subject_cert_file)
      logger.debug("Read subject cert %s", self.rpki_subject_cert_file)
      return x
    except IOError:
      return None


  def set_subject_cert(self, cert):
    logger.debug("Writing subject cert %s, SKI %s", self.rpki_subject_cert_file, cert.hSKI())
    with open(self.rpki_subject_cert_file, "wb") as f:
      f.write(cert.get_DER())


  def del_subject_cert(self):
    logger.debug("Deleting subject cert %s", self.rpki_subject_cert_file)
    os.remove(self.rpki_subject_cert_file)


  def get_subject_pkcs10(self):
    try:
      x = rpki.x509.PKCS10(Auto_file = self.rpki_subject_pkcs10)
      logger.debug("Read subject PKCS #10 %s", self.rpki_subject_pkcs10)
      return x
    except IOError:
      return None


  def set_subject_pkcs10(self, pkcs10):
    logger.debug("Writing subject PKCS #10 %s", self.rpki_subject_pkcs10)
    with open(self.rpki_subject_pkcs10, "wb") as f:
      f.write(pkcs10.get_DER())


  def del_subject_pkcs10(self):
    logger.debug("Deleting subject PKCS #10 %s", self.rpki_subject_pkcs10)
    try:
      os.remove(self.rpki_subject_pkcs10)
    except OSError:
      pass


  def issue_subject_cert_maybe(self, new_pkcs10):
    now = rpki.sundial.now()
    subject_cert = self.get_subject_cert()
    hash = None if subject_cert is None else rpki.x509.sha256(subject_cert.get_DER()).encode("hex")
    old_pkcs10 = self.get_subject_pkcs10()
    if new_pkcs10 is not None and new_pkcs10 != old_pkcs10:
      self.set_subject_pkcs10(new_pkcs10)
      if subject_cert is not None:
        logger.debug("PKCS #10 changed, regenerating subject certificate")
        self.revoke_subject_cert(now)
        subject_cert = None
    if subject_cert is not None and subject_cert.getNotAfter() <= now + self.rpki_subject_regen:
      logger.debug("Subject certificate has reached expiration threshold, regenerating")
      self.revoke_subject_cert(now)
      subject_cert = None
    if subject_cert is not None and self.root_newer_than_subject():
      logger.debug("Root certificate has changed, regenerating subject")
      self.revoke_subject_cert(now)
      subject_cert = None
    if subject_cert is not None:
      return subject_cert, None
    pkcs10 = old_pkcs10 if new_pkcs10 is None else new_pkcs10
    if pkcs10 is None:
      logger.debug("No PKCS #10 request, can't generate subject certificate yet")
      return None, None
    resources = self.rpki_root_cert.get_3779resources()
    notAfter = now + self.rpki_subject_lifetime
    logger.info("Generating subject cert %s with resources %s, expires %s",
                self.rpki_subject_cert_uri, resources, notAfter)
    req_key = pkcs10.getPublicKey()
    req_sia = pkcs10.get_SIA()
    self.next_serial_number()
    subject_cert = self.rpki_root_cert.issue(
      keypair     = self.rpki_root_key,
      subject_key = req_key,
      serial      = self.serial_number,
      sia         = req_sia,
      aia         = self.rpki_root_cert_uri,
      crldp       = self.rpki_root_crl_uri,
      resources   = resources,
      notBefore   = now,
      notAfter    = notAfter)
    self.set_subject_cert(subject_cert)
    pubd_msg = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                       type = "query", version = rpki.publication.version)
    pdu = SubElement(pubd_msg, rpki.publication.tag_publish, uri = self.rpki_subject_cert_uri)
    pdu.text = subject_cert.get_Base64()
    if hash is not None:
      pdu.set("hash", hash)
    self.generate_crl_and_manifest(now, pubd_msg)
    return subject_cert, pubd_msg


  def generate_crl_and_manifest(self, now, pubd_msg):
    subject_cert = self.get_subject_cert()
    self.next_serial_number()
    self.next_crl_number()
    while self.revoked and self.revoked[0][1] + 2 * self.rpki_subject_regen < now:
      del self.revoked[0]
    crl = rpki.x509.CRL.generate(
      keypair             = self.rpki_root_key,
      issuer              = self.rpki_root_cert,
      serial              = self.crl_number,
      thisUpdate          = now,
      nextUpdate          = now + self.rpki_subject_regen,
      revokedCertificates = self.revoked)
    hash = self.read_hash_maybe(self.rpki_root_crl_file)
    logger.debug("Writing CRL %s", self.rpki_root_crl_file)
    with open(self.rpki_root_crl_file, "wb") as f:
      f.write(crl.get_DER())
    pdu = SubElement(pubd_msg, rpki.publication.tag_publish, uri = self.rpki_root_crl_uri)
    pdu.text = crl.get_Base64()
    if hash is not None:
      pdu.set("hash", hash)
    manifest_content = [(os.path.basename(self.rpki_root_crl_uri), crl)]
    if subject_cert is not None:
      manifest_content.append((os.path.basename(self.rpki_subject_cert_uri), subject_cert))
    manifest_resources = rpki.resource_set.resource_bag.from_inheritance()
    manifest_keypair = rpki.x509.RSA.generate()
    manifest_cert = self.rpki_root_cert.issue(
      keypair     = self.rpki_root_key,
      subject_key = manifest_keypair.get_public(),
      serial      = self.serial_number,
      sia         = (None, None, self.rpki_root_manifest_uri),
      aia         = self.rpki_root_cert_uri,
      crldp       = self.rpki_root_crl_uri,
      resources   = manifest_resources,
      notBefore   = now,
      notAfter    = now + self.rpki_subject_lifetime,
      is_ca       = False)
    manifest = rpki.x509.SignedManifest.build(
      serial         = self.crl_number,
      thisUpdate     = now,
      nextUpdate     = now + self.rpki_subject_regen,
      names_and_objs = manifest_content,
      keypair        = manifest_keypair,
      certs          = manifest_cert)
    hash = self.read_hash_maybe(self.rpki_root_manifest_file)
    logger.debug("Writing manifest %s", self.rpki_root_manifest_file)
    with open(self.rpki_root_manifest_file, "wb") as f:
      f.write(manifest.get_DER())
    pdu = SubElement(pubd_msg, rpki.publication.tag_publish, uri = self.rpki_root_manifest_uri)
    pdu.text = manifest.get_Base64()
    if hash is not None:
      pdu.set("hash", hash)
    hash = rpki.x509.sha256(self.rpki_root_cert.get_DER()).encode("hex")
    if hash != self.rpki_root_cert_hash:
      pdu = SubElement(pubd_msg, rpki.publication.tag_publish, uri = self.rpki_root_cert_uri)
      pdu.text = self.rpki_root_cert.get_Base64()
      if self.rpki_root_cert_hash is not None:
        pdu.set("hash", self.rpki_root_cert_hash)
      self.rpki_root_cert_hash = hash


  @staticmethod
  def read_hash_maybe(fn):
    try:
      with open(fn, "rb") as f:
        return rpki.x509.sha256(f.read()).encode("hex")
    except IOError:
      return None


  def revoke_subject_cert(self, now):
    self.revoked.append((self.get_subject_cert().getSerial(), now))


  def publish(self, q_msg):
    if q_msg is None:
      return
    assert len(q_msg) > 0

    if not all(q_pdu.get("hash") is not None for q_pdu in q_msg):
      logger.debug("Some publication PDUs are missing hashes, checking published data...")
      q = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                  type = "query", version = rpki.publication.version)
      SubElement(q, rpki.publication.tag_list)
      published_hash = dict((r.get("uri"), r.get("hash")) for r in self.call_pubd(q))
      for q_pdu in q_msg:
        q_uri = q_pdu.get("uri")
        if q_pdu.get("hash") is None and published_hash.get(q_uri) is not None:
          logger.debug("Updating hash of %s to %s from previously published data", q_uri, published_hash[q_uri])
          q_pdu.set("hash", published_hash[q_uri])

    r_msg = self.call_pubd(q_msg)
    if len(q_msg) != len(r_msg):
      raise rpki.exceptions.BadPublicationReply("Wrong number of response PDUs from pubd: sent %s, got %s" % (len(q_msg), len(r_msg)))


  def call_pubd(self, q_msg):
    for q_pdu in q_msg:
      logger.info("Sending %s to pubd", q_pdu.get("uri"))
    q_der = rpki.publication.cms_msg_no_sax().wrap(q_msg, self.rootd_bpki_key, self.rootd_bpki_cert, self.rootd_bpki_crl)
    logger.debug("Sending request to pubd")
    http = httplib.HTTPConnection(self.pubd_host, self.pubd_port)
    http.request("POST", self.pubd_path, q_der, {"Content-Type" : rpki.http_simple.rpki_content_type})
    r = http.getresponse()
    if r.status != 200:
      raise rpki.exceptions.HTTPRequestFailed("HTTP request to pubd failed with status %r reason %r" % (r.status, r.reason))
    if r.getheader("Content-Type") != rpki.http_simple.rpki_content_type:
      raise rpki.exceptions.HTTPRequestFailed("HTTP request to pubd failed, got Content-Type %r, expected %r" % (
        r.getheader("Content-Type"), rpki.http_simple.rpki_content_type))
    logger.debug("Received response from pubd")
    r_der = r.read()
    r_cms = rpki.publication.cms_msg_no_sax(DER = r_der)
    r_msg = r_cms.unwrap((self.bpki_ta, self.pubd_bpki_cert))
    self.pubd_cms_timestamp = r_cms.check_replay(self.pubd_cms_timestamp, self.pubd_url)
    rpki.publication.raise_if_error(r_msg)
    return r_msg


  def compose_response(self, r_msg, pkcs10 = None):
    subject_cert, pubd_msg = self.issue_subject_cert_maybe(pkcs10)
    bag = self.rpki_root_cert.get_3779resources()
    rc = SubElement(r_msg, rpki.up_down.tag_class,
                    class_name        = self.rpki_class_name,
                    cert_url          = str(rpki.up_down.multi_uri(self.rpki_root_cert_uri)),
                    resource_set_as   = str(bag.asn),
                    resource_set_ipv4 = str(bag.v4),
                    resource_set_ipv6 = str(bag.v6),
                    resource_set_notafter = str(bag.valid_until))
    if subject_cert is not None:
      c = SubElement(rc, rpki.up_down.tag_certificate,
                     cert_url = str(rpki.up_down.multi_uri(self.rpki_subject_cert_uri)))
      c.text = subject_cert.get_Base64()
    SubElement(rc, rpki.up_down.tag_issuer).text = self.rpki_root_cert.get_Base64()
    self.publish(pubd_msg)


  def handle_list(self, q_msg, r_msg):
    self.compose_response(r_msg)


  def handle_issue(self, q_msg, r_msg):
    # This is where we'd check q_msg[0].get("class_name") if this weren't rootd.
    self.compose_response(r_msg, rpki.x509.PKCS10(Base64 = q_msg[0].text))


  def handle_revoke(self, q_msg, r_msg):
    class_name = q_msg[0].get("class_name")
    ski        = q_msg[0].get("ski")
    logger.debug("Revocation requested for class %s SKI %s", class_name, ski)
    subject_cert = self.get_subject_cert()
    if subject_cert is None:
      logger.debug("No subject certificate, nothing to revoke")
      raise rpki.exceptions.NotInDatabase
    if subject_cert.gSKI() != ski:
      logger.debug("Subject certificate has different SKI %s, not revoking", subject_cert.gSKI())
      raise rpki.exceptions.NotInDatabase
    logger.debug("Revoking certificate %s", ski)
    now = rpki.sundial.now()
    pubd_msg = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                       type = "query", version = rpki.publication.version)
    self.revoke_subject_cert(now)
    self.del_subject_cert()
    self.del_subject_pkcs10()
    SubElement(r_msg, q_msg[0].tag, class_name = class_name, ski = ski)
    self.generate_crl_and_manifest(now, pubd_msg)
    self.publish(pubd_msg)


  # Need to do something about mapping exceptions to up-down error
  # codes, right now everything shows up as "internal error".
  #
  #exceptions = {
  #  rpki.exceptions.ClassNameUnknown                    : 1201,
  #  rpki.exceptions.NoActiveCA                          : 1202,
  #  (rpki.exceptions.ClassNameUnknown, revoke_pdu)      : 1301,
  #  (rpki.exceptions.NotInDatabase,    revoke_pdu)      : 1302 }
  #
  # Might be that what we want here is a subclass of
  # rpki.exceptions.RPKI_Exception which carries an extra data field
  # for the up-down error code, so that we can add the correct code
  # when we instantiate it.
  #
  # There are also a few that are also schema violations, which means
  # we'd have to catch them before validating or pick them out of a
  # message that failed validation or otherwise break current
  # modularity.  Maybe an optional pre-validation check method hook in
  # rpki.x509.XML_CMS_object which we can use to intercept such things?


  def handler(self, request, q_der):
    try:
      q_cms = rpki.up_down.cms_msg_no_sax(DER = q_der)
      q_msg = q_cms.unwrap((self.bpki_ta, self.child_bpki_cert))
      q_type = q_msg.get("type")
      logger.info("Serving %s query", q_type)
      r_msg = Element(rpki.up_down.tag_message, nsmap = rpki.up_down.nsmap, version = rpki.up_down.version,
                      sender  = q_msg.get("recipient"), recipient = q_msg.get("sender"), type = q_type + "_response")
      try:
        self.rpkid_cms_timestamp = q_cms.check_replay(self.rpkid_cms_timestamp, request.path)
        getattr(self, "handle_" + q_type)(q_msg, r_msg)
      except Exception, e:
        # Should catch specific exceptions here to give better error codes.
        logger.exception("Exception processing up-down %s message", q_type)
        rpki.up_down.generate_error_response(r_msg, description = e)
      request.send_cms_response(rpki.up_down.cms_msg_no_sax().wrap(r_msg, self.rootd_bpki_key, self.rootd_bpki_cert,
                                                                   self.rootd_bpki_crl if self.include_bpki_crl else None))
    except Exception, e:
      logger.exception("Unhandled exception processing up-down message")
      request.send_error(500, "Unhandled exception %s: %s" % (e.__class__.__name__, e))


  def next_crl_number(self):
    if self.crl_number is None:
      try:
        crl = rpki.x509.CRL(DER_file = self.rpki_root_crl_file)
        self.crl_number = crl.getCRLNumber()
      except:                           # pylint: disable=W0702
        self.crl_number = 0
    self.crl_number += 1
    return self.crl_number


  def next_serial_number(self):
    if self.serial_number is None:
      subject_cert = self.get_subject_cert()
      if subject_cert is not None:
        self.serial_number = subject_cert.getSerial() + 1
      else:
        self.serial_number = 0
    self.serial_number += 1
    return self.serial_number


  def __init__(self):

    global rootd
    rootd = self                        # Gross, but simpler than what we'd have to do otherwise

    self.serial_number = None
    self.crl_number = None
    self.revoked = []
    self.rpkid_cms_timestamp = None
    self.pubd_cms_timestamp = None

    os.environ["TZ"] = "UTC"
    time.tzset()

    parser = argparse.ArgumentParser(description = __doc__)
    parser.add_argument("-c", "--config",
                        help = "override default location of configuration file")
    parser.add_argument("-f", "--foreground", action = "store_true",
                        help = "do not daemonize")
    parser.add_argument("--pidfile",
                        help = "override default location of pid file")
    rpki.log.argparse_setup(parser)
    args = parser.parse_args()

    rpki.log.init("rootd", args)

    self.cfg = rpki.config.parser(set_filename = args.config, section = "rootd")
    self.cfg.set_global_flags()

    if not args.foreground:
      rpki.daemonize.daemon(pidfile = args.pidfile)

    self.bpki_ta                 = rpki.x509.X509(Auto_update = self.cfg.get("bpki-ta"))
    self.rootd_bpki_key          = rpki.x509.RSA( Auto_update = self.cfg.get("rootd-bpki-key"))
    self.rootd_bpki_cert         = rpki.x509.X509(Auto_update = self.cfg.get("rootd-bpki-cert"))
    self.rootd_bpki_crl          = rpki.x509.CRL( Auto_update = self.cfg.get("rootd-bpki-crl"))
    self.child_bpki_cert         = rpki.x509.X509(Auto_update = self.cfg.get("child-bpki-cert"))

    if self.cfg.has_option("pubd-bpki-cert"):
      self.pubd_bpki_cert        = rpki.x509.X509(Auto_update = self.cfg.get("pubd-bpki-cert"))
    else:
      self.pubd_bpki_cert        = None

    self.http_server_host        = self.cfg.get("server-host", "")
    self.http_server_port        = self.cfg.getint("server-port")

    self.rpki_class_name         = self.cfg.get("rpki-class-name")

    self.rpki_root_key           = rpki.x509.RSA( Auto_update = self.cfg.get("rpki-root-key-file"))
    self.rpki_root_cert          = rpki.x509.X509(Auto_update = self.cfg.get("rpki-root-cert-file"))
    self.rpki_root_cert_uri      = self.cfg.get("rpki-root-cert-uri")
    self.rpki_root_cert_hash     = None

    self.rpki_root_manifest_file = self.cfg.get("rpki-root-manifest-file")
    self.rpki_root_manifest_uri  = self.cfg.get("rpki-root-manifest-uri")

    self.rpki_root_crl_file      = self.cfg.get("rpki-root-crl-file")
    self.rpki_root_crl_uri       = self.cfg.get("rpki-root-crl-uri")

    self.rpki_subject_cert_file  = self.cfg.get("rpki-subject-cert-file")
    self.rpki_subject_cert_uri   = self.cfg.get("rpki-subject-cert-uri")
    self.rpki_subject_pkcs10     = self.cfg.get("rpki-subject-pkcs10-file")
    self.rpki_subject_lifetime   = rpki.sundial.timedelta.parse(self.cfg.get("rpki-subject-lifetime", "8w"))
    self.rpki_subject_regen      = rpki.sundial.timedelta.parse(self.cfg.get("rpki-subject-regen",
                                                                             self.rpki_subject_lifetime.convert_to_seconds() / 2))

    self.include_bpki_crl        = self.cfg.getboolean("include-bpki-crl", False)

    self.pubd_url                = self.cfg.get("pubd-contact-uri")

    u = urlparse.urlparse(self.pubd_url)
    if u.scheme not in ("", "http") or u.username or u.password or u.params or u.query or u.fragment:
      logger.error("Unusable URL %s", self.pubd_url)
      sys.exit(1)

    self.pubd_host               = u.hostname
    self.pubd_port               = u.port or httplib.HTTP_PORT
    self.pubd_path               = u.path

    rpki.http_simple.server(host     = self.http_server_host,
                            port     = self.http_server_port,
                            handlers = self.handler)
