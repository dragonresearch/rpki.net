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
Trivial RPKI up-down protocol root server.  Not recommended for
production use.  Overrides a bunch of method definitions from the
rpki.* classes in order to reuse as much code as possible.
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

rootd = None

class list_pdu(rpki.up_down.list_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored, callback, errback):
    r_msg.payload = rpki.up_down.list_response_pdu()
    rootd.compose_response(r_msg, callback, errback)

class issue_pdu(rpki.up_down.issue_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored, callback, errback):
    self.pkcs10.check_valid_request_ca()
    r_msg.payload = rpki.up_down.issue_response_pdu()
    rootd.compose_response(r_msg, callback, errback, self.pkcs10)

class revoke_pdu(rpki.up_down.revoke_pdu):
  def serve_pdu(self, q_msg, r_msg, ignored, callback, errback):
    logger.debug("Revocation requested for SKI %s", self.ski)
    subject_cert = rootd.get_subject_cert()
    if subject_cert is None:
      logger.debug("No subject certificate, nothing to revoke")
      raise rpki.exceptions.NotInDatabase
    if subject_cert.gSKI() != self.ski:
      logger.debug("Subject certificate has different SKI %s, not revoking", subject_cert.gSKI())
      raise rpki.exceptions.NotInDatabase
    logger.debug("Revoking certificate %s", self.ski)
    now = rpki.sundial.now()
    pubd_msg = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                       type = "query", version = rpki.publication.version)
    rootd.revoke_subject_cert(now)
    rootd.del_subject_cert()
    rootd.del_subject_pkcs10()
    r_msg.payload = rpki.up_down.revoke_response_pdu()
    r_msg.payload.class_name = self.class_name
    r_msg.payload.ski = self.ski
    rootd.generate_crl_and_manifest(now, pubd_msg)
    rootd.publish(callback, errback, pubd_msg)

class error_response_pdu(rpki.up_down.error_response_pdu):
  exceptions = rpki.up_down.error_response_pdu.exceptions.copy()
  exceptions[rpki.exceptions.ClassNameUnknown, revoke_pdu] = 1301
  exceptions[rpki.exceptions.NotInDatabase,    revoke_pdu] = 1302

class message_pdu(rpki.up_down.message_pdu):

  name2type = dict(
    rpki.up_down.message_pdu.name2type,
    list            = list_pdu,
    issue           = issue_pdu,
    revoke          = revoke_pdu,
    error_response  = error_response_pdu)

  type2name = dict((v, k) for k, v in name2type.iteritems())

  error_pdu_type = error_response_pdu

  def log_query(self, child):
    logger.info("Serving %s query", self.type)

class sax_handler(rpki.up_down.sax_handler):
  pdu = message_pdu

class cms_msg(rpki.up_down.cms_msg):
  saxify = sax_handler.saxify

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


  def compose_response(self, r_msg, callback, errback, pkcs10 = None):
    subject_cert, pubd_msg = self.issue_subject_cert_maybe(pkcs10)
    rc = rpki.up_down.class_elt()
    rc.class_name = self.rpki_class_name
    rc.cert_url = rpki.up_down.multi_uri(self.rpki_root_cert_uri)
    rc.from_resource_bag(self.rpki_root_cert.get_3779resources())
    rc.issuer = self.rpki_root_cert
    r_msg.payload.classes.append(rc)
    if subject_cert is not None:
      rc.certs.append(rpki.up_down.certificate_elt())
      rc.certs[0].cert_url = rpki.up_down.multi_uri(self.rpki_subject_cert_uri)
      rc.certs[0].cert = subject_cert
    self.publish(callback, errback, pubd_msg)


  def publish(self, callback, errback, q_msg):

    def done(r_msg):
      if len(q_msg) != len(r_msg):
        raise rpki.exceptions.BadPublicationReply("Wrong number of response PDUs from pubd: sent %s, got %s" % (len(q_msg), len(r_msg)))
      callback()

    def fix_hashes(r_msg):
      published_hash = dict((r_pdu.get("uri"), r_pdu.get("hash")) for r_pdu in r_msg)
      for q_pdu in q_msg:
        if q_pdu.get("hash") is None and published_hash.get(q_pdu.get("uri")) is not None:
          logger.debug("Updating hash of %s to %s from previously published data", q_pdu.get("uri"), published_hash[q_pdu.get("uri")])
          q_pdu.set("hash", published_hash[q_pdu.get("uri")])
      self.call_pubd(done, errback, q_msg)

    assert q_msg is None or len(q_msg) > 0

    if q_msg is None:
      callback()
    elif all(q_pdu.get("hash") is not None for q_pdu in q_msg):
      self.call_pubd(done, errback, q_msg)
    else:
      logger.debug("Some publication PDUs are missing hashes, checking...")
      list_msg = Element(rpki.publication.tag_msg, nsmap = rpki.publication.nsmap,
                         type = "query", version = rpki.publication.version)
      SubElement(list_msg, rpki.publication.tag_list)
      self.call_pubd(fix_hashes, errback, list_msg)


  def call_pubd(self, callback, errback, q_msg):
    try:
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
      callback(r_msg)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      errback(e)


  def up_down_handler(self, query, path, cb):
    try:
      q_cms = cms_msg(DER = query)
      q_msg = q_cms.unwrap((self.bpki_ta, self.child_bpki_cert))
      self.rpkid_cms_timestamp = q_cms.check_replay(self.rpkid_cms_timestamp, path)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      logger.exception("Problem decoding PDU")
      return cb(400, reason = "Could not decode PDU: %s" % e)

    def done(r_msg):
      cb(200, body = cms_msg().wrap(
        r_msg, self.rootd_bpki_key, self.rootd_bpki_cert,
        self.rootd_bpki_crl if self.include_bpki_crl else None))

    try:
      q_msg.serve_top_level(None, done)
    except (rpki.async.ExitNow, SystemExit):
      raise
    except Exception, e:
      try:
        logger.exception("Exception serving up-down request %r", q_msg)
        done(q_msg.serve_error(e))
      except (rpki.async.ExitNow, SystemExit):
        raise
      except Exception, e:
        logger.exception("Exception while generating error report")
        cb(500, reason = "Could not process PDU: %s" % e)


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

    rpki.http.server(host        = self.http_server_host,
                     port        = self.http_server_port,
                     handlers    = self.up_down_handler)
