# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2011--2012  Internet Systems Consortium ("ISC")
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
Internet Registry (IR) Database, Django-style.

This is the back-end code's interface to the database.  It's intended
to be usable by command line programs and other scripts, not just
Django GUI code, so be careful.
"""

# pylint: disable=W5101,W5103

import django.db.models
import rpki.x509
import rpki.sundial
import rpki.resource_set
import socket
import rpki.POW

from rpki.fields import EnumField, SundialField, CertificateField, DERField, RSAPrivateKeyField, CRLField, PKCS10Field

## @var ip_version_choices
# Choice argument for fields implementing IP version numbers.

ip_version_choices = ((4, "IPv4"), (6, "IPv6"))

## @var ca_certificate_lifetime
# Lifetime for a BPKI CA certificate.

ca_certificate_lifetime = rpki.sundial.timedelta(days = 3652)

## @var crl_interval

# Expected interval between BPKI CRL updates.  This should be a little
# longer than the real regeneration cycle, so that the old CRL will
# not go stale while we're generating the new one.  Eg, if we
# regenerate daily, an interval of 24 hours is too short, but 25 hours
# would be OK, as would 24 hours and 30 minutes.

crl_interval = rpki.sundial.timedelta(hours = 25)

## @var ee_certificate_lifetime
# Lifetime for a BPKI EE certificate.

ee_certificate_lifetime = rpki.sundial.timedelta(days = 60)

###

# Field classes

class HandleField(django.db.models.CharField):
    """
    A handle field class.  Replace this with SlugField?
    """

    description = 'A "handle" in one of the RPKI protocols'

    def __init__(self, *args, **kwargs):
        kwargs["max_length"] = 120
        django.db.models.CharField.__init__(self, *args, **kwargs)


class SignedReferralField(DERField):
    description   = "CMS signed object containing XML"
    rpki_type     = rpki.x509.SignedReferral


# Custom managers

class CertificateManager(django.db.models.Manager):

    def get_or_certify(self, **kwargs):
        """
        Sort of like .get_or_create(), but for models containing
        certificates which need to be generated based on other fields.

        Takes keyword arguments like .get(), checks for existing object.
        If none, creates a new one; if found an existing object but some
        of the non-key fields don't match, updates the existing object.
        Runs certification method for new or updated objects.  Returns a
        tuple consisting of the object and a boolean indicating whether
        anything has changed.
        """

        # pylint: disable=E1101

        changed = False

        try:
            obj = self.get(**self._get_or_certify_keys(kwargs))

        except self.model.DoesNotExist:
            obj = self.model(**kwargs)
            changed = True

        else:
            for k in kwargs:
                if getattr(obj, k) != kwargs[k]:
                    setattr(obj, k, kwargs[k])
                    changed = True

        if changed:
            obj.avow()
            obj.save()

        return obj, changed

    def _get_or_certify_keys(self, kwargs):
        # pylint: disable=E1101,W0212
        assert len(self.model._meta.unique_together) == 1
        return dict((k, kwargs[k]) for k in self.model._meta.unique_together[0])

class ResourceHolderCAManager(CertificateManager):
    def _get_or_certify_keys(self, kwargs):
        return { "handle" : kwargs["handle"] }

class ServerCAManager(CertificateManager):
    def _get_or_certify_keys(self, kwargs):
        return { "pk" : 1 }

class ResourceHolderEEManager(CertificateManager):
    def _get_or_certify_keys(self, kwargs):
        return { "issuer" : kwargs["issuer"] }

###

class CA(django.db.models.Model):
    certificate = CertificateField()
    private_key = RSAPrivateKeyField()
    latest_crl = CRLField()

    # Might want to bring these into line with what rpkid does.  Current
    # variables here were chosen to map easily to what OpenSSL command
    # line tool was keeping on disk.

    next_serial = django.db.models.BigIntegerField(default = 1)
    next_crl_number = django.db.models.BigIntegerField(default = 1)
    last_crl_update = SundialField()
    next_crl_update = SundialField()

    class Meta:
        abstract = True

    @property
    def subject_name(self):
        raise NotImplementedError

    def avow(self):
        if self.private_key is None:
            self.private_key = rpki.x509.RSA.generate(quiet = True)
        now = rpki.sundial.now()
        notAfter = now + ca_certificate_lifetime
        self.certificate = rpki.x509.X509.bpki_self_certify(
            keypair      = self.private_key,
            subject_name = self.subject_name,
            serial       = self.next_serial,
            now          = now,
            notAfter     = notAfter)
        self.next_serial += 1
        self.generate_crl()
        return self.certificate

    def certify(self, subject_name, subject_key, validity_interval, is_ca, pathLenConstraint = None):
        now = rpki.sundial.now()
        notAfter = now + validity_interval
        result = self.certificate.bpki_certify(
            keypair           = self.private_key,
            subject_name      = subject_name,
            subject_key       = subject_key,
            serial            = self.next_serial,
            now               = now,
            notAfter          = notAfter,
            is_ca             = is_ca,
            pathLenConstraint = pathLenConstraint)
        self.next_serial += 1
        return result

    def revoke(self, cert):
        Revocation.objects.create(
            issuer  = self,
            revoked = rpki.sundial.now(),
            serial  = cert.certificate.getSerial(),
            expires = cert.certificate.getNotAfter() + crl_interval)
        cert.delete()
        self.generate_crl()

    def generate_crl(self):
        now = rpki.sundial.now()
        self.revocations.filter(expires__lt = now).delete()
        revoked = [(r.serial, r.revoked) for r in self.revocations.all()]
        self.latest_crl = rpki.x509.CRL.generate(
            keypair             = self.private_key,
            issuer              = self.certificate,
            serial              = self.next_crl_number,
            thisUpdate          = now,
            nextUpdate          = now + crl_interval,
            revokedCertificates = revoked)
        self.last_crl_update = now
        self.next_crl_update = now + crl_interval
        self.next_crl_number += 1

class ServerCA(CA):
    objects = ServerCAManager()

    def __unicode__(self):
        return ""

    @property
    def subject_name(self):
        if self.certificate is not None:
            return self.certificate.getSubject()
        else:
            return rpki.x509.X501DN.from_cn("%s BPKI server CA" % socket.gethostname())

class ResourceHolderCA(CA):
    handle = HandleField(unique = True)
    objects = ResourceHolderCAManager()

    def __unicode__(self):
        return self.handle

    @property
    def subject_name(self):
        if self.certificate is not None:
            return self.certificate.getSubject()
        else:
            return rpki.x509.X501DN.from_cn("%s BPKI resource CA" % self.handle)

class Certificate(django.db.models.Model):

    certificate = CertificateField()
    objects = CertificateManager()

    class Meta:
        abstract = True
        unique_together = ("issuer", "handle")

    def revoke(self):
        self.issuer.revoke(self)        # pylint: disable=E1101

class CrossCertification(Certificate):
    handle = HandleField()
    ta = CertificateField()             # pylint: disable=C0103

    class Meta:
        abstract = True

    def avow(self):
        # pylint: disable=E1101
        self.certificate = self.issuer.certify(
            subject_name      = self.ta.getSubject(),
            subject_key       = self.ta.getPublicKey(),
            validity_interval = ee_certificate_lifetime,
            is_ca             = True,
            pathLenConstraint = 0)

    def __unicode__(self):
        return self.handle

class HostedCA(Certificate):
    issuer = django.db.models.ForeignKey(ServerCA)
    hosted = django.db.models.OneToOneField(ResourceHolderCA, related_name = "hosted_by")

    def avow(self):
        self.certificate = self.issuer.certify(
            subject_name      = self.hosted.certificate.getSubject(),
            subject_key       = self.hosted.certificate.getPublicKey(),
            validity_interval = ee_certificate_lifetime,
            is_ca             = True,
            pathLenConstraint = 1)

    class Meta:
        unique_together = ("issuer", "hosted")

    def __unicode__(self):
        return self.hosted.handle

class Revocation(django.db.models.Model):
    serial = django.db.models.BigIntegerField()
    revoked = SundialField()
    expires = SundialField()

    class Meta:
        abstract = True
        unique_together = ("issuer", "serial")

class ServerRevocation(Revocation):
    issuer = django.db.models.ForeignKey(ServerCA, related_name = "revocations")

class ResourceHolderRevocation(Revocation):
    issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "revocations")

class EECertificate(Certificate):
    private_key = RSAPrivateKeyField()

    class Meta:
        abstract = True

    def avow(self):
        # pylint: disable=E1101
        if self.private_key is None:
            self.private_key = rpki.x509.RSA.generate(quiet = True)
        self.certificate = self.issuer.certify(
            subject_name      = self.subject_name,
            subject_key       = self.private_key.get_public(),
            validity_interval = ee_certificate_lifetime,
            is_ca             = False)

class ServerEE(EECertificate):
    issuer = django.db.models.ForeignKey(ServerCA, related_name = "ee_certificates")
    purpose = EnumField(choices = ("rpkid", "pubd", "irdbd", "irbe"))

    class Meta:
        unique_together = ("issuer", "purpose")

    @property
    def subject_name(self):
        return rpki.x509.X501DN.from_cn("%s BPKI %s EE" % (socket.gethostname(),
                                                           self.get_purpose_display()))

class Referral(EECertificate):
    issuer = django.db.models.OneToOneField(ResourceHolderCA, related_name = "referral_certificate")
    objects = ResourceHolderEEManager()

    @property
    def subject_name(self):
        return rpki.x509.X501DN.from_cn("%s BPKI Referral EE" % self.issuer.handle)

class Turtle(django.db.models.Model):
    service_uri = django.db.models.CharField(max_length = 255)

class Rootd(EECertificate, Turtle):
    issuer = django.db.models.OneToOneField(ResourceHolderCA, related_name = "rootd")
    objects = ResourceHolderEEManager()

    @property
    def subject_name(self):
        return rpki.x509.X501DN.from_cn("%s BPKI rootd EE" % self.issuer.handle)

class BSC(Certificate):
    issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "bscs")
    handle = HandleField()
    pkcs10 = PKCS10Field()

    def avow(self):
        # pylint: disable=E1101
        self.certificate = self.issuer.certify(
            subject_name      = self.pkcs10.getSubject(),
            subject_key       = self.pkcs10.getPublicKey(),
            validity_interval = ee_certificate_lifetime,
            is_ca             = False)

    def __unicode__(self):
        return self.handle

class ResourceSet(django.db.models.Model):
    valid_until = SundialField()

    class Meta:
        abstract = True

    def _select_resource_bag(self):
        return (), ()

    @property
    def resource_bag(self):
        raw_asn, raw_net = self._select_resource_bag()
        asns = rpki.resource_set.resource_set_as.from_django(
            (a.start_as, a.end_as) for a in raw_asn)
        ipv4 = rpki.resource_set.resource_set_ipv4.from_django(
            (a.start_ip, a.end_ip) for a in raw_net if a.version == "IPv4")
        ipv6 = rpki.resource_set.resource_set_ipv6.from_django(
            (a.start_ip, a.end_ip) for a in raw_net if a.version == "IPv6")
        return rpki.resource_set.resource_bag(
            valid_until = self.valid_until, asn = asns, v4 = ipv4, v6 = ipv6)

    # Writing of .setter method deferred until something needs it.

class ResourceSetASN(django.db.models.Model):
    start_as = django.db.models.BigIntegerField()
    end_as = django.db.models.BigIntegerField()

    class Meta:
        abstract = True

    def as_resource_range(self):
        return rpki.resource_set.resource_range_as(self.start_as, self.end_as)

class ResourceSetNet(django.db.models.Model):
    start_ip = django.db.models.CharField(max_length = 40)
    end_ip   = django.db.models.CharField(max_length = 40)
    version = EnumField(choices = ip_version_choices)

    class Meta:
        abstract = True

    def as_resource_range(self):
        return rpki.resource_set.resource_range_ip.from_strings(self.start_ip, self.end_ip)

class Child(CrossCertification, ResourceSet):
    issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "children")
    name = django.db.models.TextField(null = True, blank = True)

    def _select_resource_bag(self):
        child_asn = rpki.irdb.models.ChildASN.objects.raw("""
            SELECT *
            FROM irdb_childasn
            WHERE child_id = %s
            """, [self.id])
        child_net = list(rpki.irdb.models.ChildNet.objects.raw("""
            SELECT *
            FROM irdb_childnet
            WHERE child_id = %s
            """, [self.id]))
        return child_asn, child_net

    class Meta:
        unique_together = ("issuer", "handle")

class ChildASN(ResourceSetASN):
    child = django.db.models.ForeignKey(Child, related_name = "asns")

    class Meta:
        unique_together = ("child", "start_as", "end_as")

class ChildNet(ResourceSetNet):
    child = django.db.models.ForeignKey(Child, related_name = "address_ranges")

    class Meta:
        unique_together = ("child", "start_ip", "end_ip", "version")

class Parent(CrossCertification, Turtle):
    issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "parents")
    parent_handle = HandleField()
    child_handle  = HandleField()
    repository_type = EnumField(choices = ("none", "offer", "referral"))
    referrer = HandleField(null = True, blank = True)
    referral_authorization = SignedReferralField(null = True, blank = True)

    # This shouldn't be necessary
    class Meta:
        unique_together = ("issuer", "handle")

class Root(CrossCertification, Turtle):
    #
    # This is sort of a cross between a Rootd and a Parent with extra
    # fields for the root resources.  As with Parent, the private key
    # comes from a BSC rather than from a server EE cert as with
    # Rootd, so this looks looks to us like a cross certification (of
    # ourself).  We may want to revisit this.
    #
    issuer = django.db.models.OneToOneField(ResourceHolderCA, related_name = "root")
    asn_resources = django.db.models.TextField()
    ipv4_resources = django.db.models.TextField()
    ipv6_resources = django.db.models.TextField()

    class Meta:
        unique_together = ("issuer", "handle")

class ROARequest(django.db.models.Model):
    issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "roa_requests")
    asn = django.db.models.BigIntegerField()

    @property
    def roa_prefix_bag(self):
        prefixes = list(rpki.irdb.models.ROARequestPrefix.objects.raw("""
            SELECT *
            FROM irdb_roarequestprefix
            WHERE roa_request_id = %s
            """, [self.id]))
        v4 = rpki.resource_set.roa_prefix_set_ipv4.from_django(
            (p.prefix, p.prefixlen, p.max_prefixlen) for p in prefixes if p.version == "IPv4")
        v6 = rpki.resource_set.roa_prefix_set_ipv6.from_django(
            (p.prefix, p.prefixlen, p.max_prefixlen) for p in prefixes if p.version == "IPv6")
        return rpki.resource_set.roa_prefix_bag(v4 = v4, v6 = v6)

    # Writing of .setter method deferred until something needs it.

class ROARequestPrefix(django.db.models.Model):
    roa_request = django.db.models.ForeignKey(ROARequest, related_name = "prefixes")
    version = EnumField(choices = ip_version_choices)
    prefix = django.db.models.CharField(max_length = 40)
    prefixlen = django.db.models.PositiveSmallIntegerField()
    max_prefixlen = django.db.models.PositiveSmallIntegerField()

    def as_roa_prefix(self):
        if self.version == 'IPv4':
            return rpki.resource_set.roa_prefix_ipv4(rpki.POW.IPAddress(self.prefix), 
                                                     self.prefixlen, self.max_prefixlen)
        else:
            return rpki.resource_set.roa_prefix_ipv6(rpki.POW.IPAddress(self.prefix), 
                                                     self.prefixlen, self.max_prefixlen)

    def as_resource_range(self):
        return self.as_roa_prefix().to_resource_range()

    class Meta:
        unique_together = ("roa_request", "version", "prefix", "prefixlen", "max_prefixlen")

class GhostbusterRequest(django.db.models.Model):
    issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "ghostbuster_requests")
    parent = django.db.models.ForeignKey(Parent, related_name = "ghostbuster_requests", null = True)
    vcard = django.db.models.TextField()

class EECertificateRequest(ResourceSet):
    issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "ee_certificate_requests")
    pkcs10 = PKCS10Field()
    gski   = django.db.models.CharField(max_length = 27)
    cn     = django.db.models.CharField(max_length = 64)        # pylint: disable=C0103
    sn     = django.db.models.CharField(max_length = 64)        # pylint: disable=C0103
    eku    = django.db.models.TextField(null = True)

    def _select_resource_bag(self):
        ee_asn = rpki.irdb.models.EECertificateRequestASN.objects.raw("""
            SELECT *
            FROM irdb_eecertificaterequestasn
            WHERE ee_certificate_request_id = %s
            """, [self.id])
        ee_net = rpki.irdb.models.EECertificateRequestNet.objects.raw("""
            SELECT *
            FROM irdb_eecertificaterequestnet
            WHERE ee_certificate_request_id = %s
            """, [self.id])
        return ee_asn, ee_net

    class Meta:
        unique_together = ("issuer", "gski")

class EECertificateRequestASN(ResourceSetASN):
    ee_certificate_request = django.db.models.ForeignKey(EECertificateRequest, related_name = "asns")

    class Meta:
        unique_together = ("ee_certificate_request", "start_as", "end_as")

class EECertificateRequestNet(ResourceSetNet):
    ee_certificate_request = django.db.models.ForeignKey(EECertificateRequest, related_name = "address_ranges")

    class Meta:
        unique_together = ("ee_certificate_request", "start_ip", "end_ip", "version")

class Repository(CrossCertification):
    issuer = django.db.models.ForeignKey(ResourceHolderCA, related_name = "repositories")
    client_handle = HandleField()
    service_uri = django.db.models.CharField(max_length = 255)
    sia_base = django.db.models.TextField()
    rrdp_notification_uri = django.db.models.TextField(null = True)
    turtle = django.db.models.OneToOneField(Turtle, related_name = "repository")

    # This shouldn't be necessary
    class Meta:
        unique_together = ("issuer", "handle")

class Client(CrossCertification):
    issuer = django.db.models.ForeignKey(ServerCA, related_name = "clients")
    sia_base = django.db.models.TextField()

    # This shouldn't be necessary
    class Meta:
        unique_together = ("issuer", "handle")
