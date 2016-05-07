# $Id$
#
# Copyright (C) 2015-2016  Parsons Government Services ("PARSONS")
# Portions copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009-2013  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND PARSONS, DRL, AND ISC DISCLAIM
# ALL WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL
# PARSONS, DRL, OR ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
# OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION
# WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

"""
PDU classes for the RPKI-RTR protocol (RFC 6810 et sequalia).
"""

import struct
import base64
import logging
import rpki.POW

# Exceptions

class PDUException(Exception):
    """
    Parent exception type for exceptions that signal particular protocol
    errors.  String value of exception instance will be the message to
    put in the ErrorReportPDU, error_report_code value of exception
    will be the numeric code to use.
    """

    def __init__(self, msg = None, pdu = None):
        super(PDUException, self).__init__()
        assert msg is None or isinstance(msg, (str, unicode))
        self.error_report_msg = msg
        self.error_report_pdu = pdu

    def __str__(self):
        return self.error_report_msg or self.__class__.__name__

    def make_error_report(self, version):
        return ErrorReportPDU(version = version,
                              errno   = self.error_report_code,
                              errmsg  = self.error_report_msg,
                              errpdu  = self.error_report_pdu)

class UnsupportedProtocolVersion(PDUException):
    error_report_code = 4

class UnsupportedPDUType(PDUException):
    error_report_code = 5

class CorruptData(PDUException):
    error_report_code = 0

# Decorators

def wire_pdu(cls, versions = None):
    """
    Class decorator to add a PDU class to the set of known PDUs
    for all supported protocol versions.
    """

    for v in PDU.version_map.iterkeys() if versions is None else versions:
        assert cls.pdu_type not in PDU.version_map[v]
        PDU.version_map[v][cls.pdu_type] = cls
    return cls


def wire_pdu_only(*versions):
    """
    Class decorator to add a PDU class to the set of known PDUs
    for specific protocol versions.
    """

    assert versions and all(v in PDU.version_map for v in versions)
    return lambda cls: wire_pdu(cls, versions)

def clone_pdu_root(root_pdu_class):
    """
    Replace a PDU root class's version_map with a two-level deep copy of itself,
    and return a class decorator which subclasses can use to replace their
    parent classes with themselves in the resulting cloned version map.

    This function is not itself a decorator, it returns one.
    """

    root_pdu_class.version_map = dict((k, v.copy()) for k, v in root_pdu_class.version_map.iteritems())

    def decorator(cls):
        for pdu_map in root_pdu_class.version_map.itervalues():
            for pdu_type, pdu_class in pdu_map.items():
                if pdu_class in cls.__bases__:
                    pdu_map[pdu_type] = cls
        return cls

    return decorator


# PDUs

class PDU(object):
    """
    Base PDU.  Real PDUs are subclasses of this class.
    """

    version_map = {0 : {}, 1 : {}}        # Updated by @wire_pdu

    _pdu = None                           # Cached when first generated

    header_struct = struct.Struct("!BB2xL")

    pdu_type = None

    def __init__(self, version):
        assert version in self.version_map
        self.version = version

    def __cmp__(self, other):
        return cmp(self.to_pdu(), other.to_pdu())

    def to_pdu(self, announce = None):
        return NotImplementedError

    @property
    def default_version(self):
        return max(self.version_map.iterkeys())

    def check(self):
        pass

    @classmethod
    def read_pdu(cls, reader):
        return reader.update(need = cls.header_struct.size, callback = cls.got_header)

    @classmethod
    def got_header(cls, reader):
        if not reader.ready():
            return None
        assert reader.available() >= cls.header_struct.size
        version, pdu_type, length = cls.header_struct.unpack(reader.buffer[:cls.header_struct.size])
        reader.check_version(version)
        if pdu_type not in cls.version_map[version]:
            raise UnsupportedPDUType(
                "Received unsupported PDU type %d" % pdu_type)
        if length < 8:
            raise CorruptData(
                "Received PDU with length %d, which is too short to be valid" % length)
        self = cls.version_map[version][pdu_type](version = version)
        return reader.update(need = length, callback = self.got_pdu)


class PDUWithSerial(PDU):
    """
    Base class for PDUs consisting of just a serial number and nonce.
    """

    header_struct = struct.Struct("!BBHLL")

    def __init__(self, version, serial = None, nonce = None):
        super(PDUWithSerial, self).__init__(version)
        if serial is not None:
            assert isinstance(serial, int)
            self.serial = serial
        if nonce is not None:
            assert isinstance(nonce, int)
            self.nonce = nonce

    def __str__(self):
        return "[%s, serial #%d nonce %d]" % (self.__class__.__name__, self.serial, self.nonce)

    def to_pdu(self, announce = None):
        """
        Generate the wire format PDU.
        """

        assert announce is None
        if self._pdu is None:
            self._pdu = self.header_struct.pack(self.version, self.pdu_type, self.nonce,
                                                self.header_struct.size, self.serial)
        return self._pdu

    def got_pdu(self, reader):
        if not reader.ready():
            return None
        b = reader.get(self.header_struct.size)
        version, pdu_type, self.nonce, length, self.serial = self.header_struct.unpack(b)
        assert version == self.version and pdu_type == self.pdu_type
        if length != 12:
            raise CorruptData("PDU length of %d can't be right" % length, pdu = self)
        assert b == self.to_pdu()
        return self


class PDUWithNonce(PDU):
    """
    Base class for PDUs consisting of just a nonce.
    """

    header_struct = struct.Struct("!BBHL")

    def __init__(self, version, nonce = None):
        super(PDUWithNonce, self).__init__(version)
        if nonce is not None:
            assert isinstance(nonce, int)
            self.nonce = nonce

    def __str__(self):
        return "[%s, nonce %d]" % (self.__class__.__name__, self.nonce)

    def to_pdu(self, announce = None):
        """
        Generate the wire format PDU.
        """

        assert announce is None
        if self._pdu is None:
            self._pdu = self.header_struct.pack(self.version, self.pdu_type, self.nonce, self.header_struct.size)
        return self._pdu

    def got_pdu(self, reader):
        if not reader.ready():
            return None
        b = reader.get(self.header_struct.size)
        version, pdu_type, self.nonce, length = self.header_struct.unpack(b)
        assert version == self.version and pdu_type == self.pdu_type
        if length != 8:
            raise CorruptData("PDU length of %d can't be right" % length, pdu = self)
        assert b == self.to_pdu()
        return self


class PDUEmpty(PDU):
    """
    Base class for empty PDUs.
    """

    header_struct = struct.Struct("!BBHL")

    def __str__(self):
        return "[%s]" % self.__class__.__name__

    def to_pdu(self, announce = None):
        """
        Generate the wire format PDU for this prefix.
        """

        assert announce is None
        if self._pdu is None:
            self._pdu = self.header_struct.pack(self.version, self.pdu_type, 0, self.header_struct.size)
        return self._pdu

    def got_pdu(self, reader):
        if not reader.ready():
            return None
        b = reader.get(self.header_struct.size)
        version, pdu_type, zero, length = self.header_struct.unpack(b)
        assert version == self.version and pdu_type == self.pdu_type
        if zero != 0:
            raise CorruptData("Must-be-zero field isn't zero" % length, pdu = self)
        if length != 8:
            raise CorruptData("PDU length of %d can't be right" % length, pdu = self)
        assert b == self.to_pdu()
        return self

@wire_pdu
class SerialNotifyPDU(PDUWithSerial):
    """
    Serial Notify PDU.
    """

    pdu_type = 0


@wire_pdu
class SerialQueryPDU(PDUWithSerial):
    """
    Serial Query PDU.
    """

    pdu_type = 1

    def __init__(self, version, serial = None, nonce = None):
        super(SerialQueryPDU, self).__init__(self.default_version if version is None else version, serial, nonce)


@wire_pdu
class ResetQueryPDU(PDUEmpty):
    """
    Reset Query PDU.
    """

    pdu_type = 2

    def __init__(self, version):
        super(ResetQueryPDU, self).__init__(self.default_version if version is None else version)


@wire_pdu
class CacheResponsePDU(PDUWithNonce):
    """
    Cache Response PDU.
    """

    pdu_type = 3


def EndOfDataPDU(version, *args, **kwargs):
    """
    Factory for the EndOfDataPDU classes, which take different forms in
    different protocol versions.
    """

    if version == 0:
        return EndOfDataPDUv0(version, *args, **kwargs)
    if version == 1:
        return EndOfDataPDUv1(version, *args, **kwargs)
    raise NotImplementedError


# Min, max, and default values, from the current RFC 6810 bis I-D.
# Putting these here lets us keep them all in one place, and use them
# in our client API for both protocol versions even though they can
# only be set in the protocol in version 1.

default_refresh = 3600

def valid_refresh(refresh):
    if not isinstance(refresh, int) or refresh < 120 or refresh > 86400:
        raise ValueError
    return refresh

default_retry = 600

def valid_retry(retry):
    if not isinstance(retry, int) or retry < 120 or retry > 7200:
        raise ValueError
    return retry

default_expire = 7200

def valid_expire(expire):
    if not isinstance(expire, int) or expire < 600 or expire > 172800:
        raise ValueError
    return expire


@wire_pdu_only(0)
class EndOfDataPDUv0(PDUWithSerial):
    """
    End of Data PDU, protocol version 0.
    """

    pdu_type = 7

    def __init__(self, version, serial = None, nonce = None, refresh = None, retry = None, expire = None):
        super(EndOfDataPDUv0, self).__init__(version, serial, nonce)
        self.refresh = valid_refresh(default_refresh if refresh is None else refresh)
        self.retry   = valid_retry(  default_retry   if retry   is None else retry)
        self.expire  = valid_expire( default_expire  if expire  is None else expire)


@wire_pdu_only(1)
class EndOfDataPDUv1(EndOfDataPDUv0):
    """
    End of Data PDU, protocol version 1.
    """

    header_struct = struct.Struct("!BBHLLLLL")

    def __str__(self):
        return "[%s, serial #%d nonce %d refresh %d retry %d expire %d]" % (
            self.__class__.__name__, self.serial, self.nonce, self.refresh, self.retry, self.expire)

    def to_pdu(self, announce = None):
        """
        Generate the wire format PDU.
        """

        assert announce is None
        if self._pdu is None:
            self._pdu = self.header_struct.pack(self.version, self.pdu_type, self.nonce,
                                                self.header_struct.size, self.serial,
                                                self.refresh, self.retry, self.expire)
        return self._pdu

    def got_pdu(self, reader):
        if not reader.ready():
            return None
        b = reader.get(self.header_struct.size)
        version, pdu_type, self.nonce, length, self.serial, self.refresh, self.retry, self.expire \
                 = self.header_struct.unpack(b)
        assert version == self.version and pdu_type == self.pdu_type
        if length != 24:
            raise CorruptData("PDU length of %d can't be right" % length, pdu = self)
        assert b == self.to_pdu()
        return self


@wire_pdu
class CacheResetPDU(PDUEmpty):
    """
    Cache reset PDU.
    """

    pdu_type = 8


class PrefixPDU(PDU):
    """
    Object representing one prefix.  This corresponds closely to one PDU
    in the rpki-router protocol, so closely that we use lexical ordering
    of the wire format of the PDU as the ordering for this class.

    This is a virtual class, but the .from_text() constructor
    instantiates the correct concrete subclass (IPv4PrefixPDU or
    IPv6PrefixPDU) depending on the syntax of its input text.
    """

    header_struct = struct.Struct("!BB2xLBBBx")
    asnum_struct = struct.Struct("!L")
    address_byte_count = 0

    def __init__(self, version):
        super(PrefixPDU, self).__init__(version)
        self.asn = None
        self.prefix = None
        self.prefixlen = None
        self.max_prefixlen = None
        self.announce = None

    def __str__(self):
        plm = "%s/%s-%s" % (self.prefix, self.prefixlen, self.max_prefixlen)
        return "%s %8s  %-32s %s" % ("+" if self.announce else "-", self.asn, plm,
                                     ":".join(("%02X" % ord(b) for b in self.to_pdu())))

    def show(self):
        logging.debug("# Class:        %s", self.__class__.__name__)
        logging.debug("# ASN:          %s", self.asn)
        logging.debug("# Prefix:       %s", self.prefix)
        logging.debug("# Prefixlen:    %s", self.prefixlen)
        logging.debug("# MaxPrefixlen: %s", self.max_prefixlen)
        logging.debug("# Announce:     %s", self.announce)

    def check(self):
        """
        Check attributes to make sure they're within range.
        """

        if self.announce not in (0, 1):
            raise CorruptData("Announce value %d is neither zero nor one" % self.announce, pdu = self)
        if self.prefix.bits != self.address_byte_count * 8:
            raise CorruptData("IP address length %d does not match expectation" % self.prefix.bits, pdu = self)
        if self.prefixlen < 0 or self.prefixlen > self.prefix.bits:
            raise CorruptData("Implausible prefix length %d" % self.prefixlen, pdu = self)
        if self.max_prefixlen < self.prefixlen or self.max_prefixlen > self.prefix.bits:
            raise CorruptData("Implausible max prefix length %d" % self.max_prefixlen, pdu = self)
        pdulen = self.header_struct.size + self.prefix.bits/8 + self.asnum_struct.size
        if len(self.to_pdu()) != pdulen:
            raise CorruptData("Expected %d byte PDU, got %d" % (pdulen, len(self.to_pdu())), pdu = self)

    def to_pdu(self, announce = None):
        """
        Generate the wire format PDU for this prefix.
        """

        if announce is not None:
            assert announce in (0, 1)
        elif self._pdu is not None:
            return self._pdu
        pdulen = self.header_struct.size + self.prefix.bits/8 + self.asnum_struct.size
        pdu = (self.header_struct.pack(self.version, self.pdu_type, pdulen,
                                       announce if announce is not None else self.announce,
                                       self.prefixlen, self.max_prefixlen) +
               self.prefix.toBytes() +
               self.asnum_struct.pack(self.asn))
        if announce is None:
            assert self._pdu is None
            self._pdu = pdu
        return pdu

    def got_pdu(self, reader):
        if not reader.ready():
            return None
        b1 = reader.get(self.header_struct.size)
        b2 = reader.get(self.address_byte_count)
        b3 = reader.get(self.asnum_struct.size)
        version, pdu_type, length, self.announce, self.prefixlen, self.max_prefixlen = self.header_struct.unpack(b1)
        assert version == self.version and pdu_type == self.pdu_type
        if length != len(b1) + len(b2) + len(b3):
            raise CorruptData("Got PDU length %d, expected %d" % (length, len(b1) + len(b2) + len(b3)), pdu = self)
        self.prefix = rpki.POW.IPAddress.fromBytes(b2)
        self.asn = self.asnum_struct.unpack(b3)[0]
        assert b1 + b2 + b3 == self.to_pdu()
        return self


@wire_pdu
class IPv4PrefixPDU(PrefixPDU):
    """
    IPv4 flavor of a prefix.
    """

    pdu_type = 4
    address_byte_count = 4

@wire_pdu
class IPv6PrefixPDU(PrefixPDU):
    """
    IPv6 flavor of a prefix.
    """

    pdu_type = 6
    address_byte_count = 16

@wire_pdu_only(1)
class RouterKeyPDU(PDU):
    """
    Router Key PDU.
    """

    pdu_type = 9

    header_struct = struct.Struct("!BBBxL20sL")

    def __init__(self, version):
        super(RouterKeyPDU, self).__init__(version)
        self.announce = None
        self.ski = None
        self.asn = None
        self.key = None

    def __str__(self):
        return "%s %8s  %-32s %s" % ("+" if self.announce else "-", self.asn,
                                     base64.urlsafe_b64encode(self.ski).rstrip("="),
                                     ":".join(("%02X" % ord(b) for b in self.to_pdu())))

    def check(self):
        """
        Check attributes to make sure they're within range.
        """

        if self.announce not in (0, 1):
            raise CorruptData("Announce value %d is neither zero nor one" % self.announce, pdu = self)
        if len(self.ski) != 20:
            raise CorruptData("Implausible SKI length %d" % len(self.ski), pdu = self)
        pdulen = self.header_struct.size + len(self.key)
        if len(self.to_pdu()) != pdulen:
            raise CorruptData("Expected %d byte PDU, got %d" % (pdulen, len(self.to_pdu())), pdu = self)

    def to_pdu(self, announce = None):
        if announce is not None:
            assert announce in (0, 1)
        elif self._pdu is not None:
            return self._pdu
        pdulen = self.header_struct.size + len(self.key)
        pdu = (self.header_struct.pack(self.version,
                                       self.pdu_type,
                                       announce if announce is not None else self.announce,
                                       pdulen,
                                       self.ski,
                                       self.asn)
               + self.key)
        if announce is None:
            assert self._pdu is None
            self._pdu = pdu
        return pdu

    def got_pdu(self, reader):
        if not reader.ready():
            return None
        header = reader.get(self.header_struct.size)
        version, pdu_type, self.announce, length, self.ski, self.asn = self.header_struct.unpack(header)
        assert version == self.version and pdu_type == self.pdu_type
        remaining = length - self.header_struct.size
        if remaining <= 0:
            raise CorruptData("Got PDU length %d, minimum is %d" % (length, self.header_struct.size + 1), pdu = self)
        self.key = reader.get(remaining)
        assert header + self.key == self.to_pdu()
        return self


@wire_pdu
class ErrorReportPDU(PDU):
    """
    Error Report PDU.
    """

    pdu_type = 10

    header_struct = struct.Struct("!BBHL")
    string_struct = struct.Struct("!L")

    errors = {
        2 : "No Data Available" }

    fatal = {
        0 : "Corrupt Data",
        1 : "Internal Error",
        3 : "Invalid Request",
        4 : "Unsupported Protocol Version",
        5 : "Unsupported PDU Type",
        6 : "Withdrawal of Unknown Record",
        7 : "Duplicate Announcement Received" }

    assert set(errors) & set(fatal) == set()

    errors.update(fatal)

    codes = dict((v, k) for k, v in errors.items())

    def __init__(self, version, errno = None, errpdu = None, errmsg = None):
        super(ErrorReportPDU, self).__init__(version)
        assert errno is None or errno in self.errors
        self.errno = errno
        self.errpdu = errpdu
        self.errmsg = errmsg if errmsg is not None or errno is None else self.errors[errno]
        self.pdulen = None
        self.errlen = None

    def __str__(self):
        return "[%s, error #%s: %r]" % (self.__class__.__name__, self.errno, self.errmsg)

    def to_counted_string(self, s):
        return self.string_struct.pack(len(s)) + s

    def read_counted_string(self, reader, remaining):
        assert remaining >= self.string_struct.size
        n = self.string_struct.unpack(reader.get(self.string_struct.size))[0]
        assert remaining >= self.string_struct.size + n
        return n, reader.get(n), (remaining - self.string_struct.size - n)

    def to_pdu(self, announce = None):
        """
        Generate the wire format PDU for this error report.
        """

        assert announce is None
        if self._pdu is None:
            assert isinstance(self.errno, int)
            assert not isinstance(self.errpdu, ErrorReportPDU)
            p = self.errpdu
            if p is None:
                p = ""
            elif isinstance(p, PDU):
                p = p.to_pdu()
            assert isinstance(p, str)
            pdulen = self.header_struct.size + self.string_struct.size * 2 + len(p) + len(self.errmsg)
            self._pdu = self.header_struct.pack(self.version, self.pdu_type, self.errno, pdulen)
            self._pdu += self.to_counted_string(p)
            self._pdu += self.to_counted_string(self.errmsg.encode("utf8"))
        return self._pdu

    def got_pdu(self, reader):
        if not reader.ready():
            return None
        header = reader.get(self.header_struct.size)
        version, pdu_type, self.errno, length = self.header_struct.unpack(header)
        assert version == self.version and pdu_type == self.pdu_type
        remaining = length - self.header_struct.size
        self.pdulen, self.errpdu, remaining = self.read_counted_string(reader, remaining)
        self.errlen, self.errmsg, remaining = self.read_counted_string(reader, remaining)
        if length != self.header_struct.size + self.string_struct.size * 2 + self.pdulen + self.errlen:
            raise CorruptData("Got PDU length %d, expected %d" % (
                length, self.header_struct.size + self.string_struct.size * 2 + self.pdulen + self.errlen))
        assert (header
                + self.to_counted_string(self.errpdu)
                + self.to_counted_string(self.errmsg.encode("utf8"))
                == self.to_pdu())
        return self
