# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2009-2013  Internet Systems Consortium ("ISC")
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
Client implementation for the RPKI-RTR protocol (RFC 6810 et sequalia).
"""

import os
import sys
import time
import base64
import socket
import signal
import logging
import asyncore
import subprocess
import rpki.rpki_rtr.pdus
import rpki.rpki_rtr.channels

from rpki.rpki_rtr.pdus import ResetQueryPDU, SerialQueryPDU
from rpki.rpki_rtr.channels import Timestamp


class PDU(rpki.rpki_rtr.pdus.PDU):
  """
  Object representing a generic PDU in the rpki-router protocol.
  Real PDUs are subclasses of this class.
  """

  def consume(self, client):
    """
    Handle results in test client.  Default behavior is just to print
    out the PDU; data PDU subclasses may override this.
    """

    logging.debug(self)


clone_pdu = rpki.rpki_rtr.pdus.clone_pdu_root(PDU)


@clone_pdu
class SerialNotifyPDU(rpki.rpki_rtr.pdus.SerialNotifyPDU):
  """
  Serial Notify PDU.
  """

  def consume(self, client):
    """
    Respond to a SerialNotifyPDU with either a SerialQueryPDU or a
    ResetQueryPDU, depending on what we already know.
    """

    logging.debug(self)
    if client.current_serial is None or client.current_nonce != self.nonce:
      client.push_pdu(ResetQueryPDU(version = client.version))
    elif self.serial != client.current_serial:
      client.push_pdu(SerialQueryPDU(version = client.version,
                                     serial  = client.current_serial,
                                     nonce   = client.current_nonce))
    else:
      logging.debug("[Notify did not change serial number, ignoring]")


@clone_pdu
class CacheResponsePDU(rpki.rpki_rtr.pdus.CacheResponsePDU):
  """
  Cache Response PDU.
  """

  def consume(self, client):
    """
    Handle CacheResponsePDU.
    """

    logging.debug(self)
    if self.nonce != client.current_nonce:
      logging.debug("[Nonce changed, resetting]")
      client.cache_reset()

@clone_pdu
class EndOfDataPDUv0(rpki.rpki_rtr.pdus.EndOfDataPDUv0):
  """
  End of Data PDU, protocol version 0.
  """

  def consume(self, client):
    """
    Handle EndOfDataPDU response.
    """

    logging.debug(self)
    client.end_of_data(self.version, self.serial, self.nonce, self.refresh, self.retry, self.expire)

@clone_pdu
class EndOfDataPDUv1(rpki.rpki_rtr.pdus.EndOfDataPDUv1):
  """
  End of Data PDU, protocol version 1.
  """

  def consume(self, client):
    """
    Handle EndOfDataPDU response.
    """

    logging.debug(self)
    client.end_of_data(self.version, self.serial, self.nonce, self.refresh, self.retry, self.expire)


@clone_pdu
class CacheResetPDU(rpki.rpki_rtr.pdus.CacheResetPDU):
  """
  Cache reset PDU.
  """

  def consume(self, client):
    """
    Handle CacheResetPDU response, by issuing a ResetQueryPDU.
    """

    logging.debug(self)
    client.cache_reset()
    client.push_pdu(ResetQueryPDU(version = client.version))


class PrefixPDU(rpki.rpki_rtr.pdus.PrefixPDU):
  """
  Object representing one prefix.  This corresponds closely to one PDU
  in the rpki-router protocol, so closely that we use lexical ordering
  of the wire format of the PDU as the ordering for this class.

  This is a virtual class, but the .from_text() constructor
  instantiates the correct concrete subclass (IPv4PrefixPDU or
  IPv6PrefixPDU) depending on the syntax of its input text.
  """

  def consume(self, client):
    """
    Handle one incoming prefix PDU
    """

    logging.debug(self)
    client.consume_prefix(self)


@clone_pdu
class IPv4PrefixPDU(PrefixPDU, rpki.rpki_rtr.pdus.IPv4PrefixPDU):
  """
  IPv4 flavor of a prefix.
  """

  pass

@clone_pdu
class IPv6PrefixPDU(PrefixPDU, rpki.rpki_rtr.pdus.IPv6PrefixPDU):
  """
  IPv6 flavor of a prefix.
  """

  pass

@clone_pdu
class RouterKeyPDU(rpki.rpki_rtr.pdus.RouterKeyPDU):
  """
  Router Key PDU.
  """

  def consume(self, client):
    """
    Handle one incoming Router Key PDU
    """

    logging.debug(self)
    client.consume_routerkey(self)


class ClientChannel(rpki.rpki_rtr.channels.PDUChannel):
  """
  Client protocol engine, handles upcalls from PDUChannel.
  """

  current_serial = None
  current_nonce  = None
  sql            = None
  host           = None
  port           = None
  cache_id       = None

  # For initial test purposes, let's use the minimum allowed values
  # from the RFC 6810 bis I-D as the initial defaults for refresh and
  # retry, and the maximum allowed for expire; these will be overriden
  # as soon as we receive an EndOfDataPDU.
  #
  refresh =    120
  retry   =    120
  expire  = 172800

  def __init__(self, sock, proc, killsig, host, port):
    self.killsig = killsig
    self.proc = proc
    self.host = host
    self.port = port
    super(ClientChannel, self).__init__(sock = sock, root_pdu_class = PDU)
    self.start_new_pdu()

  @classmethod
  def ssh(cls, host, port):
    """
    Set up ssh connection and start listening for first PDU.
    """

    argv = ("ssh", "-p", port, "-s", host, "rpki-rtr")
    logging.debug("[Running ssh: %s]", " ".join(argv))
    s = socket.socketpair()
    return cls(sock = s[1],
               proc = subprocess.Popen(argv, executable = "/usr/bin/ssh",
                                       stdin = s[0], stdout = s[0], close_fds = True),
               killsig = signal.SIGKILL,
               host = host, port = port)

  @classmethod
  def tcp(cls, host, port):
    """
    Set up TCP connection and start listening for first PDU.
    """

    logging.debug("[Starting raw TCP connection to %s:%s]", host, port)
    try:
      addrinfo = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.error, e:
      logging.debug("[socket.getaddrinfo() failed: %s]", e)
    else:
      for ai in addrinfo:
        af, socktype, proto, cn, sa = ai                # pylint: disable=W0612
        logging.debug("[Trying addr %s port %s]", sa[0], sa[1])
        try:
          s = socket.socket(af, socktype, proto)
        except socket.error, e:
          logging.debug("[socket.socket() failed: %s]", e)
          continue
        try:
          s.connect(sa)
        except socket.error, e:
          logging.exception("[socket.connect() failed: %s]", e)
          s.close()
          continue
        return cls(sock = s, proc = None, killsig = None,
                   host = host, port = port)
    sys.exit(1)

  @classmethod
  def loopback(cls, host, port):
    """
    Set up loopback connection and start listening for first PDU.
    """

    s = socket.socketpair()
    logging.debug("[Using direct subprocess kludge for testing]")
    argv = (sys.executable, sys.argv[0], "server")
    return cls(sock = s[1],
               proc = subprocess.Popen(argv, stdin = s[0], stdout = s[0], close_fds = True),
               killsig = signal.SIGINT,
               host = host, port = port)

  @classmethod
  def tls(cls, host, port):
    """
    Set up TLS connection and start listening for first PDU.

    NB: This uses OpenSSL's "s_client" command, which does not
    check server certificates properly, so this is not suitable for
    production use.  Fixing this would be a trivial change, it just
    requires using a client program which does check certificates
    properly (eg, gnutls-cli, or stunnel's client mode if that works
    for such purposes this week).
    """

    argv = ("openssl", "s_client", "-tls1", "-quiet", "-connect", "%s:%s" % (host, port))
    logging.debug("[Running: %s]", " ".join(argv))
    s = socket.socketpair()
    return cls(sock = s[1],
               proc = subprocess.Popen(argv, stdin = s[0], stdout = s[0], close_fds = True),
               killsig = signal.SIGKILL,
               host = host, port = port)

  def setup_sql(self, sqlname):
    """
    Set up an SQLite database to contain the table we receive.  If
    necessary, we will create the database.
    """

    import sqlite3
    missing = not os.path.exists(sqlname)
    self.sql = sqlite3.connect(sqlname, detect_types = sqlite3.PARSE_DECLTYPES)
    self.sql.text_factory = str
    cur = self.sql.cursor()
    cur.execute("PRAGMA foreign_keys = on")
    if missing:
      cur.execute('''
        CREATE TABLE cache (
                cache_id        INTEGER PRIMARY KEY NOT NULL,
                host            TEXT NOT NULL,
                port            TEXT NOT NULL,
                version         INTEGER,
                nonce           INTEGER,
                serial          INTEGER,
                updated         INTEGER,
                refresh         INTEGER,
                retry           INTEGER,
                expire          INTEGER,
                UNIQUE          (host, port))''')
      cur.execute('''
        CREATE TABLE prefix (
                cache_id        INTEGER NOT NULL
                                REFERENCES cache(cache_id)
                                ON DELETE CASCADE
                                ON UPDATE CASCADE,
                asn             INTEGER NOT NULL,
                prefix          TEXT NOT NULL,
                prefixlen       INTEGER NOT NULL,
                max_prefixlen   INTEGER NOT NULL,
                UNIQUE          (cache_id, asn, prefix, prefixlen, max_prefixlen))''')

      cur.execute('''
        CREATE TABLE routerkey (
                cache_id        INTEGER NOT NULL
                                REFERENCES cache(cache_id)
                                ON DELETE CASCADE
                                ON UPDATE CASCADE,
                asn             INTEGER NOT NULL,
                ski             TEXT NOT NULL,
                key             TEXT NOT NULL,
                UNIQUE          (cache_id, asn, ski),
                UNIQUE          (cache_id, asn, key))''')

    cur.execute("SELECT cache_id, version, nonce, serial, refresh, retry, expire "
                "FROM cache WHERE host = ? AND port = ?",
                (self.host, self.port))
    try:
      self.cache_id, version, self.current_nonce, self.current_serial, refresh, retry, expire = cur.fetchone()
      if version is not None:
        self.version = version
      if refresh is not None:
        self.refresh = refresh
      if retry is not None:
        self.retry = retry
      if expire is not None:
        self.expire = expire
    except TypeError:
      cur.execute("INSERT INTO cache (host, port) VALUES (?, ?)", (self.host, self.port))
      self.cache_id = cur.lastrowid
    self.sql.commit()
    logging.info("[Session %d version %s nonce %s serial %s refresh %s retry %s expire %s]",
                 self.cache_id, self.version, self.current_nonce,
                 self.current_serial, self.refresh, self.retry, self.expire)

  def cache_reset(self):
    """
    Handle CacheResetPDU actions.
    """

    self.current_serial = None
    if self.sql:
      #
      # For some reason there was no commit here.  Dunno why.
      # See if adding one breaks anything....
      #
      cur = self.sql.cursor()
      cur.execute("DELETE FROM prefix WHERE cache_id = ?", (self.cache_id,))
      cur.execute("DELETE FROM routerkey WHERE cache_id = ?", (self.cache_id,))
      cur.execute("UPDATE cache SET version = ?, serial = NULL WHERE cache_id = ?", (self.version, self.cache_id))
      self.sql.commit()

  def end_of_data(self, version, serial, nonce, refresh, retry, expire):
    """
    Handle EndOfDataPDU actions.
    """

    assert version == self.version
    self.current_serial  = serial
    self.current_nonce   = nonce
    self.refresh         = refresh
    self.retry           = retry
    self.expire          = expire
    if self.sql:
      self.sql.execute("UPDATE cache SET"
                       " version = ?, serial = ?, nonce  = ?,"
                       " refresh = ?, retry  = ?, expire = ?,"
                       " updated = datetime('now') "
                       "WHERE cache_id = ?",
                       (version, serial, nonce, refresh, retry, expire, self.cache_id))
      self.sql.commit()

  def consume_prefix(self, prefix):
    """
    Handle one prefix PDU.
    """

    if self.sql:
      values = (self.cache_id, prefix.asn, str(prefix.prefix), prefix.prefixlen, prefix.max_prefixlen)
      if prefix.announce:
        self.sql.execute("INSERT INTO prefix (cache_id, asn, prefix, prefixlen, max_prefixlen) "
                         "VALUES (?, ?, ?, ?, ?)",
                         values)
      else:
        self.sql.execute("DELETE FROM prefix "
                         "WHERE cache_id = ? AND asn = ? AND prefix = ? AND prefixlen = ? AND max_prefixlen = ?",
                         values)

  def consume_routerkey(self, routerkey):
    """
    Handle one Router Key PDU.
    """

    if self.sql:
      values = (self.cache_id, routerkey.asn,
                base64.urlsafe_b64encode(routerkey.ski).rstrip("="),
                base64.b64encode(routerkey.key))
      if routerkey.announce:
        self.sql.execute("INSERT INTO routerkey (cache_id, asn, ski, key) "
                         "VALUES (?, ?, ?, ?)",
                         values)
      else:
        self.sql.execute("DELETE FROM routerkey "
                         "WHERE cache_id = ? AND asn = ? AND (ski = ? OR key = ?)",
                         values)

  def deliver_pdu(self, pdu):
    """
    Handle received PDU.
    """

    pdu.consume(self)

  def push_pdu(self, pdu):
    """
    Log outbound PDU then write it to stream.
    """

    logging.debug(pdu)
    super(ClientChannel, self).push_pdu(pdu)

  def cleanup(self):
    """
    Force clean up this client's child process.  If everything goes
    well, child will have exited already before this method is called,
    but we may need to whack it with a stick if something breaks.
    """

    if self.proc is not None and self.proc.returncode is None:
      try:
        os.kill(self.proc.pid, self.killsig)
      except OSError:
        pass

  def handle_close(self):
    """
    Intercept close event so we can log it, then shut down.
    """

    logging.debug("Server closed channel")
    super(ClientChannel, self).handle_close()


def client_main(args):
  """
  Toy client, intended only for debugging.

  This program takes one or more arguments.  The first argument
  determines what kind of connection it should open to the server, the
  remaining arguments are connection details specific to this
  particular type of connection.

  If the first argument is "loopback", the client will run a copy of
  the server directly in a subprocess, and communicate with it via a
  PF_UNIX socket pair.  This sub-mode takes no further arguments.

  If the first argument is "ssh", the client will attempt to run ssh
  in as subprocess to connect to the server using the ssh subsystem
  mechanism as specified for this protocol.  The remaining arguments
  should be a hostname (or IP address in a form acceptable to ssh) and
  a TCP port number.

  If the first argument is "tcp", the client will attempt to open a
  direct (and completely insecure!) TCP connection to the server.
  The remaining arguments should be a hostname (or IP address) and
  a TCP port number.

  If the first argument is "tls", the client will attempt to open a
  TLS connection to the server.  The remaining arguments should be a
  hostname (or IP address) and a TCP port number.

  An optional final name is the name of a file containing a SQLite
  database in which to store the received table.  If specified, this
  database will be created if missing.
  """

  logging.debug("[Startup]")

  constructor = getattr(rpki.rpki_rtr.client.ClientChannel, args.protocol)

  client = None
  try:
    client = constructor(args.host, args.port)
    if args.sql_database:
      client.setup_sql(args.sql_database)
    while True:
      if client.current_serial is None or client.current_nonce is None:
        client.push_pdu(ResetQueryPDU(version = client.version))
      else:
        client.push_pdu(SerialQueryPDU(version = client.version,
                                       serial  = client.current_serial,
                                       nonce   = client.current_nonce))
      polled = Timestamp.now()
      wakeup = None
      while True:
        if wakeup != polled + client.refresh:
          wakeup = Timestamp(polled + client.refresh)
          logging.info("[Last client poll %s, next %s]", polled, wakeup)
        remaining = wakeup - time.time()
        if remaining < 0:
          break
        asyncore.loop(timeout = remaining, count = 1)

  except KeyboardInterrupt:
    sys.exit(0)
  finally:
    if client is not None:
      client.cleanup()


def argparse_setup(subparsers):
  """
  Set up argparse stuff for commands in this module.
  """

  subparser = subparsers.add_parser("client", description = client_main.__doc__,
                                    help = "Test client for RPKI-RTR protocol")
  subparser.set_defaults(func = client_main, default_log_to = "stderr")
  subparser.add_argument("--sql-database", help = "filename for sqlite3 database of client state")
  subparser.add_argument("protocol", choices = ("loopback", "tcp", "ssh", "tls"), help = "connection protocol")
  subparser.add_argument("host", nargs = "?", help = "server host")
  subparser.add_argument("port", nargs = "?", help = "server port")
