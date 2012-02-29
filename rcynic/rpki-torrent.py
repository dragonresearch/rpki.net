#!/usr/local/bin/python

"""
$Id$

Copyright (C) 2012 Internet Systems Consortium, Inc. ("ISC")

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
"""

import urllib2
import httplib
import socket
import ssl
import urlparse
import zipfile
import sys
import os
import email.utils
import datetime
import base64
import hashlib
import subprocess
import syslog
import traceback
import ConfigParser

import transmissionrpc


tr_env_vars = ("TR_APP_VERSION", "TR_TIME_LOCALTIME", "TR_TORRENT_DIR",
               "TR_TORRENT_ID", "TR_TORRENT_HASH", "TR_TORRENT_NAME")


class WrongServer(Exception):
  "Hostname not in X.509v3 subjectAltName extension."

class UnexpectedRedirect(Exception):
  "Unexpected HTTP redirect."

class WrongMode(Exception):
  "Wrong operation for mode."

class BadFormat(Exception):
  "Zip file does not match our expectations."

class InconsistentEnvironment(Exception):
  "Environment variables received from Transmission aren't consistent."

class TorrentNotReady(Exception):
  "Torrent is not ready for checking."

class TorrentDoesNotMatchManifest(Exception):
  "Retrieved torrent does not match manifest."

class TorrentNameDoesNotMatchURL(Exception):
  "Torrent name doesn't uniquely match a URL."

def main():
  try:
    syslog_flags = syslog.LOG_PID;
    if os.isatty(sys.stderr.fileno()):
      syslog_flags |= syslog.LOG_PERROR
    syslog.openlog("rpki-torrent", syslog_flags)
    global cfg
    cfg = MyConfigParser()
    cfg.read([os.path.join(dn, fn)
              for fn in ("rcynic.conf", "rpki.conf")
              for dn in ("/var/rcynic/etc", "/usr/local/etc", "/etc")])
    if all(v in os.environ for v in tr_env_vars):
      torrent_completion_main()
    elif not any(v in os.environ for v in tr_env_vars):
      cronjob_main()
    else:
      raise InconsistentEnvironment
  except Exception, e:
    for line in traceback.format_exc().splitlines():
      syslog.syslog(line)
    sys.exit(1)


def cronjob_main():
  for zip_url in cfg.zip_urls:

    z = ZipFile(url = zip_url, dir = cfg.zip_dir, ta  = cfg.zip_ta)
    client = transmissionrpc.client.Client()

    if z.fetch():
      remove_torrents(client, z.torrent_name)
      syslog.syslog("Adding torrent %s" % z.torrent_name)
      client.add(z.get_torrent())

    elif cfg.run_rcynic_anyway:
      run_rcynic(client, z)


def torrent_completion_main():
  torrent_name = os.getenv("TR_TORRENT_NAME")
  torrent_id = int(os.getenv("TR_TORRENT_ID"))

  z = ZipFile(url = cfg.find_url(torrent_name), dir = cfg.zip_dir, ta = cfg.zip_ta)
  client = transmissionrpc.client.Client()
  torrent = client.info([torrent_id]).popitem()[1]

  if torrent.name != torrent_name:
    raise InconsistentEnvironment("Torrent name %s does not match ID %d" % (torrent_name, torrent_id))

  if z.torrent_name != torrent_name:
    raise InconsistentEnvironment("Torrent name %s does not match torrent name in zip file %s" % (torrent_name, z.torrent_name))

  if torrent is None or torrent.progress != 100:
    raise TorrentNotReady("Torrent %s not ready for checking, how did I get here?" % torrent_name)

  run_rcynic(client, z)


def run_rcynic(client, z):
  """
  Run rcynic and any post-processing we might want.
  """

  syslog.syslog("Checking manifest against disk")

  download_dir = client.get_session().download_dir

  manifest_from_disk = create_manifest(download_dir, z.torrent_name)
  manifest_from_zip = z.get_manifest()

  excess_files = set(manifest_from_disk) - set(manifest_from_zip)
  for fn in excess_files:
    del manifest_from_disk[fn]

  if manifest_from_disk != manifest_from_zip:
    raise TorrentDoesNotMatchManifest("Manifest for torrent %s does not match what we got" %
                                      z.torrent_name)

  if excess_files:
    syslog.syslog("Cleaning up excess files")
  for fn in excess_files:
    os.unlink(os.path.join(download_dir, fn))

  syslog.syslog("Running rcynic")
  subprocess.check_call((cfg.rcynic_prog,
                         "-c", cfg.rcynic_conf,
                         "-u", os.path.join(client.get_session().download_dir, z.torrent_name)))

  for cmd in cfg.post_rcynic_commands:
    syslog.syslog("Running post-rcynic command: %s" % cmd)
    subprocess.check_call(cmd, shell = True)


# See http://www.minstrel.org.uk/papers/sftp/ for details on how to
# set up safe upload-only SFTP directories on the server.  In
# particular http://www.minstrel.org.uk/papers/sftp/builtin/ is likely
# to be the right path.


class ZipFile(object):
  """
  Augmented version of standard python zipfile.ZipFile class, with
  some extra methods and specialized capabilities.

  All methods of the standard zipfile.ZipFile class are supported, but
  the constructor arguments are different, and opening the zip file
  itself is deferred until a call which requires this, since the file
  may first need to be fetched via HTTPS.
  """

  def __init__(self, url, dir, ta, verbose = True, mode = "r"):
    self.url = url
    self.dir = dir
    self.ta = ta
    self.verbose = verbose
    self.mode = mode
    self.filename = os.path.join(dir, os.path.basename(url))
    self.changed = False
    self.zf = None
    self.peercert = None
    self.torrent_name, zip_ext = os.path.splitext(os.path.basename(url))
    if zip_ext != ".zip":
      raise BadFormat


  def __getattr__(self, name):
    if self.zf is None:
      self.zf = zipfile.ZipFile(self.filename, mode = self.mode,
                                compression = zipfile.ZIP_DEFLATED)
    return getattr(self.zf, name)


  def build_opener(self):
    """
    Voodoo to create a urllib2.OpenerDirector object with TLS
    certificate checking enabled and a hook to set self.peercert so
    our caller can check the subjectAltName field.

    You probably don't want to look at this if you can avoid it.
    """

    # Yes, we're constructing one-off classes.  Look away, look away.

    class HTTPSConnection(httplib.HTTPSConnection):
      zip = self
      def connect(self):
        sock = socket.create_connection((self.host, self.port), self.timeout)
        if getattr(self, "_tunnel_host", None):
          self.sock = sock
          self._tunnel()
        self.sock = ssl.wrap_socket(sock,
                                    keyfile = self.key_file,
                                    certfile = self.cert_file,
                                    cert_reqs = ssl.CERT_REQUIRED,
                                    ssl_version = ssl.PROTOCOL_TLSv1,
                                    ca_certs = self.zip.ta)
        self.zip.peercert = self.sock.getpeercert()

    class HTTPSHandler(urllib2.HTTPSHandler):
      def https_open(self, req):
        return self.do_open(HTTPSConnection, req)

    return urllib2.build_opener(HTTPSHandler)


  def check_subjectAltNames(self):
    """
    Check self.peercert against URL to make sure we were talking to
    the right HTTPS server.
    """

    hostname = urlparse.urlparse(self.url).hostname
    subjectAltNames = set(i[1]
                          for i in self.peercert.get("subjectAltName", ())
                          if i[0] == "DNS")
    if hostname not in subjectAltNames:
      raise WrongServer


  def download_file(self, r, bufsize = 4096):
    """
    Downloaded file to disk.
    """

    tempname = self.filename + ".new"
    f = open(tempname, "wb")
    n = int(r.info()["Content-Length"])
    for i in xrange(0, n - bufsize, bufsize):
      f.write(r.read(bufsize))
    f.write(r.read())
    f.close()
    mtime = email.utils.mktime_tz(email.utils.parsedate_tz(r.info()["Last-Modified"]))
    os.utime(tempname, (mtime, mtime))
    os.rename(tempname, self.filename)


  def fetch(self):
    """
    Fetch zip file from URL given to constructor.
    This only works in read mode, makes no sense in write mode.
    """

    if self.mode != "r":
      raise WrongMode

    headers = { "User-Agent" : "rpki-torrent" }
    try:
      headers["If-Modified-Since"] = email.utils.formatdate(
        os.path.getmtime(self.filename), False, True)
    except OSError:
      pass

    syslog.syslog("Checking %s..." % self.url)
    try:
      r = self.build_opener().open(urllib2.Request(self.url, None, headers))
      syslog.syslog("%s has changed, starting download" % self.url)
      self.changed = True
    except urllib2.HTTPError, e:
      if e.code != 304:
        raise
      r = None
      syslog.syslog("%s has not changed" % self.url)

    self.check_subjectAltNames()

    if r is not None and r.geturl() != self.url:
      raise UnexpectedRedirect

    if r is not None:
      self.download_file(r)
      r.close()

    return self.changed


  def check_format(self):
    """
    Make sure that format of zip file matches our preconceptions: it
    should contain two files, one of which is the .torrent file, the
    other is the manifest, with names derived from the torrent name
    inferred from the URL.
    """

    if set(self.namelist()) != set((self.torrent_name + ".torrent", self.torrent_name + ".manifest")):
      raise BadFormat


  def get_torrent(self):
    """
    Extract torrent file from zip file, encoded in Base64 because
    that's what the transmisionrpc library says it wants.
    """

    self.check_format()
    return base64.b64encode(self.read(self.torrent_name + ".torrent"))


  def get_manifest(self):
    """
    Extract manifest from zip file, as a dictionary.

    For the moment we're fixing up the internal file names from the
    format that the existing shell-script prototype uses, but this
    should go away once this program both generates and checks the
    manifests.
    """

    self.check_format()
    result = {}
    for line in self.open(self.torrent_name + ".manifest"):
      h, fn = line.split()
      #
      # Fixup for earlier manifest format, this should go away
      if not fn.startswith(self.torrent_name):
        fn = os.path.normpath(os.path.join(self.torrent_name, fn))
      #
      result[fn] = h
    return result


def create_manifest(topdir, torrent_name):
  """
  Generate a manifest, expressed as a dictionary.
  """

  result = {}
  topdir = os.path.abspath(topdir)
  for dirpath, dirnames, filenames in os.walk(os.path.join(topdir, torrent_name)):
    for filename in filenames:
      filename = os.path.join(dirpath, filename)
      f = open(filename, "rb")
      result[os.path.relpath(filename, topdir)] = hashlib.sha256(f.read()).hexdigest()
      f.close()
  return result


def remove_torrents(client, name):
  """
  Remove any torrents with the given name.  In theory there should
  never be more than one, but it doesn't cost much to check.
  """

  ids = [i for i, t in client.list().iteritems() if t.name == name]
  if ids:
    syslog.syslog("Removing torrent%s %s (%s)" % (
      "" if len(ids) == 1 else "s", name, ", ".join("#%s" % i for i in ids)))
    client.remove(ids)


class MyConfigParser(ConfigParser.RawConfigParser):

  rpki_torrent_section = "rpki-torrent"

  @property
  def zip_dir(self):
    return self.get(self.rpki_torrent_section, "zip_dir")

  @property
  def zip_ta(self):
    return self.get(self.rpki_torrent_section, "zip_ta")

  @property
  def rcynic_prog(self):
    return self.get(self.rpki_torrent_section, "rcynic_prog")

  @property
  def rcynic_conf(self):
    return self.get(self.rpki_torrent_section, "rcynic_conf")

  @property
  def run_rcynic_anyway(self):
    return self.getboolean(self.rpki_torrent_section, "run_rcynic_anyway")

  def multioption_iter(self, name, getter = None):
    if getter is None:
      getter = self.get
    if self.has_option(self.rpki_torrent_section, name):
      yield getter(self.rpki_torrent_section, name)
    name += "."
    names = [i for i in self.options(self.rpki_torrent_section) if i.startswith(name) and i[len(name):].isdigit()]
    names.sort(key = lambda s: int(s[len(name):]))
    for name in names:
      yield getter(self.rpki_torrent_section, name)

  @property
  def zip_urls(self):
    return self.multioption_iter("zip_url")

  @property
  def post_rcynic_commands(self):
    return self.multioption_iter("post_rcynic_command")

  def find_url(self, torrent_name):
    urls = [u for u in self.zip_urls
            if os.path.splitext(os.path.basename(u))[0] == torrent_name]
    if len(urls) != 1:
      raise TorrentNameDoesNotMatchURL("Can't find URL matching torrent name %s" % torrent_name)
    return urls[0]


if __name__ == "__main__":
  main()
