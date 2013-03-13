"""
Cron job for rcynic and rtr-origin in stock configuration.

$Id$

Copyright (C) 2013 Internet Systems Consortium, Inc. ("ISC")

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

# Locking code here works like FreeBSD's lockf(1) utility given -k and
# -t 0 options, which is both the sanest and simplest combination for
# our purposes.  In theory this is portable to any Unix-like system.
#
# At some point we might want to implement the chroot() and setuid()
# functionality here rather than using this mess of platform-specific
# external programs.  I don't have time to write and debug that today,
# but it might well be simpler and more portable.

import subprocess
import sys
import fcntl
import os
import pwd
import errno

we_are_root = os.getuid() == 0

beastie = sys.platform.startswith("freebsd") or sys.platform.startswith("darwin")

def bin(name, chroot = False):
  return os.path.join("/bin" if chroot and we_are_root else ac_bindir, name)

def etc(name, chroot = False):
  return os.path.join("/etc" if chroot and we_are_root else ac_sysconfdir, name)

def rcy(name):
  return os.path.join(ac_rcynic_dir, name)

def run(*cmd, **kwargs):
  chroot = kwargs.pop("chroot", False) and we_are_root
  if we_are_root:
    if chroot and beastie:
      cmd = (ac_chroot, "-u", ac_rcynic_user, "-g", ac_rcynic_group, ac_rcynic_dir) + cmd
    elif chroot and not beastie:
      cmd = (ac_chrootuid, ac_rcynic_dir, ac_rcynic_user) + cmd
    elif not chroot and beastie:
      cmd = (ac_su, "-m", ac_rcynic_user, "-c", " ".join(cmd))
    elif not chroot and not beastie:
      cmd = (ac_sudo, "-u", ac_rcynic_user) + cmd
    else:
      raise RuntimeError("How the frell did I get here?")
  try:
    subprocess.check_call(cmd, **kwargs)
  except subprocess.CalledProcessError, e:
    sys.exit(str(e))

try:
  lock = os.open(os.path.join(ac_rcynic_dir, "data/lock"), os.O_RDONLY | os.O_CREAT | os.O_NONBLOCK, 0666)
  fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
  if we_are_root:
    pw = pwd.getpwnam(ac_rcynic_user)
    os.fchown(lock, pw.pw_uid, pw.pw_gid)
except (IOError, OSError), e:
  if e.errno == errno.EAGAIN:
    sys.exit(0)                         # Another instance of this script is already running, exit silently
  else:
    sys.exit("Error %r opening lock %r" % (e.strerror, os.path.join(ac_rcynic_dir, "data/lock")))

run(bin("rcynic", chroot = True), "-c", etc("rcynic.conf", chroot = True), chroot = True)

if ac_rcynic_html_dir and os.path.exists(os.path.dirname(ac_rcynic_html_dir)):
  run(bin("rcynic-html"), rcy("data/rcynic.xml"), ac_rcynic_html_dir)

run(bin("rtr-origin"), "--cronjob", rcy("data/authenticated"), cwd = rcy("rpki-rtr"))

try:
  import rpki.gui.cacheview.util 
  rpki.gui.cacheview.util.import_rcynic_xml()
except ImportError:
  pass
