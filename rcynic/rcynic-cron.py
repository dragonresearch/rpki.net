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

import subprocess
import sys
import fcntl
import os
import pwd

# Stuff we need from autoconf:
#
#  AC_RCYNIC_USER
#  AC_RCYNIC_GROUP
#  AC_RCYNIC_DIR
#  AC_bindir
#  AC_sysconfdir
#  AC_RCYNIC_HTML_DIR
#  AC_SU
#  AC_SUDO
#  AC_CHROOT
#  AC_CHROOTUID

we_are_root = os.getuid() == 0

beastie = sys.platform.startswith("freebsd") or sys.platform.startswith("darwin")

def bin(name, chroot = False):
  return os.path.join("/bin" if chroot and we_are_root else AC_bindir, name)

def etc(name, chroot = False):
  return os.path.join("/etc" if chroot and we_are_root else AC_sysconfdir, name)

def rcy(name):
  return os.path.join(AC_RCYNIC_DIR, name)

jail_dirs = { AC_bindir : "/bin", AC_sysconfdir : "/etc" }

def run(*cmd, **kwargs):
  chroot = kwargs.pop("chroot", False) and we_are_root
  if we_are_root:
    if chroot and beastie:
      cmd = (AC_CHROOT, "-u", AC_RCYNIC_USER, "-g", AC_RCYNIC_GROUP, AC_RCYNIC_DIR) + cmd
    elif chroot and not beastie:
      cmd = (AC_CHROOTUID, AC_RCYNIC_DIR, AC_RCYNIC_USER) + cmd
    elif not chroot and beastie:
      cmd = (AC_SU, "-m", AC_RCYNIC_USER, "-c", " ".join(cmd))
    elif not chroot and not beastie:
      cmd = (AC_SUDO, "-u", AC_RCYNIC_USER) + cmd
    else:
      raise RuntimeError("How the frell did I get here?")
  try:
    subprocess.check_call(cmd, **kwargs)
  except subprocess.CalledProcessError, e:
    sys.exit("Error %r running command: %s" % (e.strerror, " ".join(repr(c) for c in cmd)))

try:
  lock = os.open(os.path.join(AC_RCYNIC_DIR, "data/lock"), os.O_RDONLY | os.O_CREAT | os.O_NONBLOCK, 0666)
  fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
  if we_are_root:
    pw = pwd.getpwnam(AC_RCYNIC_USER)
    os.fchown(lock, pw.pw_uid, pw.pw_gid)
except (IOError, OSError), e:
  sys.exit("Error %r opening lock %r" % (e.strerror, os.path.join(AC_RCYNIC_DIR, "data/lock")))

run(bin("rcynic", chroot = True), "-c", etc("rcynic.conf", chroot = True), chroot = True)

run(bin("rcynic-html"), rcy("data/rcynic.xml"), AC_RCYNIC_HTML_DIR)

run(bin("rtr-origin"), "--cronjob", rcy("data/authenticated"), cwd = rcy("rpki-rtr"))
