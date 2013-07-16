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

import os
import sys
import pwd
import fcntl
import errno
import getopt

def usage(result):
  f = sys.stderr if result else sys.stdout
  f.write("Usage: %s [--chroot] [--help]\n" % sys.argv[0])
  sys.exit(result)

def run(*cmd, **kwargs):
  chroot_this = kwargs.pop("chroot_this", False)
  cwd = kwargs.pop("cwd", None)
  pid = os.fork()
  if pid == 0:
    if chroot_this:
      os.chdir(ac_rcynic_dir)
    elif cwd is not None:
      os.chdir(cwd)
    if we_are_root:
      os.initgroups(pw.pw_name, pw.pw_gid)
    if chroot_this:
      os.chroot(ac_rcynic_dir)
    if we_are_root:
      os.setgid(pw.pw_gid)
      os.setuid(pw.pw_uid)
    os.closerange(3, os.sysconf("SC_OPEN_MAX"))
    os.execvp(cmd[0], cmd)
    os._exit(1)
  else:
    status = os.waitpid(pid, 0)[1]
    if status != 0:
      sys.exit("Program %s exited with status %s" % (" ".join(cmd), status))

want_chroot = False

opts, argv = getopt.getopt(sys.argv[1:], "h?", ["chroot", "help"])
for o, a in opts:
  if o in ("-?", "-h", "--help"):
    usage(0)
  elif o =="--chroot":
    want_chroot = True

if argv:
  usage("Unexpected arguments: %r" % (argv,))

we_are_root = os.getuid() == 0

if want_chroot and not we_are_root:
  usage("Only root can --chroot")

try:
  pw = pwd.getpwnam(ac_rcynic_user)
except KeyError:
  sys.exit("Could not find passwd entry for user %s" % ac_rcynic_user)

try:
  lock = os.open(os.path.join(ac_rcynic_dir, "data/lock"), os.O_RDONLY | os.O_CREAT | os.O_NONBLOCK, 0666)
  fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
  if we_are_root:
    os.fchown(lock, pw.pw_uid, pw.pw_gid)
except (IOError, OSError), e:
  if e.errno == errno.EAGAIN:
    sys.exit(0)                         # Another instance of this script is already running, exit silently
  else:
    sys.exit("Error %r opening lock %r" % (e.strerror, os.path.join(ac_rcynic_dir, "data/lock")))

if want_chroot:
  run("/bin/rcynic", "-c", "/etc/rcynic.conf", chroot_this = True)
else:
  run(os.path.join(ac_bindir, "rcynic"), "-c", os.path.join(ac_sysconfdir, "rcynic.conf"))

run(os.path.join(ac_bindir, "rtr-origin"),
    "--cronjob", 
    os.path.join(ac_rcynic_dir, "data/authenticated"),
    cwd = os.path.join(ac_rcynic_dir, "rpki-rtr"))

prog = os.path.join(ac_libexecdir, "rpkigui-rcynic")
if os.path.exists(prog):
  run(prog)

if ac_rcynic_html_dir and os.path.exists(os.path.dirname(ac_rcynic_html_dir)):
  run(os.path.join(ac_bindir, "rcynic-html"),
      os.path.join(ac_rcynic_dir, "data/rcynic.xml"),
      ac_rcynic_html_dir)
