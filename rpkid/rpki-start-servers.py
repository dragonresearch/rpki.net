"""
Start servers, logging to files, looking at config file to figure out
which servers the user wants started.

$Id$

Copyright (C) 2009--2012  Internet Systems Consortium ("ISC")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

Portions copyright (C) 2007--2008  American Registry for Internet Numbers ("ARIN")

Permission to use, copy, modify, and distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.

"""

import subprocess, os, getopt, sys, time, rpki.config

rpkid_dir = os.path.normpath(sys.path[0])

os.environ["TZ"] = "UTC"
time.tzset()

cfg_file = None
debug = False
piddir = None

opts, argv = getopt.getopt(sys.argv[1:], "c:dhp:?", ["config=", "debug" "help", "piddir="])
for o, a in opts:
  if o in ("-h", "--help", "-?"):
    print __doc__
    sys.exit(0)
  elif o in ("-c", "--config"):
    cfg_file = a
  elif o in ("-d", "--debug"):
    debug = True
  elif o in ("-p", "--piddir"):
    piddir = a

cfg = rpki.config.parser(cfg_file, "myrpki")

def run(name):
  cmd = (sys.executable, os.path.join(rpkid_dir, name), "-c", cfg.filename)
  if debug:
    proc = subprocess.Popen(cmd + ("-d",), stdout = open(name + ".log", "a"), stderr = subprocess.STDOUT)
  else:
    proc = subprocess.Popen(cmd)
  if proc.poll() is None:
    print "Started %r, pid %s" % (name, proc.pid)
    if piddir is not None:
      open(os.path.join(piddir, "%s.pid" % name), "w").write("%d\n" % proc.pid)
  else:
    print "Problem starting %r, pid %s" % (name, proc.pid)

if cfg.getboolean("start_rpkid", False):
  run("irdbd")

if cfg.getboolean("start_irdbd", False):
  run("rpkid")

if cfg.getboolean("start_pubd",  False):
  run("pubd")

if cfg.getboolean("start_rootd", False):
  run("rootd")
