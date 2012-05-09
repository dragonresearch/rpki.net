"""
Make a normal program into a "daemon", like the 4.4BSD daemon(3) call.

This quite follow either the 4.4BSD call or the Python 3.x library,
because it was written to fit into an existing package and I didn't
want to drag in yet another external library just for this.

Some code borrowed from 
  http://www.jejik.com/articles/2007/02/a_simple_unix_linux_daemon_in_python/

(which was explicitly placed in public domain by its author), and from

  /usr/src/lib/libc/gen/daemon.c

(the libc implementation of daemon(3) on FreeBSD).

$Id$

Copyright (C) 2012  Internet Systems Consortium ("ISC")

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

Portions copyright (c) 1990, 1993
       The Regents of the University of California.  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:
  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.
  2. Redistributions in binary form must reproduce the above copyright
     notice, this list of conditions and the following disclaimer in the
     documentation and/or other materials provided with the distribution.
  4. Neither the name of the University nor the names of its contributors
     may be used to endorse or promote products derived from this software
     without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  SUCH DAMAGE.
"""

import sys
import os
import atexit
import signal

# Does default_pid_directory need to be autoconf-configurable?

## @var default_pid_directory
# Default directory to which to write process ID files.

default_pid_directory = "/var/run/rpki"

## @var pid_filename
# Configurable filename to which to write process ID file.
# pidfile argument to daemon() overrides this.

pid_filename = None

def daemon(nochdir = False, noclose = False, pidfile = None):
  """
  Make this program become a daemon, like 4.4BSD daemon(3), and
  write its pid out to a file with cleanup on exit.
  """

  if pidfile is None:
    if pid_filename is None:
      prog = os.path.splitext(os.path.basename(sys.argv[0]))[0]
      pidfile = os.path.join(default_pid_directory, "%s.pid" % prog)
    else:
      pidfile = pid_filename

  old_sighup_action = signal.signal(signal.SIGHUP, signal.SIG_IGN)

  try: 
    pid = os.fork() 
  except OSError, e: 
    sys.exit("fork() failed: %d (%s)" % (e.errno, e.strerror))
  else:
    if pid > 0:
      os._exit(0)
	
  if not nochdir:
    os.chdir("/") 

  os.setsid() 

  if not noclose:
    sys.stdout.flush()
    sys.stderr.flush()
    fd = os.open(os.devnull, os.O_RDWR)
    os.dup2(fd, 0)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    if fd > 2:
      os.close(fd)

  signal.signal(signal.SIGHUP, old_sighup_action)

  def delete_pid_file():
    try:
      os.unlink(pidfile)
    except OSError:
      pass

  atexit.register(delete_pid_file)
  
  f = open(pidfile, "w")
  f.write("%d\n" % os.getpid())
  f.close()
