# $Id$
#
# Copyright (C) 2014  Dragon Research Labs ("DRL")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL DRL BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Schedule action to force certificate reissuance as part of upgrade to
version 0.5678 of the rpki-ca toolkit.

This code is evaluated in the context of rpki-sql-setup's
do_apply_upgrades() function and has access to its variables.
"""

# Real work here has to be a deferred upgrade because the daemons have
# to be running for anything useful to happen.

db.add_deferred_upgrade('''

print """
        Version 0.5678 included a change which changed publication
        URIs embedded in issued certificates, which requires reissuing
        all affected certificates before everything will really work
        properly again.  Attempting to do this automatically...
"""

# General plan here:
#
# - Force reissuance of everything we've issued, to whack SIA and AIA
#   of everything we're producing.
#
# - "Manually" (ie, Python code here) whack any all-numeric
#   directories in our publication tree, as those are the ones that
#   [5678] removed.
#
# - Force (re)publication of everything, just in case we accidently
# - whacked something we still cared about.
#
# We include the occasional pause to let things settle between steps.

import os
import time
import shutil
import subprocess
import rpki.autoconf

time.sleep(10)

rpkic    = os.path.join(rpki.autoconf.sbindir, "rpkic")
irbe_cli = os.path.join(rpki.autoconf.sbindir, "irbe_cli")

handles = subprocess.check_output((rpkic, "list_self_handles")).splitlines()

argv = [irbe_cli]
for handle in handles:
  argv.extend(("self", "--self_handle", handle, "--action", "set", "--reissue"))
# Run this twice
subprocess.check_call(argv)
subprocess.check_call(argv)

for d in [os.path.join(top, d)
          for top, dirs, files in os.walk(os.path.join(rpki.autoconf.datarootdir, "rpki", "publication"))
          for d in dirs
          if d.isdigit()]:
  shutil.rmtree(d, ignore_errors = True)

argv = [irbe_cli]
for handle in handles:
  argv.extend(("self", "--self_handle", handle, "--action", "set", "--publish_world_now"))
subprocess.check_call(argv)

''')
