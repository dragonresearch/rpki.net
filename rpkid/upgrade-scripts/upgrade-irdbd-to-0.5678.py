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

import time
import os.path
import subprocess
import rpki.autoconf

time.sleep(10)

rpkic    = os.path.join(rpki.autoconf.sbindir, "rpkic")
irbe_cli = os.path.join(rpki.autoconf.sbindir, "irbe_cli")

handles = subprocess.check_output((rpkic, "list_self_handles")).splitlines()

argv = [irbe_cli]
for handle in handles:
  argv.extend(("self", "--self_id", handle, "--action", "set",
               "--rekey", "--reissue", "--run_now"))
subprocess.check_call(argv)

time.sleep(10)

argv = [irbe_cli]
for handle in handles:
  argv.extend(("self", "--self_id", handle, "--action", "set",
               "--revoke", "--reissue", "--run_now", "--publish_world_now"))
subprocess.check_call(argv)

''')
