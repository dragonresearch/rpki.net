"""
Archive rcynic output in a Subversion repository.
"""

# $Id$
#
# Copyright (C) 2012 Internet Systems Consortium, Inc. ("ISC")
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS.  IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
# OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

import subprocess
import argparse
import datetime
import fcntl
import glob
import os

try:
  from lxml.etree            import ElementTree
except ImportError:
  from xml.etree.ElementTree import ElementTree


mime_types = (
  ("html", "application/xhtml+xml"),
  ("cer",  "application/pkix-cert"),
  ("crl",  "application/pkix-crl"),
  ("mft",  "application/rpki-manifest"),
  ("mnf",  "application/rpki-manifest"),
  ("roa",  "application/rpki-roa"),
  ("gbr",  "application/rpki-ghostbusters"))


def run(*cmd, **kwargs):
  """
  Run a program, displaying timing data when appropriate.
  """

  t = datetime.datetime.utcnow()
  subprocess.check_call(cmd, **kwargs)
  if args.show_timing:
    now = datetime.datetime.utcnow()
    print now, (now - t), " ".join(cmd)


def runxml(*cmd):
  """

  Run a program which produces XML output, displaying timing data when
  appropriate and returning an ElementTree constructed from the
  program's output.
  """
  t = datetime.datetime.utcnow()
  p = subprocess.Popen(cmd, stdout = subprocess.PIPE)
  x = ElementTree(file = p.stdout)
  s = p.wait()
  if s:
    raise subprocess.CalledProcessError(s, cmd[0])
  if args.show_timing:
    now = datetime.datetime.utcnow()
    print now, (now - t), " ".join(cmd)
  return x


# Main program.

parser = argparse.ArgumentParser(description = __doc__)

parser.add_argument("--show_timing", action = "store_true", help = \
                    """
                    Show timing data on programs we run.
                    """)

parser.add_argument("--verbatim", action = "store_true", help = \
                    """
                    Whether to archive rcynic's data output exactly as
                    rcynic writes it or map it into a directory
                    structure which makes more sense when used with
                    Subversion.  True means archive exactly as rcynic
                    writes it, interpreting file and directory names
                    as rsync would, transient directories and all.
                    False means map the current authenticated/ tree in
                    rcynic's output to a stable authenticated/ subtree
                    in the subversion repository, with file and
                    directory anmes from the command line shorted to
                    their last component.
                    """)

parser.add_argument("--lockfile", default = "rcynic-svn.lock", help = \
                    """
                    Lock file to to prevent multiple copies of this
                    program (eg, running under cron) from stepping on
                    each other while modifying the working directory.
                    """)

parser.add_argument("files_to_archive", nargs = "*", help = \
                    """
                    Files to archive using Subversion.  If omitted, we
                    assume that some other process has already
                    modified the Subversion working directory.
                    """)

parser.add_argument("working_directory", help = \
                    """
                    Subversion working directory to use (must already
                    exist).
                    """)

args = parser.parse_args()

if args.show_timing:
  t0 = datetime.datetime.utcnow()
  print t0, "Starting"

# Lock out other instances of this program.  We may want some more
# sophsiticated approach when combining this with other programs, but
# this should minimize the risk of multiple copies of this program
# trying to modify the same subversion working directory at the same
# time and messing each other up.  We leave the lock file in place
# because doing so removes a potential race condition.

lock = os.open("cronjob.lock", os.O_RDONLY | os.O_CREAT | os.O_NONBLOCK, 0666)
fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

# Make sure working tree is up to date.

run("svn", "update", "--quiet", args.working_directory)

# Copy rcynic's output as appropriate.

if args.files_to_archive:

  if args.verbatim:
    cmd = ["rsync", "--archive", "--quiet", "--delete"]
    cmd.extend(args.files_to_archive)
    cmd.append(args.working_directory)
    run(*cmd)

  else:
    for src in args.files_to_archive:
      cmd = ["rsync", "--archive", "--quiet", "--delete", "--copy-links"]
      cmd.append(src.rstrip("/"))
      cmd.append(args.working_directory.rstrip("/") + "/")
      run(*cmd)

# Ask Subversion to add any new files, trying hard to get the MIME
# types right.

cmd = ["svn", "add", "--quiet", "--force", "--auto-props"]

for fn2, mime_type in mime_types:
  cmd.append("--config-option")
  cmd.append("config:auto-props:*.%s=svn:mime-type=%s" % (fn2, mime_type))

cmd.append(".")

run(*cmd, cwd = args.working_directory)

# Parse XML version of Subversion's status output to figure out what
# files have been deleted, and tell Subversion that we deleted them
# intentionally.

missing = sorted(entry.get("path")
                 for entry in runxml("svn", "status", "--xml", args.working_directory).find("target").findall("entry")
                 if entry.find("wc-status").get("item") == "missing")
deleted = []

for path in missing:
  if not any(path.startswith(r) for r in deleted):
    run("svn", "delete", "--quiet", path)
    deleted.append(path + "/")

# Commit our changes and update the working tree.

run("svn", "commit", "--quiet", "--message", "Auto update.", args.working_directory)
run("svn", "update", "--quiet", args.working_directory)

if args.show_timing:
  now = datetime.datetime.utcnow()
  print now, now - t0, "total runtime"
