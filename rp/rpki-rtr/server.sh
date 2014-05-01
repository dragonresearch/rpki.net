#!/bin/sh -
#
# Wrapper for rpki-rtr server, for testing.
#
# In production we would probably want to handle all of this directly
# in the command= setting for a particular ssh key, but for testing
# it's often simpler to run a shall script to debug what arguments
# and extra commands you might need.
#
# Be warned that almost any error here will cause the subsystem to
# fail mysteriously, leaving behind naught but a SIGCHILD log message
# from sshd as this script dies.

exec /usr/local/bin/rpki-rtr server /var/rcynic/rpki-rtr
