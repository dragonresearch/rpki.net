#!/bin/sh -
#
# Wrapper for rtr-origin.py in server mode, for testing.
#
# In production we would probably want to handle all of this either
# directly in the Python code or in the command= setting for a
# particular ssh key, but for initial testing it's simpler to run a
# shall script to change to the right directory and supply any
# necessary command line arguments.
#
# Be warned that almost any error here will cause the subsystem to
# fail mysteriously, leaving behind naught but a SIGCHILD log message
# from sshd as this script dies.

cd /u/sra/rpki/subvert-rpki.hactrn.net/rtr-origin

exec /usr/local/bin/python rtr-origin.py --server
