"""
Test of the cmd module.  If given command line arguments, run them as
a single command, otherwise go into a command loop, with readline and
history and emacs keys and everything.  Whee!

$Id$

Copyright (C) 2010  Internet Systems Consortium ("ISC")

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
"""

import cmd, readline, sys, glob

class wibble(cmd.Cmd):

  prompt = "wibble> "

  identchars = cmd.IDENTCHARS + "/-."

  def do_tweedledee(self, arg):
    """
    Tweedledee said Tweeldedum had spoiled his nice new rattle.
    """
    print "Dee", arg

  def do_tweedledum(self, arg):
    """
    Tweedledum and Tweedledee agreed to have a battle.
    """
    print "Dum", arg

  def do_EOF(self, arg):
    print
    return True

  def do_exit(self, arg):
    """
    Exit program
    """
    return True

  do_quit = do_exit

  def emptyline(self):
    pass

  def do_tarbarrel(self, arg):
    """
    Just then flew down a monsterous crow as black as a tarbarrel.
    """
    print "Quite forgot their quarrel"

  def completedefault(self, text, line, begidx, endidx):
    return glob.glob(text + "*")

histfile = ".wibble_history"

try:
  readline.read_history_file(histfile)
except IOError:
  pass

readline.set_completer_delims("".join(set(readline.get_completer_delims()) - set(wibble.identchars)))

try:
  wibbler = wibble()
  if len(sys.argv) > 1:
    wibbler.onecmd(" ".join(sys.argv[1:]))
  else:
    wibbler.cmdloop()
finally:
  readline.write_history_file(histfile)

