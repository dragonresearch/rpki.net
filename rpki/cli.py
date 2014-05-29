# $Id$
#
# Copyright (C) 2013--2014  Dragon Research Labs ("DRL")
# Portions copyright (C) 2010--2012  Internet Systems Consortium ("ISC")
#
# Permission to use, copy, modify, and distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notices and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND DRL AND ISC DISCLAIM ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS.  IN NO EVENT SHALL DRL OR
# ISC BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
# DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA
# OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
# TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.

"""
Utilities for writing command line tools.
"""

import cmd
import glob
import shlex
import os.path
import argparse
import traceback

try:
  import readline
  have_readline = True
except ImportError:
  have_readline = False

class BadCommandSyntax(Exception):
  "Bad command line syntax."

class ExitArgparse(Exception):
  "Exit method from ArgumentParser."

  def __init__(self, message = None, status = 0):
    super(ExitArgparse, self).__init__()
    self.message = message
    self.status = status

class Cmd(cmd.Cmd):
  """
  Customized subclass of Python cmd module.
  """

  emptyline_repeats_last_command = False

  EOF_exits_command_loop = True

  identchars = cmd.IDENTCHARS + "/-."

  histfile = None

  last_command_failed = False

  def __init__(self, argv = None):
    cmd.Cmd.__init__(self)
    if argv:
      self.onecmd(" ".join(argv))
    else:
      self.cmdloop_with_history()

  def onecmd(self, line):
    """
    Wrap error handling around cmd.Cmd.onecmd().  Might want to do
    something kinder than showing a traceback, eventually.
    """

    self.last_command_failed = False
    try:
      return cmd.Cmd.onecmd(self, line)
    except SystemExit:
      raise
    except ExitArgparse, e:
      if e.message is not None:
        print e.message
      self.last_command_failed = e.status != 0
      return False
    except BadCommandSyntax, e:
      print e
    except Exception:
      traceback.print_exc()
    self.last_command_failed = True
    return False

  def do_EOF(self, arg):
    if self.EOF_exits_command_loop and self.prompt:
      print
    return self.EOF_exits_command_loop

  def do_exit(self, arg):
    """
    Exit program.
    """

    return True

  do_quit = do_exit

  def emptyline(self):
    """
    Handle an empty line.  cmd module default is to repeat the last
    command, which I find to be violation of the principal of least
    astonishment, so my preference is that an empty line does nothing.
    """

    if self.emptyline_repeats_last_command:
      cmd.Cmd.emptyline(self)

  def filename_complete(self, text, line, begidx, endidx):
    """
    Filename completion handler, with hack to restore what I consider
    the normal (bash-like) behavior when one hits the completion key
    and there's only one match.
    """

    result = glob.glob(text + "*")
    if len(result) == 1:
      path = result.pop()
      if os.path.isdir(path) or (os.path.islink(path) and os.path.isdir(os.path.join(path, "."))):
        result.append(path + os.path.sep)
      else:
        result.append(path + " ")
    return result

  def completenames(self, text, *ignored):
    """
    Command name completion handler, with hack to restore what I
    consider the normal (bash-like) behavior when one hits the
    completion key and there's only one match.
    """

    result = cmd.Cmd.completenames(self, text, *ignored)
    if len(result) == 1:
      result[0] += " "
    return result

  def help_help(self):
    """
    Type "help [topic]" for help on a command,
    or just "help" for a list of commands.
    """

    self.stdout.write(self.help_help.__doc__ + "\n")

  def complete_help(self, *args):
    """
    Better completion function for help command arguments.
    """

    text = args[0]
    names = self.get_names()
    result = []
    for prefix in ("do_", "help_"):
      result.extend(s[len(prefix):] for s in names if s.startswith(prefix + text) and s != "do_EOF")
    return result

  if have_readline:

    def cmdloop_with_history(self):
      """
      Better command loop, with history file and tweaked readline
      completion delimiters.
      """

      old_completer_delims = readline.get_completer_delims()
      if self.histfile is not None:
        try:
          readline.read_history_file(self.histfile)
        except IOError:
          pass
      try:
        readline.set_completer_delims("".join(set(old_completer_delims) - set(self.identchars)))
        self.cmdloop()
      finally:
        if self.histfile is not None and readline.get_current_history_length():
          readline.write_history_file(self.histfile)
        readline.set_completer_delims(old_completer_delims)

  else:

    cmdloop_with_history = cmd.Cmd.cmdloop



def yes_or_no(prompt, default = None, require_full_word = False):
  """
  Ask a yes-or-no question.
  """

  prompt = prompt.rstrip() + _yes_or_no_prompts[default]
  while True:
    answer = raw_input(prompt).strip().lower()
    if not answer and default is not None:
      return default
    if answer == "yes" or (not require_full_word and answer.startswith("y")):
      return True
    if answer == "no"  or (not require_full_word and answer.startswith("n")):
      return False
    print 'Please answer "yes" or "no"'

_yes_or_no_prompts = {
  True  : ' ("yes" or "no" ["yes"]) ',
  False : ' ("yes" or "no" ["no"]) ',
  None  : ' ("yes" or "no") ' }


class NonExitingArgumentParser(argparse.ArgumentParser):
  """
  ArgumentParser tweaked to throw ExitArgparse exception
  rather than using sys.exit(), for use with command loop.
  """

  def exit(self, status = 0, message = None):
    raise ExitArgparse(status = status, message = message)


def parsecmd(subparsers, *arg_clauses):
  """
  Decorator to combine the argparse and cmd modules.

  subparsers is an instance of argparse.ArgumentParser (or subclass) which was
  returned by calling the .add_subparsers() method on an ArgumentParser instance
  intended to handle parsing for the entire program on the command line.

  arg_clauses is a series of defarg() invocations defining arguments to be parsed
  by the argparse code.

  The decorator will use arg_clauses to construct two separate argparse parser
  instances: one will be attached to the global parser as a subparser, the
  other will be used to parse arguments for this command when invoked by cmd.

  The decorator will replace the original do_whatever method with a wrapped version
  which uses the local argparse instance to parse the single string supplied by
  the cmd module.

  The intent is that, from the command's point of view, all of this should work
  pretty much the same way regardless of whether the command was invoked from
  the global command line or from within the cmd command loop.  Either way,
  the command method should get an argparse.Namespace object.

  In theory, we could generate a completion handler from the argparse definitions,
  much as the separate argcomplete package does.  In practice this is a lot of
  work and I'm not ready to get into that just yet.
  """

  def decorate(func):
    assert func.__name__.startswith("do_")
    parser = NonExitingArgumentParser(description = func.__doc__,
                                      prog = func.__name__[3:],
                                      add_help = False)
    subparser = subparsers.add_parser(func.__name__[3:],
                                      description = func.__doc__,
                                      help = func.__doc__.lstrip().partition("\n")[0])
    for positional, keywords in arg_clauses:
      parser.add_argument(*positional, **keywords)
      subparser.add_argument(*positional, **keywords)
    subparser.set_defaults(func = func)
    def wrapped(self, arg):
      return func(self, parser.parse_args(shlex.split(arg)))
    wrapped.argparser = parser
    wrapped.__doc__ = func.__doc__
    return wrapped
  return decorate

def cmdarg(*positional, **keywords):
  """
  Syntactic sugar to let us use keyword arguments normally when constructing
  arguments for deferred calls to argparse.ArgumentParser.add_argument().
  """

  return positional, keywords
