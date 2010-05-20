"""
Utilities for writing command line tools.

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

import cmd, glob, os.path, traceback

try:
  import readline
  have_readline = True
except ImportError:
  have_readline = False

class Cmd(cmd.Cmd):
  """
  Customized subclass of Python cmd module.
  """

  emptyline_repeats_last_command = False

  EOF_exits_command_loop = True

  identchars = cmd.IDENTCHARS + "/-."

  histfile = None

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
    try:
      return cmd.Cmd.onecmd(self, line)
    except SystemExit:
      raise
    except:
      traceback.print_exc()

  def do_EOF(self, arg):
    """
    Exit program.
    """
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
    result = set(cmd.Cmd.completenames(self, text, *ignored))
    if len(result) == 1:
      result.add(result.pop() + " ")
    return list(result)

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
      result.extend(s[len(prefix):] for s in names if s.startswith(prefix + text))
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

