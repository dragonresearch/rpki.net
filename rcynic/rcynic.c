/*
 * Copyright (C) 2006  American Registry for Internet Numbers ("ARIN")
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND ARIN DISCLAIMS ALL WARRANTIES WITH
 * REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS.  IN NO EVENT SHALL ARIN BE LIABLE FOR ANY SPECIAL, DIRECT,
 * INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
 * OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 * PERFORMANCE OF THIS SOFTWARE.
 */

/* $Id* */

/*
 * "Cynical rsync": Recursively walk RPKI tree using rsync to pull
 * data from remote sites, validating certificates and CRLs as we go.
 */

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/file.h>
#include <errno.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include <time.h>
#include <string.h>
#include <sys/stat.h>

/*
 * Logging functions.
 */

static char *jane;

static void vlogmsg(char *fmt, va_list ap)
{
  char tad[30];
  time_t tad_time = time(0);
  struct tm *tad_tm = localtime(&tad_time);

  strftime(tad, sizeof(tad), "%H:%M:%S", tad_tm);
  printf("%s: ", tad);
  if (jane)
    printf("%s: ", jane);
  vprintf(fmt, ap);
  putchar('\n');
}


static void logmsg(char *fmt, ...)
{
  va_list ap;

  va_start(ap, fmt);
  vlogmsg(fmt, ap);
  va_end(ap);
}

static void fatal(int retval, char *fmt, ...)
{
  int child = retval < 0;
  va_list ap;

  if (child)
    retval = -retval;

  if (fmt) {
    va_start(ap, fmt);
    vlogmsg(fmt, ap);
    va_end(ap);
    logmsg("Last system error: %s", strerror(errno));
    logmsg("exiting with status %d", retval);
  }

  if (child)
    _exit(retval);
  else
    exit(retval);
}

/*
 * Subprocess manipulation.
 */

static int vrun(char *prog, va_list ap)
{
  char *argv[100], buffer[2000];
  int argc, pipe_fds[2], n, pid_status = -1;
  FILE *f;

  argv[argc = 0] = prog;
  while (argv[argc++]) {
    assert(argc < sizeof(argv)/sizeof(*argv));
    argv[argc] = va_arg(ap, char *);
  }

  if (pipe(pipe_fds) < 0)
    fatal(1, "pipe() failed");

  switch (vfork()) {
   case -1:
    fatal(1, "vfork() failed");
   case 0:
    close(pipe_fds[0]);
    if (dup2(pipe_fds[1], 1) < 0)
      fatal(-2, "dup2(1) failed");
    if (dup2(pipe_fds[1], 2) < 0)
      fatal(-3, "dup2(2) failed");
    execvp(prog, argv);
    fatal(-4, "execvp() failed");
  }

  close(pipe_fds[1]);
  if ((f = fdopen(pipe_fds[0], "r")) == NULL)
    fatal(1, "Couldn't open output of forked process");

  while (fgets(buffer, sizeof(buffer), f)) {
    char *s = strchr(buffer, '\n');
    if (s)
      *s = '\0';
    logmsg("%s", buffer);
  }

  wait(&pid_status);

  if (WEXITSTATUS(pid_status)) {
    logmsg("Forked process exited with status %d", pid_status);
    return 0;
  } else {
    return 1;
  }
}

static int run(char *prog, ...)
{
  int ret;
  va_list ap;
  va_start(ap, prog);
  ret = vrun(prog, ap);
  va_end(ap);
  return ret;
}
