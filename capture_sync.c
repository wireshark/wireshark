/* capture_sync.c
 * Synchronisation between Ethereal capture parent and child instances
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/* With MSVC and a libethereal.dll this file needs to import some variables 
   in a special way. Therefore _NEED_VAR_IMPORT_ is defined. */
#define _NEED_VAR_IMPORT_

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#include <pcap.h>

#include <glib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <signal.h>

#ifdef HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif

#ifndef _WIN32
/*
 * Define various POSIX macros (and, in the case of WCOREDUMP, non-POSIX
 * macros) on UNIX systems that don't have them.
 */
#ifndef WIFEXITED
# define WIFEXITED(status)	(((status) & 0177) == 0)
#endif
#ifndef WIFSTOPPED
# define WIFSTOPPED(status)	(((status) & 0177) == 0177)
#endif
#ifndef WIFSIGNALED
# define WIFSIGNALED(status)	(!WIFSTOPPED(status) && !WIFEXITED(status))
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(status)	((status) >> 8)
#endif
#ifndef WTERMSIG
# define WTERMSIG(status)	((status) & 0177)
#endif
#ifndef WCOREDUMP
# define WCOREDUMP(status)	((status) & 0200)
#endif
#ifndef WSTOPSIG
# define WSTOPSIG(status)	((status) >> 8)
#endif
#endif /* _WIN32 */

#include <epan/packet.h>
#include <epan/prefs.h>

#include "globals.h"
#include "file.h"

#include "capture.h"
#include "capture_sync.h"
#include "simple_dialog.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif
#include "ui_util.h"

#ifdef HAVE_IO_H
# include <io.h>
#endif

#ifdef _WIN32
#include <process.h>    /* For spawning child process */
#endif

/* Win32 needs the O_BINARY flag for open() */
#ifndef O_BINARY
#define O_BINARY	0
#endif


#ifndef _WIN32
static char *sync_pipe_signame(int);
#endif


static gboolean sync_pipe_input_cb(gint source, gpointer user_data);
static void sync_pipe_wait_for_child(int fork_child, gboolean always_report);

/* Size of buffer to hold decimal representation of
   signed/unsigned 64-bit int */
#define SP_DECISIZE 20

/*
 * Indications sent out on the sync pipe.
 */
#define SP_CAPSTART	';'	    /* capture start message */
#define SP_PACKET_COUNT	'*'	/* followed by count of packets captured since last message */
#define SP_ERROR_MSG	'!'	/* followed by length of error message that follows */
#define SP_DROPS	'#'	    /* followed by count of packets dropped in capture */



void
sync_pipe_capstart_to_parent(void)
{
    static const char capstart_msg = SP_CAPSTART;

    write(1, &capstart_msg, 1);
}

void
sync_pipe_packet_count_to_parent(int packet_count)
{
    char tmp[SP_DECISIZE+1+1];
    sprintf(tmp, "%d%c", packet_count, SP_PACKET_COUNT);
    write(1, tmp, strlen(tmp));
}

void
sync_pipe_errmsg_to_parent(const char *errmsg)
{
    int msglen = strlen(errmsg);
    char lenbuf[SP_DECISIZE+1+1];

    sprintf(lenbuf, "%u%c", msglen, SP_ERROR_MSG);
    write(1, lenbuf, strlen(lenbuf));
    write(1, errmsg, msglen);
}

void
sync_pipe_drops_to_parent(int drops)
{
	char tmp[SP_DECISIZE+1+1];
	sprintf(tmp, "%d%c", drops, SP_DROPS);
	write(1, tmp, strlen(tmp));
}


/* Add a string pointer to a NULL-terminated array of string pointers. */
static char **
sync_pipe_add_arg(char **args, int *argc, char *arg)
{
  /* Grow the array; "*argc" currently contains the number of string
     pointers, *not* counting the NULL pointer at the end, so we have
     to add 2 in order to get the new size of the array, including the
     new pointer and the terminating NULL pointer. */
  args = g_realloc(args, (*argc + 2) * sizeof (char *));

  /* Stuff the pointer into the penultimate element of the array, which
     is the one at the index specified by "*argc". */
  args[*argc] = arg;

  /* Now bump the count. */
  (*argc)++;

  /* We overwrite the NULL pointer; put it back right after the
     element we added. */
  args[*argc] = NULL;

  return args;
}

#ifdef _WIN32
/* Given a string, return a pointer to a quote-encapsulated version of
   the string, so we can pass it as an argument with "spawnvp" even
   if it contains blanks. */
char *
sync_pipe_quote_encapsulate(const char *string)
{
  char *encapsulated_string;

  encapsulated_string = g_new(char, strlen(string) + 3);
  sprintf(encapsulated_string, "\"%s\"", string);
  return encapsulated_string;
}
#endif



gboolean
sync_pipe_do_capture(capture_options *capture_opts, gboolean is_tempfile) {
    guint byte_count;
    int  i;
    guchar  c;
    char *msg;
    int  err;
    char ssnap[24];
    char scount[24];			/* need a constant for len of numbers */
    char sautostop_filesize[24];	/* need a constant for len of numbers */
    char sautostop_duration[24];	/* need a constant for len of numbers */
    char save_file_fd[24];
#ifndef _WIN32
    char errmsg[1024+1];
#endif
    int error;
    int argc;
    char **argv;
#ifdef _WIN32
    char sync_pipe_fd[24];
    char *fontstring;
    char *filterstring;
#endif
    enum PIPES { PIPE_READ, PIPE_WRITE };   /* Constants 0 and 1 for PIPE_READ and PIPE_WRITE */
    int sync_pipe[2];                       /* pipes used to sync between instances */


    capture_opts->fork_child = -1;

    /* Allocate the string pointer array with enough space for the
       terminating NULL pointer. */
    argc = 0;
    argv = g_malloc(sizeof (char *));
    *argv = NULL;

    /* Now add those arguments used on all platforms. */
    argv = sync_pipe_add_arg(argv, &argc, CHILD_NAME);

    argv = sync_pipe_add_arg(argv, &argc, "-i");
    argv = sync_pipe_add_arg(argv, &argc, cf_get_iface(capture_opts->cf));

    argv = sync_pipe_add_arg(argv, &argc, "-w");
    argv = sync_pipe_add_arg(argv, &argc, capture_opts->save_file);

    argv = sync_pipe_add_arg(argv, &argc, "-W");
    sprintf(save_file_fd,"%d",capture_opts->save_file_fd);	/* in lieu of itoa */
    argv = sync_pipe_add_arg(argv, &argc, save_file_fd);

    if (capture_opts->has_autostop_packets) {
      argv = sync_pipe_add_arg(argv, &argc, "-c");
      sprintf(scount,"%d",capture_opts->autostop_packets);
      argv = sync_pipe_add_arg(argv, &argc, scount);
    }

    if (capture_opts->has_snaplen) {
      argv = sync_pipe_add_arg(argv, &argc, "-s");
      sprintf(ssnap,"%d",capture_opts->snaplen);
      argv = sync_pipe_add_arg(argv, &argc, ssnap);
    }

    if (capture_opts->linktype != -1) {
      argv = sync_pipe_add_arg(argv, &argc, "-y");
#ifdef HAVE_PCAP_DATALINK_VAL_TO_NAME
      sprintf(ssnap,"%s",pcap_datalink_val_to_name(capture_opts->linktype));
#else
      /* XXX - just treat it as a number */
      sprintf(ssnap,"%d",capture_opts->linktype);
#endif
      argv = sync_pipe_add_arg(argv, &argc, ssnap);
    }

    if (capture_opts->has_autostop_filesize) {
      argv = sync_pipe_add_arg(argv, &argc, "-a");
      sprintf(sautostop_filesize,"filesize:%d",capture_opts->autostop_filesize);
      argv = sync_pipe_add_arg(argv, &argc, sautostop_filesize);
    }

    if (capture_opts->has_autostop_duration) {
      argv = sync_pipe_add_arg(argv, &argc, "-a");
      sprintf(sautostop_duration,"duration:%d",capture_opts->autostop_duration);
      argv = sync_pipe_add_arg(argv, &argc, sautostop_duration);
    }

    if (!capture_opts->show_info) {
      argv = sync_pipe_add_arg(argv, &argc, "-H");
    }

    if (!capture_opts->promisc_mode)
      argv = sync_pipe_add_arg(argv, &argc, "-p");

#ifdef _WIN32
    /* Create a pipe for the child process */

    if(_pipe(sync_pipe, 512, O_BINARY) < 0) {
      /* Couldn't create the pipe between parent and child. */
      error = errno;
      unlink(capture_opts->save_file);
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't create sync pipe: %s",
                        strerror(error));
      return FALSE;
    }

    /* Convert font name to a quote-encapsulated string and pass to child */
    argv = sync_pipe_add_arg(argv, &argc, "-m");
    fontstring = sync_pipe_quote_encapsulate(prefs.PREFS_GUI_FONT_NAME);
    argv = sync_pipe_add_arg(argv, &argc, fontstring);

    /* Convert pipe write handle to a string and pass to child */
    argv = sync_pipe_add_arg(argv, &argc, "-Z");
    itoa(sync_pipe[PIPE_WRITE], sync_pipe_fd, 10);
    argv = sync_pipe_add_arg(argv, &argc, sync_pipe_fd);

    /* Convert filter string to a quote delimited string and pass to child */
    filterstring = NULL;
    if (cf_get_cfilter(capture_opts->cf) != NULL && strlen(cf_get_cfilter(capture_opts->cf)) != 0) {
      argv = sync_pipe_add_arg(argv, &argc, "-f");
      filterstring = sync_pipe_quote_encapsulate(cf_get_cfilter(capture_opts->cf));
      argv = sync_pipe_add_arg(argv, &argc, filterstring);
    }

    /* Spawn process */
    capture_opts->fork_child = spawnvp(_P_NOWAIT, ethereal_path, argv);
    g_free(fontstring);
    if (filterstring) {
      g_free(filterstring);
    }
#else
    if (pipe(sync_pipe) < 0) {
      /* Couldn't create the pipe between parent and child. */
      error = errno;
      unlink(capture_opts->save_file);
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Couldn't create sync pipe: %s",
			strerror(error));
      return FALSE;
    }

    argv = sync_pipe_add_arg(argv, &argc, "-m");
    argv = sync_pipe_add_arg(argv, &argc, prefs.PREFS_GUI_FONT_NAME);

    if (cf_get_cfilter(capture_opts->cf) != NULL && cf_get_cfilter(capture_opts->cf) != 0) {
      argv = sync_pipe_add_arg(argv, &argc, "-f");
      argv = sync_pipe_add_arg(argv, &argc, cf_get_cfilter(capture_opts->cf));
    }

    if ((capture_opts->fork_child = fork()) == 0) {
      /*
       * Child process - run Ethereal with the right arguments to make
       * it just pop up the live capture dialog box and capture with
       * the specified capture parameters, writing to the specified file.
       *
       * args: -i interface specification
       * -w file to write
       * -W file descriptor to write
       * -c count to capture
       * -s snaplen
       * -m / -b fonts
       * -f "filter expression"
       */
      close(1);
      dup(sync_pipe[PIPE_WRITE]);
      close(sync_pipe[PIPE_READ]);
      execvp(ethereal_path, argv);
      snprintf(errmsg, sizeof errmsg, "Couldn't run %s in child process: %s",
		ethereal_path, strerror(errno));
      sync_pipe_errmsg_to_parent(errmsg);

      /* Exit with "_exit()", so that we don't close the connection
         to the X server (and cause stuff buffered up by our parent but
	 not yet sent to be sent, as that stuff should only be sent by
	 our parent). */
      _exit(2);
    }
#endif

    /* Parent process - read messages from the child process over the
       sync pipe. */
    g_free(argv);	/* free up arg array */

    /* Close the write side of the pipe, so that only the child has it
       open, and thus it completely closes, and thus returns to us
       an EOF indication, if the child closes it (either deliberately
       or by exiting abnormally). */
    close(sync_pipe[PIPE_WRITE]);

    /* Close the save file FD, as we won't be using it - we'll be opening
       it and reading the save file through Wiretap. */
    close(capture_opts->save_file_fd);

    if (capture_opts->fork_child == -1) {
      /* We couldn't even create the child process. */
      error = errno;
      close(sync_pipe[PIPE_READ]);
      unlink(capture_opts->save_file);
      g_free(capture_opts->save_file);
      capture_opts->save_file = NULL;
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Couldn't create child process: %s", strerror(error));
      return FALSE;
    }

    /* Read a byte count from "sync_pipe[PIPE_READ]", terminated with a
       colon; if the count is 0, the child process created the
       capture file and we should start reading from it, otherwise
       the capture couldn't start and the count is a count of bytes
       of error message, and we should display the message. */
    byte_count = 0;
    for (;;) {
      i = read(sync_pipe[PIPE_READ], &c, 1);
      if (i == 0) {
	/* EOF - the child process died.
	   Close the read side of the sync pipe, remove the capture file,
	   and report the failure. */
	close(sync_pipe[PIPE_READ]);
	unlink(capture_opts->save_file);
	g_free(capture_opts->save_file);
	capture_opts->save_file = NULL;
	sync_pipe_wait_for_child(capture_opts->fork_child, TRUE);
	return FALSE;
      }
      if (c == SP_CAPSTART || c == SP_ERROR_MSG)
	break;
      if (!isdigit(c)) {
	/* Child process handed us crap.
	   Close the read side of the sync pipe, remove the capture file,
	   and report the failure. */
	close(sync_pipe[PIPE_READ]);
	unlink(capture_opts->save_file);
	g_free(capture_opts->save_file);
	capture_opts->save_file = NULL;
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
			"Capture child process sent us a bad message");
	return FALSE;
      }
      byte_count = byte_count*10 + c - '0';
    }
    if (c != SP_CAPSTART) {
      /* Failure - the child process sent us a message indicating
	 what the problem was. */
      if (byte_count == 0) {
	/* Zero-length message? */
	simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Capture child process failed, but its error message was empty.");
      } else {
	msg = g_malloc(byte_count + 1);
	if (msg == NULL) {
	  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Capture child process failed, but its error message was too big.");
	} else {
	  i = read(sync_pipe[PIPE_READ], msg, byte_count);
	  msg[byte_count] = '\0';
	  if (i < 0) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		  "Capture child process failed: Error %s reading its error message.",
		  strerror(errno));
	  } else if (i == 0) {
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		  "Capture child process failed: EOF reading its error message.");
	    sync_pipe_wait_for_child(capture_opts->fork_child, FALSE);
	  } else
	    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, msg);
	  g_free(msg);
	}

	/* Close the sync pipe. */
	close(sync_pipe[PIPE_READ]);

	/* Get rid of the save file - the capture never started. */
	unlink(capture_opts->save_file);
	g_free(capture_opts->save_file);
	capture_opts->save_file = NULL;
      }
      return FALSE;
    }

    /* The child process started a capture.
       Attempt to open the capture file and set up to read it. */
    switch(cf_start_tail(capture_opts->cf, capture_opts->save_file, is_tempfile, &err)) {
    case CF_OK:
        /* We were able to open and set up to read the capture file;
           arrange that our callback be called whenever it's possible
           to read from the sync pipe, so that it's called when
           the child process wants to tell us something. */
        pipe_input_set_handler(sync_pipe[PIPE_READ], (gpointer) capture_opts, &capture_opts->fork_child, sync_pipe_input_cb);

        return TRUE;
        break;
    case CF_ERROR:
        /* We weren't able to open the capture file; user has been
        alerted. Close the sync pipe. */

        close(sync_pipe[PIPE_READ]);

        /* Don't unlink the save file - leave it around, for debugging
        purposes. */
        g_free(capture_opts->save_file);
        capture_opts->save_file = NULL;
        return FALSE;
        break;
    }

    g_assert_not_reached();
    return FALSE;
}


/* There's stuff to read from the sync pipe, meaning the child has sent
   us a message, or the sync pipe has closed, meaning the child has
   closed it (perhaps because it exited). */
static gboolean 
sync_pipe_input_cb(gint source, gpointer user_data)
{
  capture_options *capture_opts = (capture_options *)user_data;
  gint fork_child = capture_opts->fork_child;
#define BUFSIZE	4096
  char buffer[BUFSIZE+1], *p = buffer, *q = buffer, *msg, *r;
  int  nread, msglen, chars_to_copy;
  int  to_read = 0;
  int  err;


  if ((nread = read(source, buffer, BUFSIZE)) <= 0) {
    /* The child has closed the sync pipe, meaning it's not going to be
       capturing any more packets.  Pick up its exit status, and
       complain if it did anything other than exit with status 0. */
    sync_pipe_wait_for_child(fork_child, FALSE);

    /* Read what remains of the capture file, and finish the capture.
       XXX - do something if this fails? */
    switch (cf_finish_tail(capture_opts->cf, &err)) {

    case CF_READ_OK:
        if(cf_packet_count(capture_opts->cf) == 0) {
          simple_dialog(ESD_TYPE_INFO, ESD_BTN_OK, 
          "%sNo packets captured!%s\n\n"
          "As no data was captured, closing the %scapture file!",
          simple_dialog_primary_start(), simple_dialog_primary_end(),
          cf_is_tempfile(capture_opts->cf) ? "temporary " : "");
          cf_close(capture_opts->cf);
        }
        break;
    case CF_READ_ERROR:
      /* Just because we got an error, that doesn't mean we were unable
         to read any of the file; we handle what we could get from the
         file. */
      break;

    case CF_READ_ABORTED:
      /* Exit by leaving the main loop, so that any quit functions
         we registered get called. */
      main_window_quit();
      return FALSE;
    }

    /* We're not doing a capture any more, so we don't have a save
       file. */
    g_free(capture_opts->save_file);
    capture_opts->save_file = NULL;

    return FALSE;
  }

  buffer[nread] = '\0';

  while (nread != 0) {
    /* look for (possibly multiple) indications */
    switch (*q) {
    case SP_PACKET_COUNT :
      to_read += atoi(p);
      p = q + 1;
      q++;
      nread--;
      break;
    case SP_DROPS :
      cf_set_drops_known(capture_opts->cf, TRUE);
      cf_set_drops(capture_opts->cf, atoi(p));
      p = q + 1;
      q++;
      nread--;
      break;
    case SP_ERROR_MSG :
      msglen = atoi(p);
      p = q + 1;
      q++;
      nread--;

      /* Read the entire message.
         XXX - if the child hasn't sent it all yet, this could cause us
         to hang until they do. */
      msg = g_malloc(msglen + 1);
      r = msg;
      while (msglen != 0) {
      	if (nread == 0) {
      	  /* Read more. */
          if ((nread = read(source, buffer, BUFSIZE)) <= 0)
            break;
          p = buffer;
          q = buffer;
        }
      	chars_to_copy = MIN(msglen, nread);
        memcpy(r, q, chars_to_copy);
        r += chars_to_copy;
        q += chars_to_copy;
        nread -= chars_to_copy;
        msglen -= chars_to_copy;
      }
      *r = '\0';
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, msg);
      g_free(msg);
      break;
    default :
      q++;
      nread--;
      break;
    }
  }

  /* Read from the capture file the number of records the child told us
     it added.
     XXX - do something if this fails? */
  switch (cf_continue_tail(capture_opts->cf, to_read, &err)) {

  case CF_READ_OK:
  case CF_READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file.

       XXX - abort on a read error? */
    break;

  case CF_READ_ABORTED:
    /* Kill the child capture process; the user wants to exit, and we
       shouldn't just leave it running. */
    kill_capture_child(capture_opts);
    break;
  }

  return TRUE;
}


/* the child process is going down, wait until it's completely terminated */
static void
sync_pipe_wait_for_child(int fork_child, gboolean always_report)
{
  int  wstatus;

#ifdef _WIN32
  /* XXX - analyze the wait status and display more information
     in the dialog box?
     XXX - set "fork_child" to -1 if we find it exited? */
  if (_cwait(&wstatus, fork_child, _WAIT_CHILD) == -1) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		"Child capture process stopped unexpectedly");
  }
#else
  if (wait(&wstatus) != -1) {
    if (WIFEXITED(wstatus)) {
      /* The child exited; display its exit status, if it's not zero,
         and even if it's zero if "always_report" is true. */
      if (always_report || WEXITSTATUS(wstatus) != 0) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		      "Child capture process exited: exit status %d",
		      WEXITSTATUS(wstatus));
      }
    } else if (WIFSTOPPED(wstatus)) {
      /* It stopped, rather than exiting.  "Should not happen." */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Child capture process stopped: %s",
		    sync_pipe_signame(WSTOPSIG(wstatus)));
    } else if (WIFSIGNALED(wstatus)) {
      /* It died with a signal. */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Child capture process died: %s%s",
		    sync_pipe_signame(WTERMSIG(wstatus)),
		    WCOREDUMP(wstatus) ? " - core dumped" : "");
    } else {
      /* What?  It had to either have exited, or stopped, or died with
         a signal; what happened here? */
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
		    "Child capture process died: wait status %#o", wstatus);
    }
  }

  /* No more child process. */
  fork_child = -1;
#endif
}


#ifndef _WIN32
static char *
sync_pipe_signame(int sig)
{
  char *sigmsg;
  static char sigmsg_buf[6+1+3+1];

  switch (sig) {

  case SIGHUP:
    sigmsg = "Hangup";
    break;

  case SIGINT:
    sigmsg = "Interrupted";
    break;

  case SIGQUIT:
    sigmsg = "Quit";
    break;

  case SIGILL:
    sigmsg = "Illegal instruction";
    break;

  case SIGTRAP:
    sigmsg = "Trace trap";
    break;

  case SIGABRT:
    sigmsg = "Abort";
    break;

  case SIGFPE:
    sigmsg = "Arithmetic exception";
    break;

  case SIGKILL:
    sigmsg = "Killed";
    break;

  case SIGBUS:
    sigmsg = "Bus error";
    break;

  case SIGSEGV:
    sigmsg = "Segmentation violation";
    break;

  /* http://metalab.unc.edu/pub/Linux/docs/HOWTO/GCC-HOWTO
     Linux is POSIX compliant.  These are not POSIX-defined signals ---
     ISO/IEC 9945-1:1990 (IEEE Std 1003.1-1990), paragraph B.3.3.1.1 sez:

	``The signals SIGBUS, SIGEMT, SIGIOT, SIGTRAP, and SIGSYS
	were omitted from POSIX.1 because their behavior is
	implementation dependent and could not be adequately catego-
	rized.  Conforming implementations may deliver these sig-
	nals, but must document the circumstances under which they
	are delivered and note any restrictions concerning their
	delivery.''

     So we only check for SIGSYS on those systems that happen to
     implement them (a system can be POSIX-compliant and implement
     them, it's just that POSIX doesn't *require* a POSIX-compliant
     system to implement them).
   */

#ifdef SIGSYS
  case SIGSYS:
    sigmsg = "Bad system call";
    break;
#endif

  case SIGPIPE:
    sigmsg = "Broken pipe";
    break;

  case SIGALRM:
    sigmsg = "Alarm clock";
    break;

  case SIGTERM:
    sigmsg = "Terminated";
    break;

  default:
    sprintf(sigmsg_buf, "Signal %d", sig);
    sigmsg = sigmsg_buf;
    break;
  }
  return sigmsg;
}
#endif


void
sync_pipe_stop(capture_options *capture_opts)
{
  if (capture_opts->fork_child != -1) {
#ifndef _WIN32
      kill(capture_opts->fork_child, SIGUSR1);
#else
      /* XXX: this is not the preferred method of closing a process!
       * the clean way would be getting the process id of the child process,
       * then getting window handle hWnd of that process (using EnumChildWindows),
       * and then do a SendMessage(hWnd, WM_CLOSE, 0, 0) 
       *
       * Unfortunately, I don't know how to get the process id from the handle */
      /* Hint: OpenProcess will get an handle from the id, not vice versa :-(
       *
       * Hint: GenerateConsoleCtrlEvent() will only work, if both processes are 
       * running in the same console, I don't know if that is true for our case.
       * And this also will require to have the process id
       */
      TerminateProcess((HANDLE) (capture_opts->fork_child), 0);
#endif
  }
}


void
sync_pipe_kill(capture_options *capture_opts)
{
  if (capture_opts->fork_child != -1)
#ifndef _WIN32
      kill(capture_opts->fork_child, SIGTERM);	/* SIGTERM so it can clean up if necessary */
#else
      /* XXX: this is not the preferred method of closing a process!
       * the clean way would be getting the process id of the child process,
       * then getting window handle hWnd of that process (using EnumChildWindows),
       * and then do a SendMessage(hWnd, WM_CLOSE, 0, 0) 
       *
       * Unfortunately, I don't know how to get the process id from the handle */
      /* Hint: OpenProcess will get an handle from the id, not vice versa :-(
       *
       * Hint: GenerateConsoleCtrlEvent() will only work, if both processes are 
       * running in the same console, I don't know if that is true for our case.
       * And this also will require to have the process id
       */
      TerminateProcess((HANDLE) (capture_opts->fork_child), 0);
#endif
}


#endif /* HAVE_LIBPCAP */
