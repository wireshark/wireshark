/* capture.c
 * Routines for packet capture windows
 *
 * $Id: capture.c,v 1.171 2002/02/24 09:25:34 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_LIBPCAP

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
# include <sys/stat.h>
#endif

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

#ifdef HAVE_IO_H
# include <io.h>
#endif

#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <time.h>

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_IOCTL_H
#include <sys/ioctl.h>
#endif

#include <signal.h>
#include <errno.h>

#include <pcap.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifdef _WIN32
#include <process.h>    /* For spawning child process */
#endif

/*
 * XXX - the various BSDs appear to define BSD in <sys/param.h>; we don't
 * want to include it if it's not present on this platform, however.
 */
#if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__)
#ifndef BSD
#define BSD
#endif /* BSD */
#endif /* defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__bsdi__) */

/*
 * We don't want to do a "select()" on the pcap_t's file descriptor on
 * BSD (because "select()" doesn't work correctly on BPF devices on at
 * least some releases of some flavors of BSD), and we don't want to do
 * it on Windows (because "select()" is something for sockets, not for
 * arbitrary handles).
 *
 * We *do* want to do it on other platforms, as, on other platforms (with
 * the possible exception of Ultrix and Digital UNIX), the read timeout
 * doesn't expire if no packets have arrived, so a "pcap_dispatch()" call
 * will block until packets arrive, causing the UI to hang.
 */
#if !defined(BSD) && !defined(_WIN32)
# define MUST_DO_SELECT
#endif

#include "gtk/main.h"
#include "gtk/gtkglobals.h"
#include <epan/packet.h>
#include "file.h"
#include "capture.h"
#include "util.h"
#include "pcap-util.h"
#include "simple_dialog.h"
#include "prefs.h"
#include "globals.h"
#include "conditions.h"
#include "capture_stop_conditions.h"
#include "ringbuffer.h"

#include "wiretap/libpcap.h"
#include "wiretap/wtap.h"

#include "packet-atalk.h"
#include "packet-clip.h"
#include "packet-eth.h"
#include "packet-fddi.h"
#include "packet-null.h"
#include "packet-ppp.h"
#include "packet-raw.h"
#include "packet-sll.h"
#include "packet-tr.h"
#include "packet-ieee80211.h"
#include "packet-chdlc.h"
#include "packet-prism.h"

#ifdef WIN32
#include "capture-wpcap.h"
#endif

/*
 * Capture options.
 */
capture_options capture_opts;

static int sync_pipe[2]; /* used to sync father */
enum PIPES { READ, WRITE }; /* Constants 0 and 1 for READ and WRITE */
int quit_after_cap; /* Makes a "capture only mode". Implies -k */
gboolean capture_child;	/* if this is the child for "-S" */
static int fork_child = -1;	/* If not -1, in parent, process ID of child */
static guint cap_input_id;

/*
 * Indications sent out on the sync pipe.
 */
#define SP_CAPSTART	';'	/* capture start message */
#define SP_PACKET_COUNT	'*'	/* followed by count of packets captured since last message */
#define SP_ERROR_MSG	'!'	/* followed by length of error message that follows */
#define SP_DROPS	'#'	/* followed by count of packets dropped in capture */

#ifdef _WIN32
static guint cap_timer_id;
static int cap_timer_cb(gpointer); /* Win32 kludge to check for pipe input */
#endif

static void cap_file_input_cb(gpointer, gint, GdkInputCondition);
static void wait_for_child(gboolean);
#ifndef _WIN32
static char *signame(int);
#endif
static void capture_delete_cb(GtkWidget *, GdkEvent *, gpointer);
static void capture_stop_cb(GtkWidget *, gpointer);
static void capture_pcap_cb(u_char *, const struct pcap_pkthdr *,
  const u_char *);
static void get_capture_file_io_error(char *, int, const char *, int, gboolean);
static void send_errmsg_to_parent(const char *);
static float pct(gint, gint);
static void stop_capture(int signo);

typedef struct _loop_data {
  gboolean       go;           /* TRUE as long as we're supposed to keep capturing */
  gint           max;          /* Number of packets we're supposed to capture - 0 means infinite */
  int            err;          /* if non-zero, error seen while capturing */
  gint           linktype;
  gint           sync_packets;
  gboolean       pcap_err;     /* TRUE if error from pcap */
  gboolean       from_pipe;    /* TRUE if we are capturing data from a pipe */
  gboolean       modified;     /* TRUE if data in the pipe uses modified pcap headers */
  gboolean       byte_swapped; /* TRUE if data in the pipe is byte swapped */
  packet_counts  counts;
  wtap_dumper   *pdh;
} loop_data;

#ifndef _WIN32
static void adjust_header(loop_data *, struct pcap_hdr *, struct pcaprec_hdr *);
static int pipe_open_live(char *, struct pcap_hdr *, loop_data *, char *);
static int pipe_dispatch(int, loop_data *, struct pcap_hdr *);
#endif

/* Win32 needs the O_BINARY flag for open() */
#ifndef O_BINARY
#define O_BINARY	0
#endif

#ifdef _WIN32
/* Win32 needs a handle to the child capture process */
int child_process;
#endif

/* Add a string pointer to a NULL-terminated array of string pointers. */
static char **
add_arg(char **args, int *argc, char *arg)
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
quote_encapsulate(const char *string)
{
  char *encapsulated_string;

  encapsulated_string = g_new(char, strlen(string) + 3);
  sprintf(encapsulated_string, "\"%s\"", string);
  return encapsulated_string;
}
#endif

/* Open a specified file, or create a temporary file, and start a capture
   to the file in question. */
void
do_capture(char *capfile_name)
{
  char tmpname[128+1];
  gboolean is_tempfile;
  u_char c;
  int i;
  guint byte_count;
  char *msg;
  int err;
  int capture_succeeded;
  gboolean stats_known;
  struct pcap_stat stats;

  if (capfile_name != NULL) {
    if (capture_opts.ringbuffer_on) {
      /* ringbuffer is enabled */
      cfile.save_file_fd = ringbuf_init(capfile_name,
					capture_opts.ringbuffer_num_files);
    } else {
      /* Try to open/create the specified file for use as a capture buffer. */
      cfile.save_file_fd = open(capfile_name, O_RDWR|O_BINARY|O_TRUNC|O_CREAT,
				0600);
    }
    is_tempfile = FALSE;
  } else {
    /* Choose a random name for the capture buffer */
    cfile.save_file_fd = create_tempfile(tmpname, sizeof tmpname, "ether");
    capfile_name = g_strdup(tmpname);
    is_tempfile = TRUE;
  }
  if (cfile.save_file_fd == -1) {
    if (is_tempfile) {
      simple_dialog(ESD_TYPE_CRIT, NULL,
	"The temporary file to which the capture would be saved (\"%s\")"
	"could not be opened: %s.", capfile_name, strerror(errno));
    } else {
      if (capture_opts.ringbuffer_on) {
        ringbuf_error_cleanup();
      }
      simple_dialog(ESD_TYPE_CRIT, NULL,
	file_open_error_message(errno, TRUE), capfile_name);
    }
    return;
  }
  close_cap_file(&cfile);
  g_assert(cfile.save_file == NULL);
  cfile.save_file = capfile_name;

  if (capture_opts.sync_mode) {	/* do the capture in a child process */
    char ssnap[24];
    char scount[24];			/* need a constant for len of numbers */
    char sautostop_filesize[24];	/* need a constant for len of numbers */
    char sautostop_duration[24];	/* need a constant for len of numbers */
    char save_file_fd[24];
    char errmsg[1024+1];
    int error;
    int argc;
    char **argv;
#ifdef _WIN32
    char sync_pipe_fd[24];
    char *fontstring;
    char *filterstring;
#endif

    /* Allocate the string pointer array with enough space for the
       terminating NULL pointer. */
    argc = 0;
    argv = g_malloc(sizeof (char *));
    *argv = NULL;

    /* Now add those arguments used on all platforms. */
    argv = add_arg(argv, &argc, CHILD_NAME);

    argv = add_arg(argv, &argc, "-i");
    argv = add_arg(argv, &argc, cfile.iface);

    argv = add_arg(argv, &argc, "-w");
    argv = add_arg(argv, &argc, cfile.save_file);

    argv = add_arg(argv, &argc, "-W");
    sprintf(save_file_fd,"%d",cfile.save_file_fd);	/* in lieu of itoa */
    argv = add_arg(argv, &argc, save_file_fd);

    if (capture_opts.has_autostop_count) {
      argv = add_arg(argv, &argc, "-c");
      sprintf(scount,"%d",capture_opts.autostop_count);
      argv = add_arg(argv, &argc, scount);
    }

    if (capture_opts.has_snaplen) {
      argv = add_arg(argv, &argc, "-s");
      sprintf(ssnap,"%d",capture_opts.snaplen);
      argv = add_arg(argv, &argc, ssnap);
    }

    if (capture_opts.has_autostop_filesize) {
      argv = add_arg(argv, &argc, "-a");
      sprintf(sautostop_filesize,"filesize:%d",capture_opts.autostop_filesize);
      argv = add_arg(argv, &argc, sautostop_filesize);
    }

    if (capture_opts.has_autostop_duration) {
      argv = add_arg(argv, &argc, "-a");
      sprintf(sautostop_duration,"duration:%d",capture_opts.autostop_duration);
      argv = add_arg(argv, &argc, sautostop_duration);
    }

    if (!capture_opts.promisc_mode)
      argv = add_arg(argv, &argc, "-p");

#ifdef _WIN32
    /* Create a pipe for the child process */

    if(_pipe(sync_pipe, 512, O_BINARY) < 0) {
      /* Couldn't create the pipe between parent and child. */
      error = errno;
      unlink(cfile.save_file);
      g_free(cfile.save_file);
      cfile.save_file = NULL;
      simple_dialog(ESD_TYPE_CRIT, NULL, "Couldn't create sync pipe: %s",
                        strerror(error));
      return;
    }

    /* Convert font name to a quote-encapsulated string and pass to child */
    argv = add_arg(argv, &argc, "-m");
    fontstring = quote_encapsulate(prefs.gui_font_name);
    argv = add_arg(argv, &argc, fontstring);

    /* Convert pipe write handle to a string and pass to child */
    argv = add_arg(argv, &argc, "-Z");
    itoa(sync_pipe[WRITE], sync_pipe_fd, 10);
    argv = add_arg(argv, &argc, sync_pipe_fd);

    /* Convert filter string to a quote delimited string and pass to child */
    if (cfile.cfilter != NULL && strlen(cfile.cfilter) != 0) {
      argv = add_arg(argv, &argc, "-f");
      filterstring = quote_encapsulate(cfile.cfilter);
      argv = add_arg(argv, &argc, filterstring);
    }

    /* Spawn process */
    fork_child = spawnvp(_P_NOWAIT, ethereal_path, argv);
    g_free(fontstring);
    g_free(filterstring);
    /* Keep a copy for later evaluation by _cwait() */
    child_process = fork_child;
#else
    signal(SIGCHLD, SIG_IGN);
    if (pipe(sync_pipe) < 0) {
      /* Couldn't create the pipe between parent and child. */
      error = errno;
      unlink(cfile.save_file);
      g_free(cfile.save_file);
      cfile.save_file = NULL;
      simple_dialog(ESD_TYPE_CRIT, NULL, "Couldn't create sync pipe: %s",
			strerror(error));
      return;
    }

    argv = add_arg(argv, &argc, "-m");
    argv = add_arg(argv, &argc, prefs.gui_font_name);

    if (cfile.cfilter != NULL && strlen(cfile.cfilter) != 0) {
      argv = add_arg(argv, &argc, "-f");
      argv = add_arg(argv, &argc, cfile.cfilter);
    }

    if ((fork_child = fork()) == 0) {
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
      dup(sync_pipe[WRITE]);
      close(sync_pipe[READ]);
      execvp(ethereal_path, argv);
      snprintf(errmsg, sizeof errmsg, "Couldn't run %s in child process: %s",
		ethereal_path, strerror(errno));
      send_errmsg_to_parent(errmsg);

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
    close(sync_pipe[WRITE]);

    /* Close the save file FD, as we won't be using it - we'll be opening
       it and reading the save file through Wiretap. */
    close(cfile.save_file_fd);

    if (fork_child == -1) {
      /* We couldn't even create the child process. */
      error = errno;
      close(sync_pipe[READ]);
      unlink(cfile.save_file);
      g_free(cfile.save_file);
      cfile.save_file = NULL;
      simple_dialog(ESD_TYPE_CRIT, NULL, "Couldn't create child process: %s",
			strerror(error));
      return;
    }

    /* Read a byte count from "sync_pipe[READ]", terminated with a
       colon; if the count is 0, the child process created the
       capture file and we should start reading from it, otherwise
       the capture couldn't start and the count is a count of bytes
       of error message, and we should display the message. */
    byte_count = 0;
    for (;;) {
      i = read(sync_pipe[READ], &c, 1);
      if (i == 0) {
	/* EOF - the child process died.
	   Close the read side of the sync pipe, remove the capture file,
	   and report the failure. */
	close(sync_pipe[READ]);
	unlink(cfile.save_file);
	g_free(cfile.save_file);
	cfile.save_file = NULL;
	wait_for_child(TRUE);
	return;
      }
      if (c == SP_CAPSTART || c == SP_ERROR_MSG)
	break;
      if (!isdigit(c)) {
	/* Child process handed us crap.
	   Close the read side of the sync pipe, remove the capture file,
	   and report the failure. */
	close(sync_pipe[READ]);
	unlink(cfile.save_file);
	g_free(cfile.save_file);
	cfile.save_file = NULL;
	simple_dialog(ESD_TYPE_WARN, NULL,
			"Capture child process sent us a bad message");
	return;
      }
      byte_count = byte_count*10 + c - '0';
    }
    if (c == SP_CAPSTART) {
      /* Success.  Open the capture file, and set up to read it. */
      err = start_tail_cap_file(cfile.save_file, is_tempfile, &cfile);
      if (err == 0) {
	/* We were able to open and set up to read the capture file;
	   arrange that our callback be called whenever it's possible
	   to read from the sync pipe, so that it's called when
	   the child process wants to tell us something. */
#ifdef _WIN32
	/* Tricky to use pipes in win9x, as no concept of wait.  NT can
	   do this but that doesn't cover all win32 platforms.  GTK can do
	   this but doesn't seem to work over processes.  Attempt to do
	   something similar here, start a timer and check for data on every
	   timeout. */
	cap_timer_id = gtk_timeout_add(1000, cap_timer_cb, NULL);
#else
	cap_input_id = gtk_input_add_full(sync_pipe[READ],
				       GDK_INPUT_READ|GDK_INPUT_EXCEPTION,
				       cap_file_input_cb,
				       NULL,
				       (gpointer) &cfile,
				       NULL);
#endif
      } else {
	/* We weren't able to open the capture file; complain, and
	   close the sync pipe. */
	simple_dialog(ESD_TYPE_CRIT, NULL,
			file_open_error_message(err, FALSE), cfile.save_file);

	/* Close the sync pipe. */
	close(sync_pipe[READ]);

	/* Don't unlink the save file - leave it around, for debugging
	   purposes. */
	g_free(cfile.save_file);
	cfile.save_file = NULL;
      }
    } else {
      /* Failure - the child process sent us a message indicating
	 what the problem was. */
      if (byte_count == 0) {
	/* Zero-length message? */
	simple_dialog(ESD_TYPE_WARN, NULL,
		"Capture child process failed, but its error message was empty.");
      } else {
	msg = g_malloc(byte_count + 1);
	if (msg == NULL) {
	  simple_dialog(ESD_TYPE_WARN, NULL,
		"Capture child process failed, but its error message was too big.");
	} else {
	  i = read(sync_pipe[READ], msg, byte_count);
	  msg[byte_count] = '\0';
	  if (i < 0) {
	    simple_dialog(ESD_TYPE_WARN, NULL,
		  "Capture child process failed: Error %s reading its error message.",
		  strerror(errno));
	  } else if (i == 0) {
	    simple_dialog(ESD_TYPE_WARN, NULL,
		  "Capture child process failed: EOF reading its error message.");
	    wait_for_child(FALSE);
	  } else
	    simple_dialog(ESD_TYPE_WARN, NULL, msg);
	  g_free(msg);
	}

	/* Close the sync pipe. */
	close(sync_pipe[READ]);

	/* Get rid of the save file - the capture never started. */
	unlink(cfile.save_file);
	g_free(cfile.save_file);
	cfile.save_file = NULL;
      }
    }
  } else {
    /* Not sync mode. */
    capture_succeeded = capture(&stats_known, &stats);
    if (quit_after_cap) {
      /* DON'T unlink the save file.  Presumably someone wants it. */
      gtk_exit(0);
    }
    if (capture_succeeded) {
      /* Capture succeeded; read in the capture file. */
      if ((err = open_cap_file(cfile.save_file, is_tempfile, &cfile)) == 0) {
        /* Set the read filter to NULL. */
        cfile.rfcode = NULL;

        /* Get the packet-drop statistics.

           XXX - there are currently no packet-drop statistics stored
           in libpcap captures, and that's what we're reading.

           At some point, we will add support in Wiretap to return
	   packet-drop statistics for capture file formats that store it,
	   and will make "read_cap_file()" get those statistics from
	   Wiretap.  We clear the statistics (marking them as "not known")
	   in "open_cap_file()", and "read_cap_file()" will only fetch
	   them and mark them as known if Wiretap supplies them, so if
	   we get the statistics now, after calling "open_cap_file()" but
	   before calling "read_cap_file()", the values we store will
	   be used by "read_cap_file()".

           If a future libpcap capture file format stores the statistics,
           we'll put them into the capture file that we write, and will
	   thus not have to set them here - "read_cap_file()" will get
	   them from the file and use them. */
        if (stats_known) {
          cfile.drops_known = TRUE;

          /* XXX - on some systems, libpcap doesn't bother filling in
             "ps_ifdrop" - it doesn't even set it to zero - so we don't
             bother looking at it.

             Ideally, libpcap would have an interface that gave us
             several statistics - perhaps including various interface
             error statistics - and would tell us which of them it
             supplies, allowing us to display only the ones it does. */
          cfile.drops = stats.ps_drop;
        }
        switch (read_cap_file(&cfile, &err)) {

        case READ_SUCCESS:
        case READ_ERROR:
          /* Just because we got an error, that doesn't mean we were unable
             to read any of the file; we handle what we could get from the
             file. */
          break;

        case READ_ABORTED:
          /* Exit by leaving the main loop, so that any quit functions
             we registered get called. */
          gtk_main_quit();
          return;
        }
      }
    }
    /* We're not doing a capture any more, so we don't have a save
       file. */
    if (capture_opts.ringbuffer_on) {
      ringbuf_free();
    } else {
      g_free(cfile.save_file);
    }
    cfile.save_file = NULL;
  }
}

#ifdef _WIN32
/* The timer has expired, see if there's stuff to read from the pipe,
   if so call the cap_file_input_cb */
static gint
cap_timer_cb(gpointer data)
{
  HANDLE handle;
  DWORD avail = 0;
  gboolean result, result1;
  DWORD childstatus;

  /* Oddly enough although Named pipes don't work on win9x,
     PeekNamedPipe does !!! */
  handle = (HANDLE) _get_osfhandle (sync_pipe[READ]);
  result = PeekNamedPipe(handle, NULL, 0, NULL, &avail, NULL);

  /* Get the child process exit status */
  result1 = GetExitCodeProcess((HANDLE)child_process, &childstatus);

  /* If the Peek returned an error, or there are bytes to be read
     or the childwatcher thread has terminated then call the normal
     callback */
  if (!result || avail > 0 || childstatus != STILL_ACTIVE) {

    /* avoid reentrancy problems and stack overflow */
    gtk_timeout_remove(cap_timer_id);

    /* And call the real handler */
    cap_file_input_cb((gpointer) &cfile, 0, 0);

    /* Return false so that the timer is not run again */
    return FALSE;
  }
  else {
    /* No data so let timer run again */
    return TRUE;
  }
}
#endif

/* There's stuff to read from the sync pipe, meaning the child has sent
   us a message, or the sync pipe has closed, meaning the child has
   closed it (perhaps because it exited). */
static void 
cap_file_input_cb(gpointer data, gint source, GdkInputCondition condition)
{
  capture_file *cf = (capture_file *)data;
#define BUFSIZE	4096
  char buffer[BUFSIZE+1], *p = buffer, *q = buffer, *msg, *r;
  int  nread, msglen, chars_to_copy;
  int  to_read = 0;
  int  err;

#ifndef _WIN32
  /* avoid reentrancy problems and stack overflow */
  gtk_input_remove(cap_input_id);
#endif

  if ((nread = read(sync_pipe[READ], buffer, BUFSIZE)) <= 0) {
    /* The child has closed the sync pipe, meaning it's not going to be
       capturing any more packets.  Pick up its exit status, and
       complain if it did anything other than exit with status 0. */
    wait_for_child(FALSE);
      
    /* Read what remains of the capture file, and finish the capture.
       XXX - do something if this fails? */
    switch (finish_tail_cap_file(cf, &err)) {

    case READ_SUCCESS:
    case READ_ERROR:
      /* Just because we got an error, that doesn't mean we were unable
         to read any of the file; we handle what we could get from the
         file. */
      break;

    case READ_ABORTED:
      /* Exit by leaving the main loop, so that any quit functions
         we registered get called. */
      gtk_main_quit();
      return;
    }

    /* We're not doing a capture any more, so we don't have a save
       file. */
    g_free(cf->save_file);
    cf->save_file = NULL;

    return;
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
      cf->drops_known = TRUE;
      cf->drops = atoi(p);
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
          if ((nread = read(sync_pipe[READ], buffer, BUFSIZE)) <= 0)
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
      simple_dialog(ESD_TYPE_WARN, NULL, msg);
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
  switch (continue_tail_cap_file(cf, to_read, &err)) {

  case READ_SUCCESS:
  case READ_ERROR:
    /* Just because we got an error, that doesn't mean we were unable
       to read any of the file; we handle what we could get from the
       file.

       XXX - abort on a read error? */
    break;

  case READ_ABORTED:
    /* Kill the child capture process; the user wants to exit, and we
       shouldn't just leave it running. */
#ifdef _WIN32
    /* XXX - kill it. */
#else
    kill(fork_child, SIGTERM);	/* SIGTERM so it can clean up if necessary */
#endif
    break;
  }

  /* restore pipe handler */
#ifdef _WIN32
  cap_timer_id = gtk_timeout_add(1000, cap_timer_cb, NULL);
#else
  cap_input_id = gtk_input_add_full (sync_pipe[READ],
				     GDK_INPUT_READ|GDK_INPUT_EXCEPTION,
				     cap_file_input_cb,
				     NULL,
				     (gpointer) cf,
				     NULL);
#endif
}

static void
wait_for_child(gboolean always_report)
{
  int  wstatus;

#ifdef _WIN32
  /* XXX - analyze the wait stuatus and display more information
     in the dialog box? */
  if (_cwait(&wstatus, child_process, _WAIT_CHILD) == -1) {
    simple_dialog(ESD_TYPE_WARN, NULL, "Child capture process stopped unexpectedly");
  }
#else
  if (wait(&wstatus) != -1) {
    if (WIFEXITED(wstatus)) {
      /* The child exited; display its exit status, if it's not zero,
         and even if it's zero if "always_report" is true. */
      if (always_report || WEXITSTATUS(wstatus) != 0) {
        simple_dialog(ESD_TYPE_WARN, NULL,
		      "Child capture process exited: exit status %d",
		      WEXITSTATUS(wstatus));
      }
    } else if (WIFSTOPPED(wstatus)) {
      /* It stopped, rather than exiting.  "Should not happen." */
      simple_dialog(ESD_TYPE_WARN, NULL,
		    "Child capture process stopped: %s",
		    signame(WSTOPSIG(wstatus)));
    } else if (WIFSIGNALED(wstatus)) {
      /* It died with a signal. */
      simple_dialog(ESD_TYPE_WARN, NULL,
		    "Child capture process died: %s%s",
		    signame(WTERMSIG(wstatus)),
		    WCOREDUMP(wstatus) ? " - core dumped" : "");
    } else {
      /* What?  It had to either have exited, or stopped, or died with
         a signal; what happened here? */
      simple_dialog(ESD_TYPE_WARN, NULL,
		    "Child capture process died: wait status %#o", wstatus);
    }
  }

  /* No more child process. */
  fork_child = -1;
#endif
}

#ifndef _WIN32
static char *
signame(int sig)
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

/*
 * Timeout, in milliseconds, for reads from the stream of captured packets.
 *
 * XXX - Michael Tuexen says MacOS X's BPF appears to be broken, in that
 * if you use a timeout of 250 in "pcap_open_live()", you don't see
 * packets until a large number of packets arrive; the timeout doesn't
 * cause a smaller number of packets to be delivered.  Perhaps a timeout
 * that's less than 1 second acts like no timeout at all, so that you
 * don't see packets until the BPF buffer fills up?
 *
 * The workaround is to use a timeout of 1000 seconds on MacOS X.
 */
#ifdef __APPLE__
#define	CAP_READ_TIMEOUT	1000
#else
#define	CAP_READ_TIMEOUT	250
#endif

#ifndef _WIN32
/* Take carre of byte order in the libpcap headers read from pipes.
 * (function taken from wiretap/libpcap.c) */
static void
adjust_header(loop_data *ld, struct pcap_hdr *hdr, struct pcaprec_hdr *rechdr)
{
  if (ld->byte_swapped) {
    /* Byte-swap the record header fields. */
    rechdr->ts_sec = BSWAP32(rechdr->ts_sec);
    rechdr->ts_usec = BSWAP32(rechdr->ts_usec);
    rechdr->incl_len = BSWAP32(rechdr->incl_len);
    rechdr->orig_len = BSWAP32(rechdr->orig_len);
  }

  /* In file format version 2.3, the "incl_len" and "orig_len" fields were
     swapped, in order to match the BPF header layout.

     Unfortunately, some files were, according to a comment in the "libpcap"
     source, written with version 2.3 in their headers but without the
     interchanged fields, so if "incl_len" is greater than "orig_len" - which
     would make no sense - we assume that we need to swap them.  */
  if (hdr->version_major == 2 &&
      (hdr->version_minor < 3 ||
       (hdr->version_minor == 3 && rechdr->incl_len > rechdr->orig_len))) {
    guint32 temp;

    temp = rechdr->orig_len;
    rechdr->orig_len = rechdr->incl_len;
    rechdr->incl_len = temp;
  }
}

/* Mimic pcap_open_live() for pipe captures 
 * We check if "pipename" is "-" (stdin) or a FIFO, open it, and read the
 * header.
 * N.B. : we can't read the libpcap formats used in RedHat 6.1 or SuSE 6.3
 * because we can't seek on pipes (see wiretap/libpcap.c for details) */
static int
pipe_open_live(char *pipename, struct pcap_hdr *hdr, loop_data *ld, char *ebuf)
{
  struct stat pipe_stat;
  int         fd;
  guint32     magic;
  int         bytes_read, b;

  if (strcmp(pipename, "-") == 0) fd = 0; /* read from stdin */
  else if (stat(pipename, &pipe_stat) == 0 && S_ISFIFO(pipe_stat.st_mode)) {
    if ((fd = open(pipename, O_RDONLY)) == -1) return -1;
  } else return -1;

  ld->from_pipe = TRUE;
  /* read the pcap header */
  if (read(fd, &magic, sizeof magic) != sizeof magic) {
    close(fd);
    return -1;
  }

  switch (magic) {
  case PCAP_MAGIC:
    /* Host that wrote it has our byte order, and was running
       a program using either standard or ss990417 libpcap. */
    ld->byte_swapped = FALSE;
    ld->modified = FALSE;
    break;
  case PCAP_MODIFIED_MAGIC:
    /* Host that wrote it has our byte order, but was running
       a program using either ss990915 or ss991029 libpcap. */
    ld->byte_swapped = FALSE;
    ld->modified = TRUE;
    break;
  case PCAP_SWAPPED_MAGIC:
    /* Host that wrote it has a byte order opposite to ours,
       and was running a program using either standard or
       ss990417 libpcap. */
    ld->byte_swapped = TRUE;
    ld->modified = FALSE;
    break;
  case PCAP_SWAPPED_MODIFIED_MAGIC:
    /* Host that wrote it out has a byte order opposite to
       ours, and was running a program using either ss990915
       or ss991029 libpcap. */
    ld->byte_swapped = TRUE;
    ld->modified = TRUE;
    break;
  default:
    /* Not a "libpcap" type we know about. */
    close(fd);
    return -1;
  }

  /* Read the rest of the header */
  bytes_read = read(fd, hdr, sizeof(struct pcap_hdr));
  if (bytes_read <= 0) {
    close(fd);
    return -1;
  }
  while ((unsigned) bytes_read < sizeof(struct pcap_hdr))
  {
    b = read(fd, ((char *)&hdr)+bytes_read, sizeof(struct pcap_hdr) - bytes_read);
    if (b <= 0) {
      close(fd);
      return -1;
    }
    bytes_read += b;
  }
  if (ld->byte_swapped) {
    /* Byte-swap the header fields about which we care. */
    hdr->version_major = BSWAP16(hdr->version_major);
    hdr->version_minor = BSWAP16(hdr->version_minor);
    hdr->snaplen = BSWAP32(hdr->snaplen);
    hdr->network = BSWAP32(hdr->network);
  }
  if (hdr->version_major < 2) {
    close(fd);
    return -1;
  }

  return fd;
}

/* We read one record from the pipe, take care of byte order in the record
 * header, write the record in the capture file, and update capture statistics. */
static int
pipe_dispatch(int fd, loop_data *ld, struct pcap_hdr *hdr)
{
  struct wtap_pkthdr whdr;
  struct pcaprec_modified_hdr rechdr;
  int bytes_to_read, bytes_read, b;
  u_char pd[WTAP_MAX_PACKET_SIZE];
  int err;

  /* read the record header */
  bytes_to_read = ld->modified ? sizeof rechdr : sizeof rechdr.hdr;
  bytes_read = read(fd, &rechdr, bytes_to_read);
  if (bytes_read <= 0) {
    close(fd);
    ld->go = FALSE;
    return 0;
  }
  while (bytes_read < bytes_to_read)
  {
    b = read(fd, ((char *)&rechdr)+bytes_read, bytes_to_read - bytes_read);
    if (b <= 0) {
      close(fd);
      ld->go = FALSE;
      return 0;
    }
    bytes_read += b;
  }
  /* take care of byte order */
  adjust_header(ld, hdr, &rechdr.hdr);
  if (rechdr.hdr.incl_len > WTAP_MAX_PACKET_SIZE) {
    close(fd);
    ld->go = FALSE;
    return 0;
  }
  /* read the packet data */
  bytes_read = read(fd, pd, rechdr.hdr.incl_len);
  if (bytes_read <= 0) {
    close(fd);
    ld->go = FALSE;
    return 0;
  }
  while ((unsigned) bytes_read < rechdr.hdr.incl_len)
  {
    b = read(fd, pd+bytes_read, rechdr.hdr.incl_len - bytes_read);
    if (b <= 0) {
      close(fd);
      ld->go = FALSE;
      return 0;
    }
    bytes_read += b;
  }
  /* dump the packet data to the capture file */
  whdr.ts.tv_sec = rechdr.hdr.ts_sec;
  whdr.ts.tv_usec = rechdr.hdr.ts_usec;
  whdr.caplen = rechdr.hdr.incl_len;
  whdr.len = rechdr.hdr.orig_len;
  whdr.pkt_encap = ld->linktype;
  wtap_dump(ld->pdh, &whdr, NULL, pd, &err);

  /* update capture statistics */
  switch (ld->linktype) {
    case WTAP_ENCAP_ETHERNET:
      capture_eth(pd, 0, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_FDDI:
    case WTAP_ENCAP_FDDI_BITSWAPPED:
      capture_fddi(pd, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_PRISM_HEADER:
      capture_prism(pd, 0, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_TOKEN_RING:
      capture_tr(pd, 0, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_NULL:
      capture_null(pd, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_PPP:
      capture_ppp_hdlc(pd, 0, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_RAW_IP:
      capture_raw(pd, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_LINUX_ATM_CLIP:
      capture_clip(pd, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_IEEE_802_11:
      capture_ieee80211(pd, 0, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_CHDLC:
      capture_chdlc(pd, 0, whdr.caplen, &ld->counts);
      break;
    case WTAP_ENCAP_LOCALTALK:
      capture_llap(pd, whdr.caplen, &ld->counts);
      break;
    /* XXX - FreeBSD may append 4-byte ATM pseudo-header to DLT_ATM_RFC1483,
       with LLC header following; we should implement it at some
       point. */
  }

  return 1;
}
#endif

/*
 * This needs to be static, so that the SIGUSR1 handler can clear the "go"
 * flag.
 */
static loop_data   ld;

/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */
int
capture(gboolean *stats_known, struct pcap_stat *stats)
{
  GtkWidget  *cap_w, *main_vb, *stop_bt, *counts_tb;
  pcap_t     *pch;
  int         pcap_encap;
  int         file_snaplen;
  gchar       open_err_str[PCAP_ERRBUF_SIZE];
  gchar       lookup_net_err_str[PCAP_ERRBUF_SIZE];
  gchar       label_str[64];
  bpf_u_int32 netnum, netmask;
  struct bpf_program fcode;
  time_t      upd_time, cur_time;
  int         err, inpkts;
  condition  *cnd_stop_capturesize = NULL;
  condition  *cnd_stop_timeout = NULL;
  unsigned int i;
  static const char capstart_msg = SP_CAPSTART;
  char        errmsg[4096+1];
  gboolean    dump_ok;
#ifndef _WIN32
  static const char ppamsg[] = "can't find PPA for ";
  char       *libpcap_warn;
#endif
  fd_set      set1;
  struct timeval timeout;
#ifdef MUST_DO_SELECT
  int         pcap_fd = 0;
#endif
#ifdef _WIN32 
  WORD wVersionRequested; 
  WSADATA wsaData; 
#endif
#ifndef _WIN32
  int         pipe_fd = -1;
  struct pcap_hdr hdr;
#endif
  struct {
      const gchar *title;
      gint *value_ptr;
      GtkWidget *label, *value, *percent;
  } counts[] = {
      { "Total", &ld.counts.total, NULL, NULL, NULL },
      { "SCTP", &ld.counts.sctp, NULL, NULL, NULL },
      { "TCP", &ld.counts.tcp, NULL, NULL, NULL },
      { "UDP", &ld.counts.udp, NULL, NULL, NULL },
      { "ICMP", &ld.counts.icmp, NULL, NULL, NULL },
      { "OSPF", &ld.counts.ospf, NULL, NULL, NULL },
      { "GRE", &ld.counts.gre, NULL, NULL, NULL },
      { "NetBIOS", &ld.counts.netbios, NULL, NULL, NULL },
      { "IPX", &ld.counts.ipx, NULL, NULL, NULL },
      { "VINES", &ld.counts.vines, NULL, NULL, NULL },
      { "Other", &ld.counts.other, NULL, NULL, NULL }
  };

#define N_COUNTS (sizeof counts / sizeof counts[0])

  /* Initialize Windows Socket if we are in a WIN32 OS 
     This needs to be done before querying the interface for network/netmask */
#ifdef _WIN32 
  wVersionRequested = MAKEWORD( 1, 1 ); 
  err = WSAStartup( wVersionRequested, &wsaData ); 
  if (err!=0) { 
    snprintf(errmsg, sizeof errmsg, 
      "Couldn't initialize Windows Sockets."); 
	pch=NULL; 
    goto error; 
  } 
#endif 

  ld.go             = TRUE;
  ld.counts.total   = 0;
  if (capture_opts.has_autostop_count)
    ld.max          = capture_opts.autostop_count;
  else
    ld.max          = 0;	/* no limit */
  ld.err            = 0;	/* no error seen yet */
  ld.linktype       = WTAP_ENCAP_UNKNOWN;
  ld.pcap_err       = FALSE;
  ld.from_pipe      = FALSE;
  ld.sync_packets   = 0;
  ld.counts.sctp    = 0;
  ld.counts.tcp     = 0;
  ld.counts.udp     = 0;
  ld.counts.icmp    = 0;
  ld.counts.ospf    = 0;
  ld.counts.gre     = 0;
  ld.counts.ipx     = 0;
  ld.counts.netbios = 0;
  ld.counts.vines   = 0;
  ld.counts.other   = 0;
  ld.pdh            = NULL;

  /* We haven't yet gotten the capture statistics. */
  *stats_known      = FALSE;

  /* Open the network interface to capture from it.
     Some versions of libpcap may put warnings into the error buffer
     if they succeed; to tell if that's happened, we have to clear
     the error buffer, and check if it's still a null string.  */
  open_err_str[0] = '\0';
  pch = pcap_open_live(cfile.iface,
		       capture_opts.has_snaplen ? capture_opts.snaplen :
						  WTAP_MAX_PACKET_SIZE,
		       capture_opts.promisc_mode, CAP_READ_TIMEOUT,
		       open_err_str);

  if (pch == NULL) {
#ifdef _WIN32
    /* Well, we couldn't start the capture.
       If this is a child process that does the capturing in sync
       mode or fork mode, it shouldn't do any UI stuff until we pop up the
       capture-progress window, and, since we couldn't start the
       capture, we haven't popped it up. */
    if (!capture_child) {
      while (gtk_events_pending()) gtk_main_iteration();
    }

    /* On Win32 OSes, the capture devices are probably available to all
       users; don't warn about permissions problems.

       Do, however, warn that WAN devices aren't supported. */
    snprintf(errmsg, sizeof errmsg,
	"The capture session could not be initiated (%s).\n"
	"Please check that you have the proper interface specified.\n"
	"\n"
	"Note that the driver Ethereal uses for packet capture on Windows\n"
	"doesn't support capturing on PPP/WAN interfaces in Windows NT/2000.\n",
	open_err_str);
    goto error;
#else
    /* try to open cfile.iface as a pipe */
    pipe_fd = pipe_open_live(cfile.iface, &hdr, &ld, open_err_str);

    if (pipe_fd == -1) {
      /* Well, we couldn't start the capture.
	 If this is a child process that does the capturing in sync
	 mode or fork mode, it shouldn't do any UI stuff until we pop up the
	 capture-progress window, and, since we couldn't start the
	 capture, we haven't popped it up. */
      if (!capture_child) {
	while (gtk_events_pending()) gtk_main_iteration();
      }

      /* If we got a "can't find PPA for XXX" message, warn the user (who
         is running Ethereal on HP-UX) that they don't have a version
	 of libpcap that properly handles HP-UX (libpcap 0.6.x and later
	 versions, which properly handle HP-UX, say "can't find /dev/dlpi
	 PPA for XXX" rather than "can't find PPA for XXX"). */
      if (strncmp(open_err_str, ppamsg, sizeof ppamsg - 1) == 0)
	libpcap_warn =
	  "\n\n"
	  "You are running Ethereal with a version of the libpcap library\n"
	  "that doesn't handle HP-UX network devices well; this means that\n"
	  "Ethereal may not be able to capture packets.\n"
	  "\n"
	  "To fix this, you should install libpcap 0.6.2, or a later version\n"
	  "of libpcap, rather than libpcap 0.4 or 0.5.x.  It is available in\n"
	  "packaged binary form from the Software Porting And Archive Centre\n"
	  "for HP-UX; the Centre is at http://hpux.connect.org.uk/ - the page\n"
	  "at the URL lists a number of mirror sites.";
      else
	libpcap_warn = "";
      snprintf(errmsg, sizeof errmsg,
	  "The capture session could not be initiated (%s).\n"
	  "Please check to make sure you have sufficient permissions, and that\n"
	  "you have the proper interface or pipe specified.%s", open_err_str,
	  libpcap_warn);
      goto error;
    }
#endif
  }

  /* capture filters only work on real interfaces */
  if (cfile.cfilter && !ld.from_pipe) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet(cfile.iface, &netnum, &netmask, lookup_net_err_str) < 0) {
      /*
       * Well, we can't get the netmask for this interface; it's used
       * only for filters that check for broadcast IP addresses, so
       * we just punt and use 0.  It might be nice to warn the user,
       * but that's a pain in a GUI application, as it'd involve popping
       * up a message box, and it's not clear how often this would make
       * a difference (only filters that check for IP broadcast addresses
       * use the netmask).
       */
      netmask = 0;
    }
    if (pcap_compile(pch, &fcode, cfile.cfilter, 1, netmask) < 0) {
      snprintf(errmsg, sizeof errmsg, "Unable to parse filter string (%s).",
	pcap_geterr(pch));
      goto error;
    }
    if (pcap_setfilter(pch, &fcode) < 0) {
      snprintf(errmsg, sizeof errmsg, "Can't install filter (%s).",
	pcap_geterr(pch));
      goto error;
    }
  }

  /* Set up to write to the capture file. */
#ifndef _WIN32
  if (ld.from_pipe) {
    pcap_encap = hdr.network;
    file_snaplen = hdr.snaplen;
  } else
#endif
  {
    pcap_encap = get_pcap_linktype(pch, cfile.iface);
    file_snaplen = pcap_snapshot(pch);
  }
  ld.linktype = wtap_pcap_encap_to_wtap_encap(pcap_encap);
  if (ld.linktype == WTAP_ENCAP_UNKNOWN) {
    snprintf(errmsg, sizeof errmsg,
	"The network you're capturing from is of a type"
	" that Ethereal doesn't support (data link type %d).", pcap_encap);
    goto error;
  }
  if (capture_opts.ringbuffer_on) {
    ld.pdh = ringbuf_init_wtap_dump_fdopen(WTAP_FILE_PCAP, ld.linktype, 
      file_snaplen, &err);
  } else {
    ld.pdh = wtap_dump_fdopen(cfile.save_file_fd, WTAP_FILE_PCAP,
      ld.linktype, file_snaplen, &err);
  }

  if (ld.pdh == NULL) {
    /* We couldn't set up to write to the capture file. */
    switch (err) {

    case WTAP_ERR_CANT_OPEN:
      strcpy(errmsg, "The file to which the capture would be saved"
               " couldn't be created for some unknown reason.");
      break;

    case WTAP_ERR_SHORT_WRITE:
      strcpy(errmsg, "A full header couldn't be written to the file"
               " to which the capture would be saved.");
      break;

    default:
      if (err < 0) {
        snprintf(errmsg, sizeof(errmsg),
		     "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: Error %d.",
 			cfile.save_file, err);
      } else {
        snprintf(errmsg, sizeof(errmsg),
		     "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: %s.",
 			cfile.save_file, strerror(err));
      }
      break;
    }
    goto error;
  }

  /* Does "open_err_str" contain a non-empty string?  If so, "pcap_open_live()"
     returned a warning; print it, but keep capturing. */
  if (open_err_str[0] != '\0')
    g_warning("%s.", open_err_str);

  /* XXX - capture SIGTERM and close the capture, in case we're on a
     Linux 2.0[.x] system and you have to explicitly close the capture
     stream in order to turn promiscuous mode off?  We need to do that
     in other places as well - and I don't think that works all the
     time in any case, due to libpcap bugs. */

  if (capture_child) {
    /* Well, we should be able to start capturing.

       This is the child process for a sync mode capture, so sync out
       the capture file, so the header makes it to the file system,
       and send a "capture started successfully and capture file created"
       message to our parent so that they'll open the capture file and
       update its windows to indicate that we have a live capture in
       progress. */
    fflush(wtap_dump_file(ld.pdh));
    write(1, &capstart_msg, 1);
  }

  cap_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(cap_w), "Ethereal: Capture");
  gtk_window_set_modal(GTK_WINDOW(cap_w), TRUE);

  /* Container for capture display widgets */
  main_vb = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(cap_w), main_vb);
  gtk_widget_show(main_vb);

  /* Individual statistic elements */
  counts_tb = gtk_table_new(N_COUNTS, 3, TRUE);
  gtk_box_pack_start(GTK_BOX(main_vb), counts_tb, TRUE, TRUE, 3);
  gtk_widget_show(counts_tb);

  for (i = 0; i < N_COUNTS; i++) {
      counts[i].label = gtk_label_new(counts[i].title);
      gtk_misc_set_alignment(GTK_MISC(counts[i].label), 0.0f, 0.0f);

      counts[i].value = gtk_label_new("0");
      gtk_misc_set_alignment(GTK_MISC(counts[i].value), 0.0f, 0.0f);

      counts[i].percent = gtk_label_new("0.0%");
      gtk_misc_set_alignment(GTK_MISC(counts[i].percent), 0.0f, 0.0f);

      gtk_table_attach_defaults(GTK_TABLE(counts_tb),
                                counts[i].label, 0, 1, i, i + 1);

      gtk_table_attach(GTK_TABLE(counts_tb),
                       counts[i].value,
                       1, 2, i, i + 1, 0, 0, 5, 0);

      gtk_table_attach_defaults(GTK_TABLE(counts_tb),
                                counts[i].percent, 2, 3, i, i + 1);

      gtk_widget_show(counts[i].label);
      gtk_widget_show(counts[i].value);
      gtk_widget_show(counts[i].percent);
  }

  /* allow user to either click a stop button, or the close button on
	the window to stop a capture in progress. */
  stop_bt = gtk_button_new_with_label ("Stop");
  gtk_signal_connect(GTK_OBJECT(stop_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_stop_cb), (gpointer) &ld);
  gtk_signal_connect(GTK_OBJECT(cap_w), "delete_event",
	GTK_SIGNAL_FUNC(capture_delete_cb), (gpointer) &ld);
  gtk_box_pack_end(GTK_BOX(main_vb), stop_bt, FALSE, FALSE, 3);
  GTK_WIDGET_SET_FLAGS(stop_bt, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(stop_bt);
  GTK_WIDGET_SET_FLAGS(stop_bt, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(stop_bt);
  gtk_widget_show(stop_bt);

  gtk_widget_show(cap_w);

  upd_time = time(NULL);
#ifdef MUST_DO_SELECT
  if (!ld.from_pipe) pcap_fd = pcap_fileno(pch);
#endif

#ifndef _WIN32
  /*
   * Catch SIGUSR1, so that we exit cleanly if the parent process
   * kills us with it due to the user selecting "Capture->Stop".
   */
  signal(SIGUSR1, stop_capture);
#endif
  /* initialize capture stop conditions */ 
  init_capture_stop_conditions();
  /* create stop conditions */
  if (capture_opts.has_autostop_filesize)
    cnd_stop_capturesize =
        cnd_new(CND_CLASS_CAPTURESIZE,(long)capture_opts.autostop_filesize * 1000); 
  if (capture_opts.has_autostop_duration)
    cnd_stop_timeout =
        cnd_new(CND_CLASS_TIMEOUT,(gint32)capture_opts.autostop_duration);

  while (ld.go) {
    while (gtk_events_pending()) gtk_main_iteration();

#ifndef _WIN32
    if (ld.from_pipe) {
      FD_ZERO(&set1);
      FD_SET(pipe_fd, &set1);
      timeout.tv_sec = 0;
      timeout.tv_usec = CAP_READ_TIMEOUT*1000;
      if (select(pipe_fd+1, &set1, NULL, NULL, &timeout) != 0) {
	/*
	 * "select()" says we can read from the pipe without blocking; go for
	 * it. We are not sure we can read a whole record, but at least the
	 * begninning of one. pipe_dispatch() will block reading the whole
	 * record.
	 */
	inpkts = pipe_dispatch(pipe_fd, &ld, &hdr);
      } else
	inpkts = 0;
    }
    else
#endif
    {
#ifdef MUST_DO_SELECT
      /*
       * Sigh.  The semantics of the read timeout argument to
       * "pcap_open_live()" aren't particularly well specified by
       * the "pcap" man page - at least with the BSD BPF code, the
       * intent appears to be, at least in part, a way of cutting
       * down the number of reads done on a capture, by blocking
       * until the buffer fills or a timer expires - and the Linux
       * libpcap doesn't actually support it, so we can't use it
       * to break out of the "pcap_dispatch()" every 1/4 of a second
       * or so.  Linux's libpcap is not the only libpcap that doesn't
       * support the read timeout.
       *
       * Furthermore, at least on Solaris, the bufmod STREAMS module's
       * read timeout won't go off if no data has arrived, i.e. it cannot
       * be used to guarantee that a read from a DLPI stream will return
       * within a specified amount of time regardless of whether any
       * data arrives or not.
       *
       * Thus, on all platforms other than BSD, we do a "select()" on the
       * file descriptor for the capture, with a timeout of CAP_READ_TIMEOUT
       * milliseconds, or CAP_READ_TIMEOUT*1000 microseconds.
       *
       * "select()", on BPF devices, doesn't work as you might expect;
       * at least on some versions of some flavors of BSD, the timer
       * doesn't start until a read is done, so it won't expire if
       * only a "select()" or "poll()" is posted.
       */
      FD_ZERO(&set1);
      FD_SET(pcap_fd, &set1);
      timeout.tv_sec = 0;
      timeout.tv_usec = CAP_READ_TIMEOUT*1000;
      if (select(pcap_fd+1, &set1, NULL, NULL, &timeout) != 0) {
	/*
	 * "select()" says we can read from it without blocking; go for
	 * it.
	 */
	inpkts = pcap_dispatch(pch, 1, capture_pcap_cb, (u_char *) &ld);
	if (inpkts < 0) {
	  ld.pcap_err = TRUE;
	  ld.go = FALSE;
	}
      } else
	inpkts = 0;
#else
      inpkts = pcap_dispatch(pch, 1, capture_pcap_cb, (u_char *) &ld);
      if (inpkts < 0) {
        ld.pcap_err = TRUE;
        ld.go = FALSE;
      }
#endif
    }
    if (inpkts > 0)
      ld.sync_packets += inpkts;
    /* check capture stop conditons */
    if (cnd_stop_timeout != NULL && cnd_eval(cnd_stop_timeout)) {
      /* The specified capture time has elapsed; stop the capture. */
      ld.go = FALSE;
    } else if (cnd_stop_capturesize != NULL && cnd_eval(cnd_stop_capturesize, 
                  (guint32)wtap_get_bytes_dumped(ld.pdh))){
      /* Capture file reached its maximum size. */
      if (capture_opts.ringbuffer_on) {
        /* Switch to the next ringbuffer file */
        if (ringbuf_switch_file(&cfile, &ld.pdh, &ld.err)) {
          /* File switch succeeded: reset the condition */
          cnd_reset(cnd_stop_capturesize);
        } else {
          /* File switch failed: stop here */
          ld.go = FALSE;
          continue;
        }
      } else {
        /* no ringbuffer - just stop */
        ld.go = FALSE;
      }
    }
    /* Only update once a second so as not to overload slow displays */
    cur_time = time(NULL);
    if (cur_time > upd_time) {
      upd_time = cur_time;

      for (i = 0; i < N_COUNTS; i++) {
          snprintf(label_str, sizeof(label_str), "%d",
                   *counts[i].value_ptr);

          gtk_label_set(GTK_LABEL(counts[i].value), label_str);

          snprintf(label_str, sizeof(label_str), "(%.1f%%)",
                   pct(*counts[i].value_ptr, ld.counts.total));

          gtk_label_set(GTK_LABEL(counts[i].percent), label_str);
      }

      /* do sync here, too */
      fflush(wtap_dump_file(ld.pdh));
      if (capture_child && ld.sync_packets) {
	/* This is the child process for a sync mode capture, so send
	   our parent a message saying we've written out "ld.sync_packets"
	   packets to the capture file. */
	char tmp[20];
	sprintf(tmp, "%d%c", ld.sync_packets, SP_PACKET_COUNT);
	write(1, tmp, strlen(tmp));
	ld.sync_packets = 0;
      }
    }
  }
    
  /* delete stop conditions */
  if (cnd_stop_capturesize != NULL)
    cnd_delete(cnd_stop_capturesize);
  if (cnd_stop_timeout != NULL)
    cnd_delete(cnd_stop_timeout);

  if (ld.pcap_err) {
    snprintf(errmsg, sizeof(errmsg), "Error while capturing packets: %s",
      pcap_geterr(pch));
    if (capture_child) {
      /* Tell the parent, so that they can pop up the message;
         we're going to exit, so if we try to pop it up, either
         it won't pop up or it'll disappear as soon as we exit. */
      send_errmsg_to_parent(errmsg);
    } else {
     /* Just pop up the message ourselves. */
     simple_dialog(ESD_TYPE_WARN, NULL, "%s", errmsg);
    }
  }

  if (ld.err != 0) {
    get_capture_file_io_error(errmsg, sizeof(errmsg), cfile.save_file, ld.err,
			      FALSE);
    if (capture_child) {
      /* Tell the parent, so that they can pop up the message;
         we're going to exit, so if we try to pop it up, either
         it won't pop up or it'll disappear as soon as we exit. */
      send_errmsg_to_parent(errmsg);
    } else {
     /* Just pop up the message ourselves. */
     simple_dialog(ESD_TYPE_WARN, NULL, "%s", errmsg);
    }

    /* A write failed, so we've already told the user there's a problem;
       if the close fails, there's no point in telling them about that
       as well. */
    if (capture_opts.ringbuffer_on) {
      ringbuf_wtap_dump_close(&cfile, &err);
    } else {
      wtap_dump_close(ld.pdh, &err);
    }
   } else {
    if (capture_opts.ringbuffer_on) {
      dump_ok = ringbuf_wtap_dump_close(&cfile, &err);
    } else {
      dump_ok = wtap_dump_close(ld.pdh, &err);
    }
    if (!dump_ok) {
      get_capture_file_io_error(errmsg, sizeof(errmsg), cfile.save_file, err,
				TRUE);
      if (capture_child) {
        /* Tell the parent, so that they can pop up the message;
           we're going to exit, so if we try to pop it up, either
           it won't pop up or it'll disappear as soon as we exit. */
        send_errmsg_to_parent(errmsg);
      } else {
       /* Just pop up the message ourselves. */
       simple_dialog(ESD_TYPE_WARN, NULL, "%s", errmsg);
      }
    }
  }
#ifndef _WIN32
  if (ld.from_pipe)
    close(pipe_fd);
  else
#endif
  {
    /* Get the capture statistics, so we know how many packets were
       dropped. */
    if (pcap_stats(pch, stats) >= 0) {
      *stats_known = TRUE;
      if (capture_child) {
      	/* Let the parent process know. */
	char tmp[20];
	sprintf(tmp, "%d%c", stats->ps_drop, SP_DROPS);
	write(1, tmp, strlen(tmp));
      }
    } else {
      snprintf(errmsg, sizeof(errmsg),
		"Can't get packet-drop statistics: %s",
		pcap_geterr(pch));
      if (capture_child) {
        /* Tell the parent, so that they can pop up the message;
           we're going to exit, so if we try to pop it up, either
           it won't pop up or it'll disappear as soon as we exit. */
        send_errmsg_to_parent(errmsg);
      } else {
       /* Just pop up the message ourselves. */
       simple_dialog(ESD_TYPE_WARN, NULL, "%s", errmsg);
      }
    }
    pcap_close(pch);
  }

#ifdef WIN32
  /* Shut down windows sockets */
  WSACleanup();
#endif

  gtk_grab_remove(GTK_WIDGET(cap_w));
  gtk_widget_destroy(GTK_WIDGET(cap_w));

  return TRUE;

error:
  if (capture_opts.ringbuffer_on) {
    /* cleanup ringbuffer */
    ringbuf_error_cleanup();
  } else {
    /* We can't use the save file, and we have no wtap_dump stream
       to close in order to close it, so close the FD directly. */
    close(cfile.save_file_fd);

    /* We couldn't even start the capture, so get rid of the capture
       file. */
    unlink(cfile.save_file); /* silently ignore error */
    g_free(cfile.save_file);
  }
  cfile.save_file = NULL;
  if (capture_child) {
    /* This is the child process for a sync mode capture.
       Send the error message to our parent, so they can display a
       dialog box containing it. */
    send_errmsg_to_parent(errmsg);
  } else {
    /* Display the dialog box ourselves; there's no parent. */
    simple_dialog(ESD_TYPE_CRIT, NULL, "%s", errmsg);
  }
  if (pch != NULL && !ld.from_pipe)
    pcap_close(pch);

  return FALSE;
}

static void
get_capture_file_io_error(char *errmsg, int errmsglen, const char *fname,
			  int err, gboolean is_close)
{
  switch (err) {

  case ENOSPC:
    snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\") because there is no space left on the file system\n"
		"on which that file resides.",
		fname);
    break;

#ifdef EDQUOT
  case EDQUOT:
    snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\") because you are too close to, or over,"
		" your disk quota\n"
		"on the file system on which that file resides.",
		fname);
  break;
#endif

  case WTAP_ERR_CANT_CLOSE:
    snprintf(errmsg, errmsglen,
		"The file to which the capture was being saved"
		" couldn't be closed for some unknown reason.");
    break;

  case WTAP_ERR_SHORT_WRITE:
    snprintf(errmsg, errmsglen,
		"Not all the packets could be written to the file"
		" to which the capture was being saved\n"
		"(\"%s\").",
		fname);
    break;

  default:
    if (is_close) {
      snprintf(errmsg, errmsglen,
		"The file to which the capture was being saved\n"
		"(\"%s\") could not be closed: %s.",
		fname, wtap_strerror(err));
    } else {
      snprintf(errmsg, errmsglen,
		"An error occurred while writing to the file"
		" to which the capture was being saved\n"
		"(\"%s\"): %s.",
		fname, wtap_strerror(err));
    }
    break;
  }
}

static void
send_errmsg_to_parent(const char *errmsg)
{
    int msglen = strlen(errmsg);
    char lenbuf[10+1+1];

    sprintf(lenbuf, "%u%c", msglen, SP_ERROR_MSG);
    write(1, lenbuf, strlen(lenbuf));
    write(1, errmsg, msglen);
}

static float
pct(gint num, gint denom) {
  if (denom) {
    return (float) num * 100.0 / (float) denom;
  } else {
    return 0.0;
  }
}

static void
stop_capture(int signo)
{
  ld.go = FALSE;
}

static void
capture_delete_cb(GtkWidget *w, GdkEvent *event, gpointer data) {
  capture_stop_cb(NULL, data);
}

static void
capture_stop_cb(GtkWidget *w, gpointer data) {
  loop_data *ld = (loop_data *) data;
  
  ld->go = FALSE;
}

void
capture_stop(void)
{
  /*
   * XXX - find some way of signaling the child in Win32.
   */
#ifndef _WIN32
  if (fork_child != -1)
      kill(fork_child, SIGUSR1);
#endif
}

void
kill_capture_child(void)
{
  /*
   * XXX - find some way of signaling the child in Win32.
   */
#ifndef _WIN32
  if (fork_child != -1)
    kill(fork_child, SIGTERM);	/* SIGTERM so it can clean up if necessary */
#endif
}

static void
capture_pcap_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *pd) {
  struct wtap_pkthdr whdr;
  loop_data *ld = (loop_data *) user;
  int err;

  if ((++ld->counts.total >= ld->max) && (ld->max > 0)) 
  {
     ld->go = FALSE;
  }
  if (ld->pdh) {
     /* "phdr->ts" may not necessarily be a "struct timeval" - it may
        be a "struct bpf_timeval", with member sizes wired to 32
	bits - and we may go that way ourselves in the future, so
	copy the members individually. */
     whdr.ts.tv_sec = phdr->ts.tv_sec;
     whdr.ts.tv_usec = phdr->ts.tv_usec;
     whdr.caplen = phdr->caplen;
     whdr.len = phdr->len;
     whdr.pkt_encap = ld->linktype;

     /* If this fails, set "ld->go" to FALSE, to stop the capture, and set
        "ld->err" to the error. */
     if (!wtap_dump(ld->pdh, &whdr, NULL, pd, &err)) {
       ld->go = FALSE;
       ld->err = err;
     }
  }

  switch (ld->linktype) {
    case WTAP_ENCAP_ETHERNET:
      capture_eth(pd, 0, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_FDDI:
    case WTAP_ENCAP_FDDI_BITSWAPPED:
      capture_fddi(pd, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_PRISM_HEADER:
      capture_prism(pd, 0, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_TOKEN_RING:
      capture_tr(pd, 0, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_NULL:
      capture_null(pd, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_PPP:
      capture_ppp_hdlc(pd, 0, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_RAW_IP:
      capture_raw(pd, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_SLL:
      capture_sll(pd, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_LINUX_ATM_CLIP:
      capture_clip(pd, phdr->len, &ld->counts);
      break;
    case WTAP_ENCAP_LOCALTALK:
      capture_llap(pd, phdr->len, &ld->counts);
      break;
    /* XXX - FreeBSD may append 4-byte ATM pseudo-header to DLT_ATM_RFC1483,
       with LLC header following; we should implement it at some
       point. */
  }
}

#endif /* HAVE_LIBPCAP */
