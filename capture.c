/* capture.c
 * Routines for packet capture windows
 *
 * $Id: capture.c,v 1.117 2000/08/11 13:34:41 deniel Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#ifdef HAVE_IO_H
#include <io.h>
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

#ifdef HAVE_NET_IF_H
#include <net/if.h>
#endif

#include <signal.h>
#include <errno.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#ifndef lib_pcap_h
#include <pcap.h>
#endif

#ifdef _WIN32
#include <process.h>    /* For spawning child process */
#endif

#include "gtk/main.h"
#include "gtk/gtkglobals.h"
#include "packet.h"
#include "file.h"
#include "capture.h"
#include "util.h"
#include "simple_dialog.h"
#include "prefs.h"
#include "globals.h"

#include "wiretap/libpcap.h"
#include "wiretap/wtap-int.h"

#include "packet-clip.h"
#include "packet-eth.h"
#include "packet-fddi.h"
#include "packet-null.h"
#include "packet-ppp.h"
#include "packet-raw.h"
#include "packet-tr.h"

int sync_mode;	/* fork a child to do the capture, and sync between them */
static int sync_pipe[2]; /* used to sync father */
enum PIPES { READ, WRITE }; /* Constants 0 and 1 for READ and WRITE */
int quit_after_cap; /* Makes a "capture only mode". Implies -k */
gboolean capture_child;	/* if this is the child for "-S" */
static int fork_child;	/* In parent, process ID of child */
static guint cap_input_id;

#ifdef _WIN32
static guint cap_timer_id;
static int cap_timer_cb(gpointer); /* Win32 kludge to check for pipe input */
#endif

static void cap_file_input_cb(gpointer, gint, GdkInputCondition);
static void capture_delete_cb(GtkWidget *, GdkEvent *, gpointer);
static void capture_stop_cb(GtkWidget *, gpointer);
static void capture_pcap_cb(u_char *, const struct pcap_pkthdr *,
  const u_char *);
static void send_errmsg_to_parent(const char *);
static float pct(gint, gint);

typedef struct _loop_data {
  gint           go;
  gint           max;
  gint           linktype;
  gint           sync_packets;
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

  if (capfile_name != NULL) {
    /* Try to open/create the specified file for use as a capture buffer. */
    cfile.save_file_fd = open(capfile_name, O_RDWR|O_BINARY|O_TRUNC|O_CREAT, 0600);
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
      simple_dialog(ESD_TYPE_CRIT, NULL,
	file_open_error_message(errno, TRUE), capfile_name);
    }
    return;
  }
  close_cap_file(&cfile, info_bar);
  g_assert(cfile.save_file == NULL);
  cfile.save_file = capfile_name;

  if (sync_mode) {	/* do the capture in a child process */
    char ssnap[24];
    char scount[24];	/* need a constant for len of numbers */
    char save_file_fd[24];
    char errmsg[1024+1];
    int error;
#ifdef _WIN32
    char sync_pipe_fd[24];
    char *filterstring;
#endif

    sprintf(ssnap,"%d",cfile.snap); /* in lieu of itoa */
    sprintf(scount,"%d",cfile.count);
    sprintf(save_file_fd,"%d",cfile.save_file_fd);

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

    /* Convert pipe write handle to a string and pass to child */
    itoa(sync_pipe[WRITE], sync_pipe_fd, 10);
    /* Convert filter string to a quote delimited string */
    filterstring = g_new(char, strlen(cfile.cfilter) + 3);
    sprintf(filterstring, "\"%s\"", cfile.cfilter);
    filterstring[strlen(cfile.cfilter) + 2] = 0;
    /* Spawn process */
    fork_child = spawnlp(_P_NOWAIT, ethereal_path, CHILD_NAME, "-i", cfile.iface,
                         "-w", cfile.save_file, "-W", save_file_fd,
                         "-c", scount, "-s", ssnap,
                         "-Z", sync_pipe_fd,
                         strlen(cfile.cfilter) == 0 ? (const char *)NULL : "-f",
                         strlen(cfile.cfilter) == 0 ? (const char *)NULL : filterstring,
                         (const char *)NULL);
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
      execlp(ethereal_path, CHILD_NAME, "-i", cfile.iface,
		"-w", cfile.save_file, "-W", save_file_fd,
		"-c", scount, "-s", ssnap, 
		"-m", medium_font, "-b", bold_font,
		(cfile.cfilter == NULL)? 0 : "-f",
		(cfile.cfilter == NULL)? 0 : cfile.cfilter,
		(const char *)NULL);	
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
	   and report the failure.
	   XXX - reap the child process and report the status in detail. */
	close(sync_pipe[READ]);
	unlink(cfile.save_file);
	g_free(cfile.save_file);
	cfile.save_file = NULL;
	simple_dialog(ESD_TYPE_WARN, NULL, "Capture child process died");
	return;
      }
      if (c == ';')
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
    if (byte_count == 0) {
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
      msg = g_malloc(byte_count + 1);
      if (msg == NULL) {
	simple_dialog(ESD_TYPE_WARN, NULL,
		"Capture child process failed, but its error message was too big.");
      } else {
	i = read(sync_pipe[READ], msg, byte_count);
	if (i < 0) {
	  simple_dialog(ESD_TYPE_WARN, NULL,
		  "Capture child process failed: Error %s reading its error message.",
		  strerror(errno));
	} else if (i == 0) {
	  simple_dialog(ESD_TYPE_WARN, NULL,
		  "Capture child process failed: EOF reading its error message.");
	} else
	  simple_dialog(ESD_TYPE_WARN, NULL, msg);
	g_free(msg);

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
    capture_succeeded = capture();
    if (quit_after_cap) {
      /* DON'T unlink the save file.  Presumably someone wants it. */
      gtk_exit(0);
    }
    if (capture_succeeded) {
      /* Capture succeeded; read in the capture file. */
      if ((err = open_cap_file(cfile.save_file, is_tempfile, &cfile)) == 0) {
        /* Set the read filter to NULL. */
        cfile.rfcode = NULL;
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
    g_free(cfile.save_file);
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
  char buffer[256+1], *p = buffer, *q = buffer;
  int  nread;
  int  to_read = 0;
  gboolean exit_loop = FALSE;
  int  err;
  int  wstatus;
  int  wsignal;
  char *msg;
  char *sigmsg;
  char sigmsg_buf[6+1+3+1];
  char *coredumped;

#ifndef _WIN32
  /* avoid reentrancy problems and stack overflow */
  gtk_input_remove(cap_input_id);
#endif

  if ((nread = read(sync_pipe[READ], buffer, 256)) <= 0) {
    /* The child has closed the sync pipe, meaning it's not going to be
       capturing any more packets.  Pick up its exit status, and
       complain if it died of a signal. */
#ifdef _WIN32
    /* XXX - analyze the wait stuatus and display more information
       in the dialog box? */
    if (_cwait(&wstatus, child_process, _WAIT_CHILD) == -1) {
      simple_dialog(ESD_TYPE_WARN, NULL, "Child capture process stopped unexpectedly");
    }
#else
    if (wait(&wstatus) != -1) {
      /* XXX - are there any platforms on which we can run that *don't*
         support POSIX.1's <sys/wait.h> and macros therein? */
      wsignal = wstatus & 0177;
      coredumped = "";
      if (wstatus == 0177) {
      	/* It stopped, rather than exiting.  "Should not happen." */
      	msg = "stopped";
      	wsignal = (wstatus >> 8) & 0xFF;
      } else {
        msg = "terminated";
        if (wstatus & 0200)
          coredumped = " - core dumped";
      }
      if (wsignal != 0) {
        switch (wsignal) {

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
          sprintf(sigmsg_buf, "Signal %d", wsignal);
          sigmsg = sigmsg_buf;
          break;
        }
	simple_dialog(ESD_TYPE_WARN, NULL,
		"Child capture process %s: %s%s", msg, sigmsg, coredumped);
      }
    }
#endif
      
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

  while(!exit_loop) {
    /* look for (possibly multiple) '*' */
    switch (*q) {
    case '*' :
      to_read += atoi(p);
      p = q + 1; 
      q++;
      break;
    case '\0' :
      /* XXX should handle the case of a pipe full (i.e. no star found) */
      exit_loop = TRUE;
      break;
    default :
      q++;
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

/*
 * Timeout, in milliseconds, for reads from the stream of captured packets.
 */
#define	CAP_READ_TIMEOUT	250

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
  while (bytes_read < sizeof(struct pcap_hdr))
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
  while (bytes_read < rechdr.hdr.incl_len)
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

  /* Set the initial payload to the packet length, and the initial
     captured payload to the capture length (other protocols may
     reduce them if their headers say they're less). */
  pi.len = whdr.len;
  pi.captured_len = whdr.caplen;
    
  /* update capture statistics */
  switch (ld->linktype) {
    case WTAP_ENCAP_ETHERNET:
      capture_eth(pd, 0, &ld->counts);
      break;
    case WTAP_ENCAP_FDDI:
    case WTAP_ENCAP_FDDI_BITSWAPPED:
      capture_fddi(pd, &ld->counts);
      break;
    case WTAP_ENCAP_TR:
      capture_tr(pd, 0, &ld->counts);
      break;
    case WTAP_ENCAP_NULL:
      capture_null(pd, &ld->counts);
      break;
    case WTAP_ENCAP_PPP:
      capture_ppp(pd, 0, &ld->counts);
      break;
    case WTAP_ENCAP_RAW_IP:
      capture_raw(pd, &ld->counts);
      break;
    case WTAP_ENCAP_LINUX_ATM_CLIP:
      capture_clip(pd, &ld->counts);
      break;
    /* XXX - FreeBSD may append 4-byte ATM pseudo-header to DLT_ATM_RFC1483,
       with LLC header following; we should implement it at some
       point. */
  }

  return 1;
}
#endif

/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */
int
capture(void)
{
  GtkWidget  *cap_w, *main_vb, *count_lb, *sctp_lb, *tcp_lb, *udp_lb, *icmp_lb,
             *ospf_lb, *gre_lb, *netbios_lb, *ipx_lb, *vines_lb, *other_lb, *stop_bt;
  pcap_t     *pch;
  int         pcap_encap;
  int         snaplen;
  gchar       err_str[PCAP_ERRBUF_SIZE], label_str[32];
  loop_data   ld;
  bpf_u_int32 netnum, netmask;
  time_t      upd_time, cur_time;
  int         err, inpkts;
  char        errmsg[1024+1];
  fd_set      set1;
  struct timeval timeout;
#ifdef linux
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
  ld.max            = cfile.count;
  ld.linktype       = WTAP_ENCAP_UNKNOWN;
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

  /* Open the network interface to capture from it. */
  pch = pcap_open_live(cfile.iface, cfile.snap, 1, CAP_READ_TIMEOUT, err_str);

  if (pch == NULL) {
#ifndef _WIN32
    /* try to open cfile.iface as a pipe */
    pipe_fd = pipe_open_live(cfile.iface, &hdr, &ld, err_str);

    if (pipe_fd == -1) {
      /* Well, we couldn't start the capture.
	 If this is a child process that does the capturing in sync
	 mode or fork mode, it shouldn't do any UI stuff until we pop up the
	 capture-progress window, and, since we couldn't start the
	 capture, we haven't popped it up. */
      if (!capture_child) {
	while (gtk_events_pending()) gtk_main_iteration();
      }
      snprintf(errmsg, sizeof errmsg,
	  "The capture session could not be initiated (%s).\n"
	  "Please check to make sure you have sufficient permissions, and that\n"
	  "you have the proper interface or pipe specified.", err_str);
      goto error;
    }
#else
    /* Well, we couldn't start the capture.
       If this is a child process that does the capturing in sync
       mode or fork mode, it shouldn't do any UI stuff until we pop up the
       capture-progress window, and, since we couldn't start the
       capture, we haven't popped it up. */
    if (!capture_child) {
      while (gtk_events_pending()) gtk_main_iteration();
    }
    snprintf(errmsg, sizeof errmsg,
	"The capture session could not be initiated (%s).\n"
	"Please check to make sure you have sufficient permissions, and that\n"
	"you have the proper interface specified.", err_str);
    goto error;
#endif
  }

  /* capture filters only work on real interfaces */
  if (cfile.cfilter && !ld.from_pipe) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet (cfile.iface, &netnum, &netmask, err_str) < 0) {
      snprintf(errmsg, sizeof errmsg,
        "Can't use filter:  Couldn't obtain netmask info (%s).", err_str);
      goto error;
    }
    if (pcap_compile(pch, &cfile.fcode, cfile.cfilter, 1, netmask) < 0) {
      snprintf(errmsg, sizeof errmsg, "Unable to parse filter string (%s).",
	pcap_geterr(pch));
      goto error;
    }
    if (pcap_setfilter(pch, &cfile.fcode) < 0) {
      snprintf(errmsg, sizeof errmsg, "Can't install filter (%s).",
	pcap_geterr(pch));
      goto error;
    }
  }

  /* Set up to write to the capture file. */
#ifndef _WIN32
  if (ld.from_pipe) {
    pcap_encap = hdr.network;
    snaplen = hdr.snaplen;
  } else
#endif
  {
    pcap_encap = pcap_datalink(pch);
    snaplen = pcap_snapshot(pch);
  }
  ld.linktype = wtap_pcap_encap_to_wtap_encap(pcap_encap);
  if (ld.linktype == WTAP_ENCAP_UNKNOWN) {
    strcpy(errmsg, "The network you're capturing from is of a type"
             " that Ethereal doesn't support.");
    goto error;
  }
  ld.pdh = wtap_dump_fdopen(cfile.save_file_fd, WTAP_FILE_PCAP,
      ld.linktype, snaplen, &err);

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
        sprintf(errmsg, "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: Error %d.",
 			cfile.save_file, err);
      } else {
        sprintf(errmsg, "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: %s.",
 			cfile.save_file, strerror(err));
      }
      break;
    }
    goto error;
  }

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
    write(1, "0;", 2);
  }

  cap_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(cap_w), "Ethereal: Capture");
  gtk_window_set_modal(GTK_WINDOW(cap_w), TRUE);

  /* Container for capture display widgets */
  main_vb = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(cap_w), main_vb);
  gtk_widget_show(main_vb);

  count_lb = gtk_label_new("Count: 0");
  gtk_box_pack_start(GTK_BOX(main_vb), count_lb, FALSE, FALSE, 3);
  gtk_widget_show(count_lb);

  sctp_lb = gtk_label_new("SCTP: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), sctp_lb, FALSE, FALSE, 3);
  gtk_widget_show(sctp_lb);

  tcp_lb = gtk_label_new("TCP: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), tcp_lb, FALSE, FALSE, 3);
  gtk_widget_show(tcp_lb);

  udp_lb = gtk_label_new("UDP: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), udp_lb, FALSE, FALSE, 3);
  gtk_widget_show(udp_lb);

  icmp_lb = gtk_label_new("ICMP: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), icmp_lb, FALSE, FALSE, 3);
  gtk_widget_show(icmp_lb);

  ospf_lb = gtk_label_new("OSPF: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), ospf_lb, FALSE, FALSE, 3);
  gtk_widget_show(ospf_lb);

  gre_lb = gtk_label_new("GRE: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), gre_lb, FALSE, FALSE, 3);
  gtk_widget_show(gre_lb);

  netbios_lb = gtk_label_new("NetBIOS: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), netbios_lb, FALSE, FALSE, 3);
  gtk_widget_show(netbios_lb);

  ipx_lb = gtk_label_new("IPX: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), ipx_lb, FALSE, FALSE, 3);
  gtk_widget_show(ipx_lb);

  vines_lb = gtk_label_new("VINES: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), vines_lb, FALSE, FALSE, 3);
  gtk_widget_show(vines_lb);

  other_lb = gtk_label_new("Other: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), other_lb, FALSE, FALSE, 3);
  gtk_widget_show(other_lb);

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
#ifdef linux
  if (!ld.from_pipe) pcap_fd = pcap_fileno(pch);
#endif
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
#ifdef linux
      /*
       * Sigh.  The semantics of the read timeout argument to
       * "pcap_open_live()" aren't particularly well specified by
       * the "pcap" man page - at least with the BSD BPF code, the
       * intent appears to be, at least in part, a way of cutting
       * down the number of reads done on a capture, by blocking
       * until the buffer fills or a timer expires - and the Linux
       * libpcap doesn't actually support it, so we can't use it
       * to break out of the "pcap_dispatch()" every 1/4 of a second
       * or so.
       *
       * Thus, on Linux, we do a "select()" on the file descriptor for the
       * capture, with a timeout of CAP_READ_TIMEOUT milliseconds, or
       * CAP_READ_TIMEOUT*1000 microseconds.
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
      } else
	inpkts = 0;
#else
      inpkts = pcap_dispatch(pch, 1, capture_pcap_cb, (u_char *) &ld);
#endif
    }
    if (inpkts > 0)
      ld.sync_packets += inpkts;
    /* Only update once a second so as not to overload slow displays */
    cur_time = time(NULL);
    if (cur_time > upd_time) {
      upd_time = cur_time;

      sprintf(label_str, "Count: %d", ld.counts.total);
      gtk_label_set(GTK_LABEL(count_lb), label_str);

      sprintf(label_str, "SCTP: %d (%.1f%%)", ld.counts.sctp,
                pct(ld.counts.sctp, ld.counts.total));
      gtk_label_set(GTK_LABEL(sctp_lb), label_str);

      sprintf(label_str, "TCP: %d (%.1f%%)", ld.counts.tcp,
		pct(ld.counts.tcp, ld.counts.total));
      gtk_label_set(GTK_LABEL(tcp_lb), label_str);

      sprintf(label_str, "UDP: %d (%.1f%%)", ld.counts.udp,
		pct(ld.counts.udp, ld.counts.total));
      gtk_label_set(GTK_LABEL(udp_lb), label_str);

      sprintf(label_str, "ICMP: %d (%.1f%%)", ld.counts.icmp,
		pct(ld.counts.icmp, ld.counts.total));
      gtk_label_set(GTK_LABEL(icmp_lb), label_str);

      sprintf(label_str, "OSPF: %d (%.1f%%)", ld.counts.ospf,
		pct(ld.counts.ospf, ld.counts.total));
      gtk_label_set(GTK_LABEL(ospf_lb), label_str);

      sprintf(label_str, "GRE: %d (%.1f%%)", ld.counts.gre,
		pct(ld.counts.gre, ld.counts.total));
      gtk_label_set(GTK_LABEL(gre_lb), label_str);

      sprintf(label_str, "NetBIOS: %d (%.1f%%)", ld.counts.netbios,
		pct(ld.counts.netbios, ld.counts.total));
      gtk_label_set(GTK_LABEL(netbios_lb), label_str);

      sprintf(label_str, "IPX: %d (%.1f%%)", ld.counts.ipx,
		pct(ld.counts.ipx, ld.counts.total));
      gtk_label_set(GTK_LABEL(ipx_lb), label_str);

      sprintf(label_str, "VINES: %d (%.1f%%)", ld.counts.vines,
		pct(ld.counts.vines, ld.counts.total));
      gtk_label_set(GTK_LABEL(vines_lb), label_str);

      sprintf(label_str, "Other: %d (%.1f%%)", ld.counts.other,
		pct(ld.counts.other, ld.counts.total));
      gtk_label_set(GTK_LABEL(other_lb), label_str);

      /* do sync here, too */
      fflush(wtap_dump_file(ld.pdh));
      if (capture_child && ld.sync_packets) {
	/* This is the child process for a sync mode capture, so send
	   our parent a message saying we've written out "ld.sync_packets"
	   packets to the capture file. */
	char tmp[20];
	sprintf(tmp, "%d*", ld.sync_packets);
	write(1, tmp, strlen(tmp));
	ld.sync_packets = 0;
      }
    }
  }
    
  if (!wtap_dump_close(ld.pdh, &err)) {
    /* XXX - in fork mode, this may not pop up, or, if it does,
       it may disappear as soon as we exit.

       We should have the parent process, while it's reading
       the packet count update messages, catch error messages
       and pop up a message box if it sees one. */
    switch (err) {

    case WTAP_ERR_CANT_CLOSE:
      simple_dialog(ESD_TYPE_WARN, NULL,
        	"The file to which the capture was being saved"
		" couldn't be closed for some unknown reason.");
      break;

    case WTAP_ERR_SHORT_WRITE:
      simple_dialog(ESD_TYPE_WARN, NULL,
		"Not all the data could be written to the file"
		" to which the capture was being saved.");
      break;

    default:
      simple_dialog(ESD_TYPE_WARN, NULL,
		"The file to which the capture was being"
		" saved (\"%s\") could not be closed: %s.",
		cfile.save_file, wtap_strerror(err));
      break;
    }
  }
#ifndef _WIN32
  if (ld.from_pipe)
    close(pipe_fd);
  else
#endif
    pcap_close(pch);

  gtk_grab_remove(GTK_WIDGET(cap_w));
  gtk_widget_destroy(GTK_WIDGET(cap_w));

  return TRUE;

error:
  /* We can't use the save file, and we have no wtap_dump stream
     to close in order to close it, so close the FD directly. */
  close(cfile.save_file_fd);

  /* We couldn't even start the capture, so get rid of the capture
     file. */
  unlink(cfile.save_file); /* silently ignore error */
  g_free(cfile.save_file);
  cfile.save_file = NULL;
  if (capture_child) {
    /* This is the child process for a sync mode capture.
       Send the error message to our parent, so they can display a
       dialog box containing it. */
    send_errmsg_to_parent(errmsg);
  } else {
    /* Display the dialog box ourselves; there's no parent. */
    simple_dialog(ESD_TYPE_CRIT, NULL, errmsg);
  }
  if (pch != NULL && !ld.from_pipe)
    pcap_close(pch);

  return FALSE;
}

static void
send_errmsg_to_parent(const char *errmsg)
{
    int msglen = strlen(errmsg);
    char lenbuf[10+1+1];

    sprintf(lenbuf, "%u;", msglen);
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
capture_delete_cb(GtkWidget *w, GdkEvent *event, gpointer data) {
  capture_stop_cb(NULL, data);
}

static void
capture_stop_cb(GtkWidget *w, gpointer data) {
  loop_data *ld = (loop_data *) data;
  
  ld->go = FALSE;
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

     /* XXX - do something if this fails */
     wtap_dump(ld->pdh, &whdr, NULL, pd, &err);
  }

  /* Set the initial payload to the packet length, and the initial
     captured payload to the capture length (other protocols may
     reduce them if their headers say they're less). */
  pi.len = phdr->len;
  pi.captured_len = phdr->caplen;
    
  switch (ld->linktype) {
    case WTAP_ENCAP_ETHERNET:
      capture_eth(pd, 0, &ld->counts);
      break;
    case WTAP_ENCAP_FDDI:
    case WTAP_ENCAP_FDDI_BITSWAPPED:
      capture_fddi(pd, &ld->counts);
      break;
    case WTAP_ENCAP_TR:
      capture_tr(pd, 0, &ld->counts);
      break;
    case WTAP_ENCAP_NULL:
      capture_null(pd, &ld->counts);
      break;
    case WTAP_ENCAP_PPP:
      capture_ppp(pd, 0, &ld->counts);
      break;
    case WTAP_ENCAP_RAW_IP:
      capture_raw(pd, &ld->counts);
      break;
    case WTAP_ENCAP_LINUX_ATM_CLIP:
      capture_clip(pd, &ld->counts);
      break;
    /* XXX - FreeBSD may append 4-byte ATM pseudo-header to DLT_ATM_RFC1483,
       with LLC header following; we should implement it at some
       point. */
  }
}

#endif /* HAVE_LIBPCAP */
