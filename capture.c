/* capture.c
 * Routines for packet capture windows
 *
 * $Id: capture.c,v 1.94 2000/02/02 18:38:52 gram Exp $
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

#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>

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
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifndef lib_pcap_h
#include <pcap.h>
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

int sync_mode;	/* fork a child to do the capture, and sync between them */
static int sync_pipe[2]; /* used to sync father */
int quit_after_cap; /* Makes a "capture only mode". Implies -k */
gboolean capture_child;	/* if this is the child for "-S" */
static guint cap_input_id;

static void cap_file_input_cb(gpointer, gint, GdkInputCondition);
static void capture_delete_cb(GtkWidget *, GdkEvent *, gpointer);
static void capture_stop_cb(GtkWidget *, gpointer);
static void capture_pcap_cb(u_char *, const struct pcap_pkthdr *,
  const u_char *);
static float pct(gint, gint);

typedef struct _loop_data {
  gint           go;
  gint           max;
  gint           linktype;
  gint           sync_packets;
  packet_counts  counts;
  wtap_dumper   *pdh;
} loop_data;

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
    cf.save_file_fd = open(capfile_name, O_RDWR|O_TRUNC|O_CREAT, 0600);
    is_tempfile = FALSE;
  } else {
    /* Choose a random name for the capture buffer */
    cf.save_file_fd = create_tempfile(tmpname, sizeof tmpname, "ether");
    capfile_name = g_strdup(tmpname);
    is_tempfile = TRUE;
  }
  if (cf.save_file_fd == -1) {
    simple_dialog(ESD_TYPE_WARN, NULL,
	"The file to which the capture would be saved (\"%s\")"
	"could not be opened: %s.", capfile_name, strerror(errno));
    return;
  }
  close_cap_file(&cf, info_bar);
  g_assert(cf.save_file == NULL);
  cf.save_file = capfile_name;

  if (sync_mode) {	/*  use fork() for capture */
    int  fork_child;
    char ssnap[24];
    char scount[24];	/* need a constant for len of numbers */
    char save_file_fd[24];

    sprintf(ssnap,"%d",cf.snap); /* in lieu of itoa */
    sprintf(scount,"%d",cf.count);
    sprintf(save_file_fd,"%d",cf.save_file_fd);
    signal(SIGCHLD, SIG_IGN);
    pipe(sync_pipe);
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
      dup(sync_pipe[1]);
      close(sync_pipe[0]);
      execlp(ethereal_path, CHILD_NAME, "-i", cf.iface,
		"-w", cf.save_file, "-W", save_file_fd,
		"-c", scount, "-s", ssnap, 
		"-m", medium_font, "-b", bold_font,
		(cf.cfilter == NULL)? 0 : "-f",
		(cf.cfilter == NULL)? 0 : cf.cfilter,
		(const char *)NULL);	
    } else {
      /* Parent process - read messages from the child process over the
         sync pipe. */
      close(sync_pipe[1]);

      /* Read a byte count from "sync_pipe[0]", terminated with a
	 colon; if the count is 0, the child process created the
	 capture file and we should start reading from it, otherwise
	 the capture couldn't start and the count is a count of bytes
	 of error message, and we should display the message. */
      byte_count = 0;
      for (;;) {
	i = read(sync_pipe[0], &c, 1);
	if (i == 0) {
	  /* EOF - the child process died.
	     Close the read side of the sync pipe, remove the capture file,
	     and report the failure.
	     XXX - reap the child process and report the status in detail. */
	  close(sync_pipe[0]);
	  unlink(cf.save_file);
	  g_free(cf.save_file);
	  cf.save_file = NULL;
	  simple_dialog(ESD_TYPE_WARN, NULL, "Capture child process died");
	  return;
	}
	if (c == ';')
	  break;
	if (!isdigit(c)) {
	  /* Child process handed us crap.
	     Close the read side of the sync pipe, remove the capture file,
	     and report the failure. */
	  close(sync_pipe[0]);
	  unlink(cf.save_file);
	  g_free(cf.save_file);
	  cf.save_file = NULL;
	  simple_dialog(ESD_TYPE_WARN, NULL,
	     "Capture child process sent us a bad message");
	  return;
	}
	byte_count = byte_count*10 + c - '0';
      }
      if (byte_count == 0) {
	/* Success.  Open the capture file, and set up to read it. */
	err = start_tail_cap_file(cf.save_file, is_tempfile, &cf);
	if (err == 0) {
	  /* We were able to open and set up to read the capture file;
	     arrange that our callback be called whenever it's possible
	     to read from the sync pipe, so that it's called when
	     the child process wants to tell us something. */
	  cap_input_id = gtk_input_add_full(sync_pipe[0],
				       GDK_INPUT_READ|GDK_INPUT_EXCEPTION,
				       cap_file_input_cb,
				       NULL,
				       (gpointer) &cf,
				       NULL);
	} else {
	  /* We weren't able to open the capture file; complain, and
	     close the sync pipe. */
	  simple_dialog(ESD_TYPE_WARN, NULL,
			file_open_error_message(err, FALSE), cf.save_file);

	  /* Close the sync pipe. */
	  close(sync_pipe[0]);

	  /* Don't unlink the save file - leave it around, for debugging
	     purposes. */
	  g_free(cf.save_file);
	  cf.save_file = NULL;
	}
      } else {
	/* Failure - the child process sent us a message indicating
	   what the problem was. */
	msg = g_malloc(byte_count + 1);
	if (msg == NULL) {
	  simple_dialog(ESD_TYPE_WARN, NULL,
		"Capture child process failed, but its error message was too big.");
	} else {
	  i = read(sync_pipe[0], msg, byte_count);
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
	  close(sync_pipe[0]);

	  /* Get rid of the save file - the capture never started. */
	  unlink(cf.save_file);
	  g_free(cf.save_file);
	  cf.save_file = NULL;
	}
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
      if ((err = open_cap_file(cf.save_file, is_tempfile, &cf)) == 0) {
        /* Set the read filter to NULL. */
        cf.rfcode = NULL;
        err = read_cap_file(&cf);
      }
    }
    /* We're not doing a capture any more, so we don't have a save
       file. */
    g_free(cf.save_file);
    cf.save_file = NULL;
  }
}

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

  /* avoid reentrancy problems and stack overflow */
  gtk_input_remove(cap_input_id);

  if ((nread = read(sync_pipe[0], buffer, 256)) <= 0) {
    /* The child has closed the sync pipe, meaning it's not going to be
       capturing any more packets.  Pick up its exit status, and
       complain if it died of a signal. */
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
      
    /* Read what remains of the capture file, and finish the capture.
       XXX - do something if this fails? */
    err = finish_tail_cap_file(cf);

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
  err = continue_tail_cap_file(cf, to_read);

  /* restore pipe handler */
  cap_input_id = gtk_input_add_full (sync_pipe[0],
				     GDK_INPUT_READ|GDK_INPUT_EXCEPTION,
				     cap_file_input_cb,
				     NULL,
				     (gpointer) cf,
				     NULL);
}

/*
 * Timeout, in milliseconds, for reads from the stream of captured packets.
 */
#define	CAP_READ_TIMEOUT	250

/* Do the low-level work of a capture.
   Returns TRUE if it succeeds, FALSE otherwise. */
int
capture(void)
{
  GtkWidget  *cap_w, *main_vb, *count_lb, *tcp_lb, *udp_lb, *icmp_lb,
             *ospf_lb, *gre_lb, *netbios_lb, *ipx_lb, *vines_lb, *other_lb, *stop_bt;
  pcap_t     *pch;
  gchar       err_str[PCAP_ERRBUF_SIZE], label_str[32];
  loop_data   ld;
  bpf_u_int32 netnum, netmask;
  time_t      upd_time, cur_time;
  int         err, inpkts;
  char        errmsg[1024+1];
#ifdef linux
  fd_set      set1;
  struct timeval timeout;
  int         pcap_fd;
#endif

  ld.go             = TRUE;
  ld.counts.total   = 0;
  ld.max            = cf.count;
  ld.linktype       = WTAP_ENCAP_UNKNOWN;
  ld.sync_packets   = 0;
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
  pch = pcap_open_live(cf.iface, cf.snap, 1, CAP_READ_TIMEOUT, err_str);

  if (pch == NULL) {
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
  }

  if (cf.cfilter) {
    /* A capture filter was specified; set it up. */
    if (pcap_lookupnet (cf.iface, &netnum, &netmask, err_str) < 0) {
      snprintf(errmsg, sizeof errmsg,
        "Can't use filter:  Couldn't obtain netmask info (%s).", err_str);
      goto error;
    }
    if (pcap_compile(pch, &cf.fcode, cf.cfilter, 1, netmask) < 0) {
      snprintf(errmsg, sizeof errmsg, "Unable to parse filter string (%s).",
	pcap_geterr(pch));
      goto error;
    }
    if (pcap_setfilter(pch, &cf.fcode) < 0) {
      snprintf(errmsg, sizeof errmsg, "Can't install filter (%s).",
	pcap_geterr(pch));
      goto error;
    }
  }

  /* Set up to write to the capture file. */
  ld.linktype = wtap_pcap_encap_to_wtap_encap(pcap_datalink(pch));
  if (ld.linktype == WTAP_ENCAP_UNKNOWN) {
    strcpy(errmsg, "The network you're capturing from is of a type"
             " that Ethereal doesn't support.");
    goto error;
  }
  ld.pdh = wtap_dump_fdopen(cf.save_file_fd, WTAP_FILE_PCAP,
		ld.linktype, pcap_snapshot(pch), &err);

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
 			cf.save_file, err);
      } else {
        sprintf(errmsg, "The file to which the capture would be"
                     " saved (\"%s\") could not be opened: %s.",
 			cf.save_file, strerror(err));
      }
      break;
    }
    goto error;
  }

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
  gtk_window_set_title(GTK_WINDOW(cap_w), "Ethereal: Capture / Playback");

  /* Container for capture display widgets */
  main_vb = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(cap_w), main_vb);
  gtk_widget_show(main_vb);

  count_lb = gtk_label_new("Count: 0");
  gtk_box_pack_start(GTK_BOX(main_vb), count_lb, FALSE, FALSE, 3);
  gtk_widget_show(count_lb);

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
  gtk_grab_add(cap_w);

  upd_time = time(NULL);
#ifdef linux
  pcap_fd = pcap_fileno(pch);
#endif
  while (ld.go) {
    while (gtk_events_pending()) gtk_main_iteration();
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
    if (inpkts > 0)
      ld.sync_packets += inpkts;
    /* Only update once a second so as not to overload slow displays */
    cur_time = time(NULL);
    if (cur_time > upd_time) {
      upd_time = cur_time;

      sprintf(label_str, "Count: %d", ld.counts.total);
      gtk_label_set(GTK_LABEL(count_lb), label_str);

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
		cf.save_file, wtap_strerror(err));
      break;
    }
  }
  pcap_close(pch);

  gtk_grab_remove(GTK_WIDGET(cap_w));
  gtk_widget_destroy(GTK_WIDGET(cap_w));

  return TRUE;

error:
  /* We couldn't even start the capture, so get rid of the capture
     file. */
  unlink(cf.save_file); /* silently ignore error */
  g_free(cf.save_file);
  cf.save_file = NULL;
  if (capture_child) {
    /* This is the child process for a sync mode capture.
       Send the error message to our parent, so they can display a
       dialog box containing it. */
    int msglen = strlen(errmsg);
    char lenbuf[10+1+1];
    sprintf(lenbuf, "%u;", msglen);
    write(1, lenbuf, strlen(lenbuf));
    write(1, errmsg, msglen);
  } else {
    /* Display the dialog box ourselves; there's no parent. */
    simple_dialog(ESD_TYPE_WARN, NULL, errmsg);
  }
  if (pch != NULL)
    pcap_close(pch);

  return FALSE;
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
     wtap_dump(ld->pdh, &whdr, pd, &err);
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
      capture_ppp(pd, &ld->counts);
      break;
    case WTAP_ENCAP_RAW_IP:
      capture_raw(pd, &ld->counts);
      break;
    /* XXX - FreeBSD may append 4-byte ATM pseudo-header to DLT_ATM_RFC1483,
       with LLC header following; we should implement it at some
       point. */
  }
}

#endif /* HAVE_LIBPCAP */
