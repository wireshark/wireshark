/* capture.c
 * Routines for packet capture windows
 *
 * $Id: capture.c,v 1.68 1999/09/23 06:27:19 guy Exp $
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

#include <gtk/gtk.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

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

#include "gtk/main.h"
#include "packet.h"
#include "file.h"
#include "gtk/menu.h"
#include "capture.h"
#include "util.h"
#include "prefs.h"
#include "globals.h"

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

void
do_capture(void)
{
  char tmpname[128+1];
  char c;
  int i;
  guint byte_count;
  char *msg;

  /* Choose a random name for the capture buffer */
  if (cf.save_file && !cf.user_saved) {
	unlink(cf.save_file); /* silently ignore error */
	g_free(cf.save_file);
  }
  cf.save_file_fd = create_tempfile(tmpname, sizeof tmpname, "ether");
  if (cf.save_file_fd == -1) {
    simple_dialog(ESD_TYPE_WARN, NULL,
	"The file to which the capture would be saved (\"%s\")"
	"could not be opened: %s.", tmpname, strerror(errno));
    return;
  }
  cf.save_file = g_strdup(tmpname);
  cf.user_saved = 0;
  
  if( fork_mode ){	/*  use fork() for capture */
    int  fork_child;
    char ssnap[24];
    char scount[24];	/* need a constant for len of numbers */
    char save_file_fd[24];
    int err;

    sprintf(ssnap,"%d",cf.snap); /* in lieu of itoa */
    sprintf(scount,"%d",cf.count);
    sprintf(save_file_fd,"%d",cf.save_file_fd);
    signal(SIGCHLD, SIG_IGN);
    if (sync_mode) pipe(sync_pipe);
    if((fork_child = fork()) == 0){
      /* args: -k -- capture
       * -i interface specification
       * -w file to write
       * -W file descriptor to write
       * -c count to capture
       * -Q quit after capture (forces -k)
       * -s snaplen
       * -S sync mode
       * -m / -b fonts
       * -f "filter expression"
       */
       if (sync_mode) {
	 close(1);
	 dup(sync_pipe[1]);
	 close(sync_pipe[0]);
	 execlp(ethereal_path, "ethereal", "-k", "-Q", "-i", cf.iface,
		"-w", cf.save_file, "-W", save_file_fd,
		"-c", scount, "-s", ssnap, "-S", 
		"-m", medium_font, "-b", bold_font,
		(cf.cfilter == NULL)? 0 : "-f",
		(cf.cfilter == NULL)? 0 : cf.cfilter,
		(const char *)NULL);	
       }
       else {
	 execlp(ethereal_path, "ethereal", "-k", "-Q", "-i", cf.iface,
		"-w", cf.save_file, "-W", save_file_fd,
		"-c", scount, "-s", ssnap,
		"-m", medium_font, "-b", bold_font,
		(cf.cfilter == NULL)? 0 : "-f",
		(cf.cfilter == NULL)? 0 : cf.cfilter,
		(const char *)NULL);
       }
    }
    else {
       cf.filename = cf.save_file;
       if (sync_mode) {
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
	        XXX - reap it and report the status. */
	     simple_dialog(ESD_TYPE_WARN, NULL, "Capture child process died");
	     return;
	   }
	   if (c == ';')
	     break;
	   if (!isdigit(c)) {
	     /* Child process handed us crap. */
	     simple_dialog(ESD_TYPE_WARN, NULL,
	        "Capture child process sent us a bad message");
	     return;
	   }
	   byte_count = byte_count*10 + c - '0';
	 }
	 if (byte_count == 0) {
	   /* Success. */
	   err = tail_cap_file(cf.save_file, &cf);
	   if (err != 0) {
	     simple_dialog(ESD_TYPE_WARN, NULL,
			file_open_error_message(err, FALSE), cf.save_file);
	   }
	 } else {
	   /* Failure. */
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
	   }
	 }
       }
    }
  }
  else
    capture();
}

void
capture(void)
{
  GtkWidget  *cap_w, *main_vb, *count_lb, *tcp_lb, *udp_lb, *icmp_lb,
             *ospf_lb, *gre_lb, *netbios_lb, *other_lb, *stop_bt;
  pcap_t     *pch;
  gchar       err_str[PCAP_ERRBUF_SIZE], label_str[32];
  loop_data   ld;
  bpf_u_int32 netnum, netmask;
  time_t      upd_time, cur_time;
  int         err, inpkts;
  char        errmsg[1024+1];

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
  ld.counts.netbios = 0;
  ld.counts.other   = 0;
  ld.pdh            = NULL;

  close_cap_file(&cf, info_bar, file_ctx);

  pch = pcap_open_live(cf.iface, cf.snap, 1, 250, err_str);

  if (pch == NULL) {
    /* Well, we couldn't start the capture. */
    if (!fork_mode) {
      /* In fork mode, we shouldn't do any UI stuff until we pop up the
         capture-progress window, and, since we couldn't start the
	 capture, we haven't popped it up. */
      while (gtk_events_pending()) gtk_main_iteration();
    }
    snprintf(errmsg, sizeof errmsg,
      "The capture session could not be initiated (%s).\n"
      "Please check to make sure you have sufficient permissions, and that\n"
      "you have the proper interface specified.", err_str);
    goto fatal_error;
  }

  if (cf.cfilter) {
    if (pcap_lookupnet (cf.iface, &netnum, &netmask, err_str) < 0) {
      snprintf(errmsg, sizeof errmsg,
        "Can't use filter:  Couldn't obtain netmask info (%s).", err_str);
      goto fatal_error;
    }
    if (pcap_compile(pch, &cf.fcode, cf.cfilter, 1, netmask) < 0) {
      snprintf(errmsg, sizeof errmsg, "Unable to parse filter string (%s).",
	pcap_geterr(pch));
      goto fatal_error;
    }
    if (pcap_setfilter(pch, &cf.fcode) < 0) {
      snprintf(errmsg, sizeof errmsg, "Can't install filter (%s).",
	pcap_geterr(pch));
      goto fatal_error;
    }
  }

  ld.linktype = wtap_pcap_encap_to_wtap_encap(pcap_datalink(pch));
  if (ld.linktype == WTAP_ENCAP_UNKNOWN) {
    strcpy(errmsg, "The network you're capturing from is of a type"
             " that Ethereal doesn't support.");
    goto fatal_error;
  }
  ld.pdh = wtap_dump_fdopen(cf.save_file_fd, WTAP_FILE_PCAP,
		ld.linktype, pcap_snapshot(pch), &err);

  if (ld.pdh == NULL) {  /* We have an error */
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
    goto fatal_error;
  }

  if (sync_mode) {
    /* Sync out the capture file, so the header makes it to the file
       system, and send a "capture started successfully and capture
       file created" message to our parent so that they'll open the
       capture file and update its windows to indicate that we have
       a live capture in progress. */
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

  other_lb = gtk_label_new("Other: 0 (0.0%)");
  gtk_box_pack_start(GTK_BOX(main_vb), other_lb, FALSE, FALSE, 3);
  gtk_widget_show(other_lb);

  stop_bt = gtk_button_new_with_label ("Stop");
  gtk_signal_connect(GTK_OBJECT(stop_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_stop_cb), (gpointer) &ld);
  gtk_box_pack_end(GTK_BOX(main_vb), stop_bt, FALSE, FALSE, 3);
  GTK_WIDGET_SET_FLAGS(stop_bt, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(stop_bt);
  GTK_WIDGET_SET_FLAGS(stop_bt, GTK_CAN_DEFAULT);
  gtk_widget_grab_default(stop_bt);
  gtk_widget_show(stop_bt);

  gtk_widget_show(cap_w);
  gtk_grab_add(cap_w);

  upd_time = time(NULL);
  while (ld.go) {
    while (gtk_events_pending()) gtk_main_iteration();
    inpkts = pcap_dispatch(pch, 1, capture_pcap_cb, (u_char *) &ld);
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

      sprintf(label_str, "Other: %d (%.1f%%)", ld.counts.other,
		pct(ld.counts.other, ld.counts.total));
      gtk_label_set(GTK_LABEL(other_lb), label_str);

      /* do sync here, too */
      fflush(wtap_dump_file(ld.pdh));
      if (sync_mode && ld.sync_packets) {
	char tmp[20];
	sprintf(tmp, "%d*", ld.sync_packets);
	write(1, tmp, strlen(tmp));
	ld.sync_packets = 0;
      }
    }
  }
    
  if (ld.pdh) {
    if (!wtap_dump_close(ld.pdh, &err)) {
      switch (err) {

      case WTAP_ERR_CANT_CLOSE:
        strcpy(errmsg, "The file to which the capture was being saved"
               " couldn't be closed for some unknown reason.");
        break;

      case WTAP_ERR_SHORT_WRITE:
        strcpy(errmsg, "Not all the data could be written to the file"
                 " to which the capture was being saved.");
        break;

      default:
        if (err < 0) {
          sprintf(errmsg, "The file to which the capture was being"
                     " saved (\"%s\") could not be closed: Error %d.",
 			cf.save_file, err);
        } else {
          sprintf(errmsg, "The file to which the capture was being"
                     " saved (\"%s\") could not be closed: %s.",
 			cf.save_file, strerror(err));
	}
	break;
      }
      goto error;
    }
  }
  pcap_close(pch);

  gtk_grab_remove(GTK_WIDGET(cap_w));
  gtk_widget_destroy(GTK_WIDGET(cap_w));

  if (quit_after_cap) {
    /* DON'T unlink the save file.  Presumably someone wants it. */
    gtk_exit(0);
  }

  if ((err = open_cap_file(cf.save_file, &cf)) == 0) {
    /* Set the read filter to NULL. */
    cf.rfcode = NULL;
    err = read_cap_file(&cf);
    set_menu_sensitivity("/File/Save", TRUE);
    set_menu_sensitivity("/File/Save As...", FALSE);
  }
  return;

fatal_error:
  /* We couldn't even start the capture, so get rid of the capture
     file. */
  unlink(cf.save_file); /* silently ignore error */

error:
  if (sync_mode) {
    /* Send the error message to our parent, so they can display a
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

  if (quit_after_cap)
    gtk_exit(0);
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
     whdr.ts = phdr->ts;
     whdr.caplen = phdr->caplen;
     whdr.len = phdr->len;
     whdr.pkt_encap = ld->linktype;

     /* XXX - do something if this fails */
     wtap_dump(ld->pdh, &whdr, pd, &err);
  }
    
  switch (ld->linktype) {
    case WTAP_ENCAP_ETHERNET:
      capture_eth(pd, phdr->caplen, &ld->counts);
      break;
    case WTAP_ENCAP_FDDI:
    case WTAP_ENCAP_FDDI_BITSWAPPED:
      capture_fddi(pd, phdr->caplen, &ld->counts);
      break;
    case WTAP_ENCAP_TR:
      capture_tr(pd, phdr->caplen, &ld->counts);
      break;
    case WTAP_ENCAP_NULL:
      capture_null(pd, phdr->caplen, &ld->counts);
      break;
    case WTAP_ENCAP_PPP:
      capture_ppp(pd, phdr->caplen, &ld->counts);
      break;
    case WTAP_ENCAP_RAW_IP:
      capture_raw(pd, phdr->caplen, &ld->counts);
      break;
    /* XXX - FreeBSD may append 4-byte ATM pseudo-header to DLT_ATM_RFC1483,
       with LLC header following; we should implement it at some
       point. */
  }
}

#endif /* HAVE_LIBPCAP */
