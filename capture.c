/* capture.c
 * Routines for packet capture windows
 *
 * $Id: capture.c,v 1.8 1998/10/28 21:38:06 gerald Exp $
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

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <gtk/gtk.h>
#include <pcap.h>

#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#ifdef HAVE_SYS_SOCKIO_H
# include <sys/sockio.h>
#endif

#include "ethereal.h"
#include "packet.h"
#include "file.h"
#include "capture.h"
#include "etypes.h"
#include "util.h"
#include "prefs.h"

extern capture_file  cf;
extern GtkWidget    *info_bar;
extern guint         file_ctx;

/* File selection data keys */
#define E_CAP_PREP_FS_KEY "cap_prep_fs"
#define E_CAP_PREP_TE_KEY "cap_prep_te"

/* Capture callback data keys */
#define E_CAP_IFACE_KEY "cap_iface"
#define E_CAP_FILT_KEY  "cap_filter"
#define E_CAP_FILE_KEY  "cap_file"
#define E_CAP_COUNT_KEY "cap_count"
#define E_CAP_OPEN_KEY  "cap_open"
#define E_CAP_SNAP_KEY  "cap_snap"

/* Capture filter key */
#define E_CAP_FILT_TE_KEY "cap_filt_te"

GList *
get_interface_list() {
  GList  *il = NULL;
  struct  ifreq *ifr, *last;
  struct  ifconf ifc;
  int     sock = socket(AF_INET, SOCK_DGRAM, 0);

  if (sock < 0)
  {
    simple_dialog(ESD_TYPE_WARN, NULL,
      "Can't list interfaces: error opening socket.");
    return NULL;
  }

  /* Since we have to grab the interface list all at once, we'll make
     plenty of room */
  ifc.ifc_len = 1024 * sizeof(struct ifreq);
  ifc.ifc_buf = malloc(ifc.ifc_len);

  if (ioctl(sock, SIOCGIFCONF, &ifc) < 0 ||
    ifc.ifc_len < sizeof(struct ifreq))
  {
    simple_dialog(ESD_TYPE_WARN, NULL,
      "Can't list interfaces: ioctl error.");
    return NULL;
  }

  ifr  = (struct ifreq *) ifc.ifc_req;
  last = (struct ifreq *) ((char *) ifr + ifc.ifc_len);
  while (ifr < last)
  {
    /*
     * What we want:
     * - Interfaces that are up, and not loopback
     * - IP interfaces (do we really need this?)
     * - Anything that doesn't begin with "lo" (loopback again) or "dummy"
     * - Anything that doesn't include a ":" (Solaris virtuals)
     */
    if (! (ifr->ifr_flags & (IFF_UP | IFF_LOOPBACK)) &&
        (ifr->ifr_addr.sa_family == AF_INET) &&
        strncmp(ifr->ifr_name, "lo", 2) &&
        strncmp(ifr->ifr_name, "dummy", 5) &&
        ! strchr(ifr->ifr_name, ':')) {
      il = g_list_append(il, g_strdup(ifr->ifr_name));
    }
#ifdef HAVE_SOCKADDR_SA_LEN
    ifr = (struct ifreq *) ((char *) ifr + ifr->ifr_addr.sa_len + IFNAMSIZ);
#else
    ifr = (struct ifreq *) ((char *) ifr + sizeof(struct ifreq));
#endif
  }

  free(ifc.ifc_buf);
  return il;
}

void
capture_prep_cb(GtkWidget *w, gpointer d) {
  GtkWidget     *cap_open_w, *if_cb, *if_lb, *file_te, *file_bt,
                *count_lb, *count_cb, *main_vb, *if_hb, *count_hb,
                *filter_hb, *filter_bt, *filter_te, *file_hb, *caplen_hb,
                *bbox, *ok_bt, *cancel_bt, *capfile_ck, *snap_lb,
                *snap_sb;
  GtkAdjustment *adj;
  GList         *if_list, *count_list = NULL;
  gchar         *count_item1 = "0 (Infinite)", count_item2[16];

  cap_open_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);
  gtk_window_set_title(GTK_WINDOW(cap_open_w), "Ethereal: Capture Preferences");
  
  /* Container for each row of widgets */
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(cap_open_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Interface row */
  if_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), if_hb);
  gtk_widget_show(if_hb);
  
  if_lb = gtk_label_new("Interface:");
  gtk_box_pack_start(GTK_BOX(if_hb), if_lb, FALSE, FALSE, 0);
  gtk_widget_show(if_lb);
  
  if_list = get_interface_list();
  
  if_cb = gtk_combo_new();
  gtk_combo_set_popdown_strings(GTK_COMBO(if_cb), if_list);
  if (cf.iface)
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry), cf.iface);
  else if (if_list)
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry), if_list->data);
  gtk_box_pack_start(GTK_BOX(if_hb), if_cb, FALSE, FALSE, 0);
  gtk_widget_show(if_cb);
  
  while (if_list) {
    g_free(if_list->data);
    if_list = g_list_remove_link(if_list, if_list);
  }

  /* Count row */
  count_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), count_hb);
  gtk_widget_show(count_hb);
  
  count_lb = gtk_label_new("Count:");
  gtk_box_pack_start(GTK_BOX(count_hb), count_lb, FALSE, FALSE, 0);
  gtk_widget_show(count_lb);
  
  if (cf.count) {
    snprintf(count_item2, 15, "%d", cf.count);
    count_list = g_list_append(count_list, count_item2);
  }
  count_list = g_list_append(count_list, count_item1);

  count_cb = gtk_combo_new();
  gtk_combo_set_popdown_strings(GTK_COMBO(count_cb), count_list);
  gtk_box_pack_start(GTK_BOX(count_hb), count_cb, FALSE, FALSE, 0);
  gtk_widget_show(count_cb);

  while (count_list)
    count_list = g_list_remove_link(count_list, count_list);

  /* Filter row */
  filter_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), filter_hb);
  gtk_widget_show(filter_hb);
  
  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(prefs_cb), (gpointer) E_PR_PG_FILTER);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_bt, FALSE, TRUE, 0);
  gtk_widget_show(filter_bt);
  
  filter_te = gtk_entry_new();
  if (cf.cfilter) gtk_entry_set_text(GTK_ENTRY(filter_te), cf.cfilter);
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_te, TRUE, TRUE, 0);
  gtk_widget_show(filter_te);
  
  /* File row: File: button and text entry */
  file_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), file_hb);
  gtk_widget_show(file_hb);
  
  file_bt = gtk_button_new_with_label("File:");
  gtk_box_pack_start(GTK_BOX(file_hb), file_bt, FALSE, FALSE, 0);
  gtk_widget_show(file_bt);
  
  file_te = gtk_entry_new();
  if (cf.save_file)
    gtk_entry_set_text(GTK_ENTRY(file_te), cf.save_file);
  gtk_box_pack_start(GTK_BOX(file_hb), file_te, TRUE, TRUE, 0);
  gtk_widget_show(file_te);

  gtk_signal_connect_object(GTK_OBJECT(file_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_prep_file_cb), GTK_OBJECT(file_te));

  /* Misc row: Capture file checkbox and snap spinbutton */
  caplen_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), caplen_hb);
  gtk_widget_show(caplen_hb);

  capfile_ck = gtk_check_button_new_with_label("Open file after capture");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(capfile_ck), TRUE);
  gtk_box_pack_start(GTK_BOX(caplen_hb), capfile_ck, FALSE, FALSE, 3);
  gtk_widget_show(capfile_ck);

  snap_lb = gtk_label_new("Capture length");
  gtk_misc_set_alignment(GTK_MISC(snap_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(caplen_hb), snap_lb, FALSE, FALSE, 6);
  gtk_widget_show(snap_lb);

  adj = (GtkAdjustment *) gtk_adjustment_new((float) cf.snap, 1.0, 4096.0,
    1.0, 10.0, 0.0);
  snap_sb = gtk_spin_button_new (adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (snap_sb), TRUE);
  gtk_widget_set_usize (snap_sb, 80, 0);
  gtk_box_pack_start (GTK_BOX(caplen_hb), snap_sb, FALSE, FALSE, 3); 
  gtk_widget_show(snap_sb);
  
  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect_object(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_prep_ok_cb), GTK_OBJECT(cap_open_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect_object(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_prep_close_cb), GTK_OBJECT(cap_open_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Attach pointers to needed widges to the capture prefs window/object */
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_IFACE_KEY, if_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_FILT_KEY,  filter_te);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_FILE_KEY,  file_te);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_COUNT_KEY, count_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_OPEN_KEY,  capfile_ck);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_SNAP_KEY,  snap_sb);
  
  gtk_widget_show(cap_open_w);
}

void
capture_prep_file_cb(GtkWidget *w, gpointer te) {
  GtkWidget *fs;

  fs = gtk_file_selection_new ("Ethereal: Open Save File");

  gtk_object_set_data(GTK_OBJECT(w), E_CAP_PREP_FS_KEY, fs);
  gtk_object_set_data(GTK_OBJECT(w), E_CAP_PREP_TE_KEY, (GtkWidget *) te);
  
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->ok_button),
    "clicked", (GtkSignalFunc) cap_prep_fs_ok_cb, w);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->cancel_button),
    "clicked", (GtkSignalFunc) cap_prep_fs_cancel_cb, w);
  
  gtk_widget_show(fs);
}

void
cap_prep_fs_ok_cb(GtkWidget *w, gpointer data) {
  GtkWidget *fs, *te;
  
  fs = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_PREP_FS_KEY);
  te = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_PREP_TE_KEY);

  gtk_entry_set_text(GTK_ENTRY(te),
    gtk_file_selection_get_filename (GTK_FILE_SELECTION(fs)));
  cap_prep_fs_cancel_cb(w, data);
}

void
cap_prep_fs_cancel_cb(GtkWidget *w, gpointer data) {
  GtkWidget *fs;
  
  fs = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_PREP_FS_KEY);

  gtk_widget_destroy(fs);
}  

void
capture_prep_ok_cb(GtkWidget *w, gpointer data) {
  GtkWidget *if_cb, *filter_te, *file_te, *count_cb, *open_ck, *snap_sb;
  gint     open;

  if_cb     = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_IFACE_KEY);
  filter_te = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_FILT_KEY);
  file_te   = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_FILE_KEY);
  count_cb  = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_COUNT_KEY);
  open_ck   = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_OPEN_KEY);
  snap_sb   = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(data), E_CAP_SNAP_KEY);

  if (cf.iface) g_free(cf.iface);
  cf.iface =
    g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry)));
  if (cf.cfilter) g_free(cf.cfilter);
  cf.cfilter = g_strdup(gtk_entry_get_text(GTK_ENTRY(filter_te)));
  if (cf.save_file) g_free(cf.save_file);
  cf.save_file = g_strdup(gtk_entry_get_text(GTK_ENTRY(file_te)));
  cf.count =
    atoi(g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(count_cb)->entry))));
  open = GTK_TOGGLE_BUTTON(open_ck)->active;
  cf.snap = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(snap_sb));
  if (cf.snap < 1)
    cf.snap = 4096;
  else if (cf.snap < 68)
    cf.snap = 68;

  gtk_widget_destroy(GTK_WIDGET(data));
  
  capture(open);
}

void
capture_prep_close_cb(GtkWidget *w, gpointer win) {

  gtk_grab_remove(GTK_WIDGET(win));
  gtk_widget_destroy(GTK_WIDGET(win));
}

void
capture(gint open) {
  GtkWidget  *cap_w, *main_vb, *count_lb, *tcp_lb, *udp_lb, 
             *ospf_lb, *other_lb, *stop_bt;
  pcap_t     *pch;
  gchar       err_str[PCAP_ERRBUF_SIZE], label_str[32];
  loop_data   ld;
  bpf_u_int32 netnum, netmask;
  time_t      upd_time, cur_time;
  
  ld.go    = TRUE;
  ld.count = 0;
  ld.max   = cf.count;
  ld.tcp   = 0;
  ld.udp   = 0;
  ld.ospf  = 0;
  ld.other = 0;
  ld.pdh   = NULL;

  close_cap_file(&cf, info_bar, file_ctx);

  pch = pcap_open_live(cf.iface, cf.snap, 1, 250, err_str);

  if (pch) {
    if (cf.save_file[0]) {
      ld.pdh = pcap_dump_open(pch, cf.save_file);
      if (ld.pdh == NULL) {  /* We have an error */
        snprintf(err_str, PCAP_ERRBUF_SIZE, "Error trying to open dump "
          "file:\n%s", pcap_geterr(pch));
        simple_dialog(ESD_TYPE_WARN, NULL, err_str);
        g_free(cf.save_file);
        cf.save_file = NULL;
        pcap_close(pch);
        return;
      }
    }

    if (cf.cfilter) {
      if (pcap_lookupnet (cf.iface, &netnum, &netmask, err_str) < 0) {
        simple_dialog(ESD_TYPE_WARN, NULL,
          "Can't use filter:  Couldn't obtain netmask info.");
        return;
      } else if (pcap_compile(pch, &cf.fcode, cf.cfilter, 1, netmask) < 0) {
        simple_dialog(ESD_TYPE_WARN, NULL, "Unable to parse filter string.");
        return;
      } else if (pcap_setfilter(pch, &cf.fcode) < 0) {
        simple_dialog(ESD_TYPE_WARN, NULL, "Can't install filter.");
        return;
      }
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

    ospf_lb = gtk_label_new("OSPF: 0 (0.0%)");
    gtk_box_pack_start(GTK_BOX(main_vb), ospf_lb, FALSE, FALSE, 3);
    gtk_widget_show(ospf_lb);

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
      pcap_dispatch(pch, 1, capture_pcap_cb, (u_char *) &ld);

      /* Only update once a second so as not to overload slow displays */
      cur_time = time(NULL);
      if (cur_time > upd_time) {

        upd_time = cur_time;

        sprintf(label_str, "Count: %d", ld.count);
        gtk_label_set(GTK_LABEL(count_lb), label_str);

        sprintf(label_str, "TCP: %d (%.1f%%)", ld.tcp, pct(ld.tcp, ld.count));
        gtk_label_set(GTK_LABEL(tcp_lb), label_str);

        sprintf(label_str, "UDP: %d (%.1f%%)", ld.udp, pct(ld.udp, ld.count));
        gtk_label_set(GTK_LABEL(udp_lb), label_str);

        sprintf(label_str, "OSPF: %d (%.1f%%)", ld.ospf, pct(ld.ospf, ld.count));
        gtk_label_set(GTK_LABEL(ospf_lb), label_str);

        sprintf(label_str, "Other: %d (%.1f%%)", ld.other,
          pct(ld.other, ld.count));
        gtk_label_set(GTK_LABEL(other_lb), label_str);
      }
    }
    
    if (ld.pdh) pcap_dump_close(ld.pdh);
    pcap_close(pch);

    gtk_grab_remove(GTK_WIDGET(cap_w));
    gtk_widget_destroy(GTK_WIDGET(cap_w));
  } else {
    while (gtk_events_pending()) gtk_main_iteration();
    simple_dialog(ESD_TYPE_WARN, NULL,
      "The capture session could not be initiated.  Please\n"
      "check to make sure you have sufficient permissions, and\n"
      "that you have the proper interface specified.");
    g_free(cf.save_file);
    cf.save_file = NULL;
  }

  if (cf.save_file && open) load_cap_file(cf.save_file, &cf);
}

float
pct(gint num, gint denom) {
  if (denom) {
    return (float) num * 100.0 / (float) denom;
  } else {
    return 0.0;
  }
}

void
capture_stop_cb(GtkWidget *w, gpointer data) {
  loop_data *ld = (loop_data *) data;
  
  ld->go = FALSE;
}

void
capture_pcap_cb(u_char *user, const struct pcap_pkthdr *phdr,
  const u_char *pd) {
  
  guint16 etype;
  guint8  iptype = 0;
  gint    offset = 14;
  
  loop_data *ld = (loop_data *) user;
  
  if ((++ld->count >= ld->max) && (ld->max > 0)) 
  {
     ld->go = FALSE;
  }
  /* Currently, pcap_dumper_t is a FILE *.  Let's hope that doesn't change. */
  if (ld->pdh) pcap_dump((u_char *) ld->pdh, phdr, pd);
  
  etype = etype = (pd[12] << 8) | pd[13];
  if (etype <= IEEE_802_3_MAX_LEN) {
    etype = (pd[20] << 8) | pd[21];
    offset = 22;
  }
  
  switch(etype){ 
    case ETHERTYPE_IP:
      iptype = pd[offset + 9];
      switch (iptype) {
        case IP_PROTO_TCP:
          ld->tcp++;
          break;
        case IP_PROTO_UDP:
          ld->udp++;
          break;
        case IP_PROTO_OSPF:
          ld->ospf++;
          break;
        default:
          ld->other++;
        }
        break;
      case ETHERTYPE_IPX:
      case ETHERTYPE_IPv6:
      case ETHERTYPE_ATALK:
      case ETHERTYPE_VINES:
      case ETHERTYPE_ARP:
      default:
        ld->other++;
  }
}
