/* capture_dlg.c
 * Routines for packet capture windows
 *
 * $Id: capture_dlg.c,v 1.92 2004/01/10 14:11:57 ulfl Exp $
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

#include <pcap.h>
#include <string.h>
#include <gtk/gtk.h>

#include <epan/packet.h>
#include "capture.h"
#include "globals.h"
#include <epan/resolv.h>
#include "main.h"
#include "ui_util.h"
#include "capture_dlg.h"
#include "filter_prefs.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "pcap-util.h"
#include "capture_combo_utils.h"
#include "prefs.h"
#include "ringbuffer.h"
#include <epan/filesystem.h>
#include "compat_macros.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif

/* Capture callback data keys */
#define E_CAP_IFACE_KEY       "cap_iface"
#define E_CAP_SNAP_CB_KEY     "cap_snap_cb"
#define E_CAP_LT_OM_KEY       "cap_lt_om"
#define E_CAP_LT_OM_LABEL_KEY "cap_lt_om_label"
#define E_CAP_SNAP_SB_KEY     "cap_snap_sb"
#define E_CAP_PROMISC_KEY     "cap_promisc"
#define E_CAP_FILT_KEY        "cap_filter_te"
#define E_CAP_FILE_TE_KEY     "cap_file_te"
#define E_CAP_RING_ON_TB_KEY  "cap_ringbuffer_on_tb"
#define E_CAP_RING_NBF_LB_KEY "cap_ringbuffer_nbf_lb"
#define E_CAP_RING_NBF_SB_KEY "cap_ringbuffer_nbf_sb"
#define E_CAP_RING_DURATION_CB_KEY "cap_ringbuffer_duration_cb"
#define E_CAP_RING_DURATION_SB_KEY "cap_ringbuffer_duration_sb"
#define E_CAP_SYNC_KEY        "cap_sync"
#define E_CAP_AUTO_SCROLL_KEY "cap_auto_scroll"
#define E_CAP_COUNT_CB_KEY    "cap_count_cb"
#define E_CAP_COUNT_SB_KEY    "cap_count_sb"
#define E_CAP_FILESIZE_CB_KEY "cap_filesize_cb"
#define E_CAP_FILESIZE_SB_KEY "cap_filesize_sb"
#define E_CAP_FILESIZE_LB_KEY "cap_filesize_lb"
#define E_CAP_DURATION_CB_KEY "cap_duration_cb"
#define E_CAP_DURATION_SB_KEY "cap_duration_sb"
#define E_CAP_M_RESOLVE_KEY   "cap_m_resolve"
#define E_CAP_N_RESOLVE_KEY   "cap_n_resolve"
#define E_CAP_T_RESOLVE_KEY   "cap_t_resolve"

#define E_CAP_OM_LT_VALUE_KEY "cap_om_lt_value"

#define E_FS_CALLER_PTR_KEY       "fs_caller_ptr"
#define E_FILE_SEL_DIALOG_PTR_KEY "file_sel_dialog_ptr"

static void
capture_prep_file_cb(GtkWidget *w, gpointer te);

static void
select_link_type_cb(GtkWidget *w, gpointer data);

static void
cap_prep_fs_ok_cb(GtkWidget *w, gpointer data);

static void
cap_prep_fs_cancel_cb(GtkWidget *w, gpointer data);

static void
cap_prep_fs_destroy_cb(GtkWidget *win, GtkWidget* file_te);

static void
capture_prep_adjust_sensitivity(GtkWidget *tb, gpointer parent_w);

static void
capture_prep_ok_cb(GtkWidget *ok_bt, gpointer parent_w);

static void
capture_prep_close_cb(GtkWidget *close_bt, gpointer parent_w);

static void
capture_prep_destroy_cb(GtkWidget *win, gpointer user_data);

static void
capture_prep_interface_changed_cb(GtkWidget *entry, gpointer parent_w);

void
capture_stop_cb(GtkWidget *w _U_, gpointer d _U_)
{
    capture_stop();
}

/*
 * Keep a static pointer to the current "Capture Options" window, if
 * any, so that if somebody tries to do "Capture:Start" while there's
 * already a "Capture Options" window up, we just pop up the existing
 * one, rather than creating a new one.
 */
static GtkWidget *cap_open_w;

static void
set_link_type_list(GtkWidget *linktype_om, GtkWidget *entry)
{
  gchar *entry_text;
  gchar *if_text;
  gchar *if_name;
  GList *if_list;
  GList *if_entry;
  if_info_t *if_info;
  GList *lt_list;
  int err;
  char err_buf[PCAP_ERRBUF_SIZE];
  GtkWidget *lt_menu, *lt_menu_item;
  GList *lt_entry;
  data_link_info_t *data_link_info;
  gchar *linktype_menu_label;
  guint num_supported_link_types;
  GtkWidget *linktype_lb = OBJECT_GET_DATA(linktype_om, E_CAP_LT_OM_LABEL_KEY);

  lt_menu = gtk_menu_new();
  entry_text = g_strdup(gtk_entry_get_text(GTK_ENTRY(entry)));
  if_text = g_strstrip(entry_text);
  if_name = strrchr(if_text, ' ');
  if (if_name == NULL) {
    if_name = if_text;
  } else {
    if_name++;
  }

  /*
   * If the interface name is in the list of known interfaces, get
   * its list of link-layer types and set the option menu to display it.
   *
   * If it's not, don't bother - the user might be in the middle of
   * editing the list, or it might be a remote device in which case
   * getting the list could take an arbitrarily-long period of time.
   * The list currently won't contain any remote devices (as
   * "pcap_findalldevs()" doesn't know about remote devices, and neither
   * does the code we use if "pcap_findalldevs()" isn't available), but
   * should contain all the local devices on which you can capture.
   */
  lt_list = NULL;
  if (*if_name != '\0') {
    /*
     * Try to get the list of known interfaces.
     */
    if_list = get_interface_list(&err, err_buf);
    if (if_list != NULL) {
      /*
       * We have the list - check it.
       */
      for (if_entry = if_list; if_entry != NULL;
	   if_entry = g_list_next(if_entry)) {
	if_info = if_entry->data;
	if (strcmp(if_info->name, if_name) == 0) {
	  /*
	   * It's in the list.
	   * Get the list of link-layer types for it.
	   */
	  lt_list = get_pcap_linktype_list(if_name, err_buf);
	}
      }
      free_interface_list(if_list);
    }
  }
  g_free(entry_text);
  num_supported_link_types = 0;
  for (lt_entry = lt_list; lt_entry != NULL; lt_entry = g_list_next(lt_entry)) {
    data_link_info = lt_entry->data;
    if (data_link_info->description != NULL) {
      lt_menu_item = gtk_menu_item_new_with_label(data_link_info->description);
      OBJECT_SET_DATA(lt_menu_item, E_CAP_LT_OM_KEY, linktype_om);
      SIGNAL_CONNECT(lt_menu_item, "activate", select_link_type_cb,
                     GINT_TO_POINTER(data_link_info->dlt));
      num_supported_link_types++;
    } else {
      /* Not supported - tell them about it but don't let them select it. */
      linktype_menu_label = g_strdup_printf("%s (not supported)",
                                            data_link_info->name);
      lt_menu_item = gtk_menu_item_new_with_label(linktype_menu_label);
      g_free(linktype_menu_label);
      gtk_widget_set_sensitive(lt_menu_item, FALSE);
    }
    gtk_menu_append(GTK_MENU(lt_menu), lt_menu_item);
    gtk_widget_show(lt_menu_item);
  }
  if (lt_list != NULL)
    free_pcap_linktype_list(lt_list);
  gtk_option_menu_set_menu(GTK_OPTION_MENU(linktype_om), lt_menu);
  gtk_widget_set_sensitive(linktype_lb, num_supported_link_types >= 2);
  gtk_widget_set_sensitive(linktype_om, num_supported_link_types >= 2);
}

void
capture_prep_cb(GtkWidget *w _U_, gpointer d _U_)
{
  GtkWidget     *main_vb,
                *capture_fr, *capture_vb,
                *if_hb, *if_cb, *if_lb,
                *linktype_hb, *linktype_lb, *linktype_om,
                *snap_hb, *snap_cb, *snap_sb, *snap_lb,
                *promisc_cb,
                *filter_hb, *filter_bt, *filter_te,
                *file_fr, *file_vb,
                *file_hb, *file_bt, *file_te,
                *ringbuffer_hb, *ringbuffer_on_tb, *ringbuffer_nbf_lb, *ringbuffer_nbf_sb,
                *display_fr, *display_vb,
                *sync_cb, *auto_scroll_cb,
                *limit_fr, *limit_vb,
                *count_hb, *count_cb, *count_sb, *count_lb,
                *filesize_hb, *filesize_cb, *filesize_sb, *filesize_lb,
                *duration_hb, *duration_cb, *duration_sb, *duration_lb,
		*ring_duration_hb, *ring_duration_cb, *ring_duration_sb, 
		*ring_duration_lb,
                *resolv_fr, *resolv_vb,
                *m_resolv_cb, *n_resolv_cb, *t_resolv_cb,
                *bbox, *ok_bt, *cancel_bt;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
  GtkAdjustment *snap_adj, *ringbuffer_nbf_adj,
		*count_adj, *filesize_adj, *duration_adj, *ring_duration_adj;
  GList         *if_list, *combo_list;
  int           err;
  char          err_str[PCAP_ERRBUF_SIZE];

  if (cap_open_w != NULL) {
    /* There's already a "Capture Options" dialog box; reactivate it. */
    reactivate_window(cap_open_w);
    return;
  }

#ifdef _WIN32
  /* Is WPcap loaded? */
  if (!has_wpcap) {
	  simple_dialog(ESD_TYPE_CRIT, NULL,
		  "Unable to load WinPcap (wpcap.dll); Ethereal will not be able\n"
		  "to capture packets.\n\n"
		  "In order to capture packets, WinPcap must be installed; see\n"
		  "\n"
		  "        http://winpcap.polito.it/\n"
		  "\n"
		  "or the mirror at\n"
		  "\n"
		  "        http://winpcap.mirror.ethereal.com/\n"
		  "\n"
		  "or the mirror at\n"
		  "\n"
		  "        http://www.mirrors.wiretapped.net/security/packet-capture/winpcap/\n"
		  "\n"
		  "for a downloadable version of WinPcap and for instructions\n"
		  "on how to install WinPcap.");
	  return;
  }
#endif

  if_list = get_interface_list(&err, err_str);
  if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
    simple_dialog(ESD_TYPE_WARN, NULL, "Can't get list of interfaces: %s",
			err_str);
  }

  cap_open_w = dlg_window_new("Ethereal: Capture Options");
  SIGNAL_CONNECT(cap_open_w, "destroy", capture_prep_destroy_cb, NULL);

#if GTK_MAJOR_VERSION < 2
  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(cap_open_w), accel_group);
#endif

  main_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(cap_open_w), main_vb);
  gtk_widget_show(main_vb);

  /* Capture-related options frame */
  capture_fr = gtk_frame_new("Capture");
  gtk_container_add(GTK_CONTAINER(main_vb), capture_fr);
  gtk_widget_show(capture_fr);

  capture_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(capture_fr), capture_vb);
  gtk_widget_show(capture_vb);

  /* Interface row */
  if_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(capture_vb), if_hb);
  gtk_widget_show(if_hb);

  if_lb = gtk_label_new("Interface:");
  gtk_box_pack_start(GTK_BOX(if_hb), if_lb, FALSE, FALSE, 6);
  gtk_widget_show(if_lb);

  if_cb = gtk_combo_new();
  combo_list = build_capture_combo_list(if_list, TRUE);
  if (combo_list != NULL)
    gtk_combo_set_popdown_strings(GTK_COMBO(if_cb), combo_list);
  if (cfile.iface == NULL && prefs.capture_device != NULL) {
    /* No interface was specified on the command line or in a previous
       capture, but there is one specified in the preferences file;
       make the one from the preferences file the default */
    cfile.iface	= g_strdup(prefs.capture_device);
  }
  if (cfile.iface != NULL)
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry), cfile.iface);
  else if (combo_list != NULL) {
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry),
		       (char *)combo_list->data);
  }
  free_capture_combo_list(combo_list);
  free_interface_list(if_list);
  gtk_box_pack_start(GTK_BOX(if_hb), if_cb, TRUE, TRUE, 6);
  gtk_widget_show(if_cb);

  /* Linktype row */
  linktype_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(capture_vb), linktype_hb);
  gtk_widget_show(linktype_hb);

  linktype_lb = gtk_label_new("Link-layer header type:");
  gtk_box_pack_start(GTK_BOX(linktype_hb), linktype_lb, FALSE, FALSE, 6);
  gtk_widget_show(linktype_lb);

  linktype_om = gtk_option_menu_new();
  OBJECT_SET_DATA(linktype_om, E_CAP_LT_OM_LABEL_KEY, linktype_lb);
  /* Default to "use the default" */
  OBJECT_SET_DATA(linktype_om, E_CAP_OM_LT_VALUE_KEY, GINT_TO_POINTER(-1));
  set_link_type_list(linktype_om, GTK_COMBO(if_cb)->entry);
  gtk_box_pack_start (GTK_BOX(linktype_hb), linktype_om, FALSE, FALSE, 0);
  gtk_widget_show(linktype_om);
  SIGNAL_CONNECT(GTK_ENTRY(GTK_COMBO(if_cb)->entry), "changed",
                 capture_prep_interface_changed_cb, linktype_om);

  /* Capture length row */
  snap_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(capture_vb), snap_hb);
  gtk_widget_show(snap_hb);

  snap_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("_Limit each packet to", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(snap_cb),
		capture_opts.has_snaplen);
  SIGNAL_CONNECT(snap_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(snap_hb), snap_cb, FALSE, FALSE, 0);
  gtk_widget_show(snap_cb);

  snap_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat) capture_opts.snaplen,
    MIN_PACKET_SIZE, WTAP_MAX_PACKET_SIZE, 1.0, 10.0, 0.0);
  snap_sb = gtk_spin_button_new (snap_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (snap_sb), TRUE);
  WIDGET_SET_SIZE(snap_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(snap_hb), snap_sb, FALSE, FALSE, 0);
  gtk_widget_show(snap_sb);

  snap_lb = gtk_label_new("bytes");
  gtk_misc_set_alignment(GTK_MISC(snap_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(snap_hb), snap_lb, FALSE, FALSE, 0);
  gtk_widget_show(snap_lb);

  /* Promiscuous mode row */
  promisc_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
      "Capture packets in _promiscuous mode", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(promisc_cb),
		capture_opts.promisc_mode);
  gtk_container_add(GTK_CONTAINER(capture_vb), promisc_cb);
  gtk_widget_show(promisc_cb);

  /* Filter row */
  filter_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(capture_vb), filter_hb);
  gtk_widget_show(filter_hb);

  filter_bt = gtk_button_new_with_label("Filter:");
  SIGNAL_CONNECT(filter_bt, "clicked", capture_filter_construct_cb, NULL);
  SIGNAL_CONNECT(filter_bt, "destroy", filter_button_destroy_cb, NULL);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_bt, FALSE, FALSE, 3);
  gtk_widget_show(filter_bt);

  filter_te = gtk_entry_new();
  if (cfile.cfilter) gtk_entry_set_text(GTK_ENTRY(filter_te), cfile.cfilter);
  OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_te, TRUE, TRUE, 3);
  gtk_widget_show(filter_te);

  /* Capture file-related options frame */
  file_fr = gtk_frame_new("Capture file(s)");
  gtk_container_add(GTK_CONTAINER(main_vb), file_fr);
  gtk_widget_show(file_fr);

  file_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_fr), file_vb);
  gtk_widget_show(file_vb);

  /* File row */
  file_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_vb), file_hb);
  gtk_widget_show(file_hb);

  file_bt = gtk_button_new_with_label("File:");
  gtk_box_pack_start(GTK_BOX(file_hb), file_bt, FALSE, FALSE, 3);
  gtk_widget_show(file_bt);

  file_te = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(file_hb), file_te, TRUE, TRUE, 3);
  gtk_widget_show(file_te);

  SIGNAL_CONNECT(file_bt, "clicked", capture_prep_file_cb, file_te);

  /* Ring buffer row */
  ringbuffer_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_vb), ringbuffer_hb);
  gtk_widget_show(ringbuffer_hb);

  ringbuffer_on_tb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Use _ring buffer", accel_group);
  /* Ring buffer mode is allowed only if we're not doing an "Update list of
     packets in real time" capture, so force it off if we're doing such
     a capture. */
  if (capture_opts.sync_mode)
    capture_opts.ringbuffer_on = FALSE;
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ringbuffer_on_tb),
		capture_opts.ringbuffer_on);
  SIGNAL_CONNECT(ringbuffer_on_tb, "toggled", capture_prep_adjust_sensitivity,
                 cap_open_w);
  gtk_box_pack_start(GTK_BOX(ringbuffer_hb), ringbuffer_on_tb, FALSE, FALSE, 0);
  gtk_widget_show(ringbuffer_on_tb);

  ringbuffer_nbf_lb = gtk_label_new("Number of files");
  gtk_misc_set_alignment(GTK_MISC(ringbuffer_nbf_lb), 1, 0.5);
  gtk_box_pack_start(GTK_BOX(ringbuffer_hb), ringbuffer_nbf_lb, FALSE, FALSE, 6);
  gtk_widget_show(ringbuffer_nbf_lb);

  ringbuffer_nbf_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat) capture_opts.ringbuffer_num_files,
    RINGBUFFER_MIN_NUM_FILES, RINGBUFFER_MAX_NUM_FILES, 1.0, 10.0, 0.0);
  ringbuffer_nbf_sb = gtk_spin_button_new (ringbuffer_nbf_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (ringbuffer_nbf_sb), TRUE);
  WIDGET_SET_SIZE(ringbuffer_nbf_sb, 40, -1);
  gtk_box_pack_start (GTK_BOX(ringbuffer_hb), ringbuffer_nbf_sb, TRUE, TRUE, 0);
  gtk_widget_show(ringbuffer_nbf_sb);

  /* Ring buffer duration row */
  ring_duration_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_vb), ring_duration_hb);
  gtk_widget_show(ring_duration_hb);

  ring_duration_cb = gtk_check_button_new_with_label("Rotate capture file every");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ring_duration_cb),
			      capture_opts.has_ring_duration);
  SIGNAL_CONNECT(ring_duration_cb, "toggled", 
		 capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(ring_duration_hb), ring_duration_cb, 
		     FALSE, FALSE, 0);
  gtk_widget_show(ring_duration_cb);

  ring_duration_adj = (GtkAdjustment *)gtk_adjustment_new((gfloat)capture_opts.ringbuffer_duration,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  ring_duration_sb = gtk_spin_button_new (ring_duration_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (ring_duration_sb), TRUE);
  WIDGET_SET_SIZE(ring_duration_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(ring_duration_hb), ring_duration_sb, 
		      FALSE, FALSE, 0);
  gtk_widget_show(ring_duration_sb);

  ring_duration_lb = gtk_label_new("second(s)");
  gtk_misc_set_alignment(GTK_MISC(ring_duration_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(ring_duration_hb), ring_duration_lb, 
		     FALSE, FALSE, 0);
  gtk_widget_show(ring_duration_lb);

  /* Display-related options frame */
  display_fr = gtk_frame_new("Display options");
  gtk_container_add(GTK_CONTAINER(main_vb), display_fr);
  gtk_widget_show(display_fr);

  display_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(display_fr), display_vb);
  gtk_widget_show(display_vb);

  /* "Update display in real time" row */
  sync_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
      "_Update list of packets in real time", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(sync_cb),
		capture_opts.sync_mode);
  SIGNAL_CONNECT(sync_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_container_add(GTK_CONTAINER(display_vb), sync_cb);
  gtk_widget_show(sync_cb);

  /* "Auto-scroll live update" row */
  auto_scroll_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"_Automatic scrolling in live capture", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(auto_scroll_cb), auto_scroll_live);
  gtk_container_add(GTK_CONTAINER(display_vb), auto_scroll_cb);
  gtk_widget_show(auto_scroll_cb);

  /* Capture limits frame */
  limit_fr = gtk_frame_new("Capture limits");
  gtk_container_add(GTK_CONTAINER(main_vb), limit_fr);
  gtk_widget_show(limit_fr);

  limit_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(limit_fr), limit_vb);
  gtk_widget_show(limit_vb);

  /* Count row */
  count_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(limit_vb), count_hb);
  gtk_widget_show(count_hb);

  count_cb = gtk_check_button_new_with_label("Stop capture after");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(count_cb),
		capture_opts.has_autostop_count);
  SIGNAL_CONNECT(count_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(count_hb), count_cb, FALSE, FALSE, 0);
  gtk_widget_show(count_cb);

  count_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)capture_opts.autostop_count,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  count_sb = gtk_spin_button_new (count_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (count_sb), TRUE);
  WIDGET_SET_SIZE(count_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(count_hb), count_sb, FALSE, FALSE, 0);
  gtk_widget_show(count_sb);

  count_lb = gtk_label_new("packet(s) captured");
  gtk_misc_set_alignment(GTK_MISC(count_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(count_hb), count_lb, FALSE, FALSE, 0);
  gtk_widget_show(count_lb);

  /* Filesize row */
  filesize_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(limit_vb), filesize_hb);
  gtk_widget_show(filesize_hb);

  filesize_cb = gtk_check_button_new_with_label("");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(filesize_cb),
		capture_opts.has_autostop_filesize);
  SIGNAL_CONNECT(filesize_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(filesize_hb), filesize_cb, FALSE, FALSE, 0);
  gtk_widget_show(filesize_cb);

  filesize_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)capture_opts.autostop_filesize,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  filesize_sb = gtk_spin_button_new (filesize_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (filesize_sb), TRUE);
  WIDGET_SET_SIZE(filesize_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(filesize_hb), filesize_sb, FALSE, FALSE, 0);
  gtk_widget_show(filesize_sb);

  filesize_lb = gtk_label_new("");
  gtk_misc_set_alignment(GTK_MISC(filesize_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(filesize_hb), filesize_lb, FALSE, FALSE, 0);
  gtk_widget_show(filesize_lb);

  /* Duration row */
  duration_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(limit_vb), duration_hb);
  gtk_widget_show(duration_hb);

  duration_cb = gtk_check_button_new_with_label("Stop capture after");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(duration_cb),
		capture_opts.has_autostop_duration);
  SIGNAL_CONNECT(duration_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(duration_hb), duration_cb, FALSE, FALSE, 0);
  gtk_widget_show(duration_cb);

  duration_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)capture_opts.autostop_duration,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  duration_sb = gtk_spin_button_new (duration_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (duration_sb), TRUE);
  WIDGET_SET_SIZE(duration_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(duration_hb), duration_sb, FALSE, FALSE, 0);
  gtk_widget_show(duration_sb);

  duration_lb = gtk_label_new("second(s)");
  gtk_misc_set_alignment(GTK_MISC(duration_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(duration_hb), duration_lb, FALSE, FALSE, 0);
  gtk_widget_show(duration_lb);

  /* Resolution options frame */
  resolv_fr = gtk_frame_new("Name resolution");
  gtk_container_add(GTK_CONTAINER(main_vb), resolv_fr);
  gtk_widget_show(resolv_fr);

  resolv_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_add(GTK_CONTAINER(resolv_fr), resolv_vb);
  gtk_widget_show(resolv_vb);

  m_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"Enable _MAC name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(m_resolv_cb),
		g_resolv_flags & RESOLV_MAC);
  gtk_container_add(GTK_CONTAINER(resolv_vb), m_resolv_cb);
  gtk_widget_show(m_resolv_cb);

  n_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"Enable _network name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(n_resolv_cb),
		g_resolv_flags & RESOLV_NETWORK);
  gtk_container_add(GTK_CONTAINER(resolv_vb), n_resolv_cb);
  gtk_widget_show(n_resolv_cb);

  t_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"Enable _transport name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(t_resolv_cb),
		g_resolv_flags & RESOLV_TRANSPORT);
  gtk_container_add(GTK_CONTAINER(resolv_vb), t_resolv_cb);
  gtk_widget_show(t_resolv_cb);

  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = BUTTON_NEW_FROM_STOCK(STOCK_OK);
  SIGNAL_CONNECT(ok_bt, "clicked", capture_prep_ok_cb, cap_open_w);
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = BUTTON_NEW_FROM_STOCK(STOCK_CANCEL);
  SIGNAL_CONNECT(cancel_bt, "clicked", capture_prep_close_cb, cap_open_w);
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Attach pointers to needed widgets to the capture prefs window/object */
  OBJECT_SET_DATA(cap_open_w, E_CAP_IFACE_KEY, if_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_SNAP_CB_KEY, snap_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_SNAP_SB_KEY, snap_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_LT_OM_KEY, linktype_om);
  OBJECT_SET_DATA(cap_open_w, E_CAP_PROMISC_KEY, promisc_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILT_KEY,  filter_te);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILE_TE_KEY,  file_te);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_ON_TB_KEY,  ringbuffer_on_tb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_NBF_LB_KEY,  ringbuffer_nbf_lb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_NBF_SB_KEY,  ringbuffer_nbf_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_DURATION_CB_KEY,  ring_duration_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_DURATION_SB_KEY,  ring_duration_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_SYNC_KEY,  sync_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_AUTO_SCROLL_KEY, auto_scroll_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_COUNT_CB_KEY, count_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_COUNT_SB_KEY, count_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILESIZE_CB_KEY, filesize_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILESIZE_SB_KEY, filesize_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILESIZE_LB_KEY, filesize_lb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_DURATION_CB_KEY,  duration_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_DURATION_SB_KEY,  duration_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_M_RESOLVE_KEY,  m_resolv_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_N_RESOLVE_KEY,  n_resolv_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_T_RESOLVE_KEY,  t_resolv_cb);

  /* Set the sensitivity of various widgets as per the settings of other
     widgets. */
  capture_prep_adjust_sensitivity(NULL, cap_open_w);

  /* Catch the "activate" signal on the filter and file name text
     entries, so that if the user types Return there, we act as if the
     "OK" button had been selected, as happens if Return is typed if some
     widget that *doesn't* handle the Return key has the input focus. */
  dlg_set_activate(filter_te, ok_bt);
  dlg_set_activate(file_te, ok_bt);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(cap_open_w, cancel_bt);

  /* XXX - why does not

     gtk_widget_grab_focus(if_cb);

    give the initial focus to the "Interface" combo box?

    Or should I phrase that as "why does GTK+ continually frustrate
    attempts to make GUIs driveable from the keyboard?"  We have to
    go catch the activate signal on every single GtkEntry widget
    (rather than having widgets whose activate signal is *not*
    caught not catch the Return keystroke, so that it passes on,
    ultimately, to the window, which can activate the default
    widget, i.e. the "OK" button); we have to catch the "key_press_event"
    signal and have the handler check for ESC, so that we can have ESC
    activate the "Cancel" button; in order to support Alt+<key> mnemonics
    for buttons and the like, we may have to construct an accelerator
    group by hand and set up the accelerators by hand (if that even
    works - I've not tried it yet); we have to do a "gtk_widget_grab_focus()"
    to keep some container widget from getting the initial focus, so that
    you don't have to tab into the first widget in order to start typing
    in it; and it now appears that you simply *can't* make a combo box
    get the initial focus, at least not in the obvious fashion. Sigh.... */

  gtk_widget_show(cap_open_w);
}

static void
select_link_type_cb(GtkWidget *w, gpointer data)
{
  int new_linktype = GPOINTER_TO_INT(data);
  GtkWidget *linktype_om = OBJECT_GET_DATA(w, E_CAP_LT_OM_KEY);
  int old_linktype = GPOINTER_TO_INT(OBJECT_GET_DATA(linktype_om, E_CAP_OM_LT_VALUE_KEY));

  if (old_linktype != new_linktype)
    OBJECT_SET_DATA(linktype_om, E_CAP_OM_LT_VALUE_KEY, GINT_TO_POINTER(new_linktype));
}

static void
capture_prep_file_cb(GtkWidget *w, gpointer file_te)
{
  GtkWidget *caller = gtk_widget_get_toplevel(w);
  GtkWidget *fs;

  /* Has a file selection dialog box already been opened for that top-level
     widget? */
  fs = OBJECT_GET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Just re-activate that dialog box. */
    reactivate_window(fs);
    return;
  }

  fs = file_selection_new ("Ethereal: Capture File");

  /* If we've opened a file, start out by showing the files in the directory
     in which that file resided. */
  if (last_open_dir)
    gtk_file_selection_set_filename(GTK_FILE_SELECTION(fs), last_open_dir);

  OBJECT_SET_DATA(fs, E_CAP_FILE_TE_KEY, file_te);

  /* Set the E_FS_CALLER_PTR_KEY for the new dialog to point to our caller. */
  OBJECT_SET_DATA(fs, E_FS_CALLER_PTR_KEY, caller);

  /* Set the E_FILE_SEL_DIALOG_PTR_KEY for the caller to point to us */
  OBJECT_SET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY, fs);

  /* Call a handler when the file selection box is destroyed, so we can inform
     our caller, if any, that it's been destroyed. */
  SIGNAL_CONNECT(fs, "destroy", cap_prep_fs_destroy_cb, file_te);

  SIGNAL_CONNECT(GTK_FILE_SELECTION(fs)->ok_button, "clicked", cap_prep_fs_ok_cb, fs);

  /* Connect the cancel_button to destroy the widget */
  SIGNAL_CONNECT(GTK_FILE_SELECTION(fs)->cancel_button, "clicked", cap_prep_fs_cancel_cb,
                 fs);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(fs, GTK_FILE_SELECTION(fs)->cancel_button);

  gtk_widget_show(fs);
}

static void
cap_prep_fs_ok_cb(GtkWidget *w _U_, gpointer data)
{
  gchar     *cf_name;

  cf_name = g_strdup(gtk_file_selection_get_filename(
    GTK_FILE_SELECTION (data)));

  /* Perhaps the user specified a directory instead of a file.
     Check whether they did. */
  if (test_for_directory(cf_name) == EISDIR) {
        /* It's a directory - set the file selection box to display it. */
        set_last_open_dir(cf_name);
        g_free(cf_name);
        gtk_file_selection_set_filename(GTK_FILE_SELECTION(data),
          last_open_dir);
        return;
  }

  gtk_entry_set_text(GTK_ENTRY(OBJECT_GET_DATA(data, E_CAP_FILE_TE_KEY)), cf_name);

  gtk_widget_destroy(GTK_WIDGET(data));
  g_free(cf_name);
}

static void
cap_prep_fs_cancel_cb(GtkWidget *w _U_, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
cap_prep_fs_destroy_cb(GtkWidget *win, GtkWidget* file_te)
{
  GtkWidget *caller;

  /* Get the widget that requested that we be popped up.
     (It should arrange to destroy us if it's destroyed, so
     that we don't get a pointer to a non-existent window here.) */
  caller = OBJECT_GET_DATA(win, E_FS_CALLER_PTR_KEY);

  /* Tell it we no longer exist. */
  OBJECT_SET_DATA(caller, E_FILE_SEL_DIALOG_PTR_KEY, NULL);

  /* Now nuke this window. */
  gtk_grab_remove(GTK_WIDGET(win));
  gtk_widget_destroy(GTK_WIDGET(win));

  /* Give the focus to the file text entry widget so the user can just press
     Return to start the capture. */
  gtk_widget_grab_focus(file_te);
}

static void
capture_prep_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w) {
  GtkWidget *if_cb, *snap_cb, *snap_sb, *promisc_cb, *filter_te,
            *file_te, *ringbuffer_on_tb, *ringbuffer_nbf_sb,
            *linktype_om, *sync_cb, *auto_scroll_cb,
            *count_cb, *count_sb,
            *filesize_cb, *filesize_sb,
            *duration_cb, *duration_sb,
            *ring_duration_cb, *ring_duration_sb,
            *m_resolv_cb, *n_resolv_cb, *t_resolv_cb;
  gchar *entry_text;
  gchar *if_text;
  gchar *if_name;
  const gchar *filter_text;
  gchar *save_file;
  const gchar *g_save_file;
  gchar *cf_name;
  gchar *dirname;

  if_cb     = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_IFACE_KEY);
  snap_cb   = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SNAP_CB_KEY);
  snap_sb   = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SNAP_SB_KEY);
  linktype_om = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_LT_OM_KEY);
  promisc_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_PROMISC_KEY);
  filter_te = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILT_KEY);
  file_te   = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILE_TE_KEY);
  ringbuffer_on_tb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_ON_TB_KEY);
  ringbuffer_nbf_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_NBF_SB_KEY);
  ring_duration_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_DURATION_CB_KEY);
  ring_duration_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_DURATION_SB_KEY);
  sync_cb   = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SYNC_KEY);
  auto_scroll_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_AUTO_SCROLL_KEY);
  count_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_COUNT_CB_KEY);
  count_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_COUNT_SB_KEY);
  filesize_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILESIZE_CB_KEY);
  filesize_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILESIZE_SB_KEY);
  duration_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_DURATION_CB_KEY);
  duration_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_DURATION_SB_KEY);
  m_resolv_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_M_RESOLVE_KEY);
  n_resolv_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_N_RESOLVE_KEY);
  t_resolv_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_T_RESOLVE_KEY);

  entry_text =
    g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry)));
  if_text = g_strstrip(entry_text);
  /* Remove interface description; if it's present, it comes before
     the interface name, and there's a space between them, and the
     interface name is assumed to contain no space, so we look backwards
     in the string for a space. */
  if_name = strrchr(if_text, ' ');
  if (if_name == NULL) {
    if_name = if_text;
  } else {
    if_name++;
  }
  if (*if_name == '\0') {
    simple_dialog(ESD_TYPE_CRIT, NULL,
      "You didn't specify an interface on which to capture packets.");
    g_free(entry_text);
    return;
  }
  if (cfile.iface)
    g_free(cfile.iface);
  cfile.iface = g_strdup(if_name);
  g_free(entry_text);

  capture_opts.linktype =
      GPOINTER_TO_INT(OBJECT_GET_DATA(linktype_om, E_CAP_OM_LT_VALUE_KEY));

  capture_opts.has_snaplen =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(snap_cb));
  if (capture_opts.has_snaplen) {
    capture_opts.snaplen =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(snap_sb));
    if (capture_opts.snaplen < 1)
      capture_opts.snaplen = WTAP_MAX_PACKET_SIZE;
    else if (capture_opts.snaplen < MIN_PACKET_SIZE)
      capture_opts.snaplen = MIN_PACKET_SIZE;
  }

  capture_opts.promisc_mode =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(promisc_cb));

  /* XXX - don't try to get clever and set "cfile.filter" to NULL if the
     filter string is empty, as an indication that we don't have a filter
     and thus don't have to set a filter when capturing - the version of
     libpcap in Red Hat Linux 6.1, and versions based on later patches
     in that series, don't bind the AF_PACKET socket to an interface
     until a filter is set, which means they aren't bound at all if
     no filter is set, which means no packets arrive as input on that
     socket, which means Ethereal never sees any packets. */
  filter_text = gtk_entry_get_text(GTK_ENTRY(filter_te));
  if (cfile.cfilter)
    g_free(cfile.cfilter);
  g_assert(filter_text != NULL);
  cfile.cfilter = g_strdup(filter_text);

  g_save_file = gtk_entry_get_text(GTK_ENTRY(file_te));
  if (g_save_file && g_save_file[0]) {
    /* User specified a file to which the capture should be written. */
    save_file = g_strdup(g_save_file);
    /* Save the directory name for future file dialogs. */
    cf_name = g_strdup(g_save_file);
    dirname = get_dirname(cf_name);  /* Overwrites cf_name */
    set_last_open_dir(dirname);
    g_free(cf_name);
  } else {
    /* User didn't specify a file; save to a temporary file. */
    save_file = NULL;
  }

  capture_opts.has_autostop_count =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(count_cb));
  if (capture_opts.has_autostop_count)
    capture_opts.autostop_count =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(count_sb));

  capture_opts.has_autostop_filesize =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(filesize_cb));
  if (capture_opts.has_autostop_filesize)
    capture_opts.autostop_filesize =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(filesize_sb));

  capture_opts.has_autostop_duration =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(duration_cb));
  if (capture_opts.has_autostop_duration)
    capture_opts.autostop_duration =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(duration_sb));

  capture_opts.sync_mode =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb));

  auto_scroll_live =
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(auto_scroll_cb));

  g_resolv_flags = RESOLV_NONE;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(m_resolv_cb)))
    g_resolv_flags |= RESOLV_MAC;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(n_resolv_cb)))
    g_resolv_flags |= RESOLV_NETWORK;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(t_resolv_cb)))
    g_resolv_flags |= RESOLV_TRANSPORT;

  capture_opts.ringbuffer_on =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_on_tb)) &&
	!(capture_opts.sync_mode);
  if (capture_opts.ringbuffer_on) {
    if (save_file == NULL) {
      simple_dialog(ESD_TYPE_CRIT, NULL,
        "You must specify a save file if you want to use the ring buffer.");
      return;
    } else if (!capture_opts.has_autostop_filesize) {
      simple_dialog(ESD_TYPE_CRIT, NULL,
        "You must specify a file size at which to rotate the capture files\n"
        "if you want to use the ring buffer.");
      g_free(save_file);
      return;
    }
  }

  capture_opts.ringbuffer_num_files =
    gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ringbuffer_nbf_sb));
  if (capture_opts.ringbuffer_num_files > RINGBUFFER_MAX_NUM_FILES)
    capture_opts.ringbuffer_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
  else if (capture_opts.ringbuffer_num_files < RINGBUFFER_MIN_NUM_FILES)
    capture_opts.ringbuffer_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif

  capture_opts.has_ring_duration =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_duration_cb));
  if (capture_opts.has_ring_duration)
    capture_opts.ringbuffer_duration =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ring_duration_sb));

  gtk_widget_destroy(GTK_WIDGET(parent_w));

  do_capture(save_file);
  if (save_file != NULL)
    g_free(save_file);
}

static void
capture_prep_close_cb(GtkWidget *close_bt _U_, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
capture_prep_destroy_cb(GtkWidget *win, gpointer user_data _U_)
{
  GtkWidget *fs;

  /* Is there a file selection dialog associated with this
     Capture Options dialog? */
  fs = OBJECT_GET_DATA(win, E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Destroy it. */
    gtk_widget_destroy(fs);
  }

  /* Note that we no longer have a "Capture Options" dialog box. */
  cap_open_w = NULL;
}

static void
capture_prep_interface_changed_cb(GtkWidget *entry, gpointer argp)
{
  GtkWidget *linktype_om = argp;

  set_link_type_list(linktype_om, entry);
}

/*
 * Adjust the sensitivity of various widgets as per the current setting
 * of other widgets.
 */
static void
capture_prep_adjust_sensitivity(GtkWidget *tb _U_, gpointer parent_w)
{
  GtkWidget *if_cb,
            *snap_cb, *snap_sb,
            *ringbuffer_on_tb, *ringbuffer_nbf_lb, *ringbuffer_nbf_sb,
            *sync_cb, *auto_scroll_cb,
            *count_cb, *count_sb,
            *filesize_cb, *filesize_sb, *filesize_lb,
	    *duration_cb, *duration_sb,
	    *ring_duration_cb, *ring_duration_sb;

  if_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_IFACE_KEY);
  snap_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SNAP_CB_KEY);
  snap_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SNAP_SB_KEY);
  ringbuffer_on_tb  = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_ON_TB_KEY);
  ringbuffer_nbf_lb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_NBF_LB_KEY);
  ringbuffer_nbf_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_NBF_SB_KEY);
  ring_duration_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_DURATION_CB_KEY);
  ring_duration_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_DURATION_SB_KEY);
  sync_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SYNC_KEY);
  auto_scroll_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_AUTO_SCROLL_KEY);
  count_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_COUNT_CB_KEY);
  count_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_COUNT_SB_KEY);
  filesize_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILESIZE_CB_KEY);
  filesize_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILESIZE_SB_KEY);
  filesize_lb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILESIZE_LB_KEY);
  duration_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_DURATION_CB_KEY);
  duration_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_DURATION_SB_KEY);

  /* The snapshot length spinbox is sensitive iff the "Limit each packet
     to" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(snap_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(snap_cb)));

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb))) {
    /* "Update list of packets in real time" captures enabled; we don't
       support ring buffer mode for those captures, so turn ring buffer
       mode off if it's on, and make its toggle button, and the spin
       button for the number of ring buffer files (and the spin button's
       label), insensitive. */
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_on_tb))) {
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ringbuffer_on_tb), FALSE);
    }
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_on_tb), FALSE);

    /* Auto-scroll mode is meaningful only in "Update list of packets
       in real time" captures, so make its toggle button sensitive. */
    gtk_widget_set_sensitive(GTK_WIDGET(auto_scroll_cb), TRUE);
  } else {
    /* "Update list of packets in real time" captures disabled; that
       means ring buffer mode is OK, so make its toggle button
       sensitive. */
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_on_tb), TRUE);

    /* Auto-scroll mode is meaningful only in "Update list of packets
       in real time" captures, so make its toggle button insensitive. */
    gtk_widget_set_sensitive(GTK_WIDGET(auto_scroll_cb), FALSE);
  }

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_on_tb))) {
    /* Ring buffer mode enabled.  Make the spin button for the number
       of ring buffer files, and its label, sensitive. */
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_lb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_cb), TRUE);

    /* Also, indicate that the file size is a size at which to switch
       ring buffer files, not a size at which to stop the capture,
       turn its button on. */
    gtk_label_set_text(GTK_LABEL(GTK_BIN(filesize_cb)->child),
        "Rotate capture file every");
    gtk_label_set_text(GTK_LABEL(filesize_lb), "kilobyte(s)");
    gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(filesize_cb), TRUE);
  } else {
    /* Ring buffer mode disabled.  Make the spin button for the number
       of ring buffer files, and its label insensitive. */
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_lb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_cb), FALSE);

    /* Also, indicate that the file size is a size at which to stop the
       capture, not a size at which to switch ring buffer files. */
    gtk_label_set_text(GTK_LABEL(GTK_BIN(filesize_cb)->child),
        "Stop capture after");
    gtk_label_set_text(GTK_LABEL(filesize_lb), "kilobyte(s) captured");
  }

  /* The maximum packet count spinbox is sensitive if the "Stop capture
     after N packets captured" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(count_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(count_cb)));

  /* The maximum file size spinbox is sensitive if the "Stop capture
     after N kilobytes captured" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(filesize_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(filesize_cb)));

  /* The capture duration spinbox is sensitive if the "Stop capture
     after N seconds" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(duration_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(duration_cb)));

  /* The ring duration spinbox is sensitive if the "Rotate capture file
     after N seconds" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_duration_cb)));
}

#endif /* HAVE_LIBPCAP */
