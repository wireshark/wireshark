/* capture_dlg.c
 * Routines for packet capture windows
 *
 * $Id: capture_dlg.c,v 1.116 2004/03/04 19:31:21 ulfl Exp $
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
#include "file_dlg.h"
#include "help_dlg.h"

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
#define E_CAP_RING_NBF_CB_KEY "cap_ringbuffer_nbf_cb"
#define E_CAP_RING_NBF_SB_KEY "cap_ringbuffer_nbf_sb"
#define E_CAP_RING_NBF_LB_KEY "cap_ringbuffer_nbf_lb"
#define E_CAP_RING_FILESIZE_CB_KEY "cap_ringbuffer_filesize_cb"
#define E_CAP_RING_FILESIZE_SB_KEY "cap_ringbuffer_filesize_sb"
#define E_CAP_RING_FILESIZE_LB_KEY "cap_ringbuffer_filesize_lb"
#define E_CAP_RING_DURATION_CB_KEY "cap_ringbuffer_duration_cb"
#define E_CAP_RING_DURATION_SB_KEY "cap_ringbuffer_duration_sb"
#define E_CAP_RING_DURATION_LB_KEY "cap_ringbuffer_duration_lb"
#define E_CAP_SYNC_KEY        "cap_sync"
#define E_CAP_AUTO_SCROLL_KEY "cap_auto_scroll"
#define E_CAP_COUNT_CB_KEY    "cap_count_cb"
#define E_CAP_COUNT_SB_KEY    "cap_count_sb"
#define E_CAP_FILESIZE_CB_KEY "cap_filesize_cb"
#define E_CAP_FILESIZE_SB_KEY "cap_filesize_sb"
#define E_CAP_FILESIZE_LB_KEY "cap_filesize_lb"
#define E_CAP_DURATION_CB_KEY "cap_duration_cb"
#define E_CAP_DURATION_SB_KEY "cap_duration_sb"
#define E_CAP_FILES_CB_KEY    "cap_files_cb"
#define E_CAP_FILES_SB_KEY    "cap_files_sb"
#define E_CAP_FILES_LB_KEY    "cap_files_lb"
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
 * Given text that contains an interface name possibly prefixed by an
 * interface description, extract the interface name.
 */
static char *
get_if_name(char *if_text)
{
  char *if_name;

#ifdef WIN32
  /*
   * We cannot assume that the interface name doesn't contain a space;
   * some names on Windows OT do.
   *
   * We also can't assume it begins with "\Device\", either, as, on
   * Windows OT, WinPcap doesn't put "\Device\" in front of the name.
   *
   * As I remember, we can't assume that the interface description
   * doesn't contain a colon, either; I think some do.
   *
   * We can probably assume that the interface *name* doesn't contain
   * a colon, however; if any interface name does contain a colon on
   * Windows, it'll be time to just get rid of the damn interface
   * descriptions in the drop-down list, have just the names in the
   * drop-down list, and have a "Browse..." button to browse for interfaces,
   * with names, descriptions, IP addresses, blah blah blah available when
   * possible.
   *
   * So we search backwards for a colon.  If we don't find it, just
   * return the entire string; otherwise, skip the colon and any blanks
   * after it, and return that string.
   */
   if_name = strrchr(if_text, ':');
   if (if_name == NULL) {
     if_name = if_text;
   } else {
     if_name++;
     while (*if_name == ' ')
       if_name++;
   }
#else
  /*
   * There's a space between the interface description and name, and
   * the interface name shouldn't have a space in it (it doesn't, on
   * UNIX systems); look backwards in the string for a space.
   *
   * (An interface name might, however, contain a colon in it, which
   * is why we don't use the colon search on UNIX.)
   */
  if_name = strrchr(if_text, ' ');
  if (if_name == NULL) {
    if_name = if_text;
  } else {
    if_name++;
  }
#endif
  return if_name;
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
  if_name = get_if_name(if_text);

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
  }
  if (lt_list != NULL)
    free_pcap_linktype_list(lt_list);
  gtk_option_menu_set_menu(GTK_OPTION_MENU(linktype_om), lt_menu);
  gtk_widget_set_sensitive(linktype_lb, num_supported_link_types >= 2);
  gtk_widget_set_sensitive(linktype_om, num_supported_link_types >= 2);
}

void
capture_prep(void)
{
  GtkWidget     *main_vb,
                *main_hb, *left_vb, *right_vb,

                *capture_fr, *capture_vb,
                *if_hb, *if_cb, *if_lb,
                *linktype_hb, *linktype_lb, *linktype_om,
                *snap_hb, *snap_cb, *snap_sb, *snap_lb,
                *promisc_cb,
                *filter_hb, *filter_bt, *filter_te,

                *file_fr, *file_vb,
                *file_hb, *file_bt, *file_lb, *file_te,
                *ringbuffer_hb, *ringbuffer_on_tb, 
                *ring_filesize_hb, *ring_filesize_cb, *ring_filesize_sb, *ring_filesize_lb,
                *ring_duration_hb, *ring_duration_cb, *ring_duration_sb, *ring_duration_lb,
                *ringbuffer_nbf_hb, *ringbuffer_nbf_cb, *ringbuffer_nbf_sb, *ringbuffer_nbf_lb, 

                *limit_fr, *limit_vb,
                *count_hb, *count_cb, *count_sb, *count_lb,
                *filesize_hb, *filesize_cb, *filesize_sb, *filesize_lb,
                *duration_hb, *duration_cb, *duration_sb, *duration_lb,
                *files_hb, *files_cb, *files_sb, *files_lb,

                *display_fr, *display_vb,
                *sync_cb, *auto_scroll_cb,

                *resolv_fr, *resolv_vb,
                *m_resolv_cb, *n_resolv_cb, *t_resolv_cb,
                *bbox, *ok_bt, *cancel_bt,
                *help_bt;
#if GTK_MAJOR_VERSION < 2
  GtkAccelGroup *accel_group;
#endif
  GtkAdjustment *snap_adj, *ringbuffer_nbf_adj,
		*count_adj, *filesize_adj, *duration_adj, *files_adj, *ring_filesize_adj, *ring_duration_adj;
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
	  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
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
    simple_dialog(ESD_TYPE_WARN, ESD_BTN_OK, "Can't get list of interfaces: %s",
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

  /* Capture-related options frame */
  capture_fr = gtk_frame_new("Capture");
  gtk_container_add(GTK_CONTAINER(main_vb), capture_fr);

  capture_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(capture_vb), 5);
  gtk_container_add(GTK_CONTAINER(capture_fr), capture_vb);

  /* Interface row */
  if_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(capture_vb), if_hb);

  if_lb = gtk_label_new("Interface:");
  gtk_box_pack_start(GTK_BOX(if_hb), if_lb, FALSE, FALSE, 6);

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

  /* Linktype row */
  linktype_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(capture_vb), linktype_hb, FALSE, FALSE, 0);

  linktype_lb = gtk_label_new("Link-layer header type:");
  gtk_box_pack_start(GTK_BOX(linktype_hb), linktype_lb, FALSE, FALSE, 6);

  linktype_om = gtk_option_menu_new();
  OBJECT_SET_DATA(linktype_om, E_CAP_LT_OM_LABEL_KEY, linktype_lb);
  /* Default to "use the default" */
  OBJECT_SET_DATA(linktype_om, E_CAP_OM_LT_VALUE_KEY, GINT_TO_POINTER(-1));
  set_link_type_list(linktype_om, GTK_COMBO(if_cb)->entry);
  gtk_box_pack_start (GTK_BOX(linktype_hb), linktype_om, FALSE, FALSE, 0);
  SIGNAL_CONNECT(GTK_ENTRY(GTK_COMBO(if_cb)->entry), "changed",
                 capture_prep_interface_changed_cb, linktype_om);

  /* Promiscuous mode row */
  promisc_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
      "Capture packets in _promiscuous mode", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(promisc_cb),
		capture_opts.promisc_mode);
  gtk_container_add(GTK_CONTAINER(capture_vb), promisc_cb);

  /* Capture length row */
  snap_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(capture_vb), snap_hb);

  snap_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC("_Limit each packet to", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(snap_cb),
		capture_opts.has_snaplen);
  SIGNAL_CONNECT(snap_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(snap_hb), snap_cb, FALSE, FALSE, 0);

  snap_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat) capture_opts.snaplen,
    MIN_PACKET_SIZE, WTAP_MAX_PACKET_SIZE, 1.0, 10.0, 0.0);
  snap_sb = gtk_spin_button_new (snap_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (snap_sb), TRUE);
  WIDGET_SET_SIZE(snap_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(snap_hb), snap_sb, FALSE, FALSE, 0);

  snap_lb = gtk_label_new("bytes");
  gtk_misc_set_alignment(GTK_MISC(snap_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(snap_hb), snap_lb, FALSE, FALSE, 0);

  /* Filter row */
  filter_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(capture_vb), filter_hb, FALSE, FALSE, 0);

  filter_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_CAPTURE_FILTER_ENTRY);
  SIGNAL_CONNECT(filter_bt, "clicked", capture_filter_construct_cb, NULL);
  SIGNAL_CONNECT(filter_bt, "destroy", filter_button_destroy_cb, NULL);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_bt, FALSE, FALSE, 3);

  filter_te = gtk_entry_new();
  if (cfile.cfilter) gtk_entry_set_text(GTK_ENTRY(filter_te), cfile.cfilter);
  OBJECT_SET_DATA(filter_bt, E_FILT_TE_PTR_KEY, filter_te);
  gtk_box_pack_start(GTK_BOX(filter_hb), filter_te, TRUE, TRUE, 3);

  main_hb = gtk_hbox_new(FALSE, 5);
  gtk_container_border_width(GTK_CONTAINER(main_hb), 0);
  gtk_container_add(GTK_CONTAINER(main_vb), main_hb);

  left_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(left_vb), 0);
  gtk_box_pack_start(GTK_BOX(main_hb), left_vb, TRUE, TRUE, 0);

  right_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(right_vb), 0);
  gtk_box_pack_start(GTK_BOX(main_hb), right_vb, FALSE, FALSE, 0);


  /* Capture file-related options frame */
  file_fr = gtk_frame_new("Capture File(s)");
  gtk_container_add(GTK_CONTAINER(left_vb), file_fr);

  file_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(file_vb), 5);
  gtk_container_add(GTK_CONTAINER(file_fr), file_vb);

  /* File row */
  file_hb = gtk_hbox_new(FALSE, 3);
  gtk_box_pack_start(GTK_BOX(file_vb), file_hb, FALSE, FALSE, 0);

  file_lb = gtk_label_new("File:");
  gtk_box_pack_start(GTK_BOX(file_hb), file_lb, FALSE, FALSE, 3);

  file_te = gtk_entry_new();
  gtk_box_pack_start(GTK_BOX(file_hb), file_te, TRUE, TRUE, 3);

  file_bt = BUTTON_NEW_FROM_STOCK(ETHEREAL_STOCK_BROWSE);
  gtk_box_pack_start(GTK_BOX(file_hb), file_bt, FALSE, FALSE, 3);

  SIGNAL_CONNECT(file_bt, "clicked", capture_prep_file_cb, file_te);

  /* Ring buffer row */
  ringbuffer_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_vb), ringbuffer_hb);

  ringbuffer_on_tb = CHECK_BUTTON_NEW_WITH_MNEMONIC("Use _multiple files", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ringbuffer_on_tb),
		capture_opts.multi_files_on);
  SIGNAL_CONNECT(ringbuffer_on_tb, "toggled", capture_prep_adjust_sensitivity,
                 cap_open_w);
  gtk_box_pack_start(GTK_BOX(ringbuffer_hb), ringbuffer_on_tb, FALSE, FALSE, 0);

  /* Ring buffer filesize row */
  ring_filesize_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_vb), ring_filesize_hb);

  ring_filesize_cb = gtk_check_button_new_with_label("Next file every");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ring_filesize_cb),
		capture_opts.has_autostop_filesize);
  SIGNAL_CONNECT(ring_filesize_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(ring_filesize_hb), ring_filesize_cb, FALSE, FALSE, 0);

  ring_filesize_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)capture_opts.autostop_filesize,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  ring_filesize_sb = gtk_spin_button_new (ring_filesize_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (ring_filesize_sb), TRUE);
  WIDGET_SET_SIZE(ring_filesize_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(ring_filesize_hb), ring_filesize_sb, FALSE, FALSE, 0);

  ring_filesize_lb = gtk_label_new("kilobyte(s)");
  gtk_misc_set_alignment(GTK_MISC(ring_filesize_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(ring_filesize_hb), ring_filesize_lb, FALSE, FALSE, 0);

  /* Ring buffer duration row */
  ring_duration_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_vb), ring_duration_hb);

  ring_duration_cb = gtk_check_button_new_with_label("Next file every");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ring_duration_cb),
			      capture_opts.has_file_duration);
  SIGNAL_CONNECT(ring_duration_cb, "toggled", 
		 capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(ring_duration_hb), ring_duration_cb, FALSE, FALSE, 0);

  ring_duration_adj = (GtkAdjustment *)gtk_adjustment_new((gfloat)capture_opts.file_duration,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  ring_duration_sb = gtk_spin_button_new (ring_duration_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (ring_duration_sb), TRUE);
  WIDGET_SET_SIZE(ring_duration_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(ring_duration_hb), ring_duration_sb, FALSE, FALSE, 0);

  ring_duration_lb = gtk_label_new("second(s)");
  gtk_misc_set_alignment(GTK_MISC(ring_duration_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(ring_duration_hb), ring_duration_lb, 
		     FALSE, FALSE, 0);

  /* Ring buffer files row */
  ringbuffer_nbf_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_vb), ringbuffer_nbf_hb);

  ringbuffer_nbf_cb = gtk_check_button_new_with_label("Ring buffer with");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ringbuffer_nbf_cb),
		capture_opts.has_ring_num_files);
  SIGNAL_CONNECT(ringbuffer_nbf_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(ringbuffer_nbf_hb), ringbuffer_nbf_cb, FALSE, FALSE, 0);

  ringbuffer_nbf_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat) capture_opts.ring_num_files,
    2/*RINGBUFFER_MIN_NUM_FILES*/, RINGBUFFER_MAX_NUM_FILES, 1.0, 10.0, 0.0);
  ringbuffer_nbf_sb = gtk_spin_button_new (ringbuffer_nbf_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (ringbuffer_nbf_sb), TRUE);
  WIDGET_SET_SIZE(ringbuffer_nbf_sb, 80, -1);
  SIGNAL_CONNECT(ringbuffer_nbf_sb, "changed", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start (GTK_BOX(ringbuffer_nbf_hb), ringbuffer_nbf_sb, FALSE, FALSE, 0);

  ringbuffer_nbf_lb = gtk_label_new("files");
  gtk_misc_set_alignment(GTK_MISC(ringbuffer_nbf_lb), 1, 0.5);
  gtk_box_pack_start(GTK_BOX(ringbuffer_nbf_hb), ringbuffer_nbf_lb, FALSE, FALSE, 3);

  /* Files row */
  files_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(file_vb), files_hb);

  files_cb = gtk_check_button_new_with_label("Stop capture after");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(files_cb),
		capture_opts.has_autostop_files);
  SIGNAL_CONNECT(files_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(files_hb), files_cb, FALSE, FALSE, 0);

  files_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)capture_opts.autostop_files,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  files_sb = gtk_spin_button_new (files_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (files_sb), TRUE);
  WIDGET_SET_SIZE(files_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(files_hb), files_sb, FALSE, FALSE, 0);

  files_lb = gtk_label_new("file(s)");
  gtk_misc_set_alignment(GTK_MISC(files_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(files_hb), files_lb, FALSE, FALSE, 0);

  /* Capture limits frame */
  limit_fr = gtk_frame_new("Stop Capture ...");
  gtk_container_add(GTK_CONTAINER(left_vb), limit_fr);

  limit_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(limit_vb), 5);
  gtk_container_add(GTK_CONTAINER(limit_fr), limit_vb);

  /* Packet count row */
  count_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(limit_vb), count_hb);

  count_cb = gtk_check_button_new_with_label("... after");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(count_cb),
		capture_opts.has_autostop_packets);
  SIGNAL_CONNECT(count_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(count_hb), count_cb, FALSE, FALSE, 0);

  count_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)capture_opts.autostop_packets,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  count_sb = gtk_spin_button_new (count_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (count_sb), TRUE);
  WIDGET_SET_SIZE(count_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(count_hb), count_sb, FALSE, FALSE, 0);

  count_lb = gtk_label_new("packet(s)");
  gtk_misc_set_alignment(GTK_MISC(count_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(count_hb), count_lb, FALSE, FALSE, 0);

  /* Filesize row */
  filesize_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(limit_vb), filesize_hb);

  filesize_cb = gtk_check_button_new_with_label("... after");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(filesize_cb),
		capture_opts.has_autostop_filesize);
  SIGNAL_CONNECT(filesize_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(filesize_hb), filesize_cb, FALSE, FALSE, 0);

  filesize_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)capture_opts.autostop_filesize,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  filesize_sb = gtk_spin_button_new (filesize_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (filesize_sb), TRUE);
  WIDGET_SET_SIZE(filesize_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(filesize_hb), filesize_sb, FALSE, FALSE, 0);

  filesize_lb = gtk_label_new("kilobyte(s)");
  gtk_misc_set_alignment(GTK_MISC(filesize_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(filesize_hb), filesize_lb, FALSE, FALSE, 0);

  /* Duration row */
  duration_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(limit_vb), duration_hb);

  duration_cb = gtk_check_button_new_with_label("... after");
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(duration_cb),
		capture_opts.has_autostop_duration);
  SIGNAL_CONNECT(duration_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_box_pack_start(GTK_BOX(duration_hb), duration_cb, FALSE, FALSE, 0);

  duration_adj = (GtkAdjustment *) gtk_adjustment_new((gfloat)capture_opts.autostop_duration,
    1, (gfloat)INT_MAX, 1.0, 10.0, 0.0);
  duration_sb = gtk_spin_button_new (duration_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (duration_sb), TRUE);
  WIDGET_SET_SIZE(duration_sb, 80, -1);
  gtk_box_pack_start (GTK_BOX(duration_hb), duration_sb, FALSE, FALSE, 0);

  duration_lb = gtk_label_new("second(s)");
  gtk_misc_set_alignment(GTK_MISC(duration_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(duration_hb), duration_lb, FALSE, FALSE, 0);

  /* Display-related options frame */
  display_fr = gtk_frame_new("Display Options");
  gtk_container_add(GTK_CONTAINER(right_vb), display_fr);

  display_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(display_vb), 5);
  gtk_container_add(GTK_CONTAINER(display_fr), display_vb);

  /* "Update display in real time" row */
  sync_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
      "_Update list of packets in real time", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(sync_cb),
		capture_opts.sync_mode);
  SIGNAL_CONNECT(sync_cb, "toggled", capture_prep_adjust_sensitivity, cap_open_w);
  gtk_container_add(GTK_CONTAINER(display_vb), sync_cb);

  /* "Auto-scroll live update" row */
  auto_scroll_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"_Automatic scrolling in live capture", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(auto_scroll_cb), auto_scroll_live);
  gtk_container_add(GTK_CONTAINER(display_vb), auto_scroll_cb);

  /* Name Resolution frame */
  resolv_fr = gtk_frame_new("Name Resolution");
  gtk_container_add(GTK_CONTAINER(right_vb), resolv_fr);

  resolv_vb = gtk_vbox_new(FALSE, 0);
  gtk_container_border_width(GTK_CONTAINER(resolv_vb), 5);
  gtk_container_add(GTK_CONTAINER(resolv_fr), resolv_vb);

  m_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"Enable _MAC name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(m_resolv_cb),
		g_resolv_flags & RESOLV_MAC);
  gtk_container_add(GTK_CONTAINER(resolv_vb), m_resolv_cb);

  n_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"Enable _network name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(n_resolv_cb),
		g_resolv_flags & RESOLV_NETWORK);
  gtk_container_add(GTK_CONTAINER(resolv_vb), n_resolv_cb);

  t_resolv_cb = CHECK_BUTTON_NEW_WITH_MNEMONIC(
		"Enable _transport name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(t_resolv_cb),
		g_resolv_flags & RESOLV_TRANSPORT);
  gtk_container_add(GTK_CONTAINER(resolv_vb), t_resolv_cb);

  /* Button row: OK and cancel buttons */
  bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_CANCEL, GTK_STOCK_HELP, NULL);
  gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 5);

  ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
  SIGNAL_CONNECT(ok_bt, "clicked", capture_prep_ok_cb, cap_open_w);
  gtk_widget_grab_default(ok_bt);

  cancel_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
  SIGNAL_CONNECT(cancel_bt, "clicked", capture_prep_close_cb, cap_open_w);

  help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
  SIGNAL_CONNECT(help_bt, "clicked", help_topic_cb, "Capturing");

  /* Attach pointers to needed widgets to the capture prefs window/object */
  OBJECT_SET_DATA(cap_open_w, E_CAP_IFACE_KEY, if_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_SNAP_CB_KEY, snap_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_SNAP_SB_KEY, snap_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_LT_OM_KEY, linktype_om);
  OBJECT_SET_DATA(cap_open_w, E_CAP_PROMISC_KEY, promisc_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILT_KEY,  filter_te);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILE_TE_KEY,  file_te);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_ON_TB_KEY,  ringbuffer_on_tb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_NBF_CB_KEY,  ringbuffer_nbf_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_NBF_SB_KEY,  ringbuffer_nbf_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_NBF_LB_KEY,  ringbuffer_nbf_lb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_FILESIZE_CB_KEY,  ring_filesize_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_FILESIZE_SB_KEY,  ring_filesize_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_FILESIZE_LB_KEY,  ring_filesize_lb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_DURATION_CB_KEY,  ring_duration_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_DURATION_SB_KEY,  ring_duration_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_RING_DURATION_LB_KEY,  ring_duration_lb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_SYNC_KEY,  sync_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_AUTO_SCROLL_KEY, auto_scroll_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_COUNT_CB_KEY, count_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_COUNT_SB_KEY, count_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILESIZE_CB_KEY, filesize_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILESIZE_SB_KEY, filesize_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILESIZE_LB_KEY, filesize_lb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_DURATION_CB_KEY,  duration_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_DURATION_SB_KEY,  duration_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILES_CB_KEY, files_cb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILES_SB_KEY, files_sb);
  OBJECT_SET_DATA(cap_open_w, E_CAP_FILES_LB_KEY, files_lb);
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

  gtk_widget_show_all(cap_open_w);
}

static void 
capture_prep_answered_cb(gpointer dialog _U_, gint btn, gpointer data)
{
    switch(btn) {
    case(ESD_BTN_YES):
        /* save file first */
        file_save_as_cmd(after_save_capture_dialog, data);
        break;
    case(ESD_BTN_NO):
        capture_prep();
        break;
    case(ESD_BTN_CANCEL):
        break;
    default:
        g_assert_not_reached();
    }
}

void
capture_prep_cb(GtkWidget *w _U_, gpointer d _U_)
{
  gpointer  dialog;

  if((cfile.state != FILE_CLOSED) && !cfile.user_saved) {
    /* user didn't saved his current file, ask him */
    dialog = simple_dialog(ESD_TYPE_CONFIRMATION, ESD_BTNS_YES_NO_CANCEL,
                PRIMARY_TEXT_START "Save capture file before starting a new capture?" PRIMARY_TEXT_END "\n\n"
                "If you start a new capture without saving, your current capture data will be discarded.");
    simple_dialog_set_cb(dialog, capture_prep_answered_cb, NULL);
  } else {
    /* unchanged file, just capture a new one */
    capture_prep();
  }
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

  gtk_widget_show_all(fs);
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
            *file_te, *ringbuffer_on_tb, *ringbuffer_nbf_sb, *ringbuffer_nbf_cb,
            *linktype_om, *sync_cb, *auto_scroll_cb,
            *count_cb, *count_sb,
            *filesize_cb, *filesize_sb,
            *duration_cb, *duration_sb,
            *ring_filesize_cb, *ring_filesize_sb,
            *ring_duration_cb, *ring_duration_sb,
            *files_cb, *files_sb,
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
  ringbuffer_nbf_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_NBF_CB_KEY);
  ringbuffer_nbf_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_NBF_SB_KEY);
  ring_filesize_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_FILESIZE_CB_KEY);
  ring_filesize_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_FILESIZE_SB_KEY);
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
  files_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILES_CB_KEY);
  files_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILES_SB_KEY);
  m_resolv_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_M_RESOLVE_KEY);
  n_resolv_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_N_RESOLVE_KEY);
  t_resolv_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_T_RESOLVE_KEY);

  entry_text =
    g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry)));
  if_text = g_strstrip(entry_text);
  if_name = get_if_name(if_text);
  if (*if_name == '\0') {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
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

  capture_opts.has_autostop_packets =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(count_cb));
  if (capture_opts.has_autostop_packets)
    capture_opts.autostop_packets =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(count_sb));

  capture_opts.has_autostop_duration =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(duration_cb));
  if (capture_opts.has_autostop_duration)
    capture_opts.autostop_duration =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(duration_sb));

  capture_opts.sync_mode =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb));

  auto_scroll_live =
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(auto_scroll_cb));

  g_resolv_flags |= g_resolv_flags & RESOLV_CONCURRENT;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(m_resolv_cb)))
    g_resolv_flags |= RESOLV_MAC;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(n_resolv_cb)))
    g_resolv_flags |= RESOLV_NETWORK;
  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(t_resolv_cb)))
    g_resolv_flags |= RESOLV_TRANSPORT;

  capture_opts.has_ring_num_files =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_nbf_cb));  

  capture_opts.ring_num_files =
    gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ringbuffer_nbf_sb));
  if (capture_opts.ring_num_files > RINGBUFFER_MAX_NUM_FILES)
    capture_opts.ring_num_files = RINGBUFFER_MAX_NUM_FILES;
#if RINGBUFFER_MIN_NUM_FILES > 0
  else if (capture_opts.ring_num_files < RINGBUFFER_MIN_NUM_FILES)
    capture_opts.ring_num_files = RINGBUFFER_MIN_NUM_FILES;
#endif

  capture_opts.multi_files_on =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_on_tb));

  if(capture_opts.sync_mode)
    capture_opts.multi_files_on = FALSE;

  if (capture_opts.multi_files_on) {
    capture_opts.has_autostop_filesize =
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_filesize_cb));
    if (capture_opts.has_autostop_filesize)
      capture_opts.autostop_filesize =
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ring_filesize_sb));

    /* test if the settings are ok for a ringbuffer */
    if (save_file == NULL) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        PRIMARY_TEXT_START "Multiple files: No capture file name given!\n\n" PRIMARY_TEXT_END
        "You must specify a filename if you want to use multiple files.");
      return;
    } else if (!capture_opts.has_autostop_filesize) {
      simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
        PRIMARY_TEXT_START "Multiple files: No file limit given!\n\n" PRIMARY_TEXT_END
        "You must specify a file size at which is switched to the next capture file\n"
        "if you want to use multiple files.");
      g_free(save_file);
      return;
    }
  } else {
    capture_opts.has_autostop_filesize =
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(filesize_cb));
    if (capture_opts.has_autostop_filesize)
      capture_opts.autostop_filesize =
        gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(filesize_sb));
  }

  capture_opts.has_file_duration =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_duration_cb));
  if (capture_opts.has_file_duration)
    capture_opts.file_duration =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ring_duration_sb));

  capture_opts.has_autostop_files =
    gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(files_cb));
  if (capture_opts.has_autostop_files)
    capture_opts.autostop_files =
      gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(files_sb));

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
            *ringbuffer_on_tb, *ringbuffer_nbf_cb, *ringbuffer_nbf_sb, *ringbuffer_nbf_lb,
            *ring_filesize_cb, *ring_filesize_sb, *ring_filesize_lb,
            *sync_cb, *auto_scroll_cb,
            *count_cb, *count_sb,
            *filesize_cb, *filesize_sb, *filesize_lb,
            *duration_cb, *duration_sb,
            *files_cb, *files_sb, *files_lb,
            *ring_duration_cb, *ring_duration_sb, *ring_duration_lb;


  if_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_IFACE_KEY);
  snap_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SNAP_CB_KEY);
  snap_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SNAP_SB_KEY);
  ringbuffer_on_tb  = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_ON_TB_KEY);
  ringbuffer_nbf_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_NBF_CB_KEY);
  ringbuffer_nbf_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_NBF_SB_KEY);
  ringbuffer_nbf_lb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_NBF_LB_KEY);
  ring_filesize_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_FILESIZE_CB_KEY);
  ring_filesize_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_FILESIZE_SB_KEY);
  ring_filesize_lb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_FILESIZE_LB_KEY);
  ring_duration_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_DURATION_CB_KEY);
  ring_duration_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_DURATION_SB_KEY);
  ring_duration_lb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_RING_DURATION_LB_KEY);
  sync_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_SYNC_KEY);
  auto_scroll_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_AUTO_SCROLL_KEY);
  count_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_COUNT_CB_KEY);
  count_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_COUNT_SB_KEY);
  filesize_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILESIZE_CB_KEY);
  filesize_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILESIZE_SB_KEY);
  filesize_lb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILESIZE_LB_KEY);
  duration_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_DURATION_CB_KEY);
  duration_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_DURATION_SB_KEY);
  files_cb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILES_CB_KEY);
  files_sb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILES_SB_KEY);
  files_lb = (GtkWidget *) OBJECT_GET_DATA(parent_w, E_CAP_FILES_LB_KEY);

  /* The snapshot length spinbox is sensitive if the "Limit each packet
     to" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(snap_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(snap_cb)));


  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb))) {
    /* "Update list of packets in real time" captures enabled; we don't
       support ring buffer mode for those captures, so turn ring buffer
       mode off if it's on, and make its toggle button, and the spin
       button for the number of ring buffer files (and the spin button's
       label), insensitive. */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ringbuffer_on_tb), FALSE);
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
    /* Ring buffer mode enabled. */
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ring_filesize_cb), TRUE);

    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_nbf_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_lb), TRUE);

    /* The ring filesize spinbox is sensitive if the "Next capture file
         after N kilobytes" checkbox is on. */
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_filesize_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_lb), TRUE);

    /* The ring duration spinbox is sensitive if the "Next capture file
         after N seconds" checkbox is on. */
    gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ring_duration_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_lb), TRUE);

    gtk_widget_set_sensitive(GTK_WIDGET(filesize_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(filesize_sb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(filesize_lb), FALSE);

    gtk_widget_set_sensitive(GTK_WIDGET(files_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(files_sb), 
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(files_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(files_lb), TRUE);
  } else {
    /* Ring buffer mode disabled. */
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_lb), FALSE);

    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_sb),FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_filesize_lb),FALSE);

    gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_sb),FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(ring_duration_lb),FALSE);

    /* The maximum file size spinbox is sensitive if the "Stop capture
         after N kilobytes" checkbox is on. */
    gtk_widget_set_sensitive(GTK_WIDGET(filesize_cb), TRUE);
    gtk_widget_set_sensitive(GTK_WIDGET(filesize_sb),
          gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(filesize_cb)));
    gtk_widget_set_sensitive(GTK_WIDGET(filesize_lb), TRUE);

    gtk_widget_set_sensitive(GTK_WIDGET(files_cb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(files_sb), FALSE);
    gtk_widget_set_sensitive(GTK_WIDGET(files_lb), FALSE);
  }

  /* The maximum packet count spinbox is sensitive if the "Stop capture
     after N packets" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(count_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(count_cb)));

  /* The capture duration spinbox is sensitive if the "Stop capture
     after N seconds" checkbox is on. */
  gtk_widget_set_sensitive(GTK_WIDGET(duration_sb),
      gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(duration_cb)));
}

#endif /* HAVE_LIBPCAP */
