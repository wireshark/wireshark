/* capture_dlg.c
 * Routines for packet capture windows
 *
 * $Id: capture_dlg.c,v 1.50 2001/12/04 08:25:58 guy Exp $
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

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <gtk/gtk.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <time.h>

#include <pcap.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "capture.h"
#include "globals.h"
#include "resolv.h"
#include "main.h"
#include "ui_util.h"
#include "capture_dlg.h"
#include "filter_prefs.h"
#include "simple_dialog.h"
#include "dlg_utils.h"
#include "pcap-util.h"
#include "prefs.h"
#include "ringbuffer.h"

#ifdef _WIN32
#include "capture-wpcap.h"
#endif

/* Capture callback data keys */
#define E_CAP_IFACE_KEY       "cap_iface"
#define E_CAP_FILT_KEY        "cap_filter_te"
#define E_CAP_FILE_TE_KEY     "cap_file_te"
#define E_CAP_COUNT_KEY       "cap_count"
#define E_CAP_SNAP_KEY        "cap_snap"
#define E_CAP_PROMISC_KEY     "cap_promisc"
#define E_CAP_SYNC_KEY        "cap_sync"
#define E_CAP_AUTO_SCROLL_KEY "cap_auto_scroll"
#define E_CAP_M_RESOLVE_KEY   "cap_m_resolve"
#define E_CAP_N_RESOLVE_KEY   "cap_n_resolve"
#define E_CAP_T_RESOLVE_KEY   "cap_t_resolve"
#define E_CAP_FILESIZE_KEY    "cap_filesize"
#define E_CAP_DURATION_KEY    "cap_duration"
#define E_CAP_RING_TB_KEY     "cap_ringbuffer_tb"
#define E_CAP_RING_SB_KEY     "cap_ringbuffer_sb"

#define E_FS_CALLER_PTR_KEY       "fs_caller_ptr"
#define E_FILE_SEL_DIALOG_PTR_KEY "file_sel_dialog_ptr"

static void
capture_prep_file_cb(GtkWidget *w, gpointer te);

static void
cap_prep_fs_ok_cb(GtkWidget *w, gpointer data);

static void
cap_prep_fs_cancel_cb(GtkWidget *w, gpointer data);

static void
cap_prep_fs_destroy_cb(GtkWidget *win, gpointer data);

static void
capture_prep_sync_toggle_cb(GtkWidget *sync_cb, gpointer parent_w);

static void
capture_prep_ringbuffer_toggle_cb(GtkWidget *ringbuffer_tb, gpointer parent_w);

static void
capture_prep_ok_cb(GtkWidget *ok_bt, gpointer parent_w);

static void
capture_prep_close_cb(GtkWidget *close_bt, gpointer parent_w);

static void
capture_prep_destroy_cb(GtkWidget *win, gpointer user_data);

void
capture_stop_cb(GtkWidget *w, gpointer d)
{
    capture_stop();
}

/*
 * Keep a static pointer to the current "Capture Preferences" window, if
 * any, so that if somebody tries to do "Capture:Start" while there's
 * already a "Capture Preferences" window up, we just pop up the existing
 * one, rather than creating a new one.
 */
static GtkWidget *cap_open_w;

void
capture_prep_cb(GtkWidget *w, gpointer d)
{
  GtkWidget     *if_cb, *if_lb,
                *count_lb, *count_cb, *main_vb,
                *filter_bt, *filter_te,
                *file_bt, *file_te,
                *filesize_lb, *filesize_cb,
                *duration_lb, *duration_cb,
                *caplen_hb, *table,
                *bbox, *ok_bt, *cancel_bt, *snap_lb,
                *snap_sb, *promisc_cb, *sync_cb, *auto_scroll_cb,
                *m_resolv_cb, *n_resolv_cb, *t_resolv_cb,
                *ringbuffer_hb, *ringbuffer_on_tb, *ringbuffer_nbf_lb, *ringbuffer_nbf_sb;
  GtkAccelGroup *accel_group;
  GtkAdjustment *snap_adj, *ringbuffer_nbf_adj;
  GList         *if_list, *count_list = NULL, *filesize_list = NULL, *duration_list = NULL;
  gchar         *count_item1 = "0 (Infinite)", count_item2[16],
                *filesize_item1 = "0 (Infinite)", filesize_item2[16],
                *duration_item1 = "0 (Infinite)", duration_item2[16];
  int           err;
  char          err_str[PCAP_ERRBUF_SIZE];

  if (cap_open_w != NULL) {
    /* There's already a "Capture Preferences" dialog box; reactivate it. */
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
		  "        http://netgroup-serv.polito.it/winpcap/\n"
		  "\n"
		  "or the mirror at\n"
		  "\n"
		  "        http://netgroup-mirror.ethereal.com/winpcap/\n"
		  "\n"
		  "or the mirror at\n"
		  "\n"
		  "        http://www.wiretapped.net/security/packet-capture/winpcap/default.htm\n"
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
  
  cap_open_w = dlg_window_new("Ethereal: Capture Preferences");
  gtk_signal_connect(GTK_OBJECT(cap_open_w), "destroy",
	GTK_SIGNAL_FUNC(capture_prep_destroy_cb), NULL);

  /* Accelerator group for the accelerators (or, as they're called in
     Windows and, I think, in Motif, "mnemonics"; Alt+<key> is a mnemonic,
     Ctrl+<key> is an accelerator). */
  accel_group = gtk_accel_group_new();
  gtk_window_add_accel_group(GTK_WINDOW(cap_open_w), accel_group);
  
  main_vb = gtk_vbox_new(FALSE, 3);
  gtk_container_border_width(GTK_CONTAINER(main_vb), 5);
  gtk_container_add(GTK_CONTAINER(cap_open_w), main_vb);
  gtk_widget_show(main_vb);
  
  /* Table : container of the first 6 rows */
  table = gtk_table_new (6, 2, FALSE);
  gtk_table_set_row_spacings(GTK_TABLE (table), 5);
  gtk_table_set_col_spacings(GTK_TABLE (table), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), table);
  gtk_widget_show(table);

  /* Interface row */
  
  if_lb = gtk_label_new("Interface:");
  gtk_table_attach_defaults(GTK_TABLE(table), if_lb, 0, 1, 0, 1);
  gtk_widget_show(if_lb);
  
  if_cb = gtk_combo_new();
  if (if_list != NULL)
    gtk_combo_set_popdown_strings(GTK_COMBO(if_cb), if_list);
  if (cfile.iface)
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry), cfile.iface);
  else if (if_list)
    gtk_entry_set_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry), if_list->data);
  gtk_table_attach_defaults(GTK_TABLE(table), if_cb, 1, 2, 0, 1);
  gtk_widget_show(if_cb);
  
  free_interface_list(if_list);

  /* Count row */
  
  count_lb = gtk_label_new("Count:");
  gtk_table_attach_defaults(GTK_TABLE(table), count_lb, 0, 1, 1, 2);
  gtk_widget_show(count_lb);
  
  count_list = g_list_append(count_list, count_item1);
  if (cfile.count) {
    snprintf(count_item2, 15, "%d", cfile.count);
    count_list = g_list_append(count_list, count_item2);
  }

  count_cb = gtk_combo_new();
  gtk_combo_set_popdown_strings(GTK_COMBO(count_cb), count_list);
  gtk_table_attach_defaults(GTK_TABLE(table), count_cb, 1, 2, 1, 2);
  gtk_widget_show(count_cb);

  while (count_list)
    count_list = g_list_remove_link(count_list, count_list);

  /* Filesize row */
  
  filesize_lb = gtk_label_new("File size:");
  gtk_table_attach_defaults(GTK_TABLE(table), filesize_lb, 0, 1, 2, 3);
  gtk_widget_show(filesize_lb);
  
  filesize_list = g_list_append(filesize_list, filesize_item1);
  if (cfile.autostop_filesize) {
    snprintf(filesize_item2, 15, "%d", cfile.autostop_filesize);
    filesize_list = g_list_append(filesize_list, filesize_item2);
  }

  filesize_cb = gtk_combo_new();
  gtk_combo_set_popdown_strings(GTK_COMBO(filesize_cb), filesize_list);
  gtk_table_attach_defaults(GTK_TABLE(table), filesize_cb, 1, 2, 2, 3);
  gtk_widget_show(filesize_cb);

  while (filesize_list)
    filesize_list = g_list_remove_link(filesize_list, filesize_list);

  /* Duration row */
  
  duration_lb = gtk_label_new("Duration:");
  gtk_table_attach_defaults(GTK_TABLE(table), duration_lb, 0, 1, 3, 4);
  gtk_widget_show(duration_lb);
  
  duration_list = g_list_append(duration_list, duration_item1);
  if (cfile.autostop_duration) {
    snprintf(duration_item2, 15, "%d", cfile.autostop_duration);
    duration_list = g_list_append(duration_list, duration_item2);
  }

  duration_cb = gtk_combo_new();
  gtk_combo_set_popdown_strings(GTK_COMBO(duration_cb), duration_list);
  gtk_table_attach_defaults(GTK_TABLE(table), duration_cb, 1, 2, 3, 4);
  gtk_widget_show(duration_cb);

  while (duration_list)
    duration_list = g_list_remove_link(duration_list, duration_list);

  /* Filter row */
  
  filter_bt = gtk_button_new_with_label("Filter:");
  gtk_signal_connect(GTK_OBJECT(filter_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_filter_construct_cb), NULL);
  gtk_table_attach_defaults(GTK_TABLE(table), filter_bt, 0, 1, 4, 5);
  gtk_widget_show(filter_bt);
  
  filter_te = gtk_entry_new();
  if (cfile.cfilter) gtk_entry_set_text(GTK_ENTRY(filter_te), cfile.cfilter);
  gtk_object_set_data(GTK_OBJECT(filter_bt), E_FILT_TE_PTR_KEY, filter_te);
  gtk_table_attach_defaults(GTK_TABLE(table), filter_te, 1, 2, 4, 5);
  gtk_widget_show(filter_te);
  
  /* File row */
  
  file_bt = gtk_button_new_with_label("File:");
  gtk_table_attach_defaults(GTK_TABLE(table), file_bt, 0, 1, 5, 6);
  gtk_widget_show(file_bt);
  
  file_te = gtk_entry_new();
  gtk_table_attach_defaults(GTK_TABLE(table), file_te, 1, 2, 5, 6);
  gtk_widget_show(file_te);

  gtk_signal_connect(GTK_OBJECT(file_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_prep_file_cb), GTK_OBJECT(file_te));

  /* Misc row: Snap spinbutton */
  caplen_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), caplen_hb);
  gtk_widget_show(caplen_hb);

  snap_lb = gtk_label_new("Capture length");
  gtk_misc_set_alignment(GTK_MISC(snap_lb), 0, 0.5);
  gtk_box_pack_start(GTK_BOX(caplen_hb), snap_lb, FALSE, FALSE, 6);
  gtk_widget_show(snap_lb);

  snap_adj = (GtkAdjustment *) gtk_adjustment_new((float) cfile.snap,
    MIN_PACKET_SIZE, WTAP_MAX_PACKET_SIZE, 1.0, 10.0, 0.0);
  snap_sb = gtk_spin_button_new (snap_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (snap_sb), TRUE);
  gtk_widget_set_usize (snap_sb, 80, 0);
  gtk_box_pack_start (GTK_BOX(caplen_hb), snap_sb, FALSE, FALSE, 3); 
  gtk_widget_show(snap_sb);
  
  promisc_cb = dlg_check_button_new_with_label_with_mnemonic(
		"Capture packets in _promiscuous mode", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(promisc_cb), prefs.capture_prom_mode);
  gtk_container_add(GTK_CONTAINER(main_vb), promisc_cb);
  gtk_widget_show(promisc_cb);

  /* Misc row: Ringbuffer toggle button and Ringbuffer spinbutton */
  ringbuffer_hb = gtk_hbox_new(FALSE, 3);
  gtk_container_add(GTK_CONTAINER(main_vb), ringbuffer_hb);
  gtk_widget_show(ringbuffer_hb);

  ringbuffer_on_tb = dlg_check_button_new_with_label_with_mnemonic(
    "Use _ringbuffer", accel_group);
  if (prefs.capture_real_time == TRUE)
    cfile.ringbuffer_on = FALSE;
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(ringbuffer_on_tb),cfile.ringbuffer_on);
  gtk_signal_connect(GTK_OBJECT(ringbuffer_on_tb), "toggled",
    GTK_SIGNAL_FUNC(capture_prep_ringbuffer_toggle_cb), GTK_OBJECT(cap_open_w));
  gtk_box_pack_start(GTK_BOX(ringbuffer_hb), ringbuffer_on_tb, FALSE, FALSE, 0);
  gtk_widget_show(ringbuffer_on_tb);
  
  ringbuffer_nbf_lb = gtk_label_new("Number of files");
  gtk_misc_set_alignment(GTK_MISC(ringbuffer_nbf_lb), 1, 0.5);
  gtk_box_pack_start(GTK_BOX(ringbuffer_hb), ringbuffer_nbf_lb, FALSE, FALSE, 6);
  gtk_widget_show(ringbuffer_nbf_lb);

  ringbuffer_nbf_adj = (GtkAdjustment *) gtk_adjustment_new((float) cfile.ringbuffer_num_files,
    RINGBUFFER_MIN_NUM_FILES, RINGBUFFER_MAX_NUM_FILES, 1.0, 10.0, 0.0);
  ringbuffer_nbf_sb = gtk_spin_button_new (ringbuffer_nbf_adj, 0, 0);
  gtk_spin_button_set_wrap (GTK_SPIN_BUTTON (ringbuffer_nbf_sb), TRUE);
  gtk_widget_set_usize (ringbuffer_nbf_sb, 40, 0);
  gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb), cfile.ringbuffer_on);
  gtk_box_pack_start (GTK_BOX(ringbuffer_hb), ringbuffer_nbf_sb, TRUE, TRUE, 0); 
  gtk_widget_show(ringbuffer_nbf_sb);
  
  /* Misc row: Capture file checkboxes */
  sync_cb = dlg_check_button_new_with_label_with_mnemonic(
		"_Update list of packets in real time", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(sync_cb), prefs.capture_real_time);
  gtk_signal_connect(GTK_OBJECT(sync_cb), "toggled",
    GTK_SIGNAL_FUNC(capture_prep_sync_toggle_cb), GTK_OBJECT(cap_open_w));
  gtk_container_add(GTK_CONTAINER(main_vb), sync_cb);
  gtk_widget_show(sync_cb);

  auto_scroll_cb = dlg_check_button_new_with_label_with_mnemonic(
		"_Automatic scrolling in live capture", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(auto_scroll_cb), prefs.capture_auto_scroll);
  gtk_container_add(GTK_CONTAINER(main_vb), auto_scroll_cb);
  gtk_widget_show(auto_scroll_cb);

  m_resolv_cb = dlg_check_button_new_with_label_with_mnemonic(
		"Enable _MAC name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(m_resolv_cb),
		prefs.name_resolve & PREFS_RESOLV_MAC);
  gtk_container_add(GTK_CONTAINER(main_vb), m_resolv_cb);
  gtk_widget_show(m_resolv_cb);

  n_resolv_cb = dlg_check_button_new_with_label_with_mnemonic(
		"Enable _network name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(n_resolv_cb),
		prefs.name_resolve & PREFS_RESOLV_NETWORK);
  gtk_container_add(GTK_CONTAINER(main_vb), n_resolv_cb);
  gtk_widget_show(n_resolv_cb);

  t_resolv_cb = dlg_check_button_new_with_label_with_mnemonic(
		"Enable _transport name resolution", accel_group);
  gtk_toggle_button_set_state(GTK_TOGGLE_BUTTON(t_resolv_cb),
		prefs.name_resolve & PREFS_RESOLV_TRANSPORT);
  gtk_container_add(GTK_CONTAINER(main_vb), t_resolv_cb);
  gtk_widget_show(t_resolv_cb);
  
  /* Button row: OK and cancel buttons */
  bbox = gtk_hbutton_box_new();
  gtk_button_box_set_layout (GTK_BUTTON_BOX (bbox), GTK_BUTTONBOX_END);
  gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
  gtk_container_add(GTK_CONTAINER(main_vb), bbox);
  gtk_widget_show(bbox);

  ok_bt = gtk_button_new_with_label ("OK");
  gtk_signal_connect(GTK_OBJECT(ok_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_prep_ok_cb), GTK_OBJECT(cap_open_w));
  GTK_WIDGET_SET_FLAGS(ok_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), ok_bt, TRUE, TRUE, 0);
  gtk_widget_grab_default(ok_bt);
  gtk_widget_show(ok_bt);

  cancel_bt = gtk_button_new_with_label ("Cancel");
  gtk_signal_connect(GTK_OBJECT(cancel_bt), "clicked",
    GTK_SIGNAL_FUNC(capture_prep_close_cb), GTK_OBJECT(cap_open_w));
  GTK_WIDGET_SET_FLAGS(cancel_bt, GTK_CAN_DEFAULT);
  gtk_box_pack_start (GTK_BOX (bbox), cancel_bt, TRUE, TRUE, 0);
  gtk_widget_show(cancel_bt);

  /* Attach pointers to needed widgets to the capture prefs window/object */
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_IFACE_KEY, if_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_FILT_KEY,  filter_te);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_FILE_TE_KEY,  file_te);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_COUNT_KEY, count_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_SNAP_KEY,  snap_sb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_PROMISC_KEY, promisc_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_SYNC_KEY,  sync_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_AUTO_SCROLL_KEY, auto_scroll_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_M_RESOLVE_KEY,  m_resolv_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_N_RESOLVE_KEY,  n_resolv_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_T_RESOLVE_KEY,  t_resolv_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_FILESIZE_KEY,  filesize_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_DURATION_KEY,  duration_cb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_RING_TB_KEY,  ringbuffer_on_tb);
  gtk_object_set_data(GTK_OBJECT(cap_open_w), E_CAP_RING_SB_KEY,  ringbuffer_nbf_sb);

  /* Catch the "activate" signal on the frame number and file name text
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
capture_prep_file_cb(GtkWidget *w, gpointer file_te)
{
  GtkWidget *caller = gtk_widget_get_toplevel(w);
  GtkWidget *fs;

  /* Has a file selection dialog box already been opened for that top-level
     widget? */
  fs = gtk_object_get_data(GTK_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Just re-activate that dialog box. */
    reactivate_window(fs);
    return;
  }

  fs = gtk_file_selection_new ("Ethereal: Capture File");

  gtk_object_set_data(GTK_OBJECT(fs), E_CAP_FILE_TE_KEY, file_te);

  /* Set the E_FS_CALLER_PTR_KEY for the new dialog to point to our caller. */
  gtk_object_set_data(GTK_OBJECT(fs), E_FS_CALLER_PTR_KEY, caller);

  /* Set the E_FILE_SEL_DIALOG_PTR_KEY for the caller to point to us */
  gtk_object_set_data(GTK_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY, fs);

  /* Call a handler when the file selection box is destroyed, so we can inform
     our caller, if any, that it's been destroyed. */
  gtk_signal_connect(GTK_OBJECT(fs), "destroy",
	    GTK_SIGNAL_FUNC(cap_prep_fs_destroy_cb), NULL);

  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->ok_button),
    "clicked", (GtkSignalFunc) cap_prep_fs_ok_cb, fs);

  /* Connect the cancel_button to destroy the widget */
  gtk_signal_connect (GTK_OBJECT (GTK_FILE_SELECTION(fs)->cancel_button),
    "clicked", (GtkSignalFunc) cap_prep_fs_cancel_cb, fs);

  /* Catch the "key_press_event" signal in the window, so that we can catch
     the ESC key being pressed and act as if the "Cancel" button had
     been selected. */
  dlg_set_cancel(fs, GTK_FILE_SELECTION(fs)->cancel_button);
  
  gtk_widget_show(fs);
}

static void
cap_prep_fs_ok_cb(GtkWidget *w, gpointer data)
{
  gtk_entry_set_text(GTK_ENTRY(gtk_object_get_data(GTK_OBJECT(data),
      E_CAP_FILE_TE_KEY)),
      gtk_file_selection_get_filename (GTK_FILE_SELECTION(data)));
  gtk_widget_destroy(GTK_WIDGET(data));
}

static void
cap_prep_fs_cancel_cb(GtkWidget *w, gpointer data)
{
  gtk_widget_destroy(GTK_WIDGET(data));
}  

static void
cap_prep_fs_destroy_cb(GtkWidget *win, gpointer data)
{
  GtkWidget *caller;

  /* Get the widget that requested that we be popped up.
     (It should arrange to destroy us if it's destroyed, so
     that we don't get a pointer to a non-existent window here.) */
  caller = gtk_object_get_data(GTK_OBJECT(win), E_FS_CALLER_PTR_KEY);

  /* Tell it we no longer exist. */
  gtk_object_set_data(GTK_OBJECT(caller), E_FILE_SEL_DIALOG_PTR_KEY, NULL);

  /* Now nuke this window. */
  gtk_grab_remove(GTK_WIDGET(win));
  gtk_widget_destroy(GTK_WIDGET(win));
}

static int
get_positive_int(const char *string, const char *name)
{
  long number;
  char *p;

  number = strtol(string, &p, 10);
  /*
   * XXX - we allow extra stuff after 0, so that we don't have
   * problems with the "(Infinite)" value.
   */
  if (p == string || (*p != '\0' && number != 0)) {
    simple_dialog(ESD_TYPE_CRIT, NULL,
        "The specified %s is not a decimal number.", name);
    return -1;
  }
  if (number < 0) {
    simple_dialog(ESD_TYPE_CRIT, NULL,
        "The specified %s is a negative number.", name);
    return -1;
  }
  if (number > INT_MAX) {
    simple_dialog(ESD_TYPE_CRIT, NULL,
        "The specified %s is too large (greater than %d).", name, INT_MAX);
    return -1;
  }
  return number;
}

static void
capture_prep_ok_cb(GtkWidget *ok_bt, gpointer parent_w) {
  GtkWidget *if_cb, *filter_te, *file_te, *count_cb, *snap_sb, *promisc_cb,
            *sync_cb, *auto_scroll_cb, *m_resolv_cb, *n_resolv_cb, *t_resolv_cb,
            *filesize_cb, *duration_cb, *ringbuffer_on_tb, *ringbuffer_nbf_sb;
  gchar *if_text;
  gchar *if_name;
  gchar *filter_text;
  gchar *save_file;
  int value;

  if_cb     = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_IFACE_KEY);
  filter_te = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_FILT_KEY);
  file_te   = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_FILE_TE_KEY);
  count_cb  = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_COUNT_KEY);
  snap_sb   = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_SNAP_KEY);
  promisc_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_PROMISC_KEY);
  sync_cb   = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_SYNC_KEY);
  auto_scroll_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_AUTO_SCROLL_KEY);
  m_resolv_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_M_RESOLVE_KEY);
  n_resolv_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_N_RESOLVE_KEY);
  t_resolv_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_T_RESOLVE_KEY);
  filesize_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_FILESIZE_KEY);
  duration_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_DURATION_KEY);
  ringbuffer_on_tb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_RING_TB_KEY);
  ringbuffer_nbf_sb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_RING_SB_KEY);

  if_text =
    g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(if_cb)->entry)));
  if_name = strtok(if_text, " \t");
  if (if_name == NULL) {
    simple_dialog(ESD_TYPE_CRIT, NULL,
      "You didn't specify an interface on which to capture packets.");
    g_free(if_text);
    return;
  }
  if (cfile.iface)
    g_free(cfile.iface);
  cfile.iface = g_strdup(if_name);
  g_free(if_text);

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

  save_file = gtk_entry_get_text(GTK_ENTRY(file_te));
  if (save_file && save_file[0]) {
    /* User specified a file to which the capture should be written. */
    save_file = g_strdup(save_file);
  } else {
    /* User didn't specify a file; save to a temporary file. */
    save_file = NULL;
  }

  cfile.count = atoi(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(count_cb)->entry)));

  value = get_positive_int(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(filesize_cb)->entry)),
      "maximum capture file size");
  if (value == -1)
    return;	/* error */
  cfile.autostop_filesize = value;

  value = get_positive_int(gtk_entry_get_text(GTK_ENTRY(GTK_COMBO(duration_cb)->entry)),
      "capture duration");
  if (value == -1)
    return;	/* error */
  cfile.autostop_duration = value;

  cfile.snap = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(snap_sb));
  if (cfile.snap < 1)
    cfile.snap = WTAP_MAX_PACKET_SIZE;
  else if (cfile.snap < MIN_PACKET_SIZE)
    cfile.snap = MIN_PACKET_SIZE;

  prefs.capture_prom_mode = GTK_TOGGLE_BUTTON (promisc_cb)->active;

  prefs.capture_real_time = GTK_TOGGLE_BUTTON (sync_cb)->active;

  prefs.capture_auto_scroll = GTK_TOGGLE_BUTTON (auto_scroll_cb)->active;

  prefs.name_resolve = PREFS_RESOLV_NONE;
  prefs.name_resolve |= (GTK_TOGGLE_BUTTON (m_resolv_cb)->active ? PREFS_RESOLV_MAC : PREFS_RESOLV_NONE);
  prefs.name_resolve |= (GTK_TOGGLE_BUTTON (n_resolv_cb)->active ? PREFS_RESOLV_NETWORK : PREFS_RESOLV_NONE);
  prefs.name_resolve |= (GTK_TOGGLE_BUTTON (t_resolv_cb)->active ? PREFS_RESOLV_TRANSPORT : PREFS_RESOLV_NONE);

  cfile.ringbuffer_on = GTK_TOGGLE_BUTTON (ringbuffer_on_tb)->active && !(prefs.capture_real_time);
  if (cfile.ringbuffer_on == TRUE) {
    if (save_file == NULL) {
      simple_dialog(ESD_TYPE_CRIT, NULL,
        "You must specify a save file if you want to use the ringbuffer.");
      return;
    } else if (cfile.autostop_filesize == 0) {
      simple_dialog(ESD_TYPE_CRIT, NULL,
        "You must specify a maximum save file size other \nthan 0 (infinite) if you want to use the ringbuffer.");
      return;
    }
  }

  cfile.ringbuffer_num_files = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(ringbuffer_nbf_sb));
  if (cfile.ringbuffer_num_files < RINGBUFFER_MIN_NUM_FILES)
    cfile.ringbuffer_num_files = RINGBUFFER_MIN_NUM_FILES;
  else if (cfile.ringbuffer_num_files > RINGBUFFER_MAX_NUM_FILES)
    cfile.ringbuffer_num_files = RINGBUFFER_MAX_NUM_FILES;

  gtk_widget_destroy(GTK_WIDGET(parent_w));

  do_capture(save_file);
}

static void
capture_prep_close_cb(GtkWidget *close_bt, gpointer parent_w)
{
  gtk_grab_remove(GTK_WIDGET(parent_w));
  gtk_widget_destroy(GTK_WIDGET(parent_w));
}

static void
capture_prep_destroy_cb(GtkWidget *win, gpointer user_data)
{
  GtkWidget *capture_prep_filter_w;
  GtkWidget *fs;

  /* Is there a filter edit/selection dialog associated with this
     Capture Preferences dialog? */
  capture_prep_filter_w = gtk_object_get_data(GTK_OBJECT(win), E_FILT_DIALOG_PTR_KEY);

  if (capture_prep_filter_w != NULL) {
    /* Yes.  Destroy it. */
    gtk_widget_destroy(capture_prep_filter_w);
  }

  /* Is there a file selection dialog associated with this
     Print File dialog? */
  fs = gtk_object_get_data(GTK_OBJECT(win), E_FILE_SEL_DIALOG_PTR_KEY);

  if (fs != NULL) {
    /* Yes.  Destroy it. */
    gtk_widget_destroy(fs);
  }

  /* Note that we no longer have a "Capture Preferences" dialog box. */
  cap_open_w = NULL;
}

static void
capture_prep_ringbuffer_toggle_cb(GtkWidget *ringbuffer_tb, gpointer parent_w)
{
  GtkWidget *ringbuffer_nbf_sb, *sync_cb;

  ringbuffer_nbf_sb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_RING_SB_KEY);
  sync_cb = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_SYNC_KEY);

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_tb)) == TRUE) {
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb), TRUE);
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb)) == TRUE) {
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(sync_cb), FALSE);
    }
  } else {
    gtk_widget_set_sensitive(GTK_WIDGET(ringbuffer_nbf_sb), FALSE);
  }
}

static void
capture_prep_sync_toggle_cb(GtkWidget *sync_cb, gpointer parent_w)
{
  GtkWidget *ringbuffer_on_tb;

  ringbuffer_on_tb  = (GtkWidget *) gtk_object_get_data(GTK_OBJECT(parent_w), E_CAP_RING_TB_KEY);

  if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(sync_cb)) == TRUE) {
    if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ringbuffer_on_tb)) == TRUE) {
      gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(ringbuffer_on_tb), FALSE);
    }
  }
}

#endif /* HAVE_LIBPCAP */
