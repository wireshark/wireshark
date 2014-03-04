/* capture_dlg.h
 * Definitions for the "Capture Options" dialog and dialog windows popped
 * up from it
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __CAPTURE_DLG_H__
#define __CAPTURE_DLG_H__

/* extern GtkWidget* wireless_tb; */

/** @file
 *  "Capture Options" dialog box.
 *  @ingroup dialog_group
 */
#include "capture_opts.h"
#include <gtk/gtk.h>

#define CR_MAIN_NB "compile_results_main_notebook"

/** Initialize background capture filter syntax checking
 */
void capture_filter_init(void);

/** User requested the "Capture Options" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void capture_prep_cb(GtkWidget *widget, gpointer data);

/** User requested capture start by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void capture_start_cb(GtkWidget *widget, gpointer data);

/** User requested capture stop by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void capture_stop_cb(GtkWidget *widget, gpointer data);

/** User requested capture restart by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void capture_restart_cb(GtkWidget *widget, gpointer data);

/** User requested the "Capture Airpcap" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void
capture_air_cb(GtkWidget *widget, gpointer data);

#ifdef HAVE_PCAP_REMOTE
struct remote_host {
  gchar    *remote_host;          /**< Host name or network address for remote capturing */
  gchar    *remote_port;          /**< TCP port of remote RPCAP server */
  gint      auth_type;            /**< Authentication type */
  gchar    *auth_username;        /**< Remote authentication parameters */
  gchar    *auth_password;        /**< Remote authentication parameters */
};
#endif

gboolean
capture_dlg_window_present(void);

void
enable_selected_interface(gchar *name, gboolean selected);

void
options_interface_cb(GtkTreeView *view, GtkTreePath *path, GtkTreeViewColumn *column _U_, gpointer userdata);

void
capture_dlg_refresh_if(void);

void
update_visible_columns_menu (void);

void
update_visible_tree_view_columns(void);

/*
 * Refresh everything visible that shows an interface list that
 * includes local interfaces.
 */
extern void refresh_local_interface_lists(void);

/*
 * Refresh everything visible that shows an interface list that
 * includes non-local interfaces.
 */
extern void refresh_non_local_interface_lists(void);

#endif /* capture_dlg.h */
