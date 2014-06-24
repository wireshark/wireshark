/* capture_if_dlg.h
 * Definitions for packet capture interface windows
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

#ifndef __CAPTURE_IF_DLG_H__
#define __CAPTURE_IF_DLG_H__

/** A live capture has started or stopped.
 *
 * @param capture_in_progress capture is in progress
 */
void
set_capture_if_dialog_for_capture_in_progress(gboolean capture_in_progress);

/** A live capture is being stopped.
 */
void set_capture_if_dialog_for_capture_stopping(void);

/** User requested the "Capture Interfaces" dialog box by menu or toolbar.
 *
 * @param widget parent widget (unused)
 * @param data unused
 */
void
capture_if_cb(GtkWidget *widget, gpointer data);

#ifdef HAVE_LIBPCAP

#include <capchild/capture_ifinfo.h>	/* for if_info_t */

/*
 * Used to retrieve the interface icon
 */
GtkWidget *
capture_get_if_icon(interface_t *device);

void
update_selected_interface(gchar *name);

gboolean
interfaces_dialog_window_present(void);

void
add_interface(void);

void
refresh_if_window(void);

void
select_all_interfaces(gboolean enable);

void
destroy_if_window(void);

#endif /* HAVE_LIBPCAP */

#endif /* capture_if_dlg.h */


