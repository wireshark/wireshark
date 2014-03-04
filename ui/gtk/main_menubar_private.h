/* main_menubar_private.h
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

#ifndef __MAIN_MENUBAR_PRIVATE_H__
#define __MAIN_MENUBAR_PRIVATE_H__

/*** PRIVATE INTERFACE BETWEEN main.c AND main_menubar.c DON'T USE OR TOUCH :-)*/

/** The recent file read has finished, update the menu corresponding. */
extern void menu_recent_read_finished(void);

/* Enable or disable menu items based on whether you have a capture file
   you've finished reading and, if you have one, whether it's been saved
   and whether it could be saved except by copying the raw packet data. */
void set_menus_for_capture_file(capture_file *);

/** The packet history has changed, we need to update the menu.
 *
 * @param back_history some back history entries available
 * @param forward_history some forward history entries available
 */
extern void set_menus_for_packet_history(gboolean back_history, gboolean forward_history);

/* Enable or disable menu items based on whether there's a capture in
   progress. */
void set_menus_for_capture_in_progress(gboolean);

/* Disable menu items while we're waiting for the capture child to
   finish.  We disallow quitting until it finishes, and also disallow
   stopping or restarting the capture. */
void set_menus_for_capture_stopping(void);

/* Enable or disable menu items based on whether you have some captured
   packets. */
void set_menus_for_captured_packets(gboolean);

#ifdef HAVE_LIBPCAP
/** The "Auto Scroll Packet List in Live Capture" option changed. */
extern void menu_auto_scroll_live_changed(gboolean auto_scroll_in);
#endif

/** The "Colorize Packet List" option changed. */
extern void menu_colorize_changed(gboolean packet_list_colorize);

#endif /* __MAIN_MENUBAR_PRIVATE_H__ */
