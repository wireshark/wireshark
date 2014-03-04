/* main_toolbar_private.h
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

#ifndef __MAIN_TOLBAR_PRIVATE_H__
#define __MAIN_TOLBAR_PRIVATE_H__

/*** PRIVATE INTERFACE BETWEEN main.c AND main_toolbar.c DON'T USE OR TOUCH :-)*/

/** Create the main toolbar.
 * @return the new toolbar
 */
GtkWidget *toolbar_new(void);

/** We have (or don't have) a capture in progress now.
 *
 * @param have_capture_file TRUE, if we have a capture in progress file
 */
void set_toolbar_for_capture_in_progress(gboolean have_capture_file);

/** The capture is in the process of being stopped.
 */
void set_toolbar_for_capture_stopping(void);

/** We have (or don't have) captured packets now.
 *
 * @param have_captured_packets TRUE, if we have captured packets
 */
void set_toolbar_for_captured_packets(gboolean have_captured_packets);

/** The packet history has changed, we need to update the menu.
 *
 * @param back_history some back history entries available
 * @param forward_history some forward history entries available
 */
void set_toolbar_for_packet_history(gboolean back_history, gboolean forward_history);

/** The "Colorize Packet List" option has changed.
 */
void toolbar_colorize_changed(gboolean packet_list_colorize);

#ifdef HAVE_LIBPCAP
/** The "Auto Scroll in Live Capture" option has changed.
 */
void toolbar_auto_scroll_live_changed(gboolean auto_scroll_live);
#endif

/* Enable or disable toolbar items based on whether you have a capture file
 * and, if so, whether you've finished reading it and whether there's stuff
 * in it that hasn't yet been saved to a permanent file.
 * @param cf cfile_t for the capture file in question
 */
void set_toolbar_for_capture_file(capture_file *cf);

#endif /* __MAIN_TOOLBAR_PRIVATE_H__ */
