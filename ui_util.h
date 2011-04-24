/* ui_util.h
 * Declarations of UI utility routines; these routines have GUI-independent
 * APIs, but GUI-dependent implementations, so that they can be called by
 * GUI-independent code to affect the GUI.
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __UI_UTIL_H__
#define __UI_UTIL_H__

#include "epan/packet_info.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* gui_utils.c */

/* Set the name of the top-level window and its icon. */
void set_main_window_name(const gchar *);
/* Update the name of the main window if the user-specified decoration
   changed. */
void update_main_window_title(void);
/* update the main window */
extern void main_window_update(void);
/* exit the main window */
extern void main_window_exit(void);
/* quit a nested main window */
extern void main_window_nested_quit(void);
/* quit the main window */
extern void main_window_quit(void);

/* read from a pipe (callback) */
typedef gboolean (*pipe_input_cb_t) (gint source, gpointer user_data);
/* install callback function, called if pipe input is available */
extern void pipe_input_set_handler(gint source, gpointer user_data, int *child_process, pipe_input_cb_t input_cb);

/* packet_list.c */

void new_packet_list_clear(void);
void new_packet_list_freeze(void);
void new_packet_list_recreate_visible_rows(void);
void new_packet_list_thaw(void);
void new_packet_list_next(void);
void new_packet_list_prev(void);
guint new_packet_list_append(column_info *cinfo, frame_data *fdata, packet_info *pinfo);
frame_data * new_packet_list_get_row_data(gint row);
void new_packet_list_set_selected_row(gint row);
void new_packet_list_enable_color(gboolean enable);
void new_packet_list_queue_draw(void);
void new_packet_list_select_first_row(void);
void new_packet_list_select_last_row(void);
void new_packet_list_moveto_end(void);
gboolean new_packet_list_check_end(void);
gboolean new_packet_list_select_row_from_data(frame_data *fdata_needle);
void new_packet_list_resize_column(gint col);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_UTIL_H__ */
