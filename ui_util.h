/* ui_util.h
 * Definitions for UI utility routines
 *
 * $Id: ui_util.h,v 1.15 2004/01/10 17:29:26 ulfl Exp $
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

#ifndef __UI_UTIL_H__
#define __UI_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Set the name of the top-level window and its icon. */
void set_main_window_name(gchar *);

/* packet list related functions */
void packet_list_clear(void);
void packet_list_freeze(void);
void packet_list_thaw(void);
void packet_list_select_row(gint);
void packet_list_moveto_end(void);
gint packet_list_append(gchar *text[], gpointer data);
void packet_list_set_colors(gint, color_t *, color_t *);
gint packet_list_find_row_from_data(gpointer);
void packet_list_set_text(gint, gint, const gchar *);
void packet_list_set_cls_time_width(gint);
gpointer packet_list_get_row_data(gint);
void packet_list_set_selected_row(gint);
gint packet_list_get_sort_column(void);

/* create byte views in the main window */
void add_main_byte_views(epan_dissect_t *edt);
/* display the protocol tree in the main window */
void main_proto_tree_draw(proto_tree *protocol_tree);

void clear_tree_and_hex_views(void);

/* Destroy all popup packet windows. */
void destroy_packet_wins(void);

/* Destroy the save as dialog */
void file_save_as_destroy(void);

#define destroy_cfile_wins() \
    destroy_packet_wins(); \
    file_save_as_destroy();

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_UTIL_H__ */
