/* proto_draw.h
 * Definitions for GTK+ packet display structures and routines
 *
 * $Id: proto_draw.h,v 1.17 2002/03/31 23:11:04 guy Exp $
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

#ifndef __GTKPACKET_H__
#define __GTKPACKET_H__

/* Get the current text window for the notebook. */
extern GtkWidget *get_notebook_bv_ptr(GtkWidget *nb_ptr);

/*
 * Get the data and length for a byte view, given the byte view page.
 * Return the pointer, or NULL on error, and set "*data_len" to the length.
 */
extern const guint8 *get_byte_view_data_and_length(GtkWidget *byte_view,
						   guint *data_len);

/*
 * Set the current text window for the notebook to the window that
 * refers to a particular tvbuff.
 */
extern void set_notebook_page(GtkWidget *nb_ptr, tvbuff_t *tvb);

/* Redraw a given byte view window. */
extern void redraw_hex_dump(GtkWidget *nb, frame_data *fd, field_info *finfo);

/* Redraw all byte view windows. */
extern void redraw_hex_dump_all(void);

extern GtkWidget *create_byte_view(gint bv_size, GtkWidget *pane);

extern void add_byte_views(frame_data *frame, proto_tree *tree,
    GtkWidget *tree_view, GtkWidget *byte_nb_ptr);

void packet_hex_print(GtkText *, const guint8 *, frame_data *, field_info *,
		      guint);
void packet_hex_reprint(GtkText *);

void create_tree_view(gint tv_size, e_prefs *prefs, GtkWidget *pane,
		GtkWidget **tv_scrollw_p, GtkWidget **tree_view_p);
void proto_tree_draw(proto_tree *protocol_tree, GtkWidget *tree_view);
void expand_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view);
void collapse_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view);

void set_ptree_sel_browse_all(gboolean);
void set_ptree_font_all(GdkFont *font);

void clear_tree_and_hex_views(void);

#endif
