/* proto_draw.h
 * Definitions for GTK+ packet display structures and routines
 *
 * $Id: proto_draw.h,v 1.13 2001/11/20 10:10:45 guy Exp $
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
#define E_BYTE_VIEW_TREE_PTR      "byte_view_tree_ptr"
#define E_BYTE_VIEW_TREE_VIEW_PTR "byte_view_tree_view_ptr"
#define E_BYTE_VIEW_TEXT_INFO_KEY "byte_view_win"
#define E_BYTE_VIEW_DATA_PTR_KEY  "byte_view_data"
#define E_BYTE_VIEW_DATA_LEN_KEY  "byte_view_len"
#define E_BYTE_VIEW_START_KEY     "byte_view_start"
#define E_BYTE_VIEW_END_KEY       "byte_view_end"
#define E_BYTE_VIEW_ENCODE_KEY    "byte_view_encode"
#define E_BYTE_VIEW_NAME_KEY  	  "byte_view_name"

GtkWidget *add_byte_tab(GtkWidget *byte_nb, const char *name,
    const guint8 *data, int len, proto_tree *tree, GtkWidget *tree_view);
int add_byte_view( const char *name, const guint8 *data, int len);

void set_notebook_page( GtkWidget *nb_ptr, int num);
int find_notebook_page( GtkWidget *nb_ptr, gchar *label);


GtkWidget *get_byte_view( GtkWidget *byte_view_notebook);
int get_byte_view_data( GtkWidget *byte_view_notebook, guint8 **data_ptr);
int get_byte_view_and_data( GtkWidget *byte_view_notebook, GtkWidget **byte_view, guint8 **data_ptr);

void redraw_hex_dump(GtkWidget *nb, frame_data *fd, field_info *finfo);

void redraw_hex_dump_all(void);
void create_byte_view(gint bv_size, GtkWidget *pane, GtkWidget **byte_view_p,
		GtkWidget **bv_scrollw_p, int pos);
void packet_hex_print(GtkText *, guint8 *, frame_data *, field_info *, int);
void packet_hex_reprint(GtkText *);

void create_tree_view(gint tv_size, e_prefs *prefs, GtkWidget *pane,
		GtkWidget **tv_scrollw_p, GtkWidget **tree_view_p, int pos);
void proto_tree_draw(proto_tree *protocol_tree, GtkWidget *tree_view);
void expand_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view);
void collapse_all_tree(proto_tree *protocol_tree, GtkWidget *tree_view);

void set_ptree_sel_browse_all(gboolean);
void set_ptree_line_style_all(gint style);
void set_ptree_expander_style_all(gint style);
void set_ptree_font_all(GdkFont *font);

void clear_tree_and_hex_views(void);

#endif
