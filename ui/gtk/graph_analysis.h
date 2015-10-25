/* graph_analysis.h
 * Graphic Analysis addition for Wireshark
 *
 * Copyright 2004, Verso Technologies Inc.
 * By Alejandro Vaquero <alejandrovaquero@yahoo.com>
 *
 * based on rtp_analysis.c and io_stat
 *
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
 * Foundation,  Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __GRAPH_ANALYSIS_H__
#define __GRAPH_ANALYSIS_H__

#include <glib.h>
#include <gtk/gtk.h>
#include <epan/address.h>
#include <ui/tap-sequence-analysis.h>

/** max number of nodes to display, each node will be an IP address */
#define MAX_NUM_COL_CONV 10
#define NUM_DISPLAY_ITEMS 1000

typedef struct _display_items {
	guint32 frame_number;		/**< frame number */
	guint16 port_src;
	guint16 port_dst;
	gchar *frame_label;			/**< the label on top of the arrow */
	gchar *time_str;   			/**< timestamp */
	gchar *comment;				/**< a comment that appears at the right of the graph */
	guint16 conv_num;			/**< the conversation number, each conversation will be colored */
	guint16 src_node;			/**< this is used by graph_analysis.c to identify the node */
	guint16 dst_node;			/**< a node is an IP address that will be displayed in columns */
	guint16 line_style;			/**< the arrow line width in pixels*/
} display_items_t;

typedef struct _graph_analysis_dialog_data_t {
	GtkWidget *window;
	GtkWidget *parent_w;
	gboolean needs_redraw;
	gboolean inverse;          /**< set the nodes in reverse mode as "dst <---- src" instead of "src ----> dst"*/
	gint selected_row;
	GtkWidget *draw_area_time;
	GtkWidget *draw_area;
	GtkWidget *draw_area_comments;
#if GTK_CHECK_VERSION(2,22,0)
	cairo_surface_t *surface_time;
	cairo_surface_t *surface_main;
	cairo_surface_t *surface_comments;
	cairo_surface_t *surface_tile_select;
#else
	GdkPixmap *pixmap_time;
	GdkPixmap *pixmap_main;
	GdkPixmap *pixmap_comments;
	GdkPixmap *pixmap_tile_select;
#endif
	GtkWidget *scroll_window;
	GtkWidget *scroll_window_time;			/**< to enable mouse scroll from this area */
	GtkWidget *scroll_window_comments;		/**< to enable mouse scroll from this area */
	GtkWidget *v_scrollbar;
	GtkAdjustment *v_scrollbar_adjustment;
	GtkWidget *hpane;
	int surface_width;
	int surface_height;
	guint16 first_node;			/**< the first node on the left to show in the screen */
	guint32	first_item;			/**< the first item (row) to show from the top */
	guint32 last_item;			/**< the last item displayed (for correct mouse scroll handling) */
	guint32	selected_item;		/**< the selected item */
	display_items_t items[NUM_DISPLAY_ITEMS];
	guint32 left_x_border;
	char *title; 				/**< Graph analysis window's title */
} graph_analysis_dialog_data_t;

typedef void (*destroy_user_data_cb)(void *data);

/** structure that holds general information and the dialog */
typedef struct _graph_analysis_data_t {
	/**> graphic data */
	seq_analysis_info_t *graph_info;

	/**> dialog associated data */
	graph_analysis_dialog_data_t dlg;
	guint32 num_items;
	destroy_user_data_cb on_destroy_user_data;  /**< callback info for destroy */
	void *data;									/**< data to be passed when on destroy */
} graph_analysis_data_t;

graph_analysis_data_t* graph_analysis_init(seq_analysis_info_t *sainfo);
void graph_analysis_create(graph_analysis_data_t* user_data);
void graph_analysis_update(graph_analysis_data_t* user_data);
void graph_analysis_redraw(graph_analysis_data_t* user_data);


#endif /* __GRAPH_ANALYSIS_H__ */
