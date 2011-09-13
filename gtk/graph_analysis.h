/* graph_analysis.h
 * Graphic Analysis addition for Wireshark
 *
 * $Id$
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
 * Foundation,  Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __GRAPH_ANALYSIS_H__
#define __GRAPH_ANALYSIS_H__

#include <glib.h>
#include <gtk/gtk.h>
#include <epan/address.h>

#define MAX_NUM_NODES 40

/* defines an entry in for the graph analysis */
typedef struct _graph_analysis_item {
	frame_data *fd;				/* Holds the frame number and time information */
	address src_addr;
	guint16 port_src;
	address dst_addr;
	guint16 port_dst;
	gchar *frame_label;			/* the label on top of the arrow */
	gchar *comment;				/* a comment that appears at the left of the graph */
	guint16 conv_num;			/* the conversation number, each conversation will be colored */
	gboolean display;			/* indicate if the packet is displayed or not in the graph */
	guint16 src_node;			/* this is used by graph_analysis.c to identify the node */
	guint16 dst_node;			/* a node is an IP address that will be displayed in columns */
	guint16 line_style;			/* the arrow line width in pixels*/
} graph_analysis_item_t;

/* defines the graph analysis structure */
typedef struct _graph_analysis_info {
	int     nconv;       /* number of conversations in the list */
	GList*  list;   /* list with the graph analysis items */
} graph_analysis_info_t;

/* max number of nodes to display, each node will be an IP address */
#define MAX_NUM_COL_CONV 10
#define NODE_OVERFLOW MAX_NUM_NODES+1
#define NUM_DISPLAY_ITEMS 1000

typedef struct _display_items {
	guint32 frame_num;			/* frame number used to "go to" that frame */
	double time;				/* frame time */
	guint16 port_src;
	guint16 port_dst;
	gchar *frame_label;			/* the label on top of the arrow */
	gchar *comment;				/* a comment that appears at the left of the graph */
	guint16 conv_num;			/* the conversation number, each conversation will be colored */
	guint16 src_node;			/* this is used by graph_analysis.c to identify the node */
	guint16 dst_node;			/* a node is an IP address that will be displayed in columns */
	guint16 line_style;			/* the arrow line width in pixels*/
} display_items_t;

typedef struct _graph_analysis_dialog_data_t {
	GtkWidget *window;
	GtkWidget *parent_w;
	gboolean needs_redraw;
	gboolean inverse;          /* set the nodes in reverse mode as "dst <---- src" instead of "src ----> dst"*/
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
	GtkWidget *v_scrollbar;
	GtkAdjustment *v_scrollbar_adjustment;
	GtkWidget *hpane;
	int surface_width;
	int surface_height;
	guint16 first_node;			/* the first node on the left to show in the screen */
	guint32	first_item;			/* the first item (row) to show from the top */
	guint32	selected_item;		/* the selected item */
	display_items_t items[NUM_DISPLAY_ITEMS];
	guint32 left_x_border;
	char *save_file;
	char *title; 				/* Graph analysis window's title */
} graph_analysis_dialog_data_t;

typedef void (*destroy_user_data_cb)(void *data);

/* structure that holds general information and the dialog */
typedef struct _graph_analysis_data_t {
	/* graphic data */
	graph_analysis_info_t *graph_info;

	/* dialog associated data */
	graph_analysis_dialog_data_t dlg;
	address nodes[MAX_NUM_NODES];
	guint32 num_nodes;
	guint32 num_items;
	destroy_user_data_cb on_destroy_user_data;  /* callback info for destroy */
	void *data; /* data to be passes when on destroy */
} graph_analysis_data_t;

graph_analysis_data_t* graph_analysis_init(void);
void graph_analysis_create(graph_analysis_data_t* user_data);
void graph_analysis_update(graph_analysis_data_t* user_data);
void graph_analysis_redraw(graph_analysis_data_t* user_data);


#endif /* __GRAPH_ANALYSIS_H__ */
