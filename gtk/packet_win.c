/* packet_win.c
 * Routines for popping a window to display current packet
 *
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id: packet_win.c,v 1.16 2000/10/06 10:11:40 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 *
 * To do:
 * - Add close button to bottom.
 * - improve the window Title and allow user to config it
 * - Add print support ? ( could be a mess)
 * - Add button to have main window jump to this packet ?
 *
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <epan.h>
#include "main.h"
#include "timestamp.h"
#include "packet.h"
#include "capture.h"
#include "summary.h"
#include "file.h"
#include "menu.h"
#include "../menu.h"
#include "prefs_dlg.h"
#include "column.h"
#include "print.h"
#include "resolv.h"
#include "util.h"
#include "packet_win.h"
#include "simple_dialog.h"
#include "ui_util.h"
#include "proto_draw.h"
#include "dfilter.h"
#include "keys.h"
#include "gtkglobals.h"
#include "plugins.h"

/* Data structure holding information about a packet-detail window. */
struct PacketWinData {
	frame_data *frame;	   /* The frame being displayed */
	union wtap_pseudo_header pseudo_header; /* Pseudo-header for packet */
	guint8     *pd;		   /* Data for packet */
	proto_tree *protocol_tree; /* Protocol tree for packet */
	GtkWidget  *main;
	GtkWidget  *tv_scrollw;
	GtkWidget  *tree_view;
 	GtkWidget  *bv_scrollw;
 	GtkWidget  *byte_view;
 	field_info *finfo_selected;
	epan_dissect_t	*edt;
};

/* List of all the packet-detail windows popped up. */
static GList *detail_windows;

static void new_tree_view_select_row_cb( GtkCTree *ctree, GList *node,
	gint column, gpointer user_data);

static void new_tree_view_unselect_row_cb( GtkCTree *ctree, GList *node,
	gint column, gpointer user_data);

static void create_new_window( char *Title, gint tv_size, gint bv_size);
static void destroy_new_window(GtkObject *object, gpointer user_data);

void new_window_cb(GtkWidget *w){

	#define NewWinTitleLen 1000
	
        int row;
  	gint	tv_size = 95, bv_size = 75;
	int i;
	char Title[ NewWinTitleLen] = "";
	char *TextPtr;

					/* build title of window by getting */
					/* data from the packet_list GtkCList */
        /* Find what row this packet is in. */
        row = gtk_clist_find_row_from_data(GTK_CLIST(packet_list),
	    cfile.current_frame);
	g_assert(row != -1);
	for( i = 0; i < cfile.cinfo.num_cols; ++i){
					
		if ( gtk_clist_get_text(GTK_CLIST( packet_list), 
				row, i, &TextPtr)){
		
			if (( strlen( Title) + strlen( TextPtr))
					< ( NewWinTitleLen - 1)){

				strcat( Title, TextPtr);
				strcat( Title, " ");
			}
		}		
	}	
	
	create_new_window ( Title, tv_size, bv_size);
}


static void
create_new_window ( char *Title, gint tv_size, gint bv_size){

  GtkWidget *main_w, *main_vbox, *pane,
                      *tree_view, *byte_view, *tv_scrollw,
                      *bv_scrollw;
  struct PacketWinData *DataPtr;
	
  main_w = gtk_window_new(GTK_WINDOW_TOPLEVEL);

  gtk_window_set_title(GTK_WINDOW(main_w), Title);
  gtk_window_set_default_size(GTK_WINDOW(main_w), DEF_WIDTH, -1);

  /* Container for paned windows  */
  main_vbox = gtk_vbox_new(FALSE, 1);
  gtk_container_border_width(GTK_CONTAINER(main_vbox), 1);
  gtk_container_add(GTK_CONTAINER(main_w), main_vbox);
  gtk_widget_show(main_vbox);

  /* Panes for the tree and byte view */
  pane = gtk_vpaned_new();
  gtk_paned_gutter_size(GTK_PANED(pane), (GTK_PANED(pane))->handle_size);
  gtk_container_add(GTK_CONTAINER(main_vbox), pane);
  gtk_widget_show(pane);

  /* Tree view */
  create_tree_view(tv_size, &prefs, pane, &tv_scrollw, &tree_view,
			prefs.gui_scrollbar_on_right);
  gtk_widget_show(tree_view);

  /* Byte view */
  create_byte_view(bv_size, pane, &byte_view, &bv_scrollw,
			prefs.gui_scrollbar_on_right);

  /* Allocate data structure to represent this window. */
  DataPtr = (struct PacketWinData *) g_malloc(sizeof(struct PacketWinData));

  DataPtr->frame = cfile.current_frame;
  memcpy(&DataPtr->pseudo_header, &cfile.pseudo_header, sizeof DataPtr->pseudo_header);
  DataPtr->pd = g_malloc(DataPtr->frame->cap_len);
  memcpy(DataPtr->pd, cfile.pd, DataPtr->frame->cap_len);
  DataPtr->protocol_tree = proto_tree_create_root();
  proto_tree_is_visible = TRUE;
  DataPtr->edt = epan_dissect_new(&DataPtr->pseudo_header, DataPtr->pd, DataPtr->frame,
		DataPtr->protocol_tree);
  proto_tree_is_visible = FALSE;
  DataPtr->main = main_w;
  DataPtr->tv_scrollw = tv_scrollw;
  DataPtr->tree_view = tree_view;
  DataPtr->byte_view = byte_view;
  DataPtr->bv_scrollw = bv_scrollw;
  detail_windows = g_list_append(detail_windows, DataPtr);

  /* load callback handlers */
  gtk_signal_connect(GTK_OBJECT(tree_view), "tree-select-row",
		GTK_SIGNAL_FUNC(new_tree_view_select_row_cb), DataPtr);

  gtk_signal_connect(GTK_OBJECT(tree_view), "tree-unselect-row",
    		GTK_SIGNAL_FUNC(new_tree_view_unselect_row_cb), DataPtr);

  gtk_signal_connect(GTK_OBJECT(main_w), "destroy",
			GTK_SIGNAL_FUNC(destroy_new_window), DataPtr);

  /* draw the protocol tree & print hex data */
  proto_tree_draw(DataPtr->protocol_tree, tree_view);
  packet_hex_print(GTK_TEXT(byte_view), DataPtr->pd, DataPtr->frame, NULL);
		
  DataPtr->finfo_selected = NULL;
  gtk_widget_show(main_w);
}

static void
destroy_new_window(GtkObject *object, gpointer user_data)
{
  struct PacketWinData *DataPtr = user_data;

  detail_windows = g_list_remove(detail_windows, DataPtr);
  proto_tree_free(DataPtr->protocol_tree);
  epan_dissect_free(DataPtr->edt);
  g_free(DataPtr->pd);
  g_free(DataPtr);
}

static void
new_tree_view_select_row_cb(GtkCTree *ctree, GList *node, gint column,
	gpointer user_data){
	
/* called when a tree row is selected in the popup packet window */	

	field_info	*finfo;

	struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;

	g_assert(node);
	finfo = gtk_ctree_node_get_row_data( ctree, GTK_CTREE_NODE(node) );
	if (!finfo) return;

	DataPtr->finfo_selected = finfo;

	packet_hex_print(GTK_TEXT(DataPtr->byte_view), DataPtr->pd,
		DataPtr->frame, finfo);

}

static void
new_tree_view_unselect_row_cb(GtkCTree *ctree, GList *node, gint column,
	gpointer user_data){

/* called when a tree row is unselected in the popup packet window */	
	
	
	
	struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;

	DataPtr->finfo_selected = NULL;
	packet_hex_print(GTK_TEXT(DataPtr->byte_view), DataPtr->pd,
		DataPtr->frame, NULL);
}

/* Functions called from elsewhere to act on all popup packet windows. */

/* Destroy all popup packet windows. */
void
destroy_packet_wins(void)
{
	struct PacketWinData *DataPtr;

	/* Destroying a packet window causes it to be removed from
	   the list of packet windows, so we can't do a "g_list_foreach()"
	   to go through the list of all packet windows and destroy them
	   as we find them; instead, as long as the list is non-empty,
	   we destroy the first window on the list. */
	while (detail_windows != NULL) {
		DataPtr = (struct PacketWinData *)(detail_windows->data);
		gtk_widget_destroy(DataPtr->main);
	}
}

static void
redraw_hex_dump_cb(gpointer data, gpointer user_data)
{
	struct PacketWinData *DataPtr = (struct PacketWinData *)data;

	redraw_hex_dump(DataPtr->byte_view, DataPtr->pd,
	    DataPtr->frame, DataPtr->finfo_selected);
}

/* Redraw the hex dump part of all the popup packet windows. */
void
redraw_hex_dump_packet_wins(void)
{
	g_list_foreach(detail_windows, redraw_hex_dump_cb, NULL);
}
