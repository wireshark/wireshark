/* packet_win.c
 * Routines for popping a window to display current packet
 *
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
 *
 * $Id$
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
 *
 * To do:
 * - Add close button to bottom.
 * - improve the window Title and allow user to config it
 * - Add print support ? ( could be a mess)
 * - Add button to have main window jump to this packet ?
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <gtk/gtk.h>

#include <string.h>

#include <epan/epan.h>
#include "main.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#include "summary.h"
#include "file.h"
#include <epan/prefs.h>
#include "menu.h"
#include "../menu.h"
#include <epan/column.h>
#include "print.h"
#include <epan/addr_resolv.h>
#include "packet_win.h"
#include "simple_dialog.h"
#include "proto_draw.h"
#include "keys.h"
#include "gtkglobals.h"
#include "gui_utils.h"
#include <epan/plugins.h>
#include <epan/epan_dissect.h>
#include "compat_macros.h"

#include "../ui_util.h"

/* Data structure holding information about a packet-detail window. */
struct PacketWinData {
	frame_data *frame;	   /* The frame being displayed */
	union wtap_pseudo_header pseudo_header; /* Pseudo-header for packet */
	guint8     *pd;		   /* Data for packet */
	GtkWidget  *main;
	GtkWidget  *tv_scrollw;
	GtkWidget  *tree_view;
	GtkWidget  *bv_nb_ptr;
 	field_info *finfo_selected;
	epan_dissect_t	*edt;
};

/* List of all the packet-detail windows popped up. */
static GList *detail_windows;

#if GTK_MAJOR_VERSION < 2
static void new_tree_view_select_row_cb(GtkCTree *ctree, GList *node,
                                        gint column, gpointer user_data);

static void new_tree_view_unselect_row_cb( GtkCTree *ctree, GList *node,
                                           gint column, gpointer user_data);
#else
static void new_tree_view_selection_changed_cb(GtkTreeSelection *sel,
                                               gpointer user_data);

#endif

static void destroy_new_window(GtkObject *object, gpointer user_data);

void new_window_cb(GtkWidget *w _U_)
{
#define NewWinTitleLen 1000
  char Title[NewWinTitleLen] = "";
  const char *TextPtr;
  gint tv_size = 95, bv_size = 75;
  GtkWidget *main_w, *main_vbox, *pane,
                      *tree_view, *tv_scrollw,
                      *bv_nb_ptr;
  struct PacketWinData *DataPtr;
  int i;

  /* Allocate data structure to represent this window. */
  DataPtr = (struct PacketWinData *) g_malloc(sizeof(struct PacketWinData));

  DataPtr->frame = cfile.current_frame;
  memcpy(&DataPtr->pseudo_header, &cfile.pseudo_header, sizeof DataPtr->pseudo_header);
  DataPtr->pd = g_malloc(DataPtr->frame->cap_len);
  memcpy(DataPtr->pd, cfile.pd, DataPtr->frame->cap_len);
  DataPtr->edt = epan_dissect_new(TRUE, TRUE);
  epan_dissect_run(DataPtr->edt, &DataPtr->pseudo_header, DataPtr->pd,
          DataPtr->frame, &cfile.cinfo);
  epan_dissect_fill_in_columns(DataPtr->edt);

  /*
   * Build title of window by getting column data constructed when the
   * frame was dissected.
   */
  for (i = 0; i < cfile.cinfo.num_cols; ++i) {
    TextPtr = cfile.cinfo.col_data[i];
    if ((strlen(Title) + strlen(TextPtr)) < NewWinTitleLen - 1) {
      strcat(Title, TextPtr);
      strcat(Title, " ");
    }
  }

  main_w = window_new(GTK_WINDOW_TOPLEVEL, Title);
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
  tv_scrollw = main_tree_view_new(&prefs, &tree_view);
  gtk_paned_pack1(GTK_PANED(pane), tv_scrollw, TRUE, TRUE);
  WIDGET_SET_SIZE(tv_scrollw, -1, tv_size);
  gtk_widget_show(tv_scrollw);
  gtk_widget_show(tree_view);

  /* Byte view */
  bv_nb_ptr = byte_view_new();
  gtk_paned_pack2(GTK_PANED(pane), bv_nb_ptr, FALSE, FALSE);
  WIDGET_SET_SIZE(bv_nb_ptr, -1, bv_size);
  gtk_widget_show(bv_nb_ptr);

  DataPtr->main = main_w;
  DataPtr->tv_scrollw = tv_scrollw;
  DataPtr->tree_view = tree_view;
  DataPtr->bv_nb_ptr = bv_nb_ptr;
  detail_windows = g_list_append(detail_windows, DataPtr);

  /* load callback handlers */
#if GTK_MAJOR_VERSION < 2
  SIGNAL_CONNECT(tree_view, "tree-select-row", new_tree_view_select_row_cb,
                 DataPtr);

  SIGNAL_CONNECT(tree_view, "tree-unselect-row", new_tree_view_unselect_row_cb,
                 DataPtr);
#else
  SIGNAL_CONNECT(gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view)),
                 "changed", new_tree_view_selection_changed_cb, DataPtr);
#endif

  SIGNAL_CONNECT(main_w, "destroy", destroy_new_window, DataPtr);

  /* draw the protocol tree & print hex data */
  add_byte_views(DataPtr->edt, tree_view, DataPtr->bv_nb_ptr);
  proto_tree_draw(DataPtr->edt->tree, tree_view);

  DataPtr->finfo_selected = NULL;
  gtk_widget_show(main_w);
}

static void
destroy_new_window(GtkObject *object _U_, gpointer user_data)
{
  struct PacketWinData *DataPtr = user_data;

  detail_windows = g_list_remove(detail_windows, DataPtr);
  epan_dissect_free(DataPtr->edt);
  g_free(DataPtr->pd);
  g_free(DataPtr);
}

#if GTK_MAJOR_VERSION < 2
/* called when a tree row is selected in the popup packet window */
static void
new_tree_view_select_row_cb(GtkCTree *ctree, GList *node, gint column _U_,
                            gpointer user_data)
{
	field_info *finfo;
	GtkWidget *byte_view;
	const guint8 *data;
	guint len;

	struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;

	g_assert(node);
	finfo = gtk_ctree_node_get_row_data( ctree, GTK_CTREE_NODE(node) );
	if (!finfo) return;

	set_notebook_page(DataPtr->bv_nb_ptr, finfo->ds_tvb);
	byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
	if ( !byte_view)	/* exit if no hex window to write in */
		return;

	data = get_byte_view_data_and_length(byte_view, &len);
	if (data == NULL) {
                data = DataPtr->pd;
                len =  DataPtr->frame->cap_len;
        }

	DataPtr->finfo_selected = finfo;
	packet_hex_print(GTK_TEXT(byte_view), data,
		DataPtr->frame, finfo, len);
}

/* called when a tree row is unselected in the popup packet window */
static void
new_tree_view_unselect_row_cb(GtkCTree *ctree _U_, GList *node _U_,
                              gint column _U_, gpointer user_data)
{
	GtkWidget* byte_view;
	const guint8* data;
	guint len;

	struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;

	DataPtr->finfo_selected = NULL;

	byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
	if ( !byte_view)	/* exit if no hex window to write in */
		return;

	data = get_byte_view_data_and_length(byte_view, &len);
	g_assert(data != NULL);
	packet_hex_reprint(GTK_TEXT(byte_view));
}
#else
/* called when a tree row is (un)selected in the popup packet window */
static void
new_tree_view_selection_changed_cb(GtkTreeSelection *sel, gpointer user_data)
{
    field_info   *finfo;
    GtkWidget    *byte_view;
    const guint8 *data;
    guint         len;
    GtkTreeModel *model;
    GtkTreeIter   iter;

    struct PacketWinData *DataPtr = (struct PacketWinData*)user_data;

    /* if something is selected */
    if (gtk_tree_selection_get_selected(sel, &model, &iter))
    {
        gtk_tree_model_get(model, &iter, 1, &finfo, -1);
        if (!finfo) return;

        set_notebook_page(DataPtr->bv_nb_ptr, finfo->ds_tvb);
        byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
        if (!byte_view)	/* exit if no hex window to write in */
            return;

        data = get_byte_view_data_and_length(byte_view, &len);
        if (data == NULL) {
            data = DataPtr->pd;
            len =  DataPtr->frame->cap_len;
        }

        DataPtr->finfo_selected = finfo;
        packet_hex_print(GTK_TEXT_VIEW(byte_view), data,
                         DataPtr->frame, finfo, len);
    }
    else
    {
        DataPtr->finfo_selected = NULL;

        byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
        if (!byte_view)	/* exit if no hex window to write in */
            return;

        data = get_byte_view_data_and_length(byte_view, &len);
        g_assert(data != NULL);
        packet_hex_reprint(GTK_TEXT_VIEW(byte_view));
    }
}
#endif

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
		window_destroy(DataPtr->main);
	}
}

static void
redraw_hex_dump_cb(gpointer data, gpointer user_data _U_)
{
	struct PacketWinData *DataPtr = (struct PacketWinData *)data;

	redraw_hex_dump(DataPtr->bv_nb_ptr, DataPtr->frame, DataPtr->finfo_selected);
}

/* Redraw the hex dump part of all the popup packet windows. */
void
redraw_hex_dump_packet_wins(void)
{
	g_list_foreach(detail_windows, redraw_hex_dump_cb, NULL);
}
