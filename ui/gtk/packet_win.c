/* packet_win.c
 * Routines for popping a window to display current packet
 *
 * Copyright 2000, Jeffrey C. Foster <jfoste@woodward.com>
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
 *
 * To do:
 * - Add close button to bottom.
 * - improve the window Title and allow user to config it
 * - Add print support ? ( could be a mess)
 * - Add button to have main window jump to this packet ?
 */


#include "config.h"

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <string.h>

#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/addr_resolv.h>
#include <epan/epan_dissect.h>
#include <epan/strutil.h>
#include <epan/tvbuff-int.h>
#include <epan/print.h>

#include "../../file.h"

#include "ui/recent.h"
#include "ui/simple_dialog.h"
#include "ui/summary.h"
#include "ui/ws_ui_util.h"

#include "ui/gtk/font_utils.h"
#include "ui/gtk/main.h"
#include "ui/gtk/packet_win.h"
#include "ui/gtk/packet_panes.h"
#include "ui/gtk/keys.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/old-gtk-compat.h"

#include "frame_tvbuff.h"

#include "globals.h"

#define BV_SIZE 75
#define TV_SIZE 95

/* Data structure holding information about a packet-detail window. */
struct PacketWinData {
	frame_data *frame;	   /* The frame being displayed */
	wtap_rec    rec;           /* Record metadata */
	guint8     *pd;		   /* Record data */
	GtkWidget  *main;
	GtkWidget  *tv_scrollw;
	GtkWidget  *tree_view;
	GtkWidget  *bv_nb_ptr;
 	field_info *finfo_selected;
	epan_dissect_t	edt;

	int pd_offset;
	int pd_bitoffset;
};

/* List of all the packet-detail windows popped up. */
static GList *detail_windows;

static void new_tree_view_selection_changed_cb(GtkTreeSelection *sel,
                                               gpointer user_data);


static void destroy_new_window(GObject *object, gpointer user_data);

static gboolean
button_press_handler(GtkWidget *widget, GdkEvent *event, gpointer data _U_)
{
	if (widget == NULL || event == NULL) {
		return FALSE;
	}

	tree_view_select(widget, (GdkEventButton *) event);

	/* GDK_2BUTTON_PRESS is a doubleclick -> expand/collapse tree row */
	if (event->type == GDK_2BUTTON_PRESS) {
		GtkTreePath      *path;

		if (gtk_tree_view_get_path_at_pos(GTK_TREE_VIEW(widget),
						  (gint) (((GdkEventButton *)event)->x),
						  (gint) (((GdkEventButton *)event)->y),
						  &path, NULL, NULL, NULL))
		{
			if (gtk_tree_view_row_expanded(GTK_TREE_VIEW(widget), path)) {
				gtk_tree_view_collapse_row(GTK_TREE_VIEW(widget), path);
			}	else {
				gtk_tree_view_expand_row(GTK_TREE_VIEW(widget), path, FALSE);
			}
			gtk_tree_path_free(path);
		}
	}

	return FALSE;
}

/* Returns dynamically allocated memory, must be freed by caller after use */
static char*
create_packet_window_title(void)
{
	GString *title;
	int i;

	title = g_string_new("");

	/*
	 * Build title of window by getting column data constructed when the
	 * frame was dissected.
	 */
	for (i = 0; i < cfile.cinfo.num_cols; ++i) {
		g_string_append(title, cfile.cinfo.columns[i].col_data);
		g_string_append_c(title, ' ');
	}

	return g_string_free(title, FALSE);
}

static void
redissect_packet_window(gpointer object, gpointer user_data _U_)
{
	struct PacketWinData *DataPtr = (struct PacketWinData *)object;
	char *title;

	/* XXX, can be optimized? */
	proto_tree_draw(NULL, DataPtr->tree_view);
	epan_dissect_cleanup(&(DataPtr->edt));
	epan_dissect_init(&(DataPtr->edt), cfile.epan, TRUE, TRUE);
	epan_dissect_run(&(DataPtr->edt), cfile.cd_t, &DataPtr->rec,
	    frame_tvbuff_new(&cfile.provider, DataPtr->frame, DataPtr->pd),
	    DataPtr->frame, NULL);
	add_byte_views(&(DataPtr->edt), DataPtr->tree_view, DataPtr->bv_nb_ptr);
	proto_tree_draw(DataPtr->edt.tree, DataPtr->tree_view);

	/* update the window title */
	title = create_packet_window_title();
	gtk_window_set_title(GTK_WINDOW(DataPtr->main), title);
	g_free(title);
}

void new_packet_window(GtkWidget *w _U_, gboolean reference, gboolean editable _U_)
{
	char  *title;
	GtkWidget *main_w, *main_vbox, *pane,
		  *tree_view, *tv_scrollw,
		  *bv_nb_ptr;
	struct PacketWinData *DataPtr;
	frame_data *fd;

	if(reference) {
		guint32            framenum;
		header_field_info *hfinfo;

		if (! cfile.finfo_selected) {
			return;
		}

		hfinfo = cfile.finfo_selected->hfinfo;

		g_assert(hfinfo);

		if (hfinfo->type != FT_FRAMENUM) {
			return;
		}

		framenum = fvalue_get_uinteger(&cfile.finfo_selected->value);

		if (framenum == 0) {
			return;
		}

		fd = frame_data_sequence_find(cfile.provider.frames, framenum);
	}
	else {
		fd = cfile.current_frame;
	}

	if (!fd) {
		/* nothing has been captured so far */
		return;
	}

	/* With the new packetlists "lazy columns" it's necessary to reread the record */
	if (!cf_read_record(&cfile, fd)) {
		/* error reading the record */
		return;
	}

	/* Allocate data structure to represent this window. */
	DataPtr = (struct PacketWinData *) g_malloc(sizeof(struct PacketWinData));

	/* XXX, protect cfile.epan from closing (ref counting?) */
	DataPtr->frame = fd;
	DataPtr->rec  = cfile.rec;
	DataPtr->pd = (guint8 *)g_malloc(DataPtr->frame->cap_len);
	memcpy(DataPtr->pd, ws_buffer_start_ptr(&cfile.buf), DataPtr->frame->cap_len);

	epan_dissect_init(&(DataPtr->edt), cfile.epan, TRUE, TRUE);
	epan_dissect_run(&(DataPtr->edt), cfile.cd_t, &DataPtr->rec,
	                 frame_tvbuff_new(&cfile.provider, DataPtr->frame, DataPtr->pd),
			 DataPtr->frame, &cfile.cinfo);
	epan_dissect_fill_in_columns(&(DataPtr->edt), FALSE, TRUE);

	/* update the window title */
	title = create_packet_window_title();
	main_w = window_new(GTK_WINDOW_TOPLEVEL, title);
	g_free(title);
	gtk_window_set_default_size(GTK_WINDOW(main_w), DEF_WIDTH, -1);

	/* Container for paned windows  */
	main_vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 1, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(main_vbox), 1);
	gtk_container_add(GTK_CONTAINER(main_w), main_vbox);
	gtk_widget_show(main_vbox);

	/* Panes for the tree and byte view */
	pane = gtk_paned_new(GTK_ORIENTATION_VERTICAL);
	gtk_box_pack_start(GTK_BOX(main_vbox), pane, TRUE, TRUE, 0);
	gtk_widget_show(pane);

	/* Tree view */
	tv_scrollw = proto_tree_view_new(&tree_view);
	gtk_paned_pack1(GTK_PANED(pane), tv_scrollw, TRUE, TRUE);
	gtk_widget_set_size_request(tv_scrollw, -1, TV_SIZE);
	gtk_widget_show(tv_scrollw);
	gtk_widget_show(tree_view);

	/* Byte view */
	bv_nb_ptr = byte_view_new();
	gtk_paned_pack2(GTK_PANED(pane), bv_nb_ptr, FALSE, FALSE);
	gtk_widget_set_size_request(bv_nb_ptr, -1, BV_SIZE);
	gtk_widget_show(bv_nb_ptr);

	DataPtr->main = main_w;
	DataPtr->tv_scrollw = tv_scrollw;
	DataPtr->tree_view = tree_view;
	DataPtr->bv_nb_ptr = bv_nb_ptr;
	detail_windows = g_list_append(detail_windows, DataPtr);

	/* load callback handlers */
	g_signal_connect(gtk_tree_view_get_selection(GTK_TREE_VIEW(tree_view)),
			 "changed", G_CALLBACK(new_tree_view_selection_changed_cb), DataPtr);
	g_signal_connect(tree_view, "button_press_event", G_CALLBACK(button_press_handler), NULL);
		g_signal_connect(main_w, "destroy", G_CALLBACK(destroy_new_window), DataPtr);

	/* draw the protocol tree & print hex data */
	add_byte_views(&(DataPtr->edt), tree_view, DataPtr->bv_nb_ptr);
	proto_tree_draw(DataPtr->edt.tree, tree_view);

	DataPtr->finfo_selected = NULL;
	DataPtr->pd_offset = 0;
	DataPtr->pd_bitoffset = 0;
	gtk_widget_show(main_w);
}

void
redissect_all_packet_windows(void)
{
	g_list_foreach(detail_windows, redissect_packet_window, NULL);
}

static void
destroy_new_window(GObject *object _U_, gpointer user_data)
{
	struct PacketWinData *DataPtr = (struct PacketWinData *)user_data;

	detail_windows = g_list_remove(detail_windows, DataPtr);
	proto_tree_draw(NULL, DataPtr->tree_view);
	epan_dissect_cleanup(&(DataPtr->edt));
	g_free(DataPtr->pd);
	g_free(DataPtr);
}

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

		packet_hex_print(byte_view, data, DataPtr->frame, finfo, len);
	}
	else
	{
		DataPtr->finfo_selected = NULL;

		byte_view = get_notebook_bv_ptr(DataPtr->bv_nb_ptr);
		if (!byte_view)	/* exit if no hex window to write in */
			return;

		data = get_byte_view_data_and_length(byte_view, &len);
		g_assert(data != NULL);
		packet_hex_reprint(byte_view);
	}
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
		window_destroy(DataPtr->main);
	}
}

static void
redraw_packet_bytes_cb(gpointer data, gpointer user_data _U_)
{
	struct PacketWinData *DataPtr = (struct PacketWinData *)data;

	redraw_packet_bytes(DataPtr->bv_nb_ptr, DataPtr->frame, DataPtr->finfo_selected);
}

/* Redraw the packet bytes part of all the popup packet windows. */
void
redraw_packet_bytes_packet_wins(void)
{
	g_list_foreach(detail_windows, redraw_packet_bytes_cb, NULL);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
