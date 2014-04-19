/* mcast_stream_dlg.c
 *
 * Copyright 2006, Iskratel , Slovenia
 * By Jakob Bratkovic <j.bratkovic@iskratel.si> and
 * Miha Jemec <m.jemec@iskratel.si>
 *
 * based on rtp_stream_dlg.c
 * Copyright 2003, Alcatel Business Systems
 * By Lars Ruoff <lars.ruoff@gmx.net>
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

#include "config.h"

#include <stdlib.h>
#include <string.h>
#include <locale.h>

#include <gtk/gtk.h>

#include "wsutil/filesystem.h"
#include <epan/address.h>
#include <epan/addr_resolv.h>
#include <epan/strutil.h>

#include "../globals.h"
#include "../stat_menu.h"
#include "ui/simple_dialog.h"

#include "ui/gtk/mcast_stream_dlg.h"
#include "ui/gtk/mcast_stream.h"
#include "ui/gtk/gui_stat_menu.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/gtkglobals.h"
#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/stock_icons.h"

void register_tap_listener_mcast_stream_dlg(void);

/* Capture callback data keys */
#define E_MCAST_ENTRY_1     "burst_interval"
#define E_MCAST_ENTRY_2     "burst_alarm"
#define E_MCAST_ENTRY_3     "buffer_alarm"
#define E_MCAST_ENTRY_4     "stream_speed"
#define E_MCAST_ENTRY_5     "total_speed"

static const gchar FWD_LABEL_TEXT[] = "Select a stream with left mouse button";
static const gchar PAR_LABEL_TEXT[] = "\nBurst int: ms   Burst alarm: pps    Buffer alarm: KB    Stream empty speed: Mbps    Total empty speed: Mbps\n";

/****************************************************************************/
static GtkWidget    *mcast_stream_dlg = NULL;
static GtkWidget    *mcast_params_dlg = NULL;

static GtkListStore *list_store	      = NULL;
static GtkTreeIter   list_iter;
static GtkWidget    *list_w	      = NULL;
static GtkWidget    *top_label	      = NULL;
static GtkWidget    *label_fwd	      = NULL;
static GtkWidget    *label_par	      = NULL;
static GtkWidget    *bt_filter	      = NULL;

static mcast_stream_info_t *selected_stream_fwd = NULL;  /* current selection */
static GList *last_list = NULL;

static guint32 streams_nb = 0;     /* number of displayed streams */

enum
{
	MC_COL_SRC_ADDR,
	MC_COL_SRC_PORT,
	MC_COL_DST_ADDR,
	MC_COL_DST_PORT,
	MC_COL_PACKETS,
	MC_COL_PPS,
	MC_COL_AVG_BW,
	MC_COL_MAX_BW,
	MC_COL_MAX_BURST,
	MC_COL_BURST_ALARM,
	MC_COL_MAX_BUFFER,
	MC_COL_BUFFER_ALARM,
	MC_COL_DATA,
	NUM_COLS /* The number of columns */
};

/****************************************************************************/
/* CALLBACKS                                                                */
/****************************************************************************/
static void
mcaststream_on_destroy(GObject *object _U_, gpointer user_data _U_)
{
	/* Remove the stream tap listener */
	remove_tap_listener_mcast_stream();

	/* Is there a params window open? */
	if (mcast_params_dlg != NULL)
		window_destroy(mcast_params_dlg);

	/* Clean up memory used by stream tap */
	mcaststream_reset((mcaststream_tapinfo_t*)mcaststream_get_info());

	/* Note that we no longer have a "Mcast Streams" dialog box. */
	mcast_stream_dlg = NULL;
}


/****************************************************************************/
static void
mcaststream_on_unselect(GtkButton *button _U_, gpointer user_data _U_)
{
	GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(list_w));

	gtk_tree_selection_unselect_all(selection);

	selected_stream_fwd = NULL;
	gtk_label_set_text(GTK_LABEL(label_fwd), FWD_LABEL_TEXT);
	gtk_widget_set_sensitive(bt_filter, FALSE);
}


/****************************************************************************/
static void
mcaststream_on_filter(GtkButton *button _U_, gpointer user_data _U_)
{
	gchar *filter_string_fwd;
	gchar  ip_version[3];

	if (selected_stream_fwd == NULL)
		return;

	if (selected_stream_fwd->src_addr.type == AT_IPv6) {
		g_strlcpy(ip_version,"v6",sizeof(ip_version));
	} else {
		ip_version[0] = '\0';
	}
	filter_string_fwd = g_strdup_printf(
		"(ip%s.src==%s && udp.srcport==%u && ip%s.dst==%s && udp.dstport==%u)",
		ip_version,
		ep_address_to_str(&(selected_stream_fwd->src_addr)),
		selected_stream_fwd->src_port,
		ip_version,
		ep_address_to_str(&(selected_stream_fwd->dest_addr)),
		selected_stream_fwd->dest_port);

	gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), filter_string_fwd);
	g_free(filter_string_fwd);

#if 0
	main_filter_packets(&cfile, filter_string, FALSE);
	mcaststream_dlg_update(mcaststream_get_info()->strinfo_list);
#endif
}

/****************************************************************************/
/* when the user selects a row in the stream list */
static void
mcaststream_on_select_row(GtkTreeSelection *selection, gpointer data _U_)
{
	gchar label_text[80];

	if (gtk_tree_selection_get_selected(selection, NULL, &list_iter))
	{
		gtk_tree_model_get(GTK_TREE_MODEL(list_store), &list_iter, MC_COL_DATA, &selected_stream_fwd, -1);
		g_snprintf(label_text, sizeof(label_text), "Selected: %s:%u -> %s:%u",
			ep_address_to_display(&(selected_stream_fwd->src_addr)),
			selected_stream_fwd->src_port,
			ep_address_to_display(&(selected_stream_fwd->dest_addr)),
			selected_stream_fwd->dest_port
		);
		gtk_label_set_text(GTK_LABEL(label_fwd), label_text);
		gtk_widget_set_sensitive(bt_filter, TRUE);
	} else {
		selected_stream_fwd = NULL;
		gtk_label_set_text(GTK_LABEL(label_fwd), FWD_LABEL_TEXT);
		gtk_widget_set_sensitive(bt_filter, FALSE);
	}
}


/****************************************************************************/
/* INTERFACE                                                                */
/****************************************************************************/
static void
mcast_params_destroy_cb(GtkWidget *win _U_, gpointer user_data _U_)
{
	/* Note that we no longer have a mcast params dialog box. */
	mcast_params_dlg = NULL;
}


static void
mcast_params_ok_cb(GtkWidget *ok_bt _U_, gpointer parent_w)
{
	GtkWidget   *fnumber_te;
	const gchar *fnumber_text;
	gint32       fnumber;
	char        *p;

	fnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_MCAST_ENTRY_1);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = (gint)strtol(fnumber_text, &p, 10);
	if ( ((p == fnumber_text) || (*p != '\0')) || (fnumber <= 0) || (fnumber > 1000) ) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The burst interval should be between 1 and 1000 ms.");
		return;
	}
	mcast_stream_burstint = fnumber;

	fnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_MCAST_ENTRY_2);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = (gint)strtol(fnumber_text, &p, 10);
	if ( ((p == fnumber_text) || (*p != '\0')) || (fnumber <= 0) ) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The burst alarm threshold you entered isn't valid.");
		return;
	}
	mcast_stream_trigger = fnumber;

	fnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_MCAST_ENTRY_3);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = (gint)strtol(fnumber_text, &p, 10);
	if ( ((p == fnumber_text) || (*p != '\0')) || (fnumber <= 0) ) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The buffer alarm threshold you entered isn't valid.");
		return;
	}
	mcast_stream_bufferalarm = fnumber;

	fnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_MCAST_ENTRY_4);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = (gint)strtol(fnumber_text, &p, 10);
	if ( ((p == fnumber_text) || (*p != '\0')) || (fnumber <= 0) || (fnumber > 10000000) ) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The stream empty speed should be between 1 and 10000000");
		return;
	}
	mcast_stream_emptyspeed = fnumber;

	fnumber_te = (GtkWidget *)g_object_get_data(G_OBJECT(parent_w), E_MCAST_ENTRY_5);
	fnumber_text = gtk_entry_get_text(GTK_ENTRY(fnumber_te));
	fnumber = (gint)strtol(fnumber_text, &p, 10);
	if ( ((p == fnumber_text) || (*p != '\0')) || (fnumber <= 0) || (fnumber > 10000000) ) {
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "The total empty speed should be between 1 and 10000000");
		return;
	}
	mcast_stream_cumulemptyspeed = fnumber;

	window_destroy(GTK_WIDGET(parent_w));

	/* Clean up memory used by stream tap */
	mcaststream_reset((mcaststream_tapinfo_t*)mcaststream_get_info());
	/* retap all packets */
	cf_retap_packets(&cfile);

}


static void
mcast_on_params(GtkButton *button _U_, gpointer data _U_)
{
	GtkWidget *main_vb;
	GtkWidget *label, *hbuttonbox, *grid;
	GtkWidget *ok_bt, *cancel_bt;
	GtkWidget *entry1, *entry2, *entry3, *entry4, *entry5;
	gchar label_text[51];

	if (mcast_params_dlg != NULL) {
		/* There's already a Params dialog box; reactivate it. */
		reactivate_window(mcast_params_dlg);
		return;
	}

	mcast_params_dlg = dlg_window_new("Wireshark: Set parameters for Multicast Stream Analysis");
	gtk_window_set_destroy_with_parent(GTK_WINDOW(mcast_params_dlg), TRUE);
	gtk_window_set_default_size(GTK_WINDOW(mcast_params_dlg), 210, 210);

	gtk_widget_show(mcast_params_dlg);

	/* Container for each row of widgets */
	main_vb =ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 3, FALSE);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 2);
	gtk_container_add(GTK_CONTAINER(mcast_params_dlg), main_vb);
	gtk_widget_show(main_vb);

	grid = ws_gtk_grid_new();
	gtk_box_pack_start(GTK_BOX(main_vb), grid, TRUE, TRUE, 0);
	label = gtk_label_new("  Burst measurement interval (ms)  ");
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), label, 0, 0, 1, 1);
	entry1 = gtk_entry_new();
	g_snprintf(label_text, sizeof(label_text), "%u", mcast_stream_burstint);
	gtk_entry_set_text(GTK_ENTRY(entry1), label_text);
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), entry1, 1, 0, 1, 1);
	label = gtk_label_new("  Burst alarm threshold (packets)   ");
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), label, 0, 1, 1, 1);
	entry2 = gtk_entry_new();
	g_snprintf(label_text, sizeof(label_text), "%u", mcast_stream_trigger);
	gtk_entry_set_text(GTK_ENTRY(entry2), label_text);
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), entry2, 1, 1, 1, 1);
	label = gtk_label_new("  Buffer alarm threshold (bytes)     ");
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), label, 0, 2, 1, 1);
	entry3 = gtk_entry_new();
	g_snprintf(label_text, sizeof(label_text), "%u", mcast_stream_bufferalarm);
	gtk_entry_set_text(GTK_ENTRY(entry3), label_text);
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), entry3, 1, 2, 1, 1);
	label = gtk_label_new("  Stream empty speed (kbit/s)      ");
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), label, 0, 3, 1, 1);
	entry4 = gtk_entry_new();
	g_snprintf(label_text, sizeof(label_text), "%u", mcast_stream_emptyspeed);
	gtk_entry_set_text(GTK_ENTRY(entry4), label_text);
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), entry4, 1, 3, 1, 1);
	label = gtk_label_new("  Total empty speed (kbit/s)       ");
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), label, 0, 4, 1, 1);
	entry5 = gtk_entry_new();
	g_snprintf(label_text, sizeof(label_text), "%u", mcast_stream_cumulemptyspeed);
	gtk_entry_set_text(GTK_ENTRY(entry5), label_text);
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), entry5, 1, 4, 1, 1);

	gtk_widget_show (grid);

	/* button row */
	hbuttonbox = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
	ws_gtk_grid_attach_defaults(GTK_GRID(grid), hbuttonbox, 0, 5, 2, 1);
	ok_bt = ws_gtk_button_new_from_stock(GTK_STOCK_OK);
	gtk_container_add (GTK_CONTAINER(hbuttonbox), ok_bt);
	cancel_bt = ws_gtk_button_new_from_stock(GTK_STOCK_CANCEL);
	gtk_container_add (GTK_CONTAINER(hbuttonbox), cancel_bt);
	gtk_widget_set_can_default(cancel_bt, TRUE);
	gtk_button_box_set_layout(GTK_BUTTON_BOX(hbuttonbox), GTK_BUTTONBOX_END);
	gtk_box_set_spacing(GTK_BOX(hbuttonbox), 0);

	g_signal_connect(mcast_params_dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(mcast_params_dlg, "destroy", G_CALLBACK(mcast_params_destroy_cb), NULL);
	g_signal_connect(ok_bt, "clicked", G_CALLBACK(mcast_params_ok_cb), mcast_params_dlg);
	window_set_cancel_button(mcast_params_dlg, cancel_bt, window_cancel_button_cb);

	/* Attach pointers to needed widgets */
	g_object_set_data(G_OBJECT(mcast_params_dlg), E_MCAST_ENTRY_1, entry1);
	g_object_set_data(G_OBJECT(mcast_params_dlg), E_MCAST_ENTRY_2, entry2);
	g_object_set_data(G_OBJECT(mcast_params_dlg), E_MCAST_ENTRY_3, entry3);
	g_object_set_data(G_OBJECT(mcast_params_dlg), E_MCAST_ENTRY_4, entry4);
	g_object_set_data(G_OBJECT(mcast_params_dlg), E_MCAST_ENTRY_5, entry5);

	gtk_widget_show_all(mcast_params_dlg);
	window_present(mcast_params_dlg);
}


/****************************************************************************/
/* append a line to list */
static void
add_to_list_store(mcast_stream_info_t* strinfo)
{
	gchar  label_text[256];
	gchar *data[NUM_COLS];
	int    i;
	char  *savelocale;

	/* save the current locale */
	savelocale = setlocale(LC_NUMERIC, NULL);
	/* switch to "C" locale to avoid problems with localized decimal separators
		in g_snprintf("%f") functions */
	setlocale(LC_NUMERIC, "C");
	data[0] = g_strdup(ep_address_to_display(&(strinfo->src_addr)));
	data[1] = g_strdup_printf("%u", strinfo->src_port);
	data[2] = g_strdup(ep_address_to_display(&(strinfo->dest_addr)));
	data[3] = g_strdup_printf("%u", strinfo->dest_port);
	data[4] = g_strdup_printf("%u", strinfo->npackets);
	data[5] = g_strdup_printf("%u /s", strinfo->apackets);
	data[6] = g_strdup_printf("%2.1f Mbps", strinfo->average_bw);
	data[7] = g_strdup_printf("%2.1f Mbps", strinfo->element.maxbw);
	data[8] = g_strdup_printf("%u / %dms", strinfo->element.topburstsize, mcast_stream_burstint);
	data[9] = g_strdup_printf("%u", strinfo->element.numbursts);
	data[10] = g_strdup_printf("%.1f KB", (float)strinfo->element.topbuffusage/1000);
	data[11] = g_strdup_printf("%u", strinfo->element.numbuffalarms);

	/* restore previous locale setting */
	setlocale(LC_NUMERIC, savelocale);

	/* Acquire an iterator */
	gtk_list_store_append(list_store, &list_iter);

	/* Fill the new row */
	gtk_list_store_set(list_store, &list_iter,
			    MC_COL_SRC_ADDR, data[0],
			    MC_COL_SRC_PORT, data[1],
			    MC_COL_DST_ADDR, data[2],
			    MC_COL_DST_PORT, data[3],
			    MC_COL_PACKETS, data[4],
			    MC_COL_PPS, data[5],
			    MC_COL_AVG_BW, data[6],
			    MC_COL_MAX_BW, data[7],
			    MC_COL_MAX_BURST, data[8],
			    MC_COL_BURST_ALARM, data[9],
			    MC_COL_MAX_BUFFER, data[10],
			    MC_COL_BUFFER_ALARM, data[11],
			    MC_COL_DATA, strinfo,
			    -1);

	for (i = 0; i < NUM_COLS-1; i++)
		g_free(data[i]);

	/* Update the top label with the number of detected streams */
	g_snprintf(label_text, sizeof(label_text),
		"Detected %d Multicast streams,   Average Bw: %.1f Mbps   Max Bw: %.1f Mbps   Max burst: %d / %dms   Max buffer: %.1f KB",
		++streams_nb,
		mcaststream_get_info()->allstreams->average_bw, mcaststream_get_info()->allstreams->element.maxbw,
		mcaststream_get_info()->allstreams->element.topburstsize, mcast_stream_burstint,
		(float)(mcaststream_get_info()->allstreams->element.topbuffusage)/1000);
	gtk_label_set_text(GTK_LABEL(top_label), label_text);

	g_snprintf(label_text, sizeof(label_text), "\nBurst int: %u ms   Burst alarm: %u pps   Buffer alarm: %u Bytes   Stream empty speed: %u Kbps   Total empty speed: %u Kbps\n",
		mcast_stream_burstint, mcast_stream_trigger, mcast_stream_bufferalarm, mcast_stream_emptyspeed, mcast_stream_cumulemptyspeed);
	gtk_label_set_text(GTK_LABEL(label_par), label_text);
}

/****************************************************************************/
/* Create list view */
static void
create_list_view(void)
{
	GtkTreeViewColumn *column;
	GtkCellRenderer   *renderer;
	GtkTreeSortable   *sortable;
	GtkTreeView       *list_view;
	GtkTreeSelection  *selection;

	/* Create the store */
	list_store = gtk_list_store_new(NUM_COLS,       /* Total number of columns */
					G_TYPE_STRING,  /* Source address */
					G_TYPE_STRING,  /* Source port */
					G_TYPE_STRING,  /* Destination address */
					G_TYPE_STRING,  /* Destination port */
					G_TYPE_STRING,  /* Packets */
					G_TYPE_STRING,  /* Packets per second */
					G_TYPE_STRING,  /* Average bandwidth */
					G_TYPE_STRING,  /* Max. bandwidth */
					G_TYPE_STRING,  /* Max. burst */
					G_TYPE_STRING,  /* Burst alarms */
					G_TYPE_STRING,  /* Max. buffers */
					G_TYPE_STRING,  /* Buffer alarms */
					G_TYPE_POINTER  /* Data */
				       );

	/* Create a view */
	list_w = gtk_tree_view_new_with_model(GTK_TREE_MODEL(list_store));

	list_view = GTK_TREE_VIEW(list_w);
	sortable = GTK_TREE_SORTABLE(list_store);

	/* Speed up the list display */
	gtk_tree_view_set_fixed_height_mode(list_view, TRUE);

	/* Setup the sortable columns */
	gtk_tree_sortable_set_sort_column_id(sortable, MC_COL_SRC_ADDR, GTK_SORT_ASCENDING);
	gtk_tree_view_set_headers_clickable(list_view, FALSE);

	/* The view now holds a reference.  We can get rid of our own reference */
	g_object_unref(G_OBJECT(list_store));

	/*
	 * Create the first column packet, associating the "text" attribute of the
	 * cell_renderer to the first column of the model
	 */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Src IP addr", renderer,
		"text", MC_COL_SRC_ADDR,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_SRC_ADDR);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_fixed_width(column, 100);
	/* Add the column to the view. */
	gtk_tree_view_append_column(list_view, column);

	/* Source port */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Src port", renderer,
		"text", MC_COL_SRC_PORT,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_SRC_PORT);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_fixed_width(column, 80);
	gtk_tree_view_append_column(list_view, column);

	/* Destination address */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Dst IP addr", renderer,
		"text", MC_COL_DST_ADDR,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_DST_ADDR);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_fixed_width(column, 100);
	gtk_tree_view_append_column(list_view, column);

	/* Destination port */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Dst port", renderer,
		"text", MC_COL_DST_PORT,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_DST_PORT);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_fixed_width(column, 80);
	gtk_tree_view_append_column(list_view, column);

	/* Packets */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Packets", renderer,
		"text", MC_COL_PACKETS,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_PACKETS);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_fixed_width(column, 80);
	gtk_tree_view_append_column(list_view, column);

	/* Packets/s */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Packets/s", renderer,
		"text", MC_COL_PPS,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_PPS);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 60);
	gtk_tree_view_column_set_fixed_width(column, 90);
	gtk_tree_view_append_column(list_view, column);

	/* Average bandwidth */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Avg Bw", renderer,
		"text", MC_COL_AVG_BW,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_AVG_BW);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_fixed_width(column, 80);
	gtk_tree_view_append_column(list_view, column);

	/* Max. bandwidth */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Max Bw", renderer,
		"text", MC_COL_MAX_BW,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_MAX_BW);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_fixed_width(column, 80);
	gtk_tree_view_append_column(list_view, column);

	/* Max. bursts */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Max bursts", renderer,
		"text", MC_COL_MAX_BURST,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_MAX_BURST);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 70);
	gtk_tree_view_column_set_fixed_width(column, 100);
	gtk_tree_view_append_column(list_view, column);

	/* Burst alarms*/
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Burst alarms", renderer,
		"text", MC_COL_BURST_ALARM,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_BURST_ALARM);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_fixed_width(column, 110);
	gtk_tree_view_append_column(list_view, column);

	/* Max. buffers */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Max buffers", renderer,
		"text", MC_COL_MAX_BUFFER,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_MAX_BUFFER);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_fixed_width(column, 100);
	gtk_tree_view_append_column(list_view, column);

	/* Buffer alarms */
	renderer = gtk_cell_renderer_text_new();
	column = gtk_tree_view_column_new_with_attributes("Buffer alarms", renderer,
		"text", MC_COL_BUFFER_ALARM,
		NULL);
	gtk_tree_view_column_set_sort_column_id(column, MC_COL_BUFFER_ALARM);
	gtk_tree_view_column_set_resizable(column, TRUE);
	gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
	gtk_tree_view_column_set_min_width(column, 90);
	gtk_tree_view_column_set_fixed_width(column, 120);
	gtk_tree_view_append_column(list_view, column);

	/* Now enable the sorting of each column */
	gtk_tree_view_set_rules_hint(list_view, TRUE);
	gtk_tree_view_set_headers_clickable(list_view, TRUE);

	/* Setup the selection handler */
	selection = gtk_tree_view_get_selection(list_view);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

	g_signal_connect(G_OBJECT(selection), "changed", /* (un)select_row */
			 G_CALLBACK(mcaststream_on_select_row),
			 NULL);

}


/****************************************************************************/
/* Create dialog */
static void
mcaststream_dlg_create(void)
{
	GtkWidget *mcaststream_dlg_w;
	GtkWidget *main_vb;
	GtkWidget *scrolledwindow;
	GtkWidget *hbuttonbox;
	/*GtkWidget *bt_unselect;*/
	GtkWidget *bt_params;
	GtkWidget *bt_close;

	gchar	  *title_name_ptr;
	gchar	  *win_name;

	title_name_ptr = cf_get_display_name(&cfile);
	win_name = g_strdup_printf("%s - UDP Multicast Streams", title_name_ptr);
	g_free(title_name_ptr);
	mcaststream_dlg_w = dlg_window_new(win_name);

	gtk_window_set_default_size(GTK_WINDOW(mcaststream_dlg_w), 1150, 400);

	main_vb = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 0, FALSE);
	gtk_container_add(GTK_CONTAINER(mcaststream_dlg_w), main_vb);
	gtk_container_set_border_width (GTK_CONTAINER (main_vb), 12);

	top_label = gtk_label_new ("Detected 0 Multicast streams");
	gtk_box_pack_start (GTK_BOX (main_vb), top_label, FALSE, FALSE, 8);

	scrolledwindow = scrolled_window_new (NULL, NULL);
	gtk_box_pack_start (GTK_BOX (main_vb), scrolledwindow, TRUE, TRUE, 0);

	create_list_view();
	gtk_container_add(GTK_CONTAINER(scrolledwindow), list_w);

	gtk_widget_show(mcaststream_dlg_w);

	label_fwd = gtk_label_new (FWD_LABEL_TEXT);
	gtk_box_pack_start (GTK_BOX (main_vb), label_fwd, FALSE, FALSE, 0);

	label_par = gtk_label_new (PAR_LABEL_TEXT);
	gtk_box_pack_start (GTK_BOX (main_vb), label_par, FALSE, FALSE, 0);

	/* button row */
	hbuttonbox = gtk_button_box_new(GTK_ORIENTATION_HORIZONTAL);
	gtk_box_pack_start (GTK_BOX (main_vb), hbuttonbox, FALSE, FALSE, 0);
	gtk_button_box_set_layout (GTK_BUTTON_BOX (hbuttonbox), GTK_BUTTONBOX_END);
	gtk_box_set_spacing (GTK_BOX (hbuttonbox), 0);

	/*bt_unselect = gtk_button_new_with_label ("Unselect");
	  gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_unselect);
	  gtk_widget_set_tooltip_text (bt_unselect, "Undo stream selection");*/

	bt_params = gtk_button_new_with_label ("Set parameters");
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_params);
	gtk_widget_set_tooltip_text (bt_params, "Set buffer, limit and speed parameters");

	bt_filter = gtk_button_new_with_label ("Prepare Filter");
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_filter);
	gtk_widget_set_tooltip_text (bt_filter, "Prepare a display filter of the selected stream");

	bt_close = ws_gtk_button_new_from_stock(GTK_STOCK_CLOSE);
	gtk_container_add (GTK_CONTAINER (hbuttonbox), bt_close);
	gtk_widget_set_tooltip_text (bt_close, "Close this dialog");
	gtk_widget_set_can_default(bt_close, TRUE);

	/*g_signal_connect(bt_unselect, "clicked", G_CALLBACK(mcaststream_on_unselect), NULL);*/
	g_signal_connect(bt_params, "clicked", G_CALLBACK(mcast_on_params), NULL);
	g_signal_connect(bt_filter, "clicked", G_CALLBACK(mcaststream_on_filter), NULL);
	window_set_cancel_button(mcaststream_dlg_w, bt_close, window_cancel_button_cb);

	g_signal_connect(mcaststream_dlg_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(mcaststream_dlg_w, "destroy", G_CALLBACK(mcaststream_on_destroy), NULL);

	gtk_widget_show_all(mcaststream_dlg_w);
	window_present(mcaststream_dlg_w);

	mcaststream_on_unselect(NULL, NULL);

	mcast_stream_dlg = mcaststream_dlg_w;

	g_free(win_name);

}


/****************************************************************************/
/* PUBLIC								    */
/****************************************************************************/

/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of mcast_stream_info_t* */
void
mcaststream_dlg_update(GList *list)
{
	if (mcast_stream_dlg != NULL) {
		gtk_list_store_clear(list_store);
		streams_nb = 0;

		list = g_list_first(list);
		while (list)
		{
			add_to_list_store((mcast_stream_info_t*)(list->data));
			list = g_list_next(list);
		}

		mcaststream_on_unselect(NULL, NULL);
	}

	last_list = list;
}


/****************************************************************************/
/* update the contents of the dialog box clist */
/* list: pointer to list of mcast_stream_info_t* */
void
mcaststream_dlg_show(GList *list)
{
	if (mcast_stream_dlg != NULL) {
		/* There's already a dialog box; reactivate it. */
		reactivate_window(mcast_stream_dlg);
		/* Another list since last call? */
		if (list != last_list) {
			mcaststream_dlg_update(list);
		}
	}
	else {
		/* Create and show the dialog box */
		mcaststream_dlg_create();
		mcaststream_dlg_update(list);
	}
}


/****************************************************************************/
/* entry point when called via the GTK menu */
void
mcaststream_launch(GtkAction *action _U_, gpointer user_data _U_)
{
	/* Register the tap listener */
	register_tap_listener_mcast_stream();

	/* Scan for Mcast streams (redissect all packets) */
	mcaststream_scan();

	/* Show the dialog box with the list of streams */
	mcaststream_dlg_show(mcaststream_get_info()->strinfo_list);

	/* Tap listener will be removed and cleaned up in mcaststream_on_destroy */
}

/****************************************************************************/
void
register_tap_listener_mcast_stream_dlg(void)
{
}

