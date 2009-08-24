/* expert_dlg.c
 * Display of Expert information.
 *
 * Implemented as a tap listener to the "expert" tap.
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/emem.h>
#include <epan/tap.h>
#include "epan/packet_info.h"
#include <epan/stat_cmd_args.h>
#include <epan/prefs.h>

#include "../simple_dialog.h"
#include "../globals.h"
#include "../color.h"
#include "../stat_menu.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"

#include "gtk/find_dlg.h"
#include "gtk/color_dlg.h"
#include "gtk/main.h"
#include "gtk/gui_utils.h"
#include "gtk/gtkglobals.h"
#include "gtk/dlg_utils.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/tap_dfilter_dlg.h"
#include "gtk/color_utils.h"
#include "gtk/main_proto_draw.h"
#include "gtk/help_dlg.h"
#include "gtk/expert_dlg.h"

static const value_string expert_severity_om_vals[] = {
	{ PI_ERROR,		"Errors only" },
	{ PI_WARN,		"Error+Warn" },
	{ PI_NOTE,		"Error+Warn+Note" },
	{ PI_CHAT,		"Error+Warn+Note+Chat" },
	{ 0, NULL }
};

enum
{
   NO_COLUMN,
   SEVERITY_COLUMN,
   GROUP_COLUMN,
   PROTOCOL_COLUMN,
   SUMMARY_COLUMN,
   FOREGROUND_COLOR_COL,
   BACKGROUND_COLOR_COL,
   N_COLUMNS
};

/* reset of display only, e.g. for filtering */
static void expert_dlg_display_reset(expert_tapdata_t * etd)
{
	etd->disp_events = 0;
	gtk_list_store_clear(GTK_LIST_STORE(gtk_tree_view_get_model(GTK_TREE_VIEW(etd->tree_view))));

	gtk_window_set_title(GTK_WINDOW(etd->win), "Wireshark: ? Expert Infos");
	if(etd->label) {
		gtk_label_set_text(GTK_LABEL(etd->label), "Please wait ...");
	}
}


/* complete reset, e.g. capture file closed */
void expert_dlg_reset(void *tapdata)
{
	expert_tapdata_t * etd = tapdata;

	etd->chat_events = 0;
	etd->note_events = 0;
	etd->warn_events = 0;
	etd->error_events = 0;
	etd->last = 0;
	etd->first = 0;
	/* g_string_chunk_clear() is introduced in glib 2.14 */
	g_string_chunk_free(etd->text);
	etd->text = g_string_chunk_new(100);
	g_array_set_size(etd->ei_array, 0);

	expert_dlg_display_reset(etd);
}

int expert_dlg_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *pointer)
{
    expert_info_t	*ei;
    expert_tapdata_t * etd = tapdata;

    g_array_append_val(etd->ei_array, *(expert_info_t *)pointer);
    etd->last = etd->ei_array->len;
    ei = &g_array_index(etd->ei_array, expert_info_t, etd->last -1); /* ugly */
    ei->protocol = g_string_chunk_insert_const(etd->text, ei->protocol);
    ei->summary = g_string_chunk_insert_const(etd->text, ei->summary);

	switch(ei->severity) {
	case(PI_CHAT):
		etd->chat_events++;
		break;
	case(PI_NOTE):
		etd->note_events++;
		break;
	case(PI_WARN):
		etd->warn_events++;
		break;
	case(PI_ERROR):
		etd->error_events++;
		break;
	default:
		g_assert_not_reached();
	}
	if(ei->severity < etd->severity_report_level) {
		return 0; /* draw not required */
	} else {
		return 1; /* draw required */
	}
}

void
expert_dlg_draw(void *data)
{
	expert_tapdata_t *etd = data;
	expert_info_t *ei;
	gchar *title;
	const char *entries[4];   /**< column entries */
    GtkListStore *list_store;
	GtkTreeIter       iter;
	const gchar *color_str;
	guint packet_no = 0;


	if(etd->label) {
		if(etd->last - etd->first) {
			title = g_strdup_printf("Adding: %u new messages",etd->last - etd->first);
			gtk_label_set_text(GTK_LABEL(etd->label), title);
			g_free(title);
		}
	}

	/* append new events (remove from new list, append to displayed list and clist) */
	while(etd->first < etd->last){
		ei = &g_array_index(etd->ei_array, expert_info_t, etd->first);
		etd->first++;

		if(ei->severity < etd->severity_report_level) {
			continue;
		}
		etd->disp_events++;

		/* packet number */
		if(ei->packet_num) {
            packet_no = ei->packet_num;
		}

		/* severity */
		entries[0] = val_to_str(ei->severity, expert_severity_vals, "Unknown severity (%u)");

		/* group */
		entries[1] = val_to_str(ei->group, expert_group_vals, "Unknown group (%u)");

		/* protocol */
		if(ei->protocol) {
			entries[2] = ei->protocol;
		} else {
			entries[2] = "-";
		}

		/* summary */
		entries[3] = ei->summary;

		/* set rows background color depending on severity */
		switch(ei->severity) {
		case(PI_CHAT):
			color_str = gdk_color_to_string(&expert_color_chat);
			break;
		case(PI_NOTE):
			color_str = gdk_color_to_string(&expert_color_note);
			break;
		case(PI_WARN):
			color_str = gdk_color_to_string(&expert_color_warn);
			break;
		case(PI_ERROR):
			color_str = gdk_color_to_string(&expert_color_error);
			break;
		default:
			g_assert_not_reached();
		}

		list_store = GTK_LIST_STORE(gtk_tree_view_get_model(etd->tree_view)); /* Get store */
 
		/* Creates a new row at position. iter will be changed to point to this new row. 
		 * If position is larger than the number of rows on the list, then the new row will be appended to the list.
		 * The row will be filled with the values given to this function.
		 * :
		 * should generally be preferred when inserting rows in a sorted list store.
		 */
#if GTK_CHECK_VERSION(2,6,0)
		gtk_list_store_insert_with_values( list_store , &iter, G_MAXINT,
#else
		gtk_list_store_append  (list_store, &iter);
		gtk_list_store_set  (list_store, &iter,
#endif
					NO_COLUMN, packet_no,
					SEVERITY_COLUMN, entries[0],
					GROUP_COLUMN, entries[1],
					PROTOCOL_COLUMN, entries[2],
					SUMMARY_COLUMN, entries[3],
					FOREGROUND_COLOR_COL, gdk_color_to_string(&expert_color_foreground),
					BACKGROUND_COLOR_COL, color_str,
					-1);
	}
	
	if(etd->label) {
		title = g_strdup_printf("Errors: %u Warnings: %u Notes: %u Chats: %u",
			etd->error_events, etd->warn_events, etd->note_events, etd->chat_events);
			gtk_label_set_text(GTK_LABEL(etd->label), title);
		g_free(title);
	}

	title = g_strdup_printf("Wireshark: %u Expert Info%s",
		etd->disp_events,
		plurality(etd->disp_events, "", "s"));
	gtk_window_set_title(GTK_WINDOW(etd->win), title);
	g_free(title);
}

static void
select_row_cb(GtkTreeSelection *selection, gpointer *user_data _U_)
{
	//guint num = GPOINTER_TO_UINT(gtk_clist_get_row_data(clist, row));

	//cf_goto_frame(&cfile, num);

	GtkTreeIter iter;
	GtkTreeModel *model;
	guint fnumber;


	if (selection==NULL)
		return;
	
	if (gtk_tree_selection_get_selected (selection, &model, &iter)){
		gtk_tree_model_get (model, &iter, NO_COLUMN, &fnumber, -1);
		cf_goto_frame(&cfile, fnumber);
	}

}

 void
expert_dlg_init_table(expert_tapdata_t * etd, GtkWidget *vbox)
{
    GtkListStore *store;
    GtkWidget *tree;
    GtkTreeViewColumn *column;
    GtkCellRenderer *renderer;
    GtkTreeSortable *sortable;
	GtkTreeSelection  *selection;

    /* Create the store */
    store = gtk_list_store_new (N_COLUMNS,       /* Total number of columns */
                               G_TYPE_UINT,      /* No				   */
                               G_TYPE_STRING,    /* Severity           */
                               G_TYPE_STRING,    /* Group              */
                               G_TYPE_STRING,    /* Protocol           */
                               G_TYPE_STRING,    /* Summary            */
                               G_TYPE_STRING,    /* forground          */
                               G_TYPE_STRING);   /* Background         */

    /* Create a view */
    tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
    etd->tree_view = GTK_TREE_VIEW(tree);
    sortable = GTK_TREE_SORTABLE(store);

#if GTK_CHECK_VERSION(2,6,0)
	/* Speed up the list display */
	gtk_tree_view_set_fixed_height_mode(etd->tree_view, TRUE);
#endif

    /* Setup the sortable columns */
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW (tree), FALSE);

    /* The view now holds a reference.  We can get rid of our own reference */
    g_object_unref (G_OBJECT (store));

    /* Create a cell renderer */
    renderer = gtk_cell_renderer_text_new ();

    /* Create the first column, associating the "text" attribute of the
     * cell_renderer to the first column of the model */
     /* No */
    column = gtk_tree_view_column_new_with_attributes ("No", renderer,
		"text", NO_COLUMN,
		"foreground", FOREGROUND_COLOR_COL,
		"background", BACKGROUND_COLOR_COL,
		NULL);
    gtk_tree_view_column_set_sort_column_id(column, NO_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (etd->tree_view, column);

	/* Severity */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Severity", renderer,
		"text", SEVERITY_COLUMN,
		"foreground", FOREGROUND_COLOR_COL,
		"background", BACKGROUND_COLOR_COL,
		NULL);
    gtk_tree_view_column_set_sort_column_id(column, SEVERITY_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    /* Add the column to the view. */
    gtk_tree_view_append_column (etd->tree_view, column);

	/* Group */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Group", renderer,
		"text", GROUP_COLUMN,
		"foreground", FOREGROUND_COLOR_COL,
		"background", BACKGROUND_COLOR_COL,
		NULL);
    gtk_tree_view_column_set_sort_column_id(column, GROUP_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    /* Add the column to the view. */
    gtk_tree_view_append_column (etd->tree_view, column);


	/* Protocol. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Protocol", renderer,
		"text", PROTOCOL_COLUMN,
		"foreground", FOREGROUND_COLOR_COL,
		"background", BACKGROUND_COLOR_COL,
		NULL);
    gtk_tree_view_column_set_sort_column_id(column, PROTOCOL_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 80);
    gtk_tree_view_append_column (etd->tree_view, column);
 
    /* Summary. */
    renderer = gtk_cell_renderer_text_new ();
    column = gtk_tree_view_column_new_with_attributes ("Summary", renderer,
		"text", SUMMARY_COLUMN,
		"foreground", FOREGROUND_COLOR_COL,
		"background", BACKGROUND_COLOR_COL,
		NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_FIXED);
    gtk_tree_view_column_set_min_width(column, 90);
    gtk_tree_view_column_set_sort_column_id(column, SUMMARY_COLUMN);
    gtk_tree_view_column_set_resizable(column, TRUE);
    gtk_tree_view_append_column (etd->tree_view, column);
 

    gtk_tree_view_set_search_column (etd->tree_view, SUMMARY_COLUMN); /* Allow searching the summary */
    gtk_tree_view_set_reorderable (etd->tree_view, TRUE);   /* Allow user to reorder data with drag n drop */
    
    /* Now enable the sorting of each column */
    gtk_tree_view_set_rules_hint(GTK_TREE_VIEW(etd->tree_view), TRUE);
    gtk_tree_view_set_headers_clickable(GTK_TREE_VIEW(etd->tree_view), TRUE);

	/* Setup the selection handler */
	selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(etd->tree_view));
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

	g_signal_connect (G_OBJECT (selection), "changed", /* select_row */
                  G_CALLBACK (select_row_cb),
                  NULL);

	etd->scrolled_window=scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(etd->scrolled_window), GTK_WIDGET (etd->tree_view));

	gtk_box_pack_start(GTK_BOX(vbox), etd->scrolled_window, TRUE, TRUE, 0);

}


void
expert_dlg_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	expert_tapdata_t *etd=(expert_tapdata_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(etd);
	unprotect_thread_critical_region();

	/*free_srt_table_data(&etd->afp_srt_table);*/
	g_array_free(etd->ei_array, TRUE);
	g_string_chunk_free(etd->text);
	g_free(etd);
}


static void
expert_dlg_severity_cb(GtkWidget *w, gpointer data _U_)
{
	int i;
	expert_tapdata_t * etd;

	i = gtk_combo_box_get_active (GTK_COMBO_BOX(w));
	etd = g_object_get_data(G_OBJECT(w), "tapdata");

	etd->severity_report_level = expert_severity_om_vals[i].value;

	/* "move" all events from "all" back to "new" lists */
	protect_thread_critical_region();
	etd->first = 0;
	unprotect_thread_critical_region();

	/* redraw table */
	expert_dlg_display_reset(etd);
	expert_dlg_draw(etd);
}

expert_tapdata_t * expert_dlg_new_table(void)
{
	expert_tapdata_t * etd;
	etd=g_malloc0(sizeof(expert_tapdata_t));
	
	etd->ei_array = g_array_sized_new(FALSE, FALSE, sizeof(expert_info_t), 1000);
	etd->text = g_string_chunk_new(100);
	etd->severity_report_level = PI_CHAT;
	return etd;
}

static void
expert_dlg_init(const char *optarg, void* userdata _U_)
{
	expert_tapdata_t * etd;
	const char *filter=NULL;
	GString *error_string;
	GtkWidget *vbox;
	GtkWidget *table;
	GtkWidget *bbox;
	GtkWidget *close_bt;
	GtkWidget *help_bt;

	GtkWidget *severity_box;
	GtkWidget *severity_combo_box;
	GtkWidget *label;
	GtkTooltips *tooltips = gtk_tooltips_new();
	int i;

	if(!strncmp(optarg,"afp,srt,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	proto_draw_colors_init();

	etd = expert_dlg_new_table();
	etd->win=dlg_window_new("Wireshark: Expert Info");	/* transient_for top_level */
	gtk_window_set_destroy_with_parent (GTK_WINDOW(etd->win), TRUE);

	gtk_window_set_default_size(GTK_WINDOW(etd->win), 650, 600);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(etd->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	table = gtk_table_new(1, 2, TRUE /* homogeneous */);
	gtk_box_pack_start(GTK_BOX(vbox), table, FALSE, FALSE, 0);

	etd->label=gtk_label_new("Please wait ...");
	gtk_misc_set_alignment(GTK_MISC(etd->label), 0.0f, 0.5f);
	gtk_table_attach_defaults(GTK_TABLE(table), etd->label, 0, 1, 0, 1);

	severity_box = gtk_hbox_new(FALSE, 0);
	gtk_table_attach_defaults(GTK_TABLE(table), severity_box, 1, 2, 0, 1);

	label=gtk_label_new("Severity filter: ");
	gtk_box_pack_start(GTK_BOX(severity_box), label, FALSE, FALSE, 0);

	severity_combo_box = gtk_combo_box_new_text ();
	for(i=0; expert_severity_om_vals[i].strptr != NULL;i++){
		gtk_combo_box_append_text (GTK_COMBO_BOX (severity_combo_box), expert_severity_om_vals[i].strptr);
		if(expert_severity_om_vals[i].value == (guint) etd->severity_report_level) {
			gtk_combo_box_set_active(GTK_COMBO_BOX(severity_combo_box), i);
		}
	}

	g_object_set_data(G_OBJECT(severity_combo_box), "tapdata", etd);
	g_signal_connect(severity_combo_box, "changed", G_CALLBACK(expert_dlg_severity_cb), etd->win);
	gtk_box_pack_start(GTK_BOX(severity_box), severity_combo_box, FALSE, FALSE, 0);


	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(etd->win);

	expert_dlg_init_table(etd, vbox);
	/*for(i=0;i<256;i++){
		init_srt_table_row(&etd->afp_srt_table, i, val_to_str(i, CommandCode_vals, "Unknown(%u)"));
	}*/

	error_string=register_tap_listener("expert", etd, NULL /* fstring */,
		TL_REQUIRES_PROTO_TREE,
		expert_dlg_reset,
		expert_dlg_packet,
		expert_dlg_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", error_string->str);
		g_string_free(error_string, TRUE);
		g_free(etd);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(etd->win, close_bt, window_cancel_button_cb);

	help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
	g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_EXPERT_INFO_DIALOG);
	gtk_tooltips_set_tip (tooltips, help_bt, "Show topic specific help", NULL);

	g_signal_connect(etd->win, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(etd->win, "destroy", G_CALLBACK(expert_dlg_destroy_cb), etd);

	gtk_widget_show_all(etd->win);
	window_present(etd->win);

	cf_retap_packets(&cfile);

	/* This will bring up the progress bar
	 * Put our window back in front
	 */
	gdk_window_raise(etd->win->window);
	expert_dlg_draw(etd);

}


static void
expert_dlg_cb(GtkWidget *w _U_, gpointer d _U_)
{
	expert_dlg_init("", NULL);
}




void
register_tap_listener_expert(void)
{
	register_stat_cmd_arg("expert", expert_dlg_init,NULL);

	register_stat_menu_item("E_xpert Info", REGISTER_ANALYZE_GROUP_UNSORTED,
        expert_dlg_cb, NULL, NULL, NULL);
}
