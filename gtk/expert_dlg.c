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


/* reset of display only, e.g. for filtering */
static void expert_dlg_display_reset(expert_tapdata_t * etd)
{
	etd->disp_events = 0;
	gtk_clist_clear(etd->table);
	gtk_clist_columns_autosize(etd->table);

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
	g_string_chunk_clear(etd->text);
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
    ei->protocol = ei->protocol;
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
	int row;
	int displayed;
	expert_info_t *ei;
	gchar *title;
	const char *entries[5];   /**< column entries */


	displayed = etd->disp_events;

	if(etd->label) {
		if(etd->last - etd->first) {
			title = g_strdup_printf("Adding: %u new messages",etd->last - etd->first);
			gtk_label_set_text(GTK_LABEL(etd->label), title);
			g_free(title);
		}
	}

	gtk_clist_freeze(etd->table);

	/* append new events (remove from new list, append to displayed list and clist) */
	while(etd->first < etd->last){
		ei = &g_array_index(etd->ei_array, expert_info_t, etd->first);
		etd->first++;

		if(ei->severity < etd->severity_report_level) {
			continue;
		}
		etd->disp_events++;

		if(etd->disp_events == 1000)
			gtk_clist_columns_autosize(etd->table);

		/* packet number */
		if(ei->packet_num) {
            char str_buf[10];

			g_snprintf(str_buf, sizeof(str_buf), "%u", ei->packet_num);
			entries[0] = str_buf;
		} else {
			entries[0] = "-";
		}

		/* severity */
		entries[1] = val_to_str(ei->severity, expert_severity_vals, "Unknown severity (%u)");

		/* group */
		entries[2] = val_to_str(ei->group, expert_group_vals, "Unknown group (%u)");

		/* protocol */
		if(ei->protocol) {
			entries[3] = ei->protocol;
		} else {
			entries[3] = "-";
		}

		/* summary */
		entries[4] = ei->summary;

		/*gtk_clist_set_pixmap(etd->table, row, 5, ascend_pm, ascend_bm);*/

		row=gtk_clist_append(etd->table, (gchar **) entries);
		gtk_clist_set_row_data(etd->table, row, GUINT_TO_POINTER(ei->packet_num));

		/* set rows background color depending on severity */
		switch(ei->severity) {
		case(PI_CHAT):
			gtk_clist_set_background(etd->table, row, &expert_color_chat);
			break;
		case(PI_NOTE):
			gtk_clist_set_background(etd->table, row, &expert_color_note);
			break;
		case(PI_WARN):
			gtk_clist_set_background(etd->table, row, &expert_color_warn);
			break;
		case(PI_ERROR):
			gtk_clist_set_background(etd->table, row, &expert_color_error);
			break;
		default:
			g_assert_not_reached();
		}
		gtk_clist_set_foreground(etd->table, row, &expert_color_foreground);
	}
	
	if (etd->table->sort_column || etd->table->sort_type != GTK_SORT_ASCENDING)
        gtk_clist_sort(etd->table);

	/* column autosizing is very slow for large number of entries,
	 * so do it only for the first 1000 of it
	 * (there might be no large changes behind this amount) */
	if(etd->disp_events < 1000)
		gtk_clist_columns_autosize(etd->table);
	gtk_clist_moveto(etd->table,
                     etd->disp_events - 1, -1, 1.0f, 1.0f);
	gtk_clist_thaw(etd->table);

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


typedef struct column_arrows {
	GtkWidget *table;
	GtkWidget *ascend_pm;
	GtkWidget *descend_pm;
} column_arrows;


static gint
srt_sort_column(GtkCList *clist, gconstpointer ptr1, gconstpointer ptr2)
{
	char *text1 = NULL;
	char *text2 = NULL;
	int i1, i2;

	const GtkCListRow *row1 = ptr1;
	const GtkCListRow *row2 = ptr2;

	text1 = GTK_CELL_TEXT (row1->cell[clist->sort_column])->text;
	text2 = GTK_CELL_TEXT (row2->cell[clist->sort_column])->text;

	switch(clist->sort_column){
	case 0:
		i1=atoi(text1);
		i2=atoi(text2);
		return i1-i2;
	case 1:
	case 2:
	case 3:
	case 4:
		return strcmp (text1, text2);
	}
	g_assert_not_reached();
	return 0;
}


static void
srt_click_column_cb(GtkCList *clist, gint column, gpointer data)
{
	column_arrows *col_arrows = (column_arrows *) data;
	int i;

	gtk_clist_freeze(clist);

	for (i = 0; i < 5; i++) {
		gtk_widget_hide(col_arrows[i].ascend_pm);
		gtk_widget_hide(col_arrows[i].descend_pm);
	}

	if (column == clist->sort_column) {
		if (clist->sort_type == GTK_SORT_ASCENDING) {
			clist->sort_type = GTK_SORT_DESCENDING;
			gtk_widget_show(col_arrows[column].descend_pm);
		} else {
			clist->sort_type = GTK_SORT_ASCENDING;
			gtk_widget_show(col_arrows[column].ascend_pm);
		}
	} else {
		clist->sort_type = GTK_SORT_ASCENDING;
		gtk_widget_show(col_arrows[column].ascend_pm);
		gtk_clist_set_sort_column(clist, column);
	}
	gtk_clist_sort(clist);

	gtk_clist_thaw(clist);
}


static void
select_row_cb(GtkCList *clist, gint row, gint column _U_, GdkEventButton *event _U_, gpointer user_data _U_)
{
	guint num = GPOINTER_TO_UINT(gtk_clist_get_row_data(clist, row));

	cf_goto_frame(&cfile, num);
}


void
expert_dlg_init_table(expert_tapdata_t * etd, GtkWidget *vbox)
{
	int i;
	column_arrows *col_arrows;
	GtkStyle *win_style;
	GtkWidget *column_lb;
	GdkBitmap *ascend_bm, *descend_bm;
	GdkPixmap *ascend_pm, *descend_pm;
	const char *default_titles[] = { "No.", "Sever.", "Group", "Protocol", "Summary" };


	etd->scrolled_window=scrolled_window_new(NULL, NULL);
	gtk_box_pack_start(GTK_BOX(vbox), etd->scrolled_window, TRUE, TRUE, 0);

	etd->table=(GtkCList *)gtk_clist_new(5);
	g_signal_connect(etd->table, "select-row", G_CALLBACK(select_row_cb), etd);

	gtk_widget_show(GTK_WIDGET(etd->table));
	gtk_widget_show(etd->scrolled_window);

	col_arrows = (column_arrows *) g_malloc(sizeof(column_arrows) * 5);
	win_style = gtk_widget_get_style(etd->scrolled_window);
	ascend_pm = gdk_pixmap_create_from_xpm_d(etd->scrolled_window->window,
			&ascend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_ascend_xpm);
	descend_pm = gdk_pixmap_create_from_xpm_d(etd->scrolled_window->window,
			&descend_bm,
			&win_style->bg[GTK_STATE_NORMAL],
			(gchar **)clist_descend_xpm);
	for (i = 0; i < 5; i++) {
		col_arrows[i].table = gtk_table_new(2, 2, FALSE);
		gtk_table_set_col_spacings(GTK_TABLE(col_arrows[i].table), 5);
		column_lb = gtk_label_new(default_titles[i]);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), column_lb, 0, 1, 0, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		gtk_widget_show(column_lb);

		col_arrows[i].ascend_pm = gtk_pixmap_new(ascend_pm, ascend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].ascend_pm, 1, 2, 1, 2, GTK_SHRINK, GTK_SHRINK, 0, 0);
		col_arrows[i].descend_pm = gtk_pixmap_new(descend_pm, descend_bm);
		gtk_table_attach(GTK_TABLE(col_arrows[i].table), col_arrows[i].descend_pm, 1, 2, 0, 1, GTK_SHRINK, GTK_SHRINK, 0, 0);
		if (i == 0) {
			gtk_widget_show(col_arrows[i].ascend_pm);
		}
		gtk_clist_set_column_widget(GTK_CLIST(etd->table), i, col_arrows[i].table);
		gtk_widget_show(col_arrows[i].table);
	}
	gtk_clist_column_titles_show(GTK_CLIST(etd->table));

	gtk_clist_set_compare_func(etd->table, srt_sort_column);
	gtk_clist_set_sort_column(etd->table, 0);
	gtk_clist_set_sort_type(etd->table, GTK_SORT_ASCENDING);

	gtk_clist_set_column_justification(etd->table, 0, GTK_JUSTIFY_RIGHT);
	gtk_clist_set_column_justification(etd->table, 3, GTK_JUSTIFY_RIGHT);
	gtk_clist_set_shadow_type(etd->table, GTK_SHADOW_IN);
	gtk_clist_column_titles_show(etd->table);
	gtk_clist_columns_autosize(etd->table);
/*	gtk_clist_set_selection_mode(etd->table, GTK_SELECTION_SINGLE);*/
/*    gtk_list_set_selection_mode(GTK_LIST(etd->table), GTK_SELECTION_BROWSE);*/
/*    gtk_list_select_item(GTK_LIST(value_list), 0);*/
	gtk_container_add(GTK_CONTAINER(etd->scrolled_window), (GtkWidget *)etd->table);

	g_signal_connect(etd->table, "click-column", G_CALLBACK(srt_click_column_cb), col_arrows);

	gtk_widget_show(GTK_WIDGET(etd->table));
	gtk_widget_show(etd->scrolled_window);

	/* create popup menu for this table */
	/*if(etd->filter_string){
		srt_create_popup_menu(etd);
	}*/
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
expert_dlg_severity_cb(GtkWidget *w, gpointer data)
{
	int i = GPOINTER_TO_INT(data);
	expert_tapdata_t * etd;


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
	GtkWidget *severity_om;
	GtkWidget *menu;
	GtkWidget *menu_item;
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

	menu=gtk_menu_new();
	for(i=0; expert_severity_om_vals[i].strptr != NULL;i++){
		menu_item=gtk_menu_item_new_with_label(expert_severity_om_vals[i].strptr);
		g_object_set_data(G_OBJECT(menu_item), "tapdata", etd);
		g_signal_connect(menu_item, "activate", G_CALLBACK(expert_dlg_severity_cb), (gpointer)(long) i);
		gtk_menu_shell_append(GTK_MENU_SHELL(menu), menu_item);
		if(expert_severity_om_vals[i].value == (guint) etd->severity_report_level) {
			gtk_menu_set_active(GTK_MENU(menu), i);
		}
	}
	severity_om=gtk_option_menu_new();
	gtk_option_menu_set_menu(GTK_OPTION_MENU(severity_om), menu);
	gtk_box_pack_start(GTK_BOX(severity_box), severity_om, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(etd->win);

	expert_dlg_init_table(etd, vbox);
	/*for(i=0;i<256;i++){
		init_srt_table_row(&etd->afp_srt_table, i, val_to_str(i, CommandCode_vals, "Unknown(%u)"));
	}*/

	error_string=register_tap_listener("expert", etd, NULL /* fstring */,
		0,
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
