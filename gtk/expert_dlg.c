/* expert_dlg.c
 * Display of Expert information.
 * 
 * Implemented as a tap listener to the "expert" tap.
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
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/emem.h>
#include <epan/tap.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#include <gtk/gtk.h>
#include "compat_macros.h"
#include "epan/packet_info.h"
#include "image/clist_ascend.xpm"
#include "image/clist_descend.xpm"
#include "simple_dialog.h"
#include "globals.h"
#include "gtk/find_dlg.h"
#include "color.h"
#include "gtk/color_dlg.h"
#include "main.h"
#include "gui_utils.h"
#include "gtkglobals.h"
#include "dlg_utils.h"
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include <../tap_dfilter_dlg.h>
#include <epan/stat_cmd_args.h>

#include <epan/prefs.h>
#include "colors.h"
#include "proto_draw.h"
#include <epan/emem.h>



static const value_string expert_severity_vals[] = {
	{ PI_CHAT,		"Chat" },
	{ PI_NOTE,		"Note" },
	{ PI_WARN,		"Warn" },
	{ PI_ERROR,		"Error" },
	{ 0, NULL }
};

static const value_string expert_group_vals[] = {
	{ PI_CHECKSUM,		"Checksum" },
	{ PI_SEQUENCE,		"Sequence" },
	{ PI_RESPONSE_CODE, "Response" },
	{ PI_UNDECODED,		"Undecoded" },
	{ PI_MALFORMED,		"Malformed" },
	{ PI_REASSEMBLE,	"Reassemble" },
/*	{ PI_SECURITY,		"Security" },*/
	{ 0, NULL }
};

typedef struct expert_tapdata_s {
	GtkWidget	*win;
	GtkWidget	*scrolled_window;
	GtkCList	*table;
	GtkWidget	*label;
	GList		*displayed_events;
	GList		*new_events;
	guint32		chat_events;
	guint32		note_events;
	guint32		warn_events;
	guint32		error_events;
} expert_tapdata_t;


/* the current warning severity */
/* XXX - make this a preference setting / a setting in the dialog */
int severity_report_level = PI_CHAT;
//int severity_report_level = PI_NOTE;


void expert_dlg_reset(void *tapdata)
{
	expert_tapdata_t * etd = tapdata;
	gchar *title;

	g_list_free(etd->displayed_events);
	etd->displayed_events = NULL;
	g_list_free(etd->new_events);
	etd->new_events = NULL;
	etd->chat_events = 0;
	etd->note_events = 0;
	etd->warn_events = 0;
	etd->error_events = 0;
	gtk_clist_clear(etd->table);
	gtk_clist_columns_autosize(etd->table);

	title = g_strdup_printf("Errors: %u Warnings: %u Notes: %u Chats: %u", 
		etd->error_events, etd->warn_events, etd->note_events, etd->chat_events);
	gtk_label_set_text(GTK_LABEL(etd->label), "Please wait ...");
	g_free(title);

	title = g_strdup_printf("Ethereal: %u Expert Infos", 
		g_list_length(etd->displayed_events));
	gtk_window_set_title(GTK_WINDOW(etd->win), title);
	g_free(title);
}

int expert_dlg_packet(void *tapdata, packet_info *pinfo, epan_dissect_t *edt, const void *pointer)
{
	expert_info_t	*ei = (expert_info_t *) pointer;
	expert_tapdata_t * etd = tapdata;


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

	if(ei->severity < severity_report_level) {
		return 0; /* draw not required */
	}

	etd->new_events = g_list_append(etd->new_events, ei);

	return 1; /* draw required */
}

void
expert_dlg_draw(void *data)
{
	expert_tapdata_t *etd = data;
	int row;
	char *strp;
	expert_info_t *ei;
	gchar *title;
	char *entries[5] = { "", "", "", "", "" };   /**< column entries */


	/*g_warning("draw start: displayed:%u new:%u", 
		g_list_length(etd->displayed_events), g_list_length(etd->new_events));*/

	title = g_strdup_printf("Errors: %u Warnings: %u Notes: %u Chats: %u", 
		etd->error_events, etd->warn_events, etd->note_events, etd->chat_events);
	gtk_label_set_text(GTK_LABEL(etd->label), title);
	g_free(title);

	gtk_clist_freeze(etd->table);

	/* append new events (remove from new list, append to displayed list and clist) */
	while(etd->new_events != NULL){
		ei = etd->new_events->data;

		etd->new_events = g_list_remove(etd->new_events, ei);
		etd->displayed_events = g_list_append(etd->displayed_events, ei);

		row=gtk_clist_append(etd->table, entries);
		gtk_clist_set_row_data(etd->table, row, ei);

		/* packet number */
		if(ei->packet_num) {
			strp=se_strdup_printf("%u", ei->packet_num);
			gtk_clist_set_text(etd->table, row, 0, strp);
		} else {
			gtk_clist_set_text(etd->table, row, 0, "-");
		}

		/* severity */
		strp=se_strdup(val_to_str(ei->severity, expert_severity_vals, "Unknown severity (%u)"));
		gtk_clist_set_text(etd->table, row, 1, strp);

		/* group */
		strp=se_strdup(val_to_str(ei->group, expert_group_vals, "Unknown group (%u)"));
		gtk_clist_set_text(etd->table, row, 2, strp);

		/* protocol */
		if(ei->protocol) {
			gtk_clist_set_text(etd->table, row, 3, ei->protocol);
		} else {
			gtk_clist_set_text(etd->table, row, 3, "-");
		}

		/* summary */
		gtk_clist_set_text(etd->table, row, 4, ei->summary);

		/*gtk_clist_set_pixmap(etd->table, row, 5, ascend_pm, ascend_bm);*/

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

	}

	gtk_clist_sort(etd->table);
	gtk_clist_columns_autosize(etd->table);
	gtk_clist_thaw(etd->table);

	title = g_strdup_printf("Ethereal: %u Expert Infos", 
		g_list_length(etd->displayed_events));
	gtk_window_set_title(GTK_WINDOW(etd->win), title);
	g_free(title);

	/*g_warning("draw end: displayed:%u", g_list_length(etd->displayed_events));*/
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
select_row_cb(GtkCList *clist, gint row, gint column, GdkEventButton *event, gpointer user_data)
{
	expert_info_t	*ei;


	ei = (expert_info_t *) gtk_clist_get_row_data(clist, row);

	cf_goto_frame(&cfile, ei->packet_num);
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
	SIGNAL_CONNECT(etd->table, "select-row", select_row_cb, etd);

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
//	gtk_clist_set_selection_mode(etd->table, GTK_SELECTION_SINGLE);
//    gtk_list_set_selection_mode(GTK_LIST(etd->table), GTK_SELECTION_BROWSE);
//    gtk_list_select_item(GTK_LIST(value_list), 0);
	gtk_container_add(GTK_CONTAINER(etd->scrolled_window), (GtkWidget *)etd->table);

	SIGNAL_CONNECT(etd->table, "click-column", srt_click_column_cb, col_arrows);

	gtk_widget_show(GTK_WIDGET(etd->table));
	gtk_widget_show(etd->scrolled_window);

	/* create popup menu for this table */
	/*if(etd->filter_string){
		srt_create_popup_menu(etd);
	}*/
}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);
static void
expert_dlg_destroy_cb(GtkWindow *win _U_, gpointer data)
{
	expert_tapdata_t *etd=(expert_tapdata_t *)data;

	protect_thread_critical_region();
	remove_tap_listener(etd);
	unprotect_thread_critical_region();

	//free_srt_table_data(&etd->afp_srt_table);
	g_free(etd);
}



static void
expert_dlg_init(const char *optarg)
{
	expert_tapdata_t * etd;
	const char *filter=NULL;
	GString *error_string;
	GtkWidget *vbox;
	GtkWidget *bbox;
	GtkWidget *close_bt;

	if(!strncmp(optarg,"afp,srt,",8)){
		filter=optarg+8;
	} else {
		filter=NULL;
	}

	proto_draw_colors_init();

	etd=g_malloc(sizeof(expert_tapdata_t));
	etd->displayed_events = NULL;
	etd->new_events = NULL;
	etd->chat_events = 0;
	etd->note_events = 0;
	etd->warn_events = 0;
	etd->error_events = 0;

	etd->win=window_new(GTK_WINDOW_TOPLEVEL, "Ethereal: Expert Info");
	gtk_window_set_default_size(GTK_WINDOW(etd->win), 650, 600);

	vbox=gtk_vbox_new(FALSE, 3);
	gtk_container_add(GTK_CONTAINER(etd->win), vbox);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 12);

	etd->label=gtk_label_new("Please wait ...");
	gtk_box_pack_start(GTK_BOX(vbox), etd->label, FALSE, FALSE, 0);

	/* We must display TOP LEVEL Widget before calling init_srt_table() */
	gtk_widget_show_all(etd->win);

	expert_dlg_init_table(etd, vbox);
	/*for(i=0;i<256;i++){
		init_srt_table_row(&etd->afp_srt_table, i, val_to_str(i, CommandCode_vals, "Unknown(%u)"));
	}*/

	error_string=register_tap_listener("expert", etd, NULL /* fstring */,
		expert_dlg_reset,
		expert_dlg_packet,
		expert_dlg_draw);
	if(error_string){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str);
		g_string_free(error_string, TRUE);
		g_free(etd);
		return;
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	close_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(etd->win, close_bt, window_cancel_button_cb);

	SIGNAL_CONNECT(etd->win, "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(etd->win, "destroy", expert_dlg_destroy_cb, etd);

	gtk_widget_show_all(etd->win);
	window_present(etd->win);
	
	cf_retap_packets(&cfile);
}


static void 
expert_dlg_cb(GtkWidget *w _U_, gpointer d _U_)
{
	expert_dlg_init("");
}




void
register_tap_listener_expert(void)
{
	register_stat_cmd_arg("expert", expert_dlg_init);

	register_stat_menu_item("_Expert Info", REGISTER_STAT_GROUP_GENERIC,
        expert_dlg_cb, NULL, NULL, NULL);
}
