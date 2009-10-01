/* service_response_time_table.c
 * service_response_time_table   2003 Ronnie Sahlberg
 * Helper routines common to all service response time statistics
 * tap.
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

#include <gtk/gtk.h>

#include "epan/packet_info.h"

#include "../simple_dialog.h"
#include "../globals.h"

#include "gtk/service_response_time_table.h"
#include "gtk/filter_utils.h"
#include "gtk/gui_utils.h"

enum
{
   INDEX_COLUMN,
   PROCEDURE_COLUMN,
   CALLS_COLUMN,
   MIN_SRT_COLUMN,
   MAX_SRT_COLUMN,
   AVG_SRT_COLUMN,
   N_COLUMNS
};


static void
srt_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data, guint callback_action)
{
	srt_stat_table *rst = (srt_stat_table *)callback_data;
	char *str = NULL;
	GtkTreeIter iter;
	GtkTreeModel *model;
	GtkTreeSelection  *sel;
	int selection;

	if(rst->filter_string==NULL){
		return;
	}

	sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(rst->table));

	if (!gtk_tree_selection_get_selected(sel, &model, &iter))
		return;

	gtk_tree_model_get (model, &iter, INDEX_COLUMN, &selection, -1);
	if(selection>=(int)rst->num_procs){
		simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "No procedure selected");
		return;
	}

	str = g_strdup_printf("%s==%d", rst->filter_string, selection);

	apply_selected_filter (callback_action, str);

	g_free(str);
}

static gint
srt_show_popup_menu_cb(void *widg _U_, GdkEvent *event, srt_stat_table *rst)
{
	GdkEventButton *bevent = (GdkEventButton *)event;

	if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
		gtk_menu_popup(GTK_MENU(rst->menu), NULL, NULL, NULL, NULL, 
			bevent->button, bevent->time);
	}

	return FALSE;
}

static GtkItemFactoryEntry srt_list_menu_items[] =
{
	/* Match */
	{"/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/... not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/.. and Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/... or Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED, 0), NULL, NULL,},
	{"/Apply as Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED, 0), NULL, NULL,},

	/* Prepare */
	{"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/Not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/... and Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/... or Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED, 0), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED, 0), NULL, NULL,},

	/* Find Frame */
	{"/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame/Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED, 0), NULL, NULL,},
	{"/Find Frame/Find Frame/Not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_NOT_SELECTED, 0), NULL, NULL,},
	/* Find Next */
	{"/Find Frame/Find Next", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Next/Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED, 0), NULL, NULL,},
	{"/Find Frame/Find Next/Not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_NOT_SELECTED, 0), NULL, NULL,},

	/* Find Previous */
	{"/Find Frame/Find Previous", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Previous/Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED, 0), NULL, NULL,},
	{"/Find Frame/Find Previous/Not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_NOT_SELECTED, 0), NULL, NULL,},

	/* Colorize Procedure */
	{"/Colorize Procedure", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Colorize Procedure/Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED, 0), NULL, NULL,},
	{"/Colorize Procedure/Not Selected", NULL,
		GTK_MENU_FUNC(srt_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_NOT_SELECTED, 0), NULL, NULL,}

};

static void
srt_create_popup_menu(srt_stat_table *rst)
{
	GtkItemFactory *item_factory;

	item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);

	gtk_item_factory_create_items_ac(item_factory, sizeof(srt_list_menu_items)/sizeof(srt_list_menu_items[0]), srt_list_menu_items, rst, 2);

	rst->menu = gtk_item_factory_get_widget(item_factory, "<main>");
	g_signal_connect(rst->table, "button_press_event", G_CALLBACK(srt_show_popup_menu_cb), rst);
}

/*
    XXX Resizable columns are ugly when there's more than on table cf. SMB
*/
void
init_srt_table(srt_stat_table *rst, int num_procs, GtkWidget *vbox, const char *filter_string)
{
	int i;
	GtkListStore *store;
	GtkWidget *tree;
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	GtkTreeSortable *sortable;
	GtkTreeSelection  *sel;

	const char *default_titles[] = { "Index", "Procedure", "Calls", "Min SRT", "Max SRT", "Avg SRT" };

	/* Create the store */
	store = gtk_list_store_new (N_COLUMNS,  /* Total number of columns */
                               G_TYPE_INT,   	/* Index     */
                               G_TYPE_STRING,   /* Procedure */
                               G_TYPE_INT,   	/* Calls     */
                               G_TYPE_STRING,   /* Min SRT   */
                               G_TYPE_STRING,   /* Max SRT   */
                               G_TYPE_STRING);  /* Avg SRT   */

      /* Create a view */
    tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (store));
    rst->table = GTK_TREE_VIEW(tree);
    sortable = GTK_TREE_SORTABLE(store);

    /* The view now holds a reference.  We can get rid of our own reference */
	g_object_unref (G_OBJECT (store));

	if(filter_string){
		rst->filter_string=g_strdup(filter_string);
	} else {
		rst->filter_string=NULL;
	}
	for (i = 0; i < N_COLUMNS; i++) {
		renderer = gtk_cell_renderer_text_new ();
		if (i != PROCEDURE_COLUMN) {
			/* right align numbers */
			g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
		}
		g_object_set(renderer, "ypad", 0, NULL);
		column = gtk_tree_view_column_new_with_attributes (default_titles[i], renderer, "text", 
				i, NULL);
				
		gtk_tree_view_column_set_sort_column_id(column, i);
		gtk_tree_view_column_set_resizable(column, TRUE);
		gtk_tree_view_append_column (rst->table, column);
		if (i == CALLS_COLUMN) {
			/* XXX revert order sort */
			gtk_tree_view_column_clicked(column);
			gtk_tree_view_column_clicked(column);
		}
	}

	rst->scrolled_window=scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(rst->scrolled_window),
					    GTK_SHADOW_IN);
	gtk_container_add(GTK_CONTAINER(rst->scrolled_window), GTK_WIDGET (rst->table));
	gtk_box_pack_start(GTK_BOX(vbox), rst->scrolled_window, TRUE, TRUE, 0);

    gtk_tree_view_set_reorderable (rst->table, FALSE);   
	/* Now enable the sorting of each column */
	gtk_tree_view_set_rules_hint(rst->table, TRUE);
	gtk_tree_view_set_headers_clickable(rst->table, TRUE);

	gtk_widget_show(rst->scrolled_window);

	rst->num_procs=num_procs;
	rst->procedures=g_malloc(sizeof(srt_procedure_t)*num_procs);
	for(i=0;i<num_procs;i++){
		time_stat_init(&rst->procedures[i].stats);
		rst->procedures[i].index = 0;
		rst->procedures[i].procedure = NULL;
	}

	sel = gtk_tree_view_get_selection(GTK_TREE_VIEW(rst->table));
	gtk_tree_selection_set_mode(sel, GTK_SELECTION_SINGLE);
	/* create popup menu for this table */
	if(rst->filter_string){
		srt_create_popup_menu(rst);
	}
}

void
init_srt_table_row(srt_stat_table *rst, int index, const char *procedure)
{
	/* we have discovered a new procedure. Extend the table accordingly */
	if(index>=rst->num_procs){
		int old_num_procs=rst->num_procs;
		int i;

		rst->num_procs=index+1;
		rst->procedures=g_realloc(rst->procedures, sizeof(srt_procedure_t)*(rst->num_procs));
		for(i=old_num_procs;i<rst->num_procs;i++){
			time_stat_init(&rst->procedures[i].stats);
			rst->procedures[i].index = i;
			rst->procedures[i].procedure=NULL;
		}
	}
	rst->procedures[index].index = index;
	rst->procedures[index].procedure=g_strdup(procedure);
}

void
add_srt_table_data(srt_stat_table *rst, int index, const nstime_t *req_time, packet_info *pinfo)
{
	srt_procedure_t *rp;
	nstime_t t, delta;

	g_assert(index >= 0 && index < rst->num_procs);
	rp=&rst->procedures[index];

	/*
	 * If the count of calls for this procedure is currently zero, it's
	 * going to become non-zero, so add a row for it (we don't want
	 * rows for procedures that have no calls - especially if the
	 * procedure has no calls because the index doesn't correspond
	 * to a procedure, but is an unused/reserved value).
	 *
	 * (Yes, this means that the rows aren't in order by anything
	 * interesting.  That's why we have the table sorted by a column.)
	 */

	if (rp->stats.num==0){
		GtkListStore *store = GTK_LIST_STORE(gtk_tree_view_get_model(rst->table));
		gtk_list_store_append(store, &rp->iter);
		gtk_list_store_set(store, &rp->iter,
				   INDEX_COLUMN,     rp->index,
				   PROCEDURE_COLUMN, rp->procedure,
				   CALLS_COLUMN,     rp->stats.num,
				   MIN_SRT_COLUMN,   "",
				   MAX_SRT_COLUMN,   "",
				   AVG_SRT_COLUMN,   "",
				   -1);
	}

	/* calculate time delta between request and reply */
	t=pinfo->fd->abs_ts;
	nstime_delta(&delta, &t, req_time);

	time_stat_update(&rp->stats, &delta, pinfo);
}

void
draw_srt_table_data(srt_stat_table *rst)
{
	int i;
	guint64 td;
	char *min, *max, *avg;
	GtkListStore *store = GTK_LIST_STORE(gtk_tree_view_get_model(rst->table));

	for(i=0;i<rst->num_procs;i++){
		/* ignore procedures with no calls (they don't have rows) */
		if(rst->procedures[i].stats.num==0){
			continue;
		}

		/* scale it to units of 10us.*/
		/* for long captures with a large tot time, this can overflow on 32bit */
		td=(int)rst->procedures[i].stats.tot.secs;
		td=td*100000+(int)rst->procedures[i].stats.tot.nsecs/10000;
		td/=rst->procedures[i].stats.num;

		min=g_strdup_printf("%3d.%05d",
		    (int)rst->procedures[i].stats.min.secs,
		    rst->procedures[i].stats.min.nsecs/10000);

		max=g_strdup_printf("%3d.%05d",
		    (int)rst->procedures[i].stats.max.secs,
		    rst->procedures[i].stats.max.nsecs/10000);
		avg=g_strdup_printf("%3" G_GINT64_MODIFIER "d.%05" G_GINT64_MODIFIER "d",
 		    td/100000, td%100000);
		    
		gtk_list_store_set(store, &rst->procedures[i].iter,
				   CALLS_COLUMN,     rst->procedures[i].stats.num,
				   MIN_SRT_COLUMN,   min,
				   MAX_SRT_COLUMN,   max,
				   AVG_SRT_COLUMN,   avg,
				   -1);
		g_free(min);
		g_free(max);
		g_free(avg);
	}
}


void
reset_srt_table_data(srt_stat_table *rst)
{
	int i;
	GtkListStore *store;

	for(i=0;i<rst->num_procs;i++){
		time_stat_init(&rst->procedures[i].stats);
	}
	store = GTK_LIST_STORE(gtk_tree_view_get_model(rst->table));
	gtk_list_store_clear(store);
}

void
free_srt_table_data(srt_stat_table *rst)
{
	int i;

	for(i=0;i<rst->num_procs;i++){
		g_free(rst->procedures[i].procedure);
		rst->procedures[i].procedure=NULL;
	}
	g_free(rst->filter_string);
	rst->filter_string=NULL;
	g_free(rst->procedures);
	rst->procedures=NULL;
	rst->num_procs=0;
}

