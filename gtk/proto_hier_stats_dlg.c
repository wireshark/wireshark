/* proto_hier_stats_dlg.c
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

#include <gtk/gtk.h>

#include "proto_hier_stats.h"
#include "proto_hier_stats_dlg.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "find_dlg.h"
#include "color_dlg.h"
#include "gtkglobals.h"
#include "main.h"
#include "simple_dialog.h"
#include "help_dlg.h"

#define GTK_MENU_FUNC(a) ((GtkItemFactoryCallback)(a))

enum {
    PROTOCOL_COLUMN,
    PRCT_PKTS_COLUMN,
    PKTS_COLUMN,
    BYTES_COLUMN,
    BANDWIDTH_COLUMN,
    END_PKTS_COLUMN,
    END_BYTES_COLUMN,
    END_BANDWIDTH_COLUMN,
    FILTER_NAME,
    NUM_STAT_COLUMNS /* must be the last */
};

typedef struct {
        GtkTreeView  *tree_view;
	GtkTreeIter  *iter;
	ph_stats_t   *ps;
} draw_info_t;

static GtkWidget *tree;

#define PCT(x,y) (100.0 * (float)(x) / (float)(y))
#define BANDWITDH(bytes,secs) ((bytes) * 8.0 / ((secs) * 1000.0 * 1000.0))

/* Filter actions */
#define ACTION_MATCH		0
#define ACTION_PREPARE		1
#define ACTION_FIND_FRAME	2
#define ACTION_FIND_NEXT	3
#define ACTION_FIND_PREVIOUS	4
#define ACTION_COLORIZE		5

/* Action type - says what to do with the filter */
#define	ACTYPE_SELECTED		0
#define ACTYPE_NOT_SELECTED	1
#define ACTYPE_AND_SELECTED	2
#define ACTYPE_OR_SELECTED	3
#define ACTYPE_AND_NOT_SELECTED	4
#define ACTYPE_OR_NOT_SELECTED	5

/* Encoded callback arguments */
#define CALLBACK_MATCH(type)		((ACTION_MATCH<<8) | (type))
#define CALLBACK_PREPARE(type)		((ACTION_PREPARE<<8) | (type))
#define CALLBACK_FIND_FRAME(type)	((ACTION_FIND_FRAME<<8) | (type))
#define CALLBACK_FIND_NEXT(type)	((ACTION_FIND_NEXT<<8) | (type))
#define CALLBACK_FIND_PREVIOUS(type)	((ACTION_FIND_PREVIOUS<<8) | (type))
#define CALLBACK_COLORIZE(type)		((ACTION_COLORIZE<<8) | (type))

/* Extract components of callback argument */
#define FILTER_ACTION(cb_arg)		(((cb_arg)>>8) & 0xff)
#define FILTER_ACTYPE(cb_arg)		((cb_arg) & 0xff)

static void
proto_hier_select_filter_cb(GtkWidget *widget _U_, gpointer callback_data _U_, guint callback_action)
{
 	int action, type;
	char dirstr[128];
	char str[256];
	const char *current_filter;
	const char *filter = NULL;
	GtkTreeSelection *sel;
	GtkTreeModel *model;
	GtkTreeIter iter;

	action = FILTER_ACTION(callback_action);
	type = FILTER_ACTYPE(callback_action);
	
	sel = gtk_tree_view_get_selection (GTK_TREE_VIEW(tree));
	gtk_tree_selection_get_selected (sel, &model, &iter);
	gtk_tree_model_get (model, &iter, FILTER_NAME, &filter, -1);
	if (filter && 0 != strlen(filter)) {
	  g_snprintf(dirstr, 127, "%s", filter);
	} else {
	  simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "Could not acquire information to build a filter!\nTry expanding or choosing another item.");
	  return;
	}

	current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));
	switch(type){
	case ACTYPE_SELECTED:
		g_snprintf(str, 255, "%s", dirstr);
		break;
	case ACTYPE_NOT_SELECTED:
		g_snprintf(str, 255, "!(%s)", dirstr);
		break;
	case ACTYPE_AND_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			g_snprintf(str, 255, "%s", dirstr);
		else
			g_snprintf(str, 255, "(%s) && (%s)", current_filter, dirstr);
		break;
	case ACTYPE_OR_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			g_snprintf(str, 255, "%s", dirstr);
		else
			g_snprintf(str, 255, "(%s) || (%s)", current_filter, dirstr);
		break;
	case ACTYPE_AND_NOT_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			g_snprintf(str, 255, "!(%s)", dirstr);
		else
			g_snprintf(str, 255, "(%s) && !(%s)", current_filter, dirstr);
		break;
	case ACTYPE_OR_NOT_SELECTED:
		if ((!current_filter) || (0 == strlen(current_filter)))
			g_snprintf(str, 255, "!(%s)", dirstr);
		else
			g_snprintf(str, 255, "(%s) || !(%s)", current_filter, dirstr);
		break;
	}

	switch(action){
	case ACTION_MATCH:
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		main_filter_packets(&cfile, str, FALSE);
		gdk_window_raise(top_level->window);
		break;
	case ACTION_PREPARE:
		gtk_entry_set_text(GTK_ENTRY(main_display_filter_widget), str);
		break;
	case ACTION_FIND_FRAME:
		find_frame_with_filter(str);
		break;
	case ACTION_FIND_NEXT:
		find_previous_next_frame_with_filter(str, FALSE);
		break;
	case ACTION_FIND_PREVIOUS:
		find_previous_next_frame_with_filter(str, TRUE);
		break;
	case ACTION_COLORIZE:
		color_display_with_filter(str);
		break;
	}
}

static GtkItemFactoryEntry proto_hier_list_menu_items[] =
{
	/* Match */
	{"/Apply as Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Apply as Filter/Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_MATCH(ACTYPE_SELECTED), NULL, NULL,},
	{"/Apply as Filter/Not Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_MATCH(ACTYPE_NOT_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... and Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... or Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_MATCH(ACTYPE_AND_NOT_SELECTED), NULL, NULL,},
	{"/Apply as Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_MATCH(ACTYPE_OR_NOT_SELECTED), NULL, NULL,},

	/* Prepare */
	{"/Prepare a Filter", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Prepare a Filter/Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_PREPARE(ACTYPE_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/Not Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_PREPARE(ACTYPE_NOT_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... and Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... or Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... and not Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_PREPARE(ACTYPE_AND_NOT_SELECTED), NULL, NULL,},
	{"/Prepare a Filter/... or not Selected", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_PREPARE(ACTYPE_OR_NOT_SELECTED), NULL, NULL,},

	/* Find Frame */
	{"/Find Frame", NULL, NULL, 0, "<Branch>", NULL,},
	{"/Find Frame/Find Frame", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_FIND_FRAME(ACTYPE_SELECTED), NULL, NULL,},
	/* Find Next */
	{"/Find Frame/Find Next", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_FIND_NEXT(ACTYPE_SELECTED), NULL, NULL,},
	/* Find Previous */
	{"/Find Frame/Find Previous", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_FIND_PREVIOUS(ACTYPE_SELECTED), NULL, NULL,},
	/* Colorize Protocol */
	{"/Colorize Protocol", NULL,
		GTK_MENU_FUNC(proto_hier_select_filter_cb), CALLBACK_COLORIZE(ACTYPE_SELECTED), NULL, NULL,}

};

static void
fill_in_tree_node(GNode *node, gpointer data)
{
    ph_stats_node_t *stats = node->data;
    draw_info_t     *di = data;
    ph_stats_t      *ps = di->ps;
    gboolean        is_leaf;
    draw_info_t     child_di;
    double          seconds;
    gchar           *text[NUM_STAT_COLUMNS];
    GtkTreeView     *tree_view = di->tree_view;
    GtkTreeIter     *iter = di->iter;
    GtkTreeStore    *store;
    GtkTreeIter      new_iter;

    if (g_node_n_children(node) > 0) {
        is_leaf = FALSE;
    }
    else {
        is_leaf = TRUE;
    }

    seconds = ps->last_time - ps->first_time;

    text[0] = (gchar *) (stats->hfinfo->name);
    text[1] = g_strdup_printf("%6.2f%%",
                              PCT(stats->num_pkts_total, ps->tot_packets));
    text[2] = g_strdup_printf("%u", stats->num_pkts_total);
    text[3] = g_strdup_printf("%u", stats->num_bytes_total);
    if (seconds > 0.0) {
	text[4] = g_strdup_printf("%.3f", 
				  BANDWITDH(stats->num_bytes_total, seconds));
    } else {
	text[4] = "n.c.";
    }
    text[5] = g_strdup_printf("%u", stats->num_pkts_last);
    text[6] = g_strdup_printf("%u", stats->num_bytes_last);
    if (seconds > 0.0) {
	text[7] = g_strdup_printf("%.3f", 
				  BANDWITDH(stats->num_bytes_last, seconds));
    } else {
	text[7] = "n.c.";
    }

    store = GTK_TREE_STORE(gtk_tree_view_get_model(tree_view));
    gtk_tree_store_append(store, &new_iter, iter);
    gtk_tree_store_set(store, &new_iter,
                       PROTOCOL_COLUMN, text[0],
                       PRCT_PKTS_COLUMN, text[1],
                       PKTS_COLUMN, text[2],
                       BYTES_COLUMN, text[3],
		       BANDWIDTH_COLUMN, text[4],
                       END_PKTS_COLUMN, text[5],
                       END_BYTES_COLUMN, text[6],
		       END_BANDWIDTH_COLUMN, text[7],
		       FILTER_NAME, stats->hfinfo->abbrev,
                       -1);

    g_free(text[1]);
    g_free(text[2]);
    g_free(text[3]);
    if (seconds > 0.0) g_free(text[4]);
    g_free(text[5]);
    g_free(text[6]);
    if (seconds > 0.0) g_free(text[7]);

    child_di.tree_view = tree_view;
    child_di.iter = &new_iter;
    child_di.ps = ps;

    g_node_children_foreach(node, G_TRAVERSE_ALL,
                            fill_in_tree_node, &child_di);
}

static void
fill_in_tree(GtkWidget *tree, ph_stats_t *ps)
{
	draw_info_t	di;

        di.tree_view = GTK_TREE_VIEW(tree);
	di.iter = NULL;
	di.ps = ps;

	g_node_children_foreach(ps->stats_tree, G_TRAVERSE_ALL,
                                fill_in_tree_node, &di);
}

static GtkWidget *popup_menu_object;

static gint
proto_hier_show_popup_menu_cb(GtkWidget *widget _U_, GdkEvent *event, gpointer data _U_)
{
    GdkEventButton *bevent = (GdkEventButton *)event;

    if(event->type==GDK_BUTTON_PRESS && bevent->button==3){
        /* If this is a right click on one of our columns, popup the context menu */
	gtk_menu_popup(GTK_MENU(popup_menu_object), NULL, NULL, NULL, NULL,
		       bevent->button, bevent->time);
    }

    return FALSE;
}

static void
proto_hier_create_popup_menu(void)
{
    GtkItemFactory *item_factory;

    item_factory = gtk_item_factory_new(GTK_TYPE_MENU, "<main>", NULL);
    gtk_item_factory_create_items_ac(item_factory, sizeof(proto_hier_list_menu_items)/sizeof(proto_hier_list_menu_items[0]), proto_hier_list_menu_items, NULL, 2);
    popup_menu_object = gtk_item_factory_get_widget (item_factory, "<main>");
    g_signal_connect(tree, "button_press_event", G_CALLBACK(proto_hier_show_popup_menu_cb), NULL);
}

#define MAX_DLG_HEIGHT 450
#define DEF_DLG_WIDTH  700
static void
create_tree(GtkWidget *container, ph_stats_t *ps)
{
    GtkWidget	*sw;
    GtkTreeView       *tree_view;
    GtkTreeStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;

    /* Scrolled Window */
    sw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw), 
                                   GTK_SHADOW_IN);
    gtk_container_add(GTK_CONTAINER(container), sw);

    store = gtk_tree_store_new(NUM_STAT_COLUMNS, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, 
			       G_TYPE_STRING, G_TYPE_POINTER);
    tree = tree_view_new(GTK_TREE_MODEL(store));
    g_object_unref(G_OBJECT(store));
    tree_view = GTK_TREE_VIEW(tree);
    gtk_tree_view_set_headers_visible(tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(tree_view, FALSE);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Protocol", renderer,
                                                      "text", PROTOCOL_COLUMN,
                                                      NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
#if GTK_CHECK_VERSION(2,4,0)
    gtk_tree_view_column_set_expand(column, TRUE);
#endif
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("% Packets", renderer,
                                                      "text", PRCT_PKTS_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Packets", renderer,
                                                      "text", PKTS_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Bytes", renderer,
                                                      "text", BYTES_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Mbit/s", renderer,
                                                      "text", 
						      BANDWIDTH_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("End Packets",
                                                      renderer, "text",
                                                      END_PKTS_COLUMN, NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("End Bytes", renderer,
                                                      "text", END_BYTES_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("End Mbit/s", renderer,
                                                      "text", 
						      END_BANDWIDTH_COLUMN,
                                                      NULL);
    g_object_set(G_OBJECT(renderer), "xalign", 1.0, NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
    gtk_tree_view_append_column(tree_view, column);

    /* Fill in the data. */
    fill_in_tree(tree, ps);

    gtk_widget_set_size_request(tree, DEF_DLG_WIDTH, MAX_DLG_HEIGHT);
    gtk_tree_view_expand_all(tree_view);

    proto_hier_create_popup_menu ();

    gtk_container_add(GTK_CONTAINER(sw), tree);
}

void
proto_hier_stats_cb(GtkWidget *w _U_, gpointer d _U_)
{
	ph_stats_t	*ps;
	GtkWidget	*dlg, *close_bt, *help_bt, *vbox, *bbox;
	GtkWidget	*label;
	char		 title[256];
	const char      *current_filter;

	/* Get the statistics. */
	ps = ph_stats_new();
	if (ps == NULL) {
		/* The user gave up before we finished; don't pop up
		   a statistics window. */
		return;
	}

	dlg = window_new(GTK_WINDOW_TOPLEVEL, "Wireshark: Protocol Hierarchy Statistics");

	vbox = gtk_vbox_new(FALSE, 5);
	gtk_container_border_width(GTK_CONTAINER(vbox), 5);
	gtk_container_add(GTK_CONTAINER(dlg), vbox);

	current_filter=gtk_entry_get_text(GTK_ENTRY(main_display_filter_widget));

	if (current_filter && strlen(current_filter) != 0) {
		g_snprintf(title, 255, "Display filter: %s", current_filter);
	} else {
		g_snprintf(title, 255, "Display filter: none");
	}
	label = gtk_label_new(title);
	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);

	/* Data section */
	create_tree(vbox, ps);

	ph_stats_free(ps);

	/* Button row. */
	if(topic_available(HELP_STATS_PROTO_HIERARCHY_DIALOG)) {
		bbox = dlg_button_row_new(GTK_STOCK_CLOSE, GTK_STOCK_HELP, NULL);
	} else {
		bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	}
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	close_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(dlg, close_bt, window_cancel_button_cb);

	if(topic_available(HELP_STATS_PROTO_HIERARCHY_DIALOG)) {
                help_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_HELP);
		g_signal_connect(help_bt, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_STATS_PROTO_HIERARCHY_DIALOG);
	}

	g_signal_connect(dlg, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);

	gtk_widget_show_all(dlg);
	window_present(dlg);
}

