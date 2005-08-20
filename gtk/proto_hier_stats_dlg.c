/* proto_hier_stats_dlg.c
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

#include <gtk/gtk.h>

#include "proto_hier_stats.h"
#include "dlg_utils.h"
#include "gui_utils.h"
#include "main.h"
#include "compat_macros.h"
#include "help_dlg.h"

#if GTK_MAJOR_VERSION < 2
#define NUM_STAT_COLUMNS 8
#else
enum {
    PROTOCOL_COLUMN,
    PRCT_PKTS_COLUMN,
    PKTS_COLUMN,
    BYTES_COLUMN,
    BANDWIDTH_COLUMN,
    END_PKTS_COLUMN,
    END_BYTES_COLUMN,
    END_BANDWIDTH_COLUMN,
    NUM_STAT_COLUMNS /* must be the last */
};
#endif

typedef struct {
#if GTK_MAJOR_VERSION < 2
	GtkCTree     *tree;
	GtkCTreeNode *parent;
#else
        GtkTreeView  *tree_view;
	GtkTreeIter  *iter;
#endif
	ph_stats_t   *ps;
} draw_info_t;


#define PCT(x,y) (100.0 * (float)(x) / (float)(y))
#define BANDWITDH(bytes,secs) ((bytes) * 8.0 / ((secs) * 1000.0 * 1000.0))

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
#if GTK_MAJOR_VERSION < 2
    GtkCTree        *tree = di->tree;
    GtkCTreeNode    *parent = di->parent;
    GtkCTreeNode    *new_node;
#else
    GtkTreeView     *tree_view = di->tree_view;
    GtkTreeIter     *iter = di->iter;
    GtkTreeStore    *store;
    GtkTreeIter      new_iter;
#endif

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

#if GTK_MAJOR_VERSION < 2
    new_node = gtk_ctree_insert_node(tree, parent, NULL, text,
                                     7, NULL, NULL, NULL, NULL,
                                     is_leaf, TRUE);
#else
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
                       -1);
#endif

    g_free(text[1]);
    g_free(text[2]);
    g_free(text[3]);
    if (seconds > 0.0) g_free(text[4]);
    g_free(text[5]);
    g_free(text[6]);
    if (seconds > 0.0) g_free(text[7]);

#if GTK_MAJOR_VERSION < 2
    child_di.tree = tree;
    child_di.parent = new_node;
#else
    child_di.tree_view = tree_view;
    child_di.iter = &new_iter;
#endif
    child_di.ps = ps;

    g_node_children_foreach(node, G_TRAVERSE_ALL,
                            fill_in_tree_node, &child_di);
}

static void
fill_in_tree(GtkWidget *tree, ph_stats_t *ps)
{
	draw_info_t	di;

#if GTK_MAJOR_VERSION < 2
	di.tree = GTK_CTREE(tree);
	di.parent = NULL;
#else
        di.tree_view = GTK_TREE_VIEW(tree);
	di.iter = NULL;
#endif
	di.ps = ps;

	g_node_children_foreach(ps->stats_tree, G_TRAVERSE_ALL,
                                fill_in_tree_node, &di);
}

#define MAX_DLG_HEIGHT 450
#define DEF_DLG_WIDTH  700
static void
create_tree(GtkWidget *container, ph_stats_t *ps)
{
    GtkWidget	*sw, *tree;
#if GTK_MAJOR_VERSION < 2
    int		i, height;
    gchar		*column_titles[NUM_STAT_COLUMNS] = {
        "Protocol",
        "% Packets",
        "Packets",
        "Bytes",
	"Mbit/s",
        "End Packets",
        "End Bytes",
	"End Mbit/s"
    };
#else
    GtkTreeView       *tree_view;
    GtkTreeStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
#endif

    /* Scrolled Window */
    sw = scrolled_window_new(NULL, NULL);
#if GTK_MAJOR_VERSION >= 2
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(sw), 
                                   GTK_SHADOW_IN);
#endif
    gtk_container_add(GTK_CONTAINER(container), sw);

#if GTK_MAJOR_VERSION < 2
    tree = ctree_new_with_titles(NUM_STAT_COLUMNS, 0, column_titles);

    /* XXX - get 'pos' to set vertical scroll-bar placement. */

    /* The title bars do nothing. */
    gtk_clist_column_titles_passive(GTK_CLIST(tree));

    /* Auto Resize all columns */
    for (i = 0; i < NUM_STAT_COLUMNS; i++) {
        gtk_clist_set_column_auto_resize(GTK_CLIST(tree), i, TRUE);
    }


    /* Right justify numeric columns */
    for (i = 1; i < NUM_STAT_COLUMNS; i++) {
        gtk_clist_set_column_justification(GTK_CLIST(tree), i,
                                           GTK_JUSTIFY_RIGHT);
    }
#else
    store = gtk_tree_store_new(NUM_STAT_COLUMNS, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_STRING, G_TYPE_STRING, 
			       G_TYPE_STRING);
    tree = tree_view_new(GTK_TREE_MODEL(store));
    tree_view = GTK_TREE_VIEW(tree);
    gtk_tree_view_set_headers_visible(tree_view, TRUE);
    gtk_tree_view_set_headers_clickable(tree_view, FALSE);
    renderer = gtk_cell_renderer_text_new();
    column = gtk_tree_view_column_new_with_attributes("Protocol", renderer,
                                                      "text", PROTOCOL_COLUMN,
                                                      NULL);
    gtk_tree_view_column_set_sizing(column, GTK_TREE_VIEW_COLUMN_AUTOSIZE);
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
#endif

    /* Fill in the data. */
    fill_in_tree(tree, ps);

#if GTK_MAJOR_VERSION < 2
    height = GTK_CLIST(tree)->rows * (GTK_CLIST(tree)->row_height + 5);
    height = MIN(height, MAX_DLG_HEIGHT);
    WIDGET_SET_SIZE(tree, DEF_DLG_WIDTH, height);
#else
    WIDGET_SET_SIZE(tree, DEF_DLG_WIDTH, MAX_DLG_HEIGHT);
    gtk_tree_view_expand_all(tree_view);
#endif

    gtk_container_add(GTK_CONTAINER(sw), tree);
}

static void
proto_hier_stats_cb(GtkWidget *w _U_, gpointer d _U_)
{
	ph_stats_t	*ps;
	GtkWidget	*dlg, *ok_bt, *help_bt, *vbox, *bbox;

	/* Get the statistics. */
	ps = ph_stats_new();
	if (ps == NULL) {
		/* The user gave up before we finished; don't pop up
		   a statistics window. */
		return;
	}

	dlg = window_new(GTK_WINDOW_TOPLEVEL, "Ethereal: Protocol Hierarchy Statistics");

	vbox = gtk_vbox_new(FALSE, 5);
	gtk_container_border_width(GTK_CONTAINER(vbox), 5);
	gtk_container_add(GTK_CONTAINER(dlg), vbox);

	/* Data section */
	create_tree(vbox, ps);

	ph_stats_free(ps);

	/* Button row. */
    if(topic_available(HELP_STATS_PROTO_HIERARCHY_DIALOG)) {
	    bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_HELP, NULL);
    } else {
	    bbox = dlg_button_row_new(GTK_STOCK_OK, NULL);
    }
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);
	gtk_widget_show(bbox);

	ok_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
    window_set_cancel_button(dlg, ok_bt, window_cancel_button_cb);

    if(topic_available(HELP_STATS_PROTO_HIERARCHY_DIALOG)) {
        help_bt = OBJECT_GET_DATA(bbox, GTK_STOCK_HELP);
        SIGNAL_CONNECT(help_bt, "clicked", topic_cb, HELP_STATS_PROTO_HIERARCHY_DIALOG);
    }

	SIGNAL_CONNECT(dlg, "delete_event", window_delete_event_cb, NULL);

	gtk_widget_show_all(dlg);
    window_present(dlg);
}

