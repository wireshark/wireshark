/* proto_hier_stats_dlg.c
 *
 * $Id: proto_hier_stats_dlg.c,v 1.13 2004/01/10 16:27:42 ulfl Exp $
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
#include "ui_util.h"
#include "main.h"
#include "compat_macros.h"

#if GTK_MAJOR_VERSION < 2
#define NUM_STAT_COLUMNS 6
#else
enum {
    PROTOCOL_COLUMN,
    PRCT_PKTS_COLUMN,
    PKTS_COLUMN,
    BYTES_COLUMN,
    END_PKTS_COLUMN,
    END_BYTES_COLUMN,
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

static void
fill_in_tree_node(GNode *node, gpointer data)
{
    ph_stats_node_t *stats = node->data;
    draw_info_t     *di = data;

#if GTK_MAJOR_VERSION < 2
    GtkCTree        *tree = di->tree;
    GtkCTreeNode    *parent = di->parent;
    gchar           *text[NUM_STAT_COLUMNS];
    GtkCTreeNode    *new_node;
#else
    GtkTreeView     *tree_view = di->tree_view;
    GtkTreeIter     *iter = di->iter;
    GtkTreeStore    *store;
    gchar           *text[2];
    GtkTreeIter      new_iter;
#endif
    ph_stats_t      *ps = di->ps;

    gboolean         is_leaf;

    draw_info_t      child_di;

    if (g_node_n_children(node) > 0) {
        is_leaf = FALSE;
    }
    else {
        is_leaf = TRUE;
    }

    text[0] = stats->hfinfo->name;
    text[1] = g_strdup_printf("%6.2f%%",
                              PCT(stats->num_pkts_total, ps->tot_packets));
#if GTK_MAJOR_VERSION < 2
    text[2] = g_strdup_printf("%u", stats->num_pkts_total);
    text[3] = g_strdup_printf("%u", stats->num_bytes_total);
    text[4] = g_strdup_printf("%u", stats->num_pkts_last);
    text[5] = g_strdup_printf("%u", stats->num_bytes_last);

    new_node = gtk_ctree_insert_node(tree, parent, NULL, text,
                                     5, NULL, NULL, NULL, NULL,
                                     is_leaf, TRUE);
#else
    store = GTK_TREE_STORE(gtk_tree_view_get_model(tree_view));
    gtk_tree_store_append(store, &new_iter, iter);
    gtk_tree_store_set(store, &new_iter,
                       PROTOCOL_COLUMN, text[0],
                       PRCT_PKTS_COLUMN, text[1],
                       PKTS_COLUMN, stats->num_pkts_total,
                       BYTES_COLUMN, stats->num_bytes_total,
                       END_PKTS_COLUMN, stats->num_pkts_last,
                       END_BYTES_COLUMN, stats->num_bytes_last,
                       -1);
#endif

    g_free(text[1]);
#if GTK_MAJOR_VERSION < 2
    g_free(text[2]);
    g_free(text[3]);
    g_free(text[4]);
    g_free(text[5]);

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
#define DEF_DLG_WIDTH  600
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
        "End Packets",
        "End Bytes",
    };
#else
    GtkTreeView       *tree_view;
    GtkTreeStore      *store;
    GtkCellRenderer   *renderer;
    GtkTreeViewColumn *column;
#endif

    /* Scrolled Window */
    sw = gtk_scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
                                   GTK_POLICY_AUTOMATIC,
                                   GTK_POLICY_AUTOMATIC);
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
    for (i = 1; i <= 5; i++) {
        gtk_clist_set_column_justification(GTK_CLIST(tree), i,
                                           GTK_JUSTIFY_RIGHT);
    }
#else
    store = gtk_tree_store_new(NUM_STAT_COLUMNS, G_TYPE_STRING,
                               G_TYPE_STRING, G_TYPE_UINT, G_TYPE_UINT,
                               G_TYPE_UINT, G_TYPE_UINT);
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
#endif

    /* Fill in the data. */
    fill_in_tree(tree, ps);

#if GTK_MAJOR_VERSION < 2
    height = GTK_CLIST(tree)->rows * (GTK_CLIST(tree)->row_height + 5);
    height = MIN(height, MAX_DLG_HEIGHT);
    WIDGET_SET_SIZE(tree, DEF_DLG_WIDTH, height);
#else
    WIDGET_SET_SIZE(tree, DEF_DLG_WIDTH, MAX_DLG_HEIGHT);
#endif

    gtk_container_add(GTK_CONTAINER(sw), tree);
    ph_stats_free(ps);
}

#define WNAME "Protocol Hierarchy Statistics"

void
proto_hier_stats_cb(GtkWidget *w _U_, gpointer d _U_)
{
	ph_stats_t	*ps;
	GtkWidget	*dlg, *bt, *vbox, *frame, *bbox;

	/* Get the statistics. */
	ps = ph_stats_new();
	if (ps == NULL) {
		/* The user gave up before we finished; don't pop up
		   a statistics window. */
		return;
	}

	dlg = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_title(GTK_WINDOW(dlg), "Ethereal: " WNAME);
	SIGNAL_CONNECT(dlg, "realize", window_icon_realize_cb, NULL);

	vbox = gtk_vbox_new(FALSE, 5);
	gtk_container_border_width(GTK_CONTAINER(vbox), 5);
	gtk_container_add(GTK_CONTAINER(dlg), vbox);

	frame = gtk_frame_new(WNAME);
	/*gtk_container_add(GTK_CONTAINER(vbox), frame);*/
	gtk_box_pack_start(GTK_BOX(vbox), frame, TRUE, TRUE, 0);


	/* Data section */
	create_tree(frame, ps);

	/* Button row. We put it in an HButtonBox to
	 * keep it from expanding to the width of the window. */
	bbox = gtk_hbutton_box_new();
	gtk_button_box_set_spacing(GTK_BUTTON_BOX(bbox), 5);
	/*gtk_container_add(GTK_CONTAINER(vbox), bbox);*/
	gtk_box_pack_start(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	/* Close button */
    bt = BUTTON_NEW_FROM_STOCK(GTK_STOCK_CLOSE);
	SIGNAL_CONNECT_OBJECT(bt, "clicked", gtk_widget_destroy, dlg);
	gtk_container_add(GTK_CONTAINER(bbox), bt);
	GTK_WIDGET_SET_FLAGS(bt, GTK_CAN_DEFAULT);
	gtk_widget_grab_default(bt);
	dlg_set_cancel(dlg, bt);

	gtk_widget_show_all(dlg);

}

