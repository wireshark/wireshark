/* proto_hier_stats_dlg.c
 *
 * $Id: proto_hier_stats_dlg.c,v 1.3 2001/03/26 03:02:57 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include "main.h"

#define NUM_STAT_COLUMNS 6

typedef struct {

	GtkCTree	*tree;
	GtkCTreeNode	*parent;
	ph_stats_t	*ps;

} draw_info_t;


#define PCT(x,y) (100.0 * (float)(x) / (float)(y))

static void
fill_in_ctree_node(GNode *node, gpointer data)
{
	ph_stats_node_t	*stats = node->data;
	draw_info_t		*di = data;

	GtkCTree		*tree = di->tree;
	GtkCTreeNode		*parent = di->parent;
	ph_stats_t		*ps = di->ps;

	gchar			*text[NUM_STAT_COLUMNS];
	gboolean		is_leaf;
	GtkCTreeNode		*new_node;

	draw_info_t		child_di;

	if (g_node_n_children(node) > 0) {
		is_leaf = FALSE;
	}
	else {
		is_leaf = TRUE;
	}

	text[0] = stats->hfinfo->name;
	text[1] = g_strdup_printf("%6.2f%%",
			PCT(stats->num_pkts_total, ps->tot_packets));
	text[2] = g_strdup_printf("%u", stats->num_pkts_total);
	text[3] = g_strdup_printf("%u", stats->num_bytes_total);
	text[4] = g_strdup_printf("%u", stats->num_pkts_last);
	text[5] = g_strdup_printf("%u", stats->num_bytes_last);

	new_node = gtk_ctree_insert_node(tree, parent, NULL, text,
			5, NULL, NULL, NULL, NULL,
			is_leaf, TRUE);


	g_free(text[1]);
	g_free(text[2]);
	g_free(text[3]);
	g_free(text[4]);
	g_free(text[5]);

	child_di.tree = tree;
	child_di.parent = new_node;
	child_di.ps = ps;

	g_node_children_foreach(node, G_TRAVERSE_ALL,
			fill_in_ctree_node, &child_di);

}



static void
fill_in_ctree(GtkWidget *tree, ph_stats_t *ps)
{
	draw_info_t	di;

	di.tree = GTK_CTREE(tree);
	di.parent = NULL;
	di.ps = ps;

	g_node_children_foreach(ps->stats_tree, G_TRAVERSE_ALL,
			fill_in_ctree_node, &di);
}

static void
create_tree(GtkWidget *container, ph_stats_t *ps)
{
	GtkWidget	*sw, *tree;
	int		i, height;
	gchar		*column_titles[NUM_STAT_COLUMNS] = {
		"Protocol",
		"Percentage Packets",
		"Packets",
		"Bytes",
		"Last-Protocol Packets",
		"Last-Protocol Bytes",
	};

	/* Scrolled Window */
	sw = gtk_scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(sw),
			GTK_POLICY_AUTOMATIC,
			GTK_POLICY_AUTOMATIC);
	gtk_container_add(GTK_CONTAINER(container), sw);

	tree = gtk_ctree_new_with_titles(NUM_STAT_COLUMNS, 0, column_titles);

	/* XXX - get 'pos' to set vertical scroll-bar placement. */
	/* XXX - set line style from preferences ???. */

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

	/* Fill in the data. */
	fill_in_ctree(tree, ps);

	/* Try to size the CTree to a good initial size.
	 * 5 is a magic number that I pulled out off my hat.
	 * Using DEF_WIDTH is pretty bogus, too. */
	height = GTK_CLIST(tree)->rows * (GTK_CLIST(tree)->row_height + 5);
	gtk_widget_set_usize(tree, DEF_WIDTH, height);


	gtk_container_add(GTK_CONTAINER(sw), tree);
	ph_stats_free(ps);
}

#define WNAME "Protocol Hierarchy Statistics"

void
proto_hier_stats_cb(GtkWidget *w, gpointer d)
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
	bt = gtk_button_new_with_label("Close");
	gtk_signal_connect_object(GTK_OBJECT(bt), "clicked",
			GTK_SIGNAL_FUNC(gtk_widget_destroy),
			GTK_OBJECT(dlg));
	gtk_container_add(GTK_CONTAINER(bbox), bt);
	GTK_WIDGET_SET_FLAGS(bt, GTK_CAN_DEFAULT);
	gtk_widget_grab_default(bt);
	dlg_set_cancel(dlg, bt);

	gtk_widget_show_all(dlg);

}

