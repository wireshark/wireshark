/* stats_tree_stat.c
 * GTK Tap implementation of stats_tree
 * 2005, Luis E. G. Ontanon
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
#include "config.h"
#endif
#include <string.h>

#include <gtk/gtk.h>

#include <epan/stats_tree_priv.h>
#include <epan/report_err.h>

#include "../simple_dialog.h"
#include "../globals.h"
#include "../stat_menu.h"

#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/tap_param_dlg.h"
#include "gtk/main.h"

#include "gtk/old-gtk-compat.h"

struct _st_node_pres {
	GtkTreeIter*	iter;
};

struct _tree_cfg_pres {
	tap_param_dlg* stat_dlg;
};

struct _tree_pres {
	GString*	text;
	GtkWidget*	win;
	GtkTreeStore*   store;
	GtkWidget*	tree;
};

/* the columns of the tree pane */
enum _stat_tree_columns {
	TITLE_COLUMN,
	COUNT_COLUMN,
	RATE_COLUMN,
	PERCENT_COLUMN,
	N_COLUMNS
};

/* used for converting numbers */
#define NUM_BUF_SIZE  32

/* creates the gtk representation for a stat_node
 * node: the node
 */
static void
setup_gtk_node_pr(stat_node* node)
{
	GtkTreeIter* parent =  NULL;

	node->pr = g_malloc(sizeof(st_node_pres));

	if (node->st->pr->store) {
		node->pr->iter = g_malloc0(sizeof(GtkTreeIter));

		if ( node->parent && node->parent->pr ) {
			parent = node->parent->pr->iter;
		}
		gtk_tree_store_append (node->st->pr->store, node->pr->iter, parent);
		gtk_tree_store_set(node->st->pr->store, node->pr->iter,
				   TITLE_COLUMN, node->name, RATE_COLUMN, "", COUNT_COLUMN, "", -1);
	}
}


static void
draw_gtk_node(stat_node* node)
{
	static gchar value[NUM_BUF_SIZE];
	static gchar rate[NUM_BUF_SIZE];
	static gchar percent[NUM_BUF_SIZE];
	stat_node* child;

	stats_tree_get_strs_from_node(node, value, rate,
				      percent);

	if (node->st->pr->store && node->pr->iter) {
		gtk_tree_store_set(node->st->pr->store, node->pr->iter,
				   RATE_COLUMN, rate,
				   COUNT_COLUMN, value,
				   PERCENT_COLUMN, percent,
				   -1);
	}

	if (node->children) {
		for (child = node->children; child; child = child->next )
			draw_gtk_node(child);
	}
}

static void
draw_gtk_tree(void *psp)
{
	stats_tree *st = psp;
	stat_node* child;

	for (child = st->root.children; child; child = child->next ) {
		draw_gtk_node(child);

		if (child->pr->iter && st->pr->store) {
			gtk_tree_view_expand_row(GTK_TREE_VIEW(st->pr->tree),
						 gtk_tree_model_get_path(GTK_TREE_MODEL(st->pr->store),
									 child->pr->iter),
						 FALSE);
		}
	}

}

static void
free_gtk_tree(GtkWindow *win _U_, stats_tree *st)
{

	protect_thread_critical_region();
	remove_tap_listener(st);
	unprotect_thread_critical_region();

	if (st->root.pr)
		st->root.pr->iter = NULL;

	st->cfg->in_use = FALSE;
	stats_tree_free(st);

}

static void
clear_node_pr(stat_node* n)
{
	stat_node* c;
	for (c = n->children; c; c = c->next) {
		clear_node_pr(c);
	}

	if (n->pr->iter) {
		gtk_tree_store_remove(n->st->pr->store, n->pr->iter);
		n->pr->iter = NULL;
	}
}

static void
reset_tap(void* p)
{
	stats_tree* st = p;
	stat_node* c;
	for (c = st->root.children; c; c = c->next) {
		clear_node_pr(c);
	}

	st->cfg->init(st);
}

/* initializes the stats_tree window */
static void
init_gtk_tree(const char* optarg, void *userdata _U_)
{
	gchar *abbr = stats_tree_get_abbr(optarg);
	stats_tree* st = NULL;
	stats_tree_cfg* cfg = NULL;
	tree_pres* pr = g_malloc(sizeof(tree_pres));
	gchar* title = NULL;
	gchar* window_name = NULL;
	GString* error_string;
	GtkWidget *scr_win;
	size_t init_strlen;
	GtkWidget *main_vb, *bbox, *bt_close;
	GtkTreeViewColumn* column;
	GtkCellRenderer* renderer;

	if (abbr) {
		cfg = stats_tree_get_cfg_by_abbr(abbr);

		if (cfg && cfg->in_use) {
			/* XXX: ! */
			report_failure("cannot open more than one tree of the same type at once");
			return;
		}

		if (cfg != NULL) {
			init_strlen = strlen(cfg->pr->stat_dlg->init_string);

			if (strncmp (optarg, cfg->pr->stat_dlg->init_string, init_strlen) == 0){
				if (init_strlen == strlen(optarg)) {
					st = stats_tree_new(cfg,pr,NULL);
				} else {
					st = stats_tree_new(cfg,pr,(char*)optarg+init_strlen+1);
				}

			} else {
				st = stats_tree_new(cfg,pr,NULL);
			}
		} else {
			report_failure("no such stats_tree (%s) in stats_tree registry",abbr);
			g_free(abbr);
			return;
		}
		g_free(abbr);

	} else {
		report_failure("could not obtain stats_tree abbr from optarg");
		g_free(pr);
		return;
	}

	cfg->in_use = TRUE;

	window_name = g_strdup_printf("%s Stats Tree", cfg->name);

	st->pr->win = window_new_with_geom(GTK_WINDOW_TOPLEVEL,window_name,window_name);
	gtk_window_set_default_size(GTK_WINDOW(st->pr->win), 400, 400);
	g_free(window_name);

	if(st->filter){
		title=g_strdup_printf("%s with filter: %s",cfg->name,st->filter);
	} else {
		st->filter=NULL;
		title=g_strdup_printf("%s", cfg->name);
	}

	gtk_window_set_title(GTK_WINDOW(st->pr->win), title);
	g_free(title);

	main_vb = gtk_vbox_new(FALSE, 3);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 12);
	gtk_container_add(GTK_CONTAINER(st->pr->win), main_vb);

	scr_win = scrolled_window_new(NULL, NULL);

	st->pr->store = gtk_tree_store_new (N_COLUMNS, G_TYPE_STRING, G_TYPE_STRING,
					    G_TYPE_STRING, G_TYPE_STRING);

	st->pr->tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (st->pr->store));
	g_object_unref(G_OBJECT(st->pr->store));

	gtk_container_add( GTK_CONTAINER(scr_win), st->pr->tree);

	/* the columns */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Topic / Item", renderer,
							   "text", TITLE_COLUMN,
							   NULL);
	gtk_tree_view_column_set_resizable (column,TRUE);
	gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (st->pr->tree), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Count", renderer,
							   "text", COUNT_COLUMN,
							   NULL);

	gtk_tree_view_column_set_resizable (column,TRUE);
	gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (st->pr->tree), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Rate (ms)", renderer,
							   "text", RATE_COLUMN,
							   NULL);
	gtk_tree_view_column_set_resizable (column,TRUE);
	gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (st->pr->tree), column);

	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("Percent", renderer,
							   "text", PERCENT_COLUMN,
							   NULL);
	gtk_tree_view_column_set_resizable(column,TRUE);
	gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (st->pr->tree), column);

	gtk_container_add( GTK_CONTAINER(main_vb), scr_win);

	error_string = register_tap_listener( cfg->tapname,
					      st,
					      st->filter,
					      cfg->flags,
					      reset_tap,
					      stats_tree_packet,
					      draw_gtk_tree);

	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		/* destroy_stat_tree_window(st); */
		report_failure("stats_tree for: %s failed to attach to the tap: %s",cfg->name,error_string->str);
		g_string_free(error_string, TRUE);
	}

	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

	bt_close = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CLOSE);
	window_set_cancel_button(st->pr->win, bt_close, window_cancel_button_cb);

	g_signal_connect(GTK_WINDOW(st->pr->win), "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
	g_signal_connect(GTK_WINDOW(st->pr->win), "destroy", G_CALLBACK(free_gtk_tree), st);

	gtk_widget_show_all(st->pr->win);
	window_present(st->pr->win);

	cf_retap_packets(&cfile);
	gdk_window_raise(gtk_widget_get_window(st->pr->win));
}

static tap_param tree_stat_params[] = {
	{ PARAM_FILTER, "Filter", NULL }
};

static void
register_gtk_stats_tree_tap (gpointer k _U_, gpointer v, gpointer p _U_)
{
	stats_tree_cfg* cfg = v;

	cfg->pr = g_malloc(sizeof(tree_pres));

	cfg->pr->stat_dlg = g_malloc(sizeof(tap_param_dlg));

	cfg->pr->stat_dlg->win_title = g_strdup_printf("%s Stats Tree",cfg->name);
	cfg->pr->stat_dlg->init_string = g_strdup_printf("%s,tree",cfg->abbr);
	cfg->pr->stat_dlg->tap_init_cb = init_gtk_tree;
	cfg->pr->stat_dlg->index = -1;
	cfg->pr->stat_dlg->nparams = G_N_ELEMENTS(tree_stat_params);
	cfg->pr->stat_dlg->params = tree_stat_params;

	register_dfilter_stat(cfg->pr->stat_dlg, cfg->name, cfg->stat_group);
}

static void
free_tree_presentation(stats_tree* st)
{
	g_free(st->pr);
}

void
register_tap_listener_stats_tree_stat(void)
{

	stats_tree_presentation(register_gtk_stats_tree_tap,
				setup_gtk_node_pr,
				NULL,
				NULL,
				NULL,
				NULL,
				free_tree_presentation,
				NULL,
				NULL,
				NULL);
}
