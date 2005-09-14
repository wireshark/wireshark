/* stats_tree_stat.c
 * GTK Tap implementation of stats_tree
 * 2005, Luis E. G. Ontanon
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
#include "config.h"
#endif

#include <string.h>
#include <gtk/gtk.h>

#include <epan/stats_tree_priv.h>
#include <epan/report_err.h>

#include "simple_dialog.h"
#include "globals.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#include "../stat_menu.h"
#include "../tap_dfilter_dlg.h"

struct _st_node_pres {
#if GTK_MAJOR_VERSION >= 2
	GtkTreeIter*	iter;
#else
	GtkCTreeNode*	node;
#endif
};

struct _tree_cfg_pres {
	tap_dfilter_dlg* stat_dlg;
};

struct _tree_pres {
	GString*	text;
	GtkWidget*	win;

#if GTK_MAJOR_VERSION >= 2
	GtkTreeStore*   store;
	GtkWidget*	tree;
#else
	GtkWidget*	ctree;
#endif
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
static void setup_gtk_node_pr(stat_node* node) {
#if GTK_MAJOR_VERSION >= 2
	GtkTreeIter* parent =  NULL;
#else
	GtkCTreeNode* parent = NULL;
	static gchar *text[] = {
		NULL,
		"",
		"",
		""
	};
#endif
	

	node->pr = g_malloc(sizeof(st_node_pres));

#if GTK_MAJOR_VERSION >= 2
	if (node->st->pr->store) {
		node->pr->iter = g_malloc0(sizeof(GtkTreeIter));

		if ( node->parent && node->parent->pr ) {
			parent = node->parent->pr->iter;
		}
		gtk_tree_store_append (node->st->pr->store, node->pr->iter, parent);
		gtk_tree_store_set(node->st->pr->store, node->pr->iter, TITLE_COLUMN, node->name, RATE_COLUMN, "", COUNT_COLUMN, "", -1);
	}
#else
	if (node->st->pr->ctree) {
		if ( node->parent && node->parent->pr ) {
			parent = node->parent->pr->node;
		}

		text[0] = node->name;
		node->pr->node = gtk_ctree_insert_node(GTK_CTREE(node->st->pr->ctree),
		    parent, NULL, text, 0, NULL, NULL, NULL, NULL, FALSE, FALSE);
		if (!parent) {
			/* Force the children of the root node to be expanded. */
			gtk_ctree_expand(GTK_CTREE(node->st->pr->ctree),
			    node->pr->node);
		}
	}
#endif
}


static void draw_gtk_node(stat_node* node) {
	static gchar value[NUM_BUF_SIZE];
	static gchar rate[NUM_BUF_SIZE];
	static gchar percent[NUM_BUF_SIZE];
	stat_node* child;
	
	stats_tree_get_strs_from_node(node, value, rate, percent);
	
#if GTK_MAJOR_VERSION >= 2
	if (node->st->pr->store) {
		gtk_tree_store_set(node->st->pr->store, node->pr->iter,
						   RATE_COLUMN, rate,
						   COUNT_COLUMN, value,
						   PERCENT_COLUMN, percent,
						   -1);
	}
#else
	if (node->st->pr->ctree) {
		gtk_ctree_node_set_text(GTK_CTREE(node->st->pr->ctree),
					node->pr->node, RATE_COLUMN, rate);
		gtk_ctree_node_set_text(GTK_CTREE(node->st->pr->ctree),
					node->pr->node, COUNT_COLUMN, value);
		gtk_ctree_node_set_text(GTK_CTREE(node->st->pr->ctree),
					node->pr->node, PERCENT_COLUMN, percent);
	}
#endif
	
	if (node->children) {
		for (child = node->children; child; child = child->next )
			draw_gtk_node(child);
	}
}

static void draw_gtk_tree( void *psp  ) {
	stats_tree *st = psp;
	stat_node* child;

	for (child = st->root.children; child; child = child->next ) {
		draw_gtk_node(child);

#if GTK_MAJOR_VERSION >= 2
		gtk_tree_view_expand_row(GTK_TREE_VIEW(st->pr->tree),
								 gtk_tree_model_get_path(GTK_TREE_MODEL(st->pr->store),
														 child->pr->iter),
								 FALSE);
#endif
	}

}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

static void free_gtk_tree(GtkWindow *win _U_, stats_tree *st)
{
	
	protect_thread_critical_region();
	remove_tap_listener(st);
	unprotect_thread_critical_region();
	
#if GTK_MAJOR_VERSION >= 2
	if (st->root.pr)
		st->root.pr->iter = NULL;
#endif
	
	stats_tree_free(st);
	
}


/* initializes the stats_tree window */
static void init_gtk_tree(const char* optarg) {
	guint8* abbr = stats_tree_get_abbr(optarg);
	stats_tree* st = NULL;
	stats_tree_cfg* cfg = NULL;
	tree_pres* pr = g_malloc(sizeof(tree_pres));
	guint8* title = NULL;
	guint8* window_name = NULL;
	GString* error_string;
	GtkWidget *scr_win;
	guint init_strlen;
	GtkWidget *main_vb, *bbox, *bt_close;
#if GTK_MAJOR_VERSION >= 2
	GtkTreeViewColumn* column;
	GtkCellRenderer* renderer;
#else
	static char *titles[] = {
		"Topic / Item",
		"Count",
		"Rate",
		"Percent",
	};
	int i;
#endif
	
	if (abbr) {
		cfg = stats_tree_get_cfg_by_abbr(abbr);
		
		if (cfg != NULL) {
			init_strlen = strlen(cfg->pr->stat_dlg->init_string);
			
			if (strncmp (optarg, cfg->pr->stat_dlg->init_string, init_strlen) == 0){
				if (init_strlen == strlen(optarg)) {
					st = stats_tree_new(cfg,pr,NULL);
				} else { 
					st = stats_tree_new(cfg,pr,((guint8*)optarg)+init_strlen+1);
				}
				
			} else {
				st = stats_tree_new(cfg,pr,NULL);
			}
		} else {
			report_failure("no such stats_tree (%s) found in stats_tree registry",abbr);
		}
		g_free(abbr);
		
	} else {
		report_failure("could not obtain stats_tree abbr from optarg");		
	}

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
	gtk_container_border_width(GTK_CONTAINER(main_vb), 12);
	gtk_container_add(GTK_CONTAINER(st->pr->win), main_vb);

	scr_win = scrolled_window_new(NULL, NULL);

#if GTK_MAJOR_VERSION >= 2
	
	st->pr->store = gtk_tree_store_new (N_COLUMNS, G_TYPE_STRING, G_TYPE_STRING,
									G_TYPE_STRING, G_TYPE_STRING);
	
	st->pr->tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (st->pr->store));
	
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
	column = gtk_tree_view_column_new_with_attributes ("Rate", renderer,
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
#else

	st->pr->ctree = gtk_ctree_new_with_titles (N_COLUMNS, 0, titles);
	for (i = 0; i < N_COLUMNS; i++) {
		/*
		 * XXX - unfortunately, GtkCTree columns can't be
		 * both auto-resizing and resizeable.
		 */
		gtk_clist_set_column_auto_resize(GTK_CLIST(st->pr->ctree), i,
		    TRUE);
	}
	
	gtk_container_add( GTK_CONTAINER(scr_win), st->pr->ctree);
#endif

	gtk_container_add( GTK_CONTAINER(main_vb), scr_win);
	
	error_string = register_tap_listener( cfg->tapname,
										  st,
										  st->filter,
										  NULL,
										  stats_tree_packet,
										  draw_gtk_tree);
	
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		simple_dialog( ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str );
		/* destroy_stat_tree_window(st); */
		report_failure("stats_tree for: %s failed to attach to the tap: %s",cfg->name,error_string->str);
		g_string_free(error_string, TRUE);
	}
		
	/* Button row. */
	bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

	bt_close = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(st->pr->win, bt_close, window_cancel_button_cb);

	SIGNAL_CONNECT(GTK_WINDOW(st->pr->win), "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(GTK_WINDOW(st->pr->win), "destroy", free_gtk_tree, st);
	
	gtk_widget_show_all(st->pr->win);
	window_present(st->pr->win);
	
#if GTK_MAJOR_VERSION >= 2
	gtk_tree_view_set_model(GTK_TREE_VIEW(st->pr->tree),GTK_TREE_MODEL(st->pr->store));
#endif
	
	st->cfg->init(st);

	cf_retap_packets(&cfile, FALSE);
}


static void register_gtk_stats_tree_tap (gpointer k _U_, gpointer v, gpointer p _U_) {
	stats_tree_cfg* cfg = v;

	cfg->pr = g_malloc(sizeof(tree_pres));
	
	cfg->pr->stat_dlg = g_malloc(sizeof(tap_dfilter_dlg));
	
	cfg->pr->stat_dlg->win_title = g_strdup_printf("%s Stats Tree",cfg->name);
	cfg->pr->stat_dlg->init_string = g_strdup_printf("%s,tree",cfg->abbr);
	cfg->pr->stat_dlg->tap_init_cb = init_gtk_tree;
	cfg->pr->stat_dlg->index = -1;
	
	register_dfilter_stat(cfg->pr->stat_dlg, cfg->name,
	    REGISTER_STAT_GROUP_NONE);
}

static void free_tree_presentation(stats_tree* st) {
	g_free(st->pr);
}

void
register_tap_listener_stats_tree_stat(void)
{
	
	stats_tree_presentation(register_gtk_stats_tree_tap,
							setup_gtk_node_pr, NULL,
							NULL,
							NULL, NULL, free_tree_presentation, NULL, NULL, NULL);
}
