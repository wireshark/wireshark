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

/*
 TODO

 -  at reinitialization I have one of these for every node in the tree
     Gtk-CRITICAL **: file gtktreestore.c: line 1044 (gtk_tree_store_set): assertion `VALID_ITER (iter, tree_store)' failed

 - GTK1
*/

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <gtk/gtk.h>

#include <epan/stats_tree_priv.h>

#include "simple_dialog.h"
#include "globals.h"
#include "tap_menu.h"
#include "ui_util.h"
#include "dlg_utils.h"
#include "compat_macros.h"
#include "tap_dfilter_dlg.h"
#include "../tap_dfilter_dlg.h"

struct _st_node_pres {
#if GTK_MAJOR_VERSION >= 2
	GtkTreeIter*	iter;
#else
	/* g_malloc(0) ??? */
	void*		dummy;
#endif
};


struct _tree_pres {
	tap_dfilter_dlg* stat_dlg;
	GString*		text;
	GtkWidget*		win;
	
#if GTK_MAJOR_VERSION >= 2
	GtkTreeStore*   store;
	GtkWidget*		tree;
#else
	GtkText*		textbox;
#endif
};

/* the columns of the tree pane */
enum _stat_tree_columns {
	COUNT_COLUMN,
	RATE_COLUMN,
	TITLE_COLUMN,
	PERCENT_COLUMN,
	N_COLUMNS
};

/* used for converting numbers */
#define NUM_BUF_SIZE  32

/* creates the gtk representation for a stat_node
 * node: the node
 */
static void setup_gtk_node_pr(stat_node* node) {
	node->pr = g_malloc(sizeof(st_node_pres));
	

#if GTK_MAJOR_VERSION >= 2
	GtkTreeIter* parent =  NULL;
	
	if ( node->parent && node->parent->pr ) 
		parent = node->parent->pr->iter;

	node->pr->iter = g_malloc(sizeof(GtkTreeIter));

	if (node->st->pr->store) {
		gtk_tree_store_append (node->st->pr->store, node->pr->iter, parent);
		/* g_message("setup_gtk_node_pr: %s",node->name); */
		gtk_tree_store_set(node->st->pr->store, node->pr->iter, TITLE_COLUMN, node->name, RATE_COLUMN, "", COUNT_COLUMN, "", -1);
	}
#else
	node->pr->dummy = NULL;
#endif
}


#if GTK_MAJOR_VERSION >= 2
static void draw_gtk_node(stat_node* node) {
	static gchar value[NUM_BUF_SIZE];
	static gchar rate[NUM_BUF_SIZE];
	static gchar percent[NUM_BUF_SIZE];
	stat_node* child;
	
	get_strings_from_node(node, value, rate, percent);
	
	if (node->st->pr->store) {
		/* g_message("draw_gtk_node: %s",node->name); */
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
#endif

static void draw_gtk_tree( void *psp  ) {
	stats_tree *st = psp;
	stat_node* child;

#if GTK_MAJOR_VERSION >= 2
	for (child = st->root.children; child; child = child->next )
		draw_gtk_node(child);
	
	gtk_tree_view_set_model(GTK_TREE_VIEW(st->pr->tree),GTK_TREE_MODEL(st->pr->store));
#else
	GString* text = g_string_new("");
	
	for (child = st->root.children; child; child = child->next ) {
		stat_node_to_str(child,text,0);
	}
	
	gtk_text_freeze(st->textbox);
	gtk_text_set_point(st->textbox,0);
	gtk_text_forward_delete(st->textbox,gtk_text_get_length(st->textbox));
	gtk_text_insert(st->textbox,NULL,st->textbox->style->black,NULL,text->str,-1);
	gtk_text_thaw(st->textbox);
	
	g_string_free(text,TRUE);
#endif	
}

void protect_thread_critical_region(void);
void unprotect_thread_critical_region(void);

static void free_gtk_tree(GtkWindow *win _U_, stats_tree *st)
{
	
	protect_thread_critical_region();
	remove_tap_listener(st);
	unprotect_thread_critical_region();
	
	if (st->root.pr)
		st->root.pr->iter = NULL;
}


/* initializes the stats_tree window */
static void init_gtk_tree(char* optarg) {
	guint8* abbr = get_st_abbr(optarg);
	stats_tree* st = NULL;
	guint8* title = NULL;
	guint8* window_name = NULL;
	GString* error_string;
#if GTK_MAJOR_VERSION >= 2
	GtkTreeViewColumn* column;
	GtkCellRenderer* renderer;
	GtkWidget *scr_win;
#endif
	
	if (abbr) {
		st = get_stats_tree_by_abbr(abbr);
		
		if (st != NULL) {
			if (strncmp (optarg, st->pr->stat_dlg->init_string, strlen(st->pr->stat_dlg->init_string)) == 0){
				st->filter=((guint8*)optarg)+strlen(st->pr->stat_dlg->init_string);
			} else {
				st->filter=NULL;
			}
		} else {
			g_error("no such stats_tree (%s) found in stats_tree registry",abbr);
		}
		g_free(abbr);
		
	} else {
		g_error("could not obtain stats_tree abbr from optarg");		
	}
	
	window_name = g_strdup_printf("%s Stats Tree", st->abbr);
	
	st->pr->win = window_new_with_geom(GTK_WINDOW_TOPLEVEL,window_name,window_name);
	g_free(window_name);
	
	if(st->filter){
		title=g_strdup_printf("%s with filter: %s",st->name,st->filter);
	} else {
		st->filter=NULL;
		title=g_strdup_printf("%s", st->name);
	}
	
    gtk_window_set_title(GTK_WINDOW(st->pr->win), title);
	g_free(title);
	
#if GTK_MAJOR_VERSION >= 2
	scr_win = scrolled_window_new(NULL, NULL);
	
	st->pr->store = gtk_tree_store_new (N_COLUMNS, G_TYPE_STRING, G_TYPE_STRING,
									G_TYPE_STRING, G_TYPE_STRING);
	
	st->pr->tree = gtk_tree_view_new_with_model (GTK_TREE_MODEL (st->pr->store));
	
	gtk_container_add( GTK_CONTAINER(scr_win), st->pr->tree);
	gtk_container_add( GTK_CONTAINER(st->pr->win), scr_win);
	
	/* the columns */
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("What", renderer,
													   "text", TITLE_COLUMN,
													   NULL);
	gtk_tree_view_column_set_resizable (column,TRUE);
	gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (st->pr->tree), column);
	
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("count", renderer,
													   "text", COUNT_COLUMN,
													   NULL);
	
	gtk_tree_view_column_set_resizable (column,TRUE);
	gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (st->pr->tree), column);
	
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("rate", renderer,
													   "text", RATE_COLUMN,
													   NULL);
	gtk_tree_view_column_set_resizable (column,TRUE);
	gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (st->pr->tree), column);
	
	renderer = gtk_cell_renderer_text_new ();
	column = gtk_tree_view_column_new_with_attributes ("percent", renderer,
													   "text", PERCENT_COLUMN,
													   NULL);
	gtk_tree_view_column_set_resizable(column,TRUE);
	gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
	gtk_tree_view_append_column (GTK_TREE_VIEW (st->pr->tree), column);
#else
	pr->textbox = gtk_text_new(NULL,NULL);
	gtk_container_add( GTK_CONTAINER(scr_win), st->pr->textbox);
	gtk_container_add( GTK_CONTAINER(st->pr->win), scr_win);
#endif
	
	error_string = register_tap_listener( st->tapname,
										  st,
										  st->filter,
										  /* reinit_stats_tree*/ NULL,
										  stats_tree_packet,
										  draw_gtk_tree);
	
	if (error_string) {
		/* error, we failed to attach to the tap. clean up */
		simple_dialog( ESD_TYPE_ERROR, ESD_BTN_OK, error_string->str );
		/* destroy_stat_tree_window(st); */
		g_error("stats_tree for: %s failed to attach to the tap: %s",st->name,error_string->str);
		g_string_free(error_string, TRUE);
	}
		
	SIGNAL_CONNECT(GTK_WINDOW(st->pr->win), "delete_event", window_delete_event_cb, NULL);
	SIGNAL_CONNECT(GTK_WINDOW(st->pr->win), "destroy", free_gtk_tree, st);
	
	gtk_widget_show_all(st->pr->win);
	window_present(st->pr->win);
	
	if (st->init) st->init(st);

	cf_retap_packets(&cfile);
	
}


static void register_gtk_stats_tree_tap (gpointer k _U_, gpointer v, gpointer p _U_) {
	stats_tree* st = v;
	guint8* s;

	s = g_strdup_printf("%s,tree",st->abbr);
	
	register_ethereal_tap(s, init_gtk_tree);
	g_free(s);
	
	st->pr = g_malloc(sizeof(tree_pres));
	st->pr->text = NULL;
	st->pr->win = NULL;
	
#if GTK_MAJOR_VERSION >= 2
	st->pr->store = NULL;
	st->pr->tree = NULL;
#else
	st->pr->textbox = NULL;
#endif
	
	st->pr->stat_dlg = g_malloc(sizeof(tap_dfilter_dlg));
	
	st->pr->stat_dlg->win_title = g_strdup_printf("%s Packet Counter",st->name);
	st->pr->stat_dlg->init_string = g_strdup_printf("%s,tree",st->abbr);
	st->pr->stat_dlg->tap_init_cb = init_gtk_tree;
	st->pr->stat_dlg->index = -1;
	
	register_tap_menu_item(st->name, REGISTER_TAP_GROUP_NONE,
						   gtk_tap_dfilter_dlg_cb, NULL, NULL, st->pr->stat_dlg);
}

void
register_tap_listener_stats_tree_stat(void)
{	
	stats_tree_presentation(register_gtk_stats_tree_tap,
							setup_gtk_node_pr, NULL,
							draw_gtk_node,
							NULL, NULL, NULL, NULL, NULL, NULL);
}
