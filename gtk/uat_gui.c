/*
 *  uat_gui.c
 *
 *  $Id$
 *
 *  User Accessible Tables GUI
 *  Mantain an array of user accessible data strucures
 *  
 * (c) 2007, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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
#include <epan/dfilter/dfilter-macro.h>
#include "dlg_utils.h"
#include "gui_utils.h"
#include "compat_macros.h"

#include <epan/uat-int.h>
#include "uat_gui.h"

#if GTK_MAJOR_VERSION >= 2
# undef GTK_MAJOR_VERSION
# define GTK_MAJOR_VERSION 1
# define BUTTON_SIZE_X -1
# define BUTTON_SIZE_Y -1
#else
# define BUTTON_SIZE_X 50
# define BUTTON_SIZE_Y 20
#endif

struct _uat_rep_t {
	GtkWidget* window;
	GtkWidget* vbox;
    GtkWidget* scrolledwindow;
    GtkWidget* clist;
	GtkWidget* bbox;
	GtkWidget* bt_close;
	GtkWidget* bt_new;
	GtkWidget* bt_edit;
	GtkWidget* bt_delete;
	
	gint selected;
	
#if GTK_MAJOR_VERSION >= 2
	GtkTreeSelection  *selection;
#endif
	
};


static void uat_new_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	printf("New...\n");
}

static void uat_edit_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	printf("Edit %d...\n",uat->rep->selected);
}

static void uat_delete_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	printf("Delete %d...\n",uat->rep->selected);
}

static void remember_selected_row(GtkCList *clist _U_, gint row, gint column _U_, GdkEvent *event _U_, gpointer u) {
    uat_t* uat = u;
	
    uat->rep->selected = row;
    
    gtk_widget_set_sensitive (uat->rep->bt_edit, TRUE);
    gtk_widget_set_sensitive(uat->rep->bt_delete, TRUE);    
}

static void unremember_selected_row(GtkCList *clist _U_, gint row _U_, gint column _U_, GdkEvent *event _U_, gpointer u)
{
    uat_t* uat = u;

	uat->rep->selected = -1;
	gtk_widget_set_sensitive (uat->rep->bt_edit, FALSE);
	gtk_widget_set_sensitive(uat->rep->bt_delete, FALSE);
}


static void free_rep(GtkWindow *win _U_, uat_t* uat) {
	uat_rep_t* rep = uat->rep;
	uat->rep = NULL;
	printf("rep=%p",rep);
	if (rep) g_free(rep);
}

static void append_row(uat_t* uat, guint idx) {
	GPtrArray* a = g_ptr_array_new();
	void* rec = UAT_INDEX_PTR(uat,idx);
	uat_fld_t* f;
	guint rownum;
	
	for ( f = uat->fields; f ; f = f->next ) {
		guint len;
		char* ptr;
		f->tostr_cb(rec,&ptr,&len);
		g_ptr_array_add(a,ptr);
	}
	
	rownum = gtk_clist_append(GTK_CLIST(uat->rep->clist), (gchar**)a->pdata);
	gtk_clist_set_row_data(GTK_CLIST(uat->rep->clist), rownum, rec);

	g_ptr_array_free(a,TRUE);
}

GtkWidget* uat_window(uat_t* uat) {
	uat_rep_t* rep;
	uat_fld_t* f;
	guint i;
	
	if (uat->rep) {
		window_present(uat->rep->window);
		return uat->rep->window;
	} else {
		uat->rep = rep = g_malloc0(sizeof(uat_rep_t));
	}
	
	rep->window = window_new(GTK_WINDOW_TOPLEVEL, "Display Filter Macros");
	gtk_window_set_default_size(GTK_WINDOW(rep->window), 650, 600);
	
#if GTK_MAJOR_VERSION >= 2
	gtk_window_set_position(GTK_WINDOW(rep->window), GTK_WIN_POS_CENTER_ON_PARENT);
#else
	gtk_window_set_position(GTK_WINDOW(rep->window), GTK_WIN_POS_CENTER);
#endif
	
	gtk_container_border_width(GTK_CONTAINER(rep->window), 6);
	
	rep->vbox = gtk_vbox_new(FALSE, 12);
	gtk_container_border_width(GTK_CONTAINER(rep->vbox), 6);
	gtk_container_add(GTK_CONTAINER(rep->window), rep->vbox);

	rep->scrolledwindow = scrolled_window_new(NULL, NULL);
	gtk_container_add(GTK_CONTAINER(rep->vbox), rep->scrolledwindow);

#if GTK_MAJOR_VERSION >= 2
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(rep->scrolledwindow), GTK_SHADOW_IN);
#endif
	
	rep->clist = gtk_clist_new(uat->ncols);
		
	for ( f = uat->fields; f ; f = f->next ) {
		gtk_clist_set_column_title(GTK_CLIST(rep->clist), f->colnum, f->name);
		gtk_clist_set_column_auto_resize(GTK_CLIST(rep->clist), f->colnum, TRUE);
	}
	
	gtk_clist_column_titles_show(GTK_CLIST(rep->clist));
	gtk_clist_freeze(GTK_CLIST(rep->clist));
	
	for ( i = 0 ; i < *(uat->nrows_p); i++ ) {
		append_row(uat, i);
	}
	
	gtk_clist_thaw(GTK_CLIST(rep->clist));
	
#if GTK_MAJOR_VERSION < 2
	gtk_clist_set_selection_mode(GTK_CLIST(rep->clist),GTK_SELECTION_SINGLE);
#else
	rep->selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(rep->clist));
	gtk_tree_selection_set_mode(rep->selection, GTK_SELECTION_SINGLE);
#endif
	
	gtk_container_add(GTK_CONTAINER(rep->scrolledwindow), rep->clist);

	rep->bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(rep->vbox), rep->bbox, FALSE, FALSE, 0);
	
	
	rep->bt_new = BUTTON_NEW_FROM_STOCK(GTK_STOCK_NEW);
#if GTK_MAJOR_VERSION < 2
	WIDGET_SET_SIZE(rep->bt_new, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
	gtk_box_pack_start (GTK_BOX(rep->bbox), rep->bt_new, FALSE, FALSE, 5);
	
	rep->bt_edit = BUTTON_NEW_FROM_STOCK(WIRESHARK_STOCK_EDIT);
#if GTK_MAJOR_VERSION < 2
	WIDGET_SET_SIZE(rep->bt_edit, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
	gtk_box_pack_start (GTK_BOX(rep->bbox), rep->bt_edit, FALSE, FALSE, 5);
	gtk_widget_set_sensitive (rep->bt_edit, FALSE);
	
	rep->bt_delete = BUTTON_NEW_FROM_STOCK(GTK_STOCK_DELETE);
	gtk_box_pack_start (GTK_BOX(rep->bbox), rep->bt_delete, FALSE, FALSE, 5);
#if GTK_MAJOR_VERSION < 2
	WIDGET_SET_SIZE(rep->bt_delete, BUTTON_SIZE_X, BUTTON_SIZE_Y);
#endif
	gtk_widget_set_sensitive (rep->bt_delete, FALSE);
	
	
#if GTK_MAJOR_VERSION < 2
	SIGNAL_CONNECT(rep->clist, "select_row", remember_selected_row, uat);
	SIGNAL_CONNECT(rep->clist, "unselect_row", unremember_selected_row, uat);
#else
	SIGNAL_CONNECT(selection, "changed", remember_selected_row, uat);
#endif
	
	SIGNAL_CONNECT(rep->bt_new, "clicked", uat_new_cb, uat);
	SIGNAL_CONNECT(rep->bt_edit, "clicked", uat_edit_cb, uat);
	SIGNAL_CONNECT(rep->bt_delete, "clicked", uat_delete_cb, uat);
	
	
	rep->bt_close = OBJECT_GET_DATA(rep->bbox, GTK_STOCK_CLOSE);
	window_set_cancel_button(rep->window, rep->bt_close, window_cancel_button_cb);
	
	SIGNAL_CONNECT(GTK_WINDOW(rep->window), "delete_event", window_delete_event_cb, uat);
	SIGNAL_CONNECT(GTK_WINDOW(rep->window), "destroy", free_rep, uat);
	
	gtk_widget_grab_focus(rep->clist);

	gtk_widget_show_all(rep->window);
	window_present(rep->window);

	return rep->window;
}

