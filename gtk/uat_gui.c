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
#include <epan/emem.h>
#include <epan/report_err.h>
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

struct _str_pair {
	const char* ptr;
	unsigned len;
};

struct _uat_dlg_data {
    GtkWidget* win;
    GPtrArray* entries;
	uat_t* uat;
	void* rec;
	gboolean is_new;
	gint row;
};

static void append_row(uat_t* uat, guint idx) {
	GPtrArray* a = g_ptr_array_new();
	void* rec = UAT_INDEX_PTR(uat,idx);
	uat_fld_t* f;
	guint rownum;

	gtk_clist_freeze(GTK_CLIST(uat->rep->clist));

	for ( f = uat->fields; f ; f = f->next ) {
		guint len;
		char* ptr;
		f->tostr_cb(rec,&ptr,&len);
		g_ptr_array_add(a,ptr);
	}
	
	rownum = gtk_clist_append(GTK_CLIST(uat->rep->clist), (gchar**)a->pdata);
	gtk_clist_set_row_data(GTK_CLIST(uat->rep->clist), rownum, rec);

	gtk_clist_thaw(GTK_CLIST(uat->rep->clist));

	g_ptr_array_free(a,TRUE);
}

static void reset_row(uat_t* uat, guint idx) {
	void* rec = UAT_INDEX_PTR(uat,idx);
	uat_fld_t* f;
	
	gtk_clist_freeze(GTK_CLIST(uat->rep->clist));

	for ( f = uat->fields; f ; f = f->next ) {
		guint len;
		char* ptr;
		f->tostr_cb(rec,&ptr,&len);
		gtk_clist_set_text(GTK_CLIST(uat->rep->clist), idx, f->colnum, ptr);
	}
	
	gtk_clist_thaw(GTK_CLIST(uat->rep->clist));

}


static gboolean uat_dlg_cb(GtkWidget *win _U_, gpointer user_data) {
	struct _uat_dlg_data* dd = user_data;
	uat_fld_t* fld;
	char* err = NULL;
	guint i;
	
	for (fld = dd->uat->fields, i = 0; fld ; fld = fld->next, i++) {
		GtkWidget* entry = g_ptr_array_index(dd->entries,i);
		const gchar* text = gtk_entry_get_text(GTK_ENTRY(entry));
		unsigned len = strlen(text);
		
		if (fld->chk_cb) {
			if (! fld->chk_cb(dd->rec,text,len,&err)) {
				err = ep_strdup_printf("error in field '%s': %s",fld->name,err);
				goto on_failure;
			}
		}
		
		fld->set_cb(dd->rec,text,len);
	}

	if (dd->uat->update_cb) {
		dd->uat->update_cb(dd->rec,&err);
		
		if (err) {
			err = ep_strdup_printf("error updating record: %s",err);
			goto on_failure;
		}
		
		if (dd->is_new) {
			uat_add_record(dd->uat, dd->rec);
			
			if (dd->uat->free_cb) {
				dd->uat->free_cb(dd->rec);
			}
		}
	}

	uat_save(dd->uat,&err);
	
	if (err) {
		err = ep_strdup_printf("error saving '%s': %s",dd->uat->filename,err);
		goto on_failure;
	}
	
	if (dd->is_new) {
		append_row(dd->uat, (*dd->uat->nrows_p) - 1 );
	} else {
		reset_row(dd->uat,dd->row);
	}
		
	if (dd->is_new) g_free(dd->rec);
    g_ptr_array_free(dd->entries,TRUE);
    window_destroy(GTK_WIDGET(dd->win));
	
	window_present(GTK_WIDGET(dd->uat->rep->window));
	 
    return TRUE;
on_failure:
		
	report_failure("%s",err);
	return FALSE;
}

static gboolean uat_cancel_dlg_cb(GtkWidget *win _U_, gpointer user_data) {
	struct _uat_dlg_data* dd = user_data;

	window_present(GTK_WIDGET(dd->uat->rep->window));

	if (dd->is_new) g_free(dd->rec);
    g_ptr_array_free(dd->entries,TRUE);
    window_destroy(GTK_WIDGET(dd->win));
	

    return TRUE;
}

static void uat_dialog(uat_t* uat, gint row) {
    GtkWidget *win, *main_tb, *main_vb, *bbox, *bt_cancel, *bt_ok;
    struct _uat_dlg_data* dd = g_malloc(sizeof(struct _uat_dlg_data));
	uat_fld_t* fld;
	int i = 0;
	
    dd->entries = g_ptr_array_new();
    dd->win = dlg_window_new(uat->name);
    dd->uat = uat;
	dd->rec = row < 0 ? g_malloc0(uat->record_size) : UAT_INDEX_PTR(uat,row);
	dd->is_new = row < 0 ? TRUE : FALSE;
	dd->row = row;
	
    win = dd->win;
	
#if GTK_MAJOR_VERSION >= 2
    gtk_window_resize(GTK_WINDOW(win),400,15*(uat->ncols+6));
#else
    gtk_window_set_default_size(GTK_WINDOW(win), 400, 15*(uat->ncols+6));
    gtk_widget_set_usize(win, 400, 15*(uat->ncols+6));
#endif
    
    main_vb = gtk_vbox_new(TRUE,5);
    gtk_container_add(GTK_CONTAINER(win), main_vb);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 6);
	
    main_tb = gtk_table_new(uat->ncols+1, 2, FALSE);
    gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
    gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
    gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
    
    for (fld = uat->fields; fld ; fld = fld->next) {
        GtkWidget *entry, *label;
        
        label = gtk_label_new(fld->name);
        gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
        gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, i+1, i + 2);
        gtk_widget_show(label);
		
        entry = gtk_entry_new();
        g_ptr_array_add(dd->entries,entry);
        gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2, i+1, i + 2);
        gtk_widget_show(entry);

		if (! dd->is_new) {
			gchar* text;
			unsigned len;
			
			fld->tostr_cb(dd->rec,&text,&len);
			
			gtk_entry_set_text(GTK_ENTRY(entry),text);
		}
		i++;
    }
	
    bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_OK, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
    
    bt_ok = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
    SIGNAL_CONNECT(bt_ok, "clicked", uat_dlg_cb, dd);
    gtk_widget_grab_default(bt_ok);
    
    bt_cancel = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
    SIGNAL_CONNECT(bt_cancel, "clicked", uat_cancel_dlg_cb, dd);
    gtk_widget_grab_default(bt_cancel);
    
    gtk_widget_show(main_tb);
    gtk_widget_show(main_vb);
    gtk_widget_show(win);
}

struct _uat_del {
	GtkWidget *win;
	uat_t* uat;
	gint idx;
};

static void uat_del_cb(GtkButton *button _U_, gpointer u) {
	struct _uat_del* ud = u;
	uat_remove_record_idx(ud->uat, ud->idx);
	gtk_clist_remove(GTK_CLIST(ud->uat->rep->clist),ud->idx);
    window_destroy(GTK_WIDGET(ud->win));
	window_present(GTK_WIDGET(ud->uat->rep->window));
	g_free(ud);
}

static void uat_cancel_del_cb(GtkButton *button _U_, gpointer u) {
	struct _uat_del* ud = u;
    window_destroy(GTK_WIDGET(ud->win));
	window_present(GTK_WIDGET(ud->uat->rep->window));
	g_free(ud);
}

static void uat_del_dlg(uat_t* uat, int idx) {
    GtkWidget *win, *main_tb, *main_vb, *bbox, *bt_cancel, *bt_ok;
	uat_fld_t* fld;
	int i = 0;
	void* rec = UAT_INDEX_PTR(uat,idx);
	struct _uat_del* ud = g_malloc(sizeof(struct _uat_del));

	ud->uat = uat;
	ud->idx = idx;
    ud->win = win = dlg_window_new(ep_strdup_printf("Confirm Delete"));
	
#if GTK_MAJOR_VERSION >= 2
    gtk_window_resize(GTK_WINDOW(win),400,15*(uat->ncols+6));
#else
    gtk_window_set_default_size(GTK_WINDOW(win), 400, 15*(uat->ncols+6));
    gtk_widget_set_usize(win, 400, 15*(uat->ncols+6));
#endif
    
    main_vb = gtk_vbox_new(TRUE,5);
    gtk_container_add(GTK_CONTAINER(win), main_vb);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 6);
	
    main_tb = gtk_table_new(uat->ncols+1, 2, FALSE);
    gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
    gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
    gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
    
    for (fld = uat->fields; fld ; fld = fld->next) {
        GtkWidget *label;
		gchar* text;
		unsigned len;
		
		fld->tostr_cb(rec,&text,&len);
		
		
        label = gtk_label_new(fld->name);
        gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
        gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, i+1, i + 2);
        gtk_widget_show(label);
		
        label = gtk_label_new(text);
        gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
        gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 1, 2, i+1, i + 2);
        gtk_widget_show(label);
		
		i++;
    }
	
    bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_DELETE, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
    
    bt_ok = OBJECT_GET_DATA(bbox,GTK_STOCK_DELETE);
    SIGNAL_CONNECT(bt_ok, "clicked", uat_del_cb, ud);
    gtk_widget_grab_default(bt_ok);
    
    bt_cancel = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
    SIGNAL_CONNECT(bt_cancel, "clicked", uat_cancel_del_cb, ud);
    gtk_widget_grab_default(bt_cancel);
    
    gtk_widget_show(main_tb);
    gtk_widget_show(main_vb);
    gtk_widget_show(win);
}

static void uat_new_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	uat_dialog(uat, -1);
}

static void uat_edit_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	uat_dialog(uat, uat->rep->selected);
}

static void uat_delete_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	uat_del_dlg(uat,uat->rep->selected);
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
	if (rep) g_free(rep);
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

