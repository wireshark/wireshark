/*
 *  uat_gui.c
 *
 *  $Id$
 *
 *  User Accessible Tables GUI
 *  Mantain an array of user accessible data strucures
 *  
 * (c) 2007, Luis E. Garcia Ontanon <luis@ontanon.org>
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

/*
 * TO DO:
 * + improvements
 *   - field value check (red/green editbox)
 *   - tooltips (add field descriptions)
 * - Make cells editable
 * - Allow reordering via drag and drop
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>

#include <gtk/gtk.h>
#include <gdk/gdkkeysyms.h>
#if GTK_CHECK_VERSION(3,0,0)
# include <gdk/gdkkeysyms-compat.h>
#endif

#include <epan/dfilter/dfilter-macro.h>
#include <epan/emem.h>
#include <epan/report_err.h>
#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/uat-int.h>
#include <epan/value_string.h>

#include "../stat_menu.h"

#include "gtk/gtkglobals.h"
#include "gtk/gui_utils.h"
#include "gtk/dlg_utils.h"
#include "gtk/help_dlg.h"
#include "gtk/stock_icons.h"
#include "gtk/gui_stat_menu.h"
#include "gtk/main.h"
#include "gtk/uat_gui.h"


# define BUTTON_SIZE_X -1
# define BUTTON_SIZE_Y -1

struct _uat_rep_t {
	GtkWidget* window;
	GtkWidget* vbox;
	GtkWidget* scrolledwindow;
	GtkTreeView* list;
	GtkListStore *list_store;
	GtkWidget* bbox;
	GtkWidget* bt_new;
	GtkWidget* bt_edit;
	GtkWidget* bt_copy;
	GtkWidget* bt_delete;
	GtkWidget* bt_up;
	GtkWidget* bt_down;
	GtkWidget* bt_apply;
	GtkWidget* bt_cancel;
	GtkWidget* bt_ok;
	GtkWidget* unsaved_window;

	gint selected;
	gboolean dont_save;
	GtkTreeSelection  *selection;
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
	GPtrArray* tobe_freed;
};


static gboolean unsaved_dialog(GtkWindow *w, GdkEvent* e, gpointer u);
static gboolean uat_window_delete_event_cb(GtkWindow *w, GdkEvent* e, gpointer u);

static void set_buttons(uat_t* uat, gint row) {

	if (!uat->rep) return;

	if (row > 0) {
		gtk_widget_set_sensitive (uat->rep->bt_up, TRUE);
	} else {
		gtk_widget_set_sensitive (uat->rep->bt_up, FALSE);
	}

	if (row < (gint)(*uat->nrows_p - 1) && row >= 0) {
		gtk_widget_set_sensitive (uat->rep->bt_down, TRUE);
	} else {
		gtk_widget_set_sensitive (uat->rep->bt_down, FALSE);
	}

	if (row < 0) {
		gtk_widget_set_sensitive (uat->rep->bt_edit, FALSE);
		gtk_widget_set_sensitive (uat->rep->bt_copy, FALSE);
		gtk_widget_set_sensitive (uat->rep->bt_delete, FALSE);
	}

	if (uat->changed) {
		g_signal_handlers_disconnect_by_func(uat->rep->window, uat_window_delete_event_cb, uat);
		g_signal_connect(uat->rep->window, "delete_event", G_CALLBACK(unsaved_dialog), uat);
		g_signal_connect(uat->rep->window, "destroy", G_CALLBACK(unsaved_dialog), uat);
	} else {
		g_signal_handlers_disconnect_by_func(uat->rep->window, unsaved_dialog, uat);
		g_signal_connect(GTK_WINDOW(uat->rep->window), "delete_event", G_CALLBACK(uat_window_delete_event_cb), uat);
		g_signal_connect(GTK_WINDOW(uat->rep->window), "destroy", G_CALLBACK(uat_window_delete_event_cb), uat);
	}
}

static char* fld_tostr(void* rec, uat_field_t* f) {
	guint len;
	const char* ptr;
	char* out;

	f->cb.tostr(rec,&ptr,&len,f->cbdata.tostr,f->fld_data);

	switch(f->mode) {
		case PT_TXTMOD_STRING:
		case PT_TXTMOD_ENUM:
			out = ep_strndup(ptr,len);
			break;
		case PT_TXTMOD_HEXBYTES: {
			GString* s = g_string_sized_new( len*2 + 1 );
			guint i;
			
			for (i=0; i<len;i++) g_string_append_printf(s,"%.2X",((guint8*)ptr)[i]);
			
			out = ep_strdup(s->str);
			
			g_string_free(s,TRUE);
			break;
		} 
		default:
			g_assert_not_reached();
			out = NULL;
			break;
	}

	return out;
}



static void append_row(uat_t* uat, guint idx) {
	GPtrArray* a = g_ptr_array_new();
	void* rec = UAT_INDEX_PTR(uat,idx);
	uat_field_t* f = uat->fields;
	guint colnum;
	GtkTreeIter iter;

	if (! uat->rep) return;

	/* gtk_clist_freeze(GTK_CLIST(uat->rep->clist)); */

	gtk_list_store_insert_before(uat->rep->list_store, &iter, NULL);
	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		g_ptr_array_add(a,fld_tostr(rec,&(f[colnum])));
		gtk_list_store_set(uat->rep->list_store, &iter, colnum, fld_tostr(rec,&(f[colnum])), -1);
	}

	
	/* rownum = gtk_clist_append(GTK_CLIST(uat->rep->clist), (gchar**)a->pdata);
	gtk_clist_set_row_data(GTK_CLIST(uat->rep->clist), rownum, rec); */

	/* gtk_clist_thaw(GTK_CLIST(uat->rep->clist)); */

	g_ptr_array_free(a,TRUE);
}

static void reset_row(uat_t* uat, guint idx) {
	void* rec = UAT_INDEX_PTR(uat,idx);
	uat_field_t* f = uat->fields;
	guint colnum;
	GtkTreePath *path;
	GtkTreeIter iter;

	if (! uat->rep) return;

	/* gtk_clist_freeze(GTK_CLIST(uat->rep->clist)); */

	path = gtk_tree_path_new_from_indices(idx, -1);
	if (!path || !gtk_tree_model_get_iter(GTK_TREE_MODEL(uat->rep->list_store), &iter, path)) {
		return;
	}

	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		gtk_list_store_set(uat->rep->list_store, &iter, colnum, fld_tostr(rec,&(f[colnum])), -1);
		/* gtk_clist_set_text(GTK_CLIST(uat->rep->clist), idx, colnum, fld_tostr(rec,&(f[colnum]))); */
	}
	
	/* gtk_clist_thaw(GTK_CLIST(uat->rep->clist)); */

}

static guint8* unhexbytes(const char* si, guint len, guint* len_p, const char** err) {
	guint8* buf;
	guint8* p;
	const guint8* s = (void*)si;
	unsigned i;

	if (len % 2) {
		*err = "Uneven number of chars hex string";
		return NULL;
	}

	buf = ep_alloc(len/2+1);
	p = buf;

	for (i = 0; i<len ; i += 2) {
		guint8 lo = s[i+1];
		guint8 hi = s[i];

		if (hi >= '0' && hi <= '9') {
			hi -= '0';
		} else if (hi >= 'a' && hi <= 'f') {
			hi -=  'a';
			hi += 0xa;
		} else if (hi >= 'A' && hi <= 'F') {
			hi -=  'A';
			hi += 0xa;
		} else {
			goto on_error;
		}

		if (lo >= '0' && lo <= '9') {
			lo -= '0';
		} else if (lo >= 'a' && lo <= 'f') {
			lo -=  'a';
			lo += 0xa;
		} else if (lo >= 'A' && lo <= 'F') {
			lo -=  'A';
			lo += 0xa;
		} else {
			goto on_error;
		}

		*(p++) = (hi*0x10) + lo;
	}

	len /= 2;

	if (len_p) *len_p = len;

	buf[len] = '\0';

	*err = NULL;
	return buf;
	
on_error:
	*err = "Error parsing hex string";
	return NULL;
}


static gboolean uat_dlg_cb(GtkWidget *win _U_, gpointer user_data) {
	struct _uat_dlg_data* dd = user_data;
	guint ncols = dd->uat->ncols;
	uat_field_t* f = dd->uat->fields;
	const char* err = NULL;
	guint colnum;

	for ( colnum = 0; colnum < ncols; colnum++ ) {
		void* e = g_ptr_array_index(dd->entries,colnum);
		const char* text;
		unsigned len = 0;

		switch(f[colnum].mode) {
			case PT_TXTMOD_STRING:
				text = gtk_entry_get_text(GTK_ENTRY(e));
				len = (unsigned) strlen(text);
				break;
			case PT_TXTMOD_HEXBYTES: {
				text = gtk_entry_get_text(GTK_ENTRY(e));

				text = (void*) unhexbytes(text, (guint) strlen(text), &len, &err);

				if (err) {
					err = ep_strdup_printf("error in field '%s': %s",f[colnum].title,err);
					goto on_failure;
				}

				break;
			}
			case PT_TXTMOD_ENUM: {
				gint idx = *(int*)e;
				text = (idx >= 0) ? ((value_string *)(f[colnum].fld_data))[idx].strptr : "";
				len = (unsigned) strlen(text);
				break;
			}
			default:
				g_assert_not_reached();
				return FALSE;
		}


		if (f[colnum].cb.chk) {
			if (! f[colnum].cb.chk(dd->rec, text, len, f[colnum].cbdata.chk, f[colnum].fld_data, &err)) {
				err = ep_strdup_printf("error in column '%s': %s",f[colnum].title,err);
				goto on_failure;
			}
		}

		f[colnum].cb.set(dd->rec,text,len, f[colnum].cbdata.set, f[colnum].fld_data);
	}

	if (dd->uat->update_cb) {
		dd->uat->update_cb(dd->rec,&err);

		if (err) {
			err = ep_strdup_printf("error updating record: %s",err);
			goto on_failure;
		}
	}

	if (dd->is_new) {
		void* rec_tmp = dd->rec;
		dd->rec = uat_add_record(dd->uat, dd->rec);

		if (dd->uat->free_cb) {
			dd->uat->free_cb(rec_tmp);
		}

		g_free(rec_tmp);
	}
	
	dd->uat->changed = TRUE;

	set_buttons(dd->uat, dd->uat->rep ? dd->uat->rep->selected : -1);

	if (dd->is_new) {
		append_row(dd->uat, (*dd->uat->nrows_p) - 1 );
	} else {
		reset_row(dd->uat,dd->row);
	}

	g_ptr_array_free(dd->entries,TRUE);
	window_destroy(GTK_WIDGET(dd->win));

	if (dd->uat->rep)
		window_present(GTK_WIDGET(dd->uat->rep->window));

	while (dd->tobe_freed->len) g_free( g_ptr_array_remove_index_fast(dd->tobe_freed, dd->tobe_freed->len - 1 ) );

	g_free(dd);

	return TRUE;
on_failure:

	report_failure("%s",err);
	return FALSE;
}

static gboolean uat_cancel_dlg_cb(GtkWidget *win _U_, gpointer user_data) {
	struct _uat_dlg_data* dd = user_data;

	if (dd->uat->rep)
		window_present(GTK_WIDGET(dd->uat->rep->window));

	if (dd->is_new) g_free(dd->rec);
	g_ptr_array_free(dd->entries,TRUE);
	window_destroy(GTK_WIDGET(dd->win));

	while (dd->tobe_freed->len) g_free( g_ptr_array_remove_index_fast(dd->tobe_freed, dd->tobe_freed->len - 1 ) );

	g_free(dd);

	return TRUE;
}

static void fld_combo_box_changed_cb(GtkComboBox *combo_box, gpointer user_data) {
	int* valptr = user_data;
	*valptr = gtk_combo_box_get_active(combo_box);
}

static void uat_edit_dialog(uat_t* uat, gint row, gboolean copy) {
	GtkWidget *win, *main_tb, *main_vb, *bbox, *bt_cancel, *bt_ok;
	struct _uat_dlg_data* dd = g_malloc(sizeof(struct _uat_dlg_data));
	uat_field_t* f = uat->fields;
	guint colnum;
	
	dd->entries = g_ptr_array_new();
	dd->win = dlg_conf_window_new(ep_strdup_printf("%s: %s", uat->name, (row == -1 ? "New" : "Edit")));
	dd->uat = uat;
	if (copy && row >= 0) {
	  dd->rec = g_malloc0(uat->record_size);
	  if (uat->copy_cb) {
	    uat->copy_cb (dd->rec, UAT_INDEX_PTR(uat,row), uat->record_size);
	  }
	  dd->is_new = TRUE;
	} else if (row >= 0) {
	  dd->rec = UAT_INDEX_PTR(uat,row);
	  dd->is_new = FALSE;
	} else {
	  dd->rec = g_malloc0(uat->record_size);
	  dd->is_new = TRUE;
	}
	dd->row = row;
	dd->tobe_freed = g_ptr_array_new();

	win = dd->win;

	gtk_window_set_resizable(GTK_WINDOW(win),FALSE);
	gtk_window_resize(GTK_WINDOW(win),400, 30*(uat->ncols+2));

	main_vb = gtk_vbox_new(FALSE,5);
	gtk_container_add(GTK_CONTAINER(win), main_vb);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 6);

	main_tb = gtk_table_new(uat->ncols+1, 2, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 5);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 10);

	bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_OK, NULL);
	gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

	bt_ok = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
	g_signal_connect(bt_ok, "clicked", G_CALLBACK(uat_dlg_cb), dd);

	bt_cancel = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	g_signal_connect(bt_cancel, "clicked", G_CALLBACK(uat_cancel_dlg_cb), dd);
	window_set_cancel_button(win, bt_cancel, NULL);

	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		GtkWidget *entry, *label, *event_box;
		char* text = fld_tostr(dd->rec,&(f[colnum]));

		event_box = gtk_event_box_new();

		label = gtk_label_new(ep_strdup_printf("%s:", f[colnum].title));
		if (f[colnum].desc != NULL)
			gtk_widget_set_tooltip_text(event_box, f[colnum].desc);

		gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
		gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box, 0, 1, colnum+1, colnum + 2);
		gtk_container_add(GTK_CONTAINER(event_box), label);

		switch(f[colnum].mode) {
			case PT_TXTMOD_STRING:
			case PT_TXTMOD_HEXBYTES: {
				entry = gtk_entry_new();
				g_ptr_array_add(dd->entries,entry);
				gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2, colnum+1, colnum + 2);
				if (! dd->is_new || copy) {
					gtk_entry_set_text(GTK_ENTRY(entry),text);
				}
				dlg_set_activate(entry, bt_ok);
				break;
			}
			case PT_TXTMOD_ENUM: {
				GtkWidget *combo_box;
				int idx;
				const value_string* enum_vals = f[colnum].fld_data;
				int* valptr = g_malloc(sizeof(int));	/* A place to store the index of the    */
									/*  "active" fld_data array entry       */
									/* -1 means "nothing selected (active)" */
				combo_box = gtk_combo_box_new_text();
				*valptr = -1;
				for (idx = 0; enum_vals[idx].strptr != NULL; idx++) {
					const char* str = enum_vals[idx].strptr;
					gtk_combo_box_append_text(GTK_COMBO_BOX(combo_box), str);
					
					if ( g_str_equal(str, text) ) {
						*valptr = idx;
					}
				}

				g_ptr_array_add(dd->entries,valptr);
				g_ptr_array_add(dd->tobe_freed,valptr);

				if (*valptr != -1)
					gtk_combo_box_set_active(GTK_COMBO_BOX(combo_box), *valptr);

				g_signal_connect(combo_box, "changed", G_CALLBACK(fld_combo_box_changed_cb), valptr);
				gtk_table_attach_defaults(GTK_TABLE(main_tb), combo_box, 1, 2, colnum+1, colnum + 2);

				break;
			}
			default:
				g_assert_not_reached();
				return;
		}
	}
	
	gtk_widget_grab_default(bt_ok);
	gtk_widget_show_all(win);
}

struct _uat_del {
	GtkWidget *win;
	uat_t* uat;
	gint idx;
};

static void uat_del_cb(GtkButton *button _U_, gpointer u) {
	struct _uat_del* ud = u;
	GtkTreeIter iter;
	GtkTreePath *path;

	uat_remove_record_idx(ud->uat, ud->idx);

	if (ud->uat->rep) {
		path = gtk_tree_path_new_from_indices(ud->idx, -1);
		if (path && gtk_tree_model_get_iter(GTK_TREE_MODEL(ud->uat->rep->list_store), &iter, path)) {
			gtk_list_store_remove(ud->uat->rep->list_store, &iter);
		}
		/* gtk_clist_remove(GTK_CLIST(ud->uat->rep->clist),ud->idx); */
	}

	ud->uat->changed = TRUE;
	set_buttons(ud->uat,-1);

	window_destroy(GTK_WIDGET(ud->win));

	if (ud->uat->rep)
		window_present(GTK_WIDGET(ud->uat->rep->window));

	g_free(ud);
}

static void uat_cancel_del_cb(GtkButton *button _U_, gpointer u) {
	struct _uat_del* ud = u;
	window_destroy(GTK_WIDGET(ud->win));

	if (ud->uat->rep)
		window_present(GTK_WIDGET(ud->uat->rep->window));
	g_free(ud);
}

static void uat_del_dlg(uat_t* uat, int idx) {
	GtkWidget *win, *main_tb, *main_vb, *bbox, *bt_cancel, *bt_ok;
	uat_field_t* f = uat->fields;
	guint colnum;
	void* rec = UAT_INDEX_PTR(uat,idx);
	struct _uat_del* ud = g_malloc(sizeof(struct _uat_del));

	ud->uat = uat;
	ud->idx = idx;
	ud->win = win = dlg_conf_window_new(ep_strdup_printf("%s: Confirm Delete", uat->name));
	
	gtk_window_set_resizable(GTK_WINDOW(win),FALSE);
	gtk_window_resize(GTK_WINDOW(win),400,25*(uat->ncols+2));

	main_vb = gtk_vbox_new(FALSE,5);
	gtk_container_add(GTK_CONTAINER(win), main_vb);
	gtk_container_set_border_width(GTK_CONTAINER(main_vb), 6);

	main_tb = gtk_table_new(uat->ncols+1, 2, FALSE);
	gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
	gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
	gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);

	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		GtkWidget *label;
		char* text = fld_tostr(rec,&(f[colnum]));

		label = gtk_label_new(ep_strdup_printf("%s:", f[colnum].title));
		gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
		gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, colnum+1, colnum + 2);
		
		label = gtk_label_new(text);
		gtk_misc_set_alignment(GTK_MISC(label), 1.0f, 0.5f);
		gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 1, 2, colnum+1, colnum + 2);
	}

	bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_DELETE, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

	bt_ok = g_object_get_data(G_OBJECT(bbox),GTK_STOCK_DELETE);
	g_signal_connect(bt_ok, "clicked", G_CALLBACK(uat_del_cb), ud);

	bt_cancel = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	g_signal_connect(bt_cancel, "clicked", G_CALLBACK(uat_cancel_del_cb), ud);
	window_set_cancel_button( win, bt_cancel, NULL);

	gtk_widget_show_all(win);
}

static void uat_new_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;

	if (! uat->rep) return;

	uat_edit_dialog(uat, -1, FALSE);
}

static void uat_edit_cb(GtkWidget *button _U_, gpointer u) {
	uat_t* uat = u;

	if (! uat->rep) return;

	uat_edit_dialog(uat, uat->rep->selected, FALSE);
}

static void uat_copy_cb(GtkWidget *button _U_, gpointer u) {
	uat_t* uat = u;

	if (! uat->rep) return;

	uat_edit_dialog(uat, uat->rep->selected, TRUE);
}

static void uat_double_click_cb(GtkWidget *tv, GtkTreePath *path _U_, GtkTreeViewColumn *column _U_, gpointer u) {
	uat_edit_cb(tv, u);
}

static void uat_delete_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;

	if (! uat->rep) return;

	uat_del_dlg(uat,uat->rep->selected);
}

static gboolean uat_window_delete_event_cb(GtkWindow *w _U_, GdkEvent* e _U_, gpointer u) {
	uat_t* uat = u;
	
	if (uat->rep) {
		void* rep = uat->rep;

		g_signal_handlers_disconnect_by_func(uat->rep->window, uat_window_delete_event_cb, uat);
		g_signal_handlers_disconnect_by_func(uat->rep->window, unsaved_dialog, uat);

		gtk_widget_destroy(uat->rep->window);

		uat->rep = NULL;
		g_free(rep);
	}
	return TRUE;
}

static void uat_up_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	gint row = uat->rep->selected;

	g_assert(row > 0);

	uat_swap(uat,row,row-1);
	tree_view_list_store_move_selection(uat->rep->list, TRUE);
	/* gtk_clist_swap_rows(GTK_CLIST(uat->rep->clist),row,row-1); */

	uat->changed = TRUE;

	row -= 1;
	uat->rep->selected = row;
	set_buttons(uat,row);
}

static void uat_down_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	gint row = uat->rep->selected;

	g_assert(row >= 0 && (guint) row < *uat->nrows_p - 1);

	uat_swap(uat,row,row+1);
	tree_view_list_store_move_selection(uat->rep->list, FALSE);
	/* gtk_clist_swap_rows(GTK_CLIST(uat->rep->clist),row,row+1); */

	uat->changed = TRUE;

	row += 1;
	uat->rep->selected = row;
	set_buttons(uat,row);
}

static void uat_cancel_cb(GtkWidget *button _U_, gpointer u) {
	uat_t* uat = u;
	gchar* err = NULL;

	if (uat->changed) {
		uat_clear(uat);
		uat_load(uat,&err);

		if (err) {
			report_failure("Error while loading %s: %s",uat->name,err);
		}

		redissect_packets ();
	}

	g_signal_handlers_disconnect_by_func(uat->rep->window, uat_window_delete_event_cb, uat);
	g_signal_handlers_disconnect_by_func(uat->rep->window, unsaved_dialog, uat);
	gtk_widget_destroy(uat->rep->window);
	g_free(uat->rep);
	uat->rep = NULL;
}

static void uat_apply_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;

	if (uat->changed) {
		if (uat->post_update_cb) uat->post_update_cb();
		redissect_packets ();
	}
}

static void uat_ok_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	gchar* err = NULL;

	if (uat->changed) {
		uat_save(uat,&err);

		if (err) {
			report_failure("Error while saving %s: %s",uat->name,err);
		}

		if (uat->post_update_cb) uat->post_update_cb();
		redissect_packets ();
	}

	g_signal_handlers_disconnect_by_func(uat->rep->window, uat_window_delete_event_cb, uat);
	g_signal_handlers_disconnect_by_func(uat->rep->window, unsaved_dialog, uat);
	gtk_widget_destroy(uat->rep->window);
	g_free(uat->rep);
	uat->rep = NULL;
}



static void remember_selected_row(GtkWidget *w _U_, gpointer u) {
	uat_t* uat = u;
	gint row;

	row = tree_view_list_store_get_selected_row(uat->rep->list);
	uat->rep->selected = row;

	gtk_widget_set_sensitive (uat->rep->bt_edit, TRUE);
	gtk_widget_set_sensitive (uat->rep->bt_copy, uat->copy_cb ? TRUE : FALSE);
	gtk_widget_set_sensitive(uat->rep->bt_delete, TRUE);

	set_buttons(uat,row);
}

static void uat_yessave_cb(GtkWindow *w _U_, void* u) {
	uat_t* uat = u;
	gchar* err = NULL;

	window_delete_event_cb(uat->rep->unsaved_window,NULL,NULL);

	uat_save(uat,&err);

	if (err) {
		report_failure("Error while saving %s: %s",uat->name,err);
	}

	g_signal_handlers_disconnect_by_func(uat->rep->window, uat_window_delete_event_cb, uat);
	g_signal_handlers_disconnect_by_func(uat->rep->window, unsaved_dialog, uat);
	window_destroy(uat->rep->window);

	g_free(uat->rep);
	uat->rep = NULL;
}


static void uat_nosave_cb(GtkWindow *w _U_, void* u) {
	uat_t* uat = u;
	window_delete_event_cb(uat->rep->unsaved_window,NULL,NULL);
	g_signal_handlers_disconnect_by_func(uat->rep->window, uat_window_delete_event_cb, uat);
	g_signal_handlers_disconnect_by_func(uat->rep->window, unsaved_dialog, uat);
	window_destroy(uat->rep->window);

	g_free(uat->rep);
	uat->rep = NULL;
}

static gboolean unsaved_dialog(GtkWindow *w _U_, GdkEvent* e _U_, gpointer u) {
	GtkWidget *win, *vbox, *label, *bbox;
	GtkWidget *yes_bt, *no_bt;
	gchar* message;
	uat_t* uat  = u;

	if (uat->rep->unsaved_window) {
		window_present(uat->rep->unsaved_window);
		return TRUE;
	}

	uat->rep->unsaved_window = win = dlg_conf_window_new("Discard Changes?");
	gtk_window_set_default_size(GTK_WINDOW(win), 360, 140);

	gtk_window_set_position(GTK_WINDOW(win), GTK_WIN_POS_CENTER_ON_PARENT);
	vbox = gtk_vbox_new(FALSE, 12);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);
	gtk_container_add(GTK_CONTAINER(win), vbox);

	message  = ep_strdup_printf("Changes to '%s' are not being saved!\n"
		"Do you want to save '%s'?", uat->name, uat->name);

	label = gtk_label_new(message);

	bbox = dlg_button_row_new(GTK_STOCK_YES,GTK_STOCK_NO, NULL);

	yes_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_YES);
	no_bt = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_NO);

	g_signal_connect(no_bt, "clicked", G_CALLBACK(uat_nosave_cb), uat);
	g_signal_connect(yes_bt, "clicked", G_CALLBACK(uat_yessave_cb), uat);

	gtk_box_pack_start(GTK_BOX(vbox), label, FALSE, FALSE, 0);
	gtk_box_pack_end(GTK_BOX(vbox), bbox, FALSE, FALSE, 0);

	gtk_widget_show_all(win);
	window_present(win);

	return TRUE;
}

static void uat_help_cb(GtkWidget* w _U_, gpointer u) {
	help_topic_html(ep_strdup_printf("%s.html",((uat_t*)u)->help));
}

static GtkWidget* uat_window(void* u) {
	uat_t* uat = u;
	uat_field_t* f = uat->fields;
	uat_rep_t* rep;
	guint i;
	guint colnum;
	GType *col_types;
	GtkWidget *hbox, *vbox, *move_hbox, *edit_hbox;
	GtkTreeViewColumn *column;
	GtkCellRenderer *renderer;
	GtkTreeSelection *selection;

	if (uat->rep) {
		window_present(uat->rep->window);
		return uat->rep->window;
	} else {
		uat->rep = rep = g_malloc0(sizeof(uat_rep_t));
	}

	rep->window = dlg_conf_window_new(uat->name);

	gtk_window_set_resizable(GTK_WINDOW(rep->window),TRUE);
	gtk_window_resize(GTK_WINDOW(rep->window), 720, 512);
	gtk_window_set_position(GTK_WINDOW(rep->window), GTK_WIN_POS_CENTER_ON_PARENT);

	gtk_container_set_border_width(GTK_CONTAINER(rep->window), 6);

	rep->vbox = gtk_vbox_new(FALSE, 12);
	gtk_container_set_border_width(GTK_CONTAINER(rep->vbox), 6);
	gtk_container_add(GTK_CONTAINER(rep->window), rep->vbox);

	hbox = gtk_hbox_new(FALSE,12);
	gtk_container_set_border_width(GTK_CONTAINER(hbox), 6);
	gtk_container_add(GTK_CONTAINER(rep->vbox), hbox);

	vbox = gtk_vbox_new(FALSE, 12);
	gtk_container_set_border_width(GTK_CONTAINER(vbox), 6);
	gtk_box_pack_start(GTK_BOX(hbox), vbox, FALSE, FALSE, 0);

	rep->scrolledwindow = scrolled_window_new(NULL, NULL);
	gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(rep->scrolledwindow), GTK_SHADOW_IN);

	col_types = g_malloc(sizeof(GType) * uat->ncols);
	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		col_types[colnum] = G_TYPE_STRING;
	}
	rep->list_store = gtk_list_store_newv(uat->ncols, col_types);
	g_free(col_types);

	rep->list = GTK_TREE_VIEW(tree_view_new(GTK_TREE_MODEL(rep->list_store))); /* uat->ncols */
	gtk_container_add(GTK_CONTAINER(rep->scrolledwindow), GTK_WIDGET(rep->list));
	gtk_box_pack_start(GTK_BOX(hbox), rep->scrolledwindow, TRUE, TRUE, 0);

	selection = gtk_tree_view_get_selection(rep->list);
	gtk_tree_selection_set_mode(selection, GTK_SELECTION_SINGLE);

	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		renderer = gtk_cell_renderer_text_new();
		column = gtk_tree_view_column_new_with_attributes(f[colnum].title,
			renderer, "text", colnum, NULL);
		gtk_tree_view_column_set_resizable (column,TRUE);
		gtk_tree_view_column_set_sizing(column,GTK_TREE_VIEW_COLUMN_AUTOSIZE);
		gtk_tree_view_append_column (rep->list, column);
		if (f[colnum].desc != NULL)
			gtk_widget_set_tooltip_text(column->button, f[colnum].desc);

		/*
		gtk_clist_set_column_title(GTK_CLIST(rep->clist), colnum, f[colnum].title);
		gtk_clist_set_column_auto_resize(GTK_CLIST(rep->clist), colnum, TRUE);
		*/
	}

	/*
	gtk_clist_column_titles_show(GTK_CLIST(rep->clist));
	gtk_clist_freeze(GTK_CLIST(rep->clist));
	*/

	for ( i = 0 ; i < *(uat->nrows_p); i++ ) {
		append_row(uat, i);
	}

	/* gtk_clist_thaw(GTK_CLIST(rep->clist)); */

/*	rep->selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(rep->clist)); 
	gtk_tree_selection_set_mode(rep->selection, GTK_SELECTION_SINGLE);
*/
	/* gtk_clist_set_selection_mode(GTK_CLIST(rep->clist), GTK_SELECTION_SINGLE); */

	if(uat->help) {
		GtkWidget* help_btn;
		rep->bbox = dlg_button_row_new(GTK_STOCK_HELP, GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_CANCEL, NULL);
		help_btn = g_object_get_data(G_OBJECT(rep->bbox),GTK_STOCK_HELP);
		g_signal_connect(help_btn, "clicked", G_CALLBACK(uat_help_cb), uat);
	} else {

		rep->bbox = dlg_button_row_new(GTK_STOCK_OK, GTK_STOCK_APPLY, GTK_STOCK_CANCEL, NULL);
	}	

	move_hbox = gtk_vbutton_box_new();
	gtk_box_pack_start(GTK_BOX(vbox), move_hbox, TRUE, FALSE, 0);

	edit_hbox = gtk_vbutton_box_new();
	gtk_box_pack_end(GTK_BOX(vbox), edit_hbox, TRUE, FALSE, 0);


	rep->bt_down = gtk_button_new_from_stock(GTK_STOCK_GO_DOWN);
	rep->bt_up = gtk_button_new_from_stock(GTK_STOCK_GO_UP);

	gtk_box_pack_start(GTK_BOX(move_hbox), rep->bt_up, TRUE, FALSE, 5);
	gtk_box_pack_start(GTK_BOX(move_hbox), rep->bt_down, TRUE, FALSE, 5);


	rep->bt_new = gtk_button_new_from_stock(GTK_STOCK_NEW);
	rep->bt_edit = gtk_button_new_from_stock(WIRESHARK_STOCK_EDIT);
	rep->bt_copy = gtk_button_new_from_stock(GTK_STOCK_COPY);
	rep->bt_delete = gtk_button_new_from_stock(GTK_STOCK_DELETE);

	gtk_box_pack_end(GTK_BOX(edit_hbox), rep->bt_new, TRUE, FALSE, 5);
	gtk_box_pack_end(GTK_BOX(edit_hbox), rep->bt_edit, TRUE, FALSE, 5);
	gtk_box_pack_end(GTK_BOX(edit_hbox), rep->bt_copy, TRUE, FALSE, 5);
	gtk_box_pack_end(GTK_BOX(edit_hbox), rep->bt_delete, TRUE, FALSE, 5);


	rep->bt_apply = g_object_get_data(G_OBJECT(rep->bbox),GTK_STOCK_APPLY);
	rep->bt_cancel = g_object_get_data(G_OBJECT(rep->bbox),GTK_STOCK_CANCEL);
	rep->bt_ok = g_object_get_data(G_OBJECT(rep->bbox),GTK_STOCK_OK);

	gtk_box_pack_end(GTK_BOX(rep->vbox), rep->bbox, FALSE, FALSE, 0);

	gtk_widget_set_sensitive (rep->bt_up, FALSE);
	gtk_widget_set_sensitive (rep->bt_down, FALSE);
	gtk_widget_set_sensitive (rep->bt_edit, FALSE);
	gtk_widget_set_sensitive (rep->bt_copy, FALSE);
	gtk_widget_set_sensitive (rep->bt_delete, FALSE);


/*	g_signal_connect(rep->selection, "changed", G_CALLBACK(remember_selected_row), uat);*/
	g_signal_connect(rep->list, "row-activated", G_CALLBACK(uat_double_click_cb), uat);
	g_signal_connect(selection, "changed", G_CALLBACK(remember_selected_row), uat);


	g_signal_connect(rep->bt_new, "clicked", G_CALLBACK(uat_new_cb), uat);
	g_signal_connect(rep->bt_edit, "clicked", G_CALLBACK(uat_edit_cb), uat);
	g_signal_connect(rep->bt_copy, "clicked", G_CALLBACK(uat_copy_cb), uat);
	g_signal_connect(rep->bt_delete, "clicked", G_CALLBACK(uat_delete_cb), uat);

	g_signal_connect(rep->bt_up, "clicked", G_CALLBACK(uat_up_cb), uat);
	g_signal_connect(rep->bt_down, "clicked", G_CALLBACK(uat_down_cb), uat);

	g_signal_connect(rep->bt_apply, "clicked", G_CALLBACK(uat_apply_cb), uat);
	g_signal_connect(rep->bt_cancel, "clicked", G_CALLBACK(uat_cancel_cb), uat);
	g_signal_connect(rep->bt_ok, "clicked", G_CALLBACK(uat_ok_cb), uat);

	window_set_cancel_button(rep->window, rep->bt_cancel, NULL);  /* set esc to activate cancel button */

	if (uat->changed) {
		g_signal_connect(GTK_WINDOW(rep->window), "delete_event", G_CALLBACK(unsaved_dialog), uat);
		g_signal_connect(GTK_WINDOW(rep->window), "destroy", G_CALLBACK(unsaved_dialog), uat);
	} else {
		g_signal_connect(GTK_WINDOW(rep->window), "delete_event", G_CALLBACK(uat_window_delete_event_cb), uat);
		g_signal_connect(GTK_WINDOW(rep->window), "destroy", G_CALLBACK(uat_window_delete_event_cb), uat);
	}
	
	gtk_widget_grab_focus(GTK_WIDGET(rep->list));

	gtk_widget_show_all(rep->window);
	window_present(rep->window);

	return rep->window;
}

void uat_window_cb(GtkWidget* u _U_, void* uat) {
	uat_window(uat);
}

