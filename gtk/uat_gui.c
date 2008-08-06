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
	GtkWidget* clist;
	GtkWidget* bbox;
	GtkWidget* bt_new;
	GtkWidget* bt_edit;
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
			
			out = ep_strdup_printf(s->str);
			
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
	guint rownum;
	guint colnum;

	if (! uat->rep) return;

	gtk_clist_freeze(GTK_CLIST(uat->rep->clist));

	for ( colnum = 0; colnum < uat->ncols; colnum++ )
		g_ptr_array_add(a,fld_tostr(rec,&(f[colnum])));

	rownum = gtk_clist_append(GTK_CLIST(uat->rep->clist), (gchar**)a->pdata);
	gtk_clist_set_row_data(GTK_CLIST(uat->rep->clist), rownum, rec);

	gtk_clist_thaw(GTK_CLIST(uat->rep->clist));

	g_ptr_array_free(a,TRUE);
}

static void reset_row(uat_t* uat, guint idx) {
	void* rec = UAT_INDEX_PTR(uat,idx);
	uat_field_t* f = uat->fields;
	guint colnum;

	if (! uat->rep) return;

	gtk_clist_freeze(GTK_CLIST(uat->rep->clist));
	
	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		gtk_clist_set_text(GTK_CLIST(uat->rep->clist), idx, colnum, fld_tostr(rec,&(f[colnum])));
	}
	
	gtk_clist_thaw(GTK_CLIST(uat->rep->clist));

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
				len = strlen(text);
				break;
			case PT_TXTMOD_HEXBYTES: {
				text = gtk_entry_get_text(GTK_ENTRY(e));

				text = (void*) unhexbytes(text, strlen(text), &len, &err);

				if (err) {
					err = ep_strdup_printf("error in field '%s': %s",f[colnum].name,err);
					goto on_failure;
				}

				break;
			}
			case PT_TXTMOD_ENUM: {
				text = *(char**)e;
				text = text ? text : "";
				len = strlen(text);
				break;
			}
			default:
				g_assert_not_reached();
				return FALSE;
		}


		if (f[colnum].cb.chk) {
			if (! f[colnum].cb.chk(dd->rec, text, len, f[colnum].cbdata.chk, f[colnum].fld_data, &err)) {
				err = ep_strdup_printf("error in field '%s': %s",f[colnum].name,err);
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

	set_buttons(dd->uat,-1);

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

struct _fld_menu_item_data_t {
	const char* text;
	char const** valptr;
};

static void fld_menu_item_cb(GtkMenuItem *menuitem _U_, gpointer user_data) {
	struct _fld_menu_item_data_t* md = user_data;
	
	*(md->valptr) = md->text;
}

static void fld_menu_item_destroy_cb(GtkMenuItem *menuitem _U_, gpointer user_data) {
	g_free(user_data);
}

static void uat_edit_dialog(uat_t* uat, gint row) {
	GtkWidget *win, *main_tb, *main_vb, *bbox, *bt_cancel, *bt_ok;
	struct _uat_dlg_data* dd = g_malloc(sizeof(struct _uat_dlg_data));
	uat_field_t* f = uat->fields;
	guint colnum;
	GtkTooltips *tooltips;

	tooltips = gtk_tooltips_new();
	
	dd->entries = g_ptr_array_new();
	dd->win = dlg_conf_window_new(ep_strdup_printf("%s: %s", uat->name, (row == -1 ? "New" : "Edit")));
	dd->uat = uat;
	dd->rec = row < 0 ? g_malloc0(uat->record_size) : UAT_INDEX_PTR(uat,row);
	dd->is_new = row < 0 ? TRUE : FALSE;
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

	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		GtkWidget *entry, *label, *event_box;
		char* text = fld_tostr(dd->rec,&(f[colnum]));

		event_box = gtk_event_box_new();

		label = gtk_label_new(f[colnum].name);
		if (f[colnum].desc != NULL)
			gtk_tooltips_set_tip(tooltips, event_box, f[colnum].desc, NULL);

		gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
		gtk_table_attach_defaults(GTK_TABLE(main_tb), event_box, 0, 1, colnum+1, colnum + 2);
		gtk_container_add(GTK_CONTAINER(event_box), label);

		switch(f[colnum].mode) {
			case PT_TXTMOD_STRING:
			case PT_TXTMOD_HEXBYTES: {
				entry = gtk_entry_new();
				g_ptr_array_add(dd->entries,entry);
				gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2, colnum+1, colnum + 2);
				if (! dd->is_new) {
					gtk_entry_set_text(GTK_ENTRY(entry),text);
				}
				break;
			}
			case PT_TXTMOD_ENUM: {
				GtkWidget *menu, *option_menu;
				int menu_index, index;
				const value_string* enum_vals = f[colnum].fld_data;
				void* valptr = g_malloc0(sizeof(void*));

				menu = gtk_menu_new();
				menu_index = -1;
				for (index = 0; enum_vals[index].strptr != NULL; index++) {
					struct _fld_menu_item_data_t* md = g_malloc(sizeof(struct _fld_menu_item_data_t));
					const char* str = enum_vals[index].strptr;
					GtkWidget* menu_item = gtk_menu_item_new_with_label(str);
					
					md->text = str;
					md->valptr = valptr;
					
					gtk_menu_shell_append(GTK_MENU_SHELL(menu), menu_item);
					
					if ( g_str_equal(str, text) ) {
						menu_index = index;
						*((char const**)valptr) = str;
					}

					g_signal_connect(menu_item, "activate", G_CALLBACK(fld_menu_item_cb), md);
					g_signal_connect(menu_item, "destroy", G_CALLBACK(fld_menu_item_destroy_cb), md);
				}

				g_ptr_array_add(dd->entries,valptr);
				g_ptr_array_add(dd->tobe_freed,valptr);

				/* Create the option menu from the menu */
				option_menu = gtk_option_menu_new();
				gtk_option_menu_set_menu(GTK_OPTION_MENU(option_menu), menu);

				/* Set its current value to the variable's current value */
				if (menu_index != -1)
					gtk_option_menu_set_history(GTK_OPTION_MENU(option_menu), menu_index);

				gtk_table_attach_defaults(GTK_TABLE(main_tb), option_menu, 1, 2, colnum+1, colnum + 2);

				break;
			}
			default:
				g_assert_not_reached();
				return;
		}
	}
	
	bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_OK, NULL);
	gtk_box_pack_end(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

	bt_ok = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_OK);
	g_signal_connect(bt_ok, "clicked", G_CALLBACK(uat_dlg_cb), dd);

	bt_cancel = g_object_get_data(G_OBJECT(bbox), GTK_STOCK_CANCEL);
	g_signal_connect(bt_cancel, "clicked", G_CALLBACK(uat_cancel_dlg_cb), dd);
	window_set_cancel_button(win, bt_cancel, NULL);

	gtk_widget_show_all(win);
}

struct _uat_del {
	GtkWidget *win;
	uat_t* uat;
	gint idx;
};

static void uat_del_cb(GtkButton *button _U_, gpointer u) {
	struct _uat_del* ud = u;

	uat_remove_record_idx(ud->uat, ud->idx);

	if (ud->uat->rep)
		gtk_clist_remove(GTK_CLIST(ud->uat->rep->clist),ud->idx);

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

		label = gtk_label_new(f[colnum].name);
		gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
		gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, colnum+1, colnum + 2);
		
		label = gtk_label_new(text);
		gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
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

	uat_edit_dialog(uat, -1);
}

static void uat_edit_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;

	if (! uat->rep) return;

	uat_edit_dialog(uat, uat->rep->selected);
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
		if (rep) g_free(rep);
	}
	return TRUE;
}

static void uat_up_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	guint row = uat->rep->selected;

	g_assert(row > 0);

	uat_swap(uat,row,row-1);
	gtk_clist_swap_rows(GTK_CLIST(uat->rep->clist),row,row-1);

	uat->changed = TRUE;

	row -= 1;
	uat->rep->selected = row;
	set_buttons(uat,row);
}

static void uat_down_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	guint row = uat->rep->selected;

	g_assert(row < *uat->nrows_p - 1);

	uat_swap(uat,row,row+1);
	gtk_clist_swap_rows(GTK_CLIST(uat->rep->clist),row,row+1);

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

		if (cfile.state == FILE_READ_DONE) cf_reload(&cfile);
	}

	g_signal_handlers_disconnect_by_func(uat->rep->window, uat_window_delete_event_cb, uat);
	g_signal_handlers_disconnect_by_func(uat->rep->window, unsaved_dialog, uat);
	gtk_widget_destroy(uat->rep->window);
	g_free(uat->rep);
	uat->rep = NULL;
}

static void uat_apply_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;

	uat_window_delete_event_cb(NULL,NULL,uat);

	if (uat->changed && cfile.state == FILE_READ_DONE)
		cf_reload(&cfile);
}

static void uat_ok_cb(GtkButton *button _U_, gpointer u) {
	uat_t* uat = u;
	gchar* err = NULL;

	if (uat->changed) {
		uat_save(uat,&err);

		if (err) {
			report_failure("Error while saving %s: %s",uat->name,err);
		}

		if (cfile.state == FILE_READ_DONE) cf_reload(&cfile);
	}

	g_signal_handlers_disconnect_by_func(uat->rep->window, uat_window_delete_event_cb, uat);
	g_signal_handlers_disconnect_by_func(uat->rep->window, unsaved_dialog, uat);
	gtk_widget_destroy(uat->rep->window);
	g_free(uat->rep);
	uat->rep = NULL;
}



static void remember_selected_row(GtkCList *clist _U_, gint row, gint column _U_, GdkEvent *event _U_, gpointer u) {
	uat_t* uat = u;

	uat->rep->selected = row;

	gtk_widget_set_sensitive (uat->rep->bt_edit, TRUE);
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
	GtkWidget *hbox, *vbox, *move_hbox, *edit_hbox;

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

	rep->clist = gtk_clist_new(uat->ncols);
	gtk_container_add(GTK_CONTAINER(rep->scrolledwindow), rep->clist);
	gtk_box_pack_start(GTK_BOX(hbox), rep->scrolledwindow, TRUE, TRUE, 0);

	for ( colnum = 0; colnum < uat->ncols; colnum++ ) {
		gtk_clist_set_column_title(GTK_CLIST(rep->clist), colnum, f[colnum].name);
		gtk_clist_set_column_auto_resize(GTK_CLIST(rep->clist), colnum, TRUE);
	}

	gtk_clist_column_titles_show(GTK_CLIST(rep->clist));
	gtk_clist_freeze(GTK_CLIST(rep->clist));

	for ( i = 0 ; i < *(uat->nrows_p); i++ ) {
		append_row(uat, i);
	}

	gtk_clist_thaw(GTK_CLIST(rep->clist));

/*	rep->selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(rep->clist)); 
	gtk_tree_selection_set_mode(rep->selection, GTK_SELECTION_SINGLE);
*/
    gtk_clist_set_selection_mode(GTK_CLIST(rep->clist), GTK_SELECTION_SINGLE);

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
	rep->bt_delete = gtk_button_new_from_stock(GTK_STOCK_DELETE);

	gtk_box_pack_end(GTK_BOX(edit_hbox), rep->bt_new, TRUE, FALSE, 5);
	gtk_box_pack_end(GTK_BOX(edit_hbox), rep->bt_edit, TRUE, FALSE, 5);
	gtk_box_pack_end(GTK_BOX(edit_hbox), rep->bt_delete, TRUE, FALSE, 5);


	rep->bt_apply = g_object_get_data(G_OBJECT(rep->bbox),GTK_STOCK_APPLY);
	rep->bt_cancel = g_object_get_data(G_OBJECT(rep->bbox),GTK_STOCK_CANCEL);
	rep->bt_ok = g_object_get_data(G_OBJECT(rep->bbox),GTK_STOCK_OK);

	gtk_box_pack_end(GTK_BOX(rep->vbox), rep->bbox, FALSE, FALSE, 0);

	gtk_widget_set_sensitive (rep->bt_up, FALSE);
	gtk_widget_set_sensitive (rep->bt_down, FALSE);
	gtk_widget_set_sensitive (rep->bt_edit, FALSE);
	gtk_widget_set_sensitive (rep->bt_delete, FALSE);


/*	g_signal_connect(rep->selection, "changed", G_CALLBACK(remember_selected_row), uat);*/
	g_signal_connect(rep->clist, "select-row", G_CALLBACK(remember_selected_row), uat);


	g_signal_connect(rep->bt_new, "clicked", G_CALLBACK(uat_new_cb), uat);
	g_signal_connect(rep->bt_edit, "clicked", G_CALLBACK(uat_edit_cb), uat);
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
	
	gtk_widget_grab_focus(rep->clist);

	gtk_widget_show_all(rep->window);
	window_present(rep->window);

	return rep->window;
}

void uat_window_cb(GtkWidget* u _U_, void* uat) {
	uat_window(uat);
}

