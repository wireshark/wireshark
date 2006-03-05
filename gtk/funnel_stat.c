/*
 * funnel_stat.c
 *
 * EPAN's funneled GUI mini-API
 *
 * (c) 2006, Luis E. Garcia Ontanon <luis.ontanon@gmail.com>
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
 * Most of the code here has been harvested from other ethereal gtk modules.
 * most from prefs_dlg.c and about_dlg.c
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#include <string.h>

#include <gtk/gtk.h>

#include "../register.h"
#include "../timestats.h"
#include "compat_macros.h"
#include "../simple_dialog.h"
#include "gui_utils.h"
#include "dlg_utils.h"
#include "../file.h"
#include "../globals.h"
#include "../stat_menu.h"
#include "../tap_dfilter_dlg.h"
#include "font_utils.h"
#include "../stat_menu.h"
#include "gui_stat_menu.h"
#include <epan/prefs.h>
#include "column_prefs.h"
#include "prefs_dlg.h"

#include "gtkglobals.h"

#include <epan/funnel.h>

struct _funnel_text_window_t {
	GtkWidget* win;
    GtkWidget* txt;
    GtkWidget* bt_close;
    text_win_close_cb_t close_cb;
    void* close_data;
};

struct _funnel_tree_window_t {
	GtkWidget *win;

};

struct _funnel_node_t {
    void* dummy;
};

static void text_window_cancel_button_cb(GtkWidget *bt _U_, gpointer data) {
    funnel_text_window_t* tw = data;
    
    window_destroy(GTK_WIDGET(tw->win));
    tw->win = NULL;
    
    if (tw->close_cb)
        tw->close_cb(tw->close_data);
}

static void unref_text_win_cancel_bt_cb(GtkWidget *bt _U_, gpointer data) {
    funnel_text_window_t* tw = data;
    
    window_destroy(GTK_WIDGET(tw->win));
    tw->win = NULL;

    if (tw->close_cb)
        tw->close_cb(tw->close_data);
    
    g_free(tw);
}

static gboolean text_window_unref_del_event_cb(GtkWidget *win _U_, GdkEvent *event _U_, gpointer user_data) {
    funnel_text_window_t* tw = user_data;
    
    window_destroy(GTK_WIDGET(tw->win));
    tw->win = NULL;
    
    if (tw->close_cb)
        tw->close_cb(tw->close_data);
    
    g_free(tw);
    
    return TRUE;
}

static gboolean text_window_delete_event_cb(GtkWidget *win _U_, GdkEvent *event _U_, gpointer user_data)
{
    funnel_text_window_t* tw = user_data;
    
    window_destroy(GTK_WIDGET(tw->win));
    tw->win = NULL;

    if (tw->close_cb)
        tw->close_cb(tw->close_data);
    
    return TRUE;
}

static funnel_text_window_t* new_text_window(const gchar* title) {
    funnel_text_window_t* tw = g_malloc(sizeof(funnel_text_window_t));
	GtkWidget *txt_scrollw, *main_vb, *bbox;

    tw->close_cb = NULL;
    tw->close_data = NULL;
    
    tw->win = window_new(GTK_WINDOW_TOPLEVEL,title);
    SIGNAL_CONNECT(tw->win, "delete-event", text_window_delete_event_cb, tw);

    txt_scrollw = scrolled_window_new(NULL, NULL);
    main_vb = gtk_vbox_new(FALSE, 3);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 6);
	gtk_container_add(GTK_CONTAINER(tw->win), main_vb);
    
    gtk_container_add(GTK_CONTAINER(main_vb), txt_scrollw);

#if GTK_MAJOR_VERSION < 2
    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
                                   GTK_POLICY_NEVER, GTK_POLICY_ALWAYS);
    tw->txt = gtk_text_new(NULL, NULL);
    gtk_text_set_editable(GTK_TEXT(tw->txt), FALSE);
    gtk_text_set_word_wrap(GTK_TEXT(tw->txt), TRUE);
    gtk_text_set_line_wrap(GTK_TEXT(tw->txt), TRUE);
#else
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw), 
                                        GTK_SHADOW_IN);

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(txt_scrollw),
                                   GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
    tw->txt = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(tw->txt), FALSE);
    gtk_text_view_set_wrap_mode(GTK_TEXT_VIEW(tw->txt), GTK_WRAP_WORD);
    gtk_text_view_set_cursor_visible(GTK_TEXT_VIEW(tw->txt), FALSE);
    
    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(tw->txt), 4);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(tw->txt), 4);
#endif
    
    
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

    tw->bt_close = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    SIGNAL_CONNECT(tw->bt_close, "clicked", text_window_cancel_button_cb, tw);
    gtk_widget_grab_default(tw->bt_close);

    gtk_container_add(GTK_CONTAINER(txt_scrollw), tw->txt);
#if GTK_MAJOR_VERSION >= 2
    gtk_window_resize(GTK_WINDOW(tw->win),400,300);
#else
    gtk_window_set_default_size(GTK_WINDOW(tw->win), 400, 300);
    gtk_widget_set_usize(tw->win, 400, 300);
#endif
    gtk_widget_show_all(tw->win);
    
    return tw;
}


static void text_window_clear(funnel_text_window_t*  tw)
{
#if GTK_MAJOR_VERSION < 2
    GtkText *txt;

    if (! tw->win) return; 
    
    txt = GTK_TEXT(tw->txt);
    
    gtk_text_set_point(txt, 0);
    /* Keep GTK+ 1.2.3 through 1.2.6 from dumping core - see
http://www.ethereal.com/lists/ethereal-dev/199912/msg00312.html and
http://www.gnome.org/mailing-lists/archives/gtk-devel-list/1999-October/0051.shtml
        for more information */
    gtk_adjustment_set_value(txt->vadj, 0.0);
    gtk_text_forward_delete(txt, gtk_text_get_length(txt));
#else
    GtkTextBuffer *buf;

    if (! tw->win) return; 

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tw->txt));
    
    gtk_text_buffer_set_text(buf, "", 0);
#endif
}


static void text_window_append(funnel_text_window_t*  tw, const char *str)
{
    GtkWidget *txt;
    int nchars = strlen(str);
#if GTK_MAJOR_VERSION >= 2
    GtkTextBuffer *buf;
    GtkTextIter    iter;
#endif
 
    if (! tw->win) return; 

    txt = tw->txt;
    nchars = strlen(str);
    
    
#if GTK_MAJOR_VERSION < 2
	gtk_text_set_point(GTK_TEXT(txt),gtk_text_get_length(GTK_TEXT(txt)));
    gtk_text_insert(GTK_TEXT(txt), user_font_get_regular(), NULL, NULL, str, nchars);
#else
    buf= gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt));
    
    gtk_text_buffer_get_end_iter(buf, &iter);
    gtk_widget_modify_font(GTK_WIDGET(txt), user_font_get_regular());
    
    if (!g_utf8_validate(str, -1, NULL))
        printf("Invalid utf8 encoding: %s\n", str);
    
    gtk_text_buffer_insert(buf, &iter, str, nchars);
#endif
}


static void text_window_set_text(funnel_text_window_t*  tw, const gchar* text)
{
    
    if (! tw->win) return; 
    
#if GTK_MAJOR_VERSION < 2
    gtk_text_freeze(GTK_TEXT(tw->txt));
#endif

    text_window_clear(tw);
    text_window_append(tw, text);

#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(GTK_TEXT(tw->txt));
#endif
}


static void text_window_prepend(funnel_text_window_t*  tw, const char *str _U_) {
    GtkWidget *txt;
    int nchars = strlen(str);
#if GTK_MAJOR_VERSION >= 2
    GtkTextBuffer *buf;
    GtkTextIter    iter;
#endif
	
    if (! tw->win) return; 
	
    txt = tw->txt;
    nchars = strlen(str);
    
    
#if GTK_MAJOR_VERSION < 2
	gtk_text_set_point(GTK_TEXT(txt),0);
    gtk_text_insert(GTK_TEXT(txt), user_font_get_regular(), NULL, NULL, str, nchars);
#else
    buf= gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt));
    
    gtk_text_buffer_get_start_iter(buf, &iter);
    gtk_widget_modify_font(GTK_WIDGET(txt), user_font_get_regular());
    
    if (!g_utf8_validate(str, -1, NULL))
        printf("Invalid utf8 encoding: %s\n", str);
    
    gtk_text_buffer_insert(buf, &iter, str, nchars);
#endif
}

static const gchar* text_window_get_text(funnel_text_window_t*  tw) {
    GtkWidget *txt;
#if GTK_MAJOR_VERSION >= 2
    GtkTextBuffer *buf;
    GtkTextIter    start;
    GtkTextIter    end;
#endif
	
    if (! tw->win) return ""; 

	txt = tw->txt;

#if GTK_MAJOR_VERSION < 2
	/* to do */
	return "";
#else
    buf= gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt));
	gtk_text_buffer_get_start_iter(buf, &start);
	gtk_text_buffer_get_end_iter(buf, &end);
    
	return gtk_text_buffer_get_text(buf, &start, &end, FALSE);
#endif
}

static void text_window_set_close_cb(funnel_text_window_t*  tw, text_win_close_cb_t cb, void* data) {
    tw->close_cb = cb;
    tw->close_data = data;
}

static void text_window_destroy(funnel_text_window_t*  tw) {
    if (tw->win) {
        /*
         * the window is still there and its callbacks refer to this data structure
         * we need to change the callback so that they free tw.
         */
        SIGNAL_CONNECT(tw->bt_close, "clicked", unref_text_win_cancel_bt_cb, tw);
        SIGNAL_CONNECT(tw->win, "delete-event", text_window_unref_del_event_cb, tw);
    } else {
        /*
         * we have no window anymore a human user closed
         * the window already just free the container
         */
        g_free(tw);
    }
}


struct _funnel_dlg_data {
    GtkWidget* win;
    GPtrArray* entries;
    funnel_dlg_cb_t dlg_cb;
    void* data;
};

static gboolean funnel_dlg_cb(GtkWidget *win _U_, gpointer user_data)
{
    struct _funnel_dlg_data* dd = user_data;
    guint i;
    guint len = dd->entries->len;
    GPtrArray* returns = g_ptr_array_new();
    
    for(i=0; i<len; i++) {
        GtkEntry* entry = g_ptr_array_index(dd->entries,i);
        g_ptr_array_add(returns,g_strdup(gtk_entry_get_text(entry)));
    }
    
    g_ptr_array_add(returns,NULL);
    
    if (dd->dlg_cb)
        dd->dlg_cb((gchar**)returns->pdata,dd->data);

    window_destroy(GTK_WIDGET(dd->win));

    g_ptr_array_free(returns,FALSE);

    return TRUE;
}

static void funnel_cancel_btn_cb(GtkWidget *bt _U_, gpointer data) {
    GtkWidget* win = data;
    
    window_destroy(GTK_WIDGET(win));
}

static void funnel_new_dialog(const gchar* title,
                                          const gchar** fieldnames,
                                          funnel_dlg_cb_t dlg_cb,
                                          void* data) {
    GtkWidget *win, *main_tb, *main_vb, *bbox, *bt_cancel, *bt_ok;
    guint i;
    const gchar* fieldname;
    struct _funnel_dlg_data* dd = g_malloc(sizeof(struct _funnel_dlg_data));

    dd->entries = g_ptr_array_new();
    dd->dlg_cb = dlg_cb;
    dd->data = data;
    
    for (i=0;fieldnames[i];i++);

    win = dlg_window_new(title);

    dd->win = win;
    
#if GTK_MAJOR_VERSION >= 2
    gtk_window_resize(GTK_WINDOW(win),400,10*(i+2));
#else
    gtk_window_set_default_size(GTK_WINDOW(win), 400, 10*(i+2));
    gtk_widget_set_usize(win, 400, 10*(i+2));
#endif
    
    main_vb = gtk_vbox_new(TRUE,5);
    gtk_container_add(GTK_CONTAINER(win), main_vb);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 6);

    main_tb = gtk_table_new(i+1, 2, FALSE);
    gtk_box_pack_start(GTK_BOX(main_vb), main_tb, FALSE, FALSE, 0);
    gtk_table_set_row_spacings(GTK_TABLE(main_tb), 10);
    gtk_table_set_col_spacings(GTK_TABLE(main_tb), 15);
    
    for (i = 0; (fieldname = fieldnames[i]) ; i++) {
        GtkWidget *entry, *label;
        
        label = gtk_label_new(fieldname);
        gtk_misc_set_alignment(GTK_MISC(label), 1.0, 0.5);
        gtk_table_attach_defaults(GTK_TABLE(main_tb), label, 0, 1, i+1, i + 2);
        gtk_widget_show(label);

        entry = gtk_entry_new();
        g_ptr_array_add(dd->entries,entry);
        gtk_table_attach_defaults(GTK_TABLE(main_tb), entry, 1, 2, i+1, i + 2);
        gtk_widget_show(entry);
    }

    bbox = dlg_button_row_new(GTK_STOCK_CANCEL,GTK_STOCK_OK, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);
    
    bt_ok = OBJECT_GET_DATA(bbox, GTK_STOCK_OK);
    SIGNAL_CONNECT(bt_ok, "clicked", funnel_dlg_cb, dd);
    gtk_widget_grab_default(bt_ok);
    
    bt_cancel = OBJECT_GET_DATA(bbox, GTK_STOCK_CANCEL);
    SIGNAL_CONNECT(bt_cancel, "clicked", funnel_cancel_btn_cb, win);
    gtk_widget_grab_default(bt_cancel);
    
    gtk_widget_show(main_tb);
    gtk_widget_show(main_vb);
    gtk_widget_show(win);
}


/* XXX: finish this */
static void funnel_logger(const gchar *log_domain _U_,
                          GLogLevelFlags log_level _U_,
                          const gchar *message,
                          gpointer user_data _U_) {
    fputs(message,stderr);
}

static void funnel_retap_packets(void) {
	cf_retap_packets(&cfile, FALSE);
}


static const funnel_ops_t funnel_ops = {
    new_text_window,
    text_window_set_text,
    text_window_append,
    text_window_prepend,
    text_window_clear,
    text_window_get_text,
    text_window_set_close_cb,
    text_window_destroy,
    /*...,*/
    funnel_new_dialog,
    funnel_logger,
	funnel_retap_packets
};


typedef struct _menu_cb_t {
    void (*callback)(gpointer);
    void* callback_data;
    gboolean retap;
} menu_cb_t;

static void our_menu_callback(void* unused _U_, gpointer data) {
    menu_cb_t* mcb = data;
    mcb->callback(mcb->callback_data);
    if (mcb->retap) cf_retap_packets(&cfile, FALSE);
}

static void register_menu_cb(const char *name,
                             REGISTER_STAT_GROUP_E group,
                             void (*callback)(gpointer),
                             gpointer callback_data,
                             gboolean retap) {
    menu_cb_t* mcb = g_malloc(sizeof(menu_cb_t));

    mcb->callback = callback;
    mcb->callback_data = callback_data;
    mcb->retap = retap;
    
    register_stat_menu_item(name, group, our_menu_callback, NULL, NULL, mcb);

}

void initialize_funnel_ops(void) {
    funnel_set_funnel_ops(&funnel_ops);
}

void
register_tap_listener_gtkfunnel(void)
{
    funnel_register_all_menus(register_menu_cb);
}
