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
#include "filter_dlg.h"
#include "../stat_menu.h"
#include "../tap_dfilter_dlg.h"
#include "font_utils.h"
#include "../stat_menu.h"
#include "gui_stat_menu.h"

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

struct _funnel_dialog_t {
    void* dummy;
};

static void text_window_cancel_button_cb(GtkWidget *bt _U_, gpointer data) {
    funnel_text_window_t* tw = data;
    
    window_destroy(GTK_WIDGET(tw->win));
    tw->win = NULL;
    
    tw->close_cb(tw->close_data);
}

static void unref_text_win_cancel_bt_cb(GtkWidget *bt _U_, gpointer data) {
    funnel_text_window_t* tw = data;
    
    window_destroy(GTK_WIDGET(tw->win));
    tw->win = NULL;

    tw->close_cb(tw->close_data);
    
    g_free(tw);
    
}

static text_window_delete_event_cb(GtkWidget *win, GdkEvent *event _U_, gpointer user_data)
{
    funnel_text_window_t* tw = user_data;
    window_destroy(win);
    tw->close_cb(tw->close_data);
    return TRUE;
}

static funnel_text_window_t* new_text_window(const gchar* title) {
    funnel_text_window_t* tw = g_malloc(sizeof(funnel_text_window_t));
	GtkWidget *txt_scrollw, *main_vb, *bbox;

    tw->win = window_new(GTK_WINDOW_TOPLEVEL,title);
    SIGNAL_CONNECT(tw->win, "delete-event", text_window_delete_event_cb, tw);

    txt_scrollw = scrolled_window_new(NULL, NULL);
    main_vb = gtk_vbox_new(FALSE, 3);
	gtk_container_border_width(GTK_CONTAINER(main_vb), 12);
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
    /* XXX: there seems to be no way to add a small border *around* the whole text,
        * so the text will be "bump" against the edges.
        * the following is only working for left and right edges,
        * there is no such thing for top and bottom :-( */
/*    gtk_text_view_set_left_margin(GTK_TEXT_VIEW(tw->txt), 4);
    gtk_text_view_set_right_margin(GTK_TEXT_VIEW(tw->txt), 4);*/
#endif
    
    
    bbox = dlg_button_row_new(GTK_STOCK_CLOSE, NULL);
	gtk_box_pack_start(GTK_BOX(main_vb), bbox, FALSE, FALSE, 0);

    tw->bt_close = OBJECT_GET_DATA(bbox, GTK_STOCK_CLOSE);
    SIGNAL_CONNECT(tw->bt_close, "clicked", text_window_cancel_button_cb, tw);
    gtk_widget_grab_default(tw->bt_close);

    gtk_container_add(GTK_CONTAINER(txt_scrollw), tw->txt);
    gtk_window_resize(GTK_WINDOW(tw->win),400,300);
    gtk_widget_show_all(tw->win);
    
    return tw;
}


static void text_window_clear(funnel_text_window_t*  tw)
{
#if GTK_MAJOR_VERSION < 2
    GtkText *txt;

    if (! tw->win) return; 
    
    txt = tw->txt;
    
    gtk_text_set_point(txt, 0);
    /* Keep GTK+ 1.2.3 through 1.2.6 from dumping core - see
http://www.ethereal.com/lists/ethereal-dev/199912/msg00312.html and
http://www.gnome.org/mailing-lists/archives/gtk-devel-list/1999-October/0051.shtml
        for more information */
    gtk_adjustment_set_value(txt->vadj, 0.0);
    gtk_text_forward_delete(txt, gtk_text_get_length(txt));
#else
    if (! tw->win) return; 

    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(tw->txt));
    
    gtk_text_buffer_set_text(buf, "", 0);
#endif
}


static void text_window_append(funnel_text_window_t*  tw, const char *str)
{
    GtkWidget *txt;
    int nchars = strlen(str);
 
    if (! tw->win) return; 

    txt = tw->txt;
    nchars = strlen(str);
    
    
#if GTK_MAJOR_VERSION < 2
    gtk_text_insert(GTK_TEXT(txt), user_font_get_regular(), NULL, NULL, str, nchars);
#else
    GtkTextBuffer *buf= gtk_text_view_get_buffer(GTK_TEXT_VIEW(txt));
    GtkTextIter    iter;
    
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
    gtk_text_freeze(tw->txt);
#endif

    text_window_clear(tw);
    text_window_append(tw, text);

#if GTK_MAJOR_VERSION < 2
    gtk_text_thaw(tw->txt);
#endif
}


static void text_window_prepend(funnel_text_window_t*  tw, const char *str _U_) {
    if (! tw->win) return; 

}

static const gchar* text_window_get_text(funnel_text_window_t*  tw) {

    if (! tw->win) return ""; 

    return "";
}

static void text_window_set_close_cb(funnel_text_window_t*  tw, text_win_close_cb_t cb, void* data) {
    tw->close_cb = cb;
    tw->close_data = data;
}

static void text_window_destroy(funnel_text_window_t*  tw) {
    /*
     * XXX: This way Lua's garbage collector might destroy the window.
     * Here we need to change the callbacks for closing the window so that
     * the window can live after Lua has destroyed it and we do not leak the window object.
     */
    if (tw->win) {
        /*
         * the window is still there and its callbacks refer to this data structure
         * we need to change the callback so that they free tw.
         */
        SIGNAL_CONNECT(tw->bt_close, "clicked", unref_text_win_cancel_bt_cb, tw);
    } else {
        /*
         * we have no window anymore a human user closed
         * the window already just free the container
         */
        g_free(tw);
    }
}

static const funnel_ops_t ops = {
    new_text_window,
    text_window_set_text,
    text_window_append,
    text_window_prepend,
    text_window_clear,
    text_window_get_text,
    text_window_set_close_cb,
    text_window_destroy
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

void
register_tap_listener_gtkfunnel(void)
{
    funnel_set_funnel_ops(&ops);
    funnel_register_all_menus(register_menu_cb);
}
