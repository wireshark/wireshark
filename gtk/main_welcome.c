/* main_welcome.c
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
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#include <time.h>

#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "../color.h"
#ifdef HAVE_LIBPCAP
#include "capture.h"
#include "capture-pcap-util.h"
#include "capture_opts.h"
#include "capture_ui_utils.h"
#endif
#include "simple_dialog.h"
#include <wsutil/file_util.h>

#include "gtk/gui_utils.h"
#include "gtk/color_utils.h"
#include "gtk/recent.h"
#include "gtk/gtkglobals.h"
#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/main_welcome.h"
#include "gtk/help_dlg.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/stock_icons.h"
#include "gtk/utf8_entities.h"
#ifdef HAVE_LIBPCAP
#include "gtk/capture_dlg.h"
#include "gtk/capture_if_dlg.h"
#include "gtk/capture_globals.h"
#if GTK_CHECK_VERSION(2,18,0)
#include "gtk/webbrowser.h"
#endif
#endif /* HAVE_LIBPCAP */
#include "../image/wssplash-dev.xpm"
#include "../version_info.h"

#ifdef _WIN32
#include <tchar.h>
#include <windows.h>
#endif

#ifdef HAVE_AIRPCAP
#include "airpcap.h"
#include "airpcap_loader.h"
#include "airpcap_gui_utils.h"
#endif
#if defined(HAVE_AIRPCAP)
#include "../image/toolbar/capture_airpcap_16.xpm"
#endif
#if defined(HAVE_PCAP_REMOTE)
#include "gtk/remote_icons.h"
#endif

/* XXX */
extern gint if_list_comparator_alph (const void *first_arg, const void *second_arg);

static GtkWidget *welcome_hb = NULL;
static GtkWidget *header_lb = NULL;
/* Foreground colors are set using Pango markup */
#if GTK_CHECK_VERSION(3,0,0)
static GdkRGBA rgba_welcome_bg = {0.901, 0.901, 0.901, 1.0 };
static GdkRGBA rgba_header_bar_bg = { 0.094, 0.360, 0.792, 1.0 };
static GdkRGBA rgba_topic_header_bg = {  0.004, 0.224, 0.745, 1.0 };
static GdkRGBA rgba_topic_content_bg = { 1, 1, 1, 1.0 };
static GdkRGBA rgba_topic_item_idle_bg;
static GdkRGBA rgba_topic_item_entered_bg =  { 0.827, 0.847, 0.854, 1.0 };
#else
static GdkColor welcome_bg = { 0, 0xe6e6, 0xe6e6, 0xe6e6 };
static GdkColor header_bar_bg = { 0, 0x1818, 0x5c5c, 0xcaca };
static GdkColor topic_header_bg = { 0, 0x0101, 0x3939, 0xbebe };
static GdkColor topic_content_bg = { 0, 0xffff, 0xffff, 0xffff };
static GdkColor topic_item_idle_bg;
static GdkColor topic_item_entered_bg = { 0, 0xd3d3, 0xd8d8, 0xdada };
#endif
static GtkWidget *welcome_file_panel_vb = NULL;
#ifdef HAVE_LIBPCAP
static GtkWidget *welcome_if_panel_vb = NULL;
static GtkWidget *if_view = NULL;
static GtkWidget *swindow;
static GArray *interfaces = NULL;
#endif

static GSList *status_messages = NULL;

static GMutex *recent_mtx;

/* The "scroll box dynamic" is a (complicated) pseudo widget to */
/* place a vertically list of widgets in (currently the interfaces and recent files). */
/* Once this list get's higher than a specified amount, */
/* it is moved into a scrolled_window. */
/* This is all complicated, the scrolled window is a bit ugly, */
/* the sizes might not be the same on all systems, ... */
/* ... but that's the best what we currently have */
#define SCROLL_BOX_CHILD_BOX        "ScrollBoxDynamic_ChildBox"
#define SCROLL_BOX_MAX_CHILDS       "ScrollBoxDynamic_MaxChilds"
#define SCROLL_BOX_SCROLLW_Y_SIZE   "ScrollBoxDynamic_Scrollw_Y_Size"
#define SCROLL_BOX_SCROLLW          "ScrollBoxDynamic_Scrollw"
#define TREE_VIEW_INTERFACES        "TreeViewInterfaces"

static GtkWidget *
scroll_box_dynamic_new(GtkWidget *child_box, guint max_childs, guint scrollw_y_size) {
    GtkWidget * parent_box;


    parent_box = gtk_vbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(parent_box), GTK_WIDGET(child_box), TRUE, TRUE, 0);
    g_object_set_data(G_OBJECT(parent_box), SCROLL_BOX_CHILD_BOX, child_box);
    g_object_set_data(G_OBJECT(parent_box), SCROLL_BOX_MAX_CHILDS, GINT_TO_POINTER(max_childs));
    g_object_set_data(G_OBJECT(parent_box), SCROLL_BOX_SCROLLW_Y_SIZE, GINT_TO_POINTER(scrollw_y_size));
    gtk_widget_show_all(parent_box);

    return parent_box;
}


static GtkWidget *
scroll_box_dynamic_add(GtkWidget *parent_box)
{
    GtkWidget *child_box;
    GtkWidget *scrollw;
    guint max_cnt;
    guint curr_cnt;
    guint scrollw_y_size;
    GList *childs;

    child_box = g_object_get_data(G_OBJECT(parent_box), SCROLL_BOX_CHILD_BOX);
    max_cnt = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(parent_box), SCROLL_BOX_MAX_CHILDS));

    /* get the current number of children */
    childs = gtk_container_get_children(GTK_CONTAINER(child_box));
    curr_cnt = g_list_length(childs);
    g_list_free(childs);

    /* have we just reached the max? */
    if(curr_cnt == max_cnt) {
        /* create the scrolled window */
        /* XXX - there's no way to get rid of the shadow frame - except for creating an own widget :-( */
        scrollw = scrolled_window_new(NULL, NULL);
        scrollw_y_size = GPOINTER_TO_INT(g_object_get_data(G_OBJECT(parent_box), SCROLL_BOX_SCROLLW_Y_SIZE));
        gtk_widget_set_size_request(scrollw, -1, scrollw_y_size);

        g_object_set_data(G_OBJECT(parent_box), SCROLL_BOX_SCROLLW, scrollw);
        gtk_box_pack_start(GTK_BOX(parent_box), scrollw, TRUE, TRUE, 0);

        /* move child_box from parent_box into scrolled window */
        g_object_ref(child_box);
        gtk_container_remove(GTK_CONTAINER(parent_box), child_box);
        gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(scrollw),
                                              child_box);
        gtk_widget_show_all(scrollw);
    }

    return child_box;
}


static GtkWidget *
scroll_box_dynamic_reset(GtkWidget *parent_box)
{
    GtkWidget *child_box, *scrollw;


    child_box = g_object_get_data(G_OBJECT(parent_box), SCROLL_BOX_CHILD_BOX);
    scrollw = g_object_get_data(G_OBJECT(parent_box), SCROLL_BOX_SCROLLW);

    if(scrollw != NULL) {
        /* move the child_box back from scrolled window into the parent_box */
        g_object_ref(child_box);
        gtk_container_remove(GTK_CONTAINER(parent_box), scrollw);
        g_object_set_data(G_OBJECT(parent_box), SCROLL_BOX_SCROLLW, NULL);
        gtk_box_pack_start(GTK_BOX(parent_box), child_box, TRUE, TRUE, 0);
    }

    return child_box;
}


/* mouse entered this widget - change background color */
static gboolean
welcome_item_enter_cb(GtkWidget *eb, GdkEventCrossing *event _U_, gpointer user_data _U_)
{
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(eb, GTK_STATE_NORMAL, &rgba_topic_item_entered_bg);
#else
	gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_entered_bg);
#endif
    return FALSE;
}


/* mouse has left this widget - change background color  */
static gboolean
welcome_item_leave_cb(GtkWidget *eb, GdkEventCrossing *event _U_, gpointer user_data _U_)
{
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(eb, GTK_STATE_NORMAL, &rgba_topic_item_idle_bg);
#else
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_idle_bg);
#endif
    return FALSE;
}


typedef gboolean (*welcome_button_callback_t)  (GtkWidget      *widget,
                                                GdkEventButton *event,
                                                gpointer        user_data);

/* create a "button widget" */
static GtkWidget *
welcome_button(const gchar *stock_item,
               const gchar *title, const gchar *subtitle, const gchar *tooltip,
               welcome_button_callback_t welcome_button_callback, gpointer welcome_button_callback_data)
{
    GtkWidget *eb, *w, *item_hb, *text_vb;
    gchar *formatted_text;

    item_hb = gtk_hbox_new(FALSE, 1);

    /* event box (for background color and events) */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), item_hb);
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(eb, GTK_STATE_NORMAL, &rgba_topic_item_idle_bg);
#else
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_idle_bg);
#endif
    if(tooltip != NULL) {
		gtk_widget_set_tooltip_text(eb, tooltip);
    }

    g_signal_connect(eb, "enter-notify-event", G_CALLBACK(welcome_item_enter_cb), NULL);
    g_signal_connect(eb, "leave-notify-event", G_CALLBACK(welcome_item_leave_cb), NULL);
    g_signal_connect(eb, "button-release-event", G_CALLBACK(welcome_button_callback), welcome_button_callback_data);

    /* icon */
    w = gtk_image_new_from_stock(stock_item, GTK_ICON_SIZE_LARGE_TOOLBAR);
    gtk_box_pack_start(GTK_BOX(item_hb), w, FALSE, FALSE, 5);

    text_vb = gtk_vbox_new(FALSE, 3);

    /* title */
    w = gtk_label_new(title);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.5f);
    formatted_text = g_strdup_printf("<span weight=\"bold\" size=\"x-large\" foreground=\"black\">%s</span>", title);
    gtk_label_set_markup(GTK_LABEL(w), formatted_text);
    g_free(formatted_text);
    gtk_box_pack_start(GTK_BOX(text_vb), w, FALSE, FALSE, 1);

    /* subtitle */
    w = gtk_label_new(subtitle);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.5f);
    formatted_text = g_strdup_printf("<span size=\"small\" foreground=\"black\">%s</span>", subtitle);
    gtk_label_set_markup(GTK_LABEL(w), formatted_text);
    g_free(formatted_text);
    gtk_box_pack_start(GTK_BOX(text_vb), w, FALSE, FALSE, 1);

    gtk_box_pack_start(GTK_BOX(item_hb), text_vb, TRUE, TRUE, 5);

    return eb;
}


/* Hack to handle welcome-button "button-release-event" callback   */
/*  1. Dispatch to desired actual callback                         */
/*  2. Return TRUE for the event callback.                         */
/* user_data: actual (no arg) callback fcn to be invoked.          */
static gboolean
welcome_button_callback_helper(GtkWidget *w, GdkEventButton *event _U_, gpointer user_data)
{
    void (*funct)(GtkWidget *, gpointer) = user_data;
    (*funct)(w, NULL);
    return TRUE;
}


void
welcome_header_set_message(gchar *msg) {
    GString *message;
    time_t secs = time(NULL);
    struct tm *now = localtime(&secs);

    message = g_string_new("<span weight=\"bold\" size=\"x-large\" foreground=\"white\">");

    if (msg) {
        g_string_append(message, msg);
    } else { /* Use our default header */
        if ((now->tm_mon == 3 && now->tm_mday == 1) || (now->tm_mon == 6 && now->tm_mday == 14)) {
            g_string_append(message, "Sniffing the glue that holds the Internet together");
        } else {
            g_string_append(message, prefs.gui_start_title);
        }

        if (prefs.gui_version_in_start_page) {
            g_string_append_printf(message, "</span>\n<span size=\"large\" foreground=\"white\">Version " VERSION "%s",
                                   wireshark_svnversion);
        }
    }

    g_string_append(message, "</span>");

    gtk_label_set_markup(GTK_LABEL(header_lb), message->str);
    g_string_free(message, TRUE);
}


/* create the banner "above our heads" */
static GtkWidget *
welcome_header_new(void)
{
    GtkWidget *item_vb;
    GtkWidget *item_hb;
    GtkWidget *eb;
    GtkWidget *icon;

    item_vb = gtk_vbox_new(FALSE, 0);

    /* colorize vbox */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), item_vb);
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(eb, GTK_STATE_NORMAL, &rgba_header_bar_bg);
#else
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &header_bar_bg);
#endif
    item_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(item_vb), item_hb, FALSE, FALSE, 10);

    /*icon = xpm_to_widget_from_parent(top_level, wssplash_xpm);*/
	icon = xpm_to_widget(wssplash_xpm);
    gtk_box_pack_start(GTK_BOX(item_hb), icon, FALSE, FALSE, 10);

    header_lb = gtk_label_new(NULL);
    welcome_header_set_message(NULL);
    gtk_label_set_selectable(GTK_LABEL(header_lb), TRUE);
    gtk_misc_set_alignment(GTK_MISC(header_lb), 0.0f, 0.5f);
    gtk_box_pack_start(GTK_BOX(item_hb), header_lb, TRUE, TRUE, 5);

    gtk_widget_show_all(eb);

    return eb;
}


void
welcome_header_push_msg(const gchar *msg) {
    gchar *msg_copy = g_strdup(msg);

    status_messages = g_slist_append(status_messages, msg_copy);

    welcome_header_set_message(msg_copy);

    gtk_widget_hide(welcome_hb);
}


void
welcome_header_pop_msg(void) {
    gchar *msg = NULL;

    if (status_messages) {
        g_free(status_messages->data);
        status_messages = g_slist_delete_link(status_messages, status_messages);
    }

    if (status_messages) {
        msg = status_messages->data;
    }

    welcome_header_set_message(msg);

    if (!status_messages) {
        gtk_widget_show(welcome_hb);
    }
}


/* create a "topic header widget" */
static GtkWidget *
welcome_topic_header_new(const char *header)
{
    GtkWidget *w;
    GtkWidget *eb;
    gchar *formatted_message;


    w = gtk_label_new(header);
    formatted_message = g_strdup_printf("<span weight=\"bold\" size=\"x-large\" foreground=\"white\">%s</span>", header);
    gtk_label_set_markup(GTK_LABEL(w), formatted_message);
    g_free(formatted_message);

    /* colorize vbox */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), w);
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(eb, GTK_STATE_NORMAL, &rgba_topic_header_bg);
#else
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_header_bg);
#endif
    return eb;
}


/* create a "topic widget" */
static GtkWidget *
welcome_topic_new(const char *header, GtkWidget **to_fill)
{
    GtkWidget *topic_vb;
    GtkWidget *layout_vb;
    GtkWidget *topic_eb;
    GtkWidget *topic_header;


    topic_vb = gtk_vbox_new(FALSE, 0);

    topic_header = welcome_topic_header_new(header);
    gtk_box_pack_start(GTK_BOX(topic_vb), topic_header, FALSE, FALSE, 0);

    layout_vb = gtk_vbox_new(FALSE, 5);
    gtk_container_set_border_width(GTK_CONTAINER(layout_vb), 10);
    gtk_box_pack_start(GTK_BOX(topic_vb), layout_vb, FALSE, FALSE, 0);

    /* colorize vbox (we need an event box for this!) */
    topic_eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(topic_eb), topic_vb);
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(topic_eb, GTK_STATE_NORMAL, &rgba_topic_content_bg);
#else
    gtk_widget_modify_bg(topic_eb, GTK_STATE_NORMAL, &topic_content_bg);
#endif
    *to_fill = layout_vb;

    return topic_eb;
}


/* a file link was pressed */
static gboolean
welcome_filename_link_press_cb(GtkWidget *widget _U_, GdkEventButton *event _U_, gpointer data)
{
    menu_open_filename(data);

    return FALSE;
}

typedef struct _recent_item_status {
    gchar     *filename;
    GtkWidget *label;
    GObject   *menu_item;
    GString   *str;
    gboolean   stat_done;
    int        err;
    guint      timer;
} recent_item_status;

/*
 * Fetch the status of a file.
 * This function might be called as a thread. We can't use any drawing
 * routines here: http://developer.gnome.org/gdk/2.24/gdk-Threads.html
 */
static void *get_recent_item_status(void *data)
{
    recent_item_status *ri_stat = (recent_item_status *) data;
    ws_statb64 stat_buf;
    int err;

    if (!ri_stat) {
        return NULL;
    }

    /*
     * Add file size. We use binary prefixes instead of IEC because that's what
     * most OSes use.
     */
    err = ws_stat64(ri_stat->filename, &stat_buf);
    g_mutex_lock(recent_mtx);
    ri_stat->err = err;
    if(err == 0) {
        if (stat_buf.st_size/1024/1024/1024 > 10) {
            g_string_append_printf(ri_stat->str, " (%" G_GINT64_MODIFIER "d GB)", (gint64) (stat_buf.st_size/1024/1024/1024));
        } else if (stat_buf.st_size/1024/1024 > 10) {
            g_string_append_printf(ri_stat->str, " (%" G_GINT64_MODIFIER "d MB)", (gint64) (stat_buf.st_size/1024/1024));
        } else if (stat_buf.st_size/1024 > 10) {
            g_string_append_printf(ri_stat->str, " (%" G_GINT64_MODIFIER "d KB)", (gint64) (stat_buf.st_size/1024));
        } else {
            g_string_append_printf(ri_stat->str, " (%" G_GINT64_MODIFIER "d Bytes)", (gint64) (stat_buf.st_size));
        }
        /* pango format string */
        g_string_prepend(ri_stat->str, "<span foreground='blue'>");
        g_string_append(ri_stat->str, "</span>");
    } else {
        g_string_append(ri_stat->str, " [not found]");
    }

    if (!ri_stat->label) { /* The widget went away while we were busy. */
        g_free(ri_stat->filename);
        g_string_free(ri_stat->str, TRUE);
        g_free(ri_stat);
    } else {
        ri_stat->stat_done = TRUE;
    }
    g_mutex_unlock(recent_mtx);

    return NULL;
}

/* Timeout callback for recent items */
static gboolean
update_recent_items(gpointer data)
{
    recent_item_status *ri_stat = (recent_item_status *) data;
    gboolean again = TRUE;

    if (!ri_stat) {
        return FALSE;
    }

    g_mutex_lock(recent_mtx);
    if (ri_stat->stat_done) {
        again = FALSE;
        gtk_label_set_markup(GTK_LABEL(ri_stat->label), ri_stat->str->str);
        if (ri_stat->err == 0) {
            gtk_widget_set_sensitive(ri_stat->label, TRUE);
            gtk_action_set_sensitive((GtkAction *) ri_stat->menu_item, TRUE);
        }
        ri_stat->timer = 0;
    }
    /* Else append some sort of Unicode or ASCII animation to the label? */
    g_mutex_unlock(recent_mtx);
    return again;
}

static void welcome_filename_destroy_cb(GtkWidget *w _U_, gpointer data) {
    recent_item_status *ri_stat = (recent_item_status *) data;

    if (!ri_stat) {
        return;
    }

    g_mutex_lock(recent_mtx);
    if (ri_stat->timer) {
	g_source_remove(ri_stat->timer);
	ri_stat->timer = 0;
    }

    g_object_unref(ri_stat->menu_item);

    if (ri_stat->stat_done) {
	g_free(ri_stat->filename);
	g_string_free(ri_stat->str, TRUE);
	g_free(ri_stat);
    } else {
        ri_stat->label = NULL;
    }
    g_mutex_unlock(recent_mtx);
}

/* create a "file link widget" */
static GtkWidget *
welcome_filename_link_new(const gchar *filename, GtkWidget **label, GObject *menu_item)
{
    GtkWidget   *w;
    GtkWidget   *eb;
    GString     *str;
    gchar       *str_escaped;
    glong        uni_len;
    gsize        uni_start, uni_end;
    const glong  max = 60;
    recent_item_status *ri_stat;

    /* filename */
    str = g_string_new(filename);
    uni_len = g_utf8_strlen(str->str, str->len);

    /* cut max filename length */
    if (uni_len > max) {
        uni_start = g_utf8_offset_to_pointer(str->str, 20) - str->str;
        uni_end = g_utf8_offset_to_pointer(str->str, uni_len - max) - str->str;
        g_string_erase(str, uni_start, uni_end);
        g_string_insert(str, uni_start, " " UTF8_HORIZONTAL_ELLIPSIS " ");
    }

    /* escape the possibly shortened filename before adding pango language */
    str_escaped=g_markup_escape_text(str->str, -1);
    g_string_free(str, TRUE);

    /* label */
    w = gtk_label_new(str_escaped);
    *label = w;
    gtk_misc_set_padding(GTK_MISC(w), 5, 2);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.0f);
    gtk_widget_set_sensitive(w, FALSE);

    ri_stat = g_malloc(sizeof(recent_item_status));
    ri_stat->filename = g_strdup(filename);
    ri_stat->label = w;
    ri_stat->menu_item = menu_item;
    ri_stat->str = g_string_new(str_escaped);
    ri_stat->stat_done = FALSE;
    ri_stat->timer = 0;
    g_object_ref(G_OBJECT(menu_item));
    g_signal_connect(w, "destroy", G_CALLBACK(welcome_filename_destroy_cb), ri_stat);
    g_free(str_escaped);

#if GLIB_CHECK_VERSION(2,31,0)
    /* XXX - Add the filename here? */
    g_thread_new("Recent item status", get_recent_item_status, ri_stat);
#else
    g_thread_create(get_recent_item_status, ri_stat, FALSE, NULL);
#endif
    ri_stat->timer = g_timeout_add(200, update_recent_items, ri_stat);

    /* event box */
    eb = gtk_event_box_new();
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(eb, GTK_STATE_NORMAL, &rgba_topic_item_idle_bg);
#else
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_idle_bg);
#endif
    gtk_container_add(GTK_CONTAINER(eb), w);
    gtk_widget_set_tooltip_text(eb, filename);

    g_signal_connect(eb, "enter-notify-event", G_CALLBACK(welcome_item_enter_cb), w);
    g_signal_connect(eb, "leave-notify-event", G_CALLBACK(welcome_item_leave_cb), w);
    g_signal_connect(eb, "button-press-event", G_CALLBACK(welcome_filename_link_press_cb), (gchar *) filename);

    return eb;
}


/* reset the list of recent files */
void
main_welcome_reset_recent_capture_files(void)
{
    GtkWidget *child_box;
    GList* child_list;
    GList* child_list_item;


    if(welcome_file_panel_vb) {
        child_box = scroll_box_dynamic_reset(welcome_file_panel_vb);
        child_list = gtk_container_get_children(GTK_CONTAINER(child_box));
        child_list_item = child_list;

        while(child_list_item) {
            gtk_container_remove(GTK_CONTAINER(child_box), child_list_item->data);
            child_list_item = g_list_next(child_list_item);
        }

        g_list_free(child_list);
    }
}


/* add a new file to the list of recent files */
void
main_welcome_add_recent_capture_file(const char *widget_cf_name, GObject *menu_item)
{
    GtkWidget *w;
    GtkWidget *child_box;
    GtkWidget *label;


    w = welcome_filename_link_new(widget_cf_name, &label, menu_item);
    child_box = scroll_box_dynamic_add(welcome_file_panel_vb);
    gtk_box_pack_start(GTK_BOX(child_box), w, FALSE, FALSE, 0);
    gtk_widget_show_all(w);
    gtk_widget_show_all(child_box);
}

#ifdef HAVE_LIBPCAP
static gboolean select_current_ifaces(GtkTreeModel  *model,
                                  GtkTreePath   *path,
                                  GtkTreeIter   *iter,
                                  gpointer       userdata)
{
    guint i;
    gchar *if_name;
    gboolean found = FALSE;

    GtkTreeSelection *selection = (GtkTreeSelection *)userdata;
    gtk_tree_model_get (model, iter, IFACE_NAME, &if_name, -1);
    for (i = 0; i < global_capture_opts.ifaces->len; i++) {
        if (strcmp(g_array_index(global_capture_opts.ifaces, interface_options, i).name, if_name) == 0) {
            if (!gtk_tree_selection_path_is_selected(selection, path)) {
              gtk_tree_selection_select_iter(selection, iter);
            }
            found = TRUE;
            break;
        }
    }
    if (!found) {
        gtk_tree_selection_unselect_iter(selection, iter);
    }
    return FALSE;
}

gboolean on_selection_changed(GtkTreeSelection *selection _U_,
                              GtkTreeModel *model,
                              GtkTreePath *path,
                              gboolean path_currently_selected,
                              gpointer data _U_)
{
    GtkTreeIter  iter;
    gchar *if_name;
    interface_options interface_opts;
    guint i, j;
    cap_settings_t    cap_settings;
    gboolean found = FALSE;
    displayed_interface d_interface;

    d_interface.name = NULL;
    d_interface.descr = NULL;
    gtk_tree_model_get_iter (model, &iter, path);
    gtk_tree_model_get (model, &iter, IFACE_NAME, &if_name, -1);
    if (global_capture_opts.ifaces->len > 0) {
        for (i = 0; i < global_capture_opts.ifaces->len; i++) {
            if (strcmp(g_array_index(global_capture_opts.ifaces, interface_options, i).name, if_name) == 0) {
                found = TRUE;
                if (path_currently_selected) {
                    interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, i);
                    global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, i);
                    if (gtk_widget_is_focus(g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES)) && interfaces_dialog_window_present()) {
                        update_selected_interface(g_strdup(interface_opts.name), FALSE);
                    }
                    if (gtk_widget_is_focus(g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES)) && dlg_window_present()) {
                      enable_selected_interface(interface_opts.name, FALSE);
                    }
                    g_free(interface_opts.name);
                    g_free(interface_opts.descr);
                    g_free(interface_opts.cfilter);
#ifdef HAVE_PCAP_REMOTE
                    g_free(interface_opts.remote_host);
                    g_free(interface_opts.remote_port);
                    g_free(interface_opts.auth_username);
                    g_free(interface_opts.auth_password);
#endif
                    break;
                }
            }
        }
    }
    if (!found && !path_currently_selected) {
        for (j = 0; j < interfaces->len; j++) {
            d_interface = g_array_index(interfaces, displayed_interface, j);
            if (strcmp(d_interface.name, if_name) == 0) {
                interface_opts.name = g_strdup(d_interface.name);
                interface_opts.descr = g_strdup(d_interface.descr);
                interface_opts.linktype = capture_dev_user_linktype_find(interface_opts.name);
                interface_opts.cfilter = g_strdup(global_capture_opts.default_options.cfilter);
                interface_opts.has_snaplen = global_capture_opts.default_options.has_snaplen;
                interface_opts.snaplen = global_capture_opts.default_options.snaplen;
                cap_settings = capture_get_cap_settings (interface_opts.name);;
                interface_opts.promisc_mode = global_capture_opts.default_options.promisc_mode;
#if defined(_WIN32) || defined(HAVE_PCAP_CREATE)
                interface_opts.buffer_size =  global_capture_opts.default_options.buffer_size;
#endif
                interface_opts.monitor_mode = cap_settings.monitor_mode;
#ifdef HAVE_PCAP_REMOTE
                if (d_interface.remote_opts.src_type == CAPTURE_IFREMOTE) {
                    interface_opts.src_type = d_interface.remote_opts.src_type;
                    interface_opts.remote_host = g_strdup(d_interface.remote_opts.remote_host_opts.remote_host);
                    interface_opts.remote_port = g_strdup(d_interface.remote_opts.remote_host_opts.remote_port);
                    interface_opts.auth_type = d_interface.remote_opts.remote_host_opts.auth_type;
                    interface_opts.auth_username = g_strdup(d_interface.remote_opts.remote_host_opts.auth_username);
                    interface_opts.auth_password = g_strdup(d_interface.remote_opts.remote_host_opts.auth_password);
                    interface_opts.datatx_udp = d_interface.remote_opts.remote_host_opts.datatx_udp;
                    interface_opts.nocap_rpcap = d_interface.remote_opts.remote_host_opts.nocap_rpcap;
                    interface_opts.nocap_local = d_interface.remote_opts.remote_host_opts.nocap_local;
#ifdef HAVE_PCAP_SETSAMPLING
                    interface_opts.sampling_method = d_interface.remote_opts.sampling_method;
                    interface_opts.sampling_param  = d_interface.remote_opts.sampling_param;
#endif
                } else {
                    interface_opts.src_type = global_capture_opts.default_options.src_type;
                    interface_opts.remote_host = g_strdup(global_capture_opts.default_options.remote_host);
                    interface_opts.remote_port = g_strdup(global_capture_opts.default_options.remote_port);
                    interface_opts.auth_type = global_capture_opts.default_options.auth_type;
                    interface_opts.auth_username = g_strdup(global_capture_opts.default_options.auth_username);
                    interface_opts.auth_password = g_strdup(global_capture_opts.default_options.auth_password);
                    interface_opts.datatx_udp = global_capture_opts.default_options.datatx_udp;
                    interface_opts.nocap_rpcap = global_capture_opts.default_options.nocap_rpcap;
                    interface_opts.nocap_local = global_capture_opts.default_options.nocap_local;
#ifdef HAVE_PCAP_SETSAMPLING
                    interface_opts.sampling_method = global_capture_opts.default_options.sampling_method;
                    interface_opts.sampling_param  = global_capture_opts.default_options.sampling_param;
#endif
                }
#endif

                g_array_append_val(global_capture_opts.ifaces, interface_opts);
                if (gtk_widget_is_focus(g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES)) && interfaces_dialog_window_present()) {
                    update_selected_interface(g_strdup(interface_opts.name), TRUE);
                }
                if (gtk_widget_is_focus(g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES)) && dlg_window_present()) {
                    enable_selected_interface(interface_opts.name, TRUE);
                }
                break;
            }
        }
    }
    return TRUE;
}

static gboolean activate_ifaces(GtkTreeModel  *model,
                                  GtkTreePath   *path _U_,
                                  GtkTreeIter   *iter,
                                  gpointer       userdata)
{
  gchar *if_name;
  GtkWidget *view;
  GtkTreeSelection *selection;
  selected_name_t  *entry = (selected_name_t *)userdata;

  view = g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES);
  selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));
  gtk_tree_model_get (model, iter, IFACE_NAME, &if_name, -1);
  if (strcmp(if_name, entry->name) == 0) {
    if (entry->activate) {
      gtk_tree_selection_select_iter(selection, iter);
    } else {
      gtk_tree_selection_unselect_iter(selection, iter);
    }
    return TRUE;
  }
  return FALSE;
}

void change_interface_selection(gchar* name, gboolean activate)
{
    GtkWidget        *view;
    GtkTreeModel     *model;
    selected_name_t  entry;

    view = g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES);
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(view));
    entry.name = g_strdup(name);
    entry.activate = activate;
    gtk_tree_model_foreach(GTK_TREE_MODEL(model), (GtkTreeModelForeachFunc)(activate_ifaces), (gpointer) &entry);
}

void change_selection_for_all(gboolean enable)
{
  guint i;

  if (interfaces) {
    for (i = 0; i < interfaces->len; i++) {
      change_interface_selection(g_array_index(interfaces, displayed_interface, i).name, enable);
    }
  }
}
#endif

void
select_ifaces(void)
{
#ifdef HAVE_LIBPCAP
    GtkWidget        *view;
    GtkTreeModel     *model;
    GtkTreeSelection *entry;

    if (global_capture_opts.ifaces->len > 0 && swindow) {
        view = g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES);
        model = gtk_tree_view_get_model(GTK_TREE_VIEW(view));
        entry = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));
        gtk_tree_model_foreach(GTK_TREE_MODEL(model), select_current_ifaces, (gpointer) entry);
        gtk_widget_grab_focus(view);
    }
#endif
}

#ifdef HAVE_PCAP_REMOTE
void
add_interface_to_list(gchar *name, gchar *descr, remote_options *remote_opts)
{
    GtkWidget *view, *icon;
    GtkTreeModel *model;
    GtkTreeIter iter;
    gint size;
    gchar *lines;
    displayed_interface d_interface;

    d_interface.name = g_strdup(name);
    d_interface.descr = g_strdup(descr);
    d_interface.remote_opts.src_type = remote_opts->src_type;
    d_interface.remote_opts.remote_host_opts.remote_host = g_strdup(remote_opts->remote_host_opts.remote_host);
    d_interface.remote_opts.remote_host_opts.remote_port = g_strdup(remote_opts->remote_host_opts.remote_port);
    d_interface.remote_opts.remote_host_opts.auth_type = remote_opts->remote_host_opts.auth_type;
    d_interface.remote_opts.remote_host_opts.auth_username = g_strdup(remote_opts->remote_host_opts.auth_username);
    d_interface.remote_opts.remote_host_opts.auth_password = g_strdup(remote_opts->remote_host_opts.auth_password);
    d_interface.remote_opts.remote_host_opts.datatx_udp = remote_opts->remote_host_opts.datatx_udp;
    d_interface.remote_opts.remote_host_opts.nocap_rpcap = remote_opts->remote_host_opts.nocap_rpcap;
    d_interface.remote_opts.remote_host_opts.nocap_local = remote_opts->remote_host_opts.nocap_local;
#ifdef HAVE_PCAP_SETSAMPLING
    d_interface.remote_opts.sampling_method = remote_opts->sampling_method;
    d_interface.remote_opts.sampling_param = remote_opts->sampling_param;
#endif
    icon = pixbuf_to_widget(remote_sat_pb_data);
    d_interface.icon = icon;
    view = g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES);
    model = gtk_tree_view_get_model(GTK_TREE_VIEW(view));
    size = gtk_tree_model_iter_n_children(model, NULL);
    lines = g_strdup_printf("%d", size-1);
    g_array_append_val(interfaces, d_interface);
    if (gtk_tree_model_get_iter_from_string(model, &iter, lines)) {
        gtk_list_store_append (GTK_LIST_STORE(model), &iter);
        gtk_list_store_set(GTK_LIST_STORE(model), &iter, ICON, gtk_image_get_pixbuf(GTK_IMAGE(icon)), IFACE_DESCR, descr, IFACE_NAME, name, -1);
    }
}
#endif

/* list the interfaces */
void
welcome_if_tree_load(void)
{
#ifdef HAVE_LIBPCAP
    if_info_t           *if_info;
    GList               *if_list;
    int                 err;
    guint               i;
    gchar               *err_str = NULL;
    GList               *curr;
    gchar               *user_descr;
    GtkListStore        *store = NULL;
    GtkTreeIter         iter;
    GtkWidget           *icon, *view;
    GtkTreeSelection    *entry;
    displayed_interface d_interface;

    view = g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES);
    entry = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));
    gtk_tree_selection_unselect_all(entry);
    store = gtk_list_store_new(NUMCOLUMNS, GDK_TYPE_PIXBUF, G_TYPE_STRING, G_TYPE_STRING);

    /* LOAD THE INTERFACES */
    if (interfaces && interfaces->len > 0) {
        for (i = 0; i < interfaces->len; i++) {
            d_interface = g_array_index(interfaces, displayed_interface, i);
            gtk_list_store_append (store, &iter);
            gtk_list_store_set (store, &iter, ICON, d_interface.icon, IFACE_DESCR, d_interface.descr, IFACE_NAME, d_interface.name, -1);
        }
    } else {
        interfaces = g_array_new(TRUE, TRUE, sizeof(displayed_interface));
        if_list = capture_interface_list(&err, &err_str);
        if_list = g_list_sort (if_list, if_list_comparator_alph);
        if (if_list == NULL &&
            (err == CANT_GET_INTERFACE_LIST || err == DONT_HAVE_PCAP)) {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
            g_free(err_str);
            return;
        } else if (err_str) {
            g_free(err_str);
        }
        if (g_list_length(if_list) > 0) {
            /* List the interfaces */
            for (curr = g_list_first(if_list); curr; curr = g_list_next(curr)) {
                if_info = curr->data;
                /* Continue if capture device is hidden */
                if (prefs_is_capture_device_hidden(if_info->name)) {
                    continue;
                }
                gtk_list_store_append (store, &iter);
                d_interface.name = g_strdup(if_info->name);
#ifdef HAVE_PCAP_REMOTE
                d_interface.remote_opts.src_type = CAPTURE_IFLOCAL;
#endif
#ifdef HAVE_AIRPCAP
                if (get_airpcap_if_from_name(airpcap_if_list,if_info->name) != NULL)
                    icon = xpm_to_widget(capture_airpcap_16_xpm);
                else
                    icon = capture_get_if_icon(if_info);
#else
                icon = capture_get_if_icon(if_info);
#endif
                d_interface.icon = icon;
                user_descr = capture_dev_user_descr_find(if_info->name);
                if (user_descr) {
#ifndef _WIN32
                    gchar *comment = user_descr;
                    user_descr = g_strdup_printf("%s (%s)", comment, if_info->name);
                    g_free (comment);
#endif
                    gtk_list_store_set(store, &iter, ICON, gtk_image_get_pixbuf(GTK_IMAGE(icon)), IFACE_DESCR, user_descr, IFACE_NAME, if_info->name, -1);
                    d_interface.descr = g_strdup(user_descr);
                    g_free (user_descr);
                } else if (if_info->description) {
                    gtk_list_store_set (store, &iter, ICON, gtk_image_get_pixbuf(GTK_IMAGE(icon)), IFACE_DESCR, if_info->description, IFACE_NAME, if_info->name, -1);
                    d_interface.descr = g_strdup(if_info->description);
                } else {
                    gtk_list_store_set (store, &iter, ICON, gtk_image_get_pixbuf(GTK_IMAGE(icon)), IFACE_DESCR, if_info->name, IFACE_NAME, if_info->name, -1);
                    d_interface.descr = g_strdup(if_info->name);
                }
                g_array_append_val(interfaces, d_interface);
            }
        }
        free_interface_list(if_list);
        gtk_tree_view_set_model(GTK_TREE_VIEW(if_view), GTK_TREE_MODEL (store));
        if (global_capture_opts.ifaces->len > 0) {
            gtk_tree_model_foreach(GTK_TREE_MODEL(store), select_current_ifaces, (gpointer) entry);
            gtk_widget_grab_focus(view);
        }
        gtk_tree_selection_set_select_function(entry, on_selection_changed, NULL, NULL);
    }
#endif  /* HAVE_LIBPCAP */
}


/* reload the list of interfaces */
void
welcome_if_panel_reload(void)
{
#ifdef HAVE_LIBPCAP
    GtkWidget *child_box;
    GList* child_list;
    GList* child_list_item;

    if(welcome_if_panel_vb) {
        child_box = scroll_box_dynamic_reset(welcome_if_panel_vb);
        child_list = gtk_container_get_children(GTK_CONTAINER(child_box));
        child_list_item = child_list;

        while(child_list_item) {
            gtk_container_remove(GTK_CONTAINER(child_box), child_list_item->data);
            child_list_item = g_list_next(child_list_item);
        }

        g_list_free(child_list);
        welcome_if_tree_load();
        gtk_widget_show_all(welcome_if_panel_vb);
    }
#endif  /* HAVE_LIBPCAP */
}

#ifdef HAVE_LIBPCAP
static void capture_if_start(GtkWidget *w _U_, gpointer data _U_)
{
#ifdef HAVE_AIRPCAP
  interface_options interface_opts;
#endif

  if (global_capture_opts.ifaces->len == 0) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "You didn't specify an interface on which to capture packets.");
    return;
  }

  /* XXX - remove this? */
  if (global_capture_opts.save_file) {
      g_free(global_capture_opts.save_file);
      global_capture_opts.save_file = NULL;
  }
#ifdef HAVE_AIRPCAP
  interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
  airpcap_if_active = get_airpcap_if_from_name(airpcap_if_list, interface_opts.name);
  airpcap_if_selected = airpcap_if_active;
  airpcap_set_toolbar_start_capture(airpcap_if_active);
#endif
  capture_start_cb(NULL, NULL);
}
#endif

#ifdef HAVE_LIBPCAP
#if GTK_CHECK_VERSION(2,18,0)
static gboolean
activate_link_cb(GtkLabel *label _U_, gchar *uri, gpointer user_data _U_)
{
	return browser_open_url(uri);
}
#endif
#endif

/* create the welcome page */
GtkWidget *
welcome_new(void)
{
    GtkWidget *welcome_scrollw;
    GtkWidget *welcome_eb;
    GtkWidget *welcome_vb;
    GtkWidget *column_vb;
    GtkWidget *item_hb;
    GtkWidget *w;
    GtkWidget *header;
    GtkWidget *topic_vb;
    GtkWidget *topic_to_fill;
    GtkWidget *file_child_box;
    gchar *label_text;
#ifdef _WIN32
    LONG reg_ret;
    DWORD chimney_enabled = 0;
    DWORD ce_size = sizeof(chimney_enabled);
#endif
#ifdef HAVE_LIBPCAP
    GtkTreeSelection *selection;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
    GList     *if_list;
    int err;
    gchar *err_str = NULL;
#endif

    /* prepare colors */
#if 0
	/* Allocating collor isn't necessary? */

    /* "page" background */
    get_color(&welcome_bg);

    /* header bar background color */
    get_color(&header_bar_bg);

    /* topic header background color */
    get_color(&topic_header_bg);

    /* topic content background color */
    get_color(&topic_content_bg);
#endif
#if GTK_CHECK_VERSION(3,0,0)
    rgba_topic_item_idle_bg = rgba_topic_content_bg;
#else
    topic_item_idle_bg = topic_content_bg;
#endif
#if 0
	/* Allocating collor isn't necessary? */
    /* topic item entered color */
    get_color(&topic_item_entered_bg);
#endif
    welcome_scrollw = scrolled_window_new(NULL, NULL);

    welcome_vb = gtk_vbox_new(FALSE, 0);

    welcome_eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(welcome_eb), welcome_vb);
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(welcome_eb, GTK_STATE_NORMAL, &rgba_welcome_bg);
#else
	gtk_widget_modify_bg(welcome_eb, GTK_STATE_NORMAL, &welcome_bg);
#endif
    /* header */
    header = welcome_header_new();
    gtk_box_pack_start(GTK_BOX(welcome_vb), header, FALSE, FALSE, 0);

    /* content */
    welcome_hb = gtk_hbox_new(FALSE, 10);
    gtk_container_set_border_width(GTK_CONTAINER(welcome_hb), 10);
    gtk_box_pack_start(GTK_BOX(welcome_vb), welcome_hb, TRUE, TRUE, 0);


    /* column capture */
    column_vb = gtk_vbox_new(FALSE, 10);
#if GTK_CHECK_VERSION(3,0,0)
	gtk_widget_override_background_color(column_vb, GTK_STATE_NORMAL, &rgba_welcome_bg);
#else
    gtk_widget_modify_bg(column_vb, GTK_STATE_NORMAL, &welcome_bg);
#endif
    gtk_box_pack_start(GTK_BOX(welcome_hb), column_vb, TRUE, TRUE, 0);

    /* capture topic */
    topic_vb = welcome_topic_new("Capture", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

#ifdef HAVE_LIBPCAP
    if_list = capture_interface_list(&err, &err_str);
    if (g_list_length(if_list) > 0) {
        item_hb = welcome_button(WIRESHARK_STOCK_CAPTURE_INTERFACES,
            "Interface List",
            "Live list of the capture interfaces\n(counts incoming packets)",
            "Same as Capture/Interfaces menu or toolbar item",
            welcome_button_callback_helper, capture_if_cb);
        gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

        swindow = gtk_scrolled_window_new (NULL, NULL);
        gtk_widget_set_size_request(swindow, FALSE, 100);
        gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(swindow), GTK_SHADOW_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(swindow), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);

        if_view = gtk_tree_view_new ();
        g_object_set(G_OBJECT(if_view), "headers-visible", FALSE, NULL);
        g_signal_connect(if_view, "row-activated", G_CALLBACK(options_interface_cb), (gpointer)welcome_hb);
        g_object_set_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES, if_view);
        renderer = gtk_cell_renderer_pixbuf_new();
        column = gtk_tree_view_column_new_with_attributes ("",
                                               GTK_CELL_RENDERER(renderer),
                                               "pixbuf", ICON,
                                               NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(if_view), column);
        renderer = gtk_cell_renderer_text_new();
        column = gtk_tree_view_column_new_with_attributes ("",
                                               GTK_CELL_RENDERER(renderer),
                                               "text", IFACE_DESCR,
                                               NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(if_view), column);
        gtk_tree_view_column_set_resizable(gtk_tree_view_get_column(GTK_TREE_VIEW(if_view), 0), TRUE);
        renderer = gtk_cell_renderer_text_new();
        column = gtk_tree_view_column_new_with_attributes ("",
                                               GTK_CELL_RENDERER(renderer),
                                               "text", IFACE_NAME,
                                               NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(if_view), column);
        gtk_tree_view_column_set_visible(column, FALSE);
        selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(if_view));
        gtk_tree_selection_set_mode(selection, GTK_SELECTION_MULTIPLE);
        item_hb = welcome_button(WIRESHARK_STOCK_CAPTURE_START,
            "Start",
            "Choose one or more interfaces to capture from, then <b>Start</b>",
            "Same as Capture/Interfaces with default options",
            (welcome_button_callback_t)capture_if_start, (gpointer)if_view);
        gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
        welcome_if_tree_load();
        gtk_container_add (GTK_CONTAINER (swindow), if_view);
        gtk_container_add(GTK_CONTAINER(topic_to_fill), swindow);

        item_hb = welcome_button(WIRESHARK_STOCK_CAPTURE_OPTIONS,
                "Capture Options",
                "Start a capture with detailed options",
                "Same as Capture/Options menu or toolbar item",
                welcome_button_callback_helper, capture_prep_cb);
        gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
#ifdef _WIN32
        /* Check for chimney offloading */
        reg_ret = RegQueryValueEx(HKEY_LOCAL_MACHINE,
                                  _T("SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\EnableTCPChimney"),
                                  NULL, NULL, (LPBYTE) &chimney_enabled, &ce_size);
        if (reg_ret == ERROR_SUCCESS && chimney_enabled) {
            item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
                    "Offloading Detected",
                    "TCP Chimney offloading is enabled. You \nmight not capture much data.",
                    topic_online_url(ONLINEPAGE_CHIMNEY),
                    topic_menu_cb, GINT_TO_POINTER(ONLINEPAGE_CHIMNEY));
            gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
        }
#endif /* _WIN32 */
    } else {
    	if (if_list == NULL && err != NO_INTERFACES_FOUND) {
            g_free(err_str);
            if (err == CANT_GET_INTERFACE_LIST) {
                label_text = g_strdup("No interface can be used for capturing in "
                                      "this system with the current configuration.\n"
                                      "\n"
                                      "See Capture Help below for details.");
            } else {
                label_text = g_strdup("WinPcap doesn't appear to be installed.  "
                                      "In order to capture packets, WinPcap "
                                      "must be installed; see\n"
                                      "\n"
#if GTK_CHECK_VERSION(2,18,0)
                                      "        <a href=\"http://www.winpcap.org/\">http://www.winpcap.org/</a>\n"
#else
                                      "        http://www.winpcap.org/\n"
#endif
                                      "\n"
                                      "or the mirror at\n"
                                      "\n"
#if GTK_CHECK_VERSION(2,18,0)
                                      "        <a href=\"http://www.mirrors.wiretapped.net/security/packet-capture/winpcap/\">http://www.mirrors.wiretapped.net/security/packet-capture/winpcap/</a>\n"
#else
                                      "        http://www.mirrors.wiretapped.net/security/packet-capture/winpcap/\n"
#endif
                                      "\n"
                                      "or the mirror at\n"
                                      "\n"
#if GTK_CHECK_VERSION(2,18,0)
                                      "        <a href=\"http://winpcap.cs.pu.edu.tw/\">http://winpcap.cs.pu.edu.tw/</a>\n"
#else
                                      "        http://winpcap.cs.pu.edu.tw/\n"
#endif
                                      "\n"
                                      "for a downloadable version of WinPcap "
                                      "and for instructions on how to install "
                                      "WinPcap.");
            }
        } else {
            label_text = g_strdup("No interface can be used for capturing in "
                                  "this system with the current configuration.\n"
                                  "\n"
                                  "See Capture Help below for details.");
        }
        w = gtk_label_new(label_text);
        gtk_label_set_markup(GTK_LABEL(w), label_text);
        gtk_label_set_line_wrap(GTK_LABEL(w), TRUE);
        g_free (label_text);
        gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.0f);
        gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);
#if GTK_CHECK_VERSION(2,18,0)
        g_signal_connect(w, "activate-link", G_CALLBACK(activate_link_cb), NULL);
#endif
    }

    free_interface_list(if_list);

    /* capture help topic */
    topic_vb = welcome_topic_new("Capture Help", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
        "How to Capture",
        "Step by step to a successful capture setup",
        topic_online_url(ONLINEPAGE_CAPTURE_SETUP),
        topic_menu_cb, GINT_TO_POINTER(ONLINEPAGE_CAPTURE_SETUP));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
        "Network Media",
        "Specific information for capturing on:\nEthernet, WLAN, ...",
        topic_online_url(ONLINEPAGE_NETWORK_MEDIA),
        topic_menu_cb, GINT_TO_POINTER(ONLINEPAGE_NETWORK_MEDIA));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
#else
    label_text =  g_strdup("<span foreground=\"black\">Capturing is not compiled into\nthis version of Wireshark!</span>");
    w = gtk_label_new(label_text);
    gtk_label_set_markup(GTK_LABEL(w), label_text);
    g_free (label_text);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);
#endif  /* HAVE_LIBPCAP */

    /* fill bottom space */
    w = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, TRUE, TRUE, 0);


    /* column files */
    topic_vb = welcome_topic_new("Files", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(welcome_hb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_button(GTK_STOCK_OPEN,
        "Open",
        "Open a previously captured file",
        "Same as File/Open menu or toolbar item",
        welcome_button_callback_helper, file_open_cmd_cb);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    /* prepare list of recent files (will be filled in later) */
    label_text =  g_strdup("<span foreground=\"black\">Open Recent:</span>");
    w = gtk_label_new(label_text);
    gtk_label_set_markup(GTK_LABEL(w), label_text);
    g_free (label_text);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);

    file_child_box = gtk_vbox_new(FALSE, 1);
    /* 17 file items or 300 pixels height is about the size */
    /* that still fits on a screen of about 1000*700 */
    welcome_file_panel_vb = scroll_box_dynamic_new(GTK_WIDGET(file_child_box), 17, 300);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), welcome_file_panel_vb, FALSE, FALSE, 0);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
        "Sample Captures",
        "A rich assortment of example capture files on the wiki",
        topic_online_url(ONLINEPAGE_SAMPLE_CAPTURES),
        topic_menu_cb, GINT_TO_POINTER(ONLINEPAGE_SAMPLE_CAPTURES));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    /* fill bottom space */
    w = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, TRUE, TRUE, 0);


    /* column online */
    column_vb = gtk_vbox_new(FALSE, 10);
    gtk_box_pack_start(GTK_BOX(welcome_hb), column_vb, TRUE, TRUE, 0);

    /* topic online */
    topic_vb = welcome_topic_new("Online", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_button(GTK_STOCK_HOME,
        "Website",
        "Visit the project's website",
        topic_online_url(ONLINEPAGE_HOME),
        topic_menu_cb, GINT_TO_POINTER(ONLINEPAGE_HOME));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

#ifdef HHC_DIR
    item_hb = welcome_button(GTK_STOCK_HELP,
        "User's Guide",
        "The User's Guide "
        "(local version, if installed)",
        "Locally installed (if installed) otherwise online version",
        topic_menu_cb, GINT_TO_POINTER(HELP_CONTENT));
#else
    item_hb = welcome_button(GTK_STOCK_HELP,
        "User's Guide",
        "The User's Guide "
        "(online version)",
        topic_online_url(ONLINEPAGE_USERGUIDE),
        topic_menu_cb, GINT_TO_POINTER(ONLINEPAGE_USERGUIDE));
#endif
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
        "Security",
        "Work with Wireshark as securely as possible",
        topic_online_url(ONLINEPAGE_SECURITY),
        topic_menu_cb, GINT_TO_POINTER(ONLINEPAGE_SECURITY));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

#if 0
    /* XXX - add this, once the Windows update functionality is implemented */
    /* topic updates */
    topic_vb = welcome_topic_new("Updates", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    label_text =  g_strdup("<span foreground=\"black\">No updates available!</span>");
    w = gtk_label_new(label_text);
    gtk_label_set_markup(GTK_LABEL(w), label_text);
    g_free (label_text);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, TRUE, TRUE, 0);
#endif


    /* the end */
    gtk_widget_show_all(welcome_eb);

    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(welcome_scrollw),
                                          welcome_eb);
    gtk_widget_show_all(welcome_scrollw);

#if GLIB_CHECK_VERSION(2,31,0)
    recent_mtx = g_malloc(sizeof(GMutex));
    g_mutex_init(recent_mtx);
#else
    recent_mtx = g_mutex_new();
#endif

    return welcome_scrollw;
}

GtkWidget* get_welcome_window(void)
{
  return welcome_hb;
}

#ifdef HAVE_LIBPCAP
displayed_interface get_interface_data(gint index)
{
  return g_array_index(interfaces, displayed_interface, index);
}
#endif
