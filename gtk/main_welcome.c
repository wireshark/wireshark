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
#endif
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

/* XXX */
extern gint if_list_comparator_alph (const void *first_arg, const void *second_arg);

static GtkWidget *welcome_hb = NULL;
static GtkWidget *header_lb = NULL;
/* Foreground colors are set using Pango markup */
static GdkColor welcome_bg = { 0, 0xe6e6, 0xe6e6, 0xe6e6 };
static GdkColor header_bar_bg = { 0, 0x1818, 0x5c5c, 0xcaca };
static GdkColor topic_header_bg = { 0, 0x0101, 0x3939, 0xbebe };
static GdkColor topic_content_bg = { 0, 0xffff, 0xffff, 0xffff };
static GdkColor topic_item_idle_bg;
static GdkColor topic_item_entered_bg = { 0, 0xd3d3, 0xd8d8, 0xdada };

static GtkWidget *welcome_file_panel_vb = NULL;
#ifdef HAVE_LIBPCAP
static GtkWidget *welcome_if_panel_vb = NULL;
static GtkWidget *if_view = NULL;
#endif

static GSList *status_messages = NULL;

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
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_entered_bg);

    return FALSE;
}


/* mouse has left this widget - change background color  */
static gboolean
welcome_item_leave_cb(GtkWidget *eb, GdkEventCrossing *event _U_, gpointer user_data _U_)
{
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_idle_bg);

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
    GtkTooltips *tooltips;


    tooltips = gtk_tooltips_new();

    item_hb = gtk_hbox_new(FALSE, 1);

    /* event box (for background color and events) */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), item_hb);
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_idle_bg);
    if(tooltip != NULL) {
        gtk_tooltips_set_tip(tooltips, eb, tooltip, "");
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
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &header_bar_bg);

    item_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(item_vb), item_hb, FALSE, FALSE, 10);

    icon = xpm_to_widget_from_parent(top_level, wssplash_xpm);
    gtk_box_pack_start(GTK_BOX(item_hb), icon, FALSE, FALSE, 10);

    header_lb = gtk_label_new(NULL);
    welcome_header_set_message(NULL);
    gtk_misc_set_alignment (GTK_MISC(header_lb), 0.0f, 0.5f);
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
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_header_bg);

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
    gtk_widget_modify_bg(topic_eb, GTK_STATE_NORMAL, &topic_content_bg);
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


/* create a "file link widget" */
static GtkWidget *
welcome_filename_link_new(const gchar *filename, GtkWidget **label)
{
    GtkWidget   *w;
    GtkWidget   *eb;
    GString     *str;
    gchar       *str_escaped;
    glong        uni_len;
    gsize        uni_start, uni_end;
    const glong  max = 60;
    int          err;
    ws_statb64   stat_buf;
    GtkTooltips *tooltips;


    tooltips = gtk_tooltips_new();

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
    str=g_string_new(str_escaped);
    g_free(str_escaped);

    /*
     * Add file size. We use binary prefixes instead of IEC because that's what
     * most OSes use.
     */
    err = ws_stat64(filename, &stat_buf);
    if(err == 0) {
        if (stat_buf.st_size/1024/1024/1024 > 10) {
            g_string_append_printf(str, " (%" G_GINT64_MODIFIER "d GB)", (gint64) (stat_buf.st_size/1024/1024/1024));
        } else if (stat_buf.st_size/1024/1024 > 10) {
            g_string_append_printf(str, " (%" G_GINT64_MODIFIER "d MB)", (gint64) (stat_buf.st_size/1024/1024));
        } else if (stat_buf.st_size/1024 > 10) {
            g_string_append_printf(str, " (%" G_GINT64_MODIFIER "d KB)", (gint64) (stat_buf.st_size/1024));
        } else {
            g_string_append_printf(str, " (%" G_GINT64_MODIFIER "d Bytes)", (gint64) (stat_buf.st_size));
        }
    } else {
        g_string_append(str, " [not found]");
    }

    /* pango format string */
    if(err == 0) {
        g_string_prepend(str, "<span foreground='blue'>");
        g_string_append(str, "</span>");
    }

    /* label */
    w = gtk_label_new(str->str);
    *label = w;
    gtk_label_set_markup(GTK_LABEL(w), str->str);
    gtk_misc_set_padding(GTK_MISC(w), 5, 2);

    /* event box */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), w);
    gtk_tooltips_set_tip(tooltips, eb, filename, "");
    if(err != 0) {
        gtk_widget_set_sensitive(w, FALSE);
    }

    g_signal_connect(eb, "enter-notify-event", G_CALLBACK(welcome_item_enter_cb), w);
    g_signal_connect(eb, "leave-notify-event", G_CALLBACK(welcome_item_leave_cb), w);
    g_signal_connect(eb, "button-press-event", G_CALLBACK(welcome_filename_link_press_cb), (gchar *) filename);

    g_string_free(str, TRUE);

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
main_welcome_add_recent_capture_files(const char *widget_cf_name)
{
    GtkWidget *w;
    GtkWidget *child_box;
    GtkWidget *label;


    w = welcome_filename_link_new(widget_cf_name, &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_item_idle_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0f, 0.0f);
    child_box = scroll_box_dynamic_add(welcome_file_panel_vb);
    gtk_box_pack_start(GTK_BOX(child_box), w, FALSE, FALSE, 0);
    gtk_widget_show_all(w);
    gtk_widget_show_all(child_box);
}


/* list the interfaces */
void
welcome_if_tree_load(void)
{
#ifdef HAVE_LIBPCAP
    if_info_t     *if_info;
    GList         *if_list;
    int err;
    gchar         *err_str = NULL;
    int           ifs;
    GList         *curr;
    gchar         *user_descr;
    GtkListStore  *store;
    GtkTreeIter   iter;

    /* LOAD THE INTERFACES */
    if_list = capture_interface_list(&err, &err_str);
    if_list = g_list_sort (if_list, if_list_comparator_alph);
    if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
        simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
        g_free(err_str);
        return;
    } else if (err_str) {
        g_free(err_str);
    }
    if (g_list_length(if_list) > 0) {
        store = gtk_list_store_new(1, G_TYPE_STRING);
        /* List the interfaces */
        for(ifs = 0; (curr = g_list_nth(if_list, ifs)); ifs++) {
            /*g_string_assign(if_tool_str, "");*/
            if_info = curr->data;
            gtk_list_store_append (store, &iter);
            /* Continue if capture device is hidden */
            if (prefs_is_capture_device_hidden(if_info->name)) {
                continue;
            }

            user_descr = capture_dev_user_descr_find(if_info->name);
            if (user_descr) {
#ifndef _WIN32
                gchar *comment = user_descr;
                user_descr = g_strdup_printf("%s (%s)", comment, if_info->name);
                g_free (comment);
#endif
                gtk_list_store_set(store, &iter, 0, if_info->name, -1);
                g_free (user_descr);
            } else {
                gtk_list_store_set (store, &iter, 0, if_info->name, -1);
            }
        }
        gtk_tree_view_set_model(GTK_TREE_VIEW(if_view), GTK_TREE_MODEL (store));
    }
    free_interface_list(if_list);
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
static void make_selections_array(GtkTreeModel  *model,
                                  GtkTreePath   *path _U_,
                                  GtkTreeIter   *iter,
                                  gpointer       userdata _U_)
{
  gchar *if_name;
  interface_options interface_opts;
  cap_settings_t cap_settings;

  gtk_tree_model_get (model, iter, 0, &if_name, -1);
  interface_opts.name = g_strdup(if_name); 
  interface_opts.descr = get_interface_descriptive_name(interface_opts.name);
  interface_opts.linktype = capture_dev_user_linktype_find(interface_opts.name);
  interface_opts.cfilter = g_strdup(global_capture_opts.default_options.cfilter);
  interface_opts.has_snaplen = global_capture_opts.default_options.has_snaplen;
  interface_opts.snaplen = global_capture_opts.default_options.snaplen;
  cap_settings = capture_get_cap_settings (interface_opts.name);;
  interface_opts.promisc_mode = global_capture_opts.default_options.promisc_mode;
  interface_opts.buffer_size =  global_capture_opts.default_options.buffer_size;
  interface_opts.monitor_mode = cap_settings.monitor_mode;
#ifdef HAVE_PCAP_REMOTE
  interface_opts.src_type = global_capture_opts.default_options.src_type;
  interface_opts.remote_host = g_strdup(global_capture_opts.default_options.remote_host);
  interface_opts.remote_port = g_strdup(global_capture_opts.default_options.remote_port);
  interface_opts.auth_type = global_capture_opts.default_options.auth_type;
  interface_opts.auth_username = g_strdup(global_capture_opts.default_options.auth_username);
  interface_opts.auth_password = g_strdup(global_capture_opts.default_options.auth_password);
  interface_opts.datatx_udp = global_capture_opts.default_options.datatx_udp;
  interface_opts.nocap_rpcap = global_capture_opts.default_options.nocap_rpcap;
  interface_opts.nocap_local = global_capture_opts.default_options.nocap_local;
#endif
#ifdef HAVE_PCAP_SETSAMPLING
  interface_opts.sampling_method = global_capture_opts.default_options.sampling_method;
  interface_opts.sampling_param  = global_capture_opts.default_options.sampling_param;
#endif
  g_array_append_val(global_capture_opts.ifaces, interface_opts);
}

static void capture_if_start(GtkWidget *w _U_, gpointer data _U_)
{
  GtkTreeSelection *entry;
  GtkWidget*	view;
  gint len;
  interface_options  interface_opts;

  view = g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES);
  entry = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));
  len = gtk_tree_selection_count_selected_rows(entry);
  if (!entry || len==0) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "You didn't specify an interface on which to capture packets.");
    return;
  }
  while (global_capture_opts.ifaces->len > 0) {
    interface_opts = g_array_index(global_capture_opts.ifaces, interface_options, 0);
    global_capture_opts.ifaces = g_array_remove_index(global_capture_opts.ifaces, 0);
    g_free(interface_opts.name);
    g_free(interface_opts.descr);
    g_free(interface_opts.cfilter);
#ifdef HAVE_PCAP_REMOTE
    g_free(interface_opts.remote_host);
    g_free(interface_opts.remote_port);
    g_free(interface_opts.auth_username);
    g_free(interface_opts.auth_password);
#endif
  }
  gtk_tree_selection_selected_foreach(entry, make_selections_array, NULL);

  /* XXX - remove this? */
  if (global_capture_opts.save_file) {
      g_free(global_capture_opts.save_file);
      global_capture_opts.save_file = NULL;
  }
#ifdef HAVE_AIRPCAP
  airpcap_if_active = get_airpcap_if_from_name(airpcap_if_list, interface_opts.name);
  airpcap_if_selected = airpcap_if_active;
  airpcap_set_toolbar_start_capture(airpcap_if_active);
#endif
  capture_start_cb(NULL, NULL);
}
    
void capture_if_cb_prep(GtkWidget *w _U_, gpointer d _U_)
{
  GtkTreeSelection *entry;
  GtkWidget* view;

  view = g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES);
  entry = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));
  if (entry) {
   /* global_capture_opts.number_of_ifaces = gtk_tree_selection_count_selected_rows(entry);*/
    gtk_tree_selection_selected_foreach(entry, make_selections_array, NULL);
  }
  capture_if_cb(NULL, NULL);
}

void capture_opts_cb_prep(GtkWidget *w _U_, gpointer d _U_)
{
  GtkTreeSelection *entry;
  GtkWidget* view;

  view = g_object_get_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES);
  entry = gtk_tree_view_get_selection(GTK_TREE_VIEW(view));
  if (entry) {
    gtk_tree_selection_selected_foreach(entry, make_selections_array, NULL);
  }
  capture_prep_cb(NULL, NULL);
}
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
    GtkWidget *swindow;
    GtkTreeSelection *selection;
    GtkCellRenderer *renderer;
    GtkTreeViewColumn *column;
    GList     *if_list;
    int err;
    gchar *err_str = NULL;
#endif

    /* prepare colors */

    /* "page" background */
    get_color(&welcome_bg);

    /* header bar background color */
    get_color(&header_bar_bg);

    /* topic header background color */
    get_color(&topic_header_bg);

    /* topic content background color */
    get_color(&topic_content_bg);

    topic_item_idle_bg = topic_content_bg;

    /* topic item entered color */
    get_color(&topic_item_entered_bg);

    welcome_scrollw = scrolled_window_new(NULL, NULL);

    welcome_vb = gtk_vbox_new(FALSE, 0);

    welcome_eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(welcome_eb), welcome_vb);
    gtk_widget_modify_bg(welcome_eb, GTK_STATE_NORMAL, &welcome_bg);

    /* header */
    header = welcome_header_new();
    gtk_box_pack_start(GTK_BOX(welcome_vb), header, FALSE, FALSE, 0);

    /* content */
    welcome_hb = gtk_hbox_new(FALSE, 10);
    gtk_container_set_border_width(GTK_CONTAINER(welcome_hb), 10);
    gtk_box_pack_start(GTK_BOX(welcome_vb), welcome_hb, TRUE, TRUE, 0);


    /* column capture */
    column_vb = gtk_vbox_new(FALSE, 10);
    gtk_widget_modify_bg(column_vb, GTK_STATE_NORMAL, &welcome_bg);
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
            welcome_button_callback_helper, capture_if_cb_prep);
        gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
   
        swindow = gtk_scrolled_window_new (NULL, NULL);
        gtk_widget_set_size_request(swindow, FALSE, 100);
        gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(swindow), GTK_SHADOW_IN);
        gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(swindow), GTK_POLICY_AUTOMATIC, GTK_POLICY_AUTOMATIC);
  
        if_view = gtk_tree_view_new ();
        g_object_set(GTK_OBJECT(if_view), "headers-visible", FALSE, NULL);
        g_object_set_data(G_OBJECT(welcome_hb), TREE_VIEW_INTERFACES, if_view);
        renderer = gtk_cell_renderer_text_new();
        column = gtk_tree_view_column_new_with_attributes ("",  
                                               GTK_CELL_RENDERER(renderer),
                                               "text", 0,
                                               NULL);
        gtk_tree_view_append_column(GTK_TREE_VIEW(if_view), column);
        gtk_tree_view_column_set_resizable(gtk_tree_view_get_column(GTK_TREE_VIEW (if_view),0), TRUE );
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
        label_text =  g_strdup("No interface can be used for capturing in\n"
                               "this system with the current configuration.\n\n"
                               "See Capture Help below for details.");
        w = gtk_label_new(label_text);
        gtk_label_set_markup(GTK_LABEL(w), label_text);
        g_free (label_text);
        gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.0f);
        gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);
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
    label_text =  g_strdup("<span foreground=\"black\">Capturing is not compiled into this version of Wireshark!</span>");
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

    return welcome_scrollw;
}

