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
#include "capture.h"
#include "capture-pcap-util.h"
#include "capture_opts.h"
#include "capture_ui_utils.h"
#include "simple_dialog.h"
#include <wsutil/file_util.h>

#include "gtk/gui_utils.h"
#include "gtk/color_utils.h"
#include "gtk/recent.h"
#include "gtk/gtkglobals.h"
#include "gtk/main.h"
#include "gtk/menus.h"
#include "gtk/main_welcome.h"
#include "gtk/capture_dlg.h"
#include "gtk/capture_if_dlg.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/help_dlg.h"
#include "gtk/stock_icons.h"
#include "gtk/capture_globals.h"
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
static GdkColor header_bar_bg;
static GdkColor topic_header_bg;
static GdkColor topic_content_bg;
static GdkColor topic_item_idle_bg;
static GdkColor topic_item_entered_bg;

static GtkWidget *welcome_file_panel_vb = NULL;
#ifdef HAVE_LIBPCAP
static GtkWidget *welcome_if_panel_vb = NULL;
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


static GtkWidget *
scroll_box_dynamic_new(GtkBox *child_box, guint max_childs, guint scrollw_y_size) {
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
welcome_item_leave_cb(GtkWidget *eb, GdkEvent *event _U_, gpointer user_data _U_)
{
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_idle_bg);

    return FALSE;
}


/* create a "button widget" */
static GtkWidget *
welcome_button(const gchar *stock_item,
               const gchar * title, const gchar * subtitle, const gchar *tooltip,
			   GtkSignalFunc callback, void *callback_data)
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
    g_signal_connect(eb, "button-press-event", G_CALLBACK(callback), callback_data);

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

static void
welcome_header_set_message(gchar *msg) {
    GString *message;
    time_t secs = time(NULL);
    struct tm *now = localtime(&secs);
    
    message = g_string_new("<span weight=\"bold\" size=\"x-large\" foreground=\"black\">");
    
    if (msg) {
	g_string_append(message, msg);
    } else { /* Use our default header */
	if ((now->tm_mon == 3 && now->tm_mday == 1) || (now->tm_mon == 6 && now->tm_mday == 14)) {
	    g_string_append(message, "Sniffing the glue that holds the Internet together");
	} else {
	    g_string_append(message, prefs.gui_start_title);
	}
    
	if (prefs.gui_version_in_start_page) {
	    g_string_append_printf(message, "</span>\n<span size=\"large\" foreground=\"black\">Version " VERSION "%s",
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
welcome_header_push_msg(gchar *msg) {
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
    formatted_message = g_strdup_printf("<span weight=\"bold\" size=\"x-large\" foreground=\"black\">%s</span>", header);
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
welcome_filename_link_press_cb(GtkWidget *widget _U_, GdkEvent *event _U_, gpointer data)
{
    menu_open_filename(data);

    return FALSE;
}


/* create a "file link widget" */
static GtkWidget *
welcome_filename_link_new(const gchar *filename, GtkWidget **label)
{
    GtkWidget	*w;
    GtkWidget	*eb;
    GString	*str;
    gchar	*str_escaped;
    const unsigned int max = 60;
    int		err;
    struct stat stat_buf;
    GtkTooltips *tooltips;


    tooltips = gtk_tooltips_new();

    /* filename */
    str = g_string_new(filename);

    /* cut max filename length */
    if( (str->len > max) && (str->len-(max) > 5) ) {
        g_string_erase(str, 20, str->len-(max+5));
        g_string_insert(str, 20, " ... ");
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
    err = ws_stat(filename, &stat_buf);
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


#ifdef HAVE_LIBPCAP
/* user clicked on an interface button */
static gboolean
welcome_if_press_cb(GtkWidget *widget _U_, GdkEvent *event _U_, gpointer data)
{
    g_free(global_capture_opts.iface);
    g_free(global_capture_opts.iface_descr);

    global_capture_opts.iface = g_strdup(data);
    global_capture_opts.iface_descr = NULL;
    /* XXX - fix this */
    /*global_capture_opts.iface_descr = get_interface_descriptive_name(global_capture_opts.iface);*/

    /* XXX - remove this? */
    if (global_capture_opts.save_file) {
        g_free(global_capture_opts.save_file);
        global_capture_opts.save_file = NULL;
    }

#ifdef HAVE_AIRPCAP
    airpcap_if_active = get_airpcap_if_from_name(airpcap_if_list, global_capture_opts.iface);
    airpcap_if_selected = airpcap_if_active;
    airpcap_set_toolbar_start_capture(airpcap_if_active);
#endif

    capture_start_cb(NULL, NULL);

    return FALSE;
}


/* create a single interface entry */
static GtkWidget *
welcome_if_new(const if_info_t *if_info, const gchar *user_descr, GdkColor *topic_bg _U_, gpointer interf)
{
    GtkWidget *interface_hb;
    GtkWidget *w;
    GString   *message;
    GtkWidget *eb;


    /* event box */
    eb = gtk_event_box_new();
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_idle_bg);

    g_signal_connect(eb, "enter-notify-event", G_CALLBACK(welcome_item_enter_cb), NULL);
    g_signal_connect(eb, "leave-notify-event", G_CALLBACK(welcome_item_leave_cb), NULL);
    g_signal_connect(eb, "button-press-event", G_CALLBACK(welcome_if_press_cb), interf);

    interface_hb = gtk_hbox_new(FALSE, 5);
    gtk_container_add(GTK_CONTAINER(eb), interface_hb);

    /* icon */
    w = capture_get_if_icon(if_info);
    gtk_box_pack_start(GTK_BOX(interface_hb), w, FALSE, FALSE, 5);

    if (user_descr != NULL)
        message = g_string_new(user_descr);
    else if (if_info->description != NULL)
        message = g_string_new(if_info->description);
    else
        message = g_string_new(if_info->name);

    /* truncate string if it's too long */
    /* (the number of chars is a bit arbitrary, though) */
    if(message->len > 48) {
        g_string_truncate(message, 45);
        g_string_append  (message, " ...");
    }
    g_string_prepend(message, "<span foreground='blue'>");
    g_string_append (message, "</span>");
    w = gtk_label_new(message->str);
    gtk_label_set_markup(GTK_LABEL(w), message->str);
    g_string_free(message, TRUE);

    gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(interface_hb), w, FALSE, FALSE, 0);

    return eb;
}


/* load the list of interfaces */
static void
welcome_if_panel_load(void)
{
  GtkWidget *child_box;
  GtkWidget *interface_hb;

  if_info_t     *if_info;
  GList         *if_list;
  int err;
  gchar         *err_str;
  int           ifs;
  GList         *curr;
  gchar         *user_descr;


  /* LOAD THE INTERFACES */
  if_list = capture_interface_list(&err, &err_str);
  if_list = g_list_sort (if_list, if_list_comparator_alph);
  if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
    g_free(err_str);
    return;
  }

  /* List the interfaces */
  for(ifs = 0; (curr = g_list_nth(if_list, ifs)); ifs++) {
      /*g_string_assign(if_tool_str, "");*/
      if_info = curr->data;

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
        interface_hb = welcome_if_new(if_info, user_descr, &topic_content_bg, g_strdup(if_info->name));
        g_free (user_descr);
      } else {
        interface_hb = welcome_if_new(if_info, NULL, &topic_content_bg, g_strdup(if_info->name));
      }

      child_box = scroll_box_dynamic_add(welcome_if_panel_vb);
      gtk_box_pack_start(GTK_BOX(child_box), interface_hb, FALSE, FALSE, 1);
  }

  free_interface_list(if_list);
}
#endif  /* HAVE_LIBPCAP */

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

	welcome_if_panel_load();
	gtk_widget_show_all(welcome_if_panel_vb);
    }
#endif  /* HAVE_LIBPCAP */
}


/* create the welcome page */
GtkWidget *
welcome_new(void)
{
    GtkWidget *welcome_scrollw;
    GtkWidget *welcome_vb;
    GtkWidget *column_vb;
    GtkWidget *item_hb;
    GtkWidget *w;
    GtkWidget *header;
    GtkWidget *topic_vb;
    GtkWidget *topic_to_fill;
#ifdef HAVE_LIBPCAP
    GtkWidget *if_child_box;
#endif  /* HAVE_LIBPCAP */
    GtkWidget *file_child_box;
    gchar *label_text;
#ifdef _WIN32
    LONG reg_ret;
    DWORD chimney_enabled = 0;
    DWORD ce_size = sizeof(chimney_enabled);
#endif

    /* prepare colors */
    /* header bar background color */
    header_bar_bg.pixel = 0;
    header_bar_bg.red = 154 * 255;
    header_bar_bg.green = 210 * 255;
    header_bar_bg.blue = 229 * 255;
    get_color(&header_bar_bg);

    /* topic header background color */
    topic_header_bg.pixel = 0;
    topic_header_bg.red = 24 * 255;
    topic_header_bg.green = 151 * 255;
    topic_header_bg.blue = 192 * 255;
    get_color(&topic_header_bg);

    /* topic content background color */
    topic_content_bg.pixel = 0;
    topic_content_bg.red = 221 * 255;
    topic_content_bg.green = 226 * 255;
    topic_content_bg.blue = 228 * 255;
    get_color(&topic_content_bg);

    /* topic item idle background color */
    /*topic_item_idle_bg.pixel = 0;
    topic_item_idle_bg.red = 216 * 255;
    topic_item_idle_bg.green = 221 * 255;
    topic_item_idle_bg.blue = 223 * 255;
    get_color(&topic_item_idle_bg);*/

    topic_item_idle_bg = topic_content_bg;

    /* topic item entered color */
    topic_item_entered_bg.pixel = 0;
    topic_item_entered_bg.red = 211 * 255;
    topic_item_entered_bg.green = 216 * 255;
    topic_item_entered_bg.blue = 218 * 255;
    get_color(&topic_item_entered_bg);

    /*topic_item_entered_bg.pixel = 0;
    topic_item_entered_bg.red = 216 * 255;
    topic_item_entered_bg.green = 221 * 255;
    topic_item_entered_bg.blue = 223 * 255;
    get_color(&topic_item_entered_bg);*/

    /*topic_item_entered_bg.pixel = 0;
    topic_item_entered_bg.red = 154 * 255;
    topic_item_entered_bg.green = 210 * 255;
    topic_item_entered_bg.blue = 229 * 255;
    get_color(&topic_item_entered_bg);*/


    welcome_scrollw = scrolled_window_new(NULL, NULL);

    welcome_vb = gtk_vbox_new(FALSE, 0);

    /* header */
    header = welcome_header_new();
    gtk_box_pack_start(GTK_BOX(welcome_vb), header, FALSE, FALSE, 0);

    /* content */
    welcome_hb = gtk_hbox_new(FALSE, 10);
    gtk_container_set_border_width(GTK_CONTAINER(welcome_hb), 10);
    gtk_box_pack_start(GTK_BOX(welcome_vb), welcome_hb, TRUE, TRUE, 0);


    /* column capture */
    column_vb = gtk_vbox_new(FALSE, 10);
    gtk_box_pack_start(GTK_BOX(welcome_hb), column_vb, TRUE, TRUE, 0);

    /* capture topic */
    topic_vb = welcome_topic_new("Capture", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

#ifdef HAVE_LIBPCAP
    item_hb = welcome_button(WIRESHARK_STOCK_CAPTURE_INTERFACES,
        "Interface List",
		"Live list of the capture interfaces (counts incoming packets)",
        "Same as Capture/Interfaces menu or toolbar item",
        G_CALLBACK(capture_if_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    label_text =  g_strdup("<span foreground=\"black\">Start capture on interface:</span>");
    w = gtk_label_new(label_text);
    gtk_label_set_markup(GTK_LABEL(w), label_text);
    g_free (label_text);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0f, 0.0f);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);

    if_child_box = gtk_vbox_new(FALSE, 0);
    /* 8 capture interfaces or 150 pixels height is about the size */
    /* that still fits on a screen of about 1000*700 */
    welcome_if_panel_vb = scroll_box_dynamic_new(GTK_BOX(if_child_box), 8, 150);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), welcome_if_panel_vb, FALSE, FALSE, 0);
    welcome_if_panel_load();

    item_hb = welcome_button(WIRESHARK_STOCK_CAPTURE_OPTIONS,
        "Capture Options",
		"Start a capture with detailed options",
        "Same as Capture/Options menu or toolbar item",
        G_CALLBACK(capture_prep_cb), NULL);
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
	    G_CALLBACK(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_CHIMNEY));
	gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
    }
#endif /* _WIN32 */

    /* capture help topic */
    topic_vb = welcome_topic_new("Capture Help", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
		"How to Capture",
		"Step by step to a successful capture setup",
        topic_online_url(ONLINEPAGE_CAPTURE_SETUP),
        G_CALLBACK(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_CAPTURE_SETUP));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
		"Network Media",
        "Specific information for capturing on: Ethernet, WLAN, ...",
        topic_online_url(ONLINEPAGE_NETWORK_MEDIA),
        G_CALLBACK(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_NETWORK_MEDIA));
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
        G_CALLBACK(file_open_cmd_cb), NULL);
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
    welcome_file_panel_vb = scroll_box_dynamic_new(GTK_BOX(file_child_box), 17, 300);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), welcome_file_panel_vb, FALSE, FALSE, 0);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
        "Sample Captures",
		"A rich assortment of example capture files on the wiki",
        topic_online_url(ONLINEPAGE_SAMPLE_CAPTURES),
        G_CALLBACK(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_SAMPLE_CAPTURES));
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
        G_CALLBACK(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_HOME));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_button(GTK_STOCK_HELP,
        "User's Guide",
		"The User's Guide (local version, if installed)",
        "Locally installed (if installed) otherwise online version",
        G_CALLBACK(topic_menu_cb), GINT_TO_POINTER(HELP_CONTENT));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
        "Security",
		"Work with Wireshark as securely as possible",
        topic_online_url(ONLINEPAGE_SECURITY),
        G_CALLBACK(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_SECURITY));
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
    gtk_widget_show_all(welcome_vb);

    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(welcome_scrollw),
                                          welcome_vb);
    gtk_widget_show_all(welcome_scrollw);

    return welcome_scrollw;
}

