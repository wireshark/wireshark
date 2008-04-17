/* main_welcome.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
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


#include <gtk/gtk.h>

#include <epan/prefs.h>

#include "../color.h"
#include "capture.h"
#include "capture-pcap-util.h"
#include "capture_opts.h"
#include "simple_dialog.h"
#include "wiretap/file_util.h"

#include "gtk/gui_utils.h"
#include "gtk/color_utils.h"
#include "gtk/recent.h"
#include "gtk/gtkglobals.h"
#include "gtk/main.h"
#include "gtk/main_menu.h"
#include "gtk/main_welcome.h"
#include "gtk/capture_dlg.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/help_dlg.h"
#include "gtk/stock_icons.h"




/* XXX - There seems to be some disagreement about if and how this feature should be implemented.
   As I currently don't have the time to continue this, it's temporarily disabled. - ULFL */
#define SHOW_WELCOME_PAGE

#ifdef SHOW_WELCOME_PAGE
#include "../image/wssplash.xpm"
#endif


#ifdef SHOW_WELCOME_PAGE


/* XXX */
extern gint if_list_comparator_alph (const void *first_arg, const void *second_arg);


GdkColor header_bar_bg;
GdkColor topic_header_bg;
GdkColor topic_content_bg;
GdkColor topic_item_idle_bg;
GdkColor topic_item_entered_bg;

GtkWidget *welcome_file_panel_vb = NULL;



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
GtkWidget *
welcome_button(const gchar *stock_item, const gchar * title, const gchar * subtitle,
			 GtkSignalFunc callback, void *callback_data)
{
    GtkWidget *eb, *w, *item_hb, *text_vb;
    gchar *formatted_text;


    item_hb = gtk_hbox_new(FALSE, 1);

    /* event box (for background color and events) */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), item_hb);
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_idle_bg);

    g_signal_connect(eb, "enter-notify-event", G_CALLBACK(welcome_item_enter_cb), NULL);
    g_signal_connect(eb, "leave-notify-event", G_CALLBACK(welcome_item_leave_cb), NULL);
    g_signal_connect(eb, "button-press-event", G_CALLBACK(callback), callback_data);

    /* icon */
    w = gtk_image_new_from_stock(stock_item, GTK_ICON_SIZE_LARGE_TOOLBAR);
    gtk_box_pack_start(GTK_BOX(item_hb), w, FALSE, FALSE, 5);
    g_signal_connect(w, "clicked", G_CALLBACK(callback), callback_data);

    text_vb = gtk_vbox_new(FALSE, 3);

    /* title */
    w = gtk_label_new(title);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.5);
    formatted_text = g_strdup_printf("<span weight=\"bold\" size=\"x-large\">%s</span>", title);
    gtk_label_set_markup(GTK_LABEL(w), formatted_text);
    g_free(formatted_text);
    gtk_box_pack_start(GTK_BOX(text_vb), w, FALSE, FALSE, 1);
    
    /* subtitle */
    w = gtk_label_new(subtitle);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.5);
    formatted_text = g_strdup_printf("<span size=\"small\">%s</span>", subtitle);
    gtk_label_set_markup(GTK_LABEL(w), formatted_text);
    g_free(formatted_text);
    gtk_box_pack_start(GTK_BOX(text_vb), w, FALSE, FALSE, 1);
    
    gtk_box_pack_start(GTK_BOX(item_hb), text_vb, TRUE, TRUE, 5);

    return eb;
}


/* create the banner "above our heads" */
GtkWidget *
welcome_header_new(void)
{
    GtkWidget *item_vb;
    GtkWidget *item_hb;
    GtkWidget *eb;
    GtkWidget *icon;
    gchar *message;
    GtkWidget *w;


    item_vb = gtk_vbox_new(FALSE, 0);

    /* colorize vbox */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), item_vb);
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &header_bar_bg);

    item_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(item_vb), item_hb, FALSE, FALSE, 10);

    icon = xpm_to_widget_from_parent(top_level, wssplash_xpm);
    gtk_box_pack_start(GTK_BOX(item_hb), icon, FALSE, FALSE, 10);

    message = "<span weight=\"bold\" size=\"x-large\">" "The World's Most Popular Network Protocol Analyzer" "</span>";
    w = gtk_label_new(message);
    gtk_label_set_markup(GTK_LABEL(w), message);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.5);
    gtk_box_pack_start(GTK_BOX(item_hb), w, TRUE, TRUE, 5);

    gtk_widget_show_all(eb);

    return eb;
}


/* create a "topic header widget" */
GtkWidget *
welcome_topic_header_new(const char *header)
{
    GtkWidget *w;
    GtkWidget *eb;
    gchar *formatted_message;


    w = gtk_label_new(header);
    formatted_message = g_strdup_printf("<span weight=\"bold\" size=\"x-large\">%s</span>", header);
    gtk_label_set_markup(GTK_LABEL(w), formatted_message);
    g_free(formatted_message);

    /* colorize vbox */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), w);
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_header_bg);

    return eb;
}


/* create a "topic widget" */
GtkWidget *
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
    gtk_container_border_width(GTK_CONTAINER(layout_vb), 10);
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
GtkWidget *
welcome_filename_link_new(const gchar *filename, GtkWidget **label)
{
    GtkWidget *w;
    GtkWidget *eb;
    GString		*str;
    const unsigned int max = 60;
    int err;
    struct stat stat_buf;


    /* filename */
    str = g_string_new(filename);

    /* cut max filename length */
    if(str->len > max) {
        g_string_erase(str, 0, str->len-max /*cut*/);
        g_string_prepend(str, "... ");
    }

    /* add file size */
    err = eth_stat(filename, &stat_buf);
    if(err == 0) {
        if (stat_buf.st_size/1024/1024 > 10) {
            g_string_append_printf(str, " %" G_GINT64_MODIFIER "dMB", (gint64) (stat_buf.st_size/1024/1024));
        } else if (stat_buf.st_size/1024 > 10) {
            g_string_append_printf(str, " %" G_GINT64_MODIFIER "dKB", (gint64) (stat_buf.st_size/1024));
        } else {
            g_string_append_printf(str, " %" G_GINT64_MODIFIER "dBytes", (gint64) (stat_buf.st_size));
        }
    } else {
        g_string_append(str, " (not found)");
    }

    /* pango format string */
    g_string_prepend(str, "<span foreground='blue'>");
    g_string_append(str, "</span>");

    /* label */
    w = gtk_label_new(str->str);
    *label = w;
    gtk_label_set_markup(GTK_LABEL(w), str->str);
    gtk_misc_set_padding(GTK_MISC(w), 5, 2);

	/* event box */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), w);
    
    g_signal_connect(eb, "enter-notify-event", G_CALLBACK(welcome_item_enter_cb), w);
    g_signal_connect(eb, "leave-notify-event", G_CALLBACK(welcome_item_leave_cb), w);
    g_signal_connect(eb, "button-press-event", G_CALLBACK(welcome_filename_link_press_cb), (gchar *) filename);

    g_string_free(str, TRUE);

    return eb;
}


/* reset the list of recent files */
void
main_welcome_reset_recent_capture_files()
{
    GList* child_list;
    GList* child_list_item;
    
    child_list = gtk_container_get_children(GTK_CONTAINER(welcome_file_panel_vb));
    child_list_item = child_list;

    while(child_list_item) {
        gtk_container_remove(GTK_CONTAINER(welcome_file_panel_vb), child_list_item->data);
        child_list_item = g_list_next(child_list_item);
    }

    g_list_free(child_list);
}


/* add a new file to the list of recent files */
void
main_welcome_add_recent_capture_files(const char *widget_cf_name)
{
    GtkWidget *w;
    GtkWidget *label;

    w = welcome_filename_link_new(widget_cf_name, &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_item_idle_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(welcome_file_panel_vb), w, FALSE, FALSE, 0);
    gtk_widget_show_all(w);
}


#ifdef HAVE_LIBPCAP
/* user clicked on an interface button */
static gboolean
welcome_if_press_cb(GtkWidget *widget _U_, GdkEvent *event _U_, gpointer data)
{
    if (capture_opts->iface)
        g_free(capture_opts->iface);
    if (capture_opts->iface_descr)
        g_free(capture_opts->iface_descr);

    capture_opts->iface = g_strdup(data);
    capture_opts->iface_descr = NULL;
    /* XXX - fix this */
    /*capture_opts->iface_descr = get_interface_descriptive_name(capture_opts->iface);*/

    /* XXX - remove this? */
    if (capture_opts->save_file) {
    g_free(capture_opts->save_file);
    capture_opts->save_file = NULL;
    }

    capture_start_cb(NULL, NULL);

    return FALSE;
}


/* create a single interface entry */
static GtkWidget *
welcome_if_new(const char *if_name, GdkColor *topic_bg _U_, gpointer interf)
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
    w = gtk_image_new_from_stock(WIRESHARK_STOCK_CAPTURE_START, GTK_ICON_SIZE_SMALL_TOOLBAR);
    gtk_box_pack_start(GTK_BOX(interface_hb), w, FALSE, FALSE, 5);

    message = g_string_new(if_name);

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

    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(interface_hb), w, FALSE, FALSE, 0);

    return eb;
}


/* create the list of interfaces */
GtkWidget *
welcome_if_panel_new(void)
{
    GtkWidget *interface_hb;
    GtkWidget *panel_vb;

  if_info_t     *if_info;
  GList         *if_list;
  int err;
  gchar         *err_str;
  int           ifs;
  GList         *curr;


  panel_vb = gtk_vbox_new(FALSE, 0);

  /* LOAD THE INTERFACES */
  if_list = capture_interface_list(&err, &err_str);
  if_list = g_list_sort (if_list, if_list_comparator_alph);
  if (if_list == NULL && err == CANT_GET_INTERFACE_LIST) {
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err_str);
    g_free(err_str);
    return NULL;
  }

  /* List the interfaces */
  for(ifs = 0; (curr = g_list_nth(if_list, ifs)); ifs++) {
      /*g_string_assign(if_tool_str, "");*/
      if_info = curr->data;

      /* Continue if capture device is hidden */
      if (prefs_is_capture_device_hidden(if_info->name)) {
          continue;
      }

#ifdef _WIN32
    interface_hb = welcome_if_new(if_info->description, &topic_content_bg, g_strdup(if_info->name));
#else
    interface_hb = welcome_if_new(if_info->name, &topic_content_bg, g_strdup(if_info->name));
#endif
    gtk_box_pack_start(GTK_BOX(panel_vb), interface_hb, FALSE, FALSE, 2);
  }

  free_interface_list(if_list);

  return panel_vb;
}
#endif  /* HAVE_LIBPCAP */


/* create the welcome page */
GtkWidget *
welcome_new(void)
{
    GtkWidget *welcome_scrollw;
    GtkWidget *welcome_vb;
    GtkWidget *welcome_hb;
    GtkWidget *column_vb;
    GtkWidget *item_hb;
    GtkWidget *w;
    GtkWidget *header;
    GtkWidget *topic_vb;
    GtkWidget *topic_to_fill;


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
    gtk_container_border_width(GTK_CONTAINER(welcome_hb), 10);
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
		"Life list of the capture interfaces (counts incoming packets)",
        GTK_SIGNAL_FUNC(capture_if_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    w = gtk_label_new("Start capture on interface:");
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);

    w = welcome_if_panel_new();
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    item_hb = welcome_button(WIRESHARK_STOCK_CAPTURE_OPTIONS,
        "Capture Options",
		"Start a capture with detailed options",
        GTK_SIGNAL_FUNC(capture_prep_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    /* capture help topic */
    topic_vb = welcome_topic_new("Capture Help", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
		"How to Capture",
		"Step by step to a successful capture setup",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_CAPTURE_SETUP));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
		"Network Media",
        "Specific infos for capturing on: Ethernet, WLAN, ...",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_NETWORK_MEDIA));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
#else
    w = gtk_label_new("Capturing is not compiled into this version of Wireshark!");
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
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
        GTK_SIGNAL_FUNC(file_open_cmd_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    /* prepare list of recent files (will be filled in later) */
    w = gtk_label_new("Open Recent:");
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);

    welcome_file_panel_vb = gtk_vbox_new(FALSE, 1);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), welcome_file_panel_vb, FALSE, FALSE, 0);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
        "Sample Captures",
		"A rich assortment of example capture files on the wiki",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_SAMPLE_CAPTURES));
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
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_HOME));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_button(GTK_STOCK_HELP,
        "User's Guide",
		"The User's Guide (local version, if installed)",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(HELP_CONTENT));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_button(WIRESHARK_STOCK_WIKI,
        "Security",
		"Work with Wireshark as secure as possible",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_SECURITY));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

#if 0
    /* XXX - add this, once the Windows update functionality is implemented */
    /* topic updates */
    topic_vb = welcome_topic_new("Updates", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    w = gtk_label_new("No updates available!");
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, TRUE, TRUE, 0);
#endif


    /* the end */
    gtk_widget_show_all(welcome_vb);

    gtk_scrolled_window_add_with_viewport(GTK_SCROLLED_WINDOW(welcome_scrollw),
                                          welcome_vb);
    gtk_widget_show_all(welcome_scrollw);

    return welcome_scrollw;
}
#else   /* SHOW_WELCOME_PAGE */

/* SOME DUMMY FUNCTIONS, UNTIL THE WELCOME PAGE GET'S LIVE */
void main_welcome_reset_recent_capture_files(void)
{
}

/* add a new file to the list of recently used files */
void main_welcome_add_recent_capture_files(const char *widget_cf_name _U_)
{
}

GtkWidget *
welcome_new(void)
{
    /* this is just a dummy to fill up window space, simply showing nothing */
    return scrolled_window_new(NULL, NULL);
}
#endif


