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

#include <gtk/gtk.h>

#include "../color.h"

#include "gtk/gui_utils.h"
#include "gtk/color_utils.h"
#include "gtk/recent.h"
#include "gtk/gtkglobals.h"
#include "gtk/main_welcome.h"
#include "gtk/capture_dlg.h"
#include "gtk/capture_file_dlg.h"
#include "gtk/help_dlg.h"
#include "gtk/stock_icons.h"


/* XXX - There seems to be some disagreement about if and how this feature should be implemented.
   As I currently don't have the time to continue this, it's temporarily disabled. - ULFL */
/*#define SHOW_WELCOME_PAGE*/

#ifdef SHOW_WELCOME_PAGE
#include "../image/wssplash.xpm"
#endif


#ifdef SHOW_WELCOME_PAGE


GdkColor topic_item_entered_bg;
GdkColor topic_content_bg;
GdkColor header_bar_bg;
GdkColor topic_header_bg;


static gboolean
welcome_item_enter_cb(GtkWidget *eb, GdkEventCrossing *event _U_, gpointer user_data)
{
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_item_entered_bg);

    return FALSE;
}

static gboolean
welcome_item_leave_cb(GtkWidget *eb, GdkEvent *event _U_, gpointer user_data)
{
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_content_bg);

    return FALSE;
}


static gboolean
welcome_item_press_cb(GtkWidget *widget _U_, GdkEvent *event _U_, gpointer data _U_) {

    g_warning("TBD: item pressed");

    return FALSE;
}




GtkWidget *
welcome_item(const gchar *stock_item, const gchar * title, const gchar * subtitle,
			 GtkSignalFunc callback, void *callback_data)
{
    GtkWidget *eb, *w, *item_hb, *text_vb;
    gchar *formatted_text;


    item_hb = gtk_hbox_new(FALSE, 1);

    /* event box */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), item_hb);
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_content_bg);

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


static gboolean
welcome_link_press_cb(GtkWidget *widget _U_, GdkEvent *event _U_, gpointer data _U_) {

    g_warning("TBD: link pressed");

    return FALSE;
}

GtkWidget *
welcome_link_new(const gchar *text, GtkWidget **label /*, void *callback, void *private_data */)
{
    gchar *message;
    GtkWidget *w;
    GtkWidget *eb;

    message = g_strdup_printf("<span foreground='blue'>%s</span>", text);
    w = gtk_label_new(message);
    *label = w;
    gtk_label_set_markup(GTK_LABEL(w), message);
    g_free(message);

	/* event box */
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), w);
    
    g_signal_connect(eb, "enter-notify-event", G_CALLBACK(welcome_item_enter_cb), w);
    g_signal_connect(eb, "leave-notify-event", G_CALLBACK(welcome_item_leave_cb), w);
    g_signal_connect(eb, "button-press-event", G_CALLBACK(welcome_link_press_cb), w);

    return eb;
}

GtkWidget *
welcome_filename_link_new(const char *filename, GtkWidget **label)
{
    GString		*str;
    GtkWidget	*w;
    const unsigned int max = 60;


    str = g_string_new(filename);

    if(str->len > max) {
        g_string_erase(str, 0, str->len-max /*cut*/);
        g_string_prepend(str, "... ");
    }

    w = welcome_link_new(str->str, label);

    g_string_free(str, TRUE);

    return w;
}


#include <epan/prefs.h>
#include "capture.h"
#include "capture-pcap-util.h"
#include "capture_opts.h"
#include "main.h"
#include "simple_dialog.h"

extern gint if_list_comparator_alph (const void *first_arg, const void *second_arg);


static gboolean
welcome_if_press_cb(GtkWidget *widget _U_, GdkEvent *event _U_, gpointer data) {

    //g_warning("TBD: start capture pressed");

    if (capture_opts->iface)
        g_free(capture_opts->iface);
    if (capture_opts->iface_descr)
        g_free(capture_opts->iface_descr);

    capture_opts->iface = g_strdup(data);
    capture_opts->iface_descr = NULL;
    //capture_opts->iface_descr = get_interface_descriptive_name(capture_opts->iface);

    /* XXX - remove this? */
    if (capture_opts->save_file) {
    g_free(capture_opts->save_file);
    capture_opts->save_file = NULL;
    }

    capture_start_cb(NULL, NULL);

    return FALSE;
}


#ifdef HAVE_LIBPCAP
GtkWidget *
welcome_if_new(const char *if_name, GdkColor *topic_bg, gpointer interf)
{
    GtkWidget *interface_hb;
    GtkWidget *w;
    GString   *message;
    GtkWidget *eb;


    /* event box */
    eb = gtk_event_box_new();
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &topic_content_bg);

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


/*
 * Sorts the Interface List in alphabetical order
 */
/*gint if_list_comparator_alph (const void *first_arg, const void *second_arg){
  const if_info_t *first = first_arg, *second = second_arg;

  if (first != NULL && first->description != NULL &&
      second != NULL && second->description != NULL) {
    return g_ascii_strcasecmp(first->description, second->description);
  } else {
    return 0;
  }
}*/



GtkWidget *
welcome_if_panel_new(void)
{
    GtkWidget *interface_hb;
    GtkWidget *panel_vb;

  if_info_t     *if_info;
GList           *if_list;
int err;
  gchar         *err_str;
  int           ifs;
  GList         *curr;
  //if_dlg_data_t *if_dlg_data;

    panel_vb = gtk_vbox_new(FALSE, 0);

#if 0
#ifdef _WIN32
  /* Is WPcap loaded? */
  if (!has_wpcap) {
    char *detailed_err;

    detailed_err = cant_load_winpcap_err("Wireshark");
    simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", detailed_err);
    g_free(detailed_err);
    return;
  }
#endif
#endif

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
      //g_string_assign(if_tool_str, "");
      if_info = curr->data;

      /* Continue if capture device is hidden */
      if (prefs_is_capture_device_hidden(if_info->name)) {
          continue;
      }

      //if_dlg_data = g_malloc0(sizeof(if_dlg_data_t));
      //if_dlg_data->if_info = *if_info;

      /* Kind of adaptor (icon) */
      //icon = xpm_to_widget(capture_ethernet_16_xpm);
      //gtk_table_attach_defaults(GTK_TABLE(if_tb), icon, 0, 1, row, row+1);

      /* description */
      //if (if_info->description != NULL)
        //if_dlg_data->descr_lb = gtk_label_new(if_info->description);
      //else
        //if_dlg_data->descr_lb = gtk_label_new("");
      //gtk_misc_set_alignment(GTK_MISC(if_dlg_data->descr_lb), 0.0, 0.5);
      //gtk_table_attach_defaults(GTK_TABLE(if_tb), if_dlg_data->descr_lb, 2, 3, row, row+1);

#if 0
      if (if_info->description) {
        g_string_append(if_tool_str, "Description: ");
        g_string_append(if_tool_str, if_info->description);
        g_string_append(if_tool_str, "\n");
      }
#endif

    interface_hb = welcome_if_new(if_info->description, &topic_content_bg, g_strdup(if_info->name));
    gtk_box_pack_start(GTK_BOX(panel_vb), interface_hb, FALSE, FALSE, 2);

#if 0
      /* IP address */
      /* only the first IP address will be shown */
      g_string_append(if_tool_str, "IP: ");
      curr_ip = g_slist_nth(if_info->ip_addr, 0);
      if(curr_ip) {
        ip_addr = (if_addr_t *)curr_ip->data;
        switch (ip_addr->type) {

        case AT_IPv4:
          tmp_str = ip_to_str((guint8 *)&ip_addr->ip_addr.ip4_addr);
          break;

        case AT_IPv6:
          tmp_str = ip6_to_str((struct e_in6_addr *)&ip_addr->ip_addr.ip6_addr);
          break;

        default:
          g_assert_not_reached();
          tmp_str = NULL;
        }
        if_dlg_data->ip_lb = gtk_label_new(tmp_str);
        gtk_widget_set_sensitive(if_dlg_data->ip_lb, TRUE);
        g_string_append(if_tool_str, tmp_str);
      } else {
        if_dlg_data->ip_lb = gtk_label_new("unknown");
        gtk_widget_set_sensitive(if_dlg_data->ip_lb, FALSE);
        g_string_append(if_tool_str, "unknown");
      }
#endif
  }

    free_interface_list(if_list);

#if 0
    /* Generic dialup */
    interface_hb = welcome_if_new("Generic dialup adapter", &topic_content_bg, TRUE);
    gtk_box_pack_start(GTK_BOX(panel_vb), interface_hb, FALSE, FALSE, 2);

    /* Marvell interface */
    interface_hb = welcome_if_new("Marvell Gigabit Ethernet Controller", &topic_content_bg, TRUE);
    gtk_box_pack_start(GTK_BOX(panel_vb), interface_hb, FALSE, FALSE, 2);

    /* Wireless interface */
    interface_hb = welcome_if_new("Intel(R) PRO/Wireless 3945ABG Network Connection", &topic_content_bg, TRUE);
    gtk_box_pack_start(GTK_BOX(panel_vb), interface_hb, FALSE, FALSE, 2);
#endif

    return panel_vb;
}
#endif  /* HAVE_LIBPCAP */


GtkWidget *
welcome_new(void)
{
    GtkWidget *welcome_scrollw;
    GtkWidget *welcome_vb;
    GtkWidget *welcome_hb;
    GtkWidget *column_vb;
    GtkWidget *item_hb;
    GtkWidget *w;
    GtkWidget *label;
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

	/* topic item entered color */
    topic_item_entered_bg.pixel = 0;
    topic_item_entered_bg.red = 154 * 255;
    topic_item_entered_bg.green = 210 * 255;
    topic_item_entered_bg.blue = 229 * 255;
    get_color(&topic_item_entered_bg);


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
    item_hb = welcome_item(WIRESHARK_STOCK_CAPTURE_INTERFACES,
        "Interface List",
		"Life list of the capture interfaces (counts incoming packets)",
        GTK_SIGNAL_FUNC(capture_if_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    w = gtk_label_new("Start capture on interface:");
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);

    w = welcome_if_panel_new();
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    item_hb = welcome_item(WIRESHARK_STOCK_CAPTURE_OPTIONS,
        "Capture Options",
		"Start a capture with detailed options",
        GTK_SIGNAL_FUNC(capture_prep_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    /* capture help topic */
    topic_vb = welcome_topic_new("Capture Help", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_item(WIRESHARK_STOCK_WIKI,
		"How to Capture",
		"Step by step to a successful capture setup",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_CAPTURE_SETUP));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_item(WIRESHARK_STOCK_WIKI,
		"Network Media",
        "Specific infos for capturing on: Ethernet, WLAN, ...",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_NETWORK_MEDIA));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    /*item_hb = welcome_item(WIRESHARK_STOCK_WIKI,
		"Capture Filters",
		"Capture filter examples on the wiki",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_CAPTURE_FILTERS));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);*/
#else
    /* place a note that capturing is not compiled in */
    w = gtk_label_new("Capturing is not compiled into this version of Wireshark!");
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);
#endif

    /* fill bottom space */
    w = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, TRUE, TRUE, 0);


    /* column files */
    topic_vb = welcome_topic_new("Files", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(welcome_hb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_item(GTK_STOCK_OPEN,
        "Open",
		"Open a previously captured file",
        GTK_SIGNAL_FUNC(file_open_cmd_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    /* list of recent files */
    w = gtk_label_new("Open Recent:");
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);

    w = welcome_link_new("C:\\Testfiles\\hello.pcap", &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_content_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    w = welcome_filename_link_new("C:\\Testfiles\\hello2.pcap", &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_content_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    w = welcome_filename_link_new("C:\\Testfiles\\hello3.pcap", &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_content_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    w = welcome_filename_link_new("C:\\Testfiles\\hello4.pcap", &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_content_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    w = welcome_filename_link_new("C:\\Testfiles\\hello5.pcap", &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_content_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    w = welcome_filename_link_new(
		"C:\\Testfiles\\to avoid screen garbage\\Unfortunately this is a very long filename which had to be truncated.pcap",
		&label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_content_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    item_hb = welcome_item(WIRESHARK_STOCK_WIKI,
        "Sample Captures",
		"A rich assortment of sample capture files on the wiki",
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

    item_hb = welcome_item(GTK_STOCK_HOME,
        "Website",
		"Visit the project's website",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(ONLINEPAGE_HOME));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_item(WIRESHARK_STOCK_WEB_SUPPORT,
        "User's Guide",
		"The User's Guide (local version, if installed)",
        GTK_SIGNAL_FUNC(topic_menu_cb), GINT_TO_POINTER(HELP_CONTENT));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_item(WIRESHARK_STOCK_WIKI,
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
#else
GtkWidget *
welcome_new(void)
{
    /* this is just a dummy to fill up window space, simply showing nothing */
    return scrolled_window_new(NULL, NULL);
}
#endif


