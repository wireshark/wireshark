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


#include <gtk/gtk.h>

#include "gui_utils.h"
#include "recent.h"
#include "main_welcome.h"


#ifdef SHOW_WELCOME_PAGE
#include "../image/wssplash.xpm"
#endif


/*#define SHOW_WELCOME_PAGE*/
#ifdef SHOW_WELCOME_PAGE
/* XXX - There seems to be some disagreement about if and how this feature should be implemented.
   As I currently don't have the time to continue this, it's temporarily disabled. - ULFL */
GtkWidget *
welcome_item(const gchar *stock_item, const gchar * label, const gchar * message, const gchar * tooltip,
			 GtkSignalFunc callback, void *callback_data)
{
    GtkWidget *w, *item_hb;
    gchar *formatted_message;
    GtkTooltips *tooltips;

    tooltips = gtk_tooltips_new();

    item_hb = gtk_hbox_new(FALSE, 1);

    w = gtk_button_new_from_stock(stock_item);
    gtk_widget_set_size_request(w, 80, 40);
    gtk_button_set_label(GTK_BUTTON(w), label);
    gtk_tooltips_set_tip(tooltips, w, tooltip, NULL);
    gtk_box_pack_start(GTK_BOX(item_hb), w, FALSE, FALSE, 0);
    g_signal_connect(w, "clicked", G_CALLBACK(callback), callback_data);

    w = gtk_label_new(message);
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.5);
    formatted_message = g_strdup_printf("<span weight=\"bold\" size=\"x-large\">%s</span>", message);
    gtk_label_set_markup(GTK_LABEL(w), formatted_message);
    g_free(formatted_message);

    gtk_box_pack_start(GTK_BOX(item_hb), w, FALSE, FALSE, 10);

    return item_hb;
}


GtkWidget *
welcome_header_new(void)
{
    GtkWidget *item_vb;
    GtkWidget *item_hb;
    GtkWidget *eb;
    GdkColor bg;
    GtkWidget *icon;
    gchar *message;
    GtkWidget *w;


    /* background color of the header bar */
    bg.pixel = 0;
    bg.red = 154 * 255;
    bg.green = 210 * 255;
    bg.blue = 229 * 255;

    item_vb = gtk_vbox_new(FALSE, 0);

    /* colorize vbox */
    get_color(&bg);
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), item_vb);
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &bg);

    item_hb = gtk_hbox_new(FALSE, 0);
    gtk_box_pack_start(GTK_BOX(item_vb), item_hb, FALSE, FALSE, 10);

    icon = xpm_to_widget_from_parent(top_level, wssplash_xpm);
    /*icon = xpm_to_widget_from_parent(top_level, wsicon64_xpm);*/
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
    GdkColor bg;
    GtkWidget *eb;
    gchar *formatted_message;


    w = gtk_label_new(header);
    formatted_message = g_strdup_printf("<span weight=\"bold\" size=\"x-large\">%s</span>", header);
    gtk_label_set_markup(GTK_LABEL(w), formatted_message);
    g_free(formatted_message);

    /* topic header background color */
    bg.pixel = 0;
    bg.red = 24 * 255;
    bg.green = 151 * 255;
    bg.blue = 192 * 255;

    /* colorize vbox */
    get_color(&bg);
    eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(eb), w);
    gtk_widget_modify_bg(eb, GTK_STATE_NORMAL, &bg);

    return eb;
}


GtkWidget *
welcome_topic_new(const char *header, GtkWidget **to_fill)
{
    GtkWidget *topic_vb;
    GtkWidget *layout_vb;
    GtkWidget *topic_eb;
    GtkWidget *topic_header;
    GdkColor bg;

    topic_vb = gtk_vbox_new(FALSE, 0);

	/* topic content background color */
    bg.pixel = 0;
    bg.red = 221 * 255;
    bg.green = 226 * 255;
    bg.blue = 228 * 255;

    topic_header = welcome_topic_header_new(header);
    gtk_box_pack_start(GTK_BOX(topic_vb), topic_header, FALSE, FALSE, 0);

    layout_vb = gtk_vbox_new(FALSE, 5);
    gtk_container_border_width(GTK_CONTAINER(layout_vb), 10);
    gtk_box_pack_start(GTK_BOX(topic_vb), layout_vb, FALSE, FALSE, 0);

    /* colorize vbox (we need an event box for this!) */
    get_color(&bg);
    topic_eb = gtk_event_box_new();
    gtk_container_add(GTK_CONTAINER(topic_eb), topic_vb);
    gtk_widget_modify_bg(topic_eb, GTK_STATE_NORMAL, &bg);
    *to_fill = layout_vb;

    return topic_eb;
}


static gboolean
welcome_link_enter_cb(GtkWidget *widget _U_, GdkEventCrossing *event _U_, gpointer user_data)
{
    gchar *message;
    GtkWidget *w = user_data;

    message = g_strdup_printf("<span foreground='blue' underline='single'>%s</span>", g_object_get_data(G_OBJECT(w),"TEXT"));
    gtk_label_set_markup(GTK_LABEL(w), message);
    g_free(message);

    return FALSE;
}

static gboolean
welcome_link_leave_cb(GtkWidget *widget _U_, GdkEvent *event _U_, gpointer user_data)
{
    gchar *message;
    GtkWidget *w = user_data;

    message = g_strdup_printf("<span foreground='blue'>%s</span>", g_object_get_data(G_OBJECT(w),"TEXT"));
    gtk_label_set_markup(GTK_LABEL(w), message);
    g_free(message);

    return FALSE;
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

    g_signal_connect(eb, "enter-notify-event", G_CALLBACK(welcome_link_enter_cb), w);
    g_signal_connect(eb, "leave-notify-event", G_CALLBACK(welcome_link_leave_cb), w);
    g_signal_connect(eb, "button-press-event", G_CALLBACK(welcome_link_press_cb), w);

    /* XXX - memleak */
    g_object_set_data(G_OBJECT(w), "TEXT", g_strdup(text));

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


GtkWidget *
welcome_if_new(const char *if_name, GdkColor *topic_bg, gboolean active)
{
    GtkWidget *interface_hb;
    GtkWidget *w;
    GtkWidget *label;
    GtkTooltips *tooltips;
    GString   *message;


    tooltips = gtk_tooltips_new();

    interface_hb = gtk_hbox_new(FALSE, 5);

    w = welcome_link_new("START", &label);
    gtk_tooltips_set_tip(tooltips, w, "Immediately start a capture on this interface", NULL);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, topic_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(interface_hb), w, FALSE, FALSE, 0);

    w = welcome_link_new("OPTIONS", &label);
    gtk_tooltips_set_tip(tooltips, w, "Show the capture options of this interface", NULL);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, topic_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(interface_hb), w, FALSE, FALSE, 0);

    w = welcome_link_new("DETAILS", &label);
    gtk_tooltips_set_tip(tooltips, w, "Show detailed information about this interface", NULL);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, topic_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(interface_hb), w, FALSE, FALSE, 0);

    message = g_string_new(if_name);

    /* truncate string if it's too long */
    if(message->len > 38) {
        g_string_truncate(message, 35);
        g_string_append  (message, " ...");
    }
    /* if this is the "active" interface, display it bold */
    if(active) {
        g_string_prepend(message, "<span weight=\"bold\">");
        g_string_append (message, "</span>");
	}
    w = gtk_label_new(message->str);
    gtk_label_set_markup(GTK_LABEL(w), message->str);
    g_string_free(message, TRUE);

    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(interface_hb), w, FALSE, FALSE, 0);

    return interface_hb;
}

/* XXX - the layout has to be improved */
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
    GtkWidget *interface_hb;
    GdkColor  topic_bg;


    /* topic content background color */
    topic_bg.pixel = 0;
    topic_bg.red = 221 * 255;
    topic_bg.green = 226 * 255;
    topic_bg.blue = 228 * 255;

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
        "Interfaces...",
        "Interface Life List",
		"Show a life list of the available capture interfaces",
        GTK_SIGNAL_FUNC(capture_if_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
#endif

    w = gtk_label_new("Available Interfaces:");
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);

    interface_hb = welcome_if_new("Generic dialup adapter", &topic_bg, FALSE);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), interface_hb, FALSE, FALSE, 0);

    /* Marvell interface (currently "active") */
    interface_hb = welcome_if_new("Marvell Gigabit Ethernet Controller", &topic_bg, TRUE);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), interface_hb, FALSE, FALSE, 0);

    /* Wireless interface */
    interface_hb = welcome_if_new("Intel(R) PRO/Wireless 3945ABG Network Connection", &topic_bg, FALSE);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), interface_hb, FALSE, FALSE, 0);


    /* capture help topic */
    topic_vb = welcome_topic_new("Capture Help", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

#ifdef HAVE_LIBPCAP
    item_hb = welcome_item(WIRESHARK_STOCK_CAPTURE_START,
        "Setup",
		"How To: Setup a Capture",
		"How To: Setup a Capture (online from the Wiki)",
        GTK_SIGNAL_FUNC(topic_cb), GINT_TO_POINTER(ONLINEPAGE_USERGUIDE));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_item(WIRESHARK_STOCK_CAPTURE_START,
        "Examples",
		"Capture Filter Examples",
		"Capture Filter Examples (online from the Wiki)",
        GTK_SIGNAL_FUNC(topic_cb), GINT_TO_POINTER(ONLINEPAGE_USERGUIDE));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);
#endif

    /* fill bottom space */
    w = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, TRUE, TRUE, 0);


    /* column files */
    topic_vb = welcome_topic_new("Files", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(welcome_hb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_item(GTK_STOCK_OPEN,
        "Open...",
        "Open a Capture File",
		"Open a previously captured file",
        GTK_SIGNAL_FUNC(file_open_cmd_cb), NULL);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_item(GTK_STOCK_OPEN,
        "Examples",
        "Download Examples",
		"Download Example Capture Files (from the Wiki)",
        GTK_SIGNAL_FUNC(topic_cb), GINT_TO_POINTER(ONLINEPAGE_USERGUIDE));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    w = gtk_label_new("Recent Files:");
    gtk_misc_set_alignment (GTK_MISC(w), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 5);

    w = welcome_link_new("C:\\Testfiles\\hello.pcap", &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    w = welcome_filename_link_new("C:\\Testfiles\\hello2.pcap", &label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    w = welcome_filename_link_new(
		"C:\\Testfiles\\to avoid screen garbage\\Unfortunately this is a very long filename which had to be truncated.pcap",
		&label);
    gtk_widget_modify_bg(w, GTK_STATE_NORMAL, &topic_bg);
    gtk_misc_set_alignment (GTK_MISC(label), 0.0, 0.0);
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, FALSE, FALSE, 0);

    w = gtk_label_new("");
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, TRUE, TRUE, 0);


    /* column online */
    column_vb = gtk_vbox_new(FALSE, 10);
    gtk_box_pack_start(GTK_BOX(welcome_hb), column_vb, TRUE, TRUE, 0);

    /* topic online */
    topic_vb = welcome_topic_new("Online", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    item_hb = welcome_item(WIRESHARK_STOCK_WEB_SUPPORT,
        "Help",
        "Show the User's Guide",
		"Show the User's Guide (local version, if available)",
        GTK_SIGNAL_FUNC(topic_cb), GINT_TO_POINTER(ONLINEPAGE_USERGUIDE));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    item_hb = welcome_item(GTK_STOCK_HOME,
        "Home",
        "Projects Home Page",
		"Visit www.wireshark.org, the project's home page",
        GTK_SIGNAL_FUNC(topic_cb), GINT_TO_POINTER(ONLINEPAGE_HOME));
    gtk_box_pack_start(GTK_BOX(topic_to_fill), item_hb, FALSE, FALSE, 5);

    /* topic updates */
    topic_vb = welcome_topic_new("Updates", &topic_to_fill);
    gtk_box_pack_start(GTK_BOX(column_vb), topic_vb, TRUE, TRUE, 0);

    w = gtk_label_new("No updates available!");
    gtk_box_pack_start(GTK_BOX(topic_to_fill), w, TRUE, TRUE, 0);


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


