/* main_80211_toolbar.c
 * The 802.11 toolbar by Pontus Fuchs <pontus.fuchs@gmail.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/*
 * This file implements the "80211" toolbar for Wireshark.
 */

#include "config.h"

#include <stdlib.h>
#include <string.h>

#include <gtk/gtk.h>



#include "main_toolbar.h"

#include "ui/ui_util.h"
#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/main_80211_toolbar.h"

#include "caputils/ws80211_utils.h"
#include <capchild/capture_session.h>
#include <capchild/capture_sync.h>

#include <wsutil/frequency-utils.h>

static GtkWidget *tb80211_tb, *tb80211_iface_list_box, *tb80211_freq_list_box, *tb80211_chan_type_box, *tb80211_info_label;

static GArray *tb80211_interfaces;
static struct ws80211_interface *tb80211_current_iface;
static gint32 tb80211_current_freq = -1;
static gint32 tb80211_current_type = -1;

static gboolean tb80211_dont_set_chan;
static gboolean tb80211_dont_set_iface;

static void tb80211_set_info(const char *errstr)
{
    gtk_label_set_markup(GTK_LABEL(tb80211_info_label), errstr);
}

static
void add_channel_type(const char *type, int oldtype, int indx )
{
    gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(tb80211_chan_type_box), type);

    if (oldtype != -1 && oldtype == ws80211_str_to_chan_type(type)) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(tb80211_chan_type_box), indx);
        tb80211_current_type = oldtype;
    }
}

static
void tb80211_update_chan_type(void)
{
    static unsigned int tb80211_type_cnt;
    unsigned int i;
    int oldtype = -1;
    for (i = 0; i < tb80211_type_cnt; i++) {
        gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(tb80211_chan_type_box), 0);
    }

    if (!tb80211_current_iface) {
        return;
    }

    oldtype = tb80211_current_type;
    tb80211_current_type = -1;

    i = 0;
    add_channel_type(CHAN_NO_HT, oldtype, i++);

    if (tb80211_current_iface->channel_types & (1 << WS80211_CHAN_HT20)) {
        add_channel_type(CHAN_HT20, oldtype, i++);
    }
    if (tb80211_current_iface->channel_types & (1 << WS80211_CHAN_HT40MINUS)) {
        add_channel_type(CHAN_HT40MINUS, oldtype, i++);
    }
    if (tb80211_current_iface->channel_types & (1 << WS80211_CHAN_HT40PLUS)) {
        add_channel_type(CHAN_HT40PLUS, oldtype, i++);
    }
    tb80211_type_cnt = i;
}

static
void tb80211_update_freq(void)
{
    static unsigned int tb80211_freq_cnt;
    unsigned int i;
    gchar *str;
    gint32 oldfreq = 0;

    for (i = 0; i < tb80211_freq_cnt; i++) {
        gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(tb80211_freq_list_box), 0);
    }

    oldfreq = tb80211_current_freq;
    tb80211_current_freq = -1;

    if (!tb80211_current_iface)
        return;

    tb80211_freq_cnt = tb80211_current_iface->frequencies->len;
    for (i = 0; i < tb80211_freq_cnt; i++) {
        int freq;
        freq = g_array_index(tb80211_current_iface->frequencies, int, i);
        str = g_strdup_printf("%d MHz (%d)", freq, ieee80211_mhz_to_chan(freq));
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(tb80211_freq_list_box), str);
        g_free(str);

        if (freq == oldfreq) {
            gtk_combo_box_set_active(GTK_COMBO_BOX(tb80211_freq_list_box), i);
            tb80211_current_freq = oldfreq;
        }
    }
}

static
void tb80211_update_freq_and_type(void)
{
    tb80211_dont_set_chan = TRUE;
    tb80211_update_freq();
    tb80211_update_chan_type();
    tb80211_dont_set_chan = FALSE;
}

#ifdef HAVE_LIBPCAP
/* Get currently selected channel type type enum */
static
int get_selected_channel_type(void)
{
    int ret;
    gchar *s = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(tb80211_chan_type_box));

    ret = ws80211_str_to_chan_type(s);

    g_free(s);
    return ret;
}

/* Invoke dumpcap to set channel */
static int
tb80211_do_set_channel(char *iface, int freq, int type)
{
    gchar *freq_s;
    const gchar *type_s;
    gchar *data, *primary_msg, *secondary_msg;
    int ret;

    freq_s = g_strdup_printf("%d", freq);
    type_s = ws80211_chan_type_to_str(type);
    ret = sync_interface_set_80211_chan(iface, freq_s, type_s, "-1", "-1",
                                        &data, &primary_msg, &secondary_msg, main_window_update);

    /* Parse the error msg */
    if (ret && primary_msg) {
        return atoi(primary_msg);
    }
    g_free(data);
    g_free(primary_msg);
    g_free(secondary_msg);
    g_free(freq_s);
    return ret;
}

/* Called on freq and type combo box change. */
static void
tb80211_set_channel(void)
{
    gchar *info = NULL;
    int err, selected_chan, new_type, new_freq;

    GtkComboBox *freq_combo = GTK_COMBO_BOX(tb80211_freq_list_box);

    GtkComboBox *type_combo = GTK_COMBO_BOX(tb80211_chan_type_box);

    selected_chan = gtk_combo_box_get_active(freq_combo);
    if (selected_chan < 0)
        return;

    new_freq = g_array_index(tb80211_current_iface->frequencies, int, selected_chan);
    new_type = get_selected_channel_type();

    err = tb80211_do_set_channel(tb80211_current_iface->ifname, new_freq, new_type);
    if (err) {
        info = g_strdup_printf("<b>Failed to set channel: %s</b>", g_strerror(abs(err)));
        /* Try to set back to last working chan */
        err = tb80211_do_set_channel(tb80211_current_iface->ifname, tb80211_current_freq, tb80211_current_type);
        if (err) {
            gtk_combo_box_set_active(freq_combo, -1);
            gtk_combo_box_set_active(type_combo, -1);
            tb80211_current_freq = -1;
            tb80211_current_type = -1;
        }
        else {
            tb80211_update_freq_and_type();
        }
    }
    else {
        info = g_strdup_printf("%s Switched to %d MHz (%d)", tb80211_current_iface->ifname, new_freq, ieee80211_mhz_to_chan(new_freq));
        tb80211_current_freq = new_freq;
        tb80211_current_type = new_type;
    }
    tb80211_set_info(info);
    g_free(info);
}

static void
tb80211_set_chan_cb(GtkWidget *widget _U_, gpointer data _U_)
{
    if (!tb80211_current_iface || tb80211_dont_set_chan)
        return;

    tb80211_set_channel();
}
#endif

static void
tb80211_iface_changed_cb(GtkWidget *widget, gpointer data _U_)
{
    unsigned int i;
    int ret;
    struct ws80211_interface *iface;
    struct ws80211_iface_info iface_info;
    gchar *active;

    if (tb80211_dont_set_iface)
        return;

    active = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(widget));

    if (!active || tb80211_dont_set_chan)
        goto out_free;

    for (i = 0; i < tb80211_interfaces->len; i++) {
        iface = g_array_index(tb80211_interfaces, struct ws80211_interface *, i);
        if (strcmp(active, iface->ifname) == 0) {
            tb80211_current_iface = iface;
            break;
        }
    }

    tb80211_current_freq = -1;
    tb80211_current_type = -1;
    if (tb80211_current_iface) {
        ret = ws80211_get_iface_info(tb80211_current_iface->ifname, &iface_info);
        if (!ret) {
            tb80211_current_freq = iface_info.current_freq;
            tb80211_current_type = iface_info.current_chan_type;
        }
    }
    tb80211_update_freq_and_type();

out_free:
    g_free(active);
}

void
tb80211_refresh_interfaces(void)
{
    struct ws80211_interface *iface;
    unsigned int i;
    gboolean same = FALSE;
    gchar *selected_iface = NULL, *info;

    if (!tb80211_tb)
        return;

    if (tb80211_interfaces) {
        selected_iface = gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(tb80211_iface_list_box));

        for (i = 0; i < tb80211_interfaces->len; i++)
                gtk_combo_box_text_remove(GTK_COMBO_BOX_TEXT(tb80211_iface_list_box), 0);

        ws80211_free_interfaces(tb80211_interfaces);
        tb80211_interfaces = NULL;
        tb80211_current_iface = NULL;
    }
    tb80211_interfaces = ws80211_find_interfaces();

    if (!tb80211_interfaces) {
        goto out_free;
    }

    tb80211_dont_set_iface = TRUE;
    for (i = 0; i < tb80211_interfaces->len; i++) {
        iface = g_array_index(tb80211_interfaces, struct ws80211_interface *, i);
        gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(tb80211_iface_list_box), iface->ifname);

        if (selected_iface && strcmp(selected_iface, iface->ifname) == 0) {
            gtk_combo_box_set_active(GTK_COMBO_BOX(tb80211_iface_list_box), i);
            tb80211_current_iface = iface;
            same = TRUE;
        }
    }
    tb80211_dont_set_iface = FALSE;

    /* Reset selectors if interface disappeared */
    if (!same) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(tb80211_iface_list_box), -1);
        gtk_combo_box_set_active(GTK_COMBO_BOX(tb80211_freq_list_box), -1);
        gtk_combo_box_set_active(GTK_COMBO_BOX(tb80211_chan_type_box), -1);
    }

    info = g_strdup_printf("%d monitor interfaces found", tb80211_interfaces->len);
    tb80211_set_info(info);
    g_free(info);
out_free:
    g_free(selected_iface);
}

static void
tb80211_add_label(const gchar *text, GtkWidget *tb)
{
    GtkWidget     *label;
    GtkToolItem   *label_ti;

    label_ti = gtk_tool_item_new();
    gtk_widget_show(GTK_WIDGET (label_ti));
    label = gtk_label_new(text);
    gtk_widget_show(GTK_WIDGET (label));
    gtk_container_add(GTK_CONTAINER(label_ti), label);
    gtk_toolbar_insert(GTK_TOOLBAR(tb), label_ti, -1);
}

GtkWidget *
ws80211_toolbar_new(void)
{
    GtkToolItem   *ti;
    int ret;

    /* filter toolbar */
    tb80211_tb = gtk_toolbar_new();
    gtk_orientable_set_orientation(GTK_ORIENTABLE(tb80211_tb),
                                GTK_ORIENTATION_HORIZONTAL);

    gtk_widget_show(tb80211_tb);

    tb80211_add_label(" Interface: ", tb80211_tb);

    ti = gtk_tool_item_new();
    gtk_widget_show(GTK_WIDGET (ti));
    tb80211_iface_list_box = gtk_combo_box_text_new();
    g_signal_connect(tb80211_iface_list_box, "changed", G_CALLBACK(tb80211_iface_changed_cb), NULL);
    gtk_container_add(GTK_CONTAINER(ti), tb80211_iface_list_box);
    gtk_widget_show(GTK_WIDGET (tb80211_iface_list_box));
    gtk_toolbar_insert(GTK_TOOLBAR(tb80211_tb), ti, -1);

    tb80211_add_label(" Frequency: ", tb80211_tb);

    ti = gtk_tool_item_new();
    gtk_widget_show(GTK_WIDGET (ti));
    tb80211_freq_list_box = gtk_combo_box_text_new();
#ifdef HAVE_LIBPCAP
    g_signal_connect(tb80211_freq_list_box, "changed", G_CALLBACK(tb80211_set_chan_cb), NULL);
#else
    gtk_widget_set_sensitive(GTK_WIDGET(tb80211_freq_list_box), FALSE);
#endif
    gtk_container_add(GTK_CONTAINER(ti), tb80211_freq_list_box);
    gtk_widget_show(GTK_WIDGET (tb80211_freq_list_box));
    gtk_toolbar_insert(GTK_TOOLBAR(tb80211_tb), ti, -1);

    ti = gtk_tool_item_new();
    gtk_widget_show(GTK_WIDGET (ti));
    tb80211_chan_type_box = gtk_combo_box_text_new();
#ifdef HAVE_LIBPCAP
    g_signal_connect(tb80211_chan_type_box, "changed", G_CALLBACK(tb80211_set_chan_cb), NULL);
#else
    gtk_widget_set_sensitive(GTK_WIDGET(tb80211_freq_list_box), FALSE);
#endif
    gtk_container_add(GTK_CONTAINER(ti), tb80211_chan_type_box);
    gtk_widget_show(GTK_WIDGET (tb80211_chan_type_box));
    gtk_toolbar_insert(GTK_TOOLBAR(tb80211_tb), ti, -1);

    ti = gtk_separator_tool_item_new();
    gtk_widget_show(GTK_WIDGET (ti));
    gtk_toolbar_insert(GTK_TOOLBAR(tb80211_tb), ti, -1);

    ti = gtk_tool_item_new();
    gtk_widget_show(GTK_WIDGET (ti));
    tb80211_info_label = gtk_label_new("");
    gtk_container_add(GTK_CONTAINER(ti), tb80211_info_label);
    gtk_widget_show(GTK_WIDGET (tb80211_info_label));
    gtk_toolbar_insert(GTK_TOOLBAR(tb80211_tb), ti, -1);

    /* make current preferences effective */
    toolbar_redraw_all();

    ret = ws80211_init();
    if(ret) {
        tb80211_set_info("<b>Failed to initialize ws80211</b>");
    } else {
        tb80211_refresh_interfaces();
    }

    return tb80211_tb;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
