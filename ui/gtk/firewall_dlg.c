/* firewall_rules_dlg.c
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
 * Generate firewall ACL rules based on packet addresses and ports.
 * For directional rules, an outside interface is assumed.
 *
 * There may be better ways to present the information, e.g. all rules
 * in one huge text window, or some sort of tree view.
 */

/* Copied from ssl-dlg.c */

#include "config.h"

#include <string.h>

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/epan_dissect.h>
#include <wsutil/filesystem.h>

#include <ui/alert_box.h>
#include <ui/firewall_rules.h>
#include <ui/last_open_dir.h>

#include <wsutil/file_util.h>

#include "ui/gtk/main.h"
#include "ui/gtk/dlg_utils.h"
#include "ui/gtk/file_dlg.h"
#include "ui/gtk/help_dlg.h"
#include "ui/gtk/gui_utils.h"
#include "ui/gtk/old-gtk-compat.h"
#include "ui/gtk/firewall_dlg.h"

#define MAX_RULE_LEN 200

/* Copied from packet_info struct */
typedef struct _rule_info_t {
    size_t product;
    address dl_src;
    address dl_dst;
    address net_src;
    address net_dst;
    port_type ptype;
    guint32 srcport;
    guint32 destport;
    GtkWidget *text;
    GtkWidget *filter_combo_box;
    GtkWidget *deny_cb;
    GtkWidget *inbound_cb;
    gboolean inbound;
    gboolean deny;
    rule_type_e rule_type;
} rule_info_t;

static void sf_dummy(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);

static void select_product(GtkWidget * win, gpointer data);
static void select_filter(GtkWidget * win, gpointer data);
static void toggle_inbound(GtkToggleButton *t, gpointer data);
static void toggle_deny(GtkToggleButton *t, gpointer data);
static void set_rule_text(rule_info_t *rule_info);
static void firewall_destroy_cb(GtkWidget * win, gpointer data);
static void firewall_copy_cmd_cb(GtkWidget * w, gpointer data);
static void firewall_save_as_cmd_cb(GtkWidget * w, gpointer data);

#define WS_RULE_INFO_KEY "rule_info_key"

#if 0
/* List of "rule_info_t" structures for all rule windows. */
static GList *rule_infos;

/* Remove a "rule_info_t" structure from the list. */
static void
forget_rule_info(rule_info_t *rule_info)
{
  rule_infos = g_list_remove(rule_infos, rule_info);
}
#endif

void
firewall_rule_cb(GtkWidget *w _U_, gpointer data _U_)
{
    GtkWidget       *rule_w, *vbox, *txt_scrollw, *text;
    GtkWidget       *label,  *product_combo_box;
    GtkWidget       *hbox,   *button_hbox, *button;
    rule_info_t     *rule_info;
    packet_info     *pinfo = &cfile.edt->pi;
    size_t i;

    rule_info = g_new0(rule_info_t, 1);
    copy_address(&(rule_info->dl_src), &(pinfo->dl_src));
    copy_address(&(rule_info->dl_dst), &(pinfo->dl_dst));
    copy_address(&(rule_info->net_src), &(pinfo->net_src));
    copy_address(&(rule_info->net_dst), &(pinfo->net_dst));
    rule_info->ptype = pinfo->ptype;
    rule_info->srcport = pinfo->srcport;
    rule_info->destport = pinfo->destport;
    rule_info->inbound = TRUE;
    rule_info->deny = TRUE;
    rule_info->product = 0;

    rule_w = dlg_window_new("Firewall ACL Rules");

    gtk_widget_set_name(rule_w, "Firewall ACL rule window");
    gtk_container_set_border_width(GTK_CONTAINER(rule_w), 6);

    /* setup the container */
    vbox = ws_gtk_box_new(GTK_ORIENTATION_VERTICAL, 6, FALSE);
    gtk_container_add(GTK_CONTAINER(rule_w), vbox);

    /* rule type selectors hbox */
    hbox = ws_gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 1, FALSE);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    /* product selector */
    label = gtk_label_new("Product");
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

    product_combo_box = gtk_combo_box_text_new();
    for (i = 0; i < firewall_product_count(); i++) {
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(product_combo_box), firewall_product_name(i));
    }
    g_object_set_data(G_OBJECT(product_combo_box), WS_RULE_INFO_KEY, rule_info);
    g_signal_connect(product_combo_box, "changed", G_CALLBACK(select_product), NULL);
    gtk_box_pack_start(GTK_BOX(hbox), product_combo_box, FALSE, FALSE, 5);

    /* type selector */
    label = gtk_label_new("Filter");
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 10);

    rule_info->filter_combo_box = ws_combo_box_new_text_and_pointer();
    g_object_set_data(G_OBJECT(rule_info->filter_combo_box), WS_RULE_INFO_KEY, rule_info); \
    g_signal_connect(rule_info->filter_combo_box, "changed", G_CALLBACK(select_filter), NULL);
    gtk_box_pack_start(GTK_BOX(hbox), rule_info->filter_combo_box, FALSE, FALSE, 5);

    /* inbound selector */
    rule_info->inbound_cb = gtk_check_button_new_with_label("Inbound");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rule_info->inbound_cb),
        rule_info->inbound);
    gtk_box_pack_start(GTK_BOX(hbox), rule_info->inbound_cb, FALSE, FALSE, 10);
    g_signal_connect(rule_info->inbound_cb, "toggled", G_CALLBACK(toggle_inbound), rule_info);

    /* deny selector */
    rule_info->deny_cb = gtk_check_button_new_with_label("Deny");
    gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(rule_info->deny_cb),
        rule_info->deny);
    gtk_box_pack_start(GTK_BOX(hbox), rule_info->deny_cb, FALSE, FALSE, 10);
    g_signal_connect(rule_info->deny_cb, "toggled", G_CALLBACK(toggle_deny), rule_info);

    /* create a scrolled window for the text */
    txt_scrollw = scrolled_window_new(NULL, NULL);
    gtk_scrolled_window_set_shadow_type(GTK_SCROLLED_WINDOW(txt_scrollw),
                                        GTK_SHADOW_IN);
    gtk_box_pack_start(GTK_BOX(vbox), txt_scrollw, TRUE, TRUE, 0);

    /* create a text box */
    text = gtk_text_view_new();
    gtk_text_view_set_editable(GTK_TEXT_VIEW(text), FALSE);
    gtk_container_add(GTK_CONTAINER(txt_scrollw), text);
    rule_info->text = text;

    /* Button row */
    button_hbox = dlg_button_row_new(GTK_STOCK_HELP, GTK_STOCK_COPY, GTK_STOCK_SAVE, GTK_STOCK_CANCEL, NULL);
    gtk_box_pack_start(GTK_BOX(vbox), button_hbox, FALSE, FALSE, 0);

    /* Create Copy Button */
    button = (GtkWidget *)g_object_get_data(G_OBJECT(button_hbox), GTK_STOCK_COPY);
    g_signal_connect(button, "clicked", G_CALLBACK(firewall_copy_cmd_cb), rule_info);
    gtk_widget_set_tooltip_text(button, "Copy rule to clipboard");

    /* Create Save Button */
    button = (GtkWidget *)g_object_get_data(G_OBJECT(button_hbox), GTK_STOCK_SAVE);
    g_signal_connect(button, "clicked", G_CALLBACK(firewall_save_as_cmd_cb), rule_info);
    gtk_widget_set_tooltip_text(button, "Save the rule as currently displayed");

    button = (GtkWidget *)g_object_get_data(G_OBJECT(button_hbox), GTK_STOCK_CANCEL);
    gtk_widget_set_tooltip_text(button, "Cancel the dialog");
    window_set_cancel_button(rule_w, button, window_cancel_button_cb);

    button = (GtkWidget *)g_object_get_data(G_OBJECT(button_hbox), GTK_STOCK_HELP);
    g_signal_connect(button, "clicked", G_CALLBACK(topic_cb), (gpointer)HELP_FIREWALL_DIALOG);

    /* Tuck away the rule_info object into the window */
    g_object_set_data(G_OBJECT(rule_w), WS_RULE_INFO_KEY, rule_info);

    g_signal_connect(rule_w, "delete_event", G_CALLBACK(window_delete_event_cb), NULL);
    g_signal_connect(rule_w, "destroy", G_CALLBACK(firewall_destroy_cb), NULL);

    /* Make sure this widget gets destroyed if we quit the main loop,
       so that if we exit, we clean up any temporary files we have
       for "Follow SSL Stream" windows.
       gtk_quit_add_destroy is deprecated and should not be used in newly-written code. This function is going to be removed in GTK+ 3.0

       gtk_quit_add_destroy(gtk_main_level(), GTK_OBJECT(rule_w));

    */

    gtk_combo_box_set_active(GTK_COMBO_BOX(product_combo_box), 0);  /* invokes select_product callback */
    gtk_widget_show_all(rule_w);
    window_present(rule_w);
}

/* Set the current product. */
#define ADD_TO_FILTER_MENU(rt) \
        ws_combo_box_append_text_and_pointer(GTK_COMBO_BOX(rule_info->filter_combo_box), name, GUINT_TO_POINTER(rt)); \
        if (rule_type == RT_NONE) { \
            rule_type = rt; \
        }

#define NAME_TCP_UDP (rule_info->ptype == PT_TCP ? "TCP" : "UDP")

static void
select_product(GtkWidget *w, gpointer data _U_)
{
    guint prod = gtk_combo_box_get_active(GTK_COMBO_BOX(w));
    rule_info_t *rule_info;
    gchar name[MAX_RULE_LEN], addr_str[MAX_RULE_LEN];
    address *addr;
    rule_type_e rule_type = RT_NONE;
    gboolean sensitive = FALSE;

    rule_info =(rule_info_t *)g_object_get_data(G_OBJECT(w), WS_RULE_INFO_KEY);

    if (prod >= firewall_product_count() || !rule_info)
        return;

    rule_info->product = prod;

    /* Clear the list store (ie: the como_box list items) */
    ws_combo_box_clear_text_and_pointer(GTK_COMBO_BOX(rule_info->filter_combo_box));

    /* Fill in valid combo_box list items (in the list store).   */
    if (firewall_product_mac_func(prod) && rule_info->dl_src.type == AT_ETHER) {
        addr = &(rule_info->dl_src);
        address_to_str_buf(addr, name, MAX_RULE_LEN);
        ADD_TO_FILTER_MENU(RT_MAC_SRC);

        addr = &(rule_info->dl_dst);
        address_to_str_buf(addr, name, MAX_RULE_LEN);
        ADD_TO_FILTER_MENU(RT_MAC_DST);
    }

    if (firewall_product_ipv4_func(prod) && rule_info->net_src.type == AT_IPv4) {
        addr = &(rule_info->net_src);
        address_to_str_buf(addr, name, MAX_RULE_LEN);
        ADD_TO_FILTER_MENU(RT_IPv4_SRC);

        addr = &(rule_info->net_dst);
        address_to_str_buf(addr, name, MAX_RULE_LEN);
        ADD_TO_FILTER_MENU(RT_IPv4_DST);
    }

    if (firewall_product_port_func(prod) && (rule_info->ptype == PT_TCP || rule_info->ptype == PT_UDP)) {
        g_snprintf(name, MAX_RULE_LEN, "%s port %u", NAME_TCP_UDP,
            rule_info->srcport);
        ADD_TO_FILTER_MENU(RT_PORT_SRC);
        if (rule_info->srcport != rule_info->destport) {
            g_snprintf(name, MAX_RULE_LEN, "%s port %u", NAME_TCP_UDP,
                rule_info->destport);
            ADD_TO_FILTER_MENU(RT_PORT_DST);
        }
    }

    if (firewall_product_ipv4_port_func(prod) && rule_info->net_src.type == AT_IPv4 &&
            (rule_info->ptype == PT_TCP || rule_info->ptype == PT_UDP)) {
        addr = &(rule_info->net_src);
        address_to_str_buf(addr, addr_str, MAX_RULE_LEN);
        g_snprintf(name, MAX_RULE_LEN, "%s + %s port %u", addr_str,
            NAME_TCP_UDP, rule_info->srcport);
        ADD_TO_FILTER_MENU(RT_IPv4_PORT_SRC);

        addr = &(rule_info->net_dst);
        address_to_str_buf(addr, addr_str, MAX_RULE_LEN);
        g_snprintf(name, MAX_RULE_LEN, "%s + %s port %u", addr_str,
            NAME_TCP_UDP, rule_info->destport);
        ADD_TO_FILTER_MENU(RT_IPv4_PORT_DST);
    }

    if (rule_type != RT_NONE) {
        gtk_combo_box_set_active(GTK_COMBO_BOX(rule_info->filter_combo_box), 0); /* invokes select_filter callback */
        sensitive = TRUE;
    } else {
        select_filter(rule_info->filter_combo_box, NULL);  /* Call if RT_NONE [with nothing selected]  */
    }

    gtk_widget_set_sensitive(rule_info->filter_combo_box, sensitive);
    gtk_widget_set_sensitive(rule_info->inbound_cb, firewall_product_does_inbound(prod) && sensitive);
    gtk_widget_set_sensitive(rule_info->deny_cb, sensitive);
}

/* Set the rule text based upon the current product and current filter. */
static void
select_filter(GtkWidget *w, gpointer data _U_)
{
    rule_type_e cur_type;
    rule_info_t *rule_info;
    gpointer ptr;

    rule_info = (rule_info_t *)g_object_get_data(G_OBJECT(w), WS_RULE_INFO_KEY);
    if (!rule_info)
        return;


    if (ws_combo_box_get_active_pointer(GTK_COMBO_BOX(w), &ptr))
        cur_type = (rule_type_e)GPOINTER_TO_UINT(ptr);
    else
        cur_type = RT_NONE; /* If nothing selected (eg: nothing in filter list) */

    if (cur_type >= NUM_RULE_TYPES)
        return;

    rule_info->rule_type = cur_type;

    set_rule_text(rule_info);
}

/* Set inbound/outbound */
static void
toggle_inbound(GtkToggleButton *t, gpointer data)
{
    rule_info_t *rule_info = (rule_info_t *) data;

    rule_info->inbound = gtk_toggle_button_get_active(t);

    set_rule_text(rule_info);
}

/* Set deny/allow. */
static void
toggle_deny(GtkToggleButton *t, gpointer data)
{
    rule_info_t *rule_info = (rule_info_t *) data;

    rule_info->deny = gtk_toggle_button_get_active(t);

    set_rule_text(rule_info);
}

/* Set the rule text */
#define DL_ADDR (rt == RT_MAC_SRC ? &(rule_info->dl_src) : &(rule_info->dl_dst))
#define NET_ADDR (rt == RT_IPv4_SRC ? &(rule_info->net_src) : &(rule_info->net_dst))
#define NET_PORT (rt == RT_PORT_SRC ? rule_info->srcport : rule_info->destport)
static void
set_rule_text(rule_info_t *rule_info) {
    GString *rtxt = g_string_new("");
    gchar addr_str[MAX_RULE_LEN];
    rule_type_e rt = rule_info->rule_type;
    size_t prod = rule_info->product;
    address *addr = NULL;
    guint32 port = 0;
    syntax_func rt_func = NULL;

    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(rule_info->text));

    if (prod < firewall_product_count()) {
        const char *hint = firewall_product_rule_hint(prod);
        g_string_printf(rtxt, "%s %s\n", firewall_product_comment_prefix(prod), firewall_product_name(prod));
        if (strlen(hint) > 0) {
            g_string_append_printf(rtxt, " %s", hint);
        }
        switch(rt) {
            case RT_NONE:
                g_string_append_printf(rtxt, "%s Not supported", firewall_product_comment_prefix(prod));
                rt_func = sf_dummy;
                break;
            case RT_MAC_SRC:
            case RT_MAC_DST:
                addr = DL_ADDR;
                address_to_str_buf(addr, addr_str, MAX_RULE_LEN);
                rt_func = firewall_product_mac_func(prod);
                break;
            case RT_IPv4_SRC:
            case RT_IPv4_DST:
                addr = NET_ADDR;
                address_to_str_buf(addr, addr_str, MAX_RULE_LEN);
                rt_func = firewall_product_ipv4_func(prod);
                break;
            case RT_PORT_SRC:
            case RT_PORT_DST:
                port = NET_PORT;
                rt_func = firewall_product_port_func(prod);
                break;
            case RT_IPv4_PORT_SRC:
            case RT_IPv4_PORT_DST:
                addr = NET_ADDR;
                address_to_str_buf(addr, addr_str, MAX_RULE_LEN);
                port = NET_PORT;
                rt_func = firewall_product_ipv4_port_func(prod);
                break;
            default:
                break;
        }
    }

    if (rt_func) {
        rt_func(rtxt, addr_str, port, rule_info->ptype, rule_info->inbound, rule_info->deny);
    } else {
        g_string_append_printf(rtxt, "ERROR: Unable to create rule");
    }

    gtk_text_buffer_set_text(buf, rtxt->str, (gint) rtxt->len);

    g_string_free(rtxt, TRUE);
}


/* Rule text functions */
/* Dummy */
static void sf_dummy(GString *rtxt _U_, gchar *addr _U_, guint32 port _U_, port_type ptype _U_, gboolean inbound _U_, gboolean deny _U_) {
}

/* The destroy call back has the responsibility of
 * unlinking the temporary file
 * and freeing the filter_out_filter */
static void
firewall_destroy_cb(GtkWidget *w, gpointer data _U_)
{
    rule_info_t *rule_info;

    rule_info = (rule_info_t *)g_object_get_data(G_OBJECT(w), WS_RULE_INFO_KEY);
#if 0
    forget_rule_info(rule_info);
#endif
    g_free(rule_info);
    gtk_widget_destroy(w);
}

static void
firewall_copy_cmd_cb(GtkWidget *w _U_, gpointer data)
{
    rule_info_t *rule_info = (rule_info_t *)data;

    GtkTextIter start, end;
    GtkTextBuffer *buf;

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(rule_info->text));
    gtk_text_buffer_get_start_iter(buf, &start);
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_select_range(buf, &start, &end);
    gtk_text_buffer_copy_clipboard(buf, gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));
}

static gboolean
firewall_save_as_ok_cb(char *to_name, rule_info_t *rule_info)
{
    FILE  *fh;
    gchar *rule;

    GtkTextIter start, end;
    GtkTextBuffer *buf;

    fh = ws_fopen(to_name, "w");
    if (fh == NULL) {
        open_failure_alert_box(to_name, errno, TRUE);
        g_free(to_name);
        return FALSE;
    }

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(rule_info->text));
    gtk_text_buffer_get_start_iter(buf, &start);
    gtk_text_buffer_get_end_iter(buf, &end);
    rule = gtk_text_buffer_get_text(buf, &start, &end, FALSE);

    fputs(rule, fh);
    fclose(fh);

    return TRUE;
}

static char *
gtk_firewall_save_as_file(GtkWidget *caller)
{
    GtkWidget   *new_win;
    char        *pathname;

    new_win = file_selection_new("Wireshark: Save Firewall ACL Rule",
                                 GTK_WINDOW(caller),
                                 FILE_SELECTION_SAVE);

    pathname = file_selection_run(new_win);
    if (pathname == NULL) {
        /* User cancelled or closed the dialog. */
        return NULL;
    }

    /* We've crosed the Rubicon; get rid of the dialog box. */
    window_destroy(new_win);

    return pathname;
}

static void
firewall_save_as_cmd_cb(GtkWidget *w, gpointer data)
{
    GtkWidget   *caller = gtk_widget_get_toplevel(w);
    rule_info_t *rule_info = (rule_info_t *)data;
    char        *pathname;

    /*
     * Loop until the user either selects a file or gives up.
     */
    for (;;) {
        pathname = gtk_firewall_save_as_file(caller);
        if (pathname == NULL) {
            /* User gave up. */
            break;
        }
        if (firewall_save_as_ok_cb(pathname, rule_info)) {
            /* We succeeded. */
            g_free(pathname);
            break;
        }
        /* Dump failed; let the user select another file or give up. */
        g_free(pathname);
    }
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
