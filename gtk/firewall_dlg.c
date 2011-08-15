/* firewall_rules_dlg.c
 *
 * $Id$
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
 * Generate firewall ACL rules based on packet addresses and ports.
 * For directional rules, an outside interface is assumed.
 *
 * There may be better ways to present the information, e.g. all rules
 * in one huge text window, or some sort of tree view.
 */

/*
 * To add a new product, add syntax functions modify the products[] array.
 *
 * To add a new syntax function, add its prototype above the products[]
 * array, and add the function below with all the others.
 */

/* Copied from ssl-dlg.c */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <gtk/gtk.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/epan_dissect.h>
#include <epan/filesystem.h>
#include <epan/dissectors/packet-ipv6.h>

#include <../alert_box.h>
#include <../simple_dialog.h>
#include <wsutil/file_util.h>

#include <gtk/main.h>
#include <gtk/dlg_utils.h>
#include <gtk/file_dlg.h>
#include <gtk/help_dlg.h>
#include <gtk/gui_utils.h>
#include "gtk/old-gtk-compat.h"
#include "gtk/firewall_dlg.h"

#define MAX_RULE_LEN 200

/* Rule types */
typedef enum {
    RT_NONE,
    RT_MAC_SRC,
    RT_MAC_DST,
    RT_IPv4_SRC,
    RT_IPv4_DST,
    RT_PORT_SRC,
    RT_PORT_DST,
    RT_IPv4_PORT_SRC,
    RT_IPv4_PORT_DST,
    NUM_RULE_TYPES
} rule_type_t;


/* Copied from packet_info struct */
typedef struct _rule_info_t {
    gint product;
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
    GtkWidget *firewall_save_as_w;
    gboolean inbound;
    gboolean deny;
    rule_type_t rule_type;
} rule_info_t;

/* Syntax function prototypes */
typedef void (*syntax_func)(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);

static void sf_dummy(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);

static void sf_ipfw_mac(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_netfilter_mac(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);

static void sf_ios_std_ipv4(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_ios_ext_ipv4(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_ipfilter_ipv4(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_ipfw_ipv4(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_netfilter_ipv4(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_pf_ipv4(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
/* XXX - Can you addresses-only filters using WFW/netsh? */

static void sf_ios_ext_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_ipfilter_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_ipfw_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_netfilter_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_pf_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_netsh_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);

static void sf_ios_ext_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_ipfilter_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_ipfw_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_netfilter_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_pf_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);
static void sf_netsh_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny);

typedef struct _fw_product_t {
    gchar *name;
    gchar *comment_pfx;
    syntax_func mac_func;
    syntax_func ipv4_func;
    syntax_func port_func;
    syntax_func ipv4_port_func;
    gboolean does_inbound;
} fw_product;

static fw_product products[] = {
    { "Cisco IOS (standard)", "!", NULL, sf_ios_std_ipv4, NULL, NULL, FALSE },
    { "Cisco IOS (extended)", "!",
        NULL, sf_ios_ext_ipv4, sf_ios_ext_port, sf_ios_ext_ipv4_port, TRUE },
    { "IP Filter (ipfilter)", "#",
        NULL, sf_ipfilter_ipv4, sf_ipfilter_port, sf_ipfilter_ipv4_port, TRUE },
    { "IPFirewall (ipfw)", "#",
        sf_ipfw_mac, sf_ipfw_ipv4, sf_ipfw_port, sf_ipfw_ipv4_port, TRUE },
    { "Netfilter (iptables)", "#",
        sf_netfilter_mac, sf_netfilter_ipv4, sf_netfilter_port,
        sf_netfilter_ipv4_port, TRUE },
    { "Packet Filter (pf)", "#",
        NULL, sf_pf_ipv4, sf_pf_port, sf_pf_ipv4_port, TRUE },
    { "Windows Firewall (netsh)", "#",
        NULL, NULL, sf_netsh_port, sf_netsh_ipv4_port, FALSE }
};
#define NUM_PRODS (sizeof(products) / sizeof(fw_product))


static void select_product(GtkWidget * win, gpointer data);
static void select_filter(GtkWidget * win, gpointer data);
static void toggle_inbound(GtkToggleButton *t, gpointer data);
static void toggle_deny(GtkToggleButton *t, gpointer data);
static void set_rule_text(rule_info_t *rule_info);
static void firewall_destroy_cb(GtkWidget * win, gpointer data);
static void firewall_copy_cmd_cb(GtkWidget * w, gpointer data);
static void firewall_save_as_cmd_cb(GtkWidget * w, gpointer data);
static gboolean firewall_save_as_ok_cb(GtkWidget * w, gpointer fs);
static void firewall_save_as_destroy_cb(GtkWidget * win, gpointer user_data);

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
    GtkWidget	    *rule_w, *vbox, *txt_scrollw, *text;
    GtkWidget       *label,  *product_combo_box;
    GtkWidget	    *hbox,   *button_hbox, *button;
	rule_info_t	    *rule_info;
    packet_info     *pinfo = &cfile.edt->pi;
    guint i;

    rule_info = g_new0(rule_info_t, 1);
    COPY_ADDRESS(&(rule_info->dl_src), &(pinfo->dl_src));
    COPY_ADDRESS(&(rule_info->dl_dst), &(pinfo->dl_dst));
    COPY_ADDRESS(&(rule_info->net_src), &(pinfo->net_src));
    COPY_ADDRESS(&(rule_info->net_dst), &(pinfo->net_dst));
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
    vbox = gtk_vbox_new(FALSE, 6);
    gtk_container_add(GTK_CONTAINER(rule_w), vbox);

    /* rule type selectors hbox */
    hbox = gtk_hbox_new(FALSE, 1);
    gtk_box_pack_start(GTK_BOX(vbox), hbox, FALSE, FALSE, 0);

    /* product selector */
    label = gtk_label_new("Product");
    gtk_box_pack_start(GTK_BOX(hbox), label, FALSE, FALSE, 0);

    product_combo_box = gtk_combo_box_text_new();
    for (i = 0; i < NUM_PRODS; i++) {
        gtk_combo_box_text_append_text (GTK_COMBO_BOX_TEXT(product_combo_box), products[i].name);
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
    button = g_object_get_data(G_OBJECT(button_hbox), GTK_STOCK_COPY);
    g_signal_connect(button, "clicked", G_CALLBACK(firewall_copy_cmd_cb), rule_info);
	gtk_widget_set_tooltip_text(button, "Copy rule to clipboard");

    /* Create Save Button */
    button = g_object_get_data(G_OBJECT(button_hbox), GTK_STOCK_SAVE);
    g_signal_connect(button, "clicked", G_CALLBACK(firewall_save_as_cmd_cb), rule_info);
	gtk_widget_set_tooltip_text(button, "Save the rule as currently displayed");

    button = g_object_get_data(G_OBJECT(button_hbox), GTK_STOCK_CANCEL);
	gtk_widget_set_tooltip_text(button, "Cancel the dialog");
    window_set_cancel_button(rule_w, button, window_cancel_button_cb);

    button = g_object_get_data(G_OBJECT(button_hbox), GTK_STOCK_HELP);
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
    rule_info_t	*rule_info;
    gchar name[MAX_RULE_LEN], addr_str[MAX_RULE_LEN];
    address *addr;
    rule_type_t rule_type = RT_NONE;
    gboolean sensitive = FALSE;

    rule_info = g_object_get_data(G_OBJECT(w), WS_RULE_INFO_KEY);

    if (prod >= NUM_PRODS || !rule_info)
        return;

    rule_info->product = prod;

    /* Clear the list store (ie: the como_box list items) */
    ws_combo_box_clear_text_and_pointer(GTK_COMBO_BOX(rule_info->filter_combo_box));

    /* Fill in valid combo_box list items (in the list store).   */
    if (products[prod].mac_func && rule_info->dl_src.type == AT_ETHER) {
        addr = &(rule_info->dl_src);
        address_to_str_buf(addr, name, MAX_RULE_LEN);
        ADD_TO_FILTER_MENU(RT_MAC_SRC);

        addr = &(rule_info->dl_dst);
        address_to_str_buf(addr, name, MAX_RULE_LEN);
        ADD_TO_FILTER_MENU(RT_MAC_DST);
    }

    if (products[prod].ipv4_func && rule_info->net_src.type == AT_IPv4) {
        addr = &(rule_info->net_src);
        address_to_str_buf(addr, name, MAX_RULE_LEN);
        ADD_TO_FILTER_MENU(RT_IPv4_SRC);

        addr = &(rule_info->net_dst);
        address_to_str_buf(addr, name, MAX_RULE_LEN);
        ADD_TO_FILTER_MENU(RT_IPv4_DST);
    }

    if (products[prod].port_func && (rule_info->ptype == PT_TCP || rule_info->ptype == PT_UDP)) {
        g_snprintf(name, MAX_RULE_LEN, "%s port %u", NAME_TCP_UDP,
            rule_info->srcport);
        ADD_TO_FILTER_MENU(RT_PORT_SRC);
        if (rule_info->srcport != rule_info->destport) {
            g_snprintf(name, MAX_RULE_LEN, "%s port %u", NAME_TCP_UDP,
                rule_info->destport);
            ADD_TO_FILTER_MENU(RT_PORT_DST);
        }
    }

    if (products[prod].ipv4_port_func && rule_info->net_src.type == AT_IPv4 &&
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
    gtk_widget_set_sensitive(rule_info->inbound_cb, products[prod].does_inbound && sensitive);
    gtk_widget_set_sensitive(rule_info->deny_cb, sensitive);
}

/* Set the rule text based upon the current product and current filter. */
static void
select_filter(GtkWidget *w, gpointer data _U_)
{
    rule_type_t cur_type;
    rule_info_t	*rule_info;
    gpointer ptr;

    rule_info = g_object_get_data(G_OBJECT(w), WS_RULE_INFO_KEY);
    if (!rule_info)
        return;


    if (ws_combo_box_get_active_pointer(GTK_COMBO_BOX(w), &ptr))
        cur_type = GPOINTER_TO_UINT(ptr);
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
    rule_info_t	*rule_info = (rule_info_t *) data;

    rule_info->inbound = gtk_toggle_button_get_active(t);

    set_rule_text(rule_info);
}

/* Set deny/allow. */
static void
toggle_deny(GtkToggleButton *t, gpointer data)
{
    rule_info_t	*rule_info = (rule_info_t *) data;

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
    rule_type_t rt = rule_info->rule_type;
    guint prod = rule_info->product;
    address *addr = NULL;
    guint32 port = 0;
    syntax_func rt_func = NULL;

    GtkTextBuffer *buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(rule_info->text));

    if (prod < NUM_PRODS) {
        g_string_printf(rtxt, "%s %s\n", products[prod].comment_pfx, products[prod].name);
        switch(rt) {
            case RT_NONE:
                g_string_append_printf(rtxt, "%s Not supported", products[prod].comment_pfx);
                rt_func = sf_dummy;
                break;
            case RT_MAC_SRC:
            case RT_MAC_DST:
                addr = DL_ADDR;
                address_to_str_buf(addr, addr_str, MAX_RULE_LEN);
                rt_func = products[prod].mac_func;
                break;
            case RT_IPv4_SRC:
            case RT_IPv4_DST:
                addr = NET_ADDR;
                address_to_str_buf(addr, addr_str, MAX_RULE_LEN);
                rt_func = products[prod].ipv4_func;
                break;
            case RT_PORT_SRC:
            case RT_PORT_DST:
                port = NET_PORT;
                rt_func = products[prod].port_func;
                break;
            case RT_IPv4_PORT_SRC:
            case RT_IPv4_PORT_DST:
                addr = NET_ADDR;
                address_to_str_buf(addr, addr_str, MAX_RULE_LEN);
                port = NET_PORT;
                rt_func = products[prod].ipv4_port_func;
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

/* MAC */
#define IPFW_DENY (deny ? "deny" : "allow")
#define IPFW_IN (inbound ? "in" : "out")
static void sf_ipfw_mac(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "add %s MAC %s any %s",
        IPFW_DENY, addr, IPFW_IN);
}

#define NF_DROP (deny ? "DROP" : "ACCEPT")
#define NF_INPUT (inbound ? "INPUT" : "OUTPUT")
static void sf_netfilter_mac(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "iptables -A %s --mac-source %s -j %s",
        NF_INPUT, addr, NF_DROP);
}

/* IPv4 */
#define IOS_DENY (deny ? "deny" : "permit")
static void sf_ios_std_ipv4(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound _U_, gboolean deny) {
    g_string_append_printf(rtxt, "access-list NUMBER %s host %s", IOS_DENY, addr);
}

static void sf_ios_ext_ipv4(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    if (inbound)
        g_string_append_printf(rtxt, "access-list NUMBER %s ip host %s any", IOS_DENY, addr);
    else
        g_string_append_printf(rtxt, "access-list NUMBER %s ip any host %s", IOS_DENY, addr);
}

#define IPFILTER_DENY (deny ? "block" : "pass")
#define IPFILTER_IN (inbound ? "in" : "out")
static void sf_ipfilter_ipv4(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "%s %s on le0 from %s to any",
        IPFILTER_DENY, IPFILTER_IN, addr);
}

static void sf_ipfw_ipv4(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "add %s ip from %s to any %s",
        IPFW_DENY, addr, IPFW_IN);
}

static void sf_netfilter_ipv4(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "iptables -A %s -i eth0 -d %s/32 -j %s",
        NF_INPUT, addr, NF_DROP);
}

#define PF_DENY (deny ? "block" : "pass")
#define PF_IN (inbound ? "in" : "out")
static void sf_pf_ipv4(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "%s %s quick on $ext_if from %s to any",
        PF_DENY, PF_IN, addr);
}

/* Port */
#define RT_TCP_UDP (ptype == PT_TCP ? "tcp" : "udp")
static void sf_ios_ext_port(GString *rtxt, gchar *addr _U_, guint32 port, port_type ptype, gboolean inbound _U_, gboolean deny) {
    g_string_append_printf(rtxt, "access-list NUMBER %s %s any any eq %u",
        IOS_DENY, RT_TCP_UDP, port);
}

static void sf_ipfilter_port(GString *rtxt, gchar *addr _U_, guint32 port, port_type ptype _U_, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "%s %s on le0 proto %s from any to any port = %u",
        IPFILTER_DENY, IPFILTER_IN, RT_TCP_UDP, port);
}

static void sf_ipfw_port(GString *rtxt, gchar *addr _U_, guint32 port, port_type ptype, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "add %s %s from any to any %u %s",
        IPFW_DENY, RT_TCP_UDP, port, IPFW_IN);
}

static void sf_netfilter_port(GString *rtxt, gchar *addr _U_, guint32 port, port_type ptype, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "iptables -A %s -p %s --destination-port %u -j %s",
            NF_INPUT, RT_TCP_UDP, port, NF_DROP);
}

static void sf_pf_port(GString *rtxt, gchar *addr _U_, guint32 port, port_type ptype, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "%s %s quick on $ext_if proto %s from any to any port %u",
        PF_DENY, PF_IN, RT_TCP_UDP, port);
}

#define NETSH_DENY (deny ? "DISABLE" : "ENABLE")
static void sf_netsh_port(GString *rtxt, gchar *addr _U_, guint32 port, port_type ptype, gboolean inbound _U_, gboolean deny) {
    g_string_append_printf(rtxt, "add portopening %s %u Wireshark %s",
        RT_TCP_UDP, port, NETSH_DENY);
}

/* IPv4 + port */
static void sf_ios_ext_ipv4_port(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    if (inbound)
        g_string_append_printf(rtxt, "access-list NUMBER %s %s host %s any eq %u", IOS_DENY, RT_TCP_UDP, addr, port);
    else
        g_string_append_printf(rtxt, "access-list NUMBER %s %s any host %s eq %u", IOS_DENY, RT_TCP_UDP, addr, port);
}

static void sf_ipfilter_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny) {
    if (inbound)
        g_string_append_printf(rtxt, "%s %s on le0 proto %s from %s to any port = %u",
            IPFILTER_DENY, IPFILTER_IN, RT_TCP_UDP, addr, port);
    else
        g_string_append_printf(rtxt, "%s %s on le0 proto %s from any to %s port = %u",
            IPFILTER_DENY, IPFILTER_IN, RT_TCP_UDP, addr, port);
}

static void sf_ipfw_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "add %s %s from %s to any %u %s",
        IPFW_DENY, RT_TCP_UDP, addr, port, IPFW_IN);
}

static void sf_pf_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "%s %s quick on $ext_if proto %s from %s to any port %u",
        PF_DENY, PF_IN, RT_TCP_UDP, addr, port);
}

static void sf_netfilter_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "iptables -A %s -p %s -d %s/32 --destination-port %u -j %s",
        NF_INPUT, RT_TCP_UDP, addr, port, NF_DROP);
}

static void sf_netsh_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound _U_, gboolean deny) {
    g_string_append_printf(rtxt, "add portopening %s %u Wireshark %s %s",
        RT_TCP_UDP, port, NETSH_DENY, addr);
}

/* The destroy call back has the responsibility of
 * unlinking the temporary file
 * and freeing the filter_out_filter */
static void
firewall_destroy_cb(GtkWidget *w, gpointer data _U_)
{
    rule_info_t	*rule_info;

    rule_info = g_object_get_data(G_OBJECT(w), WS_RULE_INFO_KEY);
#if 0
    forget_rule_info(rule_info);
#endif
    g_free(rule_info);
	gtk_object_destroy(GTK_OBJECT(w));
}

static void
firewall_copy_cmd_cb(GtkWidget *w _U_, gpointer data)
{
    rule_info_t	*rule_info = data;

    GtkTextIter start, end;
    GtkTextBuffer *buf;

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(rule_info->text));
    gtk_text_buffer_get_start_iter(buf, &start);
    gtk_text_buffer_get_end_iter(buf, &end);
    gtk_text_buffer_select_range(buf, &start, &end);
    gtk_text_buffer_copy_clipboard(buf, gtk_clipboard_get(GDK_SELECTION_CLIPBOARD));
}

/*
 * Keep a static pointer to the current "Save SSL Follow Stream As" window, if
 * any, so that if somebody tries to do "Save"
 * while there's already a "Save SSL Follow Stream" window up, we just pop
 * up the existing one, rather than creating a new one.
 */
static void
firewall_save_as_cmd_cb(GtkWidget *w _U_, gpointer data)
{
    GtkWidget		*new_win;
    rule_info_t	*rule_info = data;

#if 0  /* XXX: GtkFileChooserDialog/gtk_dialog_run currently being used is effectively modal so this is not req'd */
    if (rule_info->firewall_save_as_w != NULL) {
	/* There's already a dialog box; reactivate it. */
	reactivate_window(rule_info->firewall_save_as_w);
	return;
    }
#endif
    new_win = file_selection_new("Wireshark: Save Firewall ACL Rule",
                                 FILE_SELECTION_SAVE);
    rule_info->firewall_save_as_w = new_win;
    gtk_file_chooser_set_do_overwrite_confirmation(GTK_FILE_CHOOSER(new_win), TRUE);

    /* Tuck away the rule_info object into the window */
    g_object_set_data(G_OBJECT(new_win), WS_RULE_INFO_KEY, rule_info);

    g_signal_connect(new_win, "destroy", G_CALLBACK(firewall_save_as_destroy_cb), rule_info);

#if 0
    if (gtk_dialog_run(GTK_DIALOG(new_win)) == GTK_RESPONSE_ACCEPT)
    {
        firewall_save_as_ok_cb(new_win, new_win);
    } else {
        window_destroy(new_win);
    }
#else
    /* "Run" the GtkFileChooserDialog.                                              */
    /* Upon exit: If "Accept" run the OK callback.                                  */
    /*            If the OK callback returns with a FALSE status, re-run the dialog.*/
    /*            If not accept (ie: cancel) destroy the window.                    */
    /* XXX: If the OK callback pops up an alert box (eg: for an error) it *must*    */
    /*      return with a TRUE status so that the dialog window will be destroyed.  */
    /*      Trying to re-run the dialog after popping up an alert box will not work */
    /*       since the user will not be able to dismiss the alert box.              */
    /*      The (somewhat unfriendly) effect: the user must re-invoke the           */
    /*      GtkFileChooserDialog whenever the OK callback pops up an alert box.     */
    /*                                                                              */
    /*      ToDo: use GtkFileChooserWidget in a dialog window instead of            */
    /*            GtkFileChooserDialog.                                             */
    while (gtk_dialog_run(GTK_DIALOG(new_win)) == GTK_RESPONSE_ACCEPT) {
        if (firewall_save_as_ok_cb(NULL, new_win)) {
            break; /* we're done */
        }
    }
    window_destroy(new_win);
#endif
}


static gboolean
firewall_save_as_ok_cb(GtkWidget * w _U_, gpointer fs)
{
    gchar	*to_name, *rule;
    rule_info_t	*rule_info;
    FILE 	*fh;
    gchar	*dirname;

    GtkTextIter start, end;
    GtkTextBuffer *buf;

    to_name = gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(fs));

    /* Perhaps the user specified a directory instead of a file.
       Check whether they did. */
    if (test_for_directory(to_name) == EISDIR) {
        /* It's a directory - set the file selection box to display that
           directory, and leave the selection box displayed. */
        set_last_open_dir(to_name);
        g_free(to_name);
        file_selection_set_current_folder(fs, get_last_open_dir());
        gtk_file_chooser_set_current_name(fs, "");
        return FALSE; /* run the dialog again */
    }

    rule_info = g_object_get_data(G_OBJECT(fs), WS_RULE_INFO_KEY);
    fh = ws_fopen(to_name, "w");
    if (fh == NULL) {
        open_failure_alert_box(to_name, errno, TRUE);
        g_free(to_name);
        return TRUE;
    }

    buf = gtk_text_view_get_buffer(GTK_TEXT_VIEW(rule_info->text));
    gtk_text_buffer_get_start_iter(buf, &start);
    gtk_text_buffer_get_end_iter(buf, &end);
    rule = gtk_text_buffer_get_text(buf, &start, &end, FALSE);

    fputs(rule, fh);
    fclose(fh);

#if 0 /* handled by caller (for now) */
    gtk_widget_hide(GTK_WIDGET(fs));
    window_destroy(GTK_WIDGET(fs));
#endif
    /* Save the directory name for future file dialogs. */
    dirname = get_dirname(to_name);  /* Overwrites to_name */
    set_last_open_dir(dirname);
    g_free(to_name);

    return TRUE;
}

static void
firewall_save_as_destroy_cb(GtkWidget * win _U_, gpointer data)
{
    rule_info_t	*rule_info = data;

    /* Note that we no longer have a dialog box. */
    rule_info->firewall_save_as_w = NULL;
}
