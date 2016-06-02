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

/*
 * To add a new product, add syntax functions modify the products[] array.
 *
 * To add a new syntax function, add its prototype above the products[]
 * array, and add the function below with all the others.
 */

 /* Copied from gtk/firewall_rules.c */

#include "config.h"

#include <glib.h>

#include "epan/address.h"

#include "firewall_rules.h"

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
    const char *name;
    const char *rule_hint;
    const char *comment_pfx;
    syntax_func mac_func;
    syntax_func ipv4_func;
    syntax_func port_func;
    syntax_func ipv4_port_func;
    gboolean does_inbound;
} fw_product;

static fw_product products[] = {
    { "Cisco IOS (standard)", "Change NUMBER to a valid ACL number.", "!",
      NULL, sf_ios_std_ipv4, NULL, NULL, FALSE },
    { "Cisco IOS (extended)", "Change NUMBER to a valid ACL number.", "!",
        NULL, sf_ios_ext_ipv4, sf_ios_ext_port, sf_ios_ext_ipv4_port, TRUE },
    { "IP Filter (ipfilter)", "Change le0 to a valid interface if needed.", "#",
        NULL, sf_ipfilter_ipv4, sf_ipfilter_port, sf_ipfilter_ipv4_port, TRUE },
    { "IPFirewall (ipfw)", "", "#",
        sf_ipfw_mac, sf_ipfw_ipv4, sf_ipfw_port, sf_ipfw_ipv4_port, TRUE },
    { "Netfilter (iptables)", "Change eth0 to a valid interface if needed.", "#",
        sf_netfilter_mac, sf_netfilter_ipv4, sf_netfilter_port,
        sf_netfilter_ipv4_port, TRUE },
    { "Packet Filter (pf)", "$ext_if should be set to a valid interface.", "#",
        NULL, sf_pf_ipv4, sf_pf_port, sf_pf_ipv4_port, TRUE },
    { "Windows Firewall (netsh)", "", "#",
        NULL, NULL, sf_netsh_port, sf_netsh_ipv4_port, FALSE }
};
#define NUM_PRODS (sizeof(products) / sizeof(fw_product))


size_t firewall_product_count(void)
{
    return NUM_PRODS;
}

const char *firewall_product_name(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return "Unknown";
    return products[product_idx].name;
}

const char *firewall_product_rule_hint(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return "";
    return products[product_idx].rule_hint;
}

const char *firewall_product_comment_prefix(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return "";
    return products[product_idx].comment_pfx;
}

syntax_func firewall_product_mac_func(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return NULL;
    return products[product_idx].mac_func;
}


syntax_func firewall_product_ipv4_func(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return NULL;
    return products[product_idx].ipv4_func;
}


syntax_func firewall_product_port_func(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return NULL;
    return products[product_idx].port_func;
}


syntax_func firewall_product_ipv4_port_func(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return NULL;
    return products[product_idx].ipv4_port_func;
}

gboolean firewall_product_does_inbound(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return FALSE;
    return products[product_idx].does_inbound;
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
    g_string_append_printf(rtxt, "iptables --append %s --in-interface eth0 --mac-source %s --jump %s",
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

#define NF_ADDR_DIR (inbound ? "--source" : "--destination")
static void sf_netfilter_ipv4(GString *rtxt, gchar *addr, guint32 port _U_, port_type ptype _U_, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "iptables --append %s --in-interface eth0 %s %s/32 --jump %s",
        NF_INPUT, NF_ADDR_DIR, addr, NF_DROP);
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

#define NF_PORT_DIR (inbound ? "--source-port" : "--destination-port")
static void sf_netfilter_port(GString *rtxt, gchar *addr _U_, guint32 port, port_type ptype, gboolean inbound, gboolean deny) {
    g_string_append_printf(rtxt, "iptables --append %s --in-interface eth0 --protocol %s %s %u --jump %s",
            NF_INPUT, RT_TCP_UDP, NF_PORT_DIR, port, NF_DROP);
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
    g_string_append_printf(rtxt, "iptables --append %s --in-interface eth0 --protocol %s %s %s/32 %s %u --jump %s",
        NF_INPUT, RT_TCP_UDP, NF_ADDR_DIR, addr, NF_PORT_DIR, port, NF_DROP);
}

static void sf_netsh_ipv4_port(GString *rtxt, gchar *addr, guint32 port, port_type ptype, gboolean inbound _U_, gboolean deny) {
    g_string_append_printf(rtxt, "add portopening %s %u Wireshark %s %s",
        RT_TCP_UDP, port, NETSH_DENY, addr);
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
