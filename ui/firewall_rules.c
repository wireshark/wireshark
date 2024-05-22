/* firewall_rules_dlg.c
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

#include <wsutil/array.h>
#include "epan/address.h"

#include "firewall_rules.h"

static void sf_ipfw_mac(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_netfilter_mac(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);

static void sf_ios_std_ipv4(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_ios_ext_ipv4(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_ipfilter_ipv4(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_ipfw_ipv4(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_netfilter_ipv4(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_pf_ipv4(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
/* XXX - Can you addresses-only filters using WFW/netsh? */

static void sf_ios_ext_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_ipfilter_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_ipfw_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_netfilter_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_pf_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_netsh_port_old(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_netsh_port_new(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);

static void sf_ios_ext_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_ipfilter_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_ipfw_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_netfilter_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_pf_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_netsh_ipv4_port_old(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);
static void sf_netsh_ipv4_port_new(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny);

typedef struct _fw_product_t {
    const char *name;
    const char *rule_hint;
    const char *comment_pfx;
    syntax_func mac_func;
    syntax_func ipv4_func;
    syntax_func port_func;
    syntax_func ipv4_port_func;
    bool does_inbound;
} fw_product;

static fw_product products[] = {
    { "Cisco IOS (standard)", "Change NUMBER to a valid ACL number.", "!",
      NULL, sf_ios_std_ipv4, NULL, NULL, false },
    { "Cisco IOS (extended)", "Change NUMBER to a valid ACL number.", "!",
        NULL, sf_ios_ext_ipv4, sf_ios_ext_port, sf_ios_ext_ipv4_port, true },
    { "IP Filter (ipfilter)", "Change le0 to a valid interface if needed.", "#",
        NULL, sf_ipfilter_ipv4, sf_ipfilter_port, sf_ipfilter_ipv4_port, true },
    { "IPFirewall (ipfw)", "", "#",
        sf_ipfw_mac, sf_ipfw_ipv4, sf_ipfw_port, sf_ipfw_ipv4_port, true },
    { "Netfilter (iptables)", "Change eth0 to a valid interface if needed.", "#",
        sf_netfilter_mac, sf_netfilter_ipv4, sf_netfilter_port,
        sf_netfilter_ipv4_port, true },
    { "Packet Filter (pf)", "$ext_if should be set to a valid interface.", "#",
        NULL, sf_pf_ipv4, sf_pf_port, sf_pf_ipv4_port, true },
    { "Windows Firewall (netsh old syntax)", "", "#",
        NULL, NULL, sf_netsh_port_old, sf_netsh_ipv4_port_old, false },
    { "Windows Firewall (netsh new syntax)", "", "#",
        NULL, NULL, sf_netsh_port_new, sf_netsh_ipv4_port_new, false }
};
#define NUM_PRODS array_length(products)


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

bool firewall_product_does_inbound(size_t product_idx)
{
    if (product_idx >= NUM_PRODS) return false;
    return products[product_idx].does_inbound;
}


/* MAC */
#define IPFW_RULE(deny) ((deny) ? "deny" : "allow")
#define IPFW_DIR(inbound) ((inbound) ? "in" : "out")
static void sf_ipfw_mac(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype _U_, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "add %s MAC %s any %s",
        IPFW_RULE(deny), addr, IPFW_DIR(inbound));
}

#define NF_RULE(deny) ((deny) ? "DROP" : "ACCEPT")
#define NF_DIR(inbound) ((inbound) ? "INPUT" : "OUTPUT")
static void sf_netfilter_mac(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype _U_, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "iptables --append %s --in-interface eth0 --mac-source %s --jump %s",
        NF_DIR(inbound), addr, NF_RULE(deny));
}

/* IPv4 */
#define IOS_RULE(deny) ((deny) ? "deny" : "permit")
static void sf_ios_std_ipv4(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype _U_, bool inbound _U_, bool deny) {
    g_string_append_printf(rtxt, "access-list NUMBER %s host %s", IOS_RULE(deny), addr);
}

static void sf_ios_ext_ipv4(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype _U_, bool inbound, bool deny) {
    if (inbound)
        g_string_append_printf(rtxt, "access-list NUMBER %s ip host %s any", IOS_RULE(deny), addr);
    else
        g_string_append_printf(rtxt, "access-list NUMBER %s ip any host %s", IOS_RULE(deny), addr);
}

#define IPFILTER_RULE(deny) ((deny) ? "block" : "pass")
#define IPFILTER_DIR(inbound) ((inbound) ? "in" : "out")

static void sf_ipfilter_ipv4(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype _U_, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "%s %s on le0 from %s to any",
        IPFILTER_RULE(deny), IPFILTER_DIR(inbound), addr);
}

static void sf_ipfw_ipv4(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype _U_, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "add %s ip from %s to any %s",
        IPFW_RULE(deny), addr, IPFW_DIR(inbound));
}

#define NF_ADDR_DIR(inbound) ((inbound) ? "--source" : "--destination")
static void sf_netfilter_ipv4(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype _U_, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "iptables --append %s --in-interface eth0 %s %s/32 --jump %s",
        NF_DIR(inbound), NF_ADDR_DIR(inbound), addr, NF_RULE(deny));
}

#define PF_RULE(deny) ((deny) ? "block" : "pass")
#define PF_DIR(inbound) ((inbound) ? "in" : "out")
static void sf_pf_ipv4(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype _U_, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "%s %s quick on $ext_if from %s to any",
        PF_RULE(deny), PF_DIR(inbound), addr);
}

/* Port */
#define RT_TCP_UDP(ptype) ((ptype) == PT_TCP ? "tcp" : "udp")
static void sf_ios_ext_port(GString *rtxt, char *addr _U_, uint32_t port, port_type ptype, bool inbound _U_, bool deny) {
    g_string_append_printf(rtxt, "access-list NUMBER %s %s any any eq %u",
        IOS_RULE(deny), RT_TCP_UDP(ptype), port);
}

static void sf_ipfilter_port(GString *rtxt, char *addr _U_, uint32_t port, port_type ptype, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "%s %s on le0 proto %s from any to any port = %u",
        IPFILTER_RULE(deny), IPFILTER_DIR(inbound), RT_TCP_UDP(ptype), port);
}

static void sf_ipfw_port(GString *rtxt, char *addr _U_, uint32_t port, port_type ptype, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "add %s %s from any to any %u %s",
        IPFW_RULE(deny), RT_TCP_UDP(ptype), port, IPFW_DIR(inbound));
}

#define NF_PORT_DIR(inbound) ((inbound) ? "--source-port" : "--destination-port")
static void sf_netfilter_port(GString *rtxt, char *addr _U_, uint32_t port, port_type ptype, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "iptables --append %s --in-interface eth0 --protocol %s %s %u --jump %s",
            NF_DIR(inbound), RT_TCP_UDP(ptype), NF_PORT_DIR(inbound), port, NF_RULE(deny));
}

static void sf_pf_port(GString *rtxt, char *addr _U_, uint32_t port, port_type ptype, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "%s %s quick on $ext_if proto %s from any to any port %u",
        PF_RULE(deny), PF_DIR(inbound), RT_TCP_UDP(ptype), port);
}

#define NETSH_RULE_OLD(deny) ((deny) ? "DISABLE" : "ENABLE")
static void sf_netsh_port_old(GString *rtxt, char *addr _U_, uint32_t port, port_type ptype, bool inbound _U_, bool deny) {
    g_string_append_printf(rtxt, "add portopening %s %u Wireshark %s",
        RT_TCP_UDP(ptype), port, NETSH_RULE_OLD(deny));
}

#define NETSH_RULE_NEW(deny) ((deny) ? "block" : "allow")
static void sf_netsh_port_new(GString *rtxt, char *addr _U_, uint32_t port, port_type ptype, bool inbound _U_, bool deny) {
    g_string_append_printf(rtxt, "add rule name=\"Wireshark\" dir=in action=%s protocol=%s localport=%u",
        NETSH_RULE_NEW(deny), RT_TCP_UDP(ptype), port);
}

/* IPv4 + port */
static void sf_ios_ext_ipv4_port(GString *rtxt, char *addr, uint32_t port _U_, port_type ptype, bool inbound, bool deny) {
    if (inbound)
        g_string_append_printf(rtxt, "access-list NUMBER %s %s host %s eq %u any", IOS_RULE(deny), RT_TCP_UDP(ptype), addr, port);
    else
        g_string_append_printf(rtxt, "access-list NUMBER %s %s any host %s eq %u", IOS_RULE(deny), RT_TCP_UDP(ptype), addr, port);
}

static void sf_ipfilter_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny) {
    if (inbound)
        g_string_append_printf(rtxt, "%s %s on le0 proto %s from %s port = %u to any",
            IPFILTER_RULE(deny), IPFILTER_DIR(inbound), RT_TCP_UDP(ptype), addr, port);
    else
        g_string_append_printf(rtxt, "%s %s on le0 proto %s from any to %s port = %u",
            IPFILTER_RULE(deny), IPFILTER_DIR(inbound), RT_TCP_UDP(ptype), addr, port);
}

static void sf_ipfw_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "add %s %s from %s %u to any %s",
        IPFW_RULE(deny), RT_TCP_UDP(ptype), addr, port, IPFW_DIR(inbound));
}

static void sf_pf_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "%s %s quick on $ext_if proto %s from %s to any port %u",
        PF_RULE(deny), PF_DIR(inbound), RT_TCP_UDP(ptype), addr, port);
}

static void sf_netfilter_ipv4_port(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound, bool deny) {
    g_string_append_printf(rtxt, "iptables --append %s --in-interface eth0 --protocol %s %s %s/32 %s %u --jump %s",
        NF_DIR(inbound), RT_TCP_UDP(ptype), NF_ADDR_DIR(inbound), addr, NF_PORT_DIR(inbound), port, NF_RULE(deny));
}

static void sf_netsh_ipv4_port_old(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound _U_, bool deny) {
    g_string_append_printf(rtxt, "add portopening %s %u Wireshark %s %s",
        RT_TCP_UDP(ptype), port, NETSH_RULE_OLD(deny), addr);
}

static void sf_netsh_ipv4_port_new(GString *rtxt, char *addr, uint32_t port, port_type ptype, bool inbound _U_, bool deny) {
    g_string_append_printf(rtxt, "add rule name=\"Wireshark\" dir=in action=%s protocol=%s localport=%u remoteip=%s",
        NETSH_RULE_NEW(deny), RT_TCP_UDP(ptype), port, addr);
}
