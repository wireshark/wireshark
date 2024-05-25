/*
 * Wireshark - Network traffic analyzer
 *
 * Copyright 1998 Gerald Combs <gerald@wireshark.org>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

// #include "config.h"
// #define WS_LOG_DOMAIN LOG_DOMAIN_DFILTER

#include <wireshark.h>

#include <epan/value_string.h>

#include "dfilter.h"
#include "dfilter-translator.h"
#include "sttype-field.h"
#include "sttype-op.h"

// name: DFTranslator
static GHashTable *registered_translators_;

static void cleanup_hash_table_key(gpointer data)
{
    g_free(data);
}

bool register_dfilter_translator(const char *translator_name, DFTranslator translator)
{
    if (!registered_translators_) {
        registered_translators_ = g_hash_table_new_full(g_str_hash,
                                                        g_str_equal,
                                                        cleanup_hash_table_key,
                                                        NULL);
    }
    return g_hash_table_insert(registered_translators_, g_strdup(translator_name), translator);
}

void deregister_dfilter_translator(const char *translator_name)
{
    if (!registered_translators_) {
        return;
    }
    g_hash_table_remove(registered_translators_, translator_name);
}

char **get_dfilter_translator_list(void)
{
    if (!registered_translators_) {
        return NULL;
    }

    GList *key_l = g_list_sort(g_hash_table_get_keys(registered_translators_), (GCompareFunc)g_ascii_strcasecmp);
    size_t key_count = g_list_length(key_l);
    if (key_count < 1) {
        g_list_free(key_l);
        return NULL;
    }

    char **translator_list = g_malloc(sizeof(char *) * (key_count + 1));
    size_t idx = 0;
    for (GList *cur = g_list_first(key_l); cur; cur = g_list_next(cur), idx++) {
        translator_list[idx] = (char *) cur->data;
    }
    translator_list[key_count] = NULL;

    g_list_free(key_l);
    return translator_list;
}

// XXX We should return an error message for failed translations.
const char *translate_dfilter(const char *translator_name, const char *dfilter)
{
    if (!registered_translators_ || !translator_name) {
        return NULL;
    }

    DFTranslator translator = (DFTranslator) g_hash_table_lookup(registered_translators_, translator_name);
    if (!translator) {
        return NULL;
    }

    stnode_t *root_node = dfilter_get_syntax_tree(dfilter);
    if (!root_node) {
        return NULL;
    }

    GString *translated_filter = g_string_new("");
    bool res = translator(root_node, translated_filter);
    stnode_free(root_node);

    return g_string_free(translated_filter, !res);
}


// pcap filter (BPF) translation
// XXX - Fields are spread across all sorts of dissectors; not sure if there is a better place for this.

const char *
stnode_op_to_pcap_filter(stnode_op_t op) {
    switch (op) {
    case STNODE_OP_NOT:         return "not";
    case STNODE_OP_AND:         return "&&";
    case STNODE_OP_OR:          return "||";
    case STNODE_OP_ANY_EQ:      return "";
    // case STNODE_OP_ALL_NE:      return "!=";
    case STNODE_OP_GT:          return "greater";
    // case STNODE_OP_GE:          return ">=";
    case STNODE_OP_LT:          return "less";
    // case STNODE_OP_LE:          return "<=";
    // case STNODE_OP_CONTAINS:    return "icontains";
    case STNODE_OP_UNARY_MINUS: return "-";
    case STNODE_OP_IN:
    case STNODE_OP_NOT_IN:
    default:
        break;
    }
    return NULL;
}

// scanner.l in libpcap
static const string_string abbrev_to_pcap_filter[] = {
    { "eth", "ether" },
    { "eth.addr", "ether host" },
    { "eth.dst", "ether dst" },
    { "eth.src", "ether src" },
    { "ppp", "ppp" },
    // { "slip", "slip" },
    { "fddi", "fddi" },
    { "fddi.addr", "fddi host" },
    { "fddi.dst", "fddi dst" },
    { "fddi.src", "fddi src" },
    { "tr", "tr" },
    { "tr.addr", "tr host" },
    { "tr.dst", "tr dst" },
    { "tr.src", "tr src" },
    { "wlan", "wlan" },
    { "wlan.addr", "wlan host" },
    { "wlan.ra", "wlan ra" },
    { "wlan.ta", "wlan ta" },
    // { "wlan.da", "wlan" },
    // { "wlan", "wlan addr1" },
    // { "wlan", "wlan addr2" },
    // { "wlan", "wlan addr3" },
    // { "wlan", "wlan addr4" },
    { "arp", "arp" },
    { "rarp", "rarp" },
    { "ip", "ip" },
    { "ip.addr", "ip host" },
    { "ip.dst", "ip dst" },
    { "ip.src", "ip src" },
    { "ip.proto", "ip proto" },
    { "sctp", "sctp" },
    { "sctp.port", "sctp port" },
    { "sctp.dstport", "sctp dst port" },
    { "sctp.srcport", "sctp src port" },
    { "tcp", "tcp" },
    { "tcp.port", "tcp port" },
    { "tcp.dstport", "tcp dst port" },
    { "tcp.srcport", "tcp src port" },
    { "udp", "udp" },
    { "udp.port", "udp port" },
    { "udp.dstport", "udp dst port" },
    { "udp.srcport", "tcp src port" },
    { "icmp", "icmp" },
    { "igmp", "igmp" },
    { "igrp", "igrp" },
    { "pim", "pim" },
    { "vrrp", "vrrp" },
    { "carp", "carp" },
    // { "", "radio" },
    { "ipv6", "ip6" },
    { "ipv6.addr", "ip6 host" },
    { "ipv6.dst", "ip6 dst" },
    { "ipv6.src", "ip6 src" },
    { "icmpv6", "icmp6" },
    { "ah", "ah" },
    { "esp", "esp" },
    // { "", "atalk" },
    { "aarp", "aarp" },
    // { "", "decnet" },
    { "lat", "lat" },
    // { "", "sca" },
    // { "", "moprc" },
    // { "", "mopdl" },
    // { "", "iso" },
    { "esis", "esis" },
    { "isis", "isis" },
    // { "", "l1" },
    // { "", "l2" },
    // { "", "iih" },
    // { "", "lsp" },
    // { "", "snp" },
    // { "", "clnp" },
    // { "", "psnp" },
    { "dec_stp", "stp" },
    { "ipx", "ipx" },
    { "netbios", "netbeui" },
    { "vlan", "vlan" },
    { "mpls", "mpls" },
    { "pppoed", "pppoed" },
    { "pppoes", "pppoes" },
    { "geneve", "geneve" },
    { "lane", "lane" },
    { "llc", "llc" },
    // { "", "metac" },
    // { "", "bcc" },
    // { "", "oam" },
    // { "", "oamf4" },
    // { "", "oamf4ec" },
    // { "", "oamf4sc" },
    // { "", "sc" },
    // { "", "ilmic" },
    // { "", "vpi" },
    // { "", "vci" },
    // { "", "connectmsg" },
    // { "", "metaconnect" },
    { NULL, NULL }
};

// NOLINTNEXTLINE(misc-no-recursion)
bool pcap_visit_dfilter_node(stnode_t *node, stnode_op_t parent_bool_op, GString *pcap_filter)
{
    stnode_t *left, *right;

    if (stnode_type_id(node) == STTYPE_TEST) {
        stnode_op_t op = STNODE_OP_UNINITIALIZED;
        sttype_oper_get(node, &op, &left, &right);

        const char *op_str = stnode_op_to_pcap_filter(op);
        if (!op_str) {
            return false;
        }

        if (left && right) {
            if ((op == STNODE_OP_ANY_EQ || op == STNODE_OP_ALL_NE) && stnode_type_id(right) != STTYPE_FVALUE) {
                // Don't translate things like "ip.src == ip.dst"
                return false;
            }
            bool add_parens = (op == STNODE_OP_AND || op == STNODE_OP_OR) && op != parent_bool_op && parent_bool_op != STNODE_OP_UNINITIALIZED;
            if (add_parens) {
                g_string_append_c(pcap_filter, '(');
            }
            if (!pcap_visit_dfilter_node(left, op, pcap_filter)) {
                return false;
            }
            if (strlen(op_str) > 0) {
                g_string_append_c(pcap_filter, ' ');
            }
            g_string_append_printf(pcap_filter, "%s ", op_str);
            if (!pcap_visit_dfilter_node(right, op, pcap_filter)) {
                return false;
            }
            if (add_parens) {
                g_string_append_c(pcap_filter, ')');
            }
        }
        else if (left) {
            op = op == STNODE_OP_NOT ? op : parent_bool_op;
            if (pcap_filter->len > 0) {
                g_string_append_c(pcap_filter, ' ');
            }
            g_string_append_printf(pcap_filter, "%s ", op_str);
            if (!pcap_visit_dfilter_node(left, op, pcap_filter)) {
                return false;
            }
        }
        else if (right) {
            ws_assert_not_reached();
        }
    }
    else if (stnode_type_id(node) == STTYPE_SET) {
        return false;
    }
    else if (stnode_type_id(node) == STTYPE_FUNCTION) {
        return false;
    }
    else if (stnode_type_id(node) == STTYPE_FIELD) {
        header_field_info *hfinfo = sttype_field_hfinfo(node);
        const char *pcap_fragment = try_str_to_str(hfinfo->abbrev, abbrev_to_pcap_filter);
        if (!pcap_fragment) {
            return false;
        }
        g_string_append_printf(pcap_filter, "%s", pcap_fragment);
    }
    else if (stnode_type_id(node) == STTYPE_FVALUE) {
        g_string_append_printf(pcap_filter, "%s", stnode_tostr(node, true));
    }
    else {
        g_string_append_printf(pcap_filter, "%s", stnode_type_name(node));
    }

    return true;
}

bool dfilter_to_pcap_filter(stnode_t *root_node, GString *pcap_filter) {
    return pcap_visit_dfilter_node(root_node, STNODE_OP_UNINITIALIZED, pcap_filter);
}

void dfilter_translator_init(void)
{
    register_dfilter_translator("pcap filter", dfilter_to_pcap_filter);
}

void dfilter_translator_cleanup(void)
{
    char **df_translators = get_dfilter_translator_list();

    if (df_translators == NULL) {
        return;
    }

    for (size_t idx = 0; df_translators[idx]; idx++) {
        deregister_dfilter_translator(df_translators[idx]);
    }

    g_free(df_translators);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
