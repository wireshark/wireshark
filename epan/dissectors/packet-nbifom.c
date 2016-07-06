/* packet-nbifom.c
 * Routines for Network-Based IP Flow Mobility (NBIFOM) dissection
 * 3GPP TS 24.161 V13.1.0 (2016-06) Release 13
 * Copyright 2016, Pascal Quantin <pascal.quantin@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>

void proto_register_nbifom(void);

static int proto_nbifom = -1;
static int hf_nbifom_param_id_ul = -1;
static int hf_nbifom_param_id_dl = -1;
static int hf_nbifom_param_contents_len = -1;
static int hf_nbifom_param_contents_dflt_access = -1;
static int hf_nbifom_param_contents_status = -1;
static int hf_nbifom_param_contents_ran_rules_handling = -1;
static int hf_nbifom_param_contents_ran_rules_status = -1;
static int hf_nbifom_param_contents_access_use_ind_spare = -1;
static int hf_nbifom_param_contents_access_use_ind_wlan_access_usable_val = -1;
static int hf_nbifom_param_contents_access_use_ind_3gpp_access_usable_val = -1;
static int hf_nbifom_param_contents_mode = -1;
static int hf_nbifom_param_contents_rem_bytes = -1;
static int hf_nbifom_routing_rule_len = -1;
static int hf_nbifom_routing_rule_id = -1;
static int hf_nbifom_routing_rule_routing_access = -1;
static int hf_nbifom_routing_rule_spare = -1;
static int hf_nbifom_routing_rule_op_code = -1;
static int hf_nbifom_routing_rule_prio = -1;
static int hf_nbifom_routing_rule_flags = -1;
static int hf_nbifom_routing_rule_flags_prot_type_nxt_hdr = -1;
static int hf_nbifom_routing_rule_flags_ipsec_spi = -1;
static int hf_nbifom_routing_rule_flags_dst_addr_prefix_len = -1;
static int hf_nbifom_routing_rule_flags_src_addr_prefix_len = -1;
static int hf_nbifom_routing_rule_flags_dst_ipv6_addr = -1;
static int hf_nbifom_routing_rule_flags_src_ipv6_addr = -1;
static int hf_nbifom_routing_rule_flags_dst_ipv4_addr = -1;
static int hf_nbifom_routing_rule_flags_src_ipv4_addr = -1;
static int hf_nbifom_routing_rule_flags_spare_bits0xc0 = -1;
static int hf_nbifom_routing_rule_flags_flow_label = -1;
static int hf_nbifom_routing_rule_flags_tos = -1;
static int hf_nbifom_routing_rule_flags_end_dst_port_range = -1;
static int hf_nbifom_routing_rule_flags_start_dst_port_range = -1;
static int hf_nbifom_routing_rule_flags_end_src_port_range = -1;
static int hf_nbifom_routing_rule_flags_start_src_port_range = -1;
static int hf_nbifom_routing_rule_flags_spare_bits0xffff = -1;
static int hf_nbifom_routing_rule_src_ipv4_addr = -1;
static int hf_nbifom_routing_rule_dst_ipv4_addr = -1;
static int hf_nbifom_routing_rule_src_ipv6_addr = -1;
static int hf_nbifom_routing_rule_dst_ipv6_addr = -1;
static int hf_nbifom_routing_rule_src_addr_prefix_len = -1;
static int hf_nbifom_routing_rule_dst_addr_prefix_len = -1;
static int hf_nbifom_routing_rule_ipsec_spi = -1;
static int hf_nbifom_routing_rule_prot_type_nxt_hdr = -1;
static int hf_nbifom_routing_rule_start_src_port_range = -1;
static int hf_nbifom_routing_rule_end_src_port_range = -1;
static int hf_nbifom_routing_rule_start_dst_port_range = -1;
static int hf_nbifom_routing_rule_end_dst_port_range = -1;
static int hf_nbifom_routing_rule_tos = -1;
static int hf_nbifom_routing_rule_flow_label = -1;

static gint ett_nbifom = -1;
static gint ett_nbifom_param_contents = -1;
static gint ett_nbifom_routing_rule = -1;
static gint ett_nbifom_routing_rule_flags = -1;

static const value_string nbifom_param_id_ue_to_nw_vals[] = {
    { 0x00, "Not assigned" },
    { 0x01, "NBIFOM mode" },
    { 0x02, "NBIFOM default access" },
    { 0x03, "NBIFOM status" },
    { 0x04, "NBIFOM routing rules" },
    { 0x05, "NBIFOM IP flow mapping" },
    { 0x06, "Not assigned" },
    { 0x07, "NBIFOM RAN rules status" },
    { 0x08, "NBIFOM access usability indication" },
    { 0, NULL }
};

static const value_string nbifom_param_id_nw_to_ue_vals[] = {
    { 0x00, "Not assigned" },
    { 0x01, "NBIFOM mode" },
    { 0x02, "NBIFOM default access" },
    { 0x03, "NBIFOM status" },
    { 0x04, "NBIFOM routing rules" },
    { 0x05, "Not assigned" },
    { 0x06, "NBIFOM RAN rules handling" },
    { 0x07, "Not assigned" },
    { 0x08, "Not assigned" },
    { 0, NULL }
};

static const value_string nbifom_dflt_access_vals[] = {
    { 0x01, "3GPP access" },
    { 0x02, "Non-3GPP access" },
    { 0, NULL },
};

static const value_string nbifom_status_vals[] = {
    { 0x00, "Accepted" },
    { 0x1a, "Insufficient resources" },
    { 0x22, "Service option temporarily out of order" },
    { 0x25, "Requested service option not subscribed" },
    { 0x39, "Incorrect indication in the routing rule operation" },
    { 0x3a, "Unknown information in IP flow filter(s)" },
    { 0x3f, "Request rejected, unspecified" },
    { 0x6f, "Protocol error, unspecified" },
    { 0x82, "Unknown routing access information" },
    { 0, NULL },
};

static const value_string nbifom_ran_rules_handling_vals[] = {
    { 0x01, "RAN rules handling parameter is not set" },
    { 0x02, "RAN rules handling parameter is set" },
    { 0, NULL }
};

static const value_string nbifom_ran_rules_status_vals[] = {
    { 0x01, "No indication" },
    { 0x02, "Move-traffic-from-WLAN indication" },
    { 0x03, "Move-traffic-to-WLAN indication" },
    { 0, NULL }
};

static const value_string nbifom_wlan_access_usable_vals[] = {
    { 0x00, "No change in usability of WLAN access" },
    { 0x01, "WLAN access becomes usable" },
    { 0x02, "WLAN access becomes unusable" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

static const value_string nbifom_3gpp_access_usable_vals[] = {
    { 0x00, "No change in usability of 3GPP access" },
    { 0x01, "3GPP access becomes usable" },
    { 0x02, "3GPP access becomes unusable" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

static const value_string nbifom_mode_vals[] = {
    { 0x01, "UE-initiated NBIFOM mode" },
    { 0x02, "Network-initiated NBIFOM mode" },
    { 0, NULL }
};

static const value_string nbifom_routing_access_vals[] = {
    { 0x01, "3GPP access" },
    { 0x02, "Non-3GPP access" },
    { 0, NULL }
};

static const value_string nbifom_op_code_vals[] = {
    { 0x00, "Spare" },
    { 0x01, "Create routing rule" },
    { 0x02, "Delete routing rule" },
    { 0x03, "Replace existing routing rule" },
    { 0x04, "Reserved" },
    { 0, NULL }
};

static void
dissect_nbifom_routing_rules(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, gint offset, guint32 params_content_len)
{
    gint curr_offset = offset;
    guint32 i = 0, routing_rule_len;
    proto_item *item;
    proto_tree *subtree;
    guint64 flags;

    while ((curr_offset - offset) < (gint)params_content_len) {
        static const int *flags1[] = {
            &hf_nbifom_routing_rule_routing_access,
            &hf_nbifom_routing_rule_spare,
            &hf_nbifom_routing_rule_op_code,
            NULL
        };
        static const int *flags2[] = {
            &hf_nbifom_routing_rule_flags_prot_type_nxt_hdr,
            &hf_nbifom_routing_rule_flags_ipsec_spi,
            &hf_nbifom_routing_rule_flags_dst_addr_prefix_len,
            &hf_nbifom_routing_rule_flags_src_addr_prefix_len,
            &hf_nbifom_routing_rule_flags_dst_ipv6_addr,
            &hf_nbifom_routing_rule_flags_src_ipv6_addr,
            &hf_nbifom_routing_rule_flags_dst_ipv4_addr,
            &hf_nbifom_routing_rule_flags_src_ipv4_addr,
            &hf_nbifom_routing_rule_flags_spare_bits0xc0,
            &hf_nbifom_routing_rule_flags_flow_label,
            &hf_nbifom_routing_rule_flags_tos,
            &hf_nbifom_routing_rule_flags_end_dst_port_range,
            &hf_nbifom_routing_rule_flags_start_dst_port_range,
            &hf_nbifom_routing_rule_flags_end_src_port_range,
            &hf_nbifom_routing_rule_flags_start_src_port_range,
            &hf_nbifom_routing_rule_flags_spare_bits0xffff,
            NULL
        };

        subtree = proto_tree_add_subtree_format(tree, tvb, curr_offset, -1, ett_nbifom_routing_rule, &item, "Routing Rule %u", ++i);
        proto_tree_add_item_ret_uint(subtree, hf_nbifom_routing_rule_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN, &routing_rule_len);
        proto_item_set_len(item, routing_rule_len+1);
        curr_offset++;
        proto_tree_add_item(subtree, hf_nbifom_routing_rule_id, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        proto_tree_add_bitmask_list(subtree, tvb, curr_offset, 1, flags1, ENC_BIG_ENDIAN);
        curr_offset++;
        proto_tree_add_item(subtree, hf_nbifom_routing_rule_prio, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
        curr_offset++;
        proto_tree_add_bitmask_ret_uint64(subtree, tvb, curr_offset, hf_nbifom_routing_rule_flags,
                                          ett_nbifom_routing_rule_flags, flags2, ENC_BIG_ENDIAN, &flags);
        curr_offset += 4;
        if (flags & 0x01000000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_src_ipv4_addr, tvb, curr_offset, 4, ENC_NA);
            curr_offset += 4;
        }
        if (flags & 0x02000000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_dst_ipv4_addr, tvb, curr_offset, 4, ENC_NA);
            curr_offset += 4;
        }
        if (flags & 0x04000000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_src_ipv6_addr, tvb, curr_offset, 16, ENC_NA);
            curr_offset += 16;
        }
        if (flags & 0x08000000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_dst_ipv6_addr, tvb, curr_offset, 16, ENC_NA);
            curr_offset += 16;
        }
        if (flags & 0x10000000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_src_addr_prefix_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
        }
        if (flags & 0x20000000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_dst_addr_prefix_len, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
        }
        if (flags & 0x40000000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_ipsec_spi, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset += 4;
        }
        if (flags & 0x80000000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_prot_type_nxt_hdr, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
        }
        if (flags & 0x00010000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_start_src_port_range, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset += 4;
        }
        if (flags & 0x00020000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_end_src_port_range, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset += 4;
        }
        if (flags & 0x00040000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_start_dst_port_range, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset += 4;
        }
        if (flags & 0x00080000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_end_dst_port_range, tvb, curr_offset, 4, ENC_BIG_ENDIAN);
            curr_offset += 4;
        }
        if (flags & 0x00100000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_tos, tvb, curr_offset, 1, ENC_BIG_ENDIAN);
            curr_offset++;
        }
        if (flags & 0x00200000) {
            proto_tree_add_item(subtree, hf_nbifom_routing_rule_flow_label, tvb, curr_offset, 3, ENC_BIG_ENDIAN);
            curr_offset += 3;
        }
    }
}

static int
dissect_nbifom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *nbifom_tree, *subtree;
    gint reported_len = tvb_reported_length(tvb);
    gint offset = 0, saved_offset;
    guint32 param_id, param_contents_len;
    int hf_nbifom_param_id = pinfo->link_dir == P2P_DIR_UL ? hf_nbifom_param_id_ul : hf_nbifom_param_id_dl;

    col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", "NBIFOM");

    item = proto_tree_add_item(tree, proto_nbifom, tvb, 0, -1, ENC_NA);
    nbifom_tree = proto_item_add_subtree(item, ett_nbifom);

    while (offset < reported_len) {
        item = proto_tree_add_item_ret_uint(nbifom_tree, hf_nbifom_param_id, tvb, offset, 1, ENC_BIG_ENDIAN, &param_id);
        offset++;
        subtree = proto_item_add_subtree(item, ett_nbifom_param_contents);
        proto_tree_add_item_ret_uint(subtree, hf_nbifom_param_contents_len, tvb, offset, 1, ENC_BIG_ENDIAN, &param_contents_len);
        offset++;
        saved_offset = offset;
        switch (param_id) {
        case 1:
            proto_tree_add_item(subtree, hf_nbifom_param_contents_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case 2:
            proto_tree_add_item(subtree, hf_nbifom_param_contents_dflt_access, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case 3:
            proto_tree_add_item(subtree, hf_nbifom_param_contents_status, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            break;
        case 5:
            if (pinfo->link_dir == P2P_DIR_DL) {
                break;
            } /* else fall through case 4 */
        case 4:
            dissect_nbifom_routing_rules(tvb, pinfo, subtree, offset, param_contents_len);
            offset += param_contents_len;
            break;
        case 6:
            if (pinfo->link_dir == P2P_DIR_DL) {
                proto_tree_add_item(subtree, hf_nbifom_param_contents_ran_rules_handling, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
            break;
        case 7:
            if (pinfo->link_dir == P2P_DIR_UL) {
                proto_tree_add_item(subtree, hf_nbifom_param_contents_ran_rules_status, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset++;
            }
            break;
        case 8:
            if (pinfo->link_dir == P2P_DIR_UL) {
                static const int * flags[] = {
                    &hf_nbifom_param_contents_access_use_ind_spare,
                    &hf_nbifom_param_contents_access_use_ind_wlan_access_usable_val,
                    &hf_nbifom_param_contents_access_use_ind_3gpp_access_usable_val,
                    NULL
                };

                proto_tree_add_bitmask_list(subtree, tvb, offset, 1, flags, ENC_BIG_ENDIAN);
                offset++;
            }
            break;
        default:
            break;
        }
        if ((offset - saved_offset) < (gint)param_contents_len) {
            proto_tree_add_item(subtree, hf_nbifom_param_contents_rem_bytes, tvb, offset, param_contents_len - (offset - saved_offset), ENC_NA);
        }
        offset = saved_offset + param_contents_len;
    }

    return tvb_captured_length(tvb);
}

void
proto_register_nbifom(void)
{
    static hf_register_info hf[] = {
        { &hf_nbifom_param_id_ul,
            { "Parameter identifier", "nbifom.param_id", FT_UINT8, BASE_HEX,
              VALS(nbifom_param_id_ue_to_nw_vals), 0, NULL, HFILL }},
        { &hf_nbifom_param_id_dl,
            { "Parameter identifier", "nbifom.param_id", FT_UINT8, BASE_HEX,
              VALS(nbifom_param_id_nw_to_ue_vals), 0, NULL, HFILL }},
        { &hf_nbifom_param_contents_len,
            { "Length of parameter contents", "nbifom.param_contents.len", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_param_contents_dflt_access,
            { "NBIFOM default access", "nbifom.param_contents.dflt_access", FT_UINT8, BASE_HEX,
              VALS(nbifom_dflt_access_vals), 0, NULL, HFILL }},
        { &hf_nbifom_param_contents_status,
            { "NBIFOM status", "nbifom.param_contents.status", FT_UINT8, BASE_HEX,
              VALS(nbifom_status_vals), 0, NULL, HFILL }},
        { &hf_nbifom_param_contents_ran_rules_handling,
            { "NBIFOM RAN rules handling", "nbifom.param_contents.ran_rules_handling", FT_UINT8, BASE_HEX,
              VALS(nbifom_ran_rules_handling_vals), 0, NULL, HFILL }},
        { &hf_nbifom_param_contents_ran_rules_status,
            { "NBIFOM RAN rules status", "nbifom.param_contents.ran_rules_status", FT_UINT8, BASE_HEX,
              VALS(nbifom_ran_rules_status_vals), 0, NULL, HFILL }},
        { &hf_nbifom_param_contents_access_use_ind_spare,
            { "Spare", "nbifom.param_contents.access_use_ind.spare", FT_UINT8, BASE_HEX,
              NULL, 0xf0, NULL, HFILL }},
        { &hf_nbifom_param_contents_access_use_ind_wlan_access_usable_val,
            { "WLAN access usable value", "nbifom.param_contents.access_use_ind.wlan_access_usable_val", FT_UINT8, BASE_HEX,
              VALS(nbifom_wlan_access_usable_vals), 0x0c, NULL, HFILL }},
        { &hf_nbifom_param_contents_access_use_ind_3gpp_access_usable_val,
            { "3GPP access usable value", "nbifom.param_contents.access_use_ind.3gpp_access_usable_val", FT_UINT8, BASE_HEX,
              VALS(nbifom_3gpp_access_usable_vals), 0x03, NULL, HFILL }},
        { &hf_nbifom_param_contents_mode,
            { "NBIFOM mode", "nbifom.param_contents.mode", FT_UINT8, BASE_HEX,
              VALS(nbifom_mode_vals), 0, NULL, HFILL }},
        { &hf_nbifom_param_contents_rem_bytes,
            { "Remaining parameter contents", "nbifom.param_contents.rem_bytes", FT_BYTES, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_len,
            { "Length of routing rule", "nbifom.routing_rule.len", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_id,
            { "Routing rule identifier", "nbifom.routing_rule.id", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_routing_access,
            { "Routing access", "nbifom.routing_rule.routing_access", FT_UINT8, BASE_DEC,
              VALS(nbifom_routing_access_vals), 0xc0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_spare,
            { "Spare", "nbifom.routing_rule.spare", FT_UINT8, BASE_HEX,
              NULL, 0x38, NULL, HFILL }},
        { &hf_nbifom_routing_rule_op_code,
            { "Operation code", "nbifom.routing_rule.op_code", FT_UINT8, BASE_HEX,
              VALS(nbifom_op_code_vals), 0x07, NULL, HFILL }},
        { &hf_nbifom_routing_rule_prio,
            { "Routing rule priority", "nbifom.routing_rule.prio", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags,
            { "Flags", "nbifom.routing_rule.flags", FT_UINT32, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_prot_type_nxt_hdr,
            { "Protocol type / next header", "nbifom.routing_rule.flags.prot_type_nxt_hdr", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x80000000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_ipsec_spi,
            { "IPSec SPI", "nbifom.routing_rule.flags.ipsec_spi", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x40000000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_dst_addr_prefix_len,
            { "Destination address prefix length", "nbifom.routing_rule.flags.dst_addr_prefix_len", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x20000000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_src_addr_prefix_len,
            { "Source address prefix length", "nbifom.routing_rule.flags.src_addr_prefix_len", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x10000000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_dst_ipv6_addr,
            { "Destination IPv6 address", "nbifom.routing_rule.flags.dst_ipv6_addr", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x08000000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_src_ipv6_addr,
            { "Source IPv6 address", "nbifom.routing_rule.flags.src_ipv6_addr", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x04000000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_dst_ipv4_addr,
            { "Destination IPv4 address", "nbifom.routing_rule.flags.dst_ipv4_addr", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x02000000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_src_ipv4_addr,
            { "Source IPv4 address", "nbifom.routing_rule.flags.src_ipv4_addr", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x01000000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_spare_bits0xc0,
            { "Spare", "nbifom.routing_rule.flags.spare", FT_UINT32, BASE_HEX,
              NULL, 0x00c00000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_flow_label,
            { "Flow label", "nbifom.routing_rule.flags.flow_label", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x00200000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_tos,
            { "Type of service", "nbifom.routing_rule.flags.tos", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x00100000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_end_dst_port_range,
            { "End destination port range", "nbifom.routing_rule.flags.end_dst_port_range", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x00080000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_start_dst_port_range,
            { "Start destination port range", "nbifom.routing_rule.flags.start_dst_port_range", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x00040000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_end_src_port_range,
            { "End source port range", "nbifom.routing_rule.flags.end_src_port_range", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x00020000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_start_src_port_range,
            { "Start source port range", "nbifom.routing_rule.flags.start_src_port_rang", FT_BOOLEAN, 32,
              TFS(&tfs_present_not_present), 0x00010000, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flags_spare_bits0xffff,
            { "Spare", "nbifom.routing_rule.flags.spare", FT_UINT32, BASE_HEX,
              NULL, 0x0000ffff, NULL, HFILL }},
        { &hf_nbifom_routing_rule_src_ipv4_addr,
            { "Source IPv4 address", "nbifom.routing_rule.src_ipv4_addr", FT_IPv4, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_dst_ipv4_addr,
            { "Destination IPv4 address", "nbifom.routing_rule.dst_ipv4_addr", FT_IPv4, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_src_ipv6_addr,
            { "Source IPv6 address", "nbifom.routing_rule.src_ipv6_addr", FT_IPv6, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_dst_ipv6_addr,
            { "Destination IPv6 address", "nbifom.routing_rule.dst_ipv6_addr", FT_IPv6, BASE_NONE,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_src_addr_prefix_len,
            { "Source address prefix length", "nbifom.routing_rule.src_addr_prefix_len", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_dst_addr_prefix_len,
            { "Destination address prefix length", "nbifom.routing_rule.dst_addr_prefix_len", FT_UINT8, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_ipsec_spi,
            { "IPSec SPI", "nbifom.routing_rule.ipsec_spi", FT_UINT32, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_prot_type_nxt_hdr,
            { "Protocol type / next header", "nbifom.routing_rule.prot_type_nxt_hdr", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_start_src_port_range,
            { "Start source port range", "nbifom.routing_rule.start_src_port_range", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_end_src_port_range,
            { "End source port range", "nbifom.routing_rule.end_src_port_range", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_start_dst_port_range,
            { "Start destination port range", "nbifom.routing_rule.start_dst_port_range", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_end_dst_port_range,
            { "End destination port range", "nbifom.routing_rule.end_dst_port_range", FT_UINT32, BASE_DEC,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_tos,
            { "Type of service", "nbifom.routing_rule.tos", FT_UINT8, BASE_HEX,
              NULL, 0, NULL, HFILL }},
        { &hf_nbifom_routing_rule_flow_label,
            { "Flow label", "nbifom.routing_rule.flow_label", FT_UINT24, BASE_HEX,
              NULL, 0x0fffff, NULL, HFILL }}
    };

    static gint *nbifom_subtrees[] = {
        &ett_nbifom,
        &ett_nbifom_param_contents,
        &ett_nbifom_routing_rule,
        &ett_nbifom_routing_rule_flags
    };

    proto_nbifom = proto_register_protocol("Network-Based IP Flow Mobility", "NBIFOM", "nbifom");
    proto_register_field_array(proto_nbifom, hf, array_length(hf));
    proto_register_subtree_array(nbifom_subtrees, array_length(nbifom_subtrees));

    register_dissector("nbifom", dissect_nbifom, proto_nbifom);
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
