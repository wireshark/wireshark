/* packet-grebonding.c
 * Routines for Huawei's GRE bonding control (RFC8157) dissection
 * Thomas Vogt
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation; either version 2 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/expert.h>
#include <epan/to_str.h>

void proto_reg_handoff_greb(void);
void proto_register_greb(void);

static int proto_greb = -1;

static int hf_greb_message_type = -1;
static int hf_greb_tunnel_type = -1;

static int hf_greb_attr = -1;
static int hf_greb_attr_type = -1;
static int hf_greb_attr_length = -1;
static int hf_greb_attr_val_uint64 = -1;
static int hf_greb_attr_val_none = -1;
static int hf_greb_attr_val_ipv6 = -1;
static int hf_greb_attr_val_ipv4 = -1;
static int hf_greb_attr_val_time = -1;
static int hf_greb_attr_val_string = -1;

static int hf_greb_attr_filter_commit = -1;
static int hf_greb_attr_filter_ack = -1;
static int hf_greb_attr_filter_packetsum = -1;
static int hf_greb_attr_filter_packetid = -1;
static int hf_greb_attr_filter_item_type = -1;
static int hf_greb_attr_filter_item_length = -1;
static int hf_greb_attr_filter_item_enabled = -1;
static int hf_greb_attr_filter_item_desc_length = -1;
static int hf_greb_attr_filter_item_desc_val = -1;
static int hf_greb_attr_filter_item_val = -1;

static int hf_greb_attr_error = -1;

/* Initialize the subtree pointers */
static gint ett_grebonding = -1;
static gint ett_grebonding_attrb = -1;
static gint ett_grebonding_filter_list = -1;
static gint ett_grebonding_filter_item = -1;
static gint ett_grebonding_ipv6_prefix = -1;

static gint *ett[] = {
    &ett_grebonding,
    &ett_grebonding_attrb,
    &ett_grebonding_filter_list,
    &ett_grebonding_filter_item,
    &ett_grebonding_ipv6_prefix
};


static const value_string greb_message_types[] = {
#define GREB_TUNNEL_SETUP_REQ 1
    {GREB_TUNNEL_SETUP_REQ, "Tunnel setup request"},
#define GREB_TUNNEL_SETUP_ACK 2
    {GREB_TUNNEL_SETUP_ACK, "Tunnel setup accept"},
#define GREB_TUNNEL_SETUP_DENY 3
    {GREB_TUNNEL_SETUP_DENY, "Tunnel setup deny"},
#define GREB_HELLO 4
    {GREB_HELLO, "Hello"},
#define GREB_TUNNEL_TEAR_DOWN 5
    {GREB_TUNNEL_TEAR_DOWN, "Tunnel tear down"},
#define GREB_NOTIFY 6
    {GREB_NOTIFY, "Notify"},
    {0, NULL}
};

static const value_string greb_tunnel_types[] = {
#define GREB_TUNNEL_FIRST 0x0001
    {GREB_TUNNEL_FIRST, "first tunnel (most likely the DSL GRE tunnel)"},
#define GREB_TUNNEL_SECOND 0x0010
    {GREB_TUNNEL_SECOND, "second tunnel (most likely the LTE GRE tunnel)" },
    {0, NULL}
};

static const value_string greb_error_codes[] = {
#define GREB_ERROR_HAAP_UNREACHABLE_LTE 1
    {GREB_ERROR_HAAP_UNREACHABLE_LTE, "HAAP not reachable over LTE"},
#define GREB_ERROR_HAAP_UNREACHABLE_DSL 2
    {GREB_ERROR_HAAP_UNREACHABLE_DSL, "HAAP not reachable via DSL"},
#define GREB_ERROR_LTE_TUNNEL_FAILED 3
    {GREB_ERROR_LTE_TUNNEL_FAILED, "LTE tunnel failed"},
#define GREB_ERROR_DSL_TUNNEL_FAILED 4
    {GREB_ERROR_DSL_TUNNEL_FAILED, "DSL tunnel failed"},
#define GREB_ERROR_DSL_UID_NOT_ALLOWED 5
    {GREB_ERROR_DSL_UID_NOT_ALLOWED, "DSL UID not allowed"},
#define GREB_ERROR_UID_NOT_ALLOWED 6
    {GREB_ERROR_UID_NOT_ALLOWED, "UID not allowed"},
#define GREB_ERROR_UID_NOT_MATCHING 7
    {GREB_ERROR_UID_NOT_MATCHING, "LTE and DSL User IDs do not match"},
#define GREB_ERROR_SECOND_SESSION_WITH_UID 8
    {GREB_ERROR_SECOND_SESSION_WITH_UID, "Session with the same User ID already exists"},
#define GREB_ERROR_CIN_NOT_PERMITTED 9
    {GREB_ERROR_CIN_NOT_PERMITTED, "Denied: CIN not permitted"},
#define GREB_ERROR_MAINTENANCE 10
    {GREB_ERROR_MAINTENANCE, "Terminated for maintenance"},
#define GREB_ERROR_BACKEND_COMMUNICATION_FAILURE_LTE 11
    {GREB_ERROR_BACKEND_COMMUNICATION_FAILURE_LTE, "HAAP Backend failure on LTE tunnel establishment"},
#define GREB_ERROR_BACKEND_COMMUNICATION_FAILURE_DSL 12
    {GREB_ERROR_BACKEND_COMMUNICATION_FAILURE_DSL, "HAAP Backend failure on DSL tunnel establishment"},
    {0,NULL}
};

static const value_string greb_attribute_types[] = {
#define GREB_ATTRB_H_IP4_ADDR 1
    {GREB_ATTRB_H_IP4_ADDR, "H IPv4 address"},
#define GREB_ATTRB_H_IP6_ADDR 2
    {GREB_ATTRB_H_IP6_ADDR, "H IPv6 address"},
#define GREB_ATTRB_CIN 3
    {GREB_ATTRB_CIN, "CIN (Client ID)"},
#define GREB_ATTRB_SESSIONID 4
    {GREB_ATTRB_SESSIONID, "Session ID"},
#define GREB_ATTRB_TIME 5
    {GREB_ATTRB_TIME, "Time"},
#define GREB_ATTRB_BYPASS_RATE 6
    {GREB_ATTRB_BYPASS_RATE, "Bypass rate"},
#define GREB_ATTRB_DOWNSTREAM_RATE 7
    {GREB_ATTRB_DOWNSTREAM_RATE, "Downstream rate"},
#define GREB_ATTRB_FILTER_LIST 8
    {GREB_ATTRB_FILTER_LIST, "Filter list"},
#define GREB_ATTRB_RTT_THRESHOLD 9
    {GREB_ATTRB_RTT_THRESHOLD, "RTT threshold"},
#define GREB_ATTRB_BYPASS_INTERVAL 10
    {GREB_ATTRB_BYPASS_INTERVAL, "Bypass interval"},
#define GREB_ATTRB_ONLY_FIRST_TUNNEL 11
    {GREB_ATTRB_ONLY_FIRST_TUNNEL, "only first tunnel (DSL)"},
#define GREB_ATTRB_OVERFLOW_TO_SECOND 12
    {GREB_ATTRB_OVERFLOW_TO_SECOND, "overflow to second tunnel (LTE)"},
#define GREB_ATTRB_IPV6_PREFIX 13
    {GREB_ATTRB_IPV6_PREFIX, "IPv6 prefix assigned by HAAP"},
#define GREB_ATTRB_ACTIVE_HELLO_INTERVAL 14
    {GREB_ATTRB_ACTIVE_HELLO_INTERVAL, "Active hello interval"},
#define GREB_ATTRB_HELLO_RETRYS 15
    {GREB_ATTRB_HELLO_RETRYS, "Hello retrys"},
#define GREB_ATTRB_IDLE_TIMEOUT 16
    {GREB_ATTRB_IDLE_TIMEOUT, "Idle timeout"},
#define GREB_ATTRB_ERROR 17
    {GREB_ATTRB_ERROR, "Error"},
#define GREB_ATTRB_DSL_FAIL 18
    {GREB_ATTRB_DSL_FAIL, "DSL fail"},
#define GREB_ATTRB_LTE_FAIL 19
    {GREB_ATTRB_LTE_FAIL, "LTE fail"},
#define GREB_ATTRB_BONDING_KEY 20
    {GREB_ATTRB_BONDING_KEY, "Bonding key"},
#define GREB_ATTRB_IPV6_PREFIX2 21
    {GREB_ATTRB_IPV6_PREFIX2, "IPv6 prefix assigned to host"},
#define GREB_ATTRB_CONFIGURED_UPSTREAM 22
    {GREB_ATTRB_CONFIGURED_UPSTREAM, "Configured upstream"},
#define GREB_ATTRB_CONFIGURED_DOWNSTREAM 23
    {GREB_ATTRB_CONFIGURED_DOWNSTREAM, "Configured downstream"},
#define GREB_ATTRB_RTT_VIOLATION 24
    {GREB_ATTRB_RTT_VIOLATION, "RTT violation"},
#define GREB_ATTRB_RTT_COMPLIANCE 25
    {GREB_ATTRB_RTT_COMPLIANCE, "RTT compliance"},
#define GREB_ATTRB_DIAG_START_BONDING 26
    {GREB_ATTRB_DIAG_START_BONDING, "Diagnostic start bonding"},
#define GREB_ATTRB_DIAG_START_DSL 27
    {GREB_ATTRB_DIAG_START_DSL, "Diagnostic start DSL"},
#define GREB_ATTRB_DIAG_END 29
    {GREB_ATTRB_DIAG_END, "Diagnostic End"},
#define GREB_ATTRB_FILTER_LIST_ACK 30
    {GREB_ATTRB_FILTER_LIST_ACK, "Filter list ACK"},
#define GREB_ATTRB_IDLE_HELLO_INTERVAL 31
    {GREB_ATTRB_IDLE_HELLO_INTERVAL, "Idle hello interval"},
#define GREB_ATTRB_NO_TRAFFIC_INTERVAL 32
    {GREB_ATTRB_NO_TRAFFIC_INTERVAL, "No traffic interval"},
#define GREB_ATTRB_ACTIVE_HELLO_STATE 33
    {GREB_ATTRB_ACTIVE_HELLO_STATE, "Active hello state"},
#define GREB_ATTRB_IDLE_HELLO_STATE 34
    {GREB_ATTRB_IDLE_HELLO_STATE, "Idle hello state"},
#define GREB_ATTRB_TUNNEL_VERIFICATION 35
    {GREB_ATTRB_TUNNEL_VERIFICATION, "Tunnel verification"},
    {255, "FIN"},
    {0, NULL}
};

static const value_string greb_filter_types[] = {
#define GREB_ATTRB_FILTER_FQDN 1
    {GREB_ATTRB_FILTER_FQDN, "FQDN"},
#define GREB_ATTRB_FILTER_DSCP 2
    {GREB_ATTRB_FILTER_DSCP, "DSCP"},
#define GREB_ATTRB_FILTER_DPORT 3
    {GREB_ATTRB_FILTER_DPORT, "Destination Port"},
#define GREB_ATTRB_FILTER_DIP 4
    {GREB_ATTRB_FILTER_DIP, "Destination IP"},
#define GREB_ATTRB_FILTER_DIPPORT 5
    {GREB_ATTRB_FILTER_DIPPORT, "Destination IP&Port"},
#define GREB_ATTRB_FILTER_SPORT 6
    {GREB_ATTRB_FILTER_SPORT, "Source Port"},
#define GREB_ATTRB_FILTER_SIP 7
    {GREB_ATTRB_FILTER_SIP, "Source IP"},
#define GREB_ATTRB_FILTER_SIPPORT 8
    {GREB_ATTRB_FILTER_SIPPORT, "Source IP&Port"},
#define GREB_ATTRB_FILTER_SMAC 9
    {GREB_ATTRB_FILTER_SMAC, "Source Mac"},
#define GREB_ATTRB_FILTER_PROTO 10
    {GREB_ATTRB_FILTER_PROTO, "Protocol"},
#define GREB_ATTRB_FILTER_SIPR 11
    {GREB_ATTRB_FILTER_SIPR, "Source IP Range"},
#define GREB_ATTRB_FILTER_DIPR 12
    {GREB_ATTRB_FILTER_DIPR, "Destination IP Range"},
#define GREB_ATTRB_FILTER_SIPRPORT 13
    {GREB_ATTRB_FILTER_SIPRPORT, "Source IP Range&Port"},
#define GREB_ATTRB_FILTER_DIPRPORT 14
    {GREB_ATTRB_FILTER_DIPRPORT, "Destination IP Range&Port"},
    {0, NULL}
};

static const value_string greb_filter_ack_codes[] = {
#define GREB_ATTRB_FILTER_ACK 0
    {GREB_ATTRB_FILTER_ACK, "Filter list acknowledged"},
#define GREB_ATTRB_FILTER_NACK_NO_OLD 1
    {GREB_ATTRB_FILTER_NACK_NO_OLD, "Filter list not acknowledged. No previous filter list to use."},
#define GREB_ATTRB_FILTER_NACK_OLD_USED 2
    {GREB_ATTRB_FILTER_NACK_OLD_USED, "Filter list not acknowledged. Previous filter list will be used."},
    {0, NULL}
};

static void
dissect_greb_h_gateway_ip_address(tvbuff_t *tvb, proto_tree *attrb_tree, guint offset, guint attrb_length)
{
    if (attrb_length == 16)
        proto_tree_add_item(attrb_tree, hf_greb_attr_val_ipv6, tvb, offset, attrb_length, ENC_NA);
    else if (attrb_length == 4)
        proto_tree_add_item(attrb_tree, hf_greb_attr_val_ipv4, tvb, offset, attrb_length, ENC_BIG_ENDIAN);
    else
        proto_tree_add_item(attrb_tree, hf_greb_attr_val_uint64, tvb, offset, attrb_length, ENC_BIG_ENDIAN);
}

static void
dissect_greb_filter_list_ack(tvbuff_t *tvb, proto_tree *attrb_tree, guint offset, guint attrb_length)
{
    proto_item *it_filter;
    proto_tree *filter_tree;
    guint filter_commit_count = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);

    it_filter = proto_tree_add_none_format(attrb_tree, hf_greb_attr_val_none, tvb, offset, attrb_length,
        "Filter list ACK - Commit %d", filter_commit_count);
    filter_tree = proto_item_add_subtree(it_filter, ett_grebonding_filter_list);
    proto_tree_add_item(filter_tree, hf_greb_attr_filter_commit, tvb, offset, attrb_length - 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(filter_tree, hf_greb_attr_filter_ack, tvb, offset + attrb_length, 1, ENC_BIG_ENDIAN);
}


static void
dissect_greb_filter_list(tvbuff_t *tvb, proto_tree *attrb_tree, guint offset, guint attrb_length)
{
    proto_item *it_filter;
    proto_tree *filter_tree;
    guint filter_commit_count = tvb_get_guint32(tvb, offset, ENC_BIG_ENDIAN);
    guint filter_packet_sum = tvb_get_guint16(tvb, offset + 4, ENC_BIG_ENDIAN);
    guint filter_packet_id = tvb_get_guint16(tvb, offset + 6, ENC_BIG_ENDIAN);
    it_filter = proto_tree_add_none_format(attrb_tree, hf_greb_attr_val_none, tvb, offset, attrb_length,
        "Filter list - Commit %d, Packet %d/%d", filter_commit_count, filter_packet_id, filter_packet_sum);
    filter_tree = proto_item_add_subtree(it_filter, ett_grebonding_filter_list);
    proto_tree_add_item(filter_tree, hf_greb_attr_filter_commit, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(filter_tree, hf_greb_attr_filter_packetid, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(filter_tree, hf_greb_attr_filter_packetsum, tvb, offset + 4, 2, ENC_BIG_ENDIAN);

    offset += 8;

    while (offset < attrb_length) {
        proto_item *it_filter_item;
        proto_tree *filter_item_tree;
        guint filter_item_length = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);
        guint filter_item_desc_length = tvb_get_guint16(tvb, offset + 6, ENC_BIG_ENDIAN);
        // bound lengths to not exceed packet
        if (filter_item_length > (guint) tvb_reported_length_remaining(tvb, offset + 2))
            filter_item_length = tvb_reported_length_remaining(tvb, offset + 2);
        if (filter_item_desc_length > filter_item_length)
            filter_item_length = filter_item_desc_length;

        it_filter_item = proto_tree_add_none_format(filter_tree, hf_greb_attr_val_none, tvb, offset,
            filter_item_length + 4, "Filter item - %s", tvb_get_string_enc(wmem_packet_scope(), tvb, offset + 8,
            filter_item_desc_length, ENC_UTF_8));
        filter_item_tree = proto_item_add_subtree(it_filter_item, ett_grebonding_filter_item);
        proto_tree_add_item(filter_item_tree, hf_greb_attr_filter_item_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(filter_item_tree, hf_greb_attr_filter_item_length, tvb, offset + 2, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(filter_item_tree, hf_greb_attr_filter_item_enabled, tvb, offset + 4, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(filter_item_tree, hf_greb_attr_filter_item_desc_length, tvb, offset + 6, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(filter_item_tree, hf_greb_attr_filter_item_desc_val, tvb, offset + 8,
            filter_item_desc_length, ENC_UTF_8 | ENC_NA);
        proto_tree_add_item(filter_item_tree, hf_greb_attr_filter_item_val, tvb, offset + 8 + filter_item_desc_length,
            filter_item_length - 4 - filter_item_desc_length, ENC_UTF_8 | ENC_NA);

        offset += filter_item_length + 4;
    }

}

static void
dissect_greb_ipv6_prefix(packet_info *pinfo, tvbuff_t *tvb, proto_tree *attrb_tree, guint offset, guint attrb_length)
{
    proto_item *item_ipv6_prefix;
    proto_tree *ipv6_prefix_tree;
    guint addr_length = attrb_length - 1;

    ipv6_prefix_tree = proto_tree_add_subtree_format(attrb_tree, tvb, offset, attrb_length,
        ett_grebonding_ipv6_prefix, &item_ipv6_prefix, "IPv6 prefix - %s/%d",
        tvb_ip6_to_str(pinfo->pool, tvb, offset), tvb_get_guint8(tvb, offset + addr_length));
    proto_tree_add_item(ipv6_prefix_tree, hf_greb_attr_val_ipv6, tvb, offset, addr_length, ENC_NA);
    proto_tree_add_item(ipv6_prefix_tree, hf_greb_attr_val_uint64, tvb, offset + addr_length, 1, ENC_BIG_ENDIAN);
}

static int
dissect_greb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti, *it_attrb;
    proto_tree *greb_tree, *attrb_tree = NULL;
    guint offset = 0;
    guint message_type = tvb_get_guint8(tvb, offset) >> 4;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "GREbond");
    ti = proto_tree_add_protocol_format(tree, proto_greb, tvb, offset, -1, "Huawei GRE bonding control message (%s)",
        val_to_str(message_type, greb_message_types, "0x%01X (unknown)"));
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, greb_message_types, "0x%02X (unknown)"));

    greb_tree = proto_item_add_subtree(ti, ett_grebonding);
    proto_tree_add_item(greb_tree, hf_greb_message_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(greb_tree, hf_greb_tunnel_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    // going through the attributes, off by one to assure length field exists
    while (offset + 1 < tvb_captured_length(tvb)) {
        guint attrb_type = tvb_get_guint8(tvb, offset);
        guint attrb_length = tvb_get_guint16(tvb, offset + 1, ENC_BIG_ENDIAN);

        it_attrb = proto_tree_add_none_format(greb_tree, hf_greb_attr, tvb, offset, attrb_length + 3, "Attribute - %s",
            val_to_str(attrb_type, greb_attribute_types, "unknown (%d)"));

        attrb_tree = proto_item_add_subtree(it_attrb, ett_grebonding_attrb);
        proto_tree_add_item(attrb_tree, hf_greb_attr_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(attrb_tree, hf_greb_attr_length, tvb, offset + 1, 2, ENC_BIG_ENDIAN);
        offset += 3;

        // bound attrb_length to not exced packet
        if (attrb_length > (guint) tvb_reported_length_remaining(tvb, offset))
            attrb_length = tvb_reported_length_remaining(tvb, offset);

        if (attrb_length > 0) {
            switch (attrb_type) {
                case GREB_ATTRB_H_IP4_ADDR:
                case GREB_ATTRB_H_IP6_ADDR:
                    dissect_greb_h_gateway_ip_address(tvb, attrb_tree, offset, attrb_length);
                    break;

                case GREB_ATTRB_IPV6_PREFIX2:
                case GREB_ATTRB_IPV6_PREFIX:
                    dissect_greb_ipv6_prefix(pinfo, tvb, attrb_tree, offset, attrb_length);
                    break;

                case GREB_ATTRB_TIME:
                    proto_tree_add_item(attrb_tree, hf_greb_attr_val_time, tvb, offset, attrb_length,
                        ENC_TIME_TIMEVAL);
                    break;

                case GREB_ATTRB_FILTER_LIST:
                    dissect_greb_filter_list(tvb, attrb_tree, offset, attrb_length);
                    break;

                case GREB_ATTRB_FILTER_LIST_ACK:
                    dissect_greb_filter_list_ack(tvb, attrb_tree, offset, attrb_length);
                    break;

                case GREB_ATTRB_CIN:
                    proto_tree_add_item(attrb_tree, hf_greb_attr_val_string, tvb, offset, attrb_length,
                        ENC_UTF_8 | ENC_NA);
                    break;

                case GREB_ATTRB_ERROR:
                    proto_tree_add_item(attrb_tree, hf_greb_attr_error, tvb, offset, attrb_length, ENC_BIG_ENDIAN);
                    break;

                default:
                    proto_tree_add_item(attrb_tree, hf_greb_attr_val_uint64, tvb, offset, attrb_length,
                        ENC_BIG_ENDIAN);
                    break;
            }

            offset += attrb_length;
        }
    }

    return tvb_captured_length(tvb);
}

void
proto_register_greb(void)
{
    static hf_register_info hf[] = {
        { &hf_greb_message_type,
            { "Message type", "grebonding.type", FT_UINT8, BASE_DEC, VALS(greb_message_types), 0xF0, "", HFILL }
        },
        { &hf_greb_tunnel_type,
            { "Tunnel type", "grebonding.tunneltype", FT_UINT8, BASE_DEC, VALS(greb_tunnel_types), 0x0F, "", HFILL }
        },
        { &hf_greb_attr,
            { "Attribute", "grebonding.attr", FT_NONE, BASE_NONE, NULL, 0, "", HFILL }
        },
        { &hf_greb_attr_length,
            { "Attribute length", "grebonding.attr.length", FT_UINT16, BASE_DEC, NULL, 0, "", HFILL }
        },
        { &hf_greb_attr_type,
            { "Attribute type", "grebonding.attr.type", FT_UINT8, BASE_DEC, VALS(greb_attribute_types), 0, "", HFILL }
        },
        { &hf_greb_attr_val_uint64,
            { "Attribute value", "grebonding.attr.val.uint64",
                FT_UINT64, BASE_DEC, NULL, 0, "", HFILL }
        },
        { &hf_greb_attr_val_time,
            { "Attribute value", "grebonding.attr.val.time",
                FT_RELATIVE_TIME, BASE_NONE, NULL, 0, "", HFILL }
        },
        { &hf_greb_attr_val_string,
            { "Attribute value", "grebonding.attr.val.string",
                FT_STRING, BASE_NONE, NULL, 0, "", HFILL }
        },
        { &hf_greb_attr_val_none,
            { "Attribute value", "grebonding.attr.val",
                FT_NONE, BASE_NONE, NULL, 0, "", HFILL }
        },
        { &hf_greb_attr_val_ipv6,
            { "Attribute value", "grebonding.attr.val.ipv6",
                FT_IPv6, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_val_ipv4,
            { "Attribute value", "grebonding.attr.val.ipv4",
                FT_IPv4, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_commit,
            { "Commit", "grebonding.attr.val.filter.commit", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_ack,
            { "Ack", "grebonding.attr.val.filter.ack",
                FT_UINT8, BASE_DEC, VALS(greb_filter_ack_codes), 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_packetsum,
            { "Packet sum", "grebonding.attr.val.filter.packetsum", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_packetid,
            { "Packet ID", "grebonding.attr.val.filter.packetid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_item_enabled,
            { "Enabled", "grebonding.attr.val.filter.item.enabled", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_item_length,
            { "Length (excl. type and length)", "grebonding.attr.val.filter.item.length",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_item_type,
            { "Type", "grebonding.attr.val.filter.item.type",
                FT_UINT16, BASE_DEC, VALS(greb_filter_types), 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_item_desc_val,
            { "Descripton", "grebonding.attr.val.filter.item.desc", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_item_desc_length,
            { "Descripton length", "grebonding.attr.val.filter.item.desc.length",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_filter_item_val,
            { "Value", "grebonding.attr.val.filter.item.val", FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_greb_attr_error,
            { "Error message", "grebonding.attr.val.error",
                FT_UINT32, BASE_DEC, VALS(greb_error_codes), 0, NULL, HFILL }
        }
    };

    proto_greb = proto_register_protocol("Huawei GRE bonding", "GREbond", "grebonding");
    proto_register_field_array(proto_greb, hf, array_length(hf));

    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_greb(void)
{
    dissector_handle_t greb_handle;

    greb_handle = create_dissector_handle(dissect_greb, proto_greb);
    dissector_add_uint("gre.proto", 0x0101, greb_handle); // used in production at Deutsche Telekom
    dissector_add_uint("gre.proto", 0xB7EA, greb_handle); // according to RFC

    // TODO
    // when capturing on the gre-interfaces itself, "Linux cooked" interfaces
    //dissector_add_uint("sll.ltype", 0x0101, greb_handle);
    //dissector_add_uint("sll.ltype", 0xB7EA, greb_handle);
    //dissector_add_uint("sll.gretype", 0x0101, greb_handle);
    //dissector_add_uint("sll.gretype", 0xB7EA, greb_handle);
}
