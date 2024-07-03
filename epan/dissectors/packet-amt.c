/* packet-amt.c
 * Routines for Automatic Multicast Tunneling (AMT) dissection
 * Copyright 2017, Alexis La Goutte (See AUTHORS)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * RFC 7450 : Automatic Multicast Tunneling
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/expert.h>

#define AMT_UDP_PORT 2268

void proto_reg_handoff_amt(void);
void proto_register_amt(void);

static dissector_handle_t amt_handle;

static int proto_amt;
static int hf_amt_version;
static int hf_amt_type;
static int hf_amt_reserved;
static int hf_amt_discovery_nonce;
static int hf_amt_relay_address_ipv4;
static int hf_amt_relay_address_ipv6;
static int hf_amt_request_nonce;
static int hf_amt_request_reserved;
static int hf_amt_request_p;
static int hf_amt_membership_query_reserved;
static int hf_amt_membership_query_l;
static int hf_amt_membership_query_g;
static int hf_amt_response_mac;
static int hf_amt_gateway_port_number;
static int hf_amt_gateway_ip_address;
static int hf_amt_multicast_data;

static expert_field ei_amt_relay_address_unknown;
static expert_field ei_amt_unknown;

static int ett_amt;

#define RELAY_DISCOVERY         1
#define RELAY_ADVERTISEMENT     2
#define REQUEST                 3
#define MEMBERSHIP_QUERY        4
#define MEMBERSHIP_UPDATE       5
#define MULTICAST_DATA          6
#define TEARDOWN                7

static const value_string amt_type_vals[] = {
    { RELAY_DISCOVERY, "Relay Discovery" },
    { RELAY_ADVERTISEMENT, "Relay Advertisement" },
    { REQUEST, "Request" },
    { MEMBERSHIP_QUERY, "Membership Query" },
    { MEMBERSHIP_UPDATE, "Membership Update" },
    { MULTICAST_DATA, "Multicast Data" },
    { TEARDOWN, "Teardown" },
    {0, NULL }
};

static const true_false_string tfs_request_p = {
    "IPv4 packet carrying an IGMPv3 General Query",
    "IPv6 packet carrying an MLDv2 General Query"
};

static dissector_handle_t ip_handle;

/* Code to actually dissect the packets */
static int
dissect_amt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti;
    proto_tree *amt_tree;
    unsigned    offset = 0;
    uint32_t    type;
    tvbuff_t   *next_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "AMT");

    ti = proto_tree_add_item(tree, proto_amt, tvb, 0, -1, ENC_NA);

    amt_tree = proto_item_add_subtree(ti, ett_amt);

    proto_tree_add_item(amt_tree, hf_amt_version, tvb, offset, 1, ENC_NA);
    proto_tree_add_item_ret_uint(amt_tree, hf_amt_type, tvb, offset, 1, ENC_NA, &type);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str_const(type, amt_type_vals, "Unknown AMT TYPE"));
    offset += 1;

    switch(type){
        case RELAY_DISCOVERY: /* 1 */
            proto_tree_add_item(amt_tree, hf_amt_reserved, tvb, offset, 3, ENC_NA);
            offset += 3;
            proto_tree_add_item(amt_tree, hf_amt_discovery_nonce, tvb, offset, 4, ENC_NA);
            offset += 4;
        break;
        case RELAY_ADVERTISEMENT:{ /* 2 */
            uint32_t relay_length;
            proto_tree_add_item(amt_tree, hf_amt_reserved, tvb, offset, 3, ENC_NA);
            offset += 3;
            proto_tree_add_item(amt_tree, hf_amt_discovery_nonce, tvb, offset, 4, ENC_NA);
            offset += 4;
            relay_length = tvb_reported_length_remaining(tvb, offset);
            switch(relay_length){
                case 4: /* IPv4 Address */
                    proto_tree_add_item(amt_tree, hf_amt_relay_address_ipv4, tvb, offset, 4, ENC_NA);
                    offset += 4;
                break;
                case 16: /* IPv6 Address */
                    proto_tree_add_item(amt_tree, hf_amt_relay_address_ipv6, tvb, offset, 16, ENC_NA);
                    offset += 16;
                break;
                default: /* Unknown type.. */
                    proto_tree_add_expert(amt_tree, pinfo, &ei_amt_relay_address_unknown, tvb, offset, relay_length);
                    offset += relay_length;
                break;
            }
        }
        break;
        case REQUEST: /* 3 */
            proto_tree_add_item(amt_tree, hf_amt_request_reserved, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(amt_tree, hf_amt_request_p, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(amt_tree, hf_amt_reserved, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(amt_tree, hf_amt_request_nonce, tvb, offset, 4, ENC_NA);
            offset += 4;
        break;
        case MEMBERSHIP_QUERY:{ /* 4 */
            uint32_t flags_g;
            proto_tree_add_item(amt_tree, hf_amt_membership_query_reserved, tvb, offset, 1, ENC_NA);
            proto_tree_add_item(amt_tree, hf_amt_membership_query_l, tvb, offset, 1, ENC_NA);
            proto_tree_add_item_ret_uint(amt_tree, hf_amt_membership_query_g, tvb, offset, 1, ENC_NA, &flags_g);
            offset += 1;
            proto_tree_add_item(amt_tree, hf_amt_response_mac, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(amt_tree, hf_amt_request_nonce, tvb, offset, 4, ENC_NA);
            offset += 4;
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(ip_handle, next_tvb, pinfo, amt_tree);
            offset += tvb_reported_length_remaining(tvb, offset);
            if(flags_g){
                offset -= 2;
                offset -= 16;
                proto_tree_add_item(amt_tree, hf_amt_gateway_port_number, tvb, offset, 2, ENC_NA);
                offset += 2;
                proto_tree_add_item(amt_tree, hf_amt_gateway_ip_address, tvb, offset, 16, ENC_NA);
                offset += 16;
            }
        }
        break;
        case MEMBERSHIP_UPDATE: /* 5 */
            proto_tree_add_item(amt_tree, hf_amt_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(amt_tree, hf_amt_response_mac, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(amt_tree, hf_amt_request_nonce, tvb, offset, 4, ENC_NA);
            offset += 4;
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(ip_handle, next_tvb, pinfo, amt_tree);
            offset += tvb_reported_length_remaining(tvb, offset);
        break;
        case MULTICAST_DATA: /* 6 */
            proto_tree_add_item(amt_tree, hf_amt_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(amt_tree, hf_amt_multicast_data, tvb, offset, -1, ENC_NA);
            next_tvb = tvb_new_subset_remaining(tvb, offset);
            call_dissector(ip_handle, next_tvb, pinfo, amt_tree);
            offset += tvb_reported_length_remaining(tvb, offset);
        break;
        case TEARDOWN:{ /* 7 */
            proto_tree_add_item(amt_tree, hf_amt_reserved, tvb, offset, 1, ENC_NA);
            offset += 1;
            proto_tree_add_item(amt_tree, hf_amt_response_mac, tvb, offset, 6, ENC_NA);
            offset += 6;
            proto_tree_add_item(amt_tree, hf_amt_request_nonce, tvb, offset, 4, ENC_NA);
            offset += 4;
            proto_tree_add_item(amt_tree, hf_amt_gateway_port_number, tvb, offset, 2, ENC_NA);
            offset += 2;
            proto_tree_add_item(amt_tree, hf_amt_gateway_ip_address, tvb, offset, 16, ENC_NA);
            offset += 16;
        }
        break;
        default:{
            uint32_t len_unknown;
            len_unknown = tvb_reported_length_remaining(tvb, offset);
            proto_tree_add_expert(amt_tree, pinfo, &ei_amt_unknown, tvb, offset, len_unknown);
            offset += len_unknown;
        }
        break;
    }
    return offset;
}

void
proto_register_amt(void)
{
    expert_module_t *expert_amt;

    static hf_register_info hf[] = {
        { &hf_amt_version,
          { "Version", "amt.version",
            FT_UINT8, BASE_DEC, NULL, 0xF0,
            "Must be always 0", HFILL }
        },
        { &hf_amt_type,
          { "Type", "amt.type",
            FT_UINT8, BASE_DEC, VALS(amt_type_vals), 0x0F,
            NULL, HFILL }
        },
        { &hf_amt_reserved,
          { "Reserved", "amt.reserved",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amt_discovery_nonce,
          { "Discovery Nonce", "amt.discovery_nonce",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amt_relay_address_ipv4,
          { "Relay Address (IPv4)", "amt.relay_address.ipv4",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amt_relay_address_ipv6,
          { "Relay Address (IPv6)", "amt.relay_address.ipv6",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amt_request_nonce,
          { "Request Nonce", "amt.request_nonce",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amt_request_reserved,
          { "Reserved", "amt.request.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFE,
            NULL, HFILL }
        },
        { &hf_amt_request_p,
          { "P Flags", "amt.request.p",
            FT_BOOLEAN, 8, TFS(&tfs_request_p), 0x01,
            NULL, HFILL }
        },
        { &hf_amt_membership_query_reserved,
          { "Reserved", "amt.membership_query.reserved",
            FT_UINT8, BASE_HEX, NULL, 0xFC,
            NULL, HFILL }
        },
        { &hf_amt_membership_query_l,
          { "L Flags", "amt.membership_query.l",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_amt_membership_query_g,
          { "G Flags", "amt.membership_query.g",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_amt_response_mac,
          { "Response MAC", "amt.response_mac",
            FT_UINT48, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amt_gateway_port_number,
          { "Gateway Port Number", "amt.gateway.port_number",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amt_gateway_ip_address,
          { "Gateway IP Address", "amt.gateway.ip_address",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_amt_multicast_data,
          { "Multicast Data", "amt.multicast_data",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
    };

    static int *ett[] = {
        &ett_amt
    };


    static ei_register_info ei[] = {
        { &ei_amt_relay_address_unknown,
          { "amt.relay_address.unknown", PI_UNDECODED, PI_NOTE,
            "Relay Address (Unknown Type)", EXPFILL }
        },
        { &ei_amt_unknown,
          { "amt.unknown", PI_UNDECODED, PI_NOTE,
            "Unknown Data", EXPFILL }
        }
    };


    proto_amt = proto_register_protocol("Automatic Multicast Tunneling", "AMT", "amt");

    proto_register_field_array(proto_amt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));


    expert_amt = expert_register_protocol(proto_amt);
    expert_register_field_array(expert_amt, ei, array_length(ei));

    amt_handle = register_dissector("amt", dissect_amt, proto_amt);
}

void
proto_reg_handoff_amt(void)
{
    ip_handle = find_dissector_add_dependency("ip", proto_amt);

    dissector_add_uint_with_preference("udp.port", AMT_UDP_PORT, amt_handle);
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
