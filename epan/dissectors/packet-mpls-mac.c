/* packet-mpls-mac.c
 *
 * Routines for MPLS Media Access Control (MAC) Address Withdrawal over Static Pseudowire.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-mpls.h"

void proto_register_mpls_mac(void);
void proto_reg_handoff_mpls_mac(void);

static dissector_handle_t mpls_mac_handle;

static int proto_mpls_mac;

static int ett_mpls_mac;
static int ett_mpls_mac_flags;
static int ett_mpls_mac_tlv;

static int hf_mpls_mac_reserved;
static int hf_mpls_mac_tlv_length_total;
static int hf_mpls_mac_flags;
static int hf_mpls_mac_flags_a;
static int hf_mpls_mac_flags_r;
static int hf_mpls_mac_flags_reserved;
static int hf_mpls_mac_tlv;
static int hf_mpls_mac_tlv_res;
static int hf_mpls_mac_tlv_type;
static int hf_mpls_mac_tlv_length;
static int hf_mpls_mac_tlv_value;
static int hf_mpls_mac_tlv_sequence_number;


static int * const mpls_mac_flags[] = {
  &hf_mpls_mac_flags_a,
  &hf_mpls_mac_flags_r,
  &hf_mpls_mac_flags_reserved,
  NULL
};

static int
dissect_mpls_mac(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    proto_item *ti;
    proto_tree *mac_tree;
    uint32_t    offset = 0, tlv_length, offset_end;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPLS-MAC");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_mpls_mac, tvb, 0, -1, ENC_NA);
    mac_tree = proto_item_add_subtree(ti, ett_mpls_mac);
    /* Reserved */
    proto_tree_add_item(mac_tree, hf_mpls_mac_reserved, tvb, offset, 2, ENC_NA);
    offset += 2;
    /* TLV length */
    proto_tree_add_item_ret_uint(mac_tree, hf_mpls_mac_tlv_length_total, tvb, offset, 1, ENC_BIG_ENDIAN, &tlv_length);
    offset += 1;
    /* Flags */
    proto_tree_add_bitmask(mac_tree, tvb, offset, hf_mpls_mac_flags,
                         ett_mpls_mac_flags,
                         mpls_mac_flags,
                         ENC_BIG_ENDIAN);
    offset += 1;
    offset_end = offset + tlv_length;

    while(offset < offset_end){
        uint32_t type, length;
        proto_tree *tlv_tree;

        ti = proto_tree_add_item(mac_tree, hf_mpls_mac_tlv, tvb, offset, 4, ENC_NA);

        tlv_tree = proto_item_add_subtree(ti, ett_mpls_mac_tlv);
        /* res(erved) */
        proto_tree_add_item(tlv_tree, hf_mpls_mac_tlv_res, tvb, offset, 2, ENC_BIG_ENDIAN);

        /* TLV Type */
        proto_tree_add_item_ret_uint(tlv_tree, hf_mpls_mac_tlv_type, tvb, offset, 2, ENC_BIG_ENDIAN, &type);
        offset += 2;

        /* TLV Length */
        proto_tree_add_item_ret_uint(tlv_tree, hf_mpls_mac_tlv_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
        offset += 2;
        proto_item_set_len(ti, 2+2+length);
        proto_item_append_text(ti, " (t=0x%x, l=%u)", type, length);

        /* TLV Value */
        proto_tree_add_item(tlv_tree, hf_mpls_mac_tlv_value, tvb, offset, length, ENC_NA);

        switch(type){
            case 0x0001:
                proto_tree_add_item(tlv_tree, hf_mpls_mac_tlv_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            break;
            default:
                offset += length;
            break;
        }

    }
    return offset;
}

void
proto_register_mpls_mac(void)
{
    static hf_register_info hf[] = {
        {
            &hf_mpls_mac_reserved,
            {
                "Reserved", "mpls_mac.reserved",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_tlv_length_total,
            {
                "TLV Length (Total)", "mpls_mac.tlv_length_total",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_flags,
            {
                "Flags", "mpls_mac.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_flags_a,
            {
                "Flags A", "mpls_mac.flags.a",
                FT_BOOLEAN, 8, NULL, 0x80,
                "set by a receiver to acknowledge receipt and processing of a MAC Address Withdraw OAM Message", HFILL
            }
        },
        {
            &hf_mpls_mac_flags_r,
            {
                "Flags R", "mpls_mac.flags.r",
                FT_BOOLEAN, 8, NULL, 0x40,
                "Set to indicate if the sender is requesting reset of the sequence numbers", HFILL
            }
        },
        {
            &hf_mpls_mac_flags_reserved,
            {
                "Flags Reserved", "mpls_mac.flags.reserved",
                FT_UINT8, BASE_HEX, NULL, 0x3F,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_tlv,
            {
                "TLV", "mpls_mac.tlv",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_tlv_res,
            {
                "Res(erved)", "mpls_mac.tlv.res",
                FT_UINT16, BASE_HEX, NULL, 0xC000,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_tlv_type,
            {
                "TLV Type", "mpls_mac.tlv.type",
                FT_UINT16, BASE_HEX, NULL, 0x3FFF,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_tlv_length,
            {
                "TLV Length", "mpls_mac.tlv.length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_tlv_value,
            {
                "TLV Value", "mpls_mac.tlv.value",
                FT_BYTES, BASE_NONE, NULL, 0x0,
                NULL, HFILL
            }
        },
        {
            &hf_mpls_mac_tlv_sequence_number,
            {
                "Sequence Number", "mpls_mac.tlv.sequence_number",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL
            }
        },
    };

    static int *ett[] = {
        &ett_mpls_mac,
        &ett_mpls_mac_flags,
        &ett_mpls_mac_tlv,
    };

    proto_mpls_mac =
        proto_register_protocol("Media Access Control (MAC) Address Withdrawal over Static Pseudowire", "MPLS-MAC", "mpls_mac");

    proto_register_field_array(proto_mpls_mac, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    mpls_mac_handle = register_dissector("mpls_mac", dissect_mpls_mac, proto_mpls_mac);
}

void
proto_reg_handoff_mpls_mac(void)
{
    dissector_add_uint("pwach.channel_type", PW_ACH_TYPE_MAC, mpls_mac_handle);
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
