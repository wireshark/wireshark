/* packet-fortinet-fgcp.c
 * Routines for FortiGate Cluster Protocol dissection
 * Copyright 2023, Alexis La Goutte <alexis.lagoutte at gmail dot com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * No spec/doc is available based on reverse/analysis of protocol...
 *
 */

#include "config.h"

#include <wireshark.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/etypes.h>

void proto_reg_handoff_fortinet_fgcp(void);
void proto_register_fortinet_fgcp(void);

static int proto_fortinet_fgcp_hb;
static int hf_fortinet_fgcp_hb_magic;
static int hf_fortinet_fgcp_hb_flag;
static int hf_fortinet_fgcp_hb_flag_b74;
static int hf_fortinet_fgcp_hb_flag_b3;
static int hf_fortinet_fgcp_hb_flag_b2;
static int hf_fortinet_fgcp_hb_flag_authentication;
static int hf_fortinet_fgcp_hb_flag_encryption;
static int hf_fortinet_fgcp_hb_mode;
static int hf_fortinet_fgcp_hb_gn;
static int hf_fortinet_fgcp_hb_group_id;
static int hf_fortinet_fgcp_hb_port;
static int hf_fortinet_fgcp_hb_revision;
static int hf_fortinet_fgcp_hb_sn;
static int hf_fortinet_fgcp_hb_payload_encrypted;
static int hf_fortinet_fgcp_hb_authentication;

static int hf_fortinet_fgcp_hb_tlv;
static int hf_fortinet_fgcp_hb_tlv_type;
static int hf_fortinet_fgcp_hb_tlv_length;
static int hf_fortinet_fgcp_hb_tlv_value;
static int hf_fortinet_fgcp_hb_tlv_vcluster_id;
static int hf_fortinet_fgcp_hb_tlv_priority;
static int hf_fortinet_fgcp_hb_tlv_override;

//static int hf_fortinet_fgcp_hb_unknown;
static int hf_fortinet_fgcp_hb_unknown_uint16;

static dissector_handle_t fortinet_fgcp_hb_handle;

static int ett_fortinet_fgcp_hb;
static int ett_fortinet_fgcp_hb_flag;
static int ett_fortinet_fgcp_hb_tlv;

static int proto_fortinet_fgcp_session;
static int hf_fortinet_fgcp_session_magic;
static int hf_fortinet_fgcp_session_type;

static dissector_handle_t fortinet_fgcp_session_handle;
static dissector_handle_t ip_handle;

static int ett_fortinet_fgcp_session;

static const value_string fortinet_fgcp_hb_mode_vals[] = {
    { 0x1,            "A/A (Active/Active)"},
    { 0x2,            "A/P (Active/Passive)"},
    {0, NULL }
};

#define HB_TLV_END_OF_TLV       0x00
#define HB_TLV_VCLUSTER_ID      0x0B
#define HB_TLV_PRIORITY         0x0C
#define HB_TLV_OVERRIDE         0x0D

static const value_string fortinet_fgcp_hb_tlv_vals[] = {
    { HB_TLV_END_OF_TLV, "End of TLV" },
    { HB_TLV_PRIORITY, "Port Priority" },
    { HB_TLV_OVERRIDE, "Override" },
    { 0, NULL }
};


static int
dissect_fortinet_fgcp_hb(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *fortinet_hb_tree;
    unsigned    offset = 0, length, auth_len=0;
    uint8_t     flags;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FGCP-HB");

    col_add_fstr(pinfo->cinfo, COL_INFO, "Cluster: %s(%u) - monitor: %s - SN: %s",
                tvb_get_string_enc(pinfo->pool, tvb, offset+4, 32, ENC_ASCII), /* Group Name*/
                tvb_get_uint16(tvb, (offset+4+32+2), ENC_LITTLE_ENDIAN),  /* Group ID*/
                tvb_get_string_enc(pinfo->pool, tvb, offset+4+32+2+14, 16, ENC_ASCII), /* Port */
                tvb_get_string_enc(pinfo->pool, tvb, offset+4+32+2+14+16+2+2, 16, ENC_ASCII) /* Serial Number */);

    ti = proto_tree_add_item(tree, proto_fortinet_fgcp_hb, tvb, 0, -1, ENC_NA);

    fortinet_hb_tree = proto_item_add_subtree(ti, ett_fortinet_fgcp_hb);

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_magic, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_mode, tvb, offset, 1, ENC_NA);
    offset += 1;

    static int * const fortinet_fgcp_hb_flag[] = {
        &hf_fortinet_fgcp_hb_flag_b74,
        &hf_fortinet_fgcp_hb_flag_b3,
        &hf_fortinet_fgcp_hb_flag_b2,
        &hf_fortinet_fgcp_hb_flag_authentication,
        &hf_fortinet_fgcp_hb_flag_encryption,
        NULL
    };

    proto_tree_add_bitmask(fortinet_hb_tree, tvb, offset, hf_fortinet_fgcp_hb_flag, ett_fortinet_fgcp_hb_flag,
                           fortinet_fgcp_hb_flag, ENC_NA);
    flags =  tvb_get_uint8(tvb, offset);
    offset += 1;

    /* Group Name */
    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_gn, tvb, offset, 32, ENC_ASCII);
    offset += 32;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_unknown_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Group Id */
    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_group_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_unknown_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_unknown_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_unknown_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_unknown_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_unknown_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_unknown_uint16, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Heartbeat Port */
    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_port, tvb, offset, 16, ENC_ASCII);
    offset += 16;

    /* Revision ? */
    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_revision, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* Hash/crc ? change after each revision*/
    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_unknown_uint16, tvb, offset, 2, ENC_NA);
    offset += 2;

    /* Serial Number */
    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_sn, tvb, offset, 16, ENC_ASCII);
    offset += 16;

    if (flags & 0x02) { /* Authentication ? */
        /* the payload finish with 32bits of authentication (hash ?) */
        auth_len = 32;
    }

    if (flags & 0x01) { /* Encrypted Payload ?*/
        length = tvb_reported_length_remaining(tvb, offset) - auth_len;
        proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_payload_encrypted, tvb, offset, length, ENC_NA);
        offset += length;
    } else {
        unsigned next_offset;

        length = tvb_reported_length_remaining(tvb, offset) - auth_len;
        next_offset = offset + length;

        while (offset < next_offset) {
                uint32_t type, len;
                proto_item *ti_tlv;
                proto_tree *tlv_tree;

                ti_tlv = proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_tlv, tvb, offset, 3, ENC_NA);
                tlv_tree = proto_item_add_subtree(ti_tlv, ett_fortinet_fgcp_hb_tlv);
                proto_tree_add_item_ret_uint(tlv_tree, hf_fortinet_fgcp_hb_tlv_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &type);
                offset += 2;
                proto_tree_add_item_ret_uint(tlv_tree, hf_fortinet_fgcp_hb_tlv_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &len);
                offset += 2;

                proto_item_append_text(ti_tlv, ": (t=%u,l=%d) %s", type, len, val_to_str_const(type, fortinet_fgcp_hb_tlv_vals ,"Unknown type") );
                proto_item_set_len(ti_tlv, 2 + 2 + len);

                proto_tree_add_item(tlv_tree, hf_fortinet_fgcp_hb_tlv_value, tvb, offset, len, ENC_NA);
                switch (type) {
                case HB_TLV_VCLUSTER_ID:{
                    uint32_t vcluster_id;
                    proto_tree_add_item_ret_uint(tlv_tree, hf_fortinet_fgcp_hb_tlv_vcluster_id, tvb, offset, 1, ENC_NA, &vcluster_id);
                    proto_item_append_text(ti_tlv, ": %u", vcluster_id);
                    offset += 1;
                    }
                break;
                case HB_TLV_PRIORITY:{
                    uint32_t priority;
                    proto_tree_add_item_ret_uint(tlv_tree, hf_fortinet_fgcp_hb_tlv_priority, tvb, offset, 1, ENC_NA, &priority);
                    proto_item_append_text(ti_tlv, ": %u", priority);
                    offset += 1;
                    }
                break;
                case HB_TLV_OVERRIDE:{
                    uint32_t override;
                    proto_tree_add_item_ret_uint(tlv_tree, hf_fortinet_fgcp_hb_tlv_override, tvb, offset, 1, ENC_NA, &override);
                    if (override){
                        proto_item_append_text(ti_tlv, ": True");
                    } else {
                        proto_item_append_text(ti_tlv, ": False");
                    }
                    offset += 1;
                    }
                break;
                default:
                    offset += len;
                break;
                }
            }
    }

    if (auth_len) { /* Authentication ? */
        proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_hb_authentication, tvb, offset, 32, ENC_NA);
        offset += 32;
    }

    return offset;
}

static int
dissect_fortinet_fgcp_session(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
        void *data _U_)
{
    proto_item *ti;
    proto_tree *fortinet_hb_tree;
    unsigned    offset = 0;
    tvbuff_t    *data_tvb;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FGCP-SESSION");

    ti = proto_tree_add_item(tree, proto_fortinet_fgcp_session, tvb, 0, -1, ENC_NA);

    fortinet_hb_tree = proto_item_add_subtree(ti, ett_fortinet_fgcp_session);

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_session_magic, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    proto_tree_add_item(fortinet_hb_tree, hf_fortinet_fgcp_session_type, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    data_tvb = tvb_new_subset_remaining(tvb, offset);
    call_dissector(ip_handle, data_tvb, pinfo, tree);

    return offset;
}

void
proto_register_fortinet_fgcp(void)
{

    static hf_register_info hf[] = {
        /* HeartBeat */
        { &hf_fortinet_fgcp_hb_magic,
            { "Magic Number", "fortinet_fgcp.hb.magic",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            "Magic Number ?", HFILL }
        },
        { &hf_fortinet_fgcp_hb_flag,
            { "Flag", "fortinet_fgcp.hb.flag",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_flag_b74,
            { "Bit 7 to 4", "fortinet_fgcp.hb.flag.b74",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            "Unknown", HFILL }
        },
        { &hf_fortinet_fgcp_hb_flag_b3,
            { "Bit b3", "fortinet_fgcp.hb.flag.b3",
            FT_UINT8, BASE_HEX, NULL, 0x08,
            "Unknown", HFILL }
        },
        { &hf_fortinet_fgcp_hb_flag_b2,
            { "Bit b2", "fortinet_fgcp.hb.flag.b2",
            FT_UINT8, BASE_HEX, NULL, 0x04,
            "Unknown", HFILL }
        },
        { &hf_fortinet_fgcp_hb_flag_authentication,
            { "Authentication", "fortinet_fgcp.hb.flag.authentication",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_flag_encryption,
            { "Encryption", "fortinet_fgcp.hb.flag.encryption",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_mode,
            { "Mode", "fortinet_fgcp.hb.mode",
            FT_UINT8, BASE_DEC, VALS(fortinet_fgcp_hb_mode_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_gn,
            { "Group Name", "fortinet_fgcp.hb.gn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_group_id,
            { "Group Id", "fortinet_fgcp.hb.group_id",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_port,
            { "Port", "fortinet_fgcp.hb.port",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_revision,
            { "Revision", "fortinet_fgcp.hb.revision",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Number of revision config for HA", HFILL }
        },
        { &hf_fortinet_fgcp_hb_sn,
            { "Serial Number", "fortinet_fgcp.hb.sn",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_payload_encrypted,
            { "Payload (encrypted)", "fortinet_fgcp.hb.payload_encrypted",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_authentication,
            { "Authentication", "fortinet_fgcp.hb.authentication",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fortinet_fgcp_hb_tlv,
          { "TLV", "fortinet_fgcp.hb.tlv",
            FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_tlv_type,
          { "Type", "fortinet_fgcp.hb.tlv.type",
            FT_UINT16, BASE_HEX, VALS(fortinet_fgcp_hb_tlv_vals), 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_tlv_length,
          { "Length", "fortinet_fgcp.hb.tlv.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_tlv_value,
          { "Value", "fortinet_fgcp.hb.tlv.value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_fortinet_fgcp_hb_tlv_vcluster_id,
            { "Vcluster ID", "fortinet_fgcp.hb.tlv.vcluster_id",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_tlv_priority,
            { "Port Priority", "fortinet_fgcp.hb.tlv.priority",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_fortinet_fgcp_hb_tlv_override,
            { "Override", "fortinet_fgcp.hb.tlv.override",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        /*
        { &hf_fortinet_fgcp_hb_unknown,
            { "Unknown", "fortinet_fgcp.hb.unknown",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "Always NULL ?", HFILL }
        },
        */
        { &hf_fortinet_fgcp_hb_unknown_uint16,
            { "Unknown", "fortinet_fgcp.hb.unknown.uint16",
            FT_UINT16, BASE_DEC_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        /* Session */
        { &hf_fortinet_fgcp_session_magic,
            { "Magic Number", "fortinet_fgcp.session.magic",
            FT_UINT16, BASE_HEX_DEC, NULL, 0x0,
            "Magic Number ?", HFILL }
        },
        { &hf_fortinet_fgcp_session_type,
            { "Type", "fortinet_fgcp.session.type",
            FT_UINT16, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_fortinet_fgcp_hb,
        &ett_fortinet_fgcp_hb_flag,
        &ett_fortinet_fgcp_hb_tlv,
        &ett_fortinet_fgcp_session,
    };

    /* Register the protocol name and description */
    proto_fortinet_fgcp_hb = proto_register_protocol("FortiGate Cluster Protocol - HeartBeat",
            "fortinet_fgcp_hb", "fortinet_fgcp_hb");

    proto_fortinet_fgcp_session = proto_register_protocol("FortiGate Cluster Protocol - Session",
            "fortinet_fgcp_session", "fortinet_fgcp_session");

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_fortinet_fgcp_hb, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    fortinet_fgcp_hb_handle = register_dissector("fortinet_fgcp_hb", dissect_fortinet_fgcp_hb,
            proto_fortinet_fgcp_hb);

    fortinet_fgcp_session_handle = register_dissector("fortinet_fgcp_session", dissect_fortinet_fgcp_session,
            proto_fortinet_fgcp_session);

}


void
proto_reg_handoff_fortinet_fgcp(void)
{
      dissector_add_uint("ethertype", ETHERTYPE_FORTINET_FGCP_HB, fortinet_fgcp_hb_handle);
      dissector_add_uint("ethertype", ETHERTYPE_FORTINET_FGCP_SESSION, fortinet_fgcp_session_handle);

      ip_handle  = find_dissector_add_dependency("ip", proto_fortinet_fgcp_session);
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
