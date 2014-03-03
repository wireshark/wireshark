/* packet-btsmp.c
 * Routines for Bluetooth Security Manager Protocol dissection
 *
 * Copyright 2012, Allan M. Madsen <allan.m@madsen.dk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include "config.h"

#include <epan/packet.h>
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
static int proto_btsmp = -1;

static int hf_btsmp_opcode = -1;
static int hf_btsmp_io_capabilities = -1;
static int hf_btsmp_oob_data_flags = -1;
static int hf_btsmp_reason = -1;
static int hf_btsmp_cfm_value = -1;
static int hf_btsmp_random = -1;
static int hf_btsmp_long_term_key = -1;
static int hf_btsmp_id_resolving_key = -1;
static int hf_btsmp_signature_key = -1;
static int hf_btsmp_bonding_flags = -1;
static int hf_btsmp_mitm_flag = -1;
static int hf_btsmp_max_enc_key_size = -1;
static int hf_btsmp_key_dist_enc = -1;
static int hf_btsmp_key_dist_id = -1;
static int hf_btsmp_key_dist_sign = -1;
static int hf_btsmp_ediv = -1;
static int hf_btsmp_authreq = -1;
static int hf_btsmp_initiator_key_distribution = -1;
static int hf_btsmp_responder_key_distribution = -1;

/* Initialize the subtree pointers */
static gint ett_btsmp = -1;
static gint ett_btsmp_auth_req = -1;
static gint ett_btsmp_key_dist = -1;

static dissector_handle_t btsmp_handle;

/* Opcodes */
static const value_string opcode_vals[] = {
    {0x01, "Pairing Request"},
    {0x02, "Pairing Response"},
    {0x03, "Pairing Confirm"},
    {0x04, "Pairing Random"},
    {0x05, "Pairing Failed"},
    {0x06, "Encryption Information"},
    {0x07, "Master Identification"},
    {0x08, "Identity Information"},
    {0x09, "Identity Address Information"},
    {0x0a, "Signing Information"},
    {0x0b, "Security Request"},
    {0x0, NULL}
};

/* IO capabilities */
static const value_string io_capability_vals[] = {
    {0x00, "Display Only"},
    {0x01, "Display Yes/No"},
    {0x02, "Keyboard Only"},
    {0x03, "No Input, No Output"},
    {0x04, "Keyboard, Display"},
    {0x0, NULL}
};

/* OOB Data present Flag */
static const value_string oob_data_flag_vals[] = {
    {0x00, "OOB Auth. Data Not Present"},
    {0x01, "OOB Auth. Data From Remote Device Present"},
    {0x0, NULL}
};

/* Bonding flags */
static const value_string bonding_flag_vals[] = {
    {0x00, "No Bonding"},
    {0x01, "Bonding"},
    {0x0, NULL}
};

/* Reason codes */
static const value_string reason_vals[] = {
    {0x01, "Passkey Entry Failed"},
    {0x02, "OOB Not Available"},
    {0x03, "Authentication Requirements"},
    {0x04, "Confirm Value Failed"},
    {0x05, "Pairing Not Supported"},
    {0x06, "Encryption Key Size"},
    {0x07, "Command Not Supported"},
    {0x08, "Unspecified Reason"},
    {0x09, "Repeated Attempts"},
    {0x0a, "Invalid Parameters"},
    {0x0, NULL}
};

void proto_register_btsmp(void);
void proto_reg_handoff_btsmp(void);

static int
dissect_btsmp_auth_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti_param;
    proto_tree *st_param;
    guint8 param;

    param = tvb_get_guint8(tvb, offset);
    ti_param = proto_tree_add_item(tree, hf_btsmp_authreq, tvb, offset, 1, ENC_NA);
    st_param = proto_item_add_subtree(ti_param, ett_btsmp_auth_req);
    proto_tree_add_item(st_param, hf_btsmp_bonding_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(ti_param, "%s, ", val_to_str_const(param & 0x03, bonding_flag_vals, "<unknown>"));
    proto_tree_add_item(st_param, hf_btsmp_mitm_flag, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_item_append_text(ti_param, "%s", (param & 0x04) ? "MITM" : "No MITM");

    col_append_fstr(pinfo->cinfo, COL_INFO, "%s, %s", val_to_str_const(param & 0x03, bonding_flag_vals, "<unknown>"), (param & 0x04) ? "MITM" : "No MITM");

    return offset + 1;
}

static int
dissect_btsmp_key_dist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, gboolean initiator)
{
    proto_item *ti_param;
    proto_tree *st_param;
    guint8 param;

    param = tvb_get_guint8(tvb, offset);
    if (initiator) {
        col_append_str(pinfo->cinfo, COL_INFO, ", Initiator Key(s): ");
        ti_param = proto_tree_add_item(tree, hf_btsmp_initiator_key_distribution, tvb, offset, 1, ENC_NA);
    }
    else {
        col_append_str(pinfo->cinfo, COL_INFO, ", Responder Key(s): ");
        ti_param = proto_tree_add_item(tree, hf_btsmp_responder_key_distribution, tvb, offset, 1, ENC_NA);
    }

    st_param = proto_item_add_subtree(ti_param, ett_btsmp_key_dist);
    proto_tree_add_item(st_param, hf_btsmp_key_dist_enc, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(st_param, hf_btsmp_key_dist_id, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(st_param, hf_btsmp_key_dist_sign, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    if (param & 0x01) {
        proto_item_append_text(ti_param, "LTK ");
        col_append_str(pinfo->cinfo, COL_INFO, "LTK ");
    }
    if (param & 0x02) {
        proto_item_append_text(ti_param, "IRK ");
        col_append_str(pinfo->cinfo, COL_INFO, "IRK ");
    }
    if (param & 0x04) {
        proto_item_append_text(ti_param, "CSRK ");
        col_append_str(pinfo->cinfo, COL_INFO, "CSRK ");
    }

    return offset + 1;
}

static int
dissect_btsmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    proto_item *ti;
    proto_tree *st;
    guint8 opcode;

    ti = proto_tree_add_item(tree, proto_btsmp, tvb, 0, -1, ENC_NA);
    st = proto_item_add_subtree(ti, ett_btsmp);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SMP");

    switch (pinfo->p2p_dir) {
        case P2P_DIR_SENT:
            col_set_str(pinfo->cinfo, COL_INFO, "Sent ");
            break;
        case P2P_DIR_RECV:
            col_set_str(pinfo->cinfo, COL_INFO, "Rcvd ");
            break;
        default:
            col_add_fstr(pinfo->cinfo, COL_INFO, "Unknown direction %d ",
                pinfo->p2p_dir);
            break;
    }

    if (tvb_length_remaining(tvb, 0) < 1)
        return FALSE;

    proto_tree_add_item(st, hf_btsmp_opcode, tvb, 0, 1, ENC_LITTLE_ENDIAN);
    opcode = tvb_get_guint8(tvb, 0);
    offset++;

    col_append_str(pinfo->cinfo, COL_INFO, val_to_str_const(opcode, opcode_vals, "<unknown>"));

    switch (opcode) {
    case 0x01: /* Pairing Request */
    case 0x02: /* Pairing Response */
    {
        col_append_str(pinfo->cinfo, COL_INFO, ": ");

        proto_tree_add_item(st, hf_btsmp_io_capabilities, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;
        proto_tree_add_item(st, hf_btsmp_oob_data_flags, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        offset = dissect_btsmp_auth_req(tvb, offset, pinfo, st);

        proto_tree_add_item(st, hf_btsmp_max_enc_key_size, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        offset++;

        offset = dissect_btsmp_key_dist(tvb, offset, pinfo, st, TRUE);
        offset = dissect_btsmp_key_dist(tvb, offset, pinfo, st, FALSE);
        break;
    }

    case 0x03: /* Pairing Confirm */
        proto_tree_add_item(st, hf_btsmp_cfm_value, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x04: /* Pairing Random */
        proto_tree_add_item(st, hf_btsmp_random, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x05: /* Pairing Failed */
        proto_tree_add_item(st, hf_btsmp_reason, tvb, offset, 1, ENC_LITTLE_ENDIAN);
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(tvb_get_guint8(tvb, offset), reason_vals, "<unknown>"));
        offset++;
        break;

    case 0x06: /* Encryption Information */
        proto_tree_add_item(st, hf_btsmp_long_term_key, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x07: /* Master Identification */
        proto_tree_add_item(st, hf_btsmp_ediv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btsmp_random, tvb, offset, 8, ENC_NA);
        offset += 8;
        break;

    case 0x08: /* Identity Information */
        proto_tree_add_item(st, hf_btsmp_id_resolving_key, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x0a: /* Signing Informationn */
        proto_tree_add_item(st, hf_btsmp_signature_key, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

     case 0x0b: /* Security Request */
        col_append_str(pinfo->cinfo, COL_INFO, ": ");
        offset = dissect_btsmp_auth_req(tvb, offset, pinfo, st);
        break;

    default:
        break;
    }

    return offset;
}

void
proto_register_btsmp(void)
{
    static hf_register_info hf[] = {
        {&hf_btsmp_opcode,
            {"Opcode", "btsmp.opcode",
            FT_UINT8, BASE_HEX, VALS(opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_reason,
            {"Reason", "btsmp.reason",
            FT_UINT8, BASE_HEX, VALS(reason_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_io_capabilities,
            {"IO Capability", "btsmp.io_capability",
            FT_UINT8, BASE_HEX, VALS(io_capability_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_oob_data_flags,
            {"OOB Data Flags", "btsmp.oob_data_flags",
            FT_UINT8, BASE_HEX, VALS(oob_data_flag_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_cfm_value,
            {"Confirm Value", "btsmp.cfm_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_random,
            {"Random Value", "btsmp.random_value",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_long_term_key,
            {"Long Term Key", "btsmp.long_term_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_id_resolving_key,
            {"Identity Resolving Key", "btsmp.id_resolving_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_signature_key,
            {"Signature Key", "btsmp.signature_key",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_bonding_flags,
            {"Bonding Flags", "btsmp.bonding_flags",
            FT_UINT8, BASE_HEX, VALS(bonding_flag_vals), 0x03,
            NULL, HFILL}
        },
        {&hf_btsmp_mitm_flag,
            {"MITM Flag", "btsmp.mitm_flag",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btsmp_max_enc_key_size,
            {"Max Encryption Key Size", "btsmp.max_enc_key_size",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btsmp_key_dist_enc,
            {"Encryption Key (LTK)", "btsmp.key_dist_enc",
            FT_UINT8, BASE_DEC, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btsmp_key_dist_id,
            {"Id Key (IRK)", "btsmp.key_dist_id",
            FT_UINT8, BASE_DEC, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btsmp_key_dist_sign,
            {"Signature Key (CSRK)", "btsmp.key_dist_sign",
            FT_UINT8, BASE_DEC, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btsmp_ediv,
            {"Encrypted Diversifier (EDIV)", "btsmp.ediv",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btsmp_authreq,
            {"AuthReq", "btsmp.authreq",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btsmp_initiator_key_distribution,
            {"Initiator Key Distribution", "btsmp.initiator_key_distribution",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btsmp_responder_key_distribution,
            {"Responder Key Distribution", "btsmp.responder_key_distribution",
            FT_NONE, BASE_NONE, NULL, 0x00,
            NULL, HFILL}
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
      &ett_btsmp,
      &ett_btsmp_auth_req,
      &ett_btsmp_key_dist
    };

    /* Register the protocol name and description */
    proto_btsmp = proto_register_protocol("Bluetooth Security Manager Protocol",
        "BT SMP", "btsmp");

    btsmp_handle = new_register_dissector("btsmp", dissect_btsmp, proto_btsmp);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btsmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btsmp(void)
{
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_SMP, btsmp_handle);
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
