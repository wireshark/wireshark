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
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-bluetooth.h"
#include "packet-btl2cap.h"

/* Initialize the protocol and registered fields */
static int proto_btsmp;

static int hf_btsmp_opcode;
static int hf_btsmp_io_capabilities;
static int hf_btsmp_oob_data_flags;
static int hf_btsmp_reason;
static int hf_btsmp_cfm_value;
static int hf_btsmp_random;
static int hf_btsmp_long_term_key;
static int hf_btsmp_id_resolving_key;
static int hf_btsmp_signature_key;
static int hf_btsmp_bonding_flags;
static int hf_btsmp_mitm_flag;
static int hf_btsmp_secure_connection_flag;
static int hf_btsmp_keypress_flag;
static int hf_btsmp_ct2_flag;
static int hf_btsmp_reserved_flag;
static int hf_btsmp_max_enc_key_size;
static int hf_btsmp_key_dist_enc;
static int hf_btsmp_key_dist_id;
static int hf_btsmp_key_dist_sign;
static int hf_btsmp_key_dist_linkkey;
static int hf_btsmp_key_dist_reserved;
static int hf_btsmp_ediv;
static int hf_btsmp_authreq;
static int hf_btsmp_initiator_key_distribution;
static int hf_btsmp_responder_key_distribution;
static int hf_bd_addr;
static int hf_address_type;
static int hf_btsmp_public_key_x;
static int hf_btsmp_public_key_y;
static int hf_btsmp_dhkey_check;
static int hf_btsmp_notification_type;

static int * const hfx_btsmp_key_distribution[] = {
    &hf_btsmp_key_dist_reserved,
    &hf_btsmp_key_dist_linkkey,
    &hf_btsmp_key_dist_sign,
    &hf_btsmp_key_dist_id,
    &hf_btsmp_key_dist_enc,
    NULL
};

static int * const hfx_btsmp_authreq[] = {
    &hf_btsmp_reserved_flag,
    &hf_btsmp_ct2_flag,
    &hf_btsmp_keypress_flag,
    &hf_btsmp_secure_connection_flag,
    &hf_btsmp_mitm_flag,
    &hf_btsmp_bonding_flags,
    NULL
};


/* Initialize the subtree pointers */
static int ett_btsmp;
static int ett_btsmp_auth_req;
static int ett_btsmp_key_dist;

static dissector_handle_t btsmp_handle;

/* Opcodes */
static const value_string opcode_vals[] = {
    {0x01, "Pairing Request"},
    {0x02, "Pairing Response"},
    {0x03, "Pairing Confirm"},
    {0x04, "Pairing Random"},
    {0x05, "Pairing Failed"},
    {0x06, "Encryption Information"},
    {0x07, "Central Identification"},
    {0x08, "Identity Information"},
    {0x09, "Identity Address Information"},
    {0x0A, "Signing Information"},
    {0x0B, "Security Request"},
    {0x0C, "Pairing Public Key"},
    {0x0D, "Pairing DHKey Check"},
    {0x0E, "Pairing Keypress Notification"},
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
    {0x0A, "Invalid Parameters"},
    {0x0B, "DHKey Check Failed"},
    {0x0C, "Numeric Comparison Failed"},
    {0x0D, "BR/EDR pairing in progress"},
    {0x0E, "Cross-transport Key Derivation/Generation not allowed"},
    {0x0, NULL}
};

static const value_string notification_type_vals[] = {
    {0x00, "Passkey Entry Started"},
    {0x01, "Passkey Digit Entered"},
    {0x02, "Passkey Digit Erased"},
    {0x03, "Passkey Cleared"},
    {0x04, "Passkey Entry Completed"},
    {0x0, NULL}
};

/* X coordinate of debug public key. Little-endian. */
static const uint8_t debug_public_key_x[32] = {
    0xe6, 0x9d, 0x35, 0x0e, 0x48, 0x01, 0x03, 0xcc,
    0xdb, 0xfd, 0xf4, 0xac, 0x11, 0x91, 0xf4, 0xef,
    0xb9, 0xa5, 0xf9, 0xe9, 0xa7, 0x83, 0x2c, 0x5e,
    0x2c, 0xbe, 0x97, 0xf2, 0xd2, 0x03, 0xb0, 0x20,
};

/* Y coordinate of debug public key. Little-endian. */
static const uint8_t debug_public_key_y[32] = {
    0x8b, 0xd2, 0x89, 0x15, 0xd0, 0x8e, 0x1c, 0x74,
    0x24, 0x30, 0xed, 0x8f, 0xc2, 0x45, 0x63, 0x76,
    0x5c, 0x15, 0x52, 0x5a, 0xbf, 0x9a, 0x32, 0x63,
    0x6d, 0xeb, 0x2a, 0x65, 0x49, 0x9c, 0x80, 0xdc
};

void proto_register_btsmp(void);
void proto_reg_handoff_btsmp(void);

static int
dissect_btsmp_auth_req(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree)
{
    uint8_t value;
    const uint8_t *ph;

    col_append_str(pinfo->cinfo, COL_INFO, "AuthReq: ");
    proto_tree_add_bitmask(tree, tvb, offset, hf_btsmp_authreq, ett_btsmp_auth_req, hfx_btsmp_authreq, ENC_LITTLE_ENDIAN);

    value = tvb_get_uint8(tvb, offset);

    ph = val_to_str_const(value & 0x03, bonding_flag_vals, "<unknown>");
    col_append_sep_str(pinfo->cinfo, COL_INFO, "", ph);

    if (value & 0x04)
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "MITM");
    if (value & 0x08)
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "SecureConnection");
    if (value & 0x10)
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Keypress");
    if (value & 0xE0)
        col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Reserved");

    return offset + 1;
}

static int
dissect_btsmp_key_dist(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, bool initiator)
{
    uint8_t value;
    bool next = false;

    if (initiator) {
        col_append_str(pinfo->cinfo, COL_INFO, " | Initiator Key(s): ");
        proto_tree_add_bitmask(tree, tvb, offset, hf_btsmp_initiator_key_distribution, ett_btsmp_key_dist, hfx_btsmp_key_distribution, ENC_LITTLE_ENDIAN);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, " | Responder Key(s): ");
        proto_tree_add_bitmask(tree, tvb, offset, hf_btsmp_responder_key_distribution, ett_btsmp_key_dist, hfx_btsmp_key_distribution, ENC_LITTLE_ENDIAN);
    }

    value = tvb_get_uint8(tvb, offset);

    if (value & 0x01) {
        col_append_str(pinfo->cinfo, COL_INFO, "LTK");
        next = true;
    }
    if (value & 0x02) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, next ? ", " : "", "IRK");
        next = true;
    }
    if (value & 0x04) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, next ? ", " : "", "CSRK");
        next = true;
    }
    if (value & 0x08) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, next ? ", " : "", "Linkkey");
        next = true;
    }
    if (value & 0xF0) {
        col_append_sep_str(pinfo->cinfo, COL_INFO, next ? ", " : "", "Reserved");
    }
    if (!next) {
        col_append_str(pinfo->cinfo, COL_INFO, "<none>");
    }

    return offset + 1;
}

static int
dissect_btsmp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int          offset = 0;
    proto_item  *ti;
    proto_tree  *st;
    uint8_t     opcode;
    uint32_t    interface_id;
    uint32_t    adapter_id;
    int         previous_proto;

    interface_id = HCI_INTERFACE_DEFAULT;
    adapter_id = HCI_ADAPTER_DEFAULT;
    previous_proto = (GPOINTER_TO_INT(wmem_list_frame_data(wmem_list_frame_prev(wmem_list_tail(pinfo->layers)))));
    if (data && previous_proto == proto_btl2cap) {
        btl2cap_data_t *l2cap_data;

        l2cap_data = (btl2cap_data_t *) data;
        if (l2cap_data) {
            interface_id = l2cap_data->interface_id;
            adapter_id = l2cap_data->adapter_id;
        }
    }

    ti = proto_tree_add_item(tree, proto_btsmp, tvb, 0, tvb_captured_length(tvb), ENC_NA);
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
            col_set_str(pinfo->cinfo, COL_INFO, "UnknownDirection ");
            break;
    }

    if (tvb_reported_length(tvb) < 1)
        return false;

    proto_tree_add_item(st, hf_btsmp_opcode, tvb, 0, 1, ENC_LITTLE_ENDIAN);
    opcode = tvb_get_uint8(tvb, 0);
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

        offset = dissect_btsmp_key_dist(tvb, offset, pinfo, st, true);
        offset = dissect_btsmp_key_dist(tvb, offset, pinfo, st, false);
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
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(tvb_get_uint8(tvb, offset), reason_vals, "<unknown>"));
        offset++;
        break;

    case 0x06: /* Encryption Information */
        proto_tree_add_item(st, hf_btsmp_long_term_key, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x07: /* Central Identification */
        proto_tree_add_item(st, hf_btsmp_ediv, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset += 2;
        proto_tree_add_item(st, hf_btsmp_random, tvb, offset, 8, ENC_NA);
        offset += 8;
        break;

    case 0x08: /* Identity Information */
        proto_tree_add_item(st, hf_btsmp_id_resolving_key, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

    case 0x09: /* Identity Address Information */
        proto_tree_add_item(st, hf_address_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        offset = dissect_bd_addr(hf_bd_addr, pinfo, st, tvb, offset, false, interface_id, adapter_id, NULL);
        break;

    case 0x0A: /* Signing Information */
        proto_tree_add_item(st, hf_btsmp_signature_key, tvb, offset, 16, ENC_NA);
        offset += 16;
        break;

     case 0x0B: /* Security Request */
        col_append_str(pinfo->cinfo, COL_INFO, ": ");
        offset = dissect_btsmp_auth_req(tvb, offset, pinfo, st);
        break;

    case 0x0C: /* Pairing Public Key */ {
        proto_item  *sub_item;

        sub_item = proto_tree_add_item(st, hf_btsmp_public_key_x, tvb, offset, 32, ENC_NA);
        if (tvb_memeql(tvb, offset, debug_public_key_x, 32) == 0)
            proto_item_append_text(sub_item, " (Debug Key)");
        offset += 32;

        sub_item = proto_tree_add_item(st, hf_btsmp_public_key_y, tvb, offset, 32, ENC_NA);
        if (tvb_memeql(tvb, offset, debug_public_key_y, 32) == 0)
            proto_item_append_text(sub_item, " (Debug Key)");
        offset += 32;

        break;}
    case 0x0D: /* Pairing DHKey Check" */
        proto_tree_add_item(st, hf_btsmp_dhkey_check, tvb, offset, 16, ENC_NA);
        offset += 16;

        break;
    case 0x0E: /* Pairing Keypress Notification */
        proto_tree_add_item(st, hf_btsmp_notification_type, tvb, offset, 1, ENC_NA);
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str_const(tvb_get_uint8(tvb, offset), notification_type_vals, "<unknown>"));
        offset += 1;

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
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btsmp_secure_connection_flag,
            {"Secure Connection Flag", "btsmp.sc_flag",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btsmp_keypress_flag,
            {"Keypress Flag", "btsmp.keypress_flag",
            FT_BOOLEAN, 8, NULL, 0x10,
            NULL, HFILL}
        },
        {&hf_btsmp_ct2_flag,
            {"CT2 Flag", "btsmp.ct2_flag",
            FT_BOOLEAN, 8, NULL, 0x20,
            NULL, HFILL}
        },
        {&hf_btsmp_reserved_flag,
            {"Reserved", "btsmp.reserved_flags",
            FT_UINT8, BASE_HEX, NULL, 0xC0,
            NULL, HFILL}
        },
        {&hf_btsmp_max_enc_key_size,
            {"Max Encryption Key Size", "btsmp.max_enc_key_size",
            FT_UINT8, BASE_DEC, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btsmp_key_dist_enc,
            {"Encryption Key (LTK)", "btsmp.key_dist_enc",
            FT_BOOLEAN, 8, NULL, 0x01,
            NULL, HFILL}
        },
        {&hf_btsmp_key_dist_id,
            {"Id Key (IRK)", "btsmp.key_dist_id",
            FT_BOOLEAN, 8, NULL, 0x02,
            NULL, HFILL}
        },
        {&hf_btsmp_key_dist_sign,
            {"Signature Key (CSRK)", "btsmp.key_dist_sign",
            FT_BOOLEAN, 8, NULL, 0x04,
            NULL, HFILL}
        },
        {&hf_btsmp_key_dist_linkkey,
            {"Link Key", "btsmp.key_dist_linkkey",
            FT_BOOLEAN, 8, NULL, 0x08,
            NULL, HFILL}
        },
        {&hf_btsmp_key_dist_reserved,
            {"Reserved", "btsmp.key_dist_reserved",
            FT_UINT8, BASE_HEX, NULL, 0xF0,
            NULL, HFILL}
        },
        {&hf_btsmp_ediv,
            {"Encrypted Diversifier (EDIV)", "btsmp.ediv",
            FT_UINT16, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btsmp_authreq,
            {"AuthReq", "btsmp.authreq",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btsmp_initiator_key_distribution,
            {"Initiator Key Distribution", "btsmp.initiator_key_distribution",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_btsmp_responder_key_distribution,
            {"Responder Key Distribution", "btsmp.responder_key_distribution",
            FT_UINT8, BASE_HEX, NULL, 0x00,
            NULL, HFILL}
        },
        {&hf_bd_addr,
          { "BD_ADDR", "btsmp.bd_addr",
            FT_ETHER, BASE_NONE, NULL, 0x0,
            "Bluetooth Device Address", HFILL}
        },
        { &hf_address_type,
            { "Address Type", "btsmp.address_type",
            FT_UINT8, BASE_HEX, VALS(bluetooth_address_type_vals), 0x0,
            NULL, HFILL }
        },
        {&hf_btsmp_public_key_x,
            {"Public Key X", "btsmp.public_key_x",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_public_key_y,
            {"Public Key Y", "btsmp.public_key_y",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_dhkey_check,
            {"DHKey Check", "btsmp.dhkey_check",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL}
        },
        {&hf_btsmp_notification_type,
            {"Notification Type", "btsmp.notification_type",
            FT_UINT8, BASE_HEX, VALS(notification_type_vals), 0x0,
            NULL, HFILL}
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
      &ett_btsmp,
      &ett_btsmp_auth_req,
      &ett_btsmp_key_dist
    };

    /* Register the protocol name and description */
    proto_btsmp = proto_register_protocol("Bluetooth Security Manager Protocol",
        "BT SMP", "btsmp");

    btsmp_handle = register_dissector("btsmp", dissect_btsmp, proto_btsmp);

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_btsmp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btsmp(void)
{
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_SMP, btsmp_handle);
    dissector_add_uint("btl2cap.cid", BTL2CAP_FIXED_CID_BR_EDR_SM, btsmp_handle);
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
