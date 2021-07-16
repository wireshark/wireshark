/* packet-lin.c
 *
 * LIN dissector.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2021-2021 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>

#include <packet-lin.h>

 /*
  * Dissector for the Local Interconnect Network (LIN) bus.
  *
  * see ISO 17987 or search for "LIN Specification 2.2a" online.
  */

#define LIN_NAME                             "LIN"
#define LIN_NAME_LONG                        "LIN Protocol"
#define LIN_NAME_FILTER                      "lin"

static heur_dissector_list_t                 heur_subdissector_list;
static heur_dtbl_entry_t                    *heur_dtbl_entry;

static int proto_lin = -1;

/* header field */
static int hf_lin_msg_format_rev = -1;
static int hf_lin_reserved1 = -1;
static int hf_lin_payload_length = -1;
static int hf_lin_message_type = -1;
static int hf_lin_checksum_type = -1;
static int hf_lin_pid = -1;
static int hf_lin_id = -1;
static int hf_lin_parity = -1;
static int hf_lin_checksum = -1;
static int hf_lin_err_errors = -1;
static int hf_lin_err_no_slave_response = -1;
static int hf_lin_err_framing = -1;
static int hf_lin_err_parity = -1;
static int hf_lin_err_checksum = -1;
static int hf_lin_err_invalidid = -1;
static int hf_lin_err_overflow = -1;
static int hf_lin_event_id = -1;

static gint ett_lin = -1;
static gint ett_lin_pid = -1;
static gint ett_errors = -1;

static int * const error_fields[] = {
    &hf_lin_err_overflow,
    &hf_lin_err_invalidid,
    &hf_lin_err_checksum,
    &hf_lin_err_parity,
    &hf_lin_err_framing,
    &hf_lin_err_no_slave_response,
    NULL
};

static dissector_table_t subdissector_table;

#define LIN_MSG_TYPE_FRAME 0
#define LIN_MSG_TYPE_EVENT 3

static const value_string lin_msg_type_names[] = {
    { LIN_MSG_TYPE_FRAME, "Frame" },
    { LIN_MSG_TYPE_EVENT, "Event" },
    {0, NULL}
};

#define LIN_CHKSUM_TYPE_UNKN_ERR 0
#define LIN_CHKSUM_TYPE_CLASSIC  1
#define LIN_CHKSUM_TYPE_ENHANCED 2
#define LIN_CHKSUM_TYPE_UNDEF    3

static const value_string lin_checksum_type_names[] = {
    { LIN_CHKSUM_TYPE_UNKN_ERR, "Unknown/Error" },
    { LIN_CHKSUM_TYPE_CLASSIC, "Classic" },
    { LIN_CHKSUM_TYPE_ENHANCED, "Enhanced" },
    { LIN_CHKSUM_TYPE_UNDEF, "Undefined" },
    {0, NULL}
};

#define LIN_EVENT_TYPE_GO_TO_SLEEP_EVENT_BY_GO_TO_SLEEP 0xB0B00001
#define LIN_EVENT_TYPE_GO_TO_SLEEP_EVENT_BY_INACTIVITY  0xB0B00002
#define LIN_EVENT_TYPE_WAKE_UP_BY_WAKE_UP_SIGNAL        0xB0B00004

static const value_string lin_event_type_names[] = {
    { LIN_EVENT_TYPE_GO_TO_SLEEP_EVENT_BY_GO_TO_SLEEP, "Go-to-Sleep event by Go-to-Sleep frame" },
    { LIN_EVENT_TYPE_GO_TO_SLEEP_EVENT_BY_INACTIVITY,  "Go-to-Sleep event by Inactivity for more than 4s" },
    { LIN_EVENT_TYPE_WAKE_UP_BY_WAKE_UP_SIGNAL,        "Wake-up event by Wake-up signal" },
    {0, NULL}
};

void proto_reg_handoff_lin(void);
void proto_register_lin(void);


static int
dissect_lin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_) {
    proto_item *ti;
    proto_item *ti_root;
    proto_tree *lin_tree;
    proto_tree *lin_id_tree;
    tvbuff_t   *next_tvb;

    guint payload_length;
    guint msg_type;
    lin_info_t lininfo;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, LIN_NAME);
    col_clear(pinfo->cinfo, COL_INFO);

    // TODO: Set end later!?
    ti_root = proto_tree_add_item(tree, proto_lin, tvb, 0, -1, ENC_NA);
    lin_tree = proto_item_add_subtree(ti_root, ett_lin);

    proto_tree_add_item(lin_tree, hf_lin_msg_format_rev, tvb, 0, 1, ENC_BIG_ENDIAN);
    ti = proto_tree_add_item(lin_tree, hf_lin_reserved1, tvb, 1, 3, ENC_BIG_ENDIAN);
    proto_item_set_hidden(ti);

    proto_tree_add_item_ret_uint(lin_tree, hf_lin_payload_length, tvb, 4, 1, ENC_BIG_ENDIAN, &payload_length);
    proto_tree_add_item_ret_uint(lin_tree, hf_lin_message_type, tvb, 4, 1, ENC_BIG_ENDIAN, &msg_type);
    if (msg_type != LIN_MSG_TYPE_EVENT) {
        proto_tree_add_item(lin_tree, hf_lin_checksum_type, tvb, 4, 1, ENC_BIG_ENDIAN);

        ti = proto_tree_add_item(lin_tree, hf_lin_pid, tvb, 5, 1, ENC_BIG_ENDIAN);
        lin_id_tree = proto_item_add_subtree(ti, ett_lin_pid);
        proto_tree_add_item(lin_id_tree, hf_lin_parity, tvb, 5, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_uint(lin_id_tree, hf_lin_id, tvb, 5, 1, ENC_BIG_ENDIAN, &(lininfo.id));

        proto_tree_add_item(lin_tree, hf_lin_checksum, tvb, 6, 1, ENC_BIG_ENDIAN);
    }
    proto_tree_add_bitmask(lin_tree, tvb, 7, hf_lin_err_errors, ett_errors, error_fields, ENC_BIG_ENDIAN);

    col_add_fstr(pinfo->cinfo, COL_INFO, "LIN %s", val_to_str(msg_type, lin_msg_type_names, "(0x%02x)"));

    switch (msg_type) {
    case LIN_MSG_TYPE_EVENT: {
        guint event_id;
        proto_tree_add_item_ret_uint(lin_tree, hf_lin_event_id, tvb, 8, 4, ENC_BIG_ENDIAN, &event_id);
        col_append_fstr(pinfo->cinfo, COL_INFO, ": %s", val_to_str(event_id, lin_event_type_names, "0x%08x"));
        proto_item_set_end(ti_root, tvb, 12);
        return 12; /* 8 Byte header + 4 Byte payload */
        }
        break;
    case LIN_MSG_TYPE_FRAME:
        if (payload_length > 0) {
            next_tvb = tvb_new_subset_length(tvb, 8, payload_length);
            lininfo.len = payload_length;
            if (!dissector_try_uint_new(subdissector_table, lininfo.id, next_tvb, pinfo, tree, TRUE, &lininfo)) {
                if (!dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &heur_dtbl_entry, &lininfo)) {
                    call_data_dissector(next_tvb, pinfo, tree);
                }
            }
        }
        break;
    }

    /* format pads to 4 bytes*/
    if (payload_length <= 4) {
        proto_item_set_end(ti_root, tvb, 12);
        return 12;
    } else if (payload_length <= 8) {
        proto_item_set_end(ti_root, tvb, 16);
        return 16;
    } else {
        return tvb_captured_length(tvb);
    }
}

void
proto_register_lin(void) {
    //module_t *lin_module;

    static hf_register_info hf[] = {
        { &hf_lin_msg_format_rev,
            { "Message Format Revision", "lin.message_format",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_lin_reserved1,
            { "Reserved", "lin.reserved",
            FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_lin_payload_length,
            { "Length", "lin.length",
            FT_UINT8, BASE_DEC, NULL, 0xf0, NULL, HFILL }},
        { &hf_lin_message_type,
            { "Message Type", "lin.message_type",
            FT_UINT8, BASE_DEC, VALS(lin_msg_type_names), 0x0c, NULL, HFILL }},
        { &hf_lin_checksum_type,
            { "Checksum Type", "lin.checksum_type",
            FT_UINT8, BASE_DEC, VALS(lin_checksum_type_names), 0x03, NULL, HFILL }},
        { &hf_lin_pid,
            { "Protected ID", "lin.protected_id",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_lin_id,
            { "Frame ID", "lin.frame_id",
            FT_UINT8, BASE_HEX_DEC, NULL, 0x3f, NULL, HFILL }},
        { &hf_lin_parity,
            { "Parity", "lin.frame_parity",
            FT_UINT8, BASE_HEX_DEC, NULL, 0xc0, NULL, HFILL }},
        { &hf_lin_checksum,
            { "Checksum", "lin.checksum",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_lin_err_errors,
            { "Errors", "lin.errors",
            FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_lin_err_no_slave_response,
            { "No Slave Response Error", "lin.errors.no_slave_response",
            FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL }},
        { &hf_lin_err_framing,
            { "Framing Error", "lin.errors.framing_error",
            FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL }},
        { &hf_lin_err_parity,
            { "Parity Error", "lin.errors.parity_error",
            FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL }},
        { &hf_lin_err_checksum,
            { "Checksum Error", "lin.errors.checksum_error",
            FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL }},
        { &hf_lin_err_invalidid,
            { "Invalid ID Error", "lin.errors.invalid_id_error",
            FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL }},
        { &hf_lin_err_overflow,
            { "Overflow Error", "lin.errors.overflow_error",
            FT_BOOLEAN, 8, NULL, 0x20, NULL, HFILL }},
        { &hf_lin_event_id,
            { "Event ID", "lin.event_id",
            FT_UINT32, BASE_HEX_DEC, VALS(lin_event_type_names), 0x00, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_lin,
        &ett_lin_pid,
        &ett_errors,
    };

    proto_lin = proto_register_protocol(LIN_NAME_LONG, LIN_NAME, LIN_NAME_FILTER);
    //lin_module = prefs_register_protocol(proto_lin, NULL);

    proto_register_field_array(proto_lin, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector(LIN_NAME_FILTER, dissect_lin, proto_lin);

    subdissector_table = register_dissector_table("lin.frame_id", "LIN Frame ID", proto_lin, FT_UINT8, BASE_HEX);
    heur_subdissector_list = register_heur_dissector_list(LIN_NAME_FILTER, proto_lin);
}

void
proto_reg_handoff_lin(void) {
    static dissector_handle_t lin_handle;
    lin_handle = create_dissector_handle(dissect_lin, proto_lin);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_LIN, lin_handle);
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
