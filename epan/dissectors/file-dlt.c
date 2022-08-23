/* file-dlt.c
 * DLT File Format.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2022-2022 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This dissector allows to parse DLT files.
 */

 /*
  * Sources for specification:
  * https://www.autosar.org/fileadmin/user_upload/standards/classic/21-11/AUTOSAR_SWS_DiagnosticLogAndTrace.pdf
  * https://www.autosar.org/fileadmin/user_upload/standards/foundation/21-11/AUTOSAR_PRS_LogAndTraceProtocol.pdf
  * https://github.com/COVESA/dlt-viewer
  */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/exceptions.h>
#include <epan/show_exception.h>
#include <epan/wmem_scopes.h>
#include <wiretap/autosar_dlt.h>

static int proto_dlt = -1;

static int hf_dlt_file_magic = -1;
static int hf_dlt_file_tstamp_s = -1;
static int hf_dlt_file_tstamp_us = -1;
static int hf_dlt_file_ecuid = -1;

static int hf_dlt_file_header_type = -1;
static int hf_dlt_file_message_counter = -1;
static int hf_dlt_file_length = -1;
static int hf_dlt_file_data = -1;

static gint ett_dlt = -1;
static gint ett_dlt_item = -1;

void proto_register_file_dlt(void);
void proto_reg_handoff_file_dlt(void);

#define MAGIC_NUMBER_SIZE 4
static const guint8 dlt_file_magic[MAGIC_NUMBER_SIZE] = { 'D', 'L', 'T', 0x01 };

static int
dissect_dlt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    volatile gint    offset = 0;
    proto_tree      *dlt_tree;
    proto_tree      *item_tree;
    proto_item      *ti;
    proto_item      *ti_item;
    guint32          len = 0;

    if (tvb_captured_length(tvb) < 16 || tvb_memeql(tvb, 0, dlt_file_magic, MAGIC_NUMBER_SIZE) != 0) {
        /* does not start with DLT\x1, so this is not DLT it seems */
        return 0;
    }

    ti = proto_tree_add_item(tree, proto_dlt, tvb, offset, -1, ENC_NA);
    dlt_tree = proto_item_add_subtree(ti, ett_dlt);

    gint tvb_length = tvb_captured_length(tvb);

    while (offset + 20 <= tvb_length) {
        item_tree = proto_tree_add_subtree_format(dlt_tree, tvb, offset, -1, ett_dlt_item, &ti_item, "DLT Log Line");
        proto_tree_add_item(item_tree, hf_dlt_file_magic, tvb, offset, 4, ENC_ASCII | ENC_NA);
        offset += 4;

        guint32 tstamp_s = 0;
        proto_tree_add_item_ret_uint(item_tree, hf_dlt_file_tstamp_s, tvb, offset, 4, ENC_LITTLE_ENDIAN, &tstamp_s);
        offset += 4;

        guint32 tstamp_us = 0;
        proto_tree_add_item_ret_uint(item_tree, hf_dlt_file_tstamp_us, tvb, offset, 4, ENC_LITTLE_ENDIAN, &tstamp_us);
        offset += 4;

        const guint8 *ecuid;
        proto_tree_add_item_ret_string(item_tree, hf_dlt_file_ecuid, tvb, offset, 4, ENC_ASCII | ENC_NA, pinfo->pool, &ecuid);
        offset += 4;

        proto_tree_add_item(item_tree, hf_dlt_file_header_type, tvb, offset, 1, ENC_NA);
        offset += 1;

        guint counter = 0;
        proto_tree_add_item_ret_uint(item_tree, hf_dlt_file_message_counter, tvb, offset, 1, ENC_NA, &counter);
        offset += 1;

        proto_tree_add_item_ret_uint(item_tree, hf_dlt_file_length, tvb, offset, 2, ENC_BIG_ENDIAN, &len);
        offset += 2;

        proto_tree_add_item(item_tree, hf_dlt_file_data, tvb, offset, len - 4, ENC_NA);
        offset += (len - 4);

        proto_item_set_end(ti_item, tvb, offset);
        proto_item_append_text(ti_item, " %3u %u.%06u ECU:%s Len:%u", counter, tstamp_s, tstamp_us, ecuid, len);
    }

    return offset;
}

static gboolean
dissect_dlt_heur(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
    return dissect_dlt(tvb, pinfo, tree, NULL) > 0;
}

void
proto_register_file_dlt(void) {
    static hf_register_info hf[] = {
        { &hf_dlt_file_magic,
            { "Magic", "file-dlt.magic", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_dlt_file_tstamp_s,
            { "Timestamp s", "file-dlt.timestamp_s", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dlt_file_tstamp_us,
            { "Timestamp us", "file-dlt.timestamp_us", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dlt_file_ecuid,
            { "ECU ID", "file-dlt.ecu_id", FT_STRING, BASE_NONE, NULL, 0x00, NULL, HFILL }},

        { &hf_dlt_file_header_type,
            { "Header Type", "file-dlt.header_type", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_dlt_file_message_counter,
            { "Message Counter", "file-dlt.msg_counter", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dlt_file_length,
            { "Length", "file-dlt.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dlt_file_data,
            { "Data", "file-dlt.data", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_dlt,
        &ett_dlt_item,
    };

    proto_dlt = proto_register_protocol("DLT File Format", "File-DLT", "file-dlt");
    proto_register_field_array(proto_dlt, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("file-dlt", dissect_dlt, proto_dlt);
}

void
proto_reg_handoff_file_dlt(void) {
    heur_dissector_add("wtap_file", dissect_dlt_heur, "DLT File", "dlt_wtap", proto_dlt, HEURISTIC_ENABLE);
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
