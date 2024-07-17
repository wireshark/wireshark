/* packet-lls.c
 * Routines for ATSC3 LLS(Low Level Signalling) dissection
 * Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * ATSC3 Signaling, Delivery, Synchronization, and Error Protection (A/331)
 * https://www.atsc.org/atsc-documents/3312017-signaling-delivery-synchronization-error-protection/
 *
 * ATSC3 Security and Service Protection (A/360)
 * https://www.atsc.org/atsc-documents/3602018-atsc-3-0-security-service-protection/
 *
 * ATSC Code Point Registry
 * https://www.atsc.org/documents/code-point-registry/
 */

#include <config.h>
#include <epan/expert.h>
#include <epan/packet.h>

#include "packet-lls.h"

#define LLS_PORT 4937 // IANA Registered (atsc-mh-ssc)

void proto_reg_handoff_lls(void);
void proto_register_lls(void);

static int proto_lls;
static int ett_lls;
static int ett_lls_smt_entry;
static int ett_lls_smt_signature;
static int ett_lls_table_payload;
static int ett_lls_table_payload_xml;

static dissector_handle_t lls_handle;
static dissector_handle_t xml_handle;
static dissector_handle_t cms_handle;

static expert_field ei_lls_table_decompression_failed;

static int hf_lls_table_id;
#define LLS_TABLE_TYPE_SIGNED_MULTI_TABLE 0xFE
#define LLS_TABLE_TYPE_SLT                0x01
static const value_string hf_lls_table_type_vals[] = {
    { 0x01, "SLT (Service List Table)" },
    { 0x02, "RRT (Rating Region Table)" },
    { 0x03, "System Time" },
    { 0x04, "AEAT (Advanced Emergency Information Table)" },
    { 0x05, "On Screen Message Notification" },
    { 0x06, "CDT (Certification Data Table)" },
    { 0x07, "DRCT (Dedicated Return Channel Table)" },
    { 0x80, "VIT (Version Information Table)" },
    { 0x81, "CPT (Content Protection Table)" },
    { 0x82, "CAP (Common Alerting Protocol)" },
    { 0xFE, "Signed Multi Table" },
    { 0xFF, "User Defined" },
    { 0x00, NULL }
};
static const value_string hf_lls_table_type_short_vals[] = {
    { 0x01, "SLT" },
    { 0x02, "RRT" },
    { 0x03, "ST" },
    { 0x04, "AEAT" },
    { 0x05, "OSMN" },
    { 0x06, "CDT" },
    { 0x07, "DRCT" },
    { 0x80, "VIT" },
    { 0x81, "CPT" },
    { 0x82, "CAP" },
    { 0xFE, "SMT" },
    { 0xFF, "USD" },
    { 0x00, NULL }
};

static int hf_lls_group_id;
static int hf_lls_group_count;
static int hf_lls_table_version;
static int hf_lls_table_payload;
static int hf_lls_table_payload_uncompressed;

static int hf_lls_smt_payload_count;
static int hf_lls_smt_entry;
static int hf_lls_smt_entry_payload_length;
static int hf_lls_smt_signature_length;
static int hf_lls_smt_signature;


static void
dissect_lls_table_payload(uint8_t lls_table_id, tvbuff_t *tvb, packet_info *pinfo, int offset, int len, proto_tree *tree)
{
    proto_item *ti = proto_tree_add_item(tree, hf_lls_table_payload, tvb, offset, len, ENC_NA);

    if (lls_table_id == LLS_TABLE_TYPE_SIGNED_MULTI_TABLE) {
        /* Nested SignedMultiTable decoding is not specified in the standard */
        return;
    }

    proto_tree *uncompress_tree = proto_item_add_subtree(ti, ett_lls_table_payload);
    tvbuff_t *uncompress_tvb = tvb_uncompress_zlib(tvb, offset, len);
    proto_tree *xml_tree = NULL;
    if (uncompress_tvb) {
        const char *table_type_short = val_to_str_const(lls_table_id, hf_lls_table_type_short_vals, "Unknown");
        char *source_name = wmem_strdup_printf(pinfo->pool, "Table ID %u (%s)", lls_table_id, table_type_short);
        add_new_data_source(pinfo, uncompress_tvb, source_name);
        unsigned decomp_length = tvb_captured_length(uncompress_tvb);

        proto_item *ti_uncomp = proto_tree_add_item(uncompress_tree, hf_lls_table_payload_uncompressed, uncompress_tvb, 0, decomp_length, ENC_ASCII);
        proto_item_set_generated(ti_uncomp);

        if (xml_handle) {
            xml_tree = proto_item_add_subtree(ti_uncomp, ett_lls_table_payload_xml);
            call_dissector(xml_handle, uncompress_tvb, pinfo, xml_tree);
        }
    } else {
        expert_add_info(pinfo, ti, &ei_lls_table_decompression_failed);
    }

    if (lls_table_id == LLS_TABLE_TYPE_SLT && xml_tree != NULL) {
        lls_extract_save_slt_table(pinfo, xml_handle);
    }
}


static int
dissect_lls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "LLS");

    proto_item *ti = proto_tree_add_item(tree, proto_lls, tvb, 0, -1, ENC_NA);
    proto_tree *lls_tree = proto_item_add_subtree(ti, ett_lls);

    int offset = 0;

    uint8_t lls_table_id = tvb_get_uint8(tvb, offset);
    col_set_str(pinfo->cinfo, COL_INFO, val_to_str_const(lls_table_id, hf_lls_table_type_vals, "Unknown"));
    proto_tree_add_item(lls_tree, hf_lls_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(lls_tree, hf_lls_group_id, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    uint16_t lls_group_count = tvb_get_uint8(tvb, offset) + 1;
    PROTO_ITEM_SET_GENERATED(
        proto_tree_add_uint(lls_tree, hf_lls_group_count, tvb, offset, 1, lls_group_count)
    );
    offset++;

    proto_tree_add_item(lls_tree, hf_lls_table_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    if (lls_table_id == LLS_TABLE_TYPE_SIGNED_MULTI_TABLE) {
        uint8_t smt_payload_count = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(lls_tree, hf_lls_smt_payload_count, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        for(uint8_t i = 0; i < smt_payload_count; i++) {
            uint16_t smt_entry_payload_length = tvb_get_uint16(tvb, offset + 2, ENC_BIG_ENDIAN);
            proto_item *smt_entry_item = proto_tree_add_item(lls_tree, hf_lls_smt_entry, tvb, offset, smt_entry_payload_length + 4, ENC_NA);
            proto_tree *smt_entry_tree = proto_item_add_subtree(smt_entry_item, ett_lls_smt_entry);

            uint8_t smt_entry_table_id = tvb_get_uint8(tvb, offset);
            const char *table_type_short = val_to_str_const(smt_entry_table_id, hf_lls_table_type_short_vals, "Unknown");
            proto_item_append_text(smt_entry_item, " (%u) Table ID=%u (%s)", i, smt_entry_table_id, table_type_short);
            col_append_fstr(pinfo->cinfo, COL_INFO, "/%s", table_type_short);
            proto_tree_add_item(smt_entry_tree, hf_lls_table_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(smt_entry_tree, hf_lls_table_version, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;

            proto_tree_add_item(smt_entry_tree, hf_lls_smt_entry_payload_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;

            dissect_lls_table_payload(smt_entry_table_id, tvb, pinfo, offset, smt_entry_payload_length, smt_entry_tree);
            offset += smt_entry_payload_length;
        }

        uint16_t smt_signature_length = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
        proto_tree_add_item(lls_tree, hf_lls_smt_signature_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        proto_item *smt_signature_item = proto_tree_add_item(lls_tree, hf_lls_smt_signature, tvb, offset, smt_signature_length, ENC_NA);
        if (cms_handle) {
            proto_tree *cms_tree = proto_item_add_subtree(smt_signature_item, ett_lls_smt_signature);
            tvbuff_t *cms_tvb = tvb_new_subset_length(tvb, offset, smt_signature_length);

            /* CMS dissector removes useful info from Protocol and Info columns so store it */
            char *col_info_text = wmem_strdup(pinfo->pool, col_get_text(pinfo->cinfo, COL_INFO));
            char *col_protocol_text = wmem_strdup(pinfo->pool, col_get_text(pinfo->cinfo, COL_PROTOCOL));

            call_dissector(cms_handle, cms_tvb, pinfo, cms_tree);

            /* Restore Protocol and Info columns */
            col_set_str(pinfo->cinfo, COL_INFO, col_info_text);
            col_set_str(pinfo->cinfo, COL_PROTOCOL, col_protocol_text);
        }
    } else {
        int table_payload_length = tvb_captured_length(tvb) - 4;
        dissect_lls_table_payload(lls_table_id, tvb, pinfo, offset, table_payload_length, lls_tree);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_lls(void)
{
    static hf_register_info hf[] = {
        { &hf_lls_table_id, {
            "Table ID", "lls.table.id",
            FT_UINT8, BASE_DEC, VALS(hf_lls_table_type_vals), 0, NULL, HFILL
        } },
        { &hf_lls_group_id, {
            "Group ID", "lls.group.id",
            FT_UINT8, BASE_DEC, 0, 0, NULL, HFILL
        } },
        { &hf_lls_group_count, {
            "Group Count", "lls.group.count",
            FT_UINT16, BASE_DEC, 0, 0, NULL, HFILL
        } },
        { &hf_lls_table_version, {
            "Table Version", "lls.table.version",
            FT_UINT8, BASE_DEC, 0, 0, NULL, HFILL
        } },
        { &hf_lls_table_payload, {
            "Table Payload", "lls.table.payload",
            FT_NONE, BASE_NONE, 0, 0, NULL, HFILL
        } },
        { &hf_lls_table_payload_uncompressed, {
            "Table Payload Uncompressed", "lls.table.payload.uncompressed",
            FT_STRING, BASE_NONE, 0, 0, NULL, HFILL
        } },


        { &hf_lls_smt_payload_count, {
            "Signed Multi Table Payload Count", "lls.smt.payload_count",
            FT_UINT8, BASE_DEC, 0, 0, NULL, HFILL
        } },
        { &hf_lls_smt_entry, {
            "Signed Multi Table Entry", "lls.smt.entry",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
        } },

        { &hf_lls_smt_entry_payload_length, {
            "Payload Length", "lls.smt.entry.payload_length",
            FT_UINT16, BASE_DEC, 0, 0, NULL, HFILL
        } },

        { &hf_lls_smt_signature_length, {
            "Signed Multi Table Signature Length", "lls.smt.signature_length",
            FT_UINT16, BASE_DEC, 0, 0, NULL, HFILL
        } },
        { &hf_lls_smt_signature, {
            "Signed Multi Table Signature", "lls.smt.signature",
            FT_NONE, BASE_NONE, 0, 0, NULL, HFILL
        } },
    };

    static int *ett[] = {
        &ett_lls,
        &ett_lls_smt_entry,
        &ett_lls_table_payload,
        &ett_lls_table_payload_xml,
        &ett_lls_smt_signature,
    };

    static ei_register_info ei[] = {
        { &ei_lls_table_decompression_failed,
          { "lls.table.decompression.failed", PI_MALFORMED, PI_ERROR,
            "LLS table payload decompression failed",
            EXPFILL }
        },
    };

    proto_lls = proto_register_protocol("ATSC3 Low Level Signalling", "LLS", "lls");

    expert_module_t *expert_lls = expert_register_protocol(proto_lls);
    expert_register_field_array(expert_lls, ei, array_length(ei));

    proto_register_field_array(proto_lls, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_lls(void)
{
    lls_handle = create_dissector_handle(dissect_lls, proto_lls);
    xml_handle = find_dissector_add_dependency("xml", proto_lls);
    cms_handle = find_dissector_add_dependency("cms", proto_lls);
    dissector_add_uint_with_preference("udp.port", LLS_PORT, lls_handle);

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
