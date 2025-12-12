/* packet-dect-nr-tap.c
 * https://github.com/DSRCorporation/dect-nr-tap
 * Routines for DECT NR+ TAP protocol dissection
 * Copyright 2025 DSR Corporation, http://dsr-wireless.com/
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "packet-dect-nr.h"

#define WS_LOG_DOMAIN "dect_nr_tap"

#include <wireshark.h>

#include <wiretap/wtap.h>
#include <wsutil/pint.h>

#include <epan/packet.h>
#include <epan/expert.h>

static int proto_dect_nr_tap;
static expert_field ei_dect_nr_tap_unknown_tlv;
static expert_field ei_dect_nr_tap_tlv_length_invalid;
static expert_field ei_dect_nr_tap_header_status_invalid;

static dissector_handle_t dect_nr_tap_handle;
static dissector_handle_t dect_nr_handle;

static int hf_dect_nr_tap_header;
static int hf_dect_nr_tap_header_version;
static int hf_dect_nr_tap_header_reserved1;
static int hf_dect_nr_tap_header_tlvs_length;
static int hf_dect_nr_tap_header_length;
static int hf_dect_nr_tap_header_reserved2;

static int hf_dect_nr_tap_tlv_element;
static int hf_dect_nr_tap_tlv_element_type;
static int hf_dect_nr_tap_tlv_element_length;
static int hf_dect_nr_tap_tlv_element_value;

static int hf_dect_nr_tap_tlv_element_data_type;
static int hf_dect_nr_tap_tlv_element_header_status;
static int hf_dect_nr_tap_tlv_element_pcc_rssi2;
static int hf_dect_nr_tap_tlv_element_pcc_snr;
static int hf_dect_nr_tap_tlv_element_pdc_rssi2;
static int hf_dect_nr_tap_tlv_element_pdc_snr;
static int hf_dect_nr_tap_tlv_element_transaction_id;
static int hf_dect_nr_tap_tlv_element_channel;
static int hf_dect_nr_tap_tlv_element_simul_trace_string_number;
static int hf_dect_nr_tap_tlv_element_padding;

static int ett_dect_nr_tap;
static int ett_dect_nr_tap_header;
static int ett_dect_nr_tap_header_tlv;

#define CUSTOM_HEADER_SIZE (8)
#define TLV_LENGTH (8)
#define TLV_NUMBER (8)

#define DN_UNKNOWN_STRING                 "Unknown"

/* A sample #define of the minimum length (in bytes) of the protocol data.
 * If data is received with fewer than this many bytes it is rejected by
 * the current dissector. */
#define dect_nr_tap_MIN_LENGTH (CUSTOM_HEADER_SIZE + TLV_LENGTH * TLV_NUMBER)

#define TLV_TYPE_DATA_TYPE                 (1)
#define TLV_TYPE_HEADER_STATUS             (2)
#define TLV_TYPE_PCC_RSSI2                 (3)
#define TLV_TYPE_PCC_SNR                   (4)
#define TLV_TYPE_PDC_RSSI2                 (5)
#define TLV_TYPE_PDC_SNR                   (6)
#define TLV_TYPE_TRANSACTION_ID            (7)
#define TLV_TYPE_CHANNEL                   (8)
#define TLV_TYPE_SIMUL_TRACE_STRING_NUMBER (9)

static const value_string dect_nr_tap_tlv_type_val[] = {
    {TLV_TYPE_DATA_TYPE,                 "Data type"},
    {TLV_TYPE_HEADER_STATUS,             "Header status"},
    {TLV_TYPE_PCC_RSSI2,                 "PCC RSSI2"},
    {TLV_TYPE_PCC_SNR,                   "PCC SNR"},
    {TLV_TYPE_PDC_RSSI2,                 "PDC RSSI2"},
    {TLV_TYPE_PDC_SNR,                   "PDC SNR"},
    {TLV_TYPE_TRANSACTION_ID,            "Transaction ID"},
    {TLV_TYPE_CHANNEL,                   "Channel"},
    {TLV_TYPE_SIMUL_TRACE_STRING_NUMBER, "Simul trace string number"},
    { 0, NULL }
};

#define PHY_LAYER_CONTROL_FIELD_40BIT        (1)
#define PHY_LAYER_CONTROL_FIELD_80BIT        (2)
#define PHY_LAYER_CONTROL_FIELD_40BIT_NO_PDC (3)
#define PHY_LAYER_CONTROL_FIELD_80BIT_NO_PDC (4)
#define PHY_LAYER_CONTROL_FIELD_NO_PCC_PDC   (5)

static const value_string dect_nr_tap_tlv_data_type_val[] = {
    {PHY_LAYER_CONTROL_FIELD_40BIT,        "PCC length is 40 bits"},
    {PHY_LAYER_CONTROL_FIELD_80BIT,        "PCC length is 80 bits"},
    {PHY_LAYER_CONTROL_FIELD_40BIT_NO_PDC, "PCC length is 40 bits, PDC bytes is absent due to PDC CRC error"},
    {PHY_LAYER_CONTROL_FIELD_80BIT_NO_PDC, "PCC length is 80 bits, PDC bytes is absent due to PDC CRC error"},
    {PHY_LAYER_CONTROL_FIELD_NO_PCC_PDC,   "PCC CRC error, neither PCC nor PDC bytes are included"},
    { 0, NULL }
};

#define HEADER_STATUS_VALID        (0)
#define HEADER_STATUS_INVALID      (1)
#define HEADER_STATUS_VALID_NO_PDC (2)

static const value_string dect_nr_tap_tlv_header_status_val[] = {
    {HEADER_STATUS_VALID,        "Valid, PDC bytes are included in packet"},
    {HEADER_STATUS_INVALID,      "Invalid, PDC bytes are absent"},
    {HEADER_STATUS_VALID_NO_PDC, "Valid, but RX operation ends before PDC reception, PDC bytes are absent"},
    { 0, NULL }
};



/*
 * Convert RSSI2 code to string.
 *
 *@param buf output string
 *@param value RSSI2 code
*/
static void
rssi2_hex2dbm(char *buf, int16_t value)
{
    /*
       Values are in dBm with 0.5 dBm resolution (Q14.1).
       For example, -87 is -43.5 dbm,  -84 is -42,0 dbm.
    */
    snprintf(buf, ITEM_LABEL_LENGTH, "%i.%i dBm", value/2, abs(value)%2 * 5);
}

/*
 * Convert SNR code to string.
 *
 *@param buf output string
 *@param value SNR code
*/
static void
snr_hex2dbm(char *buf, int16_t value)
{
    /* Values are dB values with 0.25 dB resolution (Q13.2) */
    snprintf(buf, ITEM_LABEL_LENGTH, "%i.%i dB", value/4, abs(value)%4 * 25);
}


/*
 * TLV parser.
 *
 *@param parent_tree parrent tree pointer
 *@param tvb pointer to buffer containing raw packet.
 *@param offset into the tvb to begin dissection
 *@param[out] data_type Indicates the length of PCC bytes and presence of PDC data
 *@return tlv length.
*/
static int process_tlv(proto_tree *parent_tree, tvbuff_t *tvb, packet_info *pinfo, uint32_t offset, uint32_t *data_type)
{
    uint16_t padding_length = 4; /* TLV value size = 4 */
    proto_item *ti;
    proto_tree *tree;

    ti = proto_tree_add_item(parent_tree, hf_dect_nr_tap_tlv_element, tvb, offset, TLV_LENGTH, ENC_NA);
    tree = proto_item_add_subtree(ti, ett_dect_nr_tap_header_tlv);

    uint16_t type;
    proto_tree_add_item_ret_uint16(tree, hf_dect_nr_tap_tlv_element_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, &type);
    offset += 2;

    uint16_t length;
    proto_tree_add_item_ret_uint16(tree, hf_dect_nr_tap_tlv_element_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &length);
    offset += 2;

    if (length > 4)
    {
        expert_add_info(pinfo, ti, &ei_dect_nr_tap_tlv_length_invalid);
        length = 4;
    }
    padding_length -= length;

    proto_item_set_text(ti, "%s", val_to_str_const(type, dect_nr_tap_tlv_type_val, DN_UNKNOWN_STRING));

    switch(type) {
        case TLV_TYPE_DATA_TYPE: {
            proto_tree_add_item_ret_uint(tree, hf_dect_nr_tap_tlv_element_data_type, tvb, offset, 2, ENC_LITTLE_ENDIAN, data_type);
            proto_item_append_text(ti, ": %s", val_to_str_const(*data_type, dect_nr_tap_tlv_data_type_val, DN_UNKNOWN_STRING));
            offset += 2;
            break;
        }

        case TLV_TYPE_HEADER_STATUS: {
            uint32_t status;

            proto_tree_add_item_ret_uint(tree, hf_dect_nr_tap_tlv_element_header_status, tvb, offset, 2, ENC_LITTLE_ENDIAN, &status);
            proto_item_append_text(ti, ": %s", val_to_str_const(status, dect_nr_tap_tlv_header_status_val, "Failed"));
            offset += 2;
            if (status != HEADER_STATUS_VALID) {
                expert_add_info(pinfo, ti, &ei_dect_nr_tap_header_status_invalid);
            }
            break;
        }

        case TLV_TYPE_PCC_RSSI2: {
            int32_t pcc_rssi2;
            char buf[ITEM_LABEL_LENGTH] = {0};

            proto_tree_add_item_ret_int(tree, hf_dect_nr_tap_tlv_element_pcc_rssi2, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pcc_rssi2);
            rssi2_hex2dbm(buf, (int16_t) pcc_rssi2);
            proto_item_append_text(ti, ": %s", buf);
            offset += 2;
            break;
        }

        case TLV_TYPE_PCC_SNR: {
            int32_t pcc_snr;
            char buf[ITEM_LABEL_LENGTH] = {0};

            proto_tree_add_item_ret_int(tree, hf_dect_nr_tap_tlv_element_pcc_snr, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pcc_snr);
            snr_hex2dbm(buf, (int16_t) pcc_snr);
            proto_item_append_text(ti, ": %s", buf);
            offset += 2;
            break;
        }

        case TLV_TYPE_PDC_RSSI2: {
            int32_t pdc_rssi2;
            char buf[ITEM_LABEL_LENGTH] = {0};

            proto_tree_add_item_ret_int(tree, hf_dect_nr_tap_tlv_element_pdc_rssi2, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pdc_rssi2);
            rssi2_hex2dbm(buf, (int16_t) pdc_rssi2);
            proto_item_append_text(ti, ": %s", buf);
            offset += 2;
            break;
        }

        case TLV_TYPE_PDC_SNR: {
            int32_t pdc_snr;
            char buf[ITEM_LABEL_LENGTH] = {0};

            proto_tree_add_item_ret_int(tree, hf_dect_nr_tap_tlv_element_pdc_snr, tvb, offset, 2, ENC_LITTLE_ENDIAN, &pdc_snr);
            snr_hex2dbm(buf, (int16_t) pdc_snr);
            proto_item_append_text(ti, ": %s", buf);
            offset += 2;
            break;
        }

        case TLV_TYPE_TRANSACTION_ID: {
            uint32_t transaction_id;

            proto_tree_add_item_ret_uint(tree, hf_dect_nr_tap_tlv_element_transaction_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &transaction_id);
            proto_item_append_text(ti, ": %u", transaction_id);
            offset += 2;
            break;
        }

        case TLV_TYPE_CHANNEL: {
            uint32_t channel;

            proto_tree_add_item_ret_uint(tree, hf_dect_nr_tap_tlv_element_channel, tvb, offset, 2, ENC_LITTLE_ENDIAN, &channel);
            proto_item_append_text(ti, ": %u", channel);
            offset += 2;
            break;
        }

        case TLV_TYPE_SIMUL_TRACE_STRING_NUMBER: {
            uint32_t num;

            proto_tree_add_item_ret_uint(tree, hf_dect_nr_tap_tlv_element_simul_trace_string_number, tvb, offset, 2, ENC_LITTLE_ENDIAN, &num);
            proto_item_append_text(ti, ": %u", num);
            offset += 4;
            break;
        }

        default:
            /* Unknown TLV */
            proto_tree_add_item(tree, hf_dect_nr_tap_tlv_element_value, tvb, offset, length, ENC_NA);
            offset += length;
            expert_add_info(pinfo, ti, &ei_dect_nr_tap_unknown_tlv);
            break;
    }

    if (padding_length > 0) {
        proto_tree_add_item(tree, hf_dect_nr_tap_tlv_element_padding, tvb, offset, padding_length, ENC_NA);
        offset += padding_length;
    }

    return offset;
}

/*
 * Custom header parser.
 *
 *@param parent_tree parrent tree pointer
 *@param tvb pointer to buffer containing raw packet.
 *@param offset into the tvb to begin dissection
 *@param[out] tlvs_length TLV chain length (bytes)
 *@return custom header length.
*/
static int process_custom_header(proto_tree *parent_tree, tvbuff_t *tvb, uint32_t offset, uint16_t *tlvs_length)
{
    proto_item *ti = proto_tree_add_item(parent_tree, hf_dect_nr_tap_header, tvb, offset, CUSTOM_HEADER_SIZE, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(ti, ett_dect_nr_tap_header);

    proto_tree_add_item(tree, hf_dect_nr_tap_header_version, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* 1 byte reserved */
    proto_tree_add_item(tree, hf_dect_nr_tap_header_reserved1, tvb, offset, 1, ENC_NA);
    offset += 1;

    proto_tree_add_item_ret_uint16(tree, hf_dect_nr_tap_header_tlvs_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, tlvs_length);
    offset += 2;

    proto_tree_add_item(tree, hf_dect_nr_tap_header_length, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    /* 2 byte reserved */
    proto_tree_add_item(tree, hf_dect_nr_tap_header_reserved2, tvb, offset, 2, ENC_NA);
    offset += 2;

    return offset;
}

static int
dissect_dect_nr_tap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
               void *data _U_)
{
    proto_item *ti;
    proto_tree *dect_nr_tap_tree;

    uint32_t offset = 0;
    uint16_t tlvs_length = 0;

    if (tvb_reported_length(tvb) < dect_nr_tap_MIN_LENGTH)
        return 0;

    if (tvb_captured_length(tvb) < 1)
        return 0;

    ti = proto_tree_add_item(tree, proto_dect_nr_tap, tvb, 0, -1, ENC_NA);

    dect_nr_tap_tree = proto_item_add_subtree(ti, ett_dect_nr_tap);

    offset = process_custom_header(dect_nr_tap_tree, tvb, offset, &tlvs_length);
    proto_item_set_len(ti, CUSTOM_HEADER_SIZE + tlvs_length);

    uint32_t tlvs_end = offset + tlvs_length;
    uint32_t data_type = PHY_LAYER_CONTROL_FIELD_40BIT;

    while (offset < tlvs_end) {
        offset = process_tlv(dect_nr_tap_tree, tvb, pinfo, offset, &data_type);
    }

    if (data_type != PHY_LAYER_CONTROL_FIELD_NO_PCC_PDC)
    {
        dect_nr_info_t dect_nr_info = {
            .phf_type = DECT_NR_PHF_TYPE_1
        };

        if (data_type == PHY_LAYER_CONTROL_FIELD_80BIT ||
            data_type == PHY_LAYER_CONTROL_FIELD_80BIT_NO_PDC) {
            dect_nr_info.phf_type = DECT_NR_PHF_TYPE_2;
        }

        tvbuff_t *dect_nr_tvb = tvb_new_subset_remaining(tvb, offset);
        call_dissector_with_data(dect_nr_handle, dect_nr_tvb, pinfo, tree, &dect_nr_info);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_dect_nr_tap(void)
{
    expert_module_t *expert_dect_nr_tap;

    static hf_register_info hf[] = {
        { &hf_dect_nr_tap_header,             { "Header",      "dect_nr_tap.header",             FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_header_version,     { "Version",     "dect_nr_tap.header.version",     FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_header_reserved1,   { "Reserved1",   "dect_nr_tap.header.reserved1",   FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_header_tlvs_length, { "TLVs Length", "dect_nr_tap.header.tlvs_length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}},
        { &hf_dect_nr_tap_header_length,      { "Length",      "dect_nr_tap.header.length",      FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}},
        { &hf_dect_nr_tap_header_reserved2,   { "Reserved2",   "dect_nr_tap.header.reserved2",   FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL}},

        { &hf_dect_nr_tap_tlv_element,        { "TLV element",  "dect_nr_tap.tlv_element",        FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_tlv_element_type,   { "Type",         "dect_nr_tap.tlv_element.type",   FT_UINT16, BASE_DEC, VALS(dect_nr_tap_tlv_type_val), 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_tlv_element_length, { "Length",       "dect_nr_tap.tlv_element.length", FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_tlv_element_value,  { "Value",        "dect_nr_tap.tlv_element.value",  FT_BYTES, SEP_SPACE, NULL, 0x00, NULL, HFILL }},

        { &hf_dect_nr_tap_tlv_element_data_type,                 {"Data type",                 "dect_nr_tap.tlv_element.data_type",                 FT_UINT16, BASE_NONE, VALS(dect_nr_tap_tlv_data_type_val), 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_tlv_element_header_status,             {"Header status",             "dect_nr_tap.tlv_element.header_status",             FT_UINT16, BASE_NONE, VALS(dect_nr_tap_tlv_header_status_val), 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_tlv_element_pcc_rssi2,                 {"PCC RSSI2",                 "dect_nr_tap.tlv_element.pcc_rssi2",                 FT_INT16, BASE_CUSTOM, CF_FUNC(rssi2_hex2dbm), 0x00, "Physical Control Channel RSSI2", HFILL }},
        { &hf_dect_nr_tap_tlv_element_pcc_snr,                   {"PCC SNR",                   "dect_nr_tap.tlv_element.pcc_snr",                   FT_INT16, BASE_CUSTOM, CF_FUNC(snr_hex2dbm), 0x00, "Physical Control Channel SNR", HFILL }},
        { &hf_dect_nr_tap_tlv_element_pdc_rssi2,                 {"PDC RSSI2",                 "dect_nr_tap.tlv_element.pdc_rssi2",                 FT_INT16, BASE_CUSTOM, CF_FUNC(rssi2_hex2dbm), 0x00, "Physical Data Channel RSSI2", HFILL }},
        { &hf_dect_nr_tap_tlv_element_pdc_snr,                   {"PDC SNR",                   "dect_nr_tap.tlv_element.pdc_snr",                   FT_INT16, BASE_CUSTOM, CF_FUNC(snr_hex2dbm), 0x00, "Physical Data Channel SNR", HFILL }},
        { &hf_dect_nr_tap_tlv_element_transaction_id,            {"Transaction ID",            "dect_nr_tap.tlv_element.transaction_id",            FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_tlv_element_channel,                   {"Channel",                   "dect_nr_tap.tlv_element.channel",                   FT_UINT16, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_tlv_element_simul_trace_string_number, {"Simul trace string number", "dect_nr_tap.tlv_element.simul_trace_string_number", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_dect_nr_tap_tlv_element_padding,                   {"Padding", "dect_nr_tap.tlv_element.padding", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_dect_nr_tap,
        &ett_dect_nr_tap_header,
        &ett_dect_nr_tap_header_tlv,
    };

    static ei_register_info ei[] = {
        { &ei_dect_nr_tap_tlv_length_invalid, { "dect_nr_tap.invalid_tlv_length", PI_RESPONSE_CODE, PI_WARN, "Invalid TLV value length", EXPFILL }},
        { &ei_dect_nr_tap_unknown_tlv, { "dect_nr_tap.unknown_tlv", PI_UNDECODED, PI_WARN, "Unknown TLV", EXPFILL }},
        { &ei_dect_nr_tap_header_status_invalid, { "dect_nr_tap.invalid_header_status", PI_RESPONSE_CODE, PI_NOTE, "Invalid header status", EXPFILL }},
    };

    proto_dect_nr_tap = proto_register_protocol("DECT NR+ TAP header", "DECT NR+ TAP", "dect_nr_tap");

    proto_register_field_array(proto_dect_nr_tap, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_dect_nr_tap = expert_register_protocol(proto_dect_nr_tap);
    expert_register_field_array(expert_dect_nr_tap, ei, array_length(ei));

    dect_nr_tap_handle = register_dissector("dect_nr_tap", dissect_dect_nr_tap, proto_dect_nr_tap);
}

void
proto_reg_handoff_dect_nr_tap(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_DECT_NR_TAP, dect_nr_tap_handle);

    dect_nr_handle = find_dissector_add_dependency("dect_nr", proto_dect_nr_tap);
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
