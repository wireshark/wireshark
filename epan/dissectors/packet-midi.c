/* packet-midi.c
 *
 * MIDI SysEx dissector
 * Tomasz Mon 2012
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#include "config.h"

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <packet-midi-sysex-id.h>

void proto_register_sysex(void);
void proto_reg_handoff_sysex(void);

/* protocols and header fields */
static int proto_sysex;
static int hf_sysex_message_start;
static int hf_sysex_manufacturer_id;
static int hf_sysex_three_byte_manufacturer_id;
static int hf_sysex_message_eox;

static int ett_sysex;

static dissector_table_t sysex_manufacturer_dissector_table;

static dissector_handle_t sysex_digitech_handle;

static expert_field ei_sysex_message_start_byte;
static expert_field ei_sysex_message_end_byte;
static expert_field ei_sysex_undecoded;

/* dissector for System Exclusive MIDI data */
static int
dissect_sysex_command(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
    uint8_t sysex_helper;
    int data_len;
    proto_item *item;
    proto_item *ti = NULL;
    proto_tree *tree = NULL;
    int offset = 0;
    int manufacturer_payload_len;
    uint8_t manufacturer_id;
    uint32_t three_byte_manufacturer_id = 0xFFFFFF;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "SYSEX");
    col_set_str(pinfo->cinfo, COL_INFO, "MIDI System Exclusive Command");

    data_len = tvb_reported_length(tvb);

    ti = proto_tree_add_protocol_format(parent_tree, proto_sysex, tvb, 0, -1, "MIDI System Exclusive Command");
    tree = proto_item_add_subtree(ti, ett_sysex);

    /* Check start byte (System Exclusive - 0xF0) */
    sysex_helper = tvb_get_uint8(tvb, 0);
    item = proto_tree_add_item(tree, hf_sysex_message_start, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (sysex_helper != 0xF0)
    {
        expert_add_info(pinfo, item, &ei_sysex_message_start_byte);
    }

    offset++;

    manufacturer_id = tvb_get_uint8(tvb, offset);
    /* Three-byte manufacturer ID starts with 00 */
    if (manufacturer_id == 0)
    {
        three_byte_manufacturer_id = tvb_get_ntoh24(tvb, offset);
        proto_tree_add_item(tree, hf_sysex_three_byte_manufacturer_id, tvb, offset, 3, ENC_BIG_ENDIAN);
        offset += 3;
    }
    /* One-byte manufacturer ID */
    else
    {
        proto_tree_add_item(tree, hf_sysex_manufacturer_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    /* Following data is manufacturer-specific */
    manufacturer_payload_len = data_len - offset - 1;
    if (manufacturer_payload_len > 0)
    {
        tvbuff_t *payload_tvb = tvb_new_subset_length(tvb, offset, manufacturer_payload_len);

        offset += dissector_try_uint(sysex_manufacturer_dissector_table, three_byte_manufacturer_id, payload_tvb, pinfo, parent_tree);
    }

    if (offset < data_len - 1)
    {
        proto_tree_add_expert(tree, pinfo, &ei_sysex_undecoded, tvb, offset, data_len - offset - 1);
    }

    /* Check end byte (EOX - 0xF7) */
    sysex_helper = tvb_get_uint8(tvb, data_len - 1);
    item = proto_tree_add_item(tree, hf_sysex_message_eox, tvb, data_len - 1, 1, ENC_BIG_ENDIAN);
    if (sysex_helper != 0xF7)
    {
        expert_add_info(pinfo, item, &ei_sysex_message_end_byte);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_sysex(void)
{
    static hf_register_info hf[] = {
        { &hf_sysex_message_start,
            { "SysEx message start", "sysex.start", FT_UINT8, BASE_HEX,
              NULL, 0, "System Exclusive Message start (0xF0)", HFILL }},
        { &hf_sysex_manufacturer_id,
            { "Manufacturer ID", "sysex.manufacturer_id", FT_UINT8, BASE_HEX|BASE_EXT_STRING,
              &midi_sysex_id_vals_ext, 0, NULL, HFILL }},
        { &hf_sysex_three_byte_manufacturer_id,
            { "Manufacturer ID", "sysex.manufacturer_id", FT_UINT24, BASE_HEX|BASE_EXT_STRING,
              &midi_sysex_extended_id_vals_ext, 0, NULL, HFILL }},
        { &hf_sysex_message_eox,
            { "EOX", "sysex.eox", FT_UINT8, BASE_HEX,
              NULL, 0, "System Exclusive Message end (0xF7)", HFILL}},
    };

    static int *ett[] = {
        &ett_sysex
    };

    static ei_register_info ei[] = {
        { &ei_sysex_message_start_byte, { "sysex.message_start_byte", PI_PROTOCOL, PI_WARN, "SYSEX Error: Wrong start byte", EXPFILL }},
        { &ei_sysex_message_end_byte, { "sysex.message_end_byte", PI_PROTOCOL, PI_WARN, "SYSEX Error: Wrong end byte", EXPFILL }},
        { &ei_sysex_undecoded, { "sysex.undecoded", PI_UNDECODED, PI_WARN, "Not dissected yet (report to wireshark.org)", EXPFILL }},
    };

    expert_module_t* expert_sysex;

    proto_sysex = proto_register_protocol("MIDI System Exclusive", "SYSEX", "sysex");
    proto_register_field_array(proto_sysex, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_sysex = expert_register_protocol(proto_sysex);
    expert_register_field_array(expert_sysex, ei, array_length(ei));

    sysex_manufacturer_dissector_table = register_dissector_table("sysex.manufacturer",
        "SysEx manufacturer", proto_sysex, FT_UINT24, BASE_HEX);

    register_dissector("sysex", dissect_sysex_command, proto_sysex);
}

void
proto_reg_handoff_sysex(void)
{
    sysex_digitech_handle = find_dissector_add_dependency("sysex_digitech", proto_sysex);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
