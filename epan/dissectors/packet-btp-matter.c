/* packet-btp-matter.c
 * Routines for Matter Bluetooth Transport Protocol (BTP) dissection
 * Copyright 2024, Arkadiusz Bokowy <a.bokowy@samsung.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * The dissector code is based on Matter Specification Version 1.3, section
 * 4.18. Bluetooth Transport Protocol (BTP).
 *
 * The specification is available at:
 * https://csa-iot.org/wp-content/uploads/2024/05/Matter-1.3-Core-Specification.pdf
 */

#include <config.h>

#include <epan/packet.h>
#include "packet-btatt.h"

void proto_register_btatt_matter(void);
void proto_reg_handoff_btatt_matter(void);

static int proto_matter_btp;
static dissector_handle_t matter_btp_handle;
static dissector_handle_t matter_tlv_handle;

static int hf_matter_btp_flags;
static int hf_matter_btp_flags_handshake;
static int hf_matter_btp_flags_management;
static int hf_matter_btp_flags_acknowledgment;
static int hf_matter_btp_flags_ending;
static int hf_matter_btp_flags_continuing;
static int hf_matter_btp_flags_beginning;
static int hf_matter_btp_opcode;
static int hf_matter_btp_versions;
static int hf_matter_btp_versions_0;
static int hf_matter_btp_versions_1;
static int hf_matter_btp_versions_2;
static int hf_matter_btp_versions_3;
static int hf_matter_btp_versions_4;
static int hf_matter_btp_versions_5;
static int hf_matter_btp_versions_6;
static int hf_matter_btp_versions_7;
static int hf_matter_btp_version;
static int hf_matter_btp_mtu;
static int hf_matter_btp_window_size;
static int hf_matter_btp_ack;
static int hf_matter_btp_seq;
static int hf_matter_btp_length;
static int hf_matter_btp_payload;
static int hf_matter_btp_ad;
static int hf_matter_btp_ad_tlv_tag;

static int ett_matter_btp;
static int ett_matter_btp_flags;
static int ett_matter_btp_versions;
static int ett_matter_btp_ad;

// Section 4.18.2.1
#define MATTER_BTP_FLAGS_HANDSHAKE      0x40
#define MATTER_BTP_FLAGS_MANAGEMENT     0x20
#define MATTER_BTP_FLAGS_ACKNOWLEDGMENT 0x08
#define MATTER_BTP_FLAGS_ENDING         0x04
#define MATTER_BTP_FLAGS_CONTINUING     0x02
#define MATTER_BTP_FLAGS_BEGINNING      0x01

// Section 4.18.3.1
#define MATTER_BTP_OPCODE_HANDSHAKE     0x6C

// Section 5.4.2.4.4
#define MATTER_BTP_AD_TAG_ROTATING_ID   0x00

// Section 4.18.4.2
#define MATTER_GATT_SRV_UUID            0xFFF6
// 18EE2EF5-263D-4559-959F-4F9C429F9D11, Client TX Buffer, Write
#define MATTER_GATT_CHR_TX_UUID_128     "\x18\xee\x2e\xf5\x26\x3d\x45\x59\x95\x9f\x4f\x9c\x42\x9f\x9d\x11"
// 18EE2EF5-263D-4559-959F-4F9C429F9D12, Server RX Buffer, Indication
#define MATTER_GATT_CHR_RX_UUID_128     "\x18\xee\x2e\xf5\x26\x3d\x45\x59\x95\x9f\x4f\x9c\x42\x9f\x9d\x12"
// 64630238-8772-45F2-B87D-748A83218F04, Additional Data, Read
#define MATTER_GATT_CHR_AD_UUID_128     "\x64\x63\x02\x38\x87\x72\x45\xf2\xb8\x7d\x74\x8a\x83\x21\x8f\x04"

static const value_string btp_opcode_vals[] = {
    { MATTER_BTP_OPCODE_HANDSHAKE, "Handshake" },
    { 0, NULL }
};

static const value_string btp_ad_tag_vals[] = {
    { MATTER_BTP_AD_TAG_ROTATING_ID, "Rotating Device Identifier" },
    { 0, NULL }
};

// Dissect the Additional Data characteristic using Matter-defined TLV encoding.
static int
dissect_matter_chr_ad_tlv(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int length)
{

    col_append_str(pinfo->cinfo, COL_INFO, " Additional Data");
    proto_item *item = proto_tree_add_item(tree, hf_matter_btp_ad, tvb, offset, length, ENC_NA);
    proto_tree *subtree = proto_item_add_subtree(item, ett_matter_btp_ad);

    call_dissector_with_data(matter_tlv_handle, tvb, pinfo, subtree, &hf_matter_btp_ad_tlv_tag);

    return length;
}

static int
dissect_matter_btp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *btatt_tree, void *data)
{
    btatt_data_t *att_data = (btatt_data_t *) data;
    uint64_t flags = 0;
    uint32_t opcode = 0;
    int offset = 0;

    DISSECTOR_ASSERT(att_data);
    bluetooth_data_t *bluetooth_data = att_data->bluetooth_data;
    const uint8_t att_opcode = att_data->opcode;
    const uint32_t att_handle = att_data->handle;

    // We are only interested in read, write and indication packets.
    if (att_opcode != ATT_OPCODE_READ_RESPONSE &&
            att_opcode != ATT_OPCODE_WRITE_REQUEST &&
            att_opcode != ATT_OPCODE_HANDLE_VALUE_INDICATION)
        return 0;

    /* Get UUID for current ATT handle. */
    bluetooth_uuid_t uuid = get_gatt_bluetooth_uuid_from_handle(pinfo, att_handle, att_opcode, bluetooth_data);
    /* Verify that the UUID belongs to the Matter GATT service and bail otherwise. */
    if (uuid.size != 16 || (
            memcmp(uuid.data, MATTER_GATT_CHR_TX_UUID_128, 16) != 0 &&
            memcmp(uuid.data, MATTER_GATT_CHR_RX_UUID_128, 16) != 0 &&
            memcmp(uuid.data, MATTER_GATT_CHR_AD_UUID_128, 16) != 0))
        return 0;

    /* Check that the packet is long enough to contain BTP flags byte. */
    if (tvb_reported_length(tvb) < 1)
        return 0;

    col_add_str(pinfo->cinfo, COL_PROTOCOL, "Matter BTP");

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

    col_append_str(pinfo->cinfo, COL_INFO, "Matter BTP");
    col_append_fstr(pinfo->cinfo, COL_INFO, " [Handle: 0x%04x]", att_handle);

    /* Add Matter Bluetooth Transport Protocol as a root subtree. */
    proto_item *root = proto_item_get_parent(btatt_tree);
    proto_item *item = proto_tree_add_item(root, proto_matter_btp, tvb, offset, -1, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(item, ett_matter_btp);

    // The payload format of the Additional Data characteristic is different
    // than the standard BTP packet. It uses Matter-defined TLV encoding.
    // Section 5.4.2.4.4
    if (memcmp(uuid.data, MATTER_GATT_CHR_AD_UUID_128, 16) == 0)
        return dissect_matter_chr_ad_tlv(tvb, pinfo, tree, offset, tvb_reported_length(tvb));

    static int * const btp_flags[] = {
        &hf_matter_btp_flags_beginning,
        &hf_matter_btp_flags_continuing,
        &hf_matter_btp_flags_ending,
        &hf_matter_btp_flags_acknowledgment,
        &hf_matter_btp_flags_management,
        &hf_matter_btp_flags_handshake,
        NULL
    };

    static int * const btp_versions[] = {
        &hf_matter_btp_versions_0,
        &hf_matter_btp_versions_1,
        &hf_matter_btp_versions_2,
        &hf_matter_btp_versions_3,
        &hf_matter_btp_versions_4,
        &hf_matter_btp_versions_5,
        &hf_matter_btp_versions_6,
        &hf_matter_btp_versions_7,
        NULL
    };

    proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_matter_btp_flags, ett_matter_btp_flags, btp_flags, ENC_NA, &flags);
    offset += 1;

    if (flags & MATTER_BTP_FLAGS_MANAGEMENT) {
        proto_tree_add_item_ret_uint(tree, hf_matter_btp_opcode, tvb, offset, 1, ENC_NA, &opcode);
        offset += 1;
    }

    // The handshake packet format is different than standard BTP packets.
    // Section 4.18.3
    if (flags & MATTER_BTP_FLAGS_HANDSHAKE) {

        if (opcode & MATTER_BTP_OPCODE_HANDSHAKE) {

            // Section 4.18.3.1. BTP Handshake Request
            if (memcmp(uuid.data, MATTER_GATT_CHR_TX_UUID_128, 16) == 0) {

                proto_tree_add_bitmask(tree, tvb, offset, hf_matter_btp_versions, ett_matter_btp_versions, btp_versions, ENC_NA);
                offset += 4;
                proto_tree_add_item(tree, hf_matter_btp_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN);
                offset += 2;
                proto_tree_add_item(tree, hf_matter_btp_window_size, tvb, offset, 1, ENC_NA);
                offset += 1;

                col_append_str(pinfo->cinfo, COL_INFO, " Handshake Request");
            }

            // Section 4.18.3.2. BTP Handshake Response
            if (memcmp(uuid.data, MATTER_GATT_CHR_RX_UUID_128, 16) == 0) {

                uint32_t version;
                proto_tree_add_item_ret_uint(tree, hf_matter_btp_version, tvb, offset, 1, ENC_NA, &version);
                offset += 1;

                uint32_t mtu;
                proto_tree_add_item_ret_uint(tree, hf_matter_btp_mtu, tvb, offset, 2, ENC_LITTLE_ENDIAN, &mtu);
                offset += 2;

                uint32_t window_size;
                proto_tree_add_item_ret_uint(tree, hf_matter_btp_window_size, tvb, offset, 1, ENC_NA, &window_size);
                offset += 1;

                col_append_fstr(pinfo->cinfo, COL_INFO, " Handshake Response, Version: %u, MTU: %u, Window Size: %u",
                        version, mtu, window_size);

            }

        }

        return offset;
    }

    // Mark the packet as a segment of a BTP Service Data Unit.
    col_append_str(pinfo->cinfo, COL_INFO, " SDU Segment");

    if (flags & MATTER_BTP_FLAGS_ACKNOWLEDGMENT) {
        uint32_t ack;
        proto_tree_add_item_ret_uint(tree, hf_matter_btp_ack, tvb, offset, 1, ENC_NA, &ack);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Ack: %u", ack);
        offset += 1;
    }

    // All BTP packets SHALL be sent with sequence numbers.
    // Section 4.18.4.6
    if (flags & (MATTER_BTP_FLAGS_BEGINNING | MATTER_BTP_FLAGS_CONTINUING | MATTER_BTP_FLAGS_ENDING)) {
        uint32_t seq;
        proto_tree_add_item_ret_uint(tree, hf_matter_btp_seq, tvb, offset, 1, ENC_NA, &seq);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Seq: %u", seq);
        offset += 1;
    }

    // Message length is an optional field present in the Beginning Segment only.
    // Section 4.18.2.4
    if (flags & MATTER_BTP_FLAGS_BEGINNING) {
        uint32_t length;
        proto_tree_add_item_ret_uint(tree, hf_matter_btp_length, tvb, offset, 2, ENC_LITTLE_ENDIAN, &length);
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Length: %u", length);
        offset += 2;
    }

    proto_tree_add_item(tree, hf_matter_btp_payload, tvb, offset, -1, ENC_NA);

    return tvb_captured_length(tvb);
}

void
proto_register_btatt_matter(void)
{
    static hf_register_info hf[] = {
        {&hf_matter_btp_flags,
            {"Flags", "btp-matter.flags",
            FT_UINT8, BASE_HEX, NULL, 0x0,
            "Bluetooth Transport Protocol control flags", HFILL}
        },
        {&hf_matter_btp_flags_handshake,
            {"Handshake", "btp-matter.flags.handshake",
            FT_BOOLEAN, 8, NULL, MATTER_BTP_FLAGS_HANDSHAKE,
            "BTP handshake packet for session establishment", HFILL}
        },
        {&hf_matter_btp_flags_management,
            {"Management", "btp-matter.flags.management",
            FT_BOOLEAN, 8, NULL, MATTER_BTP_FLAGS_MANAGEMENT,
            "Management message with the opcode field", HFILL}
        },
        {&hf_matter_btp_flags_acknowledgment,
            {"Acknowledgment", "btp-matter.flags.ack",
            FT_BOOLEAN, 8, NULL, MATTER_BTP_FLAGS_ACKNOWLEDGMENT,
            "Indicates the presence of the ack number field", HFILL}
        },
        {&hf_matter_btp_flags_ending,
            {"Ending", "btp-matter.flags.ending",
            FT_BOOLEAN, 8, NULL, MATTER_BTP_FLAGS_ENDING,
            "The last segment of a BTP Service Data Unit", HFILL}
        },
        {&hf_matter_btp_flags_continuing,
            {"Continuing", "btp-matter.flags.continuing",
            FT_BOOLEAN, 8, NULL, MATTER_BTP_FLAGS_CONTINUING,
            "The continuation of a BTP Service Data Unit", HFILL}
        },
        {&hf_matter_btp_flags_beginning,
            {"Beginning", "btp-matter.flags.beginning",
            FT_BOOLEAN, 8, NULL, MATTER_BTP_FLAGS_BEGINNING,
            "The first segment of a BTP Service Data Unit", HFILL}
        },
        {&hf_matter_btp_opcode,
            {"Management Opcode", "btp-matter.opcode",
            FT_UINT8, BASE_HEX, VALS(btp_opcode_vals), 0x0,
            NULL, HFILL}
        },
        {&hf_matter_btp_versions,
            {"Supported BTP versions", "btp-matter.versions",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            "The list of BTP versions supported by the client", HFILL}
        },
        {&hf_matter_btp_versions_0,
            {"Version", "btp-matter.versions.0",
            FT_UINT32, BASE_DEC, NULL, 0x0F000000,
            NULL, HFILL}
        },
        {&hf_matter_btp_versions_1,
            {"Version", "btp-matter.versions.1",
            FT_UINT32, BASE_DEC, NULL, 0xF0000000,
            NULL, HFILL}
        },
        {&hf_matter_btp_versions_2,
            {"Version", "btp-matter.versions.2",
            FT_UINT32, BASE_DEC, NULL, 0x000F0000,
            NULL, HFILL}
        },
        {&hf_matter_btp_versions_3,
            {"Version", "btp-matter.versions.3",
            FT_UINT32, BASE_DEC, NULL, 0x00F00000,
            NULL, HFILL}
        },
        {&hf_matter_btp_versions_4,
            {"Version", "btp-matter.versions.4",
            FT_UINT32, BASE_DEC, NULL, 0x00000F00,
            NULL, HFILL}
        },
        {&hf_matter_btp_versions_5,
            {"Version", "btp-matter.versions.5",
            FT_UINT32, BASE_DEC, NULL, 0x0000F000,
            NULL, HFILL}
        },
        {&hf_matter_btp_versions_6,
            {"Version", "btp-matter.versions.6",
            FT_UINT32, BASE_DEC, NULL, 0x0000000F,
            NULL, HFILL}
        },
        {&hf_matter_btp_versions_7,
            {"Version", "btp-matter.versions.7",
            FT_UINT32, BASE_DEC, NULL, 0x000000F0,
            NULL, HFILL}
        },
        {&hf_matter_btp_version,
            {"Version", "btp-matter.version",
            FT_UINT8, BASE_DEC, NULL, 0x0F,
            "The BTP protocol version selected by the server", HFILL}
        },
        {&hf_matter_btp_mtu,
            {"MTU", "btp-matter.mtu",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "Requested or selected MTU for the connection", HFILL}
        },
        {&hf_matter_btp_window_size,
            {"Window Size", "btp-matter.window",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Requested or selected maximum receive window size, in units of BTP packets", HFILL}
        },
        {&hf_matter_btp_ack,
            {"Acknowledgment", "btp-matter.ack",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The acknowledgement of the previous sequence number", HFILL}
        },
        {&hf_matter_btp_seq,
            {"Sequence Number", "btp-matter.seq",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "The monotonically increasing sequence number", HFILL}
        },
        {&hf_matter_btp_length,
            {"Length", "btp-matter.length",
            FT_UINT16, BASE_DEC, NULL, 0x0,
            "The payload length, in bytes", HFILL}
        },
        {&hf_matter_btp_payload,
            {"Payload", "btp-matter.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            "The segment of the Service Data Unit message", HFILL}
        },
        {&hf_matter_btp_ad,
            {"Additional Data", "btp-matter.ad",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "Additional commissioning-related data", HFILL}
        },
        {&hf_matter_btp_ad_tlv_tag,
            {"Tag", "btp-matter.ad.item",
            FT_UINT8, BASE_HEX, VALS(btp_ad_tag_vals), 0x0,
            NULL, HFILL}
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_matter_btp,
        &ett_matter_btp_flags,
        &ett_matter_btp_versions,
        &ett_matter_btp_ad,
    };

    /* Register the protocol name and description */
    proto_matter_btp = proto_register_protocol("Matter Bluetooth Transport Protocol", "MatterBTP", "btp-matter");
    matter_btp_handle = register_dissector("btp-matter", dissect_matter_btp, proto_matter_btp);

    /* Required function calls to register the header fields and subtrees */
    proto_register_field_array(proto_matter_btp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_btatt_matter(void)
{
    matter_tlv_handle = find_dissector_add_dependency("matter.tlv", proto_matter_btp);
    dissector_add_uint("btatt.service", MATTER_GATT_SRV_UUID, matter_btp_handle);
}
