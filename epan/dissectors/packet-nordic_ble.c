/* packet-nordic_ble.c
 * Routines for Nordic BLE sniffer dissection
 *
 * Copyright (c) 2016-2017 Nordic Semiconductor.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

/* Nordic BLE Sniffer packet format: BoardID + Header + Payload
 *
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                           BoardID  (1 byte)                           |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *
 * Header:
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                      Length of header  (1 byte)                       |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                      Length of payload  (1 byte)                      |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                      Protocol version  (1 byte)                       |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                         Packet counter (LSB)                          |
 *  |                               (2 bytes)                               |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                          Packet ID  (1 byte)                          |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *
 *  Packet ID:
 *   0x00 = REQ_FOLLOW
 *          Host tells the Sniffer to only send packets received from a specific
 *          address.
 *   0x01 = EVENT_FOLLOW
 *          Sniffer tells the Host that it has entered the FOLLOW state.
 *   0x05 = EVENT_CONNECT
 *          Sniffer tells the Host that someone has connected to the unit we
 *          are following.
 *   0x06 = EVENT_PACKET
 *          Sniffer tells the Host that it has received a packet.
 *   0x07 = REQ_SCAN_CONT
 *          Host tells the Sniffer to scan continuously and hand over the
 *          packets ASAP.
 *   0x09 = EVENT_DISCONNECT
 *          Sniffer tells the Host that the connected address we were following
 *          has received a disconnect packet.
 *   0x0C = SET_TEMPORARY_KEY
 *          Specify a temporary key to use on encryption (for OOB and passkey).
 *   0x0D = PING_REQ
 *   0x0E = PING_RESP
 *   0x13 = SWITCH_BAUD_RATE_REQ
 *   0x14 = SWITCH_BAUD_RATE_RESP
 *   0x17 = SET_ADV_CHANNEL_HOP_SEQ
 *          Host tells the Sniffer which order to cycle through the channels
 *          when following an advertiser.
 *   0xFE = GO_IDLE
 *          Host tell the Sniffer to stop sending UART traffic and listen for
 *          new commands.
 *
 * Payloads:
 *
 *  EVENT_PACKET (ID 0x06):
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                   Length of payload data  (1 byte)                    |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                            Flags  (1 byte)                            |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                           Channel  (1 byte)                           |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                          RSSI (dBm)  (1 byte)                         |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                             Event counter                             |
 *  |                               (2 bytes)                               |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                                                                       |
 *  |                     Delta time (us end to start)                      |
 *  |                               (4 bytes)                               |
 *  |                                                                       |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *  |                                                                       |
 *  |                Bluetooth Low Energy Link Layer Packet                 |
 *  |                                  ...                                  |
 *  |                                                                       |
 *  +--------+--------+--------+--------+--------+--------+--------+--------+
 *
 *  Flags:
 *   00000001 = CRC       (0 = Incorrect, 1 = OK)
 *   00000010 = Direction (0 = Slave -> Master, 1 = Master -> Slave)
 *   00000100 = Encrypted (0 = No, 1 = Yes)
 *
 *  Channel:
 *   The channel index being used.
 *
 *  Delta time:
 *   This is the time in micro seconds from the end of the previous received
 *   packet to the beginning of this packet.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto_data.h>

#include <wsutil/utf8_entities.h>
#include <wiretap/wtap.h>

#include "packet-btle.h"

/* Size of various UART Packet header fields */
#define UART_HEADER_LEN (6)
#define BLE_HEADER_LEN (10)

#define US_PER_BYTE (8)
#define NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH (10) /* Preamble (1) + AA (4) + Header (1) + Length (1) + CRC (3) = 10 Bytes */
#define BLE_METADATA_TRANFER_TIME_US (US_PER_BYTE * NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH)

#define BLE_MIN_PACKET_LENGTH (NOF_BLE_BYTES_NOT_INCLUDED_IN_BLE_LENGTH)
#define BLE_MAX_PACKET_LENGTH (50)

#define MIN_TOTAL_LENGTH (BLE_HEADER_LEN + BLE_MIN_PACKET_LENGTH)
#define MAX_TOTAL_LENGTH (UART_HEADER_LEN + BLE_HEADER_LEN + BLE_MAX_PACKET_LENGTH)

void proto_reg_handoff_nordic_ble(void);
void proto_register_nordic_ble(void);

/* Initialize the protocol and registered fields */
static int proto_nordic_ble = -1;

/* Initialize the subtree pointers */
static gint ett_nordic_ble = -1;
static gint ett_packet_header = -1;
static gint ett_flags = -1;

static int hf_nordic_ble_board_id = -1;
static int hf_nordic_ble_legacy_marker = -1;
static int hf_nordic_ble_header = -1;
static int hf_nordic_ble_header_length = -1;
static int hf_nordic_ble_payload_length = -1;
static int hf_nordic_ble_protover = -1;
static int hf_nordic_ble_packet_counter = -1;
static int hf_nordic_ble_packet_id = -1;
static int hf_nordic_ble_packet_length = -1;
static int hf_nordic_ble_flags = -1;
static int hf_nordic_ble_crcok = -1;
static int hf_nordic_ble_encrypted = -1;
static int hf_nordic_ble_micok = -1;
static int hf_nordic_ble_direction = -1;
static int hf_nordic_ble_channel = -1;
static int hf_nordic_ble_rssi = -1;
static int hf_nordic_ble_event_counter = -1;
static int hf_nordic_ble_delta_time = -1;
static int hf_nordic_ble_delta_time_ss = -1;

static expert_field ei_nordic_ble_bad_crc = EI_INIT;
static expert_field ei_nordic_ble_bad_mic = EI_INIT;
static expert_field ei_nordic_ble_bad_length = EI_INIT;

static const true_false_string direction_tfs =
{
    "Master -> Slave",
    "Slave -> Master"
};

static const true_false_string ok_incorrect =
{
    "OK",
    "Incorrect"
};

/* next dissector */
static dissector_handle_t btle_dissector_handle = NULL;
static dissector_handle_t debug_handle = NULL;

static gint
dissect_lengths(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, gboolean legacy_mode, guint8 *packet_length, gboolean *bad_length)
{
    guint8 hlen, plen;
    proto_item* item;

    if (!legacy_mode) {
        hlen = tvb_get_guint8(tvb, offset) + 1; /* Add one byte for board id */
        proto_tree_add_item(tree, hf_nordic_ble_header_length, tvb, offset, 1, ENC_NA);
        offset += 1;
    } else {
        hlen = 8; /* 2 bytes legacy marker + 6 bytes header */
    }

    plen = tvb_get_guint8(tvb, offset);
    item = proto_tree_add_item(tree, hf_nordic_ble_payload_length, tvb, offset, 1, ENC_NA);
    offset += 1;

    if (((hlen + plen) != tvb_captured_length(tvb)) ||
        ((hlen + plen) < MIN_TOTAL_LENGTH) ||
        ((hlen + plen) > MAX_TOTAL_LENGTH))
    {
        expert_add_info(pinfo, item, &ei_nordic_ble_bad_length);
        *bad_length = TRUE;
    }

    *packet_length = plen;

    return offset;
}

static gint
dissect_flags(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, btle_context_t *context)
{
    guint8 flags;
    gboolean dir, encrypted;
    proto_item *flags_item, *item;
    proto_tree *flags_tree;

    context->crc_checked_at_capture = 1;
    flags = tvb_get_guint8(tvb, offset);
    context->crc_valid_at_capture = !!(flags & 1);
    dir = !!(flags & 2);
    encrypted = !!(flags & 4);
    context->mic_valid_at_capture = !!(flags & 8);

    if (dir) {
        set_address(&pinfo->src, AT_STRINGZ, 7, "Master");
        set_address(&pinfo->dst, AT_STRINGZ, 6, "Slave");
        context->direction = BTLE_DIR_MASTER_SLAVE;
        pinfo->p2p_dir = P2P_DIR_SENT;
    }
    else {
        set_address(&pinfo->src, AT_STRINGZ, 6, "Slave");
        set_address(&pinfo->dst, AT_STRINGZ, 7, "Master");
        context->direction = BTLE_DIR_SLAVE_MASTER;
        pinfo->p2p_dir = P2P_DIR_RECV;
    }

    flags_item = proto_tree_add_item(tree, hf_nordic_ble_flags, tvb, offset, 1, ENC_NA);
    flags_tree = proto_item_add_subtree(flags_item, ett_flags);
    if (encrypted) /* if encrypted, add MIC status */
    {
        context->mic_checked_at_capture = 1;
        item = proto_tree_add_bits_item(flags_tree, hf_nordic_ble_micok, tvb, offset * 8 + 4, 1, ENC_LITTLE_ENDIAN);
        if (!context->mic_valid_at_capture) {
            /* MIC is bad */
            expert_add_info(pinfo, item, &ei_nordic_ble_bad_mic);
        }
    }
    proto_tree_add_bits_item(flags_tree, hf_nordic_ble_encrypted, tvb, offset * 8 + 5, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_bits_item(flags_tree, hf_nordic_ble_direction, tvb, offset * 8 + 6, 1, ENC_LITTLE_ENDIAN);
    item = proto_tree_add_bits_item(flags_tree, hf_nordic_ble_crcok, tvb, offset * 8 + 7, 1, ENC_LITTLE_ENDIAN);
    if (!context->crc_valid_at_capture) {
        /* CRC is bad */
        expert_add_info(pinfo, item, &ei_nordic_ble_bad_crc);
    }
    offset++;

    return offset;
}

static gint
dissect_ble_delta_time(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, guint8 packet_len)
{
    static guint8 previous_ble_packet_length = 0;
    guint32 delta_time, delta_time_ss;
    proto_item *pi;

    if (!pinfo->fd->flags.visited) {
        /* First time visiting this packet, store previous BLE packet length */
        p_add_proto_data(wmem_file_scope(), pinfo, proto_nordic_ble, 0, GUINT_TO_POINTER(previous_ble_packet_length));
    } else {
        previous_ble_packet_length = GPOINTER_TO_UINT(p_get_proto_data(wmem_file_scope(), pinfo, proto_nordic_ble, 0));
    }

    /* end - start */
    delta_time = (guint32)tvb_get_letohl(tvb, offset);
    proto_tree_add_item(tree, hf_nordic_ble_delta_time, tvb, offset, 4, ENC_LITTLE_ENDIAN);

    /* start - start */
    delta_time_ss = BLE_METADATA_TRANFER_TIME_US + (US_PER_BYTE * previous_ble_packet_length) + delta_time;
    pi = proto_tree_add_uint(tree, hf_nordic_ble_delta_time_ss, tvb, offset, 4, delta_time_ss);
    PROTO_ITEM_SET_GENERATED(pi);

    if (!pinfo->fd->flags.visited) {
        previous_ble_packet_length = packet_len;
    }
    offset += 4;

    return offset;
}

static gint
dissect_packet_counter(tvbuff_t *tvb, gint offset, proto_item *item, proto_tree *tree)
{
    proto_item_append_text(item, ", Packet counter: %u", tvb_get_guint16(tvb, offset, ENC_LITTLE_ENDIAN));
    proto_tree_add_item(tree, hf_nordic_ble_packet_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    return offset;
}

static gint
dissect_packet_header(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, gboolean legacy_mode, gboolean *bad_length, guint8 *packet_len)
{
    proto_item *ti;
    proto_tree *header_tree;
    gint start_offset = offset;

    ti = proto_tree_add_item(tree, hf_nordic_ble_header, tvb, offset, -1, ENC_NA);
    header_tree = proto_item_add_subtree(ti, ett_packet_header);

    if (legacy_mode) {
        proto_tree_add_item(header_tree, hf_nordic_ble_packet_id, tvb, offset, 1, ENC_NA);
        offset += 1;

        offset = dissect_packet_counter(tvb, offset, ti, header_tree);

        offset += 2; // Two unused bytes
    }

    offset = dissect_lengths(tvb, offset, pinfo, header_tree, legacy_mode, packet_len, bad_length);

    if (!legacy_mode) {
        proto_tree_add_item(header_tree, hf_nordic_ble_protover, tvb, offset, 1, ENC_NA);
        offset += 1;

        offset = dissect_packet_counter(tvb, offset, ti, header_tree);

        proto_tree_add_item(header_tree, hf_nordic_ble_packet_id, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    proto_item_set_len(ti, offset - start_offset);

    return offset;
}

static gint
dissect_packet(tvbuff_t *tvb, gint offset, packet_info *pinfo, proto_tree *tree, gboolean legacy_mode, btle_context_t *context, guint8 packet_len)
{
    gint32 rssi;

    if (!legacy_mode) {
        proto_tree_add_item(tree, hf_nordic_ble_packet_length, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    offset = dissect_flags(tvb, offset, pinfo, tree, context);

    proto_tree_add_item(tree, hf_nordic_ble_channel, tvb, offset, 1, ENC_NA);
    offset += 1;

    rssi = (-1)*((gint32)tvb_get_guint8(tvb, offset));
    proto_tree_add_int(tree, hf_nordic_ble_rssi, tvb, offset, 1, rssi);
    offset += 1;

    proto_tree_add_item(tree, hf_nordic_ble_event_counter, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset += 2;

    offset = dissect_ble_delta_time(tvb, offset, pinfo, tree, packet_len);

    return offset;
}

static gint
dissect_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, btle_context_t *context, gboolean *bad_length)
{
    proto_item *ti;
    proto_tree *nordic_ble_tree;
    guint8 packet_len = 0;
    gint offset = 0;
    gboolean legacy_mode = (tvb_get_guint16(tvb, 0, ENC_BIG_ENDIAN) == 0xBEEF);

    ti = proto_tree_add_item(tree, proto_nordic_ble, tvb, 0, -1, ENC_NA);
    nordic_ble_tree = proto_item_add_subtree(ti, ett_nordic_ble);

    if (legacy_mode) {
        proto_tree_add_item(nordic_ble_tree, hf_nordic_ble_legacy_marker, tvb, 0, 2, ENC_BIG_ENDIAN);
        offset += 2;
    } else {
        proto_tree_add_item(nordic_ble_tree, hf_nordic_ble_board_id, tvb, 0, 1, ENC_NA);
        offset += 1;
    }

    offset = dissect_packet_header(tvb, offset, pinfo, nordic_ble_tree, legacy_mode, bad_length, &packet_len);
    offset = dissect_packet(tvb, offset, pinfo, nordic_ble_tree, legacy_mode, context, packet_len);

    proto_item_set_len(ti, offset);

    return offset;
}

/* Main entry point for sniffer */
static int
dissect_nordic_ble(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    tvbuff_t          *payload_tvb;
    btle_context_t    *context;
    gint               offset;
    gboolean           bad_length = FALSE;

    context = wmem_new0(wmem_packet_scope(), btle_context_t);

    offset = dissect_header(tvb, pinfo, tree, context, &bad_length);
    payload_tvb = tvb_new_subset_length_caplen(tvb, offset, -1, tvb_captured_length(tvb) - offset);

    if (!bad_length) {
        call_dissector_with_data(btle_dissector_handle, payload_tvb, pinfo, tree, context);
    }

    if ((context->mic_checked_at_capture) && (!context->mic_valid_at_capture)) {
        col_add_str(pinfo->cinfo, COL_INFO, "Encrypted packet decrypted incorrectly (bad MIC)");
    }

    if (debug_handle) {
        call_dissector(debug_handle, payload_tvb, pinfo, tree);
    }

    return offset;
}

void
proto_register_nordic_ble(void)
{
    static hf_register_info hf[] = {
        { &hf_nordic_ble_board_id,
            { "Board", "nordic_ble.board_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_legacy_marker,
            { "Legacy marker", "nordic_ble.legacy_marker",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_header,
            { "Header", "nordic_ble.header",
                FT_NONE, BASE_NONE, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_header_length,
            { "Length of header", "nordic_ble.hlen",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_payload_length,
            { "Length of payload", "nordic_ble.plen",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                "Payload length", HFILL }
        },
        { &hf_nordic_ble_protover,
            { "Protocol version", "nordic_ble.protover",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_packet_counter,
            { "Packet counter", "nordic_ble.packet_counter",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                "Global packet counter for packets sent on UART", HFILL }
        },
        { &hf_nordic_ble_packet_id,
            { "Packet ID", "nordic_ble.packet_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_packet_length,
            { "Length of packet", "nordic_ble.len",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_flags,
            { "Flags", "nordic_ble.flags",
                FT_UINT8, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_crcok,
            { "CRC", "nordic_ble.crcok",
                FT_BOOLEAN, BASE_NONE, TFS(&ok_incorrect), 0x0,
                "Cyclic Redundancy Check state", HFILL }
        },
        { &hf_nordic_ble_direction,
            { "Direction", "nordic_ble.direction",
                FT_BOOLEAN, BASE_NONE, TFS(&direction_tfs), 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_encrypted,
            { "Encrypted", "nordic_ble.encrypted",
                FT_BOOLEAN, BASE_NONE, TFS(&tfs_yes_no), 0x0,
                "Was the packet encrypted", HFILL }
        },
        { &hf_nordic_ble_micok,
            { "MIC", "nordic_ble.micok",
                FT_BOOLEAN, BASE_NONE, TFS(&ok_incorrect), 0x0,
                "Message Integrity Check state", HFILL }
        },
        { &hf_nordic_ble_channel,
            { "Channel", "nordic_ble.channel",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_rssi,
            { "RSSI (dBm)", "nordic_ble.rssi",
                FT_INT16, BASE_DEC, NULL, 0x0,
                "Received Signal Strength Indicator", HFILL }
        },
        { &hf_nordic_ble_event_counter,
            { "Event counter", "nordic_ble.event_counter",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_nordic_ble_delta_time,
            { "Delta time (" UTF8_MICRO_SIGN "s end to start)", "nordic_ble.delta_time",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                UTF8_MICRO_SIGN "s since end of last reported packet", HFILL }
        },
        { &hf_nordic_ble_delta_time_ss,
            { "Delta time (" UTF8_MICRO_SIGN "s start to start)", "nordic_ble.delta_time_ss",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                UTF8_MICRO_SIGN "s since start of last reported packet", HFILL }
        }
    };

    static gint *ett[] = {
        &ett_nordic_ble,
        &ett_packet_header,
        &ett_flags
    };

    static ei_register_info ei[] = {
        { &ei_nordic_ble_bad_crc, { "nordic_ble.crc.bad", PI_CHECKSUM, PI_ERROR, "CRC is bad", EXPFILL }},
        { &ei_nordic_ble_bad_mic, { "nordic_ble.mic.bad", PI_CHECKSUM, PI_ERROR, "MIC is bad", EXPFILL }},
        { &ei_nordic_ble_bad_length, { "nordic_ble.length.bad", PI_MALFORMED, PI_ERROR, "Length is incorrect", EXPFILL }},
    };

    expert_module_t *expert_nordic_ble;

    proto_nordic_ble = proto_register_protocol("Nordic BLE Sniffer", "NORDIC_BLE", "nordic_ble");

    register_dissector("nordic_ble", dissect_nordic_ble, proto_nordic_ble);

    expert_nordic_ble = expert_register_protocol(proto_nordic_ble);
    expert_register_field_array(expert_nordic_ble, ei, array_length(ei));

    proto_register_field_array(proto_nordic_ble, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nordic_ble(void)
{
    dissector_handle_t nordic_ble_handle;

    nordic_ble_handle = create_dissector_handle(dissect_nordic_ble, proto_nordic_ble);

    btle_dissector_handle = find_dissector("btle");
    debug_handle = find_dissector("nordic_debug");

    dissector_add_for_decode_as_with_preference("udp.port", nordic_ble_handle);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_NORDIC_BLE, nordic_ble_handle);
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
 * vi: set shiftwidth =4 tabstop =8 expandtab:
 * :indentSize =4:tabSize =8:noTabs =true:
 */
