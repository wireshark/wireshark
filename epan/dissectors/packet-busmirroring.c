/* packet-busmirroring.c
 * Routines for BusMirroring protocol packet disassembly
 * Copyright 2023, Haiyun Liu <liu0hy@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later

 * Bus Mirroring is an AUTOSAR Basic Software module. Its purpose is the replication of
 * the traffic and the state of internal buses to an external bus, such that a tester
 * connected to that external bus can monitor internal buses for debugging purposes.
 * When mirroring to an IP destination bus like Ethernet, the Bus Mirroring module applies
 * a protocol to pack several smaller frames (e.g. CAN, LIN or FlexRay) into one large
 * frame of the destination bus.
 * For more information, see AUTOSAR "Specification of Bus Mirroring", Section 7.4
 * "Mirroring to FlexRay, IP, and CDD":
 * https://www.autosar.org/fileadmin/standards/R22-11/CP/AUTOSAR_SWS_BusMirroring.pdf
 */

#include "config.h"
#include <epan/packet.h>

#define BUSMIRRORING_UDP_PORT 30511

enum network_type
{
    NETWORK_TYPE_UNKNOWN = 0x00,
    NETWORK_TYPE_CAN = 0x01,
    NETWORK_TYPE_LIN = 0x02,
    NETWORK_TYPE_FLEXRAY = 0x03,
    NETWORK_TYPE_ETHERNET = 0x04
};

static int proto_busmirroring = -1;
static int hf_protocol_version = -1;
static int hf_sequence_number = -1;
static int hf_header_timestamp = -1;
static int hf_seconds = -1;
static int hf_nanoseconds = -1;
static int hf_data_length = -1;
static int hf_timestamp = -1;
static int hf_network_state_available = -1;
static int hf_frame_id_available = -1;
static int hf_payload_available = -1;
static int hf_network_type = -1;
static int hf_frames_lost = -1;
static int hf_bus_online = -1;
static int hf_can_error_passive = -1;
static int hf_can_bus_off = -1;
static int hf_can_tx_error_count = -1;
static int hf_lin_header_tx_error = -1;
static int hf_lin_tx_error = -1;
static int hf_lin_rx_error = -1;
static int hf_lin_rx_no_response = -1;
static int hf_flexray_bus_synchronous = -1;
static int hf_flexray_normal_active = -1;
static int hf_flexray_syntax_error = -1;
static int hf_flexray_content_error = -1;
static int hf_flexray_boundary_violation = -1;
static int hf_flexray_tx_conflict = -1;
static int hf_network_id = -1;
static int hf_network_state = -1;
static int hf_frame_id = -1;
static int hf_can_id_type = -1;
static int hf_can_frame_type = -1;
static int hf_can_id = -1;
static int hf_lin_pid = -1;
static int hf_flexray_channel_b = -1;
static int hf_flexray_channel_a = -1;
static int hf_flexray_slot_valid = -1;
static int hf_flexray_slot_id = -1;
static int hf_flexray_cycle = -1;
static int hf_payload_length = -1;
static int hf_payload = -1;
static int ett_busmirroring = -1;
static int ett_header_timestamp = -1;
static int ett_data_item = -1;
static int ett_network_state = -1;
static int ett_frame_id = -1;

static int
dissect_busmirroring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    static const int header_size = 14;
    int buffer_length = tvb_captured_length(tvb);
    if (buffer_length < header_size)
    {
        return 0;
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BUSMIRRORING");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_fstr(pinfo->cinfo, COL_INFO, "Busmirroring Seq=%u Len=%u", tvb_get_guint8(tvb, 1), tvb_get_guint16(tvb, 12, ENC_BIG_ENDIAN));

    proto_item *ti = proto_tree_add_item(tree, proto_busmirroring, tvb, 0, -1, ENC_NA);
    proto_tree *busmirroring_tree = proto_item_add_subtree(ti, ett_busmirroring);
    proto_tree_add_item(busmirroring_tree, hf_protocol_version, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(busmirroring_tree, hf_sequence_number, tvb, 1, 1, ENC_BIG_ENDIAN);
    nstime_t header_timestamp;
    header_timestamp.secs = tvb_get_guint48(tvb, 2, ENC_BIG_ENDIAN);
    header_timestamp.nsecs = tvb_get_guint32(tvb, 8, ENC_BIG_ENDIAN);
    proto_item *ht_item = proto_tree_add_time(busmirroring_tree, hf_header_timestamp, tvb, 2, 10, &header_timestamp);
    proto_tree *ht_tree = proto_item_add_subtree(ht_item, ett_header_timestamp);
    proto_tree_add_item(ht_tree, hf_seconds, tvb, 2, 6, ENC_BIG_ENDIAN);
    proto_tree_add_item(ht_tree, hf_nanoseconds, tvb, 8, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item(busmirroring_tree, hf_data_length, tvb, 12, 2, ENC_BIG_ENDIAN);

    int data_item_index = 0;
    int offset = header_size;
    static const int min_data_header_size = 4;
    while (offset + min_data_header_size <= buffer_length)
    {
        int data_item_length = min_data_header_size;
        uint8_t flags = tvb_get_guint8(tvb, offset + 2);
        uint8_t type = flags & 0x1F;
        uint8_t has_network_state = flags & 0x80;
        if (has_network_state)
        {
            data_item_length += 1;
        }
        uint8_t has_frame_id = flags & 0x40;
        if (has_frame_id)
        {
            uint8_t frame_id_length = 0;
            switch (type)
            {
            case NETWORK_TYPE_CAN:
                frame_id_length = 4;
                break;
            case NETWORK_TYPE_LIN:
                frame_id_length = 1;
                break;
            case NETWORK_TYPE_FLEXRAY:
                frame_id_length = 3;
                break;
            default:
                break;
            }
            data_item_length += frame_id_length;
        }
        uint8_t has_payload = flags & 0x20;
        int length = 0;
        if (has_payload)
        {
            length = tvb_get_guint8(tvb, offset + data_item_length);
            data_item_length += 1; // "Payload length" field is 1 byte long
            data_item_length += length;
        }

        if (offset + data_item_length > buffer_length) {
            return buffer_length;
        }

        proto_item *data_item = proto_tree_add_item(busmirroring_tree, proto_busmirroring, tvb, offset, data_item_length, ENC_NA);
        proto_item_set_text(data_item, "Data Item #%d", data_item_index);
        proto_tree *data_tree = proto_item_add_subtree(data_item, ett_data_item);
        proto_tree_add_item(data_tree, hf_timestamp, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_network_state_available, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_frame_id_available, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_payload_available, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_network_type, tvb, offset + 2, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_network_id, tvb, offset + 3, 1, ENC_BIG_ENDIAN);

        offset += min_data_header_size;

        if (has_network_state)
        {
            proto_item *ns_item = proto_tree_add_item(data_item, hf_network_state, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree *ns_tree = proto_item_add_subtree(ns_item, ett_network_state);
            proto_tree_add_item(ns_tree, hf_frames_lost, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(ns_tree, hf_bus_online, tvb, offset, 1, ENC_BIG_ENDIAN);
            switch (type)
            {
            case NETWORK_TYPE_CAN:
            {
                proto_tree_add_item(ns_tree, hf_can_error_passive, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_can_bus_off, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_can_tx_error_count, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            break;
            case NETWORK_TYPE_LIN:
            {
                proto_tree_add_item(ns_tree, hf_lin_header_tx_error, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_lin_tx_error, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_lin_rx_error, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_lin_rx_no_response, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            break;
            case NETWORK_TYPE_FLEXRAY:
            {
                proto_tree_add_item(ns_tree, hf_flexray_bus_synchronous, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_flexray_normal_active, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_flexray_syntax_error, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_flexray_content_error, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_flexray_boundary_violation, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree_add_item(ns_tree, hf_flexray_tx_conflict, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            default:
                break;
            }
            ++offset;
        }
        if (has_frame_id)
        {
            switch (type)
            {
            case NETWORK_TYPE_CAN:
            {
                proto_item *frame_id_item = proto_tree_add_item(data_item, hf_frame_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree *frame_id_tree = proto_item_add_subtree(frame_id_item, ett_frame_id);
                proto_tree_add_item(frame_id_tree, hf_can_id_type, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_can_frame_type, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_can_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset += 4;
            }
            break;
            case NETWORK_TYPE_LIN:
            {
                proto_item *frame_id_item = proto_tree_add_item(data_item, hf_frame_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree *frame_id_tree = proto_item_add_subtree(frame_id_item, ett_frame_id);
                proto_tree_add_item(frame_id_tree, hf_lin_pid, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
            case NETWORK_TYPE_FLEXRAY:
            {
                proto_item* frame_id_item = proto_tree_add_item(data_item, hf_frame_id, tvb, offset, 3, ENC_BIG_ENDIAN);
                proto_tree *frame_id_tree = proto_item_add_subtree(frame_id_item, ett_frame_id);
                proto_tree_add_item(frame_id_tree, hf_flexray_channel_b, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_flexray_channel_a, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_flexray_slot_valid, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_flexray_slot_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(frame_id_tree, hf_flexray_cycle, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
            }
            break;
            default:
                break;
            }
        }
        if (has_payload)
        {
            proto_tree_add_item(data_item, hf_payload_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(data_item, hf_payload, tvb, offset + 1, length, ENC_NA);
            offset += (length + 1);
        }

        ++data_item_index;
    } // while

    return buffer_length;
}

void proto_register_busmirroring(void)
{
    static const true_false_string can_id_type_names = {"Extended", "Standard"};
    static const true_false_string can_frame_type_names = {"CAN FD", "CAN 2.0"};
    static const value_string network_type_names[] = {
        {1, "CAN"},
        {2, "LIN"},
        {3, "FlexRay"},
        {4, "Ethernet"},
        {0, NULL} };
    static hf_register_info hf[] = {
        {&hf_protocol_version,
         {"Protocol Version", "busmirroring.protocol_version",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_sequence_number,
         {"Sequence Number", "busmirroring.sequence_number",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_header_timestamp,
         {"Timestamp", "busmirroring.header_timestamp",
          FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_seconds,
         {"Seconds", "busmirroring.seconds",
          FT_UINT48, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_nanoseconds,
         {"Nanoseconds", "busmirroring.nanoseconds",
          FT_UINT32, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_data_length,
         {"Data Length", "busmirroring.data_length",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_timestamp,
         {"Timestamp(10 µs)", "busmirroring.timestamp",
          FT_UINT16, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_network_state_available,
         {"Network State", "busmirroring.network_state_available",
          FT_BOOLEAN, 8,
          TFS(&tfs_available_not_available), 0x80,
          NULL, HFILL}},
        {&hf_frame_id_available,
         {"Frame ID", "busmirroring.frame_id_available",
          FT_BOOLEAN, 8,
          TFS(&tfs_available_not_available), 0x40,
          NULL, HFILL}},
        {&hf_payload_available,
         {"Payload", "busmirroring.payload_available",
          FT_BOOLEAN, 8,
          TFS(&tfs_available_not_available), 0x20,
          NULL, HFILL}},
        {&hf_network_type,
         {"Network Type", "busmirroring.network_type",
          FT_UINT8, BASE_DEC,
          VALS(network_type_names), 0x1F,
          NULL, HFILL}},
        {&hf_network_id,
         {"Network ID", "busmirroring.network_id",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_network_state,
         {"Network State", "busmirroring.network_state",
          FT_UINT8, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_frames_lost,
         {"Frames Lost", "busmirroring.frames_lost",
          FT_BOOLEAN, 8,
          NULL, 0x80,
          NULL, HFILL}},
        {&hf_bus_online,
         {"Bus Online", "busmirroring.bus_online",
          FT_BOOLEAN, 8,
          NULL, 0x40,
          NULL, HFILL}},
        {&hf_can_error_passive,
         {"Error-Passive", "busmirroring.can_error_passive",
          FT_BOOLEAN, 8,
          NULL, 0x20,
          NULL, HFILL}},
        {&hf_can_bus_off,
         {"Bus-Off", "busmirroring.can_bus_off",
          FT_BOOLEAN, 8,
          NULL, 0x10,
          NULL, HFILL}},
        {&hf_can_tx_error_count,
         {"Tx Error Count(divided by 8)", "busmirroring.can_tx_error_count",
          FT_UINT8, BASE_DEC,
          NULL, 0x0F,
          NULL, HFILL}},
        {&hf_lin_header_tx_error,
         {"Header Tx Error", "busmirroring.lin_header_tx_error",
          FT_BOOLEAN, 8,
          NULL, 0x08,
          NULL, HFILL}},
        {&hf_lin_tx_error,
         {"Tx Error", "busmirroring.lin_tx_error",
          FT_BOOLEAN, 8,
          NULL, 0x04,
          NULL, HFILL}},
        {&hf_lin_rx_error,
         {"Rx Error", "busmirroring.lin_rx_error",
          FT_BOOLEAN, 8,
          NULL, 0x02,
          NULL, HFILL}},
        {&hf_lin_rx_no_response,
         {"Rx No Response", "busmirroring.lin_rx_no_response",
          FT_BOOLEAN, 8,
          NULL, 0x01,
          NULL, HFILL}},
        {&hf_flexray_bus_synchronous,
         {"Bus Synchronous", "busmirroring.flexray_bus_synchronous",
          FT_BOOLEAN, 8,
          NULL, 0x20,
          NULL, HFILL}},
        {&hf_flexray_normal_active,
         {"Normal Active", "busmirroring.flexray_normal_active",
          FT_BOOLEAN, 8,
          NULL, 0x10,
          NULL, HFILL}},
        {&hf_flexray_syntax_error,
         {"Syntax Error", "busmirroring.flexray_syntax_error",
          FT_BOOLEAN, 8,
          NULL, 0x08,
          NULL, HFILL}},
        {&hf_flexray_content_error,
         {"Content Error", "busmirroring.flexray_content_error",
          FT_BOOLEAN, 8,
          NULL, 0x04,
          NULL, HFILL}},
        {&hf_flexray_boundary_violation,
         {"Boundary Violation", "busmirroring.flexray_boundary_violation",
          FT_BOOLEAN, 8,
          NULL, 0x02,
          NULL, HFILL}},
        {&hf_flexray_tx_conflict,
         {"Tx Conflict", "busmirroring.flexray_tx_conflict",
          FT_BOOLEAN, 8,
          NULL, 0x01,
          NULL, HFILL}},
        {&hf_frame_id,
         {"Frame ID", "busmirroring.frame_id",
          FT_UINT32, BASE_HEX,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_can_id_type,
         {"CAN ID Type", "busmirroring.can_id_type",
          FT_BOOLEAN, 32,
          TFS(&can_id_type_names), 0x80000000,
          NULL, HFILL}},
        {&hf_can_frame_type,
         {"CAN Frame Type", "busmirroring.can_frame_type",
          FT_BOOLEAN, 32,
          TFS(&can_frame_type_names), 0x40000000,
          NULL, HFILL}},
        {&hf_can_id,
         {"CAN ID", "busmirroring.can_id",
          FT_UINT32, BASE_HEX_DEC,
          NULL, 0x1FFFFFFF,
          NULL, HFILL}},
        {&hf_lin_pid,
         {"LIN PID", "busmirroring.lin_pid",
          FT_UINT8, BASE_HEX_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_flexray_channel_b,
         {"Channel B", "busmirroring.flexray_channel_b",
          FT_BOOLEAN, 16,
          TFS(&tfs_available_not_available), 0x8000,
          NULL, HFILL}},
        {&hf_flexray_channel_a,
         {"Channel A", "busmirroring.flexray_channel_a",
          FT_BOOLEAN, 16,
          TFS(&tfs_available_not_available), 0x4000,
          NULL, HFILL}},
        {&hf_flexray_slot_valid,
         {"Slot", "busmirroring.flexray_slot_valid",
          FT_BOOLEAN, 16,
          TFS(&tfs_valid_not_valid), 0x0800,
          NULL, HFILL}},
        {&hf_flexray_slot_id,
         {"Slot ID", "busmirroring.flexray_slot_id",
          FT_UINT16, BASE_HEX_DEC,
          NULL, 0x07FF,
          NULL, HFILL}},
        {&hf_flexray_cycle,
         {"Cycle", "busmirroring.flexray_cycle",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_payload_length,
         {"Payload Length", "busmirroring.payload_length",
          FT_UINT8, BASE_DEC,
          NULL, 0x0,
          NULL, HFILL}},
        {&hf_payload,
         {"Payload", "busmirroring.payload",
          FT_BYTES, BASE_NONE,
          NULL, 0x0,
          NULL, HFILL}}};

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_busmirroring,
        &ett_header_timestamp,
        &ett_data_item,
        &ett_network_state,
        &ett_frame_id};

    proto_busmirroring = proto_register_protocol(
        "Bus Mirroring Protocol", /* name        */
        "BusMirroring",           /* short_name  */
        "busmirroring"            /* filter_name */
    );

    proto_register_field_array(proto_busmirroring, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void proto_reg_handoff_busmirroring(void)
{
    static dissector_handle_t busmirroring_handle;

    busmirroring_handle = create_dissector_handle(dissect_busmirroring, proto_busmirroring);
    dissector_add_uint_with_preference("udp.port", BUSMIRRORING_UDP_PORT, busmirroring_handle);
    dissector_add_for_decode_as("udp.port", busmirroring_handle);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
