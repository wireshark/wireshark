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
#include <epan/expert.h>

#define BUSMIRRORING_UDP_PORT 30511

enum network_type
{
    NETWORK_TYPE_INVALID = 0x00,
    NETWORK_TYPE_CAN = 0x01,
    NETWORK_TYPE_LIN = 0x02,
    NETWORK_TYPE_FLEXRAY = 0x03,
    NETWORK_TYPE_ETHERNET = 0x04
};

static int proto_busmirroring;
static int hf_protocol_version;
static int hf_sequence_number;
static int hf_header_timestamp;
static int hf_seconds;
static int hf_nanoseconds;
static int hf_data_length;
static int hf_timestamp;
static int hf_network_state_available;
static int hf_frame_id_available;
static int hf_payload_available;
static int hf_network_type;
static int hf_frames_lost;
static int hf_bus_online;
static int hf_can_error_passive;
static int hf_can_bus_off;
static int hf_can_tx_error_count;
static int hf_lin_header_tx_error;
static int hf_lin_tx_error;
static int hf_lin_rx_error;
static int hf_lin_rx_no_response;
static int hf_flexray_bus_synchronous;
static int hf_flexray_normal_active;
static int hf_flexray_syntax_error;
static int hf_flexray_content_error;
static int hf_flexray_boundary_violation;
static int hf_flexray_tx_conflict;
static int hf_network_id;
static int hf_network_state;
static int hf_frame_id;
static int hf_can_id_type;
static int hf_can_frame_type;
static int hf_can_id;
static int hf_lin_pid;
static int hf_flexray_channel_b;
static int hf_flexray_channel_a;
static int hf_flexray_slot_valid;
static int hf_flexray_slot_id;
static int hf_flexray_cycle;
static int hf_payload_length;
static int hf_payload;
static int ett_busmirroring;
static int ett_header_timestamp;
static int ett_data_item;
static int ett_network_state;
static int ett_frame_id;
static expert_field ei_data_incomplete;
static expert_field ei_data_item_incomplete;
static expert_field ei_network_type_invalid;
static expert_field ei_can_id_invalid;
static expert_field ei_lin_pid_invalid;
static expert_field ei_can_length_invalid;
static expert_field ei_lin_length_invalid;

static const uint8_t pid_table[] = {
    0x80, 0xC1, 0x42, 0x03, 0xC4, 0x85, 0x06, 0x47,
    0x08, 0x49, 0xCA, 0x8B, 0x4C, 0x0D, 0x8E, 0xCF,
    0x50, 0x11, 0x92, 0xD3, 0x14, 0x55, 0xD6, 0x97,
    0xD8, 0x99, 0x1A, 0x5B, 0x9C, 0xDD, 0x5E, 0x1F,
    0x20, 0x61, 0xE2, 0xA3, 0x64, 0x25, 0xA6, 0xE7,
    0xA8, 0xE9, 0x6A, 0x2B, 0xEC, 0xAD, 0x2E, 0x6F,
    0xF0, 0xB1, 0x32, 0x73, 0xB4, 0xF5, 0x76, 0x37,
    0x78, 0x39, 0xBA, 0xFB, 0x3C, 0x7D, 0xFE, 0xBF
};

static bool is_lin_pid_valid(uint8_t pid) {
    return pid == pid_table[pid & 0x3F];
}

static int
dissect_busmirroring(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree _U_, void *data _U_)
{
    static const uint32_t header_size = 14;
    uint32_t buffer_length = tvb_captured_length(tvb);
    if (buffer_length < header_size)
    {
        return 0;
    }
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "BUSMIRRORING");

    proto_item *ti = proto_tree_add_item(tree, proto_busmirroring, tvb, 0, -1, ENC_NA);
    proto_tree *busmirroring_tree = proto_item_add_subtree(ti, ett_busmirroring);
    proto_tree_add_item(busmirroring_tree, hf_protocol_version, tvb, 0, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(busmirroring_tree, hf_sequence_number, tvb, 1, 1, ENC_BIG_ENDIAN);
    nstime_t header_timestamp = {0, 0};
    header_timestamp.secs = tvb_get_uint48(tvb, 2, ENC_BIG_ENDIAN);
    header_timestamp.nsecs = tvb_get_uint32(tvb, 8, ENC_BIG_ENDIAN);
    proto_item *ht_item = proto_tree_add_time(busmirroring_tree, hf_header_timestamp, tvb, 2, 10, &header_timestamp);
    proto_tree *ht_tree = proto_item_add_subtree(ht_item, ett_header_timestamp);
    proto_tree_add_item(ht_tree, hf_seconds, tvb, 2, 6, ENC_BIG_ENDIAN);
    proto_tree_add_item(ht_tree, hf_nanoseconds, tvb, 8, 4, ENC_BIG_ENDIAN);
    uint32_t data_length = 0;
    proto_tree_add_item_ret_uint(busmirroring_tree, hf_data_length, tvb, 12, 2, ENC_BIG_ENDIAN, &data_length);
    if (header_size + data_length > buffer_length) {
        expert_add_info(pinfo, ti, &ei_data_incomplete);
    }

    int data_item_index = 0;
    uint32_t offset = header_size;
    while (offset < buffer_length)
    {
        int data_item_start = offset;
        proto_item *data_item = proto_tree_add_item(busmirroring_tree, proto_busmirroring, tvb, offset, 0, ENC_NA);
        proto_item_set_text(data_item, "Data Item #%d", data_item_index);
        ++data_item_index;
        col_clear(pinfo->cinfo, COL_INFO);
        col_add_fstr(pinfo->cinfo, COL_INFO, "Busmirroring Seq=%u Len=%u DataItem=%u",
            tvb_get_uint8(tvb, 1), tvb_get_uint16(tvb, 12, ENC_BIG_ENDIAN), data_item_index);
        if (offset + 2 > buffer_length) {
            expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
            return buffer_length;
        }
        proto_tree *data_tree = proto_item_add_subtree(data_item, ett_data_item);
        proto_tree_add_item(data_tree, hf_timestamp, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
        proto_item_set_len(data_item, offset - data_item_start);

        if (offset + 1 > buffer_length) {
            expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
            return buffer_length;
        }
        uint8_t flags = tvb_get_uint8(tvb, offset);
        proto_tree_add_item(data_tree, hf_network_state_available, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_frame_id_available, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_payload_available, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(data_tree, hf_network_type, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_item_set_len(data_item, offset - data_item_start);

        if (offset + 1 > buffer_length) {
            expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
            return buffer_length;
        }
        proto_tree_add_item(data_tree, hf_network_id, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
        proto_item_set_len(data_item, offset - data_item_start);

        bool is_can_fd = false;
        uint8_t type = flags & 0x1F;
        switch (type)
        {
        case NETWORK_TYPE_CAN:
        {
            proto_item_append_text(data_item, ": CAN");
        }
        break;
        case NETWORK_TYPE_LIN:
        {
            proto_item_append_text(data_item, ": LIN");
        }
        break;
        case NETWORK_TYPE_FLEXRAY:
        {
            proto_item_append_text(data_item, ": FlexRay");
        }
        break;
        default:
            expert_add_info(pinfo, data_item, &ei_network_type_invalid);
            break;
        }
        uint8_t has_network_state = flags & 0x80;
        if (has_network_state)
        {
            if (offset + 1 > buffer_length) {
                expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
                return buffer_length;
            }
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
            offset += 1;
            proto_item_set_len(data_item, offset - data_item_start);
        }
        uint8_t has_frame_id = flags & 0x40;
        if (has_frame_id)
        {
            switch (type)
            {
            case NETWORK_TYPE_CAN:
            {
                if (offset + 4 > buffer_length) {
                    expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
                    return buffer_length;
                }
                proto_item *frame_id_item = proto_tree_add_item(data_item, hf_frame_id, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree *frame_id_tree = proto_item_add_subtree(frame_id_item, ett_frame_id);
                uint8_t can_id_type = tvb_get_uint8(tvb, offset) & 0x80;
                is_can_fd = tvb_get_uint8(tvb, offset) & 0x40;
                proto_tree_add_item(frame_id_tree, hf_can_id_type, tvb, offset, 4, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_can_frame_type, tvb, offset, 4, ENC_BIG_ENDIAN);
                uint32_t can_id = 0;
                proto_tree_add_item_ret_uint(frame_id_tree, hf_can_id, tvb, offset, 4, ENC_BIG_ENDIAN, &can_id);
                if (can_id_type == 0 && can_id > 0x7FF) {
                    expert_add_info(pinfo, frame_id_item, &ei_can_id_invalid);
                }
                offset += 4;
                proto_item_set_len(data_item, offset - data_item_start);
            }
            break;
            case NETWORK_TYPE_LIN:
            {
                if (offset + 1 > buffer_length) {
                    expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
                    return buffer_length;
                }
                proto_item *frame_id_item = proto_tree_add_item(data_item, hf_frame_id, tvb, offset, 1, ENC_BIG_ENDIAN);
                proto_tree *frame_id_tree = proto_item_add_subtree(frame_id_item, ett_frame_id);
                proto_tree_add_item(frame_id_tree, hf_lin_pid, tvb, offset, 1, ENC_BIG_ENDIAN);
                uint8_t pid = tvb_get_uint8(tvb, offset);
                if (!is_lin_pid_valid(pid)) {
                    expert_add_info(pinfo, frame_id_item, &ei_lin_pid_invalid);
                }
                offset += 1;
                proto_item_set_len(data_item, offset - data_item_start);
            }
            break;
            case NETWORK_TYPE_FLEXRAY:
            {
                if (offset + 3 > buffer_length) {
                    expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
                    return buffer_length;
                }
                proto_item* frame_id_item = proto_tree_add_item(data_item, hf_frame_id, tvb, offset, 3, ENC_BIG_ENDIAN);
                proto_tree *frame_id_tree = proto_item_add_subtree(frame_id_item, ett_frame_id);
                proto_tree_add_item(frame_id_tree, hf_flexray_channel_b, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_flexray_channel_a, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_flexray_slot_valid, tvb, offset, 2, ENC_BIG_ENDIAN);
                proto_tree_add_item(frame_id_tree, hf_flexray_slot_id, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
                proto_tree_add_item(frame_id_tree, hf_flexray_cycle, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                proto_item_set_len(data_item, offset - data_item_start);
            }
            break;
            default:
                break;
            }
        }
        uint8_t has_payload = flags & 0x20;
        if (has_payload)
        {
            if (offset + 1 > buffer_length) {
                expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
                return buffer_length;
            }
            uint32_t length = 0;
            proto_item* pi = proto_tree_add_item_ret_uint(data_item, hf_payload_length, tvb, offset, 1, ENC_BIG_ENDIAN, &length);
            switch (type)
            {
            case NETWORK_TYPE_CAN:
            {
                if (is_can_fd) {
                    if (length > 8 && length!=12 && length!=16 && length !=20 &&
                        length !=24 && length != 32 && length!=48 && length!=64 ) {
                        expert_add_info(pinfo, pi, &ei_can_length_invalid);
                    }
                } else{
                    if (length > 8) {
                        expert_add_info(pinfo, pi, &ei_can_length_invalid);
                    }
                }
            }
            break;
            case NETWORK_TYPE_LIN:
            {
                if (length > 8) {
                    expert_add_info(pinfo, pi, &ei_lin_length_invalid);
                }
            }
            break;
            default:
                break;
            }
            offset += 1;
            proto_item_set_len(data_item, offset - data_item_start);
            if (offset + length > buffer_length) {
                expert_add_info(pinfo, data_item, &ei_data_item_incomplete);
                return buffer_length;
            }
            proto_tree_add_item(data_item, hf_payload, tvb, offset, length, ENC_NA);
            offset += length;
            proto_item_set_len(data_item, offset - data_item_start);
        }

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

    proto_busmirroring = proto_register_protocol("Bus Mirroring Protocol", "BusMirroring", "busmirroring");

    proto_register_field_array(proto_busmirroring, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    static ei_register_info ei[] = {
        {
            &ei_data_incomplete,
            { "busmirroring.data_incomplete", PI_UNDECODED, PI_WARN,
              "Data is incomplete", EXPFILL }
        },
        {
            &ei_data_item_incomplete,
            { "busmirroring.data_item_incomplete", PI_UNDECODED, PI_WARN,
              "Data item is incomplete", EXPFILL }
        },
        {
            &ei_network_type_invalid,
            { "busmirroring.network_type_invalid", PI_PROTOCOL, PI_WARN,
              "Network type is invalid", EXPFILL }
        },
        {
            &ei_can_id_invalid,
            { "busmirroring.can_id_invalid", PI_PROTOCOL, PI_WARN,
              "ID of CAN frame is invalid", EXPFILL }
        },
        {
            &ei_lin_pid_invalid,
            { "busmirroring.lin_pid_invalid", PI_PROTOCOL, PI_WARN,
              "PID of LIN frame is invalid", EXPFILL }
        },
        {
            &ei_can_length_invalid,
            { "busmirroring.can_length_invalid", PI_PROTOCOL, PI_WARN,
              "Length of CAN frame is invalid", EXPFILL }
        },
        {
            &ei_lin_length_invalid,
            { "busmirroring.lin_length_invalid", PI_PROTOCOL, PI_WARN,
              "Length of LIN frame is invalid", EXPFILL }
        }
    };

    expert_module_t* expert_busmirroring = expert_register_protocol(proto_busmirroring);
    expert_register_field_array(expert_busmirroring, ei, array_length(ei));
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
