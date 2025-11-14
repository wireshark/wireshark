/* packet-psn.c
 * Routines for PSN packet disassembly
 *
 * Copyright (c) 2025 by Matt Morris <mattm.dev.1[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * Specification:
 * https://github.com/vyv/psn-cpp/blob/master/doc/PosiStageNetprotocol_v2.03_2019_09_09.pdf
 * https://posistage.net/wp-content/uploads/2019/01/PosiStageNetprotocol_v2.02_2016_09_15.pdf
 * https://posistage.net/wp-content/uploads/2018/07/PosiStageNetprotocolv1.7.pdf
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* Include files */
#include "config.h"
#include <epan/packet.h>
#include <epan/unit_strings.h>
#include <epan/tfs.h>
#include <epan/expert.h>

/* constants */
#define PSN_INFO_PACKET    0x6756
#define PSN_DATA_PACKET    0x6755
#define PSN_V1_INFO_PACKET 0x503c
#define PSN_V1_DATA_PACKET 0x6754

#define PSN_INFO_PACKET_HEADER 0x0000
#define PSN_INFO_SYSTEM_NAME   0x0001
#define PSN_INFO_TRACKER_LIST  0x0002

#define PSN_INFO_TRACKER_NAME  0x0000

#define PSN_DATA_PACKET_HEADER 0x0000
#define PSN_DATA_TRACKER_LIST  0x0001

#define PSN_DATA_TRACKER_POS       0x0000
#define PSN_DATA_TRACKER_SPEED     0x0001
#define PSN_DATA_TRACKER_ORI       0x0002
#define PSN_DATA_TRACKER_STATUS    0x0003
#define PSN_DATA_TRACKER_ACCEL     0x0004
#define PSN_DATA_TRACKER_TRGTPOS   0x0005
#define PSN_DATA_TRACKER_TIMESTAMP 0x0006


static int proto_psn;

static dissector_handle_t psn_handle;

static dissector_handle_t xml_dissector_handle;

/*  Open/Close trees */
static int ett_psn;

static int ett_psn_info_chunk;
static int ett_psn_data_chunk;
static int ett_psn_tracker_chunk;
static int ett_psn_tracker_info_chunk;
static int ett_psn_tracker_data_chunk;

static int ett_psn_chunk_data_field;

static int ett_psn_v1_header;
static int ett_psn_v1_tracker;

/* Expert Info  */
static expert_field ei_psn_chunk_id;
static expert_field ei_psn_chunk_len;

/*  Register fields */
static int hf_psn_info_chunk;
static int hf_psn_data_chunk;
static int hf_psn_tracker_chunk;
static int hf_psn_tracker_info_chunk;
static int hf_psn_tracker_data_chunk;

static int hf_psn_base_chunk_id;
static int hf_psn_info_chunk_id;
static int hf_psn_data_chunk_id;
static int hf_psn_tracker_id;
static int hf_psn_tracker_data_chunk_id;
static int hf_psn_tracker_info_chunk_id;

static int hf_psn_chunk_data_field;
static int hf_psn_chunk_length;
static int hf_psn_chunk_has_subchunks;

static int hf_psn_packet_timestamp;
static int hf_psn_version_high;
static int hf_psn_version_low;
static int hf_psn_frame_id;
static int hf_psn_frame_packet_count;

static int hf_psn_system_name;
static int hf_psn_tracker_name;

static int hf_psn_position_x;
static int hf_psn_position_y;
static int hf_psn_position_z;
static int hf_psn_speed_x;
static int hf_psn_speed_y;
static int hf_psn_speed_z;
static int hf_psn_ori_x;
static int hf_psn_ori_y;
static int hf_psn_ori_z;
static int hf_psn_accel_x;
static int hf_psn_accel_y;
static int hf_psn_accel_z;
static int hf_psn_trgtpos_x;
static int hf_psn_trgtpos_y;
static int hf_psn_trgtpos_z;

static int hf_psn_validity;
static int hf_psn_tracker_timestamp;

/* V1 only fields */
static int hf_psn_v1_header;
static int hf_psn_v1_identifier;
static int hf_psn_v1_tracker;
static int hf_psn_v1_position;
static int hf_psn_v1_velocity;
static int hf_psn_v1_packet_counter;
static int hf_psn_v1_world_id;
static int hf_psn_v1_tracker_count;
static int hf_psn_v1_frame_index;
static int hf_psn_v1_object_state;
static int hf_psn_v1_info_xml;
static int hf_psn_v1_reserved;

static int * const chunk_data_fields[] = {
    &hf_psn_chunk_length,
    &hf_psn_chunk_has_subchunks,
    NULL
};


static const value_string psn_base_chunk_id_names[] = {
  { PSN_INFO_PACKET,    "Information Packet" },
  { PSN_DATA_PACKET,    "Data Packet" },
  { PSN_V1_INFO_PACKET, "V1 Information Packet" },
  { PSN_V1_DATA_PACKET, "V1 Data Packet" },
  { 0,                         NULL },
};

static const value_string psn_info_chunk_id_names[] = {
  { PSN_INFO_PACKET_HEADER, "Packet Header" },
  { PSN_INFO_SYSTEM_NAME,   "System Name" },
  { PSN_INFO_TRACKER_LIST,  "Tracker List" },
  { 0,                      NULL },
};

static const value_string psn_tracker_info_chunk_id_names[] = {
  { PSN_INFO_TRACKER_NAME, "Tracker Name" },
  { 0,                      NULL },
};

static const value_string psn_data_chunk_id_names[] = {
  { PSN_DATA_PACKET_HEADER, "Packet Header" },
  { PSN_DATA_TRACKER_LIST,  "Tracker List" },
  { 0,                      NULL },
};

static const value_string psn_tracker_data_chunk_id_names[] = {
  { PSN_DATA_TRACKER_POS,       "Tracker Position" },
  { PSN_DATA_TRACKER_SPEED,     "Tracker Speed" },
  { PSN_DATA_TRACKER_ORI,       "Tracker Origin" },
  { PSN_DATA_TRACKER_STATUS,    "Tracker Status" },
  { PSN_DATA_TRACKER_ACCEL,     "Tracker Acceleration" },
  { PSN_DATA_TRACKER_TRGTPOS,   "Tracker Target Position" },
  { PSN_DATA_TRACKER_TIMESTAMP, "Tracker Timestamp" },
  { 0,                          NULL },
};
static const value_string psn_tracker_data_names[] = {
  { PSN_DATA_TRACKER_POS,       "Position" },
  { PSN_DATA_TRACKER_SPEED,     "Speed" },
  { PSN_DATA_TRACKER_ORI,       "Origin" },
  { PSN_DATA_TRACKER_STATUS,    "Status" },
  { PSN_DATA_TRACKER_ACCEL,     "Acceleration" },
  { PSN_DATA_TRACKER_TRGTPOS,   "Target Position" },
  { PSN_DATA_TRACKER_TIMESTAMP, "Timestamp" },
  { 0,                          NULL },
};

static const value_string psn_v1_identifier[] = {
  { 0x6754, "Start of Packet" },
  { 0x4576, "End of Packet" },
  { 0,      NULL },
};



/******************************************************************************/
/* Dissect protocol                                                           */

static proto_tree* dissect_psn_chunk_header(tvbuff_t *tvb, proto_tree *tree, proto_item** ti, int* offset, int* chunk_end, uint32_t* chunk_id, uint16_t* chunk_data_len, const int hf_chunk, const int ett_chunk, const int hf_chunk_id) {
    *ti = proto_tree_add_item(tree, hf_chunk, tvb, *offset, -1, ENC_NA);
    proto_tree *chunk_tree = proto_item_add_subtree(*ti, ett_chunk);

    /* Chunk Header */
    proto_tree_add_item_ret_uint(chunk_tree, hf_chunk_id, tvb, *offset, 2, ENC_LITTLE_ENDIAN, chunk_id);
    *offset+=2;

    *chunk_data_len = tvb_get_uint16(tvb, *offset, ENC_LITTLE_ENDIAN) & 0x7FFF;
    proto_item_set_len(*ti, (*chunk_data_len)+4);
    proto_tree_add_bitmask_with_flags(chunk_tree, tvb, *offset, hf_psn_chunk_data_field, ett_psn_chunk_data_field, chunk_data_fields, ENC_LITTLE_ENDIAN, BMT_NO_FLAGS);
    *offset+=2;
    *chunk_end = (*offset)+(*chunk_data_len);

    return chunk_tree;
}

static int dissect_psn_data_tracker(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    int chunk_end;
    uint32_t track_id;
    uint16_t track_data_len;
    proto_item *track_item;
    proto_tree *track_tree = dissect_psn_chunk_header(tvb, tree, &track_item, &offset, &chunk_end,
        &track_id, &track_data_len, hf_psn_tracker_data_chunk, ett_psn_tracker_data_chunk, hf_psn_tracker_data_chunk_id);

    const uint8_t* tracker_name = val_to_str_const(track_id, psn_tracker_data_names, "Unknown");
    proto_item_append_text(track_item, ": %s", tracker_name);

    switch (track_id) {
        case PSN_DATA_TRACKER_POS:
            proto_tree_add_item(track_tree, hf_psn_position_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_position_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_position_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;
        case PSN_DATA_TRACKER_SPEED:
            proto_tree_add_item(track_tree, hf_psn_speed_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_speed_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_speed_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;
        case PSN_DATA_TRACKER_ORI:
            proto_tree_add_item(track_tree, hf_psn_ori_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_ori_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_ori_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;
        case PSN_DATA_TRACKER_STATUS:
            proto_tree_add_item(track_tree, hf_psn_validity, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;
        case PSN_DATA_TRACKER_ACCEL:
            proto_tree_add_item(track_tree, hf_psn_accel_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_accel_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_accel_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;
        case PSN_DATA_TRACKER_TRGTPOS:
            proto_tree_add_item(track_tree, hf_psn_trgtpos_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_trgtpos_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            proto_tree_add_item(track_tree, hf_psn_trgtpos_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
            offset+=4;
            break;
        case PSN_DATA_TRACKER_TIMESTAMP:
            proto_tree_add_item(track_tree, hf_psn_tracker_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS);
            offset+=8;
            break;
        default:
            /* Unknown chunk type */
            expert_add_info(pinfo, track_tree, &ei_psn_chunk_id);
            return chunk_end;
    }

    if (offset != chunk_end)
        expert_add_info(pinfo, track_tree, &ei_psn_chunk_len);
    return chunk_end;
}

static int dissect_psn_data_tracker_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    int chunk_end;
    uint32_t tracker_id;
    uint16_t chunk_data_len;
    proto_item *chunk_item;
    proto_tree *chunk_tree = dissect_psn_chunk_header(tvb, tree, &chunk_item, &offset, &chunk_end,
        &tracker_id, &chunk_data_len, hf_psn_tracker_chunk, ett_psn_tracker_chunk, hf_psn_tracker_id);

    proto_item_append_text(chunk_item, ", tracker ID: %u", tracker_id);

    while (offset < chunk_end) {
        offset = dissect_psn_data_tracker(tvb, pinfo, chunk_tree, offset);
    }

    if (offset != chunk_end)
        expert_add_info(pinfo, chunk_tree, &ei_psn_chunk_len);
    return chunk_end;
}

static int dissect_psn_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    int chunk_end;
    uint32_t chunk_id;
    uint16_t chunk_data_len;
    proto_item *chunk_item;
    proto_tree *chunk_tree = dissect_psn_chunk_header(tvb, tree, &chunk_item, &offset, &chunk_end,
        &chunk_id, &chunk_data_len, hf_psn_data_chunk, ett_psn_data_chunk, hf_psn_data_chunk_id);

    switch (chunk_id) {
        case PSN_DATA_PACKET_HEADER: {
            proto_tree_add_item(chunk_tree, hf_psn_packet_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS);
            offset+=8;
            proto_tree_add_item(chunk_tree, hf_psn_version_high, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(chunk_tree, hf_psn_version_low, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            uint32_t frame_id;
            proto_tree_add_item_ret_uint(chunk_tree, hf_psn_frame_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &frame_id);
            offset+=1;
            proto_tree_add_item(chunk_tree, hf_psn_frame_packet_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", Frame %3u", frame_id);
            proto_item_append_text(chunk_item, ": Header");
            break;
        }
        case PSN_DATA_TRACKER_LIST: {
            unsigned tracker_count = 0;
            while (offset < chunk_end) {
                offset = dissect_psn_data_tracker_list(tvb, pinfo, chunk_tree, offset);
                tracker_count++;
            }
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %u Trackers", tracker_count);
            proto_item_append_text(chunk_item, ": Tracker List, %u trackers", tracker_count);
            break;
        }
        default:
            /* Unknown Chunk Type */
            expert_add_info(pinfo, chunk_tree, &ei_psn_chunk_id);
            return chunk_end;
    }

    if (offset != chunk_end)
        expert_add_info(pinfo, chunk_tree, &ei_psn_chunk_len);
    return chunk_end;
}

static int dissect_psn_info_tracker_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    int chunk_end;
    uint32_t tracker_id;
    uint16_t chunk_data_len;
    proto_item *chunk_item;
    proto_tree *chunk_tree = dissect_psn_chunk_header(tvb, tree, &chunk_item, &offset, &chunk_end,
        &tracker_id, &chunk_data_len, hf_psn_tracker_chunk, ett_psn_tracker_chunk, hf_psn_tracker_id);

    proto_item_append_text(chunk_item, ", tracker ID: %u", tracker_id);

    while (offset < chunk_end) {
        int name_chunk_end;
        uint32_t name_id;
        uint16_t name_data_len;
        proto_item *name_item;
        proto_tree *name_tree = dissect_psn_chunk_header(tvb, chunk_tree, &name_item, &offset, &name_chunk_end,
            &name_id, &name_data_len, hf_psn_tracker_info_chunk, ett_psn_tracker_info_chunk, hf_psn_tracker_info_chunk_id);

        if (name_id == PSN_INFO_TRACKER_NAME) {
            const uint8_t* tracker_name;
            proto_tree_add_item_ret_string(name_tree, hf_psn_tracker_name, tvb, offset, name_data_len, ENC_ASCII, pinfo->pool, &tracker_name);

            proto_item_append_text(name_item, ": Tracker Name, %s", tracker_name);
        }
        /* Skip all the data, even if unknown chunk */
        offset+=name_data_len;
    }

    if (offset != chunk_end)
        expert_add_info(pinfo, chunk_tree, &ei_psn_chunk_len);
    return chunk_end;
}

static int dissect_psn_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    int chunk_end;
    uint32_t chunk_id;
    uint16_t chunk_data_len;
    proto_item *chunk_item;
    proto_tree *chunk_tree = dissect_psn_chunk_header(tvb, tree, &chunk_item, &offset, &chunk_end,
        &chunk_id, &chunk_data_len, hf_psn_info_chunk, ett_psn_info_chunk, hf_psn_info_chunk_id);

    switch (chunk_id) {
        case PSN_INFO_PACKET_HEADER: {
            proto_tree_add_item(chunk_tree, hf_psn_packet_timestamp, tvb, offset, 8, ENC_LITTLE_ENDIAN|ENC_TIME_USECS);
            offset+=8;
            proto_tree_add_item(chunk_tree, hf_psn_version_high, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            proto_tree_add_item(chunk_tree, hf_psn_version_low, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;
            uint32_t frame_id;
            proto_tree_add_item_ret_uint(chunk_tree, hf_psn_frame_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &frame_id);
            offset+=1;
            proto_tree_add_item(chunk_tree, hf_psn_frame_packet_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
            offset+=1;

            col_append_fstr(pinfo->cinfo, COL_INFO, ", Frame %3u", frame_id);
            proto_item_append_text(chunk_item, ": Header");
            break;
        }
        case PSN_INFO_SYSTEM_NAME: {
            const uint8_t* name;
            proto_tree_add_item_ret_string(chunk_tree, hf_psn_system_name, tvb, offset, chunk_data_len, ENC_ASCII, pinfo->pool, &name);
            offset+=chunk_data_len;

            proto_item_append_text(chunk_item, ": System Name, %s", name);
            break;
        }
        case PSN_INFO_TRACKER_LIST: {
            unsigned tracker_count = 0;
            while (offset < chunk_end) {
                offset = dissect_psn_info_tracker_list(tvb, pinfo, chunk_tree, offset);
                tracker_count++;
            }
            proto_item_append_text(chunk_item, ": Tracker List, %u trackers", tracker_count);
            col_append_fstr(pinfo->cinfo, COL_INFO, ", %u Trackers", tracker_count);
            break;
        }
        default:
            /* Unknown Chunk Type */
            expert_add_info(pinfo, chunk_tree, &ei_psn_chunk_id);
            return chunk_end;
    }

    if (offset != chunk_end)
        expert_add_info(pinfo, chunk_tree, &ei_psn_chunk_len);
    return chunk_end;
}

static int dissect_psn_v1_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset) {
    proto_tree_add_item(tree, hf_psn_v1_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    proto_item* header = proto_tree_add_item(tree, hf_psn_v1_header, tvb, offset, 16, ENC_NA);
    proto_tree* header_tree = proto_item_add_subtree(header, ett_psn_v1_header);

    proto_tree_add_item(header_tree, hf_psn_v1_packet_counter, tvb, offset, 4, ENC_LITTLE_ENDIAN);
    offset+=4;
    proto_tree_add_item(header_tree, hf_psn_version_high, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;
    proto_tree_add_item(header_tree, hf_psn_version_low, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;
    proto_tree_add_item(header_tree, hf_psn_v1_world_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;
    uint32_t tracker_count;
    proto_tree_add_item_ret_uint(header_tree, hf_psn_v1_tracker_count, tvb, offset, 2, ENC_LITTLE_ENDIAN, &tracker_count);
    offset+=2;
    uint32_t frame_id;
    proto_tree_add_item_ret_uint(header_tree, hf_psn_frame_id, tvb, offset, 1, ENC_LITTLE_ENDIAN, &frame_id);
    offset+=1;
    proto_tree_add_item(header_tree, hf_psn_frame_packet_count, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;
    proto_tree_add_item(header_tree, hf_psn_v1_frame_index, tvb, offset, 1, ENC_LITTLE_ENDIAN);
    offset+=1;
    /* reserved */
    proto_tree_add_item(header_tree, hf_psn_v1_reserved, tvb, offset, 3, ENC_NA);
    offset+=3;

    col_append_fstr(pinfo->cinfo, COL_INFO, ", Frame %3u, %u Trackers", frame_id, tracker_count);

    for (unsigned int i = 0; i < tracker_count; i++) {
        proto_item* tracker = proto_tree_add_item(tree, hf_psn_v1_tracker, tvb, offset, 32, ENC_NA);
        proto_tree* tracker_tree = proto_item_add_subtree(tracker, ett_psn_v1_tracker);

        uint32_t tracker_id;
        proto_tree_add_item_ret_uint(tracker_tree, hf_psn_tracker_id, tvb, offset, 2, ENC_LITTLE_ENDIAN, &tracker_id);
        offset+=2;
        proto_tree_add_item(tracker_tree, hf_psn_v1_object_state, tvb, offset, 2, ENC_LITTLE_ENDIAN);
        offset+=2;
        /* reserved */
        proto_tree_add_item(tracker_tree, hf_psn_v1_reserved, tvb, offset, 4, ENC_NA);
        offset+=4;
        proto_tree_add_item(tracker_tree, hf_psn_position_x, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(tracker_tree, hf_psn_position_y, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_tree_add_item(tracker_tree, hf_psn_position_z, tvb, offset, 4, ENC_LITTLE_ENDIAN);
        offset+=4;
        proto_item_prepend_text(
            proto_tree_add_item(tracker_tree, hf_psn_speed_x, tvb, offset, 4, ENC_LITTLE_ENDIAN),
            "Speed ");
        offset+=4;
        proto_item_prepend_text(
            proto_tree_add_item(tracker_tree, hf_psn_speed_y, tvb, offset, 4, ENC_LITTLE_ENDIAN),
            "Speed ");
        offset+=4;
        proto_item_prepend_text(
            proto_tree_add_item(tracker_tree, hf_psn_speed_z, tvb, offset, 4, ENC_LITTLE_ENDIAN),
            "Speed ");
        offset+=4;

        proto_item_append_text(tracker, ", ID: %u", tracker_id);
    }
    proto_tree_add_item(tree, hf_psn_v1_identifier, tvb, offset, 2, ENC_LITTLE_ENDIAN);
    offset+=2;

    return offset;
}

static int
dissect_psn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* Check it's a PSN packet */
    if (tvb_captured_length(tvb) < 2) {
        return 0;
    }

    uint16_t chunk_id = tvb_get_uint16(tvb, 0, ENC_LITTLE_ENDIAN);
    if (try_val_to_str(chunk_id, psn_base_chunk_id_names) == NULL) {
        return 0;
    }

    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PSN");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_psn, tvb, 0, -1, ENC_NA);
    proto_tree *psn_tree = proto_item_add_subtree(ti, ett_psn);

    /* Chunk Header */
    switch (chunk_id) {
        case PSN_INFO_PACKET:
        case PSN_DATA_PACKET: {
            proto_tree_add_item(psn_tree, hf_psn_base_chunk_id, tvb, offset, 2, ENC_LITTLE_ENDIAN);
            offset+=2;

            uint16_t chunk_data_len = tvb_get_uint16(tvb, offset, ENC_LITTLE_ENDIAN) & 0x7FFF;
            proto_item_set_len(ti, chunk_data_len+4);
            proto_tree_add_bitmask_with_flags(psn_tree, tvb, offset, hf_psn_chunk_data_field, ett_psn_chunk_data_field, chunk_data_fields, ENC_LITTLE_ENDIAN, BMT_NO_FLAGS);
            offset+=2;
            int chunk_end = offset+chunk_data_len;

            if (chunk_id == PSN_INFO_PACKET) {
                proto_item_append_text(ti, ", V2 Info Packet");
                col_set_str(pinfo->cinfo, COL_INFO, "PSN V2 Info");
                while (offset < chunk_end) {
                    offset = dissect_psn_info(tvb, pinfo, psn_tree, offset);
                }
            } else {
                proto_item_append_text(ti, ", V2 Data Packet");
                col_set_str(pinfo->cinfo, COL_INFO, "PSN V2 Data");
                while (offset < chunk_end) {
                    offset = dissect_psn_data(tvb, pinfo, psn_tree, offset);
                }
            }
            return chunk_end;
        }
        case PSN_V1_DATA_PACKET:
            proto_item_append_text(ti, ", V1 Data Packet");
            col_set_str(pinfo->cinfo, COL_INFO, "PSN V1 Data");
            offset = dissect_psn_v1_data(tvb, pinfo, psn_tree, offset);
            proto_item_set_len(ti, offset);
            return offset;
        case PSN_V1_INFO_PACKET:
            if (tvb_memeql(tvb, 0, "<PSN>", 5) == 0) {
                proto_item_append_text(ti, ", V1 Info Packet");
                col_set_str(pinfo->cinfo, COL_INFO, "PSN V1 Info");
            } else if (tvb_memeql(tvb, 0, "<PSN_config>", 12) == 0) {
                proto_item_append_text(ti, ", V1 Config Packet");
                col_set_str(pinfo->cinfo, COL_INFO, "PSN V1 Config");
            } else if (tvb_memeql(tvb, 0, "<PSN_config_ACK>", 16) == 0) {
                proto_item_append_text(ti, ", V1 Config Ack Packet");
                col_set_str(pinfo->cinfo, COL_INFO, "PSN V1 Config Ack");
            } else {
                proto_item_append_text(ti, ", V1 XML Packet");
                col_set_str(pinfo->cinfo, COL_INFO, "PSN V1 XML");
            }
            return call_dissector(xml_dissector_handle, tvb, pinfo, tree);
        default:
            /* UNREACHABLE */
            return 0;
    }
}

/******************************************************************************/
/* Register protocol                                                          */
void
proto_register_psn(void) {
    static hf_register_info hf[] = {
        { &hf_psn_info_chunk,
            { "Info Chunk", "psn.info",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_data_chunk,
            { "Data Chunk", "psn.data",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_tracker_chunk,
            { "Tracker Chunk", "psn.tracker",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_tracker_data_chunk,
            { "Tracker Data Chunk", "psn.tracker.data",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_tracker_info_chunk,
            { "Tracker Info Chunk", "psn.tracker.info",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_psn_base_chunk_id,
            { "Chunk ID", "psn.chunk_id",
            FT_UINT16, BASE_HEX,
            VALS(psn_base_chunk_id_names), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_info_chunk_id,
            { "Chunk ID", "psn.info.chunk_id",
            FT_UINT16, BASE_HEX,
            VALS(psn_info_chunk_id_names), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_data_chunk_id,
            { "Chunk ID", "psn.data.chunk_id",
            FT_UINT16, BASE_HEX,
            VALS(psn_data_chunk_id_names), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_tracker_id,
            { "Tracker ID", "psn.tracker.id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_tracker_data_chunk_id,
            { "Chunk ID", "psn.tracker.data.chunk_id",
            FT_UINT16, BASE_HEX,
            VALS(psn_tracker_data_chunk_id_names), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_tracker_info_chunk_id,
            { "Chunk ID", "psn.tracker.info.chunk_id",
            FT_UINT16, BASE_HEX,
            VALS(psn_tracker_info_chunk_id_names), 0x0,
            NULL, HFILL }
        },

        { &hf_psn_chunk_data_field,
            { "Chunk Header", "psn.chunk.header",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_chunk_length,
            { "Length", "psn.chunk.len",
            FT_UINT16, BASE_DEC,
            NULL, 0x7FFF,
            NULL, HFILL }
        },
        { &hf_psn_chunk_has_subchunks,
            { "Has Sub Chunks", "psn.chunk.has_subchunks",
            FT_BOOLEAN, 16,
            TFS(&tfs_yes_no), 0x8000,
            NULL, HFILL }
        },

        { &hf_psn_packet_timestamp,
            { "Timestamp", "psn.timestamp",
            FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_version_high,
            { "Version High", "psn.version_high",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_version_low,
            { "Version Low", "psn.version_low",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_frame_id,
            { "Frame ID", "psn.frame_id",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_frame_packet_count,
            { "Frame Packet Count", "psn.frame_packet_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },


        { &hf_psn_system_name,
            { "System Name", "psn.info.system_name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_tracker_name,
            { "Tracker Name", "psn.tracker.info.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_psn_position_x,
            { "X", "psn.position.x",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_position_y,
            { "Y", "psn.position.y",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_position_z,
            { "Z", "psn.position.z",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_speed_x,
            { "X", "psn.speed.x",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_m_s), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_speed_y,
            { "Y", "psn.speed.y",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_m_s), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_speed_z,
            { "Z", "psn.speed.z",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_m_s), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_ori_x,
            { "X", "psn.origin.x",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_ori_y,
            { "Y", "psn.origin.y",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_ori_z,
            { "Z", "psn.origin.z",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_accel_x,
            { "X", "psn.acceleration.x",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meter_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_accel_y,
            { "Y", "psn.acceleration.y",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meter_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_accel_z,
            { "Z", "psn.acceleration.z",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meter_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_trgtpos_x,
            { "X", "psn.target_pos.x",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_trgtpos_y,
            { "Y", "psn.target_pos.y",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_trgtpos_z,
            { "Z", "psn.target_pos.z",
            FT_FLOAT, BASE_NONE|BASE_UNIT_STRING,
            UNS(&units_meters), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_validity,
            { "Validity", "psn.tracker.data.validity",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_tracker_timestamp,
            { "Timestamp", "psn.tracker.data.timestamp",
            FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_psn_v1_header,
            { "Header", "psn.v1.header",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_identifier,
            { "Identifier", "psn.v1.identifier",
            FT_UINT16, BASE_HEX,
            VALS(psn_v1_identifier), 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_tracker,
            { "Tracker", "psn.v1.tracker",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_position,
            { "Position", "psn.v1.position",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_velocity,
            { "Velocity", "psn.v1.velocity",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_packet_counter,
            { "Packet Counter", "psn.v1.packet_counter",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_world_id,
            { "World ID", "psn.v1.world_id",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_tracker_count,
            { "Tracker Count", "psn.v1.tracker_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_frame_index,
            { "Frame Index", "psn.v1.frame_index",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_object_state,
            { "Object State", "psn.v1.object_state",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_info_xml,
            { "V1 Info XML", "psn.v1.info_xml",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_psn_v1_reserved,
            { "Reserved", "psn.v1.reserved",
            FT_BYTES, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_psn,

        &ett_psn_info_chunk,
        &ett_psn_data_chunk,
        &ett_psn_tracker_chunk,
        &ett_psn_tracker_info_chunk,
        &ett_psn_tracker_data_chunk,

        &ett_psn_chunk_data_field,

        &ett_psn_v1_header,
        &ett_psn_v1_tracker,
    };

    static ei_register_info ei[] = {
        { &ei_psn_chunk_id,  { "psn.chunk_id.unknown", PI_PROTOCOL, PI_ERROR, "Unknown chunk ID for this location", EXPFILL }},
        { &ei_psn_chunk_len, { "psn.chunk.len.mismatch", PI_PROTOCOL, PI_WARN, "Mismatch between reported chunk length and consumed data", EXPFILL }},
    };

    proto_psn = proto_register_protocol("PosiStageNet", "PSN", "psn");

    proto_register_field_array(proto_psn, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t* expert_psn = expert_register_protocol(proto_psn);
    expert_register_field_array(expert_psn, ei, array_length(ei));

    psn_handle = register_dissector_with_description (
        "psn",          /* dissector name           */
        "PSN",          /* dissector description    */
        dissect_psn,    /* dissector function       */
        proto_psn       /* protocol being dissected */
    );
}

/******************************************************************************/
/* Register handoff                                                           */
void
proto_reg_handoff_psn(void)
{
    dissector_add_uint_with_preference("udp.port", 56565, psn_handle);

    xml_dissector_handle = find_dissector_add_dependency("xml", proto_psn);
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
