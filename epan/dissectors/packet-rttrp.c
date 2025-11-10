/* packet-rttrp.c
 * Routines for RTTrP packet disassembly
 *
 * Copyright (c) 2025 by Matt Morris <mattm.dev.1[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * Specification:
 * https://rttrp.github.io/RTTrP-Wiki/index.html
 * https://rttrp.github.io/RTTrP-Wiki/RTTrPM.html
 * https://rttrp.github.io/RTTrP-Wiki/RTTrPL.html
 * https://rttrp.github.io/RTTrP-Wiki/BlackTrax.html
 *
 * Old Zone Method:
 * https://github.com/RTTrP/RTTrP-Wiki/commit/2ddb420fa3e23e2fb7f19b51702a835026b32cf5
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* Include files */
#include "config.h"
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/unit_strings.h>
#include <epan/expert.h>

/* constants */
#define RTTRP_INT_SIG_LE 0x5441
#define RTTRP_INT_SIG_BE 0x4154

#define RTTRP_FLOAT_SIG_MOTION_BE   0x4334
#define RTTRP_FLOAT_SIG_MOTION_LE   0x3443
#define RTTRP_FLOAT_SIG_LIGHTING_BE 0x4434
#define RTTRP_FLOAT_SIG_LIGHTING_LE 0x3444

#define RTTRP_PACKET_FORMAT_RAW      0x00
#define RTTRP_PACKET_FORMAT_PROTOBUF 0x01
#define RTTRP_PACKET_FORMAT_THRIFT   0x02

#define RTTRP_MODULE_TRACKABLE                    0x01
#define RTTRP_MODULE_TRACKABLE_WITH_TIMESTAMP     0x51
#define RTTRP_MODULE_CENTROID_POSITION            0x02
#define RTTRP_MODULE_ORIENTATION_QUATERNION       0x03
#define RTTRP_MODULE_ORIENTATION_EULER            0x04
#define RTTRP_MODULE_TRACKED_POINT_POSITION       0x06
#define RTTRP_MODULE_CENTROID_ACCEL_VELOCITY      0x20
#define RTTRP_MODULE_TRACKED_POINT_ACCEL_VELOCITY 0x21
#define RTTRP_MODULE_ZONE_COLLISION_DETECTION     0x22
#define RTTRP_MODULE_LIGHTING_OUTPUT              0x07
#define RTTRP_MODULE_LIGHTING_SYNC                0x08
#define RTTRP_MODULE_UNIVERSE                     0x09
#define RTTRP_MODULE_SPOT                         0x0A

#define RTTRPL_ACTION_SNAPSHOT 0x00
#define RTTRPL_ACTION_UPDATE   0x01

#define RTTRPL_HOLD_TIME_FOREVER 0x00

static int proto_rttrp;

static dissector_handle_t rttrp_handle;


/*  Open/Close trees */
static int ett_rttrp;

static int ett_rttrp_module_trackable;
static int ett_rttrp_module_tracker_data;
static int ett_rttrp_module_lighting;
static int ett_rttrp_module_universe;
static int ett_rttrp_module_spot;

static int ett_rttrp_collision_zones;
static int ett_rttrp_collision_zone;

static int ett_rttrp_lighting_spots;
static int ett_rttrp_lighting_chan;

/* Expert Info  */
static expert_field ei_rttrp_module_type;
static expert_field ei_rttrp_module_size;

/*  Register fields */

/* RTTrP Header */
static int hf_rttrp_int_signature;
static int hf_rttrp_float_signature;
static int hf_rttrp_header_version;
static int hf_rttrp_packet_id;
static int hf_rttrp_packet_format;
static int hf_rttrp_packet_size;
static int hf_rttrp_packet_context;
static int hf_rttrp_packet_module_count;

static int hf_rttrp_module_trackable;
static int hf_rttrp_module_tracker_data;
static int hf_rttrp_module_lighting;
static int hf_rttrp_module_universe;
static int hf_rttrp_module_spot;

static int hf_rttrp_module_trackable_type;
static int hf_rttrp_module_tracker_data_type;
static int hf_rttrp_module_lighting_type;
static int hf_rttrp_module_universe_type;
static int hf_rttrp_module_spot_type;

static int hf_rttrp_module_trackable_size;
static int hf_rttrp_module_tracker_data_size;
static int hf_rttrp_module_lighting_size;
static int hf_rttrp_module_universe_size;
static int hf_rttrp_module_spot_size;

static int hf_rttrp_module_latency;

/* Trackable Module */
static int hf_rttrp_trackable_name_length;
static int hf_rttrp_trackable_name;
static int hf_rttrp_trackable_timestamp;
static int hf_rttrp_trackable_module_count;
static int hf_rttrp_trackable_modules;

/* Centroid/Point position */
static int hf_rttrp_position_x;
static int hf_rttrp_position_y;
static int hf_rttrp_position_z;
static int hf_rttrp_point_index;

static int hf_rttrp_orientation_qx;
static int hf_rttrp_orientation_qy;
static int hf_rttrp_orientation_qz;
static int hf_rttrp_orientation_qw;
static int hf_rttrp_orientation_order;
static int hf_rttrp_orientation_r1;
static int hf_rttrp_orientation_r2;
static int hf_rttrp_orientation_r3;

static int hf_rttrp_acceleration_x;
static int hf_rttrp_acceleration_y;
static int hf_rttrp_acceleration_z;
static int hf_rttrp_velocity_x;
static int hf_rttrp_velocity_y;
static int hf_rttrp_velocity_z;

static int hf_rttrp_zone_count;
static int hf_rttrp_zones;
static int hf_rttrp_zone;
static int hf_rttrp_zone_size;
static int hf_rttrp_zone_name_length;
static int hf_rttrp_zone_name;
static int hf_rttrp_zone_names_delimited_length;

/* Lighting Output */
static int hf_rttrp_lighting_sequence;
static int hf_rttrp_lighting_action;
static int hf_rttrp_lighting_hold_time;
static int hf_rttrp_lighting_universe_count;

static int hf_rttrp_universe_id;
static int hf_rttrp_universe_spot_count;
static int hf_rttrp_universe_spots;

static int hf_rttrp_spot_id;
static int hf_rttrp_spot_offset;
static int hf_rttrp_spot_channel_count;

static int hf_rttrp_channel;
static int hf_rttrp_channel_offset;
static int hf_rttrp_channel_xfade;
static int hf_rttrp_channel_value;

/* Lighting Sync */
static int hf_rttrp_sync_device_id;
static int hf_rttrp_sync_device_sub_id_0;
static int hf_rttrp_sync_device_sub_id_1;
static int hf_rttrp_sync_device_sequence_number;


static const value_string rttrp_int_sig_names[] = {
    { RTTRP_INT_SIG_BE, "RTTrP Big Endian" },
    { RTTRP_INT_SIG_LE, "RTTrP Little Endian" },
    { 0,                NULL },
};

static const value_string rttrp_float_sig_names[] = {
    { RTTRP_FLOAT_SIG_LIGHTING_BE,   "RTTrP Lighting Big Endian" },
    { RTTRP_FLOAT_SIG_LIGHTING_LE,   "RTTrP Lighting Little Endian" },
    { RTTRP_FLOAT_SIG_MOTION_BE,     "RTTrP Motion Big Endian" },
    { RTTRP_FLOAT_SIG_MOTION_LE,     "RTTrP Motion Little Endian" },
    { 0,                          NULL },
};

static const value_string rttrp_packet_format_names[] = {
    { RTTRP_PACKET_FORMAT_RAW,        "Raw" },
    { RTTRP_PACKET_FORMAT_PROTOBUF,   "Protobuf" },
    { RTTRP_PACKET_FORMAT_THRIFT,     "Thrift" },
    { 0,                              NULL },
};

static const value_string rttrp_module_names[] = {
    { RTTRP_MODULE_TRACKABLE,                    "Trackable Module (without Timestamp)" },
    { RTTRP_MODULE_TRACKABLE_WITH_TIMESTAMP,     "Trackable Module (with Timestamp)" },
    { RTTRP_MODULE_CENTROID_POSITION,            "Centroid Position Module" },
    { RTTRP_MODULE_ORIENTATION_QUATERNION,       "Orientation Module (Quaternion)" },
    { RTTRP_MODULE_ORIENTATION_EULER,            "Orientation Module (Euler)" },
    { RTTRP_MODULE_TRACKED_POINT_POSITION,       "Tracked Point Position Module" },
    { RTTRP_MODULE_CENTROID_ACCEL_VELOCITY,      "Centroid Acceleration and Velocity Module" },
    { RTTRP_MODULE_TRACKED_POINT_ACCEL_VELOCITY, "Tracked Point Acceleration and Velocity Module" },
    { RTTRP_MODULE_ZONE_COLLISION_DETECTION,     "Zone Collision Detection Module" },
    { RTTRP_MODULE_LIGHTING_OUTPUT,              "Lighting Output Module" },
    { RTTRP_MODULE_LIGHTING_SYNC,                "Lighting Sync Module" },
    { RTTRP_MODULE_UNIVERSE,                     "Universe Module" },
    { RTTRP_MODULE_SPOT,                         "Spot Module" },
    { 0,                                         NULL },
};

static const value_string rttrp_tracker_data_names[] = {
    { RTTRP_MODULE_CENTROID_POSITION,            "Centroid Position" },
    { RTTRP_MODULE_ORIENTATION_QUATERNION,       "Orientation (Quaternion)" },
    { RTTRP_MODULE_ORIENTATION_EULER,            "Orientation (Euler)" },
    { RTTRP_MODULE_TRACKED_POINT_POSITION,       "Tracked Point Position" },
    { RTTRP_MODULE_CENTROID_ACCEL_VELOCITY,      "Centroid Acceleration and Velocity" },
    { RTTRP_MODULE_TRACKED_POINT_ACCEL_VELOCITY, "Tracked Point Acceleration and Velocity" },
    { 0,                                         NULL },
};

static const value_string rttrpm_euler_order_names[] = {
    { 0x0111, "X1 X2 X3" },
    { 0x0112, "X1 X2 Y3" },
    { 0x0113, "X1 X2 Z3" },
    { 0x0121, "X1 Y2 X3" },
    { 0x0122, "X1 Y2 Y3" },
    { 0x0123, "X1 Y2 Z3" },
    { 0x0131, "X1 Z2 X3" },
    { 0x0132, "X1 Z2 Y3" },
    { 0x0133, "X1 Z2 Z3" },

    { 0x0211, "Y1 X2 X3" },
    { 0x0212, "Y1 X2 Y3" },
    { 0x0213, "Y1 X2 Z3" },
    { 0x0221, "Y1 Y2 X3" },
    { 0x0222, "Y1 Y2 Y3" },
    { 0x0223, "Y1 Y2 Z3" },
    { 0x0231, "Y1 Z2 X3" },
    { 0x0232, "Y1 Z2 Y3" },
    { 0x0233, "Y1 Z2 Z3" },

    { 0x0311, "Z1 X2 X3" },
    { 0x0312, "Z1 X2 Y3" },
    { 0x0313, "Z1 X2 Z3" },
    { 0x0321, "Z1 Y2 X3" },
    { 0x0322, "Z1 Y2 Y3" },
    { 0x0323, "Z1 Y2 Z3" },
    { 0x0331, "Z1 Z2 X3" },
    { 0x0332, "Z1 Z2 Y3" },
    { 0x0333, "Z1 Z2 Z3" },
    { 0,      NULL },
};

static const value_string rttrpl_action_names[] = {
  { RTTRPL_ACTION_SNAPSHOT, "Snapshot" },
  { RTTRPL_ACTION_UPDATE,   "Update" },
  { 0,                      NULL },
};

static const value_string rttrpl_hold_time_names[] = {
  { RTTRPL_HOLD_TIME_FOREVER, "Do not release" },
  { 0,                        NULL },
};


/******************************************************************************/
/* Dissect protocol                                                           */
static proto_tree* dissect_rttrp_module_header(tvbuff_t *tvb, proto_tree *tree, const int endianness_int, proto_item** ti, int* offset, int* module_end,
    uint32_t* module_type, uint32_t* module_size, const int hf_module, const int ett_module, const int hf_module_type, const int hf_module_size) {
    /* add subtree */
    *ti = proto_tree_add_item(tree, hf_module, tvb, *offset, -1, ENC_NA);
    proto_tree *mod_tree = proto_item_add_subtree(*ti, ett_module);

    /* add type and size to tree */
    proto_tree_add_item_ret_uint(mod_tree, hf_module_type, tvb, *offset, 1, ENC_NA, module_type);
    *offset += 1;

    proto_tree_add_item_ret_uint(mod_tree, hf_module_size, tvb, *offset, 2, endianness_int, module_size);
    proto_item_set_len(*ti, *module_size);
    *offset += 2;

    /* module_size could be <3, even though it includes these 3 bytes,
        so we make it bigger to ensure we keep making progress */
    *module_end = (*offset)+MAX(*module_size, 3)-3;
    return mod_tree;
}

/** Note that this only dissects the body of the module, not the type or size fields */
static int dissect_rttrp_module_zone_body(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, const unsigned endianness_int, uint16_t module_size) {
    uint16_t length = tvb_get_uint16(tvb, offset, endianness_int);

    /* No way of telling which version we are in to determine which zone method will be used,
     * so we guess based on if the fields look ok for the old method
    */
    if (length + 5 == module_size) {
        /* We have a 2.4.1.0 zone module ('$' delimited string) */
        proto_tree_add_item(tree, hf_rttrp_zone_names_delimited_length, tvb, offset, 2, endianness_int);
        offset += 2;

        if (length == 0) {
            /* No names to actually parse */
            return offset;
        }
        proto_item *zone_holder = proto_tree_add_item(tree, hf_rttrp_zones, tvb, offset, length, ENC_NA);
        proto_tree *zones_tree = proto_item_add_subtree(zone_holder, ett_rttrp_collision_zones);

        /* Fetch string, with terminating null added */
        uint8_t* start = tvb_get_string_enc(pinfo->pool, tvb, offset, length, ENC_ASCII);

        /* parse the delimited string */
        /* based on SrvLoc attribute list parser */
        uint32_t x = 0;
        uint8_t c = start[x];
        while (c) {
            if  (c == '$') {
                proto_tree_add_item(zones_tree, hf_rttrp_zone_name, tvb, offset, x, ENC_ASCII);
                offset += x+1;
                start += x+1;
                /* reset string length */
                x = 0;
                c = start[x];
            } else {
                /* increment and get next */
                x++;
                c = start[x];
            }
        }
        /* add final zone name */
        if (x > 0) {
            proto_tree_add_item(zones_tree, hf_rttrp_zone_name, tvb, offset, x, ENC_ASCII);
            offset += x+1;
        }
    } else {
        /* 2.4.2.0 or later zone module */
        uint32_t zone_count;
        proto_tree_add_item_ret_uint(tree, hf_rttrp_zone_count, tvb, offset, 1, ENC_NA, &zone_count);
        offset += 1;

        if (zone_count != 0) {
            proto_item *zone_holder = proto_tree_add_item(tree, hf_rttrp_zones, tvb, offset, module_size-1-3, ENC_NA);
            proto_tree *zones_tree = proto_item_add_subtree(zone_holder, ett_rttrp_collision_zones);

            for (unsigned int i = 0; i < zone_count; i++) {
                uint8_t zone_size = tvb_get_uint8(tvb, offset);

                proto_item *zone = proto_tree_add_item(zones_tree, hf_rttrp_zone, tvb, offset, zone_size, ENC_NA);
                proto_tree *zone_tree = proto_item_add_subtree(zone, ett_rttrp_collision_zone);

                proto_tree_add_item(zone_tree, hf_rttrp_zone_size, tvb, offset, 1, ENC_NA);
                offset += 1;

                uint32_t name_length;
                proto_tree_add_item_ret_uint(zone_tree, hf_rttrp_zone_name_length, tvb, offset, 1, ENC_NA, &name_length);
                offset += 1;
                proto_tree_add_item(zone_tree, hf_rttrp_zone_name, tvb, offset, name_length, endianness_int);
                offset += name_length;
            }
        }
    }

    return offset;
}

static int dissect_rttrp_module_position(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, const unsigned endianness_int, const unsigned endianness_float) {
    int module_end;
    uint32_t module_type, module_size;
    proto_item* pos_item;
    proto_tree* pos_tree = dissect_rttrp_module_header(tvb, tree, endianness_int, &pos_item, &offset,
        &module_end, &module_type, &module_size, hf_rttrp_module_tracker_data, ett_rttrp_module_tracker_data, hf_rttrp_module_tracker_data_type, hf_rttrp_module_tracker_data_size);

    switch (module_type) {
        case RTTRP_MODULE_CENTROID_POSITION:
        case RTTRP_MODULE_ORIENTATION_QUATERNION:
        case RTTRP_MODULE_ORIENTATION_EULER:
        case RTTRP_MODULE_TRACKED_POINT_POSITION:
        case RTTRP_MODULE_CENTROID_ACCEL_VELOCITY:
        case RTTRP_MODULE_TRACKED_POINT_ACCEL_VELOCITY:
            /* Continue to dissector */
            break;
        case RTTRP_MODULE_ZONE_COLLISION_DETECTION:
            /* Call into specialised dissector */
            proto_item_append_text(pos_item, ": Zone Collision Detection");
            offset = dissect_rttrp_module_zone_body(tvb, pinfo, pos_tree, offset, endianness_int, module_size);
            return module_end;
        default:
            /* Module type isn't valid here */
            expert_add_info(pinfo, pos_tree, &ei_rttrp_module_type);
            return module_end;
    }

    const char* module_name = val_to_str_const(module_type, rttrp_tracker_data_names, "Unknown");
    proto_item_append_text(pos_item, ": %s", module_name);
    /* Latency Field */
    if (module_type == RTTRP_MODULE_CENTROID_POSITION ||
        module_type == RTTRP_MODULE_TRACKED_POINT_POSITION ||
        module_type == RTTRP_MODULE_ORIENTATION_QUATERNION ||
        module_type == RTTRP_MODULE_ORIENTATION_EULER
    ) {
        uint32_t latency;
        proto_tree_add_item_ret_uint(pos_tree, hf_rttrp_module_latency, tvb, offset, 2, endianness_int, &latency);
        offset += 2;
        proto_item_append_text(pos_item, ", Latency: %ums", latency);
    }


    if (module_type == RTTRP_MODULE_ORIENTATION_QUATERNION) {
        proto_tree_add_item(pos_tree, hf_rttrp_orientation_qx, tvb, offset, 8, endianness_float);
        offset += 8;
        proto_tree_add_item(pos_tree, hf_rttrp_orientation_qy, tvb, offset, 8, endianness_float);
        offset += 8;
        proto_tree_add_item(pos_tree, hf_rttrp_orientation_qz, tvb, offset, 8, endianness_float);
        offset += 8;
        proto_tree_add_item(pos_tree, hf_rttrp_orientation_qw, tvb, offset, 8, endianness_float);
        offset += 8;
    } else if (module_type == RTTRP_MODULE_ORIENTATION_EULER) {
        proto_tree_add_item(pos_tree, hf_rttrp_orientation_order, tvb, offset, 2, endianness_int);
        offset += 2;
        proto_tree_add_item(pos_tree, hf_rttrp_orientation_r1, tvb, offset, 8, endianness_float);
        offset += 8;
        proto_tree_add_item(pos_tree, hf_rttrp_orientation_r2, tvb, offset, 8, endianness_float);
        offset += 8;
        proto_tree_add_item(pos_tree, hf_rttrp_orientation_r3, tvb, offset, 8, endianness_float);
        offset += 8;
    } else if (module_type == RTTRP_MODULE_CENTROID_POSITION ||
        module_type == RTTRP_MODULE_TRACKED_POINT_POSITION ||
        module_type == RTTRP_MODULE_CENTROID_ACCEL_VELOCITY ||
        module_type == RTTRP_MODULE_TRACKED_POINT_ACCEL_VELOCITY
    ) {
        proto_tree_add_item(pos_tree, hf_rttrp_position_x, tvb, offset, 8, endianness_float);
        offset += 8;
        proto_tree_add_item(pos_tree, hf_rttrp_position_y, tvb, offset, 8, endianness_float);
        offset += 8;
        proto_tree_add_item(pos_tree, hf_rttrp_position_z, tvb, offset, 8, endianness_float);
        offset += 8;

        if (module_type == RTTRP_MODULE_CENTROID_ACCEL_VELOCITY ||
            module_type == RTTRP_MODULE_TRACKED_POINT_ACCEL_VELOCITY
        ) {
            proto_tree_add_item(pos_tree, hf_rttrp_acceleration_x, tvb, offset, 4, endianness_float);
            offset += 4;
            proto_tree_add_item(pos_tree, hf_rttrp_acceleration_y, tvb, offset, 4, endianness_float);
            offset += 4;
            proto_tree_add_item(pos_tree, hf_rttrp_acceleration_z, tvb, offset, 4, endianness_float);
            offset += 4;

            proto_tree_add_item(pos_tree, hf_rttrp_velocity_x, tvb, offset, 4, endianness_float);
            offset += 4;
            proto_tree_add_item(pos_tree, hf_rttrp_velocity_y, tvb, offset, 4, endianness_float);
            offset += 4;
            proto_tree_add_item(pos_tree, hf_rttrp_velocity_z, tvb, offset, 4, endianness_float);
            offset += 4;
        }
    }

    /* Point index for point trackers */
    if (module_type == RTTRP_MODULE_TRACKED_POINT_POSITION ||
        module_type == RTTRP_MODULE_TRACKED_POINT_ACCEL_VELOCITY
    ) {
        uint32_t point_index;
        proto_tree_add_item_ret_uint(pos_tree, hf_rttrp_point_index, tvb, offset, 1, ENC_NA, &point_index);
        offset += 1;
        proto_item_append_text(pos_item, ", Point Index: %u", point_index);
    }

    if (offset != module_end)
        expert_add_info(pinfo, pos_tree, &ei_rttrp_module_size);
    return module_end;
}

static int dissect_rttrp_module_trackable(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, const unsigned endianness_int, const unsigned endianness_float) {
    int module_end;
    uint32_t module_type, module_size;
    proto_item* track_item;
    proto_tree* track_tree = dissect_rttrp_module_header(tvb, tree, endianness_int, &track_item, &offset,
        &module_end, &module_type, &module_size, hf_rttrp_module_trackable, ett_rttrp_module_trackable, hf_rttrp_module_trackable_type, hf_rttrp_module_trackable_size);

    if (module_type != RTTRP_MODULE_TRACKABLE && module_type != RTTRP_MODULE_TRACKABLE_WITH_TIMESTAMP) {
        expert_add_info(pinfo, track_tree, &ei_rttrp_module_type);
        return module_end;
    }

    uint32_t name_length;
    proto_tree_add_item_ret_uint(track_tree, hf_rttrp_trackable_name_length, tvb, offset, 1, ENC_NA, &name_length);
    offset += 1;
    const uint8_t* name;
    proto_tree_add_item_ret_string(track_tree, hf_rttrp_trackable_name, tvb, offset, name_length, endianness_int, pinfo->pool, &name);
    offset += name_length;

    if (module_type == RTTRP_MODULE_TRACKABLE_WITH_TIMESTAMP) {
        proto_item_append_text(track_item, " (with Timestamp)");
        proto_tree_add_item(track_tree, hf_rttrp_trackable_timestamp, tvb, offset, 4, endianness_int);
        offset += 4;
    }

    uint32_t module_count;
    proto_tree_add_item_ret_uint(track_tree, hf_rttrp_trackable_module_count, tvb, offset, 1, ENC_NA, &module_count);
    offset += 1;

    proto_item_append_text(track_item, ", Name: %s, %u sub-modules", name, module_count);

    /* Number of modules is small (about 5 max), so no extra tree */
    for (unsigned int i = 0; i < module_count; i++) {
        offset = dissect_rttrp_module_position(tvb, pinfo, track_tree, offset, endianness_int, endianness_float);
    }

    if (offset != module_end)
        expert_add_info(pinfo, track_tree, &ei_rttrp_module_size);
    return module_end;
}


static int dissect_rttrp_module_spot(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, const unsigned endianness_int) {
    int module_end;
    uint32_t module_type, module_size;
    proto_item* spot_item;
    proto_tree* spot_tree = dissect_rttrp_module_header(tvb, tree, endianness_int, &spot_item, &offset,
        &module_end, &module_type, &module_size, hf_rttrp_module_spot, ett_rttrp_module_spot, hf_rttrp_module_spot_type, hf_rttrp_module_spot_size);

    if (module_type != RTTRP_MODULE_SPOT) {
        expert_add_info(pinfo, spot_tree, &ei_rttrp_module_type);
        return module_end;
    }

    uint32_t spot_id;
    proto_tree_add_item_ret_uint(spot_tree, hf_rttrp_spot_id, tvb, offset, 2, endianness_int, &spot_id);
    offset += 2;
    proto_tree_add_item(spot_tree, hf_rttrp_spot_offset, tvb, offset, 2, endianness_int);
    offset += 2;

    uint32_t channel_count;
    proto_tree_add_item_ret_uint(spot_tree, hf_rttrp_spot_channel_count, tvb, offset, 2, endianness_int, &channel_count);
    offset += 2;

    proto_item_append_text(spot_item, ", ID: %u, %u channels", spot_id, channel_count);

    /* Number of channels is small, so we don't add an extra container */
    for (unsigned int i = 0; i < channel_count; i++) {
        proto_item *chan_item = proto_tree_add_item(spot_tree, hf_rttrp_channel, tvb, offset, 5, ENC_NA);
        proto_tree *chan_tree = proto_item_add_subtree(chan_item, ett_rttrp_lighting_chan);

        uint32_t chan_offset;
        proto_tree_add_item_ret_uint(chan_tree, hf_rttrp_channel_offset, tvb, offset, 2, endianness_int, &chan_offset);
        offset += 2;
        proto_tree_add_item(chan_tree, hf_rttrp_channel_xfade, tvb, offset, 2, endianness_int);
        offset += 2;
        uint32_t chan_value;
        proto_tree_add_item_ret_uint(chan_tree, hf_rttrp_channel_value, tvb, offset, 1, endianness_int, &chan_value);
        offset += 1;

        /* add some info about the channel (number and intensity) */
        proto_item_append_text(chan_item, ", %u @ %u", chan_offset, chan_value);
    }

    if (offset != module_end)
        expert_add_info(pinfo, spot_tree, &ei_rttrp_module_size);
    return module_end;
}

static int dissect_rttrp_module_universe(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, const unsigned endianness_int) {
    int module_end;
    uint32_t module_type, module_size;
    proto_item* univ_item;
    proto_tree* univ_tree = dissect_rttrp_module_header(tvb, tree, endianness_int, &univ_item, &offset,
        &module_end, &module_type, &module_size, hf_rttrp_module_universe, ett_rttrp_module_universe, hf_rttrp_module_universe_type, hf_rttrp_module_universe_size);

    if (module_type != RTTRP_MODULE_UNIVERSE) {
        expert_add_info(pinfo, univ_tree, &ei_rttrp_module_type);
        return module_end;
    }

    uint32_t universe_id;
    proto_tree_add_item_ret_uint(univ_tree, hf_rttrp_universe_id, tvb, offset, 2, endianness_int, &universe_id);
    offset += 2;

    uint32_t spot_count;
    proto_tree_add_item_ret_uint(univ_tree, hf_rttrp_universe_spot_count, tvb, offset, 2, endianness_int, &spot_count);
    offset += 2;

    proto_item_append_text(univ_item, ", ID: %u, %u spots", universe_id, spot_count);

    if (spot_count > 0) {
        proto_item *spot_holder = proto_tree_add_item(univ_tree, hf_rttrp_universe_spots, tvb, offset, module_size-4-3, ENC_NA);
        proto_tree *spot_tree = proto_item_add_subtree(spot_holder, ett_rttrp_lighting_spots);

        for (unsigned int i = 0; i < spot_count; i++) {
            offset = dissect_rttrp_module_spot(tvb, pinfo, spot_tree, offset, endianness_int);
        }
    }

    if (offset != module_end)
        expert_add_info(pinfo, univ_tree, &ei_rttrp_module_size);
    return module_end;
}

static int dissect_rttrp_module_lighting(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, const unsigned endianness_int) {
    int module_end;
    uint32_t module_type, module_size;
    proto_item* light_item;
    proto_tree* light_tree = dissect_rttrp_module_header(tvb, tree, endianness_int, &light_item, &offset,
        &module_end, &module_type, &module_size, hf_rttrp_module_lighting, ett_rttrp_module_lighting, hf_rttrp_module_lighting_type, hf_rttrp_module_lighting_size);

    if (module_type != RTTRP_MODULE_LIGHTING_OUTPUT && module_type != RTTRP_MODULE_LIGHTING_SYNC) {
        expert_add_info(pinfo, light_tree, &ei_rttrp_module_type);
        return module_end;
    }

    if (module_type == RTTRP_MODULE_LIGHTING_SYNC) {
        proto_tree_add_item(light_tree, hf_rttrp_sync_device_id, tvb, offset, 4, endianness_int);
        offset += 4;
        proto_tree_add_item(light_tree, hf_rttrp_sync_device_sub_id_0, tvb, offset, 4, endianness_int);
        offset += 4;
        proto_tree_add_item(light_tree, hf_rttrp_sync_device_sub_id_1, tvb, offset, 4, endianness_int);
        offset += 4;
        uint32_t sync_sequence;
        proto_tree_add_item_ret_uint(light_tree, hf_rttrp_sync_device_sequence_number, tvb, offset, 4, endianness_int, &sync_sequence);
        offset += 4;
        proto_item_append_text(light_item, ": Sync, Sequence: %u", sync_sequence);

        if (offset != module_end)
            expert_add_info(pinfo, light_tree, &ei_rttrp_module_size);
        return module_end;
    }

    /* Just lighting output now*/
    uint32_t lighting_sequence;
    proto_tree_add_item_ret_uint(light_tree, hf_rttrp_lighting_sequence, tvb, offset, 4, endianness_int, &lighting_sequence);
    offset += 4;
    proto_tree_add_item(light_tree, hf_rttrp_lighting_action, tvb, offset, 1, ENC_NA);
    offset += 1;
    proto_tree_add_item(light_tree, hf_rttrp_lighting_hold_time, tvb, offset, 4, endianness_int);
    offset += 4;

    uint32_t universe_count;
    proto_tree_add_item_ret_uint(light_tree, hf_rttrp_lighting_universe_count, tvb, offset, 2, endianness_int, &universe_count);
    offset += 2;

    proto_item_append_text(light_item, ": Output, Sequence: %u, %u universes", lighting_sequence, universe_count);

    /* Number of universes is usually small (1-10), so we don't add an extra container */
    for (unsigned int i = 0; i < universe_count; i++) {
        offset = dissect_rttrp_module_universe(tvb, pinfo, light_tree, offset, endianness_int);
    }

    if (offset != module_end)
        expert_add_info(pinfo, light_tree, &ei_rttrp_module_size);
    return module_end;
}


static int
dissect_rttrp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if (tvb_reported_length(tvb) < 4) {
        return 0;
    }

    uint16_t int_sig = tvb_get_uint16(tvb, 0, ENC_BIG_ENDIAN);
    uint16_t float_sig = tvb_get_uint16(tvb, 2, ENC_BIG_ENDIAN);

    unsigned endianness_int;
    unsigned endianness_float;

    if (int_sig == RTTRP_INT_SIG_BE) {
        endianness_int = ENC_BIG_ENDIAN;
    } else if (int_sig == RTTRP_INT_SIG_LE) {
        endianness_int = ENC_LITTLE_ENDIAN;
    } else { /* We don't have an RTTrP packet */
        return 0;
    }
    if (float_sig == RTTRP_FLOAT_SIG_LIGHTING_BE || float_sig == RTTRP_FLOAT_SIG_MOTION_BE) {
        endianness_float = ENC_BIG_ENDIAN;
    } else if (float_sig == RTTRP_FLOAT_SIG_LIGHTING_LE || float_sig == RTTRP_FLOAT_SIG_MOTION_LE) {
        endianness_float = ENC_LITTLE_ENDIAN;
    } else {
        return 0;
    }

    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTTrP");
    /* Clear the info column */
    col_set_str(pinfo->cinfo, COL_INFO, "RTTrP");

    proto_item *ti = proto_tree_add_item(tree, proto_rttrp, tvb, 0, -1, ENC_NA);
    proto_tree *rttrp_tree = proto_item_add_subtree(ti, ett_rttrp);

    /* header values are always in big endian */
    proto_tree_add_item(rttrp_tree, hf_rttrp_int_signature, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_tree_add_item(rttrp_tree, hf_rttrp_float_signature, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    /* Rename the protocol tree with additional information */
    if (float_sig == RTTRP_FLOAT_SIG_MOTION_BE || float_sig == RTTRP_FLOAT_SIG_MOTION_LE ) {
        proto_item_append_text(ti, " - Motion");
        col_append_str(pinfo->cinfo, COL_INFO, "M");
    } else if (float_sig == RTTRP_FLOAT_SIG_LIGHTING_BE || float_sig == RTTRP_FLOAT_SIG_LIGHTING_LE ) {
        proto_item_append_text(ti, " - Lighting");
        col_append_str(pinfo->cinfo, COL_INFO, "L");
    }

    proto_tree_add_item(rttrp_tree, hf_rttrp_header_version, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    uint32_t packet_id;
    proto_tree_add_item_ret_uint(rttrp_tree, hf_rttrp_packet_id, tvb, offset, 4, endianness_int, &packet_id);
    offset += 4;

    proto_tree_add_item(rttrp_tree, hf_rttrp_packet_format, tvb, offset, 1, ENC_NA);
    offset += 1;

    /* update the length of the item containing the whole packet */
    uint32_t size;
    proto_tree_add_item_ret_uint(rttrp_tree, hf_rttrp_packet_size, tvb, offset, 2, endianness_int, &size);
    proto_item_set_len(ti, size);
    offset += 2;

    uint32_t packet_context;
    proto_tree_add_item_ret_uint(rttrp_tree, hf_rttrp_packet_context, tvb, offset, 4, endianness_int, &packet_context);
    offset += 4;

    uint32_t module_count;
    proto_tree_add_item_ret_uint(rttrp_tree, hf_rttrp_packet_module_count, tvb, offset, 1, ENC_NA, &module_count);
    offset += 1;


    if (float_sig == RTTRP_FLOAT_SIG_LIGHTING_LE || float_sig==RTTRP_FLOAT_SIG_LIGHTING_BE) {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Packet ID: %5u, %u Modules, Context: 0x%08x", packet_id, module_count, packet_context);
        for (unsigned int i = 0; i < module_count; i++) {
            offset = dissect_rttrp_module_lighting(tvb, pinfo, rttrp_tree, offset, endianness_int);
        }
    } else {
        col_append_fstr(pinfo->cinfo, COL_INFO, ", Packet ID: %5u, %u Trackers, Context: 0x%08x", packet_id, module_count, packet_context);
        for (unsigned int i = 0; i < module_count; i++) {
            offset = dissect_rttrp_module_trackable(tvb, pinfo, rttrp_tree, offset, endianness_int, endianness_float);
        }
    }

    /* number of bytes read */
    return offset;
}

/* Heuristic Dissector - RTTrPM has no defined port */
static bool
dissect_rttrp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint16_t val;

    if (tvb_captured_length(tvb) < 4)
        return false;

    /* Check Int Signature */
    val = tvb_get_uint16(tvb, 0, ENC_BIG_ENDIAN);
    if (val != RTTRP_INT_SIG_BE && val != RTTRP_INT_SIG_LE)
        return false;

    /* Check Float Signature */
    val = tvb_get_uint16(tvb, 2, ENC_BIG_ENDIAN);
    if (val != RTTRP_FLOAT_SIG_LIGHTING_BE && val != RTTRP_FLOAT_SIG_LIGHTING_LE
        && val != RTTRP_FLOAT_SIG_MOTION_BE && val != RTTRP_FLOAT_SIG_MOTION_LE)
        return false;

    /* Set for the whole conversation */
    conversation_t* conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, rttrp_handle);

    dissect_rttrp(tvb, pinfo, tree, data);

    return true;
}

/******************************************************************************/
/* Register protocol                                                          */
void
proto_register_rttrp(void) {
    static hf_register_info hf[] = {
        { &hf_rttrp_int_signature,
            { "Integer Signature", "rttrp.int_signature",
            FT_UINT16, BASE_HEX,
            VALS(rttrp_int_sig_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_float_signature,
            { "Float Signature", "rttrp.float_signature",
            FT_UINT16, BASE_HEX,
            VALS(rttrp_float_sig_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_header_version,
            { "Header Version", "rttrp.header_version",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_packet_id,
            { "Packet ID", "rttrp.packet_id",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_packet_format,
            { "Packet Format", "rttrp.packet_format",
            FT_UINT8, BASE_HEX,
            VALS(rttrp_packet_format_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_packet_size,
            { "Size", "rttrp.packet_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_packet_context,
            { "Context", "rttrp.context",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_packet_module_count,
            { "Number of Sub-Modules", "rttrp.module_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_module_trackable,
            { "Trackable Module", "rttrp.trackable",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_trackable_type,
            { "Type", "rttrp.trackable.module_type",
            FT_UINT8, BASE_HEX,
            VALS(rttrp_module_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_trackable_size,
            { "Size", "rttrp.trackable.module_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_tracker_data,
            { "Tracker Data Module", "rttrp.trackable.data",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_tracker_data_type,
            { "Type", "rttrp.trackable.data.module_type",
            FT_UINT8, BASE_HEX,
            VALS(rttrp_module_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_tracker_data_size,
            { "Size", "rttrp.trackable.data.module_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_lighting,
            { "Lighting Module", "rttrp.lighting",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_lighting_type,
            { "Type", "rttrp.lighting.module_type",
            FT_UINT8, BASE_HEX,
            VALS(rttrp_module_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_lighting_size,
            { "Size", "rttrp.lighting.module_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_universe,
            { "Universe Module", "rttrp.lighting.universe",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_universe_type,
            { "Type", "rttrp.lighting.universe.module_type",
            FT_UINT8, BASE_HEX,
            VALS(rttrp_module_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_universe_size,
            { "Size", "rttrp.lighting.universe.module_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_spot,
            { "Spot Module", "rttrp.lighting.universe.spot",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_spot_type,
            { "Type", "rttrp.lighting.universe.spot.module_type",
            FT_UINT8, BASE_HEX,
            VALS(rttrp_module_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_module_spot_size,
            { "Size", "rttrp.lighting.universe.spot.module_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_module_latency,
            { "Latency", "rttrp.trackable.data.latency",
            FT_UINT16, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_milliseconds), 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_trackable_name_length,
            { "Name Length", "rttrp.trackable.name_length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_trackable_name,
            { "Name", "rttrp.trackable.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        /* No defined unit or reference, description labels it a sequence number */
        { &hf_rttrp_trackable_timestamp,
            { "Timestamp", "rttrp.trackable.timestamp",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_trackable_module_count,
            { "Number of Sub-Modules", "rttrp.trackable.module_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_trackable_modules,
            { "Sub-Modules", "rttrp.trackable.modules",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_position_x,
            { "X", "rttrp.position.x",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_position_y,
            { "Y", "rttrp.position.y",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_position_z,
            { "Z", "rttrp.position.z",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_point_index,
            { "Index", "rttrp.trackable.data.point_index",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_orientation_qx,
            { "Qx", "rttrp.orientation.qx",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_orientation_qy,
            { "Qy", "rttrp.orientation.qy",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_orientation_qz,
            { "Qz", "rttrp.orientation.qz",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_orientation_qw,
            { "Qw", "rttrp.orientation.qw",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_orientation_order,
            { "Order", "rttrp.orientation.order",
            FT_UINT16, BASE_HEX,
            VALS(rttrpm_euler_order_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_orientation_r1,
            { "R1", "rttrp.orientation.r1",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_orientation_r2,
            { "R2", "rttrp.orientation.r2",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_orientation_r3,
            { "R3", "rttrp.orientation.r3",
            FT_DOUBLE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_acceleration_x,
            { "Acceleration X", "rttrp.acceleration.x",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_acceleration_y,
            { "Acceleration Y", "rttrp.acceleration.y",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_acceleration_z,
            { "Acceleration Z", "rttrp.acceleration.z",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_velocity_x,
            { "Velocity X", "rttrp.velocity.x",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_velocity_y,
            { "Velocity Y", "rttrp.velocity.y",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_velocity_z,
            { "Velocity Z", "rttrp.velocity.z",
            FT_FLOAT, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_zone_count,
            { "Number of Zones", "rttrp.trackable.data.zone_count",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_zones,
            { "Zones", "rttrp.trackable.data.zones",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_zone,
            { "Zone", "rttrp.trackable.data.zone",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_zone_name_length,
            { "Name Length", "rttrp.trackable.data.zone.name_length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_zone_name,
            { "Name", "rttrp.trackable.data.zone.name",
            FT_STRING, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_zone_names_delimited_length,
            { "Delimited Zone List Length", "rttrp.trackable.data.zone_names_delimited_length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_zone_size,
            { "Size", "rttrp.trackable.data.zone.module_size",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_lighting_sequence,
            { "Lighting Sequence", "rttrp.lighting.sequence",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_lighting_action,
            { "Action", "rttrp.lighting.action",
            FT_UINT8, BASE_HEX,
            VALS(rttrpl_action_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_lighting_hold_time,
            { "Hold Time", "rttrp.lighting.hold_time",
            FT_UINT32, BASE_DEC | BASE_SPECIAL_VALS,
            VALS(rttrpl_hold_time_names), 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_lighting_universe_count,
            { "Number of Universe Modules", "rttrp.lighting.universe_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },


        { &hf_rttrp_universe_id,
            { "Universe ID", "rttrp.lighting.universe.id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_universe_spot_count,
            { "Number of Spot Modules", "rttrp.lighting.universe.spot_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_universe_spots,
            { "Spot Modules", "rttrp.lighting.universe.spots",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_spot_id,
            { "Spot ID", "rttrp.lighting.universe.spot.id",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_spot_offset,
            { "Spot Offset", "rttrp.lighting.universe.spot.offset",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_spot_channel_count,
            { "Number of Channel Structures", "rttrp.lighting.universe.spot.channel_count",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_channel,
            { "Channel", "rttrp.lighting.universe.spot.channel",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_channel_offset,
            { "Channel Offset", "rttrp.lighting.universe.spot.channel.offset",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_channel_xfade,
            { "Xfade", "rttrp.lighting.universe.spot.channel.xfade",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_channel_value,
            { "Value", "rttrp.lighting.universe.spot.channel.value",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_rttrp_sync_device_id,
            { "Device ID", "rttrp.lighting.device_id",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_sync_device_sub_id_0,
            { "Device Sub ID 0", "rttrp.lighting.device_sub_id_0",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_sync_device_sub_id_1,
            { "Device Sub ID 1", "rttrp.lighting.device_sub_id_1",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_rttrp_sync_device_sequence_number,
            { "Sequence Number", "rttrp.lighting.device_sequence_number",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_rttrp,

        &ett_rttrp_module_trackable,
        &ett_rttrp_module_tracker_data,
        &ett_rttrp_module_lighting,
        &ett_rttrp_module_universe,
        &ett_rttrp_module_spot,

        &ett_rttrp_collision_zones,
        &ett_rttrp_collision_zone,

        &ett_rttrp_lighting_spots,
        &ett_rttrp_lighting_chan,
    };

    static ei_register_info ei[] = {
        { &ei_rttrp_module_type, { "rttrp.module_type.invalid_type", PI_PROTOCOL, PI_ERROR, "Invalid module type for this location", EXPFILL }},
        { &ei_rttrp_module_size, { "rttrp.module_size.mismatch", PI_PROTOCOL, PI_WARN, "Mismatch between reported module length and consumed data", EXPFILL }},
    };

    proto_rttrp = proto_register_protocol("Real-Time Tracking Protocol", "RTTrP", "rttrp");

    proto_register_field_array(proto_rttrp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_t* expert_rttrp;
    expert_rttrp = expert_register_protocol(proto_rttrp);
    expert_register_field_array(expert_rttrp, ei, array_length(ei));

    rttrp_handle = register_dissector_with_description(
        "rttrp",          /* dissector name           */
        "RTTrP",          /* dissector description    */
        dissect_rttrp,    /* dissector function       */
        proto_rttrp       /* protocol being dissected */
    );
}

/******************************************************************************/
/* Register handoff                                                           */
void
proto_reg_handoff_rttrp(void)
{
    dissector_add_for_decode_as_with_preference("udp.port", rttrp_handle);

    heur_dissector_add("udp", dissect_rttrp_heur, "RTTrP over UDP", "rttrp_udp", proto_rttrp, HEURISTIC_ENABLE);
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
