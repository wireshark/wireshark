/* packet-uavcan-dsdl.c
 * Routines for dissection of DSDL used in UAVCAN
 *
 * Copyright 2020-2021 NXP
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <inttypes.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/address_types.h>
#include <epan/to_str.h>
#include <epan/proto_data.h>

#include "packet-uavcan-dsdl.h"

void proto_register_dsdl(void);
void proto_reg_handoff_dsdl(void);

static int proto_dsdl;

static int hf_heartbeat_uptime;
static int hf_heartbeat_health;
static int hf_heartbeat_mode;
static int hf_heartbeat_status_code;

static int hf_list_index;
static int hf_register_name;
static int hf_register_access_mutable;
static int hf_register_access_persistent;
static int hf_register_value_tag;
static int hf_register_value_size;


static int hf_node_id;
static int hf_pnp_unique_id;
static int hf_pnp_unique_id_hash;
static int hf_pnp_alloc;

static int hf_uavcan_primitive_Empty;
static int hf_uavcan_primitive_String;
static int hf_uavcan_primitive_Unstructured;
static int hf_uavcan_primitive_array_Integer64;
static int hf_uavcan_primitive_array_Integer32;
static int hf_uavcan_primitive_array_Integer16;
static int hf_uavcan_primitive_array_Integer8;
static int hf_uavcan_primitive_array_Natural64;
static int hf_uavcan_primitive_array_Natural32;
static int hf_uavcan_primitive_array_Natural16;
static int hf_uavcan_primitive_array_Natural8;
static int hf_uavcan_primitive_array_Real64;
static int hf_uavcan_primitive_array_Real32;
static int hf_uavcan_primitive_array_Real16;


static int hf_uavcan_getinfo_path;
static int hf_uavcan_getinfo_error;
static int hf_uavcan_getinfo_size;
static int hf_uavcan_getinfo_timestamp;
static int hf_uavcan_getinfo_is_file_not_directory;
static int hf_uavcan_getinfo_is_link;
static int hf_uavcan_getinfo_is_readable;
static int hf_uavcan_getinfo_is_writeable;
static int hf_uavcan_directory_path;
static int hf_uavcan_entry_base_name;
static int hf_uavcan_modify_error;
static int hf_uavcan_modify_source_path;
static int hf_uavcan_modify_destination_path;
static int hf_uavcan_modify_preserve_source;
static int hf_uavcan_modify_overwrite_destination;
static int hf_uavcan_read_offset;
static int hf_uavcan_read_path;
static int hf_uavcan_read_error;
static int hf_uavcan_write_offset;
static int hf_uavcan_write_path;
static int hf_uavcan_write_error;
static int hf_uavcan_entry_index;

static int hf_uavcan_time_syncronizedtimestamp;
static int hf_uavcan_diagnostic_severity;

static int ett_dsdl;

const range_string uavcan_subject_id_vals[] = {
    {      0,   6143, "Unregulated identifier"                 },
    {   6144,   7167, "Non-standard fixed regulated identifier"},
    {   7168,   7168, "Synchronization.1.0"                    },
    {   7509,   7509, "Heartbeat.1.0"                          },
    {   7510,   7510, "List.0.1"                               },
    {   8165,   8165, "NodeIDAllocationData.2.0"               },
    {   8166,   8166, "NodeIDAllocationData.1.0"               },
    {   8184,   8184, "Record.1.X"                             },
    {      0,      0, NULL                                     }
};

const range_string uavcan_service_id_vals[] = {
    {      0,    255, "Unregulated identifier"                 },
    {    256,    383, "Non-standard fixed regulated identifier"},
    {    384,    384, "Access.1.0"                             },
    {    385,    385, "List.1.0"                               },
    {    405,    405, "GetInfo.0.X"                            },
    {    406,    406, "List.0.X"                               },
    {    407,    407, "Modify.1.X"                             },
    {    408,    408, "Read.1.X"                               },
    {    409,    409, "Write.1.X"                              },
    {    430,    430, "GetInfo.1.0"                            },
    {    434,    434, "GetTransportStatistics.1.0"             },
    {    435,    435, "ExecuteCommand.1.X"                     },
    {      0,      0, NULL                                     }
};

static const address anonymous_address = ADDRESS_INIT(AT_NONE, 9, "Anonymous");

static const value_string uavcan_file_error_vals[] = {
    {      0, "Ok"             },
    {      2, "Not found"      },
    {      5, "I/O error"      },
    {     13, "Access denied"  },
    {     21, "Is directory"   },
    {     22, "Invalid value"  },
    {     27, "File too large" },
    {     28, "Out of space"   },
    {     38, "Not supported"  },
    {  65535, "Unknown"        },
    {      0, NULL             }
};

static const value_string uavcan_diagnostic_severity_vals[] = {
    {  0, "Trace"    },
    {  1, "Debug"    },
    {  2, "Info"     },
    {  3, "Notice"   },
    {  4, "Warning"  },
    {  5, "Error"    },
    {  6, "Critical" },
    {  7, "Alert"    },
    {  0, NULL       }
};

static const value_string uavcan_heartbeat_mode_vals[] = {
    {  0, "Operational"     },
    {  1, "Initialization"  },
    {  2, "Maintenance"     },
    {  3, "Software update" },
    {  0, NULL              }
};

static const value_string uavcan_heartbeat_health_vals[] = {
    {  0, "Nominal"  },
    {  1, "Advisory" },
    {  2, "Caution"  },
    {  3, "Warning"  },
    {  0, NULL       }
};

static const value_string uavcan_value_tag_vals[] = {
    {   0, "Empty"            },
    {   1, "String"           },
    {   2, "Unstructured"     },
    {   3, "Bit array"        },
    {   4, "Integer 64 Array" },
    {   5, "Integer 32 Array" },
    {   6, "Integer 16 Array" },
    {   7, "Integer 8 Array"  },
    {   8, "Natural 64 Array" },
    {   9, "Natural 32 Array" },
    {  10, "Natural 16 Array" },
    {  11, "Natural 8 Array"  },
    {  12, "Real 64 Array"    },
    {  13, "Real 32 Array"    },
    {  14, "Real 16 Array"    },
    {   0, NULL               }
};

static const value_string uavcan_nodeid_alloc_vals[] = {
    {   0, "request message"  },
    {   1, "response message" },
    {   0, NULL               }
};

static void
dissect_list_service_data(tvbuff_t *tvb, int tvb_offset, proto_tree *tree, bool is_request)
{
    if (is_request == true) {
        proto_tree_add_item(tree, hf_list_index, tvb, tvb_offset, 2, ENC_LITTLE_ENDIAN);
    } else {
        /* FT_UINT_STRING counted string, with count being the first byte */
        proto_tree_add_item(tree, hf_register_name,
                            tvb, tvb_offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
    }
}

static void
dissect_access_service_data(tvbuff_t *tvb, int tvb_offset, proto_tree *tree, bool is_request)
{
    uint32_t tag;
    int offset;

    offset = tvb_offset;

    if (is_request == true) {
        int len;
        /* FT_UINT_STRING counted string, with count being the first byte */
        proto_tree_add_item_ret_length(tree, hf_register_name,
                                 tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN, &len);
        offset += len;
    } else {
        proto_tree_add_item(tree, hf_uavcan_time_syncronizedtimestamp,
                                 tvb, offset, 7, ENC_LITTLE_ENDIAN);
        offset += 7;
        proto_tree_add_item(tree, hf_register_access_mutable,
                                 tvb, offset, 1, ENC_NA);
        proto_tree_add_item(tree, hf_register_access_persistent,
                                 tvb, offset, 1, ENC_NA);

        offset += 1;
    }

    proto_tree_add_item_ret_uint(tree, hf_register_value_tag,
                             tvb, offset, 1, ENC_NA, &tag);
    offset += 1;

    if (tag == 1) { /* String */
        proto_tree_add_item(tree, hf_register_value_size,
                                 tvb, offset, 1, ENC_NA);
        /* FT_UINT_STRING counted string, with count being the first byte */
        proto_tree_add_item(tree, hf_register_name,
                                 tvb, offset, 1, ENC_ASCII|ENC_BIG_ENDIAN);
    } else if (tag == 2 || tag == 3) {
        return; // Raw data do nothing
    } else {
        uint8_t array_len = tvb_get_uint8(tvb, offset);

        if (array_len == 0 || tag == 0) {
            proto_tree_add_item(tree, hf_uavcan_primitive_Empty,
                                     tvb, 0, 0, ENC_NA);
        } else {
            proto_tree_add_item(tree, hf_register_value_size,
                                     tvb, offset, 1, ENC_NA);
            offset += 1;

            for (uint8_t i = 0; i < array_len; i++) {
                switch (tag) {
                case 4:     /*Integer64*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Integer64,
                                             tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    break;

                case 5:     /*Integer32*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Integer32,
                                             tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    break;

                case 6:     /*Integer16*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Integer16,
                                             tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                case 7:     /*Integer8*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Integer8,
                                             tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    break;

                case 8:     /*Natural64*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Natural64,
                                             tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    break;

                case 9:     /*Natural32*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Natural32,
                                             tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    break;

                case 10:     /*Natural16*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Natural16,
                                             tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                case 11:     /*Natural8*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Natural8,
                                             tvb, offset, 1, ENC_LITTLE_ENDIAN);
                    offset += 1;
                    break;

                case 12:     /*Real64*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Real64,
                                             tvb, offset, 8, ENC_LITTLE_ENDIAN);
                    offset += 8;
                    break;

                case 13:     /*Real32*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Real32,
                                             tvb, offset, 4, ENC_LITTLE_ENDIAN);
                    offset += 4;
                    break;

                case 14:     /*Real16*/
                    proto_tree_add_item(tree, hf_uavcan_primitive_array_Real16,
                                             tvb, offset, 2, ENC_LITTLE_ENDIAN);
                    offset += 2;
                    break;

                default:
                    proto_tree_add_item(tree, hf_uavcan_primitive_Empty,
                                             tvb, 0, 0, ENC_NA);
                }
            }
        }
    }
}

static int
dissect_dsdl_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint32_t id = GPOINTER_TO_INT(data);

    proto_item_append_text(tree, " DSDL (%s)",
                           rval_to_str_const(id, uavcan_subject_id_vals, "Reserved"));

    if (id == 7509) {
        /* Dissect Heartbeat1.0 frame */
        proto_tree_add_item(tree, hf_heartbeat_uptime, tvb, 0, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_heartbeat_health, tvb, 4, 1, ENC_NA);
        proto_tree_add_item(tree, hf_heartbeat_mode, tvb, 5, 1, ENC_NA);
        proto_tree_add_item(tree, hf_heartbeat_status_code, tvb, 6, 1, ENC_NA);
        return tvb_captured_length(tvb);
    } else if (id == 8166) {
        /* Dissect NodeIDAllocationData1.0 allocation request */
        proto_tree_add_item(tree, hf_pnp_unique_id_hash, tvb, 0, 6, ENC_NA);
        proto_tree_add_item(tree, hf_pnp_alloc, tvb, 6, 1, ENC_NA);
        if (tvb_captured_length(tvb) > 8) {
            proto_tree_add_item(tree, hf_node_id, tvb, 7, 2, ENC_LITTLE_ENDIAN);
        }
        return tvb_captured_length(tvb);
    } else if (id == 8165) {
        /* Dissect NodeIDAllocationData2.0 allocation request/response */
        proto_tree_add_item(tree, hf_node_id, tvb, 0, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_pnp_unique_id, tvb, 2, 16, ENC_NA);
        proto_tree_add_uint(tree, hf_pnp_alloc, tvb, 0, 0,
                            (cmp_address(&anonymous_address, (const address *) &pinfo->src) != 0));
        return tvb_captured_length(tvb);
    } else if (id == 8184) {
        /* Dissect Synchronization.1.0 frame */
        proto_tree_add_item(tree, hf_uavcan_time_syncronizedtimestamp, tvb, 0, 7,
                            ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_diagnostic_severity, tvb, 7, 1, ENC_NA);
        proto_tree_add_item(tree, hf_uavcan_primitive_String, tvb, 8, 1,
                            ENC_ASCII|ENC_BIG_ENDIAN);
        return tvb_captured_length(tvb);
    }

    return 0;
}

static int
dissect_dsdl_service_request(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint32_t id = GPOINTER_TO_INT(data);

    (void) pinfo;

    proto_item_append_text(tree, " DSDL (%s)",
                           rval_to_str_const(id, uavcan_service_id_vals, "Reserved"));

    if (id == 384) { /* Dissect Access.1.0 frame */
        dissect_access_service_data(tvb, 0, tree, true);
        return tvb_captured_length(tvb);
    } else if (id == 385) { /* Dissect List.1.0 frame */
        dissect_list_service_data(tvb, 0, tree, true);
        return tvb_captured_length(tvb);
    } else if (id == 405) { /* Dissect GetInfo.0.X frame */
        proto_tree_add_item(tree, hf_uavcan_getinfo_path,
                            tvb, 0, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        return tvb_captured_length(tvb);
    } else if (id == 406) { /* Dissect List.0.X frame */
        proto_tree_add_item(tree, hf_uavcan_entry_index,
                            tvb, 0, 4, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_directory_path,
                            tvb, 8, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        return tvb_captured_length(tvb);
     } else if (id == 407) { /* Dissect Modify.1.X frame */
        proto_tree_add_item(tree, hf_uavcan_modify_preserve_source,
                            tvb, 0, 1, ENC_NA);
        proto_tree_add_item(tree, hf_uavcan_modify_overwrite_destination,
                            tvb, 0, 1, ENC_NA);
        int len;
        proto_tree_add_item_ret_length(tree, hf_uavcan_modify_source_path,
                            tvb, 4, 1, ENC_ASCII|ENC_BIG_ENDIAN, &len);
        proto_tree_add_item(tree, hf_uavcan_modify_destination_path,
                            tvb, 4 + len, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        return tvb_captured_length(tvb);
    } else if (id == 408) { /* Dissect Read.1.X frame */
        proto_tree_add_item(tree, hf_uavcan_read_offset,
                            tvb, 0, 5, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_read_path,
                            tvb, 5, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        return tvb_captured_length(tvb);
    } else if (id == 409) { /* Dissect Write.1.X frame */
        proto_tree_add_item(tree, hf_uavcan_write_offset,
                            tvb, 0, 5, ENC_LITTLE_ENDIAN);
        int len;
        proto_tree_add_item_ret_length(tree, hf_uavcan_write_path,
                            tvb, 5, 1, ENC_ASCII|ENC_BIG_ENDIAN, &len);
        uint16_t data_len = tvb_get_uint16(tvb, 5 + len, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_primitive_Unstructured,
                            tvb, 7 + len, data_len, ENC_NA);
        return tvb_captured_length(tvb);
    }

    return 0;
}

static int
dissect_dsdl_service_response(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    uint32_t id = GPOINTER_TO_INT(data);

    (void) pinfo;

    proto_item_append_text(tree, " DSDL (%s)",
                           rval_to_str_const(id, uavcan_service_id_vals, "Reserved"));

    if (id == 384) { /* Dissect Access.1.0 frame */
        dissect_access_service_data(tvb, 0, tree, false);
        return tvb_captured_length(tvb);
    } else if (id == 385) { /* Dissect List.1.0 frame */
        dissect_list_service_data(tvb, 0, tree, false);
        return tvb_captured_length(tvb);
    } else if (id == 405) { /* Dissect GetInfo.0.X frame */
        proto_tree_add_item(tree, hf_uavcan_getinfo_error,
                            tvb, 0, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_getinfo_size,
                            tvb, 2, 5, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_getinfo_timestamp,
                            tvb, 7, 5, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_getinfo_is_file_not_directory,
                            tvb, 13, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_getinfo_is_link,
                            tvb, 13, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_getinfo_is_readable,
                            tvb, 13, 1, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_getinfo_is_writeable,
                            tvb, 13, 1, ENC_LITTLE_ENDIAN);
        return tvb_captured_length(tvb);
    } else if (id == 406) { /* Dissect List.0.X frame */
        /* FT_UINT_STRING counted string, with count being the first byte */
        proto_tree_add_item(tree, hf_uavcan_entry_base_name,
                            tvb, 4, 1, ENC_ASCII|ENC_BIG_ENDIAN);
        return tvb_captured_length(tvb);
    } else if (id == 407) { /* Dissect Modify.1.X frame */
        proto_tree_add_item(tree, hf_uavcan_modify_error,
                            tvb, 0, 2, ENC_LITTLE_ENDIAN);
        return tvb_captured_length(tvb);
    } else if (id == 408) { /* Dissect Read.1.X frame */
        proto_tree_add_item(tree, hf_uavcan_read_error,
                            tvb, 0, 2, ENC_LITTLE_ENDIAN);
        uint16_t data_len = tvb_get_uint16(tvb, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_uavcan_primitive_Unstructured,
                            tvb, 4, data_len, ENC_NA);
        return tvb_captured_length(tvb);
    } else if (id == 409) { /* Dissect Write.1.X frame */
        proto_tree_add_item(tree, hf_uavcan_write_error,
                            tvb, 0, 2, ENC_LITTLE_ENDIAN);
        return tvb_captured_length(tvb);
    }

    return 0;
}

void
proto_register_dsdl(void)
{
    static hf_register_info hf[] = {
        {&hf_node_id,
          {"Node ID",                               "uavcan_dsdl.node.id",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_pnp_unique_id,
          {"Unique ID",                             "uavcan_dsdl.pnp.unique_id",
          FT_BYTES, BASE_NONE | BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL}},
        {&hf_pnp_unique_id_hash,
          {"Unique ID hash",                        "uavcan_dsdl.pnp.unique_id_hash",
          FT_BYTES, BASE_NONE | BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL}},
        {&hf_pnp_alloc,
          {"allocation type",                       "uavcan_dsdl.pnp.allocation",
          FT_UINT8, BASE_DEC, VALS(uavcan_nodeid_alloc_vals), 0x0, NULL, HFILL}},

        // Heartbeat 1.0
        {&hf_heartbeat_uptime,
          {"Uptime",                                "uavcan_dsdl.Heartbeat.uptime",
          FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_heartbeat_health,
          {"Health",                                "uavcan_dsdl.Heartbeat.health",
          FT_UINT8, BASE_DEC, VALS(uavcan_heartbeat_health_vals), 0x0, NULL, HFILL}},
        {&hf_heartbeat_mode,
          {"Mode",                                  "uavcan_dsdl.Heartbeat.mode",
          FT_UINT8, BASE_DEC, VALS(uavcan_heartbeat_mode_vals), 0x0, NULL, HFILL}},
        {&hf_heartbeat_status_code,
          {"Vendor specific status code",
          "uavcan_dsdl.Heartbeat.vendor_specific_status_code",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_time_syncronizedtimestamp,
          {"Timestamp (usec)",                      "uavcan_dsdl.time.SynchronizedTimestamp",
          FT_UINT56, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_diagnostic_severity,
          {"Severity",                              "uavcan_dsdl.diagnostic.severity",
          FT_UINT8, BASE_DEC, VALS(uavcan_diagnostic_severity_vals), 0x0, NULL, HFILL}},

        // List1.0 Request
        {&hf_list_index,
          {"Index",                                 "uavcan_dsdl.register.List.index",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_register_name,
          {"Name",                                  "uavcan_dsdl.register.Name",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},

        // Access1.0 Value1.0
        {&hf_register_access_mutable,
          {"Mutable",                               "uavcan_dsdl.register.Access.mutable",
          FT_UINT8, BASE_DEC, NULL, 0x1, NULL, HFILL}},
        {&hf_register_access_persistent,
          {"Persistent",                            "uavcan_dsdl.register.Access.persistent",
          FT_UINT8, BASE_DEC, NULL, 0x2, NULL, HFILL}},
        {&hf_register_value_tag,
          {"Tag",                                   "uavcan_dsdl.register.Value.tag",
          FT_UINT8, BASE_DEC, VALS(uavcan_value_tag_vals), 0x0, NULL, HFILL}},
        {&hf_register_value_size,
          {"Array size",                            "uavcan_dsdl.primitive.array.size",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_Empty,
          {"Empty",                                 "uavcan_dsdl.primitive.Empty",
          FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_String,
          {"String",                                "uavcan_dsdl.primitive.String",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_Unstructured,
          {"Unstructured",                          "uavcan_dsdl.primitive.array.Unstructured",
          FT_BYTES, BASE_NONE | BASE_ALLOW_ZERO, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Integer64,
          {"Integer64",                             "uavcan_dsdl.primitive.array.Integer64",
          FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Integer32,
          {"Integer32",                             "uavcan_dsdl.primitive.array.Integer32",
          FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Integer16,
          {"Integer16",                             "uavcan_dsdl.primitive.array.Integer16",
          FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Integer8,
          {"Integer8",                              "uavcan_dsdl.primitive.array.Integer8",
          FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Natural64,
          {"Natural64",                             "uavcan_dsdl.primitive.array.Natural64",
          FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Natural32,
          {"Natural32",                             "uavcan_dsdl.primitive.array.Natural32",
          FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Natural16,
          {"Natural16",                             "uavcan_dsdl.primitive.array.Natural16",
          FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Natural8,
          {"Natural8",                              "uavcan_dsdl.primitive.array.Natural8",
          FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Real64,
          {"Real64",                                "uavcan_dsdl.primitive.array.Real64",
          FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Real32,
          {"Real32",                                "uavcan_dsdl.primitive.array.Real32",
          FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_primitive_array_Real16,
          {"Real16",                                "uavcan_dsdl.primitive.array.Real16",
          FT_IEEE_11073_SFLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL}   /* TODO not sure check */
        },
        {&hf_uavcan_getinfo_path,
          {"Path",                                  "uavcan_dsdl.file.GetInfo.path",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_getinfo_error,
          {"Error",                                 "uavcan_dsdl.file.GetInfo.error",
          FT_UINT16, BASE_DEC, VALS(uavcan_file_error_vals), 0x0, NULL, HFILL}},
        {&hf_uavcan_getinfo_size,
          {"Size",                                  "uavcan_dsdl.file.GetInfo.size",
          FT_UINT40, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_getinfo_timestamp,
          {"Timestamp",                             "uavcan_dsdl.file.GetInfo.timestamp",
          FT_UINT40, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_getinfo_is_file_not_directory,
          {"Is file not directory",
          "uavcan_dsdl.file.GetInfo.is_file_not_directory",
          FT_UINT8, BASE_DEC, NULL, 0x1, NULL, HFILL}},
        {&hf_uavcan_getinfo_is_link,
          {"Is link",                               "uavcan_dsdl.file.GetInfo.is_link",
          FT_UINT8, BASE_DEC, NULL, 0x2, NULL, HFILL}},
        {&hf_uavcan_getinfo_is_readable,
          {"Is readable",                           "uavcan_dsdl.file.GetInfo.is_readable",
          FT_UINT8, BASE_DEC, NULL, 0x4, NULL, HFILL}},
        {&hf_uavcan_getinfo_is_writeable,
          {"Is writeable",                          "uavcan_dsdl.file.GetInfo.is_writeable",
          FT_UINT8, BASE_DEC, NULL, 0x8, NULL, HFILL}},
        {&hf_uavcan_read_path,
          {"Path",                                  "uavcan_dsdl.file.Read.path",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_write_path,
          {"Path",                                  "uavcan_dsdl.file.Write.path",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_directory_path,
          {"Directory path",                        "uavcan_dsdl.file.list.directory_path",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_entry_base_name,
          {"Base name",                             "uavcan_dsdl.file.list.entry_base_name",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_modify_source_path,
          {"Source",                                "uavcan_dsdl.file.Modify.source",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_modify_destination_path,
          {"Destination",                           "uavcan_dsdl.file.Modify.Destination",
          FT_UINT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_modify_preserve_source,
          {"Preserve source",                       "uavcan_dsdl.Modify.preserve_source",
          FT_UINT8, BASE_DEC, NULL, 0x1, NULL, HFILL}},
        {&hf_uavcan_modify_overwrite_destination,
          {"Overwrite destination",                 "uavcan_dsdl.Modify.overwrite_destination",
          FT_UINT8, BASE_DEC, NULL, 0x2, NULL, HFILL}},
        {&hf_uavcan_modify_error,
          {"Error",                                 "uavcan_dsdl.Modify.error",
          FT_UINT16, BASE_DEC, VALS(uavcan_file_error_vals), 0x0, NULL, HFILL}},
        {&hf_uavcan_read_offset,
          {"Offset",                                "uavcan_dsdl.Read.offset",
          FT_UINT40, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_read_error,
          {"Error",                                 "uavcan_dsdl.Read.error",
          FT_UINT16, BASE_DEC, VALS(uavcan_file_error_vals), 0x0, NULL, HFILL}},
        {&hf_uavcan_write_offset,
          {"Offset",                                "uavcan_dsdl.Write.offset",
          FT_UINT40, BASE_DEC, NULL, 0x0, NULL, HFILL}},
        {&hf_uavcan_write_error,
          {"Error",                                 "uavcan_dsdl.Write.error",
          FT_UINT16, BASE_DEC, VALS(uavcan_file_error_vals), 0x0, NULL, HFILL}},
        {&hf_uavcan_entry_index,
          {"Entry index",                           "uavcan_dsdl.file.list.entry_index",
          FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    };

    static int *ett[] = {
        &ett_dsdl,
    };

    proto_dsdl = proto_register_protocol("UAVCAN DSDL", "DSDL", "uavcan_dsdl");

    proto_register_field_array(proto_dsdl, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("uavcan_dsdl.message", dissect_dsdl_message, proto_dsdl);
    register_dissector("uavcan_dsdl.request", dissect_dsdl_service_request, proto_dsdl);
    register_dissector("uavcan_dsdl.response", dissect_dsdl_service_response, proto_dsdl);
}

void
proto_reg_handoff_dsdl(void)
{
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
