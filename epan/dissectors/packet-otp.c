/* packet-otp.c
 * Routines for OTP (ANSI E1.59) packet disassembly
 *
 * Copyright (c) 2025 by Matt Morris <mattm.dev.1[AT]gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


/* Include files */
#include "config.h"
#include <epan/packet.h>
#include <epan/unit_strings.h>
#include <epan/tfs.h>
#include <epan/expert.h>
#include <epan/conversation.h>
#include <wsutil/utf8_entities.h>
#include "data-dmx-manfid.h"

#define OTP_IDENTIFIER ((const uint8_t*)"OTP-E1.59\x00\x00\x00")
#define OTP_IDENTIFIER_LEN (12)

/* constants */
#define OTP_MESSAGE_TRANSFORM     0x0001
#define OTP_MESSAGE_ADVERTISEMENT 0x0002

#define OTP_POINT 0x0001

#define OTP_MODULE 0x0001

#define OTP_ADVERTISEMENT_MODULE 0x0001
#define OTP_ADVERTISEMENT_NAME   0x0002
#define OTP_ADVERTISEMENT_SYSTEM 0x0003

#define OTP_ADVERTISEMENT_MODULE_LIST 0x0001

#define OTP_ADVERTISEMENT_NAME_LIST 0x0001

#define OTP_ADVERTISEMENT_SYSTEM_LIST 0x0001


#define OTP_MANFID_ESTA    0x0000
#define OTP_MANFID_CHAMSYS 0x050A

#define OTP_MODULE_ESTA_POS           0x0001
#define OTP_MODULE_ESTA_POS_VEL_ACCEL 0x0002
#define OTP_MODULE_ESTA_ROT           0x0003
#define OTP_MODULE_ESTA_ROT_VEL_ACCEL 0x0004
#define OTP_MODULE_ESTA_SCALE         0x0005
#define OTP_MODULE_ESTA_REF_FRAME     0x0006

static int proto_otp;

static dissector_handle_t otp_handle;


/*  Open/Close trees */
static int ett_otp;

static int ett_otp_advert;
static int ett_otp_advert_module;
static int ett_otp_advert_name;
static int ett_otp_advert_system;

static int ett_otp_transform;
static int ett_otp_point;
static int ett_otp_module;

static int ett_otp_transform_options;
static int ett_otp_advert_name_options;
static int ett_otp_advert_system_options;
static int ett_otp_module_options;

static int ett_otp_advert_module_identifier;
static int ett_otp_advert_name_address_point_descriptor;
static int ett_otp_advert_system_numbers;

/* Expert Info  */
static expert_field ei_otp_pdu_vector;
static expert_field ei_otp_pdu_len;
static expert_field ei_otp_module_number;
static expert_field ei_otp_module_manfid;

/*  Register fields */

/*  OTP Layer: Table 6-1 */
static int hf_otp_identifier;
static int hf_otp_vector;
static int hf_otp_length;
static int hf_otp_footer_options;
static int hf_otp_footer_length;
static int hf_otp_sender_cid;
static int hf_otp_folio;
static int hf_otp_page;
static int hf_otp_last_page;
static int hf_otp_options;
static int hf_otp_reserved;
static int hf_otp_component_name;

/* Advertisement Layer: Table 11-1 */
static int hf_otp_advert;
static int hf_otp_advert_vector;
static int hf_otp_advert_length;
static int hf_otp_advert_reserved;

/* Module Advertisement Layer: Table 12-1 */
static int hf_otp_advert_module;
static int hf_otp_advert_module_vector;
static int hf_otp_advert_module_length;
static int hf_otp_advert_module_reserved;
static int hf_otp_advert_module_identifier;

/* Name Advertisement Layer: Table 13-1 */
static int hf_otp_advert_name;
static int hf_otp_advert_name_vector;
static int hf_otp_advert_name_length;
static int hf_otp_advert_name_options;
static int hf_otp_advert_name_req_resp;
static int hf_otp_advert_name_reserved;
static int hf_otp_advert_name_address_point_descriptor;

/* System Advertisement Layer: Table 12-1 */
static int hf_otp_advert_system;
static int hf_otp_advert_system_vector;
static int hf_otp_advert_system_length;
static int hf_otp_advert_system_options;
static int hf_otp_advert_system_req_resp;
static int hf_otp_advert_system_reserved;
static int hf_otp_advert_system_numbers;

/* Transform Layer: Table 8-1 */
static int hf_otp_transform;
static int hf_otp_transform_vector;
static int hf_otp_transform_length;
static int hf_otp_transform_system_number;
static int hf_otp_transform_timestamp;
static int hf_otp_transform_options;
static int hf_otp_transform_pointset;
static int hf_otp_transform_reserved;

/* Point Layer: Table 9-1 */
static int hf_otp_point;
static int hf_otp_point_vector;
static int hf_otp_point_length;
static int hf_otp_point_priority;
static int hf_otp_point_group_number;
static int hf_otp_point_number;
static int hf_otp_point_timestamp;
static int hf_otp_point_options;
static int hf_otp_point_reserved;
static int hf_otp_point_name;

/* Module Layer: Table 10-1 */
static int hf_otp_module;
static int hf_otp_module_manf_id;
static int hf_otp_module_length;
static int hf_otp_module_module_number;
static int hf_otp_module_esta_number;

/* Tables 16-1 to 16-6 */
static int hf_otp_module_options;
static int hf_otp_module_scaling;
static int hf_otp_module_x_um;
static int hf_otp_module_y_um;
static int hf_otp_module_z_um;
static int hf_otp_module_x_mm;
static int hf_otp_module_y_mm;
static int hf_otp_module_z_mm;
static int hf_otp_module_vx;
static int hf_otp_module_vy;
static int hf_otp_module_vz;
static int hf_otp_module_ax;
static int hf_otp_module_ay;
static int hf_otp_module_az;
static int hf_otp_module_rx;
static int hf_otp_module_ry;
static int hf_otp_module_rz;
static int hf_otp_module_rvx;
static int hf_otp_module_rvy;
static int hf_otp_module_rvz;
static int hf_otp_module_rax;
static int hf_otp_module_ray;
static int hf_otp_module_raz;
static int hf_otp_module_scale_x;
static int hf_otp_module_scale_y;
static int hf_otp_module_scale_z;
static int hf_otp_module_reference_system;
static int hf_otp_module_reference_group;
static int hf_otp_module_reference_point;


static const true_false_string tfs_scaling = {
    "mm",
    UTF8_MICRO_SIGN "m",
};

static const unit_name_string units_microdegree = { " " UTF8_MICRO_SIGN UTF8_DEGREE_SIGN, NULL };
static const unit_name_string units_millidegree_sec = { " m" UTF8_DEGREE_SIGN "/s", NULL };
static const unit_name_string units_millidegree_sec_squared = { " m" UTF8_DEGREE_SIGN "/s" UTF8_SUPERSCRIPT_TWO, NULL };

static const unit_name_string units_millimeters_space = { " mm", NULL };
static const unit_name_string units_micrometers = { " " UTF8_MICRO_SIGN "m", NULL };
static const unit_name_string units_micrometer_sec = { " " UTF8_MICRO_SIGN "m/s", NULL };
static const unit_name_string units_micrometer_sec_squared = { " " UTF8_MICRO_SIGN "m/s" UTF8_SUPERSCRIPT_TWO, NULL };

static const value_string otp_message_type_names[] = {
    { OTP_MESSAGE_TRANSFORM,     "Transform Message" },
    { OTP_MESSAGE_ADVERTISEMENT, "Advertisement Message" },
    { 0,                         NULL },
};

static const value_string otp_transform_type_names[] = {
    { OTP_POINT, "Point" },
    { 0,         NULL },
};

static const value_string otp_point_type_names[] = {
    { OTP_MODULE, "Module" },
    { 0,          NULL },
};

static const value_string otp_module_esta_names[] = {
    { OTP_MODULE_ESTA_POS,           "Position" },
    { OTP_MODULE_ESTA_POS_VEL_ACCEL, "Position Velocity/Acceleration" },
    { OTP_MODULE_ESTA_ROT,           "Rotation" },
    { OTP_MODULE_ESTA_ROT_VEL_ACCEL, "Rotation Velocity/Acceleration" },
    { OTP_MODULE_ESTA_SCALE,         "Scale" },
    { OTP_MODULE_ESTA_REF_FRAME,     "Reference Frame" },
    { 0,                             NULL },
};

static const value_string otp_advertisement_type_names[] = {
    { OTP_ADVERTISEMENT_MODULE, "Module Advertisement" },
    { OTP_ADVERTISEMENT_NAME,   "Name Advertisement" },
    { OTP_ADVERTISEMENT_SYSTEM, "System Advertisement" },
    { 0,                        NULL },
};

static const value_string otp_advertisement_module_type_names[] = {
    { OTP_ADVERTISEMENT_MODULE_LIST, "Module List" },
    { 0,                             NULL },
};
static const value_string otp_advertisement_name_type_names[] = {
    { OTP_ADVERTISEMENT_NAME_LIST, "Name List" },
    { 0,                           NULL },
};
static const value_string otp_advertisement_system_type_names[] = {
    { OTP_ADVERTISEMENT_SYSTEM_LIST, "System List" },
    { 0,                             NULL },
};


static int* const otp_advert_system_options[] = {
    &hf_otp_advert_system_req_resp,
    NULL,
};

static int* const otp_advert_name_options[] = {
    &hf_otp_advert_name_req_resp,
    NULL,
};

static int* const otp_transform_options[] = {
    &hf_otp_transform_pointset,
    NULL
};

static int* const otp_module_options[] = {
    &hf_otp_module_scaling,
    NULL
};


/******************************************************************************/
/* Dissect protocol                                                           */

static proto_tree* dissect_otp_pdu_start(tvbuff_t* tvb, proto_tree* tree, proto_item** out_item, int* offset, int* pdu_end, uint32_t* vector, uint32_t* length, int hf_pdu, int ett_pdu, int hf_pdu_vector, int hf_pdu_length) {
    *out_item = proto_tree_add_item(tree, hf_pdu, tvb, *offset, -1, ENC_NA);
    proto_tree* pdu_tree = proto_item_add_subtree(*out_item, ett_pdu);

    proto_tree_add_item_ret_uint(pdu_tree, hf_pdu_vector, tvb, *offset, 2, ENC_BIG_ENDIAN, vector);
    *offset+=2;

    proto_tree_add_item_ret_uint(pdu_tree, hf_pdu_length, tvb, *offset, 2, ENC_BIG_ENDIAN, length);
    proto_item_set_len(*out_item, (*length)+4);
    *offset+=2;

    *pdu_end = (*offset)+(*length);

    return pdu_tree;
}

static int dissect_otp_module_layer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    int pdu_end;
    uint32_t manf_id, length;
    proto_item* module_item;
    proto_tree* module_tree = dissect_otp_pdu_start(tvb, tree, &module_item, &offset, &pdu_end, &manf_id,
        &length, hf_otp_module, ett_otp_module, hf_otp_module_manf_id, hf_otp_module_length);

    /* Chamsys desks send esta standard codes with their own manufacturer ID */
    if (manf_id != OTP_MANFID_ESTA && manf_id != OTP_MANFID_CHAMSYS) {
        proto_tree_add_item(module_tree, hf_otp_module_module_number, tvb, offset, 2, ENC_BIG_ENDIAN);
        proto_item_append_text(module_item, ", Unknown Manufacturer");
        expert_add_info(pinfo, module_tree, &ei_otp_module_manfid);
        return pdu_end;
    }

    uint32_t module_number;
    proto_tree_add_item_ret_uint(module_tree, hf_otp_module_esta_number, tvb, offset, 2, ENC_BIG_ENDIAN, &module_number);
    offset+=2;
    proto_item_append_text(module_item, ", ESTA: %s", val_to_str(pinfo->pool, module_number, otp_module_esta_names, ", ESTA: Unknown (%u)"));

    switch (module_number) {
        case OTP_MODULE_ESTA_POS: {
            uint64_t scaling;
            proto_tree_add_bitmask_with_flags_ret_uint64(module_tree, tvb, offset, hf_otp_module_options, ett_otp_module_options, otp_module_options, ENC_BIG_ENDIAN, 0, &scaling);
            offset+=1;
            if (scaling & 0x80) { /* Bit set to 1 indicates values are in mm */
                proto_tree_add_item(module_tree, hf_otp_module_x_mm, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
                proto_tree_add_item(module_tree, hf_otp_module_y_mm, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
                proto_tree_add_item(module_tree, hf_otp_module_z_mm, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
            } else {
                proto_tree_add_item(module_tree, hf_otp_module_x_um, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
                proto_tree_add_item(module_tree, hf_otp_module_y_um, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
                proto_tree_add_item(module_tree, hf_otp_module_z_um, tvb, offset, 4, ENC_BIG_ENDIAN);
                offset+=4;
            }
            break;
        }
        case OTP_MODULE_ESTA_POS_VEL_ACCEL:
            proto_tree_add_item(module_tree, hf_otp_module_vx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_vy, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_vz, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_ax, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_ay, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_az, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;
        case OTP_MODULE_ESTA_ROT:
            proto_tree_add_item(module_tree, hf_otp_module_rx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_ry, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_rz, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;
        case OTP_MODULE_ESTA_ROT_VEL_ACCEL:
            proto_tree_add_item(module_tree, hf_otp_module_rvx, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_rvy, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_rvz, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_rax, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_ray, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_raz, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;
        case OTP_MODULE_ESTA_SCALE:
            proto_tree_add_item(module_tree, hf_otp_module_scale_x, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_scale_y, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            proto_tree_add_item(module_tree, hf_otp_module_scale_z, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;
        case OTP_MODULE_ESTA_REF_FRAME:
            proto_tree_add_item(module_tree, hf_otp_module_reference_system, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset+=1;
            proto_tree_add_item(module_tree, hf_otp_module_reference_group, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset+=2;
            proto_tree_add_item(module_tree, hf_otp_module_reference_point, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset+=4;
            break;
        default:
            /* Unknown module type - just skip it */
            expert_add_info(pinfo, module_tree, &ei_otp_module_number);
            break;
    }


    if (offset != pdu_end) {
        expert_add_info(pinfo, module_tree, &ei_otp_pdu_len);
    } else if (manf_id != OTP_MANFID_ESTA) {
        /* Likely a known module (we consumed the correct amount of data). And not using the ESTA manf code */
        expert_add_info(pinfo, module_tree, &ei_otp_module_manfid);
    }
    return offset;
}

static int dissect_otp_point_layer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    int pdu_end;
    uint32_t vector, length;
    proto_item* point_item;
    proto_tree* point_tree = dissect_otp_pdu_start(tvb, tree, &point_item, &offset, &pdu_end, &vector,
        &length, hf_otp_point, ett_otp_point, hf_otp_point_vector, hf_otp_point_length);

    if (vector != OTP_POINT) {
        /* Unknown PDU vector - skip it */
        expert_add_info(pinfo, point_tree, &ei_otp_pdu_vector);
        return pdu_end;
    }

    uint32_t priority, group_num, point_num;
    proto_tree_add_item_ret_uint(point_tree, hf_otp_point_priority, tvb, offset, 1, ENC_BIG_ENDIAN, &priority);
    offset+=1;
    proto_tree_add_item_ret_uint(point_tree, hf_otp_point_group_number, tvb, offset, 2, ENC_BIG_ENDIAN, &group_num);
    offset+=2;
    proto_tree_add_item_ret_uint(point_tree, hf_otp_point_number, tvb, offset, 4, ENC_BIG_ENDIAN, &point_num);
    offset+=4;
    proto_item_append_text(point_item, ", %u.%u, Priority: %u", group_num, point_num, priority);

    proto_tree_add_item(point_tree, hf_otp_point_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN|ENC_TIME_USECS);
    offset+=8;

    proto_tree_add_item(point_tree, hf_otp_point_options, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    proto_tree_add_item(point_tree, hf_otp_point_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    int module_count = 0;
    while (offset < pdu_end) {
        offset = dissect_otp_module_layer(tvb, pinfo, point_tree, offset);
        module_count++;
    }
    proto_item_append_text(point_item, ", Module count: %u", module_count);

    if (offset != pdu_end)
        expert_add_info(pinfo, point_tree, &ei_otp_pdu_len);
    return pdu_end;
}

static int dissect_otp_transform_layer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    int pdu_end;
    uint32_t vector, length;
    proto_item* trans_item;
    proto_tree* trans_tree = dissect_otp_pdu_start(tvb, tree, &trans_item, &offset, &pdu_end, &vector,
        &length, hf_otp_transform, ett_otp_transform, hf_otp_transform_vector, hf_otp_transform_length);

    if (vector != OTP_POINT) {
        /* Unknown PDU vector - skip it */
        expert_add_info(pinfo, trans_tree, &ei_otp_pdu_vector);
        return pdu_end;
    }

    uint32_t system_number;
    proto_tree_add_item_ret_uint(trans_tree, hf_otp_transform_system_number, tvb, offset, 1, ENC_BIG_ENDIAN, &system_number);
    offset+=1;
    proto_tree_add_item(trans_tree, hf_otp_transform_timestamp, tvb, offset, 8, ENC_BIG_ENDIAN|ENC_TIME_USECS);
    offset+=8;

    /* Flags */
    proto_tree_add_bitmask(trans_tree, tvb, offset, hf_otp_transform_options, ett_otp_transform_options, otp_transform_options, ENC_BIG_ENDIAN);
    offset+=1;

    proto_tree_add_item(trans_tree, hf_otp_transform_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    int point_count = 0;
    while (offset < pdu_end) {
        offset = dissect_otp_point_layer(tvb, pinfo, trans_tree, offset);
        point_count++;
    }
    proto_item_append_text(tree, ", Point Transform, System %d, %d points", system_number, point_count);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", Point Transform, System %d, %d points", system_number, point_count);

    if (offset != pdu_end)
        expert_add_info(pinfo, trans_tree, &ei_otp_pdu_len);
    return pdu_end;
}

static int dissect_otp_advertisement_module_layer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    int pdu_end;
    uint32_t vector, length;
    proto_item* advert_item;
    proto_tree* advert_tree = dissect_otp_pdu_start(tvb, tree, &advert_item, &offset, &pdu_end, &vector,
        &length, hf_otp_advert_module, ett_otp_advert_module, hf_otp_advert_module_vector, hf_otp_advert_module_length);

    if (vector != OTP_ADVERTISEMENT_MODULE_LIST) {
        /* Unknown PDU vector - skip it */
        expert_add_info(pinfo, advert_tree, &ei_otp_pdu_vector);
        return pdu_end;
    }

    proto_tree_add_item(advert_tree, hf_otp_advert_module_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    int module_count = 0;
    while (offset < pdu_end) {
        proto_item* id = proto_tree_add_item(advert_tree, hf_otp_advert_module_identifier, tvb, offset, 4, ENC_NA);
        proto_tree* id_tree = proto_item_add_subtree(id, ett_otp_advert_module_identifier);

        uint32_t manf_id;
        proto_tree_add_item_ret_uint(id_tree, hf_otp_module_manf_id, tvb, offset, 2, ENC_BIG_ENDIAN, &manf_id);
        offset+=2;
        if (manf_id == OTP_MANFID_ESTA || manf_id == OTP_MANFID_CHAMSYS) {
            uint32_t mod_number;
            proto_tree_add_item_ret_uint(id_tree, hf_otp_module_esta_number, tvb, offset, 2, ENC_BIG_ENDIAN, &mod_number);
            proto_item_append_text(id, ", ESTA: %s", val_to_str(pinfo->pool, mod_number, otp_module_esta_names, ", ESTA: Unknown (%d)"));
        } else {
            proto_item_append_text(id, ", Unknown Manufacturer");
            proto_tree_add_item(id_tree, hf_otp_module_module_number, tvb, offset, 2, ENC_BIG_ENDIAN);
        }
        offset+=2;
        module_count++;
    }
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %d modules", module_count);

    if (offset != pdu_end)
        expert_add_info(pinfo, advert_tree, &ei_otp_pdu_len);
    return pdu_end;
}
static int dissect_otp_advertisement_name_layer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    int pdu_end;
    uint32_t vector, length;
    proto_item* advert_item;
    proto_tree* advert_tree = dissect_otp_pdu_start(tvb, tree, &advert_item, &offset, &pdu_end, &vector,
        &length, hf_otp_advert_name, ett_otp_advert_name, hf_otp_advert_name_vector, hf_otp_advert_name_length);

    if (vector != OTP_ADVERTISEMENT_NAME_LIST) {
        /* Unknown PDU vector - skip it */
        expert_add_info(pinfo, advert_tree, &ei_otp_pdu_vector);
        return pdu_end;
    }

    uint64_t flags;
    proto_tree_add_bitmask_with_flags_ret_uint64(advert_tree, tvb, offset, hf_otp_advert_name_options, ett_otp_advert_name_options, otp_advert_name_options, ENC_BIG_ENDIAN, 0, &flags);
    offset+=1;
    proto_tree_add_item(advert_tree, hf_otp_advert_name_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    int name_count = 0;
    while (offset < pdu_end) {
        proto_item* desc = proto_tree_add_item(advert_tree, hf_otp_advert_name_address_point_descriptor, tvb, offset, 39, ENC_NA);
        proto_tree* desc_tree = proto_item_add_subtree(desc, ett_otp_advert_name_address_point_descriptor);

        uint32_t n;
        proto_tree_add_item_ret_uint(desc_tree, hf_otp_transform_system_number, tvb, offset, 1, ENC_BIG_ENDIAN, &n);
        proto_item_append_text(desc, ", %d", n);
        offset+=1;
        proto_tree_add_item_ret_uint(desc_tree, hf_otp_point_group_number, tvb, offset, 2, ENC_BIG_ENDIAN, &n);
        proto_item_append_text(desc, ".%d", n);
        offset+=2;
        proto_tree_add_item_ret_uint(desc_tree, hf_otp_point_number, tvb, offset, 4, ENC_BIG_ENDIAN, &n);
        proto_item_append_text(desc, ".%d", n);
        offset+=4;
        const uint8_t* point_name;
        proto_tree_add_item_ret_string(desc_tree, hf_otp_point_name, tvb, offset, 32, ENC_UTF_8, pinfo->pool, &point_name);
        proto_item_append_text(desc, ", %s", point_name);
        offset+=32;

        name_count++;
    }
    if (flags & 0x80) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Response, %d points", name_count);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, " Request");
    }

    if (offset != pdu_end)
        expert_add_info(pinfo, advert_tree, &ei_otp_pdu_len);
    return pdu_end;
}
static int dissect_otp_advertisement_system_layer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    int pdu_end;
    uint32_t vector, length;
    proto_item* advert_item;
    proto_tree* advert_tree = dissect_otp_pdu_start(tvb, tree, &advert_item, &offset, &pdu_end, &vector,
        &length, hf_otp_advert_system, ett_otp_advert_system, hf_otp_advert_system_vector, hf_otp_advert_system_length);

    if (vector != OTP_ADVERTISEMENT_SYSTEM_LIST) {
        /* Unknown PDU vector - skip it */
        expert_add_info(pinfo, advert_tree, &ei_otp_pdu_vector);
        return pdu_end;
    }

    uint64_t flags;
    proto_tree_add_bitmask_with_flags_ret_uint64(advert_tree, tvb, offset, hf_otp_advert_system_options, ett_otp_advert_system_options, otp_advert_system_options, ENC_BIG_ENDIAN, 0, &flags);
    offset+=1;
    proto_tree_add_item(advert_tree, hf_otp_advert_system_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    int sys_count = 0;
    while (offset < pdu_end) {
        proto_tree_add_item(advert_tree, hf_otp_transform_system_number, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset+=1;

        sys_count++;
    }
    if (flags & 0x80) {
        col_append_fstr(pinfo->cinfo, COL_INFO, " Response, %d systems", sys_count);
    } else {
        col_append_str(pinfo->cinfo, COL_INFO, " Request");
    }

    if (offset != pdu_end)
        expert_add_info(pinfo, advert_tree, &ei_otp_pdu_len);
    return pdu_end;
}

static int dissect_otp_advertisement_layer(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, int offset) {
    int pdu_end;
    uint32_t vector, length;
    proto_item* advert_item;
    proto_tree* advert_tree = dissect_otp_pdu_start(tvb, tree, &advert_item, &offset, &pdu_end, &vector,
        &length, hf_otp_advert, ett_otp_advert, hf_otp_advert_vector, hf_otp_advert_length);

    proto_tree_add_item(advert_tree, hf_otp_advert_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    const char* mod_str = val_to_str_const(vector, otp_advertisement_type_names, "Unknown Advertisement");
    proto_item_append_text(tree, ", %s", mod_str);
    col_append_fstr(pinfo->cinfo, COL_INFO, ", %s", mod_str);

    switch (vector) {
        case OTP_ADVERTISEMENT_MODULE:
            offset = dissect_otp_advertisement_module_layer(tvb, pinfo, advert_tree, offset);
            break;
        case OTP_ADVERTISEMENT_NAME:
            offset = dissect_otp_advertisement_name_layer(tvb, pinfo, advert_tree, offset);
            break;
        case OTP_ADVERTISEMENT_SYSTEM:
            offset = dissect_otp_advertisement_system_layer(tvb, pinfo, advert_tree, offset);
            break;
        default:
            /* Unknown PDU vector - skip it */
            expert_add_info(pinfo, tree, &ei_otp_pdu_vector);
            break;
    }

    if (offset != pdu_end)
        expert_add_info(pinfo, advert_tree, &ei_otp_pdu_len);
    return pdu_end;
}


static int
dissect_otp(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data _U_)
{
    if (tvb_reported_length(tvb) < 12) {
        return 0;
    }

    /* Check magic */
    if (tvb_memeql(tvb, 0, OTP_IDENTIFIER, OTP_IDENTIFIER_LEN) != 0) {
        return 0;
    }

    int offset = 0;
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "OTP");
    /* Clear the info column */
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item* ti = proto_tree_add_item(tree, proto_otp, tvb, 0, -1, ENC_NA);
    proto_tree* otp_tree = proto_item_add_subtree(ti, ett_otp);

    proto_tree_add_item(otp_tree, hf_otp_identifier, tvb, 0, 12, ENC_NA);
    offset+=12;

    uint32_t vector;
    proto_tree_add_item_ret_uint(otp_tree, hf_otp_vector, tvb, offset, 2, ENC_BIG_ENDIAN, &vector);
    offset+=2;

    uint32_t length;
    proto_tree_add_item_ret_uint(otp_tree, hf_otp_length, tvb, offset, 2, ENC_BIG_ENDIAN, &length);
    proto_item_set_len(ti, length+16);
    offset+=2;
    int pdu_end = offset+length;

    proto_tree_add_item(otp_tree, hf_otp_footer_options, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    proto_tree_add_item(otp_tree, hf_otp_footer_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;

    proto_tree_add_item(otp_tree, hf_otp_sender_cid, tvb, offset, 16, ENC_BIG_ENDIAN);
    offset+=16;

    uint32_t folio_num;
    proto_tree_add_item_ret_uint(otp_tree, hf_otp_folio, tvb, offset, 4, ENC_BIG_ENDIAN, &folio_num);
    offset+=4;
    proto_tree_add_item(otp_tree, hf_otp_page, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;
    proto_tree_add_item(otp_tree, hf_otp_last_page, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset+=2;

    proto_tree_add_item(otp_tree, hf_otp_options, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset+=1;
    proto_tree_add_item(otp_tree, hf_otp_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset+=4;

    const uint8_t* component_name;
    proto_tree_add_item_ret_string(otp_tree, hf_otp_component_name, tvb, offset, 32, ENC_UTF_8, pinfo->pool, &component_name);
    offset+=32;
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s, Folio: %4u", component_name, folio_num);
    proto_item_append_text(otp_tree, ", Component: %s", component_name);

    switch (vector) {
        case OTP_MESSAGE_TRANSFORM:
            offset = dissect_otp_transform_layer(tvb, pinfo, otp_tree, offset);
            break;
        case OTP_MESSAGE_ADVERTISEMENT:
            offset = dissect_otp_advertisement_layer(tvb, pinfo, otp_tree, offset);
            break;
        default:
            /* Unknown message type - skip it */
            expert_add_info(pinfo, otp_tree, &ei_otp_pdu_vector);
            break;
    }

    if (offset != pdu_end)
        expert_add_info(pinfo, otp_tree, &ei_otp_pdu_len);
    return pdu_end;
}

static bool
dissect_otp_heur(tvbuff_t* tvb, packet_info* pinfo, proto_tree* tree, void* data)
{
    if (tvb_reported_length(tvb) < 12) {
        return false;
    }

    /* Check magic */
    if (tvb_memeql(tvb, 0, OTP_IDENTIFIER, OTP_IDENTIFIER_LEN) != 0) {
        return false;
    }

    /* We know it's an OTP packet now */
    conversation_t* conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, otp_handle);

    dissect_otp(tvb, pinfo, tree, data);

    return true;
}

/******************************************************************************/
/* Register protocol                                                          */
void
proto_register_otp(void) {
    static hf_register_info hf[] = {
        { &hf_otp_identifier,
            { "OTP Packet Identifier", "otp.ident",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_vector,
            { "OTP Message Vector", "otp.vector",
            FT_UINT16, BASE_HEX,
            VALS(otp_message_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_length,
            { "Message Length", "otp.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_footer_options,
            { "Footer Options", "otp.footer.options",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_footer_length,
            { "Footer Length", "otp.footer.length",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_sender_cid,
            { "Sender CID", "otp.cid",
            FT_GUID, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_folio,
            { "Folio Number", "otp.folio",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_page,
            { "Page Number", "otp.page.current",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_last_page,
            { "Last Page Number", "otp.page.last",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_options,
            { "Options", "otp.options",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_reserved,
            { "Reserved", "otp.reserved",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_component_name,
            { "Component Name", "otp.name",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_otp_advert,
            { "Advertisement", "otp.advertisement",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_vector,
            { "Vector", "otp.advertisement.vector",
            FT_UINT16, BASE_HEX,
            VALS(otp_advertisement_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_length,
            { "PDU Length", "otp.advertisement.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_reserved,
            { "Reserved", "otp.advertisement.reserved",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_otp_advert_module,
            { "Module Advertisement", "otp.advertisement.module",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_module_vector,
            { "Vector", "otp.advertisement.module.vector",
            FT_UINT16, BASE_HEX,
            VALS(otp_advertisement_module_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_module_length,
            { "PDU Length", "otp.advertisement.module.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_module_reserved,
            { "Reserved", "otp.advertisement.module.reserved",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_module_identifier,
            { "Module Identifier", "otp.advertisement.module.identifier",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_otp_advert_name,
            { "Name Advertisement", "otp.advertisement.name",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_name_vector,
            { "Vector", "otp.advertisement.name.vector",
            FT_UINT16, BASE_HEX,
            VALS(otp_advertisement_name_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_name_length,
            { "PDU Length", "otp.advertisement.name.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_name_options,
            { "Options", "otp.advertisement.name.options",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_name_req_resp,
            { "Request/Response", "otp.advertisement.name.request",
            FT_BOOLEAN, 8,
            TFS(&tfs_response_request), 0x80,
            NULL, HFILL }
        },
        { &hf_otp_advert_name_reserved,
            { "Reserved", "otp.advertisement.name.reserved",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_name_address_point_descriptor,
            { "Address Point Descriptor", "otp.advertisement.name.descriptor",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_otp_advert_system,
            { "System Advertisement", "otp.advertisement.system",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_system_vector,
            { "Vector", "otp.advertisement.system.vector",
            FT_UINT16, BASE_HEX,
            VALS(otp_advertisement_system_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_system_length,
            { "PDU Length", "otp.advertisement.system.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_system_options,
            { "Options", "otp.advertisement.system.options",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_system_req_resp,
            { "Request/Response", "otp.advertisement.system.request",
            FT_BOOLEAN, 8,
            TFS(&tfs_response_request), 0x80,
            NULL, HFILL }
        },
        { &hf_otp_advert_system_reserved,
            { "Reserved", "otp.advertisement.system.reserved",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_advert_system_numbers,
            { "System Numbers", "otp.advertisement.system.system_numbers",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_otp_transform,
            { "Transform", "otp.transform",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_transform_vector,
            { "Vector", "otp.transform.vector",
            FT_UINT16, BASE_HEX,
            VALS(otp_transform_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_transform_length,
            { "PDU Length", "otp.transform.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_transform_system_number,
            { "System Number", "otp.transform.system",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_transform_timestamp,
            { "Timestamp", "otp.transform.timestamp",
            FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_transform_options,
            { "Options", "otp.transform.options",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_transform_pointset,
            { "Full Point Set", "otp.transform.pointset",
            FT_BOOLEAN, 8,
            NULL, 0x80,
            NULL, HFILL }
        },
        { &hf_otp_transform_reserved,
            { "Reserved", "otp.transform.reserved",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_otp_point,
            { "Point", "otp.transform.point",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_vector,
            { "Vector", "otp.transform.point.vector",
            FT_UINT16, BASE_HEX,
            VALS(otp_point_type_names), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_length,
            { "PDU Length", "otp.transform.point.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_priority,
            { "Priority", "otp.transform.point.priority",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_group_number,
            { "Group Number", "otp.transform.point.group",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_number,
            { "Point Number", "otp.transform.point.point",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_timestamp,
            { "Timestamp", "otp.transform.point.timestamp",
            FT_RELATIVE_TIME, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_options,
            { "Options", "otp.transform.point.options",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_reserved,
            { "Reserved", "otp.transform.point.reserved",
            FT_UINT32, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_point_name,
            { "Point Name", "otp.transform.point.name",
            FT_STRINGZPAD, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_otp_module,
            { "Module", "otp.transform.module",
            FT_NONE, BASE_NONE,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_manf_id,
            { "Manufacturer ID", "otp.transform.module.manfid",
            FT_UINT16, BASE_HEX|BASE_EXT_STRING,
            &dmx_esta_manfid_vals_ext, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_length,
            { "PDU Length", "otp.transform.module.length",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_module_number,
            { "Module Number", "otp.transform.module.number",
            FT_UINT16, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_esta_number,
            { "Module Number", "otp.transform.module.number",
            FT_UINT16, BASE_HEX,
            VALS(otp_module_esta_names), 0x0,
            NULL, HFILL }
        },

        { &hf_otp_module_options,
            { "Options", "otp.transform.module.esta.position.options",
            FT_UINT8, BASE_HEX,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_scaling,
            { "Scaling", "otp.transform.module.esta.position.scaling",
            FT_BOOLEAN, 8,
            TFS(&tfs_scaling), 0x80,
            NULL, HFILL }
        },
        { &hf_otp_module_x_um,
            { "X", "otp.transform.module.esta.position.x",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometers), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_y_um,
            { "Y", "otp.transform.module.esta.position.y",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometers), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_z_um,
            { "Z", "otp.transform.module.esta.position.z",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometers), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_x_mm,
            { "X", "otp.transform.module.esta.position.x",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millimeters_space), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_y_mm,
            { "Y", "otp.transform.module.esta.position.y",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millimeters_space), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_z_mm,
            { "Z", "otp.transform.module.esta.position.z",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millimeters_space), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_vx,
            { "Vx", "otp.transform.module.esta.position.vx",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometer_sec), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_vy,
            { "Vy", "otp.transform.module.esta.position.vy",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometer_sec), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_vz,
            { "Vz", "otp.transform.module.esta.position.vz",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometer_sec), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_ax,
            { "Ax", "otp.transform.module.esta.position.ax",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometer_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_ay,
            { "Ay", "otp.transform.module.esta.position.ay",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometer_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_az,
            { "Az", "otp.transform.module.esta.position.az",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_micrometer_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_rx,
            { "Rx", "otp.transform.module.esta.rotation.rx",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_microdegree), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_ry,
            { "Ry", "otp.transform.module.esta.rotation.ry",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_microdegree), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_rz,
            { "Rz", "otp.transform.module.esta.rotation.rz",
            FT_UINT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_microdegree), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_rvx,
            { "Vrx", "otp.transform.module.esta.rotation.vrx",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millidegree_sec), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_rvy,
            { "Vry", "otp.transform.module.esta.rotation.vry",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millidegree_sec), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_rvz,
            { "Vrz", "otp.transform.module.esta.rotation.vrz",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millidegree_sec), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_rax,
            { "Arx", "otp.transform.module.esta.rotation.arx",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millidegree_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_ray,
            { "Ary", "otp.transform.module.esta.rotation.ary",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millidegree_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_raz,
            { "Arz", "otp.transform.module.esta.rotation.arz",
            FT_INT32, BASE_DEC|BASE_UNIT_STRING,
            UNS(&units_millidegree_sec_squared), 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_scale_x,
            { "X Scale", "otp.transform.module.esta.scale.x",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_scale_y,
            { "Y Scale", "otp.transform.module.esta.scale.y",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_scale_z,
            { "Z Scale", "otp.transform.module.esta.scale.z",
            FT_INT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_reference_system,
            { "Reference System", "otp.transform.module.esta.reference.system",
            FT_UINT8, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_reference_group,
            { "Reference Group", "otp.transform.module.esta.reference.group",
            FT_UINT16, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_otp_module_reference_point,
            { "Reference Point", "otp.transform.module.esta.reference.point",
            FT_UINT32, BASE_DEC,
            NULL, 0x0,
            NULL, HFILL }
        },
    };

    /* Setup protocol subtree array */
    static int* ett[] = {
        &ett_otp,

        &ett_otp_advert,
        &ett_otp_advert_module,
        &ett_otp_advert_name,
        &ett_otp_advert_system,

        &ett_otp_transform,
        &ett_otp_point,
        &ett_otp_module,

        &ett_otp_transform_options,
        &ett_otp_advert_name_options,
        &ett_otp_advert_system_options,
        &ett_otp_module_options,

        &ett_otp_advert_module_identifier,
        &ett_otp_advert_name_address_point_descriptor,
        &ett_otp_advert_system_numbers,
    };

    static ei_register_info ei[] = {
        { &ei_otp_pdu_vector,        { "otp.vector.unknown", PI_PROTOCOL, PI_ERROR, "Unknown PDU vector for this location", EXPFILL }},
        { &ei_otp_pdu_len,           { "otp.length.mismatch", PI_PROTOCOL, PI_WARN, "Mismatch between reported PDU length and consumed data", EXPFILL }},
        { &ei_otp_module_number,     { "otp.transform.module.number.unknown", PI_PROTOCOL, PI_ERROR, "Unknown module number", EXPFILL }},
        { &ei_otp_module_manfid,     { "otp.transform.module.manfid.unknown", PI_PROTOCOL, PI_NOTE, "Unrecognised manufacturer and module ID conbination. Note: standard modules should be sent with the ESTA manufacturer code (0x0000)", EXPFILL }},
    };

    proto_otp = proto_register_protocol("Object Transform Protocol", "OTP", "otp");

    proto_register_field_array(proto_otp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_module_t* expert_otp = expert_register_protocol(proto_otp);
    expert_register_field_array(expert_otp, ei, array_length(ei));

    otp_handle = register_dissector_with_description (
        "otp",          /* dissector name           */
        "OTP",          /* dissector description    */
        dissect_otp,    /* dissector function       */
        proto_otp       /* protocol being dissected */
    );
}

/******************************************************************************/
/* Register handoff                                                           */
void
proto_reg_handoff_otp(void)
{
    /* OTP uses port 5568 by default, but this is more commonly used by parts of the ACN suite,
     * so we use a heuristic which also lets us capture traffic on other ports
     */
    dissector_add_for_decode_as_with_preference("udp.port", otp_handle);
    heur_dissector_add("udp", dissect_otp_heur, "OTP over UDP", "otp", proto_otp, HEURISTIC_ENABLE);
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
