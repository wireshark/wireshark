/* packet-lbmpdm.c
 * Routines for LBM PDM Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/exceptions.h>
#include "packet-lbm.h"

/* Magic number for message header to check if data is big-endian or little-endian. */
#define PDM_MSG_HDR_BE_MAGIC_BYTE_1 0xA7
#define PDM_MSG_HDR_BE_MAGIC_BYTE_2 0x1C
#define PDM_MSG_HDR_BE_MAGIC_BYTE_3 0xCA
#define PDM_MSG_HDR_BE_MAGIC_BYTE_4 0xFE
#define PDM_MSG_HDR_LE_MAGIC_BYTE_1 0xFE
#define PDM_MSG_HDR_LE_MAGIC_BYTE_2 0xCA
#define PDM_MSG_HDR_LE_MAGIC_BYTE_3 0x1C
#define PDM_MSG_HDR_LE_MAGIC_BYTE_4 0xA7

void proto_register_lbmpdm(void);

/*------------*/
/* PDM header */
/*------------*/
typedef struct lbmpdm_msg_hdr_stct_t
{
    uint32_t magic;
    uint8_t ver_type;
    uint8_t next_hdr;
    uint8_t def_major_ver;
    uint8_t def_minor_ver;
    uint32_t def_id;
    uint32_t len;
} lbmpdm_msg_hdr_t;
#define O_LBMPDM_MSG_HDR_T_MAGIC OFFSETOF(lbmpdm_msg_hdr_t, magic)
#define L_LBMPDM_MSG_HDR_T_MAGIC SIZEOF(lbmpdm_msg_hdr_t, magic)
#define O_LBMPDM_MSG_HDR_T_VER_TYPE OFFSETOF(lbmpdm_msg_hdr_t, ver_type)
#define L_LBMPDM_MSG_HDR_T_VER_TYPE SIZEOF(lbmpdm_msg_hdr_t, ver_type)
#define O_LBMPDM_MSG_HDR_T_NEXT_HDR OFFSETOF(lbmpdm_msg_hdr_t, next_hdr)
#define L_LBMPDM_MSG_HDR_T_NEXT_HDR SIZEOF(lbmpdm_msg_hdr_t, next_hdr)
#define O_LBMPDM_MSG_HDR_T_DEF_MAJOR_VER OFFSETOF(lbmpdm_msg_hdr_t, def_major_ver)
#define L_LBMPDM_MSG_HDR_T_DEF_MAJOR_VER SIZEOF(lbmpdm_msg_hdr_t, def_major_ver)
#define O_LBMPDM_MSG_HDR_T_DEF_MINOR_VER OFFSETOF(lbmpdm_msg_hdr_t, def_minor_ver)
#define L_LBMPDM_MSG_HDR_T_DEF_MINOR_VER SIZEOF(lbmpdm_msg_hdr_t, def_minor_ver)
#define O_LBMPDM_MSG_HDR_T_DEF_ID OFFSETOF(lbmpdm_msg_hdr_t, def_id)
#define L_LBMPDM_MSG_HDR_T_DEF_ID SIZEOF(lbmpdm_msg_hdr_t, def_id)
#define O_LBMPDM_MSG_HDR_T_LEN OFFSETOF(lbmpdm_msg_hdr_t, len)
#define L_LBMPDM_MSG_HDR_T_LEN SIZEOF(lbmpdm_msg_hdr_t, len)
#define L_LBMPDM_MSG_HDR_T (int) sizeof(lbmpdm_msg_hdr_t)

/*---------------------*/
/* PDM segment header. */
/*---------------------*/
typedef struct lbmpdm_seg_hdr_stct_t
{
    uint8_t next_hdr;
    uint8_t flags;
    uint16_t res;
    uint32_t len;
} lbmpdm_seg_hdr_t;
#define O_LBMPDM_SEG_HDR_T_NEXT_HDR OFFSETOF(lbmpdm_seg_hdr_t, next_hdr)
#define L_LBMPDM_SEG_HDR_T_NEXT_HDR SIZEOF(lbmpdm_seg_hdr_t, next_hdr)
#define O_LBMPDM_SEG_HDR_T_FLAGS OFFSETOF(lbmpdm_seg_hdr_t, flags)
#define L_LBMPDM_SEG_HDR_T_FLAGS SIZEOF(lbmpdm_seg_hdr_t, flags)
#define O_LBMPDM_SEG_HDR_T_RES OFFSETOF(lbmpdm_seg_hdr_t, res)
#define L_LBMPDM_SEG_HDR_T_RES SIZEOF(lbmpdm_seg_hdr_t, res)
#define O_LBMPDM_SEG_HDR_T_LEN OFFSETOF(lbmpdm_seg_hdr_t, len)
#define L_LBMPDM_SEG_HDR_T_LEN SIZEOF(lbmpdm_seg_hdr_t, len)
#define L_LBMPDM_SEG_HDR_T (int) sizeof(lbmpdm_seg_hdr_t)

/*--------------------------------*/
/* PDM definition segment header. */
/*--------------------------------*/
typedef struct lbmpdm_defn_stct_t
{
    int32_t id;
    int32_t num_fields;
    uint8_t field_names_type;
    uint8_t finalized;
    uint8_t msg_vers_major;
    uint8_t msg_vers_minor;
    uint32_t fixed_req_section_len;
    uint32_t field_info_len;
} lbmpdm_defn_t;
#define O_LBMPDM_DEFN_T_ID OFFSETOF(lbmpdm_defn_t, id)
#define L_LBMPDM_DEFN_T_ID SIZEOF(lbmpdm_defn_t, id)
#define O_LBMPDM_DEFN_T_NUM_FIELDS OFFSETOF(lbmpdm_defn_t, num_fields)
#define L_LBMPDM_DEFN_T_NUM_FIELDS SIZEOF(lbmpdm_defn_t, num_fields)
#define O_LBMPDM_DEFN_T_FIELD_NAMES_TYPE OFFSETOF(lbmpdm_defn_t, field_names_type)
#define L_LBMPDM_DEFN_T_FIELD_NAMES_TYPE SIZEOF(lbmpdm_defn_t, field_names_type)
#define O_LBMPDM_DEFN_T_FINALIZED OFFSETOF(lbmpdm_defn_t, finalized)
#define L_LBMPDM_DEFN_T_FINALIZED SIZEOF(lbmpdm_defn_t, finalized)
#define O_LBMPDM_DEFN_T_MSG_VERS_MAJOR OFFSETOF(lbmpdm_defn_t, msg_vers_major)
#define L_LBMPDM_DEFN_T_MSG_VERS_MAJOR SIZEOF(lbmpdm_defn_t, msg_vers_major)
#define O_LBMPDM_DEFN_T_MSG_VERS_MINOR OFFSETOF(lbmpdm_defn_t, msg_vers_minor)
#define L_LBMPDM_DEFN_T_MSG_VERS_MINOR SIZEOF(lbmpdm_defn_t, msg_vers_minor)
#define O_LBMPDM_DEFN_T_FIXED_REQ_SECTION_LEN OFFSETOF(lbmpdm_defn_t, fixed_req_section_len)
#define L_LBMPDM_DEFN_T_FIXED_REQ_SECTION_LEN SIZEOF(lbmpdm_defn_t, fixed_req_section_len)
#define O_LBMPDM_DEFN_T_FIELD_INFO_LEN OFFSETOF(lbmpdm_defn_t, field_info_len)
#define L_LBMPDM_DEFN_T_FIELD_INFO_LEN SIZEOF(lbmpdm_defn_t, field_info_len)
#define L_LBMPDM_DEFN_T (int) sizeof(lbmpdm_defn_t)

/*----------------------------*/
/* PDM definition field info. */
/*----------------------------*/
typedef struct lbmpdm_field_info_stct_t
{
    uint32_t id;
    uint32_t len;
    uint32_t fixed_str_len;
    uint32_t num_arr_elem;
    uint8_t req;
    uint8_t fixed;
    int32_t fld_int_name;
    int32_t str_name_len;
    /* NUL-terminated field name, if str_name_len != 0 */
    /* int16_t fld_type */
} lbmpdm_field_info_t;
#define O_LBMPDM_FIELD_INFO_T_ID OFFSETOF(lbmpdm_field_info_t, id)
#define L_LBMPDM_FIELD_INFO_T_ID SIZEOF(lbmpdm_field_info_t, id)
#define O_LBMPDM_FIELD_INFO_T_LEN OFFSETOF(lbmpdm_field_info_t, len)
#define L_LBMPDM_FIELD_INFO_T_LEN SIZEOF(lbmpdm_field_info_t, len)
#define O_LBMPDM_FIELD_INFO_T_FIXED_STR_LEN OFFSETOF(lbmpdm_field_info_t, fixed_str_len)
#define L_LBMPDM_FIELD_INFO_T_FIXED_STR_LEN SIZEOF(lbmpdm_field_info_t, fixed_str_len)
#define O_LBMPDM_FIELD_INFO_T_NUM_ARR_ELEM OFFSETOF(lbmpdm_field_info_t, num_arr_elem)
#define L_LBMPDM_FIELD_INFO_T_NUM_ARR_ELEM SIZEOF(lbmpdm_field_info_t, num_arr_elem)
#define O_LBMPDM_FIELD_INFO_T_REQ OFFSETOF(lbmpdm_field_info_t, req)
#define L_LBMPDM_FIELD_INFO_T_REQ SIZEOF(lbmpdm_field_info_t, req)
#define O_LBMPDM_FIELD_INFO_T_FIXED OFFSETOF(lbmpdm_field_info_t, fixed)
#define L_LBMPDM_FIELD_INFO_T_FIXED SIZEOF(lbmpdm_field_info_t, fixed)
#define O_LBMPDM_FIELD_INFO_T_FLD_INT_NAME (O_LBMPDM_FIELD_INFO_T_FIXED + L_LBMPDM_FIELD_INFO_T_FIXED)
#define L_LBMPDM_FIELD_INFO_T_FLD_INT_NAME 4
#define O_LBMPDM_FIELD_INFO_T_STR_NAME_LEN (O_LBMPDM_FIELD_INFO_T_FLD_INT_NAME + L_LBMPDM_FIELD_INFO_T_FLD_INT_NAME)
#define L_LBMPDM_FIELD_INFO_T_STR_NAME_LEN 4
#define L_LBMPDM_FIELD_INFO_T (O_LBMPDM_FIELD_INFO_T_STR_NAME_LEN + L_LBMPDM_FIELD_INFO_T_STR_NAME_LEN)
#define L_LBMPDM_FIELD_INFO_T_INT_NAME (int) (L_LBMPDM_FIELD_INFO_T + 2)

/*---------------------------------*/
/* PDM offset table segment entry. */
/*---------------------------------*/
typedef struct
{
    uint32_t id;
    uint32_t offset;
} lbmpdm_offset_entry_t;
#define O_LBMPDM_OFFSET_ENTRY_T_ID OFFSETOF(lbmpdm_offset_entry_t, id)
#define L_LBMPDM_OFFSET_ENTRY_T_ID SIZEOF(lbmpdm_offset_entry_t, id)
#define O_LBMPDM_OFFSET_ENTRY_T_OFFSET OFFSETOF(lbmpdm_offset_entry_t, offset)
#define L_LBMPDM_OFFSET_ENTRY_T_OFFSET SIZEOF(lbmpdm_offset_entry_t, offset)
#define L_LBMPDM_OFFSET_ENTRY_T (int) sizeof(lbmpdm_offset_entry_t)

/*-----------------------------------*/
/* Header types (value of next_hdr). */
/*-----------------------------------*/
#define PDM_HDR_TYPE_DATA 0
#define PDM_HDR_TYPE_OFSTTBLE 1
#define PDM_HDR_TYPE_DEFN 2
#define PDM_HDR_TYPE_EOM 0xFF


/* PDM protocol version number.
 */
#define PDM_VERS   1

/*------------------*/
/* PDM field types. */
/*------------------*/
#define PDM_TYPE_BOOLEAN 0
#define PDM_TYPE_INT8 1
#define PDM_TYPE_UINT8 2
#define PDM_TYPE_INT16 3
#define PDM_TYPE_UINT16 4
#define PDM_TYPE_INT32 5
#define PDM_TYPE_UINT32 6
#define PDM_TYPE_INT64 7
#define PDM_TYPE_UINT64 8
#define PDM_TYPE_FLOAT 9
#define PDM_TYPE_DOUBLE 10
#define PDM_TYPE_DECIMAL 11
#define PDM_TYPE_TIMESTAMP 12
#define PDM_TYPE_FIX_STRING 13
#define PDM_TYPE_STRING 14
#define PDM_TYPE_FIX_UNICODE 15
#define PDM_TYPE_UNICODE 16
#define PDM_TYPE_BLOB 17
#define PDM_TYPE_MESSAGE 18
#define PDM_TYPE_BOOLEAN_ARR 19
#define PDM_TYPE_INT8_ARR 20
#define PDM_TYPE_UINT8_ARR 21
#define PDM_TYPE_INT16_ARR 22
#define PDM_TYPE_UINT16_ARR 23
#define PDM_TYPE_INT32_ARR 24
#define PDM_TYPE_UINT32_ARR 25
#define PDM_TYPE_INT64_ARR 26
#define PDM_TYPE_UINT64_ARR 27
#define PDM_TYPE_FLOAT_ARR 28
#define PDM_TYPE_DOUBLE_ARR 29
#define PDM_TYPE_DECIMAL_ARR 30
#define PDM_TYPE_TIMESTAMP_ARR 31
#define PDM_TYPE_FIX_STRING_ARR 32
#define PDM_TYPE_STRING_ARR 33
#define PDM_TYPE_FIX_UNICODE_ARR 34
#define PDM_TYPE_UNICODE_ARR 35
#define PDM_TYPE_BLOB_ARR 36
#define PDM_TYPE_MESSAGE_ARR 37

/* Macros for protocol version number and pdm message type.
 */
#define PDM_HDR_VER(x) (x >> 4)
#define PDM_HDR_TYPE(x) (x & 0xF)
#define PDM_HDR_VER_TYPE(v,t) ((v << 4)|(t & 0xF))
#define PDM_HDR_VER_TYPE_VER_MASK 0xf0
#define PDM_HDR_VER_TYPE_TYPE_MASK 0x0f

#define PDM_IGNORE_FLAG 0x80

#define PDM_DEFN_STR_FIELD_NAMES 0
#define PDM_DEFN_INT_FIELD_NAMES 1

#define PDM_DEFN_OPTIONAL_FIELD 0
#define PDM_DEFN_REQUIRED_FIELD 1

#define PDM_DEFN_VARIABLE_LENGTH_FIELD 0
#define PDM_DEFN_FIXED_LENGTH_FIELD 1

typedef struct
{
    uint32_t num_flds;
    int32_t * min_set_offset;
    int32_t * offset_list;
} lbmpdm_offset_table_t;

struct lbmpdm_definition_field_t_stct;
typedef struct lbmpdm_definition_field_t_stct lbmpdm_definition_field_t;

struct lbmpdm_definition_t_stct;
typedef struct lbmpdm_definition_t_stct lbmpdm_definition_t;

struct lbmpdm_definition_field_t_stct
{
    uint32_t id;
    uint32_t len;
    uint32_t fixed_string_len;
    uint32_t num_array_elem;
    uint8_t required;
    uint8_t fixed;
    uint16_t field_type;
    uint16_t base_type;
    int32_t field_int_name;
    uint32_t field_string_name_len;
    char * field_string_name;
    int fixed_required_offset;
    lbmpdm_definition_field_t * next_fixed_required;
    lbmpdm_definition_t * definition;
};

struct lbmpdm_definition_t_stct
{
    uint64_t channel;
    uint32_t id;
    uint8_t vers_major;
    uint8_t vers_minor;
    int32_t num_fields;
    uint8_t field_names_type;
    uint8_t finalized;
    uint32_t fixed_req_section_len;
    uint32_t fixed_required_count;
    lbmpdm_definition_field_t * first_fixed_required;
    wmem_tree_t * field_list;
};

typedef struct
{
    uint64_t channel;
    uint32_t msg_def_id;
    uint8_t ver_major;
    uint8_t ver_minor;
    lbmpdm_offset_table_t * offset_table;
} lbmpdm_msg_definition_id_t;

#define LBMPDM_DEFINITION_KEY_ELEMENT_COUNT 5
#define LBMPDM_DEFINITION_KEY_ELEMENT_CHANNEL_HIGH 0
#define LBMPDM_DEFINITION_KEY_ELEMENT_CHANNEL_LOW 1
#define LBMPDM_DEFINITION_KEY_ELEMENT_ID 2
#define LBMPDM_DEFINITION_KEY_ELEMENT_VERS_MAJOR 3
#define LBMPDM_DEFINITION_KEY_ELEMENT_VERS_MINOR 4

static wmem_tree_t * lbmpdm_definition_table;

/*----------------------------------------------------------------------------*/
/* Handles of all types.                                                      */
/*----------------------------------------------------------------------------*/

/* Protocol handle */
static int proto_lbmpdm;

/* Protocol fields */
static int hf_lbmpdm_magic;
static int hf_lbmpdm_encoding;
static int hf_lbmpdm_ver;
static int hf_lbmpdm_type;
static int hf_lbmpdm_next_hdr;
static int hf_lbmpdm_def_major_ver;
static int hf_lbmpdm_def_minor_ver;
static int hf_lbmpdm_def_id;
static int hf_lbmpdm_len;
static int hf_lbmpdm_segments;
static int hf_lbmpdm_segment;
static int hf_lbmpdm_segment_next_hdr;
static int hf_lbmpdm_segment_flags;
static int hf_lbmpdm_segment_res;
static int hf_lbmpdm_segment_len;
static int hf_lbmpdm_segment_def_id;
static int hf_lbmpdm_segment_def_num_fields;
static int hf_lbmpdm_segment_def_field_names_type;
static int hf_lbmpdm_segment_def_finalized;
static int hf_lbmpdm_segment_def_msg_vers_major;
static int hf_lbmpdm_segment_def_msg_vers_minor;
static int hf_lbmpdm_segment_def_fixed_req_section_len;
static int hf_lbmpdm_segment_def_field_info_len;
static int hf_lbmpdm_segment_def_field;
static int hf_lbmpdm_segment_def_field_def_len;
static int hf_lbmpdm_segment_def_field_id;
static int hf_lbmpdm_segment_def_field_len;
static int hf_lbmpdm_segment_def_field_fixed_str_len;
static int hf_lbmpdm_segment_def_field_num_arr_elem;
static int hf_lbmpdm_segment_def_field_req;
static int hf_lbmpdm_segment_def_field_fixed;
static int hf_lbmpdm_segment_def_field_fld_int_name;
static int hf_lbmpdm_segment_def_field_str_name_len;
static int hf_lbmpdm_segment_def_field_str_name;
static int hf_lbmpdm_segment_def_field_fld_type;
static int hf_lbmpdm_offset_entry;
static int hf_lbmpdm_offset_entry_id;
static int hf_lbmpdm_offset_entry_offset;
static int hf_lbmpdm_segment_data;
static int hf_lbmpdm_field;
static int hf_lbmpdm_field_id;
static int hf_lbmpdm_field_string_name;
static int hf_lbmpdm_field_int_name;
static int hf_lbmpdm_field_type;
static int hf_lbmpdm_field_total_length;
static int hf_lbmpdm_field_length;
static int hf_lbmpdm_field_value_boolean;
static int hf_lbmpdm_field_value_int8;
static int hf_lbmpdm_field_value_uint8;
static int hf_lbmpdm_field_value_int16;
static int hf_lbmpdm_field_value_uint16;
static int hf_lbmpdm_field_value_int32;
static int hf_lbmpdm_field_value_uint32;
static int hf_lbmpdm_field_value_int64;
static int hf_lbmpdm_field_value_uint64;
static int hf_lbmpdm_field_value_float;
static int hf_lbmpdm_field_value_double;
static int hf_lbmpdm_field_value_decimal;
static int hf_lbmpdm_field_value_timestamp;
static int hf_lbmpdm_field_value_fixed_string;
static int hf_lbmpdm_field_value_string;
static int hf_lbmpdm_field_value_fixed_unicode;
static int hf_lbmpdm_field_value_unicode;
static int hf_lbmpdm_field_value_blob;
static int hf_lbmpdm_field_value_message;

/* Protocol trees */
static int ett_lbmpdm;
static int ett_lbmpdm_segments;
static int ett_lbmpdm_segment;
static int ett_lbmpdm_offset_entry;
static int ett_lbmpdm_segment_def_field;
static int ett_lbmpdm_field;

/*----------------------------------------------------------------------------*/
/* Value translation tables.                                                  */
/*----------------------------------------------------------------------------*/

/* Value tables */
static const value_string lbmpdm_field_type[] =
{
    { PDM_TYPE_BOOLEAN, "Boolean" },
    { PDM_TYPE_INT8, "8-bit integer" },
    { PDM_TYPE_UINT8, "8-bit unsigned integer" },
    { PDM_TYPE_INT16, "16-bit integer" },
    { PDM_TYPE_UINT16, "16-bit unsigned integer" },
    { PDM_TYPE_INT32, "32-bit integer" },
    { PDM_TYPE_UINT32, "32-bit unsigned integer" },
    { PDM_TYPE_INT64, "64-bit integer" },
    { PDM_TYPE_UINT64, "64-bit unsigned integer" },
    { PDM_TYPE_FLOAT, "Float" },
    { PDM_TYPE_DOUBLE, "Double" },
    { PDM_TYPE_DECIMAL, "Decimal" },
    { PDM_TYPE_TIMESTAMP, "Timestamp" },
    { PDM_TYPE_FIX_STRING, "Fixed-length string" },
    { PDM_TYPE_STRING, "String" },
    { PDM_TYPE_FIX_UNICODE, "Fixed-length unicode string" },
    { PDM_TYPE_UNICODE, "Unicode string" },
    { PDM_TYPE_BLOB, "Binary Large OBject" },
    { PDM_TYPE_MESSAGE, "Message" },
    { PDM_TYPE_BOOLEAN_ARR, "Array of booleans" },
    { PDM_TYPE_INT8_ARR, "Array of 8-bit integers" },
    { PDM_TYPE_UINT8_ARR, "Array of 8-bit unsigned integers" },
    { PDM_TYPE_INT16_ARR, "Array of 16-bit integers" },
    { PDM_TYPE_UINT16_ARR, "Array of 16-bit unsigned integers" },
    { PDM_TYPE_INT32_ARR, "Array of 32-bit integers" },
    { PDM_TYPE_UINT32_ARR, "Array of 32-bit unsigned integers" },
    { PDM_TYPE_INT64_ARR, "Array of 64-bit integers" },
    { PDM_TYPE_UINT64_ARR, "Array of 64-bit unsigned integers" },
    { PDM_TYPE_FLOAT_ARR, "Array of floats" },
    { PDM_TYPE_DOUBLE_ARR, "Array of doubles" },
    { PDM_TYPE_DECIMAL_ARR, "Array of decimals" },
    { PDM_TYPE_TIMESTAMP_ARR, "Array of timestamps" },
    { PDM_TYPE_FIX_STRING_ARR, "Array of fixed-length strings" },
    { PDM_TYPE_STRING_ARR, "Array of strings" },
    { PDM_TYPE_FIX_UNICODE_ARR, "Array of fixed-length unicode strings" },
    { PDM_TYPE_UNICODE_ARR, "Array of unicode strings" },
    { PDM_TYPE_BLOB_ARR, "Array of Binary Large OBjects" },
    { PDM_TYPE_MESSAGE_ARR, "Array of messages" },
    { 0x0, NULL }
};

static const value_string lbmpdm_next_header[] =
{
    { PDM_HDR_TYPE_DATA, "Data" },
    { PDM_HDR_TYPE_OFSTTBLE, "Offset table" },
    { PDM_HDR_TYPE_DEFN, "Definition" },
    { PDM_HDR_TYPE_EOM, "End of message" },
    { 0x0, NULL }
};

static const value_string lbmpdm_field_name_type[] =
{
    { PDM_DEFN_STR_FIELD_NAMES, "String" },
    { PDM_DEFN_INT_FIELD_NAMES, "Integer" },
    { 0x0, NULL }
};

static const value_string lbmpdm_field_required[] =
{
    { PDM_DEFN_OPTIONAL_FIELD, "Field is optional" },
    { PDM_DEFN_REQUIRED_FIELD, "Field is required" },
    { 0x0, NULL }
};

static const value_string lbmpdm_field_fixed_length[] =
{
    { PDM_DEFN_VARIABLE_LENGTH_FIELD, "Field is variable-length" },
    { PDM_DEFN_FIXED_LENGTH_FIELD, "Field is fixed-length" },
    { 0x0, NULL }
};

static int lbmpdm_get_segment_length(tvbuff_t * tvb, int offset, int encoding, int * data_length)
{
    uint32_t datalen = 0;
    int seglen = 0;

    datalen = tvb_get_uint32(tvb, offset + O_LBMPDM_SEG_HDR_T_LEN, encoding);
    seglen = ((int)datalen) + L_LBMPDM_SEG_HDR_T;
    *data_length = (int) datalen;
    return (seglen);
}

static void lbmpdm_definition_build_key(uint32_t * key_value, wmem_tree_key_t * key, uint64_t channel, uint32_t id, uint8_t version_major, uint8_t version_minor)
{
    key_value[LBMPDM_DEFINITION_KEY_ELEMENT_CHANNEL_HIGH] = (uint32_t) ((channel >> 32) & 0xffffffff);
    key_value[LBMPDM_DEFINITION_KEY_ELEMENT_CHANNEL_LOW] = (uint32_t) (channel & 0xffffffff);
    key_value[LBMPDM_DEFINITION_KEY_ELEMENT_ID] = id;
    key_value[LBMPDM_DEFINITION_KEY_ELEMENT_VERS_MAJOR] = version_major;
    key_value[LBMPDM_DEFINITION_KEY_ELEMENT_VERS_MINOR] = version_minor;
    key[0].length = LBMPDM_DEFINITION_KEY_ELEMENT_COUNT;
    key[0].key = key_value;
    key[1].length = 0;
    key[1].key = NULL;
}

static lbmpdm_definition_t * lbmpdm_definition_find(uint64_t channel, uint32_t ID, uint8_t version_major, uint8_t version_minor)
{
    lbmpdm_definition_t * entry = NULL;
    uint32_t keyval[LBMPDM_DEFINITION_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    lbmpdm_definition_build_key(keyval, tkey, channel, ID, version_major, version_minor);
    entry = (lbmpdm_definition_t *) wmem_tree_lookup32_array(lbmpdm_definition_table, tkey);
    return (entry);
}

static lbmpdm_definition_t * lbmpdm_definition_add(uint64_t channel, uint32_t id, uint8_t version_major, uint8_t version_minor)
{
    lbmpdm_definition_t * entry = NULL;
    uint32_t keyval[LBMPDM_DEFINITION_KEY_ELEMENT_COUNT];
    wmem_tree_key_t tkey[2];

    entry = lbmpdm_definition_find(channel, id, version_major, version_minor);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbmpdm_definition_t);
    entry->channel = channel;
    entry->id = id;
    entry->vers_major = version_major;
    entry->vers_minor = version_minor;
    entry->field_list = wmem_tree_new(wmem_file_scope());
    lbmpdm_definition_build_key(keyval, tkey, channel, id, version_major, version_minor);
    wmem_tree_insert32_array(lbmpdm_definition_table, tkey, (void *) entry);
    return (entry);
}

static lbmpdm_definition_field_t * lbmpdm_definition_field_find(lbmpdm_definition_t * definition, uint32_t id)
{
    lbmpdm_definition_field_t * entry = NULL;

    entry = (lbmpdm_definition_field_t *) wmem_tree_lookup32(definition->field_list, id);
    return (entry);
}

static lbmpdm_definition_field_t * lbmpdm_definition_field_add(lbmpdm_definition_t * definition, uint32_t id)
{
    lbmpdm_definition_field_t * entry = NULL;

    entry = lbmpdm_definition_field_find(definition, id);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new0(wmem_file_scope(), lbmpdm_definition_field_t);
    entry->id = id;
    entry->definition = definition;
    wmem_tree_insert32(definition->field_list, id, (void *) entry);
    return (entry);
}

/*----------------------------------------------------------------------------*/
/* Dissection functions.                                                      */
/*----------------------------------------------------------------------------*/
static void dissect_field_value(tvbuff_t * tvb, int offset, proto_tree * tree, uint16_t field_type, int field_length, int encoding)
{
    switch (field_type)
    {
        case PDM_TYPE_BOOLEAN:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_boolean, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_INT8:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_int8, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_UINT8:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_uint8, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_INT16:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_int16, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_UINT16:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_uint16, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_INT32:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_int32, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_UINT32:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_uint32, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_INT64:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_int64, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_UINT64:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_uint64, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_FLOAT:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_float, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_DOUBLE:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_double, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_DECIMAL:
            {
                int64_t mantissa;
                int8_t exponent;
                int64_t whole = 0;
                uint64_t fraction = 0;
                int8_t shift_count;

                exponent = tvb_get_int8(tvb, offset);
                mantissa = tvb_get_int64(tvb, offset + 1, encoding);
                if (exponent >= 0)
                {
                    whole = mantissa;
                    shift_count = exponent;
                    while (shift_count > 0)
                    {
                        whole *= 10;
                        shift_count--;
                    }
                    proto_tree_add_none_format(tree, hf_lbmpdm_field_value_decimal, tvb, offset, field_length,
                        "DECIMAL Value: %" PRId64 " (%" PRId64 "e%d)", whole, mantissa, exponent);
                }
                else
                {
                    uint64_t divisor = 1;
                    int decimal_digits = -exponent;
                    shift_count = decimal_digits;
                    while (shift_count > 0)
                    {
                        divisor *= 10;
                        shift_count--;
                    }
                    if (mantissa < 0)
                    {
                        whole = -mantissa;
                    }
                    else
                    {
                        whole = mantissa;
                    }
                    fraction = whole % divisor;
                    whole /= divisor;
                    if (mantissa < 0)
                    {
                        whole *= -1;
                    }
                    proto_tree_add_none_format(tree, hf_lbmpdm_field_value_decimal, tvb, offset, field_length,
                        "DECIMAL Value: %" PRId64 ".%0*" PRIu64 " (%" PRId64 "e%d)",
                        whole, decimal_digits, fraction, mantissa, exponent);
                }
            }
            break;
        case PDM_TYPE_TIMESTAMP:
            {
                nstime_t timestamp;

                timestamp.secs = (time_t)tvb_get_uint32(tvb, offset, encoding);
                timestamp.nsecs = (int)(tvb_get_uint32(tvb, offset + 4, encoding) * 1000);
                proto_tree_add_time(tree, hf_lbmpdm_field_value_timestamp, tvb, offset, field_length, &timestamp);
            }
            break;
        case PDM_TYPE_FIX_STRING:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_fixed_string, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_STRING:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_string, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_FIX_UNICODE:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_fixed_unicode, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_UNICODE:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_unicode, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_BLOB:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_blob, tvb, offset, field_length, encoding);
            break;
        case PDM_TYPE_MESSAGE:
            proto_tree_add_item(tree, hf_lbmpdm_field_value_message, tvb, offset, field_length, encoding);
            break;
        default:
            break;
    }
}

static int dissect_field(tvbuff_t * tvb, int offset, proto_tree * tree, lbmpdm_definition_field_t * field, bool string_field_names, int encoding)
{
    proto_item * field_item = NULL;
    proto_tree * field_tree = NULL;
    proto_item * ti = NULL;
    int ofs = offset;
    uint32_t element_count = 0;
    uint32_t idx;
    int len_dissected = 0;

    field_item = proto_tree_add_item(tree, hf_lbmpdm_field, tvb, offset, field->len, ENC_NA);
    field_tree = proto_item_add_subtree(field_item, ett_lbmpdm_field);
    ti = proto_tree_add_uint(field_tree, hf_lbmpdm_field_id, tvb, 0, 0, field->id);
    proto_item_set_generated(ti);
    if (string_field_names)
    {
        ti = proto_tree_add_string(field_tree, hf_lbmpdm_field_string_name, tvb, 0, 0, field->field_string_name);
    }
    else
    {
        ti = proto_tree_add_uint(field_tree, hf_lbmpdm_field_int_name, tvb, 0, 0, field->field_int_name);
    }
    proto_item_set_generated(ti);
    ti = proto_tree_add_uint(field_tree, hf_lbmpdm_field_type, tvb, 0, 0, field->field_type);
    proto_item_set_generated(ti);
    if (field->num_array_elem == 0)
    {
        element_count = 1;
    }
    else
    {
        element_count = field->num_array_elem;
        if (field->fixed == PDM_DEFN_VARIABLE_LENGTH_FIELD)
        {
            proto_tree_add_item(field_tree, hf_lbmpdm_field_total_length, tvb, ofs, 4, encoding);
            len_dissected += 4;
            ofs += 4;
        }
    }
    for (idx = 0; idx < element_count; ++idx)
    {
        /* field_len is length of the entire entry, including any length prefix. */
        uint32_t field_len = field->len / element_count;
        /* value_len is the length of the data only. */
        uint32_t value_len = field_len;
        /* value_offset is the offset of the actual value. */
        int value_offset = ofs;

        if (field->fixed == PDM_DEFN_VARIABLE_LENGTH_FIELD)
        {
            proto_tree_add_item(field_tree, hf_lbmpdm_field_length, tvb, ofs, 4, encoding);
            value_len = tvb_get_uint32(tvb, ofs, encoding);
            field_len = value_len + 4;
            value_offset += 4;
        }
        else if (field->fixed_string_len > 0)
        {
            value_len = field->fixed_string_len;
        }
        dissect_field_value(tvb, value_offset, field_tree, field->base_type, value_len, encoding);
        ofs += (int)field_len;
        len_dissected += (int)field_len;
    }
    return (len_dissected);
}

static int dissect_segment_data(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmpdm_msg_definition_id_t * id, int encoding)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int datalen = 0;
    int seglen = 0;
    lbmpdm_definition_t * def = NULL;

    seglen = lbmpdm_get_segment_length(tvb, offset, encoding, &datalen);
    subtree_item = proto_tree_add_none_format(tree, hf_lbmpdm_segment, tvb, offset, seglen, "Data Segment");
    subtree = proto_item_add_subtree(subtree_item, ett_lbmpdm_segment);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_next_hdr, tvb, offset + O_LBMPDM_SEG_HDR_T_NEXT_HDR, L_LBMPDM_SEG_HDR_T_NEXT_HDR, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_flags, tvb, offset + O_LBMPDM_SEG_HDR_T_FLAGS, L_LBMPDM_SEG_HDR_T_FLAGS, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_res, tvb, offset + O_LBMPDM_SEG_HDR_T_RES, L_LBMPDM_SEG_HDR_T_RES, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_len, tvb, offset + O_LBMPDM_SEG_HDR_T_LEN, L_LBMPDM_SEG_HDR_T_LEN, encoding);
    if ((id != NULL) && (id->offset_table != NULL))
    {
        def = lbmpdm_definition_find(id->channel, id->msg_def_id, id->ver_major, id->ver_minor);
    }
    if (def == NULL)
    {
        proto_tree_add_item(subtree, hf_lbmpdm_segment_data, tvb, offset + L_LBMPDM_SEG_HDR_T, datalen, ENC_NA);
    }
    else
    {
        int fld_offset = offset + L_LBMPDM_SEG_HDR_T;
        lbmpdm_definition_field_t * field = NULL;
        bool string_field_names = false;
        uint32_t idx;

        if (def->field_names_type == PDM_DEFN_STR_FIELD_NAMES)
        {
            string_field_names = true;
        }
        else
        {
            string_field_names = false;
        }

        /* Handle any fixed required fields first. */
        for (field = def->first_fixed_required; field != NULL; field = field->next_fixed_required)
        {
            fld_offset += dissect_field(tvb, fld_offset, subtree, field, string_field_names, encoding);
        }
        /* Step through the offset table. */
        for (idx = 0; idx < id->offset_table->num_flds; ++idx)
        {
            int32_t ofs = id->offset_table->offset_list[idx];
            if (ofs != -1)
            {
                field = lbmpdm_definition_field_find(def, idx);
                if (field != NULL)
                {
                    (void)dissect_field(tvb, offset + L_LBMPDM_SEG_HDR_T + ofs, subtree, field, string_field_names, encoding);
                }
            }
        }
    }
    return (seglen);
}

static int dissect_segment_ofstable(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbmpdm_offset_table_t * * offset_table, int encoding)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int datalen = 0;
    int seglen = 0;
    int ofs = 0;
    int field_count = 0;
    int idx;
    int32_t * id_list = NULL;
    int32_t * ofs_list = NULL;
    int32_t max_index = -1;
    int32_t min_offset = INT32_MAX;
    lbmpdm_offset_table_t * ofs_table = NULL;

    seglen = lbmpdm_get_segment_length(tvb, offset, encoding, &datalen);
    subtree_item = proto_tree_add_none_format(tree, hf_lbmpdm_segment, tvb, offset, seglen, "Offset Table Segment");
    subtree = proto_item_add_subtree(subtree_item, ett_lbmpdm_segment);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_next_hdr, tvb, offset + O_LBMPDM_SEG_HDR_T_NEXT_HDR, L_LBMPDM_SEG_HDR_T_NEXT_HDR, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_flags, tvb, offset + O_LBMPDM_SEG_HDR_T_FLAGS, L_LBMPDM_SEG_HDR_T_FLAGS, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_res, tvb, offset + O_LBMPDM_SEG_HDR_T_RES, L_LBMPDM_SEG_HDR_T_RES, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_len, tvb, offset + O_LBMPDM_SEG_HDR_T_LEN, L_LBMPDM_SEG_HDR_T_LEN, encoding);
    field_count = datalen / L_LBMPDM_OFFSET_ENTRY_T;
    id_list = wmem_alloc_array(pinfo->pool, int32_t, field_count);
    ofs_list = wmem_alloc_array(pinfo->pool, int32_t, field_count);
    for (idx = 0; idx < field_count; ++idx)
    {
        id_list[idx] = -1;
        ofs_list[idx] = -1;
    }
    ofs = offset + L_LBMPDM_SEG_HDR_T;
    for (idx = 0; idx < field_count; idx++, ofs += L_LBMPDM_OFFSET_ENTRY_T)
    {
        proto_item * offset_item = NULL;
        proto_tree * offset_tree = NULL;

        offset_item = proto_tree_add_item(subtree, hf_lbmpdm_offset_entry, tvb, ofs, L_LBMPDM_OFFSET_ENTRY_T, ENC_NA);
        offset_tree = proto_item_add_subtree(offset_item, ett_lbmpdm_offset_entry);
        proto_tree_add_item(offset_tree, hf_lbmpdm_offset_entry_id, tvb, ofs + O_LBMPDM_OFFSET_ENTRY_T_ID, L_LBMPDM_OFFSET_ENTRY_T_ID, encoding);
        id_list[idx] = (int32_t)tvb_get_uint32(tvb, ofs + O_LBMPDM_OFFSET_ENTRY_T_ID, encoding);
        proto_tree_add_item(offset_tree, hf_lbmpdm_offset_entry_offset, tvb, ofs + O_LBMPDM_OFFSET_ENTRY_T_OFFSET, L_LBMPDM_OFFSET_ENTRY_T_OFFSET, encoding);
        ofs_list[idx] = (int32_t)tvb_get_uint32(tvb, ofs + O_LBMPDM_OFFSET_ENTRY_T_OFFSET, encoding);
        if (id_list[idx] < 0 || ofs_list[idx] < 0) {
            THROW(ReportedBoundsError);
        }
        if (id_list[idx] > max_index)
        {
            max_index = id_list[idx];
        }
        if (ofs_list[idx] < min_offset)
        {
            min_offset = ofs_list[idx];
        }
    }
    ofs_table = wmem_new(pinfo->pool, lbmpdm_offset_table_t);
    ofs_table->num_flds = max_index + 1;
    ofs_table->min_set_offset = NULL;
    ofs_table->offset_list = wmem_alloc_array(pinfo->pool, int32_t, ofs_table->num_flds);
    for (idx = 0; idx < (int)ofs_table->num_flds; ++idx)
    {
        ofs_table->offset_list[idx] = -1;
    }
    for (idx = 0; idx < field_count; ++idx)
    {
        ofs_table->offset_list[id_list[idx]] = ofs_list[idx];
        if (ofs_list[idx] == min_offset)
        {
            ofs_table->min_set_offset = &(ofs_table->offset_list[id_list[idx]]);
        }
    }
    if (offset_table != NULL)
    {
        *offset_table = ofs_table;
    }
    return (seglen);
}

static int dissect_segment_defn(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, uint64_t channel, int encoding)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int seglen = 0;
    int ofs = 0;
    bool string_field_name = false;
    int remaining_datalen = 0;
    uint32_t num_fields = 0;
    lbmpdm_definition_t * def = NULL;
    bool add_definition = false;
    uint32_t def_id = 0;
    uint8_t vers_major = 0;
    uint8_t vers_minor = 0;
    lbmpdm_definition_field_t * last_fixed_required_field = NULL;

    seglen = lbmpdm_get_segment_length(tvb, offset, encoding, &remaining_datalen);
    if (pinfo->fd->visited == 0)
    {
        add_definition = true;
    }
    subtree_item = proto_tree_add_none_format(tree, hf_lbmpdm_segment, tvb, offset, seglen, "Definition Segment");
    subtree = proto_item_add_subtree(subtree_item, ett_lbmpdm_segment);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_next_hdr, tvb, offset + O_LBMPDM_SEG_HDR_T_NEXT_HDR, L_LBMPDM_SEG_HDR_T_NEXT_HDR, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_flags, tvb, offset + O_LBMPDM_SEG_HDR_T_FLAGS, L_LBMPDM_SEG_HDR_T_FLAGS, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_res, tvb, offset + O_LBMPDM_SEG_HDR_T_RES, L_LBMPDM_SEG_HDR_T_RES, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_len, tvb, offset + O_LBMPDM_SEG_HDR_T_LEN, L_LBMPDM_SEG_HDR_T_LEN, encoding);
    ofs = offset + L_LBMPDM_SEG_HDR_T;
    proto_tree_add_item(subtree, hf_lbmpdm_segment_def_id, tvb, ofs + O_LBMPDM_DEFN_T_ID, L_LBMPDM_DEFN_T_ID, encoding);
    def_id = tvb_get_uint32(tvb, ofs + O_LBMPDM_DEFN_T_ID, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_def_num_fields, tvb, ofs + O_LBMPDM_DEFN_T_NUM_FIELDS, L_LBMPDM_DEFN_T_NUM_FIELDS, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_def_field_names_type, tvb, ofs + O_LBMPDM_DEFN_T_FIELD_NAMES_TYPE, L_LBMPDM_DEFN_T_FIELD_NAMES_TYPE, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_def_finalized, tvb, ofs + O_LBMPDM_DEFN_T_FINALIZED, L_LBMPDM_DEFN_T_FINALIZED, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_def_msg_vers_major, tvb, ofs + O_LBMPDM_DEFN_T_MSG_VERS_MAJOR, L_LBMPDM_DEFN_T_MSG_VERS_MAJOR, encoding);
    vers_major = tvb_get_uint8(tvb, ofs + O_LBMPDM_DEFN_T_MSG_VERS_MAJOR);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_def_msg_vers_minor, tvb, ofs + O_LBMPDM_DEFN_T_MSG_VERS_MINOR, L_LBMPDM_DEFN_T_MSG_VERS_MINOR, encoding);
    vers_minor = tvb_get_uint8(tvb, ofs + O_LBMPDM_DEFN_T_MSG_VERS_MINOR);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_def_fixed_req_section_len, tvb, ofs + O_LBMPDM_DEFN_T_FIXED_REQ_SECTION_LEN, L_LBMPDM_DEFN_T_FIXED_REQ_SECTION_LEN, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_def_field_info_len, tvb, ofs + O_LBMPDM_DEFN_T_FIELD_INFO_LEN, L_LBMPDM_DEFN_T_FIELD_INFO_LEN, encoding);
    if (tvb_get_uint8(tvb, ofs + O_LBMPDM_DEFN_T_FIELD_NAMES_TYPE) == PDM_DEFN_STR_FIELD_NAMES)
    {
        string_field_name = true;
    }
    num_fields = tvb_get_uint32(tvb, ofs + O_LBMPDM_DEFN_T_NUM_FIELDS, encoding);
    if (add_definition)
    {
        def = lbmpdm_definition_find(channel, def_id, vers_major, vers_minor);
        if (def == NULL)
        {
            def = lbmpdm_definition_add(channel, def_id, vers_major, vers_minor);
            def->num_fields = num_fields;
            def->field_names_type = tvb_get_uint8(tvb, ofs + O_LBMPDM_DEFN_T_FIELD_NAMES_TYPE);
            def->fixed_req_section_len = tvb_get_uint32(tvb, ofs + O_LBMPDM_DEFN_T_FIXED_REQ_SECTION_LEN, encoding);
            def->first_fixed_required = NULL;
            def->fixed_required_count = 0;
        }
    }
    ofs += L_LBMPDM_DEFN_T;
    remaining_datalen = seglen - L_LBMPDM_SEG_HDR_T - L_LBMPDM_DEFN_T;
    while ((remaining_datalen > 0) && (num_fields > 0))
    {
        proto_item * field_item = NULL;
        proto_tree * field_tree = NULL;
        uint32_t def_len = L_LBMPDM_FIELD_INFO_T_INT_NAME;
        int def_ofs = 0;
        int type_ofs = L_LBMPDM_FIELD_INFO_T;
        uint32_t string_name_len = 0;
        int string_name_ofs = -1;

        if (string_field_name)
        {
            def_len = tvb_get_uint32(tvb, ofs, encoding) + 4;
        }
        field_item = proto_tree_add_item(subtree, hf_lbmpdm_segment_def_field, tvb, ofs, def_len, ENC_NA);
        field_tree = proto_item_add_subtree(field_item, ett_lbmpdm_segment_def_field);
        if (string_field_name)
        {
            proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_def_len, tvb, ofs, 4, encoding);
            def_ofs = 4;
            type_ofs += def_ofs;
        }
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_id, tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_ID, L_LBMPDM_FIELD_INFO_T_ID, encoding);
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_len, tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_LEN, L_LBMPDM_FIELD_INFO_T_LEN, encoding);
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_fixed_str_len, tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_FIXED_STR_LEN, L_LBMPDM_FIELD_INFO_T_FIXED_STR_LEN, encoding);
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_num_arr_elem, tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_NUM_ARR_ELEM, L_LBMPDM_FIELD_INFO_T_NUM_ARR_ELEM, encoding);
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_req, tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_REQ, L_LBMPDM_FIELD_INFO_T_REQ, encoding);
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_fixed, tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_FIXED, L_LBMPDM_FIELD_INFO_T_FIXED, encoding);
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_fld_int_name, tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_FLD_INT_NAME, L_LBMPDM_FIELD_INFO_T_FLD_INT_NAME, encoding);
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_str_name_len, tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_STR_NAME_LEN, L_LBMPDM_FIELD_INFO_T_STR_NAME_LEN, encoding);
        if (string_field_name)
        {
            string_name_len = tvb_get_uint32(tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_STR_NAME_LEN, encoding);
            if (string_name_len > 0)
            {
                string_name_ofs = ofs + def_ofs + L_LBMPDM_FIELD_INFO_T;
                proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_str_name, tvb, string_name_ofs, (int)string_name_len, ENC_ASCII);
                type_ofs += string_name_len;
            }
        }
        proto_tree_add_item(field_tree, hf_lbmpdm_segment_def_field_fld_type, tvb, ofs + type_ofs, 2, encoding);
        if (add_definition && (def != NULL))
        {
            lbmpdm_definition_field_t * field = NULL;
            uint32_t field_id;

            field_id = tvb_get_uint32(tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_ID, encoding);
            field = lbmpdm_definition_field_find(def, field_id);
            if (field == NULL)
            {
                field = lbmpdm_definition_field_add(def, field_id);
                if (field != NULL)
                {
                    field->len = tvb_get_uint32(tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_LEN, encoding);
                    field->fixed_string_len = tvb_get_uint32(tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_FIXED_STR_LEN, encoding);
                    field->num_array_elem = tvb_get_uint32(tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_NUM_ARR_ELEM, encoding);
                    field->required = tvb_get_uint8(tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_REQ);
                    field->fixed = tvb_get_uint8(tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_FIXED);
                    field->field_int_name = tvb_get_uint32(tvb, ofs + def_ofs + O_LBMPDM_FIELD_INFO_T_FLD_INT_NAME, encoding);
                    if (string_field_name && (string_name_len > 0))
                    {
                        field->field_string_name_len = string_name_len;
                        field->field_string_name = tvb_get_string_enc(wmem_file_scope(), tvb, string_name_ofs, string_name_len, ENC_ASCII);
                    }
                    else
                    {
                        field->field_string_name_len = 0;
                        field->field_string_name = NULL;
                    }
                    field->field_type = tvb_get_uint16(tvb, ofs + type_ofs, encoding);
                    switch (field->field_type)
                    {
                        case PDM_TYPE_BOOLEAN:
                        case PDM_TYPE_BOOLEAN_ARR:
                            field->base_type = PDM_TYPE_BOOLEAN;
                            break;
                        case PDM_TYPE_INT8:
                        case PDM_TYPE_INT8_ARR:
                            field->base_type = PDM_TYPE_INT8;
                            break;
                        case PDM_TYPE_UINT8:
                        case PDM_TYPE_UINT8_ARR:
                            field->base_type = PDM_TYPE_UINT8;
                            break;
                        case PDM_TYPE_INT16:
                        case PDM_TYPE_INT16_ARR:
                            field->base_type = PDM_TYPE_INT16;
                            break;
                        case PDM_TYPE_UINT16:
                        case PDM_TYPE_UINT16_ARR:
                            field->base_type = PDM_TYPE_UINT16;
                            break;
                        case PDM_TYPE_INT32:
                        case PDM_TYPE_INT32_ARR:
                            field->base_type = PDM_TYPE_INT32;
                            break;
                        case PDM_TYPE_UINT32:
                        case PDM_TYPE_UINT32_ARR:
                            field->base_type = PDM_TYPE_UINT32;
                            break;
                        case PDM_TYPE_INT64:
                        case PDM_TYPE_INT64_ARR:
                            field->base_type = PDM_TYPE_INT64;
                            break;
                        case PDM_TYPE_UINT64:
                        case PDM_TYPE_UINT64_ARR:
                            field->base_type = PDM_TYPE_UINT64;
                            break;
                        case PDM_TYPE_FLOAT:
                        case PDM_TYPE_FLOAT_ARR:
                            field->base_type = PDM_TYPE_FLOAT;
                            break;
                        case PDM_TYPE_DOUBLE:
                        case PDM_TYPE_DOUBLE_ARR:
                            field->base_type = PDM_TYPE_DOUBLE;
                            break;
                        case PDM_TYPE_DECIMAL:
                        case PDM_TYPE_DECIMAL_ARR:
                            field->base_type = PDM_TYPE_DECIMAL;
                            break;
                        case PDM_TYPE_TIMESTAMP:
                        case PDM_TYPE_TIMESTAMP_ARR:
                            field->base_type = PDM_TYPE_TIMESTAMP;
                            break;
                        case PDM_TYPE_FIX_STRING:
                        case PDM_TYPE_FIX_STRING_ARR:
                            field->base_type = PDM_TYPE_FIX_STRING;
                            break;
                        case PDM_TYPE_STRING:
                        case PDM_TYPE_STRING_ARR:
                            field->base_type = PDM_TYPE_STRING;
                            break;
                        case PDM_TYPE_FIX_UNICODE:
                        case PDM_TYPE_FIX_UNICODE_ARR:
                            field->base_type = PDM_TYPE_FIX_UNICODE;
                            break;
                        case PDM_TYPE_UNICODE:
                        case PDM_TYPE_UNICODE_ARR:
                            field->base_type = PDM_TYPE_UNICODE;
                            break;
                        case PDM_TYPE_BLOB:
                        case PDM_TYPE_BLOB_ARR:
                        default:
                            field->base_type = PDM_TYPE_BLOB;
                            break;
                        case PDM_TYPE_MESSAGE:
                        case PDM_TYPE_MESSAGE_ARR:
                            field->base_type = PDM_TYPE_MESSAGE;
                            break;
                    }
                    if ((field->fixed == PDM_DEFN_FIXED_LENGTH_FIELD) && (field->required == PDM_DEFN_REQUIRED_FIELD))
                    {
                        if (last_fixed_required_field == NULL)
                        {
                            def->first_fixed_required = field;
                            field->fixed_required_offset = 0;
                        }
                        else
                        {
                            last_fixed_required_field->next_fixed_required = field;
                            field->fixed_required_offset = last_fixed_required_field->fixed_required_offset + last_fixed_required_field->len;
                        }
                        last_fixed_required_field = field;
                        def->fixed_required_count++;
                    }
                }
            }
        }
        ofs += def_len;
        remaining_datalen -= def_len;
        num_fields--;
    }
    return (seglen);
}

static int dissect_segment_unknown(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, int encoding)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    int datalen = 0;
    int seglen = 0;

    seglen = lbmpdm_get_segment_length(tvb, offset, encoding, &datalen);
    subtree_item = proto_tree_add_none_format(tree, hf_lbmpdm_segment, tvb, offset, seglen, "Unknown Segment");
    subtree = proto_item_add_subtree(subtree_item, ett_lbmpdm_segment);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_next_hdr, tvb, offset + O_LBMPDM_SEG_HDR_T_NEXT_HDR, L_LBMPDM_SEG_HDR_T_NEXT_HDR, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_flags, tvb, offset + O_LBMPDM_SEG_HDR_T_FLAGS, L_LBMPDM_SEG_HDR_T_FLAGS, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_res, tvb, offset + O_LBMPDM_SEG_HDR_T_RES, L_LBMPDM_SEG_HDR_T_RES, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_len, tvb, offset + O_LBMPDM_SEG_HDR_T_LEN, L_LBMPDM_SEG_HDR_T_LEN, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_segment_data, tvb, offset + L_LBMPDM_SEG_HDR_T, datalen, ENC_NA);
    return (seglen);
}

static bool check_lbmpdm_encoding(tvbuff_t * tvb, int offset, int * encoding)
{
    uint8_t magic_byte_1;
    uint8_t magic_byte_2;
    uint8_t magic_byte_3;
    uint8_t magic_byte_4;
    bool result = true;

    magic_byte_1 = tvb_get_uint8(tvb, offset);
    magic_byte_2 = tvb_get_uint8(tvb, offset + 1);
    magic_byte_3 = tvb_get_uint8(tvb, offset + 2);
    magic_byte_4 = tvb_get_uint8(tvb, offset + 3);
    if ((magic_byte_1 == PDM_MSG_HDR_BE_MAGIC_BYTE_1) && (magic_byte_2 == PDM_MSG_HDR_BE_MAGIC_BYTE_2)
        && (magic_byte_3 == PDM_MSG_HDR_BE_MAGIC_BYTE_3) && (magic_byte_4 == PDM_MSG_HDR_BE_MAGIC_BYTE_4))
    {
        *encoding = ENC_BIG_ENDIAN;
    }
    else if ((magic_byte_1 == PDM_MSG_HDR_LE_MAGIC_BYTE_1) && (magic_byte_2 == PDM_MSG_HDR_LE_MAGIC_BYTE_2)
            && (magic_byte_3 == PDM_MSG_HDR_LE_MAGIC_BYTE_3) && (magic_byte_4 == PDM_MSG_HDR_LE_MAGIC_BYTE_4))
    {
        *encoding = ENC_LITTLE_ENDIAN;
    }
    else
    {
        result = false;
    }
    return (result);
}

bool lbmpdm_verify_payload(tvbuff_t * tvb, int offset, int * encoding, int * length)
{
    uint8_t next_header;
    uint32_t len = 0;

    if (!tvb_bytes_exist(tvb, offset, L_LBMPDM_MSG_HDR_T))
    {
        return false;
    }
    if (!check_lbmpdm_encoding(tvb, offset, encoding))
    {
        return false;
    }
    next_header = tvb_get_uint8(tvb, offset + O_LBMPDM_MSG_HDR_T_NEXT_HDR);
    switch (next_header)
    {
        case PDM_HDR_TYPE_DATA:
        case PDM_HDR_TYPE_OFSTTBLE:
        case PDM_HDR_TYPE_DEFN:
        case PDM_HDR_TYPE_EOM:
            break;
        default:
            return false;
    }
    len = tvb_get_uint32(tvb, offset + O_LBMPDM_MSG_HDR_T_LEN, *encoding);
    if (len > INT_MAX)
    {
        return false;
    }
    *length = (int)len;
    return true;
}

int lbmpdm_dissect_lbmpdm_payload(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, uint64_t channel)
{
    proto_item * subtree_item = NULL;
    proto_tree * subtree = NULL;
    proto_item * segments_item = NULL;
    proto_tree * segments_tree = NULL;
    proto_item * pi = NULL;
    uint8_t next_hdr;
    int dissected_len = 0;
    int encoding;
    int msglen = 0;
    int len_remaining = 0;
    int ofs = 0;
    int segment_len = 0;
    int datalen = 0;
    uint32_t raw_msglen = 0;
    lbmpdm_msg_definition_id_t msgid;

    if (!lbmpdm_verify_payload(tvb, offset, &encoding, &raw_msglen))
    {
        return 0;
    }
    msglen = (int)raw_msglen;

    msgid.channel = channel;
    msgid.offset_table = NULL;
    subtree_item = proto_tree_add_protocol_format(tree, proto_lbmpdm, tvb, offset, msglen, "LBMPDM Protocol");
    subtree = proto_item_add_subtree(subtree_item, ett_lbmpdm);
    proto_tree_add_item(subtree, hf_lbmpdm_magic, tvb, offset + O_LBMPDM_MSG_HDR_T_MAGIC, L_LBMPDM_MSG_HDR_T_MAGIC, encoding);
    pi = proto_tree_add_string(subtree, hf_lbmpdm_encoding, tvb, offset + O_LBMPDM_MSG_HDR_T_MAGIC, L_LBMPDM_MSG_HDR_T_MAGIC,
        ((encoding == ENC_BIG_ENDIAN) ? "Big-Endian" : "Little-Endian"));
    proto_item_set_generated(pi);
    proto_tree_add_item(subtree, hf_lbmpdm_ver, tvb, offset + O_LBMPDM_MSG_HDR_T_VER_TYPE, L_LBMPDM_MSG_HDR_T_VER_TYPE, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_type, tvb, offset + O_LBMPDM_MSG_HDR_T_VER_TYPE, L_LBMPDM_MSG_HDR_T_VER_TYPE, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_next_hdr, tvb, offset + O_LBMPDM_MSG_HDR_T_NEXT_HDR, L_LBMPDM_MSG_HDR_T_NEXT_HDR, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_def_major_ver, tvb, offset + O_LBMPDM_MSG_HDR_T_DEF_MAJOR_VER, L_LBMPDM_MSG_HDR_T_DEF_MAJOR_VER, encoding);
    msgid.ver_major = tvb_get_uint8(tvb, offset + O_LBMPDM_MSG_HDR_T_DEF_MAJOR_VER);
    proto_tree_add_item(subtree, hf_lbmpdm_def_minor_ver, tvb, offset + O_LBMPDM_MSG_HDR_T_DEF_MINOR_VER, L_LBMPDM_MSG_HDR_T_DEF_MINOR_VER, encoding);
    msgid.ver_minor = tvb_get_uint8(tvb, offset + O_LBMPDM_MSG_HDR_T_DEF_MINOR_VER);
    proto_tree_add_item(subtree, hf_lbmpdm_def_id, tvb, offset + O_LBMPDM_MSG_HDR_T_DEF_ID, L_LBMPDM_MSG_HDR_T_DEF_ID, encoding);
    msgid.msg_def_id = tvb_get_uint32(tvb, offset + O_LBMPDM_MSG_HDR_T_DEF_ID, encoding);
    proto_tree_add_item(subtree, hf_lbmpdm_len, tvb, offset + O_LBMPDM_MSG_HDR_T_LEN, L_LBMPDM_MSG_HDR_T_LEN, encoding);

    next_hdr = tvb_get_uint8(tvb, offset + O_LBMPDM_MSG_HDR_T_NEXT_HDR);
    len_remaining = msglen - L_LBMPDM_MSG_HDR_T;
    ofs = offset + L_LBMPDM_MSG_HDR_T;
    dissected_len = L_LBMPDM_MSG_HDR_T;
    datalen = msglen - L_LBMPDM_MSG_HDR_T;
    if (len_remaining > 0)
    {
        uint8_t this_hdr = next_hdr;

        segments_item = proto_tree_add_item(subtree, hf_lbmpdm_segments, tvb, ofs, datalen, encoding);
        segments_tree = proto_item_add_subtree(segments_item, ett_lbmpdm_segments);
        while ((this_hdr != PDM_HDR_TYPE_EOM) && (len_remaining >= L_LBMPDM_SEG_HDR_T))
        {
            next_hdr = tvb_get_uint8(tvb, ofs + O_LBMPDM_SEG_HDR_T_NEXT_HDR);
            switch (this_hdr)
            {
                case PDM_HDR_TYPE_DATA:
                    segment_len = dissect_segment_data(tvb, ofs, pinfo, segments_tree, &msgid, encoding);
                    break;
                case PDM_HDR_TYPE_OFSTTBLE:
                    segment_len = dissect_segment_ofstable(tvb, ofs, pinfo, segments_tree, &(msgid.offset_table), encoding);
                    break;
                case PDM_HDR_TYPE_DEFN:
                    segment_len = dissect_segment_defn(tvb, ofs, pinfo, segments_tree, channel, encoding);
                    break;
                default:
                    segment_len = dissect_segment_unknown(tvb, ofs, pinfo, segments_tree, encoding);
                    break;
            }
            this_hdr = next_hdr;
            dissected_len += segment_len;
            len_remaining -= segment_len;
            ofs += segment_len;
        }
    }
    return (dissected_len);
}

int lbmpdm_get_minimum_length(void)
{
    return (L_LBMPDM_MSG_HDR_T);
}

/* Register all the bits needed with the filtering engine */
void proto_register_lbmpdm(void)
{
    static hf_register_info hf[] =
    {
        { &hf_lbmpdm_magic,
            { "Magic", "lbmpdm.magic", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_encoding,
            { "Encoding", "lbmpdm.encoding", FT_STRING, BASE_NONE, NULL, 0x0, "encoding as determined by magic number", HFILL } },
        { &hf_lbmpdm_ver,
            { "Version", "lbmpdm.ver", FT_UINT8, BASE_DEC, NULL, PDM_HDR_VER_TYPE_VER_MASK, NULL, HFILL } },
        { &hf_lbmpdm_type,
            { "Type", "lbmpdm.type", FT_UINT8, BASE_DEC, NULL, PDM_HDR_VER_TYPE_TYPE_MASK, NULL, HFILL } },
        { &hf_lbmpdm_next_hdr,
            { "Next Header", "lbmpdm.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmpdm_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmpdm_def_major_ver,
            { "Definition Major Version", "lbmpdm.def_major_ver", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_def_minor_ver,
            { "Definition Minor Version", "lbmpdm.def_minor_ver", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_def_id,
            { "Definition ID", "lbmpdm.def_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_len,
            { "Length", "lbmpdm.len", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segments,
            { "Segments", "lbmpdm.segments", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment,
            { "Segment", "lbmpdm.segment", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_next_hdr,
            { "Next Header", "lbmpdm.segment.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbmpdm_next_header), 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_flags,
            { "Flags", "lbmpdm.segment.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_res,
            { "Reserved", "lbmpdm.segment.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_len,
            { "Length", "lbmpdm.segment.len", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_id,
            { "Definition ID", "lbmpdm.segment_def.id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_num_fields,
            { "Number Of Fields", "lbmpdm.segment_def.num_fields", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_names_type,
            { "Field Names Type", "lbmpdm.segment_def.field_names_type", FT_UINT8, BASE_HEX, VALS(lbmpdm_field_name_type), 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_finalized,
            { "Finalized", "lbmpdm.segment_def.finalized", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_msg_vers_major,
            { "Definition Major Version", "lbmpdm.segment_def.msg_vers_major", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_msg_vers_minor,
            { "Definition Minor Version", "lbmpdm.segment_def.msg_vers_minor", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_fixed_req_section_len,
            { "Fixed Required Section Length", "lbmpdm.segment_def.fixed_req_section_len", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_info_len,
            { "Field Information Length", "lbmpdm.segment_def.field_info_len", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field,
            { "Field Definition", "lbmpdm.segment_def.field", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_def_len,
            { "Definition Length", "lbmpdm.segment_def.field.def_len", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_id,
            { "ID", "lbmpdm.segment_def.field.id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_len,
            { "Length", "lbmpdm.segment_def.field.len", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_fixed_str_len,
            { "Fixed String Length", "lbmpdm.segment_def.field.fixed_str_len", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_num_arr_elem,
            { "Number Of Array Elements", "lbmpdm.segment_def.field.num_arr_elem", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_req,
            { "Required", "lbmpdm.segment_def.field.req", FT_UINT8, BASE_HEX, VALS(lbmpdm_field_required), 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_fixed,
            { "Fixed Length Field", "lbmpdm.segment_def.field.fixed", FT_UINT8, BASE_HEX, VALS(lbmpdm_field_fixed_length), 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_fld_int_name,
            { "Field Integer Name", "lbmpdm.segment_def.field.fld_int_name", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_str_name_len,
            { "String Name Length", "lbmpdm.segment_def.field.str_name_len", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_str_name,
            { "String Name", "lbmpdm.segment_def.field.str_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_def_field_fld_type,
            { "Field Type", "lbmpdm.segment_def.field.fld_type", FT_UINT16, BASE_DEC_HEX, VALS(lbmpdm_field_type), 0x0, NULL, HFILL } },
        { &hf_lbmpdm_offset_entry,
            { "Offset Entry", "lbmpdm.segment_ofs.entry", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_offset_entry_id,
            { "ID", "lbmpdm.segment_ofs.entry.id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_offset_entry_offset,
            { "Offset", "lbmpdm.segment_ofs.entry.offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_segment_data,
            { "Data", "lbmpdm.segment.data", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field,
            { "Field", "lbmpdm.field", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_id,
            { "ID", "lbmpdm.field.id", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_string_name,
            { "String Name", "lbmpdm.field.string_name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_int_name,
            { "Integer Name", "lbmpdm.field.int_name", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_type,
            { "Type", "lbmpdm.field.type", FT_UINT16, BASE_DEC_HEX, VALS(lbmpdm_field_type), 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_total_length,
            { "Total Length", "lbmpdm.field.total_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_length,
            { "Length", "lbmpdm.field.length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_boolean,
            { "Boolean Value", "lbmpdm.field.value_boolean", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_int8,
            { "INT8 Value", "lbmpdm.field.value_int8", FT_INT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_uint8,
            { "UINT8 Value", "lbmpdm.field.value_uint8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_int16,
            { "INT16 Value", "lbmpdm.field.value_int16", FT_INT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_uint16,
            { "UINT16 Value", "lbmpdm.field.value_uint16", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_int32,
            { "INT32 Value", "lbmpdm.field.value_int32", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_uint32,
            { "UINT32 Value", "lbmpdm.field.value_uint32", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_int64,
            { "INT64 Value", "lbmpdm.field.value_int64", FT_INT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_uint64,
            { "UINT64 Value", "lbmpdm.field.value_uint64", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_float,
            { "FLOAT Value", "lbmpdm.field.value_float", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_double,
            { "DOUBLE Value", "lbmpdm.field.value_double", FT_DOUBLE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_decimal,
            { "DECIMAL Value", "lbmpdm.field.value_decimal", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_timestamp,
            { "TIMESTAMP Value", "lbmpdm.field.value_timestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_fixed_string,
            { "FIXED STRING Value", "lbmpdm.field.value_fixed_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_string,
            { "STRING Value", "lbmpdm.field.value_string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_fixed_unicode,
            { "FIXED UNICODE Value", "lbmpdm.field.value_fixed_unicode", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_unicode,
            { "UNICODE Value", "lbmpdm.field.value_unicode", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_blob,
            { "BLOB Value", "lbmpdm.field.value_blob", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbmpdm_field_value_message,
            { "MESSAGE Value", "lbmpdm.field.value_message", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } }
    };
    static int * ett[] =
    {
        &ett_lbmpdm,
        &ett_lbmpdm_segments,
        &ett_lbmpdm_segment,
        &ett_lbmpdm_offset_entry,
        &ett_lbmpdm_segment_def_field,
        &ett_lbmpdm_field
    };

    proto_lbmpdm = proto_register_protocol("LBMPDM Protocol", "LBMPDM", "lbmpdm");

    proto_register_field_array(proto_lbmpdm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    lbmpdm_definition_table = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
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
