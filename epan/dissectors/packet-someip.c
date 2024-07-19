/* packet-someip.c
 * SOME/IP dissector.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de> / <lars.voelker@bmw.de>
 * Copyright 2012-2024 Dr. Lars Voelker
 * Copyright 2019      Ana Pantar
 * Copyright 2019      Guenter Ebermann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/uat.h>
#include "packet-tcp.h"
#include <epan/reassemble.h>
#include <epan/addr_resolv.h>
#include <epan/stats_tree.h>
#include <epan/prefs-int.h>

#include "packet-udp.h"
#include "packet-dtls.h"
#include "packet-someip.h"
#include "packet-tls.h"

/*
 * Dissector for SOME/IP, SOME/IP-TP, and SOME/IP Payloads.
 *
 * See
 *     http://www.some-ip.com
 *
 *
 * This dissector also supports the experimental WTLV or TLV extension,
 * which is not part of the original SOME/IP.
 * This add-on feature uses a so-called WireType, which is basically
 * a type of a length field and an ID to each parameter. Since the
 * WireType is not really a type, we should avoid TLV as name for this.
 * Only use this, if you know what you are doing since this changes the
 * serialization methodology of SOME/IP in a incompatible way and might
 * break the dissection of your messages.
 */

#define SOMEIP_NAME                             "SOME/IP"
#define SOMEIP_NAME_LONG                        "SOME/IP Protocol"
#define SOMEIP_NAME_FILTER                      "someip"
#define SOMEIP_NAME_PREFIX                      "someip.payload"

#define SOMEIP_NAME_LONG_MULTIPLE               "SOME/IP Protocol (Multiple Payloads)"
#define SOMEIP_NAME_LONG_BROKEN                 "SOME/IP: Incomplete headers!"
#define SOMEIP_NAME_LONG_TOO_SHORT              "SOME/IP: Incomplete SOME/IP payload!"

 /*** Configuration ***/
#define DATAFILE_SOMEIP_SERVICES                "SOMEIP_service_identifiers"
#define DATAFILE_SOMEIP_METHODS                 "SOMEIP_method_event_identifiers"
#define DATAFILE_SOMEIP_EVENTGROUPS             "SOMEIP_eventgroup_identifiers"
#define DATAFILE_SOMEIP_CLIENTS                 "SOMEIP_client_identifiers"

#define DATAFILE_SOMEIP_PARAMETERS              "SOMEIP_parameter_list"
#define DATAFILE_SOMEIP_BASE_TYPES              "SOMEIP_parameter_base_types"
#define DATAFILE_SOMEIP_ARRAYS                  "SOMEIP_parameter_arrays"
#define DATAFILE_SOMEIP_STRINGS                 "SOMEIP_parameter_strings"
#define DATAFILE_SOMEIP_TYPEDEFS                "SOMEIP_parameter_typedefs"
#define DATAFILE_SOMEIP_STRUCTS                 "SOMEIP_parameter_structs"
#define DATAFILE_SOMEIP_UNIONS                  "SOMEIP_parameter_unions"
#define DATAFILE_SOMEIP_ENUMS                   "SOMEIP_parameter_enums"

#define SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_UNKNOWN      0
#define SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_BASE_TYPE    1
#define SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_STRING       2
#define SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ARRAY        3
#define SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_STRUCT       4
#define SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_UNION        5
#define SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_TYPEDEF      6
#define SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ENUM         7

/*** SOME/IP ***/
#define SOMEIP_HDR_LEN                          16
#define SOMEIP_HDR_PART1_LEN                    8
#define SOMEIP_HDR_PART2_LEN_INCL_TP            12
#define SOMEIP_TP_HDR_LEN                       4
#define SOMEIP_PROTOCOL_VERSION                 1

/* Message Types */
#define SOMEIP_MSGTYPE_REQUEST                  0x00
#define SOMEIP_MSGTYPE_REQUEST_NO_RESPONSE      0x01
#define SOMEIP_MSGTYPE_NOTIFICATION             0x02
#define SOMEIP_MSGTYPE_RESPONSE                 0x80
#define SOMEIP_MSGTYPE_ERROR                    0x81

#define SOMEIP_MSGTYPE_ACK_MASK                 0x40
#define SOMEIP_MSGTYPE_TP_MASK                  0x20
#define SOMEIP_MSGTYPE_FLAGS_MASK               0x60
#define SOMEIP_MSGTYPE_NO_FLAGS_MASK            0x9f
#define SOMEIP_MSGTYPE_TP_STRING                "SOME/IP-TP segment"
#define SOMEIP_MSGTYPE_ACK_STRING               "ACK"

/* SOME/IP-TP */
#define SOMEIP_TP_OFFSET_MASK                   0xfffffff0
#define SOMEIP_TP_OFFSET_MASK_FLAGS             0x0000000f
#define SOMEIP_TP_OFFSET_MASK_RESERVED          0x0000000e
#define SOMEIP_TP_OFFSET_MASK_MORE_SEGMENTS     0x00000001

/* Return Codes */
#define SOMEIP_RETCODE_OK                       0x00
#define SOMEIP_RETCODE_NOT_OK                   0x01
#define SOMEIP_RETCODE_UNKNOWN_SERVICE          0x02
#define SOMEIP_RETCODE_UNKNOWN_METHOD           0x03
#define SOMEIP_RETCODE_NOT_READY                0x04
#define SOMEIP_RETCODE_NOT_REACHABLE            0x05
#define SOMEIP_RETCODE_TIMEOUT                  0x06
#define SOMEIP_RETCODE_WRONG_PROTO_VER          0x07
#define SOMEIP_RETCODE_WRONG_INTERFACE_VER      0x08
#define SOMEIP_RETCODE_MALFORMED_MSG            0x09
#define SOMEIP_RETCODE_WRONG_MESSAGE_TYPE       0x0a

/* SOME/IP WTLV (experimental "WTLV" extension) */
#define SOMEIP_WTLV_MASK_RES                     0x8000
#define SOMEIP_WTLV_MASK_WIRE_TYPE               0x7000
#define SOMEIP_WTLV_MASK_DATA_ID                 0x0fff

/* ID wireshark identifies the dissector by */
static int proto_someip;
static module_t *someip_module;

static dissector_handle_t someip_handle_udp;
static dissector_handle_t someip_handle_tcp;
static dissector_handle_t dtls_handle;

/* header field */
static int hf_someip_messageid;
static int hf_someip_serviceid;
static int hf_someip_servicename;
static int hf_someip_methodid;
static int hf_someip_methodname;
static int hf_someip_length;
static int hf_someip_clientid;
static int hf_someip_clientname;
static int hf_someip_sessionid;
static int hf_someip_protover;
static int hf_someip_interface_ver;
static int hf_someip_messagetype;
static int hf_someip_messagetype_ack_flag;
static int hf_someip_messagetype_tp_flag;
static int hf_someip_returncode;

static int hf_someip_tp;
static int hf_someip_tp_offset;
static int hf_someip_tp_offset_encoded;
static int hf_someip_tp_flags;
static int hf_someip_tp_reserved;
static int hf_someip_tp_more_segments;

static int hf_someip_payload;

/* protocol tree items */
static int ett_someip;
static int ett_someip_msgtype;
static int ett_someip_tp;

/* dissector handling */
static dissector_table_t someip_dissector_table;

/* message reassembly for SOME/IP-TP */
static int hf_someip_tp_fragments;
static int hf_someip_tp_fragment;
static int hf_someip_tp_fragment_overlap;
static int hf_someip_tp_fragment_overlap_conflicts;
static int hf_someip_tp_fragment_multiple_tails;
static int hf_someip_tp_fragment_too_long_fragment;
static int hf_someip_tp_fragment_error;
static int hf_someip_tp_fragment_count;
static int hf_someip_tp_reassembled_in;
static int hf_someip_tp_reassembled_length;
static int hf_someip_tp_reassembled_data;

static int hf_payload_unparsed;
static int hf_payload_length_field_8bit;
static int hf_payload_length_field_16bit;
static int hf_payload_length_field_32bit;
static int hf_payload_type_field_8bit;
static int hf_payload_type_field_16bit;
static int hf_payload_type_field_32bit;
static int hf_payload_str_base;
static int hf_payload_str_string;
static int hf_payload_str_struct;
static int hf_payload_str_array;
static int hf_payload_str_union;

static int hf_payload_wtlv_tag;
static int hf_payload_wtlv_tag_res;
static int hf_payload_wtlv_tag_wire_type;
static int hf_payload_wtlv_tag_data_id;

static hf_register_info* dynamic_hf_param;
static unsigned dynamic_hf_param_size;
static hf_register_info* dynamic_hf_array;
static unsigned dynamic_hf_array_size;
static hf_register_info* dynamic_hf_struct;
static unsigned dynamic_hf_struct_size;
static hf_register_info* dynamic_hf_union;
static unsigned dynamic_hf_union_size;

static int ett_someip_tp_fragment;
static int ett_someip_tp_fragments;
static int ett_someip_payload;
static int ett_someip_string;
static int ett_someip_array;
static int ett_someip_array_dim;
static int ett_someip_struct;
static int ett_someip_union;
static int ett_someip_parameter;
static int ett_someip_wtlv_tag;

static const fragment_items someip_tp_frag_items = {
    &ett_someip_tp_fragment,
    &ett_someip_tp_fragments,
    &hf_someip_tp_fragments,
    &hf_someip_tp_fragment,
    &hf_someip_tp_fragment_overlap,
    &hf_someip_tp_fragment_overlap_conflicts,
    &hf_someip_tp_fragment_multiple_tails,
    &hf_someip_tp_fragment_too_long_fragment,
    &hf_someip_tp_fragment_error,
    &hf_someip_tp_fragment_count,
    &hf_someip_tp_reassembled_in,
    &hf_someip_tp_reassembled_length,
    &hf_someip_tp_reassembled_data,
    "SOME/IP-TP Segments"
};

static bool someip_tp_reassemble = true;
static bool someip_deserializer_activated = true;
static bool someip_deserializer_wtlv_default;
static bool someip_detect_dtls;

/* SOME/IP Message Types */
static const value_string someip_msg_type[] = {
    {SOMEIP_MSGTYPE_REQUEST,                                            "Request"},
    {SOMEIP_MSGTYPE_REQUEST_NO_RESPONSE,                                "Request no response"},
    {SOMEIP_MSGTYPE_NOTIFICATION,                                       "Notification"},
    {SOMEIP_MSGTYPE_RESPONSE,                                           "Response"},
    {SOMEIP_MSGTYPE_ERROR,                                              "Error"},
    {SOMEIP_MSGTYPE_REQUEST | SOMEIP_MSGTYPE_ACK_MASK,                  "Request Ack"},
    {SOMEIP_MSGTYPE_REQUEST_NO_RESPONSE | SOMEIP_MSGTYPE_ACK_MASK,      "Request no response Ack"},
    {SOMEIP_MSGTYPE_NOTIFICATION | SOMEIP_MSGTYPE_ACK_MASK,             "Notification Ack"},
    {SOMEIP_MSGTYPE_RESPONSE | SOMEIP_MSGTYPE_ACK_MASK,                 "Response Ack"},
    {SOMEIP_MSGTYPE_ERROR | SOMEIP_MSGTYPE_ACK_MASK,                    "Error Ack"},
    {0, NULL}
};

/* SOME/IP Return Code */
static const value_string someip_return_code[] = {
    {SOMEIP_RETCODE_OK,                                                 "Ok"},
    {SOMEIP_RETCODE_NOT_OK,                                             "Not Ok"},
    {SOMEIP_RETCODE_UNKNOWN_SERVICE,                                    "Unknown Service"},
    {SOMEIP_RETCODE_UNKNOWN_METHOD,                                     "Unknown Method/Event"},
    {SOMEIP_RETCODE_NOT_READY,                                          "Not Ready"},
    {SOMEIP_RETCODE_NOT_REACHABLE,                                      "Not Reachable (internal)"},
    {SOMEIP_RETCODE_TIMEOUT,                                            "Timeout (internal)"},
    {SOMEIP_RETCODE_WRONG_PROTO_VER,                                    "Wrong Protocol Version"},
    {SOMEIP_RETCODE_WRONG_INTERFACE_VER,                                "Wrong Interface Version"},
    {SOMEIP_RETCODE_MALFORMED_MSG,                                      "Malformed Message"},
    {SOMEIP_RETCODE_WRONG_MESSAGE_TYPE,                                 "Wrong Message Type"},
    {0, NULL}
};

/*** expert info items ***/
static expert_field ei_someip_unknown_version;
static expert_field ei_someip_message_truncated;
static expert_field ei_someip_incomplete_headers;

static expert_field ei_someip_payload_truncated;
static expert_field ei_someip_payload_malformed;
static expert_field ei_someip_payload_config_error;
static expert_field ei_someip_payload_alignment_error;
static expert_field ei_someip_payload_static_array_min_not_max;
static expert_field ei_someip_payload_dyn_array_not_within_limit;

/*** Data Structure for mapping IDs to Names (Services, Methods, ...) ***/
static GHashTable *data_someip_services;
static GHashTable *data_someip_methods;
static GHashTable *data_someip_eventgroups;
static GHashTable *data_someip_clients;

static GHashTable *data_someip_parameter_list;
static GHashTable *data_someip_parameter_base_type_list;
static GHashTable *data_someip_parameter_strings;
static GHashTable *data_someip_parameter_typedefs;
static GHashTable *data_someip_parameter_arrays;
static GHashTable *data_someip_parameter_structs;
static GHashTable *data_someip_parameter_unions;
static GHashTable *data_someip_parameter_enums;

/*** Taps ***/
static int tap_someip_messages = -1;

/*** Stats ***/
static const char *st_str_ip_src = "Source Addresses";
static const char *st_str_ip_dst = "Destination Addresses";

static int st_node_ip_src = -1;
static int st_node_ip_dst = -1;

/***********************************************
 ********* Preferences / Configuration *********
 ***********************************************/

typedef struct _someip_payload_parameter_item {
    uint32_t    pos;
    char       *name;
    uint32_t    data_type;
    uint32_t    id_ref;
    int        *hf_id;
    char       *filter_string;
} someip_payload_parameter_item_t;

#define INIT_SOMEIP_PAYLOAD_PARAMETER_ITEM(NAME) \
    (NAME)->pos = 0; \
    (NAME)->name = NULL; \
    (NAME)->data_type = 0; \
    (NAME)->id_ref = 0; \
    (NAME)->hf_id = NULL; \
    (NAME)->filter_string = NULL;


typedef struct _someip_payload_parameter_base_type_list {
    uint32_t    id;
    char       *name;
    char       *data_type;
    bool        big_endian;
    uint32_t    bitlength_base_type;
    uint32_t    bitlength_encoded_type;
} someip_payload_parameter_base_type_list_t;

#define INIT_COMMON_BASE_TYPE_LIST_ITEM(NAME) \
    (NAME)->id                      = 0; \
    (NAME)->name                    = NULL; \
    (NAME)->data_type               = NULL ; \
    (NAME)->big_endian              = true; \
    (NAME)->bitlength_base_type     = 0; \
    (NAME)->bitlength_encoded_type  = 0;


typedef struct _someip_payload_parameter_string {
    uint32_t    id;
    char       *name;
    char       *encoding;
    bool        dynamic_length;
    uint32_t    max_length;
    uint32_t    length_of_length;   /* default: 32 */
    bool        big_endian;
    uint32_t    pad_to;
} someip_payload_parameter_string_t;

#define INIT_SOMEIP_PAYLOAD_PARAMETER_STRING(NAME) \
    (NAME)->id                  = 0; \
    (NAME)->name                = NULL; \
    (NAME)->encoding            = NULL; \
    (NAME)->dynamic_length      = false; \
    (NAME)->max_length          = 0; \
    (NAME)->length_of_length    = 0; \
    (NAME)->big_endian          = true; \
    (NAME)->pad_to              = 0;


typedef struct _someip_payload_parameter_typedef {
    uint32_t   id;
    char*     name;
    uint32_t   data_type;
    uint32_t   id_ref;
} someip_payload_parameter_typedef_t;

#define INIT_SOMEIP_PAYLOAD_PARAMETER_TYPEDEF(NAME) \
    (NAME)->id          = 0; \
    (NAME)->name        = NULL; \
    (NAME)->data_type   = 0; \
    (NAME)->id_ref      = 0;


typedef struct _someip_payload_parameter_struct {
    uint32_t    id;
    char       *struct_name;
    uint32_t    length_of_length;   /* default: 0 */
    uint32_t    pad_to;             /* default: 0 */
    bool        wtlv_encoding;
    uint32_t    num_of_items;

    /* array of items */
    someip_payload_parameter_item_t *items;
} someip_payload_parameter_struct_t;

#define INIT_SOMEIP_PAYLOAD_PARAMETER_STRUCT(NAME) \
    (NAME)->id                  = 0; \
    (NAME)->struct_name         = NULL; \
    (NAME)->length_of_length    = 0; \
    (NAME)->pad_to              = 0; \
    (NAME)->wtlv_encoding       = false; \
    (NAME)->num_of_items        = 0;


typedef struct _someip_payload_parameter_enum_item {
    uint64_t    value;
    char       *name;
} someip_payload_parameter_enum_item_t;

#define INIT_SOMEIP_PAYLOAD_PARAMETER_ENUM_ITEM(NAME) \
    (NAME)->value   = 0; \
    (NAME)->name    = NULL;


typedef struct _someip_payload_parameter_enum {
    uint32_t    id;
    char       *name;
    uint32_t    data_type;
    uint32_t    id_ref;
    uint32_t    num_of_items;

    someip_payload_parameter_enum_item_t *items;
} someip_payload_parameter_enum_t;

#define INIT_SOMEIP_PAYLOAD_PARAMETER_ENUM(NAME) \
    (NAME)->id              = 0; \
    (NAME)->name            = NULL; \
    (NAME)->data_type       = 0; \
    (NAME)->id_ref          = 0; \
    (NAME)->num_of_items    = 0; \
    (NAME)->items           = NULL;

typedef struct _someip_parameter_union_item {
    uint32_t            id;
    char               *name;
    uint32_t            data_type;
    uint32_t            id_ref;
    int                *hf_id;
    char               *filter_string;
} someip_parameter_union_item_t;

typedef struct _someip_parameter_union {
    uint32_t            id;
    char               *name;
    uint32_t            length_of_length;       /* default: 32 */
    uint32_t            length_of_type;         /* default: 32 */
    uint32_t            pad_to;                 /* default: 0 */
    uint32_t            num_of_items;

    someip_parameter_union_item_t *items;
} someip_parameter_union_t;

typedef struct _someip_parameter_union_uat {
    uint32_t            id;
    char               *name;
    uint32_t            length_of_length;
    uint32_t            length_of_type;
    uint32_t            pad_to;
    uint32_t            num_of_items;
    uint32_t            type_id;
    char               *type_name;
    uint32_t            data_type;
    uint32_t            id_ref;
    char               *filter_string;
} someip_parameter_union_uat_t;

typedef struct _someip_parameter_enum_uat {
    uint32_t            id;
    char               *name;
    uint32_t            data_type;
    uint32_t            id_ref;
    uint32_t            num_of_items;
    uint32_t            value;
    char               *value_name;
} someip_parameter_enum_uat_t;

typedef struct _someip_parameter_array_dim {
    uint32_t            num;
    uint32_t            lower_limit;
    uint32_t            upper_limit;
    uint32_t            length_of_length;
    uint32_t            pad_to;
} someip_parameter_array_dim_t;

typedef struct _someip_parameter_array {
    uint32_t            id;
    char               *name;
    uint32_t            data_type;
    uint32_t            id_ref;
    uint32_t            num_of_dims;
    int                *hf_id;
    char               *filter_string;

    someip_parameter_array_dim_t *dims;
} someip_parameter_array_t;

typedef struct _someip_parameter_array_uat {
    uint32_t            id;
    char               *name;
    uint32_t            data_type;
    uint32_t            id_ref;
    uint32_t            num_of_dims;
    char               *filter_string;

    uint32_t            num;
    uint32_t            lower_limit;
    uint32_t            upper_limit;
    uint32_t            length_of_length;
    uint32_t            pad_to;
} someip_parameter_array_uat_t;

typedef struct _someip_parameter_list {
    uint32_t            service_id;
    uint32_t            method_id;
    uint32_t            version;
    uint32_t            message_type;
    bool                wtlv_encoding;

    uint32_t            num_of_items;

    someip_payload_parameter_item_t *items;
} someip_parameter_list_t;

typedef struct _someip_parameter_list_uat {
    uint32_t            service_id;
    uint32_t            method_id;
    uint32_t            version;
    uint32_t            message_type;
    bool                wtlv_encoding;

    uint32_t            num_of_params;

    uint32_t            pos;
    char               *name;
    uint32_t            data_type;
    uint32_t            id_ref;
    char               *filter_string;
} someip_parameter_list_uat_t;

typedef struct _someip_parameter_struct_uat {
    uint32_t            id;
    char               *struct_name;
    uint32_t            length_of_length;       /* default: 0 */
    uint32_t            pad_to;                 /* default: 0 */
    bool                wtlv_encoding;

    uint32_t            num_of_items;

    uint32_t            pos;
    char               *name;
    uint32_t            data_type;
    uint32_t            id_ref;
    char               *filter_string;
} someip_parameter_struct_uat_t;

typedef someip_payload_parameter_base_type_list_t someip_parameter_base_type_list_uat_t;
typedef someip_payload_parameter_string_t someip_parameter_string_uat_t;
typedef someip_payload_parameter_typedef_t someip_parameter_typedef_uat_t;

typedef struct _generic_one_id_string {
    unsigned   id;
    char   *name;
} generic_one_id_string_t;

typedef struct _generic_two_id_string {
    unsigned   id;
    unsigned   id2;
    char   *name;
} generic_two_id_string_t;

static generic_one_id_string_t *someip_service_ident;
static unsigned someip_service_ident_num;

static generic_two_id_string_t *someip_method_ident;
static unsigned someip_method_ident_num;

static generic_two_id_string_t *someip_eventgroup_ident;
static unsigned someip_eventgroup_ident_num;

static generic_two_id_string_t *someip_client_ident;
static unsigned someip_client_ident_num;

static someip_parameter_list_uat_t *someip_parameter_list;
static unsigned someip_parameter_list_num;

static someip_parameter_string_uat_t *someip_parameter_strings;
static unsigned someip_parameter_strings_num;

static someip_parameter_typedef_uat_t *someip_parameter_typedefs;
static unsigned someip_parameter_typedefs_num;

static someip_parameter_array_uat_t *someip_parameter_arrays;
static unsigned someip_parameter_arrays_num;

static someip_parameter_struct_uat_t *someip_parameter_structs;
static unsigned someip_parameter_structs_num;

static someip_parameter_union_uat_t *someip_parameter_unions;
static unsigned someip_parameter_unions_num;

static someip_parameter_enum_uat_t *someip_parameter_enums;
static unsigned someip_parameter_enums_num;

static someip_parameter_base_type_list_uat_t *someip_parameter_base_type_list;
static unsigned someip_parameter_base_type_list_num;

void proto_register_someip(void);
void proto_reg_handoff_someip(void);

static void deregister_dynamic_hf_data(hf_register_info **hf_array, unsigned *hf_size);
static void update_dynamic_hf_entries_someip_parameter_list(void);
static void update_dynamic_hf_entries_someip_parameter_arrays(void);
static void update_dynamic_hf_entries_someip_parameter_structs(void);
static void update_dynamic_hf_entries_someip_parameter_unions(void);

/* Segmentation support
 * https://gitlab.com/wireshark/wireshark/-/issues/18880
 */
typedef struct _someip_segment_key {
    address src_addr;
    address dst_addr;
    uint32_t src_port;
    uint32_t dst_port;
    someip_info_t info;
} someip_segment_key;

static unsigned
someip_segment_hash(const void *k)
{
    const someip_segment_key *key = (const someip_segment_key *)k;
    unsigned hash_val;

    hash_val = (key->info.service_id << 16 | key->info.method_id) ^
        (key->info.client_id << 16 | key->info.session_id);

    return hash_val;
}

static int
someip_segment_equal(const void *k1, const void *k2)
{
    const someip_segment_key *key1 = (someip_segment_key *)k1;
    const someip_segment_key *key2 = (someip_segment_key *)k2;

    return (key1->info.session_id == key2->info.session_id) &&
        (key1->info.service_id == key2->info.service_id) &&
        (key1->info.client_id == key2->info.client_id) &&
        (key1->info.method_id == key2->info.method_id) &&
        (key1->info.message_type == key2->info.message_type) &&
        (key1->info.major_version == key2->info.major_version) &&
        (addresses_equal(&key1->src_addr, &key2->src_addr)) &&
        (addresses_equal(&key1->dst_addr, &key2->dst_addr)) &&
        (key1->src_port == key2->src_port) &&
        (key1->dst_port == key2->dst_port);
}

/*
 * Create a fragment key for temporary use; it can point to non-
 * persistent data, and so must only be used to look up and
 * delete entries, not to add them.
 */
static void *
someip_segment_temporary_key(const packet_info *pinfo, const uint32_t id _U_,
                          const void *data)
{
    const someip_info_t *info = (const someip_info_t *)data;
    someip_segment_key *key = g_slice_new(someip_segment_key);

    /* Do a shallow copy of the addresses. */
    copy_address_shallow(&key->src_addr, &pinfo->src);
    copy_address_shallow(&key->dst_addr, &pinfo->dst);
    key->src_port = pinfo->srcport;
    key->dst_port = pinfo->destport;
    memcpy(&key->info, info, sizeof(someip_info_t));

    return (void *)key;
}

/*
 * Create a fragment key for permanent use; it must point to persistent
 * data, so that it can be used to add entries.
 */
static void *
someip_segment_persistent_key(const packet_info *pinfo,
                              const uint32_t id _U_, const void *data)
{
    const someip_info_t *info = (const someip_info_t *)data;
    someip_segment_key *key = g_slice_new(someip_segment_key);

    /* Do a deep copy of the addresses. */
    copy_address(&key->src_addr, &pinfo->src);
    copy_address(&key->dst_addr, &pinfo->dst);
    key->src_port = pinfo->srcport;
    key->dst_port = pinfo->destport;
    memcpy(&key->info, info, sizeof(someip_info_t));

    return (void *)key;
}

static void
someip_segment_free_temporary_key(void *ptr)
{
    someip_segment_key *key = (someip_segment_key *)ptr;
    if (key) {
        g_slice_free(someip_segment_key, key);
    }
}
static void
someip_segment_free_persistent_key(void *ptr)
{
    someip_segment_key *key = (someip_segment_key *)ptr;
    if (key) {
        /* Free up the copies of the addresses from the old key. */
        free_address(&key->src_addr);
        free_address(&key->dst_addr);

        g_slice_free(someip_segment_key, key);
    }
}

static const reassembly_table_functions
someip_reassembly_table_functions = {
    someip_segment_hash,
    someip_segment_equal,
    someip_segment_temporary_key,
    someip_segment_persistent_key,
    someip_segment_free_temporary_key,
    someip_segment_free_persistent_key
};

static reassembly_table someip_tp_reassembly_table;


/* register a UDP SOME/IP port */
void
register_someip_port_udp(uint32_t portnumber) {
    dissector_add_uint("udp.port", portnumber, someip_handle_udp);
}

/* register a TCP SOME/IP port */
void
register_someip_port_tcp(uint32_t portnumber) {
    dissector_add_uint("tcp.port", portnumber, someip_handle_tcp);
}

/*** UAT Callbacks and Helpers ***/

static void
set_prefs_changed(void) {
    /* This ensures that proto_reg_handoff_someip is called, even if SOME/IP is not bound to any port yet. */
    if (someip_module) {
        someip_module->prefs_changed_flags |= (PREF_EFFECT_DISSECTION|PREF_EFFECT_FIELDS);
    }
}

static char*
check_filter_string(char *filter_string, uint32_t id) {
    char   *err = NULL;
    unsigned char  c;

    c = proto_check_field_name(filter_string);
    if (c) {
        if (c == '.') {
            err = ws_strdup_printf("Filter String contains illegal chars '.' (ID: %i )", id);
        } else if (g_ascii_isprint(c)) {
            err = ws_strdup_printf("Filter String contains illegal chars '%c' (ID: %i)", c, id);
        } else {
            err = ws_strdup_printf("Filter String contains invalid byte \\%03o (ID: %i)", c, id);
        }
    }

    return err;
}

static void
someip_free_key(void *key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
simple_free(void *data _U_) {
    /* we need to free because of the g_strdup in post_update*/
    g_free(data);
}

/* ID -> Name */
static void *
copy_generic_one_id_string_cb(void *n, const void *o, size_t size _U_) {
    generic_one_id_string_t        *new_rec = (generic_one_id_string_t *)n;
    const generic_one_id_string_t  *old_rec = (const generic_one_id_string_t *)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->id   = old_rec->id;
    return new_rec;
}

static bool
update_serviceid(void *r, char **err) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;

    if (rec->id == 0xffff) {
        *err = ws_strdup_printf("Service-ID 0xffff is reserved and cannot be used (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->id > 0xffff) {
        *err = ws_strdup_printf("Service-IDs have to be 16bit (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    return true;
}

static void
free_generic_one_id_string_cb(void *r) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static void
post_update_one_id_string_template_cb(generic_one_id_string_t *data, unsigned data_num, GHashTable *ht) {
    unsigned   i;
    int    *key = NULL;

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int);
        *key = data[i].id;

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}

/* ID/ID2 -> Name */

static void *
copy_generic_two_id_string_cb(void *n, const void *o, size_t size _U_) {
    generic_two_id_string_t        *new_rec = (generic_two_id_string_t *)n;
    const generic_two_id_string_t  *old_rec = (const generic_two_id_string_t *)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->id   = old_rec->id;
    new_rec->id2  = old_rec->id2;
    return new_rec;
}

static bool
update_two_identifier_16bit_check_both(void *r, char **err) {
    generic_two_id_string_t *rec = (generic_two_id_string_t *)r;

    if (rec->id == 0xffff) {
        *err = ws_strdup_printf("Service-ID 0xffff is reserved and cannot be used (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->id > 0xffff) {
        *err = ws_strdup_printf("Service-IDs have to be 16bit (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->id2 == 0xffff) {
        *err = ws_strdup_printf("0xffff is reserved and cannot be used (ID: %i  ID2: %i  Name: %s)", rec->id, rec->id2, rec->name);
        return false;
    }

    if (rec->id2 > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit identifiers (ID: %i  ID2: %i  Name: %s)", rec->id, rec->id2, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    return true;
}

static bool
update_generic_two_identifier_16bit(void *r, char **err) {
    generic_two_id_string_t *rec = (generic_two_id_string_t *)r;

    if (rec->id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit identifiers (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->id2 > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit identifiers (ID: %i  ID2: %i  Name: %s)", rec->id, rec->id2, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    return true;
}

static void
free_generic_two_id_string_cb(void *r) {
    generic_two_id_string_t *rec = (generic_two_id_string_t *)r;

    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static void
post_update_generic_two_id_string_template_cb(generic_two_id_string_t *data, unsigned data_num, GHashTable *ht) {
    unsigned   i;
    int    *key = NULL;
    unsigned   tmp;
    unsigned   tmp2;

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int);
        tmp = (data[i].id & 0xffff) << 16;
        tmp2 = (data[i].id2 & 0xffff);

        /* the hash table does not know about uint32, so we use int32 */
        *key = (int)(tmp + tmp2);

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}

char *
someip_lookup_service_name(uint16_t serviceid) {
    uint32_t tmp = (uint32_t)serviceid;

    if (data_someip_services == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(data_someip_services, &tmp);
}

static char *
someip_lookup_method_name(uint16_t serviceid, uint16_t methodid) {
    uint32_t tmp = (serviceid << 16) + methodid;

    if (data_someip_methods == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(data_someip_methods, &tmp);
}

char *
someip_lookup_eventgroup_name(uint16_t serviceid, uint16_t eventgroupid) {
    uint32_t tmp = (serviceid << 16) + eventgroupid;

    if (data_someip_eventgroups == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(data_someip_eventgroups, &tmp);
}

static char *
someip_lookup_client_name(uint16_t serviceid, uint16_t clientid) {
    uint32_t tmp = (serviceid << 16) + clientid;

    if (data_someip_clients == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(data_someip_clients, &tmp);
}


/*** SOME/IP Services ***/
UAT_HEX_CB_DEF        (someip_service_ident, id,    generic_one_id_string_t)
UAT_CSTRING_CB_DEF    (someip_service_ident, name,  generic_one_id_string_t)

static void
reset_someip_service_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_services) {
        g_hash_table_destroy(data_someip_services);
        data_someip_services = NULL;
    }
}

static void
post_update_someip_service_cb(void) {
    reset_someip_service_cb();

    /* create new hash table */
    data_someip_services = g_hash_table_new_full(g_int_hash, g_int_equal, &someip_free_key, &simple_free);
    post_update_one_id_string_template_cb(someip_service_ident, someip_service_ident_num, data_someip_services);
}


/*** SOME/IP Methods/Events/Fields ***/
UAT_HEX_CB_DEF      (someip_method_ident, id,   generic_two_id_string_t)
UAT_HEX_CB_DEF      (someip_method_ident, id2,  generic_two_id_string_t)
UAT_CSTRING_CB_DEF  (someip_method_ident, name, generic_two_id_string_t)

static void
reset_someip_method_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_methods) {
        g_hash_table_destroy(data_someip_methods);
        data_someip_methods = NULL;
    }
}

static void
post_update_someip_method_cb(void) {
    reset_someip_method_cb();

    /* create new hash table */
    data_someip_methods = g_hash_table_new_full(g_int_hash, g_int_equal, &someip_free_key, &simple_free);
    post_update_generic_two_id_string_template_cb(someip_method_ident, someip_method_ident_num, data_someip_methods);
}


/*** SOME/IP Eventgroups ***/
UAT_HEX_CB_DEF      (someip_eventgroup_ident, id,   generic_two_id_string_t)
UAT_HEX_CB_DEF      (someip_eventgroup_ident, id2,  generic_two_id_string_t)
UAT_CSTRING_CB_DEF  (someip_eventgroup_ident, name, generic_two_id_string_t)

static void
reset_someip_eventgroup_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_eventgroups) {
        g_hash_table_destroy(data_someip_eventgroups);
        data_someip_eventgroups = NULL;
    }
}

static void
post_update_someip_eventgroup_cb(void) {
    reset_someip_eventgroup_cb();

    /* create new hash table */
    data_someip_eventgroups = g_hash_table_new_full(g_int_hash, g_int_equal, &someip_free_key, &simple_free);
    post_update_generic_two_id_string_template_cb(someip_eventgroup_ident, someip_eventgroup_ident_num, data_someip_eventgroups);
}


/*** SOME/IP Clients ***/
UAT_HEX_CB_DEF(someip_client_ident, id, generic_two_id_string_t)
UAT_HEX_CB_DEF(someip_client_ident, id2, generic_two_id_string_t)
UAT_CSTRING_CB_DEF(someip_client_ident, name, generic_two_id_string_t)

static void
reset_someip_client_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_clients) {
        g_hash_table_destroy(data_someip_clients);
        data_someip_clients = NULL;
    }
}

static void
post_update_someip_client_cb(void) {
    reset_someip_client_cb();

    /* create new hash table */
    data_someip_clients = g_hash_table_new_full(g_int_hash, g_int_equal, &someip_free_key, &simple_free);
    post_update_generic_two_id_string_template_cb(someip_client_ident, someip_client_ident_num, data_someip_clients);
}

static void
someip_payload_free_key(void *key) {
    wmem_free(wmem_epan_scope(), key);
}

static int64_t
someip_parameter_key(uint16_t serviceid, uint16_t methodid, uint8_t version, uint8_t msgtype) {
    int64_t tmp1;
    int64_t tmp2;
    int64_t tmp3;
    int64_t tmp4;

    /* key:
        Service-ID [16bit] | Method-ID [16bit] | Version [8bit] | Message-Type [8bit]
    */

    tmp1 = (int64_t)(serviceid & 0xffff);
    tmp2 = (int64_t)(methodid & 0xffff) << 16;
    tmp3 = (int64_t)(version & 0xff) << 32;
    tmp4 = (int64_t)(msgtype & 0xff) << 40;

    return (int64_t)(tmp1 + tmp2 + tmp3 + tmp4);
}

static someip_parameter_list_t*
get_parameter_config(uint16_t serviceid, uint16_t methodid, uint8_t version, uint8_t msgtype) {
    int64_t                 *key = NULL;
    someip_parameter_list_t *tmp = NULL;

    if (data_someip_parameter_list == NULL) {
        return NULL;
    }

    key = wmem_new(wmem_epan_scope(), int64_t);
    *key = someip_parameter_key(serviceid, methodid, version, msgtype);
    tmp = (someip_parameter_list_t *)g_hash_table_lookup(data_someip_parameter_list, key);
    wmem_free(wmem_epan_scope(), key);

    return tmp;
}

static void *
get_generic_config(GHashTable *ht, int64_t id) {
    if (ht == NULL) {
        return NULL;
    }

    return (void *)g_hash_table_lookup(ht, &id);
}

static someip_payload_parameter_base_type_list_t*
get_base_type_config(uint32_t id) {
    return (someip_payload_parameter_base_type_list_t *)get_generic_config(data_someip_parameter_base_type_list, (int64_t)id);
}

static someip_payload_parameter_string_t*
get_string_config(uint32_t id) {
    return (someip_payload_parameter_string_t *)get_generic_config(data_someip_parameter_strings, (int64_t)id);
}

static someip_payload_parameter_typedef_t*
get_typedef_config(uint32_t id) {
    return (someip_payload_parameter_typedef_t *)get_generic_config(data_someip_parameter_typedefs, (int64_t)id);
}

static someip_parameter_array_t*
get_array_config(uint32_t id) {
    return (someip_parameter_array_t *)get_generic_config(data_someip_parameter_arrays, (int64_t)id);
}

static someip_payload_parameter_struct_t*
get_struct_config(uint32_t id) {
    return (someip_payload_parameter_struct_t *)get_generic_config(data_someip_parameter_structs, (int64_t)id);
}

static someip_parameter_union_t*
get_union_config(uint32_t id) {
    return (someip_parameter_union_t *)get_generic_config(data_someip_parameter_unions, (int64_t)id);
}

static someip_payload_parameter_enum_t*
get_enum_config(uint32_t id) {
    return (someip_payload_parameter_enum_t *)get_generic_config(data_someip_parameter_enums, (int64_t)id);
}

UAT_HEX_CB_DEF(someip_parameter_list, service_id, someip_parameter_list_uat_t)
UAT_HEX_CB_DEF(someip_parameter_list, method_id, someip_parameter_list_uat_t)
UAT_DEC_CB_DEF(someip_parameter_list, version, someip_parameter_list_uat_t)
UAT_HEX_CB_DEF(someip_parameter_list, message_type, someip_parameter_list_uat_t)
UAT_BOOL_CB_DEF(someip_parameter_list, wtlv_encoding, someip_parameter_list_uat_t)

UAT_DEC_CB_DEF(someip_parameter_list, num_of_params, someip_parameter_list_uat_t)

UAT_DEC_CB_DEF(someip_parameter_list, pos, someip_parameter_list_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_list, name, someip_parameter_list_uat_t)
UAT_DEC_CB_DEF(someip_parameter_list, data_type, someip_parameter_list_uat_t)
UAT_HEX_CB_DEF(someip_parameter_list, id_ref, someip_parameter_list_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_list, filter_string, someip_parameter_list_uat_t)

static void *
copy_someip_parameter_list_cb(void *n, const void *o, size_t size _U_) {
    someip_parameter_list_uat_t        *new_rec = (someip_parameter_list_uat_t *)n;
    const someip_parameter_list_uat_t  *old_rec = (const someip_parameter_list_uat_t *)o;

    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }

    if (old_rec->filter_string) {
        new_rec->filter_string = g_strdup(old_rec->filter_string);
    } else {
        new_rec->filter_string = NULL;
    }

    new_rec->service_id    = old_rec->service_id;
    new_rec->method_id     = old_rec->method_id;
    new_rec->version       = old_rec->version;
    new_rec->message_type  = old_rec->message_type;
    new_rec->wtlv_encoding = old_rec->wtlv_encoding;
    new_rec->num_of_params = old_rec->num_of_params;
    new_rec->pos           = old_rec->pos;
    new_rec->data_type     = old_rec->data_type;
    new_rec->id_ref        = old_rec->id_ref;

    return new_rec;
}

static bool
update_someip_parameter_list(void *r, char **err) {
    someip_parameter_list_uat_t *rec = (someip_parameter_list_uat_t *)r;
    unsigned char c;

    if (rec->service_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit Service IDs (Service-ID: %i  Name: %s)", rec->service_id, rec->name);
        return false;
    }

    if (rec->method_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit Method IDs (Service-ID: %i  Method-ID: %i  Name: %s)", rec->service_id, rec->method_id, rec->name);
        return false;
    }

    if (rec->version > 0xff) {
        *err = ws_strdup_printf("We currently only support 8 bit Version (Service-ID: %i  Method-ID: %i  Version: %d  Name: %s)", rec->service_id, rec->method_id, rec->version, rec->name);
        return false;
    }

    if (rec->message_type > 0xff) {
        *err = ws_strdup_printf("We currently only support 8 bit Message Type (Service-ID: %i  Method-ID: %i  Version: %d  Message Type: %x  Name: %s)", rec->service_id, rec->method_id, rec->version, rec->message_type, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty");
        return false;
    }

    if (rec->pos >= rec->num_of_params) {
        *err = ws_strdup_printf("Position >= Number of Parameters");
        return false;
    }

    if (rec->filter_string == NULL || rec->filter_string[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty");
        return false;
    }

    c = proto_check_field_name(rec->filter_string);
    if (c) {
        if (c == '.') {
            *err = ws_strdup_printf("Filter String contains illegal chars '.' (Service-ID: %i  Method-ID: %i)", rec->service_id, rec->method_id);
        } else if (g_ascii_isprint(c)) {
            *err = ws_strdup_printf("Filter String contains illegal chars '%c' (Service-ID: %i  Method-ID: %i)", c, rec->service_id, rec->method_id);
        } else {
            *err = ws_strdup_printf("Filter String contains invalid byte \\%03o (Service-ID: %i  Method-ID: %i)", c, rec->service_id, rec->method_id);
        }
        return false;
    }

    return true;
}

static void
free_someip_parameter_list_cb(void *r) {
    someip_parameter_list_uat_t *rec = (someip_parameter_list_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }

    if (rec->filter_string) {
        g_free(rec->filter_string);
        rec->filter_string = NULL;
    }
}

static void
free_someip_parameter_list(void *data) {
    someip_parameter_list_t *list = (someip_parameter_list_t *)data;

    if (list->items != NULL) {
        wmem_free(wmem_epan_scope(), (void *)(list->items));
        list->items = NULL;
    }

    wmem_free(wmem_epan_scope(), (void *)data);
}

static void
post_update_someip_parameter_list_read_in_data(someip_parameter_list_uat_t *data, unsigned data_num, GHashTable *ht) {
    unsigned                            i = 0;
    int64_t                            *key = NULL;
    someip_parameter_list_t            *list = NULL;
    someip_payload_parameter_item_t    *item = NULL;
    someip_payload_parameter_item_t    *items = NULL;

    if (ht == NULL || data == NULL || data_num == 0) {
        return;
    }

    for (i = 0; i < data_num; i++) {
        /* the hash table does not know about uint64, so we use int64*/
        key = wmem_new(wmem_epan_scope(), int64_t);
        *key = someip_parameter_key((uint16_t)data[i].service_id, (uint16_t)data[i].method_id, (uint8_t)data[i].version, (uint8_t)data[i].message_type);

        list = (someip_parameter_list_t *)g_hash_table_lookup(ht, key);
        if (list == NULL) {

            list = wmem_new(wmem_epan_scope(), someip_parameter_list_t);

            list->service_id    = data[i].service_id;
            list->method_id     = data[i].method_id;
            list->version       = data[i].version;
            list->message_type  = data[i].message_type;
            list->wtlv_encoding = data[i].wtlv_encoding;
            list->num_of_items  = data[i].num_of_params;

            items = (someip_payload_parameter_item_t *)wmem_alloc0_array(wmem_epan_scope(), someip_payload_parameter_item_t, data[i].num_of_params);
            list->items = items;

            /* create new entry ... */
            g_hash_table_insert(ht, key, list);
        } else {
            /* already present, deleting key */
            wmem_free(wmem_epan_scope(), key);
        }

        /* and now we add to item array */
        if (data[i].num_of_params == list->num_of_items && data[i].pos < list->num_of_items) {
            item = &(list->items[data[i].pos]);

            /* we do not care if we overwrite param */
            item->name          = data[i].name;
            item->id_ref        = data[i].id_ref;
            item->pos           = data[i].pos;
            item->data_type     = data[i].data_type;
            item->filter_string = data[i].filter_string;
        }
    }
}

static void
reset_someip_parameter_list_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_parameter_list) {
        deregister_dynamic_hf_data(&dynamic_hf_param, &dynamic_hf_param_size);
        g_hash_table_destroy(data_someip_parameter_list);
        data_someip_parameter_list = NULL;
    }

    set_prefs_changed();
}

static void
post_update_someip_parameter_list_cb(void) {
    reset_someip_parameter_list_cb();

    data_someip_parameter_list = g_hash_table_new_full(g_int64_hash, g_int64_equal, &someip_payload_free_key, &free_someip_parameter_list);
    post_update_someip_parameter_list_read_in_data(someip_parameter_list, someip_parameter_list_num, data_someip_parameter_list);
}

UAT_HEX_CB_DEF(someip_parameter_enums, id, someip_parameter_enum_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_enums, name, someip_parameter_enum_uat_t)
UAT_DEC_CB_DEF(someip_parameter_enums, data_type, someip_parameter_enum_uat_t)
UAT_HEX_CB_DEF(someip_parameter_enums, id_ref, someip_parameter_enum_uat_t)
UAT_DEC_CB_DEF(someip_parameter_enums, num_of_items, someip_parameter_enum_uat_t)

UAT_HEX_CB_DEF(someip_parameter_enums, value, someip_parameter_enum_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_enums, value_name, someip_parameter_enum_uat_t)

static void *
copy_someip_parameter_enum_cb(void *n, const void *o, size_t size _U_) {
    someip_parameter_enum_uat_t        *new_rec = (someip_parameter_enum_uat_t *)n;
    const someip_parameter_enum_uat_t  *old_rec = (const someip_parameter_enum_uat_t *)o;

    new_rec->id = old_rec->id;
    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }
    new_rec->data_type    = old_rec->data_type;
    new_rec->id_ref       = old_rec->id_ref;
    new_rec->num_of_items = old_rec->num_of_items;

    new_rec->value = old_rec->value;
    if (old_rec->value_name) {
        new_rec->value_name = g_strdup(old_rec->value_name);
    } else {
        new_rec->value_name = NULL;
    }

    return new_rec;
}

static bool
update_someip_parameter_enum(void *r, char **err) {
    someip_parameter_enum_uat_t *rec = (someip_parameter_enum_uat_t *)r;

    /* enum name is not used in a filter yet. */

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->value_name == NULL || rec->value_name[0] == 0) {
        *err = ws_strdup_printf("Value Name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->num_of_items == 0) {
        *err = ws_strdup_printf("Number_of_Items = 0 (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ENUM) {
        *err = ws_strdup_printf("An enum cannot reference an enum (ID: 0x%x)!", rec->id);
        return false;
    }

    return true;
}

static void
free_someip_parameter_enum_cb(void *r) {
    someip_parameter_enum_uat_t *rec = (someip_parameter_enum_uat_t *)r;
    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }

    if (rec->value_name) {
        g_free(rec->value_name);
        rec->value_name = NULL;
    }
}

static void
free_someip_parameter_enum(void *data) {
    someip_payload_parameter_enum_t *list = (someip_payload_parameter_enum_t *)data;

    if (list->items != NULL) {
        wmem_free(wmem_epan_scope(), (void *)(list->items));
        list->items = NULL;
    }

    wmem_free(wmem_epan_scope(), (void *)data);
}

static void
post_update_someip_parameter_enum_read_in_data(someip_parameter_enum_uat_t *data, unsigned data_num, GHashTable *ht) {
    unsigned                                i = 0;
    unsigned                                j = 0;
    int64_t                                *key = NULL;
    someip_payload_parameter_enum_t        *list = NULL;
    someip_payload_parameter_enum_item_t   *item = NULL;

    if (ht == NULL || data == NULL || data_num == 0) {
        return;
    }

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int64_t);
        *key = data[i].id;

        list = (someip_payload_parameter_enum_t *)g_hash_table_lookup(ht, key);
        if (list == NULL) {

            list = wmem_new(wmem_epan_scope(), someip_payload_parameter_enum_t);
            INIT_SOMEIP_PAYLOAD_PARAMETER_ENUM(list)

            list->id           = data[i].id;
            list->name         = data[i].name;
            list->data_type    = data[i].data_type;
            list->id_ref       = data[i].id_ref;
            list->num_of_items = data[i].num_of_items;

            list->items = (someip_payload_parameter_enum_item_t *)wmem_alloc0_array(wmem_epan_scope(), someip_payload_parameter_enum_item_t, list->num_of_items);

            /* create new entry ... */
            g_hash_table_insert(ht, key, list);
        } else {
            /* don't need it anymore */
            wmem_free(wmem_epan_scope(), key);
        }

        /* and now we add to item array */
        if (list->num_of_items > 0 && data[i].num_of_items == list->num_of_items) {

            /* find first empty slot */
            for (j = 0; j < list->num_of_items && list->items[j].name != NULL; j++);

            if (j < list->num_of_items) {
                item = &(list->items[j]);
                INIT_SOMEIP_PAYLOAD_PARAMETER_ENUM_ITEM(item)

                /* we do not care if we overwrite param */
                item->value = data[i].value;
                item->name  = data[i].value_name;
            }
        }
    }
}

static void
reset_someip_parameter_enum_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_parameter_enums) {
        g_hash_table_destroy(data_someip_parameter_enums);
        data_someip_parameter_enums = NULL;
    }

    set_prefs_changed();
}

static void
post_update_someip_parameter_enum_cb(void) {
    reset_someip_parameter_enum_cb();

    data_someip_parameter_enums = g_hash_table_new_full(g_int64_hash, g_int64_equal, &someip_payload_free_key, &free_someip_parameter_enum);
    post_update_someip_parameter_enum_read_in_data(someip_parameter_enums, someip_parameter_enums_num, data_someip_parameter_enums);
}

UAT_HEX_CB_DEF(someip_parameter_arrays, id, someip_parameter_array_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_arrays, name, someip_parameter_array_uat_t)
UAT_DEC_CB_DEF(someip_parameter_arrays, data_type, someip_parameter_array_uat_t)
UAT_HEX_CB_DEF(someip_parameter_arrays, id_ref, someip_parameter_array_uat_t)
UAT_DEC_CB_DEF(someip_parameter_arrays, num_of_dims, someip_parameter_array_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_arrays, filter_string, someip_parameter_array_uat_t)

UAT_DEC_CB_DEF(someip_parameter_arrays, num, someip_parameter_array_uat_t)
UAT_DEC_CB_DEF(someip_parameter_arrays, lower_limit, someip_parameter_array_uat_t)
UAT_DEC_CB_DEF(someip_parameter_arrays, upper_limit, someip_parameter_array_uat_t)
UAT_DEC_CB_DEF(someip_parameter_arrays, length_of_length, someip_parameter_array_uat_t)
UAT_DEC_CB_DEF(someip_parameter_arrays, pad_to, someip_parameter_array_uat_t)

static void *
copy_someip_parameter_array_cb(void *n, const void *o, size_t size _U_) {
    someip_parameter_array_uat_t       *new_rec = (someip_parameter_array_uat_t *)n;
    const someip_parameter_array_uat_t *old_rec = (const someip_parameter_array_uat_t *)o;

    new_rec->id = old_rec->id;
    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }
    new_rec->data_type = old_rec->data_type;
    new_rec->id_ref = old_rec->id_ref;
    new_rec->num_of_dims = old_rec->num_of_dims;
    if (old_rec->filter_string) {
        new_rec->filter_string = g_strdup(old_rec->filter_string);
    } else {
        new_rec->filter_string = NULL;
    }

    new_rec->num              = old_rec->num;
    new_rec->lower_limit      = old_rec->lower_limit;
    new_rec->upper_limit      = old_rec->upper_limit;
    new_rec->length_of_length = old_rec->length_of_length;
    new_rec->pad_to           = old_rec->pad_to;

    return new_rec;
}

static bool
update_someip_parameter_array(void *r, char **err) {
    someip_parameter_array_uat_t *rec = (someip_parameter_array_uat_t *)r;
    char                         *tmp;

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->num >= rec->num_of_dims) {
        *err = ws_strdup_printf("Dimension >= Number of Dimensions (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->filter_string == NULL || rec->filter_string[0] == 0) {
        *err = ws_strdup_printf("Filter String cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    tmp = check_filter_string(rec->filter_string, rec->id);
    if (tmp != NULL) {
        *err = tmp;
        return false;
    }

    if (rec->data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ARRAY && rec->id == rec->id_ref) {
        *err = ws_strdup_printf("An array cannot include itself (ID: 0x%x)!", rec->id);
        return false;
    }

    return true;
}

static void
free_someip_parameter_array_cb(void *r) {
    someip_parameter_array_uat_t *rec = (someip_parameter_array_uat_t *)r;

    if (rec->name) g_free(rec->name);
    rec->name = NULL;

    if (rec->filter_string) g_free(rec->filter_string);
    rec->filter_string = NULL;
}

static void
free_someip_parameter_array(void *data) {
    someip_parameter_array_t *list = (someip_parameter_array_t *)data;

    if (list->dims != NULL) {
        wmem_free(wmem_epan_scope(), (void *)(list->dims));
        list->dims = NULL;
    }

    wmem_free(wmem_epan_scope(), (void *)data);
}

static void
post_update_someip_parameter_array_read_in_data(someip_parameter_array_uat_t *data, unsigned data_num, GHashTable *ht) {
    unsigned                         i = 0;
    int64_t                         *key = NULL;
    someip_parameter_array_t        *list = NULL;
    someip_parameter_array_dim_t    *item = NULL;
    someip_parameter_array_dim_t    *items = NULL;

    if (ht == NULL || data == NULL || data_num == 0) {
        return;
    }

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int64_t);
        *key = data[i].id;

        list = (someip_parameter_array_t *)g_hash_table_lookup(ht, key);
        if (list == NULL) {

            list = wmem_new(wmem_epan_scope(), someip_parameter_array_t);

            list->id            = data[i].id;
            list->name          = data[i].name;
            list->data_type     = data[i].data_type;
            list->id_ref        = data[i].id_ref;
            list->num_of_dims   = data[i].num_of_dims;
            list->filter_string = data[i].filter_string;

            items = (someip_parameter_array_dim_t *)wmem_alloc0_array(wmem_epan_scope(), someip_parameter_array_dim_t, data[i].num_of_dims);
            list->dims = items;

            /* create new entry ... */
            g_hash_table_insert(ht, key, list);
        }

        /* and now we add to item array */
        if (data[i].num_of_dims == list->num_of_dims && data[i].num < list->num_of_dims) {
            item = &(list->dims[data[i].num]);

            /* we do not care if we overwrite param */
            item->num              = data[i].num;
            item->lower_limit      = data[i].lower_limit;
            item->upper_limit      = data[i].upper_limit;
            item->length_of_length = data[i].length_of_length;
            item->pad_to           = data[i].pad_to;
        }
    }
}

static void
reset_someip_parameter_array_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_parameter_arrays) {
        deregister_dynamic_hf_data(&dynamic_hf_array, &dynamic_hf_array_size);
        g_hash_table_destroy(data_someip_parameter_arrays);
        data_someip_parameter_arrays = NULL;
    }

    set_prefs_changed();
}

static void
post_update_someip_parameter_array_cb(void) {
    reset_someip_parameter_array_cb();

    data_someip_parameter_arrays = g_hash_table_new_full(g_int64_hash, g_int64_equal, &someip_payload_free_key, &free_someip_parameter_array);
    post_update_someip_parameter_array_read_in_data(someip_parameter_arrays, someip_parameter_arrays_num, data_someip_parameter_arrays);
}

UAT_HEX_CB_DEF(someip_parameter_structs, id, someip_parameter_struct_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_structs, struct_name, someip_parameter_struct_uat_t)
UAT_DEC_CB_DEF(someip_parameter_structs, length_of_length, someip_parameter_struct_uat_t)
UAT_DEC_CB_DEF(someip_parameter_structs, pad_to, someip_parameter_struct_uat_t)
UAT_BOOL_CB_DEF(someip_parameter_structs, wtlv_encoding, someip_parameter_struct_uat_t)
UAT_DEC_CB_DEF(someip_parameter_structs, num_of_items, someip_parameter_struct_uat_t)

UAT_DEC_CB_DEF(someip_parameter_structs, pos, someip_parameter_struct_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_structs, name, someip_parameter_struct_uat_t)
UAT_DEC_CB_DEF(someip_parameter_structs, data_type, someip_parameter_struct_uat_t)
UAT_HEX_CB_DEF(someip_parameter_structs, id_ref, someip_parameter_struct_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_structs, filter_string, someip_parameter_struct_uat_t)

static void *
copy_someip_parameter_struct_cb(void *n, const void *o, size_t size _U_) {
    someip_parameter_struct_uat_t       *new_rec = (someip_parameter_struct_uat_t *)n;
    const someip_parameter_struct_uat_t *old_rec = (const someip_parameter_struct_uat_t *)o;

    new_rec->id = old_rec->id;

    if (old_rec->struct_name) {
        new_rec->struct_name = g_strdup(old_rec->struct_name);
    } else {
        new_rec->struct_name = NULL;
    }

    new_rec->length_of_length = old_rec->length_of_length;
    new_rec->pad_to           = old_rec->pad_to;
    new_rec->wtlv_encoding    = old_rec->wtlv_encoding;
    new_rec->num_of_items     = old_rec->num_of_items;

    new_rec->pos = old_rec->pos;

    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }

    new_rec->data_type = old_rec->data_type;
    new_rec->id_ref    = old_rec->id_ref;

    if (old_rec->filter_string) {
        new_rec->filter_string = g_strdup(old_rec->filter_string);
    } else {
        new_rec->filter_string = NULL;
    }

    return new_rec;
}

static bool
update_someip_parameter_struct(void *r, char **err) {
    someip_parameter_struct_uat_t *rec = (someip_parameter_struct_uat_t *)r;
    char                          *tmp = NULL;

    if (rec->struct_name == NULL || rec->struct_name[0] == 0) {
        *err = ws_strdup_printf("Struct name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->filter_string == NULL || rec->filter_string[0] == 0) {
        *err = ws_strdup_printf("Struct name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    tmp = check_filter_string(rec->filter_string, rec->id);
    if (tmp != NULL) {
        *err = tmp;
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->pos >= rec->num_of_items) {
        *err = ws_strdup_printf("Position >= Number of Parameters (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_STRUCT && rec->id == rec->id_ref) {
        *err = ws_strdup_printf("A struct cannot include itself (ID: 0x%x)!", rec->id);
        return false;
    }

    return true;
}

static void
free_someip_parameter_struct_cb(void *r) {
    someip_parameter_struct_uat_t *rec = (someip_parameter_struct_uat_t *)r;

    if (rec->struct_name) g_free(rec->struct_name);
    rec->struct_name = NULL;

    if (rec->name) g_free(rec->name);
    rec->name = NULL;

    if (rec->filter_string) g_free(rec->filter_string);
    rec->filter_string = NULL;
}

static void
free_someip_parameter_struct(void *data) {
    someip_payload_parameter_struct_t *list = (someip_payload_parameter_struct_t *)data;

    if (list->items != NULL) {
        wmem_free(wmem_epan_scope(), (void *)(list->items));
        list->items = NULL;
    }

    wmem_free(wmem_epan_scope(), (void *)data);
}

static void
post_update_someip_parameter_struct_read_in_data(someip_parameter_struct_uat_t *data, unsigned data_num, GHashTable *ht) {
    unsigned                            i = 0;
    int64_t                            *key = NULL;
    someip_payload_parameter_struct_t  *list = NULL;
    someip_payload_parameter_item_t    *item = NULL;
    someip_payload_parameter_item_t    *items = NULL;

    if (ht == NULL || data == NULL || data_num == 0) {
        return;
    }

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int64_t);
        *key = data[i].id;

        list = (someip_payload_parameter_struct_t *)g_hash_table_lookup(ht, key);
        if (list == NULL) {
            list = wmem_new(wmem_epan_scope(), someip_payload_parameter_struct_t);
            INIT_SOMEIP_PAYLOAD_PARAMETER_STRUCT(list)

            list->id               = data[i].id;
            list->struct_name      = data[i].struct_name;
            list->length_of_length = data[i].length_of_length;
            list->pad_to           = data[i].pad_to;
            list->wtlv_encoding    = data[i].wtlv_encoding;
            list->num_of_items     = data[i].num_of_items;

            items = (someip_payload_parameter_item_t *)wmem_alloc0_array(wmem_epan_scope(), someip_payload_parameter_item_t, data[i].num_of_items);
            list->items = items;

            /* create new entry ... */
            g_hash_table_insert(ht, key, list);
        }

        /* and now we add to item array */
        if (data[i].num_of_items == list->num_of_items && data[i].pos < list->num_of_items) {
            item = &(list->items[data[i].pos]);
            INIT_SOMEIP_PAYLOAD_PARAMETER_ITEM(item)

            /* we do not care if we overwrite param */
            item->name          = data[i].name;
            item->id_ref        = data[i].id_ref;
            item->pos           = data[i].pos;
            item->data_type     = data[i].data_type;
            item->filter_string = data[i].filter_string;
        }
    }
}

static void
reset_someip_parameter_struct_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_parameter_structs) {
        deregister_dynamic_hf_data(&dynamic_hf_struct, &dynamic_hf_struct_size);
        g_hash_table_destroy(data_someip_parameter_structs);
        data_someip_parameter_structs = NULL;
    }

    set_prefs_changed();
}

static void
post_update_someip_parameter_struct_cb(void) {
    reset_someip_parameter_struct_cb();

    data_someip_parameter_structs = g_hash_table_new_full(g_int64_hash, g_int64_equal, &someip_payload_free_key, &free_someip_parameter_struct);
    post_update_someip_parameter_struct_read_in_data(someip_parameter_structs, someip_parameter_structs_num, data_someip_parameter_structs);
}

UAT_HEX_CB_DEF(someip_parameter_unions, id, someip_parameter_union_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_unions, name, someip_parameter_union_uat_t)
UAT_DEC_CB_DEF(someip_parameter_unions, length_of_length, someip_parameter_union_uat_t)
UAT_DEC_CB_DEF(someip_parameter_unions, length_of_type, someip_parameter_union_uat_t)
UAT_DEC_CB_DEF(someip_parameter_unions, pad_to, someip_parameter_union_uat_t)

UAT_DEC_CB_DEF(someip_parameter_unions, num_of_items, someip_parameter_union_uat_t)

UAT_DEC_CB_DEF(someip_parameter_unions, type_id, someip_parameter_union_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_unions, type_name, someip_parameter_union_uat_t)
UAT_DEC_CB_DEF(someip_parameter_unions, data_type, someip_parameter_union_uat_t)
UAT_HEX_CB_DEF(someip_parameter_unions, id_ref, someip_parameter_union_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_unions, filter_string, someip_parameter_union_uat_t)

static void *
copy_someip_parameter_union_cb(void *n, const void *o, size_t size _U_) {
    someip_parameter_union_uat_t        *new_rec = (someip_parameter_union_uat_t *)n;
    const someip_parameter_union_uat_t  *old_rec = (const someip_parameter_union_uat_t *)o;

    new_rec->id = old_rec->id;

    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }

    new_rec->length_of_length = old_rec->length_of_length;
    new_rec->length_of_type   = old_rec->length_of_type;
    new_rec->pad_to           = old_rec->pad_to;
    new_rec->num_of_items     = old_rec->num_of_items;
    new_rec->type_id          = old_rec->type_id;

    if (old_rec->type_name) {
        new_rec->type_name = g_strdup(old_rec->type_name);
    } else {
        new_rec->type_name = NULL;
    }

    new_rec->data_type        = old_rec->data_type;
    new_rec->id_ref           = old_rec->id_ref;

    if (old_rec->filter_string) {
        new_rec->filter_string = g_strdup(old_rec->filter_string);
    } else {
        new_rec->filter_string = NULL;
    }

    return new_rec;
}

static bool
update_someip_parameter_union(void *r, char **err) {
    someip_parameter_union_uat_t *rec = (someip_parameter_union_uat_t *)r;
    char                         *tmp;

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Union name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    tmp = check_filter_string(rec->filter_string, rec->id);
    if (tmp != NULL) {
        *err = tmp;
        return false;
    }

    if (rec->type_name == NULL || rec->type_name[0] == 0) {
        *err = ws_strdup_printf("Type Name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_UNION && rec->id == rec->id_ref) {
        *err = ws_strdup_printf("A union cannot include itself (ID: 0x%x)!", rec->id);
        return false;
    }

    return true;
}

static void
free_someip_parameter_union_cb(void *r) {
    someip_parameter_union_uat_t *rec = (someip_parameter_union_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }

    if (rec->type_name) {
        g_free(rec->type_name);
        rec->type_name = NULL;
    }

    if (rec->filter_string) {
        g_free(rec->filter_string);
        rec->filter_string = NULL;
    }
}

static void
free_someip_parameter_union(void *data) {
    someip_parameter_union_t *list = (someip_parameter_union_t *)data;

    if (list->items != NULL) {
        wmem_free(wmem_epan_scope(), (void *)(list->items));
        list->items = NULL;
    }

    wmem_free(wmem_epan_scope(), (void *)data);
}

static void
post_update_someip_parameter_union_read_in_data(someip_parameter_union_uat_t *data, unsigned data_num, GHashTable *ht) {
    unsigned        i = 0;
    unsigned        j = 0;
    int64_t        *key = NULL;
    someip_parameter_union_t       *list = NULL;
    someip_parameter_union_item_t  *item = NULL;

    if (ht == NULL || data == NULL || data_num == 0) {
        return;
    }

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int64_t);
        *key = data[i].id;

        list = (someip_parameter_union_t *)g_hash_table_lookup(ht, key);
        if (list == NULL) {

            list = wmem_new(wmem_epan_scope(), someip_parameter_union_t);

            list->id               = data[i].id;
            list->name             = data[i].name;
            list->length_of_length = data[i].length_of_length;
            list->length_of_type   = data[i].length_of_type;
            list->pad_to           = data[i].pad_to;
            list->num_of_items     = data[i].num_of_items;

            list->items = (someip_parameter_union_item_t *)wmem_alloc0_array(wmem_epan_scope(), someip_parameter_union_item_t, list->num_of_items);

            /* create new entry ... */
            g_hash_table_insert(ht, key, list);
        } else {
            /* don't need it anymore */
            wmem_free(wmem_epan_scope(), key);
        }

        /* and now we add to item array */
        if (data[i].num_of_items == list->num_of_items) {

            /* find first empty slot */
            for (j = 0; j < list->num_of_items && list->items[j].name != NULL; j++);

            if (j < list->num_of_items) {
                item = &(list->items[j]);

                /* we do not care if we overwrite param */
                item->id            = data[i].type_id;
                item->name          = data[i].type_name;
                item->data_type     = data[i].data_type;
                item->id_ref        = data[i].id_ref;
                item->filter_string = data[i].filter_string;
            }
        }
    }
}

static void
reset_someip_parameter_union_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_parameter_unions) {
        deregister_dynamic_hf_data(&dynamic_hf_union, &dynamic_hf_union_size);
        g_hash_table_destroy(data_someip_parameter_unions);
        data_someip_parameter_unions = NULL;
    }

    set_prefs_changed();
}

static void
post_update_someip_parameter_union_cb(void) {
    reset_someip_parameter_union_cb();

    data_someip_parameter_unions = g_hash_table_new_full(g_int64_hash, g_int64_equal, &someip_payload_free_key, &free_someip_parameter_union);
    post_update_someip_parameter_union_read_in_data(someip_parameter_unions, someip_parameter_unions_num, data_someip_parameter_unions);
}

UAT_HEX_CB_DEF(someip_parameter_base_type_list, id, someip_parameter_base_type_list_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_base_type_list, name, someip_parameter_base_type_list_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_base_type_list, data_type, someip_parameter_base_type_list_uat_t)
UAT_BOOL_CB_DEF(someip_parameter_base_type_list, big_endian, someip_parameter_base_type_list_uat_t)
UAT_DEC_CB_DEF(someip_parameter_base_type_list, bitlength_base_type, someip_parameter_base_type_list_uat_t)
UAT_DEC_CB_DEF(someip_parameter_base_type_list, bitlength_encoded_type, someip_parameter_base_type_list_uat_t)

static void *
copy_someip_parameter_base_type_list_cb(void *n, const void *o, size_t size _U_) {
    someip_parameter_base_type_list_uat_t       *new_rec = (someip_parameter_base_type_list_uat_t *)n;
    const someip_parameter_base_type_list_uat_t *old_rec = (const someip_parameter_base_type_list_uat_t *)o;

    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }

    if (old_rec->data_type) {
        new_rec->data_type = g_strdup(old_rec->data_type);
    } else {
        new_rec->data_type = NULL;
    }

    new_rec->id                     = old_rec->id;
    new_rec->big_endian             = old_rec->big_endian;
    new_rec->bitlength_base_type    = old_rec->bitlength_base_type;
    new_rec->bitlength_encoded_type = old_rec->bitlength_encoded_type;

    return new_rec;
}

static bool
update_someip_parameter_base_type_list(void *r, char **err) {
    someip_parameter_base_type_list_uat_t *rec = (someip_parameter_base_type_list_uat_t *)r;

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->id > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit IDs (%i) Name: %s", rec->id, rec->name);
        return false;
    }

    if (rec->bitlength_base_type != 8 && rec->bitlength_base_type != 16 && rec->bitlength_base_type != 32 && rec->bitlength_base_type != 64) {
        *err = ws_strdup_printf("Bit length of base type may only be 8, 16, 32, or 64. Affected item: ID (%i) Name (%s).", rec->id, rec->name);
        return false;
    }

    /* As long as we check that rec->bitlength_base_type equals rec->bitlength_encoded_type, we do not have to check that bitlength_encoded_type is 8, 16, 32, or 64. */

    if (rec->bitlength_base_type != rec->bitlength_encoded_type) {
        *err = ws_strdup_printf("Bit length of encoded type must be equal to bit length of base type. Affected item: ID (%i) Name (%s). Shortened types supported by Signal-PDU dissector.", rec->id, rec->name);
        return false;
    }

    return true;
}

static void
free_someip_parameter_base_type_list_cb(void *r) {
    someip_parameter_base_type_list_uat_t *rec = (someip_parameter_base_type_list_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }

    if (rec->data_type) {
        g_free(rec->data_type);
        rec->data_type = NULL;
    }
}

static void
reset_someip_parameter_base_type_list_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_parameter_base_type_list) {
        g_hash_table_destroy(data_someip_parameter_base_type_list);
        data_someip_parameter_base_type_list = NULL;
    }

    set_prefs_changed();
}

static void
post_update_someip_parameter_base_type_list_cb(void) {
    unsigned   i;
    int64_t *key = NULL;

    reset_someip_parameter_base_type_list_cb();

    /* we don't need to free the data as long as we don't alloc it first */
    data_someip_parameter_base_type_list = g_hash_table_new_full(g_int64_hash, g_int64_equal, &someip_payload_free_key, NULL);

    if (data_someip_parameter_base_type_list == NULL || someip_parameter_base_type_list == NULL || someip_parameter_base_type_list_num == 0) {
        return;
    }

    if (someip_parameter_base_type_list_num > 0) {
        for (i = 0; i < someip_parameter_base_type_list_num; i++) {
            key = wmem_new(wmem_epan_scope(), int64_t);
            *key = someip_parameter_base_type_list[i].id;

            g_hash_table_insert(data_someip_parameter_base_type_list, key, &someip_parameter_base_type_list[i]);
        }
    }
}

UAT_HEX_CB_DEF(someip_parameter_strings, id, someip_parameter_string_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_strings, name, someip_parameter_string_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_strings, encoding, someip_parameter_string_uat_t)
UAT_BOOL_CB_DEF(someip_parameter_strings, dynamic_length, someip_parameter_string_uat_t)
UAT_DEC_CB_DEF(someip_parameter_strings, max_length, someip_parameter_string_uat_t)
UAT_DEC_CB_DEF(someip_parameter_strings, length_of_length, someip_parameter_string_uat_t)
UAT_BOOL_CB_DEF(someip_parameter_strings, big_endian, someip_parameter_string_uat_t)
UAT_DEC_CB_DEF(someip_parameter_strings, pad_to, someip_parameter_string_uat_t)

static void *
copy_someip_parameter_string_list_cb(void *n, const void *o, size_t size _U_) {
    someip_parameter_string_uat_t       *new_rec = (someip_parameter_string_uat_t *)n;
    const someip_parameter_string_uat_t *old_rec = (const someip_parameter_string_uat_t *)o;

    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }

    if (old_rec->encoding) {
        new_rec->encoding = g_strdup(old_rec->encoding);
    } else {
        new_rec->encoding = NULL;
    }

    new_rec->id               = old_rec->id;
    new_rec->dynamic_length   = old_rec->dynamic_length;
    new_rec->max_length       = old_rec->max_length;
    new_rec->length_of_length = old_rec->length_of_length;
    new_rec->big_endian       = old_rec->big_endian;
    new_rec->pad_to           = old_rec->pad_to;

    return new_rec;
}

static bool
update_someip_parameter_string_list(void *r, char **err) {
    someip_parameter_string_uat_t *rec = (someip_parameter_string_uat_t *)r;

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty (ID: 0x%x)!", rec->id);
        return false;
    }

    if (rec->id > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit IDs (%i) Name: %s", rec->id, rec->name);
        return false;
    }

    if (rec->max_length > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit max_length (%i) Name: %s", rec->max_length, rec->name);
        return false;
    }

    if (rec->length_of_length != 0 && rec->length_of_length != 8 && rec->length_of_length != 16 && rec->length_of_length != 32) {
        *err = ws_strdup_printf("length_of_length can be only 0, 8, 16, or 32 but not %d (IDs: %i Name: %s)", rec->length_of_length, rec->id, rec->name);
        return false;
    }

    return true;
}

static void
free_someip_parameter_string_list_cb(void *r) {
    someip_parameter_string_uat_t *rec = (someip_parameter_string_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }

    if (rec->encoding) {
        g_free(rec->encoding);
        rec->encoding = NULL;
    }
}

static void
reset_someip_parameter_string_list_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_parameter_strings) {
        g_hash_table_destroy(data_someip_parameter_strings);
        data_someip_parameter_strings = NULL;
    }

    set_prefs_changed();
}

static void
post_update_someip_parameter_string_list_cb(void) {
    unsigned   i;
    int64_t *key = NULL;

    reset_someip_parameter_string_list_cb();

    /* we don't need to free the data as long as we don't alloc it first */
    data_someip_parameter_strings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &someip_payload_free_key, NULL);

    if (data_someip_parameter_strings == NULL || someip_parameter_strings == NULL || someip_parameter_strings_num == 0) {
        return;
    }

    if (someip_parameter_strings_num > 0) {
        for (i = 0; i < someip_parameter_strings_num; i++) {
            key = wmem_new(wmem_epan_scope(), int64_t);
            *key = someip_parameter_strings[i].id;

            g_hash_table_insert(data_someip_parameter_strings, key, &someip_parameter_strings[i]);
        }
    }
}

UAT_HEX_CB_DEF(someip_parameter_typedefs, id, someip_parameter_typedef_uat_t)
UAT_CSTRING_CB_DEF(someip_parameter_typedefs, name, someip_parameter_typedef_uat_t)
UAT_DEC_CB_DEF(someip_parameter_typedefs, data_type, someip_parameter_typedef_uat_t)
UAT_HEX_CB_DEF(someip_parameter_typedefs, id_ref, someip_parameter_typedef_uat_t)

static void *
copy_someip_parameter_typedef_list_cb(void *n, const void *o, size_t size _U_) {
    someip_parameter_typedef_uat_t         *new_rec = (someip_parameter_typedef_uat_t *)n;
    const someip_parameter_typedef_uat_t   *old_rec = (const someip_parameter_typedef_uat_t *)o;

    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }

    new_rec->id = old_rec->id;
    new_rec->data_type = old_rec->data_type;
    new_rec->id_ref = old_rec->id_ref;

    return new_rec;
}

static bool
update_someip_parameter_typedef_list(void *r, char **err) {
    someip_parameter_typedef_uat_t *rec = (someip_parameter_typedef_uat_t *)r;

    if (rec->id > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit IDs (%i) Name: %s", rec->id, rec->name);
        return false;
    }

    if (rec->data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_TYPEDEF && rec->id == rec->id_ref) {
        *err = ws_strdup_printf("A typedef cannot reference itself (ID: 0x%x)!", rec->id);
        return false;
    }

    return true;
}

static void
free_someip_parameter_typedef_list_cb(void *r) {
    someip_parameter_typedef_uat_t *rec = (someip_parameter_typedef_uat_t *)r;

    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }
}

static void
reset_someip_parameter_typedef_list_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_someip_parameter_typedefs) {
        g_hash_table_destroy(data_someip_parameter_typedefs);
        data_someip_parameter_typedefs = NULL;
    }

    set_prefs_changed();
}

static void
post_update_someip_parameter_typedef_list_cb(void) {
    unsigned   i;
    int64_t *key = NULL;

    reset_someip_parameter_typedef_list_cb();

    /* we don't need to free the data as long as we don't alloc it first */
    data_someip_parameter_typedefs = g_hash_table_new_full(g_int64_hash, g_int64_equal, &someip_payload_free_key, NULL);

    if (data_someip_parameter_typedefs == NULL || someip_parameter_typedefs == NULL || someip_parameter_typedefs_num == 0) {
        return;
    }

    if (someip_parameter_typedefs_num > 0) {
        for (i = 0; i < someip_parameter_typedefs_num; i++) {
            /* key: ID [32bit] */
            key = wmem_new(wmem_epan_scope(), int64_t);
            *key = someip_parameter_typedefs[i].id;
            g_hash_table_insert(data_someip_parameter_typedefs, key, &someip_parameter_typedefs[i]);
        }
    }
}


static void
deregister_dynamic_hf_data(hf_register_info **hf_array, unsigned *hf_size) {
    if (*hf_array) {
        /* Unregister all fields used before */
        for (unsigned i = 0; i < *hf_size; i++) {
            if ((*hf_array)[i].p_id != NULL) {
                proto_deregister_field(proto_someip, *((*hf_array)[i].p_id));
                g_free((*hf_array)[i].p_id);
                (*hf_array)[i].p_id = NULL;
            }
        }
        proto_add_deregistered_data(*hf_array);
        *hf_array = NULL;
        *hf_size = 0;
    }
}

static void
allocate_dynamic_hf_data(hf_register_info **hf_array, unsigned *hf_size, unsigned new_size) {
    *hf_array = g_new0(hf_register_info, new_size);
    *hf_size = new_size;
}

typedef struct _param_return_attibutes_t {
    enum ftenum     type;
    int             display_base;
    char           *base_type_name;
} param_return_attributes_t;

static param_return_attributes_t
get_param_attributes(uint8_t data_type, uint32_t id_ref) {
    int count = 10;

    param_return_attributes_t ret;
    ret.type = FT_NONE;
    ret.display_base = BASE_NONE;
    ret.base_type_name = NULL;

    /* we limit the number of typedef recursion to "count" */
    while (data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_TYPEDEF && count > 0) {
        someip_payload_parameter_typedef_t *tmp = get_typedef_config(id_ref);
        /* this should not be a typedef since we don't support recursion of typedefs */
        if (tmp != NULL) {
            data_type = tmp->data_type;
            id_ref = tmp->id_ref;
        }
        count--;
    }

    if (data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ENUM) {
        someip_payload_parameter_enum_t *tmp = get_enum_config(id_ref);
        /* this can only be a base type ... */
        if (tmp != NULL) {
            data_type = tmp->data_type;
            id_ref = tmp->id_ref;
        }
    }

    if (data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_STRING) {
        someip_payload_parameter_string_t *tmp = get_string_config(id_ref);
        ret.type = FT_STRING;
        ret.display_base = BASE_NONE;
        if (tmp != NULL) {
            ret.base_type_name = tmp->name;
        }
        return ret;
    }

    if (data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_BASE_TYPE) {
        someip_payload_parameter_base_type_list_t *tmp = get_base_type_config(id_ref);

        ret.display_base = BASE_DEC;

        if (tmp != NULL) {
            ret.base_type_name = tmp->name;

            if (g_strcmp0(tmp->data_type, "uint8") == 0) {
                ret.type = FT_UINT8;
            } else if (g_strcmp0(tmp->data_type, "uint16") == 0) {
                ret.type = FT_UINT16;
            } else if (g_strcmp0(tmp->data_type, "uint24") == 0) {
                ret.type = FT_UINT24;
            } else if (g_strcmp0(tmp->data_type, "uint32") == 0) {
                ret.type = FT_UINT32;
            } else if (g_strcmp0(tmp->data_type, "uint40") == 0) {
                ret.type = FT_UINT40;
            } else if (g_strcmp0(tmp->data_type, "uint48") == 0) {
                ret.type = FT_UINT48;
            } else if (g_strcmp0(tmp->data_type, "uint56") == 0) {
                ret.type = FT_UINT56;
            } else if (g_strcmp0(tmp->data_type, "uint64") == 0) {
                ret.type = FT_UINT64;
            } else if (g_strcmp0(tmp->data_type, "int8") == 0) {
                ret.type = FT_INT8;
            } else if (g_strcmp0(tmp->data_type, "int16") == 0) {
                ret.type = FT_INT16;
            } else if (g_strcmp0(tmp->data_type, "int24") == 0) {
                ret.type = FT_INT24;
            } else if (g_strcmp0(tmp->data_type, "int32") == 0) {
                ret.type = FT_INT32;
            } else if (g_strcmp0(tmp->data_type, "int40") == 0) {
                ret.type = FT_INT40;
            } else if (g_strcmp0(tmp->data_type, "int48") == 0) {
                ret.type = FT_INT48;
            } else if (g_strcmp0(tmp->data_type, "int56") == 0) {
                ret.type = FT_INT56;
            } else if (g_strcmp0(tmp->data_type, "int64") == 0) {
                ret.type = FT_INT64;
            } else if (g_strcmp0(tmp->data_type, "float32") == 0) {
                ret.type = FT_FLOAT;
                ret.display_base = BASE_NONE;
            } else if (g_strcmp0(tmp->data_type, "float64") == 0) {
                ret.type = FT_DOUBLE;
                ret.display_base = BASE_NONE;
            } else {
                ret.type = FT_NONE;
            }
        } else {
            ret.type = FT_NONE;
        }
    }

    /* all other types are handled or don't need a type! */
    return ret;
}

static int*
update_dynamic_hf_entry(hf_register_info *hf_array, int pos, uint32_t data_type, unsigned id_ref, char *param_name, char *filter_string) {
    param_return_attributes_t   attribs;
    int                        *hf_id;

    attribs = get_param_attributes(data_type, id_ref);
    if (hf_array == NULL || attribs.type == FT_NONE) {
        return NULL;
    }

    hf_id = g_new(int, 1);
    *hf_id = 0;
    hf_array[pos].p_id = hf_id;

    hf_array[pos].hfinfo.strings = NULL;
    hf_array[pos].hfinfo.bitmask = 0;
    hf_array[pos].hfinfo.blurb   = NULL;

    if (attribs.base_type_name == NULL) {
        hf_array[pos].hfinfo.name = g_strdup(param_name);
    } else {
        hf_array[pos].hfinfo.name = ws_strdup_printf("%s [%s]", param_name, attribs.base_type_name);
    }

    hf_array[pos].hfinfo.abbrev = ws_strdup_printf("%s.%s", SOMEIP_NAME_PREFIX, filter_string);
    hf_array[pos].hfinfo.type = attribs.type;
    hf_array[pos].hfinfo.display = attribs.display_base;

    HFILL_INIT(hf_array[pos]);

    return hf_id;
}

static void
update_dynamic_param_hf_entry(void *key _U_, void *value, void *data) {
    uint32_t                   *pos = (uint32_t *)data;
    someip_parameter_list_t    *list = (someip_parameter_list_t *)value;
    unsigned                    i = 0;

    for (i = 0; i < list->num_of_items ; i++) {
        if (*pos >= dynamic_hf_param_size) {
            return;
        }

        someip_payload_parameter_item_t *item = &(list->items[i]);

        item->hf_id = update_dynamic_hf_entry(dynamic_hf_param, *pos, item->data_type, item->id_ref, item->name, item->filter_string);

        if (item->hf_id != NULL) {
            (*pos)++;
        }
    }
}

static void
update_dynamic_array_hf_entry(void *key _U_, void *value, void *data) {
    uint32_t                   *pos = (uint32_t *)data;
    someip_parameter_array_t   *item = (someip_parameter_array_t *)value;

    if (*pos >= dynamic_hf_array_size) {
        return;
    }

    item->hf_id = update_dynamic_hf_entry(dynamic_hf_array, *pos, item->data_type, item->id_ref, item->name, item->filter_string);

    if (item->hf_id != NULL) {
        (*pos)++;
    }
}

static void
update_dynamic_struct_hf_entry(void *key _U_, void *value, void *data) {
    uint32_t                           *pos = (uint32_t *)data;
    someip_payload_parameter_struct_t  *list = (someip_payload_parameter_struct_t *)value;
    unsigned                            i = 0;

    for (i = 0; i < list->num_of_items; i++) {
        if (*pos >= dynamic_hf_struct_size) {
            return;
        }
        someip_payload_parameter_item_t *item = &(list->items[i]);

        item->hf_id = update_dynamic_hf_entry(dynamic_hf_struct, *pos, item->data_type, item->id_ref, item->name, item->filter_string);

        if (item->hf_id != NULL) {
            (*pos)++;
        }
    }
}

static void
update_dynamic_union_hf_entry(void *key _U_, void *value, void *data) {
    uint32_t                   *pos = (uint32_t *)data;
    someip_parameter_union_t   *list = (someip_parameter_union_t *)value;
    unsigned                    i = 0;

    for (i = 0; i < list->num_of_items; i++) {
        if (*pos >= dynamic_hf_union_size) {
            return;
        }

        someip_parameter_union_item_t *item = &(list->items[i]);

        item->hf_id = update_dynamic_hf_entry(dynamic_hf_union, *pos, item->data_type, item->id_ref, item->name, item->filter_string);

        if (item->hf_id != NULL) {
            (*pos)++;
        }
    }
}

static void
update_dynamic_hf_entries_someip_parameter_list(void) {
    if (data_someip_parameter_list != NULL) {
        deregister_dynamic_hf_data(&dynamic_hf_param, &dynamic_hf_param_size);
        allocate_dynamic_hf_data(&dynamic_hf_param, &dynamic_hf_param_size, someip_parameter_list_num);
        uint32_t pos = 0;
        g_hash_table_foreach(data_someip_parameter_list, update_dynamic_param_hf_entry, &pos);
        proto_register_field_array(proto_someip, dynamic_hf_param, pos);
    }
}

static void
update_dynamic_hf_entries_someip_parameter_arrays(void) {
    if (data_someip_parameter_arrays != NULL) {
        deregister_dynamic_hf_data(&dynamic_hf_array, &dynamic_hf_array_size);
        allocate_dynamic_hf_data(&dynamic_hf_array, &dynamic_hf_array_size, someip_parameter_arrays_num);
        uint32_t pos = 0;
        g_hash_table_foreach(data_someip_parameter_arrays, update_dynamic_array_hf_entry, &pos);
        proto_register_field_array(proto_someip, dynamic_hf_array, pos);
    }
}

static void
update_dynamic_hf_entries_someip_parameter_structs(void) {
    if (data_someip_parameter_structs != NULL) {
        deregister_dynamic_hf_data(&dynamic_hf_struct, &dynamic_hf_struct_size);
        allocate_dynamic_hf_data(&dynamic_hf_struct, &dynamic_hf_struct_size, someip_parameter_structs_num);
        uint32_t pos = 0;
        g_hash_table_foreach(data_someip_parameter_structs, update_dynamic_struct_hf_entry, &pos);
        proto_register_field_array(proto_someip, dynamic_hf_struct, pos);
    }
}

static void
update_dynamic_hf_entries_someip_parameter_unions(void) {
    if (data_someip_parameter_unions != NULL) {
        deregister_dynamic_hf_data(&dynamic_hf_union, &dynamic_hf_union_size);
        allocate_dynamic_hf_data(&dynamic_hf_union, &dynamic_hf_union_size, someip_parameter_unions_num);
        uint32_t pos = 0;
        g_hash_table_foreach(data_someip_parameter_unions, update_dynamic_union_hf_entry, &pos);
        proto_register_field_array(proto_someip, dynamic_hf_union, pos);
    }
}

static void
expert_someip_payload_truncated(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int length) {
    proto_tree_add_expert(tree, pinfo, &ei_someip_payload_truncated, tvb, offset, length);
    col_append_str(pinfo->cinfo, COL_INFO, " [SOME/IP Payload: Truncated payload!]");
}

static void
expert_someip_payload_malformed(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int length) {
    proto_tree_add_expert(tree, pinfo, &ei_someip_payload_malformed, tvb, offset, length);
    col_append_str(pinfo->cinfo, COL_INFO, " [SOME/IP Payload: Malformed payload!]");
}

static void
expert_someip_payload_config_error(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int length, const char *message) {
    proto_tree_add_expert_format(tree, pinfo, &ei_someip_payload_config_error, tvb, offset, length, "SOME/IP Payload: %s", message);
    col_append_str(pinfo->cinfo, COL_INFO, " [SOME/IP Payload: Config Error]");
}

/*******************************************
 **************** Statistics ***************
 *******************************************/

static void
someip_messages_stats_tree_init(stats_tree *st) {
    st_node_ip_src = stats_tree_create_node(st, st_str_ip_src, 0, STAT_DT_INT, true);
    stat_node_set_flags(st, st_str_ip_src, 0, false, ST_FLG_SORT_TOP);
    st_node_ip_dst = stats_tree_create_node(st, st_str_ip_dst, 0, STAT_DT_INT, true);
}

static tap_packet_status
someip_messages_stats_tree_packet(stats_tree *st, packet_info *pinfo, epan_dissect_t *edt _U_, const void *p, tap_flags_t flags _U_) {
    static char tmp_srv_str[128];
    static char tmp_meth_str[128];
    static char tmp_addr_str[128];
    int tmp;

    DISSECTOR_ASSERT(p);
    const someip_messages_tap_t *data = (const someip_messages_tap_t *)p;

    snprintf(tmp_addr_str, sizeof(tmp_addr_str) - 1, "%s (%s)", address_to_str(pinfo->pool, &pinfo->net_src), address_to_name(&pinfo->net_src));
    tick_stat_node(st, st_str_ip_src, 0, false);
    int src_id = tick_stat_node(st, tmp_addr_str, st_node_ip_src, true);

    snprintf(tmp_addr_str, sizeof(tmp_addr_str) - 1, "%s (%s)", address_to_str(pinfo->pool, &pinfo->net_dst), address_to_name(&pinfo->net_dst));
    tick_stat_node(st, st_str_ip_dst, 0, false);
    int dst_id = tick_stat_node(st, tmp_addr_str, st_node_ip_dst, true);

    char *service_name = someip_lookup_service_name(data->service_id);
    if (service_name == NULL) {
        snprintf(tmp_srv_str, sizeof(tmp_srv_str) - 1, "Service 0x%04x", data->service_id);
    } else {
        snprintf(tmp_srv_str, sizeof(tmp_srv_str) - 1, "Service 0x%04x (%s)", data->service_id, service_name);
    }

    char *method_name = someip_lookup_method_name(data->service_id, data->method_id);
    if (method_name == NULL) {
        snprintf(tmp_meth_str, sizeof(tmp_meth_str) - 1, "Method 0x%04x %s", data->method_id,
            val_to_str(data->message_type, someip_msg_type, "Message-Type: 0x%02x"));
    } else {
        snprintf(tmp_meth_str, sizeof(tmp_meth_str) - 1, "Method 0x%04x (%s) %s", data->method_id, method_name,
            val_to_str(data->message_type, someip_msg_type, "Message-Type: 0x%02x"));
    }

    tmp = tick_stat_node(st, tmp_srv_str, src_id, true);
    tick_stat_node(st, tmp_meth_str, tmp, false);
    tmp = tick_stat_node(st, tmp_srv_str, dst_id, true);
    tick_stat_node(st, tmp_meth_str, tmp, false);

    return TAP_PACKET_REDRAW;
}

/*******************************************
 ******** SOME/IP Payload Dissector ********
 *******************************************/

static int
dissect_someip_payload_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t data_type, uint32_t idref, char *name, int *hf_id_ptr, int wtlv_offset);

static int
dissect_someip_payload_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, someip_payload_parameter_item_t *items, uint32_t num_of_items, bool wtlv);

/* add a flexible size length field, -1 for error*/
static int64_t
dissect_someip_payload_length_field(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, int offset, int length_of_length_field) {
    proto_item *ti;
    uint32_t    tmp = 0;

    switch (length_of_length_field) {
    case 8:
        ti = proto_tree_add_item_ret_uint(subtree, hf_payload_length_field_8bit, tvb, offset, length_of_length_field / 8, ENC_NA, &tmp);
        proto_item_set_hidden(ti);
        break;
    case 16:
        ti = proto_tree_add_item_ret_uint(subtree, hf_payload_length_field_16bit, tvb, offset, length_of_length_field / 8, ENC_BIG_ENDIAN, &tmp);
        proto_item_set_hidden(ti);
        break;
    case 32:
        ti = proto_tree_add_item_ret_uint(subtree, hf_payload_length_field_32bit, tvb, offset, length_of_length_field / 8, ENC_BIG_ENDIAN, &tmp);
        proto_item_set_hidden(ti);
        break;
    default:
        proto_tree_add_expert_format(subtree, pinfo, &ei_someip_payload_config_error, tvb, offset, 0,
            "SOME/IP: Payload: length of length field does not make sense: %d bits", length_of_length_field);
        col_append_str(pinfo->cinfo, COL_INFO, " [SOME/IP: Payload Config Error]");
        return -1;
    }

    return (int64_t)tmp;
}

/* add a flexible size type field */
static int64_t
dissect_someip_payload_type_field(tvbuff_t *tvb, packet_info *pinfo, proto_tree *subtree, int offset, int length_of_type_field) {
    proto_item *ti;
    uint32_t    tmp = 0;

    switch (length_of_type_field) {
    case 8:
        ti = proto_tree_add_item_ret_uint(subtree, hf_payload_type_field_8bit, tvb, offset, length_of_type_field / 8, ENC_NA, &tmp);
        proto_item_set_hidden(ti);
        break;
    case 16:
        ti = proto_tree_add_item_ret_uint(subtree, hf_payload_type_field_16bit, tvb, offset, length_of_type_field / 8, ENC_BIG_ENDIAN, &tmp);
        proto_item_set_hidden(ti);
        break;
    case 32:
        ti = proto_tree_add_item_ret_uint(subtree, hf_payload_type_field_32bit, tvb, offset, length_of_type_field / 8, ENC_BIG_ENDIAN, &tmp);
        proto_item_set_hidden(ti);
        break;
    default:
        proto_tree_add_expert_format(subtree, pinfo, &ei_someip_payload_config_error, tvb, offset, 0,
            "SOME/IP: Payload: length of type field does not make sense: %d bits", length_of_type_field);
        col_append_str(pinfo->cinfo, COL_INFO, " [SOME/IP: Payload Config Error]");
        return -1;
    }

    return (int64_t)tmp;
}

static uint32_t
dissect_someip_payload_add_wtlv_if_needed(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_item *ti_root, proto_tree *parent_tree) {
    static int * const tag_bitfield[] = {
        &hf_payload_wtlv_tag_res,
        &hf_payload_wtlv_tag_wire_type,
        &hf_payload_wtlv_tag_data_id,
        NULL
    };

    if (offset < 0) {
        return 0;
    }

    proto_tree *tree = parent_tree;
    if (tree == NULL) {
        tree = proto_item_add_subtree(ti_root, ett_someip_parameter);
    }

    uint64_t tagdata = 0;
    proto_item *ti = proto_tree_add_bitmask_ret_uint64(tree, tvb, offset, hf_payload_wtlv_tag, ett_someip_wtlv_tag, tag_bitfield, ENC_BIG_ENDIAN, &tagdata);
    proto_item_set_hidden(ti);

    unsigned wiretype = (unsigned)((tagdata & SOMEIP_WTLV_MASK_WIRE_TYPE) >> 12);

    switch (wiretype) {
    case 5:
        return 8;
    case 6:
        return 16;
    case 7:
        return 32;
    default:
        return 0;
    }
}

static int
dissect_someip_payload_base_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset, uint8_t data_type, uint32_t id, char *name, int *hf_id_ptr, int wtlv_offset) {
    someip_payload_parameter_base_type_list_t  *base_type = NULL;
    someip_payload_parameter_enum_t            *enum_config = NULL;

    uint32_t    basetype_id = 0;
    uint32_t    enum_id = 0;

    int         param_length = -1;

    proto_item *ti = NULL;

    uint64_t    value = 0;
    uint32_t    value32 = 0;
    bool        value_set = false;

    uint32_t    i = 0;
    char       *value_name = NULL;

    bool        big_endian = true;

    int         hf_id = 0;

    if (hf_id_ptr != NULL) {
        hf_id = *hf_id_ptr;
    }

    switch (data_type) {
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_BASE_TYPE:
        basetype_id = id;
        break;
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ENUM:
        enum_id = id;
        enum_config = get_enum_config(enum_id);
        if (enum_config == NULL) {
            return 0;
        }
        basetype_id = enum_config->id_ref;
        break;
    default:
        return 0;
    }

    base_type = get_base_type_config(basetype_id);
    if (base_type == NULL) {
        return 0;
    }

    big_endian = base_type->big_endian;
    param_length = (int)((base_type->bitlength_base_type) / 8);

    if (param_length > tvb_captured_length_remaining(tvb, 0) - offset) {
        return 0;
    }

    if (hf_id > 0) {
        if (strncmp(base_type->data_type, "uint", 4) == 0) {
            if (base_type->bitlength_base_type > 32) {
                ti = proto_tree_add_item_ret_uint64(tree, hf_id, tvb, offset, param_length, big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN, &value);
            } else {
                ti = proto_tree_add_item_ret_uint(tree, hf_id, tvb, offset, param_length, big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN, &value32);
                value = (uint64_t)value32;
            }
            value_set = true;
        } else {
            ti = proto_tree_add_item(tree, hf_id, tvb, offset, param_length, big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN);
        }
    } else {
        if (name == NULL) {
            ti = proto_tree_add_string_format(tree, hf_payload_str_base, tvb, offset, param_length, base_type->name, "[%s]", base_type->name);
        } else {
            ti = proto_tree_add_string_format(tree, hf_payload_str_base, tvb, offset, param_length, base_type->name, "%s [%s]", name, base_type->name);
        }
    }

    dissect_someip_payload_add_wtlv_if_needed(tvb, pinfo, wtlv_offset, ti, NULL);

    if (enum_config != NULL && value_set == true) {
        for (i = 0; i < enum_config->num_of_items; i++) {
            if (enum_config->items[i].value == value) {
                value_name = enum_config->items[i].name;
                break;
            }
        }
        if (value_name != NULL) {
            proto_item_append_text(ti, " (%s)", value_name);
        }
    }

    return param_length;
}

static int
dissect_someip_payload_string(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint32_t id, char *name, int *hf_id_ptr, int wtlv_offset) {
    someip_payload_parameter_string_t *config = NULL;

    uint8_t    *buf = NULL;
    uint32_t    i = 0;

    proto_item *ti = NULL;
    proto_tree *subtree = NULL;
    int64_t     tmp = 0;
    uint32_t    length = 0;
    int         offset_orig = offset;

    unsigned    str_encoding = 0;
    int         hf_id = hf_payload_str_string;

    if (hf_id_ptr != NULL) {
        hf_id = *hf_id_ptr;
    }

    config = get_string_config(id);

    if (config == NULL) {
        return 0;
    }

    if (wtlv_offset >= 0) {
        ti = proto_tree_add_string_format(tree, hf_id, tvb, wtlv_offset, 0, name, "%s [%s]", name, config->name);
    } else {
        ti = proto_tree_add_string_format(tree, hf_id, tvb, offset, 0, name, "%s [%s]", name, config->name);
    }

    subtree = proto_item_add_subtree(ti, ett_someip_string);
    uint32_t length_of_length = dissect_someip_payload_add_wtlv_if_needed(tvb, pinfo, wtlv_offset, ti, NULL);

    /* WTLV length overrides configured length */
    if (config->length_of_length == 0 && length_of_length == 0) {
        length = config->max_length;
    } else {
        if (length_of_length == 0) {
            length_of_length = config->length_of_length;
        }

        if (tvb_captured_length_remaining(tvb, offset) < (int)(length_of_length >> 3)) {
            expert_someip_payload_malformed(tree, pinfo, tvb, offset, 0);
            return 0;
        }

        tmp = dissect_someip_payload_length_field(tvb, pinfo, subtree, offset, length_of_length);
        if (tmp < 0) {
            /* error */
            return length_of_length / 8;
        }
        length = (uint32_t)tmp;
        offset += length_of_length / 8;
    }

    if ((uint32_t)tvb_captured_length_remaining(tvb, offset) < length) {
        expert_someip_payload_malformed(subtree, pinfo, tvb, offset, 0);
        return 0;
    }

    if (strcmp(config->encoding, "utf-8") == 0) {
        str_encoding = ENC_UTF_8 | ENC_NA;
    } else if (strcmp(config->encoding, "utf-16") == 0) {
        str_encoding = ENC_UTF_16 | (config->big_endian ? ENC_BIG_ENDIAN : ENC_LITTLE_ENDIAN);
    } else {
        str_encoding = ENC_ASCII | ENC_NA;
    }

    buf = tvb_get_string_enc(pinfo->pool, tvb, offset, length, str_encoding);

    /* sanitizing buffer */
    if ((str_encoding == (ENC_ASCII | ENC_NA)) || (str_encoding & ENC_UTF_8)) {
        for (i = 0; i < length; i++) {
            if (buf[i] > 0x00 && buf[i] < 0x20) {
                buf[i] = 0x20;
            }
        }
    }

    proto_item_append_text(ti, ": %s", buf);
    offset += length;

    proto_item_set_end(ti, tvb, offset);

    return offset - offset_orig;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_someip_payload_struct(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, uint32_t id, char *name, int wtlv_offset) {
    someip_payload_parameter_struct_t *config = NULL;

    proto_tree *subtree = NULL;
    proto_item *ti = NULL;
    tvbuff_t   *subtvb = tvb;

    int64_t     length = 0;
    int         offset = offset_orig;

    config = get_struct_config(id);

    if (config == NULL || tree == NULL || tvb == NULL) {
        return 0;
    }

    if (wtlv_offset >= 0) {
        ti = proto_tree_add_string_format(tree, hf_payload_str_struct, tvb, wtlv_offset, 0, config->struct_name, "struct %s [%s]", name, config->struct_name);
    } else {
        ti = proto_tree_add_string_format(tree, hf_payload_str_struct, tvb, offset, 0, config->struct_name, "struct %s [%s]", name, config->struct_name);
    }

    subtree = proto_item_add_subtree(ti, ett_someip_struct);
    uint32_t length_of_length = dissect_someip_payload_add_wtlv_if_needed(tvb, pinfo, wtlv_offset, ti, subtree);

    /* WTLV length overrides configured length */
    if (length_of_length == 0) {
        length_of_length = config->length_of_length;
    }

    if (tvb_captured_length_remaining(tvb, 0) < (int)(length_of_length >> 3)) {
        expert_someip_payload_malformed(tree, pinfo, tvb, offset, 0);
        return 0;
    };

    if (length_of_length != 0) {
        length = dissect_someip_payload_length_field(tvb, pinfo, subtree, offset, length_of_length);
        if (length < 0) {
            /* error */
            return length_of_length / 8;
        }
        offset += length_of_length / 8;
        int endpos = offset_orig + (length_of_length / 8) + (uint32_t)length;
        proto_item_set_end(ti, tvb, endpos);
        subtvb = tvb_new_subset_length(tvb, 0, endpos);
    }

    offset += dissect_someip_payload_parameters(subtvb, pinfo, subtree, offset, config->items, config->num_of_items, config->wtlv_encoding);

    if (length_of_length == 0) {
        proto_item_set_end(ti, tvb, offset);

        return offset - offset_orig;
    } else {
        return (length_of_length / 8) + (uint32_t)length;
    }
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_someip_payload_typedef(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint32_t id, char *name _U_, int *hf_id, int wtlv_offset) {
    someip_payload_parameter_typedef_t *config = NULL;

    config = get_typedef_config(id);

    if (config == NULL) {
        return 0;
    }

    /* we basically skip over the typedef for now */
    return dissect_someip_payload_parameter(tvb, pinfo, tree, offset, (uint8_t)config->data_type, config->id_ref, config->name, hf_id, wtlv_offset);
}

/* returns bytes parsed, length needs to be int to encode "non-existing" as -1 */
static int
dissect_someip_payload_array_dim_length(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, int *length, int *lower_limit, int *upper_limit,
    someip_parameter_array_t *config, int current_dim, uint32_t length_of_length) {
    int     offset = offset_orig;
    int64_t tmp = 0;

    *lower_limit = config->dims[current_dim].lower_limit;
    *upper_limit = config->dims[current_dim].upper_limit;

    /* length needs to be -1, if we do not have a dynamic length array */
    *length = -1;

    if (length_of_length == 0) {
        length_of_length = config->dims[current_dim].length_of_length;
    }
    if (length_of_length > 0) {
        /* we are filling the length with number of bytes we found in the packet */
        tmp = dissect_someip_payload_length_field(tvb, pinfo, tree, offset, length_of_length);
        if (tmp < 0) {
            /* leave *length = -1 */
            return length_of_length/8;
        }
        *length = (int32_t)tmp;
        offset += length_of_length/8;
    } else {
        /* without a length field, the number of elements needs be fixed */
        if (config->dims[current_dim].lower_limit != config->dims[current_dim].upper_limit) {
            proto_tree_add_expert_format(tree, pinfo, &ei_someip_payload_static_array_min_not_max, tvb, offset_orig, 0,
                "Static array config with Min!=Max (%d, %d)", config->dims[current_dim].lower_limit, config->dims[current_dim].upper_limit);
            col_append_str(pinfo->cinfo, COL_INFO, " [SOME/IP Payload: Static array config with Min!=Max!]");

            return 0;
        }
    }

    return offset - offset_orig;
}

/* returns bytes parsed, length needs to be int to encode "non-existing" as -1 */
static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_someip_payload_array_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, int length, int lower_limit, int upper_limit,
    someip_parameter_array_t *config) {
    tvbuff_t   *subtvb = NULL;
    uint32_t    offset = offset_orig;
    uint32_t    bytes_parsed = 0;
    uint32_t    ret = 0;
    int         count = 0;

    if (length != -1) {
        if (length <= tvb_captured_length_remaining(tvb, offset)) {
            subtvb = tvb_new_subset_length(tvb, offset, length);
            /* created subtvb. so we set offset=0 */
            offset = 0;
        } else {
            expert_someip_payload_truncated(tree, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset));
            return tvb_captured_length_remaining(tvb, offset);
        }
    } else {
        subtvb = tvb;
    }

    while ((length == -1 && count < upper_limit) || ((int)offset < length)) {
        bytes_parsed = dissect_someip_payload_parameter(subtvb, pinfo, tree, offset, (uint8_t)config->data_type, config->id_ref, config->name, config->hf_id, -1);
        if (bytes_parsed == 0) {
            /* does this make sense? */
            return 1;
        }
        offset += bytes_parsed;
        count++;
    }

    if (count<lower_limit && count>upper_limit) {
        proto_tree_add_expert_format(tree, pinfo, &ei_someip_payload_dyn_array_not_within_limit, tvb, offset_orig, length,
            "Number of items (%d) outside limit %d-%d", count, lower_limit, upper_limit);
        col_append_str(pinfo->cinfo, COL_INFO, " [SOME/IP Payload: Dynamic array does not stay between Min and Max values]");
    }

    if (length != -1) {
        /* we created subtvb first and set offset to 0 */
        ret = offset;
    } else {
        ret = offset - offset_orig;
    }

    return ret;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_someip_payload_array_dim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, int length, int lower_limit, int upper_limit, someip_parameter_array_t *config, unsigned current_dim, char *name, uint32_t length_of_length) {
    proto_item *ti = NULL;
    proto_tree *subtree = NULL;
    int         sub_length = 0;
    int         sub_lower_limit = 0;
    int         sub_upper_limit = 0;
    int         i = 0;

    int         sub_offset = 0;
    int         offset = offset_orig;

    if (config->num_of_dims == current_dim + 1) {
        /* only payload left. :) */
        offset += dissect_someip_payload_array_payload(tvb, pinfo, tree, offset, length, lower_limit, upper_limit, config);
    } else {
        if (length != -1) {
            while (offset < offset_orig + (int)length) {
                sub_offset = offset;

                ti = proto_tree_add_string_format(tree, hf_payload_str_array, tvb, sub_offset, 0, name, "subarray (dim: %d, limit %d-%d)", current_dim + 1, sub_lower_limit, sub_upper_limit);
                subtree = proto_item_add_subtree(ti, ett_someip_array_dim);

                offset += dissect_someip_payload_array_dim_length(tvb, pinfo, subtree, offset, &sub_length, &sub_lower_limit, &sub_upper_limit, config, current_dim + 1, length_of_length);

                if (tvb_captured_length_remaining(tvb, offset) < (int)sub_length) {
                    expert_someip_payload_truncated(subtree, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset));
                    return 0;
                }

                offset += dissect_someip_payload_array_dim(tvb, pinfo, subtree, offset, sub_length, sub_lower_limit, sub_upper_limit, config, current_dim + 1, name, length_of_length);

                proto_item_set_end(ti, tvb, offset);
            }
        } else {
            /* Multi-dim static array */
            sub_lower_limit = config->dims[current_dim].lower_limit;
            sub_upper_limit = config->dims[current_dim].upper_limit;

            for (i = 0; i < upper_limit; i++) {
                offset += dissect_someip_payload_array_dim(tvb, pinfo, tree, offset, -1, sub_lower_limit, sub_upper_limit, config, current_dim + 1, name, length_of_length);
            }
        }
    }

    return offset - offset_orig;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_someip_payload_array(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, uint32_t id, char *name, int wtlv_offset) {
    someip_parameter_array_t *config = NULL;

    proto_tree *subtree;
    proto_item *ti = NULL;

    int         offset = offset_orig;

    int         length = 0;
    int         size_of_length = 0;
    int         lower_limit = 0;
    int         upper_limit = 0;

    config = get_array_config(id);

    if (config == NULL) {
        return 0;
    }

    if (config->num_of_dims == 0 || config->dims == NULL) {
        expert_someip_payload_config_error(tree, pinfo, tvb, offset, 0, "Array config has not enough dimensions for this array!");
        return 0;
    }

    ti = proto_tree_add_string_format(tree, hf_payload_str_array, tvb, offset, 0, config->name, "array %s", name);
    subtree = proto_item_add_subtree(ti, ett_someip_array);
    uint32_t length_of_length = dissect_someip_payload_add_wtlv_if_needed(tvb, pinfo, wtlv_offset, ti, subtree);

    offset += dissect_someip_payload_array_dim_length(tvb, pinfo, subtree, offset_orig, &length, &lower_limit, &upper_limit, config, 0, length_of_length);
    size_of_length = offset - offset_orig;

    if (length != -1) {
        proto_item_append_text(ti, " (elements limit: %d-%d)", lower_limit, upper_limit);
    } else {
         proto_item_append_text(ti, " (elements limit: %d)", upper_limit);
    }

    offset += dissect_someip_payload_array_dim(tvb, pinfo, subtree, offset, length, lower_limit, upper_limit, config, 0, name, length_of_length);

    proto_item_set_end(ti, tvb, offset);

    if (length >= 0) {
        /* length field present */
        return size_of_length + length;
    } else {
        /* We have no length field, so we return what has been parsed! */
        return offset - offset_orig;
    }
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_someip_payload_union(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset_orig, uint32_t id, char *name, int wtlv_offset) {
    someip_parameter_union_t        *config = NULL;
    someip_parameter_union_item_t   *item = NULL;

    proto_item *ti = NULL;
    proto_tree *subtree = NULL;

    tvbuff_t   *subtvb;
    int         buf_length = -1;

    int64_t     tmp = 0;
    uint32_t    length = 0;
    uint32_t    type = 0;

    uint32_t    i = 0;

    int         offset = offset_orig;

    config = get_union_config(id);
    buf_length = tvb_captured_length_remaining(tvb, 0);

    if (config == NULL) {
        expert_someip_payload_config_error(tree, pinfo, tvb, offset, 0, "Union ID not configured");
        return 0;
    }

    if (wtlv_offset >= 0) {
        ti = proto_tree_add_string_format(tree, hf_payload_str_union, tvb, wtlv_offset, 0, name, "union %s [%s]", name, config->name);
    } else {
        ti = proto_tree_add_string_format(tree, hf_payload_str_union, tvb, offset_orig, 0, name, "union %s [%s]", name, config->name);
    }

    subtree = proto_item_add_subtree(ti, ett_someip_union);
    uint32_t length_of_length = dissect_someip_payload_add_wtlv_if_needed(tvb, pinfo, wtlv_offset, ti, subtree);

    if (length_of_length == 0) {
        length_of_length = config->length_of_length;
    }

    if ((length_of_length + config->length_of_type) / 8 > (unsigned)buf_length - offset) {
        expert_someip_payload_truncated(tree, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset));
        return 0;
    }

    tmp = dissect_someip_payload_length_field(tvb, pinfo, subtree, offset_orig, length_of_length);
    if (tmp == -1) {
        return offset - offset_orig;
    } else {
        length = (uint32_t)tmp;
    }

    tmp = dissect_someip_payload_type_field(tvb, pinfo, subtree, offset_orig + length_of_length / 8, config->length_of_type);
    if (tmp == -1) {
        return offset - offset_orig;
    } else {
        type = (uint32_t)tmp;
    }

    offset += (length_of_length + config->length_of_type) / 8;
    proto_item_set_end(ti, tvb, offset + length);

    item = NULL;
    for (i = 0; i < config->num_of_items; i++) {
        if (config->items[i].id == type && config->items[i].name != NULL) {
            item = &(config->items[i]);
        }
    }

    if (item != NULL) {
        subtvb = tvb_new_subset_length(tvb, offset, length);
        dissect_someip_payload_parameter(subtvb, pinfo, subtree, 0, (uint8_t)item->data_type, item->id_ref, item->name, item->hf_id, -1);
    } else {
        expert_someip_payload_config_error(tree, pinfo, tvb, offset, 0, "Union type not configured");
    }

    return length + (config->length_of_type + length_of_length) / 8;
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_someip_payload_parameter(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, uint8_t data_type, uint32_t idref, char *name, int *hf_id_ptr, int wtlv_offset) {
    int bytes_parsed = 0;

    increment_dissection_depth(pinfo);
    switch (data_type) {
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_TYPEDEF:
        bytes_parsed = dissect_someip_payload_typedef(tvb, pinfo, tree, offset, idref, name, hf_id_ptr, wtlv_offset);
        break;
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_BASE_TYPE:
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ENUM:
        bytes_parsed = dissect_someip_payload_base_type(tvb, pinfo, tree, offset, data_type, idref, name, hf_id_ptr, wtlv_offset);
        break;
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_STRING:
        bytes_parsed = dissect_someip_payload_string(tvb, pinfo, tree, offset, idref, name, hf_id_ptr, wtlv_offset);
        break;
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ARRAY:
        bytes_parsed = dissect_someip_payload_array(tvb, pinfo, tree, offset, idref, name, wtlv_offset);
        break;
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_STRUCT:
        bytes_parsed = dissect_someip_payload_struct(tvb, pinfo, tree, offset, idref, name, wtlv_offset);
        break;
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_UNION:
        bytes_parsed = dissect_someip_payload_union(tvb, pinfo, tree, offset, idref, name, wtlv_offset);
        break;
    default:
        proto_tree_add_expert_format(tree, pinfo, &ei_someip_payload_config_error, tvb, offset, 0,
            "SOME/IP: Payload: item->data_type (0x%x) unknown/not implemented yet! name: %s, id_ref: 0x%x",
            data_type, name, idref);
        col_append_str(pinfo->cinfo, COL_INFO, " [SOME/IP: Payload Config Error]");
        break;
    }
    decrement_dissection_depth(pinfo);

    return bytes_parsed;
}

/*
 * returns <0 for errors
 */
static int dissect_someip_payload_peek_length_of_length(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int length, someip_payload_parameter_item_t *item) {
    if (item == NULL) {
        return -1;
    }

    uint32_t data_type = item->data_type;
    uint32_t id_ref    = item->id_ref;

    /* a config error could cause an endless loop, so we limit the number of indirections with loop_limit */
    int loop_limit = 255;
    while (data_type == SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_TYPEDEF && loop_limit > 0) {
        someip_payload_parameter_typedef_t *tmp = get_typedef_config(id_ref);
        data_type = tmp->data_type;
        id_ref = tmp->id_ref;
        loop_limit--;
    }

    someip_payload_parameter_string_t  *tmp_string_config;
    someip_parameter_array_t           *tmp_array_config;
    someip_payload_parameter_struct_t  *tmp_struct_config;
    someip_parameter_union_t           *tmp_union_config;

    switch (data_type) {
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_STRING:
        tmp_string_config = get_string_config(id_ref);
        if (tmp_string_config == NULL) {
            return -1;
        }

        return tmp_string_config->length_of_length;

    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ARRAY:
        tmp_array_config = get_array_config(id_ref);
        if (tmp_array_config == NULL) {
            return -1;
        }

        if (tmp_array_config->num_of_dims < 1 || tmp_array_config->dims == NULL) {
            expert_someip_payload_config_error(tree, pinfo, tvb, offset, length, "array configuration does not support WTLV");
            return -1;
        }

        return tmp_array_config->dims[0].length_of_length;

    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_STRUCT:
        tmp_struct_config = get_struct_config(id_ref);
        if (tmp_struct_config == NULL) {
            return -1;
        }

        return tmp_struct_config->length_of_length;

    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_UNION:
        tmp_union_config = get_union_config(id_ref);
        if (tmp_union_config == NULL) {
            return -1;
        }

        return tmp_union_config->length_of_length;

    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_TYPEDEF:
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_BASE_TYPE:
    case SOMEIP_PAYLOAD_PARAMETER_DATA_TYPE_ENUM:
    default:
        /* This happens only if configuration or message are buggy. */
        return -2;
    }
}

static int
// NOLINTNEXTLINE(misc-no-recursion)
dissect_someip_payload_parameters(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, someip_payload_parameter_item_t *items, uint32_t num_of_items, bool wtlv) {
    someip_payload_parameter_item_t *item;

    int       offset_orig = offset;

    if (items == NULL && !someip_deserializer_wtlv_default) {
        return 0;
    }

    if (wtlv) {
        while (tvb_captured_length_remaining(tvb, offset) >= 2) {
            uint64_t tagdata = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            unsigned wiretype = (tagdata & SOMEIP_WTLV_MASK_WIRE_TYPE) >> 12;
            unsigned param_id = tagdata & SOMEIP_WTLV_MASK_DATA_ID;
            offset += 2;

            if (param_id < num_of_items && items != NULL) {
                item = &(items[param_id]);
            } else {
                item = NULL;
            }

            unsigned param_length = 0;
            switch (wiretype) {

            /* fixed length type with just 1, 2, 4, or 8 byte length */
            case 0:
            case 1:
            case 2:
            case 3:
                param_length = 1 << wiretype;
                break;

            /* var length types like structs, strings, arrays, and unions */
            case 4:
                /* this type is deprecated and should not be used*/

                switch (dissect_someip_payload_peek_length_of_length(tree, pinfo, tvb, offset - 2, 0, item)) {
                case 8:
                    param_length = 1 + tvb_get_uint8(tvb, offset);
                    break;
                case 16:
                    param_length = 2 + tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
                    break;
                case 32:
                    param_length = 4 + tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
                    break;
                default:
                    expert_someip_payload_config_error(tree, pinfo, tvb, offset - 2, 2, "WTLV type 4 but datatype has not an appropriate length field configured");
                    return 8 * (offset - offset_orig);
                }
                break;

            case 5:
                param_length = 1 + tvb_get_uint8(tvb, offset);
                break;
            case 6:
                param_length = 2 + tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
                break;
            case 7:
                param_length = 4 + tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
                break;

            default:
                 /* unsupported Wire Type!*/
                expert_someip_payload_malformed(tree, pinfo, tvb, offset - 2, 2);
                break;
            }

            tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset - 2, param_length + 2);
            if (item != NULL) {
                dissect_someip_payload_parameter(subtvb, pinfo, tree, 2, (uint8_t)item->data_type, item->id_ref, item->name, item->hf_id, 0);
            } else {
                proto_item *ti = proto_tree_add_item(tree, hf_payload_unparsed, subtvb, 2, param_length, ENC_NA);
                dissect_someip_payload_add_wtlv_if_needed(tvb, pinfo, offset - 2, ti, NULL);
            }
            offset += param_length;
        }
    } else {
        if (items == NULL) {
            return 0;
        }
        uint32_t i;
        for (i = 0; i < num_of_items; i++) {
            item = &(items[i]);
            offset += dissect_someip_payload_parameter(tvb, pinfo, tree, offset, (uint8_t)item->data_type, item->id_ref, item->name, item->hf_id, -1);
        }
    }

    return offset - offset_orig;
}

static void
dissect_someip_payload(tvbuff_t* tvb, packet_info* pinfo, proto_item *ti, uint16_t serviceid, uint16_t methodid, uint8_t version, uint8_t msgtype) {
    someip_parameter_list_t* paramlist = NULL;

    int         length = -1;
    int         offset = 0;

    proto_tree *tree = NULL;

    length = tvb_captured_length_remaining(tvb, 0);
    tree = proto_item_add_subtree(ti, ett_someip_payload);
    paramlist = get_parameter_config(serviceid, methodid, version, msgtype);

    if (paramlist == NULL) {
        if (someip_deserializer_wtlv_default) {
            offset += dissect_someip_payload_parameters(tvb, pinfo, tree, offset, NULL, 0, true);
        } else {
            return;
        }
    } else {
        offset += dissect_someip_payload_parameters(tvb, pinfo, tree, offset, paramlist->items, paramlist->num_of_items, paramlist->wtlv_encoding);
    }

    if (length > offset) {
        proto_tree_add_item(tree, hf_payload_unparsed, tvb, offset, length - (offset), ENC_NA);
    }
}

/***********************************
 ******** SOME/IP Dissector ********
 ***********************************/

static int
dissect_someip_message(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    uint32_t        offset = 0;
    uint32_t        someip_messageid = 0;
    uint32_t        someip_serviceid = 0;
    uint32_t        someip_methodid = 0;
    uint32_t        someip_clientid = 0;
    uint32_t        someip_sessionid = 0;
    uint32_t        someip_length = 0;
    const char     *service_description = NULL;
    const char     *method_description = NULL;
    const char     *client_description = NULL;
    someip_info_t   someip_data = SOMEIP_INFO_T_INIT;

    uint32_t        someip_payload_length = 0;
    tvbuff_t       *subtvb = NULL;

    proto_item     *ti = NULL;
    proto_item     *ti_someip = NULL;
    proto_tree     *someip_tree = NULL;
    proto_tree     *msgtype_tree = NULL;

    uint32_t        protocol_version = 0;
    uint32_t        version = 0;
    uint32_t        msgtype = 0;
    bool            msgtype_ack = false;
    bool            msgtype_tp = false;
    uint32_t        retcode = 0;
    int             tmp = 0;

    int             tvb_length = tvb_captured_length_remaining(tvb, offset);

    col_set_str(pinfo->cinfo, COL_PROTOCOL, SOMEIP_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, SOMEIP_NAME_LONG);
    ti_someip = proto_tree_add_item(tree, proto_someip, tvb, offset, -1, ENC_NA);
    someip_tree = proto_item_add_subtree(ti_someip, ett_someip);

    /* we should never get called with less than 8 bytes */
    if (tvb_length < 8) {
        return tvb_length;
    }

    /* Message ID = Service ID + Method ID*/
    someip_messageid = tvb_get_ntohl(tvb, 0);
    ti = proto_tree_add_uint_format_value(someip_tree, hf_someip_messageid, tvb, offset, 4, someip_messageid, "0x%08x", someip_messageid);
    proto_item_set_hidden(ti);

    /* Service ID */
    ti = proto_tree_add_item_ret_uint(someip_tree, hf_someip_serviceid, tvb, offset, 2, ENC_BIG_ENDIAN, &someip_serviceid);
    someip_data.service_id = someip_serviceid;
    service_description = someip_lookup_service_name(someip_serviceid);
    if (service_description != NULL) {
        proto_item_append_text(ti, " (%s)", service_description);
        ti = proto_tree_add_string(someip_tree, hf_someip_servicename, tvb, offset, 2, service_description);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);
    }
    offset += 2;

    /* Method ID */
    ti = proto_tree_add_item_ret_uint(someip_tree, hf_someip_methodid, tvb, offset, 2, ENC_BIG_ENDIAN, &someip_methodid);
    someip_data.method_id = someip_methodid;
    method_description = someip_lookup_method_name(someip_serviceid, someip_methodid);
    if (method_description != NULL) {
        proto_item_append_text(ti, " (%s)", method_description);
        ti = proto_tree_add_string(someip_tree, hf_someip_methodname , tvb, offset, 2, method_description);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);
    }
    offset += 2;

    /* Length */
    proto_tree_add_item_ret_uint(someip_tree, hf_someip_length, tvb, offset, 4, ENC_BIG_ENDIAN, &someip_length);
    offset += 4;

    /* this checks if value of the header field */
    if (someip_length < 8) {
        expert_add_info_format(pinfo, ti_someip, &ei_someip_incomplete_headers, "%s", "SOME/IP length too short (<8 Bytes)!");
        return tvb_length;
    }

    /* Add some additional info to the Protocol line and the Info Column*/
    if (service_description == NULL) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (Service ID: 0x%04x, Method ID: 0x%04x, Length: %i)",
                     SOMEIP_NAME_LONG, someip_serviceid, someip_methodid, someip_length);
    } else if (method_description == NULL) {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (Service ID: 0x%04x (%s), Method ID: 0x%04x, Length: %i)",
                     SOMEIP_NAME_LONG, someip_serviceid, service_description, someip_methodid, someip_length);
    } else {
        col_add_fstr(pinfo->cinfo, COL_INFO, "%s (Service ID: 0x%04x (%s), Method ID: 0x%04x (%s), Length: %i)",
                     SOMEIP_NAME_LONG, someip_serviceid, service_description, someip_methodid, method_description, someip_length);
    }
    proto_item_append_text(ti_someip, " (Service ID: 0x%04x, Method ID: 0x%04x, Length: %i)", someip_serviceid, someip_methodid, someip_length);

    /* check if we have bytes for the rest of the header */
    if (tvb_length < 0 || offset + 8 > (uint32_t)tvb_length) {
        expert_add_info_format(pinfo, ti_someip, &ei_someip_incomplete_headers, "%s", "SOME/IP not enough buffer bytes for header!");
        return tvb_length;
    }

    /* Client ID */
    ti = proto_tree_add_item_ret_uint(someip_tree, hf_someip_clientid, tvb, offset, 2, ENC_BIG_ENDIAN, &someip_clientid);
    someip_data.client_id = someip_clientid;
    client_description = someip_lookup_client_name(someip_serviceid, someip_clientid);
    if (client_description != NULL) {
        proto_item_append_text(ti, " (%s)", client_description);
        ti = proto_tree_add_string(someip_tree, hf_someip_clientname, tvb, offset, 2, client_description);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);
    }
    offset += 2;

    /* Session ID */
    proto_tree_add_item_ret_uint(someip_tree, hf_someip_sessionid, tvb, offset, 2, ENC_BIG_ENDIAN, &someip_sessionid);
    someip_data.session_id = someip_sessionid;
    offset += 2;

    /* Protocol Version*/
    ti = proto_tree_add_item_ret_uint(someip_tree, hf_someip_protover, tvb, offset, 1, ENC_BIG_ENDIAN, &protocol_version);
    if (protocol_version!=SOMEIP_PROTOCOL_VERSION) {
        expert_add_info(pinfo, ti, &ei_someip_unknown_version);
    }
    offset += 1;

    /* Major Version of Service Interface */
    proto_tree_add_item_ret_uint(someip_tree, hf_someip_interface_ver, tvb, offset, 1, ENC_BIG_ENDIAN, &version);
    someip_data.major_version = version;
    offset += 1;

    /* Message Type */
    ti = proto_tree_add_item_ret_uint(someip_tree, hf_someip_messagetype, tvb, offset, 1, ENC_BIG_ENDIAN, &msgtype);
    someip_data.message_type = msgtype;
    msgtype_tree = proto_item_add_subtree(ti, ett_someip_msgtype);
    proto_tree_add_item_ret_boolean(msgtype_tree, hf_someip_messagetype_ack_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &msgtype_ack);
    proto_tree_add_item_ret_boolean(msgtype_tree, hf_someip_messagetype_tp_flag, tvb, offset, 1, ENC_BIG_ENDIAN, &msgtype_tp);

    proto_item_append_text(ti, " (%s)", val_to_str_const((~SOMEIP_MSGTYPE_TP_MASK)&msgtype, someip_msg_type, "Unknown Message Type"));
    if (msgtype_tp) {
        proto_item_append_text(ti, " (%s)", SOMEIP_MSGTYPE_TP_STRING);
    }
    offset += 1;

    /* Return Code */
    ti = proto_tree_add_item_ret_uint(someip_tree, hf_someip_returncode, tvb, offset, 1, ENC_BIG_ENDIAN, &retcode);
    proto_item_append_text(ti, " (%s)", val_to_str_const(retcode, someip_return_code, "Unknown Return Code"));
    offset += 1;

    /* lets figure out what we have for the rest */
    if (((uint32_t)tvb_length >= (someip_length + 8)) ) {
        someip_payload_length = someip_length - SOMEIP_HDR_PART1_LEN;
    } else {
        someip_payload_length = tvb_length - SOMEIP_HDR_LEN;
        expert_add_info(pinfo, ti_someip, &ei_someip_message_truncated);
    }

    /* Is this a SOME/IP-TP segment? */
    if (msgtype_tp) {
        uint32_t        tp_offset = 0;
        bool            tp_more_segments = false;
        bool            update_col_info = true;
        fragment_head  *someip_tp_head = NULL;
        proto_tree     *tp_tree = NULL;

        ti = proto_tree_add_item(someip_tree, hf_someip_tp, tvb, offset, someip_payload_length, ENC_NA);
        tp_tree = proto_item_add_subtree(ti, ett_someip_tp);

        /* Unfortunately, with a bitmask set the value is always shifted and cannot be set directly. */
        proto_tree_add_item_ret_uint(tp_tree, hf_someip_tp_offset_encoded, tvb, offset, 4, ENC_BIG_ENDIAN, &tp_offset);
        tp_offset <<= 4;
        proto_tree_add_item(tp_tree, hf_someip_tp_reserved, tvb, offset, 4, ENC_BIG_ENDIAN);
        proto_tree_add_item_ret_boolean(tp_tree, hf_someip_tp_more_segments, tvb, offset, 4, ENC_BIG_ENDIAN, &tp_more_segments);
        ti = proto_tree_add_uint(tp_tree, hf_someip_tp_offset, tvb, offset, 4, tp_offset);
        PROTO_ITEM_SET_GENERATED(ti);
        offset += 4;

        proto_tree_add_item(tp_tree, hf_someip_payload, tvb, offset, someip_payload_length - SOMEIP_TP_HDR_LEN, ENC_NA);

        if (someip_tp_reassemble && tvb_bytes_exist(tvb, offset, someip_payload_length - SOMEIP_TP_HDR_LEN)) {
            someip_tp_head = fragment_add_check(&someip_tp_reassembly_table, tvb, offset, pinfo, 0,
                                                &someip_data, tp_offset, someip_payload_length - SOMEIP_TP_HDR_LEN, tp_more_segments);
            subtvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled SOME/IP-TP Segment",
                     someip_tp_head, &someip_tp_frag_items, &update_col_info, someip_tree);
        }
    } else {
        subtvb = tvb_new_subset_length(tvb, SOMEIP_HDR_LEN, someip_payload_length);
    }

    if (subtvb != NULL) {
        /* TAP */
        if (have_tap_listener(tap_someip_messages)) {
            someip_messages_tap_t *stats_data = wmem_alloc(pinfo->pool, sizeof(someip_messages_tap_t));
            stats_data->service_id = (uint16_t)someip_serviceid;
            stats_data->method_id = (uint16_t)someip_methodid;
            stats_data->interface_version = (uint8_t)version;
            stats_data->message_type = (uint8_t)(~SOMEIP_MSGTYPE_TP_MASK) & msgtype;

            tap_queue_packet(tap_someip_messages, pinfo, stats_data);
        }

        tvb_length = tvb_captured_length_remaining(subtvb, 0);
        if (tvb_length > 0) {
            tmp = dissector_try_uint_new(someip_dissector_table, someip_messageid, subtvb, pinfo, tree, false, &someip_data);

            /* if no subdissector was found, the generic payload dissector takes over. */
            if (tmp==0) {
                ti = proto_tree_add_item(someip_tree, hf_someip_payload, subtvb, 0, tvb_length, ENC_NA);

                if (someip_deserializer_activated) {
                    dissect_someip_payload(subtvb, pinfo, ti, (uint16_t)someip_serviceid, (uint16_t)someip_methodid, (uint8_t)version, (uint8_t)(~SOMEIP_MSGTYPE_TP_MASK)&msgtype);
                } else {
                    proto_tree* payload_dissection_disabled_info_sub_tree = proto_item_add_subtree(ti, ett_someip_payload);
                    proto_tree_add_text_internal(payload_dissection_disabled_info_sub_tree, subtvb, 0, tvb_length, "Dissection of payload is disabled. It can be enabled via protocol preferences.");
                }
            }
        }
    }

    return SOMEIP_HDR_LEN + someip_payload_length;
}

static unsigned
get_someip_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    return SOMEIP_HDR_PART1_LEN + (unsigned)tvb_get_ntohl(tvb, offset + 4);
}

static int
dissect_someip_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    tcp_dissect_pdus(tvb, pinfo, tree, true, SOMEIP_HDR_PART1_LEN, get_someip_message_len, dissect_someip_message, data);
    return tvb_reported_length(tvb);
}

static bool
could_this_be_dtls(tvbuff_t *tvb) {
    /* Headers compared
     *
     * Byte | SOME/IP     | DTLS
     * --------------------------------
     * 00   | Service ID  | Content Type
     * 01   | Service ID  | Version
     * 02   | Method ID   | Version
     * 03   | Method ID   | Epoch
     * 04   | Length      | Epoch
     * 05   | Length      | Sequence Counter
     * 06   | Length      | Sequence Counter
     * 07   | Length      | Sequence Counter
     * 08   | Client ID   | Sequence Counter
     * 09   | Client ID   | Sequence Counter
     * 10   | Session ID  | Sequence Counter
     * 11   | Session ID  | Length
     * 12   | SOME/IP Ver | Length
     * 13   | Iface Ver   | ...
     * 14   | Msg Type    | ...
     * 15   | Return Code | ...
     * 16   | ...         | ...
     */
    int length = tvb_captured_length_remaining(tvb, 0);

    /* DTLS header is 13 bytes. */
    if (length < 13) {
        /* not sure what we have here ... */
        return false;
    }

    uint8_t dtls_content_type = tvb_get_uint8(tvb, 0);
    uint16_t dtls_version = tvb_get_uint16(tvb, 1, ENC_BIG_ENDIAN);
    uint16_t dtls_length = tvb_get_uint16(tvb, 11, ENC_BIG_ENDIAN);

    bool dtls_possible = (20 <= dtls_content_type) && (dtls_content_type <= 63) &&
                             (0xfefc <= dtls_version) && (dtls_version <= 0xfeff) &&
                             ((uint32_t)length == (uint32_t)dtls_length + 13);

    if (dtls_possible && length < SOMEIP_HDR_LEN) {
        return true;
    }

    uint32_t someip_length = tvb_get_uint32(tvb, 4, ENC_BIG_ENDIAN);
    uint8_t someip_version = tvb_get_uint8(tvb, 12);

    /* typically this is 1500 bytes or less on UDP but being conservative */
    bool someip_possible = (someip_version == 1) && (8 <= someip_length) && (someip_length <= 65535) &&
                               ((uint32_t)length == someip_length + 8);

    return dtls_possible && !someip_possible;
}

static int
dissect_someip_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    if (someip_detect_dtls && could_this_be_dtls(tvb)) {
        if (!PINFO_FD_VISITED(pinfo)) {
            dissector_add_uint("dtls.port", (uint16_t)pinfo->destport, someip_handle_udp);
        }

        if (dtls_handle != 0) {
            return call_dissector_with_data(dtls_handle, tvb, pinfo, tree, data);
        }
    }

    return udp_dissect_pdus(tvb, pinfo, tree, SOMEIP_HDR_PART1_LEN, NULL, get_someip_message_len, dissect_someip_message, data);
}

static bool
test_someip(packet_info *pinfo _U_, tvbuff_t *tvb, int offset _U_, void *data _U_) {
    if (tvb_captured_length(tvb) < SOMEIP_HDR_LEN) {
        return false;
    }

    if (tvb_get_uint32(tvb, 4, ENC_BIG_ENDIAN) < 8) {
        return false;
    }

    if ((tvb_get_uint8(tvb, 12)) != SOMEIP_PROTOCOL_VERSION) {
        return false;
    }

    if (!try_val_to_str((tvb_get_uint8(tvb, 14) & ~SOMEIP_MSGTYPE_TP_MASK), someip_msg_type)) {
        return false;
    }

    return true;
}

static bool
dissect_some_ip_heur_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    if (test_someip(pinfo, tvb, 0, data)) {
        tcp_dissect_pdus(tvb, pinfo, tree, true, SOMEIP_HDR_PART1_LEN, get_someip_message_len, dissect_someip_message, data);
        return true;
    }
    return false;
}

static bool
dissect_some_ip_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return (udp_dissect_pdus(tvb, pinfo, tree, SOMEIP_HDR_PART1_LEN, test_someip, get_someip_message_len, dissect_someip_message, data) != 0);
}

void
proto_register_someip(void) {
    expert_module_t *expert_module_someip;

    uat_t *someip_service_uat;
    uat_t *someip_method_uat;
    uat_t *someip_eventgroup_uat;
    uat_t *someip_client_uat;

    uat_t  *someip_parameter_base_type_list_uat;
    uat_t  *someip_parameter_strings_uat;
    uat_t  *someip_parameter_typedefs_uat;
    uat_t  *someip_parameter_list_uat;
    uat_t  *someip_parameter_arrays_uat;
    uat_t  *someip_parameter_structs_uat;
    uat_t  *someip_parameter_unions_uat;
    uat_t  *someip_parameter_enums_uat;

    /* data fields */
    static hf_register_info hf[] = {
        { &hf_someip_serviceid,
            { "Service ID", "someip.serviceid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_servicename,
            { "Service Name", "someip.servicename",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_methodid,
            { "Method ID", "someip.methodid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_methodname,
            { "Method Name", "someip.methodname",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_messageid,
            { "Message ID", "someip.messageid",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_length,
            { "Length", "someip.length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_clientid,
            { "Client ID", "someip.clientid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_clientname,
            { "Client Name", "someip.clientname",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_sessionid,
            { "Session ID", "someip.sessionid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_protover,
            { "SOME/IP Version", "someip.protoversion",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_interface_ver,
            { "Interface Version", "someip.interfaceversion",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_messagetype,
            { "Message Type", "someip.messagetype",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_messagetype_ack_flag,
            { "Message Type Ack Flag", "someip.messagetype.ack",
            FT_BOOLEAN, 8, NULL, SOMEIP_MSGTYPE_ACK_MASK, NULL, HFILL }},
        { &hf_someip_messagetype_tp_flag,
            { "Message Type TP Flag", "someip.messagetype.tp",
            FT_BOOLEAN, 8, NULL, SOMEIP_MSGTYPE_TP_MASK, NULL, HFILL }},
        { &hf_someip_returncode,
            { "Return Code", "someip.returncode",
            FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

        { &hf_someip_payload,
            { "Payload", "someip.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_someip_tp,
            { "SOME/IP-TP", "someip.tp",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_tp_offset,
            { "Offset", "someip.tp.offset",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_someip_tp_offset_encoded,
            { "Encoded Offset", "someip.tp.offset_encoded",
            FT_UINT32, BASE_HEX, NULL, SOMEIP_TP_OFFSET_MASK, NULL, HFILL }},
        { &hf_someip_tp_flags,
            { "Flags", "someip.tp.flags",
            FT_UINT32, BASE_HEX, NULL, SOMEIP_TP_OFFSET_MASK_FLAGS, NULL, HFILL }},
        { &hf_someip_tp_reserved,
            { "Reserved", "someip.tp.flags.reserved",
            FT_UINT32, BASE_HEX, NULL, SOMEIP_TP_OFFSET_MASK_RESERVED, NULL, HFILL }},
        { &hf_someip_tp_more_segments,
            { "More Segments", "someip.tp.flags.more_segments",
            FT_BOOLEAN, 32, NULL, SOMEIP_TP_OFFSET_MASK_MORE_SEGMENTS, NULL, HFILL }},

        {&hf_someip_tp_fragments,
            {"SOME/IP-TP segments", "someip.tp.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_fragment,
            {"SOME/IP-TP segment", "someip.tp.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_fragment_overlap,
            {"SOME/IP-TP segment overlap", "someip.tp.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_fragment_overlap_conflicts,
            {"SOME/IP-TP segment overlapping with conflicting data", "someip.tp.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_fragment_multiple_tails,
            {"SOME/IP-TP Message has multiple tail fragments", "someip.tp.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_fragment_too_long_fragment,
            {"SOME/IP-TP segment too long", "someip.tp.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_fragment_error,
            {"SOME/IP-TP Message defragmentation error", "someip.tp.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_fragment_count,
            {"SOME/IP-TP segment count", "someip.tp.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_reassembled_in,
            {"Reassembled in", "someip.tp.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        {&hf_someip_tp_reassembled_length,
            {"Reassembled length", "someip.tp.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },

        {&hf_someip_tp_reassembled_data,
            {"Reassembled data", "someip.tp.reassembled.data",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_payload_unparsed,
            { "Unparsed Payload", "someip.payload.unparsed",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_payload_length_field_8bit,
            { "Length", "someip.payload.length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_length_field_16bit,
            { "Length", "someip.payload.length",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_length_field_32bit,
            { "Length", "someip.payload.length",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_type_field_8bit,
            { "Type", "someip.payload.type",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_type_field_16bit,
            { "Type", "someip.payload.type",
            FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_type_field_32bit,
            { "Type", "someip.payload.type",
            FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },

        { &hf_payload_str_base, {
            "(base)", "someip.payload.base",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_str_string, {
            "(string)", "someip.payload.string",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_str_struct, {
            "(struct)", "someip.payload.struct",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_str_array, {
            "(array)", "someip.payload.array",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_str_union, {
            "(array)", "someip.payload.union",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },

        { &hf_payload_wtlv_tag, {
            "WTLV-TAG", "someip.payload.wtlvtag",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_payload_wtlv_tag_res, {
            "Reserved", "someip.payload.wtlvtag.res",
            FT_UINT16, BASE_DEC, NULL, SOMEIP_WTLV_MASK_RES, NULL, HFILL } },
        { &hf_payload_wtlv_tag_wire_type, {
            "Wire Type", "someip.payload.wtlvtag.wire_type",
            FT_UINT16, BASE_DEC, NULL, SOMEIP_WTLV_MASK_WIRE_TYPE, NULL, HFILL } },
        { &hf_payload_wtlv_tag_data_id, {
            "Data ID", "someip.payload.wtlvtag.data_id",
            FT_UINT16, BASE_DEC, NULL, SOMEIP_WTLV_MASK_DATA_ID, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_someip,
        &ett_someip_msgtype,
        &ett_someip_tp,
        &ett_someip_tp_fragment,
        &ett_someip_tp_fragments,

        &ett_someip_payload,
        &ett_someip_string,
        &ett_someip_array,
        &ett_someip_array_dim,
        &ett_someip_struct,
        &ett_someip_union,

        &ett_someip_parameter,
        &ett_someip_wtlv_tag,
    };


    /* UATs for user_data fields */
    static uat_field_t someip_service_uat_fields[] = {
        UAT_FLD_HEX(someip_service_ident, id, "Service ID", "ID of the SOME/IP Service (16bit hex without leading 0x)"),
        UAT_FLD_CSTRING(someip_service_ident, name, "Service Name", "Name of the SOME/IP Service (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_method_uat_fields[] = {
        UAT_FLD_HEX(someip_method_ident, id, "Service ID", "ID of the SOME/IP Service (16bit hex without leading 0x)"),
        UAT_FLD_HEX(someip_method_ident, id2, "Methods ID", "ID of the SOME/IP Method/Event/Notifier (16bit hex without leading 0x)"),
        UAT_FLD_CSTRING(someip_method_ident, name, "Method Name", "Name of the SOME/IP Method/Event/Notifier (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_eventgroup_uat_fields[] = {
        UAT_FLD_HEX(someip_eventgroup_ident, id, "Service ID", "ID of the SOME/IP Service (16bit hex without leading 0x)"),
        UAT_FLD_HEX(someip_eventgroup_ident, id2, "Eventgroup ID", "ID of the SOME/IP Eventgroup (16bit hex without leading 0x)"),
        UAT_FLD_CSTRING(someip_eventgroup_ident, name, "Eventgroup Name", "Name of the SOME/IP Service (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_client_uat_fields[] = {
        UAT_FLD_HEX(someip_client_ident, id, "Service ID", "ID of the SOME/IP Service (16bit hex without leading 0x)"),
        UAT_FLD_HEX(someip_client_ident, id2, "Client ID", "ID of the SOME/IP Client (16bit hex without leading 0x)"),
        UAT_FLD_CSTRING(someip_client_ident, name, "Client Name", "Name of the SOME/IP Client (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_parameter_list_uat_fields[] = {
        UAT_FLD_HEX(someip_parameter_list, service_id,              "Service ID",               "ID of the SOME/IP Service (16bit hex without leading 0x)"),
        UAT_FLD_HEX(someip_parameter_list, method_id,               "Method ID",                "ID of the SOME/IP Method/Event/Notifier (16bit hex without leading 0x)"),
        UAT_FLD_DEC(someip_parameter_list, version,                 "Version",                  "Version of the SOME/IP Service (8bit dec)"),
        UAT_FLD_HEX(someip_parameter_list, message_type,            "Message Type",             "Message Type (8bit hex without leading 0x)"),
        UAT_FLD_BOOL(someip_parameter_list, wtlv_encoding,          "WTLV Extension?",          "SOME/IP is extended by Wiretag-Length-Value encoding for this parameter list (not pure SOME/IP)"),

        UAT_FLD_DEC(someip_parameter_list, num_of_params,           "Number of Parameters",     "Number of Parameters (16bit dec), needs to be larger than greatest Parameter Position/ID"),

        UAT_FLD_DEC(someip_parameter_list, pos,                     "Parameter Position/ID",    "Position or ID of parameter (16bit dec, starting with 0)"),
        UAT_FLD_CSTRING(someip_parameter_list, name,                "Parameter Name",           "Name of parameter (string)"),
        UAT_FLD_DEC(someip_parameter_list, data_type,               "Parameter Type",           "Type of parameter (1: base, 2: string, 3: array, 4: struct, 5: union, 6: typedef, 7: enum)"),
        UAT_FLD_HEX(someip_parameter_list, id_ref,                  "ID Reference",             "ID Reference (32bit hex)"),
        UAT_FLD_CSTRING(someip_parameter_list, filter_string,       "Filter String",            "Unique filter string that will be prepended with someip.payload. (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_parameter_array_uat_fields[] = {
        UAT_FLD_HEX(someip_parameter_arrays, id,                    "ID",                       "ID of SOME/IP array (32bit hex without leading 0x)"),
        UAT_FLD_CSTRING(someip_parameter_arrays, name,              "Array Name",               "Name of array"),
        UAT_FLD_DEC(someip_parameter_arrays, data_type,             "Parameter Type",           "Type of parameter (1: base, 2: string, 3: array, 4: struct, 5: union, 6: typedef, 7: enum)"),
        UAT_FLD_HEX(someip_parameter_arrays, id_ref,                "ID Reference",             "ID Reference (32bit hex)"),
        UAT_FLD_DEC(someip_parameter_arrays, num_of_dims,           "Number of Items",          "Number of Dimensions (16bit dec)"),
        UAT_FLD_CSTRING(someip_parameter_arrays, filter_string,     "Filter String",            "Unique filter string that will be prepended with someip.payload. (string)"),

        UAT_FLD_DEC(someip_parameter_arrays, num,                   "Dimension",                "Dimension (16bit dec, starting with 0)"),
        UAT_FLD_DEC(someip_parameter_arrays, lower_limit,           "Lower Limit",              "Dimension (32bit dec)"),
        UAT_FLD_DEC(someip_parameter_arrays, upper_limit,           "Upper Limit",              "Dimension (32bit dec)"),
        UAT_FLD_DEC(someip_parameter_arrays, length_of_length,      "Length of Length Field",   "Length of the arrays length field in bits (8bit dec)"),
        UAT_FLD_DEC(someip_parameter_arrays, pad_to,                "Pad to",                   "Padding pads to reach alignment (8bit dec)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_parameter_struct_uat_fields[] = {
        UAT_FLD_HEX(someip_parameter_structs, id,                   "ID",                       "ID of SOME/IP struct (32bit hex without leading 0x)"),
        UAT_FLD_CSTRING(someip_parameter_structs, struct_name,      "Struct Name",              "Name of struct"),
        UAT_FLD_DEC(someip_parameter_structs, length_of_length,     "Length of Length Field",   "Length of the structs length field in bits (8bit dec)"),
        UAT_FLD_DEC(someip_parameter_structs, pad_to,               "Pad to",                   "Padding pads to reach alignment (8bit dec)"),
        UAT_FLD_BOOL(someip_parameter_structs, wtlv_encoding,       "WTLV Extension?",          "SOME/IP is extended by Wiretag-Length-Value encoding for this struct (not pure SOME/IP)"),
        UAT_FLD_DEC(someip_parameter_structs, num_of_items,         "Number of Items",          "Number of Items (16bit dec)"),

        UAT_FLD_DEC(someip_parameter_structs, pos,                  "Parameter Position/ID",    "Position or ID of parameter (16bit dec, starting with 0)"),
        UAT_FLD_CSTRING(someip_parameter_structs, name,             "Parameter Name",           "Name of parameter (string)"),
        UAT_FLD_DEC(someip_parameter_structs, data_type,            "Parameter Type",           "Type of parameter (1: base, 2: string, 3: array, 4: struct, 5: union, 6: typedef, 7: enum)"),
        UAT_FLD_HEX(someip_parameter_structs, id_ref,               "ID Reference",             "ID Reference (32bit hex)"),
        UAT_FLD_CSTRING(someip_parameter_structs, filter_string,    "Filter String",            "Unique filter string that will be prepended with someip.payload. (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_parameter_union_uat_fields[] = {
        UAT_FLD_HEX(someip_parameter_unions, id,                    "ID",                       "ID of SOME/IP union (32bit hex without leading 0x)"),
        UAT_FLD_CSTRING(someip_parameter_unions, name,              "Union Name",               "Name of union"),
        UAT_FLD_DEC(someip_parameter_unions, length_of_length,      "Length of Length Field",   "Length of the unions length field in bits (uint8 dec)"),
        UAT_FLD_DEC(someip_parameter_unions, length_of_type,        "Length of Type Field",     "Length of the unions type field in bits (8bit dec)"),
        UAT_FLD_DEC(someip_parameter_unions, pad_to,                "Pad to",                   "Padding pads to reach alignment (8bit dec)"),

        UAT_FLD_DEC(someip_parameter_unions, num_of_items,          "Number of Items",          "Number of Items (32bit dec)"),

        UAT_FLD_DEC(someip_parameter_unions, type_id,               "Type ID",                  "ID of Type (32bit dec, starting with 0)"),
        UAT_FLD_CSTRING(someip_parameter_unions, type_name,         "Type Name",                "Name of Type (string)"),
        UAT_FLD_DEC(someip_parameter_unions, data_type,             "Data Type",                "Type of payload (1: base, 2: string, 3: array, 4: struct, 5: union, 6: typedef, 7: enum)"),
        UAT_FLD_HEX(someip_parameter_unions, id_ref,                "ID Reference",             "ID Reference (32bit hex)"),
        UAT_FLD_CSTRING(someip_parameter_unions, filter_string,     "Filter String",            "Unique filter string that will be prepended with someip.payload. (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_parameter_enum_uat_fields[] = {
        UAT_FLD_HEX(someip_parameter_enums, id,                     "ID",                       "ID of SOME/IP enum (32bit hex without leading 0x)"),
        UAT_FLD_CSTRING(someip_parameter_enums, name,               "Name",                     "Name of Enumeration (string)"),
        UAT_FLD_DEC(someip_parameter_enums, data_type,              "Parameter Type",           "Type of parameter (1: base, 2: string, 3: array, 4: struct, 5: union, 6: typedef, 7: enum)"),
        UAT_FLD_HEX(someip_parameter_enums, id_ref,                 "ID Reference",             "ID Reference (32bit hex)"),
        UAT_FLD_DEC(someip_parameter_enums, num_of_items,           "Number of Items",          "Number of Items (32bit dec)"),

        UAT_FLD_HEX(someip_parameter_enums, value,                  "Value",                    "Value (64bit uint hex)"),
        UAT_FLD_CSTRING(someip_parameter_enums, value_name,         "Value Name",               "Name (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_parameter_base_type_list_uat_fields[] = {
        UAT_FLD_HEX(someip_parameter_base_type_list, id,                        "ID ",                  "ID  (32bit hex)"),
        UAT_FLD_CSTRING(someip_parameter_base_type_list, name,                  "Name",                 "Name of type (string)"),
        UAT_FLD_CSTRING(someip_parameter_base_type_list, data_type,             "Data Type",            "Data type (string)"),
        UAT_FLD_BOOL(someip_parameter_base_type_list, big_endian,               "Big Endian",           "Encoded Big Endian"),
        UAT_FLD_DEC(someip_parameter_base_type_list, bitlength_base_type,       "Bitlength base type",  "Bitlength base type (uint32 dec)"),
        UAT_FLD_DEC(someip_parameter_base_type_list, bitlength_encoded_type,    "Bitlength enc. type",  "Bitlength encoded type (uint32 dec)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_parameter_string_list_uat_fields[] = {
        UAT_FLD_HEX(someip_parameter_strings, id,                   "ID ",                  "ID  (32bit hex)"),
        UAT_FLD_CSTRING(someip_parameter_strings, name,             "Name",                 "Name of string (string)"),
        UAT_FLD_CSTRING(someip_parameter_strings, encoding,         "Encoding",             "String Encoding (ascii, utf-8, utf-16)"),
        UAT_FLD_BOOL(someip_parameter_strings, dynamic_length,      "Dynamic Length",       "Dynamic length of string"),
        UAT_FLD_DEC(someip_parameter_strings, max_length,           "Max. Length",          "Maximum length/Length (uint32 dec)"),
        UAT_FLD_DEC(someip_parameter_strings, length_of_length,     "Length of Len Field",  "Length of the length field in bits (uint8 dec)"),
        UAT_FLD_BOOL(someip_parameter_strings, big_endian,          "Big Endian",           "Encoded Big Endian"),
        UAT_FLD_DEC(someip_parameter_strings, pad_to,               "Pad to",               "Padding pads to reach alignment (8bit dec)"),
        UAT_END_FIELDS
    };

    static uat_field_t someip_parameter_typedef_list_uat_fields[] = {
        UAT_FLD_HEX(someip_parameter_typedefs, id,                  "ID ",                  "ID  (32bit hex)"),
        UAT_FLD_CSTRING(someip_parameter_typedefs, name,            "Name",                 "Name of typedef (string)"),
        UAT_FLD_DEC(someip_parameter_typedefs, data_type,           "Data Type",            "Type referenced item (1: base, 2: string, 3: array, 4: struct, 5: union, 6: typedef, 7: enum)"),
        UAT_FLD_HEX(someip_parameter_typedefs, id_ref,              "ID Reference",         "ID Reference (32bit hex)"),
        UAT_END_FIELDS
    };

    static ei_register_info ei[] = {
        { &ei_someip_unknown_version,{ "someip.unknown_protocol_version",
          PI_PROTOCOL, PI_WARN, "SOME/IP Unknown Protocol Version!", EXPFILL } },
        { &ei_someip_message_truncated,{ "someip.message_truncated",
          PI_MALFORMED, PI_ERROR, "SOME/IP Truncated message!", EXPFILL } },
        { &ei_someip_incomplete_headers,{ "someip.incomplete_headers",
          PI_MALFORMED, PI_ERROR, "SOME/IP Incomplete headers or some bytes left over!", EXPFILL } },

        { &ei_someip_payload_truncated, {"someip.payload.expert_truncated",
          PI_MALFORMED, PI_ERROR, "SOME/IP Payload: Truncated payload!", EXPFILL} },
        { &ei_someip_payload_malformed, {"someip.payload.expert_malformed",
          PI_MALFORMED, PI_ERROR, "SOME/IP Payload: Malformed payload!", EXPFILL} },
        { &ei_someip_payload_config_error, {"someip.payload.expert_config_error",
         PI_MALFORMED, PI_ERROR, "SOME/IP Payload: Config Error!", EXPFILL} },
        { &ei_someip_payload_alignment_error, {"someip.payload.expert_alignment_error",
          PI_MALFORMED, PI_ERROR, "SOME/IP Payload: SOME/IP datatype must be align to a byte!", EXPFILL} },
        { &ei_someip_payload_static_array_min_not_max, {"someip.payload.expert_static_array_min_max",
          PI_MALFORMED, PI_ERROR, "SOME/IP Payload: Static array with min!=max!", EXPFILL} },
        { &ei_someip_payload_dyn_array_not_within_limit, {"someip.payload.expert_dyn_array_not_within_limit",
          PI_MALFORMED, PI_WARN, "SOME/IP Payload: Dynamic array does not stay between Min and Max values!", EXPFILL} },
    };

    /* Register Protocol, Handles, Fields, ETTs, Expert Info, Dissector Table, Taps */
    proto_someip = proto_register_protocol(SOMEIP_NAME_LONG, SOMEIP_NAME, SOMEIP_NAME_FILTER);
    someip_handle_udp = register_dissector("someip_udp", dissect_someip_udp, proto_someip);
    someip_handle_tcp = register_dissector("someip_tcp", dissect_someip_tcp, proto_someip);

    proto_register_field_array(proto_someip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_someip = expert_register_protocol(proto_someip);
    expert_register_field_array(expert_module_someip, ei, array_length(ei));

    someip_dissector_table = register_dissector_table("someip.messageid", "SOME/IP Message ID", proto_someip, FT_UINT32, BASE_HEX);

    tap_someip_messages = register_tap("someip_messages");

    /* init for SOME/IP-TP */
    reassembly_table_init(&someip_tp_reassembly_table, &someip_reassembly_table_functions);

    /* Register preferences */
    someip_module = prefs_register_protocol(proto_someip, &proto_reg_handoff_someip);

    /* UATs */
    someip_service_uat = uat_new("SOME/IP Services",
        sizeof(generic_one_id_string_t),                   /* record size           */
        DATAFILE_SOMEIP_SERVICES,                          /* filename              */
        true,                                              /* from profile          */
        (void **) &someip_service_ident,                   /* data_ptr              */
        &someip_service_ident_num,                         /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_generic_one_id_string_cb,                     /* copy callback         */
        update_serviceid,                                  /* update callback       */
        free_generic_one_id_string_cb,                     /* free callback         */
        post_update_someip_service_cb,                     /* post update callback  */
        reset_someip_service_cb,                           /* reset callback        */
        someip_service_uat_fields                          /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "services", "SOME/IP Services",
        "A table to define names of SOME/IP services", someip_service_uat);

    someip_method_uat = uat_new("SOME/IP Methods/Events/Fields",
        sizeof(generic_two_id_string_t),                    /* record size           */
        DATAFILE_SOMEIP_METHODS,                            /* filename              */
        true,                                               /* from profile          */
        (void **) &someip_method_ident,                     /* data_ptr              */
        &someip_method_ident_num,                           /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                             /* but not fields        */
        NULL,                                               /* help                  */
        copy_generic_two_id_string_cb,                      /* copy callback         */
        update_two_identifier_16bit_check_both,             /* update callback       */
        free_generic_two_id_string_cb,                      /* free callback         */
        post_update_someip_method_cb,                       /* post update callback  */
        reset_someip_method_cb,                             /* reset callback        */
        someip_method_uat_fields                            /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "methods", "SOME/IP Methods",
        "A table to define names of SOME/IP methods", someip_method_uat);

    someip_eventgroup_uat = uat_new("SOME/IP Eventgroups",
        sizeof(generic_two_id_string_t),                   /* record size           */
        DATAFILE_SOMEIP_EVENTGROUPS,                       /* filename              */
        true,                                              /* from profile          */
        (void **) &someip_eventgroup_ident,                /* data_ptr              */
        &someip_eventgroup_ident_num,                      /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_generic_two_id_string_cb,                     /* copy callback         */
        update_two_identifier_16bit_check_both,            /* update callback       */
        free_generic_two_id_string_cb,                     /* free callback         */
        post_update_someip_eventgroup_cb,                  /* post update callback  */
        reset_someip_eventgroup_cb,                        /* reset callback        */
        someip_eventgroup_uat_fields                       /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "eventgroups", "SOME/IP Eventgroups",
        "A table to define names of SOME/IP eventgroups", someip_eventgroup_uat);

    someip_client_uat = uat_new("SOME/IP Clients",
        sizeof(generic_two_id_string_t),                   /* record size           */
        DATAFILE_SOMEIP_CLIENTS,                           /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_client_ident,                     /* data_ptr              */
        &someip_client_ident_num,                          /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_generic_two_id_string_cb,                     /* copy callback         */
        update_generic_two_identifier_16bit,               /* update callback       */
        free_generic_two_id_string_cb,                     /* free callback         */
        post_update_someip_client_cb,                      /* post update callback  */
        reset_someip_client_cb,                            /* reset callback        */
        someip_client_uat_fields                           /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "clients", "SOME/IP Clients",
        "A table to define names of SOME/IP clients", someip_client_uat);

    someip_parameter_list_uat = uat_new("SOME/IP Parameter List",
        sizeof(someip_parameter_list_uat_t),               /* record size           */
        DATAFILE_SOMEIP_PARAMETERS,                        /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_parameter_list,                   /* data_ptr              */
        &someip_parameter_list_num,                        /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        NULL,                                              /* help                  */
        copy_someip_parameter_list_cb,                     /* copy callback         */
        update_someip_parameter_list,                      /* update callback       */
        free_someip_parameter_list_cb,                     /* free callback         */
        post_update_someip_parameter_list_cb,              /* post update callback  */
        reset_someip_parameter_list_cb,                    /* reset callback        */
        someip_parameter_list_uat_fields                   /* UAT field definitions */
    );

    prefs_register_bool_preference(someip_module, "reassemble_tp", "Reassemble SOME/IP-TP",
        "Reassemble SOME/IP-TP segments", &someip_tp_reassemble);

    prefs_register_bool_preference(someip_module, "payload_dissector_activated",
        "Dissect Payload",
        "Should the SOME/IP Dissector use the payload dissector?",
        &someip_deserializer_activated);

    prefs_register_bool_preference(someip_module, "detect_dtls_and_hand_off",
        "Try to automatically detect DTLS",
        "Should the SOME/IP Dissector automatically detect DTLS and hand off to it?",
        &someip_detect_dtls);

    prefs_register_bool_preference(someip_module, "payload_dissector_wtlv_default",
        "Try WTLV payload dissection for unconfigured messages (not pure SOME/IP)",
        "Should the SOME/IP Dissector use the payload dissector with the experimental WTLV encoding for unconfigured messages?",
        &someip_deserializer_wtlv_default);

    prefs_register_uat_preference(someip_module, "_someip_parameter_list", "SOME/IP Parameter List",
        "A table to define names of SOME/IP parameters", someip_parameter_list_uat);

    someip_parameter_arrays_uat = uat_new("SOME/IP Parameter Arrays",
        sizeof(someip_parameter_array_uat_t),              /* record size           */
        DATAFILE_SOMEIP_ARRAYS,                            /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_parameter_arrays,                 /* data_ptr              */
        &someip_parameter_arrays_num,                      /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        NULL,                                              /* help                  */
        copy_someip_parameter_array_cb,                    /* copy callback         */
        update_someip_parameter_array,                     /* update callback       */
        free_someip_parameter_array_cb,                    /* free callback         */
        post_update_someip_parameter_array_cb,             /* post update callback  */
        reset_someip_parameter_array_cb,                   /* reset callback        */
        someip_parameter_array_uat_fields                  /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "_someip_parameter_arrays", "SOME/IP Parameter Arrays",
        "A table to define arrays used by SOME/IP", someip_parameter_arrays_uat);

    someip_parameter_structs_uat = uat_new("SOME/IP Parameter Structs",
        sizeof(someip_parameter_struct_uat_t),             /* record size           */
        DATAFILE_SOMEIP_STRUCTS,                           /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_parameter_structs,                /* data_ptr              */
        &someip_parameter_structs_num,                     /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        NULL,                                              /* help                  */
        copy_someip_parameter_struct_cb,                   /* copy callback         */
        update_someip_parameter_struct,                    /* update callback       */
        free_someip_parameter_struct_cb,                   /* free callback         */
        post_update_someip_parameter_struct_cb,            /* post update callback  */
        reset_someip_parameter_struct_cb,                  /* reset callback        */
        someip_parameter_struct_uat_fields                 /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "_someip_parameter_structs", "SOME/IP Parameter Structs",
        "A table to define structs used by SOME/IP", someip_parameter_structs_uat);

    someip_parameter_unions_uat = uat_new("SOME/IP Parameter Unions",
        sizeof(someip_parameter_union_uat_t),              /* record size           */
        DATAFILE_SOMEIP_UNIONS,                            /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_parameter_unions,                 /* data_ptr              */
        &someip_parameter_unions_num,                      /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        NULL,                                              /* help                  */
        copy_someip_parameter_union_cb,                    /* copy callback         */
        update_someip_parameter_union,                     /* update callback       */
        free_someip_parameter_union_cb,                    /* free callback         */
        post_update_someip_parameter_union_cb,             /* post update callback  */
        reset_someip_parameter_union_cb,                   /* reset callback        */
        someip_parameter_union_uat_fields                  /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "_someip_parameter_unions", "SOME/IP Parameter Unions",
        "A table to define unions used by SOME/IP", someip_parameter_unions_uat);

    someip_parameter_enums_uat = uat_new("SOME/IP Parameter Enums",
        sizeof(someip_parameter_enum_uat_t),               /* record size           */
        DATAFILE_SOMEIP_ENUMS,                             /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_parameter_enums,                  /* data_ptr              */
        &someip_parameter_enums_num,                       /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_someip_parameter_enum_cb,                     /* copy callback         */
        update_someip_parameter_enum,                      /* update callback       */
        free_someip_parameter_enum_cb,                     /* free callback         */
        post_update_someip_parameter_enum_cb,              /* post update callback  */
        reset_someip_parameter_enum_cb,                    /* reset callback        */
        someip_parameter_enum_uat_fields                   /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "_someip_parameter_enums", "SOME/IP Parameter Enums",
        "A table to define enumerations used by SOME/IP", someip_parameter_enums_uat);

    someip_parameter_base_type_list_uat = uat_new("SOME/IP Parameter Base Type List",
        sizeof(someip_parameter_base_type_list_uat_t),     /* record size           */
        DATAFILE_SOMEIP_BASE_TYPES,                        /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_parameter_base_type_list,         /* data_ptr              */
        &someip_parameter_base_type_list_num,              /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_someip_parameter_base_type_list_cb,           /* copy callback         */
        update_someip_parameter_base_type_list,            /* update callback       */
        free_someip_parameter_base_type_list_cb,           /* free callback         */
        post_update_someip_parameter_base_type_list_cb,    /* post update callback  */
        reset_someip_parameter_base_type_list_cb,          /* reset callback        */
        someip_parameter_base_type_list_uat_fields         /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "_someip_parameter_base_type_list", "SOME/IP Parameter Base Type List",
        "A table to define base types of SOME/IP parameters", someip_parameter_base_type_list_uat);

    someip_parameter_strings_uat = uat_new("SOME/IP Parameter String List",
        sizeof(someip_parameter_string_uat_t),             /* record size           */
        DATAFILE_SOMEIP_STRINGS,                           /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_parameter_strings,                /* data_ptr              */
        &someip_parameter_strings_num,                     /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_someip_parameter_string_list_cb,              /* copy callback         */
        update_someip_parameter_string_list,               /* update callback       */
        free_someip_parameter_string_list_cb,              /* free callback         */
        post_update_someip_parameter_string_list_cb,       /* post update callback  */
        reset_someip_parameter_string_list_cb,             /* reset callback        */
        someip_parameter_string_list_uat_fields            /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "_someip_parameter_string_list", "SOME/IP Parameter String List",
        "A table to define strings parameters", someip_parameter_strings_uat);

    someip_parameter_typedefs_uat = uat_new("SOME/IP Parameter Typedef List",
        sizeof(someip_parameter_typedef_uat_t),            /* record size           */
        DATAFILE_SOMEIP_TYPEDEFS,                          /* filename              */
        true,                                              /* from profile          */
        (void **)&someip_parameter_typedefs,               /* data_ptr              */
        &someip_parameter_typedefs_num,                    /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_someip_parameter_typedef_list_cb,             /* copy callback         */
        update_someip_parameter_typedef_list,              /* update callback       */
        free_someip_parameter_typedef_list_cb,             /* free callback         */
        post_update_someip_parameter_typedef_list_cb,      /* post update callback  */
        reset_someip_parameter_typedef_list_cb,            /* reset callback        */
        someip_parameter_typedef_list_uat_fields           /* UAT field definitions */
    );

    prefs_register_uat_preference(someip_module, "_someip_parameter_typedef_list", "SOME/IP Parameter Typedef List",
        "A table to define typedefs", someip_parameter_typedefs_uat);
}

static void
clean_all_hashtables_with_empty_uat(void) {
    /* On config change, we delete all hashtables which should have 0 entries! */
    /* Usually this is already done in the post update cb of the uat.*/
    /* Unfortunately, Wireshark does not call the post_update_cb on config errors. :( */
    if (data_someip_services && someip_service_ident_num==0) {
        g_hash_table_destroy(data_someip_services);
        data_someip_services = NULL;
    }
    if (data_someip_methods && someip_method_ident_num==0) {
        g_hash_table_destroy(data_someip_methods);
        data_someip_methods = NULL;
    }
    if (data_someip_eventgroups && someip_eventgroup_ident_num==0) {
        g_hash_table_destroy(data_someip_eventgroups);
        data_someip_eventgroups = NULL;
    }
    if (data_someip_clients && someip_client_ident_num == 0) {
        g_hash_table_destroy(data_someip_clients);
        data_someip_clients = NULL;
    }
    if (data_someip_parameter_list && someip_parameter_list_num==0) {
        g_hash_table_destroy(data_someip_parameter_list);
        data_someip_parameter_list = NULL;
    }
    if (data_someip_parameter_arrays && someip_parameter_arrays_num==0) {
        g_hash_table_destroy(data_someip_parameter_arrays);
        data_someip_parameter_arrays = NULL;
    }
    if (data_someip_parameter_structs && someip_parameter_structs_num==0) {
        g_hash_table_destroy(data_someip_parameter_structs);
        data_someip_parameter_structs = NULL;
    }
    if (data_someip_parameter_unions && someip_parameter_unions_num==0) {
        g_hash_table_destroy(data_someip_parameter_unions);
        data_someip_parameter_unions = NULL;
    }
    if (data_someip_parameter_enums && someip_parameter_enums_num == 0) {
        g_hash_table_destroy(data_someip_parameter_enums);
        data_someip_parameter_enums = NULL;
    }
    if (data_someip_parameter_base_type_list && someip_parameter_base_type_list_num==0) {
        g_hash_table_destroy(data_someip_parameter_base_type_list);
        data_someip_parameter_base_type_list = NULL;
    }
    if (data_someip_parameter_strings && someip_parameter_strings_num==0) {
        g_hash_table_destroy(data_someip_parameter_strings);
        data_someip_parameter_strings = NULL;
    }
    if (data_someip_parameter_typedefs && someip_parameter_typedefs_num==0) {
        g_hash_table_destroy(data_someip_parameter_typedefs);
        data_someip_parameter_typedefs = NULL;
    }
}

void
proto_reg_handoff_someip(void) {
    static bool initialized = false;

    if (!initialized) {
        /* add support for (D)TLS decode as */
        dtls_dissector_add(0, someip_handle_udp);
        ssl_dissector_add(0, someip_handle_tcp);

        heur_dissector_add("udp", dissect_some_ip_heur_udp, "SOME/IP over UDP", "someip_udp_heur", proto_someip, HEURISTIC_DISABLE);
        heur_dissector_add("tcp", dissect_some_ip_heur_tcp, "SOME/IP over TCP", "someip_tcp_heur", proto_someip, HEURISTIC_DISABLE);

        stats_tree_register("someip_messages", "someip_messages", "SOME/IP Messages", 0, someip_messages_stats_tree_packet, someip_messages_stats_tree_init, NULL);

        dissector_add_uint_range_with_preference("udp.port", "", someip_handle_udp);
        dissector_add_uint_range_with_preference("tcp.port", "", someip_handle_tcp);

        dtls_handle = find_dissector("dtls");

        initialized = true;
    } else {
        clean_all_hashtables_with_empty_uat();
    }

    update_dynamic_hf_entries_someip_parameter_list();
    update_dynamic_hf_entries_someip_parameter_arrays();
    update_dynamic_hf_entries_someip_parameter_structs();
    update_dynamic_hf_entries_someip_parameter_unions();
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
