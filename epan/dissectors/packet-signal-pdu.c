/* packet-signal-pdu.c
 * Signal PDU dissector.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2020-2023 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * This dissector allows Signal PDUs (e.g. CAN or FlexRay) to be dissected into signals (automotive use case).
 *
 * This feature is based on typical operations of signal messages:
 * - Scaling/Offset: Move the value by multiplying with scaler and moving by adding offset. (compu methods).
 * - Multiplexer: A signal in the PDU determines, what signals follow.
 * - Value names: Giving raw values names.
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/to_str.h>
#include <epan/uat.h>
#include <epan/proto_data.h>

#include <wsutil/sign_ext.h>

#include "packet-someip.h"
#include "packet-socketcan.h"
#include "packet-flexray.h"
#include "packet-pdu-transport.h"
#include "packet-lin.h"
#include "packet-autosar-ipdu-multiplexer.h"
#include "packet-dlt.h"
#include "packet-uds.h"
#include "packet-isobus.h"

/*
 * Dissector for CAN, FlexRay, and other message payloads.
 * This includes such PDUs being transported on top of TECMP,
 * SOME/IP, and others.
 */

#define SPDU_NAME                                           "Signal PDU"
#define SPDU_NAME_LONG                                      "Signal PDU"
#define SPDU_NAME_FILTER                                    "signal_pdu"


/*** Configuration ***/

/* Define the Signal PDUs and their IDs and Names. */
#define DATAFILE_SPDU_MESSAGES                              "Signal_PDU_identifiers"
/* Define how to parse Signal PDUs into Signals. */
#define DATAFILE_SPDU_SIGNALS                               "Signal_PDU_signal_list"
/* Define enumeration for signal values. */
#define DATAFILE_SPDU_VALUE_NAMES                           "Signal_PDU_signal_values"

/* Using the following config files the payloads of different protocols are mapped to Signal PDU IDs: */
#define DATAFILE_SPDU_SOMEIP_MAPPING                        "Signal_PDU_Binding_SOMEIP"
#define DATAFILE_SPDU_CAN_MAPPING                           "Signal_PDU_Binding_CAN"
#define DATAFILE_SPDU_FLEXRAY_MAPPING                       "Signal_PDU_Binding_FlexRay"
#define DATAFILE_SPDU_LIN_MAPPING                           "Signal_PDU_Binding_LIN"
#define DATAFILE_SPDU_PDU_TRANSPORT_MAPPING                 "Signal_PDU_Binding_PDU_Transport"
#define DATAFILE_SPDU_IPDUM_MAPPING                         "Signal_PDU_Binding_AUTOSAR_IPduM"
#define DATAFILE_SPDU_DLT_MAPPING                           "Signal_PDU_Binding_DLT"
#define DATAFILE_SPDU_UDS_MAPPING                           "Signal_PDU_Binding_UDS"
#define DATAFILE_SPDU_ISOBUS_MAPPING                        "Signal_PDU_Binding_ISOBUS"

/* ID wireshark identifies the dissector by */
static int proto_signal_pdu;

static dissector_handle_t signal_pdu_handle_someip;
static dissector_handle_t signal_pdu_handle_can;
static dissector_handle_t signal_pdu_handle_flexray;
static dissector_handle_t signal_pdu_handle_lin;
static dissector_handle_t signal_pdu_handle_pdu_transport;
static dissector_handle_t signal_pdu_handle_ipdum;
static dissector_handle_t signal_pdu_handle_isobus;

static int hf_pdu_name;
static int hf_payload_unparsed;

static int ett_spdu_payload;
static int ett_spdu_signal;
static bool spdu_deserializer_activated                 = true;
static bool spdu_deserializer_show_hidden;
static bool spdu_deserializer_hide_raw_values           = true;

/*** expert info items ***/
static expert_field ei_spdu_payload_truncated;
static expert_field ei_spdu_config_error;
static expert_field ei_spdu_unaligned_data;

/*** Data Structure for UAT based config ***/
static GHashTable *data_spdu_messages;

static GHashTable *data_spdu_signal_list;
static GHashTable *data_spdu_signal_value_names;

static GHashTable *data_spdu_someip_mappings;
static GHashTable *data_spdu_can_mappings;
static GHashTable *data_spdu_flexray_mappings;
static GHashTable *data_spdu_lin_mappings;
static GHashTable *data_spdu_pdu_transport_mappings;
static GHashTable *data_spdu_ipdum_mappings;
static GHashTable *data_spdu_dlt_mappings;
static GHashTable *data_spdu_uds_mappings;
static GHashTable *data_spdu_isobus_mappings;

static hf_register_info *dynamic_hf_base_raw;
static hf_register_info *dynamic_hf_agg_sum;
static hf_register_info *dynamic_hf_agg_avg;
static hf_register_info *dynamic_hf_agg_int;
static unsigned dynamic_hf_number_of_entries;
static unsigned dynamic_hf_base_raw_number;
static unsigned dynamic_hf_agg_sum_number;
static unsigned dynamic_hf_agg_avg_number;
static unsigned dynamic_hf_agg_int_number;

#define HF_TYPE_BASE                                        0
#define HF_TYPE_RAW                                         1
#define HF_TYPE_AGG_SUM                                     2
#define HF_TYPE_AGG_AVG                                     3
#define HF_TYPE_AGG_INT                                     4
#define HF_TYPE_NONE                                        0xffff

#define HF_TYPE_COUNT_BASE_RAW_TABLE                        2


/***********************************************
 ********* Preferences / Configuration *********
 ***********************************************/

typedef struct _generic_one_id_string {
    unsigned    id;
    char       *name;
} generic_one_id_string_t;

typedef enum _spdu_data_type {
    SPDU_DATA_TYPE_NONE,
    SPDU_DATA_TYPE_UINT,
    SPDU_DATA_TYPE_INT,
    SPDU_DATA_TYPE_FLOAT,
    SPDU_DATA_TYPE_STRING,
    SPDU_DATA_TYPE_STRINGZ,
    SPDU_DATA_TYPE_UINT_STRING,
} spdu_dt_t;

typedef struct _spdu_signal_value_name_item {
    uint64_t    value_start;
    uint64_t    value_end;
    char* name;
} spdu_signal_value_name_item_t;

#define INIT_SIGNAL_VALUE_NAME_ITEM(NAME) \
    (NAME)->value_start = 0; \
    (NAME)->value_end  = 0; \
    (NAME)->name        = NULL;

typedef struct _spdu_signal_value_name {
    uint32_t        id;
    uint32_t        num_of_items;
    uint32_t        pos;
    val64_string* vs;

    spdu_signal_value_name_item_t* items;
} spdu_signal_value_name_t;

#define INIT_SIGNAL_VALUE_NAME(NAME) \
    (NAME)->id              = 0; \
    (NAME)->pos             = 0; \
    (NAME)->num_of_items    = 0; \
    (NAME)->vs              = NULL; \
    (NAME)->items           = NULL;

typedef struct _spdu_signal_item {
    uint32_t    pos;
    char       *name;
    spdu_dt_t   data_type;
    bool        big_endian;
    uint32_t    bitlength_base_type;
    uint32_t    bitlength_encoded_type;
    bool        scale_or_offset;
    double      scaler;
    double      offset;
    bool        multiplexer;
    int         multiplex_value_only;
    bool        hidden;
    unsigned    encoding;

    bool        aggregate_sum;
    bool        aggregate_avg;
    bool        aggregate_int;

    int        *hf_id_effective;
    int        *hf_id_raw;
    int        *hf_id_agg_sum;
    int        *hf_id_agg_avg;
    int        *hf_id_agg_int;

    spdu_signal_value_name_t* sig_val_names;
    bool        sig_val_names_valid;
} spdu_signal_item_t;

typedef struct _spdu_signal_list {
    uint32_t    id;
    uint32_t    num_of_items;
    bool        aggregation;

    spdu_signal_item_t *items;
} spdu_signal_list_t;

typedef struct _spdu_signal_list_uat {
    uint32_t    id;
    uint32_t    num_of_params;

    uint32_t    pos;
    char       *name;
    char       *filter_string;
    char       *data_type;
    bool        big_endian;
    uint32_t    bitlength_base_type;
    uint32_t    bitlength_encoded_type;
    char       *scaler;
    char       *offset;
    bool        multiplexer;
    int         multiplex_value_only;
    bool        hidden;
    bool        aggregate_sum;
    bool        aggregate_avg;
    bool        aggregate_int;
} spdu_signal_list_uat_t;

typedef struct _spdu_signal_value_name_uat {
    uint32_t    id;
    uint32_t    pos;
    uint32_t    num_of_items;
    uint64_t    value_start;
    uint64_t    value_end;
    char       *value_name;
} spdu_signal_value_name_uat_t;


typedef struct _spdu_someip_mapping {
    uint32_t    service_id;
    uint32_t    method_id;
    uint32_t    major_version;
    uint32_t    message_type;

    uint32_t    spdu_message_id;
} spdu_someip_mapping_t;

#define INIT_SOMEIP_MAPPING(NAME) \
    (NAME)->service_id = 0; \
    (NAME)->method_id = 0; \
    (NAME)->major_version = 0; \
    (NAME)->message_type = 0; \
    (NAME)->message_id = 0;

typedef spdu_someip_mapping_t spdu_someip_mapping_uat_t;


typedef struct _spdu_can_mapping {
    uint32_t    can_id;
    uint32_t    bus_id;
    uint32_t    message_id;
} spdu_can_mapping_t;
typedef spdu_can_mapping_t spdu_can_mapping_uat_t;


typedef struct _spdu_flexray_mapping {
    uint32_t    channel;
    uint32_t    cycle;
    uint32_t    flexray_id;
    uint32_t    message_id;
} spdu_flexray_mapping_t;
typedef spdu_flexray_mapping_t spdu_flexray_mapping_uat_t;


typedef struct _spdu_lin_mapping {
    uint32_t    frame_id;
    uint32_t    bus_id;
    uint32_t    message_id;
} spdu_lin_mapping_t;
typedef spdu_lin_mapping_t spdu_lin_mapping_uat_t;


typedef struct _spdu_pdu_transport_mapping {
    uint32_t    pdu_id;
    uint32_t    message_id;
} spdu_pdu_transport_mapping_t;
typedef spdu_pdu_transport_mapping_t spdu_pdu_transport_mapping_uat_t;


typedef struct _spdu_ipdum_mapping {
    uint32_t    pdu_id;
    uint32_t    message_id;
} spdu_ipdum_mapping_t;
typedef spdu_ipdum_mapping_t spdu_ipdum_mapping_uat_t;


typedef struct _spdu_dlt_mapping {
    char       *ecu_id;
    uint32_t    dlt_message_id;
    uint32_t    message_id;
} spdu_dlt_mapping_t;
typedef spdu_dlt_mapping_t spdu_dlt_mapping_uat_t;


typedef struct _spdu_uds_mapping {
    uint32_t    uds_address;
    uint32_t    service;
    bool        reply;
    uint32_t    id;
    uint32_t    message_id;
} spdu_uds_mapping_t;
typedef spdu_uds_mapping_t spdu_uds_mapping_uat_t;


typedef struct _spdu_isobus_mapping {
    uint32_t    pgn;
    uint32_t    bus_id;
    uint32_t    message_id;
} spdu_isobus_mapping_t;
typedef spdu_isobus_mapping_t spdu_isobus_mapping_uat_t;


static generic_one_id_string_t *spdu_message_ident;
static unsigned spdu_message_ident_num;

static spdu_signal_list_uat_t *spdu_signal_list;
static unsigned spdu_signal_list_num;

static spdu_signal_value_name_uat_t *spdu_signal_value_names;
static unsigned spdu_parameter_value_names_num;

static spdu_someip_mapping_t *spdu_someip_mapping;
static unsigned spdu_someip_mapping_num;

static spdu_can_mapping_t *spdu_can_mapping;
static unsigned spdu_can_mapping_num;

static spdu_flexray_mapping_t *spdu_flexray_mapping;
static unsigned spdu_flexray_mapping_num;

static spdu_lin_mapping_t *spdu_lin_mapping;
static unsigned spdu_lin_mapping_num;

static spdu_pdu_transport_mapping_t *spdu_pdu_transport_mapping;
static unsigned spdu_pdu_transport_mapping_num;

static spdu_ipdum_mapping_t *spdu_ipdum_mapping;
static unsigned spdu_ipdum_mapping_num;

static spdu_dlt_mapping_t *spdu_dlt_mapping;
static unsigned spdu_dlt_mapping_num;

static spdu_uds_mapping_t *spdu_uds_mapping;
static unsigned spdu_uds_mapping_num;

static spdu_isobus_mapping_t *spdu_isobus_mapping;
static unsigned spdu_isobus_mapping_num;

void proto_register_signal_pdu(void);
void proto_reg_handoff_signal_pdu(void);

static void
register_signal_pdu_can(void) {
    if (signal_pdu_handle_can == NULL) {
        return;
    }

    dissector_delete_all("can.id", signal_pdu_handle_can);
    dissector_delete_all("can.extended_id", signal_pdu_handle_can);

    /* CAN: loop over all frame IDs in HT */
    if (data_spdu_can_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_spdu_can_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            int32_t id = (*(int32_t *)tmp->data);

            if ((id & CAN_EFF_FLAG) == CAN_EFF_FLAG) {
                dissector_add_uint("can.extended_id", id & CAN_EFF_MASK, signal_pdu_handle_can);
            } else {
                dissector_add_uint("can.id", id & CAN_SFF_MASK, signal_pdu_handle_can);
            }
        }

        g_list_free(keys);
    }
}

static void
register_signal_pdu_lin(void) {
    if (signal_pdu_handle_lin == NULL) {
        return;
    }

    dissector_delete_all("lin.frame_id", signal_pdu_handle_lin);

    /* LIN: loop over all frame IDs in HT */
    if (data_spdu_lin_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_spdu_lin_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            int32_t *id = (int32_t *)tmp->data;
            /* we register the combination of bus and frame id */
            dissector_add_uint("lin.frame_id", *id, signal_pdu_handle_lin);
        }

        g_list_free(keys);
    }
}

static void
register_signal_pdu_someip(void) {
    if (signal_pdu_handle_someip == NULL) {
        return;
    }

    dissector_delete_all("someip.messageid", signal_pdu_handle_someip);

    /* SOME/IP: loop over all messages IDs in HT */
    if (data_spdu_someip_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_spdu_someip_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            int64_t *id = (int64_t *)tmp->data;
            uint32_t message_id = (uint32_t)((uint64_t)(*id)) & 0xffffffff;
            dissector_add_uint("someip.messageid", message_id, signal_pdu_handle_someip);
        }

        g_list_free(keys);
    }
}

static void
register_signal_pdu_pdu_transport(void) {
    if (signal_pdu_handle_pdu_transport == NULL) {
        return;
    }

    dissector_delete_all("pdu_transport.id", signal_pdu_handle_pdu_transport);

    /* PDU Transport: loop over all messages IDs in HT */
    if (data_spdu_pdu_transport_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_spdu_pdu_transport_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            int64_t *id = (int64_t *)tmp->data;
            dissector_add_uint("pdu_transport.id", ((uint32_t)((uint64_t)(*id)) & 0xffffffff), signal_pdu_handle_pdu_transport);
        }

        g_list_free(keys);
    }
}

static void
register_signal_pdu_ipdum(void) {
    if (signal_pdu_handle_ipdum == NULL) {
        return;
    }

    dissector_delete_all("ipdum.pdu.id", signal_pdu_handle_ipdum);

    /* IPduM: loop over all messages IDs in HT */
    if (data_spdu_ipdum_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_spdu_ipdum_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            int64_t *id = (int64_t *)tmp->data;
            dissector_add_uint("ipdum.pdu.id", ((uint32_t)((uint64_t)(*id)) & 0xffffffff), signal_pdu_handle_ipdum);
        }

        g_list_free(keys);
    }
}

static void
register_signal_pdu_isobus(void) {
    if (signal_pdu_handle_isobus == NULL) {
        return;
    }

    dissector_delete_all("isobus.pgn", signal_pdu_handle_isobus);

    /* ISOBUS: loop over all messages IDs in HT */
    if (data_spdu_isobus_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_spdu_isobus_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            int64_t *id = (int64_t *)tmp->data;
            dissector_add_uint("isobus.pgn", ((uint32_t)((uint64_t)(*id)) & 0xffffffff), signal_pdu_handle_isobus);
        }

        g_list_free(keys);
    }
}

/*** UAT Callbacks and Helpers ***/
static void
spdu_payload_free_key(void *key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
spdu_payload_free_generic_data(void *data _U_) {
    /* currently nothing to be free */
}

/* ID -> Name */
static void *
copy_generic_one_id_string_cb(void *n, const void *o, size_t size _U_) {
    generic_one_id_string_t *new_rec = (generic_one_id_string_t *)n;
    const generic_one_id_string_t *old_rec = (const generic_one_id_string_t *)o;

    if (old_rec->name == NULL) {
        new_rec->name = NULL;
    } else {
        new_rec->name = g_strdup(old_rec->name);
    }

    new_rec->id = old_rec->id;
    return new_rec;
}

static bool
update_generic_one_identifier_32bit(void *r, char **err) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;

    if (rec->id > 0xffffffff) {
        *err = ws_strdup_printf("We currently only support 32 bit identifiers (ID: %i  Name: %s)", rec->id, rec->name);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return false;
    }

    unsigned char c = proto_check_field_name(rec->name);
    if (c) {
        if (c == '.') {
            *err = ws_strdup_printf("Name contains illegal chars '.' (ID: 0x%08x)", rec->id);
        } else if (g_ascii_isprint(c)) {
            *err = ws_strdup_printf("Name contains illegal chars '%c' (ID: 0x%08x)", c, rec->id);
        } else {
            *err = ws_strdup_printf("Name contains invalid byte \\%03o  (ID: 0x%08x)", c, rec->id);
        }
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
    for (i = 0; i < data_num; i++) {
        int *key = wmem_new(wmem_epan_scope(), int);
        *key = data[i].id;

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}


/*** Signal PDU Messages ***/
UAT_HEX_CB_DEF(spdu_message_ident, id, generic_one_id_string_t)
UAT_CSTRING_CB_DEF(spdu_message_ident, name, generic_one_id_string_t)

static void
post_update_spdu_message_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_messages) {
        g_hash_table_destroy(data_spdu_messages);
        data_spdu_messages = NULL;
    }

    /* create new hash table */
    data_spdu_messages = g_hash_table_new_full(g_int_hash, g_int_equal, &spdu_payload_free_key, &spdu_payload_free_generic_data);
    post_update_one_id_string_template_cb(spdu_message_ident, spdu_message_ident_num, data_spdu_messages);
}

static char *
get_message_name(uint32_t id) {
    uint32_t tmp = id;

    if (data_spdu_messages == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(data_spdu_messages, &tmp);
}

/* UAT: Signals */
UAT_HEX_CB_DEF(spdu_signal_list, id, spdu_signal_list_uat_t)
UAT_DEC_CB_DEF(spdu_signal_list, num_of_params, spdu_signal_list_uat_t)

UAT_DEC_CB_DEF(spdu_signal_list, pos, spdu_signal_list_uat_t)
UAT_CSTRING_CB_DEF(spdu_signal_list, name, spdu_signal_list_uat_t)
UAT_CSTRING_CB_DEF(spdu_signal_list, filter_string, spdu_signal_list_uat_t)
UAT_CSTRING_CB_DEF(spdu_signal_list, data_type, spdu_signal_list_uat_t)
UAT_BOOL_CB_DEF(spdu_signal_list, big_endian, spdu_signal_list_uat_t)
UAT_DEC_CB_DEF(spdu_signal_list, bitlength_base_type, spdu_signal_list_uat_t)
UAT_DEC_CB_DEF(spdu_signal_list, bitlength_encoded_type, spdu_signal_list_uat_t)
UAT_CSTRING_CB_DEF(spdu_signal_list, scaler, spdu_signal_list_uat_t)
UAT_CSTRING_CB_DEF(spdu_signal_list, offset, spdu_signal_list_uat_t)
UAT_BOOL_CB_DEF(spdu_signal_list, multiplexer, spdu_signal_list_uat_t)
UAT_SIGNED_DEC_CB_DEF(spdu_signal_list, multiplex_value_only, spdu_signal_list_uat_t)
UAT_BOOL_CB_DEF(spdu_signal_list, hidden, spdu_signal_list_uat_t)
UAT_BOOL_CB_DEF(spdu_signal_list, aggregate_sum, spdu_signal_list_uat_t)
UAT_BOOL_CB_DEF(spdu_signal_list, aggregate_avg, spdu_signal_list_uat_t)
UAT_BOOL_CB_DEF(spdu_signal_list, aggregate_int, spdu_signal_list_uat_t)

static void *
copy_spdu_signal_list_cb(void *n, const void *o, size_t size _U_) {
    spdu_signal_list_uat_t *new_rec = (spdu_signal_list_uat_t *)n;
    const spdu_signal_list_uat_t *old_rec = (const spdu_signal_list_uat_t *)o;

    new_rec->id = old_rec->id;
    new_rec->num_of_params = old_rec->num_of_params;
    new_rec->pos = old_rec->pos;

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
    if (old_rec->data_type) {
        new_rec->data_type = g_strdup(old_rec->data_type);
    } else {
        new_rec->data_type = NULL;
    }

    new_rec->big_endian = old_rec->big_endian;
    new_rec->bitlength_base_type = old_rec->bitlength_base_type;
    new_rec->bitlength_encoded_type = old_rec->bitlength_encoded_type;

    if (old_rec->scaler) {
        new_rec->scaler = g_strdup(old_rec->scaler);
    } else {
        new_rec->scaler = NULL;
    }
    if (old_rec->offset) {
        new_rec->offset = g_strdup(old_rec->offset);
    } else {
        new_rec->offset = NULL;
    }

    new_rec->multiplexer = old_rec->multiplexer;
    new_rec->multiplex_value_only = old_rec->multiplex_value_only;

    new_rec->hidden = old_rec->hidden;
    new_rec->aggregate_sum = old_rec->aggregate_sum;
    new_rec->aggregate_avg = old_rec->aggregate_avg;
    new_rec->aggregate_int = old_rec->aggregate_int;

    return new_rec;
}

static bool
update_spdu_signal_list(void *r, char **err) {
    char *tmp;
    unsigned char c;
    double scaler;
    double offset;
    spdu_signal_list_uat_t *rec = (spdu_signal_list_uat_t *)r;

    offset = g_ascii_strtod(rec->offset, &tmp);
    if (!(offset == offset)) {
        *err = ws_strdup_printf("Offset not a double!");
        return false;
    }

    scaler = g_ascii_strtod(rec->scaler, &tmp);
    if (!(scaler == scaler)) {
        *err = ws_strdup_printf("Scaler not a double!");
        return false;
    }

    if (rec->pos >= 0xffff) {
        *err = ws_strdup_printf("Position too big");
        return false;
    }

    if (rec->num_of_params >= 0xffff) {
        *err = ws_strdup_printf("Number of Parameters too big");
        return false;
    }

    if (rec->pos >= rec->num_of_params) {
        *err = ws_strdup_printf("Position %u >= Number of Parameters %u (ID: 0x%x)", rec->pos, rec->num_of_params, rec->id);
        return false;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty");
        return false;
    }

    if (rec->filter_string == NULL || rec->filter_string[0] == 0) {
        *err = ws_strdup_printf("Filter String cannot be empty");
        return false;
    }

    c = proto_check_field_name(rec->filter_string);
    if (c) {
        if (c == '.') {
            *err = ws_strdup_printf("Filter String contains illegal chars '.' (ID: 0x%08x)", rec->id);
        } else if (g_ascii_isprint(c)) {
            *err = ws_strdup_printf("Filter String contains illegal chars '%c' (ID: 0x%08x)", c, rec->id);
        } else {
            *err = ws_strdup_printf("Filter String contains invalid byte \\%03o  (ID: 0x%08x)", c, rec->id);
        }
        return false;
    }

    if (g_strcmp0(rec->data_type, "uint") != 0 &&
        g_strcmp0(rec->data_type, "int") != 0 &&
        g_strcmp0(rec->data_type, "float") != 0 &&
        g_strcmp0(rec->data_type, "string") != 0 &&
        g_strcmp0(rec->data_type, "stringz") != 0 &&
        g_strcmp0(rec->data_type, "uint_string") != 0 &&
        g_strcmp0(rec->data_type, "utf_string") != 0 &&
        g_strcmp0(rec->data_type, "utf_stringz") != 0 &&
        g_strcmp0(rec->data_type, "utf_uint_string") != 0) {
            *err = ws_strdup_printf("Currently the only supported data types are uint, int, float, string, stringz, uint_string, utf_string, utf_stringz, and utf_uint_string (ID: 0x%08x)", rec->id);
        return false;
    }

    /* uint */
    if (g_strcmp0(rec->data_type, "uint") == 0) {
        if ((rec->bitlength_base_type != 8) && (rec->bitlength_base_type != 16) && (rec->bitlength_base_type != 32) && (rec->bitlength_base_type != 64)) {
            *err = ws_strdup_printf("Data type uint is only supported as 8, 16, 32, or 64 bit base type (ID: 0x%08x)", rec->id);
            return false;
        }
    }

    /* int */
    if (g_strcmp0(rec->data_type, "int") == 0) {
        if (rec->bitlength_base_type != rec->bitlength_encoded_type) {
            *err = ws_strdup_printf("Data type int is only supported in non-shortened length (ID: 0x%08x)", rec->id);
            return false;
        }

        if ((rec->bitlength_encoded_type != 8) && (rec->bitlength_encoded_type != 16) && (rec->bitlength_encoded_type != 32) && (rec->bitlength_encoded_type != 64)) {
            *err = ws_strdup_printf("Data type int is only supported in 8, 16, 32, or 64 bit (ID: 0x%08x)", rec->id);
            return false;
        }
    }

    /* float */
    if (g_strcmp0(rec->data_type, "float") == 0) {
        if (rec->bitlength_base_type != rec->bitlength_encoded_type) {
            *err = ws_strdup_printf("Data type float is only supported in non-shortened length (ID: 0x%08x)", rec->id);
            return false;
        }

        if ((rec->bitlength_encoded_type != 32) && (rec->bitlength_encoded_type != 64)) {
            *err = ws_strdup_printf("Data type float is only supported in 32 or 64 bit (ID: 0x%08x)", rec->id);
            return false;
        }

        if ((scaler != 1.0) || (offset != 0.0)) {
            *err = ws_strdup_printf("Data type float currently does not support scaling and offset (ID: 0x%08x)", rec->id);
            return false;
        }

        if (rec->multiplexer == true) {
            *err = ws_strdup_printf("Data type float currently cannot be used as multiplexer (ID: 0x%08x)", rec->id);
            return false;
        }
    }

    /* string, stringz, uint_string, utf_string, utf_stringz, utf_uint_string */
    if (g_strcmp0(rec->data_type, "string") == 0 || g_strcmp0(rec->data_type, "stringz") == 0 || g_strcmp0(rec->data_type, "uint_string") == 0 ||
        g_strcmp0(rec->data_type, "utf_string") == 0 || g_strcmp0(rec->data_type, "utf_stringz") == 0 || g_strcmp0(rec->data_type, "utf_uint_string") == 0) {
        if ((scaler != 1.0) || (offset != 0.0)) {
            *err = ws_strdup_printf("Data types string, stringz, uint_string, utf_string, utf_stringz, and utf_uint_string currently do not support scaling and offset (ID: 0x%08x)", rec->id);
            return false;
        }

        if (rec->multiplexer == true) {
            *err = ws_strdup_printf("Data types string, stringz, uint_string, utf_string, utf_stringz, and utf_uint_string currently cannot be used as multiplexer (ID: 0x%08x)", rec->id);
            return false;
        }

        if ((g_strcmp0(rec->data_type, "string") == 0 || g_strcmp0(rec->data_type, "stringz") == 0 || g_strcmp0(rec->data_type, "uint_string") == 0) &&
            rec->bitlength_base_type != 8) {
            *err = ws_strdup_printf("Data types string, stringz, and uint_string only support 8 bit Bitlength base type since they are ASCII-based (ID: 0x%08x)", rec->id);
            return false;
        }

        if ((g_strcmp0(rec->data_type, "utf_string") == 0 || g_strcmp0(rec->data_type, "utf_stringz") == 0 || g_strcmp0(rec->data_type, "utf_uint_string") == 0) &&
            rec->bitlength_base_type != 8 && rec->bitlength_base_type != 16) {
            *err = ws_strdup_printf("Data types utf_string, utf_stringz, and utf_uint_string only support Bitlength base type with 8 bit (UTF-8) or 16 bit (UTF-16) (ID: 0x%08x)", rec->id);
            return false;
        }

        if ((g_strcmp0(rec->data_type, "stringz") == 0 || g_strcmp0(rec->data_type, "utf_stringz") == 0 ) &&
            (rec->bitlength_encoded_type != 0)) {
            *err = ws_strdup_printf("Data types stringz and utf_stringz only support Bitlength encoded with 0 bit since the length is determined by zero-termination (ID: 0x%08x)", rec->id);
            return false;
        }

        if ((g_strcmp0(rec->data_type, "uint_string") == 0 || g_strcmp0(rec->data_type, "utf_uint_string") == 0) &&
            (rec->bitlength_encoded_type != 8) && (rec->bitlength_encoded_type != 16) && (rec->bitlength_encoded_type != 32) && (rec->bitlength_encoded_type != 64)) {
            *err = ws_strdup_printf("Data types uint_string and utf_uint_string only support Bitlength encoded with 8, 16, 32, or 64 bit since that defines the length of the length field (ID: 0x%08x)", rec->id);
            return false;
        }
    }

    if (g_strcmp0(rec->data_type, "uint") != 0 && g_strcmp0(rec->data_type, "int") != 0 && g_strcmp0(rec->data_type, "float") != 0 &&
        (rec->aggregate_sum || rec->aggregate_avg || rec->aggregate_int)) {
        *err = ws_strdup_printf("Aggregation is only allowed for uint, int, and float (ID: 0x%08x)", rec->id);
        return false;
    }

    return true;
}

static void
free_spdu_signal_list_cb(void *r) {
    spdu_signal_list_uat_t *rec = (spdu_signal_list_uat_t *)r;
    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }
    if (rec->filter_string) {
        g_free(rec->filter_string);
        rec->filter_string = NULL;
    }
    if (rec->data_type) {
        g_free(rec->data_type);
        rec->data_type = NULL;
    }
    if (rec->scaler) {
        g_free(rec->scaler);
        rec->scaler = NULL;
    }
    if (rec->offset) {
        g_free(rec->offset);
        rec->offset = NULL;
    }
}

static void
deregister_user_data_hfarray(hf_register_info **hf_array, unsigned *number_of_entries) {
    if (hf_array == NULL || number_of_entries == NULL) {
        return;
    }

    unsigned dynamic_hf_size = *number_of_entries;
    hf_register_info *dynamic_hf = *hf_array;

    if (dynamic_hf != NULL) {
        /* Unregister all fields */
        for (unsigned i = 0; i < dynamic_hf_size; i++) {
            if (dynamic_hf[i].p_id != NULL) {
                if (*(dynamic_hf[i].p_id) > 0) {
                    proto_deregister_field(proto_signal_pdu, *(dynamic_hf[i].p_id));
                }
                g_free(dynamic_hf[i].p_id);
                dynamic_hf[i].p_id = NULL;

                /* workaround since the proto.c proto_free_field_strings would double free this... */
                dynamic_hf[i].hfinfo.strings = NULL;
            }
        }

        proto_add_deregistered_data(dynamic_hf);
        *hf_array = NULL;
        *number_of_entries = 0;
    }
}

static void
deregister_user_data(void)
{
    deregister_user_data_hfarray(&dynamic_hf_base_raw, &dynamic_hf_base_raw_number);
    deregister_user_data_hfarray(&dynamic_hf_agg_sum, &dynamic_hf_agg_sum_number);
    deregister_user_data_hfarray(&dynamic_hf_agg_avg, &dynamic_hf_agg_avg_number);
    deregister_user_data_hfarray(&dynamic_hf_agg_int, &dynamic_hf_agg_int_number);
    dynamic_hf_number_of_entries = 0;
}

static spdu_signal_value_name_t *get_signal_value_name_config(uint32_t id, uint16_t pos);

static int*
create_hf_entry(hf_register_info *dynamic_hf, unsigned i, uint32_t id, uint32_t pos, char *name, char *filter_string, spdu_dt_t data_type, bool scale_or_offset, uint32_t hf_type) {
    val64_string *vs = NULL;

    int *hf_id = g_new(int, 1);
    *hf_id = 0;

    spdu_signal_value_name_t *sig_val = get_signal_value_name_config(id, pos);
    if (sig_val != NULL) {
        vs = sig_val->vs;
    }

    dynamic_hf[i].p_id = hf_id;
    dynamic_hf[i].hfinfo.bitmask = 0x0;

    switch (hf_type) {
    case HF_TYPE_RAW:
        dynamic_hf[i].hfinfo.name = ws_strdup_printf("%s_raw", name);
        dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("%s.%s_raw", SPDU_NAME_FILTER, filter_string);
        break;

    case HF_TYPE_AGG_SUM:
        dynamic_hf[i].hfinfo.name = ws_strdup_printf("%s_sum", name);
        dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("%s.%s_sum", SPDU_NAME_FILTER, filter_string);
        break;

    case HF_TYPE_AGG_AVG:
        dynamic_hf[i].hfinfo.name = ws_strdup_printf("%s_avg", name);
        dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("%s.%s_avg", SPDU_NAME_FILTER, filter_string);
        break;

    case HF_TYPE_AGG_INT:
        dynamic_hf[i].hfinfo.name = ws_strdup_printf("%s_int", name);
        dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("%s.%s_int", SPDU_NAME_FILTER, filter_string);
        break;

    case HF_TYPE_BASE:
        dynamic_hf[i].hfinfo.name = ws_strdup(name);
        dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("%s.%s", SPDU_NAME_FILTER, filter_string);
        break;

    case HF_TYPE_NONE:
    default:
        /* we bail out but have set hf_id to 0 before */
        dynamic_hf[i].hfinfo.name = ws_strdup_printf("%s_none", name);
        dynamic_hf[i].hfinfo.abbrev = ws_strdup_printf("%s.%s_none", SPDU_NAME_FILTER, filter_string);
        return hf_id;
    }
    dynamic_hf[i].hfinfo.bitmask = 0;
    dynamic_hf[i].hfinfo.blurb = NULL;

    if ((scale_or_offset && hf_type == HF_TYPE_BASE) || hf_type == HF_TYPE_AGG_SUM || hf_type == HF_TYPE_AGG_AVG || hf_type == HF_TYPE_AGG_INT) {
        dynamic_hf[i].hfinfo.display = BASE_NONE;
        dynamic_hf[i].hfinfo.type = FT_DOUBLE;
    } else {
        switch (data_type) {
        case SPDU_DATA_TYPE_UINT:
            dynamic_hf[i].hfinfo.display = BASE_DEC;
            dynamic_hf[i].hfinfo.type = FT_UINT64;
            break;

        case SPDU_DATA_TYPE_INT:
            dynamic_hf[i].hfinfo.display = BASE_DEC;
            dynamic_hf[i].hfinfo.type = FT_INT64;
            break;

        case SPDU_DATA_TYPE_FLOAT:
            dynamic_hf[i].hfinfo.display = BASE_NONE;
            dynamic_hf[i].hfinfo.type = FT_DOUBLE;
            break;

        case SPDU_DATA_TYPE_STRING:
            dynamic_hf[i].hfinfo.display = BASE_NONE;
            dynamic_hf[i].hfinfo.type = FT_STRING;
            break;

        case SPDU_DATA_TYPE_STRINGZ:
            dynamic_hf[i].hfinfo.display = BASE_NONE;
            dynamic_hf[i].hfinfo.type = FT_STRINGZ;
            break;

        case SPDU_DATA_TYPE_UINT_STRING:
            dynamic_hf[i].hfinfo.display = BASE_NONE;
            dynamic_hf[i].hfinfo.type = FT_UINT_STRING;
            break;

        case SPDU_DATA_TYPE_NONE:
            /* do nothing */
            break;
        }
    }

    if (hf_type == HF_TYPE_RAW && vs != NULL) {
        dynamic_hf[i].hfinfo.strings = VALS64(vs);
        dynamic_hf[i].hfinfo.display |= BASE_VAL64_STRING | BASE_SPECIAL_VALS;
    } else {
        dynamic_hf[i].hfinfo.strings = NULL;
    }

    HFILL_INIT(dynamic_hf[i]);

    return hf_id;
}

static void
post_update_spdu_signal_list_read_in_data(spdu_signal_list_uat_t *data, unsigned data_num, GHashTable *ht) {
    if (ht == NULL || data == NULL || data_num == 0) {
        return;
    }

    if (data_num) {
        dynamic_hf_number_of_entries = data_num;
        /* lets create the dynamic_hf array (base + raw) */
        dynamic_hf_base_raw = g_new0(hf_register_info, 2 * dynamic_hf_number_of_entries);
        dynamic_hf_base_raw_number = 2 * dynamic_hf_number_of_entries;

        /* lets create the other dynamic_hf arrays */
        dynamic_hf_agg_sum = g_new0(hf_register_info, dynamic_hf_number_of_entries);
        dynamic_hf_agg_sum_number = 0;
        dynamic_hf_agg_avg = g_new0(hf_register_info, dynamic_hf_number_of_entries);
        dynamic_hf_agg_avg_number = 0;
        dynamic_hf_agg_int = g_new0(hf_register_info, dynamic_hf_number_of_entries);
        dynamic_hf_agg_int_number = 0;


        unsigned i = 0;
        for (i = 0; i < data_num; i++) {

            /* the hash table does not know about uint64, so we use int64*/
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            *key = (uint32_t)data[i].id;

            spdu_signal_list_t *list = (spdu_signal_list_t *)g_hash_table_lookup(ht, key);
            if (list == NULL) {

                list = wmem_new(wmem_epan_scope(), spdu_signal_list_t);

                list->id = data[i].id;
                list->num_of_items = data[i].num_of_params;

                spdu_signal_item_t *items = (spdu_signal_item_t *)wmem_alloc0_array(wmem_epan_scope(), spdu_signal_item_t, data[i].num_of_params);

                list->items = items;

                /* create new entry ... */
                g_hash_table_insert(ht, key, list);
            } else {
                /* already present, deleting key */
                wmem_free(wmem_epan_scope(), key);
            }

            /* and now we add to item array */
            if (data[i].num_of_params == list->num_of_items && data[i].pos < list->num_of_items) {
                spdu_signal_item_t *item = &(list->items[data[i].pos]);

                /* we do not care if we overwrite param */
                item->name = g_strdup(data[i].name);
                item->pos = data[i].pos;

                item->encoding = ENC_ASCII;
                if (g_strcmp0("utf_string", data[i].data_type) == 0 ||
                    g_strcmp0("utf_stringz", data[i].data_type) == 0 ||
                    g_strcmp0("utf_uint_string", data[i].data_type) == 0) {
                    switch (data[i].bitlength_base_type) {
                    case 8:
                        item->encoding = ENC_UTF_8;
                        break;
                    case 16:
                        item->encoding = ENC_UTF_16;
                        break;
                    default:
                        /* this should never happen, since it is validated in the update callback */
                        item->encoding = ENC_ASCII;
                        break;
                    }
                }

                if (g_strcmp0("uint", data[i].data_type) == 0) {
                    item->data_type = SPDU_DATA_TYPE_UINT;
                } else if (g_strcmp0("int", data[i].data_type) == 0) {
                    item->data_type = SPDU_DATA_TYPE_INT;
                } else if (g_strcmp0("float", data[i].data_type) == 0) {
                    item->data_type = SPDU_DATA_TYPE_FLOAT;
                } else if (g_strcmp0("string", data[i].data_type) == 0 || g_strcmp0("utf_string", data[i].data_type) == 0) {
                    item->data_type = SPDU_DATA_TYPE_STRING;
                } else if (g_strcmp0("stringz", data[i].data_type) == 0 || g_strcmp0("utf_stringz", data[i].data_type) == 0) {
                    item->data_type = SPDU_DATA_TYPE_STRINGZ;
                } else if (g_strcmp0("uint_string", data[i].data_type) == 0 || g_strcmp0("utf_uint_string", data[i].data_type) == 0) {
                    item->data_type = SPDU_DATA_TYPE_UINT_STRING;
                } else {
                    item->data_type = SPDU_DATA_TYPE_NONE;
                }

                item->big_endian = data[i].big_endian;
                item->bitlength_base_type = data[i].bitlength_base_type;
                item->bitlength_encoded_type = data[i].bitlength_encoded_type;
                item->scaler = g_ascii_strtod(data[i].scaler, NULL);
                item->offset = g_ascii_strtod(data[i].offset, NULL);
                item->scale_or_offset = (item->scaler != 1.0 || item->offset != 0.0);
                item->multiplexer = data[i].multiplexer;
                item->multiplex_value_only = data[i].multiplex_value_only;
                item->hidden = data[i].hidden;

                item->aggregate_sum = data[i].aggregate_sum;
                item->aggregate_avg = data[i].aggregate_avg;
                item->aggregate_int = data[i].aggregate_int;

                /* if one signal needs aggregation, the messages needs to know */
                list->aggregation |= item->aggregate_sum | item->aggregate_avg | item->aggregate_int;

                item->hf_id_effective = create_hf_entry(dynamic_hf_base_raw, HF_TYPE_COUNT_BASE_RAW_TABLE * i + HF_TYPE_BASE, data[i].id, data[i].pos, data[i].name, data[i].filter_string, item->data_type, item->scale_or_offset, HF_TYPE_BASE);
                item->hf_id_raw       = create_hf_entry(dynamic_hf_base_raw, HF_TYPE_COUNT_BASE_RAW_TABLE * i + HF_TYPE_RAW, data[i].id, data[i].pos, data[i].name, data[i].filter_string, item->data_type, item->scale_or_offset, HF_TYPE_RAW);
                if (data[i].aggregate_sum) {
                    item->hf_id_agg_sum = create_hf_entry(dynamic_hf_agg_sum, dynamic_hf_agg_sum_number++, data[i].id, data[i].pos, data[i].name, data[i].filter_string, item->data_type, item->scale_or_offset, HF_TYPE_AGG_SUM);
                }
                if (data[i].aggregate_avg) {
                    item->hf_id_agg_avg = create_hf_entry(dynamic_hf_agg_avg, dynamic_hf_agg_avg_number++, data[i].id, data[i].pos, data[i].name, data[i].filter_string, item->data_type, item->scale_or_offset, HF_TYPE_AGG_AVG);
                }
                if (data[i].aggregate_int) {
                    item->hf_id_agg_int = create_hf_entry(dynamic_hf_agg_int, dynamic_hf_agg_int_number++, data[i].id, data[i].pos, data[i].name, data[i].filter_string, item->data_type, item->scale_or_offset, HF_TYPE_AGG_INT);
                }
            }
        }

        if (dynamic_hf_base_raw_number) {
            proto_register_field_array(proto_signal_pdu, dynamic_hf_base_raw, dynamic_hf_base_raw_number);
        }
        if (dynamic_hf_agg_sum_number) {
            proto_register_field_array(proto_signal_pdu, dynamic_hf_agg_sum, dynamic_hf_agg_sum_number);
        }
        if (dynamic_hf_agg_avg_number) {
            proto_register_field_array(proto_signal_pdu, dynamic_hf_agg_avg, dynamic_hf_agg_avg_number);
        }
        if (dynamic_hf_agg_int_number) {
            proto_register_field_array(proto_signal_pdu, dynamic_hf_agg_int, dynamic_hf_agg_int_number);
        }
    }
}

static void
post_update_spdu_signal_value_names_read_in_data(spdu_signal_value_name_uat_t* data, unsigned data_num, GHashTable* ht) {
    if (ht == NULL || data == NULL || data_num == 0) {
        return;
    }

    unsigned i;
    for (i = 0; i < data_num; i++) {
        int64_t* key = wmem_new(wmem_epan_scope(), int64_t);
        *key = (uint64_t)data[i].id | ((uint64_t)data[i].pos << 32);

        spdu_signal_value_name_t* list = (spdu_signal_value_name_t*)g_hash_table_lookup(ht, key);
        if (list == NULL) {

            list = wmem_new(wmem_epan_scope(), spdu_signal_value_name_t);
            INIT_SIGNAL_VALUE_NAME(list)

                list->id = data[i].id;
            list->pos = data[i].pos;
            list->num_of_items = data[i].num_of_items;

            list->items = (spdu_signal_value_name_item_t*)wmem_alloc0_array(wmem_epan_scope(), spdu_signal_value_name_item_t, list->num_of_items);
            list->vs = (val64_string*)wmem_alloc0_array(wmem_epan_scope(), val64_string, list->num_of_items + 1);

            /* create new entry ... */
            g_hash_table_insert(ht, key, list);
        }
        else {
            /* do not need it anymore */
            wmem_free(wmem_epan_scope(), key);
        }

        /* and now we add to item array */
        if (list->num_of_items > 0 && data[i].num_of_items == list->num_of_items) {

            /* find first empty slot for value */
            unsigned j;
            for (j = 0; j < list->num_of_items && list->items[j].name != NULL; j++);

            if (j < list->num_of_items) {
                spdu_signal_value_name_item_t* item = &(list->items[j]);
                INIT_SIGNAL_VALUE_NAME_ITEM(item)

                    item->value_start = data[i].value_start;
                item->value_end = data[i].value_end;
                item->name = g_strdup(data[i].value_name);
            }

            /* find first empty slot for range_value array */
            unsigned g;
            for (g = 0; g < list->num_of_items && list->vs[g].strptr != NULL; g++);

            if (g < list->num_of_items) {
                /* Limitation: range strings currently do not support uint64_t min/max and do not support filtering using value names. */
                /* Therefore, we currently use only val64_string. :-( */
                list->vs[g].value = (uint32_t)data[i].value_start;
                list->vs[g].strptr = g_strdup(data[i].value_name);
            }
        }
    }
}

static void
post_update_spdu_signal_list_and_value_names_cb(void) {
    /* destroy old hash tables, if they exist */
    if (data_spdu_signal_list) {
        g_hash_table_destroy(data_spdu_signal_list);
        data_spdu_signal_list = NULL;
    }
    if (data_spdu_signal_value_names) {
        g_hash_table_destroy(data_spdu_signal_value_names);
        data_spdu_signal_value_names = NULL;
    }

    deregister_user_data();

    data_spdu_signal_list = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, &spdu_payload_free_generic_data);
    data_spdu_signal_value_names = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, &spdu_payload_free_generic_data);
    post_update_spdu_signal_list_read_in_data(spdu_signal_list, spdu_signal_list_num, data_spdu_signal_list);
    post_update_spdu_signal_value_names_read_in_data(spdu_signal_value_names, spdu_parameter_value_names_num, data_spdu_signal_value_names);
}

static void
reset_spdu_signal_list(void)
{
    deregister_user_data();
}

static spdu_signal_list_t *
get_parameter_config(uint64_t id) {
    if (data_spdu_signal_list == NULL) {
        return NULL;
    }

    int64_t key = (int64_t)id;
    return (spdu_signal_list_t *)g_hash_table_lookup(data_spdu_signal_list, &key);
}

/* UAT: Value Names */
UAT_HEX_CB_DEF(spdu_signal_value_names, id, spdu_signal_value_name_uat_t)
UAT_DEC_CB_DEF(spdu_signal_value_names, pos, spdu_signal_value_name_uat_t)
UAT_DEC_CB_DEF(spdu_signal_value_names, num_of_items, spdu_signal_value_name_uat_t)
UAT_HEX64_CB_DEF(spdu_signal_value_names, value_start, spdu_signal_value_name_uat_t)
UAT_HEX64_CB_DEF(spdu_signal_value_names, value_end, spdu_signal_value_name_uat_t)
UAT_CSTRING_CB_DEF(spdu_signal_value_names, value_name, spdu_signal_value_name_uat_t)

static void *
copy_spdu_signal_value_name_cb(void *n, const void *o, size_t size _U_) {
    spdu_signal_value_name_uat_t *new_rec = (spdu_signal_value_name_uat_t *)n;
    const spdu_signal_value_name_uat_t *old_rec = (const spdu_signal_value_name_uat_t *)o;

    new_rec->id = old_rec->id;
    new_rec->num_of_items = old_rec->num_of_items;
    new_rec->pos = old_rec->pos;

    new_rec->value_start = old_rec->value_start;
    new_rec->value_end = old_rec->value_end;

    if (old_rec->value_name) {
        new_rec->value_name = g_strdup(old_rec->value_name);
    } else {
        new_rec->value_name = NULL;
    }

    return new_rec;
}

static bool
update_spdu_signal_value_name(void *r, char **err) {
    spdu_signal_value_name_uat_t *rec = (spdu_signal_value_name_uat_t *)r;

    if (rec->value_name == NULL || rec->value_name[0] == 0) {
        *err = ws_strdup_printf("Value Name cannot be empty");
        return false;
    }

    if (rec->value_end < rec->value_start) {
        *err = ws_strdup_printf("Value Range is defined backwards (end < start)!");
        return false;
    }

    if (rec->pos >= 0xffff) {
        *err = ws_strdup_printf("Position too big");
        return false;
    }

    return true;
}

static void
free_spdu_signal_value_name_cb(void *r) {
    spdu_signal_value_name_uat_t *rec = (spdu_signal_value_name_uat_t *)r;
    if (rec->value_name) {
        g_free(rec->value_name);
        rec->value_name = NULL;
    }
}

static spdu_signal_value_name_t *
get_signal_value_name_config(uint32_t id, uint16_t pos) {
    if (data_spdu_signal_list == NULL) {
        return NULL;
    }

    int64_t key = (uint64_t)id | (uint64_t)pos << 32;
    return (spdu_signal_value_name_t *)g_hash_table_lookup(data_spdu_signal_value_names, &key);
}

/* UAT: SOME/IP Mapping */
UAT_HEX_CB_DEF(spdu_someip_mapping, service_id, spdu_someip_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_someip_mapping, method_id, spdu_someip_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_someip_mapping, major_version, spdu_someip_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_someip_mapping, message_type, spdu_someip_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_someip_mapping, spdu_message_id, spdu_someip_mapping_uat_t)

static int64_t
spdu_someip_key(uint16_t service_id, uint16_t method_id, uint8_t major_version, uint8_t message_type) {
    return (int64_t)method_id | ((int64_t)service_id << 16) | ((int64_t)major_version << 32) | ((int64_t)message_type << 40);
}

static void *
copy_spdu_someip_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_someip_mapping_uat_t *new_rec = (spdu_someip_mapping_uat_t *)n;
    const spdu_someip_mapping_uat_t *old_rec = (const spdu_someip_mapping_uat_t *)o;

    new_rec->service_id = old_rec->service_id;
    new_rec->method_id = old_rec->method_id;
    new_rec->major_version = old_rec->major_version;
    new_rec->message_type = old_rec->message_type;
    new_rec->spdu_message_id = old_rec->spdu_message_id;

    return new_rec;
}

static bool
update_spdu_someip_mapping(void *r, char **err) {
    spdu_someip_mapping_uat_t *rec = (spdu_someip_mapping_uat_t *)r;

    if (rec->service_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit SOME/IP Service IDs (Service-ID: %x  Method-ID: %x  MsgType: %x  Version: %i)",
                                rec->service_id, rec->method_id, rec->message_type, rec->major_version);
        return false;
    }

    if (rec->method_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit SOME/IP Method IDs (Service-ID: %x  Method-ID: %x  MsgType: %x  Version: %i)",
                                rec->service_id, rec->method_id, rec->message_type, rec->major_version);
        return false;
    }

    if (rec->major_version > 0xff) {
        *err = ws_strdup_printf("We currently only support 8 bit SOME/IP major versions (Service-ID: %x  Method-ID: %x  MsgType: %x  Version: %i)",
                                 rec->service_id, rec->method_id, rec->message_type, rec->major_version);
    }

    if (rec->message_type > 0xff) {
        *err = ws_strdup_printf("We currently only support 8 bit SOME/IP message types (Service-ID: %x  Method-ID: %x  MsgType: %x  Version: %i)",
                                 rec->service_id, rec->method_id, rec->message_type, rec->major_version);
    }

    return true;
}

static void
post_update_spdu_someip_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_someip_mappings) {
        g_hash_table_destroy(data_spdu_someip_mappings);
        data_spdu_someip_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_someip_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_someip_mappings == NULL || spdu_someip_mapping == NULL) {
        return;
    }

    unsigned i;
    if (spdu_someip_mapping_num > 0) {
        for (i = 0; i < spdu_someip_mapping_num; i++) {
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            *key = spdu_someip_key((uint16_t)spdu_someip_mapping[i].service_id,
                                   (uint16_t)spdu_someip_mapping[i].method_id,
                                   (uint8_t)spdu_someip_mapping[i].major_version,
                                   (uint8_t)spdu_someip_mapping[i].message_type);

            g_hash_table_insert(data_spdu_someip_mappings, key, &spdu_someip_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    register_signal_pdu_someip();
}

static spdu_someip_mapping_t *
get_someip_mapping(uint16_t service_id, uint16_t method_id, uint8_t major_version, uint8_t message_type) {
    if (data_spdu_someip_mappings == NULL) {
        return NULL;
    }

    int64_t key = spdu_someip_key(service_id, method_id, major_version, message_type);
    return (spdu_someip_mapping_t *)g_hash_table_lookup(data_spdu_someip_mappings, &key);
}

/* UAT: CAN Mapping */
UAT_HEX_CB_DEF(spdu_can_mapping, can_id, spdu_can_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_can_mapping, bus_id, spdu_can_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_can_mapping, message_id, spdu_can_mapping_uat_t)

static void *
copy_spdu_can_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_can_mapping_uat_t *new_rec = (spdu_can_mapping_uat_t *)n;
    const spdu_can_mapping_uat_t *old_rec = (const spdu_can_mapping_uat_t *)o;

    new_rec->can_id = old_rec->can_id;
    new_rec->bus_id = old_rec->bus_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static bool
update_spdu_can_mapping(void *r, char **err) {
    spdu_can_mapping_uat_t *rec = (spdu_can_mapping_uat_t *)r;

    if ((rec->can_id & (CAN_RTR_FLAG | CAN_ERR_FLAG)) != 0) {
        *err = g_strdup_printf("We currently do not support CAN IDs with RTR or Error Flag set (CAN_ID: 0x%x)", rec->can_id);
        return false;
    }

    if ((rec->can_id & CAN_EFF_FLAG) == 0 && rec->can_id > CAN_SFF_MASK) {
        *err = g_strdup_printf("Standard CAN ID (EFF flag not set) cannot be bigger than 0x7ff (CAN_ID: 0x%x)", rec->can_id);
        return false;
    }

    return true;
}

static void
post_update_spdu_can_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_can_mappings) {
        g_hash_table_destroy(data_spdu_can_mappings);
        data_spdu_can_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_can_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_can_mappings == NULL || spdu_can_mapping == NULL) {
        return;
    }

    if (spdu_can_mapping_num > 0) {
        unsigned i;
        for (i = 0; i < spdu_can_mapping_num; i++) {
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            *key = spdu_can_mapping[i].can_id;
            *key |= ((int64_t)(spdu_can_mapping[i].bus_id & 0xffff)) << 32;

            g_hash_table_insert(data_spdu_can_mappings, key, &spdu_can_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    register_signal_pdu_can();
}

static spdu_can_mapping_t *
get_can_mapping(uint32_t id, uint16_t bus_id) {
    if (data_spdu_can_mappings == NULL) {
        return NULL;
    }

    /* key is Bus ID, EFF Flag, CAN-ID*/
    int64_t key = ((int64_t)id & (CAN_EFF_MASK | CAN_EFF_FLAG)) | ((int64_t)bus_id << 32);
    spdu_can_mapping_t *tmp = (spdu_can_mapping_t *)g_hash_table_lookup(data_spdu_can_mappings, &key);
    if (tmp == NULL) {
        /* try again without Bus ID set */
        key = id & (CAN_EFF_MASK | CAN_EFF_FLAG);
        tmp = (spdu_can_mapping_t *)g_hash_table_lookup(data_spdu_can_mappings, &key);
    }

    return tmp;
}


/* UAT: FlexRay Mapping */
UAT_HEX_CB_DEF(spdu_flexray_mapping, channel, spdu_flexray_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_flexray_mapping, cycle, spdu_flexray_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_flexray_mapping, flexray_id, spdu_flexray_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_flexray_mapping, message_id, spdu_flexray_mapping_uat_t)

static void *
copy_spdu_flexray_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_flexray_mapping_uat_t *new_rec = (spdu_flexray_mapping_uat_t *)n;
    const spdu_flexray_mapping_uat_t *old_rec = (const spdu_flexray_mapping_uat_t *)o;

    new_rec->channel    = old_rec->channel;
    new_rec->cycle      = old_rec->cycle;
    new_rec->flexray_id = old_rec->flexray_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static bool
update_spdu_flexray_mapping(void *r, char **err) {
    spdu_flexray_mapping_uat_t *rec = (spdu_flexray_mapping_uat_t *)r;

    if (rec->cycle > 0xff) {
        *err = ws_strdup_printf("We currently only support 8 bit Cycles (Cycle: %i  Frame ID: %i)", rec->cycle, rec->flexray_id);
        return false;
    }

    if (rec->flexray_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit Frame IDs (Cycle: %i  Frame ID: %i)", rec->cycle, rec->flexray_id);
        return false;
    }

    return true;
}

static void
post_update_spdu_flexray_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_flexray_mappings) {
        g_hash_table_destroy(data_spdu_flexray_mappings);
        data_spdu_flexray_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_flexray_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_flexray_mappings == NULL || spdu_flexray_mapping == NULL) {
        return;
    }

    if (spdu_flexray_mapping_num > 0) {
        unsigned i;
        for (i = 0; i < spdu_flexray_mapping_num; i++) {
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            *key = spdu_flexray_mapping[i].flexray_id & 0xffff;
            *key |= (int64_t)(spdu_flexray_mapping[i].cycle & 0xff) << 16;
            *key |= (int64_t)(spdu_flexray_mapping[i].channel & 0xff) << 24;

            g_hash_table_insert(data_spdu_flexray_mappings, key, &spdu_flexray_mapping[i]);
        }
    }
}

static spdu_flexray_mapping_t *
get_flexray_mapping(uint8_t channel, uint8_t cycle, uint16_t flexray_id) {
    if (data_spdu_flexray_mappings == NULL) {
        return NULL;
    }

    int64_t key = ((int64_t)channel << 24) | ((int64_t)cycle << 16) | (int64_t)flexray_id;
    return (spdu_flexray_mapping_t *)g_hash_table_lookup(data_spdu_flexray_mappings, &key);
}


/* UAT: LIN Mapping */
UAT_HEX_CB_DEF(spdu_lin_mapping, frame_id, spdu_lin_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_lin_mapping, bus_id, spdu_lin_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_lin_mapping, message_id, spdu_lin_mapping_uat_t)

static void *
copy_spdu_lin_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_lin_mapping_uat_t *new_rec = (spdu_lin_mapping_uat_t *)n;
    const spdu_lin_mapping_uat_t *old_rec = (const spdu_lin_mapping_uat_t *)o;

    new_rec->frame_id = old_rec->frame_id;
    new_rec->bus_id = old_rec->bus_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static bool
update_spdu_lin_mapping(void *r, char **err) {
    spdu_lin_mapping_uat_t *rec = (spdu_lin_mapping_uat_t *)r;

    if (rec->frame_id > LIN_ID_MASK) {
        *err = ws_strdup_printf("LIN Frame IDs are only uint with 6 bits (ID: %i)", rec->frame_id);
        return false;
    }

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("LIN Bus IDs are only uint with 16 bits (ID: 0x%x, Bus ID: 0x%x)", rec->frame_id, rec->bus_id);
        return false;
    }

    return true;
}

static void
post_update_spdu_lin_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_lin_mappings) {
        g_hash_table_destroy(data_spdu_lin_mappings);
        data_spdu_lin_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_lin_mappings = g_hash_table_new_full(g_int_hash, g_int_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_lin_mappings == NULL || spdu_lin_mapping == NULL) {
        return;
    }

    if (spdu_lin_mapping_num > 0) {
        unsigned i;
        for (i = 0; i < spdu_lin_mapping_num; i++) {
            int *key = wmem_new(wmem_epan_scope(), int);
            *key = (spdu_lin_mapping[i].frame_id) & LIN_ID_MASK;
            *key |= ((spdu_lin_mapping[i].bus_id) & 0xffff) << 16;

            g_hash_table_insert(data_spdu_lin_mappings, key, &spdu_lin_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    register_signal_pdu_lin();
}

static spdu_lin_mapping_t *
get_lin_mapping(lin_info_t *lininfo) {
    if (data_spdu_lin_mappings == NULL) {
        return NULL;
    }

    int32_t key = ((lininfo->id) & LIN_ID_MASK) | (((lininfo->bus_id) & 0xffff) << 16);

    spdu_lin_mapping_uat_t *tmp = (spdu_lin_mapping_uat_t *)g_hash_table_lookup(data_spdu_lin_mappings, &key);

    if (tmp == NULL) {
        /* try again without Bus ID set */
        key = (lininfo->id) & LIN_ID_MASK;
        tmp = (spdu_lin_mapping_uat_t *)g_hash_table_lookup(data_spdu_lin_mappings, &key);
    }

    return tmp;
}

/* UAT: PDU Transport Mapping */
UAT_HEX_CB_DEF(spdu_pdu_transport_mapping, pdu_id, spdu_pdu_transport_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_pdu_transport_mapping, message_id, spdu_pdu_transport_mapping_uat_t)

static void *
copy_spdu_pdu_transport_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_pdu_transport_mapping_uat_t *new_rec = (spdu_pdu_transport_mapping_uat_t *)n;
    const spdu_pdu_transport_mapping_uat_t *old_rec = (const spdu_pdu_transport_mapping_uat_t *)o;

    new_rec->pdu_id = old_rec->pdu_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static bool
update_spdu_pdu_transport_mapping(void *r, char **err) {
    spdu_pdu_transport_mapping_uat_t *rec = (spdu_pdu_transport_mapping_uat_t *)r;

    if (rec->pdu_id > 0xffffffff) {
        *err = ws_strdup_printf("PDU-Transport IDs are only uint32 (ID: %i)", rec->pdu_id);
        return false;
    }

    return true;
}

static void
post_update_spdu_pdu_transport_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_pdu_transport_mappings) {
        g_hash_table_destroy(data_spdu_pdu_transport_mappings);
        data_spdu_pdu_transport_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_pdu_transport_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_pdu_transport_mappings == NULL || spdu_pdu_transport_mapping == NULL) {
        return;
    }

    if (spdu_pdu_transport_mapping_num > 0) {
        unsigned i;
        for (i = 0; i < spdu_pdu_transport_mapping_num; i++) {
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            *key = spdu_pdu_transport_mapping[i].pdu_id;

            g_hash_table_insert(data_spdu_pdu_transport_mappings, key, &spdu_pdu_transport_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    register_signal_pdu_pdu_transport();
}

static spdu_pdu_transport_mapping_t *
get_pdu_transport_mapping(uint32_t pdu_transport_id) {
    if (data_spdu_pdu_transport_mappings == NULL) {
        return NULL;
    }

    int64_t key = pdu_transport_id;
    return (spdu_pdu_transport_mapping_uat_t *)g_hash_table_lookup(data_spdu_pdu_transport_mappings, &key);
}

/* UAT: IPduM Mapping */
UAT_HEX_CB_DEF(spdu_ipdum_mapping, pdu_id, spdu_ipdum_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_ipdum_mapping, message_id, spdu_ipdum_mapping_uat_t)

static void *
copy_spdu_ipdum_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_ipdum_mapping_uat_t *new_rec = (spdu_ipdum_mapping_uat_t *)n;
    const spdu_ipdum_mapping_uat_t *old_rec = (const spdu_ipdum_mapping_uat_t *)o;

    new_rec->pdu_id = old_rec->pdu_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static bool
update_spdu_ipdum_mapping(void *r, char **err) {
    spdu_ipdum_mapping_uat_t *rec = (spdu_ipdum_mapping_uat_t *)r;

    if (rec->pdu_id > 0xffffffff) {
        *err = ws_strdup_printf("IPduM IDs are only uint32 (ID: %i)", rec->pdu_id);
        return false;
    }

    return true;
}

static void
post_update_spdu_ipdum_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_ipdum_mappings) {
        g_hash_table_destroy(data_spdu_ipdum_mappings);
        data_spdu_ipdum_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_ipdum_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_ipdum_mappings == NULL || spdu_ipdum_mapping == NULL) {
        return;
    }

    if (spdu_ipdum_mapping_num > 0) {
        unsigned i;
        for (i = 0; i < spdu_ipdum_mapping_num; i++) {
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            *key = spdu_ipdum_mapping[i].pdu_id;

            g_hash_table_insert(data_spdu_ipdum_mappings, key, &spdu_ipdum_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    register_signal_pdu_ipdum();
}

static spdu_ipdum_mapping_uat_t *
get_ipdum_mapping(uint32_t pdu_id) {
    if (data_spdu_ipdum_mappings == NULL) {
        return NULL;
    }

    int64_t key = pdu_id;
    return (spdu_ipdum_mapping_uat_t *)g_hash_table_lookup(data_spdu_ipdum_mappings, &key);
}

/* UAT: DLT Mapping */
UAT_CSTRING_CB_DEF(spdu_dlt_mapping, ecu_id, spdu_dlt_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_dlt_mapping, dlt_message_id, spdu_dlt_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_dlt_mapping, message_id, spdu_dlt_mapping_uat_t)

static void *
copy_spdu_dlt_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_dlt_mapping_uat_t *new_rec = (spdu_dlt_mapping_uat_t *)n;
    const spdu_dlt_mapping_uat_t *old_rec = (const spdu_dlt_mapping_uat_t *)o;

    if (old_rec->ecu_id) {
        new_rec->ecu_id = g_strdup(old_rec->ecu_id);
    } else {
        new_rec->ecu_id = NULL;
    }

    new_rec->dlt_message_id = old_rec->dlt_message_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static bool
update_spdu_dlt_mapping(void *r, char **err) {
    spdu_dlt_mapping_uat_t *rec = (spdu_dlt_mapping_uat_t *)r;

    if (rec->ecu_id != NULL && strlen(rec->ecu_id) > 4) {
        *err = ws_strdup_printf("ECU ID can only be up to 4 characters long!");
        return false;
    }

    return true;
}

static void
post_update_spdu_dlt_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_dlt_mappings) {
        g_hash_table_destroy(data_spdu_dlt_mappings);
        data_spdu_dlt_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_dlt_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_dlt_mappings == NULL || spdu_dlt_mapping == NULL) {
        return;
    }

    if (spdu_dlt_mapping_num > 0) {
        unsigned i;
        for (i = 0; i < spdu_dlt_mapping_num; i++) {
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            *key = spdu_dlt_mapping[i].dlt_message_id;
            *key |= (int64_t)(dlt_ecu_id_to_gint32(spdu_dlt_mapping[i].ecu_id)) << 32;

            g_hash_table_insert(data_spdu_dlt_mappings, key, &spdu_dlt_mapping[i]);
        }
    }
}

static spdu_dlt_mapping_uat_t *
get_dlt_mapping(uint32_t pdu_id, const char *ecu_id) {
    if (data_spdu_dlt_mappings == NULL) {
        return NULL;
    }

    int64_t key = pdu_id;
    key |= (int64_t)dlt_ecu_id_to_gint32(ecu_id) << 32;

    return (spdu_dlt_mapping_uat_t *)g_hash_table_lookup(data_spdu_dlt_mappings, &key);
}

/* UAT: UDS Mapping */
UAT_HEX_CB_DEF(spdu_uds_mapping, uds_address, spdu_uds_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_uds_mapping, service, spdu_uds_mapping_uat_t)
UAT_BOOL_CB_DEF(spdu_uds_mapping, reply, spdu_uds_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_uds_mapping, id, spdu_uds_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_uds_mapping, message_id, spdu_uds_mapping_uat_t)

static void *
copy_spdu_uds_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_uds_mapping_uat_t *new_rec = (spdu_uds_mapping_uat_t *)n;
    const spdu_uds_mapping_uat_t *old_rec = (const spdu_uds_mapping_uat_t *)o;

    new_rec->uds_address = old_rec->uds_address;
    new_rec->service = old_rec->service;
    new_rec->reply = old_rec->reply;
    new_rec->id = old_rec->id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static bool
update_spdu_uds_mapping(void *r, char **err) {
    spdu_uds_mapping_uat_t *rec = (spdu_uds_mapping_uat_t *)r;

    if (rec->id > 0xffff) {
        *err = g_strdup_printf("UDS IDs are only uint16!");
        return false;
    }

    if (rec->service > 0xff) {
        *err = g_strdup_printf("UDS Services are only uint8!");
        return false;
    }

    return true;
}

static void
post_update_spdu_uds_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_uds_mappings) {
        g_hash_table_destroy(data_spdu_uds_mappings);
        data_spdu_uds_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_uds_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_uds_mappings == NULL || spdu_uds_mapping == NULL) {
        return;
    }

    if (spdu_uds_mapping_num > 0) {
        unsigned i;
        uint32_t sid;
        for (i = 0; i < spdu_uds_mapping_num; i++) {
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            if (spdu_uds_mapping[i].reply) {
                sid = (0xff & spdu_uds_mapping[i].service) | UDS_REPLY_MASK;
            } else {
                sid = (0xff & spdu_uds_mapping[i].service);
            }

            *key = (uint64_t)(spdu_uds_mapping[i].uds_address) | ((uint64_t)(0xffff & spdu_uds_mapping[i].id) << 32) | ((uint64_t)sid << 48);
            g_hash_table_insert(data_spdu_uds_mappings, key, &spdu_uds_mapping[i]);

            /* Adding with 0xffffffff (ANY) as address too */
            key = wmem_new(wmem_epan_scope(), int64_t);
            *key = (uint64_t)(0xffffffff) | ((uint64_t)(0xffff & spdu_uds_mapping[i].id) << 32) | ((uint64_t)sid << 48);
            g_hash_table_insert(data_spdu_uds_mappings, key, &spdu_uds_mapping[i]);
        }
    }
}

static spdu_uds_mapping_uat_t *
get_uds_mapping(uds_info_t *uds_info) {
    uint32_t sid;

    DISSECTOR_ASSERT(uds_info);
    if (data_spdu_uds_mappings == NULL) {
        return NULL;
    }

    int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
    if (uds_info->reply) {
        sid = (0xff & uds_info->service) | UDS_REPLY_MASK;
    } else {
        sid = (0xff & uds_info->service);
    }
    *key = (uint64_t)(uds_info->uds_address) | ((uint64_t)(0xffff & uds_info->id) << 32) | ((uint64_t)sid << 48);

    spdu_uds_mapping_uat_t *tmp = (spdu_uds_mapping_uat_t *)g_hash_table_lookup(data_spdu_uds_mappings, key);

    /* if we cannot find it for the Address, lets look at MAXUINT32 */
    if (tmp == NULL) {
        *key = (uint64_t)(UINT32_MAX) | ((uint64_t)(0xffff & uds_info->id) << 32) | ((uint64_t)sid << 48);

        tmp = (spdu_uds_mapping_uat_t *)g_hash_table_lookup(data_spdu_uds_mappings, key);
    }

    wmem_free(wmem_epan_scope(), key);

    return tmp;
}

/* UAT: ISOBUS Mapping */
UAT_HEX_CB_DEF(spdu_isobus_mapping, pgn, spdu_isobus_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_isobus_mapping, bus_id, spdu_isobus_mapping_uat_t)
UAT_HEX_CB_DEF(spdu_isobus_mapping, message_id, spdu_isobus_mapping_uat_t)

static void *
copy_spdu_isobus_mapping_cb(void *n, const void *o, size_t size _U_) {
    spdu_isobus_mapping_uat_t *new_rec = (spdu_isobus_mapping_uat_t *)n;
    const spdu_isobus_mapping_uat_t *old_rec = (const spdu_isobus_mapping_uat_t *)o;

    new_rec->pgn = old_rec->pgn;
    new_rec->bus_id = old_rec->bus_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static bool
update_spdu_isobus_mapping(void *r, char **err) {
    spdu_isobus_mapping_uat_t *rec = (spdu_isobus_mapping_uat_t *)r;

    if (rec->pgn > 0x03ffff) {
        *err = g_strdup_printf("PGN %u > %u!", rec->pgn, 0x03ffff);
        return false;
    }

    return true;
}

static void
post_update_spdu_isobus_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_spdu_isobus_mappings) {
        g_hash_table_destroy(data_spdu_isobus_mappings);
        data_spdu_isobus_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_spdu_isobus_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &spdu_payload_free_key, NULL);

    if (data_spdu_isobus_mappings == NULL || spdu_isobus_mapping == NULL) {
        return;
    }

    if (spdu_isobus_mapping_num > 0) {
        unsigned i;
        for (i = 0; i < spdu_isobus_mapping_num; i++) {
            int64_t *key = wmem_new(wmem_epan_scope(), int64_t);
            *key = spdu_isobus_mapping[i].pgn;
            *key |= ((int64_t)(spdu_isobus_mapping[i].bus_id & 0xffff)) << 32;

            g_hash_table_insert(data_spdu_isobus_mappings, key, &spdu_isobus_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    register_signal_pdu_isobus();
}

static spdu_isobus_mapping_uat_t *
get_isobus_mapping(uint32_t pgn, uint16_t bus_id) {
    if (data_spdu_isobus_mappings == NULL) {
        return NULL;
    }

    /* key is PGN */
    int64_t key = ((int64_t)pgn) | ((int64_t)bus_id << 32);
    spdu_isobus_mapping_t *tmp = (spdu_isobus_mapping_t *)g_hash_table_lookup(data_spdu_isobus_mappings, &key);
    if (tmp == NULL) {
        /* try again without Bus ID set */
        key = (int64_t)pgn;
        tmp = (spdu_isobus_mapping_t *)g_hash_table_lookup(data_spdu_isobus_mappings, &key);
    }

    return tmp;
}

/**************************************
 ********     Expert Infos     ********
 **************************************/

static void
expert_spdu_payload_truncated(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int length) {
    proto_tree_add_expert(tree, pinfo, &ei_spdu_payload_truncated, tvb, offset, length);
    col_append_str(pinfo->cinfo, COL_INFO, " [Signal PDU: Truncated payload!]");
}

static void
expert_spdu_config_error(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int length) {
    proto_tree_add_expert(tree, pinfo, &ei_spdu_config_error, tvb, offset, length);
    col_append_str(pinfo->cinfo, COL_INFO, " [Signal PDU: Config Error!]");
}

static void
expert_spdu_unaligned_data(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, int offset, int length) {
    proto_tree_add_expert(tree, pinfo, &ei_spdu_unaligned_data, tvb, offset, length);
    col_append_str(pinfo->cinfo, COL_INFO, " [Signal PDU: Unaligned Data!]");
}


/**************************************
 ********  Aggregation Feature ********
 **************************************/

typedef struct _spdu_frame_data {
    double   sum;
    uint32_t count;
    double   avg;
    double   sum_time_value_products;
} spdu_frame_data_t;

typedef struct _spdu_aggregation {
    double   sum;
    uint32_t count;
    nstime_t start_time;

    nstime_t last_time;
    double   last_value;
    double   sum_time_value_products;
} spdu_aggregation_t;

static wmem_map_t *spdu_aggregation_data;

static spdu_aggregation_t *
get_or_create_aggregation_data(packet_info *pinfo, int hf_id_effective) {
    DISSECTOR_ASSERT(spdu_aggregation_data != NULL);
    DISSECTOR_ASSERT(hf_id_effective > 0);

    spdu_aggregation_t *data = (spdu_aggregation_t *)wmem_map_lookup(spdu_aggregation_data, GINT_TO_POINTER(hf_id_effective));

    if (data == NULL)
    {
        data = wmem_new0(wmem_file_scope(), spdu_aggregation_t);
        data->sum = 0;
        data->count = 0;
        data->start_time = pinfo->abs_ts;
        data->last_time = pinfo->abs_ts;
        data->sum_time_value_products = 0.0;
        wmem_map_insert(spdu_aggregation_data, GINT_TO_POINTER(hf_id_effective), data);
    }

    return data;
}


/**************************************
 ********   Dissector Helpers  ********
 **************************************/

/* There is similar code in tvbuff.c ... */

static double
spdu_ieee_double_from_64bits(uint64_t value) {
    union {
        double d;
        uint64_t w;
    } ieee_fp_union;

    ieee_fp_union.w = value;

    return ieee_fp_union.d;
}

static float
spdu_ieee_float_from_32bits(uint32_t value) {
    union {
        float d;
        uint32_t w;
    } ieee_fp_union;

    ieee_fp_union.w = value;

    return ieee_fp_union.d;
}


/**************************************
 ******** Signal PDU Dissector ********
 **************************************/

static uint64_t
dissect_shifted_and_shortened_uint(tvbuff_t *tvb, int offset, int offset_bits, int offset_end, int offset_end_bits, bool big_endian) {
    int32_t i;
    uint64_t value_guint64 = 0;

    if (!big_endian) {
        /* offset and offset_end need to be included */
        for (i = offset_end; i >= offset; i--) {

            if (i != offset_end || offset_end_bits != 0) {
                uint8_t tmp = tvb_get_uint8(tvb, i);
                int tmp_bit_count = 8;

                if (i == offset_end) {
                    tmp = tmp & (0xff >> (8 - offset_end_bits));
                    /* don't need to shift value, in the first round */
                    tmp_bit_count = 0;
                }

                if (i == offset) {
                    tmp >>= offset_bits;
                    tmp_bit_count = 8 - offset_bits;
                }

                value_guint64 <<= (unsigned)tmp_bit_count;
                value_guint64 |= tmp;
            }
        }
    } else {
        /* offset_end needs to be included. */
        for (i = offset; i <= offset_end; i++) {

            /* Do not read the last byte, if you do not need any bit of it. Else we read behind buffer! */
            if (i != offset_end || offset_end_bits != 0) {
                uint8_t tmp = tvb_get_uint8(tvb, i);
                int tmp_bit_count = 8;

                if (i == offset) {
                    tmp = tmp & (0xff >> offset_bits);
                    /* don't need to shift value, in the first round */
                    tmp_bit_count = 0;
                }

                if (i == offset_end) {
                    tmp >>= 8 - offset_end_bits;
                    tmp_bit_count = offset_end_bits;
                }

                value_guint64 <<= (unsigned)tmp_bit_count;
                value_guint64 |= tmp;
            }
        }
    }
    return value_guint64;
}

static int
dissect_spdu_payload_signal(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int offset, int offset_bits, spdu_signal_item_t *item, int *multiplexer) {
    DISSECTOR_ASSERT(item != NULL);
    DISSECTOR_ASSERT(item->hf_id_effective != NULL);

    proto_item *ti = NULL;
    proto_tree *subtree = NULL;

    char       *value_name = NULL;
    int         hf_id_effective = 0;
    int         hf_id_raw = 0;

    int offset_end = (int)((8 * offset + offset_bits + item->bitlength_encoded_type) / 8);
    int offset_end_bits = (int)((8 * offset + offset_bits + item->bitlength_encoded_type) % 8);

    int string_length = 0;
    int signal_length = offset_end - offset;
    if (offset_end_bits != 0) {
        signal_length++;
    }

    if (item->multiplex_value_only != -1 && item->multiplex_value_only != *multiplexer) {
        /* multiplexer set and we are in the wrong multiplex */
        return 0;
    }

    if (tvb_captured_length_remaining(tvb, offset) < signal_length) {
        expert_spdu_payload_truncated(tree, pinfo, tvb, offset, tvb_captured_length_remaining(tvb, offset));
        return -1;
    }

    if (!spdu_deserializer_show_hidden && item->hidden) {
        return (int)item->bitlength_encoded_type;
    }

    if (item != NULL && item->hf_id_effective != NULL) {
        hf_id_effective = *item->hf_id_effective;
    } else {
        expert_spdu_config_error(tree, pinfo, tvb, offset, signal_length);
    }

    if (item == NULL) {
        return tvb_captured_length_remaining(tvb, offset);
    }

    if (item->hf_id_raw != NULL) {
        hf_id_raw = *item->hf_id_raw;
    } else {
        expert_spdu_config_error(tree, pinfo, tvb, offset, signal_length);
    }

    uint64_t value_guint64 = dissect_shifted_and_shortened_uint(tvb, offset, offset_bits, offset_end, offset_end_bits, item->big_endian);

    /* we need to reset this because it is reused */
    ti = NULL;

    double value_gdouble = 0.0;

    switch (item->data_type) {
    case SPDU_DATA_TYPE_UINT: {
        value_gdouble = (double)value_guint64;

        if (item->multiplexer) {
            *multiplexer = (int)value_guint64;
        }

        /* show names for values */
        if (item->sig_val_names != NULL) {
            uint32_t i;
            for (i = 0; i < item->sig_val_names->num_of_items; i++) {
                if (item->sig_val_names->items[i].value_start <= value_guint64 && value_guint64 <= item->sig_val_names->items[i].value_end) {
                    value_name = item->sig_val_names->items[i].name;
                }
            }
        }

        /* scale and output */
        if (item->scale_or_offset) {
            value_gdouble = item->scaler * value_gdouble + item->offset;
            ti = proto_tree_add_double(tree, hf_id_effective, tvb, offset, signal_length, value_gdouble);
        } else {
            ti = proto_tree_add_uint64(tree, hf_id_effective, tvb, offset, signal_length, value_guint64);
        }
        if (value_name != NULL) {
            proto_item_append_text(ti, " [raw: 0x%" PRIx64 ": %s]", value_guint64, value_name);
        } else {
            proto_item_append_text(ti, " [raw: 0x%" PRIx64 "]", value_guint64);
        }

        subtree = proto_item_add_subtree(ti, ett_spdu_signal);
        ti = proto_tree_add_uint64(subtree, hf_id_raw, tvb, offset, signal_length, value_guint64);
        proto_item_append_text(ti, " (0x%" PRIx64 ")", value_guint64);
    }
        break;

    case SPDU_DATA_TYPE_INT: {
        int64_t value_gint64 = ws_sign_ext64(value_guint64, (int)item->bitlength_encoded_type);
        value_gdouble = (double)value_gint64;

        if (item->multiplexer) {
            *multiplexer = (int)value_gint64;
        }

        /* scale and output */
        if (item->scale_or_offset) {
            value_gdouble = item->scaler * value_gdouble + item->offset;
            ti = proto_tree_add_double(tree, hf_id_effective, tvb, offset, signal_length, value_gdouble);
        } else {
            ti = proto_tree_add_int64(tree, hf_id_effective, tvb, offset, signal_length, value_gint64);
        }
        if (value_name != NULL) {
            proto_item_append_text(ti, " [raw: %" PRIx64 ": %s]", value_gint64, value_name);
        } else {
            proto_item_append_text(ti, " [raw: %" PRIx64 "]", value_gint64);
        }

        subtree = proto_item_add_subtree(ti, ett_spdu_signal);
        ti = proto_tree_add_int64(subtree, hf_id_raw, tvb, offset, signal_length, value_gint64);
        proto_item_append_text(ti, " (0x%" PRIx64 ")", value_gint64);
    }
        break;

    case SPDU_DATA_TYPE_FLOAT: {
        value_gdouble = 0.0;

        switch (item->bitlength_base_type) {
        case 64:
            value_gdouble = spdu_ieee_double_from_64bits(value_guint64);
            break;
        case 32:
            value_gdouble = (double)spdu_ieee_float_from_32bits((uint32_t)value_guint64);
            break;
        default:
            /* not supported and cannot occur since the config is checked! */
            break;
        }

        /* scaler, offset, multiplexer not allowed by config checks */

        ti = proto_tree_add_double(tree, hf_id_effective, tvb, offset, signal_length, value_gdouble);

        if (value_name != NULL) {
            proto_item_append_text(ti, " [raw: 0x%" PRIx64 ": %s]", value_guint64, value_name);
        } else {
            proto_item_append_text(ti, " [raw: 0x%" PRIx64 "]", value_guint64);
        }

        subtree = proto_item_add_subtree(ti, ett_spdu_signal);
        ti = proto_tree_add_double(subtree, hf_id_raw, tvb, offset, signal_length, value_gdouble);
        proto_item_append_text(ti, " [raw: 0x%" PRIx64 "]", value_guint64);
    }
        break;

    case SPDU_DATA_TYPE_STRING:
        if (offset_bits != 0) {
            expert_spdu_unaligned_data(tree, pinfo, tvb, offset, 0);
        }

        proto_tree_add_item(tree, hf_id_effective, tvb, offset, signal_length, item->encoding);
        break;

    case SPDU_DATA_TYPE_STRINGZ:
        if (offset_bits != 0) {
            expert_spdu_unaligned_data(tree, pinfo, tvb, offset, 0);
        }
        proto_tree_add_item_ret_length(tree, hf_id_effective, tvb, offset, -1, item->encoding, &string_length);
        string_length *= 8;
        break;

    case SPDU_DATA_TYPE_UINT_STRING:
        if (offset_bits != 0) {
            expert_spdu_unaligned_data(tree, pinfo, tvb, offset, 0);
        }

        if (item->big_endian) {
            proto_tree_add_item_ret_length(tree, hf_id_effective, tvb, offset, signal_length, item->encoding | ENC_BIG_ENDIAN, &string_length);
        } else {
            proto_tree_add_item_ret_length(tree, hf_id_effective, tvb, offset, signal_length, item->encoding | ENC_LITTLE_ENDIAN, &string_length);
        }
        string_length = string_length * 8 - (int)item->bitlength_encoded_type;
        break;

    case SPDU_DATA_TYPE_NONE:
        /* do nothing */
        break;
    }

    /* hide raw value per default, if effective value is present */
    if (spdu_deserializer_hide_raw_values) {
        proto_item_set_hidden(ti);
    }

    /* Value passed in with value_gdouble, tree via subtree. */
    if (item->aggregate_sum || item->aggregate_avg || item->aggregate_int) {
        int hf_id_eff = *(item->hf_id_effective);
        spdu_aggregation_t *agg_data = get_or_create_aggregation_data(pinfo, hf_id_eff);
        spdu_frame_data_t *spdu_frame_data = (spdu_frame_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_signal_pdu, (uint32_t)hf_id_eff);

        if (!PINFO_FD_VISITED(pinfo)) {
            nstime_t delta;

            agg_data->sum += value_gdouble;
            agg_data->count++;

            nstime_delta(&delta, &(pinfo->abs_ts), &(agg_data->last_time));
            double delta_s = nstime_to_sec(&delta);

            if (delta_s > 0.0) {
                agg_data->sum_time_value_products += delta_s * agg_data->last_value;
                agg_data->last_time = pinfo->abs_ts;
            }
            agg_data->last_value = value_gdouble;

            if (!spdu_frame_data) {
                spdu_frame_data = wmem_new0(wmem_file_scope(), spdu_frame_data_t);
                p_add_proto_data(wmem_file_scope(), pinfo, proto_signal_pdu, (uint32_t)hf_id_eff, spdu_frame_data);
            }

            spdu_frame_data->sum = agg_data->sum;
            spdu_frame_data->count = agg_data->count;
            spdu_frame_data->avg = agg_data->sum / agg_data->count;
            spdu_frame_data->sum_time_value_products = agg_data->sum_time_value_products;
        }

        /* if frame data was not created on first pass, we cannot calculate it now */
        if (spdu_frame_data != NULL) {
            if (item->aggregate_sum) {
                proto_tree_add_double(subtree, *(item->hf_id_agg_sum), tvb, offset, signal_length, spdu_frame_data->sum);
            }
            if (item->aggregate_avg) {
                proto_tree_add_double(subtree, *(item->hf_id_agg_avg), tvb, offset, signal_length, spdu_frame_data->avg);
            }
            if (item->aggregate_int && (spdu_frame_data->sum_time_value_products == spdu_frame_data->sum_time_value_products)) {
                proto_tree_add_double(subtree, *(item->hf_id_agg_int), tvb, offset, signal_length, spdu_frame_data->sum_time_value_products);
            }
        }
    }

    return (int)item->bitlength_encoded_type + string_length;
}

static int
dissect_spdu_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root_tree, uint32_t id, bool update_column) {
    int offset = 0;
    int offset_bits = 0;
    int bits_parsed = 0;
    int multiplexer = -1;

    proto_item *ti = proto_tree_add_item(root_tree, proto_signal_pdu, tvb, offset, -1, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(ti, ett_spdu_payload);

    char *name = get_message_name(id);

    if (name != NULL) {
        proto_item_append_text(ti, ": %s", name);
        if (update_column) {
            col_append_fstr(pinfo->cinfo, COL_INFO, " (PDU: %s)", name);
            col_set_str(pinfo->cinfo, COL_PROTOCOL, SPDU_NAME);
        }
        ti = proto_tree_add_string(tree, hf_pdu_name, tvb, offset, -1, name);
        proto_item_set_generated(ti);
        proto_item_set_hidden(ti);
    }

    spdu_signal_list_t *paramlist = get_parameter_config(id);

    if (name == NULL && paramlist == NULL) {
        /* unknown message, lets skip */
        return 0;
    }

    if (!spdu_deserializer_activated) {
        /* we only receive a tvb with nothing behind us */
        proto_tree_add_text_internal(tree, tvb, 0, tvb_captured_length(tvb), "Dissection of payload is disabled. It can be enabled via protocol preferences.");
        return tvb_captured_length(tvb);
    }

    if (tvb_captured_length(tvb) > 0 && paramlist == NULL) {
        /* we only receive a tvb with nothing behind us */
        proto_tree_add_text_internal(tree, tvb, 0, tvb_captured_length(tvb), "Payload of PDU is not configured. See protocol preferences.");
        return tvb_captured_length(tvb);
    }

    if (root_tree == NULL && !proto_field_is_referenced(root_tree, proto_signal_pdu) && !paramlist->aggregation) {
        /* we only receive a tvb with nothing behind us */
        return tvb_captured_length(tvb);
    }

    int length = tvb_captured_length_remaining(tvb, 0);

    unsigned i;
    for (i = 0; i < paramlist->num_of_items; i++) {
        if (!paramlist->items[i].sig_val_names_valid) {
            paramlist->items[i].sig_val_names = get_signal_value_name_config(paramlist->id, paramlist->items[i].pos);
            paramlist->items[i].sig_val_names_valid = true;
        }
        bits_parsed = dissect_spdu_payload_signal(tvb, pinfo, tree, offset, offset_bits, &(paramlist->items[i]), &multiplexer);
        if (bits_parsed == -1) {
            break;
        }
        offset = (8 * offset + offset_bits + bits_parsed) / 8;
        offset_bits = (8 * offset + offset_bits + bits_parsed) % 8;
    }

    if (bits_parsed != -1 && length > offset + 1) {
        if (offset_bits == 0) {
            proto_tree_add_item(tree, hf_payload_unparsed, tvb, offset, length - offset, ENC_NA);
        } else {
            proto_tree_add_item(tree, hf_payload_unparsed, tvb, offset + 1, length - (offset + 1), ENC_NA);
        }
    }

    return offset;
}

static int
dissect_spdu_message_someip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    someip_info_t *someip_info = (someip_info_t *)data;

    DISSECTOR_ASSERT(someip_info);

    spdu_someip_mapping_t *someip_mapping = get_someip_mapping(someip_info->service_id, someip_info->method_id, someip_info->major_version, someip_info->message_type);

    if (someip_mapping == NULL) {
        return 0;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, someip_mapping->spdu_message_id, false);
}

static int
dissect_spdu_message_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    struct can_info *can_info = (struct can_info *)data;
    DISSECTOR_ASSERT(can_info);

    if (can_info->id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
        /* Error and RTR frames are not for us. */
        return 0;
    }

    spdu_can_mapping_t *can_mapping = get_can_mapping(can_info->id, can_info->bus_id);
    if (can_mapping == NULL) {
        return 0;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, can_mapping->message_id, true);
}

static bool
dissect_spdu_message_can_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_spdu_message_can(tvb, pinfo, tree, data) != 0;
}

static int
dissect_spdu_message_flexray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    struct flexray_info *flexray_data = (struct flexray_info *)data;
    DISSECTOR_ASSERT(flexray_data);

    spdu_flexray_mapping_t *flexray_mapping = get_flexray_mapping(flexray_data->ch, flexray_data->cc, flexray_data->id);

    if (flexray_mapping == NULL) {
        return 0;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, flexray_mapping->message_id, true);
}

static bool
dissect_spdu_message_flexray_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_spdu_message_flexray(tvb, pinfo, tree, data) != 0;
}

static int
dissect_spdu_message_lin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    lin_info_t *lininfo = (lin_info_t *)data;

    DISSECTOR_ASSERT(lininfo);

    spdu_lin_mapping_t *lin_mapping = get_lin_mapping(lininfo);

    if (lin_mapping == NULL) {
        return 0;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, lin_mapping->message_id, true);
}

static int
dissect_spdu_message_pdu_transport(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    pdu_transport_info_t *pdu_info = (pdu_transport_info_t *)data;
    DISSECTOR_ASSERT(pdu_info);

    spdu_pdu_transport_mapping_t *pdu_transport_mapping = get_pdu_transport_mapping(pdu_info->id);

    if (pdu_transport_mapping == NULL) {
        return 0;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, pdu_transport_mapping->message_id, false);
}

static int
dissect_spdu_message_ipdum(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    autosar_ipdu_multiplexer_info_t *pdu_info = (autosar_ipdu_multiplexer_info_t *)data;
    DISSECTOR_ASSERT(pdu_info);

    spdu_ipdum_mapping_uat_t *ipdum_mapping = get_ipdum_mapping(pdu_info->pdu_id);

    if (ipdum_mapping == NULL) {
        return 0;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, ipdum_mapping->message_id, true);
}

static bool
dissect_spdu_message_dlt_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    dlt_info_t *pdu_info = (dlt_info_t *)data;
    DISSECTOR_ASSERT(pdu_info);

    spdu_dlt_mapping_uat_t *dlt_mapping = get_dlt_mapping(pdu_info->message_id, pdu_info->ecu_id);

    if (dlt_mapping == NULL) {
        return false;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, dlt_mapping->message_id, true) != 0;
}

static bool
dissect_spdu_message_uds_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    uds_info_t *uds_info = (uds_info_t *)data;
    DISSECTOR_ASSERT(uds_info);

    spdu_uds_mapping_t *uds_mapping = get_uds_mapping(uds_info);
    if (uds_mapping == NULL) {
        return false;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, uds_mapping->message_id, false) != 0;
}

static int
dissect_spdu_message_isobus(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    isobus_info_t *isobus_info = (isobus_info_t *)data;
    DISSECTOR_ASSERT(isobus_info);

    spdu_isobus_mapping_t *isobus_mapping = get_isobus_mapping(isobus_info->pgn, isobus_info->bus_id);

    if (isobus_mapping == NULL) {
        return 0;
    }

    return dissect_spdu_payload(tvb, pinfo, tree, isobus_mapping->message_id, true);
}

/**************************************
 ********  Register Dissector  ********
 **************************************/

void
proto_register_signal_pdu(void) {
    module_t *spdu_module;
    expert_module_t *expert_module_lpdu;

    /* UAT for naming */
    uat_t *spdu_messages_uat;

    /* the UATs for parsing the message*/
    uat_t *spdu_signal_list_uat;
    uat_t *spdu_parameter_value_names_uat;

    /* UATs for mapping different incoming payloads to messages*/
    uat_t *spdu_someip_mapping_uat;
    uat_t *spdu_can_mapping_uat;
    uat_t *spdu_flexray_mapping_uat;
    uat_t *spdu_lin_mapping_uat;
    uat_t *spdu_pdu_transport_mapping_uat;
    uat_t *spdu_ipdum_mapping_uat;
    uat_t *spdu_dlt_mapping_uat;
    uat_t *spdu_uds_mapping_uat;
    uat_t *spdu_isobus_mapping_uat;

    /* data fields */
    static hf_register_info hf[] = {
        { &hf_pdu_name,
            { "Signal PDU Name", "signal_pdu.name",
            FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_payload_unparsed,
            { "Unparsed Payload", "signal_pdu.payload.unparsed",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_spdu_payload,
        &ett_spdu_signal,
    };

    /* UATs for user_data fields */
    static uat_field_t spdu_messages_uat_fields[] = {
        UAT_FLD_HEX(spdu_message_ident, id,                             "Signal PDU ID",         "ID of the Signal PDU"),
        UAT_FLD_CSTRING(spdu_message_ident, name,                       "Name",                  "Name of the Signal PDU"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_signal_list_uat_fields[] = {
        UAT_FLD_HEX(spdu_signal_list, id,                               "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_FLD_DEC(spdu_signal_list, num_of_params,                    "Number of Signals",     "Number of signals (16bit dec)"),

        UAT_FLD_DEC(spdu_signal_list, pos,                              "Signal Position",       "Position of signal (16bit dec, starting with 0)"),
        UAT_FLD_CSTRING(spdu_signal_list, name,                         "Signal Name",           "Name of signal (string)"),
        UAT_FLD_CSTRING(spdu_signal_list, filter_string,                "Filter String",         "Unique filter string that will be prepended with signal_pdu. (string)"),
        UAT_FLD_CSTRING(spdu_signal_list, data_type,                    "Data Type",             "Data type (string), [uint|int|float|string|stringz|uint_string|utf8_string|utf8_stringz|utf8_uint_string]"),
        UAT_FLD_BOOL(spdu_signal_list, big_endian,                      "Big Endian?",           "Big Endian encoded [false|true]"),
        UAT_FLD_DEC(spdu_signal_list, bitlength_base_type,              "Bitlength base type",   "Bitlength base type (uint32 dec). The length of the original type or the length of a single character."),
        UAT_FLD_DEC(spdu_signal_list, bitlength_encoded_type,           "Bitlength enc. type",   "Bitlength encoded type (uint32 dec). The shortened length of uints or the total length of string/utf8_string or the length of the uint_string/utf8_uint_string length field."),
        UAT_FLD_CSTRING(spdu_signal_list, scaler,                       "Scaler",                "Raw value is multiplied by this Scaler, e.g. 1.0 (double)"),
        UAT_FLD_CSTRING(spdu_signal_list, offset,                       "Offset",                "Scaled raw value is shifted by this Offset, e.g. 1.0 (double)"),
        UAT_FLD_BOOL(spdu_signal_list, multiplexer,                     "Multiplexer?",          "Is this used as multiplexer? [false|true]"),
        UAT_FLD_SIGNED_DEC(spdu_signal_list, multiplex_value_only,      "Multiplexer value",     "The multiplexer value for which this is relevant (-1 all)"),
        UAT_FLD_BOOL(spdu_signal_list, hidden,                          "Hidden?",               "Should this field be hidden in the dissection? [false|true]"),
        UAT_FLD_BOOL(spdu_signal_list, aggregate_sum,                   "Calc Sum?",             "Should this field be aggregated using sum function? [false|true]"),
        UAT_FLD_BOOL(spdu_signal_list, aggregate_avg,                   "Calc Avg?",             "Should this field be aggregated using average function? [false|true]"),
        UAT_FLD_BOOL(spdu_signal_list, aggregate_int,                   "Calc Int?",             "Should this field be aggregated using integrate function (sum of time value product)? [false|true]"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_parameter_value_name_uat_fields[] = {
        UAT_FLD_HEX(spdu_signal_value_names, id,                        "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_FLD_DEC(spdu_signal_value_names, pos,                       "Signal Position",       "Position of signal (16bit dec, starting with 0)"),
        UAT_FLD_DEC(spdu_signal_value_names, num_of_items,              "Number of Names",       "Number of Value Names defined (32bit dec)"),
        UAT_FLD_HEX64(spdu_signal_value_names, value_start,             "Value Range Start",     "Value Range Start (64bit uint hex)"),
        UAT_FLD_HEX64(spdu_signal_value_names, value_end,               "Value Range End",       "Value Range End (64bit uint hex)"),
        UAT_FLD_CSTRING(spdu_signal_value_names, value_name,            "Value Name",            "Name for the values in this range (string)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_someip_mapping_uat_fields[] = {
        UAT_FLD_HEX(spdu_someip_mapping, service_id,                    "SOME/IP Service ID",    "SOME/IP Service ID (16bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_someip_mapping, method_id,                     "SOME/IP Method ID",     "SOME/IP Method ID (16bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_someip_mapping, major_version,                 "SOME/IP Major Version", "SOME/IP Major Version (8bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_someip_mapping, message_type,                  "SOME/IP Message Type",  "SOME/IP Message Type (8bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_someip_mapping, spdu_message_id,               "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_can_mapping_uat_fields[] = {
        UAT_FLD_HEX(spdu_can_mapping, can_id,                           "CAN ID",                "CAN ID (32bit hex without leading 0x, highest bit 1 for extended, 0 for standard ID)"),
        UAT_FLD_HEX(spdu_can_mapping, bus_id,                           "Bus ID",                "Bus ID on which frame was recorded with 0=any (16bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_can_mapping, message_id,                       "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_flexray_mapping_uat_fields[] = {
        UAT_FLD_HEX(spdu_flexray_mapping, channel,                      "Channel",               "Channel (8bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_flexray_mapping, cycle,                        "Cycle",                 "Cycle (8bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_flexray_mapping, flexray_id,                   "Frame ID",              "Frame ID (16bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_flexray_mapping, message_id,                   "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_lin_mapping_uat_fields[] = {
        UAT_FLD_HEX(spdu_lin_mapping, frame_id,                         "Frame ID",              "LIN Frame ID (6bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_lin_mapping, bus_id,                           "Bus ID",                "Bus ID on which frame was recorded with 0=any (16bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_lin_mapping, message_id,                       "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_pdu_transport_mapping_uat_fields[] = {
        UAT_FLD_HEX(spdu_pdu_transport_mapping, pdu_id,                 "PDU ID",                "PDU ID (32bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_pdu_transport_mapping, message_id,             "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_ipdum_mapping_uat_fields[] = {
        UAT_FLD_HEX(spdu_ipdum_mapping, pdu_id,                         "PDU ID",                "PDU ID (32bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_ipdum_mapping, message_id,                     "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_dlt_mapping_uat_fields[] = {
        UAT_FLD_CSTRING(spdu_dlt_mapping, ecu_id,                       "ECU ID",                "ECU ID (4 ASCII chars only!)"),
        UAT_FLD_HEX(spdu_dlt_mapping, dlt_message_id,                   "DLT Message ID",        "Message ID (32bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_dlt_mapping, message_id,                       "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_uds_mapping_uat_fields[] = {
        UAT_FLD_HEX(spdu_uds_mapping, uds_address,                      "ECU Address",           "ECU Address (32bit hex without leading 0x, 0xffffffff means any)"),
        UAT_FLD_HEX(spdu_uds_mapping, service,                          "UDS Service",           "UDS Service (8bit hex without leading 0x)"),
        UAT_FLD_BOOL(spdu_uds_mapping, reply,                           "Reply",                 "Reply [false|true]"),
        UAT_FLD_HEX(spdu_uds_mapping, id,                               "ID",                    "ID (16bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_uds_mapping, message_id,                       "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t spdu_isobus_mapping_uat_fields[] = {
        UAT_FLD_HEX(spdu_isobus_mapping, pgn,                           "PGN",                   "PGN (18bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_isobus_mapping, bus_id,                        "Bus ID",                "Bus ID on which frame was recorded with 0=any (16bit hex without leading 0x)"),
        UAT_FLD_HEX(spdu_isobus_mapping, message_id,                    "Signal PDU ID",         "ID of the Signal PDU (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static ei_register_info ei[] = {
        { &ei_spdu_payload_truncated, {"signal_pdu.payload.expert_truncated",
          PI_MALFORMED, PI_ERROR, "Signal PDU: Truncated payload!", EXPFILL} },
        { &ei_spdu_config_error, {"signal_pdu.payload.config_error",
          PI_MALFORMED, PI_ERROR, "Signal PDU: Config Error (missing filter, filter duplicate, ...)!", EXPFILL} },
        { &ei_spdu_unaligned_data, {"signal_pdu.payload.unaligned_data",
          PI_MALFORMED, PI_ERROR, "Signal PDU: Unaligned data! Strings etc. need to be aligned to bytes!", EXPFILL} },
    };

    /* Register ETTs */
    proto_signal_pdu = proto_register_protocol(SPDU_NAME_LONG, SPDU_NAME, SPDU_NAME_FILTER);
    proto_register_field_array(proto_signal_pdu, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_module_lpdu = expert_register_protocol(proto_signal_pdu);
    expert_register_field_array(expert_module_lpdu, ei, array_length(ei));

    /* Register preferences */
    spdu_module = prefs_register_protocol(proto_signal_pdu, &proto_reg_handoff_signal_pdu);


    /* UATs */
    spdu_messages_uat = uat_new("Signal PDU Messages",
        sizeof(generic_one_id_string_t),                   /* record size           */
        DATAFILE_SPDU_MESSAGES,                            /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_message_ident,                      /* data_ptr              */
        &spdu_message_ident_num,                           /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_generic_one_id_string_cb,                     /* copy callback         */
        update_generic_one_identifier_32bit,               /* update callback       */
        free_generic_one_id_string_cb,                     /* free callback         */
        post_update_spdu_message_cb,                       /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_messages_uat_fields                           /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_signal_pdus", "Signal PDUs",
        "A table to define names of signal PDUs", spdu_messages_uat);

    prefs_register_static_text_preference(spdu_module, "empty1", "", NULL);
    prefs_register_static_text_preference(spdu_module, "dis", "PDU Dissection:", NULL);

    prefs_register_bool_preference(spdu_module, "payload_dissector_activated",
        "Dissect Payload",
        "Should the payload dissector be active?",
        &spdu_deserializer_activated);

    prefs_register_bool_preference(spdu_module, "payload_dissector_show_hidden",
        "Show hidden entries",
        "Should the payload dissector show entries marked as hidden in the configuration?",
        &spdu_deserializer_show_hidden);

    prefs_register_bool_preference(spdu_module, "payload_dissector_hide_raw_values",
        "Hide raw values",
        "Should the payload dissector hide raw values?",
        &spdu_deserializer_hide_raw_values);

    spdu_parameter_value_names_uat = uat_new("Signal Value Names",
        sizeof(spdu_signal_value_name_uat_t),              /* record size           */
        DATAFILE_SPDU_VALUE_NAMES,                         /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_signal_value_names,                 /* data_ptr              */
        &spdu_parameter_value_names_num,                   /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_signal_value_name_cb,                    /* copy callback         */
        update_spdu_signal_value_name,                     /* update callback       */
        free_spdu_signal_value_name_cb,                    /* free callback         */
        post_update_spdu_signal_list_and_value_names_cb,   /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_parameter_value_name_uat_fields               /* UAT field definitions */
    );

    /* value names must be for signals since we need this data for the later */
    prefs_register_uat_preference(spdu_module, "_spdu_parameter_value_names", "Value Names",
        "A table to define names of signal values", spdu_parameter_value_names_uat);


    spdu_signal_list_uat = uat_new("Signal PDU Signal List",
        sizeof(spdu_signal_list_uat_t),                    /* record size           */
        DATAFILE_SPDU_SIGNALS,                             /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_signal_list,                        /* data_ptr              */
        &spdu_signal_list_num,                             /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION | UAT_AFFECTS_FIELDS,
        NULL,                                              /* help                  */
        copy_spdu_signal_list_cb,                          /* copy callback         */
        update_spdu_signal_list,                           /* update callback       */
        free_spdu_signal_list_cb,                          /* free callback         */
        post_update_spdu_signal_list_and_value_names_cb,   /* post update callback  */
        reset_spdu_signal_list,                            /* reset callback        */
        spdu_signal_list_uat_fields                        /* UAT field definitions */
    );

    static const char *spdu_signal_list_uat_defaults_[] = {
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
        "FALSE", "FALSE", "FALSE" };
    uat_set_default_values(spdu_signal_list_uat, spdu_signal_list_uat_defaults_);

    prefs_register_uat_preference(spdu_module, "_spdu_signal_list", "Signal List",
        "A table to define names of signals", spdu_signal_list_uat);


    prefs_register_static_text_preference(spdu_module, "empty2", "", NULL);
    prefs_register_static_text_preference(spdu_module, "map", "Protocol Mappings:", NULL);


    spdu_someip_mapping_uat = uat_new("SOME/IP",
        sizeof(spdu_someip_mapping_uat_t),                 /* record size           */
        DATAFILE_SPDU_SOMEIP_MAPPING,                      /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_someip_mapping,                     /* data_ptr              */
        &spdu_someip_mapping_num,                          /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_someip_mapping_cb,                       /* copy callback         */
        update_spdu_someip_mapping,                        /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_someip_mapping_cb,                /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_someip_mapping_uat_fields                     /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_someip_mapping", "SOME/IP Mappings",
        "A table to map SOME/IP payloads to Signal PDUs", spdu_someip_mapping_uat);


    spdu_can_mapping_uat = uat_new("CAN",
        sizeof(spdu_can_mapping_uat_t),                    /* record size           */
        DATAFILE_SPDU_CAN_MAPPING,                         /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_can_mapping,                        /* data_ptr              */
        &spdu_can_mapping_num,                             /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_can_mapping_cb,                          /* copy callback         */
        update_spdu_can_mapping,                           /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_can_mapping_cb,                   /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_can_mapping_uat_fields                        /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_can_mapping", "CAN Mappings",
        "A table to map CAN payloads to Signal PDUs", spdu_can_mapping_uat);


    spdu_flexray_mapping_uat = uat_new("FlexRay",
        sizeof(spdu_flexray_mapping_uat_t),                /* record size           */
        DATAFILE_SPDU_FLEXRAY_MAPPING,                     /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_flexray_mapping,                    /* data_ptr              */
        &spdu_flexray_mapping_num,                         /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_flexray_mapping_cb,                      /* copy callback         */
        update_spdu_flexray_mapping,                       /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_flexray_mapping_cb,               /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_flexray_mapping_uat_fields                    /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_flexray_mapping", "FlexRay Mappings",
        "A table to map FlexRay payloads to Signal PDUs", spdu_flexray_mapping_uat);


    spdu_lin_mapping_uat = uat_new("LIN",
        sizeof(spdu_lin_mapping_uat_t),                    /* record size           */
        DATAFILE_SPDU_LIN_MAPPING,                         /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_lin_mapping,                        /* data_ptr              */
        &spdu_lin_mapping_num,                             /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_lin_mapping_cb,                          /* copy callback         */
        update_spdu_lin_mapping,                           /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_lin_mapping_cb,                   /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_lin_mapping_uat_fields                        /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_lin_mapping", "LIN Mappings",
        "A table to map LIN payloads to Signal PDUs", spdu_lin_mapping_uat);


    spdu_pdu_transport_mapping_uat = uat_new("PDU Transport",
        sizeof(spdu_pdu_transport_mapping_uat_t),          /* record size           */
        DATAFILE_SPDU_PDU_TRANSPORT_MAPPING,               /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_pdu_transport_mapping,              /* data_ptr              */
        &spdu_pdu_transport_mapping_num,                   /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_pdu_transport_mapping_cb,                /* copy callback         */
        update_spdu_pdu_transport_mapping,                 /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_pdu_transport_mapping_cb,         /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_pdu_transport_mapping_uat_fields              /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_pdu_transport_mapping", "PDU Transport Mappings",
        "A table to map PDU Transport payloads to Signal PDUs", spdu_pdu_transport_mapping_uat);


    spdu_ipdum_mapping_uat = uat_new("AUTOSAR I-PduM",
        sizeof(spdu_ipdum_mapping_uat_t),                  /* record size           */
        DATAFILE_SPDU_IPDUM_MAPPING,                       /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_ipdum_mapping,                      /* data_ptr              */
        &spdu_ipdum_mapping_num,                           /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_ipdum_mapping_cb,                        /* copy callback         */
        update_spdu_ipdum_mapping,                         /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_ipdum_mapping_cb,                 /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_ipdum_mapping_uat_fields                      /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_ipdum_mapping", "IPduM Mappings",
        "A table to map AUTOSAR I-PduM PDUs to Signal PDUs", spdu_ipdum_mapping_uat);


    spdu_dlt_mapping_uat = uat_new("DLT",
        sizeof(spdu_dlt_mapping_uat_t),                    /* record size           */
        DATAFILE_SPDU_DLT_MAPPING,                         /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_dlt_mapping,                        /* data_ptr              */
        &spdu_dlt_mapping_num,                             /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_dlt_mapping_cb,                          /* copy callback         */
        update_spdu_dlt_mapping,                           /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_dlt_mapping_cb,                   /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_dlt_mapping_uat_fields                        /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_dlt_mapping", "DLT Mappings",
        "A table to map DLT non-verbose Payloads to Signal PDUs", spdu_dlt_mapping_uat);


    spdu_uds_mapping_uat = uat_new("UDS",
        sizeof(spdu_uds_mapping_uat_t),                    /* record size           */
        DATAFILE_SPDU_UDS_MAPPING,                         /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_uds_mapping,                        /* data_ptr              */
        &spdu_uds_mapping_num,                             /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_uds_mapping_cb,                          /* copy callback         */
        update_spdu_uds_mapping,                           /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_uds_mapping_cb,                   /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_uds_mapping_uat_fields                        /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_uds_mapping", "UDS Mappings",
        "A table to map UDS payloads to Signal PDUs", spdu_uds_mapping_uat);


    spdu_isobus_mapping_uat = uat_new("ISOBUS",
        sizeof(spdu_isobus_mapping_uat_t),                 /* record size           */
        DATAFILE_SPDU_ISOBUS_MAPPING,                      /* filename              */
        true,                                              /* from profile          */
        (void **)&spdu_isobus_mapping,                     /* data_ptr              */
        &spdu_isobus_mapping_num,                          /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_spdu_isobus_mapping_cb,                       /* copy callback         */
        update_spdu_isobus_mapping,                        /* update callback       */
        NULL,                                              /* free callback         */
        post_update_spdu_isobus_mapping_cb,                /* post update callback  */
        NULL,                                              /* reset callback        */
        spdu_isobus_mapping_uat_fields                     /* UAT field definitions */
    );

    prefs_register_uat_preference(spdu_module, "_spdu_isobus_mapping", "ISOBUS Mappings",
        "A table to map ISOBUS payloads to Signal PDUs", spdu_isobus_mapping_uat);


    /* Aggregation Feature */
    spdu_aggregation_data = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
}

void
proto_reg_handoff_signal_pdu(void) {
    static bool initialized = false;

    if (!initialized) {
        signal_pdu_handle_someip = register_dissector("signal_pdu_over_someip", dissect_spdu_message_someip, proto_signal_pdu);

        signal_pdu_handle_can = register_dissector("signal_pdu_over_can", dissect_spdu_message_can, proto_signal_pdu);
        dissector_add_for_decode_as("can.subdissector", signal_pdu_handle_can);
        heur_dissector_add("can", dissect_spdu_message_can_heur, "Signal PDU over CAN", "signal_pdu_can_heur", proto_signal_pdu, HEURISTIC_ENABLE);

        signal_pdu_handle_flexray = register_dissector("signal_pdu_over_flexray", dissect_spdu_message_flexray, proto_signal_pdu);
        dissector_add_for_decode_as("flexray.subdissector", signal_pdu_handle_flexray);
        heur_dissector_add("flexray", dissect_spdu_message_flexray_heur, "Signal PDU over FlexRay", "signal_pdu_flexray_heur", proto_signal_pdu, HEURISTIC_ENABLE);

        signal_pdu_handle_lin = register_dissector("signal_pdu_over_lin", dissect_spdu_message_lin, proto_signal_pdu);

        signal_pdu_handle_pdu_transport = register_dissector("signal_pdu_over_pdu_transport", dissect_spdu_message_pdu_transport, proto_signal_pdu);

        signal_pdu_handle_ipdum = register_dissector("signal_pdu_over_IPduM", dissect_spdu_message_ipdum, proto_signal_pdu);

        heur_dissector_add("dlt", dissect_spdu_message_dlt_heur, "Signal PDU over DLT", "signal_pdu_dlt_heur", proto_signal_pdu, HEURISTIC_ENABLE);

        heur_dissector_add("uds", dissect_spdu_message_uds_heur, "Signal PDU over UDS", "signal_pdu_uds_heur", proto_signal_pdu, HEURISTIC_ENABLE);

        signal_pdu_handle_isobus = register_dissector("signal_pdu_over_ISOBUS", dissect_spdu_message_isobus, proto_signal_pdu);

        initialized = true;
    }
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
