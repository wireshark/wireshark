/* packet-autosar-ipdu-multiplexer.c
 * Dissector for AUTOSAR I-PDU Multiplexer.
 * By Dr. Lars Voelker <lars.voelker@technica-engineering.de>
 * Copyright 2021-2022 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 */

#include <config.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include "packet-autosar-ipdu-multiplexer.h"

#include <packet-socketcan.h>
#include <packet-flexray.h>
#include <packet-pdu-transport.h>
#include <packet-lin.h>

void proto_register_autosar_ipdu_multiplexer(void);
void proto_reg_handoff_autosar_ipdu_multiplexer(void);

/*
 * Dissector for AUTOSAR I-PDU Multiplexer
 *
 * See https ://www.autosar.org/fileadmin/user_upload/standards/classic/20-11/AUTOSAR_SWS_IPDUMultiplexer.pdf
 */

/* this protocol */
static int proto_ipdu_multiplexer = -1;
#define IPDUM_NAME "AUTOSAR I-PduM"

/* dissector handles - incoming messages */
static dissector_handle_t ipdum_handle_can              = NULL;
static dissector_handle_t ipdum_handle_flexray          = NULL;
static dissector_handle_t ipdum_handle_lin              = NULL;
static dissector_handle_t ipdum_handle_pdu_transport    = NULL;

/* subdissectors - outgoing messages */
static dissector_table_t subdissector_table;

/* header field */
static int hf_pdu                       = -1;
static int hf_pdu_id                    = -1;
static int hf_pdu_name                  = -1;
static int hf_payload_unparsed          = -1;

/* etts */
static gint ett_ipdum                   = -1;
static gint ett_ipdum_pdu               = -1;

/**************************************
 ********      UAT configs     ********
 **************************************/
#define DATAFILE_IPDUM_MESSAGES                         "AUTOSAR_IPDUM_Messages"
#define DATAFILE_IPDUM_CAN_MAPPING                      "AUTOSAR_IPDUM_Binding_CAN"
#define DATAFILE_IPDUM_FLEXRAY_MAPPING                  "AUTOSAR_IPDUM_Binding_FlexRay"
#define DATAFILE_IPDUM_LIN_MAPPING                      "AUTOSAR_IPDUM_Binding_LIN"
#define DATAFILE_IPDUM_PDU_TRANSPORT_MAPPING            "AUTOSAR_IPDUM_Binding_PDU_Transport"


typedef struct _ipdum_message_item {
    guint32     pos;
    guint32     pdu_id;
    gchar      *name;
    guint32     start_pos;
    guint32     bit_length;
    guint32     update_bit_pos;
} ipdum_message_item_t;

typedef struct _ipdum_message_list {
    guint32     id;
    guint32     num_of_items;

    ipdum_message_item_t *items;
} ipdum_message_list_t;

typedef struct _ipdum_message_list_uat {
    guint32     id;
    guint32     num_of_params;

    guint32     pos;
    guint32     pdu_id;
    gchar      *name;
    guint32     start_pos;
    guint32     bit_length;
    guint32     update_bit_pos;
} ipdum_message_list_uat_t;


typedef struct _ipdum__can_mapping {
    guint32     can_id;
    guint32     bus_id;
    guint32     message_id;
} ipdum_can_mapping_t;
typedef ipdum_can_mapping_t ipdum_can_mapping_uat_t;

typedef struct _ipdum_flexray_mapping {
    guint32     channel;
    guint32     cycle;
    guint32     frame_id;
    guint32     message_id;
} ipdum_flexray_mapping_t;
typedef ipdum_flexray_mapping_t ipdum_flexray_mapping_uat_t;

typedef struct _ipdum_lin_mapping {
    guint32     frame_id;
    guint32     bus_id;
    guint32     message_id;
} ipdum_lin_mapping_t;
typedef ipdum_lin_mapping_t ipdum_lin_mapping_uat_t;

typedef struct _ipdum_pdu_transport_mapping {
    guint32     pdu_id;
    guint32     message_id;
} ipdum_pdu_transport_mapping_t;
typedef ipdum_pdu_transport_mapping_t ipdum_pdu_transport_mapping_uat_t;

static ipdum_message_list_uat_t *ipdum_message_list = NULL;
static guint ipdum_message_list_num = 0;
static GHashTable *data_ipdum_messages = NULL;

static ipdum_can_mapping_t *ipdum_can_mapping = NULL;
static guint ipdum_can_mapping_num = 0;
static GHashTable *data_ipdum_can_mappings = NULL;

static ipdum_flexray_mapping_t *ipdum_flexray_mapping = NULL;
static guint ipdum_flexray_mapping_num = 0;
static GHashTable *data_ipdum_flexray_mappings = NULL;

static ipdum_lin_mapping_t *ipdum_lin_mapping = NULL;
static guint ipdum_lin_mapping_num = 0;
static GHashTable *data_ipdum_lin_mappings = NULL;

static ipdum_pdu_transport_mapping_t *ipdum_pdu_transport_mapping = NULL;
static guint ipdum_pdu_transport_mapping_num = 0;
static GHashTable *data_ipdum_pdu_transport_mappings = NULL;


/* UAT Callbacks and Helpers */

static void
ipdum_payload_free_key(gpointer key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
ipdum_payload_free_generic_data(gpointer data _U_) {
    /* currently nothing to be free */
}


/* UAT: I-PduM Message Config */
UAT_HEX_CB_DEF(ipdum_message_list, id, ipdum_message_list_uat_t)
UAT_DEC_CB_DEF(ipdum_message_list, num_of_params, ipdum_message_list_uat_t)
UAT_DEC_CB_DEF(ipdum_message_list, pos, ipdum_message_list_uat_t)
UAT_HEX_CB_DEF(ipdum_message_list, pdu_id, ipdum_message_list_uat_t)
UAT_CSTRING_CB_DEF(ipdum_message_list, name, ipdum_message_list_uat_t)
UAT_DEC_CB_DEF(ipdum_message_list, start_pos, ipdum_message_list_uat_t)
UAT_DEC_CB_DEF(ipdum_message_list, bit_length, ipdum_message_list_uat_t)
UAT_DEC_CB_DEF(ipdum_message_list, update_bit_pos, ipdum_message_list_uat_t)

static void *
copy_ipdum_message_list_cb(void *n, const void *o, size_t size _U_) {
    ipdum_message_list_uat_t        *new_rec = (ipdum_message_list_uat_t *)n;
    const ipdum_message_list_uat_t  *old_rec = (const ipdum_message_list_uat_t *)o;

    new_rec->id = old_rec->id;
    new_rec->num_of_params = old_rec->num_of_params;

    new_rec->pos = old_rec->pos;
    new_rec->pdu_id = old_rec->pdu_id;

    if (old_rec->name) {
        new_rec->name = g_strdup(old_rec->name);
    } else {
        new_rec->name = NULL;
    }

    new_rec->start_pos = old_rec->start_pos;
    new_rec->bit_length = old_rec->bit_length;
    new_rec->update_bit_pos = old_rec->update_bit_pos;

    return new_rec;
}

static gboolean
update_ipdum_message_list(void *r, char **err) {
    ipdum_message_list_uat_t *rec = (ipdum_message_list_uat_t *)r;

    if (rec->pos >= 0xffff) {
        *err = ws_strdup_printf("Position too big");
        return FALSE;
    }

    if (rec->num_of_params >= 0xffff) {
        *err = ws_strdup_printf("Number of PDUs too big");
        return FALSE;
    }

    if (rec->pos >= rec->num_of_params) {
        *err = ws_strdup_printf("Position >= Number of PDUs");
        return FALSE;
    }

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = ws_strdup_printf("Name cannot be empty");
        return FALSE;
    }

    return TRUE;
}

static void
free_ipdum_message_list_cb(void*r) {
    ipdum_message_list_uat_t *rec = (ipdum_message_list_uat_t *)r;
    if (rec->name) {
        g_free(rec->name);
        rec->name = NULL;
    }
}

static void
post_update_ipdum_message_list_read_in_data(ipdum_message_list_uat_t *data, guint data_num, GHashTable *ht) {
    if (ht == NULL || data == NULL || data_num == 0) {
        return;
    }

    if (data_num) {
        guint i = 0;
        for (i = 0; i < data_num; i++) {

            /* the hash table does not know about uint64, so we use int64*/
            gint64 *key = wmem_new(wmem_epan_scope(), gint64);
            *key = (guint32)data[i].id;

            ipdum_message_list_t *list = (ipdum_message_list_t *)g_hash_table_lookup(ht, key);
            if (list == NULL) {

                list = wmem_new(wmem_epan_scope(), ipdum_message_list_t);

                list->id = data[i].id;
                list->num_of_items = data[i].num_of_params;

                ipdum_message_item_t *items = (ipdum_message_item_t *)wmem_alloc0_array(wmem_epan_scope(), ipdum_message_item_t, data[i].num_of_params);

                list->items = items;

                /* create new entry ... */
                g_hash_table_insert(ht, key, list);
            } else {
                /* already present, deleting key */
                wmem_free(wmem_epan_scope(), key);
            }

            /* and now we add to item array */
            if (data[i].num_of_params == list->num_of_items && data[i].pos < list->num_of_items) {
                ipdum_message_item_t *item = &(list->items[data[i].pos]);

                /* we do not care if we overwrite param */
                item->pos = data[i].pos;
                item->pdu_id = data[i].pdu_id;
                item->name = g_strdup(data[i].name);
                item->start_pos = data[i].start_pos;
                item->bit_length = data[i].bit_length;
                item->update_bit_pos = data[i].update_bit_pos;
            }
        }
    }
}

static void
post_update_ipdum_message_list_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_ipdum_messages) {
        g_hash_table_destroy(data_ipdum_messages);
        data_ipdum_messages = NULL;
    }

    data_ipdum_messages = g_hash_table_new_full(g_int64_hash, g_int64_equal, &ipdum_payload_free_key, &ipdum_payload_free_generic_data);
    post_update_ipdum_message_list_read_in_data(ipdum_message_list, ipdum_message_list_num, data_ipdum_messages);
}

static ipdum_message_list_t *
get_message_config(guint32 id) {
    if (data_ipdum_messages == NULL) {
        return NULL;
    }

    gint64 key = (gint64)id;
    return (ipdum_message_list_t *)g_hash_table_lookup(data_ipdum_messages, &key);
}


/* UAT: CAN Binding Config */
UAT_HEX_CB_DEF(ipdum_can_mapping, can_id, ipdum_can_mapping_uat_t)
UAT_HEX_CB_DEF(ipdum_can_mapping, bus_id, ipdum_can_mapping_uat_t)
UAT_HEX_CB_DEF(ipdum_can_mapping, message_id, ipdum_can_mapping_uat_t)

static void *
copy_ipdum_can_mapping_cb(void *n, const void *o, size_t size _U_) {
    ipdum_can_mapping_uat_t       *new_rec = (ipdum_can_mapping_uat_t *)n;
    const ipdum_can_mapping_uat_t *old_rec = (const ipdum_can_mapping_uat_t *)o;

    new_rec->can_id = old_rec->can_id;
    new_rec->bus_id = old_rec->bus_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static gboolean
update_ipdum_can_mapping(void *r, char **err) {
    ipdum_can_mapping_uat_t *rec = (ipdum_can_mapping_uat_t *)r;

    if ((rec->can_id & (CAN_RTR_FLAG | CAN_ERR_FLAG)) != 0) {
        *err = g_strdup_printf("We currently do not support CAN IDs with RTR or Error Flag set (CAN_ID: 0x%x)", rec->can_id);
        return FALSE;
    }

    if ((rec->can_id & CAN_EFF_FLAG) == 0 && rec->can_id > CAN_SFF_MASK) {
        *err = g_strdup_printf("Standard CAN ID (EFF flag not set) cannot be bigger than 0x7ff (CAN_ID: 0x%x)", rec->can_id);
        return FALSE;
    }

    return TRUE;
}

static void
post_update_register_can(void) {
    if (ipdum_handle_can == NULL) {
        return;
    }

    dissector_delete_all("can.id", ipdum_handle_can);
    dissector_delete_all("can.extended_id", ipdum_handle_can);

    /* CAN: loop over all frame IDs in HT */
    if (data_ipdum_can_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_ipdum_can_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            gint32 id = (*(gint32*)tmp->data);

            if ((id & CAN_EFF_FLAG) == CAN_EFF_FLAG) {
                dissector_add_uint("can.extended_id", id & CAN_EFF_MASK, ipdum_handle_can);
            } else {
                dissector_add_uint("can.id", id & CAN_SFF_MASK, ipdum_handle_can);
            }
        }

        g_list_free(keys);
    }
}

static void
post_update_ipdum_can_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_ipdum_can_mappings) {
        g_hash_table_destroy(data_ipdum_can_mappings);
        data_ipdum_can_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_ipdum_can_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &ipdum_payload_free_key, NULL);

    if (data_ipdum_can_mappings == NULL || ipdum_can_mapping == NULL) {
        return;
    }

    if (ipdum_can_mapping_num > 0) {
        guint i;
        for (i = 0; i < ipdum_can_mapping_num; i++) {
            gint64 *key = wmem_new(wmem_epan_scope(), gint64);
            *key = ipdum_can_mapping[i].can_id;
            *key |= ((gint64)(ipdum_can_mapping[i].bus_id & 0xffff)) << 32;

            g_hash_table_insert(data_ipdum_can_mappings, key, &ipdum_can_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    post_update_register_can();
}

static ipdum_can_mapping_t *
get_can_mapping(guint32 id, guint16 bus_id) {
    if (data_ipdum_can_mappings == NULL) {
        return NULL;
    }

    gint64 key = ((gint64)id & (CAN_EFF_MASK | CAN_EFF_FLAG)) | ((gint64)bus_id << 32);
    ipdum_can_mapping_t *tmp = (ipdum_can_mapping_t *)g_hash_table_lookup(data_ipdum_can_mappings, &key);
    if (tmp == NULL) {
        /* try again without Bus ID set */
        key = id & (CAN_EFF_MASK | CAN_EFF_FLAG);
        tmp = (ipdum_can_mapping_t *)g_hash_table_lookup(data_ipdum_can_mappings, &key);
    }

    return tmp;
}


/* UAT: FlexRay Binding Config */
UAT_HEX_CB_DEF(ipdum_flexray_mapping, channel, ipdum_flexray_mapping_uat_t)
UAT_HEX_CB_DEF(ipdum_flexray_mapping, cycle, ipdum_flexray_mapping_uat_t)
UAT_HEX_CB_DEF(ipdum_flexray_mapping, frame_id, ipdum_flexray_mapping_uat_t)
UAT_HEX_CB_DEF(ipdum_flexray_mapping, message_id, ipdum_flexray_mapping_uat_t)

static void *
copy_ipdum_flexray_mapping_cb(void *n, const void *o, size_t size _U_) {
    ipdum_flexray_mapping_uat_t       *new_rec = (ipdum_flexray_mapping_uat_t *)n;
    const ipdum_flexray_mapping_uat_t *old_rec = (const ipdum_flexray_mapping_uat_t *)o;

    new_rec->channel = old_rec->channel;
    new_rec->cycle = old_rec->cycle;
    new_rec->frame_id = old_rec->frame_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static gboolean
update_ipdum_flexray_mapping(void *r, char **err) {
    ipdum_flexray_mapping_uat_t *rec = (ipdum_flexray_mapping_uat_t *)r;

    if (rec->cycle > 0xff) {
        *err = ws_strdup_printf("We currently only support 8 bit Cycles (Cycle: %i  Frame ID: %i)", rec->cycle, rec->frame_id);
        return FALSE;
    }

    if (rec->frame_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit Frame IDs (Cycle: %i  Frame ID: %i)", rec->cycle, rec->frame_id);
        return FALSE;
    }

    return TRUE;
}

static void
post_update_ipdum_flexray_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_ipdum_flexray_mappings) {
        g_hash_table_destroy(data_ipdum_flexray_mappings);
        data_ipdum_flexray_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_ipdum_flexray_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &ipdum_payload_free_key, NULL);

    if (data_ipdum_flexray_mappings == NULL || ipdum_flexray_mapping == NULL) {
        return;
    }

    if (ipdum_flexray_mapping_num > 0) {
        guint i;
        for (i = 0; i < ipdum_flexray_mapping_num; i++) {
            gint64 *key = wmem_new(wmem_epan_scope(), gint64);
            *key = ipdum_flexray_mapping[i].frame_id & 0xffff;
            *key |= ((gint64)ipdum_flexray_mapping[i].cycle & 0xff) << 16;
            *key |= ((gint64)ipdum_flexray_mapping[i].channel & 0xff) << 24;

            g_hash_table_insert(data_ipdum_flexray_mappings, key, &ipdum_flexray_mapping[i]);
        }
    }
}

static ipdum_flexray_mapping_t *
get_flexray_mapping(guint8 channel, guint8 cycle, guint16 flexray_id) {
    if (data_ipdum_flexray_mappings == NULL) {
        return NULL;
    }

    gint64 *key = wmem_new(wmem_epan_scope(), gint64);
    *key = (channel << 24) | (cycle << 16) | flexray_id;

    ipdum_flexray_mapping_t *tmp = (ipdum_flexray_mapping_t*)g_hash_table_lookup(data_ipdum_flexray_mappings, key);
    wmem_free(wmem_epan_scope(), key);

    return tmp;
}


/* UAT: LIN Binding Config */
UAT_HEX_CB_DEF(ipdum_lin_mapping, frame_id, ipdum_lin_mapping_uat_t)
UAT_HEX_CB_DEF(ipdum_lin_mapping, bus_id, ipdum_lin_mapping_uat_t)
UAT_HEX_CB_DEF(ipdum_lin_mapping, message_id, ipdum_lin_mapping_uat_t)

static void *
copy_ipdum_lin_mapping_cb(void *n, const void *o, size_t size _U_) {
    ipdum_lin_mapping_uat_t *new_rec = (ipdum_lin_mapping_uat_t *)n;
    const ipdum_lin_mapping_uat_t *old_rec = (const ipdum_lin_mapping_uat_t*)o;

    new_rec->frame_id = old_rec->frame_id;
    new_rec->bus_id = old_rec->bus_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static gboolean
update_ipdum_lin_mapping(void *r, char **err) {
    ipdum_lin_mapping_uat_t *rec = (ipdum_lin_mapping_uat_t *)r;

    if (rec->frame_id > LIN_ID_MASK) {
        *err = ws_strdup_printf("LIN Frame IDs are only uint with 6 bits (ID: %i)", rec->frame_id);
        return FALSE;
    }

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("LIN Bus IDs are only uint with 16 bits (ID: 0x%x, Bus ID: 0x%x)", rec->frame_id, rec->bus_id);
        return FALSE;
    }

    return TRUE;
}

static void
post_update_register_lin(void) {
    if (ipdum_handle_lin == NULL) {
        return;
    }

    dissector_delete_all("lin.frame_id", ipdum_handle_lin);

    /* LIN: loop over all frame IDs in HT */
    if (data_ipdum_lin_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_ipdum_lin_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            gint32 *id = (gint32*)tmp->data;
            /* we register the combination of bus and frame id */
            dissector_add_uint("lin.frame_id", *id, ipdum_handle_lin);
        }

        g_list_free(keys);
    }
}

static void
post_update_ipdum_lin_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_ipdum_lin_mappings) {
        g_hash_table_destroy(data_ipdum_lin_mappings);
        data_ipdum_lin_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_ipdum_lin_mappings = g_hash_table_new_full(g_int_hash, g_int_equal, &ipdum_payload_free_key, NULL);

    if (data_ipdum_lin_mappings == NULL || ipdum_lin_mapping == NULL) {
        return;
    }

    if (ipdum_lin_mapping_num > 0) {
        guint i;
        for (i = 0; i < ipdum_lin_mapping_num; i++) {
            gint *key = wmem_new(wmem_epan_scope(), gint);
            *key = (ipdum_lin_mapping[i].frame_id) & LIN_ID_MASK;
            *key |= ((ipdum_lin_mapping[i].bus_id) & 0xffff) << 16;

            g_hash_table_insert(data_ipdum_lin_mappings, key, &ipdum_lin_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    post_update_register_lin();
}

static ipdum_lin_mapping_t*
get_lin_mapping(lin_info_t *lininfo) {
    if (data_ipdum_lin_mappings == NULL) {
        return NULL;
    }

    gint32 key = ((lininfo->id) & LIN_ID_MASK) | (((lininfo->bus_id) & 0xffff) << 16);

    ipdum_lin_mapping_t *tmp = (ipdum_lin_mapping_t *)g_hash_table_lookup(data_ipdum_lin_mappings, &key);

    if (tmp == NULL) {
        /* try again without Bus ID set */
        key = (lininfo->id) & LIN_ID_MASK;
        tmp = (ipdum_lin_mapping_t *)g_hash_table_lookup(data_ipdum_lin_mappings, &key);
    }

    return tmp;
}


/* UAT: PDU Transport Binding Config */
UAT_HEX_CB_DEF(ipdum_pdu_transport_mapping, pdu_id, ipdum_pdu_transport_mapping_uat_t)
UAT_HEX_CB_DEF(ipdum_pdu_transport_mapping, message_id, ipdum_pdu_transport_mapping_uat_t)

static void *
copy_ipdum_pdu_transport_mapping_cb(void *n, const void *o, size_t size _U_) {
    ipdum_pdu_transport_mapping_uat_t *new_rec = (ipdum_pdu_transport_mapping_uat_t*)n;
    const ipdum_pdu_transport_mapping_uat_t *old_rec = (const ipdum_pdu_transport_mapping_uat_t*)o;

    new_rec->pdu_id = old_rec->pdu_id;
    new_rec->message_id = old_rec->message_id;

    return new_rec;
}

static gboolean
update_ipdum_pdu_transport_mapping(void *r, char **err) {
    ipdum_pdu_transport_mapping_uat_t *rec = (ipdum_pdu_transport_mapping_uat_t *)r;

    if (rec->pdu_id > 0xffffffff) {
        *err = ws_strdup_printf("PDU-Transport IDs are only uint32 (ID: %i)", rec->pdu_id);
        return FALSE;
    }

    return TRUE;
}

static void
post_update_register_pdu_transport(void) {
    if (ipdum_handle_pdu_transport == NULL) {
        return;
    }

    dissector_delete_all("pdu_transport.id", ipdum_handle_pdu_transport);

    /* PDU Transport: loop over all messages IDs in HT */
    if (data_ipdum_pdu_transport_mappings != NULL) {
        GList *keys = g_hash_table_get_keys(data_ipdum_pdu_transport_mappings);

        GList *tmp;
        for (tmp = keys; tmp != NULL; tmp = tmp->next) {
            gint64 *id = (gint64*)tmp->data;
            dissector_add_uint("pdu_transport.id", ((guint32)((guint64)(*id)) & 0xffffffff), ipdum_handle_pdu_transport);
        }

        g_list_free(keys);
    }
}

static void
post_update_ipdum_pdu_transport_mapping_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_ipdum_pdu_transport_mappings) {
        g_hash_table_destroy(data_ipdum_pdu_transport_mappings);
        data_ipdum_pdu_transport_mappings = NULL;
    }

    /* we don't need to free the data as long as we don't alloc it first */
    data_ipdum_pdu_transport_mappings = g_hash_table_new_full(g_int64_hash, g_int64_equal, &ipdum_payload_free_key, NULL);

    if (data_ipdum_pdu_transport_mappings == NULL || ipdum_pdu_transport_mapping == NULL) {
        return;
    }

    if (ipdum_pdu_transport_mapping_num > 0) {
        guint i;
        for (i = 0; i < ipdum_pdu_transport_mapping_num; i++) {
            gint64 *key = wmem_new(wmem_epan_scope(), gint64);
            *key = ipdum_pdu_transport_mapping[i].pdu_id;

            g_hash_table_insert(data_ipdum_pdu_transport_mappings, key, &ipdum_pdu_transport_mapping[i]);
        }
    }

    /* we need to make sure we register again */
    post_update_register_pdu_transport();
}

static ipdum_pdu_transport_mapping_t *
get_pdu_transport_mapping(guint32 pdu_transport_id) {
    if (data_ipdum_pdu_transport_mappings == NULL) {
        return NULL;
    }

    gint64 key = (gint64)pdu_transport_id;
    return (ipdum_pdu_transport_mapping_t *)g_hash_table_lookup(data_ipdum_pdu_transport_mappings, &key);
}

/**************************************
 ********      Dissection      ********
 **************************************/

static int
dissect_ipdum_payload(tvbuff_t *tvb, packet_info *pinfo, proto_tree *root_tree, guint32 id) {
    gint offset = 0;
    gint length = tvb_captured_length_remaining(tvb, 0);

    proto_item *ti = proto_tree_add_item(root_tree, proto_ipdu_multiplexer, tvb, offset, -1, ENC_NA);
    proto_tree *tree = proto_item_add_subtree(ti, ett_ipdum);

    ipdum_message_list_t *config = get_message_config(id);
    guint i;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, IPDUM_NAME);
    col_set_str(pinfo->cinfo, COL_INFO, IPDUM_NAME);

    if (config == NULL || config->num_of_items == 0) {
        proto_tree_add_item(tree, hf_payload_unparsed, tvb, offset, length, ENC_NA);
    } else {
        for (i = 0; i < config->num_of_items; i++) {
            gboolean update_bit_ok = true;

            if (config->items[i].update_bit_pos != 0xffff) {
                gint update_byte = config->items[i].update_bit_pos / 8;
                gint update_bit_mask = 1 << (config->items[i].update_bit_pos % 8);
                guint8 tmp = tvb_get_guint8(tvb, update_byte);
                update_bit_ok = (tmp & update_bit_mask) == update_bit_mask;
            }

            if (update_bit_ok) {
                gint start_byte = config->items[i].start_pos / 8;
                gint end_byte = (config->items[i].start_pos + config->items[i].bit_length) / 8;
                if ((config->items[i].start_pos + config->items[i].bit_length) % 8 != 0) {
                    end_byte++;
                }

                gint pdu_len = end_byte - start_byte;
                if (pdu_len > tvb_captured_length_remaining(tvb, offset + start_byte)) {
                    pdu_len = tvb_captured_length_remaining(tvb, offset + start_byte);
                }

                ti = proto_tree_add_item(tree, hf_pdu, tvb, offset + start_byte, pdu_len, ENC_NA);
                proto_tree *pdu_tree = proto_item_add_subtree(ti, ett_ipdum_pdu);
                proto_tree_add_string(pdu_tree, hf_pdu_name, tvb, offset + start_byte, pdu_len, config->items[i].name);
                proto_tree_add_uint(pdu_tree, hf_pdu_id, tvb, offset + start_byte, pdu_len, config->items[i].pdu_id);

                tvbuff_t *subtvb = tvb_new_subset_length(tvb, offset + start_byte, pdu_len);
                if (subtvb != NULL) {
                    autosar_ipdu_multiplexer_info_t pdu_t_info;
                    pdu_t_info.pdu_id = config->items[i].pdu_id;

                    dissector_try_uint_new(subdissector_table, config->items[i].pdu_id, subtvb, pinfo, root_tree, FALSE, (void *)(&pdu_t_info));
                }
            }
        }
    }
    return length;
}

static int
dissect_ipdum_message_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    struct can_info *can_info = (struct can_info *)data;
    DISSECTOR_ASSERT(can_info);

    if (can_info->id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
        /* Error and RTR frames are not for us. */
        return 0;
    }

    ipdum_can_mapping_t *can_mapping = get_can_mapping(can_info->id, can_info->bus_id);
    if (can_mapping == NULL) {
        return 0;
    }

    return dissect_ipdum_payload(tvb, pinfo, tree, can_mapping->message_id);
}

static gboolean
dissect_ipdum_message_can_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_ipdum_message_can(tvb, pinfo, tree, data) != 0;
}

static int
dissect_ipdum_message_flexray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    struct flexray_info *flexray_data = (struct flexray_info*)data;
    DISSECTOR_ASSERT(flexray_data);

    ipdum_flexray_mapping_t *flexray_mapping = get_flexray_mapping(flexray_data->ch, flexray_data->cc, flexray_data->id);

    if (flexray_mapping == NULL) {
        return 0;
    }

    return dissect_ipdum_payload(tvb, pinfo, tree, flexray_mapping->message_id);
}

static gboolean
dissect_ipdum_message_flexray_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return dissect_ipdum_message_flexray(tvb, pinfo, tree, data) != 0;
}

static int
dissect_ipdum_message_lin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    lin_info_t *lininfo = (lin_info_t *)data;
    DISSECTOR_ASSERT(lininfo);

    ipdum_lin_mapping_t *lin_mapping = get_lin_mapping(lininfo);

    if (lin_mapping == NULL) {
        return 0;
    }

    return dissect_ipdum_payload(tvb, pinfo, tree, lin_mapping->message_id);
}

static int
dissect_ipdum_message_pdu_transport(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    pdu_transport_info_t *pdu_info = (pdu_transport_info_t*)data;
    DISSECTOR_ASSERT(pdu_info);

    ipdum_pdu_transport_mapping_t *pdu_transport_mapping = get_pdu_transport_mapping(pdu_info->id);

    if (pdu_transport_mapping == NULL) {
        return 0;
    }

    return dissect_ipdum_payload(tvb, pinfo, tree, pdu_transport_mapping->message_id);
}


/**************************************
 ********  Register Dissector  ********
 **************************************/

void
proto_register_autosar_ipdu_multiplexer(void) {
    module_t   *ipdum_module;

    /* UAT for parsing the message */
    uat_t      *ipdum_message_uat;

    /* UATs for binding to protocol */
    uat_t      *ipdum_can_mapping_uat;
    uat_t      *ipdum_flexray_mapping_uat;
    uat_t      *ipdum_lin_mapping_uat;
    uat_t      *ipdum_pdu_transport_mapping_uat;

    static hf_register_info hf[] = {
        { &hf_pdu,
            { "PDU", "ipdum.pdu", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_pdu_id,
            { "PDU-ID", "ipdum.pdu.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_pdu_name,
            { "Name", "ipdum.pdu.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_payload_unparsed,
            { "Unparsed Payload", "ipdum.unparsed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_ipdum,
        &ett_ipdum_pdu,
    };

    static uat_field_t ipdum_message_list_uat_fields[] = {
        UAT_FLD_HEX(ipdum_message_list, id,                         "I-PduM Message ID",        "ID of the I-PduM Message (32bit hex without leading 0x)"),
        UAT_FLD_DEC(ipdum_message_list, num_of_params,              "Number of PDUs",           "Number of PDUs (16bit dec)"),

        UAT_FLD_DEC(ipdum_message_list, pos,                        "PDU Position",             "Position of PDU (16bit dec, starting with 0)"),
        UAT_FLD_HEX(ipdum_message_list, pdu_id,                     "PDU ID",                   "ID of the PDU (32bit hex without leading 0x)"),
        UAT_FLD_CSTRING(ipdum_message_list, name,                   "PDU Name",                 "Name of PDU (string)"),
        UAT_FLD_DEC(ipdum_message_list, start_pos,                  "PDU Start Pos (bits)",     "Start Position of PDU in bits (16bit dec, starting with 0)"),
        UAT_FLD_DEC(ipdum_message_list, bit_length,                 "PDU Length (bits)",        "Lenght of PDU in bits (16bit dec, starting with 0)"),
        UAT_FLD_DEC(ipdum_message_list, update_bit_pos,             "PDU Update Bit",           "Position of Update bit (16bit dec, starting with 0, 65535 disabled)"),
        UAT_END_FIELDS
    };

    static uat_field_t ipdum_can_mapping_uat_fields[] = {
        UAT_FLD_HEX(ipdum_can_mapping, can_id,                      "CAN ID",                   "CAN ID (32bit hex without leading 0x, highest bit 1 for extended, 0 for standard ID)"),
        UAT_FLD_HEX(ipdum_can_mapping, bus_id,                      "Bus ID",                   "Bus ID on which frame was recorded with 0=any (16bit hex without leading 0x)"),
        UAT_FLD_HEX(ipdum_can_mapping, message_id,                  "Message ID",               "ID of the I-PduM Config (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t ipdum_flexray_mapping_uat_fields[] = {
        UAT_FLD_HEX(ipdum_flexray_mapping, channel,                 "Channel",                  "Channel (8bit hex without leading 0x)"),
        UAT_FLD_HEX(ipdum_flexray_mapping, frame_id,                "Frame ID",                 "Frame ID (16bit hex without leading 0x)"),
        UAT_FLD_HEX(ipdum_flexray_mapping, cycle,                   "Cycle",                    "Cycle (8bit hex without leading 0x)"),
        UAT_FLD_HEX(ipdum_flexray_mapping, message_id,              "Message ID",               "ID of the I-PduM Config (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t ipdum_lin_mapping_uat_fields[] = {
        UAT_FLD_HEX(ipdum_lin_mapping, frame_id,                    "Frame ID",                 "LIN Frame ID (6bit hex without leading 0x)"),
        UAT_FLD_HEX(ipdum_lin_mapping, bus_id,                      "Bus ID",                   "Bus ID on which frame was recorded with 0=any (16bit hex without leading 0x)"),
        UAT_FLD_HEX(ipdum_lin_mapping, message_id,                  "Message ID",               "ID of the I-PduM Config (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };

    static uat_field_t ipdum_pdu_transport_mapping_uat_fields[] = {
        UAT_FLD_HEX(ipdum_pdu_transport_mapping, pdu_id,            "PDU ID",                   "PDU ID (32bit hex without leading 0x)"),
        UAT_FLD_HEX(ipdum_pdu_transport_mapping, message_id,        "Message ID",               "ID of the I-PduM Config (32bit hex without leading 0x)"),
        UAT_END_FIELDS
    };


    proto_ipdu_multiplexer = proto_register_protocol("AUTOSAR I-PDU Multiplexer", IPDUM_NAME, "ipdum");
    ipdum_module = prefs_register_protocol(proto_ipdu_multiplexer, NULL);

    proto_register_field_array(proto_ipdu_multiplexer, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    subdissector_table = register_dissector_table("ipdum.pdu.id", "I-PduM PDU ID", proto_ipdu_multiplexer, FT_UINT32, BASE_HEX);


    ipdum_message_uat = uat_new("I-PduM Message List",
        sizeof(ipdum_message_list_uat_t),                  /* record size           */
        DATAFILE_IPDUM_MESSAGES,                           /* filename              */
        TRUE,                                              /* from profile          */
        (void**)&ipdum_message_list,                       /* data_ptr              */
        &ipdum_message_list_num,                           /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_ipdum_message_list_cb,                        /* copy callback         */
        update_ipdum_message_list,                         /* update callback       */
        free_ipdum_message_list_cb,                        /* free callback         */
        post_update_ipdum_message_list_cb,                 /* post update callback  */
        NULL,                                              /* reset callback        */
        ipdum_message_list_uat_fields                      /* UAT field definitions */
    );

    prefs_register_uat_preference(ipdum_module, "_ipdum_message_list", "Message List",
                                  "A table to define messages and PDUs", ipdum_message_uat);


    prefs_register_static_text_preference(ipdum_module, "empty1", "", NULL);
    prefs_register_static_text_preference(ipdum_module, "map", "Protocol Mappings:", NULL);


    ipdum_can_mapping_uat = uat_new("CAN",
        sizeof(ipdum_can_mapping_uat_t),                   /* record size           */
        DATAFILE_IPDUM_CAN_MAPPING,                        /* filename              */
        TRUE,                                              /* from profile          */
        (void**)&ipdum_can_mapping,                        /* data_ptr              */
        &ipdum_can_mapping_num,                            /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL, /* help */                                   /* help                  */
        copy_ipdum_can_mapping_cb,                         /* copy callback         */
        update_ipdum_can_mapping,                          /* update callback       */
        NULL,                                              /* free callback         */
        post_update_ipdum_can_mapping_cb,                  /* post update callback  */
        NULL, /* reset */                                  /* reset callback        */
        ipdum_can_mapping_uat_fields                       /* UAT field definitions */
    );

    prefs_register_uat_preference(ipdum_module, "_ipdum_can_mapping", "CAN Mappings",
        "A table to map CAN payloads to I-PduM Message configuration", ipdum_can_mapping_uat);


    ipdum_flexray_mapping_uat = uat_new("FlexRay",
        sizeof(ipdum_flexray_mapping_uat_t),               /* record size           */
        DATAFILE_IPDUM_FLEXRAY_MAPPING,                    /* filename              */
        TRUE,                                              /* from profile          */
        (void**)&ipdum_flexray_mapping,                    /* data_ptr              */
        &ipdum_flexray_mapping_num,                        /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_ipdum_flexray_mapping_cb,                     /* copy callback         */
        update_ipdum_flexray_mapping,                      /* update callback       */
        NULL,                                              /* free callback         */
        post_update_ipdum_flexray_mapping_cb,              /* post update callback  */
        NULL,                                              /* reset callback        */
        ipdum_flexray_mapping_uat_fields                   /* UAT field definitions */
    );

    prefs_register_uat_preference(ipdum_module, "_ipdum_flexray_mapping", "FlexRay Mappings",
        "A table to map FlexRay payloads to I-PduM Message configuration", ipdum_flexray_mapping_uat);


    ipdum_lin_mapping_uat = uat_new("LIN",
        sizeof(ipdum_lin_mapping_uat_t),                   /* record size           */
        DATAFILE_IPDUM_LIN_MAPPING,                        /* filename              */
        TRUE,                                              /* from profile          */
        (void**)&ipdum_lin_mapping,                        /* data_ptr              */
        &ipdum_lin_mapping_num,                            /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_ipdum_lin_mapping_cb,                         /* copy callback         */
        update_ipdum_lin_mapping,                          /* update callback       */
        NULL,                                              /* free callback         */
        post_update_ipdum_lin_mapping_cb,                  /* post update callback  */
        NULL,                                              /* reset callback        */
        ipdum_lin_mapping_uat_fields                       /* UAT field definitions */
    );

    prefs_register_uat_preference(ipdum_module, "_ipdum_lin_mapping", "LIN Mappings",
        "A table to map LIN payloads to I-PduM Message configuration", ipdum_lin_mapping_uat);


    ipdum_pdu_transport_mapping_uat = uat_new("PDU Transport",
        sizeof(ipdum_pdu_transport_mapping_uat_t),         /* record size           */
        DATAFILE_IPDUM_PDU_TRANSPORT_MAPPING,              /* filename              */
        TRUE,                                              /* from profile          */
        (void**)&ipdum_pdu_transport_mapping,              /* data_ptr              */
        &ipdum_pdu_transport_mapping_num,                  /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                            /* but not fields        */
        NULL,                                              /* help                  */
        copy_ipdum_pdu_transport_mapping_cb,               /* copy callback         */
        update_ipdum_pdu_transport_mapping,                /* update callback       */
        NULL,                                              /* free callback         */
        post_update_ipdum_pdu_transport_mapping_cb,        /* post update callback  */
        NULL,                                              /* reset callback        */
        ipdum_pdu_transport_mapping_uat_fields             /* UAT field definitions */
    );

    prefs_register_uat_preference(ipdum_module, "_ipdum_pdu_transport_mapping", "PDU Transport Mappings",
        "A table to map PDU Transport payloads to I-PduM Message configuration", ipdum_pdu_transport_mapping_uat);
}

void
proto_reg_handoff_autosar_ipdu_multiplexer(void) {
    static gboolean initialized = FALSE;

    if (!initialized) {
        ipdum_handle_can = register_dissector("ipdu_multiplexer_over_can", dissect_ipdum_message_can, proto_ipdu_multiplexer);
        dissector_add_for_decode_as("can.subdissector", ipdum_handle_can);
        heur_dissector_add("can", dissect_ipdum_message_can_heur, "IPDU Multiplexer over CAN", "ipdu_multiplexer_can_heur", proto_ipdu_multiplexer, HEURISTIC_ENABLE);

        ipdum_handle_flexray = register_dissector("ipdu_multiplexer_over_flexray", dissect_ipdum_message_flexray, proto_ipdu_multiplexer);
        dissector_add_for_decode_as("flexray.subdissector", ipdum_handle_flexray);
        heur_dissector_add("flexray", dissect_ipdum_message_flexray_heur, "IPDU Multiplexer over FlexRay", "ipdu_multiplexer_flexray_heur", proto_ipdu_multiplexer, HEURISTIC_ENABLE);

        ipdum_handle_lin = register_dissector("ipdu_multiplexer_over_lin", dissect_ipdum_message_lin, proto_ipdu_multiplexer);

        ipdum_handle_pdu_transport = register_dissector("ipdu_multiplexer_over_pdu_transport", dissect_ipdum_message_pdu_transport, proto_ipdu_multiplexer);

        initialized = TRUE;
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
