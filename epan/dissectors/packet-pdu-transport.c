/* packet-pdu_transport.c
 * PDU Transport dissector for FDN and others.
 * By <lars.voelker@technica-engineering.de>
 * Copyright 2020-2020 Dr. Lars Voelker
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

 /*
  * This is a dissector for PDUs transported over UDP or TCP.
  * The transported PDUs are typically CAN, FlexRay, LIN, or other protocols.
  *
  * The format is as follows:
  *  uint32        ID
  *  uint32        length
  *  uint8[length] data
  *  (restart with ID, if more data exists)
  *
  * One known implementation of this protocol is the AUTOSAR Socket Adaptor
  * with Header Option turned on.
  * See AUTOSAR "Specification of Socket Adaptor" (SWS), Section 7.3 PDU Header option:
  * https://www.autosar.org/fileadmin/user_upload/standards/classic/20-11/AUTOSAR_SWS_SocketAdaptor.pdf
  */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/reassemble.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/dissectors/packet-pdu-transport.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

void proto_register_pdu_transport(void);
void proto_reg_handoff_pdu_transport(void);

static int proto_pdu_transport = -1;
static dissector_handle_t pdu_transport_handle_udp = NULL;
static dissector_handle_t pdu_transport_handle_tcp = NULL;

static dissector_table_t subdissector_table = NULL;

#define PDU_TRANSPORT_NAME "PDU Transport"
#define PDU_TRANSPORT_HDR_LEN 8

/* header field */
static int hf_pdu_transport_id = -1;
static int hf_pdu_transport_length = -1;
static int hf_pdu_transport_payload = -1;

/* protocol tree items */
static gint ett_pdu_transport = -1;

/* expert info items */
static expert_field ef_pdu_transport_message_truncated = EI_INIT;

/********* UATs *********/

typedef struct _generic_one_id_string {
    guint   id;
    gchar  *name;
} generic_one_id_string_t;

static void
pdu_transport_free_key(gpointer key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
simple_free(gpointer data _U_) {
    /* we need to free because of the g_strdup in post_update*/
    g_free(data);
}

/* ID -> Name */
static void *
copy_generic_one_id_string_cb(void* n, const void* o, size_t size _U_) {
    generic_one_id_string_t* new_rec = (generic_one_id_string_t*)n;
    const generic_one_id_string_t* old_rec = (const generic_one_id_string_t*)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->id = old_rec->id;
    return new_rec;
}

static gboolean
update_generic_one_identifier_32bit(void *r, char **err) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;

    if (rec->name == NULL || rec->name[0] == 0) {
        *err = g_strdup("Name cannot be empty");
        return FALSE;
    }

    return TRUE;
}

static void
free_generic_one_id_string_cb(void*r) {
    generic_one_id_string_t* rec = (generic_one_id_string_t*)r;
    /* freeing result of g_strdup */
    g_free(rec->name);
    rec->name = NULL;
}

static void
post_update_one_id_string_template_cb(generic_one_id_string_t *data, guint data_num, GHashTable *ht) {
    guint   i;
    int    *key = NULL;

    for (i = 0; i < data_num; i++) {
        key = wmem_new(wmem_epan_scope(), int);
        *key = data[i].id;

        g_hash_table_insert(ht, key, g_strdup(data[i].name));
    }
}

static char*
ht_lookup_name(GHashTable* ht, unsigned int identifier) {
    char           *tmp = NULL;
    unsigned int   *id = NULL;

    if (ht == NULL) {
        return NULL;
    }

    id = wmem_new(wmem_epan_scope(), unsigned int);
    *id = (unsigned int)identifier;
    tmp = (char *)g_hash_table_lookup(ht, id);
    wmem_free(wmem_epan_scope(), id);

    return tmp;
}

/*** UAT pdu_transport_CM_IDs ***/
#define DATAFILE_PDU_IDS                "PDU_Transport_identifiers"

static GHashTable *data_pdu_transport_pdus = NULL;
static generic_one_id_string_t* pdu_transport_pdus = NULL;
static guint pdu_transport_pdus_num = 0;

UAT_HEX_CB_DEF(pdu_transport_pdus, id, generic_one_id_string_t)
UAT_CSTRING_CB_DEF(pdu_transport_pdus, name, generic_one_id_string_t)

static void
post_update_pdu_transport_pdus_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_pdu_transport_pdus) {
        g_hash_table_destroy(data_pdu_transport_pdus);
        data_pdu_transport_pdus = NULL;
    }

    /* create new hash table */
    data_pdu_transport_pdus = g_hash_table_new_full(g_int_hash, g_int_equal, &pdu_transport_free_key, &simple_free);
    post_update_one_id_string_template_cb(pdu_transport_pdus, pdu_transport_pdus_num, data_pdu_transport_pdus);
}

static int
dissect_pdu_transport(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item         *ti_top = NULL;
    proto_item         *ti = NULL;
    proto_tree         *pdu_transport_tree = NULL;
    guint               offset = 0;
    tvbuff_t           *subtvb = NULL;
    gint                tmp = 0;

    guint32             length = 0;
    guint32             pdu_id = 0;
    const gchar        *descr;

    if (p_get_proto_data(pinfo->pool, pinfo, proto_pdu_transport, pinfo->curr_layer_num) != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_set_fence(pinfo->cinfo, COL_INFO);
    }

    col_set_str(pinfo->cinfo, COL_INFO, "PDU");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PDU_TRANSPORT_NAME);
    ti_top = proto_tree_add_item(tree, proto_pdu_transport, tvb, 0, -1, ENC_NA);
    pdu_transport_tree = proto_item_add_subtree(ti_top, ett_pdu_transport);

    if (tvb_captured_length_remaining(tvb, offset) < 8) {
        expert_add_info(pinfo, ti_top, &ef_pdu_transport_message_truncated);
    }

    /* taken from packet-ip.c
     * if pdu_transport is not referenced from any filters we don't need to worry about
     * generating any tree items.  We must do this after we created the actual
     * protocol above so that proto hier stat still works though.
     * XXX: Note that because of the following optimization expert items must
     *      not be generated inside of an 'if (tree) ...'
     *      so that Analyze ! Expert ...  will work.
     */

    if (!proto_field_is_referenced(tree, proto_pdu_transport)) {
        pdu_transport_tree = NULL;
    }

    ti = proto_tree_add_item_ret_uint(pdu_transport_tree, hf_pdu_transport_id, tvb, offset, 4, ENC_BIG_ENDIAN, &pdu_id);
    offset += 4;

    proto_tree_add_item_ret_uint(pdu_transport_tree, hf_pdu_transport_length, tvb, offset, 4, ENC_BIG_ENDIAN, &length);
    offset += 4;

    descr = ht_lookup_name(data_pdu_transport_pdus, pdu_id);

    if (descr != NULL) {
        proto_item_append_text(ti_top, ", ID 0x%x (%s), Length: %d", pdu_id, descr, length);
        proto_item_append_text(ti, " (%s)", descr);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (ID: 0x%x, %s)", pdu_id, descr);
    } else {
        proto_item_append_text(ti_top, ", ID 0x%x, Length: %d", pdu_id, length);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (ID: 0x%x)", pdu_id);
    }

    p_add_proto_data(pinfo->pool, pinfo, proto_pdu_transport, pinfo->curr_layer_num, GUINT_TO_POINTER(pdu_id));

    tmp = tvb_captured_length_remaining(tvb, offset);
    if ((gint)length <= tmp) {
        proto_tree_add_item(pdu_transport_tree, hf_pdu_transport_payload, tvb, offset, length, ENC_NA);
        subtvb = tvb_new_subset_length_caplen(tvb, offset, length, length);
    } else {
        proto_tree_add_item(pdu_transport_tree, hf_pdu_transport_payload, tvb, offset, tmp, ENC_NA);
        subtvb = tvb_new_subset_length_caplen(tvb, offset, tmp, length);
        expert_add_info(pinfo, ti_top, &ef_pdu_transport_message_truncated);
    }
    if (subtvb != NULL) {
        pdu_transport_info_t pdu_t_info;
        pdu_t_info.id = pdu_id;

        dissector_try_uint_new(subdissector_table, pdu_id, subtvb, pinfo, tree, FALSE, (void *)(&pdu_t_info));
    }
    offset += (gint)length;

    col_set_fence(pinfo->cinfo, COL_INFO);
    return offset;
}

static guint
get_pdu_transport_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void* data _U_) {
    return PDU_TRANSPORT_HDR_LEN + (guint)tvb_get_ntohl(tvb, offset + 4);
}

static int
dissect_pdu_transport_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    tcp_dissect_pdus(tvb, pinfo, tree, TRUE, PDU_TRANSPORT_HDR_LEN, get_pdu_transport_message_len, dissect_pdu_transport, data);
    return tvb_reported_length(tvb);
}

static int
dissect_pdu_transport_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return udp_dissect_pdus(tvb, pinfo, tree, PDU_TRANSPORT_HDR_LEN, NULL, get_pdu_transport_message_len, dissect_pdu_transport, data);
}


static void pdu_transport_id_prompt(packet_info *pinfo, gchar* result)
{
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "PDU Transport ID 0x%08x as",
               GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_pdu_transport, pinfo->curr_layer_num)));
}

static gpointer pdu_transport_id_value(packet_info *pinfo)
{
    /* Limitation: This only returns the last proto_data, since udp_dissect_pdus gives us the same layer for all. */
    return p_get_proto_data(pinfo->pool, pinfo, proto_pdu_transport, pinfo->curr_layer_num);
}

void
proto_register_pdu_transport(void) {
    module_t *pdu_transport_module = NULL;
    expert_module_t *expert_module_pdu_transport = NULL;
    uat_t *pdu_transport_pduid_uat = NULL;

    static hf_register_info hf[] = {
        { &hf_pdu_transport_id,
            { "ID", "pdu_transport.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_pdu_transport_length,
            { "Length", "pdu_transport.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_pdu_transport_payload,
            { "Payload", "pdu_transport.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static gint *ett[] = {
        &ett_pdu_transport,
    };

    static ei_register_info ei[] = {
    { &ef_pdu_transport_message_truncated,{ "pdu_transport.message_truncated",
      PI_MALFORMED, PI_ERROR, "PDU Transport Truncated message!", EXPFILL } },
    };

    /* Decode As handling */
    static build_valid_func  pdu_transport_da_build_value[1] = {pdu_transport_id_value};
    static decode_as_value_t pdu_transport_da_values = {pdu_transport_id_prompt, 1, pdu_transport_da_build_value};

    static decode_as_t pdu_transport_da = { "pdu_transport", "pdu_transport.id", 1, 0, &pdu_transport_da_values,
                                            NULL, NULL, decode_as_default_populate_list,
                                            decode_as_default_reset, decode_as_default_change, NULL };

    proto_pdu_transport = proto_register_protocol("PDU Transport Protocol", PDU_TRANSPORT_NAME, "pdu_transport");

    proto_register_field_array(proto_pdu_transport, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pdu_transport_module = prefs_register_protocol(proto_pdu_transport, NULL);
    expert_module_pdu_transport = expert_register_protocol(proto_pdu_transport);
    expert_register_field_array(expert_module_pdu_transport, ei, array_length(ei));

    static uat_field_t pdu_transport_cm_id_uat_fields[] = {
        UAT_FLD_HEX(pdu_transport_pdus, id, "ID", "ID  (hex uint32)"),
        UAT_FLD_CSTRING(pdu_transport_pdus, name, "Name", "Name of the PDU (string)"),
        UAT_END_FIELDS
    };

    pdu_transport_pduid_uat = uat_new("pdu_transport Capture Modules",
        sizeof(generic_one_id_string_t),        /* record size           */
        DATAFILE_PDU_IDS,                       /* filename              */
        TRUE,                                   /* from profile          */
        (void**)&pdu_transport_pdus,            /* data_ptr              */
        &pdu_transport_pdus_num,                /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_generic_one_id_string_cb,          /* copy callback         */
        update_generic_one_identifier_32bit,    /* update callback       */
        free_generic_one_id_string_cb,          /* free callback         */
        post_update_pdu_transport_pdus_cb,      /* post update callback  */
        NULL,                                   /* reset callback        */
        pdu_transport_cm_id_uat_fields          /* UAT field definitions */
    );

    prefs_register_uat_preference(pdu_transport_module, "_udf_pdu_transport_pdus", "PDUs",
        "A table to define names and IDs of PDUs", pdu_transport_pduid_uat);

    subdissector_table = register_dissector_table("pdu_transport.id", "PDU Transport ID", proto_pdu_transport, FT_UINT32, BASE_HEX);
    register_decode_as(&pdu_transport_da);
}

void
proto_reg_handoff_pdu_transport(void) {

    pdu_transport_handle_udp = register_dissector("pdu_transport_over_udp", dissect_pdu_transport_udp, proto_pdu_transport);
    pdu_transport_handle_tcp = register_dissector("pdu_transport_over_tcp", dissect_pdu_transport_tcp, proto_pdu_transport);

    dissector_add_uint_range_with_preference("udp.port", "", pdu_transport_handle_udp);
    dissector_add_uint_range_with_preference("tcp.port", "", pdu_transport_handle_tcp);
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
