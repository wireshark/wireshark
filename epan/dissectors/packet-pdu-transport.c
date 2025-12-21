/* packet-pdu_transport.c
 * PDU Transport dissector for FDN and others.
 * By <lars.voelker@technica-engineering.de>
 * Copyright 2020-2025 Dr. Lars Völker
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
  *  ID         (optional) [uint8, uint16, or uint32]
  *  Length     (optional) [uint8, uint16, or uint32]
  *  Data       uint8[length]
  *  (restart with ID, if more data exists and Length field present)
  *
  * The dissector will try to match in this order:
  *  Source and Destination port
  *  Destination port and Any for Source port
  *  Source port and Any for Destination port
  *  Any for both ports
  *
  *
  * One known implementation of this protocol is the AUTOSAR Socket Adaptor:
  *  With Header Option turned on: uint32 ID and uint32 Length.
  *  With Header Option turned off: no ID and no Length.
  *
  * See AUTOSAR "Specification of Socket Adaptor" (SWS), Section 7.3 PDU Header option:
  * https://www.autosar.org/fileadmin/standards/R24-11/CP/AUTOSAR_CP_SWS_SocketAdaptor.pdf
  */

#include <config.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include "packet-tcp.h"
#include <epan/reassemble.h>
#include "packet-udp.h"
#include "packet-pdu-transport.h"
#include <epan/decode_as.h>
#include <epan/proto_data.h>

void proto_register_pdu_transport(void);
void proto_reg_handoff_pdu_transport(void);

static int proto_pdu_transport;
static dissector_handle_t pdu_transport_handle_udp;
static dissector_handle_t pdu_transport_handle_tcp;

static dissector_table_t subdissector_table;

#define PDU_TRANSPORT_NAME "PDU Transport"
#define PDU_TRANSPORT_HDR_LEN 8

/* header field */
static int hf_pdu_transport_id;
static int hf_pdu_transport_name;
static int hf_pdu_transport_impl_id;
static int hf_pdu_transport_length;
static int hf_pdu_transport_payload;

/* protocol tree items */
static int ett_pdu_transport;

/* expert info items */
static expert_field ei_pdu_transport_message_truncated;

/********* UATs *********/

typedef struct _generic_one_id_string {
    unsigned   id;
    char   *name;
} generic_one_id_string_t;

/* ID -> Name */
static void *
copy_generic_one_id_string_cb(void *n, const void *o, size_t size _U_) {
    generic_one_id_string_t *new_rec = (generic_one_id_string_t *)n;
    const generic_one_id_string_t *old_rec = (const generic_one_id_string_t *)o;

    new_rec->name = g_strdup(old_rec->name);
    new_rec->id = old_rec->id;
    return new_rec;
}

static bool
update_generic_one_identifier_32bit(void *r, char **err) {
    generic_one_id_string_t *rec = (generic_one_id_string_t *)r;

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

/*** UAT PDU Transport PDUs - ID to Name lookup ***/
#define DATAFILE_PDU_IDS                "PDU_Transport_identifiers"

static GHashTable *data_pdu_transport_pdus;
static generic_one_id_string_t *pdu_transport_pdus;
static unsigned pdu_transport_pdus_num;

UAT_HEX_CB_DEF(pdu_transport_pdus, id, generic_one_id_string_t)
UAT_CSTRING_CB_DEF(pdu_transport_pdus, name, generic_one_id_string_t)

static void
post_update_pdu_transport_pdus_cb(void) {
    /* destroy old hash table, if it exists */
    if (data_pdu_transport_pdus) {
        g_hash_table_destroy(data_pdu_transport_pdus);
    }

    /* create new hash table */
    data_pdu_transport_pdus = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    for (unsigned i = 0; i < pdu_transport_pdus_num; i++) {
        g_hash_table_insert(data_pdu_transport_pdus, GUINT_TO_POINTER(pdu_transport_pdus[i].id), pdu_transport_pdus[i].name);
    }
}

static void
reset_pdu_transport_pdus_cb(void) {
    /* destroy hash table, if it exists */
    if (data_pdu_transport_pdus) {
        g_hash_table_destroy(data_pdu_transport_pdus);
        data_pdu_transport_pdus = NULL;
    }
}

static char *
lookup_pdu_name(uint32_t identifier) {
    if (data_pdu_transport_pdus == NULL) {
        return NULL;
    }

    return (char *)g_hash_table_lookup(data_pdu_transport_pdus, GUINT_TO_POINTER(identifier));
}


/*** UAT pdu_transport_extended_config ***/
#define DATAFILE_EXT_CFG                "PDU_Transport_extended_config"
#define PORT_ANY                        65536

typedef struct _pdu_transport_ext_cfg {
    bool        tcp;
    uint32_t    source_port;
    uint32_t    destination_port;
    uint32_t    size_of_id_field;
    uint32_t    size_of_length_field;
    uint32_t    default_id;
} pdu_transport_ext_cfg_t;


static GHashTable *data_pdu_transport_ext_cfg = NULL;
static pdu_transport_ext_cfg_t *pdu_transport_ext_cfg;
static unsigned pdu_transport_ext_cfg_num;

UAT_BOOL_CB_DEF(pdu_transport_ext_cfg, tcp, pdu_transport_ext_cfg_t)
UAT_DEC_CB_DEF(pdu_transport_ext_cfg, source_port, pdu_transport_ext_cfg_t)
UAT_DEC_CB_DEF(pdu_transport_ext_cfg, destination_port, pdu_transport_ext_cfg_t)
UAT_DEC_CB_DEF(pdu_transport_ext_cfg, size_of_id_field, pdu_transport_ext_cfg_t)
UAT_DEC_CB_DEF(pdu_transport_ext_cfg, size_of_length_field, pdu_transport_ext_cfg_t)
UAT_HEX_CB_DEF(pdu_transport_ext_cfg, default_id, pdu_transport_ext_cfg_t)

static void *
copy_pdu_transport_ext_cfg_cb(void *n, const void *o, size_t size _U_) {
    pdu_transport_ext_cfg_t *new_rec = (pdu_transport_ext_cfg_t *)n;
    const pdu_transport_ext_cfg_t *old_rec = (const pdu_transport_ext_cfg_t *)o;

    new_rec->tcp = old_rec->tcp;
    new_rec->source_port = old_rec->source_port;
    new_rec->destination_port = old_rec->destination_port;
    new_rec->size_of_id_field = old_rec->size_of_id_field;
    new_rec->size_of_length_field = old_rec->size_of_length_field;
    new_rec->default_id = old_rec->default_id;
    return new_rec;
}

static bool
update_pdu_transport_ext_cfg_cb(void *r, char **err) {
    pdu_transport_ext_cfg_t *rec = (pdu_transport_ext_cfg_t *)r;

    if (rec->source_port > UINT16_MAX && rec->source_port != PORT_ANY) {
        *err = g_strdup("Source Port can only be up to 65535 or Any (65536)!");
        return false;
    }

    if (rec->destination_port > UINT16_MAX && rec->destination_port != PORT_ANY) {
        *err = g_strdup("Destination Port can only be up to 65535 or Any (65536)!");
        return false;
    }

    if (rec->size_of_id_field != 0 && rec->size_of_id_field != 8 && rec->size_of_id_field != 16 && rec->size_of_id_field != 32) {
        *err = g_strdup("Size of the ID field can only be 0, 8, 16, or 32 bit!");
        return false;
    }

    if (rec->size_of_length_field != 0 && rec->size_of_length_field != 8 && rec->size_of_length_field != 16 && rec->size_of_length_field != 32) {
        *err = g_strdup("Size of the Length field can only be 0, 8, 16, or 32 bit!");
        return false;
    }

    return true;
}


static void
reset_pdu_transport_ext_cfg_cb(void) {
    /* destroy hash table, if it exists */
    if (data_pdu_transport_ext_cfg) {
        g_hash_table_destroy(data_pdu_transport_ext_cfg);
        data_pdu_transport_ext_cfg = NULL;
    }
}

static void
post_update_pdu_transport_ext_cfg_cb(void) {
    reset_pdu_transport_ext_cfg_cb();

    /* create new hash table */
    data_pdu_transport_ext_cfg = g_hash_table_new_full(g_direct_hash, g_direct_equal, NULL, NULL);

    for (unsigned i = 0; i < pdu_transport_ext_cfg_num; i++) {
        uint32_t key = 0;
        if (pdu_transport_ext_cfg[i].destination_port != PORT_ANY) {
            key |= pdu_transport_ext_cfg[i].destination_port;
        }

        if (pdu_transport_ext_cfg[i].source_port != PORT_ANY) {
            key |= (pdu_transport_ext_cfg[i].source_port << 16);
        }

        g_hash_table_insert(data_pdu_transport_ext_cfg, GUINT_TO_POINTER(key), &(pdu_transport_ext_cfg[i]));
    }
}

static void
lookup_extended_config(packet_info *pinfo _U_, unsigned *size_of_id, unsigned *size_of_len, uint32_t *default_id) {
    /* Set backward compatible defaults, in case we find no entry */
    *size_of_id = 4;
    *size_of_len = 4;

    if (data_pdu_transport_ext_cfg == NULL) {
        return;
    }

    if (pinfo->ptype != PT_TCP && pinfo->ptype != PT_UDP) {
        return;
    }

    bool tcp = (pinfo->ptype == PT_TCP);
    pdu_transport_ext_cfg_t *entry = NULL;

    /* Try Source-Port / Dest-Port */
    uint32_t key = pinfo->srcport << 16 | pinfo->destport;
    entry = (pdu_transport_ext_cfg_t *)g_hash_table_lookup(data_pdu_transport_ext_cfg, GUINT_TO_POINTER(key));

    /* If not found, try Any / Dest-Port */
    if (entry == NULL || entry->tcp != tcp) {
        key = pinfo->destport;
        entry = (pdu_transport_ext_cfg_t *)g_hash_table_lookup(data_pdu_transport_ext_cfg, GUINT_TO_POINTER(key));
    }

    /* If not found, try Source-Port / Any */
    if (entry == NULL || entry->tcp != tcp) {
        key = pinfo->srcport << 16;
        entry = (pdu_transport_ext_cfg_t *)g_hash_table_lookup(data_pdu_transport_ext_cfg, GUINT_TO_POINTER(key));
    }

    /* If not found, try Any / Any */
    if (entry == NULL || entry->tcp != tcp) {
        key = 0;
        entry = (pdu_transport_ext_cfg_t *)g_hash_table_lookup(data_pdu_transport_ext_cfg, GUINT_TO_POINTER(key));
    }

    if (entry != NULL && entry->tcp == tcp) {
        *size_of_id = entry->size_of_id_field / 8;
        *size_of_len = entry->size_of_length_field / 8;
        *default_id = entry->default_id;
    }
}


static int
dissect_pdu_transport(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item         *ti = NULL;
    unsigned            offset = 0;

    if (p_get_proto_data(pinfo->pool, pinfo, proto_pdu_transport, pinfo->curr_proto_layer_num) != NULL) {
        col_append_str(pinfo->cinfo, COL_INFO, ", ");
        col_set_fence(pinfo->cinfo, COL_INFO);
    }

    col_set_str(pinfo->cinfo, COL_INFO, "PDU");
    col_set_str(pinfo->cinfo, COL_PROTOCOL, PDU_TRANSPORT_NAME);
    proto_item *ti_top = proto_tree_add_item(tree, proto_pdu_transport, tvb, 0, -1, ENC_NA);
    proto_tree *pdu_transport_tree = proto_item_add_subtree(ti_top, ett_pdu_transport);

    unsigned size_of_id_field;
    unsigned size_of_len_field;
    uint32_t default_id;

    lookup_extended_config(pinfo, &size_of_id_field, &size_of_len_field, &default_id);

    if (tvb_captured_length_remaining(tvb, offset) < size_of_id_field + size_of_len_field) {
        expert_add_info(pinfo, ti_top, &ei_pdu_transport_message_truncated);
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

    uint32_t pdu_id;
    if (size_of_id_field > 0) {
        proto_tree_add_item_ret_uint(pdu_transport_tree, hf_pdu_transport_id, tvb, offset, size_of_id_field, ENC_BIG_ENDIAN, &pdu_id);
    } else {
        ti = proto_tree_add_uint(pdu_transport_tree, hf_pdu_transport_impl_id, tvb, 0, 0, default_id);
        proto_item_set_generated(ti);
        pdu_id = default_id;
    }
    const char *descr = lookup_pdu_name(pdu_id);

    if (descr != NULL) {
        ti = proto_tree_add_string(pdu_transport_tree, hf_pdu_transport_name, tvb, offset, 4, descr);
        proto_item_set_generated(ti);
    }
    offset += size_of_id_field;

    uint32_t length;
    if (size_of_len_field > 0) {
        proto_tree_add_item_ret_uint(pdu_transport_tree, hf_pdu_transport_length, tvb, offset, size_of_len_field, ENC_BIG_ENDIAN, &length);
        offset += size_of_len_field;
    } else {
        length = tvb_captured_length_remaining(tvb, offset);
    }

    if (descr != NULL) {
        proto_item_append_text(ti_top, ", ID 0x%x (%s), Length: %d", pdu_id, descr, length);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (ID: 0x%x, %s)", pdu_id, descr);
    } else {
        proto_item_append_text(ti_top, ", ID 0x%x, Length: %d", pdu_id, length);
        col_append_fstr(pinfo->cinfo, COL_INFO, " (ID: 0x%x)", pdu_id);
    }

    p_add_proto_data(pinfo->pool, pinfo, proto_pdu_transport, pinfo->curr_proto_layer_num, GUINT_TO_POINTER(pdu_id));

    int tmp = tvb_captured_length_remaining(tvb, offset);
    tvbuff_t *subtvb = NULL;
    if ((int)length <= tmp) {
        proto_tree_add_item(pdu_transport_tree, hf_pdu_transport_payload, tvb, offset, length, ENC_NA);
    } else {
        proto_tree_add_item(pdu_transport_tree, hf_pdu_transport_payload, tvb, offset, tmp, ENC_NA);
        expert_add_info(pinfo, ti_top, &ei_pdu_transport_message_truncated);
    }
    subtvb = tvb_new_subset_length(tvb, offset, length);
    if (subtvb != NULL) {
        pdu_transport_info_t pdu_t_info;
        pdu_t_info.id = pdu_id;
        dissector_try_uint_with_data(subdissector_table, pdu_id, subtvb, pinfo, tree, false, (void *)(&pdu_t_info));
    }
    offset += (int)length;

    col_set_fence(pinfo->cinfo, COL_INFO);
    return offset;
}

static unsigned
get_pdu_transport_message_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset, void *data _U_) {
    return PDU_TRANSPORT_HDR_LEN + (unsigned)tvb_get_ntohl(tvb, offset + 4);
}

static int
dissect_pdu_transport_tcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    tcp_dissect_pdus(tvb, pinfo, tree, true, PDU_TRANSPORT_HDR_LEN, get_pdu_transport_message_len, dissect_pdu_transport, data);
    return tvb_reported_length(tvb);
}

static int
dissect_pdu_transport_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data) {
    return udp_dissect_pdus(tvb, pinfo, tree, PDU_TRANSPORT_HDR_LEN, NULL, get_pdu_transport_message_len, dissect_pdu_transport, data);
}


static void
pdu_transport_id_prompt(packet_info *pinfo, char *result) {
    snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "PDU Transport ID 0x%08x as",
             GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_pdu_transport, pinfo->curr_proto_layer_num)));
}

static void *
pdu_transport_id_value(packet_info *pinfo) {
    /* Limitation: This only returns the last proto_data, since udp_dissect_pdus gives us the same layer for all. */
    return p_get_proto_data(pinfo->pool, pinfo, proto_pdu_transport, pinfo->curr_proto_layer_num);
}

void
proto_register_pdu_transport(void) {
    module_t *pdu_transport_module = NULL;
    expert_module_t *expert_module_pdu_transport = NULL;

    static hf_register_info hf[] = {
        { &hf_pdu_transport_id,
            { "ID", "pdu_transport.id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_pdu_transport_impl_id,
            { "ID (Implicit)", "pdu_transport.implicit_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},
        { &hf_pdu_transport_name,
            { "Name", "pdu_transport.name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }},
        { &hf_pdu_transport_length,
            { "Length", "pdu_transport.length", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},
        { &hf_pdu_transport_payload,
            { "Payload", "pdu_transport.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    static int *ett[] = {
        &ett_pdu_transport,
    };

    static ei_register_info ei[] = {
    { &ei_pdu_transport_message_truncated,{ "pdu_transport.message_truncated",
      PI_MALFORMED, PI_ERROR, "PDU Transport Truncated message!", EXPFILL } },
    };

    /* Decode As handling */
    static build_valid_func  pdu_transport_da_build_value[1] = {pdu_transport_id_value};
    static decode_as_value_t pdu_transport_da_values = {pdu_transport_id_prompt, 1, pdu_transport_da_build_value};

    static decode_as_t pdu_transport_da = { "pdu_transport", "pdu_transport.id", 1, 0, &pdu_transport_da_values,
                                            NULL, NULL, decode_as_default_populate_list,
                                            decode_as_default_reset, decode_as_default_change, NULL, NULL, NULL };

    proto_pdu_transport = proto_register_protocol("PDU Transport Protocol", PDU_TRANSPORT_NAME, "pdu_transport");

    proto_register_field_array(proto_pdu_transport, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    pdu_transport_module = prefs_register_protocol(proto_pdu_transport, NULL);
    expert_module_pdu_transport = expert_register_protocol(proto_pdu_transport);
    expert_register_field_array(expert_module_pdu_transport, ei, array_length(ei));


    /* UAT PDU-Transport PDUs */

    static uat_field_t pdu_transport_pdus_uat_fields[] = {
        UAT_FLD_HEX(pdu_transport_pdus, id, "ID", "ID  (hex uint32)"),
        UAT_FLD_CSTRING(pdu_transport_pdus, name, "Name", "Name of the PDU (string)"),
        UAT_END_FIELDS
    };


    uat_t *pdu_transport_pduid_uat  = uat_new("PDU Transport PDUs",
        sizeof(generic_one_id_string_t),        /* record size           */
        DATAFILE_PDU_IDS,                       /* filename              */
        true,                                   /* from profile          */
        (void**)&pdu_transport_pdus,            /* data_ptr              */
        &pdu_transport_pdus_num,                /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_generic_one_id_string_cb,          /* copy callback         */
        update_generic_one_identifier_32bit,    /* update callback       */
        free_generic_one_id_string_cb,          /* free callback         */
        post_update_pdu_transport_pdus_cb,      /* post update callback  */
        reset_pdu_transport_pdus_cb,            /* reset callback        */
        pdu_transport_pdus_uat_fields           /* UAT field definitions */
    );

    prefs_register_uat_preference(pdu_transport_module, "_udf_pdu_transport_pdus", "PDUs",
        "A table to define names and IDs of PDUs", pdu_transport_pduid_uat);


    /* UAT PDU-Transport Extended Config */

    static uat_field_t pdu_transport_ext_cfg_uat_fields[] = {
    UAT_FLD_BOOL(pdu_transport_ext_cfg, tcp, "TCP?", "TCP (true) / UDP (false)"),
    UAT_FLD_DEC(pdu_transport_ext_cfg, source_port, "Source Port", "Source Port  (Dec 0..65535, 65536 means any)"),
    UAT_FLD_DEC(pdu_transport_ext_cfg, destination_port, "Destination Port", "Destination Port  (Dec 0..65535, 65536 means any)"),
    UAT_FLD_DEC(pdu_transport_ext_cfg, size_of_id_field, "Size of ID", "Size of ID  (0, 8, 16, 32 bit. 32 bit is default)"),
    UAT_FLD_DEC(pdu_transport_ext_cfg, size_of_length_field, "Size of Length", "Size of Length  (0, 8, 16, 32 bit. 32 bit is default)"),
    UAT_FLD_HEX(pdu_transport_ext_cfg, default_id, "Default ID", "Default ID. Used, when no ID present in packet."),
    UAT_END_FIELDS
    };

    uat_t *pdu_transport_ext_cfg_uat = uat_new("PDU Transport Extended Config",
        sizeof(pdu_transport_ext_cfg_t),        /* record size           */
        DATAFILE_EXT_CFG,                       /* filename              */
        true,                                   /* from profile          */
        (void**)&pdu_transport_ext_cfg,         /* data_ptr              */
        &pdu_transport_ext_cfg_num,             /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                 /* but not fields        */
        NULL,                                   /* help                  */
        copy_pdu_transport_ext_cfg_cb,          /* copy callback         */
        update_pdu_transport_ext_cfg_cb,        /* update callback       */
        NULL,                                   /* free callback         */
        post_update_pdu_transport_ext_cfg_cb,   /* post update callback  */
        reset_pdu_transport_ext_cfg_cb,         /* reset callback        */
        pdu_transport_ext_cfg_uat_fields        /* UAT field definitions */
    );

    prefs_register_uat_preference(pdu_transport_module, "_udf_pdu_transport_ext_cfg", "Extended Config",
        "A table to define the extended configuration", pdu_transport_ext_cfg_uat);


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
