/* packet-flexray.c
 * Routines for FlexRay dissection
 * Copyright 2016, Roman Leonhartsberger <ro.leonhartsberger@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <epan/packet.h>
#include <epan/decode_as.h>
#include <epan/prefs.h>
#include <wiretap/wtap.h>
#include <epan/expert.h>
#include <epan/uat.h>

#include "packet-flexray.h"


void proto_reg_handoff_flexray(void);
void proto_register_flexray(void);

static dissector_handle_t flexray_handle;

static bool prefvar_try_heuristic_first;

static dissector_table_t subdissector_table;
static dissector_table_t flexrayid_subdissector_table;

static heur_dissector_list_t heur_subdissector_list;
static heur_dtbl_entry_t *heur_dtbl_entry;

static int proto_flexray;
static int hf_flexray_measurement_header_field;
static int hf_flexray_error_flags_field;
static int hf_flexray_frame_header;

static int hf_flexray_ti;
static int hf_flexray_ch;
static int hf_flexray_fcrc_err;
static int hf_flexray_hcrc_err;
static int hf_flexray_fes_err;
static int hf_flexray_cod_err;
static int hf_flexray_tss_viol;
static int hf_flexray_res;
static int hf_flexray_ppi;
static int hf_flexray_nfi;
static int hf_flexray_sfi;
static int hf_flexray_stfi;
static int hf_flexray_fid;
static int hf_flexray_pl;
static int hf_flexray_hcrc;
static int hf_flexray_cc;
static int hf_flexray_sl;
static int hf_flexray_flexray_id;

static int ett_flexray;
static int ett_flexray_measurement_header;
static int ett_flexray_error_flags;
static int ett_flexray_frame;

static int * const error_fields[] = {
    &hf_flexray_fcrc_err,
    &hf_flexray_hcrc_err,
    &hf_flexray_fes_err,
    &hf_flexray_cod_err,
    &hf_flexray_tss_viol,
    NULL
};

static expert_field ei_flexray_frame_payload_truncated;
static expert_field ei_flexray_symbol_frame;
static expert_field ei_flexray_error_flag;
static expert_field ei_flexray_stfi_flag;

#define FLEXRAY_FRAME 0x01
#define FLEXRAY_SYMBOL 0x02

#define FLEXRAY_HEADER_LENGTH 5

static const value_string flexray_type_names[] = {
    { FLEXRAY_FRAME, "FRAME" },
    { FLEXRAY_SYMBOL, "SYMB" },
    {0, NULL}
};

static const true_false_string flexray_channel_tfs = {
    "CHB",
    "CHA"
};

static const true_false_string flexray_nfi_tfs = {
    "False",
    "True"
};

/* Senders and Receivers UAT */
typedef struct _sender_receiver_config {
    unsigned  bus_id;
    unsigned  channel;
    unsigned  cycle;
    unsigned  frame_id;
    char *sender_name;
    char *receiver_name;
} sender_receiver_config_t;

#define DATAFILE_FR_SENDER_RECEIVER "FR_senders_receivers"

static GHashTable *data_sender_receiver;
static sender_receiver_config_t *sender_receiver_configs;
static unsigned sender_receiver_config_num;

UAT_HEX_CB_DEF(sender_receiver_configs, bus_id, sender_receiver_config_t)
UAT_HEX_CB_DEF(sender_receiver_configs, channel, sender_receiver_config_t)
UAT_HEX_CB_DEF(sender_receiver_configs, cycle, sender_receiver_config_t)
UAT_HEX_CB_DEF(sender_receiver_configs, frame_id, sender_receiver_config_t)
UAT_CSTRING_CB_DEF(sender_receiver_configs, sender_name, sender_receiver_config_t)
UAT_CSTRING_CB_DEF(sender_receiver_configs, receiver_name, sender_receiver_config_t)

static void *
copy_sender_receiver_config_cb(void *n, const void *o, size_t size _U_) {
    sender_receiver_config_t *new_rec = (sender_receiver_config_t *)n;
    const sender_receiver_config_t *old_rec = (const sender_receiver_config_t *)o;

    new_rec->bus_id = old_rec->bus_id;
    new_rec->channel = old_rec->channel;
    new_rec->cycle = old_rec->cycle;
    new_rec->frame_id = old_rec->frame_id;
    new_rec->sender_name = g_strdup(old_rec->sender_name);
    new_rec->receiver_name = g_strdup(old_rec->receiver_name);
    return new_rec;
}

static bool
update_sender_receiver_config(void *r, char **err) {
    sender_receiver_config_t *rec = (sender_receiver_config_t *)r;

    if (rec->channel > 0x1) {
        *err = ws_strdup_printf("We currently only support 0 and 1 for Channels (Channel: %i  Frame ID: %i)", rec->channel, rec->frame_id);
        return false;
    }

    if (rec->cycle > 0xff) {
        *err = ws_strdup_printf("We currently only support 8 bit Cycles (Cycle: %i  Frame ID: %i)", rec->cycle, rec->frame_id);
        return false;
    }

    if (rec->frame_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit Frame IDs (Cycle: %i  Frame ID: %i)", rec->cycle, rec->frame_id);
        return false;
    }

    if (rec->bus_id > 0xffff) {
        *err = ws_strdup_printf("We currently only support 16 bit bus identifiers (Bus ID: 0x%x)", rec->bus_id);
        return false;
    }

    return true;
}

static void
free_sender_receiver_config_cb(void *r) {
    sender_receiver_config_t *rec = (sender_receiver_config_t *)r;
    /* freeing result of g_strdup */
    g_free(rec->sender_name);
    rec->sender_name = NULL;
    g_free(rec->receiver_name);
    rec->receiver_name = NULL;
}

static uint64_t
sender_receiver_key(uint16_t bus_id, uint8_t channel, uint8_t cycle, uint16_t frame_id) {
    return ((uint64_t)bus_id << 32) | ((uint64_t)channel << 24) | ((uint64_t)cycle << 16) | frame_id;
}

static sender_receiver_config_t *
ht_lookup_sender_receiver_config(flexray_info_t *flexray_info) {
    sender_receiver_config_t *tmp = NULL;
    uint64_t                  key = 0;

    if (sender_receiver_configs == NULL) {
        return NULL;
    }

    key = sender_receiver_key(flexray_info->bus_id, flexray_info->ch, flexray_info->cc, flexray_info->id);
    tmp = (sender_receiver_config_t *)g_hash_table_lookup(data_sender_receiver, &key);

    if (tmp == NULL) {
        key = sender_receiver_key(0, flexray_info->ch, flexray_info->cc, flexray_info->id);
        tmp = (sender_receiver_config_t *)g_hash_table_lookup(data_sender_receiver, &key);
    }

    return tmp;
}

static void
sender_receiver_free_key(void *key) {
    wmem_free(wmem_epan_scope(), key);
}

static void
post_update_sender_receiver_cb(void) {
    unsigned i;
    uint64_t *key_id = NULL;

    /* destroy old hash table, if it exist */
    if (data_sender_receiver) {
        g_hash_table_destroy(data_sender_receiver);
        data_sender_receiver = NULL;
    }

    /* create new hash table */
    data_sender_receiver = g_hash_table_new_full(g_int64_hash, g_int64_equal, &sender_receiver_free_key, NULL);

    if (data_sender_receiver == NULL || sender_receiver_configs == NULL || sender_receiver_config_num == 0) {
        return;
    }

    for (i = 0; i < sender_receiver_config_num; i++) {
        key_id = wmem_new(wmem_epan_scope(), uint64_t);
        *key_id = sender_receiver_key(sender_receiver_configs[i].bus_id, sender_receiver_configs[i].channel,
                                      sender_receiver_configs[i].cycle, sender_receiver_configs[i].frame_id);
        g_hash_table_insert(data_sender_receiver, key_id, &sender_receiver_configs[i]);
    }
}

bool
flexray_set_source_and_destination_columns(packet_info *pinfo, flexray_info_t *flexray_info) {
    sender_receiver_config_t *tmp = ht_lookup_sender_receiver_config(flexray_info);

    if (tmp != NULL) {
        /* remove all addresses to support FlexRay as payload (e.g., TECMP) */
        clear_address(&pinfo->net_src);
        clear_address(&pinfo->dl_src);
        clear_address(&pinfo->src);
        clear_address(&pinfo->net_dst);
        clear_address(&pinfo->dl_dst);
        clear_address(&pinfo->dst);

        col_add_str(pinfo->cinfo, COL_DEF_SRC, tmp->sender_name);
        col_add_str(pinfo->cinfo, COL_DEF_DST, tmp->receiver_name);
        return true;
    }
    return false;
}

uint32_t
flexray_calc_flexrayid(uint16_t bus_id, uint8_t channel, uint16_t frame_id, uint8_t cycle) {
    /* Bus-ID 4bit->4bit | Channel 1bit->4bit | Frame ID 11bit->16bit | Cycle 6bit->8bit */

    return (uint32_t)(bus_id & 0xf) << 28 |
           (uint32_t)(channel & 0x0f) << 24 |
           (uint32_t)(frame_id & 0xffff) << 8 |
           (uint32_t)(cycle & 0xff);
}

uint32_t
flexray_flexrayinfo_to_flexrayid(flexray_info_t *flexray_info) {
    return flexray_calc_flexrayid(flexray_info->bus_id, flexray_info->ch, flexray_info->id, flexray_info->cc);
}

bool
flexray_call_subdissectors(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, flexray_info_t *flexray_info, const bool use_heuristics_first) {
    uint32_t flexray_id = flexray_flexrayinfo_to_flexrayid(flexray_info);

    /* lets try an exact match first */
    if (dissector_try_uint_new(flexrayid_subdissector_table, flexray_id, tvb, pinfo, tree, true, flexray_info)) {
        return true;
    }

    /* lets try with BUS-ID = 0 (any) */
    if (dissector_try_uint_new(flexrayid_subdissector_table, flexray_id & ~FLEXRAY_ID_BUS_ID_MASK, tvb, pinfo, tree, true, flexray_info)) {
        return true;
    }

    /* lets try with cycle = 0xff (any) */
    if (dissector_try_uint_new(flexrayid_subdissector_table, flexray_id | FLEXRAY_ID_CYCLE_MASK, tvb, pinfo, tree, true, flexray_info)) {
        return true;
    }

    /* lets try with BUS-ID = 0 (any) and cycle = 0xff (any) */
    if (dissector_try_uint_new(flexrayid_subdissector_table, (flexray_id & ~FLEXRAY_ID_BUS_ID_MASK) | FLEXRAY_ID_CYCLE_MASK, tvb, pinfo, tree, true, flexray_info)) {
        return true;
    }

    if (!use_heuristics_first) {
        if (!dissector_try_payload_new(subdissector_table, tvb, pinfo, tree, false, flexray_info)) {
            if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, flexray_info)) {
                return false;
            }
        }
    } else {
        if (!dissector_try_heuristic(heur_subdissector_list, tvb, pinfo, tree, &heur_dtbl_entry, flexray_info)) {
            if (!dissector_try_payload_new(subdissector_table, tvb, pinfo, tree, false, flexray_info)) {
                return false;
            }
        }
    }

    return true;
}

static int
dissect_flexray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
    proto_item *ti;
    proto_tree *flexray_tree, *measurement_tree;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FLEXRAY");
    col_clear(pinfo->cinfo, COL_INFO);

    ti = proto_tree_add_item(tree, proto_flexray, tvb, 0, -1, ENC_NA);
    flexray_tree = proto_item_add_subtree(ti, ett_flexray);

    /* Measurement Header [1 Byte] */
    ti = proto_tree_add_item(flexray_tree, hf_flexray_measurement_header_field, tvb, 0, 1, ENC_BIG_ENDIAN);
    measurement_tree = proto_item_add_subtree(ti, ett_flexray_measurement_header);

    bool flexray_channel_is_b;
    proto_tree_add_item_ret_boolean(measurement_tree, hf_flexray_ch, tvb, 0, 1, ENC_BIG_ENDIAN, &flexray_channel_is_b);

    uint32_t frame_type;
    proto_tree_add_item_ret_uint(measurement_tree, hf_flexray_ti, tvb, 0, 1, ENC_BIG_ENDIAN, &frame_type);
    col_add_fstr(pinfo->cinfo, COL_INFO, "%s:", val_to_str(frame_type, flexray_type_names, "Unknown (0x%02x)"));

    if (frame_type == FLEXRAY_FRAME) {
        proto_tree *error_flags_tree, *flexray_frame_tree;
        bool call_subdissector = true;

        /* Error Flags [1 Byte] */
        ti = proto_tree_add_bitmask(flexray_tree, tvb, 1, hf_flexray_error_flags_field, ett_flexray_error_flags, error_fields, ENC_BIG_ENDIAN);
        error_flags_tree = proto_item_add_subtree(ti, ett_flexray_error_flags);

        uint8_t error_flags = tvb_get_uint8(tvb, 1) & 0x1f;
        if (error_flags) {
            expert_add_info(pinfo, error_flags_tree, &ei_flexray_error_flag);
            call_subdissector = false;
        }

        /* FlexRay Frame [5 Bytes + Payload]*/
        int flexray_frame_length = tvb_captured_length(tvb) - 2;

        proto_item *ti_header = proto_tree_add_item(flexray_tree, hf_flexray_frame_header, tvb, 2, -1, ENC_NA);
        flexray_frame_tree = proto_item_add_subtree(ti_header, ett_flexray_frame);

        bool nfi, sfi, stfi;
        proto_tree_add_item(flexray_frame_tree, hf_flexray_res, tvb, 2, 1, ENC_NA);
        proto_tree_add_item(flexray_frame_tree, hf_flexray_ppi, tvb, 2, 1, ENC_NA);
        proto_tree_add_item_ret_boolean(flexray_frame_tree, hf_flexray_nfi, tvb, 2, 1, ENC_NA, &nfi);
        proto_tree_add_item_ret_boolean(flexray_frame_tree, hf_flexray_sfi, tvb, 2, 1, ENC_NA, &sfi);
        proto_tree_add_item_ret_boolean(flexray_frame_tree, hf_flexray_stfi, tvb, 2, 1, ENC_NA, &stfi);

        if (stfi && !sfi) {
            expert_add_info(pinfo, flexray_frame_tree, &ei_flexray_stfi_flag);
            call_subdissector = false;
        }

        uint32_t flexray_id;
        proto_tree_add_item_ret_uint(flexray_frame_tree, hf_flexray_fid, tvb, 2, 2, ENC_BIG_ENDIAN, &flexray_id);
        col_append_fstr(pinfo->cinfo, COL_INFO, " ID %4d", flexray_id);

        if (flexray_id == 0) {
            call_subdissector = false;
        }

        uint32_t flexray_pl;
        proto_tree_add_item_ret_uint(flexray_frame_tree, hf_flexray_pl, tvb, 4, 1, ENC_BIG_ENDIAN, &flexray_pl);
        int flexray_reported_payload_length = 2 * flexray_pl;
        int flexray_current_payload_length = flexray_frame_length - FLEXRAY_HEADER_LENGTH;
        bool payload_truncated = flexray_reported_payload_length > flexray_current_payload_length;

        if (flexray_reported_payload_length < flexray_current_payload_length) {
            flexray_current_payload_length = MAX(0, flexray_reported_payload_length);
        }

        proto_tree_add_item(flexray_frame_tree, hf_flexray_hcrc, tvb, 4, 3, ENC_BIG_ENDIAN);

        uint32_t flexray_cc;
        proto_tree_add_item_ret_uint(flexray_frame_tree, hf_flexray_cc, tvb, 6, 1, ENC_BIG_ENDIAN, &flexray_cc);
        col_append_fstr(pinfo->cinfo, COL_INFO, " CC %2d", flexray_cc);

        if (nfi) {
            if (payload_truncated) {
                expert_add_info(pinfo, flexray_frame_tree, &ei_flexray_frame_payload_truncated);
                call_subdissector = false;
            }

            if (tvb != NULL && flexray_current_payload_length > 0) {
                col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, 7, flexray_current_payload_length, ' '));
            }

        } else {
            call_subdissector = false;
            col_append_fstr(pinfo->cinfo, COL_INFO, "   NF");

            /* Payload is optional on Null Frames */
            if (payload_truncated && flexray_current_payload_length != 0) {
                expert_add_info(pinfo, flexray_frame_tree, &ei_flexray_frame_payload_truncated);
            }
        }

        proto_item_set_end(ti_header, tvb, 2 + FLEXRAY_HEADER_LENGTH);

        /* Only supporting single bus id right now */
        flexray_info_t flexray_info = { .id = (uint16_t)flexray_id,
                                        .cc = (uint8_t)flexray_cc,
                                        .ch  = flexray_channel_is_b ? 1 : 0,
                                        .bus_id = 0};

        ti = proto_tree_add_uint(flexray_frame_tree, hf_flexray_flexray_id, tvb, 0, 7, flexray_flexrayinfo_to_flexrayid(&flexray_info));
        proto_item_set_hidden(ti);
        flexray_set_source_and_destination_columns(pinfo, &flexray_info);

        if (flexray_current_payload_length > 0) {
            tvbuff_t *next_tvb = tvb_new_subset_length(tvb, 7, flexray_current_payload_length);
            if (!call_subdissector || !flexray_call_subdissectors(next_tvb, pinfo, tree, &flexray_info, prefvar_try_heuristic_first)) {
                call_data_dissector(next_tvb, pinfo, tree);
            }
        }
    } else if (frame_type == FLEXRAY_SYMBOL) {
        /* FlexRay Symbol [1 Byte] */
        expert_add_info(pinfo, flexray_tree, &ei_flexray_symbol_frame);

        uint32_t symbol_length;
        proto_tree_add_item_ret_uint(flexray_tree, hf_flexray_sl, tvb, 1, 1, ENC_BIG_ENDIAN, &symbol_length);
        col_append_fstr(pinfo->cinfo, COL_INFO, " SL %3d", symbol_length);
    }

    return tvb_captured_length(tvb);
}

void
proto_register_flexray(void) {
    module_t *flexray_module;
    expert_module_t *expert_flexray;
    uat_t  *sender_receiver_uat = NULL;

    static hf_register_info hf[] = {
        { &hf_flexray_measurement_header_field, {
            "Measurement Header", "flexray.mhf", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_flexray_ti, {
            "Type Index", "flexray.ti", FT_UINT8, BASE_HEX, VALS(flexray_type_names), 0x7f, NULL, HFILL } },
        { &hf_flexray_ch, {
            "Channel", "flexray.ch", FT_BOOLEAN, 8, TFS(&flexray_channel_tfs), 0x80, NULL, HFILL } },
        { &hf_flexray_error_flags_field, {
            "Error Flags", "flexray.eff", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_flexray_fcrc_err, {
            "Frame CRC error", "flexray.fcrc_err", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
        { &hf_flexray_hcrc_err, {
            "Header CRC error", "flexray.hcrc_err", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_flexray_fes_err, {
            "Frame End Sequence error", "flexray.fes_err", FT_BOOLEAN, 8, NULL, 0x04, NULL, HFILL } },
        { &hf_flexray_cod_err, {
            "Coding error", "flexray.cod_err", FT_BOOLEAN, 8, NULL, 0x02, NULL, HFILL } },
        { &hf_flexray_tss_viol, {
            "TSS violation", "flexray.tss_viol", FT_BOOLEAN, 8, NULL, 0x01, NULL, HFILL } },
        { &hf_flexray_frame_header, {
            "FlexRay Frame Header", "flexray.frame_header", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_flexray_res, {
            "Reserved", "flexray.res", FT_BOOLEAN, 8, NULL, 0x80, NULL, HFILL } },
        { &hf_flexray_ppi, {
            "Payload Preamble Indicator", "flexray.ppi", FT_BOOLEAN, 8, NULL, 0x40, NULL, HFILL } },
        { &hf_flexray_nfi, {
            "Null Frame Indicator", "flexray.nfi", FT_BOOLEAN, 8, TFS(&flexray_nfi_tfs), 0x20, NULL, HFILL } },
        { &hf_flexray_sfi, {
            "Sync Frame Indicator", "flexray.sfi", FT_BOOLEAN, 8, NULL, 0x10, NULL, HFILL } },
        { &hf_flexray_stfi, {
            "Startup Frame Indicator", "flexray.stfi", FT_BOOLEAN, 8, NULL, 0x08, NULL, HFILL } },
        { &hf_flexray_fid, {
            "Frame ID", "flexray.fid", FT_UINT16, BASE_DEC, NULL, 0x07ff, NULL, HFILL } },
        { &hf_flexray_pl, {
            "Payload length", "flexray.pl", FT_UINT8, BASE_DEC, NULL, 0xfe, NULL, HFILL } },
        { &hf_flexray_hcrc, {
            "Header CRC", "flexray.hcrc", FT_UINT24, BASE_DEC, NULL, 0x01ffc0, NULL, HFILL } },
        { &hf_flexray_cc, {
            "Cycle Counter", "flexray.cc", FT_UINT8, BASE_DEC, NULL, 0x3f, NULL, HFILL } },
        { &hf_flexray_sl, {
            "Symbol length", "flexray.sl", FT_UINT8, BASE_DEC, NULL, 0x7f, NULL, HFILL } },
        { &hf_flexray_flexray_id, {
            "FlexRay ID (combined)", "flexray.combined_id", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL } },
    };

    static int *ett[] = {
        &ett_flexray,
        &ett_flexray_measurement_header,
        &ett_flexray_error_flags,
        &ett_flexray_frame
    };

    static ei_register_info ei[] = {
        { &ei_flexray_frame_payload_truncated, {
            "flexray.malformed_frame_payload_truncated", PI_MALFORMED, PI_ERROR, "Truncated Frame Payload", EXPFILL } },
        { &ei_flexray_symbol_frame, {
            "flexray.symbol_frame", PI_SEQUENCE, PI_CHAT, "Packet is a Symbol Frame", EXPFILL } },
        { &ei_flexray_error_flag, {
            "flexray.error_flag", PI_PROTOCOL, PI_WARN, "One or more Error Flags set", EXPFILL } },
        { &ei_flexray_stfi_flag, {
            "flexray.stfi_flag", PI_PROTOCOL, PI_WARN, "A startup frame must always be a sync frame", EXPFILL } }
    };

    proto_flexray = proto_register_protocol("FlexRay Protocol", "FLEXRAY", "flexray");

    flexray_module = prefs_register_protocol(proto_flexray, NULL);

    proto_register_field_array(proto_flexray, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_flexray = expert_register_protocol(proto_flexray);
    expert_register_field_array(expert_flexray, ei, array_length(ei));

    flexray_handle = register_dissector("flexray", dissect_flexray, proto_flexray);

    prefs_register_bool_preference(flexray_module, "try_heuristic_first", "Try heuristic sub-dissectors first",
        "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector registered to \"decode as\"",
        &prefvar_try_heuristic_first
    );

    static uat_field_t sender_receiver_mapping_uat_fields[] = {
        UAT_FLD_HEX(sender_receiver_configs,     bus_id,        "Bus ID",        "Bus ID of the Interface with 0 meaning any(hex uint16 without leading 0x)."),
        UAT_FLD_HEX(sender_receiver_configs,     channel,       "Channel",       "Channel (8bit hex without leading 0x)"),
        UAT_FLD_HEX(sender_receiver_configs,     cycle,         "Cycle",         "Cycle (8bit hex without leading 0x)"),
        UAT_FLD_HEX(sender_receiver_configs,     frame_id,      "Frame ID",      "Frame ID (16bit hex without leading 0x)"),
        UAT_FLD_CSTRING(sender_receiver_configs, sender_name,   "Sender Name",   "Name of Sender(s)"),
        UAT_FLD_CSTRING(sender_receiver_configs, receiver_name, "Receiver Name", "Name of Receiver(s)"),
        UAT_END_FIELDS
    };

    sender_receiver_uat = uat_new("Sender Receiver Config",
        sizeof(sender_receiver_config_t),   /* record size           */
        DATAFILE_FR_SENDER_RECEIVER,        /* filename              */
        true,                               /* from profile          */
        (void**)&sender_receiver_configs,   /* data_ptr              */
        &sender_receiver_config_num,        /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,             /* but not fields        */
        NULL,                               /* help                  */
        copy_sender_receiver_config_cb,     /* copy callback         */
        update_sender_receiver_config,      /* update callback       */
        free_sender_receiver_config_cb,     /* free callback         */
        post_update_sender_receiver_cb,     /* post update callback  */
        NULL,                               /* reset callback        */
        sender_receiver_mapping_uat_fields  /* UAT field definitions */
    );

    prefs_register_uat_preference(flexray_module, "_sender_receiver_config", "Sender Receiver Config",
        "A table to define the mapping between Bus ID and CAN ID to Sender and Receiver.", sender_receiver_uat);

    subdissector_table = register_decode_as_next_proto(proto_flexray, "flexray.subdissector", "FLEXRAY next level dissector", NULL);
    flexrayid_subdissector_table = register_dissector_table("flexray.combined_id", "FlexRay ID (combined)", proto_flexray, FT_UINT32, BASE_HEX);
    heur_subdissector_list = register_heur_dissector_list_with_description("flexray", "FlexRay info", proto_flexray);
}

void
proto_reg_handoff_flexray(void) {
    dissector_add_uint("wtap_encap", WTAP_ENCAP_FLEXRAY, flexray_handle);
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
