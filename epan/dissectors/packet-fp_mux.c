/* Routines for Huawei's FP Mux Header disassembly
 * Protocol reference: EU Patent publication No. EP2053798
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>
#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include "packet-umts_fp.h"
#include "packet-umts_mac.h"
#include "packet-umts_rlc.h"

/* Externals */
extern int proto_fp;
extern int proto_umts_mac;
extern int proto_umts_rlc;

void proto_register_fp_mux(void);
void proto_reg_handoff_fp_mux(void);

static int proto_fp_mux = -1;
static dissector_handle_t fp_mux_handle;
static heur_dissector_list_t heur_subdissector_list;

/* Constants */
#define MAX_PAYLOADS 64

/* Trees */
static int ett_fpmux = -1;

/* Fields */
static int hf_fpmux_uid = -1;
static int hf_fpmux_extension_flag = -1;
static int hf_fpmux_length = -1;

/* Expert Fields */
static expert_field ei_fpm_length_needlessly_extended = EI_INIT;
static expert_field ei_fpm_too_many_payloads = EI_INIT;
static expert_field ei_fpm_bad_length = EI_INIT;

/* Preferences */
/* Place UID in proto tree */
static gboolean fp_mux_uid_in_tree = TRUE;
/* Call heuristic FP dissectors on payload */
static gboolean call_fp_heur = TRUE;

/* Enum Values */
static const true_false_string fpmux_extension_flag_vals = {
    "Extension Present", "No Extension"
};


/* Per-packet info */
typedef struct fp_mux_info_t {
    guint32        srcport;
    guint32        destport;
    fp_info*       fpinfos[MAX_PAYLOADS];
    umts_mac_info* macinfos[MAX_PAYLOADS];
    rlc_info*      rlcinfos[MAX_PAYLOADS];
} fp_mux_info_t;

static void dissect_payload(tvbuff_t *next_tvb, packet_info *pinfo, proto_tree *tree, struct fp_mux_info_t* fp_mux_info, guint16 payload_index, guint16 uid)
{
    heur_dtbl_entry_t *hdtbl_entry;
    gboolean conv_dissected; /* If the TVB was dissected using the conversation dissector*/
    gboolean heur_dissected; /* If the TVB was dissected using a heuristic dissector*/
    guint32 current_destport,current_srcport;

    /* Saving old ports */
    current_destport = pinfo->destport;
    current_srcport = pinfo->srcport;

    /* Replacing ports with UID (ports are used by the FP dissector) */
    pinfo->destport = uid;
    pinfo->srcport = 0;

    /* Adding previously created FP/MAC/RLC info */
    p_add_proto_data(wmem_file_scope(), pinfo, proto_fp, 0, fp_mux_info->fpinfos[payload_index]);
    p_add_proto_data(wmem_file_scope(), pinfo, proto_umts_mac, 0, fp_mux_info->macinfos[payload_index]);
    p_add_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0, fp_mux_info->rlcinfos[payload_index]);

    /* Trying a dissector assigned to the conversation (Usually from NBAP) */
    conv_dissected = try_conversation_dissector(&pinfo->dst, &pinfo->src, CONVERSATION_UDP,
                                 pinfo->destport, pinfo->srcport, next_tvb, pinfo, tree, NULL, 0);
    if (!conv_dissected) {
        /* No conversation dissector / TVB was rejected, try other options */
        if(call_fp_heur) {
            /* Trying heuristic dissector */
            heur_dissected = dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree, &hdtbl_entry, NULL);
            if(!heur_dissected) {
                /* No heuristic dissector / TVB was rejected, show as data */
                call_data_dissector(next_tvb,pinfo,tree);
            }
        }
        else {
            /* Trying heuristic dissectors disabled, show as data */
            call_data_dissector(next_tvb,pinfo,tree);
        }
    }

    /* Saving FP/MAC/RLC Info which the sub dissector might have attached */
    fp_mux_info->fpinfos[payload_index] =  (fp_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    fp_mux_info->macinfos[payload_index] = (umts_mac_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_mac, 0);
    fp_mux_info->rlcinfos[payload_index] = (rlc_info *)p_get_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);

    /* Removing FP/MAC/RLC info from the packet */
    /* to allow other packets to be dissected correctly */
    p_remove_proto_data(wmem_file_scope(), pinfo, proto_fp, 0);
    p_remove_proto_data(wmem_file_scope(), pinfo, proto_umts_mac, 0);
    p_remove_proto_data(wmem_file_scope(), pinfo, proto_umts_rlc, 0);

    /* Setting a fence in the info column to aggregate all payloads' descriptions */
    const gchar* info = col_get_text(pinfo->cinfo, COL_INFO);
    if (info != NULL && *info != '\0') {
        /* Only creating fence if the column's current text isn't NULL or an empty string */
        col_append_str(pinfo->cinfo, COL_INFO, " ");
        col_set_fence(pinfo->cinfo, COL_INFO);
    }

    /* Restoring ports */
    pinfo->destport = current_destport;
    pinfo->srcport = current_srcport;
}

static int dissect_fp_mux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
    guint16 uid;
    gboolean ext_flag;
    guint8 length_field_size;
    guint16 length;
    guint32 header_length;
    guint32 total_length;
    guint32 offset = 0;
    guint32 out_value = 0;
    guint32 payload_index = 0;
    tvbuff_t *next_tvb;
    proto_item *ti;
    proto_tree *fpmux_tree = NULL;
    struct fp_mux_info_t* fp_mux_info;

    total_length = tvb_captured_length(tvb);

    /* Adding FP MUX info*/
    fp_mux_info = (fp_mux_info_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fp_mux, 0);
    if (!fp_mux_info) {
        fp_mux_info = wmem_new0(wmem_file_scope(), struct fp_mux_info_t);
        /* remember 'lower' UDP layer port information so we can later
         * differentiate 'lower' UDP layer from 'user data' UDP layer */
        fp_mux_info->srcport = pinfo->srcport;
        fp_mux_info->destport = pinfo->destport;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_fp_mux, 0, fp_mux_info);
    }

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FP Mux");
    col_clear(pinfo->cinfo, COL_INFO);

    while (offset != total_length) {
        ext_flag = tvb_get_bits(tvb, (offset+2)*8, 1, ENC_NA) == 0x01;
        header_length = ext_flag ? 4 : 3;

        /* Adding another FP Mux tree */
        ti = proto_tree_add_item(tree, proto_fp_mux, tvb, offset, header_length, ENC_NA);
        fpmux_tree = proto_item_add_subtree(ti, ett_fpmux);

        /* Adding User Identifier field */
        proto_tree_add_item_ret_uint(fpmux_tree, hf_fpmux_uid, tvb, offset, 2, ENC_BIG_ENDIAN, &out_value);
        uid = (guint16)out_value;
        offset += 2;
        /* Appending User Identifier to FP Mux tree label */
        if (fp_mux_uid_in_tree) {
            proto_item_append_text(ti, ", Uid: %d", uid);
        }

        /* Adding Extension Flag */
        ti = proto_tree_add_boolean(fpmux_tree, hf_fpmux_extension_flag, tvb, offset, 1, ext_flag);
        proto_item_append_text(ti," (%d)", ext_flag ? 1 : 0);

        /* Adding Length field */
        if(ext_flag) {
            /* Extended - Length is 15 bits */
            length = tvb_get_ntohs(tvb, offset) & 0x7FFF;
            length_field_size = 2;
        }
        else {
            /* Not extended - Length is 7 bits */
            length = tvb_get_guint8(tvb, offset) & 0x7F;
            length_field_size = 1;
        }
        proto_tree_add_uint(fpmux_tree, hf_fpmux_length, tvb, offset, length_field_size, length);
        if(length == 0) {
            /* Length is zero. Showing error and aborting dissection*/
            proto_tree_add_expert_format(fpmux_tree, pinfo, &ei_fpm_bad_length, tvb, offset, length_field_size,
                "Bad length: payload length can't be 0");
            return total_length;
        }
        if (length > total_length - offset) {
            /* Length value too big. Showing error and aborting dissection*/
            proto_tree_add_expert_format(fpmux_tree, pinfo, &ei_fpm_bad_length, tvb, offset, length_field_size,
                "Bad length: payload length exceeds remaining data length (%d) ", (total_length - offset));
            return total_length;
        }
        if (length < 128 && ext_flag) {
            /* Length could fit in 7 bits yet the length field was extended */
            proto_tree_add_expert(fpmux_tree, pinfo, &ei_fpm_length_needlessly_extended, tvb, offset, length_field_size);
        }
        offset += length_field_size;

        /* Dissecting Payload */
        next_tvb = tvb_new_subset_length(tvb,offset,length);
        if(payload_index >= MAX_PAYLOADS) {
            /* Too many FP payloads. Showing error and aboring dissection*/
            proto_tree_add_expert_format(fpmux_tree, pinfo, &ei_fpm_too_many_payloads, tvb, offset, -1,
                "Too many FP packets muxed in a single packet ( Maximum expected: %d )", MAX_PAYLOADS);
            return total_length;
        }
        dissect_payload(next_tvb,pinfo,tree,fp_mux_info,payload_index,uid);
        offset += length;

        payload_index++;
    }

    return total_length;
}


static int heur_dissect_fp_mux(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    gboolean ext_flag;
    guint8 length_field_size;
    guint16 length;
    guint32 header_length;
    guint32 total_length;
    guint32 offset = 0;
    guint32 chunks = 0;
    conversation_t *conversation;
    struct fp_mux_info_t* fp_mux_info;

    total_length = tvb_captured_length(tvb);
    if (total_length == 0) {
        return FALSE;
    }

    fp_mux_info = (fp_mux_info_t* )p_get_proto_data(wmem_file_scope(), pinfo, proto_fp_mux, 0);
    if (fp_mux_info) {
        if (fp_mux_info->srcport == pinfo->srcport &&
            fp_mux_info->destport == pinfo->destport) {
            /* Already framed as FP Mux*/
            dissect_fp_mux(tvb, pinfo, tree, data);
            return TRUE;
        }
        else {
            return FALSE;
        }
    }

    while(offset < total_length)
    {
        if(total_length < offset + 2) {
            return FALSE;
        }
        ext_flag = ((tvb_get_guint8(tvb, offset + 2)&0x80)==0x80);
        header_length = ext_flag ? 4 : 3;

        if(total_length < offset + header_length) {
            return FALSE;
        }

        offset = offset + 2; /* Skipping UID */
        if(ext_flag) {
            /* Extended - Length is 15 bits */
            length = tvb_get_ntohs(tvb, offset) & 0x7FFF;
            length_field_size = 2;
        }
        else {
            /* Not extended - Length is 7 bits */
            length = tvb_get_guint8(tvb, offset) & 0x7F;
            length_field_size = 1;
        }

        if(length < 3) { /* Minimal FP frame length is 3 bytes*/
            return FALSE;
        }

        offset += length_field_size;
        offset += length;

        chunks++;
    }

    if(offset > total_length) {
        return FALSE;
    }

    if(chunks == 1) {
        /* Might be coincidental, let's hope other packets with more payloads arrive */
        return FALSE;
    }

    /* This is FP Mux! */
    /* Set conversation dissector and dissect */
    conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, fp_mux_handle);
    dissect_fp_mux(tvb, pinfo, tree, data);

    return TRUE;
}


void
proto_register_fp_mux(void)
{
    module_t *fp_mux_module;
    expert_module_t* expert_fp_mux;

    static hf_register_info hf[] = {
        { &hf_fpmux_uid, { "User Identifier", "fp_mux.uid", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_fpmux_extension_flag, { "Extension", "fp_mux.ef", FT_BOOLEAN, BASE_NONE, TFS(&fpmux_extension_flag_vals), 0, "Extension Flag", HFILL } },
        { &hf_fpmux_length, { "Length", "fp_mux.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL } },
    };

    static gint *ett[] = {
        &ett_fpmux
    };

    static ei_register_info ei[] = {
         { &ei_fpm_length_needlessly_extended, { "fp_mux.needlessly_extended_length", PI_PROTOCOL, PI_WARN, "Length field needlessly extended", EXPFILL }},
         { &ei_fpm_too_many_payloads, { "fp_mux.too_many_payloads", PI_PROTOCOL, PI_ERROR, "Too many FP packets muxed in a single packet", EXPFILL }},
         { &ei_fpm_bad_length, { "fp_mux.bad_length", PI_PROTOCOL, PI_ERROR, "Bad length", EXPFILL }},
    };

    /* Register protocol */
    proto_fp_mux = proto_register_protocol("Huawei FP Multiplexing Header", "FP Mux", "fp_mux");
    fp_mux_handle =register_dissector("fp_mux", dissect_fp_mux, proto_fp_mux);

    proto_register_field_array(proto_fp_mux, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fp_mux = expert_register_protocol(proto_fp_mux);
    expert_register_field_array(expert_fp_mux, ei, array_length(ei));

    /* Register heuristic table */
    heur_subdissector_list = register_heur_dissector_list("fp_mux", proto_fp_mux);

    /* Register configuration preferences */
    fp_mux_module = prefs_register_protocol(proto_fp_mux, NULL);
    prefs_register_bool_preference(fp_mux_module, "uid_in_tree",
                                 "Show UID in protocol tree",
                                 "Whether the UID value should be appended in the protocol tree",
                                 &fp_mux_uid_in_tree);
    prefs_register_bool_preference(fp_mux_module, "call_heur_fp",
                                 "Call Heuristic FP Dissectors",
                                 "Whether to try heuristic FP dissectors for the muxed payloads",
                                 &call_fp_heur);
}

void
proto_reg_handoff_fp_mux(void)
{
    dissector_add_uint_range_with_preference("udp.port", "", fp_mux_handle);
    heur_dissector_add("udp", heur_dissect_fp_mux, "FP Mux over UDP", "fp_mux_udp", proto_fp_mux, HEURISTIC_DISABLE);
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
