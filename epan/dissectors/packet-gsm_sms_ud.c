/* packet-gsm_sms_ud.c
 * Routines for GSM SMS TP-UD (GSM 03.40) dissection
 *
 * Refer to the AUTHORS file or the AUTHORS section in the man page
 * for contacting the author(s) of this file.
 *
 * Separated from the SMPP dissector by Chris Wilson.
 *
 * UDH and WSP dissection of SMS message, Short Message reassembly,
 * "Decode Short Message with Port Number UDH as CL-WSP" preference,
 * "Always try subdissection of 1st fragment" preference,
 * provided by Olivier Biot.
 *
 * Note on SMS Message reassembly
 * ------------------------------
 *   The current Short Message reassembly is possible thanks to the
 *   message identifier (8 or 16 bit identifier). It is able to reassemble
 *   short messages that are sent over either the same SMPP connection or
 *   distinct SMPP connections. Normally the reassembly code is able to deal
 *   with duplicate message identifiers since the fragment_add_seq_check()
 *   call is used.
 *
 *   The SMS TP-UD preference "always try subdissection of 1st fragment" allows
 *   a subdissector to be called for the first Short Message fragment,
 *   even if reassembly is not possible. This way partial dissection
 *   is still possible. This preference is switched off by default.
 *
 * Note on Short Message decoding as CL-WSP
 * ----------------------------------------
 *    The SMS TP-UD preference "port_number_udh_means_wsp" is switched off
 *    by default. If it is enabled, then any Short Message with a Port Number
 *    UDH will be decoded as CL-WSP if:
 *    -  The Short Message is not segmented
 *    -  The entire segmented Short Message is reassembled
 *    -  It is the 1st segment of an unreassembled Short Message (if the
 *       "always try subdissection of 1st fragment" preference is enabled)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <epan/prefs.h>
#include <epan/reassemble.h>
#include "packet-gsm_sms.h"
#include "packet-smpp.h"

void proto_register_gsm_sms_ud(void);
void proto_reg_handoff_gsm_sms_ud(void);

static int proto_gsm_sms_ud;

/*
 * Short Message fragment handling
 */
static int hf_gsm_sms_ud_fragments;
static int hf_gsm_sms_ud_fragment;
static int hf_gsm_sms_ud_fragment_overlap;
static int hf_gsm_sms_ud_fragment_overlap_conflicts;
static int hf_gsm_sms_ud_fragment_multiple_tails;
static int hf_gsm_sms_ud_fragment_too_long_fragment;
static int hf_gsm_sms_ud_fragment_error;
static int hf_gsm_sms_ud_fragment_count;
static int hf_gsm_sms_ud_reassembled_in;
static int hf_gsm_sms_ud_reassembled_length;
static int hf_gsm_sms_ud_short_msg;

static int ett_gsm_sms;
static int ett_gsm_sms_ud_fragment;
static int ett_gsm_sms_ud_fragments;

/* Subdissector declarations */
static dissector_table_t gsm_sms_dissector_table;

/* Short Message reassembly */
static reassembly_table sm_reassembly_table;

static const fragment_items sm_frag_items = {
    /* Fragment subtrees */
    &ett_gsm_sms_ud_fragment,
    &ett_gsm_sms_ud_fragments,
    /* Fragment fields */
    &hf_gsm_sms_ud_fragments,
    &hf_gsm_sms_ud_fragment,
    &hf_gsm_sms_ud_fragment_overlap,
    &hf_gsm_sms_ud_fragment_overlap_conflicts,
    &hf_gsm_sms_ud_fragment_multiple_tails,
    &hf_gsm_sms_ud_fragment_too_long_fragment,
    &hf_gsm_sms_ud_fragment_error,
    &hf_gsm_sms_ud_fragment_count,
    /* Reassembled in field */
    &hf_gsm_sms_ud_reassembled_in,
    /* Reassembled length field */
    &hf_gsm_sms_ud_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Short Message fragments"
};

/* Dissect all SM data as WSP if the UDH contains a Port Number IE */
static bool port_number_udh_means_wsp;

/* Always try dissecting the 1st fragment of a SM,
 * even if it is not reassembled */
static bool try_dissect_1st_frag;

/* Prevent subdissectors changing column data */
static bool prevent_subdissectors_changing_columns;

static dissector_handle_t wsp_handle;

/* Parse Short Message. This function is only called from the SMPP
 * dissector if the UDH present, or if the UDH fields were obtained
 * elsewhere in SMPP TLVs.
 * Call WSP dissector if port matches WSP traffic.
 */
static void
parse_gsm_sms_ud_message(proto_tree *sm_tree, tvbuff_t *tvb, packet_info *pinfo, smpp_data_t *smpp_data)
{
    tvbuff_t      *sm_tvb                    = NULL;
    proto_tree    *top_tree;
    unsigned       sm_len                    = tvb_reported_length(tvb);
    uint32_t       i                         = 0;
    /* Multiple Messages UDH */
    bool           is_fragmented             = false;
    fragment_head *fd_sm                     = NULL;
    bool           save_fragmented           = false;
    bool           try_gsm_sms_ud_reassemble = false;
    /* SMS Message reassembly */
    bool           reassembled               = false;
    uint32_t       reassembled_in            = 0;

    gsm_sms_udh_fields_t *udh_fields = NULL;
    if (smpp_data) {
        udh_fields = smpp_data->udh_fields;
    }

    top_tree = proto_tree_get_parent_tree(sm_tree);

    if (!udh_fields) {
        udh_fields = wmem_new0(pinfo->pool, gsm_sms_udh_fields_t);
    }

    if (smpp_data && smpp_data->udhi) {
        /* XXX: We don't handle different encodings in this dissector yet,
         * so just treat everything as 8-bit binary encoding. */
        uint8_t fill_bits = 0;
        uint8_t udl = sm_len;
        dis_field_udh(tvb, pinfo, sm_tree, &i, &sm_len, &udl, OTHER, &fill_bits, udh_fields);
    }

    if (tvb_reported_length_remaining(tvb, i) <= 0)
        return; /* No more data */

    if (udh_fields->frags > 1) {
        is_fragmented = true;
    }

    /*
     * Try reassembling the packets.
     * XXX - fragment numbers are 1-origin, but the fragment number
     * field could be 0.
     * Should we flag a fragmented message with a fragment number field
     * of 0?
     * What if the fragment count is 0?  Should we flag that as well?
     */
    if (is_fragmented && udh_fields->frag != 0 && udh_fields->frags != 0 &&
        tvb_bytes_exist(tvb, i, sm_len)) {
        try_gsm_sms_ud_reassemble = true;
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = true;
        fd_sm = fragment_add_seq_check(&sm_reassembly_table,
                tvb, i,
                pinfo,
                udh_fields->sm_id,    /* uint32_t ID for fragments belonging together */
                NULL,
                udh_fields->frag-1,   /* uint32_t fragment sequence number */
                sm_len,               /* uint32_t fragment length */
                (udh_fields->frag != udh_fields->frags));     /* More fragments? */
        if (fd_sm) {
            reassembled    = true;
            reassembled_in = fd_sm->reassembled_in;
        }
        sm_tvb = process_reassembled_data(tvb, i, pinfo,
            "Reassembled Short Message", fd_sm, &sm_frag_items,
            NULL, sm_tree);
        if (reassembled) { /* Reassembled */
            col_append_str(pinfo->cinfo, COL_INFO,
                        " (Short Message Reassembled)");
        } else {
            /* Not last packet of reassembled Short Message */
            col_append_fstr(pinfo->cinfo, COL_INFO,
                    " (Short Message fragment %u of %u)", udh_fields->frag, udh_fields->frags);
        }
    } /* Else: not fragmented */

    if (! sm_tvb) /* One single Short Message, or not reassembled */
        sm_tvb = tvb_new_subset_remaining(tvb, i);
    /* Try calling a subdissector */
    if (sm_tvb) {
        if ((reassembled && pinfo->num == reassembled_in)
            || udh_fields->frag==0 || (udh_fields->frag==1 && try_dissect_1st_frag)) {
            /* Try calling a subdissector only if:
             *  - the Short Message is reassembled in this very packet,
             *  - the Short Message consists of only one "fragment",
             *  - the preference "Always Try Dissection for 1st SM fragment"
             *    is switched on, and this is the SM's 1st fragment. */
            if (udh_fields->port_src || udh_fields->port_dst) {
                bool disallow_write = false; /* true if we changed writability
                                    of the columns of the summary */
                if (prevent_subdissectors_changing_columns && col_get_writable(pinfo->cinfo, -1)) {
                    disallow_write = true;
                    col_set_writable(pinfo->cinfo, -1, false);
                }

                if (port_number_udh_means_wsp) {
                    call_dissector(wsp_handle, sm_tvb, pinfo, top_tree);
                } else {
                    if (! dissector_try_uint(gsm_sms_dissector_table, udh_fields->port_src,
                                sm_tvb, pinfo, top_tree)) {
                        if (! dissector_try_uint(gsm_sms_dissector_table, udh_fields->port_dst,
                                    sm_tvb, pinfo, top_tree)) {
                            if (sm_tree) { /* Only display if needed */
                                proto_tree_add_item(sm_tree, hf_gsm_sms_ud_short_msg, sm_tvb, 0, -1, ENC_NA);
                            }
                        }
                    }
                }

                if (disallow_write)
                    col_set_writable(pinfo->cinfo, -1, true);
            } else { /* No ports IE */
                proto_tree_add_item(sm_tree, hf_gsm_sms_ud_short_msg, sm_tvb, 0, -1, ENC_NA);
            }
        } else {
            /* The packet is not reassembled,
             * or it is reassembled in another packet */
            proto_tree_add_bytes_format(sm_tree, hf_gsm_sms_ud_short_msg, sm_tvb, 0, -1,
                    NULL, "Unreassembled Short Message fragment %u of %u",
                    udh_fields->frag, udh_fields->frags);
        }
    }

    if (try_gsm_sms_ud_reassemble) /* Clean up defragmentation */
        pinfo->fragmented = save_fragmented;
    return;
}

static int
dissect_gsm_sms_ud(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data)
{
    proto_item *ti;
    proto_tree *subtree;
    smpp_data_t *smpp_data = NULL;

    if (data) {
        smpp_data = (smpp_data_t*)data;
    }

    ti      = proto_tree_add_item(tree, proto_gsm_sms_ud, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_gsm_sms);
    parse_gsm_sms_ud_message(subtree, tvb, pinfo, smpp_data);
    return tvb_captured_length(tvb);
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_sms_ud(void)
{
    module_t *gsm_sms_ud_module; /* Preferences for GSM SMS UD */

    /* Setup list of header fields  */
    static hf_register_info hf[] = {
        /*
         * Short Message fragment reassembly
         */
        {   &hf_gsm_sms_ud_fragments,
            {   "Short Message fragments", "gsm_sms_ud.fragments",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "GSM Short Message fragments",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_fragment,
            {   "Short Message fragment", "gsm_sms_ud.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                "GSM Short Message fragment",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_fragment_overlap,
            {   "Short Message fragment overlap", "gsm_sms_ud.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "GSM Short Message fragment overlaps with other fragment(s)",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_fragment_overlap_conflicts,
            {   "Short Message fragment overlapping with conflicting data",
                "gsm_sms_ud.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "GSM Short Message fragment overlaps with conflicting data",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_fragment_multiple_tails,
            {   "Short Message has multiple tail fragments",
                "gsm_sms_ud.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "GSM Short Message fragment has multiple tail fragments",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_fragment_too_long_fragment,
            {   "Short Message fragment too long",
                "gsm_sms_ud.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x0,
                "GSM Short Message fragment data goes beyond the packet end",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_fragment_error,
            {   "Short Message defragmentation error", "gsm_sms_ud.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                "GSM Short Message defragmentation error due to illegal fragments",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_fragment_count,
            {   "Short Message fragment count", "gsm_sms_ud.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                NULL,
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_reassembled_in,
            {   "Reassembled in",
                "gsm_sms_ud.reassembled.in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00,
                "GSM Short Message has been reassembled in this packet.",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_reassembled_length,
            {   "Reassembled Short Message length",
                "gsm_sms_ud.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x00,
                "The total length of the reassembled payload",
                HFILL
            }
        },
        {   &hf_gsm_sms_ud_short_msg,
            {   "Short Message body",
                "gsm_sms_ud.short_msg",
                FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL
            }
        },
    };

    static int *ett[] = {
    &ett_gsm_sms,
    &ett_gsm_sms_ud_fragment,
    &ett_gsm_sms_ud_fragments,
    };
    /* Register the protocol name and description */
    proto_gsm_sms_ud = proto_register_protocol("GSM Short Message Service User Data", "GSM SMS UD", "gsm_sms_ud");

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_gsm_sms_ud, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Subdissector code */
    gsm_sms_dissector_table = register_dissector_table("gsm_sms_ud.udh.port",
        "GSM SMS port IE in UDH", proto_gsm_sms_ud, FT_UINT16, BASE_DEC);

    /* Preferences for GSM SMS UD */
    gsm_sms_ud_module = prefs_register_protocol(proto_gsm_sms_ud, NULL);
    /* For reading older preference files with "smpp-gsm-sms." preferences */
    prefs_register_module_alias("smpp-gsm-sms", gsm_sms_ud_module);
    prefs_register_bool_preference(gsm_sms_ud_module,
        "port_number_udh_means_wsp",
        "Port Number IE in UDH always triggers CL-WSP dissection",
        "Always decode a GSM Short Message as Connectionless WSP "
        "if a Port Number Information Element is present "
        "in the SMS User Data Header.",
        &port_number_udh_means_wsp);
    prefs_register_bool_preference(gsm_sms_ud_module, "try_dissect_1st_fragment",
        "Always try subdissection of 1st Short Message fragment",
        "Always try subdissection of the 1st fragment of a fragmented "
        "GSM Short Message. If reassembly is possible, the Short Message "
        "may be dissected twice (once as a short frame, once in its "
        "entirety).",
        &try_dissect_1st_frag);
    prefs_register_bool_preference(gsm_sms_ud_module, "prevent_dissectors_chg_cols",
            "Prevent sub-dissectors from changing column data",
        "Prevent sub-dissectors from replacing column data with their "
        "own. Eg. Prevent WSP dissector overwriting SMPP information.",
        &prevent_subdissectors_changing_columns);

    register_dissector("gsm_sms_ud", dissect_gsm_sms_ud, proto_gsm_sms_ud);

    reassembly_table_register(&sm_reassembly_table,
                          &addresses_reassembly_table_functions);
}

void
proto_reg_handoff_gsm_sms_ud(void)
{
    wsp_handle = find_dissector_add_dependency("wsp-cl", proto_gsm_sms_ud);
    DISSECTOR_ASSERT(wsp_handle);
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
