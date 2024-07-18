/* packet-rmt-alc.c
 * Reliable Multicast Transport (RMT)
 * ALC Protocol Instantiation dissector
 * Copyright 2005, Stefano Pettini <spettini@users.sourceforge.net>
 * Copyright 2023, Sergey V. Lobanov <sergey@lobanov.in>
 *
 * Asynchronous Layered Coding (ALC):
 * ----------------------------------
 *
 * A massively scalable reliable content delivery protocol.
 * Asynchronous Layered Coding combines the Layered Coding Transport
 * (LCT) building block, a multiple rate congestion control building
 * block and the Forward Error Correction (FEC) building block to
 * provide congestion controlled reliable asynchronous delivery of
 * content to an unlimited number of concurrent receivers from a single
 * sender.
 *
 * References:
 *     RFC 3450, Asynchronous Layered Coding protocol instantiation
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
#include <epan/expert.h>
#include <epan/conversation.h>
#include <wiretap/wtap.h>

#include "packet-rmt-common.h"
#include "packet-lls.h"

/* Initialize the protocol and registered fields */
/* ============================================= */
static dissector_handle_t alc_handle;

void proto_register_alc(void);
void proto_reg_handoff_alc(void);

static int proto_rmt_alc;

static int hf_version;
static int hf_atsc3;
static int hf_object_start_offset;
static int hf_payload;
static int hf_uncomp_payload;

static int ett_main;
static int ett_uncomp_payload;
static int ett_uncomp_decode;

static expert_field ei_version1_only;

static dissector_handle_t xml_handle;
static dissector_handle_t rmt_lct_handle;
static dissector_handle_t rmt_fec_handle;

static dissector_table_t media_type_dissector_table;

static bool g_codepoint_as_fec_encoding = true;
static int      g_ext_192                   = LCT_PREFS_EXT_192_FLUTE;
static int      g_ext_193                   = LCT_PREFS_EXT_193_FLUTE;
static int      g_atsc3_mode                = LCT_ATSC3_MODE_AUTO;

static void
try_decode_payload(tvbuff_t *tvb, packet_info *pinfo, proto_item *tree)
{
    uint32_t b03 = tvb_get_uint32(tvb, 0, ENC_BIG_ENDIAN);
    /* xml ("<?xm") */
    if (b03 == 0x3C3F786D) {
        call_dissector(xml_handle, tvb, pinfo, tree);
    } else {
        uint32_t b47 = tvb_get_uint32(tvb, 4, ENC_BIG_ENDIAN);
        /* mp4 ("ftyp" or "sidx" or "styp" mp4 box) */
        if (b47 == 0x66747970 || b47 == 0x73696478 || b47 == 0x73747970) {
            /* MP4 dissector removes useful info from Protocol and Info columns so store it */
            char *col_info_text = wmem_strdup(pinfo->pool, col_get_text(pinfo->cinfo, COL_INFO));
            char *col_protocol_text = wmem_strdup(pinfo->pool, col_get_text(pinfo->cinfo, COL_PROTOCOL));

            int mp4_dis = dissector_try_string(media_type_dissector_table, "video/mp4", tvb, pinfo, tree, NULL);
            char *col_protocol_text_mp4 = wmem_strdup(pinfo->pool,col_get_text(pinfo->cinfo, COL_PROTOCOL));

            /* Restore Protocol and Info columns and add MP4 Protocol Info */
            col_set_str(pinfo->cinfo, COL_INFO, col_info_text);
            col_set_str(pinfo->cinfo, COL_PROTOCOL, col_protocol_text);
            if (mp4_dis > 0) {
                col_append_sep_str(pinfo->cinfo, COL_PROTOCOL, "/", col_protocol_text_mp4);
            }
        }
    }
}

static void
try_uncompress(tvbuff_t *tvb, packet_info *pinfo, int offset, /*int len,*/ proto_item *ti)
{
    tvbuff_t *uncompress_tvb = tvb_uncompress_zlib(tvb, offset, tvb_captured_length(tvb) - offset);
    if (uncompress_tvb) {
        add_new_data_source(pinfo, uncompress_tvb, "Uncompressed Payload");

        proto_tree *uncompress_tree = proto_item_add_subtree(ti, ett_uncomp_payload);
        unsigned decomp_length = tvb_captured_length(uncompress_tvb);
        proto_item *ti_uncomp = proto_tree_add_item(uncompress_tree, hf_uncomp_payload, uncompress_tvb, 0, decomp_length, ENC_ASCII);
        proto_item_set_generated(ti_uncomp);

        proto_tree *payload_tree = proto_item_add_subtree(ti_uncomp, ett_uncomp_decode);
        try_decode_payload(uncompress_tvb, pinfo, payload_tree);
    }
}

/* Code to actually dissect the packets */
/* ==================================== */
static int
dissect_alc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    uint8_t             version;
    lct_data_exchange_t lct;
    fec_data_exchange_t fec;
    int                 len;
    bool                is_atsc3;

    if (g_atsc3_mode == LCT_ATSC3_MODE_FORCE) {
        is_atsc3 = true;
    } else if (g_atsc3_mode == LCT_ATSC3_MODE_DISABLED) {
        is_atsc3 = false;
    } else { /* Auto detect mode*/
        /* If packet encap is ALP then it is necessary to use ATSC decoding mode*/
        is_atsc3 = pinfo->rec->rec_header.packet_header.pkt_encap == WTAP_ENCAP_ATSC_ALP;
    }

    /* Offset for subpacket dissection */
    unsigned offset = 0;

    /* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti;
    proto_tree *alc_tree;

    tvbuff_t *new_tvb;

    /* Make entries in Protocol column and Info column on summary display */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ALC");
    col_clear(pinfo->cinfo, COL_INFO);

    /* ALC header dissection */
    /* --------------------- */

    version = hi_nibble(tvb_get_uint8(tvb, offset));

    /* Create subtree for the ALC protocol */
    ti = proto_tree_add_item(tree, proto_rmt_alc, tvb, offset, -1, ENC_NA);
    alc_tree = proto_item_add_subtree(ti, ett_main);

    /* Fill the ALC subtree */
    ti = proto_tree_add_uint(alc_tree, hf_version, tvb, offset, 1, version);
    PROTO_ITEM_SET_GENERATED(
        proto_tree_add_boolean(alc_tree, hf_atsc3, 0, 0, 0, is_atsc3)
    );

    /* This dissector supports only ALCv1 packets.
     * If version > 1 print only version field and quit.
     */
    if (version != 1) {
        expert_add_info(pinfo, ti, &ei_version1_only);

        /* Complete entry in Info column on summary display */
        col_add_fstr(pinfo->cinfo, COL_INFO, "Version: %u (not supported)", version);
        return 0;
    }

    /* LCT header dissection */
    /* --------------------- */
    new_tvb = tvb_new_subset_remaining(tvb,offset);

    lct.ext_192 = g_ext_192;
    lct.ext_193 = g_ext_193;
    lct.codepoint = 0;
    lct.is_flute = false;
    lct.is_atsc3 = is_atsc3;
    lct.is_sp = false;
    len = call_dissector_with_data(rmt_lct_handle, new_tvb, pinfo, alc_tree, &lct);
    if (len < 0)
        return offset;

    offset += len;

    /* FEC header dissection */
    /* --------------------- */

    /* Only if LCT dissector has determined FEC Encoding ID */
    /* FEC dissector needs to be called with encoding_id filled */
    if (!lct.is_sp && g_codepoint_as_fec_encoding && tvb_reported_length(tvb) > offset)
    {
        fec.encoding_id = lct.codepoint;

        new_tvb = tvb_new_subset_remaining(tvb,offset);
        len = call_dissector_with_data(rmt_fec_handle, new_tvb, pinfo, alc_tree, &fec);
        if (len < 0)
            return offset;

        offset += len;
    }

    /* A/331 specifies start_offset field */
    int64_t object_start_offset = -1;
    if (lct.is_sp) {
        object_start_offset = tvb_get_uint32(tvb, offset, 4);
        proto_tree_add_item(alc_tree, hf_object_start_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    }

    /* Add the Payload item */
    if (tvb_reported_length(tvb) > offset){
        if(lct.is_flute){
            new_tvb = tvb_new_subset_remaining(tvb,offset);
            call_dissector(xml_handle, new_tvb, pinfo, alc_tree);
        }else{
            ti = proto_tree_add_item(alc_tree, hf_payload, tvb, offset, -1, ENC_NA);
            if (object_start_offset == 0 &&
                tvb_captured_length_remaining(tvb, offset) > 18 &&
                tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN) == 0x1f8b) {
                /* gzip is detected */
                try_uncompress(tvb, pinfo, offset, ti);
            } else if (object_start_offset == 0) {
                /* gzip is not detected */
                new_tvb = tvb_new_subset_remaining(tvb, offset);
                try_decode_payload(new_tvb, pinfo, alc_tree);
            }
        }
    }

    /* Add Channel info in ATSC3 mode */
    if(lct.is_atsc3) {
        char *channel_info = get_slt_channel_info(pinfo);
        if (channel_info != NULL) {
            col_append_sep_str(pinfo->cinfo, COL_INFO, " ", channel_info);
            wmem_free(pinfo->pool, channel_info);
        }
    }

    return tvb_reported_length(tvb);
}


static bool
dissect_alc_heur_udp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* Lookup over ATSC3 SLT Table*/
    if (!test_alc_over_slt(pinfo, tvb, 0, data))
        return false;

    conversation_t *conversation = find_or_create_conversation(pinfo);
    conversation_set_dissector(conversation, alc_handle);

    return (dissect_alc(tvb, pinfo, tree, data) != 0);
}

void proto_register_alc(void)
{
    /* Setup ALC header fields */
    static hf_register_info hf_ptr[] = {

        { &hf_version,
          { "Version", "alc.version", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_atsc3,
          { "Decode as ATSC3", "alc.atsc3", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_object_start_offset,
          { "Object Start Offset", "alc.object_start_offset", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }},

        { &hf_payload,
          { "Payload", "alc.payload", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},

        { &hf_uncomp_payload,
          { "Uncompressed Payload", "alc.payload.uncompressed", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static int *ett_ptr[] = {
        &ett_main,
        &ett_uncomp_payload,
        &ett_uncomp_decode,
    };

    static ei_register_info ei[] = {
        { &ei_version1_only, { "alc.version1_only", PI_PROTOCOL, PI_WARN, "Sorry, this dissector supports ALC version 1 only", EXPFILL }},
    };

    module_t *module;
    expert_module_t* expert_rmt_alc;

    /* Register the protocol name and description */
    proto_rmt_alc = proto_register_protocol("Asynchronous Layered Coding", "ALC", "alc");
    alc_handle = register_dissector("alc", dissect_alc, proto_rmt_alc);

    /* Register the header fields and subtrees used */
    proto_register_field_array(proto_rmt_alc, hf_ptr, array_length(hf_ptr));
    proto_register_subtree_array(ett_ptr, array_length(ett_ptr));
    expert_rmt_alc = expert_register_protocol(proto_rmt_alc);
    expert_register_field_array(expert_rmt_alc, ei, array_length(ei));

    /* Register preferences */
    module = prefs_register_protocol(proto_rmt_alc, NULL);

    prefs_register_obsolete_preference(module, "default.udp_port.enabled");

    prefs_register_bool_preference(module,
                                   "lct.codepoint_as_fec_id",
                                   "LCT Codepoint as FEC Encoding ID",
                                   "Whether the LCT header Codepoint field should be considered the FEC Encoding ID of carried object",
                                   &g_codepoint_as_fec_encoding);

    prefs_register_enum_preference(module,
                                   "lct.ext.192",
                                   "LCT header extension 192",
                                   "How to decode LCT header extension 192",
                                   &g_ext_192,
                                   enum_lct_ext_192,
                                   false);

    prefs_register_enum_preference(module,
                                   "lct.ext.193",
                                   "LCT header extension 193",
                                   "How to decode LCT header extension 193",
                                   &g_ext_193,
                                   enum_lct_ext_193,
                                   false);

    prefs_register_enum_preference(module,
                                   "lct.atsc3.mode",
                                   "ATSC3 Mode",
                                   "How to detect ATSC3 data",
                                   &g_atsc3_mode,
                                   enum_lct_atsc3_mode,
                                   false);
}

void proto_reg_handoff_alc(void)
{
    dissector_add_for_decode_as_with_preference("udp.port", alc_handle);
    xml_handle = find_dissector_add_dependency("xml", proto_rmt_alc);
    rmt_lct_handle = find_dissector_add_dependency("rmt-lct", proto_rmt_alc);
    rmt_fec_handle = find_dissector_add_dependency("rmt-fec", proto_rmt_alc);
    heur_dissector_add("udp", dissect_alc_heur_udp, "Asynchronous Layered Coding",
                       "alc", proto_rmt_alc, HEURISTIC_ENABLE);

    media_type_dissector_table = find_dissector_table("media_type");
}

/*
 * Editor modelines - https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
