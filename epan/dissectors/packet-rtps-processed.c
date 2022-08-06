/* packet-rtps-processed.c
 * Dissector for the Real-Time Publish-Subscribe (RTPS) Processed Protocol.
 *
 * (c) 2020 Copyright, Real-Time Innovations, Inc.
 * Real-Time Innovations, Inc.
 * 232 East Java Drive
 * Sunnyvale, CA 94089
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * -----------------------------------------------------------------------------
 * RTI Connext DDS can capture RTPS-related traffic by using the Network Capture
 * Utility. The generated .pcap capture files will follow a format that
 * defines how information must be saved, and then parsed.
 *
 * The format is divided into two layers/protocols: virtual transport
 * (packet-rtps-virtual-transport.c) and processed (packet-rtps-processed.c).
 * This file is about the processed dissector. For a general introduction and
 * information about the virtual transport dissector, read the documentation at
 * the beginning of packet-rtps-virtual-transport.c.
 *
 * The processed dissector is called by the transport dissector. It should never
 * be called directly by Wireshark without going through the transport
 * dissector first.
 *
 * The advanced information contains one parameter that it is really important
 * (and compulsory). This parameter is the "main frame", i.e. the frame that
 * would usually be captured over the wire. This frame is encrypted if security
 * applies.
 *
 * Then we have two optional fields: advanced frame0 and frame1.
 *   - frame0: Contains the RTPS frame with submessage protection (but
 *             decrypted at the RTPS level).
 *   - frame1:
 *     - Inbound traffic: A list of decrypted RTPS submessages (the protected
 *                        ones from frame0).
 *     - Outbound traffic: The RTPS message before any kind of protection.
 * The contents encrypted at RTPS message level can be found in the main frame.
 *
 * We can see there is a difference between frame1 (the parameter containing the
 * decrypted RTPS submessages): inbound traffic has a list of submessages (no
 * RTPS header) but outbound traffic has a RTPS message. The reason behind
 * this is related to how RTI Connext DDS handles protected inbound traffic.
 *
 * An alternative would be to build the RTPS message from frame0 and frame1 and
 * then pass it to the RTPS dissector. This solution would be cleaner but would
 * require to keep a buffer and information between parameters.
 * The current solution is kept for the moment.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/addr_resolv.h>
#include <epan/wmem_scopes.h>
#include <epan/conversation.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-rtps.h>


#define PARAM_ID_ADVANCED_FRAME0               0x000C1
#define PARAM_ID_ADVANCED_FRAME1               0x000C2

void proto_reg_handoff_rtps_processed(void);
void proto_register_rtps_processed(void);
static gint dissect_rtps_processed(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree,
        void *data);
static void get_new_colinfo_w_submessages(
        wmem_strbuf_t *out,
        wmem_strbuf_t *frame,
        const gchar *submessages);

/* Subtree pointers */
static gint rtpsproc_tree = -1;
static gint rtpsproc_ett = -1;
static gint rtpsproc_ett_security = -1;
static gint rtpsproc_ett_advanced_frame0 = -1;
static gint rtpsproc_ett_advanced_frame1 = -1;

/* Initialize the protocol and registered fields */
static header_field_info *rtpsproc_hf = NULL;
static gint rtpsproc_hf_param_id = -1;
static gint rtpsproc_hf_param_length = -1;

/* Used for caching a handle to the RTPS dissector */
static dissector_handle_t rtps_handle = NULL;

/* ========================================================================== */
/*                                 Dissector                                  */
/* ========================================================================== */
/*
 * Parameters must be in the right order or dissector will fail.
 * This was done instead of looping for all parameters (like in
 * packet-rtps-virtual-transport.c) because:
 *   - The number of parameters is small.
 *   - This way we can skip creating some headings if they are not needed (by
 *     using zeros instead).
 */
static gint dissect_rtps_processed(
        tvbuff_t *tvb,
        packet_info *pinfo,
        proto_tree *tree,
        void *data)
{
    proto_tree *rtpsproc_tree_general = NULL;
    proto_tree *rtpsproc_tree_security = NULL;
    proto_item *rtpsproc_ti = NULL;
    guint16 param_id;
    guint16 param_length;
    gint offset = 0;
    gint offset_version = 4; /* 'R', 'T', 'P', 'S' */
    tvbuff_t *rtps_payload = NULL;
    tvbuff_t *message_payload = NULL;
    struct rtpsvt_data *transport_data = (struct rtpsvt_data *) data;
    const gchar *title_security;
    guint16 rtps_version = 0x0203;
    guint16 rtps_vendor_id = 0x0101;
    endpoint_guid guid;

    if (transport_data == NULL) {
        /* Reject the packet if no transport information */
        return 0;
    }
    param_length = transport_data->rtps_length;
    title_security = transport_data->direction == 1
                        ? "RTPS Security decoding"
                        : "RTPS Security pre-encoding";

    /* *****************************  MAIN  ***********************************/
    /*
     * The contents passed to the rtpsproc dissector must start with the RTPS
     * frame.
     */
    rtps_version = tvb_get_guint16(
            tvb,
            offset + offset_version,
            ENC_BIG_ENDIAN);
    rtps_vendor_id = tvb_get_guint16(
            tvb,
            offset + offset_version + 2,
            ENC_BIG_ENDIAN);
    guid.host_id = tvb_get_ntohl(tvb, offset + offset_version + 4);
    guid.app_id = tvb_get_ntohl(tvb, offset + offset_version + 8);
    guid.instance_id = tvb_get_ntohl(tvb, offset + offset_version + 12);
    guid.fields_present = GUID_HAS_HOST_ID | GUID_HAS_APP_ID | GUID_HAS_INSTANCE_ID;
    rtps_payload = tvb_new_subset_length(tvb, offset, param_length);
    if (rtps_handle != NULL) {
        call_dissector(rtps_handle, rtps_payload, pinfo, tree);
    }
    offset += param_length;

    /* *********** Add subtree used for the fields of our rtpsproc_tree *******/
    rtpsproc_ti = proto_tree_add_item(
            tree,
            rtpsproc_tree,
            tvb,
            offset,
            -1,
            ENC_BIG_ENDIAN);
    rtpsproc_tree_general = proto_item_add_subtree(rtpsproc_ti, rtpsproc_ett);

    /* ***************************  ADVANCED 0  *******************************/
    param_id = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    if (param_id == PARAM_ID_ADVANCED_FRAME0) {
        proto_tree *rtpsproc_tree_frame0  = NULL;
        param_length = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);

        rtpsproc_tree_security = proto_tree_add_subtree_format(
                rtpsproc_tree_general,
                tvb,
                offset,
                0,
                rtpsproc_ett_security,
                NULL,
                "%s",
                title_security);

        rtpsproc_tree_frame0 = proto_tree_add_subtree_format(
                rtpsproc_tree_security,
                tvb,
                offset,
                0,
                rtpsproc_ett_advanced_frame0,
                NULL,
                "%s",
                "RTPS level");

        proto_tree_add_uint(
                rtpsproc_tree_frame0,
                rtpsproc_hf_param_id,
                tvb,
                offset,
                2, /* length */
                param_id);
        offset += 2;

        proto_tree_add_uint(
                rtpsproc_tree_frame0,
                rtpsproc_hf_param_length,
                tvb,
                offset,
                2, /* length */
                param_length);
        offset += 2;

        message_payload = tvb_new_subset_length(tvb, offset, param_length);
        if (rtps_handle != NULL) {
            call_dissector(
                    rtps_handle,
                    message_payload,
                    pinfo,
                    rtpsproc_tree_frame0);
        }
        offset += param_length;
    } else {
        /*
         * If there is no security information, param_id is zeroed.
         * In that case the length is also zero, so we move 4 Bytes in total.
         */
        offset += 4;
    }

    /* ***************************  ADVANCED 1  *******************************/
    param_id = tvb_get_guint16(tvb, offset, ENC_BIG_ENDIAN);
    if (param_id == PARAM_ID_ADVANCED_FRAME1) {
        proto_tree *rtpsproc_tree_frame1  = NULL;
        const gchar *title = transport_data->direction
                ? "Submessage level"
                : "RTPS and Submessage level (no protection)";
        param_length = tvb_get_guint16(tvb, offset + 2, ENC_BIG_ENDIAN);

        if (rtpsproc_tree_security == NULL) {
            rtpsproc_tree_security = proto_tree_add_subtree_format(
                    rtpsproc_tree_general,
                    tvb,
                    offset,
                    0,
                    rtpsproc_ett_security,
                    NULL,
                    "%s",
                    title_security);
        }

        rtpsproc_tree_frame1 = proto_tree_add_subtree_format(
                rtpsproc_tree_security,
                tvb,
                offset,
                0,
                rtpsproc_ett_advanced_frame1,
                NULL,
                "%s",
                title);

        proto_tree_add_uint(
                rtpsproc_tree_frame1,
                rtpsproc_hf_param_id,
                tvb,
                offset,
                2, /* length */
                param_id);
        offset += 2;

        proto_tree_add_uint(
                rtpsproc_tree_frame1,
                rtpsproc_hf_param_length,
                tvb,
                offset,
                2, /* length */
                param_length);
        offset += 2;

        /*
         * Depending on the direction we have:
         *   - Inbound: List of decrypted submessages.
         *   - Outbound: The RTPS message before any kind of protection.
         * So, we handle them differently.
         */
        if (transport_data->direction) {
            tvbuff_t *rtps_submessages = NULL;
            wmem_strbuf_t *info_w_encrypted = NULL; /* Current info */
            wmem_strbuf_t *info_w_decrypted = NULL; /* New info */

            /*
             * Get the current column info. This has the RTPS frames with the
             * encrypted submessages. We are going to update the text so that
             * it has the decrypted information, which is more useful to the
             * user.
             */
            if (pinfo->cinfo) {
                const gchar *colinfo = col_get_text(pinfo->cinfo, COL_INFO);
                if (colinfo) {
                    info_w_encrypted = wmem_strbuf_new(
                            pinfo->pool,
                            colinfo);
                    col_clear(pinfo->cinfo, COL_INFO);
                }
            }
            /* Dissect the submessages using the RTPS dissector */
            rtps_submessages = tvb_new_subset_length(tvb, offset, param_length);
            dissect_rtps_submessages(
                    rtps_submessages,
                    0, /* offset */
                    pinfo,
                    rtpsproc_tree_frame1,
                    rtps_version,
                    rtps_vendor_id,
                    &guid);

            /*
             * Get the decrypted submessages and update the column information.
             */
            if (pinfo->cinfo) {
                const gchar *colinfo = col_get_text(pinfo->cinfo, COL_INFO);
                info_w_decrypted = wmem_strbuf_new(pinfo->pool, "");
                if (colinfo) {
                    get_new_colinfo_w_submessages(
                            info_w_decrypted, /* out */
                            info_w_encrypted, /* in */
                            colinfo); /* in */
                    col_clear(pinfo->cinfo, COL_INFO);
                    col_set_str(
                            pinfo->cinfo,
                            COL_INFO,
                            wmem_strbuf_get_str(info_w_decrypted));
                }
            }
        } else {
            message_payload = tvb_new_subset_length(tvb, offset, param_length);
            if (rtps_handle != NULL) {
                call_dissector(
                        rtps_handle,
                        message_payload,
                        pinfo,
                        rtpsproc_tree_frame1);
            }
        }
    }
    return tvb_captured_length(tvb);
}

/* ========================================================================== */
/*                                 Other                                      */
/* ========================================================================== */

/*
 * This function is called at startup and caches the handle for the register.
 * That way we don't have to find the dissector for each packet.
 */
void proto_reg_handoff_rtps_processed(void)
{
    rtps_handle = find_dissector("rtps");
}

static void get_new_colinfo_w_submessages(
        wmem_strbuf_t *out,
        wmem_strbuf_t *frame,
        const gchar *submessages)
{
    const gchar *pattern = "SEC_PREFIX, SEC_BODY, SEC_POSTFIX";
    const gchar *frame_str = wmem_strbuf_get_str(frame);
    gsize idx = 0; /* index for iterating frame_str */
    gchar *submessages_dup = g_strdup(submessages);
    /* First decrypted submessage in submessages list */
    gchar *submessage_current = strtok(submessages_dup, ", ");
    /* First encrypted submessage. Found by searching the RTPS colinfo */
    gchar *encrypted_current = strstr(&frame_str[idx], pattern);

    while (encrypted_current != NULL) {
        /* Copy the RTPS frame up to the newly found encrypted submessage */
        gsize length_to_copy = encrypted_current - &frame_str[idx];
        wmem_strbuf_append_len(out, &frame_str[idx], length_to_copy);

        /* Copy the decrypted contents that replace the encrypted submessage */
        wmem_strbuf_append(out, submessage_current);

        /* Advance the index and continue searching */
        idx += length_to_copy + strlen(pattern);
        encrypted_current = strstr(&frame_str[idx], pattern);
    }
    /* Copy the remaining from the RTPS frame */
    wmem_strbuf_append(out, &frame_str[idx]);
}

/* ========================================================================== */
/*                            Protocol egistration                            */
/* ========================================================================== */
void
proto_register_rtps_processed(void)
{
    static hf_register_info hf[] = {
        {
            &rtpsproc_hf_param_id,
            {
                "Parameter Identifier", "rtpsproc.param.id",
                FT_UINT16, BASE_DEC, NULL, 0, 0, HFILL
            },
        },
        {
            &rtpsproc_hf_param_length,
            {
                "Parameter Length", "rtpsproc.param.length",
                FT_UINT16, BASE_DEC, NULL, 0, 0, HFILL
            }
        },
    };
    static gint *ett[] = {
        &rtpsproc_ett,
        &rtpsproc_ett_security,
        &rtpsproc_ett_advanced_frame0,
        &rtpsproc_ett_advanced_frame1
    };

  /* Register the protocol name and description */
    rtpsproc_tree = proto_register_protocol(
            "Real-Time Publish-Subscribe Wire Protocol (processed)",
            "RTPS-PROC",
            "rtpsproc");

    /* Required function calls to register the header fields and subtrees */
    rtpsproc_hf = proto_registrar_get_nth(rtpsproc_tree);
    proto_register_field_array(rtpsproc_tree, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("rtpsproc", dissect_rtps_processed, rtpsproc_tree);
}

// /*
//  * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
//  *
//  * Local variables:
//  * c-basic-offset: 4
//  * tab-width: 8
//  * indent-tabs-mode: nil
//  * End:
//  *
//  * vi: set shiftwidth=4 tabstop=8 expandtab:
//  * :indentSize=4:tabSize=8:noTabs=true:
//  */
