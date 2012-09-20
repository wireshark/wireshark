/* packet-gsm_sms_ud.c
 * Routines for GSM SMS TP-UD (GSM 03.40) dissection
 *
 * $Id$
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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>

#include <epan/prefs.h>
#include <epan/reassemble.h>

static void dissect_gsm_sms_ud(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

static int proto_gsm_sms_ud = -1;

/*
 * Short Message fragment handling
 */
static int hf_gsm_sms_ud_fragments = -1;
static int hf_gsm_sms_ud_fragment = -1;
static int hf_gsm_sms_ud_fragment_overlap = -1;
static int hf_gsm_sms_ud_fragment_overlap_conflicts = -1;
static int hf_gsm_sms_ud_fragment_multiple_tails = -1;
static int hf_gsm_sms_ud_fragment_too_long_fragment = -1;
static int hf_gsm_sms_ud_fragment_error = -1;
static int hf_gsm_sms_ud_fragment_count = -1;
static int hf_gsm_sms_ud_reassembled_in = -1;
static int hf_gsm_sms_ud_reassembled_length = -1;
/*
 * User Data Header section
 */
static int hf_gsm_sms_udh_length = -1;
static int hf_gsm_sms_udh_iei = -1;
static int hf_gsm_sms_udh_multiple_messages = -1;
static int hf_gsm_sms_udh_multiple_messages_msg_id = -1;
static int hf_gsm_sms_udh_multiple_messages_msg_parts = -1;
static int hf_gsm_sms_udh_multiple_messages_msg_part = -1;
static int hf_gsm_sms_udh_ports = -1;
static int hf_gsm_sms_udh_ports_src = -1;
static int hf_gsm_sms_udh_ports_dst = -1;

static gint ett_gsm_sms = -1;
static gint ett_udh = -1;
static gint ett_udh_ie = -1;
static gint ett_gsm_sms_ud_fragment = -1;
static gint ett_gsm_sms_ud_fragments = -1;

/* Subdissector declarations */
static dissector_table_t gsm_sms_dissector_table;

/* Short Message reassembly */
static GHashTable *sm_fragment_table    = NULL;
static GHashTable *sm_reassembled_table = NULL;

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
static gboolean port_number_udh_means_wsp = FALSE;

/* Always try dissecting the 1st fragment of a SM,
 * even if it is not reassembled */
static gboolean try_dissect_1st_frag = FALSE;

/* Prevent subdissectors changing column data */
static gboolean prevent_subdissectors_changing_columns = FALSE;

static dissector_handle_t wsp_handle;

static void
gsm_sms_ud_defragment_init(void)
{
    fragment_table_init(&sm_fragment_table);
    reassembled_table_init(&sm_reassembled_table);
}

/*
 * Value-arrays for field-contents
 */
/* 3GPP TS 23.040 V6.1.0 (2003-06) */
static const value_string vals_udh_iei[] = {
    { 0x00, "SMS - Concatenated short messages, 8-bit reference number" },
    { 0x01, "SMS - Special SMS Message Indication" },
    { 0x02, "Reserved" },
    { 0x03, "Value not used to avoid misinterpretation as <LF> character" },
    { 0x04, "SMS - Application port addressing scheme, 8 bit address" },
    { 0x05, "SMS - Application port addressing scheme, 16 bit address" },
    { 0x06, "SMS - SMSC Control Parameters" },
    { 0x07, "SMS - UDH Source Indicator" },
    { 0x08, "SMS - Concatenated short message, 16-bit reference number" },
    { 0x09, "SMS - Wireless Control Message Protocol" },
    { 0x0A, "EMS - Text Formatting" },
    { 0x0B, "EMS - Predefined Sound" },
    { 0x0C, "EMS - User Defined Sound (iMelody max 128 bytes)" },
    { 0x0D, "EMS - Predefined Animation" },
    { 0x0E, "EMS - Large Animation (16*16 times 4 = 32*4 =128 bytes)" },
    { 0x0F, "EMS - Small Animation (8*8 times 4 = 8*4 =32 bytes)" },
    { 0x10, "EMS - Large Picture (32*32 = 128 bytes)" },
    { 0x11, "EMS - Small Picture (16*16 = 32 bytes)" },
    { 0x12, "EMS - Variable Picture" },
    { 0x13, "EMS - User prompt indicator" },
    { 0x14, "EMS - Extended Object" },
    { 0x15, "EMS - Reused Extended Object" },
    { 0x16, "EMS - Compression Control" },
    { 0x17, "EMS - Object Distribution Indicator" },
    { 0x18, "EMS - Standard WVG object" },
    { 0x19, "EMS - Character Size WVG object" },
    { 0x1A, "EMS - Extended Object Data Request Command" },
    { 0x20, "SMS - RFC 822 E-Mail Header" },
    { 0x21, "SMS - Hyperlink format element" },
    { 0x22, "SMS - Reply Address Element" },
    { 0x00, NULL }
};


/* Parse Short Message, only if UDH present
 * (otherwise this function is not called).
 * Call WSP dissector if port matches WSP traffic.
 */
static void
parse_gsm_sms_ud_message(proto_tree *sm_tree, tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *top_tree)
{
    tvbuff_t      *sm_tvb                    = NULL;
    proto_item    *ti;
    proto_tree    *subtree, *tree;
    guint8         udh_len, udh, len;
    guint          sm_len                    = tvb_reported_length(tvb);
    guint          sm_data_len;
    guint32        i                         = 0;
    /* Multiple Messages UDH */
    gboolean       is_fragmented             = FALSE;
    fragment_data *fd_sm                     = NULL;
    guint16        sm_id                     = 0;
    guint16        frags                     = 0;
    guint16        frag                      = 0;
    gboolean       save_fragmented           = FALSE;
    gboolean       try_gsm_sms_ud_reassemble = FALSE;
    /* SMS Message reassembly */
    gboolean       reassembled               = FALSE;
    guint32        reassembled_in            = 0;
    /* Port Number UDH */
    guint16        p_src                     = 0;
    guint16        p_dst                     = 0;
    gboolean       ports_available           = FALSE;

    udh_len = tvb_get_guint8(tvb, i++);
    ti   = proto_tree_add_uint(sm_tree, hf_gsm_sms_udh_length, tvb, 0, 1, udh_len);
    tree = proto_item_add_subtree(ti, ett_udh);
    while (i < udh_len) {
        udh = tvb_get_guint8(tvb, i++);
        len = tvb_get_guint8(tvb, i++);
        subtree = proto_tree_add_uint(tree, hf_gsm_sms_udh_iei,
                tvb, i-2, 2+len, udh);
        switch (udh) {
            case 0x00: /* Multiple messages - 8-bit message ID */
                if (len == 3) {
                    sm_id = tvb_get_guint8(tvb, i++);
                    frags = tvb_get_guint8(tvb, i++);
                    frag  = tvb_get_guint8(tvb, i++);
                    if (frags > 1)
                        is_fragmented = TRUE;
                    proto_item_append_text(subtree,
                            ": message %u, part %u of %u", sm_id, frag, frags);
                    subtree = proto_item_add_subtree(subtree,
                            ett_udh_ie);
                    proto_tree_add_uint(subtree,
                            hf_gsm_sms_udh_multiple_messages_msg_id,
                            tvb, i-3, 1, sm_id);
                    proto_tree_add_uint(subtree,
                            hf_gsm_sms_udh_multiple_messages_msg_parts,
                            tvb, i-2, 1, frags);
                    proto_tree_add_uint(subtree,
                            hf_gsm_sms_udh_multiple_messages_msg_part,
                            tvb, i-1, 1, frag);
                } else {
                    proto_item_append_text(subtree, " - Invalid format!");
                    i += len;
                }
                break;

            case 0x08: /* Multiple messages - 16-bit message ID */
                if (len == 4) {
                    sm_id = tvb_get_ntohs(tvb, i); i += 2;
                    frags = tvb_get_guint8(tvb, i++);
                    frag  = tvb_get_guint8(tvb, i++);
                    if (frags > 1)
                        is_fragmented = TRUE;
                    proto_item_append_text(subtree,
                            ": message %u, part %u of %u", sm_id, frag, frags);
                    subtree = proto_item_add_subtree(subtree,
                            ett_udh_ie);
                    proto_tree_add_uint(subtree,
                            hf_gsm_sms_udh_multiple_messages_msg_id,
                            tvb, i-4, 2, sm_id);
                    proto_tree_add_uint(subtree,
                            hf_gsm_sms_udh_multiple_messages_msg_parts,
                            tvb, i-2, 1, frags);
                    proto_tree_add_uint(subtree,
                            hf_gsm_sms_udh_multiple_messages_msg_part,
                            tvb, i-1, 1, frag);
                } else {
                    proto_item_append_text(subtree, " - Invalid format!");
                    i += len;
                }
                break;

            case 0x04: /* Port Number UDH - 8-bit address */
                if (len == 2) { /* Port fields */
                    p_dst = tvb_get_guint8(tvb, i++);
                    p_src = tvb_get_guint8(tvb, i++);
                    proto_item_append_text(subtree,
                            ": source port %u, destination port %u",
                            p_src, p_dst);
                    subtree = proto_item_add_subtree(subtree, ett_udh_ie);
                    proto_tree_add_uint(subtree, hf_gsm_sms_udh_ports_dst,
                            tvb, i-2, 1, p_dst);
                    proto_tree_add_uint(subtree, hf_gsm_sms_udh_ports_src,
                            tvb, i-1, 1, p_src);
                    ports_available = TRUE;
                } else {
                    proto_item_append_text(subtree, " - Invalid format!");
                    i += len;
                }
                break;

            case 0x05: /* Port Number UDH - 16-bit address */
                if (len == 4) { /* Port fields */
                    p_dst = tvb_get_ntohs(tvb, i); i += 2;
                    p_src = tvb_get_ntohs(tvb, i); i += 2;
                    proto_item_append_text(subtree,
                            ": source port %u, destination port %u",
                            p_src, p_dst);
                    subtree = proto_item_add_subtree(subtree, ett_udh_ie);
                    proto_tree_add_uint(subtree, hf_gsm_sms_udh_ports_dst,
                            tvb, i-4, 2, p_dst);
                    proto_tree_add_uint(subtree, hf_gsm_sms_udh_ports_src,
                            tvb, i-2, 2, p_src);
                    ports_available = TRUE;
                } else {
                    proto_item_append_text(subtree, " - Invalid format!");
                    i += len;
                }
                break;

            default:
                i += len;
                break;
        }
    }
    if (tvb_reported_length_remaining(tvb, i) <= 0)
        return; /* No more data */

    /*
     * XXX - where does the "1" come from?  If it weren't there,
     * "sm_data_len" would, I think, be the same as
     * "tvb_reported_length_remaining(tvb, i)".
     *
     * I think that the above check ensures that "sm_len" won't
     * be less than or equal to "udh_len", so it ensures that
     * "sm_len" won't be less than "1 + udh_len", so we don't
     * have to worry about "sm_data_len" being negative.
     */
    sm_data_len = sm_len - (1 + udh_len);
    if (sm_data_len == 0)
        return; /* no more data */

    /*
     * Try reassembling the packets.
     * XXX - fragment numbers are 1-origin, but the fragment number
     * field could be 0.
     * Should we flag a fragmented message with a fragment number field
     * of 0?
     * What if the fragment count is 0?  Should we flag that as well?
     */
    if (is_fragmented && frag != 0 && frags != 0 &&
        tvb_bytes_exist(tvb, i, sm_data_len)) {
        try_gsm_sms_ud_reassemble = TRUE;
        save_fragmented = pinfo->fragmented;
        pinfo->fragmented = TRUE;
        fd_sm = fragment_add_seq_check(tvb, i, pinfo,
                sm_id,                /* guint32 ID for fragments belonging together */
                sm_fragment_table,    /* list of message fragments */
                sm_reassembled_table, /* list of reassembled messages */
                frag-1,               /* guint32 fragment sequence number */
                sm_data_len,          /* guint32 fragment length */
                (frag != frags));     /* More fragments? */
        if (fd_sm) {
            reassembled    = TRUE;
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
                    " (Short Message fragment %u of %u)", frag, frags);
        }
    } /* Else: not fragmented */

    if (! sm_tvb) /* One single Short Message, or not reassembled */
        sm_tvb = tvb_new_subset_remaining(tvb, i);
    /* Try calling a subdissector */
    if (sm_tvb) {
        if ((reassembled && pinfo->fd->num == reassembled_in)
            || frag==0 || (frag==1 && try_dissect_1st_frag)) {
            /* Try calling a subdissector only if:
             *  - the Short Message is reassembled in this very packet,
             *  - the Short Message consists of only one "fragment",
             *  - the preference "Always Try Dissection for 1st SM fragment"
             *    is switched on, and this is the SM's 1st fragment. */
            if (ports_available) {
                gboolean disallow_write = FALSE; /* TRUE if we changed writability
                                    of the columns of the summary */
                if (prevent_subdissectors_changing_columns && col_get_writable(pinfo->cinfo)) {
                    disallow_write = TRUE;
                    col_set_writable(pinfo->cinfo, FALSE);
                }

                if (port_number_udh_means_wsp) {
                    call_dissector(wsp_handle, sm_tvb, pinfo, top_tree);
                } else {
                    if (! dissector_try_uint(gsm_sms_dissector_table, p_src,
                                sm_tvb, pinfo, top_tree)) {
                        if (! dissector_try_uint(gsm_sms_dissector_table, p_dst,
                                    sm_tvb, pinfo, top_tree)) {
                            if (sm_tree) { /* Only display if needed */
                                proto_tree_add_text(sm_tree, sm_tvb, 0, -1,
                                        "Short Message body");
                            }
                        }
                    }
                }

                if (disallow_write)
                    col_set_writable(pinfo->cinfo, TRUE);
            } else { /* No ports IE */
                proto_tree_add_text(sm_tree, sm_tvb, 0, -1,
                        "Short Message body");
            }
        } else {
            /* The packet is not reassembled,
             * or it is reassembled in another packet */
            proto_tree_add_text(sm_tree, sm_tvb, 0, -1,
                    "Unreassembled Short Message fragment %u of %u",
                    frag, frags);
        }
    }

    if (try_gsm_sms_ud_reassemble) /* Clean up defragmentation */
        pinfo->fragmented = save_fragmented;
    return;
}

static void
dissect_gsm_sms_ud(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *ti;
    proto_tree *subtree;

    ti      = proto_tree_add_item(tree, proto_gsm_sms_ud, tvb, 0, -1, ENC_NA);
    subtree = proto_item_add_subtree(ti, ett_gsm_sms);
    parse_gsm_sms_ud_message(subtree, tvb, pinfo, tree);
}

/* Register the protocol with Wireshark */
void
proto_register_gsm_sms_ud(void)
{
    module_t *gsm_sms_ud_module; /* Preferences for GSM SMS UD */

    /* Setup list of header fields  */
    static hf_register_info hf[] = {
        /*
         * User Data Header
         */
        {   &hf_gsm_sms_udh_iei,
            {   "IE Id", "gsm_sms_ud.udh.iei",
                FT_UINT8, BASE_HEX, VALS(vals_udh_iei), 0x00,
                "Name of the User Data Header Information Element.",
                HFILL
            }
        },
        {   &hf_gsm_sms_udh_length,
            {   "UDH Length", "gsm_sms_ud.udh.len",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Length of the User Data Header (bytes)",
                HFILL
            }
        },
        {   &hf_gsm_sms_udh_multiple_messages,
            {   "Multiple messages UDH", "gsm_sms_ud.udh.mm",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Multiple messages User Data Header",
                HFILL
            }
        },
        {   &hf_gsm_sms_udh_multiple_messages_msg_id,
            {   "Message identifier", "gsm_sms_ud.udh.mm.msg_id",
                FT_UINT16, BASE_DEC, NULL, 0x00,
                "Identification of the message",
                HFILL
            }
        },
        {   &hf_gsm_sms_udh_multiple_messages_msg_parts,
            {   "Message parts", "gsm_sms_ud.udh.mm.msg_parts",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Total number of message parts (fragments)",
                HFILL
            }
        },
        {   &hf_gsm_sms_udh_multiple_messages_msg_part,
            {   "Message part number", "gsm_sms_ud.udh.mm.msg_part",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                "Message part (fragment) sequence number",
                HFILL
            }
        },
        {   &hf_gsm_sms_udh_ports,
            {   "Port number UDH", "gsm_sms_ud.udh.ports",
                FT_NONE, BASE_NONE, NULL, 0x00,
                "Port number User Data Header",
                HFILL
            }
        },
        {   &hf_gsm_sms_udh_ports_src,
            {   "Source port", "gsm_sms_ud.udh.ports.src",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL,
                HFILL
            }
        },
        {   &hf_gsm_sms_udh_ports_dst,
            {   "Destination port", "gsm_sms_ud.udh.ports.dst",
                FT_UINT8, BASE_DEC, NULL, 0x00,
                NULL,
                HFILL
            }
        },
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
    };

    static gint *ett[] = {
    &ett_gsm_sms,
    &ett_udh,
    &ett_udh_ie,
    &ett_gsm_sms_ud_fragment,
    &ett_gsm_sms_ud_fragments,
    };
    /* Register the protocol name and description */
    proto_gsm_sms_ud = proto_register_protocol(
        "GSM Short Message Service User Data",  /* Name */
        "GSM SMS UD",           /* Short name */
        "gsm_sms_ud");          /* Filter name */

    /* Required function calls to register header fields and subtrees used */
    proto_register_field_array(proto_gsm_sms_ud, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Subdissector code */
    gsm_sms_dissector_table = register_dissector_table("gsm_sms_ud.udh.port",
        "GSM SMS port IE in UDH", FT_UINT16, BASE_DEC);

    /* Preferences for GSM SMS UD */
    gsm_sms_ud_module = prefs_register_protocol(proto_gsm_sms_ud, NULL);
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

    /* GSM SMS UD dissector initialization routines */
    register_init_routine(gsm_sms_ud_defragment_init);
}

void
proto_reg_handoff_gsm_sms_ud(void)
{
    wsp_handle = find_dissector("wsp-cl");
    DISSECTOR_ASSERT(wsp_handle);
}
