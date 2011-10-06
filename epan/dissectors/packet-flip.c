/* packet-flip.c
 * Routines for FLIP packet dissection
 *
 * Copyright 2009, Juha Siltanen <juha.siltanen@nsn.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

/*
 * FLIP (Flow Layer Internal Protocol) is a proprietary protocol
 * developed by Nokia Siemens Networks.
 */

/*
 * Version information
 *
 * Version 0.0.1, November 23rd, 2009.
 *
 * Support for the basic and checksum headers.
 *
 * Version 0.0.2, August 26th, 2010.
 *
 * Support for payload dissecting.
 *
 * Version 0.0.3, September 14th, 2010.
 *
 * Bugfix: sorting by protocol didn't always fill in the protocol column.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/in_cksum.h>

#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/strutil.h>

#include "packet-rtp.h"
#include "packet-rtcp.h"
#include <epan/rtp_pt.h>

static int proto_flip = -1;

/* BASIC */
static int hf_flip_basic_e         = -1;
static int hf_flip_basic_reserved  = -1;
static int hf_flip_basic_flowid    = -1;
static int hf_flip_basic_seqnum    = -1;
static int hf_flip_basic_len       = -1;

/* CHECKSUM */
static int hf_flip_chksum_etype  = -1;
static int hf_flip_chksum_spare  = -1;
static int hf_flip_chksum_e      = -1;
static int hf_flip_chksum_chksum = -1;

#define FLIP_BASIC            (0)
#define FLIP_CHKSUM           (1)

#define FLIP_BASIC_HDR_LEN         (8)
#define FLIP_CHKSUM_HDR_LEN        (4)
#define FLIP_EXTENSION_HDR_MIN_LEN (4)

static const value_string flip_short_header_names[]={
    { FLIP_BASIC,  "BASIC" },
    { FLIP_CHKSUM, "CHKSUM"},
    { 0,           NULL}
};

static const value_string flip_long_header_names[] = {
    { FLIP_BASIC,  "Basic"},
    { FLIP_CHKSUM, "Checksum"},
    { 0,           NULL }
};

static const value_string flip_boolean[] = {
    {0, "No"},
    {1, "Yes"},
    {0, NULL}
};

static const value_string flip_etype[] = {
    { FLIP_CHKSUM, "Checksum" },
    { 0,           NULL }
};

#define FLIP_PAYLOAD_DECODING_MODE_NONE      (0)
#define FLIP_PAYLOAD_DECODING_MODE_HEURISTIC (1)
#define FLIP_PAYLOAD_DECODING_MODE_FORCED    (2)

static enum_val_t flip_payload_decoding_modes[] = {
    {"none",      "no decoding", FLIP_PAYLOAD_DECODING_MODE_NONE},
    {"heuristic", "heuristic",   FLIP_PAYLOAD_DECODING_MODE_HEURISTIC},
    {"forced",    "forced",      FLIP_PAYLOAD_DECODING_MODE_FORCED},
    {NULL, NULL, 0}
};

static gint global_flip_payload_decoding_mode =
    FLIP_PAYLOAD_DECODING_MODE_HEURISTIC;

static gboolean is_heur_enabled_rtp  = TRUE;
static gboolean is_heur_enabled_rtcp = TRUE;

static const char *global_forced_protocol = "data";
static gboolean is_forced_handle_ok = FALSE;

static gint ett_flip         = -1;
static gint ett_flip_basic   = -1;
static gint ett_flip_chksum  = -1;
static gint ett_flip_payload = -1;

static dissector_handle_t rtp_handle;
static dissector_handle_t rtcp_handle;
static dissector_handle_t data_handle;
static dissector_handle_t forced_handle;

/* Forward declaration. */
void
proto_reg_handoff_flip(void);
static gboolean
is_payload_rtp(tvbuff_t *tvb);
static gboolean
is_payload_rtcp(tvbuff_t *tvb);

/* Dissect the checksum extension header. */
static int
dissect_flip_chksum_hdr(tvbuff_t    *tvb,
                        packet_info *pinfo,
                        proto_tree  *tree,
                        guint16     computed_chksum,
                        gboolean    *ext_hdr_follows_ptr)
{
    proto_item *item;
    proto_tree *chksum_hdr_tree;
    guint32  dw;
    guint8   chksum_hdr_etype;
    guint8   chksum_hdr_spare;
    guint8   chksum_hdr_ext;
    guint16  chksum_hdr_chksum;

    gint bytes_dissected;
    gint offset;

    item            = NULL;
    chksum_hdr_tree = NULL;

    bytes_dissected = 0;
    offset          = 0;

    dw = tvb_get_ntohl(tvb, offset);
    chksum_hdr_etype  = (guint8) ((dw & 0xFF000000) >> 24);
    chksum_hdr_spare  = (guint8) ((dw & 0x00FE0000) >> 17);
    chksum_hdr_ext    = (guint8) ((dw & 0x00010000) >> 16);
    chksum_hdr_chksum = (guint16) (dw & 0x0000FFFF);

    /* The actually shouldn't be any headers after checksum. */
    if (chksum_hdr_ext == 1) {
        *ext_hdr_follows_ptr = TRUE;
    }
    else {
        *ext_hdr_follows_ptr = FALSE;
    }

    if (tree) {
        item = proto_tree_add_text(tree, tvb,
                                   offset + 0, 4, "Checksum Header");
        chksum_hdr_tree = proto_item_add_subtree(item, ett_flip_chksum);

        /* ETYPE: 8 bits */
        proto_tree_add_uint_format_value(chksum_hdr_tree, hf_flip_chksum_etype,
                                         tvb, offset + 0, 1, dw,
                                         "%s", val_to_str(chksum_hdr_etype,
                                                    flip_etype,
                                                    "Unknown"));
        /* SPARE: 7 bits */
        proto_tree_add_uint_format_value(chksum_hdr_tree, hf_flip_chksum_spare,
                                         tvb, offset + 1, 1, dw,
                                         "%d (0x%02x)",
                                         chksum_hdr_spare, chksum_hdr_spare);

        /* EXT HDR: 1 bit */
        proto_tree_add_uint_format_value(chksum_hdr_tree, hf_flip_chksum_e,
                                         tvb, offset + 1, 1, dw,
                                         "%s", val_to_str(chksum_hdr_ext,
                                                    flip_boolean,
                                                    "Unknown"));
        /* CHKSUM: 16 bits. */
        proto_tree_add_uint_format_value(
            chksum_hdr_tree,
            hf_flip_chksum_chksum,
            tvb, offset + 2, 2,
            chksum_hdr_chksum,
            "0x%04x [%s] (computed 0x%04x)",
            chksum_hdr_chksum,
            ((chksum_hdr_chksum == computed_chksum) ? "Correct" : "Incorrect"),
            computed_chksum);
    }

    /* Show faulty checksums. */
    if (computed_chksum != chksum_hdr_chksum) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "Checksum 0x%04x [%s] (computed 0x%04x)",
                     chksum_hdr_chksum,
                     ((chksum_hdr_chksum == computed_chksum) ?
                      "Correct" : "Incorrect"),
                     computed_chksum);
    }

    bytes_dissected += FLIP_CHKSUM_HDR_LEN;

    return bytes_dissected;

} /* dissect_flip_chksum_hdr() */


/* Detection logic grabbed from packet-rtp.c and modified. */

#define RTP_VERSION(octet)      ((octet) >> 6)
#define RTP_MARKER(octet)       ((octet) & 0x80)
#define RTP_PAYLOAD_TYPE(octet) ((octet) & 0x7F)

#define RTP_V2_HEADER_MIN_LEN 12

static gboolean
is_payload_rtp(tvbuff_t *tvb)
{
    guint8 octet1, octet2;
    unsigned int version;
    unsigned int payload_type;
    unsigned int offset;
    gint         len_remaining;

    offset = 0;

    len_remaining = tvb_length_remaining(tvb, offset);
    if (len_remaining < RTP_V2_HEADER_MIN_LEN) {
        return FALSE;
    }

    octet1 = tvb_get_guint8(tvb, offset);
    version = RTP_VERSION(octet1);

    /* Accept only version 2. */
    if (version != 2) {
        return FALSE;
    }

    octet2 = tvb_get_guint8(tvb, offset + 1);
    payload_type = RTP_PAYLOAD_TYPE(octet2);

    if ((payload_type <= PT_H263)
        ||
        ((payload_type >= PT_UNDF_96) && (payload_type <= PT_UNDF_127))) {
        /* OK */
        ;
    }
    else {
        return FALSE;
    }

    return TRUE;

} /* is_payload_rtp() */


/* Detection logic grabbed from packet-rtcp.c and modified. */

#define RTCP_SR    200
#define RTCP_RR    201
#define RTCP_BYE   203
#define RTCP_APP   204

#define RTCP_V2_HEADER_MIN_LEN 4

static gboolean
is_payload_rtcp(tvbuff_t *tvb)
{
    unsigned int first_byte;
    unsigned int packet_type;
    unsigned int offset;
    gint         len_remaining;

    offset = 0;

    len_remaining = tvb_length_remaining(tvb, offset);
    if (len_remaining < RTCP_V2_HEADER_MIN_LEN) {
        return FALSE;
    }

    /* Look at first byte */
    first_byte = tvb_get_guint8(tvb, offset);

    /* Are version bits set to 2? */
    if (((first_byte & 0xC0) >> 6) != 2) {
        return FALSE;
    }

    /* Look at packet type */
    packet_type = tvb_get_guint8(tvb, offset + 1);

    /* First packet within compound packet is supposed to be a sender
       or receiver report.
       - allow BYE because this happens anyway
       - allow APP because TBCP ("PoC1") packets aren't compound... */
    if (!((packet_type == RTCP_SR)  || (packet_type == RTCP_RR) ||
          (packet_type == RTCP_BYE) || (packet_type == RTCP_APP))) {
        return FALSE;
    }

    /* Overall length must be a multiple of 4 bytes */
    if (tvb_reported_length(tvb) % 4) {
        return FALSE;
    }

    return TRUE;

} /* is_payload_rtcp() */

/* Protocol dissection */
static int
dissect_flip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *item;
    proto_item *ti;
    proto_tree *flip_tree;
    proto_tree *basic_hdr_tree;
    tvbuff_t   *flip_tvb;

    guint32 dw1;
    guint32 dw2;

    /* Basic header fields. */
    guint8   basic_hdr_ext;
    guint8   basic_hdr_reserved;
    guint32  basic_hdr_flow_id;
    guint16  basic_hdr_seqnum;
    guint16  basic_hdr_len;

    gboolean ext_hdr;

    gint bytes_dissected;
    gint payload_len;
    gint frame_len;
    gint flip_len;
    gint offset;

    /* Error handling for basic header. */
    gboolean is_faulty_frame;

    item             = NULL;
    ti               = NULL;
    flip_tree        = NULL;
    basic_hdr_tree   = NULL;
    flip_tvb         = NULL;

    ext_hdr = FALSE;

    bytes_dissected = 0;
    payload_len     = 0;
    frame_len       = 0;
    flip_len        = 0;
    offset          = 0;

    is_faulty_frame     = FALSE;

    /* Show this protocol as FLIP. */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FLIP");

    /*
     * The frame can be faulty in several ways:
     * - too short (even for the basic header)
     * - length inconsistent (header and frame info different)
     * - checksum doesn't check out
     * - extension header is indicated, but the frame is too short for it
     * - unknown extension header type
     */

    /* Check that there's enough data at least for the basic header. */
    frame_len = tvb_length(tvb);
    if (frame_len < FLIP_BASIC_HDR_LEN) {
        /* Not enough. This must be a malformed packet. */
        goto DISSECT_FLIP_EXIT;
    }

    bytes_dissected += FLIP_BASIC_HDR_LEN;

    /* Process the first 32 bits of the basic header. */
    dw1 = tvb_get_ntohl(tvb, offset + 0);
    basic_hdr_ext      = ((dw1 & 0x80000000) >> 31);
    basic_hdr_reserved = ((dw1 & 0x70000000) >> 24);
    basic_hdr_flow_id  = (dw1 & 0x0FFFFFFF);

    /* Process the second 32 bits of the basic header. */
    dw2 = tvb_get_ntohl(tvb, offset + 4);
    basic_hdr_seqnum = (guint16) ((dw2 & 0xFFFF0000) >> 16);
    basic_hdr_len    = (guint16) (dw2 & 0x0000FFFF);

    /* Does the basic header indicate that an extension is next? */
    if (basic_hdr_ext == 1) {
        ext_hdr = TRUE;
    }

    flip_len = basic_hdr_len;

    /*
     * Check the length value.
     */
    if ((flip_len < FLIP_BASIC_HDR_LEN) || (flip_len > frame_len)) {
        /* Faulty frame. Show the basic header anyway for debugging. */
        is_faulty_frame = TRUE;
    }

    /* Fill in the info column. */
    col_add_fstr(pinfo->cinfo, COL_INFO,
                 "FlowID %s", val_to_str(basic_hdr_flow_id, NULL, "0x%08x"));

    flip_tvb = tvb_new_subset(tvb, 0, frame_len, frame_len);

    /* We are asked for details. */
    if (tree) {
        if (PTREE_DATA(tree)->visible) {
            ti = proto_tree_add_protocol_format(
                tree, proto_flip, flip_tvb, 0, flip_len,
                "NSN FLIP, FlowID %s",
                val_to_str(basic_hdr_flow_id, NULL, "0x%08x"));
        }
        else {
            ti = proto_tree_add_item(tree, proto_flip, flip_tvb, 0,
                                     flip_len, FALSE);
        }
        flip_tree = proto_item_add_subtree(ti, ett_flip);

        /* basic header */
        item = proto_tree_add_text(flip_tree, flip_tvb, 0, 8, "Basic Header");
        basic_hdr_tree = proto_item_add_subtree(item, ett_flip_basic);

        /* Extension header follows? 1 bit. */
        proto_tree_add_uint_format_value(basic_hdr_tree,
                                         hf_flip_basic_e,
                                         flip_tvb, offset + 0, 1, dw1,
                                         "%s", val_to_str(basic_hdr_ext,
                                                    flip_boolean,
                                                    "Unknown"));
        /* Reserved: 3 bits. */
        proto_tree_add_uint_format_value(basic_hdr_tree,
                                         hf_flip_basic_reserved,
                                         flip_tvb, offset + 0, 1, dw1,
                                         "%d", basic_hdr_reserved);
        /* Flow ID: 28 bits. */
        proto_tree_add_item(basic_hdr_tree, hf_flip_basic_flowid,
                            flip_tvb, offset + 0, 4, ENC_BIG_ENDIAN);

        /* Sequence number: 16 bits. */
        proto_tree_add_uint_format_value(basic_hdr_tree, hf_flip_basic_seqnum,
                                         flip_tvb, offset + 4, 2, dw2,
                                         "%d (0x%04x)",
                                         basic_hdr_seqnum, basic_hdr_seqnum);
        /* Packet length: 16 bits. */
        proto_tree_add_uint_format_value(basic_hdr_tree, hf_flip_basic_len,
                                         flip_tvb, offset + 6, 2, dw2,
                                         "%d (0x%04x)",
                                         basic_hdr_len, basic_hdr_len);
    }

    offset += FLIP_BASIC_HDR_LEN;

    /*
     * Process faults found when parsing the basic header.
     */
    if (is_faulty_frame == TRUE) {
        if (flip_len > frame_len) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Length mismatch: frame %d bytes, hdr %d bytes",
                         frame_len, flip_len);
        }
        else if (flip_len < FLIP_BASIC_HDR_LEN) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Invalid length in basic header: %d bytes", flip_len);
        }

        goto DISSECT_FLIP_EXIT;
    }

    /*
     * Now we know that the basic header is sensible.
     */
    payload_len  = basic_hdr_len;
    payload_len -= FLIP_BASIC_HDR_LEN;

    /*
     * Dissect extension headers (if any).
     */
    if ((ext_hdr == TRUE) && (payload_len < FLIP_EXTENSION_HDR_MIN_LEN)) {
        col_add_fstr(pinfo->cinfo, COL_INFO,
                     "Extension header indicated, but not enough data");
        goto DISSECT_FLIP_EXIT;
    }

    while ((ext_hdr == TRUE) && (payload_len >= FLIP_EXTENSION_HDR_MIN_LEN)) {
        /* Detect the next header type. */
        guint8  ext_hdr_type;
        gint    bytes_handled;
        guint16 computed_chksum;

        tvbuff_t *chksum_tvb;

        ext_hdr_type = tvb_get_guint8(flip_tvb, offset);

        switch (ext_hdr_type) {
        case FLIP_CHKSUM:
            /* Calculate checksum, let the chksum dissector verify it. */
            {
                vec_t   vec[2];

                vec[0].ptr = tvb_get_ptr(flip_tvb, 0, bytes_dissected + 2);
                vec[0].len = bytes_dissected + 2;
                vec[1].ptr = tvb_get_ptr(flip_tvb, bytes_dissected + 4,
                                         flip_len - (bytes_dissected + 4));
                vec[1].len = flip_len - (bytes_dissected + 4);
                computed_chksum = in_cksum(&vec[0], 2);

                /* Checksums handled in network order. */
                computed_chksum = g_htons(computed_chksum);
            }

            chksum_tvb = tvb_new_subset(flip_tvb, offset,
                                        FLIP_CHKSUM_HDR_LEN,
                                        FLIP_CHKSUM_HDR_LEN);

            /* Note that flip_tree is NULL if no details are requested. */
            bytes_handled = dissect_flip_chksum_hdr(chksum_tvb,
                                                    pinfo,
                                                    flip_tree,
                                                    computed_chksum,
                                                    &ext_hdr);
            bytes_dissected += bytes_handled;
            payload_len     -= bytes_handled;
            offset          += bytes_handled;
            break;

        default:
            /* Unknown header type. */
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Invalid extension header type 0x%02x", ext_hdr_type);
            goto DISSECT_FLIP_EXIT;
            break;
        }
    }

    /*
     * Show payload (if any) as bytes.
     */
    if (payload_len > 0) {

        dissector_handle_t handle;
        tvbuff_t           *payload_tvb;
        gint               data_len;
        gboolean           has_user_messed_up;

        data_len = 0;
        has_user_messed_up = FALSE;

        payload_tvb = tvb_new_subset(flip_tvb, offset,
                                     payload_len, payload_len);

        /*
         * 1) no decoding -> data
         * 2) heuristic decoding
         * 3) forced decoding
         */
        switch (global_flip_payload_decoding_mode) {
        case FLIP_PAYLOAD_DECODING_MODE_NONE:
            /* Dissect as data. */
            handle = data_handle;
            break;

        case FLIP_PAYLOAD_DECODING_MODE_HEURISTIC:
            if ((is_heur_enabled_rtp == TRUE)
                &&
                (is_payload_rtp(payload_tvb) == TRUE)) {
                /* Dissect as RTP. */
                handle = rtp_handle;
            }
            else if ((is_heur_enabled_rtcp == TRUE)
                     &&
                     (is_payload_rtcp(payload_tvb))) {
                /* Dissect as RTCP. */
                handle = rtcp_handle;
            }
            else {
                /* Dissect as data. */
                handle = data_handle;
            }
            break;

        case FLIP_PAYLOAD_DECODING_MODE_FORCED:
            if (is_forced_handle_ok == TRUE) {
                handle = forced_handle;
            }
            else {
                /* Use data as backup. */
                handle = data_handle;

                /* Tell the user he messed up. */
                has_user_messed_up = TRUE;
            }
            break;

        default:
            /* Fault in dissector's internal logic. */
            DISSECTOR_ASSERT(0);
            break;
        }

        /*
         * If tree is NULL, we still cannot quit, we must give
         * the RTP/RTCP/data dissectors a chance to fill in
         * the protocol column.
         */
        data_len = call_dissector(handle, payload_tvb, pinfo, tree);

        if (has_user_messed_up == TRUE) {
            col_add_fstr(pinfo->cinfo, COL_INFO,
                         "Invalid user dissector \"%s\"",
                         global_forced_protocol);
        }

        bytes_dissected += data_len;

    } /* if (payload_len > 0) */

DISSECT_FLIP_EXIT:
    return bytes_dissected;

} /* dissect_flip() */


/* Protocol initialization */
void
proto_register_flip(void)
{
    static hf_register_info hf[] = {
        /*
         * Basic header.
         */
        {&hf_flip_basic_e,
         {"Extension Header Follows", "flip.basic.e", FT_UINT32, BASE_DEC,
          VALS(flip_boolean), 0x80000000, NULL, HFILL}
        },
        {&hf_flip_basic_reserved,
         {"Reserved", "flip.basic.reserved", FT_UINT32, BASE_DEC,
          NULL, 0x70000000, "Basic Header Reserved", HFILL}
        },
        {&hf_flip_basic_flowid,
         {"FlowID", "flip.basic.flowid", FT_UINT32, BASE_HEX,
          NULL, 0x0FFFFFFF, "Basic Header Flow ID", HFILL}
        },
        {&hf_flip_basic_seqnum,
         {"Seqnum", "flip.basic.seqnum", FT_UINT32, BASE_DEC,
          NULL, 0xFFFF0000, "Basic Header Sequence Number", HFILL}
        },
        {&hf_flip_basic_len,
         {"Len", "flip.basic.len", FT_UINT32, BASE_DEC,
          NULL, 0x0000FFFF, "Basic Header Packet Length", HFILL}
        },
        /*
         * Checksum header.
         */
        {&hf_flip_chksum_etype,
         {"Extension Type", "flip.chksum.etype", FT_UINT32, BASE_DEC,
          VALS(flip_etype), 0xFF000000, "Checksum Header Extension Type", HFILL}
        },
        {&hf_flip_chksum_spare,
         {"Spare", "flip.chksum.spare", FT_UINT32, BASE_DEC,
          NULL, 0x00FE0000, "Checksum Header Spare", HFILL}
        },
        {&hf_flip_chksum_e,
         {"Extension Header Follows", "flip.chksum.e", FT_UINT32, BASE_DEC,
          VALS(flip_boolean), 0x00010000, NULL, HFILL}
        },
        {&hf_flip_chksum_chksum,
         {"Checksum", "flip.chksum.chksum", FT_UINT32, BASE_HEX,
          NULL, 0x0000FFFF, NULL, HFILL}
        }
    };

    static gint *ett[] = {
        &ett_flip,
        &ett_flip_basic,
        &ett_flip_chksum,
        &ett_flip_payload
    };

    module_t *flip_module;

    proto_flip = proto_register_protocol(
        "NSN FLIP", /* name */
        "FLIP",     /* short name */
        "flip"      /* abbrev */
        );

    proto_register_field_array(proto_flip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));


    flip_module = prefs_register_protocol(proto_flip,
                                          proto_reg_handoff_flip);

    /* Register preferences */
    prefs_register_enum_preference(
        flip_module,
        "decoding_mode",
        "FLIP payload decoding mode",
        "Decode FLIP payload according to mode",
        &global_flip_payload_decoding_mode,
        flip_payload_decoding_modes,
        TRUE);

    prefs_register_static_text_preference(
        flip_module,
        "heur_enabled_protocols",
        "Heuristic mode: enabled protocols",
        "Enabled protocols for heuristic mode");

    prefs_register_bool_preference(
        flip_module,
        "heur_decode_rtp",
        "RTP",
        "Decode payload as RTP if detected",
        &is_heur_enabled_rtp);

    prefs_register_bool_preference(
        flip_module,
        "heur_decode_rtcp",
        "RTCP",
        "Decode payload as RTCP if detected",
        &is_heur_enabled_rtcp);

    prefs_register_static_text_preference(
        flip_module,
        "forced_protocol",
        "Forced mode: decode to user-specified protocol",
        "Mapping of flow IDs to their decodings");

    prefs_register_string_preference(
        flip_module,
        "forced_decode",
        "Protocol name",
        "Decoding to user-defined protocol",
        &global_forced_protocol);

} /* proto_register_flip() */

/* Protocol handoff */
void
proto_reg_handoff_flip(void)
{
    dissector_handle_t flip_handle;

    static gboolean flip_prefs_initialized = FALSE;

    if (flip_prefs_initialized == FALSE) {
        flip_handle = new_create_dissector_handle(dissect_flip, proto_flip);
        dissector_add_uint("ethertype", ETHERTYPE_FLIP, flip_handle);

        rtp_handle  = find_dissector("rtp");
        rtcp_handle = find_dissector("rtcp");
        data_handle = find_dissector("data");

        flip_prefs_initialized = TRUE;
    }

    /* Preferences update: check user-specified dissector. */
    is_forced_handle_ok = FALSE;
    forced_handle = find_dissector(global_forced_protocol);
    if (forced_handle != NULL) {
        is_forced_handle_ok = TRUE;
    }

} /* proto_reg_handoff_flip() */

/* end of file packet-flip.c */
