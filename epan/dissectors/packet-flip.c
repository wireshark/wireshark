/* packet-flip.c
 * Routines for FLIP packet dissection
 *
 * Copyright 2009, Juha Siltanen <juha.siltanen@nsn.com>
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

/*
 * FLIP (Flow Layer Internal Protocol) is a proprietary protocol
 * developed by Nokia Solutions and Networks (previous was 'Nokia Siemens Networks').
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

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/decode_as.h>
#include <epan/in_cksum.h>

#include <epan/prefs.h>

#include <epan/rtp_pt.h>

void proto_register_flip(void);
void proto_reg_handoff_flip(void);

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

static const value_string flip_etype[] = {
    { FLIP_CHKSUM, "Checksum" },
    { 0,           NULL }
};

static dissector_table_t subdissector_table;

static gint ett_flip         = -1;
static gint ett_flip_basic   = -1;
static gint ett_flip_chksum  = -1;
static gint ett_flip_payload = -1;

static void flip_prompt(packet_info *pinfo _U_, gchar* result)
{
    g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Decode FLIP payload protocol as");
}

static gpointer flip_value(packet_info *pinfo _U_)
{
    return 0;
}

/* Dissect the checksum extension header. */
static int
dissect_flip_chksum_hdr(tvbuff_t    *tvb,
                        packet_info *pinfo,
                        proto_tree  *tree,
                        guint16     computed_chksum,
                        gboolean    *ext_hdr_follows_ptr)
{
    proto_tree *chksum_hdr_tree;
    guint32  dw;
    guint8   chksum_hdr_etype;
    guint8   chksum_hdr_ext;
    guint16  chksum_hdr_chksum;

    gint bytes_dissected;
    gint offset;

    chksum_hdr_tree = NULL;

    bytes_dissected = 0;
    offset          = 0;

    dw = tvb_get_ntohl(tvb, offset);
    chksum_hdr_etype  = (guint8) ((dw & 0xFF000000) >> 24);
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
        chksum_hdr_tree = proto_tree_add_subtree(tree, tvb, offset + 0, 4,
                            ett_flip_chksum, NULL, "Checksum Header");

        /* ETYPE: 8 bits */
        proto_tree_add_uint_format_value(chksum_hdr_tree, hf_flip_chksum_etype,
                                         tvb, offset + 0, 1, dw,
                                         "%s", val_to_str_const(chksum_hdr_etype,
                                                                flip_etype,
                                                                "Unknown"));
        /* SPARE: 7 bits */
        proto_tree_add_item(chksum_hdr_tree, hf_flip_chksum_spare, tvb, offset, 4, ENC_BIG_ENDIAN);

        /* EXT HDR: 1 bit */
        proto_tree_add_item(chksum_hdr_tree, hf_flip_chksum_e,
                                         tvb, offset, 4, ENC_BIG_ENDIAN);
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

/* Protocol dissection */
static int
dissect_flip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *ti = NULL;
    proto_tree *flip_tree = NULL;
    proto_tree *basic_hdr_tree = NULL;
    tvbuff_t   *flip_tvb;

    guint32 dw1;

    /* Basic header fields. */
    guint8   basic_hdr_ext;
    guint32  basic_hdr_flow_id;
    guint16  basic_hdr_len;

    gboolean ext_hdr = FALSE;

    gint bytes_dissected = 0;
    gint payload_len;
    gint frame_len;
    gint flip_len;
    gint offset = 0;

    /* Error handling for basic header. */
    gboolean is_faulty_frame = FALSE;

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
    frame_len = tvb_captured_length(tvb);
    if (frame_len < FLIP_BASIC_HDR_LEN) {
        return 0;
    }

    bytes_dissected += FLIP_BASIC_HDR_LEN;

    /* Process the first 32 bits of the basic header. */
    dw1 = tvb_get_ntohl(tvb, offset + 0);
    basic_hdr_ext      = ((dw1 & 0x80000000) >> 31);
    basic_hdr_flow_id  = (dw1 & 0x0FFFFFFF);

    /* Process the second 32 bits of the basic header. */
    basic_hdr_len    = (guint16) (tvb_get_ntohl(tvb, offset + 4) & 0x0000FFFF);


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

    flip_tvb = tvb_new_subset_length(tvb, 0, frame_len);

    /* We are asked for details. */
    if (tree) {
        ti = proto_tree_add_protocol_format(
                tree, proto_flip, flip_tvb, 0, flip_len,
                "NSN FLIP, FlowID %s",
                val_to_str(basic_hdr_flow_id, NULL, "0x%08x"));
        flip_tree = proto_item_add_subtree(ti, ett_flip);

        /* basic header */
        basic_hdr_tree = proto_tree_add_subtree(flip_tree, flip_tvb, offset, 8, ett_flip_basic, NULL, "Basic Header");

        /* Extension header follows? 1 bit. */
        proto_tree_add_item(basic_hdr_tree, hf_flip_basic_e, flip_tvb, offset, 4, ENC_BIG_ENDIAN);

        /* Reserved: 3 bits. */
        proto_tree_add_item(basic_hdr_tree, hf_flip_basic_reserved, flip_tvb, offset, 4, ENC_BIG_ENDIAN);

        /* Flow ID: 28 bits. */
        proto_tree_add_item(basic_hdr_tree, hf_flip_basic_flowid, flip_tvb, offset, 4, ENC_BIG_ENDIAN);

        /* Sequence number: 16 bits. */
        proto_tree_add_item(basic_hdr_tree, hf_flip_basic_seqnum, flip_tvb, offset + 4, 2, ENC_BIG_ENDIAN);

        /* Packet length: 16 bits. */
        proto_tree_add_item(basic_hdr_tree, hf_flip_basic_len, flip_tvb, offset + 6, 2, ENC_BIG_ENDIAN);
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
    payload_len  = basic_hdr_len - FLIP_BASIC_HDR_LEN;

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

                SET_CKSUM_VEC_TVB(vec[0], flip_tvb, 0, bytes_dissected + 2);
                SET_CKSUM_VEC_TVB(vec[1], flip_tvb, bytes_dissected + 4,
                                  flip_len - (bytes_dissected + 4));
                computed_chksum = in_cksum(&vec[0], 2);

                /* Checksums handled in network order. */
                computed_chksum = g_htons(computed_chksum);
            }

            chksum_tvb = tvb_new_subset_length(flip_tvb, offset,
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

        tvbuff_t           *payload_tvb;
        gint               data_len;

        payload_tvb = tvb_new_subset_length(flip_tvb, offset, payload_len);

        /* Functionality for choosing subdissector is controlled through Decode As as FLIP doesn't
           have a unique identifier to determine subdissector */
        data_len = dissector_try_uint(subdissector_table, 0, payload_tvb, pinfo, tree);
        if (data_len <= 0)
        {
            data_len = call_data_dissector(payload_tvb, pinfo, tree);
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
         {"Extension Header Follows", "flip.basic.e", FT_BOOLEAN, 32,
          TFS(&tfs_yes_no), 0x80000000, NULL, HFILL}
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
         {"Seqnum", "flip.basic.seqnum", FT_UINT16, BASE_DEC_HEX,
          NULL, 0x0, "Basic Header Sequence Number", HFILL}
        },
        {&hf_flip_basic_len,
         {"Len", "flip.basic.len", FT_UINT16, BASE_DEC_HEX,
          NULL, 0x0, "Basic Header Packet Length", HFILL}
        },
        /*
         * Checksum header.
         */
        {&hf_flip_chksum_etype,
         {"Extension Type", "flip.chksum.etype", FT_UINT32, BASE_DEC,
          VALS(flip_etype), 0xFF000000, "Checksum Header Extension Type", HFILL}
        },
        {&hf_flip_chksum_spare,
         {"Spare", "flip.chksum.spare", FT_UINT32, BASE_DEC_HEX,
          NULL, 0x00FE0000, "Checksum Header Spare", HFILL}
        },
        {&hf_flip_chksum_e,
         {"Extension Header Follows", "flip.chksum.e", FT_BOOLEAN, 32,
          TFS(&tfs_yes_no), 0x00010000, NULL, HFILL}
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

    /* Decode As handling */
    static build_valid_func flip_da_build_value[1] = {flip_value};
    static decode_as_value_t flip_da_values = {flip_prompt, 1, flip_da_build_value};
    static decode_as_t flip_da = {"flip", "FLIP Payload", "flip.payload", 1, 0, &flip_da_values, NULL, NULL,
                                    decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

    proto_flip = proto_register_protocol(
        "NSN FLIP", /* name */
        "FLIP",     /* short name */
        "flip"      /* abbrev */
        );

    proto_register_field_array(proto_flip, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    subdissector_table = register_dissector_table("flip.payload", "FLIP subdissector", proto_flip, FT_UINT32, BASE_HEX);

    flip_module = prefs_register_protocol(proto_flip, NULL);

    /* Register preferences - now obsolete because of Decode As*/
    prefs_register_obsolete_preference(flip_module, "decoding_mode");
    prefs_register_obsolete_preference(flip_module, "heur_enabled_protocols");
    prefs_register_obsolete_preference(flip_module, "heur_decode_rtp");
    prefs_register_obsolete_preference(flip_module, "heur_decode_rtcp");
    prefs_register_obsolete_preference(flip_module, "forced_protocol");
    prefs_register_obsolete_preference(flip_module, "forced_decode");

    register_decode_as(&flip_da);

} /* proto_register_flip() */

/* Protocol handoff */
void
proto_reg_handoff_flip(void)
{
    dissector_handle_t flip_handle;

    flip_handle = create_dissector_handle(dissect_flip, proto_flip);
    dissector_add_uint("ethertype", ETHERTYPE_FLIP, flip_handle);
} /* proto_reg_handoff_flip() */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
