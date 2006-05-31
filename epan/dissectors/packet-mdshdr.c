/* packet-mdshdr.c
 * Routines for dissection of Cisco MDS Switch Internal Header
 * Copyright 2001, Dinesh G Dutt <ddutt@andiamo.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from WHATEVER_FILE_YOU_USED (where "WHATEVER_FILE_YOU_USED"
 * is a dissector file; if you just copied this from README.developer,
 * don't bother with the "Copied from" - you don't even need to put
 * in a "Copied from" if you copied an existing dissector, especially
 * if the bulk of the code in the new dissector is your code)
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif

#include <glib.h>

#include <epan/value_string.h>
#include <etypes.h>
#include <epan/packet.h>
#include <epan/prefs.h>

#define MDSHDR_VERSION_OFFSET 		0

/* Mdshdr Control bits */
#define MDSHDR_CTL_IDXDIRECT             1
#define MDSHDR_CTL_IGNACLO               2
#define MDSHDR_CTL_DRP                   4

/* OFFSETS OF FIELDS */
#define MDSHDR_VER_OFFSET                0
#define MDSHDR_SOF_OFFSET                1
#define MDSHDR_PKTLEN_OFFSET             2
#define MDSHDR_DIDX_OFFSET               5
#define MDSHDR_SIDX_OFFSET               6
#define MDSHDR_VSAN_OFFSET               13

/* Two size definitions are sufficient */
#define MDSHDR_SIZE_BYTE                 sizeof (gchar)
#define MDSHDR_SIZE_INT16                sizeof (guint16)
#define MDSHDR_SIZE_INT32                sizeof (guint32)

/* Other miscellaneous defines; can't rely on sizeof structs */
#define MDSHDR_MAX_VERSION               0
#define MDSHDR_HEADER_SIZE               16
#define MDSHDR_TRAILER_SIZE              6

/* SOF Encodings */
#define MDSHDR_SOFc1                     0x1
#define MDSHDR_SOFi1                     0x2
#define MDSHDR_SOFn1                     0x3
#define MDSHDR_SOFi2                     0x4
#define MDSHDR_SOFn2                     0x5
#define MDSHDR_SOFi3                     0x6
#define MDSHDR_SOFn3                     0x7
#define MDSHDR_SOFf                      0x8
#define MDSHDR_SOFc4                     0x9
#define MDSHDR_SOFi4                     0xa
#define MDSHDR_SOFn4                     0xb

/* EOF Encodings */
#define MDSHDR_EOFt                      0x1
#define MDSHDR_EOFdt                     0x2
#define MDSHDR_EOFa                      0x4
#define MDSHDR_EOFn                      0x3
#define MDSHDR_EOFdti                    0x6
#define MDSHDR_EOFni                     0x7
#define MDSHDR_EOFrt                     0xa
#define MDSHDR_EOFrti                    0xe
#define MDSHDR_EOF_UNKNOWN               0xb

/* Initialize the protocol and registered fields */
static int proto_mdshdr = -1;
static int hf_mdshdr_sof = -1;
static int hf_mdshdr_pkt_len = -1;
static int hf_mdshdr_dstidx = -1;
static int hf_mdshdr_srcidx = -1;
static int hf_mdshdr_vsan = -1;
static int hf_mdshdr_eof = -1;
static int hf_mdshdr_span = -1;
static int hf_mdshdr_fccrc = -1;

/* Initialize the subtree pointers */
static gint ett_mdshdr = -1;
static gint ett_mdshdr_hdr = -1;
static gint ett_mdshdr_trlr = -1;

static dissector_handle_t data_handle, fc_dissector_handle;

static gboolean decode_if_zero_etype = TRUE;

static const value_string sof_vals[] = {
    {MDSHDR_SOFc1,               "SOFc1"},
    {MDSHDR_SOFi1,               "SOFi1"},
    {MDSHDR_SOFn1,               "SOFn1"},
    {MDSHDR_SOFi2,               "SOFi2"},
    {MDSHDR_SOFn2,               "SOFn2"},
    {MDSHDR_SOFi3,               "SOFi3"},
    {MDSHDR_SOFn3,               "SOFn3"},
    {MDSHDR_SOFc4,               "SOFc4"},
    {MDSHDR_SOFi4,               "SOFi4"},
    {MDSHDR_SOFn4,               "SOFn4"},
    {MDSHDR_SOFf,                "SOFf"},
    {0,                         NULL},
};

static const value_string eof_vals[] = {
    {MDSHDR_EOFt,                "EOFt"},
    {MDSHDR_EOFdt,               "EOFdt"},
    {MDSHDR_EOFa,                "EOFa"},
    {MDSHDR_EOFn,                "EOFn"},
    {MDSHDR_EOFdti,              "EOFdti"},
    {MDSHDR_EOFni,               "EOFni"},
    {MDSHDR_EOFrt,               "EOFrt"},
    {MDSHDR_EOFrti,              "EOFrti"},
    {MDSHDR_EOF_UNKNOWN,         ""},
    {0,                          NULL},
};

void proto_reg_handoff_mdshdr(void);

/* Code to actually dissect the packets */
static void
dissect_mdshdr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
    proto_item *ti_main, *ti_hdr, *ti_trlr;
    proto_tree *mdshdr_tree_main, *mdshdr_tree_hdr, *mdshdr_tree_trlr;
    int offset = 0,
        pktlen;
    tvbuff_t *next_tvb;
    guint8 sof, eof;
    guint16 vsan;
    guint8 span_id;
    int trailer_start = 0;

    /* Make entries in Protocol column and Info column on summary display */
    if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "MDS Header");
    
    if (check_col (pinfo->cinfo, COL_INFO))
        col_clear (pinfo->cinfo, COL_INFO);

    sof = tvb_get_guint8 (tvb, offset+MDSHDR_SOF_OFFSET) & 0x0F;
    pktlen = tvb_get_ntohs (tvb, offset+MDSHDR_PKTLEN_OFFSET) & 0x1FFF;
    vsan = tvb_get_ntohs (tvb, offset+MDSHDR_VSAN_OFFSET) & 0x0FFF;
    span_id = (tvb_get_ntohs (tvb, offset+MDSHDR_VSAN_OFFSET) & 0xF000) >> 12;
    
    /* The Mdshdr trailer is at the end of the frame */
    if (tvb_bytes_exist (tvb, 0, MDSHDR_HEADER_SIZE + pktlen)) {
        trailer_start = MDSHDR_HEADER_SIZE + pktlen - MDSHDR_TRAILER_SIZE; 
    
        eof = tvb_get_guint8 (tvb, trailer_start);
        tvb_set_reported_length (tvb, MDSHDR_HEADER_SIZE+pktlen);
    }
    else {
        eof = MDSHDR_EOF_UNKNOWN;
    }

    pinfo->src_idx = (tvb_get_ntohs (tvb, MDSHDR_SIDX_OFFSET) & 0x3FF);
    pinfo->dst_idx = (tvb_get_ntohs (tvb, MDSHDR_DIDX_OFFSET) & 0xFFC) >> 2;
    pinfo->vsan = vsan;
    pinfo->sof_eof = 0;

    if ((sof == MDSHDR_SOFi3) || (sof == MDSHDR_SOFi2) || (sof == MDSHDR_SOFi1)
        || (sof == MDSHDR_SOFi4)) {
        pinfo->sof_eof = PINFO_SOF_FIRST_FRAME;
    }
    else if (sof == MDSHDR_SOFf) {
        pinfo->sof_eof = PINFO_SOF_SOFF;      
    }

    if (eof != MDSHDR_EOFn) {
        pinfo->sof_eof |= PINFO_EOF_LAST_FRAME;
    }
    else if (eof != MDSHDR_EOFt) {
        pinfo->sof_eof |= PINFO_EOF_INVALID;
    }
    
    /* In the interest of speed, if "tree" is NULL, don't do any work not
       necessary to generate protocol tree items. */
    if (tree) {

        /* create display subtree for the protocol */
        ti_main = proto_tree_add_protocol_format (tree, proto_mdshdr, tvb, 0,
                                                  MDSHDR_HEADER_SIZE+pktlen,
                                                  "MDS Header(%s/%s)", 
						  val_to_str(sof, sof_vals, "Unknown(%u)"),
                                                  val_to_str(eof, eof_vals, "Unknown(%u)"));

        mdshdr_tree_main = proto_item_add_subtree (ti_main, ett_mdshdr);

        /* Add Header part as subtree first */
        ti_hdr = proto_tree_add_text (mdshdr_tree_main, tvb, MDSHDR_VER_OFFSET,
                                      MDSHDR_HEADER_SIZE, "MDS Header");

        mdshdr_tree_hdr = proto_item_add_subtree (ti_hdr, ett_mdshdr_hdr);
        proto_tree_add_item_hidden (mdshdr_tree_hdr, hf_mdshdr_sof, tvb, MDSHDR_SOF_OFFSET,
                                    MDSHDR_SIZE_BYTE, 0);
        proto_tree_add_item (mdshdr_tree_hdr, hf_mdshdr_pkt_len, tvb, MDSHDR_PKTLEN_OFFSET, 
                             MDSHDR_SIZE_INT16, 0);
        proto_tree_add_item (mdshdr_tree_hdr, hf_mdshdr_dstidx, tvb, MDSHDR_DIDX_OFFSET,
                             MDSHDR_SIZE_INT16, 0);
        proto_tree_add_item (mdshdr_tree_hdr, hf_mdshdr_srcidx, tvb, MDSHDR_SIDX_OFFSET,
                             MDSHDR_SIZE_INT16, 0);
        proto_tree_add_item (mdshdr_tree_hdr, hf_mdshdr_vsan, tvb, MDSHDR_VSAN_OFFSET,
                             MDSHDR_SIZE_INT16, 0);
        proto_tree_add_uint_hidden(mdshdr_tree_hdr, hf_mdshdr_span,
                                   tvb, MDSHDR_VSAN_OFFSET,
                                   MDSHDR_SIZE_BYTE, span_id);
        
        /* Add Mdshdr Trailer part */
        if (tvb_bytes_exist (tvb, 0, MDSHDR_HEADER_SIZE+pktlen)) {
            ti_trlr = proto_tree_add_text (mdshdr_tree_main, tvb, trailer_start,
                                           MDSHDR_TRAILER_SIZE,
                                           "MDS Trailer");
            mdshdr_tree_trlr = proto_item_add_subtree (ti_trlr, ett_mdshdr_trlr);
        
            proto_tree_add_item (mdshdr_tree_trlr, hf_mdshdr_eof, tvb,
                                 trailer_start, MDSHDR_SIZE_BYTE, 0);
            proto_tree_add_item (mdshdr_tree_trlr, hf_mdshdr_fccrc, tvb,
                                 trailer_start+2, MDSHDR_SIZE_INT32, 0);
        }
    }
    
    /* If this protocol has a sub-dissector call it here, see section 1.8 */
    if (tvb_bytes_exist (tvb, 0, MDSHDR_HEADER_SIZE+pktlen)) {
        next_tvb = tvb_new_subset (tvb, MDSHDR_HEADER_SIZE, pktlen, pktlen);
    }
    else {
        next_tvb = tvb_new_subset (tvb, MDSHDR_HEADER_SIZE, -1, -1);
    }

    /* Call the Fibre Channel dissector */
    if (fc_dissector_handle) {
        call_dissector (fc_dissector_handle, next_tvb, pinfo, tree);
    }
    else {
        call_dissector (data_handle, next_tvb, pinfo, tree);
    }
}


/* Register the protocol with Wireshark. This format is require because a script
 * is used to build the C function that calls all the protocol registration.
 */

void
proto_register_mdshdr(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_mdshdr_sof,
          {"SOF", "mdshdr.sof", FT_UINT8, BASE_DEC, VALS(sof_vals), 0x0, "", HFILL}},
        { &hf_mdshdr_pkt_len,
          {"Packet Len", "mdshdr.plen", FT_UINT16, BASE_DEC, NULL, 0x1FFF, "", HFILL}},
        { &hf_mdshdr_dstidx,
          {"Dst Index", "mdshdr.dstidx", FT_UINT16, BASE_HEX, NULL, 0xFFC, "", HFILL}},
        { &hf_mdshdr_srcidx,
          {"Src Index", "mdshdr.srcidx", FT_UINT16, BASE_HEX, NULL, 0x3FF, "", HFILL}},
        { &hf_mdshdr_vsan,
          {"VSAN", "mdshdr.vsan", FT_UINT16, BASE_DEC, NULL, 0x0FFF, "", HFILL}},
        { &hf_mdshdr_eof,
          {"EOF", "mdshdr.eof", FT_UINT8, BASE_DEC, VALS(eof_vals), 0x0, "", HFILL}},
        { &hf_mdshdr_span,
          {"SPAN Frame", "mdshdr.span", FT_UINT8, BASE_DEC, NULL, 0x0,
           "", HFILL}},
        { &hf_mdshdr_fccrc,
          {"CRC", "mdshdr.crc", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL}},
    };

/* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_mdshdr,
        &ett_mdshdr_hdr,
        &ett_mdshdr_trlr
    };
    module_t *mdshdr_module;

/* Register the protocol name and description */
    proto_mdshdr = proto_register_protocol("MDS Header", "MDS Header", "mdshdr");

/* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_mdshdr, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    mdshdr_module = prefs_register_protocol (proto_mdshdr, proto_reg_handoff_mdshdr);
    prefs_register_bool_preference (mdshdr_module, "decode_if_etype_zero",
                                    "Decode as MDS Header if Ethertype == 0",
                                    "A frame is considered for decoding as MDSHDR if either "
                                    "ethertype is 0xFCFC or zero. Turn this flag off if you "
                                    "you don't want ethertype zero to be decoded as MDSHDR. "
                                    "This might be useful to avoid problems with test frames.",
                                    &decode_if_zero_etype);
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_mdshdr(void)
{
    static dissector_handle_t mdshdr_handle;
    static gboolean registered_for_zero_etype = FALSE;
    static gboolean mdshdr_prefs_initialized = FALSE;

    if (!mdshdr_prefs_initialized) {
        /*
         * This is the first time this has been called (i.e.,
         * Wireshark/TShark is starting up), so create a handle for
         * the MDS Header dissector, register the dissector for
         * ethertype ETHERTYPE_FCFT, and fetch the data and Fibre
         * Channel handles.
         */
        mdshdr_handle = create_dissector_handle (dissect_mdshdr, proto_mdshdr);
        dissector_add ("ethertype", ETHERTYPE_FCFT, mdshdr_handle);
        data_handle = find_dissector ("data");
        fc_dissector_handle = find_dissector ("fc");
        mdshdr_prefs_initialized = TRUE;
    }

    /*
     * Only register the dissector for ethertype 0 if the preference
     * is set to do so.
     */
    if (decode_if_zero_etype) {
        /*
         * The preference to register for ethertype ETHERTYPE_UNK (0)
         * is set; if we're not registered for ethertype ETHERTYPE_UNK,
         * do so.
         */
        if (!registered_for_zero_etype) {
            dissector_add ("ethertype", ETHERTYPE_UNK, mdshdr_handle);
            registered_for_zero_etype = TRUE;
        }
    } else {
        /*
         * The preference to register for ethertype ETHERTYPE_UNK (0)
         * is not set; if we're registered for ethertype ETHERTYPE_UNK,
         * undo that registration.
         */
        if (registered_for_zero_etype) {
            dissector_delete ("ethertype", ETHERTYPE_UNK, mdshdr_handle);
            registered_for_zero_etype = FALSE;
        }
    }
}
