/* packet-srp.c
 * Routines for H.324/SRP dissection
 * 2004 Richard van der Hoff <richardv@mxtelecom.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/bitswap.h>
#include <epan/circuit.h>
#include <epan/stream.h>
#include <epan/crc16-tvb.h>

/* Wireshark ID of the protocols */
static int proto_srp = -1;
static int proto_ccsrl = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
 * our header fields; they are filled out when we call
 * proto_register_field_array() in proto_register_srp()
 */
static int hf_srp_header = -1;
static int hf_srp_seqno = -1;
static int hf_srp_crc = -1;
static int hf_srp_crc_bad = -1;
static int hf_ccsrl_ls = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_srp = -1;
static gint ett_ccsrl = -1;

static dissector_handle_t ccsrl_handle;
static dissector_handle_t h245dg_handle;

/*****************************************************************************/
#define SRP_SRP_COMMAND 249
#define SRP_SRP_RESPONSE 251
#define SRP_NSRP_RESPONSE 247

static const value_string srp_frame_types[] = {
  {SRP_SRP_COMMAND, "SRP command"},
  {SRP_SRP_RESPONSE, "SRP response"},
  {SRP_NSRP_RESPONSE, "NSRP response"},
  {0,NULL}
};

static const value_string ccsrl_ls_vals[] = {
  {0xFF, "Yes"},
  {0x00, "No"},
  {0,NULL}
};

/*****************************************************************************/

static void dissect_ccsrl(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_item *ccsrl_item;
    proto_tree *ccsrl_tree=NULL;
    guint8 lastseg = tvb_get_guint8(tvb,0);
    tvbuff_t *next_tvb;

    /* add the 'ccsrl' tree to the main tree */
    if (tree) {
	ccsrl_item = proto_tree_add_item (tree, proto_ccsrl, tvb, 0, -1, ENC_NA);
	ccsrl_tree = proto_item_add_subtree (ccsrl_item, ett_ccsrl);
	proto_tree_add_uint(ccsrl_tree,hf_ccsrl_ls,tvb,0,1,lastseg);
    }

    /* XXX add support for reassembly of fragments */

    /* XXX currently, we always dissect as H245. It's not necessarily
        that though.
    */
    next_tvb = tvb_new_subset_remaining(tvb, 1);
    call_dissector( h245dg_handle, next_tvb, pinfo, ccsrl_tree );
}

static void dissect_srp_command(tvbuff_t * tvb, packet_info * pinfo, proto_tree * srp_tree)
{
    tvbuff_t *next_tvb;
    guint payload_len;

    if( srp_tree )
	proto_tree_add_item(srp_tree,hf_srp_seqno,tvb,1,1,ENC_BIG_ENDIAN);

    payload_len = tvb_reported_length_remaining(tvb,4);
    next_tvb = tvb_new_subset(tvb, 2, payload_len, payload_len );

    /* XXX currently, we always dissect as CCSRL. It's only that in
     * H324/Annex C though.
     */
    call_dissector(ccsrl_handle, next_tvb, pinfo, srp_tree );
}

static void dissect_srp (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_item *srp_item = NULL;
    proto_tree *srp_tree = NULL;
    proto_item *hidden_item;

    guint8 header = tvb_get_guint8(tvb,0);

    /* add the 'srp' tree to the main tree */
    if (tree) {
	srp_item = proto_tree_add_item (tree, proto_srp, tvb, 0, -1, ENC_NA);
	srp_tree = proto_item_add_subtree (srp_item, ett_srp);
	proto_tree_add_uint(srp_tree,hf_srp_header,tvb,0,1,header);
    }

    switch( header ) {
	case SRP_SRP_COMMAND:
	    dissect_srp_command(tvb,pinfo,srp_tree);
	    break;

	case SRP_SRP_RESPONSE:
	    break;

	case SRP_NSRP_RESPONSE:
	    if( srp_tree )
		proto_tree_add_item(srp_tree,hf_srp_seqno,tvb,1,1,ENC_BIG_ENDIAN);
	    break;

	default:
	    break;
    }

    if( srp_tree ) {
	guint16 crc, calc_crc;
	guint crc_offset = tvb_reported_length(tvb)-2;
	crc = tvb_get_letohs(tvb,-2);

	/* crc includes the header */
	calc_crc = crc16_ccitt_tvb(tvb,crc_offset);

	if( crc == calc_crc ) {
	    proto_tree_add_uint_format(srp_tree, hf_srp_crc, tvb,
				       crc_offset, 2, crc,
				       "CRC: 0x%04x (correct)", crc);
	} else {
	    hidden_item = proto_tree_add_boolean(srp_tree, hf_srp_crc_bad, tvb,
					  crc_offset, 2, TRUE);
	    PROTO_ITEM_SET_HIDDEN(hidden_item);
	    proto_tree_add_uint_format(srp_tree, hf_srp_crc, tvb,
				       crc_offset, 2, crc,
				       "CRC: 0x%04x (incorrect, should be 0x%04x)",
				       crc,
				       calc_crc);
	}
    }

}

void proto_register_ccsrl (void)
{
    static hf_register_info hf[] = {
	{ &hf_ccsrl_ls,
	  { "Last Segment","ccsrl.ls",FT_UINT8, BASE_HEX, ccsrl_ls_vals, 0x0,
	    "Last segment indicator", HFILL}},
    };

    static gint *ett[] = {
	&ett_ccsrl,
    };

    proto_ccsrl = proto_register_protocol ("H.324/CCSRL", "CCSRL", "ccsrl");
    proto_register_field_array (proto_ccsrl, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_dissector("ccsrl", dissect_ccsrl, proto_ccsrl);
}

void proto_register_srp (void)
{
    static hf_register_info hf[] = {
	{&hf_srp_header,
	 { "Header", "srp.header", FT_UINT8, BASE_DEC, srp_frame_types, 0x0,
	   "SRP header octet", HFILL }},
	{&hf_srp_seqno,
	 { "Sequence Number", "srp.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
	   NULL, HFILL }},
	{&hf_srp_crc,
	 { "CRC", "srp.crc", FT_UINT16, BASE_HEX, NULL, 0x0,
	   NULL, HFILL }},
	{ &hf_srp_crc_bad,
	  { "Bad CRC","srp.crc_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    NULL, HFILL }},
    };

    static gint *ett[] = {
	&ett_srp,
    };

    proto_srp = proto_register_protocol ("H.324/SRP", "SRP", "srp");
    proto_register_field_array (proto_srp, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_dissector("srp", dissect_srp, proto_srp);

    /* register our init routine to be called at the start of a capture,
       to clear out our hash tables etc */
    /* register_init_routine(&srp_init_protocol); */

}


void proto_reg_handoff_srp(void) {
    ccsrl_handle = find_dissector("ccsrl");
    h245dg_handle = find_dissector("h245dg");
}
