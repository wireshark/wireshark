/* packet-mpls.c
 * Routines for MPLS data packet disassembly
 * RFC 3032
 *
 * (c) Copyright Ashok Narayanan <ashokn@cisco.com>
 *
 * (c) Copyright 2006, _FF_ Francesco Fondelli <francesco.fondelli@gmail.com>  
 *                     added MPLS OAM support, ITU-T Y.1711
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
 * NOTES
 *
 * This module defines routines to handle Ethernet-encapsulated MPLS IP packets.
 * It should implement all the functionality in <draft-ietf-mpls-label-encaps-07.txt>
 * Multicast MPLS support is not tested yet
 */

/* FF NOTES
 *
 * The OAM patch should dissect OAM pdus as described in ITU-T Y.1711
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/ppptypes.h>
#include <epan/etypes.h>
#include <epan/prefs.h>
#include "packet-ppp.h"
#include "packet-mpls.h"

static gint proto_mpls = -1;

static gint ett_mpls = -1;
static gint ett_mpls_control = -1;
static gint ett_mpls_oam = -1;

const value_string special_labels[] = {
    {LABEL_IP4_EXPLICIT_NULL,	"IPv4 Explicit-Null"},
    {LABEL_ROUTER_ALERT,	"Router Alert"},
    {LABEL_IP6_EXPLICIT_NULL,	"IPv6 Explicit-Null"},
    {LABEL_IMPLICIT_NULL,	"Implicit-Null"},
    {LABEL_OAM_ALERT,		"OAM Alert"},
    {0, NULL }
};

/* MPLS filter values */
enum mpls_filter_keys {

    /* Is the packet MPLS-encapsulated? */
/*    MPLSF_PACKET,*/

    /* MPLS encap properties */
    MPLSF_LABEL,
    MPLSF_EXP,
    MPLSF_BOTTOM_OF_STACK,
    MPLSF_TTL,

    MPLSF_MAX
};

static int mpls_filter[MPLSF_MAX];
static int hf_mpls_control_control = -1;
static int hf_mpls_control_res = -1;

static int hf_mpls_oam_function_type = -1;
static int hf_mpls_oam_ttsi = -1;
static int hf_mpls_oam_frequency = -1;
static int hf_mpls_oam_defect_type = -1;
static int hf_mpls_oam_defect_location = -1;
static int hf_mpls_oam_bip16 = -1;

static const value_string oam_function_type_vals[] = {
    {0x00,	"Reserved"},
    {0x01,	"CV (Connectivity Verification)"},
    {0x02,	"FDI (Forward Defect Indicator)"},
    {0x03,	"BDI (Backward Defect Indicator)"},
    {0x04,	"Reserved for Performance packets"},
    {0x05,	"Reserved for LB-Req (Loopback Request)"},
    {0x06,	"Reserved for LB-Rsp (Loopback Response)"},
    {0x07,	"FDD (Fast Failure Detection)"},
    {0, NULL }
};

static const value_string oam_frequency_vals[] = {
    {0x00,	"Reserved"},
    {0x01,	"10 ms"},
    {0x02,	"20 ms"},
    {0x03,	"50 ms (default value)"},
    {0x04,	"100 ms"},
    {0x05,	"200 ms"},
    {0x06,	"500 ms"},
    /* 7-255 Reserved */
    {0, NULL }
};

static const value_string oam_defect_type_vals[] = {
    {0x0000,	"Reserved"},
    {0x0101,	"dServer"},
    {0x0102,	"dPeerME"},
    {0x0201,	"dLOCV"},
    {0x0202,	"dTTSI_Mismatch"},
    {0x0203,	"dTTSI_Mismerge"},
    {0x0204,	"dExcess"},
    {0x02FF,	"dUnknown"},
    {0xFFFF,	"Reserved"},
    {0, NULL }
};

static hf_register_info mplsf_info[] = {

/*    {&mpls_filter[MPLSF_PACKET],
     {"MPLS Label Switched Packet", "mpls", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},*/

    {&mpls_filter[MPLSF_LABEL],
     {"MPLS Label", "mpls.label", FT_UINT32, BASE_DEC, VALS(special_labels), 0x0,
      "", HFILL }},

    {&mpls_filter[MPLSF_EXP],
     {"MPLS Experimental Bits", "mpls.exp", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},

    {&mpls_filter[MPLSF_BOTTOM_OF_STACK],
     {"MPLS Bottom Of Label Stack", "mpls.bottom", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},

    {&mpls_filter[MPLSF_TTL],
     {"MPLS TTL", "mpls.ttl", FT_UINT8, BASE_DEC, NULL, 0x0,
      "", HFILL }},

    {&hf_mpls_control_control,
     {"MPLS Control Channel", "mpls.cw.control", FT_UINT8, BASE_DEC, NULL, 0xF0,
      "First nibble", HFILL }},

    {&hf_mpls_control_res,
     {"Reserved", "mpls.cw.res", FT_UINT16, BASE_HEX, NULL, 0xFFF, 
      "Reserved", HFILL }},

    /* OAM header fields */
    {&hf_mpls_oam_function_type,
     {"Function Type", "mpls.oam.function_type", FT_UINT8, 
      BASE_HEX, VALS(oam_function_type_vals), 0x0, "Function Type codepoint", HFILL }},

    {&hf_mpls_oam_ttsi,
     {"Trail Termination Source Identifier", "mpls.oam.ttsi", FT_UINT32, 
      BASE_HEX, NULL, 0x0, "Trail Termination Source Identifier", HFILL }},

    {&hf_mpls_oam_frequency,
     {"Frequency", "mpls.oam.frequency", FT_UINT8, 
      BASE_HEX, VALS(oam_frequency_vals), 0x0, "Frequency of probe injection", HFILL }},

    {&hf_mpls_oam_defect_type,
     {"Defect Type", "mpls.oam.defect_type", FT_UINT16, 
      BASE_HEX, VALS(oam_defect_type_vals), 0x0, "Defect Type", HFILL }},

    {&hf_mpls_oam_defect_location,
     {"Defect Location (AS)", "mpls.oam.defect_location", FT_UINT32, 
      BASE_DEC, NULL, 0x0, "Defect Location", HFILL }},

    {&hf_mpls_oam_bip16,
     {"BIP16", "mpls.oam.bip16", FT_UINT16, 
      BASE_HEX, NULL, 0x0, "BIP16", HFILL }},
};

static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t data_handle;
static dissector_table_t ppp_subdissector_table;

/*
 * Given a 4-byte MPLS label starting at offset "offset", in tvbuff "tvb",
 * decode it.
 * Return the label in "label", EXP bits in "exp",
 * bottom_of_stack in "bos", and TTL in "ttl"
 */
void decode_mpls_label(tvbuff_t *tvb, int offset,
		       guint32 *label, guint8 *exp,
		       guint8 *bos, guint8 *ttl)
{
    guint8 octet0 = tvb_get_guint8(tvb, offset+0);
    guint8 octet1 = tvb_get_guint8(tvb, offset+1);
    guint8 octet2 = tvb_get_guint8(tvb, offset+2);

    *label = (octet0 << 12) + (octet1 << 4) + ((octet2 >> 4) & 0xff);
    *exp = (octet2 >> 1) & 0x7;
    *bos = (octet2 & 0x1);
    *ttl = tvb_get_guint8(tvb, offset+3);
}

static void
dissect_mpls_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree  *mpls_control_tree = NULL;
    proto_item  *ti;
    tvbuff_t    *next_tvb;
    guint8      ctrl;
    guint16     res, ppp_proto;

    if (tvb_reported_length_remaining(tvb, 0) < 4){
        if(tree)
            proto_tree_add_text(tree, tvb, 0, -1, "Error processing Message");
        return;
    }
    ctrl = (tvb_get_guint8(tvb, 0) & 0xF0) >> 4;
    res = tvb_get_ntohs(tvb, 0) & 0x0FFF;
    ppp_proto = tvb_get_ntohs(tvb, 2);
    if (tree) {
        ti = proto_tree_add_text(tree, tvb, 0, 4, "MPLS PW Control Channel Header");
        mpls_control_tree = proto_item_add_subtree(ti, ett_mpls_control);
        if(mpls_control_tree == NULL) return;

        proto_tree_add_uint_format(mpls_control_tree, hf_mpls_control_control, tvb, 0, 1,
            ctrl, "Control Channel: 0x%1x", ctrl);
        proto_tree_add_uint_format(mpls_control_tree, hf_mpls_control_res, tvb, 0, 2,
            res, "Reserved: 0x%03x", res);
        proto_tree_add_text(mpls_control_tree, tvb, 2, 2,
            "PPP DLL Protocol Number: %s (0x%04X)", 
                val_to_str(ppp_proto, ppp_vals, "Unknown"), ppp_proto);
    }
    next_tvb = tvb_new_subset(tvb, 4, -1, -1);
    if (!dissector_try_port(ppp_subdissector_table, ppp_proto, 
        next_tvb, pinfo, tree)) {
            call_dissector(data_handle, next_tvb, pinfo, tree);
    }


}

static void
dissect_mpls_oam_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *mpls_tree, 
		     int offset, guint8 exp, guint8 bos, guint8 ttl)
{
    proto_tree  *mpls_oam_tree = NULL;
    proto_item  *ti = NULL;
    int functype = -1;
    const guint8 allone[] = { 0xff, 0xff };
    const guint8 allzero[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 
			       0x00, 0x00, 0x00, 0x00, 0x00,
			       0x00, 0x00, 0x00, 0x00, 0x00, 
			       0x00, 0x00, 0x00, 0x00, 0x00 };
    
    /* if called with main tree == null just set col info with func type string and return */
    if (!tree) {
	if (check_col(pinfo->cinfo, COL_INFO)) {
	    if (tvb_bytes_exist(tvb, offset, 1)) {
		functype = tvb_get_guint8(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, " (OAM: %s)", 
				(functype == 0x01) ? "CV"  :
				(functype == 0x02) ? "FDI" :
				(functype == 0x03) ? "BDI" :
				(functype == 0x07) ? "FDD" : "reserved/unknown");
	    }
	}
	return;
    }
    
    /* sanity checks */
    if (!mpls_tree)
	return;

    if (!tvb_bytes_exist(tvb, offset, 44)) {
	/* ITU-T Y.1711, 5.3: OAM pdus must have a minimum payload length of 44 bytes */
	proto_tree_add_text(mpls_tree, tvb, offset, -1, "Error: must have a minimum payload length of 44 bytes");
	return;
    }
    
    ti = proto_tree_add_text(mpls_tree, tvb, offset, 44, "MPLS Operation & Maintenance");
    mpls_oam_tree = proto_item_add_subtree(ti, ett_mpls_oam);
    
    if (!mpls_oam_tree) 
	return;
    
    /* checks for exp, bos and ttl encoding */
    
    if (exp!=0)
	proto_tree_add_text(mpls_oam_tree, tvb, offset - 2, 1, "Warning: Exp bits should be 0 for OAM");

    if (bos!=1)
	proto_tree_add_text(mpls_oam_tree, tvb, offset - 2, 1, "Warning: S bit should be 1 for OAM");
    
    if (ttl!=1)
	proto_tree_add_text(mpls_oam_tree, tvb, offset - 1, 1, "Warning: TTL should be 1 for OAM");

    /* starting dissection */
    
    functype = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_function_type, tvb, offset, 1, TRUE);
    offset++;
    
    switch(functype) {
    case 0x01: /* CV */
	{
	    guint32 lsrid_ipv4addr;
	    
	    /* 3 octets reserved (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 3) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 3, 
				    "Error: these bytes are reserved and must be 0x00");
	    }
	    offset+=3;
	    
	    /* ttsi (ipv4 flavor as in RFC 2373) */
	    if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 10, 
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=10;
		
	    if (tvb_memeql(tvb, offset, allone, 2) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 2, 
				    "Error: these bytes are padding and must be 0xFF");
	    }
	    offset+=2;
	    
	    lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
	    proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSR ID: %s", ip_to_str((guint8 *)&lsrid_ipv4addr));
	    offset+=4;

	    proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSP ID: %d", tvb_get_ntohl(tvb, offset));
	    offset+=4;
	    
	    /* 18 octets of padding (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 18) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 18, 
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=18;
	}
	break;

    case 0x02: /* FDI */
    case 0x03: /* BDI */
	{
	    guint32 lsrid_ipv4addr;
	    
	    /* 1 octets reserved (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 1) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 3, 
				    "Error: this byte is reserved and must be 0x00");
	    }
	    offset++;

	    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_defect_type, tvb, offset, 2, TRUE);
	    offset+=2;

	    /* ttsi (ipv4 flavor as in RFC 2373) is optional if not used must be set to all 0x00 */
	    if (tvb_memeql(tvb, offset, allzero, 20) == 0) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 20, "TTSI not preset (optional for FDI/BDI)");
		offset+=20;
	    } else {
		if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
		    proto_tree_add_text(mpls_oam_tree, tvb, offset, 10, 
					"Error: these bytes are padding and must be 0x00");
		}
		offset+=10;
		
		if (tvb_memeql(tvb, offset, allone, 2) == -1) {
		    proto_tree_add_text(mpls_oam_tree, tvb, offset, 2, 
					"Error: these bytes are padding and must be 0xFF");
		}
		offset+=2;
		
		lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSR ID: %s", ip_to_str((guint8 *)&lsrid_ipv4addr));
		offset+=4;
		
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSP ID: %d", tvb_get_ntohl(tvb, offset));
		offset+=4;
	    }
	    
	    /* defect location */
	    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_defect_location, tvb, offset, 4, TRUE);
	    offset+=4;

	    /* 14 octets of padding (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 14) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 14, 
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=14;
	}
	break;
	
    case 0x07: /* FDD */ 
	{
	    guint32 lsrid_ipv4addr;
	    
	    /* 3 octets reserved (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 3) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 3, 
				    "Error: these bytes are reserved and must be 0x00");
	    }
	    offset+=3;
	    
	    /* ttsi (ipv4 flavor as in RFC 2373) */
	    if (tvb_memeql(tvb, offset, allzero, 10) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 10, 
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=10;
		
	    if (tvb_memeql(tvb, offset, allone, 2) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 2, 
				    "Error: these bytes are padding and must be 0xFF");
	    }
	    offset+=2;
	    
	    lsrid_ipv4addr = tvb_get_ipv4(tvb, offset);
	    proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSR ID: %s", ip_to_str((guint8 *)&lsrid_ipv4addr));
	    offset+=4;

	    proto_tree_add_text(mpls_oam_tree, tvb, offset, 4, "LSP ID: %d", tvb_get_ntohl(tvb, offset));
	    offset+=4;
	    
	    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_frequency, tvb, offset, 1, TRUE);
	    offset++;

	    /* 17 octets of padding (all 0x00) */
	    if (tvb_memeql(tvb, offset, allzero, 17) == -1) {
		proto_tree_add_text(mpls_oam_tree, tvb, offset, 17,
				    "Error: these bytes are padding and must be 0x00");
	    }
	    offset+=17;
	}
	break;

    default:
	proto_tree_add_text(mpls_oam_tree, tvb, offset - 1, -1, "Unknown MPLS OAM pdu");
	return;
    }
    
    /* BIP16 */
    proto_tree_add_item(mpls_oam_tree, hf_mpls_oam_bip16, tvb, offset, 2, TRUE);
    offset+=2;
}
    

static void
dissect_mpls(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    int offset = 0;
    guint32 label;
    guint8 exp;
    guint8 bos;
    guint8 ttl;
    guint8 ipvers;

    proto_tree  *mpls_tree = NULL;
    proto_item  *ti;
    tvbuff_t *next_tvb;

    if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
	col_set_str(pinfo->cinfo,COL_PROTOCOL, "MPLS");
    }

    if (check_col(pinfo->cinfo,COL_INFO)) {
	col_add_fstr(pinfo->cinfo,COL_INFO,"MPLS Label Switched Packet");
    }

    /* Start Decoding Here. */
    while (tvb_reported_length_remaining(tvb, offset) > 0) {
	
	decode_mpls_label(tvb, offset, &label, &exp, &bos, &ttl);
		
	if (tree) {

	    ti = proto_tree_add_item(tree, proto_mpls, tvb, offset, 4, FALSE);
	    mpls_tree = proto_item_add_subtree(ti, ett_mpls);

	    proto_item_append_text(ti, ", Label: %u", label);
	    if (label <= LABEL_MAX_RESERVED){
		proto_tree_add_uint_format(mpls_tree, mpls_filter[MPLSF_LABEL], tvb,
				    offset, 3, label, "MPLS Label: %u (%s)",
				    label, val_to_str(label, special_labels,
						      "Reserved - Unknown"));
		proto_item_append_text(ti, " (%s)", val_to_str(label, special_labels,
					"Reserved - Unknown"));
	    } else {
		proto_tree_add_uint_format(mpls_tree, mpls_filter[MPLSF_LABEL], tvb,
				    offset, 3, label, "MPLS Label: %u", label);
	    }

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_EXP], tvb,
				offset+2,1, exp);
	    proto_item_append_text(ti, ", Exp: %u", exp);

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_BOTTOM_OF_STACK], tvb,
				offset+2,1, bos);
	    proto_item_append_text(ti, ", S: %u", bos);

	    proto_tree_add_uint(mpls_tree,mpls_filter[MPLSF_TTL], tvb,
				offset+3,1, ttl);
	    proto_item_append_text(ti, ", TTL: %u", ttl);	    
	}

	if (label == LABEL_OAM_ALERT) {
	    /* OAM pdus are injected in normal data plane flow in order to test a LSP, 
	     * they carry no user data.
	     */
	    dissect_mpls_oam_pdu(tvb, pinfo, tree, mpls_tree, offset + 4, exp, bos, ttl);
	    return;
	}

	offset += 4;
	if (bos) break;
    }
    next_tvb = tvb_new_subset(tvb, offset, -1, -1);

    ipvers = (tvb_get_guint8(tvb, offset) >> 4) & 0x0F;
    if (ipvers == 6) {
      call_dissector(ipv6_handle, next_tvb, pinfo, tree);
    } else if (ipvers == 4) {
      call_dissector(ipv4_handle, next_tvb, pinfo, tree);
    } else if (ipvers == 1) {
      dissect_mpls_control(next_tvb, pinfo, tree);
    } else {
      call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, tree);
    }
}

void
proto_register_mpls(void)
{
	static gint *ett[] = {
		&ett_mpls,
                &ett_mpls_control,
		&ett_mpls_oam,
	};

	proto_mpls = proto_register_protocol("MultiProtocol Label Switching Header",
	    "MPLS", "mpls");
	proto_register_field_array(proto_mpls, mplsf_info, array_length(mplsf_info));
	proto_register_subtree_array(ett, array_length(ett));
	register_dissector("mpls", dissect_mpls, proto_mpls);
}

void
proto_reg_handoff_mpls(void)
{
	dissector_handle_t mpls_handle;

	/*
	 * Get a handle for the IPv4 and IPv6 dissectors and PPP protocol dissector table.
	 */
	ipv4_handle = find_dissector("ip");
	ipv6_handle = find_dissector("ipv6");
	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
        data_handle = find_dissector("data");
        ppp_subdissector_table = find_dissector_table("ppp.protocol");


	mpls_handle = create_dissector_handle(dissect_mpls, proto_mpls);
	dissector_add("ethertype", ETHERTYPE_MPLS, mpls_handle);
	dissector_add("ethertype", ETHERTYPE_MPLS_MULTI, mpls_handle);
	dissector_add("ppp.protocol", PPP_MPLS_UNI, mpls_handle);
	dissector_add("ppp.protocol", PPP_MPLS_MULTI, mpls_handle);
	dissector_add("chdlctype", ETHERTYPE_MPLS, mpls_handle);
	dissector_add("chdlctype", ETHERTYPE_MPLS_MULTI, mpls_handle);
	dissector_add("gre.proto", ETHERTYPE_MPLS, mpls_handle);
	dissector_add("gre.proto", ETHERTYPE_MPLS_MULTI, mpls_handle);
}
