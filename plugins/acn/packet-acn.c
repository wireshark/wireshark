/* packet-acn.c
 * Routines for ACN packet disassembly
 *
 * $Id: packet-acn.c,v 1.1 2003/10/14 01:18:11 guy Exp $
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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

/* Include files */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "plugins/plugin_api.h"

#include "moduleinfo.h"
#include "acn.h"

#include <stdio.h>
#include <stdlib.h>
#include <gmodule.h>
#include <ctype.h>
#include <time.h>
#include <string.h>
#include <epan/packet.h>
#include <epan/resolv.h>
#include "prefs.h"
#include <epan/strutil.h>

#include "plugins/plugin_api_defs.h"

/* Define version if we are not building ethereal statically */

#ifndef ENABLE_STATIC
G_MODULE_EXPORT const gchar version[] = VERSION;
#endif

/*
 * See
 *
 *	http://www.esta.org/tsp/E1-17inst.htm
 */

static const value_string acn_proto_vals[] = {
	{ ACN_PDU_PROTO_UNKNOWN,	"ACN Unknown Protocol"},
	{ ACN_PDU_PROTO_SDT,		"ACN SDT Protocol" },
	{ ACN_PDU_PROTO_DMP,		"ACN DMP Protocol" },
	{ 0,				NULL }
};

static const value_string acn_sdt_type_vals[] = {
	{ ACN_SDT_TYPE_UNKNOWN,		"ACN SDT Unknown Type"},
	{ ACN_SDT_TYPE_RELSEQDATA,	"ACN SDT RELSEQDATA"},
	{ ACN_SDT_TYPE_UNRELSEQDATA,	"ACN SDT UNRELSEQDATA"},
	{ ACN_SDT_TYPE_UNSEQDATA,	"ACN SDT UNSEQDATA"},
	{ ACN_SDT_TYPE_JOIN,		"ACN SDT JOIN"},
	{ ACN_SDT_TYPE_TRANSFER,	"ACN SDT TRANSFER"},
	{ ACN_SDT_TYPE_JOINREF,		"ACN SDT JOINREF"},
	{ ACN_SDT_TYPE_JOINACC,		"ACN SDT JOINACC"},
	{ ACN_SDT_TYPE_LEAVEREQ,	"ACN SDT LEAVEREQ"},
	{ ACN_SDT_TYPE_LEAVE,		"ACN SDT LEAVE"},
	{ ACN_SDT_TYPE_LEAVING,		"ACN SDT LEAVING"},
	{ ACN_SDT_TYPE_NAKUPON,		"ACN SDT NAKUPON"},
	{ ACN_SDT_TYPE_NAKUPOFF,	"ACN SDT NAKUPOFF"},
	{ ACN_SDT_TYPE_NAKDOWNON,	"ACN SDT NAKDOWNON"},
	{ ACN_SDT_TYPE_NAKDOWNOFF,	"ACN SDT NAKDOWNOFF"},
	{ ACN_SDT_TYPE_REPLOSTSEQON,	"ACN SDT REPLOSTSEQON"},
	{ ACN_SDT_TYPE_REPLOSTSEQOFF,	"ACN SDT REPLOSTSEQOFF"},
	{ ACN_SDT_TYPE_SESSEXPIRY,	"ACN SDT SESEXPIRY"},
	{ ACN_SDT_TYPE_MAK,		"ACN SDT MAC"},
	{ ACN_SDT_TYPE_ACK,		"ACN SDT ACK"},
	{ ACN_SDT_TYPE_NAK,		"ACN SDT NAK"},
	{ ACN_SDT_TYPE_SEQLOST,		"ACN SDT SEQLOST"},
	{ ACN_SDT_TYPE_NAKPARAMS,	"ACN SDT NAKPARAMS"},
	{ 0,				NULL }
};

static const value_string acn_dmp_type_vals[] = {
	{ ACN_DMP_TYPE_UNKNOWN,		"ACN DMP Unknown Type"},
	{ 0,				NULL }
};

void proto_reg_handoff_acn(void);

/* Define the acn proto */
static int proto_acn = -1;

/* Define the tree for acn */
static int ett_acn = -1;

/* PDU */
static int hf_acn_pdu = -1;

static int hf_acn_pdu_flags = -1;

static int hf_acn_pdu_des = -1;
static int hf_acn_pdu_src = -1;
static int hf_acn_pdu_flag_p = -1;
static int hf_acn_pdu_flag_t = -1;
static int hf_acn_pdu_flag_res = -1;
static int hf_acn_pdu_flag_z = -1;
static int hf_acn_pdu_length = -1;

/* PDU optional */
static int hf_acn_pdu_ext_length_16 = -1;
static int hf_acn_pdu_ext_length_32 = -1;
static int hf_acn_pdu_source_ps = -1;
static int hf_acn_pdu_source_cid = -1;
static int hf_acn_pdu_destination_ps = -1;
static int hf_acn_pdu_destination_cid = -1;
static int hf_acn_pdu_protocol = -1;
static int hf_acn_pdu_type = -1;
static int hf_acn_pdu_type_sdt = -1;
static int hf_acn_pdu_type_dmp = -1;
static int hf_acn_pdu_data = -1;

static int hf_acn_pdu_padding = -1;

/* SDT */
static int hf_acn_sdt_session_nr = -1;
static int hf_acn_sdt_tot_seq_nr = -1;
static int hf_acn_sdt_rel_seq_nr = -1;
static int hf_acn_sdt_unavailable_wrappers = -1;
static int hf_acn_sdt_refuse_code = -1;
static int hf_acn_sdt_last_rel_seq = -1;
static int hf_acn_sdt_last_rel_wrapper = -1;
static int hf_acn_sdt_session_exp_time = -1;


/*
 * Here are the global variables associated with the preferences
 * for acn
 */

static guint global_udp_port_acn = 0;
static guint udp_port_acn = 0;

/* A static handle for the ip dissector */
static dissector_handle_t ip_handle;

static guint dissect_pdu(tvbuff_t *tvb, guint offset, proto_tree *tree, acn_pdu_history_t* parent_hist, guint max_size);
static guint dissect_sdt(tvbuff_t *tvb, guint offset, proto_tree *tree, acn_pdu_history_t* parent_hist, guint max_size);
static guint dissect_dmp(tvbuff_t *tvb, guint offset, proto_tree *tree, acn_pdu_history_t* parent_hist, guint max_size);

static guint 
dissect_sdt(tvbuff_t *tvb, guint offset, proto_tree *tree, acn_pdu_history_t* parent_hist, guint max_size)
{
	proto_tree *flags_tree, *flags_item;
	guint start_offset = offset;
	acn_pdu_history_t hist;
	guint size = 0;

	hist = *parent_hist;

	switch( parent_hist->type )
	{
		case ACN_SDT_TYPE_UNKNOWN:
			break;

		case ACN_SDT_TYPE_RELSEQDATA:
		case ACN_SDT_TYPE_UNRELSEQDATA:
			proto_tree_add_item(tree, hf_acn_sdt_session_nr, tvb,
						offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(tree, hf_acn_sdt_tot_seq_nr, tvb,
						offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_acn_sdt_rel_seq_nr, tvb,
						offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_acn_sdt_unavailable_wrappers, tvb,
						offset, 4, FALSE);
			offset += 4;

			max_size = max_size - (offset - start_offset);
			while( max_size >= ACN_PDU_MIN_SIZE) {
				size = dissect_pdu( tvb, offset, tree, &hist, max_size);
				offset += size;
				max_size -= size;
			}
			
			size = offset - start_offset;

			break;

		case ACN_SDT_TYPE_UNSEQDATA:
			proto_tree_add_item(tree, hf_acn_sdt_session_nr, tvb,
						offset, 2, FALSE);
			offset += 2;

			max_size = max_size - (offset - start_offset);
			while( max_size >= ACN_PDU_MIN_SIZE) {
				size = dissect_pdu( tvb, offset, tree, &hist, max_size);
				offset += size;
				max_size -= size;
			}
			
			size = offset - start_offset;

			break;
			
		case ACN_SDT_TYPE_JOIN:
			break;

		case ACN_SDT_TYPE_TRANSFER:
			break;

		case ACN_SDT_TYPE_JOINREF:
			proto_tree_add_item(tree, hf_acn_sdt_session_nr, tvb,
						offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(tree, hf_acn_sdt_refuse_code, tvb,
						offset, 2, FALSE);
			offset += 2;

			size = offset - start_offset;
			break;

		case ACN_SDT_TYPE_JOINACC:
		case ACN_SDT_TYPE_ACK:
			proto_tree_add_item(tree, hf_acn_sdt_last_rel_seq, tvb,
						offset, 4, FALSE);
			offset += 4;

			size = offset - start_offset;

			break;

		case ACN_SDT_TYPE_LEAVING:
			proto_tree_add_item(tree, hf_acn_sdt_last_rel_wrapper, tvb,
						offset, 4, FALSE);
			offset += 4;

			size = offset - start_offset;
			break;


		case ACN_SDT_TYPE_SESSEXPIRY:
			proto_tree_add_item(tree, hf_acn_sdt_session_exp_time, tvb,
						offset, 2, FALSE);
			offset += 2;

			size = offset - start_offset;
			break;

		case ACN_SDT_TYPE_MAK:
			break;
			
		case ACN_SDT_TYPE_NAK:
			break;
			
		case ACN_SDT_TYPE_SEQLOST:
			break;

		case ACN_SDT_TYPE_NAKPARAMS:
			break;

		case ACN_SDT_TYPE_LEAVEREQ:
		case ACN_SDT_TYPE_LEAVE:
		case ACN_SDT_TYPE_NAKUPON:
		case ACN_SDT_TYPE_NAKUPOFF:
		case ACN_SDT_TYPE_NAKDOWNON:
		case ACN_SDT_TYPE_NAKDOWNOFF:
		case ACN_SDT_TYPE_REPLOSTSEQON:
		case ACN_SDT_TYPE_REPLOSTSEQOFF:
			/* no data */
			break;

		default:
			break;
	}
	
	return size;
}

static guint 
dissect_dmp(tvbuff_t *tvb, guint offset, proto_tree *tree, acn_pdu_history_t* parent_hist, guint max_size)
{
	return 0;
}

static guint 
dissect_pdu(tvbuff_t *tvb, guint offset, proto_tree *tree, acn_pdu_history_t* parent_hist, guint max_size)
{
	guint size,data_size;
	guint8 flags;
	guint src,des;
	proto_tree *ti, *si, *flags_tree, *flags_item;
	guint start_offset = offset;
	acn_pdu_history_t hist;
	

	ti = proto_tree_add_item(tree,
				hf_acn_pdu,
				tvb,
				offset,
				0,
				FALSE);
 
	si = proto_item_add_subtree(ti, ett_acn);
 
	flags = tvb_get_guint8(tvb, offset);
	flags_item = proto_tree_add_uint(si, hf_acn_pdu_flags, tvb,
					offset, 1, flags);

	flags_tree=proto_item_add_subtree(flags_item, ett_acn);
	
	proto_tree_add_item(flags_tree, hf_acn_pdu_des, tvb, offset, 1, FALSE);
	proto_tree_add_item(flags_tree, hf_acn_pdu_src, tvb, offset, 1, FALSE);
	proto_tree_add_item(flags_tree, hf_acn_pdu_flag_p, tvb, offset, 1, FALSE);
	proto_tree_add_item(flags_tree, hf_acn_pdu_flag_t, tvb, offset, 1, FALSE);
	proto_tree_add_item(flags_tree, hf_acn_pdu_flag_res, tvb, offset, 1, FALSE);
	proto_tree_add_item(flags_tree, hf_acn_pdu_flag_z, tvb, offset, 1, FALSE);

	offset += 1;

	size = tvb_get_guint8(tvb, offset);	
	proto_tree_add_uint(si, hf_acn_pdu_length, tvb,
	                          offset, 1, size);
	offset += 1;
	

	if( size == 0 ){
		size = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(si, hf_acn_pdu_ext_length_16, tvb,
					offset, 2, size);	
		offset += 2;	
	} else if( size == 1 ){
		size = tvb_get_ntohl( tvb, offset);
		proto_tree_add_uint(si, hf_acn_pdu_ext_length_32, tvb,
					offset, 4, size);	
		offset += 4;
	}

	switch( hist.source_type )
	{
		case ACN_PDU_SRC_SAME:
			break;
			
		case ACN_PDU_SRC_PS:
			hist.source_type = ACN_PDU_SRC_PS;
			src = tvb_get_ntohs(tvb, offset);
			hist.source.ps = src;
			proto_tree_add_uint(si, hf_acn_pdu_source_ps, tvb,
						offset, 2, src);
			offset += 2;
			break;
			
		case ACN_PDU_SRC_CID:
			hist.source_type = ACN_PDU_SRC_CID;
			tvb_memcpy(tvb, hist.source.cid, offset, 16 );
			proto_tree_add_item(si, hf_acn_pdu_source_cid, tvb,
						offset, 16, FALSE);
			offset += 16;
			break;
			
		case ACN_PDU_SRC_UM:
			hist.source_type = ACN_PDU_SRC_UM;
			break;	
	} 


	switch( flags & ACN_PDU_DES )
	{	
		case ACN_PDU_DES_SAME:
			break;
			
		case ACN_PDU_DES_PS:
			hist.destination_type = ACN_PDU_DES_PS;
			des = tvb_get_ntohs(tvb, offset);
			hist.destination.ps = des;
			proto_tree_add_uint(si, hf_acn_pdu_destination_ps, tvb,
						offset, 2, des);	
			offset += 2;
			break;
			
		case ACN_PDU_DES_CID:
			hist.destination_type = ACN_PDU_DES_CID;
			tvb_memcpy(tvb, hist.destination.cid, offset, 16 );
			proto_tree_add_item(si, hf_acn_pdu_destination_cid, tvb,
						offset, 16, FALSE);
			offset += 16;
			break;
			
		case ACN_PDU_DES_ALL:
			hist.destination_type = ACN_PDU_DES_ALL;
			break;	
	} 

	if( flags & ACN_PDU_FLAG_P )
	{
		hist.protocol = tvb_get_ntohs( tvb, offset );
		proto_tree_add_item(si, hf_acn_pdu_protocol, tvb,
					offset, 2, TRUE );
		offset += 2;
	}

	if( flags & ACN_PDU_FLAG_T )
	{
		hist.type = tvb_get_ntohs( tvb, offset );
	
		switch( hist.protocol ) { 
			case ACN_PDU_PROTO_SDT:
				proto_tree_add_item(si, hf_acn_pdu_type_sdt, tvb,
						offset, 2, TRUE );
				break;

			case ACN_PDU_PROTO_DMP:
				proto_tree_add_item(si, hf_acn_pdu_type_dmp, tvb,
						offset, 2, TRUE );
				break;
				
			default:
				proto_tree_add_item(si, hf_acn_pdu_type, tvb,
						offset, 2, TRUE );
				break;	
	
	
	
		}
		
		offset += 2;
	}

	hist = *parent_hist;

	if( flags & ACN_PDU_FLAG_Z )
	{
		data_size = size - (offset - start_offset);
		
		switch( hist.protocol ) {
			case ACN_PDU_PROTO_SDT:
				dissect_sdt( tvb, offset, si, &hist, data_size);
				break;
			
			case ACN_PDU_PROTO_DMP:
				dissect_dmp( tvb, offset, si, &hist, data_size);	
				break;
	
			default:
				proto_tree_add_item(si, hf_acn_pdu_data, tvb,
							offset, data_size, TRUE );
				break;	
		}

		offset += data_size;
	}

	if( size & 0x00000001 )
	{
	
		proto_tree_add_item(si, hf_acn_pdu_padding, tvb,
					offset, 1, TRUE );
		
		size += 1;
		offset += 1;
	}

	proto_item_set_len(si, size);

	return size;
}

static void
dissect_acn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
	gint offset = 0;
	guint size,max_size;
	acn_pdu_history_t hist;

	/* Set the protocol column */
	if(check_col(pinfo->cinfo,COL_PROTOCOL)){
		col_set_str(pinfo->cinfo,COL_PROTOCOL,"ACN");
	}

	/* Clear out stuff in the info column */
	if(check_col(pinfo->cinfo,COL_INFO)){
		col_clear(pinfo->cinfo,COL_INFO);
	}

	if (tree) 
	{
		/* history default values */
		hist.destination_type = ACN_PDU_DES_ALL; 
		hist.source_type = ACN_PDU_SRC_UM;
		hist.protocol = ACN_PDU_PROTO_UNKNOWN;
		hist.type = ACN_PDU_TYPE_UNKNOWN;
		
		max_size = tvb_reported_length_remaining(tvb, offset);
		
		while( max_size >= ACN_PDU_MIN_SIZE) {
			size = dissect_pdu( tvb, offset, tree, &hist, max_size);
			offset += size;
			max_size -= size;
		}
	}
}

void
proto_register_acn(void) {
  static hf_register_info hf[] = {
	/* PDU */
	{ &hf_acn_pdu,
	    { "ACN PDU", "acn.pdu",
		FT_NONE, BASE_NONE, NULL, 0,
		"ACN PDU", HFILL }},

	{ &hf_acn_pdu_flags,
	    { "PDU Flags","acn.pdu.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0,
		"PDU flags", HFILL }},

	{ &hf_acn_pdu_des,
	    { "PDU des","acn.pdu.des",
		FT_UINT8, BASE_HEX, NULL, 0xC0,
		"PDU des", HFILL }},

	{ &hf_acn_pdu_src,
	    { "PDU src","acn.pdu.src",
		FT_UINT8, BASE_HEX, NULL, 0x30,
		"PDU src", HFILL }},

	{ &hf_acn_pdu_flag_p,
	    { "PDU Flag p","acn.pdu.flag_p",
		FT_UINT8, BASE_HEX, NULL, 0x08,
		"PDU flag p", HFILL }},

	{ &hf_acn_pdu_flag_t,
	    { "PDU Flag t","acn.pdu.flag_t",
		FT_UINT8, BASE_HEX, NULL, 0x04,
		"PDU flag t", HFILL }},

	{ &hf_acn_pdu_flag_z,
	    { "PDU Flag z","acn.pdu.flag_z",
		FT_UINT8, BASE_HEX, NULL, 0x01,
		"PDU flag z", HFILL }},

	{ &hf_acn_pdu_flag_res,
	    { "PDU Flag res","acn.pdu.flag_res",
		FT_UINT8, BASE_HEX, NULL, 0x02,
		"PDU flag res", HFILL }},

	{ &hf_acn_pdu_length,
	    { "PDU Lenght","acn.pdu.length",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"PDU Length", HFILL }},

	{ &hf_acn_pdu_ext_length_16,
	    { "PDU Ext Length 16bit","acn.pdu.ext_length_16",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"PDU Ext Length 16bit", HFILL }},

	{ &hf_acn_pdu_ext_length_32,
	    { "PDU Ext Length 32bit","acn.pdu.ext_length_32",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"PDU Ext Length 32bit", HFILL }},

	{ &hf_acn_pdu_source_ps,
	    { "PDU Source PS","acn.pdu.source_ps",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"PDU Source", HFILL }},

	{ &hf_acn_pdu_source_cid,
	    { "PDU Source CID","acn.pdu.source_cid",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"PDU Source CID", HFILL }},

	{ &hf_acn_pdu_destination_ps,
	    { "PDU Destination PS","acn.pdu.destination_ps",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"PDU Destination PS", HFILL }},

	{ &hf_acn_pdu_destination_cid,
	    { "PDU Destination CID","acn.pdu.destination_cid",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"PDU Destination CID", HFILL }},

	{ &hf_acn_pdu_protocol,
	    { "PDU Protocol","acn.pdu.protocol",
		FT_UINT16, BASE_HEX, VALS(acn_proto_vals), 0x0,
		"PDU Protocol", HFILL }},

	{ &hf_acn_pdu_type,
	    { "PDU Type","acn.pdu.type",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"PDU Type", HFILL }},

	{ &hf_acn_pdu_type_sdt,
	    { "PDU Type SDT","acn.pdu.type_sdt",
		FT_UINT16, BASE_HEX, VALS(acn_sdt_type_vals), 0x0,
		"PDU Type SDT", HFILL }},

	{ &hf_acn_pdu_type_dmp,
	    { "PDU Type DMP","acn.pdu.type_dmp",
		FT_UINT16, BASE_HEX, VALS(acn_dmp_type_vals), 0x0,
		"PDU Type DMP", HFILL }},
		
	{ &hf_acn_pdu_data,
	    { "PDU Data","acn.pdu.data",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"PDU Data", HFILL }},

	{ &hf_acn_pdu_padding,
	    { "PDU Padding","acn.pdu.padding",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"PDU Padding", HFILL }},

	{ &hf_acn_sdt_session_nr,
	    { "PDU SDT Session Nr","acn.sdt.session_nr",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"PDU SDT Session Nr", HFILL }},

	{ &hf_acn_sdt_tot_seq_nr,
	    { "PDU SDT Total Sequence Nr","acn.sdt.tot_seq_nr",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"PDU SDT Total Sequence Nr", HFILL }},

	{ &hf_acn_sdt_rel_seq_nr,
	    { "PDU SDT Rel Seq Nr","acn.sdt.rel_seq_nr",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"PDU SDT Rel Sequence Nr", HFILL }},

	{ &hf_acn_sdt_unavailable_wrappers,
	    { "PDU SDT Unavailable Wrappers","acn.sdt.unavailable_wrappers",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"PDU SDT Unavailable Wrappers", HFILL }},
		
	{ &hf_acn_sdt_refuse_code,
	    { "PDU SDT Refuse code","acn.sdt.refuse_code",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"PDU SDT Refuse Code", HFILL }},

	{ &hf_acn_sdt_last_rel_seq,
	    { "PDU SDT Last reliable seq nr","acn.sdt.last_rel_seq",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"PDU SDT Last reliable seq nr", HFILL }},

	{ &hf_acn_sdt_last_rel_wrapper,
	    { "PDU SDT Last reliable Wrapper","acn.sdt.last_rel_wrapper",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"PDU SDT Last reliable Wrapper", HFILL }},

	{ &hf_acn_sdt_session_exp_time,
	    { "PDU SDT Session expire time","acn.sdt.session_exp_time",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"PDU SDT Session expire time", HFILL }}

  };

  static gint *ett[] = {
    &ett_acn,
  };

  module_t *acn_module;

  proto_acn = proto_register_protocol("ACN",
				      "ACN","acn");
  proto_register_field_array(proto_acn,hf,array_length(hf));
  proto_register_subtree_array(ett,array_length(ett));

  acn_module = prefs_register_protocol(proto_acn,
				       proto_reg_handoff_acn);
#if 0
  prefs_register_uint_preference(artnet_module, "udp_port",
				 "ARTNET UDP Port",
				 "The UDP port on which "
				 "Art-Net "
				 "packets will be sent",
				 10,&global_udp_port_artnet);
#endif
}

/* The registration hand-off routing */

void
proto_reg_handoff_acn(void) {
  static int acn_initialized = FALSE;
  static dissector_handle_t acn_handle;

  ip_handle = find_dissector("ip");

  if(!acn_initialized) {
    acn_handle = create_dissector_handle(dissect_acn,proto_acn);
    acn_initialized = TRUE;
  } else {
    dissector_delete("udp.port",udp_port_acn,acn_handle);
  }

  udp_port_acn = global_udp_port_acn;
  
  dissector_add("udp.port",global_udp_port_acn,acn_handle);
}

/* Start the functions we need for the plugin stuff */

#ifndef ENABLE_STATIC

G_MODULE_EXPORT void
plugin_reg_handoff(void){
  proto_reg_handoff_acn();
}

G_MODULE_EXPORT void
plugin_init(plugin_address_table_t *pat
#ifndef PLUGINS_NEED_ADDRESS_TABLE
_U_
#endif
){
  /* initialise the table of pointers needed in Win32 DLLs */
  plugin_address_table_init(pat);
  /* register the new protocol, protocol fields, and subtrees */
  if (proto_acn == -1) { /* execute protocol initialization only once */
    proto_register_acn();
  }
}

#endif

/* End the functions we need for plugin stuff */

