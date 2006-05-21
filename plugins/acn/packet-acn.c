/* packet-acn.c
 * Routines for ACN packet disassembly
 *
 * $Id$
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <time.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/prefs.h>
#include <epan/strutil.h>

#include "acn.h"

/*
 * See
 *
 *	http://www.esta.org/tsp/E1-17inst.htm
 */

static const value_string acn_proto_vals[] = {
	{ ACN_PDU_PROTO_UNKNOWN,	"Unknown"},
	{ ACN_PDU_PROTO_SDT,		"SDT" },
	{ ACN_PDU_PROTO_DMP,		"DMP" },
	{ 0,				NULL }
};

static const value_string acn_sdt_type_vals[] = {
	{ ACN_SDT_TYPE_UNKNOWN,		"Unknown"},
	{ ACN_SDT_TYPE_RELSEQDATA,	"RELSEQDATA"},
	{ ACN_SDT_TYPE_UNRELSEQDATA,	"UNRELSEQDATA"},
	{ ACN_SDT_TYPE_UNSEQDATA,	"UNSEQDATA"},
	{ ACN_SDT_TYPE_JOIN,		"JOIN"},
	{ ACN_SDT_TYPE_TRANSFER,	"TRANSFER"},
	{ ACN_SDT_TYPE_JOINREF,		"JOINREF"},
	{ ACN_SDT_TYPE_JOINACC,		"JOINACC"},
	{ ACN_SDT_TYPE_LEAVEREQ,	"LEAVEREQ"},
	{ ACN_SDT_TYPE_LEAVE,		"LEAVE"},
	{ ACN_SDT_TYPE_LEAVING,		"LEAVING"},
	{ ACN_SDT_TYPE_NAKUPON,		"NAKUPON"},
	{ ACN_SDT_TYPE_NAKUPOFF,	"NAKUPOFF"},
	{ ACN_SDT_TYPE_NAKDOWNON,	"NAKDOWNON"},
	{ ACN_SDT_TYPE_NAKDOWNOFF,	"NAKDOWNOFF"},
	{ ACN_SDT_TYPE_REPLOSTSEQON,	"REPLOSTSEQON"},
	{ ACN_SDT_TYPE_REPLOSTSEQOFF,	"REPLOSTSEQOFF"},
	{ ACN_SDT_TYPE_SESSEXPIRY,	"SESEXPIRY"},
	{ ACN_SDT_TYPE_MAK,		"MAK"},
	{ ACN_SDT_TYPE_ACK,		"ACK"},
	{ ACN_SDT_TYPE_NAK,		"NAK"},
	{ ACN_SDT_TYPE_SEQLOST,		"SEQLOST"},
	{ ACN_SDT_TYPE_NAKPARAMS,	"NAKPARAMS"},
	{ 0,				NULL }
};

static const value_string acn_dmp_type_vals[] = {
	{ ACN_DMP_TYPE_UNKNOWN,		"Unknown"},
	{ 0,				NULL }
};


static const value_string acn_sdt_address_type_vals[] = {
	{ ACN_SDT_ADDR_NULL,		"Unspecified"},
	{ ACN_SDT_ADDR_IPV4,		"IP version 4"},
	{ ACN_SDT_ADDR_IPV6,		"IP version 6"},
	{ 0,				NULL }
};

static const value_string acn_sdt_des_flag_vals[] = {
	{ 0,				"Default"},
	{ 1,				"Protocol Specific"},
	{ 2,				"CID"},
	{ 3,				"All"}, 
	{ 0,				NULL }
};

static const value_string acn_sdt_src_flag_vals[] = {
	{ 0,				"Default"},
	{ 1,				"Protocol Specific"},
	{ 2,				"CID"},
	{ 3,				"Unspecified"}, 
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
static int hf_acn_pdu_unknown_data = -1;

static int hf_acn_pdu_padding = -1;

/* SDT */
static int hf_acn_sdt_session_nr = -1;
static int hf_acn_sdt_tot_seq_nr = -1;
static int hf_acn_sdt_rel_seq_nr = -1;
static int hf_acn_sdt_unavailable_wrappers = -1;
static int hf_acn_sdt_refuse_code = -1;
static int hf_acn_sdt_last_rel_seq = -1;
static int hf_acn_sdt_new_rel_seq = -1;
static int hf_acn_sdt_last_rel_wrapper = -1;
static int hf_acn_sdt_nr_lost_wrappers = -1;
static int hf_acn_sdt_session_exp_time = -1;
static int hf_acn_sdt_upstream_address_type = -1;
static int hf_acn_sdt_upstream_ipv4_address = -1;
static int hf_acn_sdt_upstream_ipv6_address = -1;
static int hf_acn_sdt_upstream_port = -1;
static int hf_acn_sdt_downstream_address_type = -1;
static int hf_acn_sdt_downstream_ipv4_address = -1;
static int hf_acn_sdt_downstream_ipv6_address = -1;
static int hf_acn_sdt_downstream_port = -1;

static int hf_acn_sdt_flags = -1;
static int hf_acn_sdt_flag_u = -1;
static int hf_acn_sdt_flag_d = -1;
static int hf_acn_sdt_flag_l = -1;

static int hf_acn_sdt_mid = -1;
static int hf_acn_sdt_nak_holdoff_interval = -1;
static int hf_acn_sdt_nak_modulus = -1;
static int hf_acn_sdt_max_nak_wait_time = -1;
static int hf_acn_sdt_leader_cid = -1;
static int hf_acn_sdt_member_cid = -1;
static int hf_acn_sdt_ack_threshold = -1;

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
	guint flags;
	guint type;
	guint count;

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
			proto_tree_add_item(tree, hf_acn_sdt_session_nr, tvb,
						offset, 2, FALSE);
			offset += 2;

			flags = tvb_get_guint8(tvb, offset);
			flags_item = proto_tree_add_uint(tree, hf_acn_sdt_flags, tvb,
							offset, 1, flags);

			flags_tree=proto_item_add_subtree(flags_item, ett_acn);
			proto_tree_add_item(flags_tree, hf_acn_sdt_flag_u, tvb, offset, 1, FALSE);
			proto_tree_add_item(flags_tree, hf_acn_sdt_flag_d, tvb, offset, 1, FALSE);
			proto_tree_add_item(flags_tree, hf_acn_sdt_flag_l, tvb, offset, 1, FALSE);
			offset += 1;

			type = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_acn_sdt_upstream_address_type, tvb,
					    offset, 1, FALSE);
			offset += 1;
			
			switch( type )
			{
				default:
				case ACN_SDT_ADDR_NULL:
					break;
					
				case ACN_SDT_ADDR_IPV4:
					proto_tree_add_item(tree, hf_acn_sdt_upstream_port, tvb,
								offset, 2, FALSE);
					offset += 2;
				
					proto_tree_add_item(tree, hf_acn_sdt_upstream_ipv4_address, tvb,
								offset, 4, FALSE);
					offset += 4;
				
					break;
					
				case ACN_SDT_ADDR_IPV6:
					proto_tree_add_item(tree, hf_acn_sdt_upstream_port, tvb,
								offset, 2, FALSE);
					offset += 2;

					proto_tree_add_item(tree, hf_acn_sdt_upstream_ipv6_address, tvb,
								offset, 16, FALSE);
					offset += 16;
				
					break;		
			}
			
			flags = tvb_get_guint8(tvb, offset);
			flags_item = proto_tree_add_uint(tree, hf_acn_sdt_flags, tvb,
							offset, 1, flags);

			flags_tree=proto_item_add_subtree(flags_item, ett_acn);
			offset += 1;

			type = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_acn_sdt_downstream_address_type, tvb,
					    offset, 1, FALSE);
			offset += 1;
			
			switch( type )
			{
				default:
				case ACN_SDT_ADDR_NULL:
					break;
					
				case ACN_SDT_ADDR_IPV4:
					proto_tree_add_item(tree, hf_acn_sdt_downstream_port, tvb,
								offset, 2, FALSE);
					offset += 2;

					proto_tree_add_item(tree, hf_acn_sdt_downstream_ipv4_address, tvb,
								offset, 4, FALSE);
					offset += 4;
				
				
					break;
					
				case ACN_SDT_ADDR_IPV6:
					proto_tree_add_item(tree, hf_acn_sdt_downstream_port, tvb,
								offset, 2, FALSE);
					offset += 2;

					proto_tree_add_item(tree, hf_acn_sdt_downstream_ipv6_address, tvb,
								offset, 16, FALSE);
					offset += 16;
				
					break;		
			}
			
							
			proto_tree_add_item(tree, hf_acn_sdt_mid, tvb,
						offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(tree, hf_acn_sdt_tot_seq_nr, tvb,
						offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_acn_sdt_rel_seq_nr, tvb,
						offset, 4, FALSE);
			offset += 4;
			
			proto_tree_add_item(tree, hf_acn_sdt_session_exp_time, tvb,
						offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(tree, hf_acn_sdt_nak_holdoff_interval, tvb,
						offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(tree, hf_acn_sdt_nak_modulus, tvb,
						offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(tree, hf_acn_sdt_max_nak_wait_time, tvb,
						offset, 2, FALSE);
			offset += 2;
					
			size = offset - start_offset;

			break;

		case ACN_SDT_TYPE_TRANSFER:
			proto_tree_add_item(tree, hf_acn_sdt_leader_cid, tvb,
						offset, 16, FALSE);
			offset += 16;

			proto_tree_add_item(tree, hf_acn_sdt_session_nr, tvb,
						offset, 2, FALSE);
			offset += 2;

			flags = tvb_get_guint8(tvb, offset);
			flags_item = proto_tree_add_uint(tree, hf_acn_sdt_flags, tvb,
							offset, 1, flags);

			flags_tree=proto_item_add_subtree(flags_item, ett_acn);
			proto_tree_add_item(flags_tree, hf_acn_sdt_flag_u, tvb, offset, 1, FALSE);
			proto_tree_add_item(flags_tree, hf_acn_sdt_flag_d, tvb, offset, 1, FALSE);
			proto_tree_add_item(flags_tree, hf_acn_sdt_flag_l, tvb, offset, 1, FALSE);
			offset += 1;

			type = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_acn_sdt_upstream_address_type, tvb,
					    offset, 1, FALSE);
			offset += 1;
			
			switch( type )
			{
				default:
				case ACN_SDT_ADDR_NULL:
					break;
					
				case ACN_SDT_ADDR_IPV4:
					proto_tree_add_item(tree, hf_acn_sdt_upstream_ipv4_address, tvb,
								offset, 4, FALSE);
					offset += 4;
				
					proto_tree_add_item(tree, hf_acn_sdt_upstream_port, tvb,
								offset, 2, FALSE);
					offset += 2;
				
					break;
					
				case ACN_SDT_ADDR_IPV6:
					proto_tree_add_item(tree, hf_acn_sdt_upstream_ipv6_address, tvb,
								offset, 16, FALSE);
					offset += 16;
				
					proto_tree_add_item(tree, hf_acn_sdt_upstream_port, tvb,
								offset, 2, FALSE);
					offset += 2;
					break;		
			}
			
			flags = tvb_get_guint8(tvb, offset);
			flags_item = proto_tree_add_uint(tree, hf_acn_sdt_flags, tvb,
							offset, 1, flags);

			flags_tree=proto_item_add_subtree(flags_item, ett_acn);
			offset += 1;

			type = tvb_get_guint8(tvb, offset);
			proto_tree_add_item(tree, hf_acn_sdt_downstream_address_type, tvb,
					    offset, 1, FALSE);
			offset += 1;
			
			switch( type )
			{
				default:
				case ACN_SDT_ADDR_NULL:
					break;
					
				case ACN_SDT_ADDR_IPV4:
					proto_tree_add_item(tree, hf_acn_sdt_downstream_ipv4_address, tvb,
								offset, 4, FALSE);
					offset += 4;
				
					proto_tree_add_item(tree, hf_acn_sdt_downstream_port, tvb,
								offset, 2, FALSE);
					offset += 2;
				
					break;
					
				case ACN_SDT_ADDR_IPV6:
					proto_tree_add_item(tree, hf_acn_sdt_downstream_ipv6_address, tvb,
								offset, 16, FALSE);
					offset += 16;
				
					proto_tree_add_item(tree, hf_acn_sdt_downstream_port, tvb,
								offset, 2, FALSE);
					offset += 2;
					break;		
			}
			
							
			proto_tree_add_item(tree, hf_acn_sdt_mid, tvb,
						offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(tree, hf_acn_sdt_tot_seq_nr, tvb,
						offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_acn_sdt_rel_seq_nr, tvb,
						offset, 4, FALSE);
			offset += 4;
			
			proto_tree_add_item(tree, hf_acn_sdt_session_exp_time, tvb,
						offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(tree, hf_acn_sdt_nak_holdoff_interval, tvb,
						offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(tree, hf_acn_sdt_nak_modulus, tvb,
						offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(tree, hf_acn_sdt_max_nak_wait_time, tvb,
						offset, 2, FALSE);
			offset += 2;
			
			/* CID+MID list */
			count = (max_size - (offset - start_offset)) / 18;
			while( count > 0) {
				proto_tree_add_item(tree, hf_acn_sdt_member_cid, tvb,
							offset, 16, FALSE);
				offset += 16;

				proto_tree_add_item(tree, hf_acn_sdt_mid, tvb,
							offset, 2, FALSE);
				offset += 2;

				count--;
			}
			
			size = offset - start_offset;

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
			proto_tree_add_item(tree, hf_acn_sdt_ack_threshold, tvb,
						offset, 2, FALSE);
			offset += 2;

			count = (max_size - (offset - start_offset)) / 2;
			while( count > 0) {
				proto_tree_add_item(tree, hf_acn_sdt_mid, tvb,
							offset, 2, FALSE);
				offset += 2;

				count--;
			}
			
			size = offset - start_offset;
			break;
			
		case ACN_SDT_TYPE_NAK:				
			proto_tree_add_item(tree, hf_acn_sdt_session_nr, tvb,
						offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(tree, hf_acn_sdt_mid, tvb,
						offset, 2, FALSE);
			offset += 2;

			proto_tree_add_item(tree, hf_acn_sdt_last_rel_seq, tvb,
						offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_acn_sdt_nr_lost_wrappers, tvb,
						offset, 2, FALSE);
			offset += 2;

			size = offset - start_offset;
			break;
			
		case ACN_SDT_TYPE_SEQLOST:
			proto_tree_add_item(tree, hf_acn_sdt_last_rel_seq, tvb,
						offset, 4, FALSE);
			offset += 4;

			proto_tree_add_item(tree, hf_acn_sdt_new_rel_seq, tvb,
						offset, 4, FALSE);
			offset += 4;
			size = offset - start_offset;
			break;

		case ACN_SDT_TYPE_NAKPARAMS:
			proto_tree_add_item(tree, hf_acn_sdt_nak_holdoff_interval, tvb,
						offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(tree, hf_acn_sdt_nak_modulus, tvb,
						offset, 2, FALSE);
			offset += 2;
			
			proto_tree_add_item(tree, hf_acn_sdt_max_nak_wait_time, tvb,
						offset, 2, FALSE);
			offset += 2;

			size = offset - start_offset;
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
			size = offset - start_offset;
			break;

		default:
			break;
	}
	
	return size;
}

static guint 
dissect_dmp(tvbuff_t *tvb _U_, guint offset _U_, proto_tree *tree _U_, acn_pdu_history_t* parent_hist _U_, guint max_size _U_)
{
	return 0;
}

static guint 
dissect_pdu(tvbuff_t *tvb, guint offset, proto_tree *tree, acn_pdu_history_t* parent_hist, guint max_size)
{
	guint size,data_size;
	guint8 flags;
	guint src,des;
	proto_tree *ti, *si, *flags_tree, *flags_item, *data_tree, *data_item;
	guint start_offset = offset;
	acn_pdu_history_t hist = *parent_hist;
	

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
	
	if(size > max_size )
		size = max_size;

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


	switch( flags & ACN_PDU_SRC )
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



	if( flags & ACN_PDU_FLAG_P )
	{
		hist.protocol = tvb_get_ntohs( tvb, offset );
		proto_tree_add_item(si, hf_acn_pdu_protocol, tvb,
					offset, 2, FALSE );
		offset += 2;
	}

	if( flags & ACN_PDU_FLAG_T )
	{
		hist.type = tvb_get_ntohs( tvb, offset );
	
		switch( hist.protocol ) { 
			case ACN_PDU_PROTO_SDT:
				proto_tree_add_item(si, hf_acn_pdu_type_sdt, tvb,
						offset, 2, FALSE );
				break;

			case ACN_PDU_PROTO_DMP:
				proto_tree_add_item(si, hf_acn_pdu_type_dmp, tvb,
						offset, 2, FALSE );
				break;
				
			default:
				proto_tree_add_item(si, hf_acn_pdu_type, tvb,
						offset, 2, FALSE );
				break;	
	
	
	
		}
		
		offset += 2;
	}

	if( flags & ACN_PDU_FLAG_Z )
	{
		data_size = size - (offset - start_offset);


		data_item = proto_tree_add_item(si, hf_acn_pdu_data, tvb,
						offset, data_size, FALSE);

		data_tree=proto_item_add_subtree(data_item, ett_acn);


		switch( hist.protocol ) {
			case ACN_PDU_PROTO_SDT:
				dissect_sdt( tvb, offset, data_tree, &hist, data_size);
				break;
			
			case ACN_PDU_PROTO_DMP:
				dissect_dmp( tvb, offset, data_tree, &hist, data_size);	
				break;
	
			default:
				proto_tree_add_item(si, hf_acn_pdu_unknown_data, tvb,
							offset, data_size, FALSE );
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
	    { "Flags","acn.pdu.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0,
		"Flags", HFILL }},

	{ &hf_acn_pdu_des,
	    { "des","acn.pdu.des",
		FT_UINT8, BASE_HEX, VALS( acn_sdt_des_flag_vals ), 0xC0,
		"des", HFILL }},

	{ &hf_acn_pdu_src,
	    { "src","acn.pdu.src",
		FT_UINT8, BASE_HEX, VALS( acn_sdt_src_flag_vals ), 0x30,
		"src", HFILL }},

	{ &hf_acn_pdu_flag_p,
	    { "P","acn.pdu.flag_p",
		FT_UINT8, BASE_HEX, NULL, 0x08,
		"P", HFILL }},

	{ &hf_acn_pdu_flag_t,
	    { "T","acn.pdu.flag_t",
		FT_UINT8, BASE_HEX, NULL, 0x04,
		"T", HFILL }},

	{ &hf_acn_pdu_flag_z,
	    { "Z","acn.pdu.flag_z",
		FT_UINT8, BASE_HEX, NULL, 0x01,
		"Z", HFILL }},

	{ &hf_acn_pdu_flag_res,
	    { "res","acn.pdu.flag_res",
		FT_UINT8, BASE_HEX, NULL, 0x02,
		"res", HFILL }},

	{ &hf_acn_pdu_length,
	    { "Length","acn.pdu.length",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Length", HFILL }},

	{ &hf_acn_pdu_ext_length_16,
	    { "Ext Length 16bit","acn.pdu.ext_length_16",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"Ext Length 16bit", HFILL }},

	{ &hf_acn_pdu_ext_length_32,
	    { "Ext Length 32bit","acn.pdu.ext_length_32",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"Ext Length 32bit", HFILL }},

	{ &hf_acn_pdu_source_ps,
	    { "Source PS","acn.pdu.source_ps",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"Source PS", HFILL }},

	{ &hf_acn_pdu_source_cid,
	    { "Source CID","acn.pdu.source_cid",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"Source CID", HFILL }},

	{ &hf_acn_pdu_destination_ps,
	    { "Destination PS","acn.pdu.destination_ps",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"Destination PS", HFILL }},

	{ &hf_acn_pdu_destination_cid,
	    { "Destination CID","acn.pdu.destination_cid",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"Destination CID", HFILL }},

	{ &hf_acn_pdu_protocol,
	    { "Protocol","acn.pdu.protocol",
		FT_UINT16, BASE_HEX, VALS(acn_proto_vals), 0x0,
		"Protocol", HFILL }},

	{ &hf_acn_pdu_type,
	    { "Type","acn.pdu.type",
		FT_UINT16, BASE_HEX, NULL, 0x0,
		"Type", HFILL }},

	{ &hf_acn_pdu_type_sdt,
	    { "SDT Type","acn.pdu.type_sdt",
		FT_UINT16, BASE_HEX, VALS(acn_sdt_type_vals), 0x0,
		"SDT Type", HFILL }},

	{ &hf_acn_pdu_type_dmp,
	    { "DMP Type","acn.pdu.type_dmp",
		FT_UINT16, BASE_HEX, VALS(acn_dmp_type_vals), 0x0,
		"DMP Type", HFILL }},
		
	{ &hf_acn_pdu_data,
	    { "Data","acn.pdu.data",
		FT_NONE, BASE_HEX, NULL, 0x0,
		"Data", HFILL }},

	{ &hf_acn_pdu_unknown_data,
	    { "Unknown Data","acn.pdu.unknown_data",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"Unknown Data", HFILL }},

	{ &hf_acn_pdu_padding,
	    { "Padding","acn.pdu.padding",
		FT_UINT8, BASE_DEC, NULL, 0x0,
		"Padding", HFILL }},

	{ &hf_acn_sdt_session_nr,
	    { "SDT Session Nr","acn.sdt.session_nr",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT Session Nr", HFILL }},

	{ &hf_acn_sdt_tot_seq_nr,
	    { "SDT Total Sequence Nr","acn.sdt.tot_seq_nr",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"SDT Total Sequence Nr", HFILL }},

	{ &hf_acn_sdt_rel_seq_nr,
	    { "SDT Rel Seq Nr","acn.sdt.rel_seq_nr",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"SDT Rel Sequence Nr", HFILL }},

	{ &hf_acn_sdt_unavailable_wrappers,
	    { "SDT Unavailable Wrappers","acn.sdt.unavailable_wrappers",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"SDT Unavailable Wrappers", HFILL }},
		
	{ &hf_acn_sdt_refuse_code,
	    { "SDT Refuse code","acn.sdt.refuse_code",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT Refuse Code", HFILL }},

	{ &hf_acn_sdt_last_rel_seq,
	    { "SDT Last reliable seq nr","acn.sdt.last_rel_seq",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"SDT Last reliable seq nr", HFILL }},

	{ &hf_acn_sdt_new_rel_seq,
	    { "SDT reliable seq nr to continue with","acn.sdt.new_rel_seq",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"SDT reliable seq nr to continue with", HFILL }},

	{ &hf_acn_sdt_last_rel_wrapper,
	    { "SDT Last reliable Wrapper","acn.sdt.last_rel_wrapper",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"SDT Last reliable Wrapper", HFILL }},

	{ &hf_acn_sdt_nr_lost_wrappers,
	    { "SDT Nr of lost Wrappers","acn.sdt.nr_lost_wrappers",
		FT_UINT32, BASE_DEC, NULL, 0x0,
		"SDT Nr of lost  Wrappers", HFILL }},

	{ &hf_acn_sdt_session_exp_time,
	    { "SDT Session expire time","acn.sdt.session_exp_time",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT Session expire time", HFILL }},
		
	{ &hf_acn_sdt_flags,
	    { "SDT Flags","acn.sdt.flags",
		FT_UINT8, BASE_HEX, NULL, 0x0,
		"SDT Flags", HFILL }},

	{ &hf_acn_sdt_flag_u,
	    { "U","acn.sdt.flag_u",
		FT_UINT8, BASE_HEX, NULL, 0x80,
		"U", HFILL }},

	{ &hf_acn_sdt_flag_d,
	    { "D","acn.sdt.flag_d",
		FT_UINT8, BASE_HEX, NULL, 0x40,
		"D", HFILL }},

	{ &hf_acn_sdt_flag_l,
	    { "L","acn.sdt.flag_l",
		FT_UINT8, BASE_HEX, NULL, 0x20,
		"L", HFILL }},

	{ &hf_acn_sdt_upstream_address_type,
	    { "SDT Upstream address type","acn.sdt.upstream_address_type",
		FT_UINT8, BASE_HEX, VALS(acn_sdt_address_type_vals), 0x0,
		"SDT Upstream address type", HFILL }},

	{ &hf_acn_sdt_downstream_address_type,
	    { "SDT Downstream address type","acn.sdt.downstream_address_type",
		FT_UINT8, BASE_HEX, VALS(acn_sdt_address_type_vals), 0x0,
		"SDT Downstream address type", HFILL }},

	{ &hf_acn_sdt_upstream_port,
	    { "SDT Upstream Port","acn.sdt.upstream_port",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT Upstream Port", HFILL }},

	{ &hf_acn_sdt_downstream_port,
	    { "SDT Donwstream Port","acn.sdt.downstream_port",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT Downstream Port", HFILL }},

	{ &hf_acn_sdt_downstream_ipv4_address,
	    { "SDT Donwstream IPv4 Address","acn.sdt.downstream_ipv4_address",
		FT_IPv4, BASE_DEC, NULL, 0x0,
		"SDT Downstream IPv4 Address", HFILL }},

	{ &hf_acn_sdt_upstream_ipv4_address,
	    { "SDT Upstream IPv4 Address","acn.sdt.upstream_ipv4_address",
		FT_IPv4, BASE_DEC, NULL, 0x0,
		"SDT Upstream IPv4 Address", HFILL }},

	{ &hf_acn_sdt_downstream_ipv6_address,
	    { "SDT Donwstream IPv6 Address","acn.sdt.downstream_ipv6_address",
		FT_IPv6, BASE_DEC, NULL, 0x0,
		"SDT Downstream IPv6 Address", HFILL }},

	{ &hf_acn_sdt_upstream_ipv6_address,
	    { "SDT Upstream IPv6 Address","acn.sdt.upstream_ipv6_address",
		FT_IPv6, BASE_DEC, NULL, 0x0,
		"SDT Upstream IPv6 Address", HFILL }},

	{ &hf_acn_sdt_mid,
	    { "SDT Member ID","acn.sdt.mid",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT Member ID", HFILL }},

	{ &hf_acn_sdt_nak_holdoff_interval,
	    { "SDT NAK holdoff interval","acn.sdt.nak_holdoff_interval",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT NAK holdoff interval", HFILL }},

	{ &hf_acn_sdt_nak_modulus,
	    { "SDT NAK modulus","acn.sdt.nak_modulus",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT NAK modulus", HFILL }},

	{ &hf_acn_sdt_max_nak_wait_time,
	    { "SDT Max. NAK wait time","acn.sdt.max_nak_wait_time",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT Max. NAK wait time ", HFILL }},

	{ &hf_acn_sdt_ack_threshold,
	    { "SDT ACK threshold","acn.sdt.ack_threshold",
		FT_UINT16, BASE_DEC, NULL, 0x0,
		"SDT ACK threshold", HFILL }},

	{ &hf_acn_sdt_member_cid,
	    { "SDT Memebr CID","acn.sdt.member_cid",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"SDT Member CID", HFILL }},

	{ &hf_acn_sdt_leader_cid,
	    { "SDT Leader CID","acn.sdt.leader_cid",
		FT_BYTES, BASE_HEX, NULL, 0x0,
		"SDT Leader CID", HFILL }}

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
