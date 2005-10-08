/* packet-mbtcp.c
 * Routines for Modbus/TCP dissection
 * By Riaan Swart <rswart@cs.sun.ac.za>
 * Copyright 2001, Institute for Applied Computer Science
 * 					 University of Stellenbosch
 *
 * See
 *
 *	http://www.modicon.com/openmbus/
 *
 * for information on Modbus/TCP.
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>

#define DEBUG

#define TCP_PORT_MBTCP		502	/* Modbus/TCP located on TCP port 502 */

/* Modbus protocol function codes */
#define read_coils		1
#define read_input_discretes	2
#define read_mult_regs		3
#define read_input_regs		4
#define write_coil		5
#define write_single_reg	6
#define read_except_stat	7
#define diagnostics		8
#define program_484		9
#define poll_484		10
#define get_comm_event_ctrs	11
#define get_comm_event_log	12
#define program_584_984		13
#define poll_584_984		14
#define force_mult_coils	15
#define write_mult_regs		16
#define report_slave_id		17
#define program_884_u84		18
#define reset_comm_link		19
#define read_genl_ref		20
#define write_genl_ref		21
#define mask_write_reg		22
#define read_write_reg		23
#define read_fifo_queue		24
#define program_ConCept		40
#define firmware_replace	125
#define program_584_984_2	126
#define report_local_addr_mb	127

/* Modbus protocol exception codes */
#define illegal_function	0x01
#define illegal_address		0x02
#define illegal_value		0x03
#define illegal_response	0x04
#define acknowledge		0x05
#define slave_busy		0x06
#define negative_ack		0x07
#define memory_err		0x08
#define gateway_unavailable	0x0a
#define gateway_trgt_fail	0x0b

/* return codes of function classifying packets as query/response */
#define query_packet		0
#define response_packet		1
#define cannot_classify		2

/* Modbus header */
typedef struct _modbus_hdr {
	guint8	unit_id;	/* unit identifier (previously slave addr) */
	guint8	function_code; 	/* Modbus function code */
} modbus_hdr;

/* Modbus/TCP header, containing the Modbus header */
typedef struct _mbtcp_hdr {
	guint16		transaction_id;		/* copied by svr, usually 0 */
	guint16 	protocol_id;		/* always 0 */
	guint16		len;			/* len of data that follows */
	modbus_hdr	mdbs_hdr;		/* mdbus hdr directly after mdbs/tcp hdr *
						 * in packet */
} mbtcp_hdr;

/* Initialize the protocol and registered fields */
static int proto_mbtcp = -1;
static int hf_mbtcp_transid = -1;
static int hf_mbtcp_protid = -1;
static int hf_mbtcp_len = -1;
static int hf_mbtcp_unitid = -1;
static int hf_mbtcp_functioncode = -1;
static int hf_modbus_reference = -1;
static int hf_modbus_lreference = -1;
static int hf_modbus_reftype = -1;
static int hf_modbus_readref = -1;
static int hf_modbus_writeref = -1;
static int hf_modbus_wordcnt = -1;
static int hf_modbus_readwordcnt = -1;
static int hf_modbus_writewordcnt = -1;
static int hf_modbus_bytecnt = -1;
static int hf_modbus_lbytecnt = -1;
static int hf_modbus_bitcnt = -1;
static int hf_modbus_exceptioncode = -1;
static int hf_modbus_andmask = -1;
static int hf_modbus_ormask = -1;

/* Initialize the subtree pointers */
static gint ett_mbtcp = -1;
static gint ett_modbus_hdr = -1;
static gint ett_group_hdr = -1;

static int
classify_packet(packet_info *pinfo)
{
	/* see if nature of packets can be derived from src/dst ports */
	/* if so, return as found */
	if ( ( 502 == pinfo->srcport && 502 != pinfo->destport ) ||
		 ( 502 != pinfo->srcport && 502 == pinfo->destport ) ) {
		/* the slave is receiving queries on port 502 */
		if ( 502 == pinfo->srcport )
			return response_packet;
		else if ( 502 == pinfo->destport )
			return query_packet;
	}
	/* else, cannot classify */
	return cannot_classify;
}

/* Translate function to string, as given on p6 of
 * "Open Modbus/TCP Specification", release 1 by Andy Swales. */
static const value_string function_code_vals[] = {
	{ read_coils,			"Read coils" },
	{ read_input_discretes,		"Read input discretes" },
	{ read_mult_regs,		"Read multiple registers" },
	{ read_input_regs,		"Read input registers" },
	{ write_coil,			"Write coil" },
	{ write_single_reg,		"Write single register" },
	{ read_except_stat,		"Read exception status" },
	{ diagnostics,			"Diagnostics" },
	{ program_484,			"Program (484)" },
	{ poll_484,			"Poll (484)" },
	{ get_comm_event_ctrs,		"Get Comm. Event Counters" },
	{ get_comm_event_log,		"Get Comm. Event Log" },
	{ program_584_984,		"Program (584/984)" },
	{ poll_584_984,			"Poll (584/984)" },
	{ force_mult_coils,		"Force Multiple Coils" },
	{ write_mult_regs,		"Write Multiple Registers" },
	{ report_slave_id,		"Report Slave ID" },
	{ program_884_u84,		"Program 884/u84" },
	{ reset_comm_link,		"Reset Comm. Link (884/u84)" },
	{ read_genl_ref,		"Read General Reference" },
	{ write_genl_ref,		"Write General Reference" },
	{ mask_write_reg,		"Mask Write Register" },
	{ read_write_reg,		"Read Write Register" },
	{ read_fifo_queue,		"Read FIFO Queue" },
	{ program_ConCept,		"Program (ConCept)" },
	{ firmware_replace,		"Firmware replacement" },
	{ program_584_984_2,		"Program (584/984)" },
	{ report_local_addr_mb,		"Report local address (Modbus)" },
	{ 0,				NULL }
};

static const value_string exception_code_vals[] = {
	{ illegal_function,	"Illegal function" },
	{ illegal_address,	"Illegal data address" },
	{ illegal_value,	"Illegal data value" },
	{ illegal_response,	"Illegal response length" },
	{ acknowledge,		"Acknowledge" },
	{ slave_busy,		"Slave device busy" },
	{ negative_ack,		"Negative acknowledge" },
	{ memory_err,		"Memory parity error" },
	{ gateway_unavailable,	"Gateway path unavailable" },
	{ gateway_trgt_fail,	"Gateway target device failed to respond" },
	{ 0,			NULL }
};

/* Code to actually dissect the packets */
static void
dissect_mbtcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Set up structures needed to add the protocol subtree and manage it */
	mbtcp_hdr	mh;
	proto_item	*mi, *mf;
	proto_tree	*mbtcp_tree, *modbus_tree, *group_tree;
	int		offset, group_offset, packet_type;
	guint		i;
	gint		packet_len, payload_start, payload_len;
	const char	*func_string = "";
	char		*pkt_type_str = "";
	char		*err_str = "";
	guint32		byte_cnt, group_byte_cnt, group_word_cnt;
	guint32		packet_num;	/* num to uniquely identify different mbtcp
					 * packets in one TCP packet */
	guint8		exception_code;
	gboolean	exception_returned;

/* Make entries in Protocol column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Modbus/TCP");

	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

/* Make entries in Info column on summary display */
	offset = 0;
	tvb_memcpy(tvb, (guint8 *)&mh, offset, sizeof(mbtcp_hdr));
	mh.transaction_id				=	g_ntohs(mh.transaction_id);
	mh.protocol_id					=	g_ntohs(mh.protocol_id);
	mh.len							=	g_ntohs(mh.len);
	if ( mh.mdbs_hdr.function_code & 0x80 ) {
		exception_code = tvb_get_guint8(tvb, offset + sizeof(mbtcp_hdr));
		mh.mdbs_hdr.function_code ^= 0x80;
		exception_returned = TRUE;
	}
	else {
		exception_code = 0;
		exception_returned = FALSE;
	}
	func_string = val_to_str(mh.mdbs_hdr.function_code, function_code_vals,
	    "Unknown function (%u)");
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		packet_type = classify_packet(pinfo);
		switch ( packet_type ) {
			case query_packet : 		pkt_type_str="query";
												break;
			case response_packet : 	pkt_type_str="response";
												break;
			case cannot_classify :		err_str="Unable to classify as query or response.";
										pkt_type_str="unknown";
												break;
			default :
												break;
		}
		if ( exception_returned )
			err_str="Exception returned ";
		col_add_fstr(pinfo->cinfo, COL_INFO,
				"%8s [%2u pkt(s)]: trans: %5u; unit: %3u, func: %3u: %s. %s",
				pkt_type_str, 1, mh.transaction_id, (unsigned char) mh.mdbs_hdr.unit_id,
				(unsigned char) mh.mdbs_hdr.function_code, func_string, err_str);
	}

	/* build up protocol tree and iterate over multiple packets */
	packet_num = 0;
	while (1) {
		packet_type = classify_packet(pinfo);
		packet_len = sizeof(mbtcp_hdr) - sizeof(modbus_hdr) + mh.len;

		/* if a tree exists, perform operations to add fields to it */
		if (tree) {
			mi = proto_tree_add_protocol_format(tree, proto_mbtcp, tvb, offset,
					packet_len, "Modbus/TCP");
			mbtcp_tree = proto_item_add_subtree(mi, ett_mbtcp);

			/* Add items to protocol tree specific to Modbus/TCP Modbus/TCP */
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_transid, tvb, offset, 2,
					mh.transaction_id);
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_protid, tvb, offset + 2, 2,
					mh.protocol_id);
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_len, tvb, offset + 4, 2,
					mh.len);
					
			/* Add items to protocol tree specific to Modbus generic */
			mf = proto_tree_add_text(mbtcp_tree, tvb, offset + 6, mh.len,
					"Modbus");
	  		modbus_tree = proto_item_add_subtree(mf, ett_modbus_hdr);
			proto_tree_add_uint(modbus_tree, hf_mbtcp_unitid, tvb, offset + 6, 1,
					mh.mdbs_hdr.unit_id);
			mi = proto_tree_add_uint(modbus_tree, hf_mbtcp_functioncode, tvb, offset + 7, 1,
					mh.mdbs_hdr.function_code);
					
			/** detail payload as a function of exception/function code */
			func_string = val_to_str(mh.mdbs_hdr.function_code,
			    function_code_vals, "Unknown function");
			payload_start = offset + 8;
			payload_len = mh.len - sizeof(modbus_hdr);
			if (exception_returned) {
				proto_item_set_text(mi, "function %u:  %s.  Exception: %s",
						mh.mdbs_hdr.function_code,
						func_string,
						val_to_str(exception_code,
						    exception_code_vals,
						    "Unknown exception code (%u)"));
				proto_tree_add_uint(modbus_tree, hf_modbus_exceptioncode, tvb, payload_start, 1,
						exception_code);
			}
			else {
				proto_item_set_text(mi, "function %u:  %s", mh.mdbs_hdr.function_code,
						func_string);
				switch (mh.mdbs_hdr.function_code) {
					
					case read_coils:			
					case read_input_discretes:	
						if (packet_type == query_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_bitcnt, tvb, payload_start + 2, 2, FALSE);
						}
						else if (packet_type == response_packet) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1, byte_cnt);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 1, byte_cnt, "Data");
						}
						break;
						
					case read_mult_regs:		
					case read_input_regs:		
						if (packet_type == query_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, FALSE);
						}
						else if (packet_type == response_packet) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1, byte_cnt);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 1, byte_cnt, "Data");
						}
						break;
						
					case write_coil:			
						if (packet_type == query_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 2, 1, "Data");
							proto_tree_add_text(modbus_tree, tvb, payload_start + 3, 1, "Padding");
						}
						else if (packet_type == response_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 2, 1, "Data");
							proto_tree_add_text(modbus_tree, tvb, payload_start + 3, 1, "Padding");
						}
						break;
						
					case write_single_reg:		
						if (packet_type == query_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 2, 2, "Data");
						}
						else if (packet_type == response_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 2, 2, "Data");
						}
						break;
						
					case read_except_stat:		
						if (packet_type == response_packet)
							proto_tree_add_text(modbus_tree, tvb, payload_start, 1, "Data");
						break;
						
					case force_mult_coils:		
						if (packet_type == query_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_bitcnt, tvb, payload_start + 2, 2, FALSE);
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 4);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 4, 1,
									byte_cnt);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 5, byte_cnt, "Data");
						}
						else if (packet_type == response_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_bitcnt, tvb, payload_start + 2, 2, FALSE);
						}
						break;
						
					case write_mult_regs:		
						if (packet_type == query_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, FALSE);
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 4);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 4, 1,
									byte_cnt);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 5, byte_cnt, "Data");
						}
						else if (packet_type == response_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, FALSE);
						}
						break;
						
					case read_genl_ref:			
						if (packet_type == query_packet) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1,
									byte_cnt);
									
							/* add subtrees to describe each group of packet */
							group_offset = payload_start + 1;
							for (i = 0; i < byte_cnt / 7; i++) {
								mi = proto_tree_add_text( modbus_tree, tvb, group_offset, 7,
										"Group %u", i);
						  		group_tree = proto_item_add_subtree(mi, ett_group_hdr);
								proto_tree_add_item(group_tree, hf_modbus_reftype, tvb, group_offset, 1, FALSE);
								proto_tree_add_item(group_tree, hf_modbus_lreference, tvb, group_offset + 1, 4, FALSE);
								proto_tree_add_item(group_tree, hf_modbus_wordcnt, tvb, group_offset + 5, 2, FALSE);
								group_offset += 7;
							}
						}
						else if (packet_type == response_packet) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1,
									byte_cnt);
									
							/* add subtrees to describe each group of packet */
							group_offset = payload_start + 1;
							i = 0;
							while (byte_cnt > 0) {
								group_byte_cnt = (guint32)tvb_get_guint8(tvb, group_offset);
								mi = proto_tree_add_text( modbus_tree, tvb, group_offset, group_byte_cnt + 1,
										"Group %u", i);
						  		group_tree = proto_item_add_subtree(mi, ett_group_hdr);
								proto_tree_add_uint(group_tree, hf_modbus_bytecnt, tvb, group_offset, 1,
										group_byte_cnt);
								proto_tree_add_item(group_tree, hf_modbus_reftype, tvb, group_offset + 1, 1, FALSE);
								proto_tree_add_text(group_tree, tvb, group_offset + 2, group_byte_cnt - 1, "Data");
								group_offset += (group_byte_cnt + 1);
								byte_cnt -= (group_byte_cnt + 1);
								i++;
							}
						}
						break;
						
					case write_genl_ref:		
						if ((packet_type == query_packet) || (packet_type == response_packet)) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1,
									byte_cnt);
									
							/* add subtrees to describe each group of packet */
							group_offset = payload_start + 1;
							i = 0;
							while (byte_cnt > 0) {
								group_word_cnt = tvb_get_ntohs(tvb, group_offset + 5);
								group_byte_cnt = (2 * group_word_cnt) + 7;
								mi = proto_tree_add_text( modbus_tree, tvb, group_offset, 
										group_byte_cnt, "Group %u", i);
						  		group_tree = proto_item_add_subtree(mi, ett_group_hdr);
								proto_tree_add_item(group_tree, hf_modbus_reftype, tvb, group_offset, 1, FALSE);
								proto_tree_add_item(group_tree, hf_modbus_lreference, tvb, group_offset + 1, 4, FALSE);
								proto_tree_add_uint(group_tree, hf_modbus_wordcnt, tvb, group_offset + 5, 2, 
										group_word_cnt);
								proto_tree_add_text(group_tree, tvb, group_offset + 7, group_byte_cnt - 7, "Data");
								group_offset += group_byte_cnt;
								byte_cnt -= group_byte_cnt;
								i++;
							}
						}
						break;
						
					case mask_write_reg:		
						if ((packet_type == query_packet) || (packet_type == response_packet)) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_andmask, tvb, payload_start + 2, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_ormask, tvb, payload_start + 4, 2, FALSE);
						}
						break;
						
					case read_write_reg:		
						if (packet_type == query_packet) {
							proto_tree_add_item(modbus_tree, hf_modbus_readref, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_readwordcnt, tvb, payload_start + 2, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_writeref, tvb, payload_start + 4, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_writewordcnt, tvb, payload_start + 6, 2, FALSE);
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 8);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 8, 1,
									byte_cnt);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 9, byte_cnt, "Data");
						}
						else if (packet_type == response_packet) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1,
									byte_cnt);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 1, byte_cnt, "Data");
						}
						break;
						
					case read_fifo_queue:		
						if (packet_type == query_packet)
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
						else if (packet_type == response_packet) {
							byte_cnt = (guint32)tvb_get_ntohs(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_lbytecnt, tvb, payload_start, 2,
									byte_cnt);
							proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, FALSE);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 4, byte_cnt - 2, "Data");
						}
						break;
						
					case diagnostics:			
					case program_484:			
					case poll_484:				
					case get_comm_event_ctrs:	
					case get_comm_event_log:	
					case program_584_984:		
					case poll_584_984:			
					case report_slave_id:		
					case program_884_u84:		
					case reset_comm_link:		
					case program_ConCept:		
					case firmware_replace:		
					case program_584_984_2:		
					case report_local_addr_mb:	
						/* these function codes are not part of the Modbus/TCP specification */
					default:					
						if (payload_len > 0)
							proto_tree_add_text(modbus_tree, tvb, payload_start, payload_len, "Data");
						break;
				}
			}
		}
		
		/* move onto next packet (if there) */
		offset += packet_len;
		packet_num++;
		if (tvb_reported_length_remaining(tvb, offset) > 0) {
			
			/* load header structure for next packet */
			tvb_memcpy(tvb, (guint8 *)&mh, offset, sizeof(mbtcp_hdr));
			mh.transaction_id				=	g_ntohs(mh.transaction_id);
			mh.protocol_id					=	g_ntohs(mh.protocol_id);
			mh.len							=	g_ntohs(mh.len);
	
			if ( mh.mdbs_hdr.function_code & 0x80 ) {
				exception_code = tvb_get_guint8(tvb, offset + sizeof(mbtcp_hdr));
				mh.mdbs_hdr.function_code ^= 0x80;
				exception_returned = TRUE;
			} else
				exception_returned = FALSE;
		}
		else
			break;
	}
}


/* Register the protocol with Ethereal */

void
proto_register_modbus(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		/* Modbus/TCP header fields */
		{ &hf_mbtcp_transid,
			{ "transaction identifier",			"modbus_tcp.trans_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_mbtcp_protid,
			{ "protocol identifier",			"modbus_tcp.prot_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_mbtcp_len,
			{ "length",							"modbus_tcp.len",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		/* Modbus header fields */
		{ &hf_mbtcp_unitid,
			{ "unit identifier",           		"modbus_tcp.unit_id",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_mbtcp_functioncode,
			{ "function code",            		"modbus_tcp.func_code",
			FT_UINT8, BASE_DEC, VALS(function_code_vals), 0x0,
			"", HFILL }
		},
		{ &hf_modbus_reference,
			{ "reference number",            	"modbus_tcp.reference_num",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_lreference,
			{ "reference number (32 bit)",   	"modbus_tcp.reference_num_32",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_reftype,
			{ "reference type",   				"modbus_tcp.reference_type",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_readref,
			{ "read reference number",   		"modbus_tcp.read_reference_num",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_writeref,
			{ "write reference number",   		"modbus_tcp.write_reference_num",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_wordcnt,
			{ "word count",            			"modbus_tcp.word_cnt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_readwordcnt,
			{ "read word count",       			"modbus_tcp.read_word_cnt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_writewordcnt,
			{ "write word count",       		"modbus_tcp.write_word_cnt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_bitcnt,
			{ "bit count",            			"modbus_tcp.bit_cnt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_bytecnt,
			{ "byte count",            			"modbus_tcp.byte_cnt",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_lbytecnt,
			{ "byte count (16-bit)",   			"modbus_tcp.byte_cnt_16",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_exceptioncode,
			{ "exception code",            		"modbus_tcp.exception_code",
			FT_UINT8, BASE_DEC, VALS(exception_code_vals), 0x0,
			"", HFILL }
		},
		{ &hf_modbus_andmask,
			{ "AND mask",            			"modbus_tcp.and_mask",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }
		},
		{ &hf_modbus_ormask,
			{ "OR mask",            			"modbus_tcp.or_mask",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			"", HFILL }
		}
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mbtcp,
		&ett_modbus_hdr,
		&ett_group_hdr
	};

	/* Register the protocol name and description */
	proto_mbtcp = proto_register_protocol("Modbus/TCP", "Modbus/TCP", "mbtcp");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_mbtcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
 */
void
proto_reg_handoff_mbtcp(void)
{
	dissector_handle_t mbtcp_handle;

	mbtcp_handle = create_dissector_handle(dissect_mbtcp, proto_mbtcp);
	dissector_add("tcp.port", TCP_PORT_MBTCP, mbtcp_handle);
}
