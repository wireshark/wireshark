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
 * $Id: packet-mbtcp.c,v 1.5 2001/09/14 07:10:05 guy Exp $
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

/*	TODO:
 *	Analysis of the payload of the Modbus packet.
 *		--	Based on the function code in the header, and the fact that the packet is 
 *			either a query or a response, the different fields in the payload can be 
 *			interpreted and displayed.
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

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif

#include "packet.h"

#define DEBUG  

#define TCP_PORT_MBTCP		502	/* Modbus/TCP located on TCP port 502 */

/* Modbus protocol function codes */
#define read_coils				1
#define read_input_discretes	2
#define read_mult_regs			3
#define read_input_regs			4
#define write_coil				5
#define write_single_reg		6
#define read_except_stat		7
#define diagnostics				8
#define program_484				9
#define poll_484					10
#define get_comm_event_ctrs	11
#define get_comm_event_log		12
#define program_584_984			13
#define poll_584_984				14
#define force_mult_coils		15
#define write_mult_regs			16
#define report_slave_id			17
#define program_884_u84			18
#define reset_comm_link			19
#define read_genl_ref			20
#define write_genl_ref			21
#define mask_write_reg			22
#define read_write_reg			23
#define read_fifo_queue			24
#define program_ConCept			40
#define firmware_replace		125
#define program_584_984_2		126
#define report_local_addr_mb	127

/* Modbus protocol exception codes */
#define illegal_function		0x01
#define illegal_address			0x02
#define illegal_value			0x03
#define illegal_response		0x04
#define acknowledge				0x05
#define slave_busy				0x06
#define negative_ack				0x07
#define memory_err				0x08
#define gateway_unavailable	0x0a
#define gateway_trgt_fail		0x0b

/* return codes of function classifying packets as query/response */
#define query_packet				0
#define response_packet			1
#define cannot_classify			2

/* Modbus header */
typedef struct _modbus_hdr {
	gchar		unit_id;			/* unit identifier (previously slave addr) */
	gchar		function_code; /* Modbus function code */
} modbus_hdr;

/* Modbus/TCP header, containing the Modbus header */
typedef struct _mbtcp_hdr {
	guint16		transaction_id;	/* copied by svr, usually 0 */
	guint16 		protocol_id;		/* always 0 */
	guint16		len;					/* len of data that follows */
	modbus_hdr	mdbs_hdr;			/* mdbus hdr directly after mdbs/tcp hdr *
											 * in packet */
} mbtcp_hdr;

/* Initialize the protocol and registered fields */
static int proto_mbtcp = -1;
static int hf_mbtcp_transid = -1;
static int hf_mbtcp_protid = -1;
static int hf_mbtcp_len = -1;
static int hf_mbtcp_unitid = -1;
static int hf_mbtcp_functioncode = -1;

/* Initialize the subtree pointers */
static gint ett_mbtcp = -1;
static gint ett_modbus_hdr = -1;
	
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

/* returns string describing function, as given on p6 of 
 * "Open Modbus/TCP Specification", release 1 by Andy Swales. */
static char *
function_string(guint16 func_code)
{
	switch ( func_code ) {
		case read_coils:				return "Read coils";								break;
		case read_input_discretes:	return "Read input discretes";				break;
		case read_mult_regs:			return "Read multiple registers";			break;
		case read_input_regs:		return "Read input registers";				break;
		case write_coil:				return "Write coil";								break;
		case write_single_reg:		return "Write single register";				break;
		case read_except_stat:		return "Read exception status";				break;
		case diagnostics:				return "Diagnostics";							break;
		case program_484:				return "Program (484)";							break;
		case poll_484:					return "Poll (484)";								break;
		case get_comm_event_ctrs:	return "Get Comm. Event Counters";			break;
		case get_comm_event_log:	return "Get Comm. Event Log";					break;
		case program_584_984:		return "Program (584/984)";					break;
		case poll_584_984:			return "Poll (584/984)";						break;
		case force_mult_coils:		return "Force Multiple Coils";				break;
		case write_mult_regs:		return "Write Multiple Registers";			break;
		case report_slave_id:		return "Report Slave ID";						break;
		case program_884_u84:		return "Program 884/u84";						break;
		case reset_comm_link:		return "Reset Comm. Link (884/u84)";		break;
		case read_genl_ref:			return "Read General Reference";				break;
		case write_genl_ref:			return "Write General Reference";			break;
		case mask_write_reg:			return "Mask Write Register";					break;
		case read_write_reg:			return "Read Write Register";					break;
		case read_fifo_queue:		return "Read FIFO Queue";						break;
		case program_ConCept:		return "Program (ConCept)";					break;
		case firmware_replace:		return "Firmware replacement";				break;
		case program_584_984_2:		return "Program (584/984)";					break;
		case report_local_addr_mb:	return "Report local address (Modbus)";	break;
		default:							return "Unknown function";						break;
	}
}
static char *
exception_string(guint8 exception_code)
{
	switch( exception_code ) {
		case illegal_function:		return "Illegal function";				break;
		case illegal_address:		return "Illegal data address";		break;
		case illegal_value:			return "Illegal data value";			break;
		case illegal_response:		return "Illegal response length";	break;
		case acknowledge:				return "Acknowledge";					break;
		case slave_busy:				return "Slave device busy";			break;
		case negative_ack:			return "Negative acknowledge";		break;
		case memory_err:				return "Memory parity error";			break;
		case gateway_unavailable:	return "Gateway path unavailable";	break;
		case gateway_trgt_fail:		return "Gateway target device failed to respond";	break;
		default:							return "Unknown exception code";		break;
	}
}

/* Code to actually dissect the packets */
static void
dissect_mbtcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
/* Set up structures needed to add the protocol subtree and manage it */
	mbtcp_hdr	mh;
	proto_item	*mi, *mf;
	proto_tree	*mbtcp_tree, *modbus_tree;
	int			offset = 0;
	gint			packet_end, packet_len;
	char			*func_string = "", pkt_type_str[9] = "";
	char			err_str[100] = "";
	int			packet_type;
	guint32		packet_num = 0;	/* num to uniquely identify different mbtcp 
												 * packets in one TCP packet */
	guint8		exception_code = 0, exception_returned = 0;
	
/* Make entries in Protocol column on summary display */
	if (check_col(pinfo->fd, COL_PROTOCOL)) 
		col_set_str(pinfo->fd, COL_PROTOCOL, "Modbus/TCP");

	if (check_col(pinfo->fd, COL_INFO))
		col_clear(pinfo->fd, COL_INFO);

/* Make entries in Info column on summary display (updated after building proto tree) */
	tvb_memcpy(tvb, (guint8 *)&mh, offset, sizeof(mbtcp_hdr));
	mh.transaction_id				=	ntohs(mh.transaction_id);
	mh.protocol_id					=	ntohs(mh.protocol_id);
	mh.len							=	ntohs(mh.len);
	if ( mh.mdbs_hdr.function_code & 0x80 ) {
		mh.mdbs_hdr.function_code ^= 0x80;
		exception_returned = 1;
	}
	func_string = function_string(mh.mdbs_hdr.function_code);
	if (check_col(pinfo->fd, COL_INFO))
	{
		packet_type = classify_packet(pinfo);
		switch ( packet_type ) {
			case query_packet : 			strcpy(pkt_type_str, "query");  
												break;
			case response_packet : 		strcpy(pkt_type_str, "response");  
												break;
			case cannot_classify :		strcpy(err_str, "Unable to classify as query or response.");
												strcpy(pkt_type_str, "unknown");
												break;
			default :
												break;
		}
		if ( exception_returned )
			strcpy(err_str, "Exception returned ");
		col_add_fstr(pinfo->fd, COL_INFO, 
				"%8s [%2u pkt(s)]: trans: %5u; unit: %3u, func: %3u: %s. %s", 
				pkt_type_str, 1, mh.transaction_id, (unsigned char) mh.mdbs_hdr.unit_id, 
				(unsigned char) mh.mdbs_hdr.function_code, func_string, err_str);
	}	

	/* build up protocol tree */
	do {
	/* Avoids alignment problems on many architectures. */
		tvb_memcpy(tvb, (guint8 *)&mh, offset, sizeof(mbtcp_hdr));
		mh.transaction_id				=	ntohs(mh.transaction_id);
		mh.protocol_id					=	ntohs(mh.protocol_id);
		mh.len							=	ntohs(mh.len);
			
		if ( mh.mdbs_hdr.function_code & 0x80 ) {
			tvb_memcpy(tvb, (guint8 *)&exception_code, offset + sizeof(mbtcp_hdr), 1);
			mh.mdbs_hdr.function_code ^= 0x80;
			exception_returned = 1;
		} else 
			exception_code = 0;
		
		packet_type = classify_packet(pinfo);
		
		/* if a tree exists, perform operations to add fields to it */
		if (tree) {
			packet_len = sizeof(mbtcp_hdr) - sizeof(modbus_hdr) + mh.len;
			mi = proto_tree_add_protocol_format(tree, proto_mbtcp, tvb, offset, 
					packet_len, "Modbus/TCP");
			mbtcp_tree = proto_item_add_subtree(mi, ett_mbtcp);
	
			/* Add items to protocol tree */
			/* Modbus/TCP */
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_transid, tvb, offset, 2, 
					mh.transaction_id);
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_protid, tvb, offset + 2, 2, 
					mh.protocol_id);
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_len, tvb, offset + 4, 2, 
					mh.len);
			/* Modbus */
			packet_end = mh.len;
			mf = proto_tree_add_text(mbtcp_tree, tvb, offset + 6, packet_end, 
					"Modbus");
	  		modbus_tree = proto_item_add_subtree(mf, ett_modbus_hdr);	
			proto_tree_add_item(modbus_tree, hf_mbtcp_unitid, tvb, offset + 6, 1, 
					mh.mdbs_hdr.unit_id);
			mi = proto_tree_add_item(modbus_tree, hf_mbtcp_functioncode, tvb, offset + 7, 1, 
					mh.mdbs_hdr.function_code);
			func_string = function_string(mh.mdbs_hdr.function_code);
			if ( 0 == exception_code ) 
				proto_item_set_text(mi, "function %u:  %s", mh.mdbs_hdr.function_code, 
						func_string);
			else  
				proto_item_set_text(mi, "function %u:  %s.  Exception: %s",	
						mh.mdbs_hdr.function_code, func_string, exception_string(exception_code)); 
			
			packet_end = mh.len - 2;
			proto_tree_add_text(modbus_tree, tvb, offset + 8, packet_end, 
					"Modbus data");
		}
		offset = offset + sizeof(mbtcp_hdr) + (mh.len - sizeof(modbus_hdr));
		packet_num++;
	} while ( tvb_reported_length_remaining(tvb, offset) > 0 );

	
/* Update entries in Info column on summary display */
	if (check_col(pinfo->fd, COL_INFO))
	{
		switch ( packet_type ) {
			case query_packet : 			strcpy(pkt_type_str, "query");  
												break;
			case response_packet : 		strcpy(pkt_type_str, "response");  
												break;
			case cannot_classify :		strcpy(err_str, "Unable to classify as query or response.");
												strcpy(pkt_type_str, "unknown");
												break;
			default :
												break;
		}
		if ( exception_returned )
			strcpy(err_str, "Exception returned ");
		col_add_fstr(pinfo->fd, COL_INFO, 
				"%8s [%2u pkt(s)]: trans: %5u; unit: %3u, func: %3u: %s. %s", 
				pkt_type_str, packet_num, mh.transaction_id, (unsigned char) mh.mdbs_hdr.unit_id, 
				(unsigned char) mh.mdbs_hdr.function_code, func_string, err_str); 
	}

/* If this protocol has a sub-dissector call it here, see section 1.8 */
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_modbus(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		/* Modbus/TCP header fields */
		{ &hf_mbtcp_transid,
			{ "transaction identifier",           "modbus_tcp.trans_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_mbtcp_protid,
			{ "protocol identifier",           "modbus_tcp.prot_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_mbtcp_len,
			{ "length",           "modbus_tcp.len",
			FT_UINT16, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		/* Modbus header fields */
		{ &hf_mbtcp_unitid,
			{ "unit identifier",           "modbus_tcp.unit_id",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		},
		{ &hf_mbtcp_functioncode,
			{ "function code ",           "modbus_tcp.func_code",
			FT_UINT8, BASE_DEC, NULL, 0x0,          
			"", HFILL }
		}
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_mbtcp,
		&ett_modbus_hdr
	};

/* Register the protocol name and description */
	proto_mbtcp = proto_register_protocol("Modbus/TCP",
	    "Modbus/TCP", "mbtcp");

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
	dissector_add("tcp.port", TCP_PORT_MBTCP, dissect_mbtcp, proto_mbtcp);
}
