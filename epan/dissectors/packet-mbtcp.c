/* packet-mbtcp.c
 * Routines for Modbus/TCP and Modbus/UDP dissection
 * By Riaan Swart <rswart@cs.sun.ac.za>
 * Copyright 2001, Institute for Applied Computer Science
 * 					 University of Stellenbosch
 *
 * See
 *
 *	http://www.modbus.org/
 *
 * for information on Modbus/TCP.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

#define PORT_MBTCP		502	/* Modbus/TCP and Modbus/UDP located on port 502 */

/* Modbus protocol function codes */
#define READ_COILS		1
#define READ_INPUT_DISCRETES	2
#define READ_MULT_REGS		3
#define READ_INPUT_REGS		4
#define WRITE_COIL		5
#define WRITE_SINGLE_REG	6
#define READ_EXCEPT_STAT	7
#define DIAGNOSTICS		8
#define PROGRAM_484		9
#define POLL_484		10
#define GET_COMM_EVENT_CTRS	11
#define GET_COMM_EVENT_LOG	12
#define PROGRAM_584_984		13
#define POLL_584_984		14
#define FORCE_MULT_COILS	15
#define WRITE_MULT_REGS		16
#define REPORT_SLAVE_ID		17
#define PROGRAM_884_U84		18
#define RESET_COMM_LINK		19
#define READ_GENL_REF		20
#define WRITE_GENL_REF		21
#define MASK_WRITE_REG		22
#define READ_WRITE_REG		23
#define READ_FIFO_QUEUE		24
#define PROGRAM_CONCEPT		40
#define ENCAP_INTERFACE_TRANSP  43
#define FIRMWARE_REPLACE	125
#define PROGRAM_584_984_2	126
#define REPORT_LOCAL_ADDR_MB	127

/* Modbus protocol exception codes */
#define ILLEGAL_FUNCTION	0x01
#define ILLEGAL_ADDRESS		0x02
#define ILLEGAL_VALUE		0x03
#define ILLEGAL_RESPONSE	0x04
#define ACKNOWLEDGE		0x05
#define SLAVE_BUSY		0x06
#define NEGATIVE_ACK		0x07
#define MEMORY_ERR		0x08
#define GATEWAY_UNAVAILABLE	0x0a
#define GATEWAY_TRGT_FAIL	0x0b

/* return codes of function classifying packets as query/response */
#define QUERY_PACKET		0
#define RESPONSE_PACKET		1
#define CANNOT_CLASSIFY		2

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
static int hf_modbus_data = -1;

/* Initialize the subtree pointers */
static gint ett_mbtcp = -1;
static gint ett_modbus_hdr = -1;
static gint ett_group_hdr = -1;

static dissector_table_t mbtcp_dissector_table;

static int
classify_packet(packet_info *pinfo)
{
	/* see if nature of packets can be derived from src/dst ports */
	/* if so, return as found */
	if (( pinfo->srcport == PORT_MBTCP ) && ( pinfo->destport != PORT_MBTCP ))
		return RESPONSE_PACKET;
	if (( pinfo->srcport != PORT_MBTCP ) && ( pinfo->destport == PORT_MBTCP ))
		return QUERY_PACKET;

	/* else, cannot classify */
	return CANNOT_CLASSIFY;
}

/* Translate function to string, as given on p6 of
 * "Open Modbus/TCP Specification", release 1 by Andy Swales. */
static const value_string function_code_vals[] = {
	{ READ_COILS,			"Read coils" },
	{ READ_INPUT_DISCRETES,		"Read input discretes" },
	{ READ_MULT_REGS,		"Read multiple registers" },
	{ READ_INPUT_REGS,		"Read input registers" },
	{ WRITE_COIL,			"Write coil" },
	{ WRITE_SINGLE_REG,		"Write single register" },
	{ READ_EXCEPT_STAT,		"Read exception status" },
	{ DIAGNOSTICS,			"Diagnostics" },
	{ PROGRAM_484,			"Program (484)" },
	{ POLL_484,			"Poll (484)" },
	{ GET_COMM_EVENT_CTRS,		"Get Comm. Event Counters" },
	{ GET_COMM_EVENT_LOG,		"Get Comm. Event Log" },
	{ PROGRAM_584_984,		"Program (584/984)" },
	{ POLL_584_984,			"Poll (584/984)" },
	{ FORCE_MULT_COILS,		"Force Multiple Coils" },
	{ WRITE_MULT_REGS,		"Write Multiple Registers" },
	{ REPORT_SLAVE_ID,		"Report Slave ID" },
	{ PROGRAM_884_U84,		"Program 884/u84" },
	{ RESET_COMM_LINK,		"Reset Comm. Link (884/u84)" },
	{ READ_GENL_REF,		"Read General Reference" },
	{ WRITE_GENL_REF,		"Write General Reference" },
	{ MASK_WRITE_REG,		"Mask Write Register" },
	{ READ_WRITE_REG,		"Read Write Register" },
	{ READ_FIFO_QUEUE,		"Read FIFO Queue" },
	{ PROGRAM_CONCEPT,		"Program (ConCept)" },
	{ ENCAP_INTERFACE_TRANSP,	"Encapsulated Interface Transport" },
	{ FIRMWARE_REPLACE,		"Firmware replacement" },
	{ PROGRAM_584_984_2,		"Program (584/984)" },
	{ REPORT_LOCAL_ADDR_MB,		"Report local address (Modbus)" },
	{ 0,				NULL }
};

static const value_string exception_code_vals[] = {
	{ ILLEGAL_FUNCTION,	"Illegal function" },
	{ ILLEGAL_ADDRESS,	"Illegal data address" },
	{ ILLEGAL_VALUE,	"Illegal data value" },
	{ ILLEGAL_RESPONSE,	"Illegal response length" },
	{ ACKNOWLEDGE,		"Acknowledge" },
	{ SLAVE_BUSY,		"Slave device busy" },
	{ NEGATIVE_ACK,		"Negative acknowledge" },
	{ MEMORY_ERR,		"Memory parity error" },
	{ GATEWAY_UNAVAILABLE,	"Gateway path unavailable" },
	{ GATEWAY_TRGT_FAIL,	"Gateway target device failed to respond" },
	{ 0,			NULL }
};

/* Code to allow special handling of mbtcp data */
static void
dissect_mbtcp_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint8 function_code, gint payload_start, gint payload_len)
{
	gint reported_len;
	tvbuff_t *next_tvb;

	reported_len = tvb_reported_length_remaining(tvb, payload_start);

	if ( ( payload_start + payload_len ) > reported_len ) {
		proto_tree_add_bytes_format(tree, hf_modbus_data, tvb, payload_start, payload_len, NULL, "Data");
		return;
	}

	next_tvb = tvb_new_subset(tvb, payload_start, payload_len, reported_len);

	switch ( function_code ) {
		default:
			if ( ! dissector_try_string(mbtcp_dissector_table, "data", next_tvb, pinfo, tree) )
				proto_tree_add_bytes_format(tree, hf_modbus_data, tvb, payload_start, payload_len, NULL, "Data");
	}
}

/* Code to actually dissect the packets */
static int
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
	const char	*pkt_type_str = "";
	const char	*err_str = "";
	guint32		byte_cnt, group_byte_cnt, group_word_cnt;
	guint32		packet_num;	/* num to uniquely identify different mbtcp
					 * packets in one packet */
	guint8		exception_code;
	gboolean	exception_returned;
	guint8		fc;

	mh.transaction_id = tvb_get_ntohs(tvb, 0);
	mh.protocol_id = tvb_get_ntohs(tvb, 2);
	mh.len = tvb_get_ntohs(tvb, 4);
	mh.mdbs_hdr.unit_id = tvb_get_guint8(tvb, 6);
	mh.mdbs_hdr.function_code = tvb_get_guint8(tvb, 7);


	/* check that it actually looks like Modbus/TCP */
	/* protocol id == 0 */
	if( mh.protocol_id != 0 ){
		return 0;
	}
	/* length is at least 2 (unit_id + function_code) */
	if( mh.len < 2 ){
		return 0;
	}
	/* function code is in the set 1-24, 40, 125-127.
	 * Note that function code is only 7 bits.
	 */
	fc=mh.mdbs_hdr.function_code&0x7f;
	if(!match_strval(fc, function_code_vals))
		return 0;


	/* Make entries in Protocol column on summary display */
	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Modbus/TCP");

	col_clear(pinfo->cinfo, COL_INFO);


	/* Make entries in Info column on summary display */
	offset = 0;

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
			case QUERY_PACKET : 		pkt_type_str="query";
												break;
			case RESPONSE_PACKET : 	pkt_type_str="response";
												break;
			case CANNOT_CLASSIFY :		err_str="Unable to classify as query or response.";
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

			/* Add items to protocol tree specific to Modbus/TCP */
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_transid, tvb, offset, 2,
					mh.transaction_id);
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_protid, tvb, offset + 2, 2,
					mh.protocol_id);
			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_len, tvb, offset + 4, 2,
					mh.len);

			proto_tree_add_uint(mbtcp_tree, hf_mbtcp_unitid, tvb, offset + 6, 1,
					mh.mdbs_hdr.unit_id);


			/* Add items to protocol tree specific to Modbus generic */
			mf = proto_tree_add_text(mbtcp_tree, tvb, offset + 7, mh.len - 1,
					"Modbus");
	  		modbus_tree = proto_item_add_subtree(mf, ett_modbus_hdr);
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

					case READ_COILS:
					case READ_INPUT_DISCRETES:
						if (packet_type == QUERY_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_bitcnt, tvb, payload_start + 2, 2, FALSE);
						}
						else if (packet_type == RESPONSE_PACKET) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1, byte_cnt);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 1, byte_cnt);
						}
						break;

					case READ_MULT_REGS:
					case READ_INPUT_REGS:
						if (packet_type == QUERY_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, FALSE);
						}
						else if (packet_type == RESPONSE_PACKET) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1, byte_cnt);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 1, byte_cnt);
						}
						break;

					case WRITE_COIL:
						if (packet_type == QUERY_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 2, 1);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 3, 1, "Padding");
						}
						else if (packet_type == RESPONSE_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 2, 1);
							proto_tree_add_text(modbus_tree, tvb, payload_start + 3, 1, "Padding");
						}
						break;

					case WRITE_SINGLE_REG:
						if (packet_type == QUERY_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 2, 2);
						}
						else if (packet_type == RESPONSE_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 2, 2);
						}
						break;

					case READ_EXCEPT_STAT:
						if (packet_type == RESPONSE_PACKET)
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start, 1);
						break;

					case FORCE_MULT_COILS:
						if (packet_type == QUERY_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_bitcnt, tvb, payload_start + 2, 2, FALSE);
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 4);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 4, 1,
									byte_cnt);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 5, byte_cnt);
						}
						else if (packet_type == RESPONSE_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_bitcnt, tvb, payload_start + 2, 2, FALSE);
						}
						break;

					case WRITE_MULT_REGS:
						if (packet_type == QUERY_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, FALSE);
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 4);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 4, 1,
									byte_cnt);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 5, byte_cnt);
						}
						else if (packet_type == RESPONSE_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, FALSE);
						}
						break;

					case READ_GENL_REF:
						if (packet_type == QUERY_PACKET) {
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
						else if (packet_type == RESPONSE_PACKET) {
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
								dissect_mbtcp_data(tvb, pinfo, group_tree, mh.mdbs_hdr.function_code, group_offset + 2, group_byte_cnt - 1);
								group_offset += (group_byte_cnt + 1);
								byte_cnt -= (group_byte_cnt + 1);
								i++;
							}
						}
						break;

					case WRITE_GENL_REF:
						if ((packet_type == QUERY_PACKET) || (packet_type == RESPONSE_PACKET)) {
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
								dissect_mbtcp_data(tvb, pinfo, group_tree, mh.mdbs_hdr.function_code, group_offset + 7, group_byte_cnt - 7);
								group_offset += group_byte_cnt;
								byte_cnt -= group_byte_cnt;
								i++;
							}
						}
						break;

					case MASK_WRITE_REG:
						if ((packet_type == QUERY_PACKET) || (packet_type == RESPONSE_PACKET)) {
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_andmask, tvb, payload_start + 2, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_ormask, tvb, payload_start + 4, 2, FALSE);
						}
						break;

					case READ_WRITE_REG:
						if (packet_type == QUERY_PACKET) {
							proto_tree_add_item(modbus_tree, hf_modbus_readref, tvb, payload_start, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_readwordcnt, tvb, payload_start + 2, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_writeref, tvb, payload_start + 4, 2, FALSE);
							proto_tree_add_item(modbus_tree, hf_modbus_writewordcnt, tvb, payload_start + 6, 2, FALSE);
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start + 8);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start + 8, 1,
									byte_cnt);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 9, byte_cnt);
						}
						else if (packet_type == RESPONSE_PACKET) {
							byte_cnt = (guint32)tvb_get_guint8(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_bytecnt, tvb, payload_start, 1,
									byte_cnt);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 1, byte_cnt);
						}
						break;

					case READ_FIFO_QUEUE:
						if (packet_type == QUERY_PACKET)
							proto_tree_add_item(modbus_tree, hf_modbus_reference, tvb, payload_start, 2, FALSE);
						else if (packet_type == RESPONSE_PACKET) {
							byte_cnt = (guint32)tvb_get_ntohs(tvb, payload_start);
							proto_tree_add_uint(modbus_tree, hf_modbus_lbytecnt, tvb, payload_start, 2,
									byte_cnt);
							proto_tree_add_item(modbus_tree, hf_modbus_wordcnt, tvb, payload_start + 2, 2, FALSE);
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start + 4, byte_cnt - 2);
						}
						break;

					case DIAGNOSTICS:
					case PROGRAM_484:
					case POLL_484:
					case GET_COMM_EVENT_CTRS:
					case GET_COMM_EVENT_LOG:
					case PROGRAM_584_984:
					case POLL_584_984:
					case REPORT_SLAVE_ID:
					case PROGRAM_884_U84:
					case RESET_COMM_LINK:
					case PROGRAM_CONCEPT:
					case FIRMWARE_REPLACE:
					case PROGRAM_584_984_2:
					case REPORT_LOCAL_ADDR_MB:
						/* these function codes are not part of the Modbus/TCP specification */
					default:
						if (payload_len > 0)
							dissect_mbtcp_data(tvb, pinfo, modbus_tree, mh.mdbs_hdr.function_code, payload_start, payload_len);
						break;
				}
			}
		}

		/* move onto next packet (if there) */
		offset += packet_len;
		packet_num++;
		if (tvb_reported_length_remaining(tvb, offset) > 0) {

			/* load header structure for next packet */
			mh.transaction_id = tvb_get_ntohs(tvb, offset+0);
			mh.protocol_id = tvb_get_ntohs(tvb, offset+2);
			mh.len = tvb_get_ntohs(tvb, offset+4);
			mh.mdbs_hdr.unit_id = tvb_get_guint8(tvb, offset+6);
			mh.mdbs_hdr.function_code = tvb_get_guint8(tvb, offset+7);


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

	return tvb_length(tvb);
}


/* Register the protocol with Wireshark */

void
proto_register_modbus(void)
{

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		/* Modbus/TCP header fields */
		{ &hf_mbtcp_transid,
			{ "transaction identifier",			"modbus_tcp.trans_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_mbtcp_protid,
			{ "protocol identifier",			"modbus_tcp.prot_id",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_mbtcp_len,
			{ "length",					"modbus_tcp.len",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		/* Modbus header fields */
		{ &hf_mbtcp_unitid,
			{ "unit identifier",				"modbus_tcp.unit_id",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_mbtcp_functioncode,
			{ "function code",				"modbus_tcp.func_code",
			FT_UINT8, BASE_DEC, VALS(function_code_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_reference,
			{ "reference number",				"modbus_tcp.reference_num",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_lreference,
			{ "reference number (32 bit)",			"modbus_tcp.reference_num_32",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_reftype,
			{ "reference type",				"modbus_tcp.reference_type",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_readref,
			{ "read reference number",			"modbus_tcp.read_reference_num",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_writeref,
			{ "write reference number",			"modbus_tcp.write_reference_num",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_wordcnt,
			{ "word count",					"modbus_tcp.word_cnt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_readwordcnt,
			{ "read word count",				"modbus_tcp.read_word_cnt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_writewordcnt,
			{ "write word count",				"modbus_tcp.write_word_cnt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_bitcnt,
			{ "bit count",					"modbus_tcp.bit_cnt",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_bytecnt,
			{ "byte count",					"modbus_tcp.byte_cnt",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_lbytecnt,
			{ "byte count (16-bit)",			"modbus_tcp.byte_cnt_16",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_exceptioncode,
			{ "exception code",				"modbus_tcp.exception_code",
			FT_UINT8, BASE_DEC, VALS(exception_code_vals), 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_andmask,
			{ "AND mask",					"modbus_tcp.and_mask",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_ormask,
			{ "OR mask",					"modbus_tcp.or_mask",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_modbus_data,
			{ "Data",					"modbus_tcp.data",
		    FT_BYTES,  BASE_NONE, NULL,    0x0, NULL, HFILL }
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

       /* Registering protocol to be called by another dissector */
	new_register_dissector("mbtcp", dissect_mbtcp, proto_mbtcp);

	/* Registering subdissector table */
	mbtcp_dissector_table = register_dissector_table("mbtcp.data", "Modbus/TCP Data", FT_STRING, BASE_NONE);

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

	mbtcp_handle = new_create_dissector_handle(dissect_mbtcp, proto_mbtcp);
	dissector_add_uint("tcp.port", PORT_MBTCP, mbtcp_handle);
	dissector_add_uint("udp.port", PORT_MBTCP, mbtcp_handle);
}
