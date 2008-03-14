/* packet-infiniband.h
 * Routines for Infiniband/ERF Dissection
 *
 * Copyright 2008 Endace Technology Limited
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
#ifndef __PACKET_INFINIBAND_H_
#define __PACKET_INFINIBAND_H_

#define PROTO_TAG_INFINIBAND	"Infiniband"

/* Wireshark ID */
static int proto_infiniband = -1;
/*static int hf_infiniband_pdu_type = -1; unnecessary for now */
static gint ett_infiniband = -1;


/* Dissector Declarations */
static dissector_handle_t infiniband_handle;
void proto_register_infiniband(void);
void proto_reg_handoff_infiniband(void);
static void dissect_infiniband(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static gint32 find_next_header_sequence(guint32 OpCode);
static gboolean contains(guint32 value, guint32* arr, int length);

/* Parsing Methods for specific IB headers. */

static void parse_VENDOR(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);
static void  parse_PAYLOAD(proto_tree * parentTree, tvbuff_t *tvb, gint *offset, gint length);
static void parse_IETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);
static void parse_IMMDT(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);
static void parse_ATOMICACKETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);
static void parse_AETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);
static void parse_ATOMICETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);
static void parse_RETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);
static void parse_DETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);
static void parse_RDETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset);

/* These are not currently used, but in the future */
/* can be expanded and used to provide better visualization in Wireshark. */
static const value_string packettypenames[] = 
{
	{ 4, "Local" },
	{ 3, "Global" },
	{ 2, "Raw (Raw Header)" },
	{ 1, "Raw (IPv6 Header)"},
	{ 0, NULL}
};

/* Just a map so we can display a value for FT_BOOLEAN types */

static const value_string IB_Boolean[] = {
  { 0, " 0 " },
  { 1, " 1 " },
  { 2, NULL }
};
	
/* Local Route Header (LRH) */
static int hf_infiniband_LRH = -1;
static int hf_infiniband_virtual_lane = -1;
static int hf_infiniband_link_version = -1;
static int hf_infiniband_service_level = -1;
static int hf_infiniband_reserved2 = -1;
static int hf_infiniband_link_next_header = -1;
static int hf_infiniband_destination_local_id = -1;
static int hf_infiniband_reserved5 = -1;
static int hf_infiniband_packet_length = -1;
static int hf_infiniband_source_local_id = -1;	
/* Global Route Header (GRH) */
static int hf_infiniband_GRH = -1;
static int hf_infiniband_ip_version = -1;
static int hf_infiniband_traffic_class = -1;
static int hf_infiniband_flow_label = -1;
static int hf_infiniband_payload_length = -1;
static int hf_infiniband_next_header = -1;
static int hf_infiniband_hop_limit = -1;
static int hf_infiniband_source_gid = -1;
static int hf_infiniband_destination_gid = -1;	
/* Base Transport Header (BTH) */
static int hf_infiniband_BTH = -1;
static int hf_infiniband_opcode = -1;
static int hf_infiniband_solicited_event = -1;
static int hf_infiniband_migreq = -1;
static int hf_infiniband_pad_count = -1;
static int hf_infiniband_transport_header_version = -1;
static int hf_infiniband_partition_key = -1;
static int hf_infiniband_reserved8 = -1;
static int hf_infiniband_destination_qp = -1;
static int hf_infiniband_acknowledge_request = -1;
static int hf_infiniband_reserved7 = -1;
static int hf_infiniband_packet_sequence_number = -1;	
/* Reliable Datagram Extended Transport Header (RDETH) */
static int hf_infiniband_RDETH = -1;
static int hf_infiniband_reserved8_RDETH = -1;
static int hf_infiniband_ee_context = -1;
/* Datagram Extended Transport Header (DETH) */
static int hf_infiniband_DETH = -1;
static int hf_infiniband_queue_key = -1;
static int hf_infiniband_reserved8_DETH = -1;
static int hf_infiniband_source_qp = -1;	
/* RDMA Extended Transport Header (RETH) */
static int hf_infiniband_RETH = -1;
static int hf_infiniband_virtual_address = -1;
static int hf_infiniband_remote_key = -1;
static int hf_infiniband_dma_length = -1;	
/* Atomic Extended Transport Header (AtomicETH) */
static int hf_infiniband_AtomicETH = -1;
static int hf_infiniband_virtual_address_AtomicETH = -1;
static int hf_infiniband_remote_key_AtomicETH = -1;
static int hf_infiniband_swap_or_add_data = -1;
static int hf_infiniband_compare_data = -1;	
/* ACK Extended Transport Header (AETH) */
static int hf_infiniband_AETH = -1;
static int hf_infiniband_syndrome = -1;
static int hf_infiniband_message_sequence_number = -1;
/* Atomic ACK Extended Transport Header (AtomicAckETH) */
static int hf_infiniband_AtomicAckETH = -1;
static int hf_infiniband_original_remote_data = -1;
/* Immediate Extended Transport Header (ImmDt) */
static int hf_infiniband_IMMDT = -1;
/* Invalidate Extended Transport Header (IETH) */
static int hf_infiniband_IETH = -1;
/* Payload */
static int hf_infiniband_payload = -1;
static int hf_infiniband_invariant_crc = -1;
static int hf_infiniband_variant_crc = -1;
/* Unknown or Vendor Specific */
static int hf_infiniband_raw_data = -1;
static int hf_infiniband_vendor = -1;



/* Link Next Header Values */
#define IBA_GLOBAL 3
#define IBA_LOCAL  2
#define IP_NON_IBA 1
#define RAW        0

/* OpCodeValues */
/* Code Bits [7-5] Connection Type  */
/*           [4-0] Message Type */

/* Reliable Connection (RC) */
/* [7-5] = 000 */
#define RC_SEND_FIRST					0 /*0x00000000 */
#define RC_SEND_MIDDLE					1 /*0x00000001 */
#define RC_SEND_LAST					2 /*0x00000010 */
#define RC_SEND_LAST_IMM				3 /*0x00000011 */
#define RC_SEND_ONLY					4 /*0x00000100 */
#define RC_SEND_ONLY_IMM				5 /*0x00000101 */
#define RC_RDMA_WRITE_FIRST				6 /*0x00000110 */
#define RC_RDMA_WRITE_MIDDLE			7 /*0x00000111 */
#define RC_RDMA_WRITE_LAST				8 /*0x00001000 */
#define RC_RDMA_WRITE_LAST_IMM			9 /*0x00001001 */
#define RC_RDMA_WRITE_ONLY				10 /*0x00001010 */
#define RC_RDMA_WRITE_ONLY_IMM			11 /*0x00001011 */
#define RC_RDMA_READ_REQUEST			12 /*0x00001100 */
#define RC_RDMA_READ_RESPONSE_FIRST		13 /*0x00001101 */
#define RC_RDMA_READ_RESPONSE_MIDDLE	14 /*0x00001110 */
#define RC_RDMA_READ_RESPONSE_LAST		15 /*0x00001111 */
#define RC_RDMA_READ_RESPONSE_ONLY		16 /*0x00010000 */
#define RC_ACKNOWLEDGE					17 /*0x00010001 */
#define RC_ATOMIC_ACKNOWLEDGE			18 /*0x00010010 */
#define RC_CMP_SWAP						19 /*0x00010011 */
#define RC_FETCH_ADD					20 /*0x00010100 */
#define RC_SEND_LAST_INVAL				22 /*0x00010110 */
#define RC_SEND_ONLY_INVAL				23 /*0x00010111 */

/* Reliable Datagram (RD) */
/* [7-5] = 010 */
#define RD_SEND_FIRST					64 /*0x01000000 */
#define RD_SEND_MIDDLE					65 /*0x01000001 */
#define RD_SEND_LAST					66 /*0x01000010 */
#define RD_SEND_LAST_IMM				67 /*0x01000011 */
#define RD_SEND_ONLY					68 /*0x01000100 */
#define RD_SEND_ONLY_IMM				69 /*0x01000101 */
#define RD_RDMA_WRITE_FIRST				70 /*0x01000110 */
#define RD_RDMA_WRITE_MIDDLE			71 /*0x01000111 */
#define RD_RDMA_WRITE_LAST				72 /*0x01001000 */
#define RD_RDMA_WRITE_LAST_IMM			73 /*0x01001001 */
#define RD_RDMA_WRITE_ONLY				74 /*0x01001010 */
#define RD_RDMA_WRITE_ONLY_IMM			75 /*0x01001011 */
#define RD_RDMA_READ_REQUEST			76 /*0x01001100 */
#define RD_RDMA_READ_RESPONSE_FIRST		77 /*0x01001101 */
#define RD_RDMA_READ_RESPONSE_MIDDLE	78 /*0x01001110 */
#define RD_RDMA_READ_RESPONSE_LAST		79 /*0x01001111 */
#define RD_RDMA_READ_RESPONSE_ONLY		80 /*0x01010000 */
#define RD_ACKNOWLEDGE					81 /*0x01010001 */
#define RD_ATOMIC_ACKNOWLEDGE			82 /*0x01010010 */
#define RD_CMP_SWAP						83 /*0x01010011 */
#define RD_FETCH_ADD					84 /*0x01010100 */
#define RD_RESYNC						85 /*0x01010101 */

/* Unreliable Datagram (UD) */
/* [7-5] = 011 */
#define UD_SEND_ONLY					100 /*0x01100100 */
#define UD_SEND_ONLY_IMM				101 /*0x01100101 */

/* Unreliable Connection (UC) */
/* [7-5] = 001 */
#define UC_SEND_FIRST					32 /*0x00100000 */
#define UC_SEND_MIDDLE					33 /*0x00100001 */
#define UC_SEND_LAST					34 /*0x00100010 */
#define UC_SEND_LAST_IMM				35 /*0x00100011 */
#define UC_SEND_ONLY					36 /*0x00100100 */
#define UC_SEND_ONLY_IMM				37 /*0x00100101 */
#define UC_RDMA_WRITE_FIRST				38 /*0x00100110 */
#define UC_RDMA_WRITE_MIDDLE			39 /*0x00100111 */
#define UC_RDMA_WRITE_LAST				40 /*0x00101000 */
#define UC_RDMA_WRITE_LAST_IMM			41 /*0x00101001 */
#define UC_RDMA_WRITE_ONLY				42 /*0x00101010 */
#define UC_RDMA_WRITE_ONLY_IMM			43 /*0x00101011 */

static value_string OpCodeMap[] =
{
	{ RC_SEND_FIRST, "Reliable Connection Send First" },
	{ RC_SEND_MIDDLE, "Reliable Connection Send Middle"},
	{ RC_SEND_LAST, "Reliable Connection Send Last" },
	{ RC_SEND_LAST_IMM, "Reliable Connection Send Last Immediate"},
	{ RC_SEND_ONLY, "Reliable Connection Send Only"},
	{ RC_SEND_ONLY_IMM, "Reliable Connection Send Only Immediate"},
	{ RC_RDMA_WRITE_FIRST, "Reliable Connection RDMA Write First" },
	{ RC_RDMA_WRITE_MIDDLE, "Reliable Connection RDMA Write Middle"},
	{ RC_RDMA_WRITE_LAST, "Reliable Connection RDMA Write Last"},
	{ RC_RDMA_WRITE_LAST_IMM, "Reliable Connection RDMA Write Last Immediate " },
	{ RC_RDMA_WRITE_ONLY, "Reliable Connection RDMA Write Only" },
	{ RC_RDMA_WRITE_ONLY_IMM, "Reliable Connection RDMA Write Only Immediate"},
	{ RC_RDMA_READ_REQUEST,	 "Reliable Connection RDMA Read Request" },
	{ RC_RDMA_READ_RESPONSE_FIRST, "Reliable Connection RDMA Read Response First" },
	{ RC_RDMA_READ_RESPONSE_MIDDLE, "Reliable Connection RDMA Read Response Middle"},
	{ RC_RDMA_READ_RESPONSE_LAST, "Reliable Connection RDMA Read Response Last" },
	{ RC_RDMA_READ_RESPONSE_ONLY, "Reliable Connection RDMA Read Response Only"},
	{ RC_ACKNOWLEDGE, "Reliable Connection Acknowledge" },
	{ RC_ATOMIC_ACKNOWLEDGE, "Reliable Connection Atomic Acknowledge" },
	{ RC_CMP_SWAP, "Reliable Connection Compare Swap" },
	{ RC_FETCH_ADD, "Reliable Connection Fetch Add"},
	{ RC_SEND_LAST_INVAL, "Reliable Connection Send Last Invalidate"},
	{ RC_SEND_ONLY_INVAL, "Reliable Connection Send Only Invalidate" },


	{ RD_SEND_FIRST, "Reliable Datagram Send First"},
	{ RD_SEND_MIDDLE,"Reliable Datagram Send Middle" },
	{ RD_SEND_LAST,	"Reliable Datagram Send Last"},
	{ RD_SEND_LAST_IMM,	"Reliable Datagram Last Immediate" },
	{ RD_SEND_ONLY,"Reliable Datagram Send Only"},
	{ RD_SEND_ONLY_IMM,"Reliable Datagram Send Only Immediate"},
	{ RD_RDMA_WRITE_FIRST,"Reliable Datagram RDMA Write First"},
	{ RD_RDMA_WRITE_MIDDLE,	"Reliable Datagram RDMA Write Middle"},
	{ RD_RDMA_WRITE_LAST,"Reliable Datagram RDMA Write Last"},
	{ RD_RDMA_WRITE_LAST_IMM,"Reliable Datagram RDMA Write Last Immediate"},
	{ RD_RDMA_WRITE_ONLY,"Reliable Datagram RDMA Write Only"},
	{ RD_RDMA_WRITE_ONLY_IMM,"Reliable Datagram RDMA Write Only Immediate"},
	{ RD_RDMA_READ_REQUEST,"Reliable Datagram RDMA Read Request"},
	{ RD_RDMA_READ_RESPONSE_FIRST,"Reliable Datagram RDMA Read Response First"},
	{ RD_RDMA_READ_RESPONSE_MIDDLE,"Reliable Datagram RDMA Read Response Middle"},
	{ RD_RDMA_READ_RESPONSE_LAST,"Reliable Datagram RDMA Read Response Last"},
	{ RD_RDMA_READ_RESPONSE_ONLY,"Reliable Datagram RDMA Read Response Only"},
	{ RD_ACKNOWLEDGE,"Reliable Datagram Acknowledge"},
	{ RD_ATOMIC_ACKNOWLEDGE,"Reliable Datagram Atomic Acknowledge"},
	{ RD_CMP_SWAP,"Reliable Datagram Compare Swap"},
	{ RD_FETCH_ADD,	"Reliable Datagram Fetch Add"},
	{ RD_RESYNC,"Reliable Datagram RESYNC"},


	{ UD_SEND_ONLY,	"Unreliable Datagram Send Only"},
	{ UD_SEND_ONLY_IMM,	"Unreliable Datagram Send Only Immediate"},


	{ UC_SEND_FIRST,"Unreliable Connection Send First"},
	{ UC_SEND_MIDDLE,"Unreliable Connection Send Middle"},
	{ UC_SEND_LAST,"Unreliable Connection Send Last"},
	{ UC_SEND_LAST_IMM,"Unreliable Connection Send Last Immediate"},
	{ UC_SEND_ONLY,"Unreliable Connection Send Only"},
	{ UC_SEND_ONLY_IMM,"Unreliable Connection Send Only Immediate"},
	{ UC_RDMA_WRITE_FIRST,"Unreliable Connection RDMA Write First"},
	{ UC_RDMA_WRITE_MIDDLE,"Unreliable Connection RDMA Write Middle"},
	{ UC_RDMA_WRITE_LAST,"Unreliable Connection RDMA Write Last"},
	{ UC_RDMA_WRITE_LAST_IMM,"Unreliable Connection RDMA Write Last Immediate"},
	{ UC_RDMA_WRITE_ONLY,"Unreliable Connection RDMA Write Only"},
	{ UC_RDMA_WRITE_ONLY_IMM,"Unreliable Connection RDMA Write Only Immediate"},
	{ 0, NULL }

};



/* Header Ordering Based on OPCODES */
/* These are simply an enumeration of the possible header combinations defined by the IB Spec. */
/* These enumerations  */
/* #DEFINE [HEADER_ORDER]         [ENUM] */
/* __________________________________ */
#define RDETH_DETH_PAYLD			0
/* __________________________________ */
#define RDETH_DETH_RETH_PAYLD		1
/* __________________________________ */
#define RDETH_DETH_IMMDT_PAYLD		2
/* __________________________________ */
#define RDETH_DETH_RETH_IMMDT_PAYLD 3
/* __________________________________ */
#define RDETH_DETH_RETH				4
/* __________________________________ */
#define RDETH_AETH_PAYLD			5
/* __________________________________ */
#define RDETH_PAYLD					6
/* __________________________________ */
#define RDETH_AETH					7
/* __________________________________ */
#define RDETH_AETH_ATOMICACKETH		8
/* __________________________________ */
#define RDETH_DETH_ATOMICETH		9
/* ___________________________________ */
#define RDETH_DETH					10
/* ___________________________________ */
#define DETH_PAYLD					11
/* ___________________________________ */
#define DETH_IMMDT_PAYLD			12
/* ___________________________________ */
#define PAYLD						13
/* ___________________________________ */
#define IMMDT_PAYLD					14
/* ___________________________________ */
#define RETH_PAYLD					15
/* ___________________________________ */
#define RETH_IMMDT_PAYLD			16
/* ___________________________________ */
#define RETH						17
/* ___________________________________ */
#define AETH_PAYLD					18
/* ___________________________________ */
#define AETH						19
/* ___________________________________ */
#define AETH_ATOMICACKETH			20
/* ___________________________________ */
#define ATOMICETH					21
/* ___________________________________ */
#define IETH_PAYLD					22
/* ___________________________________ */


/* Array of all availavle OpCodes to make matching a bit easier. */
/* The OpCodes dictate the header sequence following in the packet. */
/* These arrays tell the dissector which headers must be decoded for the given OpCode. */
static guint32 opCode_RDETH_DETH_ATOMICETH[] = {
 RD_CMP_SWAP,
 RD_FETCH_ADD
};
static guint32 opCode_IETH_PAYLD[] = {
 RC_SEND_LAST_INVAL,
 RC_SEND_ONLY_INVAL
};
static guint32 opCode_ATOMICETH[] = {
 RC_CMP_SWAP,
 RC_FETCH_ADD
};
static guint32 opCode_RDETH_DETH_RETH_PAYLD[] = {
 RD_RDMA_WRITE_FIRST,
 RD_RDMA_WRITE_ONLY
};
static guint32 opCode_RETH_IMMDT_PAYLD[] = {
 RC_RDMA_WRITE_ONLY_IMM,
 UC_RDMA_WRITE_ONLY_IMM
};
static guint32 opCode_RDETH_DETH_IMMDT_PAYLD[] = {
 RD_SEND_LAST_IMM,
 RD_SEND_ONLY_IMM,
 RD_RDMA_WRITE_LAST_IMM
};

static guint32 opCode_RDETH_AETH_PAYLD[] = {
 RD_RDMA_READ_RESPONSE_FIRST,
 RD_RDMA_READ_RESPONSE_LAST,
 RD_RDMA_READ_RESPONSE_ONLY
};
static guint32 opCode_AETH_PAYLD[] = {
 RC_RDMA_READ_RESPONSE_FIRST,
 RC_RDMA_READ_RESPONSE_LAST,
 RC_RDMA_READ_RESPONSE_ONLY
};
static guint32 opCode_RETH_PAYLD[] = {
 RC_RDMA_WRITE_FIRST,
 RC_RDMA_WRITE_ONLY,
 UC_RDMA_WRITE_FIRST,
 UC_RDMA_WRITE_ONLY
};

static guint32 opCode_RDETH_DETH_PAYLD[] = {
 RD_SEND_FIRST,
 RD_SEND_MIDDLE,
 RD_SEND_LAST,
 RD_SEND_ONLY,
 RD_RDMA_WRITE_MIDDLE,
 RD_RDMA_WRITE_LAST
};

static guint32 opCode_IMMDT_PAYLD[] = {
 RC_SEND_LAST_IMM,
 RC_SEND_ONLY_IMM,
 RC_RDMA_WRITE_LAST_IMM,
 UC_SEND_LAST_IMM,
 UC_SEND_ONLY_IMM,
 UC_RDMA_WRITE_LAST_IMM
};

static guint32 opCode_PAYLD[] = {
 RC_SEND_FIRST,
 RC_SEND_MIDDLE,
 RC_SEND_LAST,
 RC_SEND_ONLY,
 RC_RDMA_WRITE_MIDDLE,
 RC_RDMA_WRITE_LAST,
 RC_RDMA_READ_RESPONSE_MIDDLE,
 UC_SEND_FIRST,
 UC_SEND_MIDDLE,
 UC_SEND_LAST,
 UC_SEND_ONLY,
 UC_RDMA_WRITE_MIDDLE,
 UC_RDMA_WRITE_LAST
};

/* It is not necessary to create arrays for these OpCodes since they indicate only one further header. */
/* We can just decode it directly */

/*static guint32 opCode_DETH_IMMDT_PAYLD[] = { */
/* UD_SEND_ONLY_IMM */
/*}; */
/*static guint32 opCode_DETH_PAYLD[] = { */
/* UD_SEND_ONLY */
/*}; */
/*static guint32 opCode_RDETH_DETH[] = { */
/* RD_RESYNC */
/*}; */
/*static guint32 opCode_RDETH_DETH_RETH[] = { */
/* RD_RDMA_READ_REQUEST */
/*}; */
/*static guint32 opCode_RDETH_DETH_RETH_IMMDT_PAYLD[] = { */
/* RD_RDMA_WRITE_ONLY_IMM */
/*}; */
/*static guint32 opCode_RDETH_AETH_ATOMICACKETH[] = { */
/* RD_ATOMIC_ACKNOWLEDGE */
/*}; */
/*static guint32 opCode_RDETH_AETH[] = { */
/* RD_ACKNOWLEDGE */
/*}; */
/*static guint32 opCode_RDETH_PAYLD[] = { */
/* RD_RDMA_READ_RESPONSE_MIDDLE */
/*}; */
/*static guint32 opCode_AETH_ATOMICACKETH[] = { */
/* RC_ATOMIC_ACKNOWLEDGE */
/*}; */
/*static guint32 opCode_RETH[] = { */
/* RC_RDMA_READ_REQUEST */
/*}; */
/*static guint32 opCode_AETH[] = { */
/* RC_ACKNOWLEDGE */
/*}; */


/* Field dissector structures. */
/* For reserved fields, reservedX denotes the reserved field is X bits in length. */
/* e.g. reserved2 is a reserved field 2 bits in length. */
/* The third parameter is a filter string associated for this field. */
/* So for instance, to filter packets for a given virtual lane, */
/* The filter (infiniband.LRH.vl == 3) or something similar would be used. */

static hf_register_info hf[] = {
	
	/* Local Route Header (LRH) */
	{&hf_infiniband_LRH,
	{"Local Route Header", "infiniband.lrh", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_virtual_lane,
	{"Virtual Lane", "infiniband.lrh.vl", FT_UINT8, BASE_HEX, NULL, 0xF0, NULL, HFILL}
	},
	{&hf_infiniband_link_version,
	{"Link Version", "infiniband.lrh.lver", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}
	},
	{&hf_infiniband_service_level,
	{"Service Level", "infiniband.lrh.sl", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}
	},
	{&hf_infiniband_reserved2,
	{"Reserved (2 bits)", "infiniband.lrh.reserved2", FT_UINT8, BASE_DEC, NULL, 0x0C, NULL, HFILL}
	},
	{&hf_infiniband_link_next_header,
	{"Link Next Header", "infiniband.lrh.lnh", FT_UINT8, BASE_HEX, NULL, 0x03, NULL, HFILL}
	},
	{&hf_infiniband_destination_local_id,
	{"Destination Local ID", "infiniband.lrh.dlid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_reserved5,
	{"Reserved (5 bits)", "infiniband.lrh.reserved5", FT_UINT16, BASE_DEC, NULL, 0xF800, NULL, HFILL}
	},
	{&hf_infiniband_packet_length,
	{"Packet Length", "infiniband.lrh.pktlen", FT_UINT16, BASE_DEC, NULL, 0x07FF, NULL, HFILL}
	},
	{&hf_infiniband_source_local_id,
	{"Source Local ID", "infiniband.lrh.slid", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	
	/* Global Route Header (GRH) */
	{&hf_infiniband_GRH,
	{"Global Route Header", "infiniband.grh", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_ip_version,
	{"IP Version", "infiniband.grh.ipver", FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL}
	},
	{&hf_infiniband_traffic_class,
	{"Traffic Class", "infiniband.grh.tclass", FT_UINT16, BASE_DEC, NULL, 0x0FF0, NULL, HFILL}
	},
	{&hf_infiniband_flow_label,
	{"Flow Label", "infiniband.grh.flowlabel", FT_UINT32, BASE_DEC, NULL, 0x000FFFFF, NULL, HFILL}
	},
	{&hf_infiniband_payload_length,
	{"Payload Length", "infiniband.grh.paylen", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_next_header,
	{"Next Header", "infiniband.grh.nxthdr", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_hop_limit,
	{"Hop Limit", "infiniband.grh.hoplmt", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_source_gid,
	{"Source GID", "infiniband.grh.sgid", FT_BYTES, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_destination_gid,
	{"Destination GID", "infiniband.grh.dgid", FT_BYTES, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	
	/* Base Transport Header (BTH) */
	{&hf_infiniband_BTH,
	{"Base Transport Header", "infiniband.bth", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_opcode,
	{"Opcode", "infiniband.bth.opcode", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_solicited_event,
	{"Solicited Event", "infiniband.bth.se", FT_BOOLEAN, BASE_DEC, NULL, 0x80, NULL, HFILL}
	},
	{&hf_infiniband_migreq,
	{"MigReq", "infiniband.bth.m", FT_BOOLEAN, BASE_DEC, NULL, 0x40, NULL, HFILL}
	},
	{&hf_infiniband_pad_count,
	{"Pad Count", "infiniband.bth.padcnt", FT_UINT8, BASE_DEC, NULL, 0x30, NULL, HFILL}
	},
	{&hf_infiniband_transport_header_version,
	{"Header Version", "infiniband.bth.tver", FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL}
	},
	{&hf_infiniband_partition_key,
	{"Partition Key", "infiniband.bth.p_key", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_reserved8,
	{"Reserved (8 bits)", "infiniband.bth.reserved8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_destination_qp,
	{"Destination Queue Pair", "infiniband.bth.destqp", FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_acknowledge_request,
	{"Acknowledge Request", "infiniband.bth.a", FT_BOOLEAN, BASE_DEC, NULL, 0x80, NULL, HFILL}
	},
	{&hf_infiniband_reserved7,
	{"Reserved (7 bits)", "infiniband.bth.reserved7", FT_UINT8, BASE_DEC, NULL, 0x7F, NULL, HFILL}
	},
	{&hf_infiniband_packet_sequence_number,
	{"Packet Sequence Number", "infiniband.bth.psn", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	
	/* Reliable Datagram Extended Transport Header (RDETH) */
	{&hf_infiniband_RDETH,
	{"Reliable Datagram Extentded Transport Header", "infiniband.rdeth", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_reserved8_RDETH,
	{"Reserved (8 bits)", "infiniband.rdeth.reserved8", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_ee_context,
	{"E2E Context", "infiniband.rdeth.eecnxt", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	
	/* Datagram Extended Transport Header (DETH) */
	{&hf_infiniband_DETH,
	{"Datagram Extended Transport Header", "infiniband.deth", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_queue_key,
	{"Queue Key", "infiniband.deth.q_key", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_reserved8_DETH,
	{"Reserved (8 bits)", "infiniband.deth.reserved8", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_source_qp,
	{"Source Queue Pair", "infiniband.deth.srcqp", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	
	/* RDMA Extended Transport Header (RETH) */
	{&hf_infiniband_RETH,
	{"RDMA Extended Transport Header", "infiniband.reth", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_virtual_address,
	{"Virtual Address", "infiniband.reth.va", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_remote_key,
	{"Remote Key", "infiniband.reth.r_key", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_dma_length,
	{"DMA Length", "infiniband.reth.dmalen", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	
	/* Atomic Extended Transport Header (AtomicETH) */
	{&hf_infiniband_AtomicETH,
	{"Atomic Extended Transport Header", "infiniband.atomiceth", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_virtual_address_AtomicETH,
	{"Virtual Address", "infiniband.atomiceth.va", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_remote_key_AtomicETH,
	{"Remote Key", "infiniband.atomiceth.r_key", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_swap_or_add_data,
	{"Swap (Or Add) Data", "infiniband.atomiceth.swapdt", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_compare_data,
	{"Compare Data", "infiniband.atomiceth.cmpdt", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	
	/* ACK Extended Transport Header (AETH) */
	{&hf_infiniband_AETH,
	{"ACK Extended Transport Header", "infiniband.aeth", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_syndrome,
	{"Syndrome", "infiniband.aeth.syndrome", FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_message_sequence_number,
	{"Message Sequence Number", "infiniband.aeth.msn", FT_UINT24, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	
	/* Atomic ACK Extended Transport Header (AtomicAckETH) */
	{&hf_infiniband_AtomicAckETH,
	{"Atomic ACK Extended Transport Header", "infiniband.atomicacketh", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_original_remote_data,
	{"Original Remote Data", "infiniband.atomicacketh.origremdt", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL}
	},
	/* Immediate Extended Transport Header (ImmDT) */
	{&hf_infiniband_IMMDT,
	{"Immediate Data", "infiniband.immdt", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	/* Invalidate Extended Transport Header (IETH) */
	{&hf_infiniband_IETH,
	{"RKey", "infiniband.ieth", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	/* Payload */
	{&hf_infiniband_payload,
	{"Payload", "infiniband.payload", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_invariant_crc,
	{"Invariant CRC", "infiniband.invariant.crc", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_variant_crc,
	{"Variant CRC", "infiniband.variant.crc", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	{&hf_infiniband_raw_data,
	{"Raw Data", "infiniband.rawdata", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	},
	/* Unknown or Vendor Specific */
	{&hf_infiniband_vendor,
	{"Unknown/Vendor Specific Data", "infiniband.vendor", FT_BYTES, BASE_HEX, NULL, 0x0, NULL, HFILL}
	}

};

static gint *ett[] = {
	&ett_infiniband
};


#endif
