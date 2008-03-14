/* packet-infiniband.c
 * Routines for Infiniband/ERF Dissection
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/proto.h>
#include <string.h>
#include "packet-infiniband.h"

void proto_register_infiniband(void)
{
	if(proto_infiniband == -1)
	{
		proto_infiniband = proto_register_protocol("InfiniBand", "InfiniBand", "infiniband");
		register_dissector("infiniband", dissect_infiniband, proto_infiniband);
	}

	proto_register_field_array(proto_infiniband, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

}

void proto_reg_handoff_infiniband(void)
{
	static int initialized=FALSE;
	if(!initialized)
	{
		infiniband_handle = create_dissector_handle(dissect_infiniband, proto_infiniband);
	}
}


static void
dissect_infiniband(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Top Level Item */
	proto_item *infiniband_packet = NULL;

	/* The Headers Subtree */
	proto_tree *all_headers_tree = NULL;

	/* LRH - Local Route Header */
	proto_tree *local_route_header_tree = NULL;
	proto_item *local_route_header_item = NULL;

	/* GRH - Global Route Header */
	proto_tree *global_route_header_tree = NULL;
	proto_item *global_route_header_item = NULL;

	/* BTH - Base Transport header */
	proto_tree *base_transport_header_tree = NULL;
	proto_item *base_transport_header_item = NULL;

	/* Raw Data - no decoding. */
	proto_item *raw_ipv6 = NULL;
	proto_item *raw_RWH_Ethertype;

	gboolean bthFollows = 0; /* Tracks if we are parsing a BTH.  This is a significant decision point */
	guint8 lnh_val = 0;	/* Link Next Header Value */
	gint offset = 0;		/* Current Offset */
	guint8 opCode = 0;		/* OpCode from BTH header. */
	gint32 nextHeaderSequence = -1; /* defined by this dissector. #define which indicates the upcoming header sequence from OpCode */
	guint16 payloadLength = 0; /* Payload Length should it exist */
	guint8 nxtHdr = 0; /* */
	guint16 packetLength = 0; /* Packet Length.  We track this as tvb->length - offset.  It provides the parsing methods a known size */
							  /* that must be available for that header. */
	e_guid_t SRCguid;
	e_guid_t DSTguid;

	/* Mark the Packet type as Infiniband in the wireshark UI */
	/* Clear other columns */
	if(pinfo->cinfo)
	{
		if(check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "InfiniBand");
		if(check_col(pinfo->cinfo, COL_INFO))
			col_clear(pinfo->cinfo, COL_INFO);
	}

	/* Get the parent tree from the ERF dissector */
	if(tree && tree->parent)
	{
		tree = tree->parent;
	}

	if(tree)
	{		
		/* proto_tree* proto_item_add_subtree(proto_item *ti, gint idx); */

		/* Top Level Packet */
		infiniband_packet = proto_tree_add_item(tree, proto_infiniband, tvb, offset, -1, FALSE);

		/* Headers Level Tree */
		all_headers_tree = proto_item_add_subtree(infiniband_packet, ett_infiniband);

		/* Local Route Header Subtree */
		local_route_header_item = proto_tree_add_bytes(all_headers_tree, hf_infiniband_LRH, tvb, offset, 8, tvb->real_data);
		proto_item_set_text(local_route_header_item, "%s", "Local Route Header");
		local_route_header_tree = proto_item_add_subtree(local_route_header_item, ett_infiniband);

		proto_tree_add_item(local_route_header_tree, hf_infiniband_virtual_lane,			tvb, offset, 1, FALSE);
		proto_tree_add_item(local_route_header_tree, hf_infiniband_link_version,			tvb, offset, 1, FALSE); offset+=1;
		proto_tree_add_item(local_route_header_tree, hf_infiniband_service_level,			tvb, offset, 1, FALSE);

		proto_tree_add_item(local_route_header_tree, hf_infiniband_reserved2,				tvb, offset, 1, FALSE);
		proto_tree_add_item(local_route_header_tree, hf_infiniband_link_next_header,		tvb, offset, 1, FALSE);
	}
	else
	{
		offset+=1;
	}
	
	/* Save Link Next Header... This tells us what the next header is. */
	lnh_val =  tvb_get_guint8(tvb, offset);
	lnh_val = lnh_val & 0x03;
	offset+=1;

	if(tree)
	{
		proto_tree_add_item(local_route_header_tree, hf_infiniband_destination_local_id,	tvb, offset, 2, FALSE);
	}

	/* Set destination in packet view. */
	if (check_col(pinfo->cinfo, COL_DEF_DST))
	{
		col_set_str(pinfo->cinfo, COL_DEF_DST, "DLID: ");
		col_set_fence(pinfo->cinfo, COL_DEF_DST);
		col_set_str(pinfo->cinfo, COL_DEF_DST, tvb_bytes_to_str(tvb, offset, 2));
	}
	offset+=2;

	if(tree)
	{
		proto_tree_add_item(local_route_header_tree, hf_infiniband_reserved5,				tvb, offset, 2, FALSE);
	}

	packetLength = tvb_get_ntohs(tvb, offset); /* Get the Packet Length. This will determine payload size later on. */
	packetLength = packetLength & 0x07FF; /* Mask off top 5 bits, they are reserved */
	packetLength = packetLength * 4; /* Multiply by 4 to get true byte length. This is by specification. PktLen is size in 4 byte words (byteSize /4). */
	
	if(tree)
	{
		proto_tree_add_item(local_route_header_tree, hf_infiniband_packet_length,			tvb, offset, 2, FALSE); offset+=2;
		proto_tree_add_item(local_route_header_tree, hf_infiniband_source_local_id,			tvb, offset, 2, FALSE);
	}
	else
	{
		offset+=2;
	}

	/* Set Source in packet view. */
	if (check_col(pinfo->cinfo, COL_DEF_SRC))
	{
		col_set_str(pinfo->cinfo, COL_DEF_SRC, "SLID: ");
		col_set_fence(pinfo->cinfo, COL_DEF_SRC);
		col_set_str(pinfo->cinfo, COL_DEF_SRC, tvb_bytes_to_str(tvb, offset, 2));
	}
	offset+=2;
	packetLength -= 8; /* Shave 8 bytes for the LRH. */

	switch(lnh_val)
	{
		case IBA_GLOBAL:
			payloadLength = tvb_get_ntohs(tvb, offset + 4);
			nxtHdr = tvb_get_guint8(tvb, offset + 6);
			if(tree)
			{
				global_route_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_GRH, tvb, offset, 40, FALSE);
				proto_item_set_text(global_route_header_item, "%s", "Global Route Header");
				global_route_header_tree = proto_item_add_subtree(global_route_header_item, ett_infiniband);
				proto_tree_add_item(global_route_header_tree, hf_infiniband_ip_version,			tvb, offset, 1, FALSE);
				proto_tree_add_item(global_route_header_tree, hf_infiniband_traffic_class,		tvb, offset, 2, FALSE);
				proto_tree_add_item(global_route_header_tree, hf_infiniband_flow_label,			tvb, offset, 4, FALSE); offset += 4;
				proto_tree_add_item(global_route_header_tree, hf_infiniband_payload_length,		tvb, offset, 2, FALSE); offset += 2;
				proto_tree_add_item(global_route_header_tree, hf_infiniband_next_header,		tvb, offset, 1, FALSE); offset +=1;
				proto_tree_add_item(global_route_header_tree, hf_infiniband_hop_limit,			tvb, offset, 1, FALSE); offset +=1;
				proto_tree_add_item(global_route_header_tree, hf_infiniband_source_gid,			tvb, offset, 16, FALSE);
			}
			else
			{
				offset+=8;
			}

			tvb_get_ntohguid(tvb, offset,&SRCguid);
			if (check_col(pinfo->cinfo, COL_DEF_SRC))
			{
				col_set_str(pinfo->cinfo, COL_DEF_SRC, "SGID: ");
				col_set_fence(pinfo->cinfo, COL_DEF_SRC);
				col_set_str(pinfo->cinfo, COL_DEF_SRC, guid_to_str(&SRCguid));
			}
			offset += 16;

			if(tree)
			{
				proto_tree_add_item(global_route_header_tree, hf_infiniband_destination_gid,	tvb, offset, 16, FALSE); offset +=16;
			}
			else
			{
				offset+=16;
			}

			tvb_get_ntohguid(tvb, offset, &DSTguid);
			if (check_col(pinfo->cinfo, COL_DEF_DST))
			{
				col_set_str(pinfo->cinfo, COL_DEF_DST, "DGID: ");
				col_set_fence(pinfo->cinfo, COL_DEF_DST);
				col_set_str(pinfo->cinfo, COL_DEF_DST, guid_to_str(&DSTguid));
			}
			offset += 16;



			packetLength -= 40; /* Shave 40 bytes for GRH */
			if(nxtHdr != 0x1B)
			{
				if(tree)
				{
					/* Some kind of packet being transported globally with IBA, but locally it is not IBA - no BTH following. */
					proto_tree *RAWDATA_header_tree = NULL;
					proto_item *RAWDATA_header_item = NULL;
					RAWDATA_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_raw_data, tvb, offset, -1, FALSE);
					proto_item_set_text(RAWDATA_header_item, "%s", "Raw Data - Non IBA local transport");
					RAWDATA_header_tree = proto_item_add_subtree(RAWDATA_header_item, ett_infiniband);
				}
				break;		
			}

			/* otherwise fall through and start parsing BTH */

		case IBA_LOCAL:
			bthFollows = TRUE;

			if(tree)
			{
				base_transport_header_item = proto_tree_add_item(all_headers_tree, hf_infiniband_BTH, tvb, offset, 12, FALSE);
				proto_item_set_text(base_transport_header_item, "%s", "Base Transport Header");
				base_transport_header_tree = proto_item_add_subtree(base_transport_header_item, ett_infiniband);
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_opcode,				  tvb, offset, 1, FALSE);
			}
			/* Get the OpCode - this tells us what headers are following */
			opCode = tvb_get_guint8(tvb, offset);
			if (check_col(pinfo->cinfo, COL_INFO))
			{
				col_set_str(pinfo->cinfo, COL_INFO, "     ");
				col_set_fence(pinfo->cinfo, COL_INFO);
				col_set_str(pinfo->cinfo, COL_INFO, val_to_str((guint32)opCode, OpCodeMap, "Unknown OpCode"));
			}
			offset +=1;
			if(tree)
			{
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_solicited_event,				tvb, offset, 1, FALSE);
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_migreq,						tvb, offset, 1, FALSE);
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_pad_count,					tvb, offset, 1, FALSE);
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_transport_header_version,		tvb, offset, 1, FALSE); offset +=1;
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_partition_key,				tvb, offset, 2, FALSE); offset +=2;
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_reserved8,					tvb, offset, 1, FALSE); offset +=1;
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_destination_qp,				tvb, offset, 3, FALSE); offset +=3;
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_acknowledge_request,			tvb, offset, 1, FALSE);
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_reserved7,					tvb, offset, 1, FALSE); offset +=1;
				proto_tree_add_item(base_transport_header_tree, hf_infiniband_packet_sequence_number,		tvb, offset, 3, FALSE); offset +=3;
			}
			else
			{
				offset+=11;
			}

			packetLength -= 12; /* Shave 12 for Base Transport Header */

		break;
		case IP_NON_IBA:
			if(!tree)
			{
				break;
			}

			/* Raw IPv6 Packet */
			raw_ipv6 = proto_tree_add_item(all_headers_tree, hf_infiniband_raw_data, tvb, offset, -1, FALSE);
			proto_item_set_text(raw_ipv6, "%s", "Raw (non-IBA Transport) IPv6 Packet");
			break;
		case RAW:
			if(!tree)
			{
				break;
			}

			/* Raw (any other) Packet */
			raw_RWH_Ethertype = proto_tree_add_item(all_headers_tree, hf_infiniband_raw_data, tvb, offset, -1, FALSE);
			proto_item_set_text(raw_RWH_Ethertype, "%s", "Raw (non-IBA Transport) Packet");

			break;
		default:
			if(!tree)
			{
				break;
			}

			/* Unknown Packet */
			raw_ipv6 = proto_tree_add_item(all_headers_tree, hf_infiniband_raw_data, tvb, offset, -1, FALSE);
			proto_item_set_text(raw_ipv6, "%s", "Unknown (non-IBA Transport) Raw Data Packet");
			break;
	}

	if(bthFollows && tree)
	{
		/* Find our next header sequence based on the Opcode */
		/* Each case decrements the packetLength by the amount of bytes consumed by each header. */
		/* The find_next_header_sequence method could be used to automate this. */
		/* We need to keep track of this so we know much data to mark as payload/ICRC/VCRC values. */
		nextHeaderSequence = find_next_header_sequence((guint32) opCode);
		switch(nextHeaderSequence)
		{
			case RDETH_DETH_PAYLD:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_DETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 8; /* DETH */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case RDETH_DETH_RETH_PAYLD:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_DETH(all_headers_tree, tvb, &offset);
				parse_RETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 8; /* DETH */
				packetLength -= 16; /* RETH */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case RDETH_DETH_IMMDT_PAYLD:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_DETH(all_headers_tree, tvb, &offset);
				parse_IMMDT(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 8; /* DETH */
				packetLength -= 4; /* IMMDT */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case RDETH_DETH_RETH_IMMDT_PAYLD:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_DETH(all_headers_tree, tvb, &offset);
				parse_RETH(all_headers_tree, tvb, &offset);
				parse_IMMDT(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 8; /* DETH */
				packetLength -= 16; /* RETH */
				packetLength -= 4; /* IMMDT */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case RDETH_DETH_RETH:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_DETH(all_headers_tree, tvb, &offset);
				parse_RETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 8; /* DETH */
				packetLength -= 16; /* RETH */

				break;
			case RDETH_AETH_PAYLD:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_AETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 4; /* AETH */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case RDETH_PAYLD:
				parse_RDETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case RDETH_AETH:
				parse_AETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 4; /* AETH */


				break;
			case RDETH_AETH_ATOMICACKETH:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_AETH(all_headers_tree, tvb, &offset);
				parse_ATOMICACKETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 4; /* AETH */
				packetLength -= 8; /* AtomicAckETH */


				break;
			case RDETH_DETH_ATOMICETH:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_DETH(all_headers_tree, tvb, &offset);
				parse_ATOMICETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 8; /* DETH */
				packetLength -= 28; /* AtomicETH */

				break;
			case RDETH_DETH:
				parse_RDETH(all_headers_tree, tvb, &offset);
				parse_DETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* RDETH */
				packetLength -= 8; /* DETH */

				break;
			case DETH_PAYLD:
				parse_DETH(all_headers_tree, tvb, &offset);

				packetLength -= 8; /* DETH */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case PAYLD:

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case IMMDT_PAYLD:
				parse_IMMDT(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* IMMDT */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case RETH_PAYLD:
				parse_RETH(all_headers_tree, tvb, &offset);

				packetLength -= 16; /* RETH */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case RETH:
				parse_RETH(all_headers_tree, tvb, &offset);

				packetLength -= 16; /* RETH */

				break;
			case AETH_PAYLD:
				parse_AETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* AETH */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case AETH:
				parse_AETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* AETH */

				break;
			case AETH_ATOMICACKETH:
				parse_AETH(all_headers_tree, tvb, &offset);
				parse_ATOMICACKETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* AETH */
				packetLength -= 8; /* AtomicAckETH */

				break;
			case ATOMICETH:
				parse_ATOMICETH(all_headers_tree, tvb, &offset);

				packetLength -= 28; /* AtomicETH */

				break;
			case IETH_PAYLD:
				parse_IETH(all_headers_tree, tvb, &offset);

				packetLength -= 4; /* IETH */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			case DETH_IMMDT_PAYLD:
				parse_DETH(all_headers_tree, tvb, &offset);
				parse_IMMDT(all_headers_tree, tvb, &offset);

				packetLength -= 8; /* DETH */
				packetLength -= 4; /* IMMDT */

				parse_PAYLOAD(all_headers_tree, tvb, &offset, packetLength);
				break;
			default:
				parse_VENDOR(all_headers_tree, tvb, &offset);
				break;
		}
	}
}


/* Description: Finds the header sequence that follows the Base Transport Header. */
/* Somwhat inefficient (should be using a single key,value pair data structure) */
/* But uses pure probablity to take a stab at better efficiency. */
/* Searches largest header sequence groups first, and then finally resorts to single matches for unique header sequences */
/* IN: OpCode: The OpCode from the Base Transport Header. */
/* OUT: The Header Sequence enumeration.  See Declarations for #defines from (0-22) */
static gint32
find_next_header_sequence(guint32 OpCode)
{
	if(contains(OpCode, &opCode_PAYLD[0], (gint32)sizeof(opCode_PAYLD)))
		return PAYLD;

	if(contains(OpCode, &opCode_IMMDT_PAYLD[0], (gint32)sizeof(opCode_IMMDT_PAYLD)))
		return IMMDT_PAYLD;

	if(contains(OpCode, &opCode_RDETH_DETH_PAYLD[0], (gint32)sizeof(opCode_RDETH_DETH_PAYLD)))
		return RDETH_DETH_PAYLD;

	if(contains(OpCode, &opCode_RETH_PAYLD[0], (gint32)sizeof(opCode_RETH_PAYLD)))
		return RETH_PAYLD;

	if(contains(OpCode, &opCode_RDETH_AETH_PAYLD[0], (gint32)sizeof(opCode_RDETH_AETH_PAYLD)))
		return RDETH_AETH_PAYLD;

	if(contains(OpCode, &opCode_AETH_PAYLD[0], (gint32)sizeof(opCode_AETH_PAYLD)))
		return AETH_PAYLD;

	if(contains(OpCode, &opCode_RDETH_DETH_IMMDT_PAYLD[0], (gint32)sizeof(opCode_RDETH_DETH_IMMDT_PAYLD)))
		return RDETH_DETH_IMMDT_PAYLD;

	if(contains(OpCode, &opCode_RETH_IMMDT_PAYLD[0], (gint32)sizeof(opCode_RETH_IMMDT_PAYLD)))
		return RETH_IMMDT_PAYLD;

	if(contains(OpCode, &opCode_RDETH_DETH_RETH_PAYLD[0], (gint32)sizeof(opCode_RDETH_DETH_RETH_PAYLD)))
		return RDETH_DETH_RETH_PAYLD;

	if(contains(OpCode, &opCode_ATOMICETH[0], (gint32)sizeof(opCode_ATOMICETH)))
		return ATOMICETH;

	if(contains(OpCode, &opCode_IETH_PAYLD[0], (gint32)sizeof(opCode_IETH_PAYLD)))
		return IETH_PAYLD;

	if(contains(OpCode, &opCode_RDETH_DETH_ATOMICETH[0], (gint32)sizeof(opCode_RDETH_DETH_ATOMICETH)))
		return RDETH_DETH_ATOMICETH;

	if((OpCode ^ RC_ACKNOWLEDGE) == 0)
		return AETH;

	if((OpCode ^ RC_RDMA_READ_REQUEST) == 0)
		return RETH;

	if((OpCode ^ RC_ATOMIC_ACKNOWLEDGE) == 0)
		return AETH_ATOMICACKETH;

	if((OpCode ^ RD_RDMA_READ_RESPONSE_MIDDLE) == 0)
		return RDETH_PAYLD;

	if((OpCode ^ RD_ACKNOWLEDGE) == 0)
		return RDETH_AETH;

	if((OpCode ^ RD_ATOMIC_ACKNOWLEDGE) == 0)
		return RDETH_AETH_ATOMICACKETH;

	if((OpCode ^ RD_RDMA_WRITE_ONLY_IMM) == 0)
		return RDETH_DETH_RETH_IMMDT_PAYLD;

	if((OpCode ^ RD_RDMA_READ_REQUEST) == 0)
		return RDETH_DETH_RETH;

	if((OpCode ^ RD_RESYNC) == 0)
		return RDETH_DETH;

	if((OpCode ^ UD_SEND_ONLY) == 0)
		return DETH_PAYLD;

	if((OpCode ^ UD_SEND_ONLY_IMM) == 0)
		return DETH_IMMDT_PAYLD;

	return -1;
}

/* Description: Finds if a given value is present in an array. This is probably in a standard library somewhere, */
/* But I'd rather define my own. */
/* IN: OpCode: The OpCode you are looking for */
/* IN: Codes: The organized array of OpCodes to look through */
/* IN: Array length, because we're in C... */
/* OUT: Boolean indicating if that OpCode was found in OpCodes */
static gboolean
contains(guint32 OpCode, guint32* Codes, gint32 length)
{
	gint32 i;
	for(i = 0; i < length; i++)
	{
		if((OpCode ^ Codes[i]) == 0)
			return TRUE;
	}
	return FALSE;
}

/* Parse RDETH - Reliable Datagram Extended Transport Header */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_RDETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* RDETH - Reliable Datagram Extended Transport Header */
	proto_tree *RDETH_header_tree = NULL;
	proto_item *RDETH_header_item = NULL;

	RDETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_RDETH, tvb, local_offset, 4, FALSE);
	proto_item_set_text(RDETH_header_item, "%s", "RDETH - Reliable Datagram Extended Transport Header");
	RDETH_header_tree = proto_item_add_subtree(RDETH_header_item, ett_infiniband);

	proto_tree_add_item(RDETH_header_tree, hf_infiniband_reserved8_RDETH,				tvb, local_offset, 1, FALSE); local_offset+=1;
	proto_tree_add_item(RDETH_header_tree, hf_infiniband_ee_context,					tvb, local_offset, 3, FALSE); local_offset+=3;

	*offset = local_offset;
}

/* Parse DETH - Datagram Extended Transport Header */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_DETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* DETH - Datagram Extended Transport Header */
	proto_tree *DETH_header_tree = NULL;
	proto_item *DETH_header_item = NULL;

	DETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_DETH, tvb, local_offset, 8, FALSE);
	proto_item_set_text(DETH_header_item, "%s", "DETH - Datagram Extended Transport Header");
	DETH_header_tree = proto_item_add_subtree(DETH_header_item, ett_infiniband);

	proto_tree_add_item(DETH_header_tree, hf_infiniband_queue_key,					tvb, local_offset, 4, FALSE); local_offset+=4;
	proto_tree_add_item(DETH_header_tree, hf_infiniband_reserved8_DETH,				tvb, local_offset, 1, FALSE); local_offset+=1;
	proto_tree_add_item(DETH_header_tree, hf_infiniband_source_qp,					tvb, local_offset, 3, FALSE); local_offset+=3;

	*offset = local_offset;
}

/* Parse RETH - RDMA Extended Transport Header */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_RETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* RETH - RDMA Extended Transport Header */
	proto_tree *RETH_header_tree = NULL;
	proto_item *RETH_header_item = NULL;

	RETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_RETH, tvb, local_offset, 16, FALSE);
	proto_item_set_text(RETH_header_item, "%s", "RETH - RDMA Extended Transport Header");
	RETH_header_tree = proto_item_add_subtree(RETH_header_item, ett_infiniband);

	proto_tree_add_item(RETH_header_tree, hf_infiniband_virtual_address,				tvb, local_offset, 8, FALSE); local_offset+=8;
	proto_tree_add_item(RETH_header_tree, hf_infiniband_remote_key,						tvb, local_offset, 4, FALSE); local_offset+=4;
	proto_tree_add_item(RETH_header_tree, hf_infiniband_dma_length,						tvb, local_offset, 4, FALSE); local_offset+=4;

	*offset = local_offset;
}

/* Parse AtomicETH - Atomic Extended Transport Header */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_ATOMICETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* AtomicETH - Atomic Extended Transport Header */
	proto_tree *ATOMICETH_header_tree = NULL;
	proto_item *ATOMICETH_header_item = NULL;

	ATOMICETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_AtomicETH, tvb, local_offset, 28, FALSE);
	proto_item_set_text(ATOMICETH_header_item, "%s", "AtomicETH - Atomic Extended Transport Header");
	ATOMICETH_header_tree = proto_item_add_subtree(ATOMICETH_header_item, ett_infiniband);

	proto_tree_add_item(ATOMICETH_header_tree, hf_infiniband_virtual_address,				tvb, local_offset, 8, FALSE); local_offset+=8;
	proto_tree_add_item(ATOMICETH_header_tree, hf_infiniband_remote_key,					tvb, local_offset, 4, FALSE); local_offset+=4;
	proto_tree_add_item(ATOMICETH_header_tree, hf_infiniband_swap_or_add_data,				tvb, local_offset, 8, FALSE); local_offset+=8;
	proto_tree_add_item(ATOMICETH_header_tree, hf_infiniband_compare_data,					tvb, local_offset, 8, FALSE); local_offset+=8;

	*offset = local_offset;
}

/* Parse AETH - ACK Extended Transport Header */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_AETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* AETH - ACK Extended Transport Header */
	proto_tree *AETH_header_tree = NULL;
	proto_item *AETH_header_item = NULL;

	AETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_AETH, tvb, local_offset, 4, FALSE);
	proto_item_set_text(AETH_header_item, "%s", "AETH - ACK Extended Transport Header");
	AETH_header_tree = proto_item_add_subtree(AETH_header_item, ett_infiniband);

	proto_tree_add_item(AETH_header_tree, hf_infiniband_syndrome,						tvb, local_offset, 1, FALSE); local_offset+=1;
	proto_tree_add_item(AETH_header_tree, hf_infiniband_message_sequence_number,		tvb, local_offset, 3, FALSE); local_offset+=3;

	*offset = local_offset;
}

/* Parse AtomicAckEth - Atomic ACK Extended Transport Header */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_ATOMICACKETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* AtomicAckEth - Atomic ACK Extended Transport Header */
	proto_tree *ATOMICACKETH_header_tree = NULL;
	proto_item *ATOMICACKETH_header_item = NULL;

	ATOMICACKETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_AtomicAckETH, tvb, local_offset, 8, FALSE);
	proto_item_set_text(ATOMICACKETH_header_item, "%s", "ATOMICACKETH - Atomic ACK Extended Transport Header");
	ATOMICACKETH_header_tree = proto_item_add_subtree(ATOMICACKETH_header_item, ett_infiniband);

	proto_tree_add_item(ATOMICACKETH_header_tree, hf_infiniband_original_remote_data,	tvb, local_offset, 8, FALSE); local_offset+=8;

	*offset = local_offset;
}

/* Parse IMMDT - Immediate Data Extended Transport Header */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_IMMDT(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* IMMDT - Immediate Data Extended Transport Header */
	proto_tree *IMMDT_header_tree = NULL;
	proto_item *IMMDT_header_item = NULL;

	IMMDT_header_item = proto_tree_add_item(parentTree, hf_infiniband_IMMDT, tvb, local_offset, 4, FALSE);
	proto_item_set_text(IMMDT_header_item, "%s", "IMMDT - Immediate Data Extended Transport Header");
	IMMDT_header_tree = proto_item_add_subtree(IMMDT_header_item, ett_infiniband);

	proto_tree_add_item(IMMDT_header_tree, hf_infiniband_IMMDT,	tvb, local_offset, 4, FALSE); local_offset+=4;

	*offset = local_offset;
}

/* Parse IETH - Invalidate Extended Transport Header */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_IETH(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* IETH - Invalidate Extended Transport Header */
	proto_tree *IETH_header_tree = NULL;
	proto_item *IETH_header_item = NULL;

	IETH_header_item = proto_tree_add_item(parentTree, hf_infiniband_IETH, tvb, local_offset, 4, FALSE);
	proto_item_set_text(IETH_header_item, "%s", "IETH - Invalidate Extended Transport Header");
	IETH_header_tree = proto_item_add_subtree(IETH_header_item, ett_infiniband);

	proto_tree_add_item(IETH_header_tree, hf_infiniband_IETH,	tvb, local_offset, 4, FALSE); local_offset+=4;

	*offset = local_offset;
}

/* Parse Payload - Packet Payload / Invariant CRC / Variant CRC */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
/* IN: Length of Payload */
static void
parse_PAYLOAD(proto_tree * parentTree, tvbuff_t *tvb, gint *offset, gint length)
{
	gint local_offset = *offset;
	/* Payload - Packet Payload */
	proto_tree *PAYLOAD_header_tree = NULL;
	proto_item *PAYLOAD_header_item = NULL;

    if((length + local_offset) >= (gint)(tvb->length)) /* oreviously consumed bytes + offset was all the data - none or corrupt payload*/
	{
		/* Error condition */
		return;
	}


	/* Calculation for Payload: */
	/* (tvb->length) Length of entire packet - (local_offset) Starting byte of Payload Data */
	PAYLOAD_header_item = proto_tree_add_item(parentTree, hf_infiniband_payload, tvb, local_offset, (tvb->length) - local_offset, FALSE); local_offset += (tvb->length - 6 - local_offset);
	proto_item_set_text(PAYLOAD_header_item, "%s", "Payload");
	PAYLOAD_header_tree = proto_item_add_subtree(PAYLOAD_header_item, ett_infiniband);

	/* offset addition is more complex for the payload. */
	/* We need the total length of the packet, - length of previous headers, + offset where payload started. */
	/* We also need  to reserve 6 bytes for the CRCs which are not actually part of the payload. */
	proto_tree_add_item(PAYLOAD_header_tree, hf_infiniband_invariant_crc,	tvb, local_offset, 4, FALSE); local_offset +=4;
    proto_tree_add_item(PAYLOAD_header_tree, hf_infiniband_variant_crc,		tvb, local_offset, 2, FALSE); local_offset +=2;

	*offset = local_offset;
}

/* Parse VENDOR - Parse a vendor specific or unknown header sequence */
/* IN: parentTree to add the dissection too - in this code the all_headers_tree */
/* IN: tvb - the data buffer from wireshark */
/* IN/OUT: The current and updated offset */
static void
parse_VENDOR(proto_tree * parentTree, tvbuff_t *tvb, gint *offset)
{
	gint local_offset = *offset;
	/* IETH - Invalidate Extended Transport Header */
	proto_tree *VENDOR_header_tree = NULL;
	proto_item *VENDOR_header_item = NULL;

	VENDOR_header_item = proto_tree_add_item(parentTree, hf_infiniband_vendor, tvb, local_offset, 4, FALSE);
	proto_item_set_text(VENDOR_header_item, "%s", "Vendor Specific or Unknown Header Sequence");
	VENDOR_header_tree = proto_item_add_subtree(VENDOR_header_item, ett_infiniband);

	proto_tree_add_item(VENDOR_header_tree, hf_infiniband_vendor,	tvb, local_offset, -1, FALSE);

	*offset = local_offset;
}


