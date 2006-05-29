/* packet-olsr.c
 * Routines for OLSR (IPv4 & IPv6 compatible) RFC parsing
 * Compatible with RFC-compliant OLSR implementations such as
 * NRLOLSRD (http://pf.itd.nrl.navy.mil/projects/olsr/).
 * Parser created by Aaron Woo <woo@itd.nrl.navy.mil> of
 * the Naval Research Laboratory
 * Currently maintained by Jeff Weston <weston@itd.nrl.navy.mil>.
 *
 * http://www.ietf.org/rfc/rfc3626.txt
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

#include <epan/packet.h>

#define UDP_PORT_OLSR	698
#define HELLO	1
#define TC	2
#define MID	3
#define HNA	4

/* Initialize the protocol and registered fields */
static int proto_olsr = -1;
static int hf_olsr_packet_len = -1;
static int hf_olsr_packet_seq_num = -1;
static int hf_olsr_message_type = -1;
static int hf_olsr_vtime = -1;
static int hf_olsr_message_size = -1;
static int hf_olsr_ttl = -1;
static int hf_olsr_hop_count = -1;
static int hf_olsr_message_seq_num = -1;

static int hf_olsr_htime = -1;
static int hf_olsr_willingness = -1;

static int hf_olsr_link_type = -1;
static int hf_olsr_link_message_size = -1;
static int hf_olsr_ansn = -1;

static int hf_olsr_origin_addr = -1;
static int hf_olsr_neighbor_addr = -1;
static int hf_olsr_interface_addr = -1;
static int hf_olsr_netmask	= -1;
static int hf_olsr_network_addr = -1;
static int hf_olsr_origin6_addr = -1;
static int hf_olsr_neighbor6_addr = -1;
static int hf_olsr_interface6_addr = -1;
static int hf_olsr_netmask6 = -1;
static int hf_olsr_network6_addr = -1;

static int hf_olsr_data = -1;

/* Initialize the subtree pointers*/
static gint ett_olsr = -1;

static const value_string message_type_vals[] = {
	{ HELLO, "HELLO" },
	{ TC,    "TC" },
	{ MID,   "MID" },
	{ HNA,   "HNA" },
	{ 0,     NULL }
};

/*------------------------- Packet Dissecting Code-------------------------*/
static int
dissect_olsr(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *olsr_tree;
        
	int offset, link_message_size, message_size, message_len, message_type, packet_size, position;
	int high_bits, low_bits, vtime, htime;
	double Vtime, Htime;
	
	guint16 packet_len;
	
	/* Does this packet have a valid message type at the beginning? */
	if (!tvb_bytes_exist(tvb, 0, 2))
		return 0;	/* not enough bytes for the packet length */
	packet_len = tvb_get_ntohs(tvb, 0);
	if (packet_len < 4)
		return 0;	/* length not enough for a packet header */
	if (packet_len > 4) {
		/*
		 * The packet claims to have more than just a packet
		 * header.
		 */
		if (packet_len < 8) {
			/*
			 * ...but it doesn't claim to have enough for
			 * a full message header.
			 */
			return 0;
		}

		/*
		 * OK, let's look at the type of the first message and
		 * at its size field.
		 */
		if (!tvb_bytes_exist(tvb, 4, 4))
			return 0;	/* not enough bytes for them */
		/* OK, what about the message length? */
		message_len = tvb_get_ntohs(tvb, 4+2);
		if (message_len < 4)
			return 0;	/* length not enough for a message header */
	}

	/*-------------Setting the Protocol and Info Columns in the Wireshark Display----------*/
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "UDP");
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_clear(pinfo->cinfo, COL_INFO);

	if (check_col(pinfo->cinfo, COL_INFO) && (pinfo->src.type==AT_IPv4))
		col_add_fstr(pinfo->cinfo, COL_INFO, "OLSR (IPv4) Packet,  Length: %u Bytes", packet_len);
	else if(check_col(pinfo->cinfo, COL_INFO) && (pinfo->src.type==AT_IPv6))
		col_add_fstr(pinfo->cinfo, COL_INFO, "OLSR (IPv6) Packet,  Length: %u Bytes", packet_len);

/*-----------------------------------------------------Fetching Info from IPv4 Packet and Adding to Tree-------------------------------------------*/
	if (tree && (pinfo->src.type==AT_IPv4)) {
		ti = proto_tree_add_item(tree, proto_olsr, tvb, 0, -1, FALSE);
		olsr_tree = proto_item_add_subtree(ti, ett_olsr);

		proto_tree_add_uint_format(olsr_tree, hf_olsr_packet_len, tvb, 0, 2, packet_len, "Packet Length: %u bytes", packet_len);
		proto_tree_add_item(olsr_tree, hf_olsr_packet_seq_num, tvb, 2, 2, FALSE);
		
		packet_size = (packet_len - 4) / 4;
		position = 4;

		while(packet_size>0)   {
			message_type = tvb_get_guint8(tvb, position);
			proto_tree_add_uint(olsr_tree, hf_olsr_message_type, tvb, position, 1, message_type);
			
			/*-------------Dissect Validity Time-------------------------*/
			vtime = tvb_get_guint8(tvb, position+1);
			high_bits = ((vtime & 0xF0) >> 4);
			low_bits = (vtime & 0x0F);
			Vtime = ((1<<low_bits)/16.0)*(1+(high_bits/16.0));
			proto_tree_add_double_format(olsr_tree, hf_olsr_vtime, tvb, position+1, 1, Vtime, "Validity Time: %.3f (in seconds)", Vtime);
			
			/*-------------Dissect Message Size---------------------------*/
			message_len = tvb_get_ntohs(tvb, position+2);
			if (message_len < 4) {
				proto_tree_add_uint_format(olsr_tree, hf_olsr_message_size, tvb, position+2, 2, message_len,"Message Size: %u bytes (too short, must be >= 4)", message_len);
				break;
			}
			proto_tree_add_uint_format(olsr_tree, hf_olsr_message_size, tvb, position+2, 2, message_len,"Message Size: %u bytes", message_len);
			
			packet_size--;
			message_size = (message_len - 4) /4;
			offset = position + 4;
			position = offset;
			
			/*-----------------Dissecting: Origin Addr, TTL, Hop Count, and Message Seq Number*/
			if(message_size > 0)	{
				proto_tree_add_item(olsr_tree, hf_olsr_origin_addr, tvb, offset, 4, FALSE);
				message_size--;
				packet_size--;
				offset+=4;
			}
			if(message_size > 0)	{
				proto_tree_add_item(olsr_tree, hf_olsr_ttl, tvb, offset, 1, FALSE);
				proto_tree_add_item(olsr_tree, hf_olsr_hop_count, tvb, offset+1, 1, FALSE);
				proto_tree_add_item(olsr_tree, hf_olsr_message_seq_num, tvb, offset+2, 2, FALSE);
				message_size--;
				packet_size--;
				offset+=4;
			}
			
			position = offset;
			
			/* --------------Dissecting TC message--------------------- */
			if(message_size>0 && message_type == TC)   {
				proto_tree_add_item(olsr_tree, hf_olsr_ansn, tvb, offset, 2, FALSE);

				offset+=4;
				message_size--;
				packet_size--;

				while(message_size>0)  {
					proto_tree_add_item(olsr_tree, hf_olsr_neighbor_addr, tvb, offset, 4, FALSE);
					message_size--;
					offset+=4;
					packet_size--;
					}
				position = offset;
			}

			/* -------------Dissect HELLO message----------------------- */
			else if(message_size>0 && message_type == HELLO)  {
				/*---------------------Dissect Hello Emission Invertal-------------------*/
				htime = tvb_get_guint8(tvb, offset+2);
				high_bits = ((htime & 0xF0) >> 4);
				low_bits = (htime & 0x0F);
				Htime = ((1<<low_bits)/16.0)*(1+(high_bits/16.0));
				proto_tree_add_double_format(olsr_tree, hf_olsr_htime, tvb, offset+2, 1, Htime, "Hello Emission Interval: %.3f (in seconds)", Htime);
				
				/*-------------------------Dissect Willingness---------------------------*/
				switch(tvb_get_guint8(tvb, offset+3))	{
					case 0:
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Never");
						break;
					case 1:
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Low");
						break;
					case 3:
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Default");
						break;
					case 6:
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: High");
						break;
					case 7:	
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Always");
						break;
					default :
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Invalid!");
						break;
				}/* end switch Willingness */
				
				offset+=4;
				message_size--;
				packet_size--;
				
				while(message_size>0)   {
					/*------------------------------Dissect Link Type---------------------------------- */
					switch(tvb_get_guint8(tvb, offset))	{
						case 0:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Unspecified Link");
							break;
						case 1:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Asymmetric Link");
							break;
						case 6:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Symmetric Link");
							break;
						case 3:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Lost Link");
							break;
						case 10:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: MPR Link");
							break;
						case 5:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Pending");
							break;
						default:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Invalid");
							break;
					}/* end switch Link Type */

					/*----------------------Dissect Link Message Size--------------------------*/
					proto_tree_add_uint_format(olsr_tree, hf_olsr_link_message_size, tvb, offset+2, 2, tvb_get_ntohs(tvb, offset+2), "Link Message Size: %u bytes", tvb_get_ntohs(tvb, offset+2));

					link_message_size = (tvb_get_ntohs(tvb, offset+2) - 4) / 4;
					offset+=4;
					message_size--;
					packet_size--;
											
					/*-------------------Dissect Neighbor Addresses--------------------*/
					while(link_message_size>0)   {
						proto_tree_add_item(olsr_tree, hf_olsr_neighbor_addr, tvb, offset, 4, FALSE);
						offset+=4;
						message_size--;
						packet_size--;
						link_message_size--;
					} /* end while */
				} /* end while */
				position = offset;
			} /* end if for Hello */
			/*---------------------------------Dissect MID Message----------------------------------*/
			else if(message_size>0 && message_type==MID)	{
				while(message_size>0)	{
					proto_tree_add_item(olsr_tree, hf_olsr_interface_addr, tvb, offset, 4, FALSE);
					message_size--;
					offset+=4;
					packet_size--;
				} /* end while for MID */
				position = offset;
			} /* end if for MID */
			/*-----------------------------Dissect HNA Message--------------------------------*/
			else if(message_size>0 && message_type==HNA)	{
				while(message_size>0)	{
					proto_tree_add_item(olsr_tree, hf_olsr_network_addr, tvb, offset, 4, FALSE);
					message_size--;
					packet_size--;
					offset+=4;
					proto_tree_add_item(olsr_tree, hf_olsr_netmask, tvb, offset, 4, FALSE);
					message_size--;
					packet_size--;
					offset+=4;
				} /* end while for HNA */
				position = offset;
			} /* end if for HNA */
			/*-----------------------------Undefined message types-----------------------------*/
			else if(message_size>0) {
				if((message_len-12)%4) {
					proto_tree_add_bytes_format(olsr_tree, hf_olsr_data, tvb, position, 1, tvb_get_ptr(tvb, position, 1), "Data (%u bytes) (must be aligned on 32 bits)", message_len-12);
					break;
				}
				proto_tree_add_bytes_format(olsr_tree, hf_olsr_data, tvb, position, message_len-12, tvb_get_ptr(tvb, position, message_len-12), "Data (%u bytes)", message_len-12);
				packet_size -= (message_len-12)/4;
				message_size = 0;
				offset += message_len-12;
				position = offset;
			} /* end if for undefined message types */
			
		} /* end while for message alive */
	} /* end if for IPV4 */


/*-----------------------------------------------------Fetching Info from IPv6 Packet and Adding to Tree-------------------------------------------------*/
	if (tree && (pinfo->src.type==AT_IPv6)) {
		ti = proto_tree_add_item(tree, proto_olsr, tvb, 0, -1, FALSE);
		olsr_tree = proto_item_add_subtree(ti, ett_olsr);

		proto_tree_add_uint_format(olsr_tree, hf_olsr_packet_len, tvb, 0, 2, packet_len, "Packet Length: %u bytes", packet_len);
		proto_tree_add_item(olsr_tree, hf_olsr_packet_seq_num, tvb, 2, 2, FALSE);

		
		packet_size = (packet_len - 4) / 4;
		position = 4;

		while(packet_size>0)   {
			message_type = tvb_get_guint8(tvb, position);
			proto_tree_add_uint(olsr_tree, hf_olsr_message_type, tvb, position, 1, message_type);

			/*-------------Dissect Validity Time-------------------------*/
			vtime = tvb_get_guint8(tvb, position+1);
			high_bits = ((vtime & 0xF0) >> 4);
			low_bits = (vtime & 0x0F);
			Vtime = ((1<<low_bits)/16.0)*(1.0+(high_bits/16.0));
			proto_tree_add_double_format(olsr_tree, hf_olsr_vtime, tvb, position+1, 1, Vtime, "Validity Time: %.3f (in seconds)", Vtime);
				 
			/*-------------Dissect Message Size---------------------------*/
			message_len = tvb_get_ntohs(tvb, position+2);
			if (message_len < 4) {
				proto_tree_add_uint_format(olsr_tree, hf_olsr_message_size, tvb, position+2, 2, message_len,"Message Size: %u bytes (too short, must be >= 4)", message_len);
				break;
			}
			proto_tree_add_uint_format(olsr_tree, hf_olsr_message_size, tvb, position+2, 2, message_len,"Message Size: %u bytes", message_len);
			
			packet_size--;
			message_size = (message_len - 4) /4;

			offset = position + 4;
			position = offset;

			/*-----------------Dissecting: Origin Addr, TTL, Hop Count, and Message Seq Number */
			if(message_size > 0)	{
				proto_tree_add_item(olsr_tree, hf_olsr_origin6_addr, tvb, offset, 16, FALSE);
				offset+=16;
				message_size-=4;
				packet_size-=4;
			}
			if(message_size > 0)	{
				proto_tree_add_item(olsr_tree, hf_olsr_ttl, tvb, offset, 1, FALSE);
				proto_tree_add_item(olsr_tree, hf_olsr_hop_count, tvb, offset+1, 1, FALSE);
				proto_tree_add_item(olsr_tree, hf_olsr_message_seq_num, tvb, offset+2, 2, FALSE);
				message_size--;
				packet_size--;
				offset+=4;
			}
	
			position = offset;
			
			/* --------------Dissecting TC message--------------------- */
			if(message_size>0 && message_type == TC)   {
				proto_tree_add_item(olsr_tree, hf_olsr_ansn, tvb, offset, 2, FALSE);

				offset+=4;
				message_size--;
				packet_size--;

				while(message_size>0)  {
					proto_tree_add_item(olsr_tree, hf_olsr_neighbor6_addr, tvb, offset, 16, FALSE);
					message_size-=4;
					offset+=16;
					packet_size-=4;
					}
				position = offset;
			}

			/* -------------Dissect HELLO message----------------------- */
			else if(message_size>0 && message_type == HELLO)  {
				/*---------------------Dissect Hellow Emission Invertal-------------------*/
				htime = tvb_get_guint8(tvb, offset+2);
				high_bits = ((htime & 0xF0) >> 4);
				low_bits = (htime & 0x0F);
				Htime = ((1<<low_bits)/16.0)*(1.0+(high_bits/16.0));
				proto_tree_add_double_format(olsr_tree, hf_olsr_htime, tvb, offset+2, 1, Htime, "Hello Emission Interval: %.3f (in seconds)", Htime);

				/*---------------------Dissect Willingness----------------------------------*/
				switch(tvb_get_guint8(tvb, offset+3))	{
					case 0:
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Never");
						break;
					case 1:
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Low");
						break;
					case 3:
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Default");
						break;
					case 6:
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: High");
						break;
					case 7:	
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Always");
						break;
					default :
						proto_tree_add_uint_format(olsr_tree, hf_olsr_willingness, tvb, offset+3, 1, tvb_get_guint8(tvb, offset+2), "Willingness: Invalid!");
						break;
				} /* end switch for willingness */
				
				offset+=4;
				message_size--;
				packet_size--;
				
				while(message_size>0)   {
					/*----------------------Dissect Link Type------------------------------------*/
					switch(tvb_get_guint8(tvb, offset))	{
						case 0:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Unspecified Link");
							break;
						case 1:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Asymmetric Link");
							break;
						case 6:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Symmetric Link");
							break;
						case 3:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Lost Link");
							break;
						case 10:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: MPR Link");
							break;
						case 5:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Pending");
							break;
						default:
							proto_tree_add_uint_format(olsr_tree, hf_olsr_link_type, tvb, offset, 1, tvb_get_guint8(tvb, offset), "Link Type: Invalid");
							break;
					} /* end switch Link Type */
				
					/*-------------------------Dissect Link Message Size-----------------------------*/
					proto_tree_add_uint_format(olsr_tree, hf_olsr_link_message_size, tvb, offset+2, 2, tvb_get_ntohs(tvb, offset+2), "Link Message Size: %u bytes", tvb_get_ntohs(tvb, offset+2));

					link_message_size = (tvb_get_ntohs(tvb, offset+2) - 4) / 4;
					offset+=4;
					message_size--;
					packet_size--;
											
					/*--------------------------Dissect Neighbor Addresses---------------------------*/
					while(link_message_size>0)   {
						proto_tree_add_item(olsr_tree, hf_olsr_neighbor6_addr, tvb, offset, 16, FALSE);
						offset+=16;
						message_size-=4;
						packet_size-=4;
						link_message_size-=4;
					} /* end while */
				} /* end while */
				position = offset;
			} /* end if for Hello */
			/*---------------------------------Dissect MID Message----------------------------------*/
			else if(message_size>0 && message_type==MID)	{
				while(message_size>0)	{
					proto_tree_add_item(olsr_tree, hf_olsr_interface6_addr, tvb, offset, 16, FALSE);
					message_size-=4;
					offset+=16;
					packet_size-=4;
				} /* end while for MID */
				position = offset;
			} /* end if for MID */
			/*-----------------------------Dissect HNA Message--------------------------------*/
			else if(message_size>0 && message_type==HNA)	{
				while(message_size>0)	{
					proto_tree_add_item(olsr_tree, hf_olsr_network6_addr, tvb, offset, 16, FALSE);
					offset+=16;
					message_size-=4;
					packet_size-=4;
					proto_tree_add_item(olsr_tree, hf_olsr_netmask6, tvb, offset, 16, FALSE);
					message_size-=4;
					packet_size-=4;
					offset+=16;
				} /* end while for HNA */
				position = offset;
			} /* end if for HNA */
			/*-----------------------------Undefined message types-----------------------------*/
			else if(message_size>0) {
				if((message_len-24)%4) {
					proto_tree_add_bytes_format(olsr_tree, hf_olsr_data, tvb, position, 1, tvb_get_ptr(tvb, position, 1), "Data (%u bytes) (must be aligned on 32 bits)", message_len-24);
					break;
				}
				proto_tree_add_bytes_format(olsr_tree, hf_olsr_data, tvb, position, message_len-24, tvb_get_ptr(tvb, position, message_len-24), "Data (%u bytes)", message_len-24);
				packet_size -= (message_len-24)/4;
				message_size = 0;
				offset += message_len-24;
				position = offset;
			} /* end if for undefined message types */
		} /* end while for message alive */
	} /* end if for IPV6 */
	return tvb_length(tvb);
} /* end Dissecting */
	
/*-----------Register the Dissector for OLSR--------------*/
void
proto_register_olsr(void)
{                 
	static hf_register_info hf[] = {
		{ &hf_olsr_packet_len,
			{ "Packet Length", "olsr.packet_len",
			   FT_UINT16, BASE_DEC, NULL, 0,          
			  "Packet Length in Bytes", HFILL }},

		{ &hf_olsr_packet_seq_num,
			{ "Packet Sequence Number", "olsr.packet_seq_num",
			   FT_UINT16, BASE_DEC, NULL, 0,
			  "Packet Sequence Number", HFILL }},

		{ &hf_olsr_message_type,
			{ "Message Type", "olsr.message_type",
			   FT_UINT8, BASE_DEC, VALS(message_type_vals), 0,
			  "Message Type", HFILL }},

		{ &hf_olsr_message_size,
			{ "Message", "olsr.message_size",
			   FT_UINT16, BASE_DEC, NULL, 0,          
			  "Message Size in Bytes", HFILL }},

		{ &hf_olsr_message_seq_num,
			{ "Message Sequence Number", "olsr.message_seq_num",
			   FT_UINT16, BASE_DEC, NULL, 0,          
			  "Message Sequence Number", HFILL }},

		{ &hf_olsr_vtime,
			{ "Validity Time", "olsr.vtime",
			   FT_DOUBLE, BASE_NONE, NULL, 0,
			  "Validity Time", HFILL }},
		
		{ &hf_olsr_ansn,
			{ "Advertised Neighbor Sequence Number (ANSN)", "olsr.ansn",
			   FT_UINT16, BASE_DEC, NULL, 0,
			  "Advertised Neighbor Sequence Number (ANSN)", HFILL }},

		{ &hf_olsr_htime,
			{ "Hello emission interval", "olsr.htime",
		 	   FT_DOUBLE, BASE_NONE, NULL, 0,
			  "Hello emission interval", HFILL }},

		{ &hf_olsr_willingness,
			{ "Willingness to Carry and Forward", "olsr.willingness",
			   FT_UINT8, BASE_DEC, NULL, 0,
			  "Willingness to Carry and Forward", HFILL }},
			  
		{ &hf_olsr_ttl,
			{ "Time to Live", "olsr.ttl",
			   FT_UINT8, BASE_DEC, NULL, 0,
			  "Time to Live", HFILL }},
			  			  
		{ &hf_olsr_link_type,
			{ "Link Type", "olsr.link_type",
			   FT_UINT8, BASE_DEC, NULL, 0,
			  "Link Type", HFILL }},

		{ &hf_olsr_link_message_size,
			{ "Link Message Size", "olsr.link_message_size",
			   FT_UINT16, BASE_DEC, NULL, 0,
			  "Link Message Size", HFILL }},

		{ &hf_olsr_hop_count,
			{ "Hop Count", "olsr.hop_count",
			   FT_UINT8, BASE_DEC, NULL, 0,
			  "Hop Count", HFILL }},

		{ &hf_olsr_origin_addr,
			{ "Originator Address", "olsr.origin_addr",
			   FT_IPv4, BASE_NONE, NULL, 0,
			  "Originator Address", HFILL }},

		{ &hf_olsr_neighbor_addr,
			{ "Neighbor Address", "olsr.neighbor_addr",
			   FT_IPv4, BASE_NONE, NULL, 0,
			  "Neighbor Address", HFILL }},

		
		{ &hf_olsr_network_addr,
			{ "Network Address", "olsr.network_addr",
			   FT_IPv4, BASE_NONE, NULL, 0,
			  "Network Address", HFILL }},

	        { &hf_olsr_interface_addr,
			{ "Interface Address", "olsr.interface_addr",
			   FT_IPv4, BASE_NONE, NULL, 0,
			  "Interface Address", HFILL }},

		{ &hf_olsr_netmask,
			{ "Netmask", "olsr.netmask",
			   FT_IPv4, BASE_NONE, NULL, 0,
			  "Netmask", HFILL }},
			  
		{ &hf_olsr_origin6_addr,
			{ "Originator Address", "olsr.origin6_addr",
			   FT_IPv6, BASE_NONE, NULL, 0,
			  "Originator Address", HFILL }},

		{ &hf_olsr_neighbor6_addr,
			{ "Neighbor Address", "olsr.neighbor6_addr",
			   FT_IPv6, BASE_NONE, NULL, 0,
			  "Neighbor Address", HFILL }},

		{ &hf_olsr_network6_addr,
			{ "Network Address", "olsr.network6_addr",
			   FT_IPv6, BASE_NONE, NULL, 0,
			  "Network Address", HFILL }},

	        { &hf_olsr_interface6_addr,
			{ "Interface Address", "olsr.interface6_addr",
			   FT_IPv6, BASE_NONE, NULL, 0,
			  "Interface Address", HFILL }},

		{ &hf_olsr_netmask6,
			{ "Netmask", "olsr.netmask6",
			   FT_IPv6, BASE_NONE, NULL, 0,
			  "Netmask", HFILL }},

		{ &hf_olsr_data,
			{ "Data", "olsr.data",
			   FT_BYTES, BASE_HEX, NULL, 0,
			  "Data", HFILL }},
	};


	static gint *ett[] = {
		&ett_olsr,
	};


	proto_olsr = proto_register_protocol("Optimized Link State Routing Protocol",
	    "OLSR", "olsr");

	proto_register_field_array(proto_olsr, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_olsr(void)
{
	dissector_handle_t olsr_handle;

	olsr_handle = new_create_dissector_handle(dissect_olsr, proto_olsr);
	dissector_add("udp.port", UDP_PORT_OLSR, olsr_handle);
}
