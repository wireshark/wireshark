/* packet-icp.c
 * Routines for ICP (internet cache protocol) packet disassembly
 * RFC 2186 && RFC 2187
 *
 * $Id: packet-icp.c,v 1.10 2000/08/07 03:20:38 guy Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Peter Torvals
 * Copyright 1999 Peter Torvals

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

#define MAX_TEXTBUF_LENGTH 600
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <stdio.h>
#include <stdlib.h> 
#include <glib.h>
#include "packet.h"
#include "resolv.h"

static int proto_icp=-1;
static int hf_icp_length=-1;
static int hf_icp_opcode=-1;
static int hf_icp_version=-1;
static int hf_icp_request_nr=-1;

static gint ett_icp = -1;
static gint ett_icp_payload = -1;

#define UDP_PORT_ICP    3130

#define CODE_ICP_OP_QUERY 1
#define CODE_ICP_OP_INVALID 0
#define CODE_ICP_OP_HIT 2
#define CODE_ICP_OP_MISS 3
#define CODE_ICP_OP_ERR 4
#define CODE_ICP_OP_SEND 5
#define CODE_ICP_OP_SENDA 6
#define CODE_ICP_OP_DATABEG 7
#define CODE_ICP_OP_DATA 8
#define CODE_ICP_OP_DATAEND 9
#define CODE_ICP_OP_SECHO 10
#define CODE_ICP_OP_DECHO 11
#define CODE_ICP_OP_MISS_NOFETCH 21
#define CODE_ICP_OP_DENIED 22
#define CODE_ICP_OP_HIT_OBJ 23

static value_string opcode_vals[] = {
{ CODE_ICP_OP_INVALID ,    "ICP_INVALID" },
{ CODE_ICP_OP_QUERY ,    "ICP_QUERY" },
{ CODE_ICP_OP_HIT ,    "ICP_HIT" },
{ CODE_ICP_OP_MISS ,    "ICP_MISS" },
{ CODE_ICP_OP_ERR ,    "ICP_ERR" },
{ CODE_ICP_OP_SEND,    "ICP_SEND" },
{ CODE_ICP_OP_SENDA, "ICP_SENDA"},
{ CODE_ICP_OP_DATABEG, "ICP_DATABEG"},
{ CODE_ICP_OP_DATA,    "ICP_DATA"},
{ CODE_ICP_OP_DATAEND, "ICP_DATA_END"}, 
{ CODE_ICP_OP_SECHO ,    "ICP_SECHO"},
{ CODE_ICP_OP_DECHO ,    "ICP_DECHO"},
{ CODE_ICP_OP_MISS_NOFETCH ,    "ICP_MISS_NOFETCH"},
{ CODE_ICP_OP_DENIED ,    "ICP_DENIED"},
{ CODE_ICP_OP_HIT_OBJ ,    "ICP_HIT_OBJ"},
{ 0,     NULL}
};



typedef struct _e_icphdr
{
  guint8 opcode;
  guint8 version;
  guint16 message_length;
  guint32 request_number;
  guint32 options;
  guint32 option_data;
  gchar sender_address[4];
} e_icphdr;

static gchar textbuf[MAX_TEXTBUF_LENGTH];

static void dissect_icp_payload( const u_char *pd, int offset,
        frame_data *fd,proto_tree *pload_tree, e_icphdr *icph)
{
/* To Be Done take care of fragmentation*/
guint32 maxlength=END_OF_FRAME;
guint32 i;
guint16 objectlength;
  switch(icph->opcode)
  {
	case CODE_ICP_OP_QUERY:
	 	/* 4 byte requester host address */
		proto_tree_add_text(pload_tree, NullTVB,offset,4,
			"Requester Host Address %u.%u.%u.%u",
			(guint8)pd[offset],
			(guint8)pd[offset+1],
			(guint8)pd[offset+2],
			(guint8)pd[offset+3]);

		/* null terminated URL */
		for (i=0; i < maxlength && 
			pd[offset+4+i] != 0 && i<(MAX_TEXTBUF_LENGTH-1);i++)
 		{
			textbuf[i]=pd[offset+4+i];
		}
		textbuf[i]=0;
		i++;
		proto_tree_add_text(pload_tree, NullTVB, offset+4,i,
			"URL: %s", textbuf);
		break;
	case CODE_ICP_OP_HIT_OBJ:
		/* null terminated url */
		for (i=0; i < maxlength && 
			pd[offset+i] != 0 && i<(MAX_TEXTBUF_LENGTH-1);i++)
 		{
			textbuf[i]=pd[offset+i];
		}
		textbuf[i]=0;
		i++;
		proto_tree_add_text(pload_tree, NullTVB, offset,i,
			"URL: %s", textbuf);
		/* 2 byte object size */
		/* object data not recommended by standard*/
		objectlength=pntohs(&pd[offset]);
		proto_tree_add_text(pload_tree, NullTVB,offset,2,"object length: %u", objectlength);
		/* object data not recommended by standard*/
		proto_tree_add_text(pload_tree, NullTVB,offset+2, maxlength-2,"object data");
		if (objectlength > maxlength-2)
		{
			proto_tree_add_text(pload_tree, NullTVB,offset,0,
				"Packet is fragmented, rest of object is in next udp packet");
		}
	case CODE_ICP_OP_MISS:
	case CODE_ICP_OP_HIT:
		for (i=0; i < maxlength && 
			pd[offset+i] != 0 && i<(MAX_TEXTBUF_LENGTH-1);i++)
 		{
			textbuf[i]=pd[offset+i];
		}
		textbuf[i]=0;
		i++;
		proto_tree_add_text(pload_tree, NullTVB, offset,i,
			"URL: %s", textbuf);	
	default: 
		/* check for fragmentation and add message if next part
			 of payload in next fragment*/
		break;
  }
}

static void dissect_icp(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
  proto_tree *icp_tree , *payload_tree;
  proto_item *ti , *payloadtf;
  e_icphdr icph;

  gchar *opcodestrval;

/* TBD: check if this is a fragment or first part of udp packet */
  icph.opcode=pd[offset];
  icph.version=pd[offset+1];
  icph.message_length=pntohs(&(pd[offset+2]));
  icph.request_number=pntohl(&(pd[offset+4]));
  memcpy(&icph.options,&pd[offset+8],sizeof(guint32));
  memcpy(&icph.option_data,&pd[offset+12],sizeof(guint32));
  memcpy(icph.sender_address,&pd[offset+16],4);


  opcodestrval =  match_strval(icph.opcode,opcode_vals);

  if (opcodestrval == NULL ) opcodestrval= "UNKNOWN OPCODE";

  sprintf(textbuf,"opc: %s(%u), Req Nr: %u", opcodestrval,
		(guint16)icph.opcode,icph.request_number);

  if (check_col(fd, COL_PROTOCOL))
        col_add_str(fd, COL_PROTOCOL, "ICP");

  if (check_col(fd, COL_INFO))
  {
        col_add_fstr(fd,COL_INFO,textbuf);
  }

  if (tree)
  {

        ti = proto_tree_add_item(tree,proto_icp, NullTVB,offset,END_OF_FRAME, FALSE);

        icp_tree = proto_item_add_subtree(ti, ett_icp);
        proto_tree_add_uint_format(icp_tree,hf_icp_opcode, NullTVB, offset,      1,
               icph.opcode, "Opcode:0x%01x (%s)",icph.opcode, opcodestrval);

        proto_tree_add_uint_format(icp_tree,hf_icp_version, NullTVB, offset+1, 1,
                icph.version,"Version: 0x%01x (%d)", icph.version, (int)icph.version);

        proto_tree_add_uint_format(icp_tree,hf_icp_length, NullTVB, offset+2, 2,
                icph.message_length,
		"Length: 0x%02x (%d)", icph.message_length,(int)icph.message_length);
        proto_tree_add_uint_format(icp_tree,hf_icp_request_nr, NullTVB, offset+4, 4,
                icph.request_number,
		"Request Number: 0x%04x (%u)", icph.request_number,icph.request_number);
		
	if ( (icph.opcode == CODE_ICP_OP_QUERY) && ((icph.options & 0x80000000 ) != 0) )
	{
		proto_tree_add_text(icp_tree, NullTVB,offset+8,4,
			"option: ICP_FLAG_HIT_OBJ");
  	}
	if ( (icph.opcode == CODE_ICP_OP_QUERY)&& ((icph.options & 0x40000000 ) != 0) )
	{
		proto_tree_add_text(icp_tree, NullTVB,offset+8,4,
			"option:ICP_FLAG_SRC_RTT");
  	}
	if ((icph.opcode != CODE_ICP_OP_QUERY)&& ((icph.options & 0x40000000 ) != 0))
	{
		proto_tree_add_text(icp_tree, NullTVB,offset+8,8,
			"option: ICP_FLAG_SCR_RTT RTT=%u", icph.option_data & 0x0000ffff);
	}
	
	proto_tree_add_text(icp_tree, NullTVB,offset+16, 4, 
			"Sender Host IP address %u.%u.%u.%u",
			(guint8)icph.sender_address[0],
			(guint8)icph.sender_address[1],
			(guint8)icph.sender_address[2],
			(guint8)icph.sender_address[3]);

        payloadtf = proto_tree_add_text(icp_tree, NullTVB,
                        offset+20,icph.message_length - 20,
                        "Payload");
        payload_tree = proto_item_add_subtree(payloadtf, ett_icp_payload);

        if (payload_tree !=NULL)
        {
                dissect_icp_payload( pd,
                                20+offset,fd,payload_tree,&icph);
        }
  }
}
void
proto_register_icp(void)
{
	static hf_register_info hf[] = {
		{ &hf_icp_opcode,
		{ "Opcode","icp.opcode", FT_UINT8, BASE_HEX, NULL, 0x0,
			"" }},

		{ &hf_icp_version,
		{ "Version",	"icp.version", FT_UINT8, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_icp_length,
		{ "Length","icp.length", FT_UINT16, BASE_DEC, NULL, 0x0,
			"" }},

		{ &hf_icp_request_nr,
		{ "Request Number","icp.nr", FT_UINT32, BASE_DEC, NULL, 0x0,
			"" }},
	};
	static gint *ett[] = {
		&ett_icp,
		&ett_icp_payload,
	};

	proto_icp = proto_register_protocol ("Internet Cache Protocol", "icp");
	proto_register_field_array(proto_icp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_icp(void)
{
	old_dissector_add("udp.port", UDP_PORT_ICP, dissect_icp);
}
