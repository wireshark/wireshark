/* packet-tftp.c
 * Routines for tftp packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 * Craig Newell <CraigN@cheque.uq.edu.au>
 *	RFC2347 TFTP Option Extension
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-bootp.c
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

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

static int proto_tftp = -1;
static int hf_tftp_opcode = -1;
static int hf_tftp_source_file = -1;
static int hf_tftp_destination_file = -1;
static int hf_tftp_transfer_type = -1;
static int hf_tftp_blocknum = -1;
static int hf_tftp_error_code = -1;
static int hf_tftp_error_string = -1;

static gint ett_tftp = -1;

static dissector_handle_t tftp_handle;

#define UDP_PORT_TFTP    69

#define	TFTP_RRQ	1
#define	TFTP_WRQ	2
#define	TFTP_DATA	3
#define	TFTP_ACK	4
#define	TFTP_ERROR	5
#define	TFTP_OACK	6

static const value_string tftp_opcode_vals[] = {
  { TFTP_RRQ,   "Read Request" },
  { TFTP_WRQ,   "Write Request" },
  { TFTP_DATA,  "Data Packet" },
  { TFTP_ACK,   "Acknowledgement" },
  { TFTP_ERROR, "Error Code" },
  { TFTP_OACK,  "Option Acknowledgement" },
  { 0,          NULL }
};

static const value_string tftp_error_code_vals[] = {
  { 0, "Not defined" },
  { 1, "File not found" },
  { 2, "Access violation" },
  { 3, "Disk full or allocation exceeded" },
  { 4, "Illegal TFTP Operation" },
  { 5, "Unknown transfer ID" },
  { 6, "File already exists" },
  { 7, "No such user" },
  { 8, "Option negotiation failed" },
  { 0, NULL }
};

static void tftp_dissect_options(tvbuff_t *tvb, int offset, proto_tree *tree);

static void
dissect_tftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree	*tftp_tree = NULL;
	proto_item	*ti;
	conversation_t  *conversation;
	gint		offset = 0;
	guint16		opcode;
	guint16		bytes;
	guint16		blocknum;
	guint           i1;
	guint16         error;

	/*
	 * The first TFTP packet goes to the TFTP port; the second one
	 * comes from some *other* port, but goes back to the same
	 * IP address and port as the ones from which the first packet
	 * came; all subsequent packets go between those two IP addresses
	 * and ports.
	 *
	 * If this packet went to the TFTP port, we check to see if
	 * there's already a conversation with one address/port pair
	 * matching the source IP address and port of this packet,
	 * the other address matching the destination IP address of this
	 * packet, and any destination port.
	 *
	 * If not, we create one, with its address 1/port 1 pair being
	 * the source address/port of this packet, its address 2 being
	 * the destination address of this packet, and its port 2 being
	 * wildcarded, and give it the TFTP dissector as a dissector.
	 */
	if (pinfo->destport == UDP_PORT_TFTP) {
	  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					   pinfo->srcport, 0, NO_PORT_B);
	  if( (conversation == NULL) || (conversation->dissector_handle!=tftp_handle) ){
	    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					    pinfo->srcport, 0, NO_PORT2);
            conversation_set_dissector(conversation, tftp_handle);
	  }
	}

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "TFTP");

	opcode = tvb_get_ntohs(tvb, offset);

	if (check_col(pinfo->cinfo, COL_INFO)) {

	  col_add_fstr(pinfo->cinfo, COL_INFO, "%s",
	    val_to_str(opcode, tftp_opcode_vals, "Unknown (0x%04x)"));

	}

	if (tree) {

	  ti = proto_tree_add_item(tree, proto_tftp, tvb, offset, -1, FALSE);
	  tftp_tree = proto_item_add_subtree(ti, ett_tftp);

	  proto_tree_add_uint(tftp_tree, hf_tftp_opcode, tvb,
			    offset, 2, opcode);
	}
	offset += 2;

	switch (opcode) {

	case TFTP_RRQ:
	  i1 = tvb_strsize(tvb, offset);
	  if (tree) {
	    proto_tree_add_item(tftp_tree, hf_tftp_source_file,
			    tvb, offset, i1, FALSE);
	  }
	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
			    tvb_get_ptr(tvb, offset, i1));
	  }
	  offset += i1;

	  i1 = tvb_strsize(tvb, offset);
	  if (tree) {
	    ti = proto_tree_add_item(tftp_tree, hf_tftp_transfer_type,
			    tvb, offset, i1, FALSE);
	  }
	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
			    tvb_get_ptr(tvb, offset, i1));
	  }
	  offset += i1;

	  if (tree)
	    tftp_dissect_options(tvb, offset, tftp_tree);
	  break;

	case TFTP_WRQ:
	  i1 = tvb_strsize(tvb, offset);
	  if (tree) {
	    proto_tree_add_item(tftp_tree, hf_tftp_destination_file,
			    tvb, offset, i1, FALSE);
	  }
	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
			    tvb_get_ptr(tvb, offset, i1));
	  }
	  offset += i1;

	  i1 = tvb_strsize(tvb, offset);
	  if (tree) {
	    ti = proto_tree_add_item(tftp_tree, hf_tftp_transfer_type,
			    tvb, offset, i1, FALSE);
	  }
	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
			    tvb_get_ptr(tvb, offset, i1));
	  }
	  offset += i1;

	  if (tree)
	    tftp_dissect_options(tvb, offset, tftp_tree);
	  break;

	case TFTP_DATA:
	  blocknum = tvb_get_ntohs(tvb, offset);
	  if (tree) {
	    proto_tree_add_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
	    		    blocknum);
	  }
	  offset += 2;

	  bytes = tvb_reported_length_remaining(tvb, offset);

	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %i%s",
		    blocknum,
		    (bytes < 512)?" (last)":"" );
	  }

	  if (bytes != 0) {
	    if (tree) {
	      proto_tree_add_text(tftp_tree, tvb, offset, -1,
		"Data (%d bytes)", bytes);
	    }
	  }
	  break;

	case TFTP_ACK:
	  blocknum = tvb_get_ntohs(tvb, offset);
	  if (tree) {
	    proto_tree_add_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
	    		    blocknum);
	  }
	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %i",
			    blocknum);
	  }
	  break;

	case TFTP_ERROR:
	  error = tvb_get_ntohs(tvb, offset);
	  if (tree) {
	    proto_tree_add_uint(tftp_tree, hf_tftp_error_code, tvb, offset, 2,
			    error);
	  }
	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Code: %s",
			    val_to_str(error, tftp_error_code_vals, "Unknown (%u)"));
	  }
	  offset += 2;

	  i1 = tvb_strsize(tvb, offset);
	  if (tree) {
	    proto_tree_add_item(tftp_tree, hf_tftp_error_string, tvb, offset,
	        i1, FALSE);
	  }
	  if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_append_fstr(pinfo->cinfo, COL_INFO, ", Message: %s",
			    tvb_get_ptr(tvb, offset, i1));
	  }
	  break;

	case TFTP_OACK:
	  if (tree)
	    tftp_dissect_options(tvb, offset, tftp_tree);
	  break;

	default:
	  if (tree) {
	    proto_tree_add_text(tftp_tree, tvb, offset, -1,
		"Data (%d bytes)", tvb_reported_length_remaining(tvb, offset));
	  }
	  break;

	}
}

static void
tftp_dissect_options(tvbuff_t *tvb, int offset, proto_tree *tree)
{
	int option_len, value_len;
	int value_offset;

	while (tvb_offset_exists(tvb, offset)) {
	  option_len = tvb_strsize(tvb, offset);	/* length of option */
	  value_offset = offset + option_len;
	  value_len = tvb_strsize(tvb, value_offset);	/* length of value */
	  proto_tree_add_text(tree, tvb, offset, option_len+value_len,
	          "Option: %s = %s",
		  tvb_get_ptr(tvb, offset, option_len),
		  tvb_get_ptr(tvb, value_offset, value_len));
	  offset += option_len + value_len;
	}
}

void
proto_register_tftp(void)
{
  static hf_register_info hf[] = {
    { &hf_tftp_opcode,
      { "Opcode",	      "tftp.opcode",
	FT_UINT16, BASE_DEC, VALS(tftp_opcode_vals), 0x0,
      	"TFTP message type", HFILL }},

    { &hf_tftp_source_file,
      { "Source File",	      "tftp.source_file",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
      	"TFTP source file name", HFILL }},

    { &hf_tftp_destination_file,
      { "DESTINATION File",   "tftp.destination_file",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
      	"TFTP source file name", HFILL }},

    { &hf_tftp_transfer_type,
      { "Type",	              "tftp.type",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
      	"TFTP transfer type", HFILL }},

    { &hf_tftp_blocknum,
      { "Block",              "tftp.block",
	FT_UINT16, BASE_DEC, NULL, 0x0,
      	"Block number", HFILL }},

    { &hf_tftp_error_code,
      { "Error code",         "tftp.error.code",
	FT_UINT16, BASE_DEC, VALS(tftp_error_code_vals), 0x0,
      	"Error code in case of TFTP error message", HFILL }},

    { &hf_tftp_error_string,
      { "Error message",      "tftp.error.message",
	FT_STRINGZ, BASE_DEC, NULL, 0x0,
      	"Error string in case of TFTP error message", HFILL }}
  };
  static gint *ett[] = {
    &ett_tftp,
  };

  proto_tftp = proto_register_protocol("Trivial File Transfer Protocol",
				       "TFTP", "tftp");
  proto_register_field_array(proto_tftp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("tftp", dissect_tftp, proto_tftp);
}

void
proto_reg_handoff_tftp(void)
{
  tftp_handle = find_dissector("tftp");

  dissector_add("udp.port", UDP_PORT_TFTP, tftp_handle);
}
