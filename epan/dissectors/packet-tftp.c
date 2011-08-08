/* packet-tftp.c
 * Routines for tftp packet dissection
 *
 * Richard Sharpe <rsharpe@ns.aus.com>
 * Craig Newell <CraigN@cheque.uq.edu.au>
 *      RFC2347 TFTP Option Extension
 * Joerg Mayer (see AUTHORS file)
 *      RFC2348 TFTP Blocksize Option
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

/* Documentation:
 * RFC 1350: THE TFTP PROTOCOL (REVISION 2)
 * RFC 2090: TFTP Multicast Option
 *           (not yet implemented)
 * RFC 2347: TFTP Option Extension
 * RFC 2348: TFTP Blocksize Option
 * RFC 2349: TFTP Timeout Interval and Transfer Size Options
 *           (not yet implemented)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <stdlib.h>
#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/emem.h>
#include <epan/expert.h>
#include <epan/range.h>
#include <epan/prefs.h>

/* Things we may want to remember for a whole conversation */
typedef struct _tftp_conv_info_t {
	guint16 blocksize;
	gchar *source_file, *destination_file;
} tftp_conv_info_t;


static int proto_tftp = -1;
static int hf_tftp_opcode = -1;
static int hf_tftp_source_file = -1;
static int hf_tftp_destination_file = -1;
static int hf_tftp_transfer_type = -1;
static int hf_tftp_blocknum = -1;
static int hf_tftp_error_code = -1;
static int hf_tftp_error_string = -1;
static int hf_tftp_option_name = -1;
static int hf_tftp_option_value = -1;

static gint ett_tftp = -1;
static gint ett_tftp_option = -1;

static dissector_handle_t tftp_handle;
static dissector_handle_t data_handle;

#define UDP_PORT_TFTP_RANGE    "69"

void proto_reg_handoff_tftp (void);

/* User definable values */
static range_t *global_tftp_port_range;

#define	TFTP_RRQ	1
#define	TFTP_WRQ	2
#define	TFTP_DATA	3
#define	TFTP_ACK	4
#define	TFTP_ERROR	5
#define	TFTP_OACK	6
#define	TFTP_INFO	255

static const value_string tftp_opcode_vals[] = {
  { TFTP_RRQ,   "Read Request" },
  { TFTP_WRQ,   "Write Request" },
  { TFTP_DATA,  "Data Packet" },
  { TFTP_ACK,   "Acknowledgement" },
  { TFTP_ERROR, "Error Code" },
  { TFTP_OACK,  "Option Acknowledgement" },
  { TFTP_INFO,  "Information (MSDP)" },
  { 0,          NULL }
};

static const value_string tftp_error_code_vals[] = {
  { 0, "Not defined" },
  { 1, "File not found" },
  { 2, "Access violation" },
  { 3, "Disk full or allocation exceeded" },
  { 4, "Illegal TFTP Operation" },
  { 5, "Unknown transfer ID" },		/* Does not cause termination */
  { 6, "File already exists" },
  { 7, "No such user" },
  { 8, "Option negotiation failed" },
  { 0, NULL }
};

static void
tftp_dissect_options(tvbuff_t *tvb, packet_info *pinfo, int offset,
	proto_tree *tree, guint16 opcode, tftp_conv_info_t *tftp_info)
{
	int option_len, value_len;
	int value_offset;
	const char *optionname;
	const char *optionvalue;
	proto_item *opt_item;
	proto_tree *opt_tree;

	while (tvb_offset_exists(tvb, offset)) {
	  option_len = tvb_strsize(tvb, offset);	/* length of option */
	  value_offset = offset + option_len;
	  value_len = tvb_strsize(tvb, value_offset);	/* length of value */
	  optionname = tvb_format_text(tvb, offset, option_len);
	  optionvalue = tvb_format_text(tvb, value_offset, value_len);
	  opt_item = proto_tree_add_text(tree, tvb, offset, option_len+value_len,
	          "Option: %s = %s", optionname, optionvalue);

	  opt_tree = proto_item_add_subtree(opt_item, ett_tftp_option);
	  proto_tree_add_item(opt_tree, hf_tftp_option_name, tvb, offset,
		option_len, FALSE);
	  proto_tree_add_item(opt_tree, hf_tftp_option_value, tvb, value_offset,
		value_len, FALSE);

	  offset += option_len + value_len;

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", %s=%s",
			  optionname, optionvalue);

	  /* Special code to handle individual options */
	  if (!g_ascii_strcasecmp((const char *)optionname, "blksize") &&
	      opcode == TFTP_OACK) {
		gint blocksize = strtol((const char *)optionvalue, NULL, 10);
		if (blocksize < 8 || blocksize > 65464) {
			expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE,
				PI_WARN, "TFTP blocksize out of range");
		} else {
			tftp_info->blocksize = blocksize;
		}
	  }
	}
}

static void dissect_tftp_message(tftp_conv_info_t *tftp_info,
				 tvbuff_t *tvb, packet_info *pinfo,
				 proto_tree *tree)
{
	proto_tree	 *tftp_tree = NULL;
	proto_item	 *ti;
	gint		 offset = 0;
	guint16		 opcode;
	guint16		 bytes;
	guint16		 blocknum;
	guint		 i1;
	guint16	         error;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "TFTP");

	opcode = tvb_get_ntohs(tvb, offset);

	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(opcode, tftp_opcode_vals, "Unknown (0x%04x)"));

	if (tree) {
	  ti = proto_tree_add_item(tree, proto_tftp, tvb, offset, -1, FALSE);
	  tftp_tree = proto_item_add_subtree(ti, ett_tftp);

	  if (tftp_info->source_file) {
	    ti = proto_tree_add_string(tftp_tree, hf_tftp_source_file, tvb,
				       0, 0, tftp_info->source_file);
	    PROTO_ITEM_SET_GENERATED(ti);
	  }

	  if (tftp_info->destination_file) {
	    ti = proto_tree_add_string(tftp_tree, hf_tftp_destination_file, tvb,
				       0, 0, tftp_info->destination_file);
	    PROTO_ITEM_SET_GENERATED(ti);
	  }

	  proto_tree_add_uint(tftp_tree, hf_tftp_opcode, tvb,
			      offset, 2, opcode);
	}
	offset += 2;

	switch (opcode) {

	case TFTP_RRQ:
	  i1 = tvb_strsize(tvb, offset);
	  proto_tree_add_item(tftp_tree, hf_tftp_source_file,
			      tvb, offset, i1, FALSE);

	  tftp_info->source_file = tvb_get_seasonal_string(tvb, offset, i1);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
			  tvb_format_stringzpad(tvb, offset, i1));

	  offset += i1;

	  i1 = tvb_strsize(tvb, offset);
	  proto_tree_add_item(tftp_tree, hf_tftp_transfer_type,
			      tvb, offset, i1, FALSE);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
			  tvb_format_stringzpad(tvb, offset, i1));

	  offset += i1;

	  tftp_dissect_options(tvb, pinfo,  offset, tftp_tree,
			       opcode, tftp_info);
	  break;

	case TFTP_WRQ:
	  i1 = tvb_strsize(tvb, offset);
	  proto_tree_add_item(tftp_tree, hf_tftp_destination_file,
			      tvb, offset, i1, FALSE);

	  tftp_info->destination_file =
	    tvb_get_seasonal_string(tvb, offset, i1);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", File: %s",
			  tvb_format_stringzpad(tvb, offset, i1));

	  offset += i1;

	  i1 = tvb_strsize(tvb, offset);
	  proto_tree_add_item(tftp_tree, hf_tftp_transfer_type,
			           tvb, offset, i1, FALSE);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", Transfer type: %s",
			  tvb_format_stringzpad(tvb, offset, i1));

	  offset += i1;

	  tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
			       opcode,  tftp_info);
	  break;

	case TFTP_INFO:
	  tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
			       opcode,  tftp_info);
	  break;

	case TFTP_DATA:
	  blocknum = tvb_get_ntohs(tvb, offset);
	  proto_tree_add_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
			      blocknum);

	  offset += 2;

	  bytes = tvb_reported_length_remaining(tvb, offset);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %i%s",
			  blocknum,
			  (bytes < tftp_info->blocksize)?" (last)":"" );

	  if (bytes != 0) {
	    tvbuff_t *data_tvb = tvb_new_subset(tvb, offset, -1, bytes);
	    call_dissector(data_handle, data_tvb, pinfo, tree);
	  }
	  break;

	case TFTP_ACK:
	  blocknum = tvb_get_ntohs(tvb, offset);
	  proto_tree_add_uint(tftp_tree, hf_tftp_blocknum, tvb, offset, 2,
			      blocknum);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", Block: %i",
			  blocknum);
	  break;

	case TFTP_ERROR:
	  error = tvb_get_ntohs(tvb, offset);
	  proto_tree_add_uint(tftp_tree, hf_tftp_error_code, tvb, offset, 2,
			      error);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", Code: %s",
			  val_to_str(error, tftp_error_code_vals, "Unknown (%u)"));

	  offset += 2;

	  i1 = tvb_strsize(tvb, offset);
	  proto_tree_add_item(tftp_tree, hf_tftp_error_string, tvb, offset,
			      i1, FALSE);

	  col_append_fstr(pinfo->cinfo, COL_INFO, ", Message: %s",
			  tvb_format_stringzpad(tvb, offset, i1));

	  expert_add_info_format(pinfo, NULL, PI_RESPONSE_CODE,
			         PI_NOTE, "TFTP blocksize out of range");
	  break;

	case TFTP_OACK:
	  tftp_dissect_options(tvb, pinfo, offset, tftp_tree,
			       opcode, tftp_info);
	  break;

	default:
	  proto_tree_add_text(tftp_tree, tvb, offset, -1,
			      "Data (%d bytes)", tvb_reported_length_remaining(tvb, offset));
	  break;

	}

  return;
}

static gboolean
dissect_embeddedtftp_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  /* Used to dissect TFTP packets where one can not assume
     that the TFTP is the only protocol used by that port, and
     that TFTP may not be carried by UDP */
  conversation_t   *conversation = NULL;
  guint16           opcode;
  tftp_conv_info_t *tftp_info;

  conversation = find_or_create_conversation(pinfo);

  tftp_info = conversation_get_proto_data(conversation, proto_tftp);
  if (!tftp_info) {
    tftp_info = se_alloc(sizeof(tftp_conv_info_t));
    tftp_info->blocksize = 512; /* TFTP default block size */
    tftp_info->source_file = NULL;
    tftp_info->destination_file = NULL;
    conversation_add_proto_data(conversation, proto_tftp, tftp_info);
  }

  opcode = tvb_get_ntohs(tvb, 0);

  if ((opcode == TFTP_RRQ) ||
      (opcode == TFTP_WRQ) ||
      (opcode == TFTP_DATA) ||
      (opcode == TFTP_ACK) ||
      (opcode == TFTP_ERROR) ||
      (opcode == TFTP_INFO) ||
      (opcode == TFTP_OACK)) {
    dissect_tftp_message(tftp_info, tvb, pinfo, tree);
    return TRUE;
  }
  else {
    return FALSE;
  }
}

static void
dissect_tftp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	conversation_t   *conversation = NULL;
	tftp_conv_info_t *tftp_info;

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
	if (value_is_in_range(global_tftp_port_range, pinfo->destport)) {
	  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					   pinfo->srcport, 0, NO_PORT_B);
	  if( (conversation == NULL) || (conversation->dissector_handle!=tftp_handle) ){
	    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					    pinfo->srcport, 0, NO_PORT2);
            conversation_set_dissector(conversation, tftp_handle);
	  }
	} else {
	  conversation = find_conversation(pinfo->fd->num, &pinfo->src, &pinfo->dst,
					   pinfo->ptype, pinfo->srcport, pinfo->destport, 0);
	  if( (conversation == NULL) || (conversation->dissector_handle!=tftp_handle) ){
	    conversation = conversation_new(pinfo->fd->num, &pinfo->src, &pinfo->dst, PT_UDP,
					    pinfo->destport, pinfo->srcport, 0);
            conversation_set_dissector(conversation, tftp_handle);
	  }
	}
	tftp_info = conversation_get_proto_data(conversation, proto_tftp);
        if (!tftp_info) {
	  tftp_info = se_alloc(sizeof(tftp_conv_info_t));
	  tftp_info->blocksize = 512; /* TFTP default block size */
	  tftp_info->source_file = NULL;
	  tftp_info->destination_file = NULL;
	  conversation_add_proto_data(conversation, proto_tftp, tftp_info);
	}

	dissect_tftp_message(tftp_info, tvb, pinfo, tree);

	return;
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
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
      	"TFTP source file name", HFILL }},

    { &hf_tftp_destination_file,
      { "DESTINATION File",   "tftp.destination_file",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
      	"TFTP source file name", HFILL }},

    { &hf_tftp_transfer_type,
      { "Type",	              "tftp.type",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
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
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
      	"Error string in case of TFTP error message", HFILL }},

    { &hf_tftp_option_name,
      { "Option name",        "tftp.option.name",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},

    { &hf_tftp_option_value,
      { "Option value",       "tftp.option.value",
	FT_STRINGZ, BASE_NONE, NULL, 0x0,
      	NULL, HFILL }},

  };
  static gint *ett[] = {
    &ett_tftp,
    &ett_tftp_option,
  };

  module_t *tftp_module;

  proto_tftp = proto_register_protocol("Trivial File Transfer Protocol",
				       "TFTP", "tftp");
  proto_register_field_array(proto_tftp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  register_dissector("tftp", dissect_tftp, proto_tftp);

  /* Set default UDP ports */
  range_convert_str(&global_tftp_port_range, UDP_PORT_TFTP_RANGE, MAX_UDP_PORT);

  tftp_module = prefs_register_protocol(proto_tftp, proto_reg_handoff_tftp);
  prefs_register_range_preference(tftp_module, "udp_ports",
				  "TFTP port numbers",
				  "Port numbers used for TFTP traffic "
				  "(default " UDP_PORT_TFTP_RANGE ")",
				  &global_tftp_port_range, MAX_UDP_PORT);
}

static void range_delete_callback (guint32 port)
{
  dissector_delete_uint("udp.port", port, tftp_handle);
}

static void range_add_callback (guint32 port)
{
  dissector_add_uint("udp.port", port, tftp_handle);
}

void
proto_reg_handoff_tftp(void)
{
  static range_t *tftp_port_range;
  static gboolean tftp_initialized = FALSE;

  if (!tftp_initialized) {
    tftp_handle = find_dissector("tftp");
    data_handle = find_dissector("data");
    heur_dissector_add("stun", dissect_embeddedtftp_heur, proto_tftp);
    tftp_initialized = TRUE;
  } else {
    range_foreach(tftp_port_range, range_delete_callback);
    g_free(tftp_port_range);
  }

  tftp_port_range = range_copy(global_tftp_port_range);
  range_foreach(tftp_port_range, range_add_callback);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab
 * :indentSize=2:tabSize=8:noTabs=true:
 */
