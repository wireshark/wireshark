/* packet-ldp.c
 * Routines for ldp packet disassembly
 *
 * $Id: packet-ldp.c,v 1.19 2001/07/21 10:27:12 guy Exp $
 * 
 * Copyright (c) November 2000 by Richard Sharpe <rsharpe@ns.aus.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs
 * Copyright 1999 Gerald Combs
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
#include <ctype.h>
#include <time.h>
#include <glib.h>
#include <string.h>
#include "packet.h"
#include "resolv.h"
#include "prefs.h"
#include "afn.h"

#define TCP_PORT_LDP 646
#define UDP_PORT_LDP 646

void proto_reg_handoff_ldp(void);

static int proto_ldp = -1;

/* Delete the following if you do not use it, or add to it if you need */
static int hf_ldp_req = -1;
static int hf_ldp_rsp = -1;
static int hf_ldp_version = -1;
static int hf_ldp_pdu_len = -1;
static int hf_ldp_lsr = -1;
static int hf_ldp_ls_id = -1;
static int hf_ldp_msg_type = -1;
static int hf_ldp_msg_len = -1;
static int hf_ldp_msg_id = -1;
static int hf_ldp_tlv_value = -1;
static int hf_ldp_tlv_type = -1;
static int hf_ldp_tlv_len = -1;
static int hf_ldp_tlv_val_hold = -1;
static int hf_ldp_tlv_val_target = -1;
static int hf_ldp_tlv_val_request = -1;
static int hf_ldp_tlv_val_res = -1;
static int hf_ldp_tlv_config_seqno = -1;
static int hf_ldp_tlv_fec_wc = -1;
static int hf_ldp_tlv_fec_af = -1;
static int hf_ldp_tlv_fec_len = -1;
static int hf_ldp_tlv_fec_pfval = -1;
static int hf_ldp_tlv_generic_label = -1;

static int ett_ldp = -1;
static int ett_ldp_header = -1;
static int ett_ldp_ldpid = -1;
static int ett_ldp_message = -1;
static int ett_ldp_tlv = -1;
static int ett_ldp_tlv_val = -1;
static int ett_ldp_fec = -1;

static int tcp_port = 0;
static int udp_port = 0;

/* Add your functions here */

static int global_ldp_tcp_port = TCP_PORT_LDP;
static int global_ldp_udp_port = UDP_PORT_LDP;

/*
 * The following define all the TLV types I know about
 */

#define TLV_FEC                    0x0100
#define TLV_ADDRESS_LIST           0x0101
#define TLV_HOP_COUNT              0x0103
#define TLV_PATH_VECTOR            0x0104
#define TLV_GENERIC_LABEL          0x0200
#define TLV_ATM_LABEL              0x0201
#define TLV_FRAME_LABEL            0x0202
#define TLV_STATUS                 0x0300
#define TLV_EXTENDED_STATUS        0x0301
#define TLV_RETURNED_PDU           0x0302
#define TLV_RETURNED_MESSAGE       0x0303
#define TLV_COMMON_HELLO_PARMS     0x0400
#define TLV_IPV4_TRANSPORT_ADDRESS 0x0401
#define TLV_CONFIGURATION_SEQNO    0x0402
#define TLV_IPV6_TRANSPORT_ADDRESS 0x0403
#define TLV_COMMON_SESSION_PARMS   0x0500
#define TLV_ATM_SESSION_PARMS      0x0501
#define TLV_FRAME_RELAY_SESSION_PARMS 0x0502
#define TLV_LABEL_REQUEST_MESSAGE_ID 0x0600

#define TLV_VENDOR_PRIVATE_START   0x3E00
#define TLV_VENDOR_PROVATE_END     0x3EFF
#define TLV_EXPERIMENTAL_START     0x3F00
#define TLV_EXPERIMENTAL_END       0x3FFF

static const value_string tlv_type_names[] = { 
  { TLV_FEC,                       "Forwarding Equivalence Classes" },
  { TLV_ADDRESS_LIST,              "Address List"},
  { TLV_HOP_COUNT,                 "Hop Count"},
  { TLV_PATH_VECTOR,               "Path Vector"},
  { TLV_GENERIC_LABEL,             "Generic Label"},
  { TLV_ATM_LABEL,                 "Frame Label"},
  { TLV_STATUS,                    "Status"},
  { TLV_EXTENDED_STATUS,           "Extended Status"},
  { TLV_RETURNED_PDU,              "Returned PDU"},
  { TLV_RETURNED_MESSAGE,          "Returned Message"},
  { TLV_COMMON_HELLO_PARMS,        "Common Hello Parameters"},
  { TLV_IPV4_TRANSPORT_ADDRESS,    "IPv4 Transport Address"},
  { TLV_CONFIGURATION_SEQNO,       "Configuration Sequence Number"},
  { TLV_IPV6_TRANSPORT_ADDRESS,    "IPv6 Transport Address"},
  { TLV_COMMON_SESSION_PARMS,      "Common Session Parameters"},
  { TLV_ATM_SESSION_PARMS,         "ATM Session Parameters"},
  { TLV_FRAME_RELAY_SESSION_PARMS, "Frame Relay Session Parameters"},
  { TLV_LABEL_REQUEST_MESSAGE_ID,  "Label Request Message ID"},
  { 0, NULL}
};

/*
 * The following define all the message types I know about
 */

#define LDP_NOTIFICATION       0x0001
#define LDP_HELLO              0x0100
#define LDP_INITIALIZATION     0x0200
#define LDP_KEEPALIVE          0x0201
#define LDP_ADDRESS            0x0300
#define LDP_ADDRESS_WITHDRAWAL 0x0301
#define LDP_LABEL_MAPPING      0x0400
#define LDP_LABEL_REQUEST      0x0401
#define LDP_LABEL_WITHDRAWAL   0x0402
#define LDP_LABEL_RELEASE      0x0403
#define LDP_LABEL_ABORT_REQUEST 0x0404
#define LDP_VENDOR_PRIVATE_START 0x3E00
#define LDP_VENDOR_PRIVATE_END   0x3EFF
#define LDP_EXPERIMENTAL_MESSAGE_START 0x3F00
#define LDP_EXPERIMENTAL_MESSAGE_END   0x3FFF

static const value_string ldp_message_types[] = {
  {LDP_NOTIFICATION,             "Notification"},
  {LDP_HELLO,                    "Hello"},
  {LDP_INITIALIZATION,           "Initialization"},
  {LDP_KEEPALIVE,                "Keep Alive"},
  {LDP_ADDRESS,                  "Address"},
  {LDP_ADDRESS_WITHDRAWAL,       "Address Withdrawal"},
  {LDP_LABEL_MAPPING,            "Label Mapping"},
  {LDP_LABEL_REQUEST,            "Label Request"},
  {LDP_LABEL_WITHDRAWAL,         "Label Withdrawal"},
  {LDP_LABEL_RELEASE,            "Label Release"},
  {LDP_LABEL_ABORT_REQUEST,      "Label Abort Request"},
  {0, NULL}
};

static const true_false_string hello_targeted_vals = {
  "Targeted Hello",
  "Link Hello"
};

static const value_string fec_types[] = {
  {1, "Wildcard FEC"},
  {2, "Prefix FEC"},
  {3, "Host Address FEC"},
  {0, NULL}
};

static const true_false_string hello_requested_vals = {
  "Source requests periodic hellos",
  "Source does not request periodic hellos"
};

/* Dissect the common hello params */

void dissect_tlv_common_hello_parms(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
  proto_tree *ti = NULL, *val_tree = NULL;

  if (tree) {

    ti = proto_tree_add_item(tree, hf_ldp_tlv_value, tvb, offset, rem,
			     FALSE);

    val_tree = proto_item_add_subtree(ti, ett_ldp_tlv_val);

    proto_tree_add_item(val_tree, hf_ldp_tlv_val_hold, tvb, offset, 2, FALSE);

    proto_tree_add_boolean(val_tree, hf_ldp_tlv_val_target, tvb, offset + 2, 2, FALSE);
    proto_tree_add_boolean(val_tree, hf_ldp_tlv_val_request, tvb, offset + 2, 2, FALSE);
    proto_tree_add_item(val_tree, hf_ldp_tlv_val_res, tvb, offset + 2, 2, FALSE);
  }

}

/* Dissect a TLV and return the number of bytes consumed ... */

int dissect_tlv(tvbuff_t *tvb, guint offset, proto_tree *tree, int rem)
{
  guint16 message = tvb_get_ntohs(tvb, offset),
          length = tvb_get_ntohs(tvb, offset + 2),
          pad = 0, fec_len = 0;
  proto_tree *ti = NULL, *tlv_tree = NULL;

  /* Hmmm, check for illegal alignment padding */

  if (message == 0x00) {

    proto_tree_add_text(tree, tvb, offset, 2, "Illegal Padding: %04X", message);
    offset += 2; pad = 2;
    message = tvb_get_ntohs(tvb, offset);
    length = tvb_get_ntohs(tvb, offset + 2);

  }

  length = MIN(length, rem);  /* Don't go haywire if a problem ... */

  if (tree) {

    /* FIXME: Account for vendor and special messages */

    ti = proto_tree_add_text(tree, tvb, offset, length + 4, "%s",
			     val_to_str(message, tlv_type_names, "Unknown TLV type (0x%04X)"));

    tlv_tree = proto_item_add_subtree(ti, ett_ldp_tlv);

    proto_tree_add_item(tlv_tree, hf_ldp_tlv_type, tvb, offset, 2, FALSE);

    proto_tree_add_item(tlv_tree, hf_ldp_tlv_len, tvb, offset + 2, 2, FALSE);

    switch (message) {

    case TLV_FEC:  /* Process an FEC */

      offset += 4;  /* Skip the TLV header */

      fec_len = length;

      while (fec_len > 0) {
	proto_tree *fec_tree = NULL;
	guint prefix_len_octets, prefix_len, prefix;  


	switch (tvb_get_guint8(tvb, offset)) {
	case 1:   /* Wild Card */

	  proto_tree_add_item(tlv_tree, hf_ldp_tlv_fec_wc, tvb, offset, 4, FALSE);
	  fec_len -= 4;

	  offset += 4;

	  break;

	case 2:   /* Prefix    */

	  /* Add a subtree for this ... */

	  ti = proto_tree_add_text(tlv_tree, tvb, offset, 8, "Prefix FEC Element");

	  fec_tree = proto_item_add_subtree(ti, ett_ldp_fec);

	  proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_wc, tvb, offset, 1, FALSE);

	  offset += 1;

	  /* XXX - the address family length should be extracted and used to
	     dissect the prefix field. */
	  proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_af, tvb, offset, 2, FALSE);
	  offset += 2;

	  prefix_len = tvb_get_guint8(tvb, offset);
	  proto_tree_add_item(fec_tree, hf_ldp_tlv_fec_len, tvb, offset, 1, FALSE);

	  offset += 1;
	  /* This is IPv4 specific. Should do IPv6 according to AF*/
	  prefix_len_octets = MIN( (prefix_len+7)/8 , 4 );
	  if (prefix_len > 32) {
	    proto_tree_add_text(fec_tree, tvb, offset, 0,
	    "Invalid prefix %u length, guessing 32", prefix_len);
	    prefix_len_octets = 4;
	  }
	  switch (prefix_len_octets){
	    case (0): /*prefix_length=0*/
	      prefix = 0;
	      break;
	    case (1): /*1<=prefix_length<=8*/
	      prefix = tvb_get_guint8(tvb, offset);
	      break;
	    case (2): /*9<=prefix_length<=16*/
	      prefix = tvb_get_letohs(tvb, offset);
	      break;
	    case (3): /*17<=prefix_length<=24*/
	      prefix = tvb_get_letoh24(tvb, offset);
	      break;
	    case (4): /*25<=prefix_length<=32*/
	      prefix = tvb_get_letohl(tvb, offset);
	      break;
	    default: /*prefix_length>32*/
	      g_assert_not_reached();
	      prefix = 0;
	      break;
	  }
	  proto_tree_add_ipv4(fec_tree, hf_ldp_tlv_fec_pfval, tvb, 
			      offset, prefix_len_octets, prefix);
	  fec_len -= 4+prefix_len_octets;
	  break;

	case 3:   /* Host address */

	  /* XXX - write me. */

	  fec_len -= 8;

	  offset += 8;

	  break;

	default:  /* Unknown */

          /* XXX - do all FEC's have a length that's a multiple of 4? */
          /* Hmmm, don't think so. Will check. RJS. */

	  fec_len -= 4;

	  offset += 4;

	  break;

	}

      }

      break;;

    case TLV_GENERIC_LABEL:

      proto_tree_add_item(tlv_tree, hf_ldp_tlv_generic_label, tvb, offset + 4, 4, FALSE);

      break;

    case TLV_COMMON_HELLO_PARMS:

      dissect_tlv_common_hello_parms(tvb, offset + 4, tlv_tree, length);
      break;

    case TLV_CONFIGURATION_SEQNO:

      proto_tree_add_item(tlv_tree, hf_ldp_tlv_config_seqno, tvb, offset + 4, 4, FALSE);
      break;

    default:
      proto_tree_add_item(tlv_tree, hf_ldp_tlv_value, tvb, offset + 4, 
			   length, FALSE);

      break;
    }

  }

  return length + pad + 4;  /* Length of the value field + header */

}

/* 
 * Each of these routines dissect the relevant messages, but the msg header 
 * has already been dissected.
 */

void
dissect_ldp_notification(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

/* Dissect a Hello Message ... */
void
dissect_ldp_hello(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_initialization(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_keepalive(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_address(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_address_withdrawal(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_label_mapping(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_label_request(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_label_withdrawal(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_label_release(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

void
dissect_ldp_label_abort_request(tvbuff_t *tvb, guint offset, packet_info *pinfo, proto_tree *tree, guint length)
{
  guint rem = length, cc = 0;

  while (rem > 0) {

    rem -= (cc = dissect_tlv(tvb, offset, tree, rem));
    offset += cc;

  }

}

static void
dissect_ldp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree     *ldp_tree = NULL, 
                 *ti = NULL,
                 *hdr_tree = NULL, *ldpid_tree = NULL;
  int	         offset = 0, msg_cnt = 0;
  guint16        ldp_message = 0;

  if (check_col(pinfo->fd, COL_PROTOCOL))
    col_add_str(pinfo->fd, COL_PROTOCOL, "LDP");
  if (check_col(pinfo->fd, COL_INFO))
    col_clear(pinfo->fd, COL_INFO);

  if (tree) {  /* Build the tree info ..., this is wrong! FIXME */

    ti = proto_tree_add_item(tree, proto_ldp, tvb, offset,
			     tvb_length_remaining(tvb, offset), FALSE);
    ldp_tree = proto_item_add_subtree(ti, ett_ldp);

    ti = proto_tree_add_text(ldp_tree, tvb, 0, 10, "Header");

    hdr_tree = proto_item_add_subtree(ti, ett_ldp_header);

    proto_tree_add_item(hdr_tree, hf_ldp_version, tvb, offset, 2, FALSE);

    offset += 2;

    proto_tree_add_item(hdr_tree, hf_ldp_pdu_len, tvb, offset, 2, FALSE);

    offset += 2;

    ti = proto_tree_add_text(hdr_tree, tvb, offset, 6, "LDP Identifier");

    ldpid_tree = proto_item_add_subtree(ti, ett_ldp_ldpid);

    proto_tree_add_item(ldpid_tree, hf_ldp_lsr, tvb, offset, 4, FALSE);

    offset += 4;

    proto_tree_add_item(ldpid_tree, hf_ldp_ls_id, tvb, offset, 2, FALSE);

    offset += 2;

  }

  offset = 10;

  while (tvb_length_remaining(tvb, offset) > 0) { /* Dissect a message */

    guint msg_len;

    ldp_message = tvb_get_ntohs(tvb, offset) & 0x7FFF; /* Get the message type */

    msg_len = tvb_get_ntohs(tvb, offset + 2);

    if (check_col(pinfo->fd, COL_INFO)) {  /* Check the type ... */

      if (msg_cnt > 0) 
	col_append_fstr(pinfo->fd, COL_INFO, ", %s",
			val_to_str(ldp_message, ldp_message_types, "Unknown Message (0x%04X)"));
      else
	col_add_fstr(pinfo->fd, COL_INFO, "%s", 
		     val_to_str(ldp_message, ldp_message_types, "Unknown Message (0x%04X)"));

    }

    msg_cnt++;

    if (tree) {

      proto_tree *ti = NULL, *msg_tree = NULL;

      /* FIXME: Account for vendor and experimental messages */

      ti = proto_tree_add_text(ldp_tree, tvb, offset, msg_len + 4, "%s",
			       val_to_str(ldp_message, ldp_message_types, "Unknown Message (0x%04X)"));

      msg_tree = proto_item_add_subtree(ti, ett_ldp_message);

      proto_tree_add_item(msg_tree, hf_ldp_msg_type, tvb, offset, 2, FALSE);

      proto_tree_add_item(msg_tree, hf_ldp_msg_len, tvb, offset + 2, 2, FALSE);

      proto_tree_add_item(msg_tree, hf_ldp_msg_id, tvb, offset + 4, 4, FALSE);

      switch (ldp_message) {

      case LDP_NOTIFICATION:

	dissect_ldp_notification(tvb, offset + 8, pinfo, msg_tree, msg_len - 4); 

	break;

      case LDP_HELLO:

	dissect_ldp_hello(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_INITIALIZATION:

	dissect_ldp_initialization(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_KEEPALIVE:

	dissect_ldp_keepalive(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_ADDRESS:

	dissect_ldp_address(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_ADDRESS_WITHDRAWAL:

	dissect_ldp_address_withdrawal(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_LABEL_MAPPING:

	dissect_ldp_label_mapping(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_LABEL_REQUEST:

	dissect_ldp_label_request(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_LABEL_WITHDRAWAL:

	dissect_ldp_label_withdrawal(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_LABEL_RELEASE:

	dissect_ldp_label_release(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      case LDP_LABEL_ABORT_REQUEST:

	dissect_ldp_label_abort_request(tvb, offset + 8, pinfo, msg_tree, msg_len - 4);

	break;

      default:

	/* Some sort of unknown message, treat as undissected data */

	break;

      }
    
    }

    offset += msg_len + 4;

  }
}

/* Register all the bits needed with the filtering engine */

void 
proto_register_ldp(void)
{
  static hf_register_info hf[] = {
    { &hf_ldp_req,
      /* Change the following to the type you need */
      { "Request", "ldp.req", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_ldp_rsp,
      { "Response", "ldp.rsp", FT_BOOLEAN, BASE_NONE, NULL, 0x0, "", HFILL }},

    { &hf_ldp_version,
      { "Version", "ldp.hdr.version", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP Version Number", HFILL }},

    { &hf_ldp_pdu_len,
      { "PDU Length", "ldp.hdr.pdu_len", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP PDU Length", HFILL }},

    { &hf_ldp_lsr,
      { "LSR ID", "ldp.hdr.ldpid.lsr", FT_UINT32, BASE_HEX, NULL, 0x0, "LDP Label Space Router ID", HFILL }},

    { &hf_ldp_ls_id,
      { "Label Space ID", "ldp.hdr.ldpid.lsid", FT_UINT16, BASE_HEX, NULL, 0x0, "LDP Label Space ID", HFILL }},

    { &hf_ldp_msg_type,
      { "Message Type", "ldp.msg.type", FT_UINT16, BASE_HEX, VALS(ldp_message_types), 0x0, "LDP message type", HFILL }},

    { &hf_ldp_msg_len,
      { "Message Length", "ldp.msg.len", FT_UINT16, BASE_DEC, NULL, 0x0, "LDP Message Length (excluding message type and len)", HFILL }},

    { &hf_ldp_msg_id, 
      { "Message ID", "ldp.msg.id", FT_UINT32, BASE_HEX, NULL, 0x0, "LDP Message ID", HFILL }},

    { &hf_ldp_tlv_type, 
      { "TLV Type", "ldp.msg.tlv.type", FT_UINT16, BASE_HEX, VALS(tlv_type_names), 0x0, "TLV Type Field", HFILL }},

    { &hf_ldp_tlv_len,
      {"TLV Length", "ldp.msg.tlv.len", FT_UINT16, BASE_DEC, NULL, 0x0, "TLV Length Field", HFILL }},

    { &hf_ldp_tlv_value,
      { "TLV Value", "ldp.msg.tlv.value", FT_BYTES, BASE_NONE, NULL, 0x0, "TLV Value Bytes", HFILL }},

    { &hf_ldp_tlv_val_hold,
      { "Hold Time", "ldp.msg.tlv.hello.hold", FT_UINT16, BASE_DEC, NULL, 0x0, "Hello Common Parameters Hold Time", HFILL }},

    { &hf_ldp_tlv_val_target,
      { "Targeted Hello", "ldp.msg.tlv.hello.targeted", FT_BOOLEAN, 8, TFS(&hello_targeted_vals), 0x80, "Hello Common Parameters Targeted Bit", HFILL }},

    { &hf_ldp_tlv_val_request,
      { "Hello Requested", "ldp,msg.tlv.hello.requested", FT_BOOLEAN, 8, TFS(&hello_requested_vals), 0x40, "Hello Common Parameters Hello Requested Bit", HFILL }},
 
    { &hf_ldp_tlv_val_res,
      { "Reserved", "ldp.msg.tlv.hello.res", FT_UINT16, BASE_HEX, NULL, 0x3FFF, "Hello Common Parameters Reserved Field", HFILL }},

    { &hf_ldp_tlv_config_seqno,
      { "Configuration Sequence Number", "ldp.msg.tlv.hello.cnf_seqno", FT_UINT32, BASE_HEX, NULL, 0x0, "Hello COnfiguration Sequence Number", HFILL }},

    { &hf_ldp_tlv_fec_wc,
      { "FEC Element Type", "ldp.msg.tlv.fec.type", FT_UINT8, BASE_DEC, VALS(fec_types), 0x0, "Forwarding Equivalence Class Element Types", HFILL }},

    { &hf_ldp_tlv_fec_af,
      { "FEC Element Address Type", "ldp.msg.tlv.fec.af", FT_UINT16, BASE_DEC, VALS(afn_vals), 0x0, "Forwarding Equivalence Class Element Address Family", HFILL }},

    { &hf_ldp_tlv_fec_len,
      { "FEC Element Length", "ldp.msg.tlv.fec.len", FT_UINT8, BASE_DEC, NULL, 0x0, "Forwarding Equivalence Class Element Length", HFILL }},

    { &hf_ldp_tlv_fec_pfval,
      { "FEC Element Prefix Value", "ldp.msg.tlv.fec.pfval", FT_IPv4, BASE_DEC, NULL, 0x0, "Forwarding Equivalence Class Element Prefix", HFILL }},

    { &hf_ldp_tlv_generic_label,
      { "Generic Label", "ldp.msg.tlv.label", FT_UINT32, BASE_HEX, NULL, 0x0, "Label Mapping Generic Label", HFILL }},

  };
  static gint *ett[] = {
    &ett_ldp,
    &ett_ldp_header,
    &ett_ldp_ldpid,
    &ett_ldp_message,
    &ett_ldp_tlv,
    &ett_ldp_tlv_val,
    &ett_ldp_fec,
  };
  module_t *ldp_module; 

  proto_ldp = proto_register_protocol("Label Distribution Protocol",
				       "LDP", "ldp");

  proto_register_field_array(proto_ldp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register our configuration options for , particularly our port */

  ldp_module = prefs_register_protocol(proto_ldp, proto_reg_handoff_ldp);

  prefs_register_uint_preference(ldp_module, "tcp.port", "LDP TCP Port",
				 "Set the port for  messages (if other"
				 " than the default of 646)",
				 10, &global_ldp_tcp_port);

  prefs_register_uint_preference(ldp_module, "udp.port", "LDP UDP Port",
				 "Set the port for  messages (if other"
				 " than the default of 646)",
				 10, &global_ldp_udp_port);

}

/* The registration hand-off routine */
void
proto_reg_handoff_ldp(void)
{
  static int ldp_prefs_initialized = FALSE;

  if (ldp_prefs_initialized) {

    dissector_delete("tcp.port", tcp_port, dissect_ldp);
    dissector_delete("udp.port", udp_port, dissect_ldp);

  }
  else {

    ldp_prefs_initialized = TRUE;

  }

  /* Set our port number for future use */

  tcp_port = global_ldp_tcp_port;
  udp_port = global_ldp_udp_port;

  dissector_add("tcp.port", global_ldp_tcp_port, dissect_ldp, proto_ldp);
  dissector_add("udp.port", global_ldp_udp_port, dissect_ldp, proto_ldp);

}
