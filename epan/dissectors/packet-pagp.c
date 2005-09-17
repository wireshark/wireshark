/* packet-pagp.c
 * Routines for PAgP (Port Aggregation Protocol - aka FEC) dissection
 * Original Author Mark C. Brown <mbrown@hp.com>
 * Copyright (C) 2004 Hewlett-Packard Development Company, L.P.
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-slowprotocols.c
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
#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/llcsaps.h>
#include <epan/ppptypes.h>
#include <epan/address.h>
#include <epan/addr_resolv.h>

/* Offsets of fields within a PagP PDU */

#define PAGP_VERSION_NUMBER		0

#define PAGP_FLAGS			1
#define PAGP_LOCAL_DEVICE_ID		2
#define PAGP_LOCAL_LEARN_CAP		8
#define PAGP_LOCAL_PORT_PRIORITY		9
#define PAGP_LOCAL_SENT_PORT_IFINDEX	10
#define PAGP_LOCAL_GROUP_CAPABILITY	14
#define PAGP_LOCAL_GROUP_IFINDEX		18
#define PAGP_PARTNER_DEVICE_ID		22
#define PAGP_PARTNER_LEARN_CAP		28
#define PAGP_PARTNER_PORT_PRIORITY		29
#define PAGP_PARTNER_SENT_PORT_IFINDEX	30
#define PAGP_PARTNER_GROUP_CAPABILITY	34
#define PAGP_PARTNER_GROUP_IFINDEX		38
#define PAGP_PARTNER_COUNT		42
#define PAGP_NUM_TLVS			44
#define PAGP_FIRST_TLV			46

#define PAGP_FLUSH_LOCAL_DEVICE_ID		2
#define PAGP_FLUSH_PARTNER_DEVICE_ID	8
#define PAGP_FLUSH_TRANSACTION_ID	14

/* PDU Versions */

#define PAGP_INFO_PDU			1
#define PAGP_FLUSH_PDU			2

/* Flag bits */

#define PAGP_FLAGS_SLOW_HELLO		0x01
#define PAGP_FLAGS_AUTO_MODE		0x02
#define PAGP_FLAGS_CONSISTENT_STATE	0x04

/* TLV Types */


#define PAGP_TLV_DEVICE_NAME		1
#define PAGP_TLV_PORT_NAME		2
#define PAGP_TLV_AGPORT_MAC		3
#define PAGP_TLV_RESERVED		4

/* Initialise the protocol and registered fields */

static int proto_pagp = -1;

static int hf_pagp_version_number = -1;

static int hf_pagp_flags = -1;
static int hf_pagp_flags_slow_hello = -1;
static int hf_pagp_flags_auto_mode = -1;
static int hf_pagp_flags_consistent_state = -1;
static int hf_pagp_local_device_id = -1;
static int hf_pagp_local_learn_cap = -1;
static int hf_pagp_local_port_priority = -1;
static int hf_pagp_local_sent_port_ifindex = -1;
static int hf_pagp_local_group_capability = -1;
static int hf_pagp_local_group_ifindex = -1;
static int hf_pagp_partner_device_id = -1;
static int hf_pagp_partner_learn_cap = -1;
static int hf_pagp_partner_port_priority = -1;
static int hf_pagp_partner_sent_port_ifindex = -1;
static int hf_pagp_partner_group_capability = -1;
static int hf_pagp_partner_group_ifindex = -1;
static int hf_pagp_partner_count = -1;
static int hf_pagp_num_tlvs = -1;
static int hf_pagp_tlv = -1;
static int hf_pagp_tlv_device_name = -1;
static int hf_pagp_tlv_port_name = -1;
static int hf_pagp_tlv_agport_mac = -1;

static int hf_pagp_flush_local_device_id = -1;
static int hf_pagp_flush_partner_device_id = -1;
static int hf_pagp_flush_transaction_id = -1;

/* Initialise the subtree pointers */

static gint ett_pagp = -1;
static gint ett_pagp_flags = -1;
static gint ett_pagp_tlvs = -1;

/* General declarations and macros */

static const char initial_sep[] = " (";
static const char cont_sep[] = ", ";

static const value_string pdu_vers[] = {
	{ 1, "Info PDU" },
	{ 2, "Flush PDU" },
	{ 0, NULL }
};

static const value_string learn_cap[] = {
	{ 1, "Source-based Distribution" },
	{ 2, "Arbitrary Distribution" },
	{ 0, NULL }
};

static const value_string tlv_types[] = {
	{ 1, "Device Name TLV" },
	{ 2, "Physical Port Name TLV" },
	{ 3, "Agport MAC Address" },
	{ 4, "Reserved" },
	{ 0, NULL }
};

static const true_false_string yesno = {
	"Yes",
	"No"
};

static const true_false_string automode = {
	"Yes",
	"Desirable Mode"
};

#define APPEND_BOOLEAN_FLAG(flag, item, string) \
	if(flag) {							\
		if(item)						\
			proto_item_append_text(item, string, sep);	\
		sep = cont_sep;						\
	}

/* Code to actually dissect the PAGP packets */
static void
dissect_pagp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
      guint32 raw_word;
      guint16 raw_half_word;
      guint16 num_tlvs;
      guint16 tlv;
      guint16 len;
      guint16 i;
      guint16 offset = PAGP_FIRST_TLV;
      guint8  raw_octet;

      guint8  flags;

      struct _address device_id;

      const guint8 *p_sys;

      guchar *ch;

      proto_tree *pagp_tree = NULL;
      proto_item *pagp_item;
      proto_tree *flags_tree;
      proto_item *flags_item;
      proto_tree *tlv_tree;
      proto_item *tlv_item;


      const char *sep;


      device_id.type = AT_ETHER;
      device_id.len = 6;

      if (check_col(pinfo->cinfo, COL_PROTOCOL)) {
	    col_set_str(pinfo->cinfo, COL_PROTOCOL, "PAGP"); /* PAGP Protocol */
      }

      if (check_col(pinfo->cinfo, COL_INFO)) {
	    col_clear(pinfo->cinfo, COL_INFO);
      }

      pinfo->current_proto = "PAGP";

      raw_octet = tvb_get_guint8(tvb, PAGP_VERSION_NUMBER);
      if (tree) {
	    pagp_item = proto_tree_add_protocol_format(tree, proto_pagp, tvb,
				0, -1, "Port Aggregation Protocol");
	    pagp_tree = proto_item_add_subtree(pagp_item, ett_pagp);
	    proto_tree_add_uint(pagp_tree, hf_pagp_version_number, tvb,
				PAGP_VERSION_NUMBER, 1, raw_octet);
      } 
      if (check_col(pinfo->cinfo, COL_INFO)) {
         col_append_str(pinfo->cinfo, COL_INFO,
  	       val_to_str(raw_octet, pdu_vers, "Unknown PDU version"));
      }

      if (raw_octet == PAGP_FLUSH_PDU) {

         device_id.data = tvb_get_ptr(tvb, PAGP_FLUSH_LOCAL_DEVICE_ID, 6);
         if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, "; Local DevID: %s",
               address_to_str(&device_id));
         }
         if (tree) {
	       proto_tree_add_ether(pagp_tree, hf_pagp_flush_local_device_id, tvb,
			   PAGP_FLUSH_LOCAL_DEVICE_ID, 6, device_id.data);
         }

         device_id.data = tvb_get_ptr(tvb, PAGP_FLUSH_PARTNER_DEVICE_ID, 6);
         if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO, ", Partner DevID: %s",
               address_to_str(&device_id));
         }
         if (tree) {
	    proto_tree_add_ether(pagp_tree, hf_pagp_flush_partner_device_id, tvb,
			   PAGP_FLUSH_PARTNER_DEVICE_ID, 6, device_id.data);
         }

         raw_word = tvb_get_ntohl(tvb, PAGP_FLUSH_TRANSACTION_ID);
	 if (check_col(pinfo->cinfo, COL_INFO)) {
            col_append_fstr(pinfo->cinfo, COL_INFO,
		"; Transaction ID: 0x%x ", raw_word);
	 }
         if (tree) {
	    proto_tree_add_uint(pagp_tree, hf_pagp_flush_transaction_id, tvb,
			   PAGP_FLUSH_TRANSACTION_ID, 4, raw_word);
	 }
         return;
      }

      /* Info PDU */

      flags = tvb_get_guint8(tvb, PAGP_FLAGS);
      if (check_col(pinfo->cinfo, COL_INFO)) {
         col_append_fstr(pinfo->cinfo, COL_INFO, "; Flags 0x%x", flags);
      }

      if (tree) {
         flags_item = proto_tree_add_uint(pagp_tree, hf_pagp_flags, tvb,
			PAGP_FLAGS, 1, flags);
         flags_tree = proto_item_add_subtree(flags_item, ett_pagp_flags);

	 sep = initial_sep;

	 APPEND_BOOLEAN_FLAG(flags & PAGP_FLAGS_SLOW_HELLO, flags_item, "%sSlow Hello");
	 proto_tree_add_boolean(flags_tree, hf_pagp_flags_slow_hello, tvb,
			PAGP_FLAGS, 1, flags);

	 APPEND_BOOLEAN_FLAG(flags & PAGP_FLAGS_AUTO_MODE, flags_item, "%sAuto Mode");
	 proto_tree_add_boolean(flags_tree, hf_pagp_flags_auto_mode, tvb,
			PAGP_FLAGS, 1, flags);

	 APPEND_BOOLEAN_FLAG(flags & PAGP_FLAGS_CONSISTENT_STATE, flags_item,
			"%sConsistent State");
	 proto_tree_add_boolean(flags_tree, hf_pagp_flags_consistent_state, tvb,
				PAGP_FLAGS, 1, flags);

	 sep = cont_sep;
	 if (sep != initial_sep) {
            /* We put something in; put in the terminating ")" */
            proto_item_append_text(flags_item, ")");
	 }
      }

      device_id.data = tvb_get_ptr(tvb, PAGP_LOCAL_DEVICE_ID, 6);
      if (check_col(pinfo->cinfo, COL_INFO)) {
         col_append_fstr(pinfo->cinfo, COL_INFO, "; Local DevID: %s",
            address_to_str(&device_id));
      }
      if (tree) {
	    proto_tree_add_ether(pagp_tree, hf_pagp_local_device_id, tvb,
				PAGP_LOCAL_DEVICE_ID, 6, device_id.data);
      }

      if (tree) {
	    raw_octet = tvb_get_guint8(tvb, PAGP_LOCAL_LEARN_CAP);
	    proto_tree_add_uint(pagp_tree, hf_pagp_local_learn_cap, tvb,
				PAGP_LOCAL_LEARN_CAP, 1, raw_octet);

	    raw_octet = tvb_get_guint8(tvb, PAGP_LOCAL_PORT_PRIORITY);
	    proto_tree_add_uint(pagp_tree, hf_pagp_local_port_priority, tvb,
				PAGP_LOCAL_PORT_PRIORITY, 1, raw_octet);

	    raw_word = tvb_get_ntohl(tvb, PAGP_LOCAL_SENT_PORT_IFINDEX);
	    proto_tree_add_uint(pagp_tree, hf_pagp_local_sent_port_ifindex, tvb,
				PAGP_LOCAL_SENT_PORT_IFINDEX, 4, raw_word);

	    raw_word = tvb_get_ntohl(tvb, PAGP_LOCAL_GROUP_CAPABILITY);
	    proto_tree_add_uint(pagp_tree, hf_pagp_local_group_capability, tvb,
				PAGP_LOCAL_GROUP_CAPABILITY, 4, raw_word);

	    raw_word = tvb_get_ntohl(tvb, PAGP_LOCAL_GROUP_IFINDEX);
	    proto_tree_add_uint(pagp_tree, hf_pagp_local_group_ifindex, tvb,
				PAGP_LOCAL_GROUP_IFINDEX, 4, raw_word);
      }

      device_id.data = tvb_get_ptr(tvb, PAGP_PARTNER_DEVICE_ID, 6);
      if (check_col(pinfo->cinfo, COL_INFO)) {
         col_append_fstr(pinfo->cinfo, COL_INFO, ", Partner DevID: %s",
  	       address_to_str(&device_id));
      }
      if (tree) {
	    proto_tree_add_ether(pagp_tree, hf_pagp_partner_device_id, tvb,
				PAGP_PARTNER_DEVICE_ID, 6, device_id.data);
      }

      if (tree) {
	    raw_octet = tvb_get_guint8(tvb, PAGP_PARTNER_LEARN_CAP);
	    proto_tree_add_uint(pagp_tree, hf_pagp_partner_learn_cap, tvb,
				PAGP_PARTNER_LEARN_CAP, 1, raw_octet);

	    raw_octet = tvb_get_guint8(tvb, PAGP_PARTNER_PORT_PRIORITY);
	    proto_tree_add_uint(pagp_tree, hf_pagp_partner_port_priority, tvb,
				PAGP_PARTNER_PORT_PRIORITY, 1, raw_octet);

	    raw_word = tvb_get_ntohl(tvb, PAGP_PARTNER_SENT_PORT_IFINDEX);
	    proto_tree_add_uint(pagp_tree, hf_pagp_partner_sent_port_ifindex, tvb,
				PAGP_PARTNER_SENT_PORT_IFINDEX, 4, raw_word);

	    raw_word = tvb_get_ntohl(tvb, PAGP_PARTNER_GROUP_CAPABILITY);
	    proto_tree_add_uint(pagp_tree, hf_pagp_partner_group_capability, tvb,
				PAGP_PARTNER_GROUP_CAPABILITY, 4, raw_word);

	    raw_word = tvb_get_ntohl(tvb, PAGP_PARTNER_GROUP_IFINDEX);
	    proto_tree_add_uint(pagp_tree, hf_pagp_partner_group_ifindex, tvb,
				PAGP_PARTNER_GROUP_IFINDEX, 4, raw_word);

	    raw_half_word = tvb_get_ntohs(tvb, PAGP_PARTNER_COUNT);
	    proto_tree_add_uint(pagp_tree, hf_pagp_partner_count, tvb,
				PAGP_PARTNER_COUNT, 2, raw_half_word);

	    num_tlvs = tvb_get_ntohs(tvb, PAGP_NUM_TLVS);
	    proto_tree_add_uint(pagp_tree, hf_pagp_num_tlvs, tvb,
				PAGP_NUM_TLVS, 2, num_tlvs);

	    /* dump TLV entries */

	    for ( i = 1; i <= num_tlvs; i++ ) {

		tlv = tvb_get_ntohs(tvb, offset);
		len = tvb_get_ntohs(tvb, offset + 2);
		if ( len == 0 ) {
		   proto_tree_add_text(pagp_tree, tvb, offset, -1,
			               "Unknown data - TLV len=0");
		   return;
		}

		tlv_item = proto_tree_add_text (pagp_tree, tvb, offset, len,
			   "TLV Entry #%d", i);
                                                                                
		tlv_tree = proto_item_add_subtree (tlv_item, ett_pagp_tlvs);
		proto_tree_add_uint_format (tlv_tree, hf_pagp_tlv, tvb,
			offset,2,tlv,"Type = %d (%s)", tlv,
			val_to_str(tlv,tlv_types, "Unknown")) ;
		proto_tree_add_text (tlv_tree, tvb, offset+2, 2,
			"Length = %u bytes (includes Type and Length)", len) ;
		if ( tvb_reported_length_remaining(tvb, offset) < len ) {
		   proto_tree_add_text(tlv_tree, tvb, offset, -1,
			               "TLV length too large");
		   return;
		}
                                                                                
		switch (tlv) {
		   case PAGP_TLV_DEVICE_NAME:
			ch = tvb_get_ephemeral_string(tvb, offset+4, len-4);
			proto_tree_add_string(tlv_tree, hf_pagp_tlv_device_name,
			   tvb, offset+4, len-4, ch);
			break;
		   case PAGP_TLV_PORT_NAME:
			ch = tvb_get_ephemeral_string(tvb, offset+4, len-4);
			proto_tree_add_string(tlv_tree, hf_pagp_tlv_port_name,
			   tvb, offset+4, len-4, ch);
			break;
		   case PAGP_TLV_AGPORT_MAC:
			p_sys = tvb_get_ptr(tvb, offset+4, 6);
			proto_tree_add_ether(tlv_tree, hf_pagp_tlv_agport_mac,
			   tvb, offset+4, 6, p_sys);
			break;
		   case PAGP_TLV_RESERVED:
			break;
		}

		offset += len;

	    }
      }
}


/* Register the protocol with Ethereal */

void
proto_register_pagp(void)
{
/* Setup list of header fields */

  static hf_register_info hf[] = {

    { &hf_pagp_version_number,
      { "Version",		"pagp.version",
	FT_UINT8,	BASE_HEX,	VALS(pdu_vers),	0x0,
      	"Identifies the PAgP PDU version: 1 = Info, 2 = Flush", HFILL }},

    { &hf_pagp_flags,
      { "Flags",		"pagp.flags",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	"Infomation flags", HFILL }},

    { &hf_pagp_flags_slow_hello,
      { "Slow Hello",		"pagp.flags.slowhello",
	FT_BOOLEAN,	8,	TFS(&yesno),	PAGP_FLAGS_SLOW_HELLO,
      	"1 = using Slow Hello, 0 = Slow Hello disabled", HFILL }},

    { &hf_pagp_flags_auto_mode,
      { "Auto Mode",		"pagp.flags.automode",
	FT_BOOLEAN,	8,	TFS(&automode),	PAGP_FLAGS_AUTO_MODE,
      	"1 = Auto Mode enabled, 0 = Desirable Mode", HFILL }},

    { &hf_pagp_flags_consistent_state,
      { "Consistent State",	"pagp.flags.state",
	FT_BOOLEAN,	8,	NULL,	PAGP_FLAGS_CONSISTENT_STATE,
      	"1 = Consistent State, 0 = Not Ready", HFILL }},

    { &hf_pagp_local_device_id,
      { "Local Device ID",	"pagp.localdevid",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"Local device ID", HFILL }},

    { &hf_pagp_local_learn_cap,
      { "Local Learn Capability",	"pagp.localearncap",
	FT_UINT8,	BASE_HEX,	VALS(learn_cap),	0x0,
      	"Local learn capability", HFILL }},

    { &hf_pagp_local_port_priority,
      { "Local Port Hot Standby Priority", 	"pagp.localportpri",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"The local hot standby priority assigned to this port", HFILL }},

    { &hf_pagp_local_sent_port_ifindex,
      { "Local Sent Port ifindex",	"pagp.localsentportifindex",
	FT_UINT32,	BASE_DEC,	NULL,	0x0,
      	"The interface index of the local port used to send PDU", HFILL }},

    { &hf_pagp_local_group_capability,
      { "Local Group Capability",	"pagp.localgroupcap",
	FT_UINT32,	BASE_HEX,	NULL,	0x0,
      	"The local group capability", HFILL }},

    { &hf_pagp_local_group_ifindex,
      { "Local Group ifindex",		"pagp.localgroupifindex",
	FT_UINT32,	BASE_DEC,	NULL,	0x0,
      	"The local group interface index", HFILL }},

    { &hf_pagp_partner_device_id,
      { "Partner Device ID",		"pagp.partnerdevid",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"Remote Device ID (MAC)", HFILL }},

    { &hf_pagp_partner_learn_cap,
      { "Partner Learn Capability",	"pagp.partnerlearncap",
	FT_UINT8,	BASE_HEX,	VALS(learn_cap),	0x0,
      	"Remote learn capability", HFILL }},

    { &hf_pagp_partner_port_priority,
      { "Partner Port Hot Standby Priority",	"pagp.partnerportpri",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	"Remote port priority", HFILL }},

    { &hf_pagp_partner_sent_port_ifindex,
      { "Partner Sent Port ifindex",	"pagp.partnersentportifindex",
	FT_UINT32,	BASE_DEC,	NULL,	0x0,
      	"Remote port interface index sent", HFILL }},

    { &hf_pagp_partner_group_capability,
      { "Partner Group Capability",	"pagp.partnergroupcap",
	FT_UINT32,	BASE_HEX,	NULL,	0x0,
      	"Remote group capability", HFILL }},

    { &hf_pagp_partner_group_ifindex,
      { "Partner Group ifindex",	"pagp.partnergroupifindex",
	FT_UINT32,	BASE_DEC,	NULL,	0x0,
      	"Remote group interface index", HFILL }},

    { &hf_pagp_partner_count,
      { "Partner Count",		"pagp.partnercount",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"Partner count", HFILL }},

    { &hf_pagp_num_tlvs,
      { "Number of TLVs",		"pagp.numtlvs",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"Number of TLVs following", HFILL }},

    { &hf_pagp_tlv,
      { "Entry",		"pagp.tlv",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	"Type/Length/Value", HFILL }},

    { &hf_pagp_tlv_device_name,
      { "Device Name",		"pagp.tlvdevname",
	FT_STRING,	BASE_NONE,	NULL,	0x0,
      	"sysName of device", HFILL }},

    { &hf_pagp_tlv_port_name,
      { "Physical Port Name",		"pagp.tlvportname",
	FT_STRING,	BASE_NONE,	NULL,	0x0,
      	"Name of port used to send PDU", HFILL }},

    { &hf_pagp_tlv_agport_mac,
      { "Agport MAC Address",		"pagp.tlvagportmac",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"Source MAC on frames for this aggregate", HFILL }},

    { &hf_pagp_flush_local_device_id,
      { "Flush Local Device ID",	"pagp.flushlocaldevid",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"Flush local device ID", HFILL }},

    { &hf_pagp_flush_partner_device_id,
      { "Flush Partner Device ID",	"pagp.flushpartnerdevid",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	"Flush remote device ID", HFILL }},

    { &hf_pagp_flush_transaction_id,
      { "Transaction ID",		"pagp.transid",
	FT_UINT32,	BASE_HEX,	NULL,	0x0,
      	"Flush transaction ID", HFILL }},

  };

  /* Setup protocol subtree array */

  static gint *ett[] = {
    &ett_pagp,
    &ett_pagp_flags,
    &ett_pagp_tlvs,
  };

  /* Register the protocol name and description */

  proto_pagp = proto_register_protocol("Port Aggregation Protocol", "PAGP", "pagp");

  /* Required function calls to register the header fields and subtrees used */

  proto_register_field_array(proto_pagp, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_pagp(void)
{
  dissector_handle_t pagp_handle;

  pagp_handle = create_dissector_handle(dissect_pagp, proto_pagp);
  dissector_add("llc.cisco_pid", 0x0104, pagp_handle);
}
