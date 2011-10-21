/* packet-dec-bpdu.c
 * Routines for DEC BPDU (DEC Spanning Tree Protocol) disassembly
 *
 * $Id$
 *
 * Copyright 2001 Paul Ionescu <paul@acorp.ro>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/etypes.h>
#include <epan/ppptypes.h>

/* Offsets of fields within a BPDU */

#define BPDU_DEC_CODE            0
#define BPDU_TYPE                1
#define BPDU_VERSION		 2
#define BPDU_FLAGS               3
#define BPDU_ROOT_PRI            4
#define BPDU_ROOT_MAC            6
#define BPDU_ROOT_PATH_COST     12
#define BPDU_BRIDGE_PRI         14
#define BPDU_BRIDGE_MAC         16
#define BPDU_PORT_IDENTIFIER    22
#define BPDU_MESSAGE_AGE        23
#define BPDU_HELLO_TIME         24
#define BPDU_MAX_AGE            25
#define BPDU_FORWARD_DELAY      26

#define DEC_BPDU_SIZE		27

/* Flag bits */

#define BPDU_FLAGS_SHORT_TIMERS		0x80
#define BPDU_FLAGS_TCACK		0x02
#define BPDU_FLAGS_TC			0x01

static int proto_dec_bpdu = -1;
static int hf_dec_bpdu_proto_id = -1;
static int hf_dec_bpdu_type = -1;
static int hf_dec_bpdu_version_id = -1;
static int hf_dec_bpdu_flags = -1;
static int hf_dec_bpdu_flags_short_timers = -1;
static int hf_dec_bpdu_flags_tcack = -1;
static int hf_dec_bpdu_flags_tc = -1;
static int hf_dec_bpdu_root_pri = -1;
static int hf_dec_bpdu_root_mac = -1;
static int hf_dec_bpdu_root_cost = -1;
static int hf_dec_bpdu_bridge_pri = -1;
static int hf_dec_bpdu_bridge_mac = -1;
static int hf_dec_bpdu_port_id = -1;
static int hf_dec_bpdu_msg_age = -1;
static int hf_dec_bpdu_hello_time = -1;
static int hf_dec_bpdu_max_age = -1;
static int hf_dec_bpdu_forward_delay = -1;

static gint ett_dec_bpdu = -1;
static gint ett_dec_bpdu_flags = -1;

static const value_string protocol_id_vals[] = {
	{ 0xe1, "DEC Spanning Tree Protocol" },
	{ 0,    NULL }
};

#define BPDU_TYPE_TOPOLOGY_CHANGE	2
#define BPDU_TYPE_HELLO			25

static const value_string bpdu_type_vals[] = {
	{ BPDU_TYPE_TOPOLOGY_CHANGE, "Topology Change Notification" },
	{ BPDU_TYPE_HELLO,           "Hello Packet" },
	{ 0,                         NULL }
};

static const char initial_sep[] = " (";
static const char cont_sep[] = ", ";

#define APPEND_BOOLEAN_FLAG(flag, item, string) \
	if(flag){							\
		if(item)						\
			proto_item_append_text(item, string, sep);	\
		sep = cont_sep;						\
	}

static void
dissect_dec_bpdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
      guint8  bpdu_type;
      guint8  flags;
      proto_tree *bpdu_tree;
      proto_tree *flags_tree;
      proto_item *ti;
      const char *sep;

      col_set_str(pinfo->cinfo, COL_PROTOCOL, "DEC_STP");
      col_clear(pinfo->cinfo, COL_INFO);

      bpdu_type = tvb_get_guint8(tvb, BPDU_TYPE);

	  col_add_str(pinfo->cinfo, COL_INFO,
		val_to_str(bpdu_type, bpdu_type_vals,
			   "Unknown BPDU type (%u)"));

      set_actual_length(tvb, DEC_BPDU_SIZE);

      if (tree) {
	    ti = proto_tree_add_item(tree, proto_dec_bpdu, tvb, 0, DEC_BPDU_SIZE,
			    	ENC_NA);
	    bpdu_tree = proto_item_add_subtree(ti, ett_dec_bpdu);

	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_proto_id, tvb,
				BPDU_DEC_CODE, 1, ENC_BIG_ENDIAN);

	    proto_tree_add_uint(bpdu_tree, hf_dec_bpdu_type, tvb,
				BPDU_TYPE, 1, bpdu_type);

	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_version_id, tvb,
				BPDU_VERSION, 1, ENC_BIG_ENDIAN);

	    flags = tvb_get_guint8(tvb, BPDU_FLAGS);
	    ti = proto_tree_add_uint(bpdu_tree, hf_dec_bpdu_flags, tvb,
				     BPDU_FLAGS, 1, flags);
	    flags_tree = proto_item_add_subtree(ti, ett_dec_bpdu_flags);
	    sep = initial_sep;
	    APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_SHORT_TIMERS, ti,
				"%sUse short timers");
	    proto_tree_add_boolean(flags_tree, hf_dec_bpdu_flags_short_timers, tvb,
				   BPDU_FLAGS, 1, flags);
	    APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_TCACK, ti,
				"%sTopology Change Acknowledgment");
	    proto_tree_add_boolean(flags_tree, hf_dec_bpdu_flags_tcack, tvb,
				   BPDU_FLAGS, 1, flags);
	    APPEND_BOOLEAN_FLAG(flags & BPDU_FLAGS_TC, ti,
				"%sTopology Change");
	    proto_tree_add_boolean(flags_tree, hf_dec_bpdu_flags_tc, tvb,
				   BPDU_FLAGS, 1, flags);
	    if (sep != initial_sep) {
	      /* We put something in; put in the terminating ")" */
	      proto_item_append_text(ti, ")");
	    }

	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_root_pri, tvb,
				BPDU_ROOT_PRI, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_root_mac, tvb,
				BPDU_ROOT_MAC, 6, ENC_NA);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_root_cost, tvb,
				BPDU_ROOT_PATH_COST, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_bridge_pri, tvb,
				BPDU_BRIDGE_PRI, 2, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_bridge_mac, tvb,
				BPDU_BRIDGE_MAC, 6, ENC_NA);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_port_id, tvb,
				BPDU_PORT_IDENTIFIER, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_msg_age, tvb,
				BPDU_MESSAGE_AGE, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_hello_time, tvb,
				BPDU_HELLO_TIME, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_max_age, tvb,
				BPDU_MAX_AGE, 1, ENC_BIG_ENDIAN);
	    proto_tree_add_item(bpdu_tree, hf_dec_bpdu_forward_delay, tvb,
				BPDU_FORWARD_DELAY, 1, ENC_BIG_ENDIAN);

      }
}

void
proto_register_dec_bpdu(void)
{

  static hf_register_info hf[] = {
    { &hf_dec_bpdu_proto_id,
      { "Protocol Identifier",		"dec_stp.protocol",
	FT_UINT8,	BASE_HEX,	VALS(protocol_id_vals), 0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_type,
      { "BPDU Type",			"dec_stp.type",
	FT_UINT8,	BASE_DEC,	VALS(bpdu_type_vals),	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_version_id,
      { "BPDU Version",			"dec_stp.version",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_flags,
      { "BPDU flags",			"dec_stp.flags",
	FT_UINT8,	BASE_HEX,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_flags_short_timers,
      { "Use short timers",		"dec_stp.flags.short_timers",
	FT_BOOLEAN,	8,		TFS(&tfs_yes_no),	BPDU_FLAGS_SHORT_TIMERS,
      	NULL, HFILL }},
    { &hf_dec_bpdu_flags_tcack,
      { "Topology Change Acknowledgment",  "dec_stp.flags.tcack",
	FT_BOOLEAN,	8,		TFS(&tfs_yes_no),	BPDU_FLAGS_TCACK,
      	NULL, HFILL }},
    { &hf_dec_bpdu_flags_tc,
      { "Topology Change",		"dec_stp.flags.tc",
	FT_BOOLEAN,	8,		TFS(&tfs_yes_no),	BPDU_FLAGS_TC,
      	NULL, HFILL }},
    { &hf_dec_bpdu_root_pri,
      { "Root Priority",		"dec_stp.root.pri",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_root_mac,
      { "Root MAC",			"dec_stp.root.mac",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_root_cost,
      { "Root Path Cost",		"dec_stp.root.cost",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_bridge_pri,
      { "Bridge Priority",		"dec_stp.bridge.pri",
	FT_UINT16,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_bridge_mac,
      { "Bridge MAC",			"dec_stp.bridge.mac",
	FT_ETHER,	BASE_NONE,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_port_id,
      { "Port identifier",		"dec_stp.port",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_msg_age,
      { "Message Age",			"dec_stp.msg_age",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_hello_time,
      { "Hello Time",			"dec_stp.hello",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_max_age,
      { "Max Age",			"dec_stp.max_age",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
    { &hf_dec_bpdu_forward_delay,
      { "Forward Delay",		"dec_stp.forward",
	FT_UINT8,	BASE_DEC,	NULL,	0x0,
      	NULL, HFILL }},
  };
  static gint *ett[] = {
    &ett_dec_bpdu,
    &ett_dec_bpdu_flags,
  };

  proto_dec_bpdu = proto_register_protocol("DEC Spanning Tree Protocol",
					   "DEC_STP", "dec_stp");
  proto_register_field_array(proto_dec_bpdu, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_dec_bpdu(void)
{
  dissector_handle_t dec_bpdu_handle;

  dec_bpdu_handle = create_dissector_handle(dissect_dec_bpdu,
					    proto_dec_bpdu);
  dissector_add_uint("ethertype", ETHERTYPE_DEC_LB, dec_bpdu_handle);
  dissector_add_uint("chdlctype", ETHERTYPE_DEC_LB, dec_bpdu_handle);
  dissector_add_uint("ppp.protocol", PPP_DEC_LB, dec_bpdu_handle);
}
