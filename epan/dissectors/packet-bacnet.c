/* packet-bacnet.c
 * Routines for BACnet (NPDU) dissection
 * Copyright 2001, Hartmut Mueller <hartmut@abmlinux.org>, FH Dortmund
 * Enhanced by Steve Karg, 2005, <skarg@users.sourceforge.net>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from README.developer,v 1.23
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

#include <glib.h>

#include <epan/packet.h>

#include <epan/llcsaps.h>

static dissector_handle_t bacapp_handle;
static dissector_handle_t data_handle;

static const char*
bacnet_mesgtyp_name (guint8 bacnet_mesgtyp){
	static const char *type_names[] = {
		"Who-Is-Router-To-Network",
		"I-Am-Router-To-Network",
		"I-Could-Be-Router-To-Network",
		"Reject-Message-To-Network",
		"Router-Busy-To-Network",
		"Router-Available-To-Network",
		"Initialize-Routing-Table",
		"Initialize-Routing-Table-Ack",
		"Establish-Connection-To-Network",
		"Disconnect-Connection-To-Network"
	};
	if(bacnet_mesgtyp < 0x0a) {
		return type_names[bacnet_mesgtyp];
	} else {
		return (bacnet_mesgtyp < 0x80)? "Reserved for Use by ASHRAE" : "Vendor Proprietary Message";
	}
}

static const char*
bacnet_rejectreason_name (guint8 bacnet_rejectreason) {
	static const char *type_names[] = {
		"Other error.",
		"The router is not directly connected to DNET and cannot find a router to DNET on any directly connected network using Who-Is-Router-To-Network messages.",
		"The router is busy and unable to accept messages for the specified DNET at the present time.",
		"It is an unknown network layer message type.",
		"The message is too long to be routed to this DNET.",
		"The router is no longer directly connected to DNET but can reconnect if requested.",
		"The router is no longer directly connected to DNET and cannot reconnect even if requested."
	};
	return (bacnet_rejectreason > 6)? "Invalid Rejection Reason.":  type_names[bacnet_rejectreason];
}

/* Network Layer Control Information */
#define BAC_CONTROL_NET		0x80
#define BAC_CONTROL_RES1	0x40
#define BAC_CONTROL_DEST	0x20
#define BAC_CONTROL_RES2	0x10
#define BAC_CONTROL_SRC		0x08
#define BAC_CONTROL_EXPECT	0x04
#define BAC_CONTROL_PRIO_HIGH	0x02
#define BAC_CONTROL_PRIO_LOW	0x01

/* Network Layer Message Types */
#define BAC_NET_WHO_R		0x00
#define BAC_NET_IAM_R		0x01
#define BAC_NET_ICB_R		0x02
#define BAC_NET_REJ		0x03
#define BAC_NET_R_BUSY		0x04
#define BAC_NET_R_AVA		0x05
#define BAC_NET_INIT_RTAB	0x06
#define BAC_NET_INIT_RTAB_ACK	0x07
#define BAC_NET_EST_CON		0x08
#define BAC_NET_DISC_CON	0x09

static const true_false_string control_net_set_high = {
	"network layer message, message type field present.",
	"BACnet APDU, message type field absent."
};

static const true_false_string control_res_high = {
	"Shall be zero, but is one.",
	"Shall be zero and is zero."
};
static const true_false_string control_dest_high = {
	"DNET, DLEN and Hop Count present. If DLEN=0: broadcast, dest. address field absent.",
	"DNET, DLEN, DADR and Hop Count absent."
};

static const true_false_string control_src_high = {
	"SNET, SLEN and SADR present, SLEN=0 invalid, SLEN specifies length of SADR",
	"SNET, SLEN and SADR absent"
};

static const true_false_string control_expect_high = {
	"BACnet-Confirmed-Request-PDU, a segment of BACnet-ComplexACK-PDU or Network Message expecting a reply present.",
	"Other than a BACnet-Confirmed-Request-PDU, segment of BACnet-ComplexACK-PDU or network layer message expecting a reply present."
};

static const true_false_string control_prio_high_high = {
	"Life Safety or Critical Equipment message.",
	"Not a Life Safety or Critical Equipment message."
};

static const true_false_string control_prio_low_high = {
	"Urgent message",
	"Normal message"
};


static int proto_bacnet = -1;
static int hf_bacnet_version = -1;
static int hf_bacnet_control = -1;
static int hf_bacnet_control_net = -1;
static int hf_bacnet_control_res1 = -1;
static int hf_bacnet_control_dest = -1;
static int hf_bacnet_control_res2 = -1;
static int hf_bacnet_control_src = -1;
static int hf_bacnet_control_expect = -1;
static int hf_bacnet_control_prio_high = -1;
static int hf_bacnet_control_prio_low = -1;
static int hf_bacnet_dnet = -1;
static int hf_bacnet_dlen = -1;
static int hf_bacnet_dadr_eth = -1;
static int hf_bacnet_dadr_mstp = -1;
static int hf_bacnet_dadr_tmp = -1;
static int hf_bacnet_snet = -1;
static int hf_bacnet_slen = -1;
static int hf_bacnet_sadr_eth = -1;
static int hf_bacnet_sadr_mstp = -1;
static int hf_bacnet_sadr_tmp = -1;
static int hf_bacnet_hopc = -1;
static int hf_bacnet_mesgtyp = -1;
static int hf_bacnet_vendor = -1;
static int hf_bacnet_perf = -1;
static int hf_bacnet_rejectreason = -1;
static int hf_bacnet_rportnum = -1;
static int hf_bacnet_portid = -1;
static int hf_bacnet_pinfolen = -1;
static int hf_bacnet_term_time_value = -1;

static gint ett_bacnet = -1;
static gint ett_bacnet_control = -1;

static void
dissect_bacnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_item *ct;
	proto_tree *bacnet_tree;
	proto_tree *control_tree;

	gint offset;
	guint8 bacnet_version;
	guint8 bacnet_control;
	guint8 bacnet_dlen;
	guint8 bacnet_slen;
	guint8 bacnet_mesgtyp;
	guint8 bacnet_rejectreason;
	guint8 bacnet_rportnum;
	guint8 bacnet_pinfolen;
	guint8 i;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "BACnet-NPDU");

	col_set_str(pinfo->cinfo, COL_INFO, "Building Automation and Control Network NPDU");

	offset = 0;
	bacnet_version = tvb_get_guint8(tvb, offset);
	bacnet_control = tvb_get_guint8(tvb, offset+1);
	bacnet_dlen = 0;
	bacnet_slen = 0;
	bacnet_mesgtyp = 0;
	bacnet_rejectreason = 0;
	bacnet_rportnum = 0;
	bacnet_pinfolen =0;
	i = 0;

	/* I don't know the length of the NPDU yet; Setting the length after dissection */
	ti = proto_tree_add_item(tree, proto_bacnet, tvb, 0, -1, FALSE);

	bacnet_tree = proto_item_add_subtree(ti, ett_bacnet);

	proto_tree_add_uint_format_value(bacnet_tree, hf_bacnet_version, tvb,
					 offset, 1,
					 bacnet_version,"0x%02x (%s)",bacnet_version,
					 (bacnet_version == 0x01)?"ASHRAE 135-1995":"unknown");
	offset ++;
	ct = proto_tree_add_uint(bacnet_tree, hf_bacnet_control,
		tvb, offset, 1, bacnet_control);
	control_tree = proto_item_add_subtree(ct, ett_bacnet_control);
	proto_tree_add_boolean(control_tree, hf_bacnet_control_net,
		tvb, offset, 1, bacnet_control);
	proto_tree_add_boolean(control_tree, hf_bacnet_control_res1, tvb,
		offset, 1, bacnet_control);
	proto_tree_add_boolean(control_tree, hf_bacnet_control_dest, tvb,
		offset, 1, bacnet_control);
	proto_tree_add_boolean(control_tree, hf_bacnet_control_res2, tvb,
		offset, 1, bacnet_control);
	proto_tree_add_boolean(control_tree, hf_bacnet_control_src, tvb,
		offset, 1, bacnet_control);
	proto_tree_add_boolean(control_tree, hf_bacnet_control_expect, tvb,
		offset, 1, bacnet_control);
	proto_tree_add_boolean(control_tree, hf_bacnet_control_prio_high,
		tvb, offset, 1, bacnet_control);
	proto_tree_add_boolean(control_tree, hf_bacnet_control_prio_low,
		tvb, offset, 1, bacnet_control);
	offset ++;
	if (bacnet_control & BAC_CONTROL_DEST) { /* DNET, DLEN, DADR */
		proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
			tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		bacnet_dlen = tvb_get_guint8(tvb, offset);
		/* DLEN = 0 is broadcast on dest.network */
		if( bacnet_dlen == 0) {
			/* append to hf_bacnet_dlen: broadcast */
			proto_tree_add_uint_format_value(bacnet_tree,
			    hf_bacnet_dlen, tvb, offset, 1, bacnet_dlen,
			    "%d indicates Broadcast on Destination Network",
			    bacnet_dlen);
			offset ++;
			/* going to SNET */
		} else if (bacnet_dlen==6) {
			proto_tree_add_uint(bacnet_tree, hf_bacnet_dlen,
				tvb, offset, 1, bacnet_dlen);
			offset ++;
			/* Ethernet MAC */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_dadr_eth, tvb, offset,
				bacnet_dlen, FALSE);
			offset += bacnet_dlen;
		} else if (bacnet_dlen==1) {
			proto_tree_add_uint(bacnet_tree, hf_bacnet_dlen,
				tvb, offset, 1, bacnet_dlen);
			offset ++;
			/* MS/TP or ARCNET MAC */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_dadr_mstp, tvb, offset,
				bacnet_dlen, ENC_BIG_ENDIAN);
			offset += bacnet_dlen;
		} else if (bacnet_dlen<7) {
			proto_tree_add_uint(bacnet_tree, hf_bacnet_dlen,
				tvb, offset, 1, bacnet_dlen);
			offset ++;
			/* Other MAC formats should be included here */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_dadr_tmp, tvb, offset,
				bacnet_dlen, ENC_NA);
			offset += bacnet_dlen;
		} else {
			proto_tree_add_uint_format_value(bacnet_tree,
			    hf_bacnet_dlen, tvb, offset, 1, bacnet_dlen,
			    "%d invalid!",
			    bacnet_dlen);
		}
	}
	if (bacnet_control & BAC_CONTROL_SRC) { /* SNET, SLEN, SADR */
		/* SNET */
		proto_tree_add_uint(bacnet_tree, hf_bacnet_snet,
			tvb, offset, 2, tvb_get_ntohs(tvb, offset));
		offset += 2;
		bacnet_slen = tvb_get_guint8(tvb, offset);
		if( bacnet_slen == 0) { /* SLEN = 0 invalid */
			proto_tree_add_uint_format_value(bacnet_tree,
			    hf_bacnet_slen, tvb, offset, 1, bacnet_slen,
			    "%d invalid!",
			    bacnet_slen);
			offset ++;
		} else if (bacnet_slen==6) {
			/* SLEN */
			 proto_tree_add_uint(bacnet_tree, hf_bacnet_slen,
				tvb, offset, 1, bacnet_slen);
			offset ++;
			/* Ethernet MAC */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_sadr_eth, tvb, offset,
				bacnet_slen, FALSE);
			offset += bacnet_slen;
		} else if (bacnet_slen==1) {
			/* SLEN */
			 proto_tree_add_uint(bacnet_tree, hf_bacnet_slen,
				tvb, offset, 1, bacnet_slen);
			offset ++;
			/* MS/TP or ARCNET MAC */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_sadr_mstp, tvb, offset,
				bacnet_slen, ENC_BIG_ENDIAN);
			offset += bacnet_slen;
		} else if (bacnet_slen<6) { /* LON MAC */
			/* SLEN */
			 proto_tree_add_uint(bacnet_tree, hf_bacnet_slen,
				tvb, offset, 1, bacnet_slen);
			offset ++;
			/* Other MAC formats should be included here */
			proto_tree_add_item(bacnet_tree,
				hf_bacnet_sadr_tmp, tvb, offset,
				bacnet_slen, ENC_NA);
			offset += bacnet_slen;
		} else {
			proto_tree_add_uint_format_value(bacnet_tree,
			hf_bacnet_slen, tvb, offset, 1, bacnet_slen,
			    "%d invalid!",
			    bacnet_slen);
			offset ++;
		}
	}
	if (bacnet_control & BAC_CONTROL_DEST) { /* Hopcount */
		proto_tree_add_item(bacnet_tree, hf_bacnet_hopc,
			tvb, offset, 1, ENC_BIG_ENDIAN);
		offset ++;
	}
	/* Network Layer Message Type */
	if (bacnet_control & BAC_CONTROL_NET) {
		bacnet_mesgtyp =  tvb_get_guint8(tvb, offset);
		proto_tree_add_uint_format_value(bacnet_tree,
		hf_bacnet_mesgtyp, tvb, offset, 1, bacnet_mesgtyp,
			"%02x (%s)", bacnet_mesgtyp,
			bacnet_mesgtyp_name(bacnet_mesgtyp));
		/* Put the NPDU Type in the info column */
		col_add_str(pinfo->cinfo, COL_INFO,
			    bacnet_mesgtyp_name(bacnet_mesgtyp));
		offset ++;
		/* Vendor ID
		* The standard says: "If Bit 7 of the control octet is 1 and
		* the Message Type field contains a value in the range
		* X'80' - X'FF', then a Vendor ID field shall be present (...)."
		* We should not go any further in dissecting the packet if it's
		* not present, but we don't know about that: No length field...
		*/
		if (bacnet_mesgtyp > 0x7f) {
			proto_tree_add_item(bacnet_tree, hf_bacnet_vendor,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			call_dissector(data_handle,
				tvb_new_subset_remaining(tvb, offset), pinfo, tree);
		}
		/* Performance Index (in I-Could-Be-Router-To-Network) */
		if (bacnet_mesgtyp == BAC_NET_ICB_R) {
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(bacnet_tree, hf_bacnet_perf,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
		}
		/* Reason, DNET (in Reject-Message-To-Network) */
		if (bacnet_mesgtyp == BAC_NET_REJ) {
			bacnet_rejectreason = tvb_get_guint8(tvb, offset);
			proto_tree_add_uint_format_value(bacnet_tree,
				hf_bacnet_rejectreason,
				tvb, offset, 1,
				bacnet_rejectreason, "%d (%s)",
				bacnet_rejectreason,
				bacnet_rejectreason_name(bacnet_rejectreason));
			offset ++;
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
		/* N*DNET (in Router-Busy-To-Network,Router-Available-To-Network) */
		if ((bacnet_mesgtyp == BAC_NET_R_BUSY) ||
			(bacnet_mesgtyp == BAC_NET_WHO_R) ||
			(bacnet_mesgtyp == BAC_NET_R_AVA) ||
			(bacnet_mesgtyp == BAC_NET_IAM_R) ) {
			while(tvb_reported_length_remaining(tvb, offset) > 1 ) {
				proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
					tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
			}
		}
		/* Initialize-Routing-Table */
		if ( (bacnet_mesgtyp == BAC_NET_INIT_RTAB) ||
			(bacnet_mesgtyp == BAC_NET_INIT_RTAB_ACK) ) {
			bacnet_rportnum = tvb_get_guint8(tvb, offset);
			/* number of ports */
			proto_tree_add_uint(bacnet_tree, hf_bacnet_rportnum,
				tvb, offset, 1, bacnet_rportnum);
			offset ++;
			for(i=0; i<bacnet_rportnum; i++) {
					/* Connected DNET */
					proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
					tvb, offset, 2, ENC_BIG_ENDIAN);
					offset += 2;
					/* Port ID */
					proto_tree_add_item(bacnet_tree, hf_bacnet_portid,
					tvb, offset, 1, ENC_BIG_ENDIAN);
					offset ++;
					/* Port Info Length */
					bacnet_pinfolen = tvb_get_guint8(tvb, offset);
					proto_tree_add_uint(bacnet_tree, hf_bacnet_pinfolen,
					tvb, offset, 1, bacnet_pinfolen);
					offset ++;
					proto_tree_add_text(bacnet_tree, tvb, offset,
					bacnet_pinfolen, "Port Info: %s",
					tvb_bytes_to_str(tvb, offset, bacnet_pinfolen));
					offset += bacnet_pinfolen;
			}
		}
		/* Establish-Connection-To-Network */
		if (bacnet_mesgtyp == BAC_NET_EST_CON) {
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
			proto_tree_add_item(bacnet_tree, hf_bacnet_term_time_value,
				tvb, offset, 1, ENC_BIG_ENDIAN);
			offset ++;
		}
		/* Disconnect-Connection-To-Network */
		if (bacnet_mesgtyp == BAC_NET_DISC_CON) {
			proto_tree_add_item(bacnet_tree, hf_bacnet_dnet,
				tvb, offset, 2, ENC_BIG_ENDIAN);
			offset += 2;
		}
	}
	/* Now set NPDU length */
	proto_item_set_len(ti, offset);

	/* dissect BACnet APDU */
	next_tvb = tvb_new_subset_remaining(tvb,offset);
	if (bacnet_control & BAC_CONTROL_NET) {
		/* Unknown function - dissect the payload as data */
		call_dissector(data_handle, next_tvb, pinfo, tree);
	} else {
		/* APDU - call the APDU dissector */
		call_dissector(bacapp_handle, next_tvb, pinfo, tree);
	}
}

void
proto_register_bacnet(void)
{
	static hf_register_info hf[] = {
		{ &hf_bacnet_version,
			{ "Version",           "bacnet.version",
			FT_UINT8, BASE_DEC, NULL, 0,
			"BACnet Version", HFILL }
		},
		{ &hf_bacnet_control,
			{ "Control",           "bacnet.control",
			FT_UINT8, BASE_HEX, NULL, 0,
			"BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_net,
			{ "NSDU contains",
			"bacnet.control_net",
			FT_BOOLEAN, 8, TFS(&control_net_set_high),
			BAC_CONTROL_NET, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_res1,
			{ "Reserved",
			"bacnet.control_res1",
			FT_BOOLEAN, 8, TFS(&control_res_high),
			BAC_CONTROL_RES1, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_dest,
			{ "Destination Specifier",
			"bacnet.control_dest",
			FT_BOOLEAN, 8, TFS(&control_dest_high),
			BAC_CONTROL_DEST, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_res2,
			{ "Reserved",
			"bacnet.control_res2",
			FT_BOOLEAN, 8, TFS(&control_res_high),
			BAC_CONTROL_RES2, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_src,
			{ "Source specifier",
			"bacnet.control_src",
			FT_BOOLEAN, 8, TFS(&control_src_high),
			BAC_CONTROL_SRC, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_expect,
			{ "Expecting Reply",
			"bacnet.control_expect",
			FT_BOOLEAN, 8, TFS(&control_expect_high),
			BAC_CONTROL_EXPECT, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_prio_high,
			{ "Priority",
			"bacnet.control_prio_high",
			FT_BOOLEAN, 8, TFS(&control_prio_high_high),
			BAC_CONTROL_PRIO_HIGH, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_control_prio_low,
			{ "Priority",
			"bacnet.control_prio_low",
			FT_BOOLEAN, 8, TFS(&control_prio_low_high),
			BAC_CONTROL_PRIO_LOW, "BACnet Control", HFILL }
		},
		{ &hf_bacnet_dnet,
			{ "Destination Network Address", "bacnet.dnet",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_dlen,
			{ "Destination MAC Layer Address Length", "bacnet.dlen",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_dadr_eth,
			{ "Destination ISO 8802-3 MAC Address", "bacnet.dadr_eth",
			FT_ETHER, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_dadr_mstp,
			{ "DADR", "bacnet.dadr_mstp",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Destination MS/TP or ARCNET MAC Address", HFILL }
		},
		{ &hf_bacnet_dadr_tmp,
			{ "Unknown Destination MAC", "bacnet.dadr_tmp",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_snet,
			{ "Source Network Address", "bacnet.snet",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_slen,
			{ "Source MAC Layer Address Length", "bacnet.slen",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_sadr_eth,
			{ "SADR", "bacnet.sadr_eth",
			FT_ETHER, BASE_NONE, NULL, 0,
			"Source ISO 8802-3 MAC Address", HFILL }
		},
		{ &hf_bacnet_sadr_mstp,
			{ "SADR", "bacnet.sadr_mstp",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Source MS/TP or ARCNET MAC Address", HFILL }
		},
		{ &hf_bacnet_sadr_tmp,
			{ "Unknown Source MAC", "bacnet.sadr_tmp",
			FT_BYTES, BASE_NONE, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_hopc,
			{ "Hop Count", "bacnet.hopc",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_mesgtyp,
			{ "Network Layer Message Type", "bacnet.mesgtyp",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_vendor,
			{ "Vendor ID", "bacnet.vendor",
			FT_UINT16, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_perf,
			{ "Performance Index", "bacnet.perf",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_rejectreason,
			{ "Reject Reason", "bacnet.rejectreason",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_rportnum,
			{ "Number of Port Mappings", "bacnet.rportnum",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_pinfolen,
			{ "Port Info Length", "bacnet.pinfolen",
			FT_UINT8, BASE_DEC, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_portid,
			{ "Port ID", "bacnet.portid",
			FT_UINT8, BASE_HEX, NULL, 0,
			NULL, HFILL }
		},
		{ &hf_bacnet_term_time_value,
			{ "Termination Time Value (seconds)", "bacnet.term_time_value",
			FT_UINT8, BASE_DEC, NULL, 0,
			"Termination Time Value", HFILL }
		}
	};

	static gint *ett[] = {
		&ett_bacnet,
		&ett_bacnet_control,
	};

	proto_bacnet = proto_register_protocol("Building Automation and Control Network NPDU",
	    "BACnet", "bacnet");

	proto_register_field_array(proto_bacnet, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("bacnet", dissect_bacnet, proto_bacnet);
}

void
proto_reg_handoff_bacnet(void)
{
	dissector_handle_t bacnet_handle;

	bacnet_handle = find_dissector("bacnet");
	dissector_add_uint("bvlc.function", 0x04, bacnet_handle);
	dissector_add_uint("bvlc.function", 0x09, bacnet_handle);
	dissector_add_uint("bvlc.function", 0x0a, bacnet_handle);
	dissector_add_uint("bvlc.function", 0x0b, bacnet_handle);
	dissector_add_uint("llc.dsap", SAP_BACNET, bacnet_handle);
	bacapp_handle = find_dissector("bacapp");
	data_handle = find_dissector("data");
}
