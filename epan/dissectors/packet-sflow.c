/* packet-sflow.c
 * Routines for sFlow dissection
 * Copyright 2003, Jeff Rizzo <riz@boogers.sf.ca.us>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

/* This file (mostly) implements a dissector for sFlow (RFC3176), 
 * from the version 4 spec at http://www.sflow.org/SFLOW-DATAGRAM.txt . 
 *
 * TODO:
 *   Fix the highlighting of the datastream when bits are selected
 *   split things out into packet-sflow.h ?
 *   make routines more consistent as to whether they return
 *     'offset' or bytes consumed ('len')
 *   implement sampled_ipv4 and sampled_ipv6 packet data types
 *   implement extended_gateway
 *   implement extended_user
 *   implement extended_url
 *   implement non-generic counters sampling
 *   implement the samples from the draft version 5 spec; see
 *      http://www.sflow.org/SFLOW-DATAGRAM5.txt (see epan/sminmpec.h
 *      for tables of SMI Network Management Private Enterprise Codes;
 *      use sminmpec_values, adding new values to epan/sminmpect.h and
 *      and sminmpec_values in epan/sminmpec.c if necessary - don't create
 *      your own table)
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/packet.h>
/*#include "packet-sflow.h"*/

#define UDP_PORT_SFLOW 6343

#define ADDRESS_IPV4 1
#define ADDRESS_IPV6 2

#define FLOWSAMPLE 1
#define COUNTERSSAMPLE 2

static const value_string sflow_sampletype[] = {
	{ FLOWSAMPLE, "Flow sample" },
	{ COUNTERSSAMPLE, "Counters sample" },
	{ 0, NULL }
};

/* interface counter types */
#define SFLOW_COUNTERS_GENERIC 1
#define SFLOW_COUNTERS_ETHERNET 2
#define SFLOW_COUNTERS_TOKENRING 3
#define SFLOW_COUNTERS_FDDI 4
#define SFLOW_COUNTERS_VG 5
#define SFLOW_COUNTERS_WAN 6
#define SFLOW_COUNTERS_VLAN 7

static const value_string sflow_counterstype [] = {
	{ SFLOW_COUNTERS_GENERIC, "Generic counters" },
	{ SFLOW_COUNTERS_ETHERNET, "Ethernet counters" },
	{ SFLOW_COUNTERS_FDDI, "FDDI counters" },
	{ SFLOW_COUNTERS_VG, "100baseVG counters" },
	{ SFLOW_COUNTERS_WAN, "WAN counters" },
	{ SFLOW_COUNTERS_VLAN, "VLAN counters" },
	{ 0, NULL }
};

#define MAX_HEADER_SIZE 256

#define SFLOW_PACKET_DATA_TYPE_HEADER 1
#define SFLOW_PACKET_DATA_TYPE_IPV4 2
#define SFLOW_PACKET_DATA_TYPE_IPV6 3

static const value_string sflow_packet_information_type [] = {
	{ SFLOW_PACKET_DATA_TYPE_HEADER, "Packet headers are sampled" },
	{ SFLOW_PACKET_DATA_TYPE_IPV4, "IP Version 4 data" },
	{ SFLOW_PACKET_DATA_TYPE_IPV6, "IP Version 6 data" },
	{ 0, NULL}
};

#define SFLOW_HEADER_ETHERNET 1
#define SFLOW_HEADER_TOKENBUS 2
#define SFLOW_HEADER_TOKENRING 3
#define SFLOW_HEADER_FDDI 4
#define SFLOW_HEADER_FRAME_RELAY 5
#define SFLOW_HEADER_X25 6
#define SFLOW_HEADER_PPP 7
#define SFLOW_HEADER_SMDS 8
#define SFLOW_HEADER_AAL5 9
#define SFLOW_HEADER_AAL5_IP 10
#define SFLOW_HEADER_IPv4 11
#define SFLOW_HEADER_IPv6 12
#define SFLOW_HEADER_MPLS 13

static const value_string sflow_header_protocol[] = {
	{ SFLOW_HEADER_ETHERNET, "Ethernet" },
	{ SFLOW_HEADER_TOKENBUS, "Token Bus" },
	{ SFLOW_HEADER_TOKENRING, "Token Ring" },
	{ SFLOW_HEADER_FDDI, "FDDI" },
	{ SFLOW_HEADER_FRAME_RELAY, "Frame Relay" },
	{ SFLOW_HEADER_X25, "X.25" },
	{ SFLOW_HEADER_PPP, "PPP" },
	{ SFLOW_HEADER_SMDS, "SMDS" },
	{ SFLOW_HEADER_AAL5, "ATM AAL5" },
	{ SFLOW_HEADER_AAL5_IP, "ATM AAL5-IP (e.g., Cisco AAL5 mux)" },
	{ SFLOW_HEADER_IPv4, "IPv4" },
	{ SFLOW_HEADER_IPv6, "IPv6" },
	{ SFLOW_HEADER_MPLS, "MPLS" },
	{ 0, NULL }
};

/* extended data types */
#define SFLOW_EXTENDED_SWITCH 1
#define SFLOW_EXTENDED_ROUTER 2
#define SFLOW_EXTENDED_GATEWAY 3
#define SFLOW_EXTENDED_USER 4
#define SFLOW_EXTENDED_URL 5

static const value_string sflow_extended_data_types[] = {
	{ SFLOW_EXTENDED_SWITCH, "Extended switch information" },
	{ SFLOW_EXTENDED_ROUTER, "Extended router information" },
	{ SFLOW_EXTENDED_GATEWAY, "Extended gateway information" },
	{ SFLOW_EXTENDED_USER, "Extended user information" },	
	{ SFLOW_EXTENDED_URL, "Extended URL information" },	
	{ 0, NULL }
};


/* flow sample header */
struct sflow_flow_sample_header {
	guint32 	sequence_number;
	guint32 	source_id;
	guint32 	sampling_rate;
	guint32 	sample_pool;
	guint32 	drops;
 	guint32 	input;
 	guint32 	output;
};

/* counters sample header */
struct sflow_counters_sample_header {
	guint32 	sequence_number;
	guint32 	source_id;
	guint32 	sampling_interval;
	guint32     counters_type;
};

/* generic interface counters */
struct if_counters {
	guint32 	ifIndex;
	guint32 	ifType;
	guint64 	ifSpeed;
	guint32 	ifDirection;
	guint32 	ifStatus;
	guint64 	ifInOctets;
	guint32 	ifInUcastPkts;
	guint32 	ifInMulticastPkts;
	guint32 	ifInBroadcastPkts;
	guint32 	ifInDiscards;
	guint32 	ifInErrors;
	guint32 	ifInUnknownProtos;
	guint64 	ifOutOctets;
	guint32 	ifOutUcastPkts;
	guint32 	ifOutMulticastPkts;
	guint32 	ifOutBroadcastPkts;
	guint32 	ifOutDiscards;
	guint32 	ifOutErrors;
	guint32 	ifPromiscuousMode;
};

/* ethernet counters.  These will be preceded by generic counters. */
struct ethernet_counters {
	guint32 	dot3StatsAlignmentErrors;
	guint32 	dot3StatsFCSErrors;
	guint32 	dot3StatsSingleCollisionFrames;
	guint32 	dot3StatsMultipleCollisionFrames;
	guint32 	dot3StatsSQETestErrors;
	guint32 	dot3StatsDeferredTransmissions;
	guint32 	dot3StatsLateCollisions;
	guint32 	dot3StatsExcessiveCollisions;
	guint32 	dot3StatsInternalMacTransmitErrors;
	guint32 	dot3StatsCarrierSenseErrors;
	guint32 	dot3StatsFrameTooLongs;
	guint32 	dot3StatsInternalMacReceiveErrors;
	guint32 	dot3StatsSymbolErrors;
};

/* Token Ring counters */
struct token_ring_counters {
	guint32 	dot5StatsLineErrors;
	guint32 	dot5StatsBurstErrors;
	guint32 	dot5StatsACErrors;
	guint32 	dot5StatsAbortTransErrors;
	guint32 	dot5StatsInternalErrors;
	guint32 	dot5StatsLostFrameErrors;
	guint32 	dot5StatsReceiveCongestions;
	guint32 	dot5StatsFrameCopiedErrors;
	guint32 	dot5StatsTokenErrors;
	guint32 	dot5StatsSoftErrors;
	guint32 	dot5StatsHardErrors;
	guint32 	dot5StatsSignalLoss;
	guint32 	dot5StatsTransmitBeacons;
	guint32 	dot5StatsRecoverys;
	guint32 	dot5StatsLobeWires;
	guint32 	dot5StatsRemoves;
	guint32 	dot5StatsSingles;
	guint32 	dot5StatsFreqErrors;
};

/* 100BaseVG counters */

struct vg_counters {
	guint32 	dot12InHighPriorityFrames;
	guint64 	dot12InHighPriorityOctets;
	guint32 	dot12InNormPriorityFrames;
	guint64 	dot12InNormPriorityOctets;
	guint32 	dot12InIPMErrors;
	guint32 	dot12InOversizeFrameErrors;
	guint32 	dot12InDataErrors;
	guint32 	dot12InNullAddressedFrames;
	guint32 	dot12OutHighPriorityFrames;
	guint64 	dot12OutHighPriorityOctets;
	guint32 	dot12TransitionIntoTrainings;
	guint64 	dot12HCInHighPriorityOctets;
	guint64 	dot12HCInNormPriorityOctets;
	guint64 	dot12HCOutHighPriorityOctets;
};

/* VLAN counters */

struct vlan_counters {
	guint32 	vlan_id;
	guint32 	octets;
	guint32 	ucastPkts;
	guint32 	multicastPkts;
	guint32 	broadcastPkts;
	guint32 	discards;
};

/* Initialize the protocol and registered fields */
static int proto_sflow = -1;
static int hf_sflow_version = -1;
/*static int hf_sflow_agent_address_type = -1; */
static int hf_sflow_agent_address_v4 = -1;
static int hf_sflow_agent_address_v6 = -1;
static int hf_sflow_sub_agent_id = -1;
static int hf_sflow_seqnum = -1;
static int hf_sflow_sysuptime = -1;
static int hf_sflow_numsamples = -1;
static int hf_sflow_header_protocol = -1;
static int hf_sflow_sampletype = -1;
static int hf_sflow_header = -1;
static int hf_sflow_packet_information_type = -1;
static int hf_sflow_extended_information_type = -1;
static int hf_sflow_vlan_in = -1;   /* incoming 802.1Q VLAN ID */
static int hf_sflow_vlan_out = -1;   /* outgoing 802.1Q VLAN ID */
static int hf_sflow_pri_in = -1;   /* incominging 802.1p priority */
static int hf_sflow_pri_out = -1;   /* outgoing 802.1p priority */
static int hf_sflow_nexthop_v4 = -1;   /* nexthop address */
static int hf_sflow_nexthop_v6 = -1;   /* nexthop address */
static int hf_sflow_nexthop_src_mask = -1;
static int hf_sflow_nexthop_dst_mask = -1;
static int hf_sflow_ifindex = -1;
static int hf_sflow_iftype = -1;
static int hf_sflow_ifspeed = -1;
static int hf_sflow_ifdirection = -1;
static int hf_sflow_ifstatus = -1;
static int hf_sflow_ifinoct = -1;
static int hf_sflow_ifinpkt = -1;
static int hf_sflow_ifinmcast = -1;
static int hf_sflow_ifinbcast = -1;
static int hf_sflow_ifinerr = -1;
static int hf_sflow_ifindisc = -1;
static int hf_sflow_ifinunk = -1;
static int hf_sflow_ifoutoct = -1;
static int hf_sflow_ifoutpkt = -1;
static int hf_sflow_ifoutmcast = -1;
static int hf_sflow_ifoutbcast = -1;
static int hf_sflow_ifoutdisc = -1;
static int hf_sflow_ifouterr = -1;
static int hf_sflow_ifpromisc = -1;

/* Initialize the subtree pointers */
static gint ett_sflow = -1;
static gint ett_sflow_sample = -1;
static gint ett_sflow_extended_data = -1;
static gint ett_sflow_sampled_header = -1;

/* dissectors for other protocols */
static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t tr_handle;
static dissector_handle_t fddi_handle;
static dissector_handle_t fr_handle;
static dissector_handle_t x25_handle;
static dissector_handle_t ppp_handle;
static dissector_handle_t smds_handle;
static dissector_handle_t aal5_handle;
static dissector_handle_t ipv4_handle;
static dissector_handle_t ipv6_handle;
static dissector_handle_t mpls_handle;

/* dissect a sampled header - layer 2 protocols */
static gint
dissect_sflow_sampled_header(tvbuff_t *tvb, packet_info *pinfo,
							 proto_tree *tree, volatile gint offset)
{
	guint32 	header_proto, frame_length;
	volatile 	guint32 	header_length;
	tvbuff_t 	*next_tvb;
	proto_tree 	*sflow_header_tree;
	proto_item 	*ti;
	/* stuff for saving column state before calling other dissectors.
	 * Thanks to Guy Harris for the tip. */
	gboolean 			save_writable;
	volatile address 	save_dl_src;
	volatile address 	save_dl_dst;
	volatile address 	save_net_src;
	volatile address 	save_net_dst;
	volatile address 	save_src;
	volatile address 	save_dst;

	header_proto = tvb_get_ntohl(tvb,offset);
	proto_tree_add_item(tree, hf_sflow_header_protocol, tvb, offset,
						4, FALSE);
	offset += 4;
	frame_length = tvb_get_ntohl(tvb,offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Frame Length: %d bytes",
						frame_length);
	offset += 4;
	header_length = tvb_get_ntohl(tvb,offset);
	offset += 4;

	if (header_length % 4) /* XDR requires 4-byte alignment */
		header_length += 4 - (header_length % 4);

	
	ti = proto_tree_add_item(tree, hf_sflow_header, tvb, offset, 
							 header_length, FALSE);
	sflow_header_tree = proto_item_add_subtree(ti, ett_sflow_sampled_header);

	/* hand the header off to the appropriate dissector.  It's probably
	 * a short frame, so ignore any exceptions. */
	next_tvb = tvb_new_subset(tvb, offset, header_length, frame_length);

	/* save some state */
	save_writable = col_get_writable(pinfo->cinfo);
	col_set_writable(pinfo->cinfo, FALSE);
	save_dl_src = pinfo->dl_src;
	save_dl_dst = pinfo->dl_dst;
	save_net_src = pinfo->net_src;
	save_net_dst = pinfo->net_dst;
	save_src = pinfo->src;
	save_dst = pinfo->dst;

	TRY {
		switch (header_proto) {
		case SFLOW_HEADER_ETHERNET:
			call_dissector(eth_withoutfcs_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_TOKENRING:
			call_dissector(tr_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_FDDI:
			call_dissector(fddi_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_FRAME_RELAY:
			call_dissector(fr_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_X25:
			call_dissector(x25_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_PPP:
			call_dissector(ppp_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_SMDS:
			call_dissector(smds_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_AAL5:
		case SFLOW_HEADER_AAL5_IP:
			/* I'll be surprised if this works! I have no AAL5 captures
			 * to test with, and I'm not sure how the encapsulation goes */
			call_dissector(aal5_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_IPv4:
			call_dissector(ipv4_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_IPv6:
			call_dissector(ipv6_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		case SFLOW_HEADER_MPLS:
			call_dissector(mpls_handle, next_tvb, pinfo, sflow_header_tree);
			break;
		default:
			/* some of the protocols, I have no clue where to begin. */
			break;
		};
	}
	CATCH2(BoundsError, ReportedBoundsError) {
		; /* do nothing */
	}
	ENDTRY;

	/* restore saved state */
	col_set_writable(pinfo->cinfo, save_writable);
	pinfo->dl_src = save_dl_src;
	pinfo->dl_dst = save_dl_dst;
	pinfo->net_src = save_net_src;
	pinfo->net_dst = save_net_dst;
	pinfo->src = save_src;
	pinfo->dst = save_dst;
	
	offset += header_length;
	return offset;
}

/* extended switch data, after the packet data */
static gint
dissect_sflow_extended_switch(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	gint32 len = 0;
	
	proto_tree_add_item(tree, hf_sflow_vlan_in, tvb, offset + len, 4, FALSE);
	len += 4;
	proto_tree_add_item(tree, hf_sflow_vlan_out, tvb, offset + len, 4, FALSE);
	len += 4;
	proto_tree_add_item(tree, hf_sflow_pri_in, tvb, offset + len, 4, FALSE);
	len += 4;
	proto_tree_add_item(tree, hf_sflow_pri_out, tvb, offset + len, 4, FALSE);
	len += 4;

	return len;
}

/* extended router data, after the packet data */
static gint
dissect_sflow_extended_router(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	gint32 	len = 0;
	guint32 address_type;

	address_type = tvb_get_ntohl(tvb, offset);
	len += 4;
	switch (address_type) {
	case ADDRESS_IPV4:
		proto_tree_add_item(tree, hf_sflow_nexthop_v4, tvb, offset + len,
							4, FALSE);
		len += 4;
		break;
	case ADDRESS_IPV6:
		proto_tree_add_item(tree, hf_sflow_nexthop_v6, tvb, offset + len,
							16, FALSE);
		len += 16;
		break;
	default:
		proto_tree_add_text(tree, tvb, offset + len - 4, 4,
							"Unknown address type (%d)", address_type);
		len += 4;  /* not perfect, but what else to do? */
		return len;  /* again, this is wrong.  but... ? */
		break;
	};
	
	proto_tree_add_item(tree, hf_sflow_nexthop_src_mask, tvb, offset + len,
							4, FALSE);
	len += 4;
	proto_tree_add_item(tree, hf_sflow_nexthop_dst_mask, tvb, offset + len,
							4, FALSE);
	len += 4;
	return len;
}

/* dissect a flow sample */
static gint
dissect_sflow_flow_sample(tvbuff_t *tvb, packet_info *pinfo,
						  proto_tree *tree, gint offset, proto_item *parent)
{
	struct sflow_flow_sample_header 	flow_header;
	proto_tree 	*extended_data_tree;
	proto_item *ti;
	guint32 	packet_type, extended_data, ext_type, i;

	/* grab the flow header.  This will remain in network byte
	   order, so must convert each item before use */
	tvb_memcpy(tvb,(guint8 *)&flow_header,offset,sizeof(flow_header));
	proto_tree_add_text(tree, tvb, offset, 4,
						"Sequence number: %u",
						g_ntohl(flow_header.sequence_number));
	proto_item_append_text(parent, ", seq %u",
						   g_ntohl(flow_header.sequence_number));
	proto_tree_add_text(tree, tvb, offset+4, 4,
						"Source ID class: %u index: %u",
						g_ntohl(flow_header.source_id) >> 24,
						g_ntohl(flow_header.source_id) & 0x00ffffff);
	proto_tree_add_text(tree, tvb, offset+8, 4,
						"Sampling rate: 1 out of %u packets",
						g_ntohl(flow_header.sampling_rate));
	proto_tree_add_text(tree, tvb, offset+12, 4,
						"Sample pool: %u total packets",
						g_ntohl(flow_header.sample_pool));
	proto_tree_add_text(tree, tvb, offset+16, 4,
						"Dropped packets: %u",
						g_ntohl(flow_header.drops));
	proto_tree_add_text(tree, tvb, offset+20, 4,
						"Input Interface: ifIndex %u",
						g_ntohl(flow_header.input));
	if (g_ntohl(flow_header.output) >> 31)
		proto_tree_add_text(tree, tvb, offset+24, 4,
							"multiple outputs: %u interfaces",
							g_ntohl(flow_header.output) & 0x00ffffff);
	else 
		proto_tree_add_text(tree, tvb, offset+24, 4,
							"Output interface: ifIndex %u",
							g_ntohl(flow_header.output) & 0x00ffffff);
	offset += sizeof(flow_header);

	/* what kind of flow sample is it? */
	packet_type = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint(tree, hf_sflow_packet_information_type, tvb, offset,
	    4, packet_type);
	offset += 4;
	switch (packet_type) {
	case SFLOW_PACKET_DATA_TYPE_HEADER:
		offset = dissect_sflow_sampled_header(tvb, pinfo, tree, offset);
		break;
	case SFLOW_PACKET_DATA_TYPE_IPV4:
	case SFLOW_PACKET_DATA_TYPE_IPV6:
	default:
		break;
	};
	/* still need to dissect extended data */
	extended_data = tvb_get_ntohl(tvb,offset);
	offset += 4; 

	for (i=0; i < extended_data; i++) {
		/* figure out what kind of extended data it is */
		ext_type = tvb_get_ntohl(tvb,offset);

		/* create a subtree.  Might want to move this to
		 * the end, so more info can be correct.
		 */
		ti = proto_tree_add_text(tree, tvb, offset, -1, "%s",
								 val_to_str(ext_type, 
											sflow_extended_data_types,
											"Unknown extended information"));
		extended_data_tree = proto_item_add_subtree(ti, ett_sflow_extended_data);
		proto_tree_add_uint(extended_data_tree,
		    hf_sflow_extended_information_type, tvb, offset, 4,
		    ext_type);
		offset += 4;

		switch (ext_type) {
		case SFLOW_EXTENDED_SWITCH:
			offset += dissect_sflow_extended_switch(tvb, extended_data_tree,
													offset);
			break;
		case SFLOW_EXTENDED_ROUTER:
			offset += dissect_sflow_extended_router(tvb, extended_data_tree,
													offset);
			break;
		case SFLOW_EXTENDED_GATEWAY:
			break;
		case SFLOW_EXTENDED_USER:
			break;
		case SFLOW_EXTENDED_URL:
			break;
		default:
			break;
		}
		proto_item_set_end(ti, tvb, offset);
	}
	return offset;
	
}

/* dissect a counters sample */
static gint
dissect_sflow_counters_sample(tvbuff_t *tvb, proto_tree *tree,
							  gint offset, proto_item *parent)
{
	struct sflow_counters_sample_header 	counters_header;
	struct if_counters ifc;
	struct ethernet_counters ethc;
	struct token_ring_counters tokc;
	struct vg_counters vgc;
	struct vlan_counters vlanc;
	
	/* grab the flow header.  This will remain in network byte
	   order, so must convert each item before use */
	tvb_memcpy(tvb,(guint8 *)&counters_header,offset,sizeof(counters_header));
	proto_tree_add_text(tree, tvb, offset, 4,
						"Sequence number: %u",
						g_ntohl(counters_header.sequence_number));
	proto_item_append_text(parent, ", seq %u",
						   g_ntohl(counters_header.sequence_number));
	proto_tree_add_text(tree, tvb, offset + 4, 4,
						"Source ID class: %u index: %u",
						g_ntohl(counters_header.source_id) >> 24,
						g_ntohl(counters_header.source_id) & 0x00ffffff);
	proto_tree_add_text(tree, tvb, offset + 8, 4,
						"Sampling Interval: %u",
						g_ntohl(counters_header.sampling_interval));
	proto_tree_add_text(tree, tvb, offset + 12, 4, "Counters type: %s",
						val_to_str(g_ntohl(counters_header.counters_type),
								   sflow_counterstype, "Unknown type"));

	offset += sizeof(counters_header);

	/* most counters types have the "generic" counters first */
	switch (g_ntohl(counters_header.counters_type)) {
	case SFLOW_COUNTERS_GENERIC:
	case SFLOW_COUNTERS_ETHERNET:
	case SFLOW_COUNTERS_TOKENRING:
	case SFLOW_COUNTERS_FDDI:
	case SFLOW_COUNTERS_VG:
	case SFLOW_COUNTERS_WAN:
		tvb_memcpy(tvb,(guint8 *)&ifc, offset, sizeof(ifc));
		proto_item_append_text(parent, ", ifIndex %u",
							   g_ntohl(ifc.ifIndex));
		proto_tree_add_item(tree, hf_sflow_ifindex, tvb, offset, 4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_iftype, tvb, offset, 4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifspeed, tvb, offset, 8, FALSE);
		offset += 8;
		proto_tree_add_item(tree, hf_sflow_ifdirection, tvb, offset, 
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifstatus, tvb, offset, 4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifinoct, tvb, offset, 8, FALSE);
		offset += 8;
		proto_tree_add_item(tree, hf_sflow_ifinpkt, tvb, offset, 4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifinmcast, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifinbcast, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifindisc, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifinerr, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifinunk, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifoutoct, tvb, offset, 8, FALSE);
		offset += 8;
		proto_tree_add_item(tree, hf_sflow_ifoutpkt, tvb, offset, 4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifoutmcast, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifoutbcast, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifoutdisc, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifouterr, tvb, offset,
							4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_ifpromisc, tvb, offset,
							4, FALSE);
		offset += 4;
		break;
	};
	
	/* Some counter types have other info to gather */
	switch (g_ntohl(counters_header.counters_type)) {
	case SFLOW_COUNTERS_ETHERNET:
		tvb_memcpy(tvb,(guint8 *)&ethc, offset, sizeof(ethc));
		offset += sizeof(ethc);
		break;
	case SFLOW_COUNTERS_TOKENRING:
		tvb_memcpy(tvb,(guint8 *)&tokc, offset, sizeof(tokc));
		offset += sizeof(tokc);
		break;
	case SFLOW_COUNTERS_VG:
		tvb_memcpy(tvb,(guint8 *)&vgc, offset, sizeof(vgc));
		offset += sizeof(vgc);
		break;
	case SFLOW_COUNTERS_VLAN:
		tvb_memcpy(tvb,(guint8 *)&vlanc, offset, sizeof(vlanc));
		offset += sizeof(vlanc);
		break;
	default:
		break;
	}
	return offset;
}

/* Code to dissect the sflow samples */
static gint
dissect_sflow_samples(tvbuff_t *tvb, packet_info *pinfo,
					  proto_tree *tree, gint offset)
{
	proto_tree 	*sflow_sample_tree;
	proto_item 	*ti; /* tree item */
	guint32 	sample_type;
	
	/* decide what kind of sample it is. */
	sample_type = tvb_get_ntohl(tvb,offset);

	ti = proto_tree_add_text(tree, tvb, offset, -1, "%s",
							 val_to_str(sample_type, sflow_sampletype,
										"Unknown sample type"));
	sflow_sample_tree = proto_item_add_subtree(ti, ett_sflow_sample);

	proto_tree_add_item(sflow_sample_tree, hf_sflow_sampletype, tvb,
						offset,	4, FALSE);
	offset += 4;

	switch (sample_type) {
	case FLOWSAMPLE:
		offset = dissect_sflow_flow_sample(tvb, pinfo, sflow_sample_tree,
										 offset, ti);
		break;
	case COUNTERSSAMPLE:
		offset = dissect_sflow_counters_sample(tvb, sflow_sample_tree,
											 offset, ti);
		break;
	default:
		break;
	}
	proto_item_set_end(ti, tvb, offset);
	return offset;
}

/* Code to actually dissect the packets */
static void
dissect_sflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item *ti;
	proto_tree *sflow_tree;
	guint32		version, sub_agent_id, seqnum;
	guint32		agent_address_type;
	union {
		guint8	v4[4];
		guint8	v6[16];
	} agent_address;
	guint32		numsamples;
	volatile guint		offset=0;
	guint 	i=0;

/* Make entries in Protocol column and Info column on summary display */
	if (check_col(pinfo->cinfo, COL_PROTOCOL)) 
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "sFlow");
    

	/* create display subtree for the protocol */
	ti = proto_tree_add_item(tree, proto_sflow, tvb, 0, -1, FALSE);
	
	sflow_tree = proto_item_add_subtree(ti, ett_sflow);
		
	version = tvb_get_ntohl(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO)) 
		col_add_fstr(pinfo->cinfo, COL_INFO, "V%u",
					 version);
	proto_tree_add_item(sflow_tree,
						hf_sflow_version, tvb, offset, 4, FALSE);
	offset += 4;

	agent_address_type = tvb_get_ntohl(tvb, offset);
	offset += 4;
	switch (agent_address_type) {
	case ADDRESS_IPV4:
		tvb_memcpy(tvb, agent_address.v4, offset, 4);
		if (check_col(pinfo->cinfo, COL_INFO)) 
			col_append_fstr(pinfo->cinfo, COL_INFO, ", agent %s",
						 ip_to_str(agent_address.v4));
		proto_tree_add_item(sflow_tree,
							hf_sflow_agent_address_v4, tvb, offset,
							4, FALSE);
		offset += 4;
		break;
	case ADDRESS_IPV6:
		tvb_memcpy(tvb, agent_address.v6, offset, 16);
		if (check_col(pinfo->cinfo, COL_INFO)) 
			col_append_fstr(pinfo->cinfo, COL_INFO, ", agent %s",
							ip6_to_str((struct e_in6_addr *)agent_address.v6));
		proto_tree_add_item(sflow_tree,
							hf_sflow_agent_address_v6, tvb, offset,
							16, FALSE);
		offset += 16;
		break;
	default:
		/* unknown address.  this will cause a malformed packet.  */
		break;
	};

	if (version == 5) {
		sub_agent_id = tvb_get_ntohl(tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO)) 
			col_append_fstr(pinfo->cinfo, COL_INFO, ", sub-agent ID %u",
							sub_agent_id);
		proto_tree_add_uint(sflow_tree, hf_sflow_sub_agent_id, tvb,
						offset, 4, sub_agent_id);
		offset += 4;
	}
	seqnum = tvb_get_ntohl(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", seq %u", seqnum);
	proto_tree_add_uint(sflow_tree, hf_sflow_seqnum, tvb,
						offset, 4, seqnum);
	offset += 4;
	proto_tree_add_item(sflow_tree, hf_sflow_sysuptime, tvb,
						offset, 4, FALSE);
	offset += 4;
	numsamples = tvb_get_ntohl(tvb,offset);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %u samples",
						numsamples);
	proto_tree_add_uint(sflow_tree, hf_sflow_numsamples, tvb,
						offset, 4, numsamples);
	offset += 4;

	/* Ok, we're now at the end of the sflow datagram header;
	 * everything from here out should be samples. Loop over
	 * the expected number of samples, and pass them to the appropriate
	 * dissectors.
	 */
	if (version == 5) {
		proto_tree_add_text(sflow_tree, tvb, offset, -1,
		    "sFlow V5 samples (please write and contribute code to dissect them!)");
	} else {
		for (i=0; i < numsamples; i++) {
			offset = dissect_sflow_samples(tvb, pinfo, sflow_tree,
			    offset);
		}
	}
}


/* Register the protocol with Ethereal */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_sflow(void)
{                 

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {
		{ &hf_sflow_version,
			{ "datagram version", "sflow.version",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"sFlow datagram version", HFILL }
		},
		{ &hf_sflow_agent_address_v4,
			{ "agent address", "sflow.agent",
			FT_IPv4, BASE_NONE, NULL, 0x0,          
			"sFlow Agent IP address", HFILL }
		},
		{ &hf_sflow_agent_address_v6,
			{ "agent address", "sflow.agent.v6",
			FT_IPv6, BASE_NONE, NULL, 0x0,          
			"sFlow Agent IPv6 address", HFILL }
		},
		{ &hf_sflow_sub_agent_id,
			{ "Sub-agent ID", "sflow.sub_agent_id",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"sFlow sub-agent ID", HFILL }
		},
		{ &hf_sflow_seqnum,
			{ "Sequence number", "sflow.sequence_number",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"sFlow datagram sequence number", HFILL }
		},
		{ &hf_sflow_sysuptime,
			{ "SysUptime", "sflow.sysuptime",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"System Uptime", HFILL }
		},
		{ &hf_sflow_numsamples,
			{ "NumSamples", "sflow.numsamples",
			FT_UINT32, BASE_DEC, NULL, 0x0,          
			"Number of samples in sFlow datagram", HFILL }
		},
		{ &hf_sflow_sampletype,
			{ "sFlow sample type", "sflow.sampletype",
			FT_UINT32, BASE_DEC, VALS(sflow_sampletype), 0x0,          
			"Type of sFlow sample", HFILL }
		},
		{ &hf_sflow_header_protocol,
			{ "Header protocol", "sflow.header_protocol",
			FT_UINT32, BASE_DEC, VALS(sflow_header_protocol), 0x0,          
			"Protocol of sampled header", HFILL }
		},
		{ &hf_sflow_header,
			{ "Header of sampled packet", "sflow.header",
			FT_BYTES, BASE_HEX, NULL, 0x0,          
			"Data from sampled header", HFILL }
		},
		{ &hf_sflow_packet_information_type,
			{ "Sample type", "sflow.packet_information_type",
			FT_UINT32, BASE_DEC, VALS(sflow_packet_information_type), 0x0,
			"Type of sampled information", HFILL }
		},
		{ &hf_sflow_extended_information_type,
			{ "Extended information type", "sflow.extended_information_type",
			FT_UINT32, BASE_DEC, VALS(sflow_extended_data_types), 0x0,
			"Type of extended information", HFILL }
		},
		{ &hf_sflow_vlan_in,
			{ "Incoming 802.1Q VLAN", "sflow.vlan.in",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Incoming VLAN ID", HFILL }
		},
		{ &hf_sflow_vlan_out,
			{ "Outgoing 802.1Q VLAN", "sflow.vlan.out",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Outgoing VLAN ID", HFILL }
		},
		{ &hf_sflow_pri_in,
			{ "Incoming 802.1p priority", "sflow.pri.in",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Incoming 802.1p priority", HFILL }
		},
		{ &hf_sflow_pri_out,
			{ "Outgoing 802.1p priority", "sflow.pri.out",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Outgoing 802.1p priority", HFILL }
		},
		{ &hf_sflow_nexthop_v4,
			{ "Next hop", "sflow.nexthop",
			FT_IPv4, BASE_DEC, NULL, 0x0,
			"Next hop address", HFILL }
		},
		{ &hf_sflow_nexthop_v6,
			{ "Next hop", "sflow.nexthop",
			FT_IPv6, BASE_HEX, NULL, 0x0,
			"Next hop address", HFILL }
		},
		{ &hf_sflow_nexthop_src_mask,
		  { "Next hop source mask", "sflow.nexthop.src_mask",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Next hop source mask bits", HFILL }
		},
		{ &hf_sflow_nexthop_dst_mask,
		  { "Next hop destination mask", "sflow.nexthop.dst_mask",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Next hop destination mask bits", HFILL }
		},
		{ &hf_sflow_ifindex,
		  { "Interface index", "sflow.ifindex",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Index", HFILL }
		},
		{ &hf_sflow_iftype,
		  { "Interface Type", "sflow.iftype",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Type", HFILL }
		},
		{ &hf_sflow_ifspeed,
		  { "Interface Speed", "sflow.ifspeed",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"Interface Speed", HFILL }
		},
		{ &hf_sflow_ifdirection,
		  { "Interface Direction", "sflow.ifdirection",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Direction", HFILL }
		},
		{ &hf_sflow_ifstatus,
		  { "Interface Status", "sflow.ifstatus",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Status", HFILL }
		},
		{ &hf_sflow_ifinoct,
		  { "Input Octets", "sflow.ifinoct",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"Interface Input Octets", HFILL }
		},
		{ &hf_sflow_ifinpkt,
		  { "Input Packets", "sflow.ifinpkt",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Input Packets", HFILL }
		},
		{ &hf_sflow_ifinmcast,
		  { "Input Multicast Packets", "sflow.ifinmcast",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Input Multicast Packets", HFILL }
		},
		{ &hf_sflow_ifinbcast,
		  { "Input Broadcast Packets", "sflow.ifinbcast",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Input Broadcast Packets", HFILL }
		},
		{ &hf_sflow_ifindisc,
		  { "Input Discarded Packets", "sflow.ifindisc",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Input Discarded Packets", HFILL }
		},
		{ &hf_sflow_ifinerr,
		  { "Input Errors", "sflow.ifinerr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Input Errors", HFILL }
		},
		{ &hf_sflow_ifinunk,
		  { "Input Unknown Protocol Packets", "sflow.ifinunk",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Input Unknown Protocol Packets", HFILL }
		},
		{ &hf_sflow_ifoutoct,
		  { "Output Octets", "sflow.ifoutoct",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"Outterface Output Octets", HFILL }
		},
		{ &hf_sflow_ifoutpkt,
		  { "Output Packets", "sflow.ifoutpkt",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Output Packets", HFILL }
		},
		{ &hf_sflow_ifoutmcast,
		  { "Output Multicast Packets", "sflow.ifoutmcast",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Output Multicast Packets", HFILL }
		},
		{ &hf_sflow_ifoutbcast,
		  { "Output Broadcast Packets", "sflow.ifoutbcast",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Output Broadcast Packets", HFILL }
		},
		{ &hf_sflow_ifoutdisc,
		  { "Output Discarded Packets", "sflow.ifoutdisc",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Output Discarded Packets", HFILL }
		},
		{ &hf_sflow_ifouterr,
		  { "Output Errors", "sflow.ifouterr",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Output Errors", HFILL }
		},
		{ &hf_sflow_ifpromisc,
		  { "Promiscuous Mode", "sflow.ifpromisc",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Promiscuous Mode", HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sflow,
		&ett_sflow_sample,
		&ett_sflow_extended_data,
		&ett_sflow_sampled_header,
	};

/* Register the protocol name and description */
	proto_sflow = proto_register_protocol("InMon sFlow",
	    "sFlow", "sflow");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_sflow, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}


/* If this dissector uses sub-dissector registration add a registration routine.
   This format is required because a script is used to find these routines and
   create the code that calls these routines.
*/
void
proto_reg_handoff_sflow(void)
{
	dissector_handle_t sflow_handle;

	/*
	 * XXX - should this be done with a dissector table?
	 */
	eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
	tr_handle = find_dissector("tr");
	fddi_handle = find_dissector("fddi");
	fr_handle = find_dissector("fr");
	x25_handle = find_dissector("x.25");
	ppp_handle = find_dissector("ppp");
#if 0
	smds_handle = find_dissector("smds");
#else
	/* We don't have an SMDS dissector yet */
	smds_handle = find_dissector("data");
#endif
#if 0
	aal5_handle = find_dissector("atm");
#else
	/* What dissector should be used here? */
	aal5_handle = find_dissector("data");
#endif
	ipv4_handle = find_dissector("ip");
	ipv6_handle = find_dissector("ipv6");
	mpls_handle = find_dissector("mpls");

	sflow_handle = create_dissector_handle(dissect_sflow,
	    proto_sflow);
	dissector_add("udp.port", UDP_PORT_SFLOW, sflow_handle);
}
