/* packeto-sflow.c
 * Routines for sFlow dissection
 * Copyright 2003, Jeff Rizzo <riz@boogers.sf.ca.us>
 * Copyright 2008, Joerg Mayer (see AUTHORS file)
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

/* This file (mostly) implements a dissector for sFlow (RFC3176),
 * from the version 4 spec at http://www.sflow.org/SFLOW-DATAGRAM.txt
 * and the version 5 http://www.sflow.org/SFLOW-DATAGRAM5.txt.
 *
 * TODO:
 *   Insert more subtrees for some of the headers
 *   Fix the highlighting of the datastream when bits are selected
 *     (user add_item instead of add_text wherever sensible)
 *   Make naming and filtering more consistent
 *   Implement expanded flow samples
 *   Implement expanded counter samples
 *   Finish extended_user
 *   Finish extended_url
 *   Implement non-generic counters sampling
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
#include <epan/ipproto.h>
#include <epan/sminmpec.h>

#define SFLOW_UDP_PORTS "6343"

static dissector_handle_t sflow_handle;

/*
 *	global_sflow_ports : holds the configured range of ports for sflow
 */
static range_t *global_sflow_ports = NULL;

static gboolean global_dissect_samp_headers = TRUE;
static gboolean global_analyze_samp_ip_headers = FALSE;

static const true_false_string yes_no_truth = {
	"Yes",
	"No"
};

#define ADDRESS_UNKNOWN 0
#define ADDRESS_IPV4 1
#define ADDRESS_IPV6 2

static const value_string sflow_agent_address_type[] = {
	{ ADDRESS_UNKNOWN, "Unknown" },
	{ ADDRESS_IPV4,	"IP_V4" },
	{ ADDRESS_IPV6, "IP_V6"},
	{ 0, NULL }
};

#define FLOWSAMPLE 1
#define COUNTERSSAMPLE 2

static const value_string sflow4_sampletype[] = {
	{ FLOWSAMPLE, "Flow sample" },
	{ COUNTERSSAMPLE, "Counters sample" },
	{ 0, NULL }
};

#define EXPFLOWSAMPLES 3
#define EXPCOUNTERSAMPLES 4

static const value_string sflow5_sampletype[] = {
	{ FLOWSAMPLE, "Flow sample" },
	{ COUNTERSSAMPLE, "Counters sample" },
	{ EXPFLOWSAMPLES, "Expanded flow sample" },
	{ EXPCOUNTERSAMPLES, "Expanded counters sample" },
	{ 0, NULL }
};

static const value_string sflow_sample_sourceidtype[] = {
	{ 0, "ifIndex" },
	{ 1, "smonVlanDataSource" },
	{ 2, "entPhysicalEntry" },
	{ 0, NULL }
};

static const value_string if_direction_vals[] = {
	{ 0, "unknown" },
	{ 1, "full duplex" },
	{ 2, "half duplex" },
	{ 3, "in" },
	{ 4, "out" },
	{ 0, NULL }
};

static const true_false_string if_status_up_down = {
	"Down",
	"Up"
};

/* interface counter types */
#define SFLOW_COUNTERS_GENERIC 1
#define SFLOW_COUNTERS_ETHERNET 2
#define SFLOW_COUNTERS_TOKENRING 3
#define SFLOW_COUNTERS_FDDI 4
#define SFLOW_COUNTERS_VG 5
#define SFLOW_COUNTERS_WAN 6
#define SFLOW_COUNTERS_VLAN 7
#define SFLOW_COUNTERS_CPU 1001

static const value_string sflow_counterstype_short [] = {
	{ SFLOW_COUNTERS_GENERIC, "Generic" },
	{ SFLOW_COUNTERS_ETHERNET, "Ethernet" },
	{ SFLOW_COUNTERS_FDDI, "FDDI" },
	{ SFLOW_COUNTERS_VG, "100baseVG" },
	{ SFLOW_COUNTERS_WAN, "WAN" },
	{ SFLOW_COUNTERS_VLAN, "VLAN" },
	{ SFLOW_COUNTERS_CPU, "CPU" },
	{ 0, NULL }
};

static const value_string sflow_counterstype [] = {
	{ SFLOW_COUNTERS_GENERIC, "Generic counters" },
	{ SFLOW_COUNTERS_ETHERNET, "Ethernet counters" },
	{ SFLOW_COUNTERS_FDDI, "FDDI counters" },
	{ SFLOW_COUNTERS_VG, "100baseVG counters" },
	{ SFLOW_COUNTERS_WAN, "WAN counters" },
	{ SFLOW_COUNTERS_VLAN, "VLAN counters" },
	{ SFLOW_COUNTERS_CPU, "CPU counters" },
	{ 0, NULL }
};

#define MAX_HEADER_SIZE 256

#define SFLOW4_PACKET_DATA_TYPE_HEADER 1
#define SFLOW4_PACKET_DATA_TYPE_IPV4 2
#define SFLOW4_PACKET_DATA_TYPE_IPV6 3

static const value_string sflow4_fs_record_type [] = {
	{ SFLOW4_PACKET_DATA_TYPE_HEADER, "Packet headers are sampled" },
	{ SFLOW4_PACKET_DATA_TYPE_IPV4, "IP Version 4 data" },
	{ SFLOW4_PACKET_DATA_TYPE_IPV6, "IP Version 6 data" },
	{ 0, NULL}
};

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

#define SFLOW5_PACKET_DATA_TYPE_RAWHEADER 1
#define SFLOW5_PACKET_DATA_TYPE_ETHERNET 2
#define SFLOW5_PACKET_DATA_TYPE_IPV4 3
#define SFLOW5_PACKET_DATA_TYPE_IPV6 4
#define SFLOW5_PACKET_DATA_TYPE_SWITCH 1001
#define SFLOW5_PACKET_DATA_TYPE_ROUTER 1002
#define SFLOW5_PACKET_DATA_TYPE_GATEWAY 1003
#define SFLOW5_PACKET_DATA_TYPE_USER 1004
#define SFLOW5_PACKET_DATA_TYPE_URL 1005
#define SFLOW5_PACKET_DATA_TYPE_MPLS 1006
#define SFLOW5_PACKET_DATA_TYPE_MPLSTUN 1008
#define SFLOW5_PACKET_DATA_TYPE_MPLSVC 1009
#define SFLOW5_PACKET_DATA_TYPE_MPLSFEC 1010
#define SFLOW5_PACKET_DATA_TYPE_MPLSLVPFEC 1011
#define SFLOW5_PACKET_DATA_TYPE_VLANTUN 1012

static const value_string sflow5_packet_fs_record_type [] = {
	{ SFLOW5_PACKET_DATA_TYPE_RAWHEADER, "Raw header" },
	{ SFLOW5_PACKET_DATA_TYPE_ETHERNET, "Ethernet header" },
	{ SFLOW5_PACKET_DATA_TYPE_IPV4, "IPv4 header" },
	{ SFLOW5_PACKET_DATA_TYPE_IPV6, "IPv6 header" },
	{ SFLOW5_PACKET_DATA_TYPE_SWITCH, "Switch data" },
	{ SFLOW5_PACKET_DATA_TYPE_ROUTER, "Router data" },
	{ SFLOW5_PACKET_DATA_TYPE_GATEWAY, "Gateway data" },
	{ SFLOW5_PACKET_DATA_TYPE_USER, "User data" },
	{ SFLOW5_PACKET_DATA_TYPE_URL, "URL data" },
	{ SFLOW5_PACKET_DATA_TYPE_MPLS, "MPLS data" },
	{ SFLOW5_PACKET_DATA_TYPE_MPLSTUN, "MPLS tunnel data" },
	{ SFLOW5_PACKET_DATA_TYPE_MPLSVC, "MPLS VC data" },
	{ SFLOW5_PACKET_DATA_TYPE_MPLSFEC, "MPLS FEC data" },
	{ SFLOW5_PACKET_DATA_TYPE_MPLSLVPFEC, "MPLS LVP FEC data" },
	{ SFLOW5_PACKET_DATA_TYPE_VLANTUN, "Vlan tunnel data" },
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
#define SFLOW_AS_SET 1
#define SFLOW_AS_SEQUENCE 2

static const value_string sflow_as_types[] = {
	{ SFLOW_AS_SET, "AS Set" },
	{ SFLOW_AS_SEQUENCE, "AS Sequence" },
	{ 0, NULL }
};


#if 0
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

/* Processor counters */

struct cpu_counters {
	guint32		cpuPercentage5s;
	guint32		cpuPercentage1m;
	guint32		cpuPercentage5m;
	guint64		memTotal;
	guint64		memFree;
};
#endif

/* Initialize the protocol and registered fields */

/* sFlow Datagram */
static int proto_sflow = -1;
static int hf_sflow_version = -1;
static int hf_sflow_agent_address_type = -1;
static int hf_sflow_agent_address_v4 = -1;
static int hf_sflow_agent_address_v6 = -1;
static int hf_sflow_sub_agent_id = -1;
static int hf_sflow_seqnum = -1;
static int hf_sflow_sysuptime = -1;
static int hf_sflow_numsamples = -1;

/* Sample header common to all sample types */
static int hf_sflow_sample_type = -1;
static int hf_sflow_sample_type_enterprise = -1;
static int hf_sflow_sample_type_enterprisetype = -1;
static int hf_sflow_sample_type_defaulttype = -1;
static int hf_sflow_sample_length = -1;

/* Flowsample header */
static int hf_sflow_fs_seqno = -1;
static int hf_sflow_fs_sourceid_type = -1;
static int hf_sflow_fs_sourceid_index = -1;
static int hf_sflow_fs_samplingrate = -1;
static int hf_sflow_fs_samplepool = -1;
static int hf_sflow_fs_drops = -1;
static int hf_sflow_fs_ifindexin = -1;
static int hf_sflow_fs_multipleoutputs = -1;
static int hf_sflow_fs_numoutinterfaces = -1;
static int hf_sflow_fs_ifindexout = -1;
static int hf_sflow_fs_numrecords = -1;
static int hf_sflow_fs_recordlength = -1;

/* Countersample header */
static int hf_sflow_cs_seqno = -1;
static int hf_sflow_cs_sourceid_type = -1;
static int hf_sflow_cs_sourceid_index = -1;
static int hf_sflow_cs_samplinginterval = -1;
static int hf_sflow_cs_numrecords = -1;
static int hf_sflow_cs_record_type = -1;
static int hf_sflow_cs_recordlength = -1;

/* Flowsample Raw packet header */
static int hf_sflow_fs_rawheader_protocol = -1;
static int hf_sflow_fs_rawheader_framelength = -1;
static int hf_sflow_fs_rawheader_stripped = -1;
static int hf_sflow_fs_rawheader_headerlength = -1;
static int hf_sflow_fs_rawheader = -1;

/* Flowsample Ethernet packet */
static int hf_sflow_fs_ethernet_framelength = -1;
static int hf_sflow_fs_ethernet_srcmac = -1;
static int hf_sflow_fs_ethernet_dstmac = -1;
static int hf_sflow_fs_ethernet_type = -1;

/* Flowsample IP packet */
static int hf_sflow_fs_ip_length = -1;
static int hf_sflow_fs_ip_protocol = -1;
static int hf_sflow_fs_ip_srcipv4 = -1;
static int hf_sflow_fs_ip_dstipv4 = -1;
static int hf_sflow_fs_ip_srcipv6 = -1;
static int hf_sflow_fs_ip_dstipv6 = -1;
static int hf_sflow_fs_ip_srcport = -1;
static int hf_sflow_fs_ip_dstport = -1;
static int hf_sflow_fs_ip_tcpflags = -1;
static int hf_sflow_fs_ip_tos = -1;
static int hf_sflow_fs_ip_priority = -1;

/* Flowsample Tokenring packet */
/* XXX */

/* Flowsample 100BaseVG packet */
/* XXX */

/* Flowsample VLAN packet */
/* XXX */

/* Flowsample CPU packet */
/* XXX */

/* sflow record */
static int hf_sflow4_fs_record_type = -1;
static int hf_sflow5_fs_record_type = -1;
static int hf_sflow4_extended_information_type = -1;

/* stuff used in extended flow records */
static int hf_sflow_vlan_in = -1;   /* incoming 802.1Q VLAN ID */
static int hf_sflow_vlan_out = -1;   /* outgoing 802.1Q VLAN ID */
static int hf_sflow_pri_in = -1;   /* incominging 802.1p priority */
static int hf_sflow_pri_out = -1;   /* outgoing 802.1p priority */
static int hf_sflow_nexthop_v4 = -1;   /* nexthop address */
static int hf_sflow_nexthop_v6 = -1;   /* nexthop address */
static int hf_sflow_nexthop_src_mask = -1;
static int hf_sflow_nexthop_dst_mask = -1;

/* extended gateway (all versions) */
static int hf_sflow_as = -1;
static int hf_sflow_src_as = -1;
static int hf_sflow_src_peer_as = -1;
static int hf_sflow_dst_as_entries = -1; /* aka length */
static int hf_sflow_dst_as = -1;
/* extended gateway (>= version 4) */
static int hf_sflow_community_entries = -1;
static int hf_sflow_localpref = -1;

/* generic counters */
static int hf_sflow_ifindex = -1;
static int hf_sflow_iftype = -1;
static int hf_sflow_ifspeed = -1;
static int hf_sflow_ifdirection = -1;
static int hf_sflow_ifstatus_unused = -1;
static int hf_sflow_ifstatus_admin = -1;
static int hf_sflow_ifstatus_oper = -1;
static int hf_sflow_ifinoct = -1;
static int hf_sflow_ifinucast = -1;
static int hf_sflow_ifinmcast = -1;
static int hf_sflow_ifinbcast = -1;
static int hf_sflow_ifinerr = -1;
static int hf_sflow_ifindisc = -1;
static int hf_sflow_ifinunk = -1;
static int hf_sflow_ifoutoct = -1;
static int hf_sflow_ifoutucast = -1;
static int hf_sflow_ifoutmcast = -1;
static int hf_sflow_ifoutbcast = -1;
static int hf_sflow_ifoutdisc = -1;
static int hf_sflow_ifouterr = -1;
static int hf_sflow_ifpromisc = -1;

/* ethernet counters */
static int hf_sflow_eth_dot3StatsAlignmentErrors = -1;
static int hf_sflow_eth_dot3StatsFCSErrors = -1;
static int hf_sflow_eth_dot3StatsSingleCollisionFrames = -1;
static int hf_sflow_eth_dot3StatsMultipleCollisionFrames = -1;
static int hf_sflow_eth_dot3StatsSQETestErrors = -1;
static int hf_sflow_eth_dot3StatsDeferredTransmissions = -1;
static int hf_sflow_eth_dot3StatsLateCollisions = -1;
static int hf_sflow_eth_dot3StatsExcessiveCollisions = -1;
static int hf_sflow_eth_dot3StatsInternalMacTransmitErrors = -1;
static int hf_sflow_eth_dot3StatsCarrierSenseErrors = -1;
static int hf_sflow_eth_dot3StatsFrameTooLongs = -1;
static int hf_sflow_eth_dot3StatsInternalMacReceiveErrors = -1;
static int hf_sflow_eth_dot3StatsSymbolErrors = -1;

/* Initialize the subtree pointers */
static gint ett_sflow = -1;
static gint ett_sflow_sample = -1;
static gint ett_sflow_extended_data = -1;
static gint ett_sflow_counters_record = -1;
static gint ett_sflow_gw_as_dst = -1;
static gint ett_sflow_gw_as_dst_seg = -1;
static gint ett_sflow_gw_community = -1;
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
/* don't dissect */
static dissector_handle_t data_handle;

void proto_reg_handoff_sflow(void);

/* dissect a sampled header - layer 2 protocols */
static gint
dissect_sflow_sample_rawheaderdata(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	volatile gint offset, guint32 version)
{
	guint32 	header_proto, frame_length;
	volatile 	guint32 	header_length;
	tvbuff_t 	*volatile next_tvb;
	proto_tree 	*volatile sflow_header_tree;
	proto_item 	*ti;
	/* stuff for saving column state before calling other dissectors.
	 * Thanks to Guy Harris for the tip. */
	volatile gboolean save_writable;
	volatile gboolean save_in_error_pkt;
	volatile address 	save_dl_src;
	volatile address 	save_dl_dst;
	volatile address 	save_net_src;
	volatile address 	save_net_dst;
	volatile address 	save_src;
	volatile address 	save_dst;

	header_proto = tvb_get_ntohl(tvb,offset);
	proto_tree_add_item(tree, hf_sflow_fs_rawheader_protocol, tvb, offset, 4, FALSE);
	offset += 4;
	frame_length = tvb_get_ntohl(tvb,offset);
	proto_tree_add_item(tree, hf_sflow_fs_rawheader_framelength, tvb, offset, 4, FALSE);
	offset += 4;
	if (version == 5) {
		proto_tree_add_item(tree, hf_sflow_fs_rawheader_stripped, tvb, offset, 4, FALSE);
		offset += 4;
	}
	header_length = tvb_get_ntohl(tvb,offset);
	proto_tree_add_item(tree, hf_sflow_fs_rawheader_headerlength, tvb, offset, 4, FALSE);
	offset += 4;

	if (header_length % 4) /* XDR requires 4-byte alignment */
		header_length += 4 - (header_length % 4);
	ti = proto_tree_add_item(tree, hf_sflow_fs_rawheader, tvb, offset, header_length, FALSE);
	sflow_header_tree = proto_item_add_subtree(ti, ett_sflow_sampled_header);

	/* hand the header off to the appropriate dissector.  It's probably
	 * a short frame, so ignore any exceptions. */
	next_tvb = tvb_new_subset(tvb, offset, header_length, frame_length);

	/* save some state */
	save_writable = col_get_writable(pinfo->cinfo);

	/*
	   If sFlow samples a TCP packet it is very likely that the
	   TCP analysis will flag the packet as having some error with
	   the sequence numbers.  sFlow only report on a "sample" of
	   traffic so many packets will not be reported on.  This is
	   most obvious if the colorizing rules are on, but will also
	   cause confusion if you attempt to filter on
	   "tcp.analysis.flags".

	   The following only works to suppress IP/TCP errors, but
	   it is a start anyway.  Other protocols carried as payloads
	   may exhibit similar issues.

	   I think what is really needed is a more general
	   "protocol_as_payload" flag.  Of course then someone has to
	   play whack-a-mole and add code to implement it to any
	   protocols that could be carried as a payload.  In the case
	   of sFlow that pretty much means anything on your network.
	*/
	save_in_error_pkt = pinfo->in_error_pkt;
	if (!global_analyze_samp_ip_headers) {
		pinfo->in_error_pkt = TRUE;
	}

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
	pinfo->in_error_pkt = save_in_error_pkt;

	pinfo->dl_src = save_dl_src;
	pinfo->dl_dst = save_dl_dst;
	pinfo->net_src = save_net_src;
	pinfo->net_dst = save_net_dst;
	pinfo->src = save_src;
	pinfo->dst = save_dst;
	
	offset += header_length;
	return offset;
}

static gint
dissect_sflow_sample_ethernet(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint offset)
{
	proto_tree_add_item(tree, hf_sflow_fs_ethernet_framelength, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_sflow_fs_ethernet_srcmac, tvb, offset, 4, FALSE);
	offset += 8;
	proto_tree_add_item(tree, hf_sflow_fs_ethernet_dstmac, tvb, offset, 4, FALSE);
	offset += 8;
	proto_tree_add_item(tree, hf_sflow_fs_ethernet_type, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

/* dissect a sampled ipv4 or ipv4 header */
static gint
dissect_sflow_sample_ip(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
	gint offset, guint32 ipversion)
{
	guint32		ip_proto;

	proto_tree_add_item(tree, hf_sflow_fs_ip_length, tvb, offset, 4, FALSE);
	offset += 4;
	ip_proto = tvb_get_ntohl(tvb, offset);
	proto_tree_add_uint_format(tree, hf_sflow_fs_ip_protocol, tvb, offset,
		4, ip_proto, "Protocol: %s (0x%02x)", ipprotostr(ip_proto), ip_proto);
	offset +=4;
	if (ipversion == 4) {
		proto_tree_add_item(tree, hf_sflow_fs_ip_srcipv4, tvb, offset, 4, FALSE);
		offset += 4;
		proto_tree_add_item(tree, hf_sflow_fs_ip_dstipv4, tvb, offset, 4, FALSE);
		offset += 4;
	} else {
		proto_tree_add_item(tree, hf_sflow_fs_ip_srcipv6, tvb, offset, 16, FALSE);
		offset += 16;
		proto_tree_add_item(tree, hf_sflow_fs_ip_dstipv6, tvb, offset, 16, FALSE);
		offset += 16;
	}
	proto_tree_add_item(tree, hf_sflow_fs_ip_srcport, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_sflow_fs_ip_dstport, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_sflow_fs_ip_tcpflags, tvb, offset, 4, FALSE);
	offset += 4;
	if (ipversion == 4) {
		proto_tree_add_item(tree, hf_sflow_fs_ip_tos, tvb, offset, 4, FALSE);
		offset += 4;
	} else {
		proto_tree_add_item(tree, hf_sflow_fs_ip_priority, tvb, offset, 4, FALSE);
		offset += 4;
	}
	return offset;
}

/* extended switch data */
static gint
dissect_sflow_extended_switch(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	proto_tree_add_item(tree, hf_sflow_vlan_in, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_sflow_pri_in, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_sflow_vlan_out, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_sflow_pri_out, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

/* extended router data */
static gint
dissect_sflow_extended_router(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	guint32 nh_address_type;

	nh_address_type = tvb_get_ntohl(tvb, offset);
	offset += 4;
	switch (nh_address_type) {
	case ADDRESS_IPV4:
		proto_tree_add_item(tree, hf_sflow_nexthop_v4, tvb, offset, 4, FALSE);
		offset += 4;
		break;
	case ADDRESS_IPV6:
		proto_tree_add_item(tree, hf_sflow_nexthop_v6, tvb, offset, 16, FALSE);
		offset += 16;
		break;
	default:
		proto_tree_add_text(tree, tvb, offset - 4, 4,
			"Unknown address type (%d)", nh_address_type);
		offset += 4;  /* not perfect, but what else to do? */
		return offset;  /* again, this is wrong.  but... ? */
	};
	
	proto_tree_add_item(tree, hf_sflow_nexthop_src_mask, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(tree, hf_sflow_nexthop_dst_mask, tvb, offset, 4, FALSE);
	offset += 4;
	return offset;
}


/* extended gateway data */
static gint
dissect_sflow_extended_gateway(tvbuff_t *tvb, proto_tree *tree, gint offset)
{
	gint32 	i, j, comm_len, dst_len, dst_seg_len;
	guint32 path_type;
	gint32  kludge;

	guint32 version = tvb_get_ntohl(tvb, 0); /* HACK */
	proto_item *ti;
	proto_tree *sflow_dst_as_tree;
	proto_tree *sflow_comm_tree;
	proto_tree *sflow_dst_as_seg_tree;

	proto_tree_add_item(tree, hf_sflow_as, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_sflow_src_as, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_sflow_src_peer_as, tvb, offset, 4, FALSE);
	offset += 4;

	dst_len = tvb_get_ntohl(tvb, offset);
	ti = proto_tree_add_uint(tree, hf_sflow_dst_as_entries, tvb, offset, 4, dst_len);
	sflow_dst_as_tree = proto_item_add_subtree(ti, ett_sflow_gw_as_dst);
	offset += 4;

	i = 0;
	while (i++ < dst_len) {
		if( version < 4 ) {
			/* Version 2 AS paths are different than versions >= 4 as
			   follows:

			   There is no type encoded in the packet.

			   The destination ASs are encoded as an array of integers
			   rather as an array of arrays of integers.  I just
			   pretended they were encoded as an array of arrays with
			   an implicit length of 1 to not have to do two
			   completely separate blocks for the different versions.

			   Having a subtree for "arrays" guaranteed to have only a
			   single element proved cumbersome to navigate so I moved
			   the creation of the subtree to only happen for versions
			   >= 4.
			 */
			dst_seg_len = 1;
			path_type = 0;
			kludge = 0;
			sflow_dst_as_seg_tree = sflow_dst_as_tree;
		} else {
			path_type = tvb_get_ntohl(tvb, offset);
			offset += 4;
			dst_seg_len = tvb_get_ntohl(tvb, offset);
			offset += 4;
			kludge = 8;
			ti = proto_tree_add_text(tree, tvb, offset-kludge, kludge,
				"%s, (%d entries)",
				val_to_str(path_type, sflow_as_types, "Unknown AS type"),
				dst_seg_len);
			sflow_dst_as_seg_tree = proto_item_add_subtree(ti, ett_sflow_gw_as_dst_seg);
		}

		j = 0;
		while (j++ < dst_seg_len) {
			proto_tree_add_item(sflow_dst_as_seg_tree, hf_sflow_dst_as,
				tvb, offset, 4, FALSE);
			offset += 4;
		}
	}

		
	if( version >= 4 ) {
		comm_len = tvb_get_ntohl(tvb, offset);

		ti = proto_tree_add_uint(tree, hf_sflow_community_entries, tvb, offset, 4, comm_len);
		sflow_comm_tree = proto_item_add_subtree(ti, ett_sflow_gw_community);
		offset += 4;
		i = 0;
		while (i++ < comm_len) {
			proto_tree_add_item(sflow_comm_tree, hf_sflow_dst_as, tvb,
				offset, 4, FALSE);
			offset += 4;
		}
		proto_tree_add_item(tree, hf_sflow_localpref, tvb, offset, 4, FALSE);
		offset += 4;
	}

	return offset;
}

/* extended url data */
/* XXX the item stuff is missing */
static gint
dissect_sflow_extended_url(tvbuff_t *tvb, proto_tree *tree _U_, gint offset)
{
	guint32		url_string_len, host_string_len;

	offset += 4;

	url_string_len = tvb_get_ntohl(tvb, offset);
	offset += 4;

	if (url_string_len & 3)
		url_string_len += (4 - (url_string_len & 3));
	offset += url_string_len;

	host_string_len = tvb_get_ntohl(tvb, offset);
	offset += 4;

	if (host_string_len & 3)
		host_string_len += (4 - (host_string_len & 3));
	offset += host_string_len;

	return offset;
}

/* extended userdata */
/* XXX the item stuff is missing */
static gint
dissect_sflow_extended_user(tvbuff_t *tvb, proto_tree *tree _U_, gint offset)
{
	guint32		src_user_string_len, dst_user_string_len;

	offset += 4;

	src_user_string_len = tvb_get_ntohl(tvb, offset);
	offset += 4;

	if (src_user_string_len & 3)
		src_user_string_len += (4 - (src_user_string_len & 3));
	offset += src_user_string_len;

	offset += 4;

	dst_user_string_len = tvb_get_ntohl(tvb, offset);
	offset += 4;

	if (dst_user_string_len & 3)
		dst_user_string_len += (4 - (dst_user_string_len & 3));
	offset += dst_user_string_len;

	return offset;
}

/* dissect a flow sample */
static gint
dissect_sflow_flow_sample(tvbuff_t *tvb, packet_info *pinfo,
	proto_tree *tree, gint offset, proto_item *parent, guint32 version)
{
	proto_tree 	*extended_data_tree;
	proto_item	*ti;
	guint32 	packet_type, extended_data, ext_type, i, j;
	guint32		sequence_number;
	guint32		output, num_records, record_length, sample_length;
	gint		return_offset = 0, nextoffset = 0;

	if (version == 5) {
		sample_length = tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(tree, hf_sflow_sample_length, tvb, offset, 4, FALSE);
		offset += 4;
		return_offset = offset + sample_length;
	}
	sequence_number = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_sflow_fs_seqno, tvb, offset, 4, FALSE);
	proto_item_append_text(parent, ", seq %u", sequence_number);
	offset += 4;

	proto_tree_add_item(tree, hf_sflow_fs_sourceid_type, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_sflow_fs_sourceid_index, tvb, offset, 3, FALSE);
	offset += 3;

	proto_tree_add_item(tree, hf_sflow_fs_samplingrate, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_sflow_fs_samplepool, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_sflow_fs_drops, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(tree, hf_sflow_fs_ifindexin, tvb, offset, 4, FALSE);
	offset += 4;

	output = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_sflow_fs_multipleoutputs, tvb, offset, 4, FALSE);
	if (output >> 31)
		proto_tree_add_item(tree, hf_sflow_fs_numoutinterfaces, tvb, offset, 4, FALSE);
	else
		proto_tree_add_item(tree, hf_sflow_fs_ifindexout, tvb, offset, 4, FALSE);
	offset += 4;

	if (version == 5) {
		num_records = tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(tree, hf_sflow_fs_numrecords, tvb, offset, 4, FALSE);
		offset += 4;
	} else {
		num_records = 1;
	}
	j = 0;
	while (j++ < num_records) {
		/* what kind of flow sample is it? */
		packet_type = tvb_get_ntohl(tvb, offset);
		if (version == 5) {
			proto_tree_add_item(tree, hf_sflow5_fs_record_type, tvb, offset, 4, FALSE);
			proto_item_append_text(parent, ", %s",
				val_to_str(packet_type, sflow5_packet_fs_record_type, "%u"));
		} else {
			proto_tree_add_item(tree, hf_sflow4_fs_record_type, tvb, offset, 4, FALSE);
		}
		offset += 4;
	
		if (version == 5) {
			record_length = tvb_get_ntohl(tvb, offset);
			proto_tree_add_item(tree, hf_sflow_fs_recordlength, tvb, offset, 4, FALSE);
			extended_data_tree = tree;
			offset += 4;
			nextoffset = offset + record_length;
	
			switch (packet_type) {
			case SFLOW5_PACKET_DATA_TYPE_RAWHEADER:
				offset = dissect_sflow_sample_rawheaderdata(tvb, pinfo, tree, offset, version);
				break;
			case SFLOW5_PACKET_DATA_TYPE_ETHERNET:
				offset = dissect_sflow_sample_ethernet(tvb, pinfo, tree, offset);
				break;
			case SFLOW5_PACKET_DATA_TYPE_IPV4:
				offset = dissect_sflow_sample_ip(tvb, pinfo, tree, offset, 4);
				break;
			case SFLOW5_PACKET_DATA_TYPE_IPV6:
				offset = dissect_sflow_sample_ip(tvb, pinfo, tree, offset, 6);
				break;
			case SFLOW5_PACKET_DATA_TYPE_SWITCH:
				offset = dissect_sflow_extended_switch(tvb, extended_data_tree, offset);
				break;
			case SFLOW5_PACKET_DATA_TYPE_ROUTER:
				offset = dissect_sflow_extended_router(tvb, extended_data_tree, offset);
				break;
			case SFLOW5_PACKET_DATA_TYPE_GATEWAY:
				offset = dissect_sflow_extended_gateway(tvb, extended_data_tree, offset);
				break;
			case SFLOW5_PACKET_DATA_TYPE_URL:
				offset = dissect_sflow_extended_url(tvb, extended_data_tree, offset);
				break;
			case SFLOW5_PACKET_DATA_TYPE_USER:
				offset = dissect_sflow_extended_user(tvb, extended_data_tree, offset);
				break;
			case SFLOW5_PACKET_DATA_TYPE_MPLS:
			case SFLOW5_PACKET_DATA_TYPE_MPLSTUN:
			case SFLOW5_PACKET_DATA_TYPE_MPLSVC:
			case SFLOW5_PACKET_DATA_TYPE_MPLSFEC:
			case SFLOW5_PACKET_DATA_TYPE_MPLSLVPFEC:
			case SFLOW5_PACKET_DATA_TYPE_VLANTUN:
			default:
				break;
			};
			offset = nextoffset;
		} else {
			switch (packet_type) {
			case SFLOW4_PACKET_DATA_TYPE_IPV4:
				offset = dissect_sflow_sample_ip(tvb, pinfo, tree, offset, 4);
				break;
			case SFLOW4_PACKET_DATA_TYPE_IPV6:
				offset = dissect_sflow_sample_ip(tvb, pinfo, tree, offset, 6);
				break;
			}
			/* still need to dissect extended data */
			extended_data = tvb_get_ntohl(tvb,offset);
			offset += 4;
			i = 0;
			while (i++ < extended_data) {
				/* figure out what kind of extended data it is */
				ext_type = tvb_get_ntohl(tvb,offset);
		
				/* create a subtree.  Might want to move this to
				 * the end, so more info can be correct.
				 */
				ti = proto_tree_add_text(tree, tvb, offset, -1, "%s",
					val_to_str(ext_type, sflow_extended_data_types,
						"Unknown extended information"));
				extended_data_tree = proto_item_add_subtree(ti, ett_sflow_extended_data);
				proto_tree_add_uint(extended_data_tree,
				    hf_sflow4_extended_information_type, tvb, offset, 4, ext_type);
				offset += 4;
	
				switch (ext_type) {
				case SFLOW_EXTENDED_SWITCH:
					offset = dissect_sflow_extended_switch(tvb, extended_data_tree, offset);
					break;
				case SFLOW_EXTENDED_ROUTER:
					offset = dissect_sflow_extended_router(tvb, extended_data_tree, offset);
					break;
				case SFLOW_EXTENDED_GATEWAY:
					offset = dissect_sflow_extended_gateway(tvb, extended_data_tree, offset);
					break;
				case SFLOW_EXTENDED_URL:
					offset = dissect_sflow_extended_url(tvb, extended_data_tree, offset);
					break;
				case SFLOW_EXTENDED_USER:
					offset = dissect_sflow_extended_user(tvb, extended_data_tree, offset);
					break;
				default:
					break;
				}
				proto_item_set_end(ti, tvb, offset);
			}
		}
	}
	if (version == 5)
		return return_offset;
	else
		return offset;
}

/* dissect a counters sample */
static gint
dissect_sflow_counters_sample(tvbuff_t *tvb, proto_tree *tree,
	gint offset, proto_item *parent, guint32 version)
{
	guint32	sequence_number, num_records, counters_type, record_length, j;
	guint32 sample_length;
	gint nextoffset = 0, return_offset = 0;
	proto_tree	*record_tree;
	proto_item	*ti; /* tree item */
	
	if (version == 5) {
		sample_length = tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(tree, hf_sflow_sample_length, tvb, offset, 4, FALSE);
		offset += 4;
		return_offset = offset + sample_length;
	}
	sequence_number = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(tree, hf_sflow_cs_seqno, tvb, offset, 4, FALSE);
	proto_item_append_text(parent, ", seq %u", sequence_number);
	offset += 4;

	proto_tree_add_item(tree, hf_sflow_cs_sourceid_type, tvb, offset, 1, FALSE);
	offset += 1;
	proto_tree_add_item(tree, hf_sflow_cs_sourceid_index, tvb, offset, 3, FALSE);
	offset += 3;

	if (version == 5) {
		num_records = tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(tree, hf_sflow_cs_numrecords, tvb, offset, 4, FALSE);
		offset += 4;
	} else {
		num_records = 1;
		proto_tree_add_item(tree, hf_sflow_cs_samplinginterval, tvb, offset, 4, FALSE);
		offset += 4;
	}

	j = 0;
	while (j++ < num_records) {
		counters_type = tvb_get_ntohl(tvb, offset);
		if (version == 5) {
			/* To put the version 4 stuff also into a subree we'd need to calculate
			   the record length via a table */
			record_length = tvb_get_ntohl(tvb, offset + 4);
			ti = proto_tree_add_text(tree, tvb, offset, record_length + 8,
				"%s record", val_to_str(counters_type, sflow_counterstype, "%u"));
			proto_item_append_text(parent, ", %s",
				val_to_str(counters_type, sflow_counterstype_short, "%u"));
	        	record_tree = proto_item_add_subtree(ti, ett_sflow_counters_record);
		} else {
			record_length = 0;
			record_tree = tree;
		}
		proto_tree_add_item(record_tree, hf_sflow_cs_record_type, tvb, offset, 4, FALSE);
		offset += 4;
	
		if (version == 5) {
			proto_tree_add_item(record_tree, hf_sflow_cs_recordlength, tvb, offset, 4, FALSE);
			offset += 4;
			nextoffset = offset + record_length;
		}
	
		/* most counters types have the "generic" counters first */
		switch (counters_type) {
		case SFLOW_COUNTERS_ETHERNET:
		case SFLOW_COUNTERS_TOKENRING:
		case SFLOW_COUNTERS_FDDI:
		case SFLOW_COUNTERS_VG:
		case SFLOW_COUNTERS_WAN:
		case SFLOW_COUNTERS_CPU:
			if (version == 5)
				break;
		case SFLOW_COUNTERS_GENERIC:
			proto_item_append_text(parent, ", ifIndex %u", tvb_get_ntohl(tvb, offset));
			proto_tree_add_item(record_tree, hf_sflow_ifindex, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_iftype, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifspeed, tvb, offset, 8, FALSE);
			offset += 8;
			proto_tree_add_item(record_tree, hf_sflow_ifdirection, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifstatus_unused, tvb, offset, 4, FALSE);
			proto_tree_add_item(record_tree, hf_sflow_ifstatus_oper, tvb, offset, 4, FALSE);
			proto_tree_add_item(record_tree, hf_sflow_ifstatus_admin, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifinoct, tvb, offset, 8, FALSE);
			offset += 8;
			proto_tree_add_item(record_tree, hf_sflow_ifinucast, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifinmcast, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifinbcast, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifindisc, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifinerr, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifinunk, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifoutoct, tvb, offset, 8, FALSE);
			offset += 8;
			proto_tree_add_item(record_tree, hf_sflow_ifoutucast, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifoutmcast, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifoutbcast, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifoutdisc, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifouterr, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_ifpromisc, tvb, offset, 4, FALSE);
			offset += 4;
			break;
		};
		
		/* Some counter types have other info to gather */
		switch (counters_type) {
		case SFLOW_COUNTERS_ETHERNET:
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsAlignmentErrors, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsFCSErrors, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsSingleCollisionFrames, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsMultipleCollisionFrames, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsSQETestErrors, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsDeferredTransmissions, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsLateCollisions, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsExcessiveCollisions, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsInternalMacTransmitErrors, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsCarrierSenseErrors, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsFrameTooLongs, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsInternalMacReceiveErrors, tvb, offset, 4, FALSE);
			offset += 4;
			proto_tree_add_item(record_tree, hf_sflow_eth_dot3StatsSymbolErrors, tvb, offset, 4, FALSE);
			offset += 4;
			break;
		case SFLOW_COUNTERS_TOKENRING:
			offset += 72;
			break;
		case SFLOW_COUNTERS_VG:
			offset += 80;
			break;
		case SFLOW_COUNTERS_VLAN:
			offset += 24;
			break;
		case SFLOW_COUNTERS_CPU:
			offset += 28;
			break;
		default:
			break;
		}
		if (version == 5)
			offset = nextoffset;
	}
	if (version == 5)
		return return_offset;
	else
		return offset;
}

/* Code to dissect the sflow samples */
static gint
dissect_sflow_samples(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	gint offset, guint32 version)
{
	proto_tree 	*sflow_sample_tree;
	proto_item 	*ti; /* tree item */
	guint32 	sample_type, sample_enterprise;
	
	/* decide what kind of sample it is. */
	if (version != 5) {
		sample_type = tvb_get_ntohl(tvb, offset);
		sample_enterprise = 0;
		ti = proto_tree_add_text(tree, tvb, offset, -1, "%s",
			val_to_str(sample_type, sflow4_sampletype,
			"Unknown sample type (v4)"));
	} else {
		sample_type = tvb_get_ntohl(tvb, offset) & 0x00000fff;
		sample_enterprise = (tvb_get_ntohl(tvb, offset) & 0xfffff000) >> 12;
		if (sample_enterprise == 0) {
			ti = proto_tree_add_text(tree, tvb, offset, -1, "%s",
				val_to_str(sample_type, sflow5_sampletype,
				"Unknown sample type (v5)"));
		} else {
			ti = proto_tree_add_text(tree, tvb, offset, -1,
				"Unsupported Enterprise: %s",
				val_to_str(sample_enterprise, sminmpec_values, "%u"));
		}
	}
	sflow_sample_tree = proto_item_add_subtree(ti, ett_sflow_sample);

	if (version != 5) {
		proto_tree_add_item(sflow_sample_tree, hf_sflow_sample_type, tvb, offset, 4, FALSE);
	} else {
		proto_tree_add_item(sflow_sample_tree, hf_sflow_sample_type_enterprise,
			tvb, offset, 4, FALSE);
		if (sample_enterprise == 0) {
			proto_tree_add_item(sflow_sample_tree, hf_sflow_sample_type_defaulttype,
				tvb, offset, 4, FALSE);
		} else {
			proto_tree_add_item(sflow_sample_tree, hf_sflow_sample_type_enterprisetype,
				tvb, offset, 4, FALSE);
		}
	}
	offset += 4;

	switch (sample_type) {
	case FLOWSAMPLE:
	case EXPFLOWSAMPLES:
		offset = dissect_sflow_flow_sample(tvb, pinfo, sflow_sample_tree, offset, ti, version);
		break;
	case COUNTERSSAMPLE:
	case EXPCOUNTERSAMPLES:
		offset = dissect_sflow_counters_sample(tvb, sflow_sample_tree, offset, ti, version);
		break;
	default:
		break;
	}
	proto_item_set_end(ti, tvb, offset);
	return offset;
}

/* Code to actually dissect the packets */
static int
dissect_sflow(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{

/* Set up structures needed to add the protocol subtree and manage it */
	proto_item	*ti;
	proto_tree	*sflow_tree;
	guint32		version, sub_agent_id, seqnum;
	guint32		agent_address_type;
	guint32		numsamples;
	volatile guint	offset=0;
	guint 		i=0;
	union {
		guint8	v4[4];
		guint8	v6[16];
	} agent_address;

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
	proto_tree_add_item(sflow_tree, hf_sflow_version, tvb, offset, 4, FALSE);
	offset += 4;

	agent_address_type = tvb_get_ntohl(tvb, offset);
	proto_tree_add_item(sflow_tree, hf_sflow_agent_address_type, tvb, offset, 4, FALSE);
	offset += 4;
	switch (agent_address_type) {
	case ADDRESS_IPV4:
		tvb_memcpy(tvb, agent_address.v4, offset, 4);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", agent %s",
				 ip_to_str(agent_address.v4));
		proto_tree_add_item(sflow_tree, hf_sflow_agent_address_v4,
			tvb, offset, 4, FALSE);
		offset += 4;
		break;
	case ADDRESS_IPV6:
		tvb_memcpy(tvb, agent_address.v6, offset, 16);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", agent %s",
				ip6_to_str((struct e_in6_addr *)agent_address.v6));
		proto_tree_add_item(sflow_tree, hf_sflow_agent_address_v6,
			tvb, offset, 16, FALSE);
		offset += 16;
		break;
	default:
		/* unknown address.  this will cause a malformed packet.  */
		return 0;
	};

	if (version == 5) {
		sub_agent_id = tvb_get_ntohl(tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, ", sub-agent ID %u",
				sub_agent_id);
		proto_tree_add_item(sflow_tree, hf_sflow_sub_agent_id,
			tvb, offset, 4, FALSE);
		offset += 4;
	}
	seqnum = tvb_get_ntohl(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", seq %u", seqnum);
	proto_tree_add_item(sflow_tree, hf_sflow_seqnum, tvb, offset, 4, FALSE);
	offset += 4;
	proto_tree_add_item(sflow_tree, hf_sflow_sysuptime, tvb, offset, 4, FALSE);
	offset += 4;
	numsamples = tvb_get_ntohl(tvb,offset);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %u samples",
						numsamples);
	proto_tree_add_item(sflow_tree, hf_sflow_numsamples, tvb, offset, 4, FALSE);
	offset += 4;

	/* Ok, we're now at the end of the sflow datagram header;
	 * everything from here out should be samples. Loop over
	 * the expected number of samples, and pass them to the appropriate
	 * dissectors.
	 */

	i = 0;
	while (i++ < numsamples)
		offset = dissect_sflow_samples(tvb, pinfo, sflow_tree, offset, version);

	return tvb_length(tvb);
}


static void
sflow_delete_callback(guint32 port)
{
	if (port) {
		dissector_delete("udp.port", port, sflow_handle);
	}
}
static void
sflow_add_callback(guint32 port)
{
	if (port) {
		dissector_add("udp.port", port, sflow_handle);
	}
}


static void
sflow_reinit(void)
{
	/*
 	 * sflow_ports : holds the currently used range of ports for sflow
 	 */
	static range_t *sflow_ports = NULL;

	if (sflow_ports) {
		range_foreach(sflow_ports, sflow_delete_callback);
		g_free(sflow_ports);
	}

	sflow_ports = range_copy(global_sflow_ports);

	range_foreach(sflow_ports, sflow_add_callback);
}


/* Register the protocol with Wireshark */

/* this format is require because a script is used to build the C function
   that calls all the protocol registration.
*/

void
proto_register_sflow(void)
{
	module_t *sflow_module;

/* Setup list of header fields  See Section 1.6.1 for details*/
	static hf_register_info hf[] = {

		/* datagram header */
		{ &hf_sflow_version,
		  { "datagram version", "sflow.version",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"sFlow datagram version", HFILL }
		},
		{ &hf_sflow_agent_address_type,
		  { "address type", "sflow.agent.addresstype",
			FT_UINT32, BASE_DEC, VALS(sflow_agent_address_type), 0x0,
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

		/* Common sample header */
		{ &hf_sflow_sample_type,
		  { "sFlow sample type", "sflow.sample.type",
			FT_UINT32, BASE_DEC, VALS(sflow4_sampletype), 0x0,
			"Type of sFlow sample", HFILL }
		},
		{ &hf_sflow_sample_type_enterprise,
		  { "sFlow sample type enterprise", "sflow.sample.enterprise",
			FT_UINT32, BASE_DEC, NULL, 0xfffff000,
			"Enterprise of sFlow sample", HFILL }
		},
		{ &hf_sflow_sample_type_defaulttype,
		  { "sFlow sample type", "sflow.sample.enterprisetype",
			FT_UINT32, BASE_DEC, VALS(sflow5_sampletype), 0x00000fff,
			"Enterprisetype of sFlow sample", HFILL }
		},
		{ &hf_sflow_sample_type_enterprisetype,
		  { "sFlow sample type", "sflow.sample.enterprisetype",
			FT_UINT32, BASE_DEC, NULL, 0x00000fff,
			"Enterprisetype of sFlow sample", HFILL }
		},
		{ &hf_sflow_sample_length,
		  { "Sample length", "sflow.sample.length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},

		/* Flowsample */
		{ &hf_sflow_fs_seqno,
		  { "Sample sequence number", "sflow.fs.seqno",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_fs_sourceid_type,
		  { "Source ID type", "sflow.fs.sourceidtype",
			FT_UINT8, BASE_DEC, VALS(sflow_sample_sourceidtype), 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_fs_sourceid_index,
		  { "Source ID index", "sflow.fs.sourceidindex",
			FT_UINT24, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_fs_samplingrate,
		  { "Sampling rate", "sflow.fs.samplingrate",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Sample 1 out of N packets", HFILL }
		},
		{ &hf_sflow_fs_samplepool,
		  { "Sample pool", "sflow.fs.pool",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Total number of packets", HFILL }
		},
		{ &hf_sflow_fs_drops,
		  { "Dropped packets", "sflow.fs.pool",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_fs_ifindexin,
		  { "Input interface index", "sflow.fs.ifindexin",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_fs_multipleoutputs,
		  { "Multiple outputs", "sflow.fs.multipleoutputs",
			FT_BOOLEAN, 32, TFS(&yes_no_truth), 0x80000000,
			"Output to more than one interface", HFILL }
		},
		{ &hf_sflow_fs_numoutinterfaces,
		  { "Number of interfaces", "sflow.fs.numoutinterfaces",
			FT_UINT32, BASE_DEC, NULL, 0x7fffffff,
			"Number of output interfaces", HFILL }
		},
		{ &hf_sflow_fs_ifindexout,
		  { "Output interface index", "sflow.fs.ifindexout",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_fs_numrecords,
		  { "Number of records", "sflow.fs.numrecords",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Number of flowsample records", HFILL }
		},
		{ &hf_sflow_fs_recordlength,
		  { "Recordlength", "sflow.fs.recordlength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow4_fs_record_type,
		  { "Sample type", "sflow.fs.recordtype",
			FT_UINT32, BASE_DEC, VALS(sflow4_fs_record_type), 0x0,
			"Type of flowsample", HFILL }
		},
		{ &hf_sflow5_fs_record_type,
		  { "Sample type", "sflow.fs.recordtype",
			FT_UINT32, BASE_DEC, VALS(sflow5_packet_fs_record_type), 0x0,
			"Type of flowsample", HFILL }
		},

		/* Countersample */
		{ &hf_sflow_cs_seqno,
		  { "Sequence number", "sflow.cs.seqno",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_cs_sourceid_type,
		  { "Source ID type", "sflow.cs.sourceidtype",
			FT_UINT8, BASE_DEC, VALS(sflow_sample_sourceidtype), 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_cs_sourceid_index,
		  { "Source ID index", "sflow.cs.sourceidindex",
			FT_UINT24, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_cs_samplinginterval,
		  { "Sampling interval", "sflow.cs.samplinginterval",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_cs_numrecords,
		  { "Number of records", "sflow.cs.numrecords",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Number of countersample records", HFILL }
		},
		{ &hf_sflow_cs_record_type,
		  { "Type of counters", "sflow.cs.recordtype",
			FT_UINT32, BASE_DEC, VALS(sflow_counterstype), 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_cs_recordlength,
		  { "Recordlength", "sflow.cs.recordlength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},

		/* Flow record: raw packet header */
		{ &hf_sflow_fs_rawheader_protocol,
		  { "Header protocol", "sflow.fs.rawheader.protocol",
			FT_UINT32, BASE_DEC, VALS(sflow_header_protocol), 0x0,
			"Protocol of sampled header", HFILL }
		},
		{ &hf_sflow_fs_rawheader_framelength,
		  { "Framelength", "sflow.fs.rawheader.framelength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Total framelength of sampled packet", HFILL }
		},
		{ &hf_sflow_fs_rawheader_stripped,
		  { "Stripped bytes", "sflow.fs.rawheader.stripped",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Bytes stripped from packet", HFILL }
		},
		{ &hf_sflow_fs_rawheader_headerlength,
		  { "Headerlength", "sflow.fs.rawheader.headerlength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Bytes sampled in packet", HFILL }
		},
		{ &hf_sflow_fs_rawheader,
		  { "Header of sampled packet", "sflow.fs.rawheader",
			FT_BYTES, BASE_HEX, NULL, 0x0,
			"Data from sampled header", HFILL }
		},

		/* Flow record: ethernet header */
		{ &hf_sflow_fs_ethernet_framelength,
		  { "Framelength", "sflow.fs.ethernet.framelength",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Total framelength of sampled packet", HFILL }
		},
		{ &hf_sflow_fs_ethernet_srcmac,
		  { "Ethertype", "sflow.fs.ethernet.srcmac",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			"Source MAC address of sampled packet", HFILL }
		},
		{ &hf_sflow_fs_ethernet_dstmac,
		  { "Ethertype", "sflow.fs.ethernet.dstmac",
			FT_ETHER, BASE_NONE, NULL, 0x0,
			"Destination MAC address of sampled packet", HFILL }
		},
		{ &hf_sflow_fs_ethernet_type,
		  { "Ethertype", "sflow.fs.ethernet.type",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Ethertype of sampled packet", HFILL }
		},

		/* Flow record: ipv4 and ipv6 headers */
		{ &hf_sflow_fs_ip_length,
		  { "IP Packet Length", "sflow.ip_length",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Length of IP Packet excluding lower layer encapsulation", HFILL }
		},
		{ &hf_sflow_fs_ip_protocol,
		  { "Protocol", "sflow.ip_protocol",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"IP Protocol", HFILL }
		},
		{ &hf_sflow_fs_ip_srcipv4,
		  { "Src IP", "sflow.src_ipv4",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"Source IPv4 Address", HFILL }
		},
		{ &hf_sflow_fs_ip_dstipv4,
		  { "Dst IP", "sflow.dst_ipv4",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			"Destination IPv4 Address", HFILL }
		},
		{ &hf_sflow_fs_ip_srcipv6,
		  { "Src IP", "sflow.src_ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x0,
			"Source IPv6 Address", HFILL }
		},
		{ &hf_sflow_fs_ip_dstipv6,
		  { "Dst IP", "sflow.dst_ipv6",
			FT_IPv6, BASE_NONE, NULL, 0x0,
			"Destination IPv6 Address", HFILL }
		},
		{ &hf_sflow_fs_ip_srcport,
		  { "Src Port", "sflow.src_port",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Source Port Number", HFILL }
		},
		{ &hf_sflow_fs_ip_dstport,
		  { "Dst Port", "sflow.dst_port",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Dst Port Number", HFILL }
		},
		{ &hf_sflow_fs_ip_tcpflags,
		  { "TCP Flags", "sflow.ip_flags",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"TCP Flags", HFILL }
		},
		{ &hf_sflow_fs_ip_tos, /* IPv4 */
		  { "ToS", "sflow.tos",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Type of Service", HFILL }
		},
		{ &hf_sflow_fs_ip_priority, /* IPv6 */
		  { "Priority", "sflow.priority",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			"Priority", HFILL }
		},

		/* XXX Fix naming for everything between here and hf_sflow_eth_... */
		{ &hf_sflow4_extended_information_type,
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
		{ &hf_sflow_as,
		  { "AS Router", "sflow.as",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Autonomous System of Router", HFILL }
		},
		{ &hf_sflow_src_as,
		  { "AS Source", "sflow.srcAS",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Autonomous System of Source", HFILL }
		},
		{ &hf_sflow_src_peer_as,
		  { "AS Peer", "sflow.peerAS",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Autonomous System of Peer", HFILL }
		},
		{ &hf_sflow_dst_as_entries,
		  { "AS Destinations", "sflow.dstASentries",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Autonomous System destinations", HFILL }
		},
		{ &hf_sflow_dst_as,
		  { "AS Destination", "sflow.dstAS",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Autonomous System destination", HFILL }
		},
		/* Needed for sFlow >= 4.  If I had a capture to test... */
		{ &hf_sflow_community_entries,
		  { "Gateway Communities", "sflow.communityEntries",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Gateway Communities", HFILL }
		},
		{ &hf_sflow_localpref,
		  { "localpref", "sflow.localpref",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Local preferences of AS route", HFILL }
		},
		/* generic counters */
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
			FT_UINT32, BASE_DEC, VALS(if_direction_vals), 0x0,
			"Interface Direction", HFILL }
		},
		{ &hf_sflow_ifstatus_unused,
		  { "If status (unused)", "sflow.ifstatus.unused",
			FT_UINT32, BASE_DEC, NULL, 0xfffffffc,
			"Unused interface status bits", HFILL }
		},
		{ &hf_sflow_ifstatus_admin,
		  { "If admin status", "sflow.ifstatus.admin",
			FT_UINT32, BASE_DEC, NULL, 0x00000001,
			"Interface admin status bit", HFILL }
		},
		{ &hf_sflow_ifstatus_oper,
		  { "If oper status", "sflow.ifstatus.oper",
			FT_UINT32, BASE_DEC, NULL, 0x00000002,
			"Interface operational status bit", HFILL }
		},
		{ &hf_sflow_ifinoct,
		  { "Input Octets", "sflow.ifinoct",
			FT_UINT64, BASE_DEC, NULL, 0x0,
			"Interface Input Octets", HFILL }
		},
		{ &hf_sflow_ifinucast,
		  { "Input unicast packets", "sflow.ifinucast",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Input Unicast Packets", HFILL }
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
		{ &hf_sflow_ifoutucast,
		  { "Output unicast packets", "sflow.ifoutucast",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			"Interface Output Unicast Packets", HFILL }
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
		/* ethernet counters */
		{ &hf_sflow_eth_dot3StatsAlignmentErrors,
		  { "dot3StatsAlignmentErrors", "sflow.cs.eth.dot3StatsAlignmentErrors",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsFCSErrors,
		  { "dot3StatsFCSErrors", "sflow.cs.eth.dot3StatsFCSErrors",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsSingleCollisionFrames,
		  { "dot3StatsSingleCollisionFrames", "sflow.cs.eth.dot3StatsSingleCollisionFrames",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsMultipleCollisionFrames,
		  { "dot3StatsMultipleCollisionFrames", "sflow.cs.eth.dot3StatsMultipleCollisionFrames",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsSQETestErrors,
		  { "dot3StatsSQETestErrors", "sflow.cs.eth.dot3StatsSQETestErrors",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsDeferredTransmissions,
		  { "dot3StatsDeferredTransmissions", "sflow.cs.eth.dot3StatsDeferredTransmissions",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsLateCollisions,
		  { "dot3StatsLateCollisions", "sflow.cs.eth.dot3StatsLateCollisions",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsExcessiveCollisions,
		  { "dot3StatsExcessiveCollisions", "sflow.cs.eth.dot3StatsExcessiveCollisions",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsInternalMacTransmitErrors,
		  { "dot3StatsInternalMacTransmitErrors", "sflow.cs.eth.dot3StatsInternalMacTransmitErrors",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsCarrierSenseErrors,
		  { "dot3StatsCarrierSenseErrors", "sflow.cs.eth.dot3StatsCarrierSenseErrors",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsFrameTooLongs,
		  { "dot3StatsFrameTooLongs", "sflow.cs.eth.dot3StatsFrameTooLongs",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsInternalMacReceiveErrors,
		  { "dot3StatsInternalMacReceiveErrors", "sflow.cs.eth.dot3StatsInternalMacReceiveErrors",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_sflow_eth_dot3StatsSymbolErrors,
		  { "dot3StatsSymbolErrors", "sflow.cs.eth.dot3StatsSymbolErrors",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
	};

/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_sflow,
		&ett_sflow_sample,
		&ett_sflow_extended_data,
		&ett_sflow_gw_as_dst,
		&ett_sflow_gw_as_dst_seg,
		&ett_sflow_gw_community,
		&ett_sflow_sampled_header,
		&ett_sflow_counters_record,
	};

/* Register the protocol name and description */
	proto_sflow = proto_register_protocol("InMon sFlow",
	    "sFlow", "sflow");

/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_sflow, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

/* Register our configuration options for sFlow */
	sflow_module = prefs_register_protocol(proto_sflow,
					       proto_reg_handoff_sflow);

/* Set default sFlow port(s) */
	range_convert_str(&global_sflow_ports, SFLOW_UDP_PORTS,
			  MAX_UDP_PORT);

	prefs_register_obsolete_preference(sflow_module, "udp.port");

	prefs_register_range_preference(sflow_module, "ports",
					"sFlow UDP Port(s)",
					"Set the port(s) for sFlow messages"
					" (default: " SFLOW_UDP_PORTS ")",
					&global_sflow_ports, MAX_UDP_PORT);

	/*
	   If I use a filter like "ip.src == 10.1.1.1" this will, in
	   addition to the usual suspects, find every sFlow packet
	   where *any* of the payload headers contain 10.1.1.1 as a
	   src addr.  I think this may not be the desired behavior.
	   It can certainly be confusing since the ip.src being found
	   is buried about 3 subtrees deep and the subtrees might be
	   under any one of the sampled (payload) header trees. It is
	   certainly not quickly obvious why the filter matched.
	*/
	prefs_register_bool_preference(sflow_module, "enable_dissection",
				       "Dissect data in sampled headers",
				       "Enabling dissection makes it easy to view protocol details in each of the sampled headers.  Disabling dissection may reduce noise caused when display filters match the contents of any sampled header(s).",
					&global_dissect_samp_headers);
	/*
	   It is not clear to me that it *ever* makes sense to enable
	   this option.  However, it was previously the default
	   behavior so I'll leave it as an option if someone thinks
	   they have a use for it.
	*/
	prefs_register_bool_preference(sflow_module, "enable_analysis",
				       "Analyze data in sampled IP headers",
				       "This option only makes sense if dissection of sampled headers is enabled and probably not even then.",
					&global_analyze_samp_ip_headers );


	register_init_routine(&sflow_reinit);
}


/* If this dissector uses sub-dissector registration add a
   registration routine.  This format is required because a script is
   used to find these routines and create the code that calls these
   routines.
*/
void
proto_reg_handoff_sflow(void)
{
	static gboolean sflow_prefs_initialized = FALSE;

	if (!sflow_prefs_initialized) {
		sflow_handle = new_create_dissector_handle(dissect_sflow,
							   proto_sflow);
		data_handle = find_dissector("data");

		sflow_prefs_initialized = TRUE;
	}

	sflow_reinit();

	/*
	 * XXX - should this be done with a dissector table?
	 */
	if (global_dissect_samp_headers) {
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
	    smds_handle = data_handle;
#endif
#if 0
	    aal5_handle = find_dissector("atm");
#else
	    /* What dissector should be used here? */
	    aal5_handle = data_handle;
#endif
	    ipv4_handle = find_dissector("ip");
	    ipv6_handle = find_dissector("ipv6");
	    mpls_handle = find_dissector("mpls");
	} else {
	    eth_withoutfcs_handle = data_handle;
	    tr_handle = data_handle;
	    fddi_handle = data_handle;
	    fr_handle = data_handle;
	    x25_handle = data_handle;
	    ppp_handle = data_handle;
	    smds_handle = data_handle;
	    aal5_handle = data_handle;
	    ipv4_handle = data_handle;
	    ipv6_handle = data_handle;
	    mpls_handle = data_handle;
	}

}

