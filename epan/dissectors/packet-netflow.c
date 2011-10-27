/*
 ** packet-netflow.c
 **
 ** $Id$
 **
 ** (c) 2002 bill fumerola <fumerola@yahoo-inc.com>
 ** (C) 2005-06 Luca Deri <deri@ntop.org>
 **
 ** All rights reserved.
 **
 ** Wireshark - Network traffic analyzer
 ** By Gerald Combs <gerald@wireshark.org>
 ** Copyright 1998 Gerald Combs
 **
 ** This program is free software; you can redistribute it and/or
 ** modify it under the terms of the GNU General Public License
 ** as published by the Free Software Foundation; either version 2
 ** of the License, or (at your option) any later version.
 **
 ** This program is distributed in the hope that it will be useful,
 ** but WITHOUT ANY WARRANTY; without even the implied warranty of
 ** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 ** GNU General Public License for more details.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *****************************************************************************
 **
 ** Previous NetFlow dissector written by Matthew Smart <smart@monkey.org>
 ** NetFlow v9 support added by same.
 **
 ** NetFlow v9 patches by Luca Deri <deri@ntop.org>
 **
 ** See
 **
 ** http://www.cisco.com/warp/public/cc/pd/iosw/prodlit/tflow_wp.htm
 ** http://www.cisco.com/en/US/technologies/tk648/tk362/technologies_white_paper09186a00800a3db9.html
 **
 ** Cisco ASA5500 Series
 ** http://www.cisco.com/en/US/docs/security/asa/asa83/netflow/netflow.html
 **
 ** for NetFlow v9 information.
 ** ( http://www.ietf.org/rfc/rfc3954.txt ?)
 ** http://www.ietf.org/rfc/rfc5101.txt
 ** http://www.ietf.org/rfc/rfc5102.txt
 ** http://www.ietf.org/rfc/rfc5103.txt
 ** http://www.iana.org/assignments/ipfix/ipfix.xml
 ** http://www.iana.org/assignments/psamp-parameters/psamp-parameters.xml
 ** for IPFIX
 **
 *****************************************************************************
 **
 ** this code was written from the following documentation:
 **
 ** http://www.cisco.com/univercd/cc/td/doc/product/rtrmgmt/nfc/nfc_3_6/iug/format.pdf
 ** http://www.caida.org/tools/measurement/cflowd/configuration/configuration-9.html
 **
 ** some documentation is more accurate then others. in some cases, live data and
 ** information contained in responses from vendors were also used. some fields
 ** are dissected as vendor specific fields.
 **
 ** See also
 **
 ** http://www.cisco.com/en/US/docs/ios/solutions_docs/netflow/nfwhite.html
 **
 ** $Yahoo: //depot/fumerola/packet-netflow/packet-netflow.c#14 $
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <string.h>

#include <epan/prefs.h>
#include <epan/sminmpec.h>
#include <epan/dissectors/packet-tcp.h>
#include <epan/dissectors/packet-udp.h>
#include <epan/expert.h>
#include <epan/dissectors/packet-ntp.h>

/* 4739 is IPFIX.
   2055 and 9996 are common defaults for Netflow
 */
#define NETFLOW_UDP_PORTS "2055,9996"
#define IPFIX_UDP_PORTS   "4739"
#define REVPEN            29305
static dissector_handle_t netflow_handle;

/*
 *	global_netflow_ports : holds the configured range of ports for netflow
 */
static range_t *global_netflow_ports = NULL;
/*
 *	global_ipfix_ports : holds the configured range of ports for IPFIX
 */
static range_t *global_ipfix_ports = NULL;

/*
 * pdu identifiers & sizes
 */

#define V1PDU_SIZE		(4 * 12)
#define V5PDU_SIZE		(4 * 12)
#define V7PDU_SIZE		(4 * 13)
#define V8PDU_AS_SIZE		(4 * 7)
#define V8PDU_PROTO_SIZE	(4 * 7)
#define V8PDU_SPREFIX_SIZE	(4 * 8)
#define V8PDU_DPREFIX_SIZE	(4 * 8)
#define V8PDU_MATRIX_SIZE	(4 * 10)
#define V8PDU_DESTONLY_SIZE	(4 * 8)
#define V8PDU_SRCDEST_SIZE	(4 * 10)
#define V8PDU_FULL_SIZE		(4 * 11)
#define V8PDU_TOSAS_SIZE	(V8PDU_AS_SIZE + 4)
#define V8PDU_TOSPROTOPORT_SIZE	(V8PDU_PROTO_SIZE + 4)
#define V8PDU_TOSSRCPREFIX_SIZE	V8PDU_SPREFIX_SIZE
#define V8PDU_TOSDSTPREFIX_SIZE	V8PDU_DPREFIX_SIZE
#define V8PDU_TOSMATRIX_SIZE	V8PDU_MATRIX_SIZE
#define V8PDU_PREPORTPROTOCOL_SIZE (4 * 10)

#define VARIABLE_LENGTH 65535

static const value_string v5_sampling_mode[] = {
	{0, "No sampling mode configured"},
	{1, "Packet Interval sampling mode configured"},
	{2, "Random sampling mode configured"},
	{0, NULL}
};

enum {
	V8PDU_NO_METHOD = 0,
	V8PDU_AS_METHOD,
	V8PDU_PROTO_METHOD,
	V8PDU_SPREFIX_METHOD,
	V8PDU_DPREFIX_METHOD,
	V8PDU_MATRIX_METHOD,
	V8PDU_DESTONLY_METHOD,
	V8PDU_SRCDEST_METHOD,
	V8PDU_FULL_METHOD,
	V8PDU_TOSAS_METHOD,
	V8PDU_TOSPROTOPORT_METHOD,
	V8PDU_TOSSRCPREFIX_METHOD,
	V8PDU_TOSDSTPREFIX_METHOD,
	V8PDU_TOSMATRIX_METHOD,
	V8PDU_PREPORTPROTOCOL_METHOD
};

static const value_string v8_agg[] = {
	{V8PDU_AS_METHOD, "V8 AS aggregation"},
	{V8PDU_PROTO_METHOD, "V8 Proto/Port aggregation"},
	{V8PDU_SPREFIX_METHOD, "V8 Source Prefix aggregation"},
	{V8PDU_DPREFIX_METHOD, "V8 Destination Prefix aggregation"},
	{V8PDU_MATRIX_METHOD, "V8 Network Matrix aggregation"},
	{V8PDU_DESTONLY_METHOD, "V8 Destination aggregation (Cisco Catalyst)"},
	{V8PDU_SRCDEST_METHOD, "V8 Src/Dest aggregation (Cisco Catalyst)"},
	{V8PDU_FULL_METHOD, "V8 Full aggregation (Cisco Catalyst)"},
	{V8PDU_TOSAS_METHOD, "V8 TOS+AS aggregation aggregation"},
	{V8PDU_TOSPROTOPORT_METHOD, "V8 TOS+Protocol aggregation"},
	{V8PDU_TOSSRCPREFIX_METHOD, "V8 TOS+Source Prefix aggregation"},
	{V8PDU_TOSDSTPREFIX_METHOD, "V8 TOS+Destination Prefix aggregation"},
	{V8PDU_TOSMATRIX_METHOD, "V8 TOS+Prefix Matrix aggregation"},
	{V8PDU_PREPORTPROTOCOL_METHOD, "V8 Port+Protocol aggregation"},
	{0, NULL}
};

/* Version 9 template cache structures */
#define V9TEMPLATE_CACHE_MAX_ENTRIES	100
/* Max number of entries/scopes per template */
#define V9TEMPLATE_MAX_FIELDS 30

struct v9_template_entry {
	guint16	type;
	guint	length;
	guint32 pen;
};

struct v9_template {
	guint	length;
	guint16	id;
	guint16	count;
	guint32 source_id;
	address	source_addr;
	gboolean option_template; /* FALSE=data template, TRUE=option template */
	guint16 count_scopes;
	struct v9_template_entry *scopes;
	struct v9_template_entry *entries;
};

static struct v9_template v9_template_cache[V9TEMPLATE_CACHE_MAX_ENTRIES];

/*
 * wireshark tree identifiers
 */

static int      proto_netflow = -1;
static int      ett_netflow = -1;
static int      ett_unixtime = -1;
static int      ett_flow = -1;
static int      ett_flowtime = -1;
static int      ett_template = -1;
static int      ett_field = -1;
static int      ett_dataflowset = -1;
static int      ett_fwdstat = -1;

/*
 * cflow header
 */

static int      hf_cflow_version = -1;
static int      hf_cflow_count = -1;
static int      hf_cflow_len = -1;
static int      hf_cflow_sysuptime = -1;
static int      hf_cflow_exporttime = -1;
static int      hf_cflow_unix_secs = -1;
static int      hf_cflow_unix_nsecs = -1;
static int      hf_cflow_timestamp = -1;
static int      hf_cflow_samplingmode = -1;
static int      hf_cflow_samplerate = -1;

/*
 * cflow version specific info
 */
static int      hf_cflow_sequence = -1;
static int      hf_cflow_engine_type = -1;
static int      hf_cflow_engine_id = -1;
static int      hf_cflow_source_id = -1;

static int      hf_cflow_aggmethod = -1;
static int      hf_cflow_aggversion = -1;

/* Version 9 */

static int	hf_cflow_template_flowset_id = -1;
static int	hf_cflow_data_flowset_id = -1;
static int	hf_cflow_data_datarecord_id = -1;
static int	hf_cflow_options_flowset_id = -1;
static int	hf_cflow_flowset_id = -1;
static int	hf_cflow_flowset_length = -1;
static int	hf_cflow_datarecord_length = -1;
static int	hf_cflow_template_id = -1;
static int	hf_cflow_template_field_count = -1;
static int	hf_cflow_template_field_type = -1;
static int	hf_cflow_template_field_length = -1;
static int	hf_cflow_option_scope_length = -1;
static int	hf_cflow_option_length = -1;
static int	hf_cflow_template_scope_field_type = -1;
static int	hf_cflow_template_scope_field_length = -1;

static int	hf_cflow_scope_system = -1;
static int	hf_cflow_scope_interface = -1;
static int	hf_cflow_scope_linecard = -1;
static int	hf_cflow_scope_cache = -1;
static int	hf_cflow_scope_template = -1;
static int	hf_cflow_scope_unknown = -1;
/* IPFIX */
static int      hf_cflow_field_count = -1;
static int      hf_cflow_scope_field_count = -1;
static int      hf_cflow_template_field_pen = -1;
static int	hf_cflow_template_field_type_ipfix = -1;
static int	hf_cflow_template_scope_field_type_ipfix = -1;

/*
 * pdu storage
 */
static int      hf_cflow_srcaddr = -1;
static int      hf_cflow_srcaddr_v6 = -1;
static int      hf_cflow_srcnet = -1;
static int      hf_cflow_dstaddr = -1;
static int      hf_cflow_dstaddr_v6 = -1;
static int      hf_cflow_dstnet = -1;
static int      hf_cflow_nexthop = -1;
static int      hf_cflow_nexthop_v6 = -1;
static int      hf_cflow_bgpnexthop = -1;
static int      hf_cflow_bgpnexthop_v6 = -1;
static int      hf_cflow_inputint = -1;
static int      hf_cflow_outputint = -1;
static int      hf_cflow_flows = -1;
static int      hf_cflow_packets = -1;
static int      hf_cflow_packets64 = -1;
static int      hf_cflow_octets = -1;
static int      hf_cflow_octets64 = -1;
static int      hf_cflow_length_min = -1;
static int      hf_cflow_length_max = -1;
static int      hf_cflow_timedelta = -1;
static int      hf_cflow_timestart = -1;
static int      hf_cflow_timeend = -1;
static int      hf_cflow_srcport = -1;
static int      hf_cflow_dstport = -1;
static int      hf_cflow_prot = -1;
static int      hf_cflow_tos = -1;
static int      hf_cflow_flags = -1;
static int      hf_cflow_tcpflags = -1;
static int      hf_cflow_dstas = -1;
static int      hf_cflow_srcas = -1;
static int      hf_cflow_dstmask = -1;
static int      hf_cflow_dstmask_v6 = -1;
static int      hf_cflow_srcmask = -1;
static int      hf_cflow_srcmask_v6 = -1;
static int      hf_cflow_routersc = -1;
static int      hf_cflow_mulpackets = -1;
static int      hf_cflow_muloctets = -1;
static int      hf_cflow_octets_exp = -1;
static int      hf_cflow_octets_exp64 = -1;
static int      hf_cflow_packets_exp = -1;
static int      hf_cflow_packets_exp64 = -1;
static int      hf_cflow_flows_exp = -1;
static int      hf_cflow_flows_exp64 = -1;
static int      hf_cflow_srcprefix = -1;
static int      hf_cflow_dstprefix = -1;
static int      hf_cflow_flow_class = -1;
static int      hf_cflow_ttl_minimum = -1;
static int      hf_cflow_ttl_maximum = -1;
static int      hf_cflow_ipv4_id = -1;
static int      hf_cflow_ip_version = -1;
static int      hf_cflow_icmp_type = -1;
static int      hf_cflow_igmp_type = -1;
static int      hf_cflow_sampling_interval = -1;
static int      hf_cflow_sampling_algorithm = -1;
static int      hf_cflow_flow_active_timeout = -1;
static int      hf_cflow_flow_inactive_timeout = -1;
static int      hf_cflow_mpls_top_label_type = -1;
static int      hf_cflow_mpls_pe_addr = -1;
static int      hf_cflow_sampler_mode = -1;
static int      hf_cflow_sampler_random_interval = -1;
static int      hf_cflow_direction = -1;
static int      hf_cflow_if_name = -1;
static int      hf_cflow_if_descr = -1;
static int      hf_cflow_sampler_name = -1;
static int      hf_cflow_forwarding_status = -1;
static int      hf_cflow_forwarding_code = -1;
static int      hf_cflow_nbar_appl_desc = -1;
static int      hf_cflow_nbar_appl_id = -1;
static int      hf_cflow_nbar_appl_name = -1;
static int      hf_cflow_peer_srcas = -1;
static int      hf_cflow_peer_dstas = -1;
static int      hf_cflow_flow_exporter = -1;
static int      hf_cflow_icmp_ipv4_type = -1;
static int      hf_cflow_icmp_ipv4_code = -1;
static int      hf_cflow_icmp_ipv6_type = -1;
static int      hf_cflow_icmp_ipv6_code = -1;
static int      hf_cflow_tcp_window_size = -1;
static int      hf_cflow_ip_total_length = -1;
static int      hf_cflow_ip_ttl = -1;
static int      hf_cflow_ip_tos = -1;
static int      hf_cflow_ip_dscp = -1;
static int      hf_cflow_octets_squared64 = -1;
static int      hf_cflow_udp_length = -1;
static int      hf_cflow_is_multicast = -1;
static int      hf_cflow_ip_header_words = -1;
static int      hf_cflow_option_map = -1;
static int      hf_cflow_section_header = -1;
static int      hf_cflow_section_payload = -1;
/* IPFIX (version 10) Information Elements */
static int      hf_cflow_post_octets		 = -1;
static int      hf_cflow_post_octets64		 = -1;
static int      hf_cflow_post_packets		 = -1;
static int      hf_cflow_post_packets64		 = -1;
static int      hf_cflow_ipv6_flowlabel		 = -1;
static int      hf_cflow_ipv6_flowlabel24	 = -1;
static int      hf_cflow_post_tos		 = -1;
static int      hf_cflow_srcmac			 = -1;
static int      hf_cflow_post_dstmac		 = -1;
static int      hf_cflow_vlanid			 = -1;
static int      hf_cflow_post_vlanid		 = -1;
static int      hf_cflow_ipv6_exthdr		 = -1;
static int      hf_cflow_dstmac			 = -1;
static int      hf_cflow_post_srcmac		 = -1;
static int      hf_cflow_fragment_offset	 = -1;
static int      hf_cflow_mpls_vpn_rd		 = -1;
static int	hf_cflow_mpls_top_label_prefix_length = -1; /* ID: 91 */
static int	hf_cflow_post_ip_diff_serv_code_point = -1; /* ID: 98 */
static int	hf_cflow_multicast_replication_factor = -1; /* ID: 99 */
static int      hf_cflow_exporter_addr           = -1;
static int      hf_cflow_exporter_addr_v6        = -1;
static int      hf_cflow_drop_octets		 = -1;
static int      hf_cflow_drop_octets64		 = -1;
static int      hf_cflow_drop_packets		 = -1;
static int      hf_cflow_drop_packets64		 = -1;
static int      hf_cflow_drop_total_octets	 = -1;
static int      hf_cflow_drop_total_octets64	 = -1;
static int      hf_cflow_drop_total_packets	 = -1;
static int      hf_cflow_drop_total_packets64	 = -1;
static int      hf_cflow_flow_end_reason	 = -1;
static int      hf_cflow_common_properties_id	 = -1;
static int      hf_cflow_observation_point_id	 = -1;
static int      hf_cflow_mpls_pe_addr_v6	 = -1;
static int      hf_cflow_port_id		 = -1;
static int      hf_cflow_mp_id			 = -1;
static int      hf_cflow_wlan_channel_id	 = -1;
static int      hf_cflow_wlan_ssid		 = -1;
static int      hf_cflow_flow_id		 = -1;
static int      hf_cflow_od_id			 = -1;
static int      hf_cflow_abstimestart		 = -1;
static int      hf_cflow_abstimeend		 = -1;
static int      hf_cflow_dstnet_v6		 = -1;
static int      hf_cflow_srcnet_v6		 = -1;
static int      hf_cflow_ignore_packets		 = -1;
static int      hf_cflow_ignore_packets64	 = -1;
static int      hf_cflow_ignore_octets		 = -1;
static int      hf_cflow_ignore_octets64	 = -1;
static int      hf_cflow_notsent_flows		 = -1;
static int      hf_cflow_notsent_flows64	 = -1;
static int      hf_cflow_notsent_packets	 = -1;
static int      hf_cflow_notsent_packets64	 = -1;
static int      hf_cflow_notsent_octets		 = -1;
static int      hf_cflow_notsent_octets64	 = -1;
static int      hf_cflow_post_total_octets	 = -1;
static int      hf_cflow_post_total_octets64	 = -1;
static int      hf_cflow_post_total_packets	 = -1;
static int      hf_cflow_post_total_packets64	 = -1;
static int      hf_cflow_key			 = -1;
static int      hf_cflow_post_total_mulpackets	 = -1;
static int      hf_cflow_post_total_mulpackets64 = -1;
static int      hf_cflow_post_total_muloctets	 = -1;
static int      hf_cflow_post_total_muloctets64	 = -1;
static int      hf_cflow_tcp_seq_num		 = -1;
static int      hf_cflow_tcp_ack_num		 = -1;
static int      hf_cflow_tcp_urg_ptr		 = -1;
static int      hf_cflow_tcp_header_length	 = -1;
static int      hf_cflow_ip_header_length	 = -1;
static int      hf_cflow_ipv6_payload_length	 = -1;
static int      hf_cflow_ipv6_next_hdr		 = -1;
static int      hf_cflow_ip_precedence		 = -1;
static int      hf_cflow_ip_fragment_flags       = -1;
static int      hf_cflow_mpls_top_label_ttl      = -1;
static int      hf_cflow_mpls_label_length       = -1;
static int      hf_cflow_mpls_label_depth        = -1;
static int      hf_cflow_mpls_top_label_exp      = -1;
static int      hf_cflow_ip_payload_length	 = -1;
static int      hf_cflow_tcp_option_map		 = -1;
static int      hf_cflow_collector_addr		 = -1;
static int      hf_cflow_collector_addr_v6	 = -1;
static int      hf_cflow_export_interface	 = -1;
static int      hf_cflow_export_protocol_version = -1;
static int      hf_cflow_export_prot		 = -1;
static int      hf_cflow_collector_port		 = -1;
static int      hf_cflow_exporter_port		 = -1;
static int      hf_cflow_total_tcp_syn		 = -1;
static int      hf_cflow_total_tcp_fin		 = -1;
static int      hf_cflow_total_tcp_rst		 = -1;
static int      hf_cflow_total_tcp_psh		 = -1;
static int      hf_cflow_total_tcp_ack		 = -1;
static int      hf_cflow_total_tcp_urg		 = -1;
static int      hf_cflow_ip_total_length64       = -1;
static int	hf_cflow_post_natsource_ipv4_address	= -1;	/* ID: 225 */
static int	hf_cflow_post_natdestination_ipv4_address	= -1;	/* ID: 226 */
static int	hf_cflow_post_naptsource_transport_port	= -1;	/* ID: 227 */
static int	hf_cflow_post_naptdestination_transport_port	= -1;	/* ID: 228 */
static int	hf_cflow_nat_originating_address_realm	= -1;	/* ID: 229 */
static int	hf_cflow_nat_event		= -1;	/* ID: 230 */
static int	hf_cflow_initiator_octets	= -1;	/* ID: 231 */
static int	hf_cflow_responder_octets	= -1;	/* ID: 232 */
static int	hf_cflow_firewall_event		= -1;	/* ID: 233 */
static int	hf_cflow_ingress_vrfid		= -1;	/* ID: 234 */
static int	hf_cflow_egress_vrfid		= -1;	/* ID: 235 */
static int	hf_cflow_vrfname		= -1;	/* ID: 236 */
static int	hf_cflow_post_mpls_top_label_exp = -1;	/* ID: 237 */
static int	hf_cflow_tcp_window_scale	 = -1;	/* ID: 238 */
static int      hf_cflow_biflow_direction	 = -1;
static int	hf_cflow_ethernet_header_length	 = -1;	/* ID: 240 */
static int	hf_cflow_ethernet_payload_length = -1;	/* ID: 241 */
static int	hf_cflow_ethernet_total_length	 = -1;	/* ID: 242 */
static int	hf_cflow_dot1q_vlan_id		 = -1;	/* ID: 243 */
static int	hf_cflow_dot1q_priority		 = -1;	/* ID: 244 */
static int	hf_cflow_dot1q_customer_vlan_id	 = -1;	/* ID: 245 */
static int	hf_cflow_dot1q_customer_priority = -1;	/* ID: 246 */
static int	hf_cflow_metro_evc_id		 = -1;	/* ID: 247 */
static int	hf_cflow_metro_evc_type		 = -1;	/* ID: 248 */
static int	hf_cflow_pseudo_wire_id		 = -1;	/* ID: 249 */
static int	hf_cflow_pseudo_wire_type	 = -1;	/* ID: 250 */
static int	hf_cflow_pseudo_wire_control_word	 = -1;	/* ID: 251 */
static int	hf_cflow_ingress_physical_interface	 = -1;	/* ID: 252 */
static int	hf_cflow_egress_physical_interface	 = -1;	/* ID: 253 */
static int	hf_cflow_post_dot1q_vlan_id		 = -1;	/* ID: 254 */
static int	hf_cflow_post_dot1q_customer_vlan_id	 = -1;	/* ID: 255 */
static int	hf_cflow_ethernet_type			 = -1;	/* ID: 256 */
static int	hf_cflow_post_ip_precedence		 = -1;	/* ID: 257 */
static int	hf_cflow_collection_time_milliseconds	 = -1;	/* ID: 258 */
static int	hf_cflow_export_sctp_stream_id		 = -1;	/* ID: 259 */
static int	hf_cflow_max_export_seconds		 = -1;	/* ID: 260 */
static int	hf_cflow_max_flow_end_seconds		 = -1;	/* ID: 261 */
static int	hf_cflow_message_md5_checksum		 = -1;	/* ID: 262 */
static int	hf_cflow_message_scope			 = -1;	/* ID: 263 */
static int	hf_cflow_min_export_seconds		 = -1;	/* ID: 264 */
static int	hf_cflow_min_flow_start_seconds		 = -1;	/* ID: 265 */
static int	hf_cflow_opaque_octets			 = -1;	/* ID: 266 */
static int	hf_cflow_session_scope			 = -1;	/* ID: 267 */
static int	hf_cflow_max_flow_end_microseconds	 = -1;	/* ID: 268 */
static int	hf_cflow_max_flow_end_milliseconds	 = -1;	/* ID: 269 */
static int	hf_cflow_max_flow_end_nanoseconds	 = -1;	/* ID: 270 */
static int	hf_cflow_min_flow_start_microseconds	 = -1;	/* ID: 271 */
static int	hf_cflow_min_flow_start_milliseconds	 = -1;	/* ID: 272 */
static int	hf_cflow_min_flow_start_nanoseconds	 = -1;	/* ID: 273 */
static int	hf_cflow_collector_certificate		 = -1;	/* ID: 274 */
static int	hf_cflow_exporter_certificate		 = -1;	/* ID: 275 */
static int	hf_cflow_selection_sequence_id		 = -1;	/* ID: 301 */
static int	hf_cflow_selector_id			 = -1;	/* ID: 302 */
static int	hf_cflow_information_element_id		 = -1;	/* ID: 303 */
static int	hf_cflow_selector_algorithm		 = -1;	/* ID: 304 */
static int	hf_cflow_sampling_packet_interval	 = -1;	/* ID: 305 */
static int	hf_cflow_sampling_packet_space		 = -1;	/* ID: 306 */
static int	hf_cflow_sampling_time_interval		 = -1;	/* ID: 307 */
static int	hf_cflow_sampling_time_space		 = -1;	/* ID: 308 */
static int	hf_cflow_sampling_size			 = -1;	/* ID: 309 */
static int	hf_cflow_sampling_population		 = -1;	/* ID: 310 */
static int	hf_cflow_sampling_probability		 = -1;	/* ID: 311 */
static int	hf_cflow_mpls_label_stack_section	 = -1;	/* ID: 316 */
static int	hf_cflow_mpls_payload_packet_section	 = -1;	/* ID: 317 */
static int	hf_cflow_selector_id_total_pkts_observed = -1;	/* ID: 318 */
static int	hf_cflow_selector_id_total_pkts_selected = -1;	/* ID: 319 */
static int	hf_cflow_absolute_error			 = -1;	/* ID: 320 */
static int	hf_cflow_relative_error			 = -1;	/* ID: 321 */
static int	hf_cflow_observation_time_seconds	 = -1;	/* ID: 322 */
static int	hf_cflow_observation_time_milliseconds	 = -1;	/* ID: 323 */
static int	hf_cflow_observation_time_microseconds	 = -1;	/* ID: 324 */
static int	hf_cflow_observation_time_nanoseconds	 = -1;	/* ID: 325 */
static int	hf_cflow_digest_hash_value		 = -1;	/* ID: 326 */
static int	hf_cflow_hash_ippayload_offset		 = -1;	/* ID: 327 */
static int	hf_cflow_hash_ippayload_size		 = -1;	/* ID: 328 */
static int	hf_cflow_hash_output_range_min		 = -1;	/* ID: 329 */
static int	hf_cflow_hash_output_range_max		 = -1;	/* ID: 330 */
static int	hf_cflow_hash_selected_range_min	 = -1;	/* ID: 331 */
static int	hf_cflow_hash_selected_range_max	 = -1;	/* ID: 332 */
static int	hf_cflow_hash_digest_output		 = -1;	/* ID: 333 */
static int	hf_cflow_hash_initialiser_value		 = -1;	/* ID: 334 */
static int	hf_cflow_selector_name			 = -1;	/* ID: 335 */
static int	hf_cflow_upper_cilimit			 = -1;	/* ID: 336 */
static int	hf_cflow_lower_cilimit			 = -1;	/* ID: 337 */
static int	hf_cflow_confidence_level		 = -1;	/* ID: 338 */
static int	hf_cflow_information_element_data_type	 = -1;	/* ID: 339 */
static int	hf_cflow_information_element_description = -1;	/* ID: 340 */
static int	hf_cflow_information_element_name	 = -1;	/* ID: 341 */
static int	hf_cflow_information_element_range_begin = -1;	/* ID: 342 */
static int	hf_cflow_information_element_range_end	 = -1;	/* ID: 343 */
static int	hf_cflow_information_element_semantics	 = -1;	/* ID: 344 */
static int	hf_cflow_information_element_units	 = -1;	/* ID: 345 */
static int	hf_cflow_private_enterprise_number	 = -1;	/* ID: 346 */

/* Cisco ASA 5500 Series */
static int	hf_cflow_ingress_acl_id	= -1; /* NF_F_INGRESS_ACL_ID (33000) */
static int	hf_cflow_egress_acl_id	= -1; /* NF_F_EGRESS_ACL_ID  (33001) */
static int	hf_cflow_fw_ext_event	= -1; /* NF_F_FW_EXT_EVENT   (33002) */
static int	hf_cflow_aaa_username	= -1; /* NF_F_USERNAME[_MAX] (40000) */

/* pie = private information element */

static int      hf_pie_cace_local_ipv4_address   = -1;
static int      hf_pie_cace_remote_ipv4_address  = -1;
static int      hf_pie_cace_local_ipv6_address   = -1;
static int      hf_pie_cace_remote_ipv6_address  = -1;
static int      hf_pie_cace_local_port           = -1;
static int      hf_pie_cace_remote_port          = -1;
static int      hf_pie_cace_local_ipv4_id        = -1;
static int      hf_pie_cace_local_icmp_id        = -1;
static int      hf_pie_cace_local_uid            = -1;
static int      hf_pie_cace_local_pid            = -1;
static int      hf_pie_cace_local_username_len   = -1;
static int      hf_pie_cace_local_username       = -1;
static int      hf_pie_cace_local_cmd_len        = -1;
static int      hf_pie_cace_local_cmd            = -1;

const value_string special_mpls_top_label_type[] = {
	{0,	"Unknown"},
	{1,	"TE-MIDPT"},
	{2,	"ATOM"},
	{3,	"VPN"},
	{4,	"BGP"},
	{5,	"LDP"},
	{0,	NULL }
};

static proto_item *
proto_tree_add_mpls_label(proto_tree * pdutree, tvbuff_t * tvb, int offset, int length, int level)
{
	proto_item * ti;
	if( length == 3) {
		guint8 b0 = tvb_get_guint8(tvb, offset);
		guint8 b1 = tvb_get_guint8(tvb, offset + 1);
		guint8 b2 = tvb_get_guint8(tvb, offset + 2);
		ti = proto_tree_add_text(pdutree, tvb, offset, length,
			"MPLS-Label%d: %u exp-bits: %u %s", level,
			((b0<<12)+(b1<<4)+(b2>>4)),
			((b2>>1)&0x7),
			((b2&0x1)?"top-of-stack":""));
	} else {
		ti = proto_tree_add_text(pdutree, tvb, offset, length,
			"MPLS-Label%d: bad length %d", level, length);
	}
	return ti;
}

void		proto_reg_handoff_netflow(void);

typedef struct _hdrinfo_t {
	guint8 vspec;
	guint32 src_id;	/* SourceID in NetFlow V9, Observation Domain ID in IPFIX */
	address net_src;
} hdrinfo_t;

typedef int     dissect_pdu_t(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset,
			      hdrinfo_t * hdrinfo);

static int      dissect_pdu(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int offset,
			    hdrinfo_t * hdrinfo);
static int      dissect_v8_aggpdu(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree,
				  int offset, hdrinfo_t * hdrinfo);
static int      dissect_v8_flowpdu(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree,
				   int offset, hdrinfo_t * hdrinfo);
static int	dissect_v9_flowset(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree,
				   int offset, hdrinfo_t * hdrinfo);
static int	dissect_v9_data(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree,
				int offset, guint16 id, guint length, hdrinfo_t * hdrinfo);
static guint	dissect_v9_pdu(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree,
			       int offset, struct v9_template * tplt, hdrinfo_t * hdrinfo);
static guint	dissect_v9_pdu_scope(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree,
			       int offset, struct v9_template * tplt);
static guint	dissect_v9_pdu_data(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree,
				    int offset, struct v9_template * tplt, hdrinfo_t * hdrinfo, guint8 ipfix_scope_flag);
static int	dissect_v9_options_template(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree,
				   int offset, hdrinfo_t *hdrinfo, guint16 flowset_id);
static int	dissect_v9_template(proto_tree * pdutree, tvbuff_t * tvb, packet_info *pinfo,
				    int offset, int len, hdrinfo_t * hdrinfo, guint16 flowset_id);
static int	v9_template_hash(guint16 id, const address * net_src,
				 guint32 src_id);
static struct v9_template *v9_template_get(guint16 id, address  * net_src,
					   guint32 src_id);
static const char *   decode_v9_template_types(int type);

static const gchar *getprefix(const guint32 * address, int prefix);

static int      flow_process_ints(proto_tree * pdutree, tvbuff_t * tvb,
				  int offset);
static int      flow_process_ports(proto_tree * pdutree, tvbuff_t * tvb,
				   int offset);
static int      flow_process_timeperiod(proto_tree * pdutree, tvbuff_t * tvb,
					int offset);
static int      flow_process_aspair(proto_tree * pdutree, tvbuff_t * tvb,
				    int offset);
static int      flow_process_sizecount(proto_tree * pdutree, tvbuff_t * tvb,
				       int offset);
static int      flow_process_textfield(proto_tree * pdutree, tvbuff_t * tvb,
				       int offset, int bytes,
				       const char *text);


static int
dissect_netflow(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
	proto_tree     *netflow_tree = NULL;
	proto_tree     *ti;
	proto_item     *timeitem, *pduitem;
	proto_tree     *timetree, *pdutree;
	unsigned int    pduret, ver = 0, pdus = 0, x = 1;
	hdrinfo_t       hdrinfo;
	gint            flow_len = -1;
	guint           available, pdusize, offset = 0;
	nstime_t        ts;
	dissect_pdu_t  *pduptr;


	ver = tvb_get_ntohs(tvb, offset);

	switch (ver) {
	case 1:
		pdusize = V1PDU_SIZE;
		pduptr = &dissect_pdu;
		break;
	case 5:
		pdusize = V5PDU_SIZE;
		pduptr = &dissect_pdu;
		break;
	case 7:
		pdusize = V7PDU_SIZE;
		pduptr = &dissect_pdu;
		break;
	case 8:
		pdusize = -1;	/* deferred */
		pduptr = &dissect_v8_aggpdu;
		break;
	case 9:
	case 10: /* IPFIX */
		pdusize = -1;	/* deferred */
		pduptr = &dissect_v9_flowset;
		break;
	default:
		/*  This does not appear to be a valid netflow packet;
		 *  return 0 to let another dissector have a chance at
		 *  dissecting it.
		 */
		return 0;
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "CFLOW");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_netflow, tvb,
					 offset, -1, FALSE);
		netflow_tree = proto_item_add_subtree(ti, ett_netflow);
	}

	hdrinfo.vspec = ver;
	hdrinfo.src_id = 0;
	SET_ADDRESS(&hdrinfo.net_src, pinfo->net_src.type, pinfo->net_src.len,
		    pinfo->net_src.data);

	if (tree)
		proto_tree_add_uint(netflow_tree, hf_cflow_version, tvb,
				    offset, 2, ver);
	offset += 2;

	pdus = tvb_get_ntohs(tvb, offset);
	if (tree) {
		if(ver == 10) {
			proto_tree_add_uint(netflow_tree, hf_cflow_len, tvb,
					    offset, 2, pdus);
			flow_len = pdus;
		} else {
			proto_tree_add_uint(netflow_tree, hf_cflow_count, tvb,
					    offset, 2, pdus);
			flow_len = -1;
		}
	}
	offset += 2;

	/*
	 * set something interesting in the display now that we have info
	 */
	if (check_col(pinfo->cinfo, COL_INFO)) {
		if (ver == 9) {
			col_add_fstr(pinfo->cinfo, COL_INFO,
				     "total: %u (v%u) record%s", pdus, ver,
				     plurality(pdus, "", "s"));
		} else if (ver == 10) {
			gint remaining = tvb_length_remaining(tvb, offset)+4;

			if(remaining == flow_len)
				col_add_fstr(pinfo->cinfo, COL_INFO, "IPFIX flow (%d bytes)", flow_len);
			else
				col_add_fstr(pinfo->cinfo, COL_INFO,
					     "IPFIX partial flow (%u/%u bytes)",
					     remaining, flow_len);
		} else {
			col_add_fstr(pinfo->cinfo, COL_INFO,
			    "total: %u (v%u) flow%s", pdus, ver,
                            plurality(pdus, "", "s"));
		}
	}

	/*
	 * the rest is only interesting if we're displaying/searching the
	 * packet
	 */
	if (!tree)
		return tvb_length(tvb);

	if(ver != 10) {
		proto_tree_add_item(netflow_tree, hf_cflow_sysuptime, tvb,
				    offset, 4, FALSE);
		offset += 4;
	}
	ts.secs = tvb_get_ntohl(tvb, offset);

	if ((ver != 9) && (ver != 10)) {
		ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
		timeitem = proto_tree_add_time(netflow_tree,
					       hf_cflow_timestamp, tvb, offset,
					       8, &ts);
	} else {
		ts.nsecs = 0;
		timeitem = proto_tree_add_time(netflow_tree,
					       hf_cflow_timestamp, tvb, offset,
					       4, &ts);
	}

	timetree = proto_item_add_subtree(timeitem, ett_unixtime);

	proto_tree_add_item(timetree,
			    (ver == 10) ? hf_cflow_exporttime : hf_cflow_unix_secs,
			    tvb, offset, 4, FALSE);

	offset += 4;

	if ((ver != 9) && (ver != 10)) {
		proto_tree_add_item(timetree, hf_cflow_unix_nsecs, tvb,
				    offset, 4, FALSE);
		offset += 4;
	}

	/*
	 * version specific header
	 */
	if (ver == 5 || ver == 7 || ver == 8 || ver == 9 || ver == 10) {
		proto_tree_add_item(netflow_tree, hf_cflow_sequence,
				    tvb, offset, 4, FALSE);
		offset += 4;
	}
	if (ver == 5 || ver == 8) {
		proto_tree_add_item(netflow_tree, hf_cflow_engine_type,
				    tvb, offset++, 1, FALSE);
		proto_tree_add_item(netflow_tree, hf_cflow_engine_id,
				    tvb, offset++, 1, FALSE);
	} else if ((ver == 9) || (ver == 10)) {
	        proto_tree_add_item(netflow_tree,
				    (ver == 9) ? hf_cflow_source_id : hf_cflow_od_id,
				    tvb, offset, 4, FALSE);
		hdrinfo.src_id = tvb_get_ntohl(tvb, offset);
		offset += 4;
	}
	if (ver == 8) {
		hdrinfo.vspec = tvb_get_guint8(tvb, offset);
		switch (hdrinfo.vspec) {
		case V8PDU_AS_METHOD:
			pdusize = V8PDU_AS_SIZE;
			break;
		case V8PDU_PROTO_METHOD:
			pdusize = V8PDU_PROTO_SIZE;
			break;
		case V8PDU_SPREFIX_METHOD:
			pdusize = V8PDU_SPREFIX_SIZE;
			break;
		case V8PDU_DPREFIX_METHOD:
			pdusize = V8PDU_DPREFIX_SIZE;
			break;
		case V8PDU_MATRIX_METHOD:
			pdusize = V8PDU_MATRIX_SIZE;
			break;
		case V8PDU_DESTONLY_METHOD:
			pdusize = V8PDU_DESTONLY_SIZE;
			pduptr = &dissect_v8_flowpdu;
			break;
		case V8PDU_SRCDEST_METHOD:
			pdusize = V8PDU_SRCDEST_SIZE;
			pduptr = &dissect_v8_flowpdu;
			break;
		case V8PDU_FULL_METHOD:
			pdusize = V8PDU_FULL_SIZE;
			pduptr = &dissect_v8_flowpdu;
			break;
		case V8PDU_TOSAS_METHOD:
			pdusize = V8PDU_TOSAS_SIZE;
			break;
		case V8PDU_TOSPROTOPORT_METHOD:
			pdusize = V8PDU_TOSPROTOPORT_SIZE;
			break;
		case V8PDU_TOSSRCPREFIX_METHOD:
			pdusize = V8PDU_TOSSRCPREFIX_SIZE;
			break;
		case V8PDU_TOSDSTPREFIX_METHOD:
			pdusize = V8PDU_TOSDSTPREFIX_SIZE;
			break;
		case V8PDU_TOSMATRIX_METHOD:
			pdusize = V8PDU_TOSMATRIX_SIZE;
			break;
		case V8PDU_PREPORTPROTOCOL_METHOD:
			pdusize = V8PDU_PREPORTPROTOCOL_SIZE;
			break;
		default:
			pdusize = -1;
			hdrinfo.vspec = 0;
			break;
		}
		proto_tree_add_uint(netflow_tree, hf_cflow_aggmethod,
				    tvb, offset++, 1, hdrinfo.vspec);
		proto_tree_add_item(netflow_tree, hf_cflow_aggversion,
				    tvb, offset++, 1, FALSE);
	}
	if (ver == 7 || ver == 8)
		offset = flow_process_textfield(netflow_tree, tvb, offset, 4,
						"reserved");
	else if (ver == 5) {
		proto_tree_add_item(netflow_tree, hf_cflow_samplingmode,
				    tvb, offset, 2, FALSE);
		proto_tree_add_item(netflow_tree, hf_cflow_samplerate,
				    tvb, offset, 2, FALSE);
		offset += 2;
	}

	if (pdus <= 0) { /* no payload to decode - in theory */
		/* This is absurd, but does happens in practice.  */
		proto_tree_add_text(netflow_tree, tvb, offset, tvb_length_remaining(tvb, offset),
					"FlowSets impossibles - PDU Count is %d", pdus);
		return tvb_length(tvb);
	}
	/*
	 * everything below here should be payload
	 */
	available = tvb_length_remaining(tvb, offset);
	for (x = 1; ((ver != 10) && (x < pdus + 1)) || ((ver == 10) && (available - pdusize > 0)); x++) {
          	/*
		 * make sure we have a pdu's worth of data
		 */
		available = tvb_length_remaining(tvb, offset);
		if(((ver == 9) || (ver == 10)) && available >= 4) {
			/* pdusize can be different for each v9 flowset */
			pdusize = tvb_get_ntohs(tvb, offset + 2);
		}

		if (available < pdusize)
			break;

		if ((ver == 9) || (ver == 10)) {
			pduitem = proto_tree_add_text(netflow_tree, tvb,
						      offset, pdusize,
						      (ver == 9) ? "FlowSet %u" : "Set %u", x);
		} else {
			pduitem = proto_tree_add_text(netflow_tree, tvb,
			    offset, pdusize, "pdu %u/%u", x, pdus);
		}
		pdutree = proto_item_add_subtree(pduitem, ett_flow);

		pduret = pduptr(tvb, pinfo, pdutree, offset, &hdrinfo);

		if (pduret < pdusize) pduret = pdusize; /* padding */

		/*
		 * if we came up short, stop processing
		 */
		if (pduret == pdusize && pduret != 0)
			offset += pduret;
		else
			break;
	}

	return tvb_length(tvb);
}

/*
 * flow_process_* == common groups of fields, probably could be inline
 */

static int
flow_process_ints(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	proto_tree_add_item(pdutree, hf_cflow_inputint, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(pdutree, hf_cflow_outputint, tvb, offset, 2,
			    FALSE);
	offset += 2;

	return offset;
}

static int
flow_process_ports(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	proto_tree_add_item(pdutree, hf_cflow_srcport, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(pdutree, hf_cflow_dstport, tvb, offset, 2, FALSE);
	offset += 2;

	return offset;
}

static int
flow_process_timeperiod(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	nstime_t        ts_start, ts_end;
	int		offset_s, offset_e;
	nstime_t	ts_delta;
	guint32         msec_start, msec_end;
	guint32         msec_delta;
	proto_tree *	timetree = 0;
	proto_item *    timeitem = 0;


	msec_start = tvb_get_ntohl(tvb, offset);
	ts_start.secs = msec_start / 1000;
	ts_start.nsecs = (msec_start % 1000) * 1000000;
	offset_s = offset;
	offset += 4;

	msec_end = tvb_get_ntohl(tvb, offset);
	ts_end.secs = msec_end / 1000;
	ts_end.nsecs = (msec_end % 1000) * 1000000;
	offset_e = offset;
	offset += 4;

	msec_delta = msec_end - msec_start;
	ts_delta.secs = msec_delta / 1000;
	ts_delta.nsecs = (msec_delta % 1000) * 1000000;


	timeitem = proto_tree_add_time(pdutree, hf_cflow_timedelta, tvb,
				       offset_s, 8, &ts_delta);
	PROTO_ITEM_SET_GENERATED(timeitem);
	timetree = proto_item_add_subtree(timeitem, ett_flowtime);

	proto_tree_add_time(timetree, hf_cflow_timestart, tvb, offset_s, 4,
			    &ts_start);
	proto_tree_add_time(timetree, hf_cflow_timeend, tvb, offset_e, 4,
			    &ts_end);

	return offset;
}


static int
flow_process_aspair(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	proto_tree_add_item(pdutree, hf_cflow_srcas, tvb, offset, 2, FALSE);
	offset += 2;

	proto_tree_add_item(pdutree, hf_cflow_dstas, tvb, offset, 2, FALSE);
	offset += 2;

	return offset;
}

static int
flow_process_sizecount(proto_tree * pdutree, tvbuff_t * tvb, int offset)
{
	proto_tree_add_item(pdutree, hf_cflow_packets, tvb, offset, 4, FALSE);
	offset += 4;

	proto_tree_add_item(pdutree, hf_cflow_octets, tvb, offset, 4, FALSE);
	offset += 4;

	return offset;
}

static int
flow_process_textfield(proto_tree * pdutree, tvbuff_t * tvb, int offset,
		       int bytes, const char *text)
{
	proto_tree_add_text(pdutree, tvb, offset, bytes, "%s", text);
	offset += bytes;

	return offset;
}

static int
dissect_v8_flowpdu(tvbuff_t * tvb _U_, packet_info * pinfo _U_, proto_tree * pdutree, int offset,
		   hdrinfo_t * hdrinfo)
{
	int             startoffset = offset;
	guint8		verspec;

	proto_tree_add_item(pdutree, hf_cflow_dstaddr, tvb, offset, 4, FALSE);
	offset += 4;

	verspec = hdrinfo->vspec;

	if (verspec != V8PDU_DESTONLY_METHOD) {
		proto_tree_add_item(pdutree, hf_cflow_srcaddr, tvb, offset, 4,
				    FALSE);
		offset += 4;
	}
	if (verspec == V8PDU_FULL_METHOD) {
		proto_tree_add_item(pdutree, hf_cflow_dstport, tvb, offset, 2,
				    FALSE);
		offset += 2;
		proto_tree_add_item(pdutree, hf_cflow_srcport, tvb, offset, 2,
				    FALSE);
		offset += 2;
	}

	offset = flow_process_sizecount(pdutree, tvb, offset);
	offset = flow_process_timeperiod(pdutree, tvb, offset);

	proto_tree_add_item(pdutree, hf_cflow_outputint, tvb, offset, 2,
			    FALSE);
	offset += 2;

	if (verspec != V8PDU_DESTONLY_METHOD) {
		proto_tree_add_item(pdutree, hf_cflow_inputint, tvb, offset, 2,
				    FALSE);
		offset += 2;
	}

	proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1, FALSE);
	if (verspec == V8PDU_FULL_METHOD)
		proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1,
				    FALSE);
	offset = flow_process_textfield(pdutree, tvb, offset, 1, "marked tos");

	if (verspec == V8PDU_SRCDEST_METHOD)
		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2,
					   "reserved");
	else if (verspec == V8PDU_FULL_METHOD)
		offset =
		    flow_process_textfield(pdutree, tvb, offset, 1, "padding");

	offset =
	    flow_process_textfield(pdutree, tvb, offset, 4, "extra packets");

	proto_tree_add_item(pdutree, hf_cflow_routersc, tvb, offset, 4, FALSE);
	offset += 4;

	return (offset - startoffset);
}

/*
 * dissect a version 8 pdu, returning the length of the pdu processed
 */

static int
dissect_v8_aggpdu(tvbuff_t * tvb _U_, packet_info * pinfo _U_, proto_tree * pdutree, int offset,
		  hdrinfo_t * hdrinfo)
{
	int             startoffset = offset;
	guint8		verspec;

	proto_tree_add_item(pdutree, hf_cflow_flows, tvb, offset, 4, FALSE);
	offset += 4;

	offset = flow_process_sizecount(pdutree, tvb, offset);
	offset = flow_process_timeperiod(pdutree, tvb, offset);

	verspec = hdrinfo->vspec;

	switch (verspec) {
	case V8PDU_AS_METHOD:
	case V8PDU_TOSAS_METHOD:
		offset = flow_process_aspair(pdutree, tvb, offset);

		if (verspec == V8PDU_TOSAS_METHOD) {
			proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
					    offset++, 1, FALSE);
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 1,
						   "padding");
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 2,
						   "reserved");
		}
		break;
	case V8PDU_PROTO_METHOD:
	case V8PDU_TOSPROTOPORT_METHOD:
		proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1,
				    FALSE);

		if (verspec == V8PDU_PROTO_METHOD)
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 1,
						   "padding");
		else if (verspec == V8PDU_TOSPROTOPORT_METHOD)
			proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
					    offset++, 1, FALSE);

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2,
					   "reserved");
		offset = flow_process_ports(pdutree, tvb, offset);

		if (verspec == V8PDU_TOSPROTOPORT_METHOD)
			offset = flow_process_ints(pdutree, tvb, offset);
		break;
	case V8PDU_SPREFIX_METHOD:
	case V8PDU_DPREFIX_METHOD:
	case V8PDU_TOSSRCPREFIX_METHOD:
	case V8PDU_TOSDSTPREFIX_METHOD:
		proto_tree_add_item(pdutree,
				    verspec ==
				    V8PDU_SPREFIX_METHOD ?
				    hf_cflow_srcnet : hf_cflow_dstnet, tvb,
				    offset, 4, FALSE);
		offset += 4;

		proto_tree_add_item(pdutree,
				    verspec ==
				    V8PDU_SPREFIX_METHOD ?
				    hf_cflow_srcmask : hf_cflow_dstmask, tvb,
				    offset++, 1, FALSE);

		if (verspec == V8PDU_SPREFIX_METHOD
		    || verspec == V8PDU_DPREFIX_METHOD)
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 1,
						   "padding");
		else if (verspec == V8PDU_TOSSRCPREFIX_METHOD
			 || verspec == V8PDU_TOSDSTPREFIX_METHOD)
			proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
					    offset++, 1, FALSE);

		proto_tree_add_item(pdutree,
				    verspec ==
				    V8PDU_SPREFIX_METHOD ? hf_cflow_srcas
				    : hf_cflow_dstas, tvb, offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(pdutree,
				    verspec ==
				    V8PDU_SPREFIX_METHOD ?
				    hf_cflow_inputint : hf_cflow_outputint,
				    tvb, offset, 2, FALSE);
		offset += 2;

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2,
					   "reserved");
		break;
	case V8PDU_MATRIX_METHOD:
	case V8PDU_TOSMATRIX_METHOD:
	case V8PDU_PREPORTPROTOCOL_METHOD:
		proto_tree_add_item(pdutree, hf_cflow_srcnet, tvb, offset, 4,
				    FALSE);
		offset += 4;

		proto_tree_add_item(pdutree, hf_cflow_dstnet, tvb, offset, 4,
				    FALSE);
		offset += 4;

		proto_tree_add_item(pdutree, hf_cflow_srcmask, tvb, offset++,
				    1, FALSE);

		proto_tree_add_item(pdutree, hf_cflow_dstmask, tvb, offset++,
				    1, FALSE);

		if (verspec == V8PDU_TOSMATRIX_METHOD ||
		    verspec == V8PDU_PREPORTPROTOCOL_METHOD) {
			proto_tree_add_item(pdutree, hf_cflow_tos, tvb,
					    offset++, 1, FALSE);
			if (verspec == V8PDU_TOSMATRIX_METHOD) {
				offset =
				    flow_process_textfield(pdutree, tvb,
							   offset, 1,
							   "padding");
			} else if (verspec == V8PDU_PREPORTPROTOCOL_METHOD) {
				proto_tree_add_item(pdutree, hf_cflow_prot,
						    tvb, offset++, 1, FALSE);
			}
		} else {
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 2,
						   "reserved");
		}

		if (verspec == V8PDU_MATRIX_METHOD
		    || verspec == V8PDU_TOSMATRIX_METHOD) {
			offset = flow_process_aspair(pdutree, tvb, offset);
		} else if (verspec == V8PDU_PREPORTPROTOCOL_METHOD) {
			offset = flow_process_ports(pdutree, tvb, offset);
		}

		offset = flow_process_ints(pdutree, tvb, offset);
		break;
	}


	return (offset - startoffset);
}

/* Dissect a version 9 FlowSet and return the length we processed. */

static int
dissect_v9_flowset(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree, int offset, hdrinfo_t * hdrinfo)
{
	int length;
	guint16	flowset_id;
	guint8 ver;

	ver = hdrinfo->vspec;

	if ((ver != 9) && (ver != 10))
		return (0);

	flowset_id = tvb_get_ntohs(tvb, offset);
	length = tvb_get_ntohs(tvb, offset + 2);

	if (length < 4) {
		expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_WARN,
				       "Length (%u) too short", length);
		return tvb_length_remaining(tvb, offset);
	}

	if ((flowset_id == 0) || (flowset_id == 2)) {
		/* Template */
		proto_tree_add_item(pdutree, hf_cflow_template_flowset_id, tvb,
		    offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(pdutree, hf_cflow_flowset_length, tvb,
		    offset, 2, FALSE);
		offset += 2;

		dissect_v9_template(pdutree, tvb, pinfo, offset, length - 4, hdrinfo, flowset_id);
	} else if ((flowset_id == 1) || (flowset_id == 3)) {
		/* Option Template */
		proto_tree_add_item(pdutree, hf_cflow_options_flowset_id, tvb,
		    offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(pdutree, hf_cflow_flowset_length, tvb,
		    offset, 2, FALSE);
		offset += 2;

		dissect_v9_options_template(tvb, pinfo, pdutree, offset, hdrinfo, flowset_id);
	} else if (flowset_id >= 4 && flowset_id <= 255) {
		/* Reserved */
		proto_tree_add_item(pdutree, hf_cflow_flowset_id, tvb,
		    offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(pdutree, hf_cflow_flowset_length, tvb,
		    offset, 2, FALSE);
	} else {
		/* Data */
		proto_tree_add_item(pdutree, (ver == 9) ? hf_cflow_data_flowset_id :  hf_cflow_data_datarecord_id, tvb,
				    offset, 2, FALSE);
		offset += 2;

		proto_tree_add_item(pdutree, (ver == 9) ? hf_cflow_flowset_length : hf_cflow_datarecord_length, tvb,
				    offset, 2, FALSE);
		offset += 2;

		dissect_v9_data(tvb, pinfo, pdutree, offset, flowset_id,
				(guint)length - 4, hdrinfo);
	}

	return (length);
}

static int
dissect_v9_data(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree, int offset,
		guint16 id, guint length, hdrinfo_t * hdrinfo)
{
	struct v9_template *tplt;
	proto_tree *data_tree;
	proto_item *data_item;
        guint       pdu_len;

	if (length == 0) {
		expert_add_info_format(pinfo, pdutree, PI_MALFORMED,
				       PI_WARN, "No flow information");
	}

	tplt = v9_template_get(id, &hdrinfo->net_src, hdrinfo->src_id);
	if (tplt != NULL  && tplt->length != 0) {
		int count = 1;
		while (length >= tplt->length) {
			data_item = proto_tree_add_text(pdutree, tvb,
							offset, tplt->length, "Flow %d", count++);
			data_tree = proto_item_add_subtree(data_item,
			    ett_dataflowset);

			pdu_len = dissect_v9_pdu(tvb, pinfo, data_tree, offset, tplt, hdrinfo);

			offset += pdu_len;
                        /* XXX - Throw an exception */
			length -= pdu_len < length ? pdu_len : length;
		}
		if (length != 0) {
			proto_tree_add_text(pdutree, tvb, offset, length,
			    "Padding (%u byte%s)",
			    length, plurality(length, "", "s"));
		}
	} else {
		proto_tree_add_text(pdutree, tvb, offset, length,
		    "Data (%u byte%s), no template found",
		    length, plurality(length, "", "s"));
	}

	return (0);
}

#define GOT_LOCAL_ADDR  (1 << 0)
#define GOT_REMOTE_ADDR (1 << 1)
#define GOT_LOCAL_PORT  (1 << 2)
#define GOT_REMOTE_PORT (1 << 3)
#define GOT_IPv4_ID     (1 << 4)
#define GOT_ICMP_ID     (1 << 5)
#define GOT_UID         (1 << 6)
#define GOT_PID         (1 << 7)
#define GOT_USERNAME    (1 << 8)
#define GOT_COMMAND     (1 << 9)

#define GOT_BASE ( \
        GOT_LOCAL_ADDR | \
        GOT_REMOTE_ADDR | \
        GOT_UID | \
        GOT_PID | \
        GOT_USERNAME | \
        GOT_COMMAND \
        )

#define GOT_TCP_UDP (GOT_BASE | GOT_LOCAL_PORT | GOT_REMOTE_PORT)
#define GOT_ICMP (GOT_BASE | GOT_IPv4_ID | GOT_ICMP_ID)

static guint
dissect_v9_pdu(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree, int offset,
    struct v9_template * tplt, hdrinfo_t * hdrinfo)
{
	int             orig_offset = offset;

	if (tplt->scopes != NULL && tplt->count_scopes > 0) {
		if (hdrinfo->vspec == 9) {
		offset += dissect_v9_pdu_scope(tvb, pinfo, pdutree, offset, tplt);
		} else if (hdrinfo->vspec == 10) {
			offset += dissect_v9_pdu_data(tvb, pinfo, pdutree, offset, tplt, hdrinfo, 1);
		}
	}
	offset += dissect_v9_pdu_data(tvb, pinfo, pdutree, offset, tplt, hdrinfo, 0);

	return (guint) (offset - orig_offset);
}

static guint
dissect_v9_pdu_scope(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *pdutree, int offset,
    struct v9_template * tplt)
{
	int             orig_offset = offset;
	proto_item *    ti;
	if(tplt->scopes != NULL) {
		int             i;
		for(i = 0; i < tplt->count_scopes; i++) {
			guint16 type = tplt->scopes[i].type;
			guint16 length = tplt->scopes[i].length;
			if (!length) {
				continue;
			}
			switch( type ) {
			case 1: /* system */
				ti = proto_tree_add_item(pdutree, hf_cflow_scope_system,
				       tvb, offset, length, FALSE);
				break;
			case 2: /* interface */
				ti = proto_tree_add_item(pdutree, hf_cflow_scope_interface,
				       tvb, offset, length, FALSE);
				break;
			case 3: /* linecard */
				proto_tree_add_item(pdutree, hf_cflow_scope_linecard,
						tvb, offset, length, FALSE);
				break;
			case 4: /* netflow cache */
				proto_tree_add_item(pdutree, hf_cflow_scope_cache,
						tvb, offset, length, FALSE);
				break;
			case 5: /* tplt */
				proto_tree_add_item(pdutree, hf_cflow_scope_template,
						tvb, offset, length, FALSE);
				break;
			default: /* unknown */
				proto_tree_add_item(pdutree, hf_cflow_scope_unknown,
						tvb, offset, length, FALSE);
				break;
			}
			offset += length;
		}
	}
        return (guint) (offset - orig_offset);
}

static guint
dissect_v9_pdu_data(tvbuff_t * tvb, packet_info * pinfo, proto_tree * pdutree, int offset,
		    struct v9_template * tplt, hdrinfo_t * hdrinfo, guint8 ipfix_scope_flag)
{
	int             orig_offset = offset;
	int             i;
	int             rev;
	nstime_t        ts_start[2], ts_end[2];
	int             offset_s[2], offset_e[2];
	nstime_t        ts_delta;
	nstime_t	ts;
	guint32         msec_start[2], msec_end[2];
	guint32         msec_delta;
	proto_tree *    timetree = 0;
	proto_item *    timeitem = 0;
	address         local_addr, remote_addr;
	guint16         local_port = 0, remote_port = 0, ipv4_id = 0, icmp_id = 0;
	guint32         uid = 0, pid = 0;
	int             uname_len;
	gchar *         uname_str = NULL;
	int             cmd_len;
	gchar *         cmd_str = NULL;
	guint16         got_flags = 0;

	gboolean        vstr_long;
	int             vstr_len;

	proto_item *    ti;
	const guint8 *reftime;
	guint16 count = ipfix_scope_flag ? tplt->count_scopes : tplt->count;
	struct v9_template_entry *entries = ipfix_scope_flag ? tplt->scopes : tplt->entries;
	proto_tree *    fwdstattree = 0;

	if (entries == NULL) {
		/* I don't think we can actually hit this condition.
		   If we can, what would cause it?  Does this need a
		   warn?  If so what?
		*/
		return 0;
	}

	offset_s[0] = offset_s[1] = offset_e[0] = offset_e[1] = 0;
	msec_start[0] = msec_start[1] = msec_end[0] = msec_end[1] = 0;

	for (i = 0; i < count; i++) {
		guint64 pen_type;
		guint16 type, length;
		guint32 pen = 0;

		rev = 0;
		type = entries[i].type;
		length = entries[i].length;
		if (hdrinfo->vspec == 10 && type & 0x8000) {
		  pen = entries[i].pen;
		  if (pen == REVPEN) { /* reverse PEN */
		    type &= 0x7fff;
		    rev = 1;
		  }
		}

		pen_type = (pen > 0 && pen != REVPEN) ? pen << 16 | (type & 0x7fff) : type;
		ti = NULL;
		switch (pen_type) {

		case 85: /* BYTES_PERMANENT */
		case 1: /* bytes */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_octets,
				    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_octets64,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "Octets: length %u", length);
			}
			break;

		case 86: /* PACKETS_PERMANENT */
		case 2: /* packets */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_packets,
				    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_packets64,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "Packets: length %u", length);
			}
			break;

		case 163: /*  observedFlowTotalCount */
		case 3: /* flows */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_flows,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "Flows: length %u", length);
			}
			break;

		case 4: /* proto */
			ti = proto_tree_add_item(pdutree, hf_cflow_prot,
			    tvb, offset, length, FALSE);
			break;

		case 5: /* TOS */
			ti = proto_tree_add_item(pdutree, hf_cflow_tos,
			    tvb, offset, length, FALSE);
			break;

		case 6: /* TCP flags */
			ti = proto_tree_add_item(pdutree, hf_cflow_tcpflags,
			    tvb, offset, length, FALSE);
			break;

		case 7: /* source port */
		case 180: /*  udpSourcePort */
		case 182: /*  tcpSourcePort */
			ti = proto_tree_add_item(pdutree, hf_cflow_srcport,
			    tvb, offset, length, FALSE);
			break;

		case 8: /* source IP */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_srcaddr,
				    tvb, offset, length, FALSE);
			} else if (length == 16) {
				ti = proto_tree_add_item(pdutree, hf_cflow_srcaddr_v6,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "SrcAddr: length %u", length);
			}
			break;

		case 9: /* source mask */
			ti = proto_tree_add_item(pdutree, hf_cflow_srcmask,
			    tvb, offset, length, FALSE);
			break;

		case 10: /* input SNMP */
			ti = proto_tree_add_item(pdutree, hf_cflow_inputint,
			    tvb, offset, length, FALSE);
			break;

		case 11: /* dest port */
		case 181: /*  udpDestinationPort */
		case 183: /*  tcpDestinationPort */
			ti = proto_tree_add_item(pdutree, hf_cflow_dstport,
			    tvb, offset, length, FALSE);
			break;

		case 12: /* dest IP */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_dstaddr,
				    tvb, offset, length, FALSE);
			} else if (length == 16) {
				ti = proto_tree_add_item(pdutree, hf_cflow_dstaddr_v6,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "DstAddr: length %u", length);
			}
			break;

		case 13: /* dest mask */
			ti = proto_tree_add_item(pdutree, hf_cflow_dstmask,
			    tvb, offset, length, FALSE);
			break;

		case 14: /* output SNMP */
			ti = proto_tree_add_item(pdutree, hf_cflow_outputint,
			    tvb, offset, length, FALSE);
			break;

		case 15: /* nexthop IP */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_nexthop,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "NextHop: length %u", length);
			}
			break;

		case 16: /* source AS */
			ti = proto_tree_add_item(pdutree, hf_cflow_srcas,
			    tvb, offset, length, FALSE);
			break;

		case 17: /* dest AS */
			ti = proto_tree_add_item(pdutree, hf_cflow_dstas,
			    tvb, offset, length, FALSE);
			break;

		case 18: /* BGP nexthop IP */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_bgpnexthop,
				    tvb, offset, length, FALSE);
			} else if (length == 16) {
				ti = proto_tree_add_item(pdutree, hf_cflow_bgpnexthop_v6,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "BGPNextHop: length %u", length);
			}
			break;

		case 19: /* multicast packets */
			ti = proto_tree_add_item(pdutree, hf_cflow_mulpackets,
			    tvb, offset, length, FALSE);
			break;

		case 20: /* multicast octets */
			ti = proto_tree_add_item(pdutree, hf_cflow_muloctets,
			    tvb, offset, length, FALSE);
			break;

		case 22: /* first switched */
		case 21: /* last switched */
			if(type == 22) {
				offset_s[rev] = offset;
			        msec_start[rev] = tvb_get_ntohl(tvb, offset);
				ts_start[rev].secs = msec_start[rev] / 1000;
				ts_start[rev].nsecs = (msec_start[rev] % 1000) * 1000000;
			} else {
				offset_e[rev] = offset;
			        msec_end[rev] = tvb_get_ntohl(tvb, offset);
				ts_end[rev].secs = msec_end[rev] / 1000;
				ts_end[rev].nsecs = (msec_end[rev] % 1000) * 1000000;
			}
			/* FALLTHROUGH */
		case 150: /*  flowStartSeconds */
		case 151: /*  flowEndSeconds */
			if (type == 150) {
			  offset_s[rev] = offset;
			  ts_start[rev].secs = tvb_get_ntohl(tvb, offset);
			  ts_start[rev].nsecs = 0;
			} else if (type == 151) {
			  offset_e[rev] = offset;
			  ts_end[rev].secs = tvb_get_ntohl(tvb, offset);
			  ts_end[rev].nsecs = 0;
			}
			/* FALLTHROUGH */
		case 152: /*  flowStartMilliseconds */
		case 153: /*  flowEndMilliseconds */
		        if(type == 152) {
			  offset_s[rev] = offset;
			  ts_start[rev].secs = tvb_get_ntohl(tvb, offset);
			  ts_start[rev].nsecs = tvb_get_ntohl(tvb, offset + 4) * 1000000;
			} else if(type == 153) {
			  offset_e[rev] = offset;
			  ts_end[rev].secs = tvb_get_ntohl(tvb, offset);
			  ts_end[rev].nsecs = tvb_get_ntohl(tvb, offset + 4) * 1000000;
			}
			/* FALLTHROUGH */
		case 154: /*  flowStartMicroseconds */
		case 155: /*  flowEndMicroseconds */
		        if(type == 154) {
			  offset_s[rev] = offset;
			  ts_start[rev].secs = tvb_get_ntohl(tvb, offset);
			  ts_start[rev].nsecs = tvb_get_ntohl(tvb, offset + 4) * 1000;
			} else if(type == 155) {
			  offset_e[rev] = offset;
			  ts_end[rev].secs = tvb_get_ntohl(tvb, offset);
			  ts_end[rev].nsecs = tvb_get_ntohl(tvb, offset + 4) * 1000;
			}
			/* FALLTHROUGH */
		case 156: /*  flowStartNanoseconds */
		case 157: /*  flowEndNanoseconds */
		        if(type == 156) {
			  offset_s[rev] = offset;
			  ts_start[rev].secs = tvb_get_ntohl(tvb, offset);
			  ts_start[rev].nsecs = tvb_get_ntohl(tvb, offset + 4);
			} else if(type == 157) {
			  offset_e[rev] = offset;
			  ts_end[rev].secs = tvb_get_ntohl(tvb, offset);
			  ts_end[rev].nsecs = tvb_get_ntohl(tvb, offset + 4);
			}
			/* FALLTHROUGH */
		case 158: /*  flowStartDeltaMicroseconds */
		case 159: /*  flowEndDeltaMicroseconds */
			if(type == 158) {
				offset_s[rev] = offset;
			        msec_start[rev] = tvb_get_ntohl(tvb, offset);
				ts_start[rev].secs = msec_start[rev] / 1000000;
				ts_start[rev].nsecs = (msec_start[rev] % 1000000) * 1000000;
			} else if(type == 159) {
				offset_e[rev] = offset;
			        msec_end[rev] = tvb_get_ntohl(tvb, offset);
				ts_end[rev].secs = msec_end[rev] / 1000000;
				ts_end[rev].nsecs = (msec_end[rev] % 1000000) * 1000000;
			}
			/* This code executed for all timestamp fields above */
			if(offset_s[rev] && offset_e[rev]) {
				nstime_delta(&ts_delta, &ts_end[rev], &ts_start[rev]);
				timeitem =
				  proto_tree_add_time(pdutree, hf_cflow_timedelta, tvb,
						      offset_s[rev], 0, &ts_delta);
				PROTO_ITEM_SET_GENERATED(timeitem);
				timetree = proto_item_add_subtree(timeitem, ett_flowtime);
				if (msec_start[rev]) {
				  proto_tree_add_time(timetree, hf_cflow_timestart, tvb,
						      offset_s[rev], length, &ts_start[rev]);
				} else {
				  proto_tree_add_time(timetree, hf_cflow_abstimestart, tvb,
						      offset_s[rev], length, &ts_start[rev]);
				}
				if (msec_end[rev]) {
				  proto_tree_add_time(timetree, hf_cflow_timeend, tvb,
						      offset_e[rev], length, &ts_end[rev]);
				} else {
				  proto_tree_add_time(timetree, hf_cflow_abstimeend, tvb,
						      offset_e[rev], length, &ts_end[rev]);
				}
			}
			break;

		case 23: /* postOctetDeltaCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_octets,
				    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_octets64,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "Post Octets: length %u", length);
			}
		  	break;

		case 24: /* postPacketDeltaCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_packets,
				    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_packets64,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "Post Packets: length %u", length);
			}
			break;

		case 25: /* length_min */
		  	  ti = proto_tree_add_item(pdutree, hf_cflow_length_min,
				      tvb, offset, length, FALSE);
		  	  break;

		case 26: /* length_max */
		  	  ti = proto_tree_add_item(pdutree, hf_cflow_length_max,
				      tvb, offset, length, FALSE);
		  	  break;

		case 27: /* IPv6 src addr */
		  	  ti = proto_tree_add_item(pdutree, hf_cflow_srcaddr_v6,
				      tvb, offset, length, FALSE);
		  	  break;

		case 28: /* IPv6 dst addr */
		  	  ti = proto_tree_add_item(pdutree, hf_cflow_dstaddr_v6,
				      tvb, offset, length, FALSE);
		  	  break;

		case 29: /* IPv6 src addr mask */
		  	  ti = proto_tree_add_item(pdutree, hf_cflow_srcmask_v6,
				      tvb, offset, length, FALSE);
		  	  break;

		case 30: /* IPv6 dst addr mask */
		  	  ti = proto_tree_add_item(pdutree, hf_cflow_dstmask_v6,
				      tvb, offset, length, FALSE);
		  	  break;

		case 31: /* flowLabelIPv6 */
		  /*  RFC5102 defines that Abstract Data Type of this
		      Information Element is unsigned32 */
		  if (length == 4) {
		    ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_flowlabel,
					tvb, offset, length, FALSE);
		  }
		  /* RFC3954 defines that length of this field is 3
		     Bytes */
		  else if (length == 3) {
		    ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_flowlabel24,
					tvb, offset, length, FALSE);
		  }
		  break;

		case 32: /* ICMP_TYPE */
			ti = proto_tree_add_item(pdutree, hf_cflow_icmp_type,
			    tvb, offset, length, FALSE);
			break;

		case 33: /* IGMP_TYPE */
			ti = proto_tree_add_item(pdutree, hf_cflow_igmp_type,
			    tvb, offset, length, FALSE);
			break;

		case 34: /* sampling interval */
		  ti = proto_tree_add_item(pdutree, hf_cflow_sampling_interval,
				      tvb, offset, length, FALSE);
		  break;

		case 35: /* sampling algorithm */
		  ti = proto_tree_add_item(pdutree, hf_cflow_sampling_algorithm,
				      tvb, offset, length, FALSE);
		  break;

		case 36: /* flow active timeout */
		   ti = proto_tree_add_item(pdutree, hf_cflow_flow_active_timeout,
				      tvb, offset, length, FALSE);
		  break;

		case 37: /* flow inactive timeout */
		   ti = proto_tree_add_item(pdutree, hf_cflow_flow_inactive_timeout,
				      tvb, offset, length, FALSE);
		  break;

		case 38: /* engine type */
		   ti = proto_tree_add_item(pdutree, hf_cflow_engine_type,
				      tvb, offset, length, FALSE);
		  break;

		case 39: /* engine id*/
		   ti = proto_tree_add_item(pdutree, hf_cflow_engine_id,
				      tvb, offset, length, FALSE);
		  break;

		case 40: /* bytes exported */
			if( length == 8 ) {
				ti = proto_tree_add_item(pdutree, hf_cflow_octets_exp64,
					      tvb, offset, length, FALSE);
			} else if( length == 4 ) {
				ti = proto_tree_add_item(pdutree, hf_cflow_octets_exp,
					      tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree, tvb, offset, length,
				    "BytesExported: length %u", length);
			}
			break;

		case 41: /* packets exported */
			if( length == 8 ) {
				ti = proto_tree_add_item(pdutree, hf_cflow_packets_exp64,
				    tvb, offset, length, FALSE);
			} else if( length == 4 ) {
				ti = proto_tree_add_item(pdutree, hf_cflow_packets_exp,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree, tvb, offset, length,
				    "PacketsExported: length %u", length);
			}
			break;

		case 42: /* flows exported */
			if( length == 8 ) {
				ti = proto_tree_add_item(pdutree, hf_cflow_flows_exp64,
				    tvb, offset, length, FALSE);
			} else if( length == 4 ) {
				ti = proto_tree_add_item(pdutree, hf_cflow_flows_exp,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree, tvb, offset, length,
				    "FlowsExported: length %u", length);
			}
			break;

		case 44: /* IP source prefix */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_srcprefix,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree, tvb, offset, length,
				    "SrcPrefix: length %u", length);
			}
			break;

		case 45: /* IP destination prefix */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_dstprefix,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree, tvb, offset, length,
				    "DstPrefix: length %u", length);
			}
			break;

		case 46: /* top MPLS label type*/
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_type,
			    tvb, offset, length, FALSE);
			break;

		case 47: /* top MPLS label PE address*/
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_pe_addr,
			    tvb, offset, length, FALSE);
			break;

		case 48: /* Flow Sampler ID */
			ti = proto_tree_add_text(pdutree, tvb, offset, length,
			    "FlowSamplerID: %d", tvb_get_guint8(tvb, offset));
			break;

		case 49: /* FLOW_SAMPLER_MODE  */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampler_mode,
			    tvb, offset, length, FALSE);
			break;

		case 50: /* FLOW_SAMPLER_RANDOM_INTERVAL  */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampler_random_interval,
			    tvb, offset, length, FALSE);
			break;

		case 51: /*  FLOW_CLASS */
			ti = proto_tree_add_item(pdutree, hf_cflow_flow_class,
			    tvb, offset, length, FALSE);
			break;

		case 52: /*  TTL_MINIMUM */
			ti = proto_tree_add_item(pdutree, hf_cflow_ttl_minimum,
			    tvb, offset, length, FALSE);
			break;

		case 53: /*  TTL_MAXIMUM */
			ti = proto_tree_add_item(pdutree, hf_cflow_ttl_maximum,
			    tvb, offset, length, FALSE);
			break;

		case 54: /* IPV4_ID  */
			ti = proto_tree_add_item(pdutree, hf_cflow_ipv4_id,
			    tvb, offset, length, FALSE);
			break;

		case 55: /* postIpClassOfService */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_tos,
			    tvb, offset, length, FALSE);
			break;

		case 56: /* sourceMacAddress */
			ti = proto_tree_add_item(pdutree, hf_cflow_srcmac,
			    tvb, offset, length, FALSE);
			break;

		case 57: /* postDestinationMacAddress */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_dstmac,
			    tvb, offset, length, FALSE);
			break;

		case 58: /* vlanId */
			ti = proto_tree_add_item(pdutree, hf_cflow_vlanid,
			    tvb, offset, length, FALSE);
			break;

		case 59: /* postVlanId */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_vlanid,
			    tvb, offset, length, FALSE);
			break;

		case 60: /* IP_VERSION */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_version,
			    tvb, offset, length, FALSE);
			break;

		case 61: /* DIRECTION   */
			ti = proto_tree_add_item(pdutree, hf_cflow_direction,
			    tvb, offset, length, FALSE);
			break;

		case 62: /* IPV6_NEXT_HOP */
			if (length == 16) {
				ti = proto_tree_add_item(pdutree, hf_cflow_nexthop_v6,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "NextHop: length %u", length);
			}
			break;

		case 63: /* BGP_IPV6_NEXT_HOP */
			if (length == 16) {
				ti = proto_tree_add_item(pdutree, hf_cflow_bgpnexthop_v6,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
				    tvb, offset, length,
				    "BGPNextHop: length %u", length);
			}
			break;

		case 64: /* ipv6ExtensionHeaders */
			ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_exthdr,
			    tvb, offset, length, FALSE);
			break;

		case 70: /* MPLS label1*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 1);
			break;

		case 71: /* MPLS label2*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 2);
			break;

		case 72: /* MPLS label3*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 3);
			break;

		case 73: /* MPLS label4*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 4);
			break;

		case 74: /* MPLS label5*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 5);
			break;

		case 75: /* MPLS label6*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 6);
			break;

		case 76: /* MPLS label7*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 7);
			break;

		case 77: /* MPLS label8*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 8);
			break;

		case 78: /* MPLS label9*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 9);
			break;

		case 79: /* MPLS label10*/
			ti = proto_tree_add_mpls_label(pdutree, tvb, offset, length, 10);
			break;

		case 80: /* destinationMacAddress */
			ti = proto_tree_add_item(pdutree, hf_cflow_dstmac,
			    tvb, offset, length, FALSE);
			break;

		case 81: /* postSourceMacAddress */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_srcmac,
			    tvb, offset, length, FALSE);
			break;

		case 82: /* IF_NAME  */
			ti = proto_tree_add_item(pdutree, hf_cflow_if_name,
			    tvb, offset, length, FALSE);
			break;

		case 83: /* IF_DESCR  */
			ti = proto_tree_add_item(pdutree, hf_cflow_if_descr,
			    tvb, offset, length, FALSE);
			break;

		case 84: /* SAMPLER_NAME  */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampler_name,
			    tvb, offset, length, FALSE);
			break;

                case 88: /* fragmentOffset */
                        ti = proto_tree_add_item(pdutree, hf_cflow_fragment_offset,
					    tvb, offset, length, FALSE);
			break;

		case 89: /* FORWARDING_STATUS */
			/* Forwarding status is encoded on 1 byte with
			 * the 2 left bits giving the status and the 6
			 * remaining bits giving the reason code. */
			ti = proto_tree_add_text(pdutree, tvb, offset, length, "Forwarding Status");
			fwdstattree = proto_item_add_subtree(ti, ett_fwdstat);
			proto_tree_add_item(fwdstattree, hf_cflow_forwarding_status,
 			    tvb, offset, length, FALSE);
			proto_tree_add_item(fwdstattree, hf_cflow_forwarding_code,
			    tvb, offset, length, FALSE);
			break;

                case 90: /* mplsVpnRouteDistinguisher */
                        ti = proto_tree_add_item(pdutree, hf_cflow_mpls_vpn_rd,
					    tvb, offset, length, FALSE);
			break;

		case 91: /* mplsTopLabelPrefixLength */
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_prefix_length,
				tvb, offset, length, FALSE);
			break;

		case 94: /* NBAR applicationDesc */
			ti = proto_tree_add_item(pdutree, hf_cflow_nbar_appl_desc,
					    tvb, offset, length, FALSE);
			break;

		case 95: /* NBAR applicationId */
			ti = proto_tree_add_item(pdutree, hf_cflow_nbar_appl_id,
					    tvb, offset+2, 2, FALSE);
			break;

		case 96: /* NBAR applicationName */
			ti = proto_tree_add_item(pdutree, hf_cflow_nbar_appl_name,
					    tvb, offset, length, FALSE);
			break;

		case 98: /* postIpDiffServCodePoint */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_ip_diff_serv_code_point,
				tvb, offset, length, FALSE);
			break;

		case 99: /* multicastReplicationFactor */
			ti = proto_tree_add_item(pdutree, hf_cflow_multicast_replication_factor,
				tvb, offset, length, FALSE);
			break;

		case 128: /* dest AS Peer */
			ti = proto_tree_add_item(pdutree, hf_cflow_peer_dstas,
			    tvb, offset, length, FALSE);
			break;

		case 129: /* source AS Peer*/
			ti = proto_tree_add_item(pdutree, hf_cflow_peer_srcas,
			    tvb, offset, length, FALSE);
			break;

                case 130: /*  exporterIPv4Address */
			ti = proto_tree_add_item(pdutree, hf_cflow_exporter_addr,
					    tvb, offset, length, FALSE);
			break;

                case 131: /*  exporterIPv6Address */
			ti = proto_tree_add_item(pdutree,
					    hf_cflow_exporter_addr_v6,
					    tvb, offset, length, FALSE);
			break;

		case 132: /*  droppedOctetDeltaCount */
		        if (length == 4) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_drop_octets,
					      tvb, offset, length, FALSE);
			} else if (length == 8) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_drop_octets64,
					      tvb, offset, length, FALSE);
			} else {
			  ti = proto_tree_add_text(pdutree, tvb, offset, length,
					      "Dropped Octets: length %u",
					      length);
			}
			break;

                case 133: /*  droppedPacketDeltaCount */
		        if (length == 4) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_drop_packets,
					      tvb, offset, length, FALSE);
			} else if (length == 8) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_drop_packets64,
					      tvb, offset, length, FALSE);
			} else {
			  ti = proto_tree_add_text(pdutree, tvb, offset, length,
					      "Dropped Packets: length %u",
					      length);
			}
			break;

		case 134: /*  droppedOctetTotalCount */
                        if (length == 4) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_drop_total_octets,
					      tvb, offset, length, FALSE);
			} else if (length == 8) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_drop_total_octets64,
					      tvb, offset, length, FALSE);
			} else {
			  ti = proto_tree_add_text(pdutree, tvb, offset, length,
					      "Dropped Total Octets: length %u", length);
			}
			break;

		case 135: /*  droppedPacketTotalCount */
		        if (length == 4) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_drop_total_packets,
					      tvb, offset, length, FALSE);
			} else if (length == 8) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_drop_total_packets64,
					      tvb, offset, length, FALSE);
			} else {
			  ti = proto_tree_add_text(pdutree, tvb, offset, length,
					      "Dropped Total Packets: length %u", length);
			}
			break;

		case 136: /*  flowEndReason */
		        ti = proto_tree_add_item(pdutree, hf_cflow_flow_end_reason,
					    tvb, offset, length, FALSE);
			break;

		case 137: /*  commonPropertiesId */
                        ti = proto_tree_add_item(pdutree, hf_cflow_common_properties_id,
					    tvb, offset, length, FALSE);
			break;

                case 138: /*  observationPointId */
                        ti = proto_tree_add_item(pdutree, hf_cflow_observation_point_id,
					    tvb, offset, length, FALSE);
			break;

		case 139: /* icmpTypeCodeIPv6 */
			ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv6_type,
			    tvb, offset, 1, FALSE);
			ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv6_code,
			    tvb, offset + 1, 1, FALSE);
			break;

		case 140: /*  mplsTopLabelIPv6Address */
			if (length == 16) {
				ti = proto_tree_add_item(pdutree,
						    hf_cflow_mpls_pe_addr_v6,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree, tvb, offset, length,
						    "mplsTopLabelIPv6Addr: length %u",
						    length);
			}
			break;

		case 141: /*  lineCardId */
			ti = proto_tree_add_item(pdutree, hf_cflow_scope_linecard,
					    tvb, offset, length, FALSE);
			break;

		case 142: /*  portId */
		        ti = proto_tree_add_item(pdutree, hf_cflow_port_id,
					    tvb, offset, length, FALSE);
			break;

                case 143: /*  meteringProcessId */
                        ti = proto_tree_add_item(pdutree, hf_cflow_mp_id,
					    tvb, offset, length, FALSE);
			break;

		case 144: /* FLOW EXPORTER */
			ti = proto_tree_add_item(pdutree, hf_cflow_flow_exporter,
			    tvb, offset, length, FALSE);
			break;

		case 145: /*  templateId */
		        ti = proto_tree_add_item(pdutree, hf_cflow_template_id,
					    tvb, offset, length, FALSE);
			break;

		case 146: /*  wlanChannelId */
		        ti = proto_tree_add_item(pdutree, hf_cflow_wlan_channel_id,
					    tvb, offset, length, FALSE);
			break;

		case 147: /*  wlanSSID */
		        ti = proto_tree_add_item(pdutree, hf_cflow_wlan_ssid,
					    tvb, offset, length, FALSE);
			break;

		case 148: /*  flowId */
		        ti = proto_tree_add_item(pdutree, hf_cflow_flow_id,
					    tvb, offset, length, FALSE);
			break;

		case 149: /*  observationDomainId */
		        ti = proto_tree_add_item(pdutree, hf_cflow_od_id,
					    tvb, offset, length, FALSE);
			break;

		case 160: /*  systemInitTimeMilliseconds */
		        ti = proto_tree_add_item(pdutree, hf_cflow_sysuptime,
					    tvb, offset, length, FALSE);
		        break;

		case 161: /*  flowDurationMilliseconds */
			msec_delta = tvb_get_ntohl(tvb, offset);
			ts_delta.secs = msec_delta / 1000;
			ts_delta.nsecs = (msec_delta % 1000) * 1000000;
			ti = proto_tree_add_time(pdutree, hf_cflow_timedelta, tvb,
					    offset, length, &ts_delta);
		        break;

		case 162: /*  flowDurationMicroseconds */
			msec_delta = tvb_get_ntohl(tvb, offset);
			ts_delta.secs = msec_delta / 1000000;
			ts_delta.nsecs = (msec_delta % 1000000) * 1000000;
			ti = proto_tree_add_time(pdutree, hf_cflow_timedelta, tvb,
					    offset, length, &ts_delta);
		        break;

		case 164: /*  ignoredPacketTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_ignore_packets,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_ignore_packets64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Ignored Packets: length %u", length);
			}
		        break;

		case 165: /*  ignoredOctetTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_ignore_octets,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_ignore_octets64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Ignored Octets: length %u", length);
			}
		        break;

		case 166: /*  notSentFlowTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_notsent_flows,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_notsent_flows64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Not Sent Flows: length %u", length);
			}
		        break;

		case 167: /*  notSentPacketTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_notsent_packets,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_notsent_packets64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Not Sent Packets: length %u", length);
			}
		        break;

		case 168: /*  notSentOctetTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_notsent_packets,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_notsent_packets64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Not Sent Packets: length %u", length);
			}
		        break;

 		case 169: /* destinationIPv6Prefix */
 			if (length == 16) {
 				ti = proto_tree_add_item(pdutree, hf_cflow_dstnet_v6,
						    tvb, offset, length, FALSE);
			} else {
 				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "DstPrefix: length %u", length);
 			}
 			break;

		case 170: /* sourceIPv6Prefix */
			if (length == 16) {
				ti = proto_tree_add_item(pdutree, hf_cflow_srcnet_v6,
						    tvb, offset, length, FALSE);
			} else if (length != 4 && length != 16) {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "SrcPrefix: length %u", length);
			}
			break;

		case 171: /* postOctetTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_total_octets,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_total_octets64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Post Total Octets: length %u", length);
			}
			break;

		case 172: /* postPacketTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_total_packets,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_total_packets64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Post Total Packets: length %u", length);
			}
			break;

		case 173: /* flowKeyIndicator */
		        ti = proto_tree_add_item(pdutree, hf_cflow_key,
					    tvb, offset, length, FALSE);
			break;

		case 174: /* postMCastPacketTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_total_mulpackets,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_total_mulpackets64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Post Total Multicast Packets: length %u", length);
			}
			break;

		case 175: /* postMCastOctetTotalCount */
			if (length == 4) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_total_muloctets,
						    tvb, offset, length, FALSE);
			} else if (length == 8) {
				ti = proto_tree_add_item(pdutree, hf_cflow_post_total_muloctets64,
						    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree,
						    tvb, offset, length,
						    "Post Total Multicast Octets: length %u", length);
			}
			break;

		case 176: /* ICMP_IPv4_TYPE */
			ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv4_type,
			    tvb, offset, length, FALSE);
			break;

		case 177: /* ICMP_IPv4_CODE */
			ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv4_code,
			    tvb, offset, length, FALSE);
			break;

		case 178: /* ICMP_IPv6_TYPE */
			ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv6_type,
			    tvb, offset, length, FALSE);
			break;

		case 179: /* ICMP_IPv6_CODE */
			ti = proto_tree_add_item(pdutree, hf_cflow_icmp_ipv6_code,
			    tvb, offset, length, FALSE);
			break;

		case 184: /* tcpSequenceNumber */
			ti = proto_tree_add_item(pdutree, hf_cflow_tcp_seq_num,
			    tvb, offset, length, FALSE);
			break;

		case 185: /* tcpAcknowledgementNumber */
			ti = proto_tree_add_item(pdutree, hf_cflow_tcp_ack_num,
			    tvb, offset, length, FALSE);
			break;

		case 186: /* TCP_WINDOWS_SIZE */
			ti = proto_tree_add_item(pdutree, hf_cflow_tcp_window_size,
			    tvb, offset, length, FALSE);
			break;

		case 187: /* tcpUrgentPointer */
			ti = proto_tree_add_item(pdutree, hf_cflow_tcp_urg_ptr,
			    tvb, offset, length, FALSE);
			break;

		case 188: /* tcpHeaderLength */
			ti = proto_tree_add_item(pdutree, hf_cflow_tcp_header_length,
			    tvb, offset, length, FALSE);
			break;

		case 189: /* ipHeaderLength */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_header_length,
			    tvb, offset, length, FALSE);
			break;

		case 190: /* IP_TOTAL_LENGTH */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_total_length,
			    tvb, offset, length, FALSE);
			break;

		case 191: /* payloadLengthIPv6 */
			ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_payload_length,
					    tvb, offset, length, FALSE);
			break;

		case 192: /* IP_TTL */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_ttl,
			    tvb, offset, length, FALSE);
			break;

		case 193: /* nextHeaderIPv6 */
			ti = proto_tree_add_item(pdutree, hf_cflow_ipv6_next_hdr,
					    tvb, offset, length, FALSE);
			break;

		case 194: /* IP_TOS */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_tos,
			    tvb, offset, length, FALSE);
			break;

		case 195: /* IP_DSCP */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_dscp,
			    tvb, offset, length, FALSE);
			break;

		case 196: /* ipPrecedence */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_precedence,
					    tvb, offset, length, FALSE);
			break;

		case 197: /* fragmentFlags */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_fragment_flags,
					    tvb, offset, length, FALSE);
			break;

		case 198: /* BYTES_SQUARED */
		case 199: /* BYTES_SQUARED_PERMANENT */
			if( length == 8 ) {
				ti = proto_tree_add_item(pdutree, hf_cflow_octets_squared64,
				    tvb, offset, length, FALSE);
			} else {
				ti = proto_tree_add_text(pdutree, tvb, offset, length,
				    "Bytes Squared: length %u", length);
			}
			break;
		case 200: /* mplsTopLabelTTL */
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_ttl,
					    tvb, offset, length, FALSE);
			break;

		case 201: /* mplsLabelStackLength */
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_label_length,
					    tvb, offset, length, FALSE);
			break;

		case 202: /* mplsLabelStackDepth */
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_label_depth,
					    tvb, offset, length, FALSE);
			break;

		case 203: /* mplsTopLabelExp */
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_top_label_exp,
					    tvb, offset, length, FALSE);
			break;

		case 204: /* ipPayloadLength */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_payload_length,
					    tvb, offset, length, FALSE);
			break;

		case 205: /* UDP_LENGTH */
			ti = proto_tree_add_item(pdutree, hf_cflow_udp_length,
					    tvb, offset, length, FALSE);
			break;

		case 206: /* IS_MULTICAST */
			ti = proto_tree_add_item(pdutree, hf_cflow_is_multicast,
					    tvb, offset, length, FALSE);
			break;

		case 207: /* IP_HEADER_WORDS */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_header_words,
					    tvb, offset, length, FALSE);
			break;

		case 208: /* OPTION_MAP */
			ti = proto_tree_add_item(pdutree, hf_cflow_option_map,
					    tvb, offset, length, FALSE);
			break;

		case 209: /* tcpOptions */
			ti = proto_tree_add_item(pdutree, hf_cflow_tcp_option_map,
					    tvb, offset, length, FALSE);
			break;

		case 210: /* paddingOctets */
			ti = proto_tree_add_text(pdutree, tvb, offset, length,
					    "Padding (%u byte%s)",
					    length, plurality(length, "", "s"));
			break;

		case 211: /* collectorIPv4Address */
			ti = proto_tree_add_item(pdutree, hf_cflow_collector_addr,
					    tvb, offset, length, FALSE);
			break;

		case 212: /* collectorIPv6Address */
			ti = proto_tree_add_item(pdutree, hf_cflow_collector_addr_v6,
					    tvb, offset, length, FALSE);
			break;

		case 213: /* exportInterface */
		        if (length == 4) {
			  ti = proto_tree_add_item(pdutree, hf_cflow_export_interface,
					      tvb, offset, length, FALSE);
			} else {
			  ti = proto_tree_add_text(pdutree,
					      tvb, offset, length,
					      "exportInterface: invalid size %d", length );
			}
			break;

		case 214: /* exportProtocolVersion */
			ti = proto_tree_add_item(pdutree, hf_cflow_export_protocol_version,
			    tvb, offset, length, FALSE);
			break;

		case 215: /* exportTransportProtocol */
			ti = proto_tree_add_item(pdutree, hf_cflow_export_prot,
			    tvb, offset, length, FALSE);
			break;

		case 216: /* collectorTransportPort */
			ti = proto_tree_add_item(pdutree, hf_cflow_collector_port,
			    tvb, offset, length, FALSE);
			break;

		case 217: /* exporterTransportPort */
			ti = proto_tree_add_item(pdutree, hf_cflow_exporter_port,
			    tvb, offset, length, FALSE);
			break;

		case 218: /* tcpSynTotalCount */
			 ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_syn,
					     tvb, offset, length, FALSE);
		         break;

		case 219: /* tcpFinTotalCount */
			 ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_fin,
					     tvb, offset, length, FALSE);
		         break;

		case 220: /* tcpRstTotalCount */
			 ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_rst,
					     tvb, offset, length, FALSE);
		         break;

		case 221: /* tcpPshTotalCount */
			 ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_psh,
					     tvb, offset, length, FALSE);
		         break;

		case 222: /* tcpAckTotalCount */
			 ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_ack,
					     tvb, offset, length, FALSE);
		         break;

		case 223: /* tcpUrgTotalCount */
			 ti = proto_tree_add_item(pdutree, hf_cflow_total_tcp_urg,
					     tvb, offset, length, FALSE);
		         break;

		case 224: /* IP_TOTAL_LENGTH */
			ti = proto_tree_add_item(pdutree, hf_cflow_ip_total_length64,
			    tvb, offset, length, FALSE);
			break;

		case 225: /* postNATSourceIPv4Address */
		case 40001: /* NF_F_XLATE_SRC_ADDR_IPV4 (Cisco ASA 5500 Series) */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_natsource_ipv4_address,
				tvb, offset, length, FALSE);
			break;

		case 226: /* postNATDestinationIPv4Address */
		case 40002: /* NF_F_XLATE_DST_ADDR_IPV4 (Cisco ASA 5500 Series) */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_natdestination_ipv4_address,
				tvb, offset, length, FALSE);
			break;

		case 227: /* postNAPTSourceTransportPort */
		case 40003: /* NF_F_XLATE_SRC_PORT (Cisco ASA 5500 Series) */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_naptsource_transport_port,
				tvb, offset, length, FALSE);
			break;

		case 228: /* postNAPTDestinationTransportPort */
		case 40004: /* NF_F_XLATE_DST_PORT (Cisco ASA 5500 Series) */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_naptdestination_transport_port,
				tvb, offset, length, FALSE);
			break;

		case 229: /* natOriginatingAddressRealm */
			ti = proto_tree_add_item(pdutree, hf_cflow_nat_originating_address_realm,
				tvb, offset, length, FALSE);
			break;

		case 230: /* natEvent */
			ti = proto_tree_add_item(pdutree, hf_cflow_nat_event,
				tvb, offset, length, FALSE);
			break;

		case 231: /* initiatorOctets */
			ti = proto_tree_add_item(pdutree, hf_cflow_initiator_octets,
				tvb, offset, length, FALSE);
			break;

		case 232: /* responderOctets */
			ti = proto_tree_add_item(pdutree, hf_cflow_responder_octets,
				tvb, offset, length, FALSE);
			break;

		case 233: /* firewallEvent */
		case 40005: /* NF_F_FW_EVENT (Cisco ASA 5500 Series) */
			ti = proto_tree_add_item(pdutree, hf_cflow_firewall_event,
				tvb, offset, length, FALSE);
			break;

		case 234: /* ingressVRFID */
			ti = proto_tree_add_item(pdutree, hf_cflow_ingress_vrfid,
				tvb, offset, length, FALSE);
			break;

		case 235: /* egressVRFID */
			ti = proto_tree_add_item(pdutree, hf_cflow_egress_vrfid,
				tvb, offset, length, FALSE);
			break;

		case 236: /* VRFname */
			ti = proto_tree_add_item(pdutree, hf_cflow_vrfname,
				tvb, offset, length, FALSE);
			break;

		case 237: /* postMplsTopLabelExp */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_mpls_top_label_exp,
				tvb, offset, length, FALSE);
		  break;

		case 238: /* tcpWindowScale */
			ti = proto_tree_add_item(pdutree, hf_cflow_tcp_window_scale,
				tvb, offset, length, FALSE);
		  break;

		case 239: /*  biflowDirection */
		        ti = proto_tree_add_item(pdutree, hf_cflow_biflow_direction,
					    tvb, offset, length, FALSE);
			break;

		case 240: /* ethernetHeaderLength */
			ti = proto_tree_add_item(pdutree, hf_cflow_ethernet_header_length,
				tvb, offset, length, FALSE);
			break;

		case 241: /* ethernetPayloadLength */
			ti = proto_tree_add_item(pdutree, hf_cflow_ethernet_payload_length,
				tvb, offset, length, FALSE);
			break;

		case 242: /* ethernetTotalLength */
			ti = proto_tree_add_item(pdutree, hf_cflow_ethernet_total_length,
				tvb, offset, length, FALSE);
			break;

		case 243: /* dot1qVlanId */
			ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_vlan_id,
				tvb, offset, length, FALSE);
			break;

		case 244: /* dot1qPriority */
			ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_priority,
				tvb, offset, length, FALSE);
			break;

		case 245: /* dot1qCustomerVlanId */
			ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_customer_vlan_id,
				tvb, offset, length, FALSE);
			break;

		case 246: /* dot1qCustomerPriority */
			ti = proto_tree_add_item(pdutree, hf_cflow_dot1q_customer_priority,
				tvb, offset, length, FALSE);
			break;

		case 247: /* metroEvcId */
			ti = proto_tree_add_item(pdutree, hf_cflow_metro_evc_id,
				tvb, offset, length, FALSE);
			break;

		case 248: /* metroEvcType */
			ti = proto_tree_add_item(pdutree, hf_cflow_metro_evc_type,
				tvb, offset, length, FALSE);
			break;

		case 249: /* pseudoWireId */
			ti = proto_tree_add_item(pdutree, hf_cflow_pseudo_wire_id,
				tvb, offset, length, FALSE);
			break;

		case 250: /* pseudoWireType */
			ti = proto_tree_add_item(pdutree, hf_cflow_pseudo_wire_type,
				tvb, offset, length, FALSE);
			break;

		case 251: /* pseudoWireControlWord */
			ti = proto_tree_add_item(pdutree, hf_cflow_pseudo_wire_control_word,
				tvb, offset, length, FALSE);
			break;

		case 252: /* ingressPhysicalInterface */
			ti = proto_tree_add_item(pdutree, hf_cflow_ingress_physical_interface,
				tvb, offset, length, FALSE);
			break;

		case 253: /* egressPhysicalInterface */
			ti = proto_tree_add_item(pdutree, hf_cflow_egress_physical_interface,
				tvb, offset, length, FALSE);
			break;

		case 254: /* postDot1qVlanId */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_dot1q_vlan_id,
				tvb, offset, length, FALSE);
			break;

		case 255: /* postDot1qCustomerVlanId */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_dot1q_customer_vlan_id,
				tvb, offset, length, FALSE);
			break;

		case 256: /* ethernetType */
			ti = proto_tree_add_item(pdutree, hf_cflow_ethernet_type,
				tvb, offset, length, FALSE);
			break;

		case 257: /* postIpPrecedence */
			ti = proto_tree_add_item(pdutree, hf_cflow_post_ip_precedence,
				tvb, offset, length, FALSE);
			break;

		case 258: /* collectionTimeMilliseconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
			ti = proto_tree_add_time(pdutree,
					       hf_cflow_collection_time_milliseconds,
					       tvb, offset, length, &ts);
			break;

		case 259: /* exportSctpStreamId */
			ti = proto_tree_add_item(pdutree, hf_cflow_export_sctp_stream_id,
				tvb, offset, length, FALSE);
			break;

		case 260: /* maxExportSeconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = 0;
			ti = proto_tree_add_time(pdutree, hf_cflow_max_export_seconds,
				tvb, offset, length, &ts);
			break;

		case 261: /* maxFlowEndSeconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = 0;
			ti = proto_tree_add_time(pdutree, hf_cflow_max_flow_end_seconds,
				tvb, offset, length, &ts);
			break;

		case 262: /* messageMD5Checksum */
			ti = proto_tree_add_item(pdutree, hf_cflow_message_md5_checksum,
				tvb, offset, length, FALSE);
			break;

		case 263: /* messageScope */
			ti = proto_tree_add_item(pdutree, hf_cflow_message_scope,
				tvb, offset, length, FALSE);
			break;

		case 264: /* minExportSeconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = 0;
			ti = proto_tree_add_time(pdutree, hf_cflow_min_export_seconds,
				tvb, offset, length, &ts);
			break;

		case 265: /* minFlowStartSeconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = 0;
			ti = proto_tree_add_time(pdutree, hf_cflow_min_flow_start_seconds,
				tvb, offset, length, &ts);
			break;

		case 266: /* opaqueOctets */
			ti = proto_tree_add_item(pdutree, hf_cflow_opaque_octets,
				tvb, offset, length, FALSE);
			break;

		case 267: /* sessionScope */
			ti = proto_tree_add_item(pdutree, hf_cflow_session_scope,
				tvb, offset, length, FALSE);
			break;

		case 268: /* maxFlowEndMicroseconds */
			reftime = tvb_get_ptr(tvb, offset, 8);
			ti = proto_tree_add_bytes_format_value(pdutree, hf_cflow_max_flow_end_microseconds,
				tvb, offset, length, reftime, "%s", ntp_fmt_ts(reftime));
			break;

		case 269: /* maxFlowEndMilliseconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
			ti = proto_tree_add_time(pdutree, hf_cflow_max_flow_end_milliseconds,
				tvb, offset, length, &ts);
			break;

		case 270: /* maxFlowEndNanoseconds */
			reftime = tvb_get_ptr(tvb, offset, 8);
			ti = proto_tree_add_bytes_format_value(pdutree, hf_cflow_max_flow_end_nanoseconds,
				tvb, offset, length, reftime, "%s", ntp_fmt_ts(reftime));
			break;

		case 271: /* minFlowStartMicroseconds */
			reftime = tvb_get_ptr(tvb, offset, 8);
			ti = proto_tree_add_bytes_format_value(pdutree, hf_cflow_min_flow_start_microseconds,
				tvb, offset, length, reftime, "%s", ntp_fmt_ts(reftime));
			break;

		case 272: /* minFlowStartMilliseconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
			ti = proto_tree_add_time(pdutree, hf_cflow_min_flow_start_milliseconds,
				tvb, offset, length, &ts);
			break;

		case 273: /* minFlowStartNanoseconds */
			reftime = tvb_get_ptr(tvb, offset, 8);
			ti = proto_tree_add_bytes_format_value(pdutree, hf_cflow_min_flow_start_nanoseconds,
				tvb, offset, length, reftime, "%s", ntp_fmt_ts(reftime));
			break;

		case 274: /* collectorCertificate */
			ti = proto_tree_add_item(pdutree, hf_cflow_collector_certificate,
				tvb, offset, length, FALSE);
			break;

		case 275: /* exporterCertificate */
			ti = proto_tree_add_item(pdutree, hf_cflow_exporter_certificate,
				tvb, offset, length, FALSE);
			break;

		case 301: /* selectionSequenceId */
			ti = proto_tree_add_item(pdutree, hf_cflow_selection_sequence_id,
				tvb, offset, length, FALSE);
			break;

		case 302: /* selectorId */
			ti = proto_tree_add_item(pdutree, hf_cflow_selector_id,
				tvb, offset, length, FALSE);
			break;

		case 303: /* informationElementId */
			ti = proto_tree_add_item(pdutree, hf_cflow_information_element_id,
				tvb, offset, length, FALSE);
			break;

		case 304: /* selectorAlgorithm */
			ti = proto_tree_add_item(pdutree, hf_cflow_selector_algorithm,
				tvb, offset, length, FALSE);
			break;

		case 305: /* samplingPacketInterval */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampling_packet_interval,
				tvb, offset, length, FALSE);
			break;

		case 306: /* samplingPacketSpace */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampling_packet_space,
				tvb, offset, length, FALSE);
			break;

		case 307: /* samplingTimeInterval */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampling_time_interval,
				tvb, offset, length, FALSE);
			break;

		case 308: /* samplingTimeSpace */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampling_time_space,
				tvb, offset, length, FALSE);
			break;

		case 309: /* samplingSize */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampling_size,
				tvb, offset, length, FALSE);
			break;

		case 310: /* samplingPopulation */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampling_population,
				tvb, offset, length, FALSE);
			break;

		case 311: /* samplingProbability */
			ti = proto_tree_add_item(pdutree, hf_cflow_sampling_probability,
				tvb, offset, length, FALSE);
			break;

		case 313: /* SECTION_HEADER */
			ti = proto_tree_add_item(pdutree, hf_cflow_section_header,
					    tvb, offset, length, FALSE);
			break;

		case 314: /* SECTION_PAYLOAD */
			ti = proto_tree_add_item(pdutree, hf_cflow_section_payload,
					    tvb, offset, length, FALSE);
			break;

		case 316: /* mplsLabelStackSection */
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_label_stack_section,
				tvb, offset, length, FALSE);
			break;

		case 317: /* mplsPayloadPacketSection */
			ti = proto_tree_add_item(pdutree, hf_cflow_mpls_payload_packet_section,
				tvb, offset, length, FALSE);
			break;

		case 318: /* selectorIdTotalPktsObserved */
			ti = proto_tree_add_item(pdutree, hf_cflow_selector_id_total_pkts_observed,
				tvb, offset, length, FALSE);
			break;

		case 319: /* selectorIdTotalPktsSelected */
			ti = proto_tree_add_item(pdutree, hf_cflow_selector_id_total_pkts_selected,
				tvb, offset, length, FALSE);
			break;

		case 320: /* absoluteError */
			ti = proto_tree_add_item(pdutree, hf_cflow_absolute_error,
				tvb, offset, length, FALSE);
			break;

		case 321: /* relativeError */
			ti = proto_tree_add_item(pdutree, hf_cflow_relative_error,
				tvb, offset, length, FALSE);
			break;

		case 322: /* observationTimeSeconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = 0;
			ti = proto_tree_add_time(pdutree, hf_cflow_observation_time_seconds,
				tvb, offset, length, &ts);
			break;

		case 323: /* observationTimeMilliseconds */
			ts.secs = tvb_get_ntohl(tvb, offset);
			ts.nsecs = tvb_get_ntohl(tvb, offset + 4);
			ti = proto_tree_add_time(pdutree, hf_cflow_observation_time_milliseconds,
				tvb, offset, length, &ts);
			break;

		case 324: /* observationTimeMicroseconds */
			reftime = tvb_get_ptr(tvb, offset, 8);
			ti = proto_tree_add_bytes_format_value(pdutree, hf_cflow_observation_time_microseconds,
				tvb, offset, length, reftime, "%s", ntp_fmt_ts(reftime));
			break;

		case 325: /* observationTimeNanoseconds */
			reftime = tvb_get_ptr(tvb, offset, 8);
			ti = proto_tree_add_bytes_format_value(pdutree, hf_cflow_observation_time_nanoseconds,
				tvb, offset, length, reftime, "%s", ntp_fmt_ts(reftime));
			break;

		case 326: /* digestHashValue */
			ti = proto_tree_add_item(pdutree, hf_cflow_digest_hash_value,
				tvb, offset, length, FALSE);
			break;

		case 327: /* hashIPPayloadOffset */
			ti = proto_tree_add_item(pdutree, hf_cflow_hash_ippayload_offset,
				tvb, offset, length, FALSE);
			break;

		case 328: /* hashIPPayloadSize */
			ti = proto_tree_add_item(pdutree, hf_cflow_hash_ippayload_size,
				tvb, offset, length, FALSE);
			break;

		case 329: /* hashOutputRangeMin */
			ti = proto_tree_add_item(pdutree, hf_cflow_hash_output_range_min,
				tvb, offset, length, FALSE);
			break;

		case 330: /* hashOutputRangeMax */
			ti = proto_tree_add_item(pdutree, hf_cflow_hash_output_range_max,
				tvb, offset, length, FALSE);
			break;

		case 331: /* hashSelectedRangeMin */
			ti = proto_tree_add_item(pdutree, hf_cflow_hash_selected_range_min,
				tvb, offset, length, FALSE);
			break;

		case 332: /* hashSelectedRangeMax */
			ti = proto_tree_add_item(pdutree, hf_cflow_hash_selected_range_max,
				tvb, offset, length, FALSE);
			break;

		case 333: /* hashDigestOutput */
			ti = proto_tree_add_item(pdutree, hf_cflow_hash_digest_output,
				tvb, offset, length, FALSE);
			break;

		case 334: /* hashInitialiserValue */
			ti = proto_tree_add_item(pdutree, hf_cflow_hash_initialiser_value,
				tvb, offset, length, FALSE);
			break;

		case 335: /* selectorName */
			ti = proto_tree_add_item(pdutree, hf_cflow_selector_name,
				tvb, offset, length, FALSE);
			break;

		case 336: /* upperCILimit */
			ti = proto_tree_add_item(pdutree, hf_cflow_upper_cilimit,
				tvb, offset, length, FALSE);
			break;

		case 337: /* lowerCILimit */
			ti = proto_tree_add_item(pdutree, hf_cflow_lower_cilimit,
				tvb, offset, length, FALSE);
			break;

		case 338: /* confidenceLevel */
			ti = proto_tree_add_item(pdutree, hf_cflow_confidence_level,
				tvb, offset, length, FALSE);
			break;

		case 339: /* informationElementDataType */
			ti = proto_tree_add_item(pdutree, hf_cflow_information_element_data_type,
				tvb, offset, length, FALSE);
			break;

		case 340: /* informationElementDescription */
			ti = proto_tree_add_item(pdutree, hf_cflow_information_element_description,
				tvb, offset, length, FALSE);
			break;

		case 341: /* informationElementName */
			ti = proto_tree_add_item(pdutree, hf_cflow_information_element_name,
				tvb, offset, length, FALSE);
			break;

		case 342: /* informationElementRangeBegin */
			ti = proto_tree_add_item(pdutree, hf_cflow_information_element_range_begin,
				tvb, offset, length, FALSE);
			break;

		case 343: /* informationElementRangeEnd */
			ti = proto_tree_add_item(pdutree, hf_cflow_information_element_range_end,
				tvb, offset, length, FALSE);
			break;

		case 344: /* informationElementSemantics */
			ti = proto_tree_add_item(pdutree, hf_cflow_information_element_semantics,
				tvb, offset, length, FALSE);
			break;

		case 345: /* informationElementUnits */
			ti = proto_tree_add_item(pdutree, hf_cflow_information_element_units,
				tvb, offset, length, FALSE);
			break;

		case 346: /* privateEnterpriseNumber */
			ti = proto_tree_add_item(pdutree, hf_cflow_private_enterprise_number,
				tvb, offset, length, FALSE);
			break;

		/* Cisco ASA 5500 Series */
		case 33000: /* NF_F_INGRESS_ACL_ID */
			proto_tree_add_item(pdutree, hf_cflow_ingress_acl_id,
				tvb, offset, length, FALSE);
			break;
		case 33001: /* NF_F_EGRESS_ACL_ID */
			proto_tree_add_item(pdutree, hf_cflow_egress_acl_id,
				tvb, offset, length, FALSE);
			break;
		case 33002: /* NF_F_FW_EXT_EVENT */
			proto_tree_add_item(pdutree, hf_cflow_fw_ext_event,
				tvb, offset, length, FALSE);
			break;
		case 40000: /* NF_F_USERNAME[_MAX] */
			proto_tree_add_item(pdutree, hf_cflow_aaa_username,
				tvb, offset, length, FALSE);
			break;

                /* CACE Technologies */
		case VENDOR_CACE << 16 | 0: /* caceLocalIPv4Address */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_local_ipv4_address,
					    tvb, offset, length, FALSE);
                        SET_ADDRESS(&local_addr, AT_IPv4, 4, tvb_get_ptr(tvb, offset, 4));
                        got_flags |= GOT_LOCAL_ADDR;
			break;

		case VENDOR_CACE << 16 | 1: /* caceRemoteIPv4Address */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_remote_ipv4_address,
					    tvb, offset, length, FALSE);
                        SET_ADDRESS(&remote_addr, AT_IPv4, 4, tvb_get_ptr(tvb, offset, 4));
                        got_flags |= GOT_REMOTE_ADDR;
			break;

		case VENDOR_CACE << 16 | 2: /* caceLocalIPv6Address */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_local_ipv6_address,
					    tvb, offset, length, FALSE);
                        SET_ADDRESS(&local_addr, AT_IPv6, 16, tvb_get_ptr(tvb, offset, 16));
                        got_flags |= GOT_LOCAL_ADDR;
			break;

		case VENDOR_CACE << 16 | 3: /* caceRemoteIPv6Address */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_remote_ipv6_address,
					    tvb, offset, length, FALSE);
                        SET_ADDRESS(&remote_addr, AT_IPv6, 16, tvb_get_ptr(tvb, offset, 16));
                        got_flags |= GOT_REMOTE_ADDR;
			break;

		case VENDOR_CACE << 16 | 4: /* caceLocalTransportPort */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_local_port,
					    tvb, offset, length, FALSE);
                        local_port = tvb_get_ntohs(tvb, offset);
                        got_flags |= GOT_LOCAL_PORT;
			break;

		case VENDOR_CACE << 16 | 5: /* caceRemoteTransportPort */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_remote_port,
					    tvb, offset, length, FALSE);
                        remote_port = tvb_get_ntohs(tvb, offset);
                        got_flags |= GOT_REMOTE_PORT;
			break;

		case VENDOR_CACE << 16 | 6: /* caceLocalIPv4id */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_local_ipv4_id,
					    tvb, offset, length, FALSE);
                        ipv4_id = tvb_get_ntohs(tvb, offset);
                        got_flags |= GOT_IPv4_ID;
			break;

		case VENDOR_CACE << 16 | 7: /* caceLocalICMPid */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_local_icmp_id,
					    tvb, offset, length, FALSE);
                        icmp_id = tvb_get_ntohs(tvb, offset);
                        got_flags |= GOT_ICMP_ID;
			break;

		case VENDOR_CACE << 16 | 8: /* caceLocalProcessUserId */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_local_uid,
					    tvb, offset, length, FALSE);
                        uid = tvb_get_ntohl(tvb, offset);
                        got_flags |= GOT_UID;
			break;

		case VENDOR_CACE << 16 | 9: /* caceLocalProcessId */
			ti = proto_tree_add_item(pdutree, hf_pie_cace_local_pid,
					    tvb, offset, length, FALSE);
                        pid = tvb_get_ntohl(tvb, offset);
                        got_flags |= GOT_PID;
			break;

		case VENDOR_CACE << 16 | 10: /* caceLocalProcessUserName */
                        uname_len = tvb_get_guint8(tvb, offset);
                        uname_str = tvb_format_text(tvb, offset+1, uname_len);
			proto_tree_add_item(pdutree, hf_pie_cace_local_username_len,
					    tvb, offset, 1, FALSE);
			ti = proto_tree_add_string(pdutree, hf_pie_cace_local_username,
					    tvb, offset+1, uname_len, uname_str);
                        length = uname_len + 1;
                        got_flags |= GOT_USERNAME;
			break;

		case VENDOR_CACE << 16 | 11: /* caceLocalProcessCommand */
                        cmd_len = tvb_get_guint8(tvb, offset);
                        cmd_str = tvb_format_text(tvb, offset+1, cmd_len);
			proto_tree_add_item(pdutree, hf_pie_cace_local_cmd_len,
					    tvb, offset, 1, FALSE);
			ti = proto_tree_add_string(pdutree, hf_pie_cace_local_cmd,
					    tvb, offset+1, cmd_len, cmd_str);
                        length = cmd_len + 1;
                        got_flags |= GOT_COMMAND;
			break;

		default:
			if (!length) {
				vstr_len = tvb_get_guint8(tvb, offset);
				if (vstr_len == 255) {
					vstr_long = TRUE;
					vstr_len = tvb_get_ntohs(tvb, offset+1);
				} else { vstr_long = FALSE; }
				length = vstr_len + (vstr_long?1+2:1);
			}
			if ((type & 0x8000) && (pen != REVPEN))
				ti = proto_tree_add_text(pdutree, tvb, offset, length,
							 "(%s) Type %u ",
							 match_strval(pen, sminmpec_values),
							 pen > 0 ? type & 0x7fff : type);
			break;
		}
		if (ti && pen == REVPEN) {
			proto_item_append_text(ti, " (Reverse Type %u %s)",
					       type & 0x7fff, decode_v9_template_types(type));
		}

		offset += length;
	}
	for (i = 0; i < 2; i++) {
		if (!(offset_s[i] && offset_e[i])) {
			if (offset_s[i]) {
				if (msec_start[i]) {
					proto_tree_add_time(pdutree, hf_cflow_timestart, tvb,
							    offset_s[i], 4, &ts_start[i]);
				} else {
					proto_tree_add_time(pdutree, hf_cflow_abstimestart, tvb,
							    offset_s[i], 4, &ts_start[i]);
				}
			}
			if (offset_e[i]) {
				if (msec_end[i]) {
					proto_tree_add_time(pdutree, hf_cflow_timeend, tvb,
							    offset_e[i], 4, &ts_end[i]);
				} else {
					proto_tree_add_time(pdutree, hf_cflow_abstimeend, tvb,
							    offset_s[i], 4, &ts_start[i]);
				}
			}
		}
	}

        /* XXX - These IDs are currently hard-coded in procflow.py. */
        if (got_flags == GOT_TCP_UDP && (tplt->id == 256 || tplt->id == 258)) {
                add_tcp_process_info(pinfo->fd->num, &local_addr, &remote_addr, local_port, remote_port, uid, pid, uname_str, cmd_str);
        }
        if (got_flags == GOT_TCP_UDP && (tplt->id == 257 || tplt->id == 259)) {
                add_udp_process_info(pinfo->fd->num, &local_addr, &remote_addr, local_port, remote_port, uid, pid, uname_str, cmd_str);
        }

        return (guint) (offset - orig_offset);

}

static int
dissect_v9_options_template(tvbuff_t *tvb, packet_info *pinfo, proto_tree *pdutree, int offset, hdrinfo_t *hdrinfo, guint16 flowset_id)
{
	guint16 option_scope_len, option_len, i, id, len;
	guint16 type;
	struct v9_template tplt;
	int tplt_offset;
	int scopes_offset;
	proto_item *ti;

	/* *** CAUTION CAUTION CAUTION CAUTION CAUTION CAUTION CAUTION ***

	   The names option_len and option_scope_len are used in
	   reverse when this function is called for IPFIX.

	   *** CAUTION CAUTION CAUTION CAUTION CAUTION CAUTION CAUTION *** */

	id = tvb_get_ntohs(tvb, offset);
	proto_tree_add_item(pdutree, hf_cflow_template_id, tvb,
			    offset, 2, FALSE);
	offset += 2;

	option_scope_len = tvb_get_ntohs(tvb, offset); /* IPFIX field count */
	proto_tree_add_item(pdutree,
			    flowset_id == 3? hf_cflow_field_count : hf_cflow_option_scope_length,
			    tvb, offset, 2, FALSE);
	offset += 2;

	option_len = tvb_get_ntohs(tvb, offset); /* IPFIX scope field count */
	ti = proto_tree_add_item(pdutree,
				 flowset_id == 3? hf_cflow_scope_field_count : hf_cflow_option_length,
				 tvb, offset, 2, FALSE);
	offset += 2;

	if (flowset_id == 3) { /* IPFIX */
		if (option_len > option_scope_len) {
			expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN,
					       "More scope fields (%u) than fields (%u)",
					       option_len, option_scope_len);
			return 0;
		}

		if (option_len == 0) {
			expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_WARN,
					       "No scope fields");
			return 0;
		}

		option_scope_len -= option_len;
	}

	if (option_len > V9TEMPLATE_MAX_FIELDS) {
		expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE,
				       "More options (%u) than we can handle",
				       option_len);
	}

	if (option_scope_len > V9TEMPLATE_MAX_FIELDS) {
		expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE,
				       "More scopes (%u) than we can handle",
				       option_scope_len);
	}

	scopes_offset = offset;

	/* Cache template */
	memset(&tplt, 0, sizeof(tplt));
	tplt.id = id;
	tplt.count = flowset_id == 1 ? 0 : option_scope_len;

	SE_COPY_ADDRESS(&tplt.source_addr, &hdrinfo->net_src);
	tplt.source_id = hdrinfo->src_id;
	/* Option scopes */
	tplt.option_template = TRUE; /* Option template */
	tplt.count_scopes = flowset_id == 1 ? 0 : option_len;
	if (!v9_template_get(id, &hdrinfo->net_src, hdrinfo->src_id) && option_len && option_scope_len && option_len <= V9TEMPLATE_MAX_FIELDS && option_scope_len <= V9TEMPLATE_MAX_FIELDS) {
		tplt.scopes = se_alloc0(option_scope_len * sizeof(struct v9_template_entry));
		tplt.entries = se_alloc0(option_len * sizeof(struct v9_template_entry));
	}

	for(i=0, len = 0;
	    flowset_id == 1 ? len < option_scope_len : i < tplt.count_scopes;
	    i++) {
		guint16 scope_length = 0;

		type = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(pdutree,
				    flowset_id == 1 ? hf_cflow_template_scope_field_type : hf_cflow_template_scope_field_type_ipfix,
				    tvb, offset, 2, FALSE);
		offset += 2; len += 2;
		scope_length = tvb_get_ntohs(tvb,offset);

		if (tplt.scopes && i < option_scope_len) {
			tplt.scopes[i].type = type;
			tplt.scopes[i].length = scope_length == VARIABLE_LENGTH ? 0 : scope_length;
			tplt.length += tplt.scopes[i].length;
		}
		proto_tree_add_item(pdutree, hf_cflow_template_scope_field_length, tvb,
				    offset, 2, FALSE);
		offset += 2; len += 2;

		/* Private Enterprise Number (IPFIX only) */
		if ((flowset_id == 3) && (type & 0x8000)) {
			if (tplt.scopes && i < option_scope_len) {
				tplt.scopes[i].pen = tvb_get_ntohl(tvb,offset);
			}
			proto_tree_add_item(pdutree,
					    hf_cflow_template_field_pen, tvb, offset, 4, FALSE);
			offset += 4; len += 4;
		}
		if (flowset_id == 1) { /* NetFlow v9 */
			tplt.count_scopes++;
		}
	}

	tplt_offset = offset;

	for(i=0, len = 0;
	    flowset_id == 1 ? len < option_len : i < tplt.count;
	    i++) {
		guint16 entry_length;

		type = tvb_get_ntohs(tvb, offset);
		proto_tree_add_item(pdutree,
				    flowset_id == 1 ? hf_cflow_template_field_type : hf_cflow_template_field_type_ipfix,
				    tvb, offset, 2, FALSE);
		offset += 2; len += 2;

		entry_length = tvb_get_ntohs(tvb, offset);

		if (tplt.entries && i < option_len) {
			tplt.entries[i].type = type;
			tplt.entries[i].length = entry_length == VARIABLE_LENGTH ? 0 : entry_length;
			tplt.length += tplt.entries[i].length;
		}
		proto_tree_add_item(pdutree, hf_cflow_template_field_length, tvb,
				    offset, 2, FALSE);
		offset += 2; len += 2;

		/* Private Enterprise Number (IPFIX only) */
		if ((flowset_id == 3) && (type & 0x8000)) {
			if (tplt.entries && i < option_len) {
				tplt.entries[i].pen = tvb_get_ntohl(tvb,offset);
			}
			proto_tree_add_item(pdutree,
					    hf_cflow_template_field_pen, tvb, offset, 4, FALSE);
			offset += 4; len += 4;
		}
		if (flowset_id == 1) { /* NetFlow v9 */
			tplt.count++;
		}
	}

	if (tplt.scopes || tplt.entries) {
		memcpy(&v9_template_cache[v9_template_hash(tplt.id,
			    &tplt.source_addr, tplt.source_id)],
			    &tplt, sizeof(tplt));
	}

	return (0);
}

static int
dissect_v9_template(proto_tree * pdutree, tvbuff_t * tvb, packet_info *pinfo, int offset, int length, hdrinfo_t * hdrinfo, guint16 flowset_id)
{
	struct v9_template tplt;
	proto_tree *tplt_tree;
	proto_item *tplt_item;
	proto_tree *field_tree;
	proto_item *field_item, *ti;
	guint16 id, count;
	int remaining = length;
	gint32 i;
	int field_start_offset;
	int orig_offset;

	while (remaining > 0) {

		orig_offset = offset;
		id = tvb_get_ntohs(tvb, offset);
		count = tvb_get_ntohs(tvb, offset + 2);

		tplt_item = proto_tree_add_text(pdutree, tvb, offset,
						    4 + sizeof(struct v9_template_entry) * count,
						    "Template (Id = %u, Count = %u)", id, count);
		tplt_tree = proto_item_add_subtree(tplt_item, ett_template);

		proto_tree_add_item(tplt_tree, hf_cflow_template_id, tvb,
				    offset, 2, FALSE);
		offset += 2;

		ti = proto_tree_add_item(tplt_tree, hf_cflow_template_field_count,
				    tvb, offset, 2, FALSE);
		offset += 2;

		if (count > V9TEMPLATE_MAX_FIELDS) {
			expert_add_info_format(pinfo, ti, PI_UNDECODED, PI_NOTE,
					       "More entries (%u) than we can handle",
					       count);
		}

		/* Cache template */
		memset(&tplt, 0, sizeof(tplt));
		tplt.id = id;
		tplt.count = count;
		SE_COPY_ADDRESS(&tplt.source_addr, &hdrinfo->net_src);
		tplt.source_id = hdrinfo->src_id;
		field_start_offset = offset;
		if (!v9_template_get(id, &hdrinfo->net_src, hdrinfo->src_id) && count && count <= V9TEMPLATE_MAX_FIELDS) {
			tplt.entries = se_alloc0(count * sizeof(struct v9_template_entry));
		}

		for (i = 0; i < count; i++) {
			guint16 type, entry_length;
			guint32 pen;

			pen = 0;
			field_item = proto_tree_add_text(tplt_tree, tvb,
							 offset, 4, "Field (%u/%u)", i, count);
			field_tree = proto_item_add_subtree(field_item, ett_field);

			type = tvb_get_ntohs(tvb, offset);
			entry_length = tvb_get_ntohs(tvb, offset + 2);
			if ((flowset_id == 2) && (type & 0x8000)) {
			  pen = tvb_get_ntohl(tvb, offset + 4);
			}

			if (tplt.entries) {
				tplt.entries[i].type = type;
				tplt.entries[i].length = entry_length == VARIABLE_LENGTH ? 0 : entry_length;
				tplt.length += tplt.entries[i].length;
				tplt.entries[i].pen = pen;
			}

			if ((flowset_id == 2) && (type & 0x8000) && (pen != REVPEN)) { /* except reverse pen */
			  proto_tree_add_text(field_tree,
					      tvb, offset, 2,
					      "Type: %u", type & 0x7fff);
			} else {
			  proto_tree_add_item(field_tree,
					      flowset_id == 0 ? hf_cflow_template_field_type : hf_cflow_template_field_type_ipfix,
					      tvb, offset, 2, FALSE);
			}
			offset += 2;

			proto_tree_add_item(field_tree,
					    hf_cflow_template_field_length, tvb, offset, 2, FALSE);
			offset += 2;
			/* Private Enterprise Number (IPFIX only) */
			if ((flowset_id == 2) && (type & 0x8000)) {
				proto_tree_add_item(field_tree,
					      hf_cflow_template_field_pen, tvb, offset, 4, FALSE);
			  offset += 4;
			}
		}

		if (tplt.entries) {
			memcpy(&v9_template_cache[v9_template_hash(tplt.id,
				    &tplt.source_addr, tplt.source_id)],
				    &tplt, sizeof(tplt));
		}
		remaining -= offset - orig_offset;
	}

	return (0);
}

static const value_string v9_template_types[] = {
	{ 1, "BYTES" },
	{ 2, "PKTS" },
	{ 3, "FLOWS" },
	{ 4, "PROTOCOL" },
	{ 5, "IP_TOS" },
	{ 6, "TCP_FLAGS" },
	{ 7, "L4_SRC_PORT" },
	{ 8, "IP_SRC_ADDR" },
	{ 9, "SRC_MASK" },
	{ 10, "INPUT_SNMP" },
	{ 11, "L4_DST_PORT" },
	{ 12, "IP_DST_ADDR" },
	{ 13, "DST_MASK" },
	{ 14, "OUTPUT_SNMP" },
	{ 15, "IP_NEXT_HOP" },
	{ 16, "SRC_AS" },
	{ 17, "DST_AS" },
	{ 18, "BGP_NEXT_HOP" },
	{ 19, "MUL_DPKTS" },
	{ 20, "MUL_DOCTETS" },
	{ 21, "LAST_SWITCHED" },
	{ 22, "FIRST_SWITCHED" },
	{ 23, "OUT_BYTES" },
	{ 24, "OUT_PKTS" },
	{ 25, "IP LENGTH MINIMUM" },
	{ 26, "IP LENGTH MAXIMUM" },
	{ 27, "IPV6_SRC_ADDR" },
	{ 28, "IPV6_DST_ADDR" },
	{ 29, "IPV6_SRC_MASK" },
	{ 30, "IPV6_DST_MASK" },
	{ 31, "FLOW_LABEL" },
	{ 32, "ICMP_TYPE" },
	{ 33, "IGMP_TYPE" },
	{ 34, "SAMPLING_INTERVAL" },
	{ 35, "SAMPLING_ALGORITHM" },
	{ 36, "FLOW_ACTIVE_TIMEOUT" },
	{ 37, "FLOW_INACTIVE_TIMEOUT" },
	{ 38, "ENGINE_TYPE" },
	{ 39, "ENGINE_ID" },
	{ 40, "TOTAL_BYTES_EXP" },
	{ 41, "TOTAL_PKTS_EXP" },
	{ 42, "TOTAL_FLOWS_EXP" },
	{ 44, "IP_SRC_PREFIX" },
	{ 45, "IP_DST_PREFIX" },
	{ 46, "MPLS_TOP_LABEL_TYPE" },
	{ 47, "MPLS_TOP_LABEL_ADDR" },
	{ 48, "FLOW_SAMPLER_ID" },
	{ 49, "FLOW_SAMPLER_MODE" },
	{ 50, "FLOW_SAMPLER_RANDOM_INTERVAL" },
	{ 51, "FLOW_CLASS" },
	{ 52, "IP TTL MINIMUM" },
	{ 53, "IP TTL MAXIMUM" },
	{ 54, "IPv4 ID" },
	{ 55, "DST_TOS" },
	{ 56, "SRC_MAC" },
	{ 57, "DST_MAC" },
	{ 58, "SRC_VLAN" },
	{ 59, "DST_VLAN" },
	{ 60, "IP_PROTOCOL_VERSION" },
	{ 61, "DIRECTION" },
	{ 62, "IPV6_NEXT_HOP" },
	{ 63, "BGP_IPV6_NEXT_HOP" },
	{ 64, "IPV6_OPTION_HEADERS" },
	{ 70, "MPLS_LABEL_1" },
	{ 71, "MPLS_LABEL_2" },
	{ 72, "MPLS_LABEL_3" },
	{ 73, "MPLS_LABEL_4" },
	{ 74, "MPLS_LABEL_5" },
	{ 75, "MPLS_LABEL_6" },
	{ 76, "MPLS_LABEL_7" },
	{ 77, "MPLS_LABEL_8" },
	{ 78, "MPLS_LABEL_9" },
	{ 79, "MPLS_LABEL_10" },
	{ 80, "DESTINATION_MAC" },
	{ 81, "SOURCE_MAC" },
	{ 82, "IF_NAME" },
	{ 83, "IF_DESC" },
	{ 84, "SAMPLER_NAME" },
	{ 85, "BYTES_TOTAL" },
	{ 86, "PACKETS_TOTAL" },
	{ 88, "FRAGMENT_OFFSET" },
	{ 89, "FORWARDING_STATUS" },
	{ 90, "VPN_ROUTE_DISTINGUISHER" },
	{ 91, "mplsTopLabelPrefixLength" },
	{ 92, "SRC_TRAFFIC_INDEX" },
	{ 93, "DST_TRAFFIC_INDEX" },
	{ 94, "APPLICATION_DESC" },
	{ 95, "APPLICATION_ID" },
	{ 96, "APPLICATION_NAME" },
	{ 98, "postIpDiffServCodePoint" },
	{ 99, "multicastReplicationFactor" },
	{ 128, "DST_AS_PEER" },
	{ 129, "SRC_AS_PEER" },
	{ 130, "exporterIPv4Address" },
	{ 131, "exporterIPv6Address" },
	{ 132, "DROPPED_BYTES" },
	{ 133, "DROPPED_PACKETS" },
	{ 134, "DROPPED_BYTES_TOTAL" },
	{ 135, "DROPPED_PACKETS_TOTAL" },
	{ 136, "flowEndReason" },
	{ 137, "commonPropertiesId" },
	{ 138, "observationPointId" },
	{ 139, "icmpTypeCodeIPv6" },
	{ 140, "MPLS_TOP_LABEL_IPv6_ADDRESS" },
	{ 141, "lineCardId" },
	{ 142, "portId" },
	{ 143, "meteringProcessId" },
	{ 144, "FLOW_EXPORTER" },
	{ 145, "templateId" },
	{ 146, "wlanChannelId" },
	{ 147, "wlanSSID" },
	{ 148, "flowId" },
	{ 149, "observationDomainId" },
	{ 150, "flowStartSeconds" },
	{ 151, "flowEndSeconds" },
	{ 152, "flowStartMilliseconds" },
	{ 153, "flowEndMilliseconds" },
	{ 154, "flowStartMicroseconds" },
	{ 155, "flowEndMicroseconds" },
	{ 156, "flowStartNanoseconds" },
	{ 157, "flowEndNanoseconds" },
	{ 158, "flowStartDeltaMicroseconds" },
	{ 159, "flowEndDeltaMicroseconds" },
	{ 160, "systemInitTimeMilliseconds" },
	{ 161, "flowDurationMilliseconds" },
	{ 162, "flowDurationMicroseconds" },
	{ 163, "observedFlowTotalCount" },
	{ 164, "ignoredPacketTotalCount" },
	{ 165, "ignoredOctetTotalCount" },
	{ 166, "notSentFlowTotalCount" },
	{ 167, "notSentPacketTotalCount" },
	{ 168, "notSentOctetTotalCount" },
	{ 169, "destinationIPv6Prefix" },
	{ 170, "sourceIPv6Prefix" },
	{ 171, "postOctetTotalCount" },
	{ 172, "postPacketTotalCount" },
	{ 173, "flowKeyIndicator" },
	{ 174, "postMCastPacketTotalCount" },
	{ 175, "postMCastOctetTotalCount" },
	{ 176, "ICMP_IPv4_TYPE" },
	{ 177, "ICMP_IPv4_CODE" },
	{ 178, "ICMP_IPv6_TYPE" },
	{ 179, "ICMP_IPv6_CODE" },
	{ 180, "UDP_SRC_PORT" },
	{ 181, "UDP_DST_PORT" },
	{ 182, "TCP_SRC_PORT" },
	{ 183, "TCP_DST_PORT" },
	{ 184, "TCP_SEQ_NUM" },
	{ 185, "TCP_ACK_NUM" },
	{ 186, "TCP_WINDOW_SIZE" },
	{ 187, "TCP_URGENT_PTR" },
	{ 188, "TCP_HEADER_LEN" },
	{ 189, "IP_HEADER_LEN" },
	{ 190, "IP_TOTAL_LEN" },
	{ 191, "payloadLengthIPv6" },
	{ 192, "IP_TTL" },
	{ 193, "nextHeaderIPv6" },
	{ 194, "IP_TOS" },
	{ 195, "IP_DSCP" },
	{ 196, "IP_PRECEDENCE" },
	{ 197, "IP_FRAGMENT_FLAGS" },
	{ 198, "BYTES_SQUARED" },
	{ 199, "BYTES_SQUARED_PERMANENT" },
	{ 200, "MPLS_TOP_LABEL_TTL" },
	{ 201, "MPLS_LABEL_STACK_OCTETS" },
	{ 202, "MPLS_LABEL_STACK_DEPTH" },
	{ 203, "MPLS_TOP_LABEL_EXP" },
	{ 204, "IP_PAYLOAD_LENGTH" },
	{ 205, "UDP_LENGTH" },
	{ 206, "IS_MULTICAST" },
	{ 207, "IP_HEADER_WORDS" },
	{ 208, "IP_OPTION_MAP" },
	{ 209, "TCP_OPTION_MAP" },
	{ 210, "paddingOctets" },
	{ 211, "collectorIPv4Address" },
	{ 212, "collectorIPv6Address" },
	{ 213, "collectorInterface" },
	{ 214, "collectorProtocolVersion" },
	{ 215, "collectorTransportProtocol" },
	{ 216, "collectorTransportPort" },
	{ 217, "exporterTransportPort" },
	{ 218, "tcpSynTotalCount" },
	{ 219, "tcpFinTotalCount" },
	{ 220, "tcpRstTotalCount" },
	{ 221, "tcpPshTotalCount" },
	{ 222, "tcpAckTotalCount" },
	{ 223, "tcpUrgTotalCount" },
	{ 224, "ipTotalLength" },
	{ 225, "postNATSourceIPv4Address" },
	{ 226, "postNATDestinationIPv4Address" },
	{ 227, "postNAPTSourceTransportPort" },
	{ 228, "postNAPTDestinationTransportPort" },
	{ 229, "natOriginatingAddressRealm" },
	{ 230, "natEvent" },
	{ 231, "initiatorOctets" },
	{ 232, "responderOctets" },
	{ 233, "firewallEvent" },
	{ 234, "ingressVRFID" },
	{ 235, "egressVRFID" },
	{ 236, "VRFname" },
	{ 237, "postMplsTopLabelExp" },
	{ 238, "tcpWindowScale" },
	{ 239, "biflowDirection" },
	{ 240, "ethernetHeaderLength" },
	{ 241, "ethernetPayloadLength" },
	{ 242, "ethernetTotalLength" },
	{ 243, "dot1qVlanId" },
	{ 244, "dot1qPriority" },
	{ 245, "dot1qCustomerVlanId" },
	{ 246, "dot1qCustomerPriority" },
	{ 247, "metroEvcId" },
	{ 248, "metroEvcType" },
	{ 249, "pseudoWireId" },
	{ 250, "pseudoWireType" },
	{ 251, "pseudoWireControlWord" },
	{ 252, "ingressPhysicalInterface" },
	{ 253, "egressPhysicalInterface" },
	{ 254, "postDot1qVlanId" },
	{ 255, "postDot1qCustomerVlanId" },
	{ 256, "ethernetType" },
	{ 257, "postIpPrecedence" },
	{ 258, "collectionTimeMilliseconds" },
	{ 259, "exportSctpStreamId" },
	{ 260, "maxExportSeconds" },
	{ 261, "maxFlowEndSeconds" },
	{ 262, "messageMD5Checksum" },
	{ 263, "messageScope" },
	{ 264, "minExportSeconds" },
	{ 265, "minFlowStartSeconds" },
	{ 266, "opaqueOctets" },
	{ 267, "sessionScope" },
	{ 268, "maxFlowEndMicroseconds" },
	{ 269, "maxFlowEndMilliseconds" },
	{ 270, "maxFlowEndNanoseconds" },
	{ 271, "minFlowStartMicroseconds" },
	{ 272, "minFlowStartMilliseconds" },
	{ 273, "minFlowStartNanoseconds" },
	{ 274, "collectorCertificate" },
	{ 275, "exporterCertificate" },
	{ 301, "selectionSequenceId" },
	{ 302, "selectorId" },
	{ 303, "informationElementId" },
	{ 304, "selectorAlgorithm" },
	{ 305, "samplingPacketInterval" },
	{ 306, "samplingPacketSpace" },
	{ 307, "samplingTimeInterval" },
	{ 308, "samplingTimeSpace" },
	{ 309, "samplingSize" },
	{ 310, "samplingPopulation" },
	{ 311, "samplingProbability" },
	{ 313, "IP_SECTION HEADER" },
	{ 314, "IP_SECTION PAYLOAD" },
	{ 316, "mplsLabelStackSection" },
	{ 317, "mplsPayloadPacketSection" },
	{ 318, "selectorIdTotalPktsObserved" },
	{ 319, "selectorIdTotalPktsSelected" },
	{ 320, "absoluteError" },
	{ 321, "relativeError" },
	{ 322, "observationTimeSeconds" },
	{ 323, "observationTimeMilliseconds" },
	{ 324, "observationTimeMicroseconds" },
	{ 325, "observationTimeNanoseconds" },
	{ 326, "digestHashValue" },
	{ 327, "hashIPPayloadOffset" },
	{ 328, "hashIPPayloadSize" },
	{ 329, "hashOutputRangeMin" },
	{ 330, "hashOutputRangeMax" },
	{ 331, "hashSelectedRangeMin" },
	{ 332, "hashSelectedRangeMax" },
	{ 333, "hashDigestOutput" },
	{ 334, "hashInitialiserValue" },
	{ 335, "selectorName" },
	{ 336, "upperCILimit" },
	{ 337, "lowerCILimit" },
	{ 338, "confidenceLevel" },
	{ 339, "informationElementDataType" },
	{ 340, "informationElementDescription" },
	{ 341, "informationElementName" },
	{ 342, "informationElementRangeBegin" },
	{ 343, "informationElementRangeEnd" },
	{ 344, "informationElementSemantics" },
	{ 345, "informationElementUnits" },
	{ 346, "privateEnterpriseNumber" },
	/* Cisco ASA5500 Series NetFlow */
	{ 33000, "INGRESS_ACL_ID" },
	{ 33001, "EGRESS_ACL_ID" },
	{ 33002, "FW_EXT_EVENT" },
	{ 40000, "AAA_USERNAME" },
	{ 40001, "XLATE_SRC_ADDR_IPV4" },
	{ 40002, "XLATE_DST_ADDR_IPV4" },
	{ 40003, "XLATE_SRC_PORT" },
	{ 40004, "XLATE_DST_PORT" },
	{ 40005, "FW_EVENT" },
	{ 0, NULL }
};

static const value_string v9_scope_field_types[] = {
	{ 1, "System" },
	{ 2, "Interface" },
	{ 3, "Line Card" },
	{ 4, "NetFlow Cache" },
	{ 5, "Template" },
	{ 0, NULL }
};

static const char *
decode_v9_template_types(int type) {
	const char *v = match_strval(type, v9_template_types);
	return ((v==NULL)?"Unknown" : v);
}

static const value_string v9_sampler_mode[] = {
	{ 0, "Determinist" },
	{ 1, "Unknown" },
	{ 2, "Random" },
	{ 0, NULL }
};
static const value_string v9_direction[] = {
	{ 0, "Ingress" },
	{ 1, "Egress" },
	{ 0, NULL }
};
static const value_string v9_forwarding_status[] = {
	{ 0, "Unknown"},  /* Observed on IOS-XR 3.2 */
	{ 1, "Forward"},  /* Observed on 7200 12.4(9)T */
	{ 2, "Drop"},     /* Observed on 7200 12.4(9)T */
	{ 3, "Consume"},  /* Observed on 7200 12.4(9)T */
	{ 0, NULL }
};
static const value_string v9_forwarding_status_code[] = {
	{ 64, "Forwarded (Unknown)" },
	{ 65, "Forwarded Fragmented" },
	{ 66, "Forwarded not Fragmented" },
	{ 128, "Dropped (Unknown)" },
	{ 129, "Drop ACL Deny" },
	{ 130, "Drop ACL drop" },
	{ 131, "Drop Unroutable" },
	{ 132, "Drop Adjacency" },
	{ 133, "Drop Fragmentation & DF set" },
	{ 134, "Drop Bad header checksum" },
	{ 135, "Drop Bad total Length" },
	{ 136, "Drop Bad Header Length" },
	{ 137, "Drop bad TTL" },
	{ 138, "Drop Policer" },
	{ 139, "Drop WRED" },
	{ 140, "Drop RPF" },
	{ 141, "Drop For us" },
	{ 142, "Drop Bad output interface" },
	{ 143, "Drop Hardware" },
	{ 192, "Consumed (Unknown)" },
	{ 193, "Terminate Punt Adjacency" },
	{ 194, "Terminate Incomplete Adjacency" },
	{ 195, "Terminate For us" },
	{ 0, NULL }
};
static const value_string v9_firewall_event[] = {
	{ 0, "Default (ignore)"},
	{ 1, "Flow created"},
	{ 2, "Flow deleted"},
	{ 3, "Flow denied"},
	{ 4, "Flow alart"},
	{ 0, NULL }
};

static const value_string v9_extended_firewall_event[] = {
	{ 0, "ignore"},
	{ 1001, "Flow denied by an ingress ACL"},
	{ 1002, "Flow denied by an egress ACL"},
	{ 1003, "Flow denied by security appliance"},
	{ 1004, "Flow denied (TCP flow beginning with not TCP SYN)"},
	{ 0, NULL }
};
static const value_string engine_type[] = {
	{ 0, "RP"},
	{ 1, "VIP/Linecard"},
	{ 2, "PFC/DFC" },
	{ 0, NULL }
};
static const value_string v9_flow_end_reason[] = {
	{ 0, "Unknown"},
	{ 1, "Idle timeout"},
	{ 2, "Active timeout" },
	{ 3, "End of Flow detected" },
	{ 4, "Forced end" },
	{ 5, "Lack of resources" },
	{ 0, NULL }
};
static const value_string v9_biflow_direction[] = {
	{ 0, "Arbitrary"},
	{ 1, "Initiator"},
	{ 2, "ReverseInitiator" },
	{ 3, "Perimeter" },
	{ 0, NULL }
};
static const value_string selector_algorithm[] = {
	{ 0, "Reserved"},
	{ 1, "Systematic count-based Sampling"},
	{ 2, "Systematic time-based Sampling"},
	{ 3, "Random n-out-of-N Sampling"},
	{ 4, "Uniform probabilistic Sampling"},
	{ 5, "Property match Filtering"},
	{ 6, "Hash based Filtering using BOB"},
	{ 7, " Hash based Filtering using IPSX"},
	{ 8, "Hash based Filtering using CRC"},
	{ 0, NULL }
};


static int
v9_template_hash(guint16 id, const address * net_src, guint32 src_id)
{
	guint32 val = 0;
	const guint8 *p;
	guint32 temp;
	int cnt, i;

	p = (guint8 *)(net_src->data);

	val += id;

	switch (net_src->type) {
	case AT_IPv4:
		cnt = 1;
		break;
	case AT_IPv6:
		cnt = 4;
		break;
	default:
		cnt = 0;
		break;
	}

	for (i=0; i < cnt; i++) {
		memcpy((guint8 *)&temp, p, 4);
		val += GUINT32_TO_LE(temp);	/* Use *reverse* of each 4 bytes of IP address when  */
						/*  calculating the hash on both BE and LE machines. */
						/* EG: hash of IP address 1.2.3.4 will be 0x04030201 */
						/* (Note that we'll get the right result on a LE     */
						/*  machine since the IP  address is stored in       */
						/*  network order and GUINT32_TO_LE is a no-op. On   */
						/*  a BE machine GUINT32_TO_LE will swap the bytes.  */
		p += 4;
	}

	val += src_id;

	return val % V9TEMPLATE_CACHE_MAX_ENTRIES;
}

static struct v9_template *
v9_template_get(guint16 id, address * net_src, guint32 src_id)
{
	struct v9_template *tplt;

	tplt = &v9_template_cache[v9_template_hash(id, net_src, src_id)];

	if (tplt->id != id ||
	    !ADDRESSES_EQUAL(&tplt->source_addr, net_src) ||
	    tplt->source_id != src_id) {
		tplt = NULL;
	}

	return (tplt);
}

/*
 * dissect a version 1, 5, or 7 pdu and return the length of the pdu we
 * processed
 */

static int
dissect_pdu(tvbuff_t * tvb, packet_info * pinfo _U_, proto_tree * pdutree, int offset, hdrinfo_t * hdrinfo)
{
	proto_item     *hidden_item;
	int             startoffset = offset;
	guint32         srcaddr, dstaddr;
	guint8          mask;
	nstime_t        ts;
	guint8		ver;

	memset(&ts, '\0', sizeof(ts));

	/*
	 * memcpy so we can use the values later to calculate a prefix
	 */
	srcaddr = tvb_get_ipv4(tvb, offset);
	proto_tree_add_ipv4(pdutree, hf_cflow_srcaddr, tvb, offset, 4,
			    srcaddr);
	offset += 4;

	dstaddr = tvb_get_ipv4(tvb, offset);
	proto_tree_add_ipv4(pdutree, hf_cflow_dstaddr, tvb, offset, 4,
			    dstaddr);
	offset += 4;

	proto_tree_add_item(pdutree, hf_cflow_nexthop, tvb, offset, 4, FALSE);
	offset += 4;

	offset = flow_process_ints(pdutree, tvb, offset);
	offset = flow_process_sizecount(pdutree, tvb, offset);
	offset = flow_process_timeperiod(pdutree, tvb, offset);
	offset = flow_process_ports(pdutree, tvb, offset);

	/*
	 * and the similarities end here
	 */

	ver = hdrinfo->vspec;

	if (ver == 1) {
		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2, "padding");

		proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1,
				    FALSE);

		proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1,
				    FALSE);

		proto_tree_add_item(pdutree, hf_cflow_tcpflags, tvb, offset++,
				    1, FALSE);

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 3, "padding");

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 4,
					   "reserved");
	} else {
		if (ver == 5)
			offset =
			    flow_process_textfield(pdutree, tvb, offset, 1,
						   "padding");
		else {
			proto_tree_add_item(pdutree, hf_cflow_flags, tvb,
					    offset++, 1, FALSE);
		}

		proto_tree_add_item(pdutree, hf_cflow_tcpflags, tvb, offset++,
				    1, FALSE);

		proto_tree_add_item(pdutree, hf_cflow_prot, tvb, offset++, 1,
				    FALSE);

		proto_tree_add_item(pdutree, hf_cflow_tos, tvb, offset++, 1,
				    FALSE);

		offset = flow_process_aspair(pdutree, tvb, offset);

		mask = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(pdutree, tvb, offset, 1,
				    "SrcMask: %u (prefix: %s/%u)",
				    mask, getprefix(&srcaddr, mask),
				    mask != 0 ? mask : 32);
		hidden_item = proto_tree_add_uint(pdutree, hf_cflow_srcmask, tvb,
					   offset++, 1, mask);
		PROTO_ITEM_SET_HIDDEN(hidden_item);

		mask = tvb_get_guint8(tvb, offset);
		proto_tree_add_text(pdutree, tvb, offset, 1,
				    "DstMask: %u (prefix: %s/%u)",
				    mask, getprefix(&dstaddr, mask),
				    mask != 0 ? mask : 32);
		hidden_item = proto_tree_add_uint(pdutree, hf_cflow_dstmask, tvb,
					   offset++, 1, mask);
		PROTO_ITEM_SET_HIDDEN(hidden_item);

		offset =
		    flow_process_textfield(pdutree, tvb, offset, 2, "padding");

		if (ver == 7) {
			proto_tree_add_item(pdutree, hf_cflow_routersc, tvb,
					    offset, 4, FALSE);
			offset += 4;
		}
	}

	return (offset - startoffset);
}

static const gchar   *
getprefix(const guint32 * addr, int prefix)
{
	guint32         gprefix;

	gprefix = *addr & g_htonl((0xffffffff << (32 - prefix)));

	return (ip_to_str((const guint8 *)&gprefix));
}

/* Called whenever a pref is changed, a new capture is loaded, & etc */
static void
netflow_reinit(void)
{
	/* Clear out the template cache. */
	memset(v9_template_cache, 0, sizeof v9_template_cache);
}

void
proto_register_netflow(void)
{
	static hf_register_info hf[] = {
		/*
		 * flow header
		 */
		{&hf_cflow_version,
		 {"Version", "cflow.version",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "NetFlow Version", HFILL}
		},
		{&hf_cflow_len,
		 {"Length", "cflow.len",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Length of PDUs", HFILL}
		},
		{&hf_cflow_count,
		 {"Count", "cflow.count",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Count of PDUs", HFILL}
		 },
		{&hf_cflow_sysuptime,
		 {"SysUptime", "cflow.sysuptime",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Time since router booted (in milliseconds)", HFILL}
		},
		{&hf_cflow_exporttime,
		 {"ExportTime", "cflow.exporttime",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Time when the flow has been exported", HFILL}
		},
		{&hf_cflow_timestamp,
		 {"Timestamp", "cflow.timestamp",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  "Current seconds since epoch", HFILL}
		 },
		{&hf_cflow_unix_secs,
		 {"CurrentSecs", "cflow.unix_secs",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Current seconds since epoch", HFILL}
		 },
		{&hf_cflow_unix_nsecs,
		 {"CurrentNSecs", "cflow.unix_nsecs",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Residual nanoseconds since epoch", HFILL}
		 },
		{&hf_cflow_samplingmode,
		 {"SamplingMode", "cflow.samplingmode",
		  FT_UINT16, BASE_DEC, VALS(v5_sampling_mode), 0xC000,
		  "Sampling Mode of exporter", HFILL}
		 },
		{&hf_cflow_samplerate,
		 {"SampleRate", "cflow.samplerate",
		  FT_UINT16, BASE_DEC, NULL, 0x3FFF,
		  "Sample Frequency of exporter", HFILL}
		 },

		/*
		 * end version-agnostic header
		 * version-specific flow header
		 */
		{&hf_cflow_sequence,
		 {"FlowSequence", "cflow.sequence",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Sequence number of flows seen", HFILL}
		 },
		{&hf_cflow_engine_type,
		 {"EngineType", "cflow.engine_type",
		  FT_UINT8, BASE_DEC, VALS(engine_type), 0x0,
		  "Flow switching engine type", HFILL}
		 },
		{&hf_cflow_engine_id,
		 {"EngineId", "cflow.engine_id",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Slot number of switching engine", HFILL}
		 },
		{&hf_cflow_source_id,
		 {"SourceId", "cflow.source_id",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Identifier for export device", HFILL}
		 },
		{&hf_cflow_aggmethod,
		 {"AggMethod", "cflow.aggmethod",
		  FT_UINT8, BASE_DEC, VALS(v8_agg), 0x0,
		  "CFlow V8 Aggregation Method", HFILL}
		 },
		{&hf_cflow_aggversion,
		 {"AggVersion", "cflow.aggversion",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "CFlow V8 Aggregation Version", HFILL}
		 },
		/*
		 * end version specific header storage
		 */
		/*
		 * Version 9
		 */
		{&hf_cflow_flowset_id,
		 {"FlowSet Id", "cflow.flowset_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_data_flowset_id,
		 {"Data FlowSet (Template Id)", "cflow.data_flowset_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Data FlowSet with corresponding to a template Id", HFILL}
		},
		{&hf_cflow_data_datarecord_id,
		 {"DataRecord (Template Id)", "cflow.data_datarecord_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "DataRecord with corresponding to a template Id", HFILL}
		},
		{&hf_cflow_options_flowset_id,
		 {"Options FlowSet", "cflow.options_flowset_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_template_flowset_id,
		 {"Template FlowSet", "cflow.template_flowset_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_flowset_length,
		 {"FlowSet Length", "cflow.flowset_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "FlowSet length", HFILL}
		 },
		{&hf_cflow_template_id,
		 {"Template Id", "cflow.template_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_template_field_count,
		 {"Field Count", "cflow.template_field_count",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Template field count", HFILL}
		 },
		{&hf_cflow_template_field_type,
		 {"Type", "cflow.template_field_type",
		  FT_UINT16, BASE_DEC, VALS(v9_template_types), 0x0,
		  "Template field type", HFILL}
		 },
		{&hf_cflow_template_field_type_ipfix,
		 {"Type", "cflow.template_field_type",
		  FT_UINT16, BASE_DEC, VALS(v9_template_types), 0x7FFF,
		  "Template field type", HFILL}
		 },
		{&hf_cflow_template_field_length,
		 {"Length", "cflow.template_field_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Template field length", HFILL}
		 },

		/* options */
		{&hf_cflow_option_scope_length,
		 {"Option Scope Length", "cflow.option_scope_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Option scope length", HFILL}
		 },
		{&hf_cflow_option_length,
		 {"Option Length", "cflow.option_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Option length", HFILL}
		 },
		{&hf_cflow_template_scope_field_type,
		 {"Scope Type", "cflow.scope_field_type",
		  FT_UINT16, BASE_DEC, VALS(v9_scope_field_types), 0x0,
		  "Scope field type", HFILL}
		},
		{&hf_cflow_template_scope_field_type_ipfix,
		 {"Scope Type", "cflow.scope_field_type",
		  FT_UINT16, BASE_DEC, VALS(v9_template_types), 0x7FF,
		  "Scope field type", HFILL}
		},
		{&hf_cflow_template_scope_field_length,
		 {"Scope Field Length", "cflow.scope_field_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Scope field length", HFILL}
		 },
		{&hf_cflow_icmp_type,
		 {"ICMP Type", "cflow.icmp_type",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "ICMP type", HFILL}
		},
		{&hf_cflow_igmp_type,
		 {"IGMP Type", "cflow.igmp_type",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IGMP type", HFILL}
		},
		{&hf_cflow_sampling_interval,
		 {"Sampling interval", "cflow.sampling_interval",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_sampling_algorithm,
		 {"Sampling algorithm", "cflow.sampling_algorithm",
		  FT_UINT8, BASE_DEC, VALS(v5_sampling_mode), 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_flow_active_timeout,
		 {"Flow active timeout", "cflow.flow_active_timeout",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_flow_inactive_timeout,
		 {"Flow inactive timeout", "cflow.flow_inactive_timeout",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},

		/*
		 * begin pdu content storage
		 */
		{&hf_cflow_srcaddr,
		 {"SrcAddr", "cflow.srcaddr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Source Address", HFILL}
		 },
		{&hf_cflow_srcaddr_v6,
		 {"SrcAddr", "cflow.srcaddrv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Flow Source Address", HFILL}
		 },
		{&hf_cflow_srcnet,
		 {"SrcNet", "cflow.srcnet",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Source Network", HFILL}
		 },
		{&hf_cflow_dstaddr,
		 {"DstAddr", "cflow.dstaddr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Destination Address", HFILL}
		 },
		{&hf_cflow_dstaddr_v6,
		 {"DstAddr", "cflow.dstaddrv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Flow Destination Address", HFILL}
		 },
		{&hf_cflow_dstnet,
		 {"DstNet", "cflow.dstnet",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Destination Network", HFILL}
		 },
		{&hf_cflow_nexthop,
		 {"NextHop", "cflow.nexthop",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Router nexthop", HFILL}
		 },
		{&hf_cflow_nexthop_v6,
		 {"NextHop", "cflow.nexthopv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Router nexthop", HFILL}
		 },
		{&hf_cflow_bgpnexthop,
		 {"BGPNextHop", "cflow.bgpnexthop",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "BGP Router Nexthop", HFILL}
		 },
		{&hf_cflow_bgpnexthop_v6,
		 {"BGPNextHop", "cflow.bgpnexthopv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "BGP Router Nexthop", HFILL}
		 },
		{&hf_cflow_inputint,
		 {"InputInt", "cflow.inputint",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Input Interface", HFILL}
		 },
		{&hf_cflow_outputint,
		 {"OutputInt", "cflow.outputint",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Output Interface", HFILL}
		 },
		{&hf_cflow_flows,
		 {"Flows", "cflow.flows",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Flows Aggregated in PDU", HFILL}
		 },
		{&hf_cflow_packets,
		 {"Packets", "cflow.packets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of packets", HFILL}
		 },
		{&hf_cflow_packets64,
		 {"Packets", "cflow.packets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of packets", HFILL}
		 },
		{&hf_cflow_octets,
		 {"Octets", "cflow.octets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of bytes", HFILL}
		 },
		{&hf_cflow_octets64,
		 {"Octets", "cflow.octets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of bytes", HFILL}
		 },
		{&hf_cflow_length_min,
		 {"MinLength", "cflow.length_min",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Packet Length Min", HFILL}
		 },
		{&hf_cflow_length_max,
		 {"MaxLength", "cflow.length_max",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Packet Length Max", HFILL}
		 },
		{&hf_cflow_timedelta,
		 {"Duration", "cflow.timedelta",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		  "Duration of flow sample (end - start)", HFILL}
		 },
		{&hf_cflow_timestart,
		 {"StartTime", "cflow.timestart",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		  "Uptime at start of flow", HFILL}
		 },
		{&hf_cflow_timeend,
		 {"EndTime", "cflow.timeend",
		  FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
		  "Uptime at end of flow", HFILL}
		 },
		{&hf_cflow_srcport,
		 {"SrcPort", "cflow.srcport",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Source Port", HFILL}
		 },
		{&hf_cflow_dstport,
		 {"DstPort", "cflow.dstport",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Destination Port", HFILL}
		 },
		{&hf_cflow_prot,
		 {"Protocol", "cflow.protocol",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IP Protocol", HFILL}
		 },
		{&hf_cflow_tos,
		 {"IP ToS", "cflow.tos",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "IP Type of Service", HFILL}
		 },
		{&hf_cflow_flags,
		 {"Export Flags", "cflow.flags",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "CFlow Flags", HFILL}
		 },
		{&hf_cflow_tcpflags,
		 {"TCP Flags", "cflow.tcpflags",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_srcas,
		 {"SrcAS", "cflow.srcas",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Source AS", HFILL}
		 },
		{&hf_cflow_dstas,
		 {"DstAS", "cflow.dstas",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Destination AS", HFILL}
		 },
		{&hf_cflow_srcmask,
		 {"SrcMask", "cflow.srcmask",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Source Prefix Mask", HFILL}
		 },
		{&hf_cflow_srcmask_v6,
		 {"SrcMask", "cflow.srcmaskv6",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IPv6 Source Prefix Mask", HFILL}
		 },
		{&hf_cflow_dstmask,
		 {"DstMask", "cflow.dstmask",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Destination Prefix Mask", HFILL}
		 },
		{&hf_cflow_dstmask_v6,
		 {"DstMask", "cflow.dstmaskv6",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IPv6 Destination Prefix Mask", HFILL}
		 },
		{&hf_cflow_routersc,
		 {"Router Shortcut", "cflow.routersc",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Router shortcut by switch", HFILL}
		 },
		{&hf_cflow_mulpackets,
		 {"MulticastPackets", "cflow.mulpackets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of multicast packets", HFILL}
		 },
		{&hf_cflow_muloctets,
		 {"MulticastOctets", "cflow.muloctets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of multicast octets", HFILL}
		 },
		{&hf_cflow_octets_exp,
		 {"OctetsExp", "cflow.octetsexp",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Octets exported", HFILL}
		 },
		{&hf_cflow_octets_exp64,
		 {"OctetsExp", "cflow.octetsexp",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Octets exported", HFILL}
		 },
		{&hf_cflow_packets_exp,
		 {"PacketsExp", "cflow.packetsexp",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Packets exported", HFILL}
		 },
		{&hf_cflow_packets_exp64,
		 {"PacketsExp", "cflow.packetsexp",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Packets exported", HFILL}
		 },
		{&hf_cflow_flows_exp,
		 {"FlowsExp", "cflow.flowsexp",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Flows exported", HFILL}
		},
		{&hf_cflow_flows_exp64,
		 {"FlowsExp", "cflow.flowsexp",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Flows exported", HFILL}
		},
		{&hf_cflow_srcprefix,
		 {"SrcPrefix", "cflow.srcprefix",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Source Prefix", HFILL}
		 },
		{&hf_cflow_dstprefix,
		 {"DstPrefix", "cflow.dstprefix",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Destination Prefix", HFILL}
		 },
		{&hf_cflow_mpls_top_label_type,
		 {"TopLabelType", "cflow.toplabeltype",
		  FT_UINT8, BASE_DEC, VALS(special_mpls_top_label_type), 0x0,
		  "Top MPLS label Type", HFILL}
		 },
		{&hf_cflow_mpls_pe_addr,
		 {"TopLabelAddr", "cflow.toplabeladdr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Top MPLS label PE address", HFILL}
		 },
		{&hf_cflow_sampler_mode ,
		 {"SamplerMode", "cflow.sampler_mode",
		  FT_UINT8, BASE_DEC, VALS(v9_sampler_mode), 0x0,
		  "Flow Sampler Mode", HFILL}
		 },
		{&hf_cflow_sampler_random_interval ,
		 {"SamplerRandomInterval", "cflow.sampler_random_interval",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Flow Sampler Random Interval", HFILL}
		 },
		{&hf_cflow_flow_class ,
		 {"FlowClass", "cflow.flow_class",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Flow Class", HFILL}
		 },
		{&hf_cflow_ttl_minimum ,
		 {"MinTTL", "cflow.ttl_min",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "TTL minimum", HFILL}
		 },
		{&hf_cflow_ttl_maximum ,
		 {"MaxTTL", "cflow.ttl_max",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "TTL maximum", HFILL}
		 },
		{&hf_cflow_ipv4_id ,
		 {"IPv4Ident", "cflow.ipv4_ident",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "IPv4 Identifier", HFILL}
		 },
		{&hf_cflow_ip_version ,
		 {"IPVersion", "cflow.ip_version",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "IP Version", HFILL}
		 },
		{&hf_cflow_direction ,
		 {"Direction", "cflow.direction",
		  FT_UINT8, BASE_DEC, VALS(v9_direction), 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_if_name ,
		 {"IfName", "cflow.if_name",
		  FT_STRINGZ/*FT_BYTES*/, BASE_NONE, NULL, 0x0,
		  "SNMP Interface Name", HFILL}
		 },
		{&hf_cflow_if_descr ,
		 {"IfDescr", "cflow.if_descr",
		  FT_STRINGZ/*FT_BYTES*/, BASE_NONE, NULL, 0x0,
		  "SNMP Interface Description", HFILL}
		 },
		{&hf_cflow_sampler_name ,
		 {"SamplerName", "cflow.sampler_name",
		  FT_STRINGZ/*FT_BYTES*/, BASE_NONE, NULL, 0x0,
		  "Sampler Name", HFILL}
		 },
		{&hf_cflow_forwarding_status ,
		 {"ForwdStat", "cflow.forwarding_status",
		  FT_UINT8, BASE_DEC, VALS(v9_forwarding_status), 0xC0,
		  "Forwarding Status", HFILL}
		 },
		{&hf_cflow_forwarding_code ,
		 {"ForwdCode", "cflow.forwarding_code",
		  FT_UINT8, BASE_DEC, NULL, 0x3F,
		  "Forwarding Code", HFILL}
		 },
		{&hf_cflow_nbar_appl_desc,
		 {"ApplicationDesc", "cflow.appl_desc",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  "Application Desc (NBAR)", HFILL}
		 },
		{&hf_cflow_nbar_appl_id,
		 {"ApplicationID", "cflow.appl_id",
		 FT_UINT16, BASE_DEC, NULL, 0x0,
		 "Application ID (NBAR)", HFILL}
		},
		{&hf_cflow_nbar_appl_name,
		 {"ApplicationName", "cflow.appl_name",
		  FT_STRINGZ, BASE_NONE, NULL, 0x0,
		  "Application Name (NBAR)", HFILL}
		 },
		{&hf_cflow_peer_srcas,
		 {"PeerSrcAS", "cflow.peer_srcas",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Peer Source AS", HFILL}
		 },
		{&hf_cflow_peer_dstas,
		 {"PeerDstAS", "cflow.peer_dstas",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Peer Destination AS", HFILL}
		 },
		{&hf_cflow_flow_exporter,
		 {"FlowExporter", "cflow.flow_exporter",
		  FT_BYTES/*FT_IPv4*/, BASE_NONE, NULL, 0x0,
		  "Flow Exporter", HFILL}
		 },
		{&hf_cflow_icmp_ipv4_type,
		 {"IPv4 ICMP Type", "cflow.icmp_ipv4_type",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IPv4 ICMP type", HFILL}
		},
		{&hf_cflow_icmp_ipv4_code,
		 {"IPv4 ICMP Code", "cflow.icmp_ipv4_code",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IPv4 ICMP code", HFILL}
		},
		{&hf_cflow_icmp_ipv6_type,
		 {"IPv6 ICMP Type", "cflow.icmp_ipv6_type",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IPv6 ICMP type", HFILL}
		},
		{&hf_cflow_icmp_ipv6_code,
		 {"IPv6 ICMP Code", "cflow.icmp_ipv6_code",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IPv6 ICMP code", HFILL}
		},
		{&hf_cflow_tcp_window_size,
		 {"TCP Windows Size", "cflow.tcp_windows_size",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "TCP Windows size", HFILL}
		 },
		{&hf_cflow_ip_total_length,
		 {"IP Total Length", "cflow.ip_total_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "IP total length", HFILL}
		},
		{&hf_cflow_ip_ttl,
		 {"IP TTL", "cflow.ip_ttl",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IP time to live", HFILL}
		},
		{&hf_cflow_ip_tos,
		 {"IP TOS", "cflow.ip_tos",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IP type of service", HFILL}
		},
		{&hf_cflow_ip_dscp,
		 {"DSCP", "cflow.ip_dscp",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IP DSCP", HFILL}
		},
		{&hf_cflow_octets_squared64,
		 {"OctetsSquared", "cflow.octets_squared",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Octets Squared", HFILL}
		},
		{&hf_cflow_udp_length,
		 {"UDP Length", "cflow.udp_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "UDP length", HFILL}
		},
		{&hf_cflow_is_multicast,
		 {"IsMulticast", "cflow.is_multicast",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Is Multicast", HFILL}
		},
		{&hf_cflow_ip_header_words,
		 {"IPHeaderLen", "cflow.ip_header_words",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_option_map,
		 {"OptionMap", "cflow.option_map",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Option Map", HFILL}
		},
		{&hf_cflow_section_header ,
		 {"SectionHeader", "cflow.section_header",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Header of Packet", HFILL}
		 },
		{&hf_cflow_section_payload ,
		 {"SectionPayload", "cflow.section_payload",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Payload of Packet", HFILL}
		 },
		/* IPFIX Information Elements */
		{&hf_cflow_post_octets,
		 {"Post Octets", "cflow.post_octets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of post bytes", HFILL}
		},
		{&hf_cflow_post_octets64,
		 {"Post Octets", "cflow.post_octets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of post bytes", HFILL}
		},
		{&hf_cflow_post_packets,
		 {"Post Packets", "cflow.post_packets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of post packets", HFILL}
		},
		{&hf_cflow_post_packets64,
		 {"Post Packets", "cflow.post_packets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of post packets", HFILL}
		},
		{&hf_cflow_ipv6_flowlabel,
		 {"ipv6FlowLabel", "cflow.ipv6flowlabel",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "IPv6 Flow Label", HFILL}
		},
		{&hf_cflow_ipv6_flowlabel24,
		 {"ipv6FlowLabel", "cflow.ipv6flowlabel24",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "IPv6 Flow Label", HFILL}
		},
		{&hf_cflow_post_tos,
		 {"Post IP ToS", "cflow.post_tos",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "Post IP Type of Service", HFILL}
		},
		{&hf_cflow_srcmac,
		 {"Source Mac Address", "cflow.srcmac",
		  FT_ETHER, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_dstmac,
		 {"Post Destination Mac Address", "cflow.post_dstmac",
		  FT_ETHER, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_vlanid,
		 {"Vlan Id", "cflow.vlanid",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_vlanid,
		 {"Post Vlan Id", "cflow.post_vlanid",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_ipv6_exthdr,
		 {"IPv6 Extension Headers", "cflow.ipv6_exthdr",
		  FT_UINT32, BASE_HEX, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_dstmac,
		 {"Destination Mac Address", "cflow.dstmac",
		  FT_ETHER, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_srcmac,
		 {"Post Source Mac Address", "cflow.post_srcmac",
		  FT_ETHER, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_fragment_offset,
		 {"Fragment Offset", "cflow.fragment_offset",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_mpls_vpn_rd,
		 {"MPLS VPN RD", "cflow.mpls_vpn_rd",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "MPLS VPN Route Distinguisher", HFILL}
		},
		{&hf_cflow_mpls_top_label_prefix_length,
		 {"Mpls Top Label Prefix Length", "cflow.mpls_top_label_prefix_length",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Mpls Top Label Prefix Length", HFILL}
		},
		{&hf_cflow_post_ip_diff_serv_code_point,
		 {"Post Ip Diff Serv Code Point", "cflow.post_ip_diff_serv_code_point",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Post Ip Diff Serv Code Point", HFILL}
		},
		{&hf_cflow_multicast_replication_factor,
		 {"Multicast Replication Factor", "cflow.multicast_replication_factor",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Multicast Replication Factor", HFILL}
		},
		{&hf_cflow_exporter_addr,
		 {"ExporterAddr", "cflow.exporter_addr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Exporter Address", HFILL}
		},
		{&hf_cflow_exporter_addr_v6,
		 {"ExporterAddr", "cflow.exporter_addr_v6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Flow Exporter Address", HFILL}
		},
		{&hf_cflow_drop_octets,
		 {"Dropped Octets", "cflow.drop_octets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of dropped bytes", HFILL}
		},
		{&hf_cflow_drop_octets64,
		 {"Dropped Octets", "cflow.drop_octets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of dropped bytes", HFILL}
		},
		{&hf_cflow_drop_packets,
		 {"Dropped Packets", "cflow.drop_packets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of dropped packets", HFILL}
		},
		{&hf_cflow_drop_packets64,
		 {"Dropped Packets", "cflow.drop_packets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of dropped packets", HFILL}
		},
		{&hf_cflow_drop_total_octets,
		 {"Dropped Total Octets", "cflow.drop_total_octets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of total dropped bytes", HFILL}
		},
		{&hf_cflow_drop_total_octets64,
		 {"Dropped Total Octets", "cflow.drop_total_octets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of total dropped bytes", HFILL}
		},
		{&hf_cflow_drop_total_packets,
		 {"Dropped Total Packets", "cflow.drop_total_packets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of total dropped packets", HFILL}
		},
		{&hf_cflow_drop_total_packets64,
		 {"Dropped Total Packets", "cflow.drop_total_packets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of total dropped packets", HFILL}
		},
		{&hf_cflow_flow_end_reason,
		 {"Flow End Reason", "cflow.flow_end_reason",
		  FT_UINT8, BASE_DEC, VALS(v9_flow_end_reason), 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_common_properties_id,
		 {"Common Properties Id", "cflow.common_properties_id",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_observation_point_id,
		 {"Observation Point Id", "cflow.observation_point_id",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_mpls_pe_addr_v6,
		 {"TopLabelAddr", "cflow.toplabeladdr",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Top MPLS label PE address", HFILL}
		},
		{&hf_cflow_port_id,
		 {"Port Id", "cflow.port_id",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_mp_id,
		 {"Metering Process Id", "cflow.mp_id",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_wlan_channel_id,
		 {"Wireless LAN Channel Id", "cflow.wlan_channel_id",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_wlan_ssid,
		 {"Wireless LAN SSId", "cflow.wlan_ssid",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_flow_id,
		 {"Flow Id", "cflow.flow_id",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_od_id,
		 {"Observation Domain Id", "cflow.od_id",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Identifier of an Observation Domain that is locally unique to an Exporting Process", HFILL}
		},
		{&hf_cflow_abstimestart,
		 {"StartTime", "cflow.abstimestart",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  "Uptime at start of flow", HFILL}
		 },
		{&hf_cflow_abstimeend,
		 {"EndTime", "cflow.abstimeend",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  "Uptime at end of flow", HFILL}
		 },
		{&hf_cflow_dstnet_v6,
		 {"DstNet", "cflow.dstnetv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Flow Destination Network", HFILL}
		},
		{&hf_cflow_srcnet_v6,
		 {"SrcNet", "cflow.srcnetv6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Flow Source Network", HFILL}
		},
		{&hf_cflow_ignore_packets,
		 {"Ignored Packets", "cflow.ignore_packets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of ignored packets", HFILL}
		},
		{&hf_cflow_ignore_packets64,
		 {"Ignored Packets", "cflow.ignore_packets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of ignored packets", HFILL}
		},
		{&hf_cflow_ignore_octets,
		 {"Ignored Octets", "cflow.ignore_octets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of ignored octets", HFILL}
		},
		{&hf_cflow_ignore_octets64,
		 {"Ignored Octets", "cflow.ignore_octets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of ignored octets", HFILL}
		},
		{&hf_cflow_notsent_flows,
		 {"Not Sent Flows", "cflow.notsent_flows",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of not sent flows", HFILL}
		},
		{&hf_cflow_notsent_flows64,
		 {"Not Sent Flows", "cflow.notsent_flows64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of not sent flows", HFILL}
		},
		{&hf_cflow_notsent_packets,
		 {"Not Sent Packets", "cflow.notsent_packets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of not sent packets", HFILL}
		},
		{&hf_cflow_notsent_packets64,
		 {"Not Sent Packets", "cflow.notsent_packets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of not sent packets", HFILL}
		},
		{&hf_cflow_notsent_octets,
		 {"Not Sent Octets", "cflow.notsent_octets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of not sent octets", HFILL}
		},
		{&hf_cflow_notsent_octets64,
		 {"Not Sent Octets", "cflow.notsent_octets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of not sent octets", HFILL}
		},
		{&hf_cflow_post_total_octets,
		 {"Post Total Octets", "cflow.post_total_octets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of post total octets", HFILL}
		},
		{&hf_cflow_post_total_octets64,
		 {"Post Total Octets", "cflow.post_total_octets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of post total octets", HFILL}
		},
		{&hf_cflow_post_total_packets,
		 {"Post Total Packets", "cflow.post_total_packets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of post total packets", HFILL}
		},
		{&hf_cflow_post_total_packets64,
		 {"Post Total Packets", "cflow.post_total_packets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of post total packets", HFILL}
		},
		{&hf_cflow_key,
		 {"floKeyIndicator", "cflow.post_key",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Flow Key Indicator", HFILL}
		},
		{&hf_cflow_post_total_mulpackets,
		 {"Post Total Multicast Packets", "cflow.post_total_mulpackets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of post total multicast packets", HFILL}
		},
		{&hf_cflow_post_total_mulpackets64,
		 {"Post Total Multicast Packets", "cflow.post_total_mulpackets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of post total multicast packets", HFILL}
		},
		{&hf_cflow_post_total_muloctets,
		 {"Post Total Multicast Octets", "cflow.post_total_muloctets",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Count of post total multicast octets", HFILL}
		},
		{&hf_cflow_post_total_muloctets64,
		 {"Post Total Multicast Octets", "cflow.post_total_muloctets64",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of post total multicast octets", HFILL}
		},
		{&hf_cflow_tcp_seq_num,
		 {"TCP Sequence Number", "cflow.tcp_seq_num",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_tcp_ack_num,
		 {"TCP Acknowledgement Number", "cflow.tcp_seq_num",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_tcp_urg_ptr,
		 {"TCP Urgent Pointer", "cflow.tcp_urg_ptr",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_tcp_header_length,
		 {"TCP Header Length", "cflow.tcp_header_length",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "TCP header length", HFILL}
		},
		{&hf_cflow_ip_header_length,
		 {"IP Header Length", "cflow.ip_header_length",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IP header length", HFILL}
		},
		{&hf_cflow_ipv6_payload_length,
		 {"IPv6 Payload Length", "cflow.ipv6_payload_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "IPv6 payload length", HFILL}
		},
		{&hf_cflow_ipv6_next_hdr,
		 {"IPv6 Next Header", "cflow.ipv6_next_hdr",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IPv6 next header", HFILL}
		},
		{&hf_cflow_ip_precedence,
		 {"IP Precedence", "cflow.ip_precedence",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "IP precedence", HFILL}
		},
		{&hf_cflow_ip_fragment_flags,
		 {"IP Fragment Flags", "cflow.ip_fragment_flags",
		  FT_UINT8, BASE_HEX, NULL, 0x0,
		  "IP fragment flags", HFILL}
		 },
		{&hf_cflow_mpls_top_label_ttl,
		 {"MPLS Top Label TTL", "cflow.mpls_top_label_ttl",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "MPLS top label time to live", HFILL}
		},
		{&hf_cflow_mpls_label_length,
		 {"MPLS Label Stack Length", "cflow.mpls_label_length",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "The length of the MPLS label stac", HFILL}
		},
		{&hf_cflow_mpls_label_depth,
		 {"MPLS Label Stack Depth", "cflow.mpls_label_depth",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "The number of labels in the MPLS label stack", HFILL}
		},
		{&hf_cflow_ip_payload_length,
		 {"IP Payload Length", "cflow.ip_payload_length",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "IP payload length", HFILL}
		},
		{&hf_cflow_mpls_top_label_exp,
		 {"MPLS Top Label Exp", "cflow.mpls_top_label_exp",
		  FT_UINT8, BASE_OCT, NULL, 0x0,
		  "MPLS top label exp", HFILL}
		},
		{&hf_cflow_tcp_option_map,
		 {"TCP OptionMap", "cflow.tcp_option_map",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "TCP Option Map", HFILL}
		},
		{&hf_cflow_collector_addr,
		 {"CollectorAddr", "cflow.collector_addr",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Flow Collector Address", HFILL}
		},
		{&hf_cflow_collector_addr_v6,
		 {"CollectorAddr", "cflow.collector_addr_v6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Flow Collector Address", HFILL}
		},
		{&hf_cflow_export_interface,
		 {"ExportInterface", "cflow.export_interface",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Export Interface", HFILL}
		 },
		{&hf_cflow_export_protocol_version,
		 {"ExportProtocolVersion", "cflow.export_protocol_version",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Export Protocol Version", HFILL}
		 },
		{&hf_cflow_export_prot,
		 {"ExportTransportProtocol", "cflow.exporter_protocol",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Transport Protocol used by the Exporting Process", HFILL}
		 },
		{&hf_cflow_collector_port,
		 {"CollectorPort", "cflow.collector_port",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Collector Port", HFILL}
		 },
		{&hf_cflow_exporter_port,
		 {"ExporterPort", "cflow.exporter_port",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Flow Exporter Port", HFILL}
		 },
		{&hf_cflow_total_tcp_syn,
		 {"Total TCP syn", "cflow.total_tcp_syn",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of total TCP syn", HFILL}
		},
		{&hf_cflow_total_tcp_fin,
		 {"Total TCP fin", "cflow.total_tcp_fin",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of total TCP fin", HFILL}
		},
		{&hf_cflow_total_tcp_rst,
		 {"Total TCP rst", "cflow.total_tcp_rst",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of total TCP rst", HFILL}
		},
		{&hf_cflow_total_tcp_psh,
		 {"Total TCP psh", "cflow.total_tcp_psh",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of total TCP psh", HFILL}
		},
		{&hf_cflow_total_tcp_ack,
		 {"Total TCP ack", "cflow.total_tcp_ack",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of total TCP ack", HFILL}
		},
		{&hf_cflow_total_tcp_urg,
		 {"Total TCP urg", "cflow.total_tcp_urg",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "Count of total TCP urg", HFILL}
		},
		{&hf_cflow_ip_total_length64,
		 {"IP Total Length", "cflow.ip_total_length",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  "IP total length", HFILL}
		},
		{&hf_cflow_post_natsource_ipv4_address,
		 {"Post NAT Source IPv4 Address", "cflow.post_natsource_ipv4_address",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_natdestination_ipv4_address,
		 {"Post NAT Destination IPv4 Address", "cflow.post_natdestination_ipv4_address",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_naptsource_transport_port,
		 {"Post NAPT Source Transport Port", "cflow.post_naptsource_transport_port",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_naptdestination_transport_port,
		 {"Post NAPT Destination Transport Port", "cflow.post_naptdestination_transport_port",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_nat_originating_address_realm,
		 {"Nat Originating Address Realm", "cflow.nat_originating_address_realm",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_nat_event,
		 {"Nat Event", "cflow.nat_event",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_initiator_octets,
		 {"Initiator Octets", "cflow.initiator_octets",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_responder_octets,
		 {"Responder Octets", "cflow.responder_octets",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_firewall_event,
		 {"Firewall Event", "cflow.firewall_event",
		  FT_UINT8, BASE_DEC, VALS(v9_firewall_event), 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_ingress_vrfid,
		 {"Ingress VRFID", "cflow.ingress_vrfid",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_egress_vrfid,
		 {"Egress VRFID", "cflow.egress_vrfid",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_vrfname,
		 {"VRFname", "cflow.vrfname",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_mpls_top_label_exp,
		 {"Post Mpls Top Label Exp", "cflow.post_mpls_top_label_exp",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_tcp_window_scale,
		 {"Tcp Window Scale", "cflow.tcp_window_scale",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_biflow_direction,
		 {"Biflow Direction", "cflow.biflow_direction",
		  FT_UINT8, BASE_DEC, VALS(v9_biflow_direction), 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_ethernet_header_length,
		 {"Ethernet Header Length", "cflow.ethernet_header_length",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_ethernet_payload_length,
		 {"Ethernet Payload Length", "cflow.ethernet_payload_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_ethernet_total_length,
		 {"Ethernet Total Length", "cflow.ethernet_total_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_dot1q_vlan_id,
		 {"Dot1q Vlan Id", "cflow.dot1q_vlan_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_dot1q_priority,
		 {"Dot1q Priority", "cflow.dot1q_priority",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_dot1q_customer_vlan_id,
		 {"Dot1q Customer Vlan Id", "cflow.dot1q_customer_vlan_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_dot1q_customer_priority,
		 {"Dot1q Customer Priority", "cflow.dot1q_customer_priority",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_metro_evc_id,
		 {"Metro Evc Id", "cflow.metro_evc_id",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_metro_evc_type,
		 {"Metro Evc Type", "cflow.metro_evc_type",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_pseudo_wire_id,
		 {"Pseudo Wire Id", "cflow.pseudo_wire_id",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_pseudo_wire_type,
		 {"Pseudo Wire Type", "cflow.pseudo_wire_type",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_pseudo_wire_control_word,
		 {"Pseudo Wire Control Word", "cflow.pseudo_wire_control_word",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_ingress_physical_interface,
		 {"Ingress Physical Interface", "cflow.ingress_physical_interface",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_egress_physical_interface,
		 {"Egress Physical Interface", "cflow.egress_physical_interface",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_dot1q_vlan_id,
		 {"Post Dot1q Vlan Id", "cflow.post_dot1q_vlan_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_dot1q_customer_vlan_id,
		 {"Post Dot1q Customer Vlan Id", "cflow.post_dot1q_customer_vlan_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_ethernet_type,
		 {"Ethernet Type", "cflow.ethernet_type",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_post_ip_precedence,
		 {"Post Ip Precedence", "cflow.post_ip_precedence",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_collection_time_milliseconds,
		 {"Collection Time Milliseconds", "cflow.collection_time_milliseconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_export_sctp_stream_id,
		 {"Export Sctp Stream Id", "cflow.export_sctp_stream_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_max_export_seconds,
		 {"Max Export Seconds", "cflow.max_export_seconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_max_flow_end_seconds,
		 {"Max Flow End Seconds", "cflow.max_flow_end_seconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_message_md5_checksum,
		 {"Message MD5 Checksum", "cflow.message_md5_checksum",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_message_scope,
		 {"Message Scope", "cflow.message_scope",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_min_export_seconds,
		 {"Min Export Seconds", "cflow.min_export_seconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_min_flow_start_seconds,
		 {"Min Flow Start Seconds", "cflow.min_flow_start_seconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_opaque_octets,
		 {"Opaque Octets", "cflow.opaque_octets",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_session_scope,
		 {"Session Scope", "cflow.session_scope",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_max_flow_end_microseconds,
		 {"Max Flow End Microseconds", "cflow.max_flow_end_microseconds",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_max_flow_end_milliseconds,
		 {"Max Flow End Milliseconds", "cflow.max_flow_end_milliseconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_max_flow_end_nanoseconds,
		 {"Max Flow End Nanoseconds", "cflow.max_flow_end_nanoseconds",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_min_flow_start_microseconds,
		 {"Min Flow Start Microseconds", "cflow.min_flow_start_microseconds",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_min_flow_start_milliseconds,
		 {"Min Flow Start Milliseconds", "cflow.min_flow_start_milliseconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_min_flow_start_nanoseconds,
		 {"Min Flow Start Nanoseconds", "cflow.min_flow_start_nanoseconds",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_collector_certificate,
		 {"Collector Certificate", "cflow.collector_certificate",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_exporter_certificate,
		 {"Exporter Certificate", "cflow.exporter_certificate",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_selection_sequence_id,
		 {"Selection Sequence Id", "cflow.selection_sequence_id",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_selector_id,
		 {"Selector Id", "cflow.selector_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_information_element_id,
		 {"Information Element Id", "cflow.information_element_id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_selector_algorithm,
		 {"Selector Algorithm", "cflow.selector_algorithm",
		  FT_UINT16, BASE_DEC, VALS(selector_algorithm), 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_sampling_packet_interval,
		 {"Sampling Packet Interval", "cflow.sampling_packet_interval",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_sampling_packet_space,
		 {"Sampling Packet Space", "cflow.sampling_packet_space",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_sampling_time_interval,
		 {"Sampling Time Interval", "cflow.sampling_time_interval",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_sampling_time_space,
		 {"Sampling Time Space", "cflow.sampling_time_space",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_sampling_size,
		 {"Sampling Size", "cflow.sampling_size",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_sampling_population,
		 {"Sampling Population", "cflow.sampling_population",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_sampling_probability,
		 {"Sampling Probability", "cflow.sampling_probability",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_mpls_label_stack_section,
		 {"Mpls Label Stack Section", "cflow.mpls_label_stack_section",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_mpls_payload_packet_section,
		 {"Mpls Payload Packet Section", "cflow.mpls_payload_packet_section",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_selector_id_total_pkts_observed,
		 {"Selector Id Total Pkts Observed", "cflow.selector_id_total_pkts_observed",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_selector_id_total_pkts_selected,
		 {"Selector Id Total Pkts Selected", "cflow.selector_id_total_pkts_selected",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_absolute_error,
		 {"Absolute Error", "cflow.absolute_error",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_relative_error,
		 {"Relative Error", "cflow.relative_error",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_observation_time_seconds,
		 {"Observation Time Seconds", "cflow.observation_time_seconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_observation_time_milliseconds,
		 {"Observation Time Milliseconds", "cflow.observation_time_milliseconds",
		  FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_observation_time_microseconds,
		 {"Observation Time Microseconds", "cflow.observation_time_microseconds",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_observation_time_nanoseconds,
		 {"Observation Time Nanoseconds", "cflow.observation_time_nanoseconds",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_digest_hash_value,
		 {"Digest Hash Value", "cflow.digest_hash_value",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_hash_ippayload_offset,
		 {"Hash IPPayload Offset", "cflow.hash_ippayload_offset",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_hash_ippayload_size,
		 {"Hash IPPayload Size", "cflow.hash_ippayload_size",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_hash_output_range_min,
		 {"Hash Output Range Min", "cflow.hash_output_range_min",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_hash_output_range_max,
		 {"Hash Output Range Max", "cflow.hash_output_range_max",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_hash_selected_range_min,
		 {"Hash Selected Range Min", "cflow.hash_selected_range_min",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_hash_selected_range_max,
		 {"Hash Selected Range Max", "cflow.hash_selected_range_max",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_hash_digest_output,
		 {"Hash Digest Output", "cflow.hash_digest_output",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_hash_initialiser_value,
		 {"Hash Initialiser Value", "cflow.hash_initialiser_value",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_selector_name,
		 {"Selector Name", "cflow.selector_name",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_upper_cilimit,
		 {"Upper CILimit", "cflow.upper_cilimit",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_lower_cilimit,
		 {"Lower CILimit", "cflow.lower_cilimit",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_confidence_level,
		 {"Confidence Level", "cflow.confidence_level",
		  FT_FLOAT, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_information_element_data_type,
		 {"Information Element Data Type", "cflow.information_element_data_type",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_information_element_description,
		 {"Information Element Description", "cflow.information_element_description",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_information_element_name,
		 {"Information Element Name", "cflow.information_element_name",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_information_element_range_begin,
		 {"Information Element Range Begin", "cflow.information_element_range_begin",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_information_element_range_end,
		 {"Information Element Range End", "cflow.information_element_range_end",
		  FT_UINT64, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_information_element_semantics,
		 {"Information Element Semantics", "cflow.information_element_semantics",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_information_element_units,
		 {"Information Element Units", "cflow.information_element_units",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		{&hf_cflow_private_enterprise_number,
		 {"Private Enterprise Number", "cflow.private_enterprise_number",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL}
		},
		/*
		 * end pdu content storage
		 */
		{&hf_cflow_scope_system ,
		 {"ScopeSystem", "cflow.scope_system",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Option Scope System", HFILL}
		 },
		{&hf_cflow_scope_interface ,
		 {"ScopeInterface", "cflow.scope_interface",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Option Scope Interface", HFILL}
		 },
		{&hf_cflow_scope_linecard ,
		 {"ScopeLinecard", "cflow.scope_linecard",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Option Scope Linecard", HFILL}
		 },
		{&hf_cflow_scope_cache ,
		 {"ScopeCache", "cflow.scope_cache",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Option Scope Cache", HFILL}
		 },
		{&hf_cflow_scope_template ,
		 {"ScopeTemplate", "cflow.scope_template",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Option Scope Template", HFILL}
		 },
		/* IPFIX */
		{&hf_cflow_datarecord_length,
		 {"DataRecord Length", "cflow.datarecord_length",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "DataRecord length", HFILL}
		},
		{&hf_cflow_template_field_pen,
		 {"PEN",
		  "cflow.template_field_pen",
		  FT_UINT32, BASE_DEC, VALS(sminmpec_values), 0x0,
		  "Private Enterprise Number", HFILL}
		},
		{&hf_cflow_scope_unknown ,
		 {"Scope Unknown", "cflow.scope",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "Option Scope Unknown", HFILL}
		 },
		{&hf_cflow_field_count,
		 {"Field Count", "cflow.field_count",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Options Template Field Count", HFILL}
		 },
		{&hf_cflow_scope_field_count,
		 {"Scope Field Count", "cflow.scope_field_count",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Options Template Scope Field Count", HFILL}
		 },
		/* Cisco ASA 5500 Series */
		{&hf_cflow_ingress_acl_id,
		 {"Ingress ACL ID", "cflow.ingress_acl_id",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_egress_acl_id,
		 {"Egress ACL ID", "cflow.egress_acl_id",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_fw_ext_event,
		 {"Extended firewall event code", "cflow.fw_ext_event",
		  FT_UINT16, BASE_DEC, VALS(v9_extended_firewall_event), 0x0,
		  NULL, HFILL}
		 },
		{&hf_cflow_aaa_username,
		 {"AAA username", "cflow.aaa_username",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  NULL, HFILL}
		 },

                /* Private Information Elements */

		/* CACE Technologies, 32622 / 0 */
		{&hf_pie_cace_local_ipv4_address,
		 {"Local IPv4 Address", "cflow.pie.cace.localaddr4",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Local IPv4 Address (caceLocalIPv4Address)", HFILL}
		},
		/* CACE Technologies, 32622 / 1 */
		{&hf_pie_cace_remote_ipv4_address,
		 {"Remote IPv4 Address", "cflow.pie.cace.remoteaddr4",
		  FT_IPv4, BASE_NONE, NULL, 0x0,
		  "Remote IPv4 Address (caceRemoteIPv4Address)", HFILL}
		},
		/* CACE Technologies, 32622 / 2 */
		{&hf_pie_cace_local_ipv6_address,
		 {"Local IPv6 Address", "cflow.pie.cace.localaddr6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Local IPv6 Address (caceLocalIPv6Address)", HFILL}
		},
		/* CACE Technologies, 32622 / 3 */
		{&hf_pie_cace_remote_ipv6_address,
		 {"Remote IPv6 Address", "cflow.pie.cace.remoteaddr6",
		  FT_IPv6, BASE_NONE, NULL, 0x0,
		  "Remote IPv6 Address (caceRemoteIPv6Address)", HFILL}
		},
		/* CACE Technologies, 32622 / 4 */
		{&hf_pie_cace_local_port,
		 {"Local Port", "cflow.pie.cace.localport",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Local Transport Port (caceLocalTransportPort)", HFILL}
		},
		/* CACE Technologies, 32622 / 5 */
		{&hf_pie_cace_remote_port,
		 {"Remote Port", "cflow.pie.cace.remoteport",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "Remote Transport Port (caceRemoteTransportPort)", HFILL}
		},
		/* CACE Technologies, 32622 / 6 */
		{&hf_pie_cace_local_ipv4_id,
		 {"Local IPv4 ID", "cflow.pie.cace.localip4id",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "The IPv4 identification header field from a locally-originated packet (caceLocalIPv4id)", HFILL}
		},
		/* CACE Technologies, 32622 / 7 */
		{&hf_pie_cace_local_icmp_id,
		 {"Local ICMP ID", "cflow.pie.cace.localicmpid",
		  FT_UINT16, BASE_DEC, NULL, 0x0,
		  "The ICMP identification header field from a locally-originated ICMPv4 or ICMPv6 echo request (caceLocalICMPid)", HFILL}
		},
		/* CACE Technologies, 32622 / 8 */
		{&hf_pie_cace_local_uid,
		 {"Local User ID", "cflow.pie.cace.localuid",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Local User ID (caceLocalProcessUserId)", HFILL}
		},
		/* CACE Technologies, 32622 / 9 */
		{&hf_pie_cace_local_pid,
		 {"Local Process ID", "cflow.pie.cace.localpid",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "Local Process ID (caceLocalProcessId)", HFILL}
		},
		/* CACE Technologies, 32622 / 10 */
		{&hf_pie_cace_local_username_len,
		 {"Local Username Length", "cflow.pie.cace.localusernamelen",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Local User Name Length (caceLocalProcessUserName)", HFILL}
		},
		/* CACE Technologies, 32622 / 10 */
		{&hf_pie_cace_local_username,
		 {"Local User Name", "cflow.pie.cace.localusername",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  "Local User Name (caceLocalProcessUserName)", HFILL}
		},
		/* CACE Technologies, 32622 / 11 */
		{&hf_pie_cace_local_cmd_len,
		 {"Local Command Length", "cflow.pie.cace.localcmdlen",
		  FT_UINT8, BASE_DEC, NULL, 0x0,
		  "Local Command Length (caceLocalProcessCommand)", HFILL}
		},
		/* CACE Technologies, 32622 / 11 */
		{&hf_pie_cace_local_cmd,
		 {"Local Command", "cflow.pie.cace.localcmd",
		  FT_STRING, BASE_NONE, NULL, 0x0,
		  "Local Command (caceLocalProcessCommand)", HFILL}
		}

	};

	static gint    *ett[] = {
		&ett_netflow,
		&ett_unixtime,
		&ett_flow,
		&ett_flowtime,
		&ett_template,
		&ett_field,
		&ett_dataflowset,
		&ett_fwdstat
	};

	module_t *netflow_module;

	proto_netflow = proto_register_protocol("Cisco NetFlow/IPFIX", "CFLOW",
						"cflow");

	proto_register_field_array(proto_netflow, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* Register our configuration options for NetFlow */
	netflow_module = prefs_register_protocol(proto_netflow,
	    proto_reg_handoff_netflow);

	/* Set default Netflow port(s) */
	range_convert_str(&global_netflow_ports,NETFLOW_UDP_PORTS,
			  MAX_UDP_PORT);
	range_convert_str(&global_ipfix_ports, IPFIX_UDP_PORTS,
			  MAX_UDP_PORT);

	prefs_register_obsolete_preference(netflow_module, "udp.port");

	prefs_register_range_preference(netflow_module, "netflow.ports",
					"NetFlow UDP Port(s)",
					"Set the port(s) for NetFlow messages"
					" (default: " NETFLOW_UDP_PORTS ")",
					&global_netflow_ports, MAX_UDP_PORT);

	prefs_register_range_preference(netflow_module, "ipfix.ports",
					"IPFIX UDP/TCP/SCTP Port(s)",
					"Set the port(s) for IPFIX messages"
					" (default: " IPFIX_UDP_PORTS ")",
					&global_ipfix_ports, MAX_UDP_PORT);

	register_init_routine(&netflow_reinit);
}


/*
 * protocol/port association
 */
static void
netflow_delete_callback(guint32 port)
{
    if ( port ) {
	dissector_delete("udp.port", port, netflow_handle);
    }
}

static void
netflow_add_callback(guint32 port)
{
    if ( port ) {
	dissector_add("udp.port", port, netflow_handle);
    }
}

static void
ipfix_delete_callback(guint32 port)
{
    if ( port ) {
	dissector_delete("udp.port", port, netflow_handle);
	dissector_delete("tcp.port", port, netflow_handle);
	dissector_delete("sctp.port", port, netflow_handle);
    }
}

static void
ipfix_add_callback(guint32 port)
{
    if ( port ) {
	dissector_add("udp.port", port, netflow_handle);
	dissector_add("tcp.port", port, netflow_handle);
	dissector_add("sctp.port", port, netflow_handle);
    }
}

void
proto_reg_handoff_netflow(void)
{
	static gboolean netflow_prefs_initialized = FALSE;
	static range_t *netflow_ports;
	static range_t *ipfix_ports;

	if (!netflow_prefs_initialized) {
		netflow_handle = new_create_dissector_handle(dissect_netflow, proto_netflow);
		netflow_prefs_initialized = TRUE;
	} else {
		range_foreach(netflow_ports, netflow_delete_callback);
		g_free(netflow_ports);
		range_foreach(ipfix_ports, ipfix_delete_callback);
		g_free(ipfix_ports);
        }

	netflow_ports = range_copy(global_netflow_ports);
	ipfix_ports = range_copy(global_ipfix_ports);

	range_foreach(netflow_ports, netflow_add_callback);
	range_foreach(ipfix_ports, ipfix_add_callback);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * ex: set shiftwidth=8 tabstop=8 noexpandtab
 * :indentSize=8:tabSize=8:noTabs=false:
 */
