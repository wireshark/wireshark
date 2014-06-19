/* packet-vines.c
 * Routines for Banyan VINES protocol packet disassembly
 *
 * Don Lafontaine <lafont02@cn.ca>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer (see AUTHORS file)
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

/* Information about VINES can be found in
 *
 * VINES Protocol Definition
 * Order Number: DA254-00
 * Banyan Systems incorporated
 * February 1990
 * Part Number: 092093-000
 *
 * Banyan Systems are no longer in business, so that document cannot be
 * ordered from them.  An online copy appears to be available at
 *
 *	http://banyan-vines.bamertal.net/Banyan-supplier-help/ProtoDef/ProtoDefMain.htm
 *
 * along with the VINES Architecture Definition at
 *
 *	http://banyan-vines.bamertal.net/Banyan-supplier-help/ArchDef/ArchDefMain.htm
 *
 * and other VINES documentation linked to from
 *
 *	http://banyan-vines.bamertal.net/Banyan-supplier-help/banyan.htm
 *
 * Some information can also be found in
 *
 *	http://docwiki.cisco.com/wiki/Banyan_VINES
 *
 * and at
 *
 *	http://www.banalyzer.de/ban/HTML/P_VINES/Eng/P_vines.html
 *
 * The document at
 *
 *	http://www.watersprings.org/pub/id/draft-ietf-rmonmib-rmonprot-v2-00.txt
 *
 * lists a bunch of values of protocol identifier fields for various
 * protocols.  It speaks of the Vines Fragmentation Protocol,
 * the "Vines Token Ring Protocol" which appears to be the same as the
 * "Vines LLC" protocol here, the Vines echo protocol, Vines IP, and
 * protocols running atop Vines IP.
 *
 * The LLC values it describes are:
 *
 *	0xbc	(SAP_VINES2) Vines Token Ring a/k/a Vines LLC
 *
 * It doesn't mention 0xba (SAP_VINES1).
 *
 * The Vines Token Ring/Vines LLC protocol identifier values it
 * describes are:
 *
 *	0xba	Vines IP
 *	0xbb	Vines Echo
 *
 * The Ethernet type values it describes are:
 *
 *	0x0bad	(ETHERTYPE_VINES) Vines IP
 *	0x0baf	Vines Echo
 */

#include "config.h"

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-vines.h"
#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/ipproto.h>
#include <epan/arcnet_pids.h>
#include <epan/llcsaps.h>
#include <epan/to_str.h>

void proto_register_vines_frp(void);
void proto_reg_handoff_vines_frp(void);
void proto_register_vines_llc(void);
void proto_reg_handoff_vines_llc(void);
void proto_register_vines_ip(void);
void proto_reg_handoff_vines_ip(void);
void proto_register_vines_echo(void);
void proto_reg_handoff_vines_echo(void);
void proto_register_vines_ipc(void);
void proto_reg_handoff_vines_ipc(void);
void proto_register_vines_spp(void);
void proto_reg_handoff_vines_spp(void);
void proto_register_vines_arp(void);
void proto_reg_handoff_vines_arp(void);
void proto_register_vines_rtp(void);
void proto_reg_handoff_vines_rtp(void);
void proto_register_vines_icp(void);
void proto_reg_handoff_vines_icp(void);


#define UDP_PORT_VINES	573

static int proto_vines_frp = -1;
static int hf_vines_frp_flags = -1;
static int hf_vines_frp_flags_first_fragment = -1;
static int hf_vines_frp_flags_last_fragment = -1;
static int hf_vines_frp_sequence_number = -1;

static gint ett_vines_frp = -1;
static gint ett_vines_frp_flags = -1;

static int proto_vines_llc = -1;
static int hf_vines_llc_packet_type = -1;

static gint ett_vines_llc = -1;

static int proto_vines_ip = -1;
static int hf_vines_ip_protocol = -1;
static int hf_vines_ip_checksum = -1;
static int hf_vines_ip_length = -1;
static int hf_vines_ip_source = -1;
static int hf_vines_ip_destination = -1;
static int hf_vines_tctl = -1;
static int hf_vines_tctl_node = -1;
static int hf_vines_tctl_class = -1;
static int hf_vines_tctl_forward_router = -1;
static int hf_vines_tctl_metric = -1;
static int hf_vines_tctl_notif_packet = -1;
static int hf_vines_tctl_hop_count = -1;

static gint ett_vines_ip = -1;
static gint ett_vines_ip_tctl = -1;

static int proto_vines_echo = -1;

static gint ett_vines_echo = -1;

static int proto_vines_ipc = -1;
static int hf_vines_ipc_src_port = -1;
static int hf_vines_ipc_dest_port = -1;
static int hf_vines_ipc_packet_type = -1;
static int hf_vines_ipc_control = -1;
static int hf_vines_ipc_control_ack = -1;
static int hf_vines_ipc_control_end_msg = -1;
static int hf_vines_ipc_control_beg_msg = -1;
static int hf_vines_ipc_control_abort_msg = -1;
static int hf_vines_ipc_local_connection_id = -1;
static int hf_vines_ipc_sequence_number = -1;
static int hf_vines_ipc_length = -1;
static int hf_vines_ipc_remote_connection_id = -1;
static int hf_vines_ipc_ack_number = -1;
static int hf_vines_ipc_error = -1;

static gint ett_vines_ipc = -1;
static gint ett_vines_ipc_control = -1;

static int proto_vines_spp = -1;
static int hf_vines_spp_src_port = -1;
static int hf_vines_spp_dest_port = -1;
static int hf_vines_spp_packet_type = -1;
static int hf_vines_spp_control = -1;
static int hf_vines_spp_control_ack = -1;
static int hf_vines_spp_control_end_msg = -1;
static int hf_vines_spp_control_beg_msg = -1;
static int hf_vines_spp_control_abort_msg = -1;
static int hf_vines_spp_local_id = -1;
static int hf_vines_spp_remote_id = -1;
static int hf_vines_spp_seq_num = -1;
static int hf_vines_spp_ack_num = -1;
static int hf_vines_spp_window = -1;

static gint ett_vines_spp = -1;
static gint ett_vines_spp_control = -1;

static int proto_vines_arp = -1;
static int hf_vines_arp_address = -1;
static int hf_vines_arp_version = -1;
static int hf_vines_arp_packet_type = -1;
static int hf_vines_arp_interface_metric = -1;
static int hf_vines_arp_sequence_number = -1;

static gint ett_vines_arp = -1;

static int proto_vines_rtp = -1;
static int hf_vines_rtp_comp_flag = -1;
static int hf_vines_rtp_comp_flag_neighbor_router = -1;
static int hf_vines_rtp_comp_flag_sequence_rtp = -1;
static int hf_vines_rtp_comp_flag_sequence_rtp_version = -1;
static int hf_vines_rtp_control = -1;
static int hf_vines_rtp_control_sync_broadcast = -1;
static int hf_vines_rtp_control_topology_update = -1;
static int hf_vines_rtp_control_specific_request = -1;
static int hf_vines_rtp_control_end_msg = -1;
static int hf_vines_rtp_control_beg_msg = -1;
static int hf_vines_rtp_machine_rtp = -1;
static int hf_vines_rtp_machine_tcpip = -1;
static int hf_vines_rtp_machine_bus = -1;
static int hf_vines_rtp_flag_sequence_rtp = -1;
static int hf_vines_rtp_flag_network_p2p = -1;
static int hf_vines_rtp_flag_data_link_p2p = -1;
static int hf_vines_rtp_flag_broadcast_medium = -1;
static int hf_vines_rtp_metric_to_preferred_gateway = -1;
static int hf_vines_rtp_requested_info = -1;
static int hf_vines_rtp_metric_to_destination = -1;
static int hf_vines_rtp_source_route_length = -1;
static int hf_vines_rtp_router_sequence_number = -1;
static int hf_vines_rtp_sequence_number = -1;
static int hf_vines_rtp_data_offset = -1;
static int hf_vines_rtp_preferred_gateway_sequence_number = -1;
static int hf_vines_rtp_preferred_gateway_node_type = -1;
static int hf_vines_rtp_metric = -1;
static int hf_vines_rtp_destination_sequence_number = -1;
static int hf_vines_rtp_link_address_length = -1;
static int hf_vines_rtp_controller_type = -1;
static int hf_vines_rtp_destination_node_type = -1;
static int hf_vines_rtp_information_type = -1;
static int hf_vines_rtp_version = -1;
static int hf_vines_rtp_preferred_gateway = -1;
static int hf_vines_rtp_neighbor_metric = -1;
static int hf_vines_rtp_destination = -1;
static int hf_vines_rtp_node_type = -1;
static int hf_vines_rtp_operation_type = -1;
static int hf_vines_rtp_packet_id = -1;
static int hf_vines_rtp_network_number = -1;
static int hf_vines_rtp_machine_type = -1;
static int hf_vines_rtp_destination_controller_type = -1;
static int hf_vines_rtp_destination_machine = -1;
static int hf_vines_rtp_pref_gateway_controller_type = -1;
static int hf_vines_rtp_pref_gateway_machine = -1;
static int hf_vines_rtp_network_flags = -1;
static int hf_vines_rtp_destination_flags = -1;
static int hf_vines_rtp_preferred_gateway_flags = -1;
static int hf_vines_rtp_preferred_gateway_data_link_address_ether = -1;
static int hf_vines_rtp_preferred_gateway_data_link_address_bytes = -1;
static int hf_vines_rtp_preferred_gateway_source_route = -1;

static gint ett_vines_rtp = -1;
static gint ett_vines_rtp_compatibility_flags = -1;
static gint ett_vines_rtp_req_info = -1;
static gint ett_vines_rtp_control_flags = -1;
static gint ett_vines_rtp_mtype = -1;
static gint ett_vines_rtp_flags = -1;

static int proto_vines_icp = -1;
static int hf_vines_icp_exception_code = -1;
static int hf_vines_icp_metric = -1;
static int hf_vines_icp_packet_type = -1;

static gint ett_vines_icp = -1;

/* VINES IP structs and definitions */

enum {
  VIP_PROTO_IPC = 1,	 /* Interprocess Communications Protocol (IPC) */
  VIP_PROTO_SPP = 2,	/* Sequenced Packet Protcol (SPP) */
  VIP_PROTO_ARP = 4,	/* Address Resolution Protocol (ARP) */
  VIP_PROTO_RTP = 5,	/* Routing Update Protocol (RTP) / SRTP (Sequenced RTP) */
  VIP_PROTO_ICP = 6	/* Internet Control Protocol (ICP) */
};

/* VINES SPP and IPC structs and definitions */

enum {
  PKTTYPE_DGRAM = 0,	/* Unreliable datagram */
  PKTTYPE_DATA = 1,	/* User Data */
  PKTTYPE_ERR = 2,	/* Error */
  PKTTYPE_DISC = 3,	/* Diconnect Request */
  PKTTYPE_PROBE = 4,	/* Probe (retransmit) */
  PKTTYPE_ACK = 5	/* Acknowledgement */
};

typedef struct _e_vspp {
  guint16 vspp_sport;
  guint16 vspp_dport;
  guint8  vspp_pkttype;
  guint8  vspp_control;
  guint16 vspp_lclid;	/* Local Connection ID */
  guint16 vspp_rmtid;	/* Remote Connection ID */
  guint16 vspp_seqno;	/* Sequence Number */
  guint16 vspp_ack;	/* Acknowledgement Number */
  guint16 vspp_win;
} e_vspp;

typedef struct _e_vipc {
  guint16 vipc_sport;
  guint16 vipc_dport;
  guint8  vipc_pkttype;
  guint8  vipc_control;
  guint16 vipc_lclid;	/* Local Connection ID */
  guint16 vipc_rmtid;	/* Remote Connection ID */
  guint16 vipc_seqno;	/* Sequence Number */
  guint16 vipc_ack;	/* Acknowledgement Number */
  guint16 vipc_err_len;
} e_vipc;

void
capture_vines(packet_counts *ld)
{
	ld->vines++;
}

static dissector_handle_t vines_ip_handle;
static dissector_handle_t data_handle;

/* Control flags */
#define VINES_FRP_FIRST_FRAGMENT	0x01
#define VINES_FRP_LAST_FRAGMENT		0x02

/* AFAIK Vines FRP (Fragmentation Protocol) is used on all media except
 * Ethernet and TR (and probably FDDI) - Fragmentation on these media types
 * is not possible
 * FIXME: Do we need to use this header with PPP too?
 */
static void
dissect_vines_frp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *vines_frp_tree;
	proto_item *ti;
	proto_tree *flags_tree;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines FRP");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_frp, tvb, 0, 2, ENC_NA);
		vines_frp_tree = proto_item_add_subtree(ti, ett_vines_frp);

		ti = proto_tree_add_item(vines_frp_tree, hf_vines_frp_flags, tvb, 0, 1, ENC_NA);
		flags_tree = proto_item_add_subtree(ti, ett_vines_frp_flags);
		proto_tree_add_item(flags_tree, hf_vines_frp_flags_first_fragment, tvb, 0, 1, ENC_NA);
		proto_tree_add_item(flags_tree, hf_vines_frp_flags_last_fragment, tvb, 0, 1, ENC_NA);

		proto_tree_add_item(vines_frp_tree, hf_vines_frp_sequence_number, tvb, 1, 1, ENC_LITTLE_ENDIAN);
	}

	/* Decode the "real" Vines now */
	next_tvb = tvb_new_subset_remaining(tvb, 2);
	call_dissector(vines_ip_handle, next_tvb, pinfo, tree);
}

static int
dissect_vines_frp_new(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *params _U_)
{
	if (pinfo->srcport != pinfo->destport) {
		/* Require that the source and destination ports be the
		 * port for Vines FRP. */
		return 0;
	}
	if (!tvb_bytes_exist(tvb, 0, 1)) {
		/* Too short to check the flags value. */
		return 0;
	}

	if ((tvb_get_guint8(tvb, 0) & ~(VINES_FRP_FIRST_FRAGMENT|VINES_FRP_LAST_FRAGMENT)) != 0) {
		/* Those are the only flags; if anything else is set, this
		 * is presumably not Vines FRP. */
		return 0;
	}
	dissect_vines_frp(tvb, pinfo, tree);
	return tvb_length(tvb);
}

void
proto_register_vines_frp(void)
{
	static hf_register_info hf[] = {
	  { &hf_vines_frp_flags,
	    { "Control Flags", "vines_frp.flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_frp_flags_first_fragment,
	    { "First fragment", "vines_frp.flags.first_fragment",
	      FT_BOOLEAN, 8, NULL, VINES_FRP_FIRST_FRAGMENT,
	      NULL, HFILL }},

	  { &hf_vines_frp_flags_last_fragment,
	    { "Last fragment", "vines_frp.flags.last_fragment",
	      FT_BOOLEAN, 8, NULL, VINES_FRP_LAST_FRAGMENT,
	      NULL, HFILL }},

	  { &hf_vines_frp_sequence_number,
	    { "Sequence Number", "vines_frp.sequence_number",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_vines_frp,
		&ett_vines_frp_flags
	};

	proto_vines_frp = proto_register_protocol(
	    "Banyan Vines Fragmentation Protocol", "Vines FRP", "vines_frp");
	proto_register_field_array(proto_vines_ip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_frp(void)
{
	dissector_handle_t vines_frp_handle, vines_frp_new_handle;

	vines_frp_handle = create_dissector_handle(dissect_vines_frp,
	    proto_vines_frp);
	dissector_add_uint("ip.proto", IP_PROTO_VINES, vines_frp_handle);

	vines_frp_new_handle = new_create_dissector_handle(dissect_vines_frp_new,
	    proto_vines_frp);
	dissector_add_uint("udp.port", UDP_PORT_VINES, vines_frp_new_handle);
}

static dissector_table_t vines_llc_dissector_table;

#define VINES_LLC_IP	0xba
#define VINES_LLC_ECHO	0xbb

static const value_string vines_llc_ptype_vals[] = {
	{ VINES_LLC_IP,   "Vines IP" },
	{ VINES_LLC_ECHO, "Vines Echo" },
	{ 0,              NULL }
};

static void
dissect_vines_llc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8   ptype;
	proto_tree *vines_llc_tree;
	proto_item *ti;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines LLC");
	col_clear(pinfo->cinfo, COL_INFO);

	ptype = tvb_get_guint8(tvb, 0);
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(ptype, vines_llc_ptype_vals,
		      "Unknown protocol 0x%02x"));
	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_llc, tvb, 0, 1, ENC_NA);
		vines_llc_tree = proto_item_add_subtree(ti, ett_vines_llc);

		proto_tree_add_item(vines_llc_tree, hf_vines_llc_packet_type, tvb, 0, 1, ENC_NA);
	}

	next_tvb = tvb_new_subset_remaining(tvb, 1);
	if (!dissector_try_uint(vines_llc_dissector_table, ptype,
	    next_tvb, pinfo, tree))
		call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_vines_llc(void)
{
	static hf_register_info hf[] = {
	  { &hf_vines_llc_packet_type,
	    { "Packet Type", "vines_llc.packet_type",
	      FT_UINT8, BASE_HEX, VALS(vines_llc_ptype_vals), 0x0,
	      NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_vines_llc,
	};

	proto_vines_llc = proto_register_protocol(
	    "Banyan Vines LLC", "Vines LLC", "vines_llc");
	proto_register_field_array(proto_vines_ip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	vines_llc_dissector_table = register_dissector_table("vines_llc.ptype",
	    "Vines LLC protocol", FT_UINT8, BASE_HEX);
}

void
proto_reg_handoff_vines_llc(void)
{
	dissector_handle_t vines_llc_handle;

	vines_llc_handle = create_dissector_handle(dissect_vines_llc,
	    proto_vines_llc);
	dissector_add_uint("llc.dsap", SAP_VINES2, vines_llc_handle);
}

static dissector_table_t vines_ip_dissector_table;

static const value_string class_vals[] = {
	{ 0x00, "Regardless of cost" },
	{ 0x10, "Without cost" },
	{ 0x20, "With low cost (>= 4800 bps)" },
	{ 0x30, "Via LAN" },
	{ 0,    NULL }
};

static const value_string proto_vals[] = {
	{ VIP_PROTO_IPC, "IPC" },
	{ VIP_PROTO_SPP, "SPP" },
	{ VIP_PROTO_ARP, "ARP" },
	{ VIP_PROTO_RTP, "RTP" },
	{ VIP_PROTO_ICP, "ICP" },
	{ 0,             NULL }
};

static const guint8 bcast_addr[VINES_ADDR_LEN] = {
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

static const true_false_string tfs_vine_tctl_router_all = { "Router nodes", "All nodes" };
static const true_false_string tfs_vine_tctl_forward_router = { "Can handle redirect packets", "Cannot handle redirect packets" };
static const true_false_string tfs_vine_tctl_return_not_return = { "Return", "Do not return" };

static void
dissect_vines_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int         offset = 0;
	guint16 vip_pktlen;
	guint8  vip_tctl;	/* Transport Control */
	guint8  vip_proto;
	proto_tree *vip_tree, *tctl_tree;
	proto_item *ti;
	const guint8     *dst_addr, *src_addr;
	gboolean is_broadcast = FALSE;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines IP");
	col_clear(pinfo->cinfo, COL_INFO);

	/* To do: check for runts, errs, etc. */

	/* capture the necessary parts of the header */
	vip_pktlen = tvb_get_ntohs(tvb, offset+2);
	vip_tctl = tvb_get_guint8(tvb, offset+3);
	vip_proto = tvb_get_guint8(tvb, offset+4);

	col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%02x)",
			val_to_str_const(vip_tctl, proto_vals, "Unknown VIP protocol"),
			vip_tctl);

	src_addr = tvb_get_ptr(tvb, offset+12, VINES_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_src, AT_VINES, VINES_ADDR_LEN, src_addr);
	SET_ADDRESS(&pinfo->src, AT_VINES, VINES_ADDR_LEN, src_addr);
	dst_addr = tvb_get_ptr(tvb, offset+6, VINES_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_dst, AT_VINES, VINES_ADDR_LEN, dst_addr);
	SET_ADDRESS(&pinfo->dst, AT_VINES, VINES_ADDR_LEN, dst_addr);

	/* helpers to transport control */
	if (memcmp(dst_addr, bcast_addr, VINES_ADDR_LEN) == 0)
		is_broadcast = TRUE;

	/*
	 * Adjust the length of this tvbuff to include only the Vines IP
	 * datagram.
	 */
	set_actual_length(tvb, vip_pktlen < 18 ? 18 : vip_pktlen);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_ip, tvb, offset, vip_pktlen, ENC_NA);
		vip_tree = proto_item_add_subtree(ti, ett_vines_ip);
		proto_tree_add_item(vip_tree, hf_vines_ip_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		proto_tree_add_item(vip_tree, hf_vines_ip_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;

		ti = proto_tree_add_item(vip_tree, hf_vines_tctl, tvb, offset, 1, ENC_BIG_ENDIAN);

		tctl_tree = proto_item_add_subtree(ti, ett_vines_ip_tctl);
		/*
		 * XXX - bit 0x80 is "Normal" if 0; what is it if 1?
		 */
		if (is_broadcast) {
			proto_tree_add_item(tctl_tree, hf_vines_tctl_node, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(tctl_tree, hf_vines_tctl_class, tvb, offset, 1, ENC_NA);
		} else {
			proto_tree_add_item(tctl_tree, hf_vines_tctl_forward_router, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(tctl_tree, hf_vines_tctl_metric, tvb, offset, 1, ENC_NA);
			proto_tree_add_item(tctl_tree, hf_vines_tctl_notif_packet, tvb, offset, 1, ENC_NA);
		}

		proto_tree_add_item(tctl_tree, hf_vines_tctl_hop_count, tvb, offset, 1, ENC_NA);
		offset += 1;

		proto_tree_add_item(vip_tree, hf_vines_ip_protocol, tvb, offset, 1, ENC_NA);
		offset += 1;

		proto_tree_add_item(vip_tree, hf_vines_ip_destination, tvb, offset, VINES_ADDR_LEN, ENC_NA);
		offset += 6;

		proto_tree_add_item(vip_tree, hf_vines_ip_source, tvb, offset, VINES_ADDR_LEN, ENC_NA);
		offset += 6;
	} else {
		offset += 18;
	}
	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if (!dissector_try_uint(vines_ip_dissector_table, vip_proto,
	    next_tvb, pinfo, tree))
		call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_vines_ip(void)
{
	static gint *ett[] = {
		&ett_vines_ip,
		&ett_vines_ip_tctl,
	};

	static hf_register_info hf[] = {
	  { &hf_vines_ip_protocol,
	    { "Protocol", "vines_ip.protocol",
	      FT_UINT8, BASE_HEX, VALS(proto_vals), 0x0,
	      "Vines protocol", HFILL }},

	  { &hf_vines_ip_checksum,
	    { "Packet checksum", "vines_ip.checksum",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ip_length,
	    { "Packet length", "vines_ip.length",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_tctl,
	    { "Transport control", "vines_ip.tctl",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_tctl_node,
	    { "Nodes", "vines_ip.tctl.node",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_tctl_router_all), 0x40,
	      NULL, HFILL }},

	  { &hf_vines_tctl_class,
	    { "Reachable", "vines_ip.tctl.class",
	      FT_UINT8, BASE_DEC, VALS(class_vals), 0x30,
	      NULL, HFILL }},

	  { &hf_vines_tctl_forward_router,
	    { "Forwarding Router", "vines_ip.tctl.forward_router",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_tctl_forward_router), 0x40,
	      NULL, HFILL }},

	  { &hf_vines_tctl_metric,
	    { "Metric notification packet", "vines_ip.tctl.metric",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_tctl_return_not_return), 0x20,
	      NULL, HFILL }},

	  { &hf_vines_tctl_notif_packet,
	    { "Exception notification packet", "vines_ip.tctl.notif_packet",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_tctl_return_not_return), 0x10,
	      NULL, HFILL }},

	  { &hf_vines_tctl_hop_count,
	    { "Hop count remaining", "vines_ip.tctl.hop_count",
	      FT_UINT8, BASE_DEC, NULL, 0x0F,
	      NULL, HFILL }},

	  { &hf_vines_ip_destination,
	     { "Destination", "vines_ip.destination",
	       FT_VINES, BASE_NONE, NULL, 0x0,
	       NULL, HFILL }},

	  { &hf_vines_ip_source,
	     { "Source", "vines_ip.source",
	       FT_VINES, BASE_NONE, NULL, 0x0,
	       NULL, HFILL }},
	};

	proto_vines_ip = proto_register_protocol("Banyan Vines IP", "Vines IP",
	    "vines_ip");
	proto_register_field_array(proto_vines_ip, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissector code */
	vines_ip_dissector_table = register_dissector_table("vines_ip.protocol",
	    "Vines protocol", FT_UINT8, BASE_HEX);

	vines_ip_handle = create_dissector_handle(dissect_vines_ip,
	    proto_vines_ip);
}

void
proto_reg_handoff_vines_ip(void)
{
	dissector_add_uint("ethertype", ETHERTYPE_VINES_IP, vines_ip_handle);
	dissector_add_uint("ppp.protocol", PPP_VINES, vines_ip_handle);
	dissector_add_uint("arcnet.protocol_id", ARCNET_PROTO_BANYAN,
	    vines_ip_handle);
	dissector_add_uint("vines_llc.ptype", VINES_LLC_IP, vines_ip_handle);
	data_handle = find_dissector("data");
}

static void
dissect_vines_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *vines_echo_tree = NULL;
	proto_item *ti;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines Echo");
	col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_echo, tvb, 0, -1, ENC_NA);
		vines_echo_tree = proto_item_add_subtree(ti, ett_vines_echo);
		proto_tree_add_text(vines_echo_tree, tvb, 0, -1, "Data");
	}
}

void
proto_register_vines_echo(void)
{
	static gint *ett[] = {
		&ett_vines_echo,
	};

	proto_vines_echo = proto_register_protocol(
	    "Banyan Vines Echo", "Vines Echo", "vines_echo");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_echo(void)
{
	dissector_handle_t vines_echo_handle;

	vines_echo_handle = create_dissector_handle(dissect_vines_echo,
	    proto_vines_echo);
	dissector_add_uint("vines_llc.ptype", VINES_LLC_ECHO, vines_echo_handle);
	dissector_add_uint("ethertype", ETHERTYPE_VINES_ECHO, vines_echo_handle);
}

static const value_string pkttype_vals[] = {
	{ PKTTYPE_DGRAM, "Datagram" },
	{ PKTTYPE_DATA,  "Data" },
	{ PKTTYPE_ERR,   "Error" },
	{ PKTTYPE_DISC,  "Disconnect" },
	{ PKTTYPE_PROBE, "Probe" },
	{ PKTTYPE_ACK,   "Ack" },
	{ 0,             NULL }
};

static heur_dissector_list_t vines_ipc_heur_subdissector_list;

static const value_string vipc_err_vals[] = {
	{ 151, "Bad socket descriptor" },
	{ 152, "Address already in use" },
	{ 153, "Invalid operation" },
	{ 154, "User address parameter fault" },
	{ 155, "Net/host unreachable" },
	{ 156, "Message overflow error" },
	{ 157, "Destination socket does not exist" },
	{ 158, "Address family does not exist" },
	{ 159, "Socket type does not exist" },
	{ 160, "Protocol does not exist" },
	{ 161, "No more sockets available" },
	{ 162, "No buffer space available" },
	{ 163, "Timeout event" },
	{ 164, "Operation not supported" },
	{ 165, "Resource not available" },
	{ 166, "Internal communication service failure" },
	{ 167, "Controller reset failure" },
	{ 0,   NULL }
};

static const true_false_string tfs_vine_ipc_send_not_send = { "Send", "Do not Send" };
static const true_false_string tfs_vine_ipc_abort_not_abort = { "Abort", "Do not abort" };

static void
dissect_vines_ipc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int          offset = 0;
	e_vipc       viph;
	proto_tree *vipc_tree = NULL, *control_tree;
	proto_item *ti;
	tvbuff_t *next_tvb;
    heur_dtbl_entry_t *hdtbl_entry;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VIPC");
	col_clear(pinfo->cinfo, COL_INFO);

	/* To do: check for runts, errs, etc. */

	/* Avoids alignment problems on many architectures. */
	tvb_memcpy(tvb, (guint8 *)&viph, offset, sizeof(e_vipc));

	viph.vipc_sport = g_ntohs(viph.vipc_sport);
	viph.vipc_dport = g_ntohs(viph.vipc_dport);
	viph.vipc_lclid = g_ntohs(viph.vipc_lclid);
	viph.vipc_rmtid = g_ntohs(viph.vipc_rmtid);
	viph.vipc_seqno = g_ntohs(viph.vipc_seqno);
	viph.vipc_ack = g_ntohs(viph.vipc_ack);
	viph.vipc_err_len = g_ntohs(viph.vipc_err_len);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines IPC");
	switch (viph.vipc_pkttype) {

	case PKTTYPE_DGRAM:
		col_add_fstr(pinfo->cinfo, COL_INFO,
				     "%s D=%04x S=%04x",
				     val_to_str(viph.vipc_pkttype, pkttype_vals,
				         "Unknown packet type (0x%02x)"),
				     viph.vipc_dport, viph.vipc_sport);
		break;

	case PKTTYPE_ERR:
		col_add_fstr(pinfo->cinfo, COL_INFO,
				     "%s NS=%u NR=%u Err=%s RID=%04x LID=%04x D=%04x S=%04x",
				     val_to_str(viph.vipc_pkttype, pkttype_vals,
				         "Unknown packet type (0x%02x)"),
				     viph.vipc_seqno, viph.vipc_ack,
				     val_to_str(viph.vipc_err_len,
				         vipc_err_vals, "Unknown (%u)"),
				     viph.vipc_rmtid, viph.vipc_lclid,
				     viph.vipc_dport, viph.vipc_sport);
		break;

	default:
		col_add_fstr(pinfo->cinfo, COL_INFO,
				     "%s NS=%u NR=%u Len=%u RID=%04x LID=%04x D=%04x S=%04x",
				     val_to_str(viph.vipc_pkttype, pkttype_vals,
				         "Unknown packet type (0x%02x)"),
				     viph.vipc_seqno, viph.vipc_ack,
				     viph.vipc_err_len, viph.vipc_rmtid,
				     viph.vipc_lclid, viph.vipc_dport,
				     viph.vipc_sport);
		break;
	}

	ti = proto_tree_add_item(tree, proto_vines_ipc, tvb, offset, sizeof(viph), ENC_NA);
	vipc_tree = proto_item_add_subtree(ti, ett_vines_ipc);

	proto_tree_add_item(vipc_tree, hf_vines_ipc_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(vipc_tree, hf_vines_ipc_dest_port, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(vipc_tree, hf_vines_ipc_packet_type, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset += 1;
	if (viph.vipc_pkttype != PKTTYPE_DGRAM) {
		ti = proto_tree_add_item(vipc_tree, hf_vines_ipc_control, tvb, offset, 1, ENC_BIG_ENDIAN);

		control_tree = proto_item_add_subtree(ti, ett_vines_ipc_control);
		/*
		 * XXX - do reassembly based on BOM/EOM bits.
		 */
		proto_tree_add_item(control_tree, hf_vines_ipc_control_ack, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(control_tree, hf_vines_ipc_control_end_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(control_tree, hf_vines_ipc_control_beg_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(control_tree, hf_vines_ipc_control_abort_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;
	if (viph.vipc_pkttype != PKTTYPE_DGRAM) {
		proto_tree_add_item(vipc_tree, hf_vines_ipc_local_connection_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(vipc_tree, hf_vines_ipc_remote_connection_id, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(vipc_tree, hf_vines_ipc_sequence_number, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(vipc_tree, hf_vines_ipc_ack_number, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		if (viph.vipc_pkttype == PKTTYPE_ERR) {
			proto_tree_add_item(vipc_tree, hf_vines_ipc_error, tvb, offset, 2, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(vipc_tree, hf_vines_ipc_length, tvb, offset, 2, ENC_BIG_ENDIAN);
		}
		offset += 2;
	}

	/*
	 * For data packets, try the heuristic dissectors for Vines SPP;
	 * if none of them accept the packet, or if it's not a data packet,
	 * dissect it as data.
	 */
	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if (viph.vipc_pkttype != PKTTYPE_DATA ||
	    !dissector_try_heuristic(vines_ipc_heur_subdissector_list,
	      next_tvb, pinfo, tree, &hdtbl_entry, NULL))
		call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_vines_ipc(void)
{
	static hf_register_info hf[] = {
	  { &hf_vines_ipc_src_port,
	    { "Source port", "vines_ipc.src_port",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_dest_port,
	    { "Destination port", "vines_ipc.dest_port",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_packet_type,
	    { "Packet type", "vines_ipc.packet_type",
	      FT_UINT8, BASE_HEX, VALS(pkttype_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_control,
	    { "Control", "vines_ipc.control",
	      FT_UINT8, BASE_HEX, VALS(pkttype_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_control_ack,
	    { "Immediate acknowledgment", "vines_ipc.control.ack",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_ipc_send_not_send), 0x80,
	      NULL, HFILL }},

	  { &hf_vines_ipc_control_end_msg,
	    { "End of message", "vines_ipc.control.end_msg",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
	      NULL, HFILL }},

	  { &hf_vines_ipc_control_beg_msg,
	    { "Beginning of message", "vines_ipc.control.beg_msg",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
	      NULL, HFILL }},

	  { &hf_vines_ipc_control_abort_msg,
	    { "Current message", "vines_ipc.control.abort_msg",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_ipc_abort_not_abort), 0x10,
	      NULL, HFILL }},

	  { &hf_vines_ipc_local_connection_id,
	    { "Local Connection ID", "vines_ipc.local_connection_id",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_remote_connection_id,
	    { "Remote Connection ID", "vines_ipc.remote_connection_id",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_sequence_number,
	    { "Sequence number", "vines_ipc.sequence_number",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_ack_number,
	    { "Ack number", "vines_ipc.ack_number",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_error,
	    { "Error", "vines_ipc.error",
	      FT_UINT16, BASE_DEC, VALS(vipc_err_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_ipc_length,
	    { "Length", "vines_ipc.length",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_vines_ipc,
		&ett_vines_ipc_control,
	};

	proto_vines_ipc = proto_register_protocol("Banyan Vines IPC",
	    "Vines IPC", "vines_ipc");
	proto_register_field_array(proto_vines_ipc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_heur_dissector_list("vines_ipc",
	    &vines_ipc_heur_subdissector_list);
}

void
proto_reg_handoff_vines_ipc(void)
{
	dissector_handle_t vines_ipc_handle;

	vines_ipc_handle = create_dissector_handle(dissect_vines_ipc,
	    proto_vines_ipc);
	dissector_add_uint("vines_ip.protocol", VIP_PROTO_IPC, vines_ipc_handle);
}

static heur_dissector_list_t vines_spp_heur_subdissector_list;

static void
dissect_vines_spp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int          offset = 0;
	e_vspp       viph;
	proto_tree  *vspp_tree, *control_tree;
	proto_item  *ti;
	tvbuff_t    *next_tvb;
    heur_dtbl_entry_t *hdtbl_entry;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "VSPP");
	col_clear(pinfo->cinfo, COL_INFO);

	/* To do: check for runts, errs, etc. */

	/* Avoids alignment problems on many architectures. */
	tvb_memcpy(tvb, (guint8 *)&viph, offset, sizeof(e_vspp));

	viph.vspp_sport = g_ntohs(viph.vspp_sport);
	viph.vspp_dport = g_ntohs(viph.vspp_dport);
	viph.vspp_lclid = g_ntohs(viph.vspp_lclid);
	viph.vspp_rmtid = g_ntohs(viph.vspp_rmtid);
	viph.vspp_seqno = g_ntohs(viph.vspp_seqno);
	viph.vspp_ack = g_ntohs(viph.vspp_ack);
	viph.vspp_win = g_ntohs(viph.vspp_win);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines SPP");
	col_add_fstr(pinfo->cinfo, COL_INFO,
			     "%s NS=%u NR=%u Window=%u RID=%04x LID=%04x D=%04x S=%04x",
			     val_to_str(viph.vspp_pkttype, pkttype_vals,
			         "Unknown packet type (0x%02x)"),
			     viph.vspp_seqno, viph.vspp_ack, viph.vspp_win,
			     viph.vspp_rmtid, viph.vspp_lclid, viph.vspp_dport,
			     viph.vspp_sport);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_spp, tvb, offset, sizeof(viph), ENC_NA);
		vspp_tree = proto_item_add_subtree(ti, ett_vines_spp);
		proto_tree_add_item(vspp_tree, hf_vines_spp_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(vspp_tree, hf_vines_spp_dest_port, tvb, offset+2, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(vspp_tree, hf_vines_spp_packet_type, tvb, offset+4, 1, ENC_BIG_ENDIAN);

		ti = proto_tree_add_item(vspp_tree, hf_vines_spp_control, tvb, offset+5, 1, ENC_BIG_ENDIAN);
		control_tree = proto_item_add_subtree(ti, ett_vines_spp_control);
		/*
		 * XXX - do reassembly based on BOM/EOM bits.
		 */
		proto_tree_add_item(control_tree, hf_vines_spp_control_ack, tvb, offset+5, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(control_tree, hf_vines_spp_control_end_msg, tvb, offset+5, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(control_tree, hf_vines_spp_control_beg_msg, tvb, offset+5, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(control_tree, hf_vines_spp_control_abort_msg, tvb, offset+5, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(vspp_tree, hf_vines_spp_local_id, tvb, offset+6, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(vspp_tree, hf_vines_spp_remote_id, tvb, offset+8, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(vspp_tree, hf_vines_spp_seq_num, tvb, offset+10, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(vspp_tree, hf_vines_spp_ack_num, tvb, offset+12, 2, ENC_BIG_ENDIAN);
		proto_tree_add_item(vspp_tree, hf_vines_spp_window, tvb, offset+14, 2, ENC_BIG_ENDIAN);
	} else {
		offset += 16; /* sizeof SPP */
	}
	/*
	 * For data packets, try the heuristic dissectors for Vines SPP;
	 * if none of them accept the packet, or if it's not a data packet,
	 * dissect it as data.
	 */
	next_tvb = tvb_new_subset_remaining(tvb, offset);
	if (viph.vspp_pkttype != PKTTYPE_DATA ||
	    !dissector_try_heuristic(vines_spp_heur_subdissector_list,
	      next_tvb, pinfo, tree, &hdtbl_entry, NULL))
		call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_vines_spp(void)
{
	static hf_register_info hf[] = {
	  { &hf_vines_spp_src_port,
	    { "Source port", "vines_spp.src_port",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_spp_dest_port,
	    { "Destination port", "vines_spp.dest_port",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_spp_packet_type,
	    { "Packet type", "vines_spp.packet_type",
	      FT_UINT8, BASE_HEX, VALS(pkttype_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_spp_control,
	    { "Control", "vines_spp.control",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_spp_control_ack,
	    { "Immediate acknowledgment", "vines_spp.control.ack",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_ipc_send_not_send), 0x80,
	      NULL, HFILL }},

	  { &hf_vines_spp_control_end_msg,
	    { "End of message", "vines_spp.control.end_msg",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x40,
	      NULL, HFILL }},

	  { &hf_vines_spp_control_beg_msg,
	    { "Beginning of message", "vines_spp.control.beg_msg",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x20,
	      NULL, HFILL }},

	  { &hf_vines_spp_control_abort_msg,
	    { "Current message", "vines_spp.control.abort_msg",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_ipc_abort_not_abort), 0x10,
	      NULL, HFILL }},

	  { &hf_vines_spp_local_id,
	    { "Local Connection ID", "vines_spp.local_id",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_spp_remote_id,
	    { "Remote Connection ID", "vines_spp.remote_id",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_spp_seq_num,
	    { "Sequence number", "vines_spp.seq_num",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_spp_ack_num,
	    { "Ack number", "vines_spp.ack_num",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_spp_window,
	    { "Window", "vines_spp.window",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }}
	};

	static gint *ett[] = {
		&ett_vines_spp,
		&ett_vines_spp_control,
	};

	proto_vines_spp = proto_register_protocol("Banyan Vines SPP",
	    "Vines SPP", "vines_spp");
	proto_register_field_array(proto_vines_spp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_heur_dissector_list("vines_spp",
	    &vines_spp_heur_subdissector_list);
}

void
proto_reg_handoff_vines_spp(void)
{
	dissector_handle_t vines_spp_handle;

	vines_spp_handle = create_dissector_handle(dissect_vines_spp,
	    proto_vines_spp);
	dissector_add_uint("vines_ip.protocol", VIP_PROTO_SPP, vines_spp_handle);
}

#define VINES_VERS_PRE_5_5	0x00
#define VINES_VERS_5_5		0x01

static const value_string vines_version_vals[] = {
	{ VINES_VERS_PRE_5_5, "Pre-5.50" },
	{ VINES_VERS_5_5,     "5.50" },
	{ 0,                  NULL }
};

#define VARP_QUERY_REQ		0x00
#define VARP_SERVICE_RESP	0x01
#define VARP_ASSIGNMENT_REQ	0x02
#define VARP_ASSIGNMENT_RESP	0x03

static const value_string vines_arp_packet_type_vals[] = {
	{ VARP_QUERY_REQ,       "Query request" },
	{ VARP_SERVICE_RESP,    "Service response" },
	{ VARP_ASSIGNMENT_REQ,  "Assignment request" },
	{ VARP_ASSIGNMENT_RESP, "Assignment response" },
	{ 0,                    NULL }
};

static void
dissect_vines_arp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *vines_arp_tree;
	proto_item *ti;
	guint8   version;
	guint16  packet_type;
	guint16  metric;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines ARP");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_vines_arp, tvb, 0, -1, ENC_NA);
	vines_arp_tree = proto_item_add_subtree(ti, ett_vines_arp);

	version = tvb_get_guint8(tvb, 0);
	proto_tree_add_item(vines_arp_tree, hf_vines_arp_version, tvb, 0, 1, ENC_NA);

	if (version == VINES_VERS_5_5) {
		/*
		 * Sequenced ARP.
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines SARP");
		packet_type = tvb_get_guint8(tvb, 1);
		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(packet_type, vines_arp_packet_type_vals,
			      "Unknown (0x%02x)"));

		proto_tree_add_item(vines_arp_tree, hf_vines_arp_packet_type, tvb, 1, 1, ENC_NA);

		if (packet_type == VARP_ASSIGNMENT_RESP) {
			col_append_fstr(pinfo->cinfo, COL_INFO,
					    ", Address = %s",
					    tvb_vines_addr_to_str(tvb, 2));
			proto_tree_add_item(vines_arp_tree, hf_vines_arp_address, tvb, 2, VINES_ADDR_LEN, ENC_NA);
		}
		proto_tree_add_item(vines_arp_tree, hf_vines_arp_sequence_number, tvb, 2+VINES_ADDR_LEN, 4, ENC_BIG_ENDIAN);
		metric = tvb_get_ntohs(tvb, 2+VINES_ADDR_LEN+4);
		proto_tree_add_uint_format_value(vines_arp_tree, hf_vines_arp_interface_metric, tvb,
					    2+VINES_ADDR_LEN+4, 2, metric,
					    "%u ticks (%g seconds)",
					    metric, metric*.2);
	} else {
		/*
		 * Non-sequenced ARP.
		 */
		packet_type = (guint8) tvb_get_ntohs(tvb, 0);
		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(packet_type, vines_arp_packet_type_vals,
			      "Unknown (0x%02x)"));
		proto_tree_add_item(vines_arp_tree, hf_vines_arp_packet_type, tvb, 0, 2, ENC_BIG_ENDIAN);

		if (packet_type == VARP_ASSIGNMENT_RESP) {
			col_append_fstr(pinfo->cinfo, COL_INFO,
					    ", Address = %s",
					    tvb_vines_addr_to_str(tvb, 2));

			proto_tree_add_item(vines_arp_tree, hf_vines_arp_address, tvb, 2, VINES_ADDR_LEN, ENC_NA);
		}
	}
}

void
proto_register_vines_arp(void)
{
	static hf_register_info hf[] = {
	  { &hf_vines_arp_version,
	    { "Version", "vines_arp.version",
	      FT_UINT8, BASE_HEX, VALS(vines_version_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_arp_packet_type,
	    { "Packet Type", "vines_arp.packet_type",
	      FT_UINT8, BASE_HEX, VALS(vines_arp_packet_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_arp_address,
	    { "Address", "vines_arp.address",
	      FT_VINES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_arp_sequence_number,
	    { "Sequence Number", "vines_arp.sequence_number",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_arp_interface_metric,
	    { "Interface Metric", "vines_arp.interface_metric",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_vines_arp,
	};

	proto_vines_arp = proto_register_protocol(
	    "Banyan Vines ARP", "Vines ARP", "vines_arp");
	proto_register_field_array(proto_vines_spp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_arp(void)
{
	dissector_handle_t vines_arp_handle;

	vines_arp_handle = create_dissector_handle(dissect_vines_arp,
	    proto_vines_arp);
	dissector_add_uint("vines_ip.protocol", VIP_PROTO_ARP, vines_arp_handle);
}

#define VRTP_OP_REQUEST		0x01
#define VRTP_OP_UPDATE_RESPONSE	0x02
#define VRTP_OP_REDIRECT	0x03
#define VRTP_OP_REINITIALIZE	0x04
#define VRTP_OP_REDIRECT2	0x06

static const value_string vines_rtp_operation_type_vals[] = {
	{ VRTP_OP_REQUEST,         "Request" },
	{ VRTP_OP_UPDATE_RESPONSE, "Update/response" },
	{ VRTP_OP_REDIRECT,        "Redirect" },
	{ VRTP_OP_REINITIALIZE,    "Reinitialize" },
	{ VRTP_OP_REDIRECT2,       "Redirect" },
	{ 0,                       NULL }
};

static const value_string vines_rtp_node_type_vals[] = {
	{ 0x01, "Host" },
	{ 0x02, "Router" },
	{ 0,    NULL }
};

static const value_string vines_rtp_controller_type_vals[] = {
	{ 0x00, "Default Card" },
	{ 0x01, "Multibuffer" },
	{ 0,    NULL }
};

static const value_string vines_rtp_info_type_vals[] = {
	{ 0x00, "Update" },
	{ 0x01, "Update" },
	{ 0x02, "Response" },
	{ 0,    NULL }
};

static const true_false_string tfs_vine_auto_config_not_auto_config = { "Auto-configured", "Not an auto-configured" };
static const true_false_string tfs_vine_rtp_not_all_neighbor_all_neighbor = { "Not all neighbor routers support", "All neighbor routers support" };
static const true_false_string tfs_vine_rtp_sequenced_not_sequenced = { "Sequenced", "Not Sequenced" };
static const true_false_string tfs_part_not_part = { "Part of", "Not part of" };
static const true_false_string tfs_fast_bus_slow_bus = { "Fast bus", "Slow bus" };
static const true_false_string tfs_vine_rtp_no_yes = { "No", "Yes" };

static void
rtp_show_machine_type(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_machine)
{
	proto_item *ti;
	proto_tree *subtree;

	ti = proto_tree_add_item(tree, hf_machine, tvb, offset, 1, ENC_NA);
	subtree = proto_item_add_subtree(ti, ett_vines_rtp_mtype);
	proto_tree_add_item(subtree, hf_vines_rtp_machine_rtp,
						tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_vines_rtp_machine_tcpip,
						tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(subtree, hf_vines_rtp_machine_bus,
						tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
rtp_show_flags(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_flag)
{
	proto_item *ti;
	proto_tree *flags_tree;

	ti = proto_tree_add_item(tree, hf_flag, tvb, offset, 1, ENC_NA);
	flags_tree = proto_item_add_subtree(ti, ett_vines_rtp_flags);
	proto_tree_add_item(flags_tree, hf_vines_rtp_flag_sequence_rtp,
						tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flags_tree, hf_vines_rtp_flag_network_p2p,
						tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flags_tree, hf_vines_rtp_flag_data_link_p2p,
						tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(flags_tree, hf_vines_rtp_flag_broadcast_medium,
						tvb, offset, 1, ENC_BIG_ENDIAN);
}

static int
srtp_show_machine_info(proto_tree *tree, tvbuff_t *tvb, int offset, int hf_vines,
						int hf_metric, int hf_nodetype, int hf_controller_type, int hf_machine)
{
	guint16 metric;

	proto_tree_add_item(tree, hf_vines, tvb, offset, VINES_ADDR_LEN, ENC_NA);
	offset += VINES_ADDR_LEN;
	metric = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint_format_value(tree, hf_metric, tvb,
						    offset, 2, metric,
						    "%u ticks (%g seconds)",
						    metric, metric*.2);
	offset += 2;
	proto_tree_add_item(tree, hf_nodetype, tvb, offset, 1, ENC_NA);
	offset += 1;
	rtp_show_machine_type(tree, tvb, offset, hf_machine);
	offset += 1;
	proto_tree_add_item(tree, hf_controller_type, tvb, offset, 1, ENC_NA);
	offset += 1;
	return offset;
}

static int
rtp_show_gateway_info(proto_tree *tree, tvbuff_t *tvb, int offset,
    guint8 link_addr_length, guint8 source_route_length)
{
	if (link_addr_length != 0) {
		proto_tree_add_item(tree,
            link_addr_length == 6 ? hf_vines_rtp_preferred_gateway_data_link_address_ether : hf_vines_rtp_preferred_gateway_data_link_address_bytes,
            tvb, offset, link_addr_length, ENC_NA);
		offset += link_addr_length;
	}
	if (source_route_length != 0) {
		proto_tree_add_item(tree, hf_vines_rtp_preferred_gateway_source_route, tvb, offset, source_route_length, ENC_NA);
		offset += source_route_length;
	}
	return offset;
}

static void
dissect_vines_rtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_tree *vines_rtp_tree = NULL;
	proto_item *ti;
	proto_tree *subtree;
	guint8   operation_type;
	guint8   link_addr_length;
	guint8   source_route_length;
	guint16  metric;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines RTP");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_vines_rtp, tvb, 0, -1, ENC_NA);
	vines_rtp_tree = proto_item_add_subtree(ti, ett_vines_rtp);

	if (tvb_get_guint8(tvb, 0) != 0) {
		/*
		 * Non-sequenced RTP.
		 */
		operation_type = tvb_get_guint8(tvb, offset);
		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(operation_type, vines_rtp_operation_type_vals,
			      "Unknown (0x%02x)"));

		if (tree) {
			proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_operation_type, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_node_type, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_controller_type, tvb, offset, 1, ENC_NA);
			offset += 1;
			rtp_show_machine_type(vines_rtp_tree, tvb, offset, hf_vines_rtp_machine_type);
			offset += 1;
			switch (operation_type) {

			case VRTP_OP_REDIRECT:
			case VRTP_OP_REDIRECT2:
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				link_addr_length = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_link_address_length, tvb, offset, 1, ENC_NA);
				offset += 1;
				source_route_length = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_source_route_length, tvb, offset, 1, ENC_NA);
				offset += 1;
				offset = srtp_show_machine_info(vines_rtp_tree, tvb, offset, hf_vines_rtp_destination,
							hf_vines_rtp_metric_to_destination, hf_vines_rtp_destination_node_type,
							hf_vines_rtp_destination_controller_type, hf_vines_rtp_destination_machine);
				offset += 1;
				offset = srtp_show_machine_info(vines_rtp_tree, tvb, offset, hf_vines_rtp_preferred_gateway,
							hf_vines_rtp_metric_to_preferred_gateway, hf_vines_rtp_preferred_gateway_node_type,
							hf_vines_rtp_pref_gateway_controller_type, hf_vines_rtp_pref_gateway_machine);
				offset += 1;
				rtp_show_gateway_info(vines_rtp_tree, tvb,offset, link_addr_length, source_route_length);
				break;

			default:
				while (tvb_reported_length_remaining(tvb, offset) > 0) {
					proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_network_number, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					metric = tvb_get_ntohs(tvb, offset);
					proto_tree_add_uint_format_value(vines_rtp_tree, hf_vines_rtp_neighbor_metric, tvb,
						    offset, 2, metric,
						    "%u ticks (%g seconds)",
						    metric,
						    metric*.2);
					offset += 2;
				}
				break;
			}
		}
	} else {
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines SRTP");
		proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_version, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		operation_type = tvb_get_guint8(tvb, offset);
		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(operation_type, vines_rtp_operation_type_vals,
			      "Unknown (0x%02x)"));

		if (tree) {
			proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_operation_type, tvb, offset, 1, ENC_NA);
			offset += 1;
			proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_node_type, tvb, offset, 1, ENC_NA);
			offset += 1;
			ti = proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_comp_flag,
					tvb, offset, 1, ENC_BIG_ENDIAN);
			subtree = proto_item_add_subtree(ti, ett_vines_rtp_compatibility_flags);

			proto_tree_add_item(subtree, hf_vines_rtp_comp_flag_neighbor_router, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(subtree, hf_vines_rtp_comp_flag_sequence_rtp, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(subtree, hf_vines_rtp_comp_flag_sequence_rtp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset += 1;
			offset += 1;	/* reserved */
			switch (operation_type) {

			case VRTP_OP_REQUEST:
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_requested_info, tvb, offset, 1, ENC_NA);
				break;

			case VRTP_OP_UPDATE_RESPONSE:
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_information_type, tvb, offset, 1, ENC_NA);
				offset += 1;
				ti = proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_control, tvb, offset, 1, ENC_BIG_ENDIAN);
				subtree = proto_item_add_subtree(ti, ett_vines_rtp_control_flags);
				proto_tree_add_item(subtree, hf_vines_rtp_control_sync_broadcast, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_vines_rtp_control_topology_update, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_vines_rtp_control_specific_request, tvb, offset, 1, ENC_BIG_ENDIAN);
				/* XXX - need reassembly? */
				proto_tree_add_item(subtree, hf_vines_rtp_control_end_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(subtree, hf_vines_rtp_control_beg_msg, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset += 1;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_packet_id, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_data_offset, tvb, offset, 2, ENC_BIG_ENDIAN);
				offset += 2;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_router_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				metric = tvb_get_ntohs(tvb, offset);
				proto_tree_add_uint_format_value(vines_rtp_tree, hf_vines_rtp_metric, tvb,
					    offset, 2, metric,
					    "%u ticks (%g seconds)",
					    metric, metric*.2);
				offset += 2;
				while (tvb_reported_length_remaining(tvb, offset) > 0) {
					proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_network_number, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					metric = tvb_get_ntohs(tvb, offset);
					if (metric == 0xffff) {
						proto_tree_add_text(vines_rtp_tree, tvb,
							    offset, 2,
							    "Neighbor Metric: Unreachable");
					} else {
						proto_tree_add_uint_format_value(vines_rtp_tree, hf_vines_rtp_neighbor_metric, tvb,
							    offset, 2, metric,
							    "%u ticks (%g seconds)",
							    metric, metric*.2);
					}
					offset += 2;
					proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
					offset += 4;
					rtp_show_flags(vines_rtp_tree, tvb, offset, hf_vines_rtp_network_flags);
					offset += 1;
					offset += 1;	/* reserved */
				}
				break;

			case VRTP_OP_REDIRECT:
				link_addr_length = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_link_address_length, tvb, offset, 1, ENC_NA);
				offset += 1;
				source_route_length = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_source_route_length, tvb, offset, 1, ENC_NA);
				offset += 1;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_destination, tvb, offset, VINES_ADDR_LEN, ENC_NA);
				offset += VINES_ADDR_LEN;
				metric = tvb_get_ntohs(tvb, offset);
				proto_tree_add_uint_format_value(vines_rtp_tree, hf_vines_rtp_metric_to_destination, tvb,
						    offset, 2, metric,
						    "%u ticks (%g seconds)",
						    metric, metric*.2);
				offset += 2;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_destination_node_type, tvb, offset, 1, ENC_NA);
				offset += 1;
				rtp_show_flags(vines_rtp_tree, tvb, offset, hf_vines_rtp_destination_flags);
				offset += 1;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_destination_sequence_number, tvb, ENC_BIG_ENDIAN, 4, ENC_BIG_ENDIAN);
				offset += 4;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_preferred_gateway, tvb, offset, VINES_ADDR_LEN, ENC_NA);
				offset += VINES_ADDR_LEN;
				metric = tvb_get_ntohs(tvb, offset);
				proto_tree_add_uint_format_value(vines_rtp_tree, hf_vines_rtp_metric_to_preferred_gateway, tvb,
						    offset, 2, metric,
						    "%u ticks (%g seconds)",
						    metric, metric*.2);
				offset += 2;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_preferred_gateway_node_type, tvb, offset, 1, ENC_NA);
				offset += 1;
				rtp_show_flags(vines_rtp_tree, tvb, offset, hf_vines_rtp_preferred_gateway_flags);
				offset += 1;
				proto_tree_add_item(vines_rtp_tree, hf_vines_rtp_preferred_gateway_sequence_number, tvb, offset, 4, ENC_BIG_ENDIAN);
				offset += 4;
				rtp_show_gateway_info(vines_rtp_tree, tvb,offset, link_addr_length, source_route_length);
				break;

			case VRTP_OP_REINITIALIZE:
				break;
			}

		}
	}
}

void
proto_register_vines_rtp(void)
{
	static hf_register_info hf[] = {
	  { &hf_vines_rtp_comp_flag,
	    { "Compatibility Flags", "vines_rtp.comp_flag",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_comp_flag_neighbor_router,
	    { "non-Vines-reachable neighbor router", "vines_rtp.comp_flag.neighbor_router",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_auto_config_not_auto_config), 0x04,
	      NULL, HFILL }},

	  { &hf_vines_rtp_comp_flag_sequence_rtp,
	    { "Sequenced RTP", "vines_rtp.comp_flag.sequence_rtp",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_rtp_not_all_neighbor_all_neighbor), 0x02,
	      NULL, HFILL }},

	  { &hf_vines_rtp_comp_flag_sequence_rtp_version,
	    { "RTP version mismatch", "vines_rtp.comp_flag.rtp_version",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_rtp_sequenced_not_sequenced), 0x01,
	      NULL, HFILL }},

	  { &hf_vines_rtp_control,
	    { "Control Flags", "vines_rtp.control",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_control_sync_broadcast,
	    { "Routing table synchronization broadcast", "vines_rtp.control.sync_broadcast",
	      FT_BOOLEAN, 8, TFS(&tfs_part_not_part), 0x10,
	      NULL, HFILL }},

	  { &hf_vines_rtp_control_topology_update,
	    { "Full topology update", "vines_rtp.control.topology_update",
	      FT_BOOLEAN, 8, TFS(&tfs_part_not_part), 0x08,
	      NULL, HFILL }},

	  { &hf_vines_rtp_control_specific_request,
	    { "Contains info specifically requested", "vines_rtp.control.specific_request",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
	      NULL, HFILL }},

	  { &hf_vines_rtp_control_end_msg,
	    { "End of message", "vines_rtp.control.end_msg",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
	      NULL, HFILL }},

	  { &hf_vines_rtp_control_beg_msg,
	    { "Beginning of message", "vines_rtp.control.beg_msg",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
	      NULL, HFILL }},

	  { &hf_vines_rtp_machine_rtp,
	    { "Sequenced RTP", "vines_rtp.machine.rtp",
	      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x04,
	      NULL, HFILL }},

	  { &hf_vines_rtp_machine_tcpip,
	    { "TCP/IP", "vines_rtp.machine.tcpip",
	      FT_BOOLEAN, 8, TFS(&tfs_supported_not_supported), 0x02,
	      NULL, HFILL }},

	  { &hf_vines_rtp_machine_bus,
	    { "Bus", "vines_rtp.machine.bus",
	      FT_BOOLEAN, 8, TFS(&tfs_fast_bus_slow_bus), 0x01,
	      NULL, HFILL }},

	  { &hf_vines_rtp_flag_sequence_rtp,
	    { "Network supports Sequenced RTP", "vines_rtp.flag.sequence_rtp",
	      FT_BOOLEAN, 8, TFS(&tfs_vine_rtp_no_yes), 0x08,
	      NULL, HFILL }},

	  { &hf_vines_rtp_flag_network_p2p,
	    { "Network accessed point-to-point on non-Vines network", "vines_rtp.flag.network_p2p",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x04,
	      NULL, HFILL }},

	  { &hf_vines_rtp_flag_data_link_p2p,
	    { "Data link to network uses point-to-point connection", "vines_rtp.flag.data_link_p2p",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x02,
	      NULL, HFILL }},

	  { &hf_vines_rtp_flag_broadcast_medium,
	    { "Network accessed across broadcast medium", "vines_rtp.flag.broadcast_medium",
	      FT_BOOLEAN, 8, TFS(&tfs_yes_no), 0x01,
	      NULL, HFILL }},

	  { &hf_vines_rtp_operation_type,
	    { "Operation Type", "vines_rtp.operation_type",
	      FT_UINT8, BASE_HEX, VALS(vines_rtp_operation_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_node_type,
	    { "Node Type", "vines_rtp.node_type",
	      FT_UINT8, BASE_HEX, VALS(vines_rtp_node_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_controller_type,
	    { "Controller Type", "vines_rtp.controller_type",
	      FT_UINT8, BASE_HEX, VALS(vines_rtp_controller_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_version,
	    { "Version", "vines_rtp.version",
	      FT_UINT16, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_link_address_length,
	    { "Link Address Length", "vines_rtp.link_address_length",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_source_route_length,
	    { "Source Route Length", "vines_rtp.source_route_length",
	      FT_UINT8, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_network_number,
	    { "Network Number", "vines_rtp.network_number",
	      FT_UINT32, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_neighbor_metric,
	    { "Neighbor Metric", "vines_rtp.neighbor_metric",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_requested_info,
	    { "Requested Info", "vines_rtp.requested_info",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_information_type,
	    { "Information Type", "vines_rtp.information_type",
	      FT_UINT8, BASE_HEX, VALS(vines_rtp_info_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_packet_id,
	    { "Packet ID", "vines_rtp.packet_id",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_data_offset,
	    { "Data Offset", "vines_rtp.data_offset",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_router_sequence_number,
	    { "Router Sequence Number", "vines_rtp.router_sequence_number",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_metric,
	    { "Metric", "vines_rtp.metric",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_sequence_number,
	    { "Sequence Number", "vines_rtp.sequence_number",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_destination,
	    { "Destination", "vines_rtp.destination",
	      FT_VINES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_metric_to_destination,
	    { "Metric to Destination", "vines_rtp.metric_to_destination",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_destination_node_type,
	    { "Destination Node Type", "vines_rtp.destination_node_type",
	      FT_UINT8, BASE_HEX, VALS(vines_rtp_node_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_destination_sequence_number,
	    { "Destination Sequence Number", "vines_rtp.destination_sequence_number",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_preferred_gateway,
	    { "Preferred Gateway", "vines_rtp.preferred_gateway",
	      FT_VINES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_metric_to_preferred_gateway,
	    { "Metric to Preferred Gateway", "vines_rtp.metric_to_preferred_gateway",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_preferred_gateway_node_type,
	    { "Preferred Gateway Node Type", "vines_rtp.preferred_gateway_node_type",
	      FT_UINT8, BASE_HEX, VALS(vines_rtp_node_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_preferred_gateway_sequence_number,
	    { "Preferred Gateway Sequence Number", "vines_rtp.preferred_gateway_sequence_number",
	      FT_UINT32, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_machine_type,
	    { "Machine Type", "vines_rtp.machine_type",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_destination_machine,
	    { "Destination Machine Type", "vines_rtp.destination_machine_type",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_pref_gateway_machine,
	    { "Preferred Gateway Machine Type", "vines_rtp.preferred_gateway_machine_type",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_destination_controller_type,
	    { "Destination Controller Type", "vines_rtp.destination_controller_type",
	      FT_UINT8, BASE_HEX, VALS(vines_rtp_controller_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_pref_gateway_controller_type,
	    { "Preferred Gateway Controller Type", "vines_rtp.preferred_gateway_controller_type",
	      FT_UINT8, BASE_HEX, VALS(vines_rtp_controller_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_network_flags,
	    { "Network Flags", "vines_rtp.network_flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_destination_flags,
	    { "Destination Flags", "vines_rtp.destination_flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_preferred_gateway_flags,
	    { "Preferred Gateway Flags", "vines_rtp.preferred_gateway_flags",
	      FT_UINT8, BASE_HEX, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_preferred_gateway_data_link_address_ether,
	    { "Preferred Gateway Data Link Address", "vines_rtp.preferred_gateway_data_link_address",
	      FT_ETHER, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_preferred_gateway_data_link_address_bytes,
	    { "Preferred Gateway Data Link Address", "vines_rtp.preferred_gateway_data_link_address",
	      FT_BYTES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},

	  { &hf_vines_rtp_preferred_gateway_source_route,
	    { "Preferred Gateway Source Route", "vines_rtp.preferred_gateway_source_route",
	      FT_BYTES, BASE_NONE, NULL, 0x0,
	      NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_vines_rtp,
		&ett_vines_rtp_compatibility_flags,
		&ett_vines_rtp_req_info,
		&ett_vines_rtp_control_flags,
		&ett_vines_rtp_mtype,
		&ett_vines_rtp_flags,
	};

	proto_vines_rtp = proto_register_protocol(
	    "Banyan Vines RTP", "Vines RTP", "vines_rtp");
	proto_register_field_array(proto_vines_rtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_rtp(void)
{
	dissector_handle_t vines_rtp_handle;

	vines_rtp_handle = create_dissector_handle(dissect_vines_rtp,
	    proto_vines_rtp);
	dissector_add_uint("vines_ip.protocol", VIP_PROTO_RTP, vines_rtp_handle);
}

#define VICP_EXCEPTION_NOTIFICATION	0x0000
#define VICP_METRIC_NOTIFICATION	0x0001

static const value_string vines_icp_packet_type_vals[] = {
	{ VICP_EXCEPTION_NOTIFICATION, "Exception notification" },
	{ VICP_METRIC_NOTIFICATION,    "Metric notification" },
	{ 0,                           NULL }
};

static void
dissect_vines_icp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_tree *vines_icp_tree;
	proto_item *ti;
	guint16  packet_type;
	guint16  exception_code;
	guint16  metric;
	gboolean save_in_error_pkt;
	tvbuff_t *next_tvb;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines ICP");
	col_clear(pinfo->cinfo, COL_INFO);

	ti = proto_tree_add_item(tree, proto_vines_icp, tvb, 0, -1, ENC_NA);
	vines_icp_tree = proto_item_add_subtree(ti, ett_vines_icp);

	packet_type = tvb_get_ntohs(tvb, offset);
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(packet_type, vines_icp_packet_type_vals,
		      "Unknown (0x%02x)"));

	proto_tree_add_item(vines_icp_tree, hf_vines_icp_packet_type, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset += 2;

	switch (packet_type) {

	case VICP_EXCEPTION_NOTIFICATION:
		exception_code = tvb_get_ntohs(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
			    val_to_str(exception_code, vipc_err_vals,
			        "Unknown exception code (%u)"));
		proto_tree_add_item(vines_icp_tree, hf_vines_icp_exception_code, tvb, offset, 2, ENC_BIG_ENDIAN);
		break;

	case VICP_METRIC_NOTIFICATION:
		metric = tvb_get_ntohs(tvb, offset);
		col_append_fstr(pinfo->cinfo, COL_INFO, ", metric %u", metric);
		proto_tree_add_item(vines_icp_tree, hf_vines_icp_metric, tvb, offset, 2, ENC_BIG_ENDIAN);
		break;
	}
	offset += 2;

	/*
	 * Save the current value of the "we're inside an error packet"
	 * flag, and set that flag; subdissectors may treat packets
	 * that are the payload of error packets differently from
	 * "real" packets.
	 */
	save_in_error_pkt = pinfo->flags.in_error_pkt;
	pinfo->flags.in_error_pkt = TRUE;

	/* Decode the first 40 bytes of the original VIP datagram. */
	next_tvb = tvb_new_subset_remaining(tvb, offset);
	call_dissector(vines_ip_handle, next_tvb, pinfo, vines_icp_tree);

	/* Restore the "we're inside an error packet" flag. */
	pinfo->flags.in_error_pkt = save_in_error_pkt;
}

void
proto_register_vines_icp(void)
{
	static hf_register_info hf[] = {
	  { &hf_vines_icp_packet_type,
	    { "Packet Type", "vines_icp.packet_type",
	      FT_UINT16, BASE_HEX, VALS(vines_icp_packet_type_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_icp_exception_code,
	    { "Exception Code", "vines_icp.exception_code",
	      FT_UINT16, BASE_DEC, VALS(vipc_err_vals), 0x0,
	      NULL, HFILL }},

	  { &hf_vines_icp_metric,
	    { "Metric", "vines_icp.metric",
	      FT_UINT16, BASE_DEC, NULL, 0x0,
	      NULL, HFILL }},
	};

	static gint *ett[] = {
		&ett_vines_icp,
	};

	proto_vines_icp = proto_register_protocol(
	    "Banyan Vines ICP", "Vines ICP", "vines_icp");
	proto_register_field_array(proto_vines_icp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_icp(void)
{
	dissector_handle_t vines_icp_handle;

	vines_icp_handle = create_dissector_handle(dissect_vines_icp,
	    proto_vines_icp);
	dissector_add_uint("vines_ip.protocol", VIP_PROTO_ICP, vines_icp_handle);
}
