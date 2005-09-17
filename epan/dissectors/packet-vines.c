/* packet-vines.c
 * Routines for Banyan VINES protocol packet disassembly
 *
 * $Id$
 *
 * Don Lafontaine <lafont02@cn.ca>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer <jmayer@loplof.de>
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
#include "config.h"
#endif

#include <string.h>
#include <glib.h>
#include <epan/packet.h>
#include "packet-vines.h"
#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/ipproto.h>
#include <epan/arcnet_pids.h>
#include <epan/llcsaps.h>

#define UDP_PORT_VINES	573

static int proto_vines_frp = -1;

static gint ett_vines_frp = -1;

static int proto_vines_llc = -1;

static gint ett_vines_llc = -1;

static int proto_vines_ip = -1;
static int hf_vines_ip_protocol = -1;

static gint ett_vines_ip = -1;
static gint ett_vines_ip_tctl = -1;

static int proto_vines_echo = -1;

static gint ett_vines_echo = -1;

static int proto_vines_ipc = -1;

static gint ett_vines_ipc = -1;
static gint ett_vines_ipc_control = -1;

static int proto_vines_spp = -1;

static gint ett_vines_spp = -1;
static gint ett_vines_spp_control = -1;

static int proto_vines_arp = -1;

static gint ett_vines_arp = -1;

static int proto_vines_rtp = -1;

static gint ett_vines_rtp = -1;
static gint ett_vines_rtp_compatibility_flags = -1;
static gint ett_vines_rtp_req_info = -1;
static gint ett_vines_rtp_control_flags = -1;
static gint ett_vines_rtp_mtype = -1;
static gint ett_vines_rtp_flags = -1;

static int proto_vines_icp = -1;

static gint ett_vines_icp = -1;

void
capture_vines(packet_counts *ld)
{
	ld->vines++;
}

static dissector_handle_t vines_ip_handle;
static dissector_handle_t data_handle;

/* AFAIK Vines FRP (Fragmentation Protocol) is used on all media except
 * Ethernet and TR (and probably FDDI) - Fragmentation on these media types
 * is not possible
 * FIXME: Do we need to use this header with PPP too?
 */
static void
dissect_vines_frp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint8   vines_frp_ctrl;
	proto_tree *vines_frp_tree;
	proto_item *ti;
	gchar	*frp_flags_str="";
	tvbuff_t *next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines FRP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_frp, tvb, 0, 2,
		    FALSE);
		vines_frp_tree = proto_item_add_subtree(ti, ett_vines_frp);

		vines_frp_ctrl = tvb_get_guint8(tvb, 0);

		/*
		 * 1: first fragment of vines packet
		 * 2: last fragment of vines packet
		 * 4 ... 80: unused
		 */
		switch (vines_frp_ctrl) {

		case 0:
			frp_flags_str= "middle";
			break;

		case 1:
			frp_flags_str= "first";
			break;

		case 2:
			frp_flags_str= "last";
			break;

		case 3:
			frp_flags_str= "only";
			break;

		default:
			frp_flags_str= "please report: unknown";
			break;
		}

		proto_tree_add_text(vines_frp_tree, tvb, 0, 1,
				    "Control Flags: 0x%02x = %s fragment",
				    vines_frp_ctrl, frp_flags_str);

		proto_tree_add_text(vines_frp_tree, tvb, 1, 1,
				    "Sequence Number: 0x%02x",
				    tvb_get_guint8(tvb, 1));
	}

	/* Decode the "real" Vines now */
	next_tvb = tvb_new_subset(tvb, 2, -1, -1);
	call_dissector(vines_ip_handle, next_tvb, pinfo, tree);
}

void
proto_register_vines_frp(void)
{
	static gint *ett[] = {
		&ett_vines_frp,
	};

	proto_vines_frp = proto_register_protocol(
	    "Banyan Vines Fragmentation Protocol", "Vines FRP", "vines_frp");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_frp(void)
{
	dissector_handle_t vines_frp_handle;

	vines_frp_handle = create_dissector_handle(dissect_vines_frp,
	    proto_vines_frp);
	dissector_add("ip.proto", IP_PROTO_VINES, vines_frp_handle);

	/* XXX: AFAIK, src and dst port must be the same; should
	   the dissector check for that? */
	dissector_add("udp.port", UDP_PORT_VINES, vines_frp_handle);
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

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines LLC");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	ptype = tvb_get_guint8(tvb, 0);
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(ptype, vines_llc_ptype_vals,
		      "Unknown protocol 0x%02x"));
	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_llc, tvb, 0, 1,
		    FALSE);
		vines_llc_tree = proto_item_add_subtree(ti, ett_vines_llc);

		proto_tree_add_text(vines_llc_tree, tvb, 0, 1,
				    "Packet Type: %s (0x%02x)",
				    val_to_str(ptype, vines_llc_ptype_vals,
				        "Unknown"),
				    ptype);
	}

	next_tvb = tvb_new_subset(tvb, 1, -1, -1);
	if (!dissector_try_port(vines_llc_dissector_table, ptype,
	    next_tvb, pinfo, tree))
		call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_vines_llc(void)
{
	static gint *ett[] = {
		&ett_vines_llc,
	};

	proto_vines_llc = proto_register_protocol(
	    "Banyan Vines LLC", "Vines LLC", "vines_llc");
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
	dissector_add("llc.dsap", SAP_VINES2, vines_llc_handle);
}

static dissector_table_t vines_ip_dissector_table;

static const value_string class_vals[] = {
	{ 0x00, "Reachable regardless of cost" },
	{ 0x10, "Reachable without cost" },
	{ 0x20, "Reachable with low cost (>= 4800 bps)" },
	{ 0x30, "Reachable via LAN" },
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

static void
dissect_vines_ip(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int         offset = 0;
	e_vip       viph;
	proto_tree *vip_tree, *tctl_tree;
	proto_item *ti;
	const guint8     *dst_addr, *src_addr;
	gboolean is_broadcast = FALSE;
	int  hops = 0;
	tvbuff_t *next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines IP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	/* To do: check for runts, errs, etc. */

	/* Avoids alignment problems on many architectures. */
	tvb_memcpy(tvb, (guint8 *)&viph, offset, sizeof(e_vip));

	viph.vip_chksum = g_ntohs(viph.vip_chksum);
	viph.vip_pktlen = g_ntohs(viph.vip_pktlen);

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s (0x%02x)",
		    val_to_str(viph.vip_proto, proto_vals,
		        "Unknown VIP protocol"),
		    viph.vip_proto);
	}

	src_addr = tvb_get_ptr(tvb, offset+12, VINES_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_src, AT_VINES, VINES_ADDR_LEN, src_addr);
	SET_ADDRESS(&pinfo->src, AT_VINES, VINES_ADDR_LEN, src_addr);
	dst_addr = tvb_get_ptr(tvb, offset+6, VINES_ADDR_LEN);
	SET_ADDRESS(&pinfo->net_dst, AT_VINES, VINES_ADDR_LEN,dst_addr);
	SET_ADDRESS(&pinfo->dst, AT_VINES, VINES_ADDR_LEN, dst_addr);

 	/* helpers to transport control */
	if (memcmp(viph.vip_dst, bcast_addr, VINES_ADDR_LEN) == 0)
 		is_broadcast = TRUE;
 	hops = viph.vip_tctl & 0xf;

	/*
	 * Adjust the length of this tvbuff to include only the Vines IP
	 * datagram.
	 */
	set_actual_length(tvb, viph.vip_pktlen < 18 ? 18 : viph.vip_pktlen);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_ip, tvb,
					 offset, viph.vip_pktlen,
					 FALSE);
		vip_tree = proto_item_add_subtree(ti, ett_vines_ip);
		proto_tree_add_text(vip_tree, tvb, offset,      2,
				    "Packet checksum: 0x%04x",
				    viph.vip_chksum);
		proto_tree_add_text(vip_tree, tvb, offset +  2, 2,
				    "Packet length: %u",
				    viph.vip_pktlen);
		ti = proto_tree_add_text(vip_tree, tvb, offset +  4, 1,
				    "Transport control: 0x%02x",
				    viph.vip_tctl);
		tctl_tree = proto_item_add_subtree(ti, ett_vines_ip_tctl);
		/*
		 * XXX - bit 0x80 is "Normal" if 0; what is it if 1?
		 */
		if (is_broadcast) {
			proto_tree_add_text(tctl_tree, tvb, offset + 4, 1,
			    decode_boolean_bitfield(viph.vip_tctl, 0x40, 1*8,
			      "Router nodes",
			      "All nodes"));
			proto_tree_add_text(tctl_tree, tvb, offset + 4, 1, "%s",
			    decode_enumerated_bitfield(viph.vip_tctl, 0x30, 1*8,
				      class_vals, "%s"));
		} else {
			proto_tree_add_text(tctl_tree, tvb, offset + 4, 1,
			    decode_boolean_bitfield(viph.vip_tctl, 0x40, 1*8,
			      "Forwarding router can handle redirect packets",
			      "Forwarding router cannot handle redirect packets"));
			proto_tree_add_text(tctl_tree, tvb, offset + 4, 1,
			    decode_boolean_bitfield(viph.vip_tctl, 0x20, 1*8,
			      "Return metric notification packet",
			      "Do not return metric notification packet"));
			proto_tree_add_text(tctl_tree, tvb, offset + 4, 1,
			    decode_boolean_bitfield(viph.vip_tctl, 0x10, 1*8,
			      "Return exception notification packet",
			      "Do not return exception notification packet"));
		}
		proto_tree_add_text(tctl_tree, tvb, offset + 4, 1,
		    decode_numeric_bitfield(viph.vip_tctl, 0x0F, 1*8,
			"Hop count remaining = %u"));
		proto_tree_add_uint(vip_tree, hf_vines_ip_protocol, tvb,
				    offset +  5, 1,
				    viph.vip_proto);
		proto_tree_add_text(vip_tree, tvb, offset +  6,
				    VINES_ADDR_LEN,
				    "Destination: %s",
				    vines_addr_to_str(dst_addr));
		proto_tree_add_text(vip_tree, tvb, offset +  12,
				    VINES_ADDR_LEN,
				    "Source: %s",
				    vines_addr_to_str(src_addr));
	}

	offset += 18;
	next_tvb = tvb_new_subset(tvb, offset, -1, -1);
	if (!dissector_try_port(vines_ip_dissector_table, viph.vip_proto,
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
	    { "Protocol",			"vines_ip.protocol",
	      FT_UINT8,		BASE_HEX,	VALS(proto_vals),	0x0,
	      "Vines protocol", HFILL }}
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
	dissector_add("ethertype", ETHERTYPE_VINES_IP, vines_ip_handle);
	dissector_add("ppp.protocol", PPP_VINES, vines_ip_handle);
	dissector_add("arcnet.protocol_id", ARCNET_PROTO_BANYAN,
	    vines_ip_handle);
	dissector_add("vines_llc.ptype", VINES_LLC_IP, vines_ip_handle);
	data_handle = find_dissector("data");
}

static void
dissect_vines_echo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *vines_echo_tree = NULL;
	proto_item *ti;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines Echo");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_echo, tvb, 0, -1,
		    FALSE);
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
	dissector_add("vines_llc.ptype", VINES_LLC_ECHO, vines_echo_handle);
	dissector_add("ethertype", ETHERTYPE_VINES_ECHO, vines_echo_handle);
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

static void
dissect_vines_ipc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int          offset = 0;
	e_vipc       viph;
	proto_tree *vipc_tree = NULL, *control_tree;
	proto_item *ti;
	tvbuff_t *next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "VIPC");
	if (check_col(pinfo->cinfo, COL_INFO))
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

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines IPC");
	if (check_col(pinfo->cinfo, COL_INFO)) {
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
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_ipc, tvb, offset,
		    sizeof(viph), FALSE);
		vipc_tree = proto_item_add_subtree(ti, ett_vines_ipc);
		proto_tree_add_text(vipc_tree, tvb, offset,      2,
				    "Source port: 0x%04x", viph.vipc_sport);
	}
	offset += 2;
	if (tree) {
		proto_tree_add_text(vipc_tree, tvb, offset,  2,
				    "Destination port: 0x%04x",
				    viph.vipc_dport);
	}
	offset += 2;
	if (tree) {
		proto_tree_add_text(vipc_tree, tvb, offset,  1,
				    "Packet type: 0x%02x (%s)",
				    viph.vipc_pkttype,
				    val_to_str(viph.vipc_pkttype, pkttype_vals,
				        "Unknown"));
	}
	offset += 1;
	if (viph.vipc_pkttype != PKTTYPE_DGRAM) {
		if (tree) {
			ti = proto_tree_add_text(vipc_tree, tvb, offset,  1,
					    "Control: 0x%02x",
					    viph.vipc_control);
			control_tree = proto_item_add_subtree(ti,
			    ett_vines_ipc_control);
			/*
			 * XXX - do reassembly based on BOM/EOM bits.
			 */
			proto_tree_add_text(control_tree, tvb, offset, 1,
			    decode_boolean_bitfield(viph.vipc_control, 0x80,
			      1*8,
			      "Send immediate acknowledgment",
			      "Do not send immediate acknowledgement"));
			proto_tree_add_text(control_tree, tvb, offset, 1,
			    decode_boolean_bitfield(viph.vipc_control, 0x40,
			      1*8,
			      "End of message",
			      "Not end of message"));
			proto_tree_add_text(control_tree, tvb, offset, 1,
			    decode_boolean_bitfield(viph.vipc_control, 0x20,
			      1*8,
			      "Beginning of message",
			      "Not beginning of message"));
			proto_tree_add_text(control_tree, tvb, offset, 1,
			    decode_boolean_bitfield(viph.vipc_control, 0x10,
			      1*8,
			      "Abort current message",
			      "Do not abort current message"));
		}
	}
	offset += 1;
	if (viph.vipc_pkttype != PKTTYPE_DGRAM) {
		if (tree) {
			proto_tree_add_text(vipc_tree, tvb, offset,  2,
					    "Local Connection ID: 0x%04x",
					    viph.vipc_lclid);
		}
		offset += 2;
		if (tree) {
			proto_tree_add_text(vipc_tree, tvb, offset,  2,
					    "Remote Connection ID: 0x%04x",
					    viph.vipc_rmtid);
		}
		offset += 2;
		if (tree) {
			proto_tree_add_text(vipc_tree, tvb, offset, 2,
					    "Sequence number: %u",
					    viph.vipc_seqno);
		}
		offset += 2;
		if (tree) {
			proto_tree_add_text(vipc_tree, tvb, offset, 2,
					    "Ack number: %u", viph.vipc_ack);
		}
		offset += 2;
		if (tree) {
			if (viph.vipc_pkttype == PKTTYPE_ERR) {
				proto_tree_add_text(vipc_tree, tvb, offset, 2,
						    "Error: %s (%u)",
						    val_to_str(viph.vipc_err_len,
						        vipc_err_vals,
						        "Unknown"),
						    viph.vipc_err_len);
			} else {
				proto_tree_add_text(vipc_tree, tvb, offset, 2,
						    "Length: %u",
						    viph.vipc_err_len);
			}
		}
		offset += 2;
	}

	/*
	 * For data packets, try the heuristic dissectors for Vines SPP;
	 * if none of them accept the packet, or if it's not a data packet,
	 * dissect it as data.
	 */
	next_tvb = tvb_new_subset(tvb, offset, -1, -1);
	if (viph.vipc_pkttype != PKTTYPE_DATA ||
	    !dissector_try_heuristic(vines_ipc_heur_subdissector_list,
	      next_tvb, pinfo, tree))
		call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_vines_ipc(void)
{
	static gint *ett[] = {
		&ett_vines_ipc,
		&ett_vines_ipc_control,
	};

	proto_vines_ipc = proto_register_protocol("Banyan Vines IPC",
	    "Vines IPC", "vines_ipc");
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
	dissector_add("vines_ip.protocol", VIP_PROTO_IPC, vines_ipc_handle);
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

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "VSPP");
	if (check_col(pinfo->cinfo, COL_INFO))
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

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines SPP");
	if (check_col(pinfo->cinfo, COL_INFO))
 		col_add_fstr(pinfo->cinfo, COL_INFO,
			     "%s NS=%u NR=%u Window=%u RID=%04x LID=%04x D=%04x S=%04x",
			     val_to_str(viph.vspp_pkttype, pkttype_vals,
			         "Unknown packet type (0x%02x)"),
			     viph.vspp_seqno, viph.vspp_ack, viph.vspp_win,
			     viph.vspp_rmtid, viph.vspp_lclid, viph.vspp_dport,
			     viph.vspp_sport);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_spp, tvb, offset,
		    sizeof(viph), FALSE);
		vspp_tree = proto_item_add_subtree(ti, ett_vines_spp);
		proto_tree_add_text(vspp_tree, tvb, offset,      2,
				    "Source port: 0x%04x", viph.vspp_sport);
		proto_tree_add_text(vspp_tree, tvb, offset + 2,  2,
				    "Destination port: 0x%04x",
				    viph.vspp_dport);
		proto_tree_add_text(vspp_tree, tvb, offset + 4,  1,
				    "Packet type: 0x%02x (%s)",
				    viph.vspp_pkttype,
				    val_to_str(viph.vspp_pkttype, pkttype_vals,
				        "Unknown"));
		ti = proto_tree_add_text(vspp_tree, tvb, offset + 5,  1,
				    "Control: 0x%02x", viph.vspp_control);
		control_tree = proto_item_add_subtree(ti, ett_vines_spp_control);
		/*
		 * XXX - do reassembly based on BOM/EOM bits.
		 */
		proto_tree_add_text(control_tree, tvb, offset + 5, 1,
		    decode_boolean_bitfield(viph.vspp_control, 0x80, 1*8,
		      "Send immediate acknowledgment",
		      "Do not send immediate acknowledgement"));
		proto_tree_add_text(control_tree, tvb, offset + 5, 1,
		    decode_boolean_bitfield(viph.vspp_control, 0x40, 1*8,
		      "End of message",
		      "Not end of message"));
		proto_tree_add_text(control_tree, tvb, offset + 5, 1,
		    decode_boolean_bitfield(viph.vspp_control, 0x20, 1*8,
		      "Beginning of message",
		      "Not beginning of message"));
		proto_tree_add_text(control_tree, tvb, offset + 5, 1,
		    decode_boolean_bitfield(viph.vspp_control, 0x10, 1*8,
		      "Abort current message",
		      "Do not abort current message"));
		proto_tree_add_text(vspp_tree, tvb, offset + 6,  2,
				    "Local Connection ID: 0x%04x",
				    viph.vspp_lclid);
		proto_tree_add_text(vspp_tree, tvb, offset + 8,  2,
				    "Remote Connection ID: 0x%04x",
				    viph.vspp_rmtid);
		proto_tree_add_text(vspp_tree, tvb, offset + 10, 2,
				    "Sequence number: %u",
				    viph.vspp_seqno);
		proto_tree_add_text(vspp_tree, tvb, offset + 12, 2,
				    "Ack number: %u", viph.vspp_ack);
		proto_tree_add_text(vspp_tree, tvb, offset + 14, 2,
				    "Window: %u", viph.vspp_win);
	}
	offset += 16; /* sizeof SPP */

	/*
	 * For data packets, try the heuristic dissectors for Vines SPP;
	 * if none of them accept the packet, or if it's not a data packet,
	 * dissect it as data.
	 */
	next_tvb = tvb_new_subset(tvb, offset, -1, -1);
	if (viph.vspp_pkttype != PKTTYPE_DATA ||
	    !dissector_try_heuristic(vines_spp_heur_subdissector_list,
	      next_tvb, pinfo, tree))
		call_dissector(data_handle, next_tvb, pinfo, tree);
}

void
proto_register_vines_spp(void)
{
	static gint *ett[] = {
		&ett_vines_spp,
		&ett_vines_spp_control,
	};

	proto_vines_spp = proto_register_protocol("Banyan Vines SPP",
	    "Vines SPP", "vines_spp");
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
	dissector_add("vines_ip.protocol", VIP_PROTO_SPP, vines_spp_handle);
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
	proto_tree *vines_arp_tree = NULL;
	proto_item *ti;
	guint8   version;
	guint16  packet_type;
	guint16  metric;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines ARP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_arp, tvb, 0, -1,
		    FALSE);
		vines_arp_tree = proto_item_add_subtree(ti, ett_vines_arp);
	}

	version = tvb_get_guint8(tvb, 0);
	if (tree) {
		proto_tree_add_text(vines_arp_tree, tvb, 0, 1,
				    "Version: %s (0x%02x)",
				    val_to_str(version, vines_version_vals,
				      "Unknown"),
				    version);
	}
	if (version == VINES_VERS_5_5) {
		/*
		 * Sequenced ARP.
		 */
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines SARP");
		packet_type = tvb_get_guint8(tvb, 1);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(packet_type, vines_arp_packet_type_vals,
			      "Unknown (0x%02x)"));
		}
		if (tree) {
			proto_tree_add_text(vines_arp_tree, tvb, 1, 1,
					    "Packet Type: %s (0x%02x)",
					    val_to_str(packet_type,
					      vines_arp_packet_type_vals,
					      "Unknown"),
					    packet_type);
		}
		if (packet_type == VARP_ASSIGNMENT_RESP) {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO,
					    ", Address = %s",
					    vines_addr_to_str(tvb_get_ptr(tvb, 2, VINES_ADDR_LEN)));
			}
			if (tree) {
				proto_tree_add_text(vines_arp_tree, tvb, 2,
						    VINES_ADDR_LEN,
						    "Address: %s",
						    vines_addr_to_str(tvb_get_ptr(tvb, 2, VINES_ADDR_LEN)));
			}
		}
		if (tree) {
			proto_tree_add_text(vines_arp_tree, tvb,
					    2+VINES_ADDR_LEN, 4,
					    "Sequence Number: %u",
					    tvb_get_ntohl(tvb, 2+VINES_ADDR_LEN));
			metric = tvb_get_ntohs(tvb, 2+VINES_ADDR_LEN+4);
			proto_tree_add_text(vines_arp_tree, tvb,
					    2+VINES_ADDR_LEN+4, 2,
					    "Interface Metric: %u ticks (%g seconds)",
					    metric, metric*.2);
		}
	} else {
		/*
		 * Non-sequenced ARP.
		 */
		packet_type = (guint8) tvb_get_ntohs(tvb, 0);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(packet_type, vines_arp_packet_type_vals,
			      "Unknown (0x%02x)"));
		}
		if (tree) {
			proto_tree_add_text(vines_arp_tree, tvb, 0, 2,
					    "Packet Type: %s (0x%04x)",
					    val_to_str(packet_type,
					      vines_arp_packet_type_vals,
					      "Unknown"),
					    packet_type);
		}
		if (packet_type == VARP_ASSIGNMENT_RESP) {
			if (check_col(pinfo->cinfo, COL_INFO)) {
				col_append_fstr(pinfo->cinfo, COL_INFO,
					    ", Address = %s",
					    vines_addr_to_str(tvb_get_ptr(tvb, 2, VINES_ADDR_LEN)));
			}
			if (tree) {
				proto_tree_add_text(vines_arp_tree, tvb, 2,
						    VINES_ADDR_LEN,
						    "Address: %s",
						    vines_addr_to_str(tvb_get_ptr(tvb, 2, VINES_ADDR_LEN)));
			}
		}
	}
}

void
proto_register_vines_arp(void)
{
	static gint *ett[] = {
		&ett_vines_arp,
	};

	proto_vines_arp = proto_register_protocol(
	    "Banyan Vines ARP", "Vines ARP", "vines_arp");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_arp(void)
{
	dissector_handle_t vines_arp_handle;

	vines_arp_handle = create_dissector_handle(dissect_vines_arp,
	    proto_vines_arp);
	dissector_add("vines_ip.protocol", VIP_PROTO_ARP, vines_arp_handle);
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

static void rtp_show_machine_type(proto_tree *tree, tvbuff_t *tvb, int offset,
    const char *tag);
static void rtp_show_flags(proto_tree *tree, tvbuff_t *tvb, int offset,
    const char *tag);
static int srtp_show_machine_info(proto_tree *tree, tvbuff_t *tvb, int offset,
    const char *tag);
static int rtp_show_gateway_info(proto_tree *tree, tvbuff_t *tvb, int offset,
    guint8 link_addr_length, guint8 source_route_length);

static void
dissect_vines_rtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	int offset = 0;
	proto_tree *vines_rtp_tree = NULL;
	proto_item *ti;
	proto_tree *subtree;
	guint16  version;
	guint8   operation_type;
	guint8   node_type;
	guint8   controller_type;
	guint8   compatibility_flags;
	guint8   link_addr_length;
	guint8   source_route_length;
	guint8   requested_info;
	guint8   info_type;
	guint8   control_flags;
	guint16  metric;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines RTP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_rtp, tvb, 0, -1,
		    FALSE);
		vines_rtp_tree = proto_item_add_subtree(ti, ett_vines_rtp);
	}

	if (tvb_get_guint8(tvb, 0) != 0) {
		/*
		 * Non-sequenced RTP.
		 */
		operation_type = tvb_get_guint8(tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(operation_type, vines_rtp_operation_type_vals,
			      "Unknown (0x%02x)"));
		}
		if (tree) {
			proto_tree_add_text(vines_rtp_tree, tvb, offset, 1,
					    "Operation Type: %s (0x%02x)",
					    val_to_str(operation_type,
					      vines_rtp_operation_type_vals,
					      "Unknown"),
					    operation_type);
			offset += 1;
			node_type = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(vines_rtp_tree, tvb, offset, 1,
					    "Node Type: %s (0x%02x)",
					    val_to_str(node_type,
					      vines_rtp_node_type_vals,
					      "Unknown"),
					    node_type);
			offset += 1;
			controller_type = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(vines_rtp_tree, tvb, offset, 1,
					    "Controller Type: %s (0x%02x)",
					    val_to_str(controller_type,
					      vines_rtp_controller_type_vals,
					      "Unknown"),
					    controller_type);
			offset += 1;
			rtp_show_machine_type(vines_rtp_tree, tvb, offset,
			    NULL);
			offset += 1;
			switch (operation_type) {

			case VRTP_OP_REDIRECT:
			case VRTP_OP_REDIRECT2:
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 2,
						    "Version: 0x%02x",
						    tvb_get_ntohs(tvb, offset));
				offset += 2;
				link_addr_length = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 1,
						    "Link Address Length: %u",
						    link_addr_length);
				offset += 1;
				source_route_length = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 1,
						    "Source Route Length: %u",
						    source_route_length);
				offset += 1;
				offset = srtp_show_machine_info(vines_rtp_tree,
				    tvb, offset, "Destination");
				offset += 1;
				offset = srtp_show_machine_info(vines_rtp_tree,
				    tvb, offset, "Preferred Gateway");
				offset += 1;
				offset = rtp_show_gateway_info(vines_rtp_tree,
				    tvb,offset, link_addr_length,
				    source_route_length);
				break;

			default:
				while (tvb_reported_length_remaining(tvb, offset) > 0) {
					proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 4,
						    "Network Number: 0x%08x",
						    tvb_get_ntohl(tvb, offset));
					offset += 4;
					metric = tvb_get_ntohs(tvb, offset);
					proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 2,
						    "Neighbor Metric: %u ticks (%g seconds)",
						    metric,
						    metric*.2);
					offset += 2;
				}
				break;
			}
		}
	} else {
		if (check_col(pinfo->cinfo, COL_PROTOCOL))
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines SRTP");
		if (tree) {
			version = tvb_get_ntohs(tvb, offset);
			proto_tree_add_text(vines_rtp_tree, tvb, offset, 2,
					    "Version: %s (0x%04x)",
					    val_to_str(version, vines_version_vals,
					      "Unknown"),
					    version);
		}
		offset += 2;
		operation_type = tvb_get_guint8(tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(operation_type, vines_rtp_operation_type_vals,
			      "Unknown (0x%02x)"));
		}
		if (tree) {
			proto_tree_add_text(vines_rtp_tree, tvb, offset, 1,
					    "Operation Type: %s (0x%02x)",
					    val_to_str(operation_type,
					      vines_rtp_operation_type_vals,
					      "Unknown"),
					    operation_type);
			offset += 1;
			node_type = tvb_get_guint8(tvb, offset);
			proto_tree_add_text(vines_rtp_tree, tvb, offset, 1,
					    "Node Type: %s (0x%02x)",
					    val_to_str(node_type,
					      vines_rtp_node_type_vals,
					      "Unknown"),
					    node_type);
			offset += 1;
			compatibility_flags = tvb_get_guint8(tvb, offset);
			ti = proto_tree_add_text(vines_rtp_tree, tvb, offset, 1,
					    "Compatibility Flags: 0x%02x",
					    compatibility_flags);
			subtree = proto_item_add_subtree(ti,
			    ett_vines_rtp_compatibility_flags);
			proto_tree_add_text(subtree, tvb,
			    offset, 1,
			    decode_boolean_bitfield(compatibility_flags,
			      0x04, 1*8,
			      "Auto-configured non-Vines-reachable neighbor router",
			      "Not an auto-configured non-Vines-reachable neighbor router"));
			proto_tree_add_text(subtree, tvb,
			    offset, 1,
			    decode_boolean_bitfield(compatibility_flags,
			      0x02, 1*8,
			      "Not all neighbor routers support Sequenced RTP",
			      "All neighbor routers support Sequenced RTP"));
			proto_tree_add_text(subtree, tvb,
			    offset, 1,
			    decode_boolean_bitfield(compatibility_flags,
			      0x01, 1*8,
			      "Sequenced RTP version mismatch",
			      "No Sequenced RTP version mismatch"));
			offset += 1;
			offset += 1;	/* reserved */
			switch (operation_type) {

			case VRTP_OP_REQUEST:
				requested_info = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 1,
						    "Requested Info: 0x%02x",
						    requested_info);
				break;

			case VRTP_OP_UPDATE_RESPONSE:
				info_type = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 1,
					    "Information Type: %s (0x%02x)",
					    val_to_str(info_type,
					      vines_rtp_info_type_vals,
					      "Unknown"),
					    info_type);
				offset += 1;
				control_flags = tvb_get_guint8(tvb, offset);
				ti = proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 1,
						    "Control Flags: 0x%02x",
						    control_flags);
				subtree = proto_item_add_subtree(ti,
				    ett_vines_rtp_control_flags);
				proto_tree_add_text(subtree, tvb,
				    offset, 1,
				    decode_boolean_bitfield(control_flags,
				      0x10, 1*8,
				      "Part of routing table synchronization broadcast",
				      "Not part of routing table synchronization broadcast"));
				proto_tree_add_text(subtree, tvb,
				    offset, 1,
				    decode_boolean_bitfield(control_flags,
				      0x08, 1*8,
				      "Part of full topology update",
				      "Not part of full topology update"));
				proto_tree_add_text(subtree, tvb,
				    offset, 1,
				    decode_boolean_bitfield(control_flags,
				      0x04, 1*8,
				      "Contains info specifically requested or network changes",
				      "Not a response to a specific request"));
				/* XXX - need reassembly? */
				proto_tree_add_text(subtree, tvb,
				    offset, 1,
				    decode_boolean_bitfield(control_flags,
				      0x02, 1*8,
				      "End of message",
				      "Not end of message"));
				proto_tree_add_text(subtree, tvb,
				    offset, 1,
				    decode_boolean_bitfield(control_flags,
				      0x01, 1*8,
				      "Beginning of message",
				      "Not beginning of message"));
				offset += 1;
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 2,
					    "Packet ID: %u",
					    tvb_get_ntohs(tvb, offset));
				offset += 2;
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 2,
					    "Data Offset: %u",
					    tvb_get_ntohs(tvb, offset));
				offset += 2;
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 4,
					    "Router Sequence Number: %u",
					    tvb_get_ntohl(tvb, offset));
				offset += 4;
				metric = tvb_get_ntohs(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 2,
					    "Metric: %u ticks (%g seconds)",
					    metric, metric*.2);
				offset += 2;
				while (tvb_reported_length_remaining(tvb, offset) > 0) {
					proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 4,
						    "Network Number: 0x%08x",
						    tvb_get_ntohl(tvb, offset));
					offset += 4;
					metric = tvb_get_ntohs(tvb, offset);
					if (metric == 0xffff) {
						proto_tree_add_text(vines_rtp_tree, tvb,
							    offset, 2,
							    "Neighbor Metric: Unreachable");
					} else {
						proto_tree_add_text(vines_rtp_tree, tvb,
							    offset, 2,
							    "Neighbor Metric: %u ticks (%g seconds)",
							    metric, metric*.2);
					}
					offset += 2;
					proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 4,
						    "Sequence Number: %u",
						    tvb_get_ntohl(tvb, offset));
					offset += 4;
					rtp_show_flags(vines_rtp_tree, tvb,
					    offset, "Network");
					offset += 1;
					offset += 1;	/* reserved */
				}
				break;

			case VRTP_OP_REDIRECT:
				link_addr_length = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 1,
						    "Link Address Length: %u",
						    link_addr_length);
				offset += 1;
				source_route_length = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 1,
						    "Source Route Length: %u",
						    source_route_length);
				offset += 1;
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, VINES_ADDR_LEN,
						    "Destination: %s",
						    vines_addr_to_str(tvb_get_ptr(tvb, offset, VINES_ADDR_LEN)));
				offset += VINES_ADDR_LEN;
				metric = tvb_get_ntohs(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 2,
						    "Metric to Destination: %u ticks (%g seconds)",
						    metric, metric*.2);
				offset += 2;
				node_type = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 1,
					    "Destination Node Type: %s (0x%02x)",
					    val_to_str(node_type,
					      vines_rtp_node_type_vals,
					      "Unknown"),
					    node_type);
				offset += 1;
				rtp_show_flags(vines_rtp_tree, tvb,
				    offset, "Destination");
				offset += 1;
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 4,
					    "Destination Sequence Number: %u",
					    tvb_get_ntohl(tvb, offset));
				offset += 4;
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, VINES_ADDR_LEN,
						    "Preferred Gateway: %s",
						    vines_addr_to_str(tvb_get_ptr(tvb, offset, VINES_ADDR_LEN)));
				offset += VINES_ADDR_LEN;
				metric = tvb_get_ntohs(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
						    offset, 2,
						    "Metric to Preferred Gateway: %u ticks (%g seconds)",
						    metric, metric*.2);
				offset += 2;
				node_type = tvb_get_guint8(tvb, offset);
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 1,
					    "Preferred Gateway Node Type: %s (0x%02x)",
					    val_to_str(node_type,
					      vines_rtp_node_type_vals,
					      "Unknown"),
					    node_type);
				offset += 1;
				rtp_show_flags(vines_rtp_tree, tvb,
				    offset, "Preferred Gateway");
				offset += 1;
				proto_tree_add_text(vines_rtp_tree, tvb,
					    offset, 4,
					    "Preferred Gateway Sequence Number: %u",
					    tvb_get_ntohl(tvb, offset));
				offset += 4;
				offset = rtp_show_gateway_info(vines_rtp_tree,
				    tvb,offset, link_addr_length,
				    source_route_length);
				break;

			case VRTP_OP_REINITIALIZE:
				break;
			}

		}
	}
}

static void
rtp_show_machine_type(proto_tree *tree, tvbuff_t *tvb, int offset, const char *tag)
{
	guint8 machine_type;
	proto_item *ti;
	proto_tree *subtree;

	machine_type = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_text(tree, tvb, offset, 1,
	    "%s%sMachine Type: 0x%02x",
	    tag == NULL ? "" : tag,
	    tag == NULL ? "" : " ",
	    machine_type);
	subtree = proto_item_add_subtree(ti, ett_vines_rtp_mtype);
	proto_tree_add_text(subtree, tvb, offset, 1,
	    decode_boolean_bitfield(machine_type, 0x04, 1*8,
	      "Sequenced RTP supported",
	      "Sequenced RTP not supported"));
	proto_tree_add_text(subtree, tvb, offset, 1,
	    decode_boolean_bitfield(machine_type, 0x02, 1*8,
	      "TCP/IP supported",
	      "TCP/IP not supported"));
	proto_tree_add_text(subtree, tvb, offset, 1,
	    decode_boolean_bitfield(machine_type, 0x01, 1*8,
	      "Fast bus",
	      "Slow bus"));
}

static void
rtp_show_flags(proto_tree *tree, tvbuff_t *tvb, int offset, const char *tag)
{
	guint8 flags;
	proto_item *ti;
	proto_tree *flags_tree;

	flags = tvb_get_guint8(tvb, offset);
	ti = proto_tree_add_text(tree, tvb, offset, 1, "%s Flags: 0x%02x",
	    tag, flags);
	flags_tree = proto_item_add_subtree(ti, ett_vines_rtp_flags);
	proto_tree_add_text(flags_tree, tvb, offset, 1,
	    decode_boolean_bitfield(flags, 0x08, 1*8,
	      "Network doesn't support Sequenced RTP",
	      "Network supports Sequenced RTP"));
	proto_tree_add_text(flags_tree, tvb, offset, 1,
	    decode_boolean_bitfield(flags, 0x04, 1*8,
	      "Network accessed point-to-point on non-Vines network",
	      "Network not accessed point-to-point on non-Vines network"));
	proto_tree_add_text(flags_tree, tvb, offset, 1,
	    decode_boolean_bitfield(flags, 0x02, 1*8,
	      "Data link to network uses point-to-point connection",
	      "Data link to network doesn't use point-to-point connection"));
	proto_tree_add_text(flags_tree, tvb, offset, 1,
	    decode_boolean_bitfield(flags, 0x01, 1*8,
	      "Network accessed across broadcast medium",
	      "Network not accessed across broadcast medium"));
}

static int
srtp_show_machine_info(proto_tree *tree, tvbuff_t *tvb, int offset, const char *tag)
{
	guint16 metric;
	guint8 node_type;
	guint8 controller_type;

	proto_tree_add_text(tree, tvb, offset, VINES_ADDR_LEN,
	    "%s: %s", tag,
	    vines_addr_to_str(tvb_get_ptr(tvb, offset, VINES_ADDR_LEN)));
	offset += VINES_ADDR_LEN;
	metric = tvb_get_ntohs(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 2,
	    "Metric to %s: %u ticks (%g seconds)", tag, metric, metric*.2);
	offset += 2;
	node_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s Node Type: %s (0x%02x)", tag,
	    val_to_str(node_type, vines_rtp_node_type_vals, "Unknown"),
	    node_type);
	offset += 1;
	rtp_show_machine_type(tree, tvb, offset, tag);
	offset += 1;
	controller_type = tvb_get_guint8(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 1,
	    "%s Controller Type: %s (0x%02x)", tag,
	    val_to_str(controller_type, vines_rtp_controller_type_vals, "Unknown"),
	    controller_type);
	offset += 1;
	return offset;
}

static int
rtp_show_gateway_info(proto_tree *tree, tvbuff_t *tvb, int offset,
    guint8 link_addr_length, guint8 source_route_length)
{
	if (link_addr_length != 0) {
		proto_tree_add_text(tree, tvb, offset, link_addr_length,
		    "Preferred Gateway Data Link Address: %s",
		    link_addr_length == 6 ?
		    ether_to_str(tvb_get_ptr(tvb, offset, link_addr_length)) :
		    tvb_bytes_to_str(tvb, offset, link_addr_length));
		offset += link_addr_length;
	}
	if (source_route_length != 0) {
		proto_tree_add_text(tree, tvb, offset, source_route_length,
		    "Preferred Gateway Source Route: %s",
		    tvb_bytes_to_str(tvb, offset, source_route_length));
		offset += source_route_length;
	}
	return offset;
}

void
proto_register_vines_rtp(void)
{
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
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_rtp(void)
{
	dissector_handle_t vines_rtp_handle;

	vines_rtp_handle = create_dissector_handle(dissect_vines_rtp,
	    proto_vines_rtp);
	dissector_add("vines_ip.protocol", VIP_PROTO_RTP, vines_rtp_handle);
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
	proto_tree *vines_icp_tree = NULL;
	proto_item *ti;
	guint16  packet_type;
	guint16  exception_code;
	guint16  metric;
	gboolean save_in_error_pkt;
	tvbuff_t *next_tvb;

	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "Vines ICP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);

	if (tree) {
		ti = proto_tree_add_item(tree, proto_vines_icp, tvb, 0, -1,
		    FALSE);
		vines_icp_tree = proto_item_add_subtree(ti, ett_vines_icp);
	}

	packet_type = tvb_get_ntohs(tvb, offset);
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(packet_type, vines_icp_packet_type_vals,
		      "Unknown (0x%02x)"));
	}
	if (tree) {
		proto_tree_add_text(vines_icp_tree, tvb, offset, 2,
				    "Packet Type: %s (0x%04x)",
				    val_to_str(packet_type,
				      vines_icp_packet_type_vals,
				      "Unknown"),
				    packet_type);
	}
	offset += 2;

	switch (packet_type) {

	case VICP_EXCEPTION_NOTIFICATION:
		exception_code = tvb_get_ntohs(tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", %s",
			    val_to_str(exception_code, vipc_err_vals,
			        "Unknown exception code (%u)"));
		}
		if (tree) {
			proto_tree_add_text(vines_icp_tree, tvb, offset, 2,
					    "Exception Code: %s (%u)",
					    val_to_str(exception_code,
					      vipc_err_vals,
					      "Unknown"),
					    exception_code);
		}
		break;

	case VICP_METRIC_NOTIFICATION:
		metric = tvb_get_ntohs(tvb, offset);
		if (check_col(pinfo->cinfo, COL_INFO)) {
			col_append_fstr(pinfo->cinfo, COL_INFO, ", metric %u",
			    metric);
		}
		if (tree) {
			proto_tree_add_text(vines_icp_tree, tvb, offset, 2,
					    "Metric: %u", metric);
		}
		break;
	}
	offset += 2;

	/*
	 * Save the current value of the "we're inside an error packet"
	 * flag, and set that flag; subdissectors may treat packets
	 * that are the payload of error packets differently from
	 * "real" packets.
	 */
	save_in_error_pkt = pinfo->in_error_pkt;
	pinfo->in_error_pkt = TRUE;

	/* Decode the first 40 bytes of the original VIP datagram. */
	next_tvb = tvb_new_subset(tvb, offset, -1, -1);
	call_dissector(vines_ip_handle, next_tvb, pinfo, vines_icp_tree);

	/* Restore the "we're inside an error packet" flag. */
	pinfo->in_error_pkt = save_in_error_pkt;
}

void
proto_register_vines_icp(void)
{
	static gint *ett[] = {
		&ett_vines_icp,
	};

	proto_vines_icp = proto_register_protocol(
	    "Banyan Vines ICP", "Vines ICP", "vines_icp");
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines_icp(void)
{
	dissector_handle_t vines_icp_handle;

	vines_icp_handle = create_dissector_handle(dissect_vines_icp,
	    proto_vines_icp);
	dissector_add("vines_ip.protocol", VIP_PROTO_ICP, vines_icp_handle);
}
