/* packet-vines.c
 * Routines for Banyan VINES protocol packet disassembly
 *
 * $Id: packet-vines.c,v 1.18 2000/08/25 18:46:10 deniel Exp $
 *
 * Don Lafontaine <lafont02@cn.ca>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 * Joerg Mayer <jmayer@telemation.de>
 *
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

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <glib.h>
#include "etypes.h"
#include "ppptypes.h"
#include "packet.h"
#include "packet-vines.h"
#include "packet-ip.h"

static int proto_vines = -1;
static int hf_vines_protocol = -1;

static gint ett_vines = -1;
static gint ett_vines_frp = -1;
static gint ett_vines_spp = -1;

#if 0
static void dissect_vines_arp(const u_char *, int, frame_data *, proto_tree *);
static void dissect_vines_icp(const u_char *, int, frame_data *, proto_tree *);
static void dissect_vines_ipc(const u_char *, int, frame_data *, proto_tree *);
static void dissect_vines_rtp(const u_char *, int, frame_data *, proto_tree *);
#endif
static void dissect_vines_spp(const u_char *, int, frame_data *, proto_tree *);
static void dissect_vines(const u_char *, int, frame_data *, proto_tree *);

void
capture_vines(const u_char *pd, int offset, packet_counts *ld)
{
  ld->vines++;
}

/* AFAIK Vines FRP (Fragmentation Protocol) is used on all media except Ethernet
 * and TR (and probably FDDI) - Fragmentation on these media types is not possible
 * FIXME: Do we need to use this header with PPP too?
 */
void
dissect_vines_frp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  guint8   vines_frp_ctrl, vines_frp_seqno; 
  proto_tree *vines_frp_tree;
  proto_item *ti;
  gchar	frp_flags_str[32];

  /* To do: Check for {cap len,pkt len} < struct len */

  vines_frp_ctrl = pd[offset];
  vines_frp_seqno = pd[offset+1];
  
  if (check_col(fd, COL_PROTOCOL))
    col_add_str(fd, COL_PROTOCOL, "Vines FRP");
  /*
   * 1: first fragment of vines packet
   * 2: last fragment of vines packet
   * 4 ... 80: unused
   */
  switch (vines_frp_ctrl) {
  case 0:
    strcpy(frp_flags_str, "middle");
    break;
  case 1:
    strcpy(frp_flags_str, "first");
    break;
  case 2:
    strcpy(frp_flags_str, "last");
    break;
  case 3:
    strcpy(frp_flags_str, "only");
    break;
  default:
    strcpy(frp_flags_str, "please report: unknown");
    break;
  }
  
  if (tree) {
    ti = proto_tree_add_text(tree, NullTVB, offset, 2, 
			     "Vines Fragmentation Protocol");
    vines_frp_tree = proto_item_add_subtree(ti, ett_vines_frp);
    proto_tree_add_text(vines_frp_tree, NullTVB, offset,     1, 
			"Control Flags: 0x%02x = %s fragment", 
			vines_frp_ctrl, frp_flags_str);
    proto_tree_add_text(vines_frp_tree, NullTVB, offset + 1, 1, 
			"Sequence Number: 0x%02x", vines_frp_seqno);
  }

  /* Skip over header */
  offset += 2;

  /* Decode the "real" Vines now */
  dissect_vines(pd, offset, fd, tree);
}

gchar *
vines_addr_to_str(const guint8 *addrp)
{
  static gchar	str[3][214];
  static gchar	*cur;

  if (cur == &str[0][0]) {
    cur = &str[1][0];
  } else if (cur == &str[1][0]) {
    cur = &str[2][0];
  } else {
    cur = &str[0][0];
  }

  sprintf(cur, "%08x.%04x", pntohl(&addrp[0]), pntohs(&addrp[4]));
  return cur;
}

static void
dissect_vines(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {
  	e_vip       viph;
  	proto_tree *vip_tree;
	proto_item *ti;
/*  	gchar      tos_str[32]; */
	int  is_broadcast = 0;
	int  hops = 0;

	OLD_CHECK_DISPLAY_AS_DATA(proto_vines, pd, offset, fd, tree);

	/* To do: check for runts, errs, etc. */

	/* Avoids alignment problems on many architectures. */
  	memcpy(&viph, &pd[offset], sizeof(e_vip));

  	viph.vip_chksum = pntohs(&pd[offset]);
  	viph.vip_pktlen = pntohs(&pd[offset+2]);
  	viph.vip_dnet = pntohl(&pd[offset+6]);
  	viph.vip_dsub = pntohs(&pd[offset+10]);
  	viph.vip_snet = pntohl(&pd[offset+12]);
  	viph.vip_ssub = pntohs(&pd[offset+16]);

    	switch (viph.vip_proto) {
       	case VIP_PROTO_IPC:
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "Vines IPC");
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "IPC (%02x)", viph.vip_proto);
 		break;
       	case VIP_PROTO_SPP:      
		if (check_col(fd, COL_PROTOCOL))
        		col_add_str(fd, COL_PROTOCOL, "Vines SPP");
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "SPP (%02x)", viph.vip_proto);
		break;
	case VIP_PROTO_ARP:
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "Vines ARP");
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "ARP (%02x)", viph.vip_proto);
		break;
	case VIP_PROTO_RTP:
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "Vines RTP");
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "RTP (%02x)", viph.vip_proto);
		break;
	case VIP_PROTO_ICP:
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "Vines ICP");
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "ICP (%02x)", viph.vip_proto);
		break;
	default:
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "Vines IP");
		if (check_col(fd, COL_INFO))
			col_add_fstr(fd, COL_INFO, "Unknown VIP protocol (%02x)", 
				     viph.vip_proto);
	}

	SET_ADDRESS(&pi.net_src, AT_VINES, VINES_ADDR_LEN, &pd[offset+12]);
	SET_ADDRESS(&pi.src, AT_VINES, VINES_ADDR_LEN, &pd[offset+12]);
	SET_ADDRESS(&pi.net_dst, AT_VINES, VINES_ADDR_LEN, &pd[offset+6]);
	SET_ADDRESS(&pi.dst, AT_VINES, VINES_ADDR_LEN, &pd[offset+6]);

 	/* helpers to decode flags */
	/* FIXME: Not used yet */
 	if ((viph.vip_dnet == 0xffffffff) && (viph.vip_dsub == 0xffff)) {
 		is_broadcast = 1;
 	}
 	hops = viph.vip_tctl & 0xf; 
 
	/*
  	viph.ip_tos = IPTOS_TOS(viph.ip_tos);
  	switch (viph.ip_tos) {
    	case IPTOS_NONE:
    	  	strcpy(tos_str, "None");
    	  	break;
    	case IPTOS_LOWDELAY:
    	  	strcpy(tos_str, "Minimize delay");
    	  	break;
    	case IPTOS_THROUGHPUT:
    	  	strcpy(tos_str, "Maximize throughput");
    	  	break;
    	case IPTOS_RELIABILITY:
    	  	strcpy(tos_str, "Maximize reliability");
    	  	break;
    	case IPTOS_LOWCOST:
    	  	strcpy(tos_str, "Minimize cost");
    	  	break;
    	default:
    	  	strcpy(tos_str, "Unknon.  Malformed?");
    	  	break;
  	}
	*/

  	if (tree) {
		ti = proto_tree_add_protocol_format(tree, proto_vines, NullTVB, 
						    offset, (viph.vip_pktlen),
						    "Vines IP");
		vip_tree = proto_item_add_subtree(ti, ett_vines);
		proto_tree_add_text(vip_tree, NullTVB, offset,      2, 
				    "Packet checksum: 0x%04x", 
				    viph.vip_chksum);
		proto_tree_add_text(vip_tree, NullTVB, offset +  2, 2, 
				    "Packet length: 0x%04x (%d)", 
				    viph.vip_pktlen, viph.vip_pktlen); 
		proto_tree_add_text(vip_tree, NullTVB, offset +  4, 1, 
				    "Transport control: 0x%02x",
				    viph.vip_tctl);
		proto_tree_add_uint(vip_tree, hf_vines_protocol, NullTVB, 
				    offset +  5, 1, 
				    viph.vip_proto);
		proto_tree_add_text(vip_tree, NullTVB, offset +  6, 
				    VINES_ADDR_LEN, 
				    "Destination: %s",
				    vines_addr_to_str(&pd[offset + 6]));
		proto_tree_add_text(vip_tree, NullTVB, offset +  12, 
				    VINES_ADDR_LEN, 
				    "Source: %s",
				    vines_addr_to_str(&pd[offset + 12]));

	}

  	offset += 18;
	switch (viph.vip_proto) {
    	case VIP_PROTO_SPP:
		dissect_vines_spp(pd, offset, fd, tree);
    		break;
	default:
		old_dissect_data(pd, offset, fd, tree);
		break;
	}
}

void dissect_vines_spp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree) {

	e_vspp       viph;
  	proto_tree *vspp_tree;
	proto_item *ti;

	/* To do: check for runts, errs, etc. */

	/* Avoids alignment problems on many architectures. */
  	memcpy(&viph, &pd[offset], sizeof(e_vspp));

  	viph.vspp_sport = ntohs(viph.vspp_sport);
  	viph.vspp_dport = ntohs(viph.vspp_dport);
  	viph.vspp_lclid = ntohs(viph.vspp_lclid);
  	viph.vspp_rmtid = ntohs(viph.vspp_rmtid);

	switch (viph.vspp_pkttype) {
      	case VSPP_PKTTYPE_DATA:      
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "VSPP Data");
        	break;
      	case VSPP_PKTTYPE_DISC:      
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "VSPP Disconnect");
        	break;
      	case VSPP_PKTTYPE_PROBE:      
		if (check_col(fd, COL_PROTOCOL))
			col_add_str(fd, COL_PROTOCOL, "VSPP Probe");
        	break;
      	case VSPP_PKTTYPE_ACK:
		if (check_col(fd, COL_PROTOCOL))
   	    		col_add_str(fd, COL_PROTOCOL, "VSPP Ack");
		break;
      	default:
		if (check_col(fd, COL_PROTOCOL))
   	    		col_add_str(fd, COL_PROTOCOL, "VSPP Unknown");
    	}

	if (check_col(fd, COL_INFO))
       		col_add_fstr(fd, COL_INFO, 
			     "NS=%04x NR=%04x Window=%04x RID=%04x LID=%04x D=%04x S=%04x", 
			     viph.vspp_seqno, viph.vspp_ack, viph.vspp_win, 
			     viph.vspp_rmtid, viph.vspp_lclid, viph.vspp_dport,
			     viph.vspp_sport);

	/*
	iph.ip_tos = IPTOS_TOS(iph.ip_tos);
	switch (iph.ip_tos) {
    	case IPTOS_NONE:
    	  	strcpy(tos_str, "None");
    	  	break;
    	case IPTOS_LOWDELAY:
    	  	strcpy(tos_str, "Minimize delay");
    	  	break;
    	case IPTOS_THROUGHPUT:
    	  	strcpy(tos_str, "Maximize throughput");
    	  	break;
    	case IPTOS_RELIABILITY:
    	  	strcpy(tos_str, "Maximize reliability");
    	  	break;
    	case IPTOS_LOWCOST:
    	  	strcpy(tos_str, "Minimize cost");
    	  	break;
    	default:
    	  	strcpy(tos_str, "Unknon.  Malformed?");
    	  	break;
  	}
	*/ 

  	if (tree) {
		ti = proto_tree_add_text(tree, NullTVB, offset, sizeof(viph), "Vines SPP");
		vspp_tree = proto_item_add_subtree(ti, ett_vines_spp);
		proto_tree_add_text(vspp_tree, NullTVB, offset,      2, 
				    "Source port: 0x%04x", viph.vspp_sport);
		proto_tree_add_text(vspp_tree, NullTVB, offset+2,    2, 
				    "Destination port: 0x%04x",
				    viph.vspp_dport); 
		proto_tree_add_text(vspp_tree, NullTVB, offset+4,    1, 
				    "Packet type: 0x%02x", viph.vspp_pkttype);
		proto_tree_add_text(vspp_tree, NullTVB, offset+5,    1, 
				    "Control: 0x%02x", viph.vspp_control);
		proto_tree_add_text(vspp_tree, NullTVB, offset+6,    2, 
				    "Local Connection ID: 0x%04x",
				    viph.vspp_lclid);
		proto_tree_add_text(vspp_tree, NullTVB, offset+8,    2,
				    "Remote Connection ID: 0x%04x", 
				    viph.vspp_rmtid);
		proto_tree_add_text(vspp_tree, NullTVB, offset+10,   2,
				    "Sequence number: 0x%04x", 
				    viph.vspp_seqno);
		proto_tree_add_text(vspp_tree, NullTVB, offset+12,   2,
				    "Ack number: 0x%04x", viph.vspp_ack);
		proto_tree_add_text(vspp_tree, NullTVB, offset+14,   2,
				    "Window: 0x%04x", viph.vspp_win);
	}
	offset += 16; /* sizeof SPP */
	old_dissect_data(pd, offset, fd, tree);
}

void
proto_register_vines(void)
{
	static gint *ett[] = {
		&ett_vines,
		&ett_vines_frp,
		&ett_vines_spp,
	};

	static hf_register_info hf[] = {
	  { &hf_vines_protocol,
	    { "Protocol",			"vines.protocol",
	      FT_UINT8,		BASE_HEX,	NULL,	0x0,
	      "Vines protocol" }}
	};

	proto_vines = proto_register_protocol("Banyan Vines", "vines");
	proto_register_field_array(proto_vines, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_vines(void)
{
	old_dissector_add("ethertype", ETHERTYPE_VINES, dissect_vines);
	old_dissector_add("ppp.protocol", PPP_VINES, dissect_vines);
	old_dissector_add("ip.proto", IP_PROTO_VINES, dissect_vines_frp);
}
