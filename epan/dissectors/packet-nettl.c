/* packet-nettl.c
 * Routines for nettl (HP-UX) record header dissection
 *
 * Original Author Mark C. Brown <mbrown@hp.com>
 * Copyright (C) 2005 Hewlett-Packard Development Company, L.P.
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-pagp.c
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
#include <epan/ipproto.h>
#include <wiretap/nettl.h>

/* Initialise the protocol and registered fields */

static int proto_nettl = -1;

static int hf_nettl_subsys = -1;
static int hf_nettl_devid = -1;
static int hf_nettl_kind = -1;
static int hf_nettl_pid = -1;
static int hf_nettl_uid = -1;

static dissector_handle_t eth_withoutfcs_handle;
static dissector_handle_t tr_handle;
static dissector_handle_t lapb_handle;
static dissector_handle_t x25_handle;
static dissector_handle_t data_handle;
static dissector_table_t wtap_dissector_table;
static dissector_table_t ip_proto_dissector_table;

/* Initialise the subtree pointers */

static gint ett_nettl = -1;

/* General declarations and macros */

static const value_string trace_kind[] = {
	{ 0x80000000, "Incoming Header" },
	{ 0x40000000, "Outgoing Header" },
	{ 0x20000000, "Incoming PDU - PDUIN" },
	{ 0x20000000, "PDUIN" },
	{ 0x10000000, "Outgoing PDU - PDUOUT" },
	{ 0x10000000, "PDUOUT" },
	{ 0x08000000, "Procedure" },
	{ 0x04000000, "State" },
	{ 0x02000000, "Error" },
	{ 0x01000000, "Logging" },
	{ 0x00800000, "Loopback" },
	{ 0, NULL }
};

static const value_string subsystem[] = {
	{ 0, "NS_LS_LOGGING" },
	{ 1, "NS_LS_NFT" },
	{ 2, "NS_LS_LOOPBACK" },
	{ 3, "NS_LS_NI" },
	{ 4, "NS_LS_IPC" },
	{ 5, "NS_LS_SOCKREGD" },
	{ 6, "NS_LS_TCP" },
	{ 7, "NS_LS_PXP" },
	{ 8, "NS_LS_UDP" },
	{ 9, "NS_LS_IP" },
	{ 10, "NS_LS_PROBE" },
	{ 11, "NS_LS_DRIVER" },
	{ 12, "NS_LS_RLBD" },
	{ 13, "NS_LS_BUFS" },
	{ 14, "NS_LS_CASE21" },
	{ 15, "NS_LS_ROUTER21" },
	{ 16, "NS_LS_NFS" },
	{ 17, "NS_LS_NETISR" },
	{ 18, "NS_LS_X25D" },
	{ 19, "NS_LS_NSE" },
	{ 20, "NS_LS_STRLOG" },
	{ 21, "NS_LS_TIRDWR" },
	{ 22, "NS_LS_TIMOD" },
	{ 23, "NS_LS_ICMP" },
	{ 24, "X25L2" },
	{ 25, "X25L3" },
	{ 26, "FILTER" },
	{ 27, "NAME" },
	{ 28, "ACC" },
	{ 29, "NS_LS_IGMP" },
	{ 31, "TOKEN" },
	{ 32, "HIPPI" },
	{ 33, "FC" },
	{ 34, "SX25L2" },
	{ 35, "SX25L3" },
	{ 36, "NS_LS_SX25" },
	{ 37, "100VG" },
	{ 38, "ATM" },
	{ 64, "FTAM_INIT" },
	{ 65, "FTAM_RESP" },
	{ 70, "FTAM_VFS" },
	{ 72, "FTAM_USER" },
	{ 82, "OVS" },
	{ 84, "OVEXTERNAL" },
	{ 90, "OTS9000" },
	{ 91, "OTS9000-NETWORK" },
	{ 92, "OTS9000-TRANSPORT" },
	{ 93, "OTS9000-SESSION" },
	{ 94, "OTS9000-ACSE_PRES" },
	{ 95, "FDDI" },
	{ 116, "SHM" },
	{ 119, "ACSE_US" },
	{ 121, "HPS" },
	{ 122, "CM" },
	{ 123, "ULA_UTILS" },
	{ 124, "EM" },
	{ 129, "STREAMS" },
	{ 164, "LAN100" },
	{ 172, "EISA100BT" },
	{ 173, "BASE100" },
	{ 174, "EISA_FDDI" },
	{ 176, "PCI_FDDI" },
	{ 177, "HSC_FDDI" },
	{ 178, "GSC100BT" },
	{ 179, "PCI100BT" },
	{ 180, "SPP100BT" },
	{ 185, "GELAN" },
	{ 187, "PCITR" },
	{ 188, "HP_APA" },
	{ 189, "HP_APAPORT" },
	{ 190, "HP_APALACP" },
	{ 210, "BTLAN" },
	{ 227, "NS_LS_SCTP" },
	{ 233, "INTL100" },
	{ 244, "NS_LS_IPV6" },
	{ 245, "NS_LS_ICMPV6" },
	{ 246, "DLPI" },
	{ 247, "VLAN" },
	{ 249, "NS_LS_LOOPBACK6" },
	{ 250, "DHCPV6D" },
	{ 252, "IGELAN" },
	{ 253, "IETHER" },
	{ 265, "IXGBE" },
	{ 513, "KL_VM" },
	{ 514, "KL_PKM" },
	{ 515, "KL_DLKM" },
	{ 516, "KL_PM" },
	{ 517, "KL_VFS" },
	{ 518, "KL_VXFS" },
	{ 519, "KL_UFS" },
	{ 520, "KL_NFS" },
	{ 521, "KL_FSVM" },
	{ 522, "KL_WSIO" },
	{ 523, "KL_SIO" },
	{ 524, "KL_NET" },
	{ 525, "KL_MC" },
	{ 526, "KL_DYNTUNE" },
	{ 0, NULL }
};


/* Code to actually dissect the nettl record headers */

static void
dissect_nettl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
      proto_tree *nettl_tree;
      proto_item *nettl_item;

      pinfo->current_proto = "nettl";

      if (check_col(pinfo->cinfo, COL_HPUX_SUBSYS))
            col_set_str(pinfo->cinfo, COL_HPUX_SUBSYS,
		val_to_str(pinfo->pseudo_header->nettl.subsys, subsystem, "Unknown"));
      if (check_col(pinfo->cinfo, COL_HPUX_DEVID)) {
            col_clear(pinfo->cinfo, COL_HPUX_DEVID);
            col_add_fstr(pinfo->cinfo, COL_HPUX_DEVID, "%4d",
		pinfo->pseudo_header->nettl.devid);
      }

      if (tree) {
	    nettl_item = proto_tree_add_protocol_format(tree, proto_nettl, tvb,
		0, -1, "HP-UX Network Tracing and Logging (nettl) header");
	    nettl_tree = proto_item_add_subtree(nettl_item, ett_nettl);
            proto_tree_add_uint_format(nettl_tree, hf_nettl_subsys, tvb,
		0, 0, pinfo->pseudo_header->nettl.subsys,
		"Subsystem: %d (%s)", pinfo->pseudo_header->nettl.subsys,
		val_to_str(pinfo->pseudo_header->nettl.subsys, subsystem, "Unknown"));
            proto_tree_add_int(nettl_tree, hf_nettl_devid, tvb,
		0, 0, pinfo->pseudo_header->nettl.devid);
            proto_tree_add_uint_format(nettl_tree, hf_nettl_kind, tvb,
		0, 0, pinfo->pseudo_header->nettl.kind,
		"Trace Kind: 0x%08x (%s)", pinfo->pseudo_header->nettl.kind,
		val_to_str(pinfo->pseudo_header->nettl.kind, trace_kind, "Unknown"));
            proto_tree_add_int(nettl_tree, hf_nettl_pid, tvb,
		0, 0, pinfo->pseudo_header->nettl.pid);
            proto_tree_add_uint(nettl_tree, hf_nettl_uid, tvb,
		0, 0, pinfo->pseudo_header->nettl.uid);

      }

      switch (pinfo->fd->lnk_t) {
         case WTAP_ENCAP_NETTL_ETHERNET:
            call_dissector(eth_withoutfcs_handle, tvb, pinfo, tree);
            break;
         case WTAP_ENCAP_NETTL_TOKEN_RING:
            call_dissector(tr_handle, tvb, pinfo, tree);
            break;
         case WTAP_ENCAP_NETTL_FDDI:
            if (!dissector_try_port(wtap_dissector_table,
			WTAP_ENCAP_FDDI_BITSWAPPED, tvb, pinfo, tree))
	            call_dissector(data_handle, tvb, pinfo, tree);
            break;
         case WTAP_ENCAP_NETTL_RAW_IP:
            if (!dissector_try_port(wtap_dissector_table,
			WTAP_ENCAP_RAW_IP, tvb, pinfo, tree))
	            call_dissector(data_handle, tvb, pinfo, tree);
            break;
         case WTAP_ENCAP_NETTL_RAW_ICMP:
            if (!dissector_try_port(ip_proto_dissector_table,
			IP_PROTO_ICMP, tvb, pinfo, tree))
	            call_dissector(data_handle, tvb, pinfo, tree);
            break;
         case WTAP_ENCAP_NETTL_RAW_ICMPV6:
            if (!dissector_try_port(ip_proto_dissector_table,
	                IP_PROTO_ICMPV6, tvb, pinfo, tree))
	            call_dissector(data_handle, tvb, pinfo, tree);
            break;
         case WTAP_ENCAP_NETTL_X25:
	    if (pinfo->pseudo_header->nettl.kind == NETTL_HDR_PDUIN)
            	pinfo->p2p_dir = P2P_DIR_RECV;
	    else if (pinfo->pseudo_header->nettl.kind == NETTL_HDR_PDUOUT)
            	pinfo->p2p_dir = P2P_DIR_SENT;
	    if (pinfo->pseudo_header->nettl.subsys == NETTL_SUBSYS_SX25L2)
            	call_dissector(lapb_handle, tvb, pinfo, tree);
	    else
            	call_dissector(x25_handle, tvb, pinfo, tree);
            break;
         default:
            if (check_col(pinfo->cinfo, COL_PROTOCOL))
                col_set_str(pinfo->cinfo, COL_PROTOCOL, "UNKNOWN");
            if (check_col(pinfo->cinfo, COL_INFO))
                col_add_fstr(pinfo->cinfo, COL_INFO,
		"Unsupported nettl subsytem: %d (%s)",
                pinfo->pseudo_header->nettl.subsys,
		val_to_str(pinfo->pseudo_header->nettl.subsys, subsystem, "Unknown"));
            call_dissector(data_handle, tvb, pinfo, tree);
      }
}


/* Register the protocol with Wireshark */

void
proto_register_nettl(void)
{
/* Setup list of header fields */

  static hf_register_info hf[] = {

	{ &hf_nettl_subsys,
	{ "Subsystem", "nettl.subsys", FT_UINT16, BASE_DEC, VALS(subsystem), 0x0,
		"HP-UX Subsystem/Driver", HFILL }},

	{ &hf_nettl_devid,
	{ "Device ID", "nettl.devid", FT_INT32, BASE_DEC, NULL, 0x0,
		"HP-UX Device ID", HFILL }},

	{ &hf_nettl_kind,
	{ "Trace Kind", "nettl.kind", FT_UINT32, BASE_HEX, VALS(trace_kind), 0x0,
		"HP-UX Trace record kind", HFILL}},

	{ &hf_nettl_pid,
	{ "Process ID (pid/ktid)", "nettl.pid", FT_INT32, BASE_DEC, NULL, 0x0,
		"HP-UX Process/thread id", HFILL}},

	{ &hf_nettl_uid,
	{ "User ID (uid)", "nettl.uid", FT_UINT16, BASE_DEC, NULL, 0x0,
		"HP-UX User ID", HFILL}},

  };

  /* Setup protocol subtree array */

  static gint *ett[] = {
    &ett_nettl,
  };

  /* Register the protocol name and description */

  proto_nettl = proto_register_protocol("HP-UX Network Tracing and Logging", "nettl", "nettl");

  /* Required function calls to register the header fields and subtrees used */

  proto_register_field_array(proto_nettl, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


void
proto_reg_handoff_nettl(void)
{
  dissector_handle_t nettl_handle;

                                                                                
  /*
   * Get handles for the Ethernet, Token Ring, FDDI, and RAW dissectors.
  */
  eth_withoutfcs_handle = find_dissector("eth_withoutfcs");
  tr_handle = find_dissector("tr");
  lapb_handle = find_dissector("lapb");
  x25_handle = find_dissector("x.25");
  data_handle = find_dissector("data");
  wtap_dissector_table = find_dissector_table("wtap_encap");
  ip_proto_dissector_table = find_dissector_table("ip.proto");

  nettl_handle = create_dissector_handle(dissect_nettl, proto_nettl);
  dissector_add("wtap_encap", WTAP_ENCAP_NETTL_ETHERNET, nettl_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_NETTL_TOKEN_RING, nettl_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_NETTL_FDDI, nettl_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_NETTL_RAW_IP, nettl_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_NETTL_RAW_ICMP, nettl_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_NETTL_RAW_ICMPV6, nettl_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_NETTL_X25, nettl_handle);
  dissector_add("wtap_encap", WTAP_ENCAP_NETTL_UNKNOWN, nettl_handle);
}
