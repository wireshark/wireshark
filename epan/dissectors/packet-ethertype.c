/* packet-ethertype.c
 * Routines for processing Ethernet payloads and payloads like Ethernet
 * payloads (i.e., payloads when there could be an Ethernet trailer and
 * possibly an FCS).
 *
 * $Id$
 *
 * Gilbert Ramirez <gram@alumni.rice.edu>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include "packet-eth.h"
#include "packet-frame.h"
#include "packet-ip.h"
#include "packet-ipv6.h"
#include "packet-ipx.h"
#include "packet-vlan.h"
#include "packet-ieee8021ah.h"
#include "packet-vines.h"
#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/prefs.h>

static dissector_table_t ethertype_dissector_table;

static dissector_handle_t data_handle;

const value_string etype_vals[] = {
  { ETHERTYPE_IP, "IP" },
  { ETHERTYPE_IPv6, "IPv6" },
  { ETHERTYPE_VLAN, "802.1Q Virtual LAN" },
  { ETHERTYPE_ARP, "ARP" },
  { ETHERTYPE_WLCCP, "Cisco Wireless Lan Context Control Protocol" },
  { ETHERTYPE_CENTRINO_PROMISC, "IEEE 802.11 (Centrino promiscuous)" },
  { ETHERTYPE_XNS_IDP, "XNS Internet Datagram Protocol" },
  { ETHERTYPE_X25L3, "X.25 Layer 3" },
  { ETHERTYPE_WOL, "Wake on LAN" },
  { ETHERTYPE_WMX_M2M, "WiMax Mac-to-Mac" },
  { ETHERTYPE_EPL_V1, "EPL_V1" },
  { ETHERTYPE_REVARP, "RARP" },
  { ETHERTYPE_DEC_LB, "DEC LanBridge" },
  { ETHERTYPE_ATALK, "Appletalk" },
  { ETHERTYPE_SNA, "SNA-over-Ethernet" },
  { ETHERTYPE_DLR, "EtherNet/IP Device Level Ring" },
  { ETHERTYPE_AARP, "AARP" },
  { ETHERTYPE_IPX, "Netware IPX/SPX" },
  { ETHERTYPE_VINES_IP, "Vines IP" },
  { ETHERTYPE_VINES_ECHO, "Vines Echo" },
  { ETHERTYPE_TRAIN, "Netmon Train" },
    /* Ethernet Loopback */
  { ETHERTYPE_LOOP, "Loopback" },
  { ETHERTYPE_FOUNDRY, "Foundry proprietary" },
  { ETHERTYPE_WCP, "Wellfleet Compression Protocol" },
  { ETHERTYPE_STP, "Spanning Tree Protocol" },
    /* for ISMP, see RFC 2641, RFC 2642, RFC 2643 */
  { ETHERTYPE_ISMP, "Cabletron Interswitch Message Protocol" },
  { ETHERTYPE_ISMP_TBFLOOD, "Cabletron SFVLAN 1.8 Tag-Based Flood" },
    /* In www.iana.org/assignments/ethernet-numbers, 8203-8205 description is
     * Quantum Software.  Now the company is called QNX Software Systems. */
  { ETHERTYPE_QNX_QNET6, "QNX 6 QNET protocol" },
  { ETHERTYPE_PPPOED, "PPPoE Discovery" },
  { ETHERTYPE_PPPOES, "PPPoE Session" },
  { ETHERTYPE_INTEL_ANS, "Intel ANS probe" },
  { ETHERTYPE_MS_NLB_HEARTBEAT, "MS NLB heartbeat" },
  { ETHERTYPE_JUMBO_LLC, "Jumbo LLC" },
  { ETHERTYPE_HOMEPLUG, "Homeplug" },
  { ETHERTYPE_HOMEPLUG_AV, "Homeplug AV" },
  { ETHERTYPE_IEEE_802_1AD, "802.1ad Provider Bridge (Q-in-Q)" },
  { ETHERTYPE_IEEE_802_1AH, "802.1ah Provider Backbone Bridge (mac-in-mac)" },
  { ETHERTYPE_EAPOL, "802.1X Authentication" },
  { ETHERTYPE_RSN_PREAUTH, "802.11i Pre-Authentication" },
  { ETHERTYPE_MPLS, "MPLS label switched packet" },
  { ETHERTYPE_MPLS_MULTI, "MPLS multicast label switched packet" },
  { ETHERTYPE_3C_NBP_DGRAM, "3Com NBP Datagram" },
  { ETHERTYPE_DEC, "DEC proto" },
  { ETHERTYPE_DNA_DL, "DEC DNA Dump/Load" },
  { ETHERTYPE_DNA_RC, "DEC DNA Remote Console" },
  { ETHERTYPE_DNA_RT, "DEC DNA Routing" },
  { ETHERTYPE_LAT, "DEC LAT" },
  { ETHERTYPE_DEC_DIAG, "DEC Diagnostics" },
  { ETHERTYPE_DEC_CUST, "DEC Customer use" },
  { ETHERTYPE_DEC_SCA, "DEC LAVC/SCA" },
  { ETHERTYPE_DEC_LAST, "DEC LAST" },
  { ETHERTYPE_ETHBRIDGE, "Transparent Ethernet bridging" },
  { ETHERTYPE_CGMP, "Cisco Group Management Protocol" },
  { ETHERTYPE_GIGAMON, "Gigamon Header" },
  { ETHERTYPE_MSRP, "802.1Qat Multiple Stream Reservation Protocol" },
  { ETHERTYPE_MMRP, "802.1ak Multiple Mac Registration Protocol" },
  { ETHERTYPE_AVBTP, "IEEE 1722 Audio Video Bridging Transport Protocol" },
  { ETHERTYPE_ROHC, "Robust Header Compression(RoHC)" },
  { ETHERTYPE_MAC_CONTROL, "MAC Control" },
  { ETHERTYPE_SLOW_PROTOCOLS, "Slow Protocols" },
  { ETHERTYPE_RTMAC, "Real-Time Media Access Control" },
  { ETHERTYPE_RTCFG, "Real-Time Configuration Protocol" },
  { ETHERTYPE_CDMA2000_A10_UBS, "CDMA2000 A10 Unstructured byte stream" },
  { ETHERTYPE_PROFINET, "PROFINET"},
  { ETHERTYPE_AOE, "ATA over Ethernet" },
  { ETHERTYPE_ECATF, "EtherCAT frame" },
  { ETHERTYPE_TELKONET, "Telkonet powerline" },
  { ETHERTYPE_EPL_V2, "ETHERNET Powerlink v2"	},
  { ETHERTYPE_XIMETA, "XiMeta Technology" },
  { ETHERTYPE_CSM_ENCAPS, "CSM_ENCAPS Protocol" },
  { ETHERTYPE_IEEE802_OUI_EXTENDED, "IEEE 802a OUI Extended Ethertype" },
  { ETHERTYPE_IEC61850_GOOSE, "IEC 61850/GOOSE" },
  { ETHERTYPE_IEC61850_GSE, "IEC 61850/GSE management services" },
  { ETHERTYPE_IEC61850_SV, "IEC 61850/SV (Sampled Value Transmission" },
  { ETHERTYPE_TIPC, "Transparent Inter Process Communication" },
  { ETHERTYPE_LLDP, "802.1 Link Layer Discovery Protocol (LLDP)" },
  { ETHERTYPE_3GPP2, "CDMA2000 A10 3GPP2 Packet" },
  { ETHERTYPE_TTE_PCF, "TTEthernet Protocol Control Frame" },
  { ETHERTYPE_LLTD, "Link Layer Topology Discovery (LLTD)" },
  { ETHERTYPE_WSMP, "(WAVE) Short Message Protocol (WSM)" },
  { ETHERTYPE_VMLAB, "VMware Lab Manager" },
  { ETHERTYPE_COBRANET, "Cirrus Cobranet Packet" },
  { ETHERTYPE_NSRP, "Juniper Netscreen Redundant Protocol" },
    /*
     * NDISWAN on Windows translates Ethernet frames from higher-level
     * protocols into PPP frames to hand to the PPP driver, and translates
     * PPP frames from the PPP driver to hand to the higher-level protocols.
     *
     * Apparently the PPP driver, on at least some versions of Windows,
     * passes frames for internal-to-PPP protocols up through NDISWAN;
     * the protocol type field appears to be passed through unchanged
     * (unlike what's done with, for example, the protocol type field
     * for IP, which is mapped from its PPP value to its Ethernet value).
     *
     * This means that we may see, on Ethernet captures, frames for
     * protocols internal to PPP, so we list as "Ethernet" protocol
     * types the PPP protocol types we've seen.
     */
  { PPP_IPCP, "PPP IP Control Protocol" },
  { PPP_LCP, "PPP Link Control Protocol" },
  { PPP_PAP, "PPP Password Authentication Protocol" },
  { PPP_CCP, "PPP Compression Control Protocol" },
  { ETHERTYPE_LLT, "Veritas Low Latency Transport (not officially registered)" },
  { ETHERTYPE_CFM, "IEEE 802.1ag Connectivity Fault Management (CFM) protocol" },
  { ETHERTYPE_DCE, "Data Center Ethernet (DCE) protocol(Cisco)" },
  { ETHERTYPE_FCOE, "Fibre Channel over Ethernet" },
  { ETHERTYPE_IEEE80211_DATA_ENCAP, "IEEE 802.11 data encapsulation" },
  { ETHERTYPE_LINX, "LINX IPC Protocol" },
  { ETHERTYPE_FIP, "FCoE Initialization Protocol" },
  { ETHERTYPE_PTP, "PTPv2 over Ethernet (IEEE1588)" },
  { ETHERTYPE_PRP, "Parallel Redundancy Protocol (IEC62439 Chapter 6)" },
  { ETHERTYPE_FLIP, "Flow Layer Internal Protocol" },
  { ETHERTYPE_ROCE, "RDMA over Converged Ethernet" },
  { ETHERTYPE_TDMOE, "Digium TDM over Ethernet Protocol" },
  { ETHERTYPE_WAI, "WAI Authentication Protocol" },
  { 0, NULL }
};

static void add_dix_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
    int trailer_id, tvbuff_t *tvb, tvbuff_t *next_tvb, int offset_after_etype,
    guint length_before, gint fcs_len);

void
capture_ethertype(guint16 etype, const guchar *pd, int offset, int len,
		  packet_counts *ld)
{
  switch (etype) {
    case ETHERTYPE_ARP:
      ld->arp++;
      break;
    case ETHERTYPE_IP:
      capture_ip(pd, offset, len, ld);
      break;
    case ETHERTYPE_IPv6:
      capture_ipv6(pd, offset, len, ld);
      break;
    case ETHERTYPE_IPX:
      capture_ipx(ld);
      break;
    case ETHERTYPE_VLAN:
      capture_vlan(pd, offset, len, ld);
      break;
    case ETHERTYPE_IEEE_802_1AD:
    case ETHERTYPE_IEEE_802_1AH:
      capture_ieee8021ah(pd, offset, len, ld);
      break;
    case ETHERTYPE_VINES_IP:
    case ETHERTYPE_VINES_ECHO:
      capture_vines(ld);
      break;
    default:
      ld->other++;
      break;
  }
}

void
ethertype(guint16 etype, tvbuff_t *tvb, int offset_after_etype,
	  packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
	  int etype_id, int trailer_id, int fcs_len)
{
	const char		*description;
	tvbuff_t		*volatile next_tvb;
	guint			length_before;
	gint			captured_length, reported_length;
	volatile gboolean	dissector_found = FALSE;
	const char		*volatile saved_proto;
	void			*pd_save;
			module_t *eth_module;
			pref_t *q_in_q_pref;

	/* Add the Ethernet type to the protocol tree */
	if (tree) {
		eth_module = prefs_find_module("eth");
		if (eth_module)
			q_in_q_pref = prefs_find_preference(eth_module, "qinq_ethertype");
		if (q_in_q_pref && (etype == prefs_get_uint_preference(q_in_q_pref)))
		proto_tree_add_uint_format_value(fh_tree, etype_id, tvb,
			offset_after_etype - 2, 2, etype, 
			"802.1QinQ VLAN in VLAN tunneling (0x%04x)", etype);
		else
			proto_tree_add_uint(fh_tree, etype_id, tvb, 
				offset_after_etype - 2, 2, etype);
	}

	/* Get the captured length and reported length of the data
	   after the Ethernet type. */
	captured_length = tvb_length_remaining(tvb, offset_after_etype);
	reported_length = tvb_reported_length_remaining(tvb,
	    offset_after_etype);

	/* Remember how much data there is after the Ethernet type,
	   including any trailer and FCS. */
	length_before = reported_length;

	/* Construct a tvbuff for the payload after the Ethernet type.
	   If the FCS length is positive, remove the FCS.
	   (If it's zero, there's no FCS; if it's negative,
	   we don't know whether there's an FCS, so we'll
	   guess based on the length of the trailer.) */
	if (fcs_len > 0) {
		if (captured_length >= 0 && reported_length >= 0) {
			if (reported_length >= fcs_len)
				reported_length -= fcs_len;
			if (captured_length > reported_length)
				captured_length = reported_length;
		}
	}
	next_tvb = tvb_new_subset(tvb, offset_after_etype, captured_length,
	    reported_length);

	pinfo->ethertype = etype;

	/* Look for sub-dissector, and call it if found.
	   Catch exceptions, so that if the reported length of "next_tvb"
	   was reduced by some dissector before an exception was thrown,
	   we can still put in an item for the trailer. */
	saved_proto = pinfo->current_proto;
	pd_save = pinfo->private_data;
	TRY {
		dissector_found = dissector_try_uint(ethertype_dissector_table,
		    etype, next_tvb, pinfo, tree);
	}
	CATCH(BoundsError) {
		/* Somebody threw BoundsError, which means that:

		     1) a dissector was found, so we don't need to
		        dissect the payload as data or update the
		        protocol or info columns;

		     2) dissecting the payload found that the packet was
		        cut off by a snapshot length before the end of
		        the payload.  The trailer comes after the payload,
		        so *all* of the trailer is cut off, and we'll
		        just get another BoundsError if we add the trailer.

		   Therefore, we just rethrow the exception so it gets
		   reported; we don't dissect the trailer or do anything
		   else. */
		 RETHROW;
	}
	CATCH(OutOfMemoryError) {
		 RETHROW;
	}
	CATCH_ALL {
		/* Somebody threw an exception other than BoundsError, which
		   means that a dissector was found, so we don't need to
		   dissect the payload as data or update the protocol or info
		   columns.  We just show the exception and then drive on
		   to show the trailer, after noting that a dissector was
		   found and restoring the protocol value that was in effect
		   before we called the subdissector. */
		show_exception(next_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);

		/*  Restore the private_data structure in case one of the
		 *  called dissectors modified it (and, due to the exception,
		 *  was unable to restore it).
		 */
		pinfo->private_data = pd_save;
		dissector_found = TRUE;
		pinfo->current_proto = saved_proto;
	}
	ENDTRY;

	if (!dissector_found) {
		/* No sub-dissector found.
		   Label rest of packet as "Data" */
		call_dissector(data_handle,next_tvb, pinfo, tree);

		/* Label protocol */
		col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", etype);

		description = match_strval(etype, etype_vals);
		if (description) {
			col_add_str(pinfo->cinfo, COL_INFO, description);
		}
	}

	add_dix_trailer(pinfo, tree, fh_tree, trailer_id, tvb, next_tvb, offset_after_etype,
			length_before, fcs_len);
}

static void
add_dix_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree, int trailer_id,
		tvbuff_t *tvb, tvbuff_t *next_tvb, int offset_after_etype,
		guint length_before, gint fcs_len)
{
	guint		length;
	tvbuff_t	*trailer_tvb;

	if (fh_tree == NULL)
		return;	/* we're not building a protocol tree */

	/* OK, how much is there in that tvbuff now? */
	length = tvb_reported_length(next_tvb);

	/* If there's less than there was before, what's left is
	   a trailer. */
	if (length < length_before) {
		/*
		 * Is any of the padding present in the tvbuff?
		 */
		if (tvb_offset_exists(tvb, offset_after_etype + length)) {
			/*
			 * Yes - create a tvbuff for the padding.
			 */
			trailer_tvb = tvb_new_subset_remaining(tvb,
			    offset_after_etype + length);
		} else {
			/*
			 * No - don't bother showing the trailer.
			 * XXX - show a Short Frame indication?
			 */
			trailer_tvb = NULL;
		}
	} else
		trailer_tvb = NULL;	/* no trailer */

	add_ethernet_trailer(pinfo, tree, fh_tree, trailer_id, tvb, trailer_tvb, fcs_len);
}

void
proto_register_ethertype(void)
{
	/* subdissector code */
	ethertype_dissector_table = register_dissector_table("ethertype",
	    "Ethertype", FT_UINT16, BASE_HEX);
}

void
proto_reg_handoff_ethertype(void)
{
	data_handle = find_dissector("data");
}
