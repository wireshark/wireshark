/* packet-ethertype.c
 * Routines for processing Ethernet payloads and payloads like Ethernet
 * payloads (i.e., payloads when there could be an Ethernet trailer and
 * possibly an FCS).
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

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/etypes.h>
#include <epan/ppptypes.h>
#include <epan/show_exception.h>
#include <epan/decode_as.h>
#include <epan/capture_dissectors.h>
#include <epan/proto_data.h>
#include "packet-eth.h"

void proto_register_ethertype(void);

static dissector_table_t ethertype_dissector_table;

static int proto_ethertype = -1;

const value_string etype_vals[] = {
	{ ETHERTYPE_IP,                   "IPv4" },
	{ ETHERTYPE_IPv6,                 "IPv6" },
	{ ETHERTYPE_VLAN,                 "802.1Q Virtual LAN" },
	{ ETHERTYPE_ARP,                  "ARP" },
	{ ETHERTYPE_WLCCP,                "Cisco Wireless Lan Context Control Protocol" },
	{ ETHERTYPE_MINT,                 "Motorola Media Independent Network Transport" },
	{ ETHERTYPE_CENTRINO_PROMISC,     "IEEE 802.11 (Centrino promiscuous)" },
	{ ETHERTYPE_XNS_IDP,              "XNS Internet Datagram Protocol" },
	{ ETHERTYPE_X25L3,                "X.25 Layer 3" },
	{ ETHERTYPE_WOL,                  "Wake on LAN" },
	{ ETHERTYPE_WMX_M2M,              "WiMax Mac-to-Mac" },
	{ ETHERTYPE_EPL_V1,               "EPL_V1" },
	{ ETHERTYPE_REVARP,               "RARP" },
	{ ETHERTYPE_DEC_LB,               "DEC LanBridge" },
	{ ETHERTYPE_ATALK,                "Appletalk" },
	{ ETHERTYPE_SNA,                  "SNA-over-Ethernet" },
	{ ETHERTYPE_DLR,                  "EtherNet/IP Device Level Ring" },
	{ ETHERTYPE_AARP,                 "AARP" },
	{ ETHERTYPE_IPX,                  "Netware IPX/SPX" },
	{ ETHERTYPE_VINES_IP,             "Vines IP" },
	{ ETHERTYPE_VINES_ECHO,           "Vines Echo" },
	{ ETHERTYPE_TRAIN,                "Netmon Train" },
	/* Ethernet Loopback */
	{ ETHERTYPE_LOOP,                 "Loopback" },
	{ ETHERTYPE_FOUNDRY,              "Foundry proprietary" },
	{ ETHERTYPE_WCP,                  "Wellfleet Compression Protocol" },
	{ ETHERTYPE_STP,                  "Spanning Tree Protocol" },
	/* for ISMP, see RFC 2641, RFC 2642, RFC 2643 */
	{ ETHERTYPE_ISMP,                 "Cabletron Interswitch Message Protocol" },
	{ ETHERTYPE_ISMP_TBFLOOD,         "Cabletron SFVLAN 1.8 Tag-Based Flood" },
	/* In www.iana.org/assignments/ethernet-numbers, 8203-8205 description is
	 * Quantum Software.  Now the company is called QNX Software Systems. */
	{ ETHERTYPE_QNX_QNET6,            "QNX 6 QNET protocol" },
	{ ETHERTYPE_PPPOED,               "PPPoE Discovery" },
	{ ETHERTYPE_PPPOES,               "PPPoE Session" },
	{ ETHERTYPE_INTEL_ANS,            "Intel ANS probe" },
	{ ETHERTYPE_MS_NLB_HEARTBEAT,     "MS NLB heartbeat" },
	{ ETHERTYPE_JUMBO_LLC,            "Jumbo LLC" },
	{ ETHERTYPE_HOMEPLUG,             "Homeplug" },
	{ ETHERTYPE_HOMEPLUG_AV,          "Homeplug AV" },
	{ ETHERTYPE_IEEE_802_1AD,         "802.1ad Provider Bridge (Q-in-Q)" },
	{ ETHERTYPE_IEEE_802_1AH,         "802.1ah Provider Backbone Bridge (mac-in-mac)" },
	{ ETHERTYPE_IEEE_802_1BR,         "802.1br Bridge Port Extension E-Tag" },
	{ ETHERTYPE_EAPOL,                "802.1X Authentication" },
	{ ETHERTYPE_RSN_PREAUTH,          "802.11i Pre-Authentication" },
	{ ETHERTYPE_MPLS,                 "MPLS label switched packet" },
	{ ETHERTYPE_MPLS_MULTI,           "MPLS multicast label switched packet" },
	{ ETHERTYPE_3C_NBP_DGRAM,         "3Com NBP Datagram" },
	{ ETHERTYPE_DEC,                  "DEC proto" },
	{ ETHERTYPE_DNA_DL,               "DEC DNA Dump/Load" },
	{ ETHERTYPE_DNA_RC,               "DEC DNA Remote Console" },
	{ ETHERTYPE_DNA_RT,               "DEC DNA Routing" },
	{ ETHERTYPE_LAT,                  "DEC LAT" },
	{ ETHERTYPE_DEC_DIAG,             "DEC Diagnostics" },
	{ ETHERTYPE_DEC_CUST,             "DEC Customer use" },
	{ ETHERTYPE_DEC_SCA,              "DEC LAVC/SCA" },
	{ ETHERTYPE_DEC_LAST,             "DEC LAST" },
	{ ETHERTYPE_ETHBRIDGE,            "Transparent Ethernet bridging" },
	{ ETHERTYPE_CGMP,                 "Cisco Group Management Protocol" },
	{ ETHERTYPE_GIGAMON,              "Gigamon Header" },
	{ ETHERTYPE_MSRP,                 "802.1Qat Multiple Stream Reservation Protocol" },
	{ ETHERTYPE_MMRP,                 "802.1ak Multiple Mac Registration Protocol" },
	{ ETHERTYPE_AVBTP,                "IEEE 1722 Audio Video Bridging Transport Protocol" },
	{ ETHERTYPE_ROHC,                 "Robust Header Compression(RoHC)" },
	{ ETHERTYPE_TRILL,                "TRansparent Interconnection of Lots of Links" },
	{ ETHERTYPE_L2ISIS,               "Intermediate System to Intermediate System" },
	{ ETHERTYPE_MAC_CONTROL,          "MAC Control" },
	{ ETHERTYPE_SLOW_PROTOCOLS,       "Slow Protocols" },
	{ ETHERTYPE_RTMAC,                "Real-Time Media Access Control" },
	{ ETHERTYPE_RTCFG,                "Real-Time Configuration Protocol" },
	{ ETHERTYPE_CDMA2000_A10_UBS,     "CDMA2000 A10 Unstructured byte stream" },
	{ ETHERTYPE_ATMOE,                "ATM over Ethernet" },
	{ ETHERTYPE_PROFINET,             "PROFINET" },
	{ ETHERTYPE_AOE,                  "ATA over Ethernet" },
	{ ETHERTYPE_ECATF,                "EtherCAT frame" },
	{ ETHERTYPE_TELKONET,             "Telkonet powerline" },
	{ ETHERTYPE_EPL_V2,               "ETHERNET Powerlink v2" },
	{ ETHERTYPE_XIMETA,               "XiMeta Technology" },
	{ ETHERTYPE_CSM_ENCAPS,           "CSM_ENCAPS Protocol" },
	{ ETHERTYPE_EXPERIMENTAL_ETH1,    "Local Experimental Ethertype 1" },
	{ ETHERTYPE_EXPERIMENTAL_ETH2,    "Local Experimental Ethertype 2" },
	{ ETHERTYPE_IEEE802_OUI_EXTENDED, "IEEE 802a OUI Extended Ethertype" },
	{ ETHERTYPE_IEC61850_GOOSE,       "IEC 61850/GOOSE" },
	{ ETHERTYPE_IEC61850_GSE,         "IEC 61850/GSE management services" },
	{ ETHERTYPE_IEC61850_SV,          "IEC 61850/SV (Sampled Value Transmission" },
	{ ETHERTYPE_TIPC,                 "Transparent Inter Process Communication" },
	{ ETHERTYPE_LLDP,                 "802.1 Link Layer Discovery Protocol (LLDP)" },
	{ ETHERTYPE_3GPP2,                "CDMA2000 A10 3GPP2 Packet" },
	{ ETHERTYPE_TTE_PCF,              "TTEthernet Protocol Control Frame" },
	{ ETHERTYPE_CESOETH,              "Circuit Emulation Services over Ethernet (MEF8)" },
	{ ETHERTYPE_LLTD,                 "Link Layer Topology Discovery (LLTD)" },
	{ ETHERTYPE_WSMP,                 "(WAVE) Short Message Protocol (WSM)" },
	{ ETHERTYPE_VMLAB,                "VMware Lab Manager" },
	{ ETHERTYPE_COBRANET,             "Cirrus Cobranet Packet" },
	{ ETHERTYPE_NSRP,                 "Juniper Netscreen Redundant Protocol" },
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
	{ PPP_IPCP,                       "PPP IP Control Protocol" },
	{ PPP_LCP,                        "PPP Link Control Protocol" },
	{ PPP_PAP,                        "PPP Password Authentication Protocol" },
	{ PPP_CCP,                        "PPP Compression Control Protocol" },
	{ ETHERTYPE_LLT,                  "Veritas Low Latency Transport (not officially registered)" },
	{ ETHERTYPE_CFM,                  "IEEE 802.1ag Connectivity Fault Management (CFM) protocol" },
	{ ETHERTYPE_DCE,                  "Data Center Ethernet (DCE) protocol(Cisco)" },
	{ ETHERTYPE_FCOE,                 "Fibre Channel over Ethernet" },
	{ ETHERTYPE_IEEE80211_DATA_ENCAP, "IEEE 802.11 data encapsulation" },
	{ ETHERTYPE_LINX,                 "LINX IPC Protocol" },
	{ ETHERTYPE_FIP,                  "FCoE Initialization Protocol" },
	{ ETHERTYPE_MIH,                  "Media Independent Handover Protocol" },
	{ ETHERTYPE_ELMI,                 "Ethernet Local Management Interface (MEF16)" },
	{ ETHERTYPE_PTP,                  "PTPv2 over Ethernet (IEEE1588)" },
	{ ETHERTYPE_NCSI,                 "Network Controller Sideband Interface" },
	{ ETHERTYPE_PRP,                  "Parallel Redundancy Protocol (PRP) and HSR Supervision (IEC62439 Part 3)" },
	{ ETHERTYPE_FLIP,                 "Flow Layer Internal Protocol" },
	{ ETHERTYPE_ROCE,                 "RDMA over Converged Ethernet" },
	{ ETHERTYPE_TDMOE,                "Digium TDM over Ethernet Protocol" },
	{ ETHERTYPE_WAI,                  "WAI Authentication Protocol" },
	{ ETHERTYPE_VNTAG,                "VN-Tag" },
	{ ETHERTYPE_HSR,                  "High-availability Seamless Redundancy (IEC62439 Part 3)" },
	{ ETHERTYPE_BPQ,                  "AX.25" },
	{ ETHERTYPE_CMD,                  "CiscoMetaData" },
	{ ETHERTYPE_XIP,                  "eXpressive Internet Protocol" },
	{ ETHERTYPE_NWP,                  "Neighborhood Watch Protocol" },
	{ ETHERTYPE_BLUECOM,              "bluecom Protocol" },
	{ ETHERTYPE_QINQ_OLD,             "QinQ: old non-standard 802.1ad" },
	{ 0, NULL }
};

static void eth_prompt(packet_info *pinfo, gchar* result)
{
	g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "Ethertype 0x%04x as",
		GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_ethertype, 0)));
}

static gpointer eth_value(packet_info *pinfo)
{
	return p_get_proto_data(pinfo->pool, pinfo, proto_ethertype, 0);
}

static void add_dix_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
			    int trailer_id, tvbuff_t *tvb, tvbuff_t *next_tvb, int offset_after_etype,
			    guint length_before, gint fcs_len);

/*
void
ethertype(guint16 etype, tvbuff_t *tvb, int offset_after_etype,
	  packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree,
	  int etype_id, int trailer_id, int fcs_len)
*/
static int
dissect_ethertype(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
	const char	  *description;
	tvbuff_t	  *volatile next_tvb;
	guint		   length_before;
	gint		   captured_length, reported_length;
	volatile int  dissector_found = 0;
	const char	  *volatile saved_proto;
	ethertype_data_t  *ethertype_data;

	/* Reject the packet if data is NULL */
	if (data == NULL)
		return 0;
	ethertype_data = (ethertype_data_t*)data;

	/* Add the Ethernet type to the protocol tree */
	proto_tree_add_uint(ethertype_data->fh_tree, ethertype_data->etype_id, tvb,
				    ethertype_data->offset_after_ethertype - 2, 2, ethertype_data->etype);

	/* Get the captured length and reported length of the data
	   after the Ethernet type. */
	captured_length = tvb_captured_length_remaining(tvb, ethertype_data->offset_after_ethertype);
	reported_length = tvb_reported_length_remaining(tvb,
							ethertype_data->offset_after_ethertype);

	/* Remember how much data there is after the Ethernet type,
	   including any trailer and FCS. */
	length_before = reported_length;

	/* Construct a tvbuff for the payload after the Ethernet type.
	   If the FCS length is positive, remove the FCS.
	   (If it's zero, there's no FCS; if it's negative,
	   we don't know whether there's an FCS, so we'll
	   guess based on the length of the trailer.) */
	if (ethertype_data->fcs_len > 0) {
		if (captured_length >= 0 && reported_length >= 0) {
			if (reported_length >= ethertype_data->fcs_len)
				reported_length -= ethertype_data->fcs_len;
			if (captured_length > reported_length)
				captured_length = reported_length;
		}
	}
	next_tvb = tvb_new_subset(tvb, ethertype_data->offset_after_ethertype, captured_length,
				  reported_length);

	p_add_proto_data(pinfo->pool, pinfo, proto_ethertype, 0, GUINT_TO_POINTER((guint)ethertype_data->etype));

	/* Look for sub-dissector, and call it if found.
	   Catch exceptions, so that if the reported length of "next_tvb"
	   was reduced by some dissector before an exception was thrown,
	   we can still put in an item for the trailer. */
	saved_proto = pinfo->current_proto;
	TRY {
		dissector_found = dissector_try_uint(ethertype_dissector_table,
						     ethertype_data->etype, next_tvb, pinfo, tree);
	}
	CATCH_NONFATAL_ERRORS {
		/* Somebody threw an exception that means that there
		   was a problem dissecting the payload; that means
		   that a dissector was found, so we don't need to
		   dissect the payload as data or update the protocol
		   or info columns.

		   Just show the exception and then drive on to show
		   the trailer, after noting that a dissector was found
		   and restoring the protocol value that was in effect
		   before we called the subdissector. */
		show_exception(next_tvb, pinfo, tree, EXCEPT_CODE, GET_MESSAGE);

		dissector_found = 1;
		pinfo->current_proto = saved_proto;
	}
	ENDTRY;

	if (!dissector_found) {
		/* No sub-dissector found.
		   Label rest of packet as "Data" */
		call_data_dissector(next_tvb, pinfo, tree);

		/* Label protocol */
		col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "0x%04x", ethertype_data->etype);

		description = try_val_to_str(ethertype_data->etype, etype_vals);
		if (description) {
			col_add_str(pinfo->cinfo, COL_INFO, description);
		}
	}

	add_dix_trailer(pinfo, tree, ethertype_data->fh_tree, ethertype_data->trailer_id, tvb, next_tvb, ethertype_data->offset_after_ethertype,
			length_before, ethertype_data->fcs_len);

	return tvb_captured_length(tvb);
}

static void
add_dix_trailer(packet_info *pinfo, proto_tree *tree, proto_tree *fh_tree, int trailer_id,
		tvbuff_t *tvb, tvbuff_t *next_tvb, int offset_after_etype,
		guint length_before, gint fcs_len)
{
	guint		 length;
	tvbuff_t	*trailer_tvb;

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
	/* Decode As handling */
	static build_valid_func eth_da_build_value[1] = {eth_value};
	static decode_as_value_t eth_da_values = {eth_prompt, 1, eth_da_build_value};
	static decode_as_t ethertype_da = {"ethertype", "Link", "ethertype", 1, 0, &eth_da_values, NULL, NULL,
										decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};


	proto_ethertype = proto_register_protocol("Ethertype", "Ethertype", "ethertype");
	/* This isn't a real protocol, so you can't disable its dissection. */
	proto_set_cant_toggle(proto_ethertype);

	register_dissector("ethertype", dissect_ethertype, proto_ethertype);

	/* subdissector code */
	ethertype_dissector_table = register_dissector_table("ethertype",
								"Ethertype", proto_ethertype, FT_UINT16, BASE_HEX);
	register_capture_dissector_table("ethertype", "Ethertype");

	register_decode_as(&ethertype_da);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
