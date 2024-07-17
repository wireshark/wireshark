/* packet-mint.c
 * Routines for the disassembly of the Media Independent Network Transport
 * protocol used between wireless controllers and APs
 *
 * Copyright 2013 Joerg Mayer (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Extremenetworks/Zebra/Motorola/Symbol WLAN proprietary protocol
 * http://www.awimobility.com/s.nl/ctype.KB/it.I/id.7761/KB.81/.f
 * and
 * http://www.michaelfmcnamara.com/files/motorola/WiNG_5X_How_To_NOC.pdf
 * looks like a mixture of lwapp/capwap and is-is/ospf
 *
 * MLCP: MINT Link Creation Protocol
 */

/* We don't want the tranported data to pollute the output until
 * we know how to correctly determine the packet type and length
 */
#define MINT_DEVELOPMENT 1

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/etypes.h>
#include <epan/show_exception.h>

void proto_register_mint(void);
void proto_reg_handoff_mint(void);

#define PROTO_SHORT_NAME "MINT"
#define PROTO_LONG_NAME "Media Independent Network Transport"

/* 0x8783 ETHERTYPE_MINT */
/* Destmac: 01-a0-f8-00-00-00: Hello packets in multicast mode */
/* Mint overhead: 86 bytes */
/* 24576 = 0x6000 */
#define PORT_MINT_CONTROL_TUNNEL	24576
/* 24577 = 0x6001 */
#define PORT_MINT_DATA_TUNNEL		24577
#define PORT_MINT_RANGE			"24576-24577"
/* MLCP: VLAN or IP-based */

static dissector_handle_t eth_handle;

static int proto_mint;

static int hf_mint_control;
static int hf_mint_control_32zerobytes;
static int hf_mint_control_unknown1;
static int hf_mint_data;
static int hf_mint_data_seqno;
static int hf_mint_data_unknown1;
static int hf_mint_data_vlan;
static int hf_mint_ethshim;
static int hf_mint_ethshim_length;
static int hf_mint_ethshim_unknown;
static int hf_mint_header;
static int hf_mint_header_dstdataport;
static int hf_mint_header_dstid;
static int hf_mint_header_srcdataport;
static int hf_mint_header_srcid;
static int hf_mint_header_ttl;
static int hf_mint_header_unknown1;
static int hf_mint_header_unknown2;
static int hf_mint_mlcp_length;
static int hf_mint_mlcp_message;
static int hf_mint_mlcp_type;
static int hf_mint_mlcp_value;
static int hf_mint_neighbor_unknown;
static int hf_mint_router_array;
static int hf_mint_router_element;
static int hf_mint_router_header_length;
static int hf_mint_router_header_sender;
static int hf_mint_router_header_unknown;
static int hf_mint_router_length;
static int hf_mint_router_message_type;
static int hf_mint_router_type_csnp;
static int hf_mint_router_type_helo;
static int hf_mint_router_type_lsp;
static int hf_mint_router_type_psnp;
static int hf_mint_router_type_unknown;
static int hf_mint_router_unknown1;
static int hf_mint_router_unknown2;
static int hf_mint_router_unknown3;
static int hf_mint_router_value;

/* ett handles */
static int ett_mint_ethshim;
static int ett_mint;
static int ett_mint_header;
static int ett_mint_ctrl;
static int ett_mint_data;

static dissector_handle_t mint_control_handle;
static dissector_handle_t mint_data_handle;
static dissector_handle_t mint_eth_handle;

/* Output of "service show mint ports" on controller */

typedef enum {
	MINT_PORT_0			=   0,
	MINT_PORT_DATA			=   1,
	MINT_PORT_DATA_FLOOD		=   2,
	MINT_PORT_FDB_UPDATE		=   3,
	MINT_PORT_MDD			=   8,
	MINT_PORT_RIM			=   9,
	MINT_PORT_SMARTRF		=  10,
	MINT_PORT_CONFIG		=  11,
	MINT_PORT_ROUTER		=  12,
	MINT_PORT_REDUNDANCY		=  13,
	MINT_PORT_HOTSPOT		=  14,
	MINT_PORT_PING			=  15,
	MINT_PORT_STATS			=  16,
	MINT_PORT_JOIN			=  18,
	MINT_PORT_FILEXFR		=  19,
	MINT_PORT_SECURITY		=  20,
	MINT_PORT_BOOTSTRAP		=  21,
	MINT_PORT_XPATH			=  22,
	MINT_PORT_MCAST_RP		=  23,
	MINT_PORT_MCAST_CTRL		=  24,
	MINT_PORT_MCAST_DATA		=  25,
	MINT_PORT_RADPROXY		=  26,
	MINT_PORT_CLUSTER		=  27,
	MINT_PORT_MIGRATION		=  28,
	MINT_PORT_CLUSTER_SYNC		=  29,
	MINT_PORT_NEIGHBOR		=  30,
	MINT_PORT_GKEY			=  31,
	MINT_PORT_MARP			=  32,
	MINT_PORT_MPROXY		=  33,
	MINT_PORT_MLCP			=  34,
	MINT_PORT_TELNET		=  35,
	MINT_PORT_RDBG_REQ		=  36,
	MINT_PORT_RDBG_SRV0		=  37,
	MINT_PORT_RDBG_SRV1		=  38,
	MINT_PORT_RDBG_SRV2		=  39,
	MINT_PORT_RDBG_SRV3		=  40,
	MINT_PORT_RDBG_SRV4		=  41,
	MINT_PORT_RDBG_SRV5		=  42,
	MINT_PORT_RDBG_SRV6		=  43,
	MINT_PORT_RDBG_SRV7		=  44,
	MINT_PORT_TRACEROUTE		=  45,
	MINT_PORT_STATS_LISTEN		=  46,
	MINT_PORT_NOC_CONTROLLER	=  47,
	MINT_PORT_NOC_CLIENT		=  48,
	MINT_PORT_STATS_SERVER		=  49,
	MINT_PORT_EXTVLAN		=  50,
	MINT_PORT_RAD_DYNAMIC		=  51,
	MINT_PORT_RFD_CLIENT		=  52,
	MINT_PORT_RFD_SERVER		=  53,
	MINT_PORT_NOC_SERVER		=  54,
	MINT_PORT_NOC__CLIENT		=  55,
	MINT_PORT_CP_STATS_CLIENT	=  56,
	MINT_PORT_NX_URLINFO_SRVR	=  57,
	MINT_PORT_NX_URLINFO_PRXY	=  58,
	MINT_PORT_LDAP_PROXY		=  59,
	MINT_PORT_ANALYTICS		=  60,
	MINT_PORT_ADOPTION		=  61,
	MINT_PORT_CLUSTER_ADOPT		=  62,
	MINT_PORT_NOC_SITE		=  63,
	MINT_PORT_DAD			=  64,
	MINT_PORT_CCACHE		=  65,
	MINT_PORT_GLB_ASSOC_LIST	=  66,
	MINT_PORT_BONJOUR		= 131,
	MINT_PORT_DPD2_EXTIF		= 132,
	MINT_PORT_TROUBLE		= 133,
	MINT_PORT_URLF_CLASSIFIER	= 134,
	MINT_PORT_NF_PROXY		= 135,
	MINT_PORT_WING_EXPRESS		= 136,
	MINT_PORT_NSM_STAT_CLIENT	= 138,
	MINT_PORT_DPD2_STATS_CLIENT	= 140,
	MINT_PORT_BTIM_STATS_CLIENT	= 142
} mint_packettype_t;

static const value_string mint_port_vals[] = {
	{ MINT_PORT_0,			"0 port" },
	{ MINT_PORT_DATA,		"data/dgram" },
	{ MINT_PORT_DATA_FLOOD,		"data-flood/dgram" },
	{ MINT_PORT_FDB_UPDATE,		"fdb-update/dgram" },
	{ MINT_PORT_MDD,		"mdd/dgram" },
	{ MINT_PORT_RIM,		"rim/dgram" },
	{ MINT_PORT_SMARTRF,		"smartrf/seqpkt" },
	{ MINT_PORT_CONFIG,		"config/stream" },
	{ MINT_PORT_ROUTER,		"router/dgram" },
	{ MINT_PORT_REDUNDANCY,		"redundancy/seqpkt" },
	{ MINT_PORT_HOTSPOT,		"hotspot/seqpkt" },
	{ MINT_PORT_PING,		"ping/dgram" },
	{ MINT_PORT_STATS,		"stats/dgram" },
	{ MINT_PORT_JOIN,		"join/seqpkt" },
	{ MINT_PORT_FILEXFR,		"filexfr/stream" },
	{ MINT_PORT_SECURITY,		"security/seqpkt" },
	{ MINT_PORT_BOOTSTRAP,		"bootstrap/seqpkt" },
	{ MINT_PORT_XPATH,		"xpath/stream" },
	{ MINT_PORT_MCAST_RP,		"mcast-rp/dgram" },
	{ MINT_PORT_MCAST_CTRL,		"mcast-ctrl/seqpkt" },
	{ MINT_PORT_MCAST_DATA,		"mcast-data/seqpkt" },
	{ MINT_PORT_RADPROXY,		"radproxy/dgram" },
	{ MINT_PORT_CLUSTER,		"cluster/seqpkt" },
	{ MINT_PORT_MIGRATION,		"migration/stream" },
	{ MINT_PORT_CLUSTER_SYNC,	"cluster-sync/stream" },
	{ MINT_PORT_NEIGHBOR,		"neighbor/seqpkt" },
	{ MINT_PORT_GKEY,		"gkey/dgram" },
	{ MINT_PORT_MARP,		"marp/dgram" },
	{ MINT_PORT_MPROXY,		"mproxy/seqpkt" },
	{ MINT_PORT_MLCP,		"mlcp/dgram" },
	{ MINT_PORT_TELNET,		"telnet/stream" },
	{ MINT_PORT_RDBG_REQ,		"rdbg-req/seqpkt" },
	{ MINT_PORT_RDBG_SRV0,		"rdbg-srv0/seqpkt" },
	{ MINT_PORT_RDBG_SRV1,		"rdbg-srv1/seqpkt" },
	{ MINT_PORT_RDBG_SRV2,		"rdbg-srv2/seqpkt" },
	{ MINT_PORT_RDBG_SRV3,		"rdbg-srv3/seqpkt" },
	{ MINT_PORT_RDBG_SRV4,		"rdbg-srv4/seqpkt" },
	{ MINT_PORT_RDBG_SRV5,		"rdbg-srv5/seqpkt" },
	{ MINT_PORT_RDBG_SRV6,		"rdbg-srv6/seqpkt" },
	{ MINT_PORT_RDBG_SRV7,		"rdbg-srv7/seqpkt" },
	{ MINT_PORT_TRACEROUTE,		"traceroute/seqpkt" },
	{ MINT_PORT_STATS_LISTEN,	"stats-listen/seqpkt" },
	{ MINT_PORT_NOC_CONTROLLER,	"noc-controller/seqpkt" },
	{ MINT_PORT_NOC_CLIENT,		"noc-client/seqpkt" },
	{ MINT_PORT_STATS_SERVER,	"stats-server/seqpkt" },
	{ MINT_PORT_EXTVLAN,		"extvlan/dgram" },
	{ MINT_PORT_RAD_DYNAMIC,	"rad-dynamic/seqpkt" },
	{ MINT_PORT_RFD_CLIENT,		"rfd_client/stream" },
	{ MINT_PORT_RFD_SERVER,		"rfd_server/stream" },
	{ MINT_PORT_NOC_SERVER,		"noc_server/stream" },
	{ MINT_PORT_NOC__CLIENT,	"noc_client/stream" },
	{ MINT_PORT_CP_STATS_CLIENT,	"cp_stats_client/stream" },
	{ MINT_PORT_NX_URLINFO_SRVR,	"nx_urlinfo_srvr/dgram" },
	{ MINT_PORT_NX_URLINFO_PRXY,	"nx_urlinfo_prxy/dgram" },
	{ MINT_PORT_LDAP_PROXY,		"ldap_proxy/stream" },
	{ MINT_PORT_ANALYTICS,		"analytics/dgram" },
	{ MINT_PORT_ADOPTION,		"adoption/seqpkt" },
	{ MINT_PORT_CLUSTER_ADOPT,	"cluster-adopt/seqpkt" },
	{ MINT_PORT_NOC_SITE,		"noc-site/stream" },
	{ MINT_PORT_DAD,		"dad/stream" },
	{ MINT_PORT_CCACHE,		"ccache/dgram" },
	{ MINT_PORT_GLB_ASSOC_LIST,	"glb_assoc_list/dgram" },
	{ MINT_PORT_BONJOUR,		"bonjour/dgram" },
	{ MINT_PORT_DPD2_EXTIF,		"dpd2-extif/dgram" },
	{ MINT_PORT_TROUBLE,		"trouble/dgram" },
	{ MINT_PORT_URLF_CLASSIFIER,	"urlf_classifier/dgram" },
	{ MINT_PORT_NF_PROXY,		"nf-proxy/dgram" },
	{ MINT_PORT_WING_EXPRESS,	"wing_express/dgram" },
	{ MINT_PORT_NSM_STAT_CLIENT,	"nsm-stat-client/stream" },
	{ MINT_PORT_DPD2_STATS_CLIENT,	"dpd2-stats-client/stream" },
	{ MINT_PORT_BTIM_STATS_CLIENT,	"btim-stats-client/stream" },

	{ 0,    NULL }
};

static const value_string mint_router_csnp_tlv_vals[] = {

	{ 0,    NULL }
};

static const value_string mint_router_helo_tlv_vals[] = {
	{ 1,	"MINT ID" },
	{ 8,	"IPv4 address" },

	{ 0,    NULL }
};

static const value_string mint_router_lsp_tlv_vals[] = {
	{ 8,	"MINT ID" },

	{ 0,    NULL }
};

static const value_string mint_router_psnp_tlv_vals[] = {

	{ 0,    NULL }
};

static const value_string mint_0x22_tlv_vals[] = {

	{ 0,    NULL }
};

static int
dissect_eth_frame(tvbuff_t *tvb, packet_info *pinfo, proto_tree *mint_tree,
	volatile uint32_t offset, uint32_t length)
{
	tvbuff_t *eth_tvb;

#ifdef MINT_DEVELOPMENT
	col_set_writable(pinfo->cinfo, -1, false);
#endif

	eth_tvb = tvb_new_subset_length(tvb, offset, length);
	/* Continue after Ethernet dissection errors */
	TRY {
		call_dissector(eth_handle, eth_tvb, pinfo, mint_tree);
	} CATCH_NONFATAL_ERRORS {
		show_exception(eth_tvb, pinfo, mint_tree, EXCEPT_CODE, GET_MESSAGE);
	} ENDTRY;
	offset += length;

#ifdef MINT_DEVELOPMENT
	col_set_writable(pinfo->cinfo, -1, true);
#endif
	return offset;
}

static int
dissect_mint_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
	uint32_t offset, uint32_t packet_length, unsigned received_via)
{
	proto_item *ti;
	proto_tree *mint_tree = NULL;
	proto_tree *mint_header_tree = NULL;
	proto_tree *mint_data_tree = NULL;
	proto_tree *mint_ctrl_tree = NULL;
	uint16_t bytes_remaining;
	uint16_t mint_port;
	uint8_t type, length, header_length;
	uint32_t message_type;
	uint8_t element_length;
	int hf_tlv_vals;

	mint_port = tvb_get_ntohs(tvb, offset + 12);

	col_set_str(pinfo->cinfo, COL_PROTOCOL, PROTO_SHORT_NAME);
	col_add_str(pinfo->cinfo, COL_INFO, val_to_str(mint_port,
		mint_port_vals, "Type %03d"));

	ti = proto_tree_add_item(tree, proto_mint, tvb,
		offset, packet_length, ENC_NA);
	mint_tree = proto_item_add_subtree(ti, ett_mint);

	ti = proto_tree_add_item(mint_tree, hf_mint_header, tvb,
		offset, 16, ENC_NA);
	mint_header_tree = proto_item_add_subtree(ti, ett_mint_header);

	/* MINT header */
	proto_tree_add_item(mint_header_tree, hf_mint_header_unknown1, tvb,
		offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(mint_header_tree, hf_mint_header_ttl, tvb,
		offset, 1, ENC_NA);
	offset += 1;
	proto_tree_add_item(mint_header_tree, hf_mint_header_unknown2, tvb,
		offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(mint_header_tree, hf_mint_header_dstid, tvb,
		offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(mint_header_tree, hf_mint_header_srcid, tvb,
		offset, 4, ENC_NA);
	offset += 4;
	proto_tree_add_item(mint_header_tree, hf_mint_header_dstdataport, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	proto_tree_add_item(mint_header_tree, hf_mint_header_srcdataport, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	offset += 2;
	/* FIXME: This is probably not the right way to determine the packet type.
	 *	  It's more likely something in mint_header_unknown1 but I haven't
	 *        found out what. */
	switch(mint_port) {
	case MINT_PORT_DATA:
		ti = proto_tree_add_item(mint_tree, hf_mint_data, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_data_tree = proto_item_add_subtree(ti, ett_mint_data);
		proto_tree_add_item(mint_data_tree, hf_mint_data_unknown1, tvb,
			offset, 2, ENC_NA);
		offset += 2;
		/* Transported user frame */
		if (offset < packet_length)
			offset += dissect_eth_frame(tvb, pinfo, tree,
				offset, packet_length - offset);
		break;
	case MINT_PORT_DATA_FLOOD:
		ti = proto_tree_add_item(mint_tree, hf_mint_data, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_data_tree = proto_item_add_subtree(ti, ett_mint_data);
		/* Decode as vlan only for now. To be verified against a capture
		 * with CoS != 0 */
		proto_tree_add_item(mint_data_tree, hf_mint_data_vlan, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		proto_tree_add_item(mint_data_tree, hf_mint_data_seqno, tvb,
			offset, 4, ENC_NA);
		offset += 4;
		proto_tree_add_item(mint_data_tree, hf_mint_data_unknown1, tvb,
			offset, 4, ENC_NA);
		offset += 4;
		/* Transported user frame */
		if (offset < packet_length)
			offset += dissect_eth_frame(tvb, pinfo, tree,
				offset, packet_length - offset);
		break;
	case MINT_PORT_ROUTER:
		ti = proto_tree_add_item(mint_tree, hf_mint_control, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_ctrl_tree = proto_item_add_subtree(ti, ett_mint_ctrl);
		proto_tree_add_item(mint_ctrl_tree, hf_mint_control_32zerobytes, tvb,
			offset, 32, ENC_NA);
		offset += 32;

		proto_tree_add_item(mint_ctrl_tree, hf_mint_router_unknown1, tvb,
			offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(mint_ctrl_tree, hf_mint_router_unknown2, tvb,
			offset, 1, ENC_NA);
		offset += 1;
		proto_tree_add_item(mint_ctrl_tree, hf_mint_router_unknown3, tvb,
			offset, 1, ENC_NA);
		offset += 1;
		header_length = tvb_get_uint8(tvb, offset);
		proto_tree_add_item(mint_ctrl_tree, hf_mint_router_header_length, tvb,
			offset, 1, ENC_NA);
		offset += 1;
		message_type = tvb_get_ntohl(tvb, offset);
		proto_tree_add_item(mint_ctrl_tree, hf_mint_router_message_type, tvb,
			offset, 4, ENC_ASCII);
		offset += 4;
		proto_tree_add_item(mint_ctrl_tree, hf_mint_router_header_sender, tvb,
			offset, 4, ENC_NA);
		offset += 4;
		switch (message_type) {
			case 0x43534E50: /* CSNP */
				element_length = 12;
				hf_tlv_vals = hf_mint_router_type_csnp;
				break;
			case 0x48454C4F: /* HELO */
				element_length = 0;
				hf_tlv_vals = hf_mint_router_type_helo;
				break;
			case 0x4C535000: /* LSP */
				element_length = 8;
				hf_tlv_vals = hf_mint_router_type_lsp;
				break;
			case 0x50534E50: /* PSNP */
				element_length = 4;
				hf_tlv_vals = hf_mint_router_type_psnp;
				break;
			default:
				element_length = 0;
				hf_tlv_vals = hf_mint_router_type_unknown;
		}
		/* FIXME: This should go into the per message_type switch above */
		if (header_length > 12) {
			proto_tree_add_item(mint_ctrl_tree, hf_mint_router_header_unknown, tvb,
				offset, header_length - 12, ENC_NA);
			offset += header_length - 12;
		}
		while (offset < packet_length - 2) {
			type = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(mint_ctrl_tree, hf_tlv_vals, tvb,
				offset, 1, ENC_NA);
			offset += 1;
			length = tvb_get_uint8(tvb, offset);
			/* FIXME: This is a hack - reliable array detection missing */
			if (type == 1 && length == 128) {
				proto_tree_add_item(mint_ctrl_tree, hf_mint_router_array, tvb,
					offset, 1, ENC_NA);
				offset += 1;
				length = tvb_get_uint8(tvb, offset);
			}
			proto_tree_add_item(mint_ctrl_tree, hf_mint_router_length, tvb,
				offset, 1, ENC_NA);
			offset += 1;
			if (offset + length > packet_length) {
				/* FIXME: print expert information */
				break;
			}
			if (type == 1 && element_length) {
				uint32_t end_offset = offset + length;
				for (; offset < end_offset; offset += element_length) {
					proto_tree_add_item(mint_ctrl_tree, hf_mint_router_element, tvb,
						offset, element_length, ENC_NA);
				}
			} else {
				proto_tree_add_item(mint_ctrl_tree, hf_mint_router_value, tvb,
					offset, length, ENC_NA);
				offset += length;
			}
		}
		break;
	case MINT_PORT_NEIGHBOR:
		ti = proto_tree_add_item(mint_tree, hf_mint_control, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_ctrl_tree = proto_item_add_subtree(ti, ett_mint_ctrl);
		proto_tree_add_item(mint_ctrl_tree, hf_mint_control_32zerobytes, tvb,
			offset, 32, ENC_NA);
		offset += 32;
		bytes_remaining = packet_length - offset;
		proto_tree_add_item(mint_ctrl_tree, hf_mint_neighbor_unknown, tvb,
			offset, bytes_remaining, ENC_NA);
		offset += bytes_remaining;
		break;
	case MINT_PORT_MLCP:
		ti = proto_tree_add_item(mint_tree, hf_mint_control, tvb,
			offset, packet_length - 16, ENC_NA);
		mint_ctrl_tree = proto_item_add_subtree(ti, ett_mint_ctrl);
		proto_tree_add_item(mint_ctrl_tree, hf_mint_control_32zerobytes, tvb,
			offset, 32, ENC_NA);
		offset += 32;
		proto_tree_add_item(mint_ctrl_tree, hf_mint_mlcp_message, tvb,
			offset, 2, ENC_BIG_ENDIAN);
		offset += 2;
		while (offset < packet_length - 2) {
			proto_tree_add_item(mint_ctrl_tree, hf_mint_mlcp_type, tvb,
				offset, 1, ENC_NA);
			offset += 1;
			length = tvb_get_uint8(tvb, offset);
			proto_tree_add_item(mint_ctrl_tree, hf_mint_mlcp_length, tvb,
				offset, 1, ENC_NA);
			offset += 1;
			if (offset + length > packet_length) {
				/* print expert information */
				break;
			}
			proto_tree_add_item(mint_ctrl_tree, hf_mint_mlcp_value, tvb,
				offset, length, ENC_NA);
			offset += length;
		}
		break;
	default:
		bytes_remaining = packet_length - offset;
		switch(received_via) {
		case PORT_MINT_CONTROL_TUNNEL:
		case ETHERTYPE_MINT:
			proto_tree_add_item(mint_tree, hf_mint_control_unknown1, tvb,
				offset, bytes_remaining, ENC_NA);
			break;
		case PORT_MINT_DATA_TUNNEL:
			proto_tree_add_item(mint_tree, hf_mint_data_unknown1, tvb,
				offset, bytes_remaining, ENC_NA);
			break;
		default:
			DISSECTOR_ASSERT_NOT_REACHED();
		}
		offset += bytes_remaining;
		break;
	}
#if defined MINT_DEVELOPMENT
	tree_expanded_set(ett_mint, true);
	tree_expanded_set(ett_mint_ethshim, true);
	tree_expanded_set(ett_mint_header, true);
	tree_expanded_set(ett_mint_ctrl, true);
	tree_expanded_set(ett_mint_data, true);
#endif
	return offset;
}

static int
dissect_mint_control(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t packet_length = tvb_captured_length(tvb);

	return dissect_mint_common(tvb, pinfo, tree, 0, packet_length,
		PORT_MINT_CONTROL_TUNNEL);
}

static int
dissect_mint_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	uint32_t packet_length = tvb_captured_length(tvb);

	return dissect_mint_common(tvb, pinfo, tree, 0, packet_length,
		PORT_MINT_DATA_TUNNEL);
}

static int
dissect_mint_ethshim(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *mint_ethshim_tree = NULL;
	uint32_t offset = 0;
	uint32_t packet_length;

	ti = proto_tree_add_item(tree, hf_mint_ethshim, tvb,
		offset, 4, ENC_NA);
	mint_ethshim_tree = proto_item_add_subtree(ti, ett_mint_ethshim);

	proto_tree_add_item(mint_ethshim_tree, hf_mint_ethshim_unknown, tvb,
		offset, 2, ENC_NA);
	offset += 2;
	proto_tree_add_item(mint_ethshim_tree, hf_mint_ethshim_length, tvb,
		offset, 2, ENC_BIG_ENDIAN);
	packet_length = tvb_get_ntohs(tvb, offset) + 4;
	offset += 2;

	offset += dissect_mint_common(tvb, pinfo, tree, 4, packet_length, ETHERTYPE_MINT);

	return offset;
}

static bool
test_mint_control(tvbuff_t *tvb _U_)
{
#if 0
	/* Minimum of 8 bytes, first byte (version) has value of 3 */
	if ( tvb_length(tvb) < 8
		    || tvb_get_uint8(tvb, 0) != 3
		    /* || tvb_get_uint8(tvb, 2) != 0
		    || tvb_get_ntohs(tvb, 6) > tvb_reported_length(tvb) */
	) {
		return false;
	}
#endif
	return true;
}

static bool
test_mint_data(tvbuff_t *tvb _U_)
{
#if 0
	/* Minimum of 8 bytes, first byte (version) has value of 3 */
	if ( tvb_length(tvb) < 8
		    || tvb_get_uint8(tvb, 0) != 3
		    /* || tvb_get_uint8(tvb, 2) != 0
		    || tvb_get_ntohs(tvb, 6) > tvb_reported_length(tvb) */
	) {
		return false;
	}
#endif
	return true;
}

static bool
test_mint_eth(tvbuff_t *tvb _U_)
{
#if 0
	/* Minimum of 8 bytes, first byte (version) has value of 3 */
	if ( tvb_length(tvb) < 8
		    || tvb_get_uint8(tvb, 0) != 3
		    /* || tvb_get_uint8(tvb, 2) != 0
		    || tvb_get_ntohs(tvb, 6) > tvb_reported_length(tvb) */
	) {
		return false;
	}
#endif
	return true;
}

static int
dissect_mint_control_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if ( !test_mint_control(tvb) ) {
		return 0;
	}
	return dissect_mint_control(tvb, pinfo, tree);
}

static int
dissect_mint_data_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if ( !test_mint_data(tvb) ) {
		return 0;
	}
	return dissect_mint_data(tvb, pinfo, tree);
}

static int
dissect_mint_ethshim_static(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
	if ( !test_mint_eth(tvb) ) {
		return 0;
	}
	return dissect_mint_ethshim(tvb, pinfo, tree);
}

void
proto_register_mint(void)
{
	static hf_register_info hf[] = {
		{ &hf_mint_ethshim,
			{ "MINT Ethernet Shim", "mint.ethshim",
			  FT_PROTOCOL, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_ethshim_unknown,
			{ "Unknown", "mint.ethshim.unknown",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_ethshim_length,
			{ "Length", "mint.ethshim.length",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_header,
			{ "Header", "mint.header",
			  FT_PROTOCOL, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_header_unknown1,
			{ "HdrUnk1", "mint.header.unknown1",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_header_ttl,
			{ "TTL", "mint.header.ttl",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_header_unknown2,
			{ "HdrUnk2", "mint.header.unknown2",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_header_srcid,
			{ "Src MINT ID", "mint.header.srcid",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_header_dstid,
			{ "Dst MINT ID", "mint.header.dstid",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_header_srcdataport,
			{ "Src port", "mint.header.srcport",
			  FT_UINT16, BASE_DEC, VALS(mint_port_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_header_dstdataport,
			{ "Dst port", "mint.header.dstport",
			  FT_UINT16, BASE_DEC, VALS(mint_port_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_data,
			{ "Data Frame", "mint.data",
			  FT_PROTOCOL, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_data_vlan,
			{ "Data VLAN", "mint.data.vlan",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_data_seqno,
			{ "Sequence Number", "mint.data.seqno",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_data_unknown1,
			{ "DataUnk1", "mint.data.unknown1",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_control,
			{ "Control Frame", "mint.control",
			  FT_PROTOCOL, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_control_32zerobytes,
			{ "Zero Bytes", "mint.control.32zerobytes",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_control_unknown1,
			{ "CtrlUnk1", "mint.control.unknown1",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_unknown1,
			{ "Unknown1", "mint.control.router.unknown1",
			  FT_UINT8, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_unknown2,
			{ "Unknown2", "mint.control.router.unknown2",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_unknown3,
			{ "Unknown3", "mint.control.router.unknown3",
			  FT_UINT8, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_header_length,
			{ "Headerlength", "mint.control.router.header.length",
			  FT_UINT8, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_message_type,
			{ "Message type", "mint.control.router.message.type",
			  FT_STRING, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_header_sender,
			{ "Sender ID", "mint.control.router.header.sender",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_header_unknown,
			{ "Header unknown", "mint.control.router.header.unknown",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_type_unknown,
			{ "TLV Type", "mint.control.router.tlvtype",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_type_csnp,
			{ "TLV Type", "mint.control.router.tlvtype",
			  FT_UINT8, BASE_DEC, VALS(mint_router_csnp_tlv_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_type_helo,
			{ "TLV Type", "mint.control.router.tlvtype",
			  FT_UINT8, BASE_DEC, VALS(mint_router_helo_tlv_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_type_lsp,
			{ "TLV Type", "mint.control.router.tlvtype",
			  FT_UINT8, BASE_DEC, VALS(mint_router_lsp_tlv_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_type_psnp,
			{ "TLV Type", "mint.control.router.tlvtype",
			  FT_UINT8, BASE_DEC, VALS(mint_router_psnp_tlv_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_length,
			{ "TLV Length", "mint.control.router.tlvlength",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_array,
			{ "Array indicator", "mint.control.router.array",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_element,
			{ "Array element", "mint.control.router.element",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_router_value,
			{ "TLV Value", "mint.control.router.tlvvalue",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_neighbor_unknown,
			{ "Unknown", "mint.control.neighbor.unknown",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_mlcp_message,
			{ "Message", "mint.control.mlcp.message",
			  FT_UINT16, BASE_HEX, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_mlcp_type,
			{ "TLV Type", "mint.control.mlcp.tlvtype",
			  FT_UINT8, BASE_DEC, VALS(mint_0x22_tlv_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_mlcp_length,
			{ "TLV Length", "mint.control.mlcp.tlvlength",
			  FT_UINT8, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_mint_mlcp_value,
			{ "TLV Value", "mint.control.mlcp.tlvvalue",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
	};

	static int *ett[] = {
		&ett_mint_ethshim,
		&ett_mint,
		&ett_mint_header,
		&ett_mint_ctrl,
		&ett_mint_data,
	};

	proto_mint = proto_register_protocol(PROTO_LONG_NAME, PROTO_SHORT_NAME, "mint");
	/* Created to remove Decode As confusion */
	int proto_mint_data = proto_register_protocol_in_name_only("Media Independent Network Transport Data", "MINT (Data)", "mint_data", proto_mint, FT_PROTOCOL);

	proto_register_field_array(proto_mint, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	mint_control_handle = register_dissector("mint_control", dissect_mint_control_static, proto_mint);
	mint_data_handle = register_dissector("mint_data", dissect_mint_data_static, proto_mint_data);
	mint_eth_handle = register_dissector("mint_eth", dissect_mint_ethshim_static, proto_mint);
}

void
proto_reg_handoff_mint(void)
{
	dissector_add_uint_range_with_preference("udp.port", PORT_MINT_RANGE, mint_control_handle);
	dissector_add_uint("ethertype", ETHERTYPE_MINT, mint_eth_handle);

	eth_handle = find_dissector_add_dependency("eth_withoutfcs", proto_mint);
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
