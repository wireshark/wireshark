/* packet-sll.c
 * Routines for disassembly of packets from Linux "cooked mode" captures
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
#include <epan/conversation_table.h>
#include <epan/arptypes.h>
#include <wsutil/pint.h>
#include "packet-sll.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "packet-eth.h"
#include "packet-ppp.h"
#include "packet-gre.h"
#include "packet-arp.h"
#include <epan/addr_resolv.h>
#include <epan/etypes.h>
#include <epan/arptypes.h>
#include <epan/decode_as.h>
#include <epan/proto_data.h>

void proto_register_sll(void);
void proto_reg_handoff_sll(void);

typedef struct sll_tap_data {
	address src_address;
} sll_tap_data;

/*
 * A LINKTYPE_LINUX_SLL fake link-layer header.
 */
#define SLL_HEADER_SIZE		16	/* total header length */

/*
 * A LINKTYPE_LINUX_SLL fake link-layer header.
 */
#define SLL2_HEADER_SIZE	20	/* total header length */

#define SLL_ADDRLEN		8	/* length of address field */

/*
 * The LINUX_SLL_ values for "sll_pkttype".
 */
#define LINUX_SLL_HOST		0
#define LINUX_SLL_BROADCAST	1
#define LINUX_SLL_MULTICAST	2
#define LINUX_SLL_OTHERHOST	3
#define LINUX_SLL_OUTGOING	4

static const value_string packet_type_vals[] = {
	{ LINUX_SLL_HOST,	"Unicast to us" },
	{ LINUX_SLL_BROADCAST,	"Broadcast" },
	{ LINUX_SLL_MULTICAST,	"Multicast" },
	{ LINUX_SLL_OTHERHOST,	"Unicast to another host" },
	{ LINUX_SLL_OUTGOING,	"Sent by us" },
	{ 0,			NULL }
};

static const value_string ltype_vals[] = {
	{ LINUX_SLL_P_802_3,	"Raw 802.3" },
	{ LINUX_SLL_P_ETHERNET,	"Ethernet" },
	{ LINUX_SLL_P_802_2,	"802.2 LLC" },
	{ LINUX_SLL_P_PPPHDLC,	"PPP (HDLC)" },
	{ LINUX_SLL_P_CAN,	"CAN" },
	{ LINUX_SLL_P_CANFD,	"CAN FD" },
	{ LINUX_SLL_P_IRDA_LAP,	"IrDA LAP" },
	{ LINUX_SLL_P_ISI,	"ISI" },
	{ LINUX_SLL_P_IEEE802154,	"IEEE 802.15.4" },
	{ 0,			NULL }
};


static dissector_handle_t sll_handle;
static dissector_handle_t sll2_handle;
static dissector_handle_t ethertype_handle;
static dissector_handle_t netlink_handle;

static int proto_sll;
static int sll_tap = -1;

static int hf_sll_etype = -1;
static int hf_sll_gretype = -1;
static int hf_sll_halen = -1;
static int hf_sll_hatype = -1;
static int hf_sll_ifindex = -1;
static int hf_sll_ltype = -1;
static int hf_sll_pkttype = -1;
static int hf_sll_src_eth = -1;
static int hf_sll_src_ipv4 = -1;
static int hf_sll_src_other = -1;
static int hf_sll_trailer = -1;
static int hf_sll_unused = -1;

static gint ett_sll = -1;

static dissector_table_t sll_hatype_dissector_table;
static dissector_table_t sll_ltype_dissector_table;
static dissector_table_t gre_dissector_table;

static void sll_prompt(packet_info *pinfo, gchar* result)
{
	snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "SLL protocol type 0x%04x as",
		GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_sll, 0)));
}

static gpointer sll_value(packet_info *pinfo)
{
	return p_get_proto_data(pinfo->pool, pinfo, proto_sll, 0);
}

static const char* sll_conv_get_filter_type(conv_item_t* conv, conv_filter_type_e filter)
{
	if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_ETHER))
		return "sll.src.eth";

	if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_ETHER))
		return "sll.src.eth";

	if ((filter == CONV_FT_SRC_ADDRESS) && (conv->src_address.type == AT_IPv4))
		return "sll.src.ipv4";

	if ((filter == CONV_FT_ANY_ADDRESS) && (conv->src_address.type == AT_IPv4))
		return "sll.src.ipv4";

	return CONV_FILTER_INVALID;
}

static ct_dissector_info_t sll_ct_dissector_info = {&sll_conv_get_filter_type};
static address no_dst = {AT_NONE, 0, NULL, NULL};

static tap_packet_status
sll_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
	conv_hash_t *hash = (conv_hash_t*) pct;
    hash->flags = flags;

	const sll_tap_data *tap_data = (const sll_tap_data*)vip;

	add_conversation_table_data(hash, &tap_data->src_address, &no_dst, 0, 0, 1, pinfo->fd->pkt_len, &pinfo->rel_ts, &pinfo->abs_ts, &sll_ct_dissector_info, ENDPOINT_NONE);

	return TAP_PACKET_REDRAW;
}

static const char* sll_host_get_filter_type(hostlist_talker_t* host, conv_filter_type_e filter)
{
	if ((filter == CONV_FT_SRC_ADDRESS) && (host->myaddress.type == AT_ETHER))
		return "sll.src.eth";

	if ((filter == CONV_FT_ANY_ADDRESS) && (host->myaddress.type == AT_ETHER))
		return "sll.src.eth";

	if ((filter == CONV_FT_SRC_ADDRESS) && (host->myaddress.type == AT_IPv4))
		return "sll.src.ipv4";

	if ((filter == CONV_FT_ANY_ADDRESS) && (host->myaddress.type == AT_IPv4))
		return "sll.src.ipv4";

	return CONV_FILTER_INVALID;
}

static hostlist_dissector_info_t sll_host_dissector_info = {&sll_host_get_filter_type};

static tap_packet_status
sll_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip, tap_flags_t flags)
{
	conv_hash_t *hash = (conv_hash_t*) pit;
    hash->flags = flags;

	const sll_tap_data *tap_data = (const sll_tap_data*)vip;

	add_hostlist_table_data(hash, &tap_data->src_address, 0, TRUE, 1, pinfo->fd->pkt_len, &sll_host_dissector_info, ENDPOINT_NONE);

	return TAP_PACKET_REDRAW;
}

static gboolean
capture_sll(const guchar *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
	guint16 hatype;
	guint16 protocol;

	if (!BYTES_ARE_IN_FRAME(0, len, SLL_HEADER_SIZE))
		return FALSE;

	protocol = pntoh16(&pd[14]);
	if (protocol <= 1536) {	/* yes, 1536 - that's how Linux does it */
		/*
		 * "proto" is *not* a length field, it's a Linux internal
		 * protocol type.
		 */
		hatype = pntoh16(&pd[2]);
		if (try_capture_dissector("sll.hatype", hatype, pd,
		    SLL_HEADER_SIZE, len, cpinfo, pseudo_header))
			return TRUE;
		return try_capture_dissector("sll.ltype", protocol, pd, SLL_HEADER_SIZE, len, cpinfo, pseudo_header);
	} else {
		return try_capture_dissector("ethertype", protocol, pd, SLL_HEADER_SIZE, len, cpinfo, pseudo_header);
	}
	return FALSE;
}

static gboolean
capture_sll2(const guchar *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
	guint16 hatype;
	guint16 protocol;

	if (!BYTES_ARE_IN_FRAME(0, len, SLL2_HEADER_SIZE))
		return FALSE;

	protocol = pntoh16(&pd[0]);
	if (protocol <= 1536) {	/* yes, 1536 - that's how Linux does it */
		/*
		 * "proto" is *not* a length field, it's a Linux internal
		 * protocol type.
		 */
		hatype = pntoh16(&pd[8]);
		if (try_capture_dissector("sll.hatype", hatype, pd,
		    SLL2_HEADER_SIZE, len, cpinfo, pseudo_header))
			return TRUE;
		return try_capture_dissector("sll.ltype", protocol, pd, SLL2_HEADER_SIZE, len, cpinfo, pseudo_header);
	} else {
		return try_capture_dissector("ethertype", protocol, pd, SLL2_HEADER_SIZE, len, cpinfo, pseudo_header);
	}
	return FALSE;
}

static void
add_ll_address(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb,
    int halen_offset, int halen_len, sll_tap_data *tap_data)
{
	guint32 ha_len;
	int ha_offset = halen_offset + halen_len;

	/*
	 * XXX - check the link-layer address type value?
	 * For now, we just assume ha_len 4 is IPv4 and ha_len 6
	 * is Ethernet.
	 */
	proto_tree_add_item_ret_uint(tree, hf_sll_halen, tvb, halen_offset, halen_len, ENC_BIG_ENDIAN, &ha_len);

	switch (ha_len) {
	case 4:
		set_address_tvb(&pinfo->dl_src, AT_IPv4, 4, tvb, ha_offset);
		copy_address_shallow(&pinfo->src, &pinfo->dl_src);
		copy_address_wmem(wmem_file_scope(), &tap_data->src_address, &pinfo->src);
		proto_tree_add_item(tree, hf_sll_src_ipv4, tvb, ha_offset, 4, ENC_BIG_ENDIAN);
		break;
	case 6:
		set_address_tvb(&pinfo->dl_src, AT_ETHER, 6, tvb, ha_offset);
		copy_address_shallow(&pinfo->src, &pinfo->dl_src);
		copy_address_wmem(wmem_file_scope(), &tap_data->src_address, &pinfo->src);
		proto_tree_add_item(tree, hf_sll_src_eth, tvb, ha_offset, 6, ENC_NA);
		break;
	case 0:
		break;
	default:
		proto_tree_add_item(tree, hf_sll_src_other, tvb,
			    ha_offset, ha_len > 8 ? 8 : ha_len, ENC_NA);
		break;
	}

	/* Not all bytes of SLL_ADDRLEN have been used. Add remaining as unused */
	if (ha_len < SLL_ADDRLEN)
		proto_tree_add_item(tree, hf_sll_unused, tvb, ha_offset + ha_len,
				SLL_ADDRLEN - ha_len, ENC_NA);
}

static guint16
add_protocol_type(proto_tree *fh_tree, tvbuff_t *tvb, int protocol_offset,
    int hatype)
{
	guint16 protocol;

	protocol = tvb_get_ntohs(tvb, protocol_offset);
	if (protocol <= 1536) {	/* yes, 1536 - that's how Linux does it */
		/*
		 * "proto" is *not* a length field, it's a Linux internal
		 * protocol type.
		 * We therefore cannot say how much of the packet will
		 * be trailer data.
		 * XXX - do the same thing we do for packets with Ethertypes?
		 */
		proto_tree_add_uint(fh_tree, hf_sll_ltype, tvb,
		    protocol_offset, 2, protocol);
	} else {
		switch (hatype) {

		case ARPHRD_IPGRE:
			/*
			 * XXX - the link-layer header appears to consist
			 * of an IPv4 header followed by a bunch of stuff
			 * that includes the GRE flags and version, but
			 * cooked captures strip the link-layer header,
			 * so we can't provide the flags and version to
			 * the dissector.
			 */
			proto_tree_add_uint(fh_tree, hf_sll_gretype, tvb,
			    protocol_offset, 2, protocol);
			break;

		default:
			proto_tree_add_uint(fh_tree, hf_sll_etype, tvb,
			    protocol_offset, 2, protocol);
			break;
		}
	}
	return protocol;
}

static void
dissect_payload(proto_tree *tree, packet_info *pinfo, proto_tree *fh_tree,
    tvbuff_t *tvb, int header_size, int hatype, guint16 protocol)
{
	tvbuff_t *next_tvb;
	ethertype_data_t ethertype_data;

	next_tvb = tvb_new_subset_remaining(tvb, header_size);
	if (protocol <= 1536) {	/* yes, 1536 - that's how Linux does it */
		/*
		 * "proto" is *not* a length field, it's a Linux internal
		 * protocol type.
		 * We therefore cannot say how much of the packet will
		 * be trailer data.
		 * XXX - do the same thing we do for packets with Ethertypes?
		 */
		if (!dissector_try_uint(sll_hatype_dissector_table, hatype,
		    next_tvb, pinfo, tree)) {
			p_add_proto_data(pinfo->pool, pinfo, proto_sll, 0, GUINT_TO_POINTER((guint)protocol));
			if (!dissector_try_uint(sll_ltype_dissector_table,
			    protocol, next_tvb, pinfo, tree)) {
				call_data_dissector(next_tvb, pinfo, tree);
			}
		}
	} else {
		switch (hatype) {

		case ARPHRD_IPGRE:
			/*
			 * XXX - the link-layer header appears to consist
			 * of an IPv4 header followed by a bunch of stuff
			 * that includes the GRE flags and version, but
			 * cooked captures strip the link-layer header,
			 * so we can't provide the flags and version to
			 * the dissector.
			 */
			dissector_try_uint(gre_dissector_table, protocol,
			    next_tvb, pinfo, tree);
			break;

		default:
			ethertype_data.etype = protocol;
			ethertype_data.payload_offset = header_size;
			ethertype_data.fh_tree = fh_tree;
			ethertype_data.trailer_id = hf_sll_trailer;
			ethertype_data.fcs_len = 0;

			call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
			break;
		}
	}
}

static int
dissect_sll_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int encap)
{
	guint16 pkttype;
	guint16 protocol;
	guint16 hatype;
	int header_size;
	int version;
	proto_item *ti;
	proto_tree *fh_tree;
	sll_tap_data* tap_data;

	switch (encap) {

	case WTAP_ENCAP_SLL:
		pkttype = tvb_get_ntohs(tvb, 0);
		header_size = SLL_HEADER_SIZE;
		version = 1;
		break;

	case WTAP_ENCAP_SLL2:
		pkttype = tvb_get_ntohs(tvb, 10);
		header_size = SLL2_HEADER_SIZE;
		version = 2;
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	/*
	 * Set "pinfo->p2p_dir" if the packet wasn't received
	 * promiscuously.
	 */
	switch (pkttype) {

	case LINUX_SLL_HOST:
	case LINUX_SLL_BROADCAST:
	case LINUX_SLL_MULTICAST:
		pinfo->p2p_dir = P2P_DIR_RECV;
		break;

	case LINUX_SLL_OUTGOING:
		pinfo->p2p_dir = P2P_DIR_SENT;
		break;
	}

	switch (encap) {

	case WTAP_ENCAP_SLL:
		hatype = tvb_get_ntohs(tvb, 2);
		break;

	case WTAP_ENCAP_SLL2:
		hatype = tvb_get_ntohs(tvb, 8);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	/*
	 * XXX - special purpose hack.  Netlink packets have a hardware
	 * address type of ARPHRD_NETLINK, but the protocol type value
	 * indicates the Netlink message type; we just hand the netlink
	 * dissector our *entire* packet.
	 *
	 * That's different from link-layer types such as 802.11+radiotap,
	 * where the payload follows the complete SLL header, and the
	 * protocol field in the SLL header is irrelevant; for those,
	 * we have the sll.hatype dissector table.
	 */
	if (hatype == ARPHRD_NETLINK) {
		return call_dissector(netlink_handle, tvb, pinfo, tree);
	}

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SLL");
	col_clear(pinfo->cinfo, COL_INFO);

	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(pkttype, packet_type_vals, "Unknown (%u)"));

	ti = proto_tree_add_protocol_format(tree, proto_sll, tvb, 0,
			header_size, "Linux cooked capture v%d", version);
	fh_tree = proto_item_add_subtree(ti, ett_sll);
	tap_data = wmem_new0(wmem_file_scope(), sll_tap_data);

	switch (encap) {

	case WTAP_ENCAP_SLL:
		proto_tree_add_item(fh_tree, hf_sll_pkttype, tvb, 0, 2, ENC_BIG_ENDIAN);

		proto_tree_add_uint(fh_tree, hf_sll_hatype, tvb, 2, 2, hatype);

		add_ll_address(fh_tree, pinfo, tvb, 4, 2, tap_data);

		protocol = add_protocol_type(fh_tree, tvb, 14, hatype);

		dissect_payload(tree, pinfo, fh_tree, tvb, SLL_HEADER_SIZE, hatype, protocol);
		break;

	case WTAP_ENCAP_SLL2:
		protocol = add_protocol_type(fh_tree, tvb, 0, hatype);

		proto_tree_add_item(fh_tree, hf_sll_ifindex, tvb, 4, 4, ENC_BIG_ENDIAN);

		proto_tree_add_uint(fh_tree, hf_sll_hatype, tvb, 8, 2, hatype);

		proto_tree_add_item(fh_tree, hf_sll_pkttype, tvb, 10, 1, ENC_BIG_ENDIAN);

		add_ll_address(fh_tree, pinfo, tvb, 11, 1, tap_data);

		dissect_payload(tree, pinfo, fh_tree, tvb, SLL2_HEADER_SIZE, hatype, protocol);
		break;

	default:
		DISSECTOR_ASSERT_NOT_REACHED();
	}

	tap_queue_packet(sll_tap, pinfo, tap_data);

	return tvb_captured_length(tvb);
}

static int
dissect_sll_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	return dissect_sll_common(tvb, pinfo, tree, WTAP_ENCAP_SLL);
}

static int
dissect_sll_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	return dissect_sll_common(tvb, pinfo, tree, WTAP_ENCAP_SLL2);
}

void
proto_register_sll(void)
{
	static hf_register_info hf[] = {
		{ &hf_sll_pkttype,
			{ "Packet type", "sll.pkttype",
			  FT_UINT16, BASE_DEC, VALS(packet_type_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_sll_hatype,
			{ "Link-layer address type", "sll.hatype",
			  FT_UINT16, BASE_DEC, VALS(arp_hrd_vals), 0x0,
			  NULL, HFILL }
		},
		{ &hf_sll_halen,
			{ "Link-layer address length", "sll.halen",
			  FT_UINT16, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_sll_src_eth,
			{ "Source", "sll.src.eth",
			  FT_ETHER, BASE_NONE, NULL, 0x0,
			  "Source link-layer address", HFILL }
		},
		{ &hf_sll_src_ipv4,
			{ "Source", "sll.src.ipv4",
			  FT_IPv4, BASE_NONE, NULL, 0x0,
			  "Source link-layer address", HFILL }
		},
		{ &hf_sll_src_other,
			{ "Source", "sll.src.other",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  "Source link-layer address", HFILL }
		},
		{ &hf_sll_unused,
			{ "Unused", "sll.unused",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  "Unused bytes", HFILL }
		},
		{ &hf_sll_ltype,
			{ "Protocol", "sll.ltype",
			  FT_UINT16, BASE_HEX, VALS(ltype_vals), 0x0,
			  "Linux protocol type", HFILL }
		},
		{ &hf_sll_gretype,
			{ "Protocol", "sll.gretype",
			  FT_UINT16, BASE_HEX, VALS(gre_typevals), 0x0,
			  "GRE protocol type", HFILL }
		},
		{ &hf_sll_etype,
			{ "Protocol", "sll.etype",
			  FT_UINT16, BASE_HEX, VALS(etype_vals), 0x0,
			  "Ethernet protocol type", HFILL }
		},
		{ &hf_sll_trailer,
			{ "Trailer", "sll.trailer",
			  FT_BYTES, BASE_NONE, NULL, 0x0,
			  NULL, HFILL }
		},
		{ &hf_sll_ifindex,
			{ "Interface index", "sll.ifindex",
			  FT_UINT32, BASE_DEC, NULL, 0x0,
			  NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_sll
	};

	/* Decode As handling */
	static build_valid_func sll_da_build_value[1] = {sll_value};
	static decode_as_value_t sll_da_values = {sll_prompt, 1, sll_da_build_value};
	static decode_as_t sll_da = {"sll.ltype", "sll.ltype", 1, 0, &sll_da_values, NULL, NULL,
				decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

	proto_sll = proto_register_protocol("Linux cooked-mode capture", "SLL", "sll" );
	proto_register_field_array(proto_sll, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	sll_handle = create_dissector_handle(dissect_sll_v1, proto_sll);
	sll2_handle = create_dissector_handle(dissect_sll_v2, proto_sll);
	sll_tap = register_tap("sll");

	/*
	 * Sigh.
	 *
	 * For some packets, the link-layer header *isn't* been stripped
	 * off in a cooked capture; the hardware address type is the
	 * device ARPTYPE, so, for those packets, we should call the
	 * dissector for that value.
	 *
	 * We define a "sll.hatype" dissector table; we try dissecting
	 * with that first, and then try the protocol type if nothing
	 * is found in sll.hatype.
	 */
	sll_hatype_dissector_table = register_dissector_table (
		"sll.hatype",
		"Linux SLL ARPHRD_ type",
		proto_sll, FT_UINT16,
		BASE_DEC
	);
	register_capture_dissector_table("sll.hatype", "Linux SLL ARPHRD_ type");

	sll_ltype_dissector_table = register_dissector_table (
		"sll.ltype",
		"Linux SLL protocol type",
		proto_sll, FT_UINT16,
		BASE_HEX
	);
	register_capture_dissector_table("sll.ltype", "Linux SLL protocol");

	register_conversation_table(proto_sll, TRUE, sll_conversation_packet, sll_hostlist_packet);

	register_decode_as(&sll_da);
}

void
proto_reg_handoff_sll(void)
{
	capture_dissector_handle_t sll_cap_handle;
	capture_dissector_handle_t sll2_cap_handle;

	/*
	 * Get handles for the IPX and LLC dissectors.
	 */
	gre_dissector_table = find_dissector_table("gre.proto");
	ethertype_handle = find_dissector_add_dependency("ethertype", proto_sll);
	netlink_handle = find_dissector_add_dependency("netlink", proto_sll);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_SLL, sll_handle);
	dissector_add_uint("wtap_encap", WTAP_ENCAP_SLL2, sll2_handle);
	sll_cap_handle = create_capture_dissector_handle(capture_sll, proto_sll);
	capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_SLL, sll_cap_handle);
	sll2_cap_handle = create_capture_dissector_handle(capture_sll2, proto_sll);
	capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_SLL2, sll2_cap_handle);
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
