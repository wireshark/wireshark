/* packet-sll.c
 * Routines for disassembly of packets from Linux "cooked mode" captures
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#define NEW_PROTO_TREE_API

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
 * A DLT_LINUX_SLL fake link-layer header.
 */
#define SLL_HEADER_SIZE	16		/* total header length */
#define SLL_ADDRLEN	8		/* length of address field */

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
static dissector_handle_t ethertype_handle;
static dissector_handle_t netlink_handle;

static header_field_info *hfi_sll = NULL;

static int proto_sll;
static int sll_tap = -1;

#define SLL_HFI_INIT HFI_INIT(proto_sll)

static header_field_info hfi_sll_pkttype SLL_HFI_INIT =
	{ "Packet type",	"sll.pkttype", FT_UINT16, BASE_DEC,
	  VALS(packet_type_vals), 0x0, NULL, HFILL };

/* ARP hardware type?  With Linux extensions? */
static header_field_info hfi_sll_hatype SLL_HFI_INIT =
	{ "Link-layer address type",	"sll.hatype", FT_UINT16, BASE_DEC,
	  NULL, 0x0, NULL, HFILL };

static header_field_info hfi_sll_halen SLL_HFI_INIT =
	{ "Link-layer address length",	"sll.halen", FT_UINT16, BASE_DEC,
	  NULL, 0x0, NULL, HFILL };

/* Source address if it's an Ethernet-type address */
static header_field_info hfi_sll_src_eth SLL_HFI_INIT =
	{ "Source",	"sll.src.eth", FT_ETHER, BASE_NONE,
	  NULL, 0x0, "Source link-layer address", HFILL };

/* Source address if it's an IPv4 address */
static header_field_info hfi_sll_src_ipv4 SLL_HFI_INIT =
	{ "Source",	"sll.src.ipv4", FT_IPv4, BASE_NONE,
	  NULL, 0x0, "Source link-layer address", HFILL };

/* Source address if it's not an Ethernet-type address */
static header_field_info hfi_sll_src_other SLL_HFI_INIT =
	{ "Source",	"sll.src.other", FT_BYTES, BASE_NONE,
	  NULL, 0x0, "Source link-layer address", HFILL };

/* Unused remaining bytes */
static header_field_info hfi_sll_unused SLL_HFI_INIT =
	{ "Unused", "sll.unused", FT_BYTES, BASE_NONE,
	  NULL, 0x0, "Unused bytes", HFILL };

/* if the protocol field is an internal Linux protocol type */
static header_field_info hfi_sll_ltype SLL_HFI_INIT =
	{ "Protocol",	"sll.ltype", FT_UINT16, BASE_HEX,
	  VALS(ltype_vals), 0x0, "Linux protocol type", HFILL };

/* if the protocol field is a GRE protocol type */
static header_field_info hfi_sll_gretype SLL_HFI_INIT =
	{ "Protocol",	"sll.gretype", FT_UINT16, BASE_HEX,
	  VALS(gre_typevals), 0x0, "GRE protocol type", HFILL };

/* registered here but handled in ethertype.c */
static header_field_info hfi_sll_etype SLL_HFI_INIT =
	{ "Protocol",	"sll.etype", FT_UINT16, BASE_HEX,
	  VALS(etype_vals), 0x0, "Ethernet protocol type", HFILL };

static header_field_info hfi_sll_trailer SLL_HFI_INIT =
	{ "Trailer", "sll.trailer", FT_BYTES, BASE_NONE,
	  NULL, 0x0, NULL, HFILL };


static gint ett_sll = -1;

static dissector_table_t sll_hatype_dissector_table;
static dissector_table_t sll_ltype_dissector_table;
static dissector_table_t gre_dissector_table;

static void sll_prompt(packet_info *pinfo, gchar* result)
{
	g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "SLL protocol type 0x%04x as",
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
sll_conversation_packet(void *pct, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	conv_hash_t *hash = (conv_hash_t*) pct;
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
sll_hostlist_packet(void *pit, packet_info *pinfo, epan_dissect_t *edt _U_, const void *vip)
{
	conv_hash_t *hash = (conv_hash_t*) pit;
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

static int
dissect_sll(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	guint16 pkttype;
	guint16 protocol;
	guint16 hatype, halen;
	proto_item *ti;
	tvbuff_t *next_tvb;
	proto_tree *fh_tree;
	ethertype_data_t ethertype_data;
	sll_tap_data* tap_data;

	pkttype = tvb_get_ntohs(tvb, 0);

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

	hatype = tvb_get_ntohs(tvb, 2);
	halen = tvb_get_ntohs(tvb, 4);

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

	ti = proto_tree_add_protocol_format(tree, hfi_sll->id, tvb, 0,
			SLL_HEADER_SIZE, "Linux cooked capture");
	fh_tree = proto_item_add_subtree(ti, ett_sll);
	proto_tree_add_item(fh_tree, &hfi_sll_pkttype, tvb, 0, 2, ENC_BIG_ENDIAN);

	tap_data = wmem_new0(wmem_file_scope(), sll_tap_data);

	/*
	 * XXX - check the link-layer address type value?
	 * For now, we just assume halen 4 is IPv4 and halen 6 is Ethernet.
	 */
	proto_tree_add_uint(fh_tree, &hfi_sll_hatype, tvb, 2, 2, hatype);
	proto_tree_add_uint(fh_tree, &hfi_sll_halen, tvb, 4, 2, halen);

	switch (halen) {
	case 4:
		set_address_tvb(&pinfo->dl_src, AT_IPv4, 4, tvb, 6);
		copy_address_shallow(&pinfo->src, &pinfo->dl_src);
		copy_address_wmem(wmem_file_scope(), &tap_data->src_address, &pinfo->src);
		proto_tree_add_item(fh_tree, &hfi_sll_src_ipv4, tvb, 6, 4, ENC_BIG_ENDIAN);
		break;
	case 6:
		set_address_tvb(&pinfo->dl_src, AT_ETHER, 6, tvb, 6);
		copy_address_shallow(&pinfo->src, &pinfo->dl_src);
		copy_address_wmem(wmem_file_scope(), &tap_data->src_address, &pinfo->src);
		proto_tree_add_item(fh_tree, &hfi_sll_src_eth, tvb, 6, 6, ENC_NA);
		break;
	case 0:
		break;
	default:
		proto_tree_add_item(fh_tree, &hfi_sll_src_other, tvb,
			    6, halen > 8 ? 8 : halen, ENC_NA);
		break;
	}

	/* Not all bytes of SLL_ADDRLEN have been used. Add remaining as unused */
	if (SLL_ADDRLEN - halen > 0)
		proto_tree_add_item(fh_tree, &hfi_sll_unused, tvb, 6 + halen,
			SLL_ADDRLEN - halen, ENC_BIG_ENDIAN);

	protocol = tvb_get_ntohs(tvb, 14);
	next_tvb = tvb_new_subset_remaining(tvb, SLL_HEADER_SIZE);
	if (protocol <= 1536) {	/* yes, 1536 - that's how Linux does it */
		/*
		 * "proto" is *not* a length field, it's a Linux internal
		 * protocol type.
		 * We therefore cannot say how much of the packet will
		 * be trailer data.
		 * XXX - do the same thing we do for packets with Ethertypes?
		 */
		proto_tree_add_uint(fh_tree, &hfi_sll_ltype, tvb, 14, 2,
		    protocol);

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
			proto_tree_add_uint(fh_tree, &hfi_sll_gretype, tvb, 14, 2,
			    protocol);
			dissector_try_uint(gre_dissector_table,
					   protocol, next_tvb, pinfo, tree);
			break;
		default:
			ethertype_data.etype = protocol;
			ethertype_data.offset_after_ethertype = SLL_HEADER_SIZE;
			ethertype_data.fh_tree = fh_tree;
			ethertype_data.etype_id = hfi_sll_etype.id;
			ethertype_data.trailer_id = hfi_sll_trailer.id;
			ethertype_data.fcs_len = 0;

			call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
			break;
		}
	}

	tap_queue_packet(sll_tap, pinfo, tap_data);

	return tvb_captured_length(tvb);
}

void
proto_register_sll(void)
{
#ifndef HAVE_HFI_SECTION_INIT
	static header_field_info *hfi[] = {
		&hfi_sll_pkttype,
		/* ARP hardware type?  With Linux extensions? */
		&hfi_sll_hatype,
		&hfi_sll_halen,
		&hfi_sll_src_eth,
		&hfi_sll_src_ipv4,
		&hfi_sll_src_other,
		&hfi_sll_unused,
		&hfi_sll_ltype,
		&hfi_sll_gretype,
		/* registered here but handled in ethertype.c */
		&hfi_sll_etype,
		&hfi_sll_trailer,
	};
#endif

	static gint *ett[] = {
		&ett_sll
	};

	/* Decode As handling */
	static build_valid_func sll_da_build_value[1] = {sll_value};
	static decode_as_value_t sll_da_values = {sll_prompt, 1, sll_da_build_value};
	static decode_as_t sll_da = {"sll.ltype", "Link", "sll.ltype", 1, 0, &sll_da_values, NULL, NULL,
				decode_as_default_populate_list, decode_as_default_reset, decode_as_default_change, NULL};

	proto_sll = proto_register_protocol("Linux cooked-mode capture",
	    "SLL", "sll" );
	hfi_sll = proto_registrar_get_nth(proto_sll);

	proto_register_fields(proto_sll, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	sll_handle = create_dissector_handle(dissect_sll, proto_sll);
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

	/*
	 * Get handles for the IPX and LLC dissectors.
	 */
	gre_dissector_table = find_dissector_table("gre.proto");
	ethertype_handle = find_dissector_add_dependency("ethertype", proto_sll);
	netlink_handle = find_dissector_add_dependency("netlink", proto_sll);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_SLL, sll_handle);
	sll_cap_handle = create_capture_dissector_handle(capture_sll, proto_sll);
	capture_dissector_add_uint("wtap_encap", WTAP_ENCAP_SLL, sll_cap_handle);
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
