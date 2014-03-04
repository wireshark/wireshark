/* packet-sll.c
 * Routines for disassembly of packets from Linux "cooked mode" captures
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#define NEW_PROTO_TREE_API

#include "config.h"

#include <glib.h>
#include <epan/arptypes.h>
#include <epan/prefs.h>
#include <epan/packet.h>
#include <wsutil/pint.h>
#include "packet-sll.h"
#include "packet-ipx.h"
#include "packet-llc.h"
#include "packet-eth.h"
#include "packet-ppp.h"
#include "packet-gre.h"
#include <epan/addr_resolv.h>
#include <epan/etypes.h>

void proto_register_sll(void);
void proto_reg_handoff_sll(void);
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
	{ LINUX_SLL_P_IRDA_LAP,	"IrDA LAP" },
	{ LINUX_SLL_P_IEEE802154,	"IEEE 802.15.4" },
	{ 0,			NULL }
};


static dissector_handle_t sll_handle;
static dissector_handle_t ethertype_handle;

static header_field_info *hfi_sll = NULL;

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

static dissector_table_t sll_linux_dissector_table;
static dissector_table_t gre_dissector_table;
static dissector_handle_t data_handle;

void
capture_sll(const guchar *pd, int len, packet_counts *ld)
{
	guint16 protocol;

	if (!BYTES_ARE_IN_FRAME(0, len, SLL_HEADER_SIZE)) {
		ld->other++;
		return;
	}
	protocol = pntoh16(&pd[14]);
	if (protocol <= 1536) {	/* yes, 1536 - that's how Linux does it */
		/*
		 * "proto" is *not* a length field, it's a Linux internal
		 * protocol type.
		 */
		switch (protocol) {

		case LINUX_SLL_P_802_2:
			/*
			 * 802.2 LLC.
			 */
			capture_llc(pd, len, SLL_HEADER_SIZE, ld);
			break;

		case LINUX_SLL_P_ETHERNET:
			/*
			 * Ethernet.
			 */
			capture_eth(pd, SLL_HEADER_SIZE, len, ld);
			break;

		case LINUX_SLL_P_802_3:
			/*
			 * Novell IPX inside 802.3 with no 802.2 LLC
			 * header.
			 */
			capture_ipx(ld);
			break;

		case LINUX_SLL_P_PPPHDLC:
			/*
			 * PPP HDLC.
			 */
			capture_ppp_hdlc(pd, len, SLL_HEADER_SIZE, ld);
			break;

		default:
			ld->other++;
			break;
		}
	} else
		capture_ethertype(protocol, pd, SLL_HEADER_SIZE, len, ld);
}

static void
dissect_sll(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	guint16 pkttype;
	guint16 protocol;
	guint16 hatype, halen;
	const guint8 *src;
	proto_item *ti;
	tvbuff_t *next_tvb;
	proto_tree *fh_tree = NULL;
	ethertype_data_t ethertype_data;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "SLL");
	col_clear(pinfo->cinfo, COL_INFO);

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

	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(pkttype, packet_type_vals, "Unknown (%u)"));

	if (tree) {
		ti = proto_tree_add_protocol_format(tree, hfi_sll->id, tvb, 0,
		    SLL_HEADER_SIZE, "Linux cooked capture");
		fh_tree = proto_item_add_subtree(ti, ett_sll);
		proto_tree_add_item(fh_tree, &hfi_sll_pkttype, tvb, 0, 2, ENC_BIG_ENDIAN);
	}

	/*
	 * XXX - check the link-layer address type value?
	 * For now, we just assume 6 means Ethernet.
	 */
	hatype = tvb_get_ntohs(tvb, 2);
	halen = tvb_get_ntohs(tvb, 4);
	if (tree) {
		proto_tree_add_uint(fh_tree, &hfi_sll_hatype, tvb, 2, 2, hatype);
		proto_tree_add_uint(fh_tree, &hfi_sll_halen, tvb, 4, 2, halen);
	}
	switch (halen) {
	case 4:
		src = tvb_get_ptr(tvb, 6, 4);
		SET_ADDRESS(&pinfo->dl_src, AT_IPv4, 4, src);
		SET_ADDRESS(&pinfo->src, AT_IPv4, 4, src);
		if (tree) {
			proto_tree_add_item(fh_tree, &hfi_sll_src_ipv4, tvb,
			    6, 4, ENC_BIG_ENDIAN);
		}
		break;
	case 6:
		src = tvb_get_ptr(tvb, 6, 6);
		SET_ADDRESS(&pinfo->dl_src, AT_ETHER, 6, src);
		SET_ADDRESS(&pinfo->src, AT_ETHER, 6, src);
		if (tree) {
			proto_tree_add_ether(fh_tree, hfi_sll_src_eth.id, tvb,
			    6, 6, src);
		}
		break;
	case 0:
		break;
	default:
		if (tree) {
			proto_tree_add_item(fh_tree, &hfi_sll_src_other, tvb,
			    6, halen > 8 ? 8 : halen, ENC_NA);
		}
		break;
	}

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

		if(!dissector_try_uint(sll_linux_dissector_table, protocol,
			next_tvb, pinfo, tree)) {
			call_dissector(data_handle, next_tvb, pinfo, tree);
		}
	} else {
		switch (hatype) {
		case ARPHRD_IPGRE:
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

	int proto_sll;

	proto_sll = proto_register_protocol("Linux cooked-mode capture",
	    "SLL", "sll" );
	hfi_sll = proto_registrar_get_nth(proto_sll);

	proto_register_fields(proto_sll, hfi, array_length(hfi));
	proto_register_subtree_array(ett, array_length(ett));

	sll_handle = create_dissector_handle(dissect_sll, proto_sll);

	sll_linux_dissector_table = register_dissector_table (
		"sll.ltype",
		"Linux SLL protocol type",
		FT_UINT16,
		BASE_HEX
	);
}

void
proto_reg_handoff_sll(void)
{
	/*
	 * Get handles for the IPX and LLC dissectors.
	 */
	gre_dissector_table = find_dissector_table("gre.proto");
	data_handle = find_dissector("data");
	ethertype_handle = find_dissector("ethertype");

	dissector_add_uint("wtap_encap", WTAP_ENCAP_SLL, sll_handle);
}
