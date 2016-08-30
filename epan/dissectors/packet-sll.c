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

#include <epan/packet.h>
#include <epan/capture_dissectors.h>
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
#include <epan/decode_as.h>
#include <epan/proto_data.h>

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
	{ LINUX_SLL_P_ISI,	"ISI" },
	{ LINUX_SLL_P_IEEE802154,	"IEEE 802.15.4" },
	{ LINUX_SLL_P_NETLINK,	"Netlink" },
	{ 0,			NULL }
};


static dissector_handle_t sll_handle;
static dissector_handle_t ethertype_handle;
static dissector_handle_t netlink_handle;

static header_field_info *hfi_sll = NULL;

static int proto_sll;

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

static void sll_prompt(packet_info *pinfo, gchar* result)
{
	g_snprintf(result, MAX_DECODE_AS_PROMPT_LEN, "SLL protocol type 0x%04x as",
		GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_sll, 0)));
}

static gpointer sll_value(packet_info *pinfo)
{
	return p_get_proto_data(pinfo->pool, pinfo, proto_sll, 0);
}

static gboolean
capture_sll(const guchar *pd, int offset _U_, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header _U_)
{
	guint16 protocol;

	if (!BYTES_ARE_IN_FRAME(0, len, SLL_HEADER_SIZE))
		return FALSE;

	protocol = pntoh16(&pd[14]);
	if (protocol <= 1536) {	/* yes, 1536 - that's how Linux does it */
		/*
		 * "proto" is *not* a length field, it's a Linux internal
		 * protocol type.
		 */
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

	/* the netlink dissector can parse our entire header, we can
	   pass it our complete tvb
	   XXX - are there any other protocols that use the same header
	   format as sll? if so, we should add a dissector table
	   sll.hatpye */
	if (hatype == LINUX_SLL_P_NETLINK) {
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
		proto_tree_add_item(fh_tree, &hfi_sll_src_ipv4, tvb, 6, 4, ENC_BIG_ENDIAN);
		break;
	case 6:
		set_address_tvb(&pinfo->dl_src, AT_ETHER, 6, tvb, 6);
		copy_address_shallow(&pinfo->src, &pinfo->dl_src);
		proto_tree_add_item(fh_tree, &hfi_sll_src_eth, tvb, 6, 6, ENC_NA);
		break;
	case 0:
		break;
	default:
		proto_tree_add_item(fh_tree, &hfi_sll_src_other, tvb,
			    6, halen > 8 ? 8 : halen, ENC_NA);
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

		p_add_proto_data(pinfo->pool, pinfo, proto_sll, 0, GUINT_TO_POINTER((guint)protocol));

		if(!dissector_try_uint(sll_linux_dissector_table, protocol,
			next_tvb, pinfo, tree)) {
			call_data_dissector(next_tvb, pinfo, tree);
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

	sll_linux_dissector_table = register_dissector_table (
		"sll.ltype",
		"Linux SLL protocol type",
		proto_sll, FT_UINT16,
		BASE_HEX
	);
	register_capture_dissector_table("sll.ltype", "Linux SLL protocol");
	register_decode_as(&sll_da);
}

void
proto_reg_handoff_sll(void)
{
	/*
	 * Get handles for the IPX and LLC dissectors.
	 */
	gre_dissector_table = find_dissector_table("gre.proto");
	ethertype_handle = find_dissector_add_dependency("ethertype", proto_sll);
	netlink_handle = find_dissector_add_dependency("netlink", proto_sll);

	dissector_add_uint("wtap_encap", WTAP_ENCAP_SLL, sll_handle);
	register_capture_dissector("wtap_encap", WTAP_ENCAP_SLL, capture_sll, hfi_sll->id);
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
