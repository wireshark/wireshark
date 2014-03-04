/* packet-nlsp.c
 * Routines for NetWare Link Services Protocol
 *
 * Based on ISIS dissector by Stuart Stanley <stuarts@mxmail.net>
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/to_str.h>
#include "packet-ipx.h"

void proto_register_nlsp(void);
void proto_reg_handoff_nlsp(void);

/* NLSP base header */
static int proto_nlsp                    = -1;

static int hf_nlsp_irpd                  = -1;
static int hf_nlsp_header_length         = -1;
static int hf_nlsp_minor_version         = -1;
static int hf_nlsp_nr                    = -1;
static int hf_nlsp_type                  = -1;
static int hf_nlsp_major_version         = -1;
static int hf_nlsp_packet_length         = -1;
static int hf_nlsp_hello_state           = -1;
static int hf_nlsp_hello_multicast       = -1;
static int hf_nlsp_hello_circuit_type    = -1;
static int hf_nlsp_hello_holding_timer   = -1;
static int hf_nlsp_hello_priority        = -1;
static int hf_nlsp_lsp_sequence_number   = -1;
static int hf_nlsp_lsp_checksum          = -1;
static int hf_nlsp_lsp_p                 = -1;
static int hf_nlsp_lsp_attached_flag     = -1;
static int hf_nlsp_lsp_lspdbol           = -1;
static int hf_nlsp_lsp_router_type       = -1;
static int hf_nlsp_lsp_link_info_clv_flags_cost_present = -1;
static int hf_nlsp_lsp_link_info_clv_flags_cost_metric = -1;
static int hf_nlsp_lsp_link_info_clv_flags_cost = -1;

static gint ett_nlsp                     = -1;
static gint ett_nlsp_hello_clv_area_addr = -1;
static gint ett_nlsp_hello_clv_neighbors = -1;
static gint ett_nlsp_hello_local_mtu     = -1;
static gint ett_nlsp_hello_clv_unknown   = -1;
static gint ett_nlsp_lsp_info            = -1;
static gint ett_nlsp_lsp_clv_area_addr   = -1;
static gint ett_nlsp_lsp_clv_mgt_info    = -1;
static gint ett_nlsp_lsp_clv_link_info   = -1;
static gint ett_nlsp_lsp_clv_svcs_info   = -1;
static gint ett_nlsp_lsp_clv_ext_routes  = -1;
static gint ett_nlsp_lsp_clv_unknown     = -1;
static gint ett_nlsp_csnp_lsp_entries    = -1;
static gint ett_nlsp_csnp_lsp_entry      = -1;
static gint ett_nlsp_csnp_clv_unknown    = -1;
static gint ett_nlsp_psnp_lsp_entries    = -1;
static gint ett_nlsp_psnp_lsp_entry      = -1;
static gint ett_nlsp_psnp_clv_unknown    = -1;

#define PACKET_TYPE_MASK	0x1f

/*
 * See
 *
 *	http://www.cisco.com/univercd/cc/td/doc/cisintwk/ito_doc/nlsp.htm
 *
 * for some information about Hello packets.
 */

#define NLSP_TYPE_L1_HELLO	15
#define NLSP_TYPE_WAN_HELLO	17
#define NLSP_TYPE_L1_LSP	18
#define NLSP_TYPE_L1_CSNP	24
#define NLSP_TYPE_L1_PSNP	26

static const value_string nlsp_packet_type_vals[] = {
	{ NLSP_TYPE_L1_HELLO,  "L1 Hello"},
	{ NLSP_TYPE_WAN_HELLO, "WAN Hello"},
	{ NLSP_TYPE_L1_LSP,    "L1 LSP"},
	{ NLSP_TYPE_L1_CSNP,   "L1 CSNP"},
	{ NLSP_TYPE_L1_PSNP,   "L1 PSNP"},
	{ 0,                   NULL}
};

static const value_string nlsp_attached_flag_vals[] = {
	{ 0, "Other routing areas cannot be reached through this router"},
	{ 1, "Other routing areas can be reached through this router"},
	{ 0, NULL}
};

static const value_string nlsp_router_type_vals[] = {
	{ 1, "Level 1 Router"},
	{ 3, "Level 1 and Level 2 Router"},
	{ 0, NULL}
};

static const true_false_string tfs_internal_external = { "Internal", "External" };

/*
 * Our sub-packet dismantle structure for CLV's
 */
typedef struct {
	int		optcode;		/* code for option */
	const char	*tree_text;		/* text for fold out */
	gint		*tree_id;		/* id for add_item */
	void		(*dissect)(tvbuff_t *tvb, proto_tree *tree,
				int offset, int length);
} nlsp_clv_handle_t;

/*
 * Name: nlsp_dissect_unknown()
 *
 * Description:
 *	There was some error in the protocol and we are in unknown space
 *	here.  Add a tree item to cover the error and go on.  Note
 *	that we make sure we don't go off the end of the bleedin packet here!
 *
 * Input
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : tree of display data.  May be NULL.
 *	int : current offset into packet data
 *	char * : format text
 *	subsequent args : arguments to format
 *
 * Output:
 *	void (may modify proto tree)
 */
static void
nlsp_dissect_unknown(tvbuff_t *tvb, proto_tree *tree, int offset,
	const char *fmat, ...)
{
	va_list	ap;

	va_start(ap, fmat);
	proto_tree_add_text_valist(tree, tvb, offset, -1, fmat, ap);
	va_end(ap);
}

/*
 * Name: nlsp_dissect_clvs()
 *
 * Description:
 *	Dispatch routine to shred all the CLVs in a packet.  We just
 *	walk through the clv entries in the packet.  For each one, we
 *	search the passed in valid clv's for this protocol (opts) for
 *	a matching code.  If found, we add to the display tree and
 *	then call the dissector.  If it is not, we just post an
 *	"unknown" clv entry using the passed in unknown clv tree id.
 *      XXX: The "unknown tree id" is an 'ett' index for use
 *           when creating a subtree;
 *           Since the 'unknown' subtree was not actually used in the
 *           code below, what was the intention for this ?
 *           For now: code related to creating an 'unknown' subtrree
 *            disabled.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	nlsp_clv_handle_t * : NULL dissector terminated array of codes
 *		and handlers (along with tree text and tree id's).
 *	int : length of CLV area.
 *	int : unknown clv tree id
 *
 * Output:
 *	void, but we will add to proto tree if !NULL.
 */
static void
nlsp_dissect_clvs(tvbuff_t *tvb, proto_tree *tree, int offset,
	const nlsp_clv_handle_t *opts, int len, int unknown_tree_id _U_)
{
	guint8 code;
	guint8 length;
	int q;
	proto_item	*ti;
	proto_tree	*clv_tree;

	while ( len > 0 ) {
		code = tvb_get_guint8(tvb, offset);
		offset += 1;
		len -= 1;
		if (len == 0)
			break;

		length = tvb_get_guint8(tvb, offset);
		offset += 1;
		len -= 1;
		if (len == 0)
			break;

		if ( len < length ) {
			nlsp_dissect_unknown(tvb, tree, offset,
				"Short CLV header (%d vs %d)",
				length, len );
			return;
		}
		q = 0;
		while ((opts[q].dissect != NULL )&&( opts[q].optcode != code )){
			q++;
		}
		if ( opts[q].dissect ) {
			if (tree) {
				/* adjust by 2 for code/len octets */
				ti = proto_tree_add_text(tree, tvb, offset - 2,
					length + 2, "%s (%u)",
					opts[q].tree_text, length );
				clv_tree = proto_item_add_subtree(ti,
					*opts[q].tree_id );
			} else {
				clv_tree = NULL;
			}
			opts[q].dissect(tvb, clv_tree, offset,
			    length);
		} else {
			if (tree) {
#if 0  /* XXX: ?? */
				ti = proto_tree_add_text(tree, tvb, offset - 2,
					length + 2, "Unknown code %u (%u)",
					code, length);
				clv_tree = proto_item_add_subtree(ti,
					unknown_tree_id );
			} else {
				clv_tree = NULL;
#else
				proto_tree_add_text(tree, tvb, offset - 2,
					length + 2, "Unknown code %u (%u)",
					code, length);
#endif
			}
		}
		offset += length;
		len -= length;
	}
}

/*
 * Name: dissect_area_address_clv()
 *
 * Description:
 *	Decode an area address clv.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_area_address_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	while (length > 0) {
		if (length < 4) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short area address entry");
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, 4,
			    "Area address network number: 0x%08x",
			    tvb_get_ntohl(tvb, offset));
		}
		offset += 4;
		length -= 4;

		if (length < 4) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short area address entry");
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, 4,
			    "Area address mask: 0x%08x",
			    tvb_get_ntohl(tvb, offset));
		}
		offset += 4;
		length -= 4;
	}
}

/*
 * Name: dissect_neighbor_clv()
 *
 * Description:
 *	Decode an neighbor clv.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_neighbor_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	while (length > 0) {
		if (length < 6) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short neighbor entry");
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, 6,
			    "Neighbor: %s",
			    tvb_ether_to_str(tvb, offset));
		}
		offset += 6;
		length -= 6;
	}
}

/*
 * Name: dissect_hello_local_mtu_clv()
 *
 * Description:
 *	Decode for a hello packet's local MTU clv.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_hello_local_mtu_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	if (length < 4) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short link info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 4,
		    "MTU Size: %u",
		    tvb_get_ntohl(tvb, offset));
	}
}

static const nlsp_clv_handle_t clv_hello_opts[] = {
	{
		0xC0,
		"Area address(es)",
		&ett_nlsp_hello_clv_area_addr,
		dissect_area_address_clv
	},
	{
		6,
		"Neighbors",
		&ett_nlsp_hello_clv_neighbors,
		dissect_neighbor_clv
	},
	{
		0xC5,
		"Local MTU",
		&ett_nlsp_hello_local_mtu,
		dissect_hello_local_mtu_clv
	},

	{
		0,
		"",
		NULL,
		NULL
	}
};

/*
 * Name: nlsp_dissect_nlsp_hello()
 *
 * Description:
 *	This procedure rips apart NLSP hellos.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *	int offset : our offset into packet data.
 *	int : hello type, a la NLSP_TYPE_* values
 *	int : header length of packet.
 *
 * Output:
 *	void, will modify proto_tree if not NULL.
 */
#define NLSP_HELLO_CTYPE_MASK		0x03
#define NLSP_HELLO_STATE_MASK		0xC0
#define NLSP_HELLO_MULTICAST_MASK	0x10

static const value_string nlsp_hello_state_vals[] = {
	{ 0, "Up" },
	{ 1, "Initializing" },
	{ 2, "Down" },
	{ 0, NULL }
};

#define NLSP_HELLO_TYPE_RESERVED	0
#define NLSP_HELLO_TYPE_LEVEL_1		1
#define NLSP_HELLO_TYPE_LEVEL_2		2
#define NLSP_HELLO_TYPE_LEVEL_12	3

static const value_string nlsp_hello_circuit_type_vals[] = {
	{ NLSP_HELLO_TYPE_RESERVED,	"Reserved 0 (discard PDU)"},
	{ NLSP_HELLO_TYPE_LEVEL_1,	"Level 1 only"},
	{ NLSP_HELLO_TYPE_LEVEL_2,	"Level 2 only"},
	{ NLSP_HELLO_TYPE_LEVEL_12,	"Level 1 and 2"},
	{ 0,		NULL}
};

#define NLSP_HELLO_PRIORITY_MASK	0x7f

static void
nlsp_dissect_nlsp_hello(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int hello_type, int header_length)
{
	guint16		packet_length;
	int 		len;
	guint16		holding_timer;

	if (tree) {
		if (hello_type == NLSP_TYPE_WAN_HELLO) {
			proto_tree_add_item(tree, hf_nlsp_hello_state, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
		} else {
			proto_tree_add_item(tree, hf_nlsp_hello_multicast, tvb,
			    offset, 1, ENC_BIG_ENDIAN);
		}
		proto_tree_add_item(tree, hf_nlsp_hello_circuit_type, tvb,
		    offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;

	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 6,
		    "Sending Router System ID: %s",
		    tvb_ether_to_str(tvb, offset));
	}
	col_append_fstr(pinfo->cinfo, COL_INFO, ", System ID: %s",
		    tvb_ether_to_str(tvb, offset));

	offset += 6;

	if (tree) {
		holding_timer = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint_format_value(tree, hf_nlsp_hello_holding_timer,
		    tvb, offset, 2, holding_timer,
		    "%us", holding_timer);
	}
	offset += 2;

	packet_length = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree_add_uint(tree, hf_nlsp_packet_length, tvb,
			offset, 2, packet_length);
	}
	offset += 2;

	if (tree) {
		proto_tree_add_item(tree, hf_nlsp_hello_priority, tvb,
		    offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;

	if (hello_type == NLSP_TYPE_WAN_HELLO) {
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Local WAN Circuit ID: %u",
			    tvb_get_guint8(tvb, offset));
		}
		offset += 1;
	} else {
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, 6,
			    "Designated Router System ID: %s",
			    tvb_ether_to_str(tvb, offset));
			proto_tree_add_text(tree, tvb, offset+6, 1,
			    "Designated Router Pseudonode ID: %u",
			    tvb_get_guint8(tvb, offset+6));
		}
		offset += 7;
	}

	len = packet_length - header_length;
	if (len < 0) {
		nlsp_dissect_unknown(tvb, tree, offset,
			"packet header length %d went beyond packet",
			header_length);
		return;
	}

	/*
	 * Now, we need to decode our CLVs.  We need to pass in
	 * our list of valid ones!
	 */
	nlsp_dissect_clvs(tvb, tree, offset,
	    clv_hello_opts, len, ett_nlsp_hello_clv_unknown);
}

/*
 * Name: dissect_lsp_mgt_info_clv()
 *
 * Description:
 *	Decode for a lsp packet's management information clv.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_mgt_info_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	guint8 name_length;

	if (length < 4) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short management info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 4,
		    "Network number: 0x%08x",
		    tvb_get_ntohl(tvb, offset));
	}
	offset += 4;
	length -= 4;

	if (length < 6) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short management info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 6,
		    "Node number: %s",
		    tvb_ether_to_str(tvb, offset));
	}
	offset += 6;
	length -= 6;

	if (length < 1) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short management info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "IPX version number: %u",
		    tvb_get_guint8(tvb, offset));
	}
	offset += 1;
	length -= 1;

	if (length < 1) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short management info entry");
		return;
	}
	name_length = tvb_get_guint8(tvb, offset);
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Name length: %u", name_length);
	}
	offset += 1;
	length -= 1;

	if (name_length != 0) {
		if (length < name_length) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short management info entry");
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, name_length,
			    "Name: %s",
			    tvb_format_text(tvb, offset, name_length));
		}
	}
}

/*
 * Name: dissect_lsp_link_info_clv()
 *
 * Description:
 *	Decode for a lsp packet's link information clv.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static const value_string media_type_vals[] = {
	{ 0x0000, "Generic LAN" },
	{ 0x8000, "Generic WAN" },
	{ 0x0001, "Localtalk" },
	{ 0x0002, "Ethernet II" },
	{ 0x0003, "IEEE 802.3 with IEEE 802.2 without SNAP" },
	{ 0x0005, "IEEE 802.3 with IPX header and no 802.2 header" },
	{ 0x000A, "IEEE 802.3 with IEEE 802.2 and SNAP" },
	{ 0x0004, "IEEE 802.5 with IEEE 802.2 without SNAP" },
	{ 0x000B, "IEEE 802.5 with IEEE 802.2 and SNAP" },
	{ 0x0006, "IEEE 802.4" },
	{ 0x0007, "IBM PC Network II" },
	{ 0x0008, "Gateway G/Net" },
	{ 0x0009, "Proteon ProNET" },
	{ 0x000C, "Racore LANPAC" },
	{ 0x800D, "ISDN" },
	{ 0x000E, "ARCnet" },
	{ 0x000F, "IBM PC Network II with 802.2 without SNAP" },
	{ 0x0010, "IBM PC Network II with 802.2 and SNAP" },
	{ 0x0011, "Corvus OmniNet at 4 Mbps" },
	{ 0x0012, "Harris Adacom" },
	{ 0x0013, "IP tunnel" },
	{ 0x8013, "IP Relay" },
	{ 0x0014, "FDDI with 802.2 without SNAP" },
	{ 0x0015, "Commtex IVDLAN" },
	{ 0x0016, "Dataco OSI" },
	{ 0x0017, "FDDI with 802.2 and SNAP" },
	{ 0x0018, "IBM SDLC tunnel" },
	{ 0x0019, "PC Office frame" },
	{ 0x001A, "Hypercommunications WAIDNET" },
	{ 0x801C, "PPP" },
	{ 0x801D, "Proxim RangeLAN" },
	{ 0x801E, "X.25" },
	{ 0x801F, "Frame Relay" },
	{ 0x0020, "Integrated Workstations BUS-NET" },
	{ 0x8021, "Novell SNA Links" },
	{ 0,      NULL }
};

static void
dissect_lsp_link_info_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	guint8 flags_cost;

	if (length < 1) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short link info entry");
		return;
	}
	if (tree) {
		flags_cost = tvb_get_guint8(tvb, offset);
		proto_tree_add_item(tree, hf_nlsp_lsp_link_info_clv_flags_cost_present, tvb, offset, 1, ENC_BIG_ENDIAN);
		if (!(flags_cost & 0x80)) {
			/*
			 * 0x80 clear => cost present.
			 */
			proto_tree_add_item(tree, hf_nlsp_lsp_link_info_clv_flags_cost_metric, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(tree, hf_nlsp_lsp_link_info_clv_flags_cost, tvb, offset, 1, ENC_BIG_ENDIAN);
		}
	}
	offset += 1;
	length -= 1;

	if (length < 3) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short link info entry");
		return;
	}
	offset += 3;	/* Reserved */
	length -= 3;

	if (length < 7) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short link info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 6,
		    "Router System ID: %s",
		    tvb_ether_to_str(tvb, offset));
		proto_tree_add_text(tree, tvb, offset+6, 1,
		    "Router Pseudonode ID: %u",
		    tvb_get_guint8(tvb, offset+6));
	}
	offset += 7;
	length -= 7;

	if (length < 4) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short link info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 4,
		    "MTU Size: %u",
		    tvb_get_ntohl(tvb, offset));
	}
	offset += 4;
	length -= 4;

	if (length < 4) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short link info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 4,
		    "Delay: %uus",
		    tvb_get_ntohl(tvb, offset));
	}
	offset += 4;
	length -= 4;

	if (length < 4) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short link info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 4,
		    "Throughput: %u bits/s",
		    tvb_get_ntohl(tvb, offset));
	}
	offset += 4;
	length -= 4;

	if (length < 2) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short link info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 2,
		    "Media type: %s",
		    val_to_str(tvb_get_ntohs(tvb, offset), media_type_vals,
			"Unknown (0x%04x)"));
	}
}

/*
 * Name: dissect_lsp_svcs_info_clv()
 *
 * Description:
 *	Decode for a lsp packet's services information clv.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_svcs_info_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	if (length < 1) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short services info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 1,
		    "Hops to reach the service: %u",
		    tvb_get_guint8(tvb, offset));
	}
	offset += 1;
	length -= 1;

	if (length < 4) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short services info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 4,
		    "Network number: 0x%08x",
		    tvb_get_ntohl(tvb, offset));
	}
	offset += 4;
	length -= 4;

	if (length < 6) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short services info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 6,
		    "Node number: %s",
		    tvb_ether_to_str(tvb, offset));
	}
	offset += 6;
	length -= 6;

	if (length < 2) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short services info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 2,
		    "Socket: %s",
		    val_to_str_ext(tvb_get_ntohs(tvb, offset), &ipx_socket_vals_ext,
			"Unknown (0x%04x)"));
	}
	offset += 2;
	length -= 2;

	if (length < 2) {
		nlsp_dissect_unknown(tvb, tree, offset,
		    "Short services info entry");
		return;
	}
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 2,
		    "Type: %s",
		    val_to_str_ext(tvb_get_ntohs(tvb, offset), &novell_server_vals_ext,
			"Unknown (0x%04x)"));
	}
	offset += 2;
	length -= 2;

	if (length > 0) {
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, length,
			    "Service Name: %s",
			    tvb_format_text(tvb, offset, length));
		}
	}
}


/*
 * Name: dissect_lsp_ext_routes_clv()
 *
 * Description:
 *	Decode for a lsp packet's external routes clv.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of clv we are decoding
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_lsp_ext_routes_clv(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	while (length > 0) {
		if (length < 1) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short external routes entry");
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, 1,
			    "Hops: %u",
			    tvb_get_guint8(tvb, offset));
		}
		offset += 1;
		length -= 1;

		if (length < 4) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short external routes entry");
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, 4,
			    "Network number: 0x%08x",
			    tvb_get_ntohl(tvb, offset));
		}
		offset += 4;
		length -= 4;

		if (length < 2) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short external routes entry");
			return;
		}
		if (tree) {
			proto_tree_add_text(tree, tvb, offset, 2,
			    "RIP delay: %u ticks",
			    tvb_get_ntohs(tvb, offset));
		}
		offset += 2;
		length -= 2;
	}
}

static const nlsp_clv_handle_t clv_l1_lsp_opts[] = {
	{
		0xC0,
		"Area address(es)",
		&ett_nlsp_lsp_clv_area_addr,
		dissect_area_address_clv
	},
	{
		0xC1,
		"Management information",
		&ett_nlsp_lsp_clv_mgt_info,
		dissect_lsp_mgt_info_clv
	},
	{
		0xC2,
		"Link information",
		&ett_nlsp_lsp_clv_link_info,
		dissect_lsp_link_info_clv
	},
	{
		0xC3,
		"Services information",
		&ett_nlsp_lsp_clv_svcs_info,
		dissect_lsp_svcs_info_clv
	},
	{
		0xC4,
		"External routes",
		&ett_nlsp_lsp_clv_ext_routes,
		dissect_lsp_ext_routes_clv
	},

	{
		0,
		"",
		NULL,
		NULL
	}
};

/*
 * Name: nlsp_dissect_nlsp_lsp()
 *
 * Description:
 *	Print out the LSP part of the main header and then call the CLV
 *	de-mangler with the right list of valid CLVs.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *	int offset : our offset into packet data.
 *	int : header length of packet.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
/* P | ATT | OVERFLOW | ROUTER TYPE FIELD description */
#define NLSP_LSP_PARTITION_MASK     0x80
#define NLSP_LSP_PARTITION_SHIFT    7
#define NLSP_LSP_PARTITION(info)    (((info) & NLSP_LSP_PARTITION_MASK) >> NLSP_LSP_PARTITION_SHIFT)

#define NLSP_LSP_ATT_MASK     0x78
#define NLSP_LSP_ATT_SHIFT    3
#define NLSP_LSP_ATT(info)    (((info) & NLSP_LSP_ATT_MASK) >> NLSP_LSP_ATT_SHIFT)

#define NLSP_LSP_OVERFLOW_MASK     0x04
#define NLSP_LSP_OVERFLOW_SHIFT    2
#define NLSP_LSP_OVERFLOW(info)    (((info) & NLSP_LSP_OVERFLOW_MASK) >> NLSP_LSP_OVERFLOW_SHIFT)

#define NLSP_LSP_ROUTER_TYPE_MASK     0x03
#define NLSP_LSP_ROUTER_TYPE(info)    ((info) & NLSP_LSP_ROUTER_TYPE_MASK)

static void
nlsp_dissect_nlsp_lsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int header_length)
{
	guint16		packet_length;
	guint16		remaining_lifetime;
	guint32		sequence_number;
	int		len;

	packet_length = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree_add_uint(tree, hf_nlsp_packet_length, tvb,
			offset, 2, packet_length);
	}
	offset += 2;

	remaining_lifetime = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree_add_text(tree, tvb, offset, 2,
				    "Remaining Lifetime: %us",
				    remaining_lifetime);
	}
	offset += 2;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", LSP ID: %s",
		    tvb_ether_to_str(tvb, offset));

	proto_tree_add_text(tree, tvb, offset, 6,
		    "LSP ID system ID: %s",
		    tvb_ether_to_str(tvb, offset));

	offset += 6;
	/* XXX - append the pseudonode ID */
	proto_tree_add_text(tree, tvb, offset, 1,
		    "LSP ID pseudonode ID: %u",
		    tvb_get_guint8(tvb, offset));

	offset += 1;
	proto_tree_add_text(tree, tvb, offset, 1,
		    "LSP ID LSP number: %u",
		    tvb_get_guint8(tvb, offset));
	offset += 1;

	sequence_number = tvb_get_ntohl(tvb, offset);
	col_append_fstr(pinfo->cinfo, COL_INFO,
		    ", Sequence: 0x%08x, Lifetime: %us",
		    sequence_number, remaining_lifetime);

	proto_tree_add_uint(tree, hf_nlsp_lsp_sequence_number, tvb,
			offset, 4, sequence_number);
	offset += 4;

	/* XXX -> we could validate the cksum here! */
	proto_tree_add_item(tree, hf_nlsp_lsp_checksum, tvb,
		offset, 2, ENC_BIG_ENDIAN );

	offset += 2;

	if (tree) {
		proto_tree_add_item(tree, hf_nlsp_lsp_p, tvb,
		    offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_nlsp_lsp_attached_flag, tvb,
		    offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_nlsp_lsp_lspdbol, tvb,
		    offset, 1, ENC_BIG_ENDIAN);
		proto_tree_add_item(tree, hf_nlsp_lsp_router_type, tvb,
		    offset, 1, ENC_BIG_ENDIAN);
	}
	offset += 1;

	len = packet_length - header_length;
	if (len < 0) {
		nlsp_dissect_unknown(tvb, tree, offset,
			"packet header length %d went beyond packet",
			 header_length);
		return;
	}

	/*
	 * Now, we need to decode our CLVs.  We need to pass in
	 * our list of valid ones!
	 */
	nlsp_dissect_clvs(tvb, tree, offset,
		clv_l1_lsp_opts, len, ett_nlsp_lsp_clv_unknown);
}

/*
 * Name: dissect_snp_lsp_entries()
 *
 * Description:
 *	All the snp packets use a common payload format.  We have up
 *	to n entries (based on length), which are made of:
 *		2 : remaining life time
 *		8 : lsp id
 *		4 : sequence number
 *		2 : checksum
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to fill out.  May be NULL
 *	int : offset into packet data where we are.
 *	int : length of payload to decode.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
dissect_csnp_lsp_entries(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	proto_tree *subtree,*ti;

	while (length > 0) {
		if (length < 16) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short CSNP header entry");
			return;
		}

		ti = proto_tree_add_text(tree, tvb, offset, 16,
		    "LSP-ID: %s, Sequence: 0x%08x, Lifetime: %5us, Checksum: 0x%04x",
		    tvb_ether_to_str(tvb, offset+2), /* XXX - rest of system ID */
		    tvb_get_ntohl(tvb, offset+10),
		    tvb_get_ntohs(tvb, offset),
		    tvb_get_ntohs(tvb, offset+14));

		subtree = proto_item_add_subtree(ti, ett_nlsp_csnp_lsp_entry);

		proto_tree_add_text(subtree, tvb, offset+2, 6,
		    "LSP ID source ID: %s",
		    tvb_ether_to_str(tvb, offset+2));
		proto_tree_add_text(subtree, tvb, offset+8, 1,
		    "LSP ID pseudonode ID: %u",
		    tvb_get_guint8(tvb, offset+8));
		proto_tree_add_text(subtree, tvb, offset+9, 1,
		    "LSP ID LSP number: %u",
		    tvb_get_guint8(tvb, offset+9));

		proto_tree_add_text(subtree, tvb, offset+10, 4,
			"LSP Sequence Number: 0x%08x",
			tvb_get_ntohl(tvb, offset+10));

		proto_tree_add_text(subtree, tvb, offset, 2,
			"Remaining Lifetime: %us",
			tvb_get_ntohs(tvb, offset));

		proto_tree_add_text(subtree, tvb, offset+14, 2,
			"LSP checksum: 0x%04x",
			tvb_get_ntohs(tvb, offset+14));

		length -= 16;
		offset += 16;
	}
}

static void
dissect_psnp_lsp_entries(tvbuff_t *tvb, proto_tree *tree, int offset,
    int length)
{
	proto_tree *subtree,*ti;

	while (length > 0) {
		if (length < 16) {
			nlsp_dissect_unknown(tvb, tree, offset,
			    "Short PSNP header entry");
			return;
		}

		ti = proto_tree_add_text(tree, tvb, offset, 16,
		    "LSP-ID: %s, Sequence: 0x%08x, Lifetime: %5us, Checksum: 0x%04x",
		    tvb_ether_to_str(tvb, offset+2), /* XXX - rest of system ID */
		    tvb_get_ntohl(tvb, offset+10),
		    tvb_get_ntohs(tvb, offset),
		    tvb_get_ntohs(tvb, offset+14));

		subtree = proto_item_add_subtree(ti, ett_nlsp_psnp_lsp_entry);

		proto_tree_add_text(subtree, tvb, offset+2, 6,
		    "LSP ID source ID: %s",
		    tvb_ether_to_str(tvb, offset+2));
		proto_tree_add_text(subtree, tvb, offset+8, 1,
		    "LSP ID pseudonode ID: %u",
		    tvb_get_guint8(tvb, offset+8));
		proto_tree_add_text(subtree, tvb, offset+9, 1,
		    "LSP ID LSP number: %u",
		    tvb_get_guint8(tvb, offset+9));

		proto_tree_add_text(subtree, tvb, offset+10, 4,
			"LSP Sequence Number: 0x%08x",
			tvb_get_ntohl(tvb, offset+10));

		proto_tree_add_text(subtree, tvb, offset, 2,
			"Remaining Lifetime: %us",
			tvb_get_ntohs(tvb, offset));

		proto_tree_add_text(subtree, tvb, offset+14, 2,
			"LSP checksum: 0x%04x",
			tvb_get_ntohs(tvb, offset+14));

		length -= 16;
		offset += 16;
	}
}

static const nlsp_clv_handle_t clv_l1_csnp_opts[] = {
	{
		9,
		"LSP entries",
		&ett_nlsp_csnp_lsp_entries,
		dissect_csnp_lsp_entries
	},

	{
		0,
		"",
		NULL,
		NULL
	}
};

/*
 * Name: nlsp_dissect_nlsp_csnp()
 *
 * Description:
 *	Tear apart a L1 CSNP header and then call into payload dissect
 *	to pull apart the lsp id payload.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *	int offset : our offset into packet data.
 *	int : header length of packet.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
nlsp_dissect_nlsp_csnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int header_length)
{
	guint16		packet_length;
	int 		len;

	packet_length = tvb_get_ntohs(tvb, offset);
	if (tree) {
		proto_tree_add_uint(tree, hf_nlsp_packet_length, tvb,
			offset, 2, packet_length);
	}
	offset += 2;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", Source ID: %s",
		    tvb_ether_to_str(tvb, offset));
	proto_tree_add_text(tree, tvb, offset, 6,
		    "Source ID system ID: %s",
		    tvb_ether_to_str(tvb, offset));
	offset += 6;
	/* XXX - add the pseudonode ID */
	proto_tree_add_text(tree, tvb, offset, 1,
		    "Source ID pseudonode ID: %u",
		    tvb_get_guint8(tvb, offset));
	offset += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", Start LSP ID: %s",
		    tvb_ether_to_str(tvb, offset));
	proto_tree_add_text(tree, tvb, offset, 6,
		    "Start LSP ID source ID: %s",
		    tvb_ether_to_str(tvb, offset));
	offset += 6;
	/* XXX - append the pseudonode ID */
	proto_tree_add_text(tree, tvb, offset, 1,
		    "Start LSP ID pseudonode ID: %u",
		    tvb_get_guint8(tvb, offset));
	offset += 1;

	proto_tree_add_text(tree, tvb, offset, 1,
		    "Start LSP ID LSP number: %u",
		    tvb_get_guint8(tvb, offset));
	offset += 1;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", End LSP ID: %s",
		    tvb_ether_to_str(tvb, offset));
	proto_tree_add_text(tree, tvb, offset, 6,
		    "End LSP ID source ID: %s",
		    tvb_ether_to_str(tvb, offset));
	offset += 6;
	/* XXX - append the pseudonode ID */
	proto_tree_add_text(tree, tvb, offset, 1,
		    "End LSP ID pseudonode ID: %u",
		    tvb_get_guint8(tvb, offset));
	offset += 1;
	proto_tree_add_text(tree, tvb, offset, 1,
		    "End LSP ID LSP number: %u",
		    tvb_get_guint8(tvb, offset));
	offset += 1;

	len = packet_length - header_length;
	if (len < 0) {
		return;
	}
	/* Call into payload dissector */
	nlsp_dissect_clvs(tvb, tree, offset,
	    clv_l1_csnp_opts, len, ett_nlsp_csnp_clv_unknown);
}

static const nlsp_clv_handle_t clv_l1_psnp_opts[] = {
	{
		9,
		"LSP entries",
		&ett_nlsp_psnp_lsp_entries,
		dissect_psnp_lsp_entries
	},

	{
		0,
		"",
		NULL,
		NULL
	}
};

/*
 * Name: nlsp_dissect_nlsp_psnp()
 *
 * Description:
 *	Tear apart a L1 PSNP header and then call into payload dissect
 *	to pull apart the lsp id payload.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	proto_tree * : protocol display tree to add to.  May be NULL.
 *	int offset : our offset into packet data.
 *	int : header length of packet.
 *
 * Output:
 *      void, but we will add to proto tree if !NULL.
 */
static void
nlsp_dissect_nlsp_psnp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    int offset, int header_length)
{
	guint16		packet_length;
	int 		len;

	packet_length = tvb_get_ntohs(tvb, offset);
	proto_tree_add_uint(tree, hf_nlsp_packet_length, tvb,
			offset, 2, packet_length);
	offset += 2;

	col_append_fstr(pinfo->cinfo, COL_INFO, ", Source ID: %s",
		    tvb_ether_to_str(tvb, offset));
	proto_tree_add_text(tree, tvb, offset, 6,
		    "Source ID system ID: %s",
		    tvb_ether_to_str(tvb, offset));
	offset += 6;
	/* XXX - add the pseudonode ID */
	proto_tree_add_text(tree, tvb, offset, 1,
		    "Source ID pseudonode ID: %u",
		    tvb_get_guint8(tvb, offset));
	offset += 1;

	len = packet_length - header_length;
	if (len < 0) {
		return;
	}
	/* Call into payload dissector */
	nlsp_dissect_clvs(tvb, tree, offset,
	    clv_l1_psnp_opts, len, ett_nlsp_psnp_clv_unknown);
}

/*
 * Name: dissect_nlsp()
 *
 * Description:
 *	Main entry area for nlsp de-mangling.  This will build the
 *	main nlsp tree data and call the sub-protocols as needed.
 *
 * Input:
 *	tvbuff_t * : tvbuffer for packet data
 *	packet_info * : info for current packet
 *	proto_tree * : tree of display data.  May be NULL.
 *
 * Output:
 *	void, but we will add to the proto_tree if it is not NULL.
 */
static void
dissect_nlsp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti;
	proto_tree *nlsp_tree;
	int offset = 0;
	guint8 nlsp_major_version;
	guint8 nlsp_header_length;
	guint8 packet_type_flags;
	guint8 packet_type;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "NLSP");
	col_clear(pinfo->cinfo, COL_INFO);

	nlsp_major_version = tvb_get_guint8(tvb, 5);
	if (nlsp_major_version != 1){
		col_add_fstr(pinfo->cinfo, COL_INFO,
				"Unknown NLSP version (%u vs 1)",
				nlsp_major_version);

		nlsp_dissect_unknown(tvb, tree, 0,
			"Unknown NLSP version (%d vs 1)",
			nlsp_major_version, 1);
		return;
	}

	ti = proto_tree_add_item(tree, proto_nlsp, tvb, 0, -1, ENC_NA);
	nlsp_tree = proto_item_add_subtree(ti, ett_nlsp);

	proto_tree_add_item(nlsp_tree, hf_nlsp_irpd, tvb, offset, 1,
			ENC_BIG_ENDIAN );
	offset += 1;

	nlsp_header_length = tvb_get_guint8(tvb, 1);
	proto_tree_add_uint(nlsp_tree, hf_nlsp_header_length, tvb,
			offset, 1, nlsp_header_length );
	offset += 1;

	proto_tree_add_item(nlsp_tree, hf_nlsp_minor_version, tvb,
			offset, 1, ENC_BIG_ENDIAN );
	offset += 1;

	offset += 1;	/* Reserved */

	packet_type_flags = tvb_get_guint8(tvb, offset);
	packet_type = packet_type_flags & PACKET_TYPE_MASK;
	col_add_str(pinfo->cinfo, COL_INFO,
		    val_to_str(packet_type, nlsp_packet_type_vals, "Unknown (%u)"));
	if (packet_type == NLSP_TYPE_L1_LSP) {
		proto_tree_add_boolean(nlsp_tree, hf_nlsp_nr, tvb, offset, 1,
			    packet_type_flags );
	}
	proto_tree_add_uint(nlsp_tree, hf_nlsp_type, tvb, offset, 1,
		    packet_type_flags );
	offset += 1;

	proto_tree_add_item(nlsp_tree, hf_nlsp_major_version, tvb,
			offset, 1, ENC_BIG_ENDIAN );
	offset += 1;

	offset += 2;	/* Reserved */

	switch (packet_type) {

	case NLSP_TYPE_L1_HELLO:
	case NLSP_TYPE_WAN_HELLO:
		nlsp_dissect_nlsp_hello(tvb, pinfo, nlsp_tree, offset,
		    packet_type, nlsp_header_length);
		break;

	case NLSP_TYPE_L1_LSP:
		nlsp_dissect_nlsp_lsp(tvb, pinfo, nlsp_tree, offset,
		    nlsp_header_length);
		break;

	case NLSP_TYPE_L1_CSNP:
		nlsp_dissect_nlsp_csnp(tvb, pinfo, nlsp_tree, offset,
		    nlsp_header_length);
		break;

	case NLSP_TYPE_L1_PSNP:
		nlsp_dissect_nlsp_psnp(tvb, pinfo, nlsp_tree, offset,
		    nlsp_header_length);
		break;

	default:
		nlsp_dissect_unknown(tvb, tree, offset,
			"Unknown NLSP packet type");
	}
}

/*
 * Name: proto_register_nlsp()
 *
 * Description:
 *	main register for NLSP protocol set.  We register some display
 *	formats and the protocol module variables.
 *
 * 	NOTE: this procedure to autolinked by the makefile process that
 *	builds register.c
 *
 * Input:
 *	void
 *
 * Output:
 *	void
 */
void
proto_register_nlsp(void)
{
	static hf_register_info hf[] = {
	    { &hf_nlsp_irpd,
	      { "NetWare Link Services Protocol Discriminator",	"nlsp.irpd",
		FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_nlsp_header_length,
	      { "PDU Header Length", "nlsp.header_length",
	        FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_nlsp_minor_version,
	      { "Minor Version", "nlsp.minor_version", FT_UINT8,
	         BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_nlsp_nr,
	      { "Multi-homed Non-routing Server", "nlsp.nr", FT_BOOLEAN, 8,
	        NULL, 0x80, NULL, HFILL }},

	    { &hf_nlsp_type,
	      { "Packet Type", "nlsp.type", FT_UINT8, BASE_DEC,
	        VALS(nlsp_packet_type_vals), PACKET_TYPE_MASK, NULL, HFILL }},

	    { &hf_nlsp_major_version,
	      { "Major Version", "nlsp.major_version", FT_UINT8,
	         BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_nlsp_packet_length,
	      { "Packet Length", "nlsp.packet_length",
	        FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }},

	    { &hf_nlsp_hello_state,
	      { "State", "nlsp.hello.state", FT_UINT8, BASE_DEC,
	        VALS(nlsp_hello_state_vals), NLSP_HELLO_STATE_MASK,
		NULL, HFILL }},

	    { &hf_nlsp_hello_multicast,
	      { "Multicast Routing", "nlsp.hello.multicast", FT_BOOLEAN, 8,
	        TFS(&tfs_supported_not_supported), NLSP_HELLO_MULTICAST_MASK,
		"If set, this router supports multicast routing", HFILL }},

	    { &hf_nlsp_hello_circuit_type,
	      { "Circuit Type", "nlsp.hello.circuit_type", FT_UINT8, BASE_DEC,
	        VALS(nlsp_hello_circuit_type_vals), NLSP_HELLO_CTYPE_MASK,
		NULL, HFILL }},

	    { &hf_nlsp_hello_holding_timer,
	      { "Holding Timer", "nlsp.hello.holding_timer", FT_UINT8, BASE_DEC,
	        NULL, 0x0, NULL, HFILL }},

	    { &hf_nlsp_hello_priority,
	      { "Priority", "nlsp.hello.priority", FT_UINT8, BASE_DEC,
	        NULL, NLSP_HELLO_PRIORITY_MASK,
		NULL, HFILL }},

	    { &hf_nlsp_lsp_sequence_number,
	      { "Sequence Number", "nlsp.sequence_number",
	        FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_nlsp_lsp_checksum,
	      { "Checksum", "nlsp.lsp.checksum",
	        FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }},

	    { &hf_nlsp_lsp_p,
	      { "Partition Repair", "nlsp.lsp.partition_repair", FT_BOOLEAN, 8,
	        TFS(&tfs_supported_not_supported), NLSP_LSP_PARTITION_MASK,
		"If set, this router supports the optional Partition Repair function", HFILL }},

	    { &hf_nlsp_lsp_attached_flag,
	      { "Attached Flag", "nlsp.lsp.attached_flag", FT_UINT8, BASE_DEC,
	        VALS(nlsp_attached_flag_vals), NLSP_LSP_ATT_MASK, NULL, HFILL }},

	    { &hf_nlsp_lsp_lspdbol,
	      { "LSP Database Overloaded", "nlsp.lsp.lspdbol", FT_BOOLEAN, 8,
	        NULL, NLSP_LSP_OVERFLOW_MASK, NULL, HFILL }},

	    { &hf_nlsp_lsp_router_type,
	      { "Router Type", "nlsp.lsp.router_type", FT_UINT8, BASE_DEC,
	        VALS(nlsp_router_type_vals), NLSP_LSP_ROUTER_TYPE_MASK,
	        NULL, HFILL }},

	    { &hf_nlsp_lsp_link_info_clv_flags_cost_present,
	      { "Cost present", "nlsp.lsp.link_info_clv.flags.cost_present", FT_BOOLEAN, 8,
	        TFS(&tfs_no_yes), 0x80, NULL, HFILL }},

	    { &hf_nlsp_lsp_link_info_clv_flags_cost_metric,
	      { "Cost metric", "nlsp.lsp.link_info_clv.flags.cost_metric", FT_BOOLEAN, 8,
	        TFS(&tfs_internal_external), 0x40, NULL, HFILL }},

	    { &hf_nlsp_lsp_link_info_clv_flags_cost,
	      { "Cost", "nlsp.lsp.link_info_clv.flags.cost", FT_UINT8, BASE_DEC,
	        NULL, 0x3F, NULL, HFILL }},
	};
	static gint *ett[] = {
		&ett_nlsp,
		&ett_nlsp_hello_clv_area_addr,
		&ett_nlsp_hello_clv_neighbors,
		&ett_nlsp_hello_local_mtu,
		&ett_nlsp_hello_clv_unknown,
		&ett_nlsp_lsp_info,
		&ett_nlsp_lsp_clv_area_addr,
		&ett_nlsp_lsp_clv_mgt_info,
		&ett_nlsp_lsp_clv_link_info,
		&ett_nlsp_lsp_clv_svcs_info,
		&ett_nlsp_lsp_clv_ext_routes,
		&ett_nlsp_lsp_clv_unknown,
		&ett_nlsp_csnp_lsp_entries,
		&ett_nlsp_csnp_lsp_entry,
		&ett_nlsp_csnp_clv_unknown,
		&ett_nlsp_psnp_lsp_entries,
		&ett_nlsp_psnp_lsp_entry,
		&ett_nlsp_psnp_clv_unknown,
	};

	proto_nlsp = proto_register_protocol("NetWare Link Services Protocol",
	    "NLSP", "nlsp");
	proto_register_field_array(proto_nlsp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_nlsp(void)
{
	dissector_handle_t nlsp_handle;

	nlsp_handle = create_dissector_handle(dissect_nlsp, proto_nlsp);
	dissector_add_uint("ipx.socket", IPX_SOCKET_NLSP, nlsp_handle);
}
