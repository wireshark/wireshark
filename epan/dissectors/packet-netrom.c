/* packet-netrom.c
 *
 * Routines for Amateur Packet Radio protocol dissection
 * NET/ROM inter-node frames.
 * Copyright 2005,2006,2007,2008,2009,2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
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

/*
 * Information on the protocol drawn from:
 *
 * Protocol specification is at:
 *
 *    ftp://ftp.ucsd.edu/hamradio/packet/tcpip/docs/netrom.ps.gz
 *
 * (yes, it's PostScript, and, yes, it's an FTP URL).
 *
 * Inspiration on how to build the dissector drawn from
 *   packet-sdlc.c
 *   packet-x25.c
 *   packet-lapb.c
 *   paket-gprs-llc.c
 *   xdlc.c
 * with the base file built from README.developers.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/to_str.h>
#include <epan/capture_dissectors.h>
#include <epan/ax25_pids.h>

void proto_register_netrom(void);
void proto_reg_handoff_netrom(void);

#define STRLEN 80

#define NETROM_MIN_SIZE		   7	/* minimum payload for a routing packet */
#define NETROM_HEADER_SIZE	  20	/* minimum payload for a normal packet */

#define	NETROM_PROTOEXT		0x00
#define	NETROM_CONNREQ		0x01
#define	NETROM_CONNACK		0x02
#define	NETROM_DISCREQ		0x03
#define	NETROM_DISCACK		0x04
#define	NETROM_INFO		0x05
#define	NETROM_INFOACK		0x06

#define	NETROM_MORE_FLAG	0x20
#define	NETROM_NAK_FLAG		0x40
#define	NETROM_CHOKE_FLAG	0x80

#define NETROM_PROTO_IP		0x0C

/* Dissector handles */
static dissector_handle_t ip_handle;

/* Initialize the protocol and registered fields */
static int proto_netrom			= -1;
static int hf_netrom_src		= -1;
static int hf_netrom_dst		= -1;
static int hf_netrom_ttl		= -1;
static int hf_netrom_my_cct_index	= -1;
static int hf_netrom_my_cct_id		= -1;
static int hf_netrom_your_cct_index	= -1;
static int hf_netrom_your_cct_id	= -1;
static int hf_netrom_n_r		= -1;
static int hf_netrom_n_s		= -1;
static int hf_netrom_type		= -1;
static int hf_netrom_op			= -1;
static int hf_netrom_more		= -1;
static int hf_netrom_nak		= -1;
static int hf_netrom_choke		= -1;

static int hf_netrom_user		= -1;
static int hf_netrom_node		= -1;
static int hf_netrom_pwindow		= -1;
static int hf_netrom_awindow		= -1;

static int hf_netrom_mnemonic		= -1;

/*
 * Structure containing pointers to hf_ values for various subfields of
 * the type field.
 */
typedef struct {
	int	*hf_tf_op;
	int	*hf_tf_more;
	int	*hf_tf_nak;
	int	*hf_tf_choke;
} netrom_tf_items;

static const netrom_tf_items netrom_type_items = {
	&hf_netrom_op,
	&hf_netrom_more,
	&hf_netrom_nak,
	&hf_netrom_choke
};


const value_string op_code_vals_abbrev[] = {
	{ NETROM_PROTOEXT	, "PROTOEXT"},
	{ NETROM_CONNREQ	, "CONNREQ"},
	{ NETROM_CONNACK	, "CONNACK"},
	{ NETROM_DISCREQ	, "DISCREQ"},
	{ NETROM_DISCACK	, "DISCACK"},
	{ NETROM_INFO		, "INFO"},
	{ NETROM_INFOACK	, "INFOACK"},
	{ 0			, NULL}
};

const value_string op_code_vals_text[] = {
	{ NETROM_PROTOEXT	, "Protocol extension"},
	{ NETROM_CONNREQ	, "Connect request"},
	{ NETROM_CONNACK	, "Connect acknowledge"},
	{ NETROM_DISCREQ	, "Disconnect request"},
	{ NETROM_DISCACK	, "Disconnect acknowledge"},
	{ NETROM_INFO		, "Information"},
	{ NETROM_INFOACK	, "Information acknowledge"},
	{ 0			, NULL}
};

/* Initialize the subtree pointers */
static gint ett_netrom      = -1;
static gint ett_netrom_type = -1;

static void
dissect_netrom_type(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree,
			int hf_netrom_type_param, gint ett_netrom_type_param, const netrom_tf_items *type_items )
{
	proto_tree *tc;
	proto_tree *type_tree;
	char       *info_buffer;
	guint8      type;
	guint8      op_code;

	type    =  tvb_get_guint8( tvb, offset );
	op_code = type &0x0f;

	info_buffer = wmem_strdup_printf( wmem_packet_scope(), "%s%s%s%s (0x%02x)",
					val_to_str_const( op_code, op_code_vals_text, "Unknown" ),
					( type & NETROM_MORE_FLAG  ) ? ", More"  : "",
					( type & NETROM_NAK_FLAG   ) ? ", NAK"   : "",
					( type & NETROM_CHOKE_FLAG ) ? ", Choke" : "",
					type );
	col_add_str( pinfo->cinfo, COL_INFO, info_buffer );

	if ( tree )
		{
		tc = proto_tree_add_uint_format( tree,
						hf_netrom_type_param,
						tvb,
						offset,
						1,
						type,
						"Type field: %s",
						info_buffer
						);
		type_tree = proto_item_add_subtree( tc, ett_netrom_type_param );

		proto_tree_add_item( type_tree, *type_items->hf_tf_op, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( type_tree, *type_items->hf_tf_choke, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( type_tree, *type_items->hf_tf_nak, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_item( type_tree, *type_items->hf_tf_more, tvb, offset, 1, ENC_BIG_ENDIAN );
		}
}

static void
dissect_netrom_proto(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item   *ti;
	proto_tree   *netrom_tree;
	int           offset;
#if 0
	guint8        src_ssid;
	guint8        dst_ssid;
#endif
	guint8        op_code;
	guint8        cct_index;
	guint8        cct_id;
	tvbuff_t     *next_tvb;

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "NET/ROM" );
	col_clear( pinfo->cinfo, COL_INFO );

	offset = 0;

	/* source */
	set_address_tvb(&pinfo->dl_src,	AT_AX25, AX25_ADDR_LEN, tvb, offset);
	set_address_tvb(&pinfo->src,	AT_AX25, AX25_ADDR_LEN, tvb, offset);
	/* src_ssid = tvb_get_guint8(tvb, offset+6); */
	offset += AX25_ADDR_LEN; /* step over src addr */

	/* destination */
	set_address_tvb(&pinfo->dl_dst,	AT_AX25, AX25_ADDR_LEN, tvb, offset);
	set_address_tvb(&pinfo->dst,	AT_AX25, AX25_ADDR_LEN, tvb, offset);
	/* dst_ssid = tvb_get_guint8(tvb, offset+6); */
	offset += AX25_ADDR_LEN; /* step over dst addr */

	offset += 1; /* step over ttl */
	cct_index =  tvb_get_guint8( tvb, offset );
	offset += 1; /* step over cct index*/
	cct_id =  tvb_get_guint8( tvb, offset );
	offset += 1; /* step over cct id */
	offset += 1; /* step over n_s */
	offset += 1; /* step over n_r */

	/* frame type */
	op_code =  tvb_get_guint8( tvb, offset ) & 0x0f;
	/*offset += 1;*/ /* step over op_code */

	col_add_fstr( pinfo->cinfo, COL_INFO, "%s", val_to_str_const( op_code, op_code_vals_text, "Unknown" ));

	/* if ( tree ) */
		{
		/* create display subtree for the protocol */

		ti = proto_tree_add_protocol_format( tree, proto_netrom, tvb, 0, NETROM_HEADER_SIZE,
			"NET/ROM, Src: %s, Dst: %s",
			address_to_str(wmem_packet_scope(), &pinfo->src),
			address_to_str(wmem_packet_scope(), &pinfo->dst));

		netrom_tree = proto_item_add_subtree( ti, ett_netrom );

		offset = 0;

		/* source */
		proto_tree_add_item( netrom_tree, hf_netrom_src, tvb, offset, AX25_ADDR_LEN, ENC_NA );
		offset += AX25_ADDR_LEN;

		/* destination */
		proto_tree_add_item( netrom_tree, hf_netrom_dst, tvb, offset, AX25_ADDR_LEN, ENC_NA );
		offset += AX25_ADDR_LEN;

		/* ttl */
		proto_tree_add_item( netrom_tree, hf_netrom_ttl, tvb, offset, 1, ENC_BIG_ENDIAN );
		offset += 1;

		switch ( op_code )
			{
			case NETROM_PROTOEXT	:
						/* cct index */
						proto_tree_add_item( netrom_tree, hf_netrom_my_cct_index, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* cct id */
						proto_tree_add_item( netrom_tree, hf_netrom_my_cct_id, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* unused */
						offset += 1;

						/* unused */
						offset += 1;
						break;
			case NETROM_CONNREQ	:
						/* cct index */
						proto_tree_add_item( netrom_tree, hf_netrom_my_cct_index, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* cct id */
						proto_tree_add_item( netrom_tree, hf_netrom_my_cct_id, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* unused */
						offset += 1;

						/* unused */
						offset += 1;

						break;
			case NETROM_CONNACK	:
						/* your cct index */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_index, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* your cct id */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_id, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* my cct index */
						proto_tree_add_item( netrom_tree, hf_netrom_my_cct_index, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* my cct id */
						proto_tree_add_item( netrom_tree, hf_netrom_my_cct_id, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						break;
			case NETROM_DISCREQ	:
						/* your cct index */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_index, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* your cct id */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_id, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* unused */
						offset += 1;

						/* unused */
						offset += 1;

						break;
			case NETROM_DISCACK	:
						/* your cct index */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_index, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* your cct id */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_id, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* unused */
						offset += 1;

						/* unused */
						offset += 1;

						break;
			case NETROM_INFO	:
						/* your cct index */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_index, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* your cct id */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_id, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* n_s */
						proto_tree_add_item( netrom_tree, hf_netrom_n_s, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* n_r */
						proto_tree_add_item( netrom_tree, hf_netrom_n_r, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						break;
			case NETROM_INFOACK	:
						/* your cct index */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_index, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* your cct id */
						proto_tree_add_item( netrom_tree, hf_netrom_your_cct_id, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						/* unused */
						offset += 1;

						/* n_r */
						proto_tree_add_item( netrom_tree, hf_netrom_n_r, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						break;
			default			:
						offset += 1;
						offset += 1;
						offset += 1;
						offset += 1;

						break;
			}

		/* type */
		dissect_netrom_type(	tvb,
					offset,
					pinfo,
					netrom_tree,
					hf_netrom_type,
					ett_netrom_type,
					&netrom_type_items
					);
		offset += 1;

		switch ( op_code )
			{
			case NETROM_PROTOEXT	:
						break;
			case NETROM_CONNREQ	:
						/* proposed window size */
						proto_tree_add_item( netrom_tree, hf_netrom_pwindow, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						proto_tree_add_item( netrom_tree, hf_netrom_user, tvb, offset, AX25_ADDR_LEN, ENC_NA );
						offset += AX25_ADDR_LEN;

						proto_tree_add_item( netrom_tree, hf_netrom_node, tvb, offset, AX25_ADDR_LEN, ENC_NA );
						offset += AX25_ADDR_LEN;

						break;
			case NETROM_CONNACK	:
						/* accepted window size */
						proto_tree_add_item( netrom_tree, hf_netrom_awindow, tvb, offset, 1, ENC_BIG_ENDIAN );
						offset += 1;

						break;
			case NETROM_DISCREQ	:
						break;
			case NETROM_DISCACK	:
						break;
			case NETROM_INFO	:
						break;
			case NETROM_INFOACK	:
						break;
			default			:
						break;
			}
		}

	/* Call sub-dissectors here */

	next_tvb = tvb_new_subset_remaining(tvb, offset);

	switch ( op_code )
		{
		case NETROM_PROTOEXT	:
					if ( cct_index == NETROM_PROTO_IP && cct_id == NETROM_PROTO_IP )
						call_dissector( ip_handle , next_tvb, pinfo, tree );
					else
						call_data_dissector(next_tvb, pinfo, tree );

					break;
		case NETROM_INFO	:
		default			:
					call_data_dissector(next_tvb, pinfo, tree );
					break;
		}
}

static void
dissect_netrom_routing(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	tvbuff_t *next_tvb;
	const guint8* mnemonic;
	gint mnemonic_len;

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "NET/ROM");
	col_set_str( pinfo->cinfo, COL_INFO, "routing table frame");

	if (tree)
	{
		proto_item *ti;
		proto_tree *netrom_tree;
		ti = proto_tree_add_item( tree, proto_netrom, tvb, 0, -1, ENC_NA);
		netrom_tree = proto_item_add_subtree( ti, ett_netrom );

		proto_tree_add_item_ret_string_and_length(netrom_tree, hf_netrom_mnemonic, tvb, 1, 6, ENC_ASCII|ENC_NA,
													wmem_packet_scope(), &mnemonic, &mnemonic_len);
		proto_item_append_text(ti, ", routing table frame, Node: %.6s", mnemonic);
	}

	next_tvb = tvb_new_subset_remaining(tvb, 7);

	call_data_dissector(next_tvb, pinfo, tree );
}

/* Code to actually dissect the packets */
static int
dissect_netrom(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_)
{
	if ( tvb_get_guint8( tvb, 0 ) == 0xff )
		dissect_netrom_routing( tvb, pinfo, tree );
	else
		dissect_netrom_proto( tvb, pinfo, tree );

	return tvb_captured_length(tvb);
}

static gboolean
capture_netrom( const guchar *pd _U_, int offset, int len, capture_packet_info_t *cpinfo _U_, const union wtap_pseudo_header *pseudo_header _U_)
{
	if ( ! BYTES_ARE_IN_FRAME( offset, len, NETROM_MIN_SIZE ) )
		return FALSE;

	/* XXX - check for IP-over-NetROM here! */
	return FALSE;
}

void
proto_register_netrom(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_netrom_src,
			{ "Source",			"netrom.src",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Source callsign", HFILL }
		},
		{ &hf_netrom_dst,
			{ "Destination",		"netrom.dst",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Destination callsign", HFILL }
		},
		{ &hf_netrom_ttl,
			{ "TTL",			"netrom.ttl",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_netrom_my_cct_index,
			{ "My circuit index",		"netrom.my.cct.index",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_netrom_my_cct_id,
			{ "My circuit ID",		"netrom.my.cct.id",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_netrom_your_cct_index,
			{ "Your circuit index",		"netrom.your.cct.index",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_netrom_your_cct_id,
			{ "Your circuit ID",		"netrom.your.cct.id",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_netrom_n_r,
			{ "N(r)",			"netrom.n_r",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_netrom_n_s,
			{ "N(s)",			"netrom.n_s",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_netrom_type,
			{ "Type",			"netrom.type",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Packet type field", HFILL }
		},
		{ &hf_netrom_op,
			{ "OP code",			"netrom.op",
			FT_UINT8, BASE_HEX, VALS( op_code_vals_abbrev ), 0x0f,
			"Protocol operation code", HFILL }
		},
		{ &hf_netrom_more,
			{ "More",			"netrom.flag.more",
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), NETROM_MORE_FLAG,
			"More flag", HFILL }
		},
		{ &hf_netrom_nak,
			{ "NAK",			"netrom.flag.nak",
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), NETROM_NAK_FLAG,
			"NAK flag", HFILL }
		},
		{ &hf_netrom_choke,
			{ "Choke",			"netrom.flag.choke",
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), NETROM_CHOKE_FLAG,
			"Choke flag", HFILL }
		},
		{ &hf_netrom_user,
			{ "User",			"netrom.user",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"User callsign", HFILL }
		},
		{ &hf_netrom_node,
			{ "Node",			"netrom.node",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Node callsign", HFILL }
		},
		{ &hf_netrom_pwindow,
			{ "Window",			"netrom.pwindow",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Proposed window", HFILL }
		},
		{ &hf_netrom_awindow,
			{ "Window",			"netrom.awindow",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Accepted window", HFILL }
		},
		{ &hf_netrom_mnemonic,
			{ "Node name",			"netrom.name",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_netrom,
		&ett_netrom_type,
	};

	/* Register the protocol name and description */
	proto_netrom = proto_register_protocol( "Amateur Radio NET/ROM", "NET/ROM", "netrom" );

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array( proto_netrom, hf, array_length(hf ) );
	proto_register_subtree_array( ett, array_length( ett ) );
}

void
proto_reg_handoff_netrom(void)
{
	dissector_add_uint( "ax25.pid", AX25_P_NETROM, create_dissector_handle( dissect_netrom, proto_netrom ) );
	register_capture_dissector("ax25.pid", AX25_P_NETROM, capture_netrom, proto_netrom);

	ip_handle   = find_dissector_add_dependency( "ip", proto_netrom );
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
