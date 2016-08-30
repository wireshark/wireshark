/* packet-ax25.c
 *
 * Routines for Amateur Packet Radio protocol dissection
 * AX.25 frames
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
 * This dissector is for:
 * AX.25 Amateur Packet-Radio Link-Layer Protocol, Version 2.0, October 1984
 *
 * At the time of writing the specification could be found here:
 *   http://www.tapr.org/pub_ax25.html
 *
 * A newer version, Version 2.2, July 1998, can be found at
 *   http://www.ax25.net/AX25.2.2-Jul%2098-2.pdf
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
#include <epan/capture_dissectors.h>
#include <wiretap/wtap.h>
#include <epan/to_str.h>
#include <epan/xdlc.h>
#include <epan/ax25_pids.h>
#include <epan/ipproto.h>
#include "packet-ax25.h"

#define STRLEN	80

#define AX25_HEADER_SIZE	15 /* length of src_addr + dst_addr + cntl */
#define AX25_MAX_DIGIS		 8

void proto_register_ax25(void);
void proto_reg_handoff_ax25(void);

/* Dissector table */
static dissector_table_t ax25_dissector_table;

/* Initialize the protocol and registered fields */
static int proto_ax25		= -1;
static int hf_ax25_dst		= -1;
static int hf_ax25_src		= -1;
static int hf_ax25_via[ AX25_MAX_DIGIS ]	= { -1,-1,-1,-1,-1,-1,-1,-1 };

static int hf_ax25_ctl		= -1;

static int hf_ax25_n_r		= -1;
static int hf_ax25_n_s		= -1;

static int hf_ax25_p		= -1;
static int hf_ax25_f		= -1;

static int hf_ax25_ftype_s	= -1;
static int hf_ax25_ftype_i	= -1;
static int hf_ax25_ftype_su	= -1;

static int hf_ax25_u_cmd	= -1;
static int hf_ax25_u_resp	= -1;

static int hf_ax25_pid		= -1;

static const xdlc_cf_items ax25_cf_items = {
	&hf_ax25_n_r,
	&hf_ax25_n_s,
	&hf_ax25_p,
	&hf_ax25_f,
	&hf_ax25_ftype_s,
	&hf_ax25_u_cmd,
	&hf_ax25_u_resp,
	&hf_ax25_ftype_i,
	&hf_ax25_ftype_su
};

static const value_string pid_vals[] = {
	{ AX25_P_ROSE,	   "Rose" },
	{ AX25_P_RFC1144C, "RFC1144 (compressed)" },
	{ AX25_P_RFC1144,  "RFC1144 (uncompressed)" },
	{ AX25_P_SEGMENT,  "Segment" },
	{ AX25_P_TEXNET,   "Texnet" },
	{ AX25_P_LCP,	   "Link Quality protocol" },
	{ AX25_P_ATALK,	   "AppleTalk" },
	{ AX25_P_ATALKARP, "AppleTalk ARP" },
	{ AX25_P_IP,	   "IP" },
	{ AX25_P_ARP,	   "ARP" },
	{ AX25_P_FLEXNET,  "FlexNet" },
	{ AX25_P_NETROM,   "NetRom" },
	{ AX25_P_NO_L3,	   "No L3" },
	{ AX25_P_L3_ESC,   "L3 esc" },
	{ 0, NULL }
};

static gint ett_ax25 = -1;
static gint ett_ax25_ctl = -1;

static dissector_handle_t ax25_handle;

static int
dissect_ax25( tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_ )
{
	proto_item *ti;
	proto_tree *ax25_tree;
	int offset;
	int via_index;
	char *info_buffer;
	/* char v2cmdresp; */
	const char *ax25_version;
	int is_response;
	guint8 control;
	guint8 pid = AX25_P_NO_L3;
	guint8 src_ssid;
	guint8 dst_ssid;
	tvbuff_t *next_tvb = NULL;


	info_buffer = (char *)wmem_alloc( wmem_packet_scope(), STRLEN );
	info_buffer[0] = '\0';

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "AX.25" );
	col_clear( pinfo->cinfo, COL_INFO );

	/* start at the dst addr */
	offset = 0;
	/* create display subtree for the protocol */
	ti = proto_tree_add_protocol_format( parent_tree, proto_ax25, tvb, offset, -1, "AX.25");
	ax25_tree = proto_item_add_subtree( ti, ett_ax25 );

	proto_tree_add_item( ax25_tree, hf_ax25_dst, tvb, offset, AX25_ADDR_LEN, ENC_NA);
	set_address_tvb(&pinfo->dl_dst, AT_AX25, AX25_ADDR_LEN, tvb, offset);
	copy_address_shallow(&pinfo->dst, &pinfo->dl_dst);
	dst_ssid = tvb_get_guint8(tvb, offset+6);

	/* step over dst addr point at src addr */
	offset += AX25_ADDR_LEN;

	proto_tree_add_item( ax25_tree, hf_ax25_src, tvb, offset, AX25_ADDR_LEN, ENC_NA);
	set_address_tvb(&pinfo->dl_src, AT_AX25, AX25_ADDR_LEN, tvb, offset);
	copy_address_shallow(&pinfo->src, &pinfo->dl_src);
	src_ssid = tvb_get_guint8(tvb, offset+6);

	/* step over src addr point at either 1st via addr or control byte */
	offset += AX25_ADDR_LEN;

	proto_item_append_text( ti, ", Src: %s, Dst: %s",
		address_to_str(wmem_packet_scope(), &pinfo->src),
		address_to_str(wmem_packet_scope(), &pinfo->dst));

	/* decode the cmd/resp field */
	/* v2cmdresp = '.'; */
	switch ( ( (dst_ssid >> 6) & 0x02) | ( (src_ssid >> 7) & 0x01 ) )
		{
		case 1 : /* V2.0 Response */
			ax25_version = "V2.0+";
			/* v2cmdresp = 'R'; */
			is_response = TRUE;
			break;
		case 2 : /* V2.0 Command */
			ax25_version = "V2.0+";
			/* v2cmdresp = 'C'; */
			is_response = FALSE;
			break;
		default :
			ax25_version = "V?.?";
			/* v2cmdresp = '?'; */
			is_response = FALSE;
			break;
		}
	proto_item_append_text( ti, ", Ver: %s", ax25_version );

	/* handle the vias, if any */
	via_index = 0;
	while ( ( tvb_get_guint8( tvb, offset - 1 ) & 0x01 ) == 0 )
		{
		if ( via_index < AX25_MAX_DIGIS )
			{
			proto_tree_add_item( ax25_tree, hf_ax25_via[ via_index ], tvb, offset, AX25_ADDR_LEN, ENC_NA);
			via_index++;
			}
		/* step over a via addr */
		offset += AX25_ADDR_LEN;
		}

	/* XXX - next-to-last argument should be TRUE if modulo 128 operation */
	control = dissect_xdlc_control(	tvb,
					offset,
					pinfo,
					ax25_tree,
					hf_ax25_ctl,
					ett_ax25_ctl,
					&ax25_cf_items,
					NULL,
					NULL,
					NULL,
					is_response,
					FALSE,
					FALSE );
	/* XXX - second argument should be TRUE if modulo 128 operation */
	offset += XDLC_CONTROL_LEN(control, FALSE); /* step over control field */

	if ( XDLC_IS_INFORMATION( control ) )
		{

		pid      = tvb_get_guint8( tvb, offset );
		col_append_fstr( pinfo->cinfo, COL_INFO, ", %s", val_to_str(pid, pid_vals, "Unknown (0x%02x)") );
		proto_tree_add_uint( ax25_tree, hf_ax25_pid, tvb, offset, 1, pid );

		/* Call sub-dissectors here */

		offset += 1; /* step over pid to the 1st byte of the payload */

		proto_item_set_end(ti, tvb, offset);

		next_tvb = tvb_new_subset_remaining(tvb, offset);

		if (!dissector_try_uint(ax25_dissector_table, pid, next_tvb, pinfo, parent_tree))
			{
			call_data_dissector(next_tvb, pinfo, parent_tree);
			}
		}
	else
		proto_item_set_end(ti, tvb, offset);

	return tvb_captured_length(tvb);
}

gboolean
capture_ax25( const guchar *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
	guint8 control;
	guint8 pid;
	int l_offset;

	if ( ! BYTES_ARE_IN_FRAME( offset, len, AX25_HEADER_SIZE ) )
		return FALSE;

	l_offset = offset;
	l_offset += AX25_ADDR_LEN; /* step over dst addr point at src addr */
	l_offset += AX25_ADDR_LEN; /* step over src addr point at either 1st via addr or control byte */
	while ( ( pd[ l_offset - 1 ] & 0x01 ) == 0 )
		l_offset += AX25_ADDR_LEN; /* step over a via addr */

	control = pd[ l_offset ];

	/* decode the pid field (if appropriate) */
	if ( XDLC_IS_INFORMATION( control ) )
	{
		l_offset += 1; /* step over control byte point at pid */
		pid = pd[ l_offset ];

		l_offset += 1; /* step over the pid and point to the first byte of the payload */
		return try_capture_dissector("ax25.pid", pid & 0x0ff, pd, l_offset, len, cpinfo, pseudo_header);
	}
	return FALSE;
}

void
proto_register_ax25(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_ax25_dst,
			{ "Destination",		"ax25.dst",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Destination callsign", HFILL }
		},
		{ &hf_ax25_src,
			{ "Source",			"ax25.src",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Source callsign", HFILL }
		},
		{ &hf_ax25_via[ 0 ],
			{ "Via 1",			"ax25.via1",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 1", HFILL }
		},
		{ &hf_ax25_via[ 1 ],
			{ "Via 2",			"ax25.via2",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 2", HFILL }
		},
		{ &hf_ax25_via[ 2 ],
			{ "Via 3",			"ax25.via3",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 3", HFILL }
		},
		{ &hf_ax25_via[ 3 ],
			{ "Via 4",			"ax25.via4",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 4", HFILL }
		},
		{ &hf_ax25_via[ 4 ],
			{ "Via 5",			"ax25.via5",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 5", HFILL }
		},
		{ &hf_ax25_via[ 5 ],
			{ "Via 6",			"ax25.via6",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 6", HFILL }
		},
		{ &hf_ax25_via[ 6 ],
			{ "Via 7",			"ax25.via7",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 7", HFILL }
		},
		{ &hf_ax25_via[ 7 ],
			{ "Via 8",			"ax25.via8",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 8", HFILL }
		},
		{ &hf_ax25_ctl,
			{ "Control",			"ax25.ctl",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			"Control field", HFILL }
		},
		{ &hf_ax25_n_r,
			{ "n(r)",			"ax25.ctl.n_r",
			FT_UINT8, BASE_DEC, NULL, XDLC_N_R_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_n_s,
			{ "n(s)",			"ax25.ctl.n_s",
			FT_UINT8, BASE_DEC, NULL, XDLC_N_S_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_p,
			{ "Poll",			"ax25.ctl.p",
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
			NULL, HFILL }
		},
		{ &hf_ax25_f,
			{ "Final",			"ax25.ctl.f",
			FT_BOOLEAN, 8, TFS(&tfs_set_notset), XDLC_P_F,
			NULL, HFILL }
		},
		{ &hf_ax25_ftype_s,
			{ "Frame type",			"ax25.ctl.ftype_s",
			FT_UINT8, BASE_HEX, VALS(stype_vals), XDLC_S_FTYPE_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_ftype_i,
			{ "Frame type",			"ax25.ctl.ftype_i",
			FT_UINT8, BASE_HEX, VALS(ftype_vals), XDLC_I_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_ftype_su,
			{ "Frame type",			"ax25.ctl.ftype_su",
			FT_UINT8, BASE_HEX, VALS(ftype_vals), XDLC_S_U_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_u_cmd,
			{ "Frame type",			"ax25.ctl.u_cmd",
			FT_UINT8, BASE_HEX, VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_u_resp,
			{ "Frame type",			"ax25.ctl.u_resp",
			FT_UINT8, BASE_HEX, VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK,
			NULL, HFILL }
		},
		{ &hf_ax25_pid,
			{ "Protocol ID",		"ax25.pid",
			FT_UINT8, BASE_HEX, VALS(pid_vals), 0x0,
			"Protocol identifier", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ax25,
		&ett_ax25_ctl,
	};

	/* Register the protocol name and description */
	proto_ax25 = proto_register_protocol("Amateur Radio AX.25", "AX.25", "ax25");

	/* Register the dissector */
	ax25_handle = register_dissector( "ax25", dissect_ax25, proto_ax25 );

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array( proto_ax25, hf, array_length(hf ) );
	proto_register_subtree_array(ett, array_length(ett ) );

	/* Register dissector table for protocol IDs */
	ax25_dissector_table = register_dissector_table("ax25.pid", "AX.25 protocol ID", proto_ax25, FT_UINT8, BASE_HEX);
	register_capture_dissector_table("ax25.pid", "AX.25");
}

void
proto_reg_handoff_ax25(void)
{
	dissector_add_uint("wtap_encap", WTAP_ENCAP_AX25, ax25_handle);
	dissector_add_uint("ip.proto", IP_PROTO_AX25, ax25_handle);

	register_capture_dissector("wtap_encap", WTAP_ENCAP_AX25, capture_ax25, proto_ax25);
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
