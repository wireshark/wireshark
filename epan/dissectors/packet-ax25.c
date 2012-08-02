/* packet-ax25.c
 *
 * Routines for Amateur Packet Radio protocol dissection
 * Copyright 2005,2006,2007,2008,2009,2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * This dissector is for:
 * AX.25 Amateur Packet-Radio Link-Layer Protocol, Version 2.0, October 1984
 *
 * At the time of writing the specification could be found here:
 *   http://www.tapr.org/pub_ax25.html
 *
 * Inspiration on how to build the dissector drawn from
 *   packet-sdlc.c
 *   packet-x25.c
 *   packet-lapb.c
 *   paket-gprs-llc.c
 *   xdlc.c
 * with the base file built from README.developers.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>

#include <epan/strutil.h>
#include <epan/packet.h>
#include <epan/emem.h>
#include <epan/xdlc.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <packet-ip.h>

#include "packet-ax25.h"
#include "packet-netrom.h"
#include "packet-flexnet.h"

#define STRLEN	80

#define AX25_ADDR_LEN		7  /* length of an AX.25 address */
#define AX25_HEADER_SIZE	15 /* length of src_addr + dst_addr + cntl */
#define AX25_MAX_DIGIS		8

/* Layer 3 Protocol ID's (pid) */
#define AX25_P_ROSE	0x01	/* ISO 8208 / CCITT X.25 PLP */
#define AX25_P_RFC1144C	0x06	/* Compressed TCP/IP packet. Van Jacobson RFC1144 */
#define AX25_P_RFC1144	0x07	/* Uncompressed TCP/IP packet. Van Jacobson RFC1144 */
#define AX25_P_SEGMENT	0x08	/* segmentation fragment */
#define AX25_P_TEXNET	0xC3	/* TEXNET datagram */
#define AX25_P_LCP	0xC4	/* Link Quality Protocol */
#define AX25_P_ATALK	0xCA	/* AppleTalk */
#define AX25_P_ATALKARP	0xCB	/* AppleTalk ARP */
#define AX25_P_IP	0xCC	/* ARPA Internet Protocol */
#define AX25_P_ARP	0xCD	/* ARPA Address Resolution Protocol */
#define AX25_P_FLEXNET 	0xCE	/* FlexNet */
#define AX25_P_NETROM 	0xCF	/* NET/ROM */
#define AX25_P_NO_L3 	0xF0	/* No layer 3 protocol */
#define AX25_P_L3_ESC 	0xFF	/* Escape character. Next octet contains more layer 3 protocol info */

#define I_FRAME( control )  ( ( control & 0x01) == 0 )
#define UI_FRAME( control ) ( ( ( control & 0x03) == 3 ) && ( ( ( ( ( control >> 5 ) & 0x07) << 2) | ( ( control >> 2 ) & 0x03) ) == 0 ) )

/* Forward declaration we need below */
void proto_reg_handoff_ax25(void);

/* Dissector handles - all the possibles are listed */
static dissector_handle_t rose_handle;
static dissector_handle_t rfc1144c_handle;
static dissector_handle_t rfc1144_handle;
static dissector_handle_t segment_handle;
static dissector_handle_t texnet_handle;
static dissector_handle_t lcp_handle;
static dissector_handle_t atalk_handle;
static dissector_handle_t atalkarp_handle;
static dissector_handle_t ip_handle;
static dissector_handle_t arp_handle;
static dissector_handle_t flexnet_handle;
static dissector_handle_t netrom_handle;
static dissector_handle_t no_l3_handle;
static dissector_handle_t l3_esc_handle;
static dissector_handle_t default_handle;

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

/* Initialize the subtree pointers */
static gint ett_ax25 = -1;
static gint ett_ax25_ctl = -1;

/* Code to actually dissect the packets */
static void
dissect_ax25( tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree )
{
	proto_item *ti;
	proto_tree *ax25_tree;
	int offset;
	int control_offset;
	int hdr_len;
	int via_index;
	char *info_buffer;
	/* char v2cmdresp; */
	char *ax25_version;
	int is_response;
	char *text_ptr;
	const guint8 *src_addr;
	const guint8 *dst_addr;
	const guint8 *via_addr;
	guint8 control;
	guint8 pid = AX25_P_NO_L3;
	char *pid_text = NULL;
	guint8 src_ssid;
	guint8 dst_ssid;
	void *saved_private_data;
	tvbuff_t *next_tvb = NULL;


	info_buffer = ep_alloc( STRLEN );
	info_buffer[0]='\0';

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "AX.25" );

	col_clear( pinfo->cinfo, COL_INFO );

	/* protocol offset for an AX.25 packet */
	/* start at the dst addr */
	offset = 0;

	dst_addr = tvb_get_ptr( tvb,  offset, AX25_ADDR_LEN );
	SET_ADDRESS( &pinfo->dl_dst,	AT_AX25, AX25_ADDR_LEN, dst_addr );
	SET_ADDRESS( &pinfo->dst,	AT_AX25, AX25_ADDR_LEN, dst_addr );
	dst_ssid = *(dst_addr + 6);
	offset += AX25_ADDR_LEN; /* step over dst addr point at src addr */

	src_addr = tvb_get_ptr( tvb,  offset, AX25_ADDR_LEN );
	SET_ADDRESS( &pinfo->dl_src,	AT_AX25, AX25_ADDR_LEN, src_addr );
	SET_ADDRESS( &pinfo->src,	AT_AX25, AX25_ADDR_LEN, src_addr );
	src_ssid = *(src_addr + 6);
	offset += AX25_ADDR_LEN; /* step over src addr point at either 1st via addr or control byte */

	/* step over any vias */
	while ( ( tvb_get_guint8( tvb, offset - 1 ) & 0x01 ) == 0 )
		offset += AX25_ADDR_LEN; /* step over a via addr */

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

	/* decode the control field */
	control_offset = offset;
	control  = tvb_get_guint8( tvb, control_offset );

	text_ptr = "????";
	switch ( control & 0x03 )
		{
		case 1 :
			switch ( ( control >> 2 ) & 0x03 )
				{
				case 0 : text_ptr = "RR"; break;
				case 1 : text_ptr = "RNR"; break;
				case 2 : text_ptr = "REJ"; break;
				case 3 : text_ptr = "SREJ"; break;
				}
			break;
		case 3 :
			switch ( ( ( ( control >> 5 ) & 0x07) << 2) | ( ( control >> 2 ) & 0x03) )
				{
				case 0  :  text_ptr = "UI"; break;
				case 3  :  text_ptr = "DM"; break;
				case 7  :  text_ptr = "SABM"; break;
				case 8  :  text_ptr = "DISC"; break;
				case 12 :  text_ptr = "UA"; break;
				case 15 :  text_ptr = "SABME"; break;
				case 17 :  text_ptr = "FRMR"; break;
				case 23 :  text_ptr = "XID"; break;
				case 28 :  text_ptr = "TEST"; break;
				default :  text_ptr = "????"; break;
				}
			break;
		default :
			text_ptr = "I";
			break;
		}
	g_snprintf( info_buffer, STRLEN, "%s", text_ptr );

	/* decode the pid field (if appropriate) */
	if ( I_FRAME( control ) || UI_FRAME( control ) )
		{
		offset += 1; /* step over control byte point at pid */
		pid      = tvb_get_guint8( tvb, offset );
		switch ( pid )
			{
			case AX25_P_ROSE	: pid_text = "Rose"			; break;
			case AX25_P_RFC1144C	: pid_text = "RFC1144 (compressed)"	; break;
			case AX25_P_RFC1144	: pid_text = "RFC1144 (uncompressed)"	; break;
			case AX25_P_SEGMENT	: pid_text = "Segment"			; break;
			case AX25_P_TEXNET	: pid_text = "Texnet"			; break;
			case AX25_P_LCP		: pid_text = "Link Quality protocol"	; break;
			case AX25_P_ATALK	: pid_text = "AppleTalk"		; break;
			case AX25_P_ATALKARP	: pid_text = "AppleTalk ARP"		; break;
			case AX25_P_IP		: pid_text = "IP"			; break;
			case AX25_P_ARP		: pid_text = "ARP"			; break;
			case AX25_P_FLEXNET	: pid_text = "FlexNet"			; break;
			case AX25_P_NETROM	: pid_text = "NetRom"			; break;
			case AX25_P_NO_L3	: pid_text = "No L3"			; break;
			case AX25_P_L3_ESC	: pid_text = "L3 esc"			; break;
			default			: pid_text = "Unknown"			; break;
			}
		g_snprintf( info_buffer, STRLEN, "%s (%s)", info_buffer, pid_text );
		}

	col_add_str( pinfo->cinfo, COL_INFO, info_buffer );

	if ( parent_tree )
		{
		/* start at the dst addr */
		offset = 0;

		/* create display subtree for the protocol */
		hdr_len = AX25_HEADER_SIZE;
		if ( I_FRAME( control ) || UI_FRAME( control ) )
			hdr_len += 1;

		ti = proto_tree_add_protocol_format( parent_tree, proto_ax25, tvb, offset, hdr_len,
			"AX.25, Src: %s (%s), Dst: %s (%s), Ver: %s",
			get_ax25_name( src_addr ),
			ax25_to_str( src_addr ),
			get_ax25_name( dst_addr ),
			ax25_to_str( dst_addr ),
			ax25_version
			);

		ax25_tree = proto_item_add_subtree( ti, ett_ax25 );

		proto_tree_add_ax25( ax25_tree, hf_ax25_dst, tvb, offset, AX25_ADDR_LEN, dst_addr );

		/* step over dst addr point at src addr */
		offset += AX25_ADDR_LEN;
		proto_tree_add_ax25( ax25_tree, hf_ax25_src, tvb, offset, AX25_ADDR_LEN, src_addr );

		/* step over src addr point at either 1st via addr or control byte */
		offset += AX25_ADDR_LEN;

		/* handle the vias, if any */
		via_index = 0;
		while ( ( tvb_get_guint8( tvb, offset - 1 ) & 0x01 ) == 0 )
			{
			if ( via_index < AX25_MAX_DIGIS )
				{
				via_addr = tvb_get_ptr( tvb,  offset, AX25_ADDR_LEN );
				proto_tree_add_ax25( ax25_tree, hf_ax25_via[ via_index ], tvb, offset, AX25_ADDR_LEN, via_addr );
				via_index++;
				}
			/* step over a via addr */
			offset += AX25_ADDR_LEN;
			}

		dissect_xdlc_control(	tvb,
					control_offset,
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

		if ( I_FRAME( control ) || UI_FRAME( control ) )
			{
			char *s;

			offset += 1; /* step over control byte point at pid */

			s = ep_alloc( STRLEN );
			g_snprintf( s, STRLEN, "%s (0x%0x)", pid_text, pid );
			proto_tree_add_string( ax25_tree, hf_ax25_pid, tvb, offset, 1, s );
			}
		}

	/* Call sub-dissectors here */

	if ( I_FRAME( control ) || UI_FRAME( control ) )
		{
		offset += 1; /* step over pid to the 1st byte of the payload */

		saved_private_data = pinfo->private_data;

		next_tvb = tvb_new_subset(tvb, offset, -1, -1);

		switch ( pid )
			{
			case AX25_P_ROSE	: call_dissector( rose_handle    , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_RFC1144C	: call_dissector( rfc1144c_handle, next_tvb, pinfo, parent_tree ); break;
			case AX25_P_RFC1144	: call_dissector( rfc1144_handle , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_SEGMENT	: call_dissector( segment_handle , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_TEXNET	: call_dissector( texnet_handle  , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_LCP		: call_dissector( lcp_handle     , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_ATALK	: call_dissector( atalk_handle   , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_ATALKARP	: call_dissector( atalkarp_handle, next_tvb, pinfo, parent_tree ); break;
			case AX25_P_IP		: call_dissector( ip_handle      , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_ARP		: call_dissector( arp_handle     , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_FLEXNET	: call_dissector( flexnet_handle , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_NETROM	: call_dissector( netrom_handle  , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_NO_L3	: call_dissector( no_l3_handle   , next_tvb, pinfo, parent_tree ); break;
			case AX25_P_L3_ESC	: call_dissector( l3_esc_handle  , next_tvb, pinfo, parent_tree ); break;
			default			: call_dissector( default_handle , next_tvb, pinfo, parent_tree ); break;
			}
		pinfo->private_data = saved_private_data;
		}
}

void
proto_register_ax25(void)
{
	static const true_false_string flags_set_truth =
		{
		"Set",
		"Not set"
		};


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
		{ &(hf_ax25_via[ 0 ]),
			{ "Via 1",			"ax25.via1",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 1", HFILL }
		},
		{ &(hf_ax25_via[ 1 ]),
			{ "Via 2",			"ax25.via2",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 2", HFILL }
		},
		{ &(hf_ax25_via[ 2 ]),
			{ "Via 3",			"ax25.via3",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 3", HFILL }
		},
		{ &(hf_ax25_via[ 3 ]),
			{ "Via 4",			"ax25.via4",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 4", HFILL }
		},
		{ &(hf_ax25_via[ 4 ]),
			{ "Via 5",			"ax25.via5",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 5", HFILL }
		},
		{ &(hf_ax25_via[ 5 ]),
			{ "Via 6",			"ax25.via6",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 6", HFILL }
		},
		{ &(hf_ax25_via[ 6 ]),
			{ "Via 7",			"ax25.via7",
			FT_AX25, BASE_NONE, NULL, 0x0,
			"Via callsign 7", HFILL }
		},
		{ &(hf_ax25_via[ 7 ]),
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
			"", HFILL }
		},
		{ &hf_ax25_n_s,
			{ "n(s)",			"ax25.ctl.n_s",
			FT_UINT8, BASE_DEC, NULL, XDLC_N_S_MASK,
			"", HFILL }
		},
		{ &hf_ax25_p,
			{ "Poll",			"ax25.ctl.p",
			FT_BOOLEAN, 8, TFS(&flags_set_truth), XDLC_P_F,
			"", HFILL }
		},
		{ &hf_ax25_f,
			{ "Final",			"ax25.ctl.f",
			FT_BOOLEAN, 8, TFS(&flags_set_truth), XDLC_P_F,
			"", HFILL }
		},
		{ &hf_ax25_ftype_s,
			{ "Frame type",			"ax25.ctl.ftype_s",
			FT_UINT8, BASE_HEX, VALS(stype_vals), XDLC_S_FTYPE_MASK,
			"", HFILL }
		},
		{ &hf_ax25_ftype_i,
			{ "Frame type",			"ax25.ctl.ftype_i",
			FT_UINT8, BASE_HEX, VALS(ftype_vals), XDLC_I_MASK,
			"", HFILL }
		},
		{ &hf_ax25_ftype_su,
			{ "Frame type",			"ax25.ctl.ftype_su",
			FT_UINT8, BASE_HEX, VALS(ftype_vals), XDLC_S_U_MASK,
			"", HFILL }
		},
		{ &hf_ax25_u_cmd,
			{ "Frame type",			"ax25.ctl.u_cmd",
			FT_UINT8, BASE_HEX, VALS(modifier_vals_cmd), XDLC_U_MODIFIER_MASK,
			"", HFILL }
		},
		{ &hf_ax25_u_resp,
			{ "Frame type",			"ax25.ctl.u_resp",
			FT_UINT8, BASE_HEX, VALS(modifier_vals_resp), XDLC_U_MODIFIER_MASK,
			"", HFILL }
		},
		{ &hf_ax25_pid,
			{ "Packet ID",			"ax25.pid",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"Packet identifier", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ax25,
		&ett_ax25_ctl,
	};

	/* Register the protocol name and description */
	proto_ax25 = proto_register_protocol("Amateur Radio AX.25", "AX25", "ax25");

	/* Register the dissector */
	register_dissector( "ax25", dissect_ax25, proto_ax25 );

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array( proto_ax25, hf, array_length(hf ) );
	proto_register_subtree_array(ett, array_length(ett ) );
}

void
proto_reg_handoff_ax25(void)
{
        static gboolean inited = FALSE;

        if( !inited ) {

	dissector_handle_t ax25_handle;

	ax25_handle = create_dissector_handle( dissect_ax25, proto_ax25 );
	dissector_add_uint("wtap_encap", WTAP_ENCAP_AX25, ax25_handle);
	dissector_add_uint("ip.proto", IP_PROTO_AX25, ax25_handle);

	/*
	  I have added the "data" dissector for all the currently known PID's
	  This is so at least we have an entry in the tree that allows the
	  payload to be hightlighted.
	  When a new dissector is available all that needs to be done is to
	  replace the current dissector name "data" with the new dissector name.
	*/
	rose_handle     = find_dissector( "data" /* "x.25"      */ );
	rfc1144c_handle = find_dissector( "data" /* "rfc1144c"  */ );
	rfc1144_handle  = find_dissector( "data" /* "rfc1144"   */ );
	segment_handle  = find_dissector( "data" /* "segment"   */ );
	texnet_handle   = find_dissector( "data" /* "texnet"    */ );
	lcp_handle      = find_dissector( "data" /* "lcp"       */ );
	atalk_handle    = find_dissector( "data" /* "atalk"     */ );
	atalkarp_handle = find_dissector( "data" /* "atalkarp"  */ );
	ip_handle       = find_dissector( "ip" );
	arp_handle      = find_dissector( "arp" );
	flexnet_handle  = find_dissector( "flexnet" );
	netrom_handle   = find_dissector( "netrom" );
	no_l3_handle    = find_dissector( "data" /* "ax25_nol3" */ );
	l3_esc_handle   = find_dissector( "data" /* "l3_esc"    */ );
	default_handle  = find_dissector( "data" );

        inited = TRUE;
        }
}

void
capture_ax25( const guchar *pd, int offset, int len, packet_counts *ld)
{
	guint8 control;
	guint8 pid;
	int l_offset;

if ( ! BYTES_ARE_IN_FRAME( offset, len, AX25_HEADER_SIZE ) )
	{
	ld->other++;
	return;
	}

l_offset = offset;
l_offset += AX25_ADDR_LEN; /* step over dst addr point at src addr */
l_offset += AX25_ADDR_LEN; /* step over src addr point at either 1st via addr or control byte */
while ( ( pd[ l_offset - 1 ] & 0x01 ) == 0 )
	l_offset += AX25_ADDR_LEN; /* step over a via addr */

control = pd[ l_offset ];

/* decode the pid field (if appropriate) */
if ( I_FRAME( control ) || UI_FRAME( control ) )
	{
	l_offset += 1; /* step over control byte point at pid */
	pid = pd[ l_offset ];

	l_offset += 1; /* step over the pid and point to the first byte of the payload */
	switch ( pid & 0x0ff )
		{
		case AX25_P_ROSE	: break;
		case AX25_P_RFC1144C	: break;
		case AX25_P_RFC1144	: break;
		case AX25_P_SEGMENT	: break;
		case AX25_P_TEXNET	: break;
		case AX25_P_LCP		: break;
		case AX25_P_ATALK	: break;
		case AX25_P_ATALKARP	: break;
		case AX25_P_IP		: capture_ip( pd, l_offset, len, ld ); break;
		case AX25_P_ARP		: break;
		case AX25_P_FLEXNET	: capture_flexnet( pd, l_offset, len, ld ); break;
		case AX25_P_NETROM	: capture_netrom( pd, l_offset, len, ld );  break;
		case AX25_P_NO_L3	: break;
		case AX25_P_L3_ESC	: break;
		default			: break;
		}
	}
}
