/* packet-ax25-nol3.c
 *
 * Routines for Amateur Packet Radio protocol dissection
 * Copyright 2007,2008,2009,2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This dissector is for the "No Layer 3 protocol" PID of the AX.25 Amateur
 * Packet-Radio Link-Layer Protocol, Version 2.0, October 1984
 *
 * At the time of writing the specification could be found here:
 *   http://www.tapr.org/pub_ax25.html
 *
 * Information on the "protocols" recognised by this dissector are drawn from:
 *  DX cluster:
 *    A network capture kindly donated by Luca Melette.
 *  APRS:
 *    http://www.aprs.org/
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
#include <epan/prefs.h>
#include <epan/ax25_pids.h>

#define STRLEN	80

void proto_register_ax25_nol3(void);
void proto_reg_handoff_ax25_nol3(void);

/* Dissector handles - all the possibles are listed */
static dissector_handle_t aprs_handle;

/* Initialize the protocol and registered fields */
static int proto_ax25_nol3;
static int proto_dx;

static int hf_dx_report;

/* static int hf_text; */

/* Global preferences */
static bool gPREF_APRS;
static bool gPREF_DX;

/* Initialize the subtree pointers */
static int ett_ax25_nol3;

static int ett_dx;


/* Code to actually dissect the packets */
static int
dissect_dx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	proto_item *ti;
	proto_tree *dx_tree;

	int data_len;
	int offset;

	offset   = 0;
	data_len = tvb_reported_length_remaining( tvb, offset );

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "DX" );

	col_add_str( pinfo->cinfo, COL_INFO, tvb_format_text( pinfo->pool, tvb, offset, 15 ) );

	if ( parent_tree )
		{
		/* create display subtree for the protocol */
		ti = proto_tree_add_protocol_format( parent_tree, proto_dx, tvb, 0, -1,
		    "DX (%s)", tvb_format_text( pinfo->pool, tvb, offset, 15 ) );
		dx_tree = proto_item_add_subtree( ti, ett_dx );
		offset = 0;

		proto_tree_add_item( dx_tree, hf_dx_report, tvb, offset, data_len, ENC_ASCII );
	}

	return tvb_captured_length(tvb);
}

static bool
isaprs( uint8_t dti )
{
	bool b = false;

	switch ( dti )
		{
		case 0x1c	:
		case 0x1d	:
		case '!'	:
		case '#'	:
		case '$'	:
		case '%'	:
		case '&'	:
		case ')'	:
		case '*'	:
		case '+'	:
		case ','	:
		case '.'	:
		case '/'	:
		case ':'	:
		case ';'	:
		case '<'	:
		case '='	:
		case '>'	:
		case '?'	:
		case '@'	:
		case 'T'	:
		case '['	:
		case '\''	:
		case '_'	:
		case '`'	:
		case '{'	:
		case '}'	: b = true; break;
		default		: break;
		}
	return b;
}

static int
dissect_ax25_nol3(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_ )
{
	proto_item *ti;
	proto_tree *ax25_nol3_tree;
	char       *info_buffer;
	int         offset;
	tvbuff_t   *next_tvb = NULL;
	uint8_t     dti      = 0;
	bool        dissected;

	info_buffer = (char *)wmem_alloc( pinfo->pool, STRLEN );
	info_buffer[0] = '\0';

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "AX.25-NoL3");

	col_clear( pinfo->cinfo, COL_INFO);

	offset = 0;
	snprintf( info_buffer, STRLEN, "Text" );

	if ( gPREF_APRS )
		{
		dti = tvb_get_uint8( tvb, offset );
		if ( isaprs( dti ) )
			snprintf( info_buffer, STRLEN, "APRS" );
		}
	if ( gPREF_DX )
		{
		if ( tvb_get_uint8( tvb, offset ) == 'D' && tvb_get_uint8( tvb, offset + 1 ) == 'X' )
		snprintf( info_buffer, STRLEN, "DX cluster" );
		}

	col_add_str( pinfo->cinfo, COL_INFO, info_buffer );

	/* Call sub-dissectors here */

	/* create display subtree for the protocol */
	ti = proto_tree_add_protocol_format( parent_tree,
						proto_ax25_nol3,
						tvb,
						0,
						-1,
						"AX.25 No Layer 3 - (%s)", info_buffer );
	ax25_nol3_tree = proto_item_add_subtree( ti, ett_ax25_nol3 );

	next_tvb = tvb_new_subset_remaining(tvb, offset);
	dissected = false;
	if ( gPREF_APRS )
		{
		if ( isaprs( dti ) )
			{
			dissected = true;
			call_dissector( aprs_handle , next_tvb, pinfo, ax25_nol3_tree );
			}
		}
	if ( gPREF_DX )
		{
		if ( tvb_get_uint8( tvb, offset ) == 'D' && tvb_get_uint8( tvb, offset + 1 ) == 'X' )
			{
			dissected = true;
			dissect_dx( next_tvb, pinfo, ax25_nol3_tree, NULL );
			}
		}
	if ( ! dissected )
		call_data_dissector(next_tvb, pinfo, ax25_nol3_tree );

	return tvb_captured_length(tvb);
}

void
proto_register_ax25_nol3(void)
{
	module_t *ax25_nol3_module;

	/* Setup list of header fields */
#if 0 /* not used ? */
	static hf_register_info hf[] = {
		{ &hf_text,
			{ "Text",			"ax25_nol3.text",
			FT_STRING, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
	};
#endif

	static hf_register_info hf_dx[] = {
		{ &hf_dx_report,
			{ "DX",				"ax25_nol3.dx",
			FT_STRING, BASE_NONE, NULL, 0x0,
			"DX cluster", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_ax25_nol3,
		&ett_dx,
	};

	/* Register the protocol name and description */
	proto_ax25_nol3 = proto_register_protocol("AX.25 no Layer 3", "AX.25 no L3", "ax25_nol3");

	/* Required function calls to register the header fields and subtrees used */
	/* proto_register_field_array( proto_ax25_nol3, hf, array_length(hf ) ); */
	proto_register_subtree_array( ett, array_length( ett ) );

	/* Register preferences module */
	ax25_nol3_module = prefs_register_protocol( proto_ax25_nol3, NULL);

	/* Register any preference */
	prefs_register_bool_preference(ax25_nol3_module, "showaprs",
	     "Decode the APRS info field",
	     "Enable decoding of the payload as APRS.",
	     &gPREF_APRS );

	prefs_register_bool_preference(ax25_nol3_module, "showcluster",
	     "Decode DX cluster info field",
	     "Enable decoding of the payload as DX cluster info.",
	     &gPREF_DX );

	/* Register the sub-protocol name and description */
	proto_dx = proto_register_protocol("DX cluster", "DX", "dx");

	/* Register the dissector */
	register_dissector( "dx", dissect_dx, proto_dx);

	/* Register the header fields */
	proto_register_field_array( proto_dx, hf_dx, array_length( hf_dx ) );

	/* Register the subtrees used */
	/* proto_register_subtree_array( ett_dx, array_length( ett_dx ) ); */
}

void
proto_reg_handoff_ax25_nol3(void)
{
	dissector_add_uint( "ax25.pid", AX25_P_NO_L3, create_dissector_handle( dissect_ax25_nol3, proto_ax25_nol3 ) );

	/*
	 */
	aprs_handle     = find_dissector_add_dependency( "aprs", proto_ax25_nol3 );
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
