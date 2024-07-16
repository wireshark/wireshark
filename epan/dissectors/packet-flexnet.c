/* packet-flexnet.c
 *
 * Routines for Amateur Packet Radio protocol dissection
 * Copyright 2005,2006,2007,2008,2009,2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Information on the protocol drawn from:
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
#include <epan/ax25_pids.h>

void proto_register_flexnet(void);
void proto_reg_handoff_flexnet(void);

static dissector_handle_t flexnet_handle;

#define FLEXNET_ADRLEN  15
#define FLEXNET_CTLLEN  15
#define FLEXNET_HDRLEN  (FLEXNET_ADRLEN + FLEXNET_ADRLEN + FLEXNET_CTLLEN)

static int proto_flexnet;
static int hf_flexnet_dst;
static int hf_flexnet_src;
static int hf_flexnet_ctl;

static int ett_flexnet;
static int ett_flexnet_ctl;

static int
dissect_flexnet(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_)
{
	tvbuff_t   *next_tvb;

	col_set_str( pinfo->cinfo, COL_PROTOCOL, "Flexnet");
	col_clear( pinfo->cinfo, COL_INFO );

	if ( parent_tree )
		{
		proto_item *ti;
		proto_tree *flexnet_tree;
		int	    offset;

		/* create display subtree for the protocol */

		ti = proto_tree_add_protocol_format( parent_tree, proto_flexnet, tvb, 0, FLEXNET_HDRLEN, "FLEXNET" );

		flexnet_tree = proto_item_add_subtree( ti, ett_flexnet );

		offset = 0;

		proto_tree_add_item( flexnet_tree, hf_flexnet_dst, tvb, offset, FLEXNET_ADRLEN, ENC_NA );
		offset +=FLEXNET_ADRLEN;

		proto_tree_add_item( flexnet_tree, hf_flexnet_src, tvb, offset, FLEXNET_ADRLEN, ENC_NA );
		offset +=FLEXNET_ADRLEN;

		proto_tree_add_item( flexnet_tree, hf_flexnet_ctl, tvb, offset, FLEXNET_CTLLEN, ENC_NA );
		/* offset +=FLEXNET_CTLLEN; */
		}

	/* Call sub-dissectors here */

	next_tvb = tvb_new_subset_remaining(tvb, FLEXNET_HDRLEN);
	call_data_dissector(next_tvb, pinfo, parent_tree );
	return tvb_captured_length(tvb);
}

void
proto_register_flexnet(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_flexnet_dst,
			{ "Destination",		"flexnet.dst",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Destination address", HFILL }
		},
		{ &hf_flexnet_src,
			{ "Source",			"flexnet.src",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			"Source address", HFILL }
		},
		{ &hf_flexnet_ctl,
			{ "Control",			"flexnet.ctl",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_flexnet,
		&ett_flexnet_ctl,
	};

	/* Register the protocol name and description */
	proto_flexnet = proto_register_protocol("FlexNet", "FLEXNET", "flexnet");

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array( proto_flexnet, hf, array_length( hf ) );
	proto_register_subtree_array( ett, array_length( ett ) );

	flexnet_handle = register_dissector( "flexnet", dissect_flexnet, proto_flexnet );
}

void
proto_reg_handoff_flexnet(void)
{
	dissector_add_uint( "ax25.pid", AX25_P_FLEXNET, flexnet_handle );
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
