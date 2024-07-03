/* packet-bpq.c
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
 * This dissector is for:
 *   Ethernet encapsulated Amateur AX.25 (AX.25 over Ethernet)
 *
 * Information was drawn from:
 *   ?
 *
 * It uses Ether ID 0x08ff which is not officially registered.
 *
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/capture_dissectors.h>

#define STRLEN	80

#define BPQ_HEADER_SIZE	2 /* length of bpq_len */

void proto_register_bpq(void);
void proto_reg_handoff_bpq(void);

static dissector_handle_t bpq_handle;
static dissector_handle_t ax25_handle;

static capture_dissector_handle_t ax25_cap_handle;

static int proto_bpq;
static int hf_bpq_len;

static int ett_bpq;

static int
dissect_bpq( tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_ )
{
	proto_item *ti;
	proto_tree *bpq_tree;
	int	    offset;
	uint16_t	    bpq_len;
	tvbuff_t   *next_tvb;


	col_set_str( pinfo->cinfo, COL_PROTOCOL, "BPQ" );

	col_clear( pinfo->cinfo, COL_INFO );

	/* protocol offset for the BPQ header */
	offset = 0;

	bpq_len = tvb_get_letohs( tvb, offset );

	col_add_fstr( pinfo->cinfo, COL_INFO, "%u", bpq_len );

	if ( parent_tree )
		{
		/* protocol offset for the BPQ header */
		offset = 0;

		/* create display subtree for the protocol */
		ti = proto_tree_add_protocol_format( parent_tree, proto_bpq, tvb, offset, BPQ_HEADER_SIZE,
			"BPQ, Len: %u",
			bpq_len & 0xfff	/* XXX - lower 12 bits? */
			);

		bpq_tree = proto_item_add_subtree( ti, ett_bpq );

		proto_tree_add_item( bpq_tree, hf_bpq_len, tvb, offset, BPQ_HEADER_SIZE, ENC_LITTLE_ENDIAN );

	}

	offset += BPQ_HEADER_SIZE;

	/* XXX - use the length */
	next_tvb = tvb_new_subset_remaining( tvb, offset );
	call_dissector( ax25_handle, next_tvb, pinfo, parent_tree );
	return tvb_captured_length(tvb);
}

static bool
capture_bpq( const unsigned char *pd, int offset, int len, capture_packet_info_t *cpinfo, const union wtap_pseudo_header *pseudo_header)
{
	int l_offset;

	if ( ! BYTES_ARE_IN_FRAME( offset, len, BPQ_HEADER_SIZE ) )
		return false;

	l_offset = offset;
	l_offset += BPQ_HEADER_SIZE; /* step over bpq header to point at the AX.25 packet*/
	return call_capture_dissector( ax25_cap_handle, pd, l_offset, len, cpinfo, pseudo_header );
}

void
proto_register_bpq(void)
{
	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_bpq_len,
			{ "BPQ len",			"bpq.len",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL, HFILL }
		},
	};

	/* Setup protocol subtree array */
	static int *ett[] = {
		&ett_bpq,
	};

	/* Register the protocol name and description */
	proto_bpq = proto_register_protocol( "Amateur Radio BPQ", "BPQ", "bpq" );

	/* Register the dissector */
	bpq_handle = register_dissector("bpq", dissect_bpq, proto_bpq);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array( proto_bpq, hf, array_length( hf ) );
	proto_register_subtree_array( ett, array_length( ett ) );
}

void
proto_reg_handoff_bpq(void)
{
	capture_dissector_handle_t bpq_cap_handle;

	dissector_add_uint("ethertype", ETHERTYPE_BPQ, bpq_handle);
	bpq_cap_handle = create_capture_dissector_handle(capture_bpq, proto_bpq);
	capture_dissector_add_uint("ethertype", ETHERTYPE_BPQ, bpq_cap_handle);

	/* BPQ is only implemented for AX.25 */
	ax25_handle     = find_dissector_add_dependency( "ax25", proto_bpq );

	ax25_cap_handle = find_capture_dissector( "ax25" );
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
