/* packet-tpkt.c
 *
 * Routine to check for RFC 1006 TPKT header and to dissect TPKT header
 * Copyright 2000, Philips Electronics N.V.
 * Andreas Sikkema <andreas.sikkema@philips.com>
 *
 * Routine to dissect RFC 1006 TPKT packet containing OSI TP PDU
 * Copyright 2001, Martin Thomas <Martin_A_Thomas@yahoo.com>
 *
 * $Id: packet-tpkt.c,v 1.11 2002/02/02 02:51:20 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#  include <netinet/in.h>
#endif

#include <stdio.h>
#include <string.h>

#include "packet-tpkt.h"

/* TPKT header fields             */
static int proto_tpkt          = -1;
static int hf_tpkt_version     = -1;
static int hf_tpkt_reserved    = -1;
static int hf_tpkt_length      = -1;

/* TPKT fields defining a sub tree */
static gint ett_tpkt           = -1;

#define TCP_PORT_TPKT	102

/* find the dissector for OSI TP (aka COTP) */
static dissector_handle_t osi_tp_handle; 

/*
 * Check whether this could be a TPKT-encapsulated PDU.
 * Returns -1 if it's not.
 * Sets "*offset" to the offset of the first byte past the TPKT header,
 * and returns the length from the TPKT header, if it is.
 */
int
is_tpkt( tvbuff_t *tvb, int *offset )
{
	guint16 data_len;

	/*
	 * If TPKT is disabled, don't dissect it, just return -1, meaning
	 * "this isn't TPKT".
	 */
	if (!proto_is_protocol_enabled(proto_tpkt))
		return -1;

	/* There should at least be 4 bytes left in the frame */
	if ( (*offset) + 4 > (int)tvb_length( tvb ) )
		return -1;	/* there aren't */

	/*
	 * The first octet should be 3 and the second one should be 0 
	 * The H.323 implementers guide suggests that this might not 
	 * always be the case....
	 */
	if ( ! ( ( tvb_get_guint8( tvb, ( *offset ) ) == 3 ) && 
		 ( tvb_get_guint8( tvb, ( *offset ) + 1 ) == 0 ) ) )
		return -1;	/* They're not */

	data_len = tvb_get_ntohs( tvb, ( *offset ) + 2 );

	*offset += 4;
	return data_len;
}

/*
 * Dissect the TPKT header; called from the TPKT dissector, as well as
 * from dissectors such as the dissector for Q.931-over-TCP.
 *
 * Returns the PDU length from the TPKT header.
 */
int
dissect_tpkt_header( tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *tpkt_tree     = NULL;
	guint16 data_len;

	pinfo->current_proto = "TPKT";

	if ( check_col( pinfo->cinfo, COL_PROTOCOL ) ) {
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "TPKT" );
	}
	
	data_len = tvb_get_ntohs( tvb, offset + 2 );

	if ( check_col( pinfo->cinfo, COL_INFO) ) {
		col_add_fstr( pinfo->cinfo, COL_INFO, "TPKT Data length = %u",
		    data_len );
	}

	if ( tree ) {
		ti = proto_tree_add_item( tree, proto_tpkt, tvb, offset, 4,
		    FALSE );
		tpkt_tree = proto_item_add_subtree( ti, ett_tpkt );
		/* Version 1st octet */
		proto_tree_add_item( tpkt_tree, hf_tpkt_version, tvb,
		    offset, 1, FALSE );
		offset++;
		/* Reserved octet*/
		proto_tree_add_item( tpkt_tree, hf_tpkt_reserved, tvb,
		    offset, 1, FALSE );
		offset++;
	}
	else {
		offset += 2;
	}

	if ( tree )
		proto_tree_add_uint( tpkt_tree, hf_tpkt_length, tvb,
		    offset, 2, data_len );

	return data_len;
}

/*
 * Dissect RFC 1006 TPKT, which wraps a TPKT header around an OSI TP
 * PDU.
 */
static void
dissect_tpkt( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	int tpkt_len;
	int offset = 0;
	int length, reported_length;
	tvbuff_t *next_tvb;

	/* Dissect the TPKT header. */
	tpkt_len = dissect_tpkt_header(tvb, offset, pinfo, tree);
	offset += 4;

	/*
	 * Now hand the minimum of (what's in this frame, what the TPKT
	 * header says is in the PDU) on to the OSI TP dissector.
	 */
	length = tvb_length_remaining(tvb, offset);
	reported_length = tvb_reported_length_remaining(tvb, offset);
	if (length > tpkt_len)
		length = tpkt_len;
	if (reported_length > tpkt_len)
		reported_length = tpkt_len;
	next_tvb = tvb_new_subset(tvb, offset, length, reported_length);

	call_dissector(osi_tp_handle, next_tvb, pinfo, tree);
}

void
proto_register_tpkt(void)
{
	static hf_register_info hf[] = 
	{
		{ 
			&hf_tpkt_version,
			{ 
				"Version", 
				"tpkt.version", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_tpkt_reserved,
			{ 
				"Reserved", 
				"tpkt.reserved", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_tpkt_length,
			{ 
				"Length", 
				"tpkt.length", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
	};
	
	static gint *ett[] = 
	{
		&ett_tpkt,
	};


	proto_tpkt = proto_register_protocol("TPKT", "TPKT", "tpkt");
	proto_register_field_array(proto_tpkt, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_tpkt(void)
{
	dissector_handle_t tpkt_handle;

	osi_tp_handle = find_dissector("ositp");
	tpkt_handle = create_dissector_handle(dissect_tpkt, proto_tpkt);
	dissector_add("tcp.port", TCP_PORT_TPKT, tpkt_handle);
}
