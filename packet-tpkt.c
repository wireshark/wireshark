/* packet-tpkt.c
 *
 * Routines for TPKT dissection
 * Copyright 2000, Philips Electronics N.V.
 * Andreas Sikkema <andreas.sikkema@philips.com>
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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

/*
 * This dissector tries to dissect the TPKT protocol according to
 * RFC 1006
 *
 * IMPORTANT IMPORTANT IMPORTANT IMPORTANT IMPORTANT IMPORTANT IMPORTANT 
 *
 * Please examine the dissector. It is NOT defined in the normal way!
 * Some variables are references and the dissector also returns a 
 * value! And no, this is not a heuristic dissector!
 * 
 * IMPORTANT IMPORTANT IMPORTANT IMPORTANT IMPORTANT IMPORTANT IMPORTANT 
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include "packet.h"

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

int 
is_tpkt( tvbuff_t *tvb, unsigned int* offset )
{
	if ( (*offset) + 4 > tvb_length( tvb ) ) return FALSE;
	if ( ! ( ( tvb_get_guint8( tvb, ( *offset ) ) == 3 ) && 
		       ( tvb_get_guint8( tvb, ( *offset ) + 1 ) == 0 ) ) ) return FALSE;

  return TRUE;
}

int
dissect_tpkt( tvbuff_t *tvb, unsigned int* offset, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *tpkt_tree     = NULL;
	unsigned int data_len = 0;


	pinfo->current_proto = "TPKT";

	/* There should at least be 4 bytes left in the frame */
	if ( (*offset) + 4 > tvb_length( tvb ) ) return -1;
	/* 
	 * The first octet should be 3 and the second one should be 0 
	 * The H.323 implementers guide suggests that this migh not 
	 * always be the case....
	 */
	if ( ! ( ( tvb_get_guint8( tvb, ( *offset ) ) == 3 ) && 
		       ( tvb_get_guint8( tvb, ( *offset ) + 1 ) == 0 ) ) ) return -1;

	if ( check_col( pinfo->fd, COL_PROTOCOL ) ) {
		col_set_str( pinfo->fd, COL_PROTOCOL, "TPKT" );
	}
	
	if ( check_col( pinfo->fd, COL_INFO) ) {
		/*data_len = pntohs( &pd[ (*offset) + 2 ] );*/
		data_len = tvb_get_ntohs( tvb, (*offset) + 2 );

		col_add_fstr( pinfo->fd, COL_INFO, "TPKT Data length = %d", data_len );
	}

	if ( tree ) {
		ti = proto_tree_add_item( tree, proto_tpkt, tvb, (*offset), 4, FALSE );
		tpkt_tree = proto_item_add_subtree( ti, ett_tpkt );
		/* Version 1st octet */
		proto_tree_add_item( tpkt_tree, hf_tpkt_version, tvb, (*offset), 1, FALSE );
		(*offset)++;
		/* Reserved octet*/
		proto_tree_add_item( tpkt_tree, hf_tpkt_reserved, tvb, (*offset), 1, FALSE );
		(*offset)++;
	}
	else {
		(*offset) += 2;
	}
	/* Length, two octets */
	/*data_len = pntohs( &pd[ (*offset) ] );*/
	data_len = tvb_get_ntohs( tvb, (*offset) );

	if ( tree )
		proto_tree_add_uint_format( tpkt_tree, hf_tpkt_length, tvb, (*offset), 2, data_len, "Length: %d", data_len );

	(*offset) += 2;
	return data_len;
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
				"" 
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
				"" 
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
				"" 
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
