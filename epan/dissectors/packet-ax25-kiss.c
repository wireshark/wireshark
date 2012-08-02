/* packet-ax25-kiss.c
 *
 * Routines for AX.25 KISS protocol dissection
 * Copyright 2010,2012 R.W. Stearn <richard@rns-stearn.demon.co.uk>
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
 * This dissector handles the "KISS" protocol as implemented by the
 * Linux kernel.
 *
 * The original definition of the KISS protocol can be found here:
 *   http://www.ka9q.net/papers/kiss.html
 * and here:
 *   http://www.ax25.net/kiss.aspx
 *
 * Linux implementation does not appear to attempt to implement that
 * protocol in full. Does provide the ability to send a KISS command via
 * ax25_kiss_cmd() and internally will send FULLDUPLEX KISS commands if
 * DAMA is enabled/disabled.
 * i.e.:
 *      ax25_dev_dama_on  sends FullDuplex ON
 *      ax25_dev_dama_off sends FullDuplex OFF
 *
 * Data frames are prefixed with a "Data Frame" command but the port appears to
 * be always 0.
 *
 * Abstract from http://www.ka9q.net/papers/kiss.html
 * --------------------------------------------------
 * For reference the first byte of a KISS frame is the frame type and the TNC
 * port number,
 *   LSB 4 bits = frame type,
 *   MSB 4 bits = port number.
 *
 * The frame types are:
 * Command        Function         Comments
 *    0           Data frame       The  rest  of the frame is data to
 *                                 be sent on the HDLC channel.
 *
 *    1           TXDELAY          The next  byte  is  the  transmitter
 *                                 keyup  delay  in  10 ms units.
 *                                 The default start-up value is 50
 *                                 (i.e., 500 ms).
 *
 *    2           P                The next byte  is  the  persistence
 *                                 parameter,  p, scaled to the range
 *                                 0 - 255 with the following
 *                                 formula:
 *
 *                                          P = p * 256 - 1
 *
 *                                 The  default  value  is  P  =  63
 *                                 (i.e.,  p  =  0.25).
 *
 *    3           SlotTime         The next byte is the slot interval
 *                                 in 10 ms units.
 *                                 The default is 10 (i.e., 100ms).
 *
 *    4           TXtail           The next byte is the time to hold
 *                                 up the TX after the FCS has been
 *                                 sent, in 10 ms units.  This command
 *                                 is obsolete, and is included  here
 *                                 only for  compatibility  with  some
 *                                 existing  implementations.
 *
 *    5          FullDuplex        The next byte is 0 for half duplex,
 *                                 nonzero  for full  duplex.
 *                                 The  default  is  0
 *                                 (i.e.,  half  duplex).
 *
 *    6          SetHardware       Specific for each TNC.  In the
 *                                 TNC-1, this command  sets  the
 *                                 modem speed.  Other implementations
 *                                 may use this function  for   other
 *                                 hardware-specific   functions.
 *
 *    FF         Return            Exit KISS and return control to a
 *                                 higher-level program. This is useful
 *                                 only when KISS is  incorporated
 *                                 into  the TNC along with other
 *                                 applications.
 *
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
#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/etypes.h>

#include "packet-ax25-kiss.h"

#define STRLEN	80

#define KISS_HEADER_SIZE	1 /* length of the KISS type header */

/* KISS frame types */
#define KISS_DATA_FRAME		0
#define KISS_TXDELAY		1
#define KISS_PERSISTENCE	2
#define KISS_SLOT_TIME		3
#define KISS_TXTAIL		4
#define KISS_FULLDUPLEX		5
#define KISS_SETHARDWARE	6
#define KISS_RETURN		15

#define KISS_CMD_MASK           0x0f
#define KISS_PORT_MASK          0xf0

/* Forward declaration we need below */
void proto_reg_handoff_ax25_kiss(void);

/* Dissector handles - all the possibles are listed */

/* Initialize the protocol and registered fields */
static int proto_ax25_kiss           = -1;
static int hf_ax25_kiss_cmd		= -1;
static int hf_ax25_kiss_port		= -1;
static int hf_ax25_kiss_txdelay	= -1;
static int hf_ax25_kiss_persistence	= -1;
static int hf_ax25_kiss_slottime	= -1;
static int hf_ax25_kiss_txtail	= -1;
static int hf_ax25_kiss_fullduplex	= -1;
static int hf_ax25_kiss_sethardware	= -1;

/* Global preference ("controls" display of numbers) */
/*
static gboolean gPREF_HEX = FALSE;
*/

/* Initialize the subtree pointers */
static gint ett_ax25_kiss = -1;

/* Code to actually dissect the packets */
static void
dissect_ax25_kiss( tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree )
{
	proto_item *ti;
	proto_tree *kiss_tree;
	int offset;
	int kiss_cmd;
	int kiss_type;
	int kiss_port;
	int kiss_param;
	int kiss_param_len;
	char *frame_type_text;
	char *info_buffer;
#if 0
	void *saved_private_data;
	tvbuff_t *next_tvb = NULL;
#endif


	info_buffer = ep_alloc( STRLEN );
	info_buffer[0]='\0';

	if ( check_col( pinfo->cinfo, COL_PROTOCOL ) )
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "KISS" );

	col_clear( pinfo->cinfo, COL_INFO );

	/* protocol offset for the KISS header */
	offset = 0;

	kiss_cmd = tvb_get_guint8( tvb, offset ) & 0xff;
	kiss_type = kiss_cmd & KISS_CMD_MASK;
	kiss_port = (kiss_cmd & KISS_PORT_MASK) >> 4;
	offset += KISS_HEADER_SIZE;

	frame_type_text = "????";
	kiss_param = 0;
	kiss_param_len = 0;
	switch ( kiss_type )
		{
		case KISS_DATA_FRAME	: frame_type_text = "Data frame"; break;
		case KISS_TXDELAY	: frame_type_text = "Tx Delay";     kiss_param_len = 1; kiss_param = tvb_get_guint8( tvb, offset ) & 0xff; break;
		case KISS_PERSISTENCE	: frame_type_text = "Persistence";  kiss_param_len = 1; kiss_param = tvb_get_guint8( tvb, offset ) & 0xff; break;
		case KISS_SLOT_TIME	: frame_type_text = "Slot time";    kiss_param_len = 1; kiss_param = tvb_get_guint8( tvb, offset ) & 0xff; break;
		case KISS_TXTAIL	: frame_type_text = "Tx tail";      kiss_param_len = 1; kiss_param = tvb_get_guint8( tvb, offset ) & 0xff; break;
		case KISS_FULLDUPLEX	: frame_type_text = "Full duplex";  kiss_param_len = 1; kiss_param = tvb_get_guint8( tvb, offset ) & 0xff; break;
		case KISS_SETHARDWARE	: frame_type_text = "Set hardware"; kiss_param_len = 1; kiss_param = tvb_get_guint8( tvb, offset ) & 0xff; break;
		case KISS_RETURN	: frame_type_text = "Return"; break;
		default			: break;
		}
	g_snprintf( info_buffer, STRLEN, "%s, Port %u", frame_type_text, kiss_port );
	if ( kiss_param_len > 0 )
		g_snprintf( info_buffer, STRLEN, "%s %u, Port %u", frame_type_text, kiss_param,
				kiss_port );

	offset += kiss_param_len;

	col_add_str( pinfo->cinfo, COL_INFO, info_buffer );

	if ( parent_tree )
		{
		/* protocol offset for the KISS header */
		offset = 0;

		/* create display subtree for the protocol */
		ti = proto_tree_add_protocol_format( parent_tree, proto_ax25_kiss, tvb, offset,
			KISS_HEADER_SIZE + kiss_param_len,
			"KISS: %s",
			info_buffer
			);

		kiss_tree = proto_item_add_subtree( ti, ett_ax25_kiss );

		proto_tree_add_uint( kiss_tree, hf_ax25_kiss_cmd,  tvb, offset, KISS_HEADER_SIZE,
					kiss_cmd );
		proto_tree_add_uint( kiss_tree, hf_ax25_kiss_port, tvb, offset, KISS_HEADER_SIZE,
					kiss_cmd );
		offset += KISS_HEADER_SIZE;

		switch ( kiss_type  )
			{
			case KISS_DATA_FRAME	: break;
			case KISS_TXDELAY	:
						proto_tree_add_uint( kiss_tree, hf_ax25_kiss_txdelay,
							tvb, offset, kiss_param_len, kiss_param );
						offset += kiss_param_len;
						break;
			case KISS_PERSISTENCE	:
						proto_tree_add_uint( kiss_tree, hf_ax25_kiss_persistence,
							tvb, offset, kiss_param_len, kiss_param );
						offset += kiss_param_len;
						break;
			case KISS_SLOT_TIME	:
						proto_tree_add_uint( kiss_tree, hf_ax25_kiss_slottime,
							tvb, offset, kiss_param_len, kiss_param );
						offset += kiss_param_len;
						break;
			case KISS_TXTAIL	:
						proto_tree_add_uint( kiss_tree, hf_ax25_kiss_txtail,
							tvb, offset, kiss_param_len, kiss_param );
						offset += kiss_param_len;
						break;
			case KISS_FULLDUPLEX	:
						proto_tree_add_uint( kiss_tree, hf_ax25_kiss_fullduplex,
							tvb, offset, kiss_param_len, kiss_param );
						offset += kiss_param_len;
						break;
			case KISS_SETHARDWARE	:
						proto_tree_add_uint( kiss_tree, hf_ax25_kiss_sethardware,
							tvb, offset, kiss_param_len, kiss_param );
						offset += kiss_param_len;
						break;
			case KISS_RETURN	: break;
			default			: break;
			}

	}
	/* Call sub-dissectors here */

}

void
proto_register_ax25_kiss(void)
{
	module_t *ax25_kiss_module;

	/* Setup list of header fields */
	static hf_register_info hf[] = {
		{ &hf_ax25_kiss_cmd,
			{ "Cmd",			"ax25_kiss.cmd",
			FT_UINT8, BASE_DEC, NULL, KISS_CMD_MASK,
			"Cmd", HFILL }
		},
		{ &hf_ax25_kiss_port,
			{ "Port",			"ax25_kiss.port",
			FT_UINT8, BASE_DEC, NULL, KISS_PORT_MASK,
			"Port", HFILL }
		},
		{ &hf_ax25_kiss_txdelay,
			{ "Tx delay",			"ax25_kiss.txdelay",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Tx delay", HFILL }
		},
		{ &hf_ax25_kiss_persistence,
			{ "Persistence",		"ax25_kiss.persistence",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Persistence", HFILL }
		},
		{ &hf_ax25_kiss_slottime,
			{ "Slot time",			"ax25_kiss.slottime",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Slot time", HFILL }
		},
		{ &hf_ax25_kiss_txtail,
			{ "Tx tail",			"ax25_kiss.txtail",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Tx tail", HFILL }
		},
		{ &hf_ax25_kiss_fullduplex,
			{ "Full duplex",		"ax25_kiss.fullduplex",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Full duplex", HFILL }
		},
		{ &hf_ax25_kiss_sethardware,
			{ "Set hardware",		"ax25_kiss.sethardware",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Set hardware", HFILL }
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
		&ett_ax25_kiss,
	};

	/* Register the protocol name and description */
	proto_ax25_kiss = proto_register_protocol( "AX.25 KISS", "AX.25 KISS", "ax25_kiss" );

	/* Register the dissector */
	register_dissector( "ax25_kiss", dissect_ax25_kiss, proto_ax25_kiss );

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array( proto_ax25_kiss, hf, array_length( hf ) );
	proto_register_subtree_array( ett, array_length( ett ) );

	/* Register preferences module */
        ax25_kiss_module = prefs_register_protocol( proto_ax25_kiss, proto_reg_handoff_ax25_kiss );

	/* Register any preference */
/*
        prefs_register_bool_preference( ax25_kiss_module, "showhex",
             "Display numbers in Hex",
	     "Enable to display numerical values in hexadecimal.",
	     &gPREF_HEX );
*/
}

void
proto_reg_handoff_ax25_kiss(void)
{
	static gboolean inited = FALSE;

	if( !inited ) {

		dissector_handle_t kiss_handle;

		kiss_handle = create_dissector_handle( dissect_ax25_kiss, proto_ax25_kiss );
		dissector_add( "wtap_encap", WTAP_ENCAP_AX25_KISS, kiss_handle );

		inited = TRUE;
	}
}

void
capture_ax25_kiss( const guchar *pd, int offset, int len, packet_counts *ld)
{
	int l_offset;
	guint8 kiss_cmd;

	if ( ! BYTES_ARE_IN_FRAME( offset, len, KISS_HEADER_SIZE ) ) {
		ld->other++;
		return;
	}

	l_offset = offset;
	kiss_cmd = pd[ l_offset ];
	l_offset += KISS_HEADER_SIZE; /* step over kiss header */
	switch ( kiss_cmd & KISS_CMD_MASK )
		{
		case KISS_DATA_FRAME	: break;
		case KISS_TXDELAY	: l_offset += 1; break;
		case KISS_PERSISTENCE	: l_offset += 1; break;
		case KISS_SLOT_TIME	: l_offset += 1; break;
		case KISS_TXTAIL	: l_offset += 1; break;
		case KISS_FULLDUPLEX	: l_offset += 1; break;
		case KISS_SETHARDWARE	: l_offset += 1; break;
		case KISS_RETURN	: break;
		default			: break;
		}

}
