/* packet-applemidi.c
 * Routines for dissection of Apple network-midi session establishment.
 * Copyright 2006-2012, Tobias Erichsen <t.erichsen@gmx.de>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-data.c, README.developer, and various other files.
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
 *
 *
 * Apple network-midi session establishment is a lightweight protocol for
 * providing a simple session establishment for MIDI-data sent in the form
 * of RTP-MIDI (RFC 4695 / 6295).  Peers recognize each other using the
 * Apple Bonjour scheme with the service-name "_apple-midi._udp", establish
 * a connection using AppleMIDI (no official name, just an abbreviation)
 * and then send payload using RTP-MIDI.  The implementation of this
 * dissector is based on the Apple implementation summary from May 6th, 2005
 * and the extension from August 13th, 2010.
 *
 * 2010-11-29
 * - initial version of dissector
 * 2012-02-24
 * - implemented dynamic payloadtype support to automatically punt
 *   the decoding to the RTP-MIDI dissector via the RTP dissector
 * - added new bitrate receive limit feature
 *
 * Here are some links:
 *
 * http://www.cs.berkeley.edu/~lazzaro/rtpmidi/
 * http://www.faqs.org/rfcs/rfc4695.html
 * http://www.faqs.org/rfcs/rfc6295.html
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include "packet-rtp.h"

/* Definitions for protocol name during dissector-register */
#define APPLEMIDI_DISSECTOR_NAME			"Apple Network-MIDI Session Protocol"
#define APPLEMIDI_DISSECTOR_SHORTNAME			"AppleMIDI"
#define APPLEMIDI_DISSECTOR_ABBREVIATION		"applemidi"

/* Signature "Magic Value" for Apple network MIDI session establishment */
#define APPLEMIDI_PROTOCOL_SIGNATURE			0xffff

/* Apple network MIDI valid commands */
#define APPLEMIDI_COMMAND_INVITATION			0x494e		/*   "IN"   */
#define APPLEMIDI_COMMAND_INVITATION_REJECTED		0x4e4f		/*   "NO"   */
#define APLLEMIDI_COMMAND_INVITATION_ACCEPTED		0x4f4b		/*   "OK"   */
#define APPLEMIDI_COMMAND_ENDSESSION			0x4259		/*   "BY"   */
#define APPLEMIDI_COMMAND_SYNCHRONIZATION		0x434b		/*   "CK"   */
#define APPLEMIDI_COMMAND_RECEIVER_FEEDBACK		0x5253		/*   "RS"   */
#define APPLEMIDI_COMMAND_BITRATE_RECEIVE_LIMIT		0x524c		/*   "RL"   */

static int	hf_applemidi_signature			= -1;
static int	hf_applemidi_command			= -1;
static int	hf_applemidi_protocol_version		= -1;
static int	hf_applemidi_token			= -1;
static int	hf_applemidi_ssrc			= -1;
static int	hf_applemidi_name			= -1;
static int	hf_applemidi_count			= -1;
static int	hf_applemidi_padding			= -1;
static int	hf_applemidi_timestamp1			= -1;
static int	hf_applemidi_timestamp2			= -1;
static int	hf_applemidi_timestamp3			= -1;
static int	hf_applemidi_sequence_num		= -1;
static int	hf_applemidi_rtp_sequence_num		= -1;
static int	hf_applemidi_rtp_bitrate_limit		= -1;
static int	hf_applemidi_unknown_data		= -1;


static gint	ett_applemidi				= -1;
static gint	ett_applemidi_seq_num			= -1;


static const value_string applemidi_commands[] = {
	{ APPLEMIDI_COMMAND_INVITATION,			"Invitation" },
	{ APPLEMIDI_COMMAND_INVITATION_REJECTED,	"Invitation Rejected" },
	{ APLLEMIDI_COMMAND_INVITATION_ACCEPTED,	"Invitation Accepted" },
	{ APPLEMIDI_COMMAND_ENDSESSION,			"End Session" },
	{ APPLEMIDI_COMMAND_SYNCHRONIZATION,		"Synchronization" },
	{ APPLEMIDI_COMMAND_RECEIVER_FEEDBACK,		"Receiver Feedback" },
	{ APPLEMIDI_COMMAND_BITRATE_RECEIVE_LIMIT,	"Bitrate Receive Limit" },
	{ 0,						NULL },
};


static int			proto_applemidi		= -1;

static dissector_handle_t	applemidi_handle;
static dissector_handle_t	rtp_handle;

static const char applemidi_unknown_command[]		= "unknown command: 0x%04x";


static void free_encoding_name_str (void *ptr)
{
  encoding_name_and_rate_t *encoding_name_and_rate = (encoding_name_and_rate_t *)ptr;

  if (encoding_name_and_rate->encoding_name) {
    g_free(encoding_name_and_rate->encoding_name);
  }
}

static void
dissect_applemidi_common( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint16 command ) {

	guint16		 seq_num;
	guint8		 count;
	guint8		*name;
	gint		 offset			= 0;
	gint		 len;
	gint		 string_size;
	proto_tree	*applemidi_tree;
	proto_tree	*applemidi_tree_seq_num;


	col_set_str( pinfo->cinfo, COL_PROTOCOL, APPLEMIDI_DISSECTOR_SHORTNAME );

	/* Clear out stuff in the info column */
	col_clear( pinfo->cinfo, COL_INFO );

	col_add_fstr( pinfo->cinfo, COL_INFO, "%s", val_to_str( command, applemidi_commands, applemidi_unknown_command ) );

	if ( tree ) {
		proto_item *ti;
		ti = proto_tree_add_item( tree, proto_applemidi, tvb, 0, -1, ENC_NA  );
		applemidi_tree = proto_item_add_subtree( ti, ett_applemidi );

		proto_tree_add_item( applemidi_tree, hf_applemidi_signature, tvb, offset, 2, ENC_BIG_ENDIAN  );
		offset += 2;

		proto_tree_add_item( applemidi_tree, hf_applemidi_command, tvb, offset, 2, ENC_BIG_ENDIAN  );
		offset += 2;

		/* the format of packets for "IN", "NO", "OK" and "BY" is identical and contains
		 * the protocol version, a random number generated by the initiator of the session,
		 * the SSRC that is used by the respective sides RTP-entity and optionally the
		 * name of the participant */
		if ( ( APPLEMIDI_COMMAND_INVITATION == command ) || ( APPLEMIDI_COMMAND_INVITATION_REJECTED == command ) || ( APLLEMIDI_COMMAND_INVITATION_ACCEPTED == command ) || ( APPLEMIDI_COMMAND_ENDSESSION == command ) ) {

			proto_tree_add_item( applemidi_tree, hf_applemidi_protocol_version, tvb, offset, 4, ENC_BIG_ENDIAN  );
			offset += 4;

			proto_tree_add_item( applemidi_tree, hf_applemidi_token, tvb, offset, 4, ENC_BIG_ENDIAN  );
			offset += 4;

			proto_tree_add_item( applemidi_tree, hf_applemidi_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN  );
			offset += 4;

			len = tvb_reported_length(tvb) - offset;

			/* Name is optional */
			if ( len > 0 ) {
				name = tvb_get_ephemeral_string( tvb, offset, len );
				string_size = (gint)( strlen( name ) + 1 );
				proto_tree_add_item( applemidi_tree, hf_applemidi_name, tvb, offset, string_size, ENC_UTF_8|ENC_NA );
				col_append_fstr( pinfo->cinfo, COL_INFO, ": peer = \"%s\"", name );
				offset += string_size;
			}

		/* the synchronization packet contains three 64bit timestamps,  and a value to define how
		 * many of the timestamps transmitted are valid */
		} else if ( APPLEMIDI_COMMAND_SYNCHRONIZATION == command ) {
			proto_tree_add_item( applemidi_tree, hf_applemidi_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
			offset += 4;

			count = tvb_get_guint8( tvb, offset );
			proto_tree_add_item( applemidi_tree, hf_applemidi_count, tvb, offset, 1, ENC_BIG_ENDIAN );
			col_append_fstr( pinfo->cinfo, COL_INFO, ": count = %u", count );
			offset += 1;

			proto_tree_add_item( applemidi_tree, hf_applemidi_padding, tvb, offset, 3, ENC_BIG_ENDIAN );
			offset += 3;

			proto_tree_add_item( applemidi_tree, hf_applemidi_timestamp1, tvb, offset, 8, ENC_BIG_ENDIAN );
			offset += 8;

			proto_tree_add_item( applemidi_tree, hf_applemidi_timestamp2, tvb, offset, 8, ENC_BIG_ENDIAN );
			offset += 8;

			proto_tree_add_item( applemidi_tree, hf_applemidi_timestamp3, tvb, offset, 8, ENC_BIG_ENDIAN );
			offset += 8;
		/* With the receiver feedback packet, the recipient can tell the sender up to what sequence
		 * number in the RTP-stream the packets have been received; this can be used to shorten the
		 * recovery-journal-section in the RTP-session */
		} else if ( APPLEMIDI_COMMAND_RECEIVER_FEEDBACK == command ) {
			proto_tree_add_item( applemidi_tree, hf_applemidi_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
			offset += 4;

			ti = proto_tree_add_item( applemidi_tree, hf_applemidi_sequence_num, tvb, offset, 4, ENC_BIG_ENDIAN );
			/* Apple includes a 32bit sequence-number, but the RTP-packet only specifies 16bit.
			 * this subtree and subitem are added to be able to associate the sequence-number
			 * here easier with the one specified in the corresponding RTP-packet */
			applemidi_tree_seq_num = proto_item_add_subtree( ti, ett_applemidi_seq_num );
			seq_num = tvb_get_ntohs( tvb, offset );
			proto_tree_add_uint( applemidi_tree_seq_num, hf_applemidi_rtp_sequence_num, tvb, offset, 2, seq_num );
			offset += 4;

			col_append_fstr( pinfo->cinfo, COL_INFO, ": seq = %u", seq_num );
		/* With the bitrate receive limit packet, the recipient can tell the sender to limit
		   the transmission to a certain bitrate.  This is important if the peer is a gateway
		   to a hardware-device that only supports a certain speed.  Like the MIDI 1.0 DIN-cable
		   MIDI-implementation which is limited to 31250.  */
		} else if ( APPLEMIDI_COMMAND_BITRATE_RECEIVE_LIMIT == command ) {
			proto_tree_add_item( applemidi_tree, hf_applemidi_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN );
			offset += 4;

			ti = proto_tree_add_item( applemidi_tree, hf_applemidi_rtp_bitrate_limit, tvb, offset, 4, ENC_BIG_ENDIAN );
			offset += 4;
		}
		/* If there is any remaining data (possibly because an unknown command was encountered),
		 * we just dump it here */
		len = tvb_length_remaining( tvb, offset );
		if ( len > 0 ) {
			proto_tree_add_item( applemidi_tree, hf_applemidi_unknown_data, tvb, offset, len, ENC_NA );
		}
	}
}

static gboolean
test_applemidi(tvbuff_t *tvb, guint16 *command_p, gboolean conversation_established ) {

	*command_p = 0xffff;

	/* An applemidi session protocol UDP-packet must start with the "magic value" of 0xffff ... */
	if ( APPLEMIDI_PROTOCOL_SIGNATURE != tvb_get_ntohs( tvb, 0 ) )
		return FALSE;

	*command_p = tvb_get_ntohs( tvb, 2 );

	/* If the conversation is establised (one prior packet with a valid known command)
	 * we won't check the commands anymore - this way we still show new commands
	 * Apple might introduct as "unknown" instead of punting to RTP-dissector */
	if ( conversation_established ) {
		return TRUE;
	}


	/* ... followed by packet-command: "IN", "NO", "OK", "BY", "CK" and "RS" and "RL" */
	if ( ( APPLEMIDI_COMMAND_INVITATION            == *command_p ) ||
	     ( APPLEMIDI_COMMAND_INVITATION_REJECTED   == *command_p ) ||
	     ( APLLEMIDI_COMMAND_INVITATION_ACCEPTED   == *command_p ) ||
	     ( APPLEMIDI_COMMAND_ENDSESSION            == *command_p ) ||
	     ( APPLEMIDI_COMMAND_SYNCHRONIZATION       == *command_p ) ||
	     ( APPLEMIDI_COMMAND_RECEIVER_FEEDBACK     == *command_p ) ||
	     ( APPLEMIDI_COMMAND_BITRATE_RECEIVE_LIMIT == *command_p ) )
		return TRUE;

	return FALSE;
}



/* dissect_applemidi() is called when a packet is seen from a previously identified applemidi conversation */
/*  If the packet isn't a valid applemidi packet, assume it's an RTP-MIDI packet.                          */

static void
dissect_applemidi( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree ) {
	guint16		command;

	if ( test_applemidi( tvb, &command, TRUE ) )
		dissect_applemidi_common( tvb, pinfo, tree, command );
	else
		call_dissector( rtp_handle, tvb, pinfo, tree );
}

static gboolean
dissect_applemidi_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree ) {

	guint16		 command;
	conversation_t	*p_conv;
	struct _rtp_conversation_info *p_conv_data = NULL;
	encoding_name_and_rate_t *encoding_name_and_rate = NULL;
	GHashTable *rtp_dyn_payload = NULL;
	gint *key;

	if ( tvb_length( tvb ) < 4)
		return FALSE;  /* not enough bytes to check */

	if ( !test_applemidi( tvb, &command, FALSE ) ) {
		return FALSE;
	}

	/* set dynamic payload-type 97 which is used by Apple for their RTP-MIDI implementation for this
	   address/port-tuple to cause RTP-dissector to call the RTP-MIDI-dissector for payload-decoding */

	encoding_name_and_rate = g_malloc( sizeof( encoding_name_and_rate_t ) );
	rtp_dyn_payload = g_hash_table_new_full( g_int_hash, g_int_equal, g_free, free_encoding_name_str );
	encoding_name_and_rate->encoding_name = g_strdup( "rtp-midi" );
	encoding_name_and_rate->sample_rate = 10000;
	key = g_malloc( sizeof( gint ) );
	*key = 97;
	g_hash_table_insert( rtp_dyn_payload, key, encoding_name_and_rate );
        rtp_add_address( pinfo, &pinfo->src, pinfo->srcport, 0, APPLEMIDI_DISSECTOR_SHORTNAME, pinfo->fd->num, FALSE, rtp_dyn_payload);

	/* call dissect_applemidi() from now on for UDP packets on this "connection"
	   it is important to do this step after calling rtp_add_address, otherwise
	   all further packets will go directly to the RTP-dissector!                */

	p_conv = find_or_create_conversation(pinfo);
	conversation_set_dissector( p_conv, applemidi_handle );

	/* punt to actual decoding */

	dissect_applemidi_common( tvb, pinfo, tree, command );
	return TRUE;

}


void
proto_register_applemidi( void )
{
	static hf_register_info hf[] =	{
		{
			&hf_applemidi_signature,
			{
				"Signature",
				"applemidi.signature",
				FT_UINT16,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_command,
			{
				"Command",
				"applemidi.command",
				FT_UINT16,
				BASE_HEX,
				VALS( applemidi_commands ),
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_protocol_version,
			{
				"Protocol Version",
				"applemidi.protocol_version",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_token,
			{
				"Initiator Token",
				"applemidi.initiator_token",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_ssrc,
			{
				"Sender SSRC",
				"applemidi.sender_ssrc",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_name,
			{
				"Name",
				"applemidi.name",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_count,
			{
				"Count",
				"applemidi.count",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_padding,
			{
				"Padding",
				"applemidi.padding",
				FT_UINT24,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_timestamp1,
			{
				"Timestamp 1",
				"applemidi.timestamp1",
				FT_UINT64,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_timestamp2,
			{
				"Timestamp 2",
				"applemidi.timestamp2",
				FT_UINT64,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_timestamp3,
			{
				"Timestamp 3",
				"applemidi.timestamp3",
				FT_UINT64,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_sequence_num,
			{
				"Sequence Number",
				"applemidi.sequence_number",
				FT_UINT32,
				BASE_HEX,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_rtp_sequence_num,
			{
				"RTP Sequence Number",
				"applemidi.rtp_sequence_number",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_rtp_bitrate_limit,
			{
				"Bitrate limit",
				"applemidi.bitrate_limit",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_applemidi_unknown_data,
			{
				"Unknown Data",
				"rtpmidi.unknown_data",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x00,
				NULL, HFILL
			}
		},
	};


	static gint *ett[] = {
		&ett_applemidi,
		&ett_applemidi_seq_num
	};

	proto_applemidi = proto_register_protocol( APPLEMIDI_DISSECTOR_NAME, APPLEMIDI_DISSECTOR_SHORTNAME, APPLEMIDI_DISSECTOR_ABBREVIATION );
	proto_register_field_array( proto_applemidi, hf, array_length( hf ) );
	proto_register_subtree_array( ett, array_length( ett ) );

}

void
proto_reg_handoff_applemidi( void ) {


	applemidi_handle = create_dissector_handle( dissect_applemidi, proto_applemidi );

	/* If we cannot decode the data it will be RTP-MIDI since the Apple session protocol uses
	 * two ports: the control-port and the MIDI-port.  On both ports an invitation is being sent.
	 * The second port is then used for the RTP-MIDI-data. So if we can't find valid AppleMidi
	 * packets, it will be most likely RTP-MIDI...
	 */
	rtp_handle = find_dissector( "rtp" );
	heur_dissector_add( "udp", dissect_applemidi_heur, proto_applemidi );

}
