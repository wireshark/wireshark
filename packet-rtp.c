/* packet-rtp.c
 *
 * Routines for RTP dissection
 * RTP = Real time Transport Protocol
 * 
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
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
 * This dissector tries to dissect the RTP protocol according to Annex A
 * of ITU-T Recommendation H.225.0 (02/98) or RFC 1889
 *
 * RTP traffic is handled by an even UDP portnumber. This can be any 
 * port number, but there is a registered port available, port 5004
 * See Annex B of ITU-T Recommendation H.225.0, section B.7
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

#include "packet-rtp.h"
#include "packet-h261.h"
#include "conversation.h"

/* RTP header fields             */
static int proto_rtp           = -1;
static int hf_rtp_version      = -1;
static int hf_rtp_padding      = -1;
static int hf_rtp_extension    = -1;
static int hf_rtp_csrc_count   = -1;
static int hf_rtp_marker       = -1;
static int hf_rtp_payload_type = -1;
static int hf_rtp_seq_nr       = -1;
static int hf_rtp_timestamp    = -1;
static int hf_rtp_ssrc         = -1;
static int hf_rtp_csrc_item    = -1;
static int hf_rtp_data         = -1;
static int hf_rtp_padding_data = -1;
static int hf_rtp_padding_count= -1;

/* RTP header extension fields   */
static int hf_rtp_prof_define  = -1;
static int hf_rtp_length       = -1;
static int hf_rtp_hdr_ext      = -1;

/* RTP fields defining a sub tree */
static gint ett_rtp       = -1;
static gint ett_csrc_list = -1;
static gint ett_hdr_ext   = -1;

/*
 * Fields in the first octet of the RTP header.
 */

/* Version is the first 2 bits of the first octet*/
#define RTP_VERSION(octet)	((octet) >> 6)

/* Padding is the third bit; No need to shift, because true is any value
   other than 0! */
#define RTP_PADDING(octet)	((octet) & 0x20)

/* Extension bit is the fourth bit */
#define RTP_EXTENSION(octet)	((octet) & 0x10)

/* CSRC count is the last four bits */
#define RTP_CSRC_COUNT(octet)	((octet) & 0xF)

static const value_string rtp_version_vals[] = 
{
	{ 0, "Old VAT Version" },
	{ 1, "First Draft Version" },
	{ 2, "RFC 1889 Version" },
	{ 0, NULL },
};

/*
 * Fields in the second octet of the RTP header.
 */

/* Marker is the first bit of the second octet */
#define RTP_MARKER(octet)	((octet) & 0x80)

/* Payload type is the last 7 bits */
#define RTP_PAYLOAD_TYPE(octet)	((octet) & 0x7F)

/* 
 * RTP Payload types 
 * Table B.2 / H.225.0
 */
#define PT_PCMU 0
#define PT_PCMA 8
#define PT_G722 9
#define PT_G723 4
#define PT_G728 15
#define PT_G729 18
#define PT_H261 31
#define PT_H263 34

static const value_string rtp_payload_type_vals[] = 
{
	{ PT_PCMU, "ITU-T G.711 PCMU" },
	{ PT_PCMA, "ITU-T G.711 PCMA" },
	{ PT_G722, "ITU-T G.722" },
	{ PT_G723, "ITU-T G.723" },
	{ PT_G728, "ITU-T G.728" },
	{ PT_G729, "ITU-T G.729" },
	{ PT_H261, "ITU-T H.261" },
	{ PT_H263, "ITU-T H.263" },
	{ 0, NULL },
};

static address fake_addr;
static int heur_init = FALSE;

static const char rtp_proto[] = "RTP";

void rtp_add_address( const unsigned char* ip_addr, int prt )
{
	address src_addr;
	conversation_t* pconv = ( conversation_t* ) NULL;

	src_addr.type = AT_IPv4;
	src_addr.len = 4;
	src_addr.data = ip_addr;

	/*
	 * The first time the function is called let the tcp dissector
	 * know that we're interested in traffic
	 */
	if ( ! heur_init ) {
		heur_dissector_add( "udp", dissect_rtp_heur );
		heur_init = TRUE;
	}

	/*
	 * Check if the ip address an dport combination is not 
	 * already registered
	 */
	pconv = find_conversation( &src_addr, &fake_addr, PT_UDP, prt, 0, 0 );

	/*
	 * If not, add
	 */
	if ( ! pconv ) {
		conversation_new( &src_addr, &fake_addr, PT_UDP, (guint32) prt,
		    (guint32) 0, ( void * ) rtp_proto, 0 );
	}

}

#if 0
static void rtp_init( void ) 
{
	unsigned char* tmp_data;
	int i;

	/* Create a fake adddress... */
	fake_addr.type = AT_IPv4;
	fake_addr.len = 4;

	tmp_data = malloc( fake_addr.len );
	for ( i = 0; i < fake_addr.len; i++) {
		tmp_data[i] = 0;
	}
	fake_addr.data = tmp_data;
}
#endif

gboolean
dissect_rtp_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	conversation_t* pconv;

	if (!proto_is_protocol_enabled(proto_rtp))
		return FALSE;	/* RTP has been disabled */

	/* This is a heuristic dissector, which means we get all the TCP
	 * traffic not sent to a known dissector and not claimed by
	 * a heuristic dissector called before us!
	 * So we first check if the frame is really meant for us.
	 */
	if ( ( pconv = find_conversation( &pi.src, &fake_addr, pi.ptype,
	    pi.srcport, 0, 0 ) ) == NULL ) {
		/*
		 * The source ip:port combination was not what we were
		 * looking for, check the destination
		 */
		if ( ( pconv = find_conversation( &pi.dst, &fake_addr,
		    pi.ptype, pi.destport, 0, 0 ) ) == NULL ) {
			return FALSE;
		}
	}

	/*
	 * An RTP conversation always contains data
	 */
	if ( pconv->data == NULL )
		return FALSE;

	/*
	 * An RTP conversation data always contains "RTP"
	 */
	if ( strcmp( pconv->data, rtp_proto ) != 0 )
		return FALSE;

	dissect_rtp( tvb, pinfo, tree );

	return TRUE;
}

void 
dissect_rtp_data( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, proto_tree *rtp_tree, int offset, unsigned int data_len, unsigned int payload_type )
{
	tvbuff_t *newtvb;

	switch( payload_type ) {
		case PT_H261:
			/*
			 * What does reported length DO?
			 */
			newtvb = tvb_new_subset( tvb, offset, data_len, -1 );
			dissect_h261(newtvb, pinfo, tree);
			break;
		default:
			proto_tree_add_bytes( rtp_tree, hf_rtp_data, tvb, offset, data_len, tvb_get_ptr( tvb, offset, data_len ) );
			break;
	}
}

void
dissect_rtp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *rtp_tree      = NULL;
	proto_tree *rtp_csrc_tree = NULL;
	guint8      octet;
	unsigned int version;
	gboolean    padding_set;
	gboolean    extension_set;
	unsigned int csrc_count;
	gboolean    marker_set;
	unsigned int payload_type;
	unsigned int i            = 0;
	unsigned int hdr_extension= 0;
	unsigned int padding_count= 0;
	unsigned int offset = 0;
	guint16     seq_num;
	guint32     timestamp;
	guint32     sync_src;
	guint32     csrc_item;

	CHECK_DISPLAY_AS_DATA(proto_rtp, tvb, pinfo, tree);

	pinfo->current_proto = "RTP";

	/* Get the fields in the first octet */
	octet = tvb_get_guint8( tvb, offset );
	version = RTP_VERSION( octet );
	padding_set = RTP_PADDING( octet );
	extension_set = RTP_EXTENSION( octet );
	csrc_count = RTP_CSRC_COUNT( octet );

	/* Get the fields in the second octet */
	octet = tvb_get_guint8( tvb, offset + 1 );
	marker_set = RTP_MARKER( octet );
	payload_type = RTP_PAYLOAD_TYPE( octet );

	/* Get the subsequent fields */
	seq_num = tvb_get_ntohs( tvb, offset + 2 );
	timestamp = tvb_get_ntohl( tvb, offset + 4 );
	sync_src = tvb_get_ntohl( tvb, offset + 8 );

	if ( check_col( pinfo->fd, COL_PROTOCOL ) )   {
		col_set_str( pinfo->fd, COL_PROTOCOL, "RTP" );
	}
	
	if ( check_col( pinfo->fd, COL_INFO) ) {
		col_add_fstr( pinfo->fd, COL_INFO,
		    "Payload type=%s, SSRC=%u, Seq=%u, Time=%u%s",
		    val_to_str( payload_type, rtp_payload_type_vals,
		        "Unknown (%u)" ),
		    sync_src,
		    seq_num,
		    timestamp,
		    marker_set ? ", Mark" : "");
	}

	if ( tree ) {
		ti = proto_tree_add_item( tree, proto_rtp, tvb, offset, tvb_length_remaining( tvb, offset ), FALSE );
		rtp_tree = proto_item_add_subtree( ti, ett_rtp );
		
		proto_tree_add_uint( rtp_tree, hf_rtp_version, tvb,
		    offset, 1, version );
		proto_tree_add_boolean( rtp_tree, hf_rtp_padding, tvb,
		    offset, 1, padding_set );
		proto_tree_add_boolean( rtp_tree, hf_rtp_extension, tvb,
		    offset, 1, extension_set );
		proto_tree_add_uint( rtp_tree, hf_rtp_csrc_count, tvb,
		    offset, 1, csrc_count );
		offset++;

		proto_tree_add_boolean( rtp_tree, hf_rtp_marker, tvb, offset,
		    1, marker_set );
		proto_tree_add_uint( rtp_tree, hf_rtp_payload_type, tvb,
		    offset, 1, payload_type );
		offset++;

		/* Sequence number 16 bits (2 octets) */
		proto_tree_add_uint( rtp_tree, hf_rtp_seq_nr, tvb, offset, 2, seq_num );
		offset += 2;

		/* Timestamp 32 bits (4 octets) */
		proto_tree_add_uint( rtp_tree, hf_rtp_timestamp, tvb, offset, 4, timestamp );
		offset += 4;

		/* Synchronization source identifier 32 bits (4 octets) */
		proto_tree_add_uint( rtp_tree, hf_rtp_ssrc, tvb, offset, 4, sync_src );
		offset += 4;

		/* CSRC list*/
		if ( csrc_count > 0 ) {
			ti = proto_tree_add_text(rtp_tree, tvb, offset, csrc_count * 4, "Contributing Source identifiers");
			rtp_csrc_tree = proto_item_add_subtree( ti, ett_csrc_list );
			for (i = 0; i < csrc_count; i++ ) {
				csrc_item = tvb_get_ntohl( tvb, offset );
				proto_tree_add_uint_format( rtp_csrc_tree,
				    hf_rtp_csrc_item, tvb, offset, 4,
				    csrc_item,
				    "CSRC item %d: %u",
				    i, csrc_item );
				offset += 4;
			}
		}

		/* Optional RTP header extension */
		if ( extension_set ) {
			/* Defined by profile field is 16 bits (2 octets) */
			proto_tree_add_uint( rtp_tree, hf_rtp_prof_define, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
			offset += 2;

			hdr_extension = tvb_get_ntohs( tvb, offset );
			proto_tree_add_uint( rtp_tree, hf_rtp_length, tvb,
			    offset, 2, hdr_extension);
			if ( hdr_extension > 0 ) {
				ti = proto_tree_add_text(rtp_tree, tvb, offset, csrc_count * 4, "Header extensions");
				/* I'm re-using the old tree variable here
				   from the CSRC list!*/
				rtp_csrc_tree = proto_item_add_subtree( ti,
				    ett_hdr_ext );
				for (i = 0; i < hdr_extension; i++ ) {
					proto_tree_add_uint( rtp_csrc_tree, hf_rtp_hdr_ext, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
					offset += 4;
				}
			}
		}
		/* Find the padding 
		 * The padding count is found in the LAST octet of the packet
		 * This contains the number of octets that can be ignored at 
		 * the end of the packet
		 */
		if ( padding_set ) {
			padding_count = tvb_get_guint8( tvb, tvb_length( tvb ) - 1 );
			if ( padding_count > 0 ) {
				dissect_rtp_data( tvb, pinfo, tree, rtp_tree, offset, tvb_length( tvb ) - padding_count, payload_type );
				offset = tvb_length( tvb ) - padding_count;
				proto_tree_add_item( rtp_tree, hf_rtp_padding_data, tvb, offset, padding_count - 1, FALSE );
				offset += padding_count - 1;
				proto_tree_add_item( rtp_tree, hf_rtp_padding_count, tvb, offset, 1, FALSE );
			}
			else {
				proto_tree_add_item( rtp_tree, hf_rtp_padding_count, tvb, tvb_length( tvb ) - 1, 1, FALSE );
			}
		}
		else {
			dissect_rtp_data( tvb, pinfo, tree, rtp_tree, offset, tvb_length_remaining( tvb, offset ) - padding_count, payload_type );
		}
	}
}

void
proto_register_rtp(void)
{
	static hf_register_info hf[] = 
	{
		{ 
			&hf_rtp_version,
			{ 
				"Version", 
				"rtp.version", 
				FT_UINT8, 
				BASE_DEC, 
				VALS(rtp_version_vals), 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_padding,
			{ 
				"Padding", 
				"rtp.padding", 
				FT_BOOLEAN, 
				BASE_NONE, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_extension,
			{ 
				"Extension", 
				"rtp.ext", 
				FT_BOOLEAN, 
				BASE_NONE, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_csrc_count,
			{ 
				"Contributing source identifiers count", 
				"rtp.cc", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_marker,
			{ 
				"Marker", 
				"rtp.marker", 
				FT_BOOLEAN, 
				BASE_NONE, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_payload_type,
			{ 
				"Payload type", 
				"rtp.p_type", 
				FT_UINT8, 
				BASE_DEC, 
				VALS(rtp_payload_type_vals), 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_seq_nr,
			{ 
				"Sequence number", 
				"rtp.seq", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_timestamp,
			{ 
				"Timestamp", 
				"rtp.timestamp", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_ssrc,
			{ 
				"Synchronization Source identifier", 
				"rtp.ssrc", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_prof_define,
			{ 
				"Defined by profile", 
				"rtp.ext.profile", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_length,
			{ 
				"Extension length", 
				"rtp.ext.len", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_csrc_item,
			{ 
				"CSRC item", 
				"rtp.csrc.item", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_hdr_ext,
			{ 
				"Header extension", 
				"rtp.hdr_ext", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_data,
			{ 
				"Payload", 
				"rtp.payload", 
				FT_BYTES, 
				BASE_HEX, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_padding_data,
			{ 
				"Padding data", 
				"rtp.padding.data", 
				FT_BYTES, 
				BASE_HEX, 
				NULL, 
				0x0,
				"" 
			}
		},
		{ 
			&hf_rtp_padding_count,
			{ 
				"Padding count", 
				"rtp.padding.count", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"" 
			}
		},
};
	
	static gint *ett[] = 
	{
		&ett_rtp,
		&ett_csrc_list,
		&ett_hdr_ext,
	};


	proto_rtp = proto_register_protocol("Real-Time Transport Protocol",
	    "RTP", "rtp");
	proto_register_field_array(proto_rtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

#if 0
	register_init_routine( &rtp_init );
#endif
}

void
proto_reg_handoff_rtp(void)
{
	/*
	 * Register this dissector as one that can be assigned to a
	 * UDP conversation.
	 */
	conv_dissector_add("udp", dissect_rtp);
}
