/* packet-rtcp.c
 *
 * $Id: packet-rtcp.c,v 1.18 2001/07/03 04:56:45 guy Exp $
 *
 * Routines for RTCP dissection
 * RTCP = Real-time Transport Control Protocol
 * 
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
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

/*
 * This dissector tries to dissect the RTCP protocol according to Annex A
 * of ITU-T Recommendation H.225.0 (02/98) and RFC 1889
 * H.225.0 literally copies RFC 1889, but omitting a few sections.
 *
 * RTCP traffic is handled by an uneven UDP portnumber. This can be any 
 * port number, but there is a registered port available, port 5005
 * See Annex B of ITU-T Recommendation H.225.0, section B.7
 *
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

#include "packet-rtcp.h"
#if 0
#include "packet-ntp.h"
#endif
#include "conversation.h"

/* Version is the first 2 bits of the first octet*/
#define RTCP_VERSION(octet)	((octet) >> 6)

/* Padding is the third bit; no need to shift, because true is any value
   other than 0! */
#define RTCP_PADDING(octet)	((octet) & 0x20)

/* Receiver/ Sender count is the 5 last bits  */
#define RTCP_COUNT(octet)	((octet) & 0x1F)

static const value_string rtcp_version_vals[] = 
{
	{ 0, "Old VAT Version" },
	{ 1, "First Draft Version" },
	{ 2, "RFC 1889 Version" },
	{ 0, NULL },
};

/* RTCP packet types according to Section A.11.1 */
#define RTCP_SR   200
#define RTCP_RR   201
#define RTCP_SDES 202
#define RTCP_BYE  203
#define RTCP_APP  204
/* Supplemental H.261 specific RTCP packet types according to Section C.3.5 */
#define RTCP_FIR  192
#define RTCP_NACK 193

static const value_string rtcp_packet_type_vals[] = 
{
	{ RTCP_SR,   "Sender Report" },
	{ RTCP_RR,   "Receiver Report" },
	{ RTCP_SDES, "Source description" },
	{ RTCP_BYE,  "Goodbye" },
	{ RTCP_APP,  "Application specific" },
	{ RTCP_FIR,  "Full Intra-frame Request (H.261)" },
	{ RTCP_NACK, "Negative Acknowledgement (H.261)" },
	{ 0,         NULL },
};

/* RTCP SDES types (Section A.11.2) */
#define RTCP_SDES_END    0
#define RTCP_SDES_CNAME  1
#define RTCP_SDES_NAME   2
#define RTCP_SDES_EMAIL  3
#define RTCP_SDES_PHONE  4
#define RTCP_SDES_LOC    5
#define RTCP_SDES_TOOL   6
#define RTCP_SDES_NOTE   7
#define RTCP_SDES_PRIV   8

static const value_string rtcp_sdes_type_vals[] = 
{
	{ RTCP_SDES_END,   "END" },
	{ RTCP_SDES_CNAME, "CNAME (user and domain)" },
	{ RTCP_SDES_NAME,  "NAME (common name)" },
	{ RTCP_SDES_EMAIL, "EMAIL (e-mail address)" },
	{ RTCP_SDES_PHONE, "PHONE (phone number)" },
	{ RTCP_SDES_LOC,   "LOC (geographic location)" },
	{ RTCP_SDES_TOOL,  "TOOL (name/version of source app)" },
	{ RTCP_SDES_NOTE,  "NOTE (note about source)" },
	{ RTCP_SDES_PRIV,  "PRIV (private extensions)" },
	{ 0,               NULL },
};

/* RTCP header fields                   */
static int proto_rtcp                = -1;
static int hf_rtcp_version           = -1;
static int hf_rtcp_padding           = -1;
static int hf_rtcp_rc                = -1;
static int hf_rtcp_sc                = -1;
static int hf_rtcp_pt                = -1;
static int hf_rtcp_length            = -1;
static int hf_rtcp_ssrc_sender       = -1;
static int hf_rtcp_ntp               = -1;
static int hf_rtcp_rtp_timestamp     = -1;
static int hf_rtcp_sender_pkt_cnt    = -1;
static int hf_rtcp_sender_oct_cnt    = -1;
static int hf_rtcp_ssrc_source       = -1;
static int hf_rtcp_ssrc_fraction     = -1;
static int hf_rtcp_ssrc_cum_nr       = -1;
/* First the 32 bit number, then the split 
 * up 16 bit values */
/* These two are added to a subtree */
static int hf_rtcp_ssrc_ext_high_seq = -1;
static int hf_rtcp_ssrc_high_seq     = -1;
static int hf_rtcp_ssrc_high_cycles  = -1;
static int hf_rtcp_ssrc_jitter       = -1;
static int hf_rtcp_ssrc_lsr          = -1;
static int hf_rtcp_ssrc_dlsr         = -1;
static int hf_rtcp_ssrc_csrc         = -1;
static int hf_rtcp_ssrc_type         = -1;
static int hf_rtcp_ssrc_length       = -1;
static int hf_rtcp_ssrc_text         = -1;
static int hf_rtcp_ssrc_prefix_len   = -1;
static int hf_rtcp_ssrc_prefix_string= -1;
static int hf_rtcp_subtype           = -1;
static int hf_rtcp_name_ascii        = -1;
static int hf_rtcp_app_data          = -1;
static int hf_rtcp_fsn               = -1;
static int hf_rtcp_blp               = -1;
static int hf_rtcp_padding_count     = -1;
static int hf_rtcp_padding_data      = -1;

/* RTCP fields defining a sub tree */
static gint ett_rtcp           = -1;
static gint ett_ssrc           = -1;
static gint ett_ssrc_item      = -1;
static gint ett_ssrc_ext_high  = -1;
static gint ett_sdes           = -1;
static gint ett_sdes_item      = -1;

static address fake_addr;
static int heur_init = FALSE;

static char rtcp_proto[] = "RTCP";

static gboolean dissect_rtcp_heur( tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree );

void rtcp_add_address( const unsigned char* ip_addr, int prt )
{
	address src_addr;
	conversation_t* pconv = ( conversation_t* ) NULL;

	src_addr.type = AT_IPv4;
	src_addr.len = 4;
	src_addr.data = ip_addr;

	/*
	 * The first time the function is called let the udp dissector
	 * know that we're interested in traffic
	 */
	if ( ! heur_init ) {
		heur_dissector_add( "udp", dissect_rtcp_heur, proto_rtcp );
		heur_init = TRUE;
	}

	/*
	 * Check if the ip address and port combination is not 
	 * already registered
	 */
	pconv = find_conversation( &src_addr, &fake_addr, PT_UDP, prt, 0, 0 );

	/*
	 * If not, add
	 */
	if ( ! pconv ) {
		conversation_new( &src_addr, &fake_addr, PT_UDP, (guint32) prt,
		    (guint32) 0, (void*) rtcp_proto, 0 );
	}

}

#if 0
static void rtcp_init( void ) 
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

static gboolean
dissect_rtcp_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	conversation_t* pconv;

	if (!proto_is_protocol_enabled(proto_rtcp))
		return FALSE;	/* RTCP has been disabled */

	/* This is a heuristic dissector, which means we get all the UDP
	 * traffic not sent to a known dissector and not claimed by
	 * a heuristic dissector called before us!
	 * So we first check if the frame is really meant for us.
	 */
	if ( ( pconv = find_conversation( &pinfo->src, &fake_addr, pinfo->ptype,
	    pinfo->srcport, 0, 0 ) ) == NULL ) {
		/*
		 * The source ip:port combination was not what we were
		 * looking for, check the destination
		 */
		if ( ( pconv = find_conversation( &pinfo->dst, &fake_addr,
		    pinfo->ptype, pinfo->destport, 0, 0 ) ) == NULL ) {
			return FALSE;
		}
	}


	/*
	 * An RTCP conversation always contains data
	 */
	if ( pconv->data == NULL )
		return FALSE;

	/*
	 * An RTCP conversation data always contains "RTCP"
	 */
	if ( strcmp( pconv->data, rtcp_proto ) != 0 )
		return FALSE;

	/*
	 * The message is a valid RTCP message!
	 */
	dissect_rtcp( tvb, pinfo, tree );

	return TRUE;
}


static int
dissect_rtcp_nack( tvbuff_t *tvb, int offset, frame_data *fd, proto_tree *tree )
{
	/* Packet type = FIR (H261) */
	proto_tree_add_uint( tree, hf_rtcp_rc, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 31 );
	offset++;
	/* Packet type, 8 bits  = APP */
	proto_tree_add_item( tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
	offset++;

	/* Packet length in 32 bit words minus one */
	proto_tree_add_uint( tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
	offset += 2;

	/* SSRC  */
	proto_tree_add_uint( tree, hf_rtcp_ssrc_source, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
	offset += 4;
	
	/* FSN, 16 bits */
	proto_tree_add_uint( tree, hf_rtcp_fsn, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
	offset += 2;

	/* BLP, 16 bits */
	proto_tree_add_uint( tree, hf_rtcp_blp, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
	offset += 2;

	return offset;
}

static int
dissect_rtcp_fir( tvbuff_t *tvb, int offset, frame_data *fd, proto_tree *tree )
{
	/* Packet type = FIR (H261) */
	proto_tree_add_uint( tree, hf_rtcp_rc, tvb, offset, 1, tvb_get_guint8( tvb, offset ) & 31 );
	offset++;
	/* Packet type, 8 bits  = APP */
	proto_tree_add_item( tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
	offset++;

	/* Packet length in 32 bit words minus one */
	proto_tree_add_uint( tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
	offset += 2;

	/* SSRC  */
	proto_tree_add_uint( tree, hf_rtcp_ssrc_source, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
	offset += 4;
	
	return offset;
}

static int
dissect_rtcp_app( tvbuff_t *tvb, int offset, frame_data *fd, proto_tree *tree,
    unsigned int padding, unsigned int packet_len )
{
	unsigned int counter = 0;
	char ascii_name[5];

	/* SSRC / CSRC */
	proto_tree_add_uint( tree, hf_rtcp_ssrc_source, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
	offset += 4;
	packet_len -= 4;

	/* Name (ASCII) */
	for( counter = 0; counter < 4; counter++ )
	    ascii_name[ counter ] = tvb_get_guint8( tvb, offset + counter );
	/* strncpy( ascii_name, pd + offset, 4 ); */
	ascii_name[4] = '\0';
	proto_tree_add_string( tree, hf_rtcp_name_ascii, tvb, offset, 4,
	    ascii_name );
	offset += 4;
	packet_len -= 4;

	/* Applications specific data */
	if ( padding ) {
		/* If there's padding present, we have to remove that from the data part 
		 * The last octet of the packet contains the length of the padding
		 */
		packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
	}
	proto_tree_add_item( tree, hf_rtcp_app_data, tvb, offset, packet_len, FALSE );
	offset += packet_len;

	return offset;
}

static int
dissect_rtcp_bye( tvbuff_t *tvb, int offset, frame_data *fd, proto_tree *tree,
    int count )
{
	unsigned int chunk          = 1;
	unsigned int reason_length  = 0;
	unsigned int counter = 0;
	char* reason_text = NULL;

	while ( chunk <= count ) {
		/* source identifier, 32 bits */
		proto_tree_add_uint( tree, hf_rtcp_ssrc_source, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
		offset += 4;
	}

	/* Bye reason consists of an 8 bit length l and a string with length l */
	reason_length = tvb_get_guint8( tvb, offset );
	proto_tree_add_item( tree, hf_rtcp_ssrc_length, tvb, offset, 1, FALSE );
	offset++;

	reason_text = ( char* ) malloc( reason_length + 1 );
	for ( counter = 0; counter < reason_length; counter++ ) reason_text[ counter ] = tvb_get_guint8( tvb, offset + counter );
	/* strncpy( reason_text, pd + offset, reason_length ); */
	reason_text[ reason_length ] = '\0';
	proto_tree_add_string( tree, hf_rtcp_ssrc_text, tvb, offset, reason_length, reason_text );
	free( reason_text );
	offset += reason_length;

	return offset;

}

static int
dissect_rtcp_sdes( tvbuff_t *tvb, int offset, frame_data *fd, proto_tree *tree,
    int count )
{
	unsigned int chunk          = 1;
	proto_item *sdes_item;
	proto_tree *sdes_tree;
	proto_tree *sdes_item_tree;
	proto_item *ti;
	int start_offset;
	int items_start_offset;
	guint32 ssrc;
	unsigned int item_len       = 0;
	unsigned int sdes_type      = 0;
	unsigned int counter        = 0;
	unsigned int prefix_len     = 0;
	char *prefix_string = NULL;
	
	while ( chunk <= count ) {
		/* Create a subtree for this chunk; we don't yet know
		   the length. */
		start_offset = offset;

		ssrc = tvb_get_ntohl( tvb, offset );
		sdes_item = proto_tree_add_text(tree, tvb, offset, 0,
		    "Chunk %u, SSRC/CSRC %u", chunk, ssrc);
		sdes_tree = proto_item_add_subtree( sdes_item, ett_sdes );

		/* SSRC_n source identifier, 32 bits */
		proto_tree_add_uint( sdes_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ssrc );
		offset += 4;

		/* Create a subtree for the SDES items; we don't yet know
		   the length */	
		items_start_offset = offset;
		ti = proto_tree_add_text(sdes_tree, tvb, offset, 0,
		    "SDES items" );
		sdes_item_tree = proto_item_add_subtree( ti, ett_sdes_item );
		
		/*
		 * Not every message is ended with "null" bytes, so check for
		 * end of frame instead.
		 */
		while ( ( tvb_get_guint8( tvb, offset ) != RTCP_SDES_END )
		    && ( tvb_bytes_exist( tvb, offset, 2) ) ) {
			/* ID, 8 bits */
			sdes_type = tvb_get_guint8( tvb, offset );
			proto_tree_add_item( sdes_item_tree, hf_rtcp_ssrc_type, tvb, offset, 1, FALSE );
			offset++;

			/* Item length, 8 bits */
			item_len = tvb_get_guint8( tvb, offset );
			proto_tree_add_item( sdes_item_tree, hf_rtcp_ssrc_length, tvb, offset, 1, FALSE );
			offset++;

			if ( sdes_type == RTCP_SDES_PRIV ) {
				/* PRIV adds two items between the SDES length
				 * and value - an 8 bit length giving the
				 * length of a "prefix string", and the string.
				 */
				prefix_len = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( sdes_item_tree, hf_rtcp_ssrc_prefix_len, tvb, offset, 1, FALSE );
				offset++;

				prefix_string = ( char * ) malloc( prefix_len + 1 );
				for ( counter = 0; counter < prefix_len; counter++ )
					prefix_string[ counter ] =
					    tvb_get_guint8( tvb, offset + counter );
				/* strncpy( prefix_string, pd + offset, prefix_len ); */
				prefix_string[ prefix_len ] = '\0';
				proto_tree_add_string( sdes_item_tree, hf_rtcp_ssrc_prefix_string, tvb, offset, prefix_len, prefix_string );
				free( prefix_string );
				offset += prefix_len;
			}
			prefix_string = ( char * ) malloc( item_len + 1 );
			for ( counter = 0; counter < item_len; counter++ )
			    prefix_string[ counter ] =
			        tvb_get_guint8( tvb, offset + counter );
			/* strncpy( prefix_string, pd + offset, item_len ); */
			prefix_string[ item_len] = 0;
			proto_tree_add_string( sdes_item_tree, hf_rtcp_ssrc_text, tvb, offset, item_len, prefix_string );
			free( prefix_string );
			offset += item_len;
		}

		/* Set the length of the items subtree. */
		proto_item_set_len(ti, offset - items_start_offset);

		/* 32 bits = 4 bytes, so..... 
		 * If offset % 4 != 0, we divide offset by 4, add one and then 
		 * multiply by 4 again to reach the boundary
		 */
		if ( offset % 4 != 0 )
			offset = ((offset / 4) + 1 ) * 4;

		/* Set the length of this chunk. */
		proto_item_set_len(sdes_item, offset - start_offset);

		chunk++;
	}


	return offset;
}

static int
dissect_rtcp_rr( tvbuff_t *tvb, int offset, frame_data *fd, proto_tree *tree,
    int count )
{
	unsigned int counter = 1;
	proto_tree *ssrc_tree = (proto_tree*) NULL;
	proto_tree *ssrc_sub_tree = (proto_tree*) NULL;
	proto_tree *high_sec_tree = (proto_tree*) NULL;
	proto_item *ti = (proto_item*) NULL;
	guint8 rr_flt;
	unsigned int cum_nr = 0;

	while ( counter <= count ) {
		/* Create a new subtree for a length of 24 bytes */
		ti = proto_tree_add_text(tree, tvb, offset, 24,
		    "Source %u", counter );
		ssrc_tree = proto_item_add_subtree( ti, ett_ssrc );
		
		/* SSRC_n source identifier, 32 bits */
		proto_tree_add_uint( ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
		offset += 4;
	
		ti = proto_tree_add_text(ssrc_tree, tvb, offset, 20, "SSRC contents" );
		ssrc_sub_tree = proto_item_add_subtree( ti, ett_ssrc_item );

		/* Fraction lost, 8bits */
		rr_flt = tvb_get_guint8( tvb, offset );
		proto_tree_add_uint_format( ssrc_sub_tree, hf_rtcp_ssrc_fraction, tvb,
		    offset, 1, rr_flt, "Fraction lost: %u / 256", rr_flt );
		offset++;

		/* Cumulative number of packets lost, 24 bits */
		cum_nr = tvb_get_ntohl( tvb, offset ) >> 8;
		proto_tree_add_uint( ssrc_sub_tree, hf_rtcp_ssrc_cum_nr, tvb,
		    offset, 3, cum_nr );
		offset += 3;

		/* Extended highest sequence nr received, 32 bits
		 * Just for the sake of it, let's add another subtree
		 * because this might be a little clearer
		 */
		ti = proto_tree_add_uint( ssrc_tree, hf_rtcp_ssrc_ext_high_seq,
		    tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
		high_sec_tree = proto_item_add_subtree( ti, ett_ssrc_ext_high );
		/* Sequence number cycles */
		proto_tree_add_uint( high_sec_tree, hf_rtcp_ssrc_high_cycles,
		    tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
		offset += 2;
		/* highest sequence number received */
		proto_tree_add_uint( high_sec_tree, hf_rtcp_ssrc_high_seq,
		    tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
		offset += 2;

		/* Interarrival jitter */
		proto_tree_add_uint( ssrc_tree, hf_rtcp_ssrc_jitter, tvb,
		    offset, 4, tvb_get_ntohl( tvb, offset ) );
		offset += 4;

		/* Last SR timestamp */
		proto_tree_add_uint( ssrc_tree, hf_rtcp_ssrc_lsr, tvb,
		    offset, 4, tvb_get_ntohl( tvb, offset ) );
		offset += 4;

		/* Delay since last SR timestamp */
		proto_tree_add_uint( ssrc_tree, hf_rtcp_ssrc_dlsr, tvb,
		    offset, 4, tvb_get_ntohl( tvb, offset ) );
		offset += 4;
		counter++;
	}

	return offset;
}

static int
dissect_rtcp_sr( tvbuff_t *tvb, int offset, frame_data *fd, proto_tree *tree,
    int count )
{
#if 0
	gchar buff[ NTP_TS_SIZE ];
	char* ptime = tvb_get_ptr( tvb, offset, 8 );

	/* Retreive the NTP timestamp. Using the NTP dissector for this */
	ntp_fmt_ts( ptime, buff );
	proto_tree_add_string_format( tree, hf_rtcp_ntp, tvb, offset, 8, ( const char* ) &buff, "NTP timestamp: %s", &buff );
	free( ptime ); ??????????????????????????????????????????????????????????????????
	offset += 8;
#else
	/*
	 * XXX - RFC 1889 says this is an NTP timestamp, but that appears
	 * not to be the case.
	 */
	proto_tree_add_text(tree, tvb, offset, 4, "Timestamp, MSW: %u",
		tvb_get_ntohl(tvb, offset));
	offset += 4;
	proto_tree_add_text(tree, tvb, offset, 4, "Timestamp, LSW: %u",
		tvb_get_ntohl(tvb, offset));
	offset += 4;
#endif
	/* RTP timestamp, 32 bits */
	proto_tree_add_uint( tree, hf_rtcp_rtp_timestamp, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
	offset += 4;
	/* Sender's packet count, 32 bits */
	proto_tree_add_uint( tree, hf_rtcp_sender_pkt_cnt, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
	offset += 4;
	/* Sender's octet count, 32 bits */
	proto_tree_add_uint( tree, hf_rtcp_sender_oct_cnt, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
	offset += 4;

	/* The rest of the packet is equal to the RR packet */
	if ( count > 0 )
		offset = dissect_rtcp_rr( tvb, offset, fd, tree, count );

	return offset;
}

void
dissect_rtcp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti           = NULL;
	proto_tree *rtcp_tree    = NULL;
	unsigned int temp_byte   = 0;
	unsigned int padding_set = 0;
	unsigned int elem_count  = 0;
	unsigned int packet_type = 0;
	unsigned int offset      = 0;
	guint16 packet_length    = 0;

	CHECK_DISPLAY_AS_DATA(proto_rtcp, tvb, pinfo, tree);

	pinfo->current_proto = "RTCP";

	if ( check_col( pinfo->fd, COL_PROTOCOL ) )   {
		col_set_str( pinfo->fd, COL_PROTOCOL, "RTCP" );
	}
	
	if ( check_col( pinfo->fd, COL_INFO) ) {
		/* The second octet contains the packet type */
		/* switch ( pd[ offset + 1 ] ) { */
		switch ( tvb_get_guint8( tvb, 1 ) ) {
			case RTCP_SR:
				col_set_str( pinfo->fd, COL_INFO, "Sender Report");
				break;
			case RTCP_RR:
				col_set_str( pinfo->fd, COL_INFO, "Receiver Report");
				break;
			case RTCP_SDES:
				col_set_str( pinfo->fd, COL_INFO, "Source Description");
				break;
			case RTCP_BYE:
				col_set_str( pinfo->fd, COL_INFO, "Goodbye");
				break;
			case RTCP_APP:
				col_set_str( pinfo->fd, COL_INFO, "Application defined");
				break;
			case RTCP_FIR:
				col_set_str( pinfo->fd, COL_INFO, "Full Intra-frame Request (H.261)");
				break;
			case RTCP_NACK:
				col_set_str( pinfo->fd, COL_INFO, "Negative Acknowledgement (H.261)");
				break;
			default:
				col_set_str( pinfo->fd, COL_INFO, "Unknown packet type");
				break;
		}
	}

	if ( tree ) {

		/* 
		 * Check if there are at least 4 bytes left in the frame, 
		 * the last 16 bits of those is the length of the current 
		 * RTCP message. The last compound message contains padding,
		 * that enables us to break from the while loop.
		 */
		while ( tvb_bytes_exist( tvb, offset, 4) ) {
			/* 
			 * First retreive the packet_type
			 */
			packet_type = tvb_get_guint8( tvb, offset + 1 );

			/*
			 * Check if it's a valid type
			 */
			if ( ( packet_type < 192 ) || ( packet_type >  204 ) )
				break;
			
			/*
			 * get the packet-length for the complete RTCP packet
			 */
			packet_length = ( tvb_get_ntohs( tvb, offset + 2 ) + 1 ) * 4;

			ti = proto_tree_add_item(tree, proto_rtcp, tvb, offset, packet_length, FALSE ); 
			rtcp_tree = proto_item_add_subtree( ti, ett_rtcp );

			temp_byte = tvb_get_guint8( tvb, offset );

			proto_tree_add_uint( rtcp_tree, hf_rtcp_version, tvb,
			    offset, 1, RTCP_VERSION( temp_byte ) );
			padding_set = RTCP_PADDING( temp_byte );
			proto_tree_add_boolean( rtcp_tree, hf_rtcp_padding, tvb,
			    offset, 1, padding_set );
			elem_count = RTCP_COUNT( temp_byte );

			switch ( packet_type ) {
				case RTCP_SR:
				case RTCP_RR:
					/* Receiver report count, 5 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_rc, tvb, offset, 1, elem_count );
					offset++;
					/* Packet type, 8 bits */
					proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
					offset++;
					/* Packet length in 32 bit words MINUS one, 16 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
					offset += 2;
					/* Sender Synchronization source, 32 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_ssrc_sender, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
					offset += 4;

					if ( packet_type == RTCP_SR ) offset = dissect_rtcp_sr( tvb, offset, pinfo->fd, rtcp_tree, elem_count );
					else offset = dissect_rtcp_rr( tvb, offset, pinfo->fd, rtcp_tree, elem_count );
					break;
				case RTCP_SDES:
					/* Source count, 5 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_sc, tvb, offset, 1, elem_count );
					offset++;
					/* Packet type, 8 bits */
					proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
					offset++;
					/* Packet length in 32 bit words MINUS one, 16 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
					offset += 2;
					offset = dissect_rtcp_sdes( tvb, offset, pinfo->fd, rtcp_tree, elem_count );
					break;
				case RTCP_BYE:
					/* Source count, 5 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_sc, tvb, offset, 1, elem_count );
					offset++;
					/* Packet type, 8 bits */
					proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
					offset++;
					/* Packet length in 32 bit words MINUS one, 16 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
					offset += 2;
					offset = dissect_rtcp_bye( tvb, offset, pinfo->fd, rtcp_tree, elem_count );
					break;
				case RTCP_APP:
					/* Subtype, 5 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_subtype, tvb, offset, 1, elem_count );
					offset++;
					/* Packet type, 8 bits */
					proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
					offset++;
					/* Packet length in 32 bit words MINUS one, 16 bits */
					proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
					offset += 2;
					offset = dissect_rtcp_app( tvb, offset,
					    pinfo->fd, rtcp_tree, padding_set,
					    packet_length - 4 );
					break;
				case RTCP_FIR:
					offset = dissect_rtcp_fir( tvb, offset, pinfo->fd, rtcp_tree );
					break;
				case RTCP_NACK:
					offset = dissect_rtcp_nack( tvb, offset, pinfo->fd, rtcp_tree );
					break;
				default:
					/*
					 * To prevent endless loops in case of an unknown message type
					 * increase offset. Some time the while will end :-)
					 */
					offset++;
					break;
			}
		}
		/* If the padding bit is set, the last octet of the 
		 * packet contains the length of the padding 
		 * We only have to check for this at the end of the LAST RTCP message
		 */
		if ( padding_set ) {
			/* If everything went according to plan offset should now point to the 
			 * first octet of the padding 
			 */
			proto_tree_add_item( rtcp_tree, hf_rtcp_padding_data, tvb, offset, tvb_length_remaining( tvb, offset) - 1, FALSE );
			offset += tvb_length_remaining( tvb, offset) - 1;
			proto_tree_add_item( rtcp_tree, hf_rtcp_padding_count, tvb, offset, 1, FALSE );
		}
	}
}

void
proto_register_rtcp(void)
{
	static hf_register_info hf[] = 
	{
		{ 
			&hf_rtcp_version,
			{ 
				"Version", 
				"rtcp.version", 
				FT_UINT8, 
				BASE_DEC, 
				VALS(rtcp_version_vals), 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_padding,
			{ 
				"Padding", 
				"rtcp.padding", 
				FT_BOOLEAN, 
				BASE_NONE, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_rc,
			{ 
				"Reception report count", 
				"rtcp.rc", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_sc,
			{ 
				"Source count", 
				"rtcp.sc", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_pt,
			{ 
				"Packet type", 
				"rtcp.pt", 
				FT_UINT8, 
				BASE_DEC, 
				VALS( rtcp_packet_type_vals ), 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_length,
			{ 
				"Length", 
				"rtcp.length", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_sender,
			{ 
				"Sender SSRC", 
				"rtcp.senderssrc", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ntp,
			{ 
				"NTP timestamp", 
				"rtcp.timestamp.ntp", 
				FT_STRING, 
				BASE_NONE, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_rtp_timestamp,
			{ 
				"RTP timestamp", 
				"rtcp.timestamp.rtp", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_sender_pkt_cnt,
			{ 
				"Sender's packet count", 
				"rtcp.sender.packetcount", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_sender_oct_cnt,
			{ 
				"Sender's octet count", 
				"rtcp.sender.octetcount", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_source,
			{ 
				"Identifier", 
				"rtcp.ssrc.identifier", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_fraction,
			{ 
				"Fraction lost", 
				"rtcp.ssrc.fraction", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_cum_nr,
			{ 
				"Cumulative number of packets lost", 
				"rtcp.ssrc.cum_nr", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_ext_high_seq,
			{ 
				"Extended highest sequence number received", 
				"rtcp.ssrc.ext_high", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_high_seq,
			{ 
				"Highest sequence number received", 
				"rtcp.ssrc.high_seq", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_high_cycles,
			{ 
				"Sequence number cycles count", 
				"rtcp.ssrc.high_cycles", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_jitter,
			{ 
				"Interarrival jitter", 
				"rtcp.ssrc.jitter", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_lsr,
			{ 
				"Last SR timestamp", 
				"rtcp.ssrc.lsr", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_dlsr,
			{ 
				"Delay since last SR timestamp", 
				"rtcp.ssrc.dlsr", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_csrc,
			{ 
				"SSRC / CSRC identifier", 
				"rtcp.sdes.ssrc_csrc", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_type,
			{ 
				"Type", 
				"rtcp.sdes.type", 
				FT_UINT8, 
				BASE_DEC, 
				VALS( rtcp_sdes_type_vals ), 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_length,
			{ 
				"Length", 
				"rtcp.sdes.length", 
				FT_UINT32, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_text,
			{ 
				"Text", 
				"rtcp.sdes.text", 
				FT_STRING, 
				BASE_NONE, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_prefix_len,
			{ 
				"Prefix length", 
				"rtcp.sdes.prefix.length", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_ssrc_prefix_string,
			{ 
				"Prefix string", 
				"rtcp.sdes.prefix.string", 
				FT_STRING, 
				BASE_NONE, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_subtype,
			{ 
				"Subtype", 
				"rtcp.app.subtype", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_name_ascii,
			{ 
				"Name (ASCII)", 
				"rtcp.app.name", 
				FT_STRING, 
				BASE_NONE, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_app_data,
			{ 
				"Application specific data", 
				"rtcp.app.data", 
				FT_BYTES, 
				BASE_NONE, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_fsn,
			{ 
				"First sequence number", 
				"rtcp.nack.fsn", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_blp,
			{ 
				"Bitmask of following lost packets", 
				"rtcp.nack.blp", 
				FT_UINT16, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_padding_count,
			{ 
				"Padding count", 
				"rtcp.padding.count", 
				FT_UINT8, 
				BASE_DEC, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
		{ 
			&hf_rtcp_padding_data,
			{ 
				"Padding data", 
				"rtcp.padding.data", 
				FT_BYTES, 
				BASE_NONE, 
				NULL, 
				0x0,
				"", HFILL 
			}
		},
};
	
	static gint *ett[] = 
	{
		&ett_rtcp,
		&ett_ssrc,
		&ett_ssrc_item,
		&ett_ssrc_ext_high,
		&ett_sdes,
		&ett_sdes_item,
	};


	proto_rtcp = proto_register_protocol("Real-time Transport Control Protocol",
	    "RTCP", "rtcp");
	proto_register_field_array(proto_rtcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

#if 0
	register_init_routine( &rtcp_init );
#endif
}

void
proto_reg_handoff_rtcp(void)
{
	/*
	 * Register this dissector as one that can be assigned to a
	 * UDP conversation.
	 */
	conv_dissector_add("udp", dissect_rtcp, proto_rtcp);
}
