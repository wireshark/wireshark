/* packet-rtcp.c
 *
 * $Id$
 *
 * Routines for RTCP dissection
 * RTCP = Real-time Transport Control Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <h323@ramdyne.nl>
 *
 * Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * See also http://www.iana.org/assignments/rtp-parameters
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "packet-rtcp.h"
#if 0
#include "packet-ntp.h"
#endif
#include <epan/conversation.h>

#include <epan/prefs.h>


/* Version is the first 2 bits of the first octet*/
#define RTCP_VERSION(octet)	((octet) >> 6)

/* Padding is the third bit; no need to shift, because true is any value
   other than 0! */
#define RTCP_PADDING(octet)	((octet) & 0x20)

/* Receiver/ Sender count is the 5 last bits  */
#define RTCP_COUNT(octet)	((octet) & 0x1F)

static dissector_handle_t rtcp_handle;

static const value_string rtcp_version_vals[] =
{
	{ 0, "Old VAT Version" },
	{ 1, "First Draft Version" },
	{ 2, "RFC 1889 Version" },
	{ 0, NULL },
};

/* RTCP packet types according to Section A.11.1 */
/* And http://www.iana.org/assignments/rtp-parameters */
#define RTCP_SR   200
#define RTCP_RR   201
#define RTCP_SDES 202
#define RTCP_BYE  203
#define RTCP_APP  204
#define RTCP_XR	  207
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
	{ RTCP_XR,   "Extended report"},
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
#define RTCP_SDES_H323_CADDR   9

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
	{ RTCP_SDES_H323_CADDR,"H323-CADDR (H.323 callable address)"},
	{ 0,               NULL },
};
/* RTCP Application PoC1 Value strings */
static const value_string rtcp_app_poc1_floor_cnt_type_vals[] =
{
	{  0,   "Floor Request"},
	{  1,   "Floor Grant"},
	{  2,   "Floor Taken"},
	{  3,   "Floor Deny"},
	{  4,   "Floor Release"},
	{  5,   "Floor Idle"},
	{  6,   "Floor Revoke"},
	{  0,   NULL },
};

static const value_string rtcp_app_poc1_reason_code1_vals[] =
{
	{  1,   "Floor already in use"},
	{  2,   "Internal PoC server error"},
	{  3,	"Only one participant in the group "},
	{  0,   NULL },
};

static const value_string rtcp_app_poc1_reason_code2_vals[] =
{
	{  1,   "Only one user"},
	{  2,   "Talk burst too long"},
	{  3,	"No access to floor"},
	{  0,   NULL },
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
static int hf_rtcp_app_poc1_subtype  = -1;
static int hf_rtcp_app_poc1_sip_uri  = -1;
static int hf_rtcp_app_poc1_disp_name = -1;
static int hf_rtcp_app_poc1_last_pkt_seq_no = -1;
static int hf_rtcp_app_poc1_reason_code1	= -1;
static int hf_rtcp_app_poc1_item_len		= -1;
static int hf_rtcp_app_poc1_reason1_phrase	= -1;
static int hf_rtcp_app_poc1_reason_code2	= -1;
static int hf_rtcp_app_poc1_additionalinfo	= -1;

/* RTCP setup fields */
static int hf_rtcp_setup        = -1;
static int hf_rtcp_setup_frame  = -1;
static int hf_rtcp_setup_method = -1;

/* RTCP roundtrip delay fields */
static int hf_rtcp_roundtrip_delay        = -1;
static int hf_rtcp_roundtrip_delay_frame  = -1;
static int hf_rtcp_roundtrip_delay_delay  = -1;



/* RTCP fields defining a sub tree */
static gint ett_rtcp			= -1;
static gint ett_ssrc			= -1;
static gint ett_ssrc_item		= -1;
static gint ett_ssrc_ext_high		= -1;
static gint ett_sdes			= -1;
static gint ett_sdes_item		= -1;
static gint ett_PoC1			= -1;
static gint ett_rtcp_setup		= -1;
static gint ett_rtcp_roundtrip_delay	= -1;

/* Main dissection function */
static void dissect_rtcp( tvbuff_t *tvb, packet_info *pinfo,
     proto_tree *tree );

/* Heuristic dissection */
static gboolean global_rtcp_heur = FALSE;
static gboolean dissect_rtcp_heur( tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree );

/* Displaying set info */
static gboolean global_rtcp_show_setup_info = TRUE;
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

/* Related to roundtrip calculation (using LSR and DLSR) */
static gboolean global_rtcp_show_roundtrip_calculation = FALSE;
#define MIN_ROUNDTRIP_TO_REPORT_DEFAULT 10
static guint global_rtcp_show_roundtrip_calculation_minimum = MIN_ROUNDTRIP_TO_REPORT_DEFAULT;
static void remember_outgoing_sr(packet_info *pinfo, long lsr);
static void calculate_roundtrip_delay(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, guint32 lsr, guint32 dlsr);
static void add_roundtrip_delay_info(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, guint frame, guint delay);


/* Memory chunk for storing conversation and per-packet info */
static GMemChunk *rtcp_conversations = NULL;

/* Set up an RTCP conversation using the info given */
void rtcp_add_address( packet_info *pinfo,
                       address *addr, int port,
                       int other_port,
                       gchar *setup_method, guint32 setup_frame_number)
{
	address null_addr;
	conversation_t* p_conv;
	struct _rtcp_conversation_info *p_conv_data = NULL;

	/*
	 * If this isn't the first time this packet has been processed,
	 * we've already done this work, so we don't need to do it
	 * again.
	 */
	if (pinfo->fd->flags.visited)
	{
		return;
	}

	SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

	/*
	 * Check if the ip address and port combination is not
	 * already registered as a conversation.
	 */
	p_conv = find_conversation( addr, &null_addr, PT_UDP, port, other_port,
	                            NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

	/*
	 * If not, create a new conversation.
	 */
	if ( ! p_conv ) {
		p_conv = conversation_new( addr, &null_addr, PT_UDP,
		                           (guint32)port, (guint32)other_port,
		                           NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
	}

	/* Set dissector */
	conversation_set_dissector(p_conv, rtcp_handle);

	/*
	 * Check if the conversation has data associated with it.
	 */
	p_conv_data = conversation_get_proto_data(p_conv, proto_rtcp);

	/*
	 * If not, add a new data item.
	 */
	if ( ! p_conv_data ) {
		/* Create conversation data */
		p_conv_data = g_mem_chunk_alloc(rtcp_conversations);
		if (!p_conv_data)
		{
			return;
		}
		memset(p_conv_data, 0, sizeof(struct _rtcp_conversation_info));
		conversation_add_proto_data(p_conv, proto_rtcp, p_conv_data);
	}

	/*
	 * Update the conversation data.
	 */
	p_conv_data->setup_method_set = TRUE;
	strncpy(p_conv_data->setup_method, setup_method, MAX_RTCP_SETUP_METHOD_SIZE);
	p_conv_data->setup_method[MAX_RTCP_SETUP_METHOD_SIZE] = '\0';
	p_conv_data->setup_frame_number = setup_frame_number;
}

static void rtcp_init( void )
{
	/* (Re)allocate mem chunk for conversations */
	if (rtcp_conversations)
	{
		g_mem_chunk_destroy(rtcp_conversations);
	}
	rtcp_conversations = g_mem_chunk_new("rtcp_conversations",
	                                     sizeof(struct _rtcp_conversation_info),
	                                     20 * sizeof(struct _rtcp_conversation_info),
	                                     G_ALLOC_ONLY);
}

static gboolean
dissect_rtcp_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
 	unsigned int offset = 0;
	unsigned int first_byte;
	unsigned int packet_type;

	/* This is a heuristic dissector, which means we get all the UDP
	 * traffic not sent to a known dissector and not claimed by
	 * a heuristic dissector called before us!
	 */

	if (!global_rtcp_heur)
	{
		return FALSE;
	}

	/* Was it sent between 2 odd-numbered ports? */
	if (!(pinfo->srcport % 2) || !(pinfo->destport % 2))
	{
		return FALSE;
	}

	/* Look at first byte */
	first_byte = tvb_get_guint8(tvb, offset);

	/* Are version bits set to 2? */
	if (((first_byte & 0xC0) >> 6) != 2)
	{
		return FALSE;
	}

	/* Look at packet type */
	packet_type = tvb_get_guint8(tvb, offset + 1);

	/* First packet within compound packet is supposed to be a sender
	   or receiver report.  Also see BYE so allow this...  */
	if (!((packet_type == RTCP_SR)  || (packet_type == RTCP_RR) ||
           packet_type == RTCP_BYE))
	{
		return FALSE;
	}

	/* Overall length must be a multiple of 4 bytes */
	if (tvb_length(tvb) % 4)
	{
		return FALSE;
	}

	/* OK, dissect as RTCP */
	dissect_rtcp(tvb, pinfo, tree);
	return TRUE;
}


static int
dissect_rtcp_nack( tvbuff_t *tvb, int offset, proto_tree *tree )
{
	/* Packet type = FIR (H261) */
	proto_tree_add_uint( tree, hf_rtcp_rc, tvb, offset, 1, tvb_get_guint8( tvb, offset ) );
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
dissect_rtcp_fir( tvbuff_t *tvb, int offset, proto_tree *tree )
{
	/* Packet type = FIR (H261) */
	proto_tree_add_uint( tree, hf_rtcp_rc, tvb, offset, 1, tvb_get_guint8( tvb, offset ) );
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
dissect_rtcp_app( tvbuff_t *tvb,packet_info *pinfo, int offset, proto_tree *tree,
    unsigned int padding, unsigned int packet_len, guint rtcp_subtype )
{
	unsigned int counter = 0;
	char ascii_name[5];
	guint sdes_type		= 0;
	guint item_len		= 0;
	guint items_start_offset;
	proto_tree *PoC1_tree;
	proto_item *PoC1_item;

	/* XXX If more application types are to be dissected it may be useful to use a table like in packet-sip.c */
	static const char app_name_str[] = "PoC1";


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
	if ( strncasecmp(ascii_name,app_name_str,4 ) != 0 ){ /* Not PoC1 */
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO,"( %s ) subtype=%u",ascii_name, rtcp_subtype);
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
	}else{/* PoC1 Application */
		proto_item *item;
		item = proto_tree_add_uint( tree, hf_rtcp_app_poc1_subtype, tvb, offset - 8, 1, rtcp_subtype );
		PROTO_ITEM_SET_GENERATED(item);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO,"(%s) subtype=%s",ascii_name,
				val_to_str(rtcp_subtype,rtcp_app_poc1_floor_cnt_type_vals,"unknown (%u)") );
		offset += 4;
		packet_len -= 4;
		/* Applications specific data */
		if ( padding ) {
			/* If there's padding present, we have to remove that from the data part
			* The last octet of the packet contains the length of the padding
			*/
			packet_len -= tvb_get_guint8( tvb, offset + packet_len - 1 );
		}
		/* Create a subtree for the PoC1 Application items; we don't yet know
		   the length */
		items_start_offset = offset;

		PoC1_item = proto_tree_add_text(tree, tvb, offset, packet_len,
		    "PoC1 Application specific data");
		PoC1_tree = proto_item_add_subtree( PoC1_item, ett_PoC1 );


		proto_tree_add_item( PoC1_tree, hf_rtcp_app_data, tvb, offset, packet_len, FALSE );
		switch ( rtcp_subtype ) {
			case 2:
				sdes_type = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_ssrc_type, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				/* Item length, 8 bits */
				item_len = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_ssrc_length, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_sip_uri, tvb, offset, item_len, FALSE );
				offset = offset + item_len;
				packet_len = packet_len - item_len;
				sdes_type = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_ssrc_type, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				/* Item length, 8 bits */
				item_len = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_ssrc_length, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				if ( item_len != 0 )
					proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_disp_name, tvb, offset, item_len, FALSE );
				offset = offset + item_len;
				packet_len = packet_len - item_len;
				break;
			case 3:
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason_code1, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				/* Item length, 8 bits */
				item_len = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_item_len, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				if ( item_len != 0 )
					proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason1_phrase, tvb, offset, item_len, FALSE );
				offset = offset + item_len;
				packet_len = packet_len - item_len;
				break;
			case 4:
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_last_pkt_seq_no, tvb, offset, 2, FALSE );
				proto_tree_add_text(PoC1_tree, tvb, offset + 2, 2, "Padding 2 bytes");
				offset += 4;
				packet_len-=4;
				break;
			case 6:
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason_code2, tvb, offset, 2, FALSE );
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_additionalinfo, tvb, offset + 2, 2, FALSE );
				offset += 4;
				packet_len-=4;
				break;
			default:
				break;
		}
		offset += packet_len;
		return offset;
	}
}


static int
dissect_rtcp_bye( tvbuff_t *tvb, int offset, proto_tree *tree,
    unsigned int count )
{
	unsigned int chunk          = 1;
	unsigned int reason_length  = 0;
	char* reason_text = NULL;

	while ( chunk <= count ) {
		/* source identifier, 32 bits */
		proto_tree_add_item( tree, hf_rtcp_ssrc_source, tvb, offset, 4, FALSE);
		offset += 4;
		chunk++;
	}

	if ( tvb_reported_length_remaining( tvb, offset ) > 0 ) {
		/* Bye reason consists of an 8 bit length l and a string with length l */
		reason_length = tvb_get_guint8( tvb, offset );
		proto_tree_add_item( tree, hf_rtcp_ssrc_length, tvb, offset, 1, FALSE );
		offset++;

		reason_text = tvb_get_string(tvb, offset, reason_length);
		proto_tree_add_string( tree, hf_rtcp_ssrc_text, tvb, offset, reason_length, reason_text );
		g_free( reason_text );
		offset += reason_length;
	}

	return offset;

}

static void
dissect_rtcp_sdes( tvbuff_t *tvb, int offset, proto_tree *tree,
    unsigned int count )
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
		if (ssrc == 0) {
		    /* According to RFC1889 section 6.4:
		     * "The list of items in each chunk is terminated by one or more
		     * null octets, the first of which is interpreted as an item type
		     * of zero to denote the end of the list, and the remainder as
		     * needed to pad until the next 32-bit boundary.
		     *
		     * A chunk with zero items (four null octets) is valid but useless."
		     */
		    proto_tree_add_text(tree, tvb, offset, 4, "Padding");
		    offset += 4;
		    continue;
		}
		sdes_item = proto_tree_add_text(tree, tvb, offset, -1,
		    "Chunk %u, SSRC/CSRC %u", chunk, ssrc);
		sdes_tree = proto_item_add_subtree( sdes_item, ett_sdes );

		/* SSRC_n source identifier, 32 bits */
		proto_tree_add_uint( sdes_tree, hf_rtcp_ssrc_source, tvb, offset, 4, ssrc );
		offset += 4;

		/* Create a subtree for the SDES items; we don't yet know
		   the length */
		items_start_offset = offset;
		ti = proto_tree_add_text(sdes_tree, tvb, offset, -1,
		    "SDES items" );
		sdes_item_tree = proto_item_add_subtree( ti, ett_sdes_item );

		/*
		 * Not every message is ended with "null" bytes, so check for
		 * end of frame instead.
		 */
		while ( ( tvb_reported_length_remaining( tvb, offset ) > 0 )
		    && ( tvb_get_guint8( tvb, offset ) != RTCP_SDES_END ) ) {
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

				prefix_string = g_malloc( prefix_len + 1 );
				for ( counter = 0; counter < prefix_len; counter++ )
					prefix_string[ counter ] =
					    tvb_get_guint8( tvb, offset + counter );
				/* strncpy( prefix_string, pd + offset, prefix_len ); */
				prefix_string[ prefix_len ] = '\0';
				proto_tree_add_string( sdes_item_tree, hf_rtcp_ssrc_prefix_string, tvb, offset, prefix_len, prefix_string );
				g_free( prefix_string );
				offset += prefix_len;
			}
			prefix_string = g_malloc( item_len + 1 );
			for ( counter = 0; counter < item_len; counter++ )
			    prefix_string[ counter ] =
			        tvb_get_guint8( tvb, offset + counter );
			/* strncpy( prefix_string, pd + offset, item_len ); */
			prefix_string[ item_len] = 0;
			proto_tree_add_string( sdes_item_tree, hf_rtcp_ssrc_text, tvb, offset, item_len, prefix_string );
			g_free( prefix_string );
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
}

static int
dissect_rtcp_rr( packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree,
    unsigned int count )
{
	unsigned int counter = 1;
	proto_tree *ssrc_tree = (proto_tree*) NULL;
	proto_tree *ssrc_sub_tree = (proto_tree*) NULL;
	proto_tree *high_sec_tree = (proto_tree*) NULL;
	proto_item *ti = (proto_item*) NULL;
	guint8 rr_flt;
	unsigned int cum_nr = 0;

	while ( counter <= count ) {
		guint32 lsr, dlsr;

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
		lsr = tvb_get_ntohl( tvb, offset );
		proto_tree_add_uint( ssrc_tree, hf_rtcp_ssrc_lsr, tvb,
		                     offset, 4, lsr );
		offset += 4;

		/* Delay since last SR timestamp */
		dlsr = tvb_get_ntohl( tvb, offset );
		proto_tree_add_uint( ssrc_tree, hf_rtcp_ssrc_dlsr, tvb,
		                     offset, 4, dlsr );
		offset += 4;

		/* Do roundtrip calculation */
		if (global_rtcp_show_roundtrip_calculation)
		{
			/* Based on delay since SR was send in other direction */
			calculate_roundtrip_delay(tvb, pinfo, ssrc_tree, lsr, dlsr);
		}

		counter++;
	}

	return offset;
}

static int
dissect_rtcp_sr( packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *tree,
    unsigned int count )
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
	guint32 ts_msw, ts_lsw;

	ts_msw = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Timestamp, MSW: %u", ts_msw);
	offset += 4;
	ts_lsw = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Timestamp, LSW: %u", ts_lsw);
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

	/* Record the time of this packet in the sender's conversation */
	if (global_rtcp_show_roundtrip_calculation)
	{
		/* Use middle 32 bits of 64-bit time value */
		guint32 lsr = ((ts_msw & 0x0000ffff) << 16 | (ts_lsw & 0xffff0000) >> 16);

		/* Record the time that we sent this in appropriate conversation */
		remember_outgoing_sr(pinfo, lsr);
	}

	/* The rest of the packet is equal to the RR packet */
	if ( count != 0 )
		offset = dissect_rtcp_rr( pinfo, tvb, offset, tree, count );

	return offset;
}

/* Look for conversation info and display any setup info found */
void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Conversation and current data */
	conversation_t *p_conv = NULL;
	struct _rtcp_conversation_info *p_conv_data = NULL;

	/* Use existing packet data if available */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtcp);

	if (!p_conv_data)
	{
		/* First time, get info from conversation */
		p_conv = find_conversation(&pinfo->net_dst, &pinfo->net_src,
		                           pinfo->ptype,
		                           pinfo->destport, pinfo->srcport, NO_ADDR_B);

		if (p_conv)
		{
			/* Look for data in conversation */
			struct _rtcp_conversation_info *p_conv_packet_data;
			p_conv_data = conversation_get_proto_data(p_conv, proto_rtcp);

			if (p_conv_data)
			{
				/* Save this conversation info into packet info */
				p_conv_packet_data = g_mem_chunk_alloc(rtcp_conversations);
				if (!p_conv_packet_data)
				{
					return;
				}
				memcpy(p_conv_packet_data, p_conv_data,
				       sizeof(struct _rtcp_conversation_info));

				p_add_proto_data(pinfo->fd, proto_rtcp, p_conv_packet_data);
			}
		}
	}

	/* Create setup info subtree with summary info. */
	if (p_conv_data && p_conv_data->setup_method_set)
	{
		proto_tree *rtcp_setup_tree;
		proto_item *ti =  proto_tree_add_string_format(tree, hf_rtcp_setup, tvb, 0, 0,
		                                               "",
		                                               "Stream setup by %s (frame %d)",
		                                               p_conv_data->setup_method,
		                                               p_conv_data->setup_frame_number);
		PROTO_ITEM_SET_GENERATED(ti);
		rtcp_setup_tree = proto_item_add_subtree(ti, ett_rtcp_setup);
		if (rtcp_setup_tree)
		{
			/* Add details into subtree */
			proto_item* item = proto_tree_add_uint(rtcp_setup_tree, hf_rtcp_setup_frame,
			                                       tvb, 0, 0, p_conv_data->setup_frame_number);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_string(rtcp_setup_tree, hf_rtcp_setup_method,
			                             tvb, 0, 0, p_conv_data->setup_method);
			PROTO_ITEM_SET_GENERATED(item);
		}
	}
}


/* Update conversation data to record time that outgoing rr/sr was sent */
static void remember_outgoing_sr(packet_info *pinfo, long lsr)
{
	conversation_t *p_conv = NULL;
	struct _rtcp_conversation_info *p_conv_data = NULL;
	struct _rtcp_conversation_info *p_packet_data = NULL;

	/* This information will be accessed when an incoming packet comes back to
	   the side that sent this packet, so no use storing in the packet
	   info.  However, do store the fact that we've already set this info
	   before  */


	/**************************************************************************/
	/* First of all, see if we've already stored this information for this sr */

	/* Look first in packet info */
	p_packet_data = p_get_proto_data(pinfo->fd, proto_rtcp);
	if (p_packet_data && p_packet_data->last_received_set &&
	    p_packet_data->last_received_frame_number >= pinfo->fd->num)
	{
		/* We already did this, OK */
		return;
	}


	/**************************************************************************/
	/* Otherwise, we want to find/create the conversation and update it       */

	/* First time, get info from conversation.
	   Even though we think of this as an outgoing packet being sent,
	   we store the time as being received by the destination. */
	p_conv = find_conversation(&pinfo->net_dst, &pinfo->net_src,
	                           pinfo->ptype,
	                           pinfo->destport, pinfo->srcport, NO_ADDR_B);

	/* If the conversation doesn't exist, create it now. */
	if (!p_conv)
	{
		p_conv = conversation_new(&pinfo->net_dst, &pinfo->net_src, PT_UDP,
		                          pinfo->destport, pinfo->srcport,
		                          NO_ADDR2);
		if (!p_conv)
		{
			/* Give up if can't create it */
			return;
		}
	}


	/****************************************************/
	/* Now find/create conversation data                */
	p_conv_data = conversation_get_proto_data(p_conv, proto_rtcp);
	if (!p_conv_data)
	{
		/* Allocate memory for data */
		p_conv_data = g_mem_chunk_alloc(rtcp_conversations);
		if (!p_conv_data)
		{
			/* Give up if couldn't allocate space for memory */
			return;
		}
		memset(p_conv_data, 0, sizeof(struct _rtcp_conversation_info));

		/* Add it to conversation. */
		conversation_add_proto_data(p_conv, proto_rtcp, p_conv_data);
	}

	/*******************************************************/
	/* Update conversation data                            */
	p_conv_data->last_received_set = TRUE;
	p_conv_data->last_received_frame_number = pinfo->fd->num;
	p_conv_data->last_received_time_secs = pinfo->fd->abs_secs;
	p_conv_data->last_received_time_usecs = pinfo->fd->abs_usecs;
	p_conv_data->last_received_ts = lsr;


	/****************************************************************/
	/* Update packet info to record conversation state              */

	/* Will use/create packet info */
	if (!p_packet_data)
	{
		p_packet_data = g_mem_chunk_alloc(rtcp_conversations);
		if (!p_packet_data)
		{
			/* Give up if allocation fails */
			return;
		}
		memset(p_packet_data, 0, sizeof(struct _rtcp_conversation_info));

		p_add_proto_data(pinfo->fd, proto_rtcp, p_packet_data);
	}

	/* Copy current conversation data into packet info */
	p_packet_data->last_received_set = TRUE;
	p_packet_data->last_received_frame_number = p_conv_data->last_received_frame_number;
	p_packet_data->last_received_time_secs = p_conv_data->last_received_time_secs;
	p_packet_data->last_received_time_usecs = p_conv_data->last_received_time_usecs;
}


/* Use received sr to work out what the roundtrip delay is
   (at least between capture point and the other endpoint involved in
    the conversation) */
static void calculate_roundtrip_delay(tvbuff_t *tvb, packet_info *pinfo,
                                      proto_tree *tree, guint32 lsr, guint32 dlsr)
{
	/*****************************************************/
	/* This is called dissecting an SR.  We need to:
	   - look in the packet info for stored calculation.  If found, use.
	   - look up the conversation of the sending side to see when the
	     'last SR' was detected (received)
	   - calculate the network delay using the that packet time,
	     this packet time, and dlsr
	*****************************************************/

	conversation_t *p_conv = NULL;
	struct _rtcp_conversation_info *p_conv_data = NULL;
	struct _rtcp_conversation_info *p_packet_data = NULL;


	/*************************************************/
	/* Look for previously stored calculation result */
	p_packet_data = p_get_proto_data(pinfo->fd, proto_rtcp);
	if (p_packet_data && p_packet_data->calculated_delay_set)
	{
		/* Show info. */
		add_roundtrip_delay_info(tvb, pinfo, tree,
		                         p_packet_data->calculated_delay_used_frame,
		                         p_packet_data->calculated_delay);
		return;
	}


	/********************************************************************/
	/* Look for captured timestamp of last SR in conversation of sender */
	/* of this packet                                                   */
	p_conv = find_conversation(&pinfo->net_src, &pinfo->net_dst,
	                           pinfo->ptype,
	                           pinfo->srcport, pinfo->destport, NO_ADDR_B);
	if (!p_conv)
	{
		return;
	}

	/* Look for conversation data  */
	p_conv_data = conversation_get_proto_data(p_conv, proto_rtcp);
	if (!p_conv_data)
	{
		return;
	}

	if (p_conv_data->last_received_set)
	{
		/* Store result of calculation in packet info */
		if (!p_packet_data)
		{
			/* Create packet info if it doesn't exist */
			p_packet_data = g_mem_chunk_alloc(rtcp_conversations);
			if (!p_packet_data)
			{
				/* Give up if allocation fails */
				return;
			}

			memset(p_packet_data, 0, sizeof(struct _rtcp_conversation_info));

			/* Set as packet info */
			p_add_proto_data(pinfo->fd, proto_rtcp, p_packet_data);
		}

		/* Any previous report must match the lsr given here */
		if (p_conv_data->last_received_ts == lsr)
		{
			/* Look at time of since original packet was sent */
			gint seconds_between_packets =
			      pinfo->fd->abs_secs - p_conv_data->last_received_time_secs;
			gint useconds_between_packets =
			      pinfo->fd->abs_usecs - p_conv_data->last_received_time_usecs;


			gint total_gap = ((seconds_between_packets*1000000) +
			                 useconds_between_packets) / 1000;
			gint delay = total_gap - (int)(((double)dlsr/(double)65536) * 1000.0);

			/* No useful calculation can be done if dlsr not set... */
			if (!dlsr)
			{
				return;
			}

			p_packet_data->calculated_delay_set = TRUE;
			p_packet_data->calculated_delay = delay;
			p_packet_data->calculated_delay_used_frame = p_conv_data->last_received_frame_number;

			/* Show info. */
			add_roundtrip_delay_info(tvb, pinfo, tree, p_conv_data->last_received_frame_number, delay);
		}
	}
}

/* Show the calcaulted roundtrip delay info by adding protocol tree items
   and appending text to the info column */
static void add_roundtrip_delay_info(tvbuff_t *tvb, packet_info *pinfo,
                                     proto_tree *tree, guint frame, guint delay)
{
	proto_tree *rtcp_roundtrip_delay_tree;
	proto_item *ti;

	/* Don't report on calculated delays below the threshold */
	if (delay < global_rtcp_show_roundtrip_calculation_minimum)
	{
		return;
	}

	/* Add labelled subtree for roundtrip delay info */
	ti =  proto_tree_add_string_format(tree, hf_rtcp_roundtrip_delay, tvb, 0, 0,
	                                   "",
	                                   "Calculated Roundtrip delay <-> %s = %dms, using frame %d",
	                                   address_to_str(&pinfo->net_src), delay,
	                                   frame);

	PROTO_ITEM_SET_GENERATED(ti);
	rtcp_roundtrip_delay_tree = proto_item_add_subtree(ti, ett_rtcp_roundtrip_delay);
	if (rtcp_roundtrip_delay_tree)
	{
		/* Add details into subtree */
		proto_item* item = proto_tree_add_uint(rtcp_roundtrip_delay_tree,
		                                       hf_rtcp_roundtrip_delay_frame,
		                                       tvb, 0, 0, frame);
		PROTO_ITEM_SET_GENERATED(item);
		item = proto_tree_add_uint(rtcp_roundtrip_delay_tree, hf_rtcp_roundtrip_delay_delay,
		                           tvb, 0, 0, delay);
		PROTO_ITEM_SET_GENERATED(item);
	}

	/* Report delay in INFO column */
	if (check_col(pinfo->cinfo, COL_INFO))
	{
		col_append_fstr(pinfo->cinfo, COL_INFO,
		                " (roundtrip delay <-> %s = %dms, using frame %d)",
						address_to_str(&pinfo->net_src), delay, frame);
	}
}



static void
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
	guint rtcp_subtype		 = 0;

	if ( check_col( pinfo->cinfo, COL_PROTOCOL ) )   {
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "RTCP" );
	}

	if ( check_col( pinfo->cinfo, COL_INFO) ) {
		/* The second octet contains the packet type */
		/* switch ( pd[ offset + 1 ] ) { */
		switch ( tvb_get_guint8( tvb, 1 ) ) {
			case RTCP_SR:
				col_set_str( pinfo->cinfo, COL_INFO, "Sender Report");
				break;
			case RTCP_RR:
				col_set_str( pinfo->cinfo, COL_INFO, "Receiver Report");
				break;
			case RTCP_SDES:
				col_set_str( pinfo->cinfo, COL_INFO, "Source Description");
				break;
			case RTCP_BYE:
				col_set_str( pinfo->cinfo, COL_INFO, "Goodbye");
				break;
			case RTCP_APP:
				col_set_str( pinfo->cinfo, COL_INFO, "Application defined");
				break;
			case RTCP_XR:
				col_set_str( pinfo->cinfo, COL_INFO, "Extended report");
				break;
			case RTCP_FIR:
				col_set_str( pinfo->cinfo, COL_INFO, "Full Intra-frame Request (H.261)");
				break;
			case RTCP_NACK:
				col_set_str( pinfo->cinfo, COL_INFO, "Negative Acknowledgement (H.261)");
				break;
			default:
				col_set_str( pinfo->cinfo, COL_INFO, "Unknown packet type");
				break;
		}
	}

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

		/* Conversation setup info */
		if (global_rtcp_show_setup_info)
		{
			show_setup_info(tvb, pinfo, rtcp_tree);
		}


        temp_byte = tvb_get_guint8( tvb, offset );

		proto_tree_add_uint( rtcp_tree, hf_rtcp_version, tvb,
							 offset, 1, temp_byte);
        padding_set = RTCP_PADDING( temp_byte );

		proto_tree_add_boolean( rtcp_tree, hf_rtcp_padding, tvb,
								offset, 1, temp_byte );
        elem_count = RTCP_COUNT( temp_byte );

        switch ( packet_type ) {
            case RTCP_SR:
            case RTCP_RR:
                /* Receiver report count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_rc, tvb, offset, 1, temp_byte );
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

                if ( packet_type == RTCP_SR ) offset = dissect_rtcp_sr( pinfo, tvb, offset, rtcp_tree, elem_count );
                else offset = dissect_rtcp_rr( pinfo, tvb, offset, rtcp_tree, elem_count );
                break;
            case RTCP_SDES:
                /* Source count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_sc, tvb, offset, 1, temp_byte );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
                offset += 2;
                dissect_rtcp_sdes( tvb, offset, rtcp_tree, elem_count );
                offset += packet_length - 4;
                break;
            case RTCP_BYE:
                /* Source count, 5 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_sc, tvb, offset, 1, temp_byte );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
                offset += 2;
                offset = dissect_rtcp_bye( tvb, offset, rtcp_tree, elem_count );
                break;
            case RTCP_APP:
                /* Subtype, 5 bits */
                rtcp_subtype = elem_count;
                proto_tree_add_uint( rtcp_tree, hf_rtcp_subtype, tvb, offset, 1, elem_count );
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
                offset += 2;
                offset = dissect_rtcp_app( tvb, pinfo, offset,
                    rtcp_tree, padding_set,
                    packet_length - 4, rtcp_subtype );
                break;
            case RTCP_FIR:
                offset = dissect_rtcp_fir( tvb, offset, rtcp_tree );
                break;
            case RTCP_NACK:
                offset = dissect_rtcp_nack( tvb, offset, rtcp_tree );
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
				0xC0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_padding,
			{
				"Padding",
				"rtcp.padding",
				FT_BOOLEAN,
				8,
				NULL,
				0x20,
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
				0x1F,
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
				0x1F,
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
			&hf_rtcp_app_poc1_subtype,
			{
				"Subtype",
				"rtcp.app.PoC1.subtype",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_app_poc1_floor_cnt_type_vals),
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_sip_uri,
			{
				"SIP URI",
				"rtcp.app.poc1.sip.uri",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_disp_name,
			{
				"Display Name",
				"rtcp.app.poc1.disp.name",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_last_pkt_seq_no,
			{
				"Seq. no of last RTP packet",
				"rtcp.app.poc1.last.pkt.seq.no",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_reason_code1,
			{
				"Reason code",
				"rtcp.app.poc1.reason.code",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_app_poc1_reason_code1_vals),
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_item_len,
			{
				"Item length",
				"rtcp.app.poc1.item.len",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_reason1_phrase,
			{
				"Reason Phrase",
				"rtcp.app.poc1.reason.phrase",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_reason_code2,
			{
				"Reason code",
				"rtcp.app.poc1.reason.code",
				FT_UINT16,
				BASE_DEC,
				VALS(rtcp_app_poc1_reason_code2_vals),
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_additionalinfo,
			{
				"additional information",
				"rtcp.app.poc1.add.info",
				FT_UINT16,
				BASE_DEC,
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
		{
			&hf_rtcp_setup,
			{
				"Stream setup",
				"rtcp.setup",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"Stream setup, method and frame number", HFILL
			}
		},
		{
			&hf_rtcp_setup_frame,
			{
				"Setup frame",
				"rtcp.setup-frame",
				FT_FRAMENUM,
				BASE_NONE,
				NULL,
				0x0,
				"Frame that set up this stream", HFILL
			}
		},
		{
			&hf_rtcp_setup_method,
			{
				"Setup Method",
				"rtcp.setup-method",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"Method used to set up this stream", HFILL
			}
		},
		{
			&hf_rtcp_roundtrip_delay,
			{
				"Roundtrip Delay",
				"rtcp.roundtrip-delay",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"Calculated roundtrip delay, frame and ms value", HFILL
			}
		},
		{
			&hf_rtcp_roundtrip_delay_frame,
			{
				"Previous SR frame used in calculation",
				"rtcp.roundtrip-previous-sr-frame",
				FT_FRAMENUM,
				BASE_NONE,
				NULL,
				0x0,
				"Frame used to calculate roundtrip delay", HFILL
			}
		},
		{
			&hf_rtcp_roundtrip_delay_delay,
			{
				"Roundtrip Delay(ms)",
				"rtcp.roundtrip-delay-delay",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"Calculated roundtrip delay in ms", HFILL
			}
		}

	};

	static gint *ett[] =
	{
		&ett_rtcp,
		&ett_ssrc,
		&ett_ssrc_item,
		&ett_ssrc_ext_high,
		&ett_sdes,
		&ett_sdes_item,
		&ett_PoC1,
		&ett_rtcp_setup,
		&ett_rtcp_roundtrip_delay
	};

	module_t *rtcp_module;

	proto_rtcp = proto_register_protocol("Real-time Transport Control Protocol",
	    "RTCP", "rtcp");
	proto_register_field_array(proto_rtcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rtcp", dissect_rtcp, proto_rtcp);

	rtcp_module = prefs_register_protocol(proto_rtcp, NULL);

	prefs_register_bool_preference(rtcp_module, "show_setup_info",
		"Show stream setup information",
		"Where available, show which protocol and frame caused "
		"this RTCP stream to be created",
		&global_rtcp_show_setup_info);

	prefs_register_bool_preference(rtcp_module, "heuristic_rtcp",
		"Try to decode RTCP outside of conversations ",
		"If call control SIP/H.323/RTSP/.. messages are missing in the trace, "
		"RTCP isn't decoded without this",
		&global_rtcp_heur);

	prefs_register_bool_preference(rtcp_module, "show_roundtrip_calculation",
		"Show relative roundtrip calculations",
		"Try to work out network delay by comparing time between packets "
		"as captured and delays as seen by endpoint",
		&global_rtcp_show_roundtrip_calculation);

	prefs_register_uint_preference(rtcp_module, "roundtrip_min_threshhold",
		"Minimum roundtrip calculations to report (ms)",
		"Minimum calculated roundtrip delay time in milliseconds that "
		"should be reported",
		MIN_ROUNDTRIP_TO_REPORT_DEFAULT, &global_rtcp_show_roundtrip_calculation_minimum);


	register_init_routine( &rtcp_init );
}

void
proto_reg_handoff_rtcp(void)
{
	/*
	 * Register this dissector as one that can be selected by a
	 * UDP port number.
	 */
	rtcp_handle = find_dissector("rtcp");
	dissector_add_handle("udp.port", rtcp_handle);

	heur_dissector_add( "udp", dissect_rtcp_heur, proto_rtcp);
}
