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
 * Copyright 2005, Nagarjuna Venna <nvenna@brixnet.com>
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
 * Information on PoC can be found from http://www.openmobilealliance.org/
 *
 * RTCP XR is specified in RFC 3611.
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
#include "packet-ntp.h"
#include <epan/conversation.h>

#include <epan/prefs.h>
#include <epan/emem.h>


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
#define RTCP_RTPFB  205
#define RTCP_PSFB  206
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
	{ RTCP_RTPFB, "Generic RTP Feedback" },
	{ RTCP_PSFB, "Payload-specific" },
	{ RTCP_XR,   "Extended report (RFC 3611)"},
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

/* RTCP XR Blocks (Section 4, RTC 3611) */
#define RTCP_XR_LOSS_RLE    1
#define RTCP_XR_DUP_RLE     2
#define RTCP_XR_PKT_RXTIMES 3
#define RTCP_XR_REF_TIME    4
#define RTCP_XR_DLRR        5
#define RTCP_XR_STATS_SUMRY 6
#define RTCP_XR_VOIP_METRCS 7

static const value_string rtcp_xr_type_vals[] = 
{
	{ RTCP_XR_LOSS_RLE,     "Loss Run Length Encoding Report Block" },
	{ RTCP_XR_DUP_RLE,      "Duplicate Run Length Encoding Report Block" },
	{ RTCP_XR_PKT_RXTIMES,  "Packet Receipt Times Report Block" },
	{ RTCP_XR_REF_TIME,     "Receiver Reference Time Report Block" },
	{ RTCP_XR_DLRR,         "DLRR Report Block" },
	{ RTCP_XR_STATS_SUMRY,  "Statistics Summary Report Block" },
	{ RTCP_XR_VOIP_METRCS,  "VoIP Metrics Report Block" },
	{ 0, NULL}
};

/* XR VoIP Metrics Block - PLC Algorithms */
static const value_string rtcp_xr_plc_algo_vals[] = 
{
	{ 0, "Unspecified" },
	{ 1, "Disabled" },
	{ 2, "Enhanced" },
	{ 3, "Standard" },
	{ 0, NULL }
};

/* XR VoIP Metrics Block - JB Adaptive */
static const value_string rtcp_xr_jb_adaptive_vals[] = 
{
	{ 0, "Unknown" },
	{ 1, "Reserved" },
	{ 2, "Non-Adaptive" },
	{ 3, "Adaptive" },
	{ 0, NULL }
};

/* XR Stats Summary Block - IP TTL or Hop Limit */
static const value_string rtcp_xr_ip_ttl_vals[] = 
{
	{ 0, "No TTL Values" },
	{ 1, "IPv4" },
	{ 2, "IPv6" },
	{ 3, "Undefined" },
	{ 0, NULL }
};

/* RTCP Application PoC1 Value strings 
 * OMA-TS-PoC-UserPlane-V1_0-20051006-C
 */
static const value_string rtcp_app_poc1_floor_cnt_type_vals[] =
{
	{  0,   "TBCP Talk Burst Request"},
	{  1,   "TBCP Talk Burst Granted"},
	{  2,   "TBCP Talk Burst Taken (no reply expected)"},
	{  3,   "TBCP Talk Burst Deny"},
	{  4,   "TBCP Talk Burst Release"},
	{  5,   "TBCP Talk Burst Idle"},
	{  6,   "TBCP Talk Burst Revoke"},
	{  7,	"TBCP Talk Burst Acknowledgement"},
	{  8,	"TBCP Queue Status Request"},
	{  9,	"TBCP Queue Status Response"},
	{ 11,	"TBCP Disconnect"},
	{ 15,	"TBCP Connect"},
	{ 18,	"TBCP Talk Burst Taken (ack expected)"},
	{  0,   NULL },
};

static const value_string rtcp_app_poc1_reason_code1_vals[] =
{
	{  1,   "Floor already in use"},
	{  2,   "Internal PoC server error"},
	{  3,	"Only one participant in the group"},
	{  4,	"Retry-after timer has not expired"},
	{  5,	"Listen only"},
	{  0,   NULL },
};

static const value_string rtcp_app_poc1_reason_code2_vals[] =
{
	{  1,   "Only one user"},
	{  2,   "Talk burst too long"},
	{  3,	"No permission to send a Talk Burst"},
	{  4,	"Talk burst pre-empted"},
	{  0,   NULL },
};

static const value_string rtcp_app_poc1_reason_code_ack_vals[] =
{
	{  0,   "Accepted"},
	{  1,   "Busy"},
	{  2,   "Not accepted"},
	{  0,   NULL },
};
static const value_string rtcp_app_poc1_conn_sess_type_vals[] =
{
	{  0,	"None"},
	{  1,	"1-to-1"},
	{  2,	"Ad-hoc"},
	{  3,	"Pre-arranged"},
	{  4,	"Chat"},
	{  0,	NULL },
};

static const value_string rtcp_app_poc1_qsresp_priority_vals[] =
{
	{  0,	"No priority (un-queued)"},
	{  1,	"Normal priority"},
	{  2,	"High priority"},
	{  3,	"Pre-emptive priority"},
	{  0,	NULL },
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
static int hf_rtcp_ssrc_discarded    = -1;
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
static int hf_rtcp_sdes_type         = -1;
static int hf_rtcp_sdes_length       = -1;
static int hf_rtcp_sdes_text         = -1;
static int hf_rtcp_sdes_prefix_len   = -1;
static int hf_rtcp_sdes_prefix_string= -1;
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
static int hf_rtcp_app_poc1_stt			= -1;
static int hf_rtcp_app_poc1_partic		= -1;
static int hf_rtcp_app_poc1_ssrc_granted	= -1;
static int hf_rtcp_app_poc1_last_pkt_seq_no = -1;
static int hf_rtcp_app_poc1_reason_code1	= -1;
static int hf_rtcp_app_poc1_item_len		= -1;
static int hf_rtcp_app_poc1_reason1_phrase	= -1;
static int hf_rtcp_app_poc1_reason_code2	= -1;
static int hf_rtcp_app_poc1_additionalinfo	= -1;
static int hf_rtcp_app_poc1_ack_subtype		= -1;
static int hf_rtcp_app_poc1_ack_reason_code	= -1;
static int hf_rtcp_app_poc1_qsresp_priority	= -1;
static int hf_rtcp_app_poc1_qsresp_position	= -1;
static int hf_rtcp_app_poc1_conn_content_1st_byte[5] = { -1, -1, -1, -1, -1 };
static int hf_rtcp_app_poc1_conn_session_type	= -1;
static int hf_rtcp_app_poc1_conn_add_ind_mao	= -1;
static int hf_rtcp_app_poc1_conn_sdes_items[5] = { -1, -1, -1, -1, -1 };
static int hf_rtcp_xr_block_type     = -1;
static int hf_rtcp_xr_block_specific = -1;
static int hf_rtcp_xr_block_length   = -1;
static int hf_rtcp_xr_thinning       = -1;
static int hf_rtcp_xr_voip_metrics_burst_density = -1;
static int hf_rtcp_xr_voip_metrics_gap_density = -1;
static int hf_rtcp_xr_voip_metrics_burst_duration = -1;
static int hf_rtcp_xr_voip_metrics_gap_duration = -1;
static int hf_rtcp_xr_voip_metrics_rtdelay = -1;
static int hf_rtcp_xr_voip_metrics_esdelay = -1;
static int hf_rtcp_xr_voip_metrics_siglevel = -1;
static int hf_rtcp_xr_voip_metrics_noiselevel = -1;
static int hf_rtcp_xr_voip_metrics_rerl = -1;
static int hf_rtcp_xr_voip_metrics_gmin = -1;
static int hf_rtcp_xr_voip_metrics_rfactor = -1;
static int hf_rtcp_xr_voip_metrics_extrfactor = -1;
static int hf_rtcp_xr_voip_metrics_moslq = -1;
static int hf_rtcp_xr_voip_metrics_moscq = -1;
static int hf_rtcp_xr_voip_metrics_plc = -1;
static int hf_rtcp_xr_voip_metrics_jbadaptive = -1;
static int hf_rtcp_xr_voip_metrics_jbrate = -1;
static int hf_rtcp_xr_voip_metrics_jbnominal = -1;
static int hf_rtcp_xr_voip_metrics_jbmax = -1;
static int hf_rtcp_xr_voip_metrics_jbabsmax = -1;
static int hf_rtcp_xr_stats_loss_flag = -1;
static int hf_rtcp_xr_stats_dup_flag = -1;
static int hf_rtcp_xr_stats_jitter_flag = -1;
static int hf_rtcp_xr_stats_ttl = -1;
static int hf_rtcp_xr_beginseq = -1;
static int hf_rtcp_xr_endseq = -1;
static int hf_rtcp_xr_stats_lost = -1;
static int hf_rtcp_xr_stats_dups = -1;
static int hf_rtcp_xr_stats_minjitter = -1;
static int hf_rtcp_xr_stats_maxjitter = -1;
static int hf_rtcp_xr_stats_meanjitter = -1;
static int hf_rtcp_xr_stats_devjitter = -1;
static int hf_rtcp_xr_stats_minttl = -1;
static int hf_rtcp_xr_stats_maxttl = -1;
static int hf_rtcp_xr_stats_meanttl = -1;
static int hf_rtcp_xr_stats_devttl = -1;
static int hf_rtcp_xr_lrr = -1;
static int hf_rtcp_xr_dlrr = -1;

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
static gint ett_xr_block                = -1;
static gint ett_xr_block_contents       = -1;
static gint ett_xr_ssrc                 = -1;
static gint  ett_xr_loss_chunk = -1;
static gint ett_poc1_conn_contents	= -1;

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


/* Set up an RTCP conversation using the info given */
void rtcp_add_address( packet_info *pinfo,
                       address *addr, int port,
                       int other_port,
                       const gchar *setup_method, guint32 setup_frame_number)
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
	p_conv = find_conversation( pinfo->fd->num, addr, &null_addr, PT_UDP, port, other_port,
	                            NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

	/*
	 * If not, create a new conversation.
	 */
	if ( ! p_conv ) {
		p_conv = conversation_new( pinfo->fd->num, addr, &null_addr, PT_UDP,
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
		p_conv_data = se_alloc(sizeof(struct _rtcp_conversation_info));
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
    unsigned int padding, unsigned int packet_len, guint rtcp_subtype, guint32 app_length )
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
		app_length = app_length -8;
		if ( packet_len == 0 )
			return offset; /* No more data */
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
			case 1: /* TBCP Granted */
				proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_stt, tvb, offset, 2, FALSE );
				offset += 2;
				packet_len -= 2;
				proto_tree_add_text(PoC1_tree, tvb, offset, 2, "Spare 2 bytes" );
				offset += 2;
				packet_len -= 2;
				if (packet_len ==0)
					return offset;
				proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_partic, tvb, offset, 2, FALSE );
				offset += 2;
				packet_len -= 2;
				proto_tree_add_text(PoC1_tree, tvb, offset, 2, "Spare 2 bytes" );
				offset += 2;
				packet_len -= 2;
				break;
			case 2:		/* TBCP Talk Burst Taken (no reply expected) */
			case 18:	/* TBCP Talk Burst Taken (ack expected) */
				proto_tree_add_item(PoC1_tree, hf_rtcp_app_poc1_ssrc_granted, tvb, offset, 4, FALSE );
				offset += 4;
				packet_len -= 4;
				sdes_type = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_sdes_type, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				/* Item length, 8 bits */
				item_len = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_sdes_length, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_sip_uri, tvb, offset, item_len, FALSE );
				offset = offset + item_len;
				packet_len = packet_len - item_len;
				
				/* In the application dependent data, the TBCP Talk Burst Taken message SHALL carry
				 * a SSRC field and SDES items, CNAME and MAY carry SDES item NAME to identify the
				 * PoC Client that has been granted permission to send a Talk Burst. 
				 * The SDES item NAME SHALL be included if it is known by the PoC Server. 
				 * Therefore the length of the packet will vary depending on numbwe of SDES items 
				 * and the size of the SDES items.
				 */
				if ( packet_len == 0 )
					return offset;
				
				sdes_type = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_sdes_type, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				/* Item length, 8 bits */
				item_len = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( PoC1_tree, hf_rtcp_sdes_length, tvb, offset, 1, FALSE );
				offset++;
				packet_len--;
				if ( item_len != 0 )
					proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_disp_name, tvb, offset, item_len, FALSE );
				offset = offset + item_len;
				packet_len = packet_len - item_len;
				break;
			case 3:		/* TBCP Talk Burst Deny */
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
			case 4:		/* TBCP Talk Burst Release */
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_last_pkt_seq_no, tvb, offset, 2, FALSE );
				proto_tree_add_text(PoC1_tree, tvb, offset + 2, 2, "Padding 2 bytes");
				offset += 4;
				packet_len-=4;
				break;
						/* 5 TBCP Talk Burst Idle */
			case 6:		/* TBCP Talk Burst Revoke */
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_reason_code2, tvb, offset, 2, FALSE );
				proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_additionalinfo, tvb, offset + 2, 2, FALSE );
				offset += 4;
				packet_len-=4;
				break;

			case 7:		/* TBCP Talk Burst Acknowledgement */
			    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_ack_subtype, tvb, offset, 1, FALSE );
			    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_ack_reason_code, tvb, offset, 2, FALSE );
			    proto_tree_add_text( PoC1_tree, tvb, offset + 2, 2, "Padding 2 bytes" );
			    offset += 4;
			    packet_len -= 4;
			    break;

				/* 8 TBCP Queue Status Request */

			case 9: /*TBCP Queue Status Response */
			    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_qsresp_priority, tvb, offset, 1, FALSE );
			    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_qsresp_position, tvb, offset + 1, 2, FALSE );
			    proto_tree_add_text( PoC1_tree, tvb, offset + 3, 1, "Padding 1 byte" );
			    offset += 4;
			    packet_len -= 4;
			    break;
				
				/* 11 TBCP Disconnect */

			case 15:		/* TBCP Connect */
				{
			    proto_item *content = proto_tree_add_text(PoC1_tree, tvb, offset, 2, "SDES item content");
			    gboolean contents[5];
			    unsigned int i;

			    proto_tree *content_tree = proto_item_add_subtree(content, ett_poc1_conn_contents);
			    guint temp_byte = tvb_get_guint8( tvb, offset );

			    for ( i = 0; i < sizeof(contents) /
				      sizeof(contents[0]) &&
				      i < sizeof(hf_rtcp_app_poc1_conn_content_1st_byte) /
				      sizeof(hf_rtcp_app_poc1_conn_content_1st_byte[0]);
				  ++i ) {
				proto_tree_add_item( content_tree, hf_rtcp_app_poc1_conn_content_1st_byte[i], tvb, offset, 1, FALSE );
				contents[i] = temp_byte & (1 << (7-i));
			    }

			    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_session_type, tvb, offset + 2, 1, FALSE );

			    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_add_ind_mao, tvb, offset + 3, 1, FALSE );
			    
			    offset += 4;
			    packet_len -= 4;

			    for ( i = 0; i < sizeof(contents) /
				      sizeof(contents[0]); ++i ) {
				if ( contents[i] ) {
				    guint sdes_type, sdes_len;
				    sdes_type = tvb_get_guint8( tvb, offset++ );
				    sdes_len = tvb_get_guint8( tvb, offset );

				    proto_tree_add_item( PoC1_tree, hf_rtcp_app_poc1_conn_sdes_items[i], tvb, offset, 1, FALSE );

				    offset += sdes_len + 1;
				    packet_len -= (sdes_len + 2);
				}
			    }
			    break;
			}    
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
		proto_tree_add_item( tree, hf_rtcp_sdes_length, tvb, offset, 1, FALSE );
		offset++;

		reason_text = tvb_get_ephemeral_string(tvb, offset, reason_length);
		proto_tree_add_string( tree, hf_rtcp_sdes_text, tvb, offset, reason_length, reason_text );
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
		 * end of frame as well.
		 */
		while ( tvb_reported_length_remaining( tvb, offset ) > 0 ) {
			/* ID, 8 bits */
			sdes_type = tvb_get_guint8( tvb, offset );
			proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_type, tvb, offset, 1, FALSE );
			offset++;

			if ( sdes_type == RTCP_SDES_END ) {
				/* End of list */
				break;
			}

			/* Item length, 8 bits */
			item_len = tvb_get_guint8( tvb, offset );
			proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_length, tvb, offset, 1, FALSE );
			offset++;

			if ( sdes_type == RTCP_SDES_PRIV ) {
				/* PRIV adds two items between the SDES length
				 * and value - an 8 bit length giving the
				 * length of a "prefix string", and the string.
				 */
				prefix_len = tvb_get_guint8( tvb, offset );
				proto_tree_add_item( sdes_item_tree, hf_rtcp_sdes_prefix_len, tvb, offset, 1, FALSE );
				offset++;

				prefix_string = ep_alloc( prefix_len + 1 );
				for ( counter = 0; counter < prefix_len; counter++ )
					prefix_string[ counter ] =
					    tvb_get_guint8( tvb, offset + counter );
				/* strncpy( prefix_string, pd + offset, prefix_len ); */
				prefix_string[ prefix_len ] = '\0';
				proto_tree_add_string( sdes_item_tree, hf_rtcp_sdes_prefix_string, tvb, offset, prefix_len, prefix_string );
				offset += prefix_len;
				item_len -= prefix_len +1;
			}
			prefix_string = ep_alloc( item_len + 1 );
			for ( counter = 0; counter < item_len; counter++ )
			    prefix_string[ counter ] =
			        tvb_get_guint8( tvb, offset + counter );
			/* strncpy( prefix_string, pd + offset, item_len ); */
			prefix_string[ item_len] = 0;
			proto_tree_add_string( sdes_item_tree, hf_rtcp_sdes_text, tvb, offset, item_len, prefix_string );
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

static void parse_xr_type_specific_field(tvbuff_t *tvb, gint offset, guint block_type, proto_tree *tree)
{
    guint8 flags = tvb_get_guint8(tvb, offset);

    switch (block_type) {
    case RTCP_XR_LOSS_RLE:
    case RTCP_XR_DUP_RLE:
    case RTCP_XR_PKT_RXTIMES:
        proto_tree_add_uint(tree, hf_rtcp_xr_thinning, tvb, offset, 1, flags);
        break;
        
    case RTCP_XR_STATS_SUMRY:
        proto_tree_add_boolean(tree, hf_rtcp_xr_stats_loss_flag, tvb, offset, 1, flags);
        proto_tree_add_boolean(tree, hf_rtcp_xr_stats_dup_flag, tvb, offset, 1, flags);
        proto_tree_add_boolean(tree, hf_rtcp_xr_stats_jitter_flag, tvb, offset, 1, flags);
        proto_tree_add_uint(tree, hf_rtcp_xr_stats_ttl, tvb, offset, 1, flags);
        break;

    default:
        proto_tree_add_uint(tree, hf_rtcp_xr_block_specific, tvb, offset, 1, flags);
        break;
    }
}

static gboolean validate_xr_block_length(tvbuff_t *tvb, int offset, guint block_type, guint block_len, proto_tree *tree)
{
    proto_tree_add_uint(tree, hf_rtcp_xr_block_length, tvb, offset, 2, block_len);
    switch (block_type) {
    case RTCP_XR_REF_TIME:
        if (block_len != 2)
            proto_tree_add_text(tree, tvb, offset, 2, "Invalid block length, should be 2");
        return FALSE;

    case RTCP_XR_STATS_SUMRY:
        if (block_len != 9)
            proto_tree_add_text(tree, tvb, offset, 2, "Invalid block length, should be 9");
        return FALSE;

    case RTCP_XR_VOIP_METRCS:
        if (block_len != 8)
            proto_tree_add_text(tree, tvb, offset, 2, "Invalid block length, should be 8");
        return FALSE;

    default:
        break;
    }
    return TRUE;
}

static int
dissect_rtcp_xr(tvbuff_t *tvb, packet_info *pinfo _U_, int offset, proto_tree *tree, gint packet_len)
{
    guint block_num = 1;
    
    /* Packet length should at least be 4 */
    if (packet_len < 4) {
        proto_tree_add_text(tree, tvb, offset, packet_len, "Missing Sender SSRC");
        return offset + packet_len;
    }
	
    /* SSRC */
    proto_tree_add_item( tree, hf_rtcp_ssrc_sender, tvb, offset, 4, FALSE );
    offset += 4;
    packet_len -= 4;
    
    for(;packet_len > 0; block_num++) {
        guint block_type = tvb_get_guint8(tvb, offset), block_length = 0;
        gint content_length = 0;
        gboolean valid = TRUE;
        
        /* Create a subtree for this block, dont know the length yet*/
        proto_item *block = proto_tree_add_text(tree, tvb, offset, -1, "Block %u", block_num);
        proto_tree *xr_block_tree = proto_item_add_subtree(block, ett_xr_block);
        proto_item *contents = NULL;
        proto_item *content_tree = NULL;

        proto_tree_add_item(xr_block_tree, hf_rtcp_xr_block_type, tvb, offset, 1, FALSE);
        
        if (packet_len >= 2) {
            parse_xr_type_specific_field(tvb, offset + 1, block_type, xr_block_tree);
            if (packet_len >= 4) {
                block_length = tvb_get_ntohs(tvb, offset + 2);
                valid = validate_xr_block_length(tvb, offset + 2, block_type, block_length, xr_block_tree);
            }
        } else {
            proto_tree_add_text(xr_block_tree, tvb, offset + 1, packet_len, "Missing Required Block Headers");
            return offset + packet_len;
        }
		
        content_length = block_length * 4;
        proto_item_set_len(block, content_length + 4);
        
        if (content_length > packet_len) {
            proto_tree_add_text(xr_block_tree, tvb, offset + 2, 2, "Block length is greater than packet length");
        }
		
        offset += 4;
        packet_len -= 4;

        contents = proto_tree_add_text(xr_block_tree, tvb, offset, content_length, "Contents");
        content_tree = proto_item_add_subtree(contents, ett_xr_block_contents);
            
        switch (block_type) {
        case RTCP_XR_VOIP_METRCS: {
            guint fraction_rate, value;
            
            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, FALSE);
            offset += 4;
            
            /* Loss Rate */
            fraction_rate = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(content_tree, hf_rtcp_ssrc_fraction, tvb, offset, 1, 
                                       fraction_rate, "Fraction lost: %u / 256", fraction_rate);
            offset++;
            
            /* Discard Rate */
            fraction_rate = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint_format(content_tree, hf_rtcp_ssrc_discarded, tvb, offset, 1, 
                                       fraction_rate, "Fraction Discarded: %u / 256", fraction_rate);
            offset++;
            
            /* Burst Density */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_burst_density, tvb, offset, 1, FALSE);
            offset++;
            
            /* Gap Density */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gap_density, tvb, offset, 1, FALSE);
            offset++;
            
            /* Burst Duration */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_burst_duration, tvb, offset, 2, FALSE);
            offset += 2;
            
            /* Gap Duration */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gap_duration, tvb, offset, 2, FALSE);
            offset += 2;
            
            /* Round Trip Delay */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rtdelay, tvb, offset, 2, FALSE);
            offset += 2;
            
            /* End System Delay */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_esdelay, tvb, offset, 2, FALSE);
            offset += 2;
            
            /* Signal Level */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_siglevel, tvb, offset, 1, FALSE);
            offset++;
            
            /* Noise Level */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_noiselevel, tvb, offset, 1, FALSE);
            offset++;
            
            /* RERL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rerl, tvb, offset, 1, FALSE);
            offset++;
            
            /* GMin */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_gmin, tvb, offset, 1, FALSE);
            offset++;
            
            /* R factor */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_rfactor, tvb, offset, 1, FALSE);
            offset++;
            
            /* external R Factor */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_extrfactor, tvb, offset, 1, FALSE);
            offset++;
            
            /* MOS LQ */
            proto_tree_add_float(content_tree, hf_rtcp_xr_voip_metrics_moslq, tvb, offset, 1, 
                                 (gfloat)tvb_get_guint8(tvb, offset) / 10);
            offset++;
            
            /* MOS CQ */
            proto_tree_add_float(content_tree, hf_rtcp_xr_voip_metrics_moscq, tvb, offset, 1, 
                                 (gfloat)tvb_get_guint8(tvb, offset) / 10);
            offset++;
            
            /* PLC, JB Adaptive, JB Rate */
            value = tvb_get_guint8(tvb, offset);
            proto_tree_add_uint(content_tree, hf_rtcp_xr_voip_metrics_plc, tvb, offset, 1, value);
            proto_tree_add_uint(content_tree, hf_rtcp_xr_voip_metrics_jbadaptive, tvb, offset, 1, value);
            proto_tree_add_uint(content_tree, hf_rtcp_xr_voip_metrics_jbrate, tvb, offset, 1, value);
            offset += 2; /* skip over reseved bit */
            
            /* JB Nominal */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbnominal, tvb, offset, 2, FALSE);
            offset += 2;
            
            /* JB Max */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbmax, tvb, offset, 2, FALSE);
            offset += 2;
            
            /* JB Abs max */
            proto_tree_add_item(content_tree, hf_rtcp_xr_voip_metrics_jbabsmax, tvb, offset, 2, FALSE);
            offset += 2;

            break;
        }
            
        case RTCP_XR_STATS_SUMRY: {
            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, FALSE);
            offset += 4;

            /* Begin Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, FALSE);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, FALSE);
            offset += 2;

            /* Lost Pkts */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_lost, tvb, offset, 4, FALSE);
            offset += 4;

            /* Dup Pkts */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_dups, tvb, offset, 4, FALSE);
            offset += 4;

            /* Min Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_minjitter, tvb, offset, 4, FALSE);
            offset += 4;

            /* Max Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_maxjitter, tvb, offset, 4, FALSE);
            offset += 4;

            /* Mean Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_meanjitter, tvb, offset, 4, FALSE);
            offset += 4;

            /* Dev Jitter */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_devjitter, tvb, offset, 4, FALSE);
            offset += 4;

            /* Min TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_minttl, tvb, offset, 1, FALSE);
            offset ++;

            /* Max TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_maxttl, tvb, offset, 1, FALSE);
            offset ++;

            /* Mean TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_meanttl, tvb, offset, 1, FALSE);
            offset ++;

            /* Dev TTL */
            proto_tree_add_item(content_tree, hf_rtcp_xr_stats_devttl, tvb, offset, 1, FALSE);
            offset ++;

            break;
        }

        case RTCP_XR_REF_TIME: {
            guint32 ts_msw, ts_lsw;

            ts_msw = tvb_get_ntohl(tvb, offset);
            proto_tree_add_text(content_tree, tvb, offset, 4, "Timestamp, MSW: %u", ts_msw);
            offset += 4;
            ts_lsw = tvb_get_ntohl(tvb, offset);
            proto_tree_add_text(content_tree, tvb, offset, 4, "Timestamp, LSW: %u", ts_lsw);
            offset += 4;
            
            break;
        }

        case RTCP_XR_DLRR: {
            /* Each report block is 12 bytes */
            gint sources = content_length / 12;
            gint counter = 0;
            for(counter = 0; counter < sources; counter++) {
                /* Create a new subtree for a length of 12 bytes */
                proto_tree *ti = proto_tree_add_text(content_tree, tvb, offset, 12, "Source %u", counter + 1);
                proto_tree *ssrc_tree = proto_item_add_subtree(ti, ett_xr_ssrc);
                
                /* SSRC_n source identifier, 32 bits */
                proto_tree_add_item(ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, FALSE);
                offset += 4;
                
                /* Last RR timestamp */
                proto_tree_add_item(ssrc_tree, hf_rtcp_xr_lrr, tvb, offset, 4, FALSE);
                offset += 4;
                
                /* Delay since last RR timestamp */
                proto_tree_add_item(ssrc_tree, hf_rtcp_xr_dlrr, tvb, offset, 4, FALSE);
                offset += 4;
            }
            
            if (content_length % 12 != 0)
                offset += content_length % 12;
            break;
        }

        case RTCP_XR_PKT_RXTIMES: {
            /* 8 bytes of fixed header */
            gint count = 0, skip = 8;
            guint16 begin = 0;

            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, FALSE);
            offset += 4;

            /* Begin Seq */
            begin = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, begin);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, FALSE);
            offset += 2;

            for(count = 0; skip < content_length; skip += 4, count++) { 
                proto_tree_add_text(content_tree, tvb, offset, 4, "Seq: %u, Timestamp: %u", 
                                    (begin + count) % 65536, FALSE);
                offset += 4;
            }
            break;
        }

        case RTCP_XR_LOSS_RLE:
        case RTCP_XR_DUP_RLE: {
            /* 8 bytes of fixed header */
            gint count = 0, skip = 8;
            guint16 begin = 0;
            proto_item *chunks_item;
            proto_tree *chunks_tree;
            
            /* Identifier */
            proto_tree_add_item(content_tree, hf_rtcp_ssrc_source, tvb, offset, 4, FALSE);
            offset += 4;

            /* Begin Seq */
            begin = tvb_get_ntohs(tvb, offset);
            proto_tree_add_uint(content_tree, hf_rtcp_xr_beginseq, tvb, offset, 2, begin);
            offset += 2;

            /* End Seq */
            proto_tree_add_item(content_tree, hf_rtcp_xr_endseq, tvb, offset, 2, FALSE);
            offset += 2;

            /* report Chunks */
            chunks_item = proto_tree_add_text(content_tree, tvb, offset, content_length,"Report Chunks");
            chunks_tree = proto_item_add_subtree(chunks_item, ett_xr_loss_chunk);

            for(count = 1; skip < content_length; skip += 2, count++) {
                guint value = tvb_get_ntohs(tvb, offset);
                
                if (value == 0) {
                    proto_tree_add_text(chunks_tree, tvb, offset, 2,
                                        "Chunk: %u -- Null Terminator ",
                                        count);
                } else if (( value & 0x8000 )) {
                    const gchar* run_type = (value & 0x4000) ? "1s" : "0s";
                    value &= 0x7FFF;
                    proto_tree_add_text(chunks_tree, tvb, offset, 2,
                                        "Chunk: %u -- Length Run %s, length: %u",
                                        count, run_type, value);
                } else {
                    char bits[20+1];
                    other_decode_bitfield_value(bits, value, 0x00007FFF, 16);
                    proto_tree_add_text(chunks_tree, tvb, offset, 2,
                                        "Chunk: %u -- Bit Vector, bits: %s",
                                        count, bits );
                }
                offset += 2;
            }
            
            break;
        }

        default:
            /* skip over the unknown block */
            offset += content_length;
            break;
        }
        packet_len -= content_length;
    }
    return offset;
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
		proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_source, tvb, offset, 4, FALSE );
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
		proto_tree_add_item( high_sec_tree, hf_rtcp_ssrc_high_cycles,
		    tvb, offset, 2, FALSE );
		offset += 2;
		/* highest sequence number received */
		proto_tree_add_item( high_sec_tree, hf_rtcp_ssrc_high_seq,
		    tvb, offset, 2, FALSE );
		offset += 2;

		/* Interarrival jitter */
		proto_tree_add_item( ssrc_tree, hf_rtcp_ssrc_jitter, tvb,
		    offset, 4, FALSE );
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
	gchar *buff;

	/* Retreive the NTP timestamp. Using the NTP dissector for this */
	buff=ntp_fmt_ts(tvb_get_ptr( tvb, offset, 8 ));
	proto_tree_add_string_format( tree, hf_rtcp_ntp, tvb, offset, 8, ( const char* ) buff, "NTP timestamp: %s", buff );
	offset += 8;
#else
	/*
	 * XXX - RFC 1889 says this is an NTP timestamp, but that appears
	 * not to be the case.
	 */
	proto_item* item;
	guint32 ts_msw, ts_lsw;
	gchar *buff;

	ts_msw = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Timestamp, MSW: %u", ts_msw);
	offset += 4;
	ts_lsw = tvb_get_ntohl(tvb, offset);
	proto_tree_add_text(tree, tvb, offset, 4, "Timestamp, LSW: %u", ts_lsw);
	offset += 4;

	buff=ntp_fmt_ts(tvb_get_ptr( tvb, offset, 8 ));
	item = proto_tree_add_string_format( tree, hf_rtcp_ntp, tvb, offset-8, 8, ( const char* ) buff, "MSW and LSW as NTP timestamp: %s", buff );
	PROTO_ITEM_SET_GENERATED(item);
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
		p_conv = find_conversation(pinfo->fd->num, &pinfo->net_dst, &pinfo->net_src,
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
				p_conv_packet_data = se_alloc(sizeof(struct _rtcp_conversation_info));
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
		                                               "Stream setup by %s (frame %u)",
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
	p_conv = find_conversation(pinfo->fd->num, &pinfo->net_dst, &pinfo->net_src,
	                           pinfo->ptype,
	                           pinfo->destport, pinfo->srcport, NO_ADDR_B);

	/* If the conversation doesn't exist, create it now. */
	if (!p_conv)
	{
		p_conv = conversation_new(pinfo->fd->num, &pinfo->net_dst, &pinfo->net_src, PT_UDP,
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
		p_conv_data = se_alloc(sizeof(struct _rtcp_conversation_info));
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
	p_conv_data->last_received_timestamp = pinfo->fd->abs_ts;
	p_conv_data->last_received_ts = lsr;


	/****************************************************************/
	/* Update packet info to record conversation state              */

	/* Will use/create packet info */
	if (!p_packet_data)
	{
		p_packet_data = se_alloc(sizeof(struct _rtcp_conversation_info));
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
	p_packet_data->last_received_timestamp = p_conv_data->last_received_timestamp;
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
	p_conv = find_conversation(pinfo->fd->num, &pinfo->net_src, &pinfo->net_dst,
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
			p_packet_data = se_alloc(sizeof(struct _rtcp_conversation_info));
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
			      pinfo->fd->abs_ts.secs - p_conv_data->last_received_timestamp.secs;
			gint nseconds_between_packets =
			      pinfo->fd->abs_ts.nsecs - p_conv_data->last_received_timestamp.nsecs;


			gint total_gap = ((seconds_between_packets*1000000) +
			                 nseconds_between_packets) / 1000000;
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
	                                   "Calculated Roundtrip delay <-> %s = %ums, using frame %u",
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
		                " (roundtrip delay <-> %s = %ums, using frame %u)",
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
	guint32 app_length		 = 0;

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
        if ( ( packet_type < 192 ) || ( packet_type >  207 ) )
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
				app_length = tvb_get_ntohs( tvb, offset ) <<2;
                proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, app_length );
                offset += 2;
                offset = dissect_rtcp_app( tvb, pinfo, offset,rtcp_tree, padding_set, packet_length - 4, rtcp_subtype, app_length);
                break;
            case RTCP_XR:
                /* Reserved, 5 bits, Ignore */
                offset++;
                /* Packet type, 8 bits */
                proto_tree_add_item( rtcp_tree, hf_rtcp_pt, tvb, offset, 1, FALSE );
                offset++;
                /* Packet length in 32 bit words MINUS one, 16 bits */
                proto_tree_add_uint( rtcp_tree, hf_rtcp_length, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
                offset += 2;
                offset = dissect_rtcp_xr( tvb, pinfo, offset, rtcp_tree, packet_length - 4 );
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
			&hf_rtcp_sdes_type,
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
			&hf_rtcp_sdes_length,
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
			&hf_rtcp_sdes_text,
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
			&hf_rtcp_sdes_prefix_len,
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
			&hf_rtcp_sdes_prefix_string,
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
			&hf_rtcp_app_poc1_stt,
			{
				"Stop talking timer",
				"rtcp.app.poc1.stt",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_partic,
			{
				"Number of participants",
				"rtcp.app.poc1.participants",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_ssrc_granted,
			{
				"SSRC of client granted permission to talk",
				"rtcp.app.poc1.ssrc.granted",
				FT_UINT32,
				BASE_DEC,
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
			&hf_rtcp_app_poc1_ack_subtype,
			{
				"Subtype",
				"rtcp.app.poc1.ack.subtype",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_app_poc1_floor_cnt_type_vals),
				0xf8,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_ack_reason_code,
			{
				"Reason code",
				"rtcp.app.poc1.ack.reason.code",
				FT_UINT16,
				BASE_DEC,
				VALS(rtcp_app_poc1_reason_code_ack_vals),
				0x07ff,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_qsresp_priority,
			{
				"Priority",
				"rtcp.app.poc1.qsresp.priority",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_app_poc1_qsresp_priority_vals),
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_qsresp_position,
			{
				"Position",
				"rtcp.app.poc1.qsresp.position",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_content_1st_byte[0],
			{
				"Identity of inviting client",
				"rtcp.app.poc1.conn.content.a.id",
				FT_BOOLEAN,
				8,
				NULL,
				0x80,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_content_1st_byte[1],
			{
				"Nick name of inviting client",
				"rtcp.app.poc1.conn.content.a.dn",
				FT_BOOLEAN,
				8,
				NULL,
				0x40,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_content_1st_byte[2],
			{
				"Session identity",
				"rtcp.app.poc1.conn.content.sess.id",
				FT_BOOLEAN,
				8,
				NULL,
				0x20,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_content_1st_byte[3],
			{
				"Group name",
				"rtcp.app.poc1.conn.content.grp.dn",
				FT_BOOLEAN,
				8,
				NULL,
				0x10,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_content_1st_byte[4],
			{
				"Group identity",
				"rtcp.app.poc1.conn.content.grp.id",
				FT_BOOLEAN,
				8,
				NULL,
				0x08,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_session_type,
			{
				"Session type",
				"rtcp.app.poc1.conn.session.type",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_app_poc1_conn_sess_type_vals),
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_add_ind_mao,
			{
				"Manual answer override",
				"rtcp.app.poc1.conn.add.ind.mao",
				FT_BOOLEAN,
				8,
				NULL,
				0x80,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_sdes_items[0],
			{
				"Identity of inviting client",
				"rtcp.app.poc1.conn.sdes.a.id",
				FT_UINT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_sdes_items[1],
			{
				"Nick name of inviting client",
				"rtcp.app.poc1.conn.sdes.a.dn",
				FT_UINT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_sdes_items[2],
			{
				"Session identity",
				"rtcp.app.poc1.conn.sdes.sess.id",
				FT_UINT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_sdes_items[3],
			{
				"Group Name",
				"rtcp.app.poc1.conn.sdes.grp.dn",
				FT_UINT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_app_poc1_conn_sdes_items[4],
			{
				"Group identity",
				"rtcp.app.poc1.conn.sdes.grp.id",
				FT_UINT_STRING,
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
		},
		{
			&hf_rtcp_xr_block_type,
			{
				"Type",
				"rtcp.xr.bt",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_xr_type_vals),
				0x0,
				"Block Type", HFILL
			}
		},
		{
			&hf_rtcp_xr_block_specific,
			{
				"Type Specific",
				"rtcp.xr.bs",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Reserved", HFILL
			}
		},
		{
			&hf_rtcp_xr_block_length,
			{
				"Length",
				"rtcp.xr.bl",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"Block Length", HFILL
			}
		},
		{
			&hf_rtcp_ssrc_discarded,
			{
				"Fraction discarded",
				"rtcp.ssrc.discarded",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"Discard Rate", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_burst_density,
			{
				"Burst Density",
				"rtcp.xr.voipmetrics.burstdensity",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_gap_density,
			{
				"Gap Density",
				"rtcp.xr.voipmetrics.gapdensity",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_burst_duration,
			{
				"Burst Duration(ms)",
				"rtcp.xr.voipmetrics.burstduration",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_gap_duration,
			{
				"Gap Duration(ms)",
				"rtcp.xr.voipmetrics.gapduration",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_rtdelay,
			{
				"Round Trip Delay(ms)",
				"rtcp.xr.voipmetrics.rtdelay",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_esdelay,
			{
				"End System Delay(ms)",
				"rtcp.xr.voipmetrics.esdelay",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_siglevel,
			{
				"Signal Level",
				"rtcp.xr.voipmetrics.signallevel",
				FT_INT8,
				BASE_DEC,
				NULL,
				0x0,
				"Signal level of 127 indicates this parameter is unavailable", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_noiselevel,
			{
				"Noise Level",
				"rtcp.xr.voipmetrics.noiselevel",
				FT_INT8,
				BASE_DEC,
				NULL,
				0x0,
				"Noise level of 127 indicates this parameter is unavailable", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_rerl,
			{
				"Residual Echo Return Loss",
				"rtcp.xr.voipmetrics.rerl",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_gmin,
			{
				"Gmin",
				"rtcp.xr.voipmetrics.gmin",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_rfactor,
			{
				"R Factor",
				"rtcp.xr.voipmetrics.rfactor",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"R Factor is in the range of 0 to 100; 127 indicates this parameter is unavailable", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_extrfactor,
			{
				"External R Factor",
				"rtcp.xr.voipmetrics.extrfactor",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"R Factor is in the range of 0 to 100; 127 indicates this parameter is unavailable", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_moslq,
			{
				"MOS - Listening Quality",
				"rtcp.xr.voipmetrics.moslq",
				FT_FLOAT,
				BASE_DEC,
				NULL,
				0x0,
				"MOS is in the range of 1 to 5; 127 indicates this parameter is unavailable", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_moscq,
			{
				"MOS - Conversational Quality",
				"rtcp.xr.voipmetrics.moscq",
				FT_FLOAT,
				BASE_DEC,
				NULL,
				0x0,
				"MOS is in the range of 1 to 5; 127 indicates this parameter is unavailable", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_plc,
			{
				"Packet Loss Conealment Algorithm",
				"rtcp.xr.voipmetrics.plc",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_xr_plc_algo_vals),
				0xC0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_jbadaptive,
			{
				"Adaptive Jitter Buffer Algorithm",
				"rtcp.xr.voipmetrics.jba",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_xr_jb_adaptive_vals),
				0x30,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_jbrate,
			{
				"Jitter Buffer Rate",
				"rtcp.xr.voipmetrics.jbrate",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0F,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_jbnominal,
			{
				"Nominal Jitter Buffer Size",
				"rtcp.xr.voipmetrics.jbnominal",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_jbmax,
			{
				"Maximum Jitter Buffer Size",
				"rtcp.xr.voipmetrics.jbmax",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_voip_metrics_jbabsmax,
			{
				"Absolute Maximum Jitter Buffer Size",
				"rtcp.xr.voipmetrics.jbabsmax",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_thinning,
			{
				"Thinning factor",
				"rtcp.xr.tf",
				FT_UINT8,
				BASE_DEC,
                                NULL,
				0x0F,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_loss_flag,
			{
				"Loss Report Flag",
				"rtcp.xr.stats.lrflag",
				FT_BOOLEAN,
				8,
				NULL,
				0x80,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_dup_flag,
			{
				"Duplicates Report Flag",
				"rtcp.xr.stats.dupflag",
				FT_BOOLEAN,
				8,
				NULL,
				0x40,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_jitter_flag,
			{
				"Jitter Report Flag",
				"rtcp.xr.stats.jitterflag",
				FT_BOOLEAN,
				8,
				NULL,
				0x20,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_ttl,
			{
				"TTL or Hop Limit Flag",
				"rtcp.xr.stats.ttl",
				FT_UINT8,
				BASE_DEC,
				VALS(rtcp_xr_ip_ttl_vals),
				0x18,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_endseq,
			{
				"End Sequence Number",
				"rtcp.xr.endseq",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_beginseq,
			{
				"Begin Sequence Number",
				"rtcp.xr.beginseq",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_lost,
			{
				"Lost Packets",
				"rtcp.xr.stats.lost",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_dups,
			{
				"Duplicate Packets",
				"rtcp.xr.stats.dups",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_minjitter,
			{
				"Minimum Jitter",
				"rtcp.xr.stats.minjitter",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_maxjitter,
			{
				"Maximum Jitter",
				"rtcp.xr.stats.maxjitter",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_meanjitter,
			{
				"Mean Jitter",
				"rtcp.xr.stats.meanjitter",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_devjitter,
			{
				"Standard Deviation of Jitter",
				"rtcp.xr.stats.devjitter",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_minttl,
			{
				"Minimum TTL or Hop Limit",
				"rtcp.xr.stats.minttl",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_maxttl,
			{
				"Maximum TTL or Hop Limit",
				"rtcp.xr.stats.maxttl",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_meanttl,
			{
				"Mean TTL or Hop Limit",
				"rtcp.xr.stats.meanttl",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_stats_devttl,
			{
				"Standard Deviation of TTL",
				"rtcp.xr.stats.devttl",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_lrr,
			{
				"Last RR timestamp",
				"rtcp.xr.lrr",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				"", HFILL
			}
		},
		{
			&hf_rtcp_xr_dlrr,
			{
				"Delay since last RR timestamp",
				"rtcp.xr.dlrr",
				FT_UINT32,
				BASE_DEC,
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
		&ett_PoC1,
		&ett_rtcp_setup,
		&ett_rtcp_roundtrip_delay,
		&ett_xr_block,
		&ett_xr_block_contents,
 		&ett_xr_ssrc,
		&ett_xr_loss_chunk,
		&ett_poc1_conn_contents
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
