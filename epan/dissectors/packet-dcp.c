/* packet-dcp.c
 * Routines for Datagram Congestion Control Protocol, "DCCP" dissection: 
 * it should be conformance to draft-ietf-dccp-spec-11.txt
 *
 * Copyright 2005 _FF_
 * 
 * Francesco Fondelli <francesco dot fondelli, gmail dot com>
 *
 * $Id: README.developer 11973 2004-09-11 23:10:14Z guy $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1998 Gerald Combs
 *
 * Copied from packet-udp.c
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licepnse
 * as published by the Free Software Foundation; either version 2
 * of the Licepnse, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public Licepnse for more details.
 * 
 * You should have received a copy of the GNU General Public Licepnse
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */


/* Note: PROTOABBREV name collision problem, 'dccp' is used by Distributed Checksum 
   Clearinghouse Protocol.
   This dissector should be named packet-dccp.c IMHO.
*/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>
#include <epan/prefs.h>
#include <epan/emem.h>

#include "packet-dcp.h"

#include "packet-ip.h"
#include <epan/conversation.h>
#include <epan/tap.h>

/* Some definitions and the dissect_options() logic have been taken from Arnaldo Carvalho de Melo's DCCP implementation, thanks! */

#define DCCP_HDR_LEN                    16      /* base DCCP header length, with 48 bits seqnos */
#define DCCP_HDR_LEN_MIN		12      /*                        , with 24 bits seqnum */
#define DCCP_HDR_PKT_TYPES_LEN_MAX      12      /* max per packet type extra header length */
#define DCCP_OPT_LEN_MAX                1008
#define DCCP_HDR_LEN_MAX                (DCCP_HDR_LEN + DCCP_HDR_PKT_TYPES_LEN_MAX + DCCP_OPT_LEN_MAX)


static const value_string dcp_packet_type_vals[] = {
        {0x0, "Request"},
        {0x1, "Response"},
        {0x2, "Data"},
        {0x3, "Ack"},
        {0x4, "DataAck"},
        {0x5, "CloseReq"},
        {0x6, "Close"},
        {0x7, "Reset"},
	{0x8, "Sync"},
	{0x9, "SyncAck"},
	{0xA, "Reserved"},
	{0xB, "Reserved"},
	{0xC, "Reserved"},
	{0xD, "Reserved"},
	{0xE, "Reserved"},
	{0xF, "Reserved"},
        {0, NULL}
};

static const value_string dcp_reset_code_vals[] = {
        {0x00, "Unspecified"},
        {0x01, "Closed"},
        {0x02, "Aborted"},
        {0x03, "No Connection"},
        {0x04, "Packet Error"},
        {0x05, "Option Error"},
        {0x06, "Mandatory Error"},
        {0x07, "Connection Refused"},
	{0x08, "Bad Service Code"},
	{0x09, "Too Busy"},
	{0x0A, "Bad Init Cookie"},
	{0x0B, "Aggression Penalty"},
	{0x0C, "Reserved"},
        {0, NULL}
};

static const value_string dcp_feature_numbers_vals[] = {
        {0x01, "CCID"},
        {0x02, "Allow Short Seqnos"},
        {0x03, "Sequence Window"},
        {0x04, "ECN Incapable"},
        {0x05, "Ack Ratio"},
        {0x06, "Send Ack Vector"},
        {0x07, "Send NDP Count"},
	{0x08, "Minimum Checksum Coverage"},
	{0x09, "Check Data Checksum"},
        {0, NULL}
};


#if 0
#define DBG(str, args...)       do {\
                                        fprintf(stdout, \
                                        "[%s][%s][%d]: ",\
                                        __FILE__, \
                                        __FUNCTION__, \
                                        __LINE__); \
                                        fflush(stdout); \
                                        fprintf(stdout, str, ## args); \
                                } while (0)
#else
#define DBG0(format)
#define DBG1(format, arg1)
#define DBG2(format, arg1, arg2)
#endif /* 0/1 */


static int proto_dcp = -1;
static int dccp_tap = -1;

static int hf_dcp_srcport = -1;
static int hf_dcp_dstport = -1;
static int hf_dcp_port = -1;
static int hf_dcp_data_offset = -1;
static int hf_dcp_ccval = -1;
static int hf_dcp_cscov = -1;
static int hf_dcp_checksum = -1;
static int hf_dcp_checksum_bad = -1;
static int hf_dcp_res1 = -1;
static int hf_dcp_type = -1;
static int hf_dcp_x = -1;
static int hf_dcp_res2 = -1;
static int hf_dcp_seq = -1;

static int hf_dcp_ack_res = -1;
static int hf_dcp_ack = -1;

static int hf_dcp_service_code = -1;
static int hf_dcp_reset_code = -1;
static int hf_dcp_data1 = -1;
static int hf_dcp_data2 = -1;
static int hf_dcp_data3 = -1;

static int hf_dcp_options = -1;
static int hf_dcp_option_type = -1;
static int hf_dcp_feature_number = -1;
static int hf_dcp_ndp_count = -1;
static int hf_dcp_timestamp = -1;
static int hf_dcp_timestamp_echo = -1;
static int hf_dcp_elapsed_time = -1;
static int hf_dcp_data_checksum = -1;

static int hf_dcp_malformed = -1;

static gint ett_dcp = -1;
static gint ett_dcp_options = -1;

static dissector_table_t dcp_subdissector_table;
static heur_dissector_list_t heur_subdissector_list;
static dissector_handle_t data_handle;

/* preferences */
static gboolean dcp_summary_in_tree = TRUE;
static gboolean try_heuristic_first = FALSE;
static gboolean dccp_check_checksum = TRUE;


static void
decode_dccp_ports(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int sport, int dport)
{
	tvbuff_t *next_tvb;
	int low_port, high_port;

	next_tvb = tvb_new_subset(tvb, offset, -1, -1);

	/* determine if this packet is part of a conversation and call dissector */
	/* for the conversation if available */

	if (try_conversation_dissector(&pinfo->src, &pinfo->dst, PT_DCCP, sport, dport, next_tvb, pinfo, tree)) {
		return;
	}

	if (try_heuristic_first) {
		/* do lookup with the heuristic subdissector table */
		if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree)) {
			return;
		}
	}

	/* Do lookups with the subdissector table.
	   We try the port number with the lower value first, followed by the
	   port number with the higher value.  This means that, for packets
	   where a dissector is registered for *both* port numbers:

	   1) we pick the same dissector for traffic going in both directions;

	   2) we prefer the port number that's more likely to be the right
           one (as that prefers well-known ports to reserved ports);

	   although there is, of course, no guarantee that any such strategy
	   will always pick the right port number.
	   XXX - we ignore port numbers of 0, as some dissectors use a port
	   number of 0 to disable the port. */
	
	if (sport > dport) {
		low_port = dport;
		high_port = sport;
	} else {
		low_port = sport;
		high_port = dport;
	}
	if (low_port != 0 &&
	    dissector_try_port(dcp_subdissector_table, low_port, next_tvb, pinfo, tree)) {
		return;
	}
	if (high_port != 0 &&
	    dissector_try_port(dcp_subdissector_table, high_port, next_tvb, pinfo, tree)) {
		return;
	}

	if (!try_heuristic_first) {
		/* do lookup with the heuristic subdissector table */
		if (dissector_try_heuristic(heur_subdissector_list, next_tvb, pinfo, tree)) {
			return;
		}
	}

	/* Oh, well, we don't know this; dissect it as data. */
	call_dissector(data_handle, next_tvb, pinfo, tree);
}


/*
 * This function dissects DCCP options
 */
static void dissect_options(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *dcp_options_tree, proto_tree *tree _U_, e_dcphdr *dcph _U_,
			    int offset_start,
			    int offset_end)
{
	/* if here I'm sure there is at least offset_end - offset_start bytes in tvb and it should be options */
	int offset=offset_start;
	guint8 option_type = 0;
	guint8 option_len = 0;
	guint8 feature_number = 0; 
	int i;
	proto_item *dcp_item = NULL;
	
	while( offset < offset_end ) {
		
		/* DBG("offset==%d\n", offset); */

		/* first byte is the option type */
		option_type = tvb_get_guint8(tvb, offset);
		proto_tree_add_uint_hidden(dcp_options_tree, hf_dcp_option_type, tvb, offset, 1, option_type);
		
		if (option_type >= 32) {                               /* variable length options */

			if(!tvb_bytes_exist(tvb, offset, 1)) {
				/* DBG("malformed\n"); */
				proto_tree_add_boolean_hidden(dcp_options_tree, hf_dcp_malformed, tvb, offset, 0, TRUE);
				THROW(ReportedBoundsError);
			}

			option_len = tvb_get_guint8(tvb, offset + 1);
			
			if (option_len < 2) {
				/* DBG("malformed\n"); */
				proto_tree_add_boolean_hidden(dcp_options_tree, hf_dcp_malformed, tvb, offset, 0, TRUE);
				THROW(ReportedBoundsError);
			}
			
			if(!tvb_bytes_exist(tvb, offset, option_len)) {
				/* DBG("malformed\n"); */
				proto_tree_add_boolean_hidden(dcp_options_tree, hf_dcp_malformed, tvb, offset, 0, TRUE);
				THROW(ReportedBoundsError);
			}

		} else {                                               /* 1byte options */
			option_len = 1;
		}
		
		switch (option_type) {
			
		case 0:
			proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Padding");
			break;

		case 1:
			proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Mandatory");
			break;

		case 2:
			proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Slow Receiver");
			break;

		case 32:
			feature_number = tvb_get_guint8(tvb, offset + 2);
			proto_tree_add_uint_hidden(dcp_options_tree, hf_dcp_feature_number, tvb, offset + 2, 1, feature_number);
			
			if( (feature_number < 10) && (feature_number!=0) ) {
				dcp_item = proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							       "Change L(%s", 
							       val_to_str(feature_number, dcp_feature_numbers_vals, "Unknown Type"));
				for (i = 0; i < option_len - 3; i++) {
					if(i==0)
						proto_item_append_text(dcp_item, "%d", tvb_get_guint8(tvb, offset + 3 + i));
					else
						proto_item_append_text(dcp_item, ", %d", tvb_get_guint8(tvb, offset + 3 + i));
				}
				proto_item_append_text(dcp_item, ")");
			} else {
				if(((feature_number>=10)&&(feature_number<=127))||(feature_number==0))
					proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							    "Change L(Reserved feature number)");
				else
					proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							    "Change L(CCID-specific features)");
			}
			break;

		case 33:
			feature_number = tvb_get_guint8(tvb, offset + 2);
			proto_tree_add_uint_hidden(dcp_options_tree, hf_dcp_feature_number, tvb, offset + 2, 1, feature_number);
			
			if( (feature_number < 10) && (feature_number!=0) ) {
				dcp_item = proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							       "Confirm L(%s", 
							       val_to_str(feature_number, dcp_feature_numbers_vals, "Unknown Type"));
				for (i = 0; i < option_len - 3; i++) {
					if(i==0)
						proto_item_append_text(dcp_item, "%d", tvb_get_guint8(tvb, offset + 3 + i));
					else
						proto_item_append_text(dcp_item, ", %d", tvb_get_guint8(tvb, offset + 3 + i));
				}
				proto_item_append_text(dcp_item, ")");
			} else {
				if(((feature_number>=10)&&(feature_number<=127))||(feature_number==0))
					proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							    "Confirm L(Reserved feature number)");
				else
					proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							    "Confirm L(CCID-specific features)");
			}
			break;

		case 34:
			feature_number = tvb_get_guint8(tvb, offset + 2);
			proto_tree_add_uint_hidden(dcp_options_tree, hf_dcp_feature_number, tvb, offset + 2, 1, feature_number);
			
			if( (feature_number < 10) && (feature_number!=0) ) {
				dcp_item = proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							       "Change R(%s", 
							       val_to_str(feature_number, dcp_feature_numbers_vals, "Unknown Type"));
				for (i = 0; i < option_len - 3; i++) {
					if(i==0)
						proto_item_append_text(dcp_item, "%d", tvb_get_guint8(tvb, offset + 3 + i));
					else
						proto_item_append_text(dcp_item, ", %d", tvb_get_guint8(tvb, offset + 3 + i));
				}
				proto_item_append_text(dcp_item, ")");
			} else {
				if(((feature_number>=10)&&(feature_number<=127))||(feature_number==0))
					proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							    "Change R(Reserved feature number)");
				else
					proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							    "Change R(CCID-specific features)");
			}
			break;

		case 35:
			feature_number = tvb_get_guint8(tvb, offset + 2);
			proto_tree_add_uint_hidden(dcp_options_tree, hf_dcp_feature_number, tvb, offset + 2, 1, feature_number);
			
			if( (feature_number < 10) && (feature_number!=0) ) {
				dcp_item = proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							       "Confirm R(%s", 
							       val_to_str(feature_number, dcp_feature_numbers_vals, "Unknown Type"));
				for (i = 0; i < option_len - 3; i++) {
					if(i==0)
						proto_item_append_text(dcp_item, "%d", tvb_get_guint8(tvb, offset + 3 + i));
					else
						proto_item_append_text(dcp_item, ", %d", tvb_get_guint8(tvb, offset + 3 + i));
				}
				proto_item_append_text(dcp_item, ")");
			} else {
				if(((feature_number>=10)&&(feature_number<=127))||(feature_number==0))
					proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							    "Confirm R(Reserved feature number)");
				else
					proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
							    "Confirm R(CCID-specific features)");
			}
			break;

		case 36:
			dcp_item = proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Init Cookie(");
			for (i = 0; i < option_len - 2; i++) { 
				if(i==0)
					proto_item_append_text(dcp_item, "%02x", tvb_get_guint8(tvb, offset + 2 + i));
				else
					proto_item_append_text(dcp_item, " %02x", tvb_get_guint8(tvb, offset + 2 + i));
			}
			proto_item_append_text(dcp_item, ")");
			break;

		case 37:
			if(option_len==3)
				proto_tree_add_uint(dcp_options_tree, hf_dcp_ndp_count, tvb, offset + 2, 1, 
						    tvb_get_guint8(tvb, offset + 2));
			else if (option_len==4)
				proto_tree_add_uint(dcp_options_tree, hf_dcp_ndp_count, tvb, offset + 2, 2, 
						    tvb_get_ntohs(tvb, offset + 2));
			else if (option_len==5)
				proto_tree_add_uint(dcp_options_tree, hf_dcp_ndp_count, tvb, offset + 2, 3, 
						    tvb_get_ntoh24(tvb, offset + 2));
			else
				proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "NDP Count too long (max 3 bytes)");
			
			break;

		case 38:
			dcp_item = proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Ack Vector0(");
			for (i = 0; i < option_len - 2; i++) { 
				if(i==0)
					proto_item_append_text(dcp_item, "%02x", tvb_get_guint8(tvb, offset + 2 + i));
				else
					proto_item_append_text(dcp_item, " %02x", tvb_get_guint8(tvb, offset + 2 + i));
			}
			proto_item_append_text(dcp_item, ")");
			break;

		case 39:
			dcp_item = proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Ack Vector1(");
			for (i = 0; i < option_len - 2; i++) { 
				if(i==0)
					proto_item_append_text(dcp_item, "%02x", tvb_get_guint8(tvb, offset + 2 + i));
				else
					proto_item_append_text(dcp_item, " %02x", tvb_get_guint8(tvb, offset + 2 + i));
			}
			proto_item_append_text(dcp_item, ")");
			break;

		case 40:
			dcp_item = proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Data Dropped(");
			for (i = 0; i < option_len - 2; i++) { 
				if(i==0)
					proto_item_append_text(dcp_item, "%02x", tvb_get_guint8(tvb, offset + 2 + i));
				else
					proto_item_append_text(dcp_item, " %02x", tvb_get_guint8(tvb, offset + 2 + i));
			}
			proto_item_append_text(dcp_item, ")");
			break;

		case 41:
			if(option_len==6)
				proto_tree_add_uint(dcp_options_tree, hf_dcp_timestamp, tvb, offset + 2, 4, 
						    tvb_get_ntohl(tvb, offset + 2));
			else
				proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, 
						    "Timestamp too long [%u != 6]", option_len);
			break;

		case 42:
			if(option_len==6)
				proto_tree_add_uint(dcp_options_tree, hf_dcp_timestamp_echo, tvb, offset + 2, 4,
						    tvb_get_ntohl(tvb, offset + 2));
			else if (option_len==8) {
				proto_tree_add_uint(dcp_options_tree, hf_dcp_timestamp_echo, tvb, offset + 2, 4,
						    tvb_get_ntohl(tvb, offset + 2));
				
				proto_tree_add_uint(dcp_options_tree, hf_dcp_elapsed_time, tvb, offset + 4, 2, 
						    tvb_get_ntohs(tvb, offset + 4));
			} else if (option_len==10) {
				proto_tree_add_uint(dcp_options_tree, hf_dcp_timestamp_echo, tvb, offset + 2, 4,
						    tvb_get_ntohl(tvb, offset + 2));
				
				proto_tree_add_uint(dcp_options_tree, hf_dcp_elapsed_time, tvb, offset + 4, 4, 
						    tvb_get_ntohl(tvb, offset + 4));
			} else
				proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Wrong Timestamp Echo length");
			break;

		case 43:
			if(option_len==4)
				proto_tree_add_uint(dcp_options_tree, hf_dcp_elapsed_time, tvb, offset + 2, 2,
						    tvb_get_ntohs(tvb, offset + 2));
			else if (option_len==6)				
				proto_tree_add_uint(dcp_options_tree, hf_dcp_elapsed_time, tvb, offset + 2, 4, 
						    tvb_get_ntohl(tvb, offset + 2));
			else
				proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Wrong Elapsed Time length");
			break;

		case 44:
			if(option_len==6) {
				proto_tree_add_uint(dcp_options_tree, hf_dcp_data_checksum, tvb, offset + 2, 4, 
						    tvb_get_ntohl(tvb, offset + 2));
			} else
				proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Wrong Data checksum length");
			break;
			
		default :
			if(((option_type >= 45) && (option_type <= 127)) || 
			   ((option_type >=  3) && (option_type <=  31))) {
				proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Reserved");
				break;
			}

			if (option_type >= 128) {
				proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "CCID option %d", option_type);
				break;
			}
			
			/* if here we don't know this option */
			proto_tree_add_text(dcp_options_tree, tvb, offset, option_len, "Unknown");
			break;

		} /* end switch() */

		offset+=option_len; /* Skip over the dissected option */

	} /* end while() */
}

static void dissect_dcp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree *dcp_tree = NULL;
	proto_tree *dcp_options_tree = NULL;
	proto_item *dcp_item = NULL;

	vec_t      cksum_vec[4];
	guint32    phdr[2];
	guint16    computed_cksum;
	guint      offset = 0;
	guint      len = 0;
	guint      reported_len = 0;
	guint      advertised_dccp_header_len = 0;
	guint      options_len = 0;
	e_dcphdr   *dcph;
	
	/* get at least a full message header */
	if(!tvb_bytes_exist(tvb, 0, DCCP_HDR_LEN_MIN)) {
		/* DBG("malformed\n"); */
		if (tree)
			proto_tree_add_boolean_hidden(dcp_tree, hf_dcp_malformed, tvb, offset, 0, TRUE);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_add_fstr(pinfo->cinfo, COL_INFO, "Packet too short");
		THROW(ReportedBoundsError);
        }

	dcph=ep_alloc(sizeof(e_dcphdr));

	memset(dcph, 0, sizeof(e_dcphdr));

	SET_ADDRESS(&dcph->ip_src, pinfo->src.type, pinfo->src.len, pinfo->src.data);
	SET_ADDRESS(&dcph->ip_dst, pinfo->dst.type, pinfo->dst.len, pinfo->dst.data);
	
	if (check_col(pinfo->cinfo, COL_PROTOCOL))
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "DCCP");
	if (check_col(pinfo->cinfo, COL_INFO))
		col_clear(pinfo->cinfo, COL_INFO);
	
        /* Extract generic header */
	dcph->sport=tvb_get_ntohs(tvb, offset);
	/* DBG("dcph->sport: %d\n", dcph->sport); */
	dcph->dport=tvb_get_ntohs(tvb, offset+2);
	/* DBG("dcph->dport: %d\n", dcph->dport); */

	/* update pinfo structure. I guess I have to do it, because this is a transport protocol dissector. Right? */
	pinfo->ptype=PT_DCCP;
	pinfo->srcport=dcph->sport;
	pinfo->destport=dcph->dport;

	dcph->data_offset=tvb_get_guint8(tvb, offset+4);
	/* DBG("dcph->data_offset: %d\n", dcph->data_offset); */
	dcph->cscov=tvb_get_guint8(tvb, offset+5)&0x0F;
	/* DBG("dcph->cscov: %d\n", dcph->cscov); */
	dcph->ccval=tvb_get_guint8(tvb, offset+5)&0xF0;
	/* DBG("dcph->ccval: %d\n", dcph->ccval); */
	dcph->checksum=tvb_get_ntohs(tvb, offset+6);
	/* DBG("dcph->checksum: %d\n", dcph->checksum); */
	dcph->reserved1=tvb_get_guint8(tvb, offset+8)&0xE0;
	dcph->reserved1>>=5;
	/* DBG("dcph->reserved1: %d\n", dcph->reserved1); */
	dcph->type=tvb_get_guint8(tvb, offset+8)&0x1E;
	dcph->type>>=1;
	/* DBG("dcph->type: %d\n", dcph->type); */
	dcph->x=tvb_get_guint8(tvb, offset+8)&0x01;
	/* DBG("dcph->x: %d\n", dcph->x); */
	if(dcph->x) {
		if(!tvb_bytes_exist(tvb, 0, DCCP_HDR_LEN)) { /* at least 16 bytes */
			/* DBG("malformed\n"); */
			proto_tree_add_boolean_hidden(dcp_tree, hf_dcp_malformed, tvb, offset, 0, TRUE);
			THROW(ReportedBoundsError);
		}
		dcph->reserved2=tvb_get_guint8(tvb, offset+9);
		/* DBG("dcph->reserved2: %u\n", dcph->reserved2); */
		dcph->seq=tvb_get_ntohs(tvb, offset+10);
		dcph->seq<<=32;
		dcph->seq+=tvb_get_ntohl(tvb, offset+12);
		/* DBG("dcph->seq[48bits]: %llu\n", dcph->seq); */
	} else {
		dcph->seq=tvb_get_guint8(tvb, offset+9);
		dcph->seq<<=16;
		dcph->seq+=tvb_get_ntohs(tvb, offset+10);
		/* DBG("dcph->seq[24bits]: %llu\n", dcph->seq); */
	}
	
	if (check_col(pinfo->cinfo, COL_INFO))
		col_add_fstr(pinfo->cinfo, COL_INFO, "%s > %s [%s] Seq=%" PRIu64,
			     get_dccp_port(dcph->sport),
			     get_dccp_port(dcph->dport),
			     val_to_str(dcph->type, dcp_packet_type_vals, "Unknown Type"),
			     dcph->seq);
	
	
	if (tree) {
		if(dcp_summary_in_tree) {
			dcp_item = 
				proto_tree_add_protocol_format(tree, proto_dcp, tvb, offset, dcph->data_offset*4,
							       "Datagram Congestion Control Protocol, Src Port: %s (%u), Dst Port: %s (%u)"
							       " [%s] Seq=%" PRIu64,
							       get_dccp_port(dcph->sport), dcph->sport,
							       get_dccp_port(dcph->dport), dcph->dport,
							       val_to_str(dcph->type, dcp_packet_type_vals, "Unknown Type"),
							       dcph->seq);
		} else {
			dcp_item = proto_tree_add_item(tree, proto_dcp, tvb, offset, 8, FALSE);
		}

		dcp_tree = proto_item_add_subtree(dcp_item, ett_dcp);
		
		proto_tree_add_uint_format(dcp_tree, hf_dcp_srcport, tvb, offset, 2, dcph->sport,
					   "Source port: %s (%u)", get_dccp_port(dcph->sport), dcph->sport);
		proto_tree_add_uint_format(dcp_tree, hf_dcp_dstport, tvb, offset + 2, 2, dcph->dport,
					   "Destination port: %s (%u)", get_dccp_port(dcph->dport), dcph->dport);

		proto_tree_add_uint_hidden(dcp_tree, hf_dcp_port, tvb, offset, 2, dcph->sport);
		proto_tree_add_uint_hidden(dcp_tree, hf_dcp_port, tvb, offset + 2, 2, dcph->dport);
		
		proto_tree_add_uint(dcp_tree, hf_dcp_data_offset, tvb, offset + 4, 1, dcph->data_offset);
		proto_tree_add_uint(dcp_tree, hf_dcp_ccval, tvb, offset + 5, 1, dcph->ccval);
		proto_tree_add_uint(dcp_tree, hf_dcp_cscov, tvb, offset + 5, 1, dcph->cscov);
				
		/* checksum analisys taken from packet-udp */
				
		reported_len = tvb_reported_length(tvb);
		len = tvb_length(tvb);
		if (dcph->checksum == 0) {
			/* No checksum supplied in the packet */
			proto_tree_add_uint_format(dcp_tree, hf_dcp_checksum, tvb,
						   offset + 6, 2, dcph->checksum, "Checksum: 0x%04x (none)", dcph->checksum);
		} else if (!pinfo->fragmented && len >= reported_len) {

			/* The packet isn't part of a fragmented datagram and isn't
			   truncated, so we can checksum it.
			   XXX - make a bigger scatter-gather list once we do fragment
			   reassembly? */

			if (dccp_check_checksum) {
				
				/* Set up the fields of the pseudo-header. */
				cksum_vec[0].ptr = pinfo->src.data;
				cksum_vec[0].len = pinfo->src.len;
				cksum_vec[1].ptr = pinfo->dst.data;
				cksum_vec[1].len = pinfo->dst.len;
				cksum_vec[2].ptr = (const guint8 *)&phdr;
				switch (pinfo->src.type) {
					
				case AT_IPv4:
					phdr[0] = g_htonl((IP_PROTO_DCCP<<16) + reported_len);
					cksum_vec[2].len = 4;
					break;
				case AT_IPv6:
					phdr[0] = g_htonl(reported_len);
					phdr[1] = g_htonl(IP_PROTO_DCCP);
					cksum_vec[2].len = 8;
					break;
					
				default:
					/* DCCP runs only atop IPv4 and IPv6.... */
				  /*DISSECTOR_ASSERT_NOT_REACHED();*/
					break;
				}
				cksum_vec[3].ptr = tvb_get_ptr(tvb, offset, len);
				cksum_vec[3].len = reported_len;
				computed_cksum = in_cksum(&cksum_vec[0], 4);
				if (computed_cksum == 0) {
					proto_tree_add_uint_format(dcp_tree, hf_dcp_checksum, tvb,
								   offset + 6, 2, dcph->checksum, 
								   "Checksum: 0x%04x [correct]", dcph->checksum);
				} else {
					proto_tree_add_boolean_hidden(dcp_tree, hf_dcp_checksum_bad, tvb, offset + 6, 2, TRUE);
					proto_tree_add_uint_format(dcp_tree, hf_dcp_checksum, tvb, offset + 6, 2, dcph->checksum,
								   "Checksum: 0x%04x [incorrect, should be 0x%04x]", dcph->checksum,
								   in_cksum_shouldbe(dcph->checksum, computed_cksum));
				}
			} else {
				proto_tree_add_uint_format(dcp_tree, hf_dcp_checksum, tvb, 
							   offset + 6, 2, dcph->checksum, "Checksum: 0x%04x", dcph->checksum);
			}
		} else {
			proto_tree_add_uint_format(dcp_tree, hf_dcp_checksum, tvb, 
						   offset + 6, 2, dcph->checksum, "Checksum: 0x%04x", dcph->checksum);
		}
				
		proto_tree_add_uint_hidden(dcp_tree, hf_dcp_res1, tvb, offset + 8, 1, dcph->reserved1);
		proto_tree_add_uint(dcp_tree, hf_dcp_type, tvb, offset + 8, 1, dcph->type);
		proto_tree_add_boolean(dcp_tree, hf_dcp_x, tvb, offset + 8, 1, dcph->x);
		if(dcph->x) {
			proto_tree_add_uint_hidden(dcp_tree, hf_dcp_res2, tvb, offset + 9, 1, dcph->reserved2);
			proto_tree_add_uint64(dcp_tree, hf_dcp_seq, tvb, offset + 10, 6, dcph->seq);
		} else {
			proto_tree_add_uint64(dcp_tree, hf_dcp_seq, tvb, offset + 9, 3, dcph->seq);
			
		}
	}		

	if(dcph->x)
		offset+=16; /* Skip over extended Generic header */
	else
		offset+=12; /* Skip over not extended Generic header */
	
	/* dissecting type depending additional fields */
	switch(dcph->type) {
			
	case 0x0: /* DCCP-Request */
		if(!tvb_bytes_exist(tvb, offset, 4)) { /* at least 4 byte */
			if(tree)
				proto_tree_add_text(dcp_tree, tvb, offset, -1, "too short packet");
			return;
		}
		dcph->service_code=tvb_get_ntohl(tvb, offset);
		if(tree)
			proto_tree_add_uint(dcp_tree, hf_dcp_service_code, tvb, offset, 4, dcph->service_code);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " (service=%u)", dcph->service_code);

		offset+=4; /* Skip over service code */
		break;

	case 0x1: /* DCCP-Response */
		if(!tvb_bytes_exist(tvb, offset, 8)) { /* at least 8 byte */
			if(tree)
				proto_tree_add_text(dcp_tree, tvb, offset, -1, "too short packet");
			return;
		}
		dcph->ack_reserved=tvb_get_ntohs(tvb, offset);
		if(tree)
			proto_tree_add_uint_hidden(dcp_tree, hf_dcp_ack_res, tvb, offset, 2, dcph->ack_reserved);
		dcph->ack=tvb_get_ntohs(tvb, offset+2);  
		dcph->ack<<=32;                          
		dcph->ack+=tvb_get_ntohl(tvb, offset+4);
		
		if(tree)
			proto_tree_add_uint64(dcp_tree, hf_dcp_ack, tvb, offset + 2, 6, dcph->ack);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", dcph->ack);
		
		offset+=8; /* Skip over Acknowledgement Number Subheader */

		if(!tvb_bytes_exist(tvb, offset, 4)) { /* at least 4 byte */
			if(tree)
				proto_tree_add_text(dcp_tree, tvb, offset, -1, "too short packet");
			return;
		}
		dcph->service_code=tvb_get_ntohl(tvb, offset);
		if(tree)
			proto_tree_add_uint(dcp_tree, hf_dcp_service_code, tvb, offset, 4, dcph->service_code);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " (service=%u)", dcph->service_code);

		offset+=4; /* Skip over service code */
		break;

	case 0x2: /* DCCP-Data */
		/* nothing to dissect */
		break;
			
	case 0x3: /* DCCP-Ack */
	case 0x4: /* DCCP-DataAck */
		if(dcph->x) {
			if(!tvb_bytes_exist(tvb, offset, 8)) { /* at least 8 byte */
				if(tree)
					proto_tree_add_text(dcp_tree, tvb, offset, -1, "too short packet");
				return;
			}
			dcph->ack_reserved=tvb_get_ntohs(tvb, offset);
			if(tree)
				proto_tree_add_uint_hidden(dcp_tree, hf_dcp_ack_res, tvb, offset, 2, dcph->ack_reserved);
			dcph->ack=tvb_get_ntohs(tvb, offset+2);
			dcph->ack<<=32;
			dcph->ack+=tvb_get_ntohl(tvb, offset+4);
			if(tree)
				proto_tree_add_uint64(dcp_tree, hf_dcp_ack, tvb, offset + 2, 6, dcph->ack);
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", dcph->ack);

			offset+=8; /* Skip over Acknowledgement Number Subheader */
		} else {
			if(!tvb_bytes_exist(tvb, offset, 4)) { /* at least 4 byte */
				if(tree)
					proto_tree_add_text(dcp_tree, tvb, offset, -1, "too short packet");
				return;
			}
			dcph->ack_reserved=tvb_get_guint8(tvb, offset);
			if(tree)
				proto_tree_add_uint_hidden(dcp_tree, hf_dcp_ack_res, tvb, offset, 1, dcph->ack_reserved);
			dcph->ack=tvb_get_guint8(tvb, offset+1);
			dcph->ack<<=16;
			dcph->ack+=tvb_get_ntohs(tvb, offset+2);
			if(tree)
				proto_tree_add_uint64(dcp_tree, hf_dcp_ack, tvb, offset + 1, 3, dcph->ack);
			if (check_col(pinfo->cinfo, COL_INFO))
				col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", dcph->ack);

			offset+=4; /* Skip over Acknowledgement Number Subheader */
		}
		break;

	case 0x7: /* DCCP-Reset */
		if(!tvb_bytes_exist(tvb, offset, 8)) { /* at least 8 byte */
			if(tree)
				proto_tree_add_text(dcp_tree, tvb, offset, -1, "too short packet");
			return;
		}
		dcph->ack_reserved=tvb_get_ntohs(tvb, offset);
		if(tree)
			proto_tree_add_uint_hidden(dcp_tree, hf_dcp_ack_res, tvb, offset, 2, dcph->ack_reserved);
		dcph->ack=tvb_get_ntohs(tvb, offset+2);
		dcph->ack<<=32;
		dcph->ack+=tvb_get_ntohl(tvb, offset+4);
		if(tree)
			proto_tree_add_uint64(dcp_tree, hf_dcp_ack, tvb, offset + 2, 6, dcph->ack);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", dcph->ack);

		offset+=8; /* Skip over Acknowledgement Number Subheader */
			
		dcph->reset_code=tvb_get_guint8(tvb, offset);
		dcph->data1=tvb_get_guint8(tvb, offset+1);
		dcph->data2=tvb_get_guint8(tvb, offset+2);
		dcph->data3=tvb_get_guint8(tvb, offset+3);
		if(tree) {
			proto_tree_add_uint(dcp_tree, hf_dcp_reset_code, tvb, offset, 1, dcph->reset_code);
			proto_tree_add_uint(dcp_tree, hf_dcp_data1, tvb, offset + 1, 1, dcph->data1);
			proto_tree_add_uint(dcp_tree, hf_dcp_data2, tvb, offset + 2, 1, dcph->data2);
			proto_tree_add_uint(dcp_tree, hf_dcp_data3, tvb, offset + 3, 1, dcph->data3);
		}
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " (code=%s)", val_to_str(dcph->reset_code, dcp_reset_code_vals, "Unknown"));
		
		offset+=4; /* Skip over Reset Code and data123 */
		break;

	case 0x5: /* DCCP-CloseReq */
	case 0x6: /* DCCP-Close */
	case 0x8: /* DCCP-Sync */
	case 0x9: /* DCCP-SyncAck */
		if(!tvb_bytes_exist(tvb, offset, 8)) { /* at least 8 byte */
			if(tree)
				proto_tree_add_text(dcp_tree, tvb, offset, -1, "too short packet");
			return;
		}
		dcph->ack_reserved=tvb_get_ntohs(tvb, offset);
		if(tree)
			proto_tree_add_uint_hidden(dcp_tree, hf_dcp_ack_res, tvb, offset, 2, dcph->ack_reserved);
		dcph->ack=tvb_get_ntohs(tvb, offset+2);
		dcph->ack<<=32;
		dcph->ack+=tvb_get_ntohl(tvb, offset+4);
		if(tree)
			proto_tree_add_uint64(dcp_tree, hf_dcp_ack, tvb, offset + 2, 6, dcph->ack);
		if (check_col(pinfo->cinfo, COL_INFO))
			col_append_fstr(pinfo->cinfo, COL_INFO, " (Ack=%" PRIu64 ")", dcph->ack);

		offset+=8; /* Skip over Acknowledgement Number Subheader */
		break;

	default:
		if(tree)
			proto_tree_add_text(dcp_tree, tvb, offset, -1, "Reserved packet type: unable to dissect further");
		return;
		break;
	}
	
	
	/*  note: data_offset is the offset from the start of the packet's DCCP header to the
	 *  start of its application data area, in 32-bit words. 
	 */
		
	/* it's time to do some checks */
	advertised_dccp_header_len = dcph->data_offset*4;
	options_len = advertised_dccp_header_len - offset;
	
	if ( advertised_dccp_header_len > DCCP_HDR_LEN_MAX ) {
		if(tree)
			proto_tree_add_text(dcp_tree, tvb, 4, 2, 
					    "bogus data offset, advertised header length (%d) is larger than max (%d)",
					    advertised_dccp_header_len, DCCP_HDR_LEN_MAX);
		return;
	}
		
	if(!tvb_bytes_exist(tvb, 0, advertised_dccp_header_len)) {
		if(tree)
			proto_tree_add_text(dcp_tree, tvb, offset, -1, "too short packet: missing %d bytes of DCCP header", 
					    advertised_dccp_header_len - tvb_reported_length_remaining(tvb, offset));
		return;
	}
		
	if(options_len > DCCP_OPT_LEN_MAX) {
		/* DBG("malformed\n"); */
		if(tree)
			proto_tree_add_boolean_hidden(dcp_tree, hf_dcp_malformed, tvb, offset, 0, TRUE);
		THROW(ReportedBoundsError);
	}
	
	
	/* Dissecting Options (if here we have at least (advertised_dccp_header_len - offset) bytes of options) */		
	if(advertised_dccp_header_len == offset) {
		; /* ok no options, no need to skip over */
	} else if (advertised_dccp_header_len < offset) {
		if(tree) {
			proto_tree_add_text(dcp_tree, tvb, 4, 2, 
					    "bogus data offset, advertised header length (%d) is shorter than expected",
					    advertised_dccp_header_len);
			proto_tree_add_boolean_hidden(dcp_tree, hf_dcp_malformed, tvb, offset, 0, TRUE);
		}
		THROW(ReportedBoundsError);
	} else {
		if(dcp_tree) {
			dcp_item = proto_tree_add_none_format(dcp_tree, hf_dcp_options, tvb, offset, options_len, "Options: (%u bytes)", options_len);
			dcp_options_tree = proto_item_add_subtree(dcp_item, ett_dcp_options);
		}
		dissect_options(tvb, pinfo, dcp_options_tree, tree, dcph, offset, offset + options_len);
	}
		
	offset+=options_len; /* Skip over Options */			
	
	/* Queuing tap data */
	tap_queue_packet(dccp_tap, pinfo, dcph);
	
	/* Call sub-dissectors */

	if (!pinfo->in_error_pkt || tvb_length_remaining(tvb, offset) > 0)
		decode_dccp_ports(tvb, offset, pinfo, tree, dcph->sport, dcph->dport);
}


void proto_register_dcp(void)
{
	module_t *dcp_module;

	static hf_register_info hf[] = {
		{ &hf_dcp_srcport,
		{ "Source Port",	"dcp.srcport", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_dstport,
		{ "Destination Port",	"dcp.dstport", FT_UINT16, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

                { &hf_dcp_port,
		{ "Source or Destination Port", "dcp.port", FT_UINT16, BASE_DEC,  NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_data_offset,
		{ "Data Offset",        "dcp.data_offset", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_ccval,
		{ "CCVal",	        "dcp.ccval", FT_UINT8, BASE_DEC,  NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_cscov,
		{ "Checksum Coverage",	"dcp.cscov", FT_UINT8, BASE_DEC,  NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_checksum_bad,
		{ "Bad Checksum",	"dcp.checksum_bad", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
		  "", HFILL }},
		
		{ &hf_dcp_checksum,
		{ "Checksum",		"dcp.checksum", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_res1,
		{ "Reserved",		"dcp.res1", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_res2,
		{ "Reserved",		"dcp.res2", FT_UINT8, BASE_HEX, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_type,
		{ "Type",	        "dcp.type", FT_UINT8, BASE_DEC, VALS(dcp_packet_type_vals), 0x0,
		  "", HFILL }},

		{ &hf_dcp_x,
		{ "Extended Sequence Numbers", "dcp.x", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_seq,
		{ "Sequence Number",    "dcp.seq", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_ack_res,
		{ "Reserved",		"dcp.ack_res", FT_UINT16, BASE_HEX, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_ack,
		{ "Acknowledgement Number", "dcp.ack", FT_UINT64, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_service_code,
		{ "Service Code", "dcp.service_code", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_reset_code,
		{ "Reset Code", "dcp.reset_code", FT_UINT8, BASE_DEC, VALS(dcp_reset_code_vals), 0x0,
		  "", HFILL }},

		{ &hf_dcp_data1,
		{ "Data 1",     "dcp.data1", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_data2,
		{ "Data 2",     "dcp.data2", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_data3,
		{ "Data 3",     "dcp.data3", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_option_type,
		{ "Option Type",     "dcp.option_type", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_feature_number,
		{ "Feature Number",   "dcp.feature_number", FT_UINT8, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_ndp_count,
		{ "NDP Count",   "dcp.ndp_count", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_timestamp,
		{ "Timestamp",   "dcp.timestamp", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_timestamp_echo,
		{ "Timestamp Echo",   "dcp.timestamp_echo", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_elapsed_time,
		{ "Elapsed Time",   "dcp.elapsed_time", FT_UINT32, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_data_checksum,
		{ "Data Checksum",  "dcp.checksum_data", FT_UINT32, BASE_HEX, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_malformed,
		{ "", "dcp.malformed", FT_BOOLEAN, BASE_DEC, NULL, 0x0,
		  "", HFILL }},

		{ &hf_dcp_options,
		{ "Options", "dcp.options", FT_NONE, BASE_DEC, NULL, 0x0,
		  "DCP Options fields", HFILL }},

	};

	static gint *ett[] = {
		&ett_dcp,
		&ett_dcp_options,
	};

	proto_dcp = proto_register_protocol("Datagram Congestion Control Protocol", "DCP", "dcp");
	proto_register_field_array(proto_dcp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	/* subdissectors */
	dcp_subdissector_table = register_dissector_table("dcp.port", "DCP port", FT_UINT16, BASE_DEC);
	register_heur_dissector_list("dcp", &heur_subdissector_list);

	/* reg preferences */
	dcp_module = prefs_register_protocol(proto_dcp, NULL);
	prefs_register_bool_preference(dcp_module, "summary_in_tree",
				       "Show DCCP summary in protocol tree",
				       "Whether the DCCP summary line should be shown in the protocol tree",
				       &dcp_summary_in_tree);

	prefs_register_bool_preference(dcp_module, "try_heuristic_first",
				       "Try heuristic sub-dissectors first",
				       "Try to decode a packet using an heuristic sub-dissector before using a sub-dissector "
				       "registered to a specific port",
				       &try_heuristic_first);

	prefs_register_bool_preference(dcp_module, "check_checksum",
				       "Check the validity of the DCCP checksum when possible",
				       "Whether to check the validity of the DCCP checksum",
				       &dccp_check_checksum);
}

void proto_reg_handoff_dcp(void)
{
	dissector_handle_t dcp_handle;

	dcp_handle = create_dissector_handle(dissect_dcp, proto_dcp);
	dissector_add("ip.proto", IP_PROTO_DCCP, dcp_handle);
	data_handle = find_dissector("data");
	dccp_tap = register_tap("dccp");
}
