/* packet-rohc.c
 * Routines for RObust Header Compression (ROHC) dissection.
 *
 * Copyright 2011, Anders Broman <anders.broman[at]ericsson.com>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
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
 *
 * Ref:
 * http://www.ietf.org/rfc/rfc3095.txt         RObust Header Compression (ROHC): Framework and four profiles: RTP, UDP, ESP, and uncompressed
 * http://datatracker.ietf.org/doc/rfc4815/    RObust Header Compression (ROHC): Corrections and Clarifications to RFC 3095
 * http://datatracker.ietf.org/doc/rfc5225/    RObust Header Compression Version 2 (ROHCv2): Profiles for RTP, UDP, IP, ESP and UDP-Lite
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif


#include <epan/packet.h>
#include <epan/etypes.h>
#include <epan/ipproto.h>
#include <epan/rtp_pt.h>
#include <epan/expert.h>

#include "packet-rohc.h"
/* Initialize the protocol and registered fields */
static int proto_rohc			= -1;


static int hf_rohc_padding = -1;
static int hf_rohc_add_cid = -1;
static int hf_rohc_feedback = -1;
static int hf_rohc_code = -1;
static int hf_rohc_size = -1;
static int hf_rohc_ir_packet = -1;
static int hf_rohc_ir_dyn_packet = -1;
static int hf_rohc_small_cid = -1;
static int hf_rohc_large_cid = -1;
static int hf_rohc_acktype = -1;
static int hf_rohc_mode = -1;
static int hf_rohc_sn = -1;
static int hf_rohc_fb1_sn = -1;
static int hf_rohc_rtp_opt_type = -1;
static int hf_rohc_rtp_opt_len = -1;
static int hf_rohc_rtp_crc = -1;
static int hf_rohc_rtp_opt_sn = -1;
static int hf_rohc_feedback_option_clock = -1;
static int hf_rohc_profile = -1;
static int hf_rohc_d_bit = -1;
static int hf_rohc_rtp_version = -1;
static int hf_rohc_rtp_protocol = -1;
static int hf_rohc_rtp_ipv4_src = -1;
static int hf_rohc_rtp_ipv4_dst = -1;
static int hf_rohc_rtp_udp_src_port = -1;
static int hf_rohc_rtp_udp_dst_port = -1;
static int hf_rohc_rtp_ssrc = -1;
static int hf_rohc_rtp_tos = -1;
static int hf_rohc_rtp_ttl = -1;
static int hf_rohc_rtp_id = -1;
static int hf_rohc_rtp_df = -1;
static int hf_rohc_rtp_rnd = -1;
static int hf_rohc_rtp_nbo = -1;
static int hf_rohc_rtp_checksum = -1;
static int hf_rohc_dynamic_udp_seqnum = -1;
static int hf_rohc_rtp_v = -1;
static int hf_rohc_rtp_p = -1;
static int hf_rohc_rtp_rx = -1;
static int hf_rohc_rtp_cc = -1;
static int hf_rohc_rtp_m = -1;
static int hf_rohc_rtp_pt = -1;
static int hf_rohc_rtp_sn = -1;
static int hf_rohc_rtp_timestamp = -1;
static int hf_rohc_rtp_x = -1;
static int hf_rohc_rtp_mode = -1;
static int hf_rohc_rtp_tis = -1;
static int hf_rohc_rtp_tss = -1;
static int hf_rohc_rtp_ts_stride = -1;
static int hf_rohc_rtp_time_stride = -1;
static int hf_rohc_var_len = -1;

static int ett_rohc = -1;
static int ett_rohc_fb = -1;
static int ett_rohc_feedback = -1;
static int ett_rohc_ir = -1;
static int ett_rohc_ir_dyn = -1;
static int ett_rohc_rtp_static = -1;
static int ett_rohc_rtp_dynamic = -1;

/* RTP profile and IPv4 hard wired for now */
static guint8 g_profile = 1;
static guint8 g_version = 4;

/* ROHC Profiles */
#define ROHC_PROFILE_RTP	1
#define ROHC_PROFILE_UDP	2

static const value_string rohc_profile_vals[] =
{
   { 0x0000,    "ROHC uncompressed" },          /*RFC 5795*/
   { 0x0001,    "ROHC RTP" },                   /*RFC 3095*/
   { 0x0002,    "ROHC UDP" },                   /*RFC 3095*/
   { 0x0003,    "ROHC ESP" },                   /*RFC 3095*/
   { 0x0004,    "ROHC IP" },                    /*RFC 3843*/
   { 0x0005,    "ROHC LLA" },                   /*RFC 3242*/
   { 0x0105,    "ROHC LLA with R-mode" },       /*RFC 3408*/
   { 0x0006,    "ROHC TCP" },                   /*RFC 4996*/
   { 0x0007,    "ROHC RTP/UDP-Lite" },          /*RFC 4019*/
   { 0x0008,    "ROHC UDP-Lite" },              /*RFC 4019*/
   { 0x0101,    "ROHCv2 RTP" },                 /*RFC 5225*/
   { 0x0102,    "ROHCv2 UDP" },                 /*RFC 5225*/
   { 0x0103,    "ROHCv2 ESP" },                 /*RFC 5225*/
   { 0x0104,    "ROHCv2 IP" },                  /*RFC 5225*/
   { 0x0107,    "ROHCv2 RTP/UDP-Lite" },        /*RFC 5225*/
   { 0x0108,    "ROHCv2 UDP-Lite" },            /*RFC 5225*/
  { 0, NULL },
};

static const value_string rohc_acktype_vals[] =
{
  { 0,    "ACK" },
  { 1,    "NACK" },
  { 2,    "STATIC-NACK" },
  { 3,    "reserved (MUST NOT be used.  Otherwise unparsable)" },
  { 0, NULL },
};

static const value_string rohc_mode_vals[] =
{
  { 0,    "Reserved" },
  { 1,    "Unidirectional" },
  { 2,    "Bidirectional Optimistic" },
  { 3,    "Bidirectional Reliable" },
  { 0, NULL },
};

static const value_string rohc_rtp_opt_type_vals[] =
{
  { 1,    "CRC" },
  { 2,    "Reject" },
  { 3,    "SN-NOT-VALID" },
  { 4,    "SN" },
  { 5,    "Clock" },
  { 6,    "Jitter" },
  { 7,    "LOSS" },
  { 0, NULL },
};



static const value_string rohc_rtp_version_vals[] =
{
  { 4,    "IPv4" },
  { 6,    "IPv6" },
  { 0, NULL },
};

static const value_string rohc_var_len_vals[] =
{
  { 0,    "One octet" },
  { 2,    "Two octets" },
  { 6,    "Three octets" },
  { 7,    "Four octets" },
  { 0, NULL },
};


/* 4.5.6.  Self-describing variable-length values */
static guint32
get_self_describing_var_len_val(tvbuff_t *tvb, proto_tree *tree, int offset, int hf_index, guint8 *val_len){
	guint8 oct;
	guint32 val = 0;
	int num_bits = 0, bit_offset = offset <<3;

	oct = tvb_get_guint8(tvb, offset);
	if((oct&0x80)==0){
		/* One octet */
		*val_len = 1;
		val = (oct&0x7f);
		proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
		num_bits = 7;
		bit_offset++;
	}else if((oct&0xc0)==0x80){
		/* Two octets */
		*val_len = 2;
		proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 2, ENC_BIG_ENDIAN);
		bit_offset+=2;
		num_bits = 14;
		val =  tvb_get_ntohs(tvb, offset)&0x3fff;
	}else if((oct&0xe0)==0xc0){
		/* Three octets */
		*val_len = 3;
		proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 3, ENC_BIG_ENDIAN);
		bit_offset+=3;
		num_bits = 21;
		val = tvb_get_ntoh24(tvb, offset)&0x1fffff;
	}else if ((oct&0xe0)==0xe0){
		/* Four octets */
		*val_len = 4;
		proto_tree_add_bits_item(tree, hf_rohc_var_len, tvb, bit_offset, 4, ENC_BIG_ENDIAN);
		bit_offset+=3;
		num_bits = 29;
		val = tvb_get_ntohl(tvb, offset)&0x1fffffff;
	}
	proto_tree_add_bits_item(tree, hf_index, tvb, bit_offset, num_bits, ENC_BIG_ENDIAN);

	return val;

}

static void
dissect_rohc_feedback_data(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, gint16 feedback_data_len, rohc_info *p_rohc_info){

	proto_item *ti;
	proto_tree *rohc_feedback_tree;
	guint8 opt, opt_len, oct;


	if(feedback_data_len==1){
		/* FEEDBACK-1 */
		proto_item_append_text(p_rohc_info->last_created_item, " (type 1)");
		switch(p_rohc_info->profile){
			case ROHC_PROFILE_RTP: /* 1 */
				/*
				 *     0   1   2   3   4   5   6   7
				 *   +---+---+---+---+---+---+---+---+
				 *   |              SN               |
				 *   +---+---+---+---+---+---+---+---+
				 *
				 */

				oct = tvb_get_guint8(tvb, offset);
				proto_tree_add_item(tree, hf_rohc_fb1_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
				col_append_fstr(pinfo->cinfo, COL_INFO, " (sn=%u)", oct);
				break;
			default:
				proto_tree_add_text(tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
				break;
		}
		return;
	}
	/*  FEEDBACK-2 */
	proto_item_append_text(p_rohc_info->last_created_item, " (type 2)");
	switch(p_rohc_info->profile){
		case ROHC_PROFILE_RTP: /* 1 */
			ti = proto_tree_add_text(tree, tvb, offset, feedback_data_len, "RTP profile-specific information");
			rohc_feedback_tree = proto_item_add_subtree(ti, ett_rohc_feedback);
			proto_tree_add_item(rohc_feedback_tree, hf_rohc_acktype, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(rohc_feedback_tree, hf_rohc_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(rohc_feedback_tree, hf_rohc_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			feedback_data_len-=2;
			while(feedback_data_len>0){
				opt = opt_len = tvb_get_guint8(tvb,offset);
				opt = opt >> 4;
				opt_len = opt_len &0x0f;
				proto_tree_add_item(rohc_feedback_tree, hf_rohc_rtp_opt_type, tvb, offset, 1, ENC_BIG_ENDIAN);
				proto_tree_add_item(rohc_feedback_tree, hf_rohc_rtp_opt_len, tvb, offset, 1, ENC_BIG_ENDIAN);
				offset++;
				feedback_data_len--;
				switch(opt){
					case 1:
						/* CRC */
						proto_tree_add_item(rohc_feedback_tree, hf_rohc_rtp_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
						oct = tvb_get_guint8(tvb, offset);
						col_append_fstr(pinfo->cinfo, COL_INFO, "CRC=%u ", oct);
						break;
					case 2:
						/* REJECT: TODO */
						proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Option data[Not dissected yet]");
						break;
					case 3:
						/* SN-Not-Valid: TODO */
						proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Option data[Not dissected yet]");
						break;
					case 4:
						/* SN */
						proto_tree_add_item(rohc_feedback_tree, hf_rohc_rtp_opt_sn, tvb, offset, 1, ENC_BIG_ENDIAN);
						oct = tvb_get_guint8(tvb, offset);
						col_append_fstr(pinfo->cinfo, COL_INFO, " SN=%u ", oct);
						break;
					case 5:
						/* Clock */
						proto_tree_add_item(tree, hf_rohc_feedback_option_clock, tvb, offset, 1, ENC_BIG_ENDIAN);
						oct = tvb_get_guint8(tvb, offset);
						col_append_fstr(pinfo->cinfo, COL_INFO, " Clock=%u ", oct);
						break;
					case 6:
						/* Jitter: TODO */
						proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Option data[Not dissected yet]");
						break;
					case 7:
						/* Loss: TODO */
						proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Option data[Not dissected yet]");
						break;
					default:
						proto_tree_add_text(tree, tvb, offset, feedback_data_len, "Unknown Option data");
						break;
				}
				feedback_data_len = feedback_data_len - opt_len;
				offset = offset + opt_len;

			}
			break;
		default:
			ti = proto_tree_add_text(tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
			rohc_feedback_tree = proto_item_add_subtree(ti, ett_rohc_feedback);
			proto_tree_add_item(rohc_feedback_tree, hf_rohc_acktype, tvb, offset, 1, ENC_BIG_ENDIAN);
			break;
	}
}
int
dissect_rohc_ir_rtp_profile_dynamic(tvbuff_t *tvb, proto_tree *tree, int offset, rohc_info *p_rohc_info){

	proto_item *item;
	proto_tree *sub_tree;
	guint8 oct, rx, cc, val_len = 0;
	int i, start_offset;

	start_offset = offset;
	item = proto_tree_add_text(tree, tvb, offset, 0, "RTP Profile Dynamic Chain");
	sub_tree = proto_item_add_subtree(item, ett_rohc_rtp_dynamic);

	switch(p_rohc_info->rohc_ip_version){
		case 4:
			/* 5.7.7.4.  Initialization of IPv4 Header [IPv4, section 3.1].
			 * Dynamic part:
			 */
			/* Type of Service */
			proto_tree_add_item(sub_tree, hf_rohc_rtp_tos, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			/* Time to Live */
			proto_tree_add_item(sub_tree, hf_rohc_rtp_ttl, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			/* Identification */
			proto_tree_add_item(sub_tree, hf_rohc_rtp_id, tvb, offset, 2, ENC_BIG_ENDIAN);
			offset+=2;
			/*    +---+---+---+---+---+---+---+---+
			 *    | DF|RND|NBO|         0         |
			 *    +---+---+---+---+---+---+---+---+
			 */
			proto_tree_add_item(sub_tree, hf_rohc_rtp_df, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sub_tree, hf_rohc_rtp_rnd, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_item(sub_tree, hf_rohc_rtp_nbo, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			break;
		case 6:
			proto_tree_add_text(sub_tree, tvb, offset, -1, "Not dissected yet");
			return offset;
			break;
		default:
			break;
	}

	/* 5.7.7.5.  Initialization of UDP Header
	 * Dynamic part:
	 * Checksum
	 */
	proto_tree_add_item(sub_tree, hf_rohc_rtp_checksum, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	if (p_rohc_info->profile == 2) {
		proto_tree_add_item(sub_tree, hf_rohc_dynamic_udp_seqnum, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset +=2;
		proto_item_set_len(item, offset - start_offset);
		proto_tree_add_text(tree, tvb, offset, -1, "RTP data");
		return offset;
	}

	/* 5.7.7.6.  Initialization of RTP Header
	 * Dynamic part:
	 * Checksum
	 *      P, X, CC, PT, M, sequence number, timestamp, timestamp stride,
	 *      CSRC identifiers.
	 *
	 *        0   1   2   3   4   5   6   7
	 *      +---+---+---+---+---+---+---+---+
	 *      |  V=2  | P | RX|      CC       |  (RX is NOT the RTP X bit)
	 *      +---+---+---+---+---+---+---+---+
	 *      | M |            PT             |
	 *      +---+---+---+---+---+---+---+---+
	 *      /      RTP Sequence Number      /  2 octets
	 *      +---+---+---+---+---+---+---+---+
	 *      /   RTP Timestamp (absolute)    /  4 octets
	 *      +---+---+---+---+---+---+---+---+
	 *      /      Generic CSRC list        /  variable length
	 *      +---+---+---+---+---+---+---+---+
	 *      : Reserved  | X |  Mode |TIS|TSS:  if RX = 1
	 *      +---+---+---+---+---+---+---+---+
	 *      :         TS_Stride             :  1-4 octets, if TSS = 1
	 *      +---+---+---+---+---+---+---+---+
	 *      :         Time_Stride           :  1-4 octets, if TIS = 1
	 *      +---+---+---+---+---+---+---+---+
	 */
	proto_tree_add_item(sub_tree, hf_rohc_rtp_v, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_rohc_rtp_p, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_rohc_rtp_rx, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_rohc_rtp_cc, tvb, offset, 1, ENC_BIG_ENDIAN);
	oct = tvb_get_guint8(tvb,offset);
	cc = oct & 0x0f;
	rx = (oct >> 4)& 0x01;
	offset++;
	proto_tree_add_item(sub_tree, hf_rohc_rtp_m, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_rohc_rtp_pt, tvb, offset, 1, ENC_BIG_ENDIAN);
	offset++;
	proto_tree_add_item(sub_tree, hf_rohc_rtp_sn, tvb, offset, 2, ENC_BIG_ENDIAN);
	offset+=2;
	proto_tree_add_item(sub_tree, hf_rohc_rtp_timestamp, tvb, offset, 4, ENC_BIG_ENDIAN);
	offset+=4;
	if(cc > 0){
		/* Dissect Generic CSRC list here */
		for (i = 0; i < cc; i++ ) {
			proto_tree_add_text(sub_tree, tvb, offset, 4, "CSRC item %u",i+1);
			offset+=4;
		}
	}
	/* : Reserved  | X |  Mode |TIS|TSS:  if RX = 1 */
	if(rx==0){
		proto_tree_add_text(tree, tvb, offset, -1, "RTP data");
		return offset;
	}
	proto_tree_add_item(sub_tree, hf_rohc_rtp_x, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_rohc_rtp_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_rohc_rtp_tis, tvb, offset, 1, ENC_BIG_ENDIAN);
	proto_tree_add_item(sub_tree, hf_rohc_rtp_tss, tvb, offset, 1, ENC_BIG_ENDIAN);
	oct = tvb_get_guint8(tvb,offset);
	offset++;
	/* TS_Stride             :  1-4 octets, if TSS = 1 */
	if((oct&0x01)== 1){
		/* TS_Stride encoded as
		 * 4.5.6.  Self-describing variable-length values
		 */
		get_self_describing_var_len_val(tvb, sub_tree, offset, hf_rohc_rtp_ts_stride, &val_len);
		offset = offset + val_len;
	}

	/* Time_Stride           :  1-4 octets, if TIS = 1 */
	if((oct&0x02)== 2){
		/* Time_Stride encoded as
		 * 4.5.6.  Self-describing variable-length values
		 */
		get_self_describing_var_len_val(tvb, sub_tree, offset, hf_rohc_rtp_time_stride, &val_len);
		offset = offset + val_len;
	}

	proto_item_set_len(item, offset - start_offset);
	
	return offset;

}
static void
dissect_rohc_ir_rtp_udp_profile_static(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo, int offset, gboolean d, rohc_info *p_rohc_info){

	proto_item *item;
	proto_tree *sub_tree;
	guint8 version;
	int start_offset;

	start_offset = offset;
	item = proto_tree_add_text(tree, tvb, offset, 0, "RTP/UDP Profile Static Chain");
	sub_tree = proto_item_add_subtree(item, ett_rohc_rtp_static);

	version = tvb_get_guint8(tvb,offset)>>4;
	proto_tree_add_item(sub_tree, hf_rohc_rtp_version, tvb, offset, 1, ENC_BIG_ENDIAN);
	if(p_rohc_info->rohc_ip_version != version){
		expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
			"Configured IP version %u, differs from actual IP version %u, Dissection of other packets may be faulty",
			p_rohc_info->rohc_ip_version, version);
	}

	switch(version){
		case 4:
			/* 5.7.7.4.  Initialization of IPv4 Header [IPv4, section 3.1].
			 * Static part:
			 */
			offset++;
			/* Protocol */
			proto_tree_add_item(sub_tree, hf_rohc_rtp_protocol, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			/* Source Address */
			proto_tree_add_item(sub_tree, hf_rohc_rtp_ipv4_src, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			/* Destination Address */
			proto_tree_add_item(sub_tree, hf_rohc_rtp_ipv4_dst, tvb, offset, 4, ENC_BIG_ENDIAN);
			offset+=4;
			break;
		case 6:
			/* 5.7.7.3.  Initialization of IPv6 Header [IPv6]*/
			proto_tree_add_text(tree, tvb, offset, -1, "Not dissected yet");
			/* TODO: Short term, Calculate length and continue? */
			return;
			break;
		default:
			proto_tree_add_text(sub_tree, tvb, offset, -1, "Error unknown version, only 4 or 6 allowed");
			return;
	}
	if ((p_rohc_info->profile == ROHC_PROFILE_RTP) ||
		(p_rohc_info->profile == ROHC_PROFILE_UDP)) {
		/* 5.7.7.5.  Initialization of UDP Header [RFC-768].
		 * Static part
		 */
		/* Source Port */
		proto_tree_add_item(sub_tree, hf_rohc_rtp_udp_src_port, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		/* Destination Port */
		proto_tree_add_item(sub_tree, hf_rohc_rtp_udp_dst_port, tvb, offset, 2, ENC_BIG_ENDIAN);
		offset+=2;
		if(p_rohc_info->profile == ROHC_PROFILE_UDP){
			if(d==TRUE){
				offset = dissect_rohc_ir_rtp_profile_dynamic(tvb, tree, offset, p_rohc_info);
			}
			proto_item_set_len(item, offset - start_offset);
			proto_tree_add_text(tree, tvb, offset, -1, "UDP data");
			return;
		}

		/* 5.7.7.6.  Initialization of RTP Header [RTP]. */
		/* SSRC */
		proto_tree_add_item(sub_tree, hf_rohc_rtp_ssrc, tvb, offset, 4, ENC_BIG_ENDIAN);
		offset+=4;
		proto_item_set_len(item, offset - start_offset);

		/* D:   D = 1 indicates that the dynamic chain is present. */
		if(d==TRUE){
			offset = dissect_rohc_ir_rtp_profile_dynamic(tvb, tree, offset, p_rohc_info);
		}
		proto_tree_add_text(tree, tvb, offset, -1, "RTP data");
	}
}


static void
dissect_rohc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti, *item, *ir_item;
	proto_tree *rohc_tree, *ir_tree, *sub_tree = NULL;
	int offset = 0, length, x_bit_offset;
	guint8 oct, code, size , cid, profile, val_len;
	gint16 feedback_data_len = 0;
	gboolean is_add_cid = FALSE, d = FALSE;
	rohc_info *p_rohc_info = NULL;
	rohc_info g_rohc_info;


	if(pinfo->private_data != NULL){
		p_rohc_info = pinfo->private_data;
		memset(&g_rohc_info, 0, sizeof(rohc_info));
	}else{
		g_rohc_info.rohc_compression	= FALSE;
		g_rohc_info.rohc_ip_version		= g_version;
		g_rohc_info.cid_inclusion_info	= FALSE;
		g_rohc_info.large_cid_present	= FALSE;
		g_rohc_info.mode				= RELIABLE_BIDIRECTIONAL;
		g_rohc_info.rnd					= FALSE;
		g_rohc_info.udp_checkum_present = FALSE;
		g_rohc_info.profile				= g_profile;
		g_rohc_info.last_created_item   = NULL;
		p_rohc_info = &g_rohc_info;
	}

	length = tvb_length(tvb);

	/* If this is ROHC ethertype clear col */
	if ( pinfo->src.type == AT_ETHER ){
		col_add_fstr(pinfo->cinfo, COL_PROTOCOL, "ROHC(%s)",
			val_to_str(p_rohc_info->profile, rohc_profile_vals, "Unknown"));
		col_clear(pinfo->cinfo, COL_INFO);
	}else{
		col_append_fstr(pinfo->cinfo, COL_PROTOCOL, "|ROHC(%s)",
			val_to_str(p_rohc_info->profile, rohc_profile_vals, "Unknown"));
		/* Append a space if we add stuff to existing col info */
		col_append_str(pinfo->cinfo, COL_INFO, " ");
	}
	/*if (tree) {*/
		ti = proto_tree_add_item(tree, proto_rohc, tvb, 0, -1, ENC_NA);
		rohc_tree = proto_item_add_subtree(ti, ett_rohc);
		/*    1) If the first octet is a Padding Octet (11100000),
		 *       strip away all initial Padding Octets and goto next step.
		 */
		if(p_rohc_info->large_cid_present == FALSE){
			item = proto_tree_add_text(rohc_tree, tvb, offset, -1, "Small CID configured");
			PROTO_ITEM_SET_GENERATED(item);
		}else{
			item = proto_tree_add_text(rohc_tree, tvb, offset, -1, "Large CID configured");
			PROTO_ITEM_SET_GENERATED(item);
		}
start_over:
		cid = 0;
		oct = tvb_get_guint8(tvb,offset);
		if(oct== 0xe0){
			while(oct == 0xe0){
				offset++;
				oct = tvb_get_guint8(tvb,offset);
			}
			proto_tree_add_item(rohc_tree, hf_rohc_padding, tvb, 0, offset, ENC_NA);
		}
		/* 2) If the first remaining octet starts with 1110, it is an Add-CID octet:
		 *    remember the Add-CID octet; remove the octet.
		 */
		if((oct&0xf0) == 0xe0){
			is_add_cid = TRUE;
			cid = oct & 0x0f;
			proto_tree_add_item(rohc_tree, hf_rohc_add_cid, tvb, offset, 1, ENC_BIG_ENDIAN);
			proto_tree_add_uint(rohc_tree, hf_rohc_small_cid, tvb, offset, 1, cid);
			offset++;
			oct = tvb_get_guint8(tvb,offset);
		}
		/* feedback ?
		 * Feedback (begins with 11110)
		 */
		if((oct&0xf8) == 0xf0){
		/* 3) If the first remaining octet starts with 11110, and an Add-CID
		 *    octet was found in step 2), an error has occurred;
		 *    the header MUST be discarded without further action.
		 */

			if(is_add_cid){
				proto_tree_add_item(rohc_tree, hf_rohc_feedback, tvb, offset, 1, ENC_BIG_ENDIAN);
				col_append_str(pinfo->cinfo, COL_INFO, "Error packet");
				proto_tree_add_text(rohc_tree, tvb, offset, -1, "Error packet");
				return;
			}else{
				col_append_str(pinfo->cinfo, COL_INFO, "Feedback ");
				/* 4) If the first remaining octet starts with 11110, and an Add-CID
				 *    octet was not found in step 2), this is feedback:
				 *        find the size of the feedback data, call it s;
				 *        remove the feedback type octet;
				 *        remove the Size octet if Code is 0;
				 *        send feedback data of length s to the same-side associated
				 *        compressor;
				 *        if packet exhausted, stop; otherwise goto 2).
				 */
				p_rohc_info->last_created_item = proto_tree_add_item(rohc_tree, hf_rohc_feedback, tvb, offset, 1, ENC_BIG_ENDIAN);
				sub_tree = proto_item_add_subtree(g_rohc_info.last_created_item, ett_rohc_fb);
				proto_tree_add_item(sub_tree, hf_rohc_code, tvb, offset, 1, ENC_BIG_ENDIAN);
				code = oct&0x7;
				offset++;
				if(code==0){
					size = tvb_get_guint8(tvb,offset);
					proto_tree_add_item(sub_tree, hf_rohc_size, tvb, offset, 1, ENC_BIG_ENDIAN);
					offset++;
				}else{
					size = code;
				}
				feedback_data_len = size;
				if(p_rohc_info->large_cid_present == FALSE){
					/* Check for Add-CID octet */
					oct = tvb_get_guint8(tvb,offset);
					if((oct&0xf0) == 0xe0){
						cid = oct & 0x0f;
						proto_tree_add_item(sub_tree, hf_rohc_add_cid, tvb, offset, 1, ENC_BIG_ENDIAN);
						proto_tree_add_uint(sub_tree, hf_rohc_small_cid, tvb, offset, 1, cid);
						offset++;
						feedback_data_len--;
					}else{
						item = proto_tree_add_uint(sub_tree, hf_rohc_small_cid, tvb, 0, 0, cid);
						PROTO_ITEM_SET_GENERATED(item);
					}
				}else{
					/* Read Large CID here */
					get_self_describing_var_len_val(tvb, sub_tree, offset, hf_rohc_large_cid, &val_len);
					/* feedback_data_len - "lenght of large CID" */
					feedback_data_len = feedback_data_len - val_len;
				}
				/* Dissect feedback */
				dissect_rohc_feedback_data(tvb, sub_tree, pinfo, offset, feedback_data_len, p_rohc_info);
				offset = offset + size;
				if(offset<length)
					goto start_over;
				return;
			}
		}/*feedback */
		/* 5) If the first remaining octet starts with 1111111, this is a segment:
		 *
		 */
		if((oct&0xfe) == 0xfe){
			col_append_str(pinfo->cinfo, COL_INFO, "Segment");
			if((p_rohc_info->large_cid_present == FALSE) && (is_add_cid == FALSE)){
				item = proto_tree_add_uint(rohc_tree, hf_rohc_small_cid, tvb, 0, 0, cid);
				PROTO_ITEM_SET_GENERATED(item);
			}
			proto_tree_add_text(rohc_tree, tvb, offset, -1, "Segment [Desegmentation not implemented yet]");
			return;
		}
		/* 6) Here, it is known that the rest is forward information (unless the
		 *    header is damaged).
		 */
		if((oct&0xfe) == 0xfc){
			col_append_str(pinfo->cinfo, COL_INFO, "IR packet");
			if((p_rohc_info->large_cid_present == FALSE) && (is_add_cid == FALSE)){
				item = proto_tree_add_uint(rohc_tree, hf_rohc_small_cid, tvb, 0, 0, cid);
				PROTO_ITEM_SET_GENERATED(item);
			}
			ir_item = proto_tree_add_item(rohc_tree, hf_rohc_ir_packet, tvb, offset, 1, ENC_BIG_ENDIAN);
			ir_tree = proto_item_add_subtree(ir_item, ett_rohc_ir);
			d = oct & 0x01;
			x_bit_offset = offset;
			offset++;
			if(p_rohc_info->large_cid_present == TRUE){
				/* Handle Large CID:s here */
				get_self_describing_var_len_val(tvb, sub_tree, offset, hf_rohc_large_cid, &val_len);
				offset = offset + val_len;
			}
			profile = tvb_get_guint8(tvb,offset);
			if(profile==ROHC_PROFILE_RTP){
				proto_tree_add_item(ir_tree, hf_rohc_d_bit, tvb, x_bit_offset, 1, ENC_BIG_ENDIAN);
			}
			item = proto_tree_add_item(ir_tree, hf_rohc_profile, tvb, offset, 1, ENC_BIG_ENDIAN);
			if(p_rohc_info->profile != profile){
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
					"Configured profile %u, differs from actual profile %u, Dissection of other packets may be faulty",
					p_rohc_info->profile, profile);
				/* Oweride the configured profile */
				p_rohc_info->profile = profile;
			}
			offset++;
			proto_tree_add_item(ir_tree, hf_rohc_rtp_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			switch(profile){
				case ROHC_PROFILE_RTP:
					dissect_rohc_ir_rtp_udp_profile_static(tvb, ir_tree, pinfo, offset, d, p_rohc_info);
					break;
				case ROHC_PROFILE_UDP:
					dissect_rohc_ir_rtp_udp_profile_static(tvb, ir_tree, pinfo, offset, d, p_rohc_info);
					break;
				default:
					proto_tree_add_text(ir_tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
					break;
			}
			return;
		}
		if((oct&0xff) == 0xf8){
			col_append_str(pinfo->cinfo, COL_INFO, "IR-DYN packet");
			if((p_rohc_info->large_cid_present == FALSE) && (is_add_cid == FALSE)){
				item = proto_tree_add_uint(rohc_tree, hf_rohc_small_cid, tvb, 0, 0, cid);
				PROTO_ITEM_SET_GENERATED(item);
			}
			ir_item = proto_tree_add_item(rohc_tree, hf_rohc_ir_dyn_packet, tvb, offset, 1, ENC_BIG_ENDIAN);
			ir_tree = proto_item_add_subtree(ir_item, ett_rohc_ir_dyn);
			if(p_rohc_info->large_cid_present == TRUE){
				/* Handle Large CID:s here */
				get_self_describing_var_len_val(tvb, sub_tree, offset, hf_rohc_large_cid, &val_len);
				offset = offset + val_len;
			}
			profile = tvb_get_guint8(tvb,offset);
			item = proto_tree_add_item(ir_tree, hf_rohc_profile, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			if(p_rohc_info->profile != profile){
				expert_add_info_format(pinfo, item, PI_PROTOCOL, PI_WARN,
					"Configured profile %u, differs from actual profile %u, Dissection of other packets may be faulty",
					p_rohc_info->profile, profile);
				/* Oweride the configured profile */
				p_rohc_info->profile = profile;
			}
			proto_tree_add_item(ir_tree, hf_rohc_rtp_crc, tvb, offset, 1, ENC_BIG_ENDIAN);
			offset++;
			switch(profile){
				case ROHC_PROFILE_RTP:
					/* TODO: Currently IPv4 Hardwired, use conversation info or preference ? */
					dissect_rohc_ir_rtp_profile_dynamic(tvb, ir_tree, offset, p_rohc_info);
					break;
				default:
					proto_tree_add_text(ir_tree, tvb, offset, feedback_data_len, "profile-specific information[Not dissected yet]");
					break;
			}
			return;
		}

		if((oct&0x80)==0){
			col_set_str(pinfo->cinfo, COL_INFO, "Paket type 0");
		}else if ((oct&0xc0)==0x80){
			col_set_str(pinfo->cinfo, COL_INFO, "Paket type 1");
		}else if ((oct&0xe0)==0xc0){
			col_set_str(pinfo->cinfo, COL_INFO, "Paket type 2");
		}
	/*}*//* if tree */
}

void
proto_register_rohc(void)
{

	static hf_register_info hf[] =
	{
		{ &hf_rohc_padding,
			{ "Padding","rohc.pading",
			FT_BYTES, BASE_NONE, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_add_cid,
			{ "Add-CID","rohc.add_cid",
			FT_UINT8, BASE_HEX, NULL, 0xf0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_feedback,
			{ "Feedback","rohc.feedback",
			FT_UINT8, BASE_HEX, NULL, 0xf8,
			NULL , HFILL
			}
		},
		{ &hf_rohc_code,
			{ "Code","rohc.code",
			FT_UINT8, BASE_DEC, NULL, 0x07,
			NULL , HFILL
			}
		},
		{ &hf_rohc_size,
			{ "Size","rohc.size",
			FT_UINT8, BASE_DEC, NULL, 0x00,
			NULL , HFILL
			}
		},
		{ &hf_rohc_ir_packet,
			{ "IR packet","rohc.ir_packet",
			FT_UINT8, BASE_DEC, NULL, 0xfe,
			NULL , HFILL
			}
		},
		{ &hf_rohc_ir_dyn_packet,
			{ "IR-DYN packet","rohc.ir_dyn_packet",
			FT_UINT8, BASE_DEC, NULL, 0xff,
			NULL , HFILL
			}
		},
		{ &hf_rohc_small_cid,
			{ "Small CID","rohc.small_cid",
			FT_UINT8, BASE_DEC, NULL, 0x0f,
			NULL , HFILL
			}
		},
		{ &hf_rohc_large_cid,
			{ "Large CID","rohc.large_cid",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_acktype,
			{ "Acktype","rohc.acktype",
			FT_UINT8, BASE_DEC, VALS(rohc_acktype_vals), 0xc0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_mode,
			{ "Mode","rohc.mode",
			FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x30,
			NULL , HFILL
			}
		},
		{ &hf_rohc_sn,
			{ "SN(lsb)","rohc.sn",
			FT_UINT16, BASE_HEX, NULL, 0x0fff,
			NULL , HFILL
			}
		},
		{ &hf_rohc_fb1_sn,
			{ "SN","rohc.fb1_sn",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_opt_type,
			{ "Option type","rohc.rtp.opt_type",
			FT_UINT8, BASE_DEC, VALS(rohc_rtp_opt_type_vals), 0xf0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_opt_len,
			{ "Option length","rohc.rtp.opt_length",
			FT_UINT8, BASE_DEC, NULL, 0x0f,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_crc,
			{ "CRC","rohc.crc",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_opt_sn,
			{ "SN","rohc.opt.sn",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_feedback_option_clock,
			{ "Clock", "rohc.feedback-option-clock",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			"Feedback Option Clock", HFILL
			}
		},
		{ &hf_rohc_profile,
			{ "Profile","rohc.profile",
			FT_UINT8, BASE_DEC, VALS(rohc_profile_vals), 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_d_bit,
			{ "D - Dynamic chain","rohc.d",
			FT_BOOLEAN, 8, TFS(&tfs_present_not_present), 0x01,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_version,
			{ "Version","rohc.rtp.version",
			FT_UINT8, BASE_DEC, VALS(rohc_rtp_version_vals), 0xf0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_protocol,
			{ "Protocol","rohc.rtp.protocol",
			FT_UINT8, BASE_DEC|BASE_EXT_STRING, (&ipproto_val_ext), 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_ipv4_src,
			{ "Source address","rohc.rtp.ipv4_src",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL
			}
		},
		{ &hf_rohc_rtp_ipv4_dst,
			{ "Destination address","rohc.rtp.ipv4_dst",
			FT_IPv4, BASE_NONE, NULL, 0x0,
			NULL, HFILL
			}
		},
		{ &hf_rohc_rtp_udp_src_port,
			{ "Source Port","rohc.rtp.udp_src_port",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_udp_dst_port,
			{ "Destination Port","rohc.rtp.udp_dst_port",
			FT_UINT16, BASE_DEC, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_ssrc,
			{ "SSRC","rohc.rtp.ssrc",
			FT_UINT32, BASE_HEX, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_tos,
			{ "Type of Service","rohc.rtp.tos",
			FT_UINT8, BASE_HEX, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_ttl,
			{ "Time to Live","rohc.rtp.ttl",
			FT_UINT8, BASE_DEC, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_id,
			{ "Identification","rohc.rtp.rtp.id",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_df,
			{ "Don't Fragment(DF)","rohc.rtp.df",
			FT_BOOLEAN, 8, NULL, 0x80,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_rnd,
			{ "RND(IP-ID behaves randomly)","rohc.rtp.rnd",
			FT_BOOLEAN, 8, NULL, 0x40,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_nbo,
			{ "Network Byte Order (NBO)","rohc.rtp.nbo",
			FT_BOOLEAN, 8, NULL, 0x20,
			"Whether the IP-ID is in Network Byte Order" , HFILL
			}
		},
		{ &hf_rohc_rtp_checksum,
			{ "Checksum","rohc.rtp.checksum",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_dynamic_udp_seqnum,
			{ "UDP Sequence Number", "rohc.dynamic.udp.seqnum",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL, HFILL
			}
        },
		{ &hf_rohc_rtp_v,
			{ "version","rohc.rtp.v",
			FT_UINT8, BASE_DEC, NULL, 0xc0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_p,
			{ "Padding(P)","rohc.rtp.p",
			FT_BOOLEAN, 8, NULL, 0x20,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_rx,
			{ "RX","rohc.rtp.rx",
			FT_BOOLEAN, 8, NULL, 0x10,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_cc,
			{ "CC","rohc.rtp.cc",
			FT_UINT8, BASE_DEC, NULL, 0x0f,
			"CSRC counter from original RTP header" , HFILL
			}
		},
		{ &hf_rohc_rtp_m,
			{ "Marker Bit (M)","rohc.rtp.m",
			FT_BOOLEAN, 8,  TFS(&tfs_set_notset), 0x80,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_pt,
			{ "Payload Type(PT)","rohc.rtp.pt",
			FT_UINT8, BASE_DEC|BASE_EXT_STRING, (&rtp_payload_type_vals_ext), 0x7f,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_sn,
			{ "Sequence Number(SN)","rohc.rtp.sn",
			FT_UINT16, BASE_HEX, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_timestamp,
			{ "RTP Timestamp","rohc.rtp.timestamp",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_x,
			{ "X","rohc.rtp.x",
			FT_BOOLEAN, 8,  TFS(&tfs_set_notset), 0x80,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_mode,
			{ "Mode","rohc.rtp.mode",
			FT_UINT8, BASE_DEC, VALS(rohc_mode_vals), 0x0c,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_tis,
			{ "TIS","rohc.rtp.tis",
			FT_BOOLEAN, 8,  NULL, 0x02,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_tss,
			{ "TSS","rohc.rtp.tss",
			FT_BOOLEAN, 8,  NULL, 0x01,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_ts_stride,
			{ "TS_Stride","rohc.rtp.ts_stride",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_rtp_time_stride,
			{ "Time_Stride","rohc.rtp.time_stride",
			FT_UINT32, BASE_DEC, NULL, 0x0,
			NULL , HFILL
			}
		},
		{ &hf_rohc_var_len,
			{ "Variable length","rohc.var_len",
			FT_UINT8, BASE_DEC, VALS(rohc_var_len_vals), 0x0,
			NULL , HFILL
			}
		},
	};

	/* Setup protocol subtree array */
	static gint *ett[] = {
	&ett_rohc,
	&ett_rohc_fb,
	&ett_rohc_feedback,
	&ett_rohc_ir,
	&ett_rohc_ir_dyn,
	&ett_rohc_rtp_static,
	&ett_rohc_rtp_dynamic,
	};

	/* Register the protocol name and description */
	proto_rohc = proto_register_protocol("RObust Header Compression (ROHC)", "ROHC", "rohc");

	register_dissector("rohc", dissect_rohc, proto_rohc);

	/* Required function calls to register the header fields and subtrees used */
	proto_register_field_array(proto_rohc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_rohc(void)
{
	dissector_handle_t rohc_handle;

	rohc_handle = create_dissector_handle(dissect_rohc, proto_rohc);
	dissector_add_uint("ethertype", ETHERTYPE_ROHC, rohc_handle);

}
