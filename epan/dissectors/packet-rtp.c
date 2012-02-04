/* packet-rtp.c
 *
 * Routines for RTP dissection
 * RTP = Real time Transport Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <h323@ramdyne.nl>
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
 */

/*
 * This dissector tries to dissect the RTP protocol according to Annex A
 * of ITU-T Recommendation H.225.0 (02/98) or RFC 1889
 *
 * RTP traffic is handled by an even UDP portnumber. This can be any
 * port number, but there is a registered port available, port 5004
 * See Annex B of ITU-T Recommendation H.225.0, section B.7
 *
 * This doesn't dissect older versions of RTP, such as:
 *
 *    the vat protocol ("version 0") - see
 *
 *	ftp://ftp.ee.lbl.gov/conferencing/vat/alpha-test/vatsrc-4.0b2.tar.gz
 *
 *    and look in "session-vat.cc" if you want to write a dissector
 *    (have fun - there aren't any nice header files showing the packet
 *    format);
 *
 *    version 1, as documented in
 *
 *	ftp://gaia.cs.umass.edu/pub/hgschulz/rtp/draft-ietf-avt-rtp-04.txt
 *
 * It also dissects PacketCable CCC-encapsulated RTP data, as described in
 * chapter 5 of the PacketCable Electronic Surveillance Specification:
 *
 *   http://www.packetcable.com/downloads/specs/PKT-SP-ESP1.5-I01-050128.pdf
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>

#include "packet-rtp.h"
#include <epan/rtp_pt.h>
#include <epan/conversation.h>
#include <epan/reassemble.h>
#include <epan/tap.h>

#include <epan/prefs.h>
#include <epan/emem.h>
#include <epan/strutil.h>

/* uncomment this to enable debugging of fragment reassembly */
/* #define DEBUG_FRAGMENTS   1 */

typedef struct _rfc2198_hdr {
	unsigned int pt;
	int offset;
	int len;
	struct _rfc2198_hdr *next;
} rfc2198_hdr;

/* we have one of these for each pdu which spans more than one segment
 */
typedef struct _rtp_multisegment_pdu {
	/* the seqno of the segment where the pdu starts */
	guint32 startseq;

	/* the seqno of the segment where the pdu ends */
	guint32 endseq;
} rtp_multisegment_pdu;

typedef struct  _rtp_private_conv_info {
	/* This tree is indexed by sequence number and keeps track of all
	 * all pdus spanning multiple segments for this flow.
	 */
	emem_tree_t *multisegment_pdus;
} rtp_private_conv_info;

static GHashTable *fragment_table = NULL;

static int hf_rtp_fragments = -1;
static int hf_rtp_fragment = -1;
static int hf_rtp_fragment_overlap = -1;
static int hf_rtp_fragment_overlap_conflict = -1;
static int hf_rtp_fragment_multiple_tails = -1;
static int hf_rtp_fragment_too_long_fragment = -1;
static int hf_rtp_fragment_error = -1;
static int hf_rtp_fragment_count = -1;
static int hf_rtp_reassembled_in = -1;
static int hf_rtp_reassembled_length = -1;

static gint ett_rtp_fragment = -1;
static gint ett_rtp_fragments = -1;

static const fragment_items rtp_fragment_items = {
	&ett_rtp_fragment,
	&ett_rtp_fragments,
	&hf_rtp_fragments,
	&hf_rtp_fragment,
	&hf_rtp_fragment_overlap,
	&hf_rtp_fragment_overlap_conflict,
	&hf_rtp_fragment_multiple_tails,
	&hf_rtp_fragment_too_long_fragment,
	&hf_rtp_fragment_error,
	&hf_rtp_fragment_count,
	&hf_rtp_reassembled_in,
	&hf_rtp_reassembled_length,
	"RTP fragments"
};

static dissector_handle_t rtp_handle;
static dissector_handle_t classicstun_handle;
static dissector_handle_t classicstun_heur_handle;
static dissector_handle_t t38_handle;
static dissector_handle_t zrtp_handle;

static int rtp_tap = -1;

static dissector_table_t rtp_pt_dissector_table;
static dissector_table_t rtp_dyn_pt_dissector_table;

static dissector_table_t rtp_hdr_ext_dissector_table;

/* RTP header fields             */
static int proto_rtp           = -1;
static int hf_rtp_version      = -1;
static int hf_rtp_padding      = -1;
static int hf_rtp_extension    = -1;
static int hf_rtp_csrc_count   = -1;
static int hf_rtp_marker       = -1;
static int hf_rtp_payload_type = -1;
static int hf_rtp_seq_nr       = -1;
static int hf_rtp_ext_seq_nr   = -1;
static int hf_rtp_timestamp    = -1;
static int hf_rtp_ssrc         = -1;
static int hf_rtp_csrc_items   = -1;
static int hf_rtp_csrc_item    = -1;
static int hf_rtp_data         = -1;
static int hf_rtp_padding_data = -1;
static int hf_rtp_padding_count= -1;
static int hf_rtp_rfc2198_follow= -1;
static int hf_rtp_rfc2198_tm_off= -1;
static int hf_rtp_rfc2198_bl_len= -1;

/* RTP header extension fields   */
static int hf_rtp_prof_define  = -1;
static int hf_rtp_length       = -1;
static int hf_rtp_hdr_exts     = -1;
static int hf_rtp_hdr_ext      = -1;

/* RTP setup fields */
static int hf_rtp_setup        = -1;
static int hf_rtp_setup_frame  = -1;
static int hf_rtp_setup_method = -1;

/* RTP fields defining a sub tree */
static gint ett_rtp       = -1;
static gint ett_csrc_list = -1;
static gint ett_hdr_ext   = -1;
static gint ett_rtp_setup = -1;
static gint ett_rtp_rfc2198 = -1;
static gint ett_rtp_rfc2198_hdr = -1;

/* SRTP fields */
static int hf_srtp_encrypted_payload = -1;
static int hf_srtp_mki = -1;
static int hf_srtp_auth_tag = -1;

/* PacketCable CCC header fields */
static int proto_pkt_ccc       = -1;
static int hf_pkt_ccc_id       = -1;
static int hf_pkt_ccc_ts       = -1;

/* PacketCable CCC field defining a sub tree */
static gint ett_pkt_ccc = -1;

/* PacketCable CCC port preference */
static guint global_pkt_ccc_udp_port = 0;


#define RTP0_INVALID 0
#define RTP0_CLASSICSTUN    1
#define RTP0_T38     2

static enum_val_t rtp_version0_types[] = {
	{ "invalid", "Invalid or ZRTP packets", RTP0_INVALID },
	{ "classicstun", "CLASSIC-STUN packets", RTP0_CLASSICSTUN },
	{ "t38", "T.38 packets", RTP0_T38 },
	{ NULL, NULL, 0 }
};
static gint global_rtp_version0_type = 0;

static dissector_handle_t data_handle;

/* Forward declaration we need below */
void proto_reg_handoff_rtp(void);
void proto_reg_handoff_pkt_ccc(void);

static void dissect_rtp( tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree );
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);
static void get_conv_info(packet_info *pinfo, struct _rtp_info *rtp_info);

/* Preferences bool to control whether or not setup info should be shown */
static gboolean global_rtp_show_setup_info = TRUE;

/* Try heuristic RTP decode */
static gboolean global_rtp_heur = FALSE;

/* desegment RTP streams */
static gboolean desegment_rtp = TRUE;

/* RFC2198 Redundant Audio Data */
static guint rtp_rfc2198_pt = 99;

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
	{ 2, "RFC 1889 Version" }, /* First for speed */
	{ 0, "Old VAT Version" },
	{ 1, "First Draft Version" },
	{ 0, NULL },
};

/*
 * Fields in the second octet of the RTP header.
 */

/* Marker is the first bit of the second octet */
#define RTP_MARKER(octet)	((octet) & 0x80)

/* Payload type is the last 7 bits */
#define RTP_PAYLOAD_TYPE(octet)	((octet) & 0x7F)
/* http://www.iana.org/assignments/rtp-parameters */

static const value_string rtp_payload_type_vals[] =
{
/*  0 */	{ PT_PCMU,			"ITU-T G.711 PCMU" },
/*  1 */	{ PT_1016,			"USA Federal Standard FS-1016" },
/*  2 */	{ PT_G721,			"ITU-T G.721" },
/*  3 */	{ PT_GSM,			"GSM 06.10" },
/*  4 */	{ PT_G723,			"ITU-T G.723" },
/*  5 */	{ PT_DVI4_8000,		"DVI4 8000 samples/s" },
/*  6 */	{ PT_DVI4_16000,	"DVI4 16000 samples/s" },
/*  7 */	{ PT_LPC,			"Experimental linear predictive encoding from Xerox PARC" },
/*  8 */	{ PT_PCMA,			"ITU-T G.711 PCMA" },
/*  9 */	{ PT_G722,			"ITU-T G.722" },
/* 10 */	{ PT_L16_STEREO,	"16-bit uncompressed audio, stereo" },
/* 11 */	{ PT_L16_MONO,		"16-bit uncompressed audio, monaural" },
/* 12 */	{ PT_QCELP,			"Qualcomm Code Excited Linear Predictive coding" },
/* 13 */	{ PT_CN,			"Comfort noise" },
/* 14 */	{ PT_MPA,			"MPEG-I/II Audio"},
/* 15 */	{ PT_G728,			"ITU-T G.728" },
/* 16 */	{ PT_DVI4_11025,	"DVI4 11025 samples/s" },
/* 17 */	{ PT_DVI4_22050,	"DVI4 22050 samples/s" },
/* 18 */	{ PT_G729,			"ITU-T G.729" },
/* 19 */	{ PT_CN_OLD,		"Comfort noise (old)" },
/* 20 */	{ 20,				"Unassigned" },
/* 21 */	{ 21,				"Unassigned" },
/* 22 */	{ 22,				"Unassigned" },
/* 23 */	{ 23,				"Unassigned" },
/* 24 */	{ 24,				"Unassigned" },
/* 25 */	{ PT_CELB,			"Sun CellB video encoding" },
/* 26 */	{ PT_JPEG,			"JPEG-compressed video" },
/* 27 */	{ 27,				"Unassigned" },
/* 28 */	{ PT_NV,			"'nv' program" },
/* 29 */	{ 29,				"Unassigned" },
/* 30 */	{ 30,				"Unassigned" },
/* 31 */	{ PT_H261,			"ITU-T H.261" },
/* 32 */	{ PT_MPV,			"MPEG-I/II Video"},
/* 33 */	{ PT_MP2T,			"MPEG-II transport streams"},
/* 34 */	{ PT_H263,			"ITU-T H.263" },
/* 35-71     Unassigned  */
/* 35 */	{ 35,				"Unassigned" },
/* 36 */	{ 36,				"Unassigned" },
/* 37 */	{ 37,				"Unassigned" },
/* 38 */	{ 38,				"Unassigned" },
/* 39 */	{ 39,				"Unassigned" },
/* 40 */	{ 40,				"Unassigned" },
/* 41 */	{ 41,				"Unassigned" },
/* 42 */	{ 42,				"Unassigned" },
/* 43 */	{ 43,				"Unassigned" },
/* 44 */	{ 44,				"Unassigned" },
/* 45 */	{ 45,				"Unassigned" },
/* 46 */	{ 46,				"Unassigned" },
/* 47 */	{ 47,				"Unassigned" },
/* 48 */	{ 48,				"Unassigned" },
/* 49 */	{ 49,				"Unassigned" },
/* 50 */	{ 50,				"Unassigned" },
/* 51 */	{ 51,				"Unassigned" },
/* 52 */	{ 52,				"Unassigned" },
/* 53 */	{ 53,				"Unassigned" },
/* 54 */	{ 54,				"Unassigned" },
/* 55 */	{ 55,				"Unassigned" },
/* 56 */	{ 56,				"Unassigned" },
/* 57 */	{ 57,				"Unassigned" },
/* 58 */	{ 58,				"Unassigned" },
/* 59 */	{ 59,				"Unassigned" },
/* 60 */	{ 60,				"Unassigned" },
/* 61 */	{ 61,				"Unassigned" },
/* 62 */	{ 62,				"Unassigned" },
/* 63 */	{ 63,				"Unassigned" },
/* 64 */	{ 64,				"Unassigned" },
/* 65 */	{ 65,				"Unassigned" },
/* 66 */	{ 66,				"Unassigned" },
/* 67 */	{ 67,				"Unassigned" },
/* 68 */	{ 68,				"Unassigned" },
/* 69 */	{ 69,				"Unassigned" },
/* 70 */	{ 70,				"Unassigned" },
/* 71 */	{ 71,				"Unassigned" },
/* 72-76     Reserved for RTCP conflict avoidance                                  [RFC3551] */
/* 72 */	{ 72,				"Reserved for RTCP conflict avoidance" },
/* 73 */	{ 73,				"Reserved for RTCP conflict avoidance" },
/* 74 */	{ 74,				"Reserved for RTCP conflict avoidance" },
/* 75 */	{ 75,				"Reserved for RTCP conflict avoidance" },
/* 76 */	{ 76,				"Reserved for RTCP conflict avoidance" },
/* 77-95     Unassigned      ? */
/* 77 */	{ 77,				"Unassigned" },
/* 78 */	{ 78,				"Unassigned" },
/* 79 */	{ 79,				"Unassigned" },
/* 80 */	{ 80,				"Unassigned" },
/* 81 */	{ 81,				"Unassigned" },
/* 82 */	{ 82,				"Unassigned" },
/* 83 */	{ 83,				"Unassigned" },
/* 84 */	{ 84,				"Unassigned" },
/* 85 */	{ 85,				"Unassigned" },
/* 86 */	{ 86,				"Unassigned" },
/* 87 */	{ 87,				"Unassigned" },
/* 88 */	{ 88,				"Unassigned" },
/* 89 */	{ 89,				"Unassigned" },
/* 90 */	{ 90,				"Unassigned" },
/* 91 */	{ 91,				"Unassigned" },
/* 92 */	{ 92,				"Unassigned" },
/* 93 */	{ 93,				"Unassigned" },
/* 94 */	{ 94,				"Unassigned" },
/* 95 */	{ 95,				"Unassigned" },
 	/* Alex Lindberg - Added to support addtional RTP payload types
 	See epan/rtp_pt.h */
	{ PT_UNDF_96,	"DynamicRTP-Type-96" },
	{ PT_UNDF_97,	"DynamicRTP-Type-97" },
	{ PT_UNDF_98,	"DynamicRTP-Type-98" },
	{ PT_UNDF_99,	"DynamicRTP-Type-99" },
	{ PT_UNDF_100,	"DynamicRTP-Type-100" },
	{ PT_UNDF_101,	"DynamicRTP-Type-101" },
	{ PT_UNDF_102,	"DynamicRTP-Type-102" },
	{ PT_UNDF_103,	"DynamicRTP-Type-103" },
	{ PT_UNDF_104,	"DynamicRTP-Type-104" },
	{ PT_UNDF_105,	"DynamicRTP-Type-105" },
	{ PT_UNDF_106,	"DynamicRTP-Type-106" },
	{ PT_UNDF_107,	"DynamicRTP-Type-107" },
	{ PT_UNDF_108,	"DynamicRTP-Type-108" },
	{ PT_UNDF_109,	"DynamicRTP-Type-109" },
	{ PT_UNDF_110,	"DynamicRTP-Type-110" },
	{ PT_UNDF_111,	"DynamicRTP-Type-111" },
	{ PT_UNDF_112,	"DynamicRTP-Type-112" },
	{ PT_UNDF_113,	"DynamicRTP-Type-113" },
	{ PT_UNDF_114,	"DynamicRTP-Type-114" },
	{ PT_UNDF_115,	"DynamicRTP-Type-115" },
	{ PT_UNDF_116,	"DynamicRTP-Type-116" },
	{ PT_UNDF_117,	"DynamicRTP-Type-117" },
	{ PT_UNDF_118,	"DynamicRTP-Type-118" },
	{ PT_UNDF_119,	"DynamicRTP-Type-119" },
	{ PT_UNDF_120,	"DynamicRTP-Type-120" },
	{ PT_UNDF_121,	"DynamicRTP-Type-121" },
	{ PT_UNDF_122,	"DynamicRTP-Type-122" },
	{ PT_UNDF_123,	"DynamicRTP-Type-123" },
	{ PT_UNDF_124,	"DynamicRTP-Type-124" },
	{ PT_UNDF_125,	"DynamicRTP-Type-125" },
	{ PT_UNDF_126,	"DynamicRTP-Type-126" },
	{ PT_UNDF_127,	"DynamicRTP-Type-127" },

	{ 0,		NULL },
};

value_string_ext rtp_payload_type_vals_ext = VALUE_STRING_EXT_INIT(rtp_payload_type_vals);

static const value_string rtp_payload_type_short_vals[] =
{
	{ PT_PCMU,      "g711U" },
	{ PT_1016,      "fs-1016" },
	{ PT_G721,      "g721" },
	{ PT_GSM,       "GSM" },
	{ PT_G723,      "g723" },
	{ PT_DVI4_8000, "DVI4 8k" },
	{ PT_DVI4_16000, "DVI4 16k" },
	{ PT_LPC,       "Exp. from Xerox PARC" },
	{ PT_PCMA,      "g711A" },
	{ PT_G722,      "g722" },
	{ PT_L16_STEREO, "16-bit audio, stereo" },
	{ PT_L16_MONO,  "16-bit audio, monaural" },
	{ PT_QCELP,     "Qualcomm" },
	{ PT_CN,        "CN" },
	{ PT_MPA,       "MPEG-I/II Audio"},
	{ PT_G728,      "g728" },
	{ PT_DVI4_11025, "DVI4 11k" },
	{ PT_DVI4_22050, "DVI4 22k" },
	{ PT_G729,      "g729" },
	{ PT_CN_OLD,    "CN(old)" },
/* 20 */	{ 20,				"Unassigned" },
/* 21 */	{ 21,				"Unassigned" },
/* 22 */	{ 22,				"Unassigned" },
/* 23 */	{ 23,				"Unassigned" },
/* 24 */	{ 24,				"Unassigned" },
	{ PT_CELB,      "CellB" },
	{ PT_JPEG,      "JPEG" },
/* 27 */	{ 27,				"Unassigned" },
	{ PT_NV,        "NV" },
/* 29 */	{ 29,				"Unassigned" },
/* 30 */	{ 30,				"Unassigned" },
	{ PT_H261,      "h261" },
	{ PT_MPV,       "MPEG-I/II Video"},
	{ PT_MP2T,      "MPEG-II streams"},
	{ PT_H263,      "h263" },
/* 35-71     Unassigned  */
/* 35 */	{ 35,				"Unassigned" },
/* 36 */	{ 36,				"Unassigned" },
/* 37 */	{ 37,				"Unassigned" },
/* 38 */	{ 38,				"Unassigned" },
/* 39 */	{ 39,				"Unassigned" },
/* 40 */	{ 40,				"Unassigned" },
/* 41 */	{ 41,				"Unassigned" },
/* 42 */	{ 42,				"Unassigned" },
/* 43 */	{ 43,				"Unassigned" },
/* 44 */	{ 44,				"Unassigned" },
/* 45 */	{ 45,				"Unassigned" },
/* 46 */	{ 46,				"Unassigned" },
/* 47 */	{ 47,				"Unassigned" },
/* 48 */	{ 48,				"Unassigned" },
/* 49 */	{ 49,				"Unassigned" },
/* 50 */	{ 50,				"Unassigned" },
/* 51 */	{ 51,				"Unassigned" },
/* 52 */	{ 52,				"Unassigned" },
/* 53 */	{ 53,				"Unassigned" },
/* 54 */	{ 54,				"Unassigned" },
/* 55 */	{ 55,				"Unassigned" },
/* 56 */	{ 56,				"Unassigned" },
/* 57 */	{ 57,				"Unassigned" },
/* 58 */	{ 58,				"Unassigned" },
/* 59 */	{ 59,				"Unassigned" },
/* 60 */	{ 60,				"Unassigned" },
/* 61 */	{ 61,				"Unassigned" },
/* 62 */	{ 62,				"Unassigned" },
/* 63 */	{ 63,				"Unassigned" },
/* 64 */	{ 64,				"Unassigned" },
/* 65 */	{ 65,				"Unassigned" },
/* 66 */	{ 66,				"Unassigned" },
/* 67 */	{ 67,				"Unassigned" },
/* 68 */	{ 68,				"Unassigned" },
/* 69 */	{ 69,				"Unassigned" },
/* 70 */	{ 70,				"Unassigned" },
/* 71 */	{ 71,				"Unassigned" },
/* 72-76     Reserved for RTCP conflict avoidance                                  [RFC3551] */
/* 72 */	{ 72,				"Reserved for RTCP conflict avoidance" },
/* 73 */	{ 73,				"Reserved for RTCP conflict avoidance" },
/* 74 */	{ 74,				"Reserved for RTCP conflict avoidance" },
/* 75 */	{ 75,				"Reserved for RTCP conflict avoidance" },
/* 76 */	{ 76,				"Reserved for RTCP conflict avoidance" },
/* 77-95     Unassigned      ? */
/* 77 */	{ 77,				"Unassigned" },
/* 78 */	{ 78,				"Unassigned" },
/* 79 */	{ 79,				"Unassigned" },
/* 80 */	{ 80,				"Unassigned" },
/* 81 */	{ 81,				"Unassigned" },
/* 82 */	{ 82,				"Unassigned" },
/* 83 */	{ 83,				"Unassigned" },
/* 84 */	{ 84,				"Unassigned" },
/* 85 */	{ 85,				"Unassigned" },
/* 86 */	{ 86,				"Unassigned" },
/* 87 */	{ 87,				"Unassigned" },
/* 88 */	{ 88,				"Unassigned" },
/* 89 */	{ 89,				"Unassigned" },
/* 90 */	{ 90,				"Unassigned" },
/* 91 */	{ 91,				"Unassigned" },
/* 92 */	{ 92,				"Unassigned" },
/* 93 */	{ 93,				"Unassigned" },
/* 94 */	{ 94,				"Unassigned" },
/* 95 */	{ 95,				"Unassigned" },
 	/* Alex Lindberg - Short RTP types */
	{ PT_UNDF_96,	"RTPType-96" },
	{ PT_UNDF_97,	"RTPType-97" },
	{ PT_UNDF_98,	"RTPType-98" },
	{ PT_UNDF_99,	"RTPType-99" },
	{ PT_UNDF_100,	"RTPType-100" },
	{ PT_UNDF_101,	"RTPType-101" },
	{ PT_UNDF_102,	"RTPType-102" },
	{ PT_UNDF_103,	"RTPType-103" },
	{ PT_UNDF_104,	"RTPType-104" },
	{ PT_UNDF_105,	"RTPType-105" },
	{ PT_UNDF_106,	"RTPType-106" },
	{ PT_UNDF_107,	"RTPType-107" },
	{ PT_UNDF_108,	"RTPType-108" },
	{ PT_UNDF_109,	"RTPType-109" },
	{ PT_UNDF_110,	"RTPType-110" },
	{ PT_UNDF_111,	"RTPType-111" },
	{ PT_UNDF_112,	"RTPType-112" },
	{ PT_UNDF_113,	"RTPType-113" },
	{ PT_UNDF_114,	"RTPType-114" },
	{ PT_UNDF_115,	"RTPType-115" },
	{ PT_UNDF_116,	"RTPType-116" },
	{ PT_UNDF_117,	"RTPType-117" },
	{ PT_UNDF_118,	"RTPType-118" },
	{ PT_UNDF_119,	"RTPType-119" },
	{ PT_UNDF_120,	"RTPType-120" },
	{ PT_UNDF_121,	"RTPType-121" },
	{ PT_UNDF_122,	"RTPType-122" },
	{ PT_UNDF_123,	"RTPType-123" },
	{ PT_UNDF_124,	"RTPType-124" },
	{ PT_UNDF_125,	"RTPType-125" },
	{ PT_UNDF_126,	"RTPType-126" },
	{ PT_UNDF_127,	"RTPType-127" },

	{ 0,            NULL },
};
value_string_ext rtp_payload_type_short_vals_ext = VALUE_STRING_EXT_INIT(rtp_payload_type_short_vals);

#if 0
static const value_string srtp_encryption_alg_vals[] =
{
	{ SRTP_ENC_ALG_NULL,	"Null Encryption" },
	{ SRTP_ENC_ALG_AES_CM, "AES-128 Counter Mode" },
	{ SRTP_ENC_ALG_AES_F8,	"AES-128 F8 Mode" },
	{ 0, NULL },
};

static const value_string srtp_auth_alg_vals[] =
{
	{ SRTP_AUTH_ALG_NONE,		"No Authentication" },
	{ SRTP_AUTH_ALG_HMAC_SHA1,	"HMAC-SHA1" },
	{ 0, NULL },
};
#endif

/* initialisation routine */
static void rtp_fragment_init(void)
{
	fragment_table_init(&fragment_table);
}

void
rtp_free_hash_dyn_payload(GHashTable *rtp_dyn_payload)
{
	if (rtp_dyn_payload == NULL) return;
	g_hash_table_destroy(rtp_dyn_payload);
	rtp_dyn_payload = NULL;
}

/* Set up an SRTP conversation */
void srtp_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, guint32 setup_frame_number, gboolean is_video _U_, GHashTable *rtp_dyn_payload,
                     struct srtp_info *srtp_info)
{
	address null_addr;
	conversation_t* p_conv;
	struct _rtp_conversation_info *p_conv_data = NULL;

	/*
	 * If this isn't the first time this packet has been processed,
	 * we've already done this work, so we don't need to do it
	 * again.
	 */
	if (pinfo->fd->flags.visited)
	{
		return;
	}

#ifdef DEBUG
	printf("#%u: %srtp_add_address(%s, %u, %u, %s, %u\n", pinfo->fd->num, (srtp_info)?"s":"", ep_address_to_str(addr), port, other_port, setup_method, setup_frame_number);
#endif

	SET_ADDRESS(&null_addr, AT_NONE, 0, NULL);

	/*
	 * Check if the ip address and port combination is not
	 * already registered as a conversation.
	 */
	p_conv = find_conversation( setup_frame_number, addr, &null_addr, PT_UDP, port, other_port,
                                NO_ADDR_B | (!other_port ? NO_PORT_B : 0));

	/*
	 * If not, create a new conversation.
	 */
	if ( !p_conv || p_conv->setup_frame != setup_frame_number) {
		p_conv = conversation_new( setup_frame_number, addr, &null_addr, PT_UDP,
		                           (guint32)port, (guint32)other_port,
								   NO_ADDR2 | (!other_port ? NO_PORT2 : 0));
	}

	/* Set dissector */
	conversation_set_dissector(p_conv, rtp_handle);

	/*
	 * Check if the conversation has data associated with it.
	 */
	p_conv_data = conversation_get_proto_data(p_conv, proto_rtp);

	/*
	 * If not, add a new data item.
	 */
	if ( ! p_conv_data ) {
		/* Create conversation data */
		p_conv_data = se_alloc(sizeof(struct _rtp_conversation_info));
		p_conv_data->rtp_dyn_payload = NULL;

		/* start this at 0x10000 so that we cope gracefully with the
		 * first few packets being out of order (hence 0,65535,1,2,...)
		 */
		p_conv_data->extended_seqno = 0x10000;
		p_conv_data->rtp_conv_info = se_alloc(sizeof(rtp_private_conv_info));
		p_conv_data->rtp_conv_info->multisegment_pdus = se_tree_create(EMEM_TREE_TYPE_RED_BLACK,"rtp_ms_pdus");
		conversation_add_proto_data(p_conv, proto_rtp, p_conv_data);
	}

	/*
	 * Update the conversation data.
	 */
	/* Free the hash if already exists */
	rtp_free_hash_dyn_payload(p_conv_data->rtp_dyn_payload);

	g_strlcpy(p_conv_data->method, setup_method, MAX_RTP_SETUP_METHOD_SIZE+1);
	p_conv_data->frame_number = setup_frame_number;
	p_conv_data->is_video = is_video;
	p_conv_data->rtp_dyn_payload = rtp_dyn_payload;
	p_conv_data->srtp_info = srtp_info;
}

/* Set up an RTP conversation */
void rtp_add_address(packet_info *pinfo,
                     address *addr, int port,
                     int other_port,
                     const gchar *setup_method, guint32 setup_frame_number, gboolean is_video , GHashTable *rtp_dyn_payload)
{
	srtp_add_address(pinfo, addr, port, other_port, setup_method, setup_frame_number, is_video, rtp_dyn_payload, NULL);
}

static gboolean
dissect_rtp_heur_common( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, gboolean check_destport )
{
	guint8       octet1;
 	unsigned int version;
 	unsigned int offset = 0;

	/* This is a heuristic dissector, which means we get all the UDP
	 * traffic not sent to a known dissector and not claimed by
	 * a heuristic dissector called before us!
	 */

	if (! global_rtp_heur)
		return FALSE;

	/* Get the fields in the first octet */
	octet1 = tvb_get_guint8( tvb, offset );
	version = RTP_VERSION( octet1 );

	if (version == 0) {
		if (!(tvb_memeql(tvb, 4, "ZRTP", 4)))
		{
			call_dissector_only(zrtp_handle, tvb, pinfo, tree);
			return TRUE;
		} else {
			switch (global_rtp_version0_type) {
			case RTP0_CLASSICSTUN:
				return call_dissector_only(classicstun_heur_handle, tvb, pinfo, tree);

			case RTP0_T38:
				/* XXX: Should really be calling a heuristic dissector for T38 ??? */
				call_dissector_only(t38_handle, tvb, pinfo, tree);
				return TRUE;

			case RTP0_INVALID:

			default:
				return FALSE; /* Unknown or unsupported version */
			}
		}
	} else if (version != 2) {
		/* Unknown or unsupported version */
		return FALSE;
	}

	/* Was it sent to an even-numbered port? */
	if (check_destport && ((pinfo->destport % 2) != 0)) {
		return FALSE;
	}

	dissect_rtp( tvb, pinfo, tree );
	return TRUE;
}

static gboolean
dissect_rtp_heur_udp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	return dissect_rtp_heur_common(tvb, pinfo, tree, TRUE);
}

static gboolean
dissect_rtp_heur_stun( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	return dissect_rtp_heur_common(tvb, pinfo, tree, FALSE);
}

/*
 * Process the payload of the RTP packet, hand it to the subdissector
 */
static void
process_rtp_payload(tvbuff_t *newtvb, packet_info *pinfo, proto_tree *tree,
		    proto_tree *rtp_tree,
		    unsigned int payload_type)
{
	struct _rtp_conversation_info *p_conv_data = NULL;
	gboolean found_match = FALSE;
	int payload_len;
	struct srtp_info *srtp_info;
	int offset=0;

	payload_len = tvb_length_remaining(newtvb, offset);

	/* first check if this is added as an SRTP stream - if so, don't try to dissector the payload data for now */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);
	if (p_conv_data && p_conv_data->srtp_info) {
		srtp_info = p_conv_data->srtp_info;
		payload_len -= srtp_info->mki_len + srtp_info->auth_tag_len;
#if 0
#error Currently the srtp_info structure contains no cipher data, see packet-sdp.c adding dummy_srtp_info structure
		if (p_conv_data->srtp_info->encryption_algorithm==SRTP_ENC_ALG_NULL) {
			if (rtp_tree)
				proto_tree_add_text(rtp_tree, newtvb, offset, payload_len, "SRTP Payload with NULL encryption");
		}
		else
#endif
		{
			if (rtp_tree)
				proto_tree_add_item(rtp_tree, hf_srtp_encrypted_payload, newtvb, offset, payload_len, ENC_NA);
			found_match = TRUE;	/* use this flag to prevent dissection below */
		}
		offset += payload_len;

		if (srtp_info->mki_len) {
			proto_tree_add_item(rtp_tree, hf_srtp_mki, newtvb, offset, srtp_info->mki_len, ENC_NA);
			offset += srtp_info->mki_len;
		}

		if (srtp_info->auth_tag_len) {
			proto_tree_add_item(rtp_tree, hf_srtp_auth_tag, newtvb, offset, srtp_info->auth_tag_len, ENC_NA);
			offset += srtp_info->auth_tag_len;
		}
	}

	/* if the payload type is dynamic, we check if the conv is set and we look for the pt definition */
	else if ( (payload_type >= PT_UNDF_96 && payload_type <= PT_UNDF_127) ) {
		if (p_conv_data && p_conv_data->rtp_dyn_payload) {
			gchar *payload_type_str = NULL;
			encoding_name_and_rate_t *encoding_name_and_rate_pt = NULL;
			encoding_name_and_rate_pt = g_hash_table_lookup(p_conv_data->rtp_dyn_payload, &payload_type);
			if (encoding_name_and_rate_pt) {
				payload_type_str = encoding_name_and_rate_pt->encoding_name;
			}
			if (payload_type_str){
				found_match = dissector_try_string(rtp_dyn_pt_dissector_table,
								   payload_type_str, newtvb, pinfo, tree);
				/* If payload type string set from conversation and
				 * no matching dissector found it's probably because no subdissector
				 * exists. Don't call the dissectors based on payload number
				 * as that'd probably be the wrong dissector in this case.
				 * Just add it as data.
				 */
				if(found_match==FALSE)
					proto_tree_add_item( rtp_tree, hf_rtp_data, newtvb, 0, -1, ENC_NA );
				return;
			}

		}
	}

	/* if we don't found, it is static OR could be set static from the preferences */
	if (!found_match && !dissector_try_uint(rtp_pt_dissector_table, payload_type, newtvb, pinfo, tree))
		proto_tree_add_item( rtp_tree, hf_rtp_data, newtvb, 0, -1, ENC_NA );

}

/* Rtp payload reassembly
 *
 * This handles the reassembly of PDUs for higher-level protocols.
 *
 * We're a bit limited on how we can cope with out-of-order packets, because
 * we don't have any idea of where the datagram boundaries are. So if we see
 * packets A, C, B (all of which comprise a single datagram), we cannot know
 * that C should be added to the same datagram as A, until we come to B (which
 * may or may not actually be present...).
 *
 * What we end up doing in this case is passing A+B to the subdissector as one
 * datagram, and make out that a new one starts on C.
 */
static void
dissect_rtp_data( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		  proto_tree *rtp_tree, int offset, unsigned int data_len,
		  unsigned int data_reported_len,
		  unsigned int payload_type )
{
	tvbuff_t *newtvb;
	struct _rtp_conversation_info *p_conv_data= NULL;
	gboolean must_desegment = FALSE;
	rtp_private_conv_info *finfo = NULL;
	rtp_multisegment_pdu *msp = NULL;
	guint32 seqno;

	/* Retrieve RTPs idea of a converation */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);

	if(p_conv_data != NULL)
		finfo = p_conv_data->rtp_conv_info;

	if(finfo == NULL || !desegment_rtp) {
		/* Hand the whole lot off to the subdissector */
		newtvb=tvb_new_subset(tvb,offset,data_len,data_reported_len);
		process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type);
		return;
	}

	seqno = p_conv_data->extended_seqno;

	pinfo->can_desegment = 2;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;

#ifdef DEBUG_FRAGMENTS
	g_debug("%d: RTP Part of convo %d(%p); seqno %d",
		pinfo->fd->num,
		p_conv_data->frame_number, p_conv_data,
		seqno
		);
#endif

	/* look for a pdu which we might be extending */
	msp = (rtp_multisegment_pdu *)se_tree_lookup32_le(finfo->multisegment_pdus,seqno-1);

	if(msp && msp->startseq < seqno && msp->endseq >= seqno) {
		guint32 fid = msp->startseq;
		fragment_data *fd_head;

#ifdef DEBUG_FRAGMENTS
		g_debug("\tContinues fragment %d", fid);
#endif

		/* we always assume the datagram is complete; if this is the
		 * first pass, that's our best guess, and if it's not, what we
		 * say gets ignored anyway.
		 */
		fd_head = fragment_add_seq(tvb, offset, pinfo, fid, fragment_table,
					   seqno-msp->startseq, data_len, FALSE);

		newtvb = process_reassembled_data(tvb,offset, pinfo, "Reassembled RTP", fd_head,
						  &rtp_fragment_items, NULL, tree);

#ifdef DEBUG_FRAGMENTS
		g_debug("\tFragment Coalesced; fd_head=%p, newtvb=%p (len %d)",fd_head, newtvb,
			newtvb?tvb_reported_length(newtvb):0);
#endif

		if(newtvb != NULL) {
			/* Hand off to the subdissector */
			process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type);

			/*
			 * Check to see if there were any complete fragments within the chunk
			 */
			if( pinfo->desegment_len && pinfo->desegment_offset == 0 )
			{
#ifdef DEBUG_FRAGMENTS
				g_debug("\tNo complete pdus in payload" );
#endif
				/* Mark the fragments and not complete yet */
				fragment_set_partial_reassembly(pinfo, fid, fragment_table);

				/* we must need another segment */
				msp->endseq = MIN(msp->endseq,seqno) + 1;
			}
			else
			{
				/*
				 * Data was dissected so add the protocol tree to the display
				 */
				proto_item *rtp_tree_item, *frag_tree_item;
				/* this nargery is to insert the fragment tree into the main tree
				 * between the RTP protocol entry and the subdissector entry */
				show_fragment_tree(fd_head, &rtp_fragment_items, tree, pinfo, newtvb, &frag_tree_item);
				rtp_tree_item = proto_item_get_parent( proto_tree_get_parent( rtp_tree ));
				if( frag_tree_item && rtp_tree_item )
					proto_tree_move_item( tree, rtp_tree_item, frag_tree_item );


				if(pinfo->desegment_len)
				{
					/* the higher-level dissector has asked for some more data - ie,
					   the end of this segment does not coincide with the end of a
					   higher-level PDU. */
					must_desegment = TRUE;
				}
			}

		}

	}
	else
	{
		/*
		 * The segment is not the continuation of a fragmented segment
		 * so process it as normal
		 */
#ifdef DEBUG_FRAGMENTS
		g_debug("\tRTP non-fragment payload");
#endif
		newtvb = tvb_new_subset( tvb, offset, data_len, data_reported_len );

		/* Hand off to the subdissector */
		process_rtp_payload(newtvb, pinfo, tree, rtp_tree, payload_type);

		if(pinfo->desegment_len) {
			/* the higher-level dissector has asked for some more data - ie,
			   the end of this segment does not coincide with the end of a
			   higher-level PDU. */
			must_desegment = TRUE;
		}
	}

	/*
	 * There were bytes left over that the higher protocol couldn't dissect so save them
	 */
	if(must_desegment)
	{
		guint32 deseg_offset = pinfo->desegment_offset;
		guint32 frag_len = tvb_reported_length_remaining(newtvb, deseg_offset);
		fragment_data *fd_head = NULL;

#ifdef DEBUG_FRAGMENTS
		g_debug("\tRTP Must Desegment: tvb_len=%d ds_len=%d %d frag_len=%d ds_off=%d",
			tvb_reported_length(newtvb),
			pinfo->desegment_len,
			pinfo->fd->flags.visited,
			frag_len,
			deseg_offset);
#endif
		/* allocate a new msp for this pdu */
		msp = se_alloc(sizeof(rtp_multisegment_pdu));
		msp->startseq = seqno;
		msp->endseq = seqno+1;
		se_tree_insert32(finfo->multisegment_pdus,seqno,msp);

		/*
		 * Add the fragment to the fragment table
		 */
		fd_head = fragment_add_seq(newtvb,deseg_offset, pinfo, seqno, fragment_table, 0, frag_len,
					   TRUE );

		if(fd_head != NULL)
		{
			if( fd_head->reassembled_in != 0 && !(fd_head->flags & FD_PARTIAL_REASSEMBLY) )
			{
				proto_item *rtp_tree_item;
				rtp_tree_item = proto_tree_add_uint( tree, hf_rtp_reassembled_in,
								     newtvb, deseg_offset, tvb_reported_length_remaining(newtvb,deseg_offset),
								     fd_head->reassembled_in);
				PROTO_ITEM_SET_GENERATED(rtp_tree_item);
#ifdef DEBUG_FRAGMENTS
				g_debug("\tReassembled in %d", fd_head->reassembled_in);
#endif
			}
			else
			{
#ifdef DEBUG_FRAGMENTS
				g_debug("\tUnfinished fragment");
#endif
				/* this fragment is never reassembled */
				proto_tree_add_text( tree, tvb, deseg_offset, -1,"RTP fragment, unfinished");
			}
		}
		else
		{
			/*
			 * This fragment was the first fragment in a new entry in the
			 * frag_table; we don't yet know where it is reassembled
			 */
#ifdef DEBUG_FRAGMENTS
			g_debug("\tnew pdu");
#endif
		}

		if( pinfo->desegment_offset == 0 )
		{
			col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP");
			col_set_str(pinfo->cinfo, COL_INFO, "[RTP segment of a reassembled PDU]");
		}
	}



	pinfo->can_desegment = 0;
	pinfo->desegment_offset = 0;
	pinfo->desegment_len = 0;
}



static void
dissect_rtp_rfc2198(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	int offset = 0;
	guint8 octet1;
	int cnt;
	gboolean hdr_follow = TRUE;
	proto_item *ti = NULL;
	proto_tree *rfc2198_tree = NULL;
	proto_tree *rfc2198_hdr_tree = NULL;
	rfc2198_hdr *hdr_last, *hdr_new;
	rfc2198_hdr *hdr_chain = NULL;
	struct _rtp_conversation_info *p_conv_data= NULL;
	gchar *payload_type_str;

	/* Retrieve RTPs idea of a converation */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);

	/* Add try to RFC 2198 data */
	ti = proto_tree_add_text(tree, tvb, offset, -1, "RFC 2198: Redundant Audio Data");
	rfc2198_tree = proto_item_add_subtree(ti, ett_rtp_rfc2198);

	hdr_last = NULL;
	cnt = 0;
	while (hdr_follow) {
		cnt++;
		payload_type_str = NULL;

		/* Allocate and fill in header */
		hdr_new = ep_alloc(sizeof(rfc2198_hdr));
		hdr_new->next = NULL;
		octet1 = tvb_get_guint8(tvb, offset);
		hdr_new->pt = RTP_PAYLOAD_TYPE(octet1);
		hdr_follow = (octet1 & 0x80);

		/* if it is dynamic payload, let use the conv data to see if it is defined */
		if ((hdr_new->pt > 95) && (hdr_new->pt < 128)) {
			if (p_conv_data && p_conv_data->rtp_dyn_payload){
				encoding_name_and_rate_t *encoding_name_and_rate_pt = NULL;
				encoding_name_and_rate_pt = g_hash_table_lookup(p_conv_data->rtp_dyn_payload, &hdr_new->pt);
				if (encoding_name_and_rate_pt) {
					payload_type_str = encoding_name_and_rate_pt->encoding_name;
				}
			}
		}
		/* Add a subtree for this header and add items */
		ti = proto_tree_add_text(rfc2198_tree, tvb, offset, (hdr_follow)?4:1, "Header %u", cnt);
		rfc2198_hdr_tree = proto_item_add_subtree(ti, ett_rtp_rfc2198_hdr);
		proto_tree_add_item(rfc2198_hdr_tree, hf_rtp_rfc2198_follow, tvb, offset, 1, ENC_BIG_ENDIAN );
		proto_tree_add_uint_format(rfc2198_hdr_tree, hf_rtp_payload_type, tvb,
		    offset, 1, octet1, "Payload type: %s (%u)",
			payload_type_str ? payload_type_str : val_to_str_ext(hdr_new->pt, &rtp_payload_type_vals_ext, "Unknown"),
			hdr_new->pt);
		proto_item_append_text(ti, ": PT=%s",
				       payload_type_str ? payload_type_str :
				                          val_to_str_ext(hdr_new->pt, &rtp_payload_type_vals_ext, "Unknown (%u)"));
		offset += 1;

		/* Timestamp offset and block length don't apply to last header */
		if (hdr_follow) {
			proto_tree_add_item(rfc2198_hdr_tree, hf_rtp_rfc2198_tm_off, tvb, offset, 2, ENC_BIG_ENDIAN );
			proto_tree_add_item(rfc2198_hdr_tree, hf_rtp_rfc2198_bl_len, tvb, offset + 1, 2, ENC_BIG_ENDIAN );
			hdr_new->len = tvb_get_ntohs(tvb, offset + 1) & 0x03FF;
			proto_item_append_text(ti, ", len=%u", hdr_new->len);
			offset += 3;
		} else {
			hdr_new->len = -1;
			hdr_follow = FALSE;
		}

		if (hdr_last) {
			hdr_last->next = hdr_new;
		} else {
			hdr_chain = hdr_new;
		}
		hdr_last = hdr_new;
	}

	/* Dissect each data block according to the header info */
	hdr_last = hdr_chain;
	while (hdr_last) {
		hdr_last->offset = offset;
		if (!hdr_last->next) {
			hdr_last->len = tvb_reported_length_remaining(tvb, offset);
		}
		dissect_rtp_data(tvb, pinfo, tree, rfc2198_tree, hdr_last->offset, hdr_last->len, hdr_last->len, hdr_last->pt);
		offset += hdr_last->len;
		hdr_last = hdr_last->next;
	}
}

static void
dissect_rtp( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	proto_item *ti            = NULL;
	proto_tree *rtp_tree      = NULL;
	proto_tree *rtp_csrc_tree = NULL;
	proto_tree *rtp_hext_tree = NULL;
	guint8      octet1, octet2;
	unsigned int version;
	gboolean    padding_set;
	gboolean    extension_set;
	unsigned int csrc_count;
	gboolean    marker_set;
	unsigned int payload_type;
	gchar *payload_type_str = NULL;
	gboolean    is_srtp = FALSE;
	unsigned int i            = 0;
	unsigned int hdr_extension= 0;
	unsigned int hdr_extension_id = 0;
	unsigned int padding_count;
	gint        length, reported_length;
	int         data_len;
	unsigned int offset = 0;
	guint16     seq_num;
	guint32     timestamp;
	guint32     sync_src;
	guint32     csrc_item;
	struct _rtp_conversation_info *p_conv_data = NULL;
	/*struct srtp_info *srtp_info = NULL;*/
	/*unsigned int srtp_offset;*/
	unsigned int hdrext_offset = 0;
	tvbuff_t *newtvb = NULL;

	/* Can tap up to 4 RTP packets within same packet */
	static struct _rtp_info rtp_info_arr[4];
	static int rtp_info_current=0;
	struct _rtp_info *rtp_info;

	rtp_info_current++;
	if (rtp_info_current==4) {
		rtp_info_current=0;
	}
	rtp_info = &rtp_info_arr[rtp_info_current];

	/* Get the fields in the first octet */
	octet1 = tvb_get_guint8( tvb, offset );
	version = RTP_VERSION( octet1 );

	if (version == 0) {
		switch (global_rtp_version0_type) {
		case RTP0_CLASSICSTUN:
			call_dissector(classicstun_handle, tvb, pinfo, tree);
			return;

		case RTP0_T38:
			call_dissector(t38_handle, tvb, pinfo, tree);
			return;

		case RTP0_INVALID:
			if (!(tvb_memeql(tvb, 4, "ZRTP", 4)))
			{
				call_dissector(zrtp_handle,tvb,pinfo,tree);
				return;
			}
		default:
			; /* Unknown or unsupported version (let it fall through) */
		}
	}

	/* fill in the rtp_info structure */
	rtp_info->info_version = version;
	if (version != 2) {
		/*
		 * Unknown or unsupported version.
		 */
		col_set_str(pinfo->cinfo, COL_PROTOCOL, "RTP");

		col_add_fstr( pinfo->cinfo, COL_INFO,
		    "Unknown RTP version %u", version);

		if ( tree ) {
			ti = proto_tree_add_item( tree, proto_rtp, tvb, offset, -1, ENC_NA );
			rtp_tree = proto_item_add_subtree( ti, ett_rtp );

			proto_tree_add_uint( rtp_tree, hf_rtp_version, tvb,
			    offset, 1, octet1);
		}
		return;
	}

	padding_set = RTP_PADDING( octet1 );
	extension_set = RTP_EXTENSION( octet1 );
	csrc_count = RTP_CSRC_COUNT( octet1 );

	/* Get the fields in the second octet */
	octet2 = tvb_get_guint8( tvb, offset + 1 );
	marker_set = RTP_MARKER( octet2 );
	payload_type = RTP_PAYLOAD_TYPE( octet2 );

	/* Get the subsequent fields */
	seq_num = tvb_get_ntohs( tvb, offset + 2 );
	timestamp = tvb_get_ntohl( tvb, offset + 4 );
	sync_src = tvb_get_ntohl( tvb, offset + 8 );

	/* fill in the rtp_info structure */
	rtp_info->info_padding_set = padding_set;
	rtp_info->info_padding_count = 0;
	rtp_info->info_marker_set = marker_set;
	rtp_info->info_is_video = FALSE;
	rtp_info->info_payload_type = payload_type;
	rtp_info->info_seq_num = seq_num;
	rtp_info->info_timestamp = timestamp;
	rtp_info->info_sync_src = sync_src;
	rtp_info->info_is_srtp = FALSE;
	rtp_info->info_setup_frame_num = 0;
	rtp_info->info_payload_type_str = NULL;
	rtp_info->info_payload_rate = 0;

	/*
	 * Do we have all the data?
	 */
	length = tvb_length_remaining(tvb, offset);
	reported_length = tvb_reported_length_remaining(tvb, offset);
	if (reported_length >= 0 && length >= reported_length) {
		/*
		 * Yes.
		 */
		rtp_info->info_all_data_present = TRUE;
		rtp_info->info_data_len = reported_length;

		/*
		 * Save the pointer to raw rtp data (header + payload incl.
		 * padding).
		 * That should be safe because the "epan_dissect_t"
		 * constructed for the packet has not yet been freed when
		 * the taps are called.
		 * (Destroying the "epan_dissect_t" will end up freeing
		 * all the tvbuffs and hence invalidating pointers to
		 * their data.)
		 * See "add_packet_to_packet_list()" for details.
		 */
		rtp_info->info_data = tvb_get_ptr(tvb, 0, -1);
	} else {
		/*
		 * No - packet was cut short at capture time.
		 */
		rtp_info->info_all_data_present = FALSE;
		rtp_info->info_data_len = 0;
		rtp_info->info_data = NULL;
	}

	/* Look for conv and add to the frame if found */
	get_conv_info(pinfo, rtp_info);
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);

	if (p_conv_data)
		rtp_info->info_is_video = p_conv_data->is_video;

	if (p_conv_data && p_conv_data->srtp_info) is_srtp = TRUE;
	rtp_info->info_is_srtp = is_srtp;

	col_set_str( pinfo->cinfo, COL_PROTOCOL, (is_srtp) ? "SRTP" : "RTP" );

	/* check if this is added as an SRTP stream - if so, don't try to dissect the payload data for now */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);

#if 0 /* XXX: srtp_offset never actually used ?? */
	if (p_conv_data && p_conv_data->srtp_info) {
		srtp_info = p_conv_data->srtp_info;
		if (rtp_info->info_all_data_present) {
			srtp_offset = rtp_info->info_data_len - srtp_info->mki_len - srtp_info->auth_tag_len;
		}
	}
#endif

	/* if it is dynamic payload, let use the conv data to see if it is defined */
	if ( (payload_type>95) && (payload_type<128) ) {
		if (p_conv_data && p_conv_data->rtp_dyn_payload){
			encoding_name_and_rate_t *encoding_name_and_rate_pt = NULL;
			encoding_name_and_rate_pt = g_hash_table_lookup(p_conv_data->rtp_dyn_payload, &payload_type);
			if (encoding_name_and_rate_pt) {
				rtp_info->info_payload_type_str = payload_type_str = encoding_name_and_rate_pt->encoding_name;
				rtp_info->info_payload_rate = encoding_name_and_rate_pt->sample_rate;
			}
		}
	}

	col_add_fstr( pinfo->cinfo, COL_INFO,
	    "PT=%s, SSRC=0x%X, Seq=%u, Time=%u%s",
		payload_type_str ? payload_type_str : val_to_str_ext( payload_type, &rtp_payload_type_vals_ext,"Unknown (%u)" ),
	    sync_src,
	    seq_num,
	    timestamp,
	    marker_set ? ", Mark " : " ");


	if ( tree ) {
		proto_tree *item;
		/* Create RTP protocol tree */
		ti = proto_tree_add_item(tree, proto_rtp, tvb, offset, -1, ENC_NA );
		rtp_tree = proto_item_add_subtree(ti, ett_rtp );

		/* Conversation setup info */
		if (global_rtp_show_setup_info)
		{
			show_setup_info(tvb, pinfo, rtp_tree);
		}

		proto_tree_add_uint( rtp_tree, hf_rtp_version, tvb,
		    offset, 1, octet1 );
		proto_tree_add_boolean( rtp_tree, hf_rtp_padding, tvb,
		    offset, 1, octet1 );
		proto_tree_add_boolean( rtp_tree, hf_rtp_extension, tvb,
		    offset, 1, octet1 );
		proto_tree_add_uint( rtp_tree, hf_rtp_csrc_count, tvb,
		    offset, 1, octet1 );
		offset++;

		proto_tree_add_boolean( rtp_tree, hf_rtp_marker, tvb, offset,
		    1, octet2 );

		proto_tree_add_uint_format( rtp_tree, hf_rtp_payload_type, tvb,
		    offset, 1, octet2, "Payload type: %s (%u)",
			payload_type_str ? payload_type_str : val_to_str_ext( payload_type, &rtp_payload_type_vals_ext,"Unknown"),
			payload_type);

		offset++;

		/* Sequence number 16 bits (2 octets) */
		proto_tree_add_uint( rtp_tree, hf_rtp_seq_nr, tvb, offset, 2, seq_num );
		if(p_conv_data != NULL) {
			item = proto_tree_add_uint( rtp_tree, hf_rtp_ext_seq_nr, tvb, offset, 2, p_conv_data->extended_seqno );
			PROTO_ITEM_SET_GENERATED(item);
		}
		offset += 2;

		/* Timestamp 32 bits (4 octets) */
		proto_tree_add_uint( rtp_tree, hf_rtp_timestamp, tvb, offset, 4, timestamp );
		offset += 4;

		/* Synchronization source identifier 32 bits (4 octets) */
		proto_tree_add_uint( rtp_tree, hf_rtp_ssrc, tvb, offset, 4, sync_src );
		offset += 4;
	} else {
		offset += 12;
	}
	/* CSRC list*/
	if ( csrc_count > 0 ) {
		if ( tree ) {
			ti = proto_tree_add_item(rtp_tree, hf_rtp_csrc_items, tvb, offset,
			                         csrc_count * 4, ENC_NA);
			proto_item_append_text(ti, " (%u items)", csrc_count);
			rtp_csrc_tree = proto_item_add_subtree( ti, ett_csrc_list );
		}
		for (i = 0; i < csrc_count; i++ ) {
			csrc_item = tvb_get_ntohl( tvb, offset );
			if ( tree ) proto_tree_add_uint_format( rtp_csrc_tree,
			    hf_rtp_csrc_item, tvb, offset, 4,
			    csrc_item,
			    "CSRC item %d: 0x%X",
			    i, csrc_item );
			offset += 4;
		}
	}

	/* Optional RTP header extension */
	if ( extension_set ) {
		/* Defined by profile field is 16 bits (2 octets) */
		hdr_extension_id = tvb_get_ntohs( tvb, offset );
		if ( tree ) proto_tree_add_uint( rtp_tree, hf_rtp_prof_define, tvb, offset, 2, hdr_extension_id );
		offset += 2;

		hdr_extension = tvb_get_ntohs( tvb, offset );
		if ( tree ) proto_tree_add_uint( rtp_tree, hf_rtp_length, tvb, offset, 2, hdr_extension);
		offset += 2;
		if ( hdr_extension > 0 ) {
			if ( tree ) {
				ti = proto_tree_add_item(rtp_tree, hf_rtp_hdr_exts, tvb, offset, hdr_extension * 4, ENC_NA);
				rtp_hext_tree = proto_item_add_subtree( ti, ett_hdr_ext );
			}

			/* pass interpretation of header extension to a registered subdissector */
			newtvb = tvb_new_subset(tvb, offset, hdr_extension * 4, hdr_extension * 4);
			if ( !(dissector_try_uint(rtp_hdr_ext_dissector_table, hdr_extension_id, newtvb, pinfo, rtp_hext_tree)) ) {
				hdrext_offset = offset;
				for ( i = 0; i < hdr_extension; i++ ) {
					if ( tree ) proto_tree_add_uint( rtp_hext_tree, hf_rtp_hdr_ext, tvb, hdrext_offset, 4, tvb_get_ntohl( tvb, hdrext_offset ) );
					hdrext_offset += 4;
				}
			}
			offset += hdr_extension * 4;
		}
	}

	if ( padding_set ) {
		/*
		 * This RTP frame has padding - find it.
		 *
		 * The padding count is found in the LAST octet of
		 * the packet; it contains the number of octets
		 * that can be ignored at the end of the packet.
		 */
		if (tvb_length(tvb) < tvb_reported_length(tvb)) {
			/*
			 * We don't *have* the last octet of the
			 * packet, so we can't get the padding
			 * count.
			 *
			 * Put an indication of that into the
			 * tree, and just put in a raw data
			 * item.
			 */
			if ( tree ) proto_tree_add_text(rtp_tree, tvb, 0, 0,
			    "Frame has padding, but not all the frame data was captured");
			call_dissector(data_handle,
			    tvb_new_subset_remaining(tvb, offset),
			    pinfo, rtp_tree);
			return;
		}

		padding_count = tvb_get_guint8( tvb,
		    tvb_reported_length( tvb ) - 1 );
		data_len =
		    tvb_reported_length_remaining( tvb, offset ) - padding_count;

		rtp_info->info_payload_offset = offset;
		rtp_info->info_payload_len = tvb_length_remaining(tvb, offset);
		rtp_info->info_padding_count = padding_count;

		if (data_len > 0) {
			/*
			 * There's data left over when you take out
			 * the padding; dissect it.
			 */
			dissect_rtp_data( tvb, pinfo, tree, rtp_tree,
			    offset,
			    data_len,
			    data_len,
			    payload_type );
			offset += data_len;
		} else if (data_len < 0) {
			/*
			 * The padding count is bigger than the
			 * amount of RTP payload in the packet!
			 * Clip the padding count.
			 *
			 * XXX - put an item in the tree to indicate
			 * that the padding count is bogus?
			 */
			padding_count =
			    tvb_reported_length_remaining(tvb, offset);
		}
		if (padding_count > 1) {
			/*
			 * There's more than one byte of padding;
			 * show all but the last byte as padding
			 * data.
			 */
			if ( tree ) proto_tree_add_item( rtp_tree, hf_rtp_padding_data,
			    tvb, offset, padding_count - 1, ENC_NA );
			offset += padding_count - 1;
		}
		/*
		 * Show the last byte in the PDU as the padding
		 * count.
		 */
		if ( tree ) proto_tree_add_item( rtp_tree, hf_rtp_padding_count,
		    tvb, offset, 1, ENC_BIG_ENDIAN );
	}
	else {
		/*
		 * No padding.
		 */
		dissect_rtp_data( tvb, pinfo, tree, rtp_tree, offset,
				  tvb_length_remaining( tvb, offset ),
				  tvb_reported_length_remaining( tvb, offset ),
				  payload_type );
		rtp_info->info_payload_offset = offset;
		rtp_info->info_payload_len = tvb_length_remaining(tvb, offset);
	}
	if (!pinfo->flags.in_error_pkt)
		tap_queue_packet(rtp_tap, pinfo, rtp_info);
}


/* calculate the extended sequence number - top 16 bits of the previous sequence number,
 * plus our own; then correct for wrapping */
static guint32 calculate_extended_seqno(guint32 previous_seqno, guint16 raw_seqno)
{
	guint32 seqno = (previous_seqno & 0xffff0000) | raw_seqno;
	if(seqno + 0x8000 < previous_seqno) {
		seqno += 0x10000;
	} else if(previous_seqno + 0x8000 < seqno) {
		/* we got an out-of-order packet which happened to go backwards over the
		 * wrap boundary */
		seqno -= 0x10000;
	}
	return seqno;
}

/* Look for conversation info */
static void get_conv_info(packet_info *pinfo, struct _rtp_info *rtp_info)
{
	/* Conversation and current data */
	conversation_t *p_conv = NULL;
	struct _rtp_conversation_info *p_conv_data = NULL;

	/* Use existing packet info if available */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);

	if (!p_conv_data)
	{
		/* First time, get info from conversation */
		p_conv = find_conversation(pinfo->fd->num, &pinfo->net_dst, &pinfo->net_src,
		                           pinfo->ptype,
		                           pinfo->destport, pinfo->srcport, NO_ADDR_B);
		if (p_conv)
		{
			/* Create space for packet info */
			struct _rtp_conversation_info *p_conv_packet_data;
			p_conv_data = conversation_get_proto_data(p_conv, proto_rtp);

			if (p_conv_data) {
				guint32 seqno;

				/* Save this conversation info into packet info */
				p_conv_packet_data = se_alloc(sizeof(struct _rtp_conversation_info));
				g_strlcpy(p_conv_packet_data->method, p_conv_data->method, MAX_RTP_SETUP_METHOD_SIZE+1);
				p_conv_packet_data->frame_number = p_conv_data->frame_number;
				p_conv_packet_data->is_video = p_conv_data->is_video;
				p_conv_packet_data->rtp_dyn_payload = p_conv_data->rtp_dyn_payload;
				p_conv_packet_data->rtp_conv_info = p_conv_data->rtp_conv_info;
				p_conv_packet_data->srtp_info = p_conv_data->srtp_info;
				p_add_proto_data(pinfo->fd, proto_rtp, p_conv_packet_data);

				/* calculate extended sequence number */
				seqno = calculate_extended_seqno(p_conv_data->extended_seqno,
								 rtp_info->info_seq_num);

				p_conv_packet_data->extended_seqno = seqno;
				p_conv_data->extended_seqno = seqno;
			}
		}
	}
	if (p_conv_data) rtp_info->info_setup_frame_num = p_conv_data->frame_number;
}


/* Display setup info */
static void show_setup_info(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	/* Conversation and current data */
	struct _rtp_conversation_info *p_conv_data = NULL;
	proto_tree *rtp_setup_tree;
	proto_item *ti;

	/* Use existing packet info if available */
	p_conv_data = p_get_proto_data(pinfo->fd, proto_rtp);

	if (!p_conv_data) return;

	/* Create setup info subtree with summary info. */
	ti =  proto_tree_add_string_format(tree, hf_rtp_setup, tvb, 0, 0,
		                                               "",
		                                               "Stream setup by %s (frame %u)",
		                                               p_conv_data->method,
		                                               p_conv_data->frame_number);
		PROTO_ITEM_SET_GENERATED(ti);
		rtp_setup_tree = proto_item_add_subtree(ti, ett_rtp_setup);
		if (rtp_setup_tree)
		{
			/* Add details into subtree */
			proto_item* item = proto_tree_add_uint(rtp_setup_tree, hf_rtp_setup_frame,
			                                       tvb, 0, 0, p_conv_data->frame_number);
			PROTO_ITEM_SET_GENERATED(item);
			item = proto_tree_add_string(rtp_setup_tree, hf_rtp_setup_method,
			                             tvb, 0, 0, p_conv_data->method);
			PROTO_ITEM_SET_GENERATED(item);
		}
}

/* Dissect PacketCable CCC header */

static void
dissect_pkt_ccc(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_item *ti            = NULL;
	proto_tree *pkt_ccc_tree      = NULL;

	if ( tree ) {
		ti = proto_tree_add_item(tree, proto_pkt_ccc, tvb, 0, 12, ENC_NA);
		pkt_ccc_tree = proto_item_add_subtree(ti, ett_pkt_ccc);

		proto_tree_add_item(pkt_ccc_tree, hf_pkt_ccc_id, tvb, 0, 4, ENC_BIG_ENDIAN);
		proto_tree_add_item(pkt_ccc_tree, hf_pkt_ccc_ts, tvb, 4, 8,
				    ENC_TIME_NTP|ENC_BIG_ENDIAN);
	}

	dissect_rtp(tvb, pinfo, tree);
}


/* Register PacketCable CCC */

void
proto_register_pkt_ccc(void)
{
	static hf_register_info hf[] =
	{
		{
			&hf_pkt_ccc_id,
			{
				"PacketCable CCC Identifier",
				"pkt_ccc.ccc_id",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_pkt_ccc_ts,
			{
				"PacketCable CCC Timestamp",
				"pkt_ccc.ts",
				FT_ABSOLUTE_TIME,
				ABSOLUTE_TIME_UTC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},

	};

	static gint *ett[] =
	{
		&ett_pkt_ccc,
	};

	module_t *pkt_ccc_module;

	proto_pkt_ccc = proto_register_protocol("PacketCable Call Content Connection",
	    "PKT CCC", "pkt_ccc");
	proto_register_field_array(proto_pkt_ccc, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("pkt_ccc", dissect_pkt_ccc, proto_pkt_ccc);

	pkt_ccc_module = prefs_register_protocol(proto_pkt_ccc, proto_reg_handoff_pkt_ccc);

	prefs_register_uint_preference(pkt_ccc_module, "udp_port",
	                               "UDP port",
	                               "Decode packets on this UDP port as PacketCable CCC",
	                               10, &global_pkt_ccc_udp_port);
}

void
proto_reg_handoff_pkt_ccc(void)
{
	/*
	 * Register this dissector as one that can be selected by a
	 * UDP port number.
	 */
	static gboolean initialized = FALSE;
	static dissector_handle_t pkt_ccc_handle;
	static guint saved_pkt_ccc_udp_port;

	if (!initialized) {
		pkt_ccc_handle = find_dissector("pkt_ccc");
		dissector_add_handle("udp.port", pkt_ccc_handle);  /* for 'decode-as' */
		initialized = TRUE;
	} else {
		if (saved_pkt_ccc_udp_port != 0) {
			dissector_delete_uint("udp.port", saved_pkt_ccc_udp_port, pkt_ccc_handle);
		}
	}

	if (global_pkt_ccc_udp_port != 0) {
		dissector_add_uint("udp.port", global_pkt_ccc_udp_port, pkt_ccc_handle);
	}
	saved_pkt_ccc_udp_port = global_pkt_ccc_udp_port;
}

/* Register RTP */

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
				0xC0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_padding,
			{
				"Padding",
				"rtp.padding",
				FT_BOOLEAN,
				8,
				NULL,
				0x20,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_extension,
			{
				"Extension",
				"rtp.ext",
				FT_BOOLEAN,
				8,
				NULL,
				0x10,
				NULL, HFILL
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
				0x0F,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_marker,
			{
				"Marker",
				"rtp.marker",
				FT_BOOLEAN,
				8,
				NULL,
				0x80,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_payload_type,
			{
				"Payload type",
				"rtp.p_type",
				FT_UINT8,
				BASE_DEC,
				NULL,
				0x7F,
				NULL, HFILL
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
				NULL, HFILL
			}
		},
		{
			&hf_rtp_ext_seq_nr,
			{
				"Extended sequence number",
				"rtp.extseq",
				FT_UINT32,
				BASE_DEC,
				NULL,
				0x0,
				NULL, HFILL
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
				NULL, HFILL
			}
		},
		{
			&hf_rtp_ssrc,
			{
				"Synchronization Source identifier",
				"rtp.ssrc",
				FT_UINT32,
				BASE_HEX_DEC,
				NULL,
				0x0,
				NULL, HFILL
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
				NULL, HFILL
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
				NULL, HFILL
			}
		},
		{
			&hf_rtp_csrc_items,
			{
				"Contributing Source identifiers",
				"rtp.csrc.items",
				FT_NONE,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_csrc_item,
			{
				"CSRC item",
				"rtp.csrc.item",
				FT_UINT32,
				BASE_HEX_DEC,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_hdr_exts,
			{
				"Header extensions",
				"rtp.hdr_exts",
				FT_NONE,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
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
				NULL, HFILL
			}
		},
		{
			&hf_rtp_data,
			{
				"Payload",
				"rtp.payload",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_padding_data,
			{
				"Padding data",
				"rtp.padding.data",
				FT_BYTES,
				BASE_NONE,
				NULL,
				0x0,
				NULL, HFILL
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
				NULL, HFILL
			}
		},
		{
			&hf_rtp_setup,
			{
				"Stream setup",
				"rtp.setup",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"Stream setup, method and frame number", HFILL
			}
		},
		{
			&hf_rtp_setup_frame,
			{
				"Setup frame",
				"rtp.setup-frame",
				FT_FRAMENUM,
				BASE_NONE,
				NULL,
				0x0,
				"Frame that set up this stream", HFILL
			}
		},
		{
			&hf_rtp_setup_method,
			{
				"Setup Method",
				"rtp.setup-method",
				FT_STRING,
				BASE_NONE,
				NULL,
				0x0,
				"Method used to set up this stream", HFILL
			}
		},
		{
			&hf_rtp_rfc2198_follow,
			{
				"Follow",
				"rtp.follow",
				FT_BOOLEAN,
				8,
				TFS(&tfs_set_notset),
				0x80,
				"Next header follows", HFILL
			}
		},
		{
			&hf_rtp_rfc2198_tm_off,
			{
				"Timestamp offset",
				"rtp.timestamp-offset",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0xFFFC,
				NULL, HFILL
			}
		},
		{
			&hf_rtp_rfc2198_bl_len,
			{
				"Block length",
				"rtp.block-length",
				FT_UINT16,
				BASE_DEC,
				NULL,
				0x03FF,
				NULL, HFILL
			}
		},

		/* reassembly stuff */
		{&hf_rtp_fragments,
		 {"RTP Fragments", "rtp.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }
		},

		{&hf_rtp_fragment,
		 {"RTP Fragment data", "rtp.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }
		},

		{&hf_rtp_fragment_overlap,
		 {"Fragment overlap", "rtp.fragment.overlap", FT_BOOLEAN, BASE_NONE,
		  NULL, 0x0, "Fragment overlaps with other fragments", HFILL }
		},

		{&hf_rtp_fragment_overlap_conflict,
		 {"Conflicting data in fragment overlap", "rtp.fragment.overlap.conflict",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Overlapping fragments contained conflicting data", HFILL }
		},

		{&hf_rtp_fragment_multiple_tails,
		 {"Multiple tail fragments found", "rtp.fragment.multipletails",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Several tails were found when defragmenting the packet", HFILL }
		},

		{&hf_rtp_fragment_too_long_fragment,
		 {"Fragment too long", "rtp.fragment.toolongfragment",
		  FT_BOOLEAN, BASE_NONE, NULL, 0x0,
		  "Fragment contained data past end of packet", HFILL }
		},

		{&hf_rtp_fragment_error,
		 {"Defragmentation error", "rtp.fragment.error",
		  FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		  "Defragmentation error due to illegal fragments", HFILL }
		},

		{&hf_rtp_fragment_count,
		 {"Fragment count", "rtp.fragment.count",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  NULL, HFILL }
		},

		{&hf_rtp_reassembled_in,
		 {"RTP fragment, reassembled in frame", "rtp.reassembled_in",
		  FT_FRAMENUM, BASE_NONE, NULL, 0x0,
		  "This RTP packet is reassembled in this frame", HFILL }
		},
		{&hf_rtp_reassembled_length,
		 {"Reassembled RTP length", "rtp.reassembled.length",
		  FT_UINT32, BASE_DEC, NULL, 0x0,
		  "The total length of the reassembled payload", HFILL }
		},
		{&hf_srtp_encrypted_payload,
		 {"SRTP Encrypted Payload", "srtp.enc_payload",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  NULL, HFILL }
		},
		{&hf_srtp_mki,
		 {"SRTP MKI", "srtp.mki",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "SRTP Master Key Index", HFILL }
		},
		{&hf_srtp_auth_tag,
		 {"SRTP Auth Tag", "srtp.auth_tag",
		  FT_BYTES, BASE_NONE, NULL, 0x0,
		  "SRTP Authentication Tag", HFILL }
		}

	};

	static gint *ett[] =
	{
		&ett_rtp,
		&ett_csrc_list,
		&ett_hdr_ext,
		&ett_rtp_setup,
		&ett_rtp_rfc2198,
		&ett_rtp_rfc2198_hdr,
		&ett_rtp_fragment,
		&ett_rtp_fragments
	};

	module_t *rtp_module;


	proto_rtp = proto_register_protocol("Real-Time Transport Protocol",
					    "RTP", "rtp");
	proto_register_field_array(proto_rtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));

	register_dissector("rtp", dissect_rtp, proto_rtp);
	register_dissector("rtp.rfc2198", dissect_rtp_rfc2198, proto_rtp);

	rtp_tap = register_tap("rtp");

	rtp_pt_dissector_table = register_dissector_table("rtp.pt",
	                                                  "RTP payload type", FT_UINT8, BASE_DEC);
	rtp_dyn_pt_dissector_table = register_dissector_table("rtp_dyn_payload_type",
							      "Dynamic RTP payload type", FT_STRING, BASE_NONE);


	rtp_hdr_ext_dissector_table = register_dissector_table("rtp_hdr_ext",
	                               "RTP header extension", FT_UINT32, BASE_HEX);

	rtp_module = prefs_register_protocol(proto_rtp, proto_reg_handoff_rtp);

	prefs_register_bool_preference(rtp_module, "show_setup_info",
	                               "Show stream setup information",
	                               "Where available, show which protocol and frame caused "
	                               "this RTP stream to be created",
	                               &global_rtp_show_setup_info);

	prefs_register_bool_preference(rtp_module, "heuristic_rtp",
	                               "Try to decode RTP outside of conversations",
	                               "If call control SIP/H323/RTSP/.. messages are missing in the trace, "
	                               "RTP isn't decoded without this",
	                               &global_rtp_heur);

	prefs_register_bool_preference(rtp_module, "desegment_rtp_streams",
				       "Allow subdissector to reassemble RTP streams",
				       "Whether subdissector can request RTP streams to be reassembled",
				       &desegment_rtp);

	prefs_register_enum_preference(rtp_module, "version0_type",
	                               "Treat RTP version 0 packets as",
	                               "If an RTP version 0 packet is encountered, it can be treated as "
				       "an invalid or ZRTP packet, a CLASSIC-STUN packet, or a T.38 packet",
	                               &global_rtp_version0_type,
	                               rtp_version0_types, FALSE);
	prefs_register_uint_preference(rtp_module,
				       "rfc2198_payload_type", "Payload Type for RFC2198",
				       "Payload Type for RFC2198 Redundant Audio Data",
				       10,
				       &rtp_rfc2198_pt);

	register_init_routine(rtp_fragment_init);
}

void
proto_reg_handoff_rtp(void)
{
	static gboolean rtp_prefs_initialized = FALSE;
	static dissector_handle_t rtp_rfc2198_handle;
	static guint rtp_saved_rfc2198_pt;

	if (!rtp_prefs_initialized) {
		rtp_handle = find_dissector("rtp");
		rtp_rfc2198_handle = find_dissector("rtp.rfc2198");

		dissector_add_handle("udp.port", rtp_handle);  /* for 'decode-as' */
		dissector_add_string("rtp_dyn_payload_type", "red", rtp_rfc2198_handle);
		heur_dissector_add( "udp", dissect_rtp_heur_udp,  proto_rtp);
		heur_dissector_add("stun", dissect_rtp_heur_stun, proto_rtp);

		data_handle = find_dissector("data");
		classicstun_handle = find_dissector("classicstun");
		classicstun_heur_handle = find_dissector("classicstun-heur");
		t38_handle = find_dissector("t38");
		zrtp_handle = find_dissector("zrtp");

		rtp_prefs_initialized = TRUE;
	} else {
		dissector_delete_uint("rtp.pt", rtp_saved_rfc2198_pt, rtp_rfc2198_handle);
	}
	dissector_add_uint("rtp.pt", rtp_rfc2198_pt, rtp_rfc2198_handle);
	rtp_saved_rfc2198_pt = rtp_rfc2198_pt;
}

/*
 * Local Variables:
 * c-basic-offset: 8
 * indent-tabs-mode: t
 * tab-width: 8
 * End:
 */
