/* packet-rtp.c
 *
 * Routines for RTP dissection
 * RTP = Real time Transport Protocol
 *
 * Copyright 2000, Philips Electronics N.V.
 * Written by Andreas Sikkema <andreas.sikkema@philips.com>
 *
 * $Id: packet-rtp.c,v 1.39 2003/05/20 21:22:58 guy Exp $
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
 */


#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>

#include <stdio.h>
#include <string.h>

#include "packet-rtp.h"
#include <epan/conversation.h>
#include "tap.h"

static int rtp_tap = -1;

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

static dissector_handle_t h261_handle;
static dissector_handle_t mpeg1_handle;
static dissector_handle_t data_handle;

static gboolean dissect_rtp_heur( tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree );
static void dissect_rtp( tvbuff_t *tvb, packet_info *pinfo,
    proto_tree *tree );

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
 * Also RFC 1890, and
 *
 *	http://www.iana.org/assignments/rtp-parameters
 */
#define PT_PCMU		0	/* RFC 1890 */
#define PT_1016		1	/* RFC 1890 */
#define PT_G721		2	/* RFC 1890 */
#define PT_GSM		3	/* RFC 1890 */
#define PT_G723		4	/* From Vineet Kumar of Intel; see the Web page */
#define PT_DVI4_8000	5	/* RFC 1890 */
#define PT_DVI4_16000	6	/* RFC 1890 */
#define PT_LPC		7	/* RFC 1890 */
#define PT_PCMA		8	/* RFC 1890 */
#define PT_G722		9	/* RFC 1890 */
#define PT_L16_STEREO	10	/* RFC 1890 */
#define PT_L16_MONO	11	/* RFC 1890 */
#define PT_QCELP	12	/* Qualcomm Code Excited Linear Predictive coding? */
#define PT_CN		13	/* RFC 3389 */
#define PT_MPA		14	/* RFC 1890, RFC 2250 */
#define PT_G728		15	/* RFC 1890 */
#define PT_DVI4_11025	16	/* from Joseph Di Pol of Sun; see the Web page */
#define PT_DVI4_22050	17	/* from Joseph Di Pol of Sun; see the Web page */
#define PT_G729		18
#define PT_CELB		25	/* RFC 2029 */
#define PT_JPEG		26	/* RFC 2435 */
#define PT_NV		28	/* RFC 1890 */
#define PT_H261		31	/* RFC 2032 */
#define PT_MPV		32	/* RFC 2250 */
#define PT_MP2T		33	/* RFC 2250 */
#define PT_H263		34	/* from Chunrong Zhu of Intel; see the Web page */

static const value_string rtp_payload_type_vals[] =
{
	{ PT_PCMU,	"ITU-T G.711 PCMU" },
	{ PT_1016,	"USA Federal Standard FS-1016" },
	{ PT_G721,	"ITU-T G.721" },
	{ PT_GSM,	"GSM 06.10" },
	{ PT_G723,	"ITU-T G.723" },
	{ PT_DVI4_8000,	"DVI4 8000 samples/s" },
	{ PT_DVI4_16000, "DVI4 16000 samples/s" },
	{ PT_LPC,	"Experimental linear predictive encoding from Xerox PARC" },
	{ PT_PCMA,	"ITU-T G.711 PCMA" },
	{ PT_G722,	"ITU-T G.722" },
	{ PT_L16_STEREO, "16-bit uncompressed audio, stereo" },
	{ PT_L16_MONO,	"16-bit uncompressed audio, monaural" },
	{ PT_QCELP,	"Qualcomm Code Excited Linear Predictive coding" },
	{ PT_CN,	"Comfort noise" },
	{ PT_MPA,	"MPEG-I/II Audio"},
	{ PT_G728,	"ITU-T G.728" },
	{ PT_DVI4_11025, "DVI4 11025 samples/s" },
	{ PT_DVI4_22050, "DVI4 22050 samples/s" },
	{ PT_G729,	"ITU-T G.729" },
	{ PT_CELB,	"Sun CellB video encoding" },
	{ PT_JPEG,	"JPEG-compressed video" },
	{ PT_NV,	"'nv' program" },
	{ PT_H261,	"ITU-T H.261" },
	{ PT_MPV,	"MPEG-I/II Video"},
	{ PT_MP2T,	"MPEG-II transport streams"},
	{ PT_H263,	"ITU-T H.263" },
	{ 0,		NULL },
};

static address fake_addr;
static int heur_init = FALSE;

void rtp_add_address( packet_info *pinfo, const unsigned char* ip_addr,
    int prt )
{
	address src_addr;
	conversation_t* pconv;

	/*
	 * If this isn't the first time this packet has been processed,
	 * we've already done this work, so we don't need to do it
	 * again.
	 */
	if (pinfo->fd->flags.visited)
		return;

	src_addr.type = AT_IPv4;
	src_addr.len = 4;
	src_addr.data = ip_addr;

	/*
	 * The first time the function is called let the tcp dissector
	 * know that we're interested in traffic
	 */
	if ( ! heur_init ) {
		heur_dissector_add( "udp", dissect_rtp_heur, proto_rtp );
		heur_init = TRUE;
	}

	/*
	 * Check if the ip address an dport combination is not
	 * already registered
	 */
	pconv = find_conversation( &src_addr, &fake_addr, PT_UDP, prt, 0, 0 );

	/*
	 * If not, add
	 * XXX - use wildcard address and port B?
	 */
	if ( ! pconv ) {
		pconv = conversation_new( &src_addr, &fake_addr, PT_UDP,
		    (guint32) prt, (guint32) 0, 0 );
		conversation_add_proto_data(pconv, proto_rtp, NULL);
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

static gboolean
dissect_rtp_heur( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree )
{
	conversation_t* pconv;

	/* This is a heuristic dissector, which means we get all the TCP
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
	 * An RTP conversation always has a data item for RTP.
	 * (Its existence is sufficient to indicate that this is an RTP
	 * conversation.)
	 */
	if (conversation_get_proto_data(pconv, proto_rtp) == NULL)
		return FALSE;

	dissect_rtp( tvb, pinfo, tree );

	return TRUE;
}

static void
dissect_rtp_data( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    proto_tree *rtp_tree, int offset, unsigned int data_len,
    unsigned int data_reported_len, unsigned int payload_type )
{
	tvbuff_t *newtvb;

	switch( payload_type ) {
		case PT_H261:
			newtvb = tvb_new_subset( tvb, offset, data_len,
			    data_reported_len );
			call_dissector(h261_handle, newtvb, pinfo, tree);
			break;

		case PT_MPV:
			newtvb = tvb_new_subset( tvb, offset, data_len,
			    data_reported_len );
			call_dissector(mpeg1_handle, newtvb, pinfo, tree);
			break;

		default:
			proto_tree_add_item( rtp_tree, hf_rtp_data, tvb, offset, data_len, FALSE );
			break;
	}
}

static void
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
	unsigned int padding_count;
	int         data_len;
	unsigned int offset = 0;
	guint16     seq_num;
	guint32     timestamp;
	guint32     sync_src;
	guint32     csrc_item;

	static struct _rtp_info rtp_info;

	/* Get the fields in the first octet */
	octet = tvb_get_guint8( tvb, offset );
	version = RTP_VERSION( octet );

	if (version != 2) {
		/*
		 * Unknown or unsupported version.
		 */
		if ( check_col( pinfo->cinfo, COL_PROTOCOL ) )   {
			col_set_str( pinfo->cinfo, COL_PROTOCOL, "RTP" );
		}

		if ( check_col( pinfo->cinfo, COL_INFO) ) {
			col_add_fstr( pinfo->cinfo, COL_INFO,
			    "Unknown RTP version %u", version);
		}

		if ( tree ) {
			ti = proto_tree_add_item( tree, proto_rtp, tvb, offset, -1, FALSE );
			rtp_tree = proto_item_add_subtree( ti, ett_rtp );

			proto_tree_add_uint( rtp_tree, hf_rtp_version, tvb,
			    offset, 1, version );
		}
		return;
	}

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

	/* fill in the rtp_info structure */ 
	rtp_info.info_padding_set = padding_set;
	rtp_info.info_padding_count = 0;
	rtp_info.info_marker_set = marker_set;
	rtp_info.info_payload_type = payload_type;
	rtp_info.info_seq_num = seq_num;
	rtp_info.info_timestamp = timestamp;
	rtp_info.info_sync_src = sync_src;
	rtp_info.info_data_len = tvb_reported_length_remaining( tvb, offset );

	if ( check_col( pinfo->cinfo, COL_PROTOCOL ) )   {
		col_set_str( pinfo->cinfo, COL_PROTOCOL, "RTP" );
	}

	if ( check_col( pinfo->cinfo, COL_INFO) ) {
		col_add_fstr( pinfo->cinfo, COL_INFO,
		    "Payload type=%s, SSRC=%u, Seq=%u, Time=%u%s",
		    val_to_str( payload_type, rtp_payload_type_vals,
		        "Unknown (%u)" ),
		    sync_src,
		    seq_num,
		    timestamp,
		    marker_set ? ", Mark" : "");
	}
	if ( tree ) {
		ti = proto_tree_add_item( tree, proto_rtp, tvb, offset, -1, FALSE );
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
	} else {
		offset += 12;
	} 
	/* CSRC list*/
	if ( csrc_count > 0 ) {
        	if ( tree ) {
			ti = proto_tree_add_text(rtp_tree, tvb, offset, csrc_count * 4, "Contributing Source identifiers");
			rtp_csrc_tree = proto_item_add_subtree( ti, ett_csrc_list );
		}
		for (i = 0; i < csrc_count; i++ ) {
			csrc_item = tvb_get_ntohl( tvb, offset );
			if ( tree ) proto_tree_add_uint_format( rtp_csrc_tree,
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
		if ( tree ) proto_tree_add_uint( rtp_tree, hf_rtp_prof_define, tvb, offset, 2, tvb_get_ntohs( tvb, offset ) );
		offset += 2;

		hdr_extension = tvb_get_ntohs( tvb, offset );
		if ( tree ) proto_tree_add_uint( rtp_tree, hf_rtp_length, tvb,
		    offset, 2, hdr_extension);
		offset += 2;
		if ( hdr_extension > 0 ) {
			if ( tree ) { ti = proto_tree_add_text(rtp_tree, tvb, offset, csrc_count * 4, "Header extensions");
			/* I'm re-using the old tree variable here
			   from the CSRC list!*/
			rtp_csrc_tree = proto_item_add_subtree( ti,
			    ett_hdr_ext );
            }
			for (i = 0; i < hdr_extension; i++ ) {
				if ( tree ) proto_tree_add_uint( rtp_csrc_tree, hf_rtp_hdr_ext, tvb, offset, 4, tvb_get_ntohl( tvb, offset ) );
				offset += 4;
			}
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
			    tvb_new_subset(tvb, offset, -1, -1),
			    pinfo, rtp_tree);
			return;
		}

		padding_count = tvb_get_guint8( tvb,
		    tvb_reported_length( tvb ) - 1 );
		data_len =
		    tvb_reported_length_remaining( tvb, offset ) - padding_count;

		rtp_info.info_payload_offset = offset;
		rtp_info.info_payload_len = tvb_length_remaining(tvb, offset);
		rtp_info.info_padding_count = padding_count;

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
			    tvb, offset, padding_count - 1, FALSE );
			offset += padding_count - 1;
		}
		/*
		 * Show the last byte in the PDU as the padding
		 * count.
		 */
		if ( tree ) proto_tree_add_item( rtp_tree, hf_rtp_padding_count,
		    tvb, offset, 1, FALSE );
	}
	else {
		/*
		 * No padding.
		 */
		dissect_rtp_data( tvb, pinfo, tree, rtp_tree, offset,
		    tvb_length_remaining( tvb, offset ),
		    tvb_reported_length_remaining( tvb, offset ),
		    payload_type );
		rtp_info.info_payload_offset = offset;
		rtp_info.info_payload_len = tvb_length_remaining(tvb, offset);
	}
	tap_queue_packet(rtp_tap, pinfo, &rtp_info);
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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
				"", HFILL
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

	register_dissector("rtp", dissect_rtp, proto_rtp);
	rtp_tap = register_tap("rtp");

#if 0
	register_init_routine( &rtp_init );
#endif
}

void
proto_reg_handoff_rtp(void)
{
	dissector_handle_t rtp_handle;

	/*
	 * Get handles for the H.261 and MPEG-1 dissectors.
	 */
	h261_handle = find_dissector("h261");
	mpeg1_handle = find_dissector("mpeg1");
	data_handle = find_dissector("data");

	/*
	 * Register this dissector as one that can be selected by a
	 * UDP port number.
	 */
	rtp_handle = find_dissector("rtp");
	dissector_add_handle("udp.port", rtp_handle);
}
