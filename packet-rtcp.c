/* packet-rtcp.c
 * Routines for RTCP packet disassembly
 *
 * Jason Lango <jal@netapp.com>
 *
 * $Id: packet-rtcp.c,v 1.2 2000/05/11 08:15:42 gram Exp $
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
 *
 *
 */

#include "config.h"

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include <string.h>
#include <ctype.h>

#include <glib.h>
#include "packet.h"
#include "packet-rtcp.h"

static int proto_rtcp = -1;

static gint ett_rtcp = -1;

#define _RTCP_FLAG_BITS(hdr, s, n) \
	((u_int)(((hdr)->rtcp_flag_bits >> (8 - (s) - (n))) & ((1 << (n)) - 1)))
#define RTCP_VERSION(hdr)	_RTCP_FLAG_BITS(hdr, 0, 2)
#define RTCP_PADDING(hdr)	_RTCP_FLAG_BITS(hdr, 2, 1)
#define RTCP_COUNT(hdr)		_RTCP_FLAG_BITS(hdr, 3, 5)

#define RTCP_TYPE_SR		200	/* Sender Report */
#define RTCP_TYPE_RR		201	/* Receiver Report */
#define RTCP_TYPE_SDES		202	/* Source Description */
#define RTCP_TYPE_BYE		203	/* Goodbye */
#define RTCP_TYPE_APP		204	/* Application-defined */

typedef struct rtcp_hdr {
	guint8	rtcp_flag_bits;
	guint8	rtcp_type;		/* packet type */
	guint16	rtcp_length;		/* length in 32 bit words minus 1 */
} rtcp_hdr_t;

typedef struct rtcp_report {
	guint32	rtcp_rr_ssrc;		/* SSRC of source */
	guint8	rtcp_rr_flt;		/* fraction lost */
	guint8	rtcp_rr_cplthi;		/* hi-byte of cplt */
	guint16	rtcp_rr_cplt;		/* cumulative packets lost */
	guint32	rtcp_rr_xhiseq;		/* extended highest seq num rcvd */
	guint32	rtcp_rr_jitter;		/* interarrival jitter */
	guint32	rtcp_rr_lsr;		/* middle bits of last SR timestamp */
	guint32	rtcp_rr_dlsr;		/* delay since last SR */
} rtcp_report_t;

static int
dissect_rtcp_report(rtcp_hdr_t *hdr, int sn, const u_char *pd, int offset,
	int start_packet, int end_packet, proto_tree *rtcp_tree)
{
	int		end_offset = offset + END_OF_FRAME;
	rtcp_report_t	rep;

	if (offset >= end_offset)
		return -1;

	memcpy(&rep, &pd[offset], sizeof(rtcp_report_t) <= END_OF_FRAME ?
		sizeof(rtcp_report_t) : END_OF_FRAME);

	rep.rtcp_rr_ssrc = ntohl(rep.rtcp_rr_ssrc);
	rep.rtcp_rr_cplt = ntohs(rep.rtcp_rr_cplt);
	rep.rtcp_rr_xhiseq = ntohl(rep.rtcp_rr_xhiseq);
	rep.rtcp_rr_jitter = ntohl(rep.rtcp_rr_jitter);
	rep.rtcp_rr_lsr = ntohl(rep.rtcp_rr_lsr);
	rep.rtcp_rr_dlsr = ntohl(rep.rtcp_rr_dlsr);

	if ((offset + sizeof(rtcp_report_t)) > end_offset) {
		proto_tree_add_text(rtcp_tree, NullTVB, offset, 0,
			"Warning: Bad packet length -- "
			"data might be incorrect");
	}

	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4,
		"Source %d SSRC: %u", sn + 1, rep.rtcp_rr_ssrc);
	offset += 4;

	proto_tree_add_text(rtcp_tree, NullTVB, offset, 1,
		"Fraction lost: %u / 256", (unsigned) rep.rtcp_rr_flt);
	offset += 1;

	proto_tree_add_text(rtcp_tree, NullTVB, offset, 3,
		"Cumulative Packets Lost: %lu",
		(((unsigned long) rep.rtcp_rr_cplthi) << 16) +
		(unsigned long) rep.rtcp_rr_cplt);
	offset += 3;

	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4,
		"Extended Highest Seq #: %lu",
		(unsigned long) rep.rtcp_rr_xhiseq);
	offset += 4;

	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4,
		"Jitter: %lu", (unsigned long) rep.rtcp_rr_jitter);
	offset += 4;

	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4,
		"Last SR timestamp (middle): %lu",
		(unsigned long) rep.rtcp_rr_lsr);
	offset += 4;

	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4,
		"Delay Since Last SR: %lu",
		(unsigned long) rep.rtcp_rr_dlsr);
	offset += 4;

	return offset;
}

typedef struct rtcp_rr {
	guint32	rtcp_rr_ssrc;
} rtcp_rr_t;

static int
dissect_rtcp_rr(rtcp_hdr_t *hdr, const u_char *pd, int offset,
	int start_packet, int end_packet, proto_tree *rtcp_tree)
{
	int		end_offset = offset + END_OF_FRAME; 
	rtcp_rr_t	rr;
	int		sn;

	memcpy(&rr, &pd[offset], sizeof(rtcp_rr_t) < END_OF_FRAME ?
		sizeof(rtcp_rr_t) : END_OF_FRAME);
	rr.rtcp_rr_ssrc = ntohl(rr.rtcp_rr_ssrc);

	if ((offset + sizeof(rtcp_rr_t)) >= end_offset)
		return -1;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4, "Sender SSRC: %u",
		rr.rtcp_rr_ssrc);
	offset += 4;

	for (sn = 0; sn < RTCP_COUNT(hdr); sn++) {
		offset = dissect_rtcp_report(hdr, sn, pd, offset, start_packet,
			end_packet, rtcp_tree);
	}

	return offset;
}

typedef struct rtcp_sr {
	guint32	rtcp_sr_ssrc;
	guint32	rtcp_sr_ntp_hi;		/* MSW of NTP timestamp */
	guint32	rtcp_sr_ntp_lo;		/* LSW of NTP timestamp */
	guint32	rtcp_sr_rtp_time;	/* RTP timestamp */
	guint32	rtcp_sr_npackets;	/* sender's packet count */
	guint32	rtcp_sr_nbytes;		/* sender's octet count */
} rtcp_sr_t;

static int
dissect_rtcp_sr(rtcp_hdr_t *hdr, const u_char *pd, int offset,
	int start_packet, int end_packet, proto_tree *rtcp_tree)
{
	int		end_offset = offset + END_OF_FRAME; 
	rtcp_sr_t	sr;
	int		sn;

	memcpy(&sr, &pd[offset], sizeof(rtcp_sr_t) < END_OF_FRAME ?
		sizeof(rtcp_sr_t) : END_OF_FRAME);
	sr.rtcp_sr_ssrc = ntohl(sr.rtcp_sr_ssrc);
	sr.rtcp_sr_ntp_hi = ntohl(sr.rtcp_sr_ntp_hi);
	sr.rtcp_sr_ntp_lo = ntohl(sr.rtcp_sr_ntp_lo);
	sr.rtcp_sr_rtp_time = ntohl(sr.rtcp_sr_rtp_time);
	sr.rtcp_sr_npackets = ntohl(sr.rtcp_sr_npackets);
	sr.rtcp_sr_nbytes = ntohl(sr.rtcp_sr_nbytes);

	if ((offset + sizeof(rtcp_sr_t)) > end_offset) {
		proto_tree_add_text(rtcp_tree, NullTVB, offset, 0,
			"Warning: Bad packet length -- "
			"data might be incorrect");
	}

	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4, "Sender's SSRC: %u",
		sr.rtcp_sr_ssrc);
	offset += 4;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4, "NTP timestamp, MSW: %u",
		sr.rtcp_sr_ntp_hi);
	offset += 4;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4, "NTP timestamp, LSW: %u",
		sr.rtcp_sr_ntp_lo);
	offset += 4;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4, "RTP timestamp: %u",
		sr.rtcp_sr_rtp_time);
	offset += 4;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4, "Sender's packet count: %u",
		sr.rtcp_sr_npackets);
	offset += 4;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4, "Sender's octet count: %u",
		sr.rtcp_sr_nbytes);
	offset += 4;

	for (sn = 0; sn < RTCP_COUNT(hdr); sn++) {
		offset = dissect_rtcp_report(hdr, sn, pd, offset, start_packet,
			end_packet, rtcp_tree);
	}

	return offset;
}

static struct rtcp_chunk_type {
	int		type;
	const char	*name;
} rtcp_chunk_types[] = {
	{ 1, "CNAME (user and domain)" },
	{ 2, "NAME (common name)" },
	{ 3, "EMAIL (e-mail address)" },
	{ 4, "PHONE (phone number)" },
	{ 5, "LOC (geographic location)" },
	{ 6, "TOOL (name/version of source app)" },
	{ 7, "NOTE (note about source)" },
	{ 8, "PRIV (private extensions)" },
	{ 0, 0 }
};

static struct rtcp_chunk_type *
rtcp_find_chunk_type(int type)
{
	struct rtcp_chunk_type *tt = rtcp_chunk_types;
	static struct rtcp_chunk_type unk = { 0, "UNKNOWN" };
	for (; tt->type; tt++) {
		if (type == tt->type)
			return tt;
	}
	return &unk;
}

static int
dissect_rtcp_sdes_chunk(rtcp_hdr_t *hdr, int cn, const u_char *pd, int offset,
	int start_packet, int end_packet, proto_tree *rtcp_tree)
{
	unsigned	type;
	unsigned	len;
	struct rtcp_chunk_type *ctype;

	if ((offset + 4) > end_packet)
		return -1;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 4, "Chunk %d SSRC: %u",
		cn + 1, pntohl(&pd[offset]));
	offset += 4;

	for (;;) {
		if ((offset + 1) > end_packet)
			return -1;

		type = pd[offset];
		if (type == 0) {
			int pad_start = offset;
			offset++;
			/* NULL terminator -- align to next 32 bit boundary */
			if ((offset - start_packet) & 3) {
				offset += 4 - ((offset - start_packet) & 3);
			}
			proto_tree_add_text(rtcp_tree, NullTVB, pad_start,
				offset - pad_start,
				"(end of chunk and alignment padding)");
			break;
		}

		ctype = rtcp_find_chunk_type(type);

		proto_tree_add_text(rtcp_tree, NullTVB, offset, 1, "Chunk type: %s",
			ctype->name);
		offset++;

		if ((offset + 1) > end_packet)
			return -1;

		len = pd[offset];
		proto_tree_add_text(rtcp_tree, NullTVB, offset, 1, "Chunk length: %u",
			(unsigned) len);
		offset++;

		if ((offset + len) > end_packet)
			return -1;

		proto_tree_add_text(rtcp_tree, NullTVB, offset, len, "Chunk string: %s",
			format_text(&pd[offset], len));
		offset += len;
	}
	return offset;
}

static int
dissect_rtcp_sdes(rtcp_hdr_t *hdr, const u_char *pd, int offset,
	int start_packet, int end_packet, proto_tree *rtcp_tree)
{
	int		cn;

	for (cn = 0; cn < RTCP_COUNT(hdr); cn++) {
		offset = dissect_rtcp_sdes_chunk(hdr, cn, pd, offset,
			start_packet, end_packet, rtcp_tree);
	}
	return offset;
}

static int
dissect_one_rtcp(const u_char *pd, int offset, frame_data *fd,
	proto_tree *tree)
{
	proto_tree	*rtcp_tree;
	proto_item	*ti;
	const u_char	*data, *dataend;
	int		end_offset;
	int		start_packet;
	int		end_packet;
	rtcp_hdr_t	hdr;
	const char	*ptype;

	data = &pd[offset];
	dataend = data + END_OF_FRAME;
	start_packet = offset;
	end_offset = offset + END_OF_FRAME;

	ti = proto_tree_add_item(tree, proto_rtcp, NullTVB, offset, END_OF_FRAME, NULL);
	rtcp_tree = proto_item_add_subtree(ti, ett_rtcp);

	memcpy(&hdr, data, END_OF_FRAME < sizeof(rtcp_hdr_t) ?
		END_OF_FRAME : sizeof(rtcp_hdr_t));
	hdr.rtcp_length = ntohs(hdr.rtcp_length);

	if (offset >= end_offset)
		return -1;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 1, "Version: %u (%s)",
		RTCP_VERSION(&hdr),
		RTCP_VERSION(&hdr) == 3 ? "New Unknown Version" :
		RTCP_VERSION(&hdr) == 2 ? "RFC 1889 Version" :
		RTCP_VERSION(&hdr) == 1 ? "First Draft Version" :
		"Old Vat Version");
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 1, "Padding: %u",
		RTCP_PADDING(&hdr));
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 1, "Count: %u",
		RTCP_COUNT(&hdr));
	offset++;

	if (offset >= end_offset)
		return -1;
	switch (hdr.rtcp_type) {
	case RTCP_TYPE_SR:	ptype = "SR: Sender Report"; break;
	case RTCP_TYPE_RR:	ptype = "RR: Receiver Report"; break;
	case RTCP_TYPE_SDES:	ptype =	"SDES: Source Description"; break;
	case RTCP_TYPE_BYE:	ptype = "BYE: Goodbye"; break;
	case RTCP_TYPE_APP:	ptype = "APP: Application-defined"; break;
	default:		ptype = "Unknown"; break;
	}
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 1, "Type: %u (%s)",
		(u_int) hdr.rtcp_type, ptype);
	offset++;

	if (offset >= end_offset)
		return -1;
	proto_tree_add_text(rtcp_tree, NullTVB, offset, 2, "Length / 4 - 1: %u",
		(unsigned) hdr.rtcp_length);
	offset += 2;

	/*
	 * Don't add 1 to length, since it's accounted for above.
	 */
	end_packet = offset + hdr.rtcp_length * 4;

	switch (hdr.rtcp_type) {
	case RTCP_TYPE_RR:
		offset = dissect_rtcp_rr(&hdr, pd, offset, start_packet,
			end_packet, rtcp_tree);
		break;
	case RTCP_TYPE_SR:
		offset = dissect_rtcp_sr(&hdr, pd, offset, start_packet,
			end_packet, rtcp_tree);
		break;
	case RTCP_TYPE_SDES:
		offset = dissect_rtcp_sdes(&hdr, pd, offset, start_packet,
			end_packet, rtcp_tree);
		break;
	default:
		proto_tree_add_text(rtcp_tree, NullTVB, offset, END_OF_FRAME,
			"TYPE NOT HANDLED YET");
		offset = end_packet;
		break;
	}

	if (offset > 0 && offset < end_packet) {
		proto_tree_add_text(rtcp_tree, NullTVB, offset, end_packet - offset,
			"Extra data (%d bytes)", end_packet - offset);
	}
	if (offset < 0)
		return offset;
	return end_packet;
}

void
dissect_rtcp(const u_char *pd, int offset, frame_data *fd, proto_tree *tree)
{
	int		end_offset;

	if (check_col(fd, COL_PROTOCOL))
		col_add_str(fd, COL_PROTOCOL, "RTCP");

	if (!tree)
		return;

	end_offset = offset + END_OF_FRAME;
	while (offset > 0 && offset < end_offset) {
		offset = dissect_one_rtcp(pd, offset, fd, tree);
	}
	if (offset < 0) {
		proto_tree_add_text(tree, NullTVB, end_offset, 0,
			"Unexpected end of packet");
	}
}

void
proto_register_rtcp(void)
{
/*        static hf_register_info hf[] = {
                { &variable,
                { "Name",           "rtcp.abbreviation", TYPE, VALS_POINTER }},
        };*/
	static gint *ett[] = {
		&ett_rtcp,
	};

	proto_rtcp = proto_register_protocol("RTP Control Protocol", "rtcp");
 /*       proto_register_field_array(proto_rtcp, hf, array_length(hf));*/
	proto_register_subtree_array(ett, array_length(ett));
}
