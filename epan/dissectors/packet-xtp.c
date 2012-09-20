/* packet-xtp.c
 * Routines for Xpress Transport Protocol dissection
 * Copyright 2008, Shigeo Nakamura <naka_shigeo@yahoo.co.jp>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * Ref: http://www.packeteer.com/resources/prod-sol/XTP.pdf
 */

#include "config.h"

#include <glib.h>

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/ipproto.h>
#include <epan/in_cksum.h>


#define XTP_VERSION_4	0x001

/* XTP type of Service */
#define XTP_TOS_UNSPEC		0
#define XTP_TOS_UNACKED_DGRAM	1
#define	XTP_TOS_ACKED_DGRAM	2
#define	XTP_TOS_TRANS		3
#define	XTP_TOS_UNICAST_STREAM	4
#define	XTP_TOS_UNACKED_MULTICAST_STREAM 5
#define	XTP_TOS_MULTICAST_STREAM 6

/* Address Format */
#define XTP_ADDR_NULL		0
#define XTP_ADDR_IP		1
#define XTP_ADDR_ISO		2
#define XTP_ADDR_XEROX		3
#define XTP_ADDR_IPX		4
#define XTP_ADDR_LOCAL		5
#define XTP_ADDR_IP6		6

/* packet type */
#define XTP_DATA_PKT	0
#define XTP_CNTL_PKT	1
#define XTP_FIRST_PKT	2
#define XTP_ECNTL_PKT	3
#define XTP_TCNTL_PKT	5
#define XTP_JOIN_PKT	6
#define XTP_JCNTL_PKT	7
#define XTP_DIAG_PKT	8

/* cmd options mask */
#define XTP_CMD_OPTIONS_NOCHECK		0x400000
#define XTP_CMD_OPTIONS_EDGE		0x200000
#define XTP_CMD_OPTIONS_NOERR		0x100000
#define XTP_CMD_OPTIONS_MULTI		0x080000
#define XTP_CMD_OPTIONS_RES		0x040000
#define XTP_CMD_OPTIONS_SORT		0x020000
#define XTP_CMD_OPTIONS_NOFLOW		0x010000
#define XTP_CMD_OPTIONS_FASTNAK		0x008000
#define XTP_CMD_OPTIONS_SREQ		0x004000
#define XTP_CMD_OPTIONS_DREQ		0x002000
#define XTP_CMD_OPTIONS_RCLOSE		0x001000
#define XTP_CMD_OPTIONS_WCLOSE		0x000800
#define XTP_CMD_OPTIONS_EOM		0x000400
#define XTP_CMD_OPTIONS_END		0x000200
#define XTP_CMD_OPTIONS_BTAG		0x000100

#define XTP_KEY_RTN			((guint64)1<<63)

/** packet structures definition **/
struct xtp_cntl {
	guint64		rseq;
	guint64		alloc;
	guint32		echo;
};
#define XTP_CNTL_PKT_LEN	20

struct xtp_ecntl {
	guint64		rseq;
	guint64		alloc;
	guint32		echo;
	guint32		nspan;
};
#define MIN_XTP_ECNTL_PKT_LEN	24

struct xtp_traffic_cntl {
	guint64		rseq;
	guint64		alloc;
	guint32		echo;
	guint32		rsvd;
	guint64		xkey;
};
#define XTP_TRAFFIC_CNTL_LEN	32

/* tformat = 0x00 */
struct xtp_traffic_spec0 {
	guint16		tlen;
	guint8		service;
	guint8		tformat;
	guint32		none;
};
#define XTP_TRAFFIC_SPEC0_LEN	8

/* tformat = 0x01 */
struct xtp_traffic_spec1 {
	guint16		tlen;
	guint8		service;
	guint8		tformat;
	guint32		maxdata;
	guint32		inrate;
	guint32		inburst;
	guint32		outrate;
	guint32		outburst;
};
#define XTP_TRAFFIC_SPEC1_LEN	24

struct xtp_ip_addr_seg {
	guint16		alen;
	guint8		adomain;
	guint8		aformat;
	guint32		dsthost;
	guint32		srchost;
	guint16		dstport;
	guint16		srcport;
};
#define XTP_IP_ADDR_SEG_LEN	16
#define XTP_NULL_ADDR_SEG_LEN	8

struct xtp_diag {
	guint32		code;
	guint32		val;
	gchar		*msg;
};
#define XTP_DIAG_PKT_HEADER_LEN	8

struct xtphdr {
	guint64		key;
	guint32		cmd;
	guint32		cmd_options;		/* 24 bits */
	guint8		cmd_ptype;
	guint8		cmd_ptype_ver;		/* 3 bits */
	guint8		cmd_ptype_pformat;	/* 5 bits */
	guint32		dlen;
	guint16		check;
	guint16		sort;
	guint32		sync;
	guint64		seq;
};
#define XTP_HEADER_LEN		32


static const value_string version_vals[] = {
	{ XTP_VERSION_4, "XTP version 4.0" },
	{ 0, NULL }
};

static const value_string service_vals[] = {
	{ XTP_TOS_UNSPEC, "Unspecified" },
	{ XTP_TOS_UNACKED_DGRAM, "Traditional Unacknowledged Datagram Service" },
	{ XTP_TOS_ACKED_DGRAM, "Acknowledged Datagram Service" },
	{ XTP_TOS_TRANS, "Transaction Service" },
	{ XTP_TOS_UNICAST_STREAM, "Traditional Reliable Unicast Stream Service" },
	{ XTP_TOS_UNACKED_MULTICAST_STREAM, "Unacknowledged Multicast Stream Service" },
	{ XTP_TOS_MULTICAST_STREAM, "Reliable Multicast Stream Service" },
	{ 0, NULL }
};

static const value_string aformat_vals[] = {
	{ XTP_ADDR_NULL, "Null Address" },
	{ XTP_ADDR_IP, "Internet Protocol Address" },
	{ XTP_ADDR_ISO, "ISO Connectionless Network Layer Protocol Address" },
	{ XTP_ADDR_XEROX, "Xerox Network System Address" },
	{ XTP_ADDR_IPX, "IPX Address" },
	{ XTP_ADDR_LOCAL, "Local Address" },
	{ XTP_ADDR_IP6, "Internet Protocol Version 6 Address"  },
	{ 0, NULL }
};

static const value_string pformat_vals[] = {
	{ XTP_DATA_PKT, "DATA" },
	{ XTP_CNTL_PKT, "CNTL" },
	{ XTP_FIRST_PKT, "FIRST" },
	{ XTP_ECNTL_PKT, "ECNTL" },
	{ XTP_TCNTL_PKT, "TCNTL" },
	{ XTP_JOIN_PKT, "JOIN<obsolete>" },
	{ XTP_JCNTL_PKT, "JCNTL" },
	{ XTP_DIAG_PKT, "DIAG" },
	{ 0, NULL }
};

static const value_string diag_code_vals[] = {
	{ 1, "Context Refused" },
	{ 2, "Context Abandoned" },
	{ 3, "Invalid Context" },
	{ 4, "Request Refused" },
	{ 5, "Join Refused" },
	{ 6, "Protocol Error" },
	{ 7, "Maximum Packet Size Error" },
	{ 0, NULL }
};

static const value_string diag_val_vals[] = {
	{ 0, "Unspecified" },
	{ 1, "No listener" },
	{ 2, "Options refused" },
	{ 3, "Address format not supported" },
	{ 4, "Malformed address format" },
	{ 5, "Traffic format not supported" },
	{ 6, "Traffic specification refused" },
	{ 7, "Malformed traffic format" },
	{ 8, "No provider for service" },
	{ 9, "No resource" },
	{ 10, "Host going down" },
	{ 11, "Invalid retransmission request" },
	{ 12, "Context in improper state" },
	{ 13, "Join request denied" },
	{ 0, NULL }
};

/* Initialize the protocol and registered fields */
static int proto_xtp = -1;
/* common header */
static int hf_xtp_key = -1;
static int hf_xtp_cmd = -1;
static int hf_xtp_cmd_options = -1;
static int hf_xtp_cmd_options_nocheck = -1;
static int hf_xtp_cmd_options_edge = -1;
static int hf_xtp_cmd_options_noerr = -1;
static int hf_xtp_cmd_options_multi = -1;
static int hf_xtp_cmd_options_res = -1;
static int hf_xtp_cmd_options_sort = -1;
static int hf_xtp_cmd_options_noflow = -1;
static int hf_xtp_cmd_options_fastnak = -1;
static int hf_xtp_cmd_options_sreq = -1;
static int hf_xtp_cmd_options_dreq = -1;
static int hf_xtp_cmd_options_rclose = -1;
static int hf_xtp_cmd_options_wclose = -1;
static int hf_xtp_cmd_options_eom = -1;
static int hf_xtp_cmd_options_end = -1;
static int hf_xtp_cmd_options_btag = -1;
static int hf_xtp_cmd_ptype = -1;
static int hf_xtp_cmd_ptype_ver = -1;
static int hf_xtp_cmd_ptype_pformat = -1;
static int hf_xtp_dlen = -1;
static int hf_xtp_sort = -1;
static int hf_xtp_sync = -1;
static int hf_xtp_seq = -1;
/* control segment */
static int hf_xtp_cntl_rseq = -1;
static int hf_xtp_cntl_alloc = -1;
static int hf_xtp_cntl_echo = -1;
static int hf_xtp_ecntl_rseq = -1;
static int hf_xtp_ecntl_alloc = -1;
static int hf_xtp_ecntl_echo = -1;
static int hf_xtp_ecntl_nspan = -1;
static int hf_xtp_ecntl_span_left = -1;
static int hf_xtp_ecntl_span_right = -1;
static int hf_xtp_tcntl_rseq = -1;
static int hf_xtp_tcntl_alloc = -1;
static int hf_xtp_tcntl_echo = -1;
static int hf_xtp_tcntl_rsvd = -1;
static int hf_xtp_tcntl_xkey = -1;
/* traffic specifier */
static int hf_xtp_tspec_tlen = -1;
static int hf_xtp_tspec_service = -1;
static int hf_xtp_tspec_tformat = -1;
static int hf_xtp_tspec_traffic = -1;
static int hf_xtp_tspec_maxdata = -1;
static int hf_xtp_tspec_inrate = -1;
static int hf_xtp_tspec_outrate = -1;
static int hf_xtp_tspec_inburst = -1;
static int hf_xtp_tspec_outburst = -1;
/* address segment */
static int hf_xtp_aseg_alen = -1;
static int hf_xtp_aseg_adomain = -1;
static int hf_xtp_aseg_aformat = -1;
static int hf_xtp_aseg_address = -1;
static int hf_xtp_aseg_dsthost = -1;
static int hf_xtp_aseg_srchost = -1;
static int hf_xtp_aseg_dstport = -1;
static int hf_xtp_aseg_srcport = -1;
/* others */
static int hf_xtp_btag = -1;
static int hf_xtp_diag_code = -1;
static int hf_xtp_diag_val = -1;
static int hf_xtp_diag_msg = -1;

/* Initialize the subtree pointers */
static gint ett_xtp = -1;
static gint ett_xtp_cmd = -1;
static gint ett_xtp_cmd_options = -1;
static gint ett_xtp_cmd_ptype = -1;
static gint ett_xtp_cntl = -1;
static gint ett_xtp_ecntl = -1;
static gint ett_xtp_tcntl = -1;
static gint ett_xtp_tspec = -1;
static gint ett_xtp_jcntl = -1;
static gint ett_xtp_first = -1;
static gint ett_xtp_aseg = -1;
static gint ett_xtp_data = -1;
static gint ett_xtp_diag = -1;

/* dissector of each payload */
static int
dissect_xtp_aseg(tvbuff_t *tvb, proto_tree *tree, guint32 offset) {
	guint32 len = tvb_length_remaining(tvb, offset);
	guint32 start = offset;
	proto_item *ti, *ti2, *top_ti;
	proto_tree *xtp_subtree;
	struct xtp_ip_addr_seg aseg[1];
	int error = 0;

	top_ti = proto_tree_add_text(tree, tvb, offset, len, "Address Segment");
	xtp_subtree = proto_item_add_subtree(top_ti, ett_xtp_aseg);

	if (len < XTP_NULL_ADDR_SEG_LEN) {
		proto_item_append_text(top_ti, ", bogus length(%u, must be at least %u)",
			len, XTP_NULL_ADDR_SEG_LEN);
		return 0;
	}

	/** parse common fields **/
	/* alen(2) */
	aseg->alen = tvb_get_ntohs(tvb, offset);
	offset += 2;
	/* adomain(1) */
	aseg->adomain = tvb_get_guint8(tvb, offset);
	offset++;
	/* aformat(1) */
	aseg->aformat = tvb_get_guint8(tvb, offset);

	/** display common fields **/
	offset = start;
	/* alen(2) */
	ti = proto_tree_add_uint(xtp_subtree, hf_xtp_aseg_alen,
				tvb, offset, 2, aseg->alen);
	offset += 2;
	if (aseg->alen > len) {
		proto_item_append_text(ti, ", bogus length(%u, must be at most %u)",
			aseg->alen, len);
		error = 1;
	}
	/* adomain(1) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_aseg_adomain,
			tvb, offset, 1, aseg->adomain);
	offset++;
	/* aformat(1) */
	ti2 = proto_tree_add_uint(xtp_subtree, hf_xtp_aseg_aformat,
			tvb, offset, 1, aseg->aformat);
	offset++;
	switch (aseg->aformat) {
	case 0:
		if (aseg->alen != XTP_NULL_ADDR_SEG_LEN) {
			proto_item_append_text(ti, ", bogus length(%u, must be %u)",
				aseg->alen, XTP_NULL_ADDR_SEG_LEN);
			error = 1;
		}
		break;
	case 1:
		if (aseg->alen != XTP_IP_ADDR_SEG_LEN) {
			proto_item_append_text(ti, ", bogus length(%u, must be %u)",
				aseg->alen, XTP_IP_ADDR_SEG_LEN);
			error = 1;
		}
		break;
	default:
		if (aseg->aformat < 128) {
			proto_item_append_text(ti2,
				", Unsupported aformat(%u)", aseg->aformat);
			error = 1;
		}
		break;
	}

	if (error)
		return (offset - start);

	/** parse and display each address fileds */
	switch (aseg->aformat) {
	case 0:
		/* address(4) */
		aseg->dsthost = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_aseg_address,
				tvb, offset, 4, aseg->dsthost);
		offset += 4;
		break;
	case 1:
		/* dsthost(4) */
		aseg->dsthost = tvb_get_ipv4(tvb, offset);
		proto_tree_add_ipv4(xtp_subtree, hf_xtp_aseg_dsthost,
				tvb, offset, 4, aseg->dsthost);
		offset += 4;
		/* srchost(4) */
		aseg->srchost = tvb_get_ipv4(tvb, offset);
		proto_tree_add_ipv4(xtp_subtree, hf_xtp_aseg_srchost,
				tvb, offset, 4, aseg->srchost);
		offset += 4;
		/* dstport(2) */
		aseg->dstport = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_aseg_dstport,
				tvb, offset, 2, aseg->dstport);
		offset += 2;
		/* srcport(2) */
		aseg->srcport = tvb_get_ntohs(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_aseg_srcport,
				tvb, offset, 2, aseg->srcport);
		offset += 2;

		/** add summary **/
		proto_item_append_text(top_ti, ", Dst Port: %u", aseg->dstport);
		proto_item_append_text(top_ti, ", Src Port: %u", aseg->srcport);
		break;
	default:
		break;
	}

	return (offset - start);
}

static int
dissect_xtp_traffic_cntl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		guint32 offset) {
	guint32 len = tvb_length_remaining(tvb, offset);
	guint32 start = offset;
	proto_item *top_ti;
	proto_tree *xtp_subtree;
	struct xtp_traffic_cntl tcntl[1];

	top_ti = proto_tree_add_text(tree, tvb, offset, len,
				"Traffic Control Segment");
	xtp_subtree = proto_item_add_subtree(top_ti, ett_xtp_tcntl);

	if (len < XTP_TRAFFIC_CNTL_LEN) {
		proto_item_append_text(top_ti,
				", bogus length(%u, must be at least %u)",
				len, XTP_TRAFFIC_CNTL_LEN);
		return 0;
	}

	/** parse **/
	/* rseq(8) */
	tcntl->rseq = tvb_get_ntohl(tvb, offset);
	tcntl->rseq <<= 32;
	tcntl->rseq += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* alloc(8) */
	tcntl->alloc = tvb_get_ntohl(tvb, offset);
	tcntl->alloc <<= 32;
	tcntl->alloc += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* echo(4) */
	tcntl->echo = tvb_get_ntohl(tvb, offset);
	offset += 4;
	/* rsvd(4) */
	tcntl->rsvd = tvb_get_ntohl(tvb, offset);
	offset += 4;
	/* xkey(8) */
	tcntl->xkey = tvb_get_ntohl(tvb, offset);
	tcntl->xkey <<= 32;
	tcntl->xkey += tvb_get_ntohl(tvb, offset+4);

	/** add summary **/
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
			" Recv-Seq=%" G_GINT64_MODIFIER "u", tcntl->rseq);
		col_append_fstr(pinfo->cinfo, COL_INFO,
			" Alloc=%" G_GINT64_MODIFIER "u", tcntl->alloc);
	}
	proto_item_append_text(top_ti,
			", Recv-Seq: %" G_GINT64_MODIFIER "u", tcntl->rseq);

	/** display **/
	offset = start;
	/* rseq(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_tcntl_rseq,
			tvb, offset, 8, tcntl->rseq);
	offset += 8;
	/* alloc(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_tcntl_alloc,
			tvb, offset, 8, tcntl->alloc);
	offset += 4;
	/* echo(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_tcntl_echo,
			tvb, offset, 4, tcntl->echo);
	offset += 4;
	/* rsvd(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_tcntl_rsvd,
			tvb, offset, 4, tcntl->rsvd);
	offset += 4;
	/* xkey(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_tcntl_xkey,
			tvb, offset, 8, tcntl->xkey);
	offset += 8;

	return (offset - start);
}

static int
dissect_xtp_tspec(tvbuff_t *tvb, proto_tree *tree, guint32 offset) {
	guint32 len = tvb_length_remaining(tvb, offset);
	guint32 start = offset;
	proto_item *ti, *ti2;
	proto_tree *xtp_subtree;
	struct xtp_traffic_spec1 tspec[1];
	int error = 0;

	ti = proto_tree_add_text(tree, tvb, offset, len, "Traffic Specifier");
	xtp_subtree = proto_item_add_subtree(ti, ett_xtp_tspec);

	if (len < XTP_TRAFFIC_SPEC0_LEN) {
		proto_item_append_text(ti,
			", bogus length(%u, must be at least %u)",
			len, XTP_TRAFFIC_SPEC0_LEN);
		return 0;
	}

	/** parse common fields **/
	/* tlen(2) */
	tspec->tlen = tvb_get_ntohs(tvb, offset);
	offset += 2;
	/* service(1) */
	tspec->service = tvb_get_guint8(tvb, offset);
	offset++;
	/* tformat(1) */
	tspec->tformat = tvb_get_guint8(tvb, offset);

	/** display common fields */
	offset = start;
	/* tlen(2) */
	ti = proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_tlen,
			tvb, offset, 2, tspec->tlen);
	offset += 2;
	if (tspec->tlen > len) {
		proto_item_append_text(ti, ", bogus length(%u, must be at most %u)",
			tspec->tlen, len);
		error = 1;
	}
	/* service(1) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_service,
			tvb, offset, 1, tspec->service);
	offset++;
	/* tformat(1) */
	ti2 = proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_tformat,
			tvb, offset, 1, tspec->tformat);
	offset++;
	switch (tspec->tformat) {
	case 0:
		if (tspec->tlen != XTP_TRAFFIC_SPEC0_LEN) {
			proto_item_append_text(ti, ", bogus length(%u, must be %u)",
				tspec->tlen, XTP_TRAFFIC_SPEC0_LEN);
			error = 1;
		}
		break;
	case 1:
		if (tspec->tlen != XTP_TRAFFIC_SPEC1_LEN) {
			proto_item_append_text(ti, ", bogus length(%u, must be %u)",
				tspec->tlen, XTP_TRAFFIC_SPEC1_LEN);
			error = 1;
		}
		break;
	default:
		proto_item_append_text(ti2, ", Unsupported tformat(%u)",
				tspec->tformat);
		error = 1;
		break;
	}

	if (error)
		return (offset - start);

	/** parse and display each traffic fields **/
	switch (tspec->tformat) {
	case 0:
		/* traffic(4) */
		tspec->maxdata = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_traffic,
				tvb, offset, 4, tspec->maxdata);
		offset += 4;
		break;
	case 1:
		/* maxdata(4) */
		tspec->maxdata = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_maxdata,
				tvb, offset, 4, tspec->maxdata);
		offset += 4;
		/* inrate(4) */
		tspec->inrate = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_inrate,
				tvb, offset, 4, tspec->inrate);
		offset += 4;
		/* inburst(4) */
		tspec->inburst = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_inburst,
				tvb, offset, 4, tspec->inburst);
		offset += 4;
		/* outrate(4) */
		tspec->outrate = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_outrate,
				tvb, offset, 4, tspec->outrate);
		offset += 4;
		/* outburst(4) */
		tspec->outburst = tvb_get_ntohl(tvb, offset);
		proto_tree_add_uint(xtp_subtree, hf_xtp_tspec_outburst,
				tvb, offset, 4, tspec->outburst);
		offset += 4;
		break;
	default:
		break;
	}

	return (offset - start);
}

static void
dissect_xtp_data(tvbuff_t *tvb, proto_tree *tree, guint32 offset, gboolean have_btag) {
	guint32 len = tvb_length_remaining(tvb, offset);
	proto_item *ti;
	proto_tree *xtp_subtree;
	guint64 btag;

	ti = proto_tree_add_text(tree, tvb, offset, len, "Data Segment");
	xtp_subtree = proto_item_add_subtree(ti, ett_xtp_data);

	if (have_btag) {
		btag = tvb_get_ntohl(tvb, offset);
		btag <<= 32;
		btag += tvb_get_ntohl(tvb, offset+4);
		proto_tree_add_uint64(xtp_subtree, hf_xtp_btag, tvb, offset, 8, btag);
		offset += 8;
		len -= 8;
	}

	proto_tree_add_text(xtp_subtree, tvb, offset, len,
		"Data (%u byte%s)", len,
		plurality(len, "", "s"));

	return;
}

static void
dissect_xtp_cntl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		guint32 offset) {
	guint32 len = tvb_length_remaining(tvb, offset);
	guint32 start = offset;
	proto_item *top_ti;
	proto_tree *xtp_subtree;
	struct xtp_cntl cntl[1];

	top_ti = proto_tree_add_text(tree, tvb, offset, len,
				"Common Control Segment");
	xtp_subtree = proto_item_add_subtree(top_ti, ett_xtp_cntl);

	if (len != XTP_CNTL_PKT_LEN) {
		proto_item_append_text(top_ti, ", bogus length(%u, must be %u)",
			len, XTP_CNTL_PKT_LEN);
		return;
	}

	/** parse **/
	/* rseq(8) */
	cntl->rseq = tvb_get_ntohl(tvb, offset);
	cntl->rseq <<= 32;
	cntl->rseq += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* alloc(8) */
	cntl->alloc = tvb_get_ntohl(tvb, offset);
	cntl->alloc <<= 32;
	cntl->alloc += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* echo(4) */
	cntl->echo = tvb_get_ntohl(tvb, offset);

	/** add summary **/
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
			" Recv-Seq=%" G_GINT64_MODIFIER "u", cntl->rseq);
		col_append_fstr(pinfo->cinfo, COL_INFO,
			" Alloc=%" G_GINT64_MODIFIER "u", cntl->alloc);
	}
	proto_item_append_text(top_ti,
			", Recv-Seq: %" G_GINT64_MODIFIER "u", cntl->rseq);

	/** display **/
	offset = start;
	/* rseq(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_cntl_rseq,
			tvb, offset, 8, cntl->rseq);
	offset += 8;
	/* alloc(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_cntl_alloc,
			tvb, offset, 8, cntl->alloc);
	offset += 4;
	/* echo(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_cntl_echo,
			tvb, offset, 4, cntl->echo);

	return;
}

static void
dissect_xtp_first(tvbuff_t *tvb, proto_tree *tree, guint32 offset) {

	if (!dissect_xtp_aseg(tvb, tree, offset))
		return;

	offset += XTP_IP_ADDR_SEG_LEN;
	dissect_xtp_tspec(tvb, tree, offset);

	return;
}

#define XTP_MAX_NSPANS 10000 /* Arbitrary. (Documentation link is dead.) */
static void
dissect_xtp_ecntl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		guint32 offset) {
	guint32 len = tvb_length_remaining(tvb, offset);
	guint32 start = offset;
	proto_item *top_ti;
	proto_tree *xtp_subtree;
	struct xtp_ecntl ecntl[1];
	guint spans_len;
	guint i;

	top_ti = proto_tree_add_text(tree, tvb, offset, len,
				"Error Control Segment");
	xtp_subtree = proto_item_add_subtree(top_ti, ett_xtp_ecntl);

	if (len < MIN_XTP_ECNTL_PKT_LEN) {
		proto_item_append_text(top_ti,
				", bogus length (%u, must be at least %u)",
				len, MIN_XTP_ECNTL_PKT_LEN);
		return;
	}

	/** parse **/
	/* rseq(8) */
	ecntl->rseq = tvb_get_ntohl(tvb, offset);
	ecntl->rseq <<= 32;
	ecntl->rseq += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* alloc(8) */
	ecntl->alloc = tvb_get_ntohl(tvb, offset);
	ecntl->alloc <<= 32;
	ecntl->alloc += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* echo(4) */
	ecntl->echo = tvb_get_ntohl(tvb, offset);
	offset += 4;
	/* nspan(4) */
	ecntl->nspan = tvb_get_ntohl(tvb, offset);
	offset += 4;
	len = len + XTP_HEADER_LEN - offset;
	spans_len = 16 * ecntl->nspan;

	if (len != spans_len) {
		expert_add_info_format(pinfo, top_ti, PI_MALFORMED, PI_ERROR, "Number of spans (%u) incorrect. Should be %u.", ecntl->nspan, len);
		THROW(ReportedBoundsError);
	}

	if (ecntl->nspan > XTP_MAX_NSPANS) {
		expert_add_info_format(pinfo, top_ti, PI_MALFORMED, PI_ERROR, "Too many spans: %u", ecntl->nspan);
		THROW(ReportedBoundsError);
	}

	/** add summary **/
	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_append_fstr(pinfo->cinfo, COL_INFO,
				" Recv-Seq=%" G_GINT64_MODIFIER "u", ecntl->rseq);
		col_append_fstr(pinfo->cinfo, COL_INFO,
				" Alloc=%" G_GINT64_MODIFIER "u", ecntl->alloc);
	}
	proto_item_append_text(top_ti,
				", Recv-Seq: %" G_GINT64_MODIFIER "u", ecntl->rseq);

	/** display **/
	offset = start;
	/* rseq(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_ecntl_rseq,
				tvb, offset, 8, ecntl->rseq);
	offset += 8;
	/* alloc(8) */
	proto_tree_add_uint64(xtp_subtree, hf_xtp_ecntl_alloc,
				tvb, offset, 8, ecntl->alloc);
	offset += 8;
	/* echo(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_ecntl_echo,
				tvb, offset, 4, ecntl->echo);
	offset += 4;
	/* nspan(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_ecntl_nspan,
				tvb, offset, 4, ecntl->nspan);
	offset += 4;
	/* spans(16n) */
	for (i = 0; i < ecntl->nspan; i++) {
		proto_tree_add_item(xtp_subtree, hf_xtp_ecntl_span_left,
				tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
		proto_tree_add_item(xtp_subtree, hf_xtp_ecntl_span_right,
				tvb, offset, 8, ENC_LITTLE_ENDIAN);
		offset += 8;
	}

	return;
}

static void
dissect_xtp_tcntl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		guint32 offset) {

	if (!dissect_xtp_traffic_cntl(tvb, pinfo, tree, offset))
		return;

	offset += XTP_TRAFFIC_CNTL_LEN;
	dissect_xtp_tspec(tvb, tree, offset);

	return;
}

static void
dissect_xtp_jcntl(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
		guint32 offset) {

	if (!dissect_xtp_traffic_cntl(tvb, pinfo, tree, offset))
		return;

	offset += XTP_TRAFFIC_CNTL_LEN;
	if (!dissect_xtp_aseg(tvb, tree, offset))
		return;

	offset += XTP_IP_ADDR_SEG_LEN;
	dissect_xtp_tspec(tvb, tree, offset);

	return;
}

static void
dissect_xtp_diag(tvbuff_t *tvb, proto_tree *tree, guint32 offset) {
	guint32 len = tvb_length_remaining(tvb, offset);
	guint32 start = offset;
	proto_item *ti;
	proto_tree *xtp_subtree;
	struct xtp_diag diag[1];
	guint32 msg_len;

	ti = proto_tree_add_text(tree, tvb, offset, len, "Diagnostic Segment");
	xtp_subtree = proto_item_add_subtree(ti, ett_xtp_diag);

	if (len < XTP_DIAG_PKT_HEADER_LEN) {
		proto_item_append_text(ti,
				", bogus length (%u, must be at least %u)",
				len, XTP_DIAG_PKT_HEADER_LEN);
		return;
	}

	/** parse **/
	/* code(4) */
	diag->code = tvb_get_ntohl(tvb, offset);
	offset += 4;
	/* val(4) */
	diag->val = tvb_get_ntohl(tvb, offset);
	offset += 4;
	/* message(n) */
	msg_len = tvb_length_remaining(tvb, offset);
	diag->msg = tvb_get_string(tvb, offset, msg_len);

	/** display **/
	offset = start;
	/* code(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_diag_code,
			tvb, offset, 4, diag->code);
	offset += 4;
	/* val(4) */
	proto_tree_add_uint(xtp_subtree, hf_xtp_diag_val,
			tvb, offset, 4, diag->val);
	offset += 4;
	/* message(4) */
	proto_tree_add_string(xtp_subtree, hf_xtp_diag_msg,
			tvb, offset, msg_len, diag->msg);
	g_free(diag->msg);

	return;
}

/* main dissector */
static int
dissect_xtp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
	guint32 offset, len;
	proto_item *ti;
	proto_tree *xtp_tree, *xtp_cmd_tree, *xtp_subtree;
	struct xtphdr xtph[1];
	int	error = 0;
	gchar	*options = "<None>";
	const char *fstr[] = { "<None>", "NOCHECK", "EDGE", "NOERR", "MULTI", "RES",
				"SORT", "NOFLOW", "FASTNAK", "SREQ", "DREQ",
				"RCLOSE", "WCLOSE", "EOM", "END", "BTAG" };
	gint	fpos = 0, returned_length;
	guint	i, bpos;
	guint	cmd_options;
	vec_t	cksum_vec[1];
	guint16 computed_cksum;
	gboolean have_btag;

	if ((len = tvb_length(tvb)) < XTP_HEADER_LEN)
		return 0;

	col_set_str(pinfo->cinfo, COL_PROTOCOL, "XTP");
	col_clear(pinfo->cinfo, COL_INFO);

	/** parse header **/
	offset = 0;
	/* key(8) */
	xtph->key		= tvb_get_ntohl(tvb, offset);
	xtph->key <<= 32;
	xtph->key += tvb_get_ntohl(tvb, offset+4);
	offset += 8;
	/* cmd(4) */
	xtph->cmd		= tvb_get_ntohl(tvb, offset);
	xtph->cmd_options	= xtph->cmd >> 8;
	xtph->cmd_ptype		= xtph->cmd & 0xff;
	xtph->cmd_ptype_ver	= (xtph->cmd_ptype & 0xe0) >> 5;
	xtph->cmd_ptype_pformat	= xtph->cmd_ptype & 0x1f;
	offset += 4;
	/* dlen(4) */
	xtph->dlen		= tvb_get_ntohl(tvb, offset);
	offset += 4;
	/* check(2) */
	xtph->check		= tvb_get_ntohs(tvb, offset);
	offset += 2;
	/* sort(2) */
	xtph->sort		= tvb_get_ntohs(tvb, offset);
	offset += 2;
	/* sync(4) */
	xtph->sync		= tvb_get_ntohl(tvb, offset);
	offset += 4;
	/* seq(8) */
	xtph->seq		= tvb_get_ntohl(tvb, offset);
	xtph->seq <<= 32;
	xtph->seq += tvb_get_ntohl(tvb, offset+4);

#define MAX_OPTIONS_LEN	128
	options=ep_alloc(MAX_OPTIONS_LEN);
	options[0]=0;
	cmd_options = xtph->cmd_options >> 8;
	for (i = 0; i < 16; i++) {
		bpos = 1 << (15 - i);
		if (cmd_options & bpos) {
			returned_length = g_snprintf(&options[fpos],
			MAX_OPTIONS_LEN-fpos, "%s%s",
			fpos?", ":"",
			fstr[i]);
			fpos += MIN(returned_length, MAX_OPTIONS_LEN-fpos);
		}
	}

	if (check_col(pinfo->cinfo, COL_INFO)) {
		col_add_str(pinfo->cinfo, COL_INFO,
			    val_to_str(xtph->cmd_ptype_pformat,
					pformat_vals, "Unknown pformat (%u)"));
		col_append_fstr(pinfo->cinfo, COL_INFO, " [%s]", options);
		col_append_fstr(pinfo->cinfo, COL_INFO,
				" Seq=%" G_GINT64_MODIFIER "u", xtph->seq);
		col_append_fstr(pinfo->cinfo, COL_INFO, " Len=%u", xtph->dlen);
	}

	if (tree) {
		ti = proto_tree_add_item(tree, proto_xtp, tvb, 0, -1, ENC_NA);
		/** add summary **/
		proto_item_append_text(ti,
				", Key: 0x%016" G_GINT64_MODIFIER "X", xtph->key);
		proto_item_append_text(ti,
				", Seq: %" G_GINT64_MODIFIER "u", xtph->seq);
		proto_item_append_text(ti, ", Len: %u", xtph->dlen);

		xtp_tree = proto_item_add_subtree(ti, ett_xtp);
		/* key(8) */
		offset = 0;
		proto_tree_add_uint64(xtp_tree, hf_xtp_key,
					tvb, offset, 8, xtph->key);
		offset += 8;
		/* cmd(4) */
		ti = proto_tree_add_uint(xtp_tree, hf_xtp_cmd,
					tvb, offset, 4, xtph->cmd);
		xtp_cmd_tree = proto_item_add_subtree(ti, ett_xtp_cmd);
		ti = proto_tree_add_uint(xtp_cmd_tree, hf_xtp_cmd_options,
					tvb, offset, 3, xtph->cmd_options);
		/** add summary **/
		proto_item_append_text(ti, " [%s]", options);

		xtp_subtree = proto_item_add_subtree(ti, ett_xtp_cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_nocheck,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_edge,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_noerr,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_multi,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_res,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_sort,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_noflow,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_fastnak,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_sreq,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_dreq,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_rclose,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_wclose,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_eom,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_end,
					tvb, offset, 3, xtph->cmd_options);
		proto_tree_add_boolean(xtp_subtree, hf_xtp_cmd_options_btag,
					tvb, offset, 3, xtph->cmd_options);
		offset += 3;
		ti = proto_tree_add_uint(xtp_cmd_tree, hf_xtp_cmd_ptype,
					tvb, offset, 1, xtph->cmd_ptype);
		xtp_subtree = proto_item_add_subtree(ti, ett_xtp_cmd_ptype);
		proto_tree_add_uint(xtp_subtree, hf_xtp_cmd_ptype_ver,
					tvb, offset, 1, xtph->cmd_ptype_ver);
		if (xtph->cmd_ptype_ver != XTP_VERSION_4) {
			proto_item_append_text(ti,
				", Unknown XTP version (%03X)", xtph->cmd_ptype_ver);
			error = 1;
		}
		proto_tree_add_uint(xtp_subtree, hf_xtp_cmd_ptype_pformat,
				tvb, offset, 1, xtph->cmd_ptype_pformat);
		offset++;
		/* dlen(4) */
		ti = proto_tree_add_uint(xtp_tree, hf_xtp_dlen,
				tvb, offset, 4, xtph->dlen);
		if (xtph->dlen != len - XTP_HEADER_LEN) {
			proto_item_append_text(ti, ", bogus length (%u, must be %u)",
				xtph->dlen, len - XTP_HEADER_LEN);
			error = 1;
		}
		offset += 4;
		/* check(2) */
		if (!pinfo->fragmented) {
			guint32 check_len = XTP_HEADER_LEN;
			if (!(xtph->cmd_options & XTP_CMD_OPTIONS_NOCHECK))
				check_len += xtph->dlen;
			cksum_vec[0].ptr = tvb_get_ptr(tvb, 0, check_len);
			cksum_vec[0].len = check_len;
			computed_cksum = in_cksum(cksum_vec, 1);
			if (computed_cksum == 0) {
				proto_tree_add_text(xtp_tree, tvb, offset, 2,
					"Checksum: 0x%04x [correct]", xtph->check);
			} else {
				proto_tree_add_text(xtp_tree, tvb, offset, 2,
					"Checksum: 0x%04x [incorrect, should be 0x%04x]",
					xtph->check,
					in_cksum_shouldbe(xtph->check, computed_cksum));
			}
		}
		else {
			proto_tree_add_text(xtp_tree, tvb, offset, 2,
					"Checksum: 0x%04x", xtph->check);
		}
		offset += 2;
		/* sort(2) */
		proto_tree_add_uint(xtp_tree, hf_xtp_sort, tvb, offset, 2, xtph->sort);
		offset += 2;
		/* sync(4) */
		proto_tree_add_uint(xtp_tree, hf_xtp_sync, tvb, offset, 4, xtph->sync);
		offset += 4;
		/* seq(8) */
		proto_tree_add_uint64(xtp_tree, hf_xtp_seq, tvb, offset, 8, xtph->seq);
		offset += 8;

		if (!error) {
			switch (xtph->cmd_ptype_pformat) {
			case XTP_DATA_PKT:
				have_btag = !!(xtph->cmd_options & XTP_CMD_OPTIONS_BTAG);
				dissect_xtp_data(tvb, xtp_tree, offset, have_btag);
				break;
			case XTP_CNTL_PKT:
				dissect_xtp_cntl(tvb, pinfo, xtp_tree, offset);
				break;
			case XTP_FIRST_PKT:
				dissect_xtp_first(tvb, xtp_tree, offset);
				break;
			case XTP_ECNTL_PKT:
				dissect_xtp_ecntl(tvb, pinfo, xtp_tree, offset);
				break;
			case XTP_TCNTL_PKT:
				dissect_xtp_tcntl(tvb, pinfo, xtp_tree, offset);
				break;
			case XTP_JOIN_PKT:
				/* obsolete */
				break;
			case XTP_JCNTL_PKT:
				dissect_xtp_jcntl(tvb, pinfo, xtp_tree, offset);
				break;
			case XTP_DIAG_PKT:
				dissect_xtp_diag(tvb, xtp_tree, offset);
				break;
			default:
				/* error */
				break;
			}
		}
	}

	return tvb_length(tvb);
}

void
proto_register_xtp(void)
{
	static hf_register_info hf[] = {
		/* command header */
		{ &hf_xtp_key,
			{ "Key",           "xtp.key",
			FT_UINT64, BASE_HEX, NULL, 0x0,
			NULL, HFILL }
		},
		{ &hf_xtp_cmd,
			{ "Command", "xtp.cmd",
			FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options,
			{ "Options", "xtp.cmd.options",
			FT_UINT24, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_nocheck,
			{ "NOCHECK", "xtp.cmd.options.nocheck",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_NOCHECK, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_edge,
			{ "EDGE", "xtp.cmd.options.edge",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_EDGE, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_noerr,
			{ "NOERR", "xtp.cmd.options.noerr",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_NOERR, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_multi,
			{ "MULTI", "xtp.cmd.options.multi",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_MULTI, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_res,
			{ "RES", "xtp.cmd.options.res",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_RES, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_sort,
			{ "SORT", "xtp.cmd.options.sort",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_SORT, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_noflow,
			{ "NOFLOW", "xtp.cmd.options.noflow",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_NOFLOW, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_fastnak,
			{ "FASTNAK", "xtp.cmd.options.fastnak",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_FASTNAK, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_sreq,
			{ "SREQ", "xtp.cmd.options.sreq",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_SREQ, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_dreq,
			{ "DREQ", "xtp.cmd.options.dreq",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_DREQ, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_rclose,
			{ "RCLOSE", "xtp.cmd.options.rclose",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_RCLOSE, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_wclose,
			{ "WCLOSE", "xtp.cmd.options.wclose",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_WCLOSE, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_eom,
			{ "EOM", "xtp.cmd.options.eom",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_EOM, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_end,
			{ "END", "xtp.cmd.options.end",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_END, NULL, HFILL }
		},
		{ &hf_xtp_cmd_options_btag,
			{ "BTAG", "xtp.cmd.options.btag",
			FT_BOOLEAN, 24, TFS(&tfs_set_notset),
			XTP_CMD_OPTIONS_BTAG, NULL, HFILL }
		},
		{ &hf_xtp_cmd_ptype,
			{ "Packet type", "xtp.cmd.ptype",
			FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_cmd_ptype_ver,
			{ "Version", "xtp.cmd.ptype.ver",
			FT_UINT8, BASE_DEC, VALS(version_vals), 0x0, NULL, HFILL }
		},
		{ &hf_xtp_cmd_ptype_pformat,
			{ "Format", "xtp.cmd.ptype.pformat",
			FT_UINT8, BASE_DEC, VALS(pformat_vals), 0x0, NULL, HFILL }
		},
		{ &hf_xtp_dlen,
			{ "Data length", "xtp.dlen",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_sort,
			{ "Sort", "xtp.sort",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_sync,
			{ "Synchronizing handshake", "xtp.sync",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_seq,
			{ "Sequence number", "xtp.seq",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* control segment */
		{ &hf_xtp_cntl_rseq,
			{ "Received sequence number", "xtp.cntl.rseq",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_cntl_alloc,
			{ "Allocation", "xtp.cntl.alloc",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_cntl_echo,
			{ "Synchronizing handshake echo", "xtp.cntl.echo",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_ecntl_rseq,
			{ "Received sequence number", "xtp.ecntl.rseq",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_ecntl_alloc,
			{ "Allocation", "xtp.ecntl.alloc",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_ecntl_echo,
			{ "Synchronizing handshake echo", "xtp.ecntl.echo",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_ecntl_nspan,
			{ "Number of spans", "xtp.ecntl.nspan",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_ecntl_span_left,
			{ "Span left edge", "xtp.ecntl.span_le",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_ecntl_span_right,
			{ "Span right edge", "xtp.ecntl.span_re",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tcntl_rseq,
			{ "Received sequence number", "xtp.tcntl.rseq",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tcntl_alloc,
			{ "Allocation", "xtp.tcntl.alloc",
			FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tcntl_echo,
			{ "Synchronizing handshake echo", "xtp.tcntl.echo",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tcntl_rsvd,
			{ "Reserved", "xtp.tcntl.rsvd",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tcntl_xkey,
			{ "Exchange key", "xtp.tcntl.xkey",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		/* traffic specifier */
		{ &hf_xtp_tspec_tlen,
			{ "Length", "xtp.tspec.tlen",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tspec_service,
			{ "Service", "xtp.tspec.service",
			FT_UINT8, BASE_DEC, VALS(service_vals), 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tspec_tformat,
			{ "Format", "xtp.tspec.format",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tspec_traffic,
			{ "Traffic", "xtp.tspec.traffic",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tspec_maxdata,
			{ "Maxdata", "xtp.tspec.maxdata",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tspec_inrate,
			{ "Incoming rate", "xtp.tspec.inrate",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tspec_inburst,
			{ "Incoming burst size", "xtp.tspec.inburst",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tspec_outrate,
			{ "Outgoing rate", "xtp.tspec.outrate",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_tspec_outburst,
			{ "Outgoing burst size", "xtp.tspec.outburst",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* address segment */
		{ &hf_xtp_aseg_alen,
			{ "Length", "xtp.aseg.alen",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_aseg_adomain,
			{ "Domain", "xtp.aseg.adomain",
			FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_aseg_aformat,
			{ "Format", "xtp.aseg.aformat",
			FT_UINT8, BASE_DEC, VALS(aformat_vals), 0x0, NULL, HFILL }
		},
		{ &hf_xtp_aseg_address,
			{ "Traffic", "xtp.aseg.address",
			FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_aseg_dsthost,
			{ "Destination host", "xtp.aseg.dsthost",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_aseg_srchost,
			{ "Source host", "xtp.aseg.srchost",
			FT_IPv4, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_aseg_dstport,
			{ "Destination port", "xtp.aseg.dstport",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_aseg_srcport,
			{ "Source port", "xtp.aseg.srcport",
			FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL }
		},
		/* others */
		{ &hf_xtp_btag,
			{ "Beginning tag", "xtp.data.btag",
			FT_UINT64, BASE_HEX, NULL, 0x0, NULL, HFILL }
		},
		{ &hf_xtp_diag_code,
			{ "Diagnostic code", "xtp.diag.code",
			FT_UINT32, BASE_DEC, VALS(diag_code_vals), 0x0, NULL, HFILL }
		},
		{ &hf_xtp_diag_val,
			{ "Diagnostic value", "xtp.diag.val",
			FT_UINT32, BASE_DEC, VALS(diag_val_vals), 0x0, NULL, HFILL }
		},
		{ &hf_xtp_diag_msg,
			{ "Message", "xtp.diag.msg",
			FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL }
		},
	};

	static gint *ett[] = {
		&ett_xtp,
		&ett_xtp_cmd,
		&ett_xtp_cmd_options,
		&ett_xtp_cmd_ptype,
		&ett_xtp_cntl,
		&ett_xtp_ecntl,
		&ett_xtp_tcntl,
		&ett_xtp_tspec,
		&ett_xtp_jcntl,
		&ett_xtp_first,
		&ett_xtp_aseg,
		&ett_xtp_data,
		&ett_xtp_diag,
	};

	proto_xtp = proto_register_protocol("Xpress Transport Protocol",
	    "XTP", "xtp");
	proto_register_field_array(proto_xtp, hf, array_length(hf));
	proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_xtp(void)
{
	dissector_handle_t xtp_handle;

	xtp_handle = new_create_dissector_handle(dissect_xtp, proto_xtp);
	dissector_add_uint("ip.proto", IP_PROTO_XTP, xtp_handle);
}
