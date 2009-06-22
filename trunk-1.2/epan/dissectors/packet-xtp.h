/* packet-xtp.h
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
 */
#ifndef __PACKET_XTP_H__
#define __PACKET_XTP_H__

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

#endif /* __PACKET_XTP_H__ */
