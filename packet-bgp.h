/* packet-bgp.c
 * Definitions for BGP packet disassembly structures and routine
 *
 * $Id: packet-bgp.h,v 1.7 2000/02/15 21:02:02 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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

#ifndef __PACKET_BGP_H__
#define __PACKET_BGP_H__

void dissect_bgp(const u_char *, int, frame_data *, proto_tree *);

/* some handy things to know */
#define BGP_MAX_PACKET_SIZE		4096
#define BGP_MARKER_SIZE			16
#define BGP_HEADER_SIZE			19
#define BGP_MIN_OPEN_MSG_SIZE		29
#define BGP_MIN_UPDATE_MSG_SIZE		23
#define BGP_MIN_NOTIFICATION_MSG_SIZE	21
#define BGP_MIN_KEEPALVE_MSG_SIZE	BGP_HEADER_SIZE

/* BGP message types */
#define BGP_OPEN		1
#define BGP_UPDATE		2
#define BGP_NOTIFICATION	3
#define BGP_KEEPALIVE		4

/* BGP header */
struct bgp {
    guint8 bgp_marker[BGP_MARKER_SIZE];
    guint16 bgp_len;
    guint8 bgp_type;
};

/* BGP OPEN message */
struct bgp_open {
    guint8 bgpo_marker[BGP_MARKER_SIZE];
    guint16 bgpo_len;
    guint8 bgpo_type;
    guint8 bgpo_version;
    guint16 bgpo_myas;
    guint16 bgpo_holdtime;
    guint32 bgpo_id;
    guint8 bgpo_optlen;
    /* options should follow */
};

/* BGP NOTIFICATION message */
struct bgp_notification {
    guint8 bgpn_marker[BGP_MARKER_SIZE];
    guint16 bgpn_len;
    guint8 bgpn_type;
    guint8 bgpn_major;
    guint8 bgpn_minor;
    /* data should follow */
};

/* path attribute */
struct bgp_attr {
    guint8 bgpa_flags;
    guint8 bgpa_type;
};

/* attribute flags, from RFC1771 */
#define BGP_ATTR_FLAG_OPTIONAL        0x80
#define BGP_ATTR_FLAG_TRANSITIVE      0x40
#define BGP_ATTR_FLAG_PARTIAL         0x20
#define BGP_ATTR_FLAG_EXTENDED_LENGTH 0x10

/* AS_PATH segment types */
#define AS_SET             1   /* RFC1771 */
#define AS_SEQUENCE        2   /* RFC1771 */
#define AS_CONFED_SET      3   /* RFC1965 */
#define AS_CONFED_SEQUENCE 4   /* RFC1965 */

/* well-known communities, from RFC1997 */
#define BGP_COMM_NO_EXPORT           0xFFFFFF01
#define BGP_COMM_NO_ADVERTISE        0xFFFFFF02
#define BGP_COMM_NO_EXPORT_SUBCONFED 0xFFFFFF03
#define FOURHEX0                     0x0000
#define FOURHEXF                     0xFFFF

/* attribute types */
#define BGPTYPE_ORIGIN            1   /* RFC1771          */
#define BGPTYPE_AS_PATH           2   /* RFC1771          */
#define BGPTYPE_NEXT_HOP          3   /* RFC1771          */
#define BGPTYPE_MULTI_EXIT_DISC   4   /* RFC1771          */
#define BGPTYPE_LOCAL_PREF        5   /* RFC1771          */
#define BGPTYPE_ATOMIC_AGGREGATE  6   /* RFC1771          */
#define BGPTYPE_AGGREGATOR        7   /* RFC1771          */
#define BGPTYPE_COMMUNITIES       8   /* RFC1997          */
#define BGPTYPE_ORIGINATOR_ID     9   /* RFC1966          */
#define BGPTYPE_CLUSTER_LIST     10   /* RFC1966          */
#define BGPTYPE_DPA              11   /* work in progress */
#define BGPTYPE_ADVERTISER       12   /* RFC1863          */
#define BGPTYPE_RCID_PATH        13   /* RFC1863          */
#define BGPTYPE_MP_REACH_NLRI    14   /* RFC2283          */
#define BGPTYPE_MP_UNREACH_NLRI  15   /* RFC2283          */

/* RFC1700 address family numbers */
#define AFNUM_INET	1
#define AFNUM_INET6	2
#define AFNUM_NSAP	3
#define AFNUM_HDLC	4
#define AFNUM_BBN1822	5
#define AFNUM_802	6
#define AFNUM_E163	7
#define AFNUM_E164	8
#define AFNUM_F69	9
#define AFNUM_X121	10
#define AFNUM_IPX	11
#define AFNUM_ATALK	12
#define AFNUM_DECNET	13
#define AFNUM_BANYAN	14
#define AFNUM_E164NSAP	15

#define CHECK_SIZE(x, s, l) \
do {				\
    if ((x) + (s) > (l))	\
	return;			\
} while (0)

#ifndef offsetof
#define offsetof(type, member)  ((size_t)(&((type *)0)->member))
#endif

#endif
