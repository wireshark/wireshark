/* packet-bgp.c
 * Definitions for BGP packet disassembly structures and routine
 *
 * $Id: packet-bgp.h,v 1.2 1999/11/02 00:11:58 itojun Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@unicom.net>
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

#include "packet.h"
#include "packet-ipv6.h"

/* some handy things to know */
#define BGP_MAX_PACKET_SIZE		4096
#define BGP_MARKER_SIZE			16
#define BGP_HEADER_SIZE			19
#define BGP_MIN_OPEN_MSG_SIZE		29
#define BGP_MIN_UPDATE_MSG_SIZE		23
#define BGP_MIN_NOTIFICATION_MSG_SIZE	21
#define BGP_MIN_KEEPALVE_MSG_SIZE	BGP_HEADER_SIZE
#define BGP_MAX_AS_PATH_LENGTH		32	/* guint16s */

#define BGP_OPEN		1
#define BGP_UPDATE		2
#define BGP_NOTIFICATION	3
#define BGP_KEEPALIVE		4

struct bgp {
    guint8 bgp_marker[BGP_MARKER_SIZE];
    guint16 bgp_len;
    guint8 bgp_type;
};

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

struct bgp_notification {
    guint8 bgpn_marker[BGP_MARKER_SIZE];
    guint16 bgpn_len;
    guint8 bgpn_type;
    guint8 bgpn_major;
    guint8 bgpn_minor;
    /* data should follow */
};

struct bgp_attr {
    guint8 bgpa_flags;
    guint8 bgpa_type;
};

#define BGPTYPE_ORIGIN		1
#define BGPTYPE_AS_PATH		2
#define BGPTYPE_NEXT_HOP	3
#define BGPTYPE_MULTI_EXIT_DISC	4
#define BGPTYPE_LOCAL_PREF	5
#define BGPTYPE_ATOMIC_AGGREGATE	6
#define BGPTYPE_AGGREGATOR	7
#define BGPTYPE_MP_REACH_NLRI	14	/* RFC2283 */
#define BGPTYPE_MP_UNREACH_NLRI	15	/* RFC2283 */

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
