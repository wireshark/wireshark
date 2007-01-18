/* afn.h
 * RFC 1700 address family numbers
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

#ifndef __AFN_H__
#define __AFN_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Address family numbers, from
 *
 *	http://www.iana.org/assignments/address-family-numbers
 */
#define AFNUM_RESERVED	0	/* Reserved */
#define AFNUM_INET	1	/* IP (IP version 4) */
#define AFNUM_INET6	2	/* IP6 (IP version 6) */
#define AFNUM_NSAP	3	/* NSAP */
#define AFNUM_HDLC	4	/* HDLC (8-bit multidrop) */
#define AFNUM_BBN1822	5	/* BBN 1822 */
#define AFNUM_802	6	/* 802 (includes all 802 media plus Ethernet "canonical format") */
#define AFNUM_E163	7	/* E.163 */
#define AFNUM_E164	8	/* E.164 (SMDS, Frame Relay, ATM) */
#define AFNUM_F69	9	/* F.69 (Telex) */
#define AFNUM_X121	10	/* X.121 (X.25, Frame Relay) */
#define AFNUM_IPX	11	/* IPX */
#define AFNUM_ATALK	12	/* Appletalk */
#define AFNUM_DECNET	13	/* Decnet IV */
#define AFNUM_BANYAN	14	/* Banyan Vines */
#define AFNUM_E164NSAP	15	/* E.164 with NSAP format subaddress */
#define AFNUM_DNS	16	/* DNS (Domain Name System) */
#define AFNUM_DISTNAME	17	/* Distinguished Name */
#define AFNUM_AS_NUMBER	18	/* AS Number */
#define AFNUM_XTP_IP4	19	/* XTP over IP version 4 */
#define AFNUM_XTP_IP6	20	/* XTP over IP version 6 */
#define AFNUM_XTP	21	/* XTP native mode XTP */
#define AFNUM_FC_WWPN	22	/* Fibre Channel World-Wide Port Name */
#define AFNUM_FC_WWNN	23	/* Fibre Channel World-Wide Node Name */
#define AFNUM_GWID	24	/* GWID */
/* draft-kompella-ppvpn-l2vpn */
#define AFNUM_L2VPN     25
#define AFNUM_L2VPN_OLD 196
extern const value_string afn_vals[];

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __AFN_H__ */
