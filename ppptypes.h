/* ppptypes.h
 * Defines PPP packet types.
 *
 * $Id: ppptypes.h,v 1.6 2001/03/15 09:11:01 guy Exp $
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
 */

#ifndef __PPPTYPES_H__
#define __PPPTYPES_H__

/* Protocol types, from Linux "ppp_defs.h" and

	http://www.isi.edu/in-notes/iana/assignments/ppp-numbers

 */
#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_AT		0x29	/* AppleTalk Protocol */
#define PPP_IPX		0x2b	/* IPX protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define PPP_BPDU	0x31	/* Bridging PDU (spanning tree BPDU?) */
#define	PPP_VINES	0x35	/* Banyan Vines */
#define PPP_MP		0x3d	/* Multilink PPP */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_DEC_LB	0x0205	/* DEC LANBridge100 Spanning Tree */
#define PPP_MPLS_UNI	0x0281	/* MPLS Unicast */
#define PPP_MPLS_MULTI	0x0283	/* MPLS Multicast */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b	/* IPX Control Protocol */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP	0xc029	/* Callback Control Protocol */

#endif /* ppptypes.h */
