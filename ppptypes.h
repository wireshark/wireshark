/* ppptypes.h
 * Defines PPP packet types.
 *
 * $Id: ppptypes.h,v 1.4 2001/01/10 09:34:08 guy Exp $
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
#define	PPP_VINES	0x35	/* Banyan Vines */
#define PPP_MP		0x3d	/* Multilink PPP */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_MPLS_UNI	0x281	/* MPLS Unicast */
#define PPP_MPLS_MULTI	0x281	/* MPLS Multicast */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b	/* IPX Control Protocol */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_CBCP	0xc029	/* Callback Control Protocol */

/*
 * Address and control field for Cisco HDLC.
 * RFC 1547, "Requirements for an Internet Standard Point-to-Point Protocol",
 * section 4.3.1 "Cisco Systems point-to-point protocols", says
 *
 *	The Cisco Systems gateway supports both asynchronous links using SLIP
 *	and synchronous links using either simple HDLC framing, X.25 LAPB or
 *	full X.25.  The HDLC framing procedure includes a four byte header.
 *	The first octet (address) is either 0x0F (unicast intent) or 0x8F  
 *	(multicast intent).  The second octet (control byte) is left zero and
 *	is not checked on reception.  The third and fourth octets contain a 
 *	standard 16 bit Ethernet protocol type code.
 *
 * This is the first two octets for unicast intent frames.
 */
#define CISCO_HDLC_ADDR_CTRL	0x0F00	/* Internet Protocol */

/*
 * Protocol types for the Cisco HDLC format.
 *
 * As per the above, according to RFC 1547, these are "standard 16 bit
 * Ethernet protocol type code[s]", but 0x8035 is Reverse ARP, and
 * that is (at least according to the Linux ISDN code) not the
 * same as Cisco SLARP.
 *
 * In addition, 0x2000 is apparently the Cisco Discovery Protocol, but
 * on Ethernet those are encapsulated inside SNAP with an OUI of
 * OUI_CISCO, not OUI_ENCAP_ETHER.
 *
 * Perhaps we should set up a protocol table for those protocols
 * that differ between Ethernet and Cisco HDLC, and have the PPP
 * code first try that table and, if it finds nothing in that
 * table, call "ethertype()".  (Unfortunately, that means that -
 * assuming we had a Cisco SLARP dissector - said dissector were
 * disabled, SLARP packets would be dissected as Reverse ARP
 * packets, not as data.
 */
#define CISCO_SLARP	0x8035	/* Cisco SLARP protocol */

#endif /* ppptypes.h */
