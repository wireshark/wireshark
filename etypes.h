/* etypes.h
 * Defines ethernet packet types, similar to tcpdump's ethertype.h
 *
 * $Id: etypes.h,v 1.21 2001/06/14 20:37:07 guy Exp $
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

#ifndef __ETYPES_H__
#define __ETYPES_H__

/*
 * Maximum length of an IEEE 802.3 frame; Ethernet type/length values
 * greater than it are types, Ethernet type/length values less than or
 * equal to it are lengths.
 */
#define IEEE_802_3_MAX_LEN 1500

#ifndef ETHERTYPE_UNK
#define ETHERTYPE_UNK		0x0000
#endif

/* Sources:
 * http://www.isi.edu/in-notes/iana/assignments/ethernet-numbers
 * TCP/IP Illustrated, Volume 1
 * RFCs 894, 1042, 826
 * tcpdump's ethertype.h
 * http://www.cavebear.com/CaveBear/Ethernet/
 */

#ifndef ETHERTYPE_VINES
#define ETHERTYPE_VINES		0x0bad
#endif

#ifndef ETHERTYPE_TRAIN
/*
 * Created by Microsoft Network Monitor as a summary packet.
 */
#define ETHERTYPE_TRAIN		0x1984
#endif

#ifndef ETHERTYPE_3C_NBP_DGRAM
#define ETHERTYPE_3C_NBP_DGRAM	0x3c07
#endif

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP		0x0800
#endif

#ifndef ETHERTYPE_X25L3
#define ETHERTYPE_X25L3		0x0805
#endif

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP		0x0806
#endif

#ifndef ETHERTYPE_DEC
#define ETHERTYPE_DEC		0x6000
#endif

#ifndef ETHERTYPE_DNA_DL
#define ETHERTYPE_DNA_DL	0x6001
#endif

#ifndef ETHERTYPE_DNA_RC
#define ETHERTYPE_DNA_RC	0x6002
#endif

#ifndef ETHERTYPE_DNA_RT
#define ETHERTYPE_DNA_RT	0x6003
#endif

#ifndef ETHERTYPE_LAT
#define ETHERTYPE_LAT		0x6004
#endif

#ifndef ETHERTYPE_DEC_DIAG
#define ETHERTYPE_DEC_DIAG	0x6005
#endif

#ifndef ETHERTYPE_DEC_CUST
#define ETHERTYPE_DEC_CUST	0x6006
#endif

#ifndef ETHERTYPE_DEC_SCA
#define ETHERTYPE_DEC_SCA	0x6007
#endif

#ifndef ETHERTYPE_ETHBRIDGE
#define ETHERTYPE_ETHBRIDGE	0x6558	/* transparent Ethernet bridging */
#endif

#ifndef ETHERTYPE_REVARP
#define ETHERTYPE_REVARP	0x8035
#endif

#ifndef ETHERTYPE_DEC_LB
#define ETHERTYPE_DEC_LB	0x8038
#endif

#ifndef ETHERTYPE_ATALK
#define ETHERTYPE_ATALK		0x809b
#endif

#ifndef ETHERTYPE_AARP
#define ETHERTYPE_AARP		0x80f3
#endif

#ifndef ETHERTYPE_IPX
#define ETHERTYPE_IPX		0x8137
#endif

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN		0x8100	/* 802.1Q Virtual LAN */
#endif

#ifndef ETHERTYPE_SNMP
#define ETHERTYPE_SNMP		0x814c	/* SNMP over Ethernet, RFC 1089 */
#endif

#ifndef ETHERTYPE_WCP
#define ETHERTYPE_WCP		0x80ff	/* Wellfleet Compression Protocol */
#endif

#ifndef ETHERTYPE_IPv6
#define ETHERTYPE_IPv6		0x86dd
#endif

#ifndef ETHERTYPE_PPP
#define ETHERTYPE_PPP		0x880b	/* no, this is not PPPoE */
#endif

#ifndef ETHERTYPE_MPLS
#define ETHERTYPE_MPLS		0x8847	/* MPLS unicast packet */
#endif

#ifndef ETHERTYPE_MPLS_MULTI
#define ETHERTYPE_MPLS_MULTI	0x8848	/* MPLS multicast packet */
#endif

#ifndef ETHERTYPE_PPPOED
#define ETHERTYPE_PPPOED	0x8863	/* PPPoE Discovery Protocol */
#endif

#ifndef ETHERTYPE_PPPOES
#define ETHERTYPE_PPPOES	0x8864	/* PPPoE Session Protocol */
#endif

#ifndef ETHERTYPE_LOOP
#define ETHERTYPE_LOOP		0x9000 	/* used for layer 2 testing (do i see my own frames on the wire) */
#endif

extern const value_string etype_vals[];

#endif /* etypes.h */
