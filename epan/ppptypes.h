/* ppptypes.h
 * Defines PPP packet types.
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

	http://www.iana.org/assignments/ppp-numbers

 */
#define PPP_PADDING	0x1	/* Padding Protocol */
#define PPP_ROHC_SCID	0x3	/* ROHC small-CID */
#define PPP_ROHC_LCID	0x5	/* ROHC large-CID */
#define PPP_IP		0x21	/* Internet Protocol */
#define PPP_OSI		0x23    /* OSI Protocol */
#define PPP_DEC4	0x25	/* DECnet Phase IV */
#define PPP_AT		0x29	/* AppleTalk Protocol */
#define PPP_IPX		0x2b	/* IPX protocol */
#define	PPP_VJC_COMP	0x2d	/* VJ compressed TCP */
#define	PPP_VJC_UNCOMP	0x2f	/* VJ uncompressed TCP */
#define PPP_BPDU	0x31	/* Bridging PDU (spanning tree BPDU?) */
#define PPP_ST		0x33	/* Stream Protocol (ST-II) */
#define	PPP_VINES	0x35	/* Banyan Vines */
#define PPP_AT_EDDP	0x39	/* AppleTalk EDDP */
#define PPP_AT_SB	0x3b	/* AppleTalk SmartBuffered */
#define PPP_MP		0x3d	/* Multilink PPP */
#define PPP_NB		0x3f	/* NETBIOS Framing */
#define PPP_CISCO	0x41	/* Cisco Systems */
#define PPP_ASCOM	0x43	/* Ascom Timeplex */
#define PPP_LBLB	0x45	/* Fujitsu Link Backup and Load Balancing */
#define PPP_RL		0x47	/* DCA Remote Lan */
#define PPP_SDTP	0x49	/* Serial Data Transport Protocol */
#define PPP_LLC		0x4b	/* SNA over LLC */
#define PPP_SNA		0x4d	/* SNA */
#define PPP_IPV6HC	0x4f	/* IPv6 Header Compression  */
#define PPP_KNX		0x51	/* KNX Bridging Data */
#define PPP_ENCRYPT	0x53	/* Encryption */
#define PPP_ILE		0x55	/* Individual Link Encryption */
#define PPP_IPV6	0x57	/* Internet Protocol Version 6 */
#define PPP_MUX		0x59    /* PPP Multiplexing */
#define PPP_RTP_FH	0x61	/* RTP IPHC Full Header */
#define PPP_RTP_CTCP	0x63	/* RTP IPHC Compressed TCP */
#define PPP_RTP_CNTCP	0x65	/* RTP IPHC Compressed Non TCP */
#define PPP_RTP_CUDP8	0x67	/* RTP IPHC Compressed UDP 8 */
#define PPP_RTP_CRTP8	0x69	/* RTP IPHC Compressed RTP 8 */
#define PPP_STAMPEDE	0x6f	/* Stampede Bridging */
#define PPP_MPPLUS	0x73	/* MP+ Protocol */
#define PPP_NTCITS_IPI	0xc1	/* NTCITS IPI */
#define PPP_ML_SLCOMP	0xfb	/* single link compression in multilink */
#define PPP_COMP	0xfd	/* compressed packet */
#define PPP_STP_HELLO	0x0201	/* 802.1d Hello Packet */
#define PPP_IBM_SR	0x0203	/* IBM Source Routing BPDU */
#define PPP_DEC_LB	0x0205	/* DEC LANBridge100 Spanning Tree */
#define PPP_CDP         0x0207  /* Cisco Discovery Protocol */
#define PPP_NETCS	0x0209	/* Netcs Twin Routing */
#define PPP_STP         0x020b  /* Scheduled Transfer Protocol */
#define PPP_EDP         0x020d  /* Extreme Discovery Protocol */
#define PPP_OSCP	0x0211	/* Optical Supervisory Channel Protocol */
#define PPP_OSCP2	0x0213	/* Optical Supervisory Channel Protocol */
#define PPP_LUXCOM	0x0231	/* Luxcom */
#define PPP_SIGMA	0x0233	/* Sigma Network Systems */
#define PPP_ACSP	0x0235	/* Apple Client Server Protocol */
#define PPP_MPLS_UNI	0x0281	/* MPLS Unicast */
#define PPP_MPLS_MULTI	0x0283	/* MPLS Multicast */
#define PPP_P12844	0x0285	/* IEEE p1284.4 standard - data packets */
#define PPP_ETSI	0x0287	/* ETSI TETRA Networks Procotol Type 1 */
#define PPP_MFTP	0x0289	/* Multichannel Flow Treatment Protocol */
#define PPP_RTP_CTCPND	0x2063	/* RTP IPHC Compressed TCP No Delta */
#define PPP_RTP_CS	0x2065	/* RTP IPHC Context State */
#define PPP_RTP_CUDP16	0x2067	/* RTP IPHC Compressed UDP 16 */
#define PPP_RTP_CRDP16	0x2069	/* RTP IPHC Compressed RTP 16 */
#define PPP_CCCP	0x4001	/* Cray Communications Control Protocol */
#define PPP_CDPD_MNRP	0x4003	/* CDPD Mobile Network Registration Protocol */
#define PPP_EXPANDAP	0x4005	/* Expand accelarator protocol */
#define PPP_ODSICP	0x4007	/* ODSICP NCP */
#define PPP_DOCSIS	0x4009	/* DOCSIS DLL */
#define PPP_LZS		0x4021	/* Stacker LZS */
#define PPP_REFTEK	0x4023	/* RefTek Protocol */
#define PPP_FC		0x4025	/* Fibre Channel */
#define PPP_EMIT	0x4027	/* EMIT Protocols */
#define PPP_IPCP	0x8021	/* IP Control Protocol */
#define PPP_OSICP	0x8023  /* OSI Control Protocol */
#define PPP_XNSIDPCP	0x8025	/* Xerox NS IDP Control Protocol */
#define PPP_DECNETCP	0x8027	/* DECnet Phase IV Control Protocol */
#define PPP_ATCP	0x8029	/* AppleTalk Control Protocol */
#define PPP_IPXCP	0x802b	/* IPX Control Protocol */
#define PPP_BRIDGENCP	0x8031	/* Bridging NCP */
#define PPP_SPCP	0x8033	/* Stream Protocol Control Protocol */
#define PPP_BVCP	0x8035	/* Banyan Vines Control Protocol */
#define PPP_MLCP	0x803d	/* Multi-Link Control Protocol */
#define PPP_NBCP	0x803f	/* NETBIOS Framing Control Protocol */
#define PPP_CISCOCP	0x8041	/* Cisco Systems Control Protocol */
#define PPP_ASCOMCP	0x8043	/* Ascom Timeplex Control Protocol (?) */
#define PPP_LBLBCP	0x8045	/* Fujitsu LBLB Control Protocol */
#define PPP_RLNCP	0x8047	/* DCA Remote Lan Network Control Protocol */
#define PPP_SDCP	0x8049	/* Serial Data Control Protocol */
#define PPP_LLCCP	0x804b	/* SNA over LLC Control Protocol */
#define PPP_SNACP	0x804d	/* SNA Control Protocol */
#define PPP_KNXCP	0x8051	/* KNX Bridging Control Protocol */
#define PPP_ECP		0x8053	/* Encryption Control Protocol */
#define PPP_ILECP	0x8055	/* Individual Encryption Control Protocol */
#define PPP_IPV6CP	0x8057	/* IPv6 Control Protocol */
#define PPP_MUXCP       0x8059  /* PPPMux Control Protocol */
#define PPP_STAMPEDECP	0x806f	/* Stampede Bridging Control Protocol */
#define PPP_MPPCP	0x8073	/* MP+ Contorol Protocol */
#define PPP_IPICP	0x80c1	/* NTCITS IPI Control Protocol */
#define PPP_SLCC	0x80fb	/* single link compression in multilink control */
#define PPP_CCP		0x80fd	/* Compression Control Protocol */
#define PPP_CDPCP	0x8207	/* Cisco Discovery Protocol Control Protocol */
#define PPP_NETCSCP	0x8209	/* Netcs Twin Routing */
#define PPP_STPCP	0x820b	/* STP - Control Protocol */
#define PPP_EDPCP	0x820d	/* Extreme Discovery Protocol Control Protocol */
#define PPP_ACSPC	0x8235	/* Apple Client Server Protocol Control */
#define PPP_MPLSCP	0x8281	/* MPLS Control Protocol */
#define PPP_P12844CP	0x8285	/* IEEE p1284.4 standard - Protocol Control */
#define PPP_ETSICP	0x8287	/* ETSI TETRA TNP1 Control Protocol */
#define PPP_MFTPCP	0x8287	/* Multichannel Flow Treatment Protocol */
#define PPP_LCP		0xc021	/* Link Control Protocol */
#define PPP_PAP		0xc023	/* Password Authentication Protocol */
#define PPP_LQR		0xc025	/* Link Quality Report protocol */
#define PPP_SPAP	0xc027	/* Shiva Password Authentication Protocol */
#define PPP_CBCP	0xc029	/* CallBack Control Protocol */
#define PPP_BACP	0xc02b	/* Bandwidth Allocation Control Protocol */
#define PPP_BAP		0xc02d	/* Bandwidth Allocation Protocol */
#define PPP_CONTCP	0xc081	/* Container Control Protocol */
#define PPP_CHAP	0xc223	/* Cryptographic Handshake Auth. Protocol */
#define PPP_RSAAP	0xc225	/* RSA Authentication Protocol */
#define PPP_EAP		0xc227	/* Extensible Authentication Protocol */
#define PPP_SIEP	0xc229	/* Mitsubishi Security Information Exchange Protocol*/
#define PPP_SBAP	0xc26f	/* Stampede Bridging Authorization Protocol */
#define PPP_PRPAP	0x281	/* Proprietary Authentication Protocol */
#define PPP_PRPAP2	0x283	/* Proprietary Authentication Protocol */
#define PPP_PRPNIAP	0x481	/* Proprietary Node ID Authentication Protocol */

#endif /* ppptypes.h */
