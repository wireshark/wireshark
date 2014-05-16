/* ipproto.h
 * Declarations of IP protocol numbers, and of routines for converting
 * IP protocol numbers into strings.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __IPPROTO_H__
#define __IPPROTO_H__

#include "ws_symbol_export.h"

/*
 * IP protocol numbers.
 * http://www.iana.org/assignments/protocol-numbers/protocol-numbers.xml
 */
#define IP_PROTO_IP             0       /* dummy for IP */
#define IP_PROTO_HOPOPTS        0       /* IP6 hop-by-hop options - RFC1883 */
#define IP_PROTO_ICMP           1       /* control message protocol - RFC792 */
#define IP_PROTO_IGMP           2       /* group mgmt protocol - RFC1112 */
#define IP_PROTO_GGP            3       /* gateway^2 (deprecated) - RFC823*/
#define IP_PROTO_IPIP           4       /* IP inside IP - RFC2003*/
#define IP_PROTO_IPV4           4       /* IP header */
#define IP_PROTO_STREAM         5       /* Stream - RFC1190, RFC1819 */
#define IP_PROTO_TCP            6       /* TCP - RFC792 */
#define IP_PROTO_CBT            7       /* CBT - <A.Ballardie@cs.ucl.ac.uk> */
#define IP_PROTO_EGP            8       /* exterior gateway protocol - RFC888 */
#define IP_PROTO_IGP            9       /* any private interior gateway protocol ... */
#define IP_PROTO_IGRP           9       /* ... and used by Cisco for IGRP */
#define IP_PROTO_BBN_RCC        10      /* BBN RCC Monitoring */
#define IP_PROTO_NVPII          11      /* Network Voice Protocol - RFC741 */
#define IP_PROTO_PUP            12      /* pup */
#define IP_PROTO_ARGUS          13      /* ARGUS */
#define IP_PROTO_EMCON          14      /* EMCON */
#define IP_PROTO_XNET           15      /* Cross net debugger - IEN158 */
#define IP_PROTO_CHAOS          16      /* CHAOS */
#define IP_PROTO_UDP            17      /* user datagram protocol - RFC768 */
#define IP_PROTO_MUX            18      /* multiplexing - IEN90 */
#define IP_PROTO_DCNMEAS        19      /* DCN Measurement Subsystems */
#define IP_PROTO_HMP            20      /* Host Monitoring - RFC869 */
#define IP_PROTO_PRM            21      /* Packet radio measurement */
#define IP_PROTO_IDP            22      /* xns idp */
#define IP_PROTO_TRUNK1         23
#define IP_PROTO_TRUNK2         24
#define IP_PROTO_LEAF1          25
#define IP_PROTO_LEAF2          26
#define IP_PROTO_RDP            27      /* Reliable Data Protocol - RFC908 */
#define IP_PROTO_IRT            28      /* Internet Reliable Transation - RFC938 */
#define IP_PROTO_TP             29      /* tp-4 w/ class negotiation - RFC905 */
#define IP_PROTO_BULK           30      /* Bulk Data Transfer Protocol - RFC969 */
#define IP_PROTO_MFE_NSP        31      /* MFE Network Services Protocol */
#define IP_PROTO_MERIT          32      /* MERIT Internodal Protocol */
#define IP_PROTO_DCCP           33      /* Datagram Congestion Control Protocol */
#define IP_PROTO_3PC            34      /* Third party connect protocol */
#define IP_PROTO_IDPR           35      /* Interdomain policy routing protocol */
#define IP_PROTO_XTP            36      /* Xpress Transport Protocol */
#define IP_PROTO_DDP            37      /* Datagram Delivery Protocol */
#define IP_PROTO_CMTP           38      /* Control Message Transport Protocol */
#define IP_PROTO_TPPP           39      /* TP++ Transport Protocol */
#define IP_PROTO_IL             40      /* IL Transport Protocol */
#define IP_PROTO_IPV6           41      /* IP6 header */
#define IP_PROTO_SDRP           42      /* Source demand routing protocol */
#define IP_PROTO_ROUTING        43      /* IP6 routing header */
#define IP_PROTO_FRAGMENT       44      /* IP6 fragmentation header */
#define IP_PROTO_IDRP           45      /* Inter-Domain Routing Protocol */
#define IP_PROTO_RSVP           46      /* Resource ReSerVation protocol */
#define IP_PROTO_GRE            47      /* General Routing Encapsulation */
#define IP_PROTO_DSR            48      /* Dynamic Source Routing Protocol */
#define IP_PROTO_BNA            49      /* BNA */
#define IP_PROTO_ESP            50      /* Encap Security Payload for IPv6 - RFC2406 */
#define IP_PROTO_AH             51      /* Authentication Header for IPv6 - RFC2402*/
#define IP_PROTO_INSLP          52      /* Integrated Net Layer Security */
#define IP_PROTO_SWIPE          53      /* IP with Encryption */
#define IP_PROTO_NARP           54      /* NBMA Address resolution protocol - RFC1735 */
#define IP_PROTO_MOBILE         55      /* IP Mobility */
#define IP_PROTO_TLSP           56      /* Transport Layer Security Protocol using */
                                        /* Kryptonet key management */
#define IP_PROTO_SKIP           57      /* SKIP */
#define IP_PROTO_ICMPV6         58      /* ICMP6  - RFC1883*/
#define IP_PROTO_NONE           59      /* IP6 no next header - RFC1883 */
#define IP_PROTO_DSTOPTS        60      /* IP6 destination options - RFC1883 */
/* 61 is reserved by IANA for any host internal protocol */

/*
 * The current Protocol Numbers list says that the IP protocol number for
 * mobility headers is 135; it cites draft-ietf-mobileip-ipv6-24, but
 * that draft doesn't actually give a number.
 *
 * It appears that 62 used to be used, even though that's assigned to
 * a protocol called CFTP; however, the only reference for CFTP is a
 * Network Message from BBN back in 1982, so, for now, we support 62,
 * as well as 135, as a protocol number for mobility headers.
 */
#define IP_PROTO_MIPV6_OLD      62      /* Mobile IPv6  */
/* 63 is reserved by IANA for any local network */
#define IP_PROTO_SATEXPAK       64
#define IP_PROTO_KRYPTOLAN      65
#define IP_PROTO_RVD            66      /* MIT Remote virtual disk protocol */
#define IP_PROTO_IPPC           67      /* Internet Pluribus Packet Core */
/* 68 is reserved by IANA for any distributed file system */
#define IP_PROTO_SATMON         69      /* SATNET Monitoring */
#define IP_PROTO_VISA           70      /* VISA Protocol */
#define IP_PROTO_IPCV           71      /* Internet Packet Core Utility */
#define IP_PROTO_CPNX           72      /* Computer Protocol Network Executive */
#define IP_PROTO_CPHB           73      /* Computer Protocol Heart Beat */
#define IP_PROTO_WSN            74      /* WANG Span Network */
#define IP_PROTO_PVP            75      /* Packet Video Protocol */
#define IP_PROTO_BRSATMON       76      /* Backroon SATNET Monitoring */
#define IP_PROTO_SUNND          77      /* SUN ND Protocol - Temporary */
#define IP_PROTO_WBMON          78      /* Wideband Monitoring */
#define IP_PROTO_WBEXPAK        79      /* Wideband EXPAK */
#define IP_PROTO_ISOIP          80      /* ISO IP */
#define IP_PROTO_VMTP           81
#define IP_PROTO_SVMTP          82      /* Secure VMTP */
#define IP_PROTO_VINES          83      /* Vines over raw IP */
#define IP_PROTO_TTP            84
#define IP_PROTO_NSFNETIGP      85      /* NSFNET IGP */
#define IP_PROTO_DGP            86      /* Dissimilar Gateway Protocol */
#define IP_PROTO_TCF            87
#define IP_PROTO_EIGRP          88
#define IP_PROTO_OSPF           89      /* OSPF Interior Gateway Protocol - RFC1583 */
#define IP_PROTO_SPRITE         90      /* SPRITE RPC protocol */
#define IP_PROTO_LARP           91      /* Locus Address Resolution Protocol */
#define IP_PROTO_MTP            92      /* Multicast Transport Protocol */
#define IP_PROTO_AX25           93      /* AX.25 frames */
#define IP_PROTO_IPINIP         94      /* IP within IP Encapsulation protocol */
#define IP_PROTO_MICP           95      /* Mobile Internetworking Control Protocol */
#define IP_PROTO_SCCCP          96      /* Semaphore communications security protocol */
#define IP_PROTO_ETHERIP        97      /* Ethernet-within-IP - RFC 3378 */
#define IP_PROTO_ENCAP          98      /* encapsulation header - RFC1241*/
/* 99 is reserved by IANA for any private encryption scheme */
#define IP_PROTO_GMTP           100
#define IP_PROTO_IFMP           101     /* Ipsilon flow management protocol */
#define IP_PROTO_PNNI           102     /* PNNI over IP */
#define IP_PROTO_PIM            103     /* Protocol Independent Mcast */
#define IP_PROTO_ARIS           104
#define IP_PROTO_SCPS           105
#define IP_PROTO_QNX            106
#define IP_PROTO_AN             107     /* Active Networks */
#define IP_PROTO_IPCOMP         108     /* IP payload compression - RFC2393 */
#define IP_PROTO_SNP            109     /* Sitara Networks Protocol */
#define IP_PROTO_COMPAQ         110     /* Compaq Peer Protocol */
#define IP_PROTO_IPX            111     /* IPX over IP */
#define IP_PROTO_VRRP           112     /* Virtual Router Redundancy Protocol */
#define IP_PROTO_PGM            113     /* Pragmatic General Multicast */
/* 114 is reserved by IANA for any zero hop protocol */
#define IP_PROTO_L2TP           115     /* Layer Two Tunnelling Protocol */
#define IP_PROTO_DDX            116     /* D-II Data Exchange */
#define IP_PROTO_IATP           117     /* Interactive Agent Transfer Protocol */
#define IP_PROTO_STP            118     /* Schedule Transfer Protocol */
#define IP_PROTO_SRP            119     /* Spectralink Radio Protocol */
#define IP_PROTO_UTI            120
#define IP_PROTO_SMP            121     /* Simple Message Protocol */
#define IP_PROTO_SM             122
#define IP_PROTO_PTP            123     /* Performance Transparency Protocol */
#define IP_PROTO_ISIS           124     /* ISIS over IPv4 */
#define IP_PROTO_FIRE           125
#define IP_PROTO_CRTP           126     /* Combat Radio Transport Protocol */
#define IP_PROTO_CRUDP          127     /* Combat Radio User Datagram */
#define IP_PROTO_SSCOPMCE       128
#define IP_PROTO_IPLT           129
#define IP_PROTO_SPS            130     /* Secure Packet Shield */
#define IP_PROTO_PIPE           131     /* Private IP Encapsulation within IP */
#define IP_PROTO_SCTP           132     /* Stream Control Transmission Protocol */
#define IP_PROTO_FC             133     /* Fibre Channel */
#define IP_PROTO_RSVPE2EI       134     /* RSVP E2E Ignore - RFC3175 */
#define IP_PROTO_MIPV6          135     /* Mobile IPv6  */
#define IP_PROTO_UDPLITE        136     /* Lightweight user datagram protocol - RFC3828 */
#define IP_PROTO_MPLS_IN_IP     137     /* MPLS in IP - RFC4023 */
#define IP_PROTO_MANET          138     /* MANET Protocols */
#define IP_PROTO_HIP            139     /* Host Identity Protocol */
#define IP_PROTO_SHIM6          140     /* Shim6 Protocol */
#define IP_PROTO_WESP           141     /* 141 WESP Wrapped Encapsulating Security Payload [RFC5840] */
#define IP_PROTO_ROHC           142     /* 142 ROHC Robust Header Compression [RFC5858] */
#define IP_PROTO_AX4000         173     /* AX/4000 Testblock - non IANA */
#define IP_PROTO_NCS_HEARTBEAT  224     /* Novell NCS Heartbeat - http://support.novell.com/cgi-bin/search/searchtid.cgi?/10071158.htm */

extern value_string_ext ipproto_val_ext;
WS_DLL_PUBLIC const char *ipprotostr(const int proto);

#endif /* ipproto.h */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
