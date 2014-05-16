/* ipproto.c
 * Routines for converting IPv4 protocol/IPv6 nxthdr field into string
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

#include "config.h"

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/ipproto.h>
#include <epan/addr_resolv.h>
#include <epan/dissectors/packet-ip.h>
#include <epan/strutil.h>

static const value_string ipproto_val[] = {
#if 0
    { IP_PROTO_IP,  "IPv4" },
#endif
    { IP_PROTO_HOPOPTS, "IPv6 hop-by-hop option" }, /* 0 HOPOPT IPv6 Hop-by-Hop Option [RFC1883] */
    { IP_PROTO_ICMP,    "ICMP" },                   /* 1 ICMP Internet Control Message [RFC792]  */
    { IP_PROTO_IGMP,    "IGMP" },                   /* 2 IGMP Internet Group Management [RFC1112]  */
    { IP_PROTO_GGP,     "GGP" },                    /* 3 GGP Gateway-to-Gateway [RFC823] */
    { IP_PROTO_IPIP,    "IPIP" },                   /* 4 IPv4 IPv4 encapsulation [RFC2003] */
    { IP_PROTO_STREAM,  "Stream" },                 /* 5 ST Stream [RFC1190][RFC1819] */
    { IP_PROTO_TCP,     "TCP" },                    /* 6 TCP Transmission Control [RFC793] */
    { IP_PROTO_CBT,     "CBT" },                    /* 7 CBT CBT [Tony_Ballardie] */
    { IP_PROTO_EGP,     "EGP" },                    /* 8 EGP Exterior Gateway Protocol [RFC888][David_Mills] */
    { IP_PROTO_IGP,     "IGRP" },                   /* 9 IGP any private interior gateway (used by Cisco for their IGRP) [Internet_Assigned_Numbers_Authority] */
    { IP_PROTO_BBN_RCC, "BBN RCC" },                /* 10 BBN-RCC-MON BBN RCC Monitoring [Steve_Chipman] */
    { IP_PROTO_NVPII,   "Network Voice" },          /* 11 NVP-II Network Voice Protocol [RFC741][Steve_Casner] */
    { IP_PROTO_PUP,     "PUP" },                    /* 12 PUP PUP */
    { IP_PROTO_ARGUS,   "ARGUS" },                  /* 13 ARGUS ARGUS [Robert_W_Scheifler] */
    { IP_PROTO_EMCON,   "EMCON" },                  /* 14 EMCON EMCON [<mystery contact>] */
    { IP_PROTO_XNET,    "XNET" },                   /* 15 XNET Cross Net Debugger [Haverty, J., "XNET Formats for Internet Protocol Version 4", IEN 158, October 1980.][Jack_Haverty]  */
    { IP_PROTO_CHAOS,   "CHAOS" },                  /* 16 CHAOS Chaos [J_Noel_Chiappa] */
    { IP_PROTO_UDP,     "UDP" },                    /* 17 UDP User Datagram [RFC768][Jon_Postel] */
    { IP_PROTO_MUX,     "Multiplex" },              /* 18 MUX Multiplexing [Cohen, D. and J. Postel, "Multiplexing Protocol", IEN 90, USC/Information Sciences Institute, May 1979.][Jon_Postel]  */
    { IP_PROTO_DCNMEAS, "DCN Measurement" },        /* 19 DCN-MEAS DCN Measurement Subsystems [David_Mills] */
    { IP_PROTO_HMP,     "Host Monitoring" },        /* 20 HMP Host Monitoring [RFC869][Robert_Hinden] */
    { IP_PROTO_PRM,     "Packet radio" },           /* 21 PRM Packet Radio Measurement [Zaw_Sing_Su] */
    { IP_PROTO_IDP,     "IDP" },                    /* 22 XNS-IDP XEROX NS IDP */
    { IP_PROTO_TRUNK1,  "Trunk-1" },                /* 23 TRUNK-1 Trunk-1 [Barry_Boehm] */
    { IP_PROTO_TRUNK2,  "Trunk-2" },                /* 24 TRUNK-2 Trunk-2 [Barry_Boehm] */
    { IP_PROTO_LEAF1,   "Leaf-1" },                 /* 25 LEAF-1 Leaf-1 [Barry_Boehm] */
    { IP_PROTO_LEAF2,   "Leaf-2" },                 /* 26 LEAF-2 Leaf-2 [Barry_Boehm] */
    { IP_PROTO_RDP,     "Reliable Data" },          /* 27 RDP Reliable Data Protocol [RFC908][Robert_Hinden]  */
    { IP_PROTO_IRT,     "IRT" },                    /* 28 IRTP Internet Reliable Transaction [RFC938][Trudy_Miller] */
    { IP_PROTO_TP,      "ISO TP4" },                /* 29 ISO-TP4 ISO Transport Protocol Class 4 [RFC905][<mystery contact>] */
    { IP_PROTO_BULK,    "Bulk Data" },              /* 30 NETBLT Bulk Data Transfer Protocol [RFC969][David_Clark] */
    { IP_PROTO_MFE_NSP, "MFE NSP" },                /* 31 MFE-NSP MFE Network Services Protocol */
    { IP_PROTO_MERIT,   "Merit Internodal" },       /* 32 MERIT-INP MERIT Internodal Protocol [Hans_Werner_Braun] */
    { IP_PROTO_DCCP,    "Datagram Congestion Control Protocol" }, /* 33 DCCP Datagram Congestion Control Protocol [RFC4340] */
    { IP_PROTO_3PC,     "3rd Party Connect" },      /* 34 3PC Third Party Connect Protocol [Stuart_A_Friedberg] */
    { IP_PROTO_IDPR,    "Inter-Domain Policy Routing Protocol" }, /* 35 IDPR Inter-Domain Policy Routing Protocol [Martha_Steenstrup] */
    { IP_PROTO_XTP,     "XTP" },                    /* 36 XTP XTP [Greg_Chesson] */
    { IP_PROTO_DDP,     "Datagram delivery"},       /* 37 DDP Datagram Delivery Protocol [Wesley_Craig] */
    { IP_PROTO_CMTP,    "Control Message" },        /* 38 IDPR-CMTP IDPR Control Message Transport Proto [Martha_Steenstrup] */
    { IP_PROTO_TPPP,    "TP++" },                   /* 39 TP++ TP++ Transport Protocol [Dirk_Fromhein] */
    { IP_PROTO_IL,      "IL" },                     /* 40 IL IL Transport Protocol [Dave_Presotto] */
    { IP_PROTO_IPV6,    "IPv6" },                   /* 41 IPv6 IPv6 encapsulation [RFC2473] */
    { IP_PROTO_SDRP,    "Source demand routing" },  /* 42 SDRP Source Demand Routing Protocol [Deborah_Estrin] */
    { IP_PROTO_ROUTING, "IPv6 routing" },           /* 43 IPv6-Route Routing Header for IPv6 [Steve_Deering] */
    { IP_PROTO_FRAGMENT,"IPv6 fragment" },          /* 44 IPv6-Frag Fragment Header for IPv6 [Steve_Deering] */
    { IP_PROTO_IDRP,    "Inter-Domain Routing Protocol" }, /* 45 IDRP Inter-Domain Routing Protocol [Sue_Hares] */
    { IP_PROTO_RSVP,    "Reservation Protocol" },   /* 46 RSVP Reservation Protocol [Bob_Braden] */
    { IP_PROTO_GRE,     "Generic Routing Encapsulation" }, /* 47 GRE General Routing Encapsulation [Tony_Li] */
    { IP_PROTO_DSR,     "Dynamic source routing" }, /* 48 DSR Dynamic Source Routing Protocol [RFC4728] */
    { IP_PROTO_BNA,     "BNA" },                    /* 49 BNA BNA [Gary Salamon] */
    { IP_PROTO_ESP,     "Encap Security Payload" }, /* 50 ESP Encap Security Payload [RFC4303] */
    { IP_PROTO_AH,      "Authentication Header" },  /* 51 AH Authentication Header [RFC4302] */
    { IP_PROTO_INSLP,   "INSLP" },                  /* 52 I-NLSP Integrated Net Layer Security TUBA [K_Robert_Glenn] */
    { IP_PROTO_SWIPE,   "SWIPE" },                  /* 53 SWIPE IP with Encryption [John_Ioannidis] */
    { IP_PROTO_NARP,    "NBMA ARP"},                /* 54 NARP NBMA Address Resolution Protocol [RFC1735] */
    { IP_PROTO_MOBILE,  "IP Mobility"},             /* 55 MOBILE IP Mobility [Charlie_Perkins] */
    { IP_PROTO_TLSP,    "TLSP Kryptonet" },         /* 56 TLSP Transport Layer Security Protocol using Kryptonet key management [Christer_Oberg] */
    { IP_PROTO_SKIP,    "SKIP" },                   /* 57 SKIP SKIP [Tom_Markson] */
    { IP_PROTO_ICMPV6,  "ICMPv6" },                 /* 58 IPv6-ICMP ICMP for IPv6 [RFC1883] */
    { IP_PROTO_NONE,    "IPv6 no next header" },    /* 59 IPv6-NoNxt No Next Header for IPv6 [RFC1883] */
    { IP_PROTO_DSTOPTS, "IPv6 destination option" },/* 60 IPv6-Opts Destination Options for IPv6 [RFC1883] */
    { 61, "any host internal protocol" },           /* 61  any host internal protocol [Internet_Assigned_Numbers_Authority] */
    { IP_PROTO_MIPV6_OLD, "Mobile IPv6 (old)" },    /* 62 CFTP CFTP [Forsdick, H., "CFTP", Network Message, Bolt Beranek and Newman, January 1982.][Harry_Forsdick] */
    { 63, "any local network" },                    /* 63  any local network [Internet_Assigned_Numbers_Authority] */
    { IP_PROTO_SATEXPAK,"SATNET EXPAK" },           /* 64 SAT-EXPAK SATNET and Backroom EXPAK [Steven_Blumenthal] */
    { IP_PROTO_KRYPTOLAN, "Kryptolan" },            /* 65 KRYPTOLAN Kryptolan [Paul Liu] */
    { IP_PROTO_RVD,     "Remote Virtual Disk" },    /* 66 RVD MIT Remote Virtual Disk Protocol [Michael_Greenwald] */
    { IP_PROTO_IPPC,    "IPPC" },                   /* 67 IPPC Internet Pluribus Packet Core [Steven_Blumenthal] */
    { 68, "any distributed file system" },          /* 68  any distributed file system [Internet_Assigned_Numbers_Authority]  */
    { IP_PROTO_SATMON,  "SATNET Monitoring" },      /* 69 SAT-MON SATNET Monitoring [Steven_Blumenthal] */
    { IP_PROTO_VISA,    "VISA" },                   /* 70 VISA VISA Protocol [Gene_Tsudik] */
    { IP_PROTO_IPCV,    "IPCV" },                   /* 71 IPCV Internet Packet Core Utility [Steven_Blumenthal] */
    { IP_PROTO_CPNX,    "CPNX" },                   /* 72 CPNX Computer Protocol Network Executive [David Mittnacht] */
    { IP_PROTO_CPHB,    "CPHB" },                   /* 73 CPHB Computer Protocol Heart Beat [David Mittnacht] */
    { IP_PROTO_WSN,     "Wang Span" },              /* 74 WSN Wang Span Network [Victor Dafoulas] */
    { IP_PROTO_PVP,     "Packet Video" },           /* 75 PVP Packet Video Protocol [Steve_Casner] */
    { IP_PROTO_BRSATMON,"Backroom SATNET Mon" },    /* 76 BR-SAT-MON Backroom SATNET Monitoring [Steven_Blumenthal] */
    { IP_PROTO_SUNND,   "Sun ND Protocol" },        /* 77 SUN-ND SUN ND PROTOCOL-Temporary [William_Melohn] */
    { IP_PROTO_WBMON,   "Wideband Mon" },           /* 78 WB-MON WIDEBAND Monitoring [Steven_Blumenthal] */
    { IP_PROTO_WBEXPAK, "Wideband Expak" },         /* 79 WB-EXPAK WIDEBAND EXPAK [Steven_Blumenthal] */
    { IP_PROTO_ISOIP,   "ISO Internet Protocol" },  /* 80 ISO-IP ISO Internet Protocol [Marshall_T_Rose] */
    { IP_PROTO_VMTP,    "VMTP" },                   /* 81 VMTP VMTP [Dave_Cheriton] */
    { IP_PROTO_SVMTP,   "Secure VMTP" },            /* 82 SECURE-VMTP SECURE-VMTP [Dave_Cheriton] */
    { IP_PROTO_VINES,   "VINES" },                  /* 83 VINES VINES [Brian Horn] */
    { IP_PROTO_TTP,     "TTP" },                    /* 84 TTP TTP [Jim_Stevens] */
    { IP_PROTO_NSFNETIGP,"NSFNET IGP" },            /* 85 NSFNET-IGP NSFNET-IGP [Hans_Werner_Braun] */
    { IP_PROTO_DGP,     "Dissimilar Gateway" },     /* 86 DGP Dissimilar Gateway Protocol  */
    { IP_PROTO_TCF,     "TCF" },                    /* 87 TCF TCF [Guillermo_A_Loyola] */
    { IP_PROTO_EIGRP,   "EIGRP" },                  /* 88 EIGRP EIGRP */
    { IP_PROTO_OSPF,    "OSPF IGP" },               /* 89 OSPFIGP OSPFIGP [RFC1583][John_Moy] */
    { IP_PROTO_SPRITE,  "Sprite RPC" },             /* 90 Sprite-RPC Sprite RPC Protocol */
    { IP_PROTO_LARP,    "Locus ARP" },              /* 91 LARP Locus Address Resolution Protocol [Brian Horn] */
    { IP_PROTO_MTP,     "Multicast Transport" },    /* 92 MTP Multicast Transport Protocol [Susie_Armstrong] */
    { IP_PROTO_AX25,    "AX.25 Frames" },           /* 93 AX.25 AX.25 Frames [Brian_Kantor] */
    { IP_PROTO_IPINIP,  "IP in IP" },               /* 94 IPIP IP-within-IP Encapsulation Protocol [John_Ioannidis] */
    { IP_PROTO_MICP,    "MICP" },                   /* 95 MICP Mobile Internetworking Control Pro. [John_Ioannidis] */
    { IP_PROTO_SCCCP,   "Semaphore" },              /* 96 SCC-SP Semaphore Communications Sec. Pro. [Howard_Hart] */
    { IP_PROTO_ETHERIP, "Ether in IP" },            /* 97 ETHERIP Ethernet-within-IP Encapsulation [RFC3378] */
    { IP_PROTO_ENCAP,   "ENCAP" },                  /* 98 ENCAP Encapsulation Header [RFC1241][Robert_Woodburn] */
    { 99, "any private encryption scheme" },        /* 99  any private encryption scheme [Internet_Assigned_Numbers_Authority]  */
    { IP_PROTO_GMTP,    "GMTP" },                   /* 100 GMTP GMTP [[RXB5]]  */
    { IP_PROTO_IFMP,    "Ipsilon Flow" },           /* 101 IFMP Ipsilon Flow Management Protocol [Bob_Hinden][November 1995, 1997.]  */
    { IP_PROTO_PNNI,    "PNNI over IP" },           /* 102 PNNI PNNI over IP [Ross_Callon] */
    { IP_PROTO_PIM,     "PIM" },                    /* 103 PIM Protocol Independent Multicast [Dino_Farinacci] */
    { IP_PROTO_ARIS,    "ARIS" },                   /* 104 ARIS ARIS [Nancy_Feldman] */
    { IP_PROTO_SCPS,    "SCPS" },                   /* 105 SCPS SCPS [Robert_Durst] */
    { IP_PROTO_QNX,     "QNX" },                    /* 106 QNX QNX [Michael_Hunter] */
    { IP_PROTO_AN,      "Active Networks" },        /* 107 A/N Active Networks [Bob_Braden] */
    { IP_PROTO_IPCOMP,  "IPComp" },                 /* 108 IPComp IP Payload Compression Protocol [RFC2393] */
    { IP_PROTO_SNP,     "Sitara Networks" },        /* 109 SNP Sitara Networks Protocol [Manickam_R_Sridhar] */
    { IP_PROTO_COMPAQ,  "Compaq Peer" },            /* 110 Compaq-Peer Compaq Peer Protocol [Victor_Volpe] */
    { IP_PROTO_IPX,     "IPX IN IP" },              /* 111 IPX-in-IP IPX in IP [CJ_Lee] */
    { IP_PROTO_VRRP,    "VRRP" },                   /* 112 VRRP Virtual Router Redundancy Protocol [RFC3768][RFC5798] */
    { IP_PROTO_PGM,     "PGM" },                    /* 113 PGM PGM Reliable Transport Protocol [Tony_Speakman] */
    { 114, "any 0-hop protocol" },                  /* 114  any 0-hop protocol [Internet_Assigned_Numbers_Authority] */
    { IP_PROTO_L2TP,    "Layer 2 Tunneling" },      /* 115 L2TP Layer Two Tunneling Protocol [Bernard_Aboba] */
    { IP_PROTO_DDX,     "DDX" },                    /* 116 DDX D-II Data Exchange (DDX) [John_Worley] */
    { IP_PROTO_IATP,    "IATP" },                   /* 117 IATP Interactive Agent Transfer Protocol [John_Murphy] */
    { IP_PROTO_STP,     "STP" },                    /* 118 STP Schedule Transfer Protocol [Jean_Michel_Pittet] */
    { IP_PROTO_SRP,     "SpectraLink" },            /* 119 SRP SpectraLink Radio Protocol [Mark_Hamilton] */
    { IP_PROTO_UTI,     "UTI" },                    /* 120 UTI UTI [Peter_Lothberg] */
    { IP_PROTO_SMP,     "SMP" },                    /* 121 SMP Simple Message Protocol [Leif_Ekblad] */
    { IP_PROTO_SM,      "SM" },                     /* 122 SM SM [Jon_Crowcroft] */
    { IP_PROTO_PTP,     "PTP" },                    /* 123 PTP Performance Transparency Protocol [Michael_Welzl] */
    { IP_PROTO_ISIS,    "ISIS over IP" },           /* 124 ISIS over IPv4  [Tony_Przygienda] */
    { IP_PROTO_FIRE,    "FIRE" },                   /* 125 FIRE  [Criag_Partridge] */
    { IP_PROTO_CRTP,    "CRTP" },                   /* 126 CRTP Combat Radio Transport Protocol [Robert_Sautter] */
    { IP_PROTO_CRUDP,   "CRUDP" },                  /* 127 CRUDP Combat Radio User Datagram [Robert_Sautter] */
    { IP_PROTO_SSCOPMCE,"SSCOPMCE" },               /* 128 SSCOPMCE  [Kurt_Waber] */
    { IP_PROTO_IPLT,    "IPLT" },                   /* 129 IPLT  [[Hollbach]] */
    { IP_PROTO_SPS,     "Secure Packet" },          /* 130 SPS Secure Packet Shield [Bill_McIntosh] */
    { IP_PROTO_PIPE,    "PIPE" },                   /* 131 PIPE Private IP Encapsulation within IP [Bernhard_Petri] */
    { IP_PROTO_SCTP,    "SCTP" },                   /* 132 SCTP Stream Control Transmission Protocol [Randall_R_Stewart] */
    { IP_PROTO_FC,      "Fibre Channel" },          /* 133 FC Fibre Channel [Murali_Rajagopal] */
    { IP_PROTO_RSVPE2EI,"RSVP E2EI" },              /* 134 RSVP-E2E-IGNORE  [RFC3175] */
    { IP_PROTO_MIPV6,   "Mobile IPv6" },            /* 135 Mobility Header  [RFC3775] */
    { IP_PROTO_UDPLITE, "UDPlite" },                /* 136 UDPLite  [RFC3828] */
    { IP_PROTO_MPLS_IN_IP, "MPLS in IP" },          /* 137 MPLS-in-IP  [RFC4023] */
    { IP_PROTO_MANET,   "MANET" },                  /* 138 manet MANET Protocols [RFC-ietf-manet-iana-07] */
    { IP_PROTO_HIP,     "HIP" },                    /* 139 HIP Host Identity Protocol [RFC5201] */
    { IP_PROTO_SHIM6,   "Shim6 header" },           /* 140 Shim6 Shim6 Protocol [RFC5533] */
    { IP_PROTO_WESP,    "WESP" },                   /* 141 WESP Wrapped Encapsulating Security Payload [RFC5840] */
    { IP_PROTO_ROHC,    "ROHC" },                   /* 142 ROHC Robust Header Compression [RFC5858] */
    { 143, "Unassigned" },                          /* 143 Unassigned */
    { 144, "Unassigned" },                          /* 144 Unassigned */
    { 145, "Unassigned" },                          /* 145 Unassigned */
    { 146, "Unassigned" },                          /* 146 Unassigned */
    { 147, "Unassigned" },                          /* 147 Unassigned */
    { 148, "Unassigned" },                          /* 148 Unassigned */
    { 149, "Unassigned" },                          /* 149 Unassigned */
    { 150, "Unassigned" },                          /* 150 Unassigned */
    { 151, "Unassigned" },                          /* 151 Unassigned */
    { 152, "Unassigned" },                          /* 152 Unassigned */
    { 153, "Unassigned" },                          /* 153 Unassigned */
    { 154, "Unassigned" },                          /* 154 Unassigned */
    { 155, "Unassigned" },                          /* 155 Unassigned */
    { 156, "Unassigned" },                          /* 156 Unassigned */
    { 157, "Unassigned" },                          /* 157 Unassigned */
    { 158, "Unassigned" },                          /* 158 Unassigned */
    { 159, "Unassigned" },                          /* 159 Unassigned */
    { 160, "Unassigned" },                          /* 160 Unassigned */
    { 161, "Unassigned" },                          /* 161 Unassigned */
    { 162, "Unassigned" },                          /* 162 Unassigned */
    { 163, "Unassigned" },                          /* 163 Unassigned */
    { 164, "Unassigned" },                          /* 164 Unassigned */
    { 165, "Unassigned" },                          /* 165 Unassigned */
    { 166, "Unassigned" },                          /* 166 Unassigned */
    { 167, "Unassigned" },                          /* 167 Unassigned */
    { 168, "Unassigned" },                          /* 168 Unassigned */
    { 169, "Unassigned" },                          /* 169 Unassigned */
    { 170, "Unassigned" },                          /* 170 Unassigned */
    { 171, "Unassigned" },                          /* 171 Unassigned */
    { 172, "Unassigned" },                          /* 172 Unassigned */
    { IP_PROTO_AX4000,  "AX/4000 Testframe" },      /* 173 AX/4000 Testblock - non IANA */
    { 174, "Unassigned" },                          /* 174 Unassigned */
    { 175, "Unassigned" },                          /* 175 Unassigned */
    { 176, "Unassigned" },                          /* 176 Unassigned */
    { 177, "Unassigned" },                          /* 177 Unassigned */
    { 178, "Unassigned" },                          /* 178 Unassigned */
    { 179, "Unassigned" },                          /* 179 Unassigned */
    { 180, "Unassigned" },                          /* 180 Unassigned */
    { 181, "Unassigned" },                          /* 181 Unassigned */
    { 182, "Unassigned" },                          /* 182 Unassigned */
    { 183, "Unassigned" },                          /* 183 Unassigned */
    { 184, "Unassigned" },                          /* 184 Unassigned */
    { 185, "Unassigned" },                          /* 185 Unassigned */
    { 186, "Unassigned" },                          /* 186 Unassigned */
    { 187, "Unassigned" },                          /* 187 Unassigned */
    { 188, "Unassigned" },                          /* 188 Unassigned */
    { 189, "Unassigned" },                          /* 189 Unassigned */
    { 190, "Unassigned" },                          /* 190 Unassigned */
    { 191, "Unassigned" },                          /* 191 Unassigned */
    { 192, "Unassigned" },                          /* 192 Unassigned */
    { 193, "Unassigned" },                          /* 193 Unassigned */
    { 194, "Unassigned" },                          /* 194 Unassigned */
    { 195, "Unassigned" },                          /* 195 Unassigned */
    { 196, "Unassigned" },                          /* 196 Unassigned */
    { 197, "Unassigned" },                          /* 197 Unassigned */
    { 198, "Unassigned" },                          /* 198 Unassigned */
    { 199, "Unassigned" },                          /* 199 Unassigned */
    { 200, "Unassigned" },                          /* 200 Unassigned */
    { 201, "Unassigned" },                          /* 201 Unassigned */
    { 202, "Unassigned" },                          /* 202 Unassigned */
    { 203, "Unassigned" },                          /* 203 Unassigned */
    { 204, "Unassigned" },                          /* 204 Unassigned */
    { 205, "Unassigned" },                          /* 205 Unassigned */
    { 206, "Unassigned" },                          /* 206 Unassigned */
    { 207, "Unassigned" },                          /* 207 Unassigned */
    { 208, "Unassigned" },                          /* 208 Unassigned */
    { 209, "Unassigned" },                          /* 209 Unassigned */
    { 210, "Unassigned" },                          /* 210 Unassigned */
    { 211, "Unassigned" },                          /* 211 Unassigned */
    { 212, "Unassigned" },                          /* 212 Unassigned */
    { 213, "Unassigned" },                          /* 213 Unassigned */
    { 214, "Unassigned" },                          /* 214 Unassigned */
    { 215, "Unassigned" },                          /* 215 Unassigned */
    { 216, "Unassigned" },                          /* 216 Unassigned */
    { 217, "Unassigned" },                          /* 217 Unassigned */
    { 218, "Unassigned" },                          /* 218 Unassigned */
    { 219, "Unassigned" },                          /* 219 Unassigned */
    { 220, "Unassigned" },                          /* 220 Unassigned */
    { 221, "Unassigned" },                          /* 221 Unassigned */
    { 222, "Unassigned" },                          /* 222 Unassigned */
    { 223, "Unassigned" },                          /* 223 Unassigned */
    { IP_PROTO_NCS_HEARTBEAT,"Novell NCS Heartbeat" }, /* 224 Novell NCS Heartbeat - http://support.novell.com/cgi-bin/search/searchtid.cgi?/10071158.htm */
    { 0,        NULL },
};

value_string_ext ipproto_val_ext = VALUE_STRING_EXT_INIT(ipproto_val);

const char *ipprotostr(const int proto) {
    const char *s;

    if ((s = try_val_to_str_ext(proto, &ipproto_val_ext)) != NULL)
    return s;

    s = "Unknown";

#ifdef HAVE_GETPROTOBYNUMBER
    /*
     * XXX - have another flag for resolving network-layer
     * protocol names?
     */
    if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name || gbl_resolv_flags.concurrent_dns) {
        static char buf[128];
        struct protoent *pe;

    pe = getprotobynumber(proto);
    if (pe) {
        g_strlcpy(buf, pe->p_name, sizeof(buf));
        s = buf;
    }
    }
#endif
    return s;
}

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
