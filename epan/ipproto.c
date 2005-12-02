/* ipproto.c
 * Routines for converting IPv4 protocol/v6 nxthdr field into string
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include <glib.h>

#include <epan/ipproto.h>
#include <epan/packet.h>
#include <epan/addr_resolv.h>
#include <epan/dissectors/packet-ip.h>

static const value_string ipproto_val[] = {
#if 0
    { IP_PROTO_IP,	"IPv4" },
#endif
    { IP_PROTO_HOPOPTS,	"IPv6 hop-by-hop option" },
    { IP_PROTO_ICMP,	"ICMP" },
    { IP_PROTO_IGMP,	"IGMP" },
    { IP_PROTO_GGP,	"GGP" },
    { IP_PROTO_IPIP,	"IPIP" },
#if 0
    { IP_PROTO_IPV4,	"IPv4" },
#endif
    { IP_PROTO_STREAM,  "Stream" },
    { IP_PROTO_TCP,	"TCP" },
    { IP_PROTO_CBT,     "CBT" },
    { IP_PROTO_EGP,	"EGP" },
    { IP_PROTO_IGP,	"IGRP" },
    { IP_PROTO_BBN_RCC, "BBN RCC" },
    { IP_PROTO_NVPII,   "Network Voice" },
    { IP_PROTO_PUP,	"PUP" },
    { IP_PROTO_ARGUS,   "ARGUS" },
    { IP_PROTO_EMCON,   "EMCON" },
    { IP_PROTO_XNET,    "XNET" },
    { IP_PROTO_CHAOS,   "CHAOS" },
    { IP_PROTO_UDP,	"UDP" },
    { IP_PROTO_MUX,     "Multiplex" },
    { IP_PROTO_DCNMEAS, "DCN Measurement" },
    { IP_PROTO_HMP,     "Host Monitoring" },
    { IP_PROTO_PRM,     "Packet radio" },
    { IP_PROTO_IDP,	"IDP" },
    { IP_PROTO_TRUNK1,  "Trunk-1" },
    { IP_PROTO_TRUNK2,  "Trunk-2" },
    { IP_PROTO_LEAF1,   "Leaf-1" },
    { IP_PROTO_LEAF2,   "Leaf-2" },
    { IP_PROTO_RDP,     "Reliable Data" },
    { IP_PROTO_IRT,     "IRT" },
    { IP_PROTO_TP,	"ISO TP4" },
    { IP_PROTO_BULK,    "Bulk Data" },
    { IP_PROTO_MFE_NSP, "MFE NSP" },
    { IP_PROTO_MERIT,   "Merit Internodal" },
#if 0
    { IP_PROTO_SEP,     "Sequential Exchange" },
#endif
    { IP_PROTO_DCCP,    "Datagram Congestion Control Protocol" },
    { IP_PROTO_3PC,     "3rd Party Connect" },
    { IP_PROTO_IDPR,    "Interdomain routing" },
    { IP_PROTO_XTP,     "XTP" },
    { IP_PROTO_DDP,     "Datagram delivery"},
    { IP_PROTO_CMTP,    "Control Message" },
    { IP_PROTO_TPPP,    "TP++" },
    { IP_PROTO_IL,      "IL" },
    { IP_PROTO_IPV6,	"IPv6" },
    { IP_PROTO_SDRP,    "Source demand routing" },
    { IP_PROTO_ROUTING,	"IPv6 routing" },
    { IP_PROTO_FRAGMENT,"IPv6 fragment" },
    { IP_PROTO_IDRP,    "IDRP" },
    { IP_PROTO_RSVP,	"RSVP" },
    { IP_PROTO_GRE,	"GRE" },
    { IP_PROTO_MHRP,    "MHRP" },
    { IP_PROTO_BNA,     "BNA" },
    { IP_PROTO_ESP,	"ESP" },
    { IP_PROTO_AH,	"AH" },
    { IP_PROTO_INSLP,   "INSLP" },
    { IP_PROTO_SWIPE,   "SWIPE" },
    { IP_PROTO_NARP,    "NBMA ARP"},
    { IP_PROTO_TLSP,    "TLSP Kryptonet" },
    { IP_PROTO_SKIP,    "SKIP" },
    { IP_PROTO_ICMPV6,	"ICMPv6" },
    { IP_PROTO_NONE,	"IPv6 no next header" },
    { IP_PROTO_DSTOPTS,	"IPv6 destination option" },
    { IP_PROTO_MIPV6_OLD, "Mobile IPv6 (old)" },
    { IP_PROTO_SATEXPAK,"SATNET EXPAK" },
    { IP_PROTO_KRYPTOLAN, "Kryptolan" },
    { IP_PROTO_RVD,     "Remote Virtual Disk" },
    { IP_PROTO_IPPC,    "IPPC" },
    { IP_PROTO_SATMON,  "SATNET Monitoring" },
    { IP_PROTO_VISA,    "VISA" },
    { IP_PROTO_IPCV,    "IPCV" },
    { IP_PROTO_CPNX,    "CPNX" },
    { IP_PROTO_CPHB,    "CPHB" },
    { IP_PROTO_WSN,     "Wang Span" },
    { IP_PROTO_PVP,     "Packet Video" },
    { IP_PROTO_BRSATMON,"Backroom SATNET Mon" },
    { IP_PROTO_SUNND,   "Sun ND Protocol" },
    { IP_PROTO_WBMON,   "Wideband Mon" },
    { IP_PROTO_WBEXPAK, "Wideband Expak" },
    { IP_PROTO_EON,	"EON" },
    { IP_PROTO_VMTP,    "VMTP" },
    { IP_PROTO_SVMTP,   "Secure VMTP" },
    { IP_PROTO_VINES,	"VINES" },
    { IP_PROTO_TTP,     "TTP" },
    { IP_PROTO_NSFNETIGP,"NSFNET IGP" },
    { IP_PROTO_DGP,     "Dissimilar Gateway" },
    { IP_PROTO_TCF,     "TCF" },
    { IP_PROTO_EIGRP,	"EIGRP" },
    { IP_PROTO_OSPF,	"OSPF IGP" },
    { IP_PROTO_SPRITE,  "Sprite RPC" },
    { IP_PROTO_LARP,    "Locus ARP" },
    { IP_PROTO_MTP,     "Multicast Transport" },
    { IP_PROTO_AX25,    "AX.25 Frames" },
    { IP_PROTO_IPINIP,  "IP in IP" },
    { IP_PROTO_MICP,    "MICP" },
    { IP_PROTO_SCCCP,   "Semaphore" },
    { IP_PROTO_ETHERIP, "Ether in IP" },
    { IP_PROTO_ENCAP,	"ENCAP" },
    { IP_PROTO_GMTP,    "GMTP" },
    { IP_PROTO_IFMP,    "Ipsilon Flow" },
    { IP_PROTO_PNNI,    "PNNI over IP" },
    { IP_PROTO_PIM,	"PIM" },
    { IP_PROTO_ARIS,    "ARIS" },
    { IP_PROTO_SCPS,    "SCPS" },
    { IP_PROTO_QNX,     "QNX" },
    { IP_PROTO_AN,      "Active Networks" },
    { IP_PROTO_IPCOMP,	"IPComp" },
    { IP_PROTO_SNP,     "Sitara Networks" },
    { IP_PROTO_COMPAQ,  "Compaq Peer" },
    { IP_PROTO_IPX,     "IPX IN IP" },
    { IP_PROTO_VRRP,	"VRRP" },
    { IP_PROTO_PGM,     "PGM" },
    { IP_PROTO_L2TP,    "Layer 2 Tunneling" },
    { IP_PROTO_DDX,     "DDX" },
    { IP_PROTO_IATP,    "IATP" },
    { IP_PROTO_STP,     "STP" },
    { IP_PROTO_SRP,     "SpectraLink" },
    { IP_PROTO_UTI,     "UTI" },
    { IP_PROTO_SMP,     "SMP" },
    { IP_PROTO_SM,      "SM" },
    { IP_PROTO_PTP,     "PTP" },
    { IP_PROTO_ISIS,    "ISIS over IP" },
    { IP_PROTO_FIRE,    "FIRE" },
    { IP_PROTO_CRTP,    "CRTP" },
    { IP_PROTO_CRUDP,   "CRUDP" },
    { IP_PROTO_SSCOPMCE,"SSCOPMCE" },
    { IP_PROTO_IPLT,    "IPLT" },
    { IP_PROTO_SPS,     "Secure Packet" },
    { IP_PROTO_PIPE,    "PIPE" },
    { IP_PROTO_SCTP,    "SCTP" },
    { IP_PROTO_FC,      "Fibre Channel" },
    { IP_PROTO_RSVPE2EI,"RSVP E2EI" },
    { IP_PROTO_MIPV6,	"Mobile IPv6" },
    { IP_PROTO_UDPLITE, "UDPlite" },
    { IP_PROTO_MPLS_IN_IP, "MPLS in IP" },
    { IP_PROTO_AX4000,	"AX/4000 Testframe" },
    { IP_PROTO_NCS_HEARTBEAT,"Novell NCS Heartbeat" },
    { 0,		NULL },
};

const char *ipprotostr(int proto) {
    static char buf[128];
    const char *s;
#ifdef HAVE_GETPROTOBYNUMBER
    struct protoent *pe;
#endif

    if ((s = match_strval(proto, ipproto_val)) != NULL)
	goto ok;

#ifdef HAVE_GETPROTOBYNUMBER
    /*
     * XXX - have another flag for resolving network-layer
     * protocol names?
     */
    if (g_resolv_flags != 0) {
	pe = getprotobynumber(proto);
	if (pe) {
	    s = pe->p_name;
	    goto ok;
	}
    }
#endif

    s = "Unknown";

ok:
    g_snprintf(buf, sizeof(buf), "%s", s);
    return buf;
}
