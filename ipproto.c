/* ipproto.c
 * Routines for converting IPv4 protocol/v6 nxthdr field into string
 *
 * $Id: ipproto.c,v 1.4 1999/11/21 14:43:52 gram Exp $
 *
 * Gilbert Ramirez <gram@verdict.uthscsa.edu>
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif

#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#ifdef NEED_SNPRINTF_H
# ifdef HAVE_STDARG_H
#  include <stdarg.h>
# else
#  include <varargs.h>
# endif
# include "snprintf.h"
#endif

#include <glib.h>
#include "packet.h"
#include "etypes.h"
#include "packet-ip.h"
#include "packet-ipv6.h"

static const value_string ipproto_val[] = {
    { IP_PROTO_ICMP,	"ICMP" },
    { IP_PROTO_IGMP,	"IGMP" },
    { IP_PROTO_TCP,	"TCP" },
    { IP_PROTO_UDP,	"UDP" },
    { IP_PROTO_OSPF,	"OSPF" },
#if 0
    { IP_PROTO_IP,	"IPv4" },
#endif
    { IP_PROTO_HOPOPTS,	"IPv6 hop-by-hop option" },
    { IP_PROTO_ICMP,	"ICMP" },
    { IP_PROTO_IGMP,	"IGMP" },
    { IP_PROTO_GGP,	"GGP" },
    { IP_PROTO_IPIP,	"IPIP" },
    { IP_PROTO_IPV4,	"IPv4" },
    { IP_PROTO_TCP,	"TCP" },
    { IP_PROTO_EGP,	"EGP" },
    { IP_PROTO_PUP,	"PUP" },
    { IP_PROTO_UDP,	"UDP" },
    { IP_PROTO_IDP,	"IDP" },
    { IP_PROTO_TP,	"TP" },
    { IP_PROTO_IPV6,	"IPv6" },
    { IP_PROTO_ROUTING,	"IPv6 routing" },
    { IP_PROTO_FRAGMENT,	"IPv6 fragment" },
    { IP_PROTO_RSVP,	"RSVP" },
    { IP_PROTO_GRE,	"GRE" },
    { IP_PROTO_ESP,	"ESP" },
    { IP_PROTO_AH,	"AH" },
    { IP_PROTO_ICMPV6,	"ICMPv6" },
    { IP_PROTO_NONE,	"IPv6 no next header" },
    { IP_PROTO_DSTOPTS,	"IPv6 dstination option" },
    { IP_PROTO_EON,	"EON" },
    { IP_PROTO_OSPF,	"OSPF" },
    { IP_PROTO_ENCAP,	"ENCAP" },
    { IP_PROTO_PIM,	"PIM" },
    { IP_PROTO_IPCOMP,	"IPComp" },
    { IP_PROTO_VRRP,	"VRRP" },
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
    if (g_resolving_actif) {
	pe = getprotobynumber(proto);
	if (pe) {
	    s = pe->p_name;
	    goto ok;
	}
    }
#endif

    s = "Unknown";

ok:
    snprintf(buf, sizeof(buf), "%s", s);
    return buf;
}
