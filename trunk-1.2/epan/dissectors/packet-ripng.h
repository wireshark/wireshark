/* packet-ripng.h
 * RIPng definition
 * (c) Copyright Jun-ichiro itojun Hagino <itojun@itojun.org>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@ewireshark.org>
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

#ifndef __PACKET_RIPNG_H_DEFINED__
#define __PACKET_RIPNG_H_DEFINED__

#include "packet-ipv6.h"

/*
 * KAME Header: /cvsroot/kame/kame/kame/kame/route6d/route6d.h,v 1.1.1.1 1999/08/08 23:31:35 itojun Exp
 */

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#define	RIP6_VERSION	1

#define	RIP6_REQUEST	1
#define	RIP6_RESPONSE	2

struct netinfo6 {
	struct	e_in6_addr	rip6_dest;
	gushort	rip6_tag;
	guchar	rip6_plen;
	guchar	rip6_metric;
};

struct	rip6 {
	guchar	rip6_cmd;
	guchar	rip6_vers;
	guchar	rip6_res1[2];
	union {
		struct	netinfo6	ru6_nets[1];
		char	ru6_tracefile[1];
	} rip6un;
#define	rip6_nets	rip6un.ru6_nets
#define	rip6_tracefile	rip6un.ru6_tracefile
};

#define	HOPCNT_INFINITY6	16
#define	NEXTHOP_METRIC		0xff
#define	RIP6_MAXMTU		1500

#define	IFMINMTU		576

#ifndef	DEBUG
#define	SUPPLY_INTERVAL6	30
#define	RIP_LIFETIME		180
#define	RIP_HOLDDOWN		120
#define	RIP_TRIG_INT6_MAX	5
#define	RIP_TRIG_INT6_MIN	1
#else
/* only for debugging; can not wait for 30sec to appear a bug */
#define	SUPPLY_INTERVAL6	10
#define	RIP_LIFETIME		60
#define	RIP_HOLDDOWN		40
#define	RIP_TRIG_INT6_MAX	5
#define	RIP_TRIG_INT6_MIN	1
#endif

#define	RIP6_PORT		521
#define	RIP6_DEST		"ff02::9"

#define	LOOPBACK_IF		"lo0"

#endif /* __PACKET_RIPNG_H_DEFINED__ */
