/* ipv6-utils.h
 * Definitions for IPv6 packet disassembly 
 *
 * $Id: ipv6-utils.h,v 1.1 2001/04/01 07:06:23 hagbard Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 *
 * Copyright 1998 Gerald Combs
 *
 * MobileIPv6 support added by Tomislav Borosa <tomislav.borosa@siemens.hr>
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

#ifndef __IPV6_UTILS_H__
#define __IPV6_UTILS_H__

struct e_in6_addr {
	union {
		guint32  u6_addr32[4];
		guint16  u6_addr16[8];
		guint8   u6_addr8[16];
	} u6_addr;			/* 128 bit IP6 address */
};

#ifdef s6_addr32
#undef s6_addr32
#endif

#ifdef s6_addr16
#undef s6_addr16
#endif

#ifdef s6_addr8
#undef s6_addr8
#endif

#ifdef s6_addr
#undef s6_addr
#endif

#define s6_addr32 u6_addr.u6_addr32
#define s6_addr16 u6_addr.u6_addr16
#define s6_addr8  u6_addr.u6_addr8
#define s6_addr   u6_addr.u6_addr8

#endif /* __IPV6_UTILS_H__ */
