/* resolv.h
 * Definitions for network object lookup
 *
 * $Id: resolv.h,v 1.2 1998/09/16 03:22:18 gerald Exp $
 *
 * Laurent Deniel <deniel@worldnet.fr>
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

#ifndef __RESOLV_H__
#define __RESOLV_H__

/* global variable */

extern int g_resolving_actif;

/* Functions in resolv.c */

extern u_char *get_udp_port(u_int port);
extern u_char *get_tcp_port(u_int port);
extern u_char *get_hostname(u_int addr);

#endif /* __RESOLV_H__ */
