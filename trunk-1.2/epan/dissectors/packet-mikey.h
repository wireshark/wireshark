/* packet-mikey.h
 * Routines for Multimedia Internet KEYing dissection
 * Copyright 2007, Mikael Magnusson <mikma@users.sourceforge.net>
 *
 * $Id$
 *
 * Copyright (c) 2003 by Erwin Rol <erwin@erwinrol.com>
 * Copyright (c) 2006 by Electronic Theatre Controls, Inc.
 *                    Bill Florac <bflorac@etcconnect.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1999 Gerald Combs
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
#ifndef __PACKET_MIKEY_H__
#define __PACKET_MIKEY_H__
int
dissect_mikey(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

#endif /* define __PACKET_MIKEY_H__ */
