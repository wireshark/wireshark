/* packet-gtp.h
 * 
 * Declarations of exported routines from GTP dissector
 * Copyright 2001, Michal Melerowicz <michal.melerowicz@nokia.com>
 *                 Nicolas Balkota <balkota@mac.com>
 *
 * $Id: packet-gtp.h,v 1.1 2002/08/26 20:22:31 guy Exp $
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#ifndef __PACKET_GTP_H__
#define __PACKET_GTP_H__

extern int decode_qos_umts(
   tvbuff_t *tvb, int offset, proto_tree *tree, gchar* qos_str, guint8 type);

#endif
