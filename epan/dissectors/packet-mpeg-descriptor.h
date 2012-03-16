/* packet-mpeg-descriptor.c
 * Routines for MPEG2 (ISO/ISO 13818-1) dissectors
 * Copyright 2012, Guy Martin <gmsoft@tuxicoman.be>
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */


#ifndef __PACKET_MPEG_DESCRIPTOR_H_
#define __PACKET_MPEG_DESCRIPTOR_H_

#include <glib.h>
#include <epan/packet.h>

guint proto_mpeg_descriptor_dissect(tvbuff_t *tvb, guint offset, proto_tree *tree);

#endif
