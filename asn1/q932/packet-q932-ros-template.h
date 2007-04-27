/* packet-q932-ros.h
 * Routines for Q.932 packet dissection
 * 2007  Tomas Kukosa
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef PACKET_ROSE_H
#define PACKET_ROSE_H

#include "epan/packet.h"

typedef struct _rose_context {
  int apdu_depth;
  dissector_table_t arg_global_dissector_table;
  dissector_table_t arg_local_dissector_table; 
  dissector_table_t res_global_dissector_table;
  dissector_table_t res_local_dissector_table; 
} rose_context;

int dissect_rose_apdu(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, rose_context *rctx);

#endif  /* PACKET_ROSE_H */

