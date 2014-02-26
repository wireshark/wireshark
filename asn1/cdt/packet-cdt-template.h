/* packet-cdt.h
 *
 * Routines for Compressed Data Type packet dissection.
 *
 * Copyright 2005, Stig Bjorlykke <stig@bjorlykke.org>, Thales Norway AS
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

#ifndef PACKET_CDT_H
#define PACKET_CDT_H

void dissect_cdt (tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree);
#include "packet-cdt-exp.h"

#endif  /* PACKET_CDT_H */

