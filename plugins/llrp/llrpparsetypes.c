/* EPCglobal Low-Level Reader Protocol Packet Dissector
 *
 * Copyright 2008, Intermec Technologies Corp. <matt.poduska@intermec.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

#include "llrpparsetypes.h"

/* Length (in bits) of fixed-length field types */
unsigned short llrp_fixed_field_bitlength[] =
    { 0, 1, 2, 8, 8, 16, 16, 32, 32, 64, 64, 96 };

/* Length (in bits) of each item in variable-length field types */
unsigned short llrp_variable_field_bitlength[] =
    { 1, 8, 8, 8, 16, 16, 32, 32, 64, 64 };

/* Descriptions for each fixed-length field type */
char *llrp_fixed_field_name[] =
    { "none", "u1", "u2", "u8", "s8", "u16", "s16", "u32", "s32", "u64", "s64", "u96" };

/* Descriptions for each variable-length field type */
char *llrp_variable_field_name[] =
    { "u1v", "u8v", "s8v", "utf8v", "u16v", "s16v", "u32v", "s32v", "u64v", "s64v" };

/* Descriptions for each compound item type, indexed by LLRP_ITEM_* values */
char *llrp_compound_item_name[] =
    { "none", "field", "reserved", "parameter", "choice", "message" };
