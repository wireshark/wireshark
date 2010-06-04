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

#ifndef _LLRP_MISCELLANEOUS_H
#define _LLRP_MISCELLANEOUS_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

char *llrp_field_type_to_name(unsigned char type);
char *llrp_enumeration_to_name(t_llrp_enumeration *enumeration, unsigned short value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* _LLRP_MISCELLANEOUS_H */

