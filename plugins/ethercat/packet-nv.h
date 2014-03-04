/* packet-nv.h
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
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

#ifndef _PACKET_NV_H_
#define _PACKET_NV_H_

/* Ensure the same data layout for all platforms*/
typedef struct _ETYPE_88A4_NV_DATA_HEADER
{
   guint16 Id;
   guint16 Hash;
   guint16 Length;
   guint16 Quality;
} ETYPE_88A4_NV_DATA_HEADER;
#define ETYPE_88A4_NV_DATA_HEADER_Len (int)sizeof(ETYPE_88A4_NV_DATA_HEADER)

typedef struct _NvParserHDR
{
   guint8  Publisher[6];
   guint16 CountNV;
   guint16 CycleIndex;
   guint16 Reserved;
} NvParserHDR;
#define NvParserHDR_Len (int)sizeof(NvParserHDR)

#endif /* _PACKET_NV_H_*/
