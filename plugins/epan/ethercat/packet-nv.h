/* packet-nv.h
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
