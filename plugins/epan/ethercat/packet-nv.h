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
   uint16_t Id;
   uint16_t Hash;
   uint16_t Length;
   uint16_t Quality;
} ETYPE_88A4_NV_DATA_HEADER;
#define ETYPE_88A4_NV_DATA_HEADER_Len (int)sizeof(ETYPE_88A4_NV_DATA_HEADER)

typedef struct _NvParserHDR
{
   uint8_t Publisher[6];
   uint16_t CountNV;
   uint16_t CycleIndex;
   uint16_t Reserved;
} NvParserHDR;
#define NvParserHDR_Len (int)sizeof(NvParserHDR)

#endif /* _PACKET_NV_H_*/
