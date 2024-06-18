/* packet-ethercat-datagram.h
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _PACKET_ETHERCAT_DATAGRAM_
#define _PACKET_ETHERCAT_DATAGRAM_

/* structure for decoding the header -----------------------------------------*/
typedef union
{
   struct
   {
      uint16_t adp;
      uint16_t ado;
   } a;
   uint32_t addr;
} EcParserAddrUnion;

typedef struct _EcParser
{
   uint8_t cmd;
   uint8_t idx;
   EcParserAddrUnion anAddrUnion;
   uint16_t len;
   uint16_t intr;
} EcParserHDR, *PEcParserHDR;

#define EcParserHDR_Len 10/*sizeof(EcParserHDR)*/

#endif /* _PACKET_ETHERCAT_DATAGRAM_ */
