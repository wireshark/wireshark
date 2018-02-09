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
      guint16 adp;
      guint16 ado;
   } a;
   guint32 addr;
} EcParserAddrUnion;

typedef struct _EcParser
{
   guint8  cmd;
   guint8  idx;
   EcParserAddrUnion anAddrUnion;
   guint16 len;
   guint16 intr;
} EcParserHDR, *PEcParserHDR;

#define EcParserHDR_Len 10/*sizeof(EcParserHDR)*/

#endif /* _PACKET_ETHERCAT_DATAGRAM_ */
