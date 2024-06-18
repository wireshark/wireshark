/* packet-ioraw.h
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _PACKET_IORAW_H_
#define _PACKET_IORAW_H_

/* headers are only used for size and offset calculation*/
typedef struct _IoRawParser
{
   uint32_t head;
} IoRawParserHDR, *PIoRawParserHDR;
#define IoRawParserHDR_Len (int)sizeof(IoRawParserHDR)

#endif /* _PACKET_IORAW_H_*/
