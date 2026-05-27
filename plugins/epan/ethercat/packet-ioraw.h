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

/**
 * @brief Minimal header struct used exclusively for wire size and field offset calculations in the raw I/O parser; not overlaid onto packet data directly.
 */
typedef struct _IoRawParser
{
    uint32_t head; /**< First 32-bit word of the raw parser header, used as an anchor for size and offset derivation. */
} IoRawParserHDR, *PIoRawParserHDR;
#define IoRawParserHDR_Len (int)sizeof(IoRawParserHDR) /**< Wire size in bytes of IoRawParserHDR. */

#endif /* _PACKET_IORAW_H_*/
