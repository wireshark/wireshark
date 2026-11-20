/* packet-ethercat-frame.h
 *
 * Copyright (c) 2007 by Beckhoff Automation GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef _PACKET_ETHERCAT_FRAME_H
#define _PACKET_ETHERCAT_FRAME_H

#include <ws_diag_control.h>

/* structure for decoding the header -----------------------------------------*/
/**
 * @brief EtherCAT frame header: the 16-bit header word, as read with
 *        tvb_get_letohs(). Use ETHERCAT_FRAME_LENGTH() and
 *        ETHERCAT_FRAME_PROTOCOL() to get its fields (not bit-fields,
 *        whose layout depends on the compiler and the host byte order).
 */
typedef struct _EtherCATFrameParser
{
   uint16_t hdr;              /**< Raw 16-bit header word. */
} EtherCATFrameParserHDR;

/** @brief Total byte length of all datagrams in the frame. */
#define ETHERCAT_FRAME_LENGTH(hdr)   ((hdr) & 0x7FF)
/** @brief Protocol type identifier (0x1 = EtherCAT commands). */
#define ETHERCAT_FRAME_PROTOCOL(hdr) (((hdr) >> 12) & 0xF)

/** @brief Pointer type for #EtherCATFrameParserHDR. */
typedef EtherCATFrameParserHDR *PEtherCATFrameParserHDR;


/** @brief Wire-size of #EtherCATFrameParserHDR in bytes. */
#define EtherCATFrameParserHDR_Len (int)sizeof(EtherCATFrameParserHDR)

#endif /* _PACKET_ETHERCAT_FRAME_H */
