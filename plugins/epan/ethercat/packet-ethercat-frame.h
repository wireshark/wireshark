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
DIAG_OFF_PEDANTIC
/**
 * @brief EtherCAT frame header, giving access to the 16-bit header word
 *        both as individual bit-fields and as a raw value.
 */
typedef union _EtherCATFrameParser
{
   struct
   {
      uint16_t length   : 11; /**< Total byte length of all datagrams in the frame. */
      uint16_t reserved : 1;  /**< Reserved; must be zero. */
      uint16_t protocol : 4;  /**< Protocol type identifier (0x1 = EtherCAT commands). */
   } v;                       /**< Structured bit-field access to the header. */
   uint16_t hdr;              /**< Raw 16-bit header word. */
} EtherCATFrameParserHDR;
DIAG_ON_PEDANTIC

/** @brief Pointer type for #EtherCATFrameParserHDR. */
typedef EtherCATFrameParserHDR *PEtherCATFrameParserHDR;


/** @brief Wire-size of #EtherCATFrameParserHDR in bytes. */
#define EtherCATFrameParserHDR_Len (int)sizeof(EtherCATFrameParserHDR)

#endif /* _PACKET_ETHERCAT_FRAME_H */
