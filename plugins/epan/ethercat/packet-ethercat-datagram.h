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
/**
 * @brief Union allowing an EtherCAT address to be accessed either as
 *        a split ADP/ADO pair or as a single 32-bit word.
 */
typedef union
{
   struct
   {
      uint16_t adp; /**< ADP (Auto-Increment / Configured Station Address). */
      uint16_t ado; /**< ADO (EtherCAT Register / Physical Memory Offset). */
   } a;             /**< Structured access to the address components. */
   uint32_t addr;   /**< Raw 32-bit combined address word. */
} EcParserAddrUnion;


/**
 * @brief EtherCAT datagram header, covering all addressing modes and
 *        control fields as defined by the EtherCAT specification.
 */
typedef struct _EcParser
{
   uint8_t           cmd;          /**< EtherCAT command (e.g. NOP, APRD, FPWR, BRD). */
   uint8_t           idx;          /**< Index byte used to match responses to requests. */
   EcParserAddrUnion anAddrUnion;  /**< Address field; interpretation depends on @c cmd. */
   uint16_t          len;          /**< Data length in bytes, plus flags in upper bits. */
   uint16_t          intr;         /**< Interrupt / working counter field. */
} EcParserHDR, *PEcParserHDR;


/** @brief Fixed wire-size of #EcParserHDR in bytes (sizeof is avoided due to potential padding). */
#define EcParserHDR_Len 10/*sizeof(EcParserHDR)*/

#endif /* _PACKET_ETHERCAT_DATAGRAM_ */
