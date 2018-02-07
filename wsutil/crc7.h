/*
 * crc7.h
 *
 * Functions and types for CRC checks.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Generated on Wed Jul 11 17:24:57 2012,
 * by pycrc v0.7.10, http://www.tty1.net/pycrc/
 * using the configuration:
 *    Width        = 7
 *    Poly         = 0x45
 *    XorIn        = 0x00
 *    ReflectIn    = False
 *    XorOut       = 0x00
 *    ReflectOut   = False
 *    Algorithm    = table-driven
 ****************************************************************************
 */
#ifndef __CRC7__H__
#define __CRC7__H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * The definition of the used algorithm.
 *****************************************************************************/
#define CRC_ALGO_TABLE_DRIVEN 1

/**
 * Calculate the initial crc value.
 *
 * \return     The initial crc value.
 *****************************************************************************/
static inline guint8 crc7init(void)
{
    return 0x00 << 1;
}


/**
 * Update the crc value with new data.
 *
 * \param crc      The current crc value.
 * \param data     Pointer to a buffer of \a data_len bytes.
 * \param data_len Number of bytes in the \a data buffer.
 * \return         The updated crc value.
 *****************************************************************************/
WS_DLL_PUBLIC guint8 crc7update(guint8 crc, const unsigned char *data, int data_len);


/**
 * Calculate the final crc value.
 *
 * \param crc  The current crc value.
 * \return     The final crc value.
 *****************************************************************************/
static inline guint8 crc7finalize(guint8 crc)
{
    return (crc >> 1) ^ 0x00;
}


#ifdef __cplusplus
}           /* closing brace for extern "C" */
#endif

#endif      /* __CRC7__H__ */
