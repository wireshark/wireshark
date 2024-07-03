/** @file
 * Provides routines for encoding and decoding the extended Golay
 * (24,12,8) code.
 *
 * This implementation will detect up to 4 errors in a codeword (without
 * being able to correct them); it will correct up to 3 errors.
 *
 * We use guint32s to hold the 24-bit codewords, with the data part in
 * the bottom 12 bits and the parity in bits 12-23.
 *
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#ifndef __GOLAY_H__
#define __GOLAY_H__

#include <stdint.h>

#include "ws_symbol_export.h"

/* encodes a 12-bit word to a 24-bit codeword
 */
WS_DLL_PUBLIC
uint32_t golay_encode(unsigned w);

/* return a mask showing the bits which are in error in a received
 * 24-bit codeword, or -1 if 4 errors were detected.
 */
WS_DLL_PUBLIC
int32_t golay_errors(uint32_t codeword);

/* decode a received codeword. Up to 3 errors are corrected for; 4
   errors are detected as uncorrectable (return -1); 5 or more errors
   cause an incorrect correction.
*/
WS_DLL_PUBLIC
int golay_decode(uint32_t w);

#endif

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
