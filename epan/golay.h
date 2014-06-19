/*
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
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
#ifndef __GOLAY_H__
#define __GOLAY_H__

#include "ws_symbol_export.h"

/* encodes a 12-bit word to a 24-bit codeword
 */
WS_DLL_PUBLIC
guint32 golay_encode(guint w);

/* return a mask showing the bits which are in error in a received
 * 24-bit codeword, or -1 if 4 errors were detected.
 */
WS_DLL_PUBLIC
gint32 golay_errors(guint32 codeword);

/* decode a received codeword. Up to 3 errors are corrected for; 4
   errors are detected as uncorrectable (return -1); 5 or more errors
   cause an incorrect correction.
*/
WS_DLL_PUBLIC
gint golay_decode(guint32 w);

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
