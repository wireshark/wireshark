/*
 * crc11.h
 * http://www.tty1.net/pycrc/faq_en.html#code-ownership
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef __CRC11_____H__

#include <glib.h>

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif
/**
 * Functions and types for CRC checks.
 *
 * Generated on Tue Aug  7 15:45:57 2012,
 * by pycrc v0.7.10, http://www.tty1.net/pycrc/
 * using the configuration:
 *    Width        = 11
 *    Poly         = 0x307
 *    XorIn        = 0x000
 *    ReflectIn    = False
 *    XorOut       = 0x000
 *    ReflectOut   = False
 *    Algorithm    = table-driven
 *****************************************************************************/
WS_DLL_PUBLIC
guint16 crc11_307_noreflect_noxor(const guint8 *data, guint64 data_len);

#ifdef __cplusplus
}           /* closing brace for extern "C" */
#endif

#endif /*__CRC11_____H__*/
