/* crcdrm.h
 * another CRC 16
 * Copyright 2006, British Broadcasting Corporation
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

#ifndef __CRCDRM_H__
#define __CRCDRM_H__


#include "ws_symbol_export.h"

WS_DLL_PUBLIC
unsigned long crc_drm(const char *data, size_t bytesize,
	unsigned short num_crc_bits, unsigned long crc_gen, int invert);

#endif /* __CRCDRM_H__ */
