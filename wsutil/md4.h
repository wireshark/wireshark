/*
   Unix SMB/CIFS implementation.
   a implementation of MD4 designed for use in the SMB authentication protocol
   Copyright (C) Andrew Tridgell 1997-1998.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/

#ifndef	_MD4_H
#define	_MD4_H

#include "ws_symbol_export.h"

WS_DLL_PUBLIC
void crypt_md4(unsigned char *out, const unsigned char *in, size_t n);

#endif
