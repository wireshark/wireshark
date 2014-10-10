/* catapult_dct2000.h
*
* Wiretap Library
* Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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

#ifndef __W_CAT_DCT2K_H__
#define __W_CAT_DCT2K_H__

#include <glib.h>
#include "ws_symbol_export.h"

wtap_open_return_val catapult_dct2000_open(wtap *wth, int *err, gchar **err_info);
gboolean catapult_dct2000_dump_open(wtap_dumper *wdh, int *err);
int catapult_dct2000_dump_can_write_encap(int encap);

#define DCT2000_ENCAP_UNHANDLED 0
#define DCT2000_ENCAP_SSCOP     101
#define DCT2000_ENCAP_MTP2      102
#define DCT2000_ENCAP_NBAP      103

#endif

