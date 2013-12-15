/* dvb_chartbl.h
 * Routines for handling DVB-SI character tables (as defined in EN 300 468)
 *
 * $Id$
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
#ifndef __DVB_CHARTBL_H__
#define __DVB_CHARTBL_H__

#include "ws_symbol_export.h"

#include <epan/tvbuff.h>
#include <epan/value_string.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {

   DVB_ENCODING_LATIN = 0,
   DVB_ENCODING_ISO_8859_5,
   DVB_ENCODING_ISO_8859_6,
   DVB_ENCODING_ISO_8859_7,
   DVB_ENCODING_ISO_8859_8,
   DVB_ENCODING_ISO_8859_9,
   DVB_ENCODING_ISO_8859_10,
   DVB_ENCODING_ISO_8859_11,
   /* 0x08 is reserved */
   DVB_ENCODING_ISO_8859_13 = 9,
   DVB_ENCODING_ISO_8859_14,
   DVB_ENCODING_ISO_8859_15,

   /* TODO: 0x11...0x15 */

   DVB_ENCODING_EXT_BASE = 0x100000,
   DVB_ENCODING_EXT_ISO_8859_1  = DVB_ENCODING_EXT_BASE |  1,
   DVB_ENCODING_EXT_ISO_8859_2  = DVB_ENCODING_EXT_BASE |  2,
   DVB_ENCODING_EXT_ISO_8859_3  = DVB_ENCODING_EXT_BASE |  3,
   DVB_ENCODING_EXT_ISO_8859_4  = DVB_ENCODING_EXT_BASE |  4,
   DVB_ENCODING_EXT_ISO_8859_5  = DVB_ENCODING_EXT_BASE |  5,
   DVB_ENCODING_EXT_ISO_8859_6  = DVB_ENCODING_EXT_BASE |  6,
   DVB_ENCODING_EXT_ISO_8859_7  = DVB_ENCODING_EXT_BASE |  7,
   DVB_ENCODING_EXT_ISO_8859_8  = DVB_ENCODING_EXT_BASE |  8,
   DVB_ENCODING_EXT_ISO_8859_9  = DVB_ENCODING_EXT_BASE |  9,
   DVB_ENCODING_EXT_ISO_8859_10 = DVB_ENCODING_EXT_BASE | 10,
   DVB_ENCODING_EXT_ISO_8859_11 = DVB_ENCODING_EXT_BASE | 11,
   /* DVB_ENCODING_ISO_8859_12 = DVB_ENCODING_EXT_BASE | 12 */
   DVB_ENCODING_EXT_ISO_8859_13 = DVB_ENCODING_EXT_BASE | 13,
   DVB_ENCODING_EXT_ISO_8859_14 = DVB_ENCODING_EXT_BASE | 14,
   DVB_ENCODING_EXT_ISO_8859_15 = DVB_ENCODING_EXT_BASE | 15,

   DVB_ENCODING_INVALID   = G_MAXUINT32-3, /* length invalid */
   DVB_ENCODING_RESERVED  = G_MAXUINT32-2, /* reserved by spec */
   DVB_ENCODING_UNKNOWN   = G_MAXUINT32-1, /* not defined by spec */
} dvb_encoding_e;

extern const value_string dvb_string_encoding_vals[];

WS_DLL_PUBLIC
guint dvb_analyze_string_charset(tvbuff_t *tvb, int offset, int length,
      dvb_encoding_e *encoding);

WS_DLL_PUBLIC
guint dvb_enc_to_item_enc(dvb_encoding_e encoding);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __DVB_CHARTBL_H__ */

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
