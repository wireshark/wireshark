/* ip_opts.h
 * Definitions of structures and routines for dissection of options that
 * work like IPv4 options
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

#ifndef __IP_OPTS_H__
#define __IP_OPTS_H__

#include "ws_symbol_export.h"

/** @file
 */

typedef enum {
  OPT_LEN_NO_LENGTH,                /**< option has no data, hence no length */
  OPT_LEN_FIXED_LENGTH,             /**< option always has the same length */
  OPT_LEN_VARIABLE_LENGTH           /**< option is variable-length - optlen is minimum */
} opt_len_type;



/* Quick-Start option, as defined by RFC4782 */
#define QS_FUNC_MASK        0xf0
#define QS_RATE_MASK        0x0f
#define QS_RATE_REQUEST     0
#define QS_RATE_REPORT      8

/* IP options */
#define IPOPT_COPY_MASK         0x80
#define IPOPT_CLASS_MASK        0x60
#define IPOPT_NUMBER_MASK       0x1F

WS_DLL_PUBLIC const value_string qs_func_vals[];
WS_DLL_PUBLIC value_string_ext qs_rate_vals_ext;

WS_DLL_PUBLIC const value_string ipopt_type_class_vals[];
WS_DLL_PUBLIC const value_string ipopt_type_number_vals[];

#endif
