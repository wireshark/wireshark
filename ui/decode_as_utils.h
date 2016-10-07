/* decode_as_utils.h
 *
 * "Decode As" UI utility routines.
 *
 * By David Hampton <dhampton@mac.com>
 * Copyright 2001 David Hampton
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
 *
 */

#ifndef __DECODE_AS_UTILS_H__
#define __DECODE_AS_UTILS_H__

#include "ws_symbol_export.h"

/** @file
 *  "Decode As" / "User Specified Decodes" dialog box.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
* This is the template for the decode as option; it is shared between the
* various functions that output the usage for this parameter.
*/
#define DECODE_AS_ARG_TEMPLATE "<layer_type>==<selector>,<decode_as_protocol>"

gboolean decode_as_command_option(const gchar *cl_param);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __DECODE_AS_UTILS_H__ */

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
