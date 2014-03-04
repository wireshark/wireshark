/* u3.h
 * u3   2006 Graeme Lunt
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

#ifndef __U3_H__
#define __U3_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC gboolean u3_active(void);

WS_DLL_PUBLIC void u3_runtime_info(GString *str);

WS_DLL_PUBLIC void u3_register_pid(void);
WS_DLL_PUBLIC void u3_deregister_pid(void);

WS_DLL_PUBLIC const char *u3_expand_device_path(const char *path);
WS_DLL_PUBLIC const char *u3_contract_device_path(char *path);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __U3_H__ */
