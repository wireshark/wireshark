/* register.h
 * Definitions for protocol registration
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

#ifndef __REGISTER_H__
#define __REGISTER_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>

typedef enum {
  RA_NONE,              /* for initialization */
  RA_DISSECTORS,        /* Initializing dissectors */
  RA_LISTENERS,         /* Tap listeners */
  RA_REGISTER,          /* register */
  RA_PLUGIN_REGISTER,   /* plugin register */
  RA_PYTHON_REGISTER,   /* python register */
  RA_HANDOFF,           /* handoff */
  RA_PLUGIN_HANDOFF,    /* plugin handoff */
  RA_PYTHON_HANDOFF,    /* python handoff */
  RA_LUA_PLUGINS,       /* lua plugin register */
  RA_PREFERENCES,       /* module preferences */
  RA_CONFIGURATION      /* configuration files */
} register_action_e;

typedef void (*register_cb)(register_action_e action, const char *message, gpointer client_data);

WS_DLL_PUBLIC void register_all_protocols(register_cb cb, gpointer client_data);
WS_DLL_PUBLIC void register_all_protocol_handoffs(register_cb cb, gpointer client_data);
extern void register_all_tap_listeners(void);
WS_DLL_PUBLIC gulong register_count(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REGISTER_H__ */
