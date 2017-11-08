/* register.h
 * Definitions for protocol registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __REGISTER_H__
#define __REGISTER_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>

typedef enum {
  RA_NONE,              /* For initialization */
  RA_DISSECTORS,        /* Initializing dissectors */
  RA_LISTENERS,         /* Tap listeners */
  RA_EXTCAP,            /* extcap register preferences */
  RA_REGISTER,          /* Built-in register */
  RA_PLUGIN_REGISTER,   /* Plugin register */
  RA_HANDOFF,           /* Built-in handoff */
  RA_PLUGIN_HANDOFF,    /* Plugin handoff */
  RA_LUA_PLUGINS,       /* Lua plugin register */
  RA_LUA_DEREGISTER,    /* Lua plugin deregister */
  RA_PREFERENCES,       /* Module preferences */
  RA_INTERFACES         /* Local interfaces */
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

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
