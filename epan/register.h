/** @file
 *
 * Definitions for protocol registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#pragma once
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Identifies the current registration or initialization phase during Wireshark startup.
 */
typedef enum {
    RA_NONE,             /**< No action in progress; used for initialization */
    RA_DISSECTORS,       /**< Initializing the dissector framework */
    RA_LISTENERS,        /**< Registering tap listeners */
    RA_EXTCAP,           /**< Registering extcap plugin preferences */
    RA_REGISTER,         /**< Running built-in dissector registration routines */
    RA_PLUGIN_REGISTER,  /**< Running plugin dissector registration routines */
    RA_HANDOFF,          /**< Running built-in dissector handoff routines */
    RA_PLUGIN_HANDOFF,   /**< Running plugin dissector handoff routines */
    RA_LUA_PLUGINS,      /**< Registering Lua plugins */
    RA_LUA_DEREGISTER,   /**< Deregistering Lua plugins */
    RA_PREFERENCES,      /**< Loading and registering module preferences */
    RA_INTERFACES,       /**< Enumerating local capture interfaces */
    RA_PREFERENCES_APPLY /**< Applying preferences that have been changed */
} register_action_e;

#define RA_BASE_COUNT (RA_INTERFACES - 3) // RA_EXTCAP, RA_LUA_PLUGINS, RA_LUA_DEREGISTER

typedef void (*register_cb)(register_action_e action, const char *message, void *client_data);
typedef void (*register_entity_func)(register_cb cb, void* client_data);


/** Call each dissector's protocol registration routine.
 *
 * Each routine is called in alphabetical order from a worker thread.
 * Registration routines might call any number of routines which are not
 * thread safe, such as wmem_alloc. Callbacks should handle themselves
 * accordingly.
 *
 * @param cb Callback routine which is called for each protocol.
 * Messages have the format "proto_register_XXX".
 * @param client_data Data pointer for the callback.
 */
WS_DLL_PUBLIC
void register_all_protocols(register_cb cb, void* client_data);

/** Call each dissector's protocol handoff routine.
 *
 * Each routine is called from a worker thread. Registration routines
 * might call any number of routines which are not thread safe, such as
 * wmem_alloc. Callbacks should handle themselves accordingly.
 *
 * @param cb Callback routine which is called for each protocol.
 * Messages have the format "proto_reg_handoff_XXX".
 * @param client_data Data pointer for the callback.
 */
WS_DLL_PUBLIC
void register_all_protocol_handoffs(register_cb cb, void* client_data);


/** Call each event dissector's registration routine.
 *
 * Each routine is called in alphabetical order from a worker thread.
 * Registration routines might call any number of routines which are not
 * thread safe, such as wmem_alloc. Callbacks should handle themselves
 * accordingly.
 *
 * @param cb Callback routine which is called for each protocol.
 * Messages have the format "event_register_XXX".
 * @param client_data Data pointer for the callback.
 */
WS_DLL_PUBLIC
void register_all_event_dissectors(register_cb cb, void* client_data);

/** Call each event dissector's handoff routine.
 *
 * Each routine is called from a worker thread. Registration routines
 * might call any number of routines which are not thread safe, such as
 * wmem_alloc. Callbacks should handle themselves accordingly.
 *
 * @param cb Callback routine which is called for each protocol.
 * Messages have the format "event_reg_handoff_XXX".
 * @param client_data Data pointer for the callback.
 */
WS_DLL_PUBLIC
void register_all_event_dissectors_handoffs(register_cb cb, void* client_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
