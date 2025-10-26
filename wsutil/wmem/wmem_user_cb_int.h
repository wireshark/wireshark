/** @file
 *
 * Definitions for the Wireshark Memory Manager User Callback Internals
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_USER_CB_INT_H__
#define __WMEM_USER_CB_INT_H__

#include <glib.h>

#include "wmem_user_cb.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Invoke registered callbacks for a given allocator and event.
 *
 * Triggers all callbacks associated with the specified `allocator` for the given
 * `event`. This mechanism allows external components to respond to lifecycle
 * changes or memory events within the wmem system.
 *
 * @param allocator Pointer to the `wmem_allocator_t` whose callbacks should be invoked.
 * @param event The `wmem_cb_event_t` indicating the type of event to dispatch.
 *
 * @note This function is internal and typically used by the wmem subsystem to
 * propagate allocator events. It is not intended for general use.
 */
WS_DLL_LOCAL
void
wmem_call_callbacks(wmem_allocator_t *allocator, wmem_cb_event_t event);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WMEM_USER_CB_INT_H__ */

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
