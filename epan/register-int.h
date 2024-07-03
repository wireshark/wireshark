/** @file
 * Definitions for protocol registration
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __REGISTER_INT_H__
#define __REGISTER_INT_H__

#include "register.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

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
void register_all_protocols(register_cb cb, void *client_data);

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
void register_all_protocol_handoffs(register_cb cb, void *client_data);

unsigned long register_count(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REGISTER_INT_H__ */

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
