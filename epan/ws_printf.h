/*
 * Wrappers for printf like functions.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_PRINTF_H__
#define __WS_PRINTF_H__

/* This is intended to fool checkAPIs.pl for places that have "debugging"
(using printf) usually wrapped in an #ifdef, but checkAPIs.pl isn't smart
enough to figure that out.
Dissectors should still try to use proto_tree_add_debug_text when the
debugging context has a protocol tree.
*/
#define ws_debug_printf     printf

#endif /* __WS_PRINTF_H__ */
