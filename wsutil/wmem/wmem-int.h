/** @file
 *
 * Internal definitions for the Wireshark Memory Manager
 * Copyright 2012, Evan Huus <eapache@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WMEM_INT_H__
#define __WMEM_INT_H__

#include <glib.h>

#ifdef WS_DISABLE_ASSERT
#define ASSERT(...)     (void)0
#else
#define ASSERT(...)     g_assert(__VA_ARGS__)
#endif /* WS_DISABLE_ASSERT */

#endif /* __WMEM_INT_H__ */

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
