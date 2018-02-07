/* interface.c
 * Utility functions to get infos from interfaces
 *
 * Copyright 2016, Dario Lombardo
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef _INTERFACE_H
#define _INTERFACE_H

#include <glib.h>
#include "ws_symbol_export.h"

/* Return a list of IPv4/IPv6 addresses for local interfaces */
WS_DLL_PUBLIC
GSList* local_interfaces_to_list(void);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 noexpandtab:
 * :indentSize=4:tabSize=8:noTabs=false:
 */
