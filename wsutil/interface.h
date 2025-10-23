/** @file
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

/**
 * @brief Retrieves a list of local network interface IP addresses.
 *
 * Enumerates all active local network interfaces and returns a list of their associated
 * IPv4 and IPv6 addresses.
 *
 * @return A GSList containing string representations of IP addresses (IPv4 and IPv6).
 *         The list must be freed by the caller using g_slist_free() and g_free() for each element.
 */
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
