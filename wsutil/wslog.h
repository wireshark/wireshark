/*
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2021 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSLOG_H__
#define __WSLOG_H__

#include <ws_symbol_export.h>
#include <glib.h>

WS_DLL_PUBLIC
void ws_log_full(const char *log_domain, GLogLevelFlags log_level,
                    const char *file, int line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);

/*
 * To output debug information use the environment variable
 *   G_MESSAGES_DEBUG="<domain1> <domain2> ..." (separated with spaces)
 * to produce output for specic domains, or G_MESSAGES_DEBUG="all" for
 * all domains.
 *
 * Any variable that is only used with ws_debug() needs to be guarded
 * with #if WS_DEBUG.
 */
#if WS_DEBUG
#define ws_debug(...)   ws_log_full(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,        \
                                            __FILE__, __LINE__, G_STRFUNC,  \
                                            __VA_ARGS__)
#else
#define ws_debug(...)   ((void)0)
#endif

#endif /* __WSLOG_H__ */
