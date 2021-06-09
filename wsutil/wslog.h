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


/*
 * XXX This API should be consolidated with ui/console.h. The way this works
 * (or doesn't) with prefs->console_log_level is also weird, because not all
 * log domains are using the same log handler. The function ws_log_full()
 * currently ignores the console log level preference.
 */

WS_DLL_PUBLIC
void ws_log_full(const char *log_domain, GLogLevelFlags log_level,
                    const char *file, int line, const char *func,
                    const char *format, ...) G_GNUC_PRINTF(6,7);

/*
 * To output debug information use the environment variable
 *   G_MESSAGES_DEBUG="<domain1> <domain2> ..." (separated with spaces)
 * to produce output for specic domains, or G_MESSAGES_DEBUG="all" for
 * all domains.
 */
#ifdef WS_DEBUG
#define ws_debug(...)   ws_log_full(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,        \
                                            __FILE__, __LINE__, G_STRFUNC,  \
                                            __VA_ARGS__)
#else
/* This avoids -Wunused warnings for variables referenced by ws_debug()
 * only. The compiler will optimize it away. */
#define ws_debug(...)    \
     G_STMT_START { if (0) ws_log_full(G_LOG_DOMAIN, G_LOG_LEVEL_DEBUG,    \
               __FILE__, __LINE__, G_STRFUNC, __VA_ARGS__); } G_STMT_END
#endif

#endif /* __WSLOG_H__ */
