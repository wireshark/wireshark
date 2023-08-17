/* ws_log_defs.h
 * log domain definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_LOG_DOMAINS_H__
#define __WS_LOG_DOMAINS_H__

/*
 * Which log domain to use is a matter of policy. Any string is valid.
 * There are no hard rules but using a pre-defined log domain is a good
 * rule of thumb (there is no pre-defined domain below for dissectors
 * though).
 */

/* Main execution domain (wireshark, tshark, etc) */
#define LOG_DOMAIN_MAIN       "Main"

/* Capture domain (except for capture child, see below) */
#define LOG_DOMAIN_CAPTURE    "Capture"

/* Capture child domain (the capture child might also contain
 * file domain messages!) */
#define LOG_DOMAIN_CAPCHILD   "Capchild"

#define LOG_DOMAIN_WIRETAP    "Wiretap"

#define LOG_DOMAIN_EPAN       "Epan"

#define LOG_DOMAIN_DFILTER    "DFilter"

#define LOG_DOMAIN_WSUTIL     "WSUtil"

#define LOG_DOMAIN_QTUI       "GUI"

#define LOG_DOMAIN_UAT        "UAT"

#define LOG_DOMAIN_EXTCAP     "Extcap"

#define LOG_DOMAIN_UTF_8      "UTF-8"

#define LOG_DOMAIN_MMDB       "MaxMindDB"

#define LOG_DOMAIN_EINVAL     "InvalidArg"

#define LOG_DOMAIN_PLUGINS    "Plugins"

#define LOG_DOMAIN_WSLUA      "Lua"

/*
 * Ascending order by priority needs to be maintained. Higher priorities have
 * higher values.
 */
enum ws_log_level {
    LOG_LEVEL_NONE,       /* not user facing */
    LOG_LEVEL_NOISY,      /* extra verbose debugging */
    LOG_LEVEL_DEBUG,      /* normal debugging level */
    LOG_LEVEL_INFO,       /* chatty status but not debug */
    LOG_LEVEL_MESSAGE,    /* default level, doesn't show file/function name */
    LOG_LEVEL_WARNING,    /* can be set to fatal */
    LOG_LEVEL_CRITICAL,   /* always enabled, can be set to fatal */
    LOG_LEVEL_ERROR,      /* "error" is always fatal (aborts) */
    LOG_LEVEL_ECHO,       /* Always print message, never fatal */
    _LOG_LEVEL_LAST
};

#endif /* __WS_LOG_DOMAINS_H__ */

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
