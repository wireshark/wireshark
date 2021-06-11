/* ws_log_domains.h
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

     /* Null domain */
#define LOG_DOMAIN_NONE       "(notset)"
     /* Default domain */
#define LOG_DOMAIN_DEFAULT    "Default"
     /* Main execution domain (wireshark, tshark, etc) */
#define LOG_DOMAIN_MAIN       "Main"
     /* Capture domain (except for capture child, see below) */
#define LOG_DOMAIN_CAPTURE    "Capture"
     /* Capture child domain (the capture child might also contain
      * file domain messages!) */
#define LOG_DOMAIN_CAPCHILD   "Capchild"
#define LOG_DOMAIN_WIRETAP    "Wiretap"
#define LOG_DOMAIN_EPAN       "Epan"
#define LOG_DOMAIN_WSUTIL     "WSUtil"
#define LOG_DOMAIN_QTUI        "GUI"

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
