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

enum ws_log_domain {
     /* Default domain */
     LOG_DOMAIN_DEFAULT,
     /* Main execution domain (wireshark, tshark, etc) */
     LOG_DOMAIN_MAIN,
     /* Capture domain (except for capture child, see below) */
     LOG_DOMAIN_CAPTURE,
     /* Capture child domain (the capture child might also contain
      * file domain messages!) */
     LOG_DOMAIN_CAPCHILD,
     LOG_DOMAIN_WIRETAP,
     LOG_DOMAIN_EPAN,
     LOG_DOMAIN_WSUTIL,
     LOG_DOMAIN_QTUI,
     _LOG_DOMAIN_LAST
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
