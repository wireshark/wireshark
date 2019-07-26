/* log.h
 * log output definitions
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __LOG_H__
#define __LOG_H__

/* capture domain (except for capture child, see below) */
#define LOG_DOMAIN_CAPTURE          "Capture"

/* capture child domain (the capture child might also contain file domain messages!) */
#define LOG_DOMAIN_CAPTURE_CHILD  "CaptureChild"

/* main domain */
#define LOG_DOMAIN_MAIN           "Main"

/* enable very verbose capture log debug output */
/* (might slightly degrade performance) */
/*#define LOG_CAPTURE_VERBOSE*/

#endif

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
