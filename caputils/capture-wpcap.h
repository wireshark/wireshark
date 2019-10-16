/* capture-wpcap.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef CAPTURE_WPCAP_H
#define CAPTURE_WPCAP_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

extern gboolean has_wpcap;

extern void load_wpcap(void);

/**
 * Check to see if npf.sys is running.
 * @return TRUE if npf.sys is running, FALSE if it's not or if there was
 * an error checking its status.
 */
gboolean npf_sys_is_running(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CAPTURE_WPCAP_H */
