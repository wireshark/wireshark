/** @file
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

#ifdef HAVE_LIBPCAP
#ifdef __MINGW32__
#include <_bsd_types.h>
#endif
#include <pcap.h>
#endif

extern bool has_wpcap;

extern void load_wpcap(void);

/**
 * Check to see if npf.sys is running.
 * @return true if npf.sys is running, false if it's not or if there was
 * an error checking its status.
 */
bool npf_sys_is_running(void);

#ifdef HAVE_LIBPCAP
int
ws_pcap_findalldevs_ex(const char *a, struct pcap_rmtauth *b, pcap_if_t **c, char *errbuf);
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* CAPTURE_WPCAP_H */
