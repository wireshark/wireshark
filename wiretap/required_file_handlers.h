/* required_file_handlers.h
 * Functions and variables defined by required file handlers (pcap,
 * nanosecond pcap, pcapng).
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __REQUIRED_FILE_HANDLERS_H__
#define __REQUIRED_FILE_HANDLERS_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * These are for use within libwiretap only; they are not exported.
 */
extern void register_pcap(void);
extern void register_pcapng(void);

extern int pcap_file_type_subtype;	/* regular pcap */
extern int pcap_nsec_file_type_subtype;	/* pcap with nanosecond resolution */
extern int pcapng_file_type_subtype;	/* pcapng */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REQUIRED_FILE_HANDLERS_H__ */
