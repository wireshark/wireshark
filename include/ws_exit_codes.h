/** @file
 *
 * Definition of exit codes for programs.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_EXIT_CODES_H__
#define __WS_EXIT_CODES_H__

/* Exit codes */
#define WS_EXIT_INVALID_OPTION               1
#define WS_EXIT_INVALID_INTERFACE            2
#define WS_EXIT_INVALID_FILE                 3
#define WS_EXIT_INVALID_FILTER               4
#define WS_EXIT_INVALID_CAPABILITY           5
#define WS_EXIT_IFACE_HAS_NO_LINK_TYPES      6
#define WS_EXIT_IFACE_HAS_NO_TIMESTAMP_TYPES 7
#define WS_EXIT_INIT_FAILED                  8
#define WS_EXIT_OPEN_ERROR                   9
#define WS_EXIT_PCAP_NOT_SUPPORTED           10
#define WS_EXIT_DUMPCAP_NOT_SUPPORTED        11
#define WS_EXIT_NO_INTERFACES                12
#define WS_EXIT_PCAP_ERROR                   13
#define WS_EXIT_READ_ERROR                   14
#define WS_EXIT_WRITE_ERROR                  15
#define WS_EXIT_PRINT_ERROR                  16
#define WS_EXIT_CAPTURE_ERROR                17
#define WS_EXIT_OUT_OF_MEMORY                18

/*
 * Not an exit code; returned by some routines to indicate that the
 * program was asked to print some stuff out and then exit, and that
 * the stuff's been printed successfully and there's nothing more
 * to do, so the caller should just exit now.
 *
 * An exit code out of the range of valid UN*X exit codes is used,
 * so we don't have to shuffle it if we add a new real exit code.
 */
#define WS_EXIT_NOW                          256

#endif /* __WS_EXIT_CODES_H__ */
