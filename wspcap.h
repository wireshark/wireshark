/* wspcap.h
 *
 * Wrapper around libpcap/WinPcap's pcap.h.
 *
 * If HAVE_PCAP_REMOTE is defined, it forces the WinPcap header files to
 * define things required for remote capture, by defining HAVE_REMOTE.
 *
 * With all versions of the WinPcap SDK, if:
 *
 *    1) you are building with any current WinPcap SDK;
 *    2) you do not define HAVE_REMOTE before including pcap.h (or
 *       pcap/pcap.h);
 *    3) you define a struct pcap_stat and pass it to a call to
 *       pcap_stats();
 *    4) the system you're running on has WinPcap, rather than Npcap,
 *       installed;
 *
 * whatever is in memory after the struct pcap_stat may get overwritten,
 * with unpredictable results, because the pcap_stats() implementation for
 * WinPcap will assume that the structure has the additional members that
 * are added if and only if HAVE_REMOTE is defined, and will fill them in,
 * even if they're not there.
 *
 * Yes, this is q WinPcap bug; if your project has a public header file
 * that checks or otherwise uses a #define that's defined by your project's
 * configuration process, and don't ensure that it's always defined
 * appropriately when that header file is included, before its first use,
 * you have made a mistake.
 *
 * In libpcap 1.7.0 and later, the pcap_stats() implementation for WinPcap
 * will not fill those fields in; however, no WinPcap implementation was
 * based on that recent a libpcap release, so they all have the bug.
 *
 * Npcap was originally based on libpcap 1.8.0, and later releases are
 * based on later releases of libpcap, so they will not overwrite memory
 * past the end of the structure.
 *
 * The header file bug is fixed in libpcap 1.9.0 or later - the fields
 * are present on Windows, regardless of whether HAVE_REMOTE is defined
 * or not when the header is included (and are not present on UN*X), so
 * if you build with an SDK with libpcap 1.9.0 or later headers, you
 * do not need to define HAVE_REMOTE before including pcap.h (including it
 * will make no difference).
 *
 * No version of the WinPcap SDK provided libpcap 1.9.0-or-later headers.
 * The Npcap SDK, as of SDK version 1.04, provides them, so this is
 * only necessary for building with the WinPcap SDK.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2007 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WSPCAP_H__
#define __WSPCAP_H__

#ifdef HAVE_PCAP_REMOTE
#define HAVE_REMOTE
#endif

#include <pcap.h>

#endif /* __WSPCAP_H__ */
