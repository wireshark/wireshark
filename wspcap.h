/* wspcap.h
 *
 * Wrapper around libpcap/WinPcap's pcap.h.
 *
 * If HAVE_PCAP_REMOTE is defined, it force the WinPcap header files to
 * define things required for remote capture.
 *
 * Yes, this is q WinPcap bug; if your project has a public header file
 * that checks or otherwise uses a #define that's defined by your project's
 * configuration process, and don't ensure that it's always defined
 * appropriately when that header file is included, before its first use,
 * you have made a mistake.
 *
 * This bug is fixed in the master branch of libpcap, so any libpcap
 * release with remote capture support will not have this problem, and
 * any future WinPcap/Npcap release based on current libpcap code will
 * not have this problem.
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
