/* pcap-encap.h
 * Declarations for routines to handle pcap/pcapng linktype values
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * File format support for pcapng file format
 * Copyright (c) 2007 by Ulf Lamping <ulf.lamping@web.de>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __W_PCAP_ENCAP_H__
#define __W_PCAP_ENCAP_H__

#include <glib.h>
#include <wiretap/wtap.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

WS_DLL_PUBLIC int wtap_pcap_encap_to_wtap_encap(int encap);
WS_DLL_PUBLIC int wtap_wtap_encap_to_pcap_encap(int encap);
WS_DLL_PUBLIC gboolean wtap_encap_requires_phdr(int encap);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
