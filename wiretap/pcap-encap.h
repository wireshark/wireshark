/** @file
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

#include "wtap.h"
#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Converts a PCAP encapsulation type to a Wireshark encapsulation type.
 *
 * @param encap The PCAP encapsulation type.
 * @return int The corresponding Wireshark encapsulation type, or WTAP_ENCAP_UNKNOWN if not found.
 */
WS_DLL_PUBLIC int wtap_pcap_encap_to_wtap_encap(int encap);

/**
 * @brief Converts a Wireshark encapsulation type to a PCAP encapsulation type.
 *
 * @param encap The Wireshark encapsulation type.
 * @return int The corresponding PCAP encapsulation type, or -1 if not found.
 */
int wtap_wtap_encap_to_pcap_encap(int encap);

/**
 * @brief Checks if a given encapsulation type requires a pseudo-header.
 *
 * @param encap The encapsulation type.
 * @return bool true if the encapsulation type requires a pseudo-header, false otherwise.
 */
WS_DLL_PUBLIC bool wtap_encap_requires_phdr(int encap);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
