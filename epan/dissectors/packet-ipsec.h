/* packet-ipsec.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_IPSEC_H__
#define __PACKET_IPSEC_H__


/* Configure a new SA (programmatically, most likely from a private dissector).
   The arugments here are deliberately in the same string formats as the UAT fields
   in order to keep code paths common.
   Note that an attempt to match with these entries will be made *before* entries
   added through the UAT entry interface/file. */
WS_DLL_PUBLIC void esp_sa_record_add_from_dissector(uint8_t protocol, const char *srcIP, const char *dstIP,
                                                    char *spi,
                                                    uint8_t encryption_algo,           /* values from esp_encryption_type_vals */
                                                    const char *encryption_key,
                                                    uint8_t authentication_algo,       /* values from esp_authentication_type_vals */
                                                    const char *authentication_key);

#endif
