/* packet-rf4ce-common.h
 * Common functions and objects for RF4CE dissector
 * Copyright (C) Atmosic 2023
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef PACKET_RF4CE_COMMON_H
#define PACKET_RF4CE_COMMON_H

#include <epan/value_string.h>

extern const value_string rf4ce_yes_no_vals[];
extern const value_string rf4ce_en_dis_vals[];

#define RF4CE_PROTOABBREV_NWK     "rf4ce_nwk"
#define RF4CE_PROTOABBREV_PROFILE "rf4ce_profile"

/* Profile IDs */
#define RF4CE_NWK_PROFILE_ID_GDP   0x00
#define RF4CE_NWK_PROFILE_ID_ZRC10 0x01
#define RF4CE_NWK_PROFILE_ID_ZID   0x02
#define RF4CE_NWK_PROFILE_ID_ZRC20 0x03

#define RF4CE_IEEE_ADDR_LEN  8
#define RF4CE_SHORT_ADDR_LEN 2

#ifdef RF4CE_DEBUG_EN
void rf4ce_print_arr(const gchar *str, guint8 *ptr, guint16 len);
#define RF4CE_PRINT_ARR(s, p, l) rf4ce_print_arr(s, p, l)
#else
#define RF4CE_PRINT_ARR(s, p, l)
#endif /* RF4CE_DEBUG_EN */

#endif /* PACKET_RF4CE_COMMON_H */
