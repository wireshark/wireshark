/* eapol_keydes_types.h
 * Declarations of EAPOL Key Descriptor types
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EAPOL_KEYDES_TYPES_H__
#define __EAPOL_KEYDES_TYPES_H__

#define EAPOL_RC4_KEY           1 /* RC4 - deprecated */
#define EAPOL_RSN_KEY           2 /* 802.11i - "work in progress" */
#define EAPOL_WPA_KEY           254

#endif /* __EAPOL_KEYDES_TYPES_H__ */
