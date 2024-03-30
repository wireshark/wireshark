/** @file
 *
 * Tap credentials data structure
 * Copyright 2019 - Dario Lombardo <lomato@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __TAP_CREDENTIALS_H__
#define __TAP_CREDENTIALS_H__

#define TAP_CREDENTIALS_PLACEHOLDER "n.a."

typedef struct tap_credential {
    unsigned num;
    unsigned username_num;
    unsigned password_hf_id;
    char* username;
    const char* proto;
    char* info;
} tap_credential_t;

#endif
