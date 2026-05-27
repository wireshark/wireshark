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

#pragma once

#define CREDENTIALS_PLACEHOLDER "n.a."

/**
 * @brief Represents a single set of credentials captured from a dissected protocol exchange.
 */
typedef struct tap_credential {
    unsigned num;             /**< Packet number in which the credential was observed */
    unsigned username_num;    /**< Packet number in which the username was observed (may differ from @p num) */
    unsigned password_hf_id;  /**< Header field ID (hf index) of the password field in the dissector */
    char    *username;        /**< Extracted username string */
    const char *proto;        /**< Protocol name from which the credential was harvested (e.g. "FTP", "HTTP") */
    char    *info;            /**< Optional human-readable context or annotation about this credential */
} tap_credential_t;
