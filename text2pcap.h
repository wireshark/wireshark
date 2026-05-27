/** @file
 *
 * Utility to convert an ASCII hexdump into a libpcap-format capture file
 *
 * (c) Copyright 2001 Ashok Narayanan <ashokn@cisco.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef TEXT2PCAP_H
#define TEXT2PCAP_H

/**
 * @brief Token types produced by the bytecode/directive lexer.
 */
typedef enum {
    T_BYTE      = 1, /**< A raw byte value token */
    T_OFFSET,        /**< An offset value token */
    T_DIRECTIVE,     /**< A directive keyword token */
    T_TEXT,          /**< A plain text string token */
    T_EOL            /**< End-of-line token */
} token_t;

/**
 * @brief Parses a token from a string.
 *
 * This function takes a token type and a string as input and processes the token accordingly.
 *
 * @param token The type of token to parse.
 * @param str The string containing the token data.
 * @return int 0 on success, -1 on failure.
 */
int parse_token(token_t token, char *str);

/**
 * @brief Scans for text2pcap utility functionality.
 *
 * This function is used to scan and identify the capabilities of the text2pcap utility,
 * which converts an ASCII hexdump into a libpcap-format capture file.
 *
 * @return 0 on success, -1 on failure.
 */
int text2pcap_scan(void);

#endif

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
