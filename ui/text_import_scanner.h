/** @file
 *
 * text_import_scanner.h
 * Scanner for text import
 * November 2010, Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text2pcap.h by Ashok Narayanan <ashokn@cisco.com>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*
 *******************************************************************************/


#ifndef __TEXT_IMPORT_SCANNER_H__
#define __TEXT_IMPORT_SCANNER_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef enum {
    T_BYTE = 1,
    T_BYTES,
    T_OFFSET,
    T_DIRECTIVE,
    T_TEXT,
    T_EOL,
    T_EOF
} token_t;

typedef enum {
    IMPORT_SUCCESS,
    IMPORT_FAILURE,
    IMPORT_INIT_FAILED
} import_status_t;

import_status_t parse_token(token_t token, char *str);

extern FILE *text_importin;

import_status_t text_import_scan(FILE *input_file);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEXT_IMPORT_SCANNER_H__ */
