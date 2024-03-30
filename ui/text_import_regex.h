/** @file
 *
 * text_import_regex.h
 * Regex based alternative to the state machine for text import
 * February 2021, Paul Weiß <paulniklasweiss@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text_import.h by Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*
 *******************************************************************************/


#ifndef __TEXT_IMPORT_REGEX_H__
#define __TEXT_IMPORT_REGEX_H__

#include <glib.h>

#include "text_import.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

void parse_data(unsigned char* start_field, unsigned char* end_field, enum data_encoding encoding);

void parse_dir(const unsigned char* start_field, const unsigned char* end_field, const char* in_indicator, const char* out_indicator);

void parse_time(const unsigned char* start_field, const unsigned char* end_field, const char* _format);

void parse_seqno(const unsigned char* start_field, const unsigned char* end_field);

void flush_packet(void);

int text_import_regex(const text_import_info_t *info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __TEXT_IMPORT_REGEX_H__ */
