/* text_import_regex.c
 * Regex based text importer
 * March 2021, Paul Weiß <paulniklasweiss@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Based on text_import.c by Jaap Keuter <jaap.keuter@xs4all.nl>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>
#include <stdlib.h>

#include <glib.h>

#include "text_import.h"
#include "text_import_regex.h"

typedef unsigned int uint;

/*--- Options --------------------------------------------------------------------*/

int text_import_regex(const text_import_info_t* info) {
    int status = 1;
    int parsed_packets = 0;
    ws_debug("starting import...");

    // IO
    GMappedFile* file = g_mapped_file_ref(info->regex.import_text_GMappedFile);
    GError* gerror = NULL;
    size_t f_size = g_mapped_file_get_length(file);
    unsigned char* f_content = g_mapped_file_get_contents(file);
    { /* zero terminate the file */
        if (f_content[f_size -  1] != '\n') {
            fprintf(stderr, "Error: file did not end on \\n\n");
            g_mapped_file_unref(file);
            return -1;
        }
        f_content[f_size] = 0;
    }

    // Regex result dissecting
    bool re_time, re_dir, re_seqno;
    GMatchInfo* match;
    int field_start;
    int field_end;
    { /* analyze regex */
        re_time = g_regex_get_string_number(info->regex.format, "time") >= 0;
        re_dir = g_regex_get_string_number(info->regex.format, "dir") >= 0;
        re_seqno = g_regex_get_string_number(info->regex.format, "seqno") >= 0;
        if (g_regex_get_string_number(info->regex.format, "data") < 0) {
            /* This should never happen, as the dialog checks for this */
            fprintf(stderr, "Error could not find data in pattern\n");
            g_mapped_file_unref(file);
            return -1;
        }
    }

    ws_debug("regex has %s%s%s", re_dir ? "dir, " : "",
                                 re_time ? "time, " : "",
                                 re_seqno ? "seqno, " : "");
    g_regex_match(info->regex.format, f_content, G_REGEX_MATCH_NOTEMPTY, &match);
    while (g_match_info_matches(match)) {
        /* parse the data */
        if (!g_match_info_fetch_named_pos(match, "data", &field_start, &field_end)) {
            fprintf(stderr, "Warning: could not fetch data on would be packet %d, discarding\n", parsed_packets + 1);
            continue;
        }
        parse_data(f_content + field_start, f_content + field_end, info->regex.encoding);

        /* parse the auxiliary information if present */
        if (re_time &&
                g_match_info_fetch_named_pos(match, "time", &field_start, &field_end)) {
            parse_time(f_content + field_start, f_content + field_end, info->timestamp_format);
	} else {
            /* No time present, so add a fixed delta. */
            parse_time(NULL, NULL, NULL);
        }

        if (re_dir &&
                g_match_info_fetch_named_pos(match, "dir", &field_start, &field_end))
            parse_dir(f_content + field_start, f_content + field_end, info->regex.in_indication, info->regex.out_indication);

        if (re_seqno &&
                g_match_info_fetch_named_pos(match, "seqno", &field_start, &field_end))
            parse_seqno(f_content + field_start, f_content + field_end);

        if (ws_log_get_level() == LOG_LEVEL_NOISY) {
            g_match_info_fetch_pos(match, 0, &field_start, &field_end);
            ws_noisy("Packet %d at %x to %x: %.*s\n", parsed_packets + 1,
                    field_start, field_end,
                    field_end - field_start, f_content + field_start);
        }
        flush_packet();


        /* prepare next packet */
        ++parsed_packets;
        g_match_info_next(match, &gerror);
        if (gerror && gerror->code) {
            status = -1;
            g_error_free(gerror);
            break;
        }
    }
    ws_debug("processed %d packets", parsed_packets);
    g_match_info_unref(match);
    g_mapped_file_unref(file);
    return status * parsed_packets;
}
