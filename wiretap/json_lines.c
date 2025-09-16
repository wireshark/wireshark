/* @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This reads newline-delimited JSON records which contain timestamps. For
 * general JSON support, see json.c.
 *
 * The general format is described at https://jsonlines.org/ and logs must
 * contain timestamps from one of the following sources:
 *
 * Kubneretes audit logs: https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
 * AWS CloudTrail: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
 * GCP audit logs: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
 *
 */

#include "json_lines.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/wsjson.h>

static int json_lines_file_type_subtype = -1;

void register_json_lines(void);

static bool json_lines_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset);
static bool json_lines_seek_read(wtap* wth, int64_t seek_off, wtap_rec* rec, int* err, char** err_info);

// Maximum size of a JSON Lines line
#define MAX_JSON_LINE_SIZE (20 * 1024)
#define START_TOKENS 25

jsmntok_t *tokens = NULL;
unsigned num_tokens = 0;

// XXX We should return the precision as well.
static nstime_t get_jsonlines_timestamp(const char *log_line) {
    if (!log_line) {
        return (nstime_t) NSTIME_INIT_ZERO;
    }

    const char *timestamp_keys[] = {
        "stageTimestamp",           // Kubernetes audit, µs
        "requestReceivedTimestamp", // Kubernetes audit, µs
        "eventTime",                // CloudTrail, s
        "receiveTimestamp",         // GCP audit, ns
        "timestamp",                // GCP audit, ns
    };

    int parsed_cnt = json_parse(log_line, tokens, num_tokens);
    if (parsed_cnt == JSMN_ERROR_NOMEM) {
        int needed = json_parse(log_line, NULL, 0);
        while ((int)num_tokens < needed) num_tokens *= 2;
        tokens = g_realloc(tokens, sizeof(jsmntok_t) * num_tokens);
        parsed_cnt = json_parse(log_line, tokens, num_tokens);
    }

    if (parsed_cnt < 3) {
        return (nstime_t) NSTIME_INIT_ZERO;
    }

    for (int idx = 0; idx < parsed_cnt - 1; idx++) {
        if (tokens[idx].type == JSMN_STRING && tokens[idx+1].type == JSMN_STRING) {
            for (size_t key = 0; key < array_length(timestamp_keys); key++) {
                if (strncmp(log_line + tokens[idx].start, timestamp_keys[key], tokens[idx].end - tokens[idx].start) == 0) {
                    nstime_t ts;
                    if (iso8601_to_nstime(&ts, log_line + tokens[idx+1].start, ISO8601_DATETIME_AUTO)) {
                        return ts;
                    }
                    return (nstime_t) NSTIME_INIT_ZERO;
                }
            }
        }
    }

    return (nstime_t) NSTIME_INIT_ZERO;
}

wtap_open_return_val json_lines_open(wtap *wth, int *err, char **err_info _U_)
{
    char *line_buf = g_new(char, MAX_JSON_LINE_SIZE);

    if (!tokens) {
        num_tokens = START_TOKENS;
        tokens = g_malloc(sizeof(jsmntok_t) * num_tokens);
    }

    const char *log_line = file_gets(line_buf, MAX_JSON_LINE_SIZE, wth->fh);
    nstime_t ts = get_jsonlines_timestamp(log_line);
    g_free(line_buf);

    if (nstime_is_zero(&ts)) {
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        return WTAP_OPEN_ERROR;
    }

    wth->file_type_subtype = json_lines_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_JSON;
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->subtype_read = json_lines_read;
    wth->subtype_seek_read = json_lines_seek_read;
    wth->snapshot_length = 0;

    return WTAP_OPEN_MINE;
}

static bool json_lines_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec, int *err, char **err_info) {
    ws_buffer_assure_space(&rec->data, MAX_JSON_LINE_SIZE);
    char *line_buf = (char *) ws_buffer_start_ptr(&rec->data);

    const char *log_line = file_gets(line_buf, MAX_JSON_LINE_SIZE, fh);
    if (!log_line) {
        if (!file_eof(fh)) {
            *err = WTAP_ERR_BAD_FILE;
            *err_info = ws_strdup_printf("JSON Lines: line too long");
        }
        return false;
    }

    nstime_t ts = get_jsonlines_timestamp(log_line);
    if (nstime_is_zero(&ts)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("JSON Lines: missing timestamp");
        return false;
    }

    rec->ts = ts;
    rec->tsprec = WTAP_TSPREC_NSEC;
    unsigned line_len = (unsigned) strlen(log_line);

    wtap_setup_packet_rec(rec, wth->file_encap);
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->rec_header.packet_header.caplen = line_len;
    rec->rec_header.packet_header.len = line_len;

    return true;
}

static bool json_lines_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset) {
    *data_offset = file_tell(wth->fh);
    return json_lines_read_packet(wth, wth->fh, rec, err, err_info);
}

static bool json_lines_seek_read(wtap* wth, int64_t seek_off, wtap_rec* rec, int* err, char** err_info) {
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
        return false;
    }

    return json_lines_read_packet(wth, wth->random_fh, rec, err, err_info);
}


static const struct supported_block_type json_blocks_supported[] = {
    /*
     * This is a file format that we dissect, so we provide only one
     * "packet" with the file's contents, and don't support any
     * options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info json_lines_info = {
    "JSON Lines", "jsonlines", "jsonl", "log",
    false, BLOCKS_SUPPORTED(json_blocks_supported),
    NULL, NULL, NULL
};

void register_json_lines(void)
{
    json_lines_file_type_subtype = wtap_register_file_type_subtype(&json_lines_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("JSON Lines",
                                                   json_lines_file_type_subtype);
}

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
