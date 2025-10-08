/* @file
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * This reads sequences of JSON records which contain timestamps. For general
 * JSON support, see json.c.
 *
 * The following formats are supported:
 *
 * JSON Lines (https://jsonlines.org/), which are JSON objects separated by newlines:
 *   Kubneretes audit logs: https://kubernetes.io/docs/reference/config-api/apiserver-audit.v1/
 *   GCP audit logs: https://cloud.google.com/logging/docs/reference/v2/rest/v2/LogEntry
 *
 * AWS CloudTrail, which is a JSON object containing an array of log entries:
 * https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html
 *
 */

#include "json_log.h"

#include <string.h>

#include "wtap-int.h"
#include "file_wrappers.h"

#include <wsutil/wsjson.h>

enum log_format_e {
    LOG_FORMAT_JSON_LINES,
    LOG_FORMAT_CLOUDTRAIL,
};

typedef struct {
    enum log_format_e format;
} json_log_t;

static int json_log_file_type_subtype = -1;

void register_json_log(void);

static bool json_log_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset);
static bool json_log_seek_read(wtap* wth, int64_t seek_off, wtap_rec* rec, int* err, char** err_info);

// Maximum size of a log entry
#define MAX_JSON_LOG_ENTRY_SIZE (100 * 1024)
#define START_TOKENS 25

jsmntok_t *tokens = NULL;
unsigned num_tokens = 0;

// XXX We should return the precision as well.
static nstime_t get_entry_timestamp(const char *log_data, size_t entry_size) {
    if (!log_data) {
        return (nstime_t) NSTIME_INIT_ZERO;
    }

    const char *timestamp_keys[] = {
        "stageTimestamp",           // Kubernetes audit, µs
        "requestReceivedTimestamp", // Kubernetes audit, µs
        "eventTime",                // CloudTrail, s
        "receiveTimestamp",         // GCP audit, ns
        "timestamp",                // GCP audit, ns
    };

    int parsed_cnt = json_parse_len(log_data, entry_size, tokens, num_tokens);
    if (parsed_cnt == JSMN_ERROR_NOMEM) {
        int needed = json_parse_len(log_data, entry_size, NULL, 0);
        while ((int)num_tokens < needed) num_tokens *= 2;
        tokens = g_realloc(tokens, sizeof(jsmntok_t) * num_tokens);
        parsed_cnt = json_parse_len(log_data, entry_size, tokens, num_tokens);
    }

    if (parsed_cnt < 3) {
        return (nstime_t) NSTIME_INIT_ZERO;
    }

    for (int idx = 0; idx < parsed_cnt - 1; idx++) {
        if (tokens[idx].type == JSMN_STRING && tokens[idx+1].type == JSMN_STRING) {
            for (size_t key = 0; key < array_length(timestamp_keys); key++) {
                int key_len = (int) strlen(timestamp_keys[key]);
                if (key_len == tokens[idx].end - tokens[idx].start && strncmp(log_data + tokens[idx].start, timestamp_keys[key], key_len) == 0) {
                    nstime_t ts;
                    if (iso8601_to_nstime(&ts, log_data + tokens[idx+1].start, ISO8601_DATETIME_AUTO)) {
                        return ts;
                    }
                    return (nstime_t) NSTIME_INIT_ZERO;
                }
            }
        }
    }

    return (nstime_t) NSTIME_INIT_ZERO;
}

ptrdiff_t skip_ws(const char *log_data, const char *log_end) {
    const char *cur = log_data;
    for (; cur < log_end; cur++) {
        if (!g_ascii_isspace(*cur)) {
            break;
        }
    }
    return cur - log_data;
}

// {"Records":[
ptrdiff_t skip_cloudtrail_header(const char *log_data, const char *log_end) {
    const char *cur = log_data;
    cur += skip_ws(cur, log_end);
    if (*cur != '{') {
        return 0;
    }
    cur++;

    const char *record_key = "\"Records\"";
    if (log_end <= cur + strlen(record_key) || memcmp(cur, record_key, strlen(record_key))) {
        return 0;
    }
    cur += strlen(record_key);

    cur += skip_ws(cur, log_end);
    if (cur >= log_end || *cur != ':') {
        return 0;
    }
    cur++;

    cur += skip_ws(cur, log_end);
    if (cur >= log_end || *cur != '[') {
        return 0;
    }
    cur++;

    if (cur <= log_end) {
        return cur - log_data;
    }

    return 0;
}

// XXX Should this be in wsjson?
size_t json_object_size(const char *log_data, const char *log_end) {
    int depth = 0;
    bool in_string = false;
    bool in_escape = false;

    for (const char *cur = log_data; cur < log_end; cur++) {
        if (in_string) {
            if (in_escape) {
                in_escape = false;
            } else if (*cur == '\\') {
                in_escape = true;
            } else if (*cur == '"') {
                in_string = false;
            }
        } else {
            if (*cur == '"') {
                in_string = true;
            } else if (*cur == '{') {
                depth++;
            } else if (*cur == '}') {
                depth--;
                if (depth == 0) {
                    return cur - log_data + 1;
                }
            }
        }
    }

    return 0;
}

wtap_open_return_val json_log_open(wtap *wth, int *err, char **err_info _U_)
{
    char *log_buf = g_new(char, MAX_JSON_LOG_ENTRY_SIZE);
    char *log_data = log_buf;

    if (!tokens) {
        num_tokens = START_TOKENS;
        tokens = g_malloc(sizeof(jsmntok_t) * num_tokens);
    }

    int bytes_read = file_read(log_data, MAX_JSON_LOG_ENTRY_SIZE, wth->fh);
    if (bytes_read < 1) {
        g_free(log_buf);
        return WTAP_OPEN_NOT_MINE;
    }

    const char *log_end = log_data + bytes_read - 1;

    ptrdiff_t cloudtrail_header_len = skip_cloudtrail_header(log_data, log_end);

    log_data += cloudtrail_header_len;

    size_t entry_size = json_object_size(log_data, log_end);

    nstime_t ts = get_entry_timestamp(log_data, entry_size);

    g_free(log_buf);

    if (nstime_is_zero(&ts)) {
        return WTAP_OPEN_NOT_MINE;
    }

    if (file_seek(wth->fh, log_data - log_buf, SEEK_SET, err) == -1) {
        return WTAP_OPEN_ERROR;
    }

    json_log_t *json_log = g_new(json_log_t, 1);
    if (cloudtrail_header_len > 0) {
        json_log->format = LOG_FORMAT_CLOUDTRAIL;
    } else {
        json_log->format = LOG_FORMAT_JSON_LINES;
    }

    wth->priv = json_log;
    wth->file_type_subtype = json_log_file_type_subtype;
    wth->file_encap = WTAP_ENCAP_JSON;
    wth->file_tsprec = WTAP_TSPREC_NSEC;
    wth->subtype_read = json_log_read;
    wth->subtype_seek_read = json_log_seek_read;
    wth->snapshot_length = 0;

    return WTAP_OPEN_MINE;
}

static bool json_log_read_packet(wtap *wth, FILE_T fh, wtap_rec *rec, int *err, char **err_info) {
    // Skip over delimiters. JSON Lines uses whitespace & CloudTrail uses commas.

    int ch = file_peekc(fh);
    while (g_ascii_isspace(ch) && !file_eof(fh)) {
        file_getc(fh);
        ch = file_peekc(fh);
    }

    json_log_t *json_log = (json_log_t *) wth->priv;
    if (json_log->format == LOG_FORMAT_CLOUDTRAIL && ch == ',') {
        file_getc(fh);
        ch = file_peekc(fh);
        while (g_ascii_isspace(ch) && !file_eof(fh)) {
            file_getc(fh);
            ch = file_peekc(fh);
        }
    }

    ws_buffer_assure_space(&rec->data, MAX_JSON_LOG_ENTRY_SIZE);
    char *log_data = (char *) ws_buffer_start_ptr(&rec->data);

    int64_t start_pos = file_tell(fh);
    int bytes_read = file_read(log_data, MAX_JSON_LOG_ENTRY_SIZE, fh);
    if (bytes_read < 1) {
        if (!file_eof(fh)) {
            *err = WTAP_ERR_SHORT_READ;
        }
        return false;
    }
    const char *log_end = log_data + bytes_read - 1;


    size_t entry_size = json_object_size(log_data, log_end);

    nstime_t ts = get_entry_timestamp(log_data, entry_size);
    if (nstime_is_zero(&ts)) {
        *err = WTAP_ERR_BAD_FILE;
        *err_info = ws_strdup_printf("JSON Log: missing timestamp");
        return false;
    }

    if (file_seek(fh, start_pos + entry_size, SEEK_SET, err) == -1) {
        return false;
    }

    rec->presence_flags = WTAP_HAS_TS;
    rec->ts = ts;
    rec->tsprec = WTAP_TSPREC_NSEC;

    wtap_setup_packet_rec(rec, wth->file_encap);
    // XXX This should arguably be WTAP_BLOCK_SYSDIG_EVENT or
    // WTAP_BLOCK_something_more_appropriate, but as it stands the event will
    // be picked up by the JSON dissector in both Wireshark and Stratoshark,
    // and passed to the Falco Events dissector in Stratoshark.
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->rec_header.packet_header.caplen = (unsigned) entry_size;
    rec->rec_header.packet_header.len = (unsigned) entry_size;

    // Skip over CloudTrail array + object closing delimiters
    if (json_log->format == LOG_FORMAT_CLOUDTRAIL) {
        ch = file_peekc(fh);
        while ((g_ascii_isspace(ch) || ch == ']') && !file_eof(fh)) {
            file_getc(fh);
            ch = file_peekc(fh);
        }
        while ((g_ascii_isspace(ch) || ch == '}') && !file_eof(fh)) {
            file_getc(fh);
            ch = file_peekc(fh);
        }
    }

    return true;
}

static bool json_log_read(wtap *wth, wtap_rec *rec, int *err, char **err_info, int64_t *data_offset) {
    *data_offset = file_tell(wth->fh);
    return json_log_read_packet(wth, wth->fh, rec, err, err_info);
}

static bool json_log_seek_read(wtap* wth, int64_t seek_off, wtap_rec* rec, int* err, char** err_info) {
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1) {
        return false;
    }

    return json_log_read_packet(wth, wth->random_fh, rec, err, err_info);
}


static const struct supported_block_type json_blocks_supported[] = {
    /*
     * This is a file format that we dissect, so we provide only one
     * "packet" with the file's contents, and don't support any
     * options.
     */
    { WTAP_BLOCK_PACKET, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info json_log_info = {
    "JSON Log", "jsonlog", "jsonl", "log",
    false, BLOCKS_SUPPORTED(json_blocks_supported),
    NULL, NULL, NULL
};

void register_json_log(void)
{
    json_log_file_type_subtype = wtap_register_file_type_subtype(&json_log_info);

    /*
     * Register name for backwards compatibility with the
     * wtap_filetypes table in Lua.
     */
    wtap_register_backwards_compatibility_lua_name("JSON Log",
                                                   json_log_file_type_subtype);
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
