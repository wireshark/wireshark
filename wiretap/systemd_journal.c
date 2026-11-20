/* systemd_journal.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include "systemd_journal.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <wsutil/pint.h>

#include "wtap_module.h"
#include "pcapng_module.h"
#include "file_wrappers.h"

// To do:
// - Request a pcap encapsulation type.
// - Should we add separate types for binary, plain, and JSON or add a metadata header?

// Systemd journals are stored in the following formats:
// Journal File Format (native binary): https://www.freedesktop.org/wiki/Software/systemd/journal-files/
// Journal Export Format: https://www.freedesktop.org/wiki/Software/systemd/export/
// Journal JSON format: https://www.freedesktop.org/wiki/Software/systemd/json/
// This reads Journal Export Format files but could be extended to support
// the binary and JSON formats.

// Example data:
// __CURSOR=s=1d56bab64d414960b9907ab0cc7f7c62;i=2;b=1497926e8b4b4d3ca6a5805e157fa73c;m=5d0ae5;t=56f2f5b66ce6f;x=20cb01e28bb496a8
// __REALTIME_TIMESTAMP=1529624071163503
// __MONOTONIC_TIMESTAMP=6097637
// _BOOT_ID=1497926e8b4b4d3ca6a5805e157fa73c
// PRIORITY=6
// _MACHINE_ID=62c342838a6e436dacea041aa4b5064b
// _HOSTNAME=example.wireshark.org
// _SOURCE_MONOTONIC_TIMESTAMP=0
// _TRANSPORT=kernel
// SYSLOG_FACILITY=0
// SYSLOG_IDENTIFIER=kernel
// MESSAGE=Initializing cgroup subsys cpuset

static bool systemd_journal_read(wtap *wth, wtap_rec *rec, int *err,
        char **err_info, int64_t *data_offset);
static bool systemd_journal_seek_read(wtap *wth, int64_t seek_off,
        wtap_rec *rec, int *err, char **err_info);
static bool systemd_journal_read_export_entry(FILE_T fh, wtap_rec *rec,
        int *err, char **err_info);

// The Journal Export Format specification doesn't place limits on entry
// lengths or lines per entry. We do.
#define MAX_EXPORT_ENTRY_LENGTH WTAP_MAX_PACKET_SIZE_STANDARD
#define MAX_EXPORT_ENTRY_LINES 100

// Strictly speaking, we only need __REALTIME_TIMESTAMP= since we use
// that to set the packet timestamp. According to
// https://www.freedesktop.org/software/systemd/man/systemd.journal-fields.html
// __CURSOR= and __MONOTONIC_TIMESTAMP= should be present as well, so
// check for them order to improve our heuristics.
#define FLD__CURSOR "__CURSOR="
#define FLD__REALTIME_TIMESTAMP "__REALTIME_TIMESTAMP="
#define FLD__MONOTONIC_TIMESTAMP "__MONOTONIC_TIMESTAMP="

static int systemd_journal_file_type_subtype = -1;

void register_systemd_journal(void);

/*
 * If line starts with a field name (which consists of uppercase letters,
 * digits, and underscores) followed by '=' (a text field) or a newline
 * (a binary field), return a pointer to the character after the name;
 * otherwise, return NULL.
 */
static const char *
export_field_name_end(const char *line)
{
    const char *p = line;

    while ((*p >= 'A' && *p <= 'Z') || (*p >= '0' && *p <= '9') || *p == '_')
        p++;
    if (p == line || (*p != '=' && *p != '\n'))
        return NULL;
    return p;
}

wtap_open_return_val systemd_journal_open(wtap *wth, int *err, char **err_info)
{
    char *entry_buff = (char*) g_malloc(MAX_EXPORT_ENTRY_LENGTH);
    char *entry_line = NULL;
    const char *name_end;
    bool got_cursor = false;
    bool got_rt_ts = false;
    bool got_mt_ts = false;
    int line_num;
    int64_t max_read = INT64_MAX;
    int64_t left;

    /*
     * On a pipe, read no farther than the I/O routines guarantee we can
     * seek back over; otherwise neither we nor the open routines tried
     * after us could seek back to the beginning.
     */
    if (wth->ispipe) {
        max_read = file_bufsize(wth->fh);
    }

    errno = 0;
    for (line_num = 0; line_num < MAX_EXPORT_ENTRY_LINES; line_num++) {
        left = max_read - file_tell(wth->fh);
        if (left <= 0) {
            break;
        }
        entry_line = file_gets(entry_buff, (int)MIN(MAX_EXPORT_ENTRY_LENGTH - 1, left) + 1, wth->fh);
        if (!entry_line) {
            break;
        }
        if (entry_line[0] == '\n') {
            break;
        }
        /*
         * Every line of an entry must start with a field name. If one
         * doesn't, this isn't an export file; stop now, rather than
         * reading up to MAX_EXPORT_ENTRY_LINES lines of up to
         * MAX_EXPORT_ENTRY_LENGTH bytes each, which is slow and, on a
         * pipe, more than we can seek back over.
         */
        name_end = export_field_name_end(entry_line);
        if (name_end == NULL) {
            g_free(entry_buff);
            return WTAP_OPEN_NOT_MINE;
        }
        if (*name_end == '\n') {
            /*
             * A binary field: a 64-bit little-endian length, the data,
             * and a newline. Skip it.
             */
            uint8_t len_buf[8];
            uint64_t data_len;

            if ((int64_t)sizeof len_buf > max_read - file_tell(wth->fh)) {
                /* We couldn't seek back after reading it. */
                break;
            }
            if (!wtap_read_bytes(wth->fh, len_buf, sizeof len_buf, err, err_info)) {
                g_free(entry_buff);
                if (*err != WTAP_ERR_SHORT_READ)
                    return WTAP_OPEN_ERROR;
                *err = 0;
                return WTAP_OPEN_NOT_MINE;
            }
            data_len = pletohu64(len_buf);
            if (data_len >= MAX_EXPORT_ENTRY_LENGTH) {
                g_free(entry_buff);
                return WTAP_OPEN_NOT_MINE;
            }
            if ((int64_t)data_len + 1 > max_read - file_tell(wth->fh)) {
                /* We couldn't seek back after skipping it. */
                break;
            }
            if (!wtap_read_bytes(wth->fh, NULL, (unsigned) data_len + 1, err, err_info)) {
                g_free(entry_buff);
                if (*err != WTAP_ERR_SHORT_READ)
                    return WTAP_OPEN_ERROR;
                *err = 0;
                return WTAP_OPEN_NOT_MINE;
            }
        } else if (strncmp(entry_line, FLD__CURSOR, strlen(FLD__CURSOR)) == 0) {
            got_cursor = true;
        } else if (strncmp(entry_line, FLD__REALTIME_TIMESTAMP, strlen(FLD__REALTIME_TIMESTAMP)) == 0) {
            got_rt_ts = true;
        } else if (strncmp(entry_line, FLD__MONOTONIC_TIMESTAMP, strlen(FLD__MONOTONIC_TIMESTAMP)) == 0) {
            got_mt_ts = true;
        }
        if (got_cursor && got_rt_ts && got_mt_ts) {
            /* That's all we need. */
            break;
        }
    }
    g_free(entry_buff);

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        return WTAP_OPEN_ERROR;
    }

    if (!got_cursor || !got_rt_ts || !got_mt_ts) {
        return WTAP_OPEN_NOT_MINE;
    }

    wth->file_type_subtype = systemd_journal_file_type_subtype;
    wth->subtype_read = systemd_journal_read;
    wth->subtype_seek_read = systemd_journal_seek_read;
    wth->file_encap = WTAP_ENCAP_SYSTEMD_JOURNAL;
    wth->file_tsprec = WTAP_TSPREC_USEC;

    /*
     * Add an IDB; we don't know how many interfaces were
     * involved, so we just say one interface, about which
     * we only know the link-layer type, snapshot length,
     * and time stamp resolution.
     */
    wtap_add_generated_idb(wth);

    return WTAP_OPEN_MINE;
}

/* Read the next packet */
static bool systemd_journal_read(wtap *wth, wtap_rec *rec, int *err,
        char **err_info, int64_t *data_offset)
{
    *data_offset = file_tell(wth->fh);

    /* Read record. */
    if (!systemd_journal_read_export_entry(wth->fh, rec, err, err_info)) {
        /* Read error or EOF */
        return false;
    }

    return true;
}

static bool systemd_journal_seek_read(wtap *wth, int64_t seek_off,
        wtap_rec *rec, int *err, char **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return false;

    /* Read record. */
    if (!systemd_journal_read_export_entry(wth->random_fh, rec, err, err_info)) {
        /* Read error or EOF */
        if (*err == 0) {
            /* EOF means "short read" in random-access mode */
            *err = WTAP_ERR_SHORT_READ;
        }
        return false;
    }
    return true;
}

static bool systemd_journal_read_export_entry(FILE_T fh, wtap_rec *rec,
        int *err, char **err_info)
{
    char *entry_line = NULL;
    bool got_cursor = false;
    bool got_rt_ts = false;
    bool got_mt_ts = false;
    bool got_double_newline = false;
    int line_num;
    size_t rt_ts_len = strlen(FLD__REALTIME_TIMESTAMP);

    ws_buffer_assure_space(&rec->data, MAX_EXPORT_ENTRY_LENGTH);

    for (line_num = 0; line_num < MAX_EXPORT_ENTRY_LINES; line_num++) {
        // XXX - Should there be a file_gets_buffer() ?
        entry_line = file_gets((char*)ws_buffer_end_ptr(&rec->data), MAX_EXPORT_ENTRY_LENGTH - (int) ws_buffer_length(&rec->data), fh);
        if (!entry_line) {
            break;
        }
        ws_buffer_increase_length(&rec->data, strlen(entry_line));
        if (entry_line[0] == '\n') {
            got_double_newline = true;
            break;
        } else if (strncmp(entry_line, FLD__CURSOR, strlen(FLD__CURSOR)) == 0) {
            got_cursor = true;
        } else if (strncmp(entry_line, FLD__REALTIME_TIMESTAMP, rt_ts_len) == 0) {
            errno = 0;
            unsigned long rt_ts = strtoul(entry_line+rt_ts_len, NULL, 10);
            if (!errno) {
                rec->ts.secs = (time_t) rt_ts / 1000000;
                rec->ts.nsecs = (rt_ts % 1000000) * 1000;
                rec->tsprec = WTAP_TSPREC_USEC;
                got_rt_ts = true;
            }
        } else if (strncmp(entry_line, FLD__MONOTONIC_TIMESTAMP, strlen(FLD__MONOTONIC_TIMESTAMP)) == 0) {
            got_mt_ts = true;
        } else if (!strstr(entry_line, "=")) {
            // Start of binary data.
            if (ws_buffer_length(&rec->data) >= MAX_EXPORT_ENTRY_LENGTH - 8) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("systemd: binary length too long");
                return false;
            }
            uint64_t data_len;
            if (!wtap_read_bytes_buffer(fh, &rec->data, 8, err, err_info)) {
                return false;
            }
            data_len = pletohu64(&ws_buffer_end_ptr(&rec->data)[-8]);
            if (data_len < 1 || data_len - 1 >= MAX_EXPORT_ENTRY_LENGTH - ws_buffer_length(&rec->data)) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = ws_strdup_printf("systemd: binary data too long");
                return false;
            }
            // Data + trailing \n
            if (!wtap_read_bytes_buffer(fh, &rec->data, (unsigned) data_len + 1, err, err_info)) {
                return false;
            }
        }
        if (MAX_EXPORT_ENTRY_LENGTH < ws_buffer_length(&rec->data) + 2) { // \n\0
            break;
        }
    }

    if (!got_cursor || !got_rt_ts || !got_mt_ts) {
        return false;
    }

    if (!got_double_newline && !file_eof(fh)) {
        return false;
    }

    wtap_setup_systemd_journal_export_rec(rec);
    rec->block = wtap_block_create(WTAP_BLOCK_SYSTEMD_JOURNAL_EXPORT);
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec->rec_header.systemd_journal_export_header.record_len = (uint32_t) ws_buffer_length(&rec->data);

    return true;
}

static const struct supported_block_type systemd_journal_blocks_supported[] = {
    /*
     * We support systemd journal blocks, with no comments or other options.
     */
    { WTAP_BLOCK_SYSTEMD_JOURNAL_EXPORT, MULTIPLE_BLOCKS_SUPPORTED, NO_OPTIONS_SUPPORTED }
};

static const struct file_type_subtype_info systemd_journal_info = {
    "systemd journal export", "systemd_journal", NULL, NULL,
    false, BLOCKS_SUPPORTED(systemd_journal_blocks_supported),
    NULL, NULL, NULL
};

void register_systemd_journal(void)
{
  systemd_journal_file_type_subtype = wtap_register_file_type_subtype(&systemd_journal_info);

  /*
   * Register name for backwards compatibility with the
   * wtap_filetypes table in Lua.
   */
  wtap_register_backwards_compatibility_lua_name("SYSTEMD_JOURNAL",
                                                 systemd_journal_file_type_subtype);
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
