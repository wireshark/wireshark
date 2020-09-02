/* systemd_journal.c
 *
 * Wiretap Library
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include "wtap-int.h"
#include "pcapng_module.h"
#include "file_wrappers.h"
#include "systemd_journal.h"

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

static gboolean systemd_journal_read(wtap *wth, wtap_rec *rec, Buffer *buf,
        int *err, gchar **err_info, gint64 *data_offset);
static gboolean systemd_journal_seek_read(wtap *wth, gint64 seek_off,
        wtap_rec *rec, Buffer *buf, int *err, gchar **err_info);
static gboolean systemd_journal_read_export_entry(FILE_T fh, wtap_rec *rec,
        Buffer *buf, int *err, gchar **err_info);

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

wtap_open_return_val systemd_journal_open(wtap *wth, int *err _U_, gchar **err_info _U_)
{
    gchar *entry_buff = (gchar*) g_malloc(MAX_EXPORT_ENTRY_LENGTH);
    gchar *entry_line = NULL;
    gboolean got_cursor = FALSE;
    gboolean got_rt_ts = FALSE;
    gboolean got_mt_ts = FALSE;
    int line_num;

    errno = 0;
    for (line_num = 0; line_num < MAX_EXPORT_ENTRY_LINES; line_num++) {
        entry_line = file_gets(entry_buff, MAX_EXPORT_ENTRY_LENGTH, wth->fh);
        if (!entry_line) {
            break;
        }
        if (entry_line[0] == '\n') {
            break;
        } else if (strncmp(entry_line, FLD__CURSOR, strlen(FLD__CURSOR)) == 0) {
            got_cursor = TRUE;
        } else if (strncmp(entry_line, FLD__REALTIME_TIMESTAMP, strlen(FLD__REALTIME_TIMESTAMP)) == 0) {
            got_rt_ts = TRUE;
        } else if (strncmp(entry_line, FLD__MONOTONIC_TIMESTAMP, strlen(FLD__MONOTONIC_TIMESTAMP)) == 0) {
            got_mt_ts = TRUE;
        }
    }
    g_free(entry_buff);

    if (file_seek(wth->fh, 0, SEEK_SET, err) == -1) {
        return WTAP_OPEN_ERROR;
    }

    if (!got_cursor || !got_rt_ts || !got_mt_ts) {
        return WTAP_OPEN_NOT_MINE;
    }

    wth->file_type_subtype = WTAP_FILE_TYPE_SUBTYPE_SYSTEMD_JOURNAL;
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
static gboolean systemd_journal_read(wtap *wth, wtap_rec *rec, Buffer *buf,
        int *err, gchar **err_info, gint64 *data_offset)
{
    *data_offset = file_tell(wth->fh);

    /* Read record. */
    if (!systemd_journal_read_export_entry(wth->fh, rec, buf, err, err_info)) {
        /* Read error or EOF */
        return FALSE;
    }

    return TRUE;
}

    static gboolean
systemd_journal_seek_read(wtap *wth, gint64 seek_off,
        wtap_rec *rec, Buffer *buf,
        int *err, gchar **err_info)
{
    if (file_seek(wth->random_fh, seek_off, SEEK_SET, err) == -1)
        return FALSE;

    /* Read record. */
    if (!systemd_journal_read_export_entry(wth->random_fh, rec, buf, err, err_info)) {
        /* Read error or EOF */
        if (*err == 0) {
            /* EOF means "short read" in random-access mode */
            *err = WTAP_ERR_SHORT_READ;
        }
        return FALSE;
    }
    return TRUE;
}

static gboolean
systemd_journal_read_export_entry(FILE_T fh, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info)
{
    size_t fld_end = 0;
    gchar *buf_ptr;
    gchar *entry_line = NULL;
    gboolean got_cursor = FALSE;
    gboolean got_rt_ts = FALSE;
    gboolean got_mt_ts = FALSE;
    gboolean got_double_newline = FALSE;
    int line_num;
    size_t rt_ts_len = strlen(FLD__REALTIME_TIMESTAMP);

    ws_buffer_assure_space(buf, MAX_EXPORT_ENTRY_LENGTH);
    buf_ptr = (gchar *) ws_buffer_start_ptr(buf);

    for (line_num = 0; line_num < MAX_EXPORT_ENTRY_LINES; line_num++) {
        entry_line = file_gets(buf_ptr + fld_end, MAX_EXPORT_ENTRY_LENGTH - (int) fld_end, fh);
        if (!entry_line) {
            break;
        }
        fld_end += strlen(entry_line);
        if (entry_line[0] == '\n') {
            got_double_newline = TRUE;
            break;
        } else if (strncmp(entry_line, FLD__CURSOR, strlen(FLD__CURSOR)) == 0) {
            got_cursor = TRUE;
        } else if (strncmp(entry_line, FLD__REALTIME_TIMESTAMP, rt_ts_len) == 0) {
            errno = 0;
            unsigned long rt_ts = strtoul(entry_line+rt_ts_len, NULL, 10);
            if (!errno) {
                rec->ts.secs = (time_t) rt_ts / 1000000;
                rec->ts.nsecs = (rt_ts % 1000000) * 1000;
                rec->tsprec = WTAP_TSPREC_USEC;
                got_rt_ts = TRUE;
            }
        } else if (strncmp(entry_line, FLD__MONOTONIC_TIMESTAMP, strlen(FLD__MONOTONIC_TIMESTAMP)) == 0) {
            got_mt_ts = TRUE;
        } else if (!strstr(entry_line, "=")) {
            // Start of binary data.
            if (fld_end >= MAX_EXPORT_ENTRY_LENGTH - 8) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("systemd: binary length too long");
                return FALSE;
            }
            guint64 data_len, le_data_len;
            if (!wtap_read_bytes(fh, &le_data_len, 8, err, err_info)) {
                return FALSE;
            }
            memcpy(buf_ptr + fld_end, &le_data_len, 8);
            fld_end += 8;
            data_len = pletoh64(&le_data_len);
            if (data_len < 1 || data_len - 1 >= MAX_EXPORT_ENTRY_LENGTH - fld_end) {
                *err = WTAP_ERR_BAD_FILE;
                *err_info = g_strdup_printf("systemd: binary data too long");
                return FALSE;
            }
            // Data + trailing \n
            if (!wtap_read_bytes(fh, buf_ptr + fld_end, (unsigned) data_len + 1, err, err_info)) {
                return FALSE;
            }
            fld_end += (size_t) data_len + 1;
        }
        if (MAX_EXPORT_ENTRY_LENGTH < fld_end + 2) { // \n\0
            break;
        }
    }

    if (!got_cursor || !got_rt_ts || !got_mt_ts) {
        return FALSE;
    }

    if (!got_double_newline && !file_eof(fh)) {
        return FALSE;
    }

    rec->rec_type = REC_TYPE_FT_SPECIFIC_EVENT;
    rec->presence_flags = WTAP_HAS_TS|WTAP_HAS_CAP_LEN;
    rec->rec_header.ft_specific_header.record_type = WTAP_FILE_TYPE_SUBTYPE_SYSTEMD_JOURNAL;
    rec->rec_header.ft_specific_header.record_len = (guint32) fld_end;

    return TRUE;
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
