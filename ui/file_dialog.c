/* file_dialog.c
 * Common file dialog routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <time.h>

#include <glib.h>

#include <wsutil/nstime.h>

#include <wiretap/wtap.h>

#include <epan/prefs.h>

#include "ui/file_dialog.h"

ws_file_preview_stats_status
get_stats_for_preview(wtap *wth, ws_file_preview_stats *stats,
                      int *err, gchar **err_info)
{
    gint64       data_offset;
    wtap_rec     rec;
    Buffer       buf;
    guint32      records;
    guint32      data_records;
    double       start_time;
    double       stop_time;
    gboolean     have_times;
    gboolean     timed_out;
    time_t       time_preview, time_current;
    double       cur_time;

    have_times = FALSE;
    start_time = 0;
    stop_time = 0;
    records = 0;
    data_records = 0;
    timed_out = FALSE;
    time(&time_preview);
    wtap_rec_init(&rec);
    ws_buffer_init(&buf, 1514);
    while ((wtap_read(wth, &rec, &buf, err, err_info, &data_offset))) {
        if (rec.presence_flags & WTAP_HAS_TS) {
            cur_time = nstime_to_sec(&rec.ts);
            if (!have_times) {
                start_time = cur_time;
                stop_time = cur_time;
                have_times = TRUE;
            }
            if (cur_time < start_time) {
                start_time = cur_time;
            }
            if (cur_time > stop_time){
                stop_time = cur_time;
            }
        }

        switch (rec.rec_type) {

        case REC_TYPE_PACKET:
        case REC_TYPE_FT_SPECIFIC_EVENT:
        case REC_TYPE_FT_SPECIFIC_REPORT:
        case REC_TYPE_SYSCALL:
            data_records++;
            break;
        }

        records++;
        if ((records % 1000) == 0) {
            /* do we have a timeout? */
            time(&time_current);
            if (time_current-time_preview >= (time_t) prefs.gui_fileopen_preview) {
                timed_out = TRUE;
                break;
            }
        }
    }

    stats->have_times = have_times;
    stats->start_time = start_time;
    stats->stop_time = stop_time;
    stats->records = records;
    stats->data_records = data_records;

    wtap_rec_cleanup(&rec);
    ws_buffer_free(&buf);

    if (*err != 0) {
        /* Read error. */
        return PREVIEW_READ_ERROR;
    }
    return timed_out ? PREVIEW_TIMED_OUT : PREVIEW_SUCCEEDED;
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
