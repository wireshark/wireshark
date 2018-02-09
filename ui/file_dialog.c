/* file_dialog.c
 * Common file dialog routines
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2006 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later*/

#include "config.h"

#include <time.h>

#include <glib.h>

#include <wsutil/nstime.h>

#include <wiretap/wtap.h>

#include <epan/prefs.h>

#include "ui/file_dialog.h"

ws_file_preview_times_status
get_times_for_preview(wtap *wth, ws_file_preview_times *times,
                      guint32 *num_packets, int *err, gchar **err_info)
{
    gint64       data_offset;
    const wtap_rec *rec;
    guint32      packets;
    gboolean     have_times;
    gboolean     timed_out;
    time_t       time_preview, time_current;
    double       cur_time;

    times->start_time = 0;
    times->stop_time = 0;
    packets = 0;
    have_times = FALSE;
    timed_out = FALSE;
    time(&time_preview);
    while ((wtap_read(wth, err, err_info, &data_offset))) {
        rec = wtap_get_rec(wth);
        if (rec->presence_flags & WTAP_HAS_TS) {
            cur_time = nstime_to_sec(&rec->ts);
            if (!have_times) {
                times->start_time = cur_time;
                times->stop_time = cur_time;
                have_times = TRUE;
            }
            if (cur_time < times->start_time) {
                times->start_time = cur_time;
            }
            if (cur_time > times->stop_time){
                times->stop_time = cur_time;
            }
        }

        packets++;
        if (packets%1000 == 0) {
            /* do we have a timeout? */
            time(&time_current);
            if (time_current-time_preview >= (time_t) prefs.gui_fileopen_preview) {
                timed_out = TRUE;
                break;
            }
        }
    }
    *num_packets = packets;
    if (*err != 0) {
        /* Read error. */
        return PREVIEW_READ_ERROR;
    }

    if (have_times) {
        if (timed_out)
            return PREVIEW_TIMED_OUT;
        else
            return PREVIEW_HAVE_TIMES;
    } else
        return PREVIEW_HAVE_NO_TIMES;
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
