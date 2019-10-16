/* export_object_ui.c
 * Common routines for tracking & saving objects found in streams of data
 * Copyright 2007, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include <errno.h>

#include <glib.h>

#include <epan/packet_info.h>
#include <epan/tap.h>

#include <wiretap/wtap.h>

#include <wsutil/file_util.h>
#include <wsutil/report_message.h>

#include "export_object_ui.h"

void
eo_save_entry(const gchar *save_as_filename, export_object_entry_t *entry)
{
    int to_fd;
    gint64 bytes_left;
    int bytes_to_write;
    ssize_t bytes_written;
    guint8 *ptr;
    int err;

    to_fd = ws_open(save_as_filename, O_WRONLY | O_CREAT | O_EXCL |
             O_BINARY, 0644);
    if(to_fd == -1) { /* An error occurred */
        report_open_failure(save_as_filename, errno, TRUE);
        return;
    }

    /*
     * The third argument to _write() on Windows is an unsigned int,
     * so, on Windows, that's the size of the third argument to
     * ws_write().
     *
     * The third argument to write() on UN*X is a size_t, although
     * the return value is an ssize_t, so one probably shouldn't
     * write more than the max value of an ssize_t.
     *
     * In either case, there's no guarantee that a gint64 such as
     * payload_len can be passed to ws_write(), so we write in
     * chunks of, at most 2^31 bytes.
     */
    ptr = entry->payload_data;
    bytes_left = entry->payload_len;
    while (bytes_left != 0) {
        if (bytes_left > 0x40000000)
            bytes_to_write = 0x40000000;
        else
            bytes_to_write = (int)bytes_left;
        bytes_written = ws_write(to_fd, ptr, bytes_to_write);
        if (bytes_written <= 0) {
            if (bytes_written < 0)
                err = errno;
            else
                err = WTAP_ERR_SHORT_WRITE;
            report_write_failure(save_as_filename, err);
            ws_close(to_fd);
            return;
        }
        bytes_left -= bytes_written;
        ptr += bytes_written;
    }
    if (ws_close(to_fd) < 0)
        report_write_failure(save_as_filename, errno);
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
