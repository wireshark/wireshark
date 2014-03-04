/* export_object.c
 * Common routines for tracking & saving objects found in streams of data
 * Copyright 2007, Stephen Fisher (see AUTHORS file)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#include "config.h"

#include <string.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <errno.h>

#include <epan/packet_info.h>
#include <wiretap/wtap.h>
#include <epan/tap.h>

#include <wsutil/file_util.h>

#include <ui/alert_box.h>

#include "export_object.h"

gboolean
eo_save_entry(const gchar *save_as_filename, export_object_entry_t *entry, gboolean show_err)
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
        if (show_err)
            open_failure_alert_box(save_as_filename, errno, TRUE);
        return FALSE;
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
        if(bytes_written <= 0) {
            if (bytes_written < 0)
                err = errno;
            else
                err = WTAP_ERR_SHORT_WRITE;
            if (show_err)
                write_failure_alert_box(save_as_filename, err);
            ws_close(to_fd);
            return FALSE;
        }
        bytes_left -= bytes_written;
        ptr += bytes_written;
    }
    if (ws_close(to_fd) < 0) {
        if (show_err)
            write_failure_alert_box(save_as_filename, errno);
        return FALSE;
    }

    return TRUE;
}


#define HINIBBLE(x)     (((x) >> 4) & 0xf)
#define LONIBBLE(x)     ((x) & 0xf)
#define HEXTOASCII(x)   (((x) < 10) ? ((x) + '0') : ((x) - 10 + 'a'))
#define MAXFILELEN      255

static GString *eo_rename(GString *gstr, int dupn)
{
    GString *gstr_tmp;
    gchar *tmp_ptr;
    GString *ext_str;

    gstr_tmp = g_string_new("(");
    g_string_append_printf (gstr_tmp, "%d)", dupn);
    if ( (tmp_ptr = strrchr(gstr->str, '.')) != NULL ) {
        /* Retain the extension */
        ext_str = g_string_new(tmp_ptr);
        gstr = g_string_truncate(gstr, gstr->len - ext_str->len);
        if ( gstr->len >= (MAXFILELEN - (strlen(gstr_tmp->str) + ext_str->len)) )
            gstr = g_string_truncate(gstr, MAXFILELEN - (strlen(gstr_tmp->str) + ext_str->len));
        gstr = g_string_append(gstr, gstr_tmp->str);
        gstr = g_string_append(gstr, ext_str->str);
        g_string_free(ext_str, TRUE);
    }
    else {
        if ( gstr->len >= (MAXFILELEN - strlen(gstr_tmp->str)) )
            gstr = g_string_truncate(gstr, MAXFILELEN - strlen(gstr_tmp->str));
        gstr = g_string_append(gstr, gstr_tmp->str);
    }
    g_string_free(gstr_tmp, TRUE);
    return gstr;
}

GString *
eo_massage_str(const gchar *in_str, gsize maxlen, int dupn)
{
    gchar *tmp_ptr;
    /* The characters in "reject" come from:
     * http://msdn.microsoft.com/en-us/library/aa365247%28VS.85%29.aspx.
     * Add to the list as necessary for other OS's.
     */
    const gchar *reject = "<>:\"/\\|?*"
        "\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a"
    "\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14"
    "\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f";
    GString *out_str;
    GString *ext_str;

    out_str = g_string_new("");

    /* Find all disallowed characters/bytes and replace them with %xx */
    while ( (tmp_ptr = strpbrk(in_str, reject)) != NULL ) {
        out_str = g_string_append_len(out_str, in_str, tmp_ptr - in_str);
        out_str = g_string_append_c(out_str, '%');
        out_str = g_string_append_c(out_str, HEXTOASCII(HINIBBLE(*tmp_ptr)));
        out_str = g_string_append_c(out_str, HEXTOASCII(LONIBBLE(*tmp_ptr)));
        in_str = tmp_ptr + 1;
    }
    out_str = g_string_append(out_str, in_str);
    if ( out_str->len > maxlen ) {
        if ( (tmp_ptr = strrchr(out_str->str, '.')) != NULL ) {
            /* Retain the extension */
            ext_str = g_string_new(tmp_ptr);
            out_str = g_string_truncate(out_str, maxlen - ext_str->len);
            out_str = g_string_append(out_str, ext_str->str);
            g_string_free(ext_str, TRUE);
        }
        else
            out_str = g_string_truncate(out_str, maxlen);
    }
    if ( dupn != 0 )
        out_str = eo_rename(out_str, dupn);
    return out_str;
}

const char *
ct2ext(const char *content_type)
{
    /* TODO: Map the content type string to an extension string.  If no match,
     * return NULL. */
    return content_type;
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
