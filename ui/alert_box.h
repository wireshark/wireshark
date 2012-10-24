/* alert_box.h
 * Routines to put up various "standard" alert boxes used in multiple
 * places
 *
 * $Id$
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef __ALERT_BOX_H__
#define __ALERT_BOX_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Alert box for general errors.
 */
extern void failure_alert_box(const char *msg_format, va_list ap);

/*
 * Alert box for a failed attempt to open or create a file.
 * "err" is assumed to be a UNIX-style errno; "for_writing" is TRUE if
 * the file is being opened for writing and FALSE if it's being opened
 * for reading.
 */
extern void open_failure_alert_box(const char *filename, int err,
                                   gboolean for_writing);

/*
 * Alert box for a failed attempt to read a file.
 * "err" is assumed to be a UNIX-style errno.
 */
extern void read_failure_alert_box(const char *filename, int err);

/*
 * Alert box for a failed attempt to write to a file.
 * "err" is assumed to be a UNIX-style errno.
 */
extern void write_failure_alert_box(const char *filename, int err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __ALERT_BOX_H__ */

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
