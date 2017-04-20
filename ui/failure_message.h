/* failure_message.h
 * Routines to print various "standard" failure messages used in multiple
 * places
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

#ifndef __FAILURE_MESSAGE_H__
#define __FAILURE_MESSAGE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Error message for a failed attempt to open or create a capture file.
 * "err" is assumed to be a UNIX-style errno or a WTAP_ERR_ value;
 * "err_info" is assumed to be a string giving further information for
 * some WTAP_ERR_ values; "for_writing" is TRUE if the file is being
 * opened for writing and FALSE if it's being opened for reading;
 * "file_type_subtype" is a WTAP_FILE_TYPE_SUBTYPE_ value for the type
 * and subtype of file being opened for writing (it's ignored for
 * opening-for-reading errors).
 */
extern void cfile_open_failure_message(const char *progname,
                                       const char *filename, int err,
                                       gchar *err_info, gboolean for_writing,
                                       int file_type);

/*
 * Error message for a failed attempt to read from a capture file.
 * "err" is assumed to be a UNIX-style errno or a WTAP_ERR_ value;
 * "err_info" is assumed to be a string giving further information for
 * some WTAP_ERR_ values.
 */
extern void cfile_read_failure_message(const char *progname,
                                       const char *filename, int err,
                                       gchar *err_info);

/*
 * Error message for a failed attempt to write to a capture file.
 * "err" is assumed to be a UNIX-style errno or a WTAP_ERR_ value;
 * "err_info" is assumed to be a string giving further information for
 * some WTAP_ERR_ values; "framenum" is the frame number of the record
 * on which the error occurred; "file_type_subtype" is a
 * WTAP_FILE_TYPE_SUBTYPE_ value for the type and subtype of file being
 * written.
 */
extern void cfile_write_failure_message(const char *in_filename,
                                        const char *out_filename,
                                        int err, gchar *err_info,
                                        guint32 framenum,
                                        int file_type_subtype);

/*
 * Error message for a failed attempt to close a capture file.
 * "err" is assumed to be a UNIX-style errno or a WTAP_ERR_ value.
 *
 * When closing a capture file:
 *
 *    some information in the file that can't be determined until
 *    all packets have been written might be written to the file
 *    (such as a table of the file offsets of all packets);
 *
 *    data buffered in the low-level file writing code might be
 *    flushed to the file;
 *
 *    for remote file systems, data written to the file but not
 *    yet sent to the server might be sent to the server or, if
 *    that data was sent asynchronously, "out of space", "disk
 *    quota exceeded", or "I/O error" indications might have
 *    been received but not yet delivered, and the close operation
 *    could deliver them;
 *
 * so we have to check for write errors here.
 */
extern void cfile_close_failure_message(const char *filename, int err);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FAILURE_MESSAGE_H__ */

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
