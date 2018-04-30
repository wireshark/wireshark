/* failure_message.h
 * Routines to print various "standard" failure messages used in multiple
 * places
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __FAILURE_MESSAGE_H__
#define __FAILURE_MESSAGE_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Error message for a failed attempt to open a capture file for input.
 * "progname" is the name of the program trying to open the file;
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
 */
extern void cfile_open_failure_message(const char *progname,
                                       const char *filename, int err,
                                       gchar *err_info);

/*
 * Error message for a failed attempt to open a capture file for writing.
 * "progname" is the name of the program trying to open the file;
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "file_type_subtype" is
 * a WTAP_FILE_TYPE_SUBTYPE_ value for the type and subtype of file being
 * opened.
 */
extern void cfile_dump_open_failure_message(const char *progname,
                                            const char *filename, int err,
                                            int file_type_subtype);

/*
 * Error message for a failed attempt to read from a capture file.
 * "progname" is the name of the program trying to open the file;
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
 */
extern void cfile_read_failure_message(const char *progname,
                                       const char *filename, int err,
                                       gchar *err_info);

/*
 * Error message for a failed attempt to write to a capture file.
 * "progname" is the name of the program trying to open the file;
 * "in_filename" is the name of the file from which the record
 * being written came; "out_filename" is the name of the file to
 * which we're writing; "err" is assumed "err" is assumed to be a
 * UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed to be
 * a string giving further information for some WTAP_ERR_ values;
 * "framenum" is the frame number of the record on which the error
 * occurred; "file_type_subtype" is a WTAP_FILE_TYPE_SUBTYPE_ value
 * for the type and subtype of file being written.
 */
extern void cfile_write_failure_message(const char *progname,
                                        const char *in_filename,
                                        const char *out_filename,
                                        int err, gchar *err_info,
                                        guint32 framenum,
                                        int file_type_subtype);

/*
 * Error message for a failed attempt to close a capture file.
 * "filename" is the name of the file being closed; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value.
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
