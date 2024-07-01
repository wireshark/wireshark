/** @file
 *
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
 * Generic error message.
 */
extern void failure_message(const char *msg_format, va_list ap);

/*
 * Error message for a failed attempt to open or create a file
 * other than a capture file.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno; "for_writing" is true if we're opening
 * the file for writing and false if we're opening it for reading.
 */
extern void open_failure_message(const char *filename, int err,
                                 bool for_writing);

/*
 * Error message for a failed attempt to read from a file other than
 * a capture file.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno.
 */
extern void read_failure_message(const char *filename, int err);

/*
 * Error message for a failed attempt to write to a file other than
 * a capture file.
 * "filename" is the name of the file being written to; "err" is assumed
 * to be a UNIX-style errno.
 */
extern void write_failure_message(const char *filename, int err);

/*
 * Error message for a failed attempt to open a capture file for input.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
 */
extern void cfile_open_failure_message(const char *filename, int err,
                                       char *err_info);

/*
 * Error message for a failed attempt to open a capture file for output.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values;
 * "file_type_subtype" is a WTAP_FILE_TYPE_SUBTYPE_ value for the type
 * and subtype of file being opened.
 */
extern void cfile_dump_open_failure_message(const char *filename, int err,
                                            char *err_info,
                                            int file_type_subtype);

/*
 * Error message for a failed attempt to read from a capture file.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
 */
extern void cfile_read_failure_message(const char *filename, int err,
                                       char *err_info);

/*
 * Error message for a failed attempt to write to a capture file.
 * "in_filename" is the name of the file from which the record
 * being written came; "out_filename" is the name of the file to
 * which we're writing; "err" is assumed "err" is assumed to be a
 * UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed to be
 * a string giving further information for some WTAP_ERR_ values;
 * "framenum" is the frame number of the record on which the error
 * occurred; "file_type_subtype" is a WTAP_FILE_TYPE_SUBTYPE_ value
 * for the type and subtype of file being written.
 */
extern void cfile_write_failure_message(const char *in_filename,
                                        const char *out_filename,
                                        int err, char *err_info,
                                        uint64_t framenum,
                                        int file_type_subtype);

/*
 * Error message for a failed attempt to close a capture file.
 * "filename" is the name of the file being closed; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
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
extern void cfile_close_failure_message(const char *filename, int err,
                                        char *err_info);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FAILURE_MESSAGE_H__ */
