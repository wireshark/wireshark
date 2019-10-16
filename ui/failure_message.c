/* failure_message.c
 * Routines to print various "standard" failure messages used in multiple
 * places
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

#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <ui/cmdarg_err.h>

#include "ui/failure_message.h"

static char *
input_file_description(const char *fname)
{
    char *fstring;

    if (strcmp(fname, "-") == 0) {
        /* We're reading from the standard input */
        fstring = g_strdup("standard input");
    } else {
        /* We're reading from a file */
        fstring = g_strdup_printf("file \"%s\"", fname);
    }
    return fstring;
}

static char *
output_file_description(const char *fname)
{
    char *fstring;

    if (strcmp(fname, "-") == 0) {
        /* We're writing to to the standard output */
        fstring = g_strdup("standard output");
    } else {
        /* We're writing to a file */
        fstring = g_strdup_printf("file \"%s\"", fname);
    }
    return fstring;
}

/*
 * Error message for a failed attempt to open a capture file for reading.
 * "progname" is the name of the program trying to open the file;
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
 */
void
cfile_open_failure_message(const char *progname, const char *filename,
                           int err, gchar *err_info)
{
    if (err < 0) {
        /*
         * Wiretap error.
         * Get a string that describes what we're opening.
         */
        char *file_description = input_file_description(filename);

        switch (err) {

        case WTAP_ERR_NOT_REGULAR_FILE:
            cmdarg_err("The %s is a \"special file\" or socket or other non-regular file.",
                       file_description);
            break;

        case WTAP_ERR_RANDOM_OPEN_PIPE:
            cmdarg_err("The %s is a pipe or FIFO; %s can't read pipe or FIFO files in two-pass mode.",
                       file_description, progname);
            break;

        case WTAP_ERR_FILE_UNKNOWN_FORMAT:
            cmdarg_err("The %s isn't a capture file in a format %s understands.",
                       file_description, progname);
            break;

        case WTAP_ERR_UNSUPPORTED:
            cmdarg_err("The %s contains record data that %s doesn't support.\n"
                       "(%s)",
                       file_description, progname,
                       err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            cmdarg_err("The %s is a capture for a network type that %s doesn't support.",
                       file_description, progname);
            break;

        case WTAP_ERR_BAD_FILE:
            cmdarg_err("The %s appears to be damaged or corrupt.\n"
                       "(%s)",
                       file_description,
                       err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_CANT_OPEN:
            cmdarg_err("The %s could not be opened for some unknown reason.",
                       file_description);
            break;

        case WTAP_ERR_SHORT_READ:
            cmdarg_err("The %s appears to have been cut short in the middle of a packet or other data.",
                       file_description);
            break;

        case WTAP_ERR_DECOMPRESS:
            cmdarg_err("The %s cannot be decompressed; it may be damaged or corrupt."
                       "(%s)",
                       file_description,
                       err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED:
            cmdarg_err("The %s cannot be decompressed; it is compressed in a way that we don't support."
                       "(%s)",
                       file_description,
                       err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        default:
            cmdarg_err("The %s could not be opened: %s.",
                       file_description,
                       wtap_strerror(err));
            break;
        }
        g_free(file_description);
    } else
        cmdarg_err(file_open_error_message(err, FALSE), filename);
}

/*
 * Error message for a failed attempt to open a capture file for writing.
 * "progname" is the name of the program trying to open the file;
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "file_type_subtype" is
 * a WTAP_FILE_TYPE_SUBTYPE_ value for the type and subtype of file being
 * opened.
 */
void
cfile_dump_open_failure_message(const char *progname, const char *filename,
                                int err, int file_type_subtype)
{
    if (err < 0) {
        /*
         * Wiretap error.
         * Get a string that describes what we're opening.
         */
        char *file_description = input_file_description(filename);

        switch (err) {

        case WTAP_ERR_NOT_REGULAR_FILE:
            cmdarg_err("The %s is a \"special file\" or socket or other non-regular file.",
                       file_description);
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            cmdarg_err("The %s is a pipe, and \"%s\" capture files can't be written to a pipe.",
                       file_description,
                       wtap_file_type_subtype_short_string(file_type_subtype));
            break;

        case WTAP_ERR_UNWRITABLE_FILE_TYPE:
            cmdarg_err("%s doesn't support writing capture files in that format.",
                       progname);
            break;

        case WTAP_ERR_UNWRITABLE_ENCAP:
            cmdarg_err("The capture file being read can't be written as a \"%s\" file.",
                       wtap_file_type_subtype_short_string(file_type_subtype));
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            cmdarg_err("The capture file being read can't be written as a \"%s\" file.",
                       wtap_file_type_subtype_short_string(file_type_subtype));
            break;

        case WTAP_ERR_CANT_OPEN:
            cmdarg_err("The %s could not be created for some unknown reason.",
                       file_description);
            break;

        case WTAP_ERR_SHORT_WRITE:
            cmdarg_err("A full header couldn't be written to the %s.",
                       file_description);
            break;

        case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
            cmdarg_err("This file type cannot be written as a compressed file.");
            break;

        default:
            cmdarg_err("The %s could not be created: %s.",
                       file_description,
                       wtap_strerror(err));
            break;
        }
        g_free(file_description);
    } else
        cmdarg_err(file_open_error_message(err, TRUE), filename);
}

/*
 * Error message for a failed attempt to read from a capture file.
 * "progname" is the name of the program trying to open the file;
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
 */
void
cfile_read_failure_message(const char *progname, const char *filename,
                           int err, gchar *err_info)
{
    char *file_string;

    /* Get a string that describes what we're reading from */
    file_string = input_file_description(filename);

    switch (err) {

    case WTAP_ERR_UNSUPPORTED:
        cmdarg_err("The %s contains record data that %s doesn't support.\n"
                   "(%s)",
                   file_string, progname,
                   err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    case WTAP_ERR_SHORT_READ:
        cmdarg_err("The %s appears to have been cut short in the middle of a packet.",
                   file_string);
        break;

    case WTAP_ERR_BAD_FILE:
        cmdarg_err("The %s appears to be damaged or corrupt.\n"
                   "(%s)",
                   file_string,
                   err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    case WTAP_ERR_DECOMPRESS:
        cmdarg_err("The %s cannot be decompressed; it may be damaged or corrupt.\n"
                   "(%s)",
                   file_string,
                   err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    case WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED:
        cmdarg_err("The %s cannot be decompressed; it is compressed in a way that we don't support.\n"
                   "(%s)",
                   file_string,
                   err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    default:
        cmdarg_err("An error occurred while reading the %s: %s.",
                   file_string, wtap_strerror(err));
        break;
    }
    g_free(file_string);
}

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
void
cfile_write_failure_message(const char *progname, const char *in_filename,
                            const char *out_filename, int err, gchar *err_info,
                            guint32 framenum, int file_type_subtype)
{
    char *in_file_string;
    char *in_frame_string;
    char *out_file_string;

    /* Get a string that describes what we're reading from */
    if (in_filename == NULL) {
        in_frame_string = g_strdup("");
    } else {
        in_file_string = input_file_description(in_filename);
        in_frame_string = g_strdup_printf(" %u of %s", framenum,
                                          in_file_string);
        g_free(in_file_string);
    }

    /* Get a string that describes what we're writing to */
    out_file_string = output_file_description(out_filename);

    switch (err) {

    case WTAP_ERR_UNWRITABLE_ENCAP:
        /*
         * This is a problem with the particular frame we're writing
         * and the file type and subtype we're writing; note that,
         * and report the frame number and file type/subtype.
         */
        cmdarg_err("Frame%s has a network type that can't be saved in a \"%s\" file.",
                   in_frame_string,
                   wtap_file_type_subtype_short_string(file_type_subtype));
        break;

    case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
        /*
         * This is a problem with the particular frame we're writing and
         * the file type and subtype we're writing; note that, and report
         * the frame number and file type/subtype.
         */
        cmdarg_err("Frame%s has a network type that differs from the network type of earlier packets, which isn't supported in a \"%s\" file.",
                   in_frame_string,
                   wtap_file_type_subtype_string(file_type_subtype));
        break;

    case WTAP_ERR_PACKET_TOO_LARGE:
        /*
         * This is a problem with the particular frame we're writing
         * and the file type and subtype we're writing; note that,
         * and report the frame number and file type/subtype.
         */
        cmdarg_err("Frame%s is larger than %s supports in a \"%s\" file.",
                   in_frame_string, progname,
                   wtap_file_type_subtype_short_string(file_type_subtype));
        break;

    case WTAP_ERR_UNWRITABLE_REC_TYPE:
        /*
         * This is a problem with the particular record we're writing
         * and the file type and subtype we're writing; note that,
         * and report the record number and file type/subtype.
         */
        cmdarg_err("Record%s has a record type that can't be saved in a \"%s\" file.",
                   in_frame_string,
                   wtap_file_type_subtype_short_string(file_type_subtype));
        break;

    case WTAP_ERR_UNWRITABLE_REC_DATA:
        /*
         * This is a problem with the particular record we're writing
         * and the file type and subtype we're writing; note that,
         * and report the record number and file type/subtype.
         */
        cmdarg_err("Record%s has data that can't be saved in a \"%s\" file.\n"
                   "(%s)",
                   in_frame_string,
                   wtap_file_type_subtype_short_string(file_type_subtype),
                   err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    case ENOSPC:
        cmdarg_err("Not all the packets could be written to the %s because there is "
                   "no space left on the file system.",
                   out_file_string);
        break;

#ifdef EDQUOT
    case EDQUOT:
        cmdarg_err("Not all the packets could be written to the %s because you are "
                   "too close to, or over your disk quota.",
                   out_file_string);
  break;
#endif

    case WTAP_ERR_SHORT_WRITE:
        cmdarg_err("A full write couldn't be done to the %s.",
                   out_file_string);
        break;

    default:
        cmdarg_err("An error occurred while writing to the %s: %s.",
                   out_file_string, wtap_strerror(err));
        break;
    }
    g_free(in_frame_string);
    g_free(out_file_string);
}

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
void
cfile_close_failure_message(const char *filename, int err)
{
    char *file_string;

    /* Get a string that describes what we're writing to */
    file_string = output_file_description(filename);

    switch (err) {

    case ENOSPC:
        cmdarg_err("Not all the packets could be written to the %s because there is "
                   "no space left on the file system.",
                   file_string);
    break;

#ifdef EDQUOT
    case EDQUOT:
        cmdarg_err("Not all the packets could be written to the %s because you are "
                   "too close to, or over your disk quota.",
                   file_string);
  break;
#endif

    case WTAP_ERR_CANT_CLOSE:
        cmdarg_err("The %s couldn't be closed for some unknown reason.",
                   file_string);
        break;

    case WTAP_ERR_SHORT_WRITE:
        cmdarg_err("A full write couldn't be done to the %s.",
                   file_string);
        break;

    default:
        cmdarg_err("An error occurred while closing the file %s: %s.",
                   file_string, wtap_strerror(err));
        break;
    }
    g_free(file_string);
}
