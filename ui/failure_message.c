/* failure_message.c
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

#include "config.h"

#include <string.h>
#include <errno.h>

#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>
#include <wsutil/cmdarg_err.h>

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
 * Error message for a failed attempt to open or create a capture file.
 * "err" is assumed to be a UNIX-style errno or a WTAP_ERR_ value;
 * "err_info" is assumed to be a string giving further information for
 * some WTAP_ERR_ values; "for_writing" is TRUE if the file is being
 * opened for writing and FALSE if it's being opened for reading;
 * "file_type_subtype" is a WTAP_FILE_TYPE_SUBTYPE_ value for the type
 * and subtype of file being opened for writing (it's ignored for
 * opening-for-reading errors).
 */
void
cfile_open_failure_message(const char *progname, const char *filename,
                           int err, gchar *err_info, gboolean for_writing,
                           int file_type)
{
    char *file_description;

    /* Get a string that describes what we're opening */
    if (for_writing)
        file_description = output_file_description(filename);
    else
        file_description = input_file_description(filename);

    if (err < 0) {
        /* Wiretap error. */
        switch (err) {

        case WTAP_ERR_NOT_REGULAR_FILE:
            cmdarg_err("The %s is a \"special file\" or socket or other non-regular file.",
                       file_description);
            break;

        case WTAP_ERR_RANDOM_OPEN_PIPE:
            /* Seen only when opening a capture file for reading. */
            cmdarg_err("The %s is a pipe or FIFO; %s can't read pipe or FIFO files in two-pass mode.",
                       file_description, progname);
            break;

        case WTAP_ERR_FILE_UNKNOWN_FORMAT:
            /* Seen only when opening a capture file for reading. */
            cmdarg_err("The %s isn't a capture file in a format %s understands.",
                       file_description, progname);
            break;

        case WTAP_ERR_UNSUPPORTED:
            /* Seen only when opening a capture file for reading. */
            cmdarg_err("The %s contains record data that %s doesn't support.\n"
                       "(%s)",
                       file_description, progname,
                       err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            /* Seen only when opening a capture file for writing. */
            cmdarg_err("The %s is a pipe, and \"%s\" capture files can't be written to a pipe.",
                       file_description,
                       wtap_file_type_subtype_short_string(file_type));
            break;

        case WTAP_ERR_UNWRITABLE_FILE_TYPE:
            /* Seen only when opening a capture file for writing. */
            cmdarg_err("%s doesn't support writing capture files in that format.",
                       progname);
            break;

        case WTAP_ERR_UNWRITABLE_ENCAP:
            /* Seen only when opening a capture file for writing. */
            cmdarg_err("The capture file being read can't be written as a \"%s\" file.",
                       wtap_file_type_subtype_short_string(file_type));
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            if (for_writing) {
                cmdarg_err("The capture file being read can't be written as a \"%s\" file.",
                           wtap_file_type_subtype_short_string(file_type));
            } else {
                cmdarg_err("The %s is a capture for a network type that %s doesn't support.",
                           file_description, progname);
            }
            break;

        case WTAP_ERR_BAD_FILE:
            /* Seen only when opening a capture file for reading. */
            cmdarg_err("The %s appears to be damaged or corrupt.\n"
                       "(%s)",
                       file_description,
                       err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_CANT_OPEN:
            if (for_writing) {
                cmdarg_err("The %s could not be created for some unknown reason.",
                           file_description);
            } else {
                cmdarg_err("The %s could not be opened for some unknown reason.",
                           file_description);
            }
            break;

        case WTAP_ERR_SHORT_READ:
            cmdarg_err("The %s appears to have been cut short in the middle of a packet or other data.",
                       file_description);
            break;

        case WTAP_ERR_SHORT_WRITE:
            cmdarg_err("A full header couldn't be written to the %s.",
                       file_description);
            break;

        case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
            cmdarg_err("This file type cannot be written as a compressed file.");
            break;

        case WTAP_ERR_DECOMPRESS:
            /* Seen only when opening a capture file for reading. */
            cmdarg_err("The %s cannot be decompressed; it may be damaged or corrupt."
                       "(%s)",
                       file_description,
                       err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        default:
            cmdarg_err("The %s could not be %s: %s.",
                       file_description,
                       for_writing ? "created" : "opened",
                       wtap_strerror(err));
            break;
        }
        g_free(file_description);
    } else
        cmdarg_err(file_open_error_message(err, for_writing), filename);
}

/*
 * Error message for a failed attempt to read from a capture file.
 * "err" is assumed to be a UNIX-style errno or a WTAP_ERR_ value;
 * "err_info" is assumed to be a string giving further information for
 * some WTAP_ERR_ values.
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

    default:
        cmdarg_err("An error occurred while reading the %s: %s.",
                   file_string, wtap_strerror(err));
        break;
    }
    g_free(file_string);
}

/*
 * Error message for a failed attempt to write to a capture file.
 * "err" is assumed to be a UNIX-style errno or a WTAP_ERR_ value;
 * "err_info" is assumed to be a string giving further information for
 * some WTAP_ERR_ values; "framenum" is the frame number of the record
 * on which the error occurred; "file_type_subtype" is a
 * WTAP_FILE_TYPE_SUBTYPE_ value for the type and subtype of file being
 * written.
 */
void
cfile_write_failure_message(const char *progname, const char *in_filename,
                            const char *out_filename, int err, gchar *err_info,
                            guint32 framenum, int file_type_subtype)
{
    char *in_file_string;
    char *out_file_string;

    /* Get a string that describes what we're reading from */
    in_file_string = input_file_description(in_filename);

    /* Get a string that describes what we're writing to */
    out_file_string = output_file_description(out_filename);

    switch (err) {

    case WTAP_ERR_UNWRITABLE_ENCAP:
        /*
         * This is a problem with the particular frame we're writing
         * and the file type and subtype we're writing; note that,
         * and report the frame number and file type/subtype.
         */
        cmdarg_err("Frame %u of %s has a network type that can't be saved in a \"%s\" file.",
                   framenum, in_file_string,
                   wtap_file_type_subtype_short_string(file_type_subtype));
        break;

    case WTAP_ERR_PACKET_TOO_LARGE:
        /*
         * This is a problem with the particular frame we're writing
         * and the file type and subtype we're writing; note that,
         * and report the frame number and file type/subtype.
         */
        cmdarg_err("Frame %u of %s is larger than %s supports in a \"%s\" file.",
                   framenum, in_file_string, progname,
                   wtap_file_type_subtype_short_string(file_type_subtype));
        break;

    case WTAP_ERR_UNWRITABLE_REC_TYPE:
        /*
         * This is a problem with the particular record we're writing
         * and the file type and subtype we're writing; note that,
         * and report the record number and file type/subtype.
         */
        cmdarg_err("Record %u of %s has a record type that can't be saved in a \"%s\" file.",
                   framenum, in_file_string,
                   wtap_file_type_subtype_short_string(file_type_subtype));
        break;

    case WTAP_ERR_UNWRITABLE_REC_DATA:
        /*
         * This is a problem with the particular record we're writing
         * and the file type and subtype we're writing; note that,
         * and report the record number and file type/subtype.
         */
        cmdarg_err("Record %u of %s has data that can't be saved in a \"%s\" file.\n"
                   "(%s)",
                   framenum, in_file_string,
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
    g_free(in_file_string);
    g_free(out_file_string);
}

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
