/* failure_message_simple.c
 * Routines to print various "standard" failure messages used in multiple
 * places
 *
 * This is a "simple" version that does not link with libwiretap and interpret
 * the WTAP_ERR_ or WTAP_FILE_TYPE_SUBTYPE_ values that are parameters to the
 * capture file routines (cfile_*). It is for use in dumpcap, which does not
 * link with libwiretap or libui. The libwiretap-related routines should not
 * be called from dumpcap, but a rudimentary implementation is provided since
 * wsutil/report_message expects them.
 *
 * Console programs that do link against libwiretap should include
 * ui/failure_message.h instead.
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
#include <wsutil/report_message.h>
#include <wsutil/cmdarg_err.h>

#include "wsutil/failure_message_simple.h"

/*
 * Generic error message.
 */
static void
failure_message_simple(const char *msg_format, va_list ap)
{
    vcmdarg_err(msg_format, ap);
}

/*
 * Error message for a failed attempt to open or create a file
 * other than a capture file.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno; "for_writing" is true if we're opening
 * the file for writing and false if we're opening it for reading.
 */
static void
open_failure_message_simple(const char *filename, int err, bool for_writing)
{
    cmdarg_err(file_open_error_message(err, for_writing), filename);
}

/*
 * Error message for a failed attempt to read from a file other than
 * a capture file.
 * "filename" is the name of the file being read from; "err" is assumed
 * to be a UNIX-style errno.
 */
static void
read_failure_message_simple(const char *filename, int err)
{
    cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
               filename, g_strerror(err));
}

/*
 * Error message for a failed attempt to write to a file other than
 * a capture file.
 * "filename" is the name of the file being written to; "err" is assumed
 * to be a UNIX-style errno.
 */
static void
write_failure_message_simple(const char *filename, int err)
{
    cmdarg_err("An error occurred while writing to the file \"%s\": %s.",
               filename, g_strerror(err));
}

/*
 * Error message for a failed attempt to rename a file other than
 * a capture file.
 * "old_filename" is the name of the file being renamed; "new_filename"
 * is the name to which it's being renamed; "err" is assumed to be a
 * UNIX-style errno.
 */
static void
rename_failure_message_simple(const char *old_filename, const char *new_filename,
                       int err)
{
    cmdarg_err("An error occurred while renaming the file \"%s\" to \"%s\": %s.",
               old_filename, new_filename, g_strerror(err));
}

static char*
input_file_description(const char* fname)
{
    char* fstring;

    if (strcmp(fname, "-") == 0) {
        /* We're reading from the standard input */
        fstring = g_strdup("standard input");
    } else {
        /* We're reading from a file */
        fstring = ws_strdup_printf("file \"%s\"", fname);
    }
    return fstring;
}

static char*
output_file_description(const char* fname)
{
    char* fstring;

    if (strcmp(fname, "-") == 0) {
        /* We're writing to the standard output */
        fstring = g_strdup("standard output");
    } else {
        /* We're writing to a file */
        fstring = ws_strdup_printf("file \"%s\"", fname);
    }
    return fstring;
}

/*
 * Error message for a failed attempt to open a capture file for reading.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
 */
static void
cfile_open_failure_message_simple(const char* filename, int err, char* err_info)
{
    if (err < 0) {
        /*
         * Wiretap error.
         * Get a string that describes what we're opening.
         */
        char* file_description = input_file_description(filename);

        cmdarg_err("The %s could not be opened: libwiretap error %i.",
            file_description, err);
        g_free(file_description);
    } else
        cmdarg_err(file_open_error_message(err, false), filename);
    cmdarg_err_cont("This should not happen.");
    g_free(err_info);
}

/*
 * Error message for a failed attempt to open a capture file for writing.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values;
 * "file_type_subtype" is a WTAP_FILE_TYPE_SUBTYPE_ value for the type
 * and subtype of file being opened.
 */
static void
cfile_dump_open_failure_message_simple(const char* filename, int err, char* err_info,
    int file_type_subtype _U_)
{
    if (err < 0) {
        /*
         * Wiretap error.
         * Get a string that describes what we're opening.
         */
        char* file_description = output_file_description(filename);

        cmdarg_err("The %s could not be created: libwiretap error %i.",
            file_description, err);
        g_free(file_description);
    } else
        cmdarg_err(file_open_error_message(err, true), filename);
    cmdarg_err_cont("This should not happen.");
    g_free(err_info);
}

/*
 * Error message for a failed attempt to read from a capture file.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values.
 */
static void
cfile_read_failure_message_simple(const char* filename, int err, char* err_info)
{
    char* file_string;

    /* Get a string that describes what we're reading from */
    file_string = input_file_description(filename);

    if (err < 0) {
        cmdarg_err("An error occurred while reading the %s: libwiretap error %i.",
            file_string, err);
    } else {
        cmdarg_err("An error occurred while reading the %s: %s.",
            file_string, g_strerror(err));
    }
    cmdarg_err_cont("This should not happen.");
    g_free(file_string);
    g_free(err_info);
}

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
static void
cfile_write_failure_message_simple(const char* in_filename, const char* out_filename,
    int err, char* err_info,
    uint64_t framenum, int file_type_subtype _U_)
{
    char* in_file_string;
    char* in_frame_string;
    char* out_file_string;

    /* Get a string that describes what we're reading from */
    if (in_filename == NULL) {
        in_frame_string = g_strdup("");
    } else {
        in_file_string = input_file_description(in_filename);
        in_frame_string = ws_strdup_printf(" %" PRIu64 " of %s", framenum,
            in_file_string);
        g_free(in_file_string);
    }

    /* Get a string that describes what we're writing to */
    out_file_string = output_file_description(out_filename);

    if (err < 0) {
        cmdarg_err("An error occurred while writing to the %s: libwiretap error %i.",
            out_file_string, err);
    } else {
        cmdarg_err("An error occurred while writing to the %s: %s.",
            out_file_string, g_strerror(err));
    }
    cmdarg_err_cont("This should not happen.");
    g_free(in_frame_string);
    g_free(out_file_string);
    g_free(err_info);
}

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
static void
cfile_close_failure_message_simple(const char* filename, int err, char* err_info)
{
    char* file_string;

    /* Get a string that describes what we're writing to */
    file_string = output_file_description(filename);

    if (err < 0) {
        cmdarg_err("An error occurred while closing the file %s: libwiretap error %i.",
            file_string, err);
    } else {
        cmdarg_err("An error occurred while closing the file %s: %s.",
            file_string, g_strerror(err));
    }
    cmdarg_err_cont("This should not happen.");
    g_free(file_string);
    g_free(err_info);
}

/*
 * Register these routines with the report_message mechanism.
 */
void
init_report_failure_message_simple(const char *friendly_program_name)
{
    static const struct report_message_routines report_failure_routines = {
        failure_message_simple,
        failure_message_simple,
        open_failure_message_simple,
        read_failure_message_simple,
        write_failure_message_simple,
        rename_failure_message_simple,
        cfile_open_failure_message_simple,
        cfile_dump_open_failure_message_simple,
        cfile_read_failure_message_simple,
        cfile_write_failure_message_simple,
        cfile_close_failure_message_simple
    };

    init_report_message(friendly_program_name, &report_failure_routines);
}
