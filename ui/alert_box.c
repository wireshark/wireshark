/* alert_box.c
 * Routines to put up various "standard" alert boxes used in multiple
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

#include <wiretap/wtap.h>
#include <wsutil/filesystem.h>

#include "ui/alert_box.h"

#include "ui/simple_dialog.h"

/*
 * Alert box for general errors.
 */
void
failure_alert_box(const char *msg_format, ...)
{
    va_list ap;

    va_start(ap, msg_format);
    vsimple_error_message_box(msg_format, ap);
    va_end(ap);
}

void
vfailure_alert_box(const char *msg_format, va_list ap)
{
    vsimple_error_message_box(msg_format, ap);
}

void
vwarning_alert_box(const char *msg_format, va_list ap)
{
    vsimple_warning_message_box(msg_format, ap);
}

/*
 * Alert box for a failed attempt to open a capture file for reading.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "err_info" is assumed
 * to be a string giving further information for some WTAP_ERR_ values..
 *
 * XXX - add explanatory secondary text for at least some of the errors;
 * various HIGs suggest that you should, for example, suggest that the
 * user remove files if the file system is full.  Perhaps that's because
 * they're providing guidelines for people less sophisticated than the
 * typical Wireshark user is, but....
 */
void
cfile_open_failure_alert_box(const char *filename, int err, gchar *err_info)
{
    gchar *display_basename;

    if (err < 0) {
        /* Wiretap error. */
        display_basename = g_filename_display_basename(filename);
        switch (err) {

        case WTAP_ERR_NOT_REGULAR_FILE:
            simple_error_message_box(
                        "The file \"%s\" is a \"special file\" or socket or other non-regular file.",
                        display_basename);
            break;

        case WTAP_ERR_RANDOM_OPEN_PIPE:
            simple_error_message_box(
                        "The file \"%s\" is a pipe or FIFO; Wireshark can't read pipe or FIFO files.\n"
                        "To capture from a pipe or FIFO use wireshark -i -",
                        display_basename);
            break;

        case WTAP_ERR_FILE_UNKNOWN_FORMAT:
            simple_error_message_box(
                        "The file \"%s\" isn't a capture file in a format Wireshark understands.",
                        display_basename);
            break;

        case WTAP_ERR_UNSUPPORTED:
            simple_error_message_box(
                        "The file \"%s\" contains record data that Wireshark doesn't support.\n"
                        "(%s)",
                        display_basename,
                        err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            simple_error_message_box(
                        "The file \"%s\" is a capture for a network type that Wireshark doesn't support.",
                        display_basename);
            break;

        case WTAP_ERR_BAD_FILE:
            simple_error_message_box(
                        "The file \"%s\" appears to be damaged or corrupt.\n"
                        "(%s)",
                        display_basename,
                        err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_CANT_OPEN:
            simple_error_message_box(
                        "The file \"%s\" could not be opened for some unknown reason.",
                        display_basename);
            break;

        case WTAP_ERR_SHORT_READ:
            simple_error_message_box(
                        "The file \"%s\" appears to have been cut short"
                        " in the middle of a packet or other data.",
                        display_basename);
            break;

        case WTAP_ERR_DECOMPRESS:
            simple_error_message_box(
                        "The file \"%s\" cannot be decompressed; it may be damaged or corrupt.\n"
                        "(%s)", display_basename,
                        err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED:
            simple_error_message_box(
                        "The file \"%s\" cannot be decompressed; it is compressed in a way that we don't support.\n"
                        "(%s)", display_basename,
                        err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        default:
            simple_error_message_box(
                        "The file \"%s\" could not be opened: %s.",
                        display_basename,
                        wtap_strerror(err));
            break;
        }
        g_free(display_basename);
    } else {
        /* OS error. */
        open_failure_alert_box(filename, err, FALSE);
    }
}

/*
 * Alert box for a failed attempt to open a capture file for writing.
 * "filename" is the name of the file being opened; "err" is assumed
 * to be a UNIX-style errno or a WTAP_ERR_ value; "file_type_subtype"
 * is a WTAP_FILE_TYPE_SUBTYPE_ value for the type and subtype of file
 * being opened.
 *
 * XXX - add explanatory secondary text for at least some of the errors;
 * various HIGs suggest that you should, for example, suggest that the
 * user remove files if the file system is full.  Perhaps that's because
 * they're providing guidelines for people less sophisticated than the
 * typical Wireshark user is, but....
 */
void
cfile_dump_open_failure_alert_box(const char *filename, int err,
                                  int file_type_subtype)
{
    gchar *display_basename;

    if (err < 0) {
        /* Wiretap error. */
        display_basename = g_filename_display_basename(filename);
        switch (err) {

        case WTAP_ERR_NOT_REGULAR_FILE:
            simple_error_message_box(
                        "The file \"%s\" is a \"special file\" or socket or other non-regular file.",
                        display_basename);
            break;

        case WTAP_ERR_CANT_WRITE_TO_PIPE:
            simple_error_message_box(
                        "The file \"%s\" is a pipe, and %s capture files can't be "
                        "written to a pipe.",
                        display_basename, wtap_file_type_subtype_string(file_type_subtype));
            break;

        case WTAP_ERR_UNWRITABLE_FILE_TYPE:
            simple_error_message_box(
                        "Wireshark doesn't support writing capture files in that format.");
            break;

        case WTAP_ERR_UNWRITABLE_ENCAP:
            simple_error_message_box("Wireshark can't save this capture in that format.");
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            simple_error_message_box(
                        "Wireshark can't save this capture in that format.");
            break;

        case WTAP_ERR_CANT_OPEN:
            simple_error_message_box(
                        "The file \"%s\" could not be created for some unknown reason.",
                        display_basename);
            break;

        case WTAP_ERR_SHORT_WRITE:
            simple_error_message_box(
                        "A full header couldn't be written to the file \"%s\".",
                        display_basename);
            break;

        case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
            simple_error_message_box(
                        "This file type cannot be written as a compressed file.");
            break;

        default:
            simple_error_message_box(
                        "The file \"%s\" could not be created: %s.",
                        display_basename,
                        wtap_strerror(err));
            break;
        }
        g_free(display_basename);
    } else {
        /* OS error. */
        open_failure_alert_box(filename, err, TRUE);
    }
}

/*
 * Alert box for a failed attempt to read from a capture file.
 * "err" is assumed to be a UNIX-style errno or a WTAP_ERR_ value;
 * "err_info" is assumed to be a string giving further information for
 * some WTAP_ERR_ values.
 */
void
cfile_read_failure_alert_box(const char *filename, int err, gchar *err_info)
{
    gchar *display_name;

    if (filename == NULL)
        display_name = g_strdup("capture file");
    else {
        gchar *display_basename;

        display_basename = g_filename_display_basename(filename);
        display_name = g_strdup_printf("capture file \"%s\"", display_basename);
        g_free(display_basename);
    }

    switch (err) {

    case WTAP_ERR_UNSUPPORTED:
        simple_error_message_box(
                    "The %s contains record data that Wireshark doesn't support.\n"
                    "(%s)",
		    display_name,
                    err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    case WTAP_ERR_SHORT_READ:
        simple_error_message_box(
                    "The %s appears to have been cut short in the middle of a packet.",
                    display_name);
        break;

    case WTAP_ERR_BAD_FILE:
        simple_error_message_box(
                    "The %s appears to be damaged or corrupt.\n"
                    "(%s)",
                    display_name,
                    err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    case WTAP_ERR_DECOMPRESS:
        simple_error_message_box(
                    "The %s cannot be decompressed; it may be damaged or corrupt.\n"
                    "(%s)",
                    display_name,
                    err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    case WTAP_ERR_DECOMPRESSION_NOT_SUPPORTED:
        simple_error_message_box(
                    "The %s cannot be decompressed; it is compressed in a way that we don't support.\n"
                    "(%s)",
                    display_name,
                    err_info != NULL ? err_info : "no information supplied");
        g_free(err_info);
        break;

    default:
        simple_error_message_box(
                    "An error occurred while reading the %s: %s.",
                    display_name,
                    wtap_strerror(err));
        break;
    }
    g_free(display_name);
}

/*
 * Alert box for a failed attempt to write to a capture file.
 * "in_filename" is the name of the file from which the record being
 * written came; "out_filename" is the name of the file to which we're
 * writing; "err" is assumed "err" is assumed to be a UNIX-style errno
 * or a WTAP_ERR_ value; "err_info" is assumed to be a string giving
 * further information for some WTAP_ERR_ values; "framenum" is the frame
 * number of the record on which the error occurred; "file_type_subtype"
 * is a WTAP_FILE_TYPE_SUBTYPE_ value for the type and subtype of file
 * being written.
 */
void
cfile_write_failure_alert_box(const char *in_filename, const char *out_filename,
                              int err, gchar *err_info, guint32 framenum,
                              int file_type_subtype)
{
    char *in_file_string;
    char *out_display_basename;

    if (err < 0) {
        /* Wiretap error. */
        if (in_filename == NULL)
            in_file_string = g_strdup("");
        else
            in_file_string = g_strdup_printf(" of file \"%s\"", in_filename);

        switch (err) {

        case WTAP_ERR_UNWRITABLE_ENCAP:
            /*
             * This is a problem with the particular frame we're writing and
             * the file type and subtype we're writing; note that, and report
             * the frame number and file type/subtype.
             */
            simple_error_message_box(
                        "Frame %u%s has a network type that can't be saved in a \"%s\" file.",
                        framenum, in_file_string,
                        wtap_file_type_subtype_string(file_type_subtype));
            break;

        case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
            /*
             * This is a problem with the particular frame we're writing and
             * the file type and subtype we're writing; note that, and report
             * the frame number and file type/subtype.
             */
            simple_error_message_box(
                        "Frame %u%s has a network type that differs from the network type of earlier packets, which isn't supported in a \"%s\" file.",
                        framenum, in_file_string,
                        wtap_file_type_subtype_string(file_type_subtype));
            break;

        case WTAP_ERR_PACKET_TOO_LARGE:
            /*
             * This is a problem with the particular frame we're writing and
             * the file type and subtype we're writing; note that, and report
             * the frame number and file type/subtype.
             */
            simple_error_message_box(
                        "Frame %u%s is larger than Wireshark supports in a \"%s\" file.",
                        framenum, in_file_string,
                        wtap_file_type_subtype_string(file_type_subtype));
            break;

        case WTAP_ERR_UNWRITABLE_REC_TYPE:
            /*
             * This is a problem with the particular record we're writing and
             * the file type and subtype we're writing; note that, and report
             * the record number and file type/subtype.
             */
            simple_error_message_box(
                        "Record %u%s has a record type that can't be saved in a \"%s\" file.",
                        framenum, in_file_string,
                        wtap_file_type_subtype_string(file_type_subtype));
            break;

        case WTAP_ERR_UNWRITABLE_REC_DATA:
            /*
             * This is a problem with the particular record we're writing and
             * the file type and subtype we're writing; note that, and report
             * the record number and file type/subtype.
             */
            simple_error_message_box(
                        "Record %u%s has data that can't be saved in a \"%s\" file.\n"
                        "(%s)",
                        framenum, in_file_string,
                        wtap_file_type_subtype_string(file_type_subtype),
                        err_info != NULL ? err_info : "no information supplied");
            g_free(err_info);
            break;

        case WTAP_ERR_SHORT_WRITE:
            out_display_basename = g_filename_display_basename(out_filename);
            simple_error_message_box(
                        "A full write couldn't be done to the file \"%s\".",
                        out_display_basename);
            g_free(out_display_basename);
            break;

        default:
            out_display_basename = g_filename_display_basename(out_filename);
            simple_error_message_box(
                        "An error occurred while writing to the file \"%s\": %s.",
                        out_display_basename, wtap_strerror(err));
            g_free(out_display_basename);
            break;
        }
        g_free(in_file_string);
    } else {
        /* OS error. */
        write_failure_alert_box(out_filename, err);
    }
}

/*
 * Alert box for a failed attempt to close a capture file.
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
 *
 * XXX - add explanatory secondary text for at least some of the errors;
 * various HIGs suggest that you should, for example, suggest that the
 * user remove files if the file system is full.  Perhaps that's because
 * they're providing guidelines for people less sophisticated than the
 * typical Wireshark user is, but....
 */
void
cfile_close_failure_alert_box(const char *filename, int err)
{
    gchar *display_basename;

    if (err < 0) {
        /* Wiretap error. */
        display_basename = g_filename_display_basename(filename);
        switch (err) {

        case WTAP_ERR_CANT_CLOSE:
            simple_error_message_box(
                        "The file \"%s\" couldn't be closed for some unknown reason.",
                        display_basename);
            break;

        case WTAP_ERR_SHORT_WRITE:
            simple_error_message_box(
                        "A full write couldn't be done to the file \"%s\".",
                        display_basename);
            break;

        default:
            simple_error_message_box(
                        "An error occurred while closing the file \"%s\": %s.",
                        display_basename, wtap_strerror(err));
            break;
        }
        g_free(display_basename);
    } else {
        /* OS error.
           We assume that a close error from the OS is really a write error. */
        write_failure_alert_box(filename, err);
    }
}

/*
 * Alert box for a failed attempt to open or create a file.
 * "err" is assumed to be a UNIX-style errno; "for_writing" is TRUE if
 * the file is being opened for writing and FALSE if it's being opened
 * for reading.
 *
 * XXX - add explanatory secondary text for at least some of the errors;
 * various HIGs suggest that you should, for example, suggest that the
 * user remove files if the file system is full.  Perhaps that's because
 * they're providing guidelines for people less sophisticated than the
 * typical Wireshark user is, but....
 */
void
open_failure_alert_box(const char *filename, int err, gboolean for_writing)
{
    gchar *display_basename;

    display_basename = g_filename_display_basename(filename);
    simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                        file_open_error_message(err, for_writing),
                        display_basename);
    g_free(display_basename);
}

/*
 * Alert box for a failed attempt to read a file.
 * "err" is assumed to be a UNIX-style errno.
 */
void
read_failure_alert_box(const char *filename, int err)
{
    gchar *display_basename;

    display_basename = g_filename_display_basename(filename);
    simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                       "An error occurred while reading from the file \"%s\": %s.",
                       display_basename, g_strerror(err));
    g_free(display_basename);
}

/*
 * Alert box for a failed attempt to write to a file.
 * "err" is assumed to be a UNIX-style errno if positive and a
 * Wiretap error if negative.
 *
 * XXX - add explanatory secondary text for at least some of the errors;
 * various HIGs suggest that you should, for example, suggest that the
 * user remove files if the file system is full.  Perhaps that's because
 * they're providing guidelines for people less sophisticated than the
 * typical Wireshark user is, but....
 */
void
write_failure_alert_box(const char *filename, int err)
{
    gchar *display_basename;

    display_basename = g_filename_display_basename(filename);
    if (err < 0) {
        switch (err) {

        case WTAP_ERR_SHORT_WRITE:
            simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                              "A full write couldn't be done to the file \"%s\".",
                              display_basename);
        break;

        default:
            simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                              "An error occurred while writing to the file \"%s\": %s.",
                              display_basename, wtap_strerror(err));
        break;
        }
    } else {
        simple_message_box(ESD_TYPE_ERROR, NULL, NULL,
                           file_write_error_message(err), display_basename);
    }
    g_free(display_basename);
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
