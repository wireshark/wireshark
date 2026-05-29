/** @file
 * Declarations of routines for code that can run in GUI and command-line
 * environments to use to report errors and warnings to the user (e.g.,
 * I/O errors, or problems with preference settings) if the message should
 * be shown as a GUI error in a GUI environment.
 *
 * The application using libwsutil will register message-reporting
 * routines, and the routines declared here will call the registered
 * routines.  That way, these routines can be called by code that
 * doesn't itself know whether to pop up a dialog or print something
 * to the standard error.
 *
 * XXX - Should the capture file (_cfile_) routines be moved to libwiretap?
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __REPORT_MESSAGE_H__
#define __REPORT_MESSAGE_H__

#include <wireshark.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * @brief Dispatch table of error and warning reporting callbacks, allowing
 *        different application frontends to handle diagnostic messages independently.
 */
struct report_message_routines {
    /** @brief Reports a formatted fatal failure message via a va_list argument list.
     *  @param fmt  printf-style format string.
     *  @param ap   Variable argument list for the format string. */
    void (*vreport_failure)(const char *fmt, va_list ap);

    /** @brief Reports a formatted non-fatal warning message via a va_list argument list.
     *  @param fmt  printf-style format string.
     *  @param ap   Variable argument list for the format string. */
    void (*vreport_warning)(const char *fmt, va_list ap);

    /** @brief Reports a failure to open a file.
     *  @param filename  Path of the file that could not be opened.
     *  @param err       errno value describing the failure.
     *  @param for_writing  True if the file was being opened for writing; false for reading. */
    void (*report_open_failure)(const char *filename, int err, bool for_writing);

    /** @brief Reports a failure to read from a file.
     *  @param filename  Path of the file that could not be read.
     *  @param err       errno value describing the failure. */
    void (*report_read_failure)(const char *filename, int err);

    /** @brief Reports a failure to write to a file.
     *  @param filename  Path of the file that could not be written.
     *  @param err       errno value describing the failure. */
    void (*report_write_failure)(const char *filename, int err);

    /** @brief Reports a failure to rename a file.
     *  @param old_filename  Original path of the file.
     *  @param new_filename  Target path the file could not be renamed to.
     *  @param err           errno value describing the failure. */
    void (*report_rename_failure)(const char *old_filename, const char *new_filename, int err);

    /** @brief Reports a failure to open a capture file.
     *  @param filename  Path of the capture file that could not be opened.
     *  @param err       errno or wtap error code describing the failure.
     *  @param err_info  Additional error detail string, or NULL. */
    void (*report_cfile_open_failure)(const char *filename, int err, char *err_info);

    /** @brief Reports a failure to open a capture file for dumping (writing).
     *  @param filename   Path of the capture file that could not be opened.
     *  @param err        errno or wtap error code describing the failure.
     *  @param err_info   Additional error detail string, or NULL.
     *  @param file_type  wtap file type identifier of the intended output format. */
    void (*report_cfile_dump_open_failure)(const char *filename, int err, char *err_info, int file_type);

    /** @brief Reports a failure to read from a capture file.
     *  @param filename  Path of the capture file that could not be read.
     *  @param err       errno or wtap error code describing the failure.
     *  @param err_info  Additional error detail string, or NULL. */
    void (*report_cfile_read_failure)(const char *filename, int err, char *err_info);

    /** @brief Reports a failure to write a frame to a capture file.
     *  @param in_filename   Path of the source capture file being read.
     *  @param out_filename  Path of the destination capture file being written.
     *  @param err           errno or wtap error code describing the failure.
     *  @param err_info      Additional error detail string, or NULL.
     *  @param framenum      Frame number of the packet that could not be written.
     *  @param file_type     wtap file type identifier of the output format. */
    void (*report_cfile_write_failure)(const char *in_filename, const char *out_filename,
        int err, char *err_info, uint64_t framenum, int file_type);

    /** @brief Reports a failure to close a capture file.
     *  @param filename  Path of the capture file that could not be closed cleanly.
     *  @param err       errno or wtap error code describing the failure.
     *  @param err_info  Additional error detail string, or NULL. */
    void (*report_cfile_close_failure)(const char *filename, int err, char *err_info);
};

/**
 * @brief Initialize the report message system with program context and output routines.
 *
 * This function sets up the global reporting mechanism used for error, warning,
 * and informational messages. It registers the program name and the set of
 * callback routines that handle message output.
 *
 * @param friendly_program_name A human-readable name for the program (e.g., "Wireshark").
 *                              This name may be included in formatted messages.
 * @param routines Pointer to a structure containing function pointers for handling
 *                 different types of report messages (e.g., errors, warnings, debug).
 *
 * @note This function should be called early during application initialization,
 * before any report messages are emitted.
 */
WS_DLL_PUBLIC void init_report_message(const char *friendly_program_name,
                                       const struct report_message_routines *routines);

/**
 * @brief Report a general error message.
 *
 * Formats and emits an error message using the global reporting system.
 *
 * @param msg_format `printf`-style format string.
 * @param ... Arguments matching the format string.
 */
WS_DLL_PUBLIC void report_failure(const char *msg_format, ...) G_GNUC_PRINTF(1, 2);

/**
 * @brief Report a general warning message.
 *
 * Formats and emits a warning message using the global reporting system.
 *
 * @param msg_format `printf`-style format string.
 * @param ... Arguments matching the format string.
 */
WS_DLL_PUBLIC void report_warning(const char *msg_format, ...) G_GNUC_PRINTF(1, 2);

/**
 * @brief Reports an error encountered while opening a file.
 *
 * @p err is assumed to be a Wiretap error code; positive values are
 * UNIX-style errnos, so this function may also be used for open failures
 * that do not originate from Wiretap, provided the failure code is a plain errno.
 *
 * @param filename    Path of the file that could not be opened.
 * @param err         Wiretap or UNIX errno error code describing the failure.
 * @param for_writing @c true if the file was being opened for writing;
 *                    @c false if it was being opened for reading.
 */
WS_DLL_PUBLIC void report_open_failure(const char *filename, int err,
    bool for_writing);

/**
 * @brief Reports an error encountered while reading a file.
 * @param filename Path of the file that could not be read.
 * @param err      UNIX errno error code describing the failure.
 */
WS_DLL_PUBLIC void report_read_failure(const char *filename, int err);

/**
 * @brief Reports an error encountered while writing a file.
 * @param filename Path of the file that could not be written.
 * @param err      UNIX errno error code describing the failure.
 */
WS_DLL_PUBLIC void report_write_failure(const char *filename, int err);

/**
 * @brief Reports an error encountered while renaming a file.
 * @param old_filename Path of the file before the rename attempt.
 * @param new_filename Intended path after the rename.
 * @param err          UNIX errno error code describing the failure.
 */
WS_DLL_PUBLIC void report_rename_failure(const char *old_filename,
    const char *new_filename, int err);

/**
 * @brief Reports an error encountered while opening a capture file for reading.
 * @param filename Path of the capture file that could not be opened.
 * @param err      Wiretap error code describing the failure.
 * @param err_info Auxiliary error information string from Wiretap; may be @c NULL.
 *                 The callee takes ownership and frees this string.
 */
WS_DLL_PUBLIC void report_cfile_open_failure(const char *filename,
    int err, char *err_info);

/**
 * @brief Reports an error encountered while opening a capture file for writing (dumping).
 * @param filename         Path of the capture file that could not be opened.
 * @param err              Wiretap error code describing the failure.
 * @param err_info         Auxiliary error information string from Wiretap; may be @c NULL.
 *                         The callee takes ownership and frees this string.
 * @param file_type_subtype Wiretap file-type subtype that was requested for the output file.
 */
WS_DLL_PUBLIC void report_cfile_dump_open_failure(const char *filename,
    int err, char *err_info, int file_type_subtype);

/**
 * @brief Reports an error encountered while reading from a capture file.
 * @param filename Path of the capture file being read.
 * @param err      Wiretap error code describing the failure.
 * @param err_info Auxiliary error information string from Wiretap; may be @c NULL.
 *                 The callee takes ownership and frees this string.
 */
WS_DLL_PUBLIC void report_cfile_read_failure(const char *filename,
    int err, char *err_info);

/**
 * @brief Reports an error encountered while writing to a capture file.
 * @param in_filename      Path of the source capture file being read during the operation,
 *                         or @c NULL if the operation is not a read-write conversion.
 * @param out_filename     Path of the destination capture file being written.
 * @param err              Wiretap error code describing the failure.
 * @param err_info         Auxiliary error information string from Wiretap; may be @c NULL.
 *                         The callee takes ownership and frees this string.
 * @param framenum         One-based frame number of the packet that triggered the error.
 * @param file_type_subtype Wiretap file-type subtype of the output file.
 */
WS_DLL_PUBLIC void report_cfile_write_failure(const char *in_filename,
    const char *out_filename, int err, char *err_info, uint64_t framenum,
    int file_type_subtype);

/**
 * @brief Reports an error encountered while closing a capture file that was open for writing.
 * @param filename Path of the capture file that could not be closed cleanly.
 * @param err      Wiretap error code describing the failure.
 * @param err_info Auxiliary error information string from Wiretap; may be @c NULL.
 *                 The callee takes ownership and frees this string.
 */
WS_DLL_PUBLIC void report_cfile_close_failure(const char *filename,
    int err, char *err_info);

/**
 * @brief Return the "friendly" program name.
 * @return The friendly program name registered with init_report_message(), or NULL if it has not been registered.
 */
WS_DLL_PUBLIC const char *get_friendly_program_name(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __REPORT_MESSAGE_H__ */
