/* report_message.c
 * Routines for code that can run in GUI and command-line environments to
 * use to report errors and warnings to the user (e.g., I/O errors, or
 * problems with preference settings) if the message should be shown as
 * a GUI error in a GUI environment.
 *
 * The application using libwsutil will register error-reporting
 * routines, and the routines defined here will call the registered
 * routines.  That way, these routines can be called by code that
 * doesn't itself know whether to pop up a dialog or print something
 * to the standard error.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
#include "config.h"

#include "report_message.h"

static const char *friendly_program_name;
static const struct report_message_routines *routines;

void
init_report_message(const char *friendly_program_name_arg,
    const struct report_message_routines *routines_arg)
{
	friendly_program_name = friendly_program_name_arg;
	routines = routines_arg;
}

/*
 * Report a general error.
 */
void
report_failure(const char *msg_format, ...)
{
	va_list ap;

	va_start(ap, msg_format);
	(*routines->vreport_failure)(msg_format, ap);
	va_end(ap);
}

/*
 * Report a general warning.
 */
void
report_warning(const char *msg_format, ...)
{
	va_list ap;

	va_start(ap, msg_format);
	(*routines->vreport_warning)(msg_format, ap);
	va_end(ap);
}

/*
 * Report an error when trying to open or create a file.
 * "err" is assumed to be an error code from Wiretap; positive values are
 * UNIX-style errnos, so this can be used for open failures not from
 * Wiretap as long as the failure code is just an errno.
 */
void
report_open_failure(const char *filename, int err,
					bool for_writing)
{
	(*routines->report_open_failure)(filename, err, for_writing);
}

/*
 * Report an error when trying to read a file.
 * "err" is assumed to be a UNIX-style errno.
 */
void
report_read_failure(const char *filename, int err)
{
	(*routines->report_read_failure)(filename, err);
}

/*
 * Report an error when trying to write a file.
 * "err" is assumed to be a UNIX-style errno.
 */
void
report_write_failure(const char *filename, int err)
{
	(*routines->report_write_failure)(filename, err);
}

/*
 * Report an error from opening a capture file for reading.
 */
void
report_cfile_open_failure(const char *filename, int err, char *err_info)
{
	(*routines->report_cfile_open_failure)(filename, err, err_info);
}

/*
 * Report an error from opening a capture file for writing.
 */
void
report_cfile_dump_open_failure(const char *filename,
    int err, char *err_info, int file_type_subtype)
{
	(*routines->report_cfile_dump_open_failure)(filename,
	    err, err_info, file_type_subtype);
}

/*
 * Report an error from attempting to read from a capture file.
 */
void
report_cfile_read_failure(const char *filename, int err, char *err_info)
{
	(*routines->report_cfile_read_failure)(filename, err, err_info);
}

/*
 * Report an error from attempting to write to a capture file.
 */
void
report_cfile_write_failure(const char *in_filename, const char *out_filename,
    int err, char *err_info, uint64_t framenum, int file_type_subtype)
{
	(*routines->report_cfile_write_failure)(in_filename, out_filename,
	    err, err_info, framenum, file_type_subtype);
}

/*
 * Report an error from closing a capture file open for writing.
 */
void
report_cfile_close_failure(const char *filename, int err, char *err_info)
{
	(*routines->report_cfile_close_failure)(filename, err, err_info);
}

/*
 * Return the "friendly" program name.
 */
const char *
get_friendly_program_name(void)
{
	return friendly_program_name;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * vi: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
