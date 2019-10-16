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

#include <glib.h>
#include "report_message.h"

static void (*vreport_failure_func)(const char *, va_list);
static void (*vreport_warning_func)(const char *, va_list);
static void (*report_open_failure_func)(const char *, int, gboolean);
static void (*report_read_failure_func)(const char *, int);
static void (*report_write_failure_func)(const char *, int);

void init_report_message(void (*vreport_failure_fcn_p)(const char *, va_list),
			 void (*vreport_warning_fcn_p)(const char *, va_list),
			 void (*report_open_failure_fcn_p)(const char *, int, gboolean),
			 void (*report_read_failure_fcn_p)(const char *, int),
			 void (*report_write_failure_fcn_p)(const char *, int))
{
	vreport_failure_func = vreport_failure_fcn_p;
	vreport_warning_func = vreport_warning_fcn_p;
	report_open_failure_func = report_open_failure_fcn_p;
	report_read_failure_func = report_read_failure_fcn_p;
	report_write_failure_func = report_write_failure_fcn_p;
}

/*
 * Report a general error.
 */
void
report_failure(const char *msg_format, ...)
{
	va_list ap;

	va_start(ap, msg_format);
	(*vreport_failure_func)(msg_format, ap);
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
	(*vreport_warning_func)(msg_format, ap);
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
					gboolean for_writing)
{
	(*report_open_failure_func)(filename, err, for_writing);
}

/*
 * Report an error when trying to read a file.
 * "err" is assumed to be a UNIX-style errno.
 */
void
report_read_failure(const char *filename, int err)
{
	(*report_read_failure_func)(filename, err);
}

/*
 * Report an error when trying to write a file.
 * "err" is assumed to be a UNIX-style errno.
 */
void
report_write_failure(const char *filename, int err)
{
	(*report_write_failure_func)(filename, err);
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
