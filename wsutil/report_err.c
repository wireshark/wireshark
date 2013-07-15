/* report_err.c
* Routines for code that can run in GUI and command-line environments to
* use to report errors to the user (e.g., I/O errors, or problems with
* preference settings).
*
* The application using libwireshark will register error-reporting
* routines, and the routines defined here will call the registered
* routines.  That way, these routines can be called by code that
* doesn't itself know whether to pop up a dialog or print something
* to the standard error.
*
* $Id$
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

#include <glib.h>
#include <stdarg.h>
#include "report_err.h"

static void (*report_failure_func)(const char *, va_list);
static void (*report_open_failure_func)(const char *, int, gboolean);
static void (*report_read_failure_func)(const char *, int);
static void (*report_write_failure_func)(const char *, int);

void init_report_err(void (*report_failure_fcn_p)(const char *, va_list),
		     void (*report_open_failure_fcn_p)(const char *, int, gboolean),
		     void (*report_read_failure_fcn_p)(const char *, int),
		     void (*report_write_failure_fcn_p)(const char *, int))
{
	report_failure_func = report_failure_fcn_p;
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
	(*report_failure_func)(msg_format, ap);
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
