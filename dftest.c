/* dftest.c
 * Shows display filter byte-code, for debugging dfilter routines.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <epan/epan.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include <epan/dfilter/dfilter.h>

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif
#include <wsutil/filesystem.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>

#include <wiretap/wtap.h>

#include "ui/util.h"
#include "ui/cmdarg_err.h"
#include "ui/failure_message.h"

static void dftest_cmdarg_err(const char *fmt, va_list ap);
static void dftest_cmdarg_err_cont(const char *fmt, va_list ap);

int
main(int argc, char **argv)
{
	char		*init_progfile_dir_error;
	static const struct report_message_routines dftest_report_routines = {
		failure_message,
		failure_message,
		open_failure_message,
		read_failure_message,
		write_failure_message,
		cfile_open_failure_message,
		cfile_dump_open_failure_message,
		cfile_read_failure_message,
		cfile_write_failure_message,
		cfile_close_failure_message
	};
	char		*text;
	dfilter_t	*df;
	gchar		*err_msg;

	cmdarg_err_init(dftest_cmdarg_err, dftest_cmdarg_err_cont);

	/*
	 * Get credential information for later use.
	 */
	init_process_policies();

	/*
	 * Attempt to get the pathname of the directory containing the
	 * executable file.
	 */
	init_progfile_dir_error = init_progfile_dir(argv[0]);
	if (init_progfile_dir_error != NULL) {
		fprintf(stderr, "dftest: Can't get pathname of directory containing the dftest program: %s.\n",
			init_progfile_dir_error);
		g_free(init_progfile_dir_error);
	}

	init_report_message("dftest", &dftest_report_routines);

	timestamp_set_type(TS_RELATIVE);
	timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

	/*
	 * Libwiretap must be initialized before libwireshark is, so that
	 * dissection-time handlers for file-type-dependent blocks can
	 * register using the file type/subtype value for the file type.
	 */
	wtap_init(TRUE);

	/* Register all dissectors; we must do this before checking for the
	   "-g" flag, as the "-g" flag dumps a list of fields registered
	   by the dissectors, and we must do it before we read the preferences,
	   in case any dissectors register preferences. */
	if (!epan_init(NULL, NULL, FALSE))
		return 2;

	/*
	 * Set the C-language locale to the native environment and set the
	 * code page to UTF-8 on Windows.
	 */
#ifdef _WIN32
	setlocale(LC_ALL, ".UTF-8");
#else
	setlocale(LC_ALL, "");
#endif

	/* Load libwireshark settings from the current profile. */
	epan_load_settings();

	/* notify all registered modules that have had any of their preferences
	changed either from one of the preferences file or from the command
	line that its preferences have changed. */
	prefs_apply_all();

	/* Check for filter on command line */
	if (argc <= 1) {
		fprintf(stderr, "Usage: dftest <filter>\n");
		exit(1);
	}

	/* Get filter text */
	text = get_args_as_string(argc, argv, 1);

	printf("Filter: \"%s\"\n", text);

	/* Compile it */
	if (!dfilter_compile(text, &df, &err_msg)) {
		fprintf(stderr, "dftest: %s\n", err_msg);
		g_free(err_msg);
		epan_cleanup();
		g_free(text);
		exit(2);
	}

	printf("\n");

	if (df == NULL)
		printf("Filter is empty\n");
	else
		dfilter_dump(df);

	dfilter_free(df);
	epan_cleanup();
	g_free(text);
	exit(0);
}

/*
 * Report an error in command-line arguments.
 */
static void
dftest_cmdarg_err(const char *fmt, va_list ap)
{
	fprintf(stderr, "dftest: ");
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
dftest_cmdarg_err_cont(const char *fmt, va_list ap)
{
	vfprintf(stderr, fmt, ap);
	fprintf(stderr, "\n");
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
