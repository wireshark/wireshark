/* dftest.c.c
 *
 * $Id$
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * Shows display filter byte-code, for debugging dfilter routines.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <errno.h>

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <glib.h>
#include <epan/epan.h>

#include <epan/timestamp.h>
#include <epan/plugins.h>
#include <epan/filesystem.h>
#include <epan/privileges.h>
#include <epan/prefs.h>
#include "util.h"
#include "epan/dfilter/dfilter.h"
#include "register.h"

packet_info	pi;

static void failure_message(const char *msg_format, va_list ap);
static void open_failure_message(const char *filename, int err,
    gboolean for_writing);
static void read_failure_message(const char *filename, int err);

int
main(int argc, char **argv)
{
	char		*text;
	char		*gpf_path, *pf_path;
	int		gpf_open_errno, gpf_read_errno;
	int		pf_open_errno, pf_read_errno;
	e_prefs		*prefs;
	dfilter_t	*df;

	/*
	 * Get credential information for later use.
	 */
	get_credential_info();

	timestamp_set_type(TS_RELATIVE);

	/* register all dissectors; we must do this before checking for the
	"-g" flag, as the "-g" flag dumps a list of fields registered
	by the dissectors, and we must do it before we read the preferences,
	in case any dissectors register preferences. */
	epan_init(PLUGIN_DIR,register_all_protocols,
		  register_all_protocol_handoffs,
		  failure_message, open_failure_message, read_failure_message);

	/* now register the preferences for any non-dissector modules.
	we must do that before we read the preferences as well. */
	prefs_register_modules();

	/* set the c-language locale to the native environment. */
	setlocale(LC_ALL, "");

	prefs = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
	    &pf_open_errno, &pf_read_errno, &pf_path);
	if (gpf_path != NULL) {
		if (gpf_open_errno != 0) {
			fprintf(stderr,
			    "can't open global preferences file \"%s\": %s.\n",
			    pf_path, strerror(gpf_open_errno));
		}
		if (gpf_read_errno != 0) {
			fprintf(stderr,
			    "I/O error reading global preferences file \"%s\": %s.\n",
			    pf_path, strerror(gpf_read_errno));
		}
	}
	if (pf_path != NULL) {
		if (pf_open_errno != 0) {
			fprintf(stderr,
			    "can't open your preferences file \"%s\": %s.\n",
			    pf_path, strerror(pf_open_errno));
		}
		if (pf_read_errno != 0) {
			fprintf(stderr,
			    "I/O error reading your preferences file \"%s\": %s.\n",
			    pf_path, strerror(pf_read_errno));
		}
	}

	/* notify all registered modules that have had any of their preferences
	changed either from one of the preferences file or from the command
	line that its preferences have changed. */
	prefs_apply_all();

	/* Check for filter on command line */
	if (argc <= 1) {
		fprintf(stderr, "Usage: dftest filter\n");
		exit(1);
	}

	/* Get filter text */
	text = get_args_as_string(argc, argv, 1);

	printf("Filter: \"%s\"\n", text);

	/* Compile it */
	if (!dfilter_compile(text, &df)) {
		fprintf(stderr, "dftest: %s\n", dfilter_error_msg);
		epan_cleanup();
		exit(2);
	}
	printf("dfilter ptr = 0x%08x\n", GPOINTER_TO_INT(df));

	printf("\n\n");

	if (df == NULL)
		printf("Filter is empty\n");
	else
		dfilter_dump(df);

	epan_cleanup();
	exit(0);
}

/*
 * General errors are reported with an console message in "dftest".
 */
static void
failure_message(const char *msg_format, va_list ap)
{
	fprintf(stderr, "dftest: ");
	vfprintf(stderr, msg_format, ap);
	fprintf(stderr, "\n");
}

/*
 * Open/create errors are reported with an console message in "dftest".
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
	fprintf(stderr, "dftest: ");
	fprintf(stderr, file_open_error_message(err, for_writing), filename);
	fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in "dftest".
 */
static void
read_failure_message(const char *filename, int err)
{
	fprintf(stderr, "dftest: An error occurred while reading from the file \"%s\": %s.\n",
	    filename, strerror(err));
}
