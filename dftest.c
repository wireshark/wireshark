/* dftest.c.c
 *
 * $Id: dftest.c,v 1.2 2001/04/02 00:38:33 hagbard Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
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
 *
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <string.h>
#include <errno.h>

#if 0

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif


#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#include <signal.h>

#ifdef NEED_SNPRINTF_H
# include "snprintf.h"
#endif
#endif

#ifdef NEED_STRERROR_H
#include "strerror.h"
#endif

#include <glib.h>
#include <epan.h>

#if 0
#include "globals.h"
#include "packet.h"
#include "file.h"
#include "column.h"
#include "print.h"
#include "resolv.h"
#include "conversation.h"
#endif
#include "timestamp.h"
#include "plugins.h"
#include "prefs.h"
#include "util.h"
#include "epan/dfilter/dfilter.h"
#include "register.h"

packet_info	pi;
ts_type		timestamp_type = RELATIVE;

int
main(int argc, char **argv)
{
	char		*text;
	char		*gpf_path, *pf_path;
	int		gpf_open_errno, pf_open_errno;
	e_prefs		*prefs;
	dfilter_t	*df;

	/* register all dissectors; we must do this before checking for the
	"-g" flag, as the "-g" flag dumps a list of fields registered
	by the dissectors, and we must do it before we read the preferences,
	in case any dissectors register preferences. */
	epan_init(PLUGIN_DIR,register_all_protocols,
		  register_all_protocol_handoffs);

	/* now register the preferences for any non-dissector modules.
	we must do that before we read the preferences as well. */
	prefs_register_modules();

	/* set the c-language locale to the native environment. */
	setlocale(LC_ALL, "");

	prefs = read_prefs(&gpf_open_errno, &gpf_path, &pf_open_errno, &pf_path);
	if (gpf_path != NULL) {
		fprintf(stderr, "can't open global preferences file \"%s\": %s.\n",
				pf_path, strerror(gpf_open_errno));
	}
	if (pf_path != NULL) {
		fprintf(stderr, "can't open your preferences file \"%s\": %s.\n",
				pf_path, strerror(pf_open_errno));
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
	printf("dfilter ptr = 0x%08x\n", (unsigned int) df);

	printf("\n\n");

	dfilter_dump(df);

	epan_cleanup();
	exit(0);
}
