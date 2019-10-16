/*
 * Compile and link this with all CLI programs where the main routine
 * should get UTF-8 arguments on Windows.  In those programs, include the
 * cli_main.h header to rename main to real_main on Windows.
 *
 * This is used in software licensed under the GPLv2, and its license MUST
 * be compatible with that license.
 *
 * This is used in software licensed under the Apache 2.0 license, and its
 * license MUST be compatible with that license.
 *
 * For that purpose, we use the MIT (X11) license.
 *
 * SPDX-License-Identifier: MIT
 */

#include "cli_main.h"

#ifdef _WIN32
#include <stdlib.h>
#include <stdio.h>
#include <windows.h>

int
wmain(int argc, wchar_t *wc_argv[])
{
	char **argv;
	int i;

	argv = (char **)malloc((argc + 1) * sizeof(char *));
	if (argv == NULL) {
		fprintf(stderr, "Out of memory for converted argument list\n");
		return 2;
	}
	for (i = 0; i < argc; i++) {
		/*
		 * XXX = use WC_ERR_INVALID_CHARS rather than 0, and fail if
		 * the argument isn't valid UTF-16?
		 */
		int width;
		char *utf8_string;

		width = WideCharToMultiByte(CP_UTF8, 0, wc_argv[i], -1, NULL, 0,
		    NULL, NULL);
		if (width == 0) {
			fprintf(stderr, "WideCharToMultiByte failed: %d\n",
			    width);
			return 2;
		}
		utf8_string = malloc(width);
		if (utf8_string == NULL) {
			fprintf(stderr,
			    "Out of memory for converted argument list\n");
			return 2;
		}
		if (WideCharToMultiByte(CP_UTF8, 0, wc_argv[i], -1, utf8_string,
		    width, NULL, NULL) == 0) {
			fprintf(stderr, "WideCharToMultiByte failed: %d\n",
			    width);
			return 2;
		}
		argv[i] = utf8_string;
	}
	argv[i] = NULL;
	/*
	 * The original "main" routine was renamed to "real_main" via a macro in
	 * the cli_main.h header file since either "main" or "wmain" can be
	 * defined on Windows, but not both.
	 */
	return real_main(argc, argv);
}
#endif
