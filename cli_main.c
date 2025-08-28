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
#include <glib.h>
#include <windows.h>

int
wmain(int argc, wchar_t *wc_argv[])
{
	/* ISO C mandates that argv contents can be modified, so use a
	 * GPtrArray to keep a private reference to the allocated memory so
	 * we do not hand over our only reference and potentially lose it,
	 * or worse try to free an invalidated pointer. */
	GPtrArray *argv;
	char **argv_user;
	int return_code;

	argv = g_ptr_array_new_full(argc, g_free);
	for (int i = 0; i < argc; i++) {
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
		utf8_string = g_malloc(width);
		if (WideCharToMultiByte(CP_UTF8, 0, wc_argv[i], -1, utf8_string,
		    width, NULL, NULL) == 0) {
			fprintf(stderr, "WideCharToMultiByte failed: %d\n",
			    width);
			return 2;
		}
		g_ptr_array_add(argv, utf8_string);
	}

	argv_user = (char **)g_malloc((argc + 1) * sizeof(char *));
	for (guint i = 0; i < argv->len; i++) {
		argv_user[i] = argv->pdata[i];
	}
	argv_user[argc] = NULL;

	/*
	 * The original "main" routine was renamed to "real_main" via a macro in
	 * the cli_main.h header file since either "main" or "wmain" can be
	 * defined on Windows, but not both.
	 */
	return_code = real_main(argc, argv_user);

	/* Clean up */
	g_ptr_array_unref(argv);
	g_free(argv_user);

	return return_code;
}
#endif
