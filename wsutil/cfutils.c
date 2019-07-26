/* cfutils.c
 * Routines to work around deficiencies in Core Foundation, such as the
 * lack of a routine to convert a CFString to a C string of arbitrary
 * size.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <glib.h>
#include <CoreFoundation/CoreFoundation.h>
#include <wsutil/cfutils.h>

/*
 * Convert a CFString to a UTF-8-encoded C string; the resulting string
 * is allocated with g_malloc().  Returns NULL if the conversion fails.
 */
char *
CFString_to_C_string(CFStringRef cfstring)
{
	CFIndex string_len;
	char *string;

	string_len = CFStringGetMaximumSizeForEncoding(CFStringGetLength(cfstring),
	    kCFStringEncodingUTF8);
	string = (char *)g_malloc(string_len + 1);
	if (!CFStringGetCString(cfstring, string, string_len + 1,
	    kCFStringEncodingUTF8)) {
		g_free(string);
		return NULL;
	}
	return string;
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
