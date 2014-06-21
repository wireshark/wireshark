/* cfutils.c
 * Routines to work around deficiencies in Core Foundation, such as the
 * lack of a routine to convert a CFString to a C string of arbitrary
 * size.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2001 Gerald Combs
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

#ifdef HAVE_OS_X_FRAMEWORKS
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
#endif
