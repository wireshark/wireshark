/* version_info.c
 * Routines to report version information for stuff used by Wireshark
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

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_LIBZ
#include <zlib.h>	/* to get the libz version number */
#endif

#include "version_info.h"
#include "capture-pcap-util.h"
#include <wsutil/os_version_info.h>
#include <wsutil/compiler_info.h>
#include <wsutil/cpu_info.h>
#include <wsutil/mem_info.h>

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

/*
 * If the string doesn't end with a newline, append one.
 * Then word-wrap it to 80 columns.
 */
static void
end_string(GString *str)
{
	size_t point;
	char *p, *q;

	point = str->len;
	if (point == 0 || str->str[point - 1] != '\n')
		g_string_append(str, "\n");
	p = str->str;
	while (*p != '\0') {
		q = strchr(p, '\n');
		if (q - p > 80) {
			/*
			 * Break at or before this point.
			 */
			q = p + 80;
			while (q > p && *q != ' ')
				q--;
			if (q != p)
				*q = '\n';
		}
		p = q + 1;
	}
}

/*
 * Get various library compile-time versions and append them to
 * the specified GString.
 *
 * "additional_info" is called at the end to append any additional
 * information; this is required in order to, for example, put the
 * Portaudio information at the end of the string, as we currently
 * don't use Portaudio in TShark.
 */
void
get_compiled_version_info(GString *str, void (*prepend_info)(GString *),
			  void (*append_info)(GString *))
{
	if (sizeof(str) == 4)
		g_string_append(str, "(32-bit) ");
	else
		g_string_append(str, "(64-bit) ");

	if (prepend_info)
		(*prepend_info)(str);

	/* GLIB */
	g_string_append(str, "with ");
	g_string_append_printf(str,
#ifdef GLIB_MAJOR_VERSION
	    "GLib %d.%d.%d", GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION,
	    GLIB_MICRO_VERSION);
#else
	    "GLib (version unknown)");
#endif

	/* Libpcap */
	g_string_append(str, ", ");
	get_compiled_pcap_version(str);

	/* LIBZ */
	g_string_append(str, ", ");
#ifdef HAVE_LIBZ
	g_string_append(str, "with libz ");
#ifdef ZLIB_VERSION
	g_string_append(str, ZLIB_VERSION);
#else /* ZLIB_VERSION */
	g_string_append(str, "(version unknown)");
#endif /* ZLIB_VERSION */
#else /* HAVE_LIBZ */
	g_string_append(str, "without libz");
#endif /* HAVE_LIBZ */

#ifndef _WIN32
	/* This is UN*X-only. */
	/* LIBCAP */
	g_string_append(str, ", ");
#ifdef HAVE_LIBCAP
	g_string_append(str, "with POSIX capabilities");
#ifdef _LINUX_CAPABILITY_VERSION
	g_string_append(str, " (Linux)");
#endif /* _LINUX_CAPABILITY_VERSION */
#else /* HAVE_LIBCAP */
	g_string_append(str, "without POSIX capabilities");
#endif /* HAVE_LIBCAP */
#endif /* _WIN32 */

#ifdef __linux__
	/* This is a Linux-specific library. */
	/* LIBNL */
	g_string_append(str, ", ");
#if defined(HAVE_LIBNL1)
	g_string_append(str, "with libnl 1");
#elif defined(HAVE_LIBNL2)
	g_string_append(str, "with libnl 2");
#elif defined(HAVE_LIBNL3)
	g_string_append(str, "with libnl 3");
#else /* no libnl */
	g_string_append(str, "without libnl");
#endif /* libnl version */
#endif /* __linux__ */

	/* Additional application-dependent information */
	if (append_info)
		(*append_info)(str);
	g_string_append(str, ".");

	end_string(str);
}

/*
 * Get various library run-time versions, and the OS version, and append
 * them to the specified GString.
 */
void
get_runtime_version_info(GString *str, void (*additional_info)(GString *))
{
#ifndef _WIN32
	gchar *lang;
#endif

	g_string_append(str, "on ");

	get_os_version_info(str);

#ifndef _WIN32
	/* Locale */
	if ((lang = getenv ("LANG")) != NULL)
		g_string_append_printf(str, ", with locale %s", lang);
	else
		g_string_append(str, ", without locale");
#endif

	/* Additional application-dependent information */
	if (additional_info)
		(*additional_info)(str);

	g_string_append(str, ".");

	/* CPU Info */
	get_cpu_info(str);

	/* Get info about installed memory Windows only */
	get_mem_info(str);

	/* Compiler info */
	get_compiler_info(str);

	end_string(str);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 8
 * tab-width: 8
 * indent-tabs-mode: t
 * End:
 *
 * ex: set shiftwidth=8 tabstop=8 noexpandtab:
 * :indentSize=8:tabSize=8:noTabs=false:
 */
