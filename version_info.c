/* version_info.c
 * Routines to report version information for stuff used by Wireshark
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_LIBZ
#include <zlib.h>	/* to get the libz version number */
#endif

#ifdef HAVE_LIBPCRE
#include <pcre.h>	/* to get the libpcre version number */
#endif /* HAVE_LIBPCRE */

#ifdef HAVE_SOME_SNMP

#ifdef HAVE_NET_SNMP
#include <net-snmp/version.h>
#endif /* HAVE_NET_SNMP */

#ifdef HAVE_UCD_SNMP
#include <ucd-snmp/version.h>
#endif /* HAVE_UCD_SNMP */

#endif /* HAVE_SOME_SNMP */

#if (defined(HAVE_LIBGCRYPT) || defined(HAVE_LIBGNUTLS)) && defined(_WIN32)
#include <winposixtype.h>
#endif

#ifdef HAVE_LIBGCRYPT
#include <gcrypt.h>
#endif /* HAVE_LIBGCRYPT */

#ifdef HAVE_LIBGNUTLS
#include <gnutls/gnutls.h>
#endif /* HAVE_LIBGNUTLS */

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#include "version_info.h"
#include "capture-pcap-util.h"
#include "epan/unicode-utils.h"

#include "svnversion.h"

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#ifdef HAVE_LUA
#include <lua.h>
#endif

#ifdef SVNVERSION
	const char *svnversion = " (" SVNVERSION ")";
#else
	const char *svnversion = "";
#endif

/*
 * Add a word wrap break point, and return its index.
 */
static gint
add_word_wrap_break_point(GString *str)
{
	g_string_append(str, " ");
	return str->len - 1;
}

/*
 * Add punctuation at the end of a phrase, and see whether the last line in
 * the string goes past column 80; if so, replace the blank at the specified
 * point with a newline.
 */
static void
end_item_and_break(GString *str, char *punct, gint point)
{
	char *line_begin;

	g_string_append(str, punct);
	line_begin = strrchr(str->str, '\n');
	if (line_begin == NULL)
		line_begin = str->str;
	else
		line_begin++;
	if (strlen(line_begin) > 80) {
		g_assert(str->str[point] == ' ');
		str->str[point] = '\n';
	}
}

/*
 * If the string doesn't end with a newline, append one.
 */
static void
end_string(GString *str)
{
	size_t point;

	point = strlen(str->str);
	if (point == 0 || str->str[point - 1] != '\n')
		g_string_append(str, "\n");
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
get_compiled_version_info(GString *str, void (*additional_info)(GString *))
{
	gint break_point;

        /* GLIB */
	g_string_append(str, "with ");
	g_string_sprintfa(str,
#ifdef GLIB_MAJOR_VERSION
	    "GLib %d.%d.%d,", GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION,
	    GLIB_MICRO_VERSION);
#else
	    "GLib (version unknown),");
#endif

	break_point = add_word_wrap_break_point(str);
	get_compiled_pcap_version(str);
	end_item_and_break(str, ",", break_point);

        /* LIBZ */
	break_point = add_word_wrap_break_point(str);
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

	/* Additional application-dependent information */
	if (additional_info) {
		end_item_and_break(str, ",", break_point);
		break_point = add_word_wrap_break_point(str);
		(*additional_info)(str);
	}
	end_item_and_break(str, ".", break_point);

#ifndef HAVE_LIBPCRE
	break_point = str->len - 1;
	g_string_append(str,
	"\nNOTE: this build doesn't support the \"matches\" operator for Wireshark filter syntax");
	end_item_and_break(str, ".", break_point);
#endif	/* HAVE_LIBPCRE */

	end_string(str);
}

/*
 * Get compile-time information used only by applications that use
 * libethereal.
 */
void
get_epan_compiled_version_info(GString *str)
{
	gint break_point;

        /* PCRE */
	break_point = str->len - 1;
#ifdef HAVE_LIBPCRE
	g_string_append(str, "with libpcre ");
#ifdef PCRE_MAJOR
#ifdef PCRE_MINOR
	g_string_sprintfa(str, "%u.%u", PCRE_MAJOR, PCRE_MINOR);
#else			/* PCRE_MINOR */
	g_string_sprintfa(str, "%u", PCRE_MAJOR);
#endif			/* PCRE_MINOR */
#else		/* PCRE_MAJOR */
	g_string_append(str, "(version unknown)");
#endif		/* PCRE_MAJOR */
#else	/* HAVE_LIBPCRE */
	g_string_append(str, "without libpcre");
#endif	/* HAVE_LIBPCRE */

	end_item_and_break(str, ",", break_point);

        /* SNMP */
/* Oh, this is pretty. */
/* Oh, ha.  you think that was pretty.  Try this:! --Wes */
	break_point = add_word_wrap_break_point(str);
#ifdef HAVE_SOME_SNMP

#ifdef HAVE_UCD_SNMP
	g_string_append(str, "with UCD-SNMP ");
	g_string_append(str, VersionInfo);
#endif /* HAVE_UCD_SNMP */

#ifdef HAVE_NET_SNMP
	g_string_append(str, "with Net-SNMP ");
	g_string_append(str, netsnmp_get_version());
#endif /* HAVE_NET_SNMP */

#else /* no SNMP library */
	g_string_append(str, "without UCD-SNMP or Net-SNMP");
#endif /* HAVE_SOME_SNMP */
	end_item_and_break(str, ",", break_point);

        /* ADNS */
	break_point = add_word_wrap_break_point(str);
#ifdef HAVE_GNU_ADNS
	g_string_append(str, "with ADNS");
#else
	g_string_append(str, "without ADNS");
#endif /* HAVE_GNU_ADNS */
	end_item_and_break(str, ",", break_point);

        /* LUA */
	break_point = add_word_wrap_break_point(str);
#ifdef HAVE_LUA
	g_string_append(str, "with ");
	g_string_append(str, LUA_VERSION);
#else
	g_string_append(str, "without Lua");
#endif /* HAVE_LUA */
	end_item_and_break(str, ",", break_point);

        /* GnuTLS */
	break_point = add_word_wrap_break_point(str);
#ifdef HAVE_LIBGNUTLS
	g_string_append(str, "with GnuTLS " LIBGNUTLS_VERSION);
#else
	g_string_append(str, "without GnuTLS");
#endif /* HAVE_LIBGNUTLS */
	end_item_and_break(str, ",", break_point);

        /* Gcrypt */
	break_point = add_word_wrap_break_point(str);
#ifdef HAVE_LIBGCRYPT
	g_string_append(str, "with Gcrypt " GCRYPT_VERSION);
#else
	g_string_append(str, "without Gcrypt");
#endif /* HAVE_LIBGCRYPT */
	end_item_and_break(str, ",", break_point);

        /* Kerberos */
        /* XXX - I don't see how to get the version number, at least for KfW */
	break_point = add_word_wrap_break_point(str);
#ifdef HAVE_KERBEROS
#ifdef HAVE_MIT_KERBEROS
	g_string_append(str, "with MIT Kerberos");
#else
        /* HAVE_HEIMDAL_KERBEROS */
	g_string_append(str, "with Heimdal Kerberos");
#endif
#else
	g_string_append(str, "without Kerberos");
#endif /* HAVE_KERBEROS */
}

/*
 * Get various library run-time versions, and the OS version, and append
 * them to the specified GString.
 */
void
get_runtime_version_info(GString *str, void (*additional_info)(GString *))
{
	gint break_point;

#if defined(_WIN32)
	OSVERSIONINFO info;
#elif defined(HAVE_SYS_UTSNAME_H)
	struct utsname name;
#endif

	g_string_append(str, "on ");

#if defined(_WIN32)
	/*
	 * See
	 *
	 *	http://msdn.microsoft.com/library/default.asp?url=/library/en-us/sysinfo/base/getting_the_system_version.asp
	 *
	 * for more than you ever wanted to know about determining the
	 * flavor of Windows on which you're running.  Implementing more
	 * of that is left as an exercise to the reader - who should
	 * check any copyright information about code samples on MSDN
	 * before cutting and pasting into Wireshark.
	 *
	 * They should also note that you need an OSVERSIONINFOEX structure
	 * to get some of that information, and that not only is that
	 * structure not supported on older versions of Windows, you might
	 * not even be able to compile code that *uses* that structure with
	 * older versions of the SDK.
	 */
	info.dwOSVersionInfoSize = sizeof info;
	if (!GetVersionEx(&info)) {
		/*
		 * XXX - get the failure reason.
		 */
		g_string_append(str, "unknown Windows version");
		return;
	}
	switch (info.dwPlatformId) {

	case VER_PLATFORM_WIN32s:
		/* Shyeah, right. */
		g_string_sprintfa(str, "Windows 3.1 with Win32s");
		break;

	case VER_PLATFORM_WIN32_WINDOWS:
		/* Windows OT */
		switch (info.dwMajorVersion) {

		case 4:
			/* 3 cheers for Microsoft marketing! */
			switch (info.dwMinorVersion) {

			case 0:
				g_string_sprintfa(str, "Windows 95");
				break;

			case 10:
				g_string_sprintfa(str, "Windows 98");
				break;

			case 90:
				g_string_sprintfa(str, "Windows Me");
				break;

			default:
				g_string_sprintfa(str, "Windows OT, unknown version %lu.%lu",
				    info.dwMajorVersion, info.dwMinorVersion);
				break;
			}
			break;

		default:
			g_string_sprintfa(str, "Windows OT, unknown version %lu.%lu",
			    info.dwMajorVersion, info.dwMinorVersion);
			break;
		}
		break;

	case VER_PLATFORM_WIN32_NT:
		/* Windows NT */
		switch (info.dwMajorVersion) {

		case 3:
		case 4:
			g_string_sprintfa(str, "Windows NT %lu.%lu",
			    info.dwMajorVersion, info.dwMinorVersion);
			break;

		case 5:
			/* 3 cheers for Microsoft marketing! */
			switch (info.dwMinorVersion) {

			case 0:
				g_string_sprintfa(str, "Windows 2000");
				break;

			case 1:
				g_string_sprintfa(str, "Windows XP");
				break;

			case 2:
				g_string_sprintfa(str, "Windows Server 2003");
				break;

			default:
				g_string_sprintfa(str, "Windows NT, unknown version %lu.%lu",
				    info.dwMajorVersion, info.dwMinorVersion);
				break;
			}
			break;

		case 6:
			g_string_sprintfa(str, "Windows Vista");
			break;

		default:
			g_string_sprintfa(str, "Windows NT, unknown version %lu.%lu",
			    info.dwMajorVersion, info.dwMinorVersion);
			break;
		}
		break;

	default:
		g_string_sprintfa(str, "Unknown Windows platform %lu version %lu.%lu",
		    info.dwPlatformId, info.dwMajorVersion, info.dwMinorVersion);
		break;
	}
	if (info.szCSDVersion[0] != '\0')
		g_string_sprintfa(str, " %s", utf_16to8(info.szCSDVersion));
	g_string_sprintfa(str, ", build %lu", info.dwBuildNumber);
#elif defined(HAVE_SYS_UTSNAME_H)
	/*
	 * We have <sys/utsname.h>, so we assume we have "uname()".
	 */
	if (uname(&name) < 0) {
		g_string_sprintfa(str, "unknown OS version (uname failed - %s)",
		    strerror(errno));
		return;
	}

	if (strcmp(name.sysname, "AIX") == 0) {
		/*
		 * Yay, IBM!  Thanks for doing something different
		 * from most of the other UNIXes out there, and
		 * making "name.version" apparently be the major
		 * version number and "name.release" be the minor
		 * version number.
		 */
		g_string_sprintfa(str, "%s %s.%s", name.sysname, name.version,
		    name.release);
	} else {
		/*
		 * XXX - get "version" on any other platforms?
		 *
		 * On Digital/Tru65 UNIX, it's something unknown.
		 * On Solaris, it's some kind of build information.
		 * On HP-UX, it appears to be some sort of subrevision
		 * thing.
		 */
		g_string_sprintfa(str, "%s %s", name.sysname, name.release);
	}
#else
	g_string_append(str, "an unknown OS");
#endif

	break_point = add_word_wrap_break_point(str);

	/* Additional application-dependent information */
	if (additional_info) {
		end_item_and_break(str, ",", break_point);
		break_point = add_word_wrap_break_point(str);
		(*additional_info)(str);
	}

	end_item_and_break(str, ".", break_point);

	/* Compiler info */

	/*
	 * See http://predef.sourceforge.net/precomp.html for
	 * information on various defined strings.
	 *
	 * GCC's __VERSION__ is a nice text string for humans to
	 * read.  The page at predef.sourceforge.net largely
	 * describes numeric #defines that encode the version;
	 * if the compiler doesn't also offer a nice printable
	 * string, we should probably prettify the number somehow.
	 */
#if defined(__GNUC__) && defined(__VERSION__)
	g_string_sprintfa(str, "\n\nBuilt using gcc %s.\n", __VERSION__);
#elif defined(__HP_aCC)
	g_string_sprintfa(str, "\n\nBuilt using HP aCC %d.\n", __HP_aCC);
#elif defined(__xlC__)
	g_string_sprintfa(str, "\n\nBuilt using IBM XL C %d.%d\n",
	    (__xlC__ >> 8) & 0xFF, __xlC__ & 0xFF);
#ifdef __IBMC__
	if ((__IBMC__ % 10) != 0)
		g_string_sprintfa(str, " patch %d", __IBMC__ % 10);
#endif /* __IBMC__ */
	g_string_sprintfa(str, "\n");
#elif defined(__INTEL_COMPILER)
	g_string_sprintfa(str, "\n\nBuilt using Intel C %d.%d",
	    __INTEL_COMPILER / 100, (__INTEL_COMPILER / 10) % 10);
	if ((__INTEL_COMPILER % 10) != 0)
		g_string_sprintfa(str, " patch %d", __INTEL_COMPILER % 10);
#ifdef __INTEL_COMPILER_BUILD_DATE
	g_string_sprinta(str, ", compiler built %04d-%02d-%02d",
	    __INTEL_COMPILER_BUILD_DATE / 10000,
	    (__INTEL_COMPILER_BUILD_DATE / 100) % 100,
	    __INTEL_COMPILER_BUILD_DATE % 100);
#endif /* __INTEL_COMPILER_BUILD_DATE */
	g_string_sprintfa(str, "\n");
#elif defined(_MSC_FULL_VER)
	if (_MSC_FULL_VER > 99999999) {
		g_string_sprintfa(str, "\n\nBuilt using Microsoft Visual C++ %d.%d",
		    (_MSC_FULL_VER / 10000000) - 6,
		    (_MSC_FULL_VER / 100000) % 100);
		if ((_MSC_FULL_VER % 100000) != 0)
			g_string_sprintfa(str, " patch %d",
			    _MSC_FULL_VER % 100000);
	} else {
		g_string_sprintfa(str, "\n\nBuilt using Microsoft Visual C++ %d.%d",
		    (_MSC_FULL_VER / 1000000) - 6,
		    (_MSC_FULL_VER / 10000) % 100);
		if ((_MSC_FULL_VER % 10000) != 0)
			g_string_sprintfa(str, " patch %d",
			    _MSC_FULL_VER % 10000);
	}
	g_string_sprintfa(str, "\n");
#elif defined(_MSC_VER)
	/* _MSC_FULL_VER not defined, but _MSC_VER defined */
	g_string_sprintfa(str, "\n\nBuilt using Microsoft Visual C++ %d.%d\n",
	    (_MSC_VER / 100) - 6, _MSC_VER % 100);
#elif defined(__SUNPRO_C)
	g_string_sprintfa(str, "\n\nBuilt using Sun C %d.%d",
	    (__SUNPRO_C >> 8) & 0xF, (__SUNPRO_C >> 4) & 0xF);
	if ((__SUNPRO_C & 0xF) != 0)
		g_string_sprintfa(str, " patch %d", __SUNPRO_C & 0xF);
	g_string_sprintfa(str, "\n");
#endif

	end_string(str);
}

/*
 * Get copyright information.
 */
const char *
get_copyright_info(void)
{
	return
"Copyright 1998-2006 Gerald Combs <gerald@wireshark.org> and contributors.\n"
"This is free software; see the source for copying conditions. There is NO\n"
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\n";
}
