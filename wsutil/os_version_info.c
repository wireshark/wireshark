/* os_version_info.c
 * Routines to report operating system version information
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

#include <string.h>
#include <errno.h>

#ifdef HAVE_SYS_UTSNAME_H
#include <sys/utsname.h>
#endif

#ifdef HAVE_OS_X_FRAMEWORKS
#include <CoreFoundation/CoreFoundation.h>
#include <wsutil/cfutils.h>
#endif

#include <glib.h>

#include <wsutil/unicode-utils.h>

#include <wsutil/os_version_info.h>

#ifdef _WIN32
typedef void (WINAPI *nativesi_func_ptr)(LPSYSTEM_INFO);
#endif

/*
 * Handles the rather elaborate process of getting OS version information
 * from OS X (we want the OS X version, not the Darwin version, the latter
 * being easy to get with uname()).
 */
#ifdef HAVE_OS_X_FRAMEWORKS

/*
 * Fetch a string, as a UTF-8 C string, from a dictionary, given a key.
 */
static char *
get_string_from_dictionary(CFPropertyListRef dict, CFStringRef key)
{
	CFStringRef cfstring;

	cfstring = (CFStringRef)CFDictionaryGetValue((CFDictionaryRef)dict,
	    (const void *)key);
	if (cfstring == NULL)
		return NULL;
	if (CFGetTypeID(cfstring) != CFStringGetTypeID()) {
		/* It isn't a string.  Punt. */
		return NULL;
	}
	return CFString_to_C_string(cfstring);
}

/*
 * Get the OS X version information, and append it to the GString.
 * Return TRUE if we succeed, FALSE if we fail.
 */
static gboolean
get_os_x_version_info(GString *str)
{
	static const UInt8 server_version_plist_path[] =
	    "/System/Library/CoreServices/ServerVersion.plist";
	static const UInt8 system_version_plist_path[] =
	    "/System/Library/CoreServices/SystemVersion.plist";
	CFURLRef version_plist_file_url;
	CFReadStreamRef version_plist_stream;
	CFDictionaryRef version_dict;
	char *string;

	/*
	 * On OS X, report the OS X version number as the OS, and put
	 * the Darwin information in parentheses.
	 *
	 * Alas, Gestalt() is deprecated in Mountain Lion, so the build
	 * fails if you treat deprecation warnings as fatal.  I don't
	 * know of any replacement API, so we fall back on reading
	 * /System/Library/CoreServices/ServerVersion.plist if it
	 * exists, otherwise /System/Library/CoreServices/SystemVersion.plist,
	 * and using ProductUserVisibleVersion.  We also get the build
	 * version from ProductBuildVersion and the product name from
	 * ProductName.
	 */
	version_plist_file_url = CFURLCreateFromFileSystemRepresentation(NULL,
	    server_version_plist_path, sizeof server_version_plist_path - 1,
	    false);
	if (version_plist_file_url == NULL)
		return FALSE;
	version_plist_stream = CFReadStreamCreateWithFile(NULL,
	    version_plist_file_url);
	CFRelease(version_plist_file_url);
	if (version_plist_stream == NULL)
		return FALSE;
	if (!CFReadStreamOpen(version_plist_stream)) {
		CFRelease(version_plist_stream);

		/*
		 * Try SystemVersion.plist.
		 */
		version_plist_file_url = CFURLCreateFromFileSystemRepresentation(NULL,
		    system_version_plist_path, sizeof system_version_plist_path - 1,
		    false);
		if (version_plist_file_url == NULL)
			return FALSE;
		version_plist_stream = CFReadStreamCreateWithFile(NULL,
		    version_plist_file_url);
		CFRelease(version_plist_file_url);
		if (version_plist_stream == NULL)
			return FALSE;
		if (!CFReadStreamOpen(version_plist_stream)) {
			CFRelease(version_plist_stream);
			return FALSE;
		}
	}
#ifdef HAVE_CFPROPERTYLISTCREATEWITHSTREAM
	version_dict = (CFDictionaryRef)CFPropertyListCreateWithStream(NULL,
	    version_plist_stream, 0, kCFPropertyListImmutable,
	    NULL, NULL);
#else
	version_dict = (CFDictionaryRef)CFPropertyListCreateFromStream(NULL,
	    version_plist_stream, 0, kCFPropertyListImmutable,
	    NULL, NULL);
#endif
	if (version_dict == NULL) {
		CFRelease(version_plist_stream);
		return FALSE;
	}
	if (CFGetTypeID(version_dict) != CFDictionaryGetTypeID()) {
		/* This is *supposed* to be a dictionary.  Punt. */
		CFRelease(version_dict);
		CFReadStreamClose(version_plist_stream);
		CFRelease(version_plist_stream);
		return FALSE;
	}
	/* Get the product name string. */
	string = get_string_from_dictionary(version_dict,
	    CFSTR("ProductName"));
	if (string == NULL) {
		CFRelease(version_dict);
		CFReadStreamClose(version_plist_stream);
		CFRelease(version_plist_stream);
		return FALSE;
	}
	g_string_append_printf(str, "%s", string);
	g_free(string);

	/* Get the OS version string. */
	string = get_string_from_dictionary(version_dict,
	    CFSTR("ProductUserVisibleVersion"));
	if (string == NULL) {
		CFRelease(version_dict);
		CFReadStreamClose(version_plist_stream);
		CFRelease(version_plist_stream);
		return FALSE;
	}
	g_string_append_printf(str, " %s", string);
	g_free(string);

	/* Get the build string */
	string = get_string_from_dictionary(version_dict,
	    CFSTR("ProductBuildVersion"));
	if (string == NULL) {
		CFRelease(version_dict);
		CFReadStreamClose(version_plist_stream);
		CFRelease(version_plist_stream);
		return FALSE;
	}
	g_string_append_printf(str, ", build %s", string);
	g_free(string);
	CFRelease(version_dict);
	CFReadStreamClose(version_plist_stream);
	CFRelease(version_plist_stream);
	return TRUE;
}
#endif

/*
 * Get the OS version, and append it to the GString
 */
void
get_os_version_info(GString *str)
{
#if defined(_WIN32)
	OSVERSIONINFOEX info;
	SYSTEM_INFO system_info;
	nativesi_func_ptr nativesi_func;
#elif defined(HAVE_SYS_UTSNAME_H)
	struct utsname name;
#endif

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

	memset(&info, '\0', sizeof info);
	info.dwOSVersionInfoSize = sizeof info;
	if (!GetVersionEx((OSVERSIONINFO *)&info)) {
		/*
		 * XXX - get the failure reason.
		 */
		g_string_append(str, "unknown Windows version");
		return;
	}

	memset(&system_info, '\0', sizeof system_info);
	/* Look for and use the GetNativeSystemInfo() function if available to get the correct processor
	 * architecture even when running 32-bit Wireshark in WOW64 (x86 emulation on 64-bit Windows) */
	nativesi_func = (nativesi_func_ptr)GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "GetNativeSystemInfo");
	if(nativesi_func)
		nativesi_func(&system_info);
	else
		GetSystemInfo(&system_info);

	switch (info.dwPlatformId) {

	case VER_PLATFORM_WIN32s:
		/* Shyeah, right. */
		g_string_append_printf(str, "Windows 3.1 with Win32s");
		break;

	case VER_PLATFORM_WIN32_WINDOWS:
		/* Windows OT */
		switch (info.dwMajorVersion) {

		case 4:
			/* 3 cheers for Microsoft marketing! */
			switch (info.dwMinorVersion) {

			case 0:
				g_string_append_printf(str, "Windows 95");
				break;

			case 10:
				g_string_append_printf(str, "Windows 98");
				break;

			case 90:
				g_string_append_printf(str, "Windows Me");
				break;

			default:
				g_string_append_printf(str, "Windows OT, unknown version %lu.%lu",
				    info.dwMajorVersion, info.dwMinorVersion);
				break;
			}
			break;

		default:
			g_string_append_printf(str, "Windows OT, unknown version %lu.%lu",
			    info.dwMajorVersion, info.dwMinorVersion);
			break;
		}
		break;

	case VER_PLATFORM_WIN32_NT:
		/* Windows NT */
		switch (info.dwMajorVersion) {

		case 3:
		case 4:
			g_string_append_printf(str, "Windows NT %lu.%lu",
			    info.dwMajorVersion, info.dwMinorVersion);
			break;

		case 5:
			/* 3 cheers for Microsoft marketing! */
			switch (info.dwMinorVersion) {

			case 0:
				g_string_append_printf(str, "Windows 2000");
				break;

			case 1:
				g_string_append_printf(str, "Windows XP");
				break;

			case 2:
				if ((info.wProductType == VER_NT_WORKSTATION) &&
				    (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)) {
					g_string_append_printf(str, "Windows XP Professional x64 Edition");
				} else {
					g_string_append_printf(str, "Windows Server 2003");
					if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
						g_string_append_printf(str, " x64 Edition");
				}
				break;

			default:
				g_string_append_printf(str, "Windows NT, unknown version %lu.%lu",
						       info.dwMajorVersion, info.dwMinorVersion);
				break;
			}
			break;

		case 6: {
			gboolean is_nt_workstation;

			if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
				g_string_append(str, "64-bit ");
			else if (system_info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_INTEL)
				g_string_append(str, "32-bit ");
#ifndef VER_NT_WORKSTATION
#define VER_NT_WORKSTATION 0x01
			is_nt_workstation = ((info.wReserved[1] & 0xff) == VER_NT_WORKSTATION);
#else
			is_nt_workstation = (info.wProductType == VER_NT_WORKSTATION);
#endif
			switch (info.dwMinorVersion) {
			case 0:
				g_string_append_printf(str, is_nt_workstation ? "Windows Vista" : "Windows Server 2008");
				break;
			case 1:
				g_string_append_printf(str, is_nt_workstation ? "Windows 7" : "Windows Server 2008 R2");
				break;
			case 2:
				g_string_append_printf(str, is_nt_workstation ? "Windows 8" : "Windows Server 2012");
				break;
			case 3:
				g_string_append_printf(str, is_nt_workstation ? "Windows 8.1" : "Windows Server 2012 R2");
				break;
			default:
				g_string_append_printf(str, "Windows NT, unknown version %lu.%lu",
						       info.dwMajorVersion, info.dwMinorVersion);
				break;
			}
			break;
		}  /* case 6 */
		default:
			g_string_append_printf(str, "Windows NT, unknown version %lu.%lu",
			    info.dwMajorVersion, info.dwMinorVersion);
			break;
		} /* info.dwMajorVersion */
		break;

	default:
		g_string_append_printf(str, "Unknown Windows platform %lu version %lu.%lu",
		    info.dwPlatformId, info.dwMajorVersion, info.dwMinorVersion);
		break;
	}
	if (info.szCSDVersion[0] != '\0')
		g_string_append_printf(str, " %s", utf_16to8(info.szCSDVersion));
	g_string_append_printf(str, ", build %lu", info.dwBuildNumber);
#elif defined(HAVE_SYS_UTSNAME_H)
	/*
	 * We have <sys/utsname.h>, so we assume we have "uname()".
	 */
	if (uname(&name) < 0) {
		g_string_append_printf(str, "unknown OS version (uname failed - %s)",
		    g_strerror(errno));
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
		g_string_append_printf(str, "%s %s.%s", name.sysname, name.version,
		    name.release);
	} else {
		/*
		 * XXX - get "version" on any other platforms?
		 *
		 * On Digital/Tru64 UNIX, it's something unknown.
		 * On Solaris, it's some kind of build information.
		 * On HP-UX, it appears to be some sort of subrevision
		 * thing.
		 * On *BSD and Darwin/OS X, it's a long string giving
		 * a build date, config file name, etc., etc., etc..
		 */
#ifdef HAVE_OS_X_FRAMEWORKS
		/*
		 * On Mac OS X, report the Mac OS X version number as
		 * the OS version if we can, and put the Darwin information
		 * in parentheses.
		 */
		if (get_os_x_version_info(str)) {
			/* Success - append the Darwin information. */
			g_string_append_printf(str, " (%s %s)", name.sysname, name.release);
		} else {
			/* Failure - just use the Darwin information. */
			g_string_append_printf(str, "%s %s", name.sysname, name.release);
		}
#else /* HAVE_OS_X_FRAMEWORKS */
		/*
		 * XXX - on Linux, are there any APIs to get the distribution
		 * name and version number?  I think some distributions have
		 * that.
		 *
		 * At least on Linux Standard Base-compliant distributions,
		 * there's an "lsb_release" command.  However:
		 *
		 *	http://forums.fedoraforum.org/showthread.php?t=220885
		 *
		 * seems to suggest that if you don't have the redhat-lsb
		 * package installed, you don't have lsb_release, and that
		 * /etc/fedora-release has the release information on
		 * Fedora.
		 *
		 *	http://linux.die.net/man/1/lsb_release
		 *
		 * suggests that there's an /etc/distrib-release file, but
		 * it doesn't indicate whether "distrib" is literally
		 * "distrib" or is the name for the distribution, and
		 * also speaks of an /etc/debian_version file.
		 *
		 * "lsb_release" apparently parses /etc/lsb-release, which
		 * has shell-style assignments, assigning to, among other
		 * values, DISTRIB_ID (distributor/distribution name),
		 * DISTRIB_RELEASE (release number of the distribution),
		 * DISTRIB_DESCRIPTION (*might* be name followed by version,
		 * but the manpage for lsb_release seems to indicate that's
		 * not guaranteed), and DISTRIB_CODENAME (code name, e.g.
		 * "licentious" for the Ubuntu Licentious Lemur release).
		 * the lsb_release man page also speaks of the distrib-release
		 * file, but Debian doesn't have one, and Ubuntu 7's
		 * lsb_release command doesn't look for one.
		 *
		 * I've seen references to /etc/redhat-release as well.
		 *
		 * At least on my Ubuntu 7 system, /etc/debian_version
		 * doesn't contain anything interesting (just some Debian
		 * codenames).
		 *
		 * See also
		 *
		 *	http://bugs.python.org/issue1322
		 *
		 *	http://www.novell.com/coolsolutions/feature/11251.html
		 *
		 *	http://linuxmafia.com/faq/Admin/release-files.html
		 *
		 * and the Lib/Platform.py file in recent Python 2.x
		 * releases.
		 */
		g_string_append_printf(str, "%s %s", name.sysname, name.release);
#endif /* HAVE_OS_X_FRAMEWORKS */
	}
#else
	g_string_append(str, "an unknown OS");
#endif
}

#if defined(_WIN32)
/*
 * Get the Windows major OS version.
 *
 * XXX - Should this return the minor version as well, e.g. 0x00050002?
 *
 * XXX - I think Microsoft have now stuck it at 6 forever, so it really
 * distinguishes, on the versions of Windows we currently support and
 * future Windows versions between Windows 2000/XP (major version 5) and
 * everything after it (major version 6).
 */
guint32
get_windows_major_version(void)
{
	OSVERSIONINFO info;

	info.dwOSVersionInfoSize = sizeof info;
	if (GetVersionEx(&info)) {
		return info.dwMajorVersion;
	}
	return 0;
}
#endif
