/* version_info.c
 * Routines to report version information for Wireshark programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>

#ifdef _WIN32
#include <windows.h>
#elif __APPLE__
#include <sys/types.h>
#include <sys/sysctl.h>
#elif __linux__
#include <sys/sysinfo.h>
#endif

#include <glib.h>
#include <pcre2.h>

#ifdef HAVE_ZLIB
#include <zlib.h>
#endif

#include "vcs_version.h"

#include "version_info.h"

#include <wsutil/cpu_info.h>
#include <wsutil/os_version_info.h>
#include <wsutil/crash_info.h>
#include <wsutil/plugins.h>

static char *appname_with_version;
static char *copyright_info;
static char *license_info;
static char *comp_info;
static char *runtime_info;

static void end_string(GString *str);
static void get_compiler_info(GString *str);
static void get_mem_info(GString *str);

void
ws_init_version_info(const char *appname,
		gather_feature_func gather_compile,
		gather_feature_func gather_runtime)
{
	GString *comp_info_str, *runtime_info_str;
	GString *copyright_info_str;
	GString *license_info_str;

	copyright_info_str = g_string_new(get_copyright_info());
	end_string(copyright_info_str);
	copyright_info = g_string_free(copyright_info_str, FALSE);

	license_info_str = g_string_new(get_license_info_short());
	end_string(license_info_str);
	license_info = g_string_free(license_info_str, FALSE);

	/*
	 * Combine the supplied application name string with the
	 * version - including the VCS version, for a build from
	 * a checkout.
	 */
	if (strstr(appname, "Wireshark") != NULL) {
		appname_with_version = ws_strdup_printf("%s %s",
			appname, get_ws_vcs_version_info());
	}
	else {
		appname_with_version = ws_strdup_printf("%s (Wireshark) %s",
			appname, get_ws_vcs_version_info());
	}

	/* Get the compile-time version information string */
	comp_info_str = get_compiled_version_info(gather_compile);

	/* Get the run-time version information string */
	runtime_info_str = get_runtime_version_info(gather_runtime);

	comp_info = g_string_free(comp_info_str, FALSE);
	runtime_info = g_string_free(runtime_info_str, FALSE);

	/* Add this information to the information to be reported on a crash. */
	ws_add_crash_info("%s\n"
		"\n"
		"%s\n"
		"%s",
		appname_with_version, comp_info, runtime_info);
}

/*
 * Take the gathered list of present/absent features (dependencies)
 * and add them to the given string.
 * Callback function for g_list_foreach() used in
 * get_compiled_version_info() and get_runtime_version_info().
 */
static void
feature_to_gstring(gpointer data, gpointer user_data)
{
	gchar *feature = (gchar *)data;
	GString *str = (GString *)user_data;
	if (str->len > 0) {
		g_string_append(str, ", ");
	}
	g_string_append_printf(str, "%s %s",
			(*feature == '+' ? "with" : "without"), feature + 1);
}

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

const char *
get_appname_and_version(void)
{
	return appname_with_version;
}

static void
get_zlib_feature_info(feature_list l)
{
#ifdef HAVE_ZLIB
#ifdef ZLIB_VERSION
	with_feature(l, "zlib "ZLIB_VERSION);
#else
	with_feature(l, "zlib (version unknown)");
#endif /* ZLIB_VERSION */
#else
	without_feature(l, "zlib");
#endif /* HAVE_ZLIB */
}

/*
 * Get various library compile-time versions, put them in a GString,
 * and return the GString.
 */
GString *
get_compiled_version_info(gather_feature_func gather_compile)
{
	GString *str;
	GList *l = NULL;

	str = g_string_new("Compiled ");
	g_string_append_printf(str, "(%d-bit) ", (int)sizeof(str) * 8);

	/* Compiler info */
	g_string_append(str, "using ");
	get_compiler_info(str);

#ifdef GLIB_MAJOR_VERSION
	with_feature(&l,
		"GLib %d.%d.%d", GLIB_MAJOR_VERSION, GLIB_MINOR_VERSION,
		GLIB_MICRO_VERSION);
#else
	with_feature(&l,
		"GLib (version unknown)");
#endif
	with_feature(&l, "PCRE2");
	get_zlib_feature_info(&l);

	if (gather_compile != NULL) {
		gather_compile(&l);
	}

	l = g_list_reverse(l);
	g_list_foreach(l, feature_to_gstring, str);

#ifdef HAVE_PLUGINS
	g_string_append(str, ", with binary plugins");
#else
	g_string_append(str, ", without binary plugins");
#endif

#ifdef WS_DISABLE_DEBUG
	g_string_append(str, ", release build");
#endif

#ifdef WS_DISABLE_ASSERT
	g_string_append(str, ", without assertions");
#endif

	g_string_append(str, ".");
	end_string(str);
	free_features(&l);

	return str;
}

static void
get_mem_info(GString *str)
{
	gint64 memsize = 0;

#ifdef _WIN32
	MEMORYSTATUSEX statex;

	statex.dwLength = sizeof (statex);

	if (GlobalMemoryStatusEx(&statex))
		memsize = statex.ullTotalPhys;
#elif __APPLE__
	size_t len = sizeof(memsize);
	sysctlbyname("hw.memsize", &memsize, &len, NULL, 0);
#elif __linux__
	struct sysinfo info;
	if (sysinfo(&info) == 0)
		memsize = info.totalram * info.mem_unit;
#endif

	if (memsize > 0)
		g_string_append_printf(str, ", with %" G_GINT64_FORMAT " MB of physical memory", memsize/(1024*1024));
}

/*
 * Get compiler information, and append it to the GString.
 */
static void
get_compiler_info(GString *str)
{
	/*
	 * See https://sourceforge.net/apps/mediawiki/predef/index.php?title=Compilers
	 * information on various defined strings.
	 *
	 * GCC's __VERSION__ is a nice text string for humans to
	 * read.  The page at sourceforge.net largely describes
	 * numeric #defines that encode the version; if the compiler
	 * doesn't also offer a nice printable string, we try prettifying
	 * the number somehow.
	 */
	#if defined(_MSC_FULL_VER)
		/*
		 * We check for this first, as Microsoft have a version of their
		 * compiler that has Clang as the front end and their code generator
		 * as the back end.
		 *
		 * My head asplode.
		 */

		/* As of Wireshark 3.0, we support only Visual Studio 2015 (14.x)
		 * or later.
		 *
		 * https://dev.to/yumetodo/list-of-mscver-and-mscfullver-8nd
		 * has a *large* table of Microsoft product names, VC++ versions,
		 * _MSC_VER values, and _MSC_FULL_VER values.  All the versions
		 * we support define _MSC_FULL_VER.  We don't bother trying to
		 * get the SP/update/version number from the build number, as
		 * we'd have to keep updating that with every update; there's no
		 * way to get that information directly from a predefine, and in
		 * some cases multiple updates/versions have the *same* build
		 * number (because they didn't update the toolchain).
		 *
		 * https://docs.microsoft.com/en-us/cpp/preprocessor/predefined-macros?view=vs-2017
		 * defines the format of _MSC_VER and _MSC_FULL_VER.  _MSC_FULL_VER
		 * is a decimal number of the form MMmmBBBBB, where MM is the compiler/
		 * toolchain major version, mm is the minor version, and BBBBB is the
		 * build.  We break it down based on that.
		 */
		#define COMPILER_MAJOR_VERSION (_MSC_FULL_VER / 10000000)
		#define COMPILER_MINOR_VERSION ((_MSC_FULL_VER % 10000000) / 100000)
		#define COMPILER_BUILD_NUMBER (_MSC_FULL_VER % 100000)

		/*
		 * From https://web.archive.org/web/20190125151548/https://blogs.msdn.microsoft.com/vcblog/2014/11/17/c111417-features-in-vs-2015-preview/
		 * Bakersfield: DevDiv's upper management determines the scheduling
		 * of new major versions.  They also decided to increment the product
		 * version from 12 (for VS 2013) to 14 (for VS 2015).  However, the
		 * C++ compiler's version incremented normally, from 18 to 19.
		 * (It's larger because the C++ compiler predates the "Visual" in
		 * Visual C++.)
		 *
		 * So the product version number is 5 less than the compiler version
		 * number.
		 */
		#define VCPP_MAJOR_VERSION	(COMPILER_MAJOR_VERSION - 5)

		#if VCPP_MAJOR_VERSION == 14
			/*
			 * From https://devblogs.microsoft.com/cppblog/side-by-side-minor-version-msvc-toolsets-in-visual-studio-2017/
			 *
			 * We've been delivering improvements to Visual Studio 2017 more
			 * frequently than ever before. Since its first release in March
			 * we've released four major updates to VS2017 and are currently
			 * previewing the fifth update, VS2017 version 15.5.
			 *
			 * The MSVC toolset in VS2017 is built as a minor version update to
			 * the VS2015 compiler toolset. This minor version bump indicates
			 * that the VS2017 MSVC toolset is binary compatible with the VS2015
			 * MSVC toolset, enabling an easier upgrade for VS2015 users. Even
			 * though the MSVC compiler toolset in VS2017 delivers many new
			 * features and conformance improvements it is a minor version,
			 * compatible update from 14.00 in VS2015 to 14.10 in VS2017.
			 */
			#if COMPILER_MINOR_VERSION < 10
				#define VS_VERSION	"2015"
			#elif COMPILER_MINOR_VERSION < 20
				#define VS_VERSION	"2017"
			#elif COMPILER_MINOR_VERSION < 30
			#define VS_VERSION	"2019"
			#else
				#define VS_VERSION	"2022"
			#endif
		#else
			/*
			 * Add additional checks here, before the #else.
			 */
			#define VS_VERSION	"(unknown)"
		#endif /* VCPP_MAJOR_VERSION */

		/*
		 * XXX - should we show the raw compiler version number, as is
		 * shown by "cl /?", which would be %d.%d.%d.%d with
		 * COMPILER_MAJOR_VERSION, COMPILER_MINOR_VERSION,
		 * COMPILER_BUILD_NUMBER, and _MSC_BUILD, the last of which is
		 * "the revision number element of the compiler's version number",
		 * which I guess is not to be confused with the build number,
		 * the _BUILD in the name nonwithstanding.
		 */
		g_string_append_printf(str, "Microsoft Visual Studio " VS_VERSION " (VC++ %d.%d, build %d)",
			VCPP_MAJOR_VERSION, COMPILER_MINOR_VERSION, COMPILER_BUILD_NUMBER);
		#if defined(__clang__)
			/*
			 * See above.
			 */
			g_string_append_printf(str, " clang/C2 %s and -fno-ms-compatibility",
				__VERSION__);
		#endif
	#elif defined(__GNUC__) && defined(__VERSION__)
		/*
		 * Clang and llvm-gcc also define __GNUC__ and __VERSION__;
		 * distinguish between them.
		 */
		#if defined(__clang__)
			/* clang */
			gchar *version; /* clang's version string has a trailing space. */
			#if defined(__clang_version__)
				version = g_strdup(__clang_version__);
				g_string_append_printf(str, "Clang %s", g_strstrip(version));
			#else
				version = g_strdup(__VERSION__);
				g_string_append_printf(str, "%s", g_strstrip(version));
			#endif /* __clang_version__ */
			g_free(version);
		#elif defined(__llvm__)
			/* llvm-gcc */
			g_string_append_printf(str, "llvm-gcc %s", __VERSION__);
		#else
			/* boring old GCC */
			g_string_append_printf(str, "GCC %s", __VERSION__);
		#endif
	#elif defined(__HP_aCC)
		g_string_append_printf(str, "HP aCC %d", __HP_aCC);
	#elif defined(__xlC__)
		g_string_append_printf(str, "IBM XL C %d.%d",
			(__xlC__ >> 8) & 0xFF, __xlC__ & 0xFF);
		#ifdef __IBMC__
			if ((__IBMC__ % 10) != 0)
				g_string_append_printf(str, " patch %d", __IBMC__ % 10);
		#endif /* __IBMC__ */
	#elif defined(__INTEL_COMPILER)
		g_string_append_printf(str, "Intel C %d.%d",
			__INTEL_COMPILER / 100, (__INTEL_COMPILER / 10) % 10);
		if ((__INTEL_COMPILER % 10) != 0)
			g_string_append_printf(str, " patch %d", __INTEL_COMPILER % 10);
		#ifdef __INTEL_COMPILER_BUILD_DATE
			g_string_sprinta(str, ", compiler built %04d-%02d-%02d",
				__INTEL_COMPILER_BUILD_DATE / 10000,
				(__INTEL_COMPILER_BUILD_DATE / 100) % 100,
				__INTEL_COMPILER_BUILD_DATE % 100);
		#endif /* __INTEL_COMPILER_BUILD_DATE */
	#elif defined(__SUNPRO_C)
		g_string_append_printf(str, "Sun C %d.%d",
			(__SUNPRO_C >> 8) & 0xF, (__SUNPRO_C >> 4) & 0xF);
		if ((__SUNPRO_C & 0xF) != 0)
			g_string_append_printf(str, " patch %d", __SUNPRO_C & 0xF);
	#else
		g_string_append(str, "unknown compiler");
	#endif
}

static inline void
get_pcre2_runtime_version_info(feature_list l)
{
	/* From pcre2_api(3):
	 *     The where argument should point to a buffer that is at  least  24  code
	 *     units  long.  (The  exact  length  required  can  be  found  by calling
	 *     pcre2_config() with where set to NULL.)
	 *
	 * The API should accept a buffer size as additional input. We could opt for a
	 * stack buffer size greater than 24 but let's just go with the weirdness...
	 */
	int size;
	char *buf_pcre2;

	size = pcre2_config(PCRE2_CONFIG_VERSION, NULL);
	if (size < 0 || size > 255) {
		without_feature(l, "PCRE2 (error querying)");
		return;
	}
	buf_pcre2 = g_malloc(size + 1);
	pcre2_config(PCRE2_CONFIG_VERSION, buf_pcre2);
	buf_pcre2[size] = '\0';
	with_feature(l, "PCRE2 %s", buf_pcre2);
	g_free(buf_pcre2);
}

/*
 * Get various library run-time versions, and the OS version, and append
 * them to the specified GString.
 *
 * "additional_info" is called at the end to append any additional
 * information; this is required in order to, for example, put the
 * libcap information at the end of the string, as we currently
 * don't use libcap in TShark.
 */
GString *
get_runtime_version_info(gather_feature_func gather_runtime)
{
	GString *str;
	gchar *lc;
	GList *l = NULL;

	str = g_string_new("Running on ");

	get_os_version_info(str);

	/* CPU Info */
	get_cpu_info(str);

	/* Get info about installed memory */
	get_mem_info(str);

	with_feature(&l, "GLib %u.%u.%u",
			glib_major_version, glib_minor_version, glib_micro_version);
	get_pcre2_runtime_version_info(&l);
#if defined(HAVE_ZLIB) && !defined(_WIN32)
	with_feature(&l, "zlib %s", zlibVersion());
#endif
	if (gather_runtime != NULL) {
		gather_runtime(&l);
	}

	l = g_list_reverse(l);
	g_list_foreach(l, feature_to_gstring, str);

	/*
	 * Display LC_CTYPE as a relevant, portable and sort of representative
	 * locale configuration without being exceedingly verbose and including
	 * the whole shebang of categories using LC_ALL.
	 */
	if ((lc = setlocale(LC_CTYPE, NULL)) != NULL) {
		g_string_append_printf(str, ", with LC_TYPE=%s", lc);
	}

#ifdef HAVE_PLUGINS
	if (g_module_supported()) {
		g_string_append(str, ", binary plugins supported");
	}
#endif

	g_string_append_c(str, '.');
	end_string(str);
	free_features(&l);

	return str;
}

/*
 * Return a version number string for Wireshark, including, for builds
 * from a tree checked out from Wireshark's version control system,
 * something identifying what version was checked out.
 */
const char *
get_ws_vcs_version_info(void)
{
#ifdef VCSVERSION
	return VERSION " (" VCSVERSION ")";
#else
	return VERSION;
#endif
}

const char *
get_ws_vcs_version_info_short(void)
{
#ifdef VCSVERSION
	return VCSVERSION;
#else
	return VERSION;
#endif
}

void
get_ws_version_number(int *major, int *minor, int *micro)
{
	if (major)
		*major = VERSION_MAJOR;
	if (minor)
		*minor = VERSION_MINOR;
	if (micro)
		*micro = VERSION_MICRO;
}

void
show_version(void)
{
	printf("%s.\n\n"
		"%s"
		"%s\n"
		"%s\n"
		"%s",
		appname_with_version,
		copyright_info,
		license_info,
		comp_info,
		runtime_info);
}

void
show_help_header(const char *description)
{
	printf("%s\n"
		"%s\n"
		"See https://www.wireshark.org for more information.\n",
		appname_with_version, description);
}

/*
 * Get copyright information.
 */
const char *
get_copyright_info(void)
{
	return
		"Copyright 1998-2022 Gerald Combs <gerald@wireshark.org> and contributors.";
}

const char *
get_license_info_short(void)
{
	return
		"Licensed under the terms of the GNU General Public License (version 2 or later). "
		"This is free software; see the file named COPYING in the distribution. "
		"There is NO WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.";
}

const char *
get_license_info(void)
{
	return
		"This program is free software: you can redistribute it and/or modify "
		"it under the terms of the GNU General Public License as published by "
		"the Free Software Foundation, either version 2 of the License, or "
		"(at your option) any later version. This program is distributed in the "
		"hope that it will be useful, but WITHOUT ANY WARRANTY; without even "
		"the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. "
		"See the GNU General Public License for more details.";
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
