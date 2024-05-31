/** @file
 *
 * Declarations of routines to report version information for Wireshark
 * programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __WS_VERSION_INFO_H__
#define __WS_VERSION_INFO_H__

#include <glib.h>
#include <wsutil/feature_list.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Initialize information about the program for various purposes, including
 * reporting the version and build information for the program, putting
 * that information into crash dumps if possible, and giving the program
 * name and version information into capture files written by the program
 * if possible.
 *
 * "appname" is a string that appears at the beginning of the information;
 * it should be the application name. "(Wireshark)" will be added if
 * the program isn't Wireshark.
 *
 * "gather_compile" is called (if non-null) to add any additional build-time
 * information.
 *
 * "gather_runtime" is called (if non-null) to add any additional
 * run-time information; this is required in order to, for example,
 * put the libcap information into the string, as we currently
 * don't use libcap in TShark.
 */
WS_DLL_PUBLIC
void ws_init_version_info(const char *appname,
		gather_feature_func gather_compile,
		gather_feature_func gather_runtime);

/*
 * Get a string giving the application name, as provided to
 * ws_init_version_info(), followed by a string giving the
 * application version.
 */
WS_DLL_PUBLIC
const char *get_appname_and_version(void);

WS_DLL_PUBLIC
void
gather_pcre2_compile_info(feature_list l);

WS_DLL_PUBLIC
void
gather_zlib_compile_info(feature_list l);

WS_DLL_PUBLIC
void
gather_zlib_ng_compile_info(feature_list l);

/*
 * Get various library compile-time versions, put them in a GString,
 * and return the GString.
 *
 * "gather_compile" is called (if non-null) to add any additional build-time
 * information.
 */
WS_DLL_PUBLIC
GString *get_compiled_version_info(gather_feature_func gather_compile);

WS_DLL_PUBLIC
void
gather_pcre2_runtime_info(feature_list l);

WS_DLL_PUBLIC
void
gather_zlib_runtime_info(feature_list l);

/*
 * Get various library run-time versions, and the OS version, put them in
 * a GString, and return the GString.
 *
 * "gather_runtime" is called (if non-null) to add any additional
 * run-time information; this is required in order to, for example,
 * put the libcap information into the string, as we currently
 * don't use libcap in TShark.
 */
WS_DLL_PUBLIC
GString *get_runtime_version_info(gather_feature_func gather_runtime);

/*
 * Return a version number string for Wireshark, including, for builds
 * from a tree checked out from Wireshark's version control system,
 * something identifying what version was checked out.
 */
WS_DLL_PUBLIC
const char *get_ws_vcs_version_info(void);

/*
 * Return a version number string for Logray, including, for builds
 * from a tree checked out from Logray's version control system,
 * something identifying what version was checked out.
 */
WS_DLL_PUBLIC
const char *get_lr_vcs_version_info(void);

/*
 * Shorter version of get_ws_vcs_version_info().
 */
WS_DLL_PUBLIC
const char *get_ws_vcs_version_info_short(void);

/*
 * Return version number as integers.
 */
WS_DLL_PUBLIC
void get_ws_version_number(int *major, int *minor, int *micro);

/*
 * Show the program name and version number information on the standard
 * output; this is used for command-line "show the version" options.
 */
WS_DLL_PUBLIC
void show_version(void);

/*
 * Show the program name and version number information, a supplied
 * description string, and a "See {URL} for more information" message.
 * This is used for command-line "help" options.
 */
WS_DLL_PUBLIC
void show_help_header(const char *description);

WS_DLL_PUBLIC
const char *get_copyright_info(void);

WS_DLL_PUBLIC
const char *get_license_info(void);

WS_DLL_PUBLIC
const char *get_license_info_short(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_VERSION_INFO_H__ */
