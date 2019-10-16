/* version_info.h
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
 * it should include the application name, followed by "(Wireshark)" if
 * the program isn't Wireshark.
 *
 * "prepend_compile_time_info" is called at the start to prepend any
 * additional build information before the standard library information.
 *
 * "append_compile_time_info" is called at the end to append any additional
 * build information after the standard library information.  This is
 * required in order to, for example, put Qt information at the
 * end of the string, as we don't use Qt in TShark.
 *
 * "additional_info" is called at the end to append any additional
 * run-time information; this is required in order to, for example,
 * put the libcap information at the end of the string, as we currently
 * don't use libcap in TShark.
 */
void ws_init_version_info(const char *appname,
    void (*prepend_compile_time_info)(GString *),
    void (*append_compile_time_info)(GString *),
    void (*additional_run_time_info)(GString *));

/*
 * Get a string giving the application name, as provided to
 * ws_init_version_info(), followed by a string giving the
 * application version.
 */
const char *get_appname_and_version(void);

/*
 * Get various library compile-time versions, put them in a GString,
 * and return the GString.
 *
 * "prepend_info" is called at the start to prepend any additional
 * information before the standard library information.
 *
 * "append_info" is called at the end to append any additional
 * information after the standard library information.  This is
 * required in order to, for example, put Qt information at the
 * end of the string, as we don't use Qt in TShark.
 */
GString *get_compiled_version_info(void (*prepend_info)(GString *),
                                                 void (*append_info)(GString *));

/*
 * Get various library run-time versions, and the OS version, put them in
 * a GString, and return the GString.
 *
 * "additional_info" is called at the end to append any additional
 * information; this is required in order to, for example, put the
 * libcap information at the end of the string, as we currently
 * don't use libcap in TShark.
 */
GString *get_runtime_version_info(void (*additional_info)(GString *));

/*
 * Return a version number string for Wireshark, including, for builds
 * from a tree checked out from Wireshark's version control system,
 * something identifying what version was checked out.
 */
const char *get_ws_vcs_version_info(void);

/*
 * Return version number as integers.
 */
void get_ws_version_number(int *major, int *minor, int *micro);

/*
 * Show the program name and version number information on the standard
 * output; this is used for command-line "show the version" options.
 */
void show_version(void);

/*
 * Show the program name and version number information, a supplied
 * description string, and a "See {URL} for more information" message.
 * This is used for command-line "help" options.
 */
void show_help_header(const char *description);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_VERSION_INFO_H__ */
