/* version_info.h
 * Declarations of routines to report version information for Wireshark
 * programs
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#ifndef __WS_VERSION_INFO_H__
#define __WS_VERSION_INFO_H__

#include <glib.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Get various library compile-time versions, put them in a GString,
 * and return the GString.
 *
 * "prepend_info" is called at the start to prepend any additional
 * information before the standard library information.
 *
 * "append_info" is called at the end to append any additional
 * information after the standard library information.  This is
 * required in order to, for example, put the Portaudio information
 * at the end of the string, as we currently don't use Portaudio in
 * TShark.
 */
GString *get_compiled_version_info(void (*prepend_info)(GString *),
                                                 void (*append_info)(GString *));

/*
 * Get various library run-time versions, and the OS version, put them in
 * a GString, and return the GString.
 *
 * "additional_info" is called at the end to append any additional
 * information; this is required in order to, for example, put the
 * Portaudio information at the end of the string, as we currently
 * don't use Portaudio in TShark.
 */
GString *get_runtime_version_info(void (*additional_info)(GString *));

void show_version(const gchar *prog_name, GString *comp_info_str, GString *runtime_info_str);

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_VERSION_INFO_H__ */
