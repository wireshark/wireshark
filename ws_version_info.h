/* ws_version_info.h
 * Declarations of routines to report version information for Wireshark
 * programs
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

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __WS_VERSION_INFO_H__ */
