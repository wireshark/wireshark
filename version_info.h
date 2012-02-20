/* version_info.h
 * Declarations of outines to report version information for stuff used
 * by Wireshark
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

#ifndef __VERSION_INFO_H__
#define __VERSION_INFO_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * The svn version string or ""
 */
extern const gchar *wireshark_svnversion;

/*
 * Get various library compile-time versions and append them to
 * the specified GString.
 *
 * "prepend_info" is called at the start to prepend any additional
 * information.
 *
 * "append_info" is called at the end to append any additional
 * information; this is required in order to, for example, put the
 * Portaudio information at the end of the string, as we currently
 * don't use Portaudio in TShark.
 */
void get_compiled_version_info(GString *str,
    void (*prepend_info)(GString *),
    void (*append_info)(GString *));

/*
 * Get the OS version, and append it to the GString
 */
void get_os_version_info(GString *str);

/*
 * Get various library run-time versions, and the OS version, and append
 * them to the specified GString.
 */
void get_runtime_version_info(GString *str,
    void (*additional_info)(GString *));

/*
 * Get copyright information.
 */
const char *get_copyright_info(void);

#if defined(_WIN32)
/*
 * Get the major OS version.
 */
guint32 get_os_major_version();
#endif

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __VERSION_INFO_H__ */
