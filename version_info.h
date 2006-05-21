/* version_info.h
 * Declarations of outines to report version information for stuff used
 * by Ethereal
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
const gchar *svnversion;

/*
 * Get various library compile-time versions and append them to
 * the specified GString.
 */
void get_compiled_version_info(GString *str);

/*
 * Get various library run-time versions, and the OS version, and append
 * them to the specified GString.
 */
void get_runtime_version_info(GString *str);

/*
 * Get copyright information.
 */
const char *get_copyright_info(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __VERSION_INFO_H__ */
