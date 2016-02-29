/* all_files_wildcard.h
 * Definition of a macro for the file wildcard pattern that matches
 * all files
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

#ifndef __ALL_FILES_WILDCARD_H__
#define __ALL_FILES_WILDCARD_H__

#ifdef _WIN32
/*
 * On Windows, the wildcard for matching all files is "*.*", which
 * even matches files with no extension.
 */
#define ALL_FILES_WILDCARD "*.*"
#else
/*
 * On UN*X, the wildcard for matching all files is "*"; "*.*" only
 * matches files with at least one extension.
 */
#define ALL_FILES_WILDCARD "*"
#endif

#endif /* __ALL_FILES_WILDCARD_H__ */

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
