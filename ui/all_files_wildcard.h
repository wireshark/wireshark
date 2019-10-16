/* all_files_wildcard.h
 * Definition of a macro for the file wildcard pattern that matches
 * all files
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
