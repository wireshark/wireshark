/* fileset.h
 * Definitions for routines for file sets.
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

#ifndef __FILESET_H__
#define __FILESET_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */


typedef struct _fileset_entry {
  const char    *fullname;      /* File name with path (g_strdup'ed) */
  const char    *name;          /* File name without path (g_strdup'ed) */
  time_t        ctime;          /* create time */
  time_t        mtime;          /* last modified time */
  long          size;           /* size of file in bytes */
  gboolean      current;        /* is this the currently loaded file? */
} fileset_entry;


/* helper: is this a probable file of a file set (does the naming pattern match)? */
extern gboolean fileset_filename_match_pattern(const char *fname);

/* helper: test, if both files could be in the same file set */
extern gboolean fileset_is_file_in_set(const char *fname1, const char *fname2);

extern void fileset_add_dir(const char *fname);

extern void fileset_delete(void);

/* get the current directory name */
extern const char *fileset_get_dirname(void);

extern fileset_entry *fileset_get_next(void);
extern fileset_entry *fileset_get_previous(void);



/* this file is a part of the current file set */
extern void fileset_dlg_add_file(fileset_entry *entry);

extern void fileset_file_opened(const char *fname);

extern void fileset_file_closed(void);

extern void fileset_update_dlg(void);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILESET_H__ */

