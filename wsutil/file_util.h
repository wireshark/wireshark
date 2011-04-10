/* file_util.h
 * File utility definitions
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

#ifndef __FILE_UTIL_H__
#define __FILE_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>

#ifdef _WIN32
#include <io.h>
#include <gmodule.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif


/*  Win32: Since GLib2.6, we use UTF8 throughout the code, so file functions
 *  must tweak a given filename from UTF8 to UTF16 as we use NT Unicode (Win9x
 *  - now unsupported - used locale based encoding here).
 */
#if defined _WIN32 && GLIB_CHECK_VERSION(2,6,0)
#include <stdio.h>

extern int ws_stdio_open (const gchar *filename, int flags, int mode);
extern int ws_stdio_rename (const gchar *oldfilename, const gchar *newfilename);
extern int ws_stdio_mkdir (const gchar *filename, int mode);
extern int ws_stdio_stat (const gchar *filename, struct stat *buf);
extern int ws_stdio_unlink (const gchar *filename);
extern int ws_stdio_remove (const gchar *filename);
extern FILE * ws_stdio_fopen (const gchar *filename, const gchar *mode);
extern FILE * ws_stdio_freopen (const gchar *filename, const gchar *mode, FILE *stream);

#define ws_open		ws_stdio_open
#define ws_rename	ws_stdio_rename
#define ws_mkdir	ws_stdio_mkdir
#define ws_stat		ws_stdio_stat
#define ws_unlink	ws_stdio_unlink
#define ws_remove	ws_stdio_remove
#define ws_fopen	ws_stdio_fopen
#define ws_freopen	ws_stdio_freopen

#else	/* _WIN32 && GLIB_CHECK_VERSION */

/* "Not Windows" or GLib < 2.6: use "old school" functions */
#ifdef _WIN32
#define ws_open		_open
#define ws_stat		_stat
#define ws_unlink	_unlink
#define ws_mkdir(dir,mode)	_mkdir(dir)
#else
#define ws_open		open
#define ws_stat		stat
#define ws_unlink	unlink
#define ws_mkdir(dir,mode)	mkdir(dir,mode)
#endif /* _WIN32 */

#define ws_rename	rename
#define ws_remove	remove
#define ws_fopen	fopen
#define ws_freopen	freopen

#endif	/* _WIN32 && GLIB_CHECK_VERSION */


/* some common file function differences between UNIX and WIN32 */
#ifdef _WIN32
/* the Win32 API prepends underscores for whatever reasons */
#define ws_read    _read
#define ws_write   _write
#define ws_close   _close
#define ws_dup     _dup
#define ws_fstat64 _fstati64	/* use _fstati64 for 64-bit size support */
#define ws_lseek64 _lseeki64	/* use _lseeki64 for 64-bit offset support */

/*
 * The structure to pass to ws_fstat64().
 */
#define ws_statb64	struct _stat64

/* DLL loading */

/** Try to remove the current directory from the DLL search path.
 * SetDllDirectory is tried, then SetCurrentDirectory(program_dir)
 *
 * @return TRUE if we were able to call SetDllDirectory, FALSE otherwise.
 */
gboolean ws_init_dll_search_path();

/** Load a DLL using LoadLibrary.
 * Only the system and program directories are searched.
 *
 * @param library_name The name of the DLL.
 * @return A handle to the DLL if found, NULL on failure.
 */

void *ws_load_library(gchar *library_name);
/** Load a DLL using g_module_open.
 * Only the system and program directories are searched.
 *
 * @param module_name The name of the DLL.
 * @param flags Flags to be passed to g_module_open.
 * @return A handle to the DLL if found, NULL on failure.
 */
GModule *ws_module_open(gchar *module_name, GModuleFlags flags);

/*
 * utf8 version of getenv, needed to get win32 filename paths
 */
extern char *getenv_utf8(const char *varname);

#else /* _WIN32 */
#define ws_read    read
#define ws_write   write
#define ws_close   close
#define ws_dup     dup
#define ws_fstat64 fstat	/* AC_SYS_LARGEFILE should make off_t 64-bit */
#define ws_lseek64 lseek	/* AC_SYS_LARGEFILE should make off_t 64-bit */
#define O_BINARY   0		/* Win32 needs the O_BINARY flag for open() */

/*
 * The structure to pass to ws_fstat64().
 */
#define ws_statb64	struct stat
#endif /* _WIN32 */

/* directory handling */
#define WS_DIR				GDir
#define WS_DIRENT			const char
#define ws_dir_open			g_dir_open
#define ws_dir_read_name		g_dir_read_name
#define ws_dir_get_name(dirent)	dirent
#define ws_dir_rewind			g_dir_rewind
#define ws_dir_close			g_dir_close

/* XXX - remove include "dirent.h" */
/* XXX - remove include "direct.h" */
/* XXX - remove include "sys/stat.h" */
/* XXX - update docs (e.g. README.developer) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_UTIL_H__ */
