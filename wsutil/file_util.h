/* file_util.h
 * File utility definitions
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

#ifndef __FILE_UTIL_H__
#define __FILE_UTIL_H__

#include "ws_symbol_export.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>

#ifdef _WIN32
#include <io.h>		/* for _read(), _write(), etc. */
#include <gmodule.h>
#endif

#ifdef HAVE_FCNTL_H
#include <fcntl.h>	/* for open() */
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>	/* for read(), write(), close(), etc. */
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>	/* for stat() and struct stat */
#endif

/*
 * Visual C++ on Win32 systems doesn't define these.  (Old UNIX systems don't
 * define them either.)
 *
 * Visual C++ on Win32 systems doesn't define S_IFIFO, it defines _S_IFIFO.
 */
#ifndef S_ISREG
#define S_ISREG(mode)   (((mode) & S_IFMT) == S_IFREG)
#endif
#ifndef S_IFIFO
#define S_IFIFO _S_IFIFO
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(mode)  (((mode) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode)   (((mode) & S_IFMT) == S_IFDIR)
#endif

#include <stdio.h>

#ifdef _WIN32

/*
 * The structure to pass to ws_stat64() and ws_fstat64().
 */
#define ws_statb64	struct _stat64

/*  Win32 (and Win64): we use UTF-8 for filenames and pathnames throughout
 *  the code, so file functions must convert filenames and pathnames from
 *  UTF-8 to UTF-16 as we use NT Unicode (Win9x - now unsupported - used
 *  locale-based encoding here).  Microsoft's UN*X-style wrappers don't
 *  do that - they expect locale-based encodings - so we need our own
 *  wrappers.  (We don't use the wrappers from GLib as that would, at
 *  least for the wrappers that return file descriptors or take them
 *  as arguments, require that we use the version of the C runtime with
 *  which the GLib binaries were built, and we can't guarantee to do that.)
 *
 *  Note also that ws_stdio_rename() uses MoveFileEx() with
 *  MOVEFILE_REPLACE_EXISTING, so that it acts like UN*X rename(),
 *  removing the target if necessary.
 */

WS_DLL_PUBLIC int ws_stdio_open (const gchar *filename, int flags, int mode);
WS_DLL_PUBLIC int ws_stdio_rename (const gchar *oldfilename, const gchar *newfilename);
WS_DLL_PUBLIC int ws_stdio_mkdir (const gchar *filename, int mode);
WS_DLL_PUBLIC int ws_stdio_stat64 (const gchar *filename, ws_statb64 *buf);
WS_DLL_PUBLIC int ws_stdio_unlink (const gchar *filename);
WS_DLL_PUBLIC int ws_stdio_remove (const gchar *filename);

WS_DLL_PUBLIC FILE * ws_stdio_fopen (const gchar *filename, const gchar *mode);
WS_DLL_PUBLIC FILE * ws_stdio_freopen (const gchar *filename, const gchar *mode, FILE *stream);

#define ws_open		ws_stdio_open
#define ws_rename	ws_stdio_rename
#define ws_mkdir	ws_stdio_mkdir
#define ws_stat64	ws_stdio_stat64
#define ws_unlink	ws_stdio_unlink
#define ws_remove	ws_stdio_remove
#define ws_fopen	ws_stdio_fopen
#define ws_freopen	ws_stdio_freopen

/*
 * These routines don't take pathnames, so they don't require
 * pathname-converting wrappers on Windows.
 */
#define ws_read    _read
#define ws_write   _write
#define ws_close   _close
#define ws_dup     _dup
#define ws_fstat64 _fstati64	/* use _fstati64 for 64-bit size support */
#define ws_lseek64 _lseeki64	/* use _lseeki64 for 64-bit offset support */
#define ws_fdopen  _fdopen
#define ws_fileno  _fileno
#define ws_isatty  _isatty
#define ws_getc_unlocked _fgetc_nolock

/*
 * Other CRT functions. getpid probably belongs in sys_util.h or proc_util.h
 * but neither yet exist.
 */
#define ws_getpid  _getpid
#define ws_umask  _umask

/* DLL loading */

/** Try to remove the current directory from the DLL search path.
 * SetDllDirectory is tried, then SetCurrentDirectory(program_dir)
 *
 * @return TRUE if we were able to call SetDllDirectory, FALSE otherwise.
 */
WS_DLL_PUBLIC
gboolean ws_init_dll_search_path();

/** Load a DLL using LoadLibrary.
 * Only the system and program directories are searched.
 *
 * @param library_name The name of the DLL.
 * @return A handle to the DLL if found, NULL on failure.
 */

WS_DLL_PUBLIC
void *ws_load_library(const gchar *library_name);

/** Load a DLL using g_module_open.
 * Only the system and program directories are searched.
 *
 * @param module_name The name of the DLL.
 * @param flags Flags to be passed to g_module_open.
 * @return A handle to the DLL if found, NULL on failure.
 */
WS_DLL_PUBLIC
GModule *ws_module_open(gchar *module_name, GModuleFlags flags);

/** Create or open a "Wireshark is running" mutex.
 * Create or open a mutex which signals that Wireshark or its associated
 * executables is running. Used by the installer to test for a running application.
 */
WS_DLL_PUBLIC void create_app_running_mutex();

#else	/* _WIN32 */

/*
 * The structure to pass to ws_fstat64().
 */
#define ws_statb64	struct stat

/* Not Windows, presumed to be UN*X-compatible */
#define ws_open			open
#define ws_rename		rename
#define ws_mkdir(dir,mode)	mkdir(dir,mode)
#define ws_stat64		stat
#define ws_unlink		unlink
#define ws_remove		remove
#define ws_fopen		fopen
#define ws_freopen		freopen

#define ws_read    read
#define ws_write   write
#ifdef __cplusplus
/*
 * Just in case this is used in a class with a close method or member.
 */
#define ws_close   ::close
#else
#define ws_close   close
#endif
#define ws_dup     dup
#define ws_fstat64 fstat	/* AC_SYS_LARGEFILE should make off_t 64-bit */
#define ws_lseek64 lseek	/* AC_SYS_LARGEFILE should make off_t 64-bit */
#define ws_fdopen  fdopen
#define ws_fileno  fileno
#define ws_isatty  isatty
#define ws_getc_unlocked getc_unlocked
#define O_BINARY   0		/* Win32 needs the O_BINARY flag for open() */

/* Other CRT functions */
#define ws_getpid  getpid
#define ws_umask   umask

#endif /* _WIN32 */

/* directory handling */
#define WS_DIR				GDir
#define WS_DIRENT			const char
#define ws_dir_open			g_dir_open
#define ws_dir_read_name		g_dir_read_name
#define ws_dir_get_name(dirent)		dirent
#define ws_dir_rewind			g_dir_rewind
#define ws_dir_close			g_dir_close

/* XXX - remove include "sys/stat.h" from files that include this header */
/* XXX - update docs (e.g. README.developer) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_UTIL_H__ */
