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
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif


/* Win32: Since GLib2.6, we use UTF8 throughout the code, so file functions must tweak a given filename
	from UTF8 to UTF16 as we use NT Unicode (Win9x - now unsupported - used locale based encoding here). */
#if defined _WIN32 && (GLIB_MAJOR_VERSION > 2 || (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION >= 6))
#include <stdio.h>

extern int eth_stdio_open (const gchar *filename, int flags, int mode);
extern int eth_stdio_rename (const gchar *oldfilename, const gchar *newfilename);
extern int eth_stdio_mkdir (const gchar *filename, int mode);
extern int eth_stdio_stat (const gchar *filename, struct stat *buf);
extern int eth_stdio_unlink (const gchar *filename);
extern int eth_stdio_remove (const gchar *filename);
extern FILE * eth_stdio_fopen (const gchar *filename, const gchar *mode);
extern FILE * eth_stdio_freopen (const gchar *filename, const gchar *mode, FILE *stream);

#define eth_open	eth_stdio_open
#define eth_rename	eth_stdio_rename
#define eth_mkdir	eth_stdio_mkdir
#define eth_stat	eth_stdio_stat
#define eth_unlink	eth_stdio_unlink
#define eth_remove	eth_stdio_remove
#define eth_fopen	eth_stdio_fopen
#define eth_freopen	eth_stdio_freopen

#else	/* _WIN32 && GLIB_MAJOR_VERSION */

/* GLib 2.4 or below, using "old school" functions */
#ifdef _WIN32
#define eth_open	_open
#define eth_stat	_stat
#define eth_unlink	_unlink
#define eth_mkdir(dir,mode)	_mkdir(dir)
#else
#define eth_open	open
#define eth_stat	stat
#define eth_unlink	unlink
#define eth_mkdir(dir,mode)	mkdir(dir,mode)
#endif /* _WIN32 */

#define eth_rename	rename
#define eth_remove	remove
#define eth_fopen	fopen
#define eth_freopen	freopen

#endif	/* _WIN32 && GLIB_MAJOR_VERSION */


/* some common file function differences between UNIX and WIN32 */
#ifdef _WIN32
/* the Win32 API prepends underscores for whatever reasons */
#define eth_read  _read
#define eth_write _write
#define eth_close _close
#define eth_dup   _dup
#define eth_lseek _lseek
#else
#define eth_read  read
#define eth_write write
#define eth_close close
#define eth_dup   dup
#define eth_lseek lseek
#define O_BINARY	0		/* Win32 needs the O_BINARY flag for open() */
#endif /* _WIN32 */

/* directory handling */
#if GLIB_MAJOR_VERSION >= 2
#define ETH_DIR				GDir
#define ETH_DIRENT			const char
#define eth_dir_open			g_dir_open
#define eth_dir_read_name		g_dir_read_name
#define eth_dir_get_name(dirent)	dirent
#define eth_dir_rewind			g_dir_rewind
#define eth_dir_close			g_dir_close
#else
#define ETH_DIR				DIR
#define ETH_DIRENT			struct dirent
#define eth_dir_open(name,flags,error)	opendir(name)
#define eth_dir_read_name		readdir
#define eth_dir_get_name(dirent)	(gchar *)file->d_name
#define eth_dir_rewind			rewinddir
#define eth_dir_close			closedir
#endif /* GLIB_MAJOR_VERSION */

/* XXX - remove include "dirent.h" */
/* XXX - remove include "direct.h" */
/* XXX - remove include "sys/stat.h" */
/* XXX - update docs (e.g. README.developer) */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_UTIL_H__ */
