/* file_util.h
 * File utility definitions
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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


/* Since GLib2.6, wrappers were added around functions which provides filenames to library functions, 
	like open() does. */
#if GLIB_MAJOR_VERSION > 2 || (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION >= 6)
#include <glib/gstdio.h>	/* available since GLib 2.6 only! */

/* GLib2.6 or above, using new wrapper functions */
#define eth_mkstemp g_mkstemp
#define eth_open	g_open
#define eth_rename	g_rename
#define eth_mkdir	g_mkdir
#define eth_stat	g_stat
#define eth_unlink	g_unlink
#define eth_remove	g_remove
#define eth_fopen	g_fopen
#define eth_freopen	g_freopen

#else	/* GLIB_MAJOR_VERSION */

/* GLib 2.4 or below, using "old school" functions */
#ifdef _WIN32
#define eth_open	_open
#define eth_stat	_stat
#define eth_unlink	_unlink
#else
#define eth_open	open
#define eth_stat	stat
#define eth_unlink	unlink
#endif

#include "mkstemp.h"
#define eth_mkstemp mkstemp
#define eth_rename	rename
#define eth_mkdir	mkdir
#define eth_remove	remove
#define eth_fopen	fopen
#define eth_freopen	freopen

#endif	/* GLIB_MAJOR_VERSION */


/* some common differences between UNIX and WIN32 */
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
#endif

#if GLIB_MAJOR_VERSION >= 2
#define ETH_DIR							GDir
#define ETH_DIRENT						const char
#define eth_dir_open					g_dir_open
#define eth_dir_read_name				g_dir_read_name
#define eth_dir_get_name(dirent)		dirent
#define eth_dir_rewind					g_dir_rewind
#define eth_dir_close					g_dir_close
#else
#define ETH_DIR							DIR
#define ETH_DIRENT						struct dirent
#define eth_dir_open(name,flags,error)	opendir(name)
#define eth_dir_read_name				readdir
#define eth_dir_get_name(dirent)		(gchar *)file->d_name
#define eth_dir_rewind					g_dir_rewind
#define eth_dir_close					close_dir
#endif

/* XXX - remove include "dirent.h" */
/* XXX - remove include "direct.h" */
/* XXX - remove include "sys/stat.h" */
/* XXX - remove O_BINARY */

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __FILE_UTIL_H__ */
