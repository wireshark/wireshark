/* file_util.c
 *
 * $Id$
 *
 * (Originally part of the Wiretap Library, now part of the Wireshark
 *  utility library)
 * Copyright (c) 1998 by Gilbert Ramirez <gram@alumni.rice.edu>
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
 *
 */

/* file wrapper functions to prevent the file functions from GLib like g_open(),
 * as code compiled with MSVC 7 and above will collide with libs linked with msvcrt.dll (MSVC 6), lib GLib is
 *
 * DO NOT USE THESE FUNCTIONS DIRECTLY, USE ws_open() AND ALIKE FUNCTIONS FROM file_util.h INSTEAD!!!
 *
 * the following code is stripped down code copied from the GLib file glib/gstdio.h
 * stipped down, because this is used on _WIN32 only and we use only wide char functions */

#ifndef _WIN32
#error "This is only for Windows"
#endif

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <windows.h>
#include <errno.h>
#include <wchar.h>
#include <tchar.h>
/*#include <direct.h>*/
#include <io.h>
#include <stdlib.h>

#include "file_util.h"

static gchar *program_path = NULL;
static gchar *system_path = NULL;

/**
 * g_open:
 * @filename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 * @flags: as in open()
 * @mode: as in open()
 *
 * A wrapper for the POSIX open() function. The open() function is
 * used to convert a pathname into a file descriptor. Note that on
 * POSIX systems file descriptors are implemented by the operating
 * system. On Windows, it's the C library that implements open() and
 * file descriptors. The actual Windows API for opening files is
 * something different.
 *
 * See the C library manual for more details about open().
 *
 * Returns: a new file descriptor, or -1 if an error occurred. The
 * return value can be used exactly like the return value from open().
 *
 * Since: 2.6
 */
int
ws_stdio_open (const gchar *filename,
	int          flags,
	int          mode)
{
      wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
      int retval;
      int save_errno;

      if (wfilename == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}

      retval = _wopen (wfilename, flags, mode);
      save_errno = errno;

      g_free (wfilename);

      errno = save_errno;
      return retval;
}


/**
 * g_rename:
 * @oldfilename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 * @newfilename: a pathname in the GLib file name encoding
 *
 * A wrapper for the POSIX rename() function. The rename() function
 * renames a file, moving it between directories if required.
 *
 * See your C library manual for more details about how rename() works
 * on your system. Note in particular that on Win9x it is not possible
 * to rename a file if a file with the new name already exists. Also
 * it is not possible in general on Windows to rename an open file.
 *
 * Returns: 0 if the renaming succeeded, -1 if an error occurred
 *
 * Since: 2.6
 */
int
ws_stdio_rename (const gchar *oldfilename,
	  const gchar *newfilename)
{
      wchar_t *woldfilename = g_utf8_to_utf16 (oldfilename, -1, NULL, NULL, NULL);
      wchar_t *wnewfilename;
      int retval;
      int save_errno = 0;

      if (woldfilename == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}

      wnewfilename = g_utf8_to_utf16 (newfilename, -1, NULL, NULL, NULL);

      if (wnewfilename == NULL)
	{
	  g_free (woldfilename);
	  errno = EINVAL;
	  return -1;
	}

      if (MoveFileExW (woldfilename, wnewfilename, MOVEFILE_REPLACE_EXISTING))
	retval = 0;
      else
	{
	  retval = -1;
	  switch (GetLastError ())
	    {
#define CASE(a,b) case ERROR_##a: save_errno = b; break
	    CASE (FILE_NOT_FOUND, ENOENT);
	    CASE (PATH_NOT_FOUND, ENOENT);
	    CASE (ACCESS_DENIED, EACCES);
	    CASE (NOT_SAME_DEVICE, EXDEV);
	    CASE (LOCK_VIOLATION, EACCES);
	    CASE (SHARING_VIOLATION, EACCES);
	    CASE (FILE_EXISTS, EEXIST);
	    CASE (ALREADY_EXISTS, EEXIST);
#undef CASE
	    default: save_errno = EIO;
	    }
	}

      g_free (woldfilename);
      g_free (wnewfilename);

      errno = save_errno;
      return retval;
}

/**
 * g_mkdir:
 * @filename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 * @mode: permissions to use for the newly created directory
 *
 * A wrapper for the POSIX mkdir() function. The mkdir() function
 * attempts to create a directory with the given name and permissions.
 *
 * See the C library manual for more details about mkdir().
 *
 * Returns: 0 if the directory was successfully created, -1 if an error
 *    occurred
 *
 * Since: 2.6
 */
int
ws_stdio_mkdir (const gchar *filename,
	 int          mode)
{
      wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
      int retval;
      int save_errno;

      if (wfilename == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}

      retval = _wmkdir (wfilename);
      save_errno = errno;

      g_free (wfilename);

      errno = save_errno;
      return retval;
}

/**
 * g_stat:
 * @filename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 * @buf: a pointer to a <structname>stat</structname> struct, which
 *    will be filled with the file information
 *
 * A wrapper for the POSIX stat() function. The stat() function
 * returns information about a file.
 *
 * See the C library manual for more details about stat().
 *
 * Returns: 0 if the information was successfully retrieved, -1 if an error
 *    occurred
 *
 * Since: 2.6
 */
int
ws_stdio_stat64 (const gchar *filename,
	ws_statb64 *buf)
{
      wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
      int retval;
      int save_errno;
      size_t len;

      if (wfilename == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}

      len = wcslen (wfilename);
      while (len > 0 && G_IS_DIR_SEPARATOR (wfilename[len-1]))
	len--;
      if (len > 0 &&
	  (!g_path_is_absolute (filename) || len > (size_t) (g_path_skip_root (filename) - filename)))
	wfilename[len] = '\0';

      retval = _wstati64 (wfilename, buf);
      save_errno = errno;

      g_free (wfilename);

      errno = save_errno;
      return retval;
}
/**
 * g_unlink:
 * @filename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 *
 * A wrapper for the POSIX unlink() function. The unlink() function
 * deletes a name from the filesystem. If this was the last link to the
 * file and no processes have it opened, the diskspace occupied by the
 * file is freed.
 *
 * See your C library manual for more details about unlink(). Note
 * that on Windows, it is in general not possible to delete files that
 * are open to some process, or mapped into memory.
 *
 * Returns: 0 if the name was successfully deleted, -1 if an error
 *    occurred
 *
 * Since: 2.6
 */

int
ws_stdio_unlink (const gchar *filename)
{
      wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
      int retval;
      int save_errno;

      if (wfilename == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}

      retval = _wunlink (wfilename);
      save_errno = errno;

      g_free (wfilename);

      errno = save_errno;
      return retval;
}

/**
 * g_remove:
 * @filename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 *
 * A wrapper for the POSIX remove() function. The remove() function
 * deletes a name from the filesystem.
 *
 * See your C library manual for more details about how remove() works
 * on your system. On Unix, remove() removes also directories, as it
 * calls unlink() for files and rmdir() for directories. On Windows,
 * although remove() in the C library only works for files, this
 * function tries first remove() and then if that fails rmdir(), and
 * thus works for both files and directories. Note however, that on
 * Windows, it is in general not possible to remove a file that is
 * open to some process, or mapped into memory.
 *
 * If this function fails on Windows you can't infer too much from the
 * errno value. rmdir() is tried regardless of what caused remove() to
 * fail. Any errno value set by remove() will be overwritten by that
 * set by rmdir().
 *
 * Returns: 0 if the file was successfully removed, -1 if an error
 *    occurred
 *
 * Since: 2.6
 */
int
ws_stdio_remove (const gchar *filename)
{
      wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
      int retval;
      int save_errno;

      if (wfilename == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}

      retval = _wremove (wfilename);
      if (retval == -1)
	retval = _wrmdir (wfilename);
      save_errno = errno;

      g_free (wfilename);

      errno = save_errno;
      return retval;
}

/**
 * g_fopen:
 * @filename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 * @mode: a string describing the mode in which the file should be
 *   opened
 *
 * A wrapper for the POSIX fopen() function. The fopen() function opens
 * a file and associates a new stream with it.
 *
 * See the C library manual for more details about fopen().
 *
 * Returns: A <type>FILE</type> pointer if the file was successfully
 *    opened, or %NULL if an error occurred
 *
 * Since: 2.6
 */
FILE *
ws_stdio_fopen (const gchar *filename,
	 const gchar *mode)
{
      wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
      wchar_t *wmode;
      FILE *retval;
      int save_errno;

      if (wfilename == NULL)
	{
	  errno = EINVAL;
	  return NULL;
	}

      wmode = g_utf8_to_utf16 (mode, -1, NULL, NULL, NULL);

      if (wmode == NULL)
	{
	  g_free (wfilename);
	  errno = EINVAL;
	  return NULL;
	}

      retval = _wfopen (wfilename, wmode);
      save_errno = errno;

      g_free (wfilename);
      g_free (wmode);

      errno = save_errno;
      return retval;
}

/**
 * g_freopen:
 * @filename: a pathname in the GLib file name encoding (UTF-8 on Windows)
 * @mode: a string describing the mode in which the file should be
 *   opened
 * @stream: an existing stream which will be reused, or %NULL
 *
 * A wrapper for the POSIX freopen() function. The freopen() function
 * opens a file and associates it with an existing stream.
 *
 * See the C library manual for more details about freopen().
 *
 * Returns: A <type>FILE</type> pointer if the file was successfully
 *    opened, or %NULL if an error occurred.
 *
 * Since: 2.6
 */
FILE *
ws_stdio_freopen (const gchar *filename,
	   const gchar *mode,
	   FILE        *stream)
{
      wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
      wchar_t *wmode;
      FILE *retval;
      int save_errno;

      if (wfilename == NULL)
	{
	  errno = EINVAL;
	  return NULL;
	}

      wmode = g_utf8_to_utf16 (mode, -1, NULL, NULL, NULL);

      if (wmode == NULL)
	{
	  g_free (wfilename);
	  errno = EINVAL;
	  return NULL;
	}

      retval = _wfreopen (wfilename, wmode, stream);
      save_errno = errno;

      g_free (wfilename);
      g_free (wmode);

      errno = save_errno;
      return retval;
}


/* DLL loading */
static gboolean
init_dll_load_paths()
{
      TCHAR path_w[MAX_PATH];

      if (program_path && system_path)
	    return TRUE;

      /* XXX - Duplicate code in filesystem.c:init_progfile_dir */
      if (GetModuleFileName(NULL, path_w, MAX_PATH) == 0 || GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
	    return FALSE;
      }

      if (!program_path) {
	    gchar *app_path;
	    app_path = g_utf16_to_utf8(path_w, -1, NULL, NULL, NULL);
	    /* We could use PathRemoveFileSpec here but we'd have to link to Shlwapi.dll */
	    program_path = g_path_get_dirname(app_path);
	    g_free(app_path);
      }

      if (GetSystemDirectory(path_w, MAX_PATH) == 0) {
	    return FALSE;
      }

      if (!system_path) {
	    system_path = g_utf16_to_utf8(path_w, -1, NULL, NULL, NULL);
      }

      if (program_path && system_path)
	    return TRUE;

      return FALSE;
}

gboolean
ws_init_dll_search_path()
{
      gboolean dll_dir_set = FALSE;
      wchar_t *program_path_w;

      typedef BOOL (WINAPI *SetDllDirectoryHandler)(LPCTSTR);
      SetDllDirectoryHandler PSetDllDirectory;

      PSetDllDirectory = (SetDllDirectoryHandler) GetProcAddress(GetModuleHandle(_T("kernel32.dll")), "SetDllDirectoryW");
      if (PSetDllDirectory) {
	    dll_dir_set = PSetDllDirectory(_T(""));
      }

      if (!dll_dir_set && init_dll_load_paths()) {
	    program_path_w = g_utf8_to_utf16(program_path, -1, NULL, NULL, NULL);
	    SetCurrentDirectory(program_path_w);
	    g_free(program_path_w);
      }

      return dll_dir_set;
}

/*
 * Internally g_module_open uses LoadLibrary on Windows and returns an
 * HMODULE cast to a GModule *. However there's no guarantee that this
 * will always be the case, so we call LoadLibrary and g_module_open
 * separately.
 */

void *
ws_load_library(gchar *library_name)
{
      gchar   *full_path;
      wchar_t *full_path_w;
      HMODULE  dll_h;

      if (!init_dll_load_paths() || !library_name)
	    return NULL;

      /* First try the program directory */
      full_path = g_module_build_path(program_path, library_name);
      full_path_w = g_utf8_to_utf16(full_path, -1, NULL, NULL, NULL);

      if (full_path && full_path_w) {
	    dll_h = LoadLibraryW(full_path_w);
	    if (dll_h) {
		  g_free(full_path);
		  g_free(full_path_w);
		  return dll_h;
	    }
      }

      /* Next try the system directory */
      full_path = g_module_build_path(system_path, library_name);
      full_path_w = g_utf8_to_utf16(full_path, -1, NULL, NULL, NULL);

      if (full_path && full_path_w) {
	    dll_h = LoadLibraryW(full_path_w);
	    if (dll_h) {
		  g_free(full_path);
		  g_free(full_path_w);
		  return dll_h;
	    }
      }

      return NULL;
}

GModule *
ws_module_open(gchar *module_name, GModuleFlags flags)
{
      gchar   *full_path;
      GModule *mod;

      if (!init_dll_load_paths() || !module_name)
	    return NULL;

      /* First try the program directory */
      full_path = g_module_build_path(program_path, module_name);

      if (full_path) {
	    mod = g_module_open(full_path, flags);
	    if (mod) {
		  g_free(full_path);
		  return mod;
	    }
      }

      /* Next try the system directory */
      full_path = g_module_build_path(system_path, module_name);

      if (full_path) {
	    mod = g_module_open(full_path, flags);
	    if (mod) {
		  g_free(full_path);
		  return mod;
	    }
      }

      return NULL;
}

/* utf8 version of getenv, needed to get win32 filename paths */
char *
getenv_utf8(const char *varname)
{
	char *envvar;
	wchar_t *envvarw;
	wchar_t *varnamew;

	envvar = getenv(varname);

	/* since GLib 2.6 we need an utf8 version of the filename */
	/* using the wide char version of getenv should work under all circumstances */

	/* convert given varname to utf16, needed by _wgetenv */
	varnamew = g_utf8_to_utf16(varname, -1, NULL, NULL, NULL);
	if (varnamew == NULL) {
		return envvar;
	}

	/* use wide char version of getenv */
	envvarw = _wgetenv(varnamew);
	g_free(varnamew);
	if (envvarw == NULL) {
		return envvar;
	}

	/* convert value to utf8 */
	envvar = g_utf16_to_utf8(envvarw, -1, NULL, NULL, NULL);
	/* XXX - memleak */

	return envvar;
}
