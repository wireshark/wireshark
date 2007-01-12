/* file_util.c
 *
 * $Id$
 *
 * Wiretap Library
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
 * DO NOT USE THESE FUNCTIONS DIRECTLY, USE eth_open() AND ALIKE FUNCTIONS FROM file_util.h INSTEAD!!!
 *
 * the following code is stripped down code copied from the GLib file glib/gstdio.h 
 * stipped down, because this is used on _WIN32 only and we use only wide char functions */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#ifdef _WIN32
#include <windows.h>
#include <errno.h>
#include <wchar.h>
/*#include <direct.h>*/
#include <io.h>
#endif

#include "file_util.h"




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
eth_stdio_open (const gchar *filename,
	int          flags,
	int          mode)
{
#ifdef _WIN32
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
#else
  return open (filename, flags, mode);
#endif
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
eth_stdio_rename (const gchar *oldfilename,
	  const gchar *newfilename)
{
#ifdef _WIN32
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
#else
  return rename (oldfilename, newfilename);
#endif
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
eth_stdio_mkdir (const gchar *filename,
	 int          mode)
{
#ifdef _WIN32
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
#else
  return mkdir (filename, mode);
#endif
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
eth_stdio_stat (const gchar *filename,
	struct stat *buf)
{
#ifdef _WIN32
      wchar_t *wfilename = g_utf8_to_utf16 (filename, -1, NULL, NULL, NULL);
      int retval;
      int save_errno;
      int len;

      if (wfilename == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}

      len = wcslen (wfilename);
      while (len > 0 && G_IS_DIR_SEPARATOR (wfilename[len-1]))
	len--;
      if (len > 0 &&
	  (!g_path_is_absolute (filename) || len > g_path_skip_root (filename) - filename))
	wfilename[len] = '\0';

      retval = _wstat (wfilename, (struct _stat *) buf);
      save_errno = errno;

      g_free (wfilename);

      errno = save_errno;
      return retval;
#else
  return stat (filename, buf);
#endif
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
eth_stdio_unlink (const gchar *filename)
{
#ifdef _WIN32
      gchar *cp_filename = g_locale_from_utf8 (filename, -1, NULL, NULL, NULL);
      int retval;
      int save_errno;

      if (cp_filename == NULL)
	{
	  errno = EINVAL;
	  return -1;
	}

      retval = unlink (cp_filename);
      save_errno = errno;

      g_free (cp_filename);

      errno = save_errno;
      return retval;
#else
  return unlink (filename);
#endif
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
eth_stdio_remove (const gchar *filename)
{
#ifdef _WIN32
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
#else
  return remove (filename);
#endif
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
eth_stdio_fopen (const gchar *filename,
	 const gchar *mode)
{
#ifdef _WIN32
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
#else
  return fopen (filename, mode);
#endif
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
eth_stdio_freopen (const gchar *filename,
	   const gchar *mode,
	   FILE        *stream)
{
#ifdef _WIN32
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
#else
  return freopen (filename, mode, stream);
#endif
}

