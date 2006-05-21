/* filesystem.h
 * Filesystem utility definitions
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

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

/*
 * Given a pathname, return the last component.
 */
extern const char *get_basename(const char *);

/*
 * Given a pathname, return a string containing everything but the
 * last component.  NOTE: this overwrites the pathname handed into
 * it....
 */
extern char *get_dirname(char *);

/*
 * Given a pathname, return:
 *
 *	the errno, if an attempt to "stat()" the file fails;
 *
 *	EISDIR, if the attempt succeeded and the file turned out
 *	to be a directory;
 *
 *	0, if the attempt succeeded and the file turned out not
 *	to be a directory.
 */
extern int test_for_directory(const char *);

/*
 * Given a pathname, return:
 *
 *	the errno, if an attempt to "stat()" the file fails;
 *
 *	ESPIPE, if the attempt succeeded and the file turned out
 *	to be a FIFO;
 *
 *	0, if the attempt succeeded and the file turned out not
 *	to be a FIFO.
 */
extern int test_for_fifo(const char *);

/*
 * Get the pathname of the directory from which the executable came,
 * and save it for future use.  Returns NULL on success, and a
 * g_mallocated string containing an error on failure.
 */
extern char *init_progfile_dir(const char *arg0);

/*
 * Get the directory in which the program resides.
 */
extern const char *get_progfile_dir(void);

/*
 * Get the directory in which global configuration and data files are
 * stored.
 */
extern const char *get_datafile_dir(void);

/*
 * Construct the path name of a global configuration file, given the
 * file name.
 */
extern char *get_datafile_path(const char *filename);

/*
 * Get the directory in which files that, at least on UNIX, are
 * system files (such as "/etc/ethers") are stored; on Windows,
 * there's no "/etc" directory, so we get them from the Ethereal
 * global configuration and data file directory.
 */
extern const char *get_systemfile_dir(void);

/*
 * Create the directory that holds personal configuration files, if
 * necessary.  If we attempted to create it, and failed, return -1 and
 * set "*pf_dir_path_return" to the pathname of the directory we failed
 * to create (it's g_mallocated, so our caller should free it); otherwise,
 * return 0.
 */
extern int create_persconffile_dir(char **pf_dir_path_return);

/*
 * Construct the path name of a personal configuration file, given the
 * file name.
 *
 * On Win32, if "for_writing" is FALSE, we check whether the file exists
 * and, if not, construct a path name relative to the ".ethereal"
 * subdirectory of the user's home directory, and check whether that
 * exists; if it does, we return that, so that configuration files
 * from earlier versions can be read.
 */
extern char *get_persconffile_path(const char *filename, gboolean for_writing);

/*
 * Construct the path name of a file in $TMP/%TEMP% directory.
 * Or "/tmp/<filename>" (C:\<filename>) if that fails.
 *
 * Return value is malloced so the caller should free it.
 */
extern char *get_tempfile_path(const char *filename);

/* Delete a file */
extern gboolean deletefile (const char *path);

/*
 * Return an error message for UNIX-style errno indications on open or
 * create operations.
 */
extern const char *file_open_error_message(int err, gboolean for_writing);

/*
 * Return an error message for UNIX-style errno indications on write
 * operations.
 */
extern const char *file_write_error_message(int err);

/*
 * Check, if file is existing.
 */
extern gboolean file_exists(const char *fname);

/*
 * Check, if two filenames are identical (with absolute and relative paths).
 */
extern gboolean files_identical(const char *fname1, const char *fname2);

#ifdef WIN32
/*
 * utf8 version of getenv, needed to get win32 filename paths
 */
extern char *getenv_utf8(const char *varname);
#endif

#endif /* FILESYSTEM_H */
