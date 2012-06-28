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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef FILESYSTEM_H
#define FILESYSTEM_H

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/*
 * Default profile name.
 */
#define DEFAULT_PROFILE      "Default"


/*
 * Get the pathname of the directory from which the executable came,
 * and save it for future use.  Returns NULL on success, and a
 * g_mallocated string containing an error on failure.
 */
extern char *init_progfile_dir(const char *arg0, int (*main)(int, char **));

/*
 * Get the directory in which the program resides.
 */
extern const char *get_progfile_dir(void);

/*
 * Get the directory in which plugins are stored; this must not be called
 * before init_progfile_dir() is called, as they might be stored in a
 * subdirectory of the program file directory.
 */
extern const char *get_plugin_dir(void);

/*
 * Get the directory in which python plugins are stored; this must not be
 * called before init_progfile_dir() is called, as they might be stored in a
 * subdirectory of the program file directory.
 */
extern const char *get_wspython_dir(void);

/*
 * Get the flag indicating whether we're running from a build
 * directory.
 */
extern gboolean running_in_build_directory(void);

/*
 * Get the directory in which global configuration files are
 * stored.
 */
extern const char *get_datafile_dir(void);

/*
 * Construct the path name of a global configuration file, given the
 * file name.
 *
 * The returned file name was g_malloc()'d so it must be g_free()d when the
 * caller is done with it.
 */
extern char *get_datafile_path(const char *filename);

/*
 * Get the personal plugin dir.
 */
extern char *get_plugins_pers_dir(void);

/*
 * Get the directory in which files that, at least on UNIX, are
 * system files (such as "/etc/ethers") are stored; on Windows,
 * there's no "/etc" directory, so we get them from the Wireshark
 * global configuration and data file directory.
 */
extern const char *get_systemfile_dir(void);

/*
 * Set the configuration profile name to be used for storing
 * personal configuration files.
 */
extern void set_profile_name(const gchar *profilename);

/*
 * Get the current configuration profile name used for storing
 * personal configuration files.
 */
extern const char *get_profile_name(void);

/*
 * Check if current profile is default profile.
 */
extern gboolean is_default_profile(void);

/*
 * Check if we have global profiles.
 */
extern gboolean has_global_profiles(void);

/*
 * Get the directory used to store configuration profile directories.
 */
extern const char *get_profiles_dir(void);

/*
 * Get the directory used to store global configuration profile directories.
 */
extern const char *get_global_profiles_dir(void);


/*
 * Store filenames used for personal config files so we know which
 * files to copy when duplicate a configuration profile.
 */
extern void profile_store_persconffiles(gboolean store);

/*
 * Check if given configuration profile exists.
 */
extern gboolean profile_exists(const gchar *profilename, gboolean global);

/*
 * Create a directory for the given configuration profile.
 * If we attempted to create it, and failed, return -1 and
 * set "*pf_dir_path_return" to the pathname of the directory we failed
 * to create (it's g_mallocated, so our caller should free it); otherwise,
 * return 0.
 */
extern int create_persconffile_profile(const char *profilename,
				       char **pf_dir_path_return);

/*
 * Delete the directory for the given configuration profile.
 * If we attempted to delete it, and failed, return -1 and
 * set "*pf_dir_path_return" to the pathname of the directory we failed
 * to delete (it's g_mallocated, so our caller should free it); otherwise,
 * return 0.
 */
extern int delete_persconffile_profile(const char *profilename,
				       char **pf_dir_path_return);

/*
 * Rename the directory for the given confinguration profile.
 */
extern int rename_persconffile_profile(const char *fromname, const char *toname,
				       char **pf_from_dir_path_return,
				       char **pf_to_dir_path_return);

/*
 * Copy files in one profile to the other.
 */
extern int copy_persconffile_profile(const char *toname, const char *fromname,
				     gboolean from_global,
				     char **pf_filename_return,
				     char **pf_to_dir_path_return,
				     char **pf_from_dir_path_return);

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
 * file name.  If using configuration profiles this directory will be
 * used if "from_profile" is TRUE.
 *
 * On Win32, if "for_writing" is FALSE, we check whether the file exists
 * and, if not, construct a path name relative to the ".wireshark"
 * subdirectory of the user's home directory, and check whether that
 * exists; if it does, we return that, so that configuration files
 * from earlier versions can be read.
 *
 * The returned file name was g_malloc()'d so it must be g_free()d when the
 * caller is done with it.
 */
extern char *get_persconffile_path(const char *filename, gboolean from_profile,
				   gboolean for_writing);

/*
 * Get the (default) directory in which personal data is stored.
 *
 * On Win32, this is the "My Documents" folder in the personal profile.
 * On UNIX this is simply the current directory.
 */
extern const char *get_persdatafile_dir(void);

/*
 * Construct the path name of a file in $TMP/%TEMP% directory.
 * Or "/tmp/<filename>" (C:\<filename>) if that fails.
 *
 * Return value is g_malloced so the caller should g_free it.
 */
extern char *get_tempfile_path(const char *filename);

/*
 * process command line option belonging to the filesystem settings
 */
extern int filesystem_opt(int opt, const char *optstr);

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
 * Given a pathname, return the last component.
 */
extern const char *get_basename(const char *);

 /*
  * Given a pathname, return a pointer to the last pathname separator
  * character in the pathname, or NULL if the pathname contains no
  * separators.
  */
extern char *find_last_pathname_separator(const char *path);

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

/* Delete a file */
extern gboolean deletefile (const char *path);

/*
 * Check, if file is existing.
 */
extern gboolean file_exists(const char *fname);

/*
 * Check if two filenames are identical (with absolute and relative paths).
 */
extern gboolean files_identical(const char *fname1, const char *fname2);

/*
 * Copy a file in binary mode, for those operating systems that care about
 * such things.  This should be OK for all files, even text files, as
 * we'll copy the raw bytes, and we don't look at the bytes as we copy
 * them.
 *
 * Returns TRUE on success, FALSE on failure. If a failure, it also
 * displays a simple dialog window with the error message.
 */
extern gboolean copy_file_binary_mode(const char *from_filename,
    const char *to_filename);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* FILESYSTEM_H */
