/* filesystem.c
 * Filesystem utility routines
 *
 * $Id: filesystem.c,v 1.12 2001/10/23 08:15:11 guy Exp $
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>		/* to declare "mkdir()" on Windows */
#endif

#ifndef WIN32
#include <pwd.h>
#endif

#include "filesystem.h"

/*
 * Given a pathname, return a pointer to the last pathname separator
 * character in the pathname, or NULL if the pathname contains no
 * separators.
 */
char *
find_last_pathname_separator(char *path)
{
	char *separator;

#ifdef WIN32
	char c;

	/*
	 * We have to scan for '\' or '/'.
	 * Get to the end of the string.
	 */
	separator = path + strlen(path);	/* points to ending '\0' */
	while (separator > path) {
		c = *--separator;
		if (c == '\\' || c == '/')
			return separator;	/* found it */
	}

	/*
	 * OK, we didn't find any, so no directories - but there might
	 * be a drive letter....
	 */
	return strchr(path, ':');
#else
	separator = strrchr(path, '/');
#endif
	return separator;
}

/*
 * Given a pathname, return the last component.
 */
char *
get_basename(char *path)
{
	char *filename;

	filename = find_last_pathname_separator(path);
	if (filename == NULL) {
		/*
		 * There're no directories, drive letters, etc. in the
		 * name; the pathname *is* the file name.
		 */
		filename = path;
	} else {
		/*
		 * Skip past the pathname or drive letter separator.
		 */
		filename++;
	}
	return filename;
}

/*
 * Given a pathname, return a string containing everything but the
 * last component.  NOTE: this overwrites the pathname handed into
 * it....
 */
char *
get_dirname(char *path)
{
	char *separator;

	separator = find_last_pathname_separator(path);
	if (separator == NULL) {
		/*
		 * There're no directories, drive letters, etc. in the
		 * name; there is no directory path to return.
		 */
		return NULL;
	}

	/*
	 * Get rid of the last pathname separator and the final file
	 * name following it.
	 */
	*separator = '\0';

	/*
	 * "path" now contains the pathname of the directory containing
	 * the file/directory to which it referred.
	 */
	return path;
}

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
#define S_IFIFO	_S_IFIFO
#endif
#ifndef S_ISFIFO
#define S_ISFIFO(mode)  (((mode) & S_IFMT) == S_IFIFO)
#endif
#ifndef S_ISDIR
#define S_ISDIR(mode)   (((mode) & S_IFMT) == S_IFDIR)
#endif

int
test_for_directory(const char *path)
{
	struct stat statb;

	if (stat(path, &statb) < 0)
		return errno;

	if (S_ISDIR(statb.st_mode))
		return EISDIR;
	else
		return 0;
}

/*
 * Get the directory in which Ethereal's global configuration and data
 * files are stored.
 */
const char *
get_datafile_dir(void)
{
#ifdef WIN32
	char prog_pathname[_MAX_PATH+2];
	char *dir_end;
	size_t datafile_dir_len;
	static char *datafile_dir;

	/*
	 * Have we already gotten the pathname?
	 * If so, just return it.
	 */
	if (datafile_dir != NULL)
		return datafile_dir;

	/*
	 * No, we haven't.
	 * Start out by assuming it's the default installation directory.
	 */
	datafile_dir = "C:\\Program Files\\Ethereal\\";

	/*
	 * Now we attempt to get the full pathname of the currently running
	 * program, under the assumption that we're running an installed
	 * version of the program.  If we fail, we don't change "datafile_dir",
	 * and thus end up using DATAFILE_DIR.
	 *
	 * XXX - does NSIS put the installation directory into
	 * "\HKEY_LOCAL_MACHINE\SOFTWARE\Ethereal\InstallDir"?
	 * If so, perhaps we should read that from the registry,
	 * instead.
	 */
	if (GetModuleFileName(NULL, prog_pathname, sizeof prog_pathname) != 0) {
		/*
		 * If the program is an installed version, the full pathname
		 * includes the pathname of the directory in which it was
		 * installed; get that directory's pathname, and construct
		 * from it the pathname of the directory in which the
		 * plugins were installed.
		 *
		 * First, find the last "\\" in the directory, as that
		 * marks the end of the directory pathname.
		 *
		 * XXX - Can the pathname be something such as
		 * "C:ethereal.exe"?  Or is it always a full pathname
		 * beginning with "\\" after the drive letter?
		 */
		dir_end = strrchr(prog_pathname, '\\');
		if (dir_end != NULL) {
			/*
			 * Found it - now figure out how long the datafile
			 * directory pathname will be.
			 */
			datafile_dir_len = (dir_end - prog_pathname);

			/*
			 * Allocate a buffer for the plugin directory
			 * pathname, and construct it.
			 */
			datafile_dir = g_malloc(datafile_dir_len + 1);
			strncpy(datafile_dir, prog_pathname, datafile_dir_len);
			datafile_dir[datafile_dir_len] = '\0';
		}
	}
	return datafile_dir;
#else
	/*
	 * Just use DATAFILE_DIR, as that's what the configure script
	 * set it to be.
	 */
	return DATAFILE_DIR;
#endif
}

/*
 * Get the directory in which files that, at least on UNIX, are
 * system files (such as "/etc/ethers") are stored; on Windows,
 * there's no "/etc" directory, so we get them from the Ethereal
 * global configuration and data file directory.
 */
const char *
get_systemfile_dir(void)
{
#ifdef WIN32
	return get_datafile_dir();
#else
	return "/etc";
#endif
}

/*
 * Name of directory, under the user's home directory, in which
 * personal configuration files are stored.
 *
 * XXX - should this be ".libepan"? For backwards-compatibility, I'll keep
 * it ".ethereal" for now.
 */
#define PF_DIR ".ethereal"

/*
 * Get the directory in which personal configuration files reside;
 * it's PF_DIR, under the user's home directory.
 */
const char *
get_persconffile_dir(void)
{
#ifndef WIN32
	struct passwd *pwd;
#endif
	char *homedir;
	static char *pf_dir = NULL;

	/* Return the cached value, if available */
	if (pf_dir != NULL)
		return pf_dir;

#ifdef WIN32
	/*
	 * Use %USERPROFILE%, so that configuration files are stored
	 * in the user profile, rather than in the home directory.
	 * The Windows convention is to store configuration information
	 * in the user profile, and doing so means you can use
	 * Ethereal even if the home directory is an inaccessible
	 * network drive.
	 */
	homedir = getenv("USERPROFILE");
	if (homedir == NULL) {
		/*
		 * Give up and use "C:".
		 */
		homedir = "C:";
	}
#else
	/*
	 * If $HOME is set, use that.
	 */
	homedir = getenv("HOME");
	if (homedir == NULL) {
		/*
		 * Get their home directory from the password file.
		 * If we can't even find a password file entry for them,
		 * use "/tmp".
		 */
		pwd = getpwuid(getuid());
		if (pwd != NULL) {
			/*
			 * This is cached, so we don't need to worry
			 * about allocating multiple ones of them.
			 */
			homedir = g_strdup(pwd->pw_dir);
		} else
			homedir = "/tmp";
	}
#endif

	pf_dir = g_malloc(strlen(homedir) + strlen(PF_DIR) + 2);
	sprintf(pf_dir, "%s" G_DIR_SEPARATOR_S "%s", homedir, PF_DIR);
	return pf_dir;
}

/*
 * Create the directory that holds personal configuration files, if
 * necessary.  If we attempted to create it, and failed, return -1 and
 * set "*pf_dir_path_return" to the pathname of the directory; otherwise,
 * return 0.
 */
int
create_persconffile_dir(const char **pf_dir_path_return)
{
	const char *pf_dir_path;
	struct stat s_buf;
	int ret;

	pf_dir_path = get_persconffile_dir();
	if (stat(pf_dir_path, &s_buf) != 0) {
#ifdef WIN32
		ret = mkdir(pf_dir_path);
#else
		ret = mkdir(pf_dir_path, 0755);
#endif
	} else {
		/*
		 * Something with that pathname exists; if it's not
		 * a directory, we'll get an error if we try to put
		 * something in it, so we don't fail here, we wait
		 * for that attempt fo fail.
		 */
		ret = 0;
	}
	if (ret == -1)
		*pf_dir_path_return = pf_dir_path;
	return ret;
}
