/* filesystem.c
 * Filesystem utility routines
 *
 * $Id: filesystem.c,v 1.5 2001/08/21 06:39:16 guy Exp $
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
 * Get the directory in which global configuration and data files are
 * stored.
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
#else
	/*
	 * Just use DATAFILE_DIR, as that's what the configure script
	 * set it to be.
	 */
	return DATAFILE_DIR;
#endif
}

/* Returns the user's home directory, via the HOME environment
 * variable, or a default directory if HOME is not set */
const char*
get_home_dir(void)
{
	static const char *home = NULL;
#ifdef WIN32
	char *homedrive, *homepath;
	char *homestring;
	char *lastsep;
#else
	struct passwd *pwd;
#endif

	/* Return the cached value, if available */
	if (home)
		return home;
#ifdef WIN32
	/*
	 * XXX - should we use USERPROFILE anywhere in this process?
	 * Is there a chance that it might be set but one or more of
	 * HOMEDRIVE or HOMEPATH isn't set?
	 */
	homedrive = getenv("HOMEDRIVE");
	if (homedrive != NULL) {
		homepath = getenv("HOMEPATH");
		if (homepath != NULL) {
			/*
			 * This is cached, so we don't need to worry about
			 * allocating multiple ones of them.
			 */
			homestring =
			    g_malloc(strlen(homedrive) + strlen(homepath) + 1);
			strcpy(homestring, homedrive);
			strcat(homestring, homepath);

			/*
			 * Trim off any trailing slash or backslash.
			 */
			lastsep = find_last_pathname_separator(homestring);
			if (lastsep != NULL && *(lastsep + 1) == '\0') {
				/*
				 * Last separator is the last character
				 * in the string.  Nuke it.
				 */
				*lastsep = '\0';
			}
			home = homestring;
		} else
			home = homedrive;
	} else {
		/*
		 * Try using "windir?
		 */
		home = "C:";
	}
#else
	home = getenv("HOME");
	if (home == NULL) {
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
			home = g_strdup(pwd->pw_dir);
		} else
			home = "/tmp";
	}
#endif

	return home;
}
