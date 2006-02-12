/* filesystem.c
 * Filesystem utility routines
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

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_WINDOWS_H
#include <windows.h>
#endif

#ifndef _WIN32
#include <pwd.h>
#endif

#include "filesystem.h"
#include <wiretap/file_util.h>

/*
 * Given a pathname, return a pointer to the last pathname separator
 * character in the pathname, or NULL if the pathname contains no
 * separators.
 */
static char *
find_last_pathname_separator(const char *path)
{
	char *separator;

#ifdef _WIN32
	char c;

	/*
	 * We have to scan for '\' or '/'.
	 * Get to the end of the string.
	 */
	separator = strchr(path, '\0');		/* points to ending '\0' */
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
const char *
get_basename(const char *path)
{
	const char *filename;

	g_assert(path != NULL);
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

	g_assert(path != NULL);
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

	if (eth_stat(path, &statb) < 0)
		return errno;

	if (S_ISDIR(statb.st_mode))
		return EISDIR;
	else
		return 0;
}

int
test_for_fifo(const char *path)
{
	struct stat statb;

	if (eth_stat(path, &statb) < 0)
		return errno;

	if (S_ISFIFO(statb.st_mode))
		return ESPIPE;
	else
		return 0;
}

static char *progfile_dir;

/*
 * Get the pathname of the directory from which the executable came,
 * and save it for future use.
 */
void
init_progfile_dir(const char *arg0
#ifdef _WIN32
	_U_
#endif
)
{
	char *dir_end;
	char *path;
#ifdef _WIN32
	char prog_pathname[_MAX_PATH+2];
	size_t progfile_dir_len;

	/*
	 * Attempt to get the full pathname of the currently running
	 * program.
	 */
	if (GetModuleFileName(NULL, prog_pathname, sizeof prog_pathname) != 0) {
		/*
		 * We got it; strip off the last component, which would be
		 * the file name of the executable, giving us the pathname
		 * of the directory where the executable resies
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
			 * Found it - now figure out how long the program
			 * directory pathname will be.
			 */
			progfile_dir_len = (dir_end - prog_pathname);

			/*
			 * Allocate a buffer for the program directory
			 * pathname, and construct it.
			 */
			path = g_malloc(progfile_dir_len + 1);
			strncpy(path, prog_pathname, progfile_dir_len);
			path[progfile_dir_len] = '\0';
			progfile_dir = path;
		}
	}
#else
	char *prog_pathname;
	char *curdir;
	long path_max;
	char *path_start, *path_end;
	size_t path_component_len;

	/*
	 * Try to figure out the directory in which the currently running
	 * program resides, given the argv[0] it was started with.  That
	 * might be the absolute path of the program, or a path relative
	 * to the current directory of the process that started it, or
	 * just a name for the program if it was started from the command
	 * line and was searched for in $PATH.  It's not guaranteed to be
	 * any of those, however, so there are no guarantees....
	 */
	if (arg0[0] == '/') {
		/*
		 * It's an absolute path.
		 */
		prog_pathname = g_strdup(arg0);
	} else if (strchr(arg0, '/') != NULL) {
		/*
		 * It's a relative path, with a directory in it.
		 * Get the current directory, and combine it
		 * with that directory.
		 */
		path_max = pathconf(".", _PC_PATH_MAX);
		if (path_max == -1) {
			/*
			 * We have no idea how big a buffer to
			 * allocate for the current directory.
			 */
			return;
		}
		curdir = g_malloc(path_max);
		if (getcwd(curdir, sizeof curdir) == NULL) {
			/*
			 * It failed - give up, and just stick
			 * with DATAFILE_DIR.
			 */
			g_free(curdir);
			return;
		}
		path = g_malloc(strlen(curdir) + 1 + strlen(arg0) + 1);
		strcpy(path, curdir);
		strcat(path, "/");
		strcat(path, arg0);
		g_free(curdir);
		prog_pathname = path;
	} else {
		/*
		 * It's just a file name.
		 * Search the path for a file with that name
		 * that's executable.
		 */
		prog_pathname = NULL;	/* haven't found it yet */
		path_start = getenv("PATH");
		while (path_start != NULL) {
			/*
			 * Is there anything left in the path?
			 */
			if (*path_start == '\0')
 				break;	/* no */

			path_end = strchr(path_start, ':');
			if (path_end == NULL)
				path_end = path_start + strlen(path_start);
			path_component_len = path_end - path_start;
			path = g_malloc(path_component_len + 1
			    + strlen(arg0) + 1);
			memcpy(path, path_start, path_component_len);
			path[path_component_len] = '\0';
			strcat(path, "/");
			strcat(path, arg0);
			if (access(path, X_OK) == 0) {
				/*
				 * Found it!
				 */
				prog_pathname = path;
				break;
			}

			/*
			 * That's not it.  If there are more
			 * path components to test, try them.
			 */
			if (*path_end == '\0') {
				/*
				 * There's nothing more to try.
				 */
				break;
			}
			if (*path_start == ':')
				path_start++;
			g_free(path);
		}
	}

	if (prog_pathname != NULL) {
		/*
		 * OK, we have what we think is the pathname
		 * of the program.
		 *
		 * First, find the last "/" in the directory,
		 * as that marks the end of the directory pathname.
		 */
		dir_end = strrchr(prog_pathname, '/');
		if (dir_end != NULL) {
			/*
			 * Found it.  Strip off the last component,
			 * as that's the path of the program.
			 */
			*dir_end = '\0';

			/*
			 * Is there a "/.libs" at the end?
			 */
			dir_end = strrchr(prog_pathname, '/');
			if (dir_end != NULL) {
				if (strcmp(dir_end, "/.libs") == 0) {
					/*
					 * Yup, it's ".libs".
					 * Strip that off; it's an
					 * artifact of libtool.
					 */
					*dir_end = '\0';
				}
			}
						
			/*
			 * OK, we have the path we want.
			 */
			progfile_dir = prog_pathname;
		} else {
			/*
			 * This "shouldn't happen"; we apparently
			 * have no "/" in the pathname.
			 * Just free up prog_pathname.
			 */
			g_free(prog_pathname);
		}
	}
#endif
}

/*
 * Get the directory in which the program resides.
 */
const char *
get_progfile_dir(void)
{
	return progfile_dir;
}

/*
 * Get the directory in which the global configuration and data files are
 * stored.
 *
 * XXX - if we ever make libethereal a real library, used by multiple
 * applications (more than just Tethereal and versions of Ethereal with
 * various UIs), should the configuration files belong to the library
 * (and be shared by all those applications) or to the applications?
 *
 * If they belong to the library, that could be done on UNIX by the
 * configure script, but it's trickier on Windows, as you can't just
 * use the pathname of the executable.
 *
 * If they belong to the application, that could be done on Windows
 * by using the pathname of the executable, but we'd have to have it
 * passed in as an argument, in some call, on UNIX.
 *
 * Note that some of those configuration files might be used by code in
 * libethereal, some of them might be used by dissectors (would they
 * belong to libethereal, the application, or a separate library?),
 * and some of them might be used by other code (the Ethereal preferences
 * file includes resolver preferences that control the behavior of code
 * in libethereal, dissector preferences, and UI preferences, for
 * example).
 */
const char *
get_datafile_dir(void)
{
#ifdef _WIN32
	/*
	 * Do we have the pathname of the program?  If so, assume we're
	 * running an installed version of the program.  If we fail,
	 * we don't change "datafile_dir", and thus end up using the
	 * default.
	 *
	 * XXX - does NSIS put the installation directory into
	 * "\HKEY_LOCAL_MACHINE\SOFTWARE\Ethereal\InstallDir"?
	 * If so, perhaps we should read that from the registry,
	 * instead.
	 */
	if (progfile_dir != NULL)
		return progfile_dir;

	/*
	 * No, we don't.
	 * Fall back on the default installation directory.
	 */
	return "C:\\Program Files\\Ethereal\\";
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
 * there's no "/etc" directory, so we get them from the global
 * configuration and data file directory.
 */
const char *
get_systemfile_dir(void)
{
#ifdef _WIN32
	return get_datafile_dir();
#else
	return "/etc";
#endif
}

/*
 * Name of directory, under the user's home directory, in which
 * personal configuration files are stored.
 */
#ifdef _WIN32
#define PF_DIR "Ethereal"
#else
/*
 * XXX - should this be ".libepan"? For backwards-compatibility, I'll keep
 * it ".ethereal" for now.
 */
#define PF_DIR ".ethereal"
#endif

#ifdef WIN32
/* utf8 version of getenv, needed to get win32 filename paths */
char *getenv_utf8(const char *varname)
{
	char *envvar;
	wchar_t *envvarw;
	wchar_t *varnamew;

	envvar = getenv(varname);

	/* since GLib 2.6 we need an utf8 version of the filename */
#if GLIB_MAJOR_VERSION > 2 || (GLIB_MAJOR_VERSION == 2 && GLIB_MINOR_VERSION >= 6)
	if (!G_WIN32_HAVE_WIDECHAR_API ()) {
		/* Windows OT (9x, ME), convert from current code page to utf8 */
		/* it's the best we can do here ... */
        envvar = g_locale_to_utf8(envvar, -1, NULL, NULL, NULL);
		/* XXX - memleak */
		return envvar;
	}

	/* Windows NT, 2000, XP, ... */
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
#endif

	return envvar;
}
#endif

/*
 * Get the directory in which personal configuration files reside;
 * in UNIX-compatible systems, it's ".ethereal", under the user's home
 * directory, and on Windows systems, it's "Ethereal", under %APPDATA%
 * or, if %APPDATA% isn't set, it's "%USERPROFILE%\Application Data"
 * (which is what %APPDATA% normally is on Windows 2000).
 */
static const char *
get_persconffile_dir(void)
{
#ifdef _WIN32
	char *appdatadir;
	char *userprofiledir;
#else
	const char *homedir;
	struct passwd *pwd;
#endif
	static char *pf_dir = NULL;

	/* Return the cached value, if available */
	if (pf_dir != NULL)
		return pf_dir;

#ifdef _WIN32
	/*
	 * Use %APPDATA% or %USERPROFILE%, so that configuration files are
	 * stored in the user profile, rather than in the home directory.
	 * The Windows convention is to store configuration information
	 * in the user profile, and doing so means you can use
	 * Ethereal even if the home directory is an inaccessible
	 * network drive.
	 */
	appdatadir = getenv_utf8("APPDATA");
	if (appdatadir != NULL) {
		/*
		 * Concatenate %APPDATA% with "\Ethereal".
		 */
		pf_dir = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", 
			appdatadir, PF_DIR);
	} else {
		/*
		 * OK, %APPDATA% wasn't set, so use
		 * %USERPROFILE%\Application Data.
		 */
		userprofiledir = getenv_utf8("USERPROFILE");
		if (userprofiledir != NULL) {
			pf_dir = g_strdup_printf(
			    "%s" G_DIR_SEPARATOR_S "Application Data" G_DIR_SEPARATOR_S "%s",
			    userprofiledir, PF_DIR);
		} else {
			/*
			 * Give up and use "C:".
			 */
			pf_dir = g_strdup_printf("C:" G_DIR_SEPARATOR_S "%s", PF_DIR);
		}
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
	pf_dir = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", homedir, PF_DIR);
#endif

	return pf_dir;
}

/*
 * Create the directory that holds personal configuration files, if
 * necessary.  If we attempted to create it, and failed, return -1 and
 * set "*pf_dir_path_return" to the pathname of the directory we failed
 * to create (it's g_mallocated, so our caller should free it); otherwise,
 * return 0.
 */
int
create_persconffile_dir(char **pf_dir_path_return)
{
	const char *pf_dir_path;
#ifdef _WIN32
	char *pf_dir_path_copy, *pf_dir_parent_path;
	size_t pf_dir_parent_path_len;
#endif
	struct stat s_buf;
	int ret;

	pf_dir_path = get_persconffile_dir();
	if (eth_stat(pf_dir_path, &s_buf) != 0 && errno == ENOENT) {
#ifdef _WIN32
		/*
		 * Does the parent directory of that directory
		 * exist?  %APPDATA% may not exist even though
		 * %USERPROFILE% does.
		 *
		 * We check for the existence of the directory
		 * by first checking whether the parent directory
		 * is just a drive letter and, if it's not, by
		 * doing a "stat()" on it.  If it's a drive letter,
		 * or if the "stat()" succeeds, we assume it exists.
		 */
		pf_dir_path_copy = g_strdup(pf_dir_path);
		pf_dir_parent_path = get_dirname(pf_dir_path_copy);
		pf_dir_parent_path_len = strlen(pf_dir_parent_path);
		if (pf_dir_parent_path_len > 0
		    && pf_dir_parent_path[pf_dir_parent_path_len - 1] != ':'
		    && eth_stat(pf_dir_parent_path, &s_buf) != 0) {
			/*
			 * No, it doesn't exist - make it first.
			 */
			ret = eth_mkdir(pf_dir_parent_path, 0755);
			if (ret == -1) {
				*pf_dir_path_return = pf_dir_parent_path;
				return -1;
			}
		}
		g_free(pf_dir_path_copy);
		ret = eth_mkdir(pf_dir_path, 0755);
#else
		ret = eth_mkdir(pf_dir_path, 0755);
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
		*pf_dir_path_return = g_strdup(pf_dir_path);
	return ret;
}

#ifdef _WIN32
/*
 * Returns the user's home directory on Win32.
 */
static const char *
get_home_dir(void)
{
	static const char *home = NULL;
	char *homedrive, *homepath;
	char *homestring;
	char *lastsep;

	/* Return the cached value, if available */
	if (home)
		return home;

	/*
	 * XXX - should we use USERPROFILE anywhere in this process?
	 * Is there a chance that it might be set but one or more of
	 * HOMEDRIVE or HOMEPATH isn't set?
	 */
	homedrive = getenv_utf8("HOMEDRIVE");
	if (homedrive != NULL) {
		homepath = getenv_utf8("HOMEPATH");
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
		 * Give up and use C:.
		 */
		home = "C:";
	}

	return home;
}
#endif

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
char *
get_persconffile_path(const char *filename, gboolean for_writing
#ifndef _WIN32
	_U_
#endif
)
{
	char *path;
#ifdef _WIN32
	struct stat s_buf;
	char *old_path;
#endif

	path = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", get_persconffile_dir(),
	    filename);
#ifdef _WIN32
	if (!for_writing) {
		if (eth_stat(path, &s_buf) != 0 && errno == ENOENT) {
			/*
			 * OK, it's not in the personal configuration file
			 * directory; is it in the ".ethereal" subdirectory
			 * of their home directory?
			 */
			old_path = g_strdup_printf(
			    "%s" G_DIR_SEPARATOR_S ".ethereal" G_DIR_SEPARATOR_S "%s",
			    get_home_dir(), filename);
			if (eth_stat(old_path, &s_buf) == 0) {
				/*
				 * OK, it exists; return it instead.
				 */
				g_free(path);
				path = old_path;
			}
		}
	}
#endif

	return path;
}

/*
 * Construct the path name of a global configuration file, given the
 * file name.
 */
char *
get_datafile_path(const char *filename)
{

	return g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", get_datafile_dir(),
	    filename);
}

/* Delete a file */
gboolean
deletefile(const char *path)
{
	return eth_unlink(path) == 0;
}

/*
 * Construct and return the path name of a file in the
 * appropriate temporary file directory.
 */
char *get_tempfile_path(const char *filename)
{

	return g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s", g_get_tmp_dir(), filename);
}

/*
 * Return an error message for UNIX-style errno indications on open or
 * create operations.
 */
const char *
file_open_error_message(int err, gboolean for_writing)
{
	const char *errmsg;
	static char errmsg_errno[1024+1];

	switch (err) {

	case ENOENT:
		if (for_writing)
			errmsg = "The path to the file \"%s\" doesn't exist.";
		else
			errmsg = "The file \"%s\" doesn't exist.";
		break;

	case EACCES:
		if (for_writing)
			errmsg = "You don't have permission to create or write to the file \"%s\".";
		else
			errmsg = "You don't have permission to read the file \"%s\".";
		break;

	case EISDIR:
		errmsg = "\"%s\" is a directory (folder), not a file.";
		break;

	case ENOSPC:
		errmsg = "The file \"%s\" could not be created because there is no space left on the file system.";
		break;

#ifdef EDQUOT
	case EDQUOT:
		errmsg = "The file \"%s\" could not be created because you are too close to, or over, your disk quota.";
		break;
#endif

	default:
		g_snprintf(errmsg_errno, sizeof(errmsg_errno),
				"The file \"%%s\" could not be %s: %s.",
				for_writing ? "created" : "opened",
				strerror(err));
		errmsg = errmsg_errno;
		break;
	}
	return errmsg;
}

/*
 * Return an error message for UNIX-style errno indications on write
 * operations.
 */
const char *
file_write_error_message(int err)
{
	const char *errmsg;
	static char errmsg_errno[1024+1];

	switch (err) {

	case ENOSPC:
		errmsg = "The file \"%s\" could not be saved because there is no space left on the file system.";
		break;

#ifdef EDQUOT
	case EDQUOT:
		errmsg = "The file \"%s\" could not be saved because you are too close to, or over, your disk quota.";
		break;
#endif

	default:
		g_snprintf(errmsg_errno, sizeof(errmsg_errno),
		    "An error occurred while writing to the file \"%%s\": %s.",
		    strerror(err));
		errmsg = errmsg_errno;
		break;
	}
	return errmsg;
}


gboolean
file_exists(const char *fname)
{
  struct stat   file_stat;


#ifdef _WIN32
  /*
   * This is a bit tricky on win32. The st_ino field is documented as:
   * "The inode, and therefore st_ino, has no meaning in the FAT, ..."
   * but it *is* set to zero if stat() returns without an error,
   * so this is working, but maybe not quite the way expected. ULFL
   */
   file_stat.st_ino = 1;   /* this will make things work if an error occured */
   eth_stat(fname, &file_stat);
   if (file_stat.st_ino == 0) {
       return TRUE;
   } else {
       return FALSE;
   }
#else
   if (eth_stat(fname, &file_stat) != 0 && errno == ENOENT) {
       return FALSE;
   } else {
       return TRUE;
   }
#endif
   
}

/*
 * Check that the from file is not the same as to file
 * We do it here so we catch all cases ...
 * Unfortunately, the file requester gives us an absolute file
 * name and the read file name may be relative (if supplied on
 * the command line), so we can't just compare paths. From Joerg Mayer.
 */
gboolean
files_identical(const char *fname1, const char *fname2)
{
    /* Two different implementations, because:
     *
     * - _fullpath is not available on UN*X, so we can't get full
     *   paths and compare them (which wouldn't work with hard links
     *   in any case);
     *
     * - st_ino isn't filled in with a meaningful value on Windows.
     */
#ifdef _WIN32
    char full1[MAX_PATH], full2[MAX_PATH];

    /*
     * Get the absolute full paths of the file and compare them.
     * That won't work if you have hard links, but those aren't
     * much used on Windows, even though NTFS supports them.
     *
     * XXX - will _fullpath work with UNC?
     */
    if( _fullpath( full1, fname1, MAX_PATH ) == NULL ) {
        return FALSE;
    }

    if( _fullpath( full2, fname2, MAX_PATH ) == NULL ) {
        return FALSE;
    }
    
    if(strcmp(full1, full2) == 0) {
        return TRUE;
    } else {
        return FALSE;
    }
#else
  struct stat   filestat1, filestat2;

   /*
    * Compare st_dev and st_ino.
    */
   if (eth_stat(fname1, &filestat1) == -1)
       return FALSE;	/* can't get info about the first file */
   if (eth_stat(fname2, &filestat2) == -1)
       return FALSE;	/* can't get info about the second file */
   return (filestat1.st_dev == filestat2.st_dev &&
           filestat1.st_ino == filestat2.st_ino);
#endif
}

