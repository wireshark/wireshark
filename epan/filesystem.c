/* filesystem.c
 * Filesystem utility routines
 *
 * $Id: filesystem.c,v 1.1 2000/09/28 03:16:16 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1998 Gerald Combs
 *
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
#include <glib.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#ifndef WIN32
#include <pwd.h>
#endif

#include "filesystem.h"

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
