/* wtap.h
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
* Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/


#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>
#include <gmodule.h>

/* Why do we check for these symbols here?   we do not include any real
   config.h   so these symbols will never be true.
*/
#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

/* Since config.h is broken */
#if GLIB_MAJOR_VERSION < 2
#ifndef DIR
#include <dirent.h>
#endif
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "wtap.h"
#include "file_util.h"

#define PLUGINS_DIR_NAME	"wiretap_plugins"

static gboolean plugins_loaded = FALSE;

void wtap_load_plugins(char* dirname) {

#define FILENAME_LEN	1024

		ETH_DIR       *dir;             /* scanned directory */
		ETH_DIRENT    *file;            /* current file */
		const char    *name;
#if GLIB_MAJOR_VERSION < 2
		gchar         *hack_path;       /* pathname used to construct lt_lib_ext */
		gchar         *lt_lib_ext;      /* extension for loadable modules */
#endif
		gchar          filename[FILENAME_LEN];   /* current file name */
		GModule       *handle;          /* handle returned by dlopen */
		gchar         *version;
		gpointer       gp;
		gchar         *dot;
		
		if (plugins_loaded || ! dirname) return;
		
		plugins_loaded = TRUE;
		
#if GLIB_MAJOR_VERSION < 2
		/*
		 * We find the extension used on this platform for loadable modules
		 * by the sneaky hack of calling "g_module_build_path" to build
		 * the pathname for a module with an empty directory name and
		 * empty module name, and then search for the last "." and use
		 * everything from the last "." on.
		 */
		hack_path = g_module_build_path("", "");
		lt_lib_ext = strrchr(hack_path, '.');
		if (lt_lib_ext == NULL)
		{
			static gchar null_str[1] = {0};
			/*
			 * Does this mean there *is* no extension?  Assume so.
			 *
			 * XXX - the code below assumes that all loadable modules have
			 * an extension....
			 */
			lt_lib_ext = null_str;
		}
#endif
		
		if ((dir = eth_dir_open(dirname, 0, NULL)) != NULL)
		{
			while ((file = eth_dir_read_name(dir)) != NULL)
			{
				name = eth_dir_get_name(file);
#if GLIB_MAJOR_VERSION < 2
				/* don't try to open "." and ".." */
				if (!(strcmp(name, "..") &&
					  strcmp(name, ".")))
					continue;
				
				/* skip anything but files with lt_lib_ext */
				dot = strrchr(name, '.');
				if (dot == NULL || strcmp(dot, lt_lib_ext) != 0)
					continue;
				
#else /* GLIB 2 */
				/*
				 * GLib 2.x defines G_MODULE_SUFFIX as the extension used on
				 * this platform for loadable modules.
				 */
				/* skip anything but files with G_MODULE_SUFFIX */
				dot = strrchr(name, '.');
				if (dot == NULL || strcmp(dot+1, G_MODULE_SUFFIX) != 0)
					continue;
				
#endif
				g_snprintf(filename, FILENAME_LEN, "%s" G_DIR_SEPARATOR_S "%s",
						   dirname, name);
				if ((handle = g_module_open(filename, 0)) == NULL)
				{
					g_warning("Couldn't load module %s: %s", filename,
								   g_module_error());
					continue;
				}
				if (!g_module_symbol(handle, "version", &gp))
				{
					g_warning("The plugin %s has no version symbol", name);
					g_module_close(handle);
					continue;
				}
				version = gp;
				
				if (g_module_symbol(handle, "register_wtap_module", &gp))
				{
					void (*register_wtap_module)(void) = gp;
					register_wtap_module();
				}
			}
			eth_dir_close(dir);
		}
#if GLIB_MAJOR_VERSION < 2
		g_free(hack_path);
		g_free(dirname);
#endif

}

