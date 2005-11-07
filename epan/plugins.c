/* plugins.c
 * plugin routines
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
 * Copyright 1999 Gerald Combs
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

#include "plugins.h"

#ifdef HAVE_PLUGINS

#include <time.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
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

#include "filesystem.h"
#include <wiretap/file_util.h>
#include "report_err.h"

/* linked list of all plugins */
plugin *plugin_list;

#define PLUGINS_DIR_NAME	"plugins"

/*
 * add a new plugin to the list
 * returns :
 * - 0 : OK
 * - ENOMEM : memory allocation problem
 * - EEXIST : the same plugin (i.e. name/version) was already registered.
 */
static int
add_plugin(void *handle, gchar *name, gchar *version,
	   void (*register_protoinfo)(void), void (*reg_handoff)(void),
	   void (*register_tap_listener)(void))
{
    plugin *new_plug, *pt_plug;

    pt_plug = plugin_list;
    if (!pt_plug) /* the list is empty */
    {
	new_plug = (plugin *)g_malloc(sizeof(plugin));
	if (new_plug == NULL) return ENOMEM;
        plugin_list = new_plug;
    }
    else
    {
	while (1)
	{
	    /* check if the same name/version is already registered */
	    if (!strcmp(pt_plug->name, name) &&
		!strcmp(pt_plug->version, version))
	    {
		return EEXIST;
	    }

	    /* we found the last plugin in the list */
	    if (pt_plug->next == NULL) break;

	    pt_plug = pt_plug->next;
	}
	new_plug = (plugin *)g_malloc(sizeof(plugin));
	if (new_plug == NULL) return ENOMEM;
	pt_plug->next = new_plug;
    }

    new_plug->handle = handle;
    new_plug->name = name;
    new_plug->version = version;
    new_plug->register_protoinfo = register_protoinfo;
    new_plug->reg_handoff = reg_handoff;
    new_plug->register_tap_listener = register_tap_listener;
    new_plug->next = NULL;
    return 0;
}

/*
 * XXX - when we remove support for old-style plugins (which we should
 * probably do eventually, as all plugins should be written as new-style
 * ones), we may want to have "init_plugins()" merely save a pointer
 * to the plugin's "init" routine, just as we save a pointer to its
 * "reg_handoff" routine, and have a "register_all_plugins()" routine
 * to go through the list of plugins and call all of them.
 *
 * Then we'd have "epan_init()", or perhaps even something higher up
 * in the call tree, call "init_plugins()", and have "proto_init()"
 * call "register_all_plugins()" right after calling "register_all_protocols()";
 * this might be a bit cleaner.
 */
static void
plugins_scan_dir(const char *dirname)
{
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
    void         (*register_protoinfo)(void);
    void         (*reg_handoff)(void);
    void         (*register_tap_listener)(void);
    gchar         *dot;
    int            cr;

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
	/*
	 * Does this mean there *is* no extension?  Assume so.
	 *
	 * XXX - the code below assumes that all loadable modules have
	 * an extension....
	 */
	lt_lib_ext = "";
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
		  strcmp(name, "."))) continue;

            /* skip anything but files with lt_lib_ext */
            dot = strrchr(name, '.');
            if (dot == NULL || strcmp(dot, lt_lib_ext) != 0) continue;

#else /* GLIB 2 */
    /*
     * GLib 2.x defines G_MODULE_SUFFIX as the extension used on this
     * platform for loadable modules.
     */
	    /* skip anything but files with G_MODULE_SUFFIX */
            dot = strrchr(name, '.');
            if (dot == NULL || strcmp(dot+1, G_MODULE_SUFFIX) != 0) continue;

#endif
	    g_snprintf(filename, FILENAME_LEN, "%s" G_DIR_SEPARATOR_S "%s",
	        dirname, name);
	    if ((handle = g_module_open(filename, 0)) == NULL)
	    {
		report_failure("Couldn't load module %s: %s", filename,
			  g_module_error());
		continue;
	    }
	    if (!g_module_symbol(handle, "version", &gp))
	    {
	        report_failure("The plugin %s has no version symbol", name);
		g_module_close(handle);
		continue;
	    }
	    version = gp;
	    
	    /*
	     * Do we have a register routine?
	     */
	    if (g_module_symbol(handle, "plugin_register", &gp))
	    {
		/*
		 * Yes - this plugin includes one or more dissectors.
		 */
		register_protoinfo = gp;
	    }
	    else
	    {
		/*
		 * No - no dissectors.
		 */
		register_protoinfo = NULL;
	    }

	    /*
	     * Do we have a reg_handoff routine?
	     */
	    if (g_module_symbol(handle, "plugin_reg_handoff", &gp))
	    {
		/*
		 * Yes.
		 */
		reg_handoff = gp;
	    }
	    else
	    {
		/*
		 * No - that's OK even if we have dissectors, as long
		 * as the plugin registers by name *and* there's
		 * a caller looking for that name.
		 */
		reg_handoff = NULL;
	    }

	    /*
	     * Do we have a register_tap_listener routine?
	     */
	    if (g_module_symbol(handle, "plugin_register_tap_listener", &gp))
	    {
		/*
		 * Yes - this plugin includes one or more taps.
		 */
		register_tap_listener = gp;
	    }
	    else
	    {
		/*
		 * No - no taps here.
		 */
		register_tap_listener = NULL;
	    }

	    /*
	     * Do we have an old-style init routine?
	     */
	    if (g_module_symbol(handle, "plugin_init", &gp))
	    {
		/*
		 * Yes - do we also have a register routine or a
		 * register_tap_listener routine?  If so, this is a bogus
		 * hybrid of an old-style and new-style plugin.
		 */
		if (register_protoinfo != NULL || register_tap_listener != NULL)
		{
		    report_failure("The plugin %s has an old plugin init routine\nand a new register or register_tap_listener routine.",
			name);
		    g_module_close(handle);
		    continue;
		}

		/*
		 * It's just an unsupported old-style plugin;
		 */
		report_failure("The plugin %s has an old plugin init routine. Support has been dropped.\n Information on how to update your plugin is available at \nhttp://anonsvn.ethereal.com/ethereal/trunk/doc/README.plugins",
		    name);
		g_module_close(handle);
		continue;
	    }

	    /*
	     * Does this dissector do anything useful?
	     */
	    if (register_protoinfo == NULL &&
		register_tap_listener == NULL)
	    {
		/*
		 * No.
		 */
		report_failure("The plugin %s has neither a register routine, or a register_tap_listener routine",
		    name);
		g_module_close(handle);
		continue;
	    }

	    /*
	     * OK, attempt to add it to the list of plugins.
	     */
	    if ((cr = add_plugin(handle, g_strdup(name), version,
				 register_protoinfo, reg_handoff,
				 register_tap_listener)))
	    {
		if (cr == EEXIST)
		    fprintf(stderr, "The plugin %s, version %s\n"
			    "was found in multiple directories\n", name, version);
		else
		    fprintf(stderr, "Memory allocation problem\n"
			    "when processing plugin %s, version %s\n",
			    name, version);
		g_module_close(handle);
		continue;
	    }

	    /*
	     * Call its register routine if it has one.
	     * XXX - just save this and call it with the built-in
	     * dissector register routines?
	     */
	    if (register_protoinfo != NULL)
		    register_protoinfo();

	}
	eth_dir_close(dir);
	}
#if GLIB_MAJOR_VERSION < 2
    g_free(hack_path);
#endif
}


/* get the global plugin dir */
/* Return value is malloced so the caller should g_free() it. */
char *get_plugins_global_dir(const char *plugin_dir)
{
#ifdef _WIN32
	char *install_plugin_dir;

	/*
	 * On Windows, the data file directory is the installation
	 * directory; the plugins are stored under it.
	 *
	 * Assume we're running the installed version of Ethereal;
	 * on Windows, the data file directory is the directory
	 * in which the Ethereal binary resides.
	 */
	install_plugin_dir = g_strdup_printf("%s\\plugins\\%s", get_datafile_dir(), VERSION);

	/*
	 * Make sure that pathname refers to a directory.
	 */
	if (test_for_directory(install_plugin_dir) != EISDIR) {
		/*
		 * Either it doesn't refer to a directory or it
		 * refers to something that doesn't exist.
		 *
		 * Assume that means we're running, for example,
		 * a version of Ethereal we've built in a source
		 * directory, and fall back on the default
		 * installation directory, so you can put the plugins
		 * somewhere so they can be used with this version
		 * of Ethereal.
		 *
		 * XXX - should we, instead, have the Windows build
		 * procedure create a subdirectory of the "plugins"
		 * source directory, and copy the plugin DLLs there,
		 * so that you use the plugins from the build tree?
		 */
		g_free(install_plugin_dir);
		install_plugin_dir =
		    g_strdup("C:\\Program Files\\Ethereal\\plugins\\" VERSION);
	}

	return install_plugin_dir;
#else
	/*
	 * Scan the plugin directory.
	 */
	return g_strdup(plugin_dir);
#endif
}


/* get the personal plugin dir */
/* Return value is malloced so the caller should g_free() it. */
char *get_plugins_pers_dir(void)
{
    return get_persconffile_path(PLUGINS_DIR_NAME, FALSE);
}

/*
 * init plugins
 */
void
init_plugins(const char *plugin_dir)
{
    char *datafile_dir;

    if (plugin_list == NULL)      /* ensure init_plugins is only run once */
    {
	/*
	 * Scan the global plugin directory.
	 */
	datafile_dir = get_plugins_global_dir(plugin_dir);
	plugins_scan_dir(datafile_dir);
	g_free(datafile_dir);

	/*
	 * Scan the users plugin directory.
	 */
	datafile_dir = get_plugins_pers_dir();
	plugins_scan_dir(datafile_dir);
	g_free(datafile_dir);
    }
}

void
register_all_plugin_handoffs(void)
{
    plugin *pt_plug;

    /*
     * For all plugins with register-handoff routines, call the routines.
     * This is called from "proto_init()"; it must be called after
     * "register_all_protocols()" and "init_plugins()" are called,
     * in case one plugin registers itself either with a built-in
     * dissector or with another plugin; we must first register all
     * dissectors, whether built-in or plugin, so their dissector tables
     * are initialized, and only then register all handoffs.
     */
    for (pt_plug = plugin_list; pt_plug != NULL; pt_plug = pt_plug->next)
    {
	if (pt_plug->reg_handoff)
	    (pt_plug->reg_handoff)();
    }
}

void
register_all_plugin_tap_listeners(void)
{
    plugin *pt_plug;

    /*
     * For all plugins with register-tap-listener routines, call the
     * routines.
     */
    for (pt_plug = plugin_list; pt_plug != NULL; pt_plug = pt_plug->next)
    {
	if (pt_plug->register_tap_listener)
	    (pt_plug->register_tap_listener)();
    }
}
#endif
