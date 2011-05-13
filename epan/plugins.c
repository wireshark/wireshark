/* plugins.c
 * plugin routines
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include "plugins.h"

/* linked list of Lua plugins */
wslua_plugin *wslua_plugin_list = NULL;

#ifdef HAVE_PLUGINS

#include <time.h>

#ifdef HAVE_DIRENT_H
#include <dirent.h>
#endif

#ifdef HAVE_DIRECT_H
#include <direct.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "filesystem.h"
#include <wsutil/privileges.h>
#include <wsutil/file_util.h>
#include "report_err.h"

/* linked list of all plugins */
plugin *plugin_list = NULL;

/*
 * add a new plugin to the list
 * returns :
 * - 0 : OK
 * - ENOMEM : memory allocation problem
 * - EEXIST : the same plugin (i.e. name/version) was already registered.
 */
static int
add_plugin(void *handle, gchar *name, gchar *version,
           void (*register_protoinfo)(void),
	   void (*reg_handoff)(void),
           void (*register_tap_listener)(void),
           void (*register_wtap_module)(void),
           void (*register_codec_module)(void))
{
    plugin *new_plug, *pt_plug;

    pt_plug = plugin_list;
    if (!pt_plug) /* the list is empty */
    {
        new_plug = (plugin *)g_malloc(sizeof(plugin));
        if (new_plug == NULL)
	    return ENOMEM;
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
            if (pt_plug->next == NULL)
	        break;

            pt_plug = pt_plug->next;
        }
        new_plug = (plugin *)g_malloc(sizeof(plugin));
        if (new_plug == NULL)
	    return ENOMEM;
        pt_plug->next = new_plug;
    }

    new_plug->handle = handle;
    new_plug->name = name;
    new_plug->version = version;
    new_plug->register_protoinfo = register_protoinfo;
    new_plug->reg_handoff = reg_handoff;
    new_plug->register_tap_listener = register_tap_listener;
    new_plug->register_wtap_module = register_wtap_module;
    new_plug->register_codec_module = register_codec_module;
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
#define FILENAME_LEN        1024
    WS_DIR        *dir;             /* scanned directory */
    WS_DIRENT     *file;            /* current file */
    const char    *name;
    gchar          filename[FILENAME_LEN];   /* current file name */
    GModule       *handle;          /* handle returned by g_module_open */
    gchar         *version;
    gpointer       gp;
    void         (*register_protoinfo)(void);
    void         (*reg_handoff)(void);
    void         (*register_tap_listener)(void);
    void         (*register_wtap_module)(void);
    void         (*register_codec_module)(void);

    gchar         *dot;
    int            cr;

    if ((dir = ws_dir_open(dirname, 0, NULL)) != NULL)
    {
        while ((file = ws_dir_read_name(dir)) != NULL)
        {
            name = ws_dir_get_name(file);

            /*
             * GLib 2.x defines G_MODULE_SUFFIX as the extension used on
             * this platform for loadable modules.
             */
            /* skip anything but files with G_MODULE_SUFFIX */
            dot = strrchr(name, '.');
            if (dot == NULL || strcmp(dot+1, G_MODULE_SUFFIX) != 0)
                continue;

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
                    report_failure("The plugin '%s' has an old plugin init routine\nand a new register or register_tap_listener routine.",
                                   name);
                    g_module_close(handle);
                    continue;
                }

                /*
                 * It's just an unsupported old-style plugin;
                 */
                report_failure("The plugin '%s' has an old plugin init routine. Support has been dropped.\n Information on how to update your plugin is available at \nhttp://anonsvn.wireshark.org/wireshark/trunk/doc/README.plugins",
                               name);
                g_module_close(handle);
                continue;
            }

            /*
             * Do we have a register_wtap_module routine?
             */
            if (g_module_symbol(handle, "register_wtap_module", &gp))
            {
                register_wtap_module = gp;
            }
            else
            {
                register_wtap_module = NULL;
            }

            /*
             * Do we have a register_codec_module routine?
             */
            if (g_module_symbol(handle, "register_codec_module", &gp))
            {
                register_codec_module = gp;
            }
            else
            {
                register_codec_module = NULL;
            }

            /*
             * Does this dissector do anything useful?
             */
            if (register_protoinfo == NULL &&
                register_tap_listener == NULL &&
                register_wtap_module == NULL &&
                register_codec_module == NULL )
            {
                /*
                 * No.
                 */
                report_failure("The plugin '%s' has neither a register routine, "
                               "a register_tap_listener or a register_wtap_module or a register_codec_module routine",
                               name);
                g_module_close(handle);
                continue;
            }

            /*
             * OK, attempt to add it to the list of plugins.
             */
            if ((cr = add_plugin(handle, g_strdup(name), version,
                                 register_protoinfo, reg_handoff,
                                 register_tap_listener,register_wtap_module,register_codec_module)))
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

        }
        ws_dir_close(dir);
    }
}


/*
 * init plugins
 */
void
init_plugins(void)
{
    const char *plugin_dir;
    const char *name;
    char *plugin_dir_path;
    char *plugins_pers_dir;
    WS_DIR *dir;                /* scanned directory */
    WS_DIRENT *file;                /* current file */

    if (plugin_list == NULL)      /* ensure init_plugins is only run once */
    {
        /*
         * Scan the global plugin directory.
         * If we're running from a build directory, scan the subdirectories
         * of that directory, as the global plugin directory is the
         * "plugins" directory of the source tree, and the subdirectories
         * are the source directories for the plugins, with the plugins
         * built in those subdirectories.
         */
        plugin_dir = get_plugin_dir();
        if (running_in_build_directory())
        {
            if ((dir = ws_dir_open(plugin_dir, 0, NULL)) != NULL)
            {
                while ((file = ws_dir_read_name(dir)) != NULL)
                {
                    name = ws_dir_get_name(file);
                    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
                        continue;        /* skip "." and ".." */
                    /*
                     * Get the full path of a ".libs" subdirectory of that
                     * directory.
                     */
                    plugin_dir_path = g_strdup_printf(
                        "%s" G_DIR_SEPARATOR_S "%s" G_DIR_SEPARATOR_S ".libs",
                        plugin_dir, name);
                    if (test_for_directory(plugin_dir_path) != EISDIR) {
                        /*
                         * Either it doesn't refer to a directory or it
                         * refers to something that doesn't exist.
                         *
                         * Assume that means that the plugins are in
                         * the subdirectory of the plugin directory, not
                         * a ".libs" subdirectory of that subdirectory.
                         */
                        g_free(plugin_dir_path);
                        plugin_dir_path = g_strdup_printf("%s" G_DIR_SEPARATOR_S "%s",
                            plugin_dir, name);
                    }
                    plugins_scan_dir(plugin_dir_path);
                    g_free(plugin_dir_path);
                }
                ws_dir_close(dir);
            }
        }
        else
            plugins_scan_dir(plugin_dir);

        /*
         * If the program wasn't started with special privileges,
         * scan the users plugin directory.  (Even if we relinquish
         * them, plugins aren't safe unless we've *permanently*
         * relinquished them, and we can't do that in Wireshark as,
         * if we need privileges to start capturing, we'd need to
         * reclaim them before each time we start capturing.)
         */
        if (!started_with_special_privs())
        {
            plugins_pers_dir = get_plugins_pers_dir();
            plugins_scan_dir(plugins_pers_dir);
            g_free(plugins_pers_dir);
        }
    }

    register_all_wiretap_modules();
    register_all_codecs();
}

void
register_all_plugin_registrations(void)
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
        if (pt_plug->register_protoinfo)
            (pt_plug->register_protoinfo)();
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

void
register_all_wiretap_modules(void)
{
    plugin *pt_plug;

    /*
     * For all plugins with register_wtap_module routines, call the
     * routines.
     */
    for (pt_plug = plugin_list; pt_plug != NULL; pt_plug = pt_plug->next)
    {
        if (pt_plug->register_wtap_module)
            (pt_plug->register_wtap_module)();
    }
}

void
register_all_codecs(void)
{
    plugin *pt_plug;

    /*
     * For all plugins with register_wtap_module routines, call the
     * routines.
     */
    for (pt_plug = plugin_list; pt_plug != NULL; pt_plug = pt_plug->next)
    {
        if (pt_plug->register_codec_module)
              (pt_plug->register_codec_module)();
    }
}
#endif
