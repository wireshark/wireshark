/* plugins.c
 * plugin routines
 *
 * $Id: plugins.c,v 1.40 2001/11/04 22:14:42 guy Exp $
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

#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "filesystem.h"

#include "prefs.h"

#ifdef PLUGINS_NEED_ADDRESS_TABLE
#include "conversation.h"
#include "packet-giop.h"
#include "plugins/plugin_table.h"
static plugin_address_table_t	patable;
#endif

/* linked list of all plugins */
plugin *plugin_list;

#ifndef WIN32
static gchar std_plug_dir[] = "/usr/lib/ethereal/plugins/" VERSION;
static gchar local_plug_dir[] = "/usr/local/lib/ethereal/plugins/" VERSION;
#endif
static gchar *user_plug_dir = NULL;

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
	   void (*reg_handoff)(void))
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
    new_plug->reg_handoff = reg_handoff;
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
    gchar         *hack_path;       /* pathname used to construct lt_lib_ext */
    gchar         *lt_lib_ext;      /* extension for loadable modules */
    DIR           *dir;             /* scanned directory */
    struct dirent *file;            /* current file */
    gchar          filename[FILENAME_LEN];   /* current file name */
    GModule       *handle;          /* handle returned by dlopen */
    gchar         *name;
    gchar         *version;
    void         (*init)(void *);
    void         (*reg_handoff)(void);
    gchar         *dot;
    int            cr;

    /*
     * We find the extension used on this platform for loadable modules
     * by the sneaky hack of calling "g_module_build_path" to build
     * the pathname for a module with an empty directory name and
     * empty module name, and then search for the last "." and use
     * everything from the last "." on.
     *
     * GLib 2.0 will probably define G_MODULE_SUFFIX as the extension
     * to use, but that's not checked into the GLib CVS tree yet,
     * and we can't use it on systems that don't have GLib 2.0.
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

    if ((dir = opendir(dirname)) != NULL)
    {
	while ((file = readdir(dir)) != NULL)
	{
	    /* don't try to open "." and ".." */
	    if (!(strcmp(file->d_name, "..") &&
		  strcmp(file->d_name, "."))) continue;

            /* skip anything but files with lt_lib_ext */
            dot = strrchr(file->d_name, '.');
            if (dot == NULL || strcmp(dot, lt_lib_ext) != 0) continue;

	    snprintf(filename, FILENAME_LEN, "%s" G_DIR_SEPARATOR_S "%s",
	        dirname, file->d_name);
	    if ((handle = g_module_open(filename, 0)) == NULL) continue;
	    name = (gchar *)file->d_name;
	    if (g_module_symbol(handle, "version", (gpointer*)&version) == FALSE)
	    {
	        g_warning("The plugin %s has no version symbol", name);
		g_module_close(handle);
		continue;
	    }

	    /*
	     * Old-style dissectors don't have a "plugin_reg_handoff()"
	     * routine; we no longer support them.
	     *
	     * New-style dissectors have one, because, otherwise, there's
	     * no way for them to arrange that they ever be called.
	     */
	    if (g_module_symbol(handle, "plugin_reg_handoff",
					 (gpointer*)&reg_handoff))
	    {
		/*
		 * We require it to have a "plugin_init()" routine.
		 */
		if (!g_module_symbol(handle, "plugin_init", (gpointer*)&init))
		{
		    g_warning("The plugin %s has a plugin_reg_handoff symbol but no plugin_init routine", name);
		    g_module_close(handle);
		    continue;
		}

		/*
		 * We have a "plugin_reg_handoff()" routine, so we don't
		 * need the protocol, filter string, or dissector pointer.
		 */
		if ((cr = add_plugin(handle, g_strdup(file->d_name), version,
				     reg_handoff)))
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
		 * Call its init routine.
		 */
#ifdef PLUGINS_NEED_ADDRESS_TABLE
		init(&patable);
#else
		init(NULL);
#endif
	    }
	    else
	    {
		/*
		 * This is an old-style dissector; warn that it won't
		 * be used, as those aren't supported.
		 */
		fprintf(stderr,
		    "The plugin %s, version %s is an old-style plugin;\n"
		    "Those are no longer supported.\n", name, version);
	    }
	}
	closedir(dir);
    }
    g_free(hack_path);
}

/*
 * init plugins
 */
void
init_plugins(const char *plugin_dir)
{
#ifdef WIN32
    const char *datafile_dir;
    char *install_plugin_dir;
#else
    struct stat std_dir_stat, local_dir_stat, plugin_dir_stat;
#endif

    if (plugin_list == NULL)      /* ensure init_plugins is only run once */
    {
#ifdef PLUGINS_NEED_ADDRESS_TABLE
	/* Intialize address table */
	patable.p_pi				= &pi;

	patable.p_check_col			= check_col;
	patable.p_col_clear			= col_clear;
	patable.p_col_add_fstr			= col_add_fstr;
	patable.p_col_append_fstr		= col_append_fstr;
	patable.p_col_add_str			= col_add_str;
	patable.p_col_append_str		= col_append_str;
	patable.p_col_set_str			= col_set_str;

	patable.p_register_init_routine		= register_init_routine;
	patable.p_conv_dissector_add		= conv_dissector_add;
	patable.p_conversation_new		= conversation_new;
	patable.p_find_conversation		= find_conversation;
	patable.p_match_strval			= match_strval;
	patable.p_val_to_str			= val_to_str;

	patable.p_proto_register_protocol	= proto_register_protocol;
	patable.p_proto_register_field_array	= proto_register_field_array;
	patable.p_proto_register_subtree_array	= proto_register_subtree_array;

	patable.p_dissector_add			= dissector_add;
	patable.p_dissector_delete		= dissector_delete;

	patable.p_heur_dissector_add		= heur_dissector_add;

	patable.p_register_dissector		= register_dissector;
	patable.p_find_dissector		= find_dissector;
	patable.p_call_dissector		= call_dissector;

	patable.p_dissect_data			= dissect_data;

	patable.p_proto_is_protocol_enabled	= proto_is_protocol_enabled;

	patable.p_proto_item_get_len		= proto_item_get_len;
	patable.p_proto_item_set_len		= proto_item_set_len;
	patable.p_proto_item_set_text		= proto_item_set_text;
	patable.p_proto_item_append_text	= proto_item_append_text;
	patable.p_proto_item_add_subtree	= proto_item_add_subtree;
	patable.p_proto_tree_add_item		= proto_tree_add_item;
	patable.p_proto_tree_add_item_hidden	= proto_tree_add_item_hidden;
	patable.p_proto_tree_add_protocol_format = proto_tree_add_protocol_format;
	patable.p_proto_tree_add_bytes		= proto_tree_add_bytes;
	patable.p_proto_tree_add_bytes_hidden	= proto_tree_add_bytes_hidden;
	patable.p_proto_tree_add_bytes_format	= proto_tree_add_bytes_format;
	patable.p_proto_tree_add_time		= proto_tree_add_time;
	patable.p_proto_tree_add_time_hidden	= proto_tree_add_time_hidden;
	patable.p_proto_tree_add_time_format	= proto_tree_add_time_format;
	patable.p_proto_tree_add_ipxnet		= proto_tree_add_ipxnet;
	patable.p_proto_tree_add_ipxnet_hidden	= proto_tree_add_ipxnet_hidden;
	patable.p_proto_tree_add_ipxnet_format	= proto_tree_add_ipxnet_format;
	patable.p_proto_tree_add_ipv4		= proto_tree_add_ipv4;
	patable.p_proto_tree_add_ipv4_hidden	= proto_tree_add_ipv4_hidden;
	patable.p_proto_tree_add_ipv4_format	= proto_tree_add_ipv4_format;
	patable.p_proto_tree_add_ipv6		= proto_tree_add_ipv6;
	patable.p_proto_tree_add_ipv6_hidden	= proto_tree_add_ipv6_hidden;
	patable.p_proto_tree_add_ipv6_format	= proto_tree_add_ipv6_format;
	patable.p_proto_tree_add_ether		= proto_tree_add_ether;
	patable.p_proto_tree_add_ether_hidden	= proto_tree_add_ether_hidden;
	patable.p_proto_tree_add_ether_format	= proto_tree_add_ether_format;
	patable.p_proto_tree_add_string		= proto_tree_add_string;
	patable.p_proto_tree_add_string_hidden	= proto_tree_add_string_hidden;
	patable.p_proto_tree_add_string_format	= proto_tree_add_string_format;
	patable.p_proto_tree_add_boolean	= proto_tree_add_boolean;
	patable.p_proto_tree_add_boolean_hidden	= proto_tree_add_boolean_hidden;
	patable.p_proto_tree_add_boolean_format	= proto_tree_add_boolean_format;
	patable.p_proto_tree_add_double		= proto_tree_add_double;
	patable.p_proto_tree_add_double_hidden	= proto_tree_add_double_hidden;
	patable.p_proto_tree_add_double_format	= proto_tree_add_double_format;
	patable.p_proto_tree_add_uint		= proto_tree_add_uint;
	patable.p_proto_tree_add_uint_hidden	= proto_tree_add_uint_hidden;
	patable.p_proto_tree_add_uint_format	= proto_tree_add_uint_format;
	patable.p_proto_tree_add_int		= proto_tree_add_int;
	patable.p_proto_tree_add_int_hidden	= proto_tree_add_int_hidden;
	patable.p_proto_tree_add_int_format	= proto_tree_add_int_format;
	patable.p_proto_tree_add_text		= proto_tree_add_text;

	patable.p_tvb_new_subset		= tvb_new_subset;

	patable.p_tvb_length			= tvb_length;
	patable.p_tvb_length_remaining		= tvb_length_remaining;
	patable.p_tvb_bytes_exist		= tvb_bytes_exist;
	patable.p_tvb_offset_exists		= tvb_offset_exists;
	patable.p_tvb_reported_length		= tvb_reported_length;
	patable.p_tvb_reported_length_remaining	= tvb_reported_length_remaining;

	patable.p_tvb_get_guint8		= tvb_get_guint8;

	patable.p_tvb_get_ntohs			= tvb_get_ntohs;
	patable.p_tvb_get_ntoh24		= tvb_get_ntoh24;
	patable.p_tvb_get_ntohl			= tvb_get_ntohl;

	patable.p_tvb_get_letohs		= tvb_get_letohs;
	patable.p_tvb_get_letoh24		= tvb_get_letoh24;
	patable.p_tvb_get_letohl		= tvb_get_letohl;

	patable.p_tvb_memcpy			= tvb_memcpy;
	patable.p_tvb_memdup			= tvb_memdup;

	patable.p_tvb_get_ptr			= tvb_get_ptr;

	patable.p_tvb_find_guint8		= tvb_find_guint8;
	patable.p_tvb_pbrk_guint8		= tvb_pbrk_guint8;

	patable.p_tvb_strnlen			= tvb_strnlen;

	patable.p_tvb_format_text		= tvb_format_text;

	patable.p_tvb_get_nstringz		= tvb_get_nstringz;
	patable.p_tvb_get_nstringz0		= tvb_get_nstringz0;

	patable.p_tvb_find_line_end		= tvb_find_line_end;
	patable.p_tvb_find_line_end_unquoted	= tvb_find_line_end_unquoted;

	patable.p_tvb_strneql			= tvb_strneql;
	patable.p_tvb_strncaseeql		= tvb_strncaseeql;

	patable.p_tvb_bytes_to_str		= tvb_bytes_to_str;

	patable.p_prefs_register_protocol	= prefs_register_protocol;
	patable.p_prefs_register_uint_preference = prefs_register_uint_preference;
	patable.p_prefs_register_bool_preference = prefs_register_bool_preference;
	patable.p_prefs_register_enum_preference = prefs_register_enum_preference;
	patable.p_prefs_register_string_preference = prefs_register_string_preference;

	patable.p_register_giop_user		= register_giop_user;
	patable.p_is_big_endian			= is_big_endian;
	patable.p_get_CDR_string		= get_CDR_string;
	patable.p_get_CDR_ulong			= get_CDR_ulong;
	patable.p_get_CDR_enum			= get_CDR_enum;
	patable.p_get_CDR_object		= get_CDR_object;
	patable.p_get_CDR_boolean		= get_CDR_boolean;
#endif

#ifdef WIN32
	/*
	 * On Windows, the data file directory is the installation
	 * directory; the plugins are stored under it.
	 *
	 * Assume we're running the installed version of Ethereal;
	 * on Windows, the data file directory is the directory
	 * in which the Ethereal binary resides.
	 */
	datafile_dir = get_datafile_dir();
	install_plugin_dir = g_malloc(strlen(datafile_dir) + strlen("plugins") +
	    strlen(VERSION) + 3);
	sprintf(install_plugin_dir, "%s\\plugins\\%s", datafile_dir, VERSION);

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
		install_plugin_dir =
		    g_strdup("C:\\Program Files\\Ethereal\\plugins\\" VERSION);
	}

	/*
	 * Scan that directory.
	 */
	plugins_scan_dir(install_plugin_dir);
	g_free(install_plugin_dir);
#else
	/*
	 * XXX - why not just scan "plugin_dir"?  That's where we
	 * installed the plugins; if Ethereal isn't installed under
	 * "/usr" or "/usr/local", why should we search for its plugins
	 * there?
	 */
	plugins_scan_dir(std_plug_dir);
	plugins_scan_dir(local_plug_dir);
	if ((strcmp(std_plug_dir, plugin_dir) != 0) &&
		(strcmp(local_plug_dir, plugin_dir) != 0))
	{
	    if (stat(plugin_dir, &plugin_dir_stat) == 0)
	    {
		/* check if plugin_dir is really different from std_dir and
		 * local_dir if they exist ! */
		if (stat(std_plug_dir, &std_dir_stat) == 0)
		{
		    if (stat(local_plug_dir, &local_dir_stat) == 0)
		    {
			if ((plugin_dir_stat.st_dev != std_dir_stat.st_dev ||
				    plugin_dir_stat.st_ino != std_dir_stat.st_ino) &&
				(plugin_dir_stat.st_dev != local_dir_stat.st_dev ||
				 plugin_dir_stat.st_ino != local_dir_stat.st_ino))
			    plugins_scan_dir(plugin_dir);
		    }
		    else
		    {
			if ((plugin_dir_stat.st_dev != std_dir_stat.st_dev ||
				    plugin_dir_stat.st_ino != std_dir_stat.st_ino))
			    plugins_scan_dir(plugin_dir);
		    }
		}
		else if (stat(local_plug_dir, &local_dir_stat) == 0)
		{
		    if ((plugin_dir_stat.st_dev != local_dir_stat.st_dev ||
				plugin_dir_stat.st_ino != local_dir_stat.st_ino))
			plugins_scan_dir(plugin_dir);
		}
		else plugins_scan_dir(plugin_dir);
	    }
	}
#endif
	if (!user_plug_dir)
	    user_plug_dir = get_persconffile_path(PLUGINS_DIR_NAME, FALSE);
	plugins_scan_dir(user_plug_dir);
    }
}

void
register_all_plugin_handoffs(void)
{
  plugin *pt_plug;

  /*
   * For all new-style plugins, call the register-handoff routine.
   * This is called from "proto_init()"; it must be called after
   * "register_all_protocols()" and "init_plugins()" are called,
   * in case one plugin registers itself either with a built-in
   * dissector or with another plugin; we must first register all
   * dissectors, whether built-in or plugin, so their dissector tables
   * are initialized, and only then register all handoffs.
   *
   * We treat those protocols as always being enabled; they should
   * use the standard mechanism for enabling/disabling protocols, not
   * the plugin-specific mechanism.
   */
  for (pt_plug = plugin_list; pt_plug != NULL; pt_plug = pt_plug->next)
    (pt_plug->reg_handoff)();
}
#endif
