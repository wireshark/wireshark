/* plugins.c
 * plugin routines
 *
 * $Id: plugins.c,v 1.5 2000/01/15 00:22:34 gram Exp $
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@zing.org>
 * Copyright 1999 Gerald Combs
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
#include <sys/stat.h>
#include <sys/types.h>

#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif

#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif

#include "globals.h"


/* linked list of all plugins */
plugin *plugin_list;

static gchar std_plug_dir[] = "/usr/lib/ethereal/plugins/0.8";
static gchar local_plug_dir[] = "/usr/local/lib/ethereal/plugins/0.8";
static gchar *user_plug_dir = NULL;
static gchar *plugin_status_file = NULL;

/*
 * add a new plugin to the list
 * returns :
 * - 0 : OK
 * - ENOMEM : memory allocation problem
 * - EEXIST : the same plugin (i.e. name/version) was already registered.
 */
int
add_plugin(void *handle, gchar *name, gchar *version, gchar *protocol,
	   gchar *filter_string, dfilter *filter,
	   void (*dissector) (const u_char *,
	                      int,
			      frame_data *,
			      proto_tree *))
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
    new_plug->enabled = FALSE;
    new_plug->protocol = protocol;
    new_plug->filter_string = g_strdup(filter_string);
    new_plug->filter = filter;
    new_plug->dissector = dissector;
    new_plug->next = NULL;
    return 0;
}

/*
 * enable a plugin
 * returns a pointer to the enabled plugin, or NULL if the plugin wasn't found
 * in the list
 */
void *
enable_plugin(const gchar *name, const gchar *version)
{
    plugin *pt_plug;

    pt_plug = plugin_list;
    while (pt_plug)
    {
	if (!strcmp(pt_plug->name, name) && !strcmp(pt_plug->version, version))
	{
	    pt_plug->enabled = TRUE;
	    return pt_plug;
	}
	pt_plug = pt_plug->next;
    }
    return NULL;
}

/*
 * disable a plugin
 * returns a pointer to the disabled plugin, or NULL if the plugin wasn't found
 * in the list
 */
void *
disable_plugin(const gchar *name, const gchar *version)
{
    plugin *pt_plug;

    pt_plug = plugin_list;
    while (pt_plug)
    {
	if (!strcmp(pt_plug->name, name) && !strcmp(pt_plug->version, version))
	{
	    pt_plug->enabled = FALSE;
	    return pt_plug;
	}
	pt_plug = pt_plug->next;
    }
    return NULL;
}

/*
 * find a plugin using its name/version
 */
void *
find_plugin(const gchar *name, const gchar *version)
{
    plugin *pt_plug;

    pt_plug = plugin_list;
    while (pt_plug)
    {
	if (!strcmp(pt_plug->name, name) && !strcmp(pt_plug->version, version))
	{
	    return pt_plug;
	}
	pt_plug = pt_plug->next;
    }
    return NULL;
}

/*
 * check if a plugin is enabled
 */
gboolean
is_enabled(const gchar *name, const gchar *version)
{
    plugin *pt_plug;

    pt_plug = plugin_list;
    while (pt_plug)
    {
	if (!strcmp(pt_plug->name, name) && !strcmp(pt_plug->version, version))
	    return pt_plug->enabled;
	pt_plug = pt_plug->next;
    }
    return FALSE;
}

/*
 * replace the filter used by a plugin (filter string and dfilter)
 */
void
plugin_replace_filter(const gchar *name, const gchar *version,
	const gchar *filter_string, dfilter *filter)
{
    plugin *pt_plug;

    pt_plug = plugin_list;
    while (pt_plug)
    {
	if (!strcmp(pt_plug->name, name) && !strcmp(pt_plug->version, version))
	{
	    g_free(pt_plug->filter_string);
	    pt_plug->filter_string = g_strdup(filter_string);
	    dfilter_destroy(pt_plug->filter);
	    pt_plug->filter = filter;
	    return;
	}
	pt_plug = pt_plug->next;
    }
}

/*
 * save plugin status, returns 0 on success, -1 on failure:
 * file format :
 * for each plugin, two lines are saved :
 * plugin_name plugin_version [0|1]    (0: disabled, 1: enabled)
 * filter_string
 *
 * Ex :
 * gryphon.so 0.8.0 1
 * tcp.port == 7000
 */
int
save_plugin_status()
{
    gchar  *pf_path;
    FILE   *statusfile;
    plugin *pt_plug;

    if (!plugin_status_file) {
	plugin_status_file = (gchar *)g_malloc(strlen(getenv("HOME")) + 26);
	sprintf(plugin_status_file, "%s/%s/plugins.status", getenv("HOME"), PF_DIR);
    }
    statusfile=fopen(plugin_status_file, "w");
    if (!statusfile) {
	pf_path = g_malloc(strlen(getenv("HOME")) + strlen(PF_DIR) + 2);
	sprintf(pf_path, "%s/%s", getenv("HOME"), PF_DIR);
	#ifdef WIN32
	mkdir(pf_path);
	#else
	mkdir(pf_path, 0755);
	#endif
	g_free(pf_path);
	statusfile=fopen(plugin_status_file, "w");
	if (!statusfile) return -1;
    }

    pt_plug = plugin_list;
    while (pt_plug)
    {
	fprintf(statusfile,"%s %s %s\n%s\n", pt_plug->name, pt_plug->version,
		(pt_plug->enabled ? "1" : "0"), pt_plug->filter_string);
	pt_plug = pt_plug->next;
    }
    fclose(statusfile);
    return 0;
}

/*
 * Check if the status of this plugin has been saved.
 * If necessary, enable the plugin, and change the filter.
 */
static void
check_plugin_status(gchar *name, gchar *version, GModule *handle,
	            gchar *filter_string, FILE *statusfile)
{
    gchar   *ref_string;
    guint16  ref_string_len;
    gchar    line[512];
    void   (*proto_init)();
    dfilter *filter;

    if (!statusfile) return;

    ref_string = (gchar *)g_malloc(strlen(name) + strlen(version) + 2);
    ref_string_len = sprintf(ref_string, "%s %s", name, version);

    while (!feof(statusfile))
    {
	if (fgets(line, 512, statusfile) == NULL) return;
	if (strncmp(line, ref_string, ref_string_len) != 0) { /* not the right plugin */
	    if (fgets(line, 512, statusfile) == NULL) return;
	}
	else { /* found the plugin */
	    if (line[ref_string_len+1] == '1') {
		enable_plugin(name, version);
		if (g_module_symbol(handle, "proto_init", (gpointer*)&proto_init) == TRUE) {
		    proto_init();
		}
	    }

	    if (fgets(line, 512, statusfile) == NULL) return;
	    if (line[strlen(line)-1] == '\n') line[strlen(line)-1] = '\0';
	    /* only compile the new filter if it is different from the default */
	    if (strcmp(line, filter_string) && dfilter_compile(line, &filter) == 0)
		plugin_replace_filter(name, version, line, filter);
	    return;
	}
    }
    g_free(ref_string);
}

static void
plugins_scan_dir(const char *dirname)
{
    DIR           *dir;             /* scanned directory */
    struct dirent *file;            /* current file */
    gchar          filename[512];   /* current file name */
    GModule       *handle;          /* handle returned by dlopen */
    gchar         *name;
    gchar         *version;
    gchar         *protocol;
    gchar         *filter_string;
    gchar         *dot;
    dfilter       *filter = NULL;
    void         (*dissector) (const u_char *, int, frame_data *, proto_tree *);
    int            cr;
    FILE          *statusfile;

#ifdef WIN32
#define LT_LIB_EXT ".dll"
#else
#define LT_LIB_EXT ".la"
#endif

    if (!plugin_status_file)
    {
	plugin_status_file = (gchar *)g_malloc(strlen(getenv("HOME")) + 26);
	sprintf(plugin_status_file, "%s/%s/plugins.status", getenv("HOME"), PF_DIR);
    }
    statusfile = fopen(plugin_status_file, "r");

    if ((dir = opendir(dirname)) != NULL)
    {
	while ((file = readdir(dir)) != NULL)
	{
	    /* don't try to open "." and ".." */
	    if (!(strcmp(file->d_name, "..") &&
		  strcmp(file->d_name, "."))) continue;

            /* skip anything but .la */
            dot = strrchr(file->d_name, '.');
            if (dot == NULL || ! strcmp(dot, LT_LIB_EXT)) continue;

	    sprintf(filename, "%s/%s", dirname, file->d_name);

	    if ((handle = g_module_open(filename, 0)) == NULL) continue;
	    name = (gchar *)file->d_name;
	    if (g_module_symbol(handle, "version", (gpointer*)&version) == FALSE)
	    {
		g_module_close(handle);
		continue;
	    }
	    if (g_module_symbol(handle, "protocol", (gpointer*)&protocol) == FALSE)
	    {
		g_module_close(handle);
		continue;
	    }
	    if (g_module_symbol(handle, "filter_string", (gpointer*)&filter_string) == FALSE)
	    {
		g_module_close(handle);
		continue;
	    }
	    if (dfilter_compile(filter_string, &filter) != 0) {
		g_module_close(handle);
		continue;
	    }
	    if (g_module_symbol(handle, "dissector", (gpointer*)&dissector) == FALSE) {
		if (filter != NULL)
		    dfilter_destroy(filter);
		g_module_close(handle);
		continue;
	    }

	    if ((cr = add_plugin(handle, g_strdup(file->d_name), version,
				 protocol, filter_string, filter, dissector)))
	    {
		if (cr == EEXIST)
		    fprintf(stderr, "The plugin : %s, version %s\n"
			    "was found in multiple directories\n", name, version);
		else
		    fprintf(stderr, "Memory allocation problem\n"
			    "when processing plugin %s, version %sn",
			    name, version);
		if (filter != NULL)
		    dfilter_destroy(filter);
		g_module_close(handle);
		continue;
	    }
	    if (statusfile) {
		check_plugin_status(file->d_name, version, handle,
			            filter_string, statusfile);
		rewind(statusfile);
	    }
	}
	closedir(dir);
    }
    if (statusfile) fclose(statusfile);
}

/*
 * init plugins
 */
void
init_plugins()
{
    if (plugin_list == NULL)      /* ensure init_plugins is only run once */
    {
	plugins_scan_dir(std_plug_dir);
	plugins_scan_dir(local_plug_dir);
        if ((strcmp(std_plug_dir, PLUGIN_DIR) != 0) &&
            (strcmp(local_plug_dir, PLUGIN_DIR) != 0))
        {
          plugins_scan_dir(PLUGIN_DIR);
        }
	if (!user_plug_dir)
	{
	    user_plug_dir = (gchar *)g_malloc(strlen(getenv("HOME")) + 19);
	    sprintf(user_plug_dir, "%s/%s/plugins", getenv("HOME"), PF_DIR);
	}
	plugins_scan_dir(user_plug_dir);
    }
}

#endif
