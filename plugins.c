/* plugins.c
 * plugin routines
 *
 * $Id: plugins.c,v 1.2 1999/12/09 20:55:36 oabad Exp $
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

#ifdef HAVE_DLFCN_H

#include <time.h>

#include "globals.h"

#include "plugins.h"

/* linked list of all plugins */
plugin *plugin_list;

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

#endif
