/* qt_ui_utils.cpp
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <string.h>
#include <stdlib.h>

#include "qt_ui_utils.h"

#include <ui/recent.h>
#include <ui/ui_util.h>

#include <wsutil/str_util.h>

// XXX - Copied from ui/gtk/gui_utils.c

#define WINDOW_GEOM_KEY "window_geom"

/* load the geometry values for a window from previously saved values */
static gboolean window_geom_load(const gchar *name, window_geometry_t *geom);

/* the geometry hashtable for all known window classes,
 * the window name is the key, and the geometry struct is the value */
static GHashTable *window_geom_hash = NULL;

/* save the window and it's current geometry into the geometry hashtable */
static void
window_geom_save(const gchar *name, window_geometry_t *geom)
{
    gchar *key;
    window_geometry_t *work;

    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }
    /* if we have an old one, remove and free it first */
    work = (window_geometry_t *) g_hash_table_lookup(window_geom_hash, name);
    if(work) {
        g_hash_table_remove(window_geom_hash, name);
        g_free(work->key);
        g_free(work);
    }

    /* g_malloc and insert the new one */
    work = (window_geometry_t *) g_malloc(sizeof(*geom));
    *work = *geom;
    key = g_strdup(name);
    work->key = key;
    g_hash_table_insert(window_geom_hash, key, work);
}


/* load the desired geometry for this window from the geometry hashtable */
static gboolean
window_geom_load(const gchar *name, window_geometry_t *geom)
{
    window_geometry_t *p;

    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }

    p = (window_geometry_t *) g_hash_table_lookup(window_geom_hash, name);
    if(p) {
        *geom = *p;
        return TRUE;
    } else {
        return FALSE;
    }
}


/* read in a single key value pair from the recent file into the geometry hashtable */
extern "C" void
window_geom_recent_read_pair(const char *name, const char *key, const char *value)
{
    window_geometry_t geom;


    /* find window geometry maybe already in hashtable */
    if(!window_geom_load(name, &geom)) {
        /* not in table, init geom with "basic" values */
        geom.key        = NULL;    /* Will be set in window_geom_save () */
        geom.set_pos    = FALSE;
        geom.x          = -1;
        geom.y          = -1;
        geom.set_size   = FALSE;
        geom.width      = -1;
        geom.height     = -1;

        geom.set_maximized = FALSE;/* this is valid in GTK2 only */
        geom.maximized  = FALSE;   /* this is valid in GTK2 only */
    }

    if (strcmp(key, "x") == 0) {
        geom.x = strtol(value, NULL, 10);
        geom.set_pos = TRUE;
    } else if (strcmp(key, "y") == 0) {
        geom.y = strtol(value, NULL, 10);
        geom.set_pos = TRUE;
    } else if (strcmp(key, "width") == 0) {
        geom.width = strtol(value, NULL, 10);
        geom.set_size = TRUE;
    } else if (strcmp(key, "height") == 0) {
        geom.height = strtol(value, NULL, 10);
        geom.set_size = TRUE;
    } else if (strcmp(key, "maximized") == 0) {
        if (g_ascii_strcasecmp(value, "true") == 0) {
            geom.maximized = TRUE;
        }
        else {
            geom.maximized = FALSE;
        }
        geom.set_maximized = TRUE;
    } else {
        /*
         * Silently ignore the bogus key.  We shouldn't abort here,
         * as this could be due to a corrupt recent file.
         *
         * XXX - should we print a message about this?
         */
        return;
    }

    /* save / replace geometry in hashtable */
    window_geom_save(name, &geom);
}

/* write all geometry values of all windows from the hashtable to the recent file */
extern "C" void
window_geom_recent_write_all(gpointer rf)
{
    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }

    g_hash_table_foreach(window_geom_hash, write_recent_geom, rf);
}

/* Make the format_size_flags_e enum usable in C++ */
format_size_flags_e operator|(format_size_flags_e lhs, format_size_flags_e rhs) {
    return (format_size_flags_e) ((int)lhs| (int)rhs);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
