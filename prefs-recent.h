/* prefs-recent.h
 * Definitions for recent "preference" handling routines
 * Copyright 2004, Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __RECENT_H__
#define __RECENT_H__

#include <glib.h>

/** @file
 *  Recent user interface settings.
 *  @ingroup main_window_group
 */

/** ???. */
#define RECENT_KEY_CAPTURE_FILE         "recent.capture_file"

/** ???. */
#define RECENT_KEY_DISPLAY_FILTER       "recent.display_filter"

#define RECENT_GUI_GEOMETRY "gui.geom."

/** Recent settings. */
typedef struct recent_settings_tag {
    gboolean    main_toolbar_show;
    gboolean    filter_toolbar_show;
    gboolean    packet_list_show;
    gboolean    tree_view_show;
    gboolean    byte_view_show;
    gboolean    statusbar_show;
    gint        gui_time_format;
    gint        gui_zoom_level;

    gint        gui_geometry_main_x;
    gint        gui_geometry_main_y;
    gint        gui_geometry_main_width;
    gint        gui_geometry_main_height;

    gboolean    gui_geometry_main_maximized;    /* this is valid in GTK2 only */

    gint        gui_geometry_main_upper_pane;   /* this is valid in GTK2 only */
    gint        gui_geometry_main_lower_pane;   /* this is valid in GTK2 only */
    gint        gui_geometry_status_pane;       /* this is valid in GTK2 only */
} recent_settings_t;

/** geometry values for use in window_get_geometry() and window_set_geometry() */
typedef struct window_geometry_s {
    gchar       *key;           /**< current key in hashtable (internally used only) */
    gboolean    set_pos;        /**< set the x and y position values */
    gint        x;              /**< the windows x position */
    gint        y;              /**< the windows y position */
    gboolean    set_size;       /**< set the width and height values */
    gint        width;          /**< the windows width */
    gint        height;         /**< the windows height */

    gboolean    set_maximized;  /**< set the maximized state (GTK2 only) */
    gboolean    maximized;      /**< the windows maximized state (GTK2 only) */
} window_geometry_t;

/** Get the geometry of a window.
 *
 * @param win A pointer to the window.  The actual data type is toolkit-dependent.
 * @param geom The current geometry values of the window.  The set_xy values will not be used.
 * @todo If main uses the window_new_with_geom() to save size and such, make this function static.
 */
extern void window_get_geometry(gpointer win, window_geometry_t *geom);
/** Set the geometry of a window.
 *
 * @param win A pointer to the window.  The actual data type is toolkit-dependent.
 * @param geom The new geometry values of the window.
 * @todo If main uses the window_new_with_geom() to save size and such, make this function static
 */
extern void window_set_geometry(gpointer win, window_geometry_t *geom);


/** Global recent settings. */
extern recent_settings_t recent;

/** Write recent settings file.
 *
 * @param rf_path_return path to recent file if function failed
 * @return 0 if succeeded, errno if failed
 */
extern int write_recent(char **rf_path_return);

/** Read recent settings file.
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 */
extern void read_recent(char **rf_path_return, int *rf_errno_return);

/** Write the geometry values of a single window to the recent file.
 *
 * @param key unused
 * @param value the geometry values
 * @param rf recent file handle (FILE)
 */
extern void write_recent_geom(gpointer key, gpointer value, gpointer rf);

/*
 * These routines must be defined by each interface implementation (GTK+,
 * Windows, etc.).
 */

/** Add the capture filename (with an absolute path) to the "Recent Files" menu.
 *
 * @param cf_name Full path to capture file
 */
extern void add_menu_recent_capture_file(gchar *cf_name);

/** Write all recent capture filenames to the user's recent file.
 *
 * @param rf "Recent" file handle from caller
 */
extern void menu_recent_file_write_all(FILE *rf);

/** Write all non empty display filters (until maximum count)
 *  of the combo box GList to the user's recent file.
 *
 * @param rf "Recent" file handle from caller
 */
extern void dfilter_recent_combo_write_all(FILE *rf);

/** Write all geometry values of all windows to the recent file.
 * Will call write_recent_geom() for every existing window type.
 *
 * @param rf "Recent" file handle from caller
 */
extern void window_geom_recent_write_all(gpointer rf);

/** Read in a single geometry key value pair from the recent file.
 *
 * @param name The geom_name of the window
 * @param key The subkey of this pair (e.g. "x")
 * @param value The new value (e.g. "123")
 */
extern void window_geom_recent_read_pair(const char *name, const char *key, const char *value);

/** Add a display filter coming from the user's recent file to the dfilter
 *  combo box.
 *
 * @param dftext The filter string
 */
extern gboolean dfilter_combo_add_recent(gchar *dftext);

/** Empty out the combobox entry field */
extern void dfilter_combo_add_empty(void);

/** Get the latest opened directory.
 *
 * @return the dirname
 */
extern char *get_last_open_dir(void);

/** Set the latest opened directory.
 *  Will already be done when using file_selection_new().
 *
 * @param dirname the dirname
 */
extern void set_last_open_dir(char *dirname);

/** Save the window and it's current geometry into the geometry hashtable
 *
 * @param name The window name
 * @param geom The window geometry
 */
extern void
window_geom_save(const gchar *name, window_geometry_t *geom);

/* Load the desired geometry for this window from the geometry hashtable
 *
 * @param name The window name
 * @param geom The window geometry
 */
extern gboolean
window_geom_load(const gchar *name, window_geometry_t *geom);


#endif /* prefs-recent.h */
