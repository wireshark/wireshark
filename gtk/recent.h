/* recent.h
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

#endif /* recent.h */
