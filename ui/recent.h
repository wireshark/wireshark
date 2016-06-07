/* recent.h
 * Definitions for recent "preference" handling routines
 * Copyright 2004, Ulf Lamping <ulf.lamping@web.de>
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

#ifndef __RECENT_H__
#define __RECENT_H__

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <glib.h>
#include <stdio.h>
#include "epan/timestamp.h"
#include "ui/ui_util.h"

/** @file
 *  Recent user interface settings.
 *  @ingroup main_window_group
 */

/** ???. */
#define RECENT_KEY_CAPTURE_FILE         "recent.capture_file"

/** ???. */
#define RECENT_KEY_DISPLAY_FILTER       "recent.display_filter"

#define RECENT_KEY_COL_WIDTH            "column.width"

#define RECENT_KEY_CAPTURE_FILTER       "recent.capture_filter"

#define RECENT_KEY_REMOTE_HOST          "recent.remote_host"

typedef struct _col_width_data {
    gint   cfmt;
    gchar *cfield;
    gint   width;
    gchar  xalign;
} col_width_data;

/** Defines used in col_width_data.xalign */
#define COLUMN_XALIGN_DEFAULT  0
#define COLUMN_XALIGN_LEFT    'L'
#define COLUMN_XALIGN_CENTER  'C'
#define COLUMN_XALIGN_RIGHT   'R'

typedef enum {
  BYTES_HEX,
  BYTES_BITS
} bytes_view_type;

/** Recent settings. */
typedef struct recent_settings_tag {
    gboolean    main_toolbar_show;
    gboolean    filter_toolbar_show;
    gboolean    wireless_toolbar_show;
    gboolean    airpcap_driver_check_show;
    gboolean    packet_list_show;
    gboolean    tree_view_show;
    gboolean    byte_view_show;
    gboolean    statusbar_show;
    gboolean    packet_list_colorize;
    ts_type     gui_time_format;
    gint        gui_time_precision;
    ts_seconds_type gui_seconds_format;
    gint        gui_zoom_level;
    bytes_view_type gui_bytes_view;

    gint        gui_geometry_main_x;
    gint        gui_geometry_main_y;
    gint        gui_gtk_geometry_main_x;
    gint        gui_gtk_geometry_main_y;
    gint        gui_geometry_main_width;
    gint        gui_geometry_main_height;

    gboolean    gui_geometry_main_maximized;

    gboolean    has_gui_geometry_main_upper_pane;   /* gui_geometry_main_upper_pane is valid */
    gint        gui_geometry_main_upper_pane;
    gboolean    has_gui_geometry_main_lower_pane;   /* gui_geometry_main_lower_pane is valid */
    gint        gui_geometry_main_lower_pane;
    gboolean    has_gui_geometry_status_pane;       /* gui_geometry_status_pane is valid */
    gint        gui_geometry_status_pane_left;
    gint        gui_geometry_status_pane_right;
    gint        gui_geometry_wlan_stats_pane;
    gboolean    privs_warn_if_elevated;
    gboolean    privs_warn_if_no_npf;
    GList      *col_width_list;                     /* column widths */
    GList      *conversation_tabs;                  /* enabled conversation dialog tabs */
    GList      *endpoint_tabs;                      /* enabled endpoint dialog tabs */
    gchar      *gui_fileopen_remembered_dir;        /* folder of last capture loaded in File Open dialog */
    gboolean    gui_rlc_use_pdus_from_mac;
    GList      *custom_colors;
} recent_settings_t;

/** Global recent settings. */
extern recent_settings_t recent;

/** Write recent settings file.
 *
 * @return TRUE if succeeded, FALSE if failed
 */
extern gboolean write_recent(void);

/** Write profile recent settings file.
 *
 * @return TRUE if succeeded, FALSE if failed
 */
extern gboolean write_profile_recent(void);

/** Read recent settings file (static part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return TRUE if succeeded, FALSE if failed (check parameters for reason).
 */
extern gboolean recent_read_static(char **rf_path_return, int *rf_errno_return);

/** Read profile recent settings file (static part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return TRUE if succeeded, FALSE if failed (check parameters for reason).
 */
extern gboolean recent_read_profile_static(char **rf_path_return, int *rf_errno_return);

/** Read recent settings file (dynamic part).
 *
 * @param rf_path_return path to recent file if function failed
 * @param rf_errno_return if failed
 * @return TRUE if succeeded, FALSE if failed (check parameters for reason).
 */
extern gboolean recent_read_dynamic(char **rf_path_return, int *rf_errno_return);

/**
 * Given a -o command line string, parse it and set the recent value in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 *
 * @param prefarg a string of the form "<recent name>:<recent value>", as might appear
 * as an argument to a "-o" command line option
 * @return PREFS_SET_OK or PREFS_SET_SYNTAX_ERR
 */
extern int recent_set_arg(char *prefarg);

/** Get the column width for the given column
 *
 * @param col column number
 */
extern gint recent_get_column_width(gint col);

/** Set the column width for the given column
 *
 * @param col column number
 * @param width column width
 */
extern void recent_set_column_width(gint col, gint width);

/** Get the column xalign for the given column
 *
 * @param col column number
 */
extern gchar recent_get_column_xalign(gint col);

/** Set the column xalign for the given column
 *
 * @param col column number
 * @param xalign column alignment
 */
extern void recent_set_column_xalign(gint col, gchar xalign);

/* save the window and its current geometry into the geometry hashtable */
extern void window_geom_save(const gchar *name, window_geometry_t *geom);

/* load the desired geometry for this window from the geometry hashtable */
extern gboolean window_geom_load(const gchar *name, window_geometry_t *geom);

/**
 * Returns a list of recent capture filters.
 *
 * @param ifname interface name; NULL refers to the global list.
 */
extern GList *recent_get_cfilter_list(const gchar *ifname);

/**
 * Add a capture filter to the global recent capture filter list or
 * the recent capture filter list for an interface.
 *
 * @param ifname interface name; NULL refers to the global list.
 * @param s text of capture filter
 */
extern void recent_add_cfilter(const gchar *ifname, const gchar *s);

/**
 * Get the value of a remote host from the remote_host_list.
 *
 * @param host Host's address
 */
extern struct remote_host *recent_get_remote_host(const gchar *host);

/**
 * Get the number of entries of the remote_host_list.
 *
 * @return size of the hash table
 */
extern int recent_get_remote_host_list_size(void);

/**
 * Get the pointer of the remote_host_list.
 *
 * @return Pointer to the hash table
 */
extern GHashTable *get_remote_host_list(void);

/**
 * Free all entries of the remote_host_list.
 *
 */
extern void free_remote_host_list(void);

/**
 * Add an entry to the remote_host_list.
 *
 * @param host Key of the entry
 * @param rh Vakue of the entry
 */
extern void recent_add_remote_host(gchar *host, struct remote_host *rh);

/**
 * Fill the remote_host_list with the entries stored in the 'recent' file.
 *
 * @param s String to be filled from the 'recent' file.
 * @return True, if the list was written successfully, False otherwise.
 */
extern gboolean capture_remote_combo_add_recent(const gchar *s);

/**
 * Write the contents of the remote_host_list to the 'recent' file.
 *
 * @param rf File to write to.
 */
extern void capture_remote_combo_recent_write_all(FILE *rf);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* recent.h */

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
