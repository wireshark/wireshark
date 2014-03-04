/* recent.c
 * Recent "preference" handling routines
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

#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <epan/epan.h>
#include <wsutil/filesystem.h>
#include <epan/emem.h>
#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/column.h>
#include <epan/timestamp.h>

#include "ui/last_open_dir.h"
#include "ui/recent.h"
#include "ui/recent_utils.h"
#include "ui/simple_dialog.h"
#include "ui/ui_util.h"

#include <wsutil/u3.h>
#include <wsutil/file_util.h>
#include <wsutil/str_util.h>

#define RECENT_KEY_MAIN_TOOLBAR_SHOW        "gui.toolbar_main_show"
#define RECENT_KEY_FILTER_TOOLBAR_SHOW      "gui.filter_toolbar_show"
#define RECENT_KEY_WIRELESS_TOOLBAR_SHOW    "gui.wireless_toolbar_show"
#define RECENT_KEY_DRIVER_CHECK_SHOW        "gui.airpcap_driver_check_show"
#define RECENT_KEY_PACKET_LIST_SHOW         "gui.packet_list_show"
#define RECENT_KEY_TREE_VIEW_SHOW           "gui.tree_view_show"
#define RECENT_KEY_BYTE_VIEW_SHOW           "gui.byte_view_show"
#define RECENT_KEY_STATUSBAR_SHOW           "gui.statusbar_show"
#define RECENT_KEY_PACKET_LIST_COLORIZE     "gui.packet_list_colorize"
#define RECENT_GUI_TIME_FORMAT              "gui.time_format"
#define RECENT_GUI_TIME_PRECISION           "gui.time_precision"
#define RECENT_GUI_SECONDS_FORMAT           "gui.seconds_format"
#define RECENT_GUI_ZOOM_LEVEL               "gui.zoom_level"
#define RECENT_GUI_BYTES_VIEW               "gui.bytes_view"
#define RECENT_GUI_GEOMETRY_MAIN_X          "gui.geometry_main_x"
#define RECENT_GUI_GEOMETRY_MAIN_Y          "gui.geometry_main_y"
#define RECENT_GUI_GEOMETRY_MAIN_WIDTH      "gui.geometry_main_width"
#define RECENT_GUI_GEOMETRY_MAIN_HEIGHT     "gui.geometry_main_height"
#define RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED  "gui.geometry_main_maximized"
#define RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE "gui.geometry_main_upper_pane"
#define RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE "gui.geometry_main_lower_pane"
#define RECENT_GUI_GEOMETRY_STATUS_PANE_LEFT  "gui.geometry_status_pane"
#define RECENT_GUI_GEOMETRY_STATUS_PANE_RIGHT "gui.geometry_status_pane_right"
#define RECENT_GUI_GEOMETRY_WLAN_STATS_PANE "gui.geometry_status_wlan_stats_pane"
#define RECENT_LAST_USED_PROFILE            "gui.last_used_profile"
#define RECENT_GUI_FILEOPEN_REMEMBERED_DIR  "gui.fileopen_remembered_dir"
#define RECENT_GUI_GEOMETRY                 "gui.geom."
#define RECENT_KEY_PRIVS_WARN_IF_ELEVATED   "privs.warn_if_elevated"
#define RECENT_KEY_PRIVS_WARN_IF_NO_NPF     "privs.warn_if_no_npf"

#define RECENT_FILE_NAME "recent"
#define RECENT_COMMON_FILE_NAME "recent_common"

recent_settings_t recent;

static const char *ts_type_text[] =
  { "RELATIVE", "ABSOLUTE", "ABSOLUTE_WITH_DATE", "DELTA", "DELTA_DIS", "EPOCH", "UTC", "UTC_WITH_DATE", NULL };

static const char *ts_precision_text[] =
	{ "AUTO", "SEC", "DSEC", "CSEC", "MSEC", "USEC", "NSEC", NULL };

static const char *ts_seconds_text[] =
  { "SECONDS", "HOUR_MIN_SEC", NULL };

/* Takes an string and a pointer to an array of strings, and a default int value.
 * The array must be terminated by a NULL string. If the string is found in the array
 * of strings, the index of that string in the array is returned. Otherwise, the
 * default value that was passed as the third argument is returned.
 */
static int
find_index_from_string_array(const char *needle, const char **haystack, int default_value)
{
	int i = 0;

	while (haystack[i] != NULL) {
		if (strcmp(needle, haystack[i]) == 0) {
			return i;
		}
		i++;
	}
	return default_value;
}

static void
free_col_width_info(recent_settings_t *rs)
{
  col_width_data *cfmt;

  while (rs->col_width_list != NULL) {
    cfmt = (col_width_data *)rs->col_width_list->data;
    g_free(cfmt->cfield);
    g_free(cfmt);
    rs->col_width_list = g_list_remove_link(rs->col_width_list, rs->col_width_list);
  }
  g_list_free(rs->col_width_list);
  rs->col_width_list = NULL;
}

/** Write the geometry values of a single window to the recent file.
 *
 * @param key unused
 * @param value the geometry values
 * @param rfh recent file handle (FILE)
 */
static void
write_recent_geom(gpointer key _U_, gpointer value, gpointer rfh)
{
    window_geometry_t *geom = (window_geometry_t *)value;
    FILE *rf = (FILE *)rfh;

    fprintf(rf, "\n# Geometry and maximized state of %s window.\n", geom->key);
    fprintf(rf, "# Decimal integers.\n");
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.x: %d\n", geom->key, geom->x);
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.y: %d\n", geom->key, geom->y);
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.width: %d\n", geom->key,
  	      geom->width);
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.height: %d\n", geom->key,
  	      geom->height);

    fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
    fprintf(rf, RECENT_GUI_GEOMETRY "%s.maximized: %s\n", geom->key,
	      geom->maximized == TRUE ? "TRUE" : "FALSE");

}

/* the geometry hashtable for all known window classes,
 * the window name is the key, and the geometry struct is the value */
static GHashTable *window_geom_hash = NULL;

/* save the window and its current geometry into the geometry hashtable */
void
window_geom_save(const gchar *name, window_geometry_t *geom)
{
    gchar *key;
    window_geometry_t *work;

    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new(g_str_hash, g_str_equal);
    }
    /* if we have an old one, remove and free it first */
    work = (window_geometry_t *)g_hash_table_lookup(window_geom_hash, name);
    if(work) {
        g_hash_table_remove(window_geom_hash, name);
        g_free(work->key);
        g_free(work);
    }

    /* g_malloc and insert the new one */
    work = (window_geometry_t *)g_malloc(sizeof(window_geometry_t));
    *work = *geom;
    key = g_strdup(name);
    work->key = key;
    g_hash_table_insert(window_geom_hash, key, work);
}

/* load the desired geometry for this window from the geometry hashtable */
gboolean
window_geom_load(const gchar       *name,
                 window_geometry_t *geom)
{
    window_geometry_t *p;

    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new(g_str_hash, g_str_equal);
    }

    p = (window_geometry_t *)g_hash_table_lookup(window_geom_hash, name);
    if(p) {
        *geom = *p;
        return TRUE;
    } else {
        return FALSE;
    }
}

/** Read in a single geometry key value pair from the recent file.
 *
 * @param name the geom_name of the window
 * @param key the subkey of this pair (e.g. "x")
 * @param value the new value (e.g. "123")
 */
static void
window_geom_recent_read_pair(const char *name,
                             const char *key,
                             const char *value)
{
  window_geometry_t geom;

  /* find window geometry maybe already in hashtable */
  if(!window_geom_load(name, &geom)) {
    /* not in table, init geom with "basic" values */
    geom.key        = NULL;    /* Will be set in window_geom_save() */
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
    geom.x = (gint)strtol(value, NULL, 10);
    geom.set_pos = TRUE;
  } else if (strcmp(key, "y") == 0) {
    geom.y = (gint)strtol(value, NULL, 10);
    geom.set_pos = TRUE;
  } else if (strcmp(key, "width") == 0) {
    geom.width = (gint)strtol(value, NULL, 10);
    geom.set_size = TRUE;
  } else if (strcmp(key, "height") == 0) {
    geom.height = (gint)strtol(value, NULL, 10);
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

/** Write all geometry values of all windows to the recent file.
 * Will call write_recent_geom() for every existing window type.
 *
 * @param rf recent file handle from caller
 */
static void
window_geom_recent_write_all(FILE *rf)
{
  /* init hashtable, if not already done */
  if(!window_geom_hash) {
    window_geom_hash = g_hash_table_new(g_str_hash, g_str_equal);
  }

  g_hash_table_foreach(window_geom_hash, write_recent_geom, rf);
}

/* Global list of recent capture filters. */
static GList *recent_cfilter_list;

/*
 * Per-interface lists of recent capture filters; stored in a hash
 * table indexed by interface name.
 */
static GHashTable *per_interface_cfilter_lists_hash;

/* XXX: use a preference for this setting! */
static guint cfilter_combo_max_recent = 20;

/**
 * Returns a list of recent capture filters.
 *
 * @param ifname interface name; NULL refers to the global list.
 */
GList *
recent_get_cfilter_list(const gchar *ifname)
{
  if (ifname == NULL)
    return recent_cfilter_list;
  if (per_interface_cfilter_lists_hash == NULL) {
    /* No such lists exist. */
    return NULL;
  }
  return (GList *)g_hash_table_lookup(per_interface_cfilter_lists_hash, ifname);
}

/**
 * Add a capture filter to the global recent capture filter list or
 * the recent capture filter list for an interface.
 *
 * @param ifname interface name; NULL refers to the global list.
 * @param s text of capture filter
 */
void
recent_add_cfilter(const gchar *ifname, const gchar *s)
{
  GList     *cfilter_list;
  GList     *li;
  gchar     *li_filter, *newfilter = NULL;

  /* Don't add empty filters to the list. */
  if (s[0] == '\0')
    return;

  if (ifname == NULL)
    cfilter_list = recent_cfilter_list;
  else {
    /* If we don't yet have a hash table for per-interface recent
       capture filter lists, create one.  Have it free the new key
       if we're updating an entry rather than creating it below. */
    if (per_interface_cfilter_lists_hash == NULL)
      per_interface_cfilter_lists_hash = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL);
    cfilter_list = (GList *)g_hash_table_lookup(per_interface_cfilter_lists_hash, ifname);
  }

  li = g_list_first(cfilter_list);
  while (li) {
    /* If the filter is already in the list, remove the old one and
     * append the new one at the latest position (at g_list_append() below) */
    li_filter = (char *)li->data;
    if (strcmp(s, li_filter) == 0) {
      /* No need to copy the string, we're just moving it. */
      newfilter = li_filter;
      cfilter_list = g_list_remove(cfilter_list, li->data);
      break;
    }
    li = li->next;
  }
  if (newfilter == NULL) {
    /* The filter wasn't already in the list; make a copy to add. */
    newfilter = g_strdup(s);
  }
  cfilter_list = g_list_append(cfilter_list, newfilter);

  if (ifname == NULL)
    recent_cfilter_list = cfilter_list;
  else
    g_hash_table_insert(per_interface_cfilter_lists_hash, g_strdup(ifname), cfilter_list);
}

static void
cfilter_recent_write_all_list(FILE *rf, const gchar *ifname, GList *cfilter_list)
{
  guint      max_count = 0;
  GList     *li;

  /* write all non empty capture filter strings to the recent file (until max count) */
  li = g_list_first(cfilter_list);
  while (li && (max_count++ <= cfilter_combo_max_recent) ) {
    if (li->data && strlen((const char *)li->data)) {
      if (ifname == NULL)
        fprintf (rf, RECENT_KEY_CAPTURE_FILTER ": %s\n", (char *)li->data);
      else
        fprintf (rf, RECENT_KEY_CAPTURE_FILTER ".%s: %s\n", ifname, (char *)li->data);
    }
    li = li->next;
  }
}

static void
cfilter_recent_write_all_hash_callback(gpointer key, gpointer value, gpointer user_data)
{
  cfilter_recent_write_all_list((FILE *)user_data, (const gchar *)key, (GList *)value);
}

/** Write all capture filter values to the recent file.
 *
 * @param rf recent file handle from caller
 */
static void
cfilter_recent_write_all(FILE *rf)
{
  /* Write out the global list. */
  cfilter_recent_write_all_list(rf, NULL, recent_cfilter_list);

  /* Write out all the per-interface lists. */
  if (per_interface_cfilter_lists_hash != NULL) {
    g_hash_table_foreach(per_interface_cfilter_lists_hash, cfilter_recent_write_all_hash_callback, (gpointer)rf);
  }
}

/* Attempt to Write out "recent common" to the user's recent common file.
   If we got an error report it with a dialog box and return FALSE,
   otherwise return TRUE. */
gboolean
write_recent(void)
{
  char        *pf_dir_path;
  char        *rf_path;
  FILE        *rf;

  /* To do:
   * - Split output lines longer than MAX_VAL_LEN
   * - Create a function for the preference directory check/creation
   *   so that duplication can be avoided with filter.c
   */

  /* Create the directory that holds personal configuration files, if
     necessary.  */
  if (create_persconffile_dir(&pf_dir_path) == -1) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "Can't create directory\n\"%s\"\nfor recent file: %s.", pf_dir_path,
      g_strerror(errno));
     g_free(pf_dir_path);
     return FALSE;
  }

  rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, FALSE);
  if ((rf = ws_fopen(rf_path, "w")) == NULL) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "Can't open recent file\n\"%s\": %s.", rf_path,
      g_strerror(errno));
    g_free(rf_path);
    return FALSE;
  }
  g_free(rf_path);

  fputs("# Recent settings file for Wireshark " VERSION ".\n"
    "#\n"
    "# This file is regenerated each time Wireshark is quit.\n"
    "# So be careful, if you want to make manual changes here.\n"
    "\n"
    "######## Recent capture files (latest last), cannot be altered through command line ########\n"
    "\n", rf);

  menu_recent_file_write_all(rf);

  fputs("\n"
    "######## Recent capture filters (latest last), cannot be altered through command line ########\n"
    "\n", rf);

  cfilter_recent_write_all(rf);

  fputs("\n"
    "######## Recent display filters (latest last), cannot be altered through command line ########\n"
    "\n", rf);

  dfilter_recent_combo_write_all(rf);

#ifdef HAVE_PCAP_REMOTE
  fputs("\n"
    "######## Recent remote hosts, cannot be altered through command line ########\n"
    "\n", rf);

  capture_remote_combo_recent_write_all(rf);
#endif

  fprintf(rf, "\n# Main window geometry.\n");
  fprintf(rf, "# Decimal numbers.\n");
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_X ": %d\n", recent.gui_geometry_main_x);
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_Y ": %d\n", recent.gui_geometry_main_y);
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_WIDTH ": %d\n",
  		  recent.gui_geometry_main_width);
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_HEIGHT ": %d\n",
  		  recent.gui_geometry_main_height);

  fprintf(rf, "\n# Main window maximized.\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED ": %s\n",
		  recent.gui_geometry_main_maximized == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Statusbar left pane size.\n");
  fprintf(rf, "# Decimal number.\n");
  if (recent.gui_geometry_status_pane_left != 0) {
    fprintf(rf, RECENT_GUI_GEOMETRY_STATUS_PANE_LEFT ": %d\n",
		  recent.gui_geometry_status_pane_left);
  }
  fprintf(rf, "\n# Statusbar middle pane size.\n");
  fprintf(rf, "# Decimal number.\n");
  if (recent.gui_geometry_status_pane_right != 0) {
    fprintf(rf, RECENT_GUI_GEOMETRY_STATUS_PANE_RIGHT ": %d\n",
		  recent.gui_geometry_status_pane_right);
  }

  fprintf(rf, "\n# Last used Configuration Profile.\n");
  fprintf(rf, RECENT_LAST_USED_PROFILE ": %s\n", get_profile_name());

  fprintf(rf, "\n# WLAN statistics upper pane size.\n");
  fprintf(rf, "# Decimal number.\n");
  fprintf(rf, RECENT_GUI_GEOMETRY_WLAN_STATS_PANE ": %d\n",
	  recent.gui_geometry_wlan_stats_pane);

  fprintf(rf, "\n# Warn if running with elevated permissions (e.g. as root).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_PRIVS_WARN_IF_ELEVATED ": %s\n",
		  recent.privs_warn_if_elevated == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Warn if npf.sys isn't loaded on Windows >= 6.0.\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_PRIVS_WARN_IF_NO_NPF ": %s\n",
		  recent.privs_warn_if_no_npf == TRUE ? "TRUE" : "FALSE");

  window_geom_recent_write_all(rf);

  fclose(rf);

  /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
     an error indication, or maybe write to a new recent file and
     rename that file on top of the old one only if there are not I/O
     errors. */
  return TRUE;
}


/* Attempt to Write out profile "recent" to the user's profile recent file.
   If we got an error report it with a dialog box and return FALSE,
   otherwise return TRUE. */
gboolean
write_profile_recent(void)
{
  char        *pf_dir_path;
  char        *rf_path;
  FILE        *rf;

  /* To do:
   * - Split output lines longer than MAX_VAL_LEN
   * - Create a function for the preference directory check/creation
   *   so that duplication can be avoided with filter.c
   */

  /* Create the directory that holds personal configuration files, if
     necessary.  */
  if (create_persconffile_dir(&pf_dir_path) == -1) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "Can't create directory\n\"%s\"\nfor recent file: %s.", pf_dir_path,
      g_strerror(errno));
     g_free(pf_dir_path);
     return FALSE;
  }

  rf_path = get_persconffile_path(RECENT_FILE_NAME, TRUE);
  if ((rf = ws_fopen(rf_path, "w")) == NULL) {
     simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK,
      "Can't open recent file\n\"%s\": %s.", rf_path,
      g_strerror(errno));
    g_free(rf_path);
    return FALSE;
  }
  g_free(rf_path);

  fputs("# Recent settings file for Wireshark " VERSION ".\n"
    "#\n"
    "# This file is regenerated each time Wireshark is quit\n"
    "# and when changing configuration profile.\n"
    "# So be careful, if you want to make manual changes here.\n"
    "\n", rf);

  fprintf(rf, "\n# Main Toolbar show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_MAIN_TOOLBAR_SHOW ": %s\n",
		  recent.main_toolbar_show == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Filter Toolbar show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_FILTER_TOOLBAR_SHOW ": %s\n",
		  recent.filter_toolbar_show == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Wireless Settings Toolbar show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_WIRELESS_TOOLBAR_SHOW ": %s\n",
		  recent.wireless_toolbar_show == TRUE ? "TRUE" : "FALSE");

#ifdef HAVE_AIRPCAP
  fprintf(rf, "\n# Show (hide) old AirPcap driver warning dialog box.\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_DRIVER_CHECK_SHOW ": %s\n",
		  recent.airpcap_driver_check_show == TRUE ? "TRUE" : "FALSE");
#endif

  fprintf(rf, "\n# Packet list show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_PACKET_LIST_SHOW ": %s\n",
		  recent.packet_list_show == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Tree view show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_TREE_VIEW_SHOW ": %s\n",
		  recent.tree_view_show == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Byte view show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_BYTE_VIEW_SHOW ": %s\n",
		  recent.byte_view_show == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Statusbar show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_STATUSBAR_SHOW ": %s\n",
		  recent.statusbar_show == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Packet list colorize (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_PACKET_LIST_COLORIZE ": %s\n",
		  recent.packet_list_colorize == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Timestamp display format.\n");
  fprintf(rf, "# One of: RELATIVE, ABSOLUTE, ABSOLUTE_WITH_DATE, DELTA, DELTA_DIS, EPOCH, UTC, UTC_WITH_DATE\n");
  fprintf(rf, RECENT_GUI_TIME_FORMAT ": %s\n",
          ts_type_text[recent.gui_time_format]);

  fprintf(rf, "\n# Timestamp display precision.\n");
  fprintf(rf, "# One of: AUTO, SEC, DSEC, CSEC, MSEC, USEC, NSEC\n");
  fprintf(rf, RECENT_GUI_TIME_PRECISION ": %s\n",
          ts_precision_text[recent.gui_time_precision]);

  fprintf(rf, "\n# Seconds display format.\n");
  fprintf(rf, "# One of: SECONDS, HOUR_MIN_SEC\n");
  fprintf(rf, RECENT_GUI_SECONDS_FORMAT ": %s\n",
          ts_seconds_text[recent.gui_seconds_format]);

  fprintf(rf, "\n# Zoom level.\n");
  fprintf(rf, "# A decimal number.\n");
  fprintf(rf, RECENT_GUI_ZOOM_LEVEL ": %d\n",
		  recent.gui_zoom_level);

  fprintf(rf, "\n# Bytes view.\n");
  fprintf(rf, "# A decimal number.\n");
  fprintf(rf, RECENT_GUI_BYTES_VIEW ": %d\n",
		  recent.gui_bytes_view);

  fprintf(rf, "\n# Main window upper (or leftmost) pane size.\n");
  fprintf(rf, "# Decimal number.\n");
  if (recent.gui_geometry_main_upper_pane != 0) {
    fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE ": %d\n",
		  recent.gui_geometry_main_upper_pane);
  }
  fprintf(rf, "\n# Main window middle pane size.\n");
  fprintf(rf, "# Decimal number.\n");
  if (recent.gui_geometry_main_lower_pane != 0) {
    fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE ": %d\n",
		  recent.gui_geometry_main_lower_pane);
  }

  fprintf(rf, "\n# Packet list column pixel widths.\n");
  fprintf(rf, "# Each pair of strings consists of a column format and its pixel width.\n");
  packet_list_recent_write_all(rf);

  if (get_last_open_dir() != NULL) {
    fprintf(rf, "\n# Last directory navigated to in File Open dialog.\n");

    if(u3_active())
      fprintf(rf, RECENT_GUI_FILEOPEN_REMEMBERED_DIR ": %s\n", u3_contract_device_path(get_last_open_dir()));
    else
      fprintf(rf, RECENT_GUI_FILEOPEN_REMEMBERED_DIR ": %s\n", get_last_open_dir());
  }

  fclose(rf);

  /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
     an error indication, or maybe write to a new recent file and
     rename that file on top of the old one only if there are not I/O
     errors. */
  return TRUE;
}

/* set one user's recent common file key/value pair */
static prefs_set_pref_e
read_set_recent_common_pair_static(gchar *key, const gchar *value,
				   void *private_data _U_,
				   gboolean return_range_errors _U_)
{
  long num;
  char *p;

  if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.gui_geometry_main_maximized = TRUE;
    }
    else {
        recent.gui_geometry_main_maximized = FALSE;
    }

  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_X) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    recent.gui_geometry_main_x = (gint)num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_Y) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    recent.gui_geometry_main_y = (gint)num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_WIDTH) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_main_width = (gint)num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_HEIGHT) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_main_height = (gint)num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_STATUS_PANE_RIGHT) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_status_pane_right = (gint)num;
    recent.has_gui_geometry_status_pane = TRUE;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_STATUS_PANE_LEFT) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_status_pane_left = (gint)num;
    recent.has_gui_geometry_status_pane = TRUE;
  } else if (strcmp(key, RECENT_LAST_USED_PROFILE) == 0) {
    if ((strcmp(value, DEFAULT_PROFILE) != 0) && profile_exists (value, FALSE)) {
      set_profile_name (value);
    }
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_WLAN_STATS_PANE) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_wlan_stats_pane = (gint)num;
  } else if (strncmp(key, RECENT_GUI_GEOMETRY, sizeof(RECENT_GUI_GEOMETRY)-1) == 0) {
    /* now have something like "gui.geom.main.x", split it into win and sub_key */
    char *win = &key[sizeof(RECENT_GUI_GEOMETRY)-1];
    char *sub_key = strchr(win, '.');
    if(sub_key) {
      *sub_key = '\0';
      sub_key++;
      window_geom_recent_read_pair(win, sub_key, value);
    }
  } else if (strcmp(key, RECENT_KEY_PRIVS_WARN_IF_ELEVATED) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.privs_warn_if_elevated = TRUE;
    }
    else {
        recent.privs_warn_if_elevated = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_PRIVS_WARN_IF_NO_NPF) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.privs_warn_if_no_npf = TRUE;
    }
    else {
        recent.privs_warn_if_no_npf = FALSE;
    }
  }

  return PREFS_SET_OK;
}

/* set one user's recent file key/value pair */
static prefs_set_pref_e
read_set_recent_pair_static(gchar *key, const gchar *value,
			    void *private_data _U_,
			    gboolean return_range_errors _U_)
{
  long num;
  char *p;
  GList *col_l, *col_l_elt;
  col_width_data *cfmt;
  const gchar *cust_format = col_format_to_string(COL_CUSTOM);
  int cust_format_len = (int) strlen(cust_format);

  if (strcmp(key, RECENT_KEY_MAIN_TOOLBAR_SHOW) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.main_toolbar_show = TRUE;
    }
    else {
        recent.main_toolbar_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_FILTER_TOOLBAR_SHOW) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.filter_toolbar_show = TRUE;
    }
    else {
        recent.filter_toolbar_show = FALSE;
    }
  /* check both the old and the new keyword */
  } else if (strcmp(key, RECENT_KEY_WIRELESS_TOOLBAR_SHOW) == 0 || (strcmp(key, "gui.airpcap_toolbar_show") == 0)) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.wireless_toolbar_show = TRUE;
    }
    else {
        recent.wireless_toolbar_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_DRIVER_CHECK_SHOW) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.airpcap_driver_check_show = TRUE;
    }
    else {
        recent.airpcap_driver_check_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_PACKET_LIST_SHOW) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.packet_list_show = TRUE;
    }
    else {
        recent.packet_list_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_TREE_VIEW_SHOW) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.tree_view_show = TRUE;
    }
    else {
        recent.tree_view_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_BYTE_VIEW_SHOW) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.byte_view_show = TRUE;
    }
    else {
        recent.byte_view_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_STATUSBAR_SHOW) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.statusbar_show = TRUE;
    }
    else {
        recent.statusbar_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_PACKET_LIST_COLORIZE) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.packet_list_colorize = TRUE;
    }
    else {
        recent.packet_list_colorize = FALSE;
    }
  } else if (strcmp(key, RECENT_GUI_TIME_FORMAT) == 0) {
    recent.gui_time_format =
	(ts_type)find_index_from_string_array(value, ts_type_text, TS_RELATIVE);
  } else if (strcmp(key, RECENT_GUI_TIME_PRECISION) == 0) {
    recent.gui_time_precision =
	find_index_from_string_array(value, ts_precision_text, TS_PREC_AUTO);
  } else if (strcmp(key, RECENT_GUI_SECONDS_FORMAT) == 0) {
    recent.gui_seconds_format =
	(ts_seconds_type)find_index_from_string_array(value, ts_seconds_text, TS_SECONDS_DEFAULT);
  } else if (strcmp(key, RECENT_GUI_ZOOM_LEVEL) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    recent.gui_zoom_level = (gint)num;
  } else if (strcmp(key, RECENT_GUI_BYTES_VIEW) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    recent.gui_bytes_view = (gint)num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED) == 0) {
    if (g_ascii_strcasecmp(value, "true") == 0) {
        recent.gui_geometry_main_maximized = TRUE;
    }
    else {
        recent.gui_geometry_main_maximized = FALSE;
    }

  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_main_upper_pane = (gint)num;
    recent.has_gui_geometry_main_upper_pane = TRUE;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_main_lower_pane = (gint)num;
    recent.has_gui_geometry_main_lower_pane = TRUE;
  }
  else if (strcmp(key, RECENT_KEY_COL_WIDTH) == 0) {
    col_l = prefs_get_string_list(value);
    if (col_l == NULL)
      return PREFS_SET_SYNTAX_ERR;
    if ((g_list_length(col_l) % 2) != 0) {
      /* A title didn't have a matching width.  */
      prefs_clear_string_list(col_l);
      return PREFS_SET_SYNTAX_ERR;
    }
    /* Check to make sure all column formats are valid.  */
    col_l_elt = g_list_first(col_l);
    while(col_l_elt) {
      /* Make sure the format isn't empty.  */
      if (strcmp((const char *)col_l_elt->data, "") == 0) {
      	/* It is.  */
        prefs_clear_string_list(col_l);
        return PREFS_SET_SYNTAX_ERR;
      }

      /* Check the format.  */
      if (strncmp((const char *)col_l_elt->data, cust_format, cust_format_len) != 0) {
        if (get_column_format_from_str((const gchar *)col_l_elt->data) == -1) {
          /* It's not a valid column format.  */
          prefs_clear_string_list(col_l);
          return PREFS_SET_SYNTAX_ERR;
        }
      }

      /* Go past the format.  */
      col_l_elt = col_l_elt->next;

      /* Go past the width.  */
      col_l_elt = col_l_elt->next;
    }
    free_col_width_info(&recent);
    recent.col_width_list = NULL;
    col_l_elt = g_list_first(col_l);
    while(col_l_elt) {
      gchar *fmt = g_strdup((const gchar *)col_l_elt->data);
      cfmt = (col_width_data *) g_malloc(sizeof(col_width_data));
      if (strncmp(fmt, cust_format, cust_format_len) != 0) {
	cfmt->cfmt   = get_column_format_from_str(fmt);
	cfmt->cfield = NULL;
      } else {
	cfmt->cfmt   = COL_CUSTOM;
	cfmt->cfield = g_strdup(&fmt[cust_format_len+1]);  /* add 1 for ':' */
      }
      g_free (fmt);
      if (cfmt->cfmt == -1) {
        g_free(cfmt->cfield);
	g_free(cfmt);
	return PREFS_SET_SYNTAX_ERR;   /* string was bad */
      }

      col_l_elt      = col_l_elt->next;
      cfmt->width    = (gint)strtol((const char *)col_l_elt->data, &p, 0);
      if (p == col_l_elt->data || (*p != '\0' && *p != ':')) {
	g_free(cfmt->cfield);
	g_free(cfmt);
	return PREFS_SET_SYNTAX_ERR;	/* number was bad */
      }

      if (*p == ':') {
        cfmt->xalign = *(++p);
      } else {
        cfmt->xalign = COLUMN_XALIGN_DEFAULT;
      }

      col_l_elt      = col_l_elt->next;
      recent.col_width_list = g_list_append(recent.col_width_list, cfmt);
    }
    prefs_clear_string_list(col_l);
  } else if (strcmp(key, RECENT_GUI_FILEOPEN_REMEMBERED_DIR) == 0) {
    if (recent.gui_fileopen_remembered_dir) {
      g_free (recent.gui_fileopen_remembered_dir);
    }
    recent.gui_fileopen_remembered_dir = g_strdup(value);
  }

  return PREFS_SET_OK;
}


/* set one user's recent file key/value pair */
static prefs_set_pref_e
read_set_recent_pair_dynamic(gchar *key, const gchar *value,
			     void *private_data _U_,
			     gboolean return_range_errors _U_)
{
  if (!isprint_string(value)) {
    return PREFS_SET_SYNTAX_ERR;
  }
  if (strcmp(key, RECENT_KEY_CAPTURE_FILE) == 0) {
    if (u3_active())
      add_menu_recent_capture_file(u3_expand_device_path(value));
    else
      add_menu_recent_capture_file(value);
  } else if (strcmp(key, RECENT_KEY_DISPLAY_FILTER) == 0) {
	dfilter_combo_add_recent(value);
  } else if (strcmp(key, RECENT_KEY_CAPTURE_FILTER) == 0) {
    recent_add_cfilter(NULL, value);
  } else if (g_str_has_prefix(key, RECENT_KEY_CAPTURE_FILTER ".")) {
    /* strrchr() can't fail - string has a prefix that ends with a "." */
    recent_add_cfilter(strrchr(key, '.') + 1, value);
#ifdef HAVE_PCAP_REMOTE
  } else if (strcmp(key, RECENT_KEY_REMOTE_HOST) == 0) {
	capture_remote_combo_add_recent(value);
#endif
  }

  return PREFS_SET_OK;
}


/*
 * Given a string of the form "<recent name>:<recent value>", as might appear
 * as an argument to a "-o" option, parse it and set the recent value in
 * question.  Return an indication of whether it succeeded or failed
 * in some fashion.
 */
int
recent_set_arg(char *prefarg)
{
	gchar *p, *colonp;
	int ret;

	colonp = strchr(prefarg, ':');
	if (colonp == NULL)
		return PREFS_SET_SYNTAX_ERR;

	p = colonp;
	*p++ = '\0';

	/*
	 * Skip over any white space (there probably won't be any, but
	 * as we allow it in the preferences file, we might as well
	 * allow it here).
	 */
	while (isspace((guchar)*p))
		p++;
	if (*p == '\0') {
		/*
		 * Put the colon back, so if our caller uses, in an
		 * error message, the string they passed us, the message
		 * looks correct.
		 */
		*colonp = ':';
		return PREFS_SET_SYNTAX_ERR;
	}

	ret = read_set_recent_pair_static(prefarg, p, NULL, TRUE);
	*colonp = ':';	/* put the colon back */
	return ret;
}


/* opens the user's recent common file and read the first part */
void
recent_read_static(char **rf_path_return, int *rf_errno_return)
{
  char       *rf_path;
  FILE       *rf;

  /* set defaults */
  recent.gui_geometry_main_x        =        20;
  recent.gui_geometry_main_y        =        20;
  recent.gui_geometry_main_width    = DEF_WIDTH;
  recent.gui_geometry_main_height   = DEF_HEIGHT;
  recent.gui_geometry_main_maximized=     FALSE;

  recent.gui_geometry_status_pane_left  = (DEF_WIDTH/3);
  recent.gui_geometry_status_pane_right = (DEF_WIDTH/3);
  recent.gui_geometry_wlan_stats_pane = 200;

  recent.privs_warn_if_elevated = TRUE;
  recent.privs_warn_if_no_npf = TRUE;

  recent.col_width_list = NULL;
  recent.gui_fileopen_remembered_dir = NULL;

  /* Construct the pathname of the user's recent common file. */
  rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, FALSE);

  /* Read the user's recent common file, if it exists. */
  *rf_path_return = NULL;
  if ((rf = ws_fopen(rf_path, "r")) != NULL) {
    /* We succeeded in opening it; read it. */
    read_prefs_file(rf_path, rf, read_set_recent_common_pair_static, NULL);

    fclose(rf);
    g_free(rf_path);
    rf_path = NULL;
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *rf_errno_return = errno;
      *rf_path_return = rf_path;
    }
  }
}



/* opens the user's recent file and read the first part */
void
recent_read_profile_static(char **rf_path_return, int *rf_errno_return)
{
  char       *rf_path, *rf_common_path;
  FILE       *rf;

  /* set defaults */
  recent.main_toolbar_show      = TRUE;
  recent.filter_toolbar_show    = TRUE;
  recent.wireless_toolbar_show   = FALSE;
  recent.airpcap_driver_check_show   = TRUE;
  recent.packet_list_show       = TRUE;
  recent.tree_view_show         = TRUE;
  recent.byte_view_show         = TRUE;
  recent.statusbar_show         = TRUE;
  recent.packet_list_colorize   = TRUE;
  recent.gui_time_format        = TS_RELATIVE;
  recent.gui_time_precision     = TS_PREC_AUTO;
  recent.gui_seconds_format     = TS_SECONDS_DEFAULT;
  recent.gui_zoom_level         = 0;
  recent.gui_bytes_view         = 0;

  /* pane size of zero will autodetect */
  recent.gui_geometry_main_upper_pane   = 0;
  recent.gui_geometry_main_lower_pane   = 0;

  recent.has_gui_geometry_main_upper_pane = TRUE;
  recent.has_gui_geometry_main_lower_pane = TRUE;
  recent.has_gui_geometry_status_pane = TRUE;

  if (recent.col_width_list) {
    free_col_width_info(&recent);
  }

  if (recent.gui_fileopen_remembered_dir) {
    g_free (recent.gui_fileopen_remembered_dir);
    recent.gui_fileopen_remembered_dir = NULL;
  }

  /* Construct the pathname of the user's profile recent file. */
  rf_path = get_persconffile_path(RECENT_FILE_NAME, TRUE);

  /* Read the user's recent file, if it exists. */
  *rf_path_return = NULL;
  if ((rf = ws_fopen(rf_path, "r")) != NULL) {
    /* We succeeded in opening it; read it. */
    read_prefs_file(rf_path, rf, read_set_recent_pair_static, NULL);
    fclose(rf);

    /* XXX: The following code doesn't actually do anything since
     *  the "recent common file" always exists. Presumably the
     *  "if (!file_exists())" should actually be "if (file_exists())".
     *  However, I've left the code as is because this
     *  behaviour has existed for quite some time and I don't
     *  know what's supposed to happen at this point.
     *  ToDo: Determine if the "recent common file" should be read at this point
     */
    rf_common_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, FALSE);
    if (!file_exists(rf_common_path)) {
      /* Read older common settings from recent file */
      rf = ws_fopen(rf_path, "r");
      read_prefs_file(rf_path, rf, read_set_recent_common_pair_static, NULL);
      fclose(rf);
    }
    g_free(rf_common_path);
    g_free(rf_path);
    rf_path = NULL;
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *rf_errno_return = errno;
      *rf_path_return = rf_path;
    }
  }
}

/* opens the user's recent file and read it out */
void
recent_read_dynamic(char **rf_path_return, int *rf_errno_return)
{
  char       *rf_path;
  FILE       *rf;


  /* Construct the pathname of the user's recent common file. */
  rf_path = get_persconffile_path(RECENT_COMMON_FILE_NAME, FALSE);
  if (!file_exists (rf_path)) {
    /* Recent common file does not exist, read from default recent */
    g_free (rf_path);
    rf_path = get_persconffile_path(RECENT_FILE_NAME, FALSE);
  }

  /* Read the user's recent file, if it exists. */
  *rf_path_return = NULL;
  if ((rf = ws_fopen(rf_path, "r")) != NULL) {
    /* We succeeded in opening it; read it. */
    read_prefs_file(rf_path, rf, read_set_recent_pair_dynamic, NULL);
#if 0
    /* set dfilter combobox to have an empty line */
    dfilter_combo_add_empty();
#endif
    fclose(rf);
    g_free(rf_path);
    rf_path = NULL;
  } else {
    /* We failed to open it.  If we failed for some reason other than
       "it doesn't exist", return the errno and the pathname, so our
       caller can report the error. */
    if (errno != ENOENT) {
      *rf_errno_return = errno;
      *rf_path_return = rf_path;
    }
  }
}

gint
recent_get_column_width(gint col)
{
  GList *col_l;
  col_width_data *col_w;
  gint cfmt;
  const gchar *cfield = NULL;

  cfmt = get_column_format(col);
  if (cfmt == COL_CUSTOM) {
    cfield = get_column_custom_field(col);
  }

  col_l = g_list_first(recent.col_width_list);
  while (col_l) {
    col_w = (col_width_data *) col_l->data;
    if (col_w->cfmt == cfmt) {
      if (cfmt != COL_CUSTOM || strcmp (cfield, col_w->cfield) == 0) {
	return col_w->width;
      }
    }
    col_l = col_l->next;
  }

  return -1;
}

void
recent_set_column_width(gint col, gint width)
{
  GList *col_l;
  col_width_data *col_w;
  gint cfmt;
  const gchar *cfield = NULL;
  gboolean found = FALSE;

  cfmt = get_column_format(col);
  if (cfmt == COL_CUSTOM) {
    cfield = get_column_custom_field(col);
  }

  col_l = g_list_first(recent.col_width_list);
  while (col_l) {
    col_w = (col_width_data *) col_l->data;
    if (col_w->cfmt == cfmt) {
      if (cfmt != COL_CUSTOM || strcmp (cfield, col_w->cfield) == 0) {
	col_w->width = width;
	found = TRUE;
	break;
      }
    }
    col_l = col_l->next;
  }

  if (!found) {
    col_w = (col_width_data *) g_malloc(sizeof(col_width_data));
    col_w->cfmt = cfmt;
    if (cfield) {
      col_w->cfield = g_strdup(cfield);
    } else {
      col_w->cfield = NULL;
    }
    col_w->width = width;
    col_w->xalign = COLUMN_XALIGN_DEFAULT;
    recent.col_width_list = g_list_append(recent.col_width_list, col_w);
  }
}

gchar
recent_get_column_xalign(gint col)
{
  GList *col_l;
  col_width_data *col_w;
  gint cfmt;
  const gchar *cfield = NULL;

  cfmt = get_column_format(col);
  if (cfmt == COL_CUSTOM) {
    cfield = get_column_custom_field(col);
  }

  col_l = g_list_first(recent.col_width_list);
  while (col_l) {
    col_w = (col_width_data *) col_l->data;
    if (col_w->cfmt == cfmt) {
      if (cfmt != COL_CUSTOM || strcmp (cfield, col_w->cfield) == 0) {
        return col_w->xalign;
      }
    }
    col_l = col_l->next;
  }

  return 0;
}

void
recent_set_column_xalign(gint col, gchar xalign)
{
  GList *col_l;
  col_width_data *col_w;
  gint cfmt;
  const gchar *cfield = NULL;
  gboolean found = FALSE;

  cfmt = get_column_format(col);
  if (cfmt == COL_CUSTOM) {
    cfield = get_column_custom_field(col);
  }

  col_l = g_list_first(recent.col_width_list);
  while (col_l) {
    col_w = (col_width_data *) col_l->data;
    if (col_w->cfmt == cfmt) {
      if (cfmt != COL_CUSTOM || strcmp (cfield, col_w->cfield) == 0) {
        col_w->xalign = xalign;
        found = TRUE;
        break;
      }
    }
    col_l = col_l->next;
  }

  if (!found) {
    col_w = (col_width_data *) g_malloc(sizeof(col_width_data));
    col_w->cfmt = cfmt;
    if (cfield) {
      col_w->cfield = g_strdup(cfield);
    } else {
      col_w->cfield = NULL;
    }
    col_w->width = 40;
    col_w->xalign = xalign;
    recent.col_width_list = g_list_append(recent.col_width_list, col_w);
  }
}
