/* prefs-recent.c
 * Recent "preference" handling routines
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

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <glib.h>

#include <epan/epan.h>
#include <epan/filesystem.h>
#include <epan/timestamp.h>
#include <epan/prefs.h>
#include "prefs-recent.h"
#include <epan/prefs-int.h>


#define RECENT_KEY_MAIN_TOOLBAR_SHOW        "gui.toolbar_main_show"
#define RECENT_KEY_FILTER_TOOLBAR_SHOW      "gui.filter_toolbar_show"
#define RECENT_KEY_PACKET_LIST_SHOW         "gui.packet_list_show"
#define RECENT_KEY_TREE_VIEW_SHOW           "gui.tree_view_show"
#define RECENT_KEY_BYTE_VIEW_SHOW           "gui.byte_view_show"
#define RECENT_KEY_STATUSBAR_SHOW           "gui.statusbar_show"
#define RECENT_GUI_TIME_FORMAT              "gui.time_format"
#define RECENT_GUI_ZOOM_LEVEL               "gui.zoom_level"
#define RECENT_GUI_GEOMETRY_MAIN_X          "gui.geometry_main_x"
#define RECENT_GUI_GEOMETRY_MAIN_Y          "gui.geometry_main_y"
#define RECENT_GUI_GEOMETRY_MAIN_WIDTH      "gui.geometry_main_width"
#define RECENT_GUI_GEOMETRY_MAIN_HEIGHT     "gui.geometry_main_height"
#define RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED  "gui.geometry_main_maximized"
#define RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE "gui.geometry_main_upper_pane"
#define RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE "gui.geometry_main_lower_pane"
#define RECENT_GUI_GEOMETRY_STATUS_PANE     "gui.geometry_status_pane"
#define RECENT_GUI_FILEOPEN_REMEMBERED_DIR  "gui.fileopen_remembered_dir"

#define RECENT_FILE_NAME "recent"

recent_settings_t recent;

static gchar *last_open_dir = NULL;
static gboolean updated_last_open_dir = FALSE;

static char *ts_type_text[] =
	{ "RELATIVE", "ABSOLUTE", "ABSOLUTE_WITH_DATE", "DELTA", NULL };


/* the geometry hashtable for all known window classes,
 * the window name is the key, and the geometry struct is the value */
GHashTable *window_geom_hash = NULL;

/* Takes an string and a pointer to an array of strings, and a default int value.
 * The array must be terminated by a NULL string. If the string is found in the array
 * of strings, the index of that string in the array is returned. Otherwise, the
 * default value that was passed as the third argument is returned.
 */
static int
find_index_from_string_array(char *needle, char **haystack, int default_value)
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

/* Write out "recent" to the user's recent file, and return 0.
   If we got an error, stuff a pointer to the path of the recent file
   into "*pf_path_return", and return the errno. */
int
write_recent(char **rf_path_return)
{
  char        *rf_path;
  FILE        *rf;

  /* To do:
   * - Split output lines longer than MAX_VAL_LEN
   * - Create a function for the preference directory check/creation
   *   so that duplication can be avoided with filter.c
   */

  rf_path = get_persconffile_path(RECENT_FILE_NAME, TRUE);
  if ((rf = fopen(rf_path, "w")) == NULL) {
    *rf_path_return = rf_path;
    return errno;
  }

  fputs("# Recent settings file for Ethereal " VERSION ".\n"
    "#\n"
    "# This file is regenerated each time Ethereal is quit.\n"
    "# So be careful, if you want to make manual changes here.\n"
    "\n"
    "######## Recent capture files (latest last) ########\n"
    "\n", rf);

  menu_recent_file_write_all(rf);

  fputs("\n"
    "######## Recent display filters (latest last) ########\n"
    "\n", rf);

  dfilter_recent_combo_write_all(rf);

  fprintf(rf, "\n# Main Toolbar show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_MAIN_TOOLBAR_SHOW ": %s\n",
		  recent.main_toolbar_show == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Filter Toolbar show (hide).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_KEY_FILTER_TOOLBAR_SHOW ": %s\n",
		  recent.filter_toolbar_show == TRUE ? "TRUE" : "FALSE");

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

  fprintf(rf, "\n# Timestamp display format.\n");
  fprintf(rf, "# One of: RELATIVE, ABSOLUTE, ABSOLUTE_WITH_DATE, DELTA\n");
  fprintf(rf, RECENT_GUI_TIME_FORMAT ": %s\n",
          ts_type_text[recent.gui_time_format]);

  fprintf(rf, "\n# Zoom level.\n");
  fprintf(rf, "# A decimal number.\n");
  fprintf(rf, RECENT_GUI_ZOOM_LEVEL ": %d\n",
		  recent.gui_zoom_level);

  fprintf(rf, "\n# Main window geometry.\n");
  fprintf(rf, "# Decimal integers.\n");
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_X ": %d\n", recent.gui_geometry_main_x);
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_Y ": %d\n", recent.gui_geometry_main_y);
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_WIDTH ": %d\n",
  		  recent.gui_geometry_main_width);
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_HEIGHT ": %d\n",
  		  recent.gui_geometry_main_height);

  fprintf(rf, "\n# Main window maximized (GTK2 only).\n");
  fprintf(rf, "# TRUE or FALSE (case-insensitive).\n");
  fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED ": %s\n",
		  recent.gui_geometry_main_maximized == TRUE ? "TRUE" : "FALSE");

  fprintf(rf, "\n# Main window panes (GTK2 only).\n");
  fprintf(rf, "# Decimal numbers.\n");
  if (recent.gui_geometry_main_upper_pane != 0) {
    fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE ": %d\n",
		  recent.gui_geometry_main_upper_pane);
  }
  if (recent.gui_geometry_main_lower_pane != 0) {
    fprintf(rf, RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE ": %d\n",
		  recent.gui_geometry_main_lower_pane);
  }
  if (recent.gui_geometry_status_pane != 0) {
    fprintf(rf, RECENT_GUI_GEOMETRY_STATUS_PANE ": %d\n",
		  recent.gui_geometry_status_pane);
  }

  if (get_last_open_dir() != NULL) {
    fprintf(rf, "\n# Last directory navigated to in File Open dialog.\n");
    fprintf(rf, RECENT_GUI_FILEOPEN_REMEMBERED_DIR ": %s\n", get_last_open_dir());
  }

  window_geom_recent_write_all(rf);

  fclose(rf);

  /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
     an error indication, or maybe write to a new preferences file and
     rename that file on top of the old one only if there are not I/O
     errors. */
  return 0;
}


/* read in a single key value pair from the recent file into the geometry hashtable */
static void
window_geom_recent_read_pair(const char *name, const char *key, const char *value)
{
    window_geometry_t geom;


    /* find window geometry maybe already in hashtable */
    if(!window_geom_load(name, &geom)) {
        /* not in table, init geom with "basic" values */
        geom.key        = g_strdup(name);
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
        if (strcasecmp(value, "true") == 0) {
            geom.maximized = TRUE;
        }
        else {
            geom.maximized = FALSE;
        }
        geom.set_maximized = TRUE;
    } else {
        g_assert_not_reached();
    }

    /* save / replace geometry in hashtable */
    window_geom_save(name, &geom);
}



/* set one user's recent file key/value pair */
static int
read_set_recent_pair(gchar *key, gchar *value)
{
  long num;
  char *p;

  if (strcmp(key, RECENT_KEY_CAPTURE_FILE) == 0) {
	add_menu_recent_capture_file(value);
  } else if (strcmp(key, RECENT_KEY_DISPLAY_FILTER) == 0) {
	dfilter_combo_add_recent(value);
  } else if (strcmp(key, RECENT_KEY_MAIN_TOOLBAR_SHOW) == 0) {
    if (strcasecmp(value, "true") == 0) {
        recent.main_toolbar_show = TRUE;
    }
    else {
        recent.main_toolbar_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_FILTER_TOOLBAR_SHOW) == 0) {
    if (strcasecmp(value, "true") == 0) {
        recent.filter_toolbar_show = TRUE;
    }
    else {
        recent.filter_toolbar_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_PACKET_LIST_SHOW) == 0) {
    if (strcasecmp(value, "true") == 0) {
        recent.packet_list_show = TRUE;
    }
    else {
        recent.packet_list_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_TREE_VIEW_SHOW) == 0) {
    if (strcasecmp(value, "true") == 0) {
        recent.tree_view_show = TRUE;
    }
    else {
        recent.tree_view_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_BYTE_VIEW_SHOW) == 0) {
    if (strcasecmp(value, "true") == 0) {
        recent.byte_view_show = TRUE;
    }
    else {
        recent.byte_view_show = FALSE;
    }
  } else if (strcmp(key, RECENT_KEY_STATUSBAR_SHOW) == 0) {
    if (strcasecmp(value, "true") == 0) {
        recent.statusbar_show = TRUE;
    }
    else {
        recent.statusbar_show = FALSE;
    }
  } else if (strcmp(key, RECENT_GUI_TIME_FORMAT) == 0) {
    recent.gui_time_format =
	find_index_from_string_array(value, ts_type_text, TS_RELATIVE);
  } else if (strcmp(key, RECENT_GUI_ZOOM_LEVEL) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    recent.gui_zoom_level = num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_MAXIMIZED) == 0) {
    if (strcasecmp(value, "true") == 0) {
        recent.gui_geometry_main_maximized = TRUE;
    }
    else {
        recent.gui_geometry_main_maximized = FALSE;
    }

  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_X) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    recent.gui_geometry_main_x = num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_Y) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    recent.gui_geometry_main_y = num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_WIDTH) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_main_width = num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_HEIGHT) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_main_height = num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_UPPER_PANE) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_main_upper_pane = num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_MAIN_LOWER_PANE) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_main_lower_pane = num;
  } else if (strcmp(key, RECENT_GUI_GEOMETRY_STATUS_PANE) == 0) {
    num = strtol(value, &p, 0);
    if (p == value || *p != '\0')
      return PREFS_SET_SYNTAX_ERR;	/* number was bad */
    if (num <= 0)
      return PREFS_SET_SYNTAX_ERR;	/* number must be positive */
    recent.gui_geometry_status_pane = num;
  } else if (strcmp(key, RECENT_GUI_FILEOPEN_REMEMBERED_DIR) == 0) {
    set_last_open_dir(value);
  } else if (strncmp(key, RECENT_GUI_GEOMETRY, sizeof(RECENT_GUI_GEOMETRY)-1) == 0) {
    /* now have something like "gui.geom.main.x", split it into win and sub_key */
    char *win = &key[sizeof(RECENT_GUI_GEOMETRY)-1];
    char *sub_key = strchr(win, '.');
    if(sub_key) {
      *sub_key = '\0';
      sub_key++;
      window_geom_recent_read_pair(win, sub_key, value);
    }
  }

  return PREFS_SET_OK;
}


/* opens the user's recent file and read it out */
void
read_recent(char **rf_path_return, int *rf_errno_return)
{
  char       *rf_path;
  FILE       *rf;


  /* set defaults */
  recent.main_toolbar_show      = TRUE;
  recent.filter_toolbar_show    = TRUE;
  recent.packet_list_show       = TRUE;
  recent.tree_view_show         = TRUE;
  recent.byte_view_show         = TRUE;
  recent.statusbar_show         = TRUE;
  recent.gui_time_format        = TS_RELATIVE;
  recent.gui_zoom_level         = 0;

  recent.gui_geometry_main_x        =        20;
  recent.gui_geometry_main_y        =        20;
  recent.gui_geometry_main_width    = DEF_WIDTH;
  recent.gui_geometry_main_height   = DEF_HEIGHT;
  recent.gui_geometry_main_maximized=     FALSE;

  /* pane size of zero will autodetect */
  recent.gui_geometry_main_upper_pane   = 0;
  recent.gui_geometry_main_lower_pane   = 0;
  recent.gui_geometry_status_pane       = 0;

  /* Construct the pathname of the user's recent file. */
  rf_path = get_persconffile_path(RECENT_FILE_NAME, FALSE);

  /* Read the user's recent file, if it exists. */
  *rf_path_return = NULL;
  if ((rf = fopen(rf_path, "r")) != NULL) {
    /* We succeeded in opening it; read it. */
    read_prefs_file(rf_path, rf, read_set_recent_pair);
	/* set dfilter combobox to have an empty line */
    dfilter_combo_add_empty();
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

void
set_last_open_dir(char *dirname)
{
	int len;
	gchar *new_last_open_dir;

	if (dirname) {
		len = strlen(dirname);
		if (dirname[len-1] == G_DIR_SEPARATOR) {
			new_last_open_dir = g_strconcat(dirname, NULL);
		}
		else {
			new_last_open_dir = g_strconcat(dirname,
				G_DIR_SEPARATOR_S, NULL);
		}

		if (last_open_dir == NULL ||
		    strcmp(last_open_dir, new_last_open_dir) != 0)
			updated_last_open_dir = TRUE;
	}
	else {
		new_last_open_dir = NULL;
		if (last_open_dir != NULL)
			updated_last_open_dir = TRUE;
	}

	if (last_open_dir) {
		g_free(last_open_dir);
	}
	last_open_dir = new_last_open_dir;
}

char *
get_last_open_dir(void)
{
    return last_open_dir;
}



/* save the window and it's current geometry into the geometry hashtable */
void
window_geom_save(const gchar *name, window_geometry_t *geom)
{
    gchar *key;
    window_geometry_t *work;

    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }
    /* if we have an old one, remove and free it first */
    work = g_hash_table_lookup(window_geom_hash, name);
    if(work) {
        g_hash_table_remove(window_geom_hash, name);
        g_free(work->key);
        g_free(work);
    }

    /* malloc and insert the new one */
    work = g_malloc(sizeof(*geom));
    *work = *geom;
    key = g_strdup(name);
    work->key = key;
    g_hash_table_insert(window_geom_hash, key, work);
}


/* load the desired geometry for this window from the geometry hashtable */
gboolean
window_geom_load(const gchar *name, window_geometry_t *geom)
{
    window_geometry_t *p;

    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }

    p = g_hash_table_lookup(window_geom_hash, name);
    if(p) {
        *geom = *p;
        return TRUE;
    } else {
        return FALSE;
    }
}


/* write all geometry values of all windows from the hashtable to the recent file */
void
window_geom_recent_write_all(gpointer rf)
{
    /* init hashtable, if not already done */
    if(!window_geom_hash) {
        window_geom_hash = g_hash_table_new (g_str_hash, g_str_equal);
    }

    g_hash_table_foreach(window_geom_hash, write_recent_geom, rf);
}

/* write the geometry values of a window to recent file */
void
write_recent_geom(gpointer key _U_, gpointer value, gpointer rf)
{
    window_geometry_t *geom = value;

    fprintf(rf, "\n# Geometry and maximized state (GTK2 only) of %s window.\n", geom->key);
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


