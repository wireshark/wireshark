/* recent.c
 * Recent "preference" handling routines
 * Copyright 2004, Ulf Lamping <ulf.lamping@web.de>
 *
 * $Id: recent.c,v 1.7 2004/01/25 18:51:25 ulfl Exp $
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

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>

#include "recent.h"
#include <epan/epan.h>
#include <epan/filesystem.h>
#include "menu.h"
#include "main.h"
#include "prefs.h"
#include "prefs-int.h"

#define RECENT_FILE_NAME "recent"

/* #include "../menu.h" */
extern void add_menu_recent_capture_file(gchar *file);
extern void menu_recent_read_finished(void);

recent_settings_t recent;

static char *ts_type_text[] =
	{ "RELATIVE", "ABSOLUTE", "ABSOLUTE_WITH_DATE", "DELTA", NULL };

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
    "######## Recent capture files (latest first) ########\n"
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

  fclose(rf);

  /* XXX - catch I/O errors (e.g. "ran out of disk space") and return
     an error indication, or maybe write to a new preferences file and
     rename that file on top of the old one only if there are not I/O
     errors. */
  return 0;
}


/* set one user's recent file key/value pair */
static int
read_set_recent_pair(gchar *key, gchar *value)
{

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
    recent.gui_zoom_level = strtol(value, NULL, 0);
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

  menu_recent_read_finished();

  switch (font_apply()) {

  case FA_SUCCESS:
    break;

  case FA_FONT_NOT_RESIZEABLE:
    /* "font_apply()" popped up an alert box. */
    recent.gui_zoom_level = 0;	/* turn off zooming - font can't be resized */
    break;

  case FA_FONT_NOT_AVAILABLE:
    /* XXX - did we successfully load the un-zoomed version earlier?
       If so, this *probably* means the font is available, but not at
       this particular zoom level, but perhaps some other failure
       occurred; I'm not sure you can determine which is the case,
       however. */
    recent.gui_zoom_level = 0;	/* turn off zooming - zoom level is unavailable */
    break;
  }
}


