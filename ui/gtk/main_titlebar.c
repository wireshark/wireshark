/* main_titlebar.c
 * Main window title bar routines.
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

#include <epan/prefs.h>

#include <gtk/gtk.h>

#include "cfile.h"
#include "file.h"

#include "gtkglobals.h"
#include "gui_utils.h"
#include "main_titlebar.h"

#include <wsutil/ws_version_info.h>

/*
 * Key to attach the "un-decorated" title to the window, so that if the
 * user-specified decoration changes, we can correctly update the
 * window title.
 */
#define MAIN_WINDOW_NAME_KEY  "main_window_name"

/* Set the name of the top level main_window_name with the specified string and call
   main_titlebar_update() to construct the full title and display it in the main window. */
static void
main_set_window_name(const gchar *window_name)
{
    gchar *old_window_name;

    /* Attach the new un-decorated window name to the window. */
    old_window_name = (gchar *)g_object_get_data(G_OBJECT(top_level), MAIN_WINDOW_NAME_KEY);
    g_free(old_window_name);
    g_object_set_data(G_OBJECT(top_level), MAIN_WINDOW_NAME_KEY, g_strdup(window_name));

    main_titlebar_update();
}

/* Construct the main window's title with the current main_window_name, optionally appended
   with the user-specified title and/or wireshark version. Display the result in the main
   window title bar. */
void
main_titlebar_update(void)
{
    gchar *window_name;
    gchar *title;

    /* Get the current filename or other title set in main_set_window_name */
    window_name = (gchar *)g_object_get_data(G_OBJECT(top_level), MAIN_WINDOW_NAME_KEY);
    if (window_name != NULL) {
        /* Optionally append the user-defined window title */
        title = create_user_window_title(window_name);

        /* Optionally append the version */
        if ((prefs.gui_version_placement == version_title_only) ||
            (prefs.gui_version_placement == version_both)) {
            gchar *old_title = title;
            title = g_strdup_printf("%s   [Wireshark %s]", title, get_ws_vcs_version_info());
            g_free(old_title);
        }
        gtk_window_set_title(GTK_WINDOW(top_level), title);
        g_free(title);
    }
}

/* Set titlebar to reflect the current state of the capture file, if any */
void
set_titlebar_for_capture_file(capture_file *cf)
{
  gchar *display_name;
  gchar *window_name;

  if (cf && cf->filename) {
    display_name = cf_get_display_name(cf);
    window_name = g_strdup_printf("%s%s", cf_has_unsaved_data(cf) ? "*" : "",
                                  display_name);
    g_free(display_name);
    main_set_window_name(window_name);
    g_free(window_name);
  } else {
    main_set_window_name("The Wireshark Network Analyzer");
  }
}

/* Set titlebar to reflect a capture in progress */
void
set_titlebar_for_capture_in_progress(capture_file *cf)
{
  gchar *window_name;

  window_name = g_strdup_printf("Capturing from %s ", cf_get_tempfile_source(cf));
  main_set_window_name(window_name);
  g_free(window_name);
}
