/** @file
 *
 * Declarations of UI utility routines; these routines have GUI-independent
 * APIs, but GUI-dependent implementations, so that they can be called by
 * GUI-independent code to affect the GUI.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __UI_UTIL_H__
#define __UI_UTIL_H__

#include <stdint.h>

#include <wsutil/processes.h>

#include "epan/packet_info.h"
#include "epan/column-utils.h"
#include "epan/color_filters.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/** geometry values for use in window_get_geometry() and window_set_geometry() */
typedef struct window_geometry_s {
    gchar       *key;           /**< current key in hashtable (internally used only) */
    gboolean    set_pos;        /**< set the x and y position values */
    gint        x;              /**< the windows x position */
    gint        y;              /**< the windows y position */
    gboolean    set_size;       /**< set the width and height values */
    gint        width;          /**< the windows width */
    gint        height;         /**< the windows height */
    gboolean    set_maximized;  /**< set the maximized state */
    gboolean    maximized;      /**< the windows maximized state */
} window_geometry_t;

/* update the main window */
extern void main_window_update(void);
/* quit the main window */
extern void main_window_quit(void);

/* Exit routine provided by UI-specific code. */
extern void exit_application(int status);

/* read from a pipe (callback) */
typedef gboolean (*pipe_input_cb_t) (gint source, gpointer user_data);
/* install callback function, called if pipe input is available */
extern void pipe_input_set_handler(gint source, gpointer user_data, ws_process_id *child_process, pipe_input_cb_t input_cb);

/* packet_list.c */

void packet_list_clear(void);
void packet_list_freeze(void);
void packet_list_recreate_visible_rows(void);
void packet_list_thaw(void);
guint packet_list_append(column_info *cinfo, frame_data *fdata);
void packet_list_queue_draw(void);
gboolean packet_list_select_row_from_data(frame_data *fdata_needle);
gboolean packet_list_multi_select_active(void);

/* XXX - Yes this isn't the best place, but they are used by file_dlg_win32.c, which is supposed
         to be GUI independent, but has lots of GTK leanings.  But if you put these in a GTK UI
         header file, file_dlg_win32.c complains about all of the GTK structures also in the header
         files
         Function names make it clear where they are coming from
*/
void color_filter_add_cb(color_filter_t *colorf, gpointer user_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_UTIL_H__ */
