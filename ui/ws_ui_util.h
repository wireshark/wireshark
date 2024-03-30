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
    char        *key;           /**< current key in hashtable (internally used only) */
    bool        set_pos;        /**< set the x and y position values */
    int         x;              /**< the windows x position */
    int         y;              /**< the windows y position */
    bool        set_size;       /**< set the width and height values */
    int         width;          /**< the windows width */
    int         height;         /**< the windows height */
    bool        set_maximized;  /**< set the maximized state */
    bool        maximized;      /**< the windows maximized state */
    char*       qt_geom;        /**< hex bytestring from Qt's saveGeometry() */
} window_geometry_t;

/* update the main window */
extern void main_window_update(void);

/* Exit routine provided by UI-specific code. */
WS_NORETURN extern void exit_application(int status);

/* XXX - Yes this isn't the best place, but they are used by file_dlg_win32.c, which is supposed
         to be GUI independent, but has lots of GTK leanings.  But if you put these in a GTK UI
         header file, file_dlg_win32.c complains about all of the GTK structures also in the header
         files
         Function names make it clear where they are coming from
*/
void color_filter_add_cb(color_filter_t *colorf, void *user_data);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __UI_UTIL_H__ */
