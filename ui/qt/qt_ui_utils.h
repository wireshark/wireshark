/* qt_gui_utils.h
 * Declarations of GTK+-specific UI utility routines
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __QT_UI_UTILS_H__
#define __QT_UI_UTILS_H__

// xxx - copied from gtk/gui_utils.h

#include <stdio.h>

#include "config.h"

#include <glib.h>
#include <epan/timestamp.h>
//#include <packet_list.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// These are defined elsewhere in ../gtk/
#define RECENT_KEY_COL_WIDTH      "column.width"
#define RECENT_KEY_CAPTURE_FILTER "recent.capture_filter"
#define RECENT_KEY_CAPTURE_FILE   "recent.capture_file"
#define RECENT_KEY_REMOTE_HOST "recent.remote_host"

extern gboolean dfilter_combo_add_recent(gchar *filter);
extern gboolean cfilter_combo_add_recent(gchar *filter);
extern void dfilter_recent_combo_write_all(FILE *rf);
extern void cfilter_combo_recent_write_all(FILE *rf);
extern void new_packet_list_recent_write_all(FILE *rf);
/** Get the latest opened directory.
 *
 * @return the dirname
 */
extern char *get_last_open_dir(void);
/* Add a new recent capture filename to the "Recent Files" submenu
   (duplicates will be ignored) */
extern void add_menu_recent_capture_file(gchar *cf_name);
/** Write all recent capture filenames to the user's recent file.
 * @param rf recent file
 */
extern void menu_recent_file_write_all(FILE *rf);


/* Type of capture source */
typedef enum {
    CAPTURE_IFLOCAL,        /**< Local network interface */
    CAPTURE_IFREMOTE        /**< Remote network interface */
} capture_source;

/* Type of RPCAPD Authentication */
typedef enum {
    CAPTURE_AUTH_NULL,      /**< No authentication */
    CAPTURE_AUTH_PWD        /**< User/password authentication */
} capture_auth;

struct remote_host_t {
    gchar *remote_host;          /**< Host name or network address for remote capturing */
    gchar *remote_port;          /**< TCP port of remote RPCAP server */
    gint auth_type;              /**< Authentication type */
    gchar *auth_username;        /**< Remote authentication parameters */
    gchar *auth_password;        /**< Remote authentication parameters */
    gboolean datatx_udp;
    gboolean nocap_rpcap;
    gboolean nocap_local;
};

/** Write all remote hosts to the recent file
 *
 * @param rf recent file
 */
void
capture_remote_combo_recent_write_all(FILE *rf);

/** Add a new remote host from the recent file
 *
 * @param s string with hostname,port,auth_type
 * @return TRUE if correctly added
 */
gboolean
capture_remote_combo_add_recent(gchar *s);



/** @file
 * Utilities for Windows and other user interface functions.
 */

/** @name Window Functions
 *  @todo Move these window functions to a new file win_utils.h?
 *  @{ */


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

/** Write all geometry values of all windows to the recent file.
 * Will call write_recent_geom() for every existing window type.
 *
 * @param rf recent file handle from caller
 */
extern void window_geom_recent_write_all(gpointer rf);

/** Read in a single geometry key value pair from the recent file.
 *
 * @param name the geom_name of the window
 * @param key the subkey of this pair (e.g. "x")
 * @param value the new value (e.g. "123")
 */
extern void window_geom_recent_read_pair(const char *name, const char *key, const char *value);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __QT_UI_UTILS__H__ */
