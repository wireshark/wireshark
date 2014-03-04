/* qt_gui_utils.h
 * Declarations of GTK+-specific UI utility routines
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

#ifndef __QT_UI_UTILS_H__
#define __QT_UI_UTILS_H__

// xxx - copied from ui/gtk/gui_utils.h

#include <stdio.h>

#include "config.h"

#include <glib.h>
#include <epan/timestamp.h>

#include <QFont>
#include <QString>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

// These are defined elsewhere in ../gtk/
#define RECENT_KEY_CAPTURE_FILE   "recent.capture_file"
#define RECENT_KEY_REMOTE_HOST "recent.remote_host"

///* Type of capture source */
//typedef enum {
//    CAPTURE_IFLOCAL,        /**< Local network interface */
//    CAPTURE_IFREMOTE        /**< Remote network interface */
//} capture_source;

///* Type of RPCAPD Authentication */
//typedef enum {
//    CAPTURE_AUTH_NULL,      /**< No authentication */
//    CAPTURE_AUTH_PWD        /**< User/password authentication */
//} capture_auth;

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

#ifdef __cplusplus
}
#endif /* __cplusplus */

/** Create a glib-compatible copy of a QString.
 *
 * @param q_string A QString.
 *
 * @return A copy of the QString. UTF-8 allocated with g_malloc().
 */
gchar *qstring_strdup(QString q_string);

/** Transfer ownership of a GLib character string to a newly constructed QString
 *
 * @param glib_string A string allocated with g_malloc() or NULL. Will be
 * freed.
 *
 * @return A QString instance created from the input string.
 */
QString gchar_free_to_qstring(gchar *glib_string);

/**
 * Round the current size of a font up to its next "smooth" size.
 * If a smooth size can't be found the font is left unchanged.
 *
 * @param font The font to smooth.
 */
void smooth_font_size(QFont &font);

#endif /* __QT_UI_UTILS__H__ */

// XXX Add a routine to fetch the HWND corresponding to a widget using QPlatformIntegration

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
