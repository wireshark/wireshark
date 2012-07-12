/* capture_file_dialog.cpp
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "capture_file_dialog.h"

#ifdef Q_WS_WIN
#include <glib.h>
#include <windows.h>
#include "packet_list_record.h"
#include "cfile.h"
#include "ui/win32/file_dlg_win32.h"
#endif

#ifdef Q_WS_WIN
// All of these routines are required by file_dlg_win32.c.
// We don't yet have a good place for them so we'll add them as stubs here.

extern "C" {

// From gtk/capture_dlg.[ch]
/* capture start confirmed by "Save unsaved capture", so do it now */
extern void capture_start_confirmed(void) {
}

// From gtk/drag_and_drop.[ch]
/** Open a new file coming from drag and drop.
 * @param cf_names_freeme the selection data reported from GTK
 */
extern void dnd_open_file_cmd(gchar *cf_names_freeme) {
    Q_UNUSED(cf_names_freeme);
}

// From gtk/menus.h & main_menubar.c
/** User pushed a recent file submenu item.
 *
 * @param widget parent widget
 */
extern void menu_open_recent_file_cmd(gpointer action){
    Q_UNUSED(action)
}

/** One of the name resolution menu items changed. */
extern void menu_name_resolution_changed(void) {

}

// From gtk/export_sslkeys.[ch]
/** Callback for "Export SSL Session Keys" operation.
 *
 * @param w unused
 * @param data unused
 */
extern void savesslkeys_cb(gpointer * w, gpointer data) {
    Q_UNUSED(w);
    Q_UNUSED(data);
}

/** Dump the SSL Session Keys to a StringInfo string
 *
 * @param session_hash contains all the SSL Session Keys
 */
extern gpointer ssl_export_sessions(GHashTable *session_hash) {
    Q_UNUSED(session_hash);
    return NULL;
}

// From gtk/help_dlg.[ch]
/** Open a specific topic (create a "Help" dialog box or open a webpage).
 *
 * @param widget parent widget (unused)
 * @param topic the topic to display
 */
extern void topic_cb(gpointer *widget, int topic) {
    Q_UNUSED(widget);
    Q_UNUSED(topic);
}

}
// End stub routines
#endif // Q_WS_WIN

CaptureFileDialog::CaptureFileDialog(QWidget *parent) :
    QFileDialog(parent)
{
}

#ifdef Q_WS_WIN
int CaptureFileDialog::exec(){
    return (int) win32_open_file(parentWidget()->effectiveWinId());
}

#endif
