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

#include <glib.h>

#include <wiretap/wtap.h>

#include "capture_file_dialog.h"

#ifdef Q_WS_WIN
#include <windows.h>
#include "packet_list_record.h"
#include "cfile.h"
#include "ui/win32/file_dlg_win32.h"
#else
#include "../../epan/addr_resolv.h"
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#endif

#include <QDebug>

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

CaptureFileDialog::CaptureFileDialog(QWidget *parent, QString &fileName, QString &displayFilter) :
    QFileDialog(parent), m_fileName(fileName), m_displayFilter(displayFilter)
{
#if !defined(Q_WS_WIN)
    setWindowTitle(tr("Wireshark: Open Capture File"));
    setNameFilters(build_file_open_type_list());
    setFileMode(QFileDialog::ExistingFile);

    if (!m_fileName.isEmpty()) {
        selectFile(m_fileName);
    }

    // Add extra widgets
    // http://qt-project.org/faq/answer/how_can_i_add_widgets_to_my_qfiledialog_instance
    setOption(QFileDialog::DontUseNativeDialog, true);
    QGridLayout *fdGrid = qobject_cast<QGridLayout*>(layout());
    QHBoxLayout *hBox = new QHBoxLayout();
    QVBoxLayout *controlsBox = new QVBoxLayout();

    QLabel *dfLabel = new QLabel(tr("Display Filter:"));
    fdGrid->addWidget(dfLabel, fdGrid->rowCount(), 0, 1, 1);

    m_displayFilterEdit = new DisplayFilterEdit(this, true);
    m_displayFilterEdit->setText(m_displayFilter);
    fdGrid->addWidget(m_displayFilterEdit, fdGrid->rowCount() - 1, 1, 1, 1);

    fdGrid->addLayout(hBox, fdGrid->rowCount(), 1, 1, -1);
    hBox->addLayout(controlsBox);

    m_macRes.setText(tr("Enable &MAC name resolution"));
    m_macRes.setChecked(gbl_resolv_flags.mac_name);
    controlsBox->addWidget(&m_macRes);

    m_transportRes.setText(tr("Enable &transport name resolution"));
    m_transportRes.setChecked(gbl_resolv_flags.transport_name);
    controlsBox->addWidget(&m_transportRes);

    m_networkRes.setText(tr("Enable &network name resolution"));
    m_networkRes.setChecked(gbl_resolv_flags.network_name);
    controlsBox->addWidget(&m_networkRes);

    m_externalRes.setText(tr("Use &external name resolver"));
    m_externalRes.setChecked(gbl_resolv_flags.use_external_net_name_resolver);
    controlsBox->addWidget(&m_externalRes);
#endif
}

// Windows
#ifdef Q_WS_WIN
int CaptureFileDialog::exec() {
    GString *file_name = g_string_new(m_fileName.toUtf8().constData());
    GString *display_filter = g_string_new(m_displayFilter.toUtf8().constData());
    gboolean wof_status;

    wof_status = win32_open_file(parentWidget()->effectiveWinId(), file_name, display_filter);
    m_fileName.clear();
    m_fileName.append(QString::fromUtf8(file_name->str));
    m_displayFilter.clear();
    m_displayFilter.append(QString::fromUtf8(display_filter->str));

    g_string_free(file_name, TRUE);
    g_string_free(display_filter, TRUE);

    return (int) wof_status;
}

#else // not Q_WS_WINDOWS
int CaptureFileDialog::exec() {
    m_fileName.clear();
    m_displayFilter.clear();

    if (QFileDialog::exec() && selectedFiles().length() > 0) {
        m_fileName.append(selectedFiles()[0]);
        m_displayFilter.append(m_displayFilterEdit->text());

        gbl_resolv_flags.mac_name = m_macRes.isChecked();
        gbl_resolv_flags.transport_name = m_transportRes.isChecked();
        gbl_resolv_flags.network_name = m_networkRes.isChecked();
        gbl_resolv_flags.use_external_net_name_resolver = m_externalRes.isChecked();

        return QDialog::Accepted;
    } else {
        return QDialog::Rejected;
    }
}

void CaptureFileDialog::append_file_type(QStringList &filters, int ft)
{
    QString filter;
    bool first;
    GSList *extensions_list, *extension;

    filter = wtap_file_type_string(ft);
    filter += " (";
    extensions_list = wtap_get_file_extensions_list(ft, TRUE);
    if (extensions_list == NULL) {
        /* This file type doesn't have any particular extension
           conventionally used for it, so we'll just use "*.*"
           as the pattern; on Windows, that matches all file names
           - even those with no extension -  so we don't need to
           worry about compressed file extensions.  (It does not
           do so on UN*X; the right pattern on UN*X would just
           be "*".) */
           filter += "*.*";
    } else {
        /* Construct the list of patterns. */
        first = true;
        for (extension = extensions_list; extension != NULL;
             extension = g_slist_next(extension)) {
            /* XXX - the documentation says the separator is a blank */
            if (!first)
                filter += ';';
            filter += "*.";
            filter += (char *)extension->data;
            first = false;
        }
        wtap_free_file_extensions_list(extensions_list);
    }
    filter += ')';
    filters += filter;
    /* XXX - does QStringList's destructor destroy the strings in the list? */
}

QStringList CaptureFileDialog::build_file_open_type_list(void) {
    QStringList filters;	/* XXX - new? */
    int   ft;


    /* Add the "All Files" entry. */
    filters << QString(tr("All Files (*.*)"));

    /* Include all the file types Wireshark supports. */
    for (ft = 0; ft < WTAP_NUM_FILE_TYPES; ft++) {
        if (ft == WTAP_FILE_UNKNOWN)
            continue;  /* not a real file type */

        append_file_type(filters, ft);
    }

    return filters;
}
#endif // Q_WS_WINDOWS

#if 0
static QStringList
build_file_save_type_list(GArray *savable_file_types) {
    QStringList filters = new QStringList;
    guint i;
    int   ft;

    /* Get only the file types as which we can save this file. */
    if (savable_file_types != NULL) {
        /* OK, we have at least one file type we can save this file as.
           (If we didn't, we shouldn't have gotten here in the first
           place.)  Add them all to the filter list.  */
        for (i = 0; i < savable_file_types->len; i++) {
            ft = g_array_index(savable_file_types, int, i);
            append_file_type(filters, ft);
        }
    }

    return filters;
}
#endif
