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
#include <errno.h>
#include "../../epan/addr_resolv.h"
#include "../../epan/prefs.h"
#include "../../epan/filesystem.h"
#include "../../epan/nstime.h"
#include <QGridLayout>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QFileInfo>
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
    QGridLayout *previewGrid = new QGridLayout();
    QLabel *lbl;

    fdGrid->addWidget(new QLabel(tr("Display Filter:")), fdGrid->rowCount(), 0, 1, 1);

    m_displayFilterEdit = new DisplayFilterEdit(this, true);
    m_displayFilterEdit->setText(m_displayFilter);
    fdGrid->addWidget(m_displayFilterEdit, fdGrid->rowCount() - 1, 1, 1, 1);

    fdGrid->addLayout(hBox, fdGrid->rowCount(), 1, 1, -1);

    // Filter and resolution controls
    hBox->addLayout(controlsBox);

    m_macRes.setText(tr("&MAC name resolution"));
    m_macRes.setChecked(gbl_resolv_flags.mac_name);
    controlsBox->addWidget(&m_macRes);

    m_transportRes.setText(tr("&Transport name resolution"));
    m_transportRes.setChecked(gbl_resolv_flags.transport_name);
    controlsBox->addWidget(&m_transportRes);

    m_networkRes.setText(tr("&Network name resolution"));
    m_networkRes.setChecked(gbl_resolv_flags.network_name);
    controlsBox->addWidget(&m_networkRes);

    m_externalRes.setText(tr("&External name resolver"));
    m_externalRes.setChecked(gbl_resolv_flags.use_external_net_name_resolver);
    controlsBox->addWidget(&m_externalRes);

    // Preview
    hBox->addLayout(previewGrid);

    previewGrid->setColumnStretch(0, 0);
    previewGrid->setColumnStretch(1, 10);

    lbl = new QLabel("Format:");
    previewGrid->addWidget(lbl, 0, 0);
    previewGrid->addWidget(&m_previewFormat, 0, 1);
    m_previewLabels << lbl << &m_previewFormat;

    lbl = new QLabel("Size:");
    previewGrid->addWidget(lbl, 1, 0);
    previewGrid->addWidget(&m_previewSize, 1, 1);
    m_previewLabels << lbl << &m_previewSize;

    lbl = new QLabel("Packets:");
    previewGrid->addWidget(lbl, 2, 0);
    previewGrid->addWidget(&m_previewPackets, 2, 1);
    m_previewLabels << lbl << &m_previewPackets;

    lbl = new QLabel("First Packet:");
    previewGrid->addWidget(lbl, 3, 0);
    previewGrid->addWidget(&m_previewFirst, 3, 1);
    m_previewLabels << lbl << &m_previewFirst;

    lbl = new QLabel("Elapsed Time:");
    previewGrid->addWidget(lbl, 4, 0);
    previewGrid->addWidget(&m_previewElapsed, 4, 1);
    m_previewLabels << lbl << &m_previewElapsed;

    // Grow the dialog to account for the extra widgets.
    resize(width(), height() + hBox->minimumSize().height() + m_displayFilterEdit->minimumSize().height());

    connect(this, SIGNAL(currentChanged(const QString &)), this, SLOT(preview(const QString &)));

    preview("");

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

/* do a preview run on the currently selected capture file */
void CaptureFileDialog::preview(const QString & path)
{
    wtap        *wth;
    int          err = 0;
    gchar       *err_info;
    gint64       data_offset;
    const struct wtap_pkthdr *phdr;
    double       start_time = 0; /* seconds, with nsec resolution */
    double       stop_time = 0;  /* seconds, with nsec resolution */
    double       cur_time;
    unsigned int packets = 0;
    bool         timed_out = FALSE;
    time_t       time_preview;
    time_t       time_current;
    time_t       ti_time;
    struct tm   *ti_tm;
    unsigned int elapsed_time;

    // Follow the same steps as ui/win32/file_dlg_win32.c

    foreach (QLabel *lbl, m_previewLabels) {
        lbl->setEnabled(false);
    }

    m_previewFormat.setText(tr("-"));
    m_previewSize.setText(tr("-"));
    m_previewPackets.setText(tr("-"));
    m_previewFirst.setText(tr("-"));
    m_previewElapsed.setText(tr("-"));

    if (path.length() < 1) {
        return;
    }

    if (test_for_directory(path.toUtf8().data()) == EISDIR) {
        m_previewFormat.setText(tr("directory"));
        return;
    }

    wth = wtap_open_offline(path.toUtf8().data(), &err, &err_info, TRUE);
    if (wth == NULL) {
        if(err == WTAP_ERR_FILE_UNKNOWN_FORMAT) {
            m_previewFormat.setText(tr("unknown file format"));
        } else {
            m_previewFormat.setText(tr("error opening file"));
        }
        return;
    }

    // Success!
    foreach (QLabel *lbl, m_previewLabels) {
        lbl->setEnabled(true);
    }

    // Format
    m_previewFormat.setText(QString::fromUtf8(wtap_file_type_string(wtap_file_type(wth))));

    // Size
    m_previewSize.setText(QString("%1 bytes").arg(wtap_file_size(wth, &err)));

    time(&time_preview);
    while ( (wtap_read(wth, &err, &err_info, &data_offset)) ) {
        phdr = wtap_phdr(wth);
        cur_time = wtap_nstime_to_sec(&phdr->ts);
        if(packets == 0) {
            start_time = cur_time;
            stop_time = cur_time;
        }
        if (cur_time < start_time) {
            start_time = cur_time;
        }
        if (cur_time > stop_time){
            stop_time = cur_time;
        }

        packets++;
        if(packets%1000 == 0) {
            /* do we have a timeout? */
            time(&time_current);
            if(time_current-time_preview >= (time_t) prefs.gui_fileopen_preview) {
                timed_out = TRUE;
                break;
            }
        }
    }

    if(err != 0) {
        m_previewPackets.setText(QString("error after reading %1 packets").arg(packets));
        return;
    }

    // Packet count
    if(timed_out) {
        m_previewPackets.setText(QString("more than %1 (preview timeout)").arg(packets));
    } else {
        m_previewPackets.setText(QString("%1").arg(packets));
    }

    // First packet
    ti_time = (long)start_time;
    ti_tm = localtime( &ti_time );
    if(ti_tm) {
        m_previewFirst.setText(QString().sprintf(
                 "%04d-%02d-%02d %02d:%02d:%02d",
                 ti_tm->tm_year + 1900,
                 ti_tm->tm_mon + 1,
                 ti_tm->tm_mday,
                 ti_tm->tm_hour,
                 ti_tm->tm_min,
                 ti_tm->tm_sec
                 ));
    } else {
        m_previewFirst.setText(tr("?"));
    }

    // Elapsed time
    elapsed_time = (unsigned int)(stop_time-start_time);
    if(timed_out) {
        m_previewElapsed.setText(tr("unknown"));
    } else if(elapsed_time/86400) {
        m_previewElapsed.setText(QString().sprintf("%02u days %02u:%02u:%02u",
                elapsed_time/86400, elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60));
    } else {
        m_previewElapsed.setText(QString().sprintf("%02u:%02u:%02u",
                elapsed_time%86400/3600, elapsed_time%3600/60, elapsed_time%60));
    }

    wtap_close(wth);
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
