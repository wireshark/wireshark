/* wireshark_application.cpp
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

#include "wireshark_application.h"

#include <epan/prefs.h>

#include "qt_ui_utils.h"

#include "capture.h"
#include "log.h"
#include "recent_file_status.h"

#include <QDir>
#include <QTimer>

#ifdef Q_WS_WIN
#include <QLibrary>
#include <QDebug>
#endif

WiresharkApplication *wsApp = NULL;

// XXX - Copied from ui/gtk/file_dlg.c

// MUST be UTF-8
static char *last_open_dir = NULL;
static bool updated_last_open_dir = FALSE;
static QList<recent_item_status *> recent_items;

extern "C" char *
get_last_open_dir(void)
{
    return last_open_dir;
}

void
set_last_open_dir(const char *dirname)
{
    if (wsApp) wsApp->setLastOpenDir(dirname);
}

/*
 * Add the capture filename to the application-wide "Recent Files" list.
 * Contrary to the name this isn't limited to the "recent" menu.
 */
/*
 * XXX - We might want to call SHAddToRecentDocs under Windows 7:
 * http://stackoverflow.com/questions/437212/how-do-you-register-a-most-recently-used-list-with-windows-in-preparation-for-win
 */
extern "C" void
add_menu_recent_capture_file(gchar *cf_name) {
    QString normalized_cf_name = QString::fromUtf8(cf_name);
//    QDir cf_path;

//    cf_path.setPath(normalized_cf_name);
//    normalized_cf_name = cf_path.absolutePath();
    normalized_cf_name = QDir::cleanPath(normalized_cf_name);
    normalized_cf_name = QDir::toNativeSeparators(normalized_cf_name);

    recent_item_status *ri;

    /* Iterate through the recent items list, removing duplicate entries and every
     * item above count_max
     */
    unsigned int cnt = 1;
    foreach (ri, wsApp->recent_item_list()) {
        /* if this element string is one of our special items (separator, ...) or
         * already in the list or
         * this element is above maximum count (too old), remove it
         */
        if (ri->filename.length() < 1 ||
#ifdef _WIN32
            /* do a case insensitive compare on win32 */
            ri->filename.compare(normalized_cf_name, Qt::CaseInsensitive) == 0 ||
#else   /* _WIN32 */
            /* do a case sensitive compare on unix */
            ri->filename.compare(normalized_cf_name) == 0 ||
#endif
            cnt >= prefs.gui_recent_files_count_max) {
            wsApp->recent_item_list().removeOne(ri);
            delete(ri);
            cnt--;
        }
        cnt++;
    }
    wsApp->addRecentItem(normalized_cf_name, 0, false);
}

/* write all capture filenames of the menu to the user's recent file */
extern "C" void menu_recent_file_write_all(FILE *rf) {

    /* we have to iterate backwards through the children's list,
     * so we get the latest item last in the file.
     */
    QListIterator<recent_item_status *> rii(recent_items);
    rii.toBack();
    while (rii.hasPrevious()) {
        QString cf_name;
        /* get capture filename from the menu item label */
        cf_name = rii.previous()->filename;
        if (cf_name != NULL) {
//            if(u3_active())
//                fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", u3_contract_device_path(cf_name));
//            else
                fprintf (rf, RECENT_KEY_CAPTURE_FILE ": %s\n", cf_name.toUtf8().constData());
        }
    }
}

extern gboolean main_do_quit(void) {
    WiresharkApplication::quit();
    return FALSE;
}

//
void WiresharkApplication::refreshRecentFiles(void) {
    recent_item_status *ri;
    RecentFileStatus *rf_status;
    QThread *rf_thread;

    foreach (ri, recent_items) {
        if (ri->in_thread) {
            continue;
        }

        rf_thread = new QThread;
        rf_status = new RecentFileStatus(ri->filename);

        rf_status->moveToThread(rf_thread);

        connect(rf_thread, SIGNAL(started()), rf_status, SLOT(start()));

        connect(rf_status, SIGNAL(statusFound(QString, qint64, bool)), this, SLOT(itemStatusFinished(QString, qint64, bool)));
        connect(rf_status, SIGNAL(finished()), rf_thread, SLOT(quit()));
        connect(rf_status, SIGNAL(finished()), rf_status, SLOT(deleteLater()));
//        connect(rf_status, SIGNAL(finished()), rf_thread, SLOT(deleteLater()));

        rf_thread->start();
    }
}

void WiresharkApplication::captureCallback(int event, capture_options * capture_opts)
{
    switch(event) {
    case(capture_cb_capture_prepared):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture prepared");
        emit captureCapturePrepared(capture_opts);
        break;
    case(capture_cb_capture_update_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update started");
        emit captureCaptureUpdateStarted(capture_opts);
        break;
    case(capture_cb_capture_update_continue):
        /*g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update continue");*/
        break;
    case(capture_cb_capture_update_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture update finished");
        emit captureCaptureUpdateFinished(capture_opts);
        break;
    case(capture_cb_capture_fixed_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed started");
        emit captureCaptureFixedStarted(capture_opts);
        break;
    case(capture_cb_capture_fixed_continue):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed continue");
        break;
    case(capture_cb_capture_fixed_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture fixed finished");
        emit captureCaptureFixedFinished(capture_opts);
        break;
    case(capture_cb_capture_stopping):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture stopping");
        /* Beware: this state won't be called, if the capture child
         * closes the capturing on it's own! */
        emit captureCaptureStopping(capture_opts);
        break;
    case(capture_cb_capture_failed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: capture failed");
        emit captureCaptureFailed(capture_opts);
        break;
    default:
        g_warning("main_capture_callback: event %u unknown", event);
        g_assert_not_reached();
    }
}

void WiresharkApplication::captureFileCallback(int event, void * data)
{
    capture_file *cf = (capture_file *) data;

    switch(event) {

    case(cf_cb_file_closing):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closing");
        emit captureFileClosing(cf);
        break;
    case(cf_cb_file_closed):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Closed");
        emit captureFileClosed(cf);
        break;
    case(cf_cb_file_read_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read started");
        emit captureFileReadStarted(cf);
        break;
    case(cf_cb_file_read_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Read finished");
        emit captureFileReadFinished(cf);
        break;
    case(cf_cb_file_reload_started):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload started");
        emit captureFileReadStarted(cf);
        break;
    case(cf_cb_file_reload_finished):
        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Reload finished");
        emit captureFileReadFinished(cf);
        break;

    case(cf_cb_packet_selected):
    case(cf_cb_packet_unselected):
    case(cf_cb_field_unselected):
        // Pure signals and slots
        break;

//    case(cf_cb_file_save_started): // data = string
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save started");
//        break;
//    case(cf_cb_file_save_finished):
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save finished");
//        break;
//    case(cf_cb_file_save_failed):
//        g_log(LOG_DOMAIN_MAIN, G_LOG_LEVEL_DEBUG, "Callback: Save failed");
//        break;
    default:
        g_log(NULL, G_LOG_LEVEL_DEBUG, "FIX: main_cf_callback %d %p", event, data);
//        g_warning("main_cf_callback: event %u unknown", event);
//        g_assert_not_reached();
    }
}

QDir WiresharkApplication::lastOpenDir() {
    return QDir(last_open_dir);
}

void WiresharkApplication::setLastOpenDir(QString *dir_str) {
    setLastOpenDir(dir_str->toUtf8().constData());
}

void WiresharkApplication::setLastOpenDir(const char *dir_name)
{
    qint64 len;
    gchar *new_last_open_dir;

    if (dir_name) {
        len = strlen(dir_name);
        if (dir_name[len-1] == G_DIR_SEPARATOR) {
            new_last_open_dir = g_strconcat(dir_name, NULL);
        }
        else {
            new_last_open_dir = g_strconcat(dir_name,
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

    g_free(last_open_dir);
    last_open_dir = new_last_open_dir;
}

void WiresharkApplication::clearRecentItems() {
    recent_item_status *ri;

    foreach (ri, recent_items) {
        recent_items.removeOne(ri);
        delete(ri);
    }
    emit updateRecentItemStatus(NULL, 0, false);
}

void WiresharkApplication::itemStatusFinished(const QString &filename, qint64 size, bool accessible) {
    recent_item_status *ri;
    RecentFileStatus *rf_status = qobject_cast<RecentFileStatus *>(QObject::sender());;

//    g_log(NULL, G_LOG_LEVEL_DEBUG, "rf isf %d", recent_items.count());
    foreach (ri, recent_items) {
        if (filename == ri->filename && (size != ri->size || accessible != ri->accessible)) {
            ri->size = size;
            ri->accessible = accessible;
            ri->in_thread = false;

//            g_log(NULL, G_LOG_LEVEL_DEBUG, "rf update %s", filename.toUtf8().constData());
            emit updateRecentItemStatus(filename, size, accessible);
        }
    }

    if (rf_status) {
        rf_status->quit();
    }
}

WiresharkApplication::WiresharkApplication(int &argc,  char **argv) :
    QApplication(argc, argv)
{
    wsApp = this;

    Q_INIT_RESOURCE(display_filter);
    Q_INIT_RESOURCE(i18n);
    Q_INIT_RESOURCE(status);
    Q_INIT_RESOURCE(toolbar);
    Q_INIT_RESOURCE(welcome);

#ifdef Q_WS_WIN
    /* RichEd20.DLL is needed for native file dialog filter entries. */
    if (QLibrary::isLibrary("riched20.dll")) {
        QLibrary riched20("riched20.dll");
        riched20.load();
        if (!riched20.isLoaded()) {
            qDebug() << riched20.errorString();
        }
    }
#endif // Q_WS_WIN

    recent_timer_ = new QTimer(this);
    connect(recent_timer_, SIGNAL(timeout()), this, SLOT(refreshRecentFiles()));
    recent_timer_->start(2000);
}

QList<recent_item_status *> WiresharkApplication::recent_item_list() const {
    return recent_items;
}

void WiresharkApplication::addRecentItem(const QString &filename, qint64 size, bool accessible) {
    recent_item_status *ri = new(recent_item_status);

    ri->filename = filename;
    ri->size = size;
    ri->accessible = accessible;
    ri->in_thread = false;
    recent_items.prepend(ri);

    itemStatusFinished(filename, size, accessible);
}

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
