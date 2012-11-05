/* wireshark_application.c
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

#ifndef WIRESHARK_APPLICATION_H
#define WIRESHARK_APPLICATION_H

#include "config.h"

#include <glib.h>

#include "capture_opts.h"
#include "file.h"
#include "register.h"

#include "ui/help_url.h"

#include <QApplication>
#include <QList>
#include <QFileInfo>
#include <QThread>

// Recent items:
// - Read from prefs
// - Add from open file
// - Check current list
// - Signal updated item
// -
typedef struct _recent_item_status {
    QString filename;
    qint64 size;
    bool accessible;
    bool in_thread;
} recent_item_status;

class WiresharkApplication : public QApplication
{
    Q_OBJECT
public:
    explicit WiresharkApplication(int &argc,  char **argv);

    void registerUpdate(register_action_e action, const char *message);
    void allSystemsGo();
    QList<recent_item_status *> recentItems() const;
    void addRecentItem(const QString &filename, qint64 size, bool accessible);
#ifdef HAVE_LIBPCAP
    void captureCallback(int event, capture_options * capture_opts);
#endif
    void captureFileCallback(int event, void * data);
    QDir lastOpenDir();
    void setLastOpenDir(const char *dir_name);
    void setLastOpenDir(QString *dir_str);
    void helpTopicAction(topic_action_e action);
    QFont monospaceFont(bool bold = false);


private:
    bool initialized_;
    QTimer *recent_timer_;
    QList<QString> pending_open_files_;

protected:
    bool event(QEvent *event);

signals:
    void appInitialized();
    void openCaptureFile(QString &cf_path);
    void updateRecentItemStatus(const QString &filename, qint64 size, bool accessible);
    void splashUpdate(register_action_e action, const char *message);

#ifdef HAVE_LIBPCAP
    // XXX It might make more sense to move these to main.cpp or main_window.cpp or their own class.
    void captureCapturePrepared(capture_options *capture_opts);
    void captureCaptureUpdateStarted(capture_options *capture_opts);
    void captureCaptureUpdateFinished(capture_options *capture_opts);
    void captureCaptureFixedStarted(capture_options *capture_opts);
    void captureCaptureFixedFinished(capture_options *capture_opts);
    void captureCaptureStopping(capture_options *capture_opts);
    void captureCaptureFailed(capture_options *capture_opts);
#endif

    void captureFileOpened(const capture_file *cf);
    void captureFileReadStarted(const capture_file *cf);
    void captureFileReadFinished(const capture_file *cf);
    void captureFileClosing(const capture_file *cf);
    void captureFileClosed(const capture_file *cf);

public slots:
    void clearRecentItems();

private slots:
    void itemStatusFinished(const QString &filename = "", qint64 size = 0, bool accessible = false);
    void refreshRecentFiles(void);
};

extern WiresharkApplication *wsApp;

#endif // WIRESHARK_APPLICATION_H

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
