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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef WIRESHARK_APPLICATION_H
#define WIRESHARK_APPLICATION_H

#include "config.h"

#include <glib.h>

#include "file.h"

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
    QList<recent_item_status *> recent_item_list() const;
    void addRecentItem(const QString &filename, qint64 size, bool accessible);
    void captureFileCallback(int event, void * data);

private:
    QTimer *recentTimer;

signals:
    void updateRecentItemStatus(const QString &filename, qint64 size, bool accessible);

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
