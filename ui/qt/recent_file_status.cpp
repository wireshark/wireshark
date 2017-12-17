/* recent_file_status.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0+
 */

#include "recent_file_status.h"

RecentFileStatus::RecentFileStatus(const QString filename, QObject *parent) :
        QObject(parent), filename_(filename)
{
    // We're a QObject, which means that we emit a destroyed signal,
    // which might happen at the wrong time when automatic deletion is
    // enabled. This will trigger an assert in debug builds (bug 14279).
    setAutoDelete(false);
    // Qt::BlockingQueuedConnection shouldn't be necessary but it doesn't
    // hurt either.
    connect(this, SIGNAL(statusFound(QString, qint64, bool)),
            parent, SLOT(itemStatusFinished(QString, qint64, bool)), Qt::BlockingQueuedConnection);
}

QString RecentFileStatus::getFilename() const {
    return (filename_);
}

void RecentFileStatus::run() {
    fileinfo_.setFile(filename_);

    if (fileinfo_.isFile() && fileinfo_.isReadable()) {
        emit statusFound(filename_, fileinfo_.size(), true);
    } else {
        emit statusFound(filename_, 0, false);
    }
    deleteLater();
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
