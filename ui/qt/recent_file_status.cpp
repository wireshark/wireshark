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
