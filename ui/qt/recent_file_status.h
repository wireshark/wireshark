/* recent_file_status.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RECENT_FILE_STATUS_H
#define RECENT_FILE_STATUS_H

#include <QRunnable>
#include <QFileInfo>

class RecentFileStatus : public QObject, public QRunnable
{
    Q_OBJECT
public:
    RecentFileStatus(const QString filename, QObject *parent);

protected:
    void run();

private:
    const QString    filename_;
    QFileInfo  fileinfo_;

signals:
    void statusFound(const QString filename = QString(), qint64 size = 0, bool accessible = false);
};

#endif // RECENT_FILE_STATUS_H

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
