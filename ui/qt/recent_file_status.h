/* recent_file_status.h
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

#ifndef RECENT_FILE_STATUS_H
#define RECENT_FILE_STATUS_H

#include <QObject>

class RecentFileStatus : public QObject
{
    Q_OBJECT
public:
    RecentFileStatus(const QString &filename, QObject *parent = 0) :
        QObject(parent), filename_(filename), size_(0) {}

    QString getFilename() const { return (filename_); }
    size_t getSize() const { return (size_); }
    void quit() { emit finished(); }

private:
    QString filename_;
    size_t size_;

signals:
    void statusFound(const QString &filename = *new QString(), qint64 size = 0, bool accessible = false);
    void finished();

public slots:
    void start();

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
