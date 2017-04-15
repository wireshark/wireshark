/* interface_toolbar_reader.h
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

#ifndef INTERFACE_TOOLBAR_READER_H
#define INTERFACE_TOOLBAR_READER_H

#include <QObject>
#include <QByteArray>

namespace Ui {
class InterfaceToolbarReader;
}

class InterfaceToolbarReader : public QObject
{
    Q_OBJECT

public:
    InterfaceToolbarReader(QString ifname, QString control_in, QObject *parent = 0) :
    QObject(parent), ifname_(ifname), control_in_(control_in) {}

public slots:
    void loop();

signals:
    void received(QString ifname, int num, int command, QByteArray payload);
    void finished();

private:
    QString ifname_;
    QString control_in_;
};

#endif // INTERFACE_TOOLBAR_READER_H

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
