/* wireshark_mime_data.h
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

#ifndef UI_QT_UTILS_WIRESHARK_MIME_DATA_H_
#define UI_QT_UTILS_WIRESHARK_MIME_DATA_H_

#include <QMimeData>

class DisplayFilterMimeData: public QMimeData {
    Q_OBJECT
public:

    DisplayFilterMimeData(QString description, QString field, QString filter);

    QString description() const;
    QString field() const;
    QString filter() const;

    QString labelText() const;

private:

    QString description_;
    QString filter_;
    QString field_;

};

class ToolbarEntryMimeData: public QMimeData {
    Q_OBJECT
public:

    ToolbarEntryMimeData(QString element, int pos);

    int position() const;
    QString element() const;

    QString labelText() const;

private:

    QString element_;
    int pos_;

};

#endif /* UI_QT_UTILS_WIRESHARK_MIME_DATA_H_ */

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

