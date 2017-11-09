/* field_information.h
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

#ifndef FIELD_INFORMATION_H_
#define FIELD_INFORMATION_H_

#include <config.h>

#include <epan/proto.h>

#include "data_printer.h"

#include <QObject>

class FieldInformation : public QObject, public IDataPrintable
{
    Q_OBJECT
    Q_INTERFACES(IDataPrintable)

public:

    struct HeaderInfo
    {
        QString name;
        QString description;
        QString abbreviation;
        bool isValid;
    };

    struct Position
    {
        int start;
        int end;
        int length;
    };

    explicit FieldInformation(field_info * fi, QObject * parent = Q_NULLPTR);

    bool isValid();

    field_info * fieldInfo() const;

    HeaderInfo headerInfo() const;
    Position position() const;
    Position appendix() const;

    void setParentField(field_info * fi);
    FieldInformation * parentField() const;
    bool tvbContains(FieldInformation *);

    QByteArray printableData();

private:

    field_info * fi_;
    field_info * parent_fi_;
};


#endif // FIELD_INFORMATION_H_

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
