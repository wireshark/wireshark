/* wireshark_mime_data.cpp
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

#include <utils/wireshark_mime_data.h>

DisplayFilterMimeData::DisplayFilterMimeData(QString description, QString field, QString filter) :
QMimeData(),
description_(description),
filter_(filter),
field_(field)
{}

QString DisplayFilterMimeData::description() const
{
    return description_;
}

QString DisplayFilterMimeData::filter() const
{
    return filter_;
}

QString DisplayFilterMimeData::field() const
{
    return field_;
}

QString DisplayFilterMimeData::labelText() const
{
    return QString("%1\n%2").arg(description_, filter_);
}

ToolbarEntryMimeData::ToolbarEntryMimeData(QString element, int pos) :
    QMimeData(),
    element_(element),
    pos_(pos)
{}

QString ToolbarEntryMimeData::element() const
{
    return element_;
}

QString ToolbarEntryMimeData::labelText() const
{
    return QString("%1").arg(element_);
}

int ToolbarEntryMimeData::position() const
{
    return pos_;
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

