/* wireshark_mime_data.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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

