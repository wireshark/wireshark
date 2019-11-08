/* wireshark_mime_data.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <utils/wireshark_mime_data.h>

const QString WiresharkMimeData::ColoringRulesMimeType = "application/vnd.wireshark.coloringrules";
const QString WiresharkMimeData::ColumnListMimeType = "application/vnd.wireshark.columnlist";
const QString WiresharkMimeData::FilterListMimeType = "application/vnd.wireshark.filterlist";
const QString WiresharkMimeData::DisplayFilterMimeType = "application/vnd.wireshark.displayfilter";

void WiresharkMimeData::allowPlainText()
{
    setText(labelText());
}

ToolbarEntryMimeData::ToolbarEntryMimeData(QString element, int pos) :
    WiresharkMimeData(),
    element_(element),
    filter_(QString()),
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

void ToolbarEntryMimeData::setFilter(QString text)
{
    filter_ = text;
}

QString ToolbarEntryMimeData::filter() const
{
    return filter_;
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

