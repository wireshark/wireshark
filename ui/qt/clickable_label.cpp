/* clickable_label.cpp
 *
 * Taken from https://wiki.qt.io/Clickable_QLabel and adapted for usage
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

#include "ui/qt/clickable_label.h"

#include <QMouseEvent>

ClickableLabel::ClickableLabel(QWidget* parent)
    : QLabel(parent)
{
    setText(QString());
}

void ClickableLabel::mouseReleaseEvent(QMouseEvent * event)
{
    /* It has to be ensured, that if the user clicks on the label and then moves away out of
     * the scope of the widget, the event does not fire. Otherwise this behavior differs from
     * the way, the toolbar buttons work for instance */
    if ( event->pos().x() < 0 || event->pos().x() > size().width() )
        return;
    if ( event->pos().y() < 0 || event->pos().y() > size().height() )
        return;

    emit clicked();
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
