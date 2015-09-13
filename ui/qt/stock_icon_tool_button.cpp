/* stock_icon_tool_button.cpp
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

#include "stock_icon_tool_button.h"

#include "stock_icon.h"

#include <QApplication>
#include <QEvent>
#include <QMenu>
#include <QMouseEvent>

// We want nice icons that render correctly, and that are responsive
// when the user hovers and clicks them.
// Using setIcon renders correctly on normal and retina displays. It is
// not completely responsive, particularly on OS X.
// Calling setStyleSheet is responsive, but does not render correctly on
// retina displays: https://bugreports.qt.io/browse/QTBUG-36825
// Subclass QToolButton, which lets us catch events and set icons as needed.

StockIconToolButton::StockIconToolButton(QWidget * parent, QString stock_icon_name) :
    QToolButton(parent),
    leave_timer_(0)
{
    if (!stock_icon_name.isEmpty()) {
        setStockIcon(stock_icon_name);
    }
}

void StockIconToolButton::setIconMode(QIcon::Mode mode)
{
    QIcon mode_icon;
    QList<QIcon::State> states = QList<QIcon::State>() << QIcon::Off << QIcon::On;
    foreach (QIcon::State state, states) {
        foreach (QSize size, base_icon_.availableSizes(mode, state)) {
            mode_icon.addPixmap(base_icon_.pixmap(size, mode, state), mode, state);
        }
    }
    setIcon(mode_icon);
}

void StockIconToolButton::setStockIcon(QString icon_name)
{
    base_icon_ = StockIcon(icon_name);
    setIconMode();
}

bool StockIconToolButton::event(QEvent *event)
{
    switch (event->type()) {
        case QEvent::Enter:
        if (isEnabled()) {
            setIconMode(QIcon::Active);
            if (leave_timer_ > 0) killTimer(leave_timer_);
            leave_timer_ = startTimer(leave_interval_);
        }
        break;
    case QEvent::MouseButtonPress:
        if (isEnabled()) {
            setIconMode(QIcon::Selected);
        }
        break;
    case QEvent::Leave:
        if (leave_timer_ > 0) killTimer(leave_timer_);
        leave_timer_ = 0;
        // Fall through
    case QEvent::MouseButtonRelease:
        setIconMode();
        break;
    case QEvent::Timer:
    {
        // We can lose QEvent::Leave, QEvent::HoverLeave and underMouse()
        // on OS X if a tooltip appears:
        // https://bugreports.qt.io/browse/QTBUG-46379
        // Work around the issue by periodically checking the mouse
        // position and scheduling a fake leave event when the mouse
        // moves away.
        QTimerEvent *te = (QTimerEvent *) event;
        bool under_mouse = rect().contains(mapFromGlobal(QCursor::pos()));
        if (te->timerId() == leave_timer_ && !under_mouse) {
            killTimer(leave_timer_);
            leave_timer_ = 0;
            QMouseEvent *me = new QMouseEvent(QEvent::Leave, mapFromGlobal(QCursor::pos()), Qt::NoButton, Qt::NoButton, Qt::NoModifier);
            QApplication::postEvent(this, me);
        }
        break;
    }
    default:
        break;
    }

    return QToolButton::event(event);
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
