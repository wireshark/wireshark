/* clickable_label.cpp
 *
 * Taken from https://wiki.qt.io/Clickable_QLabel and adapted for usage
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/clickable_label.h>

#include <QMouseEvent>

ClickableLabel::ClickableLabel(QWidget* parent)
    : QLabel(parent)
{
    setMinimumWidth(0);
    setText(QString());

    setStyleSheet(QStringLiteral(
                      "QLabel {"
                      "  margin-left: 0.5em;"
                      " }"
                      ));
}

void ClickableLabel::mouseReleaseEvent(QMouseEvent * event)
{
    /* It has to be ensured, that if the user clicks on the label and then moves away out of
     * the scope of the widget, the event does not fire. Otherwise this behavior differs from
     * the way, the toolbar buttons work for instance */
    if (event->pos().x() < 0 || event->pos().x() > size().width())
        return;
    if (event->pos().y() < 0 || event->pos().y() > size().height())
        return;

    emit clicked();
}

void ClickableLabel::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton)
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        emit clickedAt(event->globalPosition().toPoint(), Qt::LeftButton);
#else
        emit clickedAt(event->globalPos(), Qt::LeftButton);
#endif
}

void ClickableLabel::contextMenuEvent(QContextMenuEvent *event)
{
    emit clickedAt(QPoint(event->globalPos()), Qt::RightButton);
}
