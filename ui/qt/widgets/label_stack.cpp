/* label_stack.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/label_stack.h>

#include <QContextMenuEvent>
#include <QPainter>
#include <QMouseEvent>
#include <QStyleOption>

#include <ui/qt/utils/color_utils.h>

/* Temporary message timeouts */
const int temporary_interval_ = 1000;
const int temporary_msg_timeout_ = temporary_interval_ * 9;
const int temporary_flash_timeout_ = temporary_interval_ / 5;
const int num_flashes_ = 3;

LabelStack::LabelStack(QWidget *parent) :
    QLabel(parent),
    temporary_ctx_(-1),
    shrinkable_(false)
{
#ifdef Q_OS_MAC
    setAttribute(Qt::WA_MacSmallSize, true);
#endif
    fillLabel();

    connect(&temporary_timer_, &QTimer::timeout, this, &LabelStack::updateTemporaryStatus);
}

void LabelStack::setTemporaryContext(const int ctx) {
    temporary_ctx_ = ctx;
}

void LabelStack::fillLabel() {
    StackItem si;
    QString style_sheet;

    style_sheet =
            "QLabel {"
            "  margin-left: 0.5em;";

    if (labels_.isEmpty()) {
        clear();
        return;
    }

    si = labels_.first();

    if (si.ctx == temporary_ctx_) {
        style_sheet += QString(
                    "  border-radius: 0.25em;"
                    "  background-color: %2;"
                    )
                .arg(ColorUtils::warningBackground().name());
    }

    style_sheet += "}";
    if (styleSheet().size() != style_sheet.size()) {
        // Can be computationally expensive.
        setStyleSheet(style_sheet);
    }
    setText(si.text);
    setToolTip(si.tooltip);
}

void LabelStack::pushText(const QString &text, int ctx, const QString &tooltip) {
    popText(ctx);

    if (ctx == temporary_ctx_) {
        temporary_timer_.stop();

        temporary_epoch_.start();
        temporary_timer_.start(temporary_flash_timeout_);
        emit toggleTemporaryFlash(true);
    }

    StackItem si;
    si.text = text;
    si.tooltip = tooltip;
    si.ctx = ctx;
    labels_.prepend(si);
    fillLabel();
}

void LabelStack::setShrinkable(bool shrinkable)
{
    shrinkable_ = shrinkable;
    int min_width = 0;

    if (shrinkable) {
        min_width = fontMetrics().height() * 5; // em-widths
    }
    setMinimumWidth(min_width);
    fillLabel();
}

void LabelStack::mousePressEvent(QMouseEvent *event)
{
    if (event->button() == Qt::LeftButton) {
#if QT_VERSION >= QT_VERSION_CHECK(6, 0 ,0)
        emit mousePressedAt(event->globalPosition().toPoint(), Qt::LeftButton);
#else
        emit mousePressedAt(event->globalPos(), Qt::LeftButton);
#endif
    }
}

void LabelStack::mouseReleaseEvent(QMouseEvent *)
{
}

void LabelStack::mouseDoubleClickEvent(QMouseEvent *)
{
}

void LabelStack::mouseMoveEvent(QMouseEvent *)
{
}

void LabelStack::contextMenuEvent(QContextMenuEvent *event)
{
    emit mousePressedAt(QPoint(event->globalPos()), Qt::RightButton);
}

void LabelStack::paintEvent(QPaintEvent *event)
{
    if (!shrinkable_) {
        QLabel::paintEvent(event);
        return;
    }

    QFrame::paintEvent(event);

    QString elided_text = fontMetrics().elidedText(text(), Qt::ElideMiddle, width());
    QPainter painter(this);
    QRect contents_rect = contentsRect();
    QStyleOption opt;

    contents_rect.adjust(margin(), margin(), -margin(), -margin());
    opt.initFrom(this);

    style()->drawItemText(&painter, contents_rect, alignment(), opt.palette,
                          isEnabled(), elided_text, foregroundRole());
}

void LabelStack::popText(int ctx) {
    QMutableListIterator<StackItem> iter(labels_);

    while (iter.hasNext()) {
        if (iter.next().ctx == ctx) {
            iter.remove();
            break;
        }
    }

    fillLabel();
}

void LabelStack::updateTemporaryStatus() {
    if (temporary_epoch_.elapsed() >= temporary_msg_timeout_) {
        popText(temporary_ctx_);
        emit toggleTemporaryFlash(false);
        temporary_timer_.stop();
    } else {
        for (int i = (num_flashes_ * 2); i > 0; i--) {
            if (temporary_epoch_.elapsed() >= temporary_flash_timeout_ * i) {
                emit toggleTemporaryFlash(i % 2);
                break;
            }
        }
    }
}
