/* elided_label.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/elided_label.h>

#include <ui/qt/utils/color_utils.h>

#include <QFontMetrics>
#include <QResizeEvent>

ElidedLabel::ElidedLabel(QWidget *parent) :
    QLabel(parent),
    small_text_(false)
{
    QFontMetrics fm(font());
    setMinimumWidth(fm.height() * 5); // em-widths
}

void ElidedLabel::setUrl(const QString &url)
{
    url_ = url;
    updateText();
}

bool ElidedLabel::event(QEvent *event)
{
    switch (event->type()) {
    case QEvent::ApplicationPaletteChange:
        updateText();
        break;
    default:
        break;

    }
    return QLabel::event(event);
}

void ElidedLabel::resizeEvent(QResizeEvent *)
{
    updateText();
}

void ElidedLabel::updateText()
{
    // XXX We should probably move text drawing to PaintEvent to match
    // LabelStack.
    int fudged_width = small_text_ ? width() * 1.2 : width();
    QString elided_text = fontMetrics().elidedText(full_text_, Qt::ElideMiddle, fudged_width);
    QString label_text = small_text_ ? "<small><i>" : "<i>";

    if (url_.length() > 0) {
        label_text.prepend(ColorUtils::themeLinkStyle());
        label_text.append(QString("<a href=\"%1\">%2</a>")
                .arg(url_)
                .arg(elided_text)
                );
    } else {
        label_text += elided_text;
    }
    label_text += small_text_ ? "</i></small>" : "</i>";
    QLabel::setText(label_text);
}

void ElidedLabel::clear()
{
    full_text_.clear();
    url_.clear();
    setToolTip("");
    updateText();
}

void ElidedLabel::setText(const QString &text)
{
    full_text_ = text;
    updateText();
}
