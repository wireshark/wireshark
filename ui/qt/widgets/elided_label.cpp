/* elided_label.cpp
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

#include "elided_label.h"

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
