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
#include <ui/qt/utils/theme_manager.h>

#include <QFontMetrics>
#include <QResizeEvent>

ElidedLabel::ElidedLabel(QWidget *parent) :
    QLabel(parent),
    small_text_(false)
{
    QFontMetrics fm(font());
    setMinimumWidth(fm.height() * 5); // em-widths
    connect(ThemeManager::instance(), &ThemeManager::themeChanged,
            this, &ElidedLabel::updateText);
}

void ElidedLabel::setUrl(const QString &url)
{
    url_ = url;
    updateText();
}

void ElidedLabel::setSuffix(const QString &suffix)
{
    suffix_ = suffix;
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
    QFontMetrics fm = fontMetrics();
    QString elided_text = fm.elidedText(full_text_, Qt::ElideMiddle, fudged_width);
    QString elided_suffix;

    if (!suffix_.isEmpty()) {
        // The text is elided first, keeping a few characters of it, then the suffix
        int min_width = qMin(fm.horizontalAdvance(full_text_), fm.averageCharWidth() * 20);
        int text_width = qMax(fudged_width - fm.horizontalAdvance(suffix_), min_width);
        elided_text = fm.elidedText(full_text_, Qt::ElideMiddle, text_width);
        elided_suffix = fm.elidedText(suffix_, Qt::ElideRight, fudged_width - fm.horizontalAdvance(elided_text));
    }

    QString label_text = small_text_ ? "<small><i>" : "<i>";

    if (url_.length() > 0) {
        label_text.prepend(ColorUtils::themeLinkStyle());
        label_text.append(QStringLiteral("<a href=\"%1\">%2</a>").arg(url_, elided_text.toHtmlEscaped()));
    } else {
        label_text += elided_text.toHtmlEscaped();
    }
    label_text += elided_suffix.toHtmlEscaped();
    label_text += small_text_ ? "</i></small> " : "</i> ";
    QLabel::setText(label_text);
}

void ElidedLabel::clear()
{
    full_text_.clear();
    url_.clear();
    suffix_.clear();
    setToolTip("");
    updateText();
}

void ElidedLabel::setText(const QString &text)
{
    full_text_ = text;
    updateText();
}
