/* find_line_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <ui/qt/widgets/find_line_edit.h>
#include <ui/qt/utils/color_utils.h>
#include "epan/prefs.h"

#include <QAction>
#include <QKeyEvent>
#include <QMenu>
#include <QRegularExpression>

void FindLineEdit::contextMenuEvent(QContextMenuEvent *event)
{
    QMenu *menu = createStandardContextMenu();
    QAction *action;

    menu->setAttribute(Qt::WA_DeleteOnClose);
    menu->addSeparator();

    action = menu->addAction(tr("Textual Find"));
    action->setCheckable(true);
    action->setChecked(!use_regex_);
    connect(action, &QAction::triggered, this, &FindLineEdit::setUseTextual);

    action = menu->addAction(tr("Regular Expression Find"));
    action->setCheckable(true);
    action->setChecked(use_regex_);
    connect(action, &QAction::triggered, this, &FindLineEdit::setUseRegex);

    menu->popup(event->globalPos());
}

void FindLineEdit::keyPressEvent(QKeyEvent *event)
{
    QLineEdit::keyPressEvent(event);

    if (use_regex_) {
        validateText();
    }
}

void FindLineEdit::validateText()
{
    QString style("QLineEdit { background-color: %1; }");

    if (!use_regex_ || text().isEmpty()) {
        setStyleSheet(style.arg(QString("")));
    } else {
        QRegularExpression regexp(text(), QRegularExpression::UseUnicodePropertiesOption);
        if (regexp.isValid()) {
            setStyleSheet(style.arg(ColorUtils::fromColorT(prefs.gui_text_valid).name()));
        } else {
            setStyleSheet(style.arg(ColorUtils::fromColorT(prefs.gui_text_invalid).name()));
        }
    }
}

void FindLineEdit::setUseTextual()
{
    use_regex_ = false;
    validateText();
    emit useRegexFind(use_regex_);
}

void FindLineEdit::setUseRegex()
{
    use_regex_ = true;
    validateText();
    emit useRegexFind(use_regex_);
}
