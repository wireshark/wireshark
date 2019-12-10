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

void FindLineEdit::contextMenuEvent(QContextMenuEvent *event)
{
    QMenu *menu = createStandardContextMenu();
    QAction *action;

    menu->addSeparator();

    action = menu->addAction(tr("Textual Find"));
    action->setCheckable(true);
    action->setChecked(!use_regex_);
    connect(action, &QAction::triggered, this, &FindLineEdit::setUseTextual);

    action = menu->addAction(tr("Regular Expression Find"));
    action->setCheckable(true);
    action->setChecked(use_regex_);
    connect(action, &QAction::triggered, this, &FindLineEdit::setUseRegex);

    menu->exec(event->globalPos());
    delete menu;
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
        QRegExp regexp(text());
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
