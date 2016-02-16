/* find_line_edit.cpp
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

#include "find_line_edit.h"
#include "color_utils.h"
#include "epan/prefs.h"

#include <QAction>
#include <QKeyEvent>
#include <QMenu>

void FindLineEdit::contextMenuEvent(QContextMenuEvent *event)
{
    QMenu *menu = createStandardContextMenu();

#if (QT_VERSION >= QT_VERSION_CHECK(5, 3, 0))
    QAction *action;

    menu->addSeparator();

    action = menu->addAction(tr("Textual Find"));
    action->setCheckable(true);
    action->setChecked(!use_regex_);
    connect(action, SIGNAL(triggered()), this, SLOT(setUseTextual()));

    action = menu->addAction(tr("Regular Expression Find"));
    action->setCheckable(true);
    action->setChecked(use_regex_);
    connect(action, SIGNAL(triggered()), this, SLOT(setUseRegex()));
#endif

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
