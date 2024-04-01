/* dissector_syntax_line_edit.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>

#include <wsutil/utf8_entities.h>

#include <ui/qt/widgets/dissector_syntax_line_edit.h>
#include <ui/qt/widgets/syntax_line_edit.h>

#include <QAction>
#include <QCompleter>
#include <QEvent>
#include <QStringListModel>

#include <wsutil/utf8_entities.h>

// Ordinary dissector names allow the same characters as display filter
// fields (heuristic dissectors don't allow upper-case.)
static const QString fld_abbrev_chars_ = "-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

DissectorSyntaxLineEdit::DissectorSyntaxLineEdit(QWidget *parent) :
    SyntaxLineEdit(parent)
{
    setAccessibleName(tr("Dissector entry"));

    completion_model_ = new QStringListModel(this);
    setCompleter(new QCompleter(completion_model_, this));
    setCompletionTokenChars(fld_abbrev_chars_);

    updateDissectorNames();
    setDefaultPlaceholderText();

    connect(this, &DissectorSyntaxLineEdit::textChanged, this,
            static_cast<void (DissectorSyntaxLineEdit::*)(const QString &)>(&DissectorSyntaxLineEdit::checkDissectorName));
}

void DissectorSyntaxLineEdit::updateDissectorNames()
{
    GList *dissector_names = get_dissector_names();
    QStringList dissector_list;
    for (GList* l = dissector_names; l != NULL; l = l->next) {
        dissector_list << (const char*) l->data;
    }
    g_list_free(dissector_names);
    dissector_list.sort();
    completion_model_->setStringList(dissector_list);
}

void DissectorSyntaxLineEdit::setDefaultPlaceholderText()
{
    placeholder_text_ = QString(tr("Enter a dissector %1")).arg(UTF8_HORIZONTAL_ELLIPSIS);

    setPlaceholderText(placeholder_text_);
}

void DissectorSyntaxLineEdit::checkDissectorName(const QString &dissector)
{
    if (dissector.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
    } else if (find_dissector(dissector.trimmed().toUtf8().constData())) {
        setSyntaxState(SyntaxLineEdit::Valid);
    } else {
        setSyntaxState(SyntaxLineEdit::Invalid);
    }
}

void DissectorSyntaxLineEdit::buildCompletionList(const QString &field_word, const QString &preamble _U_)
{
#if 0
    // It would be nice to push a hint about the current dissector with
    // the description, as we do with the status line in the main window
    // with filters.
    if (syntaxState() == Valid) {
        dissector_handle_t handle = find_dissector(field_word.toUtf8().constData());
        if (handle) {
            QString cursor_field_msg = QString("%1: %2")
                    .arg(dissector_handle_get_dissector_name(handle))
                    .arg(dissector_handle_get_description(handle));
        }
    }
#endif

    completer()->setCompletionPrefix(field_word);
}

void DissectorSyntaxLineEdit::changeEvent(QEvent* event)
{
    if (0 != event)
    {
        switch (event->type())
        {
        case QEvent::LanguageChange:
            setDefaultPlaceholderText();
            break;
        default:
            break;
        }
    }
    SyntaxLineEdit::changeEvent(event);
}
