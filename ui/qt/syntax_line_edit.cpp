/* syntax_line_edit.cpp
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

#include "config.h"

#include <glib.h>

#include <epan/prefs.h>
#include <epan/proto.h>
#include <epan/dfilter/dfilter.h>

#include "syntax_line_edit.h"

#include "color_utils.h"

#include <QAbstractItemView>
#include <QCompleter>
#include <QKeyEvent>
#include <QScrollBar>
#include <QStringListModel>

const int max_completion_items_ = 20;

SyntaxLineEdit::SyntaxLineEdit(QWidget *parent) :
    QLineEdit(parent),
    completer_(NULL),
    completion_model_(NULL)
{
    setSyntaxState();
}

// Override setCompleter so that we don't clobber the filter text on activate.
void SyntaxLineEdit::setCompleter(QCompleter *c)
{
    if (completer_)
        QObject::disconnect(completer_, 0, this, 0);

    completer_ = c;

    if (!completer_)
        return;

    completer_->setWidget(this);
    completer_->setCompletionMode(QCompleter::PopupCompletion);
    completer_->setCaseSensitivity(Qt::CaseInsensitive);
    // Completion items are not guaranteed to be sorted (recent filters +
    // fields), so no setModelSorting.
    completer_->setMaxVisibleItems(max_completion_items_);
    QObject::connect(completer_, SIGNAL(activated(QString)),
                     this, SLOT(insertFieldCompletion(QString)));
}

void SyntaxLineEdit::setSyntaxState(SyntaxState state) {
    syntax_state_ = state;
    state_style_sheet_ = QString(
            "SyntaxLineEdit[syntaxState=\"%1\"] {"
            "  color: %4;"
            "  background-color: %5;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%2\"] {"
            "  color: %4;"
            "  background-color: %6;"
            "}"

            "SyntaxLineEdit[syntaxState=\"%3\"] {"
            "  color: %4;"
            "  background-color: %7;"
            "}"
            )
            .arg(Valid)
            .arg(Invalid)
            .arg(Deprecated)
            .arg("palette(text)")   // Foreground
            .arg(ColorUtils::fromColorT(&prefs.gui_text_valid).name())        // Valid
            .arg(ColorUtils::fromColorT(&prefs.gui_text_invalid).name())      // Invalid
            .arg(ColorUtils::fromColorT(&prefs.gui_text_deprecated).name())   // VDeprecated
            ;
    setStyleSheet(style_sheet_);
}

QString SyntaxLineEdit::syntaxErrorMessage() {
    return syntax_error_message_;
}

QString SyntaxLineEdit::styleSheet() const {
    return style_sheet_;
}

QString SyntaxLineEdit::deprecatedToken()
{
    return deprecated_token_;
}

void SyntaxLineEdit::setStyleSheet(const QString &style_sheet) {
    style_sheet_ = style_sheet;
    QLineEdit::setStyleSheet(style_sheet_ + state_style_sheet_);
}

void SyntaxLineEdit::insertFilter(const QString &filter)
{
    QString padded_filter = filter;

    if (hasSelectedText()) {
        backspace();
    }

    int pos = cursorPosition();
    if (pos > 0 && !text().at(pos - 1).isSpace()) {
        padded_filter.prepend(" ");
    }
    if (pos < text().length() - 1 && !text().at(pos + 1).isSpace()) {
        padded_filter.append(" ");
    }
    insert(padded_filter);
}

void SyntaxLineEdit::checkDisplayFilter(QString filter)
{
    if (filter.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    deprecated_token_.clear();
    dfilter_t *dfp = NULL;
    gchar *err_msg;
    if (dfilter_compile(filter.toUtf8().constData(), &dfp, &err_msg)) {
        GPtrArray *depr = NULL;
        if (dfp) {
            depr = dfilter_deprecated_tokens(dfp);
        }
        if (depr) {
            // You keep using that word. I do not think it means what you think it means.
            setSyntaxState(SyntaxLineEdit::Deprecated);
            deprecated_token_ = (const char *) g_ptr_array_index(depr, 0);
        } else {
            setSyntaxState(SyntaxLineEdit::Valid);
        }
    } else {
        setSyntaxState(SyntaxLineEdit::Invalid);
        syntax_error_message_ = QString::fromUtf8(err_msg);
        g_free(err_msg);
    }
    dfilter_free(dfp);
}

void SyntaxLineEdit::checkFieldName(QString field)
{
    if (field.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    char invalid_char = proto_check_field_name(field.toUtf8().constData());
    if (invalid_char) {
        setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        checkDisplayFilter(field);
    }
}

void SyntaxLineEdit::checkInteger(QString number)
{
    if (number.isEmpty()) {
        setSyntaxState(SyntaxLineEdit::Empty);
        return;
    }

    bool ok;
    text().toInt(&ok);
    if (ok) {
        setSyntaxState(SyntaxLineEdit::Valid);
    } else {
        setSyntaxState(SyntaxLineEdit::Invalid);
    }
}

bool SyntaxLineEdit::isComplexFilter(const QString &filter)
{
    bool is_complex = false;
    for (int i = 0; i < filter.length(); i++) {
        if (!token_chars_.contains(filter.at(i))) {
            is_complex = true;
            break;
        }
    }
    // Don't complete the current filter.
    if (is_complex && filter.startsWith(text()) && filter.compare(text())) {
        return true;
    }
    return false;
}

void SyntaxLineEdit::completionKeyPressEvent(QKeyEvent *event)
{
    // Forward to the completer if needed...
    if (completer_ && completer_->popup()->isVisible()) {
        switch (event->key()) {
        case Qt::Key_Enter:
        case Qt::Key_Return:
        case Qt::Key_Escape:
        case Qt::Key_Tab:
        case Qt::Key_Backtab:
            event->ignore();
            return;
        default:
            break;
        }
    }

    // ...otherwise process the key ourselves.
    SyntaxLineEdit::keyPressEvent(event);

    if (!completer_ || !completion_model_) return;

    // Do nothing on bare shift.
    if ((event->modifiers() & Qt::ShiftModifier) && event->text().isEmpty()) return;

    if (event->modifiers() & (Qt::ControlModifier | Qt::AltModifier | Qt::MetaModifier)) {
        completer_->popup()->hide();
        return;
    }

    QPoint token_coords(getTokenUnderCursor());

    QString token_word = text().mid(token_coords.x(), token_coords.y());
    buildCompletionList(token_word);

    if (completion_model_->stringList().length() < 1) {
        completer_->popup()->hide();
        return;
    }

    QRect cr = cursorRect();
    cr.setWidth(completer_->popup()->sizeHintForColumn(0)
                + completer_->popup()->verticalScrollBar()->sizeHint().width());
    completer_->complete(cr);
}

void SyntaxLineEdit::completionFocusInEvent(QFocusEvent *event)
{
    if (completer_)
        completer_->setWidget(this);
    SyntaxLineEdit::focusInEvent(event);
}

void SyntaxLineEdit::insertFieldCompletion(const QString &completion_text)
{
    if (!completer_) return;

    QPoint field_coords(getTokenUnderCursor());

    // Insert only if we have a matching field or if the entry is empty
    if (field_coords.y() < 1 && !text().isEmpty()) {
        completer_->popup()->hide();
        return;
    }

    QString new_text = text().replace(field_coords.x(), field_coords.y(), completion_text);
    setText(new_text);
    setCursorPosition(field_coords.x() + completion_text.length());
}

QPoint SyntaxLineEdit::getTokenUnderCursor()
{
    if (selectionStart() >= 0) return (QPoint(0,0));

    int pos = cursorPosition();
    int start = pos;
    int len = 0;

    while (start > 0 && token_chars_.contains(text().at(start -1))) {
        start--;
        len++;
    }
    while (pos < text().length() && token_chars_.contains(text().at(pos))) {
        pos++;
        len++;
    }

    return QPoint(start, len);
}
