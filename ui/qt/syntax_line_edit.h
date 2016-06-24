/* syntax_line_edit.h
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

#ifndef SYNTAX_LINE_EDIT_H
#define SYNTAX_LINE_EDIT_H

#include <QLineEdit>

class QCompleter;
class QStringListModel;

// Autocompletion is partially implemented. Subclasses must:
// - Provide buildCompletionList
// - Call setCompletionTokenChars

class SyntaxLineEdit : public QLineEdit
{
    Q_OBJECT
    Q_PROPERTY(SyntaxState syntaxState READ syntaxState)
    Q_ENUMS(SyntaxState)
public:
    explicit SyntaxLineEdit(QWidget *parent = 0);
    enum SyntaxState { Empty, Busy, Invalid, Deprecated, Valid };

    SyntaxState syntaxState() const { return syntax_state_; }
    void setSyntaxState(SyntaxState state = Empty);
    QString syntaxErrorMessage();
    QString styleSheet() const;
    QString deprecatedToken();

    void setCompleter(QCompleter *c);
    QCompleter *completer() const { return completer_; }

public slots:
    void setStyleSheet(const QString &style_sheet);
    // Insert filter text at the current position, adding spaces where needed.
    void insertFilter(const QString &filter);

    // Built-in syntax checks. Connect textChanged to these as needed.
    void checkDisplayFilter(QString filter);
    void checkFieldName(QString field);
    void checkCustomColumn(QString fields);
    void checkInteger(QString number);

protected:
    QCompleter *completer_;
    QStringListModel *completion_model_;
    void setCompletionTokenChars(const QString &token_chars) { token_chars_ = token_chars; }
    bool isComplexFilter(const QString &filter);
    virtual void buildCompletionList(const QString&) { }
    // x = Start position, y = length
    QPoint getTokenUnderCursor();

    virtual bool event(QEvent *event);
    void completionKeyPressEvent(QKeyEvent *event);
    void completionFocusInEvent(QFocusEvent *event);
    virtual void focusOutEvent(QFocusEvent *event);

private:
    SyntaxState syntax_state_;
    QString style_sheet_;
    QString state_style_sheet_;
    QString syntax_error_message_;
    QString token_chars_;
    QColor busy_fg_;

private slots:
    void insertFieldCompletion(const QString &completion_text);

signals:

};

#endif // SYNTAX_LINE_EDIT_H
