/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
    // Error message with filter expression and location error.
    QString syntaxErrorMessageFull();
    QString styleSheet() const;
    QString deprecatedToken();

    void setCompleter(QCompleter *c);
    QCompleter *completer() const { return completer_; }
    void allowCompletion(bool enabled);

    static QString createSyntaxErrorMessageFull(const QString &filter,
                                                const QString &err_msg,
                                                qsizetype loc_start, size_t loc_length);

public slots:
    void setStyleSheet(const QString &style_sheet);
    // Insert filter text at the current position, adding spaces where needed.
    void insertFilter(const QString &filter);

    // Built-in syntax checks. Connect textChanged to these as needed.
    bool checkDisplayFilter(QString filter);
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
    virtual void paintEvent(QPaintEvent *event);

private:
    SyntaxState syntax_state_;
    QString style_sheet_;
    QString state_style_sheet_;
    QString syntax_error_message_;
    QString syntax_error_message_full_;
    QString token_chars_;
    bool completion_enabled_;

private slots:
    void insertFieldCompletion(const QString &completion_text);

signals:

};

#endif // SYNTAX_LINE_EDIT_H
