/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DISSECTOR_SYNTAX_LINEEDIT_H
#define DISSECTOR_SYNTAX_LINEEDIT_H

#include <ui/qt/widgets/syntax_line_edit.h>

class QEvent;
class StockIconToolButton;

class DissectorSyntaxLineEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit DissectorSyntaxLineEdit(QWidget *parent = 0);
    void updateDissectorNames();
    void setDefaultPlaceholderText();

protected:
    void keyPressEvent(QKeyEvent *event) { completionKeyPressEvent(event); }
    void focusInEvent(QFocusEvent *event) { completionFocusInEvent(event); }

public slots:
    void checkDissectorName(const QString &dissector);

private slots:
    void changeEvent(QEvent* event);

private:
    QString placeholder_text_;

    void buildCompletionList(const QString &field_word, const QString &preamble);
};

#endif // DISSECTOR_SYNTAX_LINEEDIT_H
