/* field_filter_edit.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FIELDFILTEREDIT_H
#define FIELDFILTEREDIT_H

#include <ui/qt/widgets/syntax_line_edit.h>

class QEvent;
class StockIconToolButton;

class FieldFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit FieldFilterEdit(QWidget *parent = 0);

protected:
    void keyPressEvent(QKeyEvent *event) { completionKeyPressEvent(event); }
    void focusInEvent(QFocusEvent *event) { completionFocusInEvent(event); }
    void focusOutEvent(QFocusEvent *event);

public slots:
    bool checkFilter();
    void applyDisplayFilter();

private slots:
    void checkFilter(const QString &filter_text);
    void clearFilter();
    void changeEvent(QEvent* event);

    void showFilters();
    void prepareFilter();

private:
    QString placeholder_text_;

    void setDefaultPlaceholderText();
    void buildCompletionList(const QString& field_word);

signals:
    void pushFilterSyntaxStatus(const QString&);
    void popFilterSyntaxStatus();
    void pushFilterSyntaxWarning(const QString&);
    void filterPackets(QString new_filter, bool force);
};

#endif // FIELDFILTEREDIT_H
