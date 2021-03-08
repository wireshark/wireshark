/* find_line_edit.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FIND_LINE_EDIT_H
#define FIND_LINE_EDIT_H

#include <QLineEdit>

namespace Ui {
class FindLineEdit;
}

class FindLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    explicit FindLineEdit(QWidget *parent = 0) : QLineEdit(parent), use_regex_(false) { }
    ~FindLineEdit() { }

signals:
    void useRegexFind(bool);

private slots:
    void setUseTextual();
    void setUseRegex();

private:
    void contextMenuEvent(QContextMenuEvent *event);
    void keyPressEvent(QKeyEvent *event);
    void validateText();

    bool use_regex_;
};

#endif // FIND_LINE_EDIT_H
