/* range_syntax_lineedit.h
 * Delegates for editing prefereneces.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RANGE_SYNTAX_LINEEDIT_H
#define RANGE_SYNTAX_LINEEDIT_H

#include <ui/qt/widgets/syntax_line_edit.h>

#include <QWidget>

class RangeSyntaxLineEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit RangeSyntaxLineEdit(QWidget *parent = 0);
    void setMaxRange(unsigned int max);

public slots:
    void checkRange(QString range);

private:
    unsigned int maxRange_;
};

#endif // RANGE_SYNTAX_LINEEDIT_H
