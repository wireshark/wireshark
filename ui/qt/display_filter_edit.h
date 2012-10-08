/* display_filter_edit.h
 *
 * $Id$
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

#ifndef DISPLAYFILTEREDIT_H
#define DISPLAYFILTEREDIT_H

#include <QtGui>
#include "syntax_line_edit.h"

class DisplayFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit DisplayFilterEdit(QWidget *parent = 0, bool plain = false);

protected:
    void paintEvent(QPaintEvent *evt);
    void resizeEvent(QResizeEvent *);
//    void focusInEvent(QFocusEvent *evt);
//    void focusOutEvent(QFocusEvent *evt);

private slots:
    void checkFilter(const QString &text);
    void showDisplayFilterDialog();
    void applyDisplayFilter();

private:
    bool plain_;
    bool field_name_only_;
    QString empty_filter_message_;
    QToolButton *bookmark_button_;
    QToolButton *clear_button_;
    QToolButton *apply_button_;

signals:
    void pushFilterSyntaxStatus(QString&);
    void popFilterSyntaxStatus();
    void pushFilterSyntaxWarning(QString&);

public slots:

};

#endif // DISPLAYFILTEREDIT_H

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
