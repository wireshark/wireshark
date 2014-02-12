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

class SyntaxLineEdit : public QLineEdit
{
    Q_OBJECT
    Q_PROPERTY(SyntaxState syntaxState READ syntaxState)
    Q_ENUMS(SyntaxState)
public:
    explicit SyntaxLineEdit(QWidget *parent = 0);
    enum SyntaxState { Empty, Invalid, Deprecated, Valid };

    SyntaxState syntaxState() const { return syntax_state_; }
    void setSyntaxState(SyntaxState state = Empty);
    QString styleSheet() const;
    QString deprecatedToken();

public slots:
    void setStyleSheet(const QString &style_sheet);

    // Built-in syntax checks. Connect textChanged to these as needed.
    void checkDisplayFilter(QString filter);
    void checkFieldName(QString field);

private:
    SyntaxState syntax_state_;
    QString style_sheet_;
    QString state_style_sheet_;
    QString deprecated_token_;

signals:

};

#endif // SYNTAX_LINE_EDIT_H
