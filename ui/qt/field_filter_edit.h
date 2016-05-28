/* display_filter_edit.h
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

#ifndef FIELDFILTEREDIT_H
#define FIELDFILTEREDIT_H

#include "syntax_line_edit.h"

class QEvent;
class StockIconToolButton;

class FieldFilterEdit : public SyntaxLineEdit
{
    Q_OBJECT
public:
    explicit FieldFilterEdit(QWidget *parent = 0);

protected:
    void paintEvent(QPaintEvent *evt);
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
    QAction *save_action_;
    QAction *remove_action_;

    void setDefaultPlaceholderText();
    void buildCompletionList(const QString& field_word);

signals:
    void pushFilterSyntaxStatus(const QString&);
    void popFilterSyntaxStatus();
    void pushFilterSyntaxWarning(const QString&);
    void filterPackets(QString new_filter, bool force);
};

#endif // FIELDFILTEREDIT_H

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
