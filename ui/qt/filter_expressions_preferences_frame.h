/* filter_expressions_preferences_frame.h
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

#ifndef FILTER_EXPRESSIONS_PREFERENCES_FRAME_H
#define FILTER_EXPRESSIONS_PREFERENCES_FRAME_H

#include <QFrame>

class QLineEdit;
class QTreeWidgetItem;

namespace Ui {
class FilterExpressionsPreferencesFrame;
}

class FilterExpressionsPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    explicit FilterExpressionsPreferencesFrame(QWidget *parent = 0);
    ~FilterExpressionsPreferencesFrame();

    void unstash();

protected:
    void keyPressEvent(QKeyEvent *evt);

private:
    Ui::FilterExpressionsPreferencesFrame *ui;

    int cur_column_;
    QLineEdit *cur_line_edit_;
    QString saved_col_string_;

    void addExpression(bool enabled, const QString label, const QString expression);

private slots:
    void updateWidgets(void);
    void on_expressionTreeWidget_currentItemChanged(QTreeWidgetItem *current, QTreeWidgetItem *previous);
    void on_expressionTreeWidget_itemActivated(QTreeWidgetItem *item, int column);
    void lineEditDestroyed();
    void labelEditingFinished();
    void expressionEditingFinished();
    void on_expressionTreeWidget_itemSelectionChanged();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
};

#endif // FILTER_EXPRESSIONS_PREFERENCES_FRAME_H
