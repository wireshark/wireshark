/* column_preferences_frame.h
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

#ifndef COLUMN_PREFERENCES_FRAME_H
#define COLUMN_PREFERENCES_FRAME_H

#include <QFrame>

class QComboBox;
class QLineEdit;
class QTreeWidgetItem;

namespace Ui {
class ColumnPreferencesFrame;
}

class ColumnPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    explicit ColumnPreferencesFrame(QWidget *parent = 0);
    ~ColumnPreferencesFrame();

    void unstash();

protected:
    void keyPressEvent(QKeyEvent *evt);

private:
    Ui::ColumnPreferencesFrame *ui;

    int cur_column_;
    QLineEdit *cur_line_edit_;
    QString saved_col_string_;
    QComboBox *cur_combo_box_;
    int saved_combo_idx_;
    int saved_custom_combo_idx_;

    void addColumn(bool visible, const char *title, int fmt, const char *custom_fields, int custom_occurrence);

private slots:
    void updateWidgets(void);
    void on_columnTreeWidget_currentItemChanged(QTreeWidgetItem *, QTreeWidgetItem *previous);
    void on_columnTreeWidget_itemActivated(QTreeWidgetItem *item, int column);
    void lineEditDestroyed();
    void comboDestroyed();
    void columnTitleEditingFinished();
    void columnTypeCurrentIndexChanged(int index);
    void customFieldsEditingFinished();
    void customOccurrenceEditingFinished();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
};

#endif // COLUMN_PREFERENCES_FRAME_H

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
