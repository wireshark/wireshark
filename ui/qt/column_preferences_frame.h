/* column_preferences_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
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
