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
class ColumnListModel;
class QItemSelection;

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

private:
    Ui::ColumnPreferencesFrame *ui;
    ColumnListModel * model_;

private slots:
    void selectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
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
