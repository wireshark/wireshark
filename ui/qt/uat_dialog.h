/* uat_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UAT_DIALOG_H
#define UAT_DIALOG_H

#include <config.h>

#include <glib.h>

#include "geometry_state_dialog.h"
#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>

class QComboBox;
class QPushButton;

struct epan_uat;

namespace Ui {
class UatDialog;
}

class UatDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit UatDialog(QWidget *parent = 0, struct epan_uat *uat = NULL);
    ~UatDialog();

    void setUat(struct epan_uat *uat = NULL);

private slots:
    void copyFromProfile(QString filename);
    void modelDataChanged(const QModelIndex &topLeft);
    void modelRowsRemoved();
    void modelRowsReset();
    void on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);
    void acceptChanges();
    void rejectChanges();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_moveUpToolButton_clicked();
    void on_moveDownToolButton_clicked();
    void on_clearToolButton_clicked();
    void on_buttonBox_helpRequested();

private:
    Ui::UatDialog *ui;
    UatModel *uat_model_;
    UatDelegate *uat_delegate_;
    QPushButton *ok_button_;
    QPushButton *help_button_;
    struct epan_uat *uat_;

    void checkForErrorHint(const QModelIndex &current, const QModelIndex &previous);
    bool trySetErrorHintFromField(const QModelIndex &index);
    void applyChanges();
    void addRecord(bool copy_from_current = false);
};

#endif // UAT_DIALOG_H
