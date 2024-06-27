/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef UAT_FRAME_H
#define UAT_FRAME_H

#include <QFrame>

#include <ui/qt/geometry_state_dialog.h>
#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>

class QItemSelection;

namespace Ui {
class UatFrame;
}

class UatFrame : public QFrame
{
    Q_OBJECT

public:
    explicit UatFrame(QWidget *parent = NULL);
    ~UatFrame();

    void setUat(struct epan_uat *uat);

    void acceptChanges();
    void rejectChanges();

protected:
    void showEvent(QShowEvent *);

private:
    Ui::UatFrame *ui;

    UatModel *uat_model_;
    UatDelegate *uat_delegate_;
    struct epan_uat *uat_;

    void checkForErrorHint(const QModelIndex &current, const QModelIndex &previous);
    bool trySetErrorHintFromField(const QModelIndex &index);
    void addRecord(bool copy_from_current = false);
    void applyChanges();
    void resizeColumns();

private slots:
    void copyFromProfile(QString filename);
    void modelDataChanged(const QModelIndex &topLeft);
    void modelRowsRemoved();
    void modelRowsReset();
    void uatTreeViewSelectionChanged(const QItemSelection &selected, const QItemSelection &deselected);
    void on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_moveUpToolButton_clicked();
    void on_moveDownToolButton_clicked();
    void on_clearToolButton_clicked();
};

#endif // UAT_FRAME_H
