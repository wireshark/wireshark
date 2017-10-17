/* uat_frame.h
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

#ifndef UAT_FRAME_H
#define UAT_FRAME_H

#include <QFrame>

#include <ui/qt/geometry_state_dialog.h>
#include <ui/qt/models/uat_model.h>
#include <ui/qt/models/uat_delegate.h>

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

private:
    Ui::UatFrame *ui;

    UatModel *uat_model_;
    UatDelegate *uat_delegate_;
    struct epan_uat *uat_;

    void checkForErrorHint(const QModelIndex &current, const QModelIndex &previous);
    bool trySetErrorHintFromField(const QModelIndex &index);
    void addRecord(bool copy_from_current = false);
    void applyChanges();

private slots:
    void modelDataChanged(const QModelIndex &topLeft);
    void modelRowsRemoved();
    void modelRowsReset();
    void on_uatTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_clearToolButton_clicked();
};

#endif // UAT_FRAME_H
