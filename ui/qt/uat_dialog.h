/* uat_dialog.h
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

#ifndef UAT_DIALOG_H
#define UAT_DIALOG_H

#include <config.h>

#include <glib.h>

#include "geometry_state_dialog.h"
#include "uat_model.h"
#include "uat_delegate.h"

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
    void modelDataChanged(const QModelIndex &topLeft);
    void modelRowsRemoved();
    void viewCurrentChanged(const QModelIndex &current, const QModelIndex &previous);
    void acceptChanges();
    void rejectChanges();
    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
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
