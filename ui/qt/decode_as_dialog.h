/* decode_as_dialog.h
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

#ifndef DECODE_AS_DIALOG_H
#define DECODE_AS_DIALOG_H

#include <config.h>

#include <glib.h>

#include "cfile.h"
#include <ui/qt/models/decode_as_model.h>
#include <ui/qt/models/decode_as_delegate.h>

#include "geometry_state_dialog.h"
#include <QMap>
#include <QAbstractButton>

class QComboBox;

namespace Ui {
class DecodeAsDialog;
}

class DecodeAsDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit DecodeAsDialog(QWidget *parent = 0, capture_file *cf = NULL, bool create_new = false);
    ~DecodeAsDialog();

private:
    Ui::DecodeAsDialog *ui;

    DecodeAsModel* model_;
    DecodeAsDelegate* delegate_;

    void addRecord(bool copy_from_current = false);
    void applyChanges();
    void fillTable();
    void resizeColumns();

private slots:
    void on_decodeAsTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();

    void on_buttonBox_clicked(QAbstractButton *button);
};

#endif // DECODE_AS_DIALOG_H

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
