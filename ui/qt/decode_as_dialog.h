/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef DECODE_AS_DIALOG_H
#define DECODE_AS_DIALOG_H

#include <config.h>

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

public slots:
    void modelRowsReset();

private slots:
    void copyFromProfile(QString filename);
    void on_decodeAsTreeView_currentItemChanged(const QModelIndex &current, const QModelIndex &previous);

    void on_newToolButton_clicked();
    void on_deleteToolButton_clicked();
    void on_copyToolButton_clicked();
    void on_clearToolButton_clicked();

    void on_buttonBox_clicked(QAbstractButton *button);
};

#endif // DECODE_AS_DIALOG_H
