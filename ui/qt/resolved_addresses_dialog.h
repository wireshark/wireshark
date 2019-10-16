/* resolved_addresses_dialog.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RESOLVED_ADDRESSES_DIALOG_H
#define RESOLVED_ADDRESSES_DIALOG_H

#include "geometry_state_dialog.h"

#include <wiretap/wtap.h>

class CaptureFile;
class AStringListListSortFilterProxyModel;

namespace Ui {
class ResolvedAddressesDialog;
}

class ResolvedAddressesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit ResolvedAddressesDialog(QWidget *parent, QString captureFile, wtap* wth);
    ~ResolvedAddressesDialog();

protected slots:
    void on_cmbDataType_currentIndexChanged(QString val);
    void on_txtSearchFilter_textChanged(QString text);
    void on_cmbPortFilterType_currentIndexChanged(QString val);
    void on_txtPortFilter_textChanged(QString text);

    void changeEvent(QEvent* event);

private:
    Ui::ResolvedAddressesDialog *ui;
    QString file_name_;
    QString comment_;

    AStringListListSortFilterProxyModel * ethSortModel;
    AStringListListSortFilterProxyModel * ethTypeModel;
    AStringListListSortFilterProxyModel * portSortModel;
    AStringListListSortFilterProxyModel * portTypeModel;

    void fillBlocks();
};

#endif // RESOLVED_ADDRESSES_DIALOG_H

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
