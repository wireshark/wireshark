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

class CaptureFile;
class QTextBlock;

namespace Ui {
class ResolvedAddressesDialog;
}

class ResolvedAddressesDialog : public GeometryStateDialog
{
    Q_OBJECT

public:
    explicit ResolvedAddressesDialog(QWidget *parent, CaptureFile *capture_file);
    ~ResolvedAddressesDialog();

protected slots:
    void changeEvent(QEvent* event);

private slots:
    void on_actionAddressesHosts_triggered();
    void on_actionComment_triggered();
    void on_actionIPv4HashTable_triggered();
    void on_actionIPv6HashTable_triggered();
    void on_actionPortNames_triggered();
    void on_actionEthernetAddresses_triggered();
    void on_actionEthernetManufacturers_triggered();
    void on_actionEthernetWKA_triggered();

    void on_actionShowAll_triggered();
    void on_actionHideAll_triggered();

private:
    Ui::ResolvedAddressesDialog *ui;
    QString file_name_;
    QString comment_;
    QStringList host_addresses_;
    QStringList v4_hash_addrs_;
    QStringList v6_hash_addrs_;
    QStringList service_ports_;
    QStringList ethernet_addresses_;
    QStringList ethernet_manufacturers_;
    QStringList ethernet_well_known_;

    void fillShowMenu();
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
