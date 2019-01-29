/* rsa_keys_frame.cpp
 *
 * Copyright 2019 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "rsa_keys_frame.h"
#include <ui_rsa_keys_frame.h>

#include "ui/qt/widgets/wireshark_file_dialog.h"
#include <wsutil/report_message.h>
#include <QMessageBox>

RsaKeysFrame::RsaKeysFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::RsaKeysFrame),
    rsa_keys_model_(0),
    pkcs11_libs_model_(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    ui->addItemButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteItemButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->addLibraryButton->setAttribute(Qt::WA_MacSmallSize, true);
    ui->deleteLibraryButton->setAttribute(Qt::WA_MacSmallSize, true);
#endif

#ifdef HAVE_GNUTLS_PKCS11
    pkcs11_libs_model_ = new UatModel(this, "PKCS #11 Provider Libraries");
    ui->libsView->setModel(pkcs11_libs_model_);
    connect(ui->libsView->selectionModel(), &QItemSelectionModel::currentChanged,
           this, &RsaKeysFrame::libCurrentChanged);
#else
    ui->addLibraryButton->setEnabled(false);
#endif

    rsa_keys_model_ = new UatModel(this, "RSA Private Keys");
    ui->keysView->setModel(rsa_keys_model_);
    connect(ui->keysView->selectionModel(), &QItemSelectionModel::currentChanged,
           this, &RsaKeysFrame::keyCurrentChanged);
}

RsaKeysFrame::~RsaKeysFrame()
{
    delete ui;
}

void RsaKeysFrame::keyCurrentChanged(const QModelIndex &current, const QModelIndex & /* previous */)
{
    ui->deleteItemButton->setEnabled(current.isValid());
}

void RsaKeysFrame::on_addItemButton_clicked()
{
}

void RsaKeysFrame::on_deleteItemButton_clicked()
{
    const QModelIndex &current = ui->keysView->currentIndex();
    if (rsa_keys_model_ && current.isValid()) {
        rsa_keys_model_->removeRows(current.row(), 1);
    }
}

void RsaKeysFrame::libCurrentChanged(const QModelIndex &current, const QModelIndex & /* previous */)
{
    ui->deleteLibraryButton->setEnabled(current.isValid());
}

void RsaKeysFrame::on_addLibraryButton_clicked()
{
    if (!pkcs11_libs_model_) return;

#ifdef Q_OS_WIN
    QString filter(tr("Libraries (*.dll)"));
#else
    QString filter(tr("Libraries (*.so)"));
#endif
    QString file = WiresharkFileDialog::getOpenFileName(this, tr("Select PKCS #11 Provider Library"), "", filter);
    if (file.isEmpty()) {
        return;
    }

    int row = pkcs11_libs_model_->rowCount();
    pkcs11_libs_model_->insertRows(row, 1);
    pkcs11_libs_model_->setData(pkcs11_libs_model_->index(row, 0), file);
    ui->libsView->setCurrentIndex(pkcs11_libs_model_->index(row, 0));

    // As the libraries affect the availability of PKCS #11 tokens, we will
    // immediately apply changes without waiting for the OK button to be
    // activated.
    QString error;
    if (pkcs11_libs_model_->applyChanges(error) && error.isEmpty()) {
        report_failure("%s", qPrintable(error));
    }
}

void RsaKeysFrame::on_deleteLibraryButton_clicked()
{
    if (!pkcs11_libs_model_) return;

    const QModelIndex &current = ui->libsView->currentIndex();
    if (!current.isValid()) {
        return;
    }

    QString file = pkcs11_libs_model_->data(current, 0).toString();
    pkcs11_libs_model_->removeRows(current.row(), 1);
    // Due to technical limitations of GnuTLS, libraries cannot be unloaded or
    // disabled once loaded. Inform the user of this caveat.
    QMessageBox::information(this, tr("Changes will apply after a restart"),
            tr("PKCS #11 provider %1 will be removed after the next restart.").arg(file),
            QMessageBox::Ok);
    // Make sure the UAT is actually saved to file.
    QString error;
    if (pkcs11_libs_model_->applyChanges(error) && error.isEmpty()) {
        report_failure("%s", qPrintable(error));
    }
}


/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
