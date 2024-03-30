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
#include <ui/all_files_wildcard.h>

#include <epan/secrets.h>
#include <QInputDialog>

#ifdef HAVE_LIBGNUTLS
RsaKeysFrame::RsaKeysFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::RsaKeysFrame),
    rsa_keys_model_(0),
    pkcs11_libs_model_(0)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    ui->addFileButton->setAttribute(Qt::WA_MacSmallSize, true);
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
#else   /* ! HAVE_LIBGNUTLS */
RsaKeysFrame::RsaKeysFrame(QWidget *parent) : QFrame(parent) { }
#endif  /* ! HAVE_LIBGNUTLS */

#ifdef HAVE_LIBGNUTLS
RsaKeysFrame::~RsaKeysFrame()
{
    delete ui;
}

bool RsaKeysFrame::verifyKey(const char *uri, const char *password, bool *need_password, QString &error)
{
    char *error_c = NULL;
    bool key_ok = secrets_verify_key(qPrintable(uri), qPrintable(password), need_password, &error_c);
    error = error_c ? error_c : "";
    g_free(error_c);
    return key_ok;
}

void RsaKeysFrame::addKey(const QString &uri, const QString &password)
{
    // Create a new UAT entry with the given URI and PIN/password.
    int row = rsa_keys_model_->rowCount();
    rsa_keys_model_->insertRows(row, 1);
    rsa_keys_model_->setData(rsa_keys_model_->index(row, 0), uri);
    rsa_keys_model_->setData(rsa_keys_model_->index(row, 1), password);
    ui->keysView->setCurrentIndex(rsa_keys_model_->index(row, 0));
}

void RsaKeysFrame::keyCurrentChanged(const QModelIndex &current, const QModelIndex & /* previous */)
{
    ui->deleteItemButton->setEnabled(current.isValid());
}

void RsaKeysFrame::on_addItemButton_clicked()
{
    GSList *keys_list = secrets_get_available_keys();
    QStringList keys;
    if (keys_list) {
        for (GSList *uri = keys_list; uri; uri = uri->next) {
            keys << (char *)uri->data;
        }
        g_slist_free_full(keys_list, g_free);
    }

    // Remove duplicates (keys that have already been added)
    for (int row = rsa_keys_model_->rowCount() - 1; row >= 0; --row) {
        QString item = rsa_keys_model_->data(rsa_keys_model_->index(row, 0)).toString();
        keys.removeAll(item);
    }

    if (keys.isEmpty()) {
        QMessageBox::information(this, tr("Add PKCS #11 token or key"),
                tr("No new PKCS #11 tokens or keys found, consider adding a PKCS #11 provider."),
                QMessageBox::Ok);
        return;
    }

    bool ok;
    QString item = QInputDialog::getItem(this,
            tr("Select a new PKCS #11 token or key"),
            tr("PKCS #11 token or key"), keys, 0, false, &ok);
    if (!ok || item.isEmpty()) {
        return;
    }

    // Validate the token, is a PIN needed?
    bool key_ok = false, needs_pin = true;
    QString error;
    if (!item.startsWith("pkcs11:")) {
        // For keys other than pkcs11, try to verify the key without password.
        // (The PIN must always be prompted for PKCS #11 tokens, otherwise it is
        // possible that an already unlocked token will not trigger a prompt).
        key_ok = verifyKey(qPrintable(item), NULL, &needs_pin, error);
    }
    QString pin;
    while (!key_ok && needs_pin) {
        // A PIN is possibly needed, prompt for one.
        QString msg;
        if (!error.isEmpty()) {
            msg = error + "\n";
            error.clear();
        }
        msg += tr("Enter PIN or password for %1 (it will be stored unencrypted)");
        pin = QInputDialog::getText(this, tr("Enter PIN or password for key"),
                msg.arg(item), QLineEdit::Password, "", &ok);
        if (!ok) {
            return;
        }
        key_ok = verifyKey(qPrintable(item), qPrintable(pin), NULL, error);
    }
    if (!key_ok) {
        QMessageBox::warning(this,
                tr("Add PKCS #11 token or key"),
                tr("Key could not be added: %1").arg(item),
                QMessageBox::Ok);
        return;
    }

    addKey(item, pin);
}

void RsaKeysFrame::on_addFileButton_clicked()
{
    QString filter =
        tr("RSA private key (*.pem *.p12 *.pfx *.key);;All Files (" ALL_FILES_WILDCARD ")");
    QString file = WiresharkFileDialog::getOpenFileName(this,
            tr("Select RSA private key file"), "", filter);
    if (file.isEmpty()) {
        return;
    }

    // Try to load the key as unencrypted key file. If any errors occur, assume
    // an encrypted key file and prompt for a password.
    QString password, error;
    bool key_ok = secrets_verify_key(qPrintable(file), NULL, NULL, NULL);
    while (!key_ok) {
        QString msg;
        if (!error.isEmpty()) {
            msg = error + "\n";
            error.clear();
        }
        msg += QString("Enter the password to open %1").arg(file);

        bool ok;
        password = QInputDialog::getText(this, tr("Select RSA private key file"), msg,
                QLineEdit::Password, "", &ok);
        if (!ok) {
            return;
        }
        key_ok = verifyKey(qPrintable(file), qPrintable(password), NULL, error);
    }

    addKey(file, password);
}

void RsaKeysFrame::on_deleteItemButton_clicked()
{
    const QModelIndex &current = ui->keysView->currentIndex();
    if (rsa_keys_model_ && current.isValid()) {
        rsa_keys_model_->removeRows(current.row(), 1);
    }
}

void RsaKeysFrame::acceptChanges()
{
    // Save keys list mutations. The PKCS #11 provider list was already saved.
    QString error;
    if (rsa_keys_model_->applyChanges(error) && !error.isEmpty()) {
        report_failure("%s", qPrintable(error));
    }
}

void RsaKeysFrame::rejectChanges()
{
    // Revert keys list mutations. The PKCS #11 provider list was already saved.
    QString error;
    if (rsa_keys_model_->revertChanges(error) && !error.isEmpty()) {
        report_failure("%s", qPrintable(error));
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
#endif  /* HAVE_LIBGNUTLS */
