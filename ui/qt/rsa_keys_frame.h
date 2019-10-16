/* rsa_keys_frame.h
 *
 * Copyright 2019 Peter Wu <peter@lekensteyn.nl>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef RSA_KEYS_FRAME_H
#define RSA_KEYS_FRAME_H

#include <config.h>

#include <QFrame>

#include <ui/qt/models/uat_model.h>

namespace Ui {
class RsaKeysFrame;
}

class RsaKeysFrame : public QFrame
{
    Q_OBJECT

public:
    explicit RsaKeysFrame(QWidget *parent = NULL);
#ifdef HAVE_LIBGNUTLS
    ~RsaKeysFrame();

    void acceptChanges();
    void rejectChanges();

private:
    Ui::RsaKeysFrame *ui;

    UatModel *rsa_keys_model_;
    UatModel *pkcs11_libs_model_;

    gboolean verifyKey(const char *uri, const char *password, gboolean *need_password, QString &error);
    void addKey(const QString &uri, const QString &password);

private slots:
    void keyCurrentChanged(const QModelIndex &current, const QModelIndex &previous);
    void on_addFileButton_clicked();
    void on_addItemButton_clicked();
    void on_deleteItemButton_clicked();
    void libCurrentChanged(const QModelIndex &current, const QModelIndex &previous);
    void on_addLibraryButton_clicked();
    void on_deleteLibraryButton_clicked();
#endif  /* HAVE_LIBGNUTLS */
};

#endif  /* RSA_KEYS_FRAME_H */
