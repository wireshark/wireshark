/** @file
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

/**
 * @brief UI frame for managing RSA keys and PKCS#11 libraries.
 */
class RsaKeysFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new RsaKeysFrame object.
     * @param parent The parent widget.
     */
    explicit RsaKeysFrame(QWidget *parent = NULL);
#ifdef HAVE_LIBGNUTLS
    /**
     * @brief Destroys the RsaKeysFrame object.
     */
    ~RsaKeysFrame();

    /**
     * @brief Accepts the pending RSA key and library changes.
     * @return Integer status of the operation (e.g., 0 for success).
     */
    int acceptChanges();

    /**
     * @brief Rejects the pending RSA key and library changes.
     */
    void rejectChanges();

private:
    /** @brief Pointer to the user interface object for this frame. */
    Ui::RsaKeysFrame *ui;

    /** @brief Model for managing the RSA keys UAT. */
    UatModel *rsa_keys_model_;

    /** @brief Model for managing the PKCS#11 libraries UAT. */
    UatModel *pkcs11_libs_model_;

    /**
     * @brief Verifies the validity of an RSA key.
     * @param uri The URI or file path of the key.
     * @param password The password for the key.
     * @param need_password Pointer to a boolean that will be set to true if a password is required.
     * @param error Reference to a QString where error messages will be stored.
     * @return True if the key is valid, false otherwise.
     */
    bool verifyKey(const char *uri, const char *password, bool *need_password, QString &error);

    /**
     * @brief Adds a new RSA key to the configuration.
     * @param uri The URI or file path of the key to add.
     * @param password The password for the key.
     */
    void addKey(const QString &uri, const QString &password);

private slots:
    /**
     * @brief Handles selection changes in the RSA keys table.
     * @param current The newly selected model index.
     * @param previous The previously selected model index.
     */
    void keyCurrentChanged(const QModelIndex &current, const QModelIndex &previous);

    /**
     * @brief Handles the event when the "Add File" button is clicked.
     */
    void on_addFileButton_clicked();

    /**
     * @brief Handles the event when the "Add Item" button is clicked.
     */
    void on_addItemButton_clicked();

    /**
     * @brief Handles the event when the "Delete Item" button is clicked.
     */
    void on_deleteItemButton_clicked();

    /**
     * @brief Handles selection changes in the PKCS#11 libraries table.
     * @param current The newly selected model index.
     * @param previous The previously selected model index.
     */
    void libCurrentChanged(const QModelIndex &current, const QModelIndex &previous);

    /**
     * @brief Handles the event when the "Add Library" button is clicked.
     */
    void on_addLibraryButton_clicked();

    /**
     * @brief Handles the event when the "Delete Library" button is clicked.
     */
    void on_deleteLibraryButton_clicked();
#endif  /* HAVE_LIBGNUTLS */
};

#endif  /* RSA_KEYS_FRAME_H */
