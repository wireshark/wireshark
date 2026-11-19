/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef COPY_FROM_PROFILE_BUTTON_H
#define COPY_FROM_PROFILE_BUTTON_H

#include <config.h>

#include <QMenu>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QMetaObject>

/**
 * @brief A button that presents a menu to copy settings from existing profiles.
 */
class CopyFromProfileButton : public QPushButton
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new CopyFromProfileButton.
     * @param parent The parent widget, defaults to Q_NULLPTR.
     * @param profileFile The target configuration file to copy, defaults to an empty string.
     * @param toolTip The tooltip text for the button, defaults to an empty string.
     * @param legacyFile A former name of the configuration file, used for profiles
     * that do not have profileFile, defaults to an empty string.
     */
    CopyFromProfileButton(QWidget * parent = Q_NULLPTR, QString profileFile = QString(), QString toolTip = QString(), QString legacyFile = QString());

    /**
     * @brief Sets the target configuration filename for copying.
     * @param filename The configuration filename.
     */
    void setFilename(QString filename);

    /**
     * @brief Enables the button when the profile's own entries are used and it has profiles to copy from.
     *
     * A tool tip tells why the button is disabled when the own entries are not used.
     * @param own_used Whether the own entries are used.
     */
    void setOwnEntriesUsed(bool own_used);

signals:
    /**
     * @brief Signal emitted when a profile has been selected for copying.
     * @param filename The name of the profile or file to copy from.
     */
    void copyProfile(QString filename);

private:
    /** The configuration filename associated with the copy operation. */
    QString filename_;

    /** A former name of the configuration file, looked for when filename_ is missing. */
    QString legacy_filename_;

    /** The drop-down menu containing available profiles. */
    QMenu * buttonMenu_;

    /**
     * @brief Generates a menu action for the system default profile.
     * @param filename The configuration filename.
     * @return A pointer to the created QAction.
     */
    QAction * systemDefault(QString filename);

private slots:
    /**
     * @brief Slot triggered when a menu action is selected.
     * @param action The QAction that was triggered.
     */
    void menuActionTriggered(QAction *action);
};

#endif // COPY_FROM_PROFILE_BUTTON_H
