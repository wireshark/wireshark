/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PROTOCOL_PREFERENCES_MENU_H__
#define __PROTOCOL_PREFERENCES_MENU_H__

#include <QMenu>

#include <epan/proto.h>
#include <epan/prefs.h>

/**
 * @brief A menu for displaying and modifying protocol-specific preferences.
 */
class ProtocolPreferencesMenu : public QMenu
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new ProtocolPreferencesMenu object.
     * @param parent The parent widget.
     */
    ProtocolPreferencesMenu(QWidget *parent = nullptr);

    /**
     * @brief Constructs a new ProtocolPreferencesMenu object with a title and module name.
     * @param title The title of the menu.
     * @param module_name The name of the protocol module.
     * @param parent The parent widget.
     */
    ProtocolPreferencesMenu(const QString &title, const QString &module_name, QWidget *parent = nullptr);

    /**
     * @brief Sets the protocol module for this menu.
     * @param module_name The name of the protocol module.
     */
    void setModule(const QString module_name);

    /**
     * @brief Adds a menu item for a specific preference.
     * @param pref Pointer to the preference to add.
     */
    void addMenuItem(pref_t *pref);

signals:
    /**
     * @brief Signal emitted to show preferences for a specific protocol.
     * @param module_name The name of the protocol module.
     */
    void showProtocolPreferences(const QString module_name);

    /**
     * @brief Signal emitted to edit a specific protocol preference.
     * @param pref Pointer to the preference to edit.
     * @param module Pointer to the related protocol module.
     */
    void editProtocolPreference(pref_t *pref, module_t *module);

private:
    /** @brief The name of the protocol module. */
    QString module_name_;

    /** @brief Pointer to the protocol module. */
    module_t *module_;

    /** @brief Pointer to the protocol structure. */
    protocol_t *protocol_;

private slots:
    /**
     * @brief Slot triggered when the disable protocol action is activated.
     */
    void disableProtocolTriggered();

    /**
     * @brief Slot triggered when the module preferences action is activated.
     */
    void modulePreferencesTriggered();

    /**
     * @brief Slot triggered when an editor preference action is activated.
     */
    void editorPreferenceTriggered();

    /**
     * @brief Slot triggered when a boolean preference action is activated.
     */
    void boolPreferenceTriggered();

    /**
     * @brief Slot triggered when an enumeration preference action is activated.
     */
    void enumPreferenceTriggered();

    /**
     * @brief Slot triggered when a User Accessible Table (UAT) preference action is activated.
     */
    void uatPreferenceTriggered();

    /**
     * @brief Slot triggered when a custom TCP override enum preference action is activated.
     */
    void enumCustomTCPOverridePreferenceTriggered();
};

#endif // __PROTOCOL_PREFERENCES_MENU_H__
