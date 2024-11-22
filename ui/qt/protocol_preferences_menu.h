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

class ProtocolPreferencesMenu : public QMenu
{
    Q_OBJECT

public:
    ProtocolPreferencesMenu(QWidget *parent = nullptr);
    ProtocolPreferencesMenu(const QString &title, const QString &module_name, QWidget *parent = nullptr);

    void setModule(const QString module_name);
    void addMenuItem(pref_t *pref);

signals:
    void showProtocolPreferences(const QString module_name);
    void editProtocolPreference(pref_t *pref, module_t *module);

private:
    QString module_name_;
    module_t *module_;
    protocol_t *protocol_;

private slots:
    void disableProtocolTriggered();
    void modulePreferencesTriggered();
    void editorPreferenceTriggered();
    void boolPreferenceTriggered();
    void enumPreferenceTriggered();
    void uatPreferenceTriggered();
    void enumCustomTCPOverridePreferenceTriggered();
};

#endif // __PROTOCOL_PREFERENCES_MENU_H__
