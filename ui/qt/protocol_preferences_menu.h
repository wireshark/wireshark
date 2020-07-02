/* protocol_preferences_menu.h
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

struct _protocol;
struct pref_module;
struct preference;

class ProtocolPreferencesMenu : public QMenu
{
    Q_OBJECT

public:
    ProtocolPreferencesMenu();
    ProtocolPreferencesMenu(const QString &title, const QString &module_name, QWidget *parent = nullptr);

    void setModule(const QString module_name);
    void addMenuItem(struct preference *pref);

signals:
    void showProtocolPreferences(const QString module_name);
    void editProtocolPreference(struct preference *pref, struct pref_module *module);

private:
    QString module_name_;
    struct pref_module *module_;
    struct _protocol *protocol_;

private slots:
    void disableProtocolTriggered();
    void modulePreferencesTriggered();
    void editorPreferenceTriggered();
    void boolPreferenceTriggered();
    void enumPreferenceTriggered();
    void uatPreferenceTriggered();
};

#endif // __PROTOCOL_PREFERENCES_MENU_H__

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
