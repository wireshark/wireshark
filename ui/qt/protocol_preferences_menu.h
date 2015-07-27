/* protocol_preferences_menu.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
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

    void setModule(const char *module_name);
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
