/* module_preferences_scroll_area.h
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

#ifndef MODULE_PREFERENCES_SCROLL_AREA_H
#define MODULE_PREFERENCES_SCROLL_AREA_H

#include "config.h"

#include <glib.h>

#include "color.h"

#include <epan/prefs.h>

#include <QScrollArea>

namespace Ui {
class ModulePreferencesScrollArea;
}

class ModulePreferencesScrollArea : public QScrollArea
{
    Q_OBJECT

public:
    explicit ModulePreferencesScrollArea(module_t *module, QWidget *parent = 0);
    ~ModulePreferencesScrollArea();

protected:
    void showEvent(QShowEvent *evt);
    void resizeEvent(QResizeEvent *evt);

private:
    Ui::ModulePreferencesScrollArea *ui;

    module_t *module_;
    void updateWidgets();

private slots:
    void uintLineEditTextEdited(const QString &new_str);
    void boolCheckBoxToggled(bool checked);
    void enumRadioButtonToggled(bool checked);
    void enumComboBoxCurrentIndexChanged(int index);
    void stringLineEditTextEdited(const QString &new_str);
    void rangeSyntaxLineEditTextEdited(const QString &new_str);
    void uatPushButtonPressed();
    void filenamePushButtonPressed();
    void dirnamePushButtonPressed();
};

#endif // MODULE_PREFERENCES_SCROLL_AREA_H
