/* preference_editor_frame.h
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

#ifndef PREFERENCE_EDITOR_FRAME_H
#define PREFERENCE_EDITOR_FRAME_H

#include "accordion_frame.h"

struct pref_module;
struct preference;
struct epan_range;

namespace Ui {
class PreferenceEditorFrame;
}

class PreferenceEditorFrame : public AccordionFrame
{
    Q_OBJECT

public:
    explicit PreferenceEditorFrame(QWidget *parent = 0);
    ~PreferenceEditorFrame();

public slots:
    void editPreference(struct preference *pref = NULL, struct pref_module *module = NULL);

signals:
    void showProtocolPreferences(const QString module_name);

private slots:
    // Similar to ModulePreferencesScrollArea
    void uintLineEditTextEdited(const QString &new_str);
    void stringLineEditTextEdited(const QString &new_str);
    void rangeLineEditTextEdited(const QString &new_str);

    void on_modulePreferencesToolButton_clicked();
    void on_preferenceLineEdit_returnPressed();
    void on_buttonBox_accepted();
    void on_buttonBox_rejected();

private:
    Ui::PreferenceEditorFrame *ui;

    struct pref_module *module_;
    struct preference *pref_;

    unsigned int new_uint_;
    QString new_str_;
    struct epan_range *new_range_;
};

#endif // PREFERENCE_EDITOR_FRAME_H

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
