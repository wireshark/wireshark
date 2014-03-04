/* layout_preferences_frame.h
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

#ifndef LAYOUT_PREFERENCES_FRAME_H
#define LAYOUT_PREFERENCES_FRAME_H

#include "preferences_dialog.h"

#include <QFrame>
#include <QAbstractButton>

namespace Ui {
class LayoutPreferencesFrame;
}

class LayoutPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    explicit LayoutPreferencesFrame(QWidget *parent = 0);
    ~LayoutPreferencesFrame();

protected:
    void showEvent(QShowEvent *evt);

private:
    Ui::LayoutPreferencesFrame *ui;

    pref_t *pref_layout_type_;
    pref_t *pref_layout_content_1_;
    pref_t *pref_layout_content_2_;
    pref_t *pref_layout_content_3_;

    void updateWidgets();

private slots:
    void on_layout5ToolButton_toggled(bool checked);
    void on_layout2ToolButton_toggled(bool checked);
    void on_layout1ToolButton_toggled(bool checked);
    void on_layout4ToolButton_toggled(bool checked);
    void on_layout3ToolButton_toggled(bool checked);
    void on_layout6ToolButton_toggled(bool checked);
    void on_pane1PacketListRadioButton_toggled(bool checked);
    void on_pane1PacketDetailsRadioButton_toggled(bool checked);
    void on_pane1PacketBytesRadioButton_toggled(bool checked);
    void on_pane1NoneRadioButton_toggled(bool checked);
    void on_pane2PacketListRadioButton_toggled(bool checked);
    void on_pane2PacketDetailsRadioButton_toggled(bool checked);
    void on_pane2PacketBytesRadioButton_toggled(bool checked);
    void on_pane2NoneRadioButton_toggled(bool checked);
    void on_pane3PacketListRadioButton_toggled(bool checked);
    void on_pane3PacketDetailsRadioButton_toggled(bool checked);
    void on_pane3PacketBytesRadioButton_toggled(bool checked);
    void on_pane3NoneRadioButton_toggled(bool checked);
    void on_restoreButtonBox_clicked(QAbstractButton *button);

};

#endif // LAYOUT_PREFERENCES_FRAME_H
