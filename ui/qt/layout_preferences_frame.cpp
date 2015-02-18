/* layout_preferences_frame.cpp
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

#include "layout_preferences_frame.h"
#include <ui_layout_preferences_frame.h>

#include <QAbstractButton>
#include <QToolButton>
#include <QRadioButton>

#include <QDebug>
#include <epan/prefs-int.h>

LayoutPreferencesFrame::LayoutPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::LayoutPreferencesFrame)
{
    ui->setupUi(this);

    pref_layout_type_ = prefFromPrefPtr(&prefs.gui_layout_type);
    pref_layout_content_1_ = prefFromPrefPtr(&prefs.gui_layout_content_1);
    pref_layout_content_2_ = prefFromPrefPtr(&prefs.gui_layout_content_2);
    pref_layout_content_3_ = prefFromPrefPtr(&prefs.gui_layout_content_3);

    QString image_pad_ss = "QToolButton { padding: 0.3em; }";
    ui->layout1ToolButton->setStyleSheet(image_pad_ss);
    ui->layout2ToolButton->setStyleSheet(image_pad_ss);
    ui->layout3ToolButton->setStyleSheet(image_pad_ss);
    ui->layout4ToolButton->setStyleSheet(image_pad_ss);
    ui->layout5ToolButton->setStyleSheet(image_pad_ss);
    ui->layout6ToolButton->setStyleSheet(image_pad_ss);

    pref_packet_list_separator_ = prefFromPrefPtr(&prefs.gui_qt_packet_list_separator);
    ui->packetListSeparatorCheckBox->setChecked(pref_packet_list_separator_->stashed_val.boolval);
}

LayoutPreferencesFrame::~LayoutPreferencesFrame()
{
    delete ui;
}

void LayoutPreferencesFrame::showEvent(QShowEvent *)
{
    updateWidgets();
}

void LayoutPreferencesFrame::updateWidgets()
{
    switch (pref_layout_type_->stashed_val.uint) {
    case layout_type_5:
        ui->layout5ToolButton->setChecked(true);
        break;
    case layout_type_2:
        ui->layout2ToolButton->setChecked(true);
        break;
    case layout_type_1:
        ui->layout1ToolButton->setChecked(true);
        break;
    case layout_type_4:
        ui->layout4ToolButton->setChecked(true);
        break;
    case layout_type_3:
        ui->layout3ToolButton->setChecked(true);
        break;
    case layout_type_6:
        ui->layout6ToolButton->setChecked(true);
        break;
    }

    switch (pref_layout_content_1_->stashed_val.enumval) {
    case layout_pane_content_plist:
        ui->pane1PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane1PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane1PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane1NoneRadioButton->setChecked(true);
        break;
    }

    switch (pref_layout_content_2_->stashed_val.enumval) {
    case layout_pane_content_plist:
        ui->pane2PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane2PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane2PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane2NoneRadioButton->setChecked(true);
        break;
    }

    switch (pref_layout_content_3_->stashed_val.enumval) {
    case layout_pane_content_plist:
        ui->pane3PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane3PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane3PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane3NoneRadioButton->setChecked(true);
        break;
    }
}

void LayoutPreferencesFrame::on_layout5ToolButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_type_->stashed_val.uint = layout_type_5;
}

void LayoutPreferencesFrame::on_layout2ToolButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_type_->stashed_val.uint = layout_type_2;
}

void LayoutPreferencesFrame::on_layout1ToolButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_type_->stashed_val.uint = layout_type_1;
}

void LayoutPreferencesFrame::on_layout4ToolButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_type_->stashed_val.uint = layout_type_4;
}

void LayoutPreferencesFrame::on_layout3ToolButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_type_->stashed_val.uint = layout_type_3;
}

void LayoutPreferencesFrame::on_layout6ToolButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_type_->stashed_val.uint = layout_type_6;
}

void LayoutPreferencesFrame::on_pane1PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_1_->stashed_val.enumval = layout_pane_content_plist;
    if (ui->pane2PacketListRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketListRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_1_->stashed_val.enumval = layout_pane_content_pdetails;
    if (ui->pane2PacketDetailsRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketDetailsRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_1_->stashed_val.enumval = layout_pane_content_pbytes;
    if (ui->pane2PacketBytesRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketBytesRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_1_->stashed_val.enumval = layout_pane_content_none;
}

void LayoutPreferencesFrame::on_pane2PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_2_->stashed_val.enumval = layout_pane_content_plist;
    if (ui->pane1PacketListRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketListRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_2_->stashed_val.enumval = layout_pane_content_pdetails;
    if (ui->pane1PacketDetailsRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketDetailsRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_2_->stashed_val.enumval = layout_pane_content_pbytes;
    if (ui->pane1PacketBytesRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketBytesRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_2_->stashed_val.enumval = layout_pane_content_none;
}

void LayoutPreferencesFrame::on_pane3PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_3_->stashed_val.enumval = layout_pane_content_plist;
    if (ui->pane1PacketListRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketListRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_3_->stashed_val.enumval = layout_pane_content_pdetails;
    if (ui->pane1PacketDetailsRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketDetailsRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_3_->stashed_val.enumval = layout_pane_content_pbytes;
    if (ui->pane1PacketBytesRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketBytesRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    pref_layout_content_3_->stashed_val.enumval = layout_pane_content_none;
}


void LayoutPreferencesFrame::on_restoreButtonBox_clicked(QAbstractButton *)
{
    pref_layout_type_->stashed_val.uint = pref_layout_type_->default_val.uint;
    pref_layout_content_1_->stashed_val.enumval = pref_layout_content_1_->default_val.enumval;
    updateWidgets();
    pref_layout_content_2_->stashed_val.enumval = pref_layout_content_2_->default_val.enumval;
    updateWidgets();
    pref_layout_content_3_->stashed_val.enumval = pref_layout_content_3_->default_val.enumval;
    updateWidgets();

    ui->packetListSeparatorCheckBox->setChecked(pref_packet_list_separator_->default_val.boolval);
}

void LayoutPreferencesFrame::on_packetListSeparatorCheckBox_toggled(bool checked)
{
    pref_packet_list_separator_->stashed_val.boolval = (gboolean) checked;
}

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
