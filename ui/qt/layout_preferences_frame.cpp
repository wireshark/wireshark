/* layout_preferences_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <config.h>

#include "layout_preferences_frame.h"
#include <ui_layout_preferences_frame.h>

#include <QAbstractButton>
#include <QToolButton>
#include <QRadioButton>

#include <QDebug>
#include <epan/prefs-int.h>
#include <ui/qt/models/pref_models.h>

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

    QStyleOption style_opt;
    QString indent_ss = QString(
             "QCheckBox {"
             "  margin-left: %1px;"
             "}"
             ).arg(ui->packetListSeparatorCheckBox->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left());
    ui->packetListSeparatorCheckBox->setStyleSheet(indent_ss);
    ui->packetListHeaderShowColumnDefinition->setStyleSheet(indent_ss);
    ui->statusBarShowSelectedPacketCheckBox->setStyleSheet(indent_ss);
    ui->statusBarShowFileLoadTimeCheckBox->setStyleSheet(indent_ss);

    pref_packet_list_separator_ = prefFromPrefPtr(&prefs.gui_qt_packet_list_separator);
    ui->packetListSeparatorCheckBox->setChecked(prefs_get_bool_value(pref_packet_list_separator_, pref_stashed));

    pref_packet_header_column_definition_ = prefFromPrefPtr(&prefs.gui_qt_packet_header_column_definition);
    ui->packetListHeaderShowColumnDefinition->setChecked(prefs_get_bool_value(pref_packet_header_column_definition_, pref_stashed));

    pref_show_selected_packet_ = prefFromPrefPtr(&prefs.gui_qt_show_selected_packet);
    ui->statusBarShowSelectedPacketCheckBox->setChecked(prefs_get_bool_value(pref_show_selected_packet_, pref_stashed));

    pref_show_file_load_time_ = prefFromPrefPtr(&prefs.gui_qt_show_file_load_time);
    ui->statusBarShowFileLoadTimeCheckBox->setChecked(prefs_get_bool_value(pref_show_file_load_time_, pref_stashed));
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
    switch (prefs_get_uint_value_real(pref_layout_type_, pref_stashed)) {
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

    switch (prefs_get_enum_value(pref_layout_content_1_, pref_stashed)) {
    case layout_pane_content_plist:
        ui->pane1PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane1PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane1PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdiagram:
        ui->pane1PacketDiagramRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane1NoneRadioButton->setChecked(true);
        break;
    }

    switch (prefs_get_enum_value(pref_layout_content_2_, pref_stashed)) {
    case layout_pane_content_plist:
        ui->pane2PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane2PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane2PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdiagram:
        ui->pane2PacketDiagramRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane2NoneRadioButton->setChecked(true);
        break;
    }

    switch (prefs_get_enum_value(pref_layout_content_3_, pref_stashed)) {
    case layout_pane_content_plist:
        ui->pane3PacketListRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdetails:
        ui->pane3PacketDetailsRadioButton->setChecked(true);
        break;
    case layout_pane_content_pbytes:
        ui->pane3PacketBytesRadioButton->setChecked(true);
        break;
    case layout_pane_content_pdiagram:
        ui->pane3PacketDiagramRadioButton->setChecked(true);
        break;
    case layout_pane_content_none:
        ui->pane3NoneRadioButton->setChecked(true);
        break;
    }
}

void LayoutPreferencesFrame::on_layout5ToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_5, pref_stashed);
}

void LayoutPreferencesFrame::on_layout2ToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_2, pref_stashed);
}

void LayoutPreferencesFrame::on_layout1ToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_1, pref_stashed);
}

void LayoutPreferencesFrame::on_layout4ToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_4, pref_stashed);
}

void LayoutPreferencesFrame::on_layout3ToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_3, pref_stashed);
}

void LayoutPreferencesFrame::on_layout6ToolButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_uint_value(pref_layout_type_, layout_type_6, pref_stashed);
}

void LayoutPreferencesFrame::on_pane1PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_plist, pref_stashed);
    if (ui->pane2PacketListRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketListRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_pdetails, pref_stashed);
    if (ui->pane2PacketDetailsRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketDetailsRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_pbytes, pref_stashed);
    if (ui->pane2PacketBytesRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketBytesRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1PacketDiagramRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_pdiagram, pref_stashed);
    if (ui->pane2PacketDiagramRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
    if (ui->pane3PacketDiagramRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane1NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_1_, layout_pane_content_none, pref_stashed);
}

void LayoutPreferencesFrame::on_pane2PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_plist, pref_stashed);
    if (ui->pane1PacketListRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketListRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_pdetails, pref_stashed);
    if (ui->pane1PacketDetailsRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketDetailsRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_pbytes, pref_stashed);
    if (ui->pane1PacketBytesRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketBytesRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2PacketDiagramRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_pdiagram, pref_stashed);
    if (ui->pane1PacketDiagramRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane3PacketDiagramRadioButton->isChecked())
        ui->pane3NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane2NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_2_, layout_pane_content_none, pref_stashed);
}

void LayoutPreferencesFrame::on_pane3PacketListRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_plist, pref_stashed);
    if (ui->pane1PacketListRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketListRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3PacketDetailsRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_pdetails, pref_stashed);
    if (ui->pane1PacketDetailsRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketDetailsRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3PacketBytesRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_pbytes, pref_stashed);
    if (ui->pane1PacketBytesRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketBytesRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3PacketDiagramRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_pdiagram, pref_stashed);
    if (ui->pane1PacketDiagramRadioButton->isChecked())
        ui->pane1NoneRadioButton->click();
    if (ui->pane2PacketDiagramRadioButton->isChecked())
        ui->pane2NoneRadioButton->click();
}

void LayoutPreferencesFrame::on_pane3NoneRadioButton_toggled(bool checked)
{
    if (!checked) return;
    prefs_set_enum_value(pref_layout_content_3_, layout_pane_content_none, pref_stashed);
}

void LayoutPreferencesFrame::on_restoreButtonBox_clicked(QAbstractButton *)
{
    reset_stashed_pref(pref_layout_type_);
    reset_stashed_pref(pref_layout_content_1_);
    updateWidgets();
    reset_stashed_pref(pref_layout_content_2_);
    updateWidgets();
    reset_stashed_pref(pref_layout_content_3_);
    updateWidgets();

    ui->packetListSeparatorCheckBox->setChecked(prefs_get_bool_value(pref_packet_list_separator_, pref_default));
    ui->packetListHeaderShowColumnDefinition->setChecked(prefs_get_bool_value(pref_packet_header_column_definition_, pref_default));
    ui->statusBarShowSelectedPacketCheckBox->setChecked(prefs_get_bool_value(pref_show_selected_packet_, pref_default));
    ui->statusBarShowFileLoadTimeCheckBox->setChecked(prefs_get_bool_value(pref_show_file_load_time_, pref_default));
}

void LayoutPreferencesFrame::on_packetListSeparatorCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_packet_list_separator_, (gboolean) checked, pref_stashed);
}

void LayoutPreferencesFrame::on_packetListHeaderShowColumnDefinition_toggled(bool checked)
{
    prefs_set_bool_value(pref_packet_header_column_definition_, (gboolean) checked, pref_stashed);
}

void LayoutPreferencesFrame::on_statusBarShowSelectedPacketCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_show_selected_packet_, (gboolean) checked, pref_stashed);
}

void LayoutPreferencesFrame::on_statusBarShowFileLoadTimeCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_show_file_load_time_, (gboolean) checked, pref_stashed);
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
