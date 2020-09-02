/* layout_preferences_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef LAYOUT_PREFERENCES_FRAME_H
#define LAYOUT_PREFERENCES_FRAME_H

#include <epan/prefs.h>

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
    pref_t *pref_packet_list_separator_;
    pref_t *pref_packet_header_column_definition_;
    pref_t *pref_show_selected_packet_;
    pref_t *pref_show_file_load_time_;

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
    void on_pane1PacketDiagramRadioButton_toggled(bool checked);
    void on_pane1NoneRadioButton_toggled(bool checked);
    void on_pane2PacketListRadioButton_toggled(bool checked);
    void on_pane2PacketDetailsRadioButton_toggled(bool checked);
    void on_pane2PacketBytesRadioButton_toggled(bool checked);
    void on_pane2PacketDiagramRadioButton_toggled(bool checked);
    void on_pane2NoneRadioButton_toggled(bool checked);
    void on_pane3PacketListRadioButton_toggled(bool checked);
    void on_pane3PacketDetailsRadioButton_toggled(bool checked);
    void on_pane3PacketBytesRadioButton_toggled(bool checked);
    void on_pane3PacketDiagramRadioButton_toggled(bool checked);
    void on_pane3NoneRadioButton_toggled(bool checked);
    void on_restoreButtonBox_clicked(QAbstractButton *button);
    void on_packetListSeparatorCheckBox_toggled(bool checked);
    void on_packetListHeaderShowColumnDefinition_toggled(bool checked);
    void on_statusBarShowSelectedPacketCheckBox_toggled(bool checked);
    void on_statusBarShowFileLoadTimeCheckBox_toggled(bool checked);
};

#endif // LAYOUT_PREFERENCES_FRAME_H
