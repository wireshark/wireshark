/** @file
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

/**
 * @brief A frame for configuring UI layout and packet list display preferences.
 */
class LayoutPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new LayoutPreferencesFrame.
     * @param parent The parent widget, defaults to 0.
     */
    explicit LayoutPreferencesFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the LayoutPreferencesFrame.
     */
    ~LayoutPreferencesFrame();

protected:
    /**
     * @brief Handles the event when the frame is shown.
     * @param evt The show event to handle.
     */
    void showEvent(QShowEvent *evt) override;

private:
    /** Pointer to the generated UI elements. */
    Ui::LayoutPreferencesFrame *ui;

    /** Preference for the overall layout type. */
    pref_t *pref_layout_type_;

    /** Preference for the content of the first pane. */
    pref_t *pref_layout_content_1_;

    /** Preference for the content of the second pane. */
    pref_t *pref_layout_content_2_;

    /** Preference for the content of the third pane. */
    pref_t *pref_layout_content_3_;

    /** Preference for showing a separator in the packet list. */
    pref_t *pref_packet_list_separator_;

    /** Preference for defining columns in the packet list header. */
    pref_t *pref_packet_header_column_definition_;

    /** Preference for the hover style in the packet list. */
    pref_t *pref_packet_list_hover_style_;

    /** Preference for enabling/disabling sorting in the packet list. */
    pref_t *pref_packet_list_sorting_;

    /** Preference for the maximum number of cached rows in the packet list. */
    pref_t *pref_packet_list_cached_rows_max_;

    /** Preference for showing the selected packet in the status bar. */
    pref_t *pref_show_selected_packet_;

    /** Preference for showing the file load time in the status bar. */
    pref_t *pref_show_file_load_time_;

    /** Preference for the multi-color mode in the packet list. */
    pref_t *pref_packet_list_multi_color_mode_;

    /** Preference for the multi-color shift percentage in the packet list. */
    pref_t *pref_packet_list_multi_color_shift_percent_;

    /** Preference for multi-color details in the packet list. */
    pref_t *pref_packet_list_multi_color_details_;

    /** Preference for the multi-color separator style in the packet list. */
    pref_t *pref_packet_list_multi_color_separator_;

    /**
     * @brief Updates the UI widgets to reflect the current preferences.
     */
    void updateWidgets();

private slots:
    /**
     * @brief Slot triggered when layout style 5 is toggled.
     * @param checked True if checked.
     */
    void on_layout5ToolButton_toggled(bool checked);

    /**
     * @brief Slot triggered when layout style 2 is toggled.
     * @param checked True if checked.
     */
    void on_layout2ToolButton_toggled(bool checked);

    /**
     * @brief Slot triggered when layout style 1 is toggled.
     * @param checked True if checked.
     */
    void on_layout1ToolButton_toggled(bool checked);

    /**
     * @brief Slot triggered when layout style 4 is toggled.
     * @param checked True if checked.
     */
    void on_layout4ToolButton_toggled(bool checked);

    /**
     * @brief Slot triggered when layout style 3 is toggled.
     * @param checked True if checked.
     */
    void on_layout3ToolButton_toggled(bool checked);

    /**
     * @brief Slot triggered when layout style 6 is toggled.
     * @param checked True if checked.
     */
    void on_layout6ToolButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 1 is set to packet list.
     * @param checked True if checked.
     */
    void on_pane1PacketListRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 1 is set to packet details.
     * @param checked True if checked.
     */
    void on_pane1PacketDetailsRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 1 is set to packet bytes.
     * @param checked True if checked.
     */
    void on_pane1PacketBytesRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 1 is set to packet diagram.
     * @param checked True if checked.
     */
    void on_pane1PacketDiagramRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 1 is set to none.
     * @param checked True if checked.
     */
    void on_pane1NoneRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 2 is set to packet list.
     * @param checked True if checked.
     */
    void on_pane2PacketListRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 2 is set to packet details.
     * @param checked True if checked.
     */
    void on_pane2PacketDetailsRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 2 is set to packet bytes.
     * @param checked True if checked.
     */
    void on_pane2PacketBytesRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 2 is set to packet diagram.
     * @param checked True if checked.
     */
    void on_pane2PacketDiagramRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 2 is set to none.
     * @param checked True if checked.
     */
    void on_pane2NoneRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 3 is set to packet list.
     * @param checked True if checked.
     */
    void on_pane3PacketListRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 3 is set to packet details.
     * @param checked True if checked.
     */
    void on_pane3PacketDetailsRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 3 is set to packet bytes.
     * @param checked True if checked.
     */
    void on_pane3PacketBytesRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 3 is set to packet diagram.
     * @param checked True if checked.
     */
    void on_pane3PacketDiagramRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when pane 3 is set to none.
     * @param checked True if checked.
     */
    void on_pane3NoneRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when a button in the restore button box is clicked.
     * @param button The button that was clicked.
     */
    void on_restoreButtonBox_clicked(QAbstractButton *button);

    /**
     * @brief Slot triggered when the packet list separator checkbox is toggled.
     * @param checked True if checked.
     */
    void on_packetListSeparatorCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the show column definition checkbox is toggled.
     * @param checked True if checked.
     */
    void on_packetListHeaderShowColumnDefinition_toggled(bool checked);

    /**
     * @brief Slot triggered when the hover style checkbox is toggled.
     * @param checked True if checked.
     */
    void on_packetListHoverStyleCheckbox_toggled(bool checked);

    /**
     * @brief Slot triggered when the allow sorting checkbox is toggled.
     * @param checked True if checked.
     */
    void on_packetListAllowSorting_toggled(bool checked);

    /**
     * @brief Slot triggered when the cached rows line edit is edited.
     * @param new_str The new text string.
     */
    void on_packetListCachedRowsLineEdit_textEdited(const QString &new_str);

    /**
     * @brief Slot triggered when the show selected packet checkbox is toggled.
     * @param checked True if checked.
     */
    void on_statusBarShowSelectedPacketCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the show file load time checkbox is toggled.
     * @param checked True if checked.
     */
    void on_statusBarShowFileLoadTimeCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the multi-color details checkbox is toggled.
     * @param checked True if checked.
     */
    void on_packetListMultiColorDetailsCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the multi-color mode is set to off.
     * @param checked True if checked.
     */
    void on_packetListMultiColorOffRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the multi-color mode is set to scrollbar only.
     * @param checked True if checked.
     */
    void on_packetListMultiColorScrollbarOnlyRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the multi-color mode is set to equal stripes.
     * @param checked True if checked.
     */
    void on_packetListMultiColorEqualStripesRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the multi-color mode is set to shift right.
     * @param checked True if checked.
     */
    void on_packetListMultiColorShiftRightRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the multi-color shift percent combo box index changes.
     * @param index The new index.
     */
    void on_packetListMultiColorShiftPercentComboBox_currentIndexChanged(int index);

    /**
     * @brief Slot triggered when the multi-color separator style is set to vertical.
     * @param checked True if checked.
     */
    void on_packetListMultiColorSeparatorVerticalRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the multi-color separator style is set to diagonal.
     * @param checked True if checked.
     */
    void on_packetListMultiColorSeparatorDiagonalRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the multi-color separator style is set to bubble.
     * @param checked True if checked.
     */
    void on_packetListMultiColorSeparatorBubbleRadioButton_toggled(bool checked);
};

#endif // LAYOUT_PREFERENCES_FRAME_H
