/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef MAIN_WINDOW_PREFERENCES_FRAME_H
#define MAIN_WINDOW_PREFERENCES_FRAME_H

#include <epan/prefs.h>

#include <QFrame>

namespace Ui {
class MainWindowPreferencesFrame;
}

/**
 * @brief A frame for configuring main window preferences.
 */
class MainWindowPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new MainWindowPreferencesFrame.
     * @param parent The parent widget, defaults to 0.
     */
    explicit MainWindowPreferencesFrame(QWidget *parent = 0);

    /**
     * @brief Destroys the MainWindowPreferencesFrame.
     */
    ~MainWindowPreferencesFrame();

protected:
    /**
     * @brief Handles the event when the frame is shown.
     * @param evt The show event.
     */
    void showEvent(QShowEvent *evt);

private:
    /** Pointer to the generated UI elements. */
    Ui::MainWindowPreferencesFrame *ui;

    /** Preference for saving the window position. */
    pref_t *pref_geometry_save_position_;

    /** Preference for saving the window size. */
    pref_t *pref_geometry_save_size_;

    /** Preference for saving the window maximized state. */
    pref_t *pref_geometry_save_maximized_;

    /** Preference for the file open dialog style. */
    pref_t *pref_fileopen_style_;

    /** Preference for the default file open directory. */
    pref_t *pref_fileopen_dir_;

    /** Preference for the maximum number of recent display filter entries. */
    pref_t *pref_recent_df_entries_max_;

    /** Preference for the maximum number of recent files. */
    pref_t *pref_recent_files_count_max_;

    /** Preference for asking to save unsaved capture files. */
    pref_t *pref_ask_unsaved_;

    /** Preference for display filter auto-completion. */
    pref_t *pref_autocomplete_filter_;

    /** Preference for the main toolbar style. */
    pref_t *pref_toolbar_main_style_;

    /** Preference for the custom window title. */
    pref_t *pref_window_title_;

    /** Preference for text to prepend to the window title. */
    pref_t *pref_prepend_window_title_;

    /**
     * @brief Updates the UI widgets to reflect current preference values.
     */
    void updateWidgets();

private slots:
    /**
     * @brief Slot triggered when the save geometry checkbox is toggled.
     * @param checked True if checked.
     */
    void on_geometryCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the current working directory radio button is toggled.
     * @param checked True if checked.
     */
    void on_foStyleCWDRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the last opened directory radio button is toggled.
     * @param checked True if checked.
     */
    void on_foStyleLastOpenedRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the specified directory radio button is toggled.
     * @param checked True if checked.
     */
    void on_foStyleSpecifiedRadioButton_toggled(bool checked);

    /**
     * @brief Slot triggered when the specified directory line edit is modified.
     * @param new_dir The new directory string.
     */
    void on_foStyleSpecifiedLineEdit_textEdited(const QString &new_dir);

    /**
     * @brief Slot triggered when the specified directory browse button is clicked.
     */
    void on_foStyleSpecifiedPushButton_clicked();

    /**
     * @brief Slot triggered when the max filter entries line edit is modified.
     * @param new_max The new maximum value as a string.
     */
    void on_maxFilterLineEdit_textEdited(const QString &new_max);

    /**
     * @brief Slot triggered when the max recent files line edit is modified.
     * @param new_max The new maximum value as a string.
     */
    void on_maxRecentLineEdit_textEdited(const QString &new_max);

    /**
     * @brief Slot triggered when the confirm unsaved capture checkbox is toggled.
     * @param checked True if checked.
     */
    void on_confirmUnsavedCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the display autocomplete checkbox is toggled.
     * @param checked True if checked.
     */
    void on_displayAutoCompleteCheckBox_toggled(bool checked);

    /**
     * @brief Slot triggered when the main toolbar combo box index changes.
     * @param index The new index.
     */
    void on_mainToolbarComboBox_currentIndexChanged(int index);

    /**
     * @brief Slot triggered when the language combo box index changes.
     * @param index The new index.
     */
    void on_languageComboBox_currentIndexChanged(int index);

    /**
     * @brief Slot triggered when the window title line edit is modified.
     * @param new_title The new title string.
     */
    void on_windowTitle_textEdited(const QString &new_title);

    /**
     * @brief Slot triggered when the prepend window title line edit is modified.
     * @param new_prefix The new prefix string.
     */
    void on_prependWindowTitle_textEdited(const QString &new_prefix);
};

#endif // MAIN_WINDOW_PREFERENCES_FRAME_H
