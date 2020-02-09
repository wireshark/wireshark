/* main_window_preferences_frame.h
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

class MainWindowPreferencesFrame : public QFrame
{
    Q_OBJECT

public:
    explicit MainWindowPreferencesFrame(QWidget *parent = 0);
    ~MainWindowPreferencesFrame();

protected:
    void showEvent(QShowEvent *evt);

private:
    Ui::MainWindowPreferencesFrame *ui;

    pref_t *pref_geometry_save_position_;
    pref_t *pref_geometry_save_size_;
    pref_t *pref_geometry_save_maximized_;
    pref_t *pref_fileopen_style_;
    pref_t *pref_fileopen_dir_;
    pref_t *pref_recent_df_entries_max_;
    pref_t *pref_recent_files_count_max_;
    pref_t *pref_ask_unsaved_;
    pref_t *pref_autocomplete_filter_;
    pref_t *pref_toolbar_main_style_;
    pref_t *pref_window_title_;
    pref_t *pref_prepend_window_title_;
    void updateWidgets();

private slots:
    void on_geometryCheckBox_toggled(bool checked);
    void on_foStyleLastOpenedRadioButton_toggled(bool checked);
    void on_foStyleSpecifiedRadioButton_toggled(bool checked);
    void on_foStyleSpecifiedLineEdit_textEdited(const QString &new_dir);
    void on_foStyleSpecifiedPushButton_clicked();
    void on_maxFilterLineEdit_textEdited(const QString &new_max);
    void on_maxRecentLineEdit_textEdited(const QString &new_max);
    void on_confirmUnsavedCheckBox_toggled(bool checked);
    void on_displayAutoCompleteCheckBox_toggled(bool checked);
    void on_mainToolbarComboBox_currentIndexChanged(int index);
    void on_languageComboBox_currentIndexChanged(int index);
    void on_windowTitle_textEdited(const QString &new_title);
    void on_prependWindowTitle_textEdited(const QString &new_prefix);
};

#endif // MAIN_WINDOW_PREFERENCES_FRAME_H
