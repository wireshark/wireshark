/* main_window_preferences_frame.h
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

#ifndef MAIN_WINDOW_PREFERENCES_FRAME_H
#define MAIN_WINDOW_PREFERENCES_FRAME_H

#include "preferences_dialog.h"

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
    pref_t *pref_auto_scroll_on_expand_;
    pref_t *pref_auto_scroll_percentage_;
    pref_t *pref_toolbar_main_style_;
    pref_t *pref_toolbar_filter_style_;
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
    void on_autoScrollCheckBox_toggled(bool checked);
    void on_autoScrollPercentageLineEdit_textEdited(const QString &new_pct);
    void on_mainToolbarComboBox_currentIndexChanged(int index);
    void on_languageComboBox_currentIndexChanged(int index);
};

#endif // MAIN_WINDOW_PREFERENCES_FRAME_H
