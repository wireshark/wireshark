/* main_window_preferences_frame.cpp
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

#include "main_window_preferences_frame.h"
#include "ui_main_window_preferences_frame.h"

#include <epan/prefs-int.h>

#include <QFileDialog>
#include <QDebug>

MainWindowPreferencesFrame::MainWindowPreferencesFrame(QWidget *parent) :
    QFrame(parent),
    ui(new Ui::MainWindowPreferencesFrame)
{
    ui->setupUi(this);

    pref_geometry_save_position_ = prefFromPrefPtr(&prefs.gui_geometry_save_position);
    pref_geometry_save_size_ = prefFromPrefPtr(&prefs.gui_geometry_save_size);
    pref_geometry_save_maximized_ = prefFromPrefPtr(&prefs.gui_geometry_save_maximized);
    pref_fileopen_style_ = prefFromPrefPtr(&prefs.gui_fileopen_style);
    pref_fileopen_dir_ = prefFromPrefPtr(&prefs.gui_fileopen_dir);
    pref_recent_df_entries_max_ = prefFromPrefPtr(&prefs.gui_recent_df_entries_max);
    pref_recent_files_count_max_ = prefFromPrefPtr(&prefs.gui_recent_files_count_max);
    pref_ask_unsaved_ = prefFromPrefPtr(&prefs.gui_ask_unsaved);
    pref_auto_scroll_on_expand_ = prefFromPrefPtr(&prefs.gui_auto_scroll_on_expand);
    pref_auto_scroll_percentage_ = prefFromPrefPtr(&prefs.gui_auto_scroll_percentage);
    pref_toolbar_main_style_ = prefFromPrefPtr(&prefs.gui_toolbar_main_style);
    pref_toolbar_filter_style_ = prefFromPrefPtr(&prefs.gui_toolbar_filter_style);
    pref_qt_language_ = prefFromPrefPtr(&prefs.gui_qt_language);

    QStyleOption style_opt;
    QString indent_ss = QString(
                "QRadioButton, QLineEdit, QLabel {"
                "  margin-left: %1px;"
                "}"
                ).arg(ui->geometryCheckBox->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left());
    ui->foStyleLastOpenedRadioButton->setStyleSheet(indent_ss);
    ui->foStyleSpecifiedRadioButton->setStyleSheet(indent_ss);
    ui->maxFilterLineEdit->setStyleSheet(indent_ss);
    ui->maxRecentLineEdit->setStyleSheet(indent_ss);

    ui->autoScrollPercentageLabel->setStyleSheet(indent_ss);

    int num_entry_width = ui->maxFilterLineEdit->fontMetrics().height() * 3;
    ui->maxFilterLineEdit->setMaximumWidth(num_entry_width);
    ui->maxRecentLineEdit->setMaximumWidth(num_entry_width);
    ui->autoScrollPercentageLineEdit->setMaximumWidth(num_entry_width);
}

MainWindowPreferencesFrame::~MainWindowPreferencesFrame()
{
    delete ui;
}

void MainWindowPreferencesFrame::showEvent(QShowEvent *evt)
{
    Q_UNUSED(evt);
    updateWidgets();
}

void MainWindowPreferencesFrame::updateWidgets()
{
    // Yes, this means we're potentially clobbering two prefs in favor of one.
    if (pref_geometry_save_position_->stashed_val.boolval || pref_geometry_save_size_->stashed_val.boolval || pref_geometry_save_maximized_->stashed_val.boolval) {
        ui->geometryCheckBox->setChecked(true);
    } else {
        ui->geometryCheckBox->setChecked(false);
    }

    if (pref_fileopen_style_->stashed_val.enumval == FO_STYLE_LAST_OPENED) {
        ui->foStyleLastOpenedRadioButton->setChecked(true);
    } else {
        ui->foStyleSpecifiedRadioButton->setChecked(true);
    }

    ui->foStyleSpecifiedLineEdit->setText(pref_fileopen_dir_->stashed_val.string);

    ui->maxFilterLineEdit->setText(QString::number(pref_recent_df_entries_max_->stashed_val.uint));
    ui->maxRecentLineEdit->setText(QString::number(pref_recent_files_count_max_->stashed_val.uint));

    ui->autoScrollCheckBox->setChecked(pref_auto_scroll_on_expand_->stashed_val.boolval);
    ui->autoScrollPercentageLineEdit->setText(QString::number(pref_auto_scroll_on_expand_->stashed_val.uint));

    ui->mainToolbarComboBox->setCurrentIndex(pref_toolbar_main_style_->stashed_val.enumval);
    ui->filterToolbarComboBox->setCurrentIndex(pref_toolbar_filter_style_->stashed_val.enumval);
    ui->languageComboBox->setCurrentIndex(pref_qt_language_->stashed_val.enumval);
}

void MainWindowPreferencesFrame::on_geometryCheckBox_toggled(bool checked)
{
    pref_geometry_save_position_->stashed_val.boolval = checked;
    pref_geometry_save_size_->stashed_val.boolval = checked;
    pref_geometry_save_maximized_->stashed_val.boolval = checked;
}

void MainWindowPreferencesFrame::on_foStyleLastOpenedRadioButton_toggled(bool checked)
{
    if (checked) {
        pref_fileopen_style_->stashed_val.enumval = FO_STYLE_LAST_OPENED;
    }
}

void MainWindowPreferencesFrame::on_foStyleSpecifiedRadioButton_toggled(bool checked)
{
    if (checked) {
        pref_fileopen_style_->stashed_val.enumval = FO_STYLE_SPECIFIED;
    }
}

void MainWindowPreferencesFrame::on_foStyleSpecifiedLineEdit_textEdited(const QString &new_dir)
{
    g_free(pref_fileopen_dir_->stashed_val.string);
    pref_fileopen_dir_->stashed_val.string = g_strdup(new_dir.toUtf8().constData());
    pref_fileopen_style_->stashed_val.enumval = FO_STYLE_SPECIFIED;
    updateWidgets();
}

void MainWindowPreferencesFrame::on_foStyleSpecifiedPushButton_clicked()
{
    QString specified_dir = QFileDialog::getExistingDirectory(this, tr("Open Files In"));

    if (specified_dir.isEmpty()) return;

    ui->foStyleSpecifiedLineEdit->setText(specified_dir);
    g_free(pref_fileopen_dir_->stashed_val.string);
    pref_fileopen_dir_->stashed_val.string = g_strdup(specified_dir.toUtf8().constData());
    pref_fileopen_style_->stashed_val.enumval = FO_STYLE_SPECIFIED;
    updateWidgets();
}

void MainWindowPreferencesFrame::on_maxFilterLineEdit_textEdited(const QString &new_max)
{
    pref_recent_df_entries_max_->stashed_val.uint = new_max.toUInt();
}

void MainWindowPreferencesFrame::on_maxRecentLineEdit_textEdited(const QString &new_max)
{
    pref_recent_df_entries_max_->stashed_val.uint = new_max.toUInt();
}

void MainWindowPreferencesFrame::on_confirmUnsavedCheckBox_toggled(bool checked)
{
    pref_ask_unsaved_->stashed_val.boolval = checked;
}

void MainWindowPreferencesFrame::on_autoScrollCheckBox_toggled(bool checked)
{
    pref_auto_scroll_on_expand_->stashed_val.boolval = checked;
}

void MainWindowPreferencesFrame::on_autoScrollPercentageLineEdit_textEdited(const QString &new_pct)
{
    pref_auto_scroll_percentage_->stashed_val.uint = new_pct.toUInt();
    pref_auto_scroll_on_expand_->stashed_val.boolval = TRUE;
    ui->autoScrollCheckBox->setChecked(true);
}

void MainWindowPreferencesFrame::on_mainToolbarComboBox_currentIndexChanged(int index)
{
    pref_toolbar_main_style_->stashed_val.enumval = index;
}

void MainWindowPreferencesFrame::on_filterToolbarComboBox_currentIndexChanged(int index)
{
    pref_toolbar_filter_style_->stashed_val.enumval = index;
}

void MainWindowPreferencesFrame::on_languageComboBox_currentIndexChanged(int index)
{
    pref_qt_language_->stashed_val.enumval = index;
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
