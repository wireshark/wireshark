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

#include "wireshark_application.h"
#include "main_window_preferences_frame.h"
#include "qt_ui_utils.h"

#include <ui_main_window_preferences_frame.h>
#include "ui/language.h"

#include <epan/prefs-int.h>
#include <wsutil/filesystem.h>

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

    QString globalLanguagesPath(QString(get_datafile_dir()) + "/languages/");
    QString userLanguagesPath(gchar_free_to_qstring(get_persconffile_path("languages/", FALSE)));



    QStringList filenames = QDir(":/i18n/").entryList(QStringList("wireshark_*.qm"));
    filenames += QDir(globalLanguagesPath).entryList(QStringList("wireshark_*.qm"));
    filenames += QDir(userLanguagesPath).entryList(QStringList("wireshark_*.qm"));

    for (int i = 0; i < filenames.size(); i += 1) {
        QString locale;
        locale = filenames[i];
        locale.truncate(locale.lastIndexOf('.'));
        locale.remove(0, locale.indexOf('_') + 1);

        QString lang = QLocale::languageToString(QLocale(locale).language());
        QIcon ico = QIcon();
        if (QFile::exists(QString(":/languages/%1.svg").arg(locale)))
            ico.addFile(QString(":/languages/%1.svg").arg(locale));
        if (QFile::exists(globalLanguagesPath + locale + ".svg"))
            ico.addFile(globalLanguagesPath + locale + ".svg");
        if (QFile::exists(userLanguagesPath + locale + ".svg"))
            ico.addFile(userLanguagesPath + locale + ".svg");

        ui->languageComboBox->addItem(ico, lang, locale);
    }

    ui->languageComboBox->setItemData(0, USE_SYSTEM_LANGUAGE);
    ui->languageComboBox->model()->sort(0);

    for (int i = 0; i < ui->languageComboBox->count(); i += 1) {
        if (QString(language) == ui->languageComboBox->itemData(i).toString()) {
            ui->languageComboBox->setCurrentIndex(i);
            break;
        }
    }

}

MainWindowPreferencesFrame::~MainWindowPreferencesFrame()
{
    delete ui;
}

void MainWindowPreferencesFrame::showEvent(QShowEvent *)
{
    updateWidgets();
}

void MainWindowPreferencesFrame::updateWidgets()
{
    // Yes, this means we're potentially clobbering two prefs in favor of one.
    if (prefs_get_bool_value(pref_geometry_save_position_, pref_stashed) || prefs_get_bool_value(pref_geometry_save_size_, pref_stashed) || prefs_get_bool_value(pref_geometry_save_maximized_, pref_stashed)) {
        ui->geometryCheckBox->setChecked(true);
    } else {
        ui->geometryCheckBox->setChecked(false);
    }

    if (prefs_get_enum_value(pref_fileopen_style_, pref_stashed) == FO_STYLE_LAST_OPENED) {
        ui->foStyleLastOpenedRadioButton->setChecked(true);
    } else {
        ui->foStyleSpecifiedRadioButton->setChecked(true);
    }

    ui->foStyleSpecifiedLineEdit->setText(prefs_get_string_value(pref_fileopen_dir_, pref_stashed));

    ui->maxFilterLineEdit->setText(QString::number(prefs_get_uint_value_real(pref_recent_df_entries_max_, pref_stashed)));
    ui->maxRecentLineEdit->setText(QString::number(prefs_get_uint_value_real(pref_recent_files_count_max_, pref_stashed)));

    ui->confirmUnsavedCheckBox->setChecked(prefs_get_bool_value(pref_ask_unsaved_, pref_stashed));
    ui->autoScrollCheckBox->setChecked(prefs_get_bool_value(pref_auto_scroll_on_expand_, pref_stashed));
    ui->autoScrollPercentageLineEdit->setText(QString::number(prefs_get_uint_value_real(pref_auto_scroll_on_expand_, pref_stashed)));

    ui->mainToolbarComboBox->setCurrentIndex(prefs_get_enum_value(pref_toolbar_main_style_, pref_stashed));

    for (int i = 0; i < ui->languageComboBox->count(); i += 1) {
        if (QString(language) == ui->languageComboBox->itemData(i).toString()) {
            ui->languageComboBox->setCurrentIndex(i);
            break;
        }
    }
}

void MainWindowPreferencesFrame::on_geometryCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_geometry_save_position_, checked, pref_stashed);
    prefs_set_bool_value(pref_geometry_save_size_, checked, pref_stashed);
    prefs_set_bool_value(pref_geometry_save_maximized_, checked, pref_stashed);
}

void MainWindowPreferencesFrame::on_foStyleLastOpenedRadioButton_toggled(bool checked)
{
    if (checked) {
        prefs_set_enum_value(pref_fileopen_style_, FO_STYLE_LAST_OPENED, pref_stashed);
    }
}

void MainWindowPreferencesFrame::on_foStyleSpecifiedRadioButton_toggled(bool checked)
{
    if (checked) {
        prefs_set_enum_value(pref_fileopen_style_, FO_STYLE_SPECIFIED, pref_stashed);
    }
}

void MainWindowPreferencesFrame::on_foStyleSpecifiedLineEdit_textEdited(const QString &new_dir)
{
    prefs_set_string_value(pref_fileopen_dir_, new_dir.toStdString().c_str(), pref_stashed);
    prefs_set_enum_value(pref_fileopen_style_, FO_STYLE_SPECIFIED, pref_stashed);
    updateWidgets();
}

void MainWindowPreferencesFrame::on_foStyleSpecifiedPushButton_clicked()
{
    QString specified_dir = QFileDialog::getExistingDirectory(this, tr("Open Files In"));

    if (specified_dir.isEmpty()) return;

    ui->foStyleSpecifiedLineEdit->setText(specified_dir);
    prefs_set_string_value(pref_fileopen_dir_, specified_dir.toStdString().c_str(), pref_stashed);
    prefs_set_enum_value(pref_fileopen_style_, FO_STYLE_SPECIFIED, pref_stashed);
    updateWidgets();
}

void MainWindowPreferencesFrame::on_maxFilterLineEdit_textEdited(const QString &new_max)
{
    prefs_set_uint_value(pref_recent_df_entries_max_, new_max.toUInt(), pref_stashed);
}

void MainWindowPreferencesFrame::on_maxRecentLineEdit_textEdited(const QString &new_max)
{
    prefs_set_uint_value(pref_recent_files_count_max_, new_max.toUInt(), pref_stashed);
}

void MainWindowPreferencesFrame::on_confirmUnsavedCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_ask_unsaved_, checked, pref_stashed);
}

void MainWindowPreferencesFrame::on_autoScrollCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_auto_scroll_on_expand_, checked, pref_stashed);
}

void MainWindowPreferencesFrame::on_autoScrollPercentageLineEdit_textEdited(const QString &new_pct)
{
    prefs_set_uint_value(pref_auto_scroll_percentage_, new_pct.toUInt(), pref_stashed);
    prefs_set_bool_value(pref_auto_scroll_on_expand_, TRUE, pref_stashed);
    ui->autoScrollCheckBox->setChecked(true);
}

void MainWindowPreferencesFrame::on_mainToolbarComboBox_currentIndexChanged(int index)
{
    prefs_set_enum_value(pref_toolbar_main_style_, index, pref_stashed);
}

void MainWindowPreferencesFrame::on_languageComboBox_currentIndexChanged(int index)
{
    if (language)
        g_free(language);

    language = g_strdup(ui->languageComboBox->itemData(index).toString().toStdString().c_str());
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
