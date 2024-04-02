/* main_window_preferences_frame.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "main_window_preferences_frame.h"
#include <ui/qt/utils/qt_ui_utils.h>

#include <ui_main_window_preferences_frame.h>
#include "ui/language.h"

#include <epan/prefs-int.h>
#include <ui/qt/models/pref_models.h>
#include <ui/qt/utils/color_utils.h>
#include <wsutil/filesystem.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

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
    pref_autocomplete_filter_ = prefFromPrefPtr(&prefs.gui_autocomplete_filter);
    pref_toolbar_main_style_ = prefFromPrefPtr(&prefs.gui_toolbar_main_style);
    pref_window_title_ = prefFromPrefPtr(&prefs.gui_window_title);
    pref_prepend_window_title_ = prefFromPrefPtr(&prefs.gui_prepend_window_title);

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

    int num_entry_width = ui->maxFilterLineEdit->fontMetrics().height() * 3;
    int num_entry_height = ui->maxFilterLineEdit->fontMetrics().height();
    // Some styles (e.g., adwaita) add some extra space around the contents.
    // Find the actual maximum size to set the widget.
    QStyleOptionFrame opt;
    initStyleOption(&opt);
    QSize num_entry_size = ui->maxRecentLineEdit->style()->sizeFromContents(QStyle::CT_LineEdit, &opt, QSize(num_entry_width, num_entry_height));
    ui->maxFilterLineEdit->setMaximumWidth(num_entry_size.width());
    ui->maxRecentLineEdit->setMaximumWidth(num_entry_size.width());

    QString li_path = QString(":/languages/language%1.svg").arg(ColorUtils::themeIsDark() ? ".dark" : "");
    QIcon language_icon = QIcon(li_path);
    ui->languageComboBox->setItemIcon(0, language_icon);

    QString globalLanguagesPath(QString(get_datafile_dir()) + "/languages/");
    QString userLanguagesPath(gchar_free_to_qstring(get_persconffile_path("languages/", false)));

    QStringList filenames = QDir(":/i18n/").entryList(QStringList("wireshark_*.qm"));
    filenames += QDir(globalLanguagesPath).entryList(QStringList("wireshark_*.qm"));
    filenames += QDir(userLanguagesPath).entryList(QStringList("wireshark_*.qm"));

    for (int i = 0; i < filenames.size(); i += 1) {
        QString locale;
        locale = filenames[i];
        locale.truncate(locale.lastIndexOf('.'));
        locale.remove(0, locale.indexOf('_') + 1);

        QString lang = QLocale::languageToString(QLocale(locale).language());

        ui->languageComboBox->addItem(lang, locale);
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
    ui->displayAutoCompleteCheckBox->setChecked(prefs_get_bool_value(pref_autocomplete_filter_, pref_stashed));

    ui->mainToolbarComboBox->setCurrentIndex(prefs_get_enum_value(pref_toolbar_main_style_, pref_stashed));

    for (int i = 0; i < ui->languageComboBox->count(); i += 1) {
        if (QString(language) == ui->languageComboBox->itemData(i).toString()) {
            ui->languageComboBox->setCurrentIndex(i);
            break;
        }
    }

    ui->windowTitle->setText(prefs_get_string_value(pref_window_title_, pref_stashed));
    ui->prependWindowTitle->setText(prefs_get_string_value(pref_prepend_window_title_, pref_stashed));
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
    ui->foStyleSpecifiedRadioButton->setChecked(true);
}

void MainWindowPreferencesFrame::on_foStyleSpecifiedPushButton_clicked()
{
    QString specified_dir = WiresharkFileDialog::getExistingDirectory(this, tr("Open Files In"));

    if (specified_dir.isEmpty()) return;

    ui->foStyleSpecifiedLineEdit->setText(specified_dir);
    prefs_set_string_value(pref_fileopen_dir_, specified_dir.toStdString().c_str(), pref_stashed);
    ui->foStyleSpecifiedRadioButton->setChecked(true);
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

void MainWindowPreferencesFrame::on_displayAutoCompleteCheckBox_toggled(bool checked)
{
    prefs_set_bool_value(pref_autocomplete_filter_, checked, pref_stashed);
}

void MainWindowPreferencesFrame::on_mainToolbarComboBox_currentIndexChanged(int index)
{
    prefs_set_enum_value(pref_toolbar_main_style_, index, pref_stashed);
}

void MainWindowPreferencesFrame::on_languageComboBox_currentIndexChanged(int index)
{
    g_free(language);

    language = qstring_strdup(ui->languageComboBox->itemData(index).toString());
}

void MainWindowPreferencesFrame::on_windowTitle_textEdited(const QString &new_title)
{
    prefs_set_string_value(pref_window_title_, new_title.toStdString().c_str(), pref_stashed);
}

void MainWindowPreferencesFrame::on_prependWindowTitle_textEdited(const QString &new_prefix)
{
    prefs_set_string_value(pref_prepend_window_title_, new_prefix.toStdString().c_str(), pref_stashed);
}
