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
#include "main_application.h"

#include <ui_main_window_preferences_frame.h>
#include "ui/language.h"

#include <epan/prefs-int.h>
#include <ui/qt/models/pref_models.h>
#include <ui/qt/utils/theme_manager.h>
#include <wsutil/filesystem.h>
#include <app/application_flavor.h>
#include "ui/qt/widgets/wireshark_file_dialog.h"

#include <QDebug>
#include <QCollator>

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
    QString indent_ss = QStringLiteral(
                "QRadioButton, QLineEdit, QLabel {"
                "  margin-left: %1px;"
                "}"
                ).arg(ui->geometryCheckBox->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left());
    ui->foStyleLastOpenedRadioButton->setStyleSheet(indent_ss);
    ui->foStyleSpecifiedRadioButton->setStyleSheet(indent_ss);
    ui->foStyleCWDRadioButton->setStyleSheet(indent_ss);
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

    // For the same reason that it's helpful to present a language in its native
    // term when someone is trying to switch to it, it makes sense to present
    // the "Use system setting" in the system language instead of the current
    // language. (If the user doesn't understand the resulting translation,
    // then switching to the system setting isn't going to help.)
    ui->languageComboBox->setItemText(0, mainApp->translateSystemLocale("MainWindowPreferencesFrame", "Use system setting"));
    QString li_path = QStringLiteral(":/languages/language%1.svg").arg(ThemeManager::isDark() ? ".dark" : "");
    QIcon language_icon = QIcon(li_path);
    ui->languageComboBox->setItemIcon(0, language_icon);
    ui->languageComboBox->setItemData(0, USE_SYSTEM_LANGUAGE);
    ui->languageComboBox->insertSeparator(1);

    QString globalLanguagesPath(QStringLiteral("%1/languages/").arg(get_datafile_dir(application_configuration_environment_prefix())));
    QString userLanguagesPath(gchar_free_to_qstring(get_persconffile_path("languages/", false, application_configuration_environment_prefix())));

    // Get the list of languages for which we have translations.
    QStringList filenames = QDir(":/i18n/").entryList(QStringList("wireshark_*.qm"));
    filenames += QDir(globalLanguagesPath).entryList(QStringList("wireshark_*.qm"));
    filenames += QDir(userLanguagesPath).entryList(QStringList("wireshark_*.qm"));

    // Present languages with their native name. Germanic languages generally
    // capitalize the names of languages; Romance languages generally don't.
    // Other languages have their own rules. It looks a little better IMO to
    // capitalize the first letter of each language regardless as the first
    // word of a combo box entry.
    QList<QPair<QString, QVariant>> langs;
    for (int i = 0; i < filenames.size(); i += 1) {
        QString locale;
        locale = filenames[i];
        locale.truncate(locale.lastIndexOf('.'));
        locale.remove(0, locale.indexOf('_') + 1);

        QString lang = QLocale(locale).nativeLanguageName();
        if (!lang.isEmpty()) { // empty *would* be weird
            lang.replace(0, 1, lang.at(0).toUpper());
        }

        langs.emplaceBack(lang, locale);
    }

    // Use the system locale for collation (Qt uses the CLDR guidelines.) That
    // means that, e.g., if the system locale is a Cyrillic script language all
    // the Cyrillic script native language names will be sorted before others.
    QCollator collator(QLocale::system().collation());
    //collator.setCaseSensitivity(Qt::CaseInsensitive);

    std::sort(langs.begin(), langs.end(), [&collator](const auto &a, const auto &b) {
        return collator.compare(a.first, b.first) < 0;
    });

    // Now add the languages. Sorting first means that "Use system setting"
    // is the first option regardless of locale.
    //
    // Note that since we use the system locale for collation and translating
    // "Use system setting" and native language names for the others, we don't
    // have to change the entries if the current locale changes.
    for (const auto &lang : langs) {
        ui->languageComboBox->addItem(lang.first, lang.second);
    }

    int i = ui->languageComboBox->findData(QString(get_language_used()));
    if (i != -1) {
        ui->languageComboBox->setCurrentIndex(i);
    }

    connect(ui->languageComboBox, &QComboBox::currentIndexChanged,
        this, &MainWindowPreferencesFrame::languageComboBoxCurrentIndexChanged);
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

    switch (prefs_get_enum_value(pref_fileopen_style_, pref_stashed)) {

    case FO_STYLE_LAST_OPENED:
        ui->foStyleLastOpenedRadioButton->setChecked(true);
        break;
    case FO_STYLE_CWD:
        ui->foStyleCWDRadioButton->setChecked(true);
        break;
    case FO_STYLE_SPECIFIED:
    default:
        ui->foStyleSpecifiedRadioButton->setChecked(true);
        break;
    }

    ui->foStyleSpecifiedLineEdit->setText(prefs_get_string_value(pref_fileopen_dir_, pref_stashed));

    ui->maxFilterLineEdit->setText(QString::number(prefs_get_uint_value(pref_recent_df_entries_max_, pref_stashed)));
    ui->maxRecentLineEdit->setText(QString::number(prefs_get_uint_value(pref_recent_files_count_max_, pref_stashed)));

    ui->confirmUnsavedCheckBox->setChecked(prefs_get_bool_value(pref_ask_unsaved_, pref_stashed));
    ui->displayAutoCompleteCheckBox->setChecked(prefs_get_bool_value(pref_autocomplete_filter_, pref_stashed));

    ui->mainToolbarComboBox->setCurrentIndex(prefs_get_enum_value(pref_toolbar_main_style_, pref_stashed));

    int i = ui->languageComboBox->findData(QString(get_language_used()));
    if (i != -1) {
        ui->languageComboBox->setCurrentIndex(i);
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

void MainWindowPreferencesFrame::on_foStyleCWDRadioButton_toggled(bool checked)
{
    if (checked) {
        prefs_set_enum_value(pref_fileopen_style_, FO_STYLE_CWD, pref_stashed);
    }
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

void MainWindowPreferencesFrame::languageComboBoxCurrentIndexChanged(int index _U_)
{
    set_language_used(ui->languageComboBox->currentData().toString().toUtf8().constData());
}

void MainWindowPreferencesFrame::on_windowTitle_textEdited(const QString &new_title)
{
    prefs_set_string_value(pref_window_title_, new_title.toStdString().c_str(), pref_stashed);
}

void MainWindowPreferencesFrame::on_prependWindowTitle_textEdited(const QString &new_prefix)
{
    prefs_set_string_value(pref_prepend_window_title_, new_prefix.toStdString().c_str(), pref_stashed);
}
