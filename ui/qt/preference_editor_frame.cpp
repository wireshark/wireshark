/* preference_editor_frame.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/decode_as.h>

#include <ui/preference_utils.h>
#include <ui/simple_dialog.h>

#include "preference_editor_frame.h"
#include <ui_preference_editor_frame.h>

#include <ui/qt/utils/qt_ui_utils.h>
#include <ui/qt/widgets/wireshark_file_dialog.h>
#include <wsutil/utf8_entities.h>

#include "main_application.h"

#include <QPushButton>
#include <QKeyEvent>
#include <QRegularExpression>

PreferenceEditorFrame::PreferenceEditorFrame(QWidget *parent) :
    AccordionFrame(parent),
    ui(new Ui::PreferenceEditorFrame),
    module_(NULL),
    pref_(NULL),
    new_uint_(0),
    new_str_(""),
    new_range_(NULL)
{
    ui->setupUi(this);

#ifdef Q_OS_MAC
    foreach (QWidget *w, findChildren<QWidget *>()) {
        w->setAttribute(Qt::WA_MacSmallSize, true);
    }
#endif

    connect(ui->preferenceBrowseButton, &QPushButton::clicked, this, &PreferenceEditorFrame::browsePushButtonClicked);

    // Disconnect textChanged signal for DissectorSyntaxLineEdit.
    disconnect(ui->preferenceLineEdit, &DissectorSyntaxLineEdit::textChanged, NULL, NULL);
}

PreferenceEditorFrame::~PreferenceEditorFrame()
{
    delete ui;
}

void PreferenceEditorFrame::editPreference(preference *pref, pref_module *module)
{
    pref_ = pref;
    module_ = module;

    if (!pref || !module) {
        hide();
        return;
    }

    ui->modulePreferencesToolButton->setText(tr("Open %1 preferences…").arg(module_->title));

    pref_stash(pref_, NULL);
    ui->preferenceTitleLabel->setText(QString("%1:").arg(prefs_get_title(pref)));

    // Convert the pref description from plain text to rich text.
    QString description = html_escape(prefs_get_description(pref));
    description.replace('\n', "<br>");
    QString tooltip = QString("<span>%1</span>").arg(description);
    ui->preferenceTitleLabel->setToolTip(tooltip);
    ui->preferenceLineEdit->setToolTip(tooltip);

    ui->preferenceLineEdit->clear();
    ui->preferenceLineEdit->setSyntaxState(SyntaxLineEdit::Empty);

    // Disconnect previous textChanged signal.
    disconnect(ui->preferenceLineEdit, &SyntaxLineEdit::textChanged, this, NULL);

    bool show = false;
    bool browse_button = false;

    switch (prefs_get_type(pref_)) {
    case PREF_UINT:
        connect(ui->preferenceLineEdit, &SyntaxLineEdit::textChanged,
                this, &PreferenceEditorFrame::uintLineEditTextEdited);
        show = true;
        break;
    case PREF_SAVE_FILENAME:
    case PREF_OPEN_FILENAME:
    case PREF_DIRNAME:
        browse_button = true;
        // Fallthrough
    case PREF_STRING:
    case PREF_PASSWORD:
    case PREF_DISSECTOR:
        connect(ui->preferenceLineEdit, &SyntaxLineEdit::textChanged,
                this, &PreferenceEditorFrame::stringLineEditTextEdited);
        show = true;
        break;
    case PREF_RANGE:
    case PREF_DECODE_AS_RANGE:
        connect(ui->preferenceLineEdit, &SyntaxLineEdit::textChanged,
                this, &PreferenceEditorFrame::rangeLineEditTextEdited);
        show = true;
        break;
    default:
        break;
    }

    if (show) {
        // Enable completion only for display filter search.
        if (prefs_get_type(pref_) == PREF_DISSECTOR) {
            ui->preferenceLineEdit->allowCompletion(true);
            ui->preferenceLineEdit->updateDissectorNames();
            ui->preferenceLineEdit->setDefaultPlaceholderText();
        } else {
            ui->preferenceLineEdit->allowCompletion(false);
            ui->preferenceLineEdit->setPlaceholderText("");
        }

        ui->preferenceLineEdit->setText(gchar_free_to_qstring(prefs_pref_to_str(pref_, pref_stashed)).remove(QRegularExpression("\n\t")));
        ui->preferenceBrowseButton->setHidden(!browse_button);
        animatedShow();
    }
}

void PreferenceEditorFrame::uintLineEditTextEdited(const QString &new_str)
{
    if (new_str.isEmpty()) {
        new_uint_ = prefs_get_uint_value_real(pref_, pref_stashed);
        ui->preferenceLineEdit->setSyntaxState(SyntaxLineEdit::Empty);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
        return;
    }

    bool ok;
    uint new_uint = new_str.toUInt(&ok, 0);
    if (ok) {
        new_uint_ = new_uint;
        ui->preferenceLineEdit->setSyntaxState(SyntaxLineEdit::Valid);
    } else {
        new_uint_ = prefs_get_uint_value_real(pref_, pref_stashed);
        ui->preferenceLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
    }
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok);
}

void PreferenceEditorFrame::stringLineEditTextEdited(const QString &new_str)
{
    bool ok = true;
    new_str_ = new_str;

    if (prefs_get_type(pref_) == PREF_DISSECTOR) {
        ui->preferenceLineEdit->checkDissectorName(new_str_);
        ok = (ui->preferenceLineEdit->syntaxState() != SyntaxLineEdit::Invalid);
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ok);
}

void PreferenceEditorFrame::browsePushButtonClicked()
{
    QString caption = mainApp->windowTitleString(prefs_get_title(pref_));
    QString dir = prefs_get_string_value(pref_, pref_stashed);
    QString filename;

    switch (prefs_get_type(pref_)) {
    case PREF_SAVE_FILENAME:
        filename = WiresharkFileDialog::getSaveFileName(this, caption, dir);
        break;
    case PREF_OPEN_FILENAME:
        filename = WiresharkFileDialog::getOpenFileName(this, caption, dir);
        break;
    case PREF_DIRNAME:
        filename = WiresharkFileDialog::getExistingDirectory(this, caption, dir);
        break;
    }

    if (!filename.isEmpty()) {
        ui->preferenceLineEdit->setText(filename);
    }
}

void PreferenceEditorFrame::rangeLineEditTextEdited(const QString &new_str)
{
    range_t *new_range = NULL;

    convert_ret_t ret = range_convert_str(NULL, &new_range, new_str.toUtf8().constData(), prefs_get_max_value(pref_));
    wmem_free(NULL, new_range_);
    new_range_ = new_range;

    if (ret == CVT_NO_ERROR) {
        if (new_str.isEmpty()) {
            ui->preferenceLineEdit->setSyntaxState(SyntaxLineEdit::Empty);
        } else {
            ui->preferenceLineEdit->setSyntaxState(SyntaxLineEdit::Valid);
        }
    } else {
        ui->preferenceLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(ret == CVT_NO_ERROR);
}

void PreferenceEditorFrame::showEvent(QShowEvent *event)
{
    ui->preferenceLineEdit->setFocus();
    ui->preferenceLineEdit->selectAll();

    AccordionFrame::showEvent(event);
}

void PreferenceEditorFrame::on_modulePreferencesToolButton_clicked()
{
    if (module_) {
        emit showProtocolPreferences(module_->name);
    }
    on_buttonBox_rejected();
}

void PreferenceEditorFrame::on_preferenceLineEdit_returnPressed()
{
    if (ui->buttonBox->button(QDialogButtonBox::Ok)->isEnabled()) {
        on_buttonBox_accepted();
    }
}

void PreferenceEditorFrame::on_buttonBox_accepted()
{
    unsigned int changed_flags = 0;
    unsigned int apply = 0;
    switch(prefs_get_type(pref_)) {
    case PREF_UINT:
        apply = prefs_set_uint_value(pref_, new_uint_, pref_stashed);
        break;
    case PREF_STRING:
    case PREF_SAVE_FILENAME:
    case PREF_OPEN_FILENAME:
    case PREF_DIRNAME:
    case PREF_DISSECTOR:
        apply = prefs_set_string_value(pref_, new_str_.toStdString().c_str(), pref_stashed);
        break;
    case PREF_PASSWORD:
        apply = prefs_set_password_value(pref_, new_str_.toStdString().c_str(), pref_stashed);
        break;
    case PREF_RANGE:
    case PREF_DECODE_AS_RANGE:
        apply = prefs_set_range_value(pref_, new_range_, pref_stashed);
        break;
    default:
        break;
    }

    if (apply && module_) {
        changed_flags = module_->prefs_changed_flags;
        pref_unstash_data_t unstashed_data;

        unstashed_data.module = module_;
        unstashed_data.handle_decode_as = true;

        pref_unstash(pref_, &unstashed_data);
        prefs_apply(module_);
        prefs_main_write();

        char* err = NULL;
        if (save_decode_as_entries(&err) < 0)
        {
            simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
            g_free(err);
        }
    }
    on_buttonBox_rejected();
    // Emit signals once UI is hidden
    if (apply) {
        if (changed_flags & PREF_EFFECT_FIELDS) {
            mainApp->emitAppSignal(MainApplication::FieldsChanged);
        }
        mainApp->emitAppSignal(MainApplication::PacketDissectionChanged);
        mainApp->emitAppSignal(MainApplication::PreferencesChanged);
    }
}

void PreferenceEditorFrame::on_buttonBox_rejected()
{
    pref_ = NULL;
    module_ = NULL;
    wmem_free(NULL, new_range_);
    new_range_ = NULL;
    animatedHide();
}

void PreferenceEditorFrame::keyPressEvent(QKeyEvent *event)
{
    if (pref_ && module_ && (event->modifiers() == Qt::NoModifier)) {
        if (event->key() == Qt::Key_Escape) {
            on_buttonBox_rejected();
        } else if (event->key() == Qt::Key_Enter || event->key() == Qt::Key_Return) {
            if (ui->buttonBox->button(QDialogButtonBox::Ok)->isEnabled()) {
                on_buttonBox_accepted();
            } else if (ui->preferenceLineEdit->syntaxState() == SyntaxLineEdit::Invalid) {
                mainApp->pushStatus(MainApplication::FilterSyntax, tr("Invalid value."));
            }
        }
    }

    AccordionFrame::keyPressEvent(event);
}
