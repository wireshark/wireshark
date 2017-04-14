/* preference_editor_frame.h
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

#include "config.h"

#include <glib.h>

#include <epan/prefs.h>
#include <epan/prefs-int.h>
#include <epan/decode_as.h>

#include <ui/preference_utils.h>
#include <ui/simple_dialog.h>

#include "preference_editor_frame.h"
#include <ui_preference_editor_frame.h>

#include "qt_ui_utils.h"
#include <wsutil/utf8_entities.h>

#include "wireshark_application.h"

#include <QPushButton>

// To do:
// - Handle PREF_SAVE_FILENAME, PREF_OPEN_FILENAME and PREF_DIRNAME.

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

    ui->modulePreferencesToolButton->setText(tr("Open %1 preferences" UTF8_HORIZONTAL_ELLIPSIS).arg(module_->title));

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
    disconnect(ui->preferenceLineEdit, 0, 0, 0);

    bool show = false;

    switch (prefs_get_type(pref_)) {
    case PREF_UINT:
    case PREF_DECODE_AS_UINT:
        connect(ui->preferenceLineEdit, SIGNAL(textChanged(QString)),
                this, SLOT(uintLineEditTextEdited(QString)));
        show = true;
        break;
    case PREF_STRING:
        connect(ui->preferenceLineEdit, SIGNAL(textChanged(QString)),
                this, SLOT(stringLineEditTextEdited(QString)));
        show = true;
        break;
    case PREF_RANGE:
    case PREF_DECODE_AS_RANGE:
        connect(ui->preferenceLineEdit, SIGNAL(textChanged(QString)),
                this, SLOT(rangeLineEditTextEdited(QString)));
        show = true;
        break;
    default:
        break;
    }

    if (show) {
        ui->preferenceLineEdit->setText(gchar_free_to_qstring(prefs_pref_to_str(pref_, pref_stashed)).remove(QRegExp("\n\t")));
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
    new_str_ = new_str;
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
}

void PreferenceEditorFrame::on_modulePreferencesToolButton_clicked()
{
    if (module_) {
        QString module_name = module_->name;
        emit showProtocolPreferences(module_name);
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
    bool apply = false;
    switch(prefs_get_type(pref_)) {
    case PREF_UINT:
    case PREF_DECODE_AS_UINT:
        apply = prefs_set_uint_value(pref_, new_uint_, pref_stashed);
        break;
    case PREF_STRING:
        apply = prefs_set_string_value(pref_, new_str_.toStdString().c_str(), pref_stashed);
        break;
    case PREF_RANGE:
    case PREF_DECODE_AS_RANGE:
        apply = prefs_set_range_value(pref_, new_range_, pref_stashed);
        break;
    default:
        break;
    }

    if (apply && module_) {
        pref_unstash_data_t unstashed_data;

        unstashed_data.module = module_;
        unstashed_data.handle_decode_as = TRUE;

        pref_unstash(pref_, &unstashed_data);
        prefs_apply(module_);
        if (!prefs.gui_use_pref_save) {
            gchar* err = NULL;

            prefs_main_write();

            if (save_decode_as_entries(&err) < 0)
            {
                simple_dialog(ESD_TYPE_ERROR, ESD_BTN_OK, "%s", err);
                g_free(err);
            }
        }
    }
    on_buttonBox_rejected();
    // Emit signals once UI is hidden
    if (apply) {
        wsApp->emitAppSignal(WiresharkApplication::PacketDissectionChanged);
        wsApp->emitAppSignal(WiresharkApplication::PreferencesChanged);
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
