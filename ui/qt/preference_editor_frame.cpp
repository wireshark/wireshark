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

#include <ui/preference_utils.h>

#include "preference_editor_frame.h"
#include <ui_preference_editor_frame.h>

#include "qt_ui_utils.h"
#include <wsutil/utf8_entities.h>

#include "wireshark_application.h"

#include <QPushButton>

#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
// Qt::escape
#include <QTextDocument>
#endif

// To do:
// - Handle PREF_FILENAME and PREF_DIRNAME.

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
    ui->preferenceTitleLabel->setText(QString("%1:").arg(pref->title));

    // Convert the pref description from plain text to rich text.
    QString description;
#if QT_VERSION < QT_VERSION_CHECK(5, 0, 0)
    description = Qt::escape(pref->description);
#else
    description = QString(pref->description).toHtmlEscaped();
#endif
    description.replace('\n', "<br>");
    QString tooltip = QString("<span>%1</span>").arg(description);
    ui->preferenceTitleLabel->setToolTip(tooltip);
    ui->preferenceLineEdit->setToolTip(tooltip);

    ui->preferenceLineEdit->clear();
    ui->preferenceLineEdit->setSyntaxState(SyntaxLineEdit::Empty);
    disconnect(ui->preferenceLineEdit);

    bool show = false;

    switch (pref_->type) {
    case PREF_UINT:
        new_uint_ = pref->stashed_val.uint;
        connect(ui->preferenceLineEdit, SIGNAL(textEdited(QString)),
                this, SLOT(uintLineEditTextEdited(QString)));
        show = true;
        break;
    case PREF_STRING:
        new_str_ = pref->stashed_val.string;
        connect(ui->preferenceLineEdit, SIGNAL(textEdited(QString)),
                this, SLOT(stringLineEditTextEdited(QString)));
        show = true;
        break;
    case PREF_RANGE:
        g_free(new_range_);
        new_range_ = range_copy(pref->stashed_val.range);
        connect(ui->preferenceLineEdit, SIGNAL(textEdited(QString)),
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
        new_uint_ = pref_->stashed_val.uint;
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
        new_uint_ = pref_->stashed_val.uint;
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

    convert_ret_t ret = range_convert_str(&new_range, new_str.toUtf8().constData(), pref_->info.max_value);
    g_free(new_range_);
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
    switch(pref_->type) {
    case PREF_UINT:
        if (pref_->stashed_val.uint != new_uint_) {
            pref_->stashed_val.uint = new_uint_;
            apply = true;
        }
        break;
    case PREF_STRING:
        if (new_str_.compare(pref_->stashed_val.string) != 0) {
            g_free(pref_->stashed_val.string);
            pref_->stashed_val.string = qstring_strdup(new_str_);
            apply = true;
        }
        break;
    case PREF_RANGE:
        if (!ranges_are_equal(pref_->stashed_val.range, new_range_)) {
            g_free(pref_->stashed_val.range);
            pref_->stashed_val.range = range_copy(new_range_);
            apply = true;
        }
        break;
    default:
        break;
    }

    if (apply && module_) {
        pref_unstash(pref_, &module_->prefs_changed);
        prefs_apply(module_);
        if (!prefs.gui_use_pref_save) {
            prefs_main_write();
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
    g_free(new_range_);
    new_range_ = NULL;
    ui->preferenceLineEdit->clear();
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
