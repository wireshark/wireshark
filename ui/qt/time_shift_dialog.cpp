/* time_shift_dialog.cpp
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

#include "time_shift_dialog.h"
#include "ui_time_shift_dialog.h"

#include "wireshark_application.h"

#include <ui/time_shift.h>
#include "tango_colors.h"


TimeShiftDialog::TimeShiftDialog(QWidget *parent, capture_file *cf) :
    QDialog(parent),
    ts_ui_(new Ui::TimeShiftDialog),
    cap_file_(cf),
    apply_button_(NULL)
{
    ts_ui_->setupUi(this);
    apply_button_ = ts_ui_->buttonBox->button(QDialogButtonBox::Apply);
    connect(apply_button_, SIGNAL(clicked()), this, SLOT(applyTimeShift()));

    QStyleOption style_opt;
    int rb_label_offset =  ts_ui_->shiftAllButton->style()->subElementRect(QStyle::SE_RadioButtonContents, &style_opt).left();
    int cb_label_offset =  ts_ui_->shiftAllButton->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left();
    setStyleSheet(QString(
                      "QCheckBox#setTwoCheckBox {"
                      "  margin-left: %1px;"
                      "}"
                      "QLabel#extrapolateLabel {"
                      "  margin-left: %2px;"
                      "}"
                      )
                  .arg(rb_label_offset)
                  .arg(rb_label_offset + cb_label_offset)
                  );

    if (cap_file_) {
        if (cap_file_->current_frame) {
            ts_ui_->setOneFrameLineEdit->setText(QString::number(cap_file_->current_frame->num));
        } else {
            ts_ui_->setOneFrameLineEdit->setText(QString::number(cap_file_->first_displayed));
        }
        ts_ui_->setTwoFrameLineEdit->setText(QString::number(cap_file_->last_displayed));
    }

    ts_ui_->shiftAllButton->setChecked(true);
    ts_ui_->setTwoCheckBox->setChecked(false);
    enableWidgets();
}

TimeShiftDialog::~TimeShiftDialog()
{
    delete ts_ui_;
}

void TimeShiftDialog::enableWidgets()
{
    bool enable_two = ts_ui_->setOneButton->isChecked();
    bool enable_apply = false;

    ts_ui_->setTwoCheckBox->setEnabled(enable_two);
    ts_ui_->setTwoFrameLineEdit->setEnabled(enable_two);
    ts_ui_->setTwoToLabel->setEnabled(enable_two);
    ts_ui_->setTwoTimeLineEdit->setEnabled(enable_two);
    ts_ui_->extrapolateLabel->setEnabled(enable_two && ts_ui_->setTwoCheckBox->isChecked());

    if (ts_ui_->shiftAllButton->isChecked()) {
        if (ts_ui_->shiftAllTimeLineEdit->syntaxState() == SyntaxLineEdit::Valid)
            enable_apply = true;
    } else if (ts_ui_->setOneButton->isChecked()) {
        bool set_two_valid = false;
        if (ts_ui_->setTwoCheckBox->isChecked()) {
            if (ts_ui_->setTwoFrameLineEdit->syntaxState() == SyntaxLineEdit::Valid &&
                    ts_ui_->setTwoTimeLineEdit->syntaxState() == SyntaxLineEdit::Valid) {
                set_two_valid = true;
            }
        } else {
            set_two_valid = true;
        }
        if (set_two_valid &&
                ts_ui_->setOneFrameLineEdit->syntaxState() == SyntaxLineEdit::Valid &&
                ts_ui_->setOneTimeLineEdit->syntaxState() == SyntaxLineEdit::Valid) {
            enable_apply = true;
        }
    } else if (ts_ui_->unshiftAllButton->isChecked()) {
        enable_apply = true;
    }

    if (syntax_err_.isEmpty()) {
        ts_ui_->errorLabel->clear();
        ts_ui_->errorLabel->setStyleSheet(" QLabel { margin-top: 0.5em; }");
    } else {
        ts_ui_->errorLabel->setText(syntax_err_);
        ts_ui_->errorLabel->setStyleSheet(QString(
                    "QLabel {"
                    "  margin-top: 0.5em;"
                    "  color: #%1;"
                    "  background-color: #%2;"
                    "}"
                    )
                .arg(ws_css_warn_text, 6, 16, QChar('0'))
                .arg(ws_css_warn_background, 6, 16, QChar('0'))
                );
    }
    apply_button_->setEnabled(enable_apply);
}

void TimeShiftDialog::checkFrameNumber(SyntaxLineEdit &frame_le)
{
    bool frame_valid;
    guint frame_num = frame_le.text().toUInt(&frame_valid);

    syntax_err_.clear();
    if (frame_le.text().isEmpty()) {
        frame_le.setSyntaxState(SyntaxLineEdit::Empty);
    } else if (!frame_valid || !cap_file_ || frame_num < 1 || frame_num > cap_file_->count) {
        frame_le.setSyntaxState(SyntaxLineEdit::Invalid);
        if (cap_file_) {
            syntax_err_ = QString(tr("Frame numbers must be between 1 and %1.").arg(cap_file_->count));
        } else {
            syntax_err_ = tr("Invalid frame number.");
        }
    } else {
        frame_le.setSyntaxState(SyntaxLineEdit::Valid);
    }
}

void TimeShiftDialog::checkDateTime(SyntaxLineEdit &time_le)
{
    int Y, M, D, h, m;
    long double s;
    const gchar *err_str;

    syntax_err_.clear();
    if (time_le.text().isEmpty()) {
        time_le.setSyntaxState(SyntaxLineEdit::Empty);
    } else if ((err_str = time_string_parse(time_le.text().toUtf8().constData(),
                                 &Y, &M, &D, NULL, &h, &m, &s)) != NULL) {
        syntax_err_ = err_str;
        time_le.setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        time_le.setSyntaxState(SyntaxLineEdit::Valid);
    }
}

void TimeShiftDialog::on_shiftAllButton_toggled(bool checked)
{
    Q_UNUSED(checked);
    enableWidgets();
}

void TimeShiftDialog::on_setOneButton_toggled(bool checked)
{
    Q_UNUSED(checked);
    enableWidgets();
}

void TimeShiftDialog::on_unshiftAllButton_toggled(bool checked)
{
    Q_UNUSED(checked);
    enableWidgets();
}

void TimeShiftDialog::on_setTwoCheckBox_toggled(bool checked)
{
    Q_UNUSED(checked);
    enableWidgets();
}

void TimeShiftDialog::on_shiftAllTimeLineEdit_textChanged(const QString &sa_text)
{
    int h, m;
    long double s;
    gboolean neg;
    const gchar *err_str;

    syntax_err_.clear();
    if (sa_text.isEmpty()) {
        ts_ui_->shiftAllTimeLineEdit->setSyntaxState(SyntaxLineEdit::Empty);
    } else if ((err_str = time_string_parse(sa_text.toUtf8().constData(),
                                 NULL, NULL, NULL, &neg, &h, &m, &s)) != NULL) {
        syntax_err_ = err_str;
        ts_ui_->shiftAllTimeLineEdit->setSyntaxState(SyntaxLineEdit::Invalid);
    } else {
        ts_ui_->shiftAllTimeLineEdit->setSyntaxState(SyntaxLineEdit::Valid);
    }
    ts_ui_->shiftAllButton->setChecked(true);
    enableWidgets();
}

void TimeShiftDialog::on_setOneFrameLineEdit_textChanged(const QString &frame_text)
{
    Q_UNUSED(frame_text);
    checkFrameNumber(*ts_ui_->setOneFrameLineEdit);
    ts_ui_->setOneButton->setChecked(true);
    enableWidgets();
}
void TimeShiftDialog::on_setOneTimeLineEdit_textChanged(const QString &so_text)
{
    Q_UNUSED(so_text);
    checkDateTime(*ts_ui_->setOneTimeLineEdit);
    ts_ui_->setOneButton->setChecked(true);
    enableWidgets();
}

void TimeShiftDialog::on_setTwoFrameLineEdit_textChanged(const QString &frame_text)
{
    Q_UNUSED(frame_text);
    Q_UNUSED(frame_text);
    checkFrameNumber(*ts_ui_->setTwoFrameLineEdit);
    if (ts_ui_->setTwoCheckBox->isEnabled())
        ts_ui_->setTwoCheckBox->setChecked(true);
    enableWidgets();
}

void TimeShiftDialog::on_setTwoTimeLineEdit_textChanged(const QString &st_text)
{
    Q_UNUSED(st_text);
    checkDateTime(*ts_ui_->setTwoTimeLineEdit);
    if (ts_ui_->setTwoCheckBox->isEnabled())
        ts_ui_->setTwoCheckBox->setChecked(true);
    enableWidgets();
}

void TimeShiftDialog::applyTimeShift()
{
    const gchar *err_str = NULL;

    if (!cap_file_ || cap_file_->state == FILE_CLOSED) return;

    syntax_err_.clear();
    if (cap_file_->state == FILE_READ_IN_PROGRESS) {
        syntax_err_ = tr("Time shifting is not available capturing packets.");
    } else if (ts_ui_->shiftAllButton->isChecked()) {
        err_str = time_shift_all(cap_file_,
                                 ts_ui_->shiftAllTimeLineEdit->text().toUtf8().constData());
    } else if (ts_ui_->setOneButton->isChecked()) {
        if (!ts_ui_->setTwoCheckBox->isChecked()) {
            err_str = time_shift_settime(cap_file_,
                                         ts_ui_->setOneFrameLineEdit->text().toUInt(),
                                         ts_ui_->setOneTimeLineEdit->text().toUtf8().constData()
                                         );
        } else {
            err_str = time_shift_adjtime(cap_file_,
                                         ts_ui_->setOneFrameLineEdit->text().toUInt(),
                                         ts_ui_->setOneTimeLineEdit->text().toUtf8().constData(),
                                         ts_ui_->setTwoFrameLineEdit->text().toUInt(),
                                         ts_ui_->setTwoTimeLineEdit->text().toUtf8().constData()
                                         );
        }
    } else if (ts_ui_->unshiftAllButton->isChecked()) {
        err_str = time_shift_undo(cap_file_);
    }
    if (err_str) syntax_err_ = err_str;
    enableWidgets();
}

void TimeShiftDialog::on_buttonBox_helpRequested()
{
    wsApp->helpTopicAction(HELP_TIME_SHIFT_DIALOG);
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
