/* packet_range_group_box.cpp
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

#include "packet_range_group_box.h"
#include "ui_packet_range_group_box.h"

PacketRangeGroupBox::PacketRangeGroupBox(QWidget *parent) :
    QGroupBox(parent),
    pr_ui_(new Ui::PacketRangeGroupBox),
    range_(NULL),
    syntax_state_(SyntaxLineEdit::Empty)
{
    pr_ui_->setupUi(this);

    pr_ui_->displayedButton->setChecked(true);
    pr_ui_->allButton->setChecked(true);
}

PacketRangeGroupBox::~PacketRangeGroupBox()
{
    delete pr_ui_;
}

void PacketRangeGroupBox::initRange(packet_range_t *range) {
    if (!range) return;

    range_ = range;

    if (range_->process_filtered) {
        pr_ui_->displayedButton->setChecked(true);
    } else {
        pr_ui_->capturedButton->setChecked(true);
    }

    if (range_->user_range) {
        pr_ui_->rangeLineEdit->setText(range_convert_range(range_->user_range));
    }
    updateCounts();
}

bool PacketRangeGroupBox::isValid() {
    if (pr_ui_->rangeButton->isChecked() && syntax_state_ != SyntaxLineEdit::Empty) {
        return false;
    }
    return true;
}

void PacketRangeGroupBox::updateCounts() {
    SyntaxLineEdit::SyntaxState orig_ss = syntax_state_;
    bool displayed_checked = pr_ui_->displayedButton->isChecked();
    int selected_num;
    bool can_select;
    bool selected_packets;
    int ignored_cnt = 0, displayed_ignored_cnt = 0;
    int label_count;

    if (!range_ || !range_->cf) return;

    if (range_->displayed_cnt != 0) {
        pr_ui_->displayedButton->setEnabled(true);
    } else {
        displayed_checked = false;
        pr_ui_->capturedButton->setChecked(true);
        pr_ui_->displayedButton->setEnabled(false);
    }

    // All / Captured
    pr_ui_->allCapturedLabel->setEnabled(!displayed_checked);
    label_count = range_->cf->count;
    if (range_->remove_ignored) {
        label_count -= range_->ignored_cnt;
    }
    pr_ui_->allCapturedLabel->setText(QString("%1").arg(label_count));

    // All / Displayed
    pr_ui_->allDisplayedLabel->setEnabled(displayed_checked);
    if (range_->include_dependents) {
        label_count = range_->displayed_plus_dependents_cnt;
    } else {
        label_count = range_->displayed_cnt;
    }
    if (range_->remove_ignored) {
        label_count -= range_->displayed_ignored_cnt;
    }
    pr_ui_->allDisplayedLabel->setText(QString("%1").arg(label_count));

    // Selected / Captured + Displayed
    selected_num = (range_->cf->current_frame) ? range_->cf->current_frame->num : 0;
    can_select = (selected_num != 0);
    if (can_select) {
        pr_ui_->selectedButton->setEnabled(true);
        pr_ui_->selectedCapturedLabel->setEnabled(!displayed_checked);
        pr_ui_->selectedDisplayedLabel->setEnabled(displayed_checked);
    } else {
        if (range_->process == range_process_selected) {
            pr_ui_->allButton->setChecked(true);
        }
        pr_ui_->selectedButton->setEnabled(false);
        pr_ui_->selectedCapturedLabel->setEnabled(false);
        pr_ui_->selectedDisplayedLabel->setEnabled(false);
    }
    if ((range_->remove_ignored && can_select && range_->cf->current_frame->flags.ignored) || selected_num < 1) {
        pr_ui_->selectedCapturedLabel->setText("0");
        pr_ui_->selectedDisplayedLabel->setText("0");
    } else {
        pr_ui_->selectedCapturedLabel->setText("1");
        pr_ui_->selectedDisplayedLabel->setText("1");
    }

    // Marked / Captured + Displayed
    if (displayed_checked) {
        selected_packets = (range_->displayed_marked_cnt != 0);
    } else {
        selected_packets = (range_->cf->marked_count > 0);
    }
    if (selected_packets) {
        pr_ui_->markedButton->setEnabled(true);
        pr_ui_->markedCapturedLabel->setEnabled(!displayed_checked);
        pr_ui_->markedDisplayedLabel->setEnabled(displayed_checked);
    } else {
        if (range_->process == range_process_marked) {
            pr_ui_->allButton->setChecked(true);
        }
        pr_ui_->markedButton->setEnabled(false);
        pr_ui_->markedCapturedLabel->setEnabled(false);
        pr_ui_->markedDisplayedLabel->setEnabled(false);
    }
    label_count = range_->cf->marked_count;
    if (range_->remove_ignored) {
        label_count -= range_->ignored_marked_cnt;
    }
    pr_ui_->markedCapturedLabel->setText(QString("%1").arg(label_count));
    label_count = range_->cf->marked_count;
    if (range_->remove_ignored) {
        label_count -= range_->displayed_ignored_marked_cnt;
    }
    pr_ui_->markedDisplayedLabel->setText(QString("%1").arg(label_count));

    // First to last marked / Captured + Displayed
    if (displayed_checked) {
        selected_packets = (range_->displayed_mark_range_cnt != 0);
    } else {
        selected_packets = (range_->mark_range_cnt != 0);
    }
    if (selected_packets) {
        pr_ui_->ftlMarkedButton->setEnabled(true);
        pr_ui_->ftlCapturedLabel->setEnabled(!displayed_checked);
        pr_ui_->ftlDisplayedLabel->setEnabled(displayed_checked);
    } else {
        if (range_->process == range_process_marked_range) {
            pr_ui_->allButton->setChecked(true);
        }
        pr_ui_->ftlMarkedButton->setEnabled(false);
        pr_ui_->ftlCapturedLabel->setEnabled(false);
        pr_ui_->ftlDisplayedLabel->setEnabled(false);
    }
    label_count = range_->mark_range_cnt;
    if (range_->remove_ignored) {
        label_count -= range_->ignored_mark_range_cnt;
    }
    pr_ui_->ftlCapturedLabel->setText(QString("%1").arg(label_count));
    label_count = range_->displayed_mark_range_cnt;
    if (range_->remove_ignored) {
        label_count -= range_->displayed_ignored_mark_range_cnt;
    }
    pr_ui_->ftlDisplayedLabel->setText(QString("%1").arg(label_count));

    // User specified / Captured + Displayed

    pr_ui_->rangeButton->setEnabled(true);
    pr_ui_->rangeCapturedLabel->setEnabled(!displayed_checked);
    pr_ui_->rangeDisplayedLabel->setEnabled(displayed_checked);

    packet_range_convert_str(range_, pr_ui_->rangeLineEdit->text().toUtf8().constData());

    switch (packet_range_check(range_)) {

    case CVT_NO_ERROR:
        label_count = range_->user_range_cnt;
        if (range_->remove_ignored) {
            label_count -= range_->ignored_user_range_cnt;
        }
        pr_ui_->rangeCapturedLabel->setText(QString("%1").arg(label_count));
        label_count = range_->displayed_user_range_cnt;
        if (range_->remove_ignored) {
            label_count -= range_->displayed_ignored_user_range_cnt;
        }
        pr_ui_->rangeDisplayedLabel->setText(QString("%1").arg(label_count));
        syntax_state_ = SyntaxLineEdit::Empty;
        break;

    case CVT_SYNTAX_ERROR:
        pr_ui_->rangeCapturedLabel->setText("<small><i>Bad range</i></small>");
        pr_ui_->rangeDisplayedLabel->setText("-");
        syntax_state_ = SyntaxLineEdit::Invalid;
        break;

    case CVT_NUMBER_TOO_BIG:
        pr_ui_->rangeCapturedLabel->setText("<small><i>Number too large</i></small>");
        pr_ui_->rangeDisplayedLabel->setText("-");
        syntax_state_ = SyntaxLineEdit::Invalid;
        break;

    default:
        g_assert_not_reached();
        return;
    }

    // Ignored
    switch(range_->process) {
    case(range_process_all):
        ignored_cnt = range_->ignored_cnt;
        displayed_ignored_cnt = range_->displayed_ignored_cnt;
        break;
    case(range_process_selected):
        ignored_cnt = (can_select && range_->cf->current_frame->flags.ignored) ? 1 : 0;
        displayed_ignored_cnt = ignored_cnt;
        break;
    case(range_process_marked):
        ignored_cnt = range_->ignored_marked_cnt;
        displayed_ignored_cnt = range_->displayed_ignored_marked_cnt;
        break;
    case(range_process_marked_range):
        ignored_cnt = range_->ignored_mark_range_cnt;
        displayed_ignored_cnt = range_->displayed_ignored_mark_range_cnt;
        break;
    case(range_process_user_range):
        ignored_cnt = range_->ignored_user_range_cnt;
        displayed_ignored_cnt = range_->displayed_ignored_user_range_cnt;
        break;
    default:
        g_assert_not_reached();
    }

    if (displayed_checked)
        selected_packets = (displayed_ignored_cnt != 0);
    else
        selected_packets = (ignored_cnt != 0);

    if (selected_packets) {
        pr_ui_->ignoredCheckBox->setEnabled(true);
        pr_ui_->ignoredCapturedLabel->setEnabled(!displayed_checked);
        pr_ui_->ignoredDisplayedLabel->setEnabled(displayed_checked);
    } else {
        pr_ui_->ignoredCheckBox->setEnabled(false);
        pr_ui_->ignoredCapturedLabel->setEnabled(false);
        pr_ui_->ignoredDisplayedLabel->setEnabled(false);
    }
    pr_ui_->ignoredCapturedLabel->setText(QString("%1").arg(ignored_cnt));
    pr_ui_->ignoredDisplayedLabel->setText(QString("%1").arg(displayed_ignored_cnt));

    if (orig_ss != syntax_state_) {
        pr_ui_->rangeLineEdit->setSyntaxState(syntax_state_);
        emit validityChanged(isValid());
    }
    emit rangeChanged();
}

// Slots

void PacketRangeGroupBox::on_rangeLineEdit_textChanged(const QString &range_str)
{
    Q_UNUSED(range_str)
    if (!pr_ui_->rangeButton->isChecked()) {
        pr_ui_->rangeButton->setChecked(true);
    } else {
        updateCounts();
    }
}

void PacketRangeGroupBox::processButtonToggled(bool checked, packet_range_e process) {
    if (checked && range_) {
        range_->process = process;
    }
    updateCounts();
}

void PacketRangeGroupBox::on_allButton_toggled(bool checked)
{
    processButtonToggled(checked, range_process_all);
}

void PacketRangeGroupBox::on_selectedButton_toggled(bool checked)
{
    processButtonToggled(checked, range_process_selected);
}

void PacketRangeGroupBox::on_markedButton_toggled(bool checked)
{
    processButtonToggled(checked, range_process_marked);
}

void PacketRangeGroupBox::on_ftlMarkedButton_toggled(bool checked)
{
    processButtonToggled(checked, range_process_marked_range);
}

void PacketRangeGroupBox::on_rangeButton_toggled(bool checked)
{
    processButtonToggled(checked, range_process_user_range);
}

void PacketRangeGroupBox::on_capturedButton_toggled(bool checked)
{
    if (checked) updateCounts();
}

void PacketRangeGroupBox::on_displayedButton_toggled(bool checked)
{
    if (checked) updateCounts();
}
