/* packet_format_group_box.cpp
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

#include "packet_format_group_box.h"
#include <ui_packet_format_group_box.h>

#include <QStyle>

PacketFormatGroupBox::PacketFormatGroupBox(QWidget *parent) :
    QGroupBox(parent),
    pf_ui_(new Ui::PacketFormatGroupBox)
{
    pf_ui_->setupUi(this);
    setFlat(true);

    QStyleOption style_opt;
    int cb_label_offset =  pf_ui_->detailsCheckBox->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left();
    setStyleSheet(QString(
                      "QRadioButton {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));
}

PacketFormatGroupBox::~PacketFormatGroupBox()
{
    delete pf_ui_;
}

bool PacketFormatGroupBox::summaryEnabled()
{
    return pf_ui_->summaryCheckBox->isChecked();
}

bool PacketFormatGroupBox::detailsEnabled()
{
    return pf_ui_->detailsCheckBox->isChecked();
}

bool PacketFormatGroupBox::bytesEnabled()
{
    return pf_ui_->bytesCheckBox->isChecked();
}

bool PacketFormatGroupBox::allCollapsedEnabled()
{
    return pf_ui_->allCollapsedButton->isChecked();
}

bool PacketFormatGroupBox::asDisplayedEnabled()
{
    return pf_ui_->asDisplayedButton->isChecked();
}

bool PacketFormatGroupBox::allExpandedEnabled()
{
    return pf_ui_->allExpandedButton->isChecked();
}

void PacketFormatGroupBox::on_summaryCheckBox_toggled(bool)
{
    emit formatChanged();
}

void PacketFormatGroupBox::on_detailsCheckBox_toggled(bool checked)
{
    pf_ui_->allCollapsedButton->setEnabled(checked);
    pf_ui_->asDisplayedButton->setEnabled(checked);
    pf_ui_->allExpandedButton->setEnabled(checked);
    emit formatChanged();
}

void PacketFormatGroupBox::on_bytesCheckBox_toggled(bool)
{
    emit formatChanged();
}

void PacketFormatGroupBox::on_allCollapsedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatGroupBox::on_asDisplayedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatGroupBox::on_allExpandedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}
