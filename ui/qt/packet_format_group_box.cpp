/* packet_format_group_box.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_format_group_box.h"
#include <ui_packet_format_group_box.h>
#include <ui_packet_format_json_group_box.h>

#include <epan/print.h>

#include <QLabel>
#include <QStyle>
#include <QStyleOption>

PacketFormatGroupBox::PacketFormatGroupBox(QWidget *parent) :
    QGroupBox("Packet Format", parent)
{
    setFlat(true);
}

bool PacketFormatGroupBox::isValid() const
{
    return true;
}

PacketFormatBlankGroupBox::PacketFormatBlankGroupBox(QWidget *parent) :
    PacketFormatGroupBox(parent)
{
    QVBoxLayout *vbox = new QVBoxLayout;
    QLabel *label = new QLabel((tr("The selected format has no options")));
    label->setWordWrap(true);
    vbox->addWidget(label);
    vbox->addStretch(1);
    setLayout(vbox);
}

void PacketFormatBlankGroupBox::updatePrintArgs(print_args_t&)
{
}

PacketFormatTextGroupBox::PacketFormatTextGroupBox(QWidget *parent) :
    PacketFormatGroupBox(parent),
    pf_ui_(new Ui::PacketFormatTextGroupBox)
{
    pf_ui_->setupUi(this);

    QStyleOption style_opt;
    int cb_label_offset =  pf_ui_->detailsCheckBox->style()->subElementRect(QStyle::SE_CheckBoxContents, &style_opt).left();

    // Indent the checkbox under the "Packet summary" checkbox
    pf_ui_->includeColumnHeadingsCheckBox->setStyleSheet(QStringLiteral(
                      "QCheckBox {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));

    // Indent the radio buttons under the "Packet details" checkbox
    pf_ui_->allCollapsedButton->setStyleSheet(QStringLiteral(
                      "QRadioButton {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));
    pf_ui_->asDisplayedButton->setStyleSheet(QStringLiteral(
                      "QRadioButton {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));
    pf_ui_->allExpandedButton->setStyleSheet(QStringLiteral(
                      "QRadioButton {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));

    // Indent the checkbox under the "Bytes" checkbox
    pf_ui_->includeDataSourcesCheckBox->setStyleSheet(QStringLiteral(
                      "QCheckBox {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));

    pf_ui_->timestampCheckBox->setStyleSheet(QStringLiteral(
                      "QCheckBox {"
                      "  padding-left: %1px;"
                      "}"
                      ).arg(cb_label_offset));
}

PacketFormatTextGroupBox::~PacketFormatTextGroupBox()
{
    delete pf_ui_;
}

bool PacketFormatTextGroupBox::summaryEnabled() const
{
    return pf_ui_->summaryCheckBox->isChecked();
}

bool PacketFormatTextGroupBox::detailsEnabled() const
{
    return pf_ui_->detailsCheckBox->isChecked();
}

bool PacketFormatTextGroupBox::bytesEnabled() const
{
    return pf_ui_->bytesCheckBox->isChecked();
}

bool PacketFormatTextGroupBox::includeColumnHeadingsEnabled() const
{
    return pf_ui_->includeColumnHeadingsCheckBox->isChecked();
}

bool PacketFormatTextGroupBox::allCollapsedEnabled() const
{
    return pf_ui_->allCollapsedButton->isChecked();
}

bool PacketFormatTextGroupBox::asDisplayedEnabled() const
{
    return pf_ui_->asDisplayedButton->isChecked();
}

bool PacketFormatTextGroupBox::allExpandedEnabled() const
{
    return pf_ui_->allExpandedButton->isChecked();
}

uint PacketFormatTextGroupBox::getHexdumpOptions() const
{
    return (pf_ui_->includeDataSourcesCheckBox->isChecked() ? HEXDUMP_SOURCE_MULTI : HEXDUMP_SOURCE_PRIMARY) | (pf_ui_->timestampCheckBox->isChecked() ? HEXDUMP_TIMESTAMP : HEXDUMP_TIMESTAMP_NONE);
}

bool PacketFormatTextGroupBox::isValid() const
{
    if (!summaryEnabled() && !detailsEnabled() && !bytesEnabled()) {
        return false;
    }
    return true;
}

void PacketFormatTextGroupBox::updatePrintArgs(print_args_t& print_args)
{
    print_args.format = PR_FMT_TEXT;
    print_args.print_summary = summaryEnabled();
    print_args.print_col_headings = includeColumnHeadingsEnabled();
    print_args.print_dissections = print_dissections_none;

    if (detailsEnabled()) {
        if (allCollapsedEnabled())
            print_args.print_dissections = print_dissections_collapsed;
        else if (asDisplayedEnabled())
            print_args.print_dissections = print_dissections_as_displayed;
        else if (allExpandedEnabled())
            print_args.print_dissections = print_dissections_expanded;
    }
    print_args.print_hex = bytesEnabled();
    print_args.hexdump_options = getHexdumpOptions();
}

void PacketFormatTextGroupBox::on_summaryCheckBox_toggled(bool checked)
{
    pf_ui_->includeColumnHeadingsCheckBox->setEnabled(checked);
    emit formatChanged();
}

void PacketFormatTextGroupBox::on_detailsCheckBox_toggled(bool checked)
{
    pf_ui_->allCollapsedButton->setEnabled(checked);
    pf_ui_->asDisplayedButton->setEnabled(checked);
    pf_ui_->allExpandedButton->setEnabled(checked);
    emit formatChanged();
}

void PacketFormatTextGroupBox::on_bytesCheckBox_toggled(bool checked)
{
    pf_ui_->includeDataSourcesCheckBox->setEnabled(checked);
    pf_ui_->timestampCheckBox->setEnabled(checked);
    emit formatChanged();
}

void PacketFormatTextGroupBox::on_includeColumnHeadingsCheckBox_toggled(bool)
{
    emit formatChanged();
}

void PacketFormatTextGroupBox::on_allCollapsedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatTextGroupBox::on_asDisplayedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatTextGroupBox::on_allExpandedButton_toggled(bool checked)
{
    if (checked) emit formatChanged();
}

void PacketFormatTextGroupBox::on_includeDataSourcesCheckBox_toggled(bool)
{
    emit formatChanged();
}

void PacketFormatTextGroupBox::on_timestampCheckBox_toggled(bool)
{
    emit formatChanged();
}

PacketFormatJSONGroupBox::PacketFormatJSONGroupBox(QWidget *parent) :
    PacketFormatGroupBox(parent),
    pf_ui_(new Ui::PacketFormatJSONGroupBox)
{
    pf_ui_->setupUi(this);

    connect(pf_ui_->dupKeysCheckBox, &QCheckBox::toggled, this, &PacketFormatGroupBox::formatChanged);
}

PacketFormatJSONGroupBox::~PacketFormatJSONGroupBox()
{
    delete pf_ui_;
}

bool PacketFormatJSONGroupBox::noDuplicateKeys()
{
    return pf_ui_->dupKeysCheckBox->isChecked();
}

void PacketFormatJSONGroupBox::updatePrintArgs(print_args_t& print_args)
{
    print_args.no_duplicate_keys = noDuplicateKeys();
}
