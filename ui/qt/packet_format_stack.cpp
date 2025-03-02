/* packet_format_stack.cpp
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "packet_format_stack.h"

#include <epan/print.h>
#include "packet_format_group_box.h"

PacketFormatStack::PacketFormatStack(QWidget *parent) :
    QStackedWidget(parent)
{

    PacketFormatTextGroupBox *format_text_group_box = new PacketFormatTextGroupBox(this);
    PacketFormatJSONGroupBox *format_json_group_box = new PacketFormatJSONGroupBox(this);
    PacketFormatBlankGroupBox *blank_group_box = new PacketFormatBlankGroupBox(this);

    export_type_map_[export_type_text] = addWidget(format_text_group_box);
    export_type_map_[export_type_json] = addWidget(format_json_group_box);
    blank_idx_ = addWidget(blank_group_box);

    connect(format_text_group_box, &PacketFormatGroupBox::formatChanged, this, &PacketFormatStack::formatChanged);
    connect(format_json_group_box, &PacketFormatGroupBox::formatChanged, this, &PacketFormatStack::formatChanged);
}

PacketFormatStack::~PacketFormatStack()
{
}

bool PacketFormatStack::isValid() const
{
    if (PacketFormatGroupBox *group_box = qobject_cast<PacketFormatGroupBox*>(currentWidget())) {
        return group_box->isValid();
    }
    return true;
}

void PacketFormatStack::setExportType(export_type_e type)
{
    setCurrentIndex(export_type_map_.value(type, blank_idx_));
}

void PacketFormatStack::updatePrintArgs(print_args_t& print_args)
{
    if (PacketFormatGroupBox *group_box = qobject_cast<PacketFormatGroupBox*>(currentWidget())) {
        group_box->updatePrintArgs(print_args);
    }
}
