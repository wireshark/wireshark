/* @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "stratoshark_capture_file_properties_dialog.h"
#include "app/application_flavor.h"

StratosharkCaptureFilePropertiesDialog::StratosharkCaptureFilePropertiesDialog(QWidget &parent, CaptureFile &capture_file) :
    CaptureFilePropertiesDialog(parent, capture_file)
{
}

StratosharkCaptureFilePropertiesDialog::~StratosharkCaptureFilePropertiesDialog()
{
}

QString StratosharkCaptureFilePropertiesDialog::getStartTextString() const
{
    return tr("Log start");
}

QString StratosharkCaptureFilePropertiesDialog::getFirstItemString() const
{
    return tr("First event");
}

QString StratosharkCaptureFilePropertiesDialog::getLastItemString() const
{
    return tr("Last event");
}

QString StratosharkCaptureFilePropertiesDialog::getEndTextString() const
{
    return tr("Log end");
}

QString StratosharkCaptureFilePropertiesDialog::getDroppedItemString() const
{
    return tr("Dropped events");
}

QString StratosharkCaptureFilePropertiesDialog::getItemSizeLimitString() const
{
    return tr("Event size limit (snaplen)");
}

QString StratosharkCaptureFilePropertiesDialog::getRowTitleString() const
{
    return tr("Events");
}

QString StratosharkCaptureFilePropertiesDialog::getAvgItemSizeString() const
{
    return tr("Average event size, B");
}

QString StratosharkCaptureFilePropertiesDialog::getItemCommentString() const
{
    return tr("Event Comments");
}

QString StratosharkCaptureFilePropertiesDialog::getCreatedByString() const
{
    return tr("Created by Stratoshark %1\n\n").arg(application_get_vcs_version_info());
}
