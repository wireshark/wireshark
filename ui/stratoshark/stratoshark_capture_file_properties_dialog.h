/** @file
 *
 * GSoC 2013 - QtShark
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_CAPTURE_FILE_PROPERTIES_DIALOG_H
#define STRATOSHARK_CAPTURE_FILE_PROPERTIES_DIALOG_H

#include "capture_file_properties_dialog.h"

namespace Ui {
class StratosharkCaptureFilePropertiesDialog;
}

class StratosharkCaptureFilePropertiesDialog : public CaptureFilePropertiesDialog
{
    Q_OBJECT

public:
    explicit StratosharkCaptureFilePropertiesDialog(QWidget &parent, CaptureFile& capture_file);
    virtual ~StratosharkCaptureFilePropertiesDialog();

protected:
    virtual QString getStartTextString() const override;
    virtual QString getFirstItemString() const override;
    virtual QString getLastItemString() const override;
    virtual QString getEndTextString() const override;
    virtual QString getDroppedItemString() const override;
    virtual QString getItemSizeLimitString() const override;
    virtual QString getRowTitleString() const override;
    virtual QString getAvgItemSizeString() const override;
    virtual QString getItemCommentString() const override;
    virtual QString getCreatedByString() const override;

};

#endif
