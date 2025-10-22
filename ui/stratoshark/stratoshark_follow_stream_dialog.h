/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef STRATOSHARK_FOLLOW_STREAM_DIALOG_H
#define STRATOSHARK_FOLLOW_STREAM_DIALOG_H

#include <config.h>

#include "follow_stream_dialog.h"

namespace Ui {
class StratosharkFollowStreamDialog;
}

class StratosharkFollowStreamDialog : public FollowStreamDialog
{
    Q_OBJECT

public:
    explicit StratosharkFollowStreamDialog(QWidget &parent, CaptureFile &cf, int proto_id);
    virtual ~StratosharkFollowStreamDialog();

protected:
    virtual QString labelHint(int pkt = 0) override;
    virtual QString serverToClientString() const override;
    virtual QString clientToServerString() const override;
    virtual QString bothDirectionsString() const override;

};

#endif // STRATOSHARK_FOLLOW_STREAM_DIALOG_H
