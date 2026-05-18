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

/**
 * @brief Dialog specifically for following streams in Stratoshark.
 */
class StratosharkFollowStreamDialog : public FollowStreamDialog
{
    Q_OBJECT

public:
    /**
     * @brief Constructs a new StratosharkFollowStreamDialog object.
     * @param parent The parent widget.
     * @param cf The capture file.
     * @param proto_id The protocol identifier to follow.
     */
    explicit StratosharkFollowStreamDialog(QWidget &parent, CaptureFile &cf, int proto_id);

    /**
     * @brief Destroys the StratosharkFollowStreamDialog object.
     */
    virtual ~StratosharkFollowStreamDialog();

protected:
    /**
     * @brief Generates a hint label for the stream.
     * @param pkt The packet number to base the hint on.
     * @return A QString containing the generated label hint.
     */
    virtual QString labelHint(int pkt = 0) override;

    /**
     * @brief Retrieves the string representing the server-to-client direction.
     * @return A QString containing the server-to-client text.
     */
    virtual QString serverToClientString() const override;

    /**
     * @brief Retrieves the string representing the client-to-server direction.
     * @return A QString containing the client-to-server text.
     */
    virtual QString clientToServerString() const override;

    /**
     * @brief Retrieves the string representing both directions combined.
     * @return A QString containing the both directions text.
     */
    virtual QString bothDirectionsString() const override;

};

#endif // STRATOSHARK_FOLLOW_STREAM_DIALOG_H
