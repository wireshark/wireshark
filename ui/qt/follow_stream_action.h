/** @file
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef FOLLOWSTREAMACTION_H
#define FOLLOWSTREAMACTION_H

#include "config.h"

#include <epan/packet_info.h>
#include <epan/follow.h>

#include <QAction>

#include <ui/qt/capture_file.h>

/**
 * @brief Actions for "Follow Stream" menu items.
 */
class FollowStreamAction : public QAction
{
    Q_OBJECT
public:
    /**
     * @brief Constructs a new FollowStreamAction.
     * @param parent The parent QObject.
     * @param follow Pointer to the registered follow stream type (defaults to NULL).
     */
    FollowStreamAction(QObject *parent, register_follow_t *follow = NULL);

    /**
     * @brief Retrieves the associated registered follow stream type.
     * @return Pointer to the register_follow_t structure.
     */
    register_follow_t* follow() const {return follow_;}

    /**
     * @brief Retrieves the protocol ID associated with the follow stream.
     * @return The protocol ID.
     */
    int protoId() const {return get_follow_proto_id(follow_);}

    /**
     * @brief Retrieves the filter name of the associated protocol.
     * @return The protocol filter name string.
     */
    const char* filterName() const {return proto_get_protocol_filter_name(get_follow_proto_id(follow_));}

private:
    /** Pointer to the registered follow stream type. */
    register_follow_t *follow_;
};

#endif // FOLLOWSTREAMACTION_H
