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

// Actions for "Follow Stream" menu items.

class FollowStreamAction : public QAction
{
    Q_OBJECT
public:
    FollowStreamAction(QObject *parent, register_follow_t *follow = NULL);

    register_follow_t* follow() const {return follow_;}
    int protoId() const {return get_follow_proto_id(follow_);}
    const char* filterName() const {return proto_get_protocol_filter_name(get_follow_proto_id(follow_));}

private:
    register_follow_t *follow_;
};

#endif // FOLLOWSTREAMACTION_H
