/* packet-its-template.h
 *
 * Intelligent Transport Systems Applications dissectors
 * C. Guerber <cguerber@yahoo.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_ITS_H__
#define __PACKET_ITS_H__

#include "packet-its-exp.h"

#include "packet-its-val.h"

typedef struct its_header {
    uint32_t version;
    uint32_t msgId;
    uint32_t stationId;
    uint32_t CpmContainerId;
} its_header_t;




enum regext_type_enum {
    Reg_AdvisorySpeed,
    Reg_ComputedLane,
    Reg_ConnectionManeuverAssist,
    Reg_GenericLane,
    Reg_IntersectionGeometry,
    Reg_IntersectionState,
    Reg_LaneAttributes,
    Reg_LaneDataAttribute,
    Reg_MapData,
    Reg_MovementEvent,
    Reg_MovementState,
    Reg_NodeAttributeSetLL,
    Reg_NodeAttributeSetXY,
    Reg_NodeOffsetPointLL,
    Reg_NodeOffsetPointXY,
    Reg_Position3D,
    Reg_RequestorDescription,
    Reg_RequestorType,
    Reg_RestrictionUserType,
    Reg_RoadSegment,
    Reg_SignalControlZone,
    Reg_SignalRequest,
    Reg_SignalRequestMessage,
    Reg_SignalRequestPackage,
    Reg_SignalStatus,
    Reg_SignalStatusMessage,
    Reg_SignalStatusPackage,
    Reg_SPAT,
    Reg_RTCMcorrections,
};

#endif /* __PACKET_ITS_H__ */
