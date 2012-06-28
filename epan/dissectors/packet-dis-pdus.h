/* packet-dis-pdus.h
 * Declarations for DIS PDU parsing.
 * Copyright 2005, Scientific Research Corporation
 * Initial implementation by Jeremy Ouellette <jouellet@scires.com>
 *
 * $Id$
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

#ifndef __PACKET_DIS_PDUPARSERS_H__
#define __PACKET_DIS_PDUPARSERS_H__

#include "packet-dis-fields.h"

/* DIS Entity Information / Interaction PDUs */
extern DIS_ParserNode DIS_PARSER_ENTITY_STATE_PDU[];
/* extern DIS_ParserNode DIS_PARSER_COLLISION_PDU[]; */

/* DIS Warfare PDUs */
extern DIS_ParserNode DIS_PARSER_FIRE_PDU[];
extern DIS_ParserNode DIS_PARSER_DETONATION_PDU[];

/* DIS Distributed Emission Regeneration PDUs */
extern DIS_ParserNode DIS_PARSER_ELECTROMAGNETIC_EMISSION_PDU[];

/* DIS Radio Communications protocol (RCP) family PDUs */
extern DIS_ParserNode DIS_PARSER_TRANSMITTER_PDU[];
extern DIS_ParserNode DIS_PARSER_SIGNAL_PDU[];

/* DIS Simulation Management PDUs */
extern DIS_ParserNode DIS_PARSER_START_RESUME_PDU[];
extern DIS_ParserNode DIS_PARSER_STOP_FREEZE_PDU[];
extern DIS_ParserNode DIS_PARSER_ACKNOWLEDGE_PDU[];
extern DIS_ParserNode DIS_PARSER_ACTION_REQUEST_PDU[];
extern DIS_ParserNode DIS_PARSER_ACTION_RESPONSE_PDU[];
extern DIS_ParserNode DIS_PARSER_DATA_PDU[];
extern DIS_ParserNode DIS_PARSER_DATA_QUERY_PDU[];
extern DIS_ParserNode DIS_PARSER_COMMENT_PDU[];
extern DIS_ParserNode DIS_PARSER_SIMAN_ENTITY_PDU[];

/* DIS Simulation Management with Reliability PDUs */
extern DIS_ParserNode DIS_PARSER_START_RESUME_R_PDU[];
extern DIS_ParserNode DIS_PARSER_STOP_FREEZE_R_PDU[];
extern DIS_ParserNode DIS_PARSER_ACTION_REQUEST_R_PDU[];
extern DIS_ParserNode DIS_PARSER_DATA_R_PDU[];
extern DIS_ParserNode DIS_PARSER_DATA_QUERY_R_PDU[];
extern DIS_ParserNode DIS_PARSER_SIMAN_ENTITY_R_PDU[];

/* DIS Experimental V-DIS PDUs */
extern DIS_ParserNode DIS_PARSER_APPLICATION_CONTROL_PDU[];

/* Persistent Object (PO) Family PDUs */
extern DIS_ParserNode DIS_PARSER_SIMULATOR_PRESENT_PO_PDU[];
extern DIS_ParserNode DIS_PARSER_DESCRIBE_OBJECT_PO_PDU[];
extern DIS_ParserNode DIS_PARSER_OBJECTS_PRESENT_PO_PDU[];
extern DIS_ParserNode DIS_PARSER_OBJECT_REQUEST_PO_PDU[];
extern DIS_ParserNode DIS_PARSER_DELETE_OBJECTS_PO_PDU[];
extern DIS_ParserNode DIS_PARSER_SET_WORLD_STATE_PO_PDU[];
extern DIS_ParserNode DIS_PARSER_NOMINATION_PO_PDU[];

/* Limits of integral types. */
#ifndef INT8_MIN
#define INT8_MIN               (-128)
#endif
#ifndef INT16_MIN
#define INT16_MIN              (-32767-1)
#endif
#ifndef INT32_MIN
#define INT32_MIN              (-2147483647-1)
#endif
#ifndef INT8_MAX
#define INT8_MAX               (127)
#endif
#ifndef INT16_MAX
#define INT16_MAX              (32767)
#endif
#ifndef INT32_MAX
#define INT32_MAX              (2147483647)
#endif
#ifndef UINT8_MAX
#define UINT8_MAX              (255U)
#endif
#ifndef UINT16_MAX
#define UINT16_MAX             (65535U)
#endif
#ifndef UINT32_MAX
#define UINT32_MAX             (4294967295U)
#endif

DIS_ParserNode *createSubtree(DIS_ParserNode parserNodes[], gint *ettVar);

void initializeParser(DIS_ParserNode parserNodes[]);

void initializeParsers(void);

gint parseFields(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNodes[]);

#endif /* packet-dis-pduparsers.h */
