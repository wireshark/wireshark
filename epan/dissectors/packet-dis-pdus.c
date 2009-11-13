    /* packet-dis-pdus.c
 * Routines and definitions for DIS PDU parsing.
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <string.h>
#include "packet-dis-pdus.h"
#include "packet-dis-fields.h"

#define DIS_PDU_MAX_VARIABLE_PARAMETERS 16
#define DIS_PDU_MAX_VARIABLE_RECORDS 16

gint ettVariableParameters[DIS_PDU_MAX_VARIABLE_PARAMETERS];
gint ettVariableRecords[DIS_PDU_MAX_VARIABLE_RECORDS];

gint ettFixedData = -1;
gint ettVariableData = -1;

/* DIS Entity Information / Interaction PDUs
 */
DIS_ParserNode DIS_PARSER_ENTITY_STATE_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_FORCE_ID,                "Force ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Number of Variable Parameters",0,0,0,&numVariable },
    { DIS_FIELDTYPE_ENTITY_TYPE,             "Entity Type",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_TYPE,             "Alternative Entity Type",0,0,0,0 },
    { DIS_FIELDTYPE_LINEAR_VELOCITY,         "Entity Linear Velocity",0,0,0,0 },
    { DIS_FIELDTYPE_LOCATION_WORLD,          "Entity Location",0,0,0,0 },
    { DIS_FIELDTYPE_ORIENTATION,             "Entity Orientation",0,0,0,0 },
    { DIS_FIELDTYPE_APPEARANCE,              "Entity Appearance",0,0,0,0 },
    { DIS_FIELDTYPE_DEAD_RECKONING_PARAMS,   "Dead Reckoning Parameters",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_MARKING,          "Entity Marking",0,0,0,0 },
    { DIS_FIELDTYPE_CAPABILITIES,            "Capabilities",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_PARAMETERS,     "Variable Parameter",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

/* DIS Warfare PDUs
 */
DIS_ParserNode DIS_PARSER_FIRE_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,        "Firing Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,        "Target Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,        "Munition ID",0,0,0,0 },
    { DIS_FIELDTYPE_EVENT_ID,         "Event ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,           "Fire Mission Index",0,0,0,0 },
    { DIS_FIELDTYPE_LOCATION_WORLD,   "Location in World Coordinates",0,0,0,0 },
    { DIS_FIELDTYPE_BURST_DESCRIPTOR, "Burst Descriptor",0,0,0,0 },
    { DIS_FIELDTYPE_LINEAR_VELOCITY,  "Velocity",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,          "Range",0,0,0,0 },
    { DIS_FIELDTYPE_END,              NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_DETONATION_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Firing Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Target Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Munition ID",0,0,0,0 },
    { DIS_FIELDTYPE_EVENT_ID,                "Event ID",0,0,0,0 },
    { DIS_FIELDTYPE_LINEAR_VELOCITY,         "Velocity",0,0,0,0 },
    { DIS_FIELDTYPE_LOCATION_WORLD,          "Location in World Coordinates",0,0,0,0 },
    { DIS_FIELDTYPE_BURST_DESCRIPTOR,        "Burst Descriptor",0,0,0,0 },
    { DIS_FIELDTYPE_LOCATION_ENTITY,         "Location in Entity Coordinates",0,0,0,0 },
    { DIS_FIELDTYPE_DETONATION_RESULT,       "Detonation Result",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Number of Variable Parameters",0,0,0,&numVariable },
    { DIS_FIELDTYPE_PAD16,                   "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_PARAMETERS,     "Variable Parameter",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

/* DIS Simulation Management PDUs
 */
DIS_ParserNode DIS_PARSER_START_RESUME_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_CLOCK_TIME,              "Real World Time",0,0,0,0 },
    { DIS_FIELDTYPE_CLOCK_TIME,              "Simulation Time",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_STOP_FREEZE_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_CLOCK_TIME,              "Real World Time",0,0,0,0 },
    { DIS_FIELDTYPE_REASON,                  "Reason",0,0,0,0 },
    { DIS_FIELDTYPE_FROZEN_BEHAVIOR,         "Frozen Behavior",0,0,0,0 },
    { DIS_FIELDTYPE_PAD16,                   "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_ACKNOWLEDGE_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ACKNOWLEDGE_FLAG,        "Acknowledge Flag",0,0,0,0 },
    { DIS_FIELDTYPE_RESPONSE_FLAG,           "Response Flag",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_ACTION_REQUEST_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_ACTION_ID,               "Action ID",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,          "Number of Fixed Data Fields",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,       "Number of Variable Data Fields",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUMS,            "Fixed data",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUMS,         "Variable data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_ACTION_RESPONSE_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_STATUS,          "Request Status",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,          "Number of Fixed Data Fields",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,       "Number of Variable Data Fields",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUMS,            "Fixed data",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUMS,         "Variable data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_DATA_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_PAD32,                   "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,          "Number of Fixed Data Fields",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,       "Number of Variable Data Fields",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUMS,            "Fixed data",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUMS,         "Variable data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_DATA_QUERY_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_TIME_INTERVAL,           "Time interval",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,          "Number of Fixed Datum Ids",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,       "Number of Variable Datum Ids",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUM_IDS,         "Fixed datum ids",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUM_IDS,      "Variable datum ids",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_COMMENT_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,          "Number of Fixed Data Fields",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,       "Number of Variable Data Fields",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUMS,            "Fixed data",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUMS,         "Variable data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_SIMAN_ENTITY_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

/* DIS Simulation Management with Reliability PDUs
 */
DIS_ParserNode DIS_PARSER_START_RESUME_R_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,                    "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,                    "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_CLOCK_TIME,                   "Real World Time",0,0,0,0 },
    { DIS_FIELDTYPE_CLOCK_TIME,                   "Simulation Time",0,0,0,0 },
    { DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE, "Reliability",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                         "Padding",3,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,                   "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_STOP_FREEZE_R_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,                    "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,                    "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_CLOCK_TIME,                   "Real World Time",0,0,0,0 },
    { DIS_FIELDTYPE_REASON,                       "Reason",0,0,0,0 },
    { DIS_FIELDTYPE_FROZEN_BEHAVIOR,              "Frozen Behavior",0,0,0,0 },
    { DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE, "Reliability",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                         "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,                   "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_ACTION_REQUEST_R_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,                    "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,                    "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE, "Reliability",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                         "Padding",3,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,                   "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_ACTION_ID,                    "Action ID",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,               "Number of Fixed Data Fields",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,            "Number of Variable Data Fields",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUMS,                 "Fixed data",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUMS,              "Variable data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_DATA_R_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,                    "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,                    "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE, "Reliability",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                         "Padding",3,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,                   "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,               "Number of Fixed Data Fields",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,            "Number of Variable Data Fields",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUMS,                 "Fixed data",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUMS,              "Variable data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_DATA_QUERY_R_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,                    "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,                    "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE, "Reliability",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                         "Padding",3,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,                   "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_TIME_INTERVAL,                "Time interval",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,               "Number of Fixed Datum Ids",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,            "Number of Variable Datum Ids",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUM_IDS,              "Fixed datum ids",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUM_IDS,           "Variable datum ids",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_SIMAN_ENTITY_R_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,                    "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,                    "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE, "Reliability",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                         "Padding",3,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,                   "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

/* DIS Experimental V-DIS PDUs
 */
DIS_ParserNode DIS_PARSER_APPLICATION_CONTROL_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,                    "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,                    "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE, "Reliability",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                        "Time Interval",0,0,0,0 },
    { DIS_FIELDTYPE_CONTROL_ID,                   "Control ID",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                         "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION_TYPE,             "Originating App Type",0,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION_TYPE,             "Receiving App Type",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,                   "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                        "Number of Parts",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                        "Current Part",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                       "Number of Variable Records",0,0,0,&numVariable },
    { DIS_FIELDTYPE_VARIABLE_RECORDS,             "Record",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

/* Persistent Object (PO) Family PDU parsers
 */
DIS_ParserNode DIS_PARSER_SIMULATOR_PRESENT_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                  "Simulator Type",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,                  "Database Sequence Number",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,                  "Simulator Load",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,                 "Simulation Load",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,                  "Time",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,                  "Packets Sent",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                  "Unit Database Version",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                  "Relative Battle Scheme",0,0,0,0 },
    { DIS_FIELDTYPE_FIXED_LEN_STR,           "Terrain Name",32,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                  "Terrain Version",0,0,0,0 },
    { DIS_FIELDTYPE_FIXED_LEN_STR,           "Host Name",32,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_DESCRIBE_OBJECT_PO_PDU[] =
{
    { DIS_FIELDTYPE_UINT32,                  "Database Sequence Number",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Object ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "World State ID",0,0,0,0 },
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Owner",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                  "Sequence Number",0,0,0,0 },
    { DIS_FIELDTYPE_PERSISTENT_OBJECT_CLASS, "Object Class",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Missing From World State",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_OBJECTS_PRESENT_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Owner",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "World State ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Object Count",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_OBJECT_REQUEST_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Requesting Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Object Owner",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "World State ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Object Count",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_DELETE_OBJECTS_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Requesting Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Object Count",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_SET_WORLD_STATE_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Requesting Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,                 "Clock Rate",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,                  "Seconds Since 1970",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "World State ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_NOMINATION_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Nominated Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Nominating Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Missing Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

/* Initialize the parsers for each PDU type and the standard DIS header.
 */
void initializeParsers(void)
{
    gint *ett[DIS_PDU_MAX_VARIABLE_PARAMETERS+DIS_PDU_MAX_VARIABLE_RECORDS+2];
    int   i, ett_index;

    initializeParser(DIS_FIELDS_PDU_HEADER);

    /* DIS Entity Information / Interaction PDUs */
    initializeParser(DIS_PARSER_ENTITY_STATE_PDU);

    /* DIS Warfare PDUs */
    initializeParser(DIS_PARSER_FIRE_PDU);
    initializeParser(DIS_PARSER_DETONATION_PDU);

    /* DIS Simulation Management PDUs */
    initializeParser(DIS_PARSER_START_RESUME_PDU);
    initializeParser(DIS_PARSER_STOP_FREEZE_PDU);
    initializeParser(DIS_PARSER_ACKNOWLEDGE_PDU);
    initializeParser(DIS_PARSER_ACTION_REQUEST_PDU);
    initializeParser(DIS_PARSER_ACTION_RESPONSE_PDU);
    initializeParser(DIS_PARSER_DATA_PDU);
    initializeParser(DIS_PARSER_DATA_QUERY_PDU);
    initializeParser(DIS_PARSER_COMMENT_PDU);
    initializeParser(DIS_PARSER_SIMAN_ENTITY_PDU);

    /* DIS Simulation Management with Reliability PDUs */
    initializeParser(DIS_PARSER_START_RESUME_R_PDU);
    initializeParser(DIS_PARSER_STOP_FREEZE_R_PDU);
    initializeParser(DIS_PARSER_ACTION_REQUEST_R_PDU);
    initializeParser(DIS_PARSER_DATA_R_PDU);
    initializeParser(DIS_PARSER_DATA_QUERY_R_PDU);
    initializeParser(DIS_PARSER_SIMAN_ENTITY_R_PDU);

    /* DIS Experimental V-DIS PDUs */
    initializeParser(DIS_PARSER_APPLICATION_CONTROL_PDU);

    /* Initialize the Persistent Object PDUs */
    initializeParser(DIS_FIELDS_PERSISTENT_OBJECT_HEADER);
    initializeParser(DIS_PARSER_DESCRIBE_OBJECT_PO_PDU);
    initializeParser(DIS_PARSER_SIMULATOR_PRESENT_PO_PDU);
    initializeParser(DIS_PARSER_OBJECTS_PRESENT_PO_PDU);
    initializeParser(DIS_PARSER_OBJECT_REQUEST_PO_PDU);
    initializeParser(DIS_PARSER_DELETE_OBJECTS_PO_PDU);
    initializeParser(DIS_PARSER_SET_WORLD_STATE_PO_PDU);
    initializeParser(DIS_PARSER_NOMINATION_PO_PDU);

    /* Initialize the ett array */
    ett_index = 0;
    for (i=0; i<DIS_PDU_MAX_VARIABLE_PARAMETERS; i++, ett_index++)
    {
        ettVariableParameters[i] = -1;
        ett[ett_index] = &ettVariableParameters[i];
    }
    for (i=0; i<DIS_PDU_MAX_VARIABLE_RECORDS; i++, ett_index++)
    {
        ettVariableRecords[i] = -1;
        ett[ett_index] = &ettVariableRecords[i];
    }
    ett[ett_index++] = &ettFixedData;
    ett[ett_index++] = &ettVariableData;
    proto_register_subtree_array(ett, array_length(ett));
}

/* Create a specific subtree for a PDU or a composite PDU field.
 */
DIS_ParserNode *createSubtree(DIS_ParserNode parserNodes[], gint *ettVar)
{
    guint fieldIndex = 0;
    guint fieldCount;
    gint *ett[1];
    DIS_ParserNode *newSubtree;

    while (parserNodes[fieldIndex].fieldType != DIS_FIELDTYPE_END)
    {
        ++fieldIndex;
    }

    fieldCount = fieldIndex + 1;

    newSubtree = (DIS_ParserNode*)g_malloc(sizeof(DIS_ParserNode) * fieldCount);

    memcpy(newSubtree, parserNodes, sizeof(DIS_ParserNode) * fieldCount);

    initializeParser(newSubtree);

    *ettVar = -1;
    ett[0] = ettVar;
    proto_register_subtree_array(ett, array_length(ett));

    return newSubtree;
}

/* Initialize an array of parser nodes.
 */
void initializeParser(DIS_ParserNode parserNodes[])
{
    guint parserIndex = 0;

    /* Create the parser subtrees for each of the composite field types.
     */
    while (parserNodes[parserIndex].fieldType != DIS_FIELDTYPE_END)
    {
        switch (parserNodes[parserIndex].fieldType)
        {
        /* Bit fields */
        case DIS_FIELDTYPE_APPEARANCE:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_NONE,
                &parserNodes[parserIndex].ettVar);
            break;

        /* Composite types */
        case DIS_FIELDTYPE_BURST_DESCRIPTOR:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_BURST_DESCRIPTOR,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_CLOCK_TIME:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_CLOCK_TIME,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_ENTITY_ID:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_ENTITY_ID,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_ENTITY_TYPE:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_ENTITY_TYPE,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_EVENT_ID:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_EVENT_ID,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_ORIENTATION:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_ORIENTATION,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_SIMULATION_ADDRESS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_SIMULATION_ADDRESS,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_LINEAR_VELOCITY:
        case DIS_FIELDTYPE_LOCATION_ENTITY:
        case DIS_FIELDTYPE_VECTOR_32:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VECTOR_FLOAT_32,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_LOCATION_WORLD:
        case DIS_FIELDTYPE_VECTOR_64:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VECTOR_FLOAT_64,
                &parserNodes[parserIndex].ettVar);
            break;

        /* Array records */
        case DIS_FIELDTYPE_FIXED_DATUMS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_FIXED_DATUM,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_VARIABLE_DATUMS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VARIABLE_DATUM,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_FIXED_DATUM_IDS:
        case DIS_FIELDTYPE_VARIABLE_DATUM_IDS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_DATUM_IDS,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_VARIABLE_PARAMETERS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VP_TYPE,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_VARIABLE_RECORDS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VR_TYPE,
                &parserNodes[parserIndex].ettVar);
            break;
        default:
            break;
        }
        ++parserIndex;
    }
}

/* Parse packet data based on a specified array of DIS_ParserNodes.
 */
gint parseFields(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNodes[])
{
    guint fieldIndex = 0;
    guint fieldRepeatLen = 0;

    while (parserNodes[fieldIndex].fieldType != DIS_FIELDTYPE_END)
    {
        proto_item *newField = 0;

        fieldRepeatLen = (guint) ((parserNodes[fieldIndex].fieldRepeatLen > 1) ?
            parserNodes[fieldIndex].fieldRepeatLen : 1);

        switch(parserNodes[fieldIndex].fieldType)
        {
        /* basic numeric types */
        case DIS_FIELDTYPE_INT8:
            offset = parseField_Int(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_INT16:
            offset = parseField_Int(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;
        case DIS_FIELDTYPE_INT32:
            offset = parseField_Int(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_INT64:
            offset = parseField_Int(tvb, tree, offset,
                parserNodes[fieldIndex], 8);
            break;
        case DIS_FIELDTYPE_UINT8:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_UINT16:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;
        case DIS_FIELDTYPE_UINT32:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_UINT64:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 8);
            break;
        case DIS_FIELDTYPE_FLOAT32:
            offset = parseField_Float(tvb, tree, offset,
                parserNodes[fieldIndex]);
            break;
        case DIS_FIELDTYPE_FLOAT64:
            offset = parseField_Double(tvb, tree, offset,
                parserNodes[fieldIndex]);
            break;

        /* padding */
        case DIS_FIELDTYPE_PAD8:
            offset = parseField_Pad(tvb, tree, offset,
                parserNodes[fieldIndex], 1 * fieldRepeatLen);
            break;
        case DIS_FIELDTYPE_PAD16:
            offset = parseField_Pad(tvb, tree, offset,
                parserNodes[fieldIndex], 2 * fieldRepeatLen);
            break;
        case DIS_FIELDTYPE_PAD32:
            offset = parseField_Pad(tvb, tree, offset,
                parserNodes[fieldIndex], 4 * fieldRepeatLen);
            break;

        /* enumerations (1-byte) */
        case DIS_FIELDTYPE_APPLICATION_GENERAL_STATUS:
        case DIS_FIELDTYPE_CATEGORY:
        case DIS_FIELDTYPE_CONTROL_ID:
        case DIS_FIELDTYPE_DETONATION_RESULT:
        case DIS_FIELDTYPE_DOMAIN:
        case DIS_FIELDTYPE_ENTITY_KIND:
        case DIS_FIELDTYPE_FROZEN_BEHAVIOR:
        case DIS_FIELDTYPE_PARAMETER_TYPE_DESIGNATOR:
        case DIS_FIELDTYPE_PDU_TYPE:
        case DIS_FIELDTYPE_PROTOCOL_FAMILY:
        case DIS_FIELDTYPE_PROTOCOL_VERSION:
        case DIS_FIELDTYPE_REASON:
        case DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE:
        case DIS_FIELDTYPE_PERSISTENT_OBJECT_CLASS:
        case DIS_FIELDTYPE_PERSISTENT_OBJECT_TYPE:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;

        /* enumerations (2-bytes) */
        case DIS_FIELDTYPE_ACKNOWLEDGE_FLAG:
        case DIS_FIELDTYPE_APPLICATION_STATUS_TYPE:
        case DIS_FIELDTYPE_APPLICATION_TYPE:
        case DIS_FIELDTYPE_RESPONSE_FLAG:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;

        /* enumerations (4-bytes) */
        case DIS_FIELDTYPE_ACTION_ID:
        case DIS_FIELDTYPE_REQUEST_STATUS:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;

        /* other atomic types */
        case DIS_FIELDTYPE_APPEARANCE:
            {
                proto_item *newSubtree;
                newField = proto_tree_add_text(tree, tvb, offset, 4, "%s",
                    parserNodes[fieldIndex].fieldLabel);
                newSubtree = proto_item_add_subtree(newField,
                    parserNodes[fieldIndex].ettVar);
                offset = parseField_Bitmask(tvb, newSubtree, offset,
                    parserNodes[fieldIndex], 4);
            }
            break;
        case DIS_FIELDTYPE_ARTIC_PARAM_TYPE:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_CAPABILITIES:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_COUNTRY:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;
        case DIS_FIELDTYPE_DATUM_ID:
        case DIS_FIELDTYPE_DATUM_LENGTH:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_DEAD_RECKONING_PARAMS:
            /* This is really a struct... needs a field parser.
             * For now, just skip the 12 bytes.
             */
            offset = parseField_Bytes(tvb, tree, offset,
                parserNodes[fieldIndex], 40);
            break;
        case DIS_FIELDTYPE_ENTITY_MARKING:
            /* This is really a struct... needs a field parser.
             * For now, just skip the 12 bytes.
             */
            offset = parseField_Bytes(tvb, tree, offset,
                parserNodes[fieldIndex], 12);
            break;
        case DIS_FIELDTYPE_EXTRA:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_FIXED_DATUM_VALUE:
            offset = parseField_Bytes(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_FIXED_LEN_STR:
            offset = parseField_Bytes(tvb, tree, offset,
                parserNodes[fieldIndex],
                parserNodes[fieldIndex].fieldRepeatLen);
            break;
        case DIS_FIELDTYPE_FORCE_ID:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_FUSE:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;
        case DIS_FIELDTYPE_NUM_FIXED_DATA:
        case DIS_FIELDTYPE_NUM_VARIABLE_DATA:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_REQUEST_ID:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_SPECIFIC:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_SUBCATEGORY:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_TIME_INTERVAL:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_TIMESTAMP:
            offset = parseField_Timestamp(tvb, tree, offset,
                parserNodes[fieldIndex]);
            break;
        case DIS_FIELDTYPE_WARHEAD:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;

        /* composite types */
        case DIS_FIELDTYPE_BURST_DESCRIPTOR:
        case DIS_FIELDTYPE_CLOCK_TIME:
        case DIS_FIELDTYPE_ENTITY_ID:
        case DIS_FIELDTYPE_ENTITY_TYPE:
        case DIS_FIELDTYPE_EVENT_ID:
        case DIS_FIELDTYPE_LINEAR_VELOCITY:
        case DIS_FIELDTYPE_LOCATION_ENTITY:
        case DIS_FIELDTYPE_LOCATION_WORLD:
        case DIS_FIELDTYPE_ORIENTATION:
        case DIS_FIELDTYPE_SIMULATION_ADDRESS:
        case DIS_FIELDTYPE_VECTOR_32:
        case DIS_FIELDTYPE_VECTOR_64:
            newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                parserNodes[fieldIndex].fieldLabel);
            if (parserNodes[fieldIndex].children != 0)
            {
                proto_item *newSubtree = proto_item_add_subtree(newField,
                    parserNodes[fieldIndex].ettVar);
                offset = parseFields(tvb, newSubtree, offset,
                    parserNodes[fieldIndex].children);
            }
            proto_item_set_end(newField, tvb, offset);
            break;
        case DIS_FIELDTYPE_VARIABLE_DATUM_VALUE:
            {
                guint lengthInBytes;
                lengthInBytes = variableDatumLength / 8;
                if (variableDatumLength % 8 > 0)
                {
                    lengthInBytes += (8 - (variableDatumLength % 8));
                }
                offset = parseField_Bytes(tvb, tree, offset,
                    parserNodes[fieldIndex], lengthInBytes);
            }
            break;

        /* arrays */
        case DIS_FIELDTYPE_FIXED_DATUMS:
            {
                guint i;
                if (numFixed > INT32_MAX)
                {
                    numFixed = INT32_MAX;
                }

                for (i = 0; i < numFixed; ++i)
                {
                    proto_item *newSubtree;
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                        parserNodes[fieldIndex].fieldLabel);
                    newSubtree = proto_item_add_subtree(newField, ettFixedData);
                    offset = parseFields
                        (tvb, newSubtree, offset,
                         parserNodes[fieldIndex].children);
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        case DIS_FIELDTYPE_FIXED_DATUM_IDS:
            if (numFixed > 0)
            {
                guint       i;
                proto_item *newSubtree;

                newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                    parserNodes[fieldIndex].fieldLabel);
                newSubtree = proto_item_add_subtree(newField, ettFixedData);

                if (numFixed > INT32_MAX)
                {
                    numFixed = INT32_MAX;
                }

                for (i = 0; i < numFixed; ++i)
                {
                    offset = parseFields
                        (tvb, newSubtree, offset,
                         parserNodes[fieldIndex].children);
                }
                proto_item_set_end(newField, tvb, offset);
            }
            break;
        case DIS_FIELDTYPE_VARIABLE_DATUMS:
            {
                guint i;
                if (numVariable > INT32_MAX)
                {
                    numVariable = INT32_MAX;
                }

                for (i = 0; i < numVariable; ++i)
                {
                    proto_item *newSubtree;
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                        parserNodes[fieldIndex].fieldLabel);
                    newSubtree = proto_item_add_subtree
                        (newField, ettVariableData);
                    offset = parseFields
                        (tvb, newSubtree, offset,
                         parserNodes[fieldIndex].children);
                    proto_item_set_end(newField, tvb, offset);
                }

            }
            break;
        case DIS_FIELDTYPE_VARIABLE_DATUM_IDS:
            if (numVariable > 0)
            {
                guint       i;
                proto_item *newSubtree;

                newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                    parserNodes[fieldIndex].fieldLabel);
                newSubtree = proto_item_add_subtree(newField, ettVariableData);

                if (numVariable > INT32_MAX)
                {
                    numVariable = INT32_MAX;
                }

                for (i = 0; i < numVariable; ++i)
                {
                    offset = parseFields
                        (tvb, newSubtree, offset,
                         parserNodes[fieldIndex].children);
                }
                proto_item_set_end(newField, tvb, offset);
            }
            break;
        case DIS_FIELDTYPE_VARIABLE_PARAMETERS:
            {
                guint i;

                if (numVariable > DIS_PDU_MAX_VARIABLE_PARAMETERS)
                {
                    numVariable = DIS_PDU_MAX_VARIABLE_PARAMETERS;
                }

                for (i = 0; i < numVariable; ++i)
                {
                    proto_item *newSubtree;
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                        parserNodes[fieldIndex].fieldLabel);
                    newSubtree = proto_item_add_subtree(newField,
                        ettVariableParameters[i]);
                    offset = parseFields
                        (tvb, newSubtree, offset,
                         parserNodes[fieldIndex].children);
                    offset = parseField_VariableParameter
                        (tvb, newSubtree, offset);
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        case DIS_FIELDTYPE_VARIABLE_RECORDS:
            {
                guint i;

                if (numVariable > DIS_PDU_MAX_VARIABLE_RECORDS)
                {
                    numVariable = DIS_PDU_MAX_VARIABLE_RECORDS;
                }

                for (i = 0; i < numVariable; ++i)
                {
                    proto_item *newSubtree;
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                        parserNodes[fieldIndex].fieldLabel);
                    newSubtree = proto_item_add_subtree(newField,
                        ettVariableRecords[i]);
                    offset = parseFields
                        (tvb, newSubtree, offset,
                         parserNodes[fieldIndex].children);
                    offset = parseField_VariableRecord
                        (tvb, newSubtree, offset);
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        default:
            break;
        }
        
        ++fieldIndex;
    }

    return offset;
}
