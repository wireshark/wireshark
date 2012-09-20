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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include "packet-dis-pdus.h"
#include "packet-dis-fields.h"
#include "packet-dis-enums.h"

#define DIS_PDU_MAX_VARIABLE_PARAMETERS 16
#define DIS_PDU_MAX_VARIABLE_RECORDS 16
#define DIS_PDU_MAX_ELECTROMAGNETIC_EMISSION_SYSTEMS 16


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
    { DIS_FIELDTYPE_NUM_ARTICULATION_PARAMS, "Number of Articulation Parameters",0,0,0,&numVariable },
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

/* DIS Distributed Emission Regeneration PDUs
 */
DIS_ParserNode DIS_PARSER_ELECTROMAGNETIC_EMISSION_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Emitting Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Event ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "State Update Indicator",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_ELECTROMAGNETIC_EMISSION_SYSTEMS, "Number of Systems (N)",0,0,0,&numVariable },
    { DIS_FIELDTYPE_PAD16,                   "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM, "Emission System",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};


/* DIS Radio Communications protocol (RCP) family PDUs
 */
DIS_ParserNode DIS_PARSER_TRANSMITTER_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,                    "Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_RADIO_ID,                     "Radio ID",0,0,0,&radioID },
    { DIS_FIELDTYPE_RADIO_ENTITY_TYPE,            "Radio Entity Type",0,0,0,0 },
    { DIS_FIELDTYPE_RADIO_TRANSMIT_STATE,         "Radio Transmit State",0,0,0,&disRadioTransmitState },
    { DIS_FIELDTYPE_RADIO_INPUT_SOURCE,           "Radio Input Source",0,0,0,0 },
    { DIS_FIELDTYPE_PAD16,                        "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_ANTENNA_LOCATION,             "Antenna Location",0,0,0,0 },
    { DIS_FIELDTYPE_REL_ANTENNA_LOCATON,          "Relative Antenna Location",0,0,0,0 },
    { DIS_FIELDTYPE_ANTENNA_PATTERN_TYPE,         "Antenna Pattern Type",0,0,0,&disAntennaPattern },
    { DIS_FIELDTYPE_ANTENNA_PATTERN_LENGTH,       "Antenna Pattern Length",0,0,0,0 },
    { DIS_FIELDTYPE_TRANSMIT_FREQUENCY,           "Transmit Frequency",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,                      "Transmit Frequency Bandwidth",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,                      "Transmit Power",0,0,0,0 },
    { DIS_FIELDTYPE_MODULATION_TYPE,              "Modulation Type",0,0,0,0 },
    { DIS_FIELDTYPE_CRYPTO_SYSTEM,                "Crypto System",0,0,0,0 },
    { DIS_FIELDTYPE_CRYPTO_KEY_ID,                "Crypto Key ID",0,0,0,0 },
    { DIS_FIELDTYPE_MODULATION_PARAMETER_LENGTH,  "Modulation Parameter Length",0,0,0,&modulationParamLength },
    { DIS_FIELDTYPE_PAD24,                        "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_MODULATION_PARAMETERS,        "Modulation Parameters",0,0,0,0 },
    /* need to finish decoding this PDU */
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_PARSER_SIGNAL_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_RADIO_ID,                "Radio ID",0,0,0,&radioID },
    { DIS_FIELDTYPE_ENCODING_SCHEME,         "Encoding Scheme",0,0,0,&encodingScheme },
    { DIS_FIELDTYPE_TDL_TYPE,                "TDL Type",0,0,0,0 },
    { DIS_FIELDTYPE_SAMPLE_RATE,             "Sample Rate",0,0,0,0 },
    { DIS_FIELDTYPE_DATA_LENGTH,             "Data Length",0,0,0,0 },
    { DIS_FIELDTYPE_NUMBER_OF_SAMPLES,       "Number of Samples",0,0,0,&numSamples },
    { DIS_FIELDTYPE_RADIO_DATA,              "Radio Data",0,0,0,0 },
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
    { DIS_FIELDTYPE_NUM_ARTICULATION_PARAMS, "Number of Articulation Parameters",0,0,0,&numVariable },
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

    /* DIS Distributed Emission Regeneration PDUs */
    initializeParser(DIS_PARSER_ELECTROMAGNETIC_EMISSION_PDU);

    /* DIS Radio Communications protocol (RCP) family PDUs */
    initializeParser(DIS_PARSER_TRANSMITTER_PDU);
    initializeParser(DIS_PARSER_SIGNAL_PDU);

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
        case DIS_FIELDTYPE_MOD_PARAMS_CCTT_SINCGARS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_MOD_PARAMS_CCTT_SINCGARS,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_MOD_PARAMS_JTIDS_MIDS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_MOD_PARAMS_JTIDS_MIDS,
                &parserNodes[parserIndex].ettVar);
            break;

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
        case DIS_FIELDTYPE_RADIO_ENTITY_TYPE:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_RADIO_ENTITY_TYPE,
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
        case DIS_FIELDTYPE_REL_ANTENNA_LOCATON:
        case DIS_FIELDTYPE_VECTOR_32:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VECTOR_FLOAT_32,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_LOCATION_WORLD:
        case DIS_FIELDTYPE_ANTENNA_LOCATION:
        case DIS_FIELDTYPE_VECTOR_64:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VECTOR_FLOAT_64,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_MODULATION_TYPE:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_MODULATION_TYPE,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_EMITTER_SYSTEM:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_EMITTER_SYSTEM,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_FUNDAMENTAL_PARAMETER_DATA:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_FUNDAMENTAL_PARAMETER_DATA,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_TRACK_JAM:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_TRACK_JAM,
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
    guint        fieldIndex     = 0;
    guint        fieldRepeatLen = 0;
    guint64      uintVal        = 0;
    proto_item  *pi             = NULL;
    proto_tree  *sub_tree       = NULL;
    tvbuff_t    *newtvb         = NULL;
    gint         length         = 0;
    guint16 spread_spectrum     = 0;


    length = tvb_length_remaining(tvb, offset);

    while ((parserNodes[fieldIndex].fieldType != DIS_FIELDTYPE_END)
            && (length > 0 ) )
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
        case DIS_FIELDTYPE_EXERCISE_ID:
            proto_tree_add_item(tree, hf_dis_exercise_id, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_NUM_ARTICULATION_PARAMS:
            uintVal = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dis_num_art_params, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            break;
        case DIS_FIELDTYPE_PDU_LENGTH:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_pdu_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_SITE:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_entity_id_site, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_APPLICATION:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_entity_id_application, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_ENTITY:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_entity_id_entity, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_RADIO_ID:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_radio_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 2;
            break;
        case DIS_FIELDTYPE_ENCODING_SCHEME:
            uintVal = tvb_get_ntohs(tvb, offset);
            pi = proto_tree_add_item(tree, hf_dis_ens, tvb, offset, 2, ENC_BIG_ENDIAN);
            sub_tree = proto_item_add_subtree(pi, ett_dis_ens);
            proto_tree_add_item(sub_tree, hf_dis_ens_class, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_dis_ens_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_set_end(pi, tvb, offset);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 2;
            break;
        case DIS_FIELDTYPE_TDL_TYPE:
            proto_tree_add_item(tree, hf_dis_tdl_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_SAMPLE_RATE:
            proto_tree_add_item(tree, hf_dis_sample_rate, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case DIS_FIELDTYPE_DATA_LENGTH:
            proto_tree_add_item(tree, hf_dis_data_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_NUMBER_OF_SAMPLES:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_num_of_samples, tvb, offset, 2, ENC_BIG_ENDIAN);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 2;
            break;

        case DIS_FIELDTYPE_RADIO_DATA:
            newtvb = tvb_new_subset(tvb, offset,
                                    tvb_length_remaining(tvb, offset),
                                    tvb_reported_length_remaining(tvb, offset)
                );
            proto_tree_add_item(tree, hf_dis_signal_data, newtvb, 0, -1, ENC_NA );
            /* ****ck******* need to look for padding bytes */
            break;
        case DIS_FIELDTYPE_RADIO_CATEGORY:
            proto_tree_add_item(tree, hf_dis_radio_category, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_NOMENCLATURE_VERSION:
            proto_tree_add_item(tree, hf_dis_nomenclature_version, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_NOMENCLATURE:
            proto_tree_add_item(tree, hf_dis_nomenclature, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_RADIO_TRANSMIT_STATE:
            uintVal = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dis_radio_transmit_state, tvb, offset, 1, ENC_BIG_ENDIAN);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 1;
            break;
        case DIS_FIELDTYPE_RADIO_INPUT_SOURCE:
            proto_tree_add_item(tree, hf_dis_radio_input_source, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case  DIS_FIELDTYPE_ANTENNA_PATTERN_TYPE:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_antenna_pattern_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 2;
            break;
        case DIS_FIELDTYPE_ANTENNA_PATTERN_LENGTH:
            proto_tree_add_item(tree, hf_dis_antenna_pattern_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
         case DIS_FIELDTYPE_TRANSMIT_FREQUENCY:
            proto_tree_add_item(tree, hf_dis_transmit_frequency, tvb, offset, 8, ENC_BIG_ENDIAN);
            offset += 8;
            break;
        case  DIS_FIELDTYPE_SPREAD_SPECTRUM:
            spread_spectrum = tvb_get_ntohs(tvb, offset);
            proto_tree_add_boolean(tree, hf_dis_spread_spectrum_usage, tvb, offset,  2, spread_spectrum);
            proto_tree_add_boolean(tree, hf_dis_frequency_hopping, tvb, offset,  2, spread_spectrum);
            proto_tree_add_boolean(tree, hf_dis_pseudo_noise_modulation, tvb, offset,  2, spread_spectrum);
            proto_tree_add_boolean(tree, hf_dis_time_hopping, tvb, offset,  2, spread_spectrum);
            offset += 2;
            break;
        case DIS_FIELDTYPE_MODULATION_MAJOR:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_modulation_major, tvb, offset, 2, ENC_BIG_ENDIAN);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 2;
            break;
        case DIS_FIELDTYPE_MODULATION_SYSTEM:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_modulation_system, tvb, offset, 2, ENC_BIG_ENDIAN);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 2;
            break;
        case DIS_FIELDTYPE_CRYPTO_SYSTEM:
            proto_tree_add_item(tree, hf_dis_crypto_system, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_CRYPTO_KEY_ID:
            pi = proto_tree_add_item(tree, hf_dis_crypto_key, tvb, offset, 2, ENC_BIG_ENDIAN);
            sub_tree = proto_item_add_subtree(pi, ett_dis_crypto_key);
            proto_tree_add_item(sub_tree, hf_dis_encryption_mode, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item(sub_tree, hf_dis_key_identifier, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_set_end(pi, tvb, offset);
            offset += 2;
            break;
        case DIS_FIELDTYPE_MODULATION_PARAMETER_LENGTH:
            uintVal = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dis_modulation_parameter_length, tvb, offset, 1, ENC_BIG_ENDIAN);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 1;
            break;
        case DIS_FIELDTYPE_FH_NETWORK_ID:
            proto_tree_add_item(tree, hf_dis_mod_param_fh_net_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_FH_SET_ID:
            proto_tree_add_item(tree, hf_dis_mod_param_fh_set_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_LO_SET_ID:
            proto_tree_add_item(tree, hf_dis_mod_param_fh_lo_set_id, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_FH_MSG_START:
            proto_tree_add_item(tree, hf_dis_mod_param_fh_msg_start, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_RESERVED:
            proto_tree_add_item(tree, hf_dis_mod_param_fh_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_FH_SYNC_TIME_OFFSET:
            proto_tree_add_item(tree, hf_dis_mod_param_fh_sync_time_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case DIS_FIELDTYPE_FH_SECURITY_KEY:
            proto_tree_add_item(tree, hf_dis_mod_param_fh_security_key, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_FH_CLEAR_CHANNEL:
            proto_tree_add_item(tree, hf_dis_mod_param_fh_clear_channel, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_TS_ALLOCATION_MODE:
            proto_tree_add_item(tree, hf_dis_mod_param_ts_allocation_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_TRANSMITTER_PRIMARY_MODE:
            proto_tree_add_item(tree, hf_dis_mod_param_transmitter_prim_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_TRANSMITTER_SECONDARY_MODE:
            proto_tree_add_item(tree, hf_dis_mod_param_transmitter_second_mode, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_JTIDS_SYNC_STATE:
            proto_tree_add_item(tree, hf_dis_mod_param_sync_state, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            break;
        case DIS_FIELDTYPE_NETWORK_SYNC_ID:
            proto_tree_add_item(tree, hf_dis_mod_param_network_sync_id, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;
            break;
        case DIS_FIELDTYPE_MODULATION_PARAMETERS:
            /* need to check to see if mod parms length > 0 */
            /* could get here when there are antenna pattern parameter but no mod params */
            if (modulationParamLength > 0 ) { /* we do have a mod param */
                if (systemModulation == DIS_SYSTEM_MOD_CCTT_SINCGARS)
                {
                    pi = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                                             parserNodes[fieldIndex].fieldLabel);
                    sub_tree = proto_item_add_subtree(pi, parserNodes[fieldIndex].ettVar);
                    offset = parseFields(tvb, sub_tree, offset, DIS_FIELDS_MOD_PARAMS_CCTT_SINCGARS);
                    proto_item_set_end(pi, tvb, offset);
                    break;
                }
                else if (systemModulation == DIS_SYSTEM_MOD_JTIDS_MIDS) {
                    pi = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                                             parserNodes[fieldIndex].fieldLabel);
                    sub_tree = proto_item_add_subtree(pi, parserNodes[fieldIndex].ettVar);
                    offset = parseFields(tvb, sub_tree, offset, DIS_FIELDS_MOD_PARAMS_JTIDS_MIDS);
                    proto_item_set_end(pi, tvb, offset);
                    break;
                }
                else {  /* just dump what is available */
                    newtvb = tvb_new_subset(tvb, offset,modulationParamLength, modulationParamLength);
                    proto_tree_add_item(tree, hf_dis_mod_param_dump, newtvb, 0, -1, ENC_NA );
                    offset += modulationParamLength;
                    break;
                }
            } /* else, leave offset alone, and then check antenna pattern param field */
            break;
        case DIS_FIELDTYPE_ANTENNA_PATTERN_PARAMETERS:
            /* just dump the bytes for now.  Need to do finish */
            newtvb = tvb_new_subset(tvb, offset,
                                    tvb_length_remaining(tvb, offset),
                                    tvb_reported_length_remaining(tvb, offset)
                );
            proto_tree_add_item(tree, hf_dis_antenna_pattern_parameter_dump, newtvb, 0, -1, ENC_NA );
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
        case DIS_FIELDTYPE_PAD24:
            offset = parseField_Pad(tvb, tree, offset,
                parserNodes[fieldIndex], 3 * fieldRepeatLen);
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
        case DIS_FIELDTYPE_EMISSION_FUNCTION:
        case DIS_FIELDTYPE_BEAM_FUNCTION:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;

        /* enumerations (2-bytes) */
        case DIS_FIELDTYPE_ACKNOWLEDGE_FLAG:
        case DIS_FIELDTYPE_APPLICATION_STATUS_TYPE:
        case DIS_FIELDTYPE_APPLICATION_TYPE:
        case DIS_FIELDTYPE_RESPONSE_FLAG:
        case DIS_FIELDTYPE_MODULATION_DETAIL:
        case DIS_FIELDTYPE_EMITTER_NAME:
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
        case DIS_FIELDTYPE_RADIO_ENTITY_TYPE:
        case DIS_FIELDTYPE_ANTENNA_LOCATION:
        case DIS_FIELDTYPE_REL_ANTENNA_LOCATON:
        case DIS_FIELDTYPE_EVENT_ID:
        case DIS_FIELDTYPE_LINEAR_VELOCITY:
        case DIS_FIELDTYPE_LOCATION_ENTITY:
        case DIS_FIELDTYPE_LOCATION_WORLD:
        case DIS_FIELDTYPE_ORIENTATION:
        case DIS_FIELDTYPE_SIMULATION_ADDRESS:
        case DIS_FIELDTYPE_VECTOR_32:
        case DIS_FIELDTYPE_VECTOR_64:
        case DIS_FIELDTYPE_MODULATION_TYPE:
        case DIS_FIELDTYPE_EMITTER_SYSTEM:
        case DIS_FIELDTYPE_FUNDAMENTAL_PARAMETER_DATA:
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
                    /* is remaining length large enough for another fixed datum (ID & value) */
                    length = tvb_length_remaining(tvb, offset);
                    if ( length >= 8  )
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
                    else {
                        THROW(ReportedBoundsError);
                        break;
                    }
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
                    /* is remaining length large enough for another fixed datum ID (32 bit int) */
                    if (tvb_length_remaining(tvb, offset) >= 4  )
                    {
                       offset = parseFields
                           (tvb, newSubtree, offset,
                            parserNodes[fieldIndex].children);
                    }
                    else {
                        THROW(ReportedBoundsError);
                        break;
                    }
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
                    /* simple check to detect malformed, field parsers will detect specifics */
                    length = tvb_length_remaining(tvb, offset);
                    if ( length > 0  )
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
                    else {
                        THROW(ReportedBoundsError);
                        break;
                    }
                }
            }
            break;
        case DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM:
            {
                guint i;

                for (i = 0; i < numBeams; ++i)
                {
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                        parserNodes[fieldIndex].fieldLabel);
                    if (parserNodes[fieldIndex].children != 0)
                    {
                        proto_item *newSubtree =
                            proto_item_add_subtree(newField,
                            parserNodes[fieldIndex].ettVar);
                        offset = parseFields(tvb, newSubtree, offset,
                            parserNodes[fieldIndex].children);
                    }
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        case DIS_FIELDTYPE_TRACK_JAM:
            {
                guint i;

                for (i = 0; i < numTrackJamTargets; ++i)
                {
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                        parserNodes[fieldIndex].fieldLabel);
                    if (parserNodes[fieldIndex].children != 0)
                    {
                        proto_item *newSubtree =
                            proto_item_add_subtree(newField,
                            parserNodes[fieldIndex].ettVar);
                        offset = parseFields(tvb, newSubtree, offset,
                            parserNodes[fieldIndex].children);
                    }
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        case DIS_FIELDTYPE_NUM_ELECTROMAGNETIC_EMISSION_SYSTEMS:
            uintVal = tvb_get_guint8(tvb, offset);
            proto_tree_add_item(tree, hf_dis_num_electromagnetic_emission_systems, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            break;
        case DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM:
            {
                guint i;

                if (numVariable > DIS_PDU_MAX_ELECTROMAGNETIC_EMISSION_SYSTEMS)
                {
                    numVariable = DIS_PDU_MAX_ELECTROMAGNETIC_EMISSION_SYSTEMS;
                }

                for (i = 0; i < numVariable; ++i)
                {
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                        parserNodes[fieldIndex].fieldLabel);
                    if (parserNodes[fieldIndex].children != 0)
                    {
                        proto_item *newSubtree =
                            proto_item_add_subtree(newField,
                            parserNodes[fieldIndex].ettVar);
                        offset = parseFields(tvb, newSubtree, offset,
                            parserNodes[fieldIndex].children);
                    }
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        default:
            break;
        }

        ++fieldIndex;
        length = tvb_length_remaining(tvb, offset);
    }

    return offset;
}
