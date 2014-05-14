/* packet-dis.c
 * Routines for Distributed Interactive Simulation packet
 * disassembly (IEEE-1278).
 * Copyright 2005, Scientific Research Corporation
 * Initial implementation by Jeremy Ouellette <jouellet@scires.com>
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

/* TODO / NOTES:
 * Field handling isn't ideal; this dissector should probably register
 * each individual field via the proto_register_field_array mechanism.
 * This would lead to better PDML output (instead of requiring the end user
 * to manually parse out the key/value pairs) and better searchability in
 * interactive mode.
 *
 * Lots more PDUs to implement.  Only the basic engagement events are currently
 * handled (Fire, Detonation, Entity State).  Most of the basic field types are
 * complete, however, so declaring new PDUs should be fairly simple.
 *
 * Lots more enumerations to implement.
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-link16.h"

#define DEFAULT_DIS_UDP_PORT 3000

/* Encoding type the last 14 bits */
#define DIS_ENCODING_TYPE(word) ((word) & 0x3FFF)

#define DIS_PDU_MAX_VARIABLE_PARAMETERS              16
#define DIS_PDU_MAX_VARIABLE_RECORDS                 16
#define DIS_PDU_MAX_ELECTROMAGNETIC_EMISSION_SYSTEMS 16
#define DIS_PDU_MAX_SHAFTS                           16
#define DIS_PDU_MAX_APAS                             16
#define DIS_PDU_MAX_UA_EMITTER_SYSTEMS               16
#define DIS_PDU_MAX_UA_BEAMS                         32

typedef enum
{
    DIS_VERSION_OTHER             = 0,
    DIS_VERSION_1_0               = 1,
    DIS_VERSION_IEEE_1278_1993    = 2,
    DIS_VERSION_2_0_3RD_DRAFT     = 3,
    DIS_VERSION_2_0_4TH_DRAFT     = 4,
    DIS_VERSION_IEEE_1278_1_1995  = 5,
    DIS_VERSION_IEEE_1278_1A_1998 = 6,
    DIS_VERSION_IEEE_1278_1_2012  = 7
} DIS_PDU_ProtocolVersion;

static const value_string DIS_PDU_ProtocolVersion_Strings[] =
{
    { DIS_VERSION_OTHER,             "Other" },
    { DIS_VERSION_1_0,               "DIS PDU version 1.0 (May 92)" },
    { DIS_VERSION_IEEE_1278_1993,    "IEEE 1278-1993" },
    { DIS_VERSION_2_0_3RD_DRAFT,     "DIS PDU version 2.0 - third draft (May 93)" },
    { DIS_VERSION_2_0_4TH_DRAFT,     "DIS PDU version 2.0 - fourth draft (revised) March 16, 1994" },
    { DIS_VERSION_IEEE_1278_1_1995,  "IEEE 1278.1-1995" },
    { DIS_VERSION_IEEE_1278_1A_1998, "IEEE 1278.1A-1998" },
    { DIS_VERSION_IEEE_1278_1_2012,  "IEEE 1278.1-2012" },
    { 0,                             NULL }
};

typedef enum
{
    DIS_PROTOCOLFAMILY_OTHER                                  = 0,
    DIS_PROTOCOLFAMILY_ENTITY_INFORMATION_INTERACTION         = 1,
    DIS_PROTOCOLFAMILY_WARFARE                                = 2,
    DIS_PROTOCOLFAMILY_LOGISTICS                              = 3,
    DIS_PROTOCOLFAMILY_RADIO_COMMUNICATIONS                   = 4,
    DIS_PROTOCOLFAMILY_SIMULATION_MANAGEMENT                  = 5,
    DIS_PROTOCOLFAMILY_DISTRIBUTED_EMISSION_REGENERATION      = 6,
    DIS_PROTOCOLFAMILY_ENTITY_MANAGEMENT                      = 7,
    DIS_PROTOCOLFAMILY_MINEFIELD                              = 8,
    DIS_PROTOCOLFAMILY_SYNTHETIC_ENVIRONMENT                  = 9,
    DIS_PROTOCOLFAMILY_SIMULATION_MANAGEMENT_WITH_RELIABILITY = 10,
    DIS_PROTOCOLFAMILY_LIVE_ENTITY                            = 11,
    DIS_PROTOCOLFAMILY_NON_REAL_TIME                          = 12,
    DIS_PROTOCOLFAMILY_INFORMATION_OPERATIONS                 = 13,
    DIS_PROTOCOLFAMILY_EXPERIMENTAL_COMPUTER_GENERATED_FORCES = 129,
    DIS_PROTOCOLFAMILY_EXPERIMENTAL_VDIS                      = 130,
    DIS_PROTOCOLFAMILY_PERSISTENT_OBJECT                      = 140,
    DIS_PROTOCOLFAMILY_EXPERIMENTAL                           = 150
} DIS_PDU_ProtocolFamily;

static const value_string DIS_PDU_ProtocolFamily_Strings[] =
{
    { DIS_PROTOCOLFAMILY_OTHER,                                  "Other" },
    { DIS_PROTOCOLFAMILY_ENTITY_INFORMATION_INTERACTION,         "Entity information / interaction" },
    { DIS_PROTOCOLFAMILY_WARFARE,                                "Warfare" },
    { DIS_PROTOCOLFAMILY_LOGISTICS,                              "Logistics" },
    { DIS_PROTOCOLFAMILY_RADIO_COMMUNICATIONS,                   "Radio communications" },
    { DIS_PROTOCOLFAMILY_SIMULATION_MANAGEMENT,                  "Simulation management" },
    { DIS_PROTOCOLFAMILY_DISTRIBUTED_EMISSION_REGENERATION,      "Distributed emission regeneration" },
    { DIS_PROTOCOLFAMILY_ENTITY_MANAGEMENT,                      "Entity management" },
    { DIS_PROTOCOLFAMILY_MINEFIELD,                              "Minefield" },
    { DIS_PROTOCOLFAMILY_SYNTHETIC_ENVIRONMENT,                  "Synthetic environment" },
    { DIS_PROTOCOLFAMILY_SIMULATION_MANAGEMENT_WITH_RELIABILITY, "Simulation management with reliability" },
    { DIS_PROTOCOLFAMILY_LIVE_ENTITY,                            "Live entity" },
    { DIS_PROTOCOLFAMILY_NON_REAL_TIME,                          "Non-real time" },
    { DIS_PROTOCOLFAMILY_INFORMATION_OPERATIONS,                 "Information Operations" },
    { DIS_PROTOCOLFAMILY_EXPERIMENTAL_COMPUTER_GENERATED_FORCES, "Experimental - Computer Generated Forces" },
    { DIS_PROTOCOLFAMILY_EXPERIMENTAL_VDIS,                      "Experimental - V-DIS" },
    { DIS_PROTOCOLFAMILY_PERSISTENT_OBJECT,                      "Persistent object" },
    { DIS_PROTOCOLFAMILY_EXPERIMENTAL,                           "Experimental" },
    { 0,                                                         NULL }
};

typedef enum
{
    DIS_PDUTYPE_OTHER                              = 0,
    DIS_PDUTYPE_ENTITY_STATE                       = 1,
    DIS_PDUTYPE_FIRE                               = 2,
    DIS_PDUTYPE_DETONATION                         = 3,
    DIS_PDUTYPE_COLLISION                          = 4,
    DIS_PDUTYPE_SERVICE_REQUEST                    = 5,
    DIS_PDUTYPE_RESUPPLY_OFFER                     = 6,
    DIS_PDUTYPE_RESUPPLY_RECEIVED                  = 7,
    DIS_PDUTYPE_RESUPPLY_CANCEL                    = 8,
    DIS_PDUTYPE_REPAIR_COMPLETE                    = 9,
    DIS_PDUTYPE_REPAIR_RESPONSE                    = 10,
    DIS_PDUTYPE_CREATE_ENTITY                      = 11,
    DIS_PDUTYPE_REMOVE_ENTITY                      = 12,
    DIS_PDUTYPE_START_RESUME                       = 13,
    DIS_PDUTYPE_STOP_FREEZE                        = 14,
    DIS_PDUTYPE_ACKNOWLEDGE                        = 15,
    DIS_PDUTYPE_ACTION_REQUEST                     = 16,
    DIS_PDUTYPE_ACTION_RESPONSE                    = 17,
    DIS_PDUTYPE_DATA_QUERY                         = 18,
    DIS_PDUTYPE_SET_DATA                           = 19,
    DIS_PDUTYPE_DATA                               = 20,
    DIS_PDUTYPE_EVENT_REPORT                       = 21,
    DIS_PDUTYPE_COMMENT                            = 22,
    DIS_PDUTYPE_ELECTROMAGNETIC_EMISSION           = 23,
    DIS_PDUTYPE_DESIGNATOR                         = 24,
    DIS_PDUTYPE_TRANSMITTER                        = 25,
    DIS_PDUTYPE_SIGNAL                             = 26,
    DIS_PDUTYPE_RECEIVER                           = 27,
    DIS_PDUTYPE_IFF                                = 28,
    DIS_PDUTYPE_UNDERWATER_ACOUSTIC                = 29,
    DIS_PDUTYPE_SUPPLEMENTAL_EMISSION_ENTITY_STATE = 30,
    DIS_PDUTYPE_INTERCOM_SIGNAL                    = 31,
    DIS_PDUTYPE_INTERCOM_CONTROL                   = 32,
    DIS_PDUTYPE_AGGREGATE_STATE                    = 33,
    DIS_PDUTYPE_IS_GROUP_OF                        = 34,
    DIS_PDUTYPE_TRANSFER_OWNERSHIP                 = 35,
    DIS_PDUTYPE_IS_PART_OF                         = 36,
    DIS_PDUTYPE_MINEFIELD_STATE                    = 37,
    DIS_PDUTYPE_MINEFIELD_QUERY                    = 38,
    DIS_PDUTYPE_MINEFIELD_DATA                     = 39,
    DIS_PDUTYPE_MINEFIELD_RESPONSE_NACK            = 40,
    DIS_PDUTYPE_ENVIRONMENTAL_PROCESS              = 41,
    DIS_PDUTYPE_GRIDDED_DATA                       = 42,
    DIS_PDUTYPE_POINT_OBJECT_STATE                 = 43,
    DIS_PDUTYPE_LINEAR_OBJECT_STATE                = 44,
    DIS_PDUTYPE_AREAL_OBJECT_STATE                 = 45,
    DIS_PDUTYPE_TSPI                               = 46,
    DIS_PDUTYPE_APPEARANCE                         = 47,
    DIS_PDUTYPE_ARTICULATED_PARTS                  = 48,
    DIS_PDUTYPE_LE_FIRE                            = 49,
    DIS_PDUTYPE_LE_DETONATION                      = 50,
    DIS_PDUTYPE_CREATE_ENTITY_R                    = 51,
    DIS_PDUTYPE_REMOVE_ENTITY_R                    = 52,
    DIS_PDUTYPE_START_RESUME_R                     = 53,
    DIS_PDUTYPE_STOP_FREEZE_R                      = 54,
    DIS_PDUTYPE_ACKNOWLEDGE_R                      = 55,
    DIS_PDUTYPE_ACTION_REQUEST_R                   = 56,
    DIS_PDUTYPE_ACTION_RESPONSE_R                  = 57,
    DIS_PDUTYPE_DATA_QUERY_R                       = 58,
    DIS_PDUTYPE_SET_DATA_R                         = 59,
    DIS_PDUTYPE_DATA_R                             = 60,
    DIS_PDUTYPE_EVENT_REPORT_R                     = 61,
    DIS_PDUTYPE_COMMENT_R                          = 62,
    DIS_PDUTYPE_RECORD_R                           = 63,
    DIS_PDUTYPE_SET_RECORD_R                       = 64,
    DIS_PDUTYPE_RECORD_QUERY_R                     = 65,
    DIS_PDUTYPE_COLLISION_ELASTIC                  = 66,
    DIS_PDUTYPE_ENTITY_STATE_UPDATE                = 67,
    DIS_PDUTYPE_DIRECTED_ENERGY_FIRE               = 68,
    DIS_PDUTYPE_ENTITY_DAMAGE_STATUS               = 69,
    DIS_PDUTYPE_INFORMATION_OPERATIONS_ACTION      = 70,
    DIS_PDUTYPE_INFORMATION_OPERATIONS_REPORT      = 71,
    DIS_PDUTYPE_ATTRIBUTE                          = 72,
    DIS_PDUTYPE_ANNOUNCE_OBJECT                    = 129,
    DIS_PDUTYPE_DELETE_OBJECT                      = 130,
    DIS_PDUTYPE_DESCRIBE_APPLICATION               = 131,
    DIS_PDUTYPE_DESCRIBE_EVENT                     = 132,
    DIS_PDUTYPE_DESCRIBE_OBJECT                    = 133,
    DIS_PDUTYPE_REQUEST_EVENT                      = 134,
    DIS_PDUTYPE_REQUEST_OBJECT                     = 135,
    DIS_PDUTYPE_APPLICATION_CONTROL                = 200,
    DIS_PDUTYPE_STEALTH_STATE                      = 201
} DIS_PDU_Type;

static const value_string DIS_PDU_Type_Strings[] =
{
    { DIS_PDUTYPE_OTHER,                              "Other" },
    { DIS_PDUTYPE_ENTITY_STATE,                       "Entity State" },
    { DIS_PDUTYPE_FIRE,                               "Fire" },
    { DIS_PDUTYPE_DETONATION,                         "Detonation" },
    { DIS_PDUTYPE_COLLISION,                          "Collision" },
    { DIS_PDUTYPE_SERVICE_REQUEST,                    "Service Request" },
    { DIS_PDUTYPE_RESUPPLY_OFFER,                     "Resupply Offer" },
    { DIS_PDUTYPE_RESUPPLY_RECEIVED,                  "Resupply Received" },
    { DIS_PDUTYPE_RESUPPLY_CANCEL,                    "Resupply Cancel" },
    { DIS_PDUTYPE_REPAIR_COMPLETE,                    "Repair Complete" },
    { DIS_PDUTYPE_REPAIR_RESPONSE,                    "Repair Response" },
    { DIS_PDUTYPE_CREATE_ENTITY,                      "Create Entity" },
    { DIS_PDUTYPE_REMOVE_ENTITY,                      "Remove Entity" },
    { DIS_PDUTYPE_START_RESUME,                       "Start / Resume" },
    { DIS_PDUTYPE_STOP_FREEZE,                        "Stop / Freeze" },
    { DIS_PDUTYPE_ACKNOWLEDGE,                        "Acknowledge" },
    { DIS_PDUTYPE_ACTION_REQUEST,                     "Action Request" },
    { DIS_PDUTYPE_ACTION_RESPONSE,                    "Action Response" },
    { DIS_PDUTYPE_DATA_QUERY,                         "Data Query" },
    { DIS_PDUTYPE_SET_DATA,                           "Set Data" },
    { DIS_PDUTYPE_DATA,                               "Data" },
    { DIS_PDUTYPE_EVENT_REPORT,                       "Event Report" },
    { DIS_PDUTYPE_COMMENT,                            "Comment" },
    { DIS_PDUTYPE_ELECTROMAGNETIC_EMISSION,           "Electromagnetic Emission" },
    { DIS_PDUTYPE_DESIGNATOR,                         "Designator" },
    { DIS_PDUTYPE_TRANSMITTER,                        "Transmitter" },
    { DIS_PDUTYPE_SIGNAL,                             "Signal" },
    { DIS_PDUTYPE_RECEIVER,                           "Receiver" },
    { DIS_PDUTYPE_IFF,                                "IFF" },
    { DIS_PDUTYPE_UNDERWATER_ACOUSTIC,                "Underwater Acoustic" },
    { DIS_PDUTYPE_SUPPLEMENTAL_EMISSION_ENTITY_STATE, "Supplemental Emission Entity State" },
    { DIS_PDUTYPE_INTERCOM_SIGNAL,                    "Intercom Signal" },
    { DIS_PDUTYPE_INTERCOM_CONTROL,                   "Intercom Control" },
    { DIS_PDUTYPE_AGGREGATE_STATE,                    "Aggregate State" },
    { DIS_PDUTYPE_IS_GROUP_OF,                        "IsGroupOf" },
    { DIS_PDUTYPE_TRANSFER_OWNERSHIP,                 "Transfer Ownership" },
    { DIS_PDUTYPE_IS_PART_OF,                         "IsPartOf" },
    { DIS_PDUTYPE_MINEFIELD_STATE,                    "Minefield State" },
    { DIS_PDUTYPE_MINEFIELD_QUERY,                    "Minefield Query" },
    { DIS_PDUTYPE_MINEFIELD_DATA,                     "Minefield Data" },
    { DIS_PDUTYPE_MINEFIELD_RESPONSE_NACK,            "Minefield Response NACK" },
    { DIS_PDUTYPE_ENVIRONMENTAL_PROCESS,              "Environmental Process" },
    { DIS_PDUTYPE_GRIDDED_DATA,                       "Gridded Data" },
    { DIS_PDUTYPE_POINT_OBJECT_STATE,                 "Point Object State" },
    { DIS_PDUTYPE_LINEAR_OBJECT_STATE,                "Linear Object State" },
    { DIS_PDUTYPE_AREAL_OBJECT_STATE,                 "Areal Object State" },
    { DIS_PDUTYPE_TSPI,                               "TSPI" },
    { DIS_PDUTYPE_APPEARANCE,                         "Appearance" },
    { DIS_PDUTYPE_ARTICULATED_PARTS,                  "Articulated Parts" },
    { DIS_PDUTYPE_LE_FIRE,                            "LE Fire" },
    { DIS_PDUTYPE_LE_DETONATION,                      "LE Detonation" },
    { DIS_PDUTYPE_CREATE_ENTITY_R,                    "Create Entity-R" },
    { DIS_PDUTYPE_REMOVE_ENTITY_R,                    "Remove Entity-R" },
    { DIS_PDUTYPE_START_RESUME_R,                     "Start / Resume-R" },
    { DIS_PDUTYPE_STOP_FREEZE_R,                      "Stop / Freeze-R" },
    { DIS_PDUTYPE_ACKNOWLEDGE_R,                      "Acknowledge-R" },
    { DIS_PDUTYPE_ACTION_REQUEST_R,                   "Action Request-R" },
    { DIS_PDUTYPE_ACTION_RESPONSE_R,                  "Action Response-R" },
    { DIS_PDUTYPE_DATA_QUERY_R,                       "Data Query-R" },
    { DIS_PDUTYPE_SET_DATA_R,                         "Set Data-R" },
    { DIS_PDUTYPE_DATA_R,                             "Data-R" },
    { DIS_PDUTYPE_EVENT_REPORT_R,                     "Event Report-R" },
    { DIS_PDUTYPE_COMMENT_R,                          "Comment-R" },
    { DIS_PDUTYPE_RECORD_R,                           "Record-R" },
    { DIS_PDUTYPE_SET_RECORD_R,                       "Set Record-R" },
    { DIS_PDUTYPE_RECORD_QUERY_R,                     "Record Query-R" },
    { DIS_PDUTYPE_COLLISION_ELASTIC,                  "Collision Elastic" },
    { DIS_PDUTYPE_ENTITY_STATE_UPDATE,                "Entity State Update" },
    { DIS_PDUTYPE_DIRECTED_ENERGY_FIRE,               "Directed Energy Fire" },
    { DIS_PDUTYPE_ENTITY_DAMAGE_STATUS,               "Entity Damage Status" },
    { DIS_PDUTYPE_INFORMATION_OPERATIONS_ACTION,      "Info Operations Action" },
    { DIS_PDUTYPE_INFORMATION_OPERATIONS_REPORT,      "Info Operations Report" },
    { DIS_PDUTYPE_ATTRIBUTE,                          "Attribute" },
    { DIS_PDUTYPE_ANNOUNCE_OBJECT,                    "Announce Object" },
    { DIS_PDUTYPE_DELETE_OBJECT,                      "Delete Object" },
    { DIS_PDUTYPE_DESCRIBE_APPLICATION,               "Describe Application" },
    { DIS_PDUTYPE_DESCRIBE_EVENT,                     "Describe Event" },
    { DIS_PDUTYPE_DESCRIBE_OBJECT,                    "Describe Object" },
    { DIS_PDUTYPE_REQUEST_EVENT,                      "Request Event" },
    { DIS_PDUTYPE_REQUEST_OBJECT,                     "Request Object" },
    { DIS_PDUTYPE_APPLICATION_CONTROL,                "Application Control" },
    { DIS_PDUTYPE_STEALTH_STATE,                      "Stealth State" },
    { 0,                                              NULL }
};

typedef enum
{
    DIS_ENTITYKIND_OTHER            = 0,
    DIS_ENTITYKIND_PLATFORM         = 1,
    DIS_ENTITYKIND_MUNITION         = 2,
    DIS_ENTITYKIND_LIFE_FORM        = 3,
    DIS_ENTITYKIND_ENVIRONMENTAL    = 4,
    DIS_ENTITYKIND_CULTURAL_FEATURE = 5,
    DIS_ENTITYKIND_SUPPLY           = 6,
    DIS_ENTITYKIND_RADIO            = 7,
    DIS_ENTITYKIND_EXPENDABLE       = 8,
    DIS_ENTITYKIND_SENSOR_EMITTER   = 9
} DIS_PDU_EntityKind;

static const value_string DIS_PDU_EntityKind_Strings[] =
{
    { DIS_ENTITYKIND_OTHER,            "Other" },
    { DIS_ENTITYKIND_PLATFORM,         "Platform" },
    { DIS_ENTITYKIND_MUNITION,         "Munition" },
    { DIS_ENTITYKIND_LIFE_FORM,        "Life form" },
    { DIS_ENTITYKIND_ENVIRONMENTAL,    "Environmental" },
    { DIS_ENTITYKIND_CULTURAL_FEATURE, "Cultural feature" },
    { DIS_ENTITYKIND_SUPPLY,           "Supply" },
    { DIS_ENTITYKIND_RADIO,            "Radio" },
    { DIS_ENTITYKIND_EXPENDABLE,       "Expendable" },
    { DIS_ENTITYKIND_SENSOR_EMITTER,   "Sensor/Emitter" },
    { 0,                               NULL }
};

typedef enum
{
    DIS_DOMAIN_OTHER      = 0,
    DIS_DOMAIN_LAND       = 1,
    DIS_DOMAIN_AIR        = 2,
    DIS_DOMAIN_SURFACE    = 3,
    DIS_DOMAIN_SUBSURFACE = 4,
    DIS_DOMAIN_SPACE      = 5
} DIS_PDU_Domain;

static const value_string DIS_PDU_Domain_Strings[] =
{
    { DIS_DOMAIN_OTHER,      "Other" },
    { DIS_DOMAIN_LAND,       "Land" },
    { DIS_DOMAIN_AIR,        "Air" },
    { DIS_DOMAIN_SURFACE,    "Surface" },
    { DIS_DOMAIN_SUBSURFACE, "Subsurface" },
    { DIS_DOMAIN_SPACE,      "Space" },
    { 0,                     NULL }
};

typedef enum
{
    DIS_CATEGORY_LANDPLATFORM_OTHER                                      = 0,
    DIS_CATEGORY_LANDPLATFORM_TANK                                       = 1,
    DIS_CATEGORY_LANDPLATFORM_ARMORED_FIGHTING_VEHICLE                   = 2,
    DIS_CATEGORY_LANDPLATFORM_ARMORED_UTILITY_VEHICLE                    = 3,
    DIS_CATEGORY_LANDPLATFORM_SELF_PROPELLED_ARTILLERY                   = 4,
    DIS_CATEGORY_LANDPLATFORM_TOWED_ARTILLERY                            = 5,
    DIS_CATEGORY_LANDPLATFORM_SMALL_WHEELED_UTILITY_VEHICLE              = 6,
    DIS_CATEGORY_LANDPLATFORM_LARGE_WHEELED_UTILITY_VEHICLE              = 7,
    DIS_CATEGORY_LANDPLATFORM_SMALL_TRACKED_UTILITY_VEHICLE              = 8,
    DIS_CATEGORY_LANDPLATFORM_LARGE_TRACKED_UTILITY_VEHICLE              = 9,
    DIS_CATEGORY_LANDPLATFORM_MORTAR                                     = 10,
    DIS_CATEGORY_LANDPLATFORM_MINE_PLOW                                  = 11,
    DIS_CATEGORY_LANDPLATFORM_MINE_RAKE                                  = 12,
    DIS_CATEGORY_LANDPLATFORM_MINE_ROLLER                                = 13,
    DIS_CATEGORY_LANDPLATFORM_CARGO_TRAILER                              = 14,
    DIS_CATEGORY_LANDPLATFORM_FUEL_TRAILER                               = 15,
    DIS_CATEGORY_LANDPLATFORM_GENERATOR_TRAILER                          = 16,
    DIS_CATEGORY_LANDPLATFORM_WATER_TRAILER                              = 17,
    DIS_CATEGORY_LANDPLATFORM_ENGINEER_EQUIPMENT                         = 18,
    DIS_CATEGORY_LANDPLATFORM_HEAVY_EQUIPMENT_TRANSPORT_TRAILER          = 19,
    DIS_CATEGORY_LANDPLATFORM_MAINTENANCE_EQUIPMENT_TRAILER              = 20,
    DIS_CATEGORY_LANDPLATFORM_LIMBER                                     = 21,
    DIS_CATEGORY_LANDPLATFORM_CHEMICAL_DECONTAMINATION_TRAILER           = 22,
    DIS_CATEGORY_LANDPLATFORM_WARNING_SYSTEM                             = 23,
    DIS_CATEGORY_LANDPLATFORM_TRAIN_ENGINE                               = 24,
    DIS_CATEGORY_LANDPLATFORM_TRAIN_CAR                                  = 25,
    DIS_CATEGORY_LANDPLATFORM_TRAIN_CABOOSE                              = 26,
    DIS_CATEGORY_LANDPLATFORM_CIVILIAN_VEHICLE                           = 27,
    DIS_CATEGORY_LANDPLATFORM_AIR_DEFENSE_MISSILE_DEFENSE_UNIT_EQUIPMENT = 28,
    DIS_CATEGORY_LANDPLATFORM_C3I_SYSTEM                                 = 29,
    DIS_CATEGORY_LANDPLATFORM_OPERATIONS_FACILITY                        = 30,
    DIS_CATEGORY_LANDPLATFORM_INTELLIGENCE_FACILITY                      = 31,
    DIS_CATEGORY_LANDPLATFORM_SURVEILLANCE_FACILITY                      = 32,
    DIS_CATEGORY_LANDPLATFORM_COMMUNICATIONS_FACILITY                    = 33,
    DIS_CATEGORY_LANDPLATFORM_COMMAND_FACILITY                           = 34,
    DIS_CATEGORY_LANDPLATFORM_C4I_FACILITY                               = 35,
    DIS_CATEGORY_LANDPLATFORM_CONTROL_FACILITY                           = 36,
    DIS_CATEGORY_LANDPLATFORM_FIRE_CONTROL_FACILITY                      = 37,
    DIS_CATEGORY_LANDPLATFORM_MISSILE_DEFENSE_FACILITY                   = 38,
    DIS_CATEGORY_LANDPLATFORM_FIELD_COMMAND_POST                         = 39,
    DIS_CATEGORY_LANDPLATFORM_OBSERVATION_POST                           = 40
} DIS_PDU_Category_LandPlatform;

static const value_string DIS_PDU_Category_LandPlatform_Strings[] =
{
    { DIS_CATEGORY_LANDPLATFORM_OTHER,                                      "Other" },
    { DIS_CATEGORY_LANDPLATFORM_TANK,                                       "Tank" },
    { DIS_CATEGORY_LANDPLATFORM_ARMORED_FIGHTING_VEHICLE,                   "Armored fighting vehicle" },
    { DIS_CATEGORY_LANDPLATFORM_ARMORED_UTILITY_VEHICLE,                    "Armored utility vehicle" },
    { DIS_CATEGORY_LANDPLATFORM_SELF_PROPELLED_ARTILLERY,                   "Self-propelled artillery" },
    { DIS_CATEGORY_LANDPLATFORM_TOWED_ARTILLERY,                            "Towed artillery" },
    { DIS_CATEGORY_LANDPLATFORM_SMALL_WHEELED_UTILITY_VEHICLE,              "Small wheeled utility vehicle" },
    { DIS_CATEGORY_LANDPLATFORM_LARGE_WHEELED_UTILITY_VEHICLE,              "Large wheeled utility vehicle" },
    { DIS_CATEGORY_LANDPLATFORM_SMALL_TRACKED_UTILITY_VEHICLE,              "Small tracked utility vehicle" },
    { DIS_CATEGORY_LANDPLATFORM_LARGE_TRACKED_UTILITY_VEHICLE,              "Large tracked utility vehicle" },
    { DIS_CATEGORY_LANDPLATFORM_MORTAR,                                     "Mortar" },
    { DIS_CATEGORY_LANDPLATFORM_MINE_PLOW,                                  "Mine plow" },
    { DIS_CATEGORY_LANDPLATFORM_MINE_RAKE,                                  "Mine rake" },
    { DIS_CATEGORY_LANDPLATFORM_MINE_ROLLER,                                "Mine roller" },
    { DIS_CATEGORY_LANDPLATFORM_CARGO_TRAILER,                              "Cargo trailer" },
    { DIS_CATEGORY_LANDPLATFORM_FUEL_TRAILER,                               "Fuel trailer" },
    { DIS_CATEGORY_LANDPLATFORM_GENERATOR_TRAILER,                          "Generator trailer" },
    { DIS_CATEGORY_LANDPLATFORM_WATER_TRAILER,                              "Water trailer" },
    { DIS_CATEGORY_LANDPLATFORM_ENGINEER_EQUIPMENT,                         "Engineer equipment" },
    { DIS_CATEGORY_LANDPLATFORM_HEAVY_EQUIPMENT_TRANSPORT_TRAILER,          "Heavy equipment transport trailer" },
    { DIS_CATEGORY_LANDPLATFORM_MAINTENANCE_EQUIPMENT_TRAILER,              "Maintenance equipment trailer" },
    { DIS_CATEGORY_LANDPLATFORM_LIMBER,                                     "Limber" },
    { DIS_CATEGORY_LANDPLATFORM_CHEMICAL_DECONTAMINATION_TRAILER,           "Chemical decontamination trailer" },
    { DIS_CATEGORY_LANDPLATFORM_WARNING_SYSTEM,                             "Warning system" },
    { DIS_CATEGORY_LANDPLATFORM_TRAIN_ENGINE,                               "Train engine" },
    { DIS_CATEGORY_LANDPLATFORM_TRAIN_CAR,                                  "Train car" },
    { DIS_CATEGORY_LANDPLATFORM_TRAIN_CABOOSE,                              "Train caboose" },
    { DIS_CATEGORY_LANDPLATFORM_CIVILIAN_VEHICLE,                           "Civilian vehicle" },
    { DIS_CATEGORY_LANDPLATFORM_AIR_DEFENSE_MISSILE_DEFENSE_UNIT_EQUIPMENT, "Air defense / missile defense unit equipment" },
    { DIS_CATEGORY_LANDPLATFORM_C3I_SYSTEM,                                 "C3I system" },
    { DIS_CATEGORY_LANDPLATFORM_OPERATIONS_FACILITY,                        "Operations facility" },
    { DIS_CATEGORY_LANDPLATFORM_INTELLIGENCE_FACILITY,                      "Intelligence facility" },
    { DIS_CATEGORY_LANDPLATFORM_SURVEILLANCE_FACILITY,                      "Surveillance facility" },
    { DIS_CATEGORY_LANDPLATFORM_COMMUNICATIONS_FACILITY,                    "Communications facility" },
    { DIS_CATEGORY_LANDPLATFORM_COMMAND_FACILITY,                           "Command facility" },
    { DIS_CATEGORY_LANDPLATFORM_C4I_FACILITY,                               "C4I facility" },
    { DIS_CATEGORY_LANDPLATFORM_CONTROL_FACILITY,                           "Control facility" },
    { DIS_CATEGORY_LANDPLATFORM_FIRE_CONTROL_FACILITY,                      "Fire control facility" },
    { DIS_CATEGORY_LANDPLATFORM_MISSILE_DEFENSE_FACILITY,                   "Missile defense facility" },
    { DIS_CATEGORY_LANDPLATFORM_FIELD_COMMAND_POST,                         "Field command post" },
    { DIS_CATEGORY_LANDPLATFORM_OBSERVATION_POST,                           "Field observation post" },
    { 0,                                                                    NULL }
};

typedef enum
{
    DIS_CATEGORY_AIRPLATFORM_OTHER                             = 0,
    DIS_CATEGORY_AIRPLATFORM_FIGHTER_AIR_DEFENSE               = 1,
    DIS_CATEGORY_AIRPLATFORM_ATTACK_STRIKE                     = 2,
    DIS_CATEGORY_AIRPLATFORM_BOMBER                            = 3,
    DIS_CATEGORY_AIRPLATFORM_CARGO_TANKER                      = 4,
    DIS_CATEGORY_AIRPLATFORM_ASW_PATROL_OBSERVATION            = 5,
    DIS_CATEGORY_AIRPLATFORM_ELECTRONIC_WARFARE                = 6,
    DIS_CATEGORY_AIRPLATFORM_RECONNAISSANCE                    = 7,
    DIS_CATEGORY_AIRPLATFORM_SURVEILLANCE_C2                   = 8,
    DIS_CATEGORY_AIRPLATFORM_ATTACK_HELICOPTER                 = 20,
    DIS_CATEGORY_AIRPLATFORM_UTILITY_HELICOPTER                = 21,
    DIS_CATEGORY_AIRPLATFORM_ANTISUB_WARFARE_PATROL_HELICOPTER = 22,
    DIS_CATEGORY_AIRPLATFORM_CARGO_HELICOPTER                  = 23,
    DIS_CATEGORY_AIRPLATFORM_OBSERVATION_HELICOPTER            = 24,
    DIS_CATEGORY_AIRPLATFORM_SPECIAL_OPERATIONS_HELICOPTER     = 25,
    DIS_CATEGORY_AIRPLATFORM_TRAINER                           = 40,
    DIS_CATEGORY_AIRPLATFORM_UNMANNED                          = 50,
    DIS_CATEGORY_AIRPLATFORM_NON_COMBATANT_COMMERCIAL_AIRCRAFT = 57
} DIS_PDU_Category_AirPlatform;

static const value_string DIS_PDU_Category_AirPlatform_Strings[] =
{
    { DIS_CATEGORY_AIRPLATFORM_OTHER,                             "Other" },
    { DIS_CATEGORY_AIRPLATFORM_FIGHTER_AIR_DEFENSE,               "Fighter / air defense" },
    { DIS_CATEGORY_AIRPLATFORM_ATTACK_STRIKE,                     "Attack / strike" },
    { DIS_CATEGORY_AIRPLATFORM_BOMBER,                            "Bomber" },
    { DIS_CATEGORY_AIRPLATFORM_CARGO_TANKER,                      "Cargo tanker" },
    { DIS_CATEGORY_AIRPLATFORM_ASW_PATROL_OBSERVATION,            "ASW / patrol / observation" },
    { DIS_CATEGORY_AIRPLATFORM_ELECTRONIC_WARFARE,                "Electronic warfare" },
    { DIS_CATEGORY_AIRPLATFORM_RECONNAISSANCE,                    "Reconnaissance" },
    { DIS_CATEGORY_AIRPLATFORM_SURVEILLANCE_C2,                   "Surveillance / C2" },
    { DIS_CATEGORY_AIRPLATFORM_ATTACK_HELICOPTER,                 "Attack helicopter" },
    { DIS_CATEGORY_AIRPLATFORM_UTILITY_HELICOPTER,                "Utility helicopter" },
    { DIS_CATEGORY_AIRPLATFORM_ANTISUB_WARFARE_PATROL_HELICOPTER, "Antisubmarine warfare / patrol helicopter" },
    { DIS_CATEGORY_AIRPLATFORM_CARGO_HELICOPTER,                  "Cargo helicopter" },
    { DIS_CATEGORY_AIRPLATFORM_OBSERVATION_HELICOPTER,            "Observation helicopter" },
    { DIS_CATEGORY_AIRPLATFORM_SPECIAL_OPERATIONS_HELICOPTER,     "Special operations helicopter" },
    { DIS_CATEGORY_AIRPLATFORM_TRAINER,                           "Trainer" },
    { DIS_CATEGORY_AIRPLATFORM_UNMANNED,                          "Unmanned" },
    { DIS_CATEGORY_AIRPLATFORM_NON_COMBATANT_COMMERCIAL_AIRCRAFT, "Non-combatant commercial aircraft" },
    { 0,                                                          NULL }
};

typedef enum
{
    DIS_CATEGORY_SURFACEPLATFORM_OTHER = 0
} DIS_PDU_Category_SurfacePlatform;

static const value_string DIS_PDU_Category_SurfacePlatform_Strings[] =
{
    { DIS_CATEGORY_SURFACEPLATFORM_OTHER, "Other" },
    { 0,                                  NULL}
};

typedef enum
{
    DIS_CATEGORY_SUBSURFACEPLATFORM_OTHER = 0
} DIS_PDU_Category_SubsurfacePlatform;

static const value_string DIS_PDU_Category_SubsurfacePlatform_Strings[] =
{
    { DIS_CATEGORY_SUBSURFACEPLATFORM_OTHER, "Other" },
    { 0,                                     NULL }
};

typedef enum
{
    DIS_CATEGORY_SPACEPLATFORM_OTHER = 0
} DIS_PDU_Category_SpacePlatform;

static const value_string DIS_PDU_Category_SpacePlatform_Strings[] =
{
    { DIS_CATEGORY_SPACEPLATFORM_OTHER, "Other" },
    { 0,                                NULL }
};

typedef enum
{
    DIS_ENCODING_CLASS_ENCODED_AUDIO               = 0,
    DIS_ENCODING_CLASS_RAW_BINARY_DATA             = 1,
    DIS_ENCODING_CLASS_APPL_SPEC_DATA              = 2,
    DIS_ENCODING_CLASS_DB_INDEX                    = 3
} DIS_PDU_Encoding_Class;

static const value_string DIS_PDU_Encoding_Class_Strings[] =
{
    { DIS_ENCODING_CLASS_ENCODED_AUDIO,    "Encoded Audio" },
    { DIS_ENCODING_CLASS_RAW_BINARY_DATA,  "Raw Binary Data" },
    { DIS_ENCODING_CLASS_APPL_SPEC_DATA,   "Application-Specific Data" },
    { DIS_ENCODING_CLASS_DB_INDEX,         "Database index" },
    { 0,                                   NULL }
};

typedef enum
{
    DIS_ENCODING_TYPE_OTHER                        = 0,
    DIS_ENCODING_TYPE_MU_LAW                       = 1,
    DIS_ENCODING_TYPE_CVSD                         = 2,
    DIS_ENCODING_TYPE_ADPCM_G721                   = 3,
    DIS_ENCODING_TYPE_16BIT_LINEAR_PCM             = 4,
    DIS_ENCODING_TYPE_8BIT_LINEAR_PCM              = 5,
    DIS_ENCODING_TYPE_VECTOR_QUANTIZATION          = 6
} DIS_PDU_Encoding_Type;

static const value_string DIS_PDU_Encoding_Type_Strings[] =
{
    { DIS_ENCODING_TYPE_OTHER,               "Other" },
    { DIS_ENCODING_TYPE_MU_LAW,              "8-bit mu-law" },
    { DIS_ENCODING_TYPE_CVSD,                "CVSD per MIL-STD-188-113" },
    { DIS_ENCODING_TYPE_ADPCM_G721,          "ADPCM per CCITT G.721" },
    { DIS_ENCODING_TYPE_16BIT_LINEAR_PCM,    "16-bit linear PCM" },
    { DIS_ENCODING_TYPE_8BIT_LINEAR_PCM,     "8-bit linear PCM" },
    { DIS_ENCODING_TYPE_VECTOR_QUANTIZATION, "VQ (Vector Quantization" },
    { 0,                                NULL }
};

typedef enum
{
    DIS_TDL_TYPE_OTHER                        = 0,
    DIS_TDL_TYPE_PADIL                        = 1,
    DIS_TDL_TYPE_NATO_LINK1                   = 2,
    DIS_TDL_TYPE_ATDL1                        = 3,
    DIS_TDL_TYPE_LINK_11B                     = 4,
    DIS_TDL_TYPE_SADL                         = 5,
    DIS_TDL_TYPE_JTIDS_TADIL_J                = 6,
    DIS_TDL_TYPE_JTIDS_FDL_TADIL_J            = 7,
    DIS_TDL_TYPE_LINK_11A                     = 8,
    DIS_TDL_TYPE_IJMS                         = 9,
    DIS_TDL_TYPE_LINK_4A                      = 10,
    DIS_TDL_TYPE_LINK_4C                      = 11,
    DIS_TDL_TYPE_TIBS                         = 12,
    DIS_TDL_TYPE_ATL                          = 13,
    DIS_TDL_TYPE_CONSTANT_SRC                 = 14,
    DIS_TDL_TYPE_ABBRV_CC                     = 15,
    DIS_TDL_TYPE_MILSTAR                      = 16,
    DIS_TDL_TYPE_ATHS                         = 17,
    DIS_TDL_TYPE_OTHGOLD                      = 18,
    DIS_TDL_TYPE_TACELINT                     = 19,
    DIS_TDL_TYPE_AWW13                        = 20,
    DIS_TDL_TYPE_ABBRV_CC_2                   = 21,
    DIS_TDL_TYPE_EPLRS                        = 22,
    DIS_TDL_TYPE_PLRS                         = 23,
    DIS_TDL_TYPE_SINCGARS                     = 24,
    DIS_TDL_TYPE_HAVE_QUICK_I                 = 25,
    DIS_TDL_TYPE_HAVE_QUICK_II                = 26,
    DIS_TDL_TYPE_HAVE_QUICK_IIA               = 27,
    DIS_TDL_TYPE_IFDL1                        = 28,
    DIS_TDL_TYPE_IFDL2                        = 29,
    DIS_TDL_TYPE_IDM                          = 30,
    DIS_TDL_TYPE_AFAPD                        = 31,
    DIS_TDL_TYPE_CEC                          = 32,
    DIS_TDL_TYPE_FAAD_FDL                     = 33,
    DIS_TDL_TYPE_GBDL                         = 34,
    DIS_TDL_TYPE_IVIS                         = 35,
    DIS_TDL_TYPE_MTS                          = 36,
    DIS_TDL_TYPE_TACFIRE                      = 37,
    DIS_TDL_TYPE_IBS                          = 38,
    DIS_TDL_TYPE_ABIT                         = 39,
    DIS_TDL_TYPE_ATARS                        = 40,
    DIS_TDL_TYPE_BGPHES                       = 41,
    DIS_TDL_TYPE_CHBDL                        = 42,
    DIS_TDL_TYPE_GUARDRAIL_IDL                = 43,
    DIS_TDL_TYPE_GUARDRAIL_CSS1               = 44,
    DIS_TDL_TYPE_GUARDRAIL_CSS2               = 45,
    DIS_TDL_TYPE_GUARDRAIL_CSS2_MRDL          = 46,
    DIS_TDL_TYPE_GUARDRAIL_CSS2_DASR          = 47,
    DIS_TDL_TYPE_LOS_TETHER                   = 48,
    DIS_TDL_TYPE_LWCDL                        = 49,
    DIS_TDL_TYPE_L_52M                        = 50,
    DIS_TDL_TYPE_RR_ROWL_DL                   = 51,
    DIS_TDL_TYPE_SENIOR_SPAN                  = 52,
    DIS_TDL_TYPE_SENIOR_SPUR                  = 53,
    DIS_TDL_TYPE_SENIOR_STRETCH               = 54,
    DIS_TDL_TYPE_SENIOR_YEAR_IDL              = 55,
    DIS_TDL_TYPE_SPACE_CDL                    = 56,
    DIS_TDL_TYPE_TR_1_MIST_ADL                = 57,
    DIS_TDL_TYPE_KU_BAND_SATCOM               = 58,
    DIS_TDL_TYPE_MECDL                        = 59,
    DIS_TDL_TYPE_RADAR_DATA_TSDL              = 60,
    DIS_TDL_TYPE_SCDL                         = 61,
    DIS_TDL_TYPE_TACTICAL_UAV_VIDEO           = 62,
    DIS_TDL_TYPE_UHF_SATCOM                   = 63,
    DIS_TDL_TYPE_TCDL                         = 64,
    DIS_TDL_TYPE_LLAPI                        = 65,
    DIS_TDL_TYPE_WEAPONS_DL                   = 66,
    DIS_TDL_TYPE_GC3                          = 99,
    DIS_TDL_TYPE_LINK16_STD                   = 100,
    DIS_TDL_TYPE_LINK16_EDR                   = 101,
    DIS_TDL_TYPE_JTIDS_NET_DATA_LOAD          = 102,
    DIS_TDL_TYPE_LINK22                       = 103,
    DIS_TDL_TYPE_AFIWC_IADS                   = 104
} DIS_PDU_TDL_Type;

static const value_string DIS_PDU_TDL_Type_Strings[] =
{
    {DIS_TDL_TYPE_OTHER,                     "Other" },
    {DIS_TDL_TYPE_PADIL,                     "PADIL" },
    {DIS_TDL_TYPE_NATO_LINK1,                "NATO Link-1" },
    {DIS_TDL_TYPE_ATDL1,                     "ATDL-1" },
    {DIS_TDL_TYPE_LINK_11B,                  "Link 11B (TADIL B)" },
    {DIS_TDL_TYPE_SADL,                      "Situational Awareness Data Link (SADL)" },
    {DIS_TDL_TYPE_JTIDS_TADIL_J,             "Link 16 Legacy Format  (JTIDS/TADIL-J) " },
    {DIS_TDL_TYPE_JTIDS_FDL_TADIL_J,         "Link 16 Legacy Format (JTIDS/FDL/TADIL-J)" },
    {DIS_TDL_TYPE_LINK_11A,                  "Link 11A (TADIL A)" },
    {DIS_TDL_TYPE_IJMS,                      "IJMS" },
    {DIS_TDL_TYPE_LINK_4A,                   "Link 4A (TADIL C)" },
    {DIS_TDL_TYPE_LINK_4C,                   "Link 4C" },
    {DIS_TDL_TYPE_TIBS,                      "TIBS" },
    {DIS_TDL_TYPE_ATL,                       "ATL" },
    {DIS_TDL_TYPE_CONSTANT_SRC,              "Constant Source" },
    {DIS_TDL_TYPE_ABBRV_CC,                  "Abbreviated Command and Control" },
    {DIS_TDL_TYPE_MILSTAR,                   "MILSTAR" },
    {DIS_TDL_TYPE_ATHS,                      "ATHS" },
    {DIS_TDL_TYPE_OTHGOLD,                   "OTHGOLD" },
    {DIS_TDL_TYPE_TACELINT,                  "TACELINT" },
    {DIS_TDL_TYPE_AWW13,                     "Weapons Data Link (AWW-13)" },
    {DIS_TDL_TYPE_ABBRV_CC_2,                "Abbreviated Command and Control" },
    {DIS_TDL_TYPE_EPLRS,                     "Enhanced Position Location Reporting System (EPLRS)" },
    {DIS_TDL_TYPE_PLRS,                      "Position Location Reporting System  (PLRS)" },
    {DIS_TDL_TYPE_SINCGARS,                  "SINCGARS" },
    {DIS_TDL_TYPE_HAVE_QUICK_I,              "Have Quick I" },
    {DIS_TDL_TYPE_HAVE_QUICK_II,             "Have Quick II" },
    {DIS_TDL_TYPE_HAVE_QUICK_IIA,            "Have Quick IIA (Saturn)" },
    {DIS_TDL_TYPE_IFDL1,                     "Intra-Flight Data Link 1" },
    {DIS_TDL_TYPE_IFDL2,                     "Intra-Flight Data Link 2" },
    {DIS_TDL_TYPE_IDM,                       "Improved Data Modem (IDM)" },
    {DIS_TDL_TYPE_AFAPD,                     "Air Force Application Program Development (AFAPD)" },
    {DIS_TDL_TYPE_CEC,                       "Cooperative Engagement Capability (CEC)" },
    {DIS_TDL_TYPE_FAAD_FDL,                  "Forward Area Air Defense (FAAD) Data Link (FDL)" },
    {DIS_TDL_TYPE_GBDL,                      "Ground Based Data Link (GBDL)" },
    {DIS_TDL_TYPE_IVIS,                      "Intra Vehicular Info System (IVIS)" },
    {DIS_TDL_TYPE_MTS,                       "Marine Tactical System (MTS)" },
    {DIS_TDL_TYPE_TACFIRE,                   "Tactical Fire Direction System (TACFIRE)" },
    {DIS_TDL_TYPE_IBS,                       "Integrated Broadcast Service (IBS)" },
    {DIS_TDL_TYPE_ABIT,                      "Airborne Information Transfer (ABIT)" },
    {DIS_TDL_TYPE_ATARS,                     "Advanced Tactical Airborne Reconnaissance System (ATARS) Data Link" },
    {DIS_TDL_TYPE_BGPHES,                    "Battle Group Passive Horizon Extension System (BGPHES) Data Link" },
    {DIS_TDL_TYPE_CHBDL,                     "Common High Bandwidth Data Link (CHBDL)" },
    {DIS_TDL_TYPE_GUARDRAIL_IDL,             "Guardrail Interoperable Data Link (IDL)" },
    {DIS_TDL_TYPE_GUARDRAIL_CSS1,            "Guardrail Common Sensor System One (CSS1) Data Link" },
    {DIS_TDL_TYPE_GUARDRAIL_CSS2,            "Guardrail Common Sensor System Two (CSS2) Data Link" },
    {DIS_TDL_TYPE_GUARDRAIL_CSS2_MRDL,       "Guardrail CSS2 Multi-Role Data Link (MRDL)" },
    {DIS_TDL_TYPE_GUARDRAIL_CSS2_DASR,       "Guardrail CSS2 Direct Air to Satellite Relay (DASR) Data Link" },
    {DIS_TDL_TYPE_LOS_TETHER,                "Line of Sight (LOS) Data Link Implementation (LOS tether)" },
    {DIS_TDL_TYPE_LWCDL,                     "Lightweight CDL (LWCDL)" },
    {DIS_TDL_TYPE_L_52M,                     "L-52M (SR-71)" },
    {DIS_TDL_TYPE_RR_ROWL_DL,                "Rivet Reach/Rivet Owl Data Link" },
    {DIS_TDL_TYPE_SENIOR_SPAN,               "Senior Span" },
    {DIS_TDL_TYPE_SENIOR_SPUR,               "Senior Spur" },
    {DIS_TDL_TYPE_SENIOR_STRETCH,            "Senior Stretch." },
    {DIS_TDL_TYPE_SENIOR_YEAR_IDL,           "Senior Year Interoperable Data Link (IDL)" },
    {DIS_TDL_TYPE_SPACE_CDL,                 "Space CDL" },
    {DIS_TDL_TYPE_TR_1_MIST_ADL,             "TR-1 mode MIST Airborne Data Link" },
    {DIS_TDL_TYPE_KU_BAND_SATCOM,            "Ku-band SATCOM Data Link Implementation (UAV)" },
    {DIS_TDL_TYPE_MECDL,                     "Mission Equipment Control Data link (MECDL)" },
    {DIS_TDL_TYPE_RADAR_DATA_TSDL,           "Radar Data Transmitting Set Data Link" },
    {DIS_TDL_TYPE_SCDL,                      "Surveillance and Control Data Link (SCDL)" },
    {DIS_TDL_TYPE_TACTICAL_UAV_VIDEO,        "Tactical UAV Video" },
    {DIS_TDL_TYPE_UHF_SATCOM,                "UHF SATCOM Data Link Implementation (UAV)" },
    {DIS_TDL_TYPE_TCDL,                      "Tactical Common Data Link (TCDL)" },
    {DIS_TDL_TYPE_LLAPI,                     "Low Level Air Picture Interface (LLAPI)" },
    {DIS_TDL_TYPE_WEAPONS_DL,                "Weapons Data Link (AGM-130)" },
    {DIS_TDL_TYPE_GC3,                       "GC3" },
    {DIS_TDL_TYPE_LINK16_STD,                "Link 16 Standardized Format (JTIDS/MIDS/TADIL J)" },
    {DIS_TDL_TYPE_LINK16_EDR,                "Link 16 Enhanced Data Rate (EDR JTIDS/MIDS/TADIL-J)" },
    {DIS_TDL_TYPE_JTIDS_NET_DATA_LOAD,       "JTIDS/MIDS Net Data Load (TIMS/TOMS)" },
    {DIS_TDL_TYPE_LINK22,                    "Link 22" },
    {DIS_TDL_TYPE_AFIWC_IADS,                "AFIWC IADS Communications Links" },
    { 0,                                     NULL }
};

static const value_string DIS_PDU_RadioCategory_Strings[] =
{
    {0,     "Other" },
    {1,     "Voice Transmission/Reception" },
    {2,     "Data Link Transmission/Reception" },
    {3,     "Voice and Data Link Transmission/Reception" },
    {4,     "Instrumented Landing System (ILS) Glideslope Transmitter" },
    {5,     "Instrumented Landing System (ILS) Localizer Transmitter" },
    {6,     "Instrumented Landing System (ILS) Outer Marker Beacon" },
    {7,     "Instrumented Landing System (ILS) Middle Marker Beacon" },
    {8,     "Instrumented Landing System (ILS) Inner Marker Beacon" },
    {9,     "Instrumented Landing System (ILS) Receiver (Platform Radio)" },
    {10,    "Tactical Air Navigation (TACAN) Transmitter (Ground Fixed Equipment)" },
    {11,    "Tactical Air Navigation (TACAN) Receiver (Moving Platform Equipment)" },
    {12,    "Tactical Air Navigation (TACAN) Transmitter/Receiver (Moving Platform Equipment)" },
    {13,    "Variable Omni-Ranging (VOR) Transmitter (Ground Fixed Equipment)" },
    {14,    "Variable Omni-Ranging (VOR) with Distance Measuring Equipment (DME) Transmitter (Ground Fixed Equipment)" },
    {15,    "Combined VOR/ILS Receiver (Moving Platform Equipment)" },
    {16,    "Combined VOR & TACAN (VORTAC) Transmitter" },
    {17,    "Non-Directional Beacon (NDB) Transmitter" },
    {18,    "Non-Directional Beacon (NDB) Receiver" },
    {19,    "Non-Directional Beacon (NDB) with Distance Measuring Equipment (DME) Transmitter" },
    {20,    "Distance Measuring Equipment (DME)" },
    {0,     NULL }
};

static const value_string DIS_PDU_NomenclatureVersion_Strings[] =
{
    {0,    "Other" },
    {1,    "Joint Electronics Type Designation System (JETDS) Nomenclature (AN/ per Mil-STD-196)" },
    {2,    "Manufacturer Designation" },
    {3,    "National Designation" },
    {0,    NULL }
};

static const value_string DIS_PDU_Nomenclature_Strings[] =
{
    {0,    "Other" },
    {1,    "AN/ARN-118" },
    {2,    "AN/ARN-139" },
    {3,    "Generic Ground Fixed Transmitter" },
    {4,    "Generic Ground Mobile Transmitter" },
    {0,    NULL }
};

static const value_string DIS_PDU_RadioTransmitState_Strings[] =
{
    {0,    "Off" },
    {1,    "On but not transmitting" },
    {2,    "On and transmitting" },
    {0,    NULL }
};

static const value_string DIS_PDU_RadioInputSource_Strings[] =
{
    {0,    "Other" },
    {1,    "Pilot" },
    {2,    "Copilot" },
    {3,    "First Officer" },
    {4,    "Driver" },
    {5,    "Loader" },
    {6,    "Gunner" },
    {7,    "Commander" },
    {8,    "Digital Data Device" },
    {9,    "Intercom" },
    {0,    NULL }
};

typedef enum
{
    DIS_PATTERN_OMNI_DIRECTIONAL             = 0,
    DIS_PATTERN_BEAM                         = 1,
    DIS_PATTERN_SPHERICAL_HARMONIC           = 2
} DIS_PDU_AntennaPattern_Type;

static const value_string DIS_PDU_AntennaPatternType_Strings[] =
{
    {DIS_PATTERN_OMNI_DIRECTIONAL,    "Omni-directional" },
    {DIS_PATTERN_BEAM,                "Beam" },
    {DIS_PATTERN_SPHERICAL_HARMONIC,  "Spherical harmonic" },
    {0,    NULL }
};

typedef enum
{
    DIS_MAJOR_MOD_OTHER                      = 0,
    DIS_MAJOR_MOD_AMPLITUDE                  = 1,
    DIS_MAJOR_MOD_AMPLITUDE_AND_ANGLE        = 2,
    DIS_MAJOR_MOD_ANGLE                      = 3,
    DIS_MAJOR_MOD_COMBINATION                = 4,
    DIS_MAJOR_MOD_PULSE                      = 5,
    DIS_MAJOR_MOD_UNMODULATED                = 6,
    DIS_MAJOR_MOD_CPSM                       = 7
} DIS_PDU_MAJOR_MODULATION_TYPE;

static const value_string DIS_PDU_MajorModulation_Strings[] =
{
    {DIS_MAJOR_MOD_OTHER,                    "Other" },
    {DIS_MAJOR_MOD_AMPLITUDE,                "Amplitude" },
    {DIS_MAJOR_MOD_AMPLITUDE_AND_ANGLE,      "Amplitude and Angle" },
    {DIS_MAJOR_MOD_ANGLE,                    "Angle" },
    {DIS_MAJOR_MOD_COMBINATION,              "Combination" },
    {DIS_MAJOR_MOD_PULSE,                    "Pulse" },
    {DIS_MAJOR_MOD_UNMODULATED,              "Unmodulated" },
    {DIS_MAJOR_MOD_CPSM,                     "Carrier Phase Shift Modulation (CPSM)" },
    {0,                                      NULL }
};

static const range_string DIS_PDU_Link16_CVLL_Strings[] = {
    { 0,   127, "Crypto Variable" },
    { 255, 255, "NO STATEMENT" },
    { 0,   0,   NULL }
};

typedef enum
{
    DIS_MESSAGE_TYPE_JTIDS_HEADER_MESSAGES = 0,
    DIS_MESSAGE_TYPE_RTT_A_B,
    DIS_MESSAGE_TYPE_RTT_REPLY,
    DIS_MESSAGE_TYPE_JTIDS_VOICE_CVSD,
    DIS_MESSAGE_TYPE_JTIDS_VOICE_LPC10,
    DIS_MESSAGE_TYPE_JTIDS_VOICE_LPC12,
    DIS_MESSAGE_TYPE_JTIDS_LET,
    DIS_MESSAGE_TYPE_VMF
} DIS_PDU_MessageType;

static const value_string DIS_PDU_Link16_MessageType_Strings[] =
{
    { DIS_MESSAGE_TYPE_JTIDS_HEADER_MESSAGES, "JTIDS Header/Messages" },
    { DIS_MESSAGE_TYPE_RTT_A_B,               "RTT A/B" },
    { DIS_MESSAGE_TYPE_RTT_REPLY,             "RTT Reply" },
    { DIS_MESSAGE_TYPE_JTIDS_VOICE_CVSD,      "JTIDS Voice CVSD" },
    { DIS_MESSAGE_TYPE_JTIDS_VOICE_LPC10,     "JTIDS Voice LPC10" },
    { DIS_MESSAGE_TYPE_JTIDS_VOICE_LPC12,     "JTIDS Voice LPC12" },
    { DIS_MESSAGE_TYPE_JTIDS_LET,             "JTIDS LET" },
    { DIS_MESSAGE_TYPE_VMF,                   "VMF" },
    { 0,                                      NULL }
};

typedef enum
{
    DIS_EMISSION_FUNCTION_OTHER                         = 0,
    DIS_EMISSION_FUNCTION_MULTI_FUNCTION                = 1,
    DIS_EMISSION_FUNCTION_EARLY_WARNING_SURVEILLANCE    = 2,
    DIS_EMISSION_FUNCTION_HEIGHT_FINDING                = 3,
    DIS_EMISSION_FUNCTION_FIRE_CONTROL                  = 4,
    DIS_EMISSION_FUNCTION_ACQUISITION_DETECTION         = 5,
    DIS_EMISSION_FUNCTION_TRACKING                      = 6,
    DIS_EMISSION_FUNCTION_GUIDANCE_ILLUMINATION         = 7,
    DIS_EMISSION_FUNCTION_FIRING_POINT_LAUNCH_POINT_LOCATION = 8,
    DIS_EMISSION_FUNCTION_RANGING                       = 9,
    DIS_EMISSION_FUNCTION_RADAR_ALTIMETER               = 10,
    DIS_EMISSION_FUNCTION_IMAGING                       = 11,
    DIS_EMISSION_FUNCTION_MOTION_DETECTION              = 12,
    DIS_EMISSION_FUNCTION_NAVIGATION                    = 13,
    DIS_EMISSION_FUNCTION_WEATHER_METEROLOGICAL         = 14,
    DIS_EMISSION_FUNCTION_INSTRUMENTATION               = 15,
    DIS_EMISSION_FUNCTION_IDENTIFICATION_CLASSIFICATION_INCLUDING_IFF = 16,
    DIS_EMISSION_FUNCTION_AAA_FIRE_CONTROL              = 17,
    DIS_EMISSION_FUNCTION_AIR_SEARCH_BOMB               = 18,
    DIS_EMISSION_FUNCTION_AIR_INTERCEPT                 = 19,
    DIS_EMISSION_FUNCTION_ALTIMETER                     = 20,
    DIS_EMISSION_FUNCTION_AIR_MAPPING                   = 21,
    DIS_EMISSION_FUNCTION_AIR_TRAFFIC_CONTROL           = 22,
    DIS_EMISSION_FUNCTION_BEACON                        = 23,
    DIS_EMISSION_FUNCTION_BATTLEFIELD_SURVEILLANCE      = 24,
    DIS_EMISSION_FUNCTION_GROUND_CONTROL_APPROACH       = 25,
    DIS_EMISSION_FUNCTION_GROUND_CONTROL_INTERCEPT      = 26,
    DIS_EMISSION_FUNCTION_COASTAL_SURVEILLANCE          = 27,
    DIS_EMISSION_FUNCTION_DECOY_MIMIC                   = 28,
    DIS_EMISSION_FUNCTION_DATA_TRANSMISSION             = 29,
    DIS_EMISSION_FUNCTION_EARTH_SURVEILLANCE            = 30,
    DIS_EMISSION_FUNCTION_GUN_LAY_BEACON                = 31,
    DIS_EMISSION_FUNCTION_GROUND_MAPPING                = 32,
    DIS_EMISSION_FUNCTION_HARBOR_SURVEILLANCE           = 33,
                                                  /* enum 34 deleted */
    DIS_EMISSION_FUNCTION_ILS                           = 35,
    DIS_EMISSION_FUNCTION_IONOSPHERIC_SOUND             = 36,
    DIS_EMISSION_FUNCTION_INTERROGATOR                  = 37,
    DIS_EMISSION_FUNCTION_BARRAGE_JAMMING               = 38,
    DIS_EMISSION_FUNCTION_CLICK_JAMMING                 = 39,
                                                  /* enum 40 deleted */
    DIS_EMISSION_FUNCTION_FREQUENCY_SWEPT_JAMMING       = 41,
    DIS_EMISSION_FUNCTION_JAMMING                       = 42,
                                                  /* enum 43 deleted */
    DIS_EMISSION_FUNCTION_PULSED_JAMMING                = 44,
    DIS_EMISSION_FUNCTION_REPEATER_JAMMING              = 45,
    DIS_EMISSION_FUNCTION_SPOT_NOISE_JAMMING            = 46,
    DIS_EMISSION_FUNCTION_MISSILE_ACQUISITION           = 47,
    DIS_EMISSION_FUNCTION_MISSILE_DOWNLINK              = 48,
                                                  /* enum 49 deleted */
    DIS_EMISSION_FUNCTION_SPACE                         = 50,
    DIS_EMISSION_FUNCTION_SURFACE_SEARCH                = 51,
    DIS_EMISSION_FUNCTION_SHELL_TRACKING                = 52,
                                                /* enums 52-55 unassigned */
    DIS_EMISSION_FUNCTION_TELEVISION                    = 56,
    DIS_EMISSION_FUNCTION_UNKNOWN                       = 57,
    DIS_EMISSION_FUNCTION_VIDEO_REMOTING                = 58,
    DIS_EMISSION_FUNCTION_EXPERIMENTAL_OR_TRAINING      = 59,
    DIS_EMISSION_FUNCTION_MISSILE_GUIDANCE              = 60,
    DIS_EMISSION_FUNCTION_MISSILE_HOMING                = 61,
    DIS_EMISSION_FUNCTION_MISSILE_TRACKING              = 62,
                                                  /* enum 63 unassigned */
    DIS_EMISSION_FUNCTION_JAMMING_NOISE                 = 64,
    DIS_EMISSION_FUNCTION_JAMMING_DECEPTION             = 65,
                                                  /* enum 66 deleted */
                                                /* enums 67-70 unassigned */
    DIS_EMISSION_FUNCTION_NAVIGATION_DISTANCE_MEASURING_EQUIPMENT = 71,
    DIS_EMISSION_FUNCTION_TERRAIN_FOLLOWING             = 72,
    DIS_EMISSION_FUNCTION_WEATHER_AVOIDANCE             = 73,
    DIS_EMISSION_FUNCTION_PROXIMITY_FUSE                = 74,
                                                  /* enum 75 deleted */
    DIS_EMISSION_FUNCTION_RADIOSONDE                    = 76,
    DIS_EMISSION_FUNCTION_SONOBUOY                      = 77,
    DIS_EMISSION_FUNCTION_BATHYTHERMAL_SENSOR           = 78,
    DIS_EMISSION_FUNCTION_TOWED_COUNTER_MEASURE         = 79,
                                                /* enums 80-95 unassigned */
    DIS_EMISSION_FUNCTION_WEAPON_NON_LETHAL             = 96,
    DIS_EMISSION_FUNCTION_WEAPON_LETHAL                 = 97
} DIS_PDU_Emission_Function;

static const value_string DIS_PDU_EmissionFunction_Strings[] =
{
    {DIS_EMISSION_FUNCTION_OTHER,                    "Other" },
    {DIS_EMISSION_FUNCTION_MULTI_FUNCTION,           "Multi-Function" },
    {DIS_EMISSION_FUNCTION_EARLY_WARNING_SURVEILLANCE,
                                                "Early Warning/Surveillance" },
    {DIS_EMISSION_FUNCTION_HEIGHT_FINDING,           "Height Finding" },
    {DIS_EMISSION_FUNCTION_FIRE_CONTROL,             "Fire Control" },
    {DIS_EMISSION_FUNCTION_ACQUISITION_DETECTION,    "Acquisition/Detection" },
    {DIS_EMISSION_FUNCTION_TRACKING,                 "Tracking" },
    {DIS_EMISSION_FUNCTION_GUIDANCE_ILLUMINATION,    "Guidance/Illumination" },
    {DIS_EMISSION_FUNCTION_FIRING_POINT_LAUNCH_POINT_LOCATION,
                                        "Firing point/launch point location" },
    {DIS_EMISSION_FUNCTION_RANGING,                  "Ranging" },
    {DIS_EMISSION_FUNCTION_RADAR_ALTIMETER,          "Radar Altimeter" },
    {DIS_EMISSION_FUNCTION_IMAGING,                  "Imaging" },
    {DIS_EMISSION_FUNCTION_MOTION_DETECTION,         "Motion Detection" },
    {DIS_EMISSION_FUNCTION_NAVIGATION,               "Navigation" },
    {DIS_EMISSION_FUNCTION_WEATHER_METEROLOGICAL,    "Weather / Meterological"},
    {DIS_EMISSION_FUNCTION_INSTRUMENTATION,          "Instrumentation" },
    {DIS_EMISSION_FUNCTION_IDENTIFICATION_CLASSIFICATION_INCLUDING_IFF,
                            "Identification/Classification (including IFF)" },
    {DIS_EMISSION_FUNCTION_AAA_FIRE_CONTROL,
                                "AAA (Anti-Aircraft Artillery) Fire Control" },
    {DIS_EMISSION_FUNCTION_AIR_SEARCH_BOMB,           "Air Search/Bomb" },
    {DIS_EMISSION_FUNCTION_AIR_INTERCEPT,             "Air Intercept" },
    {DIS_EMISSION_FUNCTION_ALTIMETER,                 "Altimeter" },
    {DIS_EMISSION_FUNCTION_AIR_MAPPING,               "Air Mapping" },
    {DIS_EMISSION_FUNCTION_AIR_TRAFFIC_CONTROL,       "Air Traffic Control" },
    {DIS_EMISSION_FUNCTION_BEACON,                    "Beacon" },
    {DIS_EMISSION_FUNCTION_BATTLEFIELD_SURVEILLANCE,
                                                "Battlefield Surveillance" },
    {DIS_EMISSION_FUNCTION_GROUND_CONTROL_APPROACH,
                                                "Ground Control Approach" },
    {DIS_EMISSION_FUNCTION_GROUND_CONTROL_INTERCEPT,
                                                "Ground Control Intercept" },
    {DIS_EMISSION_FUNCTION_COASTAL_SURVEILLANCE,      "Coastal Surveillance" },
    {DIS_EMISSION_FUNCTION_DECOY_MIMIC,               "Decoy/Mimic" },
    {DIS_EMISSION_FUNCTION_DATA_TRANSMISSION,         "Data Transmission" },
    {DIS_EMISSION_FUNCTION_EARTH_SURVEILLANCE,        "Earth Surveillance" },
    {DIS_EMISSION_FUNCTION_GUN_LAY_BEACON,            "Gun Lay Beacon" },
    {DIS_EMISSION_FUNCTION_GROUND_MAPPING,            "Ground Mapping" },
    {DIS_EMISSION_FUNCTION_HARBOR_SURVEILLANCE,       "Harbor Surveillance" },
    {DIS_EMISSION_FUNCTION_ILS,
                                          "ILS (Instrument Landing System)" },
    {DIS_EMISSION_FUNCTION_IONOSPHERIC_SOUND,         "Ionospheric Sound" },
    {DIS_EMISSION_FUNCTION_INTERROGATOR,              "Interrogator" },
    {DIS_EMISSION_FUNCTION_BARRAGE_JAMMING,           "Barrage Jamming" },
    {DIS_EMISSION_FUNCTION_CLICK_JAMMING,             "Click Jamming" },
    {DIS_EMISSION_FUNCTION_FREQUENCY_SWEPT_JAMMING,
                                                "Frequency Swept Jamming" },
    {DIS_EMISSION_FUNCTION_JAMMING,                   "Jamming" },
    {DIS_EMISSION_FUNCTION_PULSED_JAMMING,            "Pulsed Jamming" },
    {DIS_EMISSION_FUNCTION_REPEATER_JAMMING,          "Repeater Jamming" },
    {DIS_EMISSION_FUNCTION_SPOT_NOISE_JAMMING,        "Spot Noise Jamming" },
    {DIS_EMISSION_FUNCTION_MISSILE_ACQUISITION,       "Missile Acquisition" },
    {DIS_EMISSION_FUNCTION_MISSILE_DOWNLINK,          "Missile Downlink" },
    {DIS_EMISSION_FUNCTION_SPACE,                     "Space" },
    {DIS_EMISSION_FUNCTION_SURFACE_SEARCH,            "Surface Search" },
    {DIS_EMISSION_FUNCTION_SHELL_TRACKING,            "Shell Tracking" },
    {DIS_EMISSION_FUNCTION_TELEVISION,                "Television" },
    {DIS_EMISSION_FUNCTION_UNKNOWN,                   "Unknown" },
    {DIS_EMISSION_FUNCTION_VIDEO_REMOTING,            "Video Remoting" },
    {DIS_EMISSION_FUNCTION_EXPERIMENTAL_OR_TRAINING,
                                                "Experimental or training" },
    {DIS_EMISSION_FUNCTION_MISSILE_GUIDANCE,          "Missile Guidance" },
    {DIS_EMISSION_FUNCTION_MISSILE_HOMING,            "Missile Homing" },
    {DIS_EMISSION_FUNCTION_MISSILE_TRACKING,          "Missile Tracking" },
    {DIS_EMISSION_FUNCTION_JAMMING_NOISE,             "Jamming, noise" },
    {DIS_EMISSION_FUNCTION_JAMMING_DECEPTION,         "Jamming, deception" },
    {DIS_EMISSION_FUNCTION_NAVIGATION_DISTANCE_MEASURING_EQUIPMENT,
                                "Navigation/Distance Measuring Equipment" },
    {DIS_EMISSION_FUNCTION_TERRAIN_FOLLOWING,         "Terrain Following" },
    {DIS_EMISSION_FUNCTION_WEATHER_AVOIDANCE,         "Weather Avoidance" },
    {DIS_EMISSION_FUNCTION_PROXIMITY_FUSE,            "Proximity Fuse" },
    {DIS_EMISSION_FUNCTION_RADIOSONDE,                "Radiosonde" },
    {DIS_EMISSION_FUNCTION_SONOBUOY,                  "Sonobuoy" },
    {DIS_EMISSION_FUNCTION_BATHYTHERMAL_SENSOR,       "Bathythermal Sensor" },
    {DIS_EMISSION_FUNCTION_TOWED_COUNTER_MEASURE,     "Towed Counter Measure"},
    {DIS_EMISSION_FUNCTION_WEAPON_NON_LETHAL,         "Weapon, non-lethal" },
    {DIS_EMISSION_FUNCTION_WEAPON_LETHAL,             "Weapon, lethal" },
    {0,                                      NULL }
};


typedef enum
{
    DIS_BEAM_FUNCTION_OTHER                             = 0,
    DIS_BEAM_FUNCTION_SEARCH                            = 1,
    DIS_BEAM_FUNCTION_HEIGHT_FINDER                     = 2,
    DIS_BEAM_FUNCTION_ACQUISITION                       = 3,
    DIS_BEAM_FUNCTION_TRACKING                          = 4,
    DIS_BEAM_FUNCTION_ACQUISITION_TRACKING              = 5,
    DIS_BEAM_FUNCTION_COMMAND_GUIDANCE                  = 6,
    DIS_BEAM_FUNCTION_ILLUMINATION                      = 7,
    DIS_BEAM_FUNCTION_RANGE_ONLY_RADAR                  = 8,
    DIS_BEAM_FUNCTION_MISSILE_BEACON                    = 9,
    DIS_BEAM_FUNCTION_MISSILE_FUZE                      = 10,
    DIS_BEAM_FUNCTION_ACTIVE_RADAR_MISSILE_SEEKER       = 11,
    DIS_BEAM_FUNCTION_JAMMER                            = 12,
    DIS_BEAM_FUNCTION_IFF                               = 13,
    DIS_BEAM_FUNCTION_NAVIGATIONAL_WEATHER              = 14,
    DIS_BEAM_FUNCTION_METEOROLOGICAL                    = 15,
    DIS_BEAM_FUNCTION_DATA_TRANSMISSION                 = 16,
    DIS_BEAM_FUNCTION_NAVIGATIONAL_DIRECTIONAL_BEACON   = 17
} DIS_PDU_Beam_Function;

static const value_string DIS_PDU_BeamFunction_Strings[] =
{
    {DIS_BEAM_FUNCTION_OTHER,               "Other" },
    {DIS_BEAM_FUNCTION_SEARCH,              "Search" },
    {DIS_BEAM_FUNCTION_HEIGHT_FINDER,       "Height finder" },
    {DIS_BEAM_FUNCTION_ACQUISITION,         "Acquisition" },
    {DIS_BEAM_FUNCTION_TRACKING,            "Tracking" },
    {DIS_BEAM_FUNCTION_ACQUISITION_TRACKING,"Acquisition and tracking" },
    {DIS_BEAM_FUNCTION_COMMAND_GUIDANCE,    "Command guidance" },
    {DIS_BEAM_FUNCTION_ILLUMINATION,        "Illumination" },
    {DIS_BEAM_FUNCTION_RANGE_ONLY_RADAR,    "Range only radar" },
    {DIS_BEAM_FUNCTION_MISSILE_BEACON,      "Missile beacon" },
    {DIS_BEAM_FUNCTION_MISSILE_FUZE,        "Missile fuze" },
    {DIS_BEAM_FUNCTION_ACTIVE_RADAR_MISSILE_SEEKER,
                                            "Active radar missile seeker" },
    {DIS_BEAM_FUNCTION_JAMMER,              "Jammer" },
    {DIS_BEAM_FUNCTION_IFF,                 "IFF" },
    {DIS_BEAM_FUNCTION_NAVIGATIONAL_WEATHER,"Navigational/Weather" },
    {DIS_BEAM_FUNCTION_METEOROLOGICAL,      "Meteorological" },
    {DIS_BEAM_FUNCTION_DATA_TRANSMISSION,   "Data transmission" },
    {DIS_BEAM_FUNCTION_NAVIGATIONAL_DIRECTIONAL_BEACON,
                                            "Navigational directional beacon" },
    {0,                                     NULL }
};

static const value_string DIS_PDU_DetailModulationAmplitude_Strings[] =
{
    {0,    "Other" },
    {1,    "AFSK (Audio Frequency Shift Keying)" },
    {2,    "AM (Amplitude Modulation)" },
    {3,    "CW (Continuous Wave Modulation)" },
    {4,    "DSB (Double Sideband)" },
    {5,    "ISB (Independent Sideband)" },
    {6,    "LSB (Single Band Suppressed Carrier, Lower Sideband Mode)" },
    {7,    "SSB-Full (Single Sideband Full Carrier)" },
    {8,    "SSB-Reduc (Single Band Reduced Carrier)" },
    {9,    "USB (Single Band Suppressed Carrier, Upper Sideband Mode)" },
    {10,   "VSB (Vestigial Sideband)" },
    {0,    NULL }
};

static const value_string DIS_PDU_DetailModulationAmpAndAngle_Strings[] =
{
    {0,    "Other" },
    {1,    "Amplitude and Angle" },
    {0,    NULL }
};

static const value_string DIS_PDU_DetailModulationAngle_Strings[] =
{
    {0,    "Other" },
    {1,    "FM (Frequency Modulation)" },
    {2,    "FSK (Frequency Shift Keying)" },
    {3,    "PM (Phase Modulation)" },
    {0,    NULL }
};

static const value_string DIS_PDU_DetailModulationCombination_Strings[] =
{
    {0,    "Other" },
    {1,    "Amplitude-Angle-Pulse" },
    {0,    NULL }
};

static const value_string DIS_PDU_DetailModulationPulse_Strings[] =
{
    {0,    "Other" },
    {1,    "Pulse" },
    {2,    "X Band TACAN Pulse" },
    {3,    "Y Band TACAN Pulse" },
    {0,    NULL }
};

static const value_string DIS_PDU_DetailModulationUnmodulated_Strings[] =
{
    {0,    "Other" },
    {1,    "Continuous Wave emission of an unmodulated carrier" },
    {0,    NULL }
};

static const value_string DIS_PDU_DetailModulationCPSM_Strings[] =
{
    {0,    "Other" },
    {0,    NULL }
};

static const value_string DIS_PDU_ModParamMsgStart_Strings[] =
{
    {0,    "Not start of message" },
    {1,    "Start of Message" },
    {0,    NULL }
};

static const value_string DIS_PDU_ModParamClrChannel_Strings[] =
{
    {0,    "Not clear channel" },
    {1,    "Clear channel" },
    {0,    NULL }
};

static const value_string DIS_PDU_TSAllocationFidelity_Strings[] =
{
    {0,    "Time Slot Allocation Fidelity Level 0" },
    {1,    "Time Slot Allocation Fidelity Level 1" },
    {2,    "Time Slot Allocation Fidelity Level 2" },
    {3,    "Time Slot Allocation Fidelity Level 3" },
    {4,    "Time Slot Allocation Fidelity Level 4" },
    {0,    NULL }
};

static const value_string DIS_PDU_TerminalPrimaryMode_Strings[] =
{
    {1,    "NTR" },
    {2,    "JTIDS Unit Participant" },
    {0,    NULL }
};

static const value_string DIS_PDU_TerminalSecondaryMode_Strings[] =
{
    {0,    "None" },
    {1,    "Net Position Reference" },
    {2,    "Primary Navigation Controller" },
    {3,    "Secondary Navigation Controller" },
    {0,    NULL }
};

/* http://discussions.sisostds.org/threadview.aspx?fid=18&threadid=53172 */
static const value_string DIS_PDU_ModParamSyncState_Strings[] =
{
    {2,    "Coarse Synchronization" },
    {3,    "Fine Synchronization" },
    {0,    NULL }
};

typedef enum
{
    DIS_SYSTEM_MOD_OTHER                     = 0,
    DIS_SYSTEM_MOD_GENERIC                   = 1,
    DIS_SYSTEM_MOD_HQ                        = 2,
    DIS_SYSTEM_MOD_HQII                      = 3,
    DIS_SYSTEM_MOD_HQIIA                     = 4,
    DIS_SYSTEM_MOD_SINCGARS                  = 5,
    DIS_SYSTEM_MOD_CCTT_SINCGARS             = 6,
    DIS_SYSTEM_MOD_EPLRS                     = 7,
    DIS_SYSTEM_MOD_JTIDS_MIDS                = 8
} DIS_PDU_SYSTEM_MODULATION_TYPE;

static const value_string DIS_PDU_SystemModulation_Strings[] =
{
    {DIS_SYSTEM_MOD_OTHER,         "Other" },
    {DIS_SYSTEM_MOD_GENERIC,       "Generic" },
    {DIS_SYSTEM_MOD_HQ,            "HQ" },
    {DIS_SYSTEM_MOD_HQII,          "HQII" },
    {DIS_SYSTEM_MOD_HQIIA,         "HQIIA" },
    {DIS_SYSTEM_MOD_SINCGARS,      "SINCGARS" },
    {DIS_SYSTEM_MOD_CCTT_SINCGARS, "CCTT SINCGARS" },
    {DIS_SYSTEM_MOD_EPLRS,         "EPLRS (Enhanced Position Location Reporting System)" },
    {DIS_SYSTEM_MOD_JTIDS_MIDS,    "JTIDS/MIDS" },
    {0,    NULL }
};

static const value_string DIS_PDU_CryptoSystem_Strings[] =
{
    {0,    "Other" },
    {1,    "KY-28" },
    {2,    "VINSON (KY-57, KY-58, SINCGARS ICOM)" },
    {3,    "Narrow Spectrum Secure Voice (NSVE)" },
    {4,    "Wide Spectrum Secure Voice (WSVE)" },
    {0,    NULL }
};

typedef enum
{
    DIS_ACKNOWLEDGE_FLAG_CREATE_ENTITY               = 1,
    DIS_ACKNOWLEDGE_FLAG_REMOVE_ENTITY               = 2,
    DIS_ACKNOWLEDGE_FLAG_START_RESUME                = 3,
    DIS_ACKNOWLEDGE_FLAG_STOP_FREEZE                 = 4,
    DIS_ACKNOWLEDGE_FLAG_TRANSFER_CONTROL_REQUEST    = 5
} DIS_PDU_AcknowledgeFlag;

static const value_string DIS_PDU_AcknowledgeFlag_Strings[] =
{
    { DIS_ACKNOWLEDGE_FLAG_CREATE_ENTITY,            "Create Entity" },
    { DIS_ACKNOWLEDGE_FLAG_REMOVE_ENTITY,            "Remove Entity" },
    { DIS_ACKNOWLEDGE_FLAG_START_RESUME,             "Start Resume" },
    { DIS_ACKNOWLEDGE_FLAG_STOP_FREEZE,              "Stop Freeze" },
    { DIS_ACKNOWLEDGE_FLAG_TRANSFER_CONTROL_REQUEST, "Transfer Control Request" },
    { 0,                                             NULL }
};

typedef enum
{
    DIS_ACTION_ID_OTHER                                         =     0,
    DIS_ACTION_ID_LOCAL_STORAGE_OF_THE_REQUESTED_INFORMATION    =     1,
    DIS_ACTION_ID_INFORM_SM_OF_EVENT_RAN_OUT_OF_AMMUNITION      =     2,
    DIS_ACTION_ID_INFORM_SM_OF_EVENT_KILLED_IN_ACTION           =     3,
    DIS_ACTION_ID_INFORM_SM_OF_EVENT_DAMAGE                     =     4,
    DIS_ACTION_ID_INFORM_SM_OF_EVENT_MOBILITY_DISABLED          =     5,
    DIS_ACTION_ID_INFORM_SM_OF_EVENT_FIRE_DISABLED              =     6,
    DIS_ACTION_ID_INFORM_SM_OF_EVENT_RAN_OUT_OF_FUEL            =     7,
    DIS_ACTION_ID_RECALL_CHECKPOINT_DATA                        =     8,
    DIS_ACTION_ID_RECALL_INITIAL_PARAMETERS                     =     9,
    DIS_ACTION_ID_INITIATE_TETHER_LEAD                          =    10,
    DIS_ACTION_ID_INITIATE_TETHER_FOLLOW                        =    11,
    DIS_ACTION_ID_UNTETHER                                      =    12,
    DIS_ACTION_ID_INITIATE_SERVICE_STATION_RESUPPLY             =    13,
    DIS_ACTION_ID_INITIATE_TAILGATE_RESUPPLY                    =    14,
    DIS_ACTION_ID_INITIATE_HITCH_LEAD                           =    15,
    DIS_ACTION_ID_INITIATE_HITCH_FOLLOW                         =    16,
    DIS_ACTION_ID_UNHITCH                                       =    17,
    DIS_ACTION_ID_MOUNT                                         =    18,
    DIS_ACTION_ID_DISMOUNT                                      =    19,
    DIS_ACTION_ID_START_DRC                                     =    20,
    DIS_ACTION_ID_STOP_DRC                                      =    21,
    DIS_ACTION_ID_DATA_QUERY                                    =    22,
    DIS_ACTION_ID_STATUS_REQUEST                                =    23,
    DIS_ACTION_ID_SEND_OBJECT_STATE_DATA                        =    24,
    DIS_ACTION_ID_RECONSTITUTE                                  =    25,
    DIS_ACTION_ID_LOCK_SITE_CONFIGURATION                       =    26,
    DIS_ACTION_ID_UNLOCK_SITE_CONFIGURATION                     =    27,
    DIS_ACTION_ID_UPDATE_SITE_CONFIGURATION                     =    28,
    DIS_ACTION_ID_QUERY_SITE_CONFIGURATION                      =    29,
    DIS_ACTION_ID_TETHERING_INFORMATION                         =    30,
    DIS_ACTION_ID_MOUNT_INTENT                                  =    31,
    DIS_ACTION_ID_ACCEPT_SUBSCRIPTION                           =    33,
    DIS_ACTION_ID_UNSUBSCRIBE                                   =    34,
    DIS_ACTION_ID_TELEPORT_ENTITY                               =    35,
    DIS_ACTION_ID_CHANGE_AGGREGATE_STATE                        =    36,
    DIS_ACTION_ID_REQUEST_START_PDU                             =    37,
    DIS_ACTION_ID_WAKEUP_GET_READY_FOR_INITIALIZATION           =    38,
    DIS_ACTION_ID_INITIALIZE_INTERNAL_PARAMETERS                =    39,
    DIS_ACTION_ID_SEND_PLAN_DATA                                =    40,
    DIS_ACTION_ID_SYNCHRONIZE_INTERNAL_CLOCKS                   =    41,
    DIS_ACTION_ID_RUN                                           =    42,
    DIS_ACTION_ID_SAVE_INTERNAL_PARAMETERS                      =    43,
    DIS_ACTION_ID_SIMULATE_MALFUNCTION                          =    44,
    DIS_ACTION_ID_JOIN_EXERCISE                                 =    45,
    DIS_ACTION_ID_RESIGN_EXERCISE                               =    46,
    DIS_ACTION_ID_TIME_ADVANCE                                  =    47,
    DIS_ACTION_ID_COMMAND_FROM_SIMULATOR                        =    48,
    DIS_ACTION_ID_SLING_LOAD_CAPABILITY_REQUEST                 =  4300,
    DIS_ACTION_ID_SLING_ATTACH_REQUEST                          =  4301,
    DIS_ACTION_ID_SLING_RELEASE_REQUEST                         =  4302,
    DIS_ACTION_ID_AIRMOUNT_MOUNT_REQUEST                        =  4303,
    DIS_ACTION_ID_AIRMOUNT_DISMOUNT_REQUEST                     =  4304,
    DIS_ACTION_ID_AIRMOUNT_INFO_REQUEST                         =  4305
} DIS_PDU_ActionId;

static const value_string DIS_PDU_ActionId_Strings[] =
{
    { DIS_ACTION_ID_OTHER,                                        "Other" },
    { DIS_ACTION_ID_LOCAL_STORAGE_OF_THE_REQUESTED_INFORMATION,   "LocalStorageOfTheRequestedInformation" },
    { DIS_ACTION_ID_INFORM_SM_OF_EVENT_RAN_OUT_OF_AMMUNITION,     "InformSMofEventRanOutOfAmmunition" },
    { DIS_ACTION_ID_INFORM_SM_OF_EVENT_KILLED_IN_ACTION,          "InformSMofEventKilledInAction" },
    { DIS_ACTION_ID_INFORM_SM_OF_EVENT_DAMAGE,                    "InformSMofEventDamage" },
    { DIS_ACTION_ID_INFORM_SM_OF_EVENT_MOBILITY_DISABLED,         "InformSMofEventMobilityDisabled" },
    { DIS_ACTION_ID_INFORM_SM_OF_EVENT_FIRE_DISABLED,             "InformSMofEventFireDisabled" },
    { DIS_ACTION_ID_INFORM_SM_OF_EVENT_RAN_OUT_OF_FUEL,           "InformSMofEventRanOutOfFuel" },
    { DIS_ACTION_ID_RECALL_CHECKPOINT_DATA,                       "RecallCheckpointData" },
    { DIS_ACTION_ID_RECALL_INITIAL_PARAMETERS,                    "RecallInitialParameters" },
    { DIS_ACTION_ID_INITIATE_TETHER_LEAD,                         "InitiateTetherLead" },
    { DIS_ACTION_ID_INITIATE_TETHER_FOLLOW,                       "InitiateTetherFollow" },
    { DIS_ACTION_ID_UNTETHER,                                     "Untether" },
    { DIS_ACTION_ID_INITIATE_SERVICE_STATION_RESUPPLY,            "InitiateServiceStationResupply" },
    { DIS_ACTION_ID_INITIATE_TAILGATE_RESUPPLY,                   "InitiateTailgateResupply" },
    { DIS_ACTION_ID_INITIATE_HITCH_LEAD,                          "InitiateHitchLead" },
    { DIS_ACTION_ID_INITIATE_HITCH_FOLLOW,                        "InitiateHitchFollow" },
    { DIS_ACTION_ID_UNHITCH,                                      "Unhitch" },
    { DIS_ACTION_ID_MOUNT,                                        "Mount" },
    { DIS_ACTION_ID_DISMOUNT,                                     "Dismount" },
    { DIS_ACTION_ID_START_DRC,                                    "StartDRC" },
    { DIS_ACTION_ID_STOP_DRC,                                     "StopDRC" },
    { DIS_ACTION_ID_DATA_QUERY,                                   "DataQuery" },
    { DIS_ACTION_ID_STATUS_REQUEST,                               "StatusRequest" },
    { DIS_ACTION_ID_SEND_OBJECT_STATE_DATA,                       "SendObjectStateData" },
    { DIS_ACTION_ID_RECONSTITUTE,                                 "Reconstitute" },
    { DIS_ACTION_ID_LOCK_SITE_CONFIGURATION,                      "LockSiteConfiguration" },
    { DIS_ACTION_ID_UNLOCK_SITE_CONFIGURATION,                    "UnlockSiteConfiguration" },
    { DIS_ACTION_ID_UPDATE_SITE_CONFIGURATION,                    "UpdateSiteConfiguration" },
    { DIS_ACTION_ID_QUERY_SITE_CONFIGURATION,                     "QuerySiteConfiguration" },
    { DIS_ACTION_ID_TETHERING_INFORMATION,                        "TetheringInformation" },
    { DIS_ACTION_ID_MOUNT_INTENT,                                 "MountIntent" },
    { DIS_ACTION_ID_ACCEPT_SUBSCRIPTION,                          "AcceptSubscription" },
    { DIS_ACTION_ID_UNSUBSCRIBE,                                  "Unsubscribe" },
    { DIS_ACTION_ID_TELEPORT_ENTITY,                              "TeleportEntity" },
    { DIS_ACTION_ID_CHANGE_AGGREGATE_STATE,                       "ChangeAggregateState" },
    { DIS_ACTION_ID_REQUEST_START_PDU,                            "RequestStartPdu" },
    { DIS_ACTION_ID_WAKEUP_GET_READY_FOR_INITIALIZATION,          "WakeupGetReadyForInitialization" },
    { DIS_ACTION_ID_INITIALIZE_INTERNAL_PARAMETERS,               "InitializeInternalParameters" },
    { DIS_ACTION_ID_SEND_PLAN_DATA,                               "SendPlanData" },
    { DIS_ACTION_ID_SYNCHRONIZE_INTERNAL_CLOCKS,                  "SynchronizeInternalClocks" },
    { DIS_ACTION_ID_RUN,                                          "Run" },
    { DIS_ACTION_ID_SAVE_INTERNAL_PARAMETERS,                     "SaveInternalParameters" },
    { DIS_ACTION_ID_SIMULATE_MALFUNCTION,                         "SimulateMalfunction" },
    { DIS_ACTION_ID_JOIN_EXERCISE,                                "JoinExercise" },
    { DIS_ACTION_ID_RESIGN_EXERCISE,                              "ResignExercise" },
    { DIS_ACTION_ID_TIME_ADVANCE,                                 "TimeAdvance" },
    { DIS_ACTION_ID_COMMAND_FROM_SIMULATOR,                       "CommandFromSimulator" },
    { DIS_ACTION_ID_SLING_LOAD_CAPABILITY_REQUEST,                "SlingLoadCapabilityRequest" },
    { DIS_ACTION_ID_SLING_ATTACH_REQUEST,                         "SlingAttachRequest" },
    { DIS_ACTION_ID_SLING_RELEASE_REQUEST,                        "SlingReleaseRequest" },
    { DIS_ACTION_ID_AIRMOUNT_MOUNT_REQUEST,                       "AirmountMountRequest" },
    { DIS_ACTION_ID_AIRMOUNT_DISMOUNT_REQUEST,                    "AirmountDismountRequest" },
    { DIS_ACTION_ID_AIRMOUNT_INFO_REQUEST,                        "AirmountInfoRequest" },
    { 0,                                                          NULL }
};

typedef enum
{
    DIS_APPLICATION_GENERAL_STATUS_UNKNOWN                   = 1,
    DIS_APPLICATION_GENERAL_STATUS_FUNCTIONAL                = 2,
    DIS_APPLICATION_GENERAL_STATUS_DEGRADED_BUT_FUNCTIONAL   = 3,
    DIS_APPLICATION_GENERAL_STATUS_NOT_FUNCTIONAL            = 4
} DIS_PDU_ApplicationGeneralStatus;

static const value_string DIS_PDU_ApplicationGeneralStatus_Strings[] =
{
    { DIS_APPLICATION_GENERAL_STATUS_UNKNOWN,                  "Unknown" },
    { DIS_APPLICATION_GENERAL_STATUS_FUNCTIONAL,               "Functional" },
    { DIS_APPLICATION_GENERAL_STATUS_DEGRADED_BUT_FUNCTIONAL,  "Degraded But Functional" },
    { DIS_APPLICATION_GENERAL_STATUS_NOT_FUNCTIONAL,           "Not Functional" },
    { 0,                                                       NULL }
};

typedef enum
{
    DIS_APPLICATION_STATUS_TYPE_NOT_SPECIFIED             =     0,
    DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_USER            =    10,
    DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_SYSTEM          =    11,
    DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_IO              =    12,
    DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_IDLE            =    13,
    DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_STEAL           =    14,
    DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_NICE            =    15,
    DIS_APPLICATION_STATUS_TYPE_MEMORY_FREE               =    50,
    DIS_APPLICATION_STATUS_TYPE_MEMORY_USED               =    51,
    DIS_APPLICATION_STATUS_TYPE_SWAP_FREE                 =    60,
    DIS_APPLICATION_STATUS_TYPE_SWAP_USED                 =    61,
    DIS_APPLICATION_STATUS_TYPE_SWAP_CACHED               =    62,
    DIS_APPLICATION_STATUS_TYPE_TRANSMITTED_PACKETS_SEC   =   100,
    DIS_APPLICATION_STATUS_TYPE_TRANSMITTED_BYTES_SEC     =   101,
    DIS_APPLICATION_STATUS_TYPE_RECEIVED_PACKETS_SEC      =   110,
    DIS_APPLICATION_STATUS_TYPE_RECEIVED_BYTES_SEC        =   111,
    DIS_APPLICATION_STATUS_TYPE_NICE_LEVEL                =   150
} DIS_PDU_ApplicationStatusType;

static const value_string DIS_PDU_ApplicationStatusType_Strings[] =
{
    { DIS_APPLICATION_STATUS_TYPE_NOT_SPECIFIED,            "Not Specified" },
    { DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_USER,           "Cpu Usage User" },
    { DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_SYSTEM,         "Cpu Usage System" },
    { DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_IO,             "Cpu Usage Io" },
    { DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_IDLE,           "Cpu Usage Idle" },
    { DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_STEAL,          "Cpu Usage Steal" },
    { DIS_APPLICATION_STATUS_TYPE_CPU_USAGE_NICE,           "Cpu Usage Nice" },
    { DIS_APPLICATION_STATUS_TYPE_MEMORY_FREE,              "Memory Free" },
    { DIS_APPLICATION_STATUS_TYPE_MEMORY_USED,              "Memory Used" },
    { DIS_APPLICATION_STATUS_TYPE_SWAP_FREE,                "Swap Free" },
    { DIS_APPLICATION_STATUS_TYPE_SWAP_USED,                "Swap Used" },
    { DIS_APPLICATION_STATUS_TYPE_SWAP_CACHED,              "Swap Cached" },
    { DIS_APPLICATION_STATUS_TYPE_TRANSMITTED_PACKETS_SEC,  "Transmitted Packets Sec" },
    { DIS_APPLICATION_STATUS_TYPE_TRANSMITTED_BYTES_SEC,    "Transmitted Bytes Sec" },
    { DIS_APPLICATION_STATUS_TYPE_RECEIVED_PACKETS_SEC,     "Received Packets Sec" },
    { DIS_APPLICATION_STATUS_TYPE_RECEIVED_BYTES_SEC,       "Received Bytes Sec" },
    { DIS_APPLICATION_STATUS_TYPE_NICE_LEVEL,               "Nice Level" },
    { 0,                                                    NULL }
};

typedef enum
{
    DIS_APPLICATION_TYPE_OTHER                                  =     0,
    DIS_APPLICATION_TYPE_RESOURCE_MANAGER                       =     1,
    DIS_APPLICATION_TYPE_SIMULATION_MANAGER                     =     2,
    DIS_APPLICATION_TYPE_GATEWAY                                =     3,
    DIS_APPLICATION_TYPE_STEALTH                                =     4,
    DIS_APPLICATION_TYPE_TACTICAL_INTERNET_INTERFACE            =     5
} DIS_PDU_ApplicationType;

static const value_string DIS_PDU_ApplicationType_Strings[] =
{
    { DIS_APPLICATION_TYPE_OTHER,                        "Other" },
    { DIS_APPLICATION_TYPE_RESOURCE_MANAGER,             "Resource Manager" },
    { DIS_APPLICATION_TYPE_SIMULATION_MANAGER,           "Simulation Manager" },
    { DIS_APPLICATION_TYPE_GATEWAY,                      "Gateway" },
    { DIS_APPLICATION_TYPE_STEALTH,                      "Stealth" },
    { DIS_APPLICATION_TYPE_TACTICAL_INTERNET_INTERFACE,  "Tactical Internet Interface" },
    { 0,                                                 NULL }
};

typedef enum
{
    DIS_DETONATION_RESULT_OTHER                                   = 0,
    DIS_DETONATION_RESULT_ENTITY_IMPACT                           = 1,
    DIS_DETONATION_RESULT_ENTITY_PROXIMATE_DETONATION             = 2,
    DIS_DETONATION_RESULT_GROUND_IMPACT                           = 3,
    DIS_DETONATION_RESULT_GROUND_PROXIMATE_DETONATION             = 4,
    DIS_DETONATION_RESULT_DETONATION                              = 5,
    DIS_DETONATION_RESULT_NONE_DUD                                = 6,
    DIS_DETONATION_RESULT_HE_HIT_SMALL                            = 7,
    DIS_DETONATION_RESULT_HE_HIT_MEDIUM                           = 8,
    DIS_DETONATION_RESULT_HE_HIT_LARGE                            = 9,
    DIS_DETONATION_RESULT_ARMOR_PIERCING_HIT                      = 10,
    DIS_DETONATION_RESULT_DIRT_BLAST_SMALL                        = 11,
    DIS_DETONATION_RESULT_DIRT_BLAST_MEDIUM                       = 12,
    DIS_DETONATION_RESULT_DIRT_BLAST_LARGE                        = 13,
    DIS_DETONATION_RESULT_WATER_BLAST_SMALL                       = 14,
    DIS_DETONATION_RESULT_WATER_BLAST_MEDIUM                      = 15,
    DIS_DETONATION_RESULT_WATER_BLAST_LARGE                       = 16,
    DIS_DETONATION_RESULT_AIR_HIT                                 = 17,
    DIS_DETONATION_RESULT_BUILDING_HIT_SMALL                      = 18,
    DIS_DETONATION_RESULT_BUILDING_HIT_MEDIUM                     = 19,
    DIS_DETONATION_RESULT_BUILDING_HIT_LARGE                      = 20,
    DIS_DETONATION_RESULT_MINE_CLEARING_LINE_CHARGE               = 21,
    DIS_DETONATION_RESULT_ENVIRONMENT_OBJECT_IMPACT               = 22,
    DIS_DETONATION_RESULT_ENVIRONMENT_OBJECT_PROXIMATE_DETONATION = 23,
    DIS_DETONATION_RESULT_WATER_IMPACT                            = 24,
    DIS_DETONATION_RESULT_AIR_BURST                               = 25,
    DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_1               = 26,
    DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_2               = 27,
    DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_3               = 28,
    DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_1_AFTER_FOF     = 29,
    DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_2_AFTER_FOF     = 30,
    DIS_DETONATION_RESULT_MISS_DUE_TO_FOF                         = 31,
    DIS_DETONATION_RESULT_MISS_DUE_TO_ENDGAME_FAILURE             = 32,
    DIS_DETONATION_RESULT_MISS_DUE_TO_FOF_AND_ENDGAME_FAILURE     = 33
} DIS_PDU_DetonationResult;

static const value_string DIS_PDU_DetonationResult_Strings[] =
{
    { DIS_DETONATION_RESULT_OTHER,                                   "Other" },
    { DIS_DETONATION_RESULT_ENTITY_IMPACT,                           "Entity impact" },
    { DIS_DETONATION_RESULT_ENTITY_PROXIMATE_DETONATION,             "Entity proximate detonation" },
    { DIS_DETONATION_RESULT_GROUND_IMPACT,                           "Ground impact" },
    { DIS_DETONATION_RESULT_GROUND_PROXIMATE_DETONATION,             "Ground proximate detonation" },
    { DIS_DETONATION_RESULT_DETONATION,                              "Detonation" },
    { DIS_DETONATION_RESULT_NONE_DUD,                                "None or no detonation (dud)" },
    { DIS_DETONATION_RESULT_HE_HIT_SMALL,                            "HE hit, small" },
    { DIS_DETONATION_RESULT_HE_HIT_MEDIUM,                           "HE hit, medium" },
    { DIS_DETONATION_RESULT_HE_HIT_LARGE,                            "HE hit, large" },
    { DIS_DETONATION_RESULT_ARMOR_PIERCING_HIT,                      "Armor-piercing hit" },
    { DIS_DETONATION_RESULT_DIRT_BLAST_SMALL,                        "Dirt blast, small" },
    { DIS_DETONATION_RESULT_DIRT_BLAST_MEDIUM,                       "Dirt blast, medium" },
    { DIS_DETONATION_RESULT_DIRT_BLAST_LARGE,                        "Dirt blast, large" },
    { DIS_DETONATION_RESULT_WATER_BLAST_SMALL,                       "Water blast, small" },
    { DIS_DETONATION_RESULT_WATER_BLAST_MEDIUM,                      "Water blast, medium" },
    { DIS_DETONATION_RESULT_WATER_BLAST_LARGE,                       "Water blast, large" },
    { DIS_DETONATION_RESULT_AIR_HIT,                                 "Air hit" },
    { DIS_DETONATION_RESULT_BUILDING_HIT_SMALL,                      "Building hit, small" },
    { DIS_DETONATION_RESULT_BUILDING_HIT_MEDIUM,                     "Building hit, medium" },
    { DIS_DETONATION_RESULT_BUILDING_HIT_LARGE,                      "Building hit, large" },
    { DIS_DETONATION_RESULT_MINE_CLEARING_LINE_CHARGE,               "Mine-clearing line charge" },
    { DIS_DETONATION_RESULT_ENVIRONMENT_OBJECT_IMPACT,               "Environment object impact" },
    { DIS_DETONATION_RESULT_ENVIRONMENT_OBJECT_PROXIMATE_DETONATION, "Environment object proximate detonation" },
    { DIS_DETONATION_RESULT_WATER_IMPACT,                            "Water impact" },
    { DIS_DETONATION_RESULT_AIR_BURST,                               "Air burst" },
    { DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_1,               "Kill with fragment type 1" },
    { DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_2,               "Kill with fragment type 2" },
    { DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_3,               "Kill with fragment type 3" },
    { DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_1_AFTER_FOF,     "Kill with fragment type 1 after fly-out failure" },
    { DIS_DETONATION_RESULT_KILL_WITH_FRAGMENT_TYPE_2_AFTER_FOF,     "Kill with fragment type 2 after fly-out failure" },
    { DIS_DETONATION_RESULT_MISS_DUE_TO_FOF,                         "Miss due to fly-out failure" },
    { DIS_DETONATION_RESULT_MISS_DUE_TO_ENDGAME_FAILURE,             "Miss due to end-game failure" },
    { DIS_DETONATION_RESULT_MISS_DUE_TO_FOF_AND_ENDGAME_FAILURE,     "Miss due to fly-out and end-game failure" },
    { 0,                                                             NULL }
};

typedef enum
{
    DIS_CONTROL_ID_OTHER                                   =     0,
    DIS_CONTROL_ID_SHUTDOWN                                =     1,
    DIS_CONTROL_ID_DATA_QUERY                              =     2,
    DIS_CONTROL_ID_DATA                                    =     3,
    DIS_CONTROL_ID_SET_DATA                                =     4,
    DIS_CONTROL_ID_ADD_DATA                                =     5,
    DIS_CONTROL_ID_REMOVE_DATA                             =     6,
    DIS_CONTROL_ID_STATUS                                  =     7
} DIS_PDU_ControlId;

static const value_string DIS_PDU_ControlId_Strings[] =
{
    { DIS_CONTROL_ID_OTHER,                                  "Other" },
    { DIS_CONTROL_ID_SHUTDOWN,                               "Shutdown" },
    { DIS_CONTROL_ID_DATA_QUERY,                             "Data Query" },
    { DIS_CONTROL_ID_DATA,                                   "Data" },
    { DIS_CONTROL_ID_SET_DATA,                               "Set Data" },
    { DIS_CONTROL_ID_ADD_DATA,                               "Add Data" },
    { DIS_CONTROL_ID_REMOVE_DATA,                            "Remove Data" },
    { DIS_CONTROL_ID_STATUS,                                 "Status" },
    { 0,                                                     NULL }
};


typedef enum
{
    DIS_FROZEN_BEHAVIOR_RUN_INTERNAL_SIMULATION_CLOCK                = 0,
    DIS_FROZEN_BEHAVIOR_TRANSMIT_PDUS                                = 1,
    DIS_FROZEN_BEHAVIOR_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES          = 2,
    DIS_FROZEN_BEHAVIOR_CONTINUE_TRANSMIT_PDU                        = 3,
    DIS_FROZEN_BEHAVIOR_CEASE_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES    = 4,
    DIS_FROZEN_BEHAVIOR_CONTINUE_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES = 5
} DIS_PDU_FrozenBehavior;

static const value_string DIS_PDU_FrozenBehavior_Strings[] =
{
    { DIS_FROZEN_BEHAVIOR_RUN_INTERNAL_SIMULATION_CLOCK,                "Run Internal Simulation Clock" },
    { DIS_FROZEN_BEHAVIOR_TRANSMIT_PDUS,                                "Transmit PDUs" },
    { DIS_FROZEN_BEHAVIOR_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES,          "Update Sim Models Of Other Entities" },
    { DIS_FROZEN_BEHAVIOR_CONTINUE_TRANSMIT_PDU,                        "Continue Transmit PDU" },
    { DIS_FROZEN_BEHAVIOR_CEASE_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES,    "Cease Update Sim Models Of Other Entities" },
    { DIS_FROZEN_BEHAVIOR_CONTINUE_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES, "Continue Update Sim Models Of Other Entities" },
    { 0,                                                                NULL }
};

typedef enum
{
    DIS_PARAM_TYPE_DESIG_ARTICULATED_PART                        =  0,
    DIS_PARAM_TYPE_DESIG_ATTACHED_PART                           =  1,
    DIS_PARAM_TYPE_DESIG_SEPARATION                              =  2,
    DIS_PARAM_TYPE_DESIG_ENTITY_TYPE                             =  3,
    DIS_PARAM_TYPE_DESIG_ENTITY_ASSOCIATION                      =  4,
    DIS_PARAM_TYPE_DESIG_ANTENNA_LOCATION                        =  5,
    DIS_PARAM_TYPE_DESIG_EXTENDED_PLATFORM_APPEARANCE            = 20,
    DIS_PARAM_TYPE_DESIG_EXTENDED_LIFEFORM_APPEARANCE            = 21,
    DIS_PARAM_TYPE_DESIG_HIGH_FIDELITY_LIGHTS                    = 22,
    DIS_PARAM_TYPE_DESIG_CHEVRON_MARKING                         = 23,
    DIS_PARAM_TYPE_DESIG_HIGH_FIDELITY_THERMAL_SENSOR            = 24,
    DIS_PARAM_TYPE_DESIG_ENTITY_OFFSET                           = 25,
    DIS_PARAM_TYPE_DESIG_DEAD_RECKONING                          = 26,
    DIS_PARAM_TYPE_DESIG_ARMY_TASK_ORGANIZATION                  = 27,
    DIS_PARAM_TYPE_DESIG_HEAD_GAZING_WEAPON_AIMING               = 28,
    DIS_PARAM_TYPE_DESIG_LIFEFORM_ACTION_SEQUENCE                = 29,
    DIS_PARAM_TYPE_DESIG_LEGACY_EXTENDED_LIFEFORM_APPEARANCE     = 30
} DIS_PDU_ParameterTypeDesignator;

static const value_string DIS_PDU_ParameterTypeDesignator_Strings[] =
{
    { DIS_PARAM_TYPE_DESIG_ARTICULATED_PART,                        "Articulated Part" },
    { DIS_PARAM_TYPE_DESIG_ATTACHED_PART,                           "Attached Part" },
    { DIS_PARAM_TYPE_DESIG_SEPARATION,                              "Separation" },
    { DIS_PARAM_TYPE_DESIG_ENTITY_TYPE,                             "Entity Type" },
    { DIS_PARAM_TYPE_DESIG_ENTITY_ASSOCIATION,                      "Entity Association" },
    { DIS_PARAM_TYPE_DESIG_ANTENNA_LOCATION,                        "Antenna Location" },
    { DIS_PARAM_TYPE_DESIG_EXTENDED_PLATFORM_APPEARANCE,            "Extended Platform Appearance" },
    { DIS_PARAM_TYPE_DESIG_EXTENDED_LIFEFORM_APPEARANCE,            "Extended Lifeform Appearance" },
    { DIS_PARAM_TYPE_DESIG_HIGH_FIDELITY_LIGHTS,                    "High Fidelity Lights" },
    { DIS_PARAM_TYPE_DESIG_CHEVRON_MARKING,                         "Chevron Marking" },
    { DIS_PARAM_TYPE_DESIG_HIGH_FIDELITY_THERMAL_SENSOR,            "High Fidelity Thermal Sensor" },
    { DIS_PARAM_TYPE_DESIG_ENTITY_OFFSET,                           "Entity Offset" },
    { DIS_PARAM_TYPE_DESIG_DEAD_RECKONING,                          "Dead Reckoning" },
    { DIS_PARAM_TYPE_DESIG_ARMY_TASK_ORGANIZATION,                  "Army Task Organization" },
    { DIS_PARAM_TYPE_DESIG_HEAD_GAZING_WEAPON_AIMING,               "Head Gazing Weapon Aiming" },
    { DIS_PARAM_TYPE_DESIG_LIFEFORM_ACTION_SEQUENCE,                "Lifeform Action Sequence" },
    { DIS_PARAM_TYPE_DESIG_LEGACY_EXTENDED_LIFEFORM_APPEARANCE,     "Legacy Extended Lifeform Appearance" },
    { 0,                                                            NULL }
};

typedef enum
{
    DIS_REASON_OTHER                                             = 0,
    DIS_REASON_RECESS                                            = 1,
    DIS_REASON_TERMINATION                                       = 2,
    DIS_REASON_SYSTEM_FAILURE                                    = 3,
    DIS_REASON_SECURITY_VIOLATION                                = 4,
    DIS_REASON_ENTITY_RECONSTITUTION                             = 5,
    DIS_REASON_STOP_FOR_RESET                                    = 6,
    DIS_REASON_STOP_FOR_RESTART                                  = 7,
    DIS_REASON_ABORT_TRAINING_RETURN_TO_TACTICAL_OPERATIONS      = 8
} DIS_PDU_Reason;

static const value_string DIS_PDU_Reason_Strings[] =
{
    { DIS_REASON_OTHER,                                            "Other" },
    { DIS_REASON_RECESS,                                           "Recess" },
    { DIS_REASON_TERMINATION,                                      "Termination" },
    { DIS_REASON_SYSTEM_FAILURE,                                   "System Failure" },
    { DIS_REASON_SECURITY_VIOLATION,                               "Security Violation" },
    { DIS_REASON_ENTITY_RECONSTITUTION,                            "Entity Reconstitution" },
    { DIS_REASON_STOP_FOR_RESET,                                   "Stop For Reset" },
    { DIS_REASON_STOP_FOR_RESTART,                                 "Stop For Restart" },
    { DIS_REASON_ABORT_TRAINING_RETURN_TO_TACTICAL_OPERATIONS,     "Abort Training Return To Tactical Operations" },
    { 0,                                                           NULL }
};

typedef enum
{
    DIS_REQUEST_STATUS_OTHER                                     =     0,
    DIS_REQUEST_STATUS_PENDING                                   =     1,
    DIS_REQUEST_STATUS_EXECUTING                                 =     2,
    DIS_REQUEST_STATUS_PARTIALLY_COMPLETE                        =     3,
    DIS_REQUEST_STATUS_COMPLETE                                  =     4,
    DIS_REQUEST_STATUS_REQUEST_REJECTED                          =     5,
    DIS_REQUEST_STATUS_RETRANSMIT_REQUEST_NOW                    =     6,
    DIS_REQUEST_STATUS_RETRANSMIT_REQUEST_LATER                  =     7,
    DIS_REQUEST_STATUS_INVALID_TIME_PARAMETERS                   =     8,
    DIS_REQUEST_STATUS_SIMULATION_TIME_EXCEEDED                  =     9,
    DIS_REQUEST_STATUS_REQUEST_DONE                              =    10,
    DIS_REQUEST_STATUS_TACCSF_LOS_REPLY_TYPE_1                   =   100,
    DIS_REQUEST_STATUS_TACCSF_LOS_REPLY_TYPE_2                   =   101,
    DIS_REQUEST_STATUS_JOIN_EXERCISE_REQUEST_REJECTED            =   201
} DIS_PDU_RequestStatus;

static const value_string DIS_PDU_RequestStatus_Strings[] =
{
    { DIS_REQUEST_STATUS_OTHER,                          "Other" },
    { DIS_REQUEST_STATUS_PENDING,                        "Pending" },
    { DIS_REQUEST_STATUS_EXECUTING,                      "Executing" },
    { DIS_REQUEST_STATUS_PARTIALLY_COMPLETE,             "Partially Complete" },
    { DIS_REQUEST_STATUS_COMPLETE,                       "Complete" },
    { DIS_REQUEST_STATUS_REQUEST_REJECTED,               "Request Rejected" },
    { DIS_REQUEST_STATUS_RETRANSMIT_REQUEST_NOW,         "Retransmit Request Now" },
    { DIS_REQUEST_STATUS_RETRANSMIT_REQUEST_LATER,       "Retransmit Request Later" },
    { DIS_REQUEST_STATUS_INVALID_TIME_PARAMETERS,        "Invalid Time Parameters" },
    { DIS_REQUEST_STATUS_SIMULATION_TIME_EXCEEDED,       "Simulation Time Exceeded" },
    { DIS_REQUEST_STATUS_REQUEST_DONE,                   "Request Done" },
    { DIS_REQUEST_STATUS_TACCSF_LOS_REPLY_TYPE_1,        "TACCSF LOS Reply Type 1" },
    { DIS_REQUEST_STATUS_TACCSF_LOS_REPLY_TYPE_2,        "TACCSF LOS Reply Type 2" },
    { DIS_REQUEST_STATUS_JOIN_EXERCISE_REQUEST_REJECTED, "Join Exercise Request Rejected" },
    { 0,                                                 NULL }
};

typedef enum
{
    DIS_REQUIRED_RELIABILITY_SERVICE_ACKNOWLEDGED      = 0,
    DIS_REQUIRED_RELIABILITY_SERVICE_UNACKNOWLEDGED    = 1
} DIS_PDU_RequiredReliabilityService;

static const value_string DIS_PDU_RequiredReliabilityService_Strings[] =
{
    { DIS_REQUIRED_RELIABILITY_SERVICE_ACKNOWLEDGED,     "Acknowledged" },
    { DIS_REQUIRED_RELIABILITY_SERVICE_UNACKNOWLEDGED,   "Unacknowledged" },
    { 0,                                                 NULL }
};

typedef enum
{
    DIS_RESPONSE_FLAG_OTHER                            = 0,
    DIS_RESPONSE_FLAG_ABLE_TO_COMPLY                   = 1,
    DIS_RESPONSE_FLAG_UNABLE_TO_COMPLY                 = 2,
    DIS_RESPONSE_FLAG_PENDING_OPERATOR_ACTION          = 3
} DIS_PDU_DisResponseFlag;

static const value_string DIS_PDU_DisResponseFlag_Strings[] =
{
    { DIS_RESPONSE_FLAG_OTHER,                      "Other" },
    { DIS_RESPONSE_FLAG_ABLE_TO_COMPLY,             "Able To Comply" },
    { DIS_RESPONSE_FLAG_UNABLE_TO_COMPLY,           "Unable To Comply" },
    { DIS_RESPONSE_FLAG_PENDING_OPERATOR_ACTION,    "Pending Operator Action" },
    { 0,                                            NULL }
};

typedef enum
{
    DIS_PERSISTENT_OBJECT_TYPE_OTHER               = 0,
    DIS_PERSISTENT_OBJECT_TYPE_SIMULATOR_PRESENT   = 1,
    DIS_PERSISTENT_OBJECT_TYPE_DESCRIBE_OBJECT     = 2,
    DIS_PERSISTENT_OBJECT_TYPE_OBJECTS_PRESENT     = 3,
    DIS_PERSISTENT_OBJECT_TYPE_OBJECT_REQUEST      = 4,
    DIS_PERSISTENT_OBJECT_TYPE_DELETE_OBJECTS      = 5,
    DIS_PERSISTENT_OBJECT_TYPE_SET_WORLD_STATE     = 6,
    DIS_PERSISTENT_OBJECT_TYPE_NOMINATION          = 7
} DIS_PDU_PersistentObjectType;

static const value_string DIS_PDU_PersistentObjectType_Strings[] =
{
    { DIS_PERSISTENT_OBJECT_TYPE_OTHER,             "Other" },
    { DIS_PERSISTENT_OBJECT_TYPE_SIMULATOR_PRESENT, "Simulator Present" },
    { DIS_PERSISTENT_OBJECT_TYPE_DESCRIBE_OBJECT,   "Describe Object" },
    { DIS_PERSISTENT_OBJECT_TYPE_OBJECTS_PRESENT,   "Objects Present" },
    { DIS_PERSISTENT_OBJECT_TYPE_OBJECT_REQUEST,    "Object Request" },
    { DIS_PERSISTENT_OBJECT_TYPE_DELETE_OBJECTS,    "Delete Objects" },
    { DIS_PERSISTENT_OBJECT_TYPE_SET_WORLD_STATE,   "Set World State" },
    { DIS_PERSISTENT_OBJECT_TYPE_NOMINATION,        "Nomination" },
    { 0,                                            NULL }
};

typedef enum
{
    DIS_PO_OBJECT_CLASS_OTHER                      =  0,
    DIS_PO_OBJECT_CLASS_WORLD_STATE                =  1,
    DIS_PO_OBJECT_CLASS_OVERLAY                    =  2,
    DIS_PO_OBJECT_CLASS_POINT                      =  3,
    DIS_PO_OBJECT_CLASS_LINE                       =  4,
    DIS_PO_OBJECT_CLASS_SECTOR                     =  5,
    DIS_PO_OBJECT_CLASS_TEXT                       =  6,
    DIS_PO_OBJECT_CLASS_UNIT                       =  7,
    DIS_PO_OBJECT_CLASS_UNIT_DEFINITION            =  8,
    DIS_PO_OBJECT_CLASS_STEALTH_CONTROLLER         =  9,
    DIS_PO_OBJECT_CLASS_H_HOUR                     = 10,
    DIS_PO_OBJECT_CLASS_VARIABLE                   = 11,
    DIS_PO_OBJECT_CLASS_TASK                       = 12,
    DIS_PO_OBJECT_CLASS_TASK_STATE                 = 13,
    DIS_PO_OBJECT_CLASS_TASK_FRAME                 = 14,
    DIS_PO_OBJECT_CLASS_TASK_AUTHORIZATION         = 15,
    DIS_PO_OBJECT_CLASS_PARAMETRIC_INPUT           = 16,
    DIS_PO_OBJECT_CLASS_PARAMETRIC_INPUT_HOLDER    = 17,
    DIS_PO_OBJECT_CLASS_EXERCISE_INITIALIZER       = 18,
    DIS_PO_OBJECT_CLASS_FIRE_PARAMETERS            = 19,
    DIS_PO_OBJECT_CLASS_MINEFIELD                  = 20,
    DIS_PO_OBJECT_CLASS_SIMULATION_REQUEST         = 21,
    DIS_PO_OBJECT_CLASS_NET_SUBSCRIPTION           = 22,
    DIS_PO_OBJECT_CLASS_LINK                       = 23,
    DIS_PO_OBJECT_CLASS_MINEFIELD_PARENT           = 24,
    DIS_PO_OBJECT_CLASS_CHEMICAL                   = 25,
    DIS_PO_OBJECT_CLASS_AlertUser                  = 26,
    DIS_PO_OBJECT_CLASS_HAND_OFF                   = 27,
    DIS_PO_OBJECT_CLASS_CIRCUIT                    = 28,
    DIS_PO_OBJECT_CLASS_CARGO                      = 29,
    DIS_PO_OBJECT_CLASS_MCM_ROUTE                  = 30,
    DIS_PO_OBJECT_CLASS_MESSAGE                    = 31
} DIS_PDU_PO_ObjectClass;

static const value_string DIS_PDU_PO_ObjectClass_Strings[] =
{
    { DIS_PO_OBJECT_CLASS_OTHER,                    "Other" },
    { DIS_PO_OBJECT_CLASS_WORLD_STATE,              "World State" },
    { DIS_PO_OBJECT_CLASS_OVERLAY,                  "Overlay" },
    { DIS_PO_OBJECT_CLASS_POINT,                    "Point" },
    { DIS_PO_OBJECT_CLASS_LINE,                     "Line" },
    { DIS_PO_OBJECT_CLASS_SECTOR,                   "Sector" },
    { DIS_PO_OBJECT_CLASS_TEXT,                     "Text" },
    { DIS_PO_OBJECT_CLASS_UNIT,                     "Unit" },
    { DIS_PO_OBJECT_CLASS_UNIT_DEFINITION,          "Unit Definition" },
    { DIS_PO_OBJECT_CLASS_STEALTH_CONTROLLER,       "Stealth Controller" },
    { DIS_PO_OBJECT_CLASS_H_HOUR,                   "H Hour" },
    { DIS_PO_OBJECT_CLASS_VARIABLE,                 "Variable" },
    { DIS_PO_OBJECT_CLASS_TASK,                     "Task" },
    { DIS_PO_OBJECT_CLASS_TASK_STATE,               "Task State" },
    { DIS_PO_OBJECT_CLASS_TASK_FRAME,               "Task Frame" },
    { DIS_PO_OBJECT_CLASS_TASK_AUTHORIZATION,       "Task Authorization" },
    { DIS_PO_OBJECT_CLASS_PARAMETRIC_INPUT,         "Parametric Input" },
    { DIS_PO_OBJECT_CLASS_PARAMETRIC_INPUT_HOLDER,  "Parametric Input Holder" },
    { DIS_PO_OBJECT_CLASS_EXERCISE_INITIALIZER,     "Exercise Initializer" },
    { DIS_PO_OBJECT_CLASS_FIRE_PARAMETERS,          "Fire Parameters" },
    { DIS_PO_OBJECT_CLASS_MINEFIELD,                "Minefield" },
    { DIS_PO_OBJECT_CLASS_SIMULATION_REQUEST,       "Simulation Request" },
    { DIS_PO_OBJECT_CLASS_NET_SUBSCRIPTION,         "Net Subscription" },
    { DIS_PO_OBJECT_CLASS_LINK,                     "Link" },
    { DIS_PO_OBJECT_CLASS_MINEFIELD_PARENT,         "Minefield Parent" },
    { DIS_PO_OBJECT_CLASS_CHEMICAL,                 "Chemical" },
    { DIS_PO_OBJECT_CLASS_AlertUser,                "Alert User" },
    { DIS_PO_OBJECT_CLASS_HAND_OFF,                 "Hand Off" },
    { DIS_PO_OBJECT_CLASS_CIRCUIT,                  "Circuit" },
    { DIS_PO_OBJECT_CLASS_CARGO,                    "Cargo" },
    { DIS_PO_OBJECT_CLASS_MCM_ROUTE,                "Mcm Route" },
    { DIS_PO_OBJECT_CLASS_MESSAGE,                  "Message" },
    { 0,                                            NULL }
};

static const value_string DIS_PDU_EmitterName_Strings[] =
{
    { 10, "1RL138" },
    { 45, "1226 DECCA MIL" },
    { 80, "9GR400" },
    { 90, "9GR600" },
    { 135, "9LV 200 TA" },
    { 180, "9LV 200 TV" },
    { 225, "A310Z" },
    { 270, "A325A" },
    { 315, "A346Z" },
    { 360, "A353B" },
    { 405, "A372A" },
    { 450, "A372B" },
    { 495, "A372C" },
    { 540, "A377A" },
    { 585, "A377B" },
    { 630, "A380Z" },
    { 675, "A381Z" },
    { 720, "A398Z" },
    { 765, "A403Z" },
    { 810, "A409A" },
    { 855, "A418A" },
    { 900, "A419Z" },
    { 945, "A429Z" },
    { 990, "A432Z" },
    { 1035, "A434Z" },
    { 1080, "A401A" },
    { 1095, "AA-12 Seeker" },
    { 1100, "Agave" },
    { 1125, "AGRION 15" },
    { 1170, "AI MK 23" },
    { 1215, "AIDA II" },
    { 1260, "Albatros MK2" },
    { 1280, "1L13-3 (55G6), Box Spring" },
    { 1282, "1L13-3 (55G6), Box Spring B" },
    { 1305, "ANA SPS 502" },
    { 1350, "ANRITSU Electric AR-30A" },
    { 1395, "Antilope V" },
    { 1400, "AN/ALE-50" },
    { 1440, "AN/ALQ 99" },
    { 1485, "AN/ALQ-100" },
    { 1530, "AN/ALQ-101" },
    { 1575, "AN/ALQ-119" },
    { 1585, "AN/ALQ-122" },
    { 1620, "AN/ALQ-126A" },
    { 1626, "AN/ALQ-131" },
    { 1628, "AN/ALQ-135C/D" },
    { 1630, "AN/ALQ-144A(V)3" },
    { 1632, "AN/ALQ-153" },
    { 1634, "AN/ALQ-155" },
    { 1636, "AN/ALQ-161/A" },
    { 1638, "AN/ALQ-162" },
    { 1640, "AN/ALQ-165" },
    { 1642, "AN/ALQ-167" },
    { 1644, "AN/ALQ-172(V)2" },
    { 1646, "AN/ALQ-176" },
    { 1648, "AN/ALQ-184" },
    { 1650, "AN/ALQ-188" },
    { 1652, "AN/ALR-56" },
    { 1654, "AN/ALR-69" },
    { 1656, "AN/ALT-16A" },
    { 1658, "AN/ALT-28" },
    { 1660, "AN/ALT-32A" },
    { 1665, "AN/APD 10" },
    { 1710, "AN/APG 53" },
    { 1755, "AN/APG 59" },
    { 1800, "AN/APG-63" },
    { 1805, "AN/APG-63(V)1" },
    { 1807, "AN/APG-63(V)2" },
    { 1809, "AN/APG-63(V)3" },
    { 1845, "AN/APG 65" },
    { 1870, "AN/APG-66" },
    { 1890, "AN/APG 68" },
    { 1935, "AN/APG 70" },
    { 1945, "AN/APG-73" },
    { 1960, "AN/APG-77" },
    { 1970, "AN/APG-78" },
    { 1980, "AN/APG-502" },
    { 2025, "AN/APN-1" },
    { 2070, "AN/APN-22" },
    { 2115, "AN/APN 59" },
    { 2160, "AN/APN-69" },
    { 2205, "AN/APN-81" },
    { 2250, "AN/APN-117" },
    { 2295, "AN/APN-118" },
    { 2340, "AN/APN-130" },
    { 2385, "AN/APN-131" },
    { 2430, "AN/APN-133" },
    { 2475, "AN/APN-134" },
    { 2520, "AN/APN-147" },
    { 2565, "AN/APN-150" },
    { 2610, "AN/APN-153" },
    { 2655, "AN/APN 154" },
    { 2700, "AN/APN-155" },
    { 2745, "AN/APN-159" },
    { 2790, "AN/APN-182" },
    { 2835, "AN/APN-187" },
    { 2880, "AN/APN-190" },
    { 2925, "AN/APN 194" },
    { 2970, "AN/APN-195" },
    { 3015, "AN/APN-198" },
    { 3060, "AN/APN-200" },
    { 3105, "AN/APN 202" },
    { 3150, "AN/APN-217" },
    { 3152, "AN/APN-218" },
    { 3160, "AN/APN-238" },
    { 3162, "AN/APN-239" },
    { 3164, "AN/APN-241" },
    { 3166, "AN/APN-242" },
    { 3195, "AN/APN-506" },
    { 3240, "AN/APQ-72" },
    { 3285, "AN/APQ-99" },
    { 3330, "AN/APQ 100" },
    { 3375, "AN/APQ-102" },
    { 3420, "AN/APQ-109" },
    { 3465, "AN/APQ 113" },
    { 3510, "AN/APQ 120" },
    { 3555, "AN/APQ 126" },
    { 3600, "AN/APQ-128" },
    { 3645, "AN/APQ-129" },
    { 3690, "AN/APQ 148" },
    { 3735, "AN/APQ-153" },
    { 3780, "AN/APQ 159" },
    { 3785, "AN/APQ-164" },
    { 3788, "AN/APQ-166" },
    { 3795, "AN/APQ-181" },
    { 3820, "AN/APS-31" },
    { 3825, "AN/APS-42" },
    { 3870, "AN/APS 80" },
    { 3915, "AN/APS-88" },
    { 3960, "AN/APS 115" },
    { 4005, "AN/APS 116" },
    { 4050, "AN/APS-120" },
    { 4095, "AN/APS 121" },
    { 4140, "AN/APS 124" },
    { 4185, "AN/APS 125" },
    { 4230, "AN/APS-128" },
    { 4275, "AN/APS 130" },
    { 4320, "AN/APS 133" },
    { 4365, "AN/APS-134" },
    { 4410, "AN/APS 137" },
    { 4455, "AN/APS-138" },
    { 4465, "AN/APS-143 (V) 1" },
    { 4500, "AN/APW 22" },
    { 4545, "AN/APW 23" },
    { 4590, "AN/APX-6" },
    { 4635, "AN/APX 7" },
    { 4680, "AN/APX 39" },
    { 4725, "AN/APX-72" },
    { 4770, "AN/APX 76" },
    { 4815, "AN/APX 78" },
    { 4860, "AN/APX 101" },
    { 4870, "AN/APX-113 AIFF" },
    { 4900, "AN/APY-1" },
    { 4905, "AN/APY 2" },
    { 4950, "AN/APY 3" },
    { 4953, "AN/APY-8, LYNX(tm)" },
    { 4995, "AN/ARN 21" },
    { 5040, "AN/ARN 52" },
    { 5085, "AN/ARN 84" },
    { 5130, "AN/ARN 118" },
    { 5175, "AN/ARW 73" },
    { 5220, "AN/ASB 1" },
    { 5265, "AN/ASG 21" },
    { 5280, "AN/ASQ-108" },
    { 5310, "AN/AWG 9" },
    { 5355, "AN/BPS-9" },
    { 5400, "AN/BPS 15" },
    { 5405, "AN/BPS-16" },
    { 5420, "AN/CRM-30" },
    { 5430, "AN/DPW-23" },
    { 5445, "AN/DSQ 26 Phoenix MH" },
    { 5490, "AN/DSQ 28 Harpoon MH" },
    { 5495, "AN/FPN-40" },
    { 5500, "AN/FPN-62" },
    { 5505, "AN/FPS-16" },
    { 5507, "AN/FPS-18" },
    { 5508, "AN/FPS-89" },
    { 5510, "AN/FPS-117" },
    { 5515, "AN/FPS-20R" },
    { 5520, "AN/FPS-77" },
    { 5525, "AN/FPS-103" },
    { 5527, "AN/GPN-12" },
    { 5530, "AN/GPX-6" },
    { 5535, "AN/GPX 8" },
    { 5537, "AN/GRN-12" },
    { 5540, "AN/MPQ-10" },
    { 5545, "AN/MPQ-33/39/46/57/61 (HPIR) ILL" },
    { 5550, "AN/MPQ-34/48/55/62 (CWAR) TA" },
    { 5551, "AN/MPQ-49" },
    { 5555, "AN/MPQ-35/50 (PAR) TA" },
    { 5560, "AN/MPQ-37/51 (ROR) TT" },
    { 5570, "AN/MPQ-53" },
    { 5571, "AN/MPQ-63" },
    { 5575, "AN/MPQ-64" },
    { 5580, "AN/SPG-34" },
    { 5625, "AN/SPG 50" },
    { 5670, "AN/SPG 51" },
    { 5715, "AN/SPG-51 CWI TI" },
    { 5760, "AN/SPG-51 FC" },
    { 5805, "AN/SPG 52" },
    { 5850, "AN/SPG-53" },
    { 5895, "AN/SPG 55B" },
    { 5940, "AN/SPG 60" },
    { 5985, "AN/SPG 62" },
    { 6030, "AN/SPN 35" },
    { 6075, "AN/SPN 43" },
    { 6120, "AN/SPQ-2" },
    { 6165, "AN/SPQ 9" },
    { 6210, "AN/SPS-4" },
    { 6255, "AN/SPS-5" },
    { 6300, "AN/SPS-5C" },
    { 6345, "AN/SPS-6" },
    { 6390, "AN/SPS 10" },
    { 6435, "AN/SPS 21" },
    { 6480, "AN/SPS-28" },
    { 6525, "AN/SPS-37" },
    { 6570, "AN/SPS-39A" },
    { 6615, "AN/SPS 40" },
    { 6660, "AN/SPS-41" },
    { 6705, "AN/SPS-48" },
    { 6750, "AN/SPS-48C" },
    { 6752, "AN/SPS-48E" },
    { 6795, "AN/SPS-49" },
    { 6796, "AN/SPS-49(V)1" },
    { 6797, "AN/SPS-49(V)2" },
    { 6798, "AN/SPS-49(V)3" },
    { 6799, "AN/SPS-49(V)4" },
    { 6800, "AN/SPS-49(V)5" },
    { 6801, "AN/SPS-49(V)6" },
    { 6802, "AN/SPS-49(V)7" },
    { 6803, "AN/SPS-49(V)8" },
    { 6804, "AN/SPS-49A(V)1" },
    { 6840, "AN/SPS 52" },
    { 6885, "AN/SPS 53" },
    { 6930, "AN/SPS 55" },
    { 6975, "AN/SPS-55 SS" },
    { 7020, "AN/SPS-58" },
    { 7065, "AN/SPS 59" },
    { 7110, "AN/SPS 64" },
    { 7155, "AN/SPS 65" },
    { 7200, "AN/SPS 67" },
    { 7245, "AN/SPY-1" },
    { 7250, "AN/SPY-1A" },
    { 7252, "AN/SPY-1B" },
    { 7253, "AN/SPY-1B(V)" },
    { 7260, "AN/SPY-1D" },
    { 7261, "AN/SPY-1D(V)" },
    { 7265, "AN/SPY-1F" },
    { 7270, "AN/TPN-17" },
    { 7275, "AN/TPN-24" },
    { 7280, "AN/TPQ-18" },
    { 7295, "AN/TPQ-36" },
    { 7300, "AN/TPQ-37" },
    { 7301, "AN/TPQ-38 (V8)" },
    { 7303, "AN/TPQ-47" },
    { 7305, "AN/TPS-43" },
    { 7310, "AN/TPS-43E" },
    { 7315, "AN/TPS-59" },
    { 7320, "AN/TPS-63" },
    { 7322, "AN/TPS-70 (V) 1" },
    { 7325, "AN/TPS-75" },
    { 7330, "AN/TPX-46(V)7" },
    { 7335, "AN/ULQ-6A" },
    { 7380, "AN/UPN 25" },
    { 7425, "AN/UPS 1" },
    { 7426, "AN/UPS-2" },
    { 7470, "AN/UPX 1" },
    { 7515, "AN/UPX 5" },
    { 7560, "AN/UPX 11" },
    { 7605, "AN/UPX 12" },
    { 7650, "AN/UPX 17" },
    { 7695, "AN/UPX 23" },
    { 7740, "AN/VPS 2" },
    { 7785, "Apelco AD 7 7" },
    { 7830, "APG 71" },
    { 7875, "APN 148" },
    { 7920, "APN 227" },
    { 7965, "(deleted)" },
    { 8010, "(deleted)" },
    { 8055, "(deleted)" },
    { 8100, "APS 504 V3" },
    { 8105, "AR 3D" },
    { 8112, "Plessey AR-5" },
    { 8115, "AR 320" },
    { 8120, "AR 327" },
    { 8145, "AR M31" },
    { 8190, "ARI 5954" },
    { 8235, "ARI 5955" },
    { 8280, "ARI 5979" },
    { 8325, "ARINC 564 BNDX/KING RDR 1E" },
    { 8370, "ARINC 700 BNDX/KING RDR 1E" },
    { 8375, "ARK-1" },
    { 8380, "ARSR-3" },
    { 8390, "ARSR-18" },
    { 8415, "AS 2 Kipper" },
    { 8460, "AS 2 Kipper MH" },
    { 8505, "AS 4 Kitchen" },
    { 8550, "AS 4 Kitchen MH" },
    { 8595, "AS 5 Kelt MH" },
    { 8640, "AS 6 Kingfish MH" },
    { 8685, "AS 7 Kerry" },
    { 8730, "AS 7 Kerry MG" },
    { 8735, "AS 15 KENT altimeter" },
    { 8760, "Aspide AAM/SAM ILL" },
    { 8772, "ASR-4" },
    { 8775, "ASR O" },
    { 8780, "ASR-5" },
    { 8782, "ASR-7" },
    { 8785, "ASR-8" },
    { 8790, "ASR-9" },
    { 8812, "Raytheon ASR-10SS" },
    { 8820, "AT 2 Swatter MG" },
    { 8840, "ATCR-33" },
    { 8845, "ATCR 33 K/M" },
    { 8865, "Atlas Elektronk TRS N" },
    { 8870, "ATLAS-9740 VTS" },
    { 8910, "AVG 65" },
    { 8955, "AVH 7" },
    { 9000, "AVQ 20" },
    { 9045, "AVQ30X" },
    { 9075, "AVQ-50 (RCA)" },
    { 9090, "AVQ 70" },
    { 9135, "AWS 5" },
    { 9180, "AWS 6" },
    { 9200, "B597Z" },
    { 9205, "B636Z" },
    { 9225, "Back Net A B" },
    { 9270, "Back Trap" },
    { 9310, "BALTYK" },
    { 9315, "Ball End" },
    { 9360, "Ball Gun" },
    { 9405, "Band Stand" },
    { 9450, "P-35/37 (A); P-50 (B), Bar Lock" },
    { 9495, "Bass Tilt" },
    { 9540, "Beacon" },
    { 9585, "Bean Sticks" },
    { 9630, "Bee Hind" },
    { 9640, "Bell Crown A" },
    { 9642, "Bell Crown B" },
    { 9645, "BIG BACK" },
    { 9660, "Big Bird" },
    { 9675, "Big Bulge" },
    { 9720, "Big Bulge A" },
    { 9765, "Big Bulge B" },
    { 9780, "SNAR-10, Big Fred" },
    { 9810, "Big Mesh" },
    { 9855, "Big Net" },
    { 9885, "9S15MT, Bill Board" },
    { 9900, "Bill Fold" },
    { 9905, "Blowpipe MG" },
    { 9930, "Blue Fox, Sea Harrier FRS Mk 1/5" },
    { 9935, "Blue Vixen, Sea Harrier F/A Mk 2" },
    { 9945, "Blue Silk" },
    { 9990, "Blue Parrot" },
    { 10035, "Blue Orchid" },
    { 10080, "Boat Sail" },
    { 10125, "Bofors Electronic 9LV 331" },
    { 10170, "Bofors Ericsson Sea Giraffe 50 HC" },
    { 10215, "Bowl Mesh" },
    { 10260, "Box Brick" },
    { 10305, "Box Tail" },
    { 10350, "BPS 11A" },
    { 10395, "BPS 14" },
    { 10440, "BPS 15A" },
    { 10485, "BR-15 Tokyo KEIKI" },
    { 10510, "BRIDGEMASTE" },
    { 10530, "Bread Bin" },
    { 10575, "BT 271" },
    { 10620, "BX 732" },
    { 10665, "Buzz Stand" },
    { 10710, "C 5A Multi Mode Radar" },
    { 10755, "Caiman" },
    { 10800, "Cake Stand" },
    { 10845, "Calypso C61" },
    { 10890, "Calypso Ii" },
    { 10895, "Cardion Coastal" },
    { 10935, "Castor Ii" },
    { 10940, "Castor 2J TT (Crotale NG)" },
    { 10980, "Cat House" },
    { 10985, "CDR-431" },
    { 11000, "Chair Back TT" },
    { 11010, "Chair Back ILL" },
    { 11025, "Cheese Brick" },
    { 11070, "Clam Pipe" },
    { 11115, "Clamshell" },
    { 11160, "Collins WXR-700X" },
    { 11205, "Collins DN 101" },
    { 11250, "Contraves Sea Hunter MK 4" },
    { 11260, "Corn Can" },
    { 11270, "CR-105 RMCA" },
    { 11295, "Cross Bird" },
    { 11340, "Cross Dome" },
    { 11385, "Cross Legs" },
    { 11430, "Cross Out" },
    { 11475, "Cross Slot" },
    { 11520, "Cross Sword" },
    { 11565, "Cross Up" },
    { 11610, "Cross Sword FC" },
    { 11655, "Crotale Acquisition TA, THD-5000" },
    { 11660, "Crotale NG TA, Griffon" },
    { 11665, "Crotale TT" },
    { 11700, "Crotale MGMissile System" },
    { 11745, "CSS C 3C CAS 1M1 M2 MH" },
    { 11790, "CSS C 2B HY 1A MH" },
    { 11835, "CWS 2" },
    { 11880, "Cylinder Head" },
    { 11925, "Cyrano II" },
    { 11970, "Cyrano IV" },
    { 11975, "Cyrano IV-M" },
    { 12010, "DA-01/00" },
    { 12015, "DA 05 00" },
    { 12060, "Dawn" },
    { 12105, "Dead Duck" },
    { 12110, "DECCA-20 V90/9" },
    { 12111, "DECCA-20 V90S" },
    { 12150, "DECCA 45" },
    { 12195, "DECCA 50" },
    { 12240, "DECCA 110" },
    { 12285, "DECCA 170" },
    { 12292, "DECCA HF 2" },
    { 12330, "DECCA 202" },
    { 12375, "DECCA D202" },
    { 12420, "DECCA 303" },
    { 12430, "DECCA 535" },
    { 12465, "DECCA 626" },
    { 12510, "DECCA 629" },
    { 12555, "DECCA 914" },
    { 12600, "DECCA 916" },
    { 12610, "DECCA 926" },
    { 12645, "DECCA 1226 Commercial" },
    { 12690, "DECCA 1626" },
    { 12735, "DECCA 2459" },
    { 12780, "DECCA AWS 1" },
    { 12782, "DECCA AWS 2" },
    { 12785, "DECCA AWS 4" },
    { 12787, "DECCA AWS-4 (2)" },
    { 12800, "DECCA MAR" },
    { 12805, "DECCA RM 326" },
    { 12825, "DECCA RM 416" },
    { 12870, "DECCA RM 914" },
    { 12915, "DECCA RM 1690" },
    { 12960, "DECCA Super 101 MK 3" },
    { 13005, "DISS 1" },
    { 13050, "Rapier TTDN 181, DN 181" },
    { 13055, "Rapier 2000 TT, BLINDFIRE FSC TT" },
    { 13095, "Dog Ear" },
    { 13140, "Dog House" },
    { 13185, "Don 2" },
    { 13230, "Don A/B/2/Kay" },
    { 13275, "Donets" },
    { 13320, "Down Beat" },
    { 13365, "DRAA 2A" },
    { 13410, "DRAA 2B" },
    { 13455, "DRAC 39" },
    { 13500, "DRBC 30B" },
    { 13545, "DRBC 31A" },
    { 13590, "DRBC 32A" },
    { 13635, "DRBC 32D" },
    { 13680, "DRBC 33A" },
    { 13725, "DRBI 10" },
    { 13770, "DRBI 23" },
    { 13815, "DRBJ 11B" },
    { 13860, "DRBN 30" },
    { 13905, "DRBN 32" },
    { 13950, "DRBR 51" },
    { 13995, "DRBV 20B" },
    { 14040, "DRBV 22" },
    { 14085, "DRBV 26C" },
    { 14130, "DRBV 30" },
    { 14175, "DRBV 50" },
    { 14220, "DRBV 51" },
    { 14265, "DRBV 51A" },
    { 14310, "DRBV 51B" },
    { 14355, "DRBV 51C" },
    { 14400, "Drop Kick" },
    { 14445, "DRUA 31" },
    { 14490, "Drum Tilt" },
    { 14535, "Drum Tilt A" },
    { 14545, "Drum Tilt B" },
    { 14580, "Dumbo" },
    { 14600, "ECR-90" },
    { 14625, "Egg Cup A/B" },
    { 14670, "EKCO 190" },
    { 14715, "EL M 2001B" },
    { 14760, "EL M 2207" },
    { 14770, "EL/M 2216(V)" },
    { 14805, "ELTA EL/M 2221 GM STGR" },
    { 14810, "ELTA SIS" },
    { 14850, "EMD 2900" },
    { 14895, "End Tray" },
    { 14940, "Exocet 1" },
    { 14985, "Exocet 1 MH" },
    { 15030, "Exocet 2" },
    { 15075, "Eye Bowl" },
    { 15120, "Eye Shield" },
    { 15140, "F332Z" },
    { 15160, "FALCON" },
    { 15165, "Fan Song A" },
    { 15200, "Fan Song B/F TA" },
    { 15210, "Fan Song B/F TT" },
    { 15220, "Fan Song C/E TA" },
    { 15230, "Fan Song C/E TT" },
    { 15240, "Fan Song C/E MG" },
    { 15255, "Fan Song B/FF MG" },
    { 15300, "Fan Tail" },
    { 15310, "FCR-1401" },
    { 15345, "Fin Curve" },
    { 15390, "Fire Can" },
    { 15435, "Fire Dish" },
    { 15470, "Fire Dome TA" },
    { 15475, "Fire Dome TT" },
    { 15480, "Fire Dome TI" },
    { 15525, "Fire Iron" },
    { 15570, "Fire Wheel" },
    { 15615, "Fish Bowl" },
    { 15660, "Flap Lid" },
    { 15705, "Flap Truck" },
    { 15750, "Flap Wheel" },
    { 15795, "Flash Dance" },
    { 15840, "P-15, Flat Face A B C D" },
    { 15885, "Flat Screen" },
    { 15930, "Flat Spin" },
    { 15975, "Flat Twin" },
    { 16020, "Fledermaus" },
    { 16030, "FLYCATCHER" },
    { 16065, "Fly Screen" },
    { 16110, "Fly Screen A&B" },
    { 16155, "Fly Trap B" },
    { 16200, "Fog Lamp MG" },
    { 16245, "Fog Lamp TT" },
    { 16290, "Foil Two" },
    { 16335, "Fox Hunter" },
    { 16380, "FOX FIREFox Fire AL" },
    { 16390, "FOX FIRE ILL" },
    { 16400, "FR-151A" },
    { 16410, "FR-1505 DA" },
    { 16420, "FR-2000" },
    { 16421, "FR-2855W" },
    { 16425, "Front Dome" },
    { 16470, "Front Door" },
    { 16515, "Front Piece" },
    { 16560, "Furuno" },
    { 16561, "Furuno 1721" },
    { 16605, "Furuno 701" },
    { 16650, "Furuno 711 2" },
    { 16695, "Furuno 2400" },
    { 16740, "GA 01 00" },
    { 16785, "Gage" },
    { 16830, "Garpin" },
    { 16875, "GEM BX 132" },
    { 16880, "MPDR-12, Gepard TA" },
    { 16884, "Gepard TT" },
    { 16888, "GERAN-F" },
    { 16900, "GIRAFFE" },
    { 16915, "Gin Sling TA" },
    { 16920, "Gin Sling, Gin Sling TT" },
    { 16925, "Gin Sling MG" },
    { 16945, "GPN-22" },
    { 16950, "GRN-9" },
    { 16965, "Green Stain" },
    { 17010, "Grid Bow" },
    { 17025, "9S32, GRILL PAN TT" },
    { 17055, "Guardsman" },
    { 17070, "RPK-2, GUN DISH (ZSU-23/4)" },
    { 17100, "Hair Net" },
    { 17145, "Half Plate A" },
    { 17190, "Half Plate B" },
    { 17220, "HARD" },
    { 17235, "Hawk Screech" },
    { 17280, "Head Light A" },
    { 17325, "Head Lights" },
    { 17370, "Head Lights C" },
    { 17415, "Head Lights MG A" },
    { 17460, "Head Lights MG B" },
    { 17505, "Head Lights TT" },
    { 17550, "Head Net" },
    { 17595, "Hen Egg" },
    { 17640, "Hen House" },
    { 17685, "Hen Nest" },
    { 17730, "Hen Roost" },
    { 17775, "High Brick" },
    { 17820, "High Fix" },
    { 17865, "High Lark TI" },
    { 17910, "High Lark 1" },
    { 17955, "High Lark 2" },
    { 18000, "High Lark 4" },
    { 18045, "High Lune" },
    { 18090, "High Pole A&B" },
    { 18135, "High Scoop" },
    { 18150, "9S19MT, HIGH SCREEN" },
    { 18180, "High Sieve" },
    { 18200, "HN-503" },
    { 18225, "Home Talk" },
    { 18270, "Horn Spoon" },
    { 18280, "HOT BRICK" },
    { 18315, "Hot Flash" },
    { 18320, "IRL144M, Hot Shot TA" },
    { 18325, "IRL144M, Hot Shot TT" },
    { 18330, "IRL144M, Hot Shot MG" },
    { 18360, "IFF MK XII AIMS UPX 29" },
    { 18405, "IFF MK XV" },
    { 18410, "Javelin MG" },
    { 18450, "Jay Bird" },
    { 18460, "JRC-NMD-401" },
    { 18495, "Jupiter" },
    { 18540, "Jupiter II" },
    { 18550, "JY-8" },
    { 18555, "JY-9" },
    { 18560, "JY-14" },
    { 18585, "K376Z" },
    { 18630, "Kelvin Hughes 2A" },
    { 18675, "Kelvin Hughes 14/9" },
    { 18720, "Kelvin Hughes type 1006" },
    { 18765, "Kelvin Hughes type 1007" },
    { 18785, "KH-902M" },
    { 18810, "Kite Screech" },
    { 18855, "Kite Screech A" },
    { 18900, "Kite Screech B" },
    { 18945, "Kivach" },
    { 18990, "Knife Rest" },
    { 19035, "P-10, Knife Rest B" },
    { 19037, "KNIFE REST C" },
    { 19050, "KR-75" },
    { 19080, "KSA SRN" },
    { 19125, "KSA TSR" },
    { 19170, "Land Fall" },
    { 19215, "Land Roll MG" },
    { 19260, "Land Roll TA" },
    { 19305, "Land Roll TT" },
    { 19310, "LC-150" },
    { 19350, "Leningraf" },
    { 19395, "Light Bulb" },
    { 19400, "LMT NRAI-6A" },
    { 19440, "LN 55" },
    { 19485, "Ln 66" },
    { 19530, "Long Bow" },
    { 19575, "Long Brick" },
    { 19620, "Long Bull" },
    { 19665, "Long Eye" },
    { 19710, "Long Head" },
    { 19755, "Long Talk" },
    { 19800, "Long Track" },
    { 19845, "Long Trough" },
    { 19890, "Look Two" },
    { 19935, "LORAN" },
    { 19950, "Low Blow TA" },
    { 19955, "Low Blow TT" },
    { 19960, "Low Blow MG" },
    { 19980, "Low Sieve" },
    { 20025, "Low Trough" },
    { 20040, "TRS-2050, LP-23" },
    { 20070, "LW 08" },
    { 20090, "M-1983 FCR" },
    { 20115, "M22-40" },
    { 20160, "M44" },
    { 20205, "M401Z" },
    { 20250, "M585Z" },
    { 20295, "M588Z" },
    { 20340, "MA 1 IFF Portion" },
    { 20360, "MARELD" },
    { 20385, "MA Type 909#" },
    { 20430, "Marconi 1810" },
    { 20475, "Marconi Canada HC 75" },
    { 20495, "Marconi S 713" },
    { 20520, "Marconi S 1802" },
    { 20530, "Marconi S247" },
    { 20565, "Marconi S 810" },
    { 20585, "Marconi SA 10" },
    { 20610, "Marconi type 967" },
    { 20655, "Marconi type 968" },
    { 20700, "Marconi type 992" },
    { 20745, "Marconi/signaal type 1022" },
    { 20790, "Marconi/signaal type 910" },
    { 20835, "Marconi/signaal type 911" },
    { 20880, "Marconi/signaal type 992R" },
    { 20925, "Mesh Brick" },
    { 20950, "Mirage ILL" },
    { 20970, "MK 15 CIWS" },
    { 21015, "MK-23" },
    { 21060, "MK 23 TAS" },
    { 21105, "MK 25" },
    { 21150, "MK-35 M2" },
    { 21195, "MK 92" },
    { 21240, "MK-92 CAS" },
    { 21285, "MK-92 STIR" },
    { 21330, "MK 95" },
    { 21340, "MLA-1" },
    { 21375, "MM APS 705" },
    { 21420, "MM SPG 74" },
    { 21465, "MM SPG 75" },
    { 21490, "MM SPN 703" },
    { 21510, "MM SPS 702" },
    { 21555, "MM SPS 768" },
    { 21600, "MM SPS 774" },
    { 21645, "Moon 4" },
    { 21650, "MMRS" },
    { 21690, "MPDR 18 X" },
    { 21710, "MT-305X" },
    { 21735, "Muff Cob" },
    { 21780, "Mushroom" },
    { 21825, "Mushroom 1" },
    { 21870, "Mushroom 2" },
    { 21880, "N920Z" },
    { 21890, "Nanjing B" },
    { 21895, "Nanjing C" },
    { 21915, "Nayada" },
    { 21960, "Neptun" },
    { 21980, "NIKE TT" },
    { 22005, "NRBA 50" },
    { 22050, "NRBA 51" },
    { 22095, "NRBF 20A" },
    { 22140, "Nysa B" },
    { 22185, "O524A" },
    { 22230, "O580B" },
    { 22275, "O625Z" },
    { 22320, "O626Z" },
    { 22345, "Odd Group" },
    { 22365, "Odd Lot" },
    { 22410, "Odd Pair" },
    { 22455, "Oka" },
    { 22500, "OKEAN" },
    { 22545, "OKINXE 12C" },
    { 22590, "OMEGA" },
    { 22635, "Omera ORB32" },
    { 22680, "One Eye" },
    { 22690, "OP-28" },
    { 22725, "OPS-16B" },
    { 22730, "OPS-18" },
    { 22740, "OPS-28" },
    { 22770, "OR-2" },
    { 22810, "ORB-31S" },
    { 22815, "ORB 32" },
    { 22860, "Orion Rtn 10X" },
    { 22905, "Otomat MK II Teseo" },
    { 22950, "Owl Screech" },
    { 22955, "P360Z" },
    { 22960, "PA-1660" },
    { 22995, "Palm Frond" },
    { 23040, "Palm Frond AB" },
    { 23085, "Pat Hand TT" },
    { 23095, "Pat Hand MG" },
    { 23130, "Patty Cake" },
    { 23175, "Pawn Cake" },
    { 23220, "PBR 4 Rubin" },
    { 23265, "Pea Sticks" },
    { 23310, "Peel Cone" },
    { 23355, "Peel Group" },
    { 23400, "Peel Group A" },
    { 23445, "Peel Group B" },
    { 23490, "Peel Pair" },
    { 23535, "Philips 9LV 200" },
    { 23580, "Philips 9LV 331" },
    { 23625, "Philips LV 223" },
    { 23670, "Philips Sea Giraffe 50 HC" },
    { 23690, "Pin Jib" },
    { 23710, "Plank Shad" },
    { 23715, "Plank Shave" },
    { 23760, "Plank Shave A" },
    { 23805, "Plank Shave B" },
    { 23850, "Plate Steer" },
    { 23895, "Plessey AWS 1" },
    { 23940, "Plessey AWS 4" },
    { 23985, "Plessey AWS 6" },
    { 23990, "Plessey RJ" },
    { 24030, "Plessey type 996" },
    { 24075, "Plinth Net" },
    { 24095, "Pluto" },
    { 24100, "POHJANPALO" },
    { 24120, "POLLUX" },
    { 24165, "Pop Group" },
    { 24210, "Pop Group MG" },
    { 24255, "Pop Group TA" },
    { 24300, "Pop Group TT" },
    { 24345, "Pork Trough" },
    { 24390, "Post Bow" },
    { 24435, "Post Lamp" },
    { 24480, "Pot Drum" },
    { 24525, "Pot Head" },
    { 24570, "PRIMUS 40 WXD" },
    { 24615, "PRIMUS 300SL" },
    { 24620, "Primus 3000" },
    { 24650, "PS-05A" },
    { 24660, "PS 46 A" },
    { 24705, "PS 70 R" },
    { 24710, "PS-890" },
    { 24750, "Puff Ball" },
    { 24770, "R-76" },
    { 24780, "RAC-30" },
    { 24795, "Racal 1229" },
    { 24840, "Racal AC 2690 BT" },
    { 24885, "Racal Decca 1216" },
    { 24930, "Racal Decca 360" },
    { 24975, "Racal Decca AC 1290" },
    { 25020, "Racal Decca TM 1229" },
    { 25065, "Racal Decca TM 1626" },
    { 25110, "Racal DRBN 34A" },
    { 25155, "Radar 24" },
    { 25200, "RAN 7S" },
    { 25205, "RAN 10S" },
    { 25245, "RAN 11 LX" },
    { 25260, "Rapier TA" },
    { 25265, "Rapier 2000 TA, Dagger" },
    { 25270, "Rapier MG" },
    { 25280, "RAT-31S" },
    { 25285, "RATAC (LCT)" },
    { 25290, "Raytheon 1220" },
    { 25300, "Raytheon 1302" },
    { 25335, "Raytheon 1500" },
    { 25380, "Raytheon 1645" },
    { 25425, "Raytheon 1650" },
    { 25470, "Raytheon 1900" },
    { 25515, "Raytheon 2502" },
    { 25560, "Raytheon TM 1650/6X" },
    { 25605, "Raytheon TM 1660/12S" },
    { 25630, "RAY-1220XR" },
    { 25635, "RAY-1401" },
    { 25650, "Ray 2900" },
    { 25695, "Raypath" },
    { 25735, "RBE2" },
    { 25740, "RDM" },
    { 25760, "RDY" },
    { 25785, "RDN 72" },
    { 25830, "RDR 1A" },
    { 25835, "RDR 1E" },
    { 25840, "RDR 4A" },
    { 25875, "RDR 1200" },
    { 25885, "RDR 1400" },
    { 25890, "RDR 1400 C" },
    { 25895, "RDR 1500" },
    { 25920, "Rice Lamp" },
    { 25965, "Rice Pad" },
    { 26010, "Rice Screen" },
    { 26055, "ROLAND BN" },
    { 26100, "ROLAND MG" },
    { 26145, "ROLAND TA" },
    { 26190, "ROLAND TT" },
    { 26235, "Round Ball" },
    { 26280, "Round House" },
    { 26325, "Round House B" },
    { 26330, "RT-02/50" },
    { 26350, "RTN-1A" },
    { 26370, "RV2" },
    { 26415, "RV3" },
    { 26460, "RV5" },
    { 26505, "RV10" },
    { 26550, "RV17" },
    { 26595, "RV18" },
    { 26610, "RV-377" },
    { 26640, "RV UM" },
    { 26660, "RXN 2-60" },
    { 26670, "S-1810CD" },
    { 26685, "SA 2 Guideline" },
    { 26730, "SA 3 Goa" },
    { 26775, "SA 8 Gecko DT" },
    { 26795, "SA-12 TELAR ILL" },
    { 26820, "SA N 7 Gadfly TI" },
    { 26865, "SA N 11 Cads 1 UN" },
    { 26910, "Salt Pot A&B" },
    { 26955, "SATURNE II" },
    { 27000, "Scan Can" },
    { 27045, "Scan Fix" },
    { 27090, "Scan Odd" },
    { 27135, "Scan Three" },
    { 27140, "SCANTER (CSR)" },
    { 27141, "SCORADS" },
    { 27150, "SCOREBOARD" },
    { 27180, "Scoup Plate" },
    { 27190, "SCR-584" },
    { 27225, "Sea Archer 2" },
    { 27270, "Sea Hunter 4 MG" },
    { 27315, "Sea Hunter 4 TA" },
    { 27360, "Sea Hunter 4 TT" },
    { 27405, "Sea Gull" },
    { 27450, "Sea Net" },
    { 27495, "Sea Spray" },
    { 27540, "Sea Tiger" },
    { 27570, "Searchwater" },
    { 27585, "Selenia Orion 7" },
    { 27630, "Selenia type 912" },
    { 27675, "Selennia RAN 12 L/X" },
    { 27720, "Selennia RTN 10X" },
    { 27765, "Selinia ARP 1645" },
    { 27810, "SGR 102 00" },
    { 27855, "SGR 103/02" },
    { 27870, "SGR-104" },
    { 27900, "Sheet Bend" },
    { 27945, "Sheet Curve" },
    { 27990, "Ship Globe" },
    { 28035, "Ship Wheel" },
    { 28080, "SGR 114" },
    { 28125, "Shore Walk A" },
    { 28170, "Short Horn" },
    { 28215, "Shot Dome" },
    { 28260, "Side Globe JN" },
    { 28280, "PRV-11, Side Net" },
    { 28305, "Side Walk A" },
    { 28350, "Signaal DA 02" },
    { 28395, "Signaal DA 05" },
    { 28440, "Signaal DA 08" },
    { 28485, "Signaal LW 08" },
    { 28530, "Signaal LWOR" },
    { 28575, "Signaal M45" },
    { 28620, "Signaal MW 08" },
    { 28665, "Signaal SMART" },
    { 28710, "Signaal STING" },
    { 28755, "Signaal STIR" },
    { 28800, "Signaal WM 20/2" },
    { 28845, "Signaal WM 25" },
    { 28890, "Signaal WM 27" },
    { 28935, "Signaal WM 28" },
    { 28980, "Signaal ZW 01" },
    { 29025, "Signaal ZW 06" },
    { 29070, "Ski Pole" },
    { 29115, "Skin Head" },
    { 29160, "Skip Spin" },
    { 29185, "SKYGUARD TA, UAR-1021" },
    { 29190, "SKYGUARD TT, UAR-1021" },
    { 29205, "Sky Watch" },
    { 29215, "SKYSHADOW" },
    { 29220, "SKYSHIELD TA" },
    { 29250, "SL" },
    { 29270, "SL/ALQ-234" },
    { 29295, "Slap Shot E" },
    { 29340, "Slim Net" },
    { 29385, "Slot Back A" },
    { 29400, "Slot Back ILL" },
    { 29430, "Slot Back B" },
    { 29440, "Slot Rest" },
    { 29475, "SMA 3 RM" },
    { 29520, "SMA 3 RM 20" },
    { 29565, "SMA 3RM 20A/SMG" },
    { 29610, "SMA BPS 704" },
    { 29655, "SMA SPIN 749 (V) 2" },
    { 29700, "SMA SPN 703" },
    { 29745, "SMA SPN 751" },
    { 29790, "SMA SPOS 748" },
    { 29835, "SMA SPQ 2" },
    { 29880, "SMA SPQ 2D" },
    { 29925, "SMA SPQ 701" },
    { 29970, "SMA SPS 702 UPX" },
    { 30015, "SMA ST 2 OTOMAT II MH" },
    { 30060, "SMA 718 Beacon" },
    { 30080, "SNAP SHOT" },
    { 30105, "Snoop Drift" },
    { 30150, "Snoop Head" },
    { 30195, "Snoop Pair" },
    { 30240, "Snoop Plate" },
    { 30285, "Snoop Slab" },
    { 30330, "Snoop Tray" },
    { 30375, "Snoop Tray 1" },
    { 30420, "Snoop Tray 2" },
    { 30465, "Snoop Watch" },
    { 30470, "9S18M1, Snow Drift" },
    { 30510, "SO-1" },
    { 30520, "SO-12" },
    { 30555, "SO A Communist" },
    { 30580, "SO-69" },
    { 30600, "Sock Eye" },
    { 30645, "SOM 64" },
    { 30670, "SPADA TT" },
    { 30690, "Sparrow (AIM/RIM-7) ILL" },
    { 30700, "Sperry M-3" },
    { 30735, "SPG 53F" },
    { 30780, "SPG 70 (RTN 10X)" },
    { 30825, "SPG 74 (RTN 20X)" },
    { 30870, "SPG 75 (RTN 30X)" },
    { 30915, "SPG 76 (RTN 30X)" },
    { 30960, "Spin Scan A" },
    { 31005, "Spin Scan B" },
    { 31050, "Spin Trough" },
    { 31095, "Splash Drop" },
    { 31140, "SPN 35A" },
    { 31185, "SPN 41" },
    { 31230, "SPN 42" },
    { 31275, "SPN 43A" },
    { 31320, "SPN 43B" },
    { 31365, "SPN 44" },
    { 31410, "SPN 46" },
    { 31455, "SPN 703" },
    { 31500, "SPN 728 (V) 1" },
    { 31545, "SPN 748" },
    { 31590, "SPN 750" },
    { 31635, "Sponge Cake" },
    { 31680, "P-12, Spoon Rest" },
    { 31681, "P-18, Spoon Rest A" },
    { 31682, "P-18, Spoon Rest B" },
    { 31684, "P-18, Spoon Rest D" },
    { 31725, "SPQ 712 (RAN 12 L/X)" },
    { 31770, "SPS 6C" },
    { 31815, "SPS 10F" },
    { 31860, "SPS 12" },
    { 31905, "(deleted)SPS 58" },
    { 31950, "(deleted)SPS 64" },
    { 31995, "SPS 768 (RAN EL)" },
    { 32040, "SPS 774 (RAN 10S)" },
    { 32085, "SPY 790" },
    { 32130, "Square Head" },
    { 32175, "Square Pair" },
    { 32220, "Square Slot" },
    { 32265, "Square Tie" },
    { 32310, "Squash Dome" },
    { 32330, "P-15M, Squat Eye" },
    { 32355, "Squint Eye" },
    { 32400, "SRN 6" },
    { 32445, "SRN 15" },
    { 32490, "SRN 745" },
    { 32535, "SRO 1" },
    { 32580, "SRO 2" },
    { 32625, "SS C 2B Samlet MG" },
    { 32670, "SS N 2A B CSSC" },
    { 32715, "SS N 2A B CSSC 2A 3A2 MH" },
    { 32760, "SS N 2C Seeker" },
    { 32805, "SS N 2C D Styx" },
    { 32850, "SS N 2C D Styx C D MH" },
    { 32895, "SS N 3 SSC SS C 18 BN" },
    { 32940, "SS N 3B Sepal AL" },
    { 32985, "SS N 3B Sepal MH" },
    { 33030, "SS N 9 Siren" },
    { 33075, "SS N 9 Siren AL" },
    { 33120, "SS N 9 Siren MH" },
    { 33165, "SS N 12 Sandbox AL" },
    { 33210, "SS N 12 Sandbox MH" },
    { 33255, "SS N 19 Shipwreck" },
    { 33300, "SS N 19 Shipwreck AL" },
    { 33345, "SS N 19 Shipwreck MH" },
    { 33390, "SS N 21 AL" },
    { 33435, "SS N 22 Sunburn" },
    { 33480, "SS N 22 Sunburn MH" },
    { 33525, "Stone Cake" },
    { 33570, "STR 41" },
    { 33590, "Straight Flush TA" },
    { 33595, "Straight Flush TT" },
    { 33600, "Straight Flush ILL" },
    { 33615, "Strike Out" },
    { 33660, "Strut Curve" },
    { 33705, "Strut Pair" },
    { 33750, "Strut Pair 1" },
    { 33795, "Strut Pair 2" },
    { 33840, "Sun Visor" },
    { 33860, "Superfledermaus" },
    { 33885, "Swift Rod 1" },
    { 33930, "Swift Rod 2" },
    { 33975, "T1166" },
    { 34020, "T1171" },
    { 34040, "T1202" },
    { 34065, "T6004" },
    { 34110, "T6031" },
    { 34155, "T8067" },
    { 34200, "T8068" },
    { 34245, "T8124" },
    { 34290, "T8408" },
    { 34335, "T8911" },
    { 34380, "T8937" },
    { 34425, "T8944" },
    { 34470, "T8987" },
    { 34515, "P-14, Tall King" },
    { 34560, "Tall Mike" },
    { 34605, "Tall Path" },
    { 34625, "Team Work" },
    { 34640, "THAAD GBR" },
    { 34650, "THD 225" },
    { 34670, "THD 1940, Picador" },
    { 34695, "THD 5500" },
    { 34740, "Thin Path" },
    { 34785, "PRV-9, Thin Skin" },
    { 34795, "Thompson CSF TA-10" },
    { 34830, "Thompson CSF TH D 1040 Neptune" },
    { 34875, "Thompson CSF Calypso" },
    { 34920, "Thompson CSF CASTOR" },
    { 34965, "Thompson CSF Castor II" },
    { 35010, "Thompson CSF DRBC 32A" },
    { 35055, "Thompson CSF DRBJ 11 D/E" },
    { 35100, "Thompson CSF DRBV 15A" },
    { 35145, "Thompson CSF DRBV 15C" },
    { 35190, "Thompson CSF DRBV 22D" },
    { 35235, "Thompson CSF DRBV 23B" },
    { 35280, "Thompson CSF DRUA 33" },
    { 35325, "Thompson CSF Mars DRBV 21A" },
    { 35370, "Thompson CSF Sea Tiger" },
    { 35415, "Thompson CSF Triton" },
    { 35460, "Thompson CSF Vega with DRBC 32E" },
    { 35480, "TRS-2105, TIGER-G" },
    { 35490, "TRS-2100, TIGER-S" },
    { 35505, "Tie Rods" },
    { 35550, "36D6, Tin Shield" },
    { 35570, "Tin Trap" },
    { 35580, "TIRSPONDER" },
    { 35595, "Toad Stool 1" },
    { 35640, "Toad Stool 2" },
    { 35685, "Toad Stool 3" },
    { 35730, "Toad Stool 4" },
    { 35775, "Toad Stool 5" },
    { 35800, "Tomb Stone" },
    { 35820, "Top Bow" },
    { 35865, "Top Dome" },
    { 35910, "Top Knot" },
    { 35955, "Top Mesh" },
    { 36000, "Top Pair" },
    { 36045, "Top Plate" },
    { 36090, "Top Sail" },
    { 36135, "Top Steer" },
    { 36180, "Top Trough" },
    { 36220, "Scrum Half TA" },
    { 36225, "TorScrum Half TT, Tor" },
    { 36230, "Scrum Half MG" },
    { 36270, "Track Dish" },
    { 36315, "TORSO M" },
    { 36360, "Trap Door" },
    { 36380, "TRISPONDE" },
    { 36405, "TRS 3033" },
    { 36420, "TRS 3405" },
    { 36425, "TRS 3410" },
    { 36430, "TRS 3415" },
    { 36450, "TRS-N" },
    { 36495, "TSE 5000" },
    { 36540, "TSR 333" },
    { 36585, "Tube Arm" },
    { 36630, "Twin Eyes" },
    { 36675, "Twin Pill" },
    { 36720, "Twin Scan" },
    { 36765, "Twin Scan Ro" },
    { 36810, "Two Spot" },
    { 36855, "TYPE 262" },
    { 36900, "TYPE 275" },
    { 36945, "TYPE 293" },
    { 36990, "TYPE 343 SUN VISOR B" },
    { 37035, "TYPE 347B" },
    { 37050, "Type-404A(CH)" },
    { 37080, "Type 756" },
    { 37125, "TYPE 903" },
    { 37170, "TYPE 909 TI" },
    { 37215, "TYPE 909 TT" },
    { 37260, "TYPE 910" },
    { 37265, "TYPE-931(CH)" },
    { 37305, "TYPE 965" },
    { 37350, "TYPE 967" },
    { 37395, "TYPE 968" },
    { 37440, "TYPE 974" },
    { 37485, "TYPE 975" },
    { 37530, "TYPE 978" },
    { 37575, "TYPE 992" },
    { 37620, "TYPE 993" },
    { 37665, "TYPE 994" },
    { 37710, "TYPE 1006(1)" },
    { 37755, "TYPE 1006(2)" },
    { 37800, "TYPE 1022" },
    { 37845, "UK MK 10" },
    { 37850, "UPS-220C" },
    { 37890, "UPX 1 10" },
    { 37935, "UPX 27" },
    { 37980, "URN 20" },
    { 38025, "URN 25" },
    { 38045, "VOLEX III/IV" },
    { 38070, "W8818" },
    { 38115, "W8838" },
    { 38120, "W8852" },
    { 38160, "WAS-74S" },
    { 38205, "Wasp Head" },
    { 38210, "WATCHDOG" },
    { 38250, "Watch Guard" },
    { 38260, "Watchman" },
    { 38295, "Western Electric MK 10" },
    { 38320, "Westinghouse ADR-4 LRSR" },
    { 38340, "Westinghouse Electric SPG 50" },
    { 38385, "Westinghouse Electric W 120" },
    { 38430, "Westinghouse SPS 29C" },
    { 38475, "Westinghouse SPS 37" },
    { 38520, "Wet Eye" },
    { 38565, "Wet Eye Mod" },
    { 38570, "WGU-41/B" },
    { 38572, "WGU-44/B" },
    { 38610, "Whiff" },
    { 38655, "Whiff Brick" },
    { 38700, "Whiff Fire" },
    { 38715, "WHITE HOUSE" },
    { 38745, "Wild Card" },
    { 38790, "Witch Eight" },
    { 38835, "Witch Five" },
    { 38880, "WM2X Series" },
    { 38925, "WM2X Series CAS" },
    { 38950, "WSR-74C" },
    { 38955, "WSR-74S" },
    { 38970, "Wood Gage" },
    { 39015, "Yard Rake" },
    { 39060, "Yew Loop" },
    { 39105, "Yo-Yo" },
    { 39150, "(deleted)" },
    { 0, NULL }
};

/******************************************************************************
*
* FIELDS
*
*******************************************************************************/
static gint proto_dis = -1;
static int hf_dis_proto_ver = -1;
static int hf_dis_exercise_id = -1;
static int hf_dis_pdu_type = -1;
static int hf_dis_proto_fam = -1;
static int hf_dis_pdu_length = -1;
static int hf_dis_entity_id_site = -1;
static int hf_dis_entity_id_application = -1;
static int hf_dis_entity_id_entity = -1;
static int hf_dis_num_art_params = -1;
static int hf_dis_entityKind = -1;
static int hf_dis_entityDomain = -1;
static int hf_dis_category_land = -1;
static int hf_dis_category_air = -1;
static int hf_dis_category_surface = -1;
static int hf_dis_category_subsurface = -1;
static int hf_dis_category_space = -1;
static int hf_dis_category_radio = -1;
static int hf_dis_num_electromagnetic_emission_systems = -1;
static int hf_dis_emitter_name = -1;
static int hf_dis_emission_function = -1;
static int hf_dis_beam_function = -1;
static int hf_dis_radio_id = -1;
static int hf_dis_ens = -1;
static int hf_dis_ens_class = -1;
static int hf_dis_ens_type = -1;
static int hf_dis_ens_type_audio = -1;
static int hf_dis_tdl_type = -1;
static int hf_dis_sample_rate = -1;
static int hf_dis_data_length = -1;
static int hf_dis_num_of_samples = -1;
static int hf_dis_signal_data = -1;
static int hf_dis_radio_category = -1;
static int hf_dis_nomenclature_version = -1;
static int hf_dis_nomenclature = -1;
static int hf_dis_radio_transmit_state = -1;
static int hf_dis_radio_input_source = -1;
static int hf_dis_antenna_pattern_type = -1;
static int hf_dis_antenna_pattern_length = -1;
static int hf_dis_transmit_frequency = -1;
static int hf_dis_spread_spectrum_usage = -1;
static int hf_dis_frequency_hopping = -1;
static int hf_dis_pseudo_noise_modulation = -1;
static int hf_dis_time_hopping = -1;
static int hf_dis_modulation_major = -1;
static int hf_dis_modulation_system = -1;
static int hf_dis_crypto_system = -1;
static int hf_dis_crypto_key = -1;
static int hf_dis_encryption_mode = -1;
static int hf_dis_key_identifier = -1;
static int hf_dis_modulation_parameter_length = -1;
static int hf_dis_mod_param_fh_net_id = -1;
static int hf_dis_mod_param_fh_set_id = -1;
static int hf_dis_mod_param_fh_lo_set_id = -1;
static int hf_dis_mod_param_fh_msg_start = -1;
static int hf_dis_mod_param_fh_reserved = -1;
static int hf_dis_mod_param_fh_sync_time_offset = -1;
static int hf_dis_mod_param_fh_security_key = -1;
static int hf_dis_mod_param_fh_clear_channel = -1;
static int hf_dis_mod_param_dump = -1;
static int hf_dis_mod_param_ts_allocation_mode = -1;
static int hf_dis_mod_param_transmitter_prim_mode = -1;
static int hf_dis_mod_param_transmitter_second_mode = -1;
static int hf_dis_mod_param_sync_state = -1;
static int hf_dis_mod_param_network_sync_id = -1;
static int hf_dis_antenna_pattern_parameter_dump = -1;
static int hf_dis_num_shafts = -1;
static int hf_dis_num_apas = -1;
static int hf_dis_num_ua_emitter_systems = -1;
static int hf_dis_signal_link16_npg = -1;
static int hf_dis_signal_link16_tsec_cvll = -1;
static int hf_dis_signal_link16_msec_cvll = -1;
static int hf_dis_signal_link16_message_type = -1;
static int hf_dis_signal_link16_ptt = -1;
static int hf_dis_signal_link16_time_slot_type = - 1;
static int hf_dis_signal_link16_rti = -1;
static int hf_dis_signal_link16_stn = -1;
static int hf_dis_signal_link16_sdusn = -1;

static gint ettVariableParameters[DIS_PDU_MAX_VARIABLE_PARAMETERS];
static gint ettVariableRecords[DIS_PDU_MAX_VARIABLE_RECORDS];

static gint ettFixedData = -1;
static gint ettVariableData = -1;

static gint ett_dis = -1;
static gint ett_dis_header = -1;
static gint ett_dis_po_header = -1;
static gint ett_dis_payload = -1;
static gint ett_dis_ens = -1;
static gint ett_dis_crypto_key = -1;
static gint ett_dis_signal_link16_network_header = -1;
static gint ett_dis_signal_link16_message_data = -1;
static gint ett_dis_signal_link16_jtids_header = -1;


/* enumeration of all field types used for DIS parsing. */
typedef enum
{
    /* end marker to indicate the end of a parser sequence */
    DIS_FIELDTYPE_END = 0,

    /* basic numeric types */
    DIS_FIELDTYPE_INT8,
    DIS_FIELDTYPE_INT16,
    DIS_FIELDTYPE_INT32,
    DIS_FIELDTYPE_INT64,
    DIS_FIELDTYPE_UINT8,
    DIS_FIELDTYPE_UINT16,
    DIS_FIELDTYPE_UINT32,
    DIS_FIELDTYPE_UINT64,
    DIS_FIELDTYPE_FLOAT32,
    DIS_FIELDTYPE_FLOAT64,

    /* padding */
    DIS_FIELDTYPE_PAD8,
    DIS_FIELDTYPE_PAD16,
    DIS_FIELDTYPE_PAD24,
    DIS_FIELDTYPE_PAD32,

    /* enumerations */
    DIS_FIELDTYPE_ACKNOWLEDGE_FLAG,
    DIS_FIELDTYPE_ACTION_ID,
    DIS_FIELDTYPE_APPLICATION_GENERAL_STATUS,
    DIS_FIELDTYPE_APPLICATION_STATUS_TYPE,
    DIS_FIELDTYPE_APPLICATION_TYPE,
    DIS_FIELDTYPE_CATEGORY,
    DIS_FIELDTYPE_CONTROL_ID,
    DIS_FIELDTYPE_DETONATION_RESULT,
    DIS_FIELDTYPE_DOMAIN,
    DIS_FIELDTYPE_ENTITY_KIND,
    DIS_FIELDTYPE_FROZEN_BEHAVIOR,
    DIS_FIELDTYPE_PARAMETER_TYPE_DESIGNATOR,
    DIS_FIELDTYPE_PDU_TYPE,
    DIS_FIELDTYPE_PERSISTENT_OBJECT_TYPE,
    DIS_FIELDTYPE_PERSISTENT_OBJECT_CLASS,
    DIS_FIELDTYPE_PROTOCOL_FAMILY,
    DIS_FIELDTYPE_PROTOCOL_VERSION,
    DIS_FIELDTYPE_REASON,
    DIS_FIELDTYPE_REQUEST_STATUS,
    DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE,
    DIS_FIELDTYPE_RESPONSE_FLAG,
    DIS_FIELDTYPE_TDL_TYPE,
    DIS_FIELDTYPE_RADIO_CATEGORY,
    DIS_FIELDTYPE_NOMENCLATURE_VERSION,
    DIS_FIELDTYPE_NOMENCLATURE,
    DIS_FIELDTYPE_RADIO_TRANSMIT_STATE,
    DIS_FIELDTYPE_RADIO_INPUT_SOURCE,
    DIS_FIELDTYPE_ANTENNA_PATTERN_TYPE,
    DIS_FIELDTYPE_SPREAD_SPECTRUM,
    DIS_FIELDTYPE_MODULATION_MAJOR,
    DIS_FIELDTYPE_MODULATION_DETAIL,
    DIS_FIELDTYPE_MODULATION_SYSTEM,
    DIS_FIELDTYPE_CRYPTO_SYSTEM,
    DIS_FIELDTYPE_EMITTER_NAME,
    DIS_FIELDTYPE_EMISSION_FUNCTION,
    DIS_FIELDTYPE_BEAM_FUNCTION,

    /* other atomic types */
    DIS_FIELDTYPE_PDU_LENGTH,
    DIS_FIELDTYPE_EXERCISE_ID,
    DIS_FIELDTYPE_SITE,
    DIS_FIELDTYPE_APPLICATION,
    DIS_FIELDTYPE_ENTITY,
    DIS_FIELDTYPE_APPEARANCE,
    DIS_FIELDTYPE_ARTIC_PARAM_TYPE,
    DIS_FIELDTYPE_CAPABILITIES,
    DIS_FIELDTYPE_COUNTRY,
    DIS_FIELDTYPE_DATUM_ID,
    DIS_FIELDTYPE_DATUM_LENGTH,
    DIS_FIELDTYPE_DEAD_RECKONING_PARAMS,
    DIS_FIELDTYPE_DEAD_RECKONING_ALGORITHM,
    DIS_FIELDTYPE_DEAD_RECKONING_OTHER_PARAMS,
    DIS_FIELDTYPE_ENTITY_MARKING,
    DIS_FIELDTYPE_EXTRA,
    DIS_FIELDTYPE_FIXED_DATUM_VALUE,
    DIS_FIELDTYPE_FIXED_LEN_STR,
    DIS_FIELDTYPE_FORCE_ID,
    DIS_FIELDTYPE_FUSE,
    DIS_FIELDTYPE_NUM_FIXED_DATA,
    DIS_FIELDTYPE_NUM_VARIABLE_DATA,
    DIS_FIELDTYPE_REQUEST_ID,
    DIS_FIELDTYPE_SPECIFIC,
    DIS_FIELDTYPE_SUBCATEGORY,
    DIS_FIELDTYPE_TIME_INTERVAL,
    DIS_FIELDTYPE_TIMESTAMP,
    DIS_FIELDTYPE_WARHEAD,
    DIS_FIELDTYPE_RADIO_ID,
    DIS_FIELDTYPE_SAMPLE_RATE,
    DIS_FIELDTYPE_DATA_LENGTH,
    DIS_FIELDTYPE_NUMBER_OF_SAMPLES,
    DIS_FIELDTYPE_NUM_ARTICULATION_PARAMS,
    DIS_FIELDTYPE_ANTENNA_PATTERN_LENGTH,
    DIS_FIELDTYPE_TRANSMIT_FREQUENCY,
    DIS_FIELDTYPE_MODULATION_PARAMETER_LENGTH,
    DIS_FIELDTYPE_FH_NETWORK_ID,
    DIS_FIELDTYPE_FH_SET_ID,
    DIS_FIELDTYPE_LO_SET_ID,
    DIS_FIELDTYPE_FH_MSG_START,
    DIS_FIELDTYPE_RESERVED,
    DIS_FIELDTYPE_FH_SYNC_TIME_OFFSET,
    DIS_FIELDTYPE_FH_SECURITY_KEY,
    DIS_FIELDTYPE_FH_CLEAR_CHANNEL,
    DIS_FIELDTYPE_TS_ALLOCATION_MODE,
    DIS_FIELDTYPE_TRANSMITTER_PRIMARY_MODE,
    DIS_FIELDTYPE_TRANSMITTER_SECONDARY_MODE,
    DIS_FIELDTYPE_JTIDS_SYNC_STATE,
    DIS_FIELDTYPE_NETWORK_SYNC_ID,
    DIS_FIELDTYPE_LINK16_NPG,
    DIS_FIELDTYPE_LINK16_TSEC_CVLL,
    DIS_FIELDTYPE_LINK16_MSEC_CVLL,
    DIS_FIELDTYPE_LINK16_MESSAGE_TYPE,
    DIS_FIELDTYPE_NUM_ELECTROMAGNETIC_EMISSION_SYSTEMS,
    DIS_FIELDTYPE_NUM_OF_SHAFTS,
    DIS_FIELDTYPE_NUM_OF_APAS,
    DIS_FIELDTYPE_NUM_OF_UA_EMITTER_SYSTEMS,
    DIS_FIELDTYPE_NUM_OF_UA_EMITTER_SYSTEM_BEAMS,

        /* composite types */
    DIS_FIELDTYPE_BURST_DESCRIPTOR,
    DIS_FIELDTYPE_CLOCK_TIME,
    DIS_FIELDTYPE_ENTITY_ID,
    DIS_FIELDTYPE_ENTITY_TYPE,
    DIS_FIELDTYPE_RADIO_ENTITY_TYPE,
    DIS_FIELDTYPE_EVENT_ID,
    DIS_FIELDTYPE_LINEAR_VELOCITY,
    DIS_FIELDTYPE_LOCATION_ENTITY,
    DIS_FIELDTYPE_LOCATION_WORLD,
    DIS_FIELDTYPE_ORIENTATION,
    DIS_FIELDTYPE_SIMULATION_ADDRESS,
    DIS_FIELDTYPE_VARIABLE_DATUM_VALUE,
    DIS_FIELDTYPE_VECTOR_32,
    DIS_FIELDTYPE_VECTOR_64,
    DIS_FIELDTYPE_ENCODING_SCHEME,
    DIS_FIELDTYPE_ANTENNA_LOCATION,
    DIS_FIELDTYPE_REL_ANTENNA_LOCATON,
    DIS_FIELDTYPE_MODULATION_TYPE,
    DIS_FIELDTYPE_CRYPTO_KEY_ID,
    DIS_FIELDTYPE_MODULATION_PARAMETERS,
    DIS_FIELDTYPE_ANTENNA_PATTERN_PARAMETERS,
    DIS_FIELDTYPE_MOD_PARAMS_CCTT_SINCGARS,
    DIS_FIELDTYPE_MOD_PARAMS_JTIDS_MIDS,
    DIS_FIELDTYPE_LINK16_MESSAGE_DATA,
    DIS_FIELDTYPE_LINK16_PTT,
    DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM,
    DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM,
    DIS_FIELDTYPE_EMITTER_SYSTEM,
    DIS_FIELDTYPE_FUNDAMENTAL_PARAMETER_DATA,
    DIS_FIELDTYPE_TRACK_JAM,
    DIS_FIELDTYPE_SHAFTS,
    DIS_FIELDTYPE_APA,
    DIS_FIELDTYPE_UA_EMITTER_SYSTEMS,
    DIS_FIELDTYPE_UA_BEAMS,
    DIS_FIELDTYPE_UA_EMITTER_SYSTEM,
    DIS_FIELDTYPE_UA_BEAM_FUNDAMENTAL_PARAMETER_DATA,

    /* arrays */
    DIS_FIELDTYPE_FIXED_DATUMS,
    DIS_FIELDTYPE_FIXED_DATUM_IDS,
    DIS_FIELDTYPE_VARIABLE_DATUMS,
    DIS_FIELDTYPE_VARIABLE_DATUM_IDS,
    DIS_FIELDTYPE_VARIABLE_PARAMETERS,
    DIS_FIELDTYPE_VARIABLE_RECORDS,
    DIS_FIELDTYPE_RADIO_DATA

} DIS_FieldType;

/* Struct which contains the data needed to parse a single DIS field.
 */
typedef struct DIS_ParserNode_T
{
    DIS_FieldType fieldType;
    const char *fieldLabel;
    int fieldRepeatLen;
    int ettVar;
    struct DIS_ParserNode_T *children;
    guint32 *outputVar;
} DIS_ParserNode;

/* Struct which associates a name with a particular bit combination.
 */
typedef struct
{
    guint32 value;
    const char *label;
} DIS_BitMaskMapping;

/* Struct which specifies all possible bit mappings associated with
 * a particular bit mask.
 */
typedef struct
{
    guint32 maskBits;
    guint32 shiftBits;
    const char *label;
    DIS_BitMaskMapping bitMappings[33];
} DIS_BitMask;

/* all of these variables are assigned by reference */
/* *(parserNode.outputVar) = value                  */
static guint32 disProtocolVersion;
static guint32 pduType;
static guint32 protocolFamily;
static guint32 persistentObjectPduType;
static guint32 entityKind;
static guint32 entityDomain;
static guint32 category;
static guint32 radioID;
static guint32 disRadioTransmitState;
static guint32 encodingScheme;
static guint32 tdlType;
static guint32 numSamples;
static guint32 messageType;
static guint32 numFixed;
static guint32 numVariable;
static guint32 numBeams;
static guint32 numTrackJamTargets;
static guint32 numShafts;
static guint32 numApas;
static guint32 numUAEmitter;
static guint32 numUABeams;
static guint32 variableDatumLength;
static guint32 variableParameterType;
static guint32 variableRecordLength;
static guint32 variableRecordType;
static guint32 majorModulation;
static guint32 systemModulation;
static guint32 modulationParamLength;
static guint32 disAntennaPattern;

/* Headers
 */
static DIS_ParserNode DIS_FIELDS_PDU_HEADER[] =
{
    { DIS_FIELDTYPE_PROTOCOL_VERSION, "Protocol Version",0,0,0,&disProtocolVersion },
    { DIS_FIELDTYPE_EXERCISE_ID,      "Exercise ID",0,0,0,0 },
    { DIS_FIELDTYPE_PDU_TYPE,         "PDU Type",0,0,0,&pduType },
    { DIS_FIELDTYPE_PROTOCOL_FAMILY,  "Protocol Family",0,0,0,&protocolFamily },
    { DIS_FIELDTYPE_TIMESTAMP,        "Timestamp",0,0,0,0 },
    { DIS_FIELDTYPE_PDU_LENGTH,       "Length",0,0,0,0 },
    { DIS_FIELDTYPE_PAD16,            "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_END,              NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_PERSISTENT_OBJECT_HEADER[] =
{
    { DIS_FIELDTYPE_UINT8,                  "Protocol Version",0,0,0,0 },
    { DIS_FIELDTYPE_PERSISTENT_OBJECT_TYPE, "PO PDU Type",0,0,0,&persistentObjectPduType },
    { DIS_FIELDTYPE_UINT8,                  "Exercise ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                  "PO Database ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                 "Length",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                 "PDU Count",0,0,0,0 },
    { DIS_FIELDTYPE_END,                    NULL,0,0,0,0 }
};

/* Composite types
 */

static DIS_ParserNode DIS_FIELDS_BURST_DESCRIPTOR[] =
{
    { DIS_FIELDTYPE_ENTITY_TYPE, "Munition",0,0,0,0 },
    { DIS_FIELDTYPE_WARHEAD,     "Warhead",0,0,0,0 },
    { DIS_FIELDTYPE_FUSE,        "Fuse",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,      "Quantity",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,      "Rate",0,0,0,0 },
    { DIS_FIELDTYPE_END,         NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_CLOCK_TIME[] =
{
    { DIS_FIELDTYPE_UINT32,                 "Hour",0,0,0,0 },
    { DIS_FIELDTYPE_TIMESTAMP,              "Time Past The Hour",0,0,0,0 },
    { DIS_FIELDTYPE_END,                    NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_ENTITY_ID[] =
{
    { DIS_FIELDTYPE_SITE,        "Site",0,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION, "Application",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY,      "Entity",0,0,0,0 },
    { DIS_FIELDTYPE_END,         NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_ENTITY_TYPE[] =
{
    { DIS_FIELDTYPE_ENTITY_KIND, "Entity Kind",0,0,0,&entityKind },
    { DIS_FIELDTYPE_DOMAIN,      "Domain",0,0,0,&entityDomain },
    { DIS_FIELDTYPE_COUNTRY,     "Country",0,0,0,0 },
    { DIS_FIELDTYPE_CATEGORY,    "Category",0,0,0,&category },
    { DIS_FIELDTYPE_SUBCATEGORY, "Subcategory",0,0,0,0 },
    { DIS_FIELDTYPE_SPECIFIC,    "Specific",0,0,0,0 },
    { DIS_FIELDTYPE_EXTRA,       "Extra",0,0,0,0 },
    { DIS_FIELDTYPE_END,         NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_RADIO_ENTITY_TYPE[] =
{
    { DIS_FIELDTYPE_ENTITY_KIND,          "Entity Kind",0,0,0,&entityKind },
    { DIS_FIELDTYPE_DOMAIN,               "Domain",0,0,0,&entityDomain },
    { DIS_FIELDTYPE_COUNTRY,              "Country",0,0,0,0 },
    { DIS_FIELDTYPE_RADIO_CATEGORY,       "Radio Category",0,0,0,&category },
    { DIS_FIELDTYPE_NOMENCLATURE_VERSION, "Nomenclature Version",0,0,0,0 },
    { DIS_FIELDTYPE_NOMENCLATURE,         "Nomenclature",0,0,0,0 },
    { DIS_FIELDTYPE_END,                  NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_MODULATION_TYPE[] =
{
    { DIS_FIELDTYPE_SPREAD_SPECTRUM,        "Spread Spectrum",0,0,0,0 },
    { DIS_FIELDTYPE_MODULATION_MAJOR,       "Major",0,0,0,&majorModulation },
    { DIS_FIELDTYPE_MODULATION_DETAIL,      "Detail",0,0,0,0 },
    { DIS_FIELDTYPE_MODULATION_SYSTEM,      "System",0,0,0,&systemModulation },
    { DIS_FIELDTYPE_END,                    NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_EVENT_ID[] =
{
    { DIS_FIELDTYPE_UINT16, "Site",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Application",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Event Number",0,0,0,0 },
    { DIS_FIELDTYPE_END,    NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_ORIENTATION[] =
{
    { DIS_FIELDTYPE_FLOAT32, "Psi",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Theta",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Phi",0,0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_SIMULATION_ADDRESS[] =
{
    { DIS_FIELDTYPE_UINT16, "Site",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Application",0,0,0,0 },
    { DIS_FIELDTYPE_END,    NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VECTOR_FLOAT_32[] =
{
    { DIS_FIELDTYPE_FLOAT32, "X",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Y",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Z",0,0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VECTOR_FLOAT_64[] =
{
    { DIS_FIELDTYPE_FLOAT64, "X",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT64, "Y",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT64, "Z",0,0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_MOD_PARAMS_CCTT_SINCGARS[] =
{
    { DIS_FIELDTYPE_FH_NETWORK_ID,        "Frequency Hopping Network ID",0,0,0,0 },
    { DIS_FIELDTYPE_FH_SET_ID,            "Frequency Set ID",0,0,0,0 },
    { DIS_FIELDTYPE_LO_SET_ID,            "Lockout Set ID",0,0,0,0 },
    { DIS_FIELDTYPE_FH_MSG_START,         "Frequency Hopping Message Start",0,0,0,0 },
    { DIS_FIELDTYPE_RESERVED,             "Reserved",0,0,0,0 },
    { DIS_FIELDTYPE_FH_SYNC_TIME_OFFSET,  "FH Synchronization Time Offset",0,0,0,0 },
    { DIS_FIELDTYPE_FH_SECURITY_KEY,      "Transmission Security Key",0,0,0,0 },
    { DIS_FIELDTYPE_FH_CLEAR_CHANNEL,     "Clear Channel",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                 "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_END,                  NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_MOD_PARAMS_JTIDS_MIDS[] =
{
    { DIS_FIELDTYPE_TS_ALLOCATION_MODE,           "Time Slot Allocaton Mode",0,0,0,0 },
    { DIS_FIELDTYPE_TRANSMITTER_PRIMARY_MODE,     "Transmitter Primary Mode",0,0,0,0 },
    { DIS_FIELDTYPE_TRANSMITTER_SECONDARY_MODE,   "Transmitter Secondary Mode",0,0,0,0 },
    { DIS_FIELDTYPE_JTIDS_SYNC_STATE,             "Synchronization State",0,0,0,0 },
    { DIS_FIELDTYPE_NETWORK_SYNC_ID,              "Network Sync ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_SIGNAL_LINK16_NETWORK_HEADER[] =
{
    { DIS_FIELDTYPE_LINK16_NPG,          "Network Participant Group",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,               "Network Number",0,0,0,0 },
    { DIS_FIELDTYPE_LINK16_TSEC_CVLL,    "TSEC CVLL",0,0,0,0 },
    { DIS_FIELDTYPE_LINK16_MSEC_CVLL,    "MSEC CVLL",0,0,0,0 },
    { DIS_FIELDTYPE_LINK16_MESSAGE_TYPE, "Message Type",0,0,0,&messageType },
    { DIS_FIELDTYPE_UINT16,              "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,              "Time Slot ID",0,0,0,0 },
    { DIS_FIELDTYPE_LINK16_PTT,          "Perceived Transmit Time",0,0,0,0 },
    { DIS_FIELDTYPE_LINK16_MESSAGE_DATA, "Message Data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                 NULL,0,0,0,0 }
};

/* Array records
 */
static DIS_ParserNode DIS_FIELDS_FIXED_DATUM[] =
{
    { DIS_FIELDTYPE_DATUM_ID,                "Datum ID",0,0,0,0 },
    { DIS_FIELDTYPE_FIXED_DATUM_VALUE,       "Datum value",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VARIABLE_DATUM[] =
{
    { DIS_FIELDTYPE_DATUM_ID,                "Datum ID",0,0,0,0 },
    { DIS_FIELDTYPE_DATUM_LENGTH,            "Datum length",0,0,0,&variableDatumLength },
    { DIS_FIELDTYPE_VARIABLE_DATUM_VALUE,    "Datum value",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_DATUM_IDS[] =
{
    { DIS_FIELDTYPE_DATUM_ID,                "Datum ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_EMITTER_SYSTEM[] =
{
    { DIS_FIELDTYPE_EMITTER_NAME,            "Emitter Name",0,0,0,0 },
    { DIS_FIELDTYPE_EMISSION_FUNCTION,       "Function",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Emitter ID Number",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_UA_SHAFT[] =
{
    { DIS_FIELDTYPE_INT16,                   "Current Shaft RPM",0,0,0,0 },
    { DIS_FIELDTYPE_INT16,                   "Ordered Shaft RPM",0,0,0,0 },
    { DIS_FIELDTYPE_INT32,                   "Shaft RPM Rate of Change",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_APA[] =
{
    { DIS_FIELDTYPE_INT16,                   "Parameter Index",0,0,0,0 }, /*FIXME enum*/
    { DIS_FIELDTYPE_INT16,                   "Value", 0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_UA_EMITTER_SYSTEM[] =
{
    { DIS_FIELDTYPE_UINT16,                  "Acoustic Emitter Name",0,0,0,0 }, /*FIXME enum*/
    { DIS_FIELDTYPE_UINT8,                  "Function",0,0,0,0 }, /*FIXME enum*/
    { DIS_FIELDTYPE_UINT8,                  "Acoustic ID Number",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_FUNDAMENTAL_PARAMETER_DATA[] =
{
    { DIS_FIELDTYPE_FLOAT32,            "Frequency",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Frequency Range",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Effective Radiated Power",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Pulse Repetition Frequency",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Pulse Width",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Beam Azimuth Center",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Beam Azimuth Sweep",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Beam Elevation Center",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Beam Elevation Sweep",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,            "Beam Sweep Sync",0,0,0,0 },
    { DIS_FIELDTYPE_END,                NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_TRACK_JAM[] =
{
    { DIS_FIELDTYPE_SITE,               "Site",0,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION,        "Application",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY,             "Entity",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,              "Emitter ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,              "Beam ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                NULL,0,0,0,0 }
};

/* Variable Parameters
 */
static DIS_ParserNode DIS_FIELDS_VP_TYPE[] =
{
    { DIS_FIELDTYPE_PARAMETER_TYPE_DESIGNATOR,   "Variable Parameter Type",0,0,0,&variableParameterType },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

/* Array record contents - variable parameter records
 */
static DIS_ParserNode DIS_FIELDS_VP_GENERIC[] =
{
    { DIS_FIELDTYPE_FIXED_LEN_STR,               "Data",15,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VP_ARTICULATED_PART[] =
{
    { DIS_FIELDTYPE_UINT8,                       "Change",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                      "Part Attached To ID",0,0,0,0 },
    { DIS_FIELDTYPE_ARTIC_PARAM_TYPE,            "Parameter Type",0,0,0,0 },
    { DIS_FIELDTYPE_UINT64,                      "Parameter Value",0,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VP_ATTACHED_PART[] =
{
    { DIS_FIELDTYPE_UINT8,                       "Attached Indicator",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                      "Part Attached To ID",0,0,0,0 },
    { DIS_FIELDTYPE_ARTIC_PARAM_TYPE,            "Parameter Type",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_TYPE,                 "Part Type",0,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VP_ENTITY_OFFSET[] =
{
    { DIS_FIELDTYPE_UINT8,                       "Offset Type",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                        "Padding",2,0,0,0 },
    { DIS_FIELDTYPE_VECTOR_32,                   "Offset",0,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VP_ENTITY_ASSOCIATION[] =
{
    { DIS_FIELDTYPE_UINT8,                       "Change Indicator",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                       "Association Status",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                       "Association Type",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,                   "Object Identifier",2,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                      "Own Station Location",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                       "Physical Connection Type",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                       "Group Member Type",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                      "Group Number",0,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};
/* Variable Records
 */
static DIS_ParserNode DIS_FIELDS_VR_TYPE[] =
{
    { DIS_FIELDTYPE_UINT32,   "Record Type",0,0,0,&variableRecordType },
    { DIS_FIELDTYPE_UINT16,   "Record Length",0,0,0,&variableRecordLength },
    { DIS_FIELDTYPE_END,      NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_APPLICATION_HEALTH_STATUS[] =
{
    { DIS_FIELDTYPE_PAD8,                       "Padding",2,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION_STATUS_TYPE,    "Status Type",0,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION_GENERAL_STATUS, "General Status",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                      "Specific Status",0,0,0,0 },
    { DIS_FIELDTYPE_INT32,                      "Status Value Int",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT64,                    "Status Value Float",0,0,0,0 },
    { DIS_FIELDTYPE_END,                        NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_APPLICATION_INITIALIZATION[] =
{
    { DIS_FIELDTYPE_UINT8,                   "Exercise ID",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                    "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_FIXED_LEN_STR,           "Exercise File Path",256,0,0,0 },
    { DIS_FIELDTYPE_FIXED_LEN_STR,           "Exercise File Name",128,0,0,0 },
    { DIS_FIELDTYPE_FIXED_LEN_STR,           "Application Role",64,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_DATA_QUERY[] =
{
    { DIS_FIELDTYPE_UINT16,                  "Num Records",0,0,0,&numFixed },
    { DIS_FIELDTYPE_FIXED_DATUM_IDS,         "Record",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM[] =
{
    { DIS_FIELDTYPE_UINT8,                  "Beam Data Length",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                  "Beam ID Number",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                 "Beam Parameter Index",0,0,0,0 },
    { DIS_FIELDTYPE_FUNDAMENTAL_PARAMETER_DATA,
                                       "Fundamental Parameter Data",0,0,0,0 },
    { DIS_FIELDTYPE_BEAM_FUNCTION,          "Beam Function",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,   "Number of Targets in Track/Jam Field",0,0,0,&numTrackJamTargets },
    { DIS_FIELDTYPE_UINT8,                  "High Density Track/Jam",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                   "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,                 "Jamming Mode Sequence",0,0,0,0 },
    { DIS_FIELDTYPE_TRACK_JAM,              "Track/Jam Entity",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM[] =
{
    { DIS_FIELDTYPE_UINT8,                  "System Data Length",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                  "Number of Beams (M)",0,0,0,&numBeams },
    { DIS_FIELDTYPE_PAD16,                  "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_EMITTER_SYSTEM,         "Emitter System",0,0,0,0 },
    { DIS_FIELDTYPE_VECTOR_32,              "Location",0,0,0,0 },
    { DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM, "Beam",0,0,0,0 },
    { DIS_FIELDTYPE_END,                    NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_UA_BEAM_FUNDAMENTAL_PARAMETER_DATA[] =
{
    { DIS_FIELDTYPE_UINT16,                 "Active Emission Parameter Index",0,0,0,0 }, /*FIXME enum!!!*/
    { DIS_FIELDTYPE_UINT16,                 "Scan Pattern",0,0,0,0 }, /*FIXME enum!!!*/
    { DIS_FIELDTYPE_FLOAT32,                "Beam Center Azimuth (Horizontal Bearing)",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,                "Azimuthal Beamwidth (Horizontal Beamwidth)",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,                "Beam Center D/E",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,                "D/E Beamwidth (Vertical Beamwidth)",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_UA_BEAM[] =
{
    { DIS_FIELDTYPE_UINT8,                  "Beam Data Length",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                  "Beam ID Number",0,0,0,0 },
    { DIS_FIELDTYPE_PAD16,                  "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_UA_BEAM_FUNDAMENTAL_PARAMETER_DATA,
                                            "Fundamental Data Parameters",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_FIELDS_VR_UA_EMITTER_SYSTEM[] =
{
    { DIS_FIELDTYPE_UINT8,                  "Emitter System Data Length",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_OF_UA_EMITTER_SYSTEM_BEAMS, "Number of Beams (m)",0,0,0,0 },
    { DIS_FIELDTYPE_PAD16,                  "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_UA_EMITTER_SYSTEM,      "Acoustic Emitter System",0,0,0,0 },
    { DIS_FIELDTYPE_VECTOR_32,              "Location (with respect to entity)",0,0,0,0 },
    { DIS_FIELDTYPE_END,                    NULL,0,0,0,0 }
};

/* Bit fields
 */
static DIS_ParserNode DIS_FIELDS_NONE[] =
{
    { DIS_FIELDTYPE_END, NULL, 0,0,0,0 }
};

static DIS_BitMask DIS_APPEARANCE_LANDPLATFORM[] =
{
    { 0x00000001, 0, "Paint Scheme", {
        { 0, "Uniform color" },
        { 1, "Camouflage" },
        { 0,0 }
    } },
    { 0x00000002, 1, "Mobility", {
        { 0, "No mobility kill" },
        { 1, "Mobility kill" },
        { 0,0 }
    } },
    { 0x00000004, 2, "Fire Power", {
        { 0, "No fire-power kill" },
        { 1, "Fire-power kill" },
        { 0,0 }
    } },
    { 0x00000018, 3, "Damage", {
        { 0, "No damage" },
        { 1, "Slight damage" },
        { 2, "Moderate damage" },
        { 3, "Destroyed" },
        { 0,0 }
    } },
    { 0, 0, 0, {
        { 0, 0 }
    } }
};

static DIS_BitMask DIS_APPEARANCE_LIFEFORM[] =
{
    { 0x00000001, 0, "Paint Scheme", {
        { 0, "Uniform color" },
        { 1, "Camouflage" },
        { 0,0 }
    } },
    { 0x00000018, 3, "Health", {
        { 0, "No injury" },
        { 1, "Slight injury" },
        { 2, "Moderate injury" },
        { 3, "Fatal injury" },
        { 0,0 }
    } },
    { 0, 0, 0, {
        { 0, 0 }
    } }
};

/******************************************************************************
*
* PDUS
*
*******************************************************************************/

/* DIS Entity Information / Interaction PDUs
 */
static DIS_ParserNode DIS_PARSER_ENTITY_STATE_PDU[] =
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
static DIS_ParserNode DIS_PARSER_ELECTROMAGNETIC_EMISSION_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Emitting Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_EVENT_ID,                "Event ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "State Update Indicator",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_ELECTROMAGNETIC_EMISSION_SYSTEMS, "Number of Systems (N)",0,0,0,&numVariable },
    { DIS_FIELDTYPE_PAD16,                   "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM, "Emission System",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};


/* DIS Underwater Acoustic PDUs
 */
static DIS_ParserNode DIS_PARSER_UNDERWATER_ACOUSTIC_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Emitting Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_EVENT_ID,                "Event ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "State Update Indicator",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                    "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                  "Passive Parameter Index", 0,0,0,0 }, /* !! enum !! */
    { DIS_FIELDTYPE_UINT8,                   "Propulsion Plant Configuration",0,0,0,0 }, /* !! enum !! */
    { DIS_FIELDTYPE_NUM_OF_SHAFTS,           "Number of Shafts",0,0,0,&numShafts },
    { DIS_FIELDTYPE_NUM_OF_APAS,             "Number of Additional Passive Activities (APA)",0,0,0,&numApas },
    { DIS_FIELDTYPE_NUM_OF_UA_EMITTER_SYSTEMS, "Number of UA Emitter Systems",0,0,0,&numUAEmitter },
    { DIS_FIELDTYPE_SHAFTS,                  "Shafts",0,0,0,0 },
    { DIS_FIELDTYPE_APA,                     "APAs",0,0,0,0 },
    { DIS_FIELDTYPE_UA_EMITTER_SYSTEMS,      "Underwater Acoustic Emission System",0,0,0,0 },
    { DIS_FIELDTYPE_UA_BEAMS,                "Beams",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};


/* DIS Radio Communications protocol (RCP) family PDUs
 */
static DIS_ParserNode DIS_PARSER_TRANSMITTER_PDU[] =
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

static DIS_ParserNode DIS_PARSER_SIGNAL_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_RADIO_ID,                "Radio ID",0,0,0,&radioID },
    { DIS_FIELDTYPE_ENCODING_SCHEME,         "Encoding Scheme",0,0,0,&encodingScheme },
    { DIS_FIELDTYPE_TDL_TYPE,                "TDL Type",0,0,0,&tdlType },
    { DIS_FIELDTYPE_SAMPLE_RATE,             "Sample Rate",0,0,0,0 },
    { DIS_FIELDTYPE_DATA_LENGTH,             "Data Length",0,0,0,0 },
    { DIS_FIELDTYPE_NUMBER_OF_SAMPLES,       "Number of Samples",0,0,0,&numSamples },
    { DIS_FIELDTYPE_RADIO_DATA,              "Radio Data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

/* DIS Warfare PDUs
 */
static DIS_ParserNode DIS_PARSER_FIRE_PDU[] =
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

static DIS_ParserNode DIS_PARSER_DETONATION_PDU[] =
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
static DIS_ParserNode DIS_PARSER_START_RESUME_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_CLOCK_TIME,              "Real World Time",0,0,0,0 },
    { DIS_FIELDTYPE_CLOCK_TIME,              "Simulation Time",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_PARSER_STOP_FREEZE_PDU[] =
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

static DIS_ParserNode DIS_PARSER_ACKNOWLEDGE_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ACKNOWLEDGE_FLAG,        "Acknowledge Flag",0,0,0,0 },
    { DIS_FIELDTYPE_RESPONSE_FLAG,           "Response Flag",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_PARSER_ACTION_REQUEST_PDU[] =
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

static DIS_ParserNode DIS_PARSER_ACTION_RESPONSE_PDU[] =
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

static DIS_ParserNode DIS_PARSER_DATA_PDU[] =
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

static DIS_ParserNode DIS_PARSER_DATA_QUERY_PDU[] =
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

static DIS_ParserNode DIS_PARSER_COMMENT_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_NUM_FIXED_DATA,          "Number of Fixed Data Fields",0,0,0,&numFixed },
    { DIS_FIELDTYPE_NUM_VARIABLE_DATA,       "Number of Variable Data Fields",0,0,0,&numVariable },
    { DIS_FIELDTYPE_FIXED_DATUMS,            "Fixed data",0,0,0,0 },
    { DIS_FIELDTYPE_VARIABLE_DATUMS,         "Variable data",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_PARSER_SIMAN_ENTITY_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Originating Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Receiving Entity ID",0,0,0,0 },
    { DIS_FIELDTYPE_REQUEST_ID,              "Request ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

/* DIS Simulation Management with Reliability PDUs
 */
static DIS_ParserNode DIS_PARSER_START_RESUME_R_PDU[] =
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

static DIS_ParserNode DIS_PARSER_STOP_FREEZE_R_PDU[] =
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

static DIS_ParserNode DIS_PARSER_ACTION_REQUEST_R_PDU[] =
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

static DIS_ParserNode DIS_PARSER_DATA_R_PDU[] =
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

static DIS_ParserNode DIS_PARSER_DATA_QUERY_R_PDU[] =
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

static DIS_ParserNode DIS_PARSER_SIMAN_ENTITY_R_PDU[] =
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
static DIS_ParserNode DIS_PARSER_APPLICATION_CONTROL_PDU[] =
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
static DIS_ParserNode DIS_PARSER_SIMULATOR_PRESENT_PO_PDU[] =
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

static DIS_ParserNode DIS_PARSER_DESCRIBE_OBJECT_PO_PDU[] =
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

static DIS_ParserNode DIS_PARSER_OBJECTS_PRESENT_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Owner",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "World State ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Object Count",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_PARSER_OBJECT_REQUEST_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Requesting Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Object Owner",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "World State ID",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Object Count",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_PARSER_DELETE_OBJECTS_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Requesting Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Object Count",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_PARSER_SET_WORLD_STATE_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Requesting Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,                 "Clock Rate",0,0,0,0 },
    { DIS_FIELDTYPE_UINT32,                  "Seconds Since 1970",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "World State ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

static DIS_ParserNode DIS_PARSER_NOMINATION_PO_PDU[] =
{
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Nominated Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Nominating Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_SIMULATION_ADDRESS,      "Missing Simulator",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};


static void initializeParser(DIS_ParserNode parserNodes[]);

/* Create a specific subtree for a PDU or a composite PDU field.
 */
static DIS_ParserNode *createSubtree(DIS_ParserNode parserNodes[], gint *ettVar)
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
static void initializeParser(DIS_ParserNode parserNodes[])
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
        case DIS_FIELDTYPE_SHAFTS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VR_UA_SHAFT,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_APA:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VR_APA,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_UA_EMITTER_SYSTEMS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VR_UA_EMITTER_SYSTEM,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_UA_EMITTER_SYSTEM:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_UA_EMITTER_SYSTEM,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_UA_BEAMS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_VR_UA_BEAM,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_UA_BEAM_FUNDAMENTAL_PARAMETER_DATA:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_UA_BEAM_FUNDAMENTAL_PARAMETER_DATA,
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

/* Initialize the field parsers that are not explicitly included in any
 * specific PDU.  These fields are only accessed and used if a variant
 * field indicates they are to be used.
 */
static void initializeFieldParsers(void)
{
    initializeParser(DIS_FIELDS_VP_GENERIC);
    initializeParser(DIS_FIELDS_VP_ARTICULATED_PART);
    initializeParser(DIS_FIELDS_VP_ATTACHED_PART);
    initializeParser(DIS_FIELDS_VP_ENTITY_OFFSET);
    initializeParser(DIS_FIELDS_VP_ENTITY_ASSOCIATION);
    initializeParser(DIS_FIELDS_VR_APPLICATION_HEALTH_STATUS);
    initializeParser(DIS_FIELDS_VR_APPLICATION_INITIALIZATION);
    initializeParser(DIS_FIELDS_VR_DATA_QUERY);
    initializeParser(DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM);
    initializeParser(DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM);
    initializeParser(DIS_FIELDS_VR_UA_SHAFT);
    initializeParser(DIS_FIELDS_VR_UA_EMITTER_SYSTEM);
    initializeParser(DIS_FIELDS_VR_UA_BEAM);
    initializeParser(DIS_FIELDS_MOD_PARAMS_CCTT_SINCGARS);
    initializeParser(DIS_FIELDS_MOD_PARAMS_JTIDS_MIDS);
    initializeParser(DIS_FIELDS_SIGNAL_LINK16_NETWORK_HEADER);

}

/* Initialize the parsers for each PDU type and the standard DIS header.
 */
static void initializeParsers(void)
{
    gint *ett[DIS_PDU_MAX_VARIABLE_PARAMETERS+DIS_PDU_MAX_VARIABLE_RECORDS+2];
    int   i, ett_index;

    initializeParser(DIS_FIELDS_PDU_HEADER);

    /* DIS Entity Information / Interaction PDUs */
    initializeParser(DIS_PARSER_ENTITY_STATE_PDU);

    /* DIS Distributed Emission Regeneration PDUs */
    initializeParser(DIS_PARSER_ELECTROMAGNETIC_EMISSION_PDU);
    initializeParser(DIS_PARSER_UNDERWATER_ACOUSTIC_PDU);

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

/* Adjust an offset variable for proper alignment for a specified field length.
 */
static gint alignOffset(gint offset, guint fieldLength)
{
    gint remainder = offset % fieldLength;
    if (remainder != 0)
    {
        offset += fieldLength - remainder;
    }
    return offset;
}

/* Parse a field consisting of a specified number of bytes.  This field parser
 * doesn't perform any alignment.
 */
static gint parseField_Bytes(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
{
    proto_tree_add_text(tree, tvb, offset, numBytes, "%s (%d bytes)",
        parserNode.fieldLabel, numBytes);
    offset += numBytes;
    return offset;
}

/* Parse a bitmask field.
 */
static gint parseField_Bitmask(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
{
    DIS_BitMask *bitMask = 0;
    guint64 uintVal = 0;

    offset = alignOffset(offset, numBytes);

    switch(numBytes)
    {
    case 1:
        uintVal = tvb_get_guint8(tvb, offset);
        break;
    case 2:
        uintVal = tvb_get_ntohs(tvb, offset);
        break;
    case 4:
        uintVal = tvb_get_ntohl(tvb, offset);
        break;
    case 8:
        uintVal = tvb_get_ntoh64(tvb, offset);
        break;
    default:
        /* assert */
        break;
    }

    switch(parserNode.fieldType)
    {
    case DIS_FIELDTYPE_APPEARANCE:
        if ((entityKind == DIS_ENTITYKIND_PLATFORM) &&
            (entityDomain == DIS_DOMAIN_LAND))
        {
            bitMask = DIS_APPEARANCE_LANDPLATFORM;
        }
        else if (entityKind == DIS_ENTITYKIND_LIFE_FORM)
        {
            bitMask = DIS_APPEARANCE_LIFEFORM;
        }
        break;
    default:
        break;
    }

    if (bitMask != 0)
    {
        int maskIndex = 0;
        while (bitMask[maskIndex].maskBits != 0)
        {
            int mapIndex = 0;
            DIS_BitMaskMapping *bitMaskMap = bitMask[maskIndex].bitMappings;

            while (bitMaskMap[mapIndex].label != 0)
            {
                if (((bitMask[maskIndex].maskBits & uintVal) >> bitMask[maskIndex].shiftBits) ==
                    bitMaskMap[mapIndex].value)
                {
                    proto_tree_add_text(tree, tvb, offset, numBytes,
                        "%s = %s", bitMask[maskIndex].label,
                        bitMaskMap[mapIndex].label);
                    break;
                }
                ++mapIndex;
            }
            ++maskIndex;
        }
    }
    else
    {
        proto_tree_add_text(tree, tvb, offset, numBytes,
            "Unknown Appearance Type (%" G_GINT64_MODIFIER "u)", uintVal);
    }

    offset += numBytes;

    return offset;
}

/* Parse an unsigned integer field of a specified number of bytes.
 */
static gint parseField_UInt(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
{
    guint64 uintVal = 0;

    offset = alignOffset(offset, numBytes);

    switch(numBytes)
    {
    case 1:
        uintVal = tvb_get_guint8(tvb, offset);
        break;
    case 2:
        uintVal = tvb_get_ntohs(tvb, offset);
        break;
    case 4:
        uintVal = tvb_get_ntohl(tvb, offset);
        break;
    case 8:
        uintVal = tvb_get_ntoh64(tvb, offset);
        break;
    default:
        /* assert */
        break;
    }

    proto_tree_add_text(tree, tvb, offset, numBytes, "%s = %" G_GINT64_MODIFIER "u",
        parserNode.fieldLabel, uintVal);

    if (parserNode.outputVar != 0)
    {
        *(parserNode.outputVar) = (guint32)uintVal;
    }

    offset += numBytes;

    return offset;
}

/* Parse a signed integer field of a specified number of bytes.
 */
static gint parseField_Int(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
{
    gint64 intVal = 0;

    offset = alignOffset(offset, numBytes);

    switch(numBytes)
    {
    case 1:
        intVal = (gint8)tvb_get_guint8(tvb, offset);
        break;
    case 2:
        intVal = (gint16)tvb_get_ntohs(tvb, offset);
        break;
    case 4:
        intVal = (gint32)tvb_get_ntohl(tvb, offset);
        break;
    case 8:
        intVal = (gint64)tvb_get_ntoh64(tvb, offset);
        break;
    default:
        /* assert */
        break;
    }

    proto_tree_add_text(tree, tvb, offset, numBytes, "%s = %" G_GINT64_MODIFIER "d",
        parserNode.fieldLabel, intVal);

    offset += numBytes;

    return offset;
}

/* Parse a field that explicitly specified a number of pad bytes (vs implicit
 * padding, which occurs whenever padding is inserted to properly align the
 * field.
 */
static gint parseField_Pad(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode _U_, guint numBytes)
{
    proto_tree_add_text(tree, tvb, offset, numBytes,
        "Explicit Padding (%d bytes)", numBytes);

    offset += numBytes;

    return offset;
}

/* Parse an enumerated type field.
 */
static gint parseField_Enum(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
{
    const value_string *enumStrings = 0;
    guint32 enumVal = 0;
    const gchar *enumStr = 0;
#if 0
    proto_item *pi;
#endif
    int dis_hf_id = -1;

    offset = alignOffset(offset, numBytes);

    switch(parserNode.fieldType)
    {
    case DIS_FIELDTYPE_ACKNOWLEDGE_FLAG:
        enumStrings = DIS_PDU_AcknowledgeFlag_Strings;
        break;
    case DIS_FIELDTYPE_ACTION_ID:
        enumStrings = DIS_PDU_ActionId_Strings;
        break;
    case DIS_FIELDTYPE_APPLICATION_GENERAL_STATUS:
        enumStrings = DIS_PDU_ApplicationGeneralStatus_Strings;
        break;
    case DIS_FIELDTYPE_APPLICATION_STATUS_TYPE:
        enumStrings = DIS_PDU_ApplicationStatusType_Strings;
        break;
    case DIS_FIELDTYPE_APPLICATION_TYPE:
        enumStrings = DIS_PDU_ApplicationType_Strings;
        break;
    case DIS_FIELDTYPE_CONTROL_ID:
        enumStrings = DIS_PDU_ControlId_Strings;
        break;
    case DIS_FIELDTYPE_PROTOCOL_VERSION:
        enumStrings = DIS_PDU_ProtocolVersion_Strings;
        dis_hf_id = hf_dis_proto_ver;
        break;
    case DIS_FIELDTYPE_PROTOCOL_FAMILY:
        enumStrings = DIS_PDU_ProtocolFamily_Strings;
        dis_hf_id = hf_dis_proto_fam;
        break;
    case DIS_FIELDTYPE_PDU_TYPE:
        enumStrings = DIS_PDU_Type_Strings;
        dis_hf_id = hf_dis_pdu_type;
        break;
    case DIS_FIELDTYPE_ENTITY_KIND:
        enumStrings = DIS_PDU_EntityKind_Strings;
        dis_hf_id = hf_dis_entityKind;
        break;
    case DIS_FIELDTYPE_DOMAIN:
        enumStrings = DIS_PDU_Domain_Strings;
        dis_hf_id = hf_dis_entityDomain;
        break;
    case DIS_FIELDTYPE_DETONATION_RESULT:
        enumStrings = DIS_PDU_DetonationResult_Strings;
        break;
    case DIS_FIELDTYPE_FROZEN_BEHAVIOR:
        enumStrings = DIS_PDU_FrozenBehavior_Strings;
        break;
    case DIS_FIELDTYPE_RADIO_CATEGORY:
        enumStrings = DIS_PDU_RadioCategory_Strings;
        dis_hf_id = hf_dis_category_radio;
        break;
    case DIS_FIELDTYPE_NOMENCLATURE_VERSION:
        enumStrings = DIS_PDU_NomenclatureVersion_Strings;
        break;
    case DIS_FIELDTYPE_NOMENCLATURE:
        enumStrings = DIS_PDU_Nomenclature_Strings;
        break;
    case DIS_FIELDTYPE_CATEGORY:
        if (entityKind == DIS_ENTITYKIND_PLATFORM)
        {
            switch(entityDomain)
            {
            case DIS_DOMAIN_LAND:
                enumStrings = DIS_PDU_Category_LandPlatform_Strings;
                dis_hf_id = hf_dis_category_land;
                break;
            case DIS_DOMAIN_AIR:
                enumStrings = DIS_PDU_Category_AirPlatform_Strings;
                dis_hf_id = hf_dis_category_air;
                break;
            case DIS_DOMAIN_SURFACE:
                enumStrings = DIS_PDU_Category_SurfacePlatform_Strings;
                dis_hf_id = hf_dis_category_surface;
                break;
            case DIS_DOMAIN_SUBSURFACE:
                enumStrings = DIS_PDU_Category_SubsurfacePlatform_Strings;
                dis_hf_id = hf_dis_category_subsurface;
                break;
            case DIS_DOMAIN_SPACE:
                enumStrings = DIS_PDU_Category_SpacePlatform_Strings;
                dis_hf_id = hf_dis_category_space;
                break;
            default:
                enumStrings = 0;
                break;
            }
        }
        break;
    case DIS_FIELDTYPE_EMITTER_NAME:
        enumStrings = DIS_PDU_EmitterName_Strings;
        dis_hf_id = hf_dis_emitter_name;
        break;
    case DIS_FIELDTYPE_EMISSION_FUNCTION:
        enumStrings = DIS_PDU_EmissionFunction_Strings;
        dis_hf_id = hf_dis_emission_function;
        break;
    case DIS_FIELDTYPE_BEAM_FUNCTION:
        enumStrings = DIS_PDU_BeamFunction_Strings;
        dis_hf_id = hf_dis_beam_function;
        break;
    case DIS_FIELDTYPE_PARAMETER_TYPE_DESIGNATOR:
        enumStrings = DIS_PDU_ParameterTypeDesignator_Strings;
        break;
    case DIS_FIELDTYPE_PERSISTENT_OBJECT_TYPE:
        enumStrings = DIS_PDU_PersistentObjectType_Strings;
        break;
    case DIS_FIELDTYPE_PERSISTENT_OBJECT_CLASS:
        enumStrings = DIS_PDU_PO_ObjectClass_Strings;
        break;
    case DIS_FIELDTYPE_REASON:
        enumStrings = DIS_PDU_Reason_Strings;
        break;
    case DIS_FIELDTYPE_REQUEST_STATUS:
        enumStrings = DIS_PDU_RequestStatus_Strings;
        break;
    case DIS_FIELDTYPE_REQUIRED_RELIABILITY_SERVICE:
        enumStrings = DIS_PDU_RequiredReliabilityService_Strings;
        break;
    case DIS_FIELDTYPE_RESPONSE_FLAG:
        enumStrings = DIS_PDU_DisResponseFlag_Strings;
        break;
    case DIS_FIELDTYPE_MODULATION_DETAIL:
        switch (majorModulation) {
        case DIS_MAJOR_MOD_AMPLITUDE:
            enumStrings = DIS_PDU_DetailModulationAmplitude_Strings;
            break;
        case DIS_MAJOR_MOD_AMPLITUDE_AND_ANGLE:
            enumStrings = DIS_PDU_DetailModulationAmpAndAngle_Strings;
            break;
        case DIS_MAJOR_MOD_ANGLE:
            enumStrings = DIS_PDU_DetailModulationAngle_Strings;
            break;
        case DIS_MAJOR_MOD_COMBINATION:
            enumStrings = DIS_PDU_DetailModulationCombination_Strings;
            break;
        case DIS_MAJOR_MOD_PULSE:
            enumStrings = DIS_PDU_DetailModulationPulse_Strings;
            break;
        case DIS_MAJOR_MOD_UNMODULATED:
            enumStrings = DIS_PDU_DetailModulationUnmodulated_Strings;
            break;
        case DIS_MAJOR_MOD_CPSM: /* CPSM only has "other" defined */
        case DIS_MAJOR_MOD_OTHER:
        default:
            enumStrings = DIS_PDU_DetailModulationCPSM_Strings;
            break;
        }
        break;
    case DIS_FIELDTYPE_LINK16_MESSAGE_TYPE:
        enumStrings = DIS_PDU_Link16_MessageType_Strings;
        dis_hf_id = hf_dis_signal_link16_message_type;
        break;
    default:
        enumStrings = 0;
        break;
    }

    switch(numBytes)
    {
    case 1:
        enumVal = tvb_get_guint8(tvb, offset);
        break;
    case 2:
        enumVal = tvb_get_ntohs(tvb, offset);
        break;
    case 4:
        enumVal = tvb_get_ntohl(tvb, offset);
        break;
    default:
        /* assert */
        break;
    }

    enumStr = val_to_str(enumVal, enumStrings, "Unknown Enumeration (%d)");

    if (dis_hf_id != -1) {
#if 0
       pi = proto_tree_add_item(tree, dis_hf_id, tvb, offset, numBytes, ENC_BIG_ENDIAN);
       proto_item_set_text(pi, "%s = %s", parserNode.fieldLabel, enumStr);
#else
       proto_tree_add_item(tree, dis_hf_id, tvb, offset, numBytes, ENC_BIG_ENDIAN);
#endif
    }
    else {
       proto_tree_add_text(tree, tvb, offset, numBytes, "%s = %s",
           parserNode.fieldLabel, enumStr);
    }

    if (parserNode.outputVar != 0)
    {
        *(parserNode.outputVar) = enumVal;
    }

    offset += numBytes;

    return offset;
}

/* Parse a 4-byte floating-point value.
 */
static gint parseField_Float(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode)
{
    gfloat floatVal;

    offset = alignOffset(offset, 4);
    floatVal = tvb_get_ntohieee_float(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "%s = %f",
        parserNode.fieldLabel, floatVal);

    offset += 4;

    return offset;
}
#if 0
/* Parse a 4-byte floating-point value, given text label.
 */
static gint parseField_Float_Text(tvbuff_t *tvb, proto_tree *tree, gint offset, gchar *charStr)
{
    gfloat floatVal;

    offset = alignOffset(offset, 4);
    floatVal = tvb_get_ntohieee_float(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "%s = %f",
        charStr, floatVal);

    offset += 4;

    return offset;
}
#endif
/* Parse an 8-byte floating-point value.
 */
static gint parseField_Double(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode)
{
    gdouble doubleVal;

    offset = alignOffset(offset, 8);
    doubleVal = tvb_get_ntohieee_double(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 8, "%s = %f",
        parserNode.fieldLabel, doubleVal);

    offset += 8;

    return offset;
}

/* Parse the Timestamp */
static gint parseField_Timestamp(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode)
{
   /* some consts */
   static double MSEC_PER_SECOND = 1000.0;
   static double MSEC_PER_MINUTE = 60.0 * 1000.0 ;
   static double MSEC_PER_HOUR = 60.0 * 60.0 * 1000.0;
   static double FSV = 0x7fffffff;
   /* variables */
   guint isAbsolute = 0;
   guint32 uintVal;
   guint minutes;
   guint seconds;
   guint milliseconds;
   double ms;

   offset = alignOffset(offset, 4);

   /* convert to host value */
   uintVal = tvb_get_ntohl(tvb, offset);
   /* determine absolute vis sim time */
   if( uintVal & 1 )
      isAbsolute = 1;

   /* convert TS to MS */
   ms = (uintVal >> 1) * MSEC_PER_HOUR / FSV;
   ms += 0.5;

   /* calc minutes and reduce ms */
   minutes = (guint) (ms / MSEC_PER_MINUTE);
   ms -= (minutes * MSEC_PER_MINUTE);

   /* calc seconds and reduce ms */
   seconds = (guint) (ms / MSEC_PER_SECOND);
   ms -= (seconds * MSEC_PER_SECOND);

   /* truncate milliseconds */
   milliseconds = (guint) ms;

   /* push out the values */
   if( isAbsolute )
   {
      proto_tree_add_text(tree, tvb, offset, 4, "%s = %02d:%02d %03d absolute (UTM)",
            parserNode.fieldLabel, minutes, seconds, milliseconds);
   }
   else
   {
      proto_tree_add_text(tree, tvb, offset, 4, "%s = %02d:%02d %03d relative",
            parserNode.fieldLabel, minutes, seconds, milliseconds);
   }

   offset += 4;
   return offset;
}

static gint parseField_VariableParameter(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo);
static gint parseField_VariableRecord(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo);

/* Parse Link 16 Message Data record (SISO-STD-002, Tables 5.2.5 through 5.2.12)
 */
static gint parse_Link16_Message_Data(proto_tree *tree, tvbuff_t *tvb, gint offset, packet_info *pinfo)
{
    guint32 cache, value, i;
    Link16State state;
    tvbuff_t *newtvb;

    static const int * jtids_message_header_fields[] = {
        &hf_dis_signal_link16_time_slot_type,
        &hf_dis_signal_link16_rti,
        &hf_dis_signal_link16_stn,
        NULL
    };

    switch (messageType) {
    case DIS_MESSAGE_TYPE_JTIDS_HEADER_MESSAGES:
        proto_tree_add_bitmask_text(tree, tvb, offset, 4, "JTIDS Header", NULL, ett_dis_signal_link16_jtids_header, jtids_message_header_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

        cache = tvb_get_ntohl(tvb, offset);
        value = (cache >> 4) & 0x7FFF;
        col_append_fstr(pinfo->cinfo, COL_INFO, ", STN=0%o, Link 16 Words:", value);

        value = (cache >> 19);
        offset += 4;
        cache = tvb_get_ntohl(tvb, offset);
        value |= (cache & 0x7) << 13;
        proto_tree_add_uint(tree, hf_dis_signal_link16_sdusn, tvb, offset - 4, 8, value);
        offset += 4;

        memset(&state, 0, sizeof(state));

        for (i = 0; i < (encodingScheme & 0x3FFF); i++) {
            gint8 *word = (gint8 *)g_malloc(10);
            if (!(i & 1)) {
                word[0] = (cache >> 16) & 0xFF;
                word[1] = (cache >> 24) & 0xFF;
                cache = tvb_get_ntohl(tvb, offset);
                offset += 4;
                word[2] = cache & 0xFF;
                word[3] = (cache >> 8) & 0xFF;
                word[4] = (cache >> 16) & 0xFF;
                word[5] = (cache >> 24) & 0xFF;
                cache = tvb_get_ntohl(tvb, offset);
                offset += 4;
                word[6] = cache & 0xFF;
                word[7] = (cache >> 8) & 0xFF;
                word[8] = (cache >> 16) & 0xFF;
                word[9] = (cache >> 24) & 0xFF;
            } else {
                cache = tvb_get_ntohl(tvb, offset);
                offset += 4;
                word[0] = cache & 0xFF;
                word[1] = (cache >> 8) & 0xFF;
                word[2] = (cache >> 16) & 0xFF;
                word[3] = (cache >> 24) & 0xFF;
                cache = tvb_get_ntohl(tvb, offset);
                offset += 4;
                word[4] = cache & 0xFF;
                word[5] = (cache >> 8) & 0xFF;
                word[6] = (cache >> 16) & 0xFF;
                word[7] = (cache >> 24) & 0xFF;
                cache = tvb_get_ntohl(tvb, offset);
                offset += 4;
                word[8] = cache & 0xFF;
                word[9] = (cache >> 8) & 0xFF;
            }

            newtvb = tvb_new_child_real_data(tvb, word, 10, 10);
            tvb_set_free_cb(newtvb, g_free);
            add_new_data_source(pinfo, newtvb, "Link 16 Word");
            call_dissector_with_data(find_dissector("link16"), newtvb, pinfo, tree, &state);
        }
        break;
    }
    return offset;
}

/* Parse packet data based on a specified array of DIS_ParserNodes.
 */
static gint parseFields(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNodes[], packet_info *pinfo)
{
    guint        fieldIndex     = 0;
    guint        fieldRepeatLen = 0;
    guint64      uintVal        = 0;
    proto_item  *pi             = NULL;
    proto_tree  *sub_tree       = NULL;
    tvbuff_t    *newtvb         = NULL;
    gint         length         = 0;
    guint16 spread_spectrum     = 0;


    /* Get the length while ensuring there's at least one byte for us to
     * decode (if not, throw an exception so as to prevent very long loops).
     */
    length = tvb_ensure_length_remaining(tvb, offset+1);

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
            proto_tree_add_item(tree, hf_dis_pdu_length, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_SITE:
            proto_tree_add_item(tree, hf_dis_entity_id_site, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_APPLICATION:
            proto_tree_add_item(tree, hf_dis_entity_id_application, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_ENTITY:
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
            proto_tree_add_item(sub_tree,
                (uintVal >> 14) == DIS_ENCODING_CLASS_ENCODED_AUDIO ? hf_dis_ens_type_audio : hf_dis_ens_type,
                tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_item_set_end(pi, tvb, offset);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            offset += 2;
            break;
        case DIS_FIELDTYPE_TDL_TYPE:
            uintVal = tvb_get_ntohs(tvb, offset);
            proto_tree_add_item(tree, hf_dis_tdl_type, tvb, offset, 2, ENC_BIG_ENDIAN);
            *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
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
            if (tdlType == DIS_TDL_TYPE_LINK16_STD) {
                pi = proto_tree_add_text(tree, tvb, offset, 16, "Link 16 Network Header");
                sub_tree = proto_item_add_subtree(pi, ett_dis_signal_link16_network_header);
                offset = parseFields(tvb, sub_tree, offset, DIS_FIELDS_SIGNAL_LINK16_NETWORK_HEADER, pinfo);
                proto_item_set_end(pi, tvb, offset);

                pi = proto_tree_add_text(tree, tvb, offset, -1, "Link 16 Message Data: %s",
                    val_to_str(messageType, DIS_PDU_Link16_MessageType_Strings, ""));
                sub_tree = proto_item_add_subtree(pi, ett_dis_signal_link16_message_data);
                offset = parse_Link16_Message_Data(sub_tree, tvb, offset, pinfo);
                proto_item_set_end(pi, tvb, offset);
            } else {
                proto_tree_add_item(tree, hf_dis_signal_data, tvb, offset, -1, ENC_NA );
            }
            /* ****ck******* need to look for padding bytes */
            break;
        case DIS_FIELDTYPE_LINK16_PTT:
            if (tvb_get_ntohl(tvb, offset) == 0xFFFFFFFF)
                proto_tree_add_text(tree, tvb, offset, 8, "%s: NO STATEMENT", parserNodes[fieldIndex].fieldLabel);
            else
                proto_tree_add_item(tree, hf_dis_signal_link16_ptt, tvb, offset, 8, ENC_TIME_NTP|ENC_BIG_ENDIAN);
            offset += 8;
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
                    offset = parseFields(tvb, sub_tree, offset, DIS_FIELDS_MOD_PARAMS_CCTT_SINCGARS, pinfo);
                    proto_item_set_end(pi, tvb, offset);
                    break;
                }
                else if (systemModulation == DIS_SYSTEM_MOD_JTIDS_MIDS) {
                    pi = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                                             parserNodes[fieldIndex].fieldLabel);
                    sub_tree = proto_item_add_subtree(pi, parserNodes[fieldIndex].ettVar);
                    offset = parseFields(tvb, sub_tree, offset, DIS_FIELDS_MOD_PARAMS_JTIDS_MIDS, pinfo);
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
            newtvb = tvb_new_subset_remaining(tvb, offset);
            proto_tree_add_item(tree, hf_dis_antenna_pattern_parameter_dump, newtvb, 0, -1, ENC_NA );
            break;
        case DIS_FIELDTYPE_LINK16_NPG:
            proto_tree_add_item(tree, hf_dis_signal_link16_npg, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            break;
        case DIS_FIELDTYPE_LINK16_TSEC_CVLL:
            proto_tree_add_item(tree, hf_dis_signal_link16_tsec_cvll, tvb, offset, 1, ENC_NA);
            offset++;
            break;
        case DIS_FIELDTYPE_LINK16_MSEC_CVLL:
            proto_tree_add_item(tree, hf_dis_signal_link16_msec_cvll, tvb, offset, 1, ENC_NA);
            offset++;
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
        case DIS_FIELDTYPE_LINK16_MESSAGE_TYPE:
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
        case DIS_FIELDTYPE_UA_EMITTER_SYSTEM:
        case DIS_FIELDTYPE_UA_BEAM_FUNDAMENTAL_PARAMETER_DATA:
            newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                parserNodes[fieldIndex].fieldLabel);
            if (parserNodes[fieldIndex].children != 0)
            {
                proto_item *newSubtree = proto_item_add_subtree(newField,
                    parserNodes[fieldIndex].ettVar);
                offset = parseFields(tvb, newSubtree, offset,
                    parserNodes[fieldIndex].children, pinfo);
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
                if (numFixed > INT_MAX)
                {
                    numFixed = INT_MAX;
                }

                for (i = 0; i < numFixed; ++i)
                {
                    proto_item *newSubtree;

                    /* is remaining length large enough for another fixed datum (ID & value) */
                    /* XXX is this really necessary? */
                    tvb_ensure_length_remaining(tvb, offset+8);

                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s",
                                                   parserNodes[fieldIndex].fieldLabel);
                    newSubtree = proto_item_add_subtree(newField, ettFixedData);
                    offset = parseFields (tvb, newSubtree, offset,
                         parserNodes[fieldIndex].children, pinfo);
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

                if (numFixed > INT_MAX)
                {
                    numFixed = INT_MAX;
                }

                for (i = 0; i < numFixed; ++i)
                {
                    /* is remaining length large enough for another fixed datum ID (32 bit int) */
                    /* XXX is this really necessary? */
                    tvb_ensure_length_remaining(tvb, offset+4);
                    offset = parseFields (tvb, newSubtree, offset,
                        parserNodes[fieldIndex].children, pinfo);
                }
                proto_item_set_end(newField, tvb, offset);
            }
            break;
        case DIS_FIELDTYPE_VARIABLE_DATUMS:
            {
                guint i;
                if (numVariable > INT_MAX)
                {
                    numVariable = INT_MAX;
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
                         parserNodes[fieldIndex].children, pinfo);
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

                if (numVariable > INT_MAX)
                {
                    numVariable = INT_MAX;
                }

                for (i = 0; i < numVariable; ++i)
                {
                    offset = parseFields
                        (tvb, newSubtree, offset,
                         parserNodes[fieldIndex].children, pinfo);
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
                         parserNodes[fieldIndex].children, pinfo);
                    offset = parseField_VariableParameter
                        (tvb, newSubtree, offset, pinfo);
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
                         parserNodes[fieldIndex].children, pinfo);
                    offset = parseField_VariableRecord
                        (tvb, newSubtree, offset, pinfo);
                    proto_item_set_end(newField, tvb, offset);
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
                            parserNodes[fieldIndex].children, pinfo);
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
                            parserNodes[fieldIndex].children, pinfo);
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
                            parserNodes[fieldIndex].children, pinfo);
                    }
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        case DIS_FIELDTYPE_NUM_OF_SHAFTS:
            {
                uintVal = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_dis_num_shafts, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            }
            break;
        case DIS_FIELDTYPE_SHAFTS:
            {
                guint i;

                if (numShafts > DIS_PDU_MAX_SHAFTS)
                {
                    numShafts = DIS_PDU_MAX_SHAFTS;
                }

                for (i = 0; i < numShafts; ++i)
                {
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s [%d of %d]",
                                                   parserNodes[fieldIndex].fieldLabel, i+1, numShafts);
                    if (parserNodes[fieldIndex].children != 0)
                    {
                        proto_item *newSubtree =
                            proto_item_add_subtree(newField,
                            parserNodes[fieldIndex].ettVar);
                        offset = parseFields(tvb, newSubtree, offset,
                            parserNodes[fieldIndex].children, pinfo);
                    }
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        case DIS_FIELDTYPE_NUM_OF_APAS:
            {
                uintVal = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_dis_num_apas, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            }
            break;
        case DIS_FIELDTYPE_APA:
            {
                guint i;

                if (numApas > DIS_PDU_MAX_APAS)
                {
                    numApas = DIS_PDU_MAX_APAS;
                }

                for (i = 0; i < numApas; ++i)
                {
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s [%d of %d]",
                                                   parserNodes[fieldIndex].fieldLabel, i+1, numApas);
                    if (parserNodes[fieldIndex].children != 0)
                    {
                        proto_item *newSubtree =
                            proto_item_add_subtree(newField,
                            parserNodes[fieldIndex].ettVar);
                        offset = parseFields(tvb, newSubtree, offset,
                            parserNodes[fieldIndex].children, pinfo);
                    }
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        case DIS_FIELDTYPE_NUM_OF_UA_EMITTER_SYSTEMS:
            {
                uintVal = tvb_get_guint8(tvb, offset);
                proto_tree_add_item(tree, hf_dis_num_ua_emitter_systems, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                *(parserNodes[fieldIndex].outputVar) = (guint32)uintVal;
            }
            break;
        case DIS_FIELDTYPE_NUM_OF_UA_EMITTER_SYSTEM_BEAMS:
            {
                uintVal = tvb_get_guint8(tvb, offset);
                offset  = parseField_UInt(tvb, tree, offset, parserNodes[fieldIndex], 1);
                numUABeams += (guint32)uintVal;
            }
            break;
        case DIS_FIELDTYPE_UA_EMITTER_SYSTEMS:
            {
                guint i;

                if (numUAEmitter > DIS_PDU_MAX_UA_EMITTER_SYSTEMS)
                {
                    numUAEmitter = DIS_PDU_MAX_UA_EMITTER_SYSTEMS;
                }

                for (i = 0; i < numUAEmitter; ++i)
                {
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s [%d of %d]",
                                                   parserNodes[fieldIndex].fieldLabel, i+1, numUAEmitter);
                    if (parserNodes[fieldIndex].children != 0)
                    {
                        proto_item *newSubtree =
                            proto_item_add_subtree(newField,
                            parserNodes[fieldIndex].ettVar);
                        offset = parseFields(tvb, newSubtree, offset,
                            parserNodes[fieldIndex].children, pinfo);
                    }
                    proto_item_set_end(newField, tvb, offset);
                }
            }
            break;
        case DIS_FIELDTYPE_UA_BEAMS:
            {
                guint i;

                if (numUABeams > DIS_PDU_MAX_UA_BEAMS)
                {
                    numUABeams = DIS_PDU_MAX_UA_BEAMS;
                }

                for (i = 0; i < numUABeams; ++i)
                {
                    newField = proto_tree_add_text(tree, tvb, offset, -1, "%s [%d of %d]",
                                                   parserNodes[fieldIndex].fieldLabel, i+1, numUABeams);
                    if (parserNodes[fieldIndex].children != 0)
                    {
                        proto_item *newSubtree =
                            proto_item_add_subtree(newField,
                            parserNodes[fieldIndex].ettVar);
                        offset = parseFields(tvb, newSubtree, offset,
                            parserNodes[fieldIndex].children, pinfo);
                    }
                    proto_item_set_end(newField, tvb, offset);
                }
                numUABeams = 0; /* reset beam count for this pdu */
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

/* Parse a variable parameter field.
 */
static gint parseField_VariableParameter(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo)
{
    DIS_ParserNode *paramParser = 0;

    /* Determine the parser to use based on the type */
    switch (variableParameterType) {
    case DIS_PARAM_TYPE_DESIG_ARTICULATED_PART:
        paramParser = DIS_FIELDS_VP_ARTICULATED_PART;
        break;
    case DIS_PARAM_TYPE_DESIG_ATTACHED_PART:
        paramParser = DIS_FIELDS_VP_ATTACHED_PART;
        break;
    case DIS_PARAM_TYPE_DESIG_ENTITY_OFFSET:
        paramParser = DIS_FIELDS_VP_ENTITY_OFFSET;
        break;
    case DIS_PARAM_TYPE_DESIG_ENTITY_ASSOCIATION:
        paramParser = DIS_FIELDS_VP_ENTITY_ASSOCIATION;
        break;
    default:
        paramParser = DIS_FIELDS_VP_GENERIC;
        break;
    }

    /* Parse the variable parameter fields */
    if (paramParser)
    {
        offset = parseFields(tvb, tree, offset, paramParser, pinfo);
    }

    return offset;
}

/* Parse a variable record field.
 */
static gint parseField_VariableRecord(tvbuff_t *tvb, proto_tree *tree, gint offset, packet_info *pinfo)
{
    DIS_ParserNode *paramParser = 0;

    /* Determine the parser to use based on the type */
    switch (variableRecordType) {
    case 47200:
        paramParser = DIS_FIELDS_VR_APPLICATION_HEALTH_STATUS;
        break;
    case 47300:
        paramParser = DIS_FIELDS_VR_APPLICATION_INITIALIZATION;
        break;
    case 47600:
        paramParser = DIS_FIELDS_VR_DATA_QUERY;
        break;
    default:
        {

            guint32 dataLength = variableRecordLength - 6;

            if (dataLength > 0)
            {
                proto_tree_add_text(tree, tvb, offset, dataLength,
                    "Record Data (%d bytes)", dataLength);
                offset += dataLength;
            }
        }
        break;
    }

    /* Parse the variable record fields */
    if (paramParser)
    {
        offset = parseFields(tvb, tree, offset, paramParser, pinfo);
    }

    /* Should alignment padding be added */
    if (variableRecordLength % 8)
    {
        guint32 alignmentPadding = (8 - (variableRecordLength % 8));

        proto_tree_add_text(tree, tvb, offset, alignmentPadding,
            "Alignment Padding (%d bytes)", alignmentPadding);
        offset += alignmentPadding;
    }

    return offset;
}

void proto_register_dis(void);

static const true_false_string dis_modulation_spread_spectrum = {
    "Spread Spectrum modulation in use",
    "Spread Spectrum modulation not in use"
};

static const true_false_string dis_frequency_hopping_value = {
    "Frequency hopping modulation used",
    "Frequency hopping modulation not used"
};

static const true_false_string dis_encryption_mode_value = {
    "diphase encryption mode",
    "baseband encryption mode"
};

static const true_false_string dis_pseudo_noise_value = {
    "Pseudo Noise modulation used",
    "Pseudo Noise modulation not used"
};

static const true_false_string dis_time_hopping_value = {
    "Time hopping modulation used",
    "Time hopping modulation not used"
};

static guint dis_udp_port = DEFAULT_DIS_UDP_PORT;

static const char* dis_proto_name = "Distributed Interactive Simulation";
static const char* dis_proto_name_short = "DIS";

/* Main dissector routine to be invoked for a DIS PDU.
 */
static gint dissect_dis(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *dis_tree = 0;
    proto_item *dis_node = 0;
    proto_item *dis_header_tree = 0;
    proto_item *dis_header_node = 0;
    proto_item *dis_payload_tree = 0;
    proto_item *dis_payload_node = 0;
    gint offset = 0;
    const gchar *pduString = 0;
    DIS_ParserNode *pduParser = 0;

    /* DIS packets must be at least 12 bytes long.  DIS uses port 3000, by
     * default, but the Cisco Redundant Link Management protocol can also use
     * that port; RLM packets are 8 bytes long, so we use this to distinguish
     * between them.
     */
    if (tvb_reported_length(tvb) < 12)
    {
        return 0;
    }

    /* Reset the global PDU type variable -- this will be parsed as part of
     * the DIS header.
     */
    pduType = DIS_PDUTYPE_OTHER;
    protocolFamily = DIS_PROTOCOLFAMILY_OTHER;
    persistentObjectPduType = DIS_PERSISTENT_OBJECT_TYPE_OTHER;

    /* set the protocol column */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, dis_proto_name_short);

    /* Add the top-level DIS node under which the rest of the fields will be
     * displayed.
     */
    dis_node = proto_tree_add_protocol_format(tree, proto_dis, tvb, offset,
        -1, "Distributed Interactive Simulation");
    dis_tree = proto_item_add_subtree(dis_node, ett_dis);

    /* Add a node to contain the DIS header fields.
     */
    dis_header_node = proto_tree_add_text(dis_tree, tvb, offset, -1, "Header");
    dis_header_tree = proto_item_add_subtree(dis_header_node, ett_dis_header);
    offset = parseFields(tvb, dis_header_tree, offset, DIS_FIELDS_PDU_HEADER, pinfo);

    proto_item_set_end(dis_header_node, tvb, offset);

    /* Locate the string name for the PDU type enumeration,
     * or default to "Unknown".
    */
    pduString = val_to_str_const(pduType, DIS_PDU_Type_Strings, "Unknown");

    /* Locate the appropriate PDU parser, if type is known.
     */
    switch (protocolFamily)
    {
    case DIS_PROTOCOLFAMILY_PERSISTENT_OBJECT:
        {
            proto_item *dis_po_header_tree = 0;
            proto_item *dis_po_header_node = 0;

            dis_po_header_node = proto_tree_add_text
                (dis_header_tree, tvb, offset, -1, "PO Header");
            dis_po_header_tree = proto_item_add_subtree
                (dis_po_header_node, ett_dis_po_header);
            offset = parseFields
                (tvb, dis_po_header_tree, offset,
                 DIS_FIELDS_PERSISTENT_OBJECT_HEADER, pinfo);
            proto_item_set_end(dis_po_header_node, tvb, offset);

            /* Locate the appropriate PO PDU parser, if type is known.
             */
            switch (persistentObjectPduType)
            {
            case DIS_PERSISTENT_OBJECT_TYPE_SIMULATOR_PRESENT:
                pduParser = DIS_PARSER_SIMULATOR_PRESENT_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_DESCRIBE_OBJECT:
                pduParser = DIS_PARSER_DESCRIBE_OBJECT_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_OBJECTS_PRESENT:
                pduParser = DIS_PARSER_OBJECTS_PRESENT_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_OBJECT_REQUEST:
                pduParser = DIS_PARSER_OBJECT_REQUEST_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_DELETE_OBJECTS:
                pduParser = DIS_PARSER_DELETE_OBJECTS_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_SET_WORLD_STATE:
                pduParser = DIS_PARSER_SET_WORLD_STATE_PO_PDU;
                break;
            case DIS_PERSISTENT_OBJECT_TYPE_NOMINATION:
                pduParser = DIS_PARSER_NOMINATION_PO_PDU;
                break;
            default:
                pduParser = 0;
                break;
            }

            /* Locate the string name for the PO PDU type enumeration,
             * or default to "Unknown".
             */
            pduString = val_to_str
                (persistentObjectPduType,
                 DIS_PDU_PersistentObjectType_Strings, "Unknown");

            /* Add a node to contain the DIS PDU fields.
             */
            dis_payload_node = proto_tree_add_text(dis_tree, tvb, offset, -1,
                "%s PO PDU", pduString);

        }
        break;
    default:

        /* Add a node to contain the DIS PDU fields.
         */
        dis_payload_node = proto_tree_add_text(dis_tree, tvb, offset, -1,
            "%s PDU", pduString);

        switch (pduType)
        {
        /* DIS Entity Information / Interaction PDUs */
        case DIS_PDUTYPE_ENTITY_STATE:
            pduParser = DIS_PARSER_ENTITY_STATE_PDU;
            break;

        /* DIS Distributed Emission Regeneration PDUs */
        case DIS_PDUTYPE_ELECTROMAGNETIC_EMISSION:
            pduParser = DIS_PARSER_ELECTROMAGNETIC_EMISSION_PDU;
            break;

        case DIS_PDUTYPE_UNDERWATER_ACOUSTIC:
            pduParser = DIS_PARSER_UNDERWATER_ACOUSTIC_PDU;
            break;

        /* DIS Radio Communications protocol (RCP) family PDUs */
        case DIS_PDUTYPE_TRANSMITTER:
            pduParser = DIS_PARSER_TRANSMITTER_PDU;
            break;
        case DIS_PDUTYPE_SIGNAL:
            pduParser = DIS_PARSER_SIGNAL_PDU;
            break;

        /* DIS Warfare PDUs */
        case DIS_PDUTYPE_FIRE:
            pduParser = DIS_PARSER_FIRE_PDU;
            break;
        case DIS_PDUTYPE_DETONATION:
            if ( disProtocolVersion < DIS_VERSION_IEEE_1278_1_2012 )
            {
                pduParser = DIS_PARSER_DETONATION_PDU;
            }
            else
            {
                /* TODO: Version 7 changed the Detonation PDU format
                 *       Need a different parser
                 */
                pduParser = DIS_PARSER_DETONATION_PDU;
            }
            break;

        /* DIS Simulation Management PDUs */
        case DIS_PDUTYPE_START_RESUME:
            pduParser = DIS_PARSER_START_RESUME_PDU;
            break;
        case DIS_PDUTYPE_STOP_FREEZE:
            pduParser = DIS_PARSER_STOP_FREEZE_PDU;
            break;
        case DIS_PDUTYPE_ACKNOWLEDGE:
            pduParser = DIS_PARSER_ACKNOWLEDGE_PDU;
            break;
        case DIS_PDUTYPE_ACTION_REQUEST:
            pduParser = DIS_PARSER_ACTION_REQUEST_PDU;
            break;
        case DIS_PDUTYPE_ACTION_RESPONSE:
            pduParser = DIS_PARSER_ACTION_RESPONSE_PDU;
            break;
        case DIS_PDUTYPE_DATA:
        case DIS_PDUTYPE_SET_DATA:
            pduParser = DIS_PARSER_DATA_PDU;
            break;
        case DIS_PDUTYPE_DATA_QUERY:
            pduParser = DIS_PARSER_DATA_QUERY_PDU;
            break;
        case DIS_PDUTYPE_COMMENT:
            pduParser = DIS_PARSER_COMMENT_PDU;
            break;
        case DIS_PDUTYPE_CREATE_ENTITY:
        case DIS_PDUTYPE_REMOVE_ENTITY:
            pduParser = DIS_PARSER_SIMAN_ENTITY_PDU;
            break;

        /* DIS Simulation Management with Reliability PDUs */
        case DIS_PDUTYPE_START_RESUME_R:
            pduParser = DIS_PARSER_START_RESUME_R_PDU;
            break;
        case DIS_PDUTYPE_STOP_FREEZE_R:
            pduParser = DIS_PARSER_STOP_FREEZE_R_PDU;
            break;
        case DIS_PDUTYPE_ACKNOWLEDGE_R:
            pduParser = DIS_PARSER_ACKNOWLEDGE_PDU;
            break;
        case DIS_PDUTYPE_ACTION_REQUEST_R:
            pduParser = DIS_PARSER_ACTION_REQUEST_R_PDU;
            break;
        case DIS_PDUTYPE_ACTION_RESPONSE_R:
            pduParser = DIS_PARSER_ACTION_RESPONSE_PDU;
            break;
        case DIS_PDUTYPE_DATA_R:
        case DIS_PDUTYPE_SET_DATA_R:
            pduParser = DIS_PARSER_DATA_R_PDU;
            break;
        case DIS_PDUTYPE_DATA_QUERY_R:
            pduParser = DIS_PARSER_DATA_QUERY_R_PDU;
            break;
        case DIS_PDUTYPE_COMMENT_R:
            pduParser = DIS_PARSER_COMMENT_PDU;
            break;
        case DIS_PDUTYPE_CREATE_ENTITY_R:
        case DIS_PDUTYPE_REMOVE_ENTITY_R:
            pduParser = DIS_PARSER_SIMAN_ENTITY_R_PDU;
            break;

        /* DIS Experimental V-DIS PDUs */
        case DIS_PDUTYPE_APPLICATION_CONTROL:
            pduParser = DIS_PARSER_APPLICATION_CONTROL_PDU;
            break;

        default:
            pduParser = 0;
            break;
        }
        break;
    }

    col_clear(pinfo->cinfo, COL_INFO);

    /* If a parser was located, invoke it on the data packet.
     */
    if (pduParser != 0)
    {
        dis_payload_tree = proto_item_add_subtree(dis_payload_node,
            ett_dis_payload);
        offset = parseFields(tvb, dis_payload_tree, offset, pduParser, pinfo);

        proto_item_set_end(dis_payload_node, tvb, offset);
    }

    /* Add detail to the INFO column */
    switch (pduType)
    {
    /* DIS Entity Information / Interaction PDUs */
    case DIS_PDUTYPE_ENTITY_STATE:
        col_add_fstr( pinfo->cinfo, COL_INFO,
                      "PDUType: %s, %s, %s",
                      pduString,
                      val_to_str_const(entityKind, DIS_PDU_EntityKind_Strings, "Unknown Entity Kind"),
                      val_to_str_const(entityDomain, DIS_PDU_Domain_Strings, "Unknown Entity Domain")
                     );
        break;

    case DIS_PDUTYPE_UNDERWATER_ACOUSTIC:
        col_add_fstr( pinfo->cinfo, COL_INFO,
                      "PDUType: %s, Shafts=%d, APA=%d, Acoustic Emitter=%d",
                      pduString,
                      numShafts,
                      numApas,
                      numUAEmitter
                     );
        break;
    case DIS_PDUTYPE_SIGNAL:
        if (numSamples)
            col_prepend_fstr(pinfo->cinfo, COL_INFO, ", Number of Samples=%u",
                numSamples);

        if ((encodingScheme & 0xC000) >> 14 == DIS_ENCODING_CLASS_ENCODED_AUDIO)
            col_prepend_fstr(pinfo->cinfo, COL_INFO,", Encoding Type=%s",
                val_to_str_const(DIS_ENCODING_TYPE(encodingScheme),
                DIS_PDU_Encoding_Type_Strings, "Unknown"));

        col_prepend_fstr( pinfo->cinfo, COL_INFO,
                      "PDUType: %s, RadioID=%u", pduString, radioID);
        break;
    case DIS_PDUTYPE_TRANSMITTER:
        col_add_fstr( pinfo->cinfo, COL_INFO,
                      "PDUType: %s, RadioID=%u, Transmit State=%s",
                      pduString,
                      radioID,
                      val_to_str_const(disRadioTransmitState, DIS_PDU_RadioTransmitState_Strings, "Unknown Transmit State")
                      );
        break;
    default:
        /* set the basic info column (pdu type) */
        col_add_fstr( pinfo->cinfo, COL_INFO,
                     "PDUType: %s",
                      pduString);
        break;
    }

    return tvb_length(tvb);
}

/* Registration routine for the DIS protocol.
 */
void proto_reg_handoff_dis(void);

void proto_register_dis(void)
{

/* registration with the filtering engine */
    static hf_register_info hf[] =
        {
            { &hf_dis_proto_ver,
              { "Proto version",      "dis.proto_ver",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ProtocolVersion_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_exercise_id,
              { "Exercise ID",       "dis.exer_id",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_pdu_type,
              { "PDU type",           "dis.pdu_type",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Type_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_proto_fam,
              { "Proto Family",       "dis.proto_fam",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ProtocolFamily_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_pdu_length,
              { "PDU Length",         "dis.pdu_length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entity_id_site,
              { "Entity ID Site",     "dis.entity_id_site",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entity_id_application,
              { "Entity ID Application", "dis.entity_id_application",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entity_id_entity,
              { "Entity ID Entity",       "dis.entity_id_entity",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_num_art_params,
              { "Number of Articulation Parameters",  "dis.num_articulation_params",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entityKind,
              { "Kind",       "dis.entityKind",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_EntityKind_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_entityDomain,
              { "Domain",       "dis.entityDomain",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Domain_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_land,
              { "Category / Land",       "dis.category.land",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_LandPlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_air,
              { "Category / Air",       "dis.category.air",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_AirPlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_surface,
              { "Category / Surface",       "dis.category.surface",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_SurfacePlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_subsurface,
              { "Category / Subsurface",       "dis.category.subsurface",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_SubsurfacePlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_space,
              { "Category / Space",       "dis.category.space",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_Category_SpacePlatform_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_category_radio,
              { "Category / Radio",       "dis.category.radio",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_RadioCategory_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_emitter_name,
              { "Emitter Name", "dis.electromagnetic.emitter.name",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_EmitterName_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_emission_function,
              { "Emission Function", "dis.electromagnetic.emission.function",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_EmissionFunction_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_beam_function,
              { "Beam Function", "dis.electromagnetic.emission.beam.function",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_BeamFunction_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_num_electromagnetic_emission_systems,
              { "Number of Electromagnetic Emission Systems",  "dis.electromagnetic.num_emission_systems",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_radio_id,
              { "Radio ID",  "dis.radio.radio_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_ens,
              { "Encoding Scheme",  "dis.radio.encoding_scheme",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_ens_class,
              { "Encoding Class",  "dis.radio.encoding_class",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_Encoding_Class_Strings), 0xc000,
                NULL, HFILL }
            },
            { &hf_dis_ens_type,
              { "Encoding Type", "dis.radio.encoding_type",
                FT_UINT16, BASE_DEC, NULL, 0x3fff,
                NULL, HFILL }
            },
            { &hf_dis_ens_type_audio,
              { "Encoding Type",  "dis.radio.encoding_type.audio",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_Encoding_Type_Strings), 0x3fff,
                NULL, HFILL }
            },
            { &hf_dis_tdl_type,
              { "TDL Type", "dis.radio.tdl_type",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_TDL_Type_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_sample_rate,
              { "Sample Rate", "dis.radio.sample_rate",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_data_length,
              { "Data Length", "dis.radio.data_length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_num_of_samples,
              { "Number of Samples", "dis.radio.num_of_samples",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_signal_data,
              {"Data", "dis.radio.signal_data",
               FT_BYTES,        BASE_NONE, NULL, 0x0,
               NULL, HFILL}
            },
            { &hf_dis_radio_category,
              { "Radio Category", "dis.radio.radio_category",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_RadioCategory_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_nomenclature_version,
              { "Nomenclature Version", "dis.radio.nomenclature_version",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_NomenclatureVersion_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_nomenclature,
              { "Nomenclature", "dis.radio.nomenclature",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_Nomenclature_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_radio_transmit_state,
              { "Radio Transmit State", "dis.radio.transmit_state",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_RadioTransmitState_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_radio_input_source,
              { "Radio Input Source", "dis.radio.input_source",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_RadioInputSource_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_antenna_pattern_type,
              { "Antenna Pattern Type", "dis.radio.antenna_pattern_type",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_AntennaPatternType_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_antenna_pattern_length,
              { "Antenna Pattern Length", "dis.radio.antenna_pattern_length",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_transmit_frequency,
              { "Transmit Frequency (Hz)", "dis.radio.frequency",
                FT_UINT64, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_spread_spectrum_usage,
              { "Spread Spectrum", "dis.radio.mod_type.spread_spectrum_usage",
                FT_BOOLEAN, 16, TFS(&dis_modulation_spread_spectrum),0xFFFF,
                NULL, HFILL }
            },
            { &hf_dis_frequency_hopping,
              { "Frequency Hopping modulation", "dis.radio.mod_type.frequency_hopping",
                FT_BOOLEAN, 16, TFS(&dis_frequency_hopping_value),0x0001,
                NULL, HFILL }
            },
            { &hf_dis_pseudo_noise_modulation,
              { "Psuedo noise modulation",  "dis.radio.mod_type.pseudo_noise_modulation",
                FT_BOOLEAN, 16, TFS(&dis_pseudo_noise_value),0x0002,
                NULL, HFILL }
            },
            { &hf_dis_time_hopping,
              { "Time Hopping modulation",  "dis.radio.mod_type.time_hopping",
                FT_BOOLEAN, 16, TFS(&dis_time_hopping_value),0x0004,
                NULL, HFILL }
            },
            { &hf_dis_modulation_major,
              { "Major Modulation", "dis.radio.mod_type.major",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_MajorModulation_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_modulation_system,
              { "System Modulation", "dis.radio.mod_type.system",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_SystemModulation_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_crypto_system,
              { "Crypto System", "dis.radio.crypto_system",
                FT_UINT16, BASE_DEC, VALS(DIS_PDU_CryptoSystem_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_crypto_key,
              { "Encryption Key",  "dis.radio.encryption_key",
                FT_UINT16, BASE_HEX, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_encryption_mode,
              { "Encryption Mode",  "dis.radio.encryption_key.mode",
                FT_BOOLEAN, 16, TFS(&dis_encryption_mode_value),0x8000,
                NULL, HFILL }
            },
            { &hf_dis_key_identifier,
              { "Encryption Key ID",  "dis.radio.encryption_key.id",
                FT_UINT16, BASE_DEC, NULL,0x7FFF,
                NULL, HFILL }
            },
            { &hf_dis_modulation_parameter_length,
              { "Modulation Parameter Length", "dis.radio.mod_param.length",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_net_id,
              { "Frequency Hopping Network ID", "dis.radio.mod_param.cctt_cingars.fh_nw_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_set_id,
              { "Frequency Set ID", "dis.radio.mod_param.cctt_cingars.fh_set_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_lo_set_id,
              { "Frequency Lockout Set ID", "dis.radio.mod_param.cctt_cingars.fh_lo_set_id",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_msg_start,
              { "Start of Message", "dis.radio.mod_param.cctt_cingars.fh_msg_start",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ModParamMsgStart_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_reserved,
              { "Reserved", "dis.radio.mod_param.cctt_cingars.fh_reserved",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_sync_time_offset,
              { "Sync Time Offset (Seconds)", "dis.radio.mod_param.cctt_cingars.fh_sync_offset",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_security_key,
              { "Transmission Security Key", "dis.radio.mod_param.cctt_cingars.fh_securit_key",
                FT_UINT16, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_fh_clear_channel,
              { "Clear Channel", "dis.radio.mod_param.cctt_cingars.fh_clr_channel",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ModParamClrChannel_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_dump,
              {"Modulation Parameter All", "dis.radio.mod_param.all",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL}
            },
            { &hf_dis_mod_param_ts_allocation_mode,
              { "Time Slot Allocaton Mode", "dis.radio.mod_param.jtids.ts_alloc_mode",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_TSAllocationFidelity_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_transmitter_prim_mode,
              { "Transmitter Primary Mode", "dis.radio.mod_param.jtids.transmitter_primary_mode",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_TerminalPrimaryMode_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_transmitter_second_mode,
              { "Transmitter Primary Mode", "dis.radio.mod_param.jtids.transmitter_secondary_mode",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_TerminalSecondaryMode_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_sync_state,
              { "Synchronization State", "dis.radio.mod_param.jtids.sync_state",
                FT_UINT8, BASE_DEC, VALS(DIS_PDU_ModParamSyncState_Strings), 0x0,
                NULL, HFILL }
            },
            { &hf_dis_mod_param_network_sync_id,
              { "Network Sync ID", "dis.radio.mod_param.jtids.network_sync_id",
                FT_UINT32, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_antenna_pattern_parameter_dump,
              {"Antenna Pattern Parameter", "dis.radio.antenna_parameter",
               FT_BYTES, BASE_NONE, NULL, 0x0,
               NULL, HFILL}
            },
            { &hf_dis_signal_link16_npg,
              { "NPG Number", "dis.signal.link16.npg",
                 FT_UINT16, BASE_DEC, VALS(Link16_NPG_Strings), 0x0,
                 NULL, HFILL }
            },
            { &hf_dis_signal_link16_tsec_cvll,
              { "TSEC CVLL", "dis.signal.link16.tsec_cvll",
                 FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(DIS_PDU_Link16_CVLL_Strings), 0x0,
                 NULL, HFILL }
            },
            { &hf_dis_signal_link16_msec_cvll,
              { "MSEC CVLL", "dis.signal.link16.msec_cvll",
                 FT_UINT8, BASE_RANGE_STRING | BASE_DEC, RVALS(DIS_PDU_Link16_CVLL_Strings), 0x0,
                 NULL, HFILL }
            },
            { &hf_dis_signal_link16_message_type,
              { "Message Type", "dis.signal.link16.message_type",
                 FT_UINT8, BASE_DEC, VALS(DIS_PDU_Link16_MessageType_Strings), 0x0,
                 NULL, HFILL }
            },
            { &hf_dis_signal_link16_ptt,
              { "Perceived Transmit Time", "dis.signal.link16.ptt",
                FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_signal_link16_time_slot_type,
              { "Time Slot Type", "dis.signal.link16.time_slot_type", FT_UINT32, BASE_DEC, NULL, 0x7,
                 NULL, HFILL},
            },
            { &hf_dis_signal_link16_rti,
              { "Relay Transmission Indicator", "dis.signal.link16.relay", FT_BOOLEAN, 32, NULL, 0x8,
                 NULL, HFILL},
            },
            { &hf_dis_signal_link16_stn,
              { "Source Track Number", "dis.signal.link16.stn", FT_UINT32, BASE_OCT, NULL, 0x7FFF0,
                 NULL, HFILL },
            },
            { &hf_dis_signal_link16_sdusn,
              { "Secure Data Unit Serial Number", "dis.signal.link16.sdusn", FT_UINT16, BASE_DEC, NULL, 0x0,
                 NULL, HFILL },
            },
            { &hf_dis_num_shafts,
              { "Number of Shafts",  "dis.ua.number_of_shafts",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_num_apas,
              { "Number of APAs",  "dis.ua.number_of_apas",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
            { &hf_dis_num_ua_emitter_systems,
              { "Number of UA Emitter Systems",  "dis.ua.number_of_ua_emitter_systems",
                FT_UINT8, BASE_DEC, NULL, 0x0,
                NULL, HFILL }
            },
        };

    /* Setup protocol subtree array */
    static gint *ett[] =
    {
        &ett_dis,
        &ett_dis_header,
        &ett_dis_po_header,
        &ett_dis_ens,
        &ett_dis_crypto_key,
        &ett_dis_payload,
        &ett_dis_signal_link16_network_header,
        &ett_dis_signal_link16_message_data,
        &ett_dis_signal_link16_jtids_header,
    };

    module_t *dis_module;

    proto_dis = proto_register_protocol(dis_proto_name, dis_proto_name_short, "dis");
    proto_register_field_array(proto_dis, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    dis_module = prefs_register_protocol(proto_dis, proto_reg_handoff_dis);

    /* Create an unsigned integer preference to allow the user to specify the
     * UDP port on which to capture DIS packets.
     */
    prefs_register_uint_preference(dis_module, "udp.port",
        "DIS UDP Port",
        "Set the UDP port for DIS messages",
        10, &dis_udp_port);

    /* Perform the one-time initialization of the DIS parsers.
     */
    initializeParsers();
    initializeFieldParsers();
}

/* Register handoff routine for DIS dissector.  This will be invoked initially
 * and when the preferences are changed, to handle changing the UDP port for
 * which this dissector is registered.
 */
void proto_reg_handoff_dis(void)
{
    static gboolean dis_prefs_initialized = FALSE;
    static dissector_handle_t dis_dissector_handle;
    static guint saved_dis_udp_port;

    if (!dis_prefs_initialized)
    {
        dis_dissector_handle = new_create_dissector_handle(dissect_dis, proto_dis);
        dis_prefs_initialized = TRUE;
    }
    else
    {
        dissector_delete_uint("udp.port", saved_dis_udp_port, dis_dissector_handle);
    }

    dissector_add_uint("udp.port", dis_udp_port, dis_dissector_handle);
    saved_dis_udp_port = dis_udp_port;
}

