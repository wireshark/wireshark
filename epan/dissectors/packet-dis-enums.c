/* packet-dis-enums.c
 * String definitions for DIS enumerations.
 * Copyright 2005, Scientific Research Corporation
 * Initial implementation by Jeremy Ouellette <jouellet@scires.com>
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#include "packet-dis-enums.h"
#include <epan/value_string.h>

const value_string DIS_PDU_ProtocolVersion_Strings[] =
{
    { DIS_VERSION_OTHER,             "Other" },
    { DIS_VERSION_1_0,               "DIS PDU version 1.0 (May 92)" },
    { DIS_VERSION_IEEE_1278_1993,    "IEEE 1278-1993" },
    { DIS_VERSION_2_0_3RD_DRAFT,     "DIS PDU version 2.0 - third draft (May 93)" },
    { DIS_VERSION_2_0_4TH_DRAFT,     "DIS PDU version 2.0 - fourth draft (revised) March 16, 1994" },
    { DIS_VERSION_IEEE_1278_1_1995,  "IEEE 1278.1-1995" },
    { DIS_VERSION_IEEE_1278_1A_1998, "IEEE 1278.1A-1998" },
    { 0,                             NULL }
};

const value_string DIS_PDU_ProtocolFamily_Strings[] =
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
    { DIS_PROTOCOLFAMILY_EXPERIMENTAL_COMPUTER_GENERATED_FORCES, "Experimental - Computer Generated Forces" },
    { DIS_PROTOCOLFAMILY_PERSISTENT_OBJECT,                      "Persistent object" },
    { DIS_PROTOCOLFAMILY_EXPERIMENTAL,                           "Experimental" },
    { 0,                                                         NULL }
};

const value_string DIS_PDU_Type_Strings[] =
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
    { DIS_PDUTYPE_IFF_ATC_NAVAIDS,                    "IFF / ATC / NAVAIDS" },
    { DIS_PDUTYPE_UNDERWATER_ACOUSTIC,                "Underwater Acoustic" },
    { DIS_PDUTYPE_SUPPLEMENTAL_EMISSION_ENTITY_STATE, "Supplemental Emission Entity State" },
    { DIS_PDUTYPE_INTERCOM_SIGNAL,                    "Intercom Signal" },
    { DIS_PDUTYPE_INTERCOM_CONTROL,                   "Intercom Control" },
    { DIS_PDUTYPE_AGGREGATE_STATE,                    "Aggregate State" },
    { DIS_PDUTYPE_IS_GROUP_OF,                        "IsGroupOf" },
    { DIS_PDUTYPE_TRANSFER_CONTROL,                   "Transfer Control" },
    { DIS_PDUTYPE_IS_PART_OF,                         "IsPartOf" },
    { DIS_PDUTYPE_MINEFIELD_STATE,                    "Minefield State" },
    { DIS_PDUTYPE_MINEFIELD_QUERY,                    "Minefield Query" },
    { DIS_PDUTYPE_MINEFIELD_DATA,                     "Minefield Data" },
    { DIS_PDUTYPE_MINEFIELD_RESPONSE_NAK,             "Minefield Response NAK" },
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
    { DIS_PDUTYPE_ANNOUNCE_OBJECT,                    "Announce Object" },
    { DIS_PDUTYPE_DELETE_OBJECT,                      "Delete Object" },
    { DIS_PDUTYPE_DESCRIBE_APPLICATION,               "Describe Application" },
    { DIS_PDUTYPE_DESCRIBE_EVENT,                     "Describe Event" },
    { DIS_PDUTYPE_DESCRIBE_OBJECT,                    "Describe Object" },
    { DIS_PDUTYPE_REQUEST_EVENT,                      "Request Event" },
    { DIS_PDUTYPE_REQUEST_OBJECT,                     "Request Object" },
    { 0,                                              NULL }
};

const value_string DIS_PDU_EntityKind_Strings[] =
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

const value_string DIS_PDU_Domain_Strings[] =
{
    { DIS_DOMAIN_OTHER,      "Other" },
    { DIS_DOMAIN_LAND,       "Land" },
    { DIS_DOMAIN_AIR,        "Air" },
    { DIS_DOMAIN_SURFACE,    "Surface" },
    { DIS_DOMAIN_SUBSURFACE, "Sursurface" },
    { DIS_DOMAIN_SPACE,      "Space" },
    { 0,                     NULL }
};

const value_string DIS_PDU_Category_LandPlatform_Strings[] =
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

const value_string DIS_PDU_Category_AirPlatform_Strings[] =
{
    { DIS_CATEGORY_AIRPLATFORM_OTHER,                             "Other" },
    { DIS_CATEGORY_AIRPLATFORM_FIGHTER_AIR_DEFENSE,               "Fighter / air defense" },
    { DIS_CATEGORY_AIRPLATFORM_ATTACK_STRIKE,                     "Attack / strike" },
    { DIS_CATEGORY_AIRPLATFORM_BOMBER,                            "Bomber" },
    { DIS_CATEGORY_AIRPLATFORM_CARGO_TANKER,                      "Cargo tanker" },
    { DIS_CATEGORY_AIRPLATFORM_ASW_PATROL_OBSERVATION,            "ASW / patrol / observation" },
    { DIS_CATEGORY_AIRPLATFORM_ELECTRONIC_WARFARE,                "Electronic warfare" },
    { DIS_CATEGORY_AIRPLATFORM_RECONAISSANCE,                     "Reconaissance" },
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

const value_string DIS_PDU_Category_SurfacePlatform_Strings[] =
{
    { DIS_CATEGORY_SURFACEPLATFORM_OTHER, "Other" },
    { 0,                                  NULL}
};

const value_string DIS_PDU_Category_SubsurfacePlatform_Strings[] =
{
    { DIS_CATEGORY_SUBSURFACEPLATFORM_OTHER, "Other" },
    { 0,                                     NULL }
};

const value_string DIS_PDU_Category_SpacePlatform_Strings[] =
{
    { DIS_CATEGORY_SPACEPLATFORM_OTHER, "Other" },
    { 0,                                NULL }
};

const value_string DIS_PDU_DetonationResult_Strings[] =
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
