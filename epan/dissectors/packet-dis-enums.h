/* packet-dis-enums.h
 * Enumerated values and string array declarations for DIS enum parsing.
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

#ifndef __PACKET_DIS_ENUMS_H__
#define __PACKET_DIS_ENUMS_H__

#include <epan/value_string.h>

typedef enum
{
    DIS_VERSION_OTHER             = 0,
    DIS_VERSION_1_0               = 1,
    DIS_VERSION_IEEE_1278_1993    = 2,
    DIS_VERSION_2_0_3RD_DRAFT     = 3,
    DIS_VERSION_2_0_4TH_DRAFT     = 4,
    DIS_VERSION_IEEE_1278_1_1995  = 5,
    DIS_VERSION_IEEE_1278_1A_1998 = 6
} DIS_PDU_ProtocolVersion;

extern const value_string DIS_PDU_ProtocolVersion_Strings[];

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
    DIS_PROTOCOLFAMILY_EXPERIMENTAL_COMPUTER_GENERATED_FORCES = 129,
    DIS_PROTOCOLFAMILY_PERSISTENT_OBJECT                      = 140,
    DIS_PROTOCOLFAMILY_EXPERIMENTAL                           = 150
} DIS_PDU_ProtocolFamily;

extern const value_string DIS_PDU_ProtocolFamily_Strings[];

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
    DIS_PDUTYPE_IFF_ATC_NAVAIDS                    = 28,
    DIS_PDUTYPE_UNDERWATER_ACOUSTIC                = 29,
    DIS_PDUTYPE_SUPPLEMENTAL_EMISSION_ENTITY_STATE = 30,
    DIS_PDUTYPE_INTERCOM_SIGNAL                    = 31,
    DIS_PDUTYPE_INTERCOM_CONTROL                   = 32,
    DIS_PDUTYPE_AGGREGATE_STATE                    = 33,
    DIS_PDUTYPE_IS_GROUP_OF                        = 34,
    DIS_PDUTYPE_TRANSFER_CONTROL                   = 35,
    DIS_PDUTYPE_IS_PART_OF                         = 36,
    DIS_PDUTYPE_MINEFIELD_STATE                    = 37,
    DIS_PDUTYPE_MINEFIELD_QUERY                    = 38,
    DIS_PDUTYPE_MINEFIELD_DATA                     = 39,
    DIS_PDUTYPE_MINEFIELD_RESPONSE_NAK             = 40,
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
    DIS_PDUTYPE_ANNOUNCE_OBJECT                    = 129,
    DIS_PDUTYPE_DELETE_OBJECT                      = 130,
    DIS_PDUTYPE_DESCRIBE_APPLICATION               = 131,
    DIS_PDUTYPE_DESCRIBE_EVENT                     = 132,
    DIS_PDUTYPE_DESCRIBE_OBJECT                    = 133,
    DIS_PDUTYPE_REQUEST_EVENT                      = 134,
    DIS_PDUTYPE_REQUEST_OBJECT                     = 135
} DIS_PDU_Type;

extern const value_string DIS_PDU_Type_Strings[];

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

extern const value_string DIS_PDU_EntityKind_Strings[];

typedef enum
{
    DIS_DOMAIN_OTHER      = 0,
    DIS_DOMAIN_LAND       = 1,
    DIS_DOMAIN_AIR        = 2,
    DIS_DOMAIN_SURFACE    = 3,
    DIS_DOMAIN_SUBSURFACE = 4,
    DIS_DOMAIN_SPACE      = 5
} DIS_PDU_Domain;

extern const value_string DIS_PDU_Domain_Strings[];

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

extern const value_string DIS_PDU_Category_LandPlatform_Strings[];

typedef enum
{
    DIS_CATEGORY_AIRPLATFORM_OTHER                             = 0,
    DIS_CATEGORY_AIRPLATFORM_FIGHTER_AIR_DEFENSE               = 1,
    DIS_CATEGORY_AIRPLATFORM_ATTACK_STRIKE                     = 2,
    DIS_CATEGORY_AIRPLATFORM_BOMBER                            = 3,
    DIS_CATEGORY_AIRPLATFORM_CARGO_TANKER                      = 4,
    DIS_CATEGORY_AIRPLATFORM_ASW_PATROL_OBSERVATION            = 5,
    DIS_CATEGORY_AIRPLATFORM_ELECTRONIC_WARFARE                = 6,
    DIS_CATEGORY_AIRPLATFORM_RECONAISSANCE                     = 7,
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

extern const value_string DIS_PDU_Category_AirPlatform_Strings[];

typedef enum
{
    DIS_CATEGORY_SURFACEPLATFORM_OTHER = 0
} DIS_PDU_Category_SurfacePlatform;

extern const value_string DIS_PDU_Category_SurfacePlatform_Strings[];

typedef enum
{
    DIS_CATEGORY_SUBSURFACEPLATFORM_OTHER = 0
} DIS_PDU_Category_SubsurfacePlatform;

extern const value_string DIS_PDU_Category_SubsurfacePlatform_Strings[];

typedef enum
{
    DIS_CATEGORY_SPACEPLATFORM_OTHER = 0
} DIS_PDU_Category_SpacePlatform;

extern const value_string DIS_PDU_Category_SpacePlatform_Strings[];

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

extern const value_string DIS_PDU_DetonationResult_Strings[];

#endif /* packet-dis-enums.h */
