/* packet-dis-enums.c
 * String definitions for DIS enumerations.
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
    { DIS_VERSION_IEEE_1278_1_200X,  "IEEE 1278.1-200X" },
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
    { DIS_PROTOCOLFAMILY_INFORMATION_OPERATIONS,                 "Information Operations" },
    { DIS_PROTOCOLFAMILY_EXPERIMENTAL_COMPUTER_GENERATED_FORCES, "Experimental - Computer Generated Forces" },
    { DIS_PROTOCOLFAMILY_EXPERIMENTAL_VDIS,                      "Experimental - V-DIS" },
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
    { DIS_DOMAIN_SUBSURFACE, "Subsurface" },
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

const value_string DIS_PDU_Encoding_Class_Strings[] =
{
    { DIS_ENCODING_CLASS_ENCODED_AUDIO,    "Encoded Audio" },
    { DIS_ENCODING_CLASS_RAW_BINARY_DATA,  "Raw Binary Data" },
    { DIS_ENCODING_CLASS_APPL_SPEC_DATA,   "Application-Specific Data" },
    { DIS_ENCODING_CLASS_DB_INDEX,         "Database index" },
    { 0,                                   NULL }
};

const value_string DIS_PDU_Encoding_Type_Strings[] =
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

const value_string DIS_PDU_TDL_Type_Strings[] =
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

const value_string DIS_PDU_RadioCategory_Strings[] =
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

const value_string DIS_PDU_NomenclatureVersion_Strings[] =
{
    {0,    "Other" },
    {1,    "Joint Electronics Type Designation System (JETDS) Nomenclature (AN/ per Mil-STD-196)" },
    {2,    "Manufacturer Designation" },
    {3,    "National Designation" },
    {0,    NULL }
};

const value_string DIS_PDU_Nomenclature_Strings[] =
{
    {0,    "Other" },
    {1,    "AN/ARN-118" },
    {2,    "AN/ARN-139" },
    {3,    "Generic Ground Fixed Transmitter" },
    {4,    "Generic Ground Mobile Transmitter" },
    {0,    NULL }
};

const value_string DIS_PDU_RadioTransmitState_Strings[] =
{
    {0,    "Off" },
    {1,    "On but not transmitting" },
    {2,    "On and transmitting" },
    {0,    NULL }
};

const value_string DIS_PDU_RadioInputSource_Strings[] =
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

const value_string DIS_PDU_AntennaPatternType_Strings[] =
{
    {0,    "Omni-directional" },
    {1,    "Beam" },
    {2,    "Spherical harmonic" },
    {0,    NULL }
};

const value_string DIS_PDU_MajorModulation_Strings[] =
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

const value_string DIS_PDU_DetailModulationAmplitude_Strings[] =
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

const value_string DIS_PDU_DetailModulationAmpAndAngle_Strings[] =
{
    {0,    "Other" },
    {1,    "Amplitude and Angle" },
    {0,    NULL }
};

const value_string DIS_PDU_DetailModulationAngle_Strings[] =
{
    {0,    "Other" },
    {1,    "FM (Frequency Modulation)" },
    {2,    "FSK (Frequency Shift Keying)" },
    {3,    "PM (Phase Modulation)" },
    {0,    NULL }
};

const value_string DIS_PDU_DetailModulationCombination_Strings[] =
{
    {0,    "Other" },
    {1,    "Amplitude-Angle-Pulse" },
    {0,    NULL }
};

const value_string DIS_PDU_DetailModulationPulse_Strings[] =
{
    {0,    "Other" },
    {1,    "Pulse" },
    {2,    "X Band TACAN Pulse" },
    {3,    "Y Band TACAN Pulse" },
    {0,    NULL }
};

const value_string DIS_PDU_DetailModulationUnmodulated_Strings[] =
{
    {0,    "Other" },
    {1,    "Continuous Wave emission of an unmodulated carrier" },
    {0,    NULL }
};

const value_string DIS_PDU_DetailModulationCPSM_Strings[] =
{
    {0,    "Other" },
    {0,    NULL }
};

const value_string DIS_PDU_ModParamMsgStart_Strings[] =
{
    {0,    "Not start of message" },
    {1,    "Start of Message" },
    {0,    NULL }
};

const value_string DIS_PDU_ModParamClrChannel_Strings[] =
{
    {0,    "Not clear channel" },
    {1,    "Clear channel" },
    {0,    NULL }
};

const value_string DIS_PDU_TSAllocationFidelity_Strings[] =
{
    {0,    "Time Slot Allocation Fidelity Level 0" },
    {1,    "Time Slot Allocation Fidelity Level 1" },
    {2,    "Time Slot Allocation Fidelity Level 2" },
    {3,    "Time Slot Allocation Fidelity Level 3" },
    {4,    "Time Slot Allocation Fidelity Level 4" },
    {0,    NULL }
};

const value_string DIS_PDU_TerminalPrimaryMode_Strings[] =
{
    {0,    "NTR" },
    {1,    "JTIDS Unit Participant" },
    {0,    NULL }
};

const value_string DIS_PDU_TerminalSecondaryMode_Strings[] =
{
    {0,    "None" },
    {1,    "Net Position Reference" },
    {2,    "Primary Navigation Controller" },
    {3,    "Secondary Navigation Controller" },
    {0,    NULL }
};

const value_string DIS_PDU_ModParamSyncState_Strings[] =
{
    {0,    "Undefined" },
    {1,    "Coarse Synchronization" },
    {1,    "Fine Synchronization" },
    {0,    NULL }
};


const value_string DIS_PDU_SystemModulation_Strings[] =
{
    {0,    "Other" },
    {1,    "Generic" },
    {2,    "HQ" },
    {3,    "HQII" },
    {4,    "HQIIA" },
    {5,    "SINCGARS" },
    {6,    "CCTT SINCGARS" },
    {7,    "EPLRS (Enhanced Position Location Reporting System)" },
    {8,    "JTIDS/MIDS" },
    {0,    NULL }
};

const value_string DIS_PDU_CryptoSystem_Strings[] =
{
    {0,    "Other" },
    {1,    "KY-28" },
    {2,    "VINSON (KY-57, KY-58, SINCGARS ICOM)" },
    {3,    "Narrow Spectrum Secure Voice (NSVE)" },
    {4,    "Wide Spectrum Secure Voice (WSVE)" },
    {0,    NULL }
};

const value_string DIS_PDU_AcknowledgeFlag_Strings[] =
{
    { DIS_ACKNOWLEDGE_FLAG_CREATE_ENTITY,            "Create Entity" },
    { DIS_ACKNOWLEDGE_FLAG_REMOVE_ENTITY,            "Remove Entity" },
    { DIS_ACKNOWLEDGE_FLAG_START_RESUME,             "Start Resume" },
    { DIS_ACKNOWLEDGE_FLAG_STOP_FREEZE,              "Stop Freeze" },
    { DIS_ACKNOWLEDGE_FLAG_TRANSFER_CONTROL_REQUEST, "Transfer Control Request" },
    { 0,                                             NULL }
};

const value_string DIS_PDU_ActionId_Strings[] =
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

const value_string DIS_PDU_ApplicationGeneralStatus_Strings[] =
{
    { DIS_APPLICATION_GENERAL_STATUS_UNKNOWN,                  "Unknown" },
    { DIS_APPLICATION_GENERAL_STATUS_FUNCTIONAL,               "Functional" },
    { DIS_APPLICATION_GENERAL_STATUS_DEGRADED_BUT_FUNCTIONAL,  "Degraded But Functional" },
    { DIS_APPLICATION_GENERAL_STATUS_NOT_FUNCTIONAL,           "Not Functional" },
    { 0,                                                       NULL }
};

const value_string DIS_PDU_ApplicationStatusType_Strings[] =
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

const value_string DIS_PDU_ApplicationType_Strings[] =
{
    { DIS_APPLICATION_TYPE_OTHER,                        "Other" },
    { DIS_APPLICATION_TYPE_RESOURCE_MANAGER,             "Resource Manager" },
    { DIS_APPLICATION_TYPE_SIMULATION_MANAGER,           "Simulation Manager" },
    { DIS_APPLICATION_TYPE_GATEWAY,                      "Gateway" },
    { DIS_APPLICATION_TYPE_STEALTH,                      "Stealth" },
    { DIS_APPLICATION_TYPE_TACTICAL_INTERNET_INTERFACE,  "Tactical Internet Interface" },
    { 0,                                                 NULL }
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

const value_string DIS_PDU_ControlId_Strings[] =
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

const value_string DIS_PDU_FrozenBehavior_Strings[] =
{
    { DIS_FROZEN_BEHAVIOR_RUN_INTERNAL_SIMULATION_CLOCK,                "Run Internal Simulation Clock" },
    { DIS_FROZEN_BEHAVIOR_TRANSMIT_PDUS,                                "Transmit PDUs" },
    { DIS_FROZEN_BEHAVIOR_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES,          "Update Sim Models Of Other Entities" },
    { DIS_FROZEN_BEHAVIOR_CONTINUE_TRANSMIT_PDU,                        "Continue Transmit PDU" },
    { DIS_FROZEN_BEHAVIOR_CEASE_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES,    "Cease Update Sim Models Of Other Entities" },
    { DIS_FROZEN_BEHAVIOR_CONTINUE_UPDATE_SIM_MODELS_OF_OTHER_ENTITIES, "Continue Update Sim Models Of Other Entities" },
    { 0,                                                                NULL }
};

const value_string DIS_PDU_ParameterTypeDesignator_Strings[] =
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

const value_string DIS_PDU_Reason_Strings[] =
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

const value_string DIS_PDU_RequestStatus_Strings[] =
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

const value_string DIS_PDU_RequiredReliabilityService_Strings[] =
{
    { DIS_REQUIRED_RELIABILITY_SERVICE_ACKNOWLEDGED,     "Acknowledged" },
    { DIS_REQUIRED_RELIABILITY_SERVICE_UNACKNOWLEDGED,   "Unacknowledged" },
    { 0,                                                 NULL }
};

const value_string DIS_PDU_DisResponseFlag_Strings[] =
{
    { DIS_RESPONSE_FLAG_OTHER,                      "Other" },
    { DIS_RESPONSE_FLAG_ABLE_TO_COMPLY,             "Able To Comply" },
    { DIS_RESPONSE_FLAG_UNABLE_TO_COMPLY,           "Unable To Comply" },
    { DIS_RESPONSE_FLAG_PENDING_OPERATOR_ACTION,    "Pending Operator Action" },
    { 0,                                            NULL }
};

const value_string DIS_PDU_PersistentObjectType_Strings[] =
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

const value_string DIS_PDU_PO_ObjectClass_Strings[] =
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
