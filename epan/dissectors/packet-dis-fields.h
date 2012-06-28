/* packet-dis-fields.h
 * Declarations for DIS field parsing.
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

#ifndef __PACKET_DIS_FIELDPARSERS_H__
#define __PACKET_DIS_FIELDPARSERS_H__

#include <epan/packet.h>

extern int hf_dis_proto_ver;
extern int hf_dis_exercise_id;
extern int hf_dis_pdu_type;
extern int hf_dis_proto_fam;
extern int hf_dis_pdu_length;
extern int hf_dis_entity_id_site;
extern int hf_dis_entity_id_application;
extern int hf_dis_entity_id_entity;
extern int hf_dis_num_art_params;
extern int hf_dis_entityKind;
extern int hf_dis_entityDomain;
extern int hf_dis_category_land;
extern int hf_dis_category_air;
extern int hf_dis_category_surface;
extern int hf_dis_category_subsurface;
extern int hf_dis_category_space;
extern int hf_dis_category_radio;
extern int hf_dis_num_electromagnetic_emission_systems;
extern int hf_dis_emitter_name;
extern int hf_dis_emission_function;
extern int hf_dis_beam_function;
extern int hf_dis_radio_id;
extern int hf_dis_ens;
extern int hf_dis_ens_class;
extern int hf_dis_ens_type;
extern int hf_dis_tdl_type;
extern int hf_dis_sample_rate;
extern int hf_dis_data_length;
extern int hf_dis_num_of_samples;
extern int hf_dis_signal_data;
extern int hf_dis_radio_category;
extern int hf_dis_nomenclature_version;
extern int hf_dis_nomenclature;
extern int hf_dis_radio_transmit_state;
extern int hf_dis_radio_input_source;
extern int hf_dis_antenna_pattern_type;
extern int hf_dis_antenna_pattern_length;
extern int hf_dis_transmit_frequency;
extern int hf_dis_spread_spectrum_usage;
extern int hf_dis_frequency_hopping;
extern int hf_dis_pseudo_noise_modulation;
extern int hf_dis_time_hopping;
extern int hf_dis_modulation_major;
extern int hf_dis_modulation_system;
extern int hf_dis_crypto_system;
extern int hf_dis_crypto_key;
extern int hf_dis_encryption_mode;
extern int hf_dis_key_identifier;
extern int hf_dis_modulation_parameter_length;
extern int hf_dis_mod_param_fh_net_id;
extern int hf_dis_mod_param_fh_set_id;
extern int hf_dis_mod_param_fh_lo_set_id;
extern int hf_dis_mod_param_fh_msg_start;
extern int hf_dis_mod_param_fh_reserved;
extern int hf_dis_mod_param_fh_sync_time_offset;
extern int hf_dis_mod_param_fh_security_key;
extern int hf_dis_mod_param_fh_clear_channel;
extern int hf_dis_mod_param_dump;
extern int hf_dis_mod_param_ts_allocation_mode;
extern int hf_dis_mod_param_transmitter_prim_mode;
extern int hf_dis_mod_param_transmitter_second_mode;
extern int hf_dis_mod_param_sync_state;
extern int hf_dis_mod_param_network_sync_id;
extern int hf_dis_antenna_pattern_parameter_dump;

extern int ett_dis_ens;
extern int ett_dis_crypto_key;



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
    DIS_FIELDTYPE_NUM_ELECTROMAGNETIC_EMISSION_SYSTEMS,

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
    DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM,
    DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM,
    DIS_FIELDTYPE_EMITTER_SYSTEM,
    DIS_FIELDTYPE_FUNDAMENTAL_PARAMETER_DATA,
    DIS_FIELDTYPE_TRACK_JAM,
    
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

/* Headers */
extern DIS_ParserNode DIS_FIELDS_PDU_HEADER[];
extern DIS_ParserNode DIS_FIELDS_PERSISTENT_OBJECT_HEADER[];

/* Composite types */
extern DIS_ParserNode DIS_FIELDS_BURST_DESCRIPTOR[];
extern DIS_ParserNode DIS_FIELDS_CLOCK_TIME[];
extern DIS_ParserNode DIS_FIELDS_ENTITY_ID[];
extern DIS_ParserNode DIS_FIELDS_ENTITY_TYPE[];
extern DIS_ParserNode DIS_FIELDS_RADIO_ENTITY_TYPE[];
extern DIS_ParserNode DIS_FIELDS_MODULATION_TYPE[];
extern DIS_ParserNode DIS_FIELDS_EVENT_ID[];
extern DIS_ParserNode DIS_FIELDS_ORIENTATION[];
extern DIS_ParserNode DIS_FIELDS_SIMULATION_ADDRESS[];
extern DIS_ParserNode DIS_FIELDS_VECTOR_FLOAT_32[];
extern DIS_ParserNode DIS_FIELDS_VECTOR_FLOAT_64[];
extern DIS_ParserNode DIS_FIELDS_MOD_PARAMS_CCTT_SINCGARS[];
extern DIS_ParserNode DIS_FIELDS_MOD_PARAMS_JTIDS_MIDS[];
extern DIS_ParserNode DIS_FIELDS_EMITTER_SYSTEM[];
extern DIS_ParserNode DIS_FIELDS_FUNDAMENTAL_PARAMETER_DATA[];
extern DIS_ParserNode DIS_FIELDS_TRACK_JAM[];

/* Array records */
extern DIS_ParserNode DIS_FIELDS_FIXED_DATUM[];
extern DIS_ParserNode DIS_FIELDS_VARIABLE_DATUM[];
extern DIS_ParserNode DIS_FIELDS_DATUM_IDS[];
extern DIS_ParserNode DIS_FIELDS_VP_TYPE[];
extern DIS_ParserNode DIS_FIELDS_VR_TYPE[];
extern DIS_ParserNode DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM[];
extern DIS_ParserNode DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM[];

/* Bit fields */
extern DIS_ParserNode DIS_FIELDS_NONE[];
extern DIS_BitMask DIS_APPEARANCE_LANDPLATFORM[];
extern DIS_BitMask DIS_APPEARANCE_LIFEFORM[];

extern void initializeFieldParsers(void);

extern gint parseField_Bytes(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

extern gint parseField_Bitmask(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

extern gint parseField_UInt(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

extern gint parseField_Int(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

extern gint parseField_Enum(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

extern gint parseField_Pad(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

extern gint parseField_Float(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode);

extern gint parseField_Double(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode);

extern gint parseField_Timestamp(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode);

extern gint parseField_VariableParameter(tvbuff_t *tvb, proto_tree *tree, gint offset);

extern gint parseField_VariableRecord(tvbuff_t *tvb, proto_tree *tree, gint offset);

extern gint parseField_ElectromagneticEmissionSystemBeam(tvbuff_t *tvb, proto_tree *tree, gint offset);

extern guint32 disProtocolVersion;
extern guint32 pduType;
extern guint32 protocolFamily;
extern guint32 persistentObjectPduType;
extern guint32 entityKind;
extern guint32 entityDomain;
extern guint32 radioID;
extern guint32 disRadioTransmitState;
extern guint32 encodingScheme;
extern guint32 numSamples;
extern guint32 numFixed;
extern guint32 numVariable;
extern guint32 numBeams;
extern guint32 numTrackJamTargets;
extern guint32 variableDatumLength;
extern guint32 variableRecordLength;
extern guint32 majorModulation;
extern guint32 systemModulation;
extern guint32 modulationParamLength;
extern guint32 disAntennaPattern;


#endif /* packet-dis-fieldparsers.h */
