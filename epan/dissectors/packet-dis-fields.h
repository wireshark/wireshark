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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifndef __PACKET_DIS_FIELDPARSERS_H__
#define __PACKET_DIS_FIELDPARSERS_H__

#include <epan/packet.h>

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

    /* other atomic types */
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

    /* composite types */
    DIS_FIELDTYPE_BURST_DESCRIPTOR,
    DIS_FIELDTYPE_CLOCK_TIME,
    DIS_FIELDTYPE_ENTITY_ID,
    DIS_FIELDTYPE_ENTITY_TYPE,
    DIS_FIELDTYPE_EVENT_ID,
    DIS_FIELDTYPE_LINEAR_VELOCITY,
    DIS_FIELDTYPE_LOCATION_ENTITY,
    DIS_FIELDTYPE_LOCATION_WORLD,
    DIS_FIELDTYPE_ORIENTATION,
    DIS_FIELDTYPE_SIMULATION_ADDRESS,
    DIS_FIELDTYPE_VARIABLE_DATUM_VALUE,
    DIS_FIELDTYPE_VECTOR_32,
    DIS_FIELDTYPE_VECTOR_64,

    /* arrays */
    DIS_FIELDTYPE_FIXED_DATUMS,
    DIS_FIELDTYPE_FIXED_DATUM_IDS,
    DIS_FIELDTYPE_VARIABLE_DATUMS,
    DIS_FIELDTYPE_VARIABLE_DATUM_IDS,
    DIS_FIELDTYPE_VARIABLE_PARAMETERS,
    DIS_FIELDTYPE_VARIABLE_RECORDS

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
extern DIS_ParserNode DIS_FIELDS_EVENT_ID[];
extern DIS_ParserNode DIS_FIELDS_ORIENTATION[];
extern DIS_ParserNode DIS_FIELDS_SIMULATION_ADDRESS[];
extern DIS_ParserNode DIS_FIELDS_VECTOR_FLOAT_32[];
extern DIS_ParserNode DIS_FIELDS_VECTOR_FLOAT_64[];

/* Array records */
extern DIS_ParserNode DIS_FIELDS_FIXED_DATUM[];
extern DIS_ParserNode DIS_FIELDS_VARIABLE_DATUM[];
extern DIS_ParserNode DIS_FIELDS_DATUM_IDS[];
extern DIS_ParserNode DIS_FIELDS_VP_TYPE[];
extern DIS_ParserNode DIS_FIELDS_VR_TYPE[];

/* Bit fields */
extern DIS_ParserNode DIS_FIELDS_NONE[];
extern DIS_BitMask DIS_APPEARANCE_LANDPLATFORM[];
extern DIS_BitMask DIS_APPEARANCE_LIFEFORM[];

extern void initializeFieldParsers();

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

extern guint32 protocolVersion;
extern guint32 pduType;
extern guint32 protocolFamily;
extern guint32 persistentObjectPduType;
extern guint32 entityKind;
extern guint32 entityDomain;
extern guint32 numFixed;
extern guint32 numVariable;
extern guint32 variableDatumLength;
extern guint32 variableRecordLength;

#endif /* packet-dis-fieldparsers.h */
