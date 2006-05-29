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

    /* other atomic types, including enumerations */
    DIS_FIELDTYPE_APPEARANCE,
    DIS_FIELDTYPE_ARTIC_PARAM_TYPE_DESIGNATOR,
    DIS_FIELDTYPE_ARTIC_PARAM_TYPE,
    DIS_FIELDTYPE_CAPABILITIES,
    DIS_FIELDTYPE_CATEGORY,
    DIS_FIELDTYPE_COUNTRY,
    DIS_FIELDTYPE_DEAD_RECKONING_PARAMS,
    DIS_FIELDTYPE_DEAD_RECKONING_ALGORITHM,
    DIS_FIELDTYPE_DEAD_RECKONING_OTHER_PARAMS,
    DIS_FIELDTYPE_DETONATION_RESULT,
    DIS_FIELDTYPE_DOMAIN,
    DIS_FIELDTYPE_ENTITY_KIND,
    DIS_FIELDTYPE_ENTITY_MARKING,
    DIS_FIELDTYPE_EXTRA,
    DIS_FIELDTYPE_FORCE_ID,
    DIS_FIELDTYPE_FUSE,
    DIS_FIELDTYPE_ORIENTATION,
    DIS_FIELDTYPE_PDU_TYPE,
    DIS_FIELDTYPE_PROTOCOL_FAMILY,
    DIS_FIELDTYPE_PROTOCOL_VERSION,
    DIS_FIELDTYPE_SPECIFIC,
    DIS_FIELDTYPE_SUBCATEGORY,
    DIS_FIELDTYPE_TIMESTAMP,
    DIS_FIELDTYPE_WARHEAD,

    /* composite types */
    DIS_FIELDTYPE_ARTICULATION_PARAMETERS,
    DIS_FIELDTYPE_BURST_DESCRIPTOR,
    DIS_FIELDTYPE_ENTITY_ID,
    DIS_FIELDTYPE_ENTITY_TYPE,
    DIS_FIELDTYPE_EVENT_ID,
    DIS_FIELDTYPE_LINEAR_VELOCITY,
    DIS_FIELDTYPE_LOCATION_WORLD,
    DIS_FIELDTYPE_LOCATION_ENTITY
} DIS_FieldType;

/* Struct which contains the data needed to parse a single DIS field.
 */
typedef struct DIS_ParserNode_T
{
    DIS_FieldType fieldType;
    const char *fieldLabel;
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

extern DIS_ParserNode DIS_FIELDS_PDU_HEADER[];

extern DIS_ParserNode DIS_FIELDS_ENTITY_ID[];

extern DIS_ParserNode DIS_FIELDS_ENTITY_TYPE[];

extern DIS_ParserNode DIS_FIELDS_EVENT_ID[];

extern DIS_ParserNode DIS_FIELDS_LINEAR_VELOCITY[];

extern DIS_ParserNode DIS_FIELDS_LOCATION_WORLD[];

extern DIS_ParserNode DIS_FIELDS_LOCATION_ENTITY[];

extern DIS_ParserNode DIS_FIELDS_BURST_DESCRIPTOR[];

extern DIS_ParserNode DIS_FIELDS_ARTICULATION_PARAMETER[];

extern DIS_ParserNode DIS_FIELDS_ORIENTATION[];

extern DIS_ParserNode DIS_FIELDS_NONE[];

extern DIS_BitMask DIS_APPEARANCE_LANDPLATFORM[];

extern DIS_BitMask DIS_APPEARANCE_LIFEFORM[];

gint parseField_Bytes(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

gint parseField_Bitmask(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

gint parseField_UInt(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

gint parseField_Int(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

gint parseField_Enum(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

gint parseField_Pad(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes);

gint parseField_Float(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode);

gint parseField_Double(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode);

extern guint32 pduType;
extern guint32 entityKind;
extern guint32 entityDomain;

#endif /* packet-dis-fieldparsers.h */
