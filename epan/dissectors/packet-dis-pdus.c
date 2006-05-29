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

guint32 numArticulations;
gint ettArticulations[DIS_PDU_MAX_ARTICULATIONS];

DIS_ParserNode DIS_PARSER_ENTITY_STATE_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Entity ID",0,0,0 },
    { DIS_FIELDTYPE_FORCE_ID,                "Force ID",0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Number of Articulation Parameters",0,0,&numArticulations },
    { DIS_FIELDTYPE_ENTITY_TYPE,             "Entity Type",0,0,0 },
    { DIS_FIELDTYPE_ENTITY_TYPE,             "Alternative Entity Type",0,0,0 },
    { DIS_FIELDTYPE_LINEAR_VELOCITY,         "Entity Linear Velocity",0,0,0 },
    { DIS_FIELDTYPE_LOCATION_WORLD,          "Entity Location",0,0,0 },
    { DIS_FIELDTYPE_ORIENTATION,             "Entity Orientation",0,0,0 },
    { DIS_FIELDTYPE_APPEARANCE,              "Entity Appearance",0,0,0 },
    { DIS_FIELDTYPE_DEAD_RECKONING_PARAMS,   "Dead Reckoning Parameters",0,0,0 },
    { DIS_FIELDTYPE_ENTITY_MARKING,          "Entity Marking",0,0,0 },
    { DIS_FIELDTYPE_CAPABILITIES,            "Capabilities",0,0,0 },
    { DIS_FIELDTYPE_ARTICULATION_PARAMETERS, "Articulation Parameters",0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0 }
};

DIS_ParserNode DIS_PARSER_FIRE_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,        "Firing Entity ID",0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,        "Target Entity ID",0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,        "Munition ID",0,0,0 },
    { DIS_FIELDTYPE_EVENT_ID,         "Event ID",0,0,0 },
    { DIS_FIELDTYPE_UINT32,           "Fire Mission Index",0,0,0 },
    { DIS_FIELDTYPE_LOCATION_WORLD,   "Location in World Coordinates",0,0,0 },
    { DIS_FIELDTYPE_BURST_DESCRIPTOR, "Burst Descriptor",0,0,0 },
    { DIS_FIELDTYPE_LINEAR_VELOCITY,  "Velocity",0,0,0 },
    { DIS_FIELDTYPE_FLOAT32,          "Range",0,0,0 },
    { DIS_FIELDTYPE_END,              NULL,0,0,0 }
};

DIS_ParserNode DIS_PARSER_DETONATION_PDU[] =
{
    { DIS_FIELDTYPE_ENTITY_ID,               "Firing Entity ID",0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Target Entity ID",0,0,0 },
    { DIS_FIELDTYPE_ENTITY_ID,               "Munition ID",0,0,0 },
    { DIS_FIELDTYPE_EVENT_ID,                "Event ID",0,0,0 },
    { DIS_FIELDTYPE_LINEAR_VELOCITY,         "Velocity",0,0,0 },
    { DIS_FIELDTYPE_LOCATION_WORLD,          "Location in World Coordinates",0,0,0 },
    { DIS_FIELDTYPE_BURST_DESCRIPTOR,        "Burst Descriptor",0,0,0 },
    { DIS_FIELDTYPE_LOCATION_ENTITY,         "Location in Entity Coordinates",0,0,0 },
    { DIS_FIELDTYPE_DETONATION_RESULT,       "Detonation Result",0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Number of Articulation Parameters",0,0,0 },
    { DIS_FIELDTYPE_PAD16,                   "Padding",0,0,0 },
    { DIS_FIELDTYPE_ARTICULATION_PARAMETERS, "Articulation Parameters",0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0 }
};

/* Initialize the parsers for each PDU type and the standard DIS header.
 */
void initializeParsers(void)
{
    initializeParser(DIS_PARSER_ENTITY_STATE_PDU);
    initializeParser(DIS_PARSER_FIRE_PDU);
    initializeParser(DIS_PARSER_DETONATION_PDU);
    initializeParser(DIS_FIELDS_PDU_HEADER);
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
        case DIS_FIELDTYPE_APPEARANCE:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_NONE,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_ARTICULATION_PARAMETERS:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_ARTICULATION_PARAMETER,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_BURST_DESCRIPTOR:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_BURST_DESCRIPTOR,
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
        case DIS_FIELDTYPE_LINEAR_VELOCITY:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_LINEAR_VELOCITY,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_LOCATION_WORLD:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_LOCATION_WORLD,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_LOCATION_ENTITY:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_LOCATION_ENTITY,
                &parserNodes[parserIndex].ettVar);
            break;
        case DIS_FIELDTYPE_ORIENTATION:
            parserNodes[parserIndex].children = createSubtree(
                DIS_FIELDS_ORIENTATION,
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

    while (parserNodes[fieldIndex].fieldType != DIS_FIELDTYPE_END)
    {
        proto_item *newField = 0;
        switch(parserNodes[fieldIndex].fieldType)
        {
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
        case DIS_FIELDTYPE_PAD8:
            offset = parseField_Pad(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_PAD16:
            offset = parseField_Pad(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;
        case DIS_FIELDTYPE_PAD32:
            offset = parseField_Pad(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_APPEARANCE:
	    {
                proto_item *newSubtree;
                newField = proto_tree_add_text(tree, tvb, offset, 4,
                    parserNodes[fieldIndex].fieldLabel);
                newSubtree = proto_item_add_subtree(newField,
                    parserNodes[fieldIndex].ettVar);
                offset = parseField_Bitmask(tvb, newSubtree, offset,
                    parserNodes[fieldIndex], 4);
	    }
            break;
        case DIS_FIELDTYPE_ARTIC_PARAM_TYPE_DESIGNATOR:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_ARTIC_PARAM_TYPE:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_CAPABILITIES:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_CATEGORY:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_COUNTRY:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;
        case DIS_FIELDTYPE_DEAD_RECKONING_PARAMS:
	    /* This is really a struct... needs a field parser.
             * For now, just skip the 12 bytes.
             */
            offset = parseField_Bytes(tvb, tree, offset,
                parserNodes[fieldIndex], 40);
            break;
        case DIS_FIELDTYPE_DETONATION_RESULT:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_DOMAIN:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_ENTITY_KIND:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
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
        case DIS_FIELDTYPE_FORCE_ID:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_FUSE:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;
        case DIS_FIELDTYPE_PDU_TYPE:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_PROTOCOL_FAMILY:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_PROTOCOL_VERSION:
            offset = parseField_Enum(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_SPECIFIC:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_SUBCATEGORY:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 1);
            break;
        case DIS_FIELDTYPE_TIMESTAMP:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 4);
            break;
        case DIS_FIELDTYPE_WARHEAD:
            offset = parseField_UInt(tvb, tree, offset,
                parserNodes[fieldIndex], 2);
            break;
        case DIS_FIELDTYPE_BURST_DESCRIPTOR:
        case DIS_FIELDTYPE_ENTITY_ID:
        case DIS_FIELDTYPE_EVENT_ID:
        case DIS_FIELDTYPE_LINEAR_VELOCITY:
        case DIS_FIELDTYPE_LOCATION_WORLD:
        case DIS_FIELDTYPE_LOCATION_ENTITY:
        case DIS_FIELDTYPE_ENTITY_TYPE:
        case DIS_FIELDTYPE_ORIENTATION:
            newField = proto_tree_add_text(tree, tvb, offset, -1,
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
        case DIS_FIELDTYPE_ARTICULATION_PARAMETERS:
	    {
                guint i;

                if (numArticulations > DIS_PDU_MAX_ARTICULATIONS)
                {
                    numArticulations = DIS_PDU_MAX_ARTICULATIONS;
                }

	        for (i = 0; i < numArticulations; ++i)
	        {
		    proto_item *newSubtree;
                    newField = proto_tree_add_text(tree, tvb, offset, -1,
                        parserNodes[fieldIndex].fieldLabel);
                    newSubtree = proto_item_add_subtree(newField,
                        ettArticulations[i]);
                    offset = parseFields(tvb, newSubtree, offset,
                        parserNodes[fieldIndex].children);
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
