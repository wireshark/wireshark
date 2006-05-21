/* packet-dis-fields.c
 * Routines and definitions for DIS field parsing.
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
#include <epan/packet.h>
#include "packet-dis-fields.h"
#include "packet-dis-enums.h"

guint32 pduType;
guint32 entityKind;
guint32 entityDomain;

DIS_ParserNode DIS_FIELDS_PDU_HEADER[] =
{
    { DIS_FIELDTYPE_PROTOCOL_VERSION, "Protocol Version",0,0,0 },
    { DIS_FIELDTYPE_UINT8,            "Exercise ID",0,0,0 },
    { DIS_FIELDTYPE_PDU_TYPE,         "PDU Type",0,0,&pduType },
    { DIS_FIELDTYPE_PROTOCOL_FAMILY,  "Protocol Family",0,0,0 },
    { DIS_FIELDTYPE_TIMESTAMP,        "Timestamp",0,0,0 },
    { DIS_FIELDTYPE_UINT16,           "Length",0,0,0 },
    { DIS_FIELDTYPE_PAD16,            "Padding",0,0,0 },
    { DIS_FIELDTYPE_END,              NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_ENTITY_ID[] =
{
    { DIS_FIELDTYPE_UINT16, "Site",0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Application",0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Entity",0,0,0 },
    { DIS_FIELDTYPE_END,    NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_ENTITY_TYPE[] =
{
    { DIS_FIELDTYPE_ENTITY_KIND, "Entity Kind",0,0,&entityKind },
    { DIS_FIELDTYPE_DOMAIN,      "Domain",0,0,&entityDomain },
    { DIS_FIELDTYPE_COUNTRY,     "Country",0,0,0 },
    { DIS_FIELDTYPE_CATEGORY,    "Category",0,0,0 },
    { DIS_FIELDTYPE_SUBCATEGORY, "Subcategory",0,0,0 },
    { DIS_FIELDTYPE_SPECIFIC,    "Specific",0,0,0 },
    { DIS_FIELDTYPE_EXTRA,       "Extra",0,0,0 },
    { DIS_FIELDTYPE_END,         NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_EVENT_ID[] =
{
    { DIS_FIELDTYPE_UINT16, "Site",0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Application",0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Event Number",0,0,0 },
    { DIS_FIELDTYPE_END,    NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_LINEAR_VELOCITY[] =
{
    { DIS_FIELDTYPE_FLOAT32, "X",0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Y",0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Z",0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_LOCATION_WORLD[] =
{
    { DIS_FIELDTYPE_FLOAT64, "X",0,0,0 },
    { DIS_FIELDTYPE_FLOAT64, "Y",0,0,0 },
    { DIS_FIELDTYPE_FLOAT64, "Z",0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_LOCATION_ENTITY[] =
{
    { DIS_FIELDTYPE_FLOAT32, "X",0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Y",0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Z",0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_ORIENTATION[] =
{
    { DIS_FIELDTYPE_FLOAT32, "Psi",0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Theta",0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Phi",0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_BURST_DESCRIPTOR[] =
{
    { DIS_FIELDTYPE_ENTITY_TYPE, "Munition",0,0,0 },
    { DIS_FIELDTYPE_WARHEAD,     "Warhead",0,0,0 },
    { DIS_FIELDTYPE_FUSE,        "Fuse",0,0,0 },
    { DIS_FIELDTYPE_UINT16,      "Quantity",0,0,0 },
    { DIS_FIELDTYPE_UINT16,      "Rate",0,0,0 },
    { DIS_FIELDTYPE_END,         NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_ARTICULATION_PARAMETER[] =
{
    { DIS_FIELDTYPE_ARTIC_PARAM_TYPE_DESIGNATOR, "Parameter Type Designator",0,0,0 },
    { DIS_FIELDTYPE_UINT8,                       "Change",0,0,0 },
    { DIS_FIELDTYPE_UINT16,                      "Part Attached To ID",0,0,0 },
    { DIS_FIELDTYPE_ARTIC_PARAM_TYPE,            "Parameter Type",0,0,0 },
    { DIS_FIELDTYPE_UINT64,                      "Parameter Value",0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_NONE[] =
{
    { DIS_FIELDTYPE_END, NULL, 0,0,0 }
};

DIS_BitMask DIS_APPEARANCE_LANDPLATFORM[] =
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

DIS_BitMask DIS_APPEARANCE_LIFEFORM[] =
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
gint parseField_Bytes(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
{
    proto_tree_add_text(tree, tvb, offset, numBytes, "%s (%d bytes)",
        parserNode.fieldLabel, numBytes);
    offset += numBytes;
    return offset;
}

/* Parse a bitmask field.
 */
gint parseField_Bitmask(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
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
            "Unknown Appearance Type (%" PRIu64 ")", uintVal);
    }

    offset += numBytes;

    return offset;
}

/* Parse an unsigned integer field of a specified number of bytes.
 */
gint parseField_UInt(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
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

    proto_tree_add_text(tree, tvb, offset, numBytes, "%s = %" PRIu64,
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
gint parseField_Int(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
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

    proto_tree_add_text(tree, tvb, offset, numBytes, "%s = %" PRId64,
        parserNode.fieldLabel, uintVal);

    offset += numBytes;

    return offset;
}

/* Parse a field that explicitly specified a number of pad bytes (vs implicit
 * padding, which occurs whenever padding is inserted to properly align the
 * field.
 */
gint parseField_Pad(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
{
    proto_tree_add_text(tree, tvb, offset, numBytes,
        "Explicit Padding (%d bytes)", numBytes);

    offset += numBytes;

    return offset;
}

/* Parse an enumerated type field.
 */
gint parseField_Enum(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode, guint numBytes)
{
    const value_string *enumStrings = 0;
    guint32 enumVal = 0;
    const gchar *enumStr = 0;

    offset = alignOffset(offset, numBytes);

    switch(parserNode.fieldType)
    {
    case DIS_FIELDTYPE_PROTOCOL_VERSION:
        enumStrings = DIS_PDU_ProtocolVersion_Strings;
        break;
    case DIS_FIELDTYPE_PROTOCOL_FAMILY:
        enumStrings = DIS_PDU_ProtocolFamily_Strings;
        break;
    case DIS_FIELDTYPE_PDU_TYPE:
        enumStrings = DIS_PDU_Type_Strings;
        break;
    case DIS_FIELDTYPE_ENTITY_KIND:
        enumStrings = DIS_PDU_EntityKind_Strings;
        break;
    case DIS_FIELDTYPE_DOMAIN:
        enumStrings = DIS_PDU_Domain_Strings;
        break;
    case DIS_FIELDTYPE_DETONATION_RESULT:
        enumStrings = DIS_PDU_DetonationResult_Strings;
        break;
    case DIS_FIELDTYPE_CATEGORY:
        if (entityKind == DIS_ENTITYKIND_PLATFORM)
        {
            switch(entityDomain)
            {
            case DIS_DOMAIN_LAND:
                enumStrings = DIS_PDU_Category_LandPlatform_Strings;
                break;
            case DIS_DOMAIN_AIR:
                enumStrings = DIS_PDU_Category_AirPlatform_Strings;
                break;
            case DIS_DOMAIN_SURFACE:
                enumStrings = DIS_PDU_Category_SurfacePlatform_Strings;
                break;
            case DIS_DOMAIN_SUBSURFACE:
                enumStrings = DIS_PDU_Category_SubsurfacePlatform_Strings;
                break;
            case DIS_DOMAIN_SPACE:
                enumStrings = DIS_PDU_Category_SpacePlatform_Strings;
                break;
            default:
                enumStrings = 0;
                break;
            }
        }
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

    if (enumStrings != 0)
    {
        enumStr = val_to_str(enumVal, enumStrings, "Unknown Enum Value");
    }
    else
    {
        enumStr = "Unknown Enum Type";
    }

    proto_tree_add_text(tree, tvb, offset, numBytes, "%s = %s",
        parserNode.fieldLabel, enumStr);

    if (parserNode.outputVar != 0)
    {
        *(parserNode.outputVar) = enumVal;
    }

    offset += numBytes;

    return offset;
}

/* Parse a 4-byte floating-point value.
 */
gint parseField_Float(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode)
{
    gfloat floatVal;

    offset = alignOffset(offset, 4);
    floatVal = tvb_get_ntohieee_float(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "%s = %f",
        parserNode.fieldLabel, floatVal);

    offset += 4;

    return offset;
}

/* Parse an 8-byte floating-point value.
 */
gint parseField_Double(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode)
{
    gdouble doubleVal;

    offset = alignOffset(offset, 8);
    doubleVal = tvb_get_ntohieee_double(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 8, "%s = %lf",
        parserNode.fieldLabel, doubleVal);

    offset += 8;

    return offset;
}
