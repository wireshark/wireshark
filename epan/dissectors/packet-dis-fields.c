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

#include <epan/packet.h>
#include "packet-dis-fields.h"
#include "packet-dis-enums.h"
#include "packet-dis-pdus.h"

/* all of these variables are assigned by reference */
/* *(parserNode.outputVar) = value                  */
guint32 disProtocolVersion;
guint32 pduType;
guint32 protocolFamily;
guint32 persistentObjectPduType;
guint32 entityKind;
guint32 entityDomain;
guint32 category;
guint32 radioID;
guint32 disRadioTransmitState;
guint32 encodingScheme;
guint32 numSamples;
guint32 numFixed;
guint32 numVariable;
guint32 numBeams;
guint32 numTrackJamTargets;
guint32 variableDatumLength;
guint32 variableParameterType;
guint32 variableRecordLength;
guint32 variableRecordType;
guint32 majorModulation;
guint32 systemModulation;
guint32 modulationParamLength;
guint32 disAntennaPattern;

/* Headers
 */
DIS_ParserNode DIS_FIELDS_PDU_HEADER[] =
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

DIS_ParserNode DIS_FIELDS_PERSISTENT_OBJECT_HEADER[] =
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

DIS_ParserNode DIS_FIELDS_BURST_DESCRIPTOR[] =
{
    { DIS_FIELDTYPE_ENTITY_TYPE, "Munition",0,0,0,0 },
    { DIS_FIELDTYPE_WARHEAD,     "Warhead",0,0,0,0 },
    { DIS_FIELDTYPE_FUSE,        "Fuse",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,      "Quantity",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,      "Rate",0,0,0,0 },
    { DIS_FIELDTYPE_END,         NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_CLOCK_TIME[] =
{
    { DIS_FIELDTYPE_UINT32,                 "Hour",0,0,0,0 },
    { DIS_FIELDTYPE_TIMESTAMP,              "Time Past The Hour",0,0,0,0 },
    { DIS_FIELDTYPE_END,                    NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_ENTITY_ID[] =
{
    { DIS_FIELDTYPE_SITE,        "Site",0,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION, "Application",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY,      "Entity",0,0,0,0 },
    { DIS_FIELDTYPE_END,         NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_ENTITY_TYPE[] =
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

DIS_ParserNode DIS_FIELDS_RADIO_ENTITY_TYPE[] =
{
    { DIS_FIELDTYPE_ENTITY_KIND,          "Entity Kind",0,0,0,&entityKind },
    { DIS_FIELDTYPE_DOMAIN,               "Domain",0,0,0,&entityDomain },
    { DIS_FIELDTYPE_COUNTRY,              "Country",0,0,0,0 },
    { DIS_FIELDTYPE_RADIO_CATEGORY,       "Radio Category",0,0,0,&category },
    { DIS_FIELDTYPE_NOMENCLATURE_VERSION, "Nomenclature Version",0,0,0,0 },
    { DIS_FIELDTYPE_NOMENCLATURE,         "Nomenclature",0,0,0,0 },
    { DIS_FIELDTYPE_END,                  NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_MODULATION_TYPE[] =
{
    { DIS_FIELDTYPE_SPREAD_SPECTRUM,        "Spread Spectrum",0,0,0,0 },
    { DIS_FIELDTYPE_MODULATION_MAJOR,       "Major",0,0,0,&majorModulation },
    { DIS_FIELDTYPE_MODULATION_DETAIL,      "Detail",0,0,0,0 },
    { DIS_FIELDTYPE_MODULATION_SYSTEM,      "System",0,0,0,&systemModulation },
    { DIS_FIELDTYPE_END,                    NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_EVENT_ID[] =
{
    { DIS_FIELDTYPE_UINT16, "Site",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Application",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Event Number",0,0,0,0 },
    { DIS_FIELDTYPE_END,    NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_ORIENTATION[] =
{
    { DIS_FIELDTYPE_FLOAT32, "Psi",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Theta",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Phi",0,0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_SIMULATION_ADDRESS[] =
{
    { DIS_FIELDTYPE_UINT16, "Site",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16, "Application",0,0,0,0 },
    { DIS_FIELDTYPE_END,    NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VECTOR_FLOAT_32[] =
{
    { DIS_FIELDTYPE_FLOAT32, "X",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Y",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT32, "Z",0,0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VECTOR_FLOAT_64[] =
{
    { DIS_FIELDTYPE_FLOAT64, "X",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT64, "Y",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT64, "Z",0,0,0,0 },
    { DIS_FIELDTYPE_END,     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_MOD_PARAMS_CCTT_SINCGARS[] =
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

DIS_ParserNode DIS_FIELDS_MOD_PARAMS_JTIDS_MIDS[] =
{
    { DIS_FIELDTYPE_TS_ALLOCATION_MODE,           "Time Slot Allocaton Mode",0,0,0,0 },
    { DIS_FIELDTYPE_TRANSMITTER_PRIMARY_MODE,     "Transmitter Primary Mode",0,0,0,0 },
    { DIS_FIELDTYPE_TRANSMITTER_SECONDARY_MODE,   "Transmitter Secondary Mode",0,0,0,0 },
    { DIS_FIELDTYPE_JTIDS_SYNC_STATE,             "Synchronization State",0,0,0,0 },
    { DIS_FIELDTYPE_NETWORK_SYNC_ID,              "Network Sync ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                          NULL,0,0,0,0 }
};

/* Array records
 */
DIS_ParserNode DIS_FIELDS_FIXED_DATUM[] =
{
    { DIS_FIELDTYPE_DATUM_ID,                "Datum ID",0,0,0,0 },
    { DIS_FIELDTYPE_FIXED_DATUM_VALUE,       "Datum value",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VARIABLE_DATUM[] =
{
    { DIS_FIELDTYPE_DATUM_ID,                "Datum ID",0,0,0,0 },
    { DIS_FIELDTYPE_DATUM_LENGTH,            "Datum length",0,0,0,&variableDatumLength },
    { DIS_FIELDTYPE_VARIABLE_DATUM_VALUE,    "Datum value",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_DATUM_IDS[] =
{
    { DIS_FIELDTYPE_DATUM_ID,                "Datum ID",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_EMITTER_SYSTEM[] =
{
    { DIS_FIELDTYPE_EMITTER_NAME,            "Emitter Name",0,0,0,0 },
    { DIS_FIELDTYPE_EMISSION_FUNCTION,       "Function",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                   "Emitter ID Number",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_FUNDAMENTAL_PARAMETER_DATA[] =
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

DIS_ParserNode DIS_FIELDS_TRACK_JAM[] =
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
DIS_ParserNode DIS_FIELDS_VP_TYPE[] =
{
    { DIS_FIELDTYPE_PARAMETER_TYPE_DESIGNATOR,   "Variable Parameter Type",0,0,0,&variableParameterType },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

/* Array record contents - variable parameter records
 */
DIS_ParserNode DIS_FIELDS_VP_GENERIC[] =
{
    { DIS_FIELDTYPE_FIXED_LEN_STR,               "Data",15,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VP_ARTICULATED_PART[] =
{
    { DIS_FIELDTYPE_UINT8,                       "Change",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                      "Part Attached To ID",0,0,0,0 },
    { DIS_FIELDTYPE_ARTIC_PARAM_TYPE,            "Parameter Type",0,0,0,0 },
    { DIS_FIELDTYPE_UINT64,                      "Parameter Value",0,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VP_ATTACHED_PART[] =
{
    { DIS_FIELDTYPE_UINT8,                       "Attached Indicator",0,0,0,0 },
    { DIS_FIELDTYPE_UINT16,                      "Part Attached To ID",0,0,0,0 },
    { DIS_FIELDTYPE_ARTIC_PARAM_TYPE,            "Parameter Type",0,0,0,0 },
    { DIS_FIELDTYPE_ENTITY_TYPE,                 "Part Type",0,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VP_ENTITY_OFFSET[] =
{
    { DIS_FIELDTYPE_UINT8,                       "Offset Type",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                        "Padding",2,0,0,0 },
    { DIS_FIELDTYPE_VECTOR_32,                   "Offset",0,0,0,0 },
    { DIS_FIELDTYPE_ORIENTATION,                 "Orientation",0,0,0,0 },
    { DIS_FIELDTYPE_END,                         NULL,0,0,0,0 }
};

/* Variable Records
 */
DIS_ParserNode DIS_FIELDS_VR_TYPE[] =
{
    { DIS_FIELDTYPE_UINT32,   "Record Type",0,0,0,&variableRecordType },
    { DIS_FIELDTYPE_UINT16,   "Record Length",0,0,0,&variableRecordLength },
    { DIS_FIELDTYPE_END,      NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VR_APPLICATION_HEALTH_STATUS[] =
{
    { DIS_FIELDTYPE_PAD8,                       "Padding",2,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION_STATUS_TYPE,    "Status Type",0,0,0,0 },
    { DIS_FIELDTYPE_APPLICATION_GENERAL_STATUS, "General Status",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                      "Specific Status",0,0,0,0 },
    { DIS_FIELDTYPE_INT32,                      "Status Value Int",0,0,0,0 },
    { DIS_FIELDTYPE_FLOAT64,                    "Status Value Float",0,0,0,0 },
    { DIS_FIELDTYPE_END,                        NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VR_APPLICATION_INITIALIZATION[] =
{
    { DIS_FIELDTYPE_UINT8,                   "Exercise ID",0,0,0,0 },
    { DIS_FIELDTYPE_PAD8,                    "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_FIXED_LEN_STR,           "Exercise File Path",256,0,0,0 },
    { DIS_FIELDTYPE_FIXED_LEN_STR,           "Exercise File Name",128,0,0,0 },
    { DIS_FIELDTYPE_FIXED_LEN_STR,           "Application Role",64,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VR_DATA_QUERY[] =
{
    { DIS_FIELDTYPE_UINT16,                  "Num Records",0,0,0,&numFixed },
    { DIS_FIELDTYPE_FIXED_DATUM_IDS,         "Record",0,0,0,0 },
    { DIS_FIELDTYPE_END,                     NULL,0,0,0,0 }
};

DIS_ParserNode DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM[] =
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

DIS_ParserNode DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM[] =
{
    { DIS_FIELDTYPE_UINT8,                  "System Data Length",0,0,0,0 },
    { DIS_FIELDTYPE_UINT8,                  "Number of Beams (M)",0,0,0,&numBeams },
    { DIS_FIELDTYPE_PAD16,                  "Padding",0,0,0,0 },
    { DIS_FIELDTYPE_EMITTER_SYSTEM,         "Emitter System",0,0,0,0 },
    { DIS_FIELDTYPE_VECTOR_32,              "Location",0,0,0,0 },
    { DIS_FIELDTYPE_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM, "Beam",0,0,0,0 },
    { DIS_FIELDTYPE_END,                    NULL,0,0,0,0 }
};

/* Bit fields
 */
DIS_ParserNode DIS_FIELDS_NONE[] =
{
    { DIS_FIELDTYPE_END, NULL, 0,0,0,0 }
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

/* Initialize the field parsers that are not explicitly included in any
 * specific PDU.  These fields are only accessed and used if a variant
 * field indicates they are to be used.
 */
void initializeFieldParsers(void)
{
    initializeParser(DIS_FIELDS_VP_GENERIC);
    initializeParser(DIS_FIELDS_VP_ARTICULATED_PART);
    initializeParser(DIS_FIELDS_VP_ATTACHED_PART);
    initializeParser(DIS_FIELDS_VP_ENTITY_OFFSET);

    initializeParser(DIS_FIELDS_VR_APPLICATION_HEALTH_STATUS);
    initializeParser(DIS_FIELDS_VR_APPLICATION_INITIALIZATION);
    initializeParser(DIS_FIELDS_VR_DATA_QUERY);
    initializeParser(DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM);
    initializeParser(DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM);
    initializeParser(DIS_FIELDS_MOD_PARAMS_CCTT_SINCGARS);
    initializeParser(DIS_FIELDS_MOD_PARAMS_JTIDS_MIDS);

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
            "Unknown Appearance Type (%" G_GINT64_MODIFIER "u)", uintVal);
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

    proto_tree_add_text(tree, tvb, offset, numBytes, "%s = %" G_GINT64_MODIFIER "d",
        parserNode.fieldLabel, uintVal);

    offset += numBytes;

    return offset;
}

/* Parse a field that explicitly specified a number of pad bytes (vs implicit
 * padding, which occurs whenever padding is inserted to properly align the
 * field.
 */
gint parseField_Pad(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode _U_, guint numBytes)
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
       pi = proto_tree_add_item(tree, dis_hf_id, tvb, offset, numBytes, FALSE);
       proto_item_set_text(pi, "%s = %s", parserNode.fieldLabel, enumStr);
#else
       proto_tree_add_item(tree, dis_hf_id, tvb, offset, numBytes, FALSE);
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

/* Parse a 4-byte floating-point value, given text label.
 */
gint parseField_Float_Text(tvbuff_t *tvb, proto_tree *tree, gint offset, gchar *charStr)
{
    gfloat floatVal;

    offset = alignOffset(offset, 4);
    floatVal = tvb_get_ntohieee_float(tvb, offset);
    proto_tree_add_text(tree, tvb, offset, 4, "%s = %f",
        charStr, floatVal);

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
    proto_tree_add_text(tree, tvb, offset, 8, "%s = %f",
        parserNode.fieldLabel, doubleVal);

    offset += 8;

    return offset;
}

/* Parse the Timestamp */
gint parseField_Timestamp(tvbuff_t *tvb, proto_tree *tree, gint offset, DIS_ParserNode parserNode)
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

/* Parse a variable parameter field.
 */
gint parseField_VariableParameter(tvbuff_t *tvb, proto_tree *tree, gint offset)
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
    default:
        paramParser = DIS_FIELDS_VP_GENERIC;
        break;
    }

    /* Parse the variable parameter fields */
    if (paramParser)
    {
        offset = parseFields(tvb, tree, offset, paramParser);
    }

    return offset;
}

/* Parse a variable record field.
 */
gint parseField_VariableRecord(tvbuff_t *tvb, proto_tree *tree, gint offset)
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
        offset = parseFields(tvb, tree, offset, paramParser);
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

/* Parse a variable electromagnetic emission system beam.
 */
gint parseField_ElectromagneticEmissionSystemBeam(
    tvbuff_t *tvb, proto_tree *tree, gint offset)
{
    DIS_ParserNode *paramParser = 0;

    /* Determine the parser to use based on the PDU type */
    if (pduType == DIS_PDUTYPE_ELECTROMAGNETIC_EMISSION)
        paramParser = DIS_FIELDS_VR_ELECTROMAGNETIC_EMISSION_SYSTEM_BEAM;

    /* Parse the variable parameter fields */
    if (paramParser)
    {
        offset = parseFields(tvb, tree, offset, paramParser);
    }

    return offset;
}

