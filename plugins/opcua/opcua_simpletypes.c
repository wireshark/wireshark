/******************************************************************************
** $Id$
**
** Copyright (C) 2006-2007 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
** 
** This program is free software; you can redistribute it and/or
** modify it under the terms of the GNU General Public License
** as published by the Free Software Foundation; either version 2
** of the License, or (at your option) any later version.
** 
** This file is provided AS IS with NO WARRANTY OF ANY KIND, INCLUDING THE
** WARRANTY OF DESIGN, MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
** 
** Project: OpcUa Wireshark Plugin
**
** Description: Implementation of OpcUa built-in type parsers.
**              This contains all the simple types and some complex types.
**
** Author: Gerhard Gappmeier <gerhard.gappmeier@ascolab.com>
** Last change by: $Author: gergap $
**
******************************************************************************/

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-windows-common.h>
#include "opcua_simpletypes.h"
#include "opcua_hfindeces.h"
#include <string.h>
#include <epan/emem.h>

/* string buffer */
#define MAX_BUFFER 256

#define DIAGNOSTICINFO_ENCODINGMASK_SYMBOLICID_FLAG           0x01
#define DIAGNOSTICINFO_ENCODINGMASK_NAMESPACE_FLAG            0x02
#define DIAGNOSTICINFO_ENCODINGMASK_LOCALIZEDTEXT_FLAG        0x04
#define DIAGNOSTICINFO_ENCODINGMASK_ADDITIONALINFO_FLAG       0x08
#define DIAGNOSTICINFO_ENCODINGMASK_INNERSTATUSCODE_FLAG      0x10
#define DIAGNOSTICINFO_ENCODINGMASK_INNERDIAGNOSTICINFO_FLAG  0x20
#define LOCALIZEDTEXT_ENCODINGBYTE_LOCALE                     0x01
#define LOCALIZEDTEXT_ENCODINGBYTE_TEXT                       0x02
#define NODEID_URIMASK                                        0x80
#define DATAVALUE_ENCODINGBYTE_VALUE                          0x01
#define DATAVALUE_ENCODINGBYTE_STATUSCODE                     0x02
#define DATAVALUE_ENCODINGBYTE_SOURCETIMESTAMP                0x04
#define DATAVALUE_ENCODINGBYTE_SERVERTIMESTAMP                0x08
#define EXTOBJ_ENCODINGMASK_BINBODY_FLAG                      0x01
#define EXTOBJ_ENCODINGMASK_XMLBODY_FLAG                      0x02

static int hf_opcua_diag_mask_symbolicflag = -1;
static int hf_opcua_diag_mask_namespaceflag = -1;
static int hf_opcua_diag_mask_localizedtextflag = -1;
static int hf_opcua_diag_mask_additionalinfoflag = -1;
static int hf_opcua_diag_mask_innerstatuscodeflag = -1;
static int hf_opcua_diag_mask_innerdiaginfoflag = -1;
static int hf_opcua_loctext_mask_localeflag = -1;
static int hf_opcua_loctext_mask_textflag = -1;
static int hf_opcua_datavalue_mask_valueflag = -1;
static int hf_opcua_datavalue_mask_statuscodeflag = -1;
static int hf_opcua_datavalue_mask_sourcetimestampflag = -1;
static int hf_opcua_datavalue_mask_servertimestampflag = -1;
static int hf_opcua_nodeid_encodingmask = -1;
static int hf_opcua_variant_encodingmask = -1;
static int hf_opcua_nodeid_nsid = -1;
static int hf_opcua_nodeid_numeric = -1;
static int hf_opcua_Locale = -1;
static int hf_opcua_Text = -1;
static int hf_opcua_SourceTimestamp = -1;
static int hf_opcua_ServerTimestamp = -1;
static int hf_opcua_diag_symbolicid = -1;
static int hf_opcua_diag_namespace = -1;
static int hf_opcua_diag_localizedtext = -1;
static int hf_opcua_diag_additionalinfo = -1;
static int hf_opcua_diag_innerstatuscode = -1;
static int hf_opcua_extobj_mask_binbodyflag = -1;
static int hf_opcua_extobj_mask_xmlbodyflag = -1;

/** NodeId encoding mask table */
static const value_string g_nodeidmasks[] = {
    { 0, "Two byte encoded Numeric" },
    { 1, "Four byte encoded Numeric" },
    { 2, "Numeric of arbitrary length" },
    { 3, "String" },
    { 4, "URI" },
    { 5, "GUID" },
    { 6, "ByteString" },
    { 0x80, "UriMask" },
    { 0, NULL }
};

/** UA Variant Type enum */
typedef enum _OpcUa_BuiltInType
{
    OpcUaType_Null = 0,
    OpcUaType_Boolean = 1,
    OpcUaType_SByte = 2,
    OpcUaType_Byte = 3,
    OpcUaType_Int16 = 4,
    OpcUaType_UInt16 = 5,
    OpcUaType_Int32 = 6,
    OpcUaType_UInt32 = 7,
    OpcUaType_Int64 = 8,
    OpcUaType_UInt64 = 9,
    OpcUaType_Float = 10,
    OpcUaType_Double = 11,
    OpcUaType_String = 12,
    OpcUaType_DateTime = 13,
    OpcUaType_Guid = 14,
    OpcUaType_ByteString = 15,
    OpcUaType_XmlElement = 16,
    OpcUaType_NodeId = 17,
    OpcUaType_ExpandedNodeId = 18,
    OpcUaType_StatusCode = 19,
    OpcUaType_DiagnosticInfo = 20,
    OpcUaType_QualifiedName = 21,
    OpcUaType_LocalizedText = 22,
    OpcUaType_ExtensionObject = 23,
    OpcUaType_DataValue = 24,
    OpcUaType_Variant = 25  
}
OpcUa_BuiltInType;

/** Variant encoding mask table */
static const value_string g_VariantTypes[] = {
    { 0, "Null" },
    { 1, "Boolean" },
    { 2, "SByte" },
    { 3, "Byte" },
    { 4, "Int16" },
    { 5, "UInt16" },
    { 6, "Int32" },
    { 7, "UInt32" },
    { 8, "Int64" },
    { 9, "UInt64" },
    { 10, "Float" },
    { 11, "Double" },
    { 12, "String" },
    { 13, "DateTime" },
    { 14, "Guid" },
    { 15, "ByteString" },
    { 16, "XmlElement" },
    { 17, "NodeId" },
    { 18, "ExpandedNodeId" },
    { 19, "StatusCode" },
    { 20, "DiagnosticInfo" },
    { 21, "QualifiedName" },
    { 22, "LocalizedText" },
    { 23, "ExtensionObject" },
    { 24, "DataValue" },
    { 25, "Variant" },
    { 0x80,   "Array of Null" },
    { 0x80+1, "Array of Boolean" },
    { 0x80+2, "Array of SByte" },
    { 0x80+3, "Array of Byte" },
    { 0x80+4, "Array of Int16" },
    { 0x80+5, "Array of UInt16" },
    { 0x80+6, "Array of Int32" },
    { 0x80+7, "Array of UInt32" },
    { 0x80+8, "Array of Int64" },
    { 0x80+9, "Array of UInt64" },
    { 0x80+10, "Array of Float" },
    { 0x80+11, "Array of Double" },
    { 0x80+12, "Array of String" },
    { 0x80+13, "Array of DateTime" },
    { 0x80+14, "Array of Guid" },
    { 0x80+15, "Array of ByteString" },
    { 0x80+16, "Array of XmlElement" },
    { 0x80+17, "Array of NodeId" },
    { 0x80+18, "Array of ExpandedNodeId" },
    { 0x80+19, "Array of StatusCode" },
    { 0x80+20, "Array of DiagnosticInfo" },
    { 0x80+21, "Array of QualifiedName" },
    { 0x80+22, "Array of LocalizedText" },
    { 0x80+23, "Array of ExtensionObject" },
    { 0x80+24, "Array of DataValue" },
    { 0x80+25, "Array of Variant" },
    { 0, NULL }
};
#define VARIANT_ARRAYMASK 0x80

/* trees */
static gint ett_opcua_array = -1;
static gint ett_opcua_diagnosticinfo = -1;
static gint ett_opcua_nodeid = -1;
static gint ett_opcua_localeid = -1;
static gint ett_opcua_localizedtext = -1;
static gint ett_opcua_qualifiedname = -1;
static gint ett_opcua_datavalue = -1;
static gint ett_opcua_variant = -1;
static gint ett_opcua_extensionobject = -1;
static gint ett_opcua_extobj_encodingmask = -1;
static gint *ett[] =
{
  &ett_opcua_array,
  &ett_opcua_diagnosticinfo,
  &ett_opcua_nodeid,
  &ett_opcua_localeid,
  &ett_opcua_localizedtext,
  &ett_opcua_qualifiedname,
  &ett_opcua_datavalue,
  &ett_opcua_variant,
  &ett_opcua_extensionobject,
  &ett_opcua_extobj_encodingmask
};


static hf_register_info hf[] =
{
    /* full name  ,           abbreviation  ,       type     , display  , strings, bitmask, blurb, id, parent, ref_count, bitshift */
    { &hf_opcua_diag_mask_symbolicflag,
    {  "has symbolic id",           "", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_SYMBOLICID_FLAG, "", HFILL }
    },
    { &hf_opcua_diag_mask_namespaceflag,
    {  "has namespace",             "", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_NAMESPACE_FLAG, "", HFILL }
    },
    { &hf_opcua_diag_mask_localizedtextflag,
    {  "has localizedtext",         "", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_LOCALIZEDTEXT_FLAG, "", HFILL }
    },
    { &hf_opcua_diag_mask_additionalinfoflag,
    {  "has additional info",       "", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_ADDITIONALINFO_FLAG, "", HFILL }
    },
    { &hf_opcua_diag_mask_innerstatuscodeflag,
    {  "has inner statuscode",      "", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_INNERSTATUSCODE_FLAG, "", HFILL }
    },
    { &hf_opcua_diag_mask_innerdiaginfoflag,
    {  "has inner diagnostic info", "", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_INNERDIAGNOSTICINFO_FLAG, "", HFILL }
    },
    { &hf_opcua_loctext_mask_localeflag,
    {  "has locale information", "", FT_BOOLEAN, 8, NULL, LOCALIZEDTEXT_ENCODINGBYTE_LOCALE, "", HFILL }
    },
    { &hf_opcua_loctext_mask_textflag,
    {  "has text", "", FT_BOOLEAN, 8, NULL, LOCALIZEDTEXT_ENCODINGBYTE_TEXT, "", HFILL }
    },
    { &hf_opcua_nodeid_encodingmask,
    {  "NodeId EncodingMask",        "application.nodeid.encodingmask", FT_UINT8,   BASE_HEX,  VALS(g_nodeidmasks), 0x0,    "",    HFILL }
    },
    { &hf_opcua_nodeid_nsid,
    {  "NodeId Namespace Id",        "application.nodeid.nsid",         FT_UINT32,  BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_nodeid_numeric,
    {  "NodeId Identifier Numeric",  "application.nodeid.numeric",      FT_UINT32,  BASE_DEC,  NULL, 0x0,    "",    HFILL }
    },
    { &hf_opcua_Locale, { "Locale", "", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL } },
    { &hf_opcua_Text,   { "Text",   "", FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL } },
    { &hf_opcua_datavalue_mask_valueflag,           {  "has value", "",            FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_VALUE, "", HFILL } },
    { &hf_opcua_datavalue_mask_statuscodeflag,      {  "has statuscode", "",       FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_STATUSCODE, "", HFILL } },
    { &hf_opcua_datavalue_mask_sourcetimestampflag, {  "has source timestamp", "", FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_SOURCETIMESTAMP, "", HFILL } },
    { &hf_opcua_datavalue_mask_servertimestampflag, {  "has server timestamp", "", FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_SERVERTIMESTAMP, "", HFILL } },
    { &hf_opcua_variant_encodingmask, { "Variant Type", "", FT_UINT8, BASE_HEX, VALS(g_VariantTypes), 0x0, "", HFILL } },
    { &hf_opcua_SourceTimestamp, { "SourceTimestamp", "", FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0, "", HFILL } },
    { &hf_opcua_ServerTimestamp, { "ServerTimestamp", "", FT_ABSOLUTE_TIME, BASE_NONE, NULL, 0x0, "", HFILL } },
    { &hf_opcua_diag_symbolicid,      { "SymblicId", "",       FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_opcua_diag_namespace,       { "Namespace", "",       FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_opcua_diag_localizedtext,   { "LocaliezdText", "",   FT_INT32, BASE_DEC, NULL, 0x0, "", HFILL } },
    { &hf_opcua_diag_additionalinfo,  { "AdditionalInfo", "",  FT_STRING, BASE_NONE, NULL, 0x0, "", HFILL } },
    { &hf_opcua_diag_innerstatuscode, { "InnerStatusCode", "", FT_UINT32, BASE_HEX, NULL, 0x0, "", HFILL } },
    { &hf_opcua_extobj_mask_binbodyflag, {  "has binary body", "", FT_BOOLEAN, 8, NULL, EXTOBJ_ENCODINGMASK_BINBODY_FLAG, "", HFILL } },
    { &hf_opcua_extobj_mask_xmlbodyflag, {  "has xml body",    "", FT_BOOLEAN, 8, NULL, EXTOBJ_ENCODINGMASK_XMLBODY_FLAG, "", HFILL } }
};

void registerSimpleTypes(int proto)
{
    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

void parseBoolean(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, TRUE); *pOffset+=1;
}

void parseByte(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, TRUE); *pOffset+=1;
}

void parseSByte(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, TRUE); *pOffset+=1;
}

void parseUInt16(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 2, TRUE); *pOffset+=2;
}

void parseInt16(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 2, TRUE); *pOffset+=2;
}

void parseUInt32(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, TRUE); *pOffset+=4;
}

void parseInt32(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, TRUE); *pOffset+=4;
}

void parseUInt64(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 8, TRUE); *pOffset+=8;
}

void parseInt64(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 8, TRUE); *pOffset+=8;
}

void parseString(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    char *szValue = ep_alloc(MAX_BUFFER);
    gint iOffset = *pOffset;
    gint32 iLen = tvb_get_letohl(tvb, *pOffset);
    iOffset+=4;

    if (szValue)
    {
        if (iLen == -1)
        {
            g_snprintf(szValue, MAX_BUFFER, "[OpcUa Null String]");
        }
        else if (iLen >= 0)
        {
            int iStrLen = iLen;
            if (iStrLen > (MAX_BUFFER-1)) iStrLen = MAX_BUFFER - 1;
            /* copy non null terminated string of length iStrlen */
            strncpy(szValue, (char*)&tvb->real_data[iOffset], iStrLen);
            /* set null terminator */
            szValue[iStrLen] = 0;
            iOffset += iLen; /* eat the whole string */
        }
        else
        {
            g_snprintf(szValue, MAX_BUFFER, "[Invalid String] Ups, something is wrong with this message.");
        }

        proto_tree_add_string(tree, hfIndex, tvb, *pOffset, (iOffset - *pOffset), szValue);
        *pOffset = iOffset;
    }
}

void parseStatusCode(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, TRUE); 
    *pOffset += 4;
}

void parseLocalizedText(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName)
{
    gint        iOffset = *pOffset;
    guint8      EncodingMask;
    proto_tree *mask_tree;
    proto_tree *subtree;
    proto_item *ti;

    ti = proto_tree_add_text(tree, tvb, 0, -1, "%s: LocalizedText", szFieldName);
    subtree = proto_item_add_subtree(ti, ett_opcua_localizedtext);

    /* parse encoding mask */
    EncodingMask = tvb_get_guint8(tvb, iOffset);
    ti = proto_tree_add_text(subtree, tvb, 0, -1, "EncodingMask");
    mask_tree = proto_item_add_subtree(ti, ett_opcua_localizedtext);
    proto_tree_add_item(mask_tree, hf_opcua_loctext_mask_localeflag, tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_loctext_mask_textflag,   tvb, iOffset, 1, TRUE);
    iOffset++;

    if (EncodingMask & LOCALIZEDTEXT_ENCODINGBYTE_LOCALE)
    {
        parseString(subtree, tvb, &iOffset, hf_opcua_Locale);
    }

    if (EncodingMask & LOCALIZEDTEXT_ENCODINGBYTE_TEXT)
    {
        parseString(subtree, tvb, &iOffset, hf_opcua_Text);
    }

    *pOffset = iOffset;
}

void parseGuid(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, GUID_LEN, TRUE); *pOffset+=GUID_LEN;
}

void parseByteString(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    int iOffset = *pOffset;
    gint32 iLen = tvb_get_letohl(tvb, iOffset);
    iOffset += 4;

    if (iLen == -1)
    {
    }
    else if (iLen >= 0)
    {
        iOffset += iLen;
    }
    proto_tree_add_item(tree, hfIndex, tvb, *pOffset, (iOffset - *pOffset), TRUE);
    *pOffset = iOffset;
}

void parseXmlElement(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    parseByteString(tree, tvb, pOffset, hfIndex);
}

void parseFloat(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
	 proto_tree_add_item(tree, hfIndex, tvb, *pOffset, sizeof(gfloat), TRUE);
     *pOffset += sizeof(gfloat);
}

void parseDouble(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
	 proto_tree_add_item(tree, hfIndex, tvb, *pOffset, sizeof(gdouble), TRUE);
     *pOffset += sizeof(gdouble);
}

void parseDateTime(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    *pOffset = dissect_nt_64bit_time(tvb, tree, *pOffset, hfIndex);
}

void parseDiagnosticInfo(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName)
{
    gint        iOffset = *pOffset;
    guint8      EncodingMask;
    proto_tree *mask_tree;
    proto_tree *subtree;
    proto_item *ti;

    ti = proto_tree_add_text(tree, tvb, 0, -1, "%s: DiagnosticInfo", szFieldName);
    subtree = proto_item_add_subtree(ti, ett_opcua_diagnosticinfo);

    /* parse encoding mask */
    EncodingMask = tvb_get_guint8(tvb, iOffset);
    ti = proto_tree_add_text(subtree, tvb, 0, -1, "EncodingMask");
    mask_tree = proto_item_add_subtree(ti, ett_opcua_diagnosticinfo);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_symbolicflag,        tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_namespaceflag,       tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_localizedtextflag,   tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_additionalinfoflag,  tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_innerstatuscodeflag, tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_innerdiaginfoflag,   tvb, iOffset, 1, TRUE);
    iOffset++;

    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_SYMBOLICID_FLAG)
    {
        parseInt32(subtree, tvb, &iOffset, hf_opcua_diag_symbolicid);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_NAMESPACE_FLAG)
    {
        parseInt32(subtree, tvb, &iOffset, hf_opcua_diag_namespace);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_LOCALIZEDTEXT_FLAG)
    {
        parseInt32(subtree, tvb, &iOffset, hf_opcua_diag_localizedtext);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_ADDITIONALINFO_FLAG)
    {
        parseString(subtree, tvb, &iOffset, hf_opcua_diag_additionalinfo);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_INNERSTATUSCODE_FLAG)
    {
        parseStatusCode(subtree, tvb, &iOffset, hf_opcua_diag_innerstatuscode);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_INNERDIAGNOSTICINFO_FLAG)
    {
        parseDiagnosticInfo(subtree, tvb, &iOffset, "Inner DiagnosticInfo");
    }

    *pOffset = iOffset;
}

void parseQualifiedName(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, 0, -1, "%s: QualifiedName", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_qualifiedname);

    parseInt32(subtree, tvb, pOffset, hf_opcua_Id);
    parseString(subtree, tvb, pOffset, hf_opcua_Name);
}

void parseDataValue(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, 0, -1, "%s: DataValue", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_datavalue);
    proto_tree *mask_tree;
    gint    iOffset = *pOffset;
    guint8  EncodingMask;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    ti = proto_tree_add_text(subtree, tvb, 0, -1, "EncodingMask");
    mask_tree = proto_item_add_subtree(ti, ett_opcua_datavalue);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_valueflag,           tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_statuscodeflag,      tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_sourcetimestampflag, tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_servertimestampflag, tvb, iOffset, 1, TRUE);
    iOffset++;

    if (EncodingMask & DATAVALUE_ENCODINGBYTE_VALUE)
    {
        parseVariant(subtree, tvb, &iOffset, "Value");
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_STATUSCODE)
    {
        parseStatusCode(subtree, tvb, &iOffset, hf_opcua_StatusCode);
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SOURCETIMESTAMP)
    {
        parseDateTime(subtree, tvb, &iOffset, hf_opcua_SourceTimestamp);
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SERVERTIMESTAMP)
    {
        parseDateTime(subtree, tvb, &iOffset, hf_opcua_ServerTimestamp);
    }

    *pOffset = iOffset;
}

void parseVariant(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, 0, -1, "%s: Variant", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_variant);
    gint    iOffset = *pOffset;
    guint8  EncodingMask;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    proto_tree_add_item(subtree, hf_opcua_variant_encodingmask, tvb, iOffset, 1, TRUE);
    iOffset++;

    if (EncodingMask & VARIANT_ARRAYMASK)
    {
        EncodingMask &= ~VARIANT_ARRAYMASK;

        switch(EncodingMask)
        {
        case OpcUaType_Null: break;
        case OpcUaType_Boolean: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_Boolean, parseBoolean); break;
        case OpcUaType_SByte: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_SByte, parseSByte); break;
        case OpcUaType_Byte: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_Byte, parseByte); break;
        case OpcUaType_Int16: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_Int16, parseInt16); break;
        case OpcUaType_UInt16: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_UInt16, parseUInt16); break;
        case OpcUaType_Int32: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_Int32, parseInt32); break;
        case OpcUaType_UInt32: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_UInt32, parseUInt32); break;
        case OpcUaType_Int64: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_Int64, parseInt64); break;
        case OpcUaType_UInt64: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_UInt64, parseUInt64); break;
        case OpcUaType_Float: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_Float, parseFloat); break;
        case OpcUaType_Double: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_Double, parseDouble); break;
        case OpcUaType_String: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_String, parseString); break;
        case OpcUaType_DateTime: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_DateTime, parseDateTime); break;
        case OpcUaType_Guid: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_Guid, parseGuid); break;
        case OpcUaType_ByteString: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_ByteString, parseByteString); break;
        case OpcUaType_XmlElement: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_XmlElement, parseXmlElement); break;
        case OpcUaType_NodeId: parseArrayComplex(subtree, tvb, &iOffset, "NodeId", parseNodeId); break;
        case OpcUaType_ExpandedNodeId: parseArrayComplex(subtree, tvb, &iOffset, "ExpandedNodeId", parseExpandedNodeId); break;
        case OpcUaType_StatusCode: parseArraySimple(subtree, tvb, &iOffset, hf_opcua_StatusCode, parseStatusCode); break;
        case OpcUaType_DiagnosticInfo: parseArrayComplex(subtree, tvb, &iOffset, "DiagnosticInfo", parseDiagnosticInfo); break;
        case OpcUaType_QualifiedName: parseArrayComplex(subtree, tvb, &iOffset, "QualifiedName", parseQualifiedName); break;
        case OpcUaType_LocalizedText: parseArrayComplex(subtree, tvb, &iOffset, "LocalizedText", parseLocalizedText); break;
        case OpcUaType_ExtensionObject: parseArrayComplex(subtree, tvb, &iOffset, "ExtensionObject", parseExtensionObject); break;
        case OpcUaType_DataValue: parseArrayComplex(subtree, tvb, &iOffset, "DataValue", parseDataValue); break;
        case OpcUaType_Variant: parseArrayComplex(subtree, tvb, &iOffset, "Variant", parseVariant); break;
        }
    }
    else
    {
        switch(EncodingMask)
        {
        case OpcUaType_Null: break;
        case OpcUaType_Boolean: parseBoolean(subtree, tvb, &iOffset, hf_opcua_Boolean); break;
        case OpcUaType_SByte: parseSByte(subtree, tvb, &iOffset, hf_opcua_SByte); break;
        case OpcUaType_Byte: parseByte(subtree, tvb, &iOffset, hf_opcua_Byte); break;
        case OpcUaType_Int16: parseInt16(subtree, tvb, &iOffset, hf_opcua_Int16); break;
        case OpcUaType_UInt16: parseUInt16(subtree, tvb, &iOffset, hf_opcua_UInt16); break;
        case OpcUaType_Int32: parseInt32(subtree, tvb, &iOffset, hf_opcua_Int32); break;
        case OpcUaType_UInt32: parseUInt32(subtree, tvb, &iOffset, hf_opcua_UInt32); break;
        case OpcUaType_Int64: parseInt64(subtree, tvb, &iOffset, hf_opcua_Int64); break;
        case OpcUaType_UInt64: parseUInt64(subtree, tvb, &iOffset, hf_opcua_UInt64); break;
        case OpcUaType_Float: parseFloat(subtree, tvb, &iOffset, hf_opcua_Float); break;
        case OpcUaType_Double: parseDouble(subtree, tvb, &iOffset, hf_opcua_Double); break;
        case OpcUaType_String: parseString(subtree, tvb, &iOffset, hf_opcua_String); break;
        case OpcUaType_DateTime: parseDateTime(subtree, tvb, &iOffset, hf_opcua_DateTime); break;
        case OpcUaType_Guid: parseGuid(subtree, tvb, &iOffset, hf_opcua_Guid); break;
        case OpcUaType_ByteString: parseByteString(subtree, tvb, &iOffset, hf_opcua_ByteString); break;
        case OpcUaType_XmlElement: parseXmlElement(subtree, tvb, &iOffset, hf_opcua_XmlElement); break;
        case OpcUaType_NodeId: parseNodeId(subtree, tvb, &iOffset, "Value"); break;
        case OpcUaType_ExpandedNodeId: parseExpandedNodeId(subtree, tvb, &iOffset, "Value"); break;
        case OpcUaType_StatusCode: parseStatusCode(subtree, tvb, &iOffset, hf_opcua_StatusCode); break;
        case OpcUaType_DiagnosticInfo: parseDiagnosticInfo(subtree, tvb, &iOffset, "Value"); break;
        case OpcUaType_QualifiedName: parseQualifiedName(subtree, tvb, &iOffset, "Value"); break;
        case OpcUaType_LocalizedText: parseLocalizedText(subtree, tvb, &iOffset, "Value"); break;
        case OpcUaType_ExtensionObject: parseExtensionObject(subtree, tvb, &iOffset, "Value"); break;
        case OpcUaType_DataValue: parseDataValue(subtree, tvb, &iOffset, "Value"); break;
        case OpcUaType_Variant: parseVariant(subtree, tvb, &iOffset, "Value"); break;
        }
    }

    *pOffset = iOffset;
}

/** General parsing function for arrays of simple types.
 * All arrays have one 4 byte signed integer length information,
 * followed by n data elements.
 */
void parseArraySimple(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex, fctSimpleTypeParser pParserFunction)
{
    char szFieldName[] = "Array of Simple Type";
    proto_item *ti = proto_tree_add_text(tree, tvb, 0, -1, "%s", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_array);
    int i;
    gint32 iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, TRUE);
    *pOffset += 4;

    if (iLen == -1) return; /* no array */
    if (iLen == 0)  return; /* array with zero elements*/

    for (i=0; i<iLen; i++)
    {
        (*pParserFunction)(subtree, tvb, pOffset, hfIndex);
    }
}

/** General parsing function for arrays of enums.
 * All arrays have one 4 byte signed integer length information,
 * followed by n data elements.
 */
void parseArrayEnum(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, fctEnumParser pParserFunction)
{
    char szFieldName[] = "Array of Enum Type";
    proto_item *ti = proto_tree_add_text(tree, tvb, 0, -1, "%s", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_array);
    int i;
    gint32 iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, TRUE);
    *pOffset += 4;

    if (iLen == -1) return; /* no array */
    if (iLen == 0)  return; /* array with zero elements*/

    for (i=0; i<iLen; i++)
    {
        (*pParserFunction)(subtree, tvb, pOffset);
    }
}

/** General parsing function for arrays of complex types.
 * All arrays have one 4 byte signed integer length information,
 * followed by n data elements.
 */
void parseArrayComplex(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName, fctComplexTypeParser pParserFunction)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, 0, -1, "Array of %s", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_array);
    int i;
    gint32 iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, TRUE);
    *pOffset += 4;

    if (iLen == -1) return; /* no array */
    if (iLen == 0)  return; /* array with zero elements*/

    for (i=0; i<iLen; i++)
    {
        char szNum[20];
        g_snprintf(szNum, 20, "[%i]", i);
        (*pParserFunction)(subtree, tvb, pOffset, szNum);
    }
}

void parseNodeId(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, 0, -1, "%s: NodeId", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_nodeid);
    gint    iOffset = *pOffset;
    guint8  EncodingMask;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    proto_tree_add_item(subtree, hf_opcua_nodeid_encodingmask, tvb, iOffset, 1, TRUE);
    iOffset++;

    switch(EncodingMask)
    {
    case 0x00: /* two byte node id */
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 1, TRUE);
        iOffset+=1;
        break;
    case 0x01: /* four byte node id */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsid, tvb, iOffset, 1, TRUE);
        iOffset+=1;
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 2, TRUE);
        iOffset+=2;
        break;
    case 0x02: /* numeric, that does not fit into four bytes */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsid, tvb, iOffset, 4, TRUE);
        iOffset+=4;
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 4, TRUE);
        iOffset+=4;
        break;
    case 0x03: /* string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsid, tvb, iOffset, 4, TRUE);
        iOffset+=4;
        parseString(subtree, tvb, &iOffset, hf_opcua_String);
        break;
    case 0x04: /* uri */
        parseString(subtree, tvb, &iOffset, hf_opcua_Uri);
        break;
    case 0x05: /* guid */
        parseGuid(subtree, tvb, &iOffset, hf_opcua_Guid);
        break;
    case 0x06: /* byte string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsid, tvb, iOffset, 4, TRUE);
        iOffset+=4;
        parseByteString(subtree, tvb, &iOffset, hf_opcua_ByteString);
        break;
    };

    *pOffset = iOffset;
}

void parseExtensionObject(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName)
{
    gint    iOffset = *pOffset;
    guint8  EncodingMask;
    proto_tree *extobj_tree;
    proto_tree *mask_tree;
    proto_item *ti;

    /* add extension object subtree */
    ti = proto_tree_add_text(tree, tvb, 0, -1, "%s : ExtensionObject", szFieldName);
    extobj_tree = proto_item_add_subtree(ti, ett_opcua_extensionobject);

    /* add nodeid subtree */
    parseExpandedNodeId(extobj_tree, tvb, &iOffset, "TypeId");

    /* parse encoding mask */
    EncodingMask = tvb_get_guint8(tvb, iOffset);
    ti = proto_tree_add_text(extobj_tree, tvb, 0, -1, "EncodingMask");
    mask_tree = proto_item_add_subtree(ti, ett_opcua_extobj_encodingmask);
    proto_tree_add_item(mask_tree, hf_opcua_extobj_mask_binbodyflag, tvb, iOffset, 1, TRUE);
    proto_tree_add_item(mask_tree, hf_opcua_extobj_mask_xmlbodyflag, tvb, iOffset, 1, TRUE);
    iOffset++;

    if (EncodingMask & EXTOBJ_ENCODINGMASK_BINBODY_FLAG) /* has binary body ? */
    {
        parseByteString(extobj_tree, tvb, &iOffset, hf_opcua_ByteString);
    }

    *pOffset = iOffset;
}

void parseExpandedNodeId(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, 0, -1, "%s: ExpandedNodeId", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_nodeid);
    gint    iOffset = *pOffset;
    guint8  EncodingMask;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    proto_tree_add_item(subtree, hf_opcua_nodeid_encodingmask, tvb, iOffset, 1, TRUE);
    iOffset++;

    switch(EncodingMask)
    {
    case 0x00: /* two byte node id */
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 1, TRUE);
        iOffset+=1;
        break;
    case 0x01: /* four byte node id */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsid, tvb, iOffset, 1, TRUE);
        iOffset+=1;
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 2, TRUE);
        iOffset+=2;
        break;
    case 0x02: /* numeric, that does not fit into four bytes */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsid, tvb, iOffset, 4, TRUE);
        iOffset+=4;
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 4, TRUE);
        iOffset+=4;
        break;
    case 0x03: /* string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsid, tvb, iOffset, 4, TRUE);
        iOffset+=4;
        parseString(subtree, tvb, &iOffset, hf_opcua_String);
        break;
    case 0x04: /* uri */
        parseString(subtree, tvb, &iOffset, hf_opcua_Uri);
        break;
    case 0x05: /* guid */
        parseGuid(subtree, tvb, &iOffset, hf_opcua_Guid);
        break;
    case 0x06: /* byte string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsid, tvb, iOffset, 4, TRUE);
        iOffset+=4;
        parseByteString(subtree, tvb, &iOffset, hf_opcua_ByteString);
        break;
    };

    if (EncodingMask & NODEID_URIMASK)
    {
        parseString(subtree, tvb, &iOffset, hf_opcua_Uri);
    }

    *pOffset = iOffset;
}
