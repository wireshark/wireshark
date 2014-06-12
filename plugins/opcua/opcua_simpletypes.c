/******************************************************************************
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/dissectors/packet-windows-common.h>
#include "opcua_simpletypes.h"
#include "opcua_hfindeces.h"
#include "opcua_extensionobjectids.h"
#include "opcua_statuscode.h"
#include <epan/wmem/wmem.h>

#define DIAGNOSTICINFO_ENCODINGMASK_SYMBOLICID_FLAG           0x01
#define DIAGNOSTICINFO_ENCODINGMASK_NAMESPACE_FLAG            0x02
#define DIAGNOSTICINFO_ENCODINGMASK_LOCALIZEDTEXT_FLAG        0x04
#define DIAGNOSTICINFO_ENCODINGMASK_ADDITIONALINFO_FLAG       0x08
#define DIAGNOSTICINFO_ENCODINGMASK_INNERSTATUSCODE_FLAG      0x10
#define DIAGNOSTICINFO_ENCODINGMASK_INNERDIAGNOSTICINFO_FLAG  0x20
#define LOCALIZEDTEXT_ENCODINGBYTE_LOCALE                     0x01
#define LOCALIZEDTEXT_ENCODINGBYTE_TEXT                       0x02
#define NODEID_NAMESPACEURIFLAG                               0x80
#define NODEID_SERVERINDEXFLAG                                0x40
#define DATAVALUE_ENCODINGBYTE_VALUE                          0x01
#define DATAVALUE_ENCODINGBYTE_STATUSCODE                     0x02
#define DATAVALUE_ENCODINGBYTE_SOURCETIMESTAMP                0x04
#define DATAVALUE_ENCODINGBYTE_SERVERTIMESTAMP                0x08
#define DATAVALUE_ENCODINGBYTE_SOURCEPICOSECONDS              0x10
#define DATAVALUE_ENCODINGBYTE_SERVERPICOSECONDS              0x20
#define EXTOBJ_ENCODINGMASK_BINBODY_FLAG                      0x01
#define EXTOBJ_ENCODINGMASK_XMLBODY_FLAG                      0x02
#define STATUSCODE_STRUCTURECHANGED                           0x8000
#define STATUSCODE_SEMANTICSCHANGED                           0x4000
#define STATUSCODE_INFOTYPE_DATAVALUE                         0x00000400
#define STATUSCODE_INFOBIT_OVERFLOW                           0x0080
#define STATUSCODE_INFOBIT_HISTORIAN_PARTIAL                  0x0004
#define STATUSCODE_INFOBIT_HISTORIAN_EXTRADATA                0x0008
#define STATUSCODE_INFOBIT_HISTORIAN_MULTIVALUE               0x0010

/* Chosen arbitrarily */
#define MAX_ARRAY_LEN 10000

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
static int hf_opcua_datavalue_mask_sourcepicoseconds = -1;
static int hf_opcua_datavalue_mask_serverpicoseconds = -1;
static int hf_opcua_nodeid_encodingmask = -1;
static int hf_opcua_expandednodeid_mask_namespaceuri = -1;
static int hf_opcua_expandednodeid_mask_serverindex = -1;
static int hf_opcua_variant_encodingmask = -1;
static int hf_opcua_nodeid_nsindex = -1;
static int hf_opcua_nodeid_numeric = -1;
static int hf_opcua_nodeid_string = -1;
static int hf_opcua_nodeid_guid = -1;
static int hf_opcua_nodeid_bytestring = -1;
static int hf_opcua_localizedtext_locale = -1;
static int hf_opcua_localizedtext_text = -1;
static int hf_opcua_qualifiedname_id = -1;
static int hf_opcua_qualifiedname_name = -1;
static int hf_opcua_SourceTimestamp = -1;
static int hf_opcua_SourcePicoseconds = -1;
static int hf_opcua_ServerTimestamp = -1;
static int hf_opcua_ServerPicoseconds = -1;
static int hf_opcua_diag_symbolicid = -1;
static int hf_opcua_diag_namespace = -1;
static int hf_opcua_diag_localizedtext = -1;
static int hf_opcua_diag_additionalinfo = -1;
static int hf_opcua_diag_innerstatuscode = -1;
static int hf_opcua_extobj_mask_binbodyflag = -1;
static int hf_opcua_extobj_mask_xmlbodyflag = -1;
static int hf_opcua_ArraySize = -1;
static int hf_opcua_ServerIndex = -1;
static int hf_opcua_status_StructureChanged = -1;
static int hf_opcua_status_SemanticsChanged = -1;
static int hf_opcua_status_InfoBit_Limit_Overflow = -1;
static int hf_opcua_status_InfoBit_Historian_Partial = -1;
static int hf_opcua_status_InfoBit_Historian_ExtraData = -1;
static int hf_opcua_status_InfoBit_Historian_MultiValue = -1;
static int hf_opcua_status_InfoType = -1;
static int hf_opcua_status_Limit = -1;
static int hf_opcua_status_Historian = -1;

/** NodeId encoding mask table */
static const value_string g_nodeidmasks[] = {
    { 0x00, "Two byte encoded Numeric" },
    { 0x01, "Four byte encoded Numeric" },
    { 0x02, "Numeric of arbitrary length" },
    { 0x03, "String" },
    { 0x04, "GUID" },
    { 0x05, "Opaque" },
    { 0, NULL }
};

/** StatusCode info types */
static const value_string g_infotype[] = {
    { 0x00, "Not used" },
    { 0x01, "DataValue" },
    { 0x02, "Reserved" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

/** StatusCode Limit types */
static const value_string g_limit[] = {
    { 0x00, "None" },
    { 0x01, "Low" },
    { 0x02, "High" },
    { 0x03, "Constant" },
    { 0, NULL }
};

/** StatusCode Historian types */
static const value_string g_historian[] = {
    { 0x00, "Raw" },
    { 0x01, "Calculated" },
    { 0x02, "Interpolated" },
    { 0x03, "Reserved" },
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
    OpcUaType_QualifiedName = 20,
    OpcUaType_LocalizedText = 21,
    OpcUaType_ExtensionObject = 22,
    OpcUaType_DataValue = 23,
    OpcUaType_Variant = 24,
    OpcUaType_DiagnosticInfo = 25
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
    { 20, "QualifiedName" },
    { 21, "LocalizedText" },
    { 22, "ExtensionObject" },
    { 23, "DataValue" },
    { 24, "Variant" },
    { 25, "DiagnosticInfo" },
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
    { 0x80+20, "Array of QualifiedName" },
    { 0x80+21, "Array of LocalizedText" },
    { 0x80+22, "Array of ExtensionObject" },
    { 0x80+23, "Array of DataValue" },
    { 0x80+24, "Array of Variant" },
    { 0x80+25, "Array of DiagnosticInfo" },
    { 0xC0,   "Matrix of Null" },
    { 0xC0+1, "Matrix of Boolean" },
    { 0xC0+2, "Matrix of SByte" },
    { 0xC0+3, "Matrix of Byte" },
    { 0xC0+4, "Matrix of Int16" },
    { 0xC0+5, "Matrix of UInt16" },
    { 0xC0+6, "Matrix of Int32" },
    { 0xC0+7, "Matrix of UInt32" },
    { 0xC0+8, "Matrix of Int64" },
    { 0xC0+9, "Matrix of UInt64" },
    { 0xC0+10, "Matrix of Float" },
    { 0xC0+11, "Matrix of Double" },
    { 0xC0+12, "Matrix of String" },
    { 0xC0+13, "Matrix of DateTime" },
    { 0xC0+14, "Matrix of Guid" },
    { 0xC0+15, "Matrix of ByteString" },
    { 0xC0+16, "Matrix of XmlElement" },
    { 0xC0+17, "Matrix of NodeId" },
    { 0xC0+18, "Matrix of ExpandedNodeId" },
    { 0xC0+19, "Matrix of StatusCode" },
    { 0xC0+20, "Matrix of QualifiedName" },
    { 0xC0+21, "Matrix of LocalizedText" },
    { 0xC0+22, "Matrix of ExtensionObject" },
    { 0xC0+23, "Matrix of DataValue" },
    { 0xC0+24, "Matrix of Variant" },
    { 0xC0+25, "Matrix of DiagnosticInfo" },
    { 0, NULL }
};
#define VARIANT_ARRAYDIMENSIONS 0x40
#define VARIANT_ARRAYMASK 0x80

/* trees */
static gint ett_opcua_diagnosticinfo = -1;
static gint ett_opcua_diagnosticinfo_encodingmask = -1;
static gint ett_opcua_nodeid = -1;
static gint ett_opcua_expandednodeid = -1;
static gint ett_opcua_localizedtext = -1;
static gint ett_opcua_localizedtext_encodingmask = -1;
static gint ett_opcua_qualifiedname = -1;
static gint ett_opcua_datavalue = -1;
static gint ett_opcua_datavalue_encodingmask = -1;
static gint ett_opcua_variant = -1;
static gint ett_opcua_variant_arraydims = -1;
static gint ett_opcua_extensionobject = -1;
static gint ett_opcua_extensionobject_encodingmask = -1;
static gint ett_opcua_statuscode = -1;
static gint ett_opcua_statuscode_info = -1;
gint ett_opcua_array_Boolean = -1;
gint ett_opcua_array_SByte = -1;
gint ett_opcua_array_Byte = -1;
gint ett_opcua_array_Int16 = -1;
gint ett_opcua_array_UInt16 = -1;
gint ett_opcua_array_Int32 = -1;
gint ett_opcua_array_UInt32 = -1;
gint ett_opcua_array_Int64 = -1;
gint ett_opcua_array_UInt64 = -1;
gint ett_opcua_array_Float = -1;
gint ett_opcua_array_Double = -1;
gint ett_opcua_array_String = -1;
gint ett_opcua_array_DateTime = -1;
gint ett_opcua_array_Guid = -1;
gint ett_opcua_array_ByteString = -1;
gint ett_opcua_array_XmlElement = -1;
gint ett_opcua_array_NodeId = -1;
gint ett_opcua_array_ExpandedNodeId = -1;
gint ett_opcua_array_StatusCode = -1;
gint ett_opcua_array_DiagnosticInfo = -1;
gint ett_opcua_array_QualifiedName = -1;
gint ett_opcua_array_LocalizedText = -1;
gint ett_opcua_array_ExtensionObject = -1;
gint ett_opcua_array_DataValue = -1;
gint ett_opcua_array_Variant = -1;
static gint *ett[] =
{
  &ett_opcua_diagnosticinfo,
  &ett_opcua_diagnosticinfo_encodingmask,
  &ett_opcua_nodeid,
  &ett_opcua_expandednodeid,
  &ett_opcua_localizedtext,
  &ett_opcua_localizedtext_encodingmask,
  &ett_opcua_qualifiedname,
  &ett_opcua_datavalue,
  &ett_opcua_datavalue_encodingmask,
  &ett_opcua_variant,
  &ett_opcua_variant_arraydims,
  &ett_opcua_extensionobject,
  &ett_opcua_extensionobject_encodingmask,
  &ett_opcua_statuscode,
  &ett_opcua_statuscode_info,
  &ett_opcua_array_Boolean,
  &ett_opcua_array_SByte,
  &ett_opcua_array_Byte,
  &ett_opcua_array_Int16,
  &ett_opcua_array_UInt16,
  &ett_opcua_array_Int32,
  &ett_opcua_array_UInt32,
  &ett_opcua_array_Int64,
  &ett_opcua_array_UInt64,
  &ett_opcua_array_Float,
  &ett_opcua_array_Double,
  &ett_opcua_array_String,
  &ett_opcua_array_DateTime,
  &ett_opcua_array_Guid,
  &ett_opcua_array_ByteString,
  &ett_opcua_array_XmlElement,
  &ett_opcua_array_NodeId,
  &ett_opcua_array_ExpandedNodeId,
  &ett_opcua_array_StatusCode,
  &ett_opcua_array_DiagnosticInfo,
  &ett_opcua_array_QualifiedName,
  &ett_opcua_array_LocalizedText,
  &ett_opcua_array_ExtensionObject,
  &ett_opcua_array_DataValue,
  &ett_opcua_array_Variant
};

void registerSimpleTypes(int proto)
{
    static hf_register_info hf[] =
    {
        /* full name  ,           abbreviation  ,       type     , display  , strings, bitmask, blurb, id, parent, ref_count */
        { &hf_opcua_diag_mask_symbolicflag,
        {  "has symbolic id",           "opcua.has_symbolic_id", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_SYMBOLICID_FLAG, NULL, HFILL }
        },
        { &hf_opcua_diag_mask_namespaceflag,
        {  "has namespace",             "opcua.has_namespace", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_NAMESPACE_FLAG, NULL, HFILL }
        },
        { &hf_opcua_diag_mask_localizedtextflag,
        {  "has localizedtext",         "opcua.has_localizedtext", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_LOCALIZEDTEXT_FLAG, NULL, HFILL }
        },
        { &hf_opcua_diag_mask_additionalinfoflag,
        {  "has additional info",       "opcua.has_additional_info", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_ADDITIONALINFO_FLAG, NULL, HFILL }
        },
        { &hf_opcua_diag_mask_innerstatuscodeflag,
        {  "has inner statuscode",      "opcua.has_inner_statuscode", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_INNERSTATUSCODE_FLAG, NULL, HFILL }
        },
        { &hf_opcua_diag_mask_innerdiaginfoflag,
        {  "has inner diagnostic info", "opcua.has_inner_diagnostic_code", FT_BOOLEAN, 8, NULL, DIAGNOSTICINFO_ENCODINGMASK_INNERDIAGNOSTICINFO_FLAG, NULL, HFILL }
        },
        { &hf_opcua_loctext_mask_localeflag,
        {  "has locale information", "opcua.has_locale_information", FT_BOOLEAN, 8, NULL, LOCALIZEDTEXT_ENCODINGBYTE_LOCALE, NULL, HFILL }
        },
        { &hf_opcua_loctext_mask_textflag,
        {  "has text", "opcua.has_text", FT_BOOLEAN, 8, NULL, LOCALIZEDTEXT_ENCODINGBYTE_TEXT, NULL, HFILL }
        },
        { &hf_opcua_nodeid_encodingmask,
        {  "NodeId EncodingMask",        "application.nodeid.encodingmask", FT_UINT8,   BASE_HEX,  VALS(g_nodeidmasks), 0x0F,    NULL,    HFILL }
        },
        { &hf_opcua_nodeid_nsindex,
        {  "NodeId Namespace Index",        "application.nodeid.nsindex",         FT_UINT16,  BASE_DEC,  NULL, 0x0,    NULL,    HFILL }
        },
        { &hf_opcua_nodeid_numeric, {  "NodeId Identifier Numeric", "application.nodeid.numeric", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_nodeid_string, { "NodeId Identifier String", "application.nodeid.string", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_nodeid_guid, { "NodeId Identifier Guid", "application.nodeid.guid", FT_GUID, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_nodeid_bytestring, { "NodeId Identifier ByteString", "application.nodeid.bytestring", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_expandednodeid_mask_namespaceuri, {  "has namespace uri", "opcua.has_namespace_uri", FT_BOOLEAN, 8, NULL, NODEID_NAMESPACEURIFLAG, NULL, HFILL } },
        { &hf_opcua_expandednodeid_mask_serverindex, {  "has server index", "opcua.has_server_index", FT_BOOLEAN, 8, NULL, NODEID_SERVERINDEXFLAG, NULL, HFILL } },
        { &hf_opcua_localizedtext_locale, { "Locale", "opcua.Locale", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_localizedtext_text,   { "Text", "opcua.Text", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_qualifiedname_id,     { "Id", "opcua.Id", FT_UINT16, BASE_DEC,  NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_qualifiedname_name,   { "Name", "opcua.Name", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_datavalue_mask_valueflag,           {  "has value", "opcua.has_value",            FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_VALUE, NULL, HFILL } },
        { &hf_opcua_datavalue_mask_statuscodeflag,      {  "has statuscode", "opcua.has_statuscode",       FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_STATUSCODE, NULL, HFILL } },
        { &hf_opcua_datavalue_mask_sourcetimestampflag, {  "has source timestamp", "opcua.has_source_timestamp", FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_SOURCETIMESTAMP, NULL, HFILL } },
        { &hf_opcua_datavalue_mask_servertimestampflag, {  "has server timestamp", "opcua.has_server_timestamp", FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_SERVERTIMESTAMP, NULL, HFILL } },
        { &hf_opcua_datavalue_mask_sourcepicoseconds, {  "has source picoseconds", "opcua.has_source_picoseconds", FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_SOURCEPICOSECONDS, NULL, HFILL } },
        { &hf_opcua_datavalue_mask_serverpicoseconds, {  "has server picoseconds", "opcua.has_server_picoseconds", FT_BOOLEAN, 8, NULL, DATAVALUE_ENCODINGBYTE_SERVERPICOSECONDS, NULL, HFILL } },
        { &hf_opcua_variant_encodingmask, { "Variant Type", "opcua.has_value", FT_UINT8, BASE_HEX, VALS(g_VariantTypes), 0x0, NULL, HFILL } },
        { &hf_opcua_SourceTimestamp, { "SourceTimestamp", "opcua.SourceTimestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_SourcePicoseconds, { "SourcePicoseconds", "opcua.SourcePicoseconds", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_ServerTimestamp, { "ServerTimestamp", "opcua.ServerTimestamp", FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_ServerPicoseconds, { "ServerPicoseconds", "opcua.ServerPicoseconds", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_diag_symbolicid,      { "SymbolicId", "opcua.SymbolicId",       FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_diag_namespace,       { "Namespace", "opcua.Namespace",       FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_diag_localizedtext,   { "LocaliezdText", "opcua.LocaliezdText",   FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_diag_additionalinfo,  { "AdditionalInfo", "opcua.AdditionalInfo",  FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_diag_innerstatuscode, { "InnerStatusCode", "opcua.InnerStatusCode", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_extobj_mask_binbodyflag, {  "has binary body", "opcua.has_binary_body", FT_BOOLEAN, 8, NULL, EXTOBJ_ENCODINGMASK_BINBODY_FLAG, NULL, HFILL } },
        { &hf_opcua_extobj_mask_xmlbodyflag, {  "has xml body",    "opcua.has_xml_body", FT_BOOLEAN, 8, NULL, EXTOBJ_ENCODINGMASK_XMLBODY_FLAG, NULL, HFILL } },
        { &hf_opcua_ArraySize, { "ArraySize", "opcua.ArraySize", FT_INT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_ServerIndex, { "ServerIndex", "opcua.ServerIndex", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_opcua_status_StructureChanged, {  "StructureChanged", "opcua.statuscode.structureChanged", FT_BOOLEAN, 16, NULL, STATUSCODE_STRUCTURECHANGED, NULL, HFILL } },
        { &hf_opcua_status_SemanticsChanged, {  "SemanticsChanged", "opcua.statuscode.semanticsChanged", FT_BOOLEAN, 16, NULL, STATUSCODE_SEMANTICSCHANGED, NULL, HFILL } },
        { &hf_opcua_status_InfoBit_Limit_Overflow, {  "Overflow", "opcua.statuscode.overflow", FT_BOOLEAN, 16, NULL, STATUSCODE_INFOBIT_OVERFLOW, NULL, HFILL } },
        { &hf_opcua_status_InfoBit_Historian_Partial, {  "HistorianBit: Partial", "opcua.statuscode.historian.partial", FT_BOOLEAN, 16, NULL, STATUSCODE_INFOBIT_HISTORIAN_PARTIAL, NULL, HFILL } },
        { &hf_opcua_status_InfoBit_Historian_ExtraData, {  "HistorianBit: ExtraData", "opcua.statuscode.historian.extraData", FT_BOOLEAN, 16, NULL, STATUSCODE_INFOBIT_HISTORIAN_EXTRADATA, NULL, HFILL } },
        { &hf_opcua_status_InfoBit_Historian_MultiValue, {  "HistorianBit: MultiValue", "opcua.statuscode.historian.multiValue", FT_BOOLEAN, 16, NULL, STATUSCODE_INFOBIT_HISTORIAN_MULTIVALUE, NULL, HFILL } },
        { &hf_opcua_status_InfoType, { "InfoType", "opcua.statuscode.infoType", FT_UINT16, BASE_HEX, VALS(g_infotype), 0x0C00, NULL, HFILL } },
        { &hf_opcua_status_Limit, { "Limit", "opcua.statuscode.limit", FT_UINT16, BASE_HEX, VALS(g_limit), 0x0300, NULL, HFILL } },
        { &hf_opcua_status_Historian, { "Historian", "opcua.statuscode.historian", FT_UINT16, BASE_HEX, VALS(g_historian), 0x0003, NULL, HFILL } },
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
}

proto_item* parseBoolean(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, ENC_LITTLE_ENDIAN);
    *pOffset+=1;
    return item;
}

proto_item* parseByte(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, ENC_LITTLE_ENDIAN);
    *pOffset+=1;
    return item;
}

proto_item* parseSByte(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, ENC_LITTLE_ENDIAN);
    *pOffset+=1;
    return item;
}

proto_item* parseUInt16(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 2, ENC_LITTLE_ENDIAN);
    *pOffset+=2;
    return item;
}

proto_item* parseInt16(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 2, ENC_LITTLE_ENDIAN);
    *pOffset+=2;
    return item;
}

proto_item* parseUInt32(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);
    *pOffset+=4;
    return item;
}

proto_item* parseInt32(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);
    *pOffset+=4;
    return item;
}

proto_item* parseUInt64(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 8, ENC_LITTLE_ENDIAN);
    *pOffset+=8;
    return item;
}

proto_item* parseInt64(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 8, ENC_LITTLE_ENDIAN);
    *pOffset+=8;
    return item;
}

proto_item* parseString(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    char *szValue;
    gint iOffset = *pOffset;
    gint32 iLen = tvb_get_letohl(tvb, *pOffset);
    iOffset+=4;

    if (iLen == -1)
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 0, ENC_NA);
        proto_item_append_text(item, "[OpcUa Null String]");
        proto_item_set_end(item, tvb, *pOffset + 4);
    }
    else if (iLen == 0)
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 0, ENC_NA);
        proto_item_append_text(item, "[OpcUa Empty String]");
        proto_item_set_end(item, tvb, *pOffset + 4);
    }
    else if (iLen > 0)
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, iOffset, iLen, ENC_UTF_8|ENC_NA);
        iOffset += iLen; /* eat the whole string */
    }
    else
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 0, ENC_NA);
        szValue = wmem_strdup_printf(wmem_packet_scope(), "[Invalid String] Invalid length: %d", iLen);
        proto_item_append_text(item, "%s", szValue);
        proto_item_set_end(item, tvb, *pOffset + 4);
    }

    *pOffset = iOffset;
    return item;
}

proto_item* parseStatusCode(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    guint32 uStatusCode = 0;
    const gchar *szStatusCode = NULL;

    item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);

    uStatusCode = tvb_get_letohl(tvb, *pOffset);
    szStatusCode = val_to_str_const(uStatusCode & 0xFFFF0000, g_statusCodes, "Unknown Status Code");
    proto_item_append_text(item, " [%s]", szStatusCode);

    /* check for status code info flags */
    if (uStatusCode & 0x0000FFFF)
    {
        gint iOffset = *pOffset;
        proto_tree *flags_tree;
        proto_item *ti_inner;

        flags_tree = proto_item_add_subtree(item, ett_opcua_statuscode);

        proto_tree_add_item(flags_tree, hf_opcua_status_StructureChanged, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(flags_tree, hf_opcua_status_SemanticsChanged, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        ti_inner = proto_tree_add_item(flags_tree, hf_opcua_status_InfoType, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);

        switch (uStatusCode & 0x00000C00)
        {
        case STATUSCODE_INFOTYPE_DATAVALUE:
        {
            /* InfoType == DataValue */
            proto_tree *tree_inner;

            tree_inner = proto_item_add_subtree(ti_inner, ett_opcua_statuscode_info);

            proto_tree_add_item(tree_inner, hf_opcua_status_Limit, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree_inner, hf_opcua_status_InfoBit_Limit_Overflow, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree_inner, hf_opcua_status_InfoBit_Historian_MultiValue, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree_inner, hf_opcua_status_InfoBit_Historian_ExtraData, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree_inner, hf_opcua_status_InfoBit_Historian_Partial, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
            proto_tree_add_item(tree_inner, hf_opcua_status_Historian, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        }
        default:
            break;
        }
    }

    *pOffset += 4;
    return item;
}

void parseLocalizedText(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName)
{
    gint        iOffset = *pOffset;
    guint8      EncodingMask;
    proto_tree *mask_tree;
    proto_tree *subtree;
    proto_item *ti;
    proto_item *ti_inner;

    ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: LocalizedText", szFieldName);
    subtree = proto_item_add_subtree(ti, ett_opcua_localizedtext);

    /* parse encoding mask */
    EncodingMask = tvb_get_guint8(tvb, iOffset);
    ti_inner = proto_tree_add_text(subtree, tvb, iOffset, 1, "EncodingMask");
    mask_tree = proto_item_add_subtree(ti_inner, ett_opcua_localizedtext_encodingmask);
    proto_tree_add_item(mask_tree, hf_opcua_loctext_mask_localeflag, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_loctext_mask_textflag,   tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    iOffset++;

    if (EncodingMask & LOCALIZEDTEXT_ENCODINGBYTE_LOCALE)
    {
        parseString(subtree, tvb, &iOffset, hf_opcua_localizedtext_locale);
    }

    if (EncodingMask & LOCALIZEDTEXT_ENCODINGBYTE_TEXT)
    {
        parseString(subtree, tvb, &iOffset, hf_opcua_localizedtext_text);
    }

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

proto_item* parseGuid(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, GUID_LEN, ENC_NA);
    *pOffset+=GUID_LEN;
    return item;
}

proto_item* parseByteString(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    char *szValue;
    int iOffset = *pOffset;
    gint32 iLen = tvb_get_letohl(tvb, iOffset);
    iOffset += 4;

    if (iLen == -1)
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 0, ENC_NA);
        proto_item_append_text(item, "[OpcUa Null ByteString]");
        proto_item_set_end(item, tvb, *pOffset + 4);
    }
    else if (iLen == 0)
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 0, ENC_NA);
        proto_item_append_text(item, "[OpcUa Empty ByteString]");
        proto_item_set_end(item, tvb, *pOffset + 4);
    }
    else if (iLen > 0)
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, iOffset, iLen, ENC_NA);
        iOffset += iLen; /* eat the whole bytestring */
    }
    else
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 0, ENC_NA);
        szValue = wmem_strdup_printf(wmem_packet_scope(), "[Invalid ByteString] Invalid length: %d", iLen);
        proto_item_append_text(item, "%s", szValue);
        proto_item_set_end(item, tvb, *pOffset + 4);
    }

    *pOffset = iOffset;
    return item;
}

proto_item* parseXmlElement(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    return parseByteString(tree, tvb, pOffset, hfIndex);
}

proto_item* parseFloat(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, (int)sizeof(gfloat), ENC_LITTLE_ENDIAN);
    *pOffset += (int)sizeof(gfloat);
    return item;
}

proto_item* parseDouble(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, (int)sizeof(gdouble), ENC_LITTLE_ENDIAN);
    *pOffset += (int)sizeof(gdouble);
    return item;
}

proto_item* parseDateTime(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    *pOffset = dissect_nt_64bit_time_ex(tvb, tree, *pOffset, hfIndex, &item);
    return item;
}

void parseDiagnosticInfo(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName)
{
    gint        iOffset = *pOffset;
    guint8      EncodingMask;
    proto_tree *mask_tree;
    proto_tree *subtree;
    proto_item *ti;
    proto_item *ti_inner;

    ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: DiagnosticInfo", szFieldName);
    subtree = proto_item_add_subtree(ti, ett_opcua_diagnosticinfo);

    /* parse encoding mask */
    EncodingMask = tvb_get_guint8(tvb, iOffset);
    ti_inner = proto_tree_add_text(subtree, tvb, iOffset, 1, "EncodingMask");
    mask_tree = proto_item_add_subtree(ti_inner, ett_opcua_diagnosticinfo_encodingmask);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_symbolicflag,        tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_namespaceflag,       tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_localizedtextflag,   tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_additionalinfoflag,  tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_innerstatuscodeflag, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_diag_mask_innerdiaginfoflag,   tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
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

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

void parseQualifiedName(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: QualifiedName", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_qualifiedname);

    parseUInt16(subtree, tvb, pOffset, hf_opcua_qualifiedname_id);
    parseString(subtree, tvb, pOffset, hf_opcua_qualifiedname_name);

    proto_item_set_end(ti, tvb, *pOffset);
}

void parseDataValue(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: DataValue", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_datavalue);
    proto_tree *mask_tree;
    gint    iOffset = *pOffset;
    guint8  EncodingMask;
    proto_item *ti_inner;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    ti_inner = proto_tree_add_text(subtree, tvb, iOffset, 1, "EncodingMask");
    mask_tree = proto_item_add_subtree(ti_inner, ett_opcua_datavalue_encodingmask);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_valueflag,           tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_statuscodeflag,      tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_sourcetimestampflag, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_servertimestampflag, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_sourcepicoseconds,   tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_datavalue_mask_serverpicoseconds,   tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
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
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SOURCEPICOSECONDS)
    {
        parseUInt16(subtree, tvb, &iOffset, hf_opcua_SourcePicoseconds);
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SERVERTIMESTAMP)
    {
        parseDateTime(subtree, tvb, &iOffset, hf_opcua_ServerTimestamp);
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SERVERPICOSECONDS)
    {
        parseUInt16(subtree, tvb, &iOffset, hf_opcua_ServerPicoseconds);
    }

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

void parseVariant(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: Variant", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_variant);
    gint    iOffset = *pOffset;
    guint8  EncodingMask;
    gint32  ArrayDimensions = 0;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    proto_tree_add_item(subtree, hf_opcua_variant_encodingmask, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    iOffset++;

    if (EncodingMask & VARIANT_ARRAYMASK)
    {
        /* type is encoded in bits 0-5 */
        switch(EncodingMask & 0x3f)
        {
        case OpcUaType_Null: break;
        case OpcUaType_Boolean: parseArraySimple(subtree, tvb, &iOffset, "Boolean", "Boolean", hf_opcua_Boolean, parseBoolean, ett_opcua_array_Boolean); break;
        case OpcUaType_SByte: parseArraySimple(subtree, tvb, &iOffset, "SByte", "SByte", hf_opcua_SByte, parseSByte, ett_opcua_array_SByte); break;
        case OpcUaType_Byte: parseArraySimple(subtree, tvb, &iOffset, "Byte", "Byte", hf_opcua_Byte, parseByte, ett_opcua_array_Byte); break;
        case OpcUaType_Int16: parseArraySimple(subtree, tvb, &iOffset, "Int16", "Int16", hf_opcua_Int16, parseInt16, ett_opcua_array_Int16); break;
        case OpcUaType_UInt16: parseArraySimple(subtree, tvb, &iOffset, "UInt16", "UInt16", hf_opcua_UInt16, parseUInt16, ett_opcua_array_UInt16); break;
        case OpcUaType_Int32: parseArraySimple(subtree, tvb, &iOffset, "Int32", "Int32", hf_opcua_Int32, parseInt32, ett_opcua_array_Int32); break;
        case OpcUaType_UInt32: parseArraySimple(subtree, tvb, &iOffset, "UInt32", "UInt32", hf_opcua_UInt32, parseUInt32, ett_opcua_array_UInt32); break;
        case OpcUaType_Int64: parseArraySimple(subtree, tvb, &iOffset, "Int64", "Int64", hf_opcua_Int64, parseInt64, ett_opcua_array_Int64); break;
        case OpcUaType_UInt64: parseArraySimple(subtree, tvb, &iOffset, "UInt64", "UInt64", hf_opcua_UInt64, parseUInt64, ett_opcua_array_UInt64); break;
        case OpcUaType_Float: parseArraySimple(subtree, tvb, &iOffset, "Float", "Float", hf_opcua_Float, parseFloat, ett_opcua_array_Float); break;
        case OpcUaType_Double: parseArraySimple(subtree, tvb, &iOffset, "Double", "Double", hf_opcua_Double, parseDouble, ett_opcua_array_Double); break;
        case OpcUaType_String: parseArraySimple(subtree, tvb, &iOffset, "String", "String", hf_opcua_String, parseString, ett_opcua_array_String); break;
        case OpcUaType_DateTime: parseArraySimple(subtree, tvb, &iOffset, "DateTime", "DateTime", hf_opcua_DateTime, parseDateTime, ett_opcua_array_DateTime); break;
        case OpcUaType_Guid: parseArraySimple(subtree, tvb, &iOffset, "Guid", "Guid", hf_opcua_Guid, parseGuid, ett_opcua_array_Guid); break;
        case OpcUaType_ByteString: parseArraySimple(subtree, tvb, &iOffset, "ByteString", "ByteString", hf_opcua_ByteString, parseByteString, ett_opcua_array_ByteString); break;
        case OpcUaType_XmlElement: parseArraySimple(subtree, tvb, &iOffset, "XmlElement", "XmlElement", hf_opcua_XmlElement, parseXmlElement, ett_opcua_array_XmlElement); break;
        case OpcUaType_NodeId: parseArrayComplex(subtree, tvb, &iOffset, "NodeId", "NodeId", parseNodeId, ett_opcua_array_NodeId); break;
        case OpcUaType_ExpandedNodeId: parseArrayComplex(subtree, tvb, &iOffset, "ExpandedNodeId", "ExpandedNodeId", parseExpandedNodeId, ett_opcua_array_ExpandedNodeId); break;
        case OpcUaType_StatusCode: parseArraySimple(subtree, tvb, &iOffset, "StatusCode", "StatusCode", hf_opcua_StatusCode, parseStatusCode, ett_opcua_array_StatusCode); break;
        case OpcUaType_DiagnosticInfo: parseArrayComplex(subtree, tvb, &iOffset, "DiagnosticInfo", "DiagnosticInfo", parseDiagnosticInfo, ett_opcua_array_DiagnosticInfo); break;
        case OpcUaType_QualifiedName: parseArrayComplex(subtree, tvb, &iOffset, "QualifiedName", "QualifiedName", parseQualifiedName, ett_opcua_array_QualifiedName); break;
        case OpcUaType_LocalizedText: parseArrayComplex(subtree, tvb, &iOffset, "LocalizedText", "LocalizedText", parseLocalizedText, ett_opcua_array_LocalizedText); break;
        case OpcUaType_ExtensionObject: parseArrayComplex(subtree, tvb, &iOffset, "ExtensionObject", "ExtensionObject", parseExtensionObject, ett_opcua_array_ExtensionObject); break;
        case OpcUaType_DataValue: parseArrayComplex(subtree, tvb, &iOffset, "DataValue", "DataValue", parseDataValue, ett_opcua_array_DataValue); break;
        case OpcUaType_Variant: parseArrayComplex(subtree, tvb, &iOffset, "Variant", "Variant", parseVariant, ett_opcua_array_Variant); break;
        }

        if (EncodingMask & VARIANT_ARRAYDIMENSIONS)
        {
            proto_item *ti_2 = proto_tree_add_text(subtree, tvb, iOffset, -1, "ArrayDimensions");
            proto_tree *subtree_2 = proto_item_add_subtree(ti_2, ett_opcua_variant_arraydims);
            int i;

            /* read array length */
            ArrayDimensions = tvb_get_letohl(tvb, iOffset);
            proto_tree_add_item(subtree_2, hf_opcua_ArraySize, tvb, iOffset, 4, ENC_LITTLE_ENDIAN);

            if (ArrayDimensions > MAX_ARRAY_LEN)
            {
                proto_item *pi;
                pi = proto_tree_add_text(subtree_2, tvb, iOffset, 4, "ArrayDimensions length %d too large to process", ArrayDimensions);
                PROTO_ITEM_SET_GENERATED(pi);
                return;
            }

            iOffset += 4;
            for (i=0; i<ArrayDimensions; i++)
            {
                parseInt32(subtree_2, tvb, &iOffset, hf_opcua_Int32);
            }
            proto_item_set_end(ti_2, tvb, iOffset);
        }
    }
    else
    {
        /* type is encoded in bits 0-5 */
        switch(EncodingMask & 0x3f)
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

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

/** General parsing function for arrays of simple types.
 * All arrays have one 4 byte signed integer length information,
 * followed by n data elements.
 */
void parseArraySimple(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName, const char *szTypeName, int hfIndex, fctSimpleTypeParser pParserFunction, const gint idx)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: Array of %s", szFieldName, szTypeName);
    proto_tree *subtree = proto_item_add_subtree(ti, idx);
    int i;
    gint32 iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);

    if (iLen > MAX_ARRAY_LEN)
    {
        proto_item *pi;
        pi = proto_tree_add_text(tree, tvb, *pOffset, 4, "Array length %d too large to process", iLen);
        PROTO_ITEM_SET_GENERATED(pi);
        return;
    }

    *pOffset += 4;
    for (i=0; i<iLen; i++)
    {
        proto_item *arrayItem = (*pParserFunction)(subtree, tvb, pOffset, hfIndex);
        if (arrayItem != NULL)
        {
            proto_item_prepend_text(arrayItem, "[%i]: ", i);
        }
    }
    proto_item_set_end(ti, tvb, *pOffset);
}

/** General parsing function for arrays of enums.
 * All arrays have one 4 byte signed integer length information,
 * followed by n data elements.
 */
void parseArrayEnum(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName, const char *szTypeName, fctEnumParser pParserFunction, const gint idx)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: Array of %s", szFieldName, szTypeName);
    proto_tree *subtree = proto_item_add_subtree(ti, idx);
    int i;
    gint32 iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);

    if (iLen > MAX_ARRAY_LEN)
    {
        proto_item *pi;
        pi = proto_tree_add_text(tree, tvb, *pOffset, 4, "Array length %d too large to process", iLen);
        PROTO_ITEM_SET_GENERATED(pi);
        return;
    }

    *pOffset += 4;
    for (i=0; i<iLen; i++)
    {
        (*pParserFunction)(subtree, tvb, pOffset);
    }
    proto_item_set_end(ti, tvb, *pOffset);
}

/** General parsing function for arrays of complex types.
 * All arrays have one 4 byte signed integer length information,
 * followed by n data elements.
 */
void parseArrayComplex(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName, const char *szTypeName, fctComplexTypeParser pParserFunction, const gint idx)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: Array of %s", szFieldName, szTypeName);
    proto_tree *subtree = proto_item_add_subtree(ti, idx);
    int i;
    gint32 iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);

    if (iLen > MAX_ARRAY_LEN)
    {
        proto_item *pi;
        pi = proto_tree_add_text(tree, tvb, *pOffset, 4, "Array length %d too large to process", iLen);
        PROTO_ITEM_SET_GENERATED(pi);
        return;
    }

    *pOffset += 4;
    for (i=0; i<iLen; i++)
    {
        char szNum[20];
        g_snprintf(szNum, 20, "[%i]", i);
        (*pParserFunction)(subtree, tvb, pOffset, szNum);
    }
    proto_item_set_end(ti, tvb, *pOffset);
}

void parseNodeId(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: NodeId", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_nodeid);
    gint    iOffset = *pOffset;
    guint8  EncodingMask;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    proto_tree_add_item(subtree, hf_opcua_nodeid_encodingmask, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    iOffset++;

    switch(EncodingMask)
    {
    case 0x00: /* two byte node id */
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
        iOffset+=1;
        break;
    case 0x01: /* four byte node id */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
        iOffset+=1;
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        break;
    case 0x02: /* numeric, that does not fit into four bytes */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 4, ENC_LITTLE_ENDIAN);
        iOffset+=4;
        break;
    case 0x03: /* string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseString(subtree, tvb, &iOffset, hf_opcua_nodeid_string);
        break;
    case 0x04: /* guid */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseGuid(subtree, tvb, &iOffset, hf_opcua_nodeid_guid);
        break;
    case 0x05: /* byte string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseByteString(subtree, tvb, &iOffset, hf_opcua_nodeid_bytestring);
        break;
    };

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

void parseExtensionObject(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName)
{
    gint    iOffset = *pOffset;
    guint8  EncodingMask;
    guint32 TypeId;
    proto_tree *extobj_tree;
    proto_tree *mask_tree;
    proto_item *ti;
    proto_item *ti_inner;

    /* add extension object subtree */
    ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: ExtensionObject", szFieldName);
    extobj_tree = proto_item_add_subtree(ti, ett_opcua_extensionobject);

    /* add nodeid subtree */
    TypeId = getExtensionObjectType(tvb, &iOffset);
    parseExpandedNodeId(extobj_tree, tvb, &iOffset, "TypeId");

    /* parse encoding mask */
    EncodingMask = tvb_get_guint8(tvb, iOffset);
    ti_inner = proto_tree_add_text(extobj_tree, tvb, iOffset, 1, "EncodingMask");
    mask_tree = proto_item_add_subtree(ti_inner, ett_opcua_extensionobject_encodingmask);
    proto_tree_add_item(mask_tree, hf_opcua_extobj_mask_binbodyflag, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(mask_tree, hf_opcua_extobj_mask_xmlbodyflag, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    iOffset++;

    if (EncodingMask & EXTOBJ_ENCODINGMASK_BINBODY_FLAG) /* has binary body ? */
    {
        dispatchExtensionObjectType(extobj_tree, tvb, &iOffset, TypeId);
    }

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

void parseExpandedNodeId(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName)
{
    proto_item *ti = proto_tree_add_text(tree, tvb, *pOffset, -1, "%s: ExpandedNodeId", szFieldName);
    proto_tree *subtree = proto_item_add_subtree(ti, ett_opcua_expandednodeid);
    gint    iOffset = *pOffset;
    guint8  EncodingMask;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    proto_tree_add_item(subtree, hf_opcua_nodeid_encodingmask, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_opcua_expandednodeid_mask_namespaceuri, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_opcua_expandednodeid_mask_serverindex, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    iOffset++;

    switch(EncodingMask & 0x0F)
    {
    case 0x00: /* two byte node id */
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
        iOffset+=1;
        break;
    case 0x01: /* four byte node id */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
        iOffset+=1;
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        break;
    case 0x02: /* numeric, that does not fit into four bytes */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        proto_tree_add_item(subtree, hf_opcua_nodeid_numeric, tvb, iOffset, 4, ENC_LITTLE_ENDIAN);
        iOffset+=4;
        break;
    case 0x03: /* string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseString(subtree, tvb, &iOffset, hf_opcua_nodeid_string);
        break;
    case 0x04: /* guid */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseGuid(subtree, tvb, &iOffset, hf_opcua_nodeid_guid);
        break;
    case 0x05: /* byte string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseByteString(subtree, tvb, &iOffset, hf_opcua_nodeid_bytestring);
        break;
    };

    if (EncodingMask & NODEID_NAMESPACEURIFLAG)
    {
        parseString(subtree, tvb, &iOffset, hf_opcua_NamespaceUri);
    }
    if (EncodingMask & NODEID_SERVERINDEXFLAG)
    {
        parseUInt32(subtree, tvb, &iOffset, hf_opcua_ServerIndex);
    }

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

guint32 getExtensionObjectType(tvbuff_t *tvb, gint *pOffset)
{
    gint    iOffset = *pOffset;
    guint8  EncodingMask;
    guint32 Numeric = 0;

    EncodingMask = tvb_get_guint8(tvb, iOffset);
    iOffset++;

    switch(EncodingMask)
    {
    case 0x00: /* two byte node id */
        Numeric = tvb_get_guint8(tvb, iOffset);
        /*iOffset+=1;*/
        break;
    case 0x01: /* four byte node id */
        iOffset+=1;
        Numeric = tvb_get_letohs(tvb, iOffset);
        break;
    case 0x02: /* numeric, that does not fit into four bytes */
        iOffset+=4;
        Numeric = tvb_get_letohl(tvb, iOffset);
        break;
    case 0x03: /* string */
    case 0x04: /* uri */
    case 0x05: /* guid */
    case 0x06: /* byte string */
        /* NOT USED */
        break;
    };

    return Numeric;
}
