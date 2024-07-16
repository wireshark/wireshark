/******************************************************************************
** Copyright (C) 2006-2007 ascolab GmbH. All Rights Reserved.
** Web: http://www.ascolab.com
**
** SPDX-License-Identifier: GPL-2.0-or-later
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
******************************************************************************/

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-windows-common.h>
#include <epan/dissectors/packet-x509af.h>
#include "opcua_simpletypes.h"
#include "opcua_hfindeces.h"
#include "opcua_statuscode.h"

#define DIAGNOSTICINFO_ENCODINGMASK_SYMBOLICID_FLAG           0x01
#define DIAGNOSTICINFO_ENCODINGMASK_NAMESPACE_FLAG            0x02
#define DIAGNOSTICINFO_ENCODINGMASK_LOCALIZEDTEXT_FLAG        0x04
#define DIAGNOSTICINFO_ENCODINGMASK_LOCALE_FLAG               0x08
#define DIAGNOSTICINFO_ENCODINGMASK_ADDITIONALINFO_FLAG       0x10
#define DIAGNOSTICINFO_ENCODINGMASK_INNERSTATUSCODE_FLAG      0x20
#define DIAGNOSTICINFO_ENCODINGMASK_INNERDIAGNOSTICINFO_FLAG  0x40
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
#define RETURNDIAGNOSTICS_SERVICELEVEL_SYMBOLICID             0x0001
#define RETURNDIAGNOSTICS_SERVICELEVEL_LOCALIZEDTEXT          0x0002
#define RETURNDIAGNOSTICS_SERVICELEVEL_ADDITIONALINFO         0x0004
#define RETURNDIAGNOSTICS_SERVICELEVEL_INNERSTATUSCODE        0x0008
#define RETURNDIAGNOSTICS_SERVICELEVEL_INNERDIAGNOSTICS       0x0010
#define RETURNDIAGNOSTICS_OPERATIONLEVEL_SYMBOLICID           0x0020
#define RETURNDIAGNOSTICS_OPERATIONLEVEL_LOCALIZEDTEXT        0x0040
#define RETURNDIAGNOSTICS_OPERATIONLEVEL_ADDITIONALINFO       0x0080
#define RETURNDIAGNOSTICS_OPERATIONLEVEL_INNERSTATUSCODE      0x0100
#define RETURNDIAGNOSTICS_OPERATIONLEVEL_INNERDIAGNOSTICS     0x0200
#define NODECLASSMASK_ALL                                     0x0000
#define NODECLASSMASK_OBJECT                                  0x0001
#define NODECLASSMASK_VARIABLE                                0x0002
#define NODECLASSMASK_METHOD                                  0x0004
#define NODECLASSMASK_OBJECTTYPE                              0x0008
#define NODECLASSMASK_VARIABLETYPE                            0x0010
#define NODECLASSMASK_REFERENCETYPE                           0x0020
#define NODECLASSMASK_DATATYPE                                0x0040
#define NODECLASSMASK_VIEW                                    0x0080
#define RESULTMASK_REFERENCETYPE                              0x0001
#define RESULTMASK_ISFORWARD                                  0x0002
#define RESULTMASK_NODECLASS                                  0x0004
#define RESULTMASK_BROWSENAME                                 0x0008
#define RESULTMASK_DISPLAYNAME                                0x0010
#define RESULTMASK_TYPEDEFINITION                             0x0020
#define RESULTMASK_ALL                                        0x003F


/* Chosen arbitrarily */
#define MAX_ARRAY_LEN 10000
#define MAX_NESTING_DEPTH 100

static int hf_opcua_diag_mask;
static int hf_opcua_diag_mask_symbolicflag;
static int hf_opcua_diag_mask_namespaceflag;
static int hf_opcua_diag_mask_localizedtextflag;
static int hf_opcua_diag_mask_localeflag;
static int hf_opcua_diag_mask_additionalinfoflag;
static int hf_opcua_diag_mask_innerstatuscodeflag;
static int hf_opcua_diag_mask_innerdiaginfoflag;
static int hf_opcua_loctext_mask;
static int hf_opcua_loctext_mask_localeflag;
static int hf_opcua_loctext_mask_textflag;
static int hf_opcua_datavalue_mask;
static int hf_opcua_datavalue_mask_valueflag;
static int hf_opcua_datavalue_mask_statuscodeflag;
static int hf_opcua_datavalue_mask_sourcetimestampflag;
static int hf_opcua_datavalue_mask_servertimestampflag;
static int hf_opcua_datavalue_mask_sourcepicoseconds;
static int hf_opcua_datavalue_mask_serverpicoseconds;
static int hf_opcua_nodeid_encodingmask;
static int hf_opcua_expandednodeid_mask;
static int hf_opcua_expandednodeid_mask_namespaceuri;
static int hf_opcua_expandednodeid_mask_serverindex;
static int hf_opcua_variant_encodingmask;
static int hf_opcua_nodeid_nsindex;
static int hf_opcua_nodeid_numeric;
static int hf_opcua_nodeid_string;
static int hf_opcua_nodeid_guid;
static int hf_opcua_nodeid_bytestring;
static int hf_opcua_localizedtext_locale;
static int hf_opcua_localizedtext_text;
static int hf_opcua_qualifiedname_id;
static int hf_opcua_qualifiedname_name;
static int hf_opcua_SourceTimestamp;
static int hf_opcua_SourcePicoseconds;
static int hf_opcua_ServerTimestamp;
static int hf_opcua_ServerPicoseconds;
static int hf_opcua_diag_symbolicid;
static int hf_opcua_diag_namespace;
static int hf_opcua_diag_localizedtext;
static int hf_opcua_diag_locale;
static int hf_opcua_diag_additionalinfo;
static int hf_opcua_diag_innerstatuscode;
static int hf_opcua_extobj_mask;
static int hf_opcua_extobj_mask_binbodyflag;
static int hf_opcua_extobj_mask_xmlbodyflag;
static int hf_opcua_ArraySize;
static int hf_opcua_ServerIndex;
static int hf_opcua_status_StructureChanged;
static int hf_opcua_status_SemanticsChanged;
static int hf_opcua_status_InfoBit_Limit_Overflow;
static int hf_opcua_status_InfoBit_Historian_Partial;
static int hf_opcua_status_InfoBit_Historian_ExtraData;
static int hf_opcua_status_InfoBit_Historian_MultiValue;
static int hf_opcua_status_InfoType;
static int hf_opcua_status_Limit;
static int hf_opcua_status_Historian;
int hf_opcua_returnDiag;
int hf_opcua_returnDiag_mask_sl_symbolicId;
int hf_opcua_returnDiag_mask_sl_localizedText;
int hf_opcua_returnDiag_mask_sl_additionalinfo;
int hf_opcua_returnDiag_mask_sl_innerstatuscode;
int hf_opcua_returnDiag_mask_sl_innerdiagnostics;
int hf_opcua_returnDiag_mask_ol_symbolicId;
int hf_opcua_returnDiag_mask_ol_localizedText;
int hf_opcua_returnDiag_mask_ol_additionalinfo;
int hf_opcua_returnDiag_mask_ol_innerstatuscode;
int hf_opcua_returnDiag_mask_ol_innerdiagnostics;
int hf_opcua_nodeClassMask;
int hf_opcua_nodeClassMask_all;
int hf_opcua_nodeClassMask_object;
int hf_opcua_nodeClassMask_variable;
int hf_opcua_nodeClassMask_method;
int hf_opcua_nodeClassMask_objecttype;
int hf_opcua_nodeClassMask_variabletype;
int hf_opcua_nodeClassMask_referencetype;
int hf_opcua_nodeClassMask_datatype;
int hf_opcua_nodeClassMask_view;
int hf_opcua_resultMask;
int hf_opcua_resultMask_all;
int hf_opcua_resultMask_referencetype;
int hf_opcua_resultMask_isforward;
int hf_opcua_resultMask_nodeclass;
int hf_opcua_resultMask_browsename;
int hf_opcua_resultMask_displayname;
int hf_opcua_resultMask_typedefinition;

static expert_field ei_array_length;
static expert_field ei_nesting_depth;

extern int proto_opcua;

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
    {  0, "Null" },
    {  1, "Boolean" },
    {  2, "SByte" },
    {  3, "Byte" },
    {  4, "Int16" },
    {  5, "UInt16" },
    {  6, "Int32" },
    {  7, "UInt32" },
    {  8, "Int64" },
    {  9, "UInt64" },
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

/** BrowseRequest's BrowseDescription's NodeClassMaskTable enum table */
static const value_string g_NodeClassMask[] = {
  { NODECLASSMASK_ALL, "All" },
  { 0, NULL }
};

/* BrowseRequest's BrowseDescription's ResultMaskTable enum table */
static const value_string g_ResultMask[] = {
  { RESULTMASK_ALL, "All" },
  { 0, NULL }
};

/* trees */
static int ett_opcua_diagnosticinfo;
static int ett_opcua_diagnosticinfo_encodingmask;
static int ett_opcua_nodeid;
static int ett_opcua_expandednodeid;
static int ett_opcua_expandednodeid_encodingmask;
static int ett_opcua_localizedtext;
static int ett_opcua_localizedtext_encodingmask;
static int ett_opcua_qualifiedname;
static int ett_opcua_datavalue;
static int ett_opcua_datavalue_encodingmask;
static int ett_opcua_variant;
static int ett_opcua_variant_arraydims;
static int ett_opcua_extensionobject;
static int ett_opcua_extensionobject_encodingmask;
static int ett_opcua_statuscode;
static int ett_opcua_statuscode_info;
int ett_opcua_array_Boolean;
int ett_opcua_array_SByte;
int ett_opcua_array_Byte;
int ett_opcua_array_Int16;
int ett_opcua_array_UInt16;
int ett_opcua_array_Int32;
int ett_opcua_array_UInt32;
int ett_opcua_array_Int64;
int ett_opcua_array_UInt64;
int ett_opcua_array_Float;
int ett_opcua_array_Double;
int ett_opcua_array_String;
int ett_opcua_array_DateTime;
int ett_opcua_array_Guid;
int ett_opcua_array_ByteString;
int ett_opcua_array_XmlElement;
int ett_opcua_array_NodeId;
int ett_opcua_array_ExpandedNodeId;
int ett_opcua_array_StatusCode;
int ett_opcua_array_DiagnosticInfo;
int ett_opcua_array_QualifiedName;
int ett_opcua_array_LocalizedText;
int ett_opcua_array_ExtensionObject;
int ett_opcua_array_DataValue;
int ett_opcua_array_Variant;
int ett_opcua_returnDiagnostics;
int ett_opcua_nodeClassMask;
int ett_opcua_resultMask;

static int *ett[] =
{
    &ett_opcua_diagnosticinfo,
    &ett_opcua_diagnosticinfo_encodingmask,
    &ett_opcua_nodeid,
    &ett_opcua_expandednodeid,
    &ett_opcua_expandednodeid_encodingmask,
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
    &ett_opcua_array_Variant,
    &ett_opcua_returnDiagnostics,
    &ett_opcua_nodeClassMask,
    &ett_opcua_resultMask
};

void registerSimpleTypes(int proto)
{
    expert_module_t* expert_proto;

    static hf_register_info hf[] =
    {
        /* id                                            full name                             abbreviation                                        type                display                 strings                    bitmask                                                 blurb HFILL */
        {&hf_opcua_diag_mask,                           {"EncodingMask",                       "opcua.diag.mask",                                  FT_UINT8,           BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_diag_mask_symbolicflag,              {"has symbolic id",                    "opcua.diag.has_symbolic_id",                       FT_BOOLEAN,         8,                      NULL,                      DIAGNOSTICINFO_ENCODINGMASK_SYMBOLICID_FLAG,            NULL, HFILL}},
        {&hf_opcua_diag_mask_namespaceflag,             {"has namespace",                      "opcua.diag.has_namespace",                         FT_BOOLEAN,         8,                      NULL,                      DIAGNOSTICINFO_ENCODINGMASK_NAMESPACE_FLAG,             NULL, HFILL}},
        {&hf_opcua_diag_mask_localizedtextflag,         {"has localizedtext",                  "opcua.diag.has_localizedtext",                     FT_BOOLEAN,         8,                      NULL,                      DIAGNOSTICINFO_ENCODINGMASK_LOCALIZEDTEXT_FLAG,         NULL, HFILL}},
        {&hf_opcua_diag_mask_localeflag,                {"has locale",                         "opcua.diag.has_locale",                            FT_BOOLEAN,         8,                      NULL,                      DIAGNOSTICINFO_ENCODINGMASK_LOCALE_FLAG,                NULL, HFILL}},
        {&hf_opcua_diag_mask_additionalinfoflag,        {"has additional info",                "opcua.diag.has_additional_info",                   FT_BOOLEAN,         8,                      NULL,                      DIAGNOSTICINFO_ENCODINGMASK_ADDITIONALINFO_FLAG,        NULL, HFILL}},
        {&hf_opcua_diag_mask_innerstatuscodeflag,       {"has inner statuscode",               "opcua.diag.has_inner_statuscode",                  FT_BOOLEAN,         8,                      NULL,                      DIAGNOSTICINFO_ENCODINGMASK_INNERSTATUSCODE_FLAG,       NULL, HFILL}},
        {&hf_opcua_diag_mask_innerdiaginfoflag,         {"has inner diagnostic info",          "opcua.diag.has_inner_diagnostic_code",             FT_BOOLEAN,         8,                      NULL,                      DIAGNOSTICINFO_ENCODINGMASK_INNERDIAGNOSTICINFO_FLAG,   NULL, HFILL}},
        {&hf_opcua_loctext_mask,                        {"EncodingMask",                       "opcua.loctext.mask",                               FT_UINT8,           BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_loctext_mask_localeflag,             {"has locale information",             "opcua.loctext.has_locale_information",             FT_BOOLEAN,         8,                      NULL,                      LOCALIZEDTEXT_ENCODINGBYTE_LOCALE,                      NULL, HFILL}},
        {&hf_opcua_loctext_mask_textflag,               {"has text",                           "opcua.loctext.has_text",                           FT_BOOLEAN,         8,                      NULL,                      LOCALIZEDTEXT_ENCODINGBYTE_TEXT,                        NULL, HFILL}},
        {&hf_opcua_nodeid_encodingmask,                 {"EncodingMask",                       "opcua.nodeid.encodingmask",                        FT_UINT8,           BASE_HEX,               VALS(g_nodeidmasks),       0x0F,                                                   NULL, HFILL}},
        {&hf_opcua_nodeid_nsindex,                      {"Namespace Index",                    "opcua.nodeid.nsindex",                             FT_UINT16,          BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_nodeid_numeric,                      {"Identifier Numeric",                 "opcua.nodeid.numeric",                             FT_UINT32,          BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_nodeid_string,                       {"Identifier String",                  "opcua.nodeid.string",                              FT_STRING,          BASE_NONE,              NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_nodeid_guid,                         {"Identifier Guid",                    "opcua.nodeid.guid",                                FT_GUID,            BASE_NONE,              NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_nodeid_bytestring,                   {"Identifier ByteString",              "opcua.nodeid.bytestring",                          FT_BYTES,           BASE_NONE,              NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_expandednodeid_mask,                 {"EncodingMask",                       "opcua.expandednodeid.mask",                        FT_UINT8,           BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_expandednodeid_mask_namespaceuri,    {"has namespace uri",                  "opcua.expandednodeid.has_namespace_uri",           FT_BOOLEAN,         8,                      NULL,                      NODEID_NAMESPACEURIFLAG,                                NULL, HFILL}},
        {&hf_opcua_expandednodeid_mask_serverindex,     {"has server index",                   "opcua.expandednodeid.has_server_index",            FT_BOOLEAN,         8,                      NULL,                      NODEID_SERVERINDEXFLAG,                                 NULL, HFILL}},
        {&hf_opcua_localizedtext_locale,                {"Locale",                             "opcua.loctext.Locale",                             FT_STRING,          BASE_NONE,              NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_localizedtext_text,                  {"Text",                               "opcua.loctext.Text",                               FT_STRING,          BASE_NONE,              NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_qualifiedname_id,                    {"Id",                                 "opcua.qualname.Id",                                FT_UINT16,          BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_qualifiedname_name,                  {"Name",                               "opcua.qualname.Name",                              FT_STRING,          BASE_NONE,              NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_datavalue_mask,                      {"EncodingMask",                       "opcua.datavalue.mask",                             FT_UINT8,           BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_datavalue_mask_valueflag,            {"has value",                          "opcua.datavalue.has_value",                        FT_BOOLEAN,         8,                      NULL,                      DATAVALUE_ENCODINGBYTE_VALUE,                           NULL, HFILL}},
        {&hf_opcua_datavalue_mask_statuscodeflag,       {"has statuscode",                     "opcua.datavalue.has_statuscode",                   FT_BOOLEAN,         8,                      NULL,                      DATAVALUE_ENCODINGBYTE_STATUSCODE,                      NULL, HFILL}},
        {&hf_opcua_datavalue_mask_sourcetimestampflag,  {"has source timestamp",               "opcua.datavalue.has_source_timestamp",             FT_BOOLEAN,         8,                      NULL,                      DATAVALUE_ENCODINGBYTE_SOURCETIMESTAMP,                 NULL, HFILL}},
        {&hf_opcua_datavalue_mask_servertimestampflag,  {"has server timestamp",               "opcua.datavalue.has_server_timestamp",             FT_BOOLEAN,         8,                      NULL,                      DATAVALUE_ENCODINGBYTE_SERVERTIMESTAMP,                 NULL, HFILL}},
        {&hf_opcua_datavalue_mask_sourcepicoseconds,    {"has source picoseconds",             "opcua.datavalue.has_source_picoseconds",           FT_BOOLEAN,         8,                      NULL,                      DATAVALUE_ENCODINGBYTE_SOURCEPICOSECONDS,               NULL, HFILL}},
        {&hf_opcua_datavalue_mask_serverpicoseconds,    {"has server picoseconds",             "opcua.datavalue.has_server_picoseconds",           FT_BOOLEAN,         8,                      NULL,                      DATAVALUE_ENCODINGBYTE_SERVERPICOSECONDS,               NULL, HFILL}},
        {&hf_opcua_variant_encodingmask,                {"Variant Type",                       "opcua.variant.has_value",                          FT_UINT8,           BASE_HEX,               VALS(g_VariantTypes),      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_SourceTimestamp,                     {"SourceTimestamp",                    "opcua.datavalue.SourceTimestamp",                  FT_ABSOLUTE_TIME,   ABSOLUTE_TIME_LOCAL,    NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_SourcePicoseconds,                   {"SourcePicoseconds",                  "opcua.datavalue.SourcePicoseconds",                FT_UINT16,          BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_ServerTimestamp,                     {"ServerTimestamp",                    "opcua.datavalue.ServerTimestamp",                  FT_ABSOLUTE_TIME,   ABSOLUTE_TIME_LOCAL,    NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_ServerPicoseconds,                   {"ServerPicoseconds",                  "opcua.datavalue.ServerPicoseconds",                FT_UINT16,          BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_diag_symbolicid,                     {"SymbolicId",                         "opcua.diag.SymbolicId",                            FT_INT32,           BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_diag_namespace,                      {"Namespace",                          "opcua.diag.Namespace",                             FT_INT32,           BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_diag_localizedtext,                  {"LocalizedText",                      "opcua.diag.LocalizedText",                         FT_INT32,           BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_diag_locale,                         {"Locale",                             "opcua.diag.Locale",                                FT_INT32,           BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_diag_additionalinfo,                 {"AdditionalInfo",                     "opcua.diag.AdditionalInfo",                        FT_STRING,          BASE_NONE,              NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_diag_innerstatuscode,                {"InnerStatusCode",                    "opcua.diag.InnerStatusCode",                       FT_UINT32,          BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_extobj_mask,                         {"EncodingMask",                       "opcua.extobj.mask",                                FT_UINT8,           BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_extobj_mask_binbodyflag,             {"has binary body",                    "opcua.extobj.has_binary_body",                     FT_BOOLEAN,         8,                      NULL,                      EXTOBJ_ENCODINGMASK_BINBODY_FLAG,                       NULL, HFILL}},
        {&hf_opcua_extobj_mask_xmlbodyflag,             {"has xml body",                       "opcua.extobj.has_xml_body",                        FT_BOOLEAN,         8,                      NULL,                      EXTOBJ_ENCODINGMASK_XMLBODY_FLAG,                       NULL, HFILL}},
        {&hf_opcua_ArraySize,                           {"ArraySize",                          "opcua.variant.ArraySize",                          FT_INT32,           BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_ServerIndex,                         {"ServerIndex",                        "opcua.expandednodeid.ServerIndex",                 FT_UINT32,          BASE_DEC,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_status_StructureChanged,             {"StructureChanged",                   "opcua.statuscode.structureChanged",                FT_BOOLEAN,         16,                     NULL,                      STATUSCODE_STRUCTURECHANGED,                            NULL, HFILL}},
        {&hf_opcua_status_SemanticsChanged,             {"SemanticsChanged",                   "opcua.statuscode.semanticsChanged",                FT_BOOLEAN,         16,                     NULL,                      STATUSCODE_SEMANTICSCHANGED,                            NULL, HFILL}},
        {&hf_opcua_status_InfoBit_Limit_Overflow,       {"Overflow",                           "opcua.statuscode.overflow",                        FT_BOOLEAN,         16,                     NULL,                      STATUSCODE_INFOBIT_OVERFLOW,                            NULL, HFILL}},
        {&hf_opcua_status_InfoBit_Historian_Partial,    {"HistorianBit: Partial",              "opcua.statuscode.historian.partial",               FT_BOOLEAN,         16,                     NULL,                      STATUSCODE_INFOBIT_HISTORIAN_PARTIAL,                   NULL, HFILL}},
        {&hf_opcua_status_InfoBit_Historian_ExtraData,  {"HistorianBit: ExtraData",            "opcua.statuscode.historian.extraData",             FT_BOOLEAN,         16,                     NULL,                      STATUSCODE_INFOBIT_HISTORIAN_EXTRADATA,                 NULL, HFILL}},
        {&hf_opcua_status_InfoBit_Historian_MultiValue, {"HistorianBit: MultiValue",           "opcua.statuscode.historian.multiValue",            FT_BOOLEAN,         16,                     NULL,                      STATUSCODE_INFOBIT_HISTORIAN_MULTIVALUE,                NULL, HFILL}},
        {&hf_opcua_status_InfoType,                     {"InfoType",                           "opcua.statuscode.infoType",                        FT_UINT16,          BASE_HEX,               VALS(g_infotype),          0x0C00,                                                 NULL, HFILL}},
        {&hf_opcua_status_Limit,                        {"Limit",                              "opcua.statuscode.limit",                           FT_UINT16,          BASE_HEX,               VALS(g_limit),             0x0300,                                                 NULL, HFILL}},
        {&hf_opcua_status_Historian,                    {"Historian",                          "opcua.statuscode.historian",                       FT_UINT16,          BASE_HEX,               VALS(g_historian),         0x0003,                                                 NULL, HFILL}},
        {&hf_opcua_returnDiag,                          {"Return Diagnostics",                 "opcua.returndiag",                                 FT_UINT32,          BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_sl_symbolicId,       {"ServiceLevel / SymbolicId",          "opcua.returndiag.servicelevel.symbolicid",         FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_SERVICELEVEL_SYMBOLICID,              NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_sl_localizedText,    {"ServiceLevel / LocalizedText",       "opcua.returndiag.servicelevel.localizedtext",      FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_SERVICELEVEL_LOCALIZEDTEXT,           NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_sl_additionalinfo,   {"ServiceLevel / AdditionalInfo",      "opcua.returndiag.servicelevel.additionalinfo",     FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_SERVICELEVEL_ADDITIONALINFO,          NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_sl_innerstatuscode,  {"ServiceLevel / Inner StatusCode",    "opcua.returndiag.servicelevel.innerstatuscode",    FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_SERVICELEVEL_INNERSTATUSCODE,         NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_sl_innerdiagnostics, {"ServiceLevel / Inner Diagnostics",   "opcua.returndiag.servicelevel.innerdiagnostics",   FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_SERVICELEVEL_INNERDIAGNOSTICS,        NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_ol_symbolicId,       {"OperationLevel / SymbolicId",        "opcua.returndiag.operationlevel.symbolicid",       FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_OPERATIONLEVEL_SYMBOLICID,            NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_ol_localizedText,    {"OperationLevel / LocalizedText",     "opcua.returndiag.operationlevel.localizedtext",    FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_OPERATIONLEVEL_LOCALIZEDTEXT,         NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_ol_additionalinfo,   {"OperationLevel / AdditionalInfo",    "opcua.returndiag.operationlevel.additionalinfo",   FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_OPERATIONLEVEL_ADDITIONALINFO,        NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_ol_innerstatuscode,  {"OperationLevel / Inner StatusCode",  "opcua.returndiag.operationlevel.innerstatuscode",  FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_OPERATIONLEVEL_INNERSTATUSCODE,       NULL, HFILL}},
        {&hf_opcua_returnDiag_mask_ol_innerdiagnostics, {"OperationLevel / Inner Diagnostics", "opcua.returndiag.operationlevel.innerdiagnostics", FT_BOOLEAN,         16,                     NULL,                      RETURNDIAGNOSTICS_OPERATIONLEVEL_INNERDIAGNOSTICS,      NULL, HFILL}},
        {&hf_opcua_nodeClassMask,                       {"Node Class Mask",                    "opcua.nodeclassmask",                              FT_UINT32,          BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_nodeClassMask_all,                   {"Node Class Mask",                    "opcua.nodeclassmask.all",                          FT_UINT32,          BASE_HEX,               VALS(g_NodeClassMask),     0x0,                                                    NULL, HFILL}},
        {&hf_opcua_nodeClassMask_object,                {"Object",                             "opcua.nodeclassmask.object",                       FT_BOOLEAN,         16,                     NULL,                      NODECLASSMASK_OBJECT,                                   NULL, HFILL}},
        {&hf_opcua_nodeClassMask_variable,              {"Variable",                           "opcua.nodeclassmask.variable",                     FT_BOOLEAN,         16,                     NULL,                      NODECLASSMASK_VARIABLE,                                 NULL, HFILL}},
        {&hf_opcua_nodeClassMask_method,                {"Method",                             "opcua.nodeclassmask.method",                       FT_BOOLEAN,         16,                     NULL,                      NODECLASSMASK_METHOD,                                   NULL, HFILL}},
        {&hf_opcua_nodeClassMask_objecttype,            {"ObjectType",                         "opcua.nodeclassmask.objecttype",                   FT_BOOLEAN,         16,                     NULL,                      NODECLASSMASK_OBJECTTYPE,                               NULL, HFILL}},
        {&hf_opcua_nodeClassMask_variabletype,          {"VariableType",                       "opcua.nodeclassmask.variabletype",                 FT_BOOLEAN,         16,                     NULL,                      NODECLASSMASK_VARIABLETYPE,                             NULL, HFILL}},
        {&hf_opcua_nodeClassMask_referencetype,         {"ReferenceType",                      "opcua.nodeclassmask.referencetype",                FT_BOOLEAN,         16,                     NULL,                      NODECLASSMASK_REFERENCETYPE,                            NULL, HFILL}},
        {&hf_opcua_nodeClassMask_datatype,              {"DataType",                           "opcua.nodeclassmask.datatype",                     FT_BOOLEAN,         16,                     NULL,                      NODECLASSMASK_DATATYPE,                                 NULL, HFILL}},
        {&hf_opcua_nodeClassMask_view,                  {"View",                               "opcua.nodeclassmask.view",                         FT_BOOLEAN,         16,                     NULL,                      NODECLASSMASK_VIEW,                                     NULL, HFILL}},
        {&hf_opcua_resultMask,                          {"Result Mask",                        "opcua.resultmask",                                 FT_UINT32,          BASE_HEX,               NULL,                      0x0,                                                    NULL, HFILL}},
        {&hf_opcua_resultMask_referencetype,            {"Reference Type",                     "opcua.resultmask.referencetype",                   FT_BOOLEAN,         16,                     NULL,                      RESULTMASK_REFERENCETYPE,                               NULL, HFILL}},
        {&hf_opcua_resultMask_isforward,                {"Is Forward",                         "opcua.resultmask.isforward",                       FT_BOOLEAN,         16,                     NULL,                      RESULTMASK_ISFORWARD,                                   NULL, HFILL}},
        {&hf_opcua_resultMask_nodeclass,                {"Node Class",                         "opcua.resultmask.nodeclass",                       FT_BOOLEAN,         16,                     NULL,                      RESULTMASK_NODECLASS,                                   NULL, HFILL}},
        {&hf_opcua_resultMask_browsename,               {"Browse Name",                        "opcua.resultmask.browsename",                      FT_BOOLEAN,         16,                     NULL,                      RESULTMASK_BROWSENAME,                                  NULL, HFILL}},
        {&hf_opcua_resultMask_displayname,              {"Display Name",                       "opcua.resultmask.displayname",                     FT_BOOLEAN,         16,                     NULL,                      RESULTMASK_DISPLAYNAME,                                 NULL, HFILL}},
        {&hf_opcua_resultMask_typedefinition,           {"Type Definition",                    "opcua.resultmask.typedefinition",                  FT_BOOLEAN,         16,                     NULL,                      RESULTMASK_TYPEDEFINITION,                              NULL, HFILL}},
        {&hf_opcua_resultMask_all,                      {"Result Mask",                        "opcua.resultmask.all",                             FT_UINT32,          BASE_HEX,               VALS(g_ResultMask),        0x0,                                                    NULL, HFILL}},
    };

    static ei_register_info ei[] = {
        { &ei_array_length, { "opcua.array.length", PI_UNDECODED, PI_ERROR, "Max array length exceeded", EXPFILL }},
        { &ei_nesting_depth, { "opcua.nestingdepth", PI_UNDECODED, PI_ERROR, "Max nesting depth exceeded", EXPFILL }},
    };

    proto_register_field_array(proto, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_proto = expert_register_protocol(proto);
    expert_register_field_array(expert_proto, ei, array_length(ei));
}

proto_item* parseBoolean(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, ENC_LITTLE_ENDIAN);
    *pOffset+=1;
    return item;
}

proto_item* parseByte(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, ENC_LITTLE_ENDIAN);
    *pOffset+=1;
    return item;
}

proto_item* parseSByte(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 1, ENC_LITTLE_ENDIAN);
    *pOffset+=1;
    return item;
}

proto_item* parseUInt16(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 2, ENC_LITTLE_ENDIAN);
    *pOffset+=2;
    return item;
}

proto_item* parseInt16(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 2, ENC_LITTLE_ENDIAN);
    *pOffset+=2;
    return item;
}

proto_item* parseUInt32(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);
    *pOffset+=4;
    return item;
}

proto_item* parseInt32(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);
    *pOffset+=4;
    return item;
}

proto_item* parseUInt64(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 8, ENC_LITTLE_ENDIAN);
    *pOffset+=8;
    return item;
}

proto_item* parseInt64(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 8, ENC_LITTLE_ENDIAN);
    *pOffset+=8;
    return item;
}

proto_item* parseString(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    char *szValue;
    int iOffset = *pOffset;
    int32_t iLen = tvb_get_letohl(tvb, *pOffset);
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
        szValue = wmem_strdup_printf(pinfo->pool, "[Invalid String] Invalid length: %d", iLen);
        proto_item_append_text(item, "%s", szValue);
        proto_item_set_end(item, tvb, *pOffset + 4);
    }

    *pOffset = iOffset;
    return item;
}

proto_item* parseString_ret_string_and_length(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex, const uint8_t **retval, int *lenretval)
{
    proto_item *item = NULL;
    char *szValue;
    int iOffset = *pOffset;
    int32_t iLen = tvb_get_letohl(tvb, *pOffset);
    iOffset+=4;

    if (retval) {
        *retval = "";
    }
    if (lenretval) {
        *lenretval = iLen;
    }

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
        item = proto_tree_add_item_ret_string_and_length(tree, hfIndex, tvb, iOffset, iLen, ENC_UTF_8|ENC_NA, NULL, retval, lenretval);
        iOffset += iLen; /* eat the whole string */
    }
    else
    {
        item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 0, ENC_NA);
        szValue = wmem_strdup_printf(pinfo->pool, "[Invalid String] Invalid length: %d", iLen);
        proto_item_append_text(item, "%s", szValue);
        proto_item_set_end(item, tvb, *pOffset + 4);
    }

    *pOffset = iOffset;
    return item;
}

proto_item* parseStatusCode(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    uint32_t uStatusCode = 0;
    const char *szStatusCode = NULL;

    item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);

    uStatusCode = tvb_get_letohl(tvb, *pOffset);
    szStatusCode = val_to_str_const(uStatusCode & 0xFFFF0000, g_statusCodes, "Unknown Status Code");
    proto_item_append_text(item, " [%s]", szStatusCode);

    /* check for status code info flags */
    if (uStatusCode & 0x0000FFFF)
    {
        int iOffset = *pOffset;
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

void parseLocalizedText(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName)
{
    static int * const loctext_mask[] = {&hf_opcua_loctext_mask_localeflag,
                                        &hf_opcua_loctext_mask_textflag,
                                        NULL};

    int         iOffset = *pOffset;
    uint8_t     EncodingMask;
    proto_tree *subtree;
    proto_item *ti;

    subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1, ett_opcua_localizedtext, &ti, "%s: LocalizedText", szFieldName);

    /* parse encoding mask */
    EncodingMask = tvb_get_uint8(tvb, iOffset);
    proto_tree_add_bitmask(subtree, tvb, iOffset, hf_opcua_loctext_mask, ett_opcua_localizedtext_encodingmask, loctext_mask, ENC_LITTLE_ENDIAN);
    iOffset++;

    if (EncodingMask & LOCALIZEDTEXT_ENCODINGBYTE_LOCALE)
    {
        parseString(subtree, tvb, pinfo, &iOffset, hf_opcua_localizedtext_locale);
    }

    if (EncodingMask & LOCALIZEDTEXT_ENCODINGBYTE_TEXT)
    {
        parseString(subtree, tvb, pinfo, &iOffset, hf_opcua_localizedtext_text);
    }

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

proto_item* parseGuid(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, GUID_LEN, ENC_LITTLE_ENDIAN);
    *pOffset+=GUID_LEN;
    return item;
}

proto_item* parseByteString(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    char *szValue;
    int iOffset = *pOffset;
    int32_t iLen = tvb_get_letohl(tvb, iOffset);
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
        szValue = wmem_strdup_printf(pinfo->pool, "[Invalid ByteString] Invalid length: %d", iLen);
        proto_item_append_text(item, "%s", szValue);
        proto_item_set_end(item, tvb, *pOffset + 4);
    }

    *pOffset = iOffset;
    return item;
}

proto_item* parseXmlElement(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex)
{
    return parseByteString(tree, tvb, pinfo, pOffset, hfIndex);
}

proto_item* parseFloat(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, (int)sizeof(float), ENC_LITTLE_ENDIAN);
    *pOffset += (int)sizeof(float);
    return item;
}

proto_item* parseDouble(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = proto_tree_add_item(tree, hfIndex, tvb, *pOffset, (int)sizeof(double), ENC_LITTLE_ENDIAN);
    *pOffset += (int)sizeof(double);
    return item;
}

proto_item* parseDateTime(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    *pOffset = dissect_nt_64bit_time_ex(tvb, tree, *pOffset, hfIndex, &item, false);
    return item;
}

// NOLINTNEXTLINE(misc-no-recursion)
void parseDiagnosticInfo(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName)
{
    static int * const diag_mask[] = {&hf_opcua_diag_mask_symbolicflag,
                                     &hf_opcua_diag_mask_namespaceflag,
                                     &hf_opcua_diag_mask_localizedtextflag,
                                     &hf_opcua_diag_mask_localeflag,
                                     &hf_opcua_diag_mask_additionalinfoflag,
                                     &hf_opcua_diag_mask_innerstatuscodeflag,
                                     &hf_opcua_diag_mask_innerdiaginfoflag,
                                     NULL};

    int         iOffset = *pOffset;
    uint8_t     EncodingMask;
    proto_tree *subtree;
    proto_item *ti;
    unsigned    opcua_nested_count;

    subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1, ett_opcua_diagnosticinfo, &ti, "%s: DiagnosticInfo", szFieldName);

    /* prevent a too high nesting depth */
    opcua_nested_count = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_opcua, 0));
    if (opcua_nested_count >= MAX_NESTING_DEPTH)
    {
        expert_add_info(pinfo, ti, &ei_nesting_depth);
        return;
    }
    opcua_nested_count++;
    p_add_proto_data(pinfo->pool, pinfo, proto_opcua, 0, GUINT_TO_POINTER(opcua_nested_count));

    /* parse encoding mask */
    EncodingMask = tvb_get_uint8(tvb, iOffset);
    proto_tree_add_bitmask(subtree, tvb, iOffset, hf_opcua_diag_mask, ett_opcua_diagnosticinfo_encodingmask, diag_mask, ENC_LITTLE_ENDIAN);
    iOffset++;

    increment_dissection_depth(pinfo);
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_SYMBOLICID_FLAG)
    {
        parseInt32(subtree, tvb, pinfo, &iOffset, hf_opcua_diag_symbolicid);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_NAMESPACE_FLAG)
    {
        parseInt32(subtree, tvb, pinfo, &iOffset, hf_opcua_diag_namespace);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_LOCALE_FLAG)
    {
        parseInt32(subtree, tvb, pinfo, &iOffset, hf_opcua_diag_locale);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_LOCALIZEDTEXT_FLAG)
    {
        parseInt32(subtree, tvb, pinfo, &iOffset, hf_opcua_diag_localizedtext);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_ADDITIONALINFO_FLAG)
    {
        parseString(subtree, tvb, pinfo, &iOffset, hf_opcua_diag_additionalinfo);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_INNERSTATUSCODE_FLAG)
    {
        parseStatusCode(subtree, tvb, pinfo, &iOffset, hf_opcua_diag_innerstatuscode);
    }
    if (EncodingMask & DIAGNOSTICINFO_ENCODINGMASK_INNERDIAGNOSTICINFO_FLAG)
    {
        parseDiagnosticInfo(subtree, tvb, pinfo, &iOffset, "Inner DiagnosticInfo");
    }
    decrement_dissection_depth(pinfo);

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;

    opcua_nested_count--;
    p_add_proto_data(pinfo->pool, pinfo, proto_opcua, 0, GUINT_TO_POINTER(opcua_nested_count));
}

void parseQualifiedName(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName)
{
    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1,
                    ett_opcua_qualifiedname, &ti, "%s: QualifiedName", szFieldName);

    parseUInt16(subtree, tvb, pinfo, pOffset, hf_opcua_qualifiedname_id);
    parseString(subtree, tvb, pinfo, pOffset, hf_opcua_qualifiedname_name);

    proto_item_set_end(ti, tvb, *pOffset);
}

void parseCertificate(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, int hfIndex)
{
    proto_item *item = NULL;
    char *szValue;
    int iOffset = *pOffset;
    int32_t iLen = tvb_get_letohl(tvb, iOffset);
    iOffset += 4;

    if (iLen == -1)
    {
        item = proto_tree_add_bytes_with_length(tree, hfIndex, tvb, *pOffset, 4, NULL, 0);
        proto_item_append_text(item, "[OpcUa Null ByteString]");
    }
    else if (iLen == 0)
    {
        item = proto_tree_add_bytes_with_length(tree, hfIndex, tvb, *pOffset, 4, NULL, 0);
        proto_item_append_text(item, "[OpcUa Empty ByteString]");
    }
    else if (iLen > 0)
    {
        asn1_ctx_t asn1_ctx;
        asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, true, pinfo);
        dissect_x509af_Certificate(false, tvb, iOffset, &asn1_ctx, tree, hfIndex);
        iOffset += iLen; /* eat the whole bytestring */
    }
    else
    {
        item = proto_tree_add_bytes_with_length(tree, hfIndex, tvb, *pOffset, 4, NULL, 0);
        szValue = wmem_strdup_printf(pinfo->pool, "[Invalid ByteString] Invalid length: %d", iLen);
        proto_item_append_text(item, "%s", szValue);
    }

    *pOffset = iOffset;
}

// NOLINTNEXTLINE(misc-no-recursion)
void parseDataValue(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName)
{
    static int * const datavalue_mask[] = {&hf_opcua_datavalue_mask_valueflag,
                                          &hf_opcua_datavalue_mask_statuscodeflag,
                                          &hf_opcua_datavalue_mask_sourcetimestampflag,
                                          &hf_opcua_datavalue_mask_servertimestampflag,
                                          &hf_opcua_datavalue_mask_sourcepicoseconds,
                                          &hf_opcua_datavalue_mask_serverpicoseconds,
                                          NULL};

    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1,
                        ett_opcua_datavalue, &ti, "%s: DataValue", szFieldName);
    int     iOffset = *pOffset;
    uint8_t EncodingMask;

    EncodingMask = tvb_get_uint8(tvb, iOffset);
    proto_tree_add_bitmask(subtree, tvb, iOffset, hf_opcua_datavalue_mask, ett_opcua_datavalue_encodingmask, datavalue_mask, ENC_LITTLE_ENDIAN);
    iOffset++;

    increment_dissection_depth(pinfo);
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_VALUE)
    {
        parseVariant(subtree, tvb, pinfo, &iOffset, "Value");
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_STATUSCODE)
    {
        parseStatusCode(subtree, tvb, pinfo, &iOffset, hf_opcua_StatusCode);
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SOURCETIMESTAMP)
    {
        parseDateTime(subtree, tvb, pinfo, &iOffset, hf_opcua_SourceTimestamp);
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SOURCEPICOSECONDS)
    {
        parseUInt16(subtree, tvb, pinfo, &iOffset, hf_opcua_SourcePicoseconds);
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SERVERTIMESTAMP)
    {
        parseDateTime(subtree, tvb, pinfo, &iOffset, hf_opcua_ServerTimestamp);
    }
    if (EncodingMask & DATAVALUE_ENCODINGBYTE_SERVERPICOSECONDS)
    {
        parseUInt16(subtree, tvb, pinfo, &iOffset, hf_opcua_ServerPicoseconds);
    }
    decrement_dissection_depth(pinfo);

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

// NOLINTNEXTLINE(misc-no-recursion)
void parseVariant(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName)
{
    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1,
                            ett_opcua_variant, &ti, "%s: Variant", szFieldName);
    int     iOffset = *pOffset;
    uint8_t EncodingMask;
    int32_t ArrayDimensions = 0;
    unsigned   opcua_nested_count;

    /* prevent a too high nesting depth */
    opcua_nested_count = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_opcua, 0));
    if (opcua_nested_count >= MAX_NESTING_DEPTH)
    {
        expert_add_info(pinfo, ti, &ei_nesting_depth);
        return;
    }
    opcua_nested_count++;
    p_add_proto_data(pinfo->pool, pinfo, proto_opcua, 0, GUINT_TO_POINTER(opcua_nested_count));

    EncodingMask = tvb_get_uint8(tvb, iOffset);
    proto_tree_add_item(subtree, hf_opcua_variant_encodingmask, tvb, iOffset, 1, ENC_LITTLE_ENDIAN);
    iOffset++;

    if (EncodingMask & VARIANT_ARRAYMASK)
    {
        /* type is encoded in bits 0-5 */
        increment_dissection_depth(pinfo);
        switch(EncodingMask & 0x3f)
        {
        case OpcUaType_Null: break;
        case OpcUaType_Boolean: parseArraySimple(subtree, tvb, pinfo, &iOffset, "Boolean", "Boolean", hf_opcua_Boolean, parseBoolean, ett_opcua_array_Boolean); break;
        case OpcUaType_SByte: parseArraySimple(subtree, tvb, pinfo, &iOffset, "SByte", "SByte", hf_opcua_SByte, parseSByte, ett_opcua_array_SByte); break;
        case OpcUaType_Byte: parseArraySimple(subtree, tvb, pinfo, &iOffset, "Byte", "Byte", hf_opcua_Byte, parseByte, ett_opcua_array_Byte); break;
        case OpcUaType_Int16: parseArraySimple(subtree, tvb, pinfo, &iOffset, "Int16", "Int16", hf_opcua_Int16, parseInt16, ett_opcua_array_Int16); break;
        case OpcUaType_UInt16: parseArraySimple(subtree, tvb, pinfo, &iOffset, "UInt16", "UInt16", hf_opcua_UInt16, parseUInt16, ett_opcua_array_UInt16); break;
        case OpcUaType_Int32: parseArraySimple(subtree, tvb, pinfo, &iOffset, "Int32", "Int32", hf_opcua_Int32, parseInt32, ett_opcua_array_Int32); break;
        case OpcUaType_UInt32: parseArraySimple(subtree, tvb, pinfo, &iOffset, "UInt32", "UInt32", hf_opcua_UInt32, parseUInt32, ett_opcua_array_UInt32); break;
        case OpcUaType_Int64: parseArraySimple(subtree, tvb, pinfo, &iOffset, "Int64", "Int64", hf_opcua_Int64, parseInt64, ett_opcua_array_Int64); break;
        case OpcUaType_UInt64: parseArraySimple(subtree, tvb, pinfo, &iOffset, "UInt64", "UInt64", hf_opcua_UInt64, parseUInt64, ett_opcua_array_UInt64); break;
        case OpcUaType_Float: parseArraySimple(subtree, tvb, pinfo, &iOffset, "Float", "Float", hf_opcua_Float, parseFloat, ett_opcua_array_Float); break;
        case OpcUaType_Double: parseArraySimple(subtree, tvb, pinfo, &iOffset, "Double", "Double", hf_opcua_Double, parseDouble, ett_opcua_array_Double); break;
        case OpcUaType_String: parseArraySimple(subtree, tvb, pinfo, &iOffset, "String", "String", hf_opcua_String, parseString, ett_opcua_array_String); break;
        case OpcUaType_DateTime: parseArraySimple(subtree, tvb, pinfo, &iOffset, "DateTime", "DateTime", hf_opcua_DateTime, parseDateTime, ett_opcua_array_DateTime); break;
        case OpcUaType_Guid: parseArraySimple(subtree, tvb, pinfo, &iOffset, "Guid", "Guid", hf_opcua_Guid, parseGuid, ett_opcua_array_Guid); break;
        case OpcUaType_ByteString: parseArraySimple(subtree, tvb, pinfo, &iOffset, "ByteString", "ByteString", hf_opcua_ByteString, parseByteString, ett_opcua_array_ByteString); break;
        case OpcUaType_XmlElement: parseArraySimple(subtree, tvb, pinfo, &iOffset, "XmlElement", "XmlElement", hf_opcua_XmlElement, parseXmlElement, ett_opcua_array_XmlElement); break;
        case OpcUaType_NodeId: parseArrayComplex(subtree, tvb, pinfo, &iOffset, "NodeId", "NodeId", parseNodeId, ett_opcua_array_NodeId); break;
        case OpcUaType_ExpandedNodeId: parseArrayComplex(subtree, tvb, pinfo, &iOffset, "ExpandedNodeId", "ExpandedNodeId", parseExpandedNodeId, ett_opcua_array_ExpandedNodeId); break;
        case OpcUaType_StatusCode: parseArraySimple(subtree, tvb, pinfo, &iOffset, "StatusCode", "StatusCode", hf_opcua_StatusCode, parseStatusCode, ett_opcua_array_StatusCode); break;
        case OpcUaType_DiagnosticInfo: parseArrayComplex(subtree, tvb, pinfo, &iOffset, "DiagnosticInfo", "DiagnosticInfo", parseDiagnosticInfo, ett_opcua_array_DiagnosticInfo); break;
        case OpcUaType_QualifiedName: parseArrayComplex(subtree, tvb, pinfo, &iOffset, "QualifiedName", "QualifiedName", parseQualifiedName, ett_opcua_array_QualifiedName); break;
        case OpcUaType_LocalizedText: parseArrayComplex(subtree, tvb, pinfo, &iOffset, "LocalizedText", "LocalizedText", parseLocalizedText, ett_opcua_array_LocalizedText); break;
        case OpcUaType_ExtensionObject: parseArrayComplex(subtree, tvb, pinfo, &iOffset, "ExtensionObject", "ExtensionObject", parseExtensionObject, ett_opcua_array_ExtensionObject); break;
        case OpcUaType_DataValue: parseArrayComplex(subtree, tvb, pinfo, &iOffset, "DataValue", "DataValue", parseDataValue, ett_opcua_array_DataValue); break;
        case OpcUaType_Variant: parseArrayComplex(subtree, tvb, pinfo, &iOffset, "Variant", "Variant", parseVariant, ett_opcua_array_Variant); break;
        }
        decrement_dissection_depth(pinfo);

        if (EncodingMask & VARIANT_ARRAYDIMENSIONS)
        {
            proto_item *ti_2;
            proto_tree *subtree_2 = proto_tree_add_subtree(subtree, tvb, iOffset, -1,
                                ett_opcua_variant_arraydims, &ti_2, "ArrayDimensions");
            int i;

            /* read array length */
            ArrayDimensions = tvb_get_letohl(tvb, iOffset);
            proto_tree_add_item(subtree_2, hf_opcua_ArraySize, tvb, iOffset, 4, ENC_LITTLE_ENDIAN);

            if (ArrayDimensions > MAX_ARRAY_LEN)
            {
                proto_tree_add_expert_format(subtree_2, pinfo, &ei_array_length, tvb, iOffset, 4, "ArrayDimensions length %d too large to process", ArrayDimensions);
                return;
            }

            iOffset += 4;
            for (i=0; i<ArrayDimensions; i++)
            {
                parseInt32(subtree_2, tvb, pinfo, &iOffset, hf_opcua_Int32);
            }
            proto_item_set_end(ti_2, tvb, iOffset);
        }
    }
    else
    {
        /* type is encoded in bits 0-5 */
        increment_dissection_depth(pinfo);
        switch(EncodingMask & 0x3f)
        {
        case OpcUaType_Null: break;
        case OpcUaType_Boolean: parseBoolean(subtree, tvb, pinfo, &iOffset, hf_opcua_Boolean); break;
        case OpcUaType_SByte: parseSByte(subtree, tvb, pinfo, &iOffset, hf_opcua_SByte); break;
        case OpcUaType_Byte: parseByte(subtree, tvb, pinfo, &iOffset, hf_opcua_Byte); break;
        case OpcUaType_Int16: parseInt16(subtree, tvb, pinfo, &iOffset, hf_opcua_Int16); break;
        case OpcUaType_UInt16: parseUInt16(subtree, tvb, pinfo, &iOffset, hf_opcua_UInt16); break;
        case OpcUaType_Int32: parseInt32(subtree, tvb, pinfo, &iOffset, hf_opcua_Int32); break;
        case OpcUaType_UInt32: parseUInt32(subtree, tvb, pinfo, &iOffset, hf_opcua_UInt32); break;
        case OpcUaType_Int64: parseInt64(subtree, tvb, pinfo, &iOffset, hf_opcua_Int64); break;
        case OpcUaType_UInt64: parseUInt64(subtree, tvb, pinfo, &iOffset, hf_opcua_UInt64); break;
        case OpcUaType_Float: parseFloat(subtree, tvb, pinfo, &iOffset, hf_opcua_Float); break;
        case OpcUaType_Double: parseDouble(subtree, tvb, pinfo, &iOffset, hf_opcua_Double); break;
        case OpcUaType_String: parseString(subtree, tvb, pinfo, &iOffset, hf_opcua_String); break;
        case OpcUaType_DateTime: parseDateTime(subtree, tvb, pinfo, &iOffset, hf_opcua_DateTime); break;
        case OpcUaType_Guid: parseGuid(subtree, tvb, pinfo, &iOffset, hf_opcua_Guid); break;
        case OpcUaType_ByteString: parseByteString(subtree, tvb, pinfo, &iOffset, hf_opcua_ByteString); break;
        case OpcUaType_XmlElement: parseXmlElement(subtree, tvb, pinfo, &iOffset, hf_opcua_XmlElement); break;
        case OpcUaType_NodeId: parseNodeId(subtree, tvb, pinfo, &iOffset, "Value"); break;
        case OpcUaType_ExpandedNodeId: parseExpandedNodeId(subtree, tvb, pinfo, &iOffset, "Value"); break;
        case OpcUaType_StatusCode: parseStatusCode(subtree, tvb, pinfo, &iOffset, hf_opcua_StatusCode); break;
        case OpcUaType_DiagnosticInfo: parseDiagnosticInfo(subtree, tvb, pinfo, &iOffset, "Value"); break;
        case OpcUaType_QualifiedName: parseQualifiedName(subtree, tvb, pinfo, &iOffset, "Value"); break;
        case OpcUaType_LocalizedText: parseLocalizedText(subtree, tvb, pinfo, &iOffset, "Value"); break;
        case OpcUaType_ExtensionObject: parseExtensionObject(subtree, tvb, pinfo, &iOffset, "Value"); break;
        case OpcUaType_DataValue: parseDataValue(subtree, tvb, pinfo, &iOffset, "Value"); break;
        case OpcUaType_Variant: parseVariant(subtree, tvb, pinfo, &iOffset, "Value"); break;
        }
        decrement_dissection_depth(pinfo);
    }

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;

    opcua_nested_count--;
    p_add_proto_data(pinfo->pool, pinfo, proto_opcua, 0, GUINT_TO_POINTER(opcua_nested_count));
}

/** General parsing function for arrays of simple types.
 * All arrays have one 4 byte signed integer length information,
 * followed by n data elements.
 */
void parseArraySimple(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, int hfIndex, fctSimpleTypeParser pParserFunction, const int idx)
{
    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1, idx, &ti, "%s: Array of %s", szFieldName, szTypeName);
    int i;
    int32_t iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);

    if (iLen > MAX_ARRAY_LEN)
    {
        proto_tree_add_expert_format(subtree, pinfo, &ei_array_length, tvb, *pOffset, 4, "Array length %d too large to process", iLen);
        return;
    }

    *pOffset += 4;
    for (i=0; i<iLen; i++)
    {
        proto_item *arrayItem = (*pParserFunction)(subtree, tvb, pinfo, pOffset, hfIndex);
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
void parseArrayEnum(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, fctEnumParser pParserFunction, const int idx)
{
    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1, idx, &ti, "%s: Array of %s", szFieldName, szTypeName);
    int i;
    int32_t iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);

    if (iLen > MAX_ARRAY_LEN)
    {
        proto_tree_add_expert_format(subtree, pinfo, &ei_array_length, tvb, *pOffset, 4, "Array length %d too large to process", iLen);
        return;
    }

    *pOffset += 4;
    for (i=0; i<iLen; i++)
    {
        (*pParserFunction)(subtree, tvb, pinfo, pOffset);
    }
    proto_item_set_end(ti, tvb, *pOffset);
}

/** General parsing function for arrays of complex types.
 * All arrays have one 4 byte signed integer length information,
 * followed by n data elements.
 */
void parseArrayComplex(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName, const char *szTypeName, fctComplexTypeParser pParserFunction, const int idx)
{
    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1, idx, &ti, "%s: Array of %s", szFieldName, szTypeName);
    int i;
    int32_t iLen;

    /* read array length */
    iLen = tvb_get_letohl(tvb, *pOffset);
    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);

    if (iLen > MAX_ARRAY_LEN)
    {
        proto_tree_add_expert_format(subtree, pinfo, &ei_array_length, tvb, *pOffset, 4, "Array length %d too large to process", iLen);
        return;
    }

    *pOffset += 4;
    for (i=0; i<iLen; i++)
    {
        char szNum[20];
        snprintf(szNum, 20, "[%i]", i);
        (*pParserFunction)(subtree, tvb, pinfo, pOffset, szNum);
    }
    proto_item_set_end(ti, tvb, *pOffset);
}

void parseNodeId(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName)
{
    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1, ett_opcua_nodeid, &ti, "%s: NodeId", szFieldName);
    int     iOffset = *pOffset;
    uint8_t EncodingMask;

    EncodingMask = tvb_get_uint8(tvb, iOffset);
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
        parseString(subtree, tvb, pinfo, &iOffset, hf_opcua_nodeid_string);
        break;
    case 0x04: /* guid */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseGuid(subtree, tvb, pinfo, &iOffset, hf_opcua_nodeid_guid);
        break;
    case 0x05: /* byte string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseByteString(subtree, tvb, pinfo, &iOffset, hf_opcua_nodeid_bytestring);
        break;
    };

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

void parseExtensionObject(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName)
{
    static int * const extobj_mask[] = {&hf_opcua_extobj_mask_binbodyflag,
                                       &hf_opcua_extobj_mask_xmlbodyflag,
                                       NULL};

    int     iOffset = *pOffset;
    uint8_t EncodingMask;
    uint32_t TypeId;
    proto_tree *extobj_tree;
    proto_item *ti;
    unsigned    opcua_nested_count;

    /* add extension object subtree */
    extobj_tree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1, ett_opcua_extensionobject, &ti, "%s: ExtensionObject", szFieldName);

    /* prevent a too high nesting depth */
    opcua_nested_count = GPOINTER_TO_UINT(p_get_proto_data(pinfo->pool, pinfo, proto_opcua, 0));
    if (opcua_nested_count >= MAX_NESTING_DEPTH)
    {
        expert_add_info(pinfo, ti, &ei_nesting_depth);
        return;
    }
    opcua_nested_count++;
    p_add_proto_data(pinfo->pool, pinfo, proto_opcua, 0, GUINT_TO_POINTER(opcua_nested_count));

    /* add nodeid subtree */
    TypeId = getExtensionObjectType(tvb, &iOffset);
    parseNodeId(extobj_tree, tvb, pinfo, &iOffset, "TypeId");

    /* parse encoding mask */
    EncodingMask = tvb_get_uint8(tvb, iOffset);
    proto_tree_add_bitmask(extobj_tree, tvb, iOffset, hf_opcua_extobj_mask, ett_opcua_extensionobject_encodingmask, extobj_mask, ENC_LITTLE_ENDIAN);
    iOffset++;

    if (EncodingMask & EXTOBJ_ENCODINGMASK_BINBODY_FLAG) /* has binary body ? */
    {
        dispatchExtensionObjectType(extobj_tree, tvb, pinfo, &iOffset, TypeId);
    }

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;

    opcua_nested_count--;
    p_add_proto_data(pinfo->pool, pinfo, proto_opcua, 0, GUINT_TO_POINTER(opcua_nested_count));
}

void parseExpandedNodeId(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, const char *szFieldName)
{
    static int * const expandednodeid_mask[] = {&hf_opcua_nodeid_encodingmask,
                                               &hf_opcua_expandednodeid_mask_serverindex,
                                               &hf_opcua_expandednodeid_mask_namespaceuri,
                                               NULL};

    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1,
                ett_opcua_expandednodeid, &ti, "%s: ExpandedNodeId", szFieldName);
    int     iOffset = *pOffset;
    uint8_t EncodingMask;

    EncodingMask = tvb_get_uint8(tvb, iOffset);
    proto_tree_add_bitmask(subtree, tvb, iOffset, hf_opcua_expandednodeid_mask, ett_opcua_expandednodeid_encodingmask, expandednodeid_mask, ENC_LITTLE_ENDIAN);
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
        parseString(subtree, tvb, pinfo, &iOffset, hf_opcua_nodeid_string);
        break;
    case 0x04: /* guid */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseGuid(subtree, tvb, pinfo, &iOffset, hf_opcua_nodeid_guid);
        break;
    case 0x05: /* byte string */
        proto_tree_add_item(subtree, hf_opcua_nodeid_nsindex, tvb, iOffset, 2, ENC_LITTLE_ENDIAN);
        iOffset+=2;
        parseByteString(subtree, tvb, pinfo, &iOffset, hf_opcua_nodeid_bytestring);
        break;
    };

    if (EncodingMask & NODEID_NAMESPACEURIFLAG)
    {
        parseString(subtree, tvb, pinfo, &iOffset, hf_opcua_NamespaceUri);
    }
    if (EncodingMask & NODEID_SERVERINDEXFLAG)
    {
        parseUInt32(subtree, tvb, pinfo, &iOffset, hf_opcua_ServerIndex);
    }

    proto_item_set_end(ti, tvb, iOffset);
    *pOffset = iOffset;
}

uint32_t getExtensionObjectType(tvbuff_t *tvb, int *pOffset)
{
    int     iOffset = *pOffset;
    uint8_t EncodingMask;
    uint32_t Numeric = 0;

    EncodingMask = tvb_get_uint8(tvb, iOffset);
    iOffset++;

    switch(EncodingMask)
    {
    case 0x00: /* two byte node id */
        Numeric = tvb_get_uint8(tvb, iOffset);
        /*iOffset+=1;*/
        break;
    case 0x01: /* four byte node id */
        iOffset+=1;
        Numeric = tvb_get_letohs(tvb, iOffset);
        break;
    case 0x02: /* numeric, that does not fit into four bytes */
        iOffset+=2;
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

void parseNodeClassMask(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset)
{
    static int * const nodeclass_mask[] = {
      &hf_opcua_nodeClassMask_object,
      &hf_opcua_nodeClassMask_variable,
      &hf_opcua_nodeClassMask_method,
      &hf_opcua_nodeClassMask_objecttype,
      &hf_opcua_nodeClassMask_variabletype,
      &hf_opcua_nodeClassMask_referencetype,
      &hf_opcua_nodeClassMask_datatype,
      &hf_opcua_nodeClassMask_view,
      NULL};

    uint8_t NodeClassMask = tvb_get_uint8(tvb, *pOffset);
    if(NodeClassMask == NODECLASSMASK_ALL)
    {
        proto_tree_add_item(tree, hf_opcua_nodeClassMask_all, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);
    }
    else
    {
        proto_tree_add_bitmask(tree, tvb, *pOffset, hf_opcua_nodeClassMask, ett_opcua_nodeClassMask, nodeclass_mask, ENC_LITTLE_ENDIAN);
    }
    *pOffset+=4;
}

void parseResultMask(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo _U_, int *pOffset)
{
    static int * const browseresult_mask[] = {
      &hf_opcua_resultMask_referencetype,
      &hf_opcua_resultMask_isforward,
      &hf_opcua_resultMask_nodeclass,
      &hf_opcua_resultMask_browsename,
      &hf_opcua_resultMask_displayname,
      &hf_opcua_resultMask_typedefinition,
      NULL};

    uint8_t ResultMask = tvb_get_uint8(tvb, *pOffset);
    if(ResultMask == RESULTMASK_ALL)
    {
        proto_tree_add_item(tree, hf_opcua_resultMask_all, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);
    }
    else
    {
        proto_tree_add_bitmask(tree, tvb, *pOffset, hf_opcua_resultMask, ett_opcua_resultMask, browseresult_mask, ENC_LITTLE_ENDIAN);
    }
    *pOffset+=4;
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
