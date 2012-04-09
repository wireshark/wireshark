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
#include "opcua_identifiers.h"

/* simple types */
void parseBoolean(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseByte(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseSByte(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseUInt16(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseInt16(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseUInt32(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseInt32(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseUInt64(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseInt64(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseString(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseGuid(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseByteString(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseXmlElement(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseFloat(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseDouble(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseDateTime(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
void parseStatusCode(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex);
/* complex types */
void parseLocalizedText(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName);
void parseNodeId(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName);
void parseDiagnosticInfo(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName);
void parseExtensionObject(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName);
void parseQualifiedName(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName);
void parseDataValue(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName);
void parseVariant(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName);
void parseExpandedNodeId(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName);
void parseArraySimple(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, int hfIndex, fctSimpleTypeParser pParserFunction);
void parseArrayEnum(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, fctEnumParser pParserFunction);
void parseArrayComplex(proto_tree *tree, tvbuff_t *tvb, gint *pOffset, const char *szFieldName, fctComplexTypeParser pParserFunction);
void registerSimpleTypes(int proto);
guint32 getExtensionObjectType(tvbuff_t *tvb, gint *pOffset);
