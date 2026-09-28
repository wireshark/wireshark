/* infomodel_parser.h
 *  Header file for infomodel parsing.
 *
 * OPC UA information model (custom datatypes from a UANodeSet XML file)
 * Author: Leon Schmidt <leon.schmidt@codewerk.de>
 * Copyright (C) 2022 Codewerk GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "infomodel_elements.h"

#ifndef INFO_PARSE_H
#define INFO_PARSE_H

typedef enum _Tagtype {
    TAGTYPE_INVALID = 0,

    TAGTYPE_NOT_INTERESTING,
    TAGTYPE_ALIAS,
    TAGTYPE_DATATYPE,
    TAGTYPE_FIELD,
    TAGTYPE_OBJECT,

    TAGTYPE_OBJ_REF,
    TAGTYPE_OBJ_TYPE_REF,
    TAGTYPE_VAR_REF,
    TAGTYPE_VAR_TYPE_REF,
    TAGTYPE_DATATYPE_REF,
} Tagtype;

Infomodel* parseXml(const char* filename, GError** error);

#endif /* INFO_PARSE_H */
