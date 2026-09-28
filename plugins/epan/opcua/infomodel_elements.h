/* infomodel_elements.h
 *  Defines elements to represent an infomodel.
 *
 * OPC UA information model (custom datatypes from a UANodeSet XML file)
 * Author: Leon Schmidt <leon.schmidt@codewerk.de>
 * Copyright (C) 2022 Codewerk GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include <glib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#ifndef INFO_ELEM_H
#define INFO_ELEM_H

/* Enums */
typedef enum _AliasType {
    ALIAS_INVALID = 0,

    ALIAS_BOOLEAN,
    ALIAS_SBYTE,
    ALIAS_BYTE,
    ALIAS_INT16,
    ALIAS_UINT16,
    ALIAS_INT32,
    ALIAS_UINT32,
    ALIAS_INT64,
    ALIAS_UINT64,
    ALIAS_FLOAT,
    ALIAS_DOUBLE,
    ALIAS_DATETIME,
    ALIAS_UTCTIME,
    ALIAS_STRING,
    ALIAS_BYTESTRING,
    ALIAS_LOCALIZEDTEXT,
} AliasType;

typedef enum _DatatypeIdType {
    DATATYPEID_EMPTY = 0,

    DATATYPEID_NUMERIC,
    DATATYPEID_STRING,
    DATATYPEID_GUID,
    DATATYPEID_OPAQUE,
} DatatypeIdType;

typedef enum _Subtype {
    SUBTYPE_INVALID = 0,
    SUBTYPE_UNDEFINED,

    SUBTYPE_BOOLEAN,
    SUBTYPE_SBYTE,
    SUBTYPE_BYTE,
    SUBTYPE_INT16,
    SUBTYPE_UINT16,
    SUBTYPE_INT32,
    SUBTYPE_UINT32,
    SUBTYPE_INT64,
    SUBTYPE_UINT64,
    SUBTYPE_FLOAT,
    SUBTYPE_DOUBLE,
    SUBTYPE_DATETIME,
    SUBTYPE_STRING,
    SUBTYPE_BYTESTRING,

    SUBTYPE_STRUCT,
    SUBTYPE_ENUM,
    SUBTYPE_OPTIONSET,
    SUBTYPE_CUSTOM,
} Subtype;

/* Container struct */
typedef struct _Datatype {
    unsigned int ns; /* namespace */
    DatatypeIdType idType;

    union {
        unsigned int id_num;
        char *id_str;
        /* TODO support other datatypeidtypes */
    };
} Datatype;

/* Stores Alias Types from Infomodel as a list */
/* to translate a given ns and id to a primitive type */
/* usually specified at the beginning of an Infomodel XML */
typedef struct _AliasMap {
    char *name;
    Datatype type;
    AliasType aType;

    struct _AliasMap *next;
} AliasMap;

AliasMap *AliasMap_new(void);

/* Fill in type field depending on current name */
void AliasMap_type_lookup(AliasMap *self);
Datatype AliasMap_find_name(AliasMap *self, const char *name);

/* represents one member value of a Custom Datatype */
/* "next" points to the next member of that custom type, */
/* essentially creating a list of fields */
typedef struct _Field {
    char *name;
    Datatype type;
    int value;

    int valueRank;      /* -1: scalar, 0 or 1: one-dimensional array, > 1: matrix */
    bool isOptional;
    bool allowSubTypes;

    struct _Field *next;

    int hf_id;
    int ett_id;
} Field;

Field *Field_new(void);
void Field_delete(Field *self);

AliasType Field_find_atype(Field *self, AliasMap *map);

/* represents a Custom Datatype of the Infomodel */
/* "next" points to the next custom datatype of that Infomodel, */
/* essentially creating a list of custom datatypes */
typedef struct _CustomDatatype {
    char *name;
    Datatype id;
    Subtype subtype;
    struct _CustomDatatype *customSubtype; /* only relevant if subtype == SUBTYPE_CUSTOM */

    Field *fields_first;
    Field *fields_last;
    bool hasOptionalFields;
    bool fieldsIgnored; /* union or derived structure: its own fields are not decoded (yet) */

    int ett_id; /* only used for top level, subfields use own ett_id */

    struct _CustomDatatype *next;
} CustomDatatype;

CustomDatatype *CustomDatatype_new(void);
void CustomDatatype_delete(CustomDatatype *self);

void CustomDatatype_add_field(CustomDatatype *self, Field *field);
CustomDatatype *CustomDatatype_find(CustomDatatype *self, Datatype nodeId);

/* Represents a UAObject, which is usually referenced from a packet */
/* contains information about what Custom Datatype is used in that packet */
/* "next" points to the next UAObject, as several may be specified in a given Infomodel */
typedef struct _UAObject {
    char *name;
    Datatype id;

    Datatype refEncodingRaw;

    struct _UAObject *next;
} UAObject;

UAObject *UAObject_new(void);
void UAObject_delete(UAObject *self);

/* high level representation of an entire Infomodel */
/* contains one list of aliases, custom datatypes and UAObjects respectively */
typedef struct _Infomodel {
    AliasMap *aliases_first;
    AliasMap *aliases_last;

    CustomDatatype *customDatatype_first;
    CustomDatatype *customDatatype_last;

    UAObject *objects_first;
    UAObject *objects_last;

} Infomodel;

Infomodel *Infomodel_new(void);
void Infomodel_delete(Infomodel *self);
void Infomodel_add_aliasmap_entry(Infomodel *self, AliasMap *map);
void Infomodel_add_type(Infomodel *self, CustomDatatype *type);
void Infomodel_add_object(Infomodel *self, UAObject *object);

#endif /* INFO_ELEM_H */
