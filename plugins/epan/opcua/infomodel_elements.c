/* infomodel_elements.c
 *  Implements operations for Infomodel datatypes
 *
 * OPC UA information model (custom datatypes from a UANodeSet XML file)
 * Author: Leon Schmidt <leon.schmidt@codewerk.de>
 * Copyright (C) 2022 Codewerk GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <string.h>

#include "infomodel_elements.h"

static int Datatype_cmp(Datatype a, Datatype b) {
    if (a.ns != b.ns) return b.ns - a.ns;
    if (a.idType != b.idType) return b.idType - a.idType;
    switch (a.idType)
    {
    case DATATYPEID_NUMERIC:
        return b.id_num - a.id_num;
    case DATATYPEID_STRING:
        return strcmp(a.id_str, b.id_str); /* string identifiers are case-sensitive (OPC 10000-3 8.2.3) */
        /* TODO handle other id types */
        /* case DATATYPEID_GUID: */
        /* case DATATYPEID_OPAQUE: */
    default:
        return 0;
    }
}

AliasMap *AliasMap_new(void) {
    AliasMap *self = g_slice_new0(AliasMap);
    return self;
}

static void AliasMap_delete(AliasMap *self) {
    if (!self) return;
    AliasMap *tmp, *cur;
    cur = self;
    while (cur) {
        tmp = cur;
        cur = cur->next;
        g_free(tmp->name);
        if (tmp->type.idType == DATATYPEID_STRING) g_free(tmp->type.id_str);
        g_slice_free(AliasMap, tmp);
    }
}

/* Fill in type field depending on current name */
void AliasMap_type_lookup(AliasMap *self) {
    if      (!g_ascii_strcasecmp(self->name, "boolean"      )) self->aType = ALIAS_BOOLEAN;
    else if (!g_ascii_strcasecmp(self->name, "sbyte"        )) self->aType = ALIAS_SBYTE;
    else if (!g_ascii_strcasecmp(self->name, "byte"         )) self->aType = ALIAS_BYTE;
    else if (!g_ascii_strcasecmp(self->name, "int16"        )) self->aType = ALIAS_INT16;
    else if (!g_ascii_strcasecmp(self->name, "uint16"       )) self->aType = ALIAS_UINT16;
    else if (!g_ascii_strcasecmp(self->name, "int32"        )) self->aType = ALIAS_INT32;
    else if (!g_ascii_strcasecmp(self->name, "uint32"       )) self->aType = ALIAS_UINT32;
    else if (!g_ascii_strcasecmp(self->name, "int64"        )) self->aType = ALIAS_INT64;
    else if (!g_ascii_strcasecmp(self->name, "uint64"       )) self->aType = ALIAS_UINT64;
    else if (!g_ascii_strcasecmp(self->name, "float"        )) self->aType = ALIAS_FLOAT;
    else if (!g_ascii_strcasecmp(self->name, "double"       )) self->aType = ALIAS_DOUBLE;
    else if (!g_ascii_strcasecmp(self->name, "datetime"     )) self->aType = ALIAS_DATETIME;
    else if (!g_ascii_strcasecmp(self->name, "utctime"      )) self->aType = ALIAS_UTCTIME;
    else if (!g_ascii_strcasecmp(self->name, "string"       )) self->aType = ALIAS_STRING;
    else if (!g_ascii_strcasecmp(self->name, "bytestring"   )) self->aType = ALIAS_BYTESTRING;
    else if (!g_ascii_strcasecmp(self->name, "localizedtext")) self->aType = ALIAS_LOCALIZEDTEXT;
    else self->aType = ALIAS_INVALID;
}

Datatype AliasMap_find_name(AliasMap *self, const char *name) {
    AliasMap *cur;
    for (cur = self; cur; cur = cur->next) {
        if (!g_ascii_strcasecmp(name, cur->name)) {
            return cur->type;
        }
    }
    Datatype default_ret;
    memset(&default_ret, 0, sizeof(Datatype));
    return default_ret;
}

Field *Field_new(void) {
    Field *self = g_slice_new0(Field);
    self->valueRank = -1;
    self->hf_id = -1;
    self->ett_id = -1;
    return self;
}

void Field_delete(Field *self) {
    if (!self) return;
    Field *tmp, *cur;
    cur = self;
    while (cur) {
        tmp = cur;
        cur = cur->next;
        g_free(tmp->name);
        if (tmp->type.idType == DATATYPEID_STRING) g_free(tmp->type.id_str);
        g_slice_free(Field, tmp);
    }
}

AliasType Field_find_atype(Field *self, AliasMap *map) {
    AliasMap *cur;
    for (cur = map; cur; cur = cur->next) {
        /* the built-in types are in namespace 0, whatever an alias of another namespace is called */
        if (cur->type.ns == 0 && !Datatype_cmp(self->type, cur->type)) return cur->aType;
    }
    return ALIAS_INVALID;
}

CustomDatatype *CustomDatatype_new(void) {
    CustomDatatype *self = g_slice_new0(CustomDatatype);
    self->ett_id = -1;
    return self;
}

void CustomDatatype_delete(CustomDatatype *self) {
    if (!self) return;
    CustomDatatype *tmp, *cur;
    cur = self;
    while (cur) {
        tmp = cur;
        cur = cur->next;
        Field_delete(tmp->fields_first);
        g_free(tmp->name);
        if (tmp->id.idType == DATATYPEID_STRING) g_free(tmp->id.id_str);
        g_slice_free(CustomDatatype, tmp);
    }
}

void CustomDatatype_add_field(CustomDatatype *self, Field *field) {
    if (self->fields_last) {
        self->fields_last->next = field;
    }
    else {
        self->fields_first = field;
    }
    self->fields_last = field;
}

CustomDatatype *CustomDatatype_find(CustomDatatype *self, Datatype nodeId) {
    CustomDatatype *cur;
    for (cur = self; cur; cur = cur->next) {
        if (!Datatype_cmp(cur->id, nodeId)) return cur;
    }
    return NULL;
}

UAObject *UAObject_new(void) {
    UAObject *self = g_slice_new0(UAObject);
    return self;
}

void UAObject_delete(UAObject *self) {
    if (!self) return;
    UAObject *tmp, *cur;
    cur = self;
    while (cur) {
        tmp = cur;
        cur = cur->next;
        g_free(tmp->name);
        if (tmp->id.idType == DATATYPEID_STRING) g_free(tmp->id.id_str);
        if (tmp->refEncodingRaw.idType == DATATYPEID_STRING) g_free(tmp->refEncodingRaw.id_str);
        g_slice_free(UAObject, tmp);
    }
}

Infomodel *Infomodel_new(void) {
    Infomodel *self = g_slice_new0(Infomodel);
    return self;
}

void Infomodel_delete(Infomodel *self) {
    if (!self) return;
    AliasMap_delete(self->aliases_first);
    CustomDatatype_delete(self->customDatatype_first);
    UAObject_delete(self->objects_first);
    g_slice_free(Infomodel, self);
}

void Infomodel_add_aliasmap_entry(Infomodel *self, AliasMap *map) {
    if (self->aliases_last) {
        self->aliases_last->next = map;
    }
    else {
        self->aliases_first = map;
    }
    self->aliases_last = map;
}

void Infomodel_add_type(Infomodel *self, CustomDatatype *cType) {
    if (self->customDatatype_last) {
        self->customDatatype_last->next = cType;
    }
    else {
        self->customDatatype_first = cType;
    }
    self->customDatatype_last = cType;
}

void Infomodel_add_object(Infomodel *self, UAObject *object) {
    if (self->objects_last) {
        self->objects_last->next = object;
    }
    else {
        self->objects_first = object;
    }
    self->objects_last = object;
}
