/* infomodel_parser.c
 *  Functionality for parsing an infomodel XML file via glib.
 *
 * OPC UA information model (custom datatypes from a UANodeSet XML file)
 * Author: Leon Schmidt <leon.schmidt@codewerk.de>
 * Copyright (C) 2022 Codewerk GmbH
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <stdio.h>

#include <ws_attributes.h>
#include <wsutil/strtoi.h>

#include "infomodel_parser.h"

#define NUMID_STR "i=%u"
#define NS_NUMID_STR "ns=%u;i=%u"

static bool collectObjEncoding = false;
static bool collectCtypeSubtype = false;

static void datatype_string_mismatch(GError **error, const char *str) {
    g_set_error(
        error,
        G_MARKUP_ERROR,
        G_MARKUP_ERROR_INVALID_CONTENT,
        "Could not parse datatype string \"%s\"",
        str
    );
}

static void parseNodeId(const char *typeid_str, Datatype *typeId, GError **error) {
    if (sscanf(typeid_str, NUMID_STR, &typeId->id_num) == 1 ||
        sscanf(typeid_str, NS_NUMID_STR, &typeId->ns, &typeId->id_num) == 2) {
        typeId->idType = DATATYPEID_NUMERIC;
        return;
    }

    /* string NodeId: "s=<id>" or "ns=<n>;s=<id>" */
    const char *str = typeid_str;
    if (g_str_has_prefix(str, "ns=")) {
        str = strchr(str, ';');
        if (!str || sscanf(typeid_str, "ns=%u;", &typeId->ns) != 1) {
            datatype_string_mismatch(error, typeid_str);
            return;
        }
        str++;
    }
    if (g_str_has_prefix(str, "s=")) {
        typeId->id_str = g_strdup(str + 2);
        typeId->idType = DATATYPEID_STRING;
        return;
    }
    datatype_string_mismatch(error, typeid_str);
}

/* Is the ReferenceType of a reference the standard one with this name and namespace-0 identifier? It is a NodeId or
 * an alias, e.g. "HasSubtype" or "i=45". */
static bool is_reference_type(const char *refType, const char *name, unsigned int id) {
    Datatype nodeId;
    GError *err = NULL;

    if (!g_ascii_strcasecmp(refType, name)) return true;
    memset(&nodeId, 0, sizeof(Datatype));
    parseNodeId(refType, &nodeId, &err);
    if (err) {
        g_error_free(err);
        return false;
    }
    if (nodeId.idType == DATATYPEID_STRING) {
        g_free(nodeId.id_str);
        return false;
    }
    return nodeId.ns == 0 && nodeId.id_num == id;
}

/* name of a BrowseName ("<namespace index>:<name>", the index is optional) */
static const char *browsename_name(const char *browsename) {
    const char *name = browsename;
    while (g_ascii_isdigit(*name)) name++;
    return (name != browsename && *name == ':') ? name + 1 : browsename;
}

static Tagtype Markup_tagtype(
    GMarkupParseContext *context,
    GError **error
) {
    Tagtype tagtype = TAGTYPE_INVALID;

    const GSList *tree = g_markup_parse_context_get_element_stack(context);
    if (!g_ascii_strcasecmp((const char *)tree->data, "alias")) {
        tree = tree->next;
        if (tree && tree->next &&
            !g_ascii_strcasecmp((const char *)tree->data, "aliases") &&
            !g_ascii_strcasecmp((const char *)tree->next->data, "uanodeset")
            ) {
            tagtype = TAGTYPE_ALIAS;
        }
    }
    else if (!g_ascii_strcasecmp((const char *)tree->data, "uadatatype")) {
        tree = tree->next;
        if (tree &&
            !g_ascii_strcasecmp((const char *)tree->data, "uanodeset")
            ) {
            tagtype = TAGTYPE_DATATYPE;
        }
    }
    else if (!g_ascii_strcasecmp((const char *)tree->data, "field")) {
        tree = tree->next;
        if (tree && tree->next && tree->next->next &&
            !g_ascii_strcasecmp((const char *)tree->data, "definition") &&
            !g_ascii_strcasecmp((const char *)tree->next->data, "uadatatype") &&
            !g_ascii_strcasecmp((const char *)tree->next->next->data, "uanodeset")
            ) {
            tagtype = TAGTYPE_FIELD;
        }
    }
    else if (!g_ascii_strcasecmp((const char *)tree->data, "uaobject")) {
        tree = tree->next;
        if (tree &&
            !g_ascii_strcasecmp((const char *)tree->data, "uanodeset")
            ) {
            tagtype = TAGTYPE_OBJECT;
        }
    }
    else if (!g_ascii_strcasecmp((const char *)tree->data, "reference")) {
        tree = tree->next;
        if (tree && tree->next && tree->next->next &&
            !g_ascii_strcasecmp((const char *)tree->data, "references") &&
            !g_ascii_strcasecmp((const char *)tree->next->next->data, "uanodeset")
            ) {
            if (!g_ascii_strcasecmp((const char *)tree->next->data, "uaobject"))
                tagtype = TAGTYPE_OBJ_REF;
            else if (!g_ascii_strcasecmp((const char *)tree->next->data, "uaobjecttype"))
                tagtype = TAGTYPE_OBJ_TYPE_REF;
            else if (!g_ascii_strcasecmp((const char *)tree->next->data, "uavariable"))
                tagtype = TAGTYPE_VAR_REF;
            else if (!g_ascii_strcasecmp((const char *)tree->next->data, "uavariabletype"))
                tagtype = TAGTYPE_VAR_TYPE_REF;
            else if (!g_ascii_strcasecmp((const char *)tree->next->data, "uadatatype"))
                tagtype = TAGTYPE_DATATYPE_REF;
            else
                tagtype = TAGTYPE_NOT_INTERESTING;
        }
    }
    else {
        tagtype = TAGTYPE_NOT_INTERESTING;
    }

    if (tagtype == TAGTYPE_INVALID) {
        g_set_error(
            error,
            G_MARKUP_ERROR,
            G_MARKUP_ERROR_UNKNOWN_ELEMENT,
            "Could not identify element tag \"%s\"",
            g_markup_parse_context_get_element(context)
        );
    }
    return tagtype;
}

static void Markup_start_element(
    GMarkupParseContext *context,
    const char *element_name,
    const char **attribute_names,
    const char **attribute_values,
    void*             user_data,
    GError **error
) {
    GError *err = NULL;
    Infomodel *infomodel = (Infomodel *)user_data;

    Tagtype tagtype = Markup_tagtype(context, &err);
    if (err) {
        g_propagate_error(error, err);
        return;
    }

    if (tagtype == TAGTYPE_ALIAS) {
        const char *name;
        g_markup_collect_attributes(
            element_name, attribute_names, attribute_values, &err,
            G_MARKUP_COLLECT_STRING, "Alias", &name,
            G_MARKUP_COLLECT_INVALID
        );

        if (err) {
            g_propagate_error(error, err);
            return;
        }

        AliasMap *map = AliasMap_new();
        map->name = g_strdup(name);
        AliasMap_type_lookup(map);
        Infomodel_add_aliasmap_entry(infomodel, map);
        return;
    }

    if (tagtype == TAGTYPE_DATATYPE || tagtype == TAGTYPE_OBJECT) {
        const char *id_str, *name, *symName, *parNodeId;
        gboolean eventNotifier, isAbstract; /* not bool: G_MARKUP_COLLECT_BOOLEAN writes a gboolean */
        g_markup_collect_attributes(
            element_name, attribute_names, attribute_values, &err,
            G_MARKUP_COLLECT_STRING, "NodeId", &id_str,
            G_MARKUP_COLLECT_STRING, "BrowseName", &name,

            /* Unused */
            G_MARKUP_COLLECT_BOOLEAN | G_MARKUP_COLLECT_OPTIONAL, "EventNotifier", &eventNotifier,
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, "SymbolicName", &symName,
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, "ParentNodeId", &parNodeId,
            G_MARKUP_COLLECT_BOOLEAN | G_MARKUP_COLLECT_OPTIONAL, "IsAbstract", &isAbstract,
            G_MARKUP_COLLECT_INVALID
        );

        if (err) {
            g_propagate_error(error, err);
            return;
        }

        if (tagtype == TAGTYPE_DATATYPE) {
            CustomDatatype *cType = CustomDatatype_new();
            cType->name = g_strdup(browsename_name(name));
            parseNodeId(id_str, &cType->id, &err);
            if (err) {
                g_propagate_error(error, err);
                CustomDatatype_delete(cType);
                return;
            }
            Infomodel_add_type(infomodel, cType);
        }
        else if (tagtype == TAGTYPE_OBJECT) {
            UAObject *object = UAObject_new();
            object->name = g_strdup(browsename_name(name));
            parseNodeId(id_str, &object->id, &err);
            if (err) {
                g_propagate_error(error, err);
                UAObject_delete(object);
                return;
            }
            Infomodel_add_object(infomodel, object);
        }

        return;
    }

    if (tagtype == TAGTYPE_FIELD) {
        const char *name, *type, *value, *symName, *arrayDim, *valueRank, *maxStrLen;
        gboolean isOptional, allowSubTypes; /* not bool: G_MARKUP_COLLECT_BOOLEAN writes a gboolean */
        CustomDatatype *current_ctype = infomodel->customDatatype_last;

        if (current_ctype->subtype == SUBTYPE_STRUCT) {
            g_markup_collect_attributes(
                element_name, attribute_names, attribute_values, &err,
                G_MARKUP_COLLECT_STRING, "Name", &name,
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, "DataType", &type,
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, "ValueRank", &valueRank,
                G_MARKUP_COLLECT_BOOLEAN | G_MARKUP_COLLECT_OPTIONAL, "IsOptional", &isOptional,
                G_MARKUP_COLLECT_BOOLEAN | G_MARKUP_COLLECT_OPTIONAL, "AllowSubTypes", &allowSubTypes,

                /* Unused */
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, "SymbolicName", &symName,
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, "ArrayDimensions", &arrayDim,
                G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, "MaxStringLength", &maxStrLen,
                G_MARKUP_COLLECT_INVALID
            );

            if (err) {
                g_propagate_error(error, err);
                return;
            }

            Field *field = Field_new();
            field->name = g_strdup(name);
            if (valueRank && !ws_strtoi32(valueRank, NULL, &field->valueRank)) {
                g_set_error(error, G_MARKUP_ERROR, G_MARKUP_ERROR_INVALID_CONTENT,
                    "Could not parse ValueRank \"%s\" of field \"%s\"", valueRank, name);
                Field_delete(field);
                return;
            }
            if (type) {
                parseNodeId(type, &field->type, &err);
                if (err) {
                    /* Try to match "type" string to alias name */
                    g_error_free(err);
                    Datatype field_type = AliasMap_find_name(infomodel->aliases_first, type);
                    if (field_type.idType != DATATYPEID_EMPTY) {
                        field->type = field_type;
                        /* the field frees its own copy */
                        if (field_type.idType == DATATYPEID_STRING) field->type.id_str = g_strdup(field_type.id_str);
                    }
                    else {
                        datatype_string_mismatch(error, type);
                        Field_delete(field);
                        return;
                    }
                }
            }
            else {
                Datatype invalid;
                memset(&invalid, 0, sizeof(Datatype));
                field->type = invalid;
            }
            field->isOptional = isOptional;
            field->allowSubTypes = allowSubTypes;
            current_ctype->hasOptionalFields = current_ctype->hasOptionalFields || isOptional;
            CustomDatatype_add_field(current_ctype, field);

            return;
        }

        /* unions, derived structures, types without a known parent: their fields are not decoded (yet) */
        if (current_ctype->subtype == SUBTYPE_UNDEFINED || current_ctype->subtype == SUBTYPE_CUSTOM ||
            current_ctype->subtype == SUBTYPE_INVALID) {
            /* the root of the parents (parsed before, so no cycle); a subtype of an enumeration or a simple type is
             * decoded completely by its parent, its fields are just values */
            CustomDatatype *root = current_ctype;
            while (root->subtype == SUBTYPE_CUSTOM) root = root->customSubtype;
            if (root->subtype == SUBTYPE_STRUCT || root->subtype == SUBTYPE_UNDEFINED || root->subtype == SUBTYPE_INVALID)
                current_ctype->fieldsIgnored = true;
            return;
        }

        /* assume enum (or enum-like) field (with 'value's) */
        g_markup_collect_attributes(
            element_name, attribute_names, attribute_values, &err,
            G_MARKUP_COLLECT_STRING, "Name", &name,
            G_MARKUP_COLLECT_STRING, "Value", &value,

            /* Unused */
            G_MARKUP_COLLECT_STRING | G_MARKUP_COLLECT_OPTIONAL, "SymbolicName", &symName,
            G_MARKUP_COLLECT_INVALID
        );
        if (err) {
            g_propagate_error(error, err);
            return;
        }

        Field *field = Field_new();
        field->name = g_strdup(name);
        if (sscanf(value, "%d", &field->value) != 1) {
            g_set_error(
                error,
                G_MARKUP_ERROR,
                G_MARKUP_ERROR_INVALID_CONTENT,
                "Could not parse enum value \"%s\"",
                value
            );
        }
        CustomDatatype_add_field(current_ctype, field);

        return;
    }

    if (tagtype == TAGTYPE_OBJ_REF || tagtype == TAGTYPE_DATATYPE_REF) {
        const char *refType;
        gboolean isForward; /* not bool: GLib writes a gboolean, -1 if the attribute is absent (forward) */
        g_markup_collect_attributes(
            element_name, attribute_names, attribute_values, &err,
            G_MARKUP_COLLECT_STRING, "ReferenceType", &refType,
            G_MARKUP_COLLECT_TRISTATE, "IsForward", &isForward,
            G_MARKUP_COLLECT_INVALID
        );
        if (err) {
            g_propagate_error(error, err);
            return;
        }
        if (tagtype == TAGTYPE_OBJ_REF && is_reference_type(refType, "HasEncoding", 38)) {
            collectObjEncoding = TRUE;
        }
        /* the parent type: the inverse HasSubtype (a forward one points to a subtype) */
        if (tagtype == TAGTYPE_DATATYPE_REF && is_reference_type(refType, "HasSubtype", 45) && isForward == FALSE) {
            collectCtypeSubtype = TRUE;
        }
        return;
    }
}

static void Markup_text(
    GMarkupParseContext *context,
    const char *text,
    size_t                text_len _U_,
    void*             user_data,
    GError **error
) {
    GError *err = NULL;
    Infomodel *infomodel = (Infomodel *)user_data;

    Tagtype tagtype = Markup_tagtype(context, &err);
    if (err) {
        g_propagate_error(error, err);
        return;
    }

    if (tagtype == TAGTYPE_ALIAS) {
        /* we know that the recently added node in the aliasmap
           must have been from the current opening tag */
        parseNodeId(text, &infomodel->aliases_last->type, &err);
        if (err) {
            g_propagate_error(error, err);
        }
        return;
    }

    if (tagtype == TAGTYPE_OBJ_REF && collectObjEncoding) {
        parseNodeId(text, &infomodel->objects_last->refEncodingRaw, &err);
        collectObjEncoding = false;
        if (err) {
            g_propagate_error(error, err);
        }
        return;
    }

    if (tagtype == TAGTYPE_DATATYPE_REF && collectCtypeSubtype) {
        Datatype tmp;
        memset(&tmp, 0, sizeof(Datatype));
        parseNodeId(text, &tmp, &err);
        if (err) {
            g_propagate_error(error, err);
            return;
        }
        CustomDatatype *lastType = infomodel->customDatatype_last;
        if (tmp.idType == DATATYPEID_NUMERIC && tmp.ns == 0) {
            switch (tmp.id_num)
            {
                /* TODO parse this from Namespace0 or smth instead */
            case 1: lastType->subtype = SUBTYPE_BOOLEAN; break;
            case 2: lastType->subtype = SUBTYPE_SBYTE; break;
            case 3: lastType->subtype = SUBTYPE_BYTE; break;
            case 4: lastType->subtype = SUBTYPE_INT16; break;
            case 5: lastType->subtype = SUBTYPE_UINT16; break;
            case 6: lastType->subtype = SUBTYPE_INT32; break;
            case 7: lastType->subtype = SUBTYPE_UINT32; break;
            case 8: lastType->subtype = SUBTYPE_INT64; break;
            case 9: lastType->subtype = SUBTYPE_UINT64; break;
            case 10: lastType->subtype = SUBTYPE_FLOAT; break;
            case 11: lastType->subtype = SUBTYPE_DOUBLE; break;
            case 12: lastType->subtype = SUBTYPE_STRING; break;
            case 13: lastType->subtype = SUBTYPE_DATETIME; break;
            case 15: lastType->subtype = SUBTYPE_BYTESTRING; break;
            case 22: lastType->subtype = SUBTYPE_STRUCT; break;
            case 29: lastType->subtype = SUBTYPE_ENUM; break;
            case 12755: lastType->subtype = SUBTYPE_OPTIONSET; break;
            default: lastType->subtype = SUBTYPE_UNDEFINED; break;
            }
        }
        else {
            /* a custom datatype parsed before; a parent defined later, not in the file or the type itself: not
             * decoded (yet) */
            CustomDatatype *parent = CustomDatatype_find(infomodel->customDatatype_first, tmp);
            lastType->customSubtype = parent != lastType ? parent : NULL;
            lastType->subtype = lastType->customSubtype ? SUBTYPE_CUSTOM : SUBTYPE_UNDEFINED;
        }
        if (tmp.idType == DATATYPEID_STRING) g_free(tmp.id_str);
        collectCtypeSubtype = false;
    }
}

static GMarkupParser parser = {
    .start_element = Markup_start_element,
    .text = Markup_text,
};

Infomodel *parseXml(const char *filename, GError **error) {
    GError *err = NULL;
    GMappedFile *gmf = g_mapped_file_new(filename, false, &err);

    if (!gmf) {
        g_propagate_prefixed_error(error, err, "Reading failed: ");
        return NULL;
    }

    const char *contents = g_mapped_file_get_contents(gmf);
    size_t len = g_mapped_file_get_length(gmf);
    Infomodel *infomodel = Infomodel_new();

    GMarkupParseContext *xml = g_markup_parse_context_new(
        &parser,
        G_MARKUP_PREFIX_ERROR_POSITION,
        infomodel,
        NULL
    );

    if (!g_markup_parse_context_parse(xml, contents, len, &err)) {
        g_propagate_prefixed_error(error, err, "Parsing failed: ");
    }
    else if (!g_markup_parse_context_end_parse(xml, &err)) {
        g_propagate_prefixed_error(error, err, "Parsing didn't finish: ");
    }

    g_markup_parse_context_free(xml);
    g_mapped_file_unref(gmf);
    if (err) {
        Infomodel_delete(infomodel);
        return NULL;
    }
    return infomodel;
}
