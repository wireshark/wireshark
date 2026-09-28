/* opcua_infomodel.c
 * Custom datatypes from an information model (UANodeSet XML file)
 * Author: Leon Schmidt <leon.schmidt@codewerk.de>
 * Copyright (C) 2022 Codewerk GmbH
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/expert.h>
#include <epan/prefs.h>
#include <epan/show_exception.h>
#include <wsutil/report_message.h>

#include "opcua_infomodel.h"
#include "opcua_complextypeparser.h"
#include "opcua_hfindeces.h"
#include "infomodel_parser.h"

static int infomodel_proto;

static int hf_opcua_custom_optional_fields;

static expert_field ei_opcua_custom_not_implemented = EI_INIT;
static expert_field ei_opcua_custom_malformed = EI_INIT;

static const char *information_model_filename;
static unsigned int ns_offset;

/* information model, the file name it was loaded from, and the fields registered for its custom datatypes */
static Infomodel *infomodel;
static char *applied_filename;
static hf_register_info *custom_hf;

/* while registering the fields: hf_register_info, ett pointers, and the field type of each abbreviation */
static struct {
    GArray *hf;
    GArray *ett;
    GHashTable *abbrevs;
} infomodel_build_dict;

/* Modify the given string to make a suitable segment of a display filter    */
/*                                             copied from trdp plugin       */
/*                                             copied from wimaxasncp plugin */
static char* alnumerize(char* name) {
    char* r = name;  /* read pointer */
    char* w = name;  /* write pointer */
    char  c;

    for (; (c = *r); ++r) {
        if (g_ascii_isalnum(c) || c == '_') {            /* These characters are fine - copy them */
            *(w++) = c;
        } else if (c == ' ' || c == '-' || c == '/' || c == '.') { /* '.' would add a level to the filter name */
            if (w == name) continue;                      /* Skip these others if haven't written any characters out yet */

            if (*(w - 1) == '_') continue;                /* Skip if we would produce multiple adjacent '_'s */

            *(w++) = '_';                                 /* OK, replace with underscore */
        }
        /* Other undesirable characters are just skipped */
    }
    *w = '\0';                                            /* Terminate and return modified string */
    return name;
}

/* Segment of a field abbreviation for a type or field name, "<placeholder><k>" if nothing is left of the name
 * (e.g. an empty or non-ASCII one): Wireshark aborts on an empty segment. */
static char *abbrev_segment(const char *name, const char *placeholder, unsigned k)
{
    char *segment = alnumerize(g_strdup(name ? name : ""));

    if (!*segment) {
        g_free(segment);
        segment = g_strdup_printf("%s%u", placeholder, k);
    }
    return segment;
}

/* Different names can give the same abbreviation (1:Point and 2:Point, a-b and a_b). Wireshark chains fields of the
 * same type, and a filter on the abbreviation matches all of them. A field of another type gets a suffix: a filter
 * compares all chained fields with a value of one type. */
static void add_reg_info(
        int *hf_ptr,
        char *name,
        char *abbrev,
        enum ftenum type,
        int display) {
    char *base = abbrev;
    void *seen;
    unsigned n = 1;

    while (g_hash_table_lookup_extended(infomodel_build_dict.abbrevs, abbrev, NULL, &seen) &&
           GPOINTER_TO_INT(seen) != (int)type) {
        if (abbrev != base) g_free(abbrev);
        abbrev = g_strdup_printf("%s_%u", base, ++n);
    }
    if (abbrev != base) g_free(base);
    g_hash_table_insert(infomodel_build_dict.abbrevs, abbrev, GINT_TO_POINTER(type));

    hf_register_info hf = {
        hf_ptr, { name, abbrev, type, display, NULL, 0, NULL, HFILL }
    };
    g_array_append_val(infomodel_build_dict.hf, hf);
}

/* k: index of the field in its type */
static void add_field_reg_info(const char *typeSegment, Field *field, unsigned k) {
    char *name;
    char *abbrev;
    char *fieldSegment;

    AliasType aType = Field_find_atype(field, infomodel->aliases_first);
    if (aType == ALIAS_INVALID || field->valueRank >= 0) {
        /* insert ett if array or custom datatype */

        /* do not replace this variable by passing the address directly, */
        /* the GLib macro for append_val breaks otherwise */
        int *pett_id = &field->ett_id;
        g_array_append_val(infomodel_build_dict.ett, pett_id);
    }

    /* no hf for a field of a custom datatype (its own fields have theirs, an enumeration is shown as Int32) or of
     * LocalizedText (shown with the built-in fields); ett handled above */
    if (aType == ALIAS_INVALID || aType == ALIAS_LOCALIZEDTEXT) return;

    fieldSegment = abbrev_segment(field->name, "field", k);
    name = g_strdup(field->name && *field->name ? field->name : fieldSegment);
    abbrev = g_strdup_printf("opcua.custom_field.%s.%s", typeSegment, fieldSegment);
    g_free(fieldSegment);

    /* alias type, create according hf entry */
    switch (aType) {
    case ALIAS_BOOLEAN:
        add_reg_info(&field->hf_id, name, abbrev, FT_BOOLEAN, BASE_NONE);
        break;
    case ALIAS_SBYTE:
        add_reg_info(&field->hf_id, name, abbrev, FT_INT8, BASE_DEC);
        break;
    case ALIAS_BYTE:
        add_reg_info(&field->hf_id, name, abbrev, FT_UINT8, BASE_DEC);
        break;
    case ALIAS_INT16:
        add_reg_info(&field->hf_id, name, abbrev, FT_INT16, BASE_DEC);
        break;
    case ALIAS_UINT16:
        add_reg_info(&field->hf_id, name, abbrev, FT_UINT16, BASE_DEC);
        break;
    case ALIAS_INT32:
        add_reg_info(&field->hf_id, name, abbrev, FT_INT32, BASE_DEC);
        break;
    case ALIAS_UINT32:
        add_reg_info(&field->hf_id, name, abbrev, FT_UINT32, BASE_DEC);
        break;
    case ALIAS_INT64:
        add_reg_info(&field->hf_id, name, abbrev, FT_INT64, BASE_DEC);
        break;
    case ALIAS_UINT64:
        add_reg_info(&field->hf_id, name, abbrev, FT_UINT64, BASE_DEC);
        break;
    case ALIAS_FLOAT:
        add_reg_info(&field->hf_id, name, abbrev, FT_FLOAT, BASE_NONE);
        break;
    case ALIAS_DOUBLE:
        add_reg_info(&field->hf_id, name, abbrev, FT_DOUBLE, BASE_NONE);
        break;
    case ALIAS_DATETIME:
        add_reg_info(&field->hf_id, name, abbrev, FT_ABSOLUTE_TIME, ABSOLUTE_TIME_LOCAL);
        break;
    case ALIAS_UTCTIME:
        add_reg_info(&field->hf_id, name, abbrev, FT_ABSOLUTE_TIME, ABSOLUTE_TIME_UTC);
        break;
    case ALIAS_STRING:
        add_reg_info(&field->hf_id, name, abbrev, FT_STRING, BASE_NONE);
        break;
    default:
        add_reg_info(&field->hf_id, name, abbrev, FT_BYTES, BASE_NONE);
    }
}

static bool dissect_custom_datatype(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, CustomDatatype *type);

/* Array of a custom datatype: Int32 length (-1: null array), then the elements (OPC UA Part 6, 5.2.5). */
// NOLINTNEXTLINE(misc-no-recursion)
static bool dissect_custom_datatype_array(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, Field *field, CustomDatatype *ctype)
{
    proto_item *ti;
    proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, *pOffset, -1, field->ett_id, &ti, "%s: Array of %s", field->name, ctype->name);
    int32_t iLen = tvb_get_letohil(tvb, *pOffset);
    bool ok = true;

    proto_tree_add_item(subtree, hf_opcua_ArraySize, tvb, *pOffset, 4, ENC_LITTLE_ENDIAN);
    if (iLen > MAX_ARRAY_LEN) {
        /* the rest of the body cannot be located */
        proto_tree_add_expert_format(subtree, pinfo, &ei_array_length, tvb, *pOffset, 4, "Array length %d too large to process", iLen);
        return false;
    }
    *pOffset += 4;
    for (int32_t i = 0; ok && i < iLen; i++) {
        int start = *pOffset;
        proto_item *eti;
        proto_tree *etree = proto_tree_add_subtree_format(subtree, tvb, *pOffset, -1, ctype->ett_id, &eti, "[%d]", i);
        ok = dissect_custom_datatype(etree, tvb, pinfo, pOffset, ctype);
        proto_item_set_end(eti, tvb, *pOffset);
        if (*pOffset == start) break; /* empty elements (e.g. structure without fields), nothing more to show */
    }
    proto_item_set_end(ti, tvb, *pOffset);
    return ok;
}

/* Dissect a value of a custom datatype of the information model.
 * false: stopped at a field that cannot be dissected, the rest of the body cannot be located. */
// NOLINTNEXTLINE(misc-no-recursion)
static bool dissect_custom_datatype(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int *pOffset, CustomDatatype *type)
{
    int iOffset = *pOffset;
    uint32_t optionalMask = 0;
    unsigned optionalIdx = 0;
    bool ok = true;

    increment_dissection_depth(pinfo);

    if (type->subtype != SUBTYPE_STRUCT) {
        switch (type->subtype)
        {
        case SUBTYPE_BOOLEAN: parseBoolean(tree, tvb, pinfo, &iOffset, hf_opcua_Boolean); break;
        case SUBTYPE_SBYTE: parseSByte(tree, tvb, pinfo, &iOffset, hf_opcua_SByte); break;
        case SUBTYPE_BYTE: parseByte(tree, tvb, pinfo, &iOffset, hf_opcua_Byte); break;
        case SUBTYPE_INT16: parseInt16(tree, tvb, pinfo, &iOffset, hf_opcua_Int16); break;
        case SUBTYPE_UINT16: parseUInt16(tree, tvb, pinfo, &iOffset, hf_opcua_UInt16); break;
        case SUBTYPE_INT32: parseInt32(tree, tvb, pinfo, &iOffset, hf_opcua_Int32); break;
        case SUBTYPE_UINT32: parseUInt32(tree, tvb, pinfo, &iOffset, hf_opcua_UInt32); break;
        case SUBTYPE_INT64: parseInt64(tree, tvb, pinfo, &iOffset, hf_opcua_Int64); break;
        case SUBTYPE_UINT64: parseUInt64(tree, tvb, pinfo, &iOffset, hf_opcua_UInt64); break;
        case SUBTYPE_FLOAT: parseFloat(tree, tvb, pinfo, &iOffset, hf_opcua_Float); break;
        case SUBTYPE_DOUBLE: parseDouble(tree, tvb, pinfo, &iOffset, hf_opcua_Double); break;
        case SUBTYPE_DATETIME: parseDateTime(tree, tvb, pinfo, &iOffset, hf_opcua_DateTime); break;
        case SUBTYPE_STRING: parseString(tree, tvb, pinfo, &iOffset, hf_opcua_String); break;
        case SUBTYPE_BYTESTRING: parseByteString(tree, tvb, pinfo, &iOffset, hf_opcua_ByteString); break;
        /* enumerations are encoded as Int32 (OPC UA Part 6, 5.2.4) */
        case SUBTYPE_ENUM: parseInt32(tree, tvb, pinfo, &iOffset, hf_opcua_Int32); break;

        case SUBTYPE_OPTIONSET:
            /* TODO improve OptionSet parsing by actually respecting the Custom Datatype's fields */
            /* https://reference.opcfoundation.org/v104/Core/docs/Part3/8.41/ */
            parseOptionSet(tree, tvb, pinfo, &iOffset, type->name); break;

        case SUBTYPE_CUSTOM: ok = dissect_custom_datatype(tree, tvb, pinfo, &iOffset, type->customSubtype); break;
        default:
            break;
        }
        /* unions, types with an unknown parent, derived structures (after the parent's fields): the rest of the
         * body cannot be located */
        if (ok && (type->subtype == SUBTYPE_UNDEFINED || type->subtype == SUBTYPE_INVALID || type->fieldsIgnored)) {
            proto_tree_add_expert_format(tree, pinfo, &ei_opcua_custom_not_implemented, tvb, iOffset, 0,
                "Custom type %s: %s not yet implemented", type->name,
                type->subtype == SUBTYPE_CUSTOM ? "fields of derived structures" : "unions and types with an unknown parent");
            ok = false;
        }
        goto done;
    }

    /* structure: fields in order, optional ones only if their bit in the encoding mask is set */
    if (type->hasOptionalFields) {
        proto_tree_add_item_ret_uint(tree, hf_opcua_custom_optional_fields, tvb, iOffset, 4, ENC_LITTLE_ENDIAN, &optionalMask);
        iOffset += 4;
    }
    for (Field *field = type->fields_first; field; field = field->next) {
        if (field->isOptional) {
            /* one bit per optional field (OPC UA Part 6, 5.2.7) */
            bool present = optionalIdx < 32 && (optionalMask & (1u << optionalIdx));
            optionalIdx++;
            if (!present) continue;
        }
        AliasType aType = Field_find_atype(field, infomodel->aliases_first);
        CustomDatatype *ctype = NULL;
        if (aType == ALIAS_INVALID && !(ctype = CustomDatatype_find(infomodel->customDatatype_first, field->type))) {
            proto_tree_add_expert_format(tree, pinfo, &ei_opcua_custom_malformed, tvb, iOffset, 0,
                "Datatype of field %s not found in the information model", field->name);
            ok = false;
            goto done;
        }
        if (field->valueRank < -1) {
            /* -2 (Any) and -3 (ScalarOrOneDimension) are for variables, not structure fields */
            proto_tree_add_expert_format(tree, pinfo, &ei_opcua_custom_malformed, tvb, iOffset, 0,
                "Field %s: ValueRank %d is not valid in a structure", field->name, field->valueRank);
            ok = false;
            goto done;
        }
        if (field->allowSubTypes || field->valueRank > 1) {
            /* the field would be an ExtensionObject/Variant resp. a matrix (dimensions, then the values) */
            proto_tree_add_expert_format(tree, pinfo, &ei_opcua_custom_not_implemented, tvb, iOffset, 0,
                "Field %s: %s not yet implemented", field->name, field->allowSubTypes ? "AllowSubTypes" : "Multi-dimensional arrays");
            ok = false;
            goto done;
        }
        if (field->valueRank >= 0) {
            char const *typeName = "";
            fctSimpleTypeParser parseFct = NULL;
            fctComplexTypeParser parseCmplxFct = NULL;
            switch (aType)
            {
            case ALIAS_BOOLEAN:
                typeName = "Boolean"; parseFct = parseBoolean; break;
            case ALIAS_SBYTE:
                typeName = "SByte"; parseFct = parseSByte; break;
            case ALIAS_BYTE:
                typeName = "Byte"; parseFct = parseByte; break;
            case ALIAS_INT16:
                typeName = "Int16"; parseFct = parseInt16; break;
            case ALIAS_UINT16:
                typeName = "UInt16"; parseFct = parseUInt16; break;
            case ALIAS_INT32:
                typeName = "Int32"; parseFct = parseInt32; break;
            case ALIAS_UINT32:
                typeName = "UInt32"; parseFct = parseUInt32; break;
            case ALIAS_FLOAT:
                typeName = "Float"; parseFct = parseFloat; break;
            case ALIAS_INT64:
                typeName = "Int64"; parseFct = parseInt64; break;
            case ALIAS_UINT64:
                typeName = "UInt64"; parseFct = parseUInt64; break;
            case ALIAS_DOUBLE:
                typeName = "Double"; parseFct = parseDouble; break;
            case ALIAS_STRING:
                typeName = "String"; parseFct = parseString; break;
            case ALIAS_DATETIME:
                typeName = "DateTime"; parseFct = parseDateTime; break;
            case ALIAS_UTCTIME:
                typeName = "UtcTime"; parseFct = parseDateTime; break;
            case ALIAS_BYTESTRING:
                typeName = "ByteString"; parseFct = parseByteString; break;
            case ALIAS_LOCALIZEDTEXT:
                typeName = "LocalizedText"; parseCmplxFct = parseLocalizedText; break;
            case ALIAS_INVALID: /* custom datatype */
                if (!(ok = dissect_custom_datatype_array(tree, tvb, pinfo, &iOffset, field, ctype)))
                    goto done;
                break;
            default:
                break;
            }
            /* the built-in parsers add opcua.array.length for a longer array and return before its elements */
            bool tooLong = (parseFct || parseCmplxFct) && tvb_get_letohil(tvb, iOffset) > MAX_ARRAY_LEN;
            if (parseFct) {
                parseArraySimple(tree, tvb, pinfo, &iOffset, field->name, typeName, field->hf_id, parseFct, field->ett_id);
            }
            if (parseCmplxFct) {
                parseArrayComplex(tree, tvb, pinfo, &iOffset, field->name, typeName, parseCmplxFct, field->ett_id);
            }
            if (tooLong) {
                ok = false; /* the rest of the body cannot be located */
                goto done;
            }
        }
        else if (aType != ALIAS_INVALID) {
            int len = 0;
            switch (aType) {
            case ALIAS_BOOLEAN:
            case ALIAS_SBYTE:
            case ALIAS_BYTE:
                len = 1;
                break;
            case ALIAS_INT16:
            case ALIAS_UINT16:
                len = 2;
                break;
            case ALIAS_INT32:
            case ALIAS_UINT32:
            case ALIAS_FLOAT:
                len = 4;
                break;
            case ALIAS_INT64:
            case ALIAS_UINT64:
            case ALIAS_DOUBLE:
                len = 8;
                break;
            case ALIAS_STRING:
                parseString(tree, tvb, pinfo, &iOffset, field->hf_id);
                break;
            case ALIAS_BYTESTRING:
                parseByteString(tree, tvb, pinfo, &iOffset, field->hf_id);
                break;
            case ALIAS_LOCALIZEDTEXT:
                parseLocalizedText(tree, tvb, pinfo, &iOffset, field->name);
                break;
            case ALIAS_DATETIME:
            case ALIAS_UTCTIME:
                parseDateTime(tree, tvb, pinfo, &iOffset, field->hf_id);
                break;
            default:
                break;
            }
            if (len) {
                proto_tree_add_item(tree, field->hf_id, tvb, iOffset, len, ENC_LITTLE_ENDIAN);
                iOffset += len;
            }
        }
        else { /* no alias type found --> custom datatype */
            proto_item *ti;
            proto_tree *subtree = proto_tree_add_subtree_format(tree, tvb, iOffset, -1, field->ett_id, &ti, "%s (%s)", field->name, ctype->name);
            ok = dissect_custom_datatype(subtree, tvb, pinfo, &iOffset, ctype);
            proto_item_set_end(ti, tvb, iOffset);
            if (!ok) goto done;
        }
    }

done:
    decrement_dissection_depth(pinfo);
    *pOffset = iOffset;
    return ok;
}

/* Body of an ExtensionObject of a custom datatype, on its own: a model that does not match the body must not
 * break the rest of the packet. The TRY is in a function of its own, else GCC warns about clobbered locals. */
static void dissect_custom_body(proto_tree *tree, tvbuff_t *body_tvb, packet_info *pinfo, CustomDatatype *type)
{
    proto_tree *subtree = proto_tree_add_subtree_format(tree, body_tvb, 0, -1, type->ett_id, NULL, "Custom Type (%s)", type->name);
    unsigned depth = pinfo->dissection_depth;

    TRY {
        int body_offset = 0;
        /* stopped: the offset is meaningless, the expert info is already there */
        if (dissect_custom_datatype(subtree, body_tvb, pinfo, &body_offset, type) &&
            tvb_reported_length_remaining(body_tvb, body_offset) > 0) {
            proto_tree_add_expert_format_remaining(subtree, pinfo, &ei_opcua_custom_malformed, body_tvb, body_offset,
                "%u bytes of the body not dissected, check the information model", tvb_reported_length_remaining(body_tvb, body_offset));
        }
    }
    CATCH_BOUNDS_ERRORS {
        pinfo->dissection_depth = depth; /* the exception skipped the decrements */
        show_exception(body_tvb, pinfo, subtree, EXCEPT_CODE, GET_MESSAGE);
    }
    ENDTRY;
}

/* Does the NodeId from the information model (plus namespace offset) match the ExtensionObject's TypeId? */
static bool typeid_matches(const Datatype *id, const ExtensionObjectTypeId *typeId)
{
    if (id->ns + ns_offset != typeId->ns) return false;
    switch (id->idType) {
    case DATATYPEID_NUMERIC:
        return typeId->isNumeric && id->id_num == typeId->numeric;
    case DATATYPEID_STRING:
        return typeId->string && !strcmp(id->id_str, typeId->string);
    default:
        return false;
    }
}

bool opcua_infomodel_dissect(proto_tree *tree, tvbuff_t *tvb, packet_info *pinfo, int offset, int length,
                             const ExtensionObjectTypeId *typeId)
{
    if (!infomodel) return false;

    /* the TypeId is the NodeId of the datatype's encoding object */
    UAObject *object = infomodel->objects_first;
    while (object && !typeid_matches(&object->id, typeId)) object = object->next;
    if (!object) return false;

    CustomDatatype *type = CustomDatatype_find(infomodel->customDatatype_first, object->refEncodingRaw);
    if (!type) return false;

    dissect_custom_body(tree, tvb_new_subset_length(tvb, offset, length), pinfo, type);
    return true;
}

/* Unload the information model and deregister the fields of its custom datatypes (also the shutdown routine). */
static void unload_information_model(void)
{
    if (custom_hf) {
        proto_deregister_all_fields_with_prefix(infomodel_proto, "opcua.custom_field.");
        /* the deregistered fields point into the array, Wireshark frees it after them */
        proto_add_deregistered_data(custom_hf);
        custom_hf = NULL;
    }
    Infomodel_delete(infomodel);
    infomodel = NULL;
    g_free(applied_filename);
    applied_filename = NULL;
}

void opcua_infomodel_apply(void)
{
    const char *filename = information_model_filename && *information_model_filename ? information_model_filename : NULL;
    GError *err = NULL;

    /* only a new file name reloads the model, edits to the same file need a restart */
    if (g_strcmp0(filename, applied_filename) == 0) return;
    unload_information_model();
    if (!filename) return;
    applied_filename = g_strdup(filename); /* also if it cannot be parsed: reported once */

    infomodel = parseXml(filename, &err);
    if (err) {
        report_failure("OPC UA: Information Model %s: %s", filename, err->message);
        g_error_free(err);
    }
    if (!infomodel) return;

    infomodel_build_dict.hf = g_array_new(false, false, sizeof(hf_register_info));
    infomodel_build_dict.ett = g_array_new(false, false, sizeof(int *));
    infomodel_build_dict.abbrevs = g_hash_table_new(g_str_hash, g_str_equal); /* the keys belong to the hf array */

    unsigned k = 0;
    for (CustomDatatype *cd = infomodel->customDatatype_first; cd; cd = cd->next, k++) {
        char *typeSegment = abbrev_segment(cd->name, "type", k);
        unsigned j = 0;
        /* only structures have fields to show; those of enumerations and option sets are their values */
        for (Field *f = cd->subtype == SUBTYPE_STRUCT ? cd->fields_first : NULL; f; f = f->next, j++) {
            add_field_reg_info(typeSegment, f, j);
        }
        g_free(typeSegment);
        int *pett_id = &cd->ett_id;
        g_array_append_val(infomodel_build_dict.ett, pett_id);
    }

    proto_register_field_array(infomodel_proto, (hf_register_info *)(void *)infomodel_build_dict.hf->data,
        (int)infomodel_build_dict.hf->len);
    proto_register_subtree_array((int **)(void *)infomodel_build_dict.ett->data, (int)infomodel_build_dict.ett->len);

    /* the fields keep pointing into the hf array until they are deregistered, the ett array is not kept */
    custom_hf = (hf_register_info *)(void *)g_array_free(infomodel_build_dict.hf, false);
    g_array_free(infomodel_build_dict.ett, true);
    g_hash_table_destroy(infomodel_build_dict.abbrevs);
    infomodel_build_dict.hf = infomodel_build_dict.ett = NULL;
    infomodel_build_dict.abbrevs = NULL;
}

void opcua_infomodel_register(int proto, module_t *module)
{
    static hf_register_info hf[] = {
        { &hf_opcua_custom_optional_fields, { "Optional Fields Encoding Mask", "opcua.custom.optional_fields", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } }
    };

    static ei_register_info ei[] = {
        { &ei_opcua_custom_not_implemented, { "opcua.custom.not_implemented", PI_UNDECODED, PI_WARN,  "This feature is not yet implemented", EXPFILL } },
        { &ei_opcua_custom_malformed,       { "opcua.custom.malformed",       PI_MALFORMED, PI_ERROR, "Dissection of the custom datatype failed", EXPFILL } }
    };

    infomodel_proto = proto;
    register_shutdown_routine(unload_information_model);
    proto_register_field_array(proto, hf, array_length(hf));
    expert_register_field_array(expert_register_protocol(proto), ei, array_length(ei));

    prefs_register_filename_preference(module, "information_model", "Information Model",
        "UANodeSet XML file with custom datatypes. Used to decode ExtensionObjects of these types "
        "in OPC UA client/server and PubSub messages.", &information_model_filename, false);
    prefs_register_uint_preference(module, "ns_offset", "Namespace Offset",
        "Added to every namespace index of the information model file to get the index in the packets. "
        "Example: the file defines its types in ns=1, the server has that namespace at index 3: offset 2. "
        "One offset for the whole capture and all namespaces of the file.", 10, &ns_offset);
    prefs_set_preference_effect_fields(module, "information_model");
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
