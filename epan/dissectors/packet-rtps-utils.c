/* packet-rtps-utils.c
 * ~~~~~~~~~~~~~
 *
 * The following file contains helper routines for the RTPS packet dissector
 *
 * (c) 2005-2020 Copyright, Real-Time Innovations, Inc.
 * Real-Time Innovations, Inc.
 * 232 East Java Drive
 * Sunnyvale, CA 94089
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 *                  -------------------------------------
 *
 * The following file is part of the RTPS packet dissector for Wireshark.
 *
 * RTPS protocol was developed by Real-Time Innovations, Inc. as wire
 * protocol for Data Distribution System.
 * Additional information at:
 *
 *   OMG DDS standards: http://portals.omg.org/dds/omg-dds-standard/
 *
 *   Older OMG DDS specification:
 *                             http://www.omg.org/cgi-bin/doc?ptc/2003-07-07
 *
 *   NDDS and RTPS information: http://www.rti.com/resources.html
 *
 */

#include "config.h"

#include <epan/packet.h>
#include "packet-rtps.h"

static wmem_map_t * dissection_infos = NULL;
static wmem_map_t * union_member_mappings = NULL;
static wmem_map_t * mutable_member_mappings = NULL;

#define DISSECTION_INFO_MAX_ELEMENTS    (100)
#define MAX_MEMBER_NAME                 (256)
#define HASHMAP_DISCRIMINATOR_CONSTANT  (-2)

typedef struct _union_member_mapping {
    guint64 union_type_id;
    guint64 member_type_id;
    gint32  discriminator;
    gchar member_name[MAX_MEMBER_NAME];
} union_member_mapping;

typedef struct _mutable_member_mapping {
    gint64 key;
    guint64 struct_type_id;
    guint64 member_type_id;
    guint32 member_id;
    gchar member_name[MAX_MEMBER_NAME];
} mutable_member_mapping;

typedef struct _dissection_element {
    guint64 type_id;
    guint16 flags;
    guint32 member_id;
    gchar member_name[MAX_MEMBER_NAME];
} dissection_element;

typedef struct _dissection_info {
  guint64 type_id;
  gint member_kind;
  guint64 base_type_id;
  guint32 member_length;
  gchar member_name[MAX_MEMBER_NAME];

  RTICdrTypeObjectExtensibility extensibility;

  gint32 bound;
  gint32 num_elements;
  dissection_element elements[DISSECTION_INFO_MAX_ELEMENTS];

} dissection_info;

gint dissect_user_defined(proto_tree *tree, tvbuff_t * tvb, gint offset, guint encoding,
        dissection_info * _info, guint64 type_id, gchar * name,
        RTICdrTypeObjectExtensibility extensibility, gint offset_zero,
        guint16 flags, guint32 element_member_id);

static
gint dissect_mutable_member(proto_tree *tree , tvbuff_t * tvb, gint offset, guint encoding,
        dissection_info * info, gboolean * is_end) {

    proto_tree * member;
    guint32 member_id, member_length;
    mutable_member_mapping * mapping;
    gint64 key;

    rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
    if ((member_id & PID_LIST_END) == PID_LIST_END){
    /* If this is the end of the list, don't add a tree.
    * If we add more logic here in the future, take into account that
    * offset is incremented by 4 */
        offset += 0;
        *is_end = TRUE;
        return offset;
    }
    if (member_length == 0){
        return offset;
    }
    member = proto_tree_add_subtree_format(tree, tvb, offset, member_length, ett_rtps_dissection_tree,
        NULL, "ID: %d, Length: %d", member_id, member_length);

    {
        if (info->base_type_id > 0) {
            key = (info->base_type_id + info->base_type_id * member_id);
            mapping = (mutable_member_mapping *) wmem_map_lookup(mutable_member_mappings, &(key));
            if (mapping) { /* the library knows how to dissect this */
                proto_item_append_text(member, "(base found 0x%016" G_GINT64_MODIFIER "x)", key);
                dissect_user_defined(tree, tvb, offset, encoding, NULL, mapping->member_type_id,
                    mapping->member_name, EXTENSIBILITY_INVALID, offset, 0, mapping->member_id);
                PROTO_ITEM_SET_HIDDEN(member);
                return offset + member_length;
            } else
                proto_item_append_text(member, "(base not found 0x%016" G_GINT64_MODIFIER "x from 0x%016" G_GINT64_MODIFIER "x)",
                  key, info->base_type_id);
        }
    }

    key = (info->type_id + info->type_id * member_id);
    mapping = (mutable_member_mapping *) wmem_map_lookup(mutable_member_mappings, &(key));
    if (mapping) { /* the library knows how to dissect this */
        proto_item_append_text(member, "(found 0x%016" G_GINT64_MODIFIER "x)", key);
        dissect_user_defined(tree, tvb, offset, encoding, NULL, mapping->member_type_id,
            mapping->member_name, EXTENSIBILITY_INVALID, offset, 0, mapping->member_id);

    } else
        proto_item_append_text(member, "(not found 0x%016" G_GINT64_MODIFIER "x from 0x%016" G_GINT64_MODIFIER "x)",
                  key, info->type_id);
    PROTO_ITEM_SET_HIDDEN(member);
    return offset + member_length;
}

/* this is a recursive function. _info may or may not be NULL depending on the use iteration */
gint dissect_user_defined(proto_tree *tree, tvbuff_t * tvb, gint offset, guint encoding,
        dissection_info * _info, guint64 type_id, gchar * name,
        RTICdrTypeObjectExtensibility extensibility, gint offset_zero,
        guint16 flags, guint32 element_member_id) {

    guint64 member_kind;
    dissection_info * info = NULL;
    guint32 member_id, member_length;

    if (_info)  { /* first call enters here */
      info = _info;
      member_kind = info->member_kind;
    } else {
      info = (dissection_info *) wmem_map_lookup(dissection_infos, &(type_id));
      if (info != NULL) {
        member_kind = info->member_kind;
      } else {
        member_kind = type_id;
      }
    }
    if (info && (flags & MEMBER_OPTIONAL) == MEMBER_OPTIONAL) {
        gint offset_before = offset;
        rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
        offset = offset_before;
        if (element_member_id != 0 && member_id != element_member_id)
            return offset;
    }
    if (extensibility == EXTENSIBILITY_MUTABLE) {
      rtps_util_dissect_parameter_header(tvb, &offset, encoding, &member_id, &member_length);
      offset_zero = offset;
      if ((member_id & PID_LIST_END) == PID_LIST_END){
       /* If this is the end of the list, don't add a tree.
       * If we add more logic here in the future, take into account that
       * offset is incremented by 4 */
          offset += 0;
          return offset;
      }
      if (member_length == 0){
          return offset;
      }
    }
    //proto_item_append_text(tree, "(Before Switch 0x%016" G_GINT64_MODIFIER "x)", type_id);

    switch (member_kind) {
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_BOOLEAN_TYPE: {
            gint length = 1;
            ALIGN_ZERO(offset, length, offset_zero);
            gint16 value =  tvb_get_gint8(tvb, offset);
            proto_tree_add_boolean_format(tree, hf_rtps_dissection_boolean, tvb, offset, length, value,
                "%s: %d", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_CHAR_8_TYPE:
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_BYTE_TYPE: {
            gint length = 1;
            ALIGN_ZERO(offset, length, offset_zero);
            gint16 value =  tvb_get_gint8(tvb, offset);
            proto_tree_add_uint_format(tree, hf_rtps_dissection_byte, tvb, offset, length, value,
                "%s: %d", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_16_TYPE: {
            gint length = 2;
            ALIGN_ZERO(offset, length, offset_zero);
            gint16 value =  tvb_get_gint16(tvb, offset, encoding);
            proto_tree_add_int_format(tree, hf_rtps_dissection_int16, tvb, offset, length, value,
                "%s: %d", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_16_TYPE: {
            gint length = 2;
            ALIGN_ZERO(offset, length, offset_zero);
            guint16 value =  tvb_get_guint16(tvb, offset, encoding);
            proto_tree_add_uint_format(tree, hf_rtps_dissection_uint16, tvb, offset, length, value,
                "%s: %u", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ENUMERATION_TYPE:
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_32_TYPE: {
            gint length = 4;
            ALIGN_ZERO(offset, length, offset_zero);
            gint value =  tvb_get_gint32(tvb, offset, encoding);
            proto_tree_add_int_format(tree, hf_rtps_dissection_int32, tvb, offset, length, value,
                "%s: %d", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_32_TYPE: {
            gint length = 4;
            ALIGN_ZERO(offset, length, offset_zero);
            guint value =  tvb_get_guint32(tvb, offset, encoding);
            proto_tree_add_uint_format(tree, hf_rtps_dissection_uint32, tvb, offset, length, value,
                "%s: %u", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_64_TYPE: {
            gint length = 8;
            ALIGN_ZERO(offset, length, offset_zero);
            gint64 value =  tvb_get_gint64(tvb, offset, encoding);
            proto_tree_add_int64_format(tree, hf_rtps_dissection_int64, tvb, offset, length, value,
                "%s: %"G_GINT64_MODIFIER"d", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UINT_64_TYPE: {
            gint length = 8;
            ALIGN_ZERO(offset, length, offset_zero);
            guint64 value =  tvb_get_guint64(tvb, offset, encoding);
            proto_tree_add_uint64_format(tree, hf_rtps_dissection_uint64, tvb, offset, length, value,
                "%s: %"G_GINT64_MODIFIER"u", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_32_TYPE: {
            gint length = 4;
            ALIGN_ZERO(offset, length, offset_zero);
            gfloat value =  tvb_get_ieee_float(tvb, offset, encoding);
            proto_tree_add_float_format(tree, hf_rtps_dissection_float, tvb, offset, length, value,
                "%s: %.6f", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_64_TYPE: {
            gint length = 8;
            ALIGN_ZERO(offset, length, offset_zero);
            gdouble value =  tvb_get_ieee_double(tvb, offset, encoding);
            proto_tree_add_double_format(tree, hf_rtps_dissection_double, tvb, offset, length, value,
                "%s: %.6f", name, value);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_FLOAT_128_TYPE: {
            gint length = 16;
            ALIGN_ZERO(offset, length, offset_zero);
            proto_tree_add_item(tree, hf_rtps_dissection_int128, tvb, offset, length, encoding);
            offset += length;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ARRAY_TYPE: {
            gint i;
            proto_tree * aux_tree;
            gint base_offset = offset;

            aux_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rtps_dissection_tree,
                  NULL, name);
            for (i = 0; i < info->bound; i++) {
                gchar temp_buff[MAX_MEMBER_NAME];
                g_snprintf(temp_buff, MAX_MEMBER_NAME, "%s[%u]", name, i);
                offset = dissect_user_defined(aux_tree, tvb, offset, encoding, NULL,
                        info->base_type_id, temp_buff, EXTENSIBILITY_INVALID, offset_zero, 0, 0);
            }
            proto_item_set_len(aux_tree, offset - base_offset);
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_SEQUENCE_TYPE: {
            guint i;
            proto_tree * aux_tree;
            gint base_offset = offset;

            gint length = 4;
            ALIGN_ZERO(offset, length, offset_zero);
            guint seq_size =  tvb_get_guint32(tvb, offset, encoding);
            aux_tree = proto_tree_add_subtree_format(tree, tvb, offset, -1, ett_rtps_dissection_tree,
                  NULL, "%s (%u elements)", name, seq_size);
            offset += 4;

            for (i = 0; i < seq_size; i++) {
                gchar temp_buff[MAX_MEMBER_NAME];
                g_snprintf(temp_buff, MAX_MEMBER_NAME, "%s[%u]", name, i);
                if (info->base_type_id > 0)
                    offset = dissect_user_defined(aux_tree, tvb, offset, encoding, NULL,
                         info->base_type_id, temp_buff, EXTENSIBILITY_INVALID, offset_zero, 0, 0);
            }
            proto_item_set_len(aux_tree, offset - base_offset);
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRING_TYPE: {
            gchar * string_value = NULL;
            gint length = 4;
            ALIGN_ZERO(offset, length, offset_zero);

            guint string_size =  tvb_get_guint32(tvb, offset, encoding);
            offset += 4;
            //proto_item_append_text(tree, "(String length: %u)", string_size);

            string_value = tvb_get_string_enc(wmem_packet_scope(), tvb, offset, string_size, ENC_ASCII);
            proto_tree_add_string_format(tree, hf_rtps_dissection_string, tvb, offset, string_size,
                string_value, "%s: %s", name, string_value);

            offset += string_size;
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ALIAS_TYPE: {
            offset = dissect_user_defined(tree, tvb, offset, encoding, NULL,
                         info->base_type_id, name, EXTENSIBILITY_INVALID, offset_zero, 0, 0);
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_UNION_TYPE: {
            guint64 key = type_id - 1;
            union_member_mapping * result = (union_member_mapping *)wmem_map_lookup(union_member_mappings, &(key));

            if (result != NULL) {
                switch (result->member_type_id) {
                    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_ENUMERATION_TYPE:
                    case RTI_CDR_TYPE_OBJECT_TYPE_KIND_INT_32_TYPE: {
                        gint value =  tvb_get_gint32(tvb, offset, encoding);
                        offset += 4;
                        key = type_id + value;
                        result = (union_member_mapping *)wmem_map_lookup(union_member_mappings, &(key));
                        if (result != NULL) {
                          proto_item_append_text(tree, " (discriminator = %d, type_id = 0x%016" G_GINT64_MODIFIER "x)",
                               value, result->member_type_id);
                          offset = dissect_user_defined(tree, tvb, offset, encoding, NULL,
                             result->member_type_id, result->member_name, EXTENSIBILITY_INVALID, offset, 0, 0);
                        } else {
                            /* the hashmap uses the type_id to index the objects. substracting -2 here to lookup the discriminator
                               related to the type_id that identifies an union */
                            key = type_id + HASHMAP_DISCRIMINATOR_CONSTANT;
                            result = (union_member_mapping *)wmem_map_lookup(union_member_mappings, &(key));
                            if (result != NULL) {
                            proto_item_append_text(tree, " (discriminator = %d, type_id = 0x%016" G_GINT64_MODIFIER "x)",
                                value, result->member_type_id);
                            offset = dissect_user_defined(tree, tvb, offset, encoding, NULL,
                                result->member_type_id, result->member_name, EXTENSIBILITY_INVALID, offset, 0, 0);
                            }
                        }
                        break;
                    }
                    default:
                        break;
                }
            } else {
              proto_item_append_text(tree, "(NULL 0x%016" G_GINT64_MODIFIER "x)", type_id);
            }
            break;
        }
        case RTI_CDR_TYPE_OBJECT_TYPE_KIND_STRUCTURE_TYPE: {
            gint i;
            proto_tree * aux_tree;

            offset_zero = offset;
            aux_tree = proto_tree_add_subtree(tree, tvb, offset, -1, ett_rtps_dissection_tree,
                  NULL, name);

            if (info->extensibility == EXTENSIBILITY_MUTABLE) {
                gboolean is_end = FALSE;
                while(!is_end)
                    offset = dissect_mutable_member(aux_tree, tvb, offset, encoding, info, &is_end);
                } else {
                if (info->base_type_id > 0) {
                    proto_item_append_text(tree, "(BaseId: 0x%016" G_GINT64_MODIFIER "x)", info->base_type_id);
                    offset = dissect_user_defined(aux_tree, tvb, offset, encoding, NULL,
                            info->base_type_id, info->member_name, EXTENSIBILITY_INVALID,
                            offset, 0, 0);
                }

                for (i = 0; i < info->num_elements && i < DISSECTION_INFO_MAX_ELEMENTS; i++) {
                    if (info->elements[i].type_id > 0)
                            offset = dissect_user_defined(aux_tree, tvb, offset, encoding, NULL,
                                info->elements[i].type_id, info->elements[i].member_name, info->extensibility,
                                offset_zero, info->elements[i].flags, info->elements[i].member_id);
                }
            }
            break;
        }
        default:{
            /* undefined behavior. this should not happen. the following line helps to debug if it happened */
            proto_item_append_text(tree, "(unknown 0x%016" G_GINT64_MODIFIER "x)", member_kind);
            break;
        }
    }

    if (extensibility == EXTENSIBILITY_MUTABLE) {
        offset_zero += member_length;
        return offset_zero;
    } else {
        return offset;
    }
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
