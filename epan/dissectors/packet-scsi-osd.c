/* packet-scsi-osd.c
 * Dissector for the SCSI OSD (object based storage) commandset
 *
 * Ronnie sahlberg 2006
 * Joe Breher 2006
 * Javier Godoy 2013 (OSD-2 dissector)
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 2002 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/wmem/wmem.h>
#include <epan/conversation.h>
#include <epan/tap.h>
#include <epan/expert.h>
#include "packet-scsi.h"
#include "packet-fc.h"
#include "packet-scsi-osd.h"

void proto_register_scsi_osd(void);
void proto_reg_handoff_scsi_osd(void);

static int proto_scsi_osd                               = -1;
int hf_scsi_osd_opcode                                  = -1;
static int hf_scsi_osd_add_cdblen                       = -1;
static int hf_scsi_osd_svcaction                        = -1;
static int hf_scsi_osd_option                           = -1;
static int hf_scsi_osd_option_dpo                       = -1;
static int hf_scsi_osd_option_fua                       = -1;
static int hf_scsi_osd_getsetattrib                     = -1;
static int hf_scsi_osd_timestamps_control               = -1;
static int hf_scsi_osd_formatted_capacity               = -1;
static int hf_scsi_osd_get_attributes_page              = -1;
static int hf_scsi_osd_get_attributes_allocation_length = -1;
static int hf_scsi_osd_get_attributes_list_length       = -1;
static int hf_scsi_osd_get_attributes_list_offset       = -1;
static int hf_scsi_osd_retrieved_attributes_offset      = -1;
static int hf_scsi_osd_set_attributes_page              = -1;
static int hf_scsi_osd_set_attribute_length             = -1;
static int hf_scsi_osd_set_attribute_number             = -1;
static int hf_scsi_osd_set_attributes_offset            = -1;
static int hf_scsi_osd_set_attributes_list_length       = -1;
static int hf_scsi_osd_set_attributes_list_offset       = -1;
static int hf_scsi_osd_capability_format                = -1;
static int hf_scsi_osd_key_version                      = -1;
static int hf_scsi_osd_icva                             = -1;
static int hf_scsi_osd_security_method                  = -1;
static int hf_scsi_osd_capability_expiration_time       = -1;
static int hf_scsi_osd_audit                            = -1;
static int hf_scsi_osd_capability_discriminator         = -1;
static int hf_scsi_osd_object_created_time              = -1;
static int hf_scsi_osd_object_type                      = -1;
static int hf_scsi_osd_permissions                      = -1;
static int hf_scsi_osd_permissions_read                 = -1;
static int hf_scsi_osd_permissions_write                = -1;
static int hf_scsi_osd_permissions_get_attr             = -1;
static int hf_scsi_osd_permissions_set_attr             = -1;
static int hf_scsi_osd_permissions_create               = -1;
static int hf_scsi_osd_permissions_remove               = -1;
static int hf_scsi_osd_permissions_obj_mgmt             = -1;
static int hf_scsi_osd_permissions_append               = -1;
static int hf_scsi_osd_permissions_dev_mgmt             = -1;
static int hf_scsi_osd_permissions_global               = -1;
static int hf_scsi_osd_permissions_pol_sec              = -1;
static int hf_scsi_osd_object_descriptor_type           = -1;
static int hf_scsi_osd_object_descriptor                = -1;
static int hf_scsi_osd_ricv                             = -1;
static int hf_scsi_osd_request_nonce                    = -1;
static int hf_scsi_osd_diicvo                           = -1;
static int hf_scsi_osd_doicvo                           = -1;
static int hf_scsi_osd_requested_partition_id           = -1;
static int hf_scsi_osd_sortorder                        = -1;
static int hf_scsi_osd_partition_id                     = -1;
static int hf_scsi_osd_list_identifier                  = -1;
static int hf_scsi_osd_allocation_length                = -1;
static int hf_scsi_osd_length                           = -1;
static int hf_scsi_osd_starting_byte_address            = -1;
static int hf_scsi_osd_initial_object_id                = -1;
static int hf_scsi_osd_additional_length                = -1;
static int hf_scsi_osd_continuation_object_id           = -1;
static int hf_scsi_osd_list_flags_lstchg                = -1;
static int hf_scsi_osd_list_flags_root                  = -1;
static int hf_scsi_osd_list_collection_flags_coltn      = -1;
static int hf_scsi_osd_user_object_id                   = -1;
static int hf_scsi_osd_requested_user_object_id         = -1;
static int hf_scsi_osd_number_of_user_objects           = -1;
static int hf_scsi_osd_key_to_set                       = -1;
static int hf_scsi_osd_set_key_version                  = -1;
static int hf_scsi_osd_key_identifier                   = -1;
static int hf_scsi_osd_seed                             = -1;
static int hf_scsi_osd_collection_fcr                   = -1;
static int hf_scsi_osd_collection_object_id             = -1;
static int hf_scsi_osd_requested_collection_object_id   = -1;
static int hf_scsi_osd_partition_created_in             = -1;
static int hf_scsi_osd_partition_removed_in             = -1;
static int hf_scsi_osd_flush_scope                      = -1;
static int hf_scsi_osd_flush_collection_scope           = -1;
static int hf_scsi_osd_flush_partition_scope            = -1;
static int hf_scsi_osd_flush_osd_scope                  = -1;
static int hf_scsi_osd_attributes_list_type             = -1;
static int hf_scsi_osd_attributes_list_length           = -1;
static int hf_scsi_osd_attributes_page                  = -1;
static int hf_scsi_osd_attribute_number                 = -1;
static int hf_scsi_osd_attribute_length                 = -1;
static int hf_scsi_osd_attrval_user_object_logical_length = -1;
static int hf_scsi_osd_attrval_object_type              = -1;
static int hf_scsi_osd_attrval_partition_id             = -1;
static int hf_scsi_osd_attrval_object_id                = -1;
static int hf_scsi_osd2_query_type = -1;
static int hf_scsi_osd2_query_entry_length = -1;
static int hf_scsi_osd2_query_attributes_page = -1;
static int hf_scsi_osd2_query_attribute_number = -1;
static int hf_scsi_osd2_query_minimum_attribute_value_length = -1;
static int hf_scsi_osd2_query_maximum_attribute_value_length = -1;

/* Fields that are defined in OSD-2 are prefixed with hf_scsi_osd2_ */
static int hf_scsi_osd2_attributes_list_length      = -1;
static int hf_scsi_osd2_set_attribute_value         = -1;
static int hf_scsi_osd2_isolation                   = -1;
static int hf_scsi_osd2_immed_tr                    = -1;
static int hf_scsi_osd2_list_attr                   = -1;
static int hf_scsi_osd2_object_descriptor_format    = -1;
static int hf_scsi_osd2_matches_collection_object_id = -1;
static int hf_scsi_osd2_source_collection_object_id = -1;
static int hf_scsi_osd2_cdb_continuation_length     = -1;
static int hf_scsi_osd2_cdb_continuation_format     = -1;
static int hf_scsi_osd2_continued_service_action    = -1;
static int hf_scsi_osd2_cdb_continuation_descriptor_type = -1;
static int hf_scsi_osd2_cdb_continuation_descriptor_pad_length = -1;
static int hf_scsi_osd2_cdb_continuation_descriptor_length = -1;
static int hf_scsi_osd2_remove_scope                       = -1;

static gint ett_osd_option                  = -1;
static gint ett_osd_partition               = -1;
static gint ett_osd_attribute_parameters    = -1;
static gint ett_osd_capability              = -1;
static gint ett_osd_permission_bitmask      = -1;
static gint ett_osd_security_parameters     = -1;
static gint ett_osd_get_attributes          = -1;
static gint ett_osd_set_attributes          = -1;
static gint ett_osd_multi_object            = -1;
static gint ett_osd_attribute               = -1;
static gint ett_osd2_query_criteria_entry   = -1;

static expert_field ei_osd_attr_unknown = EI_INIT;
static expert_field ei_osd2_invalid_offset = EI_INIT;
static expert_field ei_osd2_invalid_object_descriptor_format = EI_INIT;
static expert_field ei_osd_unknown_attributes_list_type = EI_INIT;
static expert_field ei_osd2_cdb_continuation_format_unknown = EI_INIT;
static expert_field ei_osd2_continued_service_action_mismatch = EI_INIT;
static expert_field ei_osd2_cdb_continuation_descriptor_type_unknown = EI_INIT;
static expert_field ei_osd2_cdb_continuation_descriptor_length_invalid = EI_INIT;
static expert_field ei_osd2_cdb_continuation_length_invalid = EI_INIT;
static expert_field ei_osd_attr_length_invalid = EI_INIT;
static expert_field ei_osd2_query_values_equal= EI_INIT;

#define PAGE_NUMBER_OBJECT          0x00000000
#define PAGE_NUMBER_PARTITION       0x30000000
#define PAGE_NUMBER_COLLECTION      0x60000000
#define PAGE_NUMBER_ROOT            0x90000000


/* There will be one such structure create for each conversation ontop of which
 * there is an OSD session
 */
typedef struct _scsi_osd_conv_info_t {
    wmem_tree_t *luns;
} scsi_osd_conv_info_t;

/* there will be one such structure created for each lun for each conversation
 * that is handled by the OSD dissector
 */
struct _scsi_osd_lun_info_t {
    wmem_tree_t *partitions;
};

typedef void (*scsi_osd_dissector_t)(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, guint offset,
        gboolean isreq, gboolean iscdb,
         guint32 payload_len, scsi_task_data_t *cdata,
        scsi_osd_conv_info_t *conv_info,
        scsi_osd_lun_info_t *lun_info
        );

/* One such structure is created per conversation/lun/partition to
 * keep track of when partitions are created/used/destroyed
 */
typedef struct _partition_info_t {
    int created_in;
    int removed_in;
} partition_info_t;


/* This is a set of extra data specific to OSD that we need to attach to every
 * task.
 */
typedef struct _scsi_osd_extra_data_t {
    guint16 svcaction;
    guint8  gsatype;
    union {
        struct {    /* gsatype: attribute list */
            guint32 get_list_length;
            guint32 get_list_offset;
            guint32 get_list_allocation_length;
            guint32 retrieved_list_offset;
            guint32 set_list_length;
            guint32 set_list_offset;
        } al;
    } u;
    guint32 continuation_length;
    gboolean osd2;
} scsi_osd_extra_data_t;

static proto_item*
dissect_osd_user_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* user object id */
    proto_item *item;
    item = proto_tree_add_item(tree, hf_scsi_osd_user_object_id, tvb, offset, 8, ENC_NA);
    return item;
}


/*dissects an attribute that is defined as a pair of hf_index, length*/
static void
generic_attribute_dissector(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree,
                            scsi_osd_lun_info_t *lun_info _U_, const attribute_page_numbers_t *att)
{
    proto_tree_add_item(tree, *att->hf_index, tvb, 0, att->expected_length, ENC_BIG_ENDIAN);
}

static proto_item *
dissect_osd_partition_id(packet_info *pinfo, tvbuff_t *tvb, int offset,
                         proto_tree *tree, int hf_index,
                         scsi_osd_lun_info_t *lun_info, gboolean is_created,
                         gboolean is_removed);

static void
partition_id_attribute_dissector(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                                 scsi_osd_lun_info_t *lun_info, const attribute_page_numbers_t *att)
{
    dissect_osd_partition_id(pinfo, tvb, 0, tree, *att->hf_index, lun_info, FALSE, FALSE);
}

static const attribute_page_numbers_t user_object_info_attributes[] = {
    {0x82, "User object logical length", generic_attribute_dissector, &hf_scsi_osd_attrval_user_object_logical_length, 8},
    {0, NULL, NULL, NULL, 0}
};

static const attribute_page_numbers_t current_command_attributes[] = {
    {0x02, "Object Type",                            generic_attribute_dissector,      &hf_scsi_osd_attrval_object_type, 1},
    {0x03, "Partition ID",                           partition_id_attribute_dissector, &hf_scsi_osd_attrval_partition_id, 8},
    {0x04, "Collection Object ID or User Object ID", generic_attribute_dissector,      &hf_scsi_osd_attrval_object_id, 8},
    {0, NULL, NULL, NULL, 0}
};

typedef struct _attribute_pages_t {
    guint32 page;
    const attribute_page_numbers_t *attributes;
} attribute_pages_t;

static const attribute_pages_t attribute_pages[] = {
    {PAGE_NUMBER_OBJECT+1, user_object_info_attributes},
    {0xFFFFFFFE,           current_command_attributes},
    {0, NULL}
};

static const value_string attributes_page_vals[] = {
    {PAGE_NUMBER_OBJECT+0,     "User Object Directory"},
    {PAGE_NUMBER_OBJECT+1,     "User Object Information"},
    {PAGE_NUMBER_OBJECT+2,     "User Object Quotas"},
    {PAGE_NUMBER_OBJECT+3,     "User Object Timestamps"},
    {PAGE_NUMBER_OBJECT+4,     "User Object Collections"},
    {PAGE_NUMBER_OBJECT+5,     "User Object Policy/Security"},
    {PAGE_NUMBER_PARTITION,    "Partition Directory"},
    {PAGE_NUMBER_PARTITION+1,  "Partition Information"},
    {PAGE_NUMBER_PARTITION+2,  "Partition Quotas"},
    {PAGE_NUMBER_PARTITION+3,  "Partition Timestamps"},
    {PAGE_NUMBER_PARTITION+5,  "Partition Policy/Security"},
    {PAGE_NUMBER_COLLECTION,   "Collection Directory"},
    {PAGE_NUMBER_COLLECTION+1, "Collection Information"},
    {PAGE_NUMBER_COLLECTION+2, "Collection Quotas"},
    {PAGE_NUMBER_COLLECTION+4, "Collection Command Tracking"},
    {PAGE_NUMBER_COLLECTION+5, "Collection Policy/Security"},
    {PAGE_NUMBER_ROOT,         "Root Directory"},
    {PAGE_NUMBER_ROOT+1,       "Root Information"},
    {PAGE_NUMBER_ROOT+2,       "Root Quotas"},
    {PAGE_NUMBER_ROOT+3,       "Root Timestamps"},
    {PAGE_NUMBER_ROOT+5,       "Root Policy/Security"},
    {0xFFFFFFFE,               "Current Command"},
    {0xFFFFFFFF,               "All attribute pages"},
    {0, NULL}
};
value_string_ext attributes_page_vals_ext = VALUE_STRING_EXT_INIT(attributes_page_vals);

static const value_string attributes_list_type_vals[] = {
    {0x01, "Retrieve attributes for this OSD object"},
    {0x09, "Retrieve/Set attributes for this OSD object"},
    {0x0f, "Retrieve attributes for a CREATE command"},
    {0, NULL}
};

static const value_string scsi_osd2_isolation_val[] = {
    {0x00, "Default"},
    {0x01, "None"},
    {0x02, "Strict"},
    {0x04, "Range"},
    {0x05, "Functional"},
    {0x07, "Vendor specific"},
    {0, NULL}
};

static const value_string scsi_osd2_object_descriptor_format_val[] = {
    {0x01, "Partition ID"},
    {0x02, "Partition ID followed by attribute parameters"},
    {0x11, "Collection ID"},
    {0x12, "Collection ID followed by attribute parameters"},
    {0x21, "User Object ID"},
    {0x22, "User Object ID followed by attribute parameters"},
    {0, NULL}
};

static const value_string scsi_osd2_remove_scope[] = {
    {0x00, "Fail if there are collections or user objects in the partition"},
    {0x01, "Remove collections and user objects in the partition"},
    {0, NULL}
};

static const value_string scsi_osd2_cdb_continuation_format_val[] = {
    {0x01, "OSD2"},
    {0, NULL}
};

static const value_string  scsi_osd2_cdb_continuation_descriptor_type_val[] = {
    {0x0000, "No more continuation descriptors"},
    {0x0001, "Scatter/gather list"},
    {0x0002, "Query list"},
    {0x0100, "User object"},
    {0x0101, "Copy user object source"},
    {0xFFEE, "Extension capabilities"},
    {0, NULL}
};

static const value_string scsi_osd2_query_type_vals[] = {
    {0x00, "Match any query criteria"},
    {0x01, "Match all query criteria"},
    {0, NULL}
};

/* OSD2/3 helper functions */

static void
dissect_osd2_isolation(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* isolation */
    proto_tree_add_item(tree, hf_scsi_osd2_isolation, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_osd2_list_attr(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* list_attr */
    proto_tree_add_item(tree, hf_scsi_osd2_list_attr, tvb, offset, 1, ENC_BIG_ENDIAN);
}


/* used by dissect_osd_attributes_list, dissect_osd2_attribute_list_entry
and dissect_scsi_descriptor_snsinfo from packet-scsi.c*/
const attribute_page_numbers_t *
osd_lookup_attribute(guint32 page, guint32 number)
{
    const attribute_pages_t        *ap;
    const attribute_page_numbers_t *apn;

    /* find the proper attributes page */
    apn = NULL;
    for (ap=attribute_pages;ap->attributes;ap++) {
        if (ap->page == page) {
            apn = ap->attributes;
            break;
        }
    }
    if (!apn) return NULL;

    /* find the specific attribute */
    for (;apn->name;apn++) {
        if (apn->number == number) {
            break;
        }
    }
    if (!apn->name) return NULL;

    /* found it */
    return apn;
}

/* OSD-1: 7.1.3.3, OSD2 7.1.4.3 list entry format */
static guint32
dissect_osd_attribute_list_entry(packet_info *pinfo, tvbuff_t *tvb,
                                 proto_tree *tree, proto_item *item,
                                 guint32 offset, scsi_osd_lun_info_t *lun_info,
                                 gboolean osd2)
{
    guint16 attribute_length;
    guint32 page, number;
    const attribute_page_numbers_t *apn;

    /* attributes page */
    page = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_scsi_osd_attributes_page, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* attribute number */
    number = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_scsi_osd_attribute_number, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    if (osd2) {
        /*6 reserved bytes*/
        offset += 6;
    }

    /* attribute length */
    attribute_length = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_scsi_osd_attribute_length, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    proto_item_append_text(item, " 0x%08x (%s)", page,  val_to_str_ext_const(page, &attributes_page_vals_ext, "Unknown"));
    proto_item_append_text(item, " 0x%08x", number);
    apn= osd_lookup_attribute(page, number);

    if (!apn) {
        expert_add_info(pinfo, item, &ei_osd_attr_unknown);
        proto_item_append_text(item, " (Unknown)");
    } else {
        proto_item_append_text(item, " (%s)", apn->name);

        /* attribute value */
        if (attribute_length) {
            if (attribute_length != apn->expected_length) {
                proto_tree_add_expert_format(tree, pinfo, &ei_osd_attr_length_invalid,
                                             tvb, 0, attribute_length, "%s", apn->name);
            } else {
                tvbuff_t *next_tvb = tvb_new_subset_length(tvb, offset, attribute_length);
                apn->dissector(next_tvb, pinfo, tree, lun_info, apn);
            }
        }
    }

    offset += attribute_length;
    if (osd2 && (attribute_length&7)) {
        /* 8-bit padding */
        offset += 8-(attribute_length&7);
    }

    return offset;
}

/* OSD1: 7.1.3.1
   OSD2: 7.1.4.1*/
static void
dissect_osd_attributes_list(packet_info *pinfo, tvbuff_t *tvb, int offset,
                            proto_tree *tree, scsi_osd_lun_info_t *lun_info,
                            gboolean osd2)
{
    guint8      type;
    guint32     length;
    guint32     page, number;
    int         start_offset = offset;
    proto_item *item, *list_type_item;
    const attribute_page_numbers_t *apn;

    /* list type */
    type = tvb_get_guint8(tvb, offset)&0x0f;
    list_type_item = proto_tree_add_item(tree, hf_scsi_osd_attributes_list_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* OSD-1: a reserved byte */
    /* OSD-2: 3 reserved bytes */
    offset += (osd2?3:1);

    /* OSD-1: length (16 bit)
       OSD-2: length (32 bit) */
    if (osd2) {
        length = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_osd2_attributes_list_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
    } else {
        length = tvb_get_ntohs(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_osd_attributes_list_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;
    }

    /* if type is 1 length will be zero and we have to cycle over
     * all remaining bytes.   7.1.3.1
     */
    if (!osd2 && type == 1) {
        length = tvb_length_remaining(tvb, offset);
    }

    length += (osd2?8:4);

    while ( (guint32)(offset-start_offset)<length ) {
        proto_item *ti;
        proto_tree *tt;
        guint32     attribute_entry_length;

        switch (type) {
            case 0x01:
                attribute_entry_length = 8;
                break;
            case 0x0f:
                attribute_entry_length = 18+tvb_get_ntohs(tvb, offset+16);
                break;
            case 0x09:
                if (osd2) {
                    attribute_entry_length = 16+tvb_get_ntohs(tvb, offset+14);
                } else {
                    attribute_entry_length = 10+tvb_get_ntohs(tvb, offset+8);
                }
                break;
            default:
                expert_add_info(pinfo, list_type_item, &ei_osd_unknown_attributes_list_type);
                return;
        }

        if ((guint32)(offset-start_offset)+attribute_entry_length>length) break;
        ti = proto_tree_add_text(tree, tvb, offset, attribute_entry_length, "Attribute:");
        tt = proto_item_add_subtree(ti, ett_osd_attribute);

        switch (type) {
        case 0x01: /* retrieving attributes 7.1.3.2 */
            /* attributes page */
            page = tvb_get_ntohl(tvb, offset);
            proto_tree_add_item(tt, hf_scsi_osd_attributes_page, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            /* attribute number */
            number = tvb_get_ntohl(tvb, offset);
            item = proto_tree_add_item(tt, hf_scsi_osd_attribute_number, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            proto_item_append_text(ti, " 0x%08x (%s)", page,  val_to_str_ext_const(page, &attributes_page_vals_ext, "Unknown"));
            proto_item_append_text(ti, " 0x%08x", number);

            /* find the proper attributes page */
            apn = osd_lookup_attribute(page, number);
            if (!apn) {
                proto_item_append_text(ti, " (Unknown)");
                proto_item_append_text(item, " (Unknown)");
            } else {
                proto_item_append_text(ti, " (%s)", apn->name);
                proto_item_append_text(item, " (%s)", apn->name);
            }
            break;
        case 0x0f: /* create attributes 7.1.3.4 */
            /* user object id */
            dissect_osd_user_object_id(tvb, offset, tt);
            offset += 8;
            /* fallthrough to the next case */
        case 0x09: /* retrieved/set attributes OSD-1: 7.1.3.3  OSD-2: 7.1.4.3*/
            offset = dissect_osd_attribute_list_entry(pinfo, tvb, tt, ti, offset, lun_info, osd2);
            break;
        }
    }
}


/* OSD2 5.2.4 */
static void
dissect_osd_option(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree = NULL;
    proto_item *it   = NULL;
    guint8      option;

    option = tvb_get_guint8(tvb, offset);

    if (parent_tree) {
        it = proto_tree_add_item(parent_tree, hf_scsi_osd_option, tvb, offset, 1, ENC_BIG_ENDIAN);
        tree = proto_item_add_subtree(it, ett_osd_option);
    }

    proto_tree_add_item(tree, hf_scsi_osd_option_dpo, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (option&0x10) {
        proto_item_append_text(tree, " DPO");
    }

    proto_tree_add_item(tree, hf_scsi_osd_option_fua, tvb, offset, 1, ENC_BIG_ENDIAN);
    if (option&0x08) {
        proto_item_append_text(tree, " FUA");
    }
}


static const value_string scsi_osd_getsetattrib_vals[] = {
    {1, "Set one attribute using CDB fields (OSD-2)"},
    {2, "Get an attributes page and set an attribute value"},
    {3, "Get and set attributes using a list"},
    {0, NULL},
};

/* OSD2 5.2.2.1 */
static void
dissect_osd_getsetattrib(tvbuff_t *tvb, int offset, proto_tree *tree, scsi_task_data_t *cdata)
{
    if (cdata && cdata->itlq && cdata->itlq->extra_data) {
        scsi_osd_extra_data_t *extra_data = (scsi_osd_extra_data_t *)cdata->itlq->extra_data;
        extra_data->gsatype = (tvb_get_guint8(tvb, offset)>>4)&0x03;
    }
    proto_tree_add_item(tree, hf_scsi_osd_getsetattrib, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static const value_string scsi_osd_timestamps_control_vals[] = {
    {0x00, "Timestamps shall be updated"},
    {0x7f, "Timestamps shall not be updated"},
    {0, NULL},
};

/* OSD2 5.2.8 */
static void
dissect_osd_timestamps_control(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_osd_timestamps_control, tvb, offset, 1, ENC_BIG_ENDIAN);
}


static void
dissect_osd_formatted_capacity(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_osd_formatted_capacity, tvb, offset, 8, ENC_BIG_ENDIAN);
}

static void
dissect_osd_offset(packet_info *pinfo, tvbuff_t *tvb, int offset,
                   proto_tree *tree, int field, guint32 *raw_value_ptr,
                   gboolean osd2)
{
    /* dissects an OSD offset value, add proto item and updates *raw_value_ptr */
    guint32 value = *raw_value_ptr;

    if (value != 0xFFFFFFFF) {
        if (!osd2) {
            /*OSD-1: the exponent is an unsigned value (4.12.5)*/
            value = (value & 0x0fffffff) << ((value>>28) & 0x0f);
            value <<= 8;
        } else {
            /*OSD-2: the exponent is a signed value (4.15.5)*/
            int  exponent = (value>>28);
            guint32 mantissa = (value&0x0FFFFFFF);

            if (exponent&0x8) {
                exponent = -(((~exponent)&7)+1);
                if (exponent <=- 6 && mantissa != 0xFFFFFFF) {
                    proto_item *item;
                    item = proto_tree_add_item(tree, field, tvb, offset, 4, value);
                    expert_add_info(pinfo, item, &ei_osd2_invalid_offset);
                    *raw_value_ptr = 0xFFFFFFFF;
                    return;
                }
            }
            value = mantissa << (exponent+8);
        }
    }
    proto_tree_add_uint(tree, field, tvb, offset, 4, value);
    *raw_value_ptr = value;
}

static int
dissect_osd_attribute_parameters(packet_info *pinfo, tvbuff_t *tvb, int offset, proto_tree *parent_tree, scsi_task_data_t *cdata)
{
    guint8      gsatype = 0;
    proto_item *item    = NULL;
    proto_tree *tree    = NULL;
    scsi_osd_extra_data_t *extra_data = NULL;
    gboolean osd2;

    if (parent_tree) {
        item = proto_tree_add_text(parent_tree, tvb, offset, 28,
            "Attribute Parameters");
        tree = proto_item_add_subtree(item, ett_osd_attribute_parameters);
    }

    if (cdata && cdata->itlq && cdata->itlq->extra_data) {
        extra_data = (scsi_osd_extra_data_t *)cdata->itlq->extra_data;
        gsatype = extra_data->gsatype;
        osd2 = extra_data->osd2;
    } else {
        return offset;
    }

    switch (gsatype) {
    case 1: /* OSD-2 5.2.6.2 Set one attribute using CDB fields*/
    if (osd2) {
        proto_tree_add_item(tree, hf_scsi_osd_set_attributes_page, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd_set_attribute_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd_set_attribute_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd2_set_attribute_value, tvb, offset, 18, ENC_NA);
        offset += 18;
    }
    break;
    case 2: /* 5.2.2.2  attribute page */
        proto_tree_add_item(tree, hf_scsi_osd_get_attributes_page, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd_get_attributes_allocation_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd_retrieved_attributes_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd_set_attributes_page, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd_set_attribute_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd_set_attribute_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        proto_tree_add_item(tree, hf_scsi_osd_set_attributes_offset, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        break;
    case 3: /* 5.2.2.3  attribute list */
        proto_tree_add_item(tree, hf_scsi_osd_get_attributes_list_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        extra_data->u.al.get_list_length = tvb_get_ntohl(tvb, offset);
        offset += 4;

        /* 4.12.5 */
        extra_data->u.al.get_list_offset = tvb_get_ntohl(tvb, offset);
        dissect_osd_offset(pinfo, tvb, offset, tree, hf_scsi_osd_get_attributes_list_offset,
                           &extra_data->u.al.get_list_offset, osd2);
        if (extra_data->u.al.get_list_offset == 0xFFFFFFFF) {
            extra_data->u.al.get_list_length = 0;
        }
        offset += 4;

        proto_tree_add_item(tree, hf_scsi_osd_get_attributes_allocation_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        extra_data->u.al.get_list_allocation_length = tvb_get_ntohl(tvb, offset);
        offset += 4;

        /* 4.12.5 */
        extra_data->u.al.retrieved_list_offset = tvb_get_ntohl(tvb, offset);
        dissect_osd_offset(pinfo, tvb, offset, tree, hf_scsi_osd_retrieved_attributes_offset,
                           &extra_data->u.al.retrieved_list_offset, osd2);
        if (extra_data->u.al.retrieved_list_offset == 0xFFFFFFFF) {
            extra_data->u.al.get_list_allocation_length = 0;
        }
        offset += 4;

        proto_tree_add_item(tree, hf_scsi_osd_set_attributes_list_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        extra_data->u.al.set_list_length = tvb_get_ntohl(tvb, offset);
        offset += 4;

        extra_data->u.al.set_list_offset = tvb_get_ntohl(tvb, offset);
        dissect_osd_offset(pinfo, tvb, offset, tree, hf_scsi_osd_set_attributes_list_offset,
                           &extra_data->u.al.set_list_offset, osd2);
        if (extra_data->u.al.set_list_offset == 0xFFFFFFFF) {
            extra_data->u.al.set_list_length = 0;
        }
        offset += 4;

        /* 4 reserved bytes */
        offset += 4;

        break;
    }
    return offset;
}


static void
dissect_osd_attribute_data_out(packet_info *pinfo, tvbuff_t *tvb, int offset _U_,
                               proto_tree *tree, scsi_task_data_t *cdata,
                               scsi_osd_lun_info_t *lun_info)
{
    guint8      gsatype = 0;
    proto_tree *subtree;
    proto_item *item;
    scsi_osd_extra_data_t *extra_data = NULL;

    if (cdata && cdata->itlq && cdata->itlq->extra_data) {
        extra_data = (scsi_osd_extra_data_t *)cdata->itlq->extra_data;
        gsatype = extra_data->gsatype;
    } else {
        return;
    }

    switch (gsatype) {
    case 2: /* 5.2.2.2  attribute page */
/*qqq*/
        break;
    case 3: /* 5.2.2.3  attribute list */
        if (extra_data->u.al.get_list_length) {
            item = proto_tree_add_text(tree, tvb, extra_data->u.al.get_list_offset, extra_data->u.al.get_list_length, "Get Attributes Segment");
            subtree= proto_item_add_subtree(item, ett_osd_get_attributes);
            dissect_osd_attributes_list(pinfo, tvb, extra_data->u.al.get_list_offset, subtree, lun_info, extra_data->osd2);
        }
        if (extra_data->u.al.set_list_length) {
            item = proto_tree_add_text(tree, tvb, extra_data->u.al.set_list_offset, extra_data->u.al.set_list_length, "Set Attributes Segment");
            subtree= proto_item_add_subtree(item, ett_osd_set_attributes);
            dissect_osd_attributes_list(pinfo, tvb, extra_data->u.al.set_list_offset, subtree, lun_info, extra_data->osd2);
        }
        break;
    }
}


static void
dissect_osd_attribute_data_in(packet_info *pinfo, tvbuff_t *tvb, int offset _U_, proto_tree *tree, scsi_task_data_t *cdata, scsi_osd_lun_info_t *lun_info)
{
    guint8 gsatype = 0;
    scsi_osd_extra_data_t *extra_data = NULL;

    if (cdata && cdata->itlq && cdata->itlq->extra_data) {
        extra_data = (scsi_osd_extra_data_t *)cdata->itlq->extra_data;
        gsatype = extra_data->gsatype;
    } else {
        return;
    }

    switch (gsatype) {
    case 2: /* 5.2.2.2  attribute page */
/*qqq*/
        break;
    case 3: /* 5.2.2.3  attribute list */
        if (extra_data->u.al.get_list_allocation_length) {
            dissect_osd_attributes_list(pinfo, tvb, extra_data->u.al.retrieved_list_offset, tree, lun_info, extra_data->osd2);
        }
        break;
    }
}

static void
dissect_osd2_cdb_continuation_length(packet_info *pinfo, tvbuff_t *tvb,
                                     guint32 offset, proto_tree *tree,
                                     scsi_task_data_t *cdata)
{
    scsi_osd_extra_data_t *extra_data;
    guint32     continuation_length;
    proto_item *item;

    continuation_length = tvb_get_ntohl(tvb, offset);
    item = proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_length, tvb, offset, 4, ENC_BIG_ENDIAN);
    if (cdata && cdata->itlq && cdata->itlq->extra_data) {
        extra_data = (scsi_osd_extra_data_t *)cdata->itlq->extra_data;
        extra_data->continuation_length = continuation_length;
    }
    if (continuation_length>0 && continuation_length<40) {
        expert_add_info(pinfo, item, &ei_osd2_cdb_continuation_length_invalid);
    }
}

static void dissect_osd2_query_list_descriptor(packet_info *pinfo, tvbuff_t *tvb, guint32 offset, proto_tree *tree, guint32 length) {
    guint32 end = offset+length;

    /* query type */
    proto_tree_add_item(tree, hf_scsi_osd2_query_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* 3 reserved bytes */
    offset += 3;

    /*query criteria entry*/
    while (offset<end) {
        guint32     page, number;
        guint32     min_value_length, max_value_length;
        guint32     min_value_offset, max_value_offset;
        proto_item *item;
        const attribute_page_numbers_t *apn;

        /* 2 reserved bytes */
        offset += 2;

        /* query entry length */
        proto_tree_add_item(tree, hf_scsi_osd2_query_entry_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;

        /* query attributes page */
        page = tvb_get_ntohl(tvb, offset);
        proto_tree_add_item(tree, hf_scsi_osd2_query_attributes_page, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        /* query attributes number */
        number = tvb_get_ntohl(tvb, offset);
        item = proto_tree_add_item(tree, hf_scsi_osd2_query_attribute_number, tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;

        apn = osd_lookup_attribute(page, number);

        if (!apn) {
            expert_add_info(pinfo, item, &ei_osd_attr_unknown);
            proto_item_append_text(item, " (Unknown)");
        } else {
            proto_item_append_text(item, " (%s)", apn->name);
        }

        /* query minimum attribute value length */
        proto_tree_add_item(tree, hf_scsi_osd2_query_minimum_attribute_value_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        min_value_length = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* query minimum attribute value */
        /* if (apn && min_value_length) {
            call_apn_dissector(tvb, pinfo, tree, lun_info, apn, offset, min_value_length);
        } */
        max_value_offset = offset;
        offset += min_value_length;

        /* query maximum attribute value length */
        item = proto_tree_add_item(tree, hf_scsi_osd2_query_maximum_attribute_value_length, tvb, offset, 2, ENC_BIG_ENDIAN);
        max_value_length = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* xxx query maximum attribute value */
        /* if (apn && max_value_length) {
            call_apn_dissector(tvb, pinfo, tree, lun_info, apn, offset, max_value_length);
        } */
        min_value_offset = offset;
        offset += max_value_length;

        /* test if min and max values are equal */
        if (max_value_length == min_value_length) {
            unsigned int i;
            for (i=0; i<max_value_length; i++) {
                if (tvb_get_guint8(tvb, max_value_offset+i) != tvb_get_guint8(tvb, min_value_offset+i)) return;
            }
            expert_add_info(pinfo, item, &ei_osd2_query_values_equal);
        }
    }
}

static void
dissect_osd2_cdb_continuation(packet_info *pinfo, tvbuff_t *tvb, guint32 offset,
                              proto_tree *tree, scsi_task_data_t *cdata)
{
    scsi_osd_extra_data_t *extra_data = NULL;
    proto_item            *item;
    guint8                 format;
    guint16                sa;
    if (cdata && cdata->itlq && cdata->itlq->extra_data) {
        extra_data = (scsi_osd_extra_data_t *)cdata->itlq->extra_data;
    }
    if (!extra_data || extra_data->continuation_length<40) return;

    /* cdb continuation format */
    item = proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_format, tvb, offset, 1, ENC_BIG_ENDIAN);
    format = tvb_get_guint8(tvb, offset);
    if (format != 0x01) {
        expert_add_info(pinfo, item, &ei_osd2_cdb_continuation_format_unknown);
        return;
    }
    offset += 1;

    /* 1 reserved byte */
    offset += 1;

    /* continued service action */
    item = proto_tree_add_item(tree, hf_scsi_osd2_continued_service_action, tvb, offset, 2, ENC_BIG_ENDIAN);
    sa = tvb_get_ntohs(tvb, offset);
    if (sa != extra_data->svcaction) {
        expert_add_info(pinfo, item, &ei_osd2_continued_service_action_mismatch);
    }
    offset += 2;

    /*4 reserved bytes and continuation integrity check value (32 bytes, not dissected)*/
    offset += 36;


    /* CDB continuation descriptors */
    while (offset<extra_data->continuation_length) {
        guint16 type;
        guint32 length, padlen;
        proto_item *item_type, *item_length;

        /* descriptor type */
        item_type= proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_descriptor_type, tvb, offset, 2, ENC_BIG_ENDIAN);
        type = tvb_get_ntohs(tvb, offset);
        offset += 2;

        /* 1 reserved byte*/
        offset += 1;

        /* descriptor pad length */
        proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_descriptor_pad_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        padlen = tvb_get_guint8(tvb, offset)&7;
        offset += 1;

        /* descriptor length */
        item_length = proto_tree_add_item(tree, hf_scsi_osd2_cdb_continuation_descriptor_length, tvb, offset, 4, ENC_BIG_ENDIAN);
        length = tvb_get_ntohl(tvb, offset);
        offset += 4;

        switch (type) {
            case 0x0000: break;
            case 0x0001: break;
            case 0x0002: dissect_osd2_query_list_descriptor(pinfo, tvb, offset, tree, length);
            case 0x0100: break;
            case 0x0101: break;
            case 0xFFEE: break;
            default: expert_add_info(pinfo, item_type, &ei_osd2_cdb_continuation_descriptor_type_unknown);
        }

        if ((length+padlen)%8) {
            expert_add_info(pinfo, item_length, &ei_osd2_cdb_continuation_descriptor_length_invalid);
            return;
        }
        offset += length+padlen;
    }

}


static const value_string scsi_osd_capability_format_vals[] = {
    {0x00, "No Capability"},
    {0x01, "SCSI OSD Capabilities"},
    {0, NULL},
};
static const value_string scsi_osd_object_type_vals[] = {
    {0x01, "ROOT"},
    {0x02, "PARTITION"},
    {0x40, "COLLECTION"},
    {0x80, "USER"},
    {0, NULL},
};
static const value_string scsi_osd_object_descriptor_type_vals[] = {
    {0, "NONE: the object descriptor field shall be ignored"},
    {1, "U/C: a single collection or user object"},
    {2, "PAR: a single partition, including partition zero"},
    {0, NULL},
};


/* OSD 4.9.2.2.1 */
static void
dissect_osd_permissions(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_tree *tree = NULL;
    proto_item *it   = NULL;
    guint16     permissions;

    permissions = tvb_get_ntohs(tvb, offset);

    if (parent_tree) {
        it = proto_tree_add_item(parent_tree, hf_scsi_osd_permissions, tvb, offset, 2, ENC_BIG_ENDIAN);
        tree = proto_item_add_subtree(it, ett_osd_permission_bitmask);
    }

    proto_tree_add_item(tree, hf_scsi_osd_permissions_read, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x8000) {
        proto_item_append_text(tree, " READ");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_write, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x4000) {
        proto_item_append_text(tree, " WRITE");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_get_attr, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x2000) {
        proto_item_append_text(tree, " GET_ATTR");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_set_attr, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x1000) {
        proto_item_append_text(tree, " SET_ATTR");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_create, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x0800) {
        proto_item_append_text(tree, " CREATE");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_remove, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x0400) {
        proto_item_append_text(tree, " REMOVE");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_obj_mgmt, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x0200) {
        proto_item_append_text(tree, " OBJ_MGMT");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_append, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x0100) {
        proto_item_append_text(tree, " APPEND");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_dev_mgmt, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x0080) {
        proto_item_append_text(tree, " DEV_MGMT");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_global, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x0040) {
        proto_item_append_text(tree, " GLOBAL");
    }
    proto_tree_add_item(tree, hf_scsi_osd_permissions_pol_sec, tvb, offset, 2, ENC_BIG_ENDIAN);
    if (permissions&0x0020) {
        proto_item_append_text(tree, " POL/SEC");
    }
}

/* OSD-1 4.9.2.2
   OSD-2 4.11.2.2 */
static void
dissect_osd_capability(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;
    guint8 format;

    if (parent_tree) {
        item = proto_tree_add_text(parent_tree, tvb, offset, 80,
            "Capability");
        tree = proto_item_add_subtree(item, ett_osd_capability);
    }

    /* capability format */
    proto_tree_add_item(tree, hf_scsi_osd_capability_format, tvb, offset, 1, ENC_BIG_ENDIAN);
    format = tvb_get_guint8(tvb, offset)&0x0F;
    offset += 1;

    if (format != 1) return;

    /* key version and icva */
    proto_tree_add_item(tree, hf_scsi_osd_key_version, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_scsi_osd_icva, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* security method */
    proto_tree_add_item(tree, hf_scsi_osd_security_method, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* a reserved byte */
    offset += 1;

    /* capability expiration time */
    proto_tree_add_item(tree, hf_scsi_osd_capability_expiration_time, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* audit */
    proto_tree_add_item(tree, hf_scsi_osd_audit, tvb, offset, 20, ENC_NA);
    offset += 20;

    /* capability discriminator */
    proto_tree_add_item(tree, hf_scsi_osd_capability_discriminator, tvb, offset, 12, ENC_NA);
    offset += 12;

    /* object created time */
    proto_tree_add_item(tree, hf_scsi_osd_object_created_time, tvb, offset, 6, ENC_NA);
    offset += 6;

    /* object type */
    proto_tree_add_item(tree, hf_scsi_osd_object_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* permission bitmask */
    dissect_osd_permissions(tvb, offset, tree);
    offset += 5;

    /* a reserved byte */
    offset += 1;

    /* object descriptor type */
    proto_tree_add_item(tree, hf_scsi_osd_object_descriptor_type, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    /* object descriptor */
    proto_tree_add_item(tree, hf_scsi_osd_object_descriptor, tvb, offset, 24, ENC_NA);
    /*offset += 24;*/

    return;
}



/* 5.2.6 */
static int
dissect_osd_security_parameters(tvbuff_t *tvb, int offset, proto_tree *parent_tree)
{
    proto_item *item = NULL;
    proto_tree *tree = NULL;

    if (parent_tree) {
        item = proto_tree_add_text(parent_tree, tvb, offset, 40,
            "Security Parameters");
        tree = proto_item_add_subtree(item, ett_osd_security_parameters);
    }

    /* request integrity check value */
    proto_tree_add_item(tree, hf_scsi_osd_ricv, tvb, offset, 20, ENC_NA);
    offset += 20;

    /* request nonce */
    proto_tree_add_item(tree, hf_scsi_osd_request_nonce, tvb, offset, 12, ENC_NA);
    offset += 12;

    /* data in integrity check value offset */
    proto_tree_add_item(tree, hf_scsi_osd_diicvo, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* data out integrity check value offset */
    proto_tree_add_item(tree, hf_scsi_osd_doicvo, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static void
dissect_osd_format_osd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       guint offset, gboolean isreq, gboolean iscdb,
                       guint payload_len _U_, scsi_task_data_t *cdata _U_,
                       scsi_osd_conv_info_t *conv_info _U_,
                       scsi_osd_lun_info_t *lun_info _U_)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 23 reserved bytes */
        offset += 23;

        /* formatted capacity */
        dissect_osd_formatted_capacity(tvb, offset, tree);
        offset += 8;

        /* 8 reserved bytes */
        offset += 8;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for format osd */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for format osd */
    }

}


static proto_item*
dissect_osd_partition_id(packet_info *pinfo, tvbuff_t *tvb, int offset,
                         proto_tree *tree, int hf_index,
                         scsi_osd_lun_info_t *lun_info, gboolean is_created,
                         gboolean is_removed)
{
    proto_item *item = NULL;
    guint32     partition_id[2];

    /* partition id */
    item = proto_tree_add_item(tree, hf_index, tvb, offset, 8, ENC_BIG_ENDIAN);
    partition_id[0] = tvb_get_ntohl(tvb, offset);
    partition_id[1] = tvb_get_ntohl(tvb, offset+4);
    if (!partition_id[0] && !partition_id[1]) {
        proto_item_append_text(item, " (ROOT partition)");
    } else {
        partition_info_t *part_info;
        wmem_tree_key_t pikey[2];
        proto_tree *partition_tree = NULL;

        pikey[0].length = 2;
        pikey[0].key = partition_id;
        pikey[1].length = 0;
        part_info = (partition_info_t *)wmem_tree_lookup32_array(lun_info->partitions, &pikey[0]);
        if (!part_info) {
            part_info = wmem_new(wmem_file_scope(), partition_info_t);
            part_info->created_in = 0;
            part_info->removed_in = 0;

            pikey[0].length = 2;
            pikey[0].key = partition_id;
            pikey[1].length = 0;
            wmem_tree_insert32_array(lun_info->partitions, &pikey[0], part_info);
        }
        if (is_created) {
            part_info->created_in = pinfo->fd->num;
        }
        if (is_removed) {
            part_info->removed_in = pinfo->fd->num;
        }
        if (item) {
            partition_tree = proto_item_add_subtree(item, ett_osd_partition);
        }
        if (part_info->created_in) {
            proto_item *tmp_item;
            tmp_item = proto_tree_add_uint(partition_tree, hf_scsi_osd_partition_created_in, tvb, 0, 0, part_info->created_in);
            PROTO_ITEM_SET_GENERATED(tmp_item);
        }
        if (part_info->removed_in) {
            proto_item *tmp_item;
            tmp_item = proto_tree_add_uint(partition_tree, hf_scsi_osd_partition_removed_in, tvb, 0, 0, part_info->removed_in);
            PROTO_ITEM_SET_GENERATED(tmp_item);
        }
    }

    return item;
}



static void
dissect_osd_create_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             guint offset, gboolean isreq, gboolean iscdb,
                             guint payload_len _U_, scsi_task_data_t *cdata _U_,
                             scsi_osd_conv_info_t *conv_info _U_,
                             scsi_osd_lun_info_t *lun_info)
{
    gboolean osd2 = ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->svcaction&0x80;
    ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->osd2 = osd2;

    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        if (osd2) dissect_osd2_isolation(tvb, offset, tree);
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* requested partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_requested_partition_id, lun_info, TRUE, FALSE);
        offset += 8;

        /* 24 reserved bytes */
        offset += 24;

        if (osd2) {
            dissect_osd2_cdb_continuation_length(pinfo, tvb, offset, tree, cdata);
        } else {
            /* 4 reserved bytes */
        }
        offset += 4;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += osd2?104:80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += osd2?52:40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* CDB continuation */
        dissect_osd2_cdb_continuation(pinfo, tvb, offset, tree, cdata);

        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for create partition */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for create partition */
    }

}

static const value_string scsi_osd_sort_order_vals[] = {
    {0x00, "Ascending numeric value"},
    {0, NULL},
};
static int
dissect_osd_sortorder(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* sort order */
    proto_tree_add_item(tree, hf_scsi_osd_sortorder, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static int
dissect_osd_list_identifier(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* list identifier */
    proto_tree_add_item(tree, hf_scsi_osd_list_identifier, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;
}

static void
dissect_osd_allocation_length(tvbuff_t *tvb, int offset, proto_tree *tree, scsi_task_data_t *cdata)
{
    /* allocation length */
    proto_tree_add_item(tree, hf_scsi_osd_allocation_length, tvb, offset, 8, ENC_BIG_ENDIAN);

    if (cdata) {
        guint64 alloc_len = tvb_get_ntoh64(tvb, offset);
        if (alloc_len>G_GINT64_CONSTANT(0xFFFFFFFF)) {
            alloc_len = G_GINT64_CONSTANT(0xFFFFFFFF);
        }
        cdata->itlq->alloc_len = (guint32)alloc_len;
    }
}

static int
dissect_osd_initial_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* initial object id */
    proto_tree_add_item(tree, hf_scsi_osd_initial_object_id, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int
dissect_osd_additional_length(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* additional length */
    proto_tree_add_item(tree, hf_scsi_osd_additional_length, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}


static int
dissect_osd_continuation_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* continuation object id */
    proto_tree_add_item(tree, hf_scsi_osd_continuation_object_id, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static const true_false_string list_lstchg_tfs = {
    "List has CHANGED since the first List command",
    "List has NOT changed since first command"
};
static const true_false_string list_root_tfs = {
    "Objects are from root and are PARTITION IDs",
    "Objects are from the partition and are USER OBJECTs"
};
static const true_false_string list_coltn_tfs = {
    "Objects are from the partition and are COLLECTION IDs",
    "Objects are from the collection and are USER OBJECTs"
};

static proto_item*
dissect_osd_collection_object_id(tvbuff_t *tvb, int offset, proto_tree *tree, const int hfindex)
{
    /* collection object id */
    proto_item *item;
    item = proto_tree_add_item(tree, hfindex, tvb, offset, 8, ENC_NA);
    return item;
}

static void
dissect_osd_list(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 guint offset, gboolean isreq, gboolean iscdb,
                 guint payload_len _U_, scsi_task_data_t *cdata _U_,
                 scsi_osd_conv_info_t *conv_info _U_,
                 scsi_osd_lun_info_t *lun_info)
{
    guint    svcaction       = ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->svcaction;
    gboolean list_collection = (svcaction == 0x8817) || (svcaction == 0x8897);
    gboolean osd2            = svcaction&0x80;
    ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->osd2 = osd2;

    /* dissecting the CDB   dissection starts at byte 10 of the CDB */

    if (isreq && iscdb) {
        /*byte 10*/
        if (osd2) dissect_osd2_isolation(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte / sort order */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        if (!list_collection) dissect_osd_sortorder(tvb, offset, tree);
        if (osd2) dissect_osd2_list_attr(tvb, offset, tree);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        if (list_collection) {
            /* collection id */
             dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd_collection_object_id);
        } else {
           /* 8 reserved bytes */
        }
        offset += 8;

        if (osd2) {
            /* allocation length */
            dissect_osd_allocation_length(tvb, offset, tree, cdata);
            offset += 8;

            /* initial object id */
            dissect_osd_initial_object_id(tvb, offset, tree);
            offset += 8;

            /* list identifier */
            dissect_osd_list_identifier(tvb, offset, tree);
            offset += 4;
        } else {
            /* list identifier */
            dissect_osd_list_identifier(tvb, offset, tree);
            offset += 4;

            /* allocation length */
            dissect_osd_allocation_length(tvb, offset, tree, cdata);
            offset += 8;

            /* initial object id */
            dissect_osd_initial_object_id(tvb, offset, tree);
            offset += 8;
        }


        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += osd2?104:80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += osd2?52:40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for LIST or LIST COLLECTION */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {

        guint64  additional_length;
        guint64  allocation_length;
        guint64  remaining_length;
        gboolean is_root_or_coltn;
        guint8   format = 0;

        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        allocation_length = cdata->itlq->alloc_len;
        remaining_length = tvb_length_remaining(tvb, offset);
        if (remaining_length<allocation_length) allocation_length = remaining_length;
        if (allocation_length<24) return;

        /* dissection of the LIST or LIST COLLECTION DATA-IN */
        /* additional length */
        additional_length = tvb_get_ntoh64(tvb, offset);
        if (allocation_length<additional_length) additional_length = allocation_length;

        dissect_osd_additional_length(tvb, offset, tree);

        offset += 8;
        /* continuation object id */
        dissect_osd_continuation_object_id(tvb, offset, tree);
        offset += 8;
        /* list identifier */
        dissect_osd_list_identifier(tvb, offset, tree);
        offset += 4;
        /* 3 reserved bytes */
        offset += 3;

        /* OSD:  LSTCHG and ROOT flags
           OSD2: LSTCHG and OBJECT DESCRIPTOR FORMAT*/
        proto_tree_add_item(tree, hf_scsi_osd_list_flags_lstchg, tvb, offset, 1, ENC_BIG_ENDIAN);
        if (osd2) {
            proto_item *item;
            item = proto_tree_add_item(tree, hf_scsi_osd2_object_descriptor_format, tvb, offset, 1, ENC_BIG_ENDIAN);
            format = tvb_get_guint8(tvb, offset)>>2;
            if (format == 0x01 || format == 0x02) {
                is_root_or_coltn = TRUE;
                if (list_collection) format = 0;
            } else if (format == 0x11 || format == 0x12) {
                is_root_or_coltn = TRUE;
                if (!list_collection) format = 0;
            } else if (format == 0x21 || format == 0x22) {
                is_root_or_coltn = FALSE;
            } else format = 0;
            if (!format) {
                expert_add_info(pinfo, item, &ei_osd2_invalid_object_descriptor_format);
                return;
            }
        } else {
            if (list_collection) {
                proto_tree_add_item(tree, hf_scsi_osd_list_collection_flags_coltn, tvb, offset, 1, ENC_BIG_ENDIAN);
            } else {
                proto_tree_add_item(tree, hf_scsi_osd_list_flags_root, tvb, offset, 1, ENC_BIG_ENDIAN);
            }
            is_root_or_coltn = tvb_get_guint8(tvb, offset)&0x01;
        }

        offset += 1;

        while (additional_length > (offset-8)) {
            proto_item *ti;
            /* list of 8-byte IDs; the type of ID is given by is_root_or_coltn and list_collection*/
            if (is_root_or_coltn) {
                if (list_collection) {
                    ti = dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd_collection_object_id);
                } else {
                    ti = dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
                }
            } else {
                ti = dissect_osd_user_object_id(tvb, offset, tree);
            }
            offset += 8;

            /* for OSD-2 if format is 0x02, 0x12 or 0x22: sub-list of attributes*/
            if (osd2 && (format&0x02)) {
                guint32 attr_list_end;
                proto_tree *subtree;

                if (offset+8>additional_length) break;
                subtree = proto_item_add_subtree(ti, ett_osd_multi_object);

                /*object type*/
                proto_tree_add_item(subtree, hf_scsi_osd_object_type, tvb, offset, 1, ENC_BIG_ENDIAN);
                offset += 1;
                /* 5 reserved bytes */
                offset += 5;
                /* attribute list length*/
                attr_list_end = offset+2+tvb_get_ntohs(tvb, offset);
                offset += 2;
                if (attr_list_end>additional_length+8) break;
                while (offset+16<attr_list_end) {
                    guint32 attribute_length = tvb_get_ntohs(tvb, offset+14);
                    proto_item *att_item = proto_tree_add_text(subtree, tvb, offset, 16+attribute_length, "Attribute:");
                    proto_tree *att_tree = proto_item_add_subtree(att_item, ett_osd_attribute);
                    offset = dissect_osd_attribute_list_entry(pinfo, tvb, att_tree, att_item, offset, lun_info, TRUE);
                }
                offset = attr_list_end;
            }

        }
    }

}

static int
dissect_osd_requested_user_object_id(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* request user object id */
    proto_tree_add_item(tree, hf_scsi_osd_requested_user_object_id, tvb, offset, 8, ENC_NA);
    offset += 8;

    return offset;
}

static int
dissect_osd_number_of_user_objects(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* number_of_user_objects */
    proto_tree_add_item(tree, hf_scsi_osd_number_of_user_objects, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    return offset;
}

static void
dissect_osd_create(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   guint offset, gboolean isreq, gboolean iscdb,
                   guint payload_len _U_, scsi_task_data_t *cdata _U_,
                   scsi_osd_conv_info_t *conv_info _U_,
                   scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* requested user_object id */
        dissect_osd_requested_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 4 reserved bytes */
        offset += 4;

        /* number of user objects */
        dissect_osd_number_of_user_objects(tvb, offset, tree);
        offset += 2;

        /* 14 reserved bytes */
        offset += 14;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for create */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for create */
    }

}


static void
dissect_osd_remove_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             guint offset, gboolean isreq, gboolean iscdb,
                             guint payload_len _U_, scsi_task_data_t *cdata _U_,
                             scsi_osd_conv_info_t *conv_info _U_,
                             scsi_osd_lun_info_t *lun_info)
{
    gboolean osd2 = ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->svcaction&0x80;
    ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->osd2 = osd2;

    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        if (osd2) dissect_osd2_isolation(tvb, offset, tree);
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        if (osd2) proto_tree_add_item(tree, hf_scsi_osd2_remove_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, TRUE);
        offset += 8;

        /* 24 reserved bytes */
        offset += 24;

        if (osd2) {
            dissect_osd2_cdb_continuation_length(pinfo, tvb, offset, tree, cdata);
        } else {
            /* 4 reserved bytes */
        }
        offset += 4;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += osd2?104:80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += osd2?52:40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* CDB continuation */
        dissect_osd2_cdb_continuation(pinfo, tvb, offset, tree, cdata);

        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for remove partition */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for remove partition */
    }

}

static const value_string key_to_set_vals[] = {
    {1, "Root"},
    {2, "Partition"},
    {3, "Working"},
    {0, NULL},
};
static void
dissect_osd_key_to_set(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_osd_key_to_set, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_osd_set_key_version(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_osd_set_key_version, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_osd_key_identifier(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_osd_key_identifier, tvb, offset, 7, ENC_NA);
}

static void
dissect_osd_seed(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_osd_seed, tvb, offset, 20, ENC_NA);
}

static void
dissect_osd_set_key(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                    guint offset, gboolean isreq, gboolean iscdb,
                    guint payload_len _U_, scsi_task_data_t *cdata _U_,
                    scsi_osd_conv_info_t *conv_info _U_,
                    scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* a reserved byte */
        offset += 1;

        /* getset attributes byte and key to set*/
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        dissect_osd_key_to_set(tvb, offset, tree);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* key version */
        dissect_osd_set_key_version(tvb, offset, tree);
        offset += 1;

        /* key identifier */
        dissect_osd_key_identifier(tvb, offset, tree);
        offset += 7;

        /* seed */
        dissect_osd_seed(tvb, offset, tree);
        offset += 20;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for set key */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for set key */
    }

}

static void
dissect_osd_remove(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   guint offset, gboolean isreq, gboolean iscdb,
                   guint payload_len _U_, scsi_task_data_t *cdata _U_,
                   scsi_osd_conv_info_t *conv_info _U_,
                   scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* user object id */
        dissect_osd_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 20 reserved bytes */
        offset += 20;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for remove */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for remove */
    }

}

static void
dissect_osd_collection_fcr(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    proto_tree_add_item(tree, hf_scsi_osd_collection_fcr, tvb, offset, 1, ENC_BIG_ENDIAN);
}

static void
dissect_osd_remove_collection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              guint offset, gboolean isreq, gboolean iscdb,
                              guint payload_len _U_, scsi_task_data_t *cdata _U_,
                              scsi_osd_conv_info_t *conv_info _U_,
                              scsi_osd_lun_info_t *lun_info)
{
    gboolean osd2 = ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->svcaction&0x80;
    ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->osd2 = osd2;

    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        dissect_osd_collection_fcr(tvb, offset, tree);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* collection object id */
        dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd_collection_object_id);
        offset += 8;

        /* 16 reserved bytes */
        offset += 16;

        if (osd2) {
            dissect_osd2_cdb_continuation_length(pinfo, tvb, offset, tree, cdata);
        } else {
            /* 4 reserved bytes */
        }
        offset += 4;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += osd2?104:80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += osd2?52:40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* CDB continuation */
        dissect_osd2_cdb_continuation(pinfo, tvb, offset, tree, cdata);

        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for remove collection */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for remove collection */
    }

}


static int
dissect_osd_length(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* length */
    proto_tree_add_item(tree, hf_scsi_osd_length, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}

static int
dissect_osd_starting_byte_address(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* starting_byte_address */
    proto_tree_add_item(tree, hf_scsi_osd_starting_byte_address, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;

    return offset;
}


static void
dissect_osd_write(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  guint offset, gboolean isreq, gboolean iscdb,
                  guint payload_len _U_, scsi_task_data_t *cdata _U_,
                  scsi_osd_conv_info_t *conv_info _U_,
                  scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte / sort order */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* user object id */
        dissect_osd_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 4 reserved bytes */
        offset += 4;

        /* length */
        dissect_osd_length(tvb, offset, tree);
        offset += 8;

        /* starting byte address */
        dissect_osd_starting_byte_address(tvb, offset, tree);
        offset += 8;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* xxx should dissect the data ? */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for WRITE */
    }

}

static void
dissect_osd_create_collection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                              guint offset, gboolean isreq, gboolean iscdb,
                              guint payload_len _U_, scsi_task_data_t *cdata _U_,
                              scsi_osd_conv_info_t *conv_info _U_,
                              scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        dissect_osd_collection_fcr(tvb, offset, tree);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* requested collection object id */
        dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd_requested_collection_object_id);
        offset += 8;

        /* 20 reserved bytes */
        offset += 20;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for create collection */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for create collection */
    }

}


static const value_string flush_scope_vals[] = {
    {0, "User object data and attributes"},
    {1, "User object attributes only"},
    {0, NULL}
};

static int
dissect_osd_flush_scope(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* flush scope */
    proto_tree_add_item(tree, hf_scsi_osd_flush_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static void
dissect_osd_flush(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                  guint offset, gboolean isreq, gboolean iscdb,
                  guint payload_len _U_, scsi_task_data_t *cdata _U_,
                  scsi_osd_conv_info_t *conv_info _U_,
                  scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_flush_scope(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* user object id */
        dissect_osd_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 20 reserved bytes */
        offset += 20;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for flush */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for flush */
    }

}


static const value_string flush_collection_scope_vals[] = {
    {0, "List of user objects contained in the collection"},
    {1, "Collection attributes only"},
    {2, "List of user objects and collection attributes"},
    {0, NULL}
};

static int
dissect_osd_flush_collection_scope(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* flush collection scope */
    proto_tree_add_item(tree, hf_scsi_osd_flush_collection_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static void
dissect_osd_flush_collection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             guint offset, gboolean isreq, gboolean iscdb,
                             guint payload_len _U_, scsi_task_data_t *cdata _U_,
                             scsi_osd_conv_info_t *conv_info _U_,
                             scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_flush_collection_scope(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        dissect_osd_collection_fcr(tvb, offset, tree);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* collection object id */
        dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd_collection_object_id);
        offset += 8;

        /* 20 reserved bytes */
        offset += 20;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for flush collection */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for flush collection */
    }

}


static void
dissect_osd_append(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   guint offset, gboolean isreq, gboolean iscdb,
                   guint payload_len _U_, scsi_task_data_t *cdata _U_,
                   scsi_osd_conv_info_t *conv_info _U_,
                   scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* user object id */
        dissect_osd_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 4 reserved bytes */
        offset += 4;

        /* length */
        dissect_osd_length(tvb, offset, tree);
        offset += 8;

        /* 8 reserved bytes */
        offset += 8;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* xxx should dissect the data ? */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for append */
    }

}

static void
dissect_osd_create_and_write(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                             guint offset, gboolean isreq, gboolean iscdb,
                             guint payload_len _U_, scsi_task_data_t *cdata _U_,
                             scsi_osd_conv_info_t *conv_info _U_,
                             scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* requested user_object id */
        dissect_osd_requested_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 4 reserved bytes */
        offset += 4;

        /* length */
        dissect_osd_length(tvb, offset, tree);
        offset += 8;

        /* starting byte address */
        dissect_osd_starting_byte_address(tvb, offset, tree);
        offset += 8;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* should we dissect the data? */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for create and write*/
    }

}


static const value_string flush_osd_scope_vals[] = {
    {0, "List of partitions contained in the OSD logical unit"},
    {1, "Root object attributes only"},
    {2, "Everything"},
    {0, NULL}
};

static int
dissect_osd_flush_osd_scope(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* flush osd scope */
    proto_tree_add_item(tree, hf_scsi_osd_flush_osd_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}

static void
dissect_osd_flush_osd(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                      guint offset, gboolean isreq, gboolean iscdb,
                      guint payload_len _U_, scsi_task_data_t *cdata _U_,
                      scsi_osd_conv_info_t *conv_info _U_,
                      scsi_osd_lun_info_t *lun_info _U_)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_flush_osd_scope(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 39 reserved bytes */
        offset += 39;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for flush osd */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for flush osd */
    }

}


static const value_string flush_partition_scope_vals[] = {
    {0, "List of user objects and collections in the partition"},
    {1, "Partition attributes only"},
    {2, "Everything"},
    {0, NULL}
};

static int
dissect_osd_flush_partition_scope(tvbuff_t *tvb, int offset, proto_tree *tree)
{
    /* flush partition scope */
    proto_tree_add_item(tree, hf_scsi_osd_flush_partition_scope, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    return offset;
}


static void
dissect_osd_flush_partition(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                            guint offset, gboolean isreq, gboolean iscdb,
                            guint payload_len _U_, scsi_task_data_t *cdata _U_,
                            scsi_osd_conv_info_t *conv_info _U_,
                            scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_flush_partition_scope(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* 28 reserved bytes */
        offset += 28;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for flush partition */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for flush partition */
    }

}


static void
dissect_osd_get_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_,
                           scsi_osd_conv_info_t *conv_info _U_,
                           scsi_osd_lun_info_t *lun_info)
{
    gboolean osd2 = ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->svcaction&0x80;
    ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->osd2 = osd2;

    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* user_object id */
        dissect_osd_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 16 reserved bytes */
        offset += 16;

        if (osd2) {
            dissect_osd2_cdb_continuation_length(pinfo, tvb, offset, tree, cdata);
        } else {
            /* 4 reserved bytes */
        }
        offset += 4;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += osd2?104:80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += osd2?52:40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for get attributes */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for get attributes */
    }

}


static void
dissect_osd_read(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                 guint offset, gboolean isreq, gboolean iscdb,
                 guint payload_len _U_, scsi_task_data_t *cdata _U_,
                 scsi_osd_conv_info_t *conv_info _U_,
                 scsi_osd_lun_info_t *lun_info)
{
    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte / sort order */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* user object id */
        dissect_osd_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 4 reserved bytes */
        offset += 4;

        /* length */
        dissect_osd_length(tvb, offset, tree);
        offset += 8;

        /* starting byte address */
        dissect_osd_starting_byte_address(tvb, offset, tree);
        offset += 8;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for READ */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

/* xxx should dissect the data ? */
    }

}


static void
dissect_osd_set_attributes(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                           guint offset, gboolean isreq, gboolean iscdb,
                           guint payload_len _U_, scsi_task_data_t *cdata _U_,
                           scsi_osd_conv_info_t *conv_info _U_,
                           scsi_osd_lun_info_t *lun_info)
{
    gboolean osd2 = ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->svcaction&0x80;
    ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->osd2 = osd2;

    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {
        /* options byte */
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partiton id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* user_object id */
        dissect_osd_user_object_id(tvb, offset, tree);
        offset += 8;

        /* 16 reserved bytes */
        offset += 16;

        if (osd2) {
            dissect_osd2_cdb_continuation_length(pinfo, tvb, offset, tree, cdata);
        } else {
            /* 4 reserved bytes */
        }
        offset += 4;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += osd2?104:80;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += osd2?52:40;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for set attributes */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for set attributes */
    }

}


static void
dissect_osd2_create_user_tracking_collection(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
                        scsi_osd_conv_info_t *conv_info _U_,
                        scsi_osd_lun_info_t *lun_info)
{
    ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->osd2 = TRUE;

    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {

        /* options byte */
        dissect_osd2_isolation(tvb, offset, tree);
        dissect_osd_option(tvb, offset, tree);
        offset += 1;

        /* getset attributes byte */
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partition id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* user_object id */
        dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd_requested_collection_object_id);
        offset += 8;

        /* 8 reserved bytes */
        offset += 8;

        /* source collection id */
        dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd2_source_collection_object_id);
        offset += 8;

        /*cdb continuation length*/
        dissect_osd2_cdb_continuation_length(pinfo, tvb, offset, tree, cdata);
        offset += 4;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 104;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 52;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* CDB continuation */
        dissect_osd2_cdb_continuation(pinfo, tvb, offset, tree, cdata);

        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for create user tracking collection */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data in for create user tracking collection */
    }

}

static void
dissect_osd2_query(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                        guint offset, gboolean isreq, gboolean iscdb,
                        guint payload_len _U_, scsi_task_data_t *cdata _U_,
                        scsi_osd_conv_info_t *conv_info _U_,
                        scsi_osd_lun_info_t *lun_info)
{
    ((scsi_osd_extra_data_t *)cdata->itlq->extra_data)->osd2 = TRUE;

    /* dissecting the CDB   dissection starts at byte 10 of the CDB */
    if (isreq && iscdb) {

        /* isolation field */
        dissect_osd2_isolation(tvb, offset, tree);
        offset += 1;

        /* immed_tr, getset attributes*/
        proto_tree_add_item(tree, hf_scsi_osd2_immed_tr, tvb, offset, 1, ENC_BIG_ENDIAN);
        dissect_osd_getsetattrib(tvb, offset, tree, cdata);
        offset += 1;

        /* timestamps control */
        dissect_osd_timestamps_control(tvb, offset, tree);
        offset += 1;

        /* 3 reserved bytes */
        offset += 3;

        /* partition id */
        dissect_osd_partition_id(pinfo, tvb, offset, tree, hf_scsi_osd_partition_id, lun_info, FALSE, FALSE);
        offset += 8;

        /* collection_object id */
        dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd_collection_object_id);
        offset += 8;

        /* allocation_length */
        dissect_osd_allocation_length(tvb, offset, tree, cdata);
        offset += 8;

        /* matches collection id */
        dissect_osd_collection_object_id(tvb, offset, tree, hf_scsi_osd2_matches_collection_object_id);
        offset += 8;

        /*cdb continuation length*/
        dissect_osd2_cdb_continuation_length(pinfo, tvb, offset, tree, cdata);
        offset += 4;

        /* attribute parameters */
        dissect_osd_attribute_parameters(pinfo, tvb, offset, tree, cdata);
        offset += 28;

        /* capability */
        dissect_osd_capability(tvb, offset, tree);
        offset += 104;

        /* security parameters */
        dissect_osd_security_parameters(tvb, offset, tree);
        offset += 52;
    }

    /* dissecting the DATA OUT */
    if (isreq && !iscdb) {
        /* CDB continuation */
        dissect_osd2_cdb_continuation(pinfo, tvb, offset, tree, cdata);

        /* attribute data out */
        dissect_osd_attribute_data_out(pinfo, tvb, offset, tree, cdata, lun_info);

        /* no data out for query */
    }

    /* dissecting the DATA IN */
    if (!isreq && !iscdb) {
        guint64  additional_length;
        guint64  allocation_length;
        guint64  remaining_length;
        guint8   format;
        proto_item *item;

        /* attribute data in */
        dissect_osd_attribute_data_in(pinfo, tvb, offset, tree, cdata, lun_info);

        allocation_length = cdata->itlq->alloc_len;
        remaining_length = tvb_length_remaining(tvb, offset);
        if (remaining_length<allocation_length) allocation_length = remaining_length;
        if (allocation_length<12) return;

        /* dissection of the LIST or LIST COLLECTION DATA-IN */
        /* additional length */
        additional_length = tvb_get_ntoh64(tvb, offset);
        if ((guint32)(allocation_length-8)<additional_length) additional_length = (guint32)(allocation_length-8);

        dissect_osd_additional_length(tvb, offset, tree);
        offset += 8;

        /* 3 reserved bytes */
        offset += 3;
        item = proto_tree_add_item(tree, hf_scsi_osd2_object_descriptor_format, tvb, offset, 1, ENC_BIG_ENDIAN);
        format = tvb_get_guint8(tvb, offset)>>2;
        offset += 1;
        if (format != 0x21) {
            expert_add_info(pinfo, item, &ei_osd2_invalid_object_descriptor_format);
            return;
        }

        while (additional_length > (offset-4)) {
            dissect_osd_user_object_id(tvb, offset, tree);
            offset += 8;
        }
    }

}

/* OSD Service Actions */
#define OSD_FORMAT_OSD                        0x8801
#define OSD_CREATE                            0x8802
#define OSD_LIST                              0x8803
#define OSD_READ                              0x8805
#define OSD_WRITE                             0x8806
#define OSD_APPEND                            0x8807
#define OSD_FLUSH                             0x8808
#define OSD_REMOVE                            0x880a
#define OSD_CREATE_PARTITION                  0x880b
#define OSD_REMOVE_PARTITION                  0x880c
#define OSD_GET_ATTRIBUTES                    0x880e
#define OSD_SET_ATTRIBUTES                    0x880f
#define OSD_CREATE_AND_WRITE                  0x8812
#define OSD_CREATE_COLLECTION                 0x8815
#define OSD_REMOVE_COLLECTION                 0x8816
#define OSD_LIST_COLLECTION                   0x8817
#define OSD_SET_KEY                           0x8818
#define OSD_FLUSH_COLLECTION                  0x881a
#define OSD_FLUSH_PARTITION                   0x881b
#define OSD_FLUSH_OSD                         0x881c

#define OSD_2_CREATE                          0x8882
#define OSD_2_LIST                            0x8883
#define OSD_2_READ                            0x8885
#define OSD_2_WRITE                           0x8886
#define OSD_2_APPEND                          0x8887
#define OSD_2_CLEAR                           0x8889
#define OSD_2_REMOVE                          0x888a
#define OSD_2_CREATE_PARTITION                0x888b
#define OSD_2_REMOVE_PARTITION                0x888c
#define OSD_2_GET_ATTRIBUTES                  0x888e
#define OSD_2_SET_ATTRIBUTES                  0x888f
#define OSD_2_CREATE_AND_WRITE                0x8892
#define OSD_2_COPY_USER_OBJECTS               0x8893
#define OSD_2_CREATE_USER_TRACKING_COLLECTION 0x8894
#define OSD_2_REMOVE_COLLECTION               0x8896
#define OSD_2_LIST_COLLECTION                 0x8897
#define OSD_2_QUERY                           0x88a0
#define OSD_2_REMOVE_MEMBER_OBJECTS           0x88a1
#define OSD_2_GET_MEMBER_ATTRIBUTES           0x88a2
#define OSD_2_SET_MEMBER_ATTRIBUTES           0x88a3

static const value_string scsi_osd_svcaction_vals[] = {
    {OSD_FORMAT_OSD,                        "Format OSD"},
    {OSD_CREATE,                            "Create"},
    {OSD_LIST,                              "List"},
    {OSD_READ,                              "Read"},
    {OSD_WRITE,                             "Write"},
    {OSD_APPEND,                            "Append"},
    {OSD_FLUSH,                             "Flush"},
    {OSD_REMOVE,                            "Remove"},
    {OSD_CREATE_PARTITION,                  "Create Partition"},
    {OSD_REMOVE_PARTITION,                  "Remove Partition"},
    {OSD_GET_ATTRIBUTES,                    "Get Attributes"},
    {OSD_SET_ATTRIBUTES,                    "Set Attributes"},
    {OSD_CREATE_AND_WRITE,                  "Create And Write"},
    {OSD_CREATE_COLLECTION,                 "Create Collection"},
    {OSD_REMOVE_COLLECTION,                 "Remove Collection"},
    {OSD_LIST_COLLECTION,                   "List Collection"},
    {OSD_SET_KEY,                           "Set Key"},
    {OSD_FLUSH_COLLECTION,                  "Flush Collection"},
    {OSD_FLUSH_PARTITION,                   "Flush Partition"},
    {OSD_FLUSH_OSD,                         "Flush OSD"},

    {OSD_2_CREATE,                          "Create (OSD-2)"},
    {OSD_2_LIST,                            "List (OSD-2)"},
    {OSD_2_READ,                            "Read (OSD-2)"},
    {OSD_2_WRITE,                           "Write (OSD-2)"},
    {OSD_2_APPEND,                          "Append (OSD-2)"},
    {OSD_2_CLEAR,                           "Clear (OSD-2)"},
    {OSD_2_REMOVE,                          "Remove (OSD-2)"},
    {OSD_2_CREATE_PARTITION,                "Create Partition (OSD-2)"},
    {OSD_2_REMOVE_PARTITION,                "Remove Partition (OSD-2)"},
    {OSD_2_GET_ATTRIBUTES,                  "Get Attributes (OSD-2)"},
    {OSD_2_SET_ATTRIBUTES,                  "Set Attributes (OSD-2)"},
    {OSD_2_CREATE_AND_WRITE,                "Create And Write (OSD-2)"},
    {OSD_2_COPY_USER_OBJECTS,               "Copy User Objects (OSD-2)"},
    {OSD_2_CREATE_USER_TRACKING_COLLECTION, "Create User Tracking Collection  (OSD-2)"},
    {OSD_2_REMOVE_COLLECTION,               "Remove Collection (OSD-2)"},
    {OSD_2_LIST_COLLECTION,                 "List Collection (OSD-2)"},
    {OSD_2_QUERY,                           "Query (OSD-2)"},
    {OSD_2_REMOVE_MEMBER_OBJECTS,           "Remove Member Objects (OSD-2)"},
    {OSD_2_GET_MEMBER_ATTRIBUTES,           "Get Member Attributes (OSD-2)"},
    {OSD_2_SET_MEMBER_ATTRIBUTES,           "Set Member Attributes (OSD-2)"},
    {0, NULL},
};
static value_string_ext scsi_osd_svcaction_vals_ext = VALUE_STRING_EXT_INIT(scsi_osd_svcaction_vals);

/* OSD Service Action dissectors */
typedef struct _scsi_osd_svcaction_t {
    guint16              svcaction;
    scsi_osd_dissector_t dissector;
} scsi_osd_svcaction_t;

static const scsi_osd_svcaction_t scsi_osd_svcaction[] = {
    {OSD_FORMAT_OSD,                        dissect_osd_format_osd},
    {OSD_CREATE,                            dissect_osd_create},
    {OSD_LIST,                              dissect_osd_list},
    {OSD_READ,                              dissect_osd_read},
    {OSD_WRITE,                             dissect_osd_write},
    {OSD_APPEND,                            dissect_osd_append},
    {OSD_FLUSH,                             dissect_osd_flush},
    {OSD_REMOVE,                            dissect_osd_remove},
    {OSD_CREATE_PARTITION,                  dissect_osd_create_partition},
    {OSD_REMOVE_PARTITION,                  dissect_osd_remove_partition},
    {OSD_GET_ATTRIBUTES,                    dissect_osd_get_attributes},
    {OSD_SET_ATTRIBUTES,                    dissect_osd_set_attributes},
    {OSD_CREATE_AND_WRITE,                  dissect_osd_create_and_write},
    {OSD_CREATE_COLLECTION,                 dissect_osd_create_collection},
    {OSD_REMOVE_COLLECTION,                 dissect_osd_remove_collection},
    {OSD_LIST_COLLECTION,                   dissect_osd_list},
    {OSD_SET_KEY,                           dissect_osd_set_key},
    {OSD_FLUSH_COLLECTION,                  dissect_osd_flush_collection},
    {OSD_FLUSH_PARTITION,                   dissect_osd_flush_partition},
    {OSD_FLUSH_OSD,                         dissect_osd_flush_osd},
    {OSD_2_LIST,                            dissect_osd_list},
    {OSD_2_CREATE_PARTITION,                dissect_osd_create_partition},
    {OSD_2_CREATE_USER_TRACKING_COLLECTION, dissect_osd2_create_user_tracking_collection},
    {OSD_2_REMOVE_PARTITION,                dissect_osd_remove_partition},
    {OSD_2_LIST_COLLECTION,                 dissect_osd_list},
    {OSD_2_CREATE_USER_TRACKING_COLLECTION, dissect_osd2_create_user_tracking_collection},
    {OSD_2_REMOVE_COLLECTION,               dissect_osd_remove_collection},
    {OSD_2_GET_ATTRIBUTES,                  dissect_osd_get_attributes},
    {OSD_2_SET_ATTRIBUTES,                  dissect_osd_set_attributes},
    {OSD_2_QUERY,                           dissect_osd2_query},
    {0, NULL},
};

static scsi_osd_dissector_t
find_svcaction_dissector(guint16 svcaction)
{
    const scsi_osd_svcaction_t *sa = scsi_osd_svcaction;

    while (sa && sa->dissector) {
        if (sa->svcaction == svcaction) {
            return sa->dissector;
        }
        sa++;
    }
    return NULL;
}



static void
dissect_osd_opcode(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                   guint offset, gboolean isreq, gboolean iscdb,
                   guint payload_len, scsi_task_data_t *cdata)
{
    guint16               svcaction = 0;
    scsi_osd_dissector_t  dissector;
    scsi_osd_conv_info_t *conv_info;
    scsi_osd_lun_info_t  *lun_info;

    if (!tree) {
        return;
    }

    /* We must have an itl an itlq and a conversation */
    if (!cdata || !cdata->itl || !cdata->itl->conversation || !cdata->itlq) {
        return;
    }
    /* make sure we have a conversation info for this */
    conv_info = (scsi_osd_conv_info_t *)conversation_get_proto_data(cdata->itl->conversation, proto_scsi_osd);
    if (!conv_info) {
        conv_info = wmem_new(wmem_file_scope(), scsi_osd_conv_info_t);
        conv_info->luns = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(cdata->itl->conversation, proto_scsi_osd, conv_info);
    }
    /* make sure we have a lun_info structure for this */
    lun_info = (scsi_osd_lun_info_t *)wmem_tree_lookup32(conv_info->luns, cdata->itlq->lun);
    if (!lun_info) {
        lun_info = wmem_new(wmem_file_scope(), scsi_osd_lun_info_t);
        lun_info->partitions = wmem_tree_new(wmem_file_scope());
        wmem_tree_insert32(conv_info->luns, cdata->itlq->lun, (void *)lun_info);
    }

    /* dissecting the CDB */
    if (isreq && iscdb) {
        proto_tree_add_item (tree, hf_scsi_control, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        /* 5 reserved bytes */
        offset += 5;

        proto_tree_add_item (tree, hf_scsi_osd_add_cdblen, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        svcaction = tvb_get_ntohs(tvb, offset);
        if (cdata && cdata->itlq) {
            /* We must store the service action for this itlq
             * so we can indentify what the data contains
             */
            if ((!pinfo->fd->flags.visited) || (!cdata->itlq->extra_data)) {
                scsi_osd_extra_data_t *extra_data;

                extra_data = wmem_new(wmem_file_scope(), scsi_osd_extra_data_t);
                extra_data->svcaction = svcaction;
                extra_data->gsatype = 0;
                extra_data->osd2 = 0;
                extra_data->continuation_length = 0;
                cdata->itlq->extra_data = extra_data;
            }
        }
        proto_tree_add_item (tree, hf_scsi_osd_svcaction, tvb, offset, 2, ENC_BIG_ENDIAN);
        offset += 2;


        col_append_str(pinfo->cinfo, COL_INFO,
                val_to_str_ext_const(svcaction, &scsi_osd_svcaction_vals_ext, "Unknown OSD Service Action"));

        dissector = find_svcaction_dissector(svcaction);
        if (dissector) {
            (*dissector)(tvb, pinfo, tree, offset, isreq, iscdb, payload_len, cdata, conv_info, lun_info);
        }
        return;
    }

    /* If it was not a CDB, try to find the service action and pass it
     * off to the service action dissector
     */
    if (cdata && cdata->itlq && cdata->itlq->extra_data) {
        scsi_osd_extra_data_t *extra_data = (scsi_osd_extra_data_t *)cdata->itlq->extra_data;
        svcaction = extra_data->svcaction;
    }
    col_append_str(pinfo->cinfo, COL_INFO,
        val_to_str_ext_const(svcaction, &scsi_osd_svcaction_vals_ext, "Unknown OSD Service Action"));
    if (svcaction) {
        proto_item *it;
        it = proto_tree_add_uint_format_value(tree, hf_scsi_osd_svcaction, tvb, 0, 0, svcaction, "0x%04x", svcaction);
        PROTO_ITEM_SET_GENERATED(it);
    }
    dissector = find_svcaction_dissector(svcaction);
    if (dissector) {
        (*dissector)(tvb, pinfo, tree, offset, isreq, iscdb, payload_len, cdata, conv_info, lun_info);
    }

}


/* OSD Commands */
static const value_string scsi_osd_vals[] = {
    /* 0x12 */    {SCSI_SPC_INQUIRY,          "Inquiry"},
    /* 0x4C */    {SCSI_SPC_LOGSELECT,        "Log Select"},
    /* 0x4D */    {SCSI_SPC_LOGSENSE,         "Log Sense"},
    /* 0x55 */    {SCSI_SPC_MODESELECT10,     "Mode Select(10)"},
    /* 0x5A */    {SCSI_SPC_MODESENSE10,      "Mode Sense(10)"},
    /* 0x5E */    {SCSI_SPC_PERSRESVIN,       "Persistent Reserve In"},
    /* 0x5F */    {SCSI_SPC_PERSRESVOUT,      "Persistent Reserve Out"},
    /* 0x7f */    {SCSI_OSD_OPCODE,           "OSD Command" },
    /* 0xA0 */    {SCSI_SPC_REPORTLUNS,       "Report LUNs"},
    /* 0xA3 */    {SCSI_SPC_MGMT_PROTOCOL_IN, "Mgmt Protocol In"},
    {0, NULL},
};
value_string_ext scsi_osd_vals_ext = VALUE_STRING_EXT_INIT(scsi_osd_vals);

scsi_cdb_table_t scsi_osd_table[256] = {
/*OSD 0x00*/{NULL},
/*OSD 0x01*/{NULL},
/*OSD 0x02*/{NULL},
/*OSD 0x03*/{NULL},
/*OSD 0x04*/{NULL},
/*OSD 0x05*/{NULL},
/*OSD 0x06*/{NULL},
/*OSD 0x07*/{NULL},
/*OSD 0x08*/{NULL},
/*OSD 0x09*/{NULL},
/*OSD 0x0a*/{NULL},
/*OSD 0x0b*/{NULL},
/*OSD 0x0c*/{NULL},
/*OSD 0x0d*/{NULL},
/*OSD 0x0e*/{NULL},
/*OSD 0x0f*/{NULL},
/*OSD 0x10*/{NULL},
/*OSD 0x11*/{NULL},
/*OSD 0x12*/{dissect_spc_inquiry},
/*OSD 0x13*/{NULL},
/*OSD 0x14*/{NULL},
/*OSD 0x15*/{NULL},
/*OSD 0x16*/{NULL},
/*OSD 0x17*/{NULL},
/*OSD 0x18*/{NULL},
/*OSD 0x19*/{NULL},
/*OSD 0x1a*/{NULL},
/*OSD 0x1b*/{NULL},
/*OSD 0x1c*/{NULL},
/*OSD 0x1d*/{NULL},
/*OSD 0x1e*/{NULL},
/*OSD 0x1f*/{NULL},
/*OSD 0x20*/{NULL},
/*OSD 0x21*/{NULL},
/*OSD 0x22*/{NULL},
/*OSD 0x23*/{NULL},
/*OSD 0x24*/{NULL},
/*OSD 0x25*/{NULL},
/*OSD 0x26*/{NULL},
/*OSD 0x27*/{NULL},
/*OSD 0x28*/{NULL},
/*OSD 0x29*/{NULL},
/*OSD 0x2a*/{NULL},
/*OSD 0x2b*/{NULL},
/*OSD 0x2c*/{NULL},
/*OSD 0x2d*/{NULL},
/*OSD 0x2e*/{NULL},
/*OSD 0x2f*/{NULL},
/*OSD 0x30*/{NULL},
/*OSD 0x31*/{NULL},
/*OSD 0x32*/{NULL},
/*OSD 0x33*/{NULL},
/*OSD 0x34*/{NULL},
/*OSD 0x35*/{NULL},
/*OSD 0x36*/{NULL},
/*OSD 0x37*/{NULL},
/*OSD 0x38*/{NULL},
/*OSD 0x39*/{NULL},
/*OSD 0x3a*/{NULL},
/*OSD 0x3b*/{NULL},
/*OSD 0x3c*/{NULL},
/*OSD 0x3d*/{NULL},
/*OSD 0x3e*/{NULL},
/*OSD 0x3f*/{NULL},
/*OSD 0x40*/{NULL},
/*OSD 0x41*/{NULL},
/*OSD 0x42*/{NULL},
/*OSD 0x43*/{NULL},
/*OSD 0x44*/{NULL},
/*OSD 0x45*/{NULL},
/*OSD 0x46*/{NULL},
/*OSD 0x47*/{NULL},
/*OSD 0x48*/{NULL},
/*OSD 0x49*/{NULL},
/*OSD 0x4a*/{NULL},
/*OSD 0x4b*/{NULL},
/*OSD 0x4c*/{dissect_spc_logselect},
/*OSD 0x4d*/{dissect_spc_logsense},
/*OSD 0x4e*/{NULL},
/*OSD 0x4f*/{NULL},
/*OSD 0x50*/{NULL},
/*OSD 0x51*/{NULL},
/*OSD 0x52*/{NULL},
/*OSD 0x53*/{NULL},
/*OSD 0x54*/{NULL},
/*OSD 0x55*/{dissect_spc_modeselect10},
/*OSD 0x56*/{NULL},
/*OSD 0x57*/{NULL},
/*OSD 0x58*/{NULL},
/*OSD 0x59*/{NULL},
/*OSD 0x5a*/{dissect_spc_modesense10},
/*OSD 0x5b*/{NULL},
/*OSD 0x5c*/{NULL},
/*OSD 0x5d*/{NULL},
/*OSD 0x5e*/{dissect_spc_persistentreservein},
/*OSD 0x5f*/{dissect_spc_persistentreserveout},
/*OSD 0x60*/{NULL},
/*OSD 0x61*/{NULL},
/*OSD 0x62*/{NULL},
/*OSD 0x63*/{NULL},
/*OSD 0x64*/{NULL},
/*OSD 0x65*/{NULL},
/*OSD 0x66*/{NULL},
/*OSD 0x67*/{NULL},
/*OSD 0x68*/{NULL},
/*OSD 0x69*/{NULL},
/*OSD 0x6a*/{NULL},
/*OSD 0x6b*/{NULL},
/*OSD 0x6c*/{NULL},
/*OSD 0x6d*/{NULL},
/*OSD 0x6e*/{NULL},
/*OSD 0x6f*/{NULL},
/*OSD 0x70*/{NULL},
/*OSD 0x71*/{NULL},
/*OSD 0x72*/{NULL},
/*OSD 0x73*/{NULL},
/*OSD 0x74*/{NULL},
/*OSD 0x75*/{NULL},
/*OSD 0x76*/{NULL},
/*OSD 0x77*/{NULL},
/*OSD 0x78*/{NULL},
/*OSD 0x79*/{NULL},
/*OSD 0x7a*/{NULL},
/*OSD 0x7b*/{NULL},
/*OSD 0x7c*/{NULL},
/*OSD 0x7d*/{NULL},
/*OSD 0x7e*/{NULL},
/*OSD 0x7f*/{dissect_osd_opcode},
/*OSD 0x80*/{NULL},
/*OSD 0x81*/{NULL},
/*OSD 0x82*/{NULL},
/*OSD 0x83*/{NULL},
/*OSD 0x84*/{NULL},
/*OSD 0x85*/{NULL},
/*OSD 0x86*/{NULL},
/*OSD 0x87*/{NULL},
/*OSD 0x88*/{NULL},
/*OSD 0x89*/{NULL},
/*OSD 0x8a*/{NULL},
/*OSD 0x8b*/{NULL},
/*OSD 0x8c*/{NULL},
/*OSD 0x8d*/{NULL},
/*OSD 0x8e*/{NULL},
/*OSD 0x8f*/{NULL},
/*OSD 0x90*/{NULL},
/*OSD 0x91*/{NULL},
/*OSD 0x92*/{NULL},
/*OSD 0x93*/{NULL},
/*OSD 0x94*/{NULL},
/*OSD 0x95*/{NULL},
/*OSD 0x96*/{NULL},
/*OSD 0x97*/{NULL},
/*OSD 0x98*/{NULL},
/*OSD 0x99*/{NULL},
/*OSD 0x9a*/{NULL},
/*OSD 0x9b*/{NULL},
/*OSD 0x9c*/{NULL},
/*OSD 0x9d*/{NULL},
/*OSD 0x9e*/{NULL},
/*OSD 0x9f*/{NULL},
/*OSD 0xa0*/{dissect_spc_reportluns},
/*OSD 0xa1*/{NULL},
/*OSD 0xa2*/{NULL},
/*SPC 0xa3*/{dissect_spc_mgmt_protocol_in},
/*OSD 0xa4*/{NULL},
/*OSD 0xa5*/{NULL},
/*OSD 0xa6*/{NULL},
/*OSD 0xa7*/{NULL},
/*OSD 0xa8*/{NULL},
/*OSD 0xa9*/{NULL},
/*OSD 0xaa*/{NULL},
/*OSD 0xab*/{NULL},
/*OSD 0xac*/{NULL},
/*OSD 0xad*/{NULL},
/*OSD 0xae*/{NULL},
/*OSD 0xaf*/{NULL},
/*OSD 0xb0*/{NULL},
/*OSD 0xb1*/{NULL},
/*OSD 0xb2*/{NULL},
/*OSD 0xb3*/{NULL},
/*OSD 0xb4*/{NULL},
/*OSD 0xb5*/{NULL},
/*OSD 0xb6*/{NULL},
/*OSD 0xb7*/{NULL},
/*OSD 0xb8*/{NULL},
/*OSD 0xb9*/{NULL},
/*OSD 0xba*/{NULL},
/*OSD 0xbb*/{NULL},
/*OSD 0xbc*/{NULL},
/*OSD 0xbd*/{NULL},
/*OSD 0xbe*/{NULL},
/*OSD 0xbf*/{NULL},
/*OSD 0xc0*/{NULL},
/*OSD 0xc1*/{NULL},
/*OSD 0xc2*/{NULL},
/*OSD 0xc3*/{NULL},
/*OSD 0xc4*/{NULL},
/*OSD 0xc5*/{NULL},
/*OSD 0xc6*/{NULL},
/*OSD 0xc7*/{NULL},
/*OSD 0xc8*/{NULL},
/*OSD 0xc9*/{NULL},
/*OSD 0xca*/{NULL},
/*OSD 0xcb*/{NULL},
/*OSD 0xcc*/{NULL},
/*OSD 0xcd*/{NULL},
/*OSD 0xce*/{NULL},
/*OSD 0xcf*/{NULL},
/*OSD 0xd0*/{NULL},
/*OSD 0xd1*/{NULL},
/*OSD 0xd2*/{NULL},
/*OSD 0xd3*/{NULL},
/*OSD 0xd4*/{NULL},
/*OSD 0xd5*/{NULL},
/*OSD 0xd6*/{NULL},
/*OSD 0xd7*/{NULL},
/*OSD 0xd8*/{NULL},
/*OSD 0xd9*/{NULL},
/*OSD 0xda*/{NULL},
/*OSD 0xdb*/{NULL},
/*OSD 0xdc*/{NULL},
/*OSD 0xdd*/{NULL},
/*OSD 0xde*/{NULL},
/*OSD 0xdf*/{NULL},
/*OSD 0xe0*/{NULL},
/*OSD 0xe1*/{NULL},
/*OSD 0xe2*/{NULL},
/*OSD 0xe3*/{NULL},
/*OSD 0xe4*/{NULL},
/*OSD 0xe5*/{NULL},
/*OSD 0xe6*/{NULL},
/*OSD 0xe7*/{NULL},
/*OSD 0xe8*/{NULL},
/*OSD 0xe9*/{NULL},
/*OSD 0xea*/{NULL},
/*OSD 0xeb*/{NULL},
/*OSD 0xec*/{NULL},
/*OSD 0xed*/{NULL},
/*OSD 0xee*/{NULL},
/*OSD 0xef*/{NULL},
/*OSD 0xf0*/{NULL},
/*OSD 0xf1*/{NULL},
/*OSD 0xf2*/{NULL},
/*OSD 0xf3*/{NULL},
/*OSD 0xf4*/{NULL},
/*OSD 0xf5*/{NULL},
/*OSD 0xf6*/{NULL},
/*OSD 0xf7*/{NULL},
/*OSD 0xf8*/{NULL},
/*OSD 0xf9*/{NULL},
/*OSD 0xfa*/{NULL},
/*OSD 0xfb*/{NULL},
/*OSD 0xfc*/{NULL},
/*OSD 0xfd*/{NULL},
/*OSD 0xfe*/{NULL},
/*OSD 0xff*/{NULL}
};




void
proto_register_scsi_osd(void)
{
    expert_module_t *expert_scsi_osd;

    static hf_register_info hf[] = {
        { &hf_scsi_osd_opcode,
          {"OSD Opcode", "scsi_osd.opcode", FT_UINT8, BASE_HEX | BASE_EXT_STRING,
           &scsi_osd_vals_ext, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_add_cdblen,
          {"Additional CDB Length", "scsi_osd.addcdblen", FT_UINT8, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_svcaction,
          {"Service Action", "scsi_osd.svcaction", FT_UINT16, BASE_HEX | BASE_EXT_STRING,
           &scsi_osd_svcaction_vals_ext, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_option,
          {"Options Byte", "scsi_osd.option", FT_UINT8, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_option_dpo,
          {"DPO", "scsi_osd.option.dpo", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), 0x10, NULL, HFILL}},
        { &hf_scsi_osd_option_fua,
          {"FUA", "scsi_osd.option.fua", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), 0x08, NULL, HFILL}},
        { &hf_scsi_osd_getsetattrib,
          {"GET/SET CDBFMT", "scsi_osd.getset", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_getsetattrib_vals), 0x30, NULL, HFILL}},
        { &hf_scsi_osd_timestamps_control,
          {"Timestamps Control", "scsi_osd.timestamps_control", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_timestamps_control_vals), 0x0, NULL, HFILL}},
        { &hf_scsi_osd_formatted_capacity,
          {"Formatted Capacity", "scsi_osd.formatted_capacity", FT_UINT64, BASE_DEC,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_get_attributes_page,
          {"Get Attributes Page", "scsi_osd.get_attributes_page", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_get_attributes_list_length,
          {"Get Attributes List Length", "scsi_osd.get_attributes_list_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_get_attributes_list_offset,
          {"Get Attributes List Offset", "scsi_osd.get_attributes_list_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attributes_list_length,
          {"Set Attributes List Length", "scsi_osd.set_attributes_list_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attributes_list_offset,
          {"Set Attributes List Offset", "scsi_osd.set_attributes_list_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_get_attributes_allocation_length,
          {"Get Attributes Allocation Length", "scsi_osd.get_attributes_allocation_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_retrieved_attributes_offset,
          {"Retrieved Attributes Offset", "scsi_osd.retrieved_attributes_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attributes_page,
          {"Set Attributes Page", "scsi_osd.set_attributes_page", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attribute_length,
          {"Set Attribute Length", "scsi_osd.set_attribute_length", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attribute_number,
          {"Set Attribute Number", "scsi_osd.set_attribute_number", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_set_attributes_offset,
          {"Set Attributes Offset", "scsi_osd.set_attributes_offset", FT_UINT32, BASE_HEX,
           NULL, 0x0, NULL, HFILL}},
        { &hf_scsi_osd_capability_format,
          {"Capability Format", "scsi_osd.capability_format", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_capability_format_vals), 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_key_version,
          {"Key Version", "scsi_osd.key_version", FT_UINT8, BASE_HEX,
           NULL, 0xf0, NULL, HFILL}},
        { &hf_scsi_osd_icva,
          {"Integrity Check Value Algorithm", "scsi_osd.icva", FT_UINT8, BASE_HEX,
           NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_security_method,
          {"Security Method", "scsi_osd.security_method", FT_UINT8, BASE_HEX,
           NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_capability_expiration_time,
          {"Capability Expiration Time", "scsi_osd.capability_expiration_time", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_audit,
          {"Audit", "scsi_osd.audit", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_capability_discriminator,
          {"Capability Discriminator", "scsi_osd.capability_descriminator", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_object_created_time,
          {"Object Created Time", "scsi_osd.object_created_time", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_object_type,
          {"Object Type", "scsi_osd.object_type", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_object_type_vals), 0, NULL, HFILL}},
        { &hf_scsi_osd_permissions,
          {"Permissions", "scsi_osd.permissions", FT_UINT16, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_permissions_read,
          {"READ", "scsi_osd.permissions.read", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x8000, NULL, HFILL}},
        { &hf_scsi_osd_permissions_write,
          {"WRITE", "scsi_osd.permissions.write", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x4000, NULL, HFILL}},
        { &hf_scsi_osd_permissions_get_attr,
          {"GET_ATTR", "scsi_osd.permissions.get_attr", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x2000, NULL, HFILL}},
        { &hf_scsi_osd_permissions_set_attr,
          {"SET_ATTR", "scsi_osd.permissions.set_attr", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x1000, NULL, HFILL}},
        { &hf_scsi_osd_permissions_create,
          {"CREATE", "scsi_osd.permissions.create", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x0800, NULL, HFILL}},
        { &hf_scsi_osd_permissions_remove,
          {"REMOVE", "scsi_osd.permissions.remove", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x0400, NULL, HFILL}},
        { &hf_scsi_osd_permissions_obj_mgmt,
          {"OBJ_MGMT", "scsi_osd.permissions.obj_mgmt", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x0200, NULL, HFILL}},
        { &hf_scsi_osd_permissions_append,
          {"APPEND", "scsi_osd.permissions.append", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x0100, NULL, HFILL}},
        { &hf_scsi_osd_permissions_dev_mgmt,
          {"DEV_MGMT", "scsi_osd.permissions.dev_mgmt", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x0080, NULL, HFILL}},
        { &hf_scsi_osd_permissions_global,
          {"GLOBAL", "scsi_osd.permissions.global", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x0040, NULL, HFILL}},
        { &hf_scsi_osd_permissions_pol_sec,
          {"POL/SEC", "scsi_osd.permissions.pol_sec", FT_BOOLEAN, 16,
           TFS(&tfs_set_notset), 0x0020, NULL, HFILL}},

        { &hf_scsi_osd_object_descriptor_type,
          {"Object Descriptor Type", "scsi_osd.object_descriptor_type", FT_UINT8, BASE_HEX,
           VALS(scsi_osd_object_descriptor_type_vals), 0xf0, NULL, HFILL}},
        { &hf_scsi_osd_object_descriptor,
          {"Object Descriptor", "scsi_osd.object_descriptor", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_ricv,
          {"Request Integrity Check value", "scsi_osd.ricv", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_request_nonce,
          {"Request Nonce", "scsi_osd.request_nonce", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_diicvo,
          {"Data-In Integrity Check Value Offset", "scsi_osd.diicvo", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_doicvo,
          {"Data-Out Integrity Check Value Offset", "scsi_osd.doicvo", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_requested_partition_id,
          {"Requested Partition Id", "scsi_osd.requested_partition_id", FT_UINT64, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_sortorder,
          {"Sort Order", "scsi_osd.sort_order", FT_UINT8, BASE_DEC,
           VALS(scsi_osd_sort_order_vals), 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_partition_id,
          {"Partition Id", "scsi_osd.partition_id", FT_UINT64, BASE_HEX,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_list_identifier,
          {"List Identifier", "scsi_osd.list_identifier", FT_UINT32, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_allocation_length,
          {"Allocation Length", "scsi_osd.allocation_length", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_length,
          {"Length", "scsi_osd.length", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_starting_byte_address,
          {"Starting Byte Address", "scsi_osd.starting_byte_address", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_initial_object_id,
          {"Initial Object Id", "scsi_osd.initial_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_additional_length,
          {"Additional Length", "scsi_osd.additional_length", FT_UINT64, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_continuation_object_id,
          {"Continuation Object Id", "scsi_osd.continuation_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_user_object_id,
          {"User Object Id", "scsi_osd.user_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_list_flags_lstchg,
          {"LSTCHG", "scsi_osd.list.lstchg", FT_BOOLEAN, 8,
           TFS(&list_lstchg_tfs), 0x02, NULL, HFILL}},
        { &hf_scsi_osd_list_flags_root,
          {"ROOT", "scsi_osd.list.root", FT_BOOLEAN, 8,
           TFS(&list_root_tfs), 0x01, NULL, HFILL}},
        { &hf_scsi_osd_list_collection_flags_coltn,
          {"COLTN", "scsi_osd.list_collection.coltn", FT_BOOLEAN, 8,
           TFS(&list_coltn_tfs), 0x01, NULL, HFILL}},
        { &hf_scsi_osd_requested_user_object_id,
          {"Requested User Object Id", "scsi_osd.requested_user_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_number_of_user_objects,
          {"Number Of User Objects", "scsi_osd.number_of_user_objects", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_key_to_set,
          {"Key to Set", "scsi_osd.key_to_set", FT_UINT8, BASE_DEC,
           VALS(key_to_set_vals), 0x03, NULL, HFILL}},
        { &hf_scsi_osd_set_key_version,
          {"Key Version", "scsi_osd.set_key_version", FT_UINT8, BASE_DEC,
           NULL, 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_key_identifier,
          {"Key Identifier", "scsi_osd.key_identifier", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_seed,
          {"Seed", "scsi_osd.seed", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_collection_fcr,
          {"FCR", "scsi_osd.collection.fcr", FT_BOOLEAN, 8,
           TFS(&tfs_set_notset), 0x01, NULL, HFILL}},
        { &hf_scsi_osd_collection_object_id,
          {"Collection Object Id", "scsi_osd.collection_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_requested_collection_object_id,
          {"Requested Collection Object Id", "scsi_osd.requested_collection_object_id", FT_BYTES, BASE_NONE,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_partition_created_in,
          { "Created In", "scsi_osd.partition.created_in", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "The frame this partition was created", HFILL }},

        { &hf_scsi_osd_partition_removed_in,
          { "Removed In", "scsi_osd.partition.removed_in", FT_FRAMENUM, BASE_NONE,
          NULL, 0x0, "The frame this partition was removed", HFILL }},

        { &hf_scsi_osd_flush_scope,
          {"Flush Scope", "scsi_osd.flush.scope", FT_UINT8, BASE_DEC,
           VALS(flush_scope_vals), 0x03, NULL, HFILL}},

        { &hf_scsi_osd_flush_collection_scope,
          {"Flush Collection Scope", "scsi_osd.flush_collection.scope", FT_UINT8, BASE_DEC,
           VALS(flush_collection_scope_vals), 0x03, NULL, HFILL}},

        { &hf_scsi_osd_flush_partition_scope,
          {"Flush Partition Scope", "scsi_osd.flush_partition.scope", FT_UINT8, BASE_DEC,
           VALS(flush_partition_scope_vals), 0x03, NULL, HFILL}},

        { &hf_scsi_osd_flush_osd_scope,
          {"Flush OSD Scope", "scsi_osd.flush_osd.scope", FT_UINT8, BASE_DEC,
           VALS(flush_osd_scope_vals), 0x03, NULL, HFILL}},
        { &hf_scsi_osd_attributes_list_type,
          {"Attributes List Type", "scsi_osd.attributes_list.type", FT_UINT8, BASE_HEX,
           VALS(attributes_list_type_vals), 0x0f, NULL, HFILL}},
        { &hf_scsi_osd_attributes_list_length,
          {"Attributes List Length", "scsi_osd.attributes_list.length", FT_UINT16, BASE_DEC,
           NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_attributes_page,
          {"Attributes Page", "scsi_osd.attributes.page", FT_UINT32, BASE_HEX | BASE_EXT_STRING,
          &attributes_page_vals_ext, 0, NULL, HFILL}},
        { &hf_scsi_osd_attribute_number,
          {"Attribute Number", "scsi_osd.attribute.number", FT_UINT32, BASE_HEX,
          NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_attribute_length,
          {"Attribute Length", "scsi_osd.attribute.length", FT_UINT16, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_attributes_list_length,
         {"Attributes List Length", "scsi_osd2.attributes_list.length", FT_UINT32, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_attrval_user_object_logical_length,
         {"User Object Logical Length", "scsi_osd.user_object.logical_length", FT_UINT64, BASE_DEC,
          NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_attrval_object_type,
         {"Object Type", "scsi_osd.attr.object_type",  FT_UINT8, BASE_HEX, VALS(scsi_osd_object_type_vals), 0, NULL, HFILL}},
        { &hf_scsi_osd_attrval_partition_id,
         {"Partition ID", "scsi_osd.attr.partition_id", FT_UINT64, BASE_HEX,
          NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd_attrval_object_id,
         {"Object ID", "scsi_osd.attr.object_id", FT_UINT64, BASE_HEX,
          NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_set_attribute_value,
         {"Set Attributes Value", "scsi_osd.set_attribute_value", FT_BYTES, BASE_NONE, 0, 0, NULL, HFILL}},
        { &hf_scsi_osd2_isolation,
         {"Isolation", "scsi_osd2.isolation", FT_UINT8, BASE_HEX, VALS(scsi_osd2_isolation_val), 0x0F, NULL, HFILL}},
        { &hf_scsi_osd2_list_attr,
         {"LIST ATTR flag", "scsi_osd2.list_attr", FT_BOOLEAN, 8, 0, 0x40, NULL, HFILL}},
        { &hf_scsi_osd2_object_descriptor_format,
         {"Object Descriptor Format", "scsi_osd2.object_descriptor_format", FT_UINT8, BASE_HEX, VALS(scsi_osd2_object_descriptor_format_val), 0xFC, NULL, HFILL}},
        { &hf_scsi_osd2_immed_tr,
         {"Immed TR", "scsi_osd2.immed_tr", FT_UINT8, BASE_DEC, 0, 0x80, NULL, HFILL}},
        { &hf_scsi_osd2_remove_scope,
        {"Remove scope", "scsi_osd2.remove_scope", FT_UINT8, BASE_HEX, VALS(scsi_osd2_remove_scope), 0x07, NULL, HFILL}},
        { &hf_scsi_osd2_source_collection_object_id,
         {"Source Collection Object ID", "scsi_osd2.source_collection_object_id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_matches_collection_object_id,
         {"Matches Collection Object ID", "scsi_osd2.matches_collection_object_id", FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_cdb_continuation_length,
         {"CDB Continuation Length", "scsi_osd2.cdb_continuation.length", FT_UINT32, BASE_DEC, 0, 0, NULL, HFILL}},
        { &hf_scsi_osd2_cdb_continuation_format,
         {"CDB Continuation Format", "scsi_osd2.cdb_continuation.format", FT_UINT8, BASE_HEX, VALS(scsi_osd2_cdb_continuation_format_val), 0, NULL, HFILL}},
        { &hf_scsi_osd2_continued_service_action,
         {"Continued Service Action", "scsi_osd2.cdb_continuation.sa", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_cdb_continuation_descriptor_type,
         {"Descriptor Type", "scsi_osd2.cdb_continuation.desc.type", FT_UINT16, BASE_HEX, VALS(scsi_osd2_cdb_continuation_descriptor_type_val), 0, NULL, HFILL}},
        { &hf_scsi_osd2_cdb_continuation_descriptor_pad_length,
         {"Descriptor Pad Length", "scsi_osd2.cdb_continuation.desc.padlen", FT_UINT8, BASE_DEC, NULL, 0x7, NULL, HFILL}},
        { &hf_scsi_osd2_cdb_continuation_descriptor_length,
         {"Descriptor Length", "scsi_osd2.cdb_continuation.desc.length", FT_UINT32, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_query_type,
         {"Query Type", "scsi_osd2.query.type", FT_UINT8, BASE_HEX, VALS(scsi_osd2_query_type_vals), 0x0f, NULL, HFILL}},
        { &hf_scsi_osd2_query_entry_length,
         {"Entry Length", "scsi_osd2.query.entry.length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_query_attributes_page,
         {"Attributes Page", "scsi_osd2.query.entry.page", FT_UINT32, BASE_HEX | BASE_EXT_STRING, &attributes_page_vals_ext, 0, NULL, HFILL}},
        { &hf_scsi_osd2_query_attribute_number,
         {"Attribute Number", "scsi_osd2.query.entry.number", FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_query_minimum_attribute_value_length,
         {"Minimum Attribute Value Length", "scsi_osd2.query.entry.min_length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},
        { &hf_scsi_osd2_query_maximum_attribute_value_length,
         {"Maximum Attribute Value Length", "scsi_osd2.query.entry.max_length", FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL}},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_osd_option,
        &ett_osd_partition,
        &ett_osd_attribute_parameters,
        &ett_osd_capability,
        &ett_osd_permission_bitmask,
        &ett_osd_security_parameters,
        &ett_osd_get_attributes,
        &ett_osd_set_attributes,
        &ett_osd_multi_object,
        &ett_osd_attribute,
        &ett_osd2_query_criteria_entry,
    };

    /* Setup expert info */
    static ei_register_info ei[] = {
        { &ei_osd_attr_unknown,    { "scsi_osd.attr_unknown",    PI_UNDECODED, PI_NOTE,  "Unknown attribute, cannot decode attribute value", EXPFILL }},
        { &ei_osd2_invalid_offset, { "scsi_osd2.invalid_offset", PI_UNDECODED, PI_ERROR, "Invalid offset exponent", EXPFILL }},
        { &ei_osd2_invalid_object_descriptor_format, { "scsi_osd2.object_descriptor_format.invalid", PI_UNDECODED, PI_ERROR, "Invalid list format", EXPFILL }},
        { &ei_osd_unknown_attributes_list_type, {"scsi_osd.attributes_list.type.invalid", PI_UNDECODED, PI_ERROR, "Unknown attribute list type", EXPFILL }},
        { &ei_osd2_cdb_continuation_format_unknown, {"scsi_osd2.cdb_continuation.format.unknown", PI_UNDECODED, PI_ERROR, "Unknown CDB Continuation Format", EXPFILL }},
        { &ei_osd2_continued_service_action_mismatch, {"scsi_osd2.cdb_continuation.sa.mismatch", PI_PROTOCOL, PI_WARN, "CONTINUED SERVICE ACTION and SERVICE ACTION do not match", EXPFILL }},
        { &ei_osd2_cdb_continuation_descriptor_type_unknown, {"scsi_osd2.cdb_continuation.desc.type.unknown", PI_UNDECODED, PI_WARN, "Unknown descriptor type", EXPFILL }},
        { &ei_osd2_cdb_continuation_descriptor_length_invalid, {"scsi_osd2.cdb_continuation.desc.length.invalid", PI_PROTOCOL, PI_ERROR, "Invalid descriptor length (not a multiple of 8)", EXPFILL }},
        { &ei_osd2_cdb_continuation_length_invalid, {"scsi_osd2.cdb_continuation.length.invalid", PI_PROTOCOL, PI_ERROR, "Invalid CDB continuation length", EXPFILL }},
        { &ei_osd_attr_length_invalid, {"scsi_osd.attribute_length.invalid", PI_PROTOCOL, PI_ERROR, "Invalid Attribute Length", EXPFILL }},
        { &ei_osd2_query_values_equal, {"scsi_osd2.query.entry.equal", PI_PROTOCOL, PI_NOTE, "The minimum and maximum values are equal", EXPFILL }},
    };

    /* Register the protocol name and description */
    proto_scsi_osd = proto_register_protocol("SCSI_OSD", "SCSI_OSD", "scsi_osd");

    /* Required function calls to register the header fields and subtrees used */
    proto_register_field_array(proto_scsi_osd, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    /* Register expert info */
    expert_scsi_osd = expert_register_protocol(proto_scsi_osd);
    expert_register_field_array(expert_scsi_osd, ei, array_length(ei));
}

void
proto_reg_handoff_scsi_osd(void)
{
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
