/* packet-iso15765.c
 * Routines for iso15765 protocol packet disassembly
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * CAN ID Mapping
 *
 * When using ISO15765 to transport UDS and others, the diagnostic addresses might be
 * determined by mapping the underlaying CAN ID (29bit or 11bit).
 *
 * Option 1: Two Addresses can be determined (Source and Target Address.
 * Option 2: One Address can be determined (ECU Address).
 * Option 3: No Address can be determined.
 *
 * For Option 1 and 2 the ISO15765_can_id_mappings table can be used to determine the addresses:
 * - Ext Addr determines, if the CAN ID is 29bit (true) or 11bit (false)
 * - CAN ID and CAN ID Mask determined how to know if a CAN ID should be mapped
 * - Source Addr Mask and Target Addr Mask show the bits used to determine the addresses of Option 1
 * - ECU Addr Mask defines the bits for the address of Option 2
 *
 * Example:
 * - ISO15765 is applicable to all 29bit CAN IDs 0x9988TTSS, with TT the target address and SS the source address.
 * - Ext Addr: true
 * - CAN ID: 0x99880000
 * - CAN ID Mask: 0xffff0000
 * - Target Addr Mask: 0x0000ff00
 * - Source Addr Mask: 0x000000ff
 *
 * The addresses are passed via iso15765data_t to the next dissector (e.g., UDS).
 */

/*
 * Support for FlexRay variant, see: https://www.autosar.org/fileadmin/standards/R20-11/CP/AUTOSAR_SWS_FlexRayARTransportLayer.pdf
*/

#include "config.h"

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/decode_as.h>
#include <epan/reassemble.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/uat.h>
#include <wsutil/bits_ctz.h>
#include <wsutil/bits_count_ones.h>
#include <wiretap/wtap.h>

#include "packet-socketcan.h"
#include "packet-lin.h"
#include "packet-flexray.h"
#include "packet-iso15765.h"
#include "packet-autosar-ipdu-multiplexer.h"
#include "packet-pdu-transport.h"

void proto_register_iso15765(void);
void proto_reg_handoff_iso15765(void);

#define ISO15765_MESSAGE_TYPE_MASK 0xF0
#define ISO15765_MESSAGE_TYPES_SINGLE_FRAME 0
#define ISO15765_MESSAGE_TYPES_FIRST_FRAME 1
#define ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME 2
#define ISO15765_MESSAGE_TYPES_FLOW_CONTROL 3
#define ISO15765_MESSAGE_TYPES_FR_SINGLE_FRAME_EXT 4
#define ISO15765_MESSAGE_TYPES_FR_FIRST_FRAME_EXT 5
#define ISO15765_MESSAGE_TYPES_FR_CONSECUTIVE_FRAME_2 6
#define ISO15765_MESSAGE_TYPES_FR_ACK_FRAME 7

#define ISO15765_MESSAGE_DATA_LENGTH_MASK 0x0F
#define ISO15765_MESSAGE_SEQUENCE_NUMBER_MASK 0x0F
#define ISO15765_MESSAGE_FLOW_STATUS_MASK 0x0F

#define ISO15765_MESSAGE_FIRST_FRAME_DATA_LENGTH_MASK 0x0FFF

#define ISO15765_MESSAGE_AUTOSAR_ACK_MASK 0xF0
#define ISO15765_AUTOSAR_ACK_OFFSET 3

#define ISO15765_ADDR_INVALID 0xffffffff

typedef struct iso15765_identifier {
    uint32_t id;
    uint32_t seq;
    uint16_t frag_id;
    bool last;
    uint32_t bytes_used;
} iso15765_identifier_t;

typedef struct iso15765_frame {
    uint32_t seq;
    uint32_t last_byte_seen;
    uint32_t len;
    uint32_t bytes_in_cf;
    bool error;
    bool ff_seen;
    uint16_t last_frag_id;
    uint8_t  frag_id_high[16];
} iso15765_frame_t;

typedef struct iso15765_seq_key {
    uint32_t bus_type;
    uint32_t frame_id;
    uint32_t iface_id;
} iso15765_seq_key_t;

static unsigned
iso15765_seq_hash_func(const void *v)
{
    const iso15765_seq_key_t* key = (const iso15765_seq_key_t*)v;
    return (key->frame_id ^ key->bus_type);
}

static int
iso15765_seq_equal_func(const void *v1, const void *v2)
{
    const iso15765_seq_key_t* key1 = (const iso15765_seq_key_t*)v1;
    const iso15765_seq_key_t* key2 = (const iso15765_seq_key_t*)v2;

    return (key1->bus_type == key2->bus_type &&
        key1->frame_id == key2->frame_id &&
        key1->iface_id == key2->iface_id);
}

static const value_string iso15765_message_types[] = {
    {ISO15765_MESSAGE_TYPES_SINGLE_FRAME, "Single Frame"},
    {ISO15765_MESSAGE_TYPES_FIRST_FRAME, "First Frame"},
    {ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME, "Consecutive Frame"},
    {ISO15765_MESSAGE_TYPES_FLOW_CONTROL, "Flow control"},
    {ISO15765_MESSAGE_TYPES_FR_SINGLE_FRAME_EXT, "Single Frame Ext"},
    {ISO15765_MESSAGE_TYPES_FR_FIRST_FRAME_EXT, "First Frame Ext"},
    {ISO15765_MESSAGE_TYPES_FR_CONSECUTIVE_FRAME_2, "Consecutive Frame 2"},
    {ISO15765_MESSAGE_TYPES_FR_ACK_FRAME, "Ack Frame"},
    {0, NULL}
};

static const value_string iso15765_flow_status_types[] = {
    {0, "Continue to Send"},
    {1, "Wait"},
    {2, "Overflow"},
    {0, NULL}
};

#define NORMAL_ADDRESSING 1
#define EXTENDED_ADDRESSING 2

#define ZERO_BYTE_ADDRESSING 0
#define ONE_BYTE_ADDRESSING 1
#define TWO_BYTE_ADDRESSING 2

static int addressing = NORMAL_ADDRESSING;
static int flexray_addressing = ONE_BYTE_ADDRESSING;
static unsigned flexray_segment_size_limit;
static unsigned window = 8;
static range_t *configured_can_ids;
static range_t *configured_ext_can_ids;
static bool register_lin_diag_frames = true;
static range_t *configured_ipdum_pdu_ids;
static int ipdum_addressing = ZERO_BYTE_ADDRESSING;

/* Encoding */
static const enum_val_t enum_addressing[] = {
    {"normal", "Normal addressing", NORMAL_ADDRESSING},
    {"extended", "Extended addressing", EXTENDED_ADDRESSING},
    {NULL, NULL, 0}
};

/* Encoding */
static const enum_val_t enum_flexray_addressing[] = {
    {"1 Byte", "1 byte addressing", ONE_BYTE_ADDRESSING},
    {"2 Byte", "2 byte addressing", TWO_BYTE_ADDRESSING},
    {NULL, NULL, 0}
};

static const enum_val_t enum_ipdum_addressing[] = {
    {"0 Byte", "0 byte addressing", ZERO_BYTE_ADDRESSING},
    {"1 Byte", "1 byte addressing", ONE_BYTE_ADDRESSING},
    {"2 Byte", "2 byte addressing", TWO_BYTE_ADDRESSING},
    {NULL, NULL, 0}
};

static int hf_iso15765_address;
static int hf_iso15765_target_address;
static int hf_iso15765_source_address;
static int hf_iso15765_message_type;
static int hf_iso15765_data_length_8bit;
static int hf_iso15765_data_length_4bit;
static int hf_iso15765_frame_length_32bit;
static int hf_iso15765_frame_length_12bit;
static int hf_iso15765_sequence_number;
static int hf_iso15765_flow_status;
static int hf_iso15765_segment_data;
static int hf_iso15765_padding;

static int hf_iso15765_fc_bs;
static int hf_iso15765_fc_stmin;
static int hf_iso15765_fc_stmin_in_us;

static int hf_iso15765_autosar_ack;

static int ett_iso15765;

static expert_field ei_iso15765_message_type_bad;

static int proto_iso15765;
static dissector_handle_t iso15765_handle_can;
static dissector_handle_t iso15765_handle_lin;
static dissector_handle_t iso15765_handle_flexray;
static dissector_handle_t iso15765_handle_ipdum;
static dissector_handle_t iso15765_handle_pdu_transport;

static dissector_table_t subdissector_table;

static reassembly_table iso15765_reassembly_table;
static wmem_map_t* iso15765_seq_table;
static wmem_map_t *iso15765_frame_table;

static int hf_iso15765_fragments;
static int hf_iso15765_fragment;
static int hf_iso15765_fragment_overlap;
static int hf_iso15765_fragment_overlap_conflicts;
static int hf_iso15765_fragment_multiple_tails;
static int hf_iso15765_fragment_too_long_fragment;
static int hf_iso15765_fragment_error;
static int hf_iso15765_fragment_count;
static int hf_iso15765_reassembled_in;
static int hf_iso15765_reassembled_length;

static int ett_iso15765_fragment;
static int ett_iso15765_fragments;

static const fragment_items iso15765_frag_items = {
    /* Fragment subtrees */
    &ett_iso15765_fragment,
    &ett_iso15765_fragments,
    /* Fragment fields */
    &hf_iso15765_fragments,
    &hf_iso15765_fragment,
    &hf_iso15765_fragment_overlap,
    &hf_iso15765_fragment_overlap_conflicts,
    &hf_iso15765_fragment_multiple_tails,
    &hf_iso15765_fragment_too_long_fragment,
    &hf_iso15765_fragment_error,
    &hf_iso15765_fragment_count,
    /* Reassembled in field */
    &hf_iso15765_reassembled_in,
    /* Reassembled length field */
    &hf_iso15765_reassembled_length,
    /* Reassembled data field */
    NULL,
    "ISO15765 fragments"
};

/* UAT for address encoded into CAN IDs */
typedef struct config_can_addr_mapping {
    bool extended_address;
    uint32_t can_id;
    uint32_t can_id_mask;
    uint32_t source_addr_mask;
    uint32_t target_addr_mask;
    uint32_t ecu_addr_mask;
} config_can_addr_mapping_t;

static config_can_addr_mapping_t *config_can_addr_mappings;
static unsigned config_can_addr_mappings_num;
#define DATAFILE_CAN_ADDR_MAPPING "ISO15765_can_id_mappings"

UAT_BOOL_CB_DEF(config_can_addr_mappings, extended_address, config_can_addr_mapping_t)
UAT_HEX_CB_DEF(config_can_addr_mappings, can_id, config_can_addr_mapping_t)
UAT_HEX_CB_DEF(config_can_addr_mappings, can_id_mask, config_can_addr_mapping_t)
UAT_HEX_CB_DEF(config_can_addr_mappings, source_addr_mask, config_can_addr_mapping_t)
UAT_HEX_CB_DEF(config_can_addr_mappings, target_addr_mask, config_can_addr_mapping_t)
UAT_HEX_CB_DEF(config_can_addr_mappings, ecu_addr_mask, config_can_addr_mapping_t)

static void *
copy_config_can_addr_mapping_cb(void *n, const void *o, size_t size _U_) {
    config_can_addr_mapping_t *new_rec = (config_can_addr_mapping_t *)n;
    const config_can_addr_mapping_t *old_rec = (const config_can_addr_mapping_t *)o;

    new_rec->extended_address = old_rec->extended_address;
    new_rec->can_id = old_rec->can_id;
    new_rec->can_id_mask = old_rec->can_id_mask;
    new_rec->source_addr_mask = old_rec->source_addr_mask;
    new_rec->target_addr_mask = old_rec->target_addr_mask;
    new_rec->ecu_addr_mask = old_rec->ecu_addr_mask;

    return new_rec;
}

static bool
update_config_can_addr_mappings(void *r, char **err) {
    config_can_addr_mapping_t *rec = (config_can_addr_mapping_t *)r;

    if (rec->source_addr_mask == 0 && rec->target_addr_mask == 0 && rec->ecu_addr_mask == 0) {
        *err = ws_strdup_printf("You need to define the ECU Mask OR Source Mask/Target Mask!");
        return false;
    }

    if ((rec->source_addr_mask != 0 || rec->target_addr_mask != 0) && rec->ecu_addr_mask != 0) {
        *err = ws_strdup_printf("You can only use Source Address Mask/Target Address Mask OR ECU Address Mask! Not both at the same time!");
        return false;
    }

    if ((rec->source_addr_mask == 0 || rec->target_addr_mask == 0) && rec->ecu_addr_mask == 0) {
        *err = ws_strdup_printf("You can only use Source Address Mask and Target Address Mask in combination!");
        return false;
    }

    if (rec->extended_address) {
        if ((rec->source_addr_mask & ~CAN_EFF_MASK) != 0) {
            *err = ws_strdup_printf("Source Address Mask covering bits not allowed for extended IDs (29bit)!");
            return false;
        }
        if ((rec->target_addr_mask & ~CAN_EFF_MASK) != 0) {
            *err = ws_strdup_printf("Target Address Mask covering bits not allowed for extended IDs (29bit)!");
            return false;
        }
        if ((rec->ecu_addr_mask & ~CAN_EFF_MASK) != 0) {
            *err = ws_strdup_printf("ECU Address Mask covering bits not allowed for extended IDs (29bit)!");
            return false;
        }
    } else {
        if ((rec->source_addr_mask & ~CAN_SFF_MASK) != 0) {
            *err = ws_strdup_printf("Source Address Mask covering bits not allowed for standard IDs (11bit)!");
            return false;
        }
        if ((rec->target_addr_mask & ~CAN_SFF_MASK) != 0) {
            *err = ws_strdup_printf("Target Address Mask covering bits not allowed for standard IDs (11bit)!");
            return false;
        }
        if ((rec->ecu_addr_mask & ~CAN_SFF_MASK) != 0) {
            *err = ws_strdup_printf("ECU Address Mask covering bits not allowed for standard IDs (11bit)!");
            return false;
        }
    }

    return true;
}

static void
free_config_can_addr_mappings(void *r _U_) {
    /* do nothing right now */
}

static void
post_update_config_can_addr_mappings_cb(void) {
    /* do nothing right now */
}

static uint16_t
masked_guint16_value(const uint16_t value, const uint16_t mask) {
    return (value & mask) >> ws_ctz(mask);
}

static uint32_t
masked_guint32_value(const uint32_t value, const uint32_t mask) {
    return (value & mask) >> ws_ctz(mask);
}

/*
 * returning number of addresses (0:none, 1:ecu (both addr same), 2:source+target)
 */
static uint8_t
find_config_can_addr_mapping(bool ext_id, uint32_t can_id, uint16_t *source_addr, uint16_t *target_addr, uint8_t *addr_len) {
    config_can_addr_mapping_t *tmp = NULL;
    uint32_t i;

    if (source_addr == NULL || target_addr == NULL || config_can_addr_mappings == NULL) {
        return 0;
    }

    for (i = 0; i < config_can_addr_mappings_num; i++) {
        if (config_can_addr_mappings[i].extended_address == ext_id &&
            (config_can_addr_mappings[i].can_id & config_can_addr_mappings[i].can_id_mask) ==
            (can_id & config_can_addr_mappings[i].can_id_mask)) {
            tmp = &(config_can_addr_mappings[i]);
            break;
        }
    }

    *addr_len = 0;

    if (tmp != NULL) {
        if (tmp->ecu_addr_mask != 0) {
            *source_addr = masked_guint32_value(can_id, tmp->ecu_addr_mask);
            *target_addr = *source_addr;
            *addr_len = (7 + ws_count_ones(tmp->ecu_addr_mask)) / 8;
            return 1;
        }
        if (tmp->source_addr_mask != 0 && tmp->target_addr_mask != 0) {
            *source_addr = masked_guint32_value(can_id, tmp->source_addr_mask);
            *target_addr = masked_guint32_value(can_id, tmp->target_addr_mask);
            uint8_t tmp_len = ws_count_ones(tmp->source_addr_mask);
            if (ws_count_ones(tmp->target_addr_mask) > tmp_len) {
                tmp_len = ws_count_ones(tmp->target_addr_mask);
            }
            *addr_len = (7 + tmp_len) / 8;
            return 2;
        }
    }

    return 0;
}


/* UAT for PDU Transport config */
typedef struct config_pdu_tranport_config {
    uint32_t pdu_id;
    uint32_t source_address_size;
    uint32_t source_address_fixed;
    uint32_t target_address_size;
    uint32_t target_address_fixed;
    uint32_t ecu_address_size;
    uint32_t ecu_address_fixed;
} config_pdu_transport_config_t;

static config_pdu_transport_config_t *config_pdu_transport_config_items;
static unsigned config_pdu_transport_config_items_num;
#define DATAFILE_PDU_TRANSPORT_CONFIG "ISO15765_pdu_transport_config"

UAT_HEX_CB_DEF(config_pdu_transport_config_items, pdu_id, config_pdu_transport_config_t)
UAT_DEC_CB_DEF(config_pdu_transport_config_items, source_address_size, config_pdu_transport_config_t)
UAT_HEX_CB_DEF(config_pdu_transport_config_items, source_address_fixed, config_pdu_transport_config_t)
UAT_DEC_CB_DEF(config_pdu_transport_config_items, target_address_size, config_pdu_transport_config_t)
UAT_HEX_CB_DEF(config_pdu_transport_config_items, target_address_fixed, config_pdu_transport_config_t)
UAT_DEC_CB_DEF(config_pdu_transport_config_items, ecu_address_size, config_pdu_transport_config_t)
UAT_HEX_CB_DEF(config_pdu_transport_config_items, ecu_address_fixed, config_pdu_transport_config_t)


static void *
copy_config_pdu_transport_config_cb(void *n, const void *o, size_t size _U_) {
    config_pdu_transport_config_t *new_rec = (config_pdu_transport_config_t *)n;
    const config_pdu_transport_config_t *old_rec = (const config_pdu_transport_config_t *)o;

    new_rec->pdu_id = old_rec->pdu_id;
    new_rec->source_address_size = old_rec->source_address_size;
    new_rec->source_address_fixed = old_rec->source_address_fixed;
    new_rec->target_address_size = old_rec->target_address_size;
    new_rec->target_address_fixed = old_rec->target_address_fixed;
    new_rec->ecu_address_size = old_rec->ecu_address_size;
    new_rec->ecu_address_fixed = old_rec->ecu_address_fixed;

    return new_rec;
}

static bool
update_config_pdu_transport_config_item(void *r, char **err) {
    config_pdu_transport_config_t *rec = (config_pdu_transport_config_t *)r;

    bool source_address_configured = rec->source_address_size != 0 || rec->source_address_fixed != ISO15765_ADDR_INVALID;
    bool target_address_configured = rec->target_address_size != 0 || rec->target_address_fixed != ISO15765_ADDR_INVALID;
    bool ecu_address_configured = rec->ecu_address_size != 0 || rec->ecu_address_fixed != ISO15765_ADDR_INVALID;

    if (rec->source_address_size != 0 && rec->source_address_fixed != ISO15765_ADDR_INVALID) {
        *err = ws_strdup_printf("You can either set the size of the source address or configure a fixed value!");
        return false;
    }

    if (rec->target_address_size != 0 && rec->target_address_fixed != ISO15765_ADDR_INVALID) {
        *err = ws_strdup_printf("You can either set the size of the target address or configure a fixed value!");
        return false;
    }

    if (rec->ecu_address_size != 0 && rec->ecu_address_fixed != ISO15765_ADDR_INVALID) {
        *err = ws_strdup_printf("You can either set the size of the ecu address or configure a fixed value!");
        return false;
    }

    if (ecu_address_configured && (source_address_configured || target_address_configured)) {
        *err = ws_strdup_printf("You cannot configure an ecu address and a source or target address at the same time!");
        return false;
    }

    if ((source_address_configured && !target_address_configured) || (!source_address_configured && target_address_configured)) {
        *err = ws_strdup_printf("You can only configure source and target address at the same time but not only one of them!");
        return false;
    }

    return true;
}

static void
free_config_pdu_transport_config(void *r _U_) {
    /* do nothing for now */
}

static void
reset_config_pdu_transport_config_cb(void) {
    /* do nothing for now */
}

static void
post_update_config_pdu_transport_config_cb(void) {
    dissector_delete_all("pdu_transport.id", iso15765_handle_pdu_transport);

    config_pdu_transport_config_t *tmp;
    unsigned i;
    for (i = 0; i < config_pdu_transport_config_items_num; i++) {
        tmp = &(config_pdu_transport_config_items[i]);
        dissector_add_uint("pdu_transport.id", tmp->pdu_id, iso15765_handle_pdu_transport);
    }
}

static config_pdu_transport_config_t *
find_pdu_transport_config(uint32_t pdu_id) {
    unsigned i;
    for (i = 0; i < config_pdu_transport_config_items_num; i++) {
        if (config_pdu_transport_config_items[i].pdu_id == pdu_id) {
            return &(config_pdu_transport_config_items[i]);
        }
    }

    return NULL;
}

static int
handle_pdu_transport_addresses(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, int offset_orig, uint32_t pdu_id, iso15765_info_t *iso15765data) {
    int offset = offset_orig;
    config_pdu_transport_config_t *config = find_pdu_transport_config(pdu_id);

    iso15765data->number_of_addresses_valid = 0;
    iso15765data->source_address = 0xffff;
    iso15765data->target_address = 0xffff;

    if (config == NULL) {
        return offset - offset_orig;
    }

    uint32_t tmp;
    /* single address, in payload */
    if (config->ecu_address_size != 0) {
        proto_tree_add_item_ret_uint(tree, hf_iso15765_address, tvb, offset, config->ecu_address_size, ENC_BIG_ENDIAN, &tmp);
        offset += config->ecu_address_size;
        iso15765data->number_of_addresses_valid = 1;
        iso15765data->source_address = (uint16_t)tmp;
        iso15765data->target_address = (uint16_t)tmp;
        iso15765data->address_length = config->ecu_address_size;
        return offset - offset_orig;
    }

    /* single address, fixed */
    if (config->ecu_address_fixed != ISO15765_ADDR_INVALID) {
        iso15765data->number_of_addresses_valid = 1;
        iso15765data->source_address = config->ecu_address_fixed;
        iso15765data->target_address = config->ecu_address_fixed;
        iso15765data->address_length = 2; /* could be also 1 Byte but we cannot know for sure */
        return offset - offset_orig;
    }

    /* no address possible */
    if (config->source_address_size == 0 && config->source_address_fixed == ISO15765_ADDR_INVALID && config->target_address_size == 0 && config->target_address_fixed == ISO15765_ADDR_INVALID) {
        iso15765data->address_length = 0;
        return offset - offset_orig;
    }

    /* now we can only have two addresses! */
    iso15765data->number_of_addresses_valid = 2;
    iso15765data->address_length = config->source_address_size;
    if (config->target_address_size > iso15765data->address_length) {
        iso15765data->address_length = config->target_address_size;
    }

    if (config->source_address_size != 0) {
        proto_tree_add_item_ret_uint(tree, hf_iso15765_source_address, tvb, offset, config->source_address_size, ENC_BIG_ENDIAN, &tmp);
        offset += config->source_address_size;
        iso15765data->source_address = tmp;
    } else if (config->source_address_fixed != ISO15765_ADDR_INVALID) {
        iso15765data->source_address = config->source_address_fixed;
        iso15765data->address_length = 2; /* could be also 1 Byte but we cannot know for sure */
    }

    if (config->target_address_size != 0) {
        proto_tree_add_item_ret_uint(tree, hf_iso15765_target_address, tvb, offset, config->target_address_size, ENC_BIG_ENDIAN, &tmp);
        offset += config->target_address_size;
        iso15765data->target_address = tmp;
    } else if (config->target_address_fixed != ISO15765_ADDR_INVALID) {
        iso15765data->target_address = config->target_address_fixed;
        iso15765data->address_length = 2; /* could be also 1 Byte but we cannot know for sure */
    }

    return offset - offset_orig;
}

static int
dissect_iso15765(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, uint32_t bus_type, uint32_t frame_id, uint32_t frame_length) {
    static uint32_t msg_seqid = 0;

    proto_tree *iso15765_tree;
    proto_item *ti;
    proto_item *message_type_item;
    tvbuff_t*   next_tvb = NULL;
    uint16_t    pci;
    uint32_t    message_type;
    iso15765_identifier_t* iso15765_info;
    /* LIN is always extended addressing */
    uint8_t     ae = (addressing == NORMAL_ADDRESSING && bus_type != ISO15765_TYPE_LIN) ? 0 : 1;
    uint16_t    frag_id_low = 0;
    uint32_t    offset, pci_offset;
    uint32_t    data_length;
    uint32_t    full_len;
    bool        fragmented = false;
    bool        complete = false;
    uint32_t    iface_id = (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) ? pinfo->rec->rec_header.packet_header.interface_id : 0;

    iso15765_info_t iso15765data;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO15765");
    col_clear(pinfo->cinfo, COL_INFO);

    iso15765_info = (iso15765_identifier_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0);

    if (!iso15765_info) {
        iso15765_info = wmem_new0(wmem_file_scope(), iso15765_identifier_t);
        iso15765_info->id = frame_id;
        iso15765_info->last = false;
        iso15765_info->bytes_used = 0;
        p_add_proto_data(wmem_file_scope(), pinfo, proto_iso15765, 0, iso15765_info);
    }

    ti = proto_tree_add_item(tree, proto_iso15765, tvb, 0, -1, ENC_NA);
    iso15765_tree = proto_item_add_subtree(ti, ett_iso15765);

    iso15765data.bus_type = bus_type;
    iso15765data.id = frame_id;
    iso15765data.number_of_addresses_valid = 0;
    iso15765data.address_length = 0;

    if (bus_type == ISO15765_TYPE_FLEXRAY) {
        uint32_t tmp;
        proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_source_address, tvb, 0, flexray_addressing, ENC_BIG_ENDIAN, &tmp);
        iso15765data.source_address = (uint16_t)tmp;
        proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_target_address, tvb, flexray_addressing, flexray_addressing, ENC_BIG_ENDIAN, &tmp);
        iso15765data.target_address = (uint16_t)tmp;
        iso15765data.number_of_addresses_valid = 2;
        iso15765data.address_length = flexray_addressing;
        pci_offset = 2 * flexray_addressing;
    } else if (bus_type == ISO15765_TYPE_IPDUM && ipdum_addressing > 0) {
        uint32_t tmp;
        proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_source_address, tvb, 0, ipdum_addressing, ENC_BIG_ENDIAN, &tmp);
        iso15765data.source_address = (uint16_t)tmp;
        proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_target_address, tvb, ipdum_addressing, ipdum_addressing, ENC_BIG_ENDIAN, &tmp);
        iso15765data.target_address = (uint16_t)tmp;
        iso15765data.number_of_addresses_valid = 2;
        iso15765data.address_length = ipdum_addressing;
        pci_offset = 2 * ipdum_addressing;
    } else if (bus_type == ISO15765_TYPE_PDU_TRANSPORT) {
        pci_offset = handle_pdu_transport_addresses(tvb, pinfo, iso15765_tree, 0, frame_id, &iso15765data);
    } else {
        if (ae != 0) {
            uint32_t tmp;
            iso15765data.number_of_addresses_valid = 1;
            iso15765data.address_length = ae;
            proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_address, tvb, 0, ae, ENC_NA, &tmp);
            iso15765data.source_address = (uint16_t)tmp;
            iso15765data.target_address = (uint16_t)tmp;
            pci_offset = ae;
        } else {
            /* Address implicitly encoded? */
            if (bus_type == ISO15765_TYPE_CAN || bus_type == ISO15765_TYPE_CAN_FD) {
                bool ext_id = (CAN_EFF_FLAG & frame_id) == CAN_EFF_FLAG;
                uint32_t can_id = ext_id ? frame_id & CAN_EFF_MASK : frame_id & CAN_SFF_MASK;
                iso15765data.number_of_addresses_valid = find_config_can_addr_mapping(ext_id, can_id, &(iso15765data.source_address), &(iso15765data.target_address), &(iso15765data.address_length));
            }
            pci_offset = 0;
        }
    }

    offset = pci_offset;
    pci = tvb_get_uint8(tvb, offset);
    message_type_item = proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_message_type, tvb, offset, 1, ENC_NA, &message_type);
    col_add_str(pinfo->cinfo, COL_INFO, val_to_str(message_type, iso15765_message_types, "Unknown (0x%02x)"));

    switch(message_type) {
        case ISO15765_MESSAGE_TYPES_SINGLE_FRAME: {
            if (frame_length > 8 && (pci & ISO15765_MESSAGE_DATA_LENGTH_MASK) == 0) {
                /* Single Frame with CAN_DL > 8 Bytes: TTTT0000 LLLLLLLL, Type, Length */

                /* This is always zero but still we need to dissect... */
                proto_tree_add_item(iso15765_tree, hf_iso15765_data_length_4bit, tvb, offset, 1, ENC_NA);
                offset += 1;

                proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_data_length_8bit, tvb, offset, 1, ENC_NA, &data_length);
                offset += 1;
            } else {
                /* Single Frame with CAN_DL <= 8 Bytes: TTTTLLLL, Type, Length */
                proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_data_length_4bit, tvb, offset, 1, ENC_NA, &data_length);
                offset += 1;
            }

            next_tvb = tvb_new_subset_length(tvb, offset, data_length);
            complete = true;

            col_append_fstr(pinfo->cinfo, COL_INFO, "(Len: %d)", data_length);
            break;
        }
        case ISO15765_MESSAGE_TYPES_FIRST_FRAME: {
            pci = tvb_get_uint16(tvb, offset, ENC_BIG_ENDIAN);
            if (pci == 0x1000) {
                /* First Frame with CAN_DL > 4095 Bytes: TTTT0000 00000000 LLLLLLLL LLLLLLLL LLLLLLLL LLLLLLLL, Type, Length */

                /* This is always zero but still we need to dissect... */
                proto_tree_add_item(iso15765_tree, hf_iso15765_frame_length_12bit, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;

                proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_frame_length_32bit, tvb, offset, 4, ENC_BIG_ENDIAN, &full_len);
                offset += 4;
            } else {
                /* First Frame with CAN_DL <= 4095 Bytes: TTTTLLLL LLLLLLLL, Type, Length */
                full_len = pci & ISO15765_MESSAGE_FIRST_FRAME_DATA_LENGTH_MASK;
                proto_tree_add_item(iso15765_tree, hf_iso15765_frame_length_12bit, tvb, offset, 2, ENC_BIG_ENDIAN);
                offset += 2;
            }

            /* we need to assume that all following bytes are of the first frame data */
            data_length = tvb_reported_length(tvb) - offset;

            /* FlexRay data_length cut off, if configured */
            if (bus_type == ISO15765_TYPE_FLEXRAY && flexray_segment_size_limit != 0 && (uint32_t)data_length > flexray_segment_size_limit - (offset - pci_offset)) {
                data_length = flexray_segment_size_limit - (offset - pci_offset);
            }

            fragmented = true;
            frag_id_low = 0;

            /* Save information */
            if (!(pinfo->fd->visited)) {
                iso15765_seq_key_t* key;
                void* old_value;
                iso15765_seq_key_t temp_key = { bus_type, frame_id, iface_id };
                msg_seqid++;
                if (!wmem_map_lookup_extended(iso15765_seq_table, &temp_key, (const void**)&key, &old_value)) {
                    key = wmem_new(wmem_file_scope(), iso15765_seq_key_t);
                    *key = temp_key;
                }
                wmem_map_insert(iso15765_seq_table, key, GUINT_TO_POINTER(msg_seqid));

                iso15765_frame_t *iso15765_frame = wmem_new0(wmem_file_scope(), iso15765_frame_t);
                iso15765_frame->seq = iso15765_info->seq = msg_seqid;
                iso15765_frame->len = full_len;
                iso15765_frame->bytes_in_cf = MAX(8, tvb_reported_length(tvb)) - pci_offset - 1;

                wmem_map_insert(iso15765_frame_table, GUINT_TO_POINTER(iso15765_info->seq), iso15765_frame);
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, "(Frame Len: %d)", full_len);
            break;
        }
        case ISO15765_MESSAGE_TYPES_FR_CONSECUTIVE_FRAME_2:
        case ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME: {
            /* Consecutive Frame (DF): TTTTSSSS, Type, SeqNo */
            proto_tree_add_item(iso15765_tree, hf_iso15765_sequence_number, tvb, offset, 1, ENC_NA);
            col_append_fstr(pinfo->cinfo, COL_INFO, "(Seq: %d)", (pci & ISO15765_MESSAGE_DATA_LENGTH_MASK));
            offset += 1;

            /* we need to assume that all following bytes are of the first frame data */
            data_length = tvb_reported_length(tvb) - offset;

            frag_id_low = masked_guint16_value(pci, ISO15765_MESSAGE_SEQUENCE_NUMBER_MASK);
            fragmented = true;

            /* FlexRay data_length cut off, if configured */
            if (bus_type == ISO15765_TYPE_FLEXRAY && flexray_segment_size_limit != 0 && (uint32_t)data_length > flexray_segment_size_limit - (offset - pci_offset)) {
                data_length = flexray_segment_size_limit - (offset - pci_offset);
            }

            /* Save information */
            if (!(pinfo->fd->visited)) {
                iso15765_seq_key_t temp_key = { bus_type, frame_id, iface_id };
                void* old_value = wmem_map_lookup(iso15765_seq_table, &temp_key);
                iso15765_info->seq = old_value ? GPOINTER_TO_UINT(old_value) : 0;
            }
            break;
        }
        case ISO15765_MESSAGE_TYPES_FR_ACK_FRAME:
        case ISO15765_MESSAGE_TYPES_FLOW_CONTROL: {
            /* Flow Control Frame (FC): TTTTFFFF, BBBBBBBB, SSSSSSSS, Type, Flow status, Block size, Separation time */
            uint32_t status = 0;
            uint32_t bs = 0;
            uint32_t stmin = 0;
            bool stmin_in_us = false;
            data_length = 0;

            proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_flow_status, tvb, offset, 1, ENC_NA, &status);
            offset += 1;

            proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_fc_bs, tvb, offset, 1, ENC_NA, &bs);
            offset += 1;

            stmin = tvb_get_uint8(tvb, offset);
            if (stmin >= 0xF1 && stmin <= 0xF9) {
                stmin_in_us = true;
                stmin = (stmin - 0xF0) * 100U;
                proto_tree_add_uint(iso15765_tree, hf_iso15765_fc_stmin_in_us, tvb, offset, 1, stmin);
            } else {
                proto_tree_add_uint(iso15765_tree, hf_iso15765_fc_stmin, tvb, offset, 1, stmin);
            }
            offset += 1;

            if (message_type == ISO15765_MESSAGE_TYPES_FR_ACK_FRAME) {
                uint32_t ack = 0;
                uint32_t sn = 0;

                proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_autosar_ack, tvb, offset, 1, ENC_NA, &ack);
                proto_tree_add_item_ret_uint(iso15765_tree, hf_iso15765_sequence_number, tvb, offset, 1, ENC_NA, &sn);
                offset += 1;

                col_append_fstr(pinfo->cinfo, COL_INFO, "(Status: %d, Block size: 0x%x, Separation time minimum: %d %s, Ack: %d, Seq: %d)",
                                status, bs, stmin, stmin_in_us ? "µs" : "ms", ack, sn);
            } else {
                col_append_fstr(pinfo->cinfo, COL_INFO, "(Status: %d, Block size: 0x%x, Separation time minimum: %d %s)",
                                status, bs, stmin, stmin_in_us ? "µs" : "ms");
            }
            break;
        }
        case ISO15765_MESSAGE_TYPES_FR_SINGLE_FRAME_EXT: {
            offset += 1;

            data_length = tvb_get_uint8(tvb, offset);
            proto_tree_add_item(iso15765_tree, hf_iso15765_data_length_8bit, tvb, offset, 1, ENC_NA);
            offset += 1;

            next_tvb = tvb_new_subset_length(tvb, offset, data_length);
            complete = true;

            col_append_fstr(pinfo->cinfo, COL_INFO, "(Len: %d)", data_length);
            break;
        }
        case ISO15765_MESSAGE_TYPES_FR_FIRST_FRAME_EXT: {
            offset += 1;

            full_len = tvb_get_uint32(tvb, offset, ENC_BIG_ENDIAN);
            proto_tree_add_item(iso15765_tree, hf_iso15765_frame_length_32bit, tvb, offset, 4, ENC_BIG_ENDIAN);
            offset += 4;

            data_length = tvb_reported_length(tvb) - offset;
            if (bus_type == ISO15765_TYPE_FLEXRAY && flexray_segment_size_limit != 0 && (uint32_t)data_length > flexray_segment_size_limit - (offset - pci_offset)) {
                data_length = flexray_segment_size_limit - (offset - pci_offset);
            }

            fragmented = true;
            frag_id_low = 0;

            /* Save information */
            if (!(pinfo->fd->visited)) {
                iso15765_seq_key_t* key;
                void* old_value;
                iso15765_seq_key_t temp_key = { bus_type, frame_id, iface_id };
                msg_seqid++;
                if (!wmem_map_lookup_extended(iso15765_seq_table, &temp_key, (const void **)&key, &old_value)) {
                    key = wmem_new(wmem_file_scope(), iso15765_seq_key_t);
                    *key = temp_key;
                }
                wmem_map_insert(iso15765_seq_table, key, GUINT_TO_POINTER(msg_seqid));

                iso15765_frame_t *iso15765_frame = wmem_new0(wmem_file_scope(), iso15765_frame_t);
                iso15765_frame->seq = iso15765_info->seq = msg_seqid;
                iso15765_frame->len = full_len;
                iso15765_frame->bytes_in_cf = MAX(8, tvb_reported_length(tvb)) - pci_offset - 1;

                wmem_map_insert(iso15765_frame_table, GUINT_TO_POINTER(iso15765_info->seq), iso15765_frame);
            }

            col_append_fstr(pinfo->cinfo, COL_INFO, "(Frame Len: %d)", full_len);
            break;
        }
        default:
            expert_add_info_format(pinfo, message_type_item, &ei_iso15765_message_type_bad, "Bad Message Type value %u!", message_type);
            return offset;
    }

    /* Show data */
    if (data_length > 0) {
        col_append_fstr(pinfo->cinfo, COL_INFO, "   %s", tvb_bytes_to_str_punct(pinfo->pool, tvb, offset, data_length, ' '));
    }

    if (fragmented) {
        tvbuff_t *new_tvb = NULL;
        iso15765_frame_t *iso15765_frame;
        uint16_t frag_id = frag_id_low;
        /* Get frame information */
        iso15765_frame = (iso15765_frame_t *)wmem_map_lookup(iso15765_frame_table, GUINT_TO_POINTER(iso15765_info->seq));

        if (iso15765_frame != NULL) {
            if (!(pinfo->fd->visited)) {
                DISSECTOR_ASSERT(frag_id < 16);
                uint16_t tmp = iso15765_frame->frag_id_high[frag_id]++;
                /* Make sure that we assert on using more than 4096 (16*255) segments.*/
                DISSECTOR_ASSERT(iso15765_frame->frag_id_high[frag_id] != 0);
                frag_id += tmp * 16;

                /* Save the frag_id for subsequent dissection */
                iso15765_info->frag_id = frag_id;

                /* Check if there is an error in conversation */
                if (iso15765_info->frag_id + window < iso15765_frame->last_frag_id) {
                    /* Error in conversation */
                    iso15765_frame->error = true;
                }
            }

            if (!iso15765_frame->error) {
                bool           save_fragmented = pinfo->fragmented;
                uint32_t       len = data_length;
                uint32_t       missing_bytes = 0;
                fragment_head *frag_msg;

                /* Check if it's the last packet */
                if (!(pinfo->fd->visited)) {
                    iso15765_info->bytes_used = data_length;

                    if (frag_id > iso15765_frame->last_frag_id || !iso15765_frame->ff_seen) {
                        if (frag_id > iso15765_frame->last_frag_id + 1) {
                            missing_bytes = (frag_id - iso15765_frame->last_frag_id - 1) * iso15765_frame->bytes_in_cf;
                        }
                        /* Update the last_frag_id */
                        iso15765_frame->ff_seen = true;
                        iso15765_frame->last_frag_id = frag_id;


                        /* Here we use iso15765_frame->last_byte_seen to make sure that we correctly detect
                         * the last Consecutive Frame, even if some frames were missing in the middle.
                         * Note that the last Consecutive Frame might not be the last packet,
                         * as it might arrive out of order.
                         */
                        iso15765_frame->last_byte_seen += missing_bytes;
                        iso15765_frame->last_byte_seen += len;
                        if (iso15765_frame->last_byte_seen >= iso15765_frame->len) {
                            iso15765_info->last = true;
                            len -= (iso15765_frame->last_byte_seen - iso15765_frame->len);

                            /* Determine how many bytes were needed to calculate padding latter. */
                            iso15765_info->bytes_used = data_length - (iso15765_frame->last_byte_seen - iso15765_frame->len);
                        }

                    }
                }
                pinfo->fragmented = true;

                /* Add fragment to fragment table */
                frag_msg = fragment_add_seq_check(&iso15765_reassembly_table, tvb, offset, pinfo, iso15765_info->seq, NULL,
                                                  iso15765_info->frag_id, len, !iso15765_info->last);

                new_tvb = process_reassembled_data(tvb, offset, pinfo, "Reassembled Message", frag_msg,
                                                   &iso15765_frag_items, NULL, iso15765_tree);

                if (frag_msg && frag_msg->reassembled_in != pinfo->num) {
                    col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%u]", frag_msg->reassembled_in);
                }

                pinfo->fragmented = save_fragmented;
            }

            if (new_tvb) {
                /* This is a complete TVB to dissect */
                next_tvb = new_tvb;
                complete = true;
            }
        }
    }

    /* Let us correct bytes used for last segment to identify padding. */
    if (iso15765_info != NULL && iso15765_info->last) {
        data_length = iso15765_info->bytes_used;
    }

    if (message_type == ISO15765_MESSAGE_TYPES_FIRST_FRAME || message_type == ISO15765_MESSAGE_TYPES_CONSECUTIVE_FRAME ||
        message_type == ISO15765_MESSAGE_TYPES_FR_FIRST_FRAME_EXT || message_type == ISO15765_MESSAGE_TYPES_FR_CONSECUTIVE_FRAME_2) {
        proto_tree_add_item(iso15765_tree, hf_iso15765_segment_data, tvb, offset, data_length, ENC_NA);
    }

    offset += data_length;

    if (offset < tvb_captured_length(tvb)) {
        /* Unused bytes should be filled with 0xCC padding. */
        proto_tree_add_item(iso15765_tree, hf_iso15765_padding, tvb, offset, tvb_captured_length(tvb) - offset, ENC_NA);
    }

    if (next_tvb) {
        iso15765data.len = frame_length;

        if (!complete || !dissector_try_payload_new(subdissector_table, next_tvb, pinfo, tree, true, &iso15765data)) {
            call_data_dissector(next_tvb, pinfo, tree);
        }
    }

    return tvb_captured_length(tvb);
}

static int
dissect_iso15765_can(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {
    can_info_t can_info;

    DISSECTOR_ASSERT(data);
    can_info = *((can_info_t*)data);

    if (can_info.id & (CAN_ERR_FLAG | CAN_RTR_FLAG)) {
        /* Error and RTR frames are not for us. */
        return 0;
    }

    switch (can_info.fd) {

    case CAN_TYPE_CAN_FD:
        return dissect_iso15765(tvb, pinfo, tree, ISO15765_TYPE_CAN_FD, can_info.id, can_info.len);

    case CAN_TYPE_CAN_CLASSIC:
        return dissect_iso15765(tvb, pinfo, tree, ISO15765_TYPE_CAN, can_info.id, can_info.len);

    default:
        DISSECTOR_ASSERT_NOT_REACHED();
        return tvb_captured_length(tvb);
    }
}

static int
dissect_iso15765_lin(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {
    DISSECTOR_ASSERT(data);

    lin_info_t *lininfo = (lin_info_t *)data;

    return dissect_iso15765(tvb, pinfo, tree, ISO15765_TYPE_LIN, lininfo->id, lininfo->len);
}

static int
dissect_iso15765_flexray(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {
    DISSECTOR_ASSERT(data);

    flexray_info_t *flexray_id = (flexray_info_t *)data;

    uint32_t id = (((uint32_t)flexray_id->id) << 16) | (((uint32_t)flexray_id->cc) << 8) | flexray_id->ch;

    return dissect_iso15765(tvb, pinfo, tree, ISO15765_TYPE_FLEXRAY, id, tvb_captured_length(tvb));
}

static int
dissect_iso15765_ipdum(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {
    DISSECTOR_ASSERT(data);

    autosar_ipdu_multiplexer_info_t *ipdum_data = (autosar_ipdu_multiplexer_info_t *)data;

    return dissect_iso15765(tvb, pinfo, tree, ISO15765_TYPE_IPDUM, ipdum_data->pdu_id, tvb_captured_length(tvb));
}

static int
dissect_iso15765_pdu_transport(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data) {
    DISSECTOR_ASSERT(data);

    pdu_transport_info_t *pdu_transport_data = (pdu_transport_info_t *)data;

    return dissect_iso15765(tvb, pinfo, tree, ISO15765_TYPE_PDU_TRANSPORT, pdu_transport_data->id, tvb_captured_length(tvb));
}

static void
update_config(void) {
    if (iso15765_handle_lin != NULL) {
        dissector_delete_all("lin.frame_id", iso15765_handle_lin);
        if (register_lin_diag_frames) {
            /* LIN specification states that 0x3c and 0x3d are for diagnostics */
            dissector_add_uint("lin.frame_id", LIN_DIAG_MASTER_REQUEST_FRAME, iso15765_handle_lin);
            dissector_add_uint("lin.frame_id", LIN_DIAG_SLAVE_RESPONSE_FRAME, iso15765_handle_lin);
        }
    }

    if (iso15765_handle_can != NULL) {
        dissector_delete_all("can.id", iso15765_handle_can);
        dissector_delete_all("can.extended_id", iso15765_handle_can);
        dissector_add_uint_range("can.id", configured_can_ids, iso15765_handle_can);
        dissector_add_uint_range("can.extended_id", configured_ext_can_ids, iso15765_handle_can);
    }

    if (iso15765_handle_ipdum != NULL) {
        dissector_delete_all("ipdum.pdu.id", iso15765_handle_ipdum);
        dissector_add_uint_range("ipdum.pdu.id", configured_ipdum_pdu_ids, iso15765_handle_ipdum);
    }
}

void
proto_register_iso15765(void) {
    uat_t *config_can_addr_mapping_uat;
    uat_t *config_pdu_transport_config_uat;

    static hf_register_info hf[] = {
        { &hf_iso15765_address, {
            "Address", "iso15765.address", FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_iso15765_target_address, {
            "Target Address", "iso15765.target_address", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_iso15765_source_address, {
            "Source Address", "iso15765.source_address", FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL } },
        { &hf_iso15765_message_type, {
            "Message Type", "iso15765.message_type", FT_UINT8, BASE_HEX, VALS(iso15765_message_types), ISO15765_MESSAGE_TYPE_MASK, NULL, HFILL } },
        { &hf_iso15765_data_length_8bit, {
            "Data length (8bit)", "iso15765.data_length_8bit", FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL } },
        { &hf_iso15765_data_length_4bit, {
            "Data length (4bit)", "iso15765.data_length_4bit", FT_UINT8, BASE_DEC, NULL, ISO15765_MESSAGE_DATA_LENGTH_MASK, NULL, HFILL } },
        { &hf_iso15765_frame_length_32bit, {
            "Frame length (32bit)", "iso15765.frame_length_32bit", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_iso15765_frame_length_12bit, {
            "Frame length (12bit)", "iso15765.frame_length_12bit", FT_UINT16, BASE_DEC, NULL, ISO15765_MESSAGE_FIRST_FRAME_DATA_LENGTH_MASK, NULL, HFILL } },
        { &hf_iso15765_sequence_number, {
            "Sequence number", "iso15765.sequence_number", FT_UINT8, BASE_HEX, NULL, ISO15765_MESSAGE_SEQUENCE_NUMBER_MASK, NULL, HFILL } },
        { &hf_iso15765_flow_status, {
            "Flow status", "iso15765.flow_status", FT_UINT8, BASE_HEX, VALS(iso15765_flow_status_types), ISO15765_MESSAGE_FLOW_STATUS_MASK, NULL, HFILL } },

        { &hf_iso15765_fc_bs, {
            "Block size",    "iso15765.flow_control.bs", FT_UINT8, BASE_HEX, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_fc_stmin, {
            "Separation time minimum (ms)", "iso15765.flow_control.stmin", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_fc_stmin_in_us, {
            "Separation time minimum (µs)", "iso15765.flow_control.stmin", FT_UINT8, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_autosar_ack, {
            "Acknowledgment", "iso15765.autosar_ack.ack", FT_UINT8, BASE_HEX, NULL, ISO15765_MESSAGE_AUTOSAR_ACK_MASK, NULL, HFILL } },
        { &hf_iso15765_segment_data, {
            "Segment Data", "iso15765.segment_data", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_padding, {
            "Padding", "iso15765.padding", FT_BYTES, BASE_NONE, NULL, 0x00, NULL, HFILL } },

        { &hf_iso15765_fragments, {
            "Message fragments", "iso15765.fragments", FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }, },
        { &hf_iso15765_fragment, {
            "Message fragment", "iso15765.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_fragment_overlap, {
            "Message fragment overlap", "iso15765.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_fragment_overlap_conflicts, {
            "Message fragment overlapping with conflicting data", "iso15765.fragment.overlap.conflicts", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_fragment_multiple_tails, {
            "Message has multiple tail fragments", "iso15765.fragment.multiple_tails", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_fragment_too_long_fragment, {
            "Message fragment too long", "iso15765.fragment.too_long_fragment", FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_fragment_error, {
            "Message defragmentation error", "iso15765.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_fragment_count, {
            "Message fragment count", "iso15765.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_reassembled_in, {
            "Reassembled in", "iso15765.reassembled.in", FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL } },
        { &hf_iso15765_reassembled_length, {
            "Reassembled length", "iso15765.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL } },
    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_iso15765,
        &ett_iso15765_fragment,
        &ett_iso15765_fragments,
    };

    static ei_register_info ei[] = {
        { &ei_iso15765_message_type_bad, {
            "iso15765.message_type.bad", PI_MALFORMED, PI_ERROR, "Bad Message Type value", EXPFILL } },
    };

    module_t *iso15765_module;
    expert_module_t* expert_iso15765;

    proto_iso15765 = proto_register_protocol ( "ISO15765 Protocol", "ISO 15765", "iso15765");
    register_dissector("iso15765", dissect_iso15765_lin, proto_iso15765);
    expert_iso15765 = expert_register_protocol(proto_iso15765);

    proto_register_field_array(proto_iso15765, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_register_field_array(expert_iso15765, ei, array_length(ei));

    iso15765_module = prefs_register_protocol(proto_iso15765, update_config);

    prefs_register_enum_preference(iso15765_module, "addressing",
                                   "Addressing",
                                   "Addressing of ISO 15765. Normal or Extended",
                                   &addressing,
                                   enum_addressing, true);

    prefs_register_uint_preference(iso15765_module, "window",
                                   "Window",
                                   "Window of ISO 15765 fragments",
                                   10, &window);

    prefs_register_static_text_preference(iso15765_module, "empty_can", "", NULL);

    range_convert_str(wmem_epan_scope(), &configured_can_ids, "", 0x7ff);
    prefs_register_range_preference(iso15765_module, "can.ids",
                                    "CAN IDs (standard)",
                                    "ISO15765 bound standard CAN IDs",
                                    &configured_can_ids, 0x7ff);

    range_convert_str(wmem_epan_scope(), &configured_ext_can_ids, "", 0x1fffffff);
    prefs_register_range_preference(iso15765_module, "can.extended_ids",
                                    "CAN IDs (extended)",
                                    "ISO15765 bound extended CAN IDs",
                                    &configured_ext_can_ids, 0x1fffffff);

    /* UATs for config_can_addr_mapping_uat */
    static uat_field_t config_can_addr_mapping_uat_fields[] = {
        UAT_FLD_BOOL(config_can_addr_mappings, extended_address, "Ext Addr (29bit)",    "29bit Addressing (true), 11bit Addressing (false)"),
        UAT_FLD_HEX(config_can_addr_mappings,  can_id,           "CAN ID",              "CAN ID (hex)"),
        UAT_FLD_HEX(config_can_addr_mappings,  can_id_mask,      "CAN ID Mask",         "CAN ID Mask (hex)"),
        UAT_FLD_HEX(config_can_addr_mappings,  source_addr_mask, "Source Addr Mask",    "Bitmask to specify location of Source Address (hex)"),
        UAT_FLD_HEX(config_can_addr_mappings,  target_addr_mask, "Target Addr Mask",    "Bitmask to specify location of Target Address (hex)"),
        UAT_FLD_HEX(config_can_addr_mappings,  ecu_addr_mask,    "ECU Addr Mask",       "Bitmask to specify location of ECU Address (hex)"),
        UAT_END_FIELDS
    };

    config_can_addr_mapping_uat = uat_new("ISO15765 CAN ID Mapping",
        sizeof(config_can_addr_mapping_t),          /* record size           */
        DATAFILE_CAN_ADDR_MAPPING,                  /* filename              */
        true,                                       /* from profile          */
        (void**)&config_can_addr_mappings,          /* data_ptr              */
        &config_can_addr_mappings_num,              /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_config_can_addr_mapping_cb,            /* copy callback         */
        update_config_can_addr_mappings,            /* update callback       */
        free_config_can_addr_mappings,              /* free callback         */
        post_update_config_can_addr_mappings_cb,    /* post update callback  */
        NULL,                                       /* reset callback        */
        config_can_addr_mapping_uat_fields          /* UAT field definitions */
    );

    prefs_register_uat_preference(iso15765_module, "_iso15765_can_id_mappings", "CAN ID Mappings",
        "A table to define mappings rules for CAN IDs", config_can_addr_mapping_uat);

    prefs_register_static_text_preference(iso15765_module, "empty_lin", "", NULL);
    prefs_register_bool_preference(iso15765_module, "lin_diag",
                                   "Handle LIN Diagnostic Frames",
                                   "Handle LIN Diagnostic Frames",
                                   &register_lin_diag_frames);

    prefs_register_static_text_preference(iso15765_module, "empty_fr", "", NULL);
    prefs_register_enum_preference(iso15765_module, "flexray_addressing",
                                   "FlexRay Addressing",
                                   "Addressing of FlexRay TP. 1 Byte or 2 Byte",
                                   &flexray_addressing,
                                   enum_flexray_addressing, true);

    prefs_register_uint_preference(iso15765_module, "flexray_segment_size_limit",
                                   "FlexRay Segment Cutoff",
                                   "Segment Size Limit for first and consecutive frames of FlexRay (bytes after addresses)",
                                   10, &flexray_segment_size_limit);


    prefs_register_static_text_preference(iso15765_module, "empty_ipdum", "", NULL);
    range_convert_str(wmem_epan_scope(), &configured_ipdum_pdu_ids, "", 0xffffffff);
    prefs_register_range_preference(iso15765_module, "ipdum.pdu.id",
        "I-PduM PDU-IDs",
        "I-PduM PDU-IDs",
        &configured_ipdum_pdu_ids, 0xffffffff);

    prefs_register_enum_preference(iso15765_module, "ipdum_addressing",
        "I-PduM Addressing",
        "Addressing of I-PduM TP. 0, 1, or 2 Bytes",
        &ipdum_addressing,
        enum_ipdum_addressing, true);

    prefs_register_static_text_preference(iso15765_module, "empty_pdu_transport", "", NULL);

    /* UATs for config_pdu_transport_uat */
    static uat_field_t config_pdu_transport_uat_fields[] = {
        UAT_FLD_HEX(config_pdu_transport_config_items, pdu_id,               "PDU ID",             "PDU ID (hex)"),
        UAT_FLD_DEC(config_pdu_transport_config_items, source_address_size,  "Source Addr. Size",  "Size of encoded source address (0, 1, 2 bytes)"),
        UAT_FLD_HEX(config_pdu_transport_config_items, source_address_fixed, "Source Addr. Fixed", "Fixed source address for this PDU ID (hex), 0xffffffff is invalid"),
        UAT_FLD_DEC(config_pdu_transport_config_items, target_address_size,  "Target Addr. Size",  "Size of encoded target address (0, 1, 2 bytes)"),
        UAT_FLD_HEX(config_pdu_transport_config_items, target_address_fixed, "Target Addr. Fixed", "Fixed target address for this PDU ID (hex), 0xffffffff is invalid"),
        UAT_FLD_DEC(config_pdu_transport_config_items, ecu_address_size,     "Single Addr. Size",  "Size of encoded address (0, 1, 2 bytes)"),
        UAT_FLD_HEX(config_pdu_transport_config_items, ecu_address_fixed,    "Single Addr. Fixed", "Fixed address for this PDU ID (hex), 0xffffffff is invalid"),
        UAT_END_FIELDS
    };

    config_pdu_transport_config_uat = uat_new("ISO15765 PDU Transport Config",
        sizeof(config_pdu_transport_config_t),      /* record size           */
        DATAFILE_PDU_TRANSPORT_CONFIG,              /* filename              */
        true,                                       /* from profile          */
        (void**)&config_pdu_transport_config_items, /* data_ptr              */
        &config_pdu_transport_config_items_num,     /* numitems_ptr          */
        UAT_AFFECTS_DISSECTION,                     /* but not fields        */
        NULL,                                       /* help                  */
        copy_config_pdu_transport_config_cb,        /* copy callback         */
        update_config_pdu_transport_config_item,    /* update callback       */
        free_config_pdu_transport_config,           /* free callback         */
        post_update_config_pdu_transport_config_cb, /* post update callback  */
        reset_config_pdu_transport_config_cb,       /* reset callback        */
        config_pdu_transport_uat_fields             /* UAT field definitions */
    );

    prefs_register_uat_preference(iso15765_module, "_iso15765_pdu_transport_config", "PDU Transport Config",
        "A table to define the PDU Transport Config", config_pdu_transport_config_uat);


    iso15765_seq_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), iso15765_seq_hash_func, iso15765_seq_equal_func);
    iso15765_frame_table = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);

    reassembly_table_register(&iso15765_reassembly_table, &addresses_reassembly_table_functions);

    subdissector_table = register_decode_as_next_proto(proto_iso15765, "iso15765.subdissector", "ISO15765 next level dissector", NULL);
}

void
proto_reg_handoff_iso15765(void) {
    iso15765_handle_can = create_dissector_handle(dissect_iso15765_can, proto_iso15765);
    iso15765_handle_lin = create_dissector_handle(dissect_iso15765_lin, proto_iso15765);
    iso15765_handle_flexray = create_dissector_handle(dissect_iso15765_flexray, proto_iso15765);
    iso15765_handle_ipdum = create_dissector_handle(dissect_iso15765_ipdum, proto_iso15765);
    iso15765_handle_pdu_transport = create_dissector_handle(dissect_iso15765_pdu_transport, proto_iso15765);
    dissector_add_for_decode_as("can.subdissector", iso15765_handle_can);
    dissector_add_for_decode_as("flexray.subdissector", iso15765_handle_flexray);
    update_config();
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
