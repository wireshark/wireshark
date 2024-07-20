/* file-pcapng.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */


#ifndef __FILE_PCAPNG_H__
#define __FILE_PCAPNG_H__

/*
 * Structure to pass to block data dissectors.
 */
typedef struct {
    proto_item *block_item;
    proto_tree *block_tree;
    struct info *info;
} block_data_arg;


/* Callback for local block data dissection */
typedef void (local_block_dissect_t)(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, block_data_arg *argp);

/* Callback for local block option dissection function */
typedef void (local_block_option_dissect_t)(proto_tree *option_tree, proto_item *option_item,
                                            packet_info *pinfo, tvbuff_t *tvb, int offset,
                                            int unknown_option_hf,
                                            uint32_t option_code, uint32_t option_length,
                                            unsigned encoding);

typedef struct {
    const char* name;
    local_block_dissect_t *dissector;
    int option_root_hf;
    const value_string *option_vals;
    local_block_option_dissect_t *option_dissector;
} local_block_callback_info_t;

/* Routine for a local block dissector to register with main pcapng dissector.
 * For an in-tree example, please see file-pcapng-darwin.c */
void register_pcapng_local_block_dissector(uint32_t block_number, local_block_callback_info_t *info);


/* Can be called by local block type dissectors block dissector callback */
int dissect_options(proto_tree *tree, packet_info *pinfo,
        uint32_t block_type, tvbuff_t *tvb, int offset, unsigned encoding,
        void *user_data);



/* Used by custom dissector */

/* File info */
struct info {
    uint32_t       block_number;
    uint32_t       section_number;
    uint32_t       interface_number;
    uint32_t       darwin_process_event_number;
    uint32_t       frame_number;
    unsigned       encoding;
    wmem_array_t  *interfaces;
    wmem_array_t  *darwin_process_events;
};

struct interface_description {
    uint32_t link_type;
    uint32_t snap_len;
    uint64_t timestamp_resolution;
    uint64_t timestamp_offset;
};

struct darwin_process_event_description {
    uint32_t process_id;
};

/* Dissect one PCAPNG Block */
extern int dissect_block(proto_tree *tree, packet_info *pinfo, tvbuff_t *tvb, struct info *info);

#endif
