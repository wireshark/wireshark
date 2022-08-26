/* packet-fpp.c
 * Routines for IEEE 802.3br Frame Preemption Protocol packet disassembly
 *
 * Copyright 2017, Anton Glukhov <anton.a.glukhov@gmail.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"

#include <epan/packet.h>
#include <wiretap/wtap.h>

#include <epan/expert.h>
#include <epan/conversation.h>
#include <wsutil/crc32.h>
#include <epan/crc32-tvb.h>
#include <epan/reassemble.h>
#include <epan/proto_data.h>

void proto_register_fpp(void);
void proto_reg_handoff_fpp(void);

static int proto_fpp = -1;

static dissector_handle_t fpp_handle;

static int hf_fpp_preamble = -1;
static int hf_fpp_preamble_pad = -1;
static int hf_fpp_preamble_smd = -1;
static int hf_fpp_preamble_frag_count = -1;
static int hf_fpp_mdata = -1;
static int hf_fpp_crc32 = -1;
static int hf_fpp_crc32_status = -1;
static int hf_fpp_mcrc32 = -1;
static int hf_fpp_mcrc32_status = -1;

static expert_field ei_fpp_crc32 = EI_INIT;
static expert_field ei_fpp_mcrc32 = EI_INIT;

static gint ett_fpp = -1;
static gint ett_fpp_preamble = -1;

static reassembly_table fpp_reassembly_table;

static dissector_handle_t ethl2_handle;

/* Reassembly Data */
static int hf_fpp_fragments = -1;
static int hf_fpp_fragment = -1;
static int hf_fpp_fragment_overlap = -1;
static int hf_fpp_fragment_overlap_conflicts = -1;
static int hf_fpp_fragment_multiple_tails = -1;
static int hf_fpp_fragment_too_long_fragment = -1;
static int hf_fpp_fragment_error = -1;
static int hf_fpp_fragment_count = -1;
static int hf_fpp_reassembled_in = -1;
static int hf_fpp_reassembled_length = -1;
static gint ett_fpp_fragment = -1;
static gint ett_fpp_fragments = -1;

static const fragment_items fpp_frag_items = {
    /* Fragment subtrees */
    &ett_fpp_fragment,
    &ett_fpp_fragments,
    /* Fragment fields */
    &hf_fpp_fragments,
    &hf_fpp_fragment,
    &hf_fpp_fragment_overlap,
    &hf_fpp_fragment_overlap_conflicts,
    &hf_fpp_fragment_multiple_tails,
    &hf_fpp_fragment_too_long_fragment,
    &hf_fpp_fragment_error,
    &hf_fpp_fragment_count,
    /* Reassembled in field */
    &hf_fpp_reassembled_in,
    /* Reassembled length field */
    &hf_fpp_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "fpp fragments"
};

#define FPP_DEFAULT_PREAMBLE_LENGTH 8
#define FPP_CRC_LENGTH      4

typedef enum {
    FPP_Packet_Expess,
    FPP_Packet_Verify,
    FPP_Packet_Response,
    FPP_Packet_Init,
    FPP_Packet_Cont,
    FPP_Packet_Invalid,
} fpp_packet_t;

typedef enum {
    SMD_Verify     = 0x7,
    SMD_Respond    = 0x19,
    SMD_Express    = 0xd5,
    SMD_PP_Start_0 = 0xe6,
    SMD_PP_Start_1 = 0x4c,
    SMD_PP_Start_2 = 0x7f,
    SMD_PP_Start_3 = 0xb3,
    FragCount_0    = SMD_PP_Start_0,
    FragCount_1    = SMD_PP_Start_1,
    FragCount_2    = SMD_PP_Start_2,
    FragCount_3    = SMD_PP_Start_3
} first_delim;

typedef enum {
    Octet_0x55           = 0x55,
    SMD_PP_ContFrag_0    = 0x61,
    SMD_PP_ContFrag_1    = 0x52,
    SMD_PP_ContFrag_2    = 0x9e,
    SMD_PP_ContFrag_3    = 0x2a,
} second_delim;

typedef enum {
    CRC_CRC,
    CRC_mCRC,
    CRC_FALSE
} fpp_crc_t;

typedef enum {
    PACKET_DIRECTION_INBOUND  = 0x1,
    PACKET_DIRECTION_OUTBOUND = 0x2,
    PACKET_DIRECTION_UNKNOWN  = 0x0,
} packet_direction_enum;

/* Packets with correct CRC sum */
static const value_string preemptive_delim_desc[] = {
    { SMD_PP_Start_0, "[Non-fragmented packet: SMD-S0]" },
    { SMD_PP_Start_1, "[Non-fragmented packet: SMD-S1]" },
    { SMD_PP_Start_2, "[Non-fragmented packet: SMD-S2]" },
    { SMD_PP_Start_3, "[Non-fragmented packet: SMD-S3]" },
    { 0x0, NULL }
};

/* Packets with correct mCRC sum */
static const value_string initial_delim_desc[] = {
    { SMD_PP_Start_0, "[Initial fragment: SMD-S0]" },
    { SMD_PP_Start_1, "[Initial fragment: SMD-S1]" },
    { SMD_PP_Start_2, "[Initial fragment: SMD-S2]" },
    { SMD_PP_Start_3, "[Initial fragment: SMD-S3]" },
    { 0x0, NULL }
};

/* Packets with incorrect checksum */
static const value_string corrupted_delim_desc[] = {
    { SMD_PP_Start_0, "[Corrupted fragment: SMD-S0]" },
    { SMD_PP_Start_1, "[Corrupted fragment: SMD-S1]" },
    { SMD_PP_Start_2, "[Corrupted fragment: SMD-S2]" },
    { SMD_PP_Start_3, "[Corrupted fragment: SMD-S3]" },
    { 0x0, NULL }
};

static const value_string continuation_delim_desc[] = {
    { SMD_PP_ContFrag_0, "[Continuation fragment: SMD-C0]" },
    { SMD_PP_ContFrag_1, "[Continuation fragment: SMD-C1]" },
    { SMD_PP_ContFrag_2, "[Continuation fragment: SMD-C2]" },
    { SMD_PP_ContFrag_3, "[Continuation fragment: SMD-C3]" },
    { 0x0, NULL }
};

static const value_string frag_count_delim_desc[] = {
    { FragCount_0, "[#0]"},
    { FragCount_1, "[#1]"},
    { FragCount_2, "[#2]"},
    { FragCount_3, "[#3]"},
    { 0x0, NULL }
};

static const value_string delim_desc[] = {
    { SMD_Verify, "[SMD-V]" },
    { SMD_Respond, "[SMD-R]" },
    { SMD_Express, "[SMD-E]" },
    { SMD_PP_Start_0, "[SMD-S0]" },
    { SMD_PP_Start_1, "[SMD-S1]" },
    { SMD_PP_Start_2, "[SMD-S2]" },
    { SMD_PP_Start_3, "[SMD-S3]" },
    { SMD_PP_ContFrag_0, "[SMD-C0]" },
    { SMD_PP_ContFrag_1, "[SMD-C1]" },
    { SMD_PP_ContFrag_2, "[SMD-C2]" },
    { SMD_PP_ContFrag_3, "[SMD-C3]" },
    { 0x0, NULL }
};

static guint32
get_preamble_length(tvbuff_t *tvb) {

    guint32 offset = 0;

    if( 0x50 == tvb_get_guint8(tvb, offset) )
    {
        //First octet contains preamble alignment bits. Ignore it.
        offset = 1;
    }

    while( tvb_get_guint8(tvb, offset) == Octet_0x55 && ( offset + 2 < tvb_reported_length(tvb) ) )
    {
        offset++;
    }

    guint8 smd1 = tvb_get_guint8(tvb, offset);

    switch (smd1) {
        case SMD_PP_Start_0:
        case SMD_PP_Start_1:
        case SMD_PP_Start_2:
        case SMD_PP_Start_3:
        case SMD_Verify:
        case SMD_Respond:
        case SMD_Express:
            return offset + 1;
        case SMD_PP_ContFrag_0:
        case SMD_PP_ContFrag_1:
        case SMD_PP_ContFrag_2:
        case SMD_PP_ContFrag_3:
            return offset + 2;
        default:
            return FPP_DEFAULT_PREAMBLE_LENGTH;
    }
}

static fpp_crc_t
get_crc_stat(tvbuff_t *tvb, guint32 crc, guint32 mcrc) {
    fpp_crc_t crc_val;
    guint32 received_crc = tvb_get_guint32(tvb, tvb_reported_length(tvb) - FPP_CRC_LENGTH, ENC_BIG_ENDIAN);

    if (received_crc == crc) {
        crc_val = CRC_CRC;
    } else if (received_crc == mcrc) {
        crc_val = CRC_mCRC;
    } else {
        crc_val = CRC_FALSE;
    }
    return crc_val;
}

static fpp_crc_t
get_express_crc_stat(tvbuff_t *tvb, guint32 express_crc) {
    fpp_crc_t crc_val;
    guint32 received_crc = tvb_get_guint32(tvb, tvb_reported_length(tvb) - FPP_CRC_LENGTH, ENC_BIG_ENDIAN);

    if (received_crc == express_crc) {
        crc_val = CRC_CRC;
    } else {
        crc_val = CRC_FALSE;
    }
    return crc_val;
}

static fpp_packet_t
get_packet_type(tvbuff_t *tvb) {
    /* function analyze a packet based on preamble and ignore crc */

    guint32 offset = 0;

    if( 0x50 == tvb_get_guint8(tvb, offset) )
    {
        //First octet contains preamble alignment bits. Ignore it.
        offset = 1;
    }

    while( tvb_get_guint8(tvb, offset) == Octet_0x55 && ( offset + 2 < tvb_reported_length(tvb) ) )
    {
        offset++;
    }

    guint8 smd1 = tvb_get_guint8(tvb, offset);
    guint8 smd2 = tvb_get_guint8(tvb, offset + 1);

    switch (smd1) {
        case SMD_PP_Start_0:
        case SMD_PP_Start_1:
        case SMD_PP_Start_2:
        case SMD_PP_Start_3:
            return FPP_Packet_Init;
        case SMD_Verify:
            return FPP_Packet_Verify;
        case SMD_Respond:
            return FPP_Packet_Response;
        case SMD_Express:
            return FPP_Packet_Expess;
        case SMD_PP_ContFrag_0:
        case SMD_PP_ContFrag_1:
        case SMD_PP_ContFrag_2:
        case SMD_PP_ContFrag_3:
            switch (smd2) {
                case FragCount_0:
                case FragCount_1:
                case FragCount_2:
                case FragCount_3:
                    return FPP_Packet_Cont;
                default:
                    return FPP_Packet_Invalid;
            }
        default:
            return FPP_Packet_Invalid;
    }

    return FPP_Packet_Invalid;
}

static void
col_fstr_process(tvbuff_t *tvb, packet_info *pinfo, fpp_crc_t crc_val) {
    guint preamble_length = get_preamble_length( tvb );

    switch( get_packet_type(tvb) ) {
        case FPP_Packet_Expess:
            col_add_str(pinfo->cinfo, COL_INFO, "[Express]");
            break;
        case FPP_Packet_Verify:
            col_add_str(pinfo->cinfo, COL_INFO, "[Verify]");
            break;
        case FPP_Packet_Response:
            col_add_str(pinfo->cinfo, COL_INFO, "[Respond]");
            break;
        case FPP_Packet_Init:
            if (crc_val == CRC_CRC)
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s", try_val_to_str(tvb_get_guint8(tvb, preamble_length-1), preemptive_delim_desc));
            else if (crc_val == CRC_mCRC)
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s", try_val_to_str(tvb_get_guint8(tvb, preamble_length-1), initial_delim_desc));
            else
                col_add_fstr(pinfo->cinfo, COL_INFO, "%s", try_val_to_str(tvb_get_guint8(tvb, preamble_length-1), corrupted_delim_desc));
            break;
        case FPP_Packet_Cont:
            col_add_fstr(pinfo->cinfo, COL_INFO, "%s %s", try_val_to_str(tvb_get_guint8(tvb, preamble_length-2), continuation_delim_desc),
                                                          try_val_to_str(tvb_get_guint8(tvb, preamble_length-1), frag_count_delim_desc));
            break;
        default:
            break;
    }
}

struct _fpp_ctx_t {
    gboolean preemption;
    guint8 frame_cnt;
    guint8 frag_cnt;
    guint32 size;
    guint32 crc;
    wmem_map_t *crc_history;
};

typedef struct _fpp_ctx_t fpp_ctx_t;

static packet_direction_enum
get_packet_direction(packet_info *pinfo) {
    switch (pinfo->p2p_dir) {
        case P2P_DIR_RECV:
            return PACKET_DIRECTION_INBOUND;
        case P2P_DIR_SENT:
            return PACKET_DIRECTION_OUTBOUND;
        default:
            return PACKET_DIRECTION_UNKNOWN;
    }
}

static void
init_fpp_ctx(struct _fpp_ctx_t *ctx, guint8 frame_cnt, guint32 crc) {
    ctx->preemption = TRUE;
    ctx->frame_cnt = frame_cnt;
    ctx->frag_cnt = FragCount_3;
    ctx->size = 0;
    ctx->crc = crc;
    ctx->crc_history = wmem_map_new(wmem_epan_scope(), g_int_hash, g_int_equal);
}

static guint8
frag_cnt_next(guint8 cur_num) {
    switch(cur_num) {
        case FragCount_0:
            return FragCount_1;
        case FragCount_1:
            return FragCount_2;
        case FragCount_2:
            return FragCount_3;
        case FragCount_3:
        default:
            return FragCount_0;
    }
}

static guint8
get_cont_by_start(guint8 start_cnt) {
    if (start_cnt == SMD_PP_Start_0)
        return SMD_PP_ContFrag_0;
    else if (start_cnt == SMD_PP_Start_1)
        return SMD_PP_ContFrag_1;
    else if (start_cnt == SMD_PP_Start_2)
        return SMD_PP_ContFrag_2;
    else if (start_cnt == SMD_PP_Start_3)
        return SMD_PP_ContFrag_3;
    else
        return SMD_PP_ContFrag_0;
}

struct _fpp_pdata_t {
    /* struct for future possible usage */
    guint32 offset;
};

typedef struct _fpp_pdata_t fpp_pdata_t;

static void
drop_conversation(conversation_t *conv) {
    fpp_ctx_t *ctx;
    ctx = (fpp_ctx_t*)conversation_get_proto_data(conv, proto_fpp);
    if (ctx != NULL) {
        wmem_free(wmem_file_scope(), ctx);
    }
    conversation_delete_proto_data(conv, proto_fpp);
}

static void
drop_fragments(packet_info *pinfo) {
    tvbuff_t *tvbuf;
    guint interface_id;
    packet_direction_enum packet_direction = get_packet_direction(pinfo);

    if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
            interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    else
            interface_id = 0;
    interface_id = interface_id << 0x2;
    tvbuf = fragment_delete(&fpp_reassembly_table, pinfo, interface_id | packet_direction, NULL);

    if (tvbuf != NULL) {
        tvb_free(tvbuf);
    }
}

static tvbuff_t*
dissect_preemption(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
    fpp_packet_t pck_type;

    guint preamble_length = get_preamble_length( tvb );
    guint preamble_bit_length = preamble_length * 8;
    gboolean preamble_unaligned = FALSE;

    guint8 smd1 = tvb_get_guint8(tvb, preamble_length - 2);
    guint8 smd2 = tvb_get_guint8(tvb, preamble_length - 1);

    guint crc_offset = tvb_reported_length(tvb) - FPP_CRC_LENGTH;
    gint frag_size = tvb_reported_length(tvb) - preamble_length - FPP_CRC_LENGTH;

    /* Reassembly parameters. */
    tvbuff_t *new_tvb = NULL;
    fragment_head *frag_data;
    gboolean save_fragmented;
    conversation_t *conv;
    fpp_ctx_t *ctx;
    guint interface_id;
    packet_direction_enum packet_direction = get_packet_direction(pinfo);
    fpp_crc_t crc_val;

    /* mCRC calculations needs previous crc */
    guint32 crc, mcrc, prev_crc;

    if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID)
        interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    else
        interface_id = 0;
    interface_id = interface_id << 0x2;

    /* Create a tree for the preamble. */
    proto_item *ti_preamble = proto_tree_add_item(tree, hf_fpp_preamble, tvb, 0, preamble_length, ENC_NA);

    if( 0x50 == tvb_get_guint8(tvb, 0) )
    {
        //First octet contains preamble alignment bits.
        preamble_bit_length -= 4;
        preamble_unaligned = TRUE;
    }

    if( preamble_bit_length == FPP_DEFAULT_PREAMBLE_LENGTH * 8 ) {
        proto_item_append_text(ti_preamble, " [Preamble length: Normal]" );
    } else if( preamble_bit_length < FPP_DEFAULT_PREAMBLE_LENGTH * 8 ) {
        proto_item_append_text(ti_preamble, " [Preamble length: Shortened by %d bits]", FPP_DEFAULT_PREAMBLE_LENGTH * 8 - preamble_bit_length );
    } else if( preamble_bit_length > FPP_DEFAULT_PREAMBLE_LENGTH * 8 ) {
        proto_item_append_text(ti_preamble, " [Preamble length: Lengthened by %d bits]", preamble_bit_length - FPP_DEFAULT_PREAMBLE_LENGTH * 8 );
    }

    proto_tree_add_item(tree, hf_fpp_mdata, tvb, preamble_length, frag_size, ENC_NA);

    proto_tree *fpp_preamble_tree = proto_item_add_subtree(ti_preamble, ett_fpp_preamble);

    if( preamble_unaligned ) {
        proto_tree_add_item(fpp_preamble_tree, hf_fpp_preamble_pad, tvb, 0, 1, ENC_BIG_ENDIAN);
    }

    pck_type = get_packet_type(tvb);

    if(pck_type == FPP_Packet_Cont)
    {
        proto_item *ti_smd = proto_tree_add_item(fpp_preamble_tree, hf_fpp_preamble_smd, tvb, preamble_length - 2, 1, ENC_BIG_ENDIAN);
        proto_item *ti_fragcnt = proto_tree_add_item(fpp_preamble_tree, hf_fpp_preamble_frag_count, tvb, preamble_length - 1, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_smd, " %s", try_val_to_str(tvb_get_guint8(tvb, preamble_length-2), delim_desc) );
        proto_item_append_text(ti_fragcnt, " %s", try_val_to_str(tvb_get_guint8(tvb, preamble_length-1), frag_count_delim_desc) );
    }
    else
    {
        proto_item *ti_smd = proto_tree_add_item(fpp_preamble_tree, hf_fpp_preamble_smd, tvb, preamble_length - 1, 1, ENC_BIG_ENDIAN);
        proto_item_append_text(ti_smd, " %s", try_val_to_str(tvb_get_guint8(tvb, preamble_length-1), delim_desc) );
    }

    prev_crc = 0;
    conv = find_conversation_by_id(pinfo->num, CONVERSATION_NONE, interface_id | packet_direction);
    /* Create a conversation at every SMD-S fragment.
    Find the conversation for every SMD-C fragment.*/
    if (pck_type == FPP_Packet_Init) {
        /* will be used for seeding the crc calculation */
        if (!PINFO_FD_VISITED(pinfo)) {
            conv = conversation_new_by_id(pinfo->num, CONVERSATION_NONE, interface_id | packet_direction);
            /* XXX Is this needed? */
            find_conversation_pinfo(pinfo, 0);
        }
    }
    else if (pck_type == FPP_Packet_Cont && conv) {
        ctx = (fpp_ctx_t *)conversation_get_proto_data(conv, proto_fpp);
        if (ctx) {
            if (!PINFO_FD_VISITED(pinfo)) {
                if ((ctx->preemption) && (ctx->frame_cnt == smd1) && (frag_cnt_next(ctx->frag_cnt) == smd2)) {
                    prev_crc = ctx->crc;
                }
                /* create a copy of frame number and previous crc and store in crc_history */
                guint32 *copy_of_pinfo_num = wmem_new(wmem_epan_scope(), guint32);
                guint32 *copy_of_prev_crc = wmem_new(wmem_epan_scope(), guint32);
                *copy_of_pinfo_num = pinfo->num;
                *copy_of_prev_crc = prev_crc;
                wmem_map_insert(ctx->crc_history, copy_of_pinfo_num, copy_of_prev_crc);
            }
            else {
                prev_crc = *(guint32 *)wmem_map_lookup(ctx->crc_history, &pinfo->num);
            }
        }
    }

    crc = GUINT32_SWAP_LE_BE(crc32_ccitt_tvb_offset_seed(tvb, preamble_length, frag_size, GUINT32_SWAP_LE_BE(prev_crc) ^ 0xffffffff));
    mcrc = crc ^ 0xffff0000;
    crc_val = get_crc_stat(tvb, crc, mcrc);  /* might be crc if last part or mcrc if continuation */

    /* fill column Info */
    col_fstr_process(tvb, pinfo, crc_val);

    if (pck_type == FPP_Packet_Init) {
        /* Add data to this new conversation during first iteration*/
        if (conv && !PINFO_FD_VISITED(pinfo)) {
            ctx = wmem_new(wmem_file_scope(), struct _fpp_ctx_t);
            init_fpp_ctx(ctx, get_cont_by_start(smd2), crc);
            ctx->size = frag_size;
            conversation_add_proto_data(conv, proto_fpp, ctx);
        }

        if (crc_val == CRC_CRC) {
            /* Non-fragmented packet
            end of continuation */
            drop_fragments(pinfo);

            if (conv && !PINFO_FD_VISITED(pinfo)) {
                drop_conversation(conv);
            }

            proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_crc32, hf_fpp_crc32_status, &ei_fpp_crc32, pinfo, crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

            return tvb_new_subset_length(tvb, preamble_length, frag_size);
        }
        else if (crc_val == CRC_mCRC) {
            /* First fragment */
            drop_fragments(pinfo);

            frag_data = fragment_add_check(&fpp_reassembly_table,
                               tvb, preamble_length, pinfo, interface_id | packet_direction, NULL,
                               0, frag_size, TRUE);

            set_address_tvb(&pinfo->dl_dst, AT_ETHER, 6, tvb, 8);
            set_address_tvb(&pinfo->dst, AT_ETHER, 6, tvb, 8);
            set_address_tvb(&pinfo->dl_src, AT_ETHER, 6, tvb, 14);
            set_address_tvb(&pinfo->src, AT_ETHER, 6, tvb, 14);

            proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_mcrc32, hf_fpp_mcrc32_status, &ei_fpp_mcrc32, pinfo, mcrc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

            if (frag_data != NULL) {
                col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%u]", frag_data->reassembled_in);
                process_reassembled_data(tvb, preamble_length, pinfo,
                    "Reassembled FPP", frag_data, &fpp_frag_items,
                    NULL, tree);
            }
        } else {
            /* Possibly first fragment */
            drop_fragments(pinfo);
            proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_mcrc32, hf_fpp_mcrc32_status, &ei_fpp_mcrc32, pinfo, mcrc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
        }
    } else if (pck_type == FPP_Packet_Cont) {
        if (crc_val == CRC_mCRC) {
            /* Continuation fragment */
            /* Update data of this conversation */
            if (!PINFO_FD_VISITED(pinfo) && conv) {
                ctx = (fpp_ctx_t*)conversation_get_proto_data(conv, proto_fpp);
                if (ctx) {
                    fpp_pdata_t *fpp_pdata = wmem_new(wmem_file_scope(), fpp_pdata_t);
                    fpp_pdata->offset = ctx->size;
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_fpp, interface_id | packet_direction, fpp_pdata);

                    ctx->size += frag_size;
                    ctx->frag_cnt = smd2;
                    ctx->crc = crc;
                }
            }

            proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_mcrc32, hf_fpp_mcrc32_status, &ei_fpp_mcrc32, pinfo, mcrc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

            fpp_pdata_t *fpp_pdata = (fpp_pdata_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fpp, interface_id | packet_direction);
            if (fpp_pdata) {
                frag_data = fragment_add_check(&fpp_reassembly_table,
                    tvb, preamble_length, pinfo, interface_id | packet_direction, NULL,
                    fpp_pdata->offset, frag_size, TRUE);
                if (frag_data != NULL) {
                    col_append_frame_number(pinfo, COL_INFO, " [Reassembled in #%u]", frag_data->reassembled_in);
                    process_reassembled_data(tvb, preamble_length, pinfo,
                        "Reassembled FPP", frag_data, &fpp_frag_items,
                        NULL, tree);
                }
            } else {
                drop_fragments(pinfo);
            }
        } else if (crc_val == CRC_CRC) {
            /* Suppose that the last fragment dissected
                1. preemption is active
                2. check frame count and frag count values
                After these steps check crc of entire reassembled frame
            */
            if (conv) {
                ctx = (fpp_ctx_t*)conversation_get_proto_data(conv, proto_fpp);
                if ((ctx) && (ctx->preemption) && (ctx->frame_cnt == smd1) && (frag_cnt_next(ctx->frag_cnt) == smd2)) {
                    fpp_pdata_t *fpp_pdata = wmem_new(wmem_file_scope(), fpp_pdata_t);
                    if (!PINFO_FD_VISITED(pinfo)) {
                        fpp_pdata->offset = ctx->size;
                        p_add_proto_data(wmem_file_scope(), pinfo, proto_fpp, interface_id | packet_direction, fpp_pdata);
                    }
                }
            }

            fpp_pdata_t *fpp_pdata = (fpp_pdata_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_fpp, interface_id | packet_direction);
            if (fpp_pdata) {
                save_fragmented = pinfo->fragmented;
                pinfo->fragmented = TRUE;
                frag_data = fragment_add_check(&fpp_reassembly_table,
                                               tvb, preamble_length, pinfo, interface_id | packet_direction, NULL,
                                               fpp_pdata->offset, frag_size, FALSE);
                // Attempt reassembly.
                new_tvb = process_reassembled_data(tvb, preamble_length, pinfo,
                                                   "Reassembled FPP", frag_data, &fpp_frag_items,
                                                   NULL, tree);
                pinfo->fragmented = save_fragmented;
            } else {
                drop_fragments(pinfo);
                proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_mcrc32, hf_fpp_mcrc32_status, &ei_fpp_mcrc32, pinfo, mcrc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
            }

            if (new_tvb) {
                /* Reassembly was successful; return the completed datagram. */
                guint32 reassembled_crc = GUINT32_SWAP_LE_BE(crc32_ccitt_tvb_offset(new_tvb, 0, tvb_reported_length(new_tvb)));

                /* Reassembly frame takes place regardless of whether the check sum was correct or not. */
                proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_crc32, -1, &ei_fpp_crc32, pinfo, reassembled_crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

                return new_tvb;
            } else {
                /* Reassembly was unsuccessful; show this fragment.  This may
                    just mean that we don't yet have all the fragments, so
                    we should not just continue dissecting. */
                proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_mcrc32, hf_fpp_mcrc32_status, &ei_fpp_mcrc32, pinfo, crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
                return NULL;
            }
        } else {
            /* Invalid packet */
            if (!PINFO_FD_VISITED(pinfo) && conv) {
                ctx = (fpp_ctx_t *)conversation_get_proto_data(conv, proto_fpp);
                if (ctx) {
                    fpp_pdata_t *fpp_pdata = wmem_new(wmem_file_scope(), fpp_pdata_t);
                    fpp_pdata->offset = ctx->size;
                    p_add_proto_data(wmem_file_scope(), pinfo, proto_fpp, interface_id | packet_direction, fpp_pdata);

                    ctx->size += frag_size;
                    ctx->frag_cnt = smd2;
                    ctx->crc = crc;
                }
            }
            proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_mcrc32, hf_fpp_mcrc32_status, &ei_fpp_mcrc32, pinfo, mcrc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
        }

    } else if (pck_type == FPP_Packet_Verify) {
        proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_mcrc32, -1, &ei_fpp_mcrc32, pinfo, mcrc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    } else if (pck_type == FPP_Packet_Response) {
        proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_mcrc32, hf_fpp_mcrc32_status, &ei_fpp_mcrc32, pinfo, mcrc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);
    }

    return NULL;
}

static tvbuff_t *
dissect_express(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, guint32 crc, fpp_crc_t crc_val) {

    guint crc_offset = tvb_reported_length(tvb) - FPP_CRC_LENGTH;
    guint offset = 0;
    guint preamble_length = get_preamble_length( tvb );
    guint preamble_bit_length = preamble_length * 8;
    gboolean preamble_unaligned = FALSE;
    guint pdu_data_len = tvb_reported_length(tvb) - preamble_length - FPP_CRC_LENGTH;


    proto_item *ti_preamble = proto_tree_add_item(tree, hf_fpp_preamble, tvb, offset, preamble_length, ENC_NA);
    offset += preamble_length;

    if( 0x50 == tvb_get_guint8(tvb, 0) )
    {
        //First octet contains preamble alignment bits.
        preamble_bit_length -= 4;
        preamble_unaligned = TRUE;
    }

    if( preamble_bit_length == FPP_DEFAULT_PREAMBLE_LENGTH * 8 ) {
        proto_item_append_text(ti_preamble, " [Preamble length: Normal]" );
    } else if( preamble_bit_length < FPP_DEFAULT_PREAMBLE_LENGTH * 8 ) {
        proto_item_append_text(ti_preamble, " [Preamble length: Shortened by %d bits]", FPP_DEFAULT_PREAMBLE_LENGTH * 8 - preamble_bit_length );
    } else if( preamble_bit_length > FPP_DEFAULT_PREAMBLE_LENGTH * 8 ) {
        proto_item_append_text(ti_preamble, " [Preamble length: Lengthened by %d bits]", preamble_bit_length - FPP_DEFAULT_PREAMBLE_LENGTH * 8 );
    }


    proto_tree_add_item(tree, hf_fpp_mdata, tvb, offset, pdu_data_len, ENC_NA);

    proto_tree *fpp_preamble_tree = proto_item_add_subtree(ti_preamble, ett_fpp_preamble);

    if( preamble_unaligned ) {
        proto_tree_add_item(fpp_preamble_tree, hf_fpp_preamble_pad, tvb, 0, 1, ENC_BIG_ENDIAN);
    }
    proto_item *ti_smd = proto_tree_add_item(fpp_preamble_tree, hf_fpp_preamble_smd, tvb, preamble_length - 1, 1, ENC_BIG_ENDIAN);
    proto_item_append_text(ti_smd, " [SMD-E]" );

    proto_tree_add_checksum(tree, tvb, crc_offset, hf_fpp_crc32, hf_fpp_crc32_status, &ei_fpp_crc32, pinfo, crc, ENC_BIG_ENDIAN, PROTO_CHECKSUM_VERIFY);

    if (crc_val == CRC_CRC) {
        return tvb_new_subset_length(tvb, preamble_length, pdu_data_len);
    }
    return NULL;
}

static int
dissect_fpp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    guint32 express_crc;
    fpp_crc_t crc_val;
    tvbuff_t *next = tvb;
    guint preamble_length = get_preamble_length( tvb );
    guint pdu_data_len = tvb_reported_length(tvb) - preamble_length - FPP_CRC_LENGTH;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "FPP");
    col_clear(pinfo->cinfo,COL_INFO);

    proto_item *ti = proto_tree_add_item(tree, proto_fpp, tvb, 0, -1, ENC_NA);

    proto_tree *fpp_tree = proto_item_add_subtree(ti, ett_fpp);

    switch (get_packet_type(tvb)) {
        case FPP_Packet_Expess:
            /* this is the old crc calculation which is only valid for express frames */
            express_crc = GUINT32_SWAP_LE_BE(crc32_ccitt_tvb_offset(tvb, preamble_length, pdu_data_len));

            /* is express_crc valid */
            crc_val = get_express_crc_stat(tvb, express_crc);

            /* fill column Info */
            col_fstr_process(tvb, pinfo, crc_val);

            next = dissect_express(tvb, pinfo, fpp_tree, express_crc, crc_val);
            break;
        case FPP_Packet_Init:
        case FPP_Packet_Cont:
        case FPP_Packet_Verify:
        case FPP_Packet_Response:
            next = dissect_preemption(tvb, pinfo, fpp_tree);
            break;
        default:
            break;
    }

    if (next) {
        call_dissector(ethl2_handle, next, pinfo, tree);
    } else {
        tvbuff_t *new_tvb = tvb_new_subset_length(tvb, preamble_length, pdu_data_len);
        call_data_dissector(new_tvb, pinfo, tree);
    }
    return tvb_captured_length(tvb);
}

void
proto_register_fpp(void)
{
    static hf_register_info hf[] = {
        { &hf_fpp_preamble,
            { "Preamble", "fpp.preamble",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_fpp_preamble_pad,
            { "Alignment padding, not part of frame", "fpp.preamble.pad",
                FT_UINT8, BASE_HEX,
                NULL, 0x0F,
                NULL, HFILL }
        },
        { &hf_fpp_preamble_smd,
            { "SMD", "fpp.preamble.smd",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_fpp_preamble_frag_count,
            { "Fragment count", "fpp.preamble.frag_count",
                FT_UINT8, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_fpp_mdata,
            { "mData", "fpp.mdata",
                FT_BYTES, BASE_NONE,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_fpp_crc32,
            { "CRC", "fpp.crc32",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_fpp_crc32_status,
            { "Checksum Status", "fpp.checksum.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL
            },
        },
        { &hf_fpp_mcrc32,
            { "mCRC", "fpp.mcrc32",
                FT_UINT32, BASE_HEX,
                NULL, 0x0,
                NULL, HFILL }
        },
        { &hf_fpp_mcrc32_status,
            { "Checksum Status", "fpp.checksum.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0x0,
                NULL, HFILL
            },
        },

        /* Reassembly fields. */
        { &hf_fpp_fragments,
            { "Message fragments", "fpp.fragments",
                FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_fragment,
            { "Message fragment", "fpp.fragment",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_fragment_overlap,
            { "Message fragment overlap", "fpp.fragment.overlap",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_fragment_overlap_conflicts,
            { "Message fragment overlapping with conflicting data", "fpp.fragment.overlap.conflicts",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_fragment_multiple_tails,
            { "Message has multiple tail fragments", "fpp.fragment.multiple_tails",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_fragment_too_long_fragment,
            { "Message fragment too long", "fpp.fragment.too_long_fragment",
                FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_fragment_error,
            { "Message defragmentation error", "fpp.fragment.error",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_fragment_count,
            { "Message fragment count", "fpp.fragment.count",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_reassembled_in,
            { "Reassembled in", "fpp.reassembled.in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }},
        { &hf_fpp_reassembled_length,
            { "Reassembled fpp length", "fpp.reassembled.length",
                FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }},
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_fpp,
        &ett_fpp_preamble,
        /* Reassembly subtrees. */
        &ett_fpp_fragment,
        &ett_fpp_fragments
    };

    static ei_register_info ei[] = {
        { &ei_fpp_mcrc32,
            { "fpp.mcrc32_bad", PI_CHECKSUM, PI_ERROR,
                "Bad mCRC checksum", EXPFILL }
        },
        { &ei_fpp_crc32,
            { "fpp.crc32_bad", PI_CHECKSUM, PI_ERROR,
                "Bad CRC checksum", EXPFILL }
        },
    };

    expert_module_t* expert_fpp;

    proto_fpp = proto_register_protocol (
        "IEEE 802.3br Frame Preemption Protocol",
        "Frame Preemption Protocol",
        "fpp"
    );

    proto_register_field_array(proto_fpp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_fpp = expert_register_protocol(proto_fpp);
    expert_register_field_array(expert_fpp, ei, array_length(ei));

    reassembly_table_register(&fpp_reassembly_table, &addresses_reassembly_table_functions);

    fpp_handle = register_dissector("fpp", dissect_fpp, proto_fpp);
}

void
proto_reg_handoff_fpp(void)
{
    dissector_add_uint("wtap_encap", WTAP_ENCAP_ETHERNET_MPACKET, fpp_handle);

    ethl2_handle = find_dissector_add_dependency("eth_withoutfcs", proto_fpp);
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
 * :indentSize=4:tabSize=8:noTabs=false:
 */
