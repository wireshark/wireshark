/* packet-mp2t.c
 *
 * Routines for RFC 2250 MPEG2 (ISO/IEC 13818-1) Transport Stream dissection
 *
 * Copyright 2006, Erwin Rol <erwin@erwinrol.com>
 * Copyright 2012-2014, Guy Martin <gmsoft@tuxicoman.be>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
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

#include <epan/packet.h>
#include <wiretap/wtap.h>

#include <epan/rtp_pt.h>

#include <epan/conversation.h>
#include <epan/expert.h>
#include <epan/reassemble.h>
#include <epan/address_types.h>
#include <epan/proto_data.h>
#include "packet-l2tp.h"

void proto_register_mp2t(void);
void proto_reg_handoff_mp2t(void);

/* The MPEG2 TS packet size */
#define MP2T_PACKET_SIZE 188
#define MP2T_SYNC_BYTE   0x47

#define MP2T_PID_DOCSIS  0x1FFE
#define MP2T_PID_NULL    0x1FFF

static dissector_handle_t mp2t_handle;

static dissector_handle_t docsis_handle;
static dissector_handle_t mpeg_pes_handle;
static dissector_handle_t mpeg_sect_handle;

static heur_dissector_list_t heur_subdissector_list;

static int proto_mp2t = -1;
static gint ett_mp2t = -1;
static gint ett_mp2t_header = -1;
static gint ett_mp2t_af = -1;
static gint ett_mp2t_analysis = -1;
static gint ett_stuff = -1;

static int hf_mp2t_header = -1;
static int hf_mp2t_sync_byte = -1;
static int hf_mp2t_tei = -1;
static int hf_mp2t_pusi = -1;
static int hf_mp2t_tp = -1;
static int hf_mp2t_pid = -1;
static int hf_mp2t_tsc = -1;
static int hf_mp2t_afc = -1;
static int hf_mp2t_cc = -1;

/* static int hf_mp2t_analysis_flags = -1; */
static int hf_mp2t_analysis_skips = -1;
static int hf_mp2t_analysis_drops = -1;

#define MP2T_SYNC_BYTE_MASK  0xFF000000
#define MP2T_TEI_MASK        0x00800000
#define MP2T_PUSI_MASK       0x00400000
#define MP2T_TP_MASK         0x00200000
#define MP2T_PID_MASK        0x001FFF00
#define MP2T_TSC_MASK        0x000000C0
#define MP2T_AFC_MASK        0x00000030
#define MP2T_CC_MASK         0x0000000F

#define MP2T_SYNC_BYTE_SHIFT  24
#define MP2T_TEI_SHIFT        23
#define MP2T_PUSI_SHIFT       22
#define MP2T_TP_SHIFT         21
#define MP2T_PID_SHIFT         8
#define MP2T_TSC_SHIFT         6
#define MP2T_AFC_SHIFT         4
#define MP2T_CC_SHIFT          0

static int hf_mp2t_af = -1;
static int hf_mp2t_af_length = -1;
static int hf_mp2t_af_di = -1;
static int hf_mp2t_af_rai = -1;
static int hf_mp2t_af_espi = -1;
static int hf_mp2t_af_pcr_flag = -1;
static int hf_mp2t_af_opcr_flag = -1;
static int hf_mp2t_af_sp_flag = -1;
static int hf_mp2t_af_tpd_flag = -1;
static int hf_mp2t_af_afe_flag = -1;

#define MP2T_AF_DI_MASK     0x80
#define MP2T_AF_RAI_MASK    0x40
#define MP2T_AF_ESPI_MASK   0x20
#define MP2T_AF_PCR_MASK    0x10
#define MP2T_AF_OPCR_MASK   0x08
#define MP2T_AF_SP_MASK     0x04
#define MP2T_AF_TPD_MASK    0x02
#define MP2T_AF_AFE_MASK    0x01

#define MP2T_AF_DI_SHIFT     7
#define MP2T_AF_RAI_SHIFT    6
#define MP2T_AF_ESPI_SHIFT   5
#define MP2T_AF_PCR_SHIFT    4
#define MP2T_AF_OPCR_SHIFT   3
#define MP2T_AF_SP_SHIFT     2
#define MP2T_AF_TPD_SHIFT    1
#define MP2T_AF_AFE_SHIFT    0

static int hf_mp2t_af_pcr = -1;
static int hf_mp2t_af_opcr = -1;

static int hf_mp2t_af_sc = -1;

static int hf_mp2t_af_tpd_length = -1;
static int hf_mp2t_af_tpd = -1;

static int hf_mp2t_af_e_length = -1;
static int hf_mp2t_af_e_ltw_flag = -1;
static int hf_mp2t_af_e_pr_flag = -1;
static int hf_mp2t_af_e_ss_flag = -1;
static int hf_mp2t_af_e_reserved = -1;

#define MP2T_AF_E_LTW_FLAG_MASK   0x80
#define MP2T_AF_E_PR_FLAG_MASK    0x40
#define MP2T_AF_E_SS_FLAG_MASK    0x20

static int hf_mp2t_af_e_reserved_bytes = -1;
static int hf_mp2t_af_stuffing_bytes = -1;

static int hf_mp2t_af_e_ltwv_flag = -1;
static int hf_mp2t_af_e_ltwo = -1;

static int hf_mp2t_af_e_pr_reserved = -1;
static int hf_mp2t_af_e_pr = -1;

static int hf_mp2t_af_e_st = -1;
static int hf_mp2t_af_e_dnau_32_30 = -1;
static int hf_mp2t_af_e_m_1 = -1;
static int hf_mp2t_af_e_dnau_29_15 = -1;
static int hf_mp2t_af_e_m_2 = -1;
static int hf_mp2t_af_e_dnau_14_0 = -1;
static int hf_mp2t_af_e_m_3 = -1;

/* static int hf_mp2t_payload = -1; */
static int hf_mp2t_stuff_bytes = -1;
static int hf_mp2t_pointer = -1;

static int mp2t_no_address_type = -1;

static const value_string mp2t_sync_byte_vals[] = {
    { MP2T_SYNC_BYTE, "Correct" },
    { 0, NULL }
};

static const value_string mp2t_pid_vals[] = {
    { 0x0000, "Program Association Table" },
    { 0x0001, "Conditional Access Table" },
    { 0x0002, "Transport Stream Description Table" },
    { 0x0003, "Reserved" },
    { 0x0004, "Reserved" },
    { 0x0005, "Reserved" },
    { 0x0006, "Reserved" },
    { 0x0007, "Reserved" },
    { 0x0008, "Reserved" },
    { 0x0009, "Reserved" },
    { 0x000A, "Reserved" },
    { 0x000B, "Reserved" },
    { 0x000C, "Reserved" },
    { 0x000D, "Reserved" },
    { 0x000E, "Reserved" },
    { 0x000F, "Reserved" },
    { 0x1FFE, "DOCSIS Data-over-cable well-known PID" },
    { 0x1FFF, "Null packet" },
    { 0, NULL }
};


/* Values below according ETSI ETR 289 */
static const value_string mp2t_tsc_vals[] = {
    { 0, "Not scrambled" },
    { 1, "Reserved" },
    { 2, "Packet scrambled with Even Key" },
    { 3, "Packet scrambled with Odd Key" },
    { 0, NULL }
};

static const value_string mp2t_afc_vals[] = {
    { 0, "Reserved" },
    { 1, "Payload only" },
    { 2, "Adaptation Field only" },
    { 3, "Adaptation Field and Payload" },
    { 0, NULL }
};

static gint ett_msg_fragment = -1;
static gint ett_msg_fragments = -1;
static int hf_msg_fragments = -1;
static int hf_msg_fragment = -1;
static int hf_msg_fragment_overlap = -1;
static int hf_msg_fragment_overlap_conflicts = -1;
static int hf_msg_fragment_multiple_tails = -1;
static int hf_msg_fragment_too_long_fragment = -1;
static int hf_msg_fragment_error = -1;
static int hf_msg_fragment_count = -1;
static int hf_msg_reassembled_in = -1;
static int hf_msg_reassembled_length = -1;

static int hf_msg_ts_packet_reassembled = -1;

static expert_field ei_mp2t_pointer = EI_INIT;
static expert_field ei_mp2t_cc_drop = EI_INIT;
static expert_field ei_mp2t_invalid_afc = EI_INIT;

static const fragment_items mp2t_msg_frag_items = {
    /* Fragment subtrees */
    &ett_msg_fragment,
    &ett_msg_fragments,
    /* Fragment fields */
    &hf_msg_fragments,
    &hf_msg_fragment,
    &hf_msg_fragment_overlap,
    &hf_msg_fragment_overlap_conflicts,
    &hf_msg_fragment_multiple_tails,
    &hf_msg_fragment_too_long_fragment,
    &hf_msg_fragment_error,
    &hf_msg_fragment_count,
    /* Reassembled in field */
    &hf_msg_reassembled_in,
    /* Reassembled length field */
    &hf_msg_reassembled_length,
    /* Reassembled data field */
    NULL,
    /* Tag */
    "Message fragments"
};


/* Data structure used for detecting CC drops
 *
 *  conversation
 *    |
 *    +-> mp2t_analysis_data
 *          |
 *          +-> pid_table (RB tree) (key: pid)
 *          |     |
 *          |     +-> pid_analysis_data (per pid)
 *          |     +-> pid_analysis_data
 *          |     +-> pid_analysis_data
 *          |
 *          +-> frame_table (RB tree) (key: pinfo->num)
 *                |
 *                +-> frame_analysis_data (only created if drop detected)
 *                      |
 *                      +-> ts_table (RB tree)
 *                            |
 *                            +-> ts_analysis_data (per TS subframe)
 *                            +-> ts_analysis_data
 *                            +-> ts_analysis_data
 */

typedef struct mp2t_analysis_data {

    /* This structure contains a tree containing data for the
     * individual pid's, this is only used when packets are
     * processed sequentially.
     */
    wmem_tree_t    *pid_table;

    /* When detecting a CC drop, store that information for the
     * given frame.  This info is needed, when clicking around in
     * wireshark, as the pid table data only makes sense during
     * sequential processing. The flag pinfo->fd->flags.visited is
     * used to tell the difference.
     *
     */
    wmem_tree_t    *frame_table;

    /* Total counters per conversation / multicast stream */
    guint32 total_skips;
    guint32 total_discontinuity;

} mp2t_analysis_data_t;

enum pid_payload_type {
    pid_pload_unknown,
    pid_pload_docsis,
    pid_pload_pes,
    pid_pload_sect,
    pid_pload_null
};

typedef struct subpacket_analysis_data {
    guint32     frag_cur_pos;
    guint32     frag_tot_len;
    gboolean    fragmentation;
    guint32     frag_id;
} subpacket_analysis_data_t;

typedef struct packet_analysis_data {

    /* Contain information for each MPEG2-TS packet in the current big packet */
    wmem_tree_t *subpacket_table;
} packet_analysis_data_t;

/* Analysis TS frame info needed during sequential processing */
typedef struct pid_analysis_data {
    guint16                  pid;
    gint8                    cc_prev;      /* Previous CC number */
    enum pid_payload_type    pload_type;

    /* Fragments information used for first pass */
    gboolean                 fragmentation;
    guint32                  frag_cur_pos;
    guint32                  frag_tot_len;
    guint32                  frag_id;
} pid_analysis_data_t;

/* Analysis info stored for a TS frame */
typedef struct ts_analysis_data {
    guint16  pid;
    gint8    cc_prev;      /* Previous CC number */
    guint8   skips;          /* Skips between Ccs max 14 */
} ts_analysis_data_t;


typedef struct frame_analysis_data {

    /* As each frame has several pid's, thus need a pid data
     * structure per TS frame.
     */
    wmem_tree_t    *ts_table;

} frame_analysis_data_t;

static mp2t_analysis_data_t *
init_mp2t_conversation_data(void)
{
    mp2t_analysis_data_t *mp2t_data;

    mp2t_data = wmem_new0(wmem_file_scope(), struct mp2t_analysis_data);

    mp2t_data->pid_table = wmem_tree_new(wmem_file_scope());

    mp2t_data->frame_table = wmem_tree_new(wmem_file_scope());

    mp2t_data->total_skips = 0;
    mp2t_data->total_discontinuity = 0;

    return mp2t_data;
}

static mp2t_analysis_data_t *
get_mp2t_conversation_data(conversation_t *conv)
{
    mp2t_analysis_data_t *mp2t_data;

    mp2t_data = (mp2t_analysis_data_t *)conversation_get_proto_data(conv, proto_mp2t);
    if (!mp2t_data) {
        mp2t_data = init_mp2t_conversation_data();
        conversation_add_proto_data(conv, proto_mp2t, mp2t_data);
    }

    return mp2t_data;
}

static frame_analysis_data_t *
init_frame_analysis_data(mp2t_analysis_data_t *mp2t_data, packet_info *pinfo)
{
    frame_analysis_data_t *frame_analysis_data_p;

    frame_analysis_data_p = wmem_new0(wmem_file_scope(), struct frame_analysis_data);
    frame_analysis_data_p->ts_table = wmem_tree_new(wmem_file_scope());
    /* Insert into mp2t tree */
    wmem_tree_insert32(mp2t_data->frame_table, pinfo->num,
            (void *)frame_analysis_data_p);

    return frame_analysis_data_p;
}


static frame_analysis_data_t *
get_frame_analysis_data(mp2t_analysis_data_t *mp2t_data, packet_info *pinfo)
{
    frame_analysis_data_t *frame_analysis_data_p;
    frame_analysis_data_p = (frame_analysis_data_t *)wmem_tree_lookup32(mp2t_data->frame_table, pinfo->num);
    return frame_analysis_data_p;
}

static pid_analysis_data_t *
get_pid_analysis(mp2t_analysis_data_t *mp2t_data, guint32 pid)
{
    pid_analysis_data_t  *pid_data;

    pid_data = (pid_analysis_data_t *)wmem_tree_lookup32(mp2t_data->pid_table, pid);
    if (!pid_data) {
        pid_data          = wmem_new0(wmem_file_scope(), struct pid_analysis_data);
        pid_data->cc_prev = -1;
        pid_data->pid     = pid;
        pid_data->frag_id = (pid << (32 - 13)) | 0x1;

        wmem_tree_insert32(mp2t_data->pid_table, pid, (void *)pid_data);
    }
    return pid_data;
}

/* Structure to handle packets, spanned across
 * multiple MPEG packets
 */
static reassembly_table mp2t_reassembly_table;

static void
mp2t_dissect_packet(tvbuff_t *tvb, enum pid_payload_type pload_type,
            packet_info *pinfo, proto_tree *tree)
{
    dissector_handle_t handle = NULL;

    switch (pload_type) {
        case pid_pload_docsis:
            handle = docsis_handle;
            break;
        case pid_pload_pes:
            handle = mpeg_pes_handle;
            break;
        case pid_pload_sect:
            handle = mpeg_sect_handle;
            break;
        default:
            /* Should not happen */
            break;
    }

    if (handle)
        call_dissector(handle, tvb, pinfo, tree);
    else
        call_data_dissector(tvb, pinfo, tree);
}

static guint
mp2t_get_packet_length(tvbuff_t *tvb, guint offset, packet_info *pinfo,
            guint32 frag_id, enum pid_payload_type pload_type)
{
    fragment_head *frag;
    tvbuff_t      *len_tvb = NULL, *frag_tvb = NULL, *data_tvb = NULL;
    gint           pkt_len = 0;
    guint          remaining_len;

    frag = fragment_get(&mp2t_reassembly_table, pinfo, frag_id, NULL);
    if (frag)
        frag = frag->next;

    if (!frag) { /* First frame */
        remaining_len = tvb_reported_length_remaining(tvb, offset);
        if ( (pload_type == pid_pload_docsis && remaining_len < 4) ||
                (pload_type == pid_pload_sect && remaining_len < 3) ||
                (pload_type == pid_pload_pes && remaining_len < 5) ) {
            /* Not enough info to determine the size of the encapsulated packet */
            /* Just add the fragment and we'll check out the length later */
            return -1;
        }

        len_tvb = tvb;
    } else {
        /* Create a composite tvb out of the two */
        frag_tvb = tvb_new_subset_remaining(frag->tvb_data, 0);
        len_tvb = tvb_new_composite();
        tvb_composite_append(len_tvb, frag_tvb);

        data_tvb = tvb_new_subset_remaining(tvb, offset);
        tvb_composite_append(len_tvb, data_tvb);
        tvb_composite_finalize(len_tvb);

        offset = frag->offset;
    }

    /* Get the next packet's size if possible */
    switch (pload_type) {
        case pid_pload_docsis:
            pkt_len = tvb_get_ntohs(len_tvb, offset + 2) + 6;
            break;
        case pid_pload_pes:
            pkt_len = tvb_get_ntohs(len_tvb, offset + 4);
            if (pkt_len) /* A size of 0 means size not bounded */
                pkt_len += 6;
            break;
        case pid_pload_sect:
            pkt_len = (tvb_get_ntohs(len_tvb, offset + 1) & 0xFFF) + 3;
            break;
        default:
            /* Should not happen */
            break;
    }

    if (frag_tvb)
        tvb_free(frag_tvb);

    return pkt_len;
}

static void
mp2t_fragment_handle(tvbuff_t *tvb, guint offset, packet_info *pinfo,
        proto_tree *tree, guint32 frag_id,
        guint frag_offset, guint frag_len,
        gboolean fragment_last, enum pid_payload_type pload_type)
{
    /* proto_item *ti; */
    fragment_head *frag_msg;
    tvbuff_t      *new_tvb;
    gboolean       save_fragmented;
    address        save_src, save_dst;

    save_fragmented = pinfo->fragmented;
    pinfo->fragmented = TRUE;
    copy_address_shallow(&save_src, &pinfo->src);
    copy_address_shallow(&save_dst, &pinfo->dst);

    /* It's possible that a fragment in the same packet set an address already
     * This will change the hash value, we need to make sure it's NULL */

    set_address(&pinfo->src, mp2t_no_address_type, 0, NULL);
    set_address(&pinfo->dst, mp2t_no_address_type, 0, NULL);

    /* check length; send frame for reassembly */
    frag_msg = fragment_add_check(&mp2t_reassembly_table,
            tvb, offset, pinfo, frag_id, NULL,
            frag_offset,
            frag_len,
            !fragment_last);

    new_tvb = process_reassembled_data(tvb, offset, pinfo,
            "Reassembled MP2T",
            frag_msg, &mp2t_msg_frag_items,
            NULL, tree);

    copy_address_shallow(&pinfo->src, &save_src);
    copy_address_shallow(&pinfo->dst, &save_dst);

    if (new_tvb) {
        /* ti = */ proto_tree_add_item(tree, hf_msg_ts_packet_reassembled, tvb, 0, 0, ENC_NA);
        mp2t_dissect_packet(new_tvb, pload_type, pinfo, tree);
    } else {
        col_set_str(pinfo->cinfo, COL_INFO, "[MP2T fragment of a reassembled packet]");
    }

    pinfo->fragmented = save_fragmented;
}


/*  Decoding of DOCSIS MAC frames within MPEG packets. MAC frames may begin anywhere
 *  within an MPEG packet or span multiple MPEG packets.
 *  payload_unit_start_indicator bit in MPEG header, and pointer field are used to
 *  decode fragmented DOCSIS frames within MPEG packet.
 *-------------------------------------------------------------------------------
 *MPEG Header | pointer_field | stuff_bytes | Start of MAC Frame #1              |
 *(PUSI = 1)  | (= 0)         | (0 or more) |(up to 183 bytes)                   |
 *-------------------------------------------------------------------------------
 *-------------------------------------------------------------------------------
 *MPEG Header |  Continuation of MAC Frame #1                                    |
 *(PUSI = 0)  |  (up to 183 bytes)                                               |
 *-------------------------------------------------------------------------------
 *-------------------------------------------------------------------------------
 *MPEG Header | pointer_field |Tail of MAC Frame| stuff_bytes |Start of MAC Frame|
 *(PUSI = 1)  | (= M)         | #1  (M bytes)   | (0 or more) |# 2 (N bytes)     |
 *-------------------------------------------------------------------------------
 *  Source - Data-Over-Cable Service Interface Specifications
 *  CM-SP-DRFI-I07-081209
 */
static void
mp2t_process_fragmented_payload(tvbuff_t *tvb, gint offset, guint remaining_len, packet_info *pinfo,
        proto_tree *tree, proto_tree *header_tree, guint32 pusi_flag,
        pid_analysis_data_t *pid_analysis)
{
    tvbuff_t                  *next_tvb;
    guint8                     pointer       = 0;
    proto_item                *pi;
    guint                      stuff_len     = 0;
    proto_tree                *stuff_tree;
    packet_analysis_data_t    *pdata         = NULL;
    subpacket_analysis_data_t *spdata        = NULL;
    guint32                    frag_cur_pos  = 0, frag_tot_len = 0;
    gboolean                   fragmentation = FALSE;
    guint32                    frag_id       = 0;

    if (pusi_flag && pid_analysis->pload_type == pid_pload_unknown
            && remaining_len > 3) {
        /* We should already have identified if it was a DOCSIS packet
         * Remaining possibility is PES or SECT */
        if (tvb_get_ntoh24(tvb, offset) == 0x000001) {
            /* Looks like a PES packet to me ... */
            pid_analysis->pload_type = pid_pload_pes;
        } else {
            /* Most probably a SECT packet */
            pid_analysis->pload_type = pid_pload_sect;
        }
    }

    /* Unable to determine the payload type, do nothing */
    if (pid_analysis->pload_type == pid_pload_unknown)
        return;

    /* PES packet don't have pointer fields, others do */
    if (pusi_flag && pid_analysis->pload_type != pid_pload_pes) {
        pointer = tvb_get_guint8(tvb, offset);
        pi = proto_tree_add_item(header_tree, hf_mp2t_pointer, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        remaining_len--;
        if (pointer > remaining_len) {
            /* Bogus pointer */
            expert_add_info_format(pinfo, pi, &ei_mp2t_pointer,
                    "Pointer value is too large (> remaining data length %u)",
                    remaining_len);
        }
    }

    if (!pinfo->fd->flags.visited) {
        /* Get values from our current PID analysis */
        frag_cur_pos = pid_analysis->frag_cur_pos;
        frag_tot_len = pid_analysis->frag_tot_len;
        fragmentation = pid_analysis->fragmentation;
        frag_id = pid_analysis->frag_id;
        pdata = (packet_analysis_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mp2t, 0);
        if (!pdata) {
            pdata = wmem_new0(wmem_file_scope(), packet_analysis_data_t);
            pdata->subpacket_table = wmem_tree_new(wmem_file_scope());
            p_add_proto_data(wmem_file_scope(), pinfo, proto_mp2t, 0, pdata);

        } else {
            spdata = (subpacket_analysis_data_t *)wmem_tree_lookup32(pdata->subpacket_table, offset);
        }

        if (!spdata) {
            spdata = wmem_new0(wmem_file_scope(), subpacket_analysis_data_t);
            /* Save the info into pdata from pid_analysis */
            spdata->frag_cur_pos = frag_cur_pos;
            spdata->frag_tot_len = frag_tot_len;
            spdata->fragmentation = fragmentation;
            spdata->frag_id = frag_id;
            wmem_tree_insert32(pdata->subpacket_table, offset, (void *)spdata);
        }
    } else {
        /* Get saved values */
        pdata = (packet_analysis_data_t *)p_get_proto_data(wmem_file_scope(), pinfo, proto_mp2t, 0);
        if (!pdata) {
            /* Occurs for the first packets in the capture which cannot be reassembled */
            return;
        }

        spdata = (subpacket_analysis_data_t *)wmem_tree_lookup32(pdata->subpacket_table, offset);
        if (!spdata) {
            /* Occurs for the first sub packets in the capture which cannot be reassembled */
            return;
        }

        frag_cur_pos = spdata->frag_cur_pos;
        frag_tot_len = spdata->frag_tot_len;
        fragmentation = spdata->fragmentation;
        frag_id = spdata->frag_id;
    }

    if (frag_tot_len == (guint)-1) {
        frag_tot_len = mp2t_get_packet_length(tvb, offset, pinfo, frag_id, pid_analysis->pload_type);

        if (frag_tot_len == (guint)-1) {
            return;
        }
    }


    /* The beginning of a new packet is present */
    if (pusi_flag) {
        if (pointer > remaining_len) {
            /*
             * Quit, so we don't use the bogus pointer value;
             * that could cause remaining_len to become
             * "negative", meaning it becomes a very large
             * positive value.
             */
            return;
        }

        /* "pointer" contains the number of bytes until the
         * start of the new section
         *
         * if the new section does not start immediately after the
         * pointer field (i.e. pointer>0), the remaining bytes before the
         * start of the section are another fragment of the
         * current packet
         *
         * if pointer is 0, a new upper-layer packet starts at the
         * beginning of this TS packet
         * if we have pending fragments, the last TS packet contained the
         * last fragment and at the time we processed it, we couldn't figure
         * out that it is the last fragment
         * this is the case e.g. for PES packets with a 0 length field
         * ("unbounded length")
         * to handle this case, we add an empty fragment (pointer==0)
         * and reassemble, then we process the current TS packet as
         * usual
         */
        if (fragmentation) {
            mp2t_fragment_handle(tvb, offset, pinfo, tree, frag_id, frag_cur_pos,
                    pointer, TRUE, pid_analysis->pload_type);
            frag_id++;
        }

        offset += pointer;
        remaining_len -= pointer;
        fragmentation = FALSE;
        frag_cur_pos = 0;
        frag_tot_len = 0;

        if (!remaining_len) {
            /* Shouldn't happen */
            goto save_state;
        }

        while (remaining_len > 0) {
            /* Don't like subsequent packets overwrite the Info column */
            col_append_str(pinfo->cinfo, COL_INFO, " ");
            col_set_fence(pinfo->cinfo, COL_INFO);

            /* Skip stuff bytes */
            stuff_len = 0;
            while ((tvb_get_guint8(tvb, offset + stuff_len) == 0xFF)) {
                stuff_len++;
                if (stuff_len >= remaining_len) {
                    remaining_len = 0;
                    break;
                }
            }

            if (stuff_len) {
                stuff_tree = proto_tree_add_subtree_format(tree, tvb, offset, stuff_len, ett_stuff, NULL, "Stuffing");
                proto_tree_add_item(stuff_tree, hf_mp2t_stuff_bytes, tvb, offset, stuff_len, ENC_NA);
                offset += stuff_len;
                if (stuff_len >= remaining_len) {
                    goto save_state;
                }
                remaining_len -= stuff_len;
            }

            /* Get the next packet's size if possible */
            frag_tot_len = mp2t_get_packet_length(tvb, offset, pinfo, frag_id, pid_analysis->pload_type);
            if (frag_tot_len == (guint)-1 || !frag_tot_len) {
                mp2t_fragment_handle(tvb, offset, pinfo, tree, frag_id, 0, remaining_len, FALSE, pid_analysis->pload_type);
                fragmentation = TRUE;
                /*offset += remaining_len;*/
                frag_cur_pos += remaining_len;
                goto save_state;
            }

            /* Check for full packets within this TS frame */
            if (frag_tot_len &&
                    frag_tot_len <= remaining_len) {
                next_tvb = tvb_new_subset_length(tvb, offset, frag_tot_len);
                mp2t_dissect_packet(next_tvb, pid_analysis->pload_type, pinfo, tree);
                remaining_len -= frag_tot_len;
                offset += frag_tot_len;
                frag_tot_len = 0;
                frag_id++;
            } else {
                break;
            }
        }

        if (remaining_len == 0) {
            pid_analysis->frag_cur_pos = 0;
            pid_analysis->frag_tot_len = 0;
            goto save_state;

        }

    }

    /* There are remaining bytes. Add them to the fragment list */

    if ((frag_tot_len && frag_cur_pos + remaining_len >= frag_tot_len) || (!frag_tot_len && pusi_flag)) {
        mp2t_fragment_handle(tvb, offset, pinfo, tree, frag_id, frag_cur_pos, remaining_len, TRUE, pid_analysis->pload_type);
        frag_id++;
        fragmentation = FALSE;
        frag_cur_pos = 0;
        frag_tot_len = 0;
    } else {
        mp2t_fragment_handle(tvb, offset, pinfo, tree, frag_id, frag_cur_pos, remaining_len, FALSE, pid_analysis->pload_type);
        fragmentation = TRUE;
        frag_cur_pos += remaining_len;
    }

save_state:
    pid_analysis->fragmentation = fragmentation;
    pid_analysis->frag_cur_pos = frag_cur_pos;
    pid_analysis->frag_tot_len = frag_tot_len;
    pid_analysis->frag_id = frag_id;
}



/* Calc the number of skipped CC numbers. Note that this can easy
 * overflow, and a value above 7 indicate several network packets
 * could be lost.
 */
static guint32
calc_skips(gint32 curr, gint32 prev)
{
    int res;

    /* Only count the missing TS frames in between prev and curr.
     * The "prev" frame CC number seen is confirmed received, it's
     * the next frames CC counter which is the first known missing
     * TS frame
     */
    prev += 1;

    /* Calc missing TS frame 'skips' */
    res = curr - prev;

    /* Handle wrap around */
    if (res < 0)
        res += 16;

    return res;
}

#define KEY(pid, cc) ((pid << 4)|cc)

static guint32
detect_cc_drops(tvbuff_t *tvb, proto_tree *tree, packet_info *pinfo,
        guint32 pid, gint32 cc_curr, mp2t_analysis_data_t *mp2t_data)
{
    gint32 cc_prev = -1;
    pid_analysis_data_t   *pid_data              = NULL;
    ts_analysis_data_t    *ts_data               = NULL;
    frame_analysis_data_t *frame_analysis_data_p = NULL;
    proto_item            *flags_item;

    gboolean detected_drop = FALSE;
    guint32 skips = 0;

    /* The initial sequential processing stage */
    if (!pinfo->fd->flags.visited) {
        /* This is the sequential processing stage */
        pid_data = get_pid_analysis(mp2t_data, pid);

        cc_prev = pid_data->cc_prev;
        pid_data->cc_prev = cc_curr;

        /* Null packet always have a CC value equal 0 */
        if (pid == 0x1fff)
            return 0;

        /* Its allowed that (cc_prev == cc_curr) if adaptation field */
        if (cc_prev == cc_curr)
            return 0;

        /* Have not seen this pid before */
        if (cc_prev == -1)
            return 0;

        /* Detect if CC is not increasing by one all the time */
        if (cc_curr != ((cc_prev+1) & MP2T_CC_MASK)) {
            detected_drop = TRUE;

            skips = calc_skips(cc_curr, cc_prev);

            mp2t_data->total_skips += skips;
            mp2t_data->total_discontinuity++;
            /* TODO: if (skips > 7) signal_loss++; ??? */
        }
    }

    /* Save the info about the dropped packet */
    if (detected_drop && !pinfo->fd->flags.visited) {
        /* Lookup frame data, contains TS pid data objects */
        frame_analysis_data_p = get_frame_analysis_data(mp2t_data, pinfo);
        if (!frame_analysis_data_p)
            frame_analysis_data_p = init_frame_analysis_data(mp2t_data, pinfo);

        /* Create and store a new TS frame pid_data object.
           This indicate that we have a drop
         */
        ts_data = wmem_new0(wmem_file_scope(), struct ts_analysis_data);
        ts_data->cc_prev = cc_prev;
        ts_data->pid = pid;
        ts_data->skips = skips;
        wmem_tree_insert32(frame_analysis_data_p->ts_table, KEY(pid, cc_curr),
                 (void *)ts_data);
    }

    /* See if we stored info about drops */
    if (pinfo->fd->flags.visited) {

        /* Lookup frame data, contains TS pid data objects */
        frame_analysis_data_p = get_frame_analysis_data(mp2t_data, pinfo);
        if (!frame_analysis_data_p)
            return 0; /* No stored frame data -> no drops*/
        else {
            ts_data = (struct ts_analysis_data *)wmem_tree_lookup32(frame_analysis_data_p->ts_table,
                           KEY(pid, cc_curr));

            if (ts_data) {
                if (ts_data->skips > 0) {
                    detected_drop = TRUE;
                    cc_prev = ts_data->cc_prev;
                    skips   = ts_data->skips;
                }
            }
        }
    }

    /* Add info to the proto tree about drops */
    if (detected_drop) {
        expert_add_info_format(pinfo, tree, &ei_mp2t_cc_drop,
                "Detected %d missing TS frames before this (last_cc:%d total skips:%d discontinuity:%d)",
                skips, cc_prev,
                mp2t_data->total_skips,
                mp2t_data->total_discontinuity
                );

        flags_item = proto_tree_add_uint(tree, hf_mp2t_analysis_skips,
                tvb, 0, 0, skips);
        PROTO_ITEM_SET_GENERATED(flags_item);

        flags_item = proto_tree_add_uint(tree, hf_mp2t_analysis_drops,
                tvb, 0, 0, 1);
        PROTO_ITEM_SET_GENERATED(flags_item);
    }
    return skips;
}

static gint
dissect_mp2t_adaptation_field(tvbuff_t *tvb, gint offset, proto_tree *tree)
{
    gint        af_start_offset;
    proto_item *hi;
    proto_tree *mp2t_af_tree;
    guint8      af_length;
    guint8      af_flags;
    gint        stuffing_len;

    af_length = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_mp2t_af_length, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    /* fix issues where afc==3 but af_length==0
     *  Adaptaion field...spec section 2.4.3.5: The value 0 is for inserting a single
     *  stuffing byte in a Transport Stream packet. When the adaptation_field_control
     *  value is '11', the value of the adaptation_field_length shall be in the range 0 to 182.
     */
    if (af_length == 0)
        return offset;

    af_start_offset = offset;

    hi = proto_tree_add_item( tree, hf_mp2t_af, tvb, offset, af_length, ENC_NA);
    mp2t_af_tree = proto_item_add_subtree( hi, ett_mp2t_af );

    af_flags = tvb_get_guint8(tvb, offset);
    proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_di, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_rai, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_espi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_pcr_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_opcr_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_sp_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_afe_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;

    if (af_flags &  MP2T_AF_PCR_MASK) {
        guint64 pcr_base;
        guint16 pcr_ext;

        /* 33 bit PCR base, 6 bit reserved, 9 bit PCR ext */
        pcr_base = tvb_get_ntoh48(tvb, offset) >> (48-33);
        pcr_ext  = (guint16)(tvb_get_ntoh48(tvb, offset) & 0x1FF);

         proto_tree_add_uint64(mp2t_af_tree, hf_mp2t_af_pcr, tvb, offset, 6,
                pcr_base*300 + pcr_ext);

        offset += 6;
    }

    if (af_flags &  MP2T_AF_OPCR_MASK) {
        guint64 opcr_base;
        guint16 opcr_ext;

        /* the same format as PCR above */
        opcr_base = tvb_get_ntoh48(tvb, offset) >> (48-33);
        opcr_ext  = (guint16)(tvb_get_ntoh48(tvb, offset) & 0x1FF);

        proto_tree_add_uint64(mp2t_af_tree, hf_mp2t_af_opcr, tvb, offset, 6,
                opcr_base*300 + opcr_ext);

        offset += 6;
    }

    if (af_flags &  MP2T_AF_SP_MASK) {
        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_sc, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (af_flags &  MP2T_AF_TPD_MASK) {
        guint8 tpd_len;

        tpd_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_tpd, tvb, offset, tpd_len, ENC_NA);
        offset += tpd_len;
    }

    if (af_flags &  MP2T_AF_AFE_MASK) {
        guint8 e_len;
        guint8 e_flags;
        gint e_start_offset = offset;
        gint reserved_len = 0;

        e_len = tvb_get_guint8(tvb, offset);
        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_length, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        e_flags = tvb_get_guint8(tvb, offset);
        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltw_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ss_flag, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_reserved, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        if (e_flags & MP2T_AF_E_LTW_FLAG_MASK) {
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltwv_flag, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_ltwo, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

        if (e_flags & MP2T_AF_E_PR_FLAG_MASK) {
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr_reserved, tvb, offset, 3, ENC_BIG_ENDIAN);
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_pr, tvb, offset, 3, ENC_BIG_ENDIAN);
            offset += 3;
        }

        if (e_flags & MP2T_AF_E_SS_FLAG_MASK) {
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_st, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_32_30, tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_1, tvb, offset, 1, ENC_BIG_ENDIAN);
            offset += 1;
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_29_15, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_2, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_dnau_14_0, tvb, offset, 2, ENC_BIG_ENDIAN);
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_m_3, tvb, offset, 2, ENC_BIG_ENDIAN);
            offset += 2;
        }

        reserved_len = (e_len + 1) - (offset - e_start_offset);
        if (reserved_len > 0) {
            proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_e_reserved_bytes, tvb, offset, reserved_len, ENC_NA);
            offset += reserved_len;
        }
    }

    stuffing_len = af_length - (offset - af_start_offset);
    if (stuffing_len > 0) {
        proto_tree_add_item( mp2t_af_tree, hf_mp2t_af_stuffing_bytes, tvb, offset, stuffing_len, ENC_NA);
        offset += stuffing_len;
    }

    return offset;
}

static void
dissect_tsp(tvbuff_t *tvb, gint offset, packet_info *pinfo,
        proto_tree *tree, conversation_t *conv)
{
    guint32              header;
    guint                afc;
    gint                 start_offset = offset;
    gint                 payload_len;
    mp2t_analysis_data_t *mp2t_data;
    pid_analysis_data_t *pid_analysis;

    guint32     skips;
    guint32     pid;
    guint32     cc;
    guint32     pusi_flag;

    guint32 tsc;

    proto_item *ti;
    proto_item *hi;
    proto_item *item = NULL;
    proto_tree *mp2t_tree;
    proto_tree *mp2t_header_tree;
    proto_tree *mp2t_analysis_tree;
    proto_item *afci;

    ti = proto_tree_add_item( tree, proto_mp2t, tvb, offset, MP2T_PACKET_SIZE, ENC_NA );
    mp2t_tree = proto_item_add_subtree( ti, ett_mp2t );

    header = tvb_get_ntohl(tvb, offset);
    pusi_flag = (header & 0x00400000);
    pid = (header & MP2T_PID_MASK) >> MP2T_PID_SHIFT;
    tsc = (header & MP2T_TSC_MASK);
    afc = (header & MP2T_AFC_MASK) >> MP2T_AFC_SHIFT;
    cc  = (header & MP2T_CC_MASK)  >> MP2T_CC_SHIFT;

    proto_item_append_text(ti, " PID=0x%x CC=%d", pid, cc);
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MPEG TS");

    hi = proto_tree_add_item( mp2t_tree, hf_mp2t_header, tvb, offset, 4, ENC_BIG_ENDIAN);
    mp2t_header_tree = proto_item_add_subtree( hi, ett_mp2t_header );

    proto_tree_add_item( mp2t_header_tree, hf_mp2t_sync_byte, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_header_tree, hf_mp2t_tei, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_header_tree, hf_mp2t_pusi, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_header_tree, hf_mp2t_tp, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_header_tree, hf_mp2t_pid, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_header_tree, hf_mp2t_tsc, tvb, offset, 4, ENC_BIG_ENDIAN);
    afci = proto_tree_add_item( mp2t_header_tree, hf_mp2t_afc, tvb, offset, 4, ENC_BIG_ENDIAN);
    proto_tree_add_item( mp2t_header_tree, hf_mp2t_cc, tvb, offset, 4, ENC_BIG_ENDIAN);

    mp2t_data = get_mp2t_conversation_data(conv);

    pid_analysis = get_pid_analysis(mp2t_data, pid);

    if (pid_analysis->pload_type == pid_pload_unknown) {
        if (pid == MP2T_PID_NULL) {
            pid_analysis->pload_type = pid_pload_null;
        } else if (pid == MP2T_PID_DOCSIS) {
            pid_analysis->pload_type = pid_pload_docsis;
        }
    }

    if (pid_analysis->pload_type == pid_pload_docsis && (afc != 1)) {
        /* DOCSIS packets should not have an adaptation field */
        if (afc != 1) {
            expert_add_info_format(pinfo, afci, &ei_mp2t_invalid_afc,
                    "Adaptation Field Control for DOCSIS packets must be 0x01");
        }
    }

    if (pid_analysis->pload_type == pid_pload_null) {
        col_set_str(pinfo->cinfo, COL_INFO, "NULL packet");
        if (afc != 1) {
            expert_add_info_format(pinfo, afci, &ei_mp2t_invalid_afc,
                    "Adaptation Field Control for NULL packets must be 0x01");
        }
        /* Nothing more to do */
        return;
    }

    offset += 4;

    /* Create a subtree for analysis stuff */
    mp2t_analysis_tree = proto_tree_add_subtree_format(mp2t_tree, tvb, offset, 0, ett_mp2t_analysis, &item, "MPEG2 PCR Analysis");
    PROTO_ITEM_SET_GENERATED(item);

    skips = detect_cc_drops(tvb, mp2t_analysis_tree, pinfo, pid, cc, mp2t_data);

    if (skips > 0)
        proto_item_append_text(ti, " skips=%d", skips);

    if (afc == 2 || afc == 3)
        offset = dissect_mp2t_adaptation_field(tvb, offset, mp2t_tree);

    if ((offset - start_offset) < MP2T_PACKET_SIZE)
        payload_len = MP2T_PACKET_SIZE - (offset - start_offset);
    else
        payload_len = 0;

    if (!payload_len)
        return;

    if (afc == 2) {
        col_set_str(pinfo->cinfo, COL_INFO, "Adaptation field only");
        /* The rest of the packet is stuffing bytes */
        proto_tree_add_item( mp2t_tree, hf_mp2t_stuff_bytes, tvb, offset, payload_len, ENC_NA);
        offset += payload_len;
    }

    if (!tsc) {
        mp2t_process_fragmented_payload(tvb, offset, payload_len, pinfo, tree, mp2t_tree, pusi_flag, pid_analysis);
    } else {
        /* Payload is scrambled */
        col_set_str(pinfo->cinfo, COL_INFO, "Scrambled TS payload");
    }
}


static int
dissect_mp2t( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void* data _U_ )
{
    guint         offset = 0;
    conversation_t    *conv;

    conv = find_or_create_conversation(pinfo);

    for (; tvb_reported_length_remaining(tvb, offset) >= MP2T_PACKET_SIZE; offset += MP2T_PACKET_SIZE) {
       dissect_tsp(tvb, offset, pinfo, tree, conv);
    }
    return tvb_captured_length(tvb);
}

static gboolean
heur_dissect_mp2t( tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_ )
{
    gint length;
    guint offset = 0;

    length = tvb_reported_length_remaining(tvb, offset);
    if (length == 0) {
        /* Nothing to check for */
        return FALSE;
    }
    if ((length % MP2T_PACKET_SIZE) != 0) {
        /* Not a multiple of the MPEG-2 transport packet size */
        return FALSE;
    } else {
        while (tvb_offset_exists(tvb, offset)) {
            if (tvb_get_guint8(tvb, offset) != MP2T_SYNC_BYTE) {
                /* No sync byte at the appropriate offset */
                return FALSE;
            }
            offset += MP2T_PACKET_SIZE;
        }
    }

    dissect_mp2t(tvb, pinfo, tree, data);
    return TRUE;
}


static void
mp2t_init(void) {
    reassembly_table_init(&mp2t_reassembly_table,
        &addresses_reassembly_table_functions);
}

static void
mp2t_cleanup(void) {
    reassembly_table_destroy(&mp2t_reassembly_table);
}

void
proto_register_mp2t(void)
{
    static hf_register_info hf[] = {
        { &hf_mp2t_header, {
            "Header", "mp2t.header",
            FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL
        } } ,
        { &hf_mp2t_sync_byte, {
            "Sync Byte", "mp2t.sync_byte",
            FT_UINT32, BASE_HEX, VALS(mp2t_sync_byte_vals), MP2T_SYNC_BYTE_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_tei, {
            "Transport Error Indicator", "mp2t.tei",
            FT_UINT32, BASE_DEC, NULL, MP2T_TEI_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_pusi, {
            "Payload Unit Start Indicator", "mp2t.pusi",
            FT_UINT32, BASE_DEC, NULL, MP2T_PUSI_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_tp, {
            "Transport Priority", "mp2t.tp",
            FT_UINT32, BASE_DEC, NULL, MP2T_TP_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_pid, {
            "PID", "mp2t.pid",
            FT_UINT32, BASE_HEX, VALS(mp2t_pid_vals), MP2T_PID_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_tsc, {
            "Transport Scrambling Control", "mp2t.tsc",
            FT_UINT32, BASE_HEX, VALS(mp2t_tsc_vals), MP2T_TSC_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_afc, {
            "Adaptation Field Control", "mp2t.afc",
            FT_UINT32, BASE_HEX, VALS(mp2t_afc_vals) , MP2T_AFC_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_cc, {
            "Continuity Counter", "mp2t.cc",
            FT_UINT32, BASE_DEC, NULL, MP2T_CC_MASK, NULL, HFILL
        } } ,
#if 0
        { &hf_mp2t_analysis_flags, {
            "MPEG2-TS Analysis Flags", "mp2t.analysis.flags",
            FT_NONE, BASE_NONE, NULL, 0x0,
            "This frame has some of the MPEG2 analysis flags set", HFILL
        } } ,
#endif
        { &hf_mp2t_analysis_skips, {
            "TS Continuity Counter Skips", "mp2t.analysis.skips",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Missing TS frames according to CC counter values", HFILL
        } } ,
        { &hf_mp2t_analysis_drops, {
            "Some frames dropped", "mp2t.analysis.drops",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            "Discontinuity: A number of TS frames were dropped", HFILL
        } } ,
        { &hf_mp2t_af, {
            "Adaptation Field", "mp2t.af",
            FT_NONE, BASE_NONE, NULL, 0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_length, {
            "Adaptation Field Length", "mp2t.af.length",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_di, {
            "Discontinuity Indicator", "mp2t.af.di",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_DI_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_rai, {
            "Random Access Indicator", "mp2t.af.rai",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_RAI_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_espi, {
            "Elementary Stream Priority Indicator", "mp2t.af.espi",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_ESPI_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_pcr_flag, {
            "PCR Flag", "mp2t.af.pcr_flag",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_PCR_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_opcr_flag, {
            "OPCR Flag", "mp2t.af.opcr_flag",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_OPCR_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_sp_flag, {
            "Splicing Point Flag", "mp2t.af.sp_flag",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_SP_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_tpd_flag, {
            "Transport Private Data Flag", "mp2t.af.tpd_flag",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_TPD_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_afe_flag, {
            "Adaptation Field Extension Flag", "mp2t.af.afe_flag",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_AFE_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_pcr, {
            "Program Clock Reference", "mp2t.af.pcr",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_opcr, {
            "Original Program Clock Reference", "mp2t.af.opcr",
            FT_UINT64, BASE_HEX, NULL, 0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_sc, {
            "Splice Countdown", "mp2t.af.sc",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_tpd_length, {
            "Transport Private Data Length", "mp2t.af.tpd_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_tpd, {
            "Transport Private Data", "mp2t.af.tpd",
            FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_length, {
            "Adaptation Field Extension Length", "mp2t.af.e_length",
            FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_ltw_flag, {
            "LTW Flag", "mp2t.af.e.ltw_flag",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_LTW_FLAG_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_pr_flag, {
            "Piecewise Rate Flag", "mp2t.af.e.pr_flag",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_PR_FLAG_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_ss_flag, {
            "Seamless Splice Flag", "mp2t.af.e.ss_flag",
            FT_UINT8, BASE_DEC, NULL, MP2T_AF_E_SS_FLAG_MASK, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_reserved, {
            "Reserved", "mp2t.af.e.reserved",
            FT_UINT8, BASE_DEC, NULL, 0x1F, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_reserved_bytes, {
            "Reserved", "mp2t.af.e.reserved_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_stuffing_bytes, {
            "Stuffing", "mp2t.af.stuffing_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_ltwv_flag, {
            "LTW Valid Flag", "mp2t.af.e.ltwv_flag",
            FT_UINT16, BASE_DEC, NULL, 0x8000, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_ltwo, {
            "LTW Offset", "mp2t.af.e.ltwo",
            FT_UINT16, BASE_DEC, NULL, 0x7FFF, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_pr_reserved, {
            "Reserved", "mp2t.af.e.pr_reserved",
            FT_UINT24, BASE_DEC, NULL, 0xC00000, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_pr, {
            "Piecewise Rate", "mp2t.af.e.pr",
            FT_UINT24, BASE_DEC, NULL, 0x3FFFFF, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_st, {
            "Splice Type", "mp2t.af.e.st",
            FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_dnau_32_30, {
            "DTS Next AU[32...30]", "mp2t.af.e.dnau_32_30",
            FT_UINT8, BASE_DEC, NULL, 0x0E, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_m_1, {
            "Marker Bit", "mp2t.af.e.m_1",
            FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_dnau_29_15, {
            "DTS Next AU[29...15]", "mp2t.af.e.dnau_29_15",
            FT_UINT16, BASE_DEC, NULL, 0xFFFE, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_m_2, {
            "Marker Bit", "mp2t.af.e.m_2",
            FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_dnau_14_0, {
            "DTS Next AU[14...0]", "mp2t.af.e.dnau_14_0",
            FT_UINT16, BASE_DEC, NULL, 0xFFFE, NULL, HFILL
        } } ,
        { &hf_mp2t_af_e_m_3, {
            "Marker Bit", "mp2t.af.e.m_3",
            FT_UINT16, BASE_DEC, NULL, 0x0001, NULL, HFILL
        } } ,
#if 0
        { &hf_mp2t_payload, {
            "Payload", "mp2t.payload",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
        } } ,
#endif
        { &hf_mp2t_stuff_bytes, {
            "Stuffing", "mp2t.stuff_bytes",
            FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL
        } },
        { &hf_mp2t_pointer, {
            "Pointer", "mp2t.pointer",
            FT_UINT8, BASE_DEC, NULL, 0x0, NULL, HFILL
        } },
        {  &hf_msg_fragments, {
            "Message fragments", "mp2t.msg.fragments",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_fragment, {
            "Message fragment", "mp2t.msg.fragment",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_fragment_overlap, {
            "Message fragment overlap", "mp2t.msg.fragment.overlap",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_fragment_overlap_conflicts, {
            "Message fragment overlapping with conflicting data",
            "mp2t.msg.fragment.overlap.conflicts",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_fragment_multiple_tails, {
            "Message has multiple tail fragments",
            "mp2t.msg.fragment.multiple_tails",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_fragment_too_long_fragment, {
            "Message fragment too long", "mp2t.msg.fragment.too_long_fragment",
            FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_fragment_error, {
            "Message defragmentation error", "mp2t.msg.fragment.error",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_fragment_count, {
            "Message fragment count", "mp2t.msg.fragment.count",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_reassembled_in, {
            "Reassembled in", "mp2t.msg.reassembled.in",
            FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_reassembled_length, {
            "Reassembled MP2T length", "mp2t.msg.reassembled.length",
            FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL
        } },
        {  &hf_msg_ts_packet_reassembled, {
            "MPEG TS Packet (reassembled)", "mp2t.ts_packet_reassembled",
            FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL
        } },
    };

    static gint *ett[] =
    {
        &ett_mp2t,
        &ett_mp2t_header,
        &ett_mp2t_af,
        &ett_mp2t_analysis,
        &ett_stuff,
        &ett_msg_fragment,
        &ett_msg_fragments
    };

    static ei_register_info ei[] = {
        { &ei_mp2t_pointer, { "mp2t.pointer_too_large", PI_MALFORMED, PI_ERROR, "Pointer value is too large", EXPFILL }},
        { &ei_mp2t_cc_drop, { "mp2t.cc.drop", PI_MALFORMED, PI_ERROR, "Detected missing TS frames", EXPFILL }},
        { &ei_mp2t_invalid_afc, { "mp2t.afc.invalid", PI_PROTOCOL, PI_WARN,
                                    "Adaptation Field Control contains an invalid value", EXPFILL }}
    };

    expert_module_t* expert_mp2t;

    proto_mp2t = proto_register_protocol("ISO/IEC 13818-1", "MP2T", "mp2t");

    mp2t_handle = register_dissector("mp2t", dissect_mp2t, proto_mp2t);

    proto_register_field_array(proto_mp2t, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_mp2t = expert_register_protocol(proto_mp2t);
    expert_register_field_array(expert_mp2t, ei, array_length(ei));

    mp2t_no_address_type = address_type_dissector_register("AT_MP2T_NONE", "No MP2T Address", none_addr_to_str, none_addr_str_len, NULL, NULL, none_addr_len, NULL, NULL);

    heur_subdissector_list = register_heur_dissector_list("mp2t.pid", proto_mp2t);
    /* Register init of processing of fragmented DEPI packets */
    register_init_routine(mp2t_init);
    register_cleanup_routine(mp2t_cleanup);
}



void
proto_reg_handoff_mp2t(void)
{
    heur_dissector_add("udp", heur_dissect_mp2t, "MP2T over UDP", "mp2t_udp", proto_mp2t, HEURISTIC_ENABLE);

    dissector_add_uint("rtp.pt", PT_MP2T, mp2t_handle);
    dissector_add_for_decode_as("tcp.port", mp2t_handle);
    dissector_add_for_decode_as("udp.port", mp2t_handle);
    heur_dissector_add("usb.bulk", heur_dissect_mp2t, "MP2T USB bulk endpoint", "mp2t_usb_bulk", proto_mp2t, HEURISTIC_ENABLE);
    dissector_add_uint("wtap_encap", WTAP_ENCAP_MPEG_2_TS, mp2t_handle);
    dissector_add_uint("l2tp.pw_type", L2TPv3_PROTOCOL_DOCSIS_DMPT, mp2t_handle);

    docsis_handle = find_dissector("docsis");
    mpeg_pes_handle = find_dissector("mpeg-pes");
    mpeg_sect_handle = find_dissector("mpeg_sect");
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
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
