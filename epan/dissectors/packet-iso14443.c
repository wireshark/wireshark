/* packet-iso14443.c
 * Routines for ISO14443 dissection
 * Copyright 2015-2016, Martin Kaiser <martin@kaiser.cx>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ISO14443 is a set of standards describing the communication between a
 * card reader and a contactless smartcard.
 *
 * This dissector handles the initialization messages defined in
 * ISO14443-3 and the activation and protocol messages from ISO14443-4
 *
 * The standards are available as "final committee drafts" from
 * http://wg8.de/wg8n1496_17n3613_Ballot_FCD14443-3.pdf
 * http://wg8.de/wg8n1344_17n3269_Ballot_FCD14443-4.pdf
 *
 * The pcap input format for this dissector is documented at
 * http://www.kaiser.cx/pcap-iso14443.html.
 */


#include "config.h"
#include <epan/packet.h>
#include <epan/expert.h>
#include <epan/decode_as.h>
#include <epan/conversation.h>
#include <epan/tfs.h>
#include <epan/reassemble.h>
#include <epan/crc16-tvb.h>

#include <wiretap/wtap.h>

#include <wsutil/pow2.h>

/* Proximity Integrated Circuit Card, i.e. the smartcard */
#define ADDR_PICC "PICC"
/* Proximity Coupling Device, i.e. the card reader */
#define ADDR_PCD  "PCD"

/* event byte in the PCAP ISO14443 pseudo-header */
#define ISO14443_EVT_DATA_PICC_TO_PCD              0xFF
#define ISO14443_EVT_DATA_PCD_TO_PICC              0xFE
#define ISO14443_EVT_FIELD_OFF                     0xFD
#define ISO14443_EVT_FIELD_ON                      0xFC
#define ISO14443_EVT_DATA_PICC_TO_PCD_CRC_DROPPED  0xFB
#define ISO14443_EVT_DATA_PCD_TO_PICC_CRC_DROPPED  0xFA

static const value_string iso14443_event[] = {
    { ISO14443_EVT_DATA_PICC_TO_PCD, "Data transfer PICC -> PCD" },
    { ISO14443_EVT_DATA_PCD_TO_PICC, "Data transfer PCD -> PICC" },
    { ISO14443_EVT_FIELD_ON,         "Field on" },
    { ISO14443_EVT_FIELD_OFF,        "Field off" },
    { ISO14443_EVT_DATA_PICC_TO_PCD_CRC_DROPPED,
        "Data transfer PICC -> PCD (CRC bytes were dropped)" },
    { ISO14443_EVT_DATA_PCD_TO_PICC_CRC_DROPPED,
        "Data transfer PCD -> PICC (CRC bytes were dropped)" },
    { 0, NULL }
};

#define IS_DATA_TRANSFER(e) \
    ((e)==ISO14443_EVT_DATA_PICC_TO_PCD || \
     (e)==ISO14443_EVT_DATA_PCD_TO_PICC || \
     (e)==ISO14443_EVT_DATA_PICC_TO_PCD_CRC_DROPPED || \
     (e)==ISO14443_EVT_DATA_PCD_TO_PICC_CRC_DROPPED)

typedef enum _iso14443_cmd_t {
    CMD_TYPE_WUPA,    /* REQA, WUPA or ATQA */
    CMD_TYPE_WUPB,    /* REQB, WUPB or ATQB */
    CMD_TYPE_HLTA,
    CMD_TYPE_UID,     /* anticollision or selection commands
                         and their answers */
    CMD_TYPE_ATS,     /* RATS or ATS */
    CMD_TYPE_ATTRIB,  /* Attrib or the answer to Attrib */
    CMD_TYPE_BLOCK,   /* I-, R- or S-blocks */
    CMD_TYPE_UNKNOWN
} iso14443_cmd_t;

static wmem_tree_t *transactions = NULL;

typedef struct _iso14443_transaction_t {
    guint32 rqst_frame;
    guint32 resp_frame;
    iso14443_cmd_t cmd;
} iso14443_transaction_t;

typedef enum _iso14443_type_t {
    ISO14443_A,
    ISO14443_B,
    ISO14443_UNKNOWN
} iso14443_type_t;

static const value_string iso14443_short_frame[] = {
    { 0x26 , "REQA" },
    { 0x52 , "WUPA" },
    { 0, NULL }
};

/* the bit rate definitions in the attrib message */
#define BITRATE_106  0x00
#define BITRATE_212  0x01
#define BITRATE_424  0x02
#define BITRATE_847  0x03

static const value_string iso14443_bitrates[] = {
    { BITRATE_106, "106 kbit/s" },
    { BITRATE_212, "212 kbit/s" },
    { BITRATE_424, "424 kbit/s" },
    { BITRATE_847, "827 kbit/s" },
    { 0, NULL }
};

/* convert a length code into the length it encodes
   code_to_len[x] is the length encoded by x
   this conversion is used for type A's FSCI and FSDI and for type B's
   maximum frame size */
static const guint16 code_to_len[] = {
    16, 24, 32, 40, 48, 64, 96, 128, 256, 512, 1024, 2048, 4096
};
#define LEN_CODE_MAX array_length(code_to_len)

/* the bits in the ATS' TO byte indicating which other bytes are transmitted */
#define HAVE_TC1 0x40
#define HAVE_TB1 0x20
#define HAVE_TA1 0x10

#define I_BLOCK_TYPE 0x00
#define R_BLOCK_TYPE 0x02
#define S_BLOCK_TYPE 0x03
static const value_string iso14443_block_type[] = {
    { I_BLOCK_TYPE , "I-block" },
    { R_BLOCK_TYPE , "R-block" },
    { S_BLOCK_TYPE , "S-block" },
    { 0, NULL }
};

#define S_CMD_DESELECT 0x00
#define S_CMD_WTX      0x03
#define S_CMD_NONE     0xFF

static const value_string iso14443_s_block_cmd[] = {
    { S_CMD_DESELECT , "Deselect" },
    { S_CMD_WTX , "WTX" },
    { 0, NULL }
};

static const true_false_string tfs_wupb_reqb = { "WUPB", "REQB" };
static const true_false_string tfs_compliant_not_compliant = { "Compliant", "Not compliant" };
static const true_false_string tfs_incomplete_complete = { "Incomplete", "Complete" };
static const true_false_string tfs_iso_propr = { "As defined in ISO14443-3", "Proprietary" };
static const true_false_string tfs_not_required_required = { "Not required", "Required" };
static const true_false_string tfs_nak_ack = { "NAK", "ACK" };

#define CT_BYTE 0x88

#define CRC_LEN 2

/* we'll only ever have a single circuit,
   only one card can be active at a time */
#define ISO14443_CIRCUIT_ID 0

void proto_register_iso14443(void);
void proto_reg_handoff_iso14443(void);

static int proto_iso14443 = -1;

static dissector_handle_t iso14443_handle;

static dissector_table_t iso14443_cmd_type_table;

static dissector_table_t iso14443_subdissector_table;

static int ett_iso14443 = -1;
static int ett_iso14443_hdr = -1;
static int ett_iso14443_msg = -1;
static int ett_iso14443_app_data = -1;
static int ett_iso14443_prot_inf = -1;
static int ett_iso14443_bit_rate = -1;
static int ett_iso14443_prot_type = -1;
static int ett_iso14443_ats_t0 = -1;
static int ett_iso14443_ats_ta1 = -1;
static int ett_iso14443_ats_tb1 = -1;
static int ett_iso14443_ats_tc1 = -1;
static int ett_iso14443_attr_p1 = -1;
static int ett_iso14443_attr_p2 = -1;
static int ett_iso14443_attr_p3 = -1;
static int ett_iso14443_attr_p4 = -1;
static int ett_iso14443_pcb = -1;
static int ett_iso14443_inf = -1;
static int ett_iso14443_frag = -1;
static int ett_iso14443_frags = -1;

static int hf_iso14443_hdr_ver = -1;
static int hf_iso14443_event = -1;
static int hf_iso14443_len_field = -1;
static int hf_iso14443_resp_to = -1;
static int hf_iso14443_resp_in = -1;
static int hf_iso14443_short_frame = -1;
static int hf_iso14443_atqa_rfu1 = -1;
static int hf_iso14443_atqa_rfu2 = -1;
static int hf_iso14443_propr_coding = -1;
static int hf_iso14443_uid_bits = -1;
static int hf_iso14443_uid_size = -1;
static int hf_iso14443_max_frame_size = -1;
static int hf_iso14443_bit_frame_anticoll = -1;
static int hf_iso14443_apf = -1;
static int hf_iso14443_afi = -1;
static int hf_iso14443_ext_atqb = -1;
/* if this is present but unset, we have a REQB */
static int hf_iso14443_wupb = -1;
static int hf_iso14443_n = -1;
static int hf_iso14443_atqb_start = -1;
static int hf_iso14443_app_data = -1;
static int hf_iso14443_num_afi_apps = -1;
static int hf_iso14443_total_num_apps = -1;
static int hf_iso14443_prot_inf = -1;
static int hf_iso14443_bit_rate_cap = -1;
static int hf_iso14443_same_bit_rate = -1;
static int hf_iso14443_picc_pcd_847 = -1;
static int hf_iso14443_picc_pcd_424 = -1;
static int hf_iso14443_picc_pcd_212 = -1;
static int hf_iso14443_pcd_picc_847 = -1;
static int hf_iso14443_pcd_picc_424 = -1;
static int hf_iso14443_pcd_picc_212 = -1;
static int hf_iso14443_max_frame_size_code = -1;
static int hf_iso14443_prot_type = -1;
static int hf_iso14443_min_tr2 = -1;
static int hf_iso14443_4_compl_atqb = -1;
static int hf_iso14443_fwi = -1;
static int hf_iso14443_sfgi = -1;
static int hf_iso14443_adc = -1;
static int hf_iso14443_nad_supported = -1;
static int hf_iso14443_cid_supported = -1;
static int hf_iso14443_hlta = -1;
static int hf_iso14443_sel = -1;
static int hf_iso14443_nvb = -1;
static int hf_iso14443_4_compl_sak = -1;
static int hf_iso14443_uid_complete = -1;
static int hf_iso14443_ct = -1;
static int hf_iso14443_uid_cln = -1;
static int hf_iso14443_bcc = -1;
static int hf_iso14443_rats_start = -1;
static int hf_iso14443_fsdi = -1;
static int hf_iso14443_fsd = -1;
static int hf_iso14443_cid = -1;
static int hf_iso14443_tl = -1;
static int hf_iso14443_t0 = -1;
static int hf_iso14443_tc1_transmitted = -1;
static int hf_iso14443_tb1_transmitted = -1;
static int hf_iso14443_ta1_transmitted = -1;
static int hf_iso14443_fsci = -1;
static int hf_iso14443_fsc = -1;
static int hf_iso14443_tc1 = -1;
static int hf_iso14443_tb1 = -1;
static int hf_iso14443_ta1 = -1;
static int hf_iso14443_same_d = -1;
static int hf_iso14443_ds8 = -1;
static int hf_iso14443_ds4 = -1;
static int hf_iso14443_ds2 = -1;
static int hf_iso14443_dr8 = -1;
static int hf_iso14443_dr4 = -1;
static int hf_iso14443_dr2 = -1;
static int hf_iso14443_hist_bytes = -1;
static int hf_iso14443_attrib_start = -1;
static int hf_iso14443_pupi = -1;
static int hf_iso14443_param1 = -1;
static int hf_iso14443_min_tr0 = -1;
static int hf_iso14443_min_tr1 = -1;
static int hf_iso14443_eof = -1;
static int hf_iso14443_sof = -1;
static int hf_iso14443_param2 = -1;
static int hf_iso14443_bitrate_picc_pcd = -1;
static int hf_iso14443_bitrate_pcd_picc = -1;
static int hf_iso14443_param3 = -1;
static int hf_iso14443_param4 = -1;
static int hf_iso14443_mbli = -1;
static int hf_iso14443_pcb = -1;
static int hf_iso14443_block_type = -1;
static int hf_iso14443_i_blk_chaining = -1;
static int hf_iso14443_cid_following = -1;
static int hf_iso14443_nad_following = -1;
static int hf_iso14443_nak = -1;
static int hf_iso14443_blk_num = -1;
static int hf_iso14443_s_blk_cmd = -1;
static int hf_iso14443_pwr_lvl_ind = -1;
static int hf_iso14443_wtxm = -1;
static int hf_iso14443_inf = -1;
static int hf_iso14443_frags = -1;
static int hf_iso14443_frag = -1;
static int hf_iso14443_frag_overlap = -1;
static int hf_iso14443_frag_overlap_conflicts = -1;
static int hf_iso14443_frag_multiple_tails = -1;
static int hf_iso14443_frag_too_long_frag = -1;
static int hf_iso14443_frag_err = -1;
static int hf_iso14443_frag_cnt = -1;
static int hf_iso14443_reass_in = -1;
static int hf_iso14443_reass_len = -1;
static int hf_iso14443_crc = -1;
static int hf_iso14443_crc_status = -1;

static int * const bit_rate_fields[] = {
    &hf_iso14443_same_bit_rate,
    &hf_iso14443_picc_pcd_847,
    &hf_iso14443_picc_pcd_424,
    &hf_iso14443_picc_pcd_212,
    &hf_iso14443_pcd_picc_847,
    &hf_iso14443_pcd_picc_424,
    &hf_iso14443_pcd_picc_212,
    NULL
};

static int * const ats_ta1_fields[] = {
    &hf_iso14443_same_d,
    &hf_iso14443_ds8,
    &hf_iso14443_ds4,
    &hf_iso14443_ds2,
    &hf_iso14443_dr8,
    &hf_iso14443_dr4,
    &hf_iso14443_dr2,
    NULL
};

static expert_field ei_iso14443_unknown_cmd = EI_INIT;
static expert_field ei_iso14443_wrong_crc = EI_INIT;
static expert_field ei_iso14443_uid_inval_size = EI_INIT;

static reassembly_table i_block_reassembly_table;

static const fragment_items i_block_frag_items = {
    &ett_iso14443_frag,
    &ett_iso14443_frags,

    &hf_iso14443_frags,
    &hf_iso14443_frag,
    &hf_iso14443_frag_overlap,
    &hf_iso14443_frag_overlap_conflicts,
    &hf_iso14443_frag_multiple_tails,
    &hf_iso14443_frag_too_long_frag,
    &hf_iso14443_frag_err,
    &hf_iso14443_frag_cnt,

    &hf_iso14443_reass_in,
    &hf_iso14443_reass_len,
    NULL,
    "I-block fragments"
};


static int
dissect_iso14443_cmd_type_wupa(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data _U_)
{
    proto_item *ti = proto_tree_get_parent(tree);
    gint offset = 0;
    guint8 uid_bits, uid_size = 0;

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        const gchar *sf_str;
        sf_str = try_val_to_str(
            tvb_get_guint8(tvb, 0), iso14443_short_frame);
        proto_tree_add_item(tree, hf_iso14443_short_frame,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        if (sf_str) {
            proto_item_append_text(ti, ": %s", sf_str);
            col_set_str(pinfo->cinfo, COL_INFO, sf_str);
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        guint16 atqa;
        proto_item *pi_uid;

        atqa = tvb_get_letohs(tvb, offset);
        col_set_str(pinfo->cinfo, COL_INFO, "ATQA");
        proto_item_append_text(ti, ": ATQA 0x%04x", atqa);

        proto_tree_add_item(tree, hf_iso14443_atqa_rfu1,
                tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_iso14443_propr_coding,
                tvb, offset, 2, ENC_LITTLE_ENDIAN);

        uid_bits = (atqa & 0xC0) >> 6;
        if (uid_bits == 0x00)
            uid_size = 4;
        else if (uid_bits == 0x01)
            uid_size = 7;
        else if (uid_bits == 0x02)
            uid_size = 10;

        pi_uid = proto_tree_add_item(tree, hf_iso14443_uid_bits,
                tvb, offset, 2, ENC_LITTLE_ENDIAN);
        if (uid_size != 0) {
            proto_item *pi_uid_size;
            pi_uid_size = proto_tree_add_uint(tree, hf_iso14443_uid_size,
                    tvb, offset+1, 1, uid_size);
            proto_item_set_generated(pi_uid_size);
        }
        else {
            expert_add_info(pinfo, pi_uid, &ei_iso14443_uid_inval_size);
        }

        proto_tree_add_item(tree, hf_iso14443_atqa_rfu2,
                tvb, offset, 2, ENC_LITTLE_ENDIAN);
        proto_tree_add_item(tree, hf_iso14443_bit_frame_anticoll,
                tvb, offset, 2, ENC_LITTLE_ENDIAN);

        offset += 2;
    }

    return offset;
}


static int dissect_iso14443_atqb(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree, gboolean crc_dropped)
{
    proto_item *ti = proto_tree_get_parent(tree);
    proto_item *app_data_it, *prot_inf_it, *prot_type_it;
    proto_tree *app_data_tree, *prot_inf_tree, *prot_type_tree;
    gint app_data_offset, rem_len;
    gboolean nad_supported, cid_supported;
    guint8 max_frame_size_code, fwi;
    proto_item *pi;
    gboolean iso14443_adc;
    guint8 prot_inf_len = 0;

    col_set_str(pinfo->cinfo, COL_INFO, "ATQB");
    proto_item_append_text(ti, ": ATQB");
    proto_tree_add_item(tree, hf_iso14443_atqb_start,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    proto_tree_add_item(tree, hf_iso14443_pupi,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    app_data_offset = offset;
    app_data_it = proto_tree_add_item(tree, hf_iso14443_app_data,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    /* we should not link the protocol info length to the "extended
       ATQB supported" field in the WUPB - even if the PCD supports
       extended ATQB, the PICC may still send a basic one */
    rem_len = tvb_reported_length_remaining(tvb, offset);
    if (!crc_dropped) {
        if (rem_len == 5 || rem_len == 6)
            prot_inf_len = rem_len - 2;
    }
    else if (rem_len == 3 || rem_len == 4)
        prot_inf_len = rem_len;
    /* XXX - exception if (prot_inf_len==0) */

    prot_inf_it = proto_tree_add_item(tree, hf_iso14443_prot_inf,
            tvb, offset, prot_inf_len, ENC_BIG_ENDIAN);
    prot_inf_tree = proto_item_add_subtree(
            prot_inf_it, ett_iso14443_prot_inf);
    /* bit rate info are applicable only if b4 is 0 */
    if (!(tvb_get_guint8(tvb, offset) & 0x08)) {
        proto_tree_add_bitmask_with_flags(prot_inf_tree, tvb, offset,
                hf_iso14443_bit_rate_cap, ett_iso14443_bit_rate,
                bit_rate_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);
    }
    offset++;
    max_frame_size_code = (tvb_get_guint8(tvb, offset) & 0xF0) >> 4;
    proto_tree_add_uint_bits_format_value(prot_inf_tree,
            hf_iso14443_max_frame_size_code,
            tvb, offset*8, 4, max_frame_size_code, ENC_BIG_ENDIAN, "%d",
            max_frame_size_code);
    if (max_frame_size_code < LEN_CODE_MAX) {
        pi = proto_tree_add_uint(prot_inf_tree, hf_iso14443_max_frame_size,
                tvb, offset, 1, code_to_len[max_frame_size_code]);
        proto_item_set_generated(pi);
    }
    prot_type_it = proto_tree_add_item(prot_inf_tree, hf_iso14443_prot_type,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    prot_type_tree = proto_item_add_subtree(
            prot_type_it, ett_iso14443_prot_type);
    proto_tree_add_item(prot_type_tree, hf_iso14443_min_tr2,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(prot_type_tree, hf_iso14443_4_compl_atqb,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    fwi = (tvb_get_guint8(tvb, offset) & 0xF0) >> 4;
    proto_tree_add_uint_bits_format_value(prot_inf_tree, hf_iso14443_fwi,
            tvb, offset*8, 4, fwi, ENC_BIG_ENDIAN, "%d", fwi);
    iso14443_adc = tvb_get_guint8(tvb, offset) & 0x04;
    proto_tree_add_item(prot_inf_tree, hf_iso14443_adc,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    if (iso14443_adc) {
        app_data_tree = proto_item_add_subtree(
                app_data_it, ett_iso14443_app_data);
        proto_tree_add_item(app_data_tree, hf_iso14443_afi,
                tvb, app_data_offset, 1, ENC_BIG_ENDIAN);
        app_data_offset++;
        /* XXX - CRC_B app */
        app_data_offset += 2;
        proto_tree_add_item(app_data_tree, hf_iso14443_num_afi_apps,
                tvb, app_data_offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(app_data_tree, hf_iso14443_total_num_apps,
                tvb, app_data_offset, 1, ENC_BIG_ENDIAN);
    }

    nad_supported = tvb_get_guint8(tvb, offset) & 0x02;
    proto_tree_add_boolean_bits_format_value(prot_inf_tree,
            hf_iso14443_nad_supported, tvb, 8*offset+6, 1, nad_supported,
            ENC_BIG_ENDIAN, "%s", tfs_get_string(nad_supported, &tfs_supported_not_supported));
    cid_supported = tvb_get_guint8(tvb, offset) & 0x01;
    proto_tree_add_boolean_bits_format_value(prot_inf_tree,
            hf_iso14443_cid_supported, tvb, 8*offset+7, 1, cid_supported,
            ENC_BIG_ENDIAN, "%s", tfs_get_string(cid_supported, &tfs_supported_not_supported));
    offset++;

    /* XXX - extended ATQB */
    if (prot_inf_len>3)
        offset++;

    if (!crc_dropped) {
        proto_tree_add_checksum(tree, tvb, offset,
                hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                 crc16_ccitt_tvb_offset(tvb, 0, offset),
                ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += CRC_LEN;
    }

    return offset;
}


static int
dissect_iso14443_cmd_type_wupb(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    proto_item *ti = proto_tree_get_parent(tree);
    gboolean crc_dropped = (gboolean)GPOINTER_TO_UINT(data);
    gint offset = 0;
    guint8 param;
    const char *msg_type;

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        proto_tree_add_item(tree, hf_iso14443_apf,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso14443_afi,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        param = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_iso14443_ext_atqb,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(tree, hf_iso14443_wupb,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        msg_type = tfs_get_string(param & 0x08, &tfs_wupb_reqb);
        col_set_str(pinfo->cinfo, COL_INFO, msg_type);
        proto_item_append_text(ti, ": %s", msg_type);
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_n,
                tvb, offset*8+5, 3, pow2(guint32, param&0x07),
                ENC_BIG_ENDIAN, "%u", pow2(guint32, param&0x07));
        offset++;

        if (!crc_dropped) {
            proto_tree_add_checksum(tree, tvb, offset,
                    hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                    crc16_ccitt_tvb_offset(tvb, 0, offset),
                    ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
            offset += CRC_LEN;
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        offset = dissect_iso14443_atqb(tvb, offset, pinfo, tree, crc_dropped);
    }

    return offset;
}


static int
dissect_iso14443_cmd_type_hlta(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    gboolean crc_dropped = (gboolean)GPOINTER_TO_UINT(data);
    proto_item *ti = proto_tree_get_parent(tree);
    gint offset = 0;

    col_set_str(pinfo->cinfo, COL_INFO, "HLTA");
    proto_item_append_text(ti, ": HLTA");
    proto_tree_add_item(tree, hf_iso14443_hlta,
            tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;

    if (!crc_dropped) {
        proto_tree_add_checksum(tree, tvb, offset,
                hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                crc16_iso14443a_tvb_offset(tvb, 0, offset),
                ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += CRC_LEN;
    }

    return offset;
}


static int dissect_iso14443_uid_part(
        tvbuff_t *tvb, gint offset, packet_info *pinfo _U_, proto_tree *tree)
{
    guint8 uid_len = 4;

    if (tvb_get_guint8(tvb, offset) == CT_BYTE) {
        proto_tree_add_item(tree, hf_iso14443_ct, tvb, offset, 1, ENC_NA);
        offset++;
        uid_len = 3;
    }

    proto_tree_add_item(tree, hf_iso14443_uid_cln, tvb, offset, uid_len, ENC_NA);
    offset += uid_len;
    proto_tree_add_item(tree, hf_iso14443_bcc, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    return offset;
}


static int
dissect_iso14443_cmd_type_uid(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    gboolean crc_dropped = (gboolean)GPOINTER_TO_UINT(data);
    proto_item *ti = proto_tree_get_parent(tree);
    gint offset = 0;

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        proto_tree_add_item(tree, hf_iso14443_sel,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso14443_nvb,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        if (tvb_reported_length_remaining(tvb, offset) == 0) {
            col_set_str(pinfo->cinfo, COL_INFO, "Anticollision");
            proto_item_append_text(ti, ": Anticollision");
        }
        else {
            col_set_str(pinfo->cinfo, COL_INFO, "Select");
            proto_item_append_text(ti, ": Select");
            offset = dissect_iso14443_uid_part(tvb, offset, pinfo, tree);
            if (!crc_dropped) {
                proto_tree_add_checksum(tree, tvb, offset,
                        hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                        crc16_iso14443a_tvb_offset(tvb, 0, offset),
                        ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
                offset += CRC_LEN;
            }
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        if (tvb_reported_length_remaining(tvb, offset) <= 3) {
            col_set_str(pinfo->cinfo, COL_INFO, "SAK");
            proto_item_append_text(ti, ": SAK");
            proto_tree_add_item(tree, hf_iso14443_4_compl_sak,
                tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(tree, hf_iso14443_uid_complete,
                tvb, offset, 1, ENC_BIG_ENDIAN);
            offset++;
            if (!crc_dropped) {
                proto_tree_add_checksum(tree, tvb, offset,
                        hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                        crc16_iso14443a_tvb_offset(tvb, 0, offset),
                        ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
                offset += CRC_LEN;
            }
        }
        else if (tvb_reported_length_remaining(tvb, offset) == 5) {
            col_set_str(pinfo->cinfo, COL_INFO, "UID");
            offset = dissect_iso14443_uid_part(tvb, offset, pinfo, tree);
        }
    }

    return offset;
}


static int dissect_iso14443_ats(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree, gboolean crc_dropped)
{
    proto_item *ti = proto_tree_get_parent(tree);
    conversation_t *conv;
    guint8 tl, t0 = 0, fsci, fwi, sfgi;
    proto_item *t0_it, *tb1_it, *tc1_it, *pi;
    proto_tree *t0_tree, *tb1_tree, *tc1_tree;
    gint offset_tl, hist_len;
    gboolean nad_supported, cid_supported;

    col_set_str(pinfo->cinfo, COL_INFO, "ATS");
    proto_item_append_text(ti, ": ATS");

    conv = conversation_new_by_id(pinfo->num, CONVERSATION_ISO14443, ISO14443_CIRCUIT_ID);
    conversation_add_proto_data(conv, proto_iso14443, GUINT_TO_POINTER((guint)ISO14443_A));

    offset_tl = offset;
    tl = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_iso14443_tl,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* the length in TL includes the TL byte itself */
    if (tl >= 2) {
        t0 = tvb_get_guint8(tvb, offset);
        t0_it = proto_tree_add_item(tree, hf_iso14443_t0,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        t0_tree = proto_item_add_subtree(t0_it, ett_iso14443_ats_t0);
        proto_tree_add_item(t0_tree, hf_iso14443_tc1_transmitted,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(t0_tree, hf_iso14443_tb1_transmitted,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(t0_tree, hf_iso14443_ta1_transmitted,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        fsci = t0 & 0x0F;
        proto_tree_add_item(t0_tree, hf_iso14443_fsci,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        if (fsci < LEN_CODE_MAX) {
            pi = proto_tree_add_uint(t0_tree, hf_iso14443_fsc,
                    tvb, offset, 1, code_to_len[fsci]);
            proto_item_set_generated(pi);
        }
        offset++;
    }
    if (t0 & HAVE_TA1) {
        proto_tree_add_bitmask_with_flags(tree, tvb, offset,
                hf_iso14443_ta1, ett_iso14443_ats_ta1,
                ats_ta1_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        offset++;
    }
    if (t0 & HAVE_TB1) {
        tb1_it = proto_tree_add_item(tree, hf_iso14443_tb1,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        tb1_tree = proto_item_add_subtree(tb1_it, ett_iso14443_ats_tb1);
        fwi = (tvb_get_guint8(tvb, offset) & 0xF0) >> 4;
        proto_tree_add_uint_bits_format_value(tb1_tree, hf_iso14443_fwi,
                tvb, offset*8, 4, fwi, ENC_BIG_ENDIAN, "%d", fwi);
        sfgi = tvb_get_guint8(tvb, offset) & 0x0F;
        proto_tree_add_uint_bits_format_value(tb1_tree, hf_iso14443_sfgi,
                tvb, offset*8+4, 4, sfgi, ENC_BIG_ENDIAN, "%d", sfgi);
        offset++;
    }
    if (t0 & HAVE_TC1) {
        tc1_it = proto_tree_add_item(tree, hf_iso14443_tc1,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        tc1_tree = proto_item_add_subtree(tc1_it, ett_iso14443_ats_tc1);

        cid_supported = tvb_get_guint8(tvb, offset) & 0x02;
        proto_tree_add_boolean_bits_format_value(tc1_tree,
                hf_iso14443_cid_supported, tvb, 8*offset+6, 1, cid_supported,
                ENC_BIG_ENDIAN, "%s", tfs_get_string(cid_supported, &tfs_supported_not_supported));
        nad_supported = tvb_get_guint8(tvb, offset) & 0x01;
        proto_tree_add_boolean_bits_format_value(tc1_tree,
                hf_iso14443_nad_supported, tvb, 8*offset+7, 1, nad_supported,
                ENC_BIG_ENDIAN, "%s", tfs_get_string(nad_supported, &tfs_supported_not_supported));
        offset++;
    }
    hist_len = tl - (offset - offset_tl);
    if (hist_len > 0) {
        proto_tree_add_item(tree, hf_iso14443_hist_bytes,
                tvb, offset, hist_len, ENC_NA);
        offset += hist_len;
    }
    if (!crc_dropped) {
        proto_tree_add_checksum(tree, tvb, offset,
                hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                crc16_iso14443a_tvb_offset(tvb, 0, offset),
                ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += CRC_LEN;
    }

    return offset;
}


static int
dissect_iso14443_cmd_type_ats(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    gboolean crc_dropped = (gboolean)GPOINTER_TO_UINT(data);
    proto_item *ti = proto_tree_get_parent(tree);
    gint offset = 0;
    guint8 fsdi, cid;
    proto_item *pi;

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        col_set_str(pinfo->cinfo, COL_INFO, "RATS");
        proto_item_append_text(ti, ": RATS");

        proto_tree_add_item(tree, hf_iso14443_rats_start,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        fsdi = tvb_get_guint8(tvb, offset) >> 4;
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_fsdi,
                tvb, offset*8, 4, fsdi, ENC_BIG_ENDIAN, "%d", fsdi);
        if (fsdi < LEN_CODE_MAX) {
            pi = proto_tree_add_uint(tree, hf_iso14443_fsd,
                    tvb, offset, 1, code_to_len[fsdi]);
            proto_item_set_generated(pi);
        }
        cid = tvb_get_guint8(tvb, offset) & 0x0F;
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_cid,
                tvb, offset*8+4, 4, cid, ENC_BIG_ENDIAN, "%d", cid);
        offset++;
        if (!crc_dropped) {
            proto_tree_add_checksum(tree, tvb, offset,
                    hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                    crc16_iso14443a_tvb_offset(tvb, 0, offset),
                    ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
            offset += CRC_LEN;
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        offset = dissect_iso14443_ats(tvb, offset, pinfo, tree, crc_dropped);
    }

    return offset;
}


static int dissect_iso14443_attrib(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree, gboolean crc_dropped)
{
    proto_item *ti = proto_tree_get_parent(tree);
    proto_item *p1_it, *p2_it, *p3_it, *p4_it, *pi;
    proto_tree *p1_tree, *p2_tree, *p3_tree, *p4_tree;
    guint8 max_frame_size_code, cid;
    gint hl_inf_len;

    col_set_str(pinfo->cinfo, COL_INFO, "Attrib");
    proto_item_append_text(ti, ": Attrib");

    proto_tree_add_item(tree, hf_iso14443_attrib_start,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_iso14443_pupi,
            tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    p1_it = proto_tree_add_item(tree, hf_iso14443_param1,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    p1_tree = proto_item_add_subtree( p1_it, ett_iso14443_attr_p1);
    proto_tree_add_item(p1_tree, hf_iso14443_min_tr0,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(p1_tree, hf_iso14443_min_tr1,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(p1_tree, hf_iso14443_eof,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(p1_tree, hf_iso14443_sof,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    p2_it = proto_tree_add_item(tree, hf_iso14443_param2,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    p2_tree = proto_item_add_subtree( p2_it, ett_iso14443_attr_p2);
    proto_tree_add_item(p2_tree, hf_iso14443_bitrate_picc_pcd,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(p2_tree, hf_iso14443_bitrate_pcd_picc,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    max_frame_size_code = tvb_get_guint8(tvb, offset) & 0x0F;
    proto_tree_add_uint_bits_format_value(p2_tree,
            hf_iso14443_max_frame_size_code,
            tvb, offset*8+4, 4, max_frame_size_code, ENC_BIG_ENDIAN, "%d",
            max_frame_size_code);
    if (max_frame_size_code < LEN_CODE_MAX) {
        pi = proto_tree_add_uint(p2_tree, hf_iso14443_max_frame_size,
                tvb, offset, 1, code_to_len[max_frame_size_code]);
        proto_item_set_generated(pi);
    }
    offset++;

    p3_it = proto_tree_add_item(tree, hf_iso14443_param3,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    p3_tree = proto_item_add_subtree(p3_it, ett_iso14443_attr_p3);
    proto_tree_add_item(p3_tree, hf_iso14443_min_tr2,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(p3_tree, hf_iso14443_4_compl_atqb,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    p4_it = proto_tree_add_item(tree, hf_iso14443_param4,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    p4_tree = proto_item_add_subtree(p4_it, ett_iso14443_attr_p4);
    cid = tvb_get_guint8(tvb, offset) & 0x0F;
    proto_tree_add_uint_bits_format_value(p4_tree, hf_iso14443_cid,
            tvb, offset*8+4, 4, cid, ENC_BIG_ENDIAN, "%d", cid);
    offset++;

    hl_inf_len = crc_dropped ?
        tvb_reported_length_remaining(tvb, offset) :
        tvb_reported_length_remaining(tvb, offset) - CRC_LEN;
    if (hl_inf_len > 0) {
        offset += hl_inf_len;
    }
    if (!crc_dropped) {
        proto_tree_add_checksum(tree, tvb, offset,
                hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                crc16_ccitt_tvb_offset(tvb, 0, offset),
                ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
        offset += CRC_LEN;
    }

    return offset;
}


static int
dissect_iso14443_cmd_type_attrib(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    gboolean crc_dropped = (gboolean)GPOINTER_TO_UINT(data);
    proto_item *ti = proto_tree_get_parent(tree);
    gint offset = 0;
    guint8 mbli, cid;
    gint hl_resp_len;
    conversation_t *conv;

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        offset = dissect_iso14443_attrib(
                tvb, offset, pinfo, tree, crc_dropped);
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        col_set_str(pinfo->cinfo, COL_INFO, "Response to Attrib");
        proto_item_append_text(ti, ": Response to Attrib");

        conv = conversation_new_by_id(pinfo->num, CONVERSATION_ISO14443, ISO14443_CIRCUIT_ID);
        conversation_add_proto_data(conv, proto_iso14443, GUINT_TO_POINTER((guint)ISO14443_B));

        mbli = tvb_get_guint8(tvb, offset) >> 4;
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_mbli,
                tvb, offset*8, 4, mbli, ENC_BIG_ENDIAN, "%d", mbli);
        cid = tvb_get_guint8(tvb, offset) & 0x0F;
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_cid,
                tvb, offset*8+4, 4, cid, ENC_BIG_ENDIAN, "%d", cid);
        offset++;

        hl_resp_len = crc_dropped ?
            tvb_reported_length_remaining(tvb, offset) :
            tvb_reported_length_remaining(tvb, offset) - CRC_LEN;
        if (hl_resp_len > 0) {
            offset += hl_resp_len;
        }

        if (!crc_dropped) {
            proto_tree_add_checksum(tree, tvb, offset,
                    hf_iso14443_crc, hf_iso14443_crc_status, &ei_iso14443_wrong_crc, pinfo,
                    crc16_ccitt_tvb_offset(tvb, 0, offset),
                    ENC_LITTLE_ENDIAN, PROTO_CHECKSUM_VERIFY);
            offset += CRC_LEN;
        }
    }

    return offset;
}


static int
dissect_iso14443_cmd_type_block(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    gboolean crc_dropped = (gboolean)GPOINTER_TO_UINT(data);
    proto_item *ti = proto_tree_get_parent(tree);
    gint offset = 0;
    guint8 pcb, block_type;
    const gchar *bt_str;
    proto_item *pcb_ti, *inf_ti;
    proto_tree *pcb_tree, *inf_tree;
    gboolean has_cid, has_nad = FALSE;
    guint8 s_cmd = S_CMD_NONE;
    guint8 inf_len;

    pcb = tvb_get_guint8(tvb, offset);
    block_type = (pcb & 0xC0) >> 6;
    bt_str = try_val_to_str(block_type, iso14443_block_type);
    if (bt_str) {
        proto_item_append_text(ti, ": %s", bt_str);
        col_set_str(pinfo->cinfo, COL_INFO, bt_str);
    }
    has_cid = ((pcb & 0x08) != 0);

    pcb_ti = proto_tree_add_item(tree, hf_iso14443_pcb,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    pcb_tree = proto_item_add_subtree(pcb_ti, ett_iso14443_pcb);
    proto_tree_add_item(pcb_tree, hf_iso14443_block_type,
            tvb, offset, 1, ENC_BIG_ENDIAN);

    switch (block_type) {
        case I_BLOCK_TYPE:
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                    (pcb & 0x10) ? "Chaining" : "No chaining");
            proto_tree_add_item(pcb_tree, hf_iso14443_i_blk_chaining,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcb_tree, hf_iso14443_cid_following,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            has_nad = ((pcb & 0x40) != 0);
            proto_tree_add_item(pcb_tree, hf_iso14443_nad_following,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "Block number %d", pcb & 0x01);
            proto_tree_add_item(pcb_tree, hf_iso14443_blk_num,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        case R_BLOCK_TYPE:
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                    tfs_get_string(pcb & 0x10, &tfs_nak_ack));
            proto_tree_add_item(pcb_tree, hf_iso14443_nak,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            proto_tree_add_item(pcb_tree, hf_iso14443_cid_following,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, NULL,
                    "Block number %d", pcb & 0x01);
            proto_tree_add_item(pcb_tree, hf_iso14443_blk_num,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        case S_BLOCK_TYPE:
            s_cmd = (pcb & 0x30) >> 4;
            proto_tree_add_item(pcb_tree, hf_iso14443_s_blk_cmd,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            col_append_sep_str(pinfo->cinfo, COL_INFO, NULL,
                    val_to_str(s_cmd, iso14443_s_block_cmd,
                        "Unknown (0x%02x)"));
            proto_tree_add_item(pcb_tree, hf_iso14443_cid_following,
                    tvb, offset, 1, ENC_BIG_ENDIAN);
            break;

        default:
            /* Report an error? b8 = 0, b7 = 1 */
            break;
    }
    offset++;

    if (has_cid)
        offset++;
    if (has_nad)
        offset++;

    switch (block_type) {
        case I_BLOCK_TYPE:
            inf_len = crc_dropped ?
                tvb_reported_length_remaining(tvb, offset) :
                tvb_reported_length_remaining(tvb, offset) - 2;
            break;

        /* R-blocks have no payload */

        case S_BLOCK_TYPE:
            inf_len = 1;
            break;

        default:
            inf_len = 0;
            break;

    }

    if (inf_len > 0) {
        inf_ti = proto_tree_add_item(tree, hf_iso14443_inf,
                tvb, offset, inf_len, ENC_NA);
        if (block_type == S_BLOCK_TYPE) {
            if (s_cmd == S_CMD_WTX) {
                inf_tree = proto_item_add_subtree(inf_ti, ett_iso14443_inf);
                if (pinfo->p2p_dir == P2P_DIR_RECV) {
                    proto_tree_add_item(inf_tree, hf_iso14443_pwr_lvl_ind,
                            tvb, offset, 1, ENC_BIG_ENDIAN);
                }
                proto_tree_add_item(inf_tree, hf_iso14443_wtxm,
                        tvb, offset, 1, ENC_BIG_ENDIAN);
            }
        }

        if (block_type == I_BLOCK_TYPE) {
            fragment_head *frag_msg;
            tvbuff_t *inf_tvb, *payload_tvb;

            /* see the comment in dissect_dvbci_tpdu (packet-dvbci.c) */
            inf_tvb = tvb_new_subset_length(tvb, offset, inf_len);
            frag_msg = fragment_add_seq_next(&i_block_reassembly_table,
                    inf_tvb, 0, pinfo, 0, NULL, inf_len,
                    (pcb & 0x10) ? 1 : 0);

            payload_tvb = process_reassembled_data(inf_tvb, 0, pinfo,
                    "Reassembled APDU", frag_msg,
                    &i_block_frag_items, NULL, tree);

            if (payload_tvb) {
                if (!dissector_try_payload_new(iso14443_subdissector_table,
                            payload_tvb, pinfo, tree, TRUE, NULL)) {
                    call_data_dissector(payload_tvb, pinfo, tree);
                }
            }
        }

        offset += inf_len;
    }

    if (!crc_dropped) {
        iso14443_type_t t = ISO14443_UNKNOWN;
        conversation_t *conv;
        guint32 computed_checksum = 0;
        guint flags = PROTO_CHECKSUM_NO_FLAGS;

        conv = find_conversation_by_id(pinfo->num, CONVERSATION_ISO14443, ISO14443_CIRCUIT_ID);
        if (conv)
            t = (iso14443_type_t)GPOINTER_TO_UINT(conversation_get_proto_data(conv, proto_iso14443));

        if (t == ISO14443_A) {
            computed_checksum = crc16_iso14443a_tvb_offset(tvb, 0, offset);
            flags |= PROTO_CHECKSUM_VERIFY;
        }
        else if (t == ISO14443_B) {
            computed_checksum = crc16_ccitt_tvb_offset(tvb, 0, offset);
            flags |= PROTO_CHECKSUM_VERIFY;
        }

        proto_tree_add_checksum(tree, tvb, offset,
                    hf_iso14443_crc, hf_iso14443_crc_status,
                    &ei_iso14443_wrong_crc, pinfo, computed_checksum,
                    ENC_LITTLE_ENDIAN, flags);
        offset += CRC_LEN;
    }

    return offset;
}


static gint
iso14443_set_addrs(guint8 event, packet_info *pinfo)
{
    if (!IS_DATA_TRANSFER(event))
        return -1;

    /* pinfo->p2p_dir is from the perspective of the card reader,
       like in iso7816
       i.e sent is from reader to card, received is from card to reader */
    if (event == ISO14443_EVT_DATA_PCD_TO_PICC ||
            event == ISO14443_EVT_DATA_PCD_TO_PICC_CRC_DROPPED) {

        set_address(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_PCD)+1, ADDR_PCD);
        set_address(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_PICC)+1 , ADDR_PICC);

        pinfo->p2p_dir = P2P_DIR_SENT;
    }
    else {
        set_address(&pinfo->src, AT_STRINGZ,
                (int)strlen(ADDR_PICC)+1 , ADDR_PICC);
        set_address(&pinfo->dst, AT_STRINGZ,
                (int)strlen(ADDR_PCD)+1, ADDR_PCD);

        pinfo->p2p_dir = P2P_DIR_RECV;
    }

    return 1;
}


static inline gboolean
iso14443_block_pcb(guint8 byte)
{
    if ((byte & 0xE2) == 0x02) {
        /* I-block */
        return TRUE;
    }
    else if ((byte & 0xE6) == 0xA2) {
        /* R-block */
        return TRUE;
    }
    else if ((byte & 0xC7) == 0xC2) {
        /* S-block */
        return TRUE;
    }

    return FALSE;
}


static iso14443_transaction_t *
iso14443_get_transaction(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_item *it;
    wmem_tree_key_t key[3];
    iso14443_transaction_t *iso14443_trans = NULL;
    /* Is the current message a Waiting-Time-Extension request or response? */
    gboolean wtx = (tvb_get_guint8(tvb, 0) & 0xF7) == 0xF2;

    /* When going backwards from the current message, we want to link wtx
       messages only to other wtx messages (and non-wtx messages to non-wtx,
       respectively). For this to work, the wtx flag must be the first
       component of the key. */
    key[0].length = 1;
    key[0].key = &wtx;
    key[1].length = 1;
    key[1].key = &pinfo->num;
    key[2].length = 0;
    key[2].key = NULL;

    /* Is this a request message? WTX requests are sent by the PICC, all
       other requests are sent by the PCD. */
    if (((pinfo->p2p_dir == P2P_DIR_SENT) && !wtx) ||
        ((pinfo->p2p_dir == P2P_DIR_RECV) && wtx)) {
        if (PINFO_FD_VISITED(pinfo)) {
            iso14443_trans =
                (iso14443_transaction_t *)wmem_tree_lookup32_array(
                    transactions, key);
            if (iso14443_trans && iso14443_trans->rqst_frame==pinfo->num &&
                    iso14443_trans->resp_frame!=0) {
               it = proto_tree_add_uint(tree, hf_iso14443_resp_in,
                       NULL, 0, 0, iso14443_trans->resp_frame);
               proto_item_set_generated(it);
            }
        }
        else {
            iso14443_trans =
                wmem_new(wmem_file_scope(), iso14443_transaction_t);
            iso14443_trans->rqst_frame = pinfo->num;
            iso14443_trans->resp_frame = 0;
            iso14443_trans->cmd = CMD_TYPE_UNKNOWN;
            wmem_tree_insert32_array(transactions, key, (void *)iso14443_trans);
        }
    }
    else if (((pinfo->p2p_dir == P2P_DIR_SENT) && wtx) ||
        ((pinfo->p2p_dir == P2P_DIR_RECV) && !wtx)) {
        iso14443_trans = (iso14443_transaction_t *)wmem_tree_lookup32_array_le(
                transactions, key);
        if (iso14443_trans && iso14443_trans->resp_frame==0) {
            /* there's a pending request, this packet is the response */
            iso14443_trans->resp_frame = pinfo->num;
        }

        if (iso14443_trans && iso14443_trans->resp_frame == pinfo->num) {
            it = proto_tree_add_uint(tree, hf_iso14443_resp_to,
                    NULL, 0, 0, iso14443_trans->rqst_frame);
            proto_item_set_generated(it);
        }
    }

    return iso14443_trans;
}


static iso14443_cmd_t iso14443_get_cmd_type(
        tvbuff_t *tvb, packet_info *pinfo, iso14443_transaction_t *trans)
{
    guint8 first_byte;

    first_byte = tvb_get_guint8(tvb, 0);

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        if (tvb_reported_length(tvb) == 1) {
            return CMD_TYPE_WUPA;
        }
        else if (first_byte == 0x05) {
            return CMD_TYPE_WUPB;
        }
        else if (first_byte == 0x50) {
            return CMD_TYPE_HLTA;
        }
        else if (first_byte == 0x1D) {
            return CMD_TYPE_ATTRIB;
        }
        else if (first_byte == 0xE0) {
            return CMD_TYPE_ATS;
        }
        else if ((first_byte & 0xF8) == 0x90) {
            return CMD_TYPE_UID;
        }
        else if (iso14443_block_pcb(first_byte)) {
            return CMD_TYPE_BLOCK;
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        if (trans->cmd != CMD_TYPE_UNKNOWN) {
            return trans->cmd;
        }
        else if (iso14443_block_pcb(first_byte)) {
            return CMD_TYPE_BLOCK;
        }

        /* we don't try to detect any response messages based on their
           length - depending on the log tool, two trailing CRC bytes
           may be added or not */
    }

    return CMD_TYPE_UNKNOWN;
}


static gint
dissect_iso14443_msg(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, guint8 event)
{
    gboolean crc_dropped = FALSE;
    iso14443_transaction_t *iso14443_trans;
    iso14443_cmd_t cmd;
    proto_tree *msg_tree;
    gint ret;

    if (event == ISO14443_EVT_DATA_PICC_TO_PCD_CRC_DROPPED ||
            event == ISO14443_EVT_DATA_PCD_TO_PICC_CRC_DROPPED) {
        crc_dropped = TRUE;
    }

    iso14443_trans = iso14443_get_transaction(tvb, pinfo, tree);
    if (!iso14443_trans)
        return -1;

    cmd = iso14443_get_cmd_type(tvb, pinfo, iso14443_trans);
    if (cmd != CMD_TYPE_UNKNOWN)
        iso14443_trans->cmd = cmd;

    msg_tree = proto_tree_add_subtree(
            tree, tvb, 0, -1, ett_iso14443_msg, NULL, "Message");

    ret = dissector_try_uint_new(iso14443_cmd_type_table, cmd,
            tvb, pinfo, msg_tree, FALSE, GUINT_TO_POINTER((guint)crc_dropped));
    if (ret == 0) {
        proto_tree_add_expert(tree, pinfo, &ei_iso14443_unknown_cmd,
                tvb, 0, tvb_captured_length(tvb));
        ret = tvb_captured_length(tvb);
    }

    return ret;
}


static int dissect_iso14443(tvbuff_t *tvb,
        packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    gint        packet_len;
    gint        offset = 0, offset_ver, offset_evt, offset_len_field;
    gint        ret;
    guint8      version, event;
    const gchar *event_str;
    guint16     len_field;
    proto_item *tree_ti;
    proto_tree *iso14443_tree, *hdr_tree;
    tvbuff_t    *payload_tvb;
    conversation_t *conv;

    if (tvb_captured_length(tvb) < 4)
        return 0;

    offset_ver = offset;
    version = tvb_get_guint8(tvb, offset++);
    if (version != 0)
        return 0;

    offset_evt = offset;
    event = tvb_get_guint8(tvb, offset++);
    event_str = try_val_to_str(event, iso14443_event);
    if (!event_str)
        return 0;

    packet_len = tvb_reported_length(tvb);
    offset_len_field = offset;
    len_field = tvb_get_ntohs(tvb, offset);
    if (len_field != (packet_len-4))
        return 0;
    offset += 2;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "ISO 14443");
    col_clear(pinfo->cinfo, COL_INFO);

    tree_ti = proto_tree_add_protocol_format(tree, proto_iso14443,
            tvb, 0, tvb_reported_length(tvb), "ISO 14443");
    iso14443_tree = proto_item_add_subtree(tree_ti, ett_iso14443);

    hdr_tree = proto_tree_add_subtree(iso14443_tree,
            tvb, 0, offset, ett_iso14443_hdr, NULL, "Pseudo header");

    proto_tree_add_item(hdr_tree, hf_iso14443_hdr_ver,
            tvb, offset_ver, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_iso14443_event,
            tvb, offset_evt, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_iso14443_len_field,
            tvb, offset_len_field, 2, ENC_BIG_ENDIAN);

    if (IS_DATA_TRANSFER(event)) {
        iso14443_set_addrs(event, pinfo);

        payload_tvb = tvb_new_subset_remaining(tvb, offset);
        ret = dissect_iso14443_msg(payload_tvb, pinfo, iso14443_tree, event);
        if (ret > 0)
            offset += ret;
    }
    else {
        col_set_str(pinfo->cinfo, COL_INFO, event_str);

        /* all events that are not data transfers close the connection
           to the card (e.g. the field is switched on or off) */
        conv = find_conversation_by_id(pinfo->num, CONVERSATION_ISO14443, ISO14443_CIRCUIT_ID);
        if (conv)
            conv->last_frame = pinfo->num;
    }

    return offset;
}


void
proto_register_iso14443(void)
{
    static hf_register_info hf[] = {
        { &hf_iso14443_hdr_ver,
            { "Version", "iso14443.hdr_version",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_event,
            { "Event", "iso14443.event",
                FT_UINT8, BASE_HEX, VALS(iso14443_event), 0, NULL, HFILL }
        },
        { &hf_iso14443_len_field,
            { "Length field", "iso14443.length_field",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_resp_in,
            { "Response In", "iso14443.resp_in",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_iso14443_resp_to,
            { "Response To", "iso14443.resp_to",
                FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL }
        },
        { &hf_iso14443_short_frame,
            { "Short frame", "iso14443.short_frame",
                FT_UINT8, BASE_HEX, VALS(iso14443_short_frame), 0, NULL, HFILL }
        },
        { &hf_iso14443_atqa_rfu1,
            { "RFU", "iso14443.atqa_rfu",
                FT_UINT16, BASE_HEX, NULL, 0xF000, NULL, HFILL }
        },
        { &hf_iso14443_atqa_rfu2,
            { "RFU", "iso14443.atqa_rfu",
                FT_UINT16, BASE_HEX, NULL, 0x0020, NULL, HFILL }
        },
        { &hf_iso14443_propr_coding,
            { "Proprietary coding", "iso14443.propr_coding",
                FT_UINT16, BASE_HEX, NULL, 0x0F00, NULL, HFILL }
        },
        { &hf_iso14443_uid_bits,
            { "UID bits", "iso14443.uid_bits",
                FT_UINT16, BASE_HEX, NULL, 0x00C0, NULL, HFILL }
        },
        { &hf_iso14443_uid_size,
            { "UID size", "iso14443.uid_size",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_max_frame_size,
            { "Maximum frame size", "iso14443.max_frame_size",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_bit_frame_anticoll,
            { "Bit frame anticollision", "iso14443.bit_frame_anticoll",
                FT_UINT16, BASE_HEX, NULL, 0x001F, NULL, HFILL }
        },
        { &hf_iso14443_apf,
            { "Anticollision prefix", "iso14443.apf",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_afi,
            { "Application Family Identifier", "iso14443.afi",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_ext_atqb,
            { "Extended ATQB", "iso14443.ext_atqb", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL }
        },
        { &hf_iso14443_wupb,
            { "WUPB/REQB", "iso14443.wupb",
                FT_BOOLEAN, 8, TFS(&tfs_wupb_reqb), 0x08, NULL, HFILL }
        },
        { &hf_iso14443_n,
            { "N", "iso14443.n",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_atqb_start,
            { "Start byte", "iso14443.atqb_start",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_app_data,
            { "Application data", "iso14443.application_data",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_num_afi_apps,
            { "Number of applications for this AFI", "iso14443.num_afi_apps",
                FT_UINT8, BASE_DEC, NULL, 0xF0, NULL, HFILL }
        },
        { &hf_iso14443_total_num_apps,
            { "Total number of applications", "iso14443.total_num_apps",
                FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_iso14443_prot_inf,
            { "Protocol info", "iso14443.protocol_info",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_bit_rate_cap,
            { "Bit rate capability", "iso14443.bit_rate_cap",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_same_bit_rate,
            { "Same bit rate in both directions", "iso14443.same_bit_rate",
                FT_BOOLEAN, 8, TFS(&tfs_required_not_required), 0x80, NULL, HFILL }
        },
        { &hf_iso14443_picc_pcd_847,
            { "PICC to PCD, 847kbit/s", "iso14443.picc_pcd_847", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL }
        },
        { &hf_iso14443_picc_pcd_424,
            { "PICC to PCD, 424kbit/s", "iso14443.picc_pcd_424", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL }
        },
        { &hf_iso14443_picc_pcd_212,
            { "PICC to PCD, 212kbit/s", "iso14443.picc_pcd_212", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL }
        },
        { &hf_iso14443_pcd_picc_847,
            { "PCD to PICC, 847kbit/s", "iso14443.pcd_picc_847", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL }
        },
        { &hf_iso14443_pcd_picc_424,
            { "PCD to PICC, 424kbit/s", "iso14443.pcd_picc_424", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
        },
        { &hf_iso14443_pcd_picc_212,
            { "PCD to PICC, 212kbit/s", "iso14443.pcd_picc_212", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }
        },
        { &hf_iso14443_max_frame_size_code,
            { "Max frame size code", "iso14443.max_frame_size_code",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_prot_type,
            { "Protocol type", "iso14443.protocol_type",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        /* we're using min tr2 in two different places (atqb and attrib)
           the relative position within the byte is identical so we can
           set the mask here */
        { &hf_iso14443_min_tr2,
            { "Minimum TR2", "iso14443.min_tr2",
                FT_UINT8, BASE_HEX, NULL, 0x06, NULL, HFILL }
        },
        /* the same goes for the 14443-4 compliant flag */
        { &hf_iso14443_4_compl_atqb,
            { "Compliant with ISO 14443-4", "iso14443.4_compliant", FT_BOOLEAN, 8,
                TFS(&tfs_compliant_not_compliant), 0x01, NULL, HFILL }
        },
        { &hf_iso14443_fwi,
            { "FWI", "iso14443.fwi", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_sfgi,
            { "SFGI", "iso14443.sfgi", FT_UINT8, BASE_DEC,
                NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_adc,
            { "Application Data Coding", "iso14443.adc", FT_BOOLEAN, 8,
                TFS(&tfs_iso_propr), 0x04, NULL, HFILL }
        },
        { &hf_iso14443_nad_supported,
            { "NAD", "iso14443.nad_supported", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0, NULL, HFILL }
        },
        { &hf_iso14443_cid_supported,
            { "CID", "iso14443.cid_supported", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0, NULL, HFILL }
        },
        { &hf_iso14443_hlta,
            { "HLTA", "iso14443.hlta",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_sel,
            { "SEL", "iso14443.sel",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_nvb,
            { "NVB", "iso14443.nvb",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_4_compl_sak,
            { "Compliant with ISO 14443-4", "iso14443.4_compliant", FT_BOOLEAN, 8,
                TFS(&tfs_compliant_not_compliant), 0x20, NULL, HFILL }
        },
        { &hf_iso14443_uid_complete,
            { "UID complete", "iso14443.uid_complete", FT_BOOLEAN, 8,
                TFS(&tfs_incomplete_complete), 0x04, NULL, HFILL }
        },
        { &hf_iso14443_ct,
            { "CT", "iso14443.ct",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_uid_cln,
            { "UID_CLn", "iso14443.uid_cln",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_bcc,
            { "BCC", "iso14443.bcc",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_rats_start,
            { "Start byte", "iso14443.rats_start",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_fsdi,
            { "FSDI", "iso14443.fsdi",
                FT_UINT8, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_fsd,
            { "FSD", "iso14443.fsd",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_cid,
            { "CID", "iso14443.cid",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_tl,
            { "Length byte TL", "iso14443.tl",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_t0,
            { "Format byte T0", "iso14443.t0",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_tc1_transmitted,
            { "TC(1) transmitted", "iso14443.tc1_transmitted",
                FT_BOOLEAN, 8, NULL, HAVE_TC1, NULL, HFILL }
        },
        { &hf_iso14443_tb1_transmitted,
            { "TB(1) transmitted", "iso14443.tb1_transmitted",
                FT_BOOLEAN, 8, NULL, HAVE_TB1, NULL, HFILL }
        },
        { &hf_iso14443_ta1_transmitted,
            { "TA(1) transmitted", "iso14443.ta1_transmitted",
                FT_BOOLEAN, 8, NULL, HAVE_TA1, NULL, HFILL }
        },
        { &hf_iso14443_fsci,
            { "FSCI", "iso14443.fsci",
                FT_UINT8, BASE_DEC, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_iso14443_fsc,
            { "FSC", "iso14443.fsc",
                FT_UINT16, BASE_DEC, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_tc1,
            { "Interface byte TC1", "iso14443.tc1",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_tb1,
            { "Interface byte TB1", "iso14443.tb1",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_ta1,
            { "Interface byte TA1", "iso14443.ta1",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_same_d,
            { "Same D for both directions", "iso14443.same_d", FT_BOOLEAN, 8,
                TFS(&tfs_required_not_required), 0x80, NULL, HFILL }
        },
        { &hf_iso14443_ds8,
            { "DS=8", "iso14443.ds8", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x40, NULL, HFILL }
        },
        { &hf_iso14443_ds4,
            { "DS=4", "iso14443.ds4", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x20, NULL, HFILL }
        },
        { &hf_iso14443_ds2,
            { "DS=2", "iso14443.ds2", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x10, NULL, HFILL }
        },
        { &hf_iso14443_dr8,
            { "DR=8", "iso14443.dr8", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x04, NULL, HFILL }
        },
        { &hf_iso14443_dr4,
            { "DR=4", "iso14443.dr4", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
        },
        { &hf_iso14443_dr2,
            { "DR=2", "iso14443.dr2", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }
        },
        { &hf_iso14443_hist_bytes,
            { "Historical bytes", "iso14443.hist_bytes",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_attrib_start,
            { "Start byte", "iso14443.attrib_start",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_pupi,
            { "PUPI", "iso14443.pupi",
                FT_UINT32, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_param1,
            { "Param 1", "iso14443.param1",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_min_tr0,
            { "Minimum TR0", "iso14443.min_tr0",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_iso14443_min_tr1,
            { "Minimum TR1", "iso14443.min_tr1",
                FT_UINT8, BASE_HEX, NULL, 0x30, NULL, HFILL }
        },
        { &hf_iso14443_eof,
            { "EOF", "iso14443.eof", FT_BOOLEAN, 8,
                TFS(&tfs_not_required_required), 0x08, NULL, HFILL }
        },
        { &hf_iso14443_sof,
            { "SOF", "iso14443.sof", FT_BOOLEAN, 8,
                TFS(&tfs_not_required_required), 0x04, NULL, HFILL }
        },
        { &hf_iso14443_param2,
            { "Param 2", "iso14443.param2",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_bitrate_picc_pcd,
            { "Bit rate PICC to PCD", "iso14443.bitrate_picc_pcd", FT_UINT8,
                BASE_HEX, VALS(iso14443_bitrates), 0xC0, NULL, HFILL }
        },
        { &hf_iso14443_bitrate_pcd_picc,
            { "Bit rate PCD to PICC", "iso14443.bitrate_pcd_picc", FT_UINT8,
                BASE_HEX, VALS(iso14443_bitrates), 0x30, NULL, HFILL }
        },
        { &hf_iso14443_param3,
            { "Param 3", "iso14443.param3",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_param4,
            { "Param 4", "iso14443.param4",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_mbli,
            { "MBLI", "iso14443.mbli",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_pcb,
            { "PCB", "iso14443.pcb",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_block_type,
            { "Block type", "iso14443.block_type", FT_UINT8,
                BASE_HEX, VALS(iso14443_block_type), 0xC0, NULL, HFILL }
        },
        { &hf_iso14443_i_blk_chaining,
            { "Chaining", "iso14443.i_block_chaining", FT_BOOLEAN, 8,
                TFS(&tfs_set_notset), 0x10, NULL, HFILL }
        },
        { &hf_iso14443_cid_following,
            { "CID following", "iso14443.cid_following", FT_BOOLEAN, 8,
                TFS(&tfs_true_false), 0x08, NULL, HFILL }
        },
        { &hf_iso14443_nad_following,
            { "NAD following", "iso14443.nad_following", FT_BOOLEAN, 8,
                TFS(&tfs_true_false), 0x04, NULL, HFILL }
        },
        { &hf_iso14443_nak,
            { "NAK/ACK", "iso14443.nak", FT_BOOLEAN, 8,
                TFS(&tfs_nak_ack), 0x10, NULL, HFILL }
        },
        { &hf_iso14443_blk_num,
            { "Block number", "iso14443.block_number",
                FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }
        },
        { &hf_iso14443_s_blk_cmd,
            { "Command", "iso14443.s_block_cmd", FT_UINT8,
                BASE_HEX, VALS(iso14443_s_block_cmd), 0x30, NULL, HFILL }
        },
        { &hf_iso14443_pwr_lvl_ind,
            { "Power level indication", "iso14443.pwr_lvl_ind",
                FT_UINT8, BASE_HEX, NULL, 0xC0, NULL, HFILL }
        },
        { &hf_iso14443_wtxm,
            { "WTXM", "iso14443.wtxm",
                FT_UINT8, BASE_DEC, NULL, 0x3F, NULL, HFILL }
        },
        { &hf_iso14443_inf,
            { "INF", "iso14443.inf",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_frags,
          { "Apdu fragments", "iso14443.apdu_fragments",
           FT_NONE, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_frag,
          { "Apdu fragment", "iso14443.apdu_fragment",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_frag_overlap,
          { "Apdu fragment overlap", "iso14443.apdu_fragment.overlap",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_frag_overlap_conflicts,
          { "Apdu fragment overlapping with conflicting data",
           "iso14443.apdu_fragment.overlap.conflicts",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_frag_multiple_tails,
          { "Apdu has multiple tail fragments",
           "iso14443.apdu_fragment.multiple_tails",
          FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_frag_too_long_frag,
          { "Apdu fragment too long", "iso14443.apdu_fragment.too_long_fragment",
           FT_BOOLEAN, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_frag_err,
          { "Apdu defragmentation error", "iso14443.apdu_fragment.error",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_frag_cnt,
          { "Apdu fragment count", "iso14443.apdu_fragment.count",
           FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_reass_in,
          { "Apdu reassembled in", "iso14443.apdu_reassembled.in",
           FT_FRAMENUM, BASE_NONE, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_reass_len,
          { "Reassembled apdu length", "iso14443.apdu_reassembled.length",
           FT_UINT32, BASE_DEC, NULL, 0x00, NULL, HFILL }
        },
        { &hf_iso14443_crc,
            { "CRC", "iso14443.crc",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_crc_status,
            { "CRC Status", "iso14443.crc.status",
                FT_UINT8, BASE_NONE, VALS(proto_checksum_vals), 0, NULL, HFILL }
        }
   };

    static gint *ett[] = {
        &ett_iso14443,
        &ett_iso14443_hdr,
        &ett_iso14443_msg,
        &ett_iso14443_app_data,
        &ett_iso14443_prot_inf,
        &ett_iso14443_bit_rate,
        &ett_iso14443_prot_type,
        &ett_iso14443_ats_t0,
        &ett_iso14443_ats_ta1,
        &ett_iso14443_ats_tb1,
        &ett_iso14443_ats_tc1,
        &ett_iso14443_attr_p1,
        &ett_iso14443_attr_p2,
        &ett_iso14443_attr_p3,
        &ett_iso14443_attr_p4,
        &ett_iso14443_pcb,
        &ett_iso14443_inf,
        &ett_iso14443_frag,
        &ett_iso14443_frags
    };

    static ei_register_info ei[] = {
        { &ei_iso14443_unknown_cmd,
            { "iso14443.cmd.unknown", PI_PROTOCOL, PI_WARN,
                "Unknown ISO1443 command", EXPFILL }
        },
        { &ei_iso14443_wrong_crc,
            { "iso14443.crc.wrong", PI_PROTOCOL, PI_WARN, "Wrong CRC", EXPFILL }
        },
        { &ei_iso14443_uid_inval_size,
            { "iso14443.uid.invalid_size", PI_PROTOCOL, PI_WARN,
                "Invalid UID size", EXPFILL }
        }
    };

    expert_module_t* expert_iso14443;

    proto_iso14443 = proto_register_protocol(
            "ISO/IEC 14443", "ISO 14443", "iso14443");
    proto_register_field_array(proto_iso14443, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_iso14443 = expert_register_protocol(proto_iso14443);
    expert_register_field_array(expert_iso14443, ei, array_length(ei));

    iso14443_cmd_type_table = register_dissector_table(
            "iso14443.cmd_type", "ISO14443 Command Type",
            proto_iso14443, FT_UINT8, BASE_DEC);

    reassembly_table_register(&i_block_reassembly_table,
                          &addresses_reassembly_table_functions);

    iso14443_handle =
        register_dissector("iso14443", dissect_iso14443, proto_iso14443);

    transactions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());

    iso14443_subdissector_table =
        register_decode_as_next_proto(proto_iso14443,
                "iso14443.subdissector", "ISO14443 payload subdissector", NULL);
}


void
proto_reg_handoff_iso14443(void)
{
  dissector_handle_t cmd_type_handle;

  dissector_add_uint("wtap_encap", WTAP_ENCAP_ISO14443, iso14443_handle);

  cmd_type_handle = create_dissector_handle(
          dissect_iso14443_cmd_type_wupa, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_WUPA, cmd_type_handle);

  cmd_type_handle = create_dissector_handle(
          dissect_iso14443_cmd_type_wupb, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_WUPB, cmd_type_handle);

  cmd_type_handle = create_dissector_handle(
          dissect_iso14443_cmd_type_hlta, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_HLTA, cmd_type_handle);

  cmd_type_handle = create_dissector_handle(
          dissect_iso14443_cmd_type_uid, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_UID, cmd_type_handle);

  cmd_type_handle = create_dissector_handle(
          dissect_iso14443_cmd_type_ats, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_ATS, cmd_type_handle);

  cmd_type_handle = create_dissector_handle(
          dissect_iso14443_cmd_type_attrib, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_ATTRIB, cmd_type_handle);

  cmd_type_handle = create_dissector_handle(
          dissect_iso14443_cmd_type_block, proto_iso14443);
  dissector_add_uint("iso14443.cmd_type", CMD_TYPE_BLOCK, cmd_type_handle);
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
