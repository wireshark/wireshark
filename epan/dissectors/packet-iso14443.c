/* packet-iso14443.c
 * Routines for ISO14443 dissection
 * Copyright 2015, Martin Kaiser <martin@kaiser.cx>
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
#include <math.h>
#include <epan/expert.h>
#include <epan/packet.h>
#include <epan/tfs.h>
#include <wiretap/wtap.h>

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

static const value_string iso14443_short_frame[] = {
    { 0x26 , "REQA" },
    { 0x52 , "WUPA" },
    { 0, NULL }
};

#define I_BLOCK_TYPE 0x00
#define R_BLOCK_TYPE 0x02
#define S_BLOCK_TYPE 0x03
static const value_string iso14443_block_type[] = {
    { I_BLOCK_TYPE , "I-block" },
    { R_BLOCK_TYPE , "R-block" },
    { S_BLOCK_TYPE , "S-block" },
    { 0, NULL }
};

const true_false_string tfs_wupb_reqb = { "WUPB", "REQB" };
const true_false_string tfs_compliant_not_compliant = { "Compliant", "Not compliant" };
const true_false_string tfs_incomplete_complete = { "Incomplete", "Complete" };
const true_false_string tfs_iso_propr = { "As defined in ISO14443-3", "Proprietary" };

#define CT_BYTE 0x88

#define CRC_LEN 2

void proto_register_iso14443(void);
void proto_reg_handoff_iso14443(void);

static int proto_iso14443 = -1;

static dissector_handle_t iso14443_handle;

static dissector_table_t iso14443_cmd_type_table;

static int ett_iso14443 = -1;
static int ett_iso14443_hdr = -1;
static int ett_iso14443_msg = -1;
static int ett_iso14443_app_data = -1;
static int ett_iso14443_prot_inf = -1;
static int ett_iso14443_pcb = -1;

static int hf_iso14443_hdr_ver = -1;
static int hf_iso14443_event = -1;
static int hf_iso14443_len_field = -1;
static int hf_iso14443_resp_to = -1;
static int hf_iso14443_resp_in = -1;
static int hf_iso14443_short_frame = -1;
static int hf_iso14443_propr_coding = -1;
static int hf_iso14443_uid_size = -1;
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
static int hf_iso14443_min_tr2 = -1;
static int hf_iso14443_4_compl_atqb = -1;
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
static int hf_iso14443_cid = -1;
static int hf_iso14443_tl = -1;
static int hf_iso14443_attrib_start = -1;
static int hf_iso14443_pupi = -1;
static int hf_iso14443_param1 = -1;
static int hf_iso14443_param2 = -1;
static int hf_iso14443_param3 = -1;
static int hf_iso14443_param4 = -1;
static int hf_iso14443_mbli = -1;
static int hf_iso14443_pcb = -1;
static int hf_iso14443_block_type = -1;
static int hf_iso14443_i_blk_chaining = -1;
static int hf_iso14443_cid_following = -1;
static int hf_iso14443_nad_following = -1;
static int hf_iso14443_blk_num = -1;
static int hf_iso14443_inf = -1;
static int hf_iso14443_crc = -1;

static expert_field ei_iso14443_unknown_cmd = EI_INIT;


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
        col_set_str(pinfo->cinfo, COL_INFO, "ATQA");
        proto_item_append_text(ti, ": ATQA");

        proto_tree_add_item(tree, hf_iso14443_propr_coding,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;

        uid_bits = (tvb_get_guint8(tvb, offset) & 0xC0) >> 6;
        if (uid_bits == 0x00)
            uid_size = 4;
        else if (uid_bits == 0x01)
            uid_size = 7;
        else if (uid_bits == 0x02)
            uid_size = 10;
        /* XXX- expert info for invalid uid size */
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_uid_size,
                tvb, offset*8, 2, uid_size, "%d", uid_size);
        proto_tree_add_item(tree, hf_iso14443_bit_frame_anticoll,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
    }

    return offset;
}


static int dissect_iso14443_atqb(tvbuff_t *tvb, gint offset,
        packet_info *pinfo, proto_tree *tree, gboolean crc_dropped)
{
    proto_item *ti = proto_tree_get_parent(tree);
    proto_item *app_data_it, *prot_inf_it;
    proto_tree *app_data_tree, *prot_inf_tree;
    gint app_data_offset, rem_len;
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
    proto_tree_add_item(prot_inf_tree, hf_iso14443_bit_rate_cap,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* XXX - max_frame_size */
    proto_tree_add_item(prot_inf_tree, hf_iso14443_min_tr2,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(prot_inf_tree, hf_iso14443_4_compl_atqb,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* XXX - FWI */
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
    proto_tree_add_item(prot_inf_tree, hf_iso14443_nad_supported,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(prot_inf_tree, hf_iso14443_cid_supported,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    /* XXX - extended ATQB */
    if (prot_inf_len>3)
        offset++;

    if (!crc_dropped) {
        proto_tree_add_item(tree, hf_iso14443_crc,
                tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
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
        msg_type = (param & 0x08) ?
            tfs_wupb_reqb.true_string : tfs_wupb_reqb.false_string;
        col_set_str(pinfo->cinfo, COL_INFO, msg_type);
        proto_item_append_text(ti, ": %s", msg_type);
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_n,
                tvb, offset*8+5, 3, (guint8)pow(2, param&0x07),
                "%d", (guint8)pow(2, param&0x07));
        offset++;

        if (!crc_dropped) {
            proto_tree_add_item(tree, hf_iso14443_crc,
                    tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
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

    /* XXX - is the CRC calculation different for type A and type B? */
    if (!crc_dropped) {
        proto_tree_add_item(tree, hf_iso14443_crc,
                tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
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
                proto_tree_add_item(tree, hf_iso14443_crc,
                        tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
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
                proto_tree_add_item(tree, hf_iso14443_crc,
                        tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
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


static int
dissect_iso14443_cmd_type_ats(tvbuff_t *tvb, packet_info *pinfo,
        proto_tree *tree, void *data)
{
    gboolean crc_dropped = (gboolean)GPOINTER_TO_UINT(data);
    proto_item *ti = proto_tree_get_parent(tree);
    gint offset = 0;
    guint8 fsdi, cid;
    guint8 tl;

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        col_set_str(pinfo->cinfo, COL_INFO, "RATS");
        proto_item_append_text(ti, ": RATS");

        proto_tree_add_item(tree, hf_iso14443_rats_start,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        fsdi = tvb_get_guint8(tvb, offset) >> 4;
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_fsdi,
                tvb, offset*8, 4, fsdi, "%d", fsdi);
        cid = tvb_get_guint8(tvb, offset) & 0x0F;
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_cid,
                tvb, offset*8+4, 4, cid, "%d", cid);
        offset++;
        if (!crc_dropped) {
            proto_tree_add_item(tree, hf_iso14443_crc,
                    tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
            offset += CRC_LEN;
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        col_set_str(pinfo->cinfo, COL_INFO, "ATS");
        proto_item_append_text(ti, ": ATS");
        tl = tvb_get_guint8(tvb, offset);
        proto_tree_add_item(tree, hf_iso14443_tl,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        /* TL includes itself */
        offset += tl;
        if (!crc_dropped) {
            proto_tree_add_item(tree, hf_iso14443_crc,
                    tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
            offset += CRC_LEN;
        }
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
    gint hl_inf_len, hl_resp_len;
    guint8 mbli, cid;

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        col_set_str(pinfo->cinfo, COL_INFO, "Attrib");
        proto_item_append_text(ti, ": Attrib");

        proto_tree_add_item(tree, hf_iso14443_attrib_start,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso14443_pupi,
                tvb, offset, 4, ENC_BIG_ENDIAN);
        offset += 4;
        /* XXX - subtree, details for each parameter */
        proto_tree_add_item(tree, hf_iso14443_param1,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso14443_param2,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso14443_param3,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        proto_tree_add_item(tree, hf_iso14443_param4,
                tvb, offset, 1, ENC_BIG_ENDIAN);
        offset++;
        hl_inf_len = crc_dropped ?
            tvb_reported_length_remaining(tvb, offset) :
            tvb_reported_length_remaining(tvb, offset) - CRC_LEN;
        if (hl_inf_len > 0) {
            offset += hl_inf_len;
        }
        if (!crc_dropped) {
            proto_tree_add_item(tree, hf_iso14443_crc,
                    tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
            offset += CRC_LEN;
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        col_set_str(pinfo->cinfo, COL_INFO, "Response to Attrib");
        proto_item_append_text(ti, ": Response to Attrib");

        mbli = tvb_get_guint8(tvb, offset) >> 4;
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_mbli,
                tvb, offset*8, 4, mbli, "%d", mbli);
        cid = tvb_get_guint8(tvb, offset) & 0x0F;
        proto_tree_add_uint_bits_format_value(tree, hf_iso14443_cid,
                tvb, offset*8+4, 4, cid, "%d", cid);
        offset++;

        hl_resp_len = crc_dropped ?
            tvb_reported_length_remaining(tvb, offset) :
            tvb_reported_length_remaining(tvb, offset) - CRC_LEN;
        if (hl_resp_len > 0) {
            offset += hl_resp_len;
        }

        if (!crc_dropped) {
            proto_tree_add_item(tree, hf_iso14443_crc,
                    tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
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
    proto_item *pcb_ti;
    proto_tree *pcb_tree;
    gboolean has_cid, has_nad = FALSE;
    guint8 inf_len;

    pcb = tvb_get_guint8(tvb, offset);
    block_type = (pcb & 0xC0) >> 6;
    bt_str = try_val_to_str(block_type, iso14443_block_type);
    has_cid = ((pcb & 0x08) != 0);

    pcb_ti = proto_tree_add_item(tree, hf_iso14443_pcb,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    pcb_tree = proto_item_add_subtree(pcb_ti, ett_iso14443_pcb);
    proto_tree_add_item(pcb_tree, hf_iso14443_block_type,
            tvb, offset, 1, ENC_BIG_ENDIAN);
    switch (block_type) {

    case I_BLOCK_TYPE:
        proto_tree_add_item(pcb_tree, hf_iso14443_i_blk_chaining,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pcb_tree, hf_iso14443_cid_following,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        has_nad = ((pcb & 0x40) != 0);
        proto_tree_add_item(pcb_tree, hf_iso14443_nad_following,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pcb_tree, hf_iso14443_blk_num,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        break;

    case R_BLOCK_TYPE:
        proto_tree_add_item(pcb_tree, hf_iso14443_cid_following,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(pcb_tree, hf_iso14443_blk_num,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        break;

    case S_BLOCK_TYPE:
        proto_tree_add_item(pcb_tree, hf_iso14443_cid_following,
            tvb, offset, 1, ENC_BIG_ENDIAN);
        break;

    default:
        /* Report an error? b8 = 0, b7 = 1 */
        break;
    }
    if (bt_str) {
        proto_item_append_text(ti, ": %s", bt_str);
        col_set_str(pinfo->cinfo, COL_INFO, bt_str);
    }
    offset++;

    if (has_cid)
        offset++;
    if (has_nad)
        offset++;

    inf_len = crc_dropped ?
        tvb_reported_length_remaining(tvb, offset) :
        tvb_reported_length_remaining(tvb, offset) - 2;

    proto_tree_add_item(tree, hf_iso14443_inf,
            tvb, offset, inf_len, ENC_NA);
    offset += inf_len;

    if (!crc_dropped) {
        proto_tree_add_item(tree, hf_iso14443_crc,
                tvb, offset, CRC_LEN, ENC_BIG_ENDIAN);
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
iso14443_get_transaction(packet_info *pinfo, proto_tree *tree)
{
    proto_item *it;
    iso14443_transaction_t *iso14443_trans = NULL;

    if (pinfo->p2p_dir == P2P_DIR_SENT) {
        if (PINFO_FD_VISITED(pinfo)) {
            iso14443_trans = (iso14443_transaction_t *)wmem_tree_lookup32(
                    transactions, PINFO_FD_NUM(pinfo));
            if (iso14443_trans && iso14443_trans->rqst_frame==PINFO_FD_NUM(pinfo) &&
                    iso14443_trans->resp_frame!=0) {
               it = proto_tree_add_uint(tree, hf_iso14443_resp_in,
                       NULL, 0, 0, iso14443_trans->resp_frame);
               PROTO_ITEM_SET_GENERATED(it);
            }
        }
        else {
            iso14443_trans = wmem_new(wmem_file_scope(), iso14443_transaction_t);
            iso14443_trans->rqst_frame = PINFO_FD_NUM(pinfo);
            iso14443_trans->resp_frame = 0;
            /* iso14443_trans->ctrl = ctrl; */
            wmem_tree_insert32(transactions,
                    iso14443_trans->rqst_frame, (void *)iso14443_trans);
        }
    }
    else if (pinfo->p2p_dir == P2P_DIR_RECV) {
        iso14443_trans = (iso14443_transaction_t *)wmem_tree_lookup32_le(
                transactions, PINFO_FD_NUM(pinfo));
        if (iso14443_trans && iso14443_trans->resp_frame==0) {
            /* there's a pending request, this packet is the response */
            iso14443_trans->resp_frame = PINFO_FD_NUM(pinfo);
        }

        if (iso14443_trans && iso14443_trans->resp_frame == PINFO_FD_NUM(pinfo)) {
            it = proto_tree_add_uint(tree, hf_iso14443_resp_to,
                    NULL, 0, 0, iso14443_trans->rqst_frame);
            PROTO_ITEM_SET_GENERATED(it);
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

    iso14443_trans = iso14443_get_transaction(pinfo, tree);
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
        { &hf_iso14443_propr_coding,
            { "Proprietary coding", "iso14443.propr_coding",
                FT_UINT8, BASE_HEX, NULL, 0x0F, NULL, HFILL }
        },
        { &hf_iso14443_uid_size,
            { "UID size", "iso14443.uid_size",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_bit_frame_anticoll,
            { "Bit frame anicollision", "iso14443.bit_frame_anticoll",
                FT_UINT8, BASE_HEX, NULL, 0x1F, NULL, HFILL }
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
        { &hf_iso14443_min_tr2,
            { "Minimum TR2", "iso14443.min_tr2",
                FT_UINT8, BASE_HEX, NULL, 0x06, NULL, HFILL }
        },
        { &hf_iso14443_4_compl_atqb,
            { "Compliant with ISO 14443-4", "iso14443.4_compliant", FT_BOOLEAN, 8,
                TFS(&tfs_compliant_not_compliant), 0x01, NULL, HFILL }
        },
        { &hf_iso14443_adc,
            { "Application Data Coding", "iso14443.adc", FT_BOOLEAN, 8,
                TFS(&tfs_iso_propr), 0x04, NULL, HFILL }
        },
        { &hf_iso14443_nad_supported,
            { "NAD", "iso14443.nad_supported", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x02, NULL, HFILL }
        },
        { &hf_iso14443_cid_supported,
            { "CID", "iso14443.cid_supported", FT_BOOLEAN, 8,
                TFS(&tfs_supported_not_supported), 0x01, NULL, HFILL }
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
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_cid,
            { "CID", "iso14443.cid",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_tl,
            { "Length byte TL", "iso14443.tl",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
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
        { &hf_iso14443_param2,
            { "Param 2", "iso14443.param2",
                FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
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
            { "Chaining", "iso14443.i_blk_chaining", FT_BOOLEAN, 8,
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
        { &hf_iso14443_blk_num,
            { "Block number", "iso14443.block_number",
                FT_UINT8, BASE_DEC, NULL, 0x01, NULL, HFILL }
        },
        { &hf_iso14443_inf,
            { "INF", "iso14443.inf",
                FT_BYTES, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_iso14443_crc,
            { "CRC", "iso14443.crc",
                FT_UINT16, BASE_HEX, NULL, 0, NULL, HFILL }
        }
   };

    static gint *ett[] = {
        &ett_iso14443,
        &ett_iso14443_hdr,
        &ett_iso14443_msg,
        &ett_iso14443_app_data,
        &ett_iso14443_prot_inf,
        &ett_iso14443_pcb
    };

    static ei_register_info ei[] = {
        { &ei_iso14443_unknown_cmd,
            { "iso14443.cmd.unknown", PI_PROTOCOL, PI_WARN,
                "Unknown ISO1443 command", EXPFILL }
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
            FT_UINT8, BASE_DEC, DISSECTOR_TABLE_ALLOW_DUPLICATE);

    iso14443_handle =
        register_dissector("iso14443", dissect_iso14443, proto_iso14443);

    transactions = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
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
