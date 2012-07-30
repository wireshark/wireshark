/* Routines for UMTS MAC (3GPP TS 25.321) disassembly
 *
 * $Id$
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <glib.h>

#include <epan/packet.h>
#include <epan/conversation.h>
#include <epan/expert.h>

#include "packet-rrc.h"
#include "packet-umts_fp.h"
#include "packet-umts_mac.h"
#include "packet-rlc.h"
#include "packet-nbap.h"

int proto_umts_mac = -1;
extern int proto_fp;
extern int proto_rlc;
extern int proto_rrc;

/* dissector fields */
static int hf_mac_fach_fdd_tctf = -1;
static int hf_mac_rach_fdd_tctf = -1;
static int hf_mac_ct = -1;
static int hf_mac_ueid_type = -1;
static int hf_mac_crnti = -1;
static int hf_mac_urnti = -1;
static int hf_mac_channel = -1;
static int hf_mac_channel_str = -1;

static int hf_mac_lch_id = -1;
static int hf_mac_macdflowd_id = -1;
static int hf_mac_channel_hsdsch = -1;
static int hf_mac_trch_id = -1;

static int hf_mac_edch_type2_subframe_header = -1;
static int hf_mac_edch_type2_descriptors = -1;
static int hf_mac_edch_type2_lchid = -1;
static int hf_mac_edch_type2_length = -1;
static int hf_mac_edch_type2_flag = -1;
static int hf_mac_edch_type2_tsn = -1;
static int hf_mac_edch_type2_ss = -1;
static int hf_mac_edch_type2_sdu = -1;
static int hf_mac_edch_type2_sdu_data = -1;
static int hf_mac_is_2head_link = -1;
static int hf_mac_is_2tail_link = -1;

/* subtrees */
static int ett_mac = -1;
static int ett_mac_fach = -1;
static int ett_mac_rach = -1;
static int ett_mac_dch = -1;
static int ett_mac_pch = -1;
static int ett_mac_edch = -1;
static int ett_mac_hsdsch = -1;
static int ett_mac_edch_type2 = -1;
static int ett_mac_edch_type2_sdu = -1;

static dissector_handle_t rlc_pcch_handle;
static dissector_handle_t rlc_ccch_handle;
static dissector_handle_t rlc_ctch_handle;
static dissector_handle_t rlc_dcch_handle;
static dissector_handle_t rlc_ps_dtch_handle;
static dissector_handle_t rrc_handle;

/* MAC-is reassembly */
typedef struct {
    guint32 frame_num;
    guint16 tsn;
    guint8 * data;
    guint32 length;
    tvbuff_t * tvb;
    guint counterpart;
} mac_is_sdu;
typedef struct {
    guint8 * data;
    guint32 length;
    guint32 frame_num;
} mac_is_fragment;
static GHashTable * mac_is_sdus = NULL;
static GHashTable * mac_is_fragments = NULL;
static gboolean mac_is_sdu_equal(gconstpointer a, gconstpointer b)
{
	const mac_is_sdu *x = a, *y = b;
	return x->frame_num == y->frame_num && x->tsn == y->tsn;
}
static guint mac_is_sdu_hash(gconstpointer key)
{
	const mac_is_sdu *sdu = key;
	return (sdu->frame_num << 6) | sdu->tsn; /* Not so good for TSN 14 bits */
}

static const value_string rach_fdd_tctf_vals[] = {
    { TCTF_CCCH_RACH_FDD      , "CCCH over RACH (FDD)" },
    { TCTF_DCCH_DTCH_RACH_FDD , "DCCH/DTCH over RACH (FDD)" },
    { 0, NULL }
};

static const value_string fach_fdd_tctf_vals[] = {
    { TCTF_BCCH_FACH_FDD      , "BCCH over FACH (FDD)" },
    { TCTF_DCCH_DTCH_FACH_FDD , "DCCH/DTCH over FACH (FDD)" },
    { TCTF_MTCH_FACH_FDD      , "MTCH over FACH (FDD)" },
    { TCTF_CCCH_FACH_FDD      , "CCCH over FACH (FDD)" },
    { TCTF_MCCH_FACH_FDD      , "MCCH over FACH (FDD)" },
    { TCTF_MSCH_FACH_FDD      , "MSCH over FACH (FDD)" },
    { TCTF_CTCH_FACH_FDD      , "CTCH over FACH (FDD)" },
    { 0, NULL }
};

static const value_string ueid_type_vals[] = {
    { MAC_UEID_TYPE_URNTI,  "U-RNTI" },
    { MAC_UEID_TYPE_CRNTI,  "C-RNTI" },
    { 0, NULL }
};

static const value_string mac_logical_channel_vals[] = {
    { MAC_PCCH, "PCCH" },
    { MAC_CCCH, "CCCH" },
    { MAC_CTCH, "CTCH" },
    { MAC_DCCH, "DCCH" },
    { MAC_DTCH, "DTCH" },
    { MAC_BCCH, "BCCH" },
    { MAC_MCCH, "MCCH" },
    { MAC_MSCH, "MSCH" },
    { MAC_MTCH, "MTCH" },
    { MAC_N_A, "N/A" },
    { 0, NULL }
};

static guint8 fach_fdd_tctf(guint8 hdr, guint16 *bit_offs)
{
    guint8 tctf;
    /* first, test for valid 2-bit combinations */
    tctf = hdr >> 6;
    switch (tctf) {
        case TCTF_BCCH_FACH_FDD:
        case TCTF_DCCH_DTCH_FACH_FDD:
            *bit_offs = 2;
            return tctf;
    }
    /* 4-bit combinations */
    tctf = hdr >> 4;
    switch (tctf) {
        case TCTF_MTCH_FACH_FDD:
            *bit_offs = 4;
            return tctf;
    }
    /* just return the 8-bit combination */
    *bit_offs = 8;
    tctf = hdr;
    switch (tctf) {
        case TCTF_CCCH_FACH_FDD:
        case TCTF_MCCH_FACH_FDD:
        case TCTF_MSCH_FACH_FDD:
        case TCTF_CTCH_FACH_FDD:
            return tctf;
        default:
            return tctf; /* TODO */
    }
}

static guint16 tree_add_common_dcch_dtch_fields(tvbuff_t *tvb, packet_info *pinfo _U_,
    proto_tree *tree, guint16 bitoffs, fp_info *fpinf, umts_mac_info *macinf, rlc_info  *rlcinf)
{
    guint8 ueid_type;
	
    ueid_type = tvb_get_bits8(tvb, bitoffs, 2);
    proto_tree_add_bits_item(tree, hf_mac_ueid_type, tvb, bitoffs, 2, ENC_BIG_ENDIAN);
    bitoffs += 2;
    if (ueid_type == MAC_UEID_TYPE_URNTI) {
        proto_tree_add_bits_item(tree, hf_mac_urnti, tvb, bitoffs, 32, ENC_BIG_ENDIAN);
        rlcinf->urnti[fpinf->cur_tb] = tvb_get_bits32(tvb, bitoffs, 32,FALSE);
        bitoffs += 32;
    } else if (ueid_type == MAC_UEID_TYPE_CRNTI) {
        proto_tree_add_bits_item(tree, hf_mac_crnti, tvb, 4, 16, ENC_BIG_ENDIAN);
        rlcinf->urnti[fpinf->cur_tb] = tvb_get_bits16(tvb, bitoffs, 16,FALSE);
        bitoffs += 16;
    }

    if (macinf->ctmux[fpinf->cur_tb]) {
        if(rlcinf){
            rlcinf->rbid[fpinf->cur_tb] = tvb_get_bits8(tvb, bitoffs, 4)+1;
        }
        proto_tree_add_bits_item(tree, hf_mac_ct, tvb, bitoffs, 4, ENC_BIG_ENDIAN);
        bitoffs += 4;
    }
    return bitoffs;
}

static void dissect_mac_fdd_pch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *pch_tree = NULL;
    proto_item *channel_type;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");
    col_set_str(pinfo->cinfo, COL_INFO, "PCCH");

    if (tree) {
        proto_item *ti;
        ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
        pch_tree = proto_item_add_subtree(ti, ett_mac_pch);
        proto_item_append_text(ti, " (PCCH)");
        channel_type = proto_tree_add_uint(pch_tree, hf_mac_channel, tvb, 0, 0, MAC_PCCH);
        PROTO_ITEM_SET_GENERATED(channel_type);
    }
    call_dissector(rlc_pcch_handle, tvb, pinfo, tree);
}

static void dissect_mac_fdd_rach(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8         tctf;
    guint8         chan;
    guint16        bitoffs   = 0;
    tvbuff_t      *next_tvb;
    proto_tree    *rach_tree = NULL;
    proto_item    *channel_type;
    umts_mac_info *macinf;
    fp_info       *fpinf;
    rlc_info      *rlcinf;
    proto_item    *ti        = NULL;
	guint8			c_t;
    /* RACH TCTF is always 2 bit */
    tctf = tvb_get_bits8(tvb, 0, 2);
    bitoffs += 2;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str(tctf, rach_fdd_tctf_vals, "Unknown TCTF"));

    ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
    rach_tree = proto_item_add_subtree(ti, ett_mac_rach);

    macinf = (umts_mac_info *)p_get_proto_data(pinfo->fd, proto_umts_mac);
    fpinf  = (fp_info *)p_get_proto_data(pinfo->fd, proto_fp);
    rlcinf = (rlc_info *)p_get_proto_data(pinfo->fd, proto_rlc);
    if (!macinf || !fpinf) {
        proto_tree_add_text(rach_tree, tvb, 0, -1,
            "Cannot dissect MAC frame because per-frame info is missing");
            expert_add_info_format(pinfo,ti,PI_MALFORMED,PI_ERROR,"Cannot dissect MAC frame because per-frame info is missing");
        return;
    }

    proto_tree_add_bits_item(rach_tree, hf_mac_rach_fdd_tctf, tvb, 0, 2, ENC_BIG_ENDIAN);
    if (tctf == TCTF_DCCH_DTCH_RACH_FDD) {
        macinf->ctmux[fpinf->cur_tb] = 1; /* DCCH/DTCH on RACH *always* has a C/T */
        bitoffs = tree_add_common_dcch_dtch_fields(tvb, pinfo, rach_tree, bitoffs, fpinf, macinf, rlcinf);
    }

    chan = fpinf->cur_chan;
    /* handoff to next dissector */
    switch (tctf) {
        case TCTF_CCCH_RACH_FDD:
            proto_item_append_text(ti, " (CCCH)");
            channel_type = proto_tree_add_uint(rach_tree, hf_mac_channel, tvb, 0, 0, MAC_CCCH);
            PROTO_ITEM_SET_GENERATED(channel_type);
            next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
            add_new_data_source(pinfo, next_tvb, "Octet-Aligned CCCH Data");
            call_dissector(rlc_ccch_handle, next_tvb, pinfo, tree);
            break;
        case TCTF_DCCH_DTCH_RACH_FDD:
            /*Set RLC Mode/MAC content based on the L-CHID derived from the C/T flag*/
            c_t = tvb_get_bits8(tvb,bitoffs-4,4);
            rlcinf->mode[chan] = lchId_rlc_map[c_t+1];
            macinf->content[chan] = lchId_type_table[c_t+1];
            rlcinf->rbid[chan] = c_t+1;
            switch (macinf->content[chan]) {
                case MAC_CONTENT_DCCH:
                    proto_item_append_text(ti, " (DCCH)");
                    channel_type = proto_tree_add_uint(rach_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
                    PROTO_ITEM_SET_GENERATED(channel_type);
                    next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
                    add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
                    call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);
                    break;
                case MAC_CONTENT_PS_DTCH:
                    proto_item_append_text(ti, " (PS DTCH)");
                    channel_type = proto_tree_add_uint(rach_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
                    PROTO_ITEM_SET_GENERATED(channel_type);
                    next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
                    add_new_data_source(pinfo, next_tvb, "Octet-Aligned DTCH Data");
                    call_dissector(rlc_ps_dtch_handle, next_tvb, pinfo, tree);
                    break;
                case MAC_CONTENT_CS_DTCH:
                    proto_item_append_text(ti, " (CS DTCH)");
                    /* TODO */
                    break;
                default:
                    proto_item_append_text(ti, " (Unknown RACH DCCH/DTCH Content)");
                    expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Unknown RACH DCCH/DTCH Content");
            }
            break;
        default:
            proto_item_append_text(ti, " (Unknown RACH TCTF)");
            expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Unknown RACH TCTF ");
    }
}

static void dissect_mac_fdd_fach(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint8         hdr, tctf;
    guint16        bitoffs   = 0;
    guint16        tctf_len, chan;
    proto_tree    *fach_tree = NULL;
    proto_item    *channel_type;
    umts_mac_info *macinf;
    fp_info       *fpinf;
    rlc_info      *rlcinf;
    struct rrc_info *rrcinf;
    proto_item    *ti        = NULL;
    gint c_t;
    hdr = tvb_get_guint8(tvb, 0);

    /* get target channel type field */
    tctf = fach_fdd_tctf(hdr, &bitoffs);
    tctf_len = bitoffs;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

    col_add_str(pinfo->cinfo, COL_INFO,
        val_to_str(tctf, fach_fdd_tctf_vals, "Unknown TCTF"));

    ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
    fach_tree = proto_item_add_subtree(ti, ett_mac_fach);

    macinf = (umts_mac_info *)p_get_proto_data(pinfo->fd, proto_umts_mac);
    fpinf  = (fp_info *)p_get_proto_data(pinfo->fd, proto_fp);
    rlcinf = (rlc_info *)p_get_proto_data(pinfo->fd, proto_rlc);

    if (!macinf || !fpinf) {
        proto_tree_add_text(fach_tree, tvb, 0, -1,
            "Cannot dissect MAC frame because per-frame info is missing");
            expert_add_info_format(pinfo,ti,PI_MALFORMED,PI_ERROR,"Cannot dissect MAC frame because per-frame info is missing");
        return;
    }

    proto_tree_add_bits_item(fach_tree, hf_mac_fach_fdd_tctf, tvb, 0, tctf_len, ENC_BIG_ENDIAN);
    if (tctf == TCTF_DCCH_DTCH_FACH_FDD) {
        macinf->ctmux[fpinf->cur_tb] = 1; /* DCCH/DTCH on FACH *always* has a C/T */
        bitoffs = tree_add_common_dcch_dtch_fields(tvb, pinfo, fach_tree, bitoffs, fpinf, macinf, rlcinf);
    }

    chan = fpinf->cur_chan;
    switch (tctf) {
        tvbuff_t *next_tvb;
        case TCTF_CCCH_FACH_FDD:
            proto_item_append_text(ti, " (CCCH)");
            channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_CCCH);
            PROTO_ITEM_SET_GENERATED(channel_type);
            /* CCCH over FACH is always octet aligned */
            next_tvb = tvb_new_subset(tvb, 1, tvb_length_remaining(tvb, 1), -1);
            call_dissector(rlc_ccch_handle, next_tvb, pinfo, tree);
            break;
        case TCTF_DCCH_DTCH_FACH_FDD:

            /*Set RLC Mode based on the L-CHID derived from the C/T flag*/
            c_t = tvb_get_bits8(tvb,bitoffs-4,4);
            rlcinf->mode[fpinf->cur_tb] = lchId_rlc_map[c_t+1];
            macinf->content[fpinf->cur_tb] = lchId_type_table[c_t+1];
            switch (macinf->content[fpinf->cur_tb]) {

                case MAC_CONTENT_DCCH:
                    proto_item_append_text(ti, " (DCCH)");
                    channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
                    PROTO_ITEM_SET_GENERATED(channel_type);
                    next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
                    add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
                    call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);
                    break;
                case MAC_CONTENT_PS_DTCH:
                    proto_item_append_text(ti, " (PS DTCH)");
                    channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
                    PROTO_ITEM_SET_GENERATED(channel_type);
                    next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[chan] - bitoffs);
                    add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
                    call_dissector(rlc_ps_dtch_handle, next_tvb, pinfo, tree);
                    break;
                case MAC_CONTENT_CS_DTCH:
                    proto_item_append_text(ti, " (CS DTCH)");
                    expert_add_info_format(pinfo, NULL, PI_DEBUG, PI_ERROR, "CS DTCH Is not implemented");
                    /* TODO */
                    break;
                default:
                    proto_item_append_text(ti, " (Unknown FACH Content");
                    expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Unknown FACH Content for this transportblock");
            }
            break;
        case TCTF_CTCH_FACH_FDD:
            proto_item_append_text(ti, " (CTCH)");
            channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_CTCH);
            PROTO_ITEM_SET_GENERATED(channel_type);
            /* CTCH over FACH is always octet aligned */
            next_tvb = tvb_new_subset(tvb, 1, tvb_length_remaining(tvb, 1), -1);
            call_dissector(rlc_ctch_handle, next_tvb, pinfo, tree);
            break;
        /* july 5: Added support for BCCH*/
        case TCTF_BCCH_FACH_FDD:
            proto_item_append_text(ti, " (BCCH)");
            channel_type = proto_tree_add_uint(fach_tree, hf_mac_channel, tvb, 0, 0, MAC_BCCH);
            PROTO_ITEM_SET_GENERATED(channel_type);

            /*We need to skip the first two bits (the TCTF bits), and since there is no MAC header, send rest to RRC*/
            next_tvb= tvb_new_octet_aligned(tvb, 2, (tvb_length(tvb)*8)-2);
            add_new_data_source(pinfo, next_tvb, "Octet-Aligned BCCH Data");

            /* In this case skip RLC and call RRC immediately subdissector */
            rrcinf = p_get_proto_data(pinfo->fd, proto_rrc);
            if (!rrcinf) {
                rrcinf = se_alloc0(sizeof(struct rrc_info));
                p_add_proto_data(pinfo->fd, proto_rrc, rrcinf);
            }
            rrcinf->msgtype[fpinf->cur_tb] = RRC_MESSAGE_TYPE_BCCH_FACH;

            call_dissector(rrc_handle, next_tvb, pinfo, tree);

            break;
        case TCTF_MSCH_FACH_FDD:
        case TCTF_MCCH_FACH_FDD:
        case TCTF_MTCH_FACH_FDD:
            expert_add_info_format(pinfo, NULL, PI_DEBUG, PI_ERROR, " Unimplemented FACH Content type!");
            break;
        default:
            proto_item_append_text(ti, " (Unknown FACH Content)");
            expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, " Unknown FACH Content");
            break;
    }
}

static void dissect_mac_fdd_dch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint16        pos;
    guint8         bitoffs  = 0;
    umts_mac_info *macinf;
    fp_info       *fpinf;
    rlc_info      *rlcinf;
    proto_tree    *dch_tree = NULL;
    proto_item    *channel_type;
    tvbuff_t      *next_tvb;
    proto_item    *ti       = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

    ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
    dch_tree = proto_item_add_subtree(ti, ett_mac_dch);

    macinf = (umts_mac_info *)p_get_proto_data(pinfo->fd, proto_umts_mac);
    fpinf  = (fp_info *)p_get_proto_data(pinfo->fd, proto_fp);
    rlcinf = (rlc_info *)p_get_proto_data(pinfo->fd, proto_rlc);
    if (!macinf || !fpinf) {
    if(!macinf){
        g_warning("MACinf == NULL");
    }
    if(!fpinf){
        g_warning("fpinf == NULL");
    }
       ti =  proto_tree_add_text(dch_tree, tvb, 0, -1,
            "Cannot dissect MAC frame because per-frame info is missing");
        expert_add_info_format(pinfo,ti,PI_DEBUG,PI_ERROR,"MAC frame missing frame information!");
        return;
    }
    pos = fpinf->cur_tb;

    if (macinf->ctmux[pos]) {
        if(rlcinf){
            rlcinf->rbid[fpinf->cur_tb] = tvb_get_bits8(tvb, bitoffs, 4)+1;
        }
        /*Add CT flag to GUI*/
        proto_tree_add_bits_item(dch_tree, hf_mac_ct, tvb, 0, 4, ENC_BIG_ENDIAN);
        bitoffs = 4;
    }

    if (bitoffs) {
        next_tvb = tvb_new_octet_aligned(tvb, bitoffs, fpinf->chan_tf_size[pos] - bitoffs);
        add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
    } else
        next_tvb = tvb;
    switch (macinf->content[pos]) {
        case MAC_CONTENT_DCCH:
            proto_item_append_text(ti, " (DCCH)");

            /*Show logical channel id*/
            if(macinf->lchid[pos]!= 255){
                channel_type = proto_tree_add_uint(dch_tree, hf_mac_lch_id, tvb, 0, 0, macinf->lchid[pos]);
                PROTO_ITEM_SET_GENERATED(channel_type);

                if(macinf->fake_chid[pos]){
                    channel_type = proto_tree_add_text(dch_tree, tvb,0, 0, "This is a faked logical channel id!");
                    PROTO_ITEM_SET_GENERATED(channel_type);
                }
            }else{
                channel_type = proto_tree_add_text(dch_tree, tvb,0, 0, "Frame is missing logical channel");
                PROTO_ITEM_SET_GENERATED(channel_type);
            }

            channel_type = proto_tree_add_uint(dch_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
            PROTO_ITEM_SET_GENERATED(channel_type);

            /*Transport channel printout*/
            channel_type = proto_tree_add_uint(dch_tree, hf_mac_trch_id, tvb, 0, 0, macinf->trchid[pos]);
            PROTO_ITEM_SET_GENERATED(channel_type);
            call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);
            break;
        case MAC_CONTENT_PS_DTCH:
            proto_item_append_text(ti, " (PS DTCH)");
             /*Show logical channel id*/
            if(macinf->lchid[pos]!= 255){
                channel_type = proto_tree_add_uint(dch_tree, hf_mac_lch_id, tvb, 0, 0, macinf->lchid[pos]);
                PROTO_ITEM_SET_GENERATED(channel_type);
            }else{
                channel_type = proto_tree_add_text(dch_tree, tvb,0, 0, "Frame is missing logical channel");
                PROTO_ITEM_SET_GENERATED(channel_type);
            }

            channel_type = proto_tree_add_uint(dch_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
            PROTO_ITEM_SET_GENERATED(channel_type);
            call_dissector(rlc_ps_dtch_handle, next_tvb, pinfo, tree);
            break;
        case MAC_CONTENT_CS_DTCH:
            proto_item_append_text(ti, " (CS DTCH)");
            /*Show logical channel id*/
            if(macinf->lchid[pos]!= 255){
                channel_type = proto_tree_add_uint(dch_tree, hf_mac_lch_id, tvb, 0, 0, macinf->lchid[pos]);
                PROTO_ITEM_SET_GENERATED(channel_type);
                if(macinf->fake_chid[pos]){
                    channel_type = proto_tree_add_text(dch_tree, tvb,0, 0, "This is a faked logical channel id!");
                    PROTO_ITEM_SET_GENERATED(channel_type);
                }
            }else{
                channel_type = proto_tree_add_text(dch_tree, tvb,0, 0, "Frame is missing logical channel");
                PROTO_ITEM_SET_GENERATED(channel_type);
            }

            channel_type = proto_tree_add_uint(dch_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
            PROTO_ITEM_SET_GENERATED(channel_type);

            /*Transport channel printout*/
            channel_type = proto_tree_add_uint(dch_tree, hf_mac_trch_id, tvb, 0, 0, macinf->trchid[pos]);
            PROTO_ITEM_SET_GENERATED(channel_type);

            break;
        default:
            proto_item_append_text(ti, " (Unknown DCH Content)");
            expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Unknown DCH Content");
    }
}

static void init_frag(tvbuff_t * tvb, mac_is_fragment ** mifref, guint length, guint32 frame_num, guint offset)
{
    *mifref = g_new(mac_is_fragment, 1);
    (*mifref)->length = length;
    (*mifref)->data = g_malloc(length);
    (*mifref)->frame_num = frame_num;
    tvb_memcpy(tvb, (*mifref)->data, offset, length);
}

static tvbuff_t * reassemble(tvbuff_t * tvb, mac_is_fragment ** mifref, guint frame_num, guint16 tsn, guint maclength, guint offset, gboolean reverse)
{
    mac_is_sdu * head_sdu, * tail_sdu;
    mac_is_fragment * mif = *mifref;

    head_sdu = se_new(mac_is_sdu); /* SDU with head TSN and frame number. */
    tail_sdu = se_new(mac_is_sdu); /* SDU with tail TSN and frame number. */

    /* If reverse then we are sending in a head TSN and frame number. */
    if (reverse) {
        mac_is_sdu * temp = head_sdu;
        /* A tail comes in the TSN after a head. */
        head_sdu->tsn = tail_sdu->tsn = (tsn+1)%64;
        /* Swap. Head is tail, ehehehe. */
        head_sdu = tail_sdu;
        tail_sdu = temp;
    } else { /* Else we are sending in a tail TSN and frame number. */
        head_sdu->tsn = tail_sdu->tsn = tsn;
    }

    tail_sdu->frame_num = head_sdu->counterpart = frame_num;
    head_sdu->frame_num = tail_sdu->counterpart = mif->frame_num;
    tail_sdu->length = mif->length + maclength;
    tail_sdu->data = se_alloc(tail_sdu->length);
    head_sdu->length = 0;
    head_sdu->data = NULL;
    head_sdu->tvb = NULL;

    if (reverse == FALSE) {
        memcpy(tail_sdu->data, mif->data, mif->length);
        tvb_memcpy(tvb, tail_sdu->data+mif->length, offset, maclength);
    } else {
        tvb_memcpy(tvb, tail_sdu->data, offset, maclength);
        memcpy(tail_sdu->data+maclength, mif->data, mif->length);
    }
    g_free(mif->data);
    g_free(mif);
    tail_sdu->tvb = tvb_new_child_real_data(tvb, tail_sdu->data, tail_sdu->length, tail_sdu->length);
    g_hash_table_insert(mac_is_sdus, head_sdu, NULL);
    g_hash_table_insert(mac_is_sdus, tail_sdu, NULL);
    *mifref = NULL; /* Reset the pointer. */
    return tail_sdu->tvb;
}

static mac_is_sdu * get_sdu(tvbuff_t * tvb, packet_info * pinfo, guint16 tsn)
{
    gpointer orig_key = NULL;
    mac_is_sdu sdu_lookup_key;
    sdu_lookup_key.frame_num = pinfo->fd->num;
    sdu_lookup_key.tsn = tsn;

    if (g_hash_table_lookup_extended(mac_is_sdus, &sdu_lookup_key, &orig_key, NULL)) {
        mac_is_sdu * sdu = orig_key;
        if (sdu->length > 0) {
            sdu->tvb = tvb_new_child_real_data(tvb, sdu->data, sdu->length, sdu->length);
            add_new_data_source(pinfo, sdu->tvb, "Reassembled MAC-is SDU");
        }
        return sdu;
    }
    return NULL;
}

static tvbuff_t * add_to_tree(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, int id, guint16 tsn, guint offset, guint16 maclength)
{
    mac_is_sdu * sdu = get_sdu(tvb, pinfo, tsn);
    tvbuff_t * new_tvb = NULL;

    DISSECTOR_ASSERT(sdu != NULL);
    if (sdu->length > 0) {
        new_tvb = sdu->tvb;
        proto_tree_add_text(tree, new_tvb, 0, -1, "[Reassembled MAC-is SDU]");
        proto_tree_add_uint_format(tree, id, tvb, 0, 0, sdu->counterpart, "Reassembled with fragment in frame: %u", sdu->counterpart);
        proto_tree_add_item(tree, hf_mac_edch_type2_sdu_data, new_tvb, 0, -1, ENC_NA);
        return new_tvb;
    } else {
        new_tvb = tvb_new_subset(tvb, offset, maclength, -1);
        proto_tree_add_text(tree, new_tvb, 0, -1, "[This MAC-is SDU is the last segment of a MAC-d PDU or MAC-c PDU.]");
        proto_tree_add_item(tree, hf_mac_edch_type2_sdu_data, new_tvb, 0, -1, ENC_NA);
        proto_tree_add_uint(tree, id, tvb, 0, 0, sdu->counterpart);
        return NULL; /* No data here. */
    }
}

tvbuff_t * mac_is_add_fragment(tvbuff_t * tvb, packet_info *pinfo, proto_tree * tree, guint8 lchid, int offset, guint8 ss, guint16 tsn, int sdu_no, guint8 no_sdus, guint16 maclength)
{
    /* Get fragment table for this logical channel. */
    mac_is_fragment ** fragments = g_hash_table_lookup(mac_is_fragments, GINT_TO_POINTER((gint)lchid));
    /* If this is the first time we see this channel. */
    if (fragments == NULL) {
        /* Create new table */
        fragments = se_alloc_array(mac_is_fragment*, 64);
        memset(fragments, 0, sizeof(mac_is_fragment*)*64);
        g_hash_table_insert(mac_is_fragments, GINT_TO_POINTER((gint)lchid), fragments);
    }

    /* If in first scan-through. */
    if (pinfo->fd->flags.visited == FALSE) {
        /* If first SDU is last segment of previous. A tail. */
        if (sdu_no == 0 && (ss & 1) == 1) {
            /* If no one has inserted the head for our tail yet. */
            if (fragments[tsn] == NULL) {
                init_frag(tvb, &fragments[tsn], maclength, pinfo->fd->num, offset);
            /* If there is a head, attach a tail to it and return. */
            } else {
                return reassemble(tvb, &(fragments[tsn]), pinfo->fd->num, tsn, maclength, offset, FALSE);
            }
        }
        /* If last SDU is first segment of next. A head. */
        else if (sdu_no == no_sdus-1 && (ss & 2) == 2) {
            /* If there is no tail yet, store away a head for a future tail. */
            if (fragments[(tsn+1) % 64] == NULL) {
                init_frag(tvb, &(fragments[(tsn+1)%64]), maclength, pinfo->fd->num, offset);
            /* If there already is a tail for our head here, attach it. */
            } else {
                return reassemble(tvb, &fragments[(tsn+1)%64], pinfo->fd->num, tsn, maclength, offset, TRUE);
            }
        /* If our SDU is not fragmented. */
        } else {
            DISSECTOR_ASSERT((sdu_no == 0) ? (ss&1) == 0 : ((sdu_no == no_sdus-1) ? (ss&2) == 0 : TRUE));
            return tvb_new_subset(tvb, offset, maclength, -1);
        }
    /* If clicking on a packet. */
    } else if (tree) {
        /* If first SDU is last segment of previous. A tail. */
        if (sdu_no == 0 && (ss & 1) == 1) {
            return add_to_tree(tvb, pinfo, tree, hf_mac_is_2head_link, tsn, offset, maclength);
        /* If last SDU is first segment of next. A head. */
        } else if (sdu_no == no_sdus-1 && (ss & 2) == 2) {
            /* tsn+1 because reassembly is done in the tail which comes in the
             * TSN after the head. */
            mac_is_sdu * sdu = get_sdu(tvb, pinfo, (tsn+1)%64);
            tvbuff_t * new_tvb = NULL;

            DISSECTOR_ASSERT(sdu != NULL);
            if (sdu->length > 0) {
                new_tvb = sdu->tvb;
                proto_tree_add_text(tree, new_tvb, 0, -1, "[Reassembled MAC-is SDU]");
                proto_tree_add_uint_format(tree, hf_mac_is_2tail_link, tvb, 0, 0, sdu->counterpart, "Reassembled with fragment in frame: %u", sdu->counterpart);
                proto_tree_add_item(tree, hf_mac_edch_type2_sdu_data, new_tvb, 0, -1, ENC_NA);
                return new_tvb;
            } else {
                new_tvb = tvb_new_subset(tvb, offset, maclength, -1);
                proto_tree_add_text(tree, new_tvb, 0, -1, "[This MAC-is SDU is the first segment of a MAC-d PDU or MAC-c PDU.]");
                proto_tree_add_item(tree, hf_mac_edch_type2_sdu_data, new_tvb, 0, -1, ENC_NA);
                proto_tree_add_uint(tree, hf_mac_is_2tail_link, tvb, 0, 0, sdu->counterpart);
                return NULL; /* No data here. */
            }
        } else {
            tvbuff_t * new_tvb = tvb_new_subset(tvb, offset, maclength, -1);
            proto_tree_add_text(tree, new_tvb, 0, -1, "[This MAC-is SDU is a complete MAC-d PDU or MAC-c PDU]");
            proto_tree_add_item(tree, hf_mac_edch_type2_sdu_data, new_tvb, 0, -1, ENC_NA);
            return new_tvb;
        }
    }
    return NULL;
}

static void ss_interpretation(tvbuff_t * tvb, proto_tree * tree, guint8 ss, guint number_of_mac_is_sdus, guint offset)
{
    switch (ss) {
        case 0:
            if (number_of_mac_is_sdus > 1) {
                proto_tree_add_text(tree, tvb, offset, 1, "SS interpretation: The first MAC-is SDU of the MAC-is PDU is a complete MAC-d PDU or MAC-c PDU. The last MAC-is SDU of the MAC-is PDU is a complete MAC-d PDU or MAC-c PDU.");
            } else {
                proto_tree_add_text(tree, tvb, offset, 1, "SS interpretation: The MAC-is SDU of the MAC-is PDU is a complete MAC-d PDU or MAC-c PDU.");
            }
            break;
        case 1:
            if (number_of_mac_is_sdus > 1) {
                proto_tree_add_text(tree, tvb, offset, 1, "SS interpretation: The last MAC-is SDU of the MAC-is PDU is a complete MAC-d PDU or MAC-c PDU. The first MAC-is SDU of the MAC-is PDU is the last segment of a MAC-d PDU or MAC-c PDU.");
            } else {
                proto_tree_add_text(tree, tvb, offset, 1, "SS interpretation: The MAC-is SDU of the MAC-is PDU is the last segment of a MAC-d PDU or MAC-c PDU.");
            }
            break;
        case 2:
            if (number_of_mac_is_sdus > 1) {
                proto_tree_add_text(tree, tvb, offset, 1, "SS interpretation: The first MAC-is SDU of the MAC-is PDU is a complete MAC-d PDU or MAC-c PDU. The last MAC-is SDU of the MAC-is PDU is the first segment of a MAC-d PDU or MAC-c PDU.");
            } else {
                proto_tree_add_text(tree, tvb, offset, 1, "SS interpretation: The MAC-is SDU of the MAC-is PDU is the first segment of a MAC-d PDU or MAC-c PDU.");
            }
            break;
        case 3:
            if (number_of_mac_is_sdus > 1) {
                proto_tree_add_text(tree, tvb, offset, 1, "SS interpretation: The first MAC-is SDU of the MAC-is PDU is the last segment of a MAC-d PDU or MAC-c PDU and the last MAC-is SDU of MAC-is PDU is the first segment of a MAC-d PDU or MAC-c PDU.");
            } else {
                proto_tree_add_text(tree, tvb, offset, 1, "SS interpretation: The MAC-is SDU is a middle segment of a MAC-d PDU or MAC-c PDU.");
            }
            break;
    }
}

static void call_rlc(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, proto_item * ti, guint8 lchid)
{
    switch (lchId_type_table[lchid]) {
        case MAC_CONTENT_DCCH:
            proto_item_append_text(ti, " (DCCH)");
            call_dissector(rlc_dcch_handle, tvb, pinfo, tree);
            break;
        case MAC_CONTENT_PS_DTCH:
            proto_item_append_text(ti, " (PS DTCH)");
            call_dissector(rlc_ps_dtch_handle, tvb, pinfo, tree);
            break;
        case MAC_CONTENT_CS_DTCH:
            proto_item_append_text(ti, " (CS DTCH)");
            /* TODO */
            break;
        default:
            proto_item_append_text(ti, " (Unknown EDCH Content)");
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Unknown EDCH Content");
            break;
    }
}

/*
 * Dissect a MAC-is PDU.
 */
static void dissect_mac_fdd_edch_type2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    guint sdu_no, subframe_bytes = 0, offset = 0;
    guint8 ss;
    guint16 tsn;
    proto_item *pi;
    proto_tree *macis_pdu_tree, *macis_sdu_tree;
    umts_mac_is_info * mac_is_info = (umts_mac_is_info *)p_get_proto_data(pinfo->fd, proto_umts_mac);
    rlc_info * rlcinf = (rlc_info *)p_get_proto_data(pinfo->fd, proto_rlc);

    DISSECTOR_ASSERT(mac_is_info != NULL);
    DISSECTOR_ASSERT(rlcinf != NULL);

    pi = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
    macis_pdu_tree = proto_item_add_subtree(pi, ett_mac_edch_type2);

    /* SS */
    ss = (tvb_get_guint8(tvb, offset) & 0xc0) >> 6;
    proto_tree_add_item(macis_pdu_tree, hf_mac_edch_type2_ss, tvb, offset, 1, ENC_BIG_ENDIAN);

    ss_interpretation(tvb, macis_pdu_tree, ss, mac_is_info->number_of_mac_is_sdus, offset);

    /* TSN */
    tsn = tvb_get_bits8(tvb, offset*8+2, 6);
    proto_tree_add_item(macis_pdu_tree, hf_mac_edch_type2_tsn, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset++;

    /* MAC-is SDUs (i.e. MACd PDUs) */
    for (sdu_no=0; sdu_no < mac_is_info->number_of_mac_is_sdus; sdu_no++) {
        proto_item *ti;
        tvbuff_t * asm_tvb;
        guint8 lchid = mac_is_info->lchid[sdu_no]+1;
        guint sdulength = mac_is_info->sdulength[sdu_no];

        ti = proto_tree_add_item(tree, hf_mac_edch_type2_sdu, tvb, offset, sdulength, ENC_NA);
        macis_sdu_tree = proto_item_add_subtree(ti, ett_mac_edch_type2_sdu);
        proto_item_append_text(ti, " (Logical channel=%u, Len=%u)", lchid, sdulength);
        /*Set up information needed for MAC and lower layers*/
        rlcinf->mode[sdu_no] = lchId_rlc_map[lchid]; /* Set RLC mode by lchid to RLC_MODE map in nbap.h */
        rlcinf->urnti[sdu_no] = 1; /* TODO set proper value here */
        rlcinf->rbid[sdu_no] = lchid;
        rlcinf->li_size[sdu_no] = RLC_LI_7BITS;
        rlcinf->ciphered[sdu_no] = FALSE;
        rlcinf->deciphered[sdu_no] = FALSE;

        asm_tvb = mac_is_add_fragment(tvb, pinfo, macis_sdu_tree, lchid, offset, ss, tsn, sdu_no, mac_is_info->number_of_mac_is_sdus, sdulength);
        if (asm_tvb != NULL) {
            call_rlc(asm_tvb, pinfo, tree, ti, lchid);
        }

        offset += sdulength;
        subframe_bytes += sdulength;
    }

    proto_item_append_text(pi, "-is PDU (SS=%u, TSN=%u, %u bytes in %u SDU fragments)",
                           ss, tsn, subframe_bytes, mac_is_info->number_of_mac_is_sdus);

    proto_item_set_len(pi, 1+subframe_bytes);
    /*total_bytes += subframe_bytes;*/
}

static void dissect_mac_fdd_edch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree    *edch_tree = NULL;
    proto_item    *channel_type;
    umts_mac_info *macinf;
    fp_info       *fpinf;
    guint16        pos;
    proto_item    *ti        = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

    ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
    edch_tree = proto_item_add_subtree(ti, ett_mac_edch);

    fpinf  = (fp_info *)p_get_proto_data(pinfo->fd, proto_fp);

    macinf = (umts_mac_info *)p_get_proto_data(pinfo->fd, proto_umts_mac);
    if (!macinf|| !fpinf) {
        ti = proto_tree_add_text(edch_tree, tvb, 0, -1,
            "Cannot dissect MAC frame because per-frame info is missing");
          expert_add_info_format(pinfo,ti,PI_DEBUG,PI_ERROR,"MAC frame missing frame information!");
        return;
    }

    pos = fpinf->cur_tb;

    switch (macinf->content[pos]) {
        case MAC_CONTENT_DCCH:
            proto_item_append_text(ti, " (DCCH)");

            /*Show the logical channel id*/
            channel_type = proto_tree_add_uint(edch_tree, hf_mac_lch_id, tvb, 0, 0, macinf->lchid[pos]);
            PROTO_ITEM_SET_GENERATED(channel_type);

            channel_type = proto_tree_add_uint(edch_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
            PROTO_ITEM_SET_GENERATED(channel_type);


            call_dissector(rlc_dcch_handle, tvb, pinfo, tree);
            break;
        case MAC_CONTENT_PS_DTCH:
            proto_item_append_text(ti, " (PS DTCH)");

            /*Show the logical channel id*/
            channel_type = proto_tree_add_uint(edch_tree, hf_mac_lch_id, tvb, 0, 0, macinf->lchid[pos]);
            PROTO_ITEM_SET_GENERATED(channel_type);

            channel_type = proto_tree_add_uint(edch_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);
            PROTO_ITEM_SET_GENERATED(channel_type);

            call_dissector(rlc_ps_dtch_handle, tvb, pinfo, tree);
            break;
        case MAC_CONTENT_CS_DTCH:
            proto_item_append_text(ti, " (CS DTCH)");
            /* TODO */
            break;
        default:
            proto_item_append_text(ti, " (Unknown EDCH Content)");
            expert_add_info_format(pinfo, ti, PI_MALFORMED, PI_ERROR, "Unknown EDCH Content");
            break;
    }
}
/**
* Dissect hsdsch_common channel.
*
* This will dissect hsdsch common channels, we handle this seperately
* since we might have to deal with MAC-ehs and or MAC-c headers
* (in the MAC PDU).
*
* @param tvb
* @param pinfo
* @param tree
* @return Void.
*/
#if 0
static void dissect_mac_fdd_hsdsch_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
	proto_tree    *hsdsch_tree = NULL;
    /*proto_item    *channel_type;
    */
    fp_info       *fpinf;
    umts_mac_info *macinf;
    guint16        pos;
  /*  guint8         bitoffs=0;
    tvbuff_t      *next_tvb;
    */
    proto_item    *ti  = NULL;

    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

    ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
    hsdsch_tree = proto_item_add_subtree(ti, ett_mac_hsdsch);

	fpinf  = (fp_info *)p_get_proto_data(pinfo->fd, proto_fp);
	macinf = (umts_mac_info *)p_get_proto_data(pinfo->fd, proto_umts_mac);

	 if (!macinf) {
        proto_tree_add_text(hsdsch_tree, tvb, 0, -1,
            "Cannot dissect MAC frame because per-frame info is missing");
        expert_add_info_format(pinfo,ti,PI_MALFORMED,PI_ERROR,"Cannot dissect MAC frame because per-frame info is missing");
        return;
    }
    pos = fpinf->cur_tb;
    switch(macinf->content[pos]){
		/*In this case we don't have a MAC-c header 9.2.1.4*/

		/*
		case MAC_CONTENT_CCCH:

		break;
		case MAC_CONTENT_PCCH:

		break;

		case MAC_CONTENT_BCCH:

		break;
*/
		default:

			proto_item_append_text(ti, " (Unknown HSDSCH-Common Content)");
			expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Unknown HSDSCH-Common Content");
		break;
	}

}
#endif
/* to avoid unnecessary re-alignment, the 4 bit padding prepended to the HSDSCH in FP type 1
 * are handled in the MAC layer
 * If the C/T field is present, 'bitoffs' will be 8 (4 bit padding and 4 bit C/T) and
 * no re-alignment is necessary
 * If no C/T is present, the whole payload will be left-shifted by 4 bit
 */
static void dissect_mac_fdd_hsdsch(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree    *hsdsch_tree = NULL;
    proto_item    *channel_type;
    fp_info       *fpinf;
    umts_mac_info *macinf;
    guint16        pos;
    guint8         bitoffs=0;
    tvbuff_t      *next_tvb;
    proto_item    *ti          = NULL;
    rlc_info * rlcinf;

    /*struct rrc_info	*rrcinf = NULL;
    */
    col_set_str(pinfo->cinfo, COL_PROTOCOL, "MAC");

    ti = proto_tree_add_item(tree, proto_umts_mac, tvb, 0, -1, ENC_NA);
    hsdsch_tree = proto_item_add_subtree(ti, ett_mac_hsdsch);

    fpinf  = (fp_info *)p_get_proto_data(pinfo->fd, proto_fp);
    macinf = (umts_mac_info *)p_get_proto_data(pinfo->fd, proto_umts_mac);


    pos = fpinf->cur_tb;
#if 0
    if(pinfo->fd->num == 48 /*|| pinfo->fd->num == 594*/){

            rrcinf = p_get_proto_data(pinfo->fd, proto_rrc);
            if (!rrcinf) {
                rrcinf = se_alloc0(sizeof(struct rrc_info));
                p_add_proto_data(pinfo->fd, proto_rrc, rrcinf);
            }
            rrcinf->msgtype[fpinf->cur_tb] = RRC_MESSAGE_TYPE_BCCH_FACH;


	               next_tvb = tvb_new_subset(tvb, 0, tvb_length_remaining(tvb, 1), -1);
            call_dissector(rrc_handle, next_tvb, pinfo, tree);
            return;
	}
	    if(FALSE /*pinfo->fd->num == 594 || pinfo->fd->num == 594*/){

                              proto_item_append_text(ti, " (DCCH)");
                    channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);
                    PROTO_ITEM_SET_GENERATED(channel_type);
                     next_tvb = tvb_new_subset(tvb, 0, tvb_length_remaining(tvb, 0), tvb_length_remaining(tvb, 0));
                    add_new_data_source(pinfo, next_tvb, "Octet-Aligned DCCH Data");
                    call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);



            if(FALSE){
				 dissect_mac_fdd_hsdsch_common(tvb, pinfo, tree);
			}
            return;
	}
#endif
    bitoffs = fpinf->hsdsch_entity == ehs ? 0 : 4;	/*No MAC-d header for type 2*/

    if (!macinf) {
        proto_tree_add_text(hsdsch_tree, tvb, 0, -1,
            "Cannot dissect MAC frame because per-frame info is missing");
        expert_add_info_format(pinfo,ti,PI_MALFORMED,PI_ERROR,"Cannot dissect MAC frame because per-frame info is missing");
        return;
    }
    if (macinf->ctmux[pos]) {	/*The 4'st bits are padding*/
        proto_tree_add_bits_item(hsdsch_tree, hf_mac_ct, tvb, bitoffs, 4, ENC_BIG_ENDIAN);

        /*Sets the proper lchid, for later layers.*/
        macinf->lchid[pos] = tvb_get_bits8(tvb,bitoffs,4)+1;
        macinf->fake_chid[pos] = FALSE;
        macinf->content[pos] = lchId_type_table[macinf->lchid[pos]];	/*Lookup MAC content*/

        rlcinf = (rlc_info *)p_get_proto_data(pinfo->fd, proto_rlc);
        rlcinf->rbid[pos] = macinf->lchid[pos];
        rlcinf->mode[pos] =  lchId_rlc_map[macinf->lchid[pos]];	/*Look up RLC mode*/
        bitoffs += 4;
    }

   if ((bitoffs % 8) == 0) {
        next_tvb = tvb_new_subset_remaining(tvb, bitoffs/8);
    } else {
        next_tvb = tvb_new_octet_aligned(tvb, bitoffs, macinf->pdu_len);    /*Get rid of possible padding in at the end?*/
        add_new_data_source(pinfo, next_tvb, "Octet-Aligned HSDSCH Data");
    }

    switch (macinf->content[pos]) {
        case MAC_CONTENT_DCCH:
            proto_item_append_text(ti, " (DCCH)");
          /*  channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_channel_hsdsch, tvb, 0, 0, MAC_DCCH);
            PROTO_ITEM_SET_GENERATED(channel_type)*/
            /*Set the logical channel id if it exists */
            if(macinf->lchid[pos] != 255){
                channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_lch_id, tvb, 0, 0, macinf->lchid[pos]);
                PROTO_ITEM_SET_GENERATED(channel_type);
                if(macinf->fake_chid[pos]){
                    channel_type = proto_tree_add_text(hsdsch_tree, tvb,0, 0, "This is a faked logical channel id!");
                    PROTO_ITEM_SET_GENERATED(channel_type);
                }
            }else{
                channel_type = proto_tree_add_text(hsdsch_tree, tvb,0, 0, "Frame is missing logical channel");
                PROTO_ITEM_SET_GENERATED(channel_type);
            }

            /*Set the type of channel*/
            /*channel_type = proto_tree_add_text(hsdsch_tree, tvb,0, 0, "Logcial Channel Type: PS DTCH");
            PROTO_ITEM_SET_GENERATED(channel_type);
            */
            channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_channel, tvb, 0, 0, MAC_DCCH);

            PROTO_ITEM_SET_GENERATED(channel_type);

            /*Set the MACd-Flow ID*/
            channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_macdflowd_id, tvb, 0, 0, macinf->macdflow_id[pos]);
            PROTO_ITEM_SET_GENERATED(channel_type);
            call_dissector(rlc_dcch_handle, next_tvb, pinfo, tree);
            break;
        case MAC_CONTENT_PS_DTCH:
            proto_item_append_text(ti, " (PS DTCH)");

            /*Set the logical channel id if it exists */
            if(macinf->lchid[pos] != 255){
                channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_lch_id, tvb, 0, 0, macinf->lchid[pos]);
                PROTO_ITEM_SET_GENERATED(channel_type);
                    if(macinf->fake_chid[pos]){
                    channel_type = proto_tree_add_text(hsdsch_tree, tvb,0, 0, "This is a faked logical channel id!");
                    PROTO_ITEM_SET_GENERATED(channel_type);
                }
            }else{
                channel_type = proto_tree_add_text(hsdsch_tree, tvb,0, 0, "Frame is missing logical channel");
                PROTO_ITEM_SET_GENERATED(channel_type);
            }

            /*Sets the channel type*/
            channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_channel, tvb, 0, 0, MAC_DTCH);

            PROTO_ITEM_SET_GENERATED(channel_type);

            /*Set the MACd-Flow ID*/
            channel_type = proto_tree_add_uint(hsdsch_tree, hf_mac_macdflowd_id, tvb, 0, 0, macinf->macdflow_id[pos]);
            PROTO_ITEM_SET_GENERATED(channel_type);

            call_dissector(rlc_ps_dtch_handle, next_tvb, pinfo, tree);
            break;
        case MAC_CONTENT_CS_DTCH:
            proto_item_append_text(ti, " (CS DTCH)");
            break;
        default:
            proto_item_append_text(ti, " (Unknown HSDSCH Content)");
           expert_add_info_format(pinfo, NULL, PI_MALFORMED, PI_ERROR, "Unknown HSDSCH Content");
    }
}

static void mac_init(void)
{
    if (mac_is_sdus != NULL) {
        g_hash_table_destroy(mac_is_sdus);
    }
    if (mac_is_fragments != NULL) {
        g_hash_table_destroy(mac_is_fragments);
    }
    mac_is_sdus = g_hash_table_new(mac_is_sdu_hash, mac_is_sdu_equal);
    mac_is_fragments = g_hash_table_new(g_direct_hash, g_direct_equal);
}

void
proto_register_umts_mac(void)
{
    static gint *ett[] = {
        &ett_mac,
        &ett_mac_fach,
        &ett_mac_rach,
        &ett_mac_dch,
        &ett_mac_pch,
        &ett_mac_edch,
        &ett_mac_hsdsch,
        &ett_mac_edch_type2,
        &ett_mac_edch_type2_sdu
    };
    /** XX: Looks like some duplicate filter names ?? **/
    /** XX: May be OK: See doc/README.developer       **/
    static hf_register_info hf[] = {
        { &hf_mac_rach_fdd_tctf,
          { "Target Channel Type Field", "mac.tctf",
            FT_UINT8, BASE_HEX, VALS(rach_fdd_tctf_vals), 0, NULL, HFILL }
        },
        { &hf_mac_fach_fdd_tctf,
          { "Target Channel Type Field", "mac.tctf",
            FT_UINT8, BASE_HEX, VALS(fach_fdd_tctf_vals), 0, NULL, HFILL }
        },
        { &hf_mac_ct,
          { "C/T", "mac.ct",
            FT_UINT8, BASE_HEX, NULL, 0, NULL, HFILL }
        },
        { &hf_mac_ueid_type,
          { "UEID Type", "mac.ueid_type",
            FT_UINT8, BASE_DEC, VALS(ueid_type_vals), 0, NULL, HFILL }
        },
        { &hf_mac_crnti,
          { "C-RNTI (UEID)", "mac.ueid",
            FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mac_urnti,
          { "U-RNTI (UEID)", "mac.ueid",
            FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL }
        },
        { &hf_mac_channel,
          { "Logical Channel Type", "mac.logical_channel",
            FT_UINT16, BASE_DEC, VALS(mac_logical_channel_vals), 0, NULL, HFILL }
        },

         { &hf_mac_channel_str,
          { "Logical Channel", "mac.logical_channel",
            FT_STRING, BASE_NONE, NULL, 0, NULL, HFILL }
        },
         { &hf_mac_channel_hsdsch,
            { "MACd-FlowID", "mac.macd_flowid", FT_UINT16, BASE_DEC, NULL, 0x0,  NULL, HFILL }
        },
        { &hf_mac_macdflowd_id,
            { "MACd-FlowID", "mac.macd_flowid", FT_UINT16, BASE_DEC, NULL, 0x0,  NULL, HFILL }
        },
         { &hf_mac_lch_id,
            { "Logical Channel ID", "mac.logical_channel_id", FT_UINT16, BASE_DEC, NULL, 0x0,  NULL, HFILL }
        },
        { &hf_mac_trch_id,
            { "Transport Channel ID", "mac.transport_channel_id", FT_UINT16, BASE_DEC, NULL, 0x0,  NULL, HFILL }
        },
        { &hf_mac_edch_type2_descriptors,
          { "MAC-is Descriptors",
            "mac.edch.type2.descriptors", FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_mac_edch_type2_lchid,
          { "LCH-ID",
            "mac.logical_channel_id", FT_UINT8, BASE_HEX, NULL, 0xf0,
            NULL, HFILL
          }
        },
        { &hf_mac_edch_type2_length,
          { "Length",
            "mac.edch.type2.length", FT_UINT16, BASE_DEC, NULL, 0x0ffe,
            NULL, HFILL
          }
        },
        { &hf_mac_edch_type2_flag,
          { "Flag",
            "mac.edch.type2.lchid", FT_UINT8, BASE_HEX, NULL, 0x01,
            "Indicates if another entry follows", HFILL
          }
        },
        { &hf_mac_edch_type2_ss,
          { "SS",
            /* TODO: VALS */
            "mac.edch.type2.tsn", FT_UINT8, BASE_HEX, NULL, 0xc0,
            "Segmentation Status", HFILL
          }
        },
        { &hf_mac_edch_type2_tsn,
          { "TSN",
            "mac.edch.type2.tsn", FT_UINT8, BASE_DEC, NULL, 0x3f,
            "Transmission Sequence Number", HFILL
          }
        },
        { &hf_mac_edch_type2_sdu,
          { "MAC-is SDU",
            "mac.edch.type2.sdu", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_mac_edch_type2_sdu_data,
          { "Data",
            "mac.edch.type2.sdu.data", FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL
          }
        },
        { &hf_mac_edch_type2_subframe_header,
          { "Subframe header",
            "mac.edch.type2.subframeheader", FT_STRING, BASE_NONE, NULL, 0x0,
            "EDCH Subframe header", HFILL
          }
        },
        { &hf_mac_is_2tail_link,
          { "Reassembled in frame", "mac.is.taillink",
            FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }
        },
        { &hf_mac_is_2head_link,
          { "Reassembled in frame", "mac.is.headlink",
            FT_FRAMENUM, BASE_NONE, NULL, 0, NULL, HFILL }
        }
    };

    proto_umts_mac = proto_register_protocol("MAC", "MAC", "mac");
    proto_register_field_array(proto_umts_mac, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    register_dissector("mac.fdd.rach", dissect_mac_fdd_rach, proto_umts_mac);
    register_dissector("mac.fdd.fach", dissect_mac_fdd_fach, proto_umts_mac);
    register_dissector("mac.fdd.pch", dissect_mac_fdd_pch, proto_umts_mac);
    register_dissector("mac.fdd.dch", dissect_mac_fdd_dch, proto_umts_mac);
    register_dissector("mac.fdd.edch", dissect_mac_fdd_edch, proto_umts_mac);
    register_dissector("mac.fdd.edch.type2", dissect_mac_fdd_edch_type2, proto_umts_mac);
    register_dissector("mac.fdd.hsdsch", dissect_mac_fdd_hsdsch, proto_umts_mac);

    register_init_routine(mac_init);
}

void
proto_reg_handoff_umts_mac(void)
{
    rlc_pcch_handle    = find_dissector("rlc.pcch");
    rlc_ccch_handle    = find_dissector("rlc.ccch");
    rlc_ctch_handle    = find_dissector("rlc.ctch");
    rlc_dcch_handle    = find_dissector("rlc.dcch");
    rlc_ps_dtch_handle = find_dissector("rlc.ps_dtch");

    rrc_handle = find_dissector("rrc");
}
