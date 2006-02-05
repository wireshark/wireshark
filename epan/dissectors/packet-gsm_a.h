/* packet-gsm_a.h
 *
 * $Id$
 *
 * Copyright 2003, Michael Lum <mlum [AT] telostech.com>,
 * In association with Telos Technology Inc.
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */

/*
 * this enum must be kept in-sync with 'gsm_a_pd_str'
 * it is used as an index into the array
 */
typedef enum
{
    PD_GCC = 0,
    PD_BCC,
    PD_RSVD_1,
    PD_CC,
    PD_GTTP,
    PD_MM,
    PD_RR,
    PD_UNK_1,
    PD_GMM,
    PD_SMS,
    PD_SM,
    PD_SS,
    PD_LCS,
    PD_UNK_2,
    PD_RSVD_EXT,
    PD_RSVD_TEST
}
gsm_a_pd_str_e;

typedef struct _gsm_a_tap_rec_t {
    /*
     * value from packet-bssap.h
     */
    guint8		pdu_type;
    guint8		message_type;
    gsm_a_pd_str_e	protocol_disc;
} gsm_a_tap_rec_t;

void dissect_bssmap(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree);

void dtap_mm_mm_info(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);

guint8 de_lai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_mid(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 be_cell_id_list(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_cell_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_ms_cm_1(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);
guint8 de_ms_cm_2(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_sm_apn(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_sm_qos(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_sm_pflow_id(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_gmm_drx_param(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_gmm_ms_net_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_gmm_rai(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_gmm_ms_radio_acc_cap(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_rr_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_cip_mode_set(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_cell_dsc(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_ch_mode(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_cm_enq_mask(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_tlli(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);
guint8 de_rr_sus_cau(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string, int string_len);

guint8 de_rej_cause(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len, gchar *add_string _U_, int string_len _U_);
void dtap_rr_ho_cmd(tvbuff_t *tvb, proto_tree *tree, guint32 offset, guint len);

/*
 * the following allows TAP code access to the messages
 * without having to duplicate it. With MSVC and a 
 * libethereal.dll, we need a special declaration.
 */
ETH_VAR_IMPORT const value_string gsm_a_bssmap_msg_strings[];
ETH_VAR_IMPORT const value_string gsm_a_dtap_msg_mm_strings[];
ETH_VAR_IMPORT const value_string gsm_a_dtap_msg_rr_strings[];
ETH_VAR_IMPORT const value_string gsm_a_dtap_msg_cc_strings[];
ETH_VAR_IMPORT const value_string gsm_a_dtap_msg_gmm_strings[];
ETH_VAR_IMPORT const value_string gsm_a_dtap_msg_sms_strings[];
ETH_VAR_IMPORT const value_string gsm_a_dtap_msg_sm_strings[];
ETH_VAR_IMPORT const value_string gsm_a_dtap_msg_ss_strings[];
ETH_VAR_IMPORT const gchar *gsm_a_pd_str[];

extern const value_string gsm_a_qos_del_of_err_sdu_vals[];
extern const value_string gsm_a_qos_del_order_vals[];
extern const value_string gsm_a_qos_traffic_cls_vals[];
extern const value_string gsm_a_qos_ber_vals[];
extern const value_string gsm_a_qos_sdu_err_rat_vals[];
extern const value_string gsm_a_qos_traff_hdl_pri_vals[];

extern const value_string gsm_a_type_of_number_values[];
extern const value_string gsm_a_numbering_plan_id_values[]; 

