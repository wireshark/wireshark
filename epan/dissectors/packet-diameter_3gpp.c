/* packet-diameter_3gpp.c
 * Routines for dissecting 3GPP OctetSting AVP:s
 * Copyright 2008, Anders Broman <anders.broman[at]ericsson.com>
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

 /* This dissector registers a dissector table for 3GPP Vendor specific
  * AVP:s which will be called from the Diameter dissector to dissect
  * the content of AVP:s of the OctetString type(or similar).
  */

#include "config.h"

#include <epan/packet.h>
#include <epan/expert.h>

#include "packet-diameter.h"
#include "packet-gsm_a_common.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-ntp.h"
#include "packet-sip.h"

void proto_register_diameter_3gpp(void);
void proto_reg_handoff_diameter_3gpp(void);

static expert_field ei_diameter_3gpp_plmn_id_wrong_len = EI_INIT;

/* Initialize the protocol and registered fields */
static int proto_diameter_3gpp          = -1;

static int hf_diameter_3gpp_timezone                = -1;
static int hf_diameter_3gpp_timezone_adjustment     = -1;
static int hf_diameter_3gpp_rat_type                = -1;
static int hf_diameter_3gpp_visited_nw_id           = -1;
static int hf_diameter_3gpp_path                    = -1;
static int hf_diameter_3gpp_contact                 = -1;
/* static int hf_diameter_3gpp_user_data               = -1; */
static int hf_diameter_3gpp_ipaddr                  = -1;
static int hf_diameter_3gpp_mbms_required_qos_prio  = -1;
static int hf_diameter_3gpp_tmgi                    = -1;
static int hf_diameter_3gpp_service_ind             = -1;
static int hf_diameter_mbms_service_id              = -1;
static int hf_diameter_3gpp_spare_bits = -1;
static int hf_diameter_3gpp_uar_flags_flags = -1;
static int hf_diameter_3gpp_uar_flags_flags_bit0 = -1;
static int hf_diameter_3gpp_feature_list_flags = -1;
static int hf_diameter_3gpp_cx_feature_list_flags = -1;
static int hf_diameter_3gpp_cx_feature_list_1_flags_bit0 = -1;
static int hf_diameter_3gpp_cx_feature_list_1_flags_bit1 = -1;
static int hf_diameter_3gpp_cx_feature_list_1_flags_bit2 = -1;
static int hf_diameter_3gpp_cx_feature_list_1_flags_bit3 = -1;
static int hf_diameter_3gpp_cx_feature_list_1_flags_spare_bits = -1;
static int hf_diameter_3gpp_feature_list1_sh_flags_bit0 = -1;
static int hf_diameter_3gpp_feature_list1_sh_flags_bit1 = -1;
static int hf_diameter_3gpp_feature_list1_sh_flags_bit2 = -1;
static int hf_diameter_3gpp_feature_list1_sh_flags_bit3 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit0 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit1 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit2 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit3 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit4 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit5 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit6 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit7 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit8 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit9 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit10 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit11 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit12 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit13 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit14 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit15 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit16 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit17 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit18 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit19 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit20 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit21 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit22 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit23 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit24 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit25 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit26 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit27 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit28 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit29 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit30 = -1;
static int hf_diameter_3gpp_feature_list1_s6a_flags_bit31 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit0 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit1 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit2 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit3 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit4 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit5 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit6 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit7 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit8 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit9 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit10 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit11 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit12 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit13 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit14 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit15 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit16 = -1;
static int hf_diameter_3gpp_feature_list2_s6a_flags_bit17 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit0 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit1 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit2 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit3 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit4 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit5 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit6 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit7 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit8 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit9 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit10 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit11 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit12 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit13 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit14 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit15 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit16 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit17 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit18 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit19 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit20 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit21 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit22 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit23 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit24 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit25 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit26 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit27 = -1;
static int hf_diameter_3gpp_feature_list_gx_flags_bit28 = -1;
static int hf_diameter_3gpp_cms_no_gyn_session_serv_not_allowed = -1;
static int hf_diameter_3gpp_cms_no_gyn_session_serv_allowed = -1;
static int hf_diameter_3gpp_cms_rating_failed = -1;
static int hf_diameter_3gpp_cms_user_unknown = -1;
static int hf_diameter_3gpp_cms_auth_rej = -1;
static int hf_diameter_3gpp_cms_credit_ctrl_not_applicable = -1;
static int hf_diameter_3gpp_cms_end_user_serv_status = -1;
static int hf_diameter_3gpp_qos_subscribed = -1;
static int hf_diameter_3gpp_qos_reliability_cls = -1;
static int hf_diameter_3gpp_qos_prec_class = -1;
static int hf_diameter_3gpp_qos_delay_cls = -1;
static int hf_diameter_3gpp_qos_peak_thr = -1;
static int hf_diameter_3gpp_qos_mean_thr = -1;
static int hf_diameter_3gpp_qos_al_ret_priority = -1;
static int hf_diameter_3gpp_qos_del_of_err_sdu = -1;
static int hf_diameter_3gpp_qos_del_order = -1;
static int hf_diameter_3gpp_qos_traffic_cls = -1;
static int hf_diameter_3gpp_qos_maximum_sdu_size = -1;
static int hf_diameter_3gpp_qos_max_bitrate_upl = -1;
static int hf_diameter_3gpp_qos_max_bitrate_downl = -1;
static int hf_diameter_3gpp_qos_sdu_err_rat = -1;
static int hf_diameter_3gpp_qos_ber = -1;
static int hf_diameter_3gpp_qos_traff_hdl_pri = -1;
static int hf_diameter_3gpp_qos_trans_delay = -1;
static int hf_diameter_3gpp_qos_guar_bitrate_upl = -1;
static int hf_diameter_3gpp_qos_guar_bitrate_downl = -1;
static int hf_diameter_3gpp_qos_source_stat_desc = -1;
static int hf_diameter_3gpp_qos_signalling_ind  = -1;
static int hf_diameter_3gpp_qos_max_bitrate_downl_ext = -1;
static int hf_diameter_3gpp_qos_guar_bitrate_downl_ext = -1;
static int hf_diameter_3gpp_qos_max_bitrate_upl_ext = -1;
static int hf_diameter_3gpp_qos_guar_bitrate_upl_ext = -1;
static int hf_diameter_3gpp_qos_pre_emption_vulnerability = -1;
static int hf_diameter_3gpp_qos_priority_level = -1;
static int hf_diameter_3gpp_qos_pre_emption_capability = -1;
static int hf_diameter_3gpp_ulr_flags = -1;
static int hf_diameter_3gpp_ulr_flags_bit0 = -1;
static int hf_diameter_3gpp_ulr_flags_bit1 = -1;
static int hf_diameter_3gpp_ulr_flags_bit2 = -1;
static int hf_diameter_3gpp_ulr_flags_bit3 = -1;
static int hf_diameter_3gpp_ulr_flags_bit4 = -1;
static int hf_diameter_3gpp_ulr_flags_bit5 = -1;
static int hf_diameter_3gpp_ulr_flags_bit6 = -1;
static int hf_diameter_3gpp_ulr_flags_bit7 = -1;
static int hf_diameter_3gpp_ula_flags = -1;
static int hf_diameter_3gpp_ula_flags_bit0 = -1;
static int hf_diameter_3gpp_ula_flags_bit1 = -1;
static int hf_diameter_3gpp_dsr_flags = -1;
static int hf_diameter_3gpp_dsr_flags_bit0 = -1;
static int hf_diameter_3gpp_dsr_flags_bit1 = -1;
static int hf_diameter_3gpp_dsr_flags_bit2 = -1;
static int hf_diameter_3gpp_dsr_flags_bit3 = -1;
static int hf_diameter_3gpp_dsr_flags_bit4 = -1;
static int hf_diameter_3gpp_dsr_flags_bit5 = -1;
static int hf_diameter_3gpp_dsr_flags_bit6 = -1;
static int hf_diameter_3gpp_dsr_flags_bit7 = -1;
static int hf_diameter_3gpp_dsr_flags_bit8 = -1;
static int hf_diameter_3gpp_dsr_flags_bit9 = -1;
static int hf_diameter_3gpp_dsr_flags_bit10 = -1;
static int hf_diameter_3gpp_dsr_flags_bit11 = -1;
static int hf_diameter_3gpp_dsr_flags_bit12 = -1;
static int hf_diameter_3gpp_dsr_flags_bit13 = -1;
static int hf_diameter_3gpp_dsr_flags_bit14 = -1;
static int hf_diameter_3gpp_dsr_flags_bit15 = -1;
static int hf_diameter_3gpp_dsr_flags_bit16 = -1;
static int hf_diameter_3gpp_dsr_flags_bit17 = -1;
static int hf_diameter_3gpp_dsr_flags_bit18 = -1;
static int hf_diameter_3gpp_dsa_flags = -1;
static int hf_diameter_3gpp_dsa_flags_bit0 = -1;
static int hf_diameter_3gpp_ida_flags = -1;
static int hf_diameter_3gpp_ida_flags_bit0 = -1;
static int hf_diameter_3gpp_pua_flags = -1;
static int hf_diameter_3gpp_pua_flags_bit0 = -1;
static int hf_diameter_3gpp_pua_flags_bit1 = -1;
static int hf_diameter_3gpp_nor_flags = -1;
static int hf_diameter_3gpp_nor_flags_bit0 = -1;
static int hf_diameter_3gpp_nor_flags_bit1 = -1;
static int hf_diameter_3gpp_nor_flags_bit2 = -1;
static int hf_diameter_3gpp_nor_flags_bit3 = -1;
static int hf_diameter_3gpp_nor_flags_bit4 = -1;
static int hf_diameter_3gpp_nor_flags_bit5 = -1;
static int hf_diameter_3gpp_nor_flags_bit6 = -1;
static int hf_diameter_3gpp_nor_flags_bit7 = -1;
static int hf_diameter_3gpp_nor_flags_bit8 = -1;
static int hf_diameter_3gpp_nor_flags_bit9 = -1;
static int hf_diameter_3gpp_idr_flags = -1;
static int hf_diameter_3gpp_idr_flags_bit0 = -1;
static int hf_diameter_3gpp_idr_flags_bit1 = -1;
static int hf_diameter_3gpp_idr_flags_bit2 = -1;
static int hf_diameter_3gpp_idr_flags_bit3 = -1;
static int hf_diameter_3gpp_idr_flags_bit4 = -1;
static int hf_diameter_3gpp_idr_flags_bit5 = -1;
static int hf_diameter_3gpp_idr_flags_bit6 = -1;
static int hf_diameter_3gpp_idr_flags_bit7 = -1;
static int hf_diameter_3gpp_idr_flags_bit8 = -1;
static int hf_diameter_3gpp_ipv6addr = -1;
static int hf_diameter_3gpp_mbms_abs_time_ofmbms_data_tfer = -1;
static int hf_diameter_3gpp_udp_port = -1;
static int hf_diameter_3gpp_imeisv = -1;
static int hf_diameter_3gpp_af_charging_identifier = -1;
static int hf_diameter_3gpp_af_application_identifier = -1;
static int hf_diameter_3gpp_charging_rule_name = -1;
static int hf_diameter_3gpp_mbms_bearer_event = -1;
static int hf_diameter_3gpp_mbms_bearer_event_bit0 = -1;
static int hf_diameter_3gpp_mbms_bearer_result = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit0 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit1 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit2 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit3 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit4 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit5 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit6 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit7 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit8 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit9 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit10 = -1;
static int hf_diameter_3gpp_mbms_bearer_result_bit11 = -1;
static int hf_diameter_3gpp_tmgi_allocation_result = -1;
static int hf_diameter_3gpp_tmgi_allocation_result_bit0 = -1;
static int hf_diameter_3gpp_tmgi_allocation_result_bit1 = -1;
static int hf_diameter_3gpp_tmgi_allocation_result_bit2 = -1;
static int hf_diameter_3gpp_tmgi_allocation_result_bit3 = -1;
static int hf_diameter_3gpp_tmgi_allocation_result_bit4 = -1;
static int hf_diameter_3gpp_tmgi_deallocation_result = -1;
static int hf_diameter_3gpp_tmgi_deallocation_result_bit0 = -1;
static int hf_diameter_3gpp_tmgi_deallocation_result_bit1 = -1;
static int hf_diameter_3gpp_tmgi_deallocation_result_bit2 = -1;
static int hf_diameter_3gpp_sar_flags = -1;
static int hf_diameter_3gpp_sar_flags_flags_bit0 = -1;

static gint diameter_3gpp_path_ett = -1;
static gint diameter_3gpp_feature_list_ett = -1;
static gint diameter_3gpp_uar_flags_ett = -1;
static gint diameter_3gpp_tmgi_ett  = -1;
static gint diameter_3gpp_cms_ett = -1;
static gint diameter_3gpp_qos_subscribed_ett = -1;
static gint diameter_3gpp_ulr_flags_ett = -1;
static gint diameter_3gpp_ula_flags_ett = -1;
static gint diameter_3gpp_dsr_flags_ett = -1;
static gint diameter_3gpp_dsa_flags_ett = -1;
static gint diameter_3gpp_ida_flags_ett = -1;
static gint diameter_3gpp_pua_flags_ett = -1;
static gint diameter_3gpp_nor_flags_ett = -1;
static gint diameter_3gpp_idr_flags_ett = -1;
static gint diameter_3gpp_mbms_bearer_event_ett = -1;
static gint diameter_3gpp_mbms_bearer_result_ett = -1;
static gint diameter_3gpp_tmgi_allocation_result_ett = -1;
static gint diameter_3gpp_tmgi_deallocation_result_ett = -1;
static gint diameter_3gpp_sar_flags_ett = -1;


/* Dissector handles */
static dissector_handle_t xml_handle;

/* Forward declarations */
static int dissect_diameter_3gpp_ipv6addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_);

/* AVP Code: 15 3GPP-SGSN-IPv6-Address */
static int
dissect_diameter_3gpp_sgsn_ipv6_address(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    /* 3GPP AVP code 15 has a conflict between imscxdx.xml (where the AVP
    * contains an Unsigned32 enum) and TGPPGmb.xml (where the AVP contains
    * an OctetString IPv6 address).  This function decodes the latter; we
    * (silently) abort dissection if the length is 4 on the assumption that
    * the old IMS AVP is what we're decoding.
    */
    if (tvb_reported_length(tvb) == 4)
        return 4;

    return dissect_diameter_3gpp_ipv6addr(tvb, pinfo, tree, data);

}

/* AVP Code: 20 3GPP-IMEISV
* 3GPP TS 29.061
*/

static int
dissect_diameter_3gpp_imeisv(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_item *item;
    int offset = 0, i;
    int length = tvb_reported_length(tvb);
    diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;

    if (tree){
        for (i = 0; i < length; i++)
            if (!g_ascii_isprint(tvb_get_guint8(tvb, i)))
                return length;

        item = proto_tree_add_item_ret_string(tree, hf_diameter_3gpp_imeisv, tvb, offset, length,
                                              ENC_UTF_8 | ENC_NA, wmem_packet_scope(), (const guint8**)&diam_sub_dis->avp_str);
        PROTO_ITEM_SET_GENERATED(item);
    }

    return length;
}

/* AVP Code: 21 3GPP-RAT-Type
* 3GPP TS 29.061, 29.274
*/
static const value_string diameter_3gpp_rat_type_vals[] = {
    { 0, "Reserved" },
    { 1, "UTRAN" },
    { 2, "GERAN" },
    { 3, "WLAN" },
    { 4, "GAN" },
    { 5, "HSPA Evolution" },
    { 6, "EUTRAN (WB-E-UTRAN)" },
    { 7, "Virtual" },
    { 8, "EUTRAN-NB-IoT" },
    { 101, "IEEE 802.16e" },
    { 102, "3GPP2 eHRPD" },
    { 103, "3GPP2 HRPD" },
    { 104, "3GPP2 1xRTT" },
    { 105, "3GPP2 UMB" },
    { 0, NULL }
};

static int
dissect_diameter_3gpp_rat_type(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    int length = tvb_reported_length(tvb);

    proto_tree_add_item(tree, hf_diameter_3gpp_rat_type, tvb, offset, 1, ENC_BIG_ENDIAN);

    return length;
}

/* AVP Code: 23 3GPP-MS-TimeZone
 * 3GPP TS 29.061
 */
static const value_string daylight_saving_time_vals[] = {
    {0, "No adjustment"},
    {1, "+1 hour adjustment for Daylight Saving Time"},
    {2, "+2 hours adjustment for Daylight Saving Time"},
    {3, "Reserved"},
    {0, NULL}
};

static int
dissect_diameter_3gpp_ms_timezone(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    int offset = 0;
    guint8      oct, hours, minutes;
    char        sign;
    diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;

    /* 3GPP TS 23.040 version 6.6.0 Release 6
     * 9.2.3.11 TP-Service-Centre-Time-Stamp (TP-SCTS)
     * :
     * The Time Zone indicates the difference, expressed in quarters of an hour,
     * between the local time and GMT. In the first of the two semi-octets,
     * the first bit (bit 3 of the seventh octet of the TP-Service-Centre-Time-Stamp field)
     * represents the algebraic sign of this difference (0: positive, 1: negative).
     */

    oct = tvb_get_guint8(tvb, offset);
    sign = (oct & 0x08) ? '-' : '+';
    oct = (oct >> 4) + (oct & 0x07) * 10;
    hours =  oct / 4;
    minutes = oct % 4 * 15;

    proto_tree_add_uint_format_value(tree, hf_diameter_3gpp_timezone, tvb, offset, 1, oct, "GMT %c %d hours %d minutes", sign, hours, minutes);
    offset++;

    oct = tvb_get_guint8(tvb, offset) & 0x3;
    proto_tree_add_item(tree, hf_diameter_3gpp_timezone_adjustment, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    diam_sub_dis->avp_str = wmem_strdup_printf(wmem_packet_scope(), "Timezone: GMT %c %d hours %d minutes %s",
        sign,
        hours,
        minutes,
        val_to_str_const(oct, daylight_saving_time_vals, "Unknown"));

    return offset;
}
/*
* AVP Code: 504 AF-Application-Identifier
*/

static int
dissect_diameter_3gpp_af_application_identifier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_item *item;
    int offset = 0, i;
    int length = tvb_reported_length(tvb);
    diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;

    if (tree){
        for (i = 0; i < length; i++)
            if (!g_ascii_isprint(tvb_get_guint8(tvb, i)))
                return length;

        item = proto_tree_add_item_ret_string(tree, hf_diameter_3gpp_af_application_identifier, tvb, offset, length,
                                                ENC_UTF_8 | ENC_NA, wmem_packet_scope(), (const guint8**)&diam_sub_dis->avp_str);
        PROTO_ITEM_SET_GENERATED(item);
    }

    return length;
}

/*
* AVP Code: 505 AF-Charging-Identifier
*/

static int
dissect_diameter_3gpp_af_charging_identifier(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_item *item;
    int offset = 0, i;
    int length = tvb_reported_length(tvb);
    diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;

    if (tree){
        for (i = 0; i < length; i++)
            if (!g_ascii_isprint(tvb_get_guint8(tvb, i)))
                return length;

        item = proto_tree_add_item_ret_string(tree, hf_diameter_3gpp_af_charging_identifier, tvb, offset, length,
                                              ENC_UTF_8 | ENC_NA, wmem_packet_scope(), (const guint8**)&diam_sub_dis->avp_str);
        PROTO_ITEM_SET_GENERATED(item);
    }

    return length;
}

/* AVP Code: 600 Visited-Network-Identifier
 * imscxdx.xml
 * 6.3.1 Visited-Network-Identifier AVP
 * The Visited-Network-Identifier AVP is of type OctetString. This AVP contains an identifier that helps the home
 * network to identify the visited network (e.g. the visited network domain name).
 */

static int
dissect_diameter_3gpp_visited_nw_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    int offset = 0, i;
    int length = tvb_reported_length(tvb);

    for(i = 0; i < length; i++)
        if(!g_ascii_isprint(tvb_get_guint8(tvb, i)))
            return length;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_visited_nw_id, tvb, offset, length, ENC_ASCII|ENC_NA);
    PROTO_ITEM_SET_GENERATED(item);


    return length;
}

/* AVP Code: 601 Public-Identity
 * TGPP.xml
 * 6.3.2 Public-Identity AVP
 * The Public-Identity AVP is of type UTF8String. This AVP contains the public identity of a user in the IMS. The syntax
 * of this AVP corresponds either to a SIP URL (with the format defined in IETF RFC 3261 [3] and IETF RFC 2396 [4])
 * or a TEL URL (with the format defined in IETF RFC 3966 [8]). Both SIP URL and TEL URL shall be in canonical
 * form, as described in 3GPP TS 23.003 [13].
 */
static int
dissect_diameter_3gpp_public_identity(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int length = tvb_reported_length(tvb);

    dfilter_store_sip_from_addr(tvb, tree, 0, length);

    return length;

}

/* AVP Code: 629 Feature-List-id
 * Feature list Id is neede to dissect Feature list in S6a/S6d application
 * Ref 3GPP TS 29.272
 */

static int
dissect_diameter_3gpp_feature_list_id(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
    diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;

    if(diam_sub_dis_inf) {
        diam_sub_dis_inf->feature_list_id = tvb_get_ntohl(tvb,0);
    }

    return 4;
}

/* AVP Code: 637 UAR-Flags
 * imscxdx.xml
 * IMS Cx Dx AVPS 3GPP TS 29.229
 */

static int
dissect_diameter_3gpp_uar_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item       = proto_tree_add_item(tree, hf_diameter_3gpp_uar_flags_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree   = proto_item_add_subtree(item, diameter_3gpp_uar_flags_ett);

    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 31, ENC_BIG_ENDIAN);
    bit_offset+=31;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_uar_flags_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;

    return offset;
}

/* AVP Code: 630 Feature-List
 * Interpretation depends on Application Id
 * imscxdx.xml
 * IMS Cx Dx AVPS 3GPP TS 29.229
 */
static const int *diameter_3gpp_cx_feature_list_1_fields[] = {
    &hf_diameter_3gpp_cx_feature_list_1_flags_spare_bits,
    &hf_diameter_3gpp_cx_feature_list_1_flags_bit3,
    &hf_diameter_3gpp_cx_feature_list_1_flags_bit2,
    &hf_diameter_3gpp_cx_feature_list_1_flags_bit1,
    &hf_diameter_3gpp_cx_feature_list_1_flags_bit0,
    NULL
};

/* TS 129 212 V12.9.0 (2015-07) */
static const int *diameter_3gpp_gx_feature_list_1_fields[] = {
    &hf_diameter_3gpp_feature_list_gx_flags_bit28,
    &hf_diameter_3gpp_feature_list_gx_flags_bit27,
    &hf_diameter_3gpp_feature_list_gx_flags_bit26,
    &hf_diameter_3gpp_feature_list_gx_flags_bit25,
    &hf_diameter_3gpp_feature_list_gx_flags_bit24,
    &hf_diameter_3gpp_feature_list_gx_flags_bit23,
    &hf_diameter_3gpp_feature_list_gx_flags_bit22,
    &hf_diameter_3gpp_feature_list_gx_flags_bit21,
    &hf_diameter_3gpp_feature_list_gx_flags_bit20,
    &hf_diameter_3gpp_feature_list_gx_flags_bit19,
    &hf_diameter_3gpp_feature_list_gx_flags_bit18,
    &hf_diameter_3gpp_feature_list_gx_flags_bit17,
    &hf_diameter_3gpp_feature_list_gx_flags_bit16,
    &hf_diameter_3gpp_feature_list_gx_flags_bit15,
    &hf_diameter_3gpp_feature_list_gx_flags_bit14,
    &hf_diameter_3gpp_feature_list_gx_flags_bit13,
    &hf_diameter_3gpp_feature_list_gx_flags_bit12,
    &hf_diameter_3gpp_feature_list_gx_flags_bit11,
    &hf_diameter_3gpp_feature_list_gx_flags_bit10,
    &hf_diameter_3gpp_feature_list_gx_flags_bit9,
    &hf_diameter_3gpp_feature_list_gx_flags_bit8,
    &hf_diameter_3gpp_feature_list_gx_flags_bit7,
    &hf_diameter_3gpp_feature_list_gx_flags_bit6,
    &hf_diameter_3gpp_feature_list_gx_flags_bit5,
    &hf_diameter_3gpp_feature_list_gx_flags_bit4,
    &hf_diameter_3gpp_feature_list_gx_flags_bit3,
    &hf_diameter_3gpp_feature_list_gx_flags_bit2,
    &hf_diameter_3gpp_feature_list_gx_flags_bit1,
    &hf_diameter_3gpp_feature_list_gx_flags_bit0,
    NULL
};

static int
dissect_diameter_3gpp_feature_list(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset, application_id = 0, feature_list_id = 0;
    diam_sub_dis_t *diam_sub_dis_inf = (diam_sub_dis_t*)data;

    if(diam_sub_dis_inf) {
        application_id = diam_sub_dis_inf->application_id;
        feature_list_id = diam_sub_dis_inf->feature_list_id;
    }

    bit_offset = 0;
    switch (application_id) {
    case DIAM_APPID_3GPP_CX:
        proto_tree_add_bitmask_with_flags(tree, tvb, 0, hf_diameter_3gpp_cx_feature_list_flags,
            diameter_3gpp_feature_list_ett, diameter_3gpp_cx_feature_list_1_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);
        break;
    case DIAM_APPID_3GPP_SH:
        item = proto_tree_add_item(tree, hf_diameter_3gpp_feature_list_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(item, diameter_3gpp_feature_list_ett);
        proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 28, ENC_BIG_ENDIAN);
        bit_offset += 28;
        proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_sh_flags_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;
        proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_sh_flags_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;
        proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_sh_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;
        proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_sh_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        bit_offset++;
        break;
    case DIAM_APPID_3GPP_S6A_S6D:
        item = proto_tree_add_item(tree, hf_diameter_3gpp_feature_list_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
        sub_tree = proto_item_add_subtree(item, diameter_3gpp_feature_list_ett);
        if (feature_list_id == 1) {
            /* 3GPP TS 29.272 Table 7.3.10/1: Features of Feature-List-ID 1 used in S6a/S6d */
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit31, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit30, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit29, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit28, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit27, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit26, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit25, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit24, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit23, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit22, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit21, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit20, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit19, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit18, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit17, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit16, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit15, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit14, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit13, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit12, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit11, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit10, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit9, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit8, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit7, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit6, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit5, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit4, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list1_s6a_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        }
        else if (feature_list_id == 2) {
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 14, ENC_BIG_ENDIAN);
            bit_offset += 14;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit17, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit16, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit15, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit14, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit13, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit12, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit11, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit10, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit9, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit8, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit7, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit6, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit5, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit4, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
            bit_offset++;
            proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_feature_list2_s6a_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
        }
        break;
    case DIAM_APPID_3GPP_GX: /* TS 129 212 V12.9.0 (2015-07) */
        proto_tree_add_bitmask_with_flags(tree, tvb, 0, hf_diameter_3gpp_feature_list_gx_flags,
            diameter_3gpp_feature_list_ett, diameter_3gpp_gx_feature_list_1_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

        break;
    default:
        break;
    }

    return 4;

}

/* AVP Code: 640 Path
 * imscxdx.xml
 * IMS Cx Dx AVPS 3GPP TS 29.229
 * 6.3.47 Path AVP
 * The Path AVP is of type OctetString and it contains a comma separated list of SIP proxies in the Path header as defined
 * in IETF RFC 3327 [17].
 */
static int
dissect_diameter_3gpp_path(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree *sub_tree;
    int offset = 0, comma_offset;
    int end_offset = tvb_reported_length(tvb) - 1;

    sub_tree = proto_tree_add_subtree(tree, tvb, offset, -1, diameter_3gpp_path_ett, NULL, "Paths");

    while (offset < end_offset) {
        comma_offset = tvb_find_guint8(tvb, offset, -1, ',');
        if(comma_offset == -1) {
            proto_tree_add_item(sub_tree, hf_diameter_3gpp_path, tvb, offset, comma_offset, ENC_ASCII|ENC_NA);
            return end_offset;
        }
        proto_tree_add_item(sub_tree, hf_diameter_3gpp_path, tvb, offset, comma_offset, ENC_ASCII|ENC_NA);
        offset = comma_offset+1;
    }


    return tvb_reported_length(tvb);
}

/* AVP Code: 641 Contact
 * imscxdx.xml
 * IMS Cx Dx AVPS 3GPP TS 29.229
 * 6.3.48 Contact AVP
 * The Contact AVP is of type OctetString and it contains the Contact Addresses and Parameters in the Contact header as
 * defined in IETF RFC 3261.
 */
static int
dissect_diameter_3gpp_contact(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    int offset = 0;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_contact, tvb, offset, -1, ENC_ASCII|ENC_NA);
    PROTO_ITEM_SET_GENERATED(item);

    return tvb_reported_length(tvb);
}

/* AVP Code: 701 MSISDN */
static int
dissect_diameter_3gpp_msisdn(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    int length = tvb_reported_length(tvb);

    dissect_e164_msisdn(tvb, tree, offset, length, E164_ENC_BCD);

    return length;
}

/* AVP Code: 655 SAR-Flags
* TGPP.xml
* IMS Cx Dx AVPS 3GPP TS 29.229
*/

static const int *diameter_3gpp_sar_fields[] = {
    &hf_diameter_3gpp_sar_flags_flags_bit0,
    NULL
};

static int
dissect_diameter_3gpp_sar_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_tree_add_bitmask_with_flags(tree, tvb, 0, hf_diameter_3gpp_sar_flags,
        diameter_3gpp_sar_flags_ett, diameter_3gpp_sar_fields, ENC_BIG_ENDIAN, BMT_NO_APPEND);

    return 4;
}

/* AVP Code: 702 User-Data
 * TGPPSh.xml
 * The AVP codes from 709 to799 are reserved for TS 29.329
 */
/* AVP Code: 606 User-Data
 * imscxdx.xml
 * IMS Cx Dx AVPS 3GPP TS 29.229
 */
static int
dissect_diameter_3gpp_user_data(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int length = tvb_reported_length(tvb);

    /* If there is less than 38 characters this is not XML
     * <?xml version="1.0" encoding="UTF-8"?>
     */
    if(length < 38)
        return length;

    if (tvb_strncaseeql(tvb, 0, "<?xml", 5) == 0) {
        call_dissector(xml_handle, tvb, pinfo, tree);
    }

    return length;

}

/*
 * AVP Code: 704 Service-Indication
 */
static int
dissect_diameter_3gpp_service_ind(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    int offset = 0, i;
    int length = tvb_reported_length(tvb);

    for(i = 0; i < length; i++)
        if(!g_ascii_isprint(tvb_get_guint8(tvb, i)))
            return length;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_service_ind, tvb, offset, length, ENC_ASCII|ENC_NA);
    PROTO_ITEM_SET_GENERATED(item);

    return length;
}

/* AVP Code: 900 TMGI */
static int
dissect_diameter_3gpp_tmgi(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_tmgi, tvb, offset, 6, ENC_NA);
    sub_tree = proto_item_add_subtree(item,diameter_3gpp_tmgi_ett);

    /* MBMS Service ID consisting of three octets. MBMS Service ID consists of a 6-digit
     * fixed-length hexadecimal number between 000000 and FFFFFF.
     * MBMS Service ID uniquely identifies an MBMS bearer service within a PLMN.
     */

    proto_tree_add_item(sub_tree, hf_diameter_mbms_service_id, tvb, offset, 3, ENC_BIG_ENDIAN);
    offset = offset+3;
    offset = dissect_e212_mcc_mnc(tvb, pinfo, sub_tree, offset, E212_NONE, TRUE);

    return offset;

}

/* AVP Code: 903 MBMS-Service-Area */

/* AVP Code: 917 MBMS-GGSN-IPv6-Address */
static int
dissect_diameter_3gpp_ipv6addr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_diameter_3gpp_ipv6addr, tvb, offset, 16, ENC_NA);

    offset += 16;

    return offset;
}


/* AVP Code: 918 MBMS-BMSC-SSM-IP-Address */
static int
dissect_diameter_3gpp_ipaddr(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_diameter_3gpp_ipaddr, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;

    return offset;

}

/* AVP Code: 909 RAI AVP
 * 17.7.12 RAI AVP
 * The RAI AVP (AVP Code 909) is of type UTF8String, and contains the Routing Area Identity of the SGSN where the
 * UE is registered. RAI use and structure is specified in 3GPP TS 23.003 [40].
 * Its value shall be encoded as a UTF-8 string on either 11 (if the MNC contains two digits) or 12 (if the MNC contains
 * three digits) octets as follows:
 * - The MCC shall be encoded first using three UTF-8 characters on three octets, each character representing a
 * decimal digit starting with the first MCC digit.
 * - Then, the MNC shall be encoded as either two or three UTF-8 characters on two or three octets, each character
 * representing a decimal digit starting with the first MNC digit.
 * - The Location Area Code (LAC) is encoded next using four UTF-8 characters on four octets, each character
 * representing a hexadecimal digit of the LAC which is two binary octets long.
 * - The Routing Area Code (RAC) is encoded last using two UTF-8 characters on two octets, each character
 * representing a hexadecimal digit of the RAC which is one binary octet long.
 * NOTE: As an example, a RAI with the following information: MCC=123, MNC=45, LAC=41655(0xA2C1) and
 * RAC=10(0x0A) is encoded within the RAI AVP as a UTF-8 string of "12345A2C10A".
 */

static int
dissect_diameter_3gpp_rai(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, void *data)
{
    diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;
    guint length;

    length = tvb_reported_length(tvb);

    if(length==12) {
        diam_sub_dis->avp_str = wmem_strdup_printf(wmem_packet_scope(), "MCC %s, MNC %s, LAC 0x%s, RAC 0x%s",
            tvb_get_string_enc(wmem_packet_scope(), tvb,  0, 3, ENC_UTF_8|ENC_NA), /* MCC 3 digits */
            tvb_get_string_enc(wmem_packet_scope(), tvb,  3, 3, ENC_UTF_8|ENC_NA), /* MNC 3 digits */
            tvb_get_string_enc(wmem_packet_scope(), tvb,  6, 4, ENC_UTF_8|ENC_NA), /* LCC 4 digits */
            tvb_get_string_enc(wmem_packet_scope(), tvb, 10, 2, ENC_UTF_8|ENC_NA)  /* RAC 2 digits */
            );
    } else {
        diam_sub_dis->avp_str = wmem_strdup_printf(wmem_packet_scope(), "MCC %s, MNC %s, LAC 0x%s, RAC 0x%s",
            tvb_get_string_enc(wmem_packet_scope(), tvb,  0, 3, ENC_UTF_8|ENC_NA), /* MCC 3 digits */
            tvb_get_string_enc(wmem_packet_scope(), tvb,  3, 2, ENC_UTF_8|ENC_NA), /* MNC 2 digits */
            tvb_get_string_enc(wmem_packet_scope(), tvb,  5, 4, ENC_UTF_8|ENC_NA), /* LCC 4 digits */
            tvb_get_string_enc(wmem_packet_scope(), tvb,  9, 2, ENC_UTF_8|ENC_NA)  /* RAC 2 digits */
            );
    }

    return length;

}
/* AVP Code: 913 MBMS-Required-QoS */
static int
dissect_diameter_3gpp_mbms_required_qos(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    guint length;

    /* Octet
     * 1        Allocation/Retention Priority as specified in 3GPP TS 23.107.
     *          This octet encodes each priority level defined in 3GPP TS 23.107
     *          as the binary value of the priority level. It specifies the relative
     *          importance of the actual MBMS bearer service compared to other MBMS
     *          and non-MBMS bearer services for allocation and retention of the
     *          MBMS bearer service.
     * 2-N      QoS Profile as specified by the Quality-of-Service information element,
     *          from octet 3 onwards, in 3GPP TS 24.008
     */
    proto_tree_add_item(tree, hf_diameter_3gpp_mbms_required_qos_prio, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    length = tvb_reported_length(tvb) - 1;
    de_sm_qos(tvb, tree,  pinfo, offset,length, NULL, 0);
    return offset+length;

}

/* AVP Code: 926 MBMS-BMSC-SSM-UDP-Port */
/* AVP Code: 927 MBMS-GW-UDP-Port */
static int
dissect_diameter_3gpp_udp_port(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;

    proto_tree_add_item(tree, hf_diameter_3gpp_udp_port, tvb, offset, 1, ENC_BIG_ENDIAN);

    offset += 1;

    return offset;
}

/* AVP Code: 929 MBMS-Data-Transfer-Start */
/* AVP Code: 930 MBMS-Data-Transfer-Stop */
static int
dissect_diameter_3gpp_mbms_abs_time_ofmbms_data_tfer(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    int offset = 0;
    const gchar *time_str;

    time_str = tvb_ntp_fmt_ts(tvb, offset);
    proto_tree_add_string(tree, hf_diameter_3gpp_mbms_abs_time_ofmbms_data_tfer, tvb, offset, 8, time_str);
    offset+=8;

    return offset;
}

/*
 * AVP Code: 1005 Charging-Rule-Name
 */
static int
dissect_diameter_3gpp_charging_rule_name(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data)
{
    proto_item *item;
    int offset = 0, i;
    int length = tvb_reported_length(tvb);
    diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;

    if (tree){
        for (i = 0; i < length; i++)
            if (!g_ascii_isprint(tvb_get_guint8(tvb, i)))
                return length;

        item = proto_tree_add_item_ret_string(tree, hf_diameter_3gpp_charging_rule_name, tvb, offset, length,
                                              ENC_UTF_8 | ENC_NA, wmem_packet_scope(), (const guint8**)&diam_sub_dis->avp_str);
        PROTO_ITEM_SET_GENERATED(item);
    }

    return length;
}

/* AVP Code: 1082 Credit-Management-Status */
static int
dissect_diameter_3gpp_credit_management_status(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    if (tree) {
        proto_tree *subtree = proto_tree_add_subtree(tree, tvb, 0, 4, diameter_3gpp_cms_ett, NULL, "Credit-Management-Status bit mask");
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_spare_bits, tvb, 0, 25, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_cms_no_gyn_session_serv_not_allowed, tvb, 25, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_cms_no_gyn_session_serv_allowed, tvb, 26, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_cms_rating_failed, tvb, 27, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_cms_user_unknown, tvb, 28, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_cms_auth_rej, tvb, 29, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_cms_credit_ctrl_not_applicable, tvb, 30, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_cms_end_user_serv_status, tvb, 31, 1, ENC_BIG_ENDIAN);
    }

    return 4;
}


/* Helper function returning the main bitrates in kbps */
static guint32
qos_calc_bitrate(guint8 oct)
{
    if (oct <= 0x3f)
        return oct;
    if (oct <= 0x7f)
        return 64 + (oct - 0x40) * 8;

    return 576 + (oct - 0x80) * 64;
}

/* Helper function returning the extended bitrates in kbps */
static guint32
qos_calc_ext_bitrate(guint8 oct)
{
    if (oct <= 0x4a)
        return 8600 + oct * 100;
    if (oct <= 0xba)
        return 16000 + (oct - 0x4a) * 1000;

    return 128000 + (oct - 0xba) * 2000;
}


/* 3GPP TS 29.272
 * 7.3.77 QoS-Subscribed
 * AVP Code: 1404 QoS-Subscribed
 *
 * The QoS-Subscribed AVP is of type OctetString. Octets are coded according to 3GPP TS 29.002
 * (octets of QoS-Subscribed, Ext-QoS-Subscribed, Ext2-QoS-Subscribed, Ext3-QoS-Subscribed and
 * Ext4-QoS-Subscribed values are concatenated).
 *
 */
static int
dissect_diameter_3ggp_qos_susbscribed(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    guint offset = 0;
    guint length = tvb_reported_length(tvb);
    proto_tree *subtree;
    proto_item *item;
    guchar oct, tmp_oct;
    const gchar *str;
    guint32 tmp32;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_qos_subscribed, tvb, offset, length, ENC_NA);
    subtree = proto_item_add_subtree(item, diameter_3gpp_qos_subscribed_ett);

    /* QoS-Subscribed:: SIZE(3)
    * 1-3   Octets are coded according to TS 3GPP TS 24.008 Quality of Service Octets 3-5
    */
    if (length >= 3) {
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_reliability_cls, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_delay_cls, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_spare_bits, tvb, offset << 3, 2, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_prec_class, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_spare_bits, tvb, (offset << 3) + 4, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_peak_thr, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;

        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_mean_thr, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_spare_bits, tvb, (offset << 3), 3, ENC_BIG_ENDIAN);
        offset += 1;
    }

    /* Ext-QoS-Subscribed:: SIZE(1..9)
    *   1   Allocation / Retention Priority (This octet encodes each priority level defined in
    *           23.107 as the binary value of the priority level, declaration in 29.060).
    * 2-9   Octets are coded according to 3GPP TS 24.008 Quality of Service Octets 6-13
    */
    if (length >= 4) {
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_al_ret_priority, tvb, offset, 1, ENC_NA);
        offset += 1;
    }

    if (length >= 5) {
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_del_of_err_sdu, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_del_order, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_traffic_cls, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (length >= 6) {
        oct = tvb_get_guint8(tvb, offset);
        switch (oct) {
            case 0x00: str = "Subscribed maximum SDU size (MS to net); Reserved (net to MS)"; break;
            case 0x97: str = "1502 octets"; break;
            case 0x98: str = "1510 octets"; break;
            case 0x99: str = "1520 octets"; break;
            case 0xff: str = "Reserved"; break;
            default:   str = "Unspecified/Reserved";
        }

        if ((oct >= 1) && (oct <= 0x96))
            proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_maximum_sdu_size, tvb, offset, 1, oct, "%u octets (%u)", oct * 10, oct);
        else
            proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_maximum_sdu_size, tvb, offset, 1, oct, "%s (%u)", str, oct);

        offset += 1;
    }

    if (length >= 7) {
        oct = tvb_get_guint8(tvb, offset);

        switch (oct) {
            case 0x00: str = "Subscribed maximum bit rate for uplink (MS to net); Reserved (net to MS)"; break;
            case 0xfe: str = "8640 kbps; Check extended"; break;
            case 0xff: str = "0 kbps"; break;
            default:   str = wmem_strdup_printf(wmem_packet_scope(), "%u kbps", qos_calc_bitrate(oct));
        }

        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_max_bitrate_upl, tvb, offset, 1, oct, "%s (%u)", str, oct);
        offset += 1;
    }

    if (length >= 8) {
        oct = tvb_get_guint8(tvb, offset);

        switch (oct) {
            case 0x00: str = "Subscribed maximum bit rate for downlink (MS to net); Reserved (net to MS)"; break;
            case 0xfe: str = "8640 kbps; Check extended"; break;
            case 0xff: str = "0 kbps"; break;
            default:   str = wmem_strdup_printf(wmem_packet_scope(), "%u kbps", qos_calc_bitrate(oct));
        }

        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_max_bitrate_downl, tvb, offset, 1, oct, "%s (%u)", str, oct);
        offset += 1;
    }

    if (length >= 9) {
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_sdu_err_rat, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_ber, tvb, offset, 1, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (length >= 10) {
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_traff_hdl_pri, tvb, offset, 1, ENC_BIG_ENDIAN);

        oct = tvb_get_guint8(tvb, offset);
        tmp_oct = oct >> 2;
        switch (tmp_oct) {
            case 0x00: str = "Subscribed transfer delay (MS to net); Reserved (net to MS)"; break;
            case 0x3f: str = "Reserved"; break;
            default:
                if (oct <= 0x0f)
                    tmp32 = tmp_oct * 10;
                else if (oct <= 0x1f)
                    tmp32 = (tmp_oct - 0x10) * 50 + 200;
                else
                    tmp32 = (tmp_oct - 0x20) * 100 + 1000;
                str = wmem_strdup_printf(wmem_packet_scope(), "%u ms", tmp32);
        }
        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_trans_delay, tvb, offset, 1, oct, "%s (%u)", str, tmp_oct);
        offset += 1;
    }

    if (length >= 11) {
        oct = tvb_get_guint8(tvb, offset);

        switch (oct) {
        case 0x00: str = "Subscribed guaranteed bit rate for uplink (MS to net); Reserved (net to MS)"; break;
        case 0xfe: str = "8640 kbps; Check extended"; break;
        case 0xff: str = "0 kbps"; break;
        default:   str = wmem_strdup_printf(wmem_packet_scope(), "%u kbps", qos_calc_bitrate(oct));
        }

        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_guar_bitrate_upl, tvb, offset, 1, oct, "%s (%u)", str, oct);
        offset += 1;
    }

    if (length >= 12) {
        oct = tvb_get_guint8(tvb, offset);

        switch (oct) {
        case 0x00: str = "Subscribed guaranteed bit rate for downlink (MS to net); Reserved (net to MS)"; break;
        case 0xfe: str = "8640 kbps; Check extended"; break;
        case 0xff: str = "0 kbps"; break;
        default:   str = wmem_strdup_printf(wmem_packet_scope(), "%u kbps", qos_calc_bitrate(oct));
        }

        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_guar_bitrate_downl, tvb, offset, 1, oct, "%s (%u)", str, oct);
        offset += 1;
    }

    /* Ext2-QoS-Subscribed:: SIZE(1..3)
    * 1-3   Octets are coded according to 3GPP TS 24.008 Quality of Service Octets 14-16
    */
    if (length >= 13) {
        oct = tvb_get_guint8(tvb, offset);
        tmp_oct = oct & 0x0f;
        if (tmp_oct == 0x01)
            str = "speech (MS to net); spare bits (net to MS)";
        else
            str = "unknown (MS to net); spare bits (net to MS)";

        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_source_stat_desc, tvb, offset, 1, oct, "%s (%u)", str, tmp_oct);
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_signalling_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_spare_bits, tvb, (offset << 3), 3, ENC_BIG_ENDIAN);
        offset += 1;
    }

    if (length >= 14) {
        oct = tvb_get_guint8(tvb, offset);

        if (oct == 0x00)
            str = "Use the value indicated by the Maximum bit rate for downlink";
        else if (oct > 0xfa)  /* shouldn't go past 256 MBps */
            str = "undefined";
        else if (oct == 0xfa)
            str = "256 Mbps; Check extended 2";
        else {
            tmp32 = qos_calc_ext_bitrate(oct);
            if (oct >= 0x4a)
                str = wmem_strdup_printf(wmem_packet_scope(), "%u Mbps", tmp32 / 1000);
            else
                str = wmem_strdup_printf(wmem_packet_scope(), "%u kbps", tmp32);
        }
        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_max_bitrate_downl_ext, tvb, offset, 1, oct, "%s (%u)", str, oct);
        offset += 1;
    }

    if (length >= 15) {
        oct = tvb_get_guint8(tvb, offset);

        if (oct == 0x00)
            str = "Use the value indicated by the Guaranteed bit rate for downlink";
        else if (oct > 0xfa)  /* shouldn't go past 256 MBps */
            str = "undefined";
        else if (oct == 0xfa)
            str = "256 Mbps; Check extended 2";
        else {
            tmp32 = qos_calc_ext_bitrate(oct);
            if (oct >= 0x4a)
                str = wmem_strdup_printf(wmem_packet_scope(), "%u Mbps", tmp32 / 1000);
            else
                str = wmem_strdup_printf(wmem_packet_scope(), "%u kbps", tmp32);
        }
        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_guar_bitrate_downl_ext, tvb, offset, 1, oct, "%s (%u)", str, oct);
        offset += 1;
    }

    /* Ext3-QoS-Susbcribed:: SIZE(1..2)
    * 1-2   Octets are coded according to 3GPP TS 24.008 Quality of Service Octets 17-18
    */
    if (length >= 16) {
        oct = tvb_get_guint8(tvb, offset);

        if (oct == 0x00)
            str = "Use the value indicated by the Maximum bit rate for uplink";
        else if (oct > 0xfa)  /* shouldn't go past 256 MBps */
            str = "undefined";
        else if (oct == 0xfa)
            str = "256 Mbps; Check extended 2";
        else {
            tmp32 = qos_calc_ext_bitrate(oct);
            if (oct >= 0x4a)
                str = wmem_strdup_printf(wmem_packet_scope(), "%u Mbps", tmp32 / 1000);
            else
                str = wmem_strdup_printf(wmem_packet_scope(), "%u kbps", tmp32);
        }
        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_max_bitrate_upl_ext, tvb, offset, 1, oct, "%s (%u)", str, oct);
        offset += 1;
    }

    if (length >= 17) {
        oct = tvb_get_guint8(tvb, offset);

        if (oct == 0x00)
            str = "Use the value indicated by the Guaranteed bit rate for uplink";
        else if (oct > 0xfa)  /* shouldn't go past 256 MBps */
            str = "undefined";
        else if (oct == 0xfa)
            str = "256 Mbps; Check extended 2";
        else {
            tmp32 = qos_calc_ext_bitrate(oct);
            if (oct >= 0x4a)
                str = wmem_strdup_printf(wmem_packet_scope(), "%u Mbps", tmp32 / 1000);
            else
                str = wmem_strdup_printf(wmem_packet_scope(), "%u kbps", tmp32);
        }
        proto_tree_add_uint_format_value(subtree, hf_diameter_3gpp_qos_guar_bitrate_upl_ext, tvb, offset, 1, oct, "%s (%u)", str, oct);
        offset += 1;
    }

    /* Ext4-QoS-Subscribed:: SIZE(1)
    *   1   Evolved Allocation / Retention Priority.  This octet encodes the Priority Level (PL),
    *       the Preemption Capability (PCI) and Preemption Vulnerability (PVI) values, as described
    *       in 3GPP TS 29.060.
    */

    if (length >= 18) {
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_pre_emption_vulnerability, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_spare_bits, tvb, (offset << 3) + 6 , 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_priority_level, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_item(subtree, hf_diameter_3gpp_qos_pre_emption_capability, tvb, offset, 1, ENC_BIG_ENDIAN);
        proto_tree_add_bits_item(subtree, hf_diameter_3gpp_spare_bits, tvb, (offset << 3), 1, ENC_BIG_ENDIAN);
        /*offset += 1;*/
    }

    return length;
}

/* 3GPP TS 29.272
 * 7.3.7 ULR-Flags
 * AVP Code: 1405 ULR-Flags
 */
static int
dissect_diameter_3gpp_ulr_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_ulr_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_ulr_flags_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 24, ENC_BIG_ENDIAN);
    bit_offset+=24;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit7, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit6, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit5, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit4, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ulr_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;

}

/* AVP Code: 1406 ULA-Flags */
static int
dissect_diameter_3gpp_ula_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_ula_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_ula_flags_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 30, ENC_BIG_ENDIAN);
    bit_offset+=30;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ula_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ula_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;

}

/* AVP Code: 1407 Visited-PLMN-Id */
static int
dissect_diameter_3gpp_visited_plmn_id(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data)
{
    int length = tvb_reported_length(tvb);
    diam_sub_dis_t *diam_sub_dis = (diam_sub_dis_t*)data;

    if (length == 3) {
        diam_sub_dis->avp_str = dissect_e212_mcc_mnc_wmem_packet_str(tvb, pinfo, tree, 0, E212_NONE, TRUE);
    } else {
        proto_tree_add_expert(tree, pinfo, &ei_diameter_3gpp_plmn_id_wrong_len, tvb, 0, length);
    }

    return length;
}
/*
 * 3GPP TS 29.272
 * 7.3.25 DSR-Flags
 * AVP Code: 1421 DSR-Flags
 */
static int
dissect_diameter_3gpp_dsr_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_dsr_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_dsr_flags_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 13, ENC_BIG_ENDIAN);
    bit_offset+=13;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit18, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit17, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit16, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit15, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit14, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit13, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit12, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit11, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit10, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit9, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit8, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit7, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit6, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit5, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit4, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsr_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;

}

/* AVP Code: 1422 DSA-Flags */
static int
dissect_diameter_3gpp_dsa_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_dsa_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_dsa_flags_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 31, ENC_BIG_ENDIAN);
    bit_offset+=31;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_dsa_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;

}

/* AVP Code: 1441 IDA-Flags */
static int
dissect_diameter_3gpp_ida_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_ida_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_ida_flags_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 31, ENC_BIG_ENDIAN);
    bit_offset+=31;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_ida_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;

}

/* AVP Code: 1442 PUA-Flags */
static int
dissect_diameter_3gpp_pua_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_pua_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_pua_flags_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 30, ENC_BIG_ENDIAN);
    bit_offset+=30;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_pua_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_pua_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;


}

/* AVP Code: 1443 NOR-Flags */
static int
dissect_diameter_3gpp_nor_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_nor_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_nor_flags_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 22, ENC_BIG_ENDIAN);
    bit_offset+=22;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit9, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit8, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit7, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit6, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit5, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit4, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_nor_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;

}

/* AVP Code: 1490 IDR-Flags */
static int
dissect_diameter_3gpp_idr_flags(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_idr_flags, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_idr_flags_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 23, ENC_BIG_ENDIAN);
    bit_offset+=23;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit8, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit7, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit6, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit5, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit4, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_idr_flags_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;

}

/* AVP Code: 3502 MBMS-Bearer-Event */
static int
dissect_diameter_3gpp_mbms_bearer_event(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_mbms_bearer_event, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_mbms_bearer_event_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 31, ENC_BIG_ENDIAN);
    bit_offset+=31;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_event_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;
}

/* AVP Code: 3506 MBMS-Bearer-Result */
static int
dissect_diameter_3gpp_mbms_bearer_result(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_mbms_bearer_result, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_mbms_bearer_result_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 20, ENC_BIG_ENDIAN);
    bit_offset+=20;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit11, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit10, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit9, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit8, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit7, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit6, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit5, tvb,  bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit4, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_mbms_bearer_result_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;
}

/* AVP Code: 3511 TMGI-Allocation-Result */
static int
dissect_diameter_3gpp_tmgi_allocation_result(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_tmgi_allocation_result, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_tmgi_allocation_result_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 27, ENC_BIG_ENDIAN);
    bit_offset+=27;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_tmgi_allocation_result_bit4, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_tmgi_allocation_result_bit3, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_tmgi_allocation_result_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_tmgi_allocation_result_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_tmgi_allocation_result_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;
}

/* AVP Code: 3514 TMGI-Deallocation-Result */
static int
dissect_diameter_3gpp_tmgi_deallocation_result(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, void *data _U_)
{
    proto_item *item;
    proto_tree *sub_tree;
    int offset = 0;
    guint32 bit_offset;

    item = proto_tree_add_item(tree, hf_diameter_3gpp_tmgi_deallocation_result, tvb, offset, 4, ENC_BIG_ENDIAN);
    sub_tree = proto_item_add_subtree(item, diameter_3gpp_tmgi_deallocation_result_ett);
    bit_offset = 0;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_spare_bits, tvb, bit_offset, 29, ENC_BIG_ENDIAN);
    bit_offset+=29;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_tmgi_deallocation_result_bit2, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_tmgi_deallocation_result_bit1, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;
    proto_tree_add_bits_item(sub_tree, hf_diameter_3gpp_tmgi_deallocation_result_bit0, tvb, bit_offset, 1, ENC_BIG_ENDIAN);
    bit_offset++;

    offset = bit_offset>>3;
    return offset;
}


void
proto_reg_handoff_diameter_3gpp(void)
{

    /* AVP Code: 5 3GPP-GPRS Negotiated QoS profile */
    /* Registered by packet-gtp.c */

    /* AVP Code: 15 3GPP-SGSN-IPv6-Address */
    dissector_add_uint("diameter.3gpp", 15, create_dissector_handle(dissect_diameter_3gpp_sgsn_ipv6_address, proto_diameter_3gpp));

    /* AVP Code: 20 3GPP-IMEISV */
    dissector_add_uint("diameter.3gpp", 20, create_dissector_handle(dissect_diameter_3gpp_imeisv, proto_diameter_3gpp));

    /* AVP Code: 21 3GPP-RAT-Access-Type */
    dissector_add_uint("diameter.3gpp", 21, create_dissector_handle(dissect_diameter_3gpp_rat_type, proto_diameter_3gpp));


    /* AVP Code: 22 3GPP-User-Location-Info
     * Registered by packet-gtpv2.c
     */

    /* AVP Code: 23 3GPP-MS-TimeZone */
    dissector_add_uint("diameter.3gpp", 23, create_dissector_handle(dissect_diameter_3gpp_ms_timezone, proto_diameter_3gpp));

    /* AVP Code: 504 AF-Application-Identifier */
    dissector_add_uint("diameter.3gpp", 504, create_dissector_handle(dissect_diameter_3gpp_af_application_identifier, proto_diameter_3gpp));

    /* AVP Code: 505 AF-Charging-Identifier */
    dissector_add_uint("diameter.3gpp", 505, create_dissector_handle(dissect_diameter_3gpp_af_charging_identifier, proto_diameter_3gpp));

    /* AVP Code: 600 Visited-Network-Identifier */
    dissector_add_uint("diameter.3gpp", 600, create_dissector_handle(dissect_diameter_3gpp_visited_nw_id, proto_diameter_3gpp));

    /* AVP Code: 601 Public-Identity */
    dissector_add_uint("diameter.3gpp", 601, create_dissector_handle(dissect_diameter_3gpp_public_identity, proto_diameter_3gpp));

    /* AVP Code: 606 User-Data */
    dissector_add_uint("diameter.3gpp", 606, create_dissector_handle(dissect_diameter_3gpp_user_data, proto_diameter_3gpp));

    /* AVP Code: 629 Feature-List */
    dissector_add_uint("diameter.3gpp", 629, create_dissector_handle(dissect_diameter_3gpp_feature_list_id, proto_diameter_3gpp));

    /* AVP Code: 630 Feature-List */
    dissector_add_uint("diameter.3gpp", 630, create_dissector_handle(dissect_diameter_3gpp_feature_list, proto_diameter_3gpp));

    /* AVP Code: 637 UAR-Flags */
    dissector_add_uint("diameter.3gpp", 637, create_dissector_handle(dissect_diameter_3gpp_uar_flags, proto_diameter_3gpp));

    /* AVP Code: 640 Path */
    dissector_add_uint("diameter.3gpp", 640, create_dissector_handle(dissect_diameter_3gpp_path, proto_diameter_3gpp));

    /* AVP Code: 641 Contact */
    dissector_add_uint("diameter.3gpp", 641, create_dissector_handle(dissect_diameter_3gpp_contact, proto_diameter_3gpp));

    /* AVP Code: 655 SAR-Flags */
    dissector_add_uint("diameter.3gpp", 655, create_dissector_handle(dissect_diameter_3gpp_sar_flags, proto_diameter_3gpp));

    /* AVP Code: 701 MSISDN */
    dissector_add_uint("diameter.3gpp", 701, create_dissector_handle(dissect_diameter_3gpp_msisdn, proto_diameter_3gpp));

    /* AVP Code: 702 User-Data */
    dissector_add_uint("diameter.3gpp", 702, create_dissector_handle(dissect_diameter_3gpp_user_data, proto_diameter_3gpp));

    /* AVP Code: 704 Service-Indication  */
    dissector_add_uint("diameter.3gpp", 704, create_dissector_handle(dissect_diameter_3gpp_service_ind, proto_diameter_3gpp));

    /* AVP Code: 900 TMGI */
    dissector_add_uint("diameter.3gpp", 900, create_dissector_handle(dissect_diameter_3gpp_tmgi, proto_diameter_3gpp));

    /* AVP Code: 904 MBMS-Session-Duration  Registered by packet-gtp.c */
    /* AVP Code: 903 MBMS-Service-Area Registered by packet-gtp.c */

    /* AVP Code: 909 RAI */
    dissector_add_uint("diameter.3gpp", 909, create_dissector_handle(dissect_diameter_3gpp_rai, proto_diameter_3gpp));

    /* AVP Code: 911 MBMS-Time-To-Data-Transfer  Registered by packet-gtp.c */
    /* Registered by packet-gtp.c */

    /* AVP Code: 913 MBMS-Required-QoS */
    dissector_add_uint("diameter.3gpp", 913, create_dissector_handle(dissect_diameter_3gpp_mbms_required_qos, proto_diameter_3gpp));

    /* AVP Code: 917 MBMS-GGSN-IPv6-Address */
    dissector_add_uint("diameter.3gpp", 917, create_dissector_handle(dissect_diameter_3gpp_ipv6addr, proto_diameter_3gpp));

    /* AVP Code: 918 MBMS-BMSC-SSM-IP-Address */
    dissector_add_uint("diameter.3gpp", 918, create_dissector_handle(dissect_diameter_3gpp_ipaddr, proto_diameter_3gpp));

    /* AVP Code: 926 MBMS-BMSC-SSM-UDP-Port */
    /* AVP Code: 927 MBMS-GW-UDP-Port */
    dissector_add_uint("diameter.3gpp", 926, create_dissector_handle(dissect_diameter_3gpp_udp_port, proto_diameter_3gpp));
    dissector_add_uint("diameter.3gpp", 927, create_dissector_handle(dissect_diameter_3gpp_udp_port, proto_diameter_3gpp));

    /* AVP Code: 929 MBMS-Data-Transfer-Start */
    dissector_add_uint("diameter.3gpp", 929, create_dissector_handle(dissect_diameter_3gpp_mbms_abs_time_ofmbms_data_tfer, proto_diameter_3gpp));

    /* AVP Code: 930 MBMS-Data-Transfer-Stop */
    dissector_add_uint("diameter.3gpp", 930, create_dissector_handle(dissect_diameter_3gpp_mbms_abs_time_ofmbms_data_tfer, proto_diameter_3gpp));

    /* AVP Code: 1005 Charging-Rule-Name */
    dissector_add_uint("diameter.3gpp", 1005, create_dissector_handle(dissect_diameter_3gpp_charging_rule_name, proto_diameter_3gpp));

    /* AVP Code: 1005 Credit-Management-Status */
    dissector_add_uint("diameter.3gpp", 1082, create_dissector_handle(dissect_diameter_3gpp_credit_management_status, proto_diameter_3gpp));

    /* AVP Code: 1404 QoS-Subscribed */
    dissector_add_uint("diameter.3gpp", 1404, create_dissector_handle(dissect_diameter_3ggp_qos_susbscribed, proto_diameter_3gpp));

    /* AVP Code: 1405 ULR-Flags */
    dissector_add_uint("diameter.3gpp", 1405, create_dissector_handle(dissect_diameter_3gpp_ulr_flags, proto_diameter_3gpp));

    /* AVP Code: 1406 ULA-Flags */
    dissector_add_uint("diameter.3gpp", 1406, create_dissector_handle(dissect_diameter_3gpp_ula_flags, proto_diameter_3gpp));

    /*AVP Code: 1407 Visited-PLMN-Id */
    dissector_add_uint("diameter.3gpp", 1407, create_dissector_handle(dissect_diameter_3gpp_visited_plmn_id, proto_diameter_3gpp));

    /* AVP Code: 1421 DSR-Flags */
    dissector_add_uint("diameter.3gpp", 1421, create_dissector_handle(dissect_diameter_3gpp_dsr_flags, proto_diameter_3gpp));

    /* AVP Code: 1422 DSA-Flags */
    dissector_add_uint("diameter.3gpp", 1422, create_dissector_handle(dissect_diameter_3gpp_dsa_flags, proto_diameter_3gpp));

    /* AVP Code: 1441 IDA-Flags */
    dissector_add_uint("diameter.3gpp", 1441, create_dissector_handle(dissect_diameter_3gpp_ida_flags, proto_diameter_3gpp));

    /* AVP Code: 1442 PUA-Flags */
    dissector_add_uint("diameter.3gpp", 1442, create_dissector_handle(dissect_diameter_3gpp_pua_flags, proto_diameter_3gpp));

    /* AVP Code: 1443 NOR-Flags */
    dissector_add_uint("diameter.3gpp", 1443, create_dissector_handle(dissect_diameter_3gpp_nor_flags, proto_diameter_3gpp));

    /* AVP Code: 1490 IDR-Flags */
    dissector_add_uint("diameter.3gpp", 1490, create_dissector_handle(dissect_diameter_3gpp_idr_flags, proto_diameter_3gpp));

    /* AVP Code: 3502 MBMS-Bearer-Event */
    dissector_add_uint("diameter.3gpp", 3502, create_dissector_handle(dissect_diameter_3gpp_mbms_bearer_event, proto_diameter_3gpp));

    /* AVP Code: 3506 MBMS-Bearer-Result */
    dissector_add_uint("diameter.3gpp", 3506, create_dissector_handle(dissect_diameter_3gpp_mbms_bearer_result, proto_diameter_3gpp));

    /* AVP Code: 3511 TMGI-Allocation-Result */
    dissector_add_uint("diameter.3gpp", 3511, create_dissector_handle(dissect_diameter_3gpp_tmgi_allocation_result, proto_diameter_3gpp));

    /* AVP Code: 3514 TMGI-Deallocation-Result */
    dissector_add_uint("diameter.3gpp", 3514, create_dissector_handle(dissect_diameter_3gpp_tmgi_deallocation_result, proto_diameter_3gpp));

    xml_handle = find_dissector_add_dependency("xml", proto_diameter_3gpp);
}


/*
 *  3GPP TS 24.008 Quality of service
 */
static const value_string diameter_3gpp_qos_reliability_vals[] = {
    { 0x00, "Subscribed reliability class (in MS to net); Reserved (in net to MS)" },
    { 0x01, "Unused. Interpreted as Unacknowledged GTP, Ack LLC/RLC, Protected data." },
    { 0x02, "Unacknowledged GTP, Ack LLC/RLC, Protected data" },
    { 0x03, "Unacknowledged GTP/LLC, Ack RLC, Protected data" },
    { 0x04, "Unacknowledged GTP/LLC/RLC, Protected data" },
    { 0x05, "Unacknowledged GTP/LLC/RLC, Unprotected data" },
    { 0x06, "Interpreted as Unacknowledged GTP/LLC, Ack RLC, Protected data" }, /* other value */
    { 0x07, "Reserved" },
    { 0, NULL }
};

const range_string diameter_3gpp_qos_delay_cls_vals[] = {
    { 0x00, 0x00, "Subscribed delay class (in MS to net); Reserved (in net to MS)" },
    { 0x01, 0x01, "Delay class 1" },
    { 0x02, 0x02, "Delay class 2" },
    { 0x03, 0x03, "Delay class 3" },
    { 0x04, 0x04, "Delay class 4 (best effort)" },
    { 0x05, 0x06, "Interpreted as Delay class 4 (best effort)" },
    { 0x07, 0x00, "Reserved" },
    { 0, 0, NULL }
};

const range_string diameter_3gpp_qos_prec_class_vals[] = {
    { 0x00, 0x00, "Subscribed precedence (MS to net); Reserved (net to MS)" },
    { 0x01, 0x01, "High priority" },
    { 0x02, 0x02, "Normal priority" },
    { 0x03, 0x03, "Low priority" },
    { 0x04, 0x06, "Interpreted as Normal priority" },
    { 0x07, 0x07, "Reserved" },
    { 0, 0, NULL }
};

const range_string diameter_3gpp_qos_peak_thr_vals[] = {
    { 0x00, 0x00, "Subscribed peak throughput (MS to net); Reserved (net to MS)" },
    { 0x01, 0x01, "Up to 1 000 octet/s" },
    { 0x02, 0x02, "Up to 2 000 octet/s" },
    { 0x03, 0x03, "Up to 4 000 octet/s" },
    { 0x04, 0x04, "Up to 8 000 octet/s" },
    { 0x05, 0x05, "Up to 16 000 octet/s" },
    { 0x06, 0x06, "Up to 32 000 octet/s" },
    { 0x07, 0x07, "Up to 64 000 octet/s" },
    { 0x08, 0x08, "Up to 128 000 octet/s" },
    { 0x09, 0x09, "Up to 256 000 octet/s" },
    { 0x0a, 0x0e, "Interpreted as Up to 1 000 octet/s" },
    { 0x0f, 0x0f, "Reserved" },
    { 0, 0, NULL }
};

const range_string diameter_3gpp_qos_mean_thr_vals[] = {
    { 0x00, 0x00, "Subscribed peak throughput (MS to net); Reserved (net to MS)" },
    { 0x01, 0x01, "100 octet/h" },
    { 0x02, 0x02, "200 octet/h" },
    { 0x03, 0x03, "500 octet/h" },
    { 0x04, 0x04, "1 000 octet/h" },
    { 0x05, 0x05, "2 000 octet/h" },
    { 0x06, 0x06, "5 000 octet/h" },
    { 0x07, 0x07, "10 000 octet/h" },
    { 0x08, 0x08, "20 000 octet/h" },
    { 0x09, 0x09, "50 000 octet/h" },
    { 0x0a, 0x0a, "100 000 octet/h" },
    { 0x0b, 0x0b, "200 000 octet/h" },
    { 0x0c, 0x0c, "500 000 octet/h" },
    { 0x0d, 0x0d, "1 000 000 octet/h" },
    { 0x0e, 0x0e, "2 000 000 octet/h" },
    { 0x0f, 0x0f, "5 000 000 octet/h" },
    { 0x10, 0x10, "10 000 000 octet/h" },
    { 0x11, 0x11, "20 000 000 octet/h" },
    { 0x12, 0x12, "50 000 000 octet/h" },
    { 0x13, 0x1d, "Interpreted as Best effort" },
    { 0x1e, 0x1e, "Reserved" },
    { 0x1f, 0x1f, "Best effort" },
    { 0, 0, NULL }
};

const value_string diameter_3gpp_qos_del_of_err_sdu_vals[] = {
    { 0x00, "Subscribed delivery of erroneous SDUs (MS to net); Reserved (net to MS)" },
    { 0x01, "No detect ('-')" },
    { 0x02, "Erroneous SDUs are delivered ('yes')" },
    { 0x03, "Erroneous SDUs are not delivered ('no')" },
    { 0x07, "Reserved" },
    { 0, NULL }
};

const value_string diameter_3gpp_qos_del_order_vals[] = {
    { 0x00, "Subscribed delivery order (MS to net); Reserved (net to MS)" },
    { 0x01, "With delivery order ('yes')" },
    { 0x02, "Without delivery order ('no')" },
    { 0x03, "Reserved" },
    { 0, NULL }
};

const value_string diameter_3gpp_qos_traffic_cls_vals[] = {
    { 0x00, "Subscribed traffic class (MS to net); Reserved (net to MS)" },
    { 0x01, "Conversational class" },
    { 0x02, "Streaming class" },
    { 0x03, "Interactive class" },
    { 0x04, "Background class" },
    { 0x07, "Reserved" },
    { 0, NULL }
};

const value_string diameter_3gpp_qos_sdu_err_rat_vals[] = {
    { 0x00, "Subscribed SDU error ratio (MS to net); Reserved (net to MS)" },
    { 0x01, "1E-2" },
    { 0x02, "7E-3" },
    { 0x03, "1E-3" },
    { 0x04, "1E-4" },
    { 0x05, "1E-5" },
    { 0x06, "1E-6" },
    { 0x07, "1E-1" },
    { 0x15, "Reserved" },
    { 0, NULL }
};

const value_string diameter_3gpp_qos_ber_vals[] = {
    { 0x00, "Subscribed residual BER (MS to net); Reserved (net to MS)" },
    { 0x01, "5E-2" },
    { 0x02, "1E-2" },
    { 0x03, "5E-3" },
    { 0x04, "4E-3" },
    { 0x05, "1E-3" },
    { 0x06, "1E-4" },
    { 0x07, "1E-5" },
    { 0x08, "1E-6" },
    { 0x09, "6E-8" },
    { 0x15, "Reserved" },
    { 0, NULL }
};

const value_string diameter_3gpp_qos_traff_hdl_pri_vals[] = {
    { 0x00, "Subscribed traffic handling priority (MS to net); Reserved (net to MS)" },
    { 0x01, "Priority level 1" },
    { 0x02, "Priority level 2" },
    { 0x03, "Priority level 3" },
    { 0, NULL }
};

const true_false_string diameter_3gpp_qos_signalling_ind_value = {
    "Optimised for signalling traffic",
    "Not optimised for signalling traffic"
};

void
proto_register_diameter_3gpp(void)
{

    /* Setup list of header fields  See Section 1.6.1 for details*/
    static hf_register_info hf[] = {
        { &hf_diameter_3gpp_timezone,
            { "Timezone",           "diameter.3gpp.3gpp_timezone",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_timezone_adjustment,
            { "Adjustment",           "diameter.3gpp.timezone_adjustment",
            FT_UINT8, BASE_DEC, VALS(daylight_saving_time_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_rat_type,
            { "RAT Type",            "diameter.3gpp.rat-type",
            FT_UINT8, BASE_DEC, VALS(diameter_3gpp_rat_type_vals), 0x00,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_path,
            { "Path",           "diameter.3gpp.path",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_contact,
            { "Contact",           "diameter.3gpp.contact",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_visited_nw_id,
            { "Visited-Network-Identifier",           "diameter.3gpp.visited_nw_id",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
#if 0
        { &hf_diameter_3gpp_user_data,
            { "User data",           "diameter.3gpp.user_data",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
#endif
        { &hf_diameter_3gpp_ipaddr,
            { "IPv4 Address",           "diameter.3gpp.ipaddr",
            FT_IPv4, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_required_qos_prio,
            { "Allocation/Retention Priority",           "diameter.3gpp.mbms_required_qos_prio",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi,
            { "TMGI",           "diameter.3gpp.tmgi",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_service_ind,
            { "Service-Indication",           "diameter.3gpp.service_ind",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_mbms_service_id,
            { "MBMS Service ID",           "diameter.3gpp.mbms_service_id",
            FT_UINT24, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_spare_bits,
            { "Spare bit(s)", "diameter.3gpp.spare_bits",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_uar_flags_flags,
            { "Flags", "diameter.3gpp.uar_flags_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_uar_flags_flags_bit0,
            { "Emergency registration", "diameter.3gpp.uar_flags_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_flags,
            { "Feature-List Flags", "diameter.3gpp.feature_list_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cx_feature_list_flags,
            { "CX Feature-List Flags", "diameter.3gpp.cx_feature_list_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cx_feature_list_1_flags_bit0,
            { "Shared IFC Sets", "diameter.3gpp.cx_feature_list_1_flags_bit0",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cx_feature_list_1_flags_bit1,
            { "Alias Indication", "diameter.3gpp.cx_feature_list_1_flags_bit1",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cx_feature_list_1_flags_bit2,
            { "IMS Restoration Indication", "diameter.3gpp.cx_feature_list_1_flags_bit2",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000004,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cx_feature_list_1_flags_bit3,
            { "P-CSCF Restoration mechanism", "diameter.3gpp.cx_feature_list_1_flags_bit3",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000008,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cx_feature_list_1_flags_spare_bits,
        { "Spare", "diameter.3gpp.cx_feature_list_1_flags_spare",
        FT_UINT32, BASE_HEX, NULL, 0xfffffff0,
        NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_sh_flags_bit0,
        { "Notif-Eff", "diameter.3gpp.feature_list1_sh_flags_bit0",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_sh_flags_bit1,
        { "Update-Eff", "diameter.3gpp.feature_list1_sh_flags_bit1",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_sh_flags_bit2,
        { "Update-Eff-Enhance", "diameter.3gpp.feature_list1_sh_flags_bit2",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_sh_flags_bit3,
        { "Additional-MSISDN", "diameter.3gpp.feature_list1_sh_flags_bit3",
        FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
        NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit0,
            { "Operator Determined Barring of all Packet Oriented Services", "diameter.3gpp.feature_list1_s6a_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit1,
            { "Operator Determined Barring of Packet Oriented Services from access points that are within the HPLMN whilst the subscriber is roaming in a VPLMN", "diameter.3gpp.feature_list1_s6a_flags_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit2,
            { "Operator Determined Barring of Packet Oriented Services from access points that are within the roamed to VPLMN", "diameter.3gpp.feature_list1_s6a_flags_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit3,
            { "Operator Determined Barring of all outgoing calls", "diameter.3gpp.feature_list1_s6a_flags_bit3",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit4,
            { "Operator Determined Barring of all outgoing international calls", "diameter.3gpp.feature_list1_s6a_flags_bit4",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit5,
            { "Operator Determined Barring of all outgoing international calls except those directed to the home PLMN country", "diameter.3gpp.feature_list1_s6a_flags_bit5",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit6,
            { "Operator Determined Barring of all outgoing inter-zonal calls", "diameter.3gpp.feature_list1_s6a_flags_bit6",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit7,
            { "Operator Determined Barring of all outgoing inter-zonal calls except those directed to the home PLMN country", "diameter.3gpp.feature_list1_s6a_flags_bit7",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit8,
            { "Operator Determined Barring of all outgoing international calls except those directed to the home PLMN country and Barring of all outgoing inter-zonal calls", "diameter.3gpp.feature_list1_s6a_flags_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit9,
            { "Regional Subscription", "diameter.3gpp.feature_list1_s6a_flags_bit9",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },

        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit10,
            { "Trace Function", "diameter.3gpp.feature_list1_s6a_flags_bit10",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit11,
            { "All LCS Privacy Exception Classes", "diameter.3gpp.feature_list1_s6a_flags_bit11",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit12,
            { "Allow location by any LCS client", "diameter.3gpp.feature_list1_s6a_flags_bit12",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit13,
            { "Allow location by any value added LCS client to which a call/session is established from the target UE", "diameter.3gpp.feature_list1_s6a_flags_bit13",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit14,
            { "Allow location by designated external value added LCS clients", "diameter.3gpp.feature_list1_s6a_flags_bit14",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit15,
            { "Allow location by designated PLMN operator LCS clients", "diameter.3gpp.feature_list1_s6a_flags_bit15",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit16,
            { "Allow location by LCS clients of a designated LCS service type", "diameter.3gpp.feature_list1_s6a_flags_bit16",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit17,
            { "All Mobile Originating Location Request Classes", "diameter.3gpp.feature_list1_s6a_flags_bit17",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit18,
            { "Allow an MS to request its own location", "diameter.3gpp.feature_list1_s6a_flags_bit18",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit19,
            { "Allow an MS to perform self location without interaction with the PLMN", "diameter.3gpp.feature_list1_s6a_flags_bit19",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit20,
            { "Allow an MS to request transfer of its location to another LCS client", "diameter.3gpp.feature_list1_s6a_flags_bit20",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit21,
            { "Short Message MO-PP", "diameter.3gpp.feature_list1_s6a_flags_bit21",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit22,
            { "Barring of Outgoing Calls", "diameter.3gpp.feature_list1_s6a_flags_bit22",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit23,
            { "Barring of all outgoing calls", "diameter.3gpp.feature_list1_s6a_flags_bit23",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit24,
            { "Barring of outgoing international calls", "diameter.3gpp.feature_list1_s6a_flags_bit24",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit25,
            { "Barring of outgoing international calls except those directed to the home PLMN Country", "diameter.3gpp.feature_list1_s6a_flags_bit25",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit26,
            { "UE Reachability Notifcation", "diameter.3gpp.feature_list1_s6a_flags_bit26",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit27,
            { "Terminating Access Domain Selection Data Retrieval", "diameter.3gpp.feature_list1_s6a_flags_bit27",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit28,
            { "State/Location Information Retrieval", "diameter.3gpp.feature_list1_s6a_flags_bit28",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit29,
            { "Partial Purge from a Combined MME/SGSN", "diameter.3gpp.feature_list1_s6a_flags_bit29",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit30,
            { "UE Time Zone Retrieval", "diameter.3gpp.feature_list1_s6a_flags1_bit30",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list1_s6a_flags_bit31,
            { "Additional MSISDN", "diameter.3gpp.feature_list1_s6a_flags_bit31",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit0,
            { "SMS in MME", "diameter.3gpp.feature_list2_s6a_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit1,
            { "SMS in SGSN", "diameter.3gpp.feature_list2_s6a_flags_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit2,
            { "Dia-LCS-all-PrivExcep", "diameter.3gpp.feature_list2_s6a_flags_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit3,
            { "Dia-LCS-Universal", "diameter.3gpp.feature_list2_s6a_flags_bit3",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit4,
            { "Dia-LCS-CallSessionRelated", "diameter.3gpp.feature_list2_s6a_flags_bit4",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit5,
            { "Dia-LCS-CallSessionUnrelated", "diameter.3gpp.feature_list2_s6a_flags_bit5",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit6,
            { "Dia-LCS-PLMNOperator", "diameter.3gpp.feature_list2_s6a_flags_bit6",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit7,
            { "Dia-LCS-ServiceType", "diameter.3gpp.feature_list2_s6a_flags_bit7",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit8,
            { "Dia-LCS-all-MOLR-SS", "diameter.3gpp.feature_list2_s6a_flags_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit9,
            { "Dia-LCS-BasicSelfLocation", "diameter.3gpp.feature_list2_s6a_flags_bit9",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit10,
            { "Dia-LCS-AutonomousSelfLocation", "diameter.3gpp.feature_list2_s6a_flags_bit10",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit11,
            { "Dia-LCS-TransferToThirdParty", "diameter.3gpp.feature_list2_s6a_flags_bit11",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit12,
            { "Gdd-in-SGSN", "diameter.3gpp.feature_list2_s6a_flags_bit12",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit13,
            { "Optimized-LCS-Proc-Support", "diameter.3gpp.feature_list2_s6a_flags_bit13",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit14,
            { "SGSN CAMEL Capability", "diameter.3gpp.feature_list2_s6a_flags_bit14",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit15,
            { "ProSe Capability", "diameter.3gpp.feature_list2_s6a_flags_bit15",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit16,
            { "P-CSCF Restoration", "diameter.3gpp.feature_list2_s6a_flags_bit16",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list2_s6a_flags_bit17,
            { "Reset-IDs", "diameter.3gpp.feature_list2_s6a_flags_bit17",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_supported_not_supported), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags,
        { "GX Feature-List Flags", "diameter.3gpp.gx_feature_list_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit0,
            { "Rel-8 Gx", "diameter.3gpp.feature_list_gx_flags_bit0",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000001,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit1,
            { "Rel-9 Gx", "diameter.3gpp.feature_list_gx_flags_bit1",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000002,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit2,
            { "Provisioning AF Signaling IP Flow Information",
              "diameter.3gpp.feature_list_gx_flags_bit2",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported),  0x00000004,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit3,
            { "Rel-10 Gx", "diameter.3gpp.feature_list_gx_flags_bit3",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000008,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit4,
            { "Sponsored Data Connectivity",
              "diameter.3gpp.feature_list_gx_flags_bit4",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000010,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit5,
            { "IP Flow Mobility", "diameter.3gpp.feature_list_gx_flags_bit5",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported),  0x00000020,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit6,
            { "ADC", "diameter.3gpp.feature_list_gx_flags_bit6",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported),  0x00000040,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit7,
            { "vSRVCC", "diameter.3gpp.feature_list_gx_flags_bit7",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported),  0x00000080,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit8,
            { "EPC-routed", "diameter.3gpp.feature_list_gx_flags_bit8",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000100,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit9,
            { "rSRVCC", "diameter.3gpp.feature_list_gx_flags_bit9",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00000200,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit10,
            { "NetLoc", "diameter.3gpp.feature_list_gx_flags_bit10",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported),0x00000400,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit11,
            { "Usage Monitoring Congestion Handling",
              "diameter.3gpp.feature_list_gx_flags_bit11",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported),0x00000800,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit12,
            { "Extended Filter", "diameter.3gpp.feature_list_gx_flags_bit12",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00001000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit13,
            { "Trusted WLAN Access", "diameter.3gpp.feature_list_gx_flags_bit13",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00002000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit14,
            { "SGW Restoration procedures", "diameter.3gpp.feature_list_gx_flags_bit14",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00004000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit15,
            { "Time based Usage Monitoring Control", "diameter.3gpp.feature_list_gx_flags_bit15",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00008000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit16,
            { "Pending Transaction", "diameter.3gpp.feature_list_gx_flags_bit16",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00010000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit17,
            { "Application Based Charging", "diameter.3gpp.feature_list_gx_flags_bit17",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00020000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit18,
        { "Spare", "diameter.3gpp.feature_list_gx_flags_bit18",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00040000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit19,
            { "NetLoc Trusted WLAN", "diameter.3gpp.feature_list_gx_flags_bit19",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00080000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit20,
            { "Fixed Broadband Access Convergence", "diameter.3gpp.feature_list_gx_flags_bit20",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported),0x00100000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit21,
            { "Conditional APN Policy Info", "diameter.3gpp.feature_list_gx_flags_bit21",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00200000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit22,
            { "RAN and/or NAS release cause", "diameter.3gpp.feature_list_gx_flags_bit22",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00400000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit23,
            { "Presence Reporting Area Information reporting", "diameter.3gpp.feature_list_gx_flags_bit23",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x00800000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit24,
            { "P-CSCF Restoration Enhancement", "diameter.3gpp.feature_list_gx_flags_bit24",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x01000000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit25,
            { "Mission Critical QCIs", "diameter.3gpp.feature_list_gx_flags_bit25",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x02000000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit26,
            { "ResShare", "diameter.3gpp.feature_list_gx_flags_bit26",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x04000000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit27,
            { "ExUsage", "diameter.3gpp.feature_list_gx_flags_bit27",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x08000000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_feature_list_gx_flags_bit28,
        { "NBIFOM", "diameter.3gpp.feature_list_gx_flags_bit28",
            FT_BOOLEAN, 32, TFS(&tfs_supported_not_supported), 0x10000000,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cms_no_gyn_session_serv_not_allowed,
            { "No Gyn Session, service not allowed", "diameter.3gpp.cms.no_gyn_session_serv_not_allowed",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cms_no_gyn_session_serv_allowed,
            { "No Gyn Session, service allowed", "diameter.3gpp.cms.no_gyn_session_serv_allowed",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cms_rating_failed,
            { "Rating Failed", "diameter.3gpp.cms.rating_failed",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cms_user_unknown,
            { "User Unknown", "diameter.3gpp.cms.user_unknown",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cms_auth_rej,
            { "Authorization Rejected", "diameter.3gpp.cms.auth_rej",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cms_credit_ctrl_not_applicable,
            { "Credit Control Not Applicable", "diameter.3gpp.cms.credit_ctrl_not_applicable",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_cms_end_user_serv_status,
            { "End User Service Denied", "diameter.3gpp.cms.end_user_serv_status",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_subscribed,
            { "QoS-Subscribed", "diameter.3gpp.qos_subscribed",
            FT_BYTES, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_reliability_cls,
            { "Reliability class", "diameter.3gpp.qos.reliability_cls",
            FT_UINT8, BASE_DEC, VALS(diameter_3gpp_qos_reliability_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_delay_cls,
            { "Quality of Service Delay class", "diameter.3gpp.qos.delay_cls",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(diameter_3gpp_qos_delay_cls_vals), 0x38,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_prec_class,
            { "Precedence class", "diameter.3gpp.qos.prec_class",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(diameter_3gpp_qos_prec_class_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_peak_thr,
            { "Peak throughput", "diameter.3gpp.qos.qos.peak_throughput",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(diameter_3gpp_qos_peak_thr_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_mean_thr,
            { "Mean throughput", "diameter.3gpp.qos.mean_throughput",
            FT_UINT8, BASE_DEC | BASE_RANGE_STRING, RVALS(diameter_3gpp_qos_mean_thr_vals), 0x1f,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_al_ret_priority,
            { "Allocation/Retention priority", "diameter.3gpp.qos.al_ret_priority",
            FT_UINT8, BASE_DEC, NULL, 0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_del_of_err_sdu,
            { "Delivery of erroneous SDUs", "diameter.3gpp.qos.del_of_err_sdu",
            FT_UINT8, BASE_DEC, VALS(diameter_3gpp_qos_del_of_err_sdu_vals), 0x07,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_del_order,
            { "Delivery order", "diameter.3gpp.qos.del_order",
            FT_UINT8, BASE_DEC, VALS(diameter_3gpp_qos_del_order_vals), 0x18,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_traffic_cls,
            { "Traffic class", "diameter.3gpp.qos.traffic_cls",
            FT_UINT8, BASE_DEC, VALS(diameter_3gpp_qos_traffic_cls_vals), 0xe0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_maximum_sdu_size,
            { "Maximum SDU size", "diameter.3gpp.qos.qos.maximum_sdu_size",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_max_bitrate_upl,
            { "Maximum bitrate for uplink", "diameter.3gpp.qos.max_bitrate_upl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_max_bitrate_downl,
            { "Maximum bitrate for downlink", "diameter.3gpp.qos.max_bitrate_downl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_sdu_err_rat,
            { "SDU error ratio", "diameter.3gpp.qos.sdu_err_rat",
            FT_UINT8, BASE_DEC, VALS(diameter_3gpp_qos_sdu_err_rat_vals), 0x0f,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_ber,
            { "Residual Bit Error Rate (BER)", "diameter.3gpp.qos.ber",
            FT_UINT8, BASE_DEC, VALS(diameter_3gpp_qos_ber_vals), 0xf0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_traff_hdl_pri,
            { "Traffic handling priority", "diameter.3gpp.qos.traff_hdl_pri",
            FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_traff_hdl_pri_vals), 0x03,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_trans_delay,
            { "Transfer delay", "diameter.3gpp.qos.trans_delay",
            FT_UINT8, BASE_DEC, NULL, 0xfc,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_guar_bitrate_upl,
            { "Guaranteed bitrate for uplink", "diameter.3gpp.qos.guar_bitrate_upl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_guar_bitrate_downl,
            { "Guaranteed bitrate for downlink", "diameter.3gpp.qos.guar_bitrate_downl",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_diameter_3gpp_qos_source_stat_desc,
            { "Source statistics description", "diameter.3gpp.qos.source_stat_desc",
            FT_UINT8, BASE_DEC, NULL, 0x0f,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_signalling_ind,
            { "Signalling indication", "diameter.3gpp.qos.signalling_ind",
            FT_BOOLEAN, SEP_DOT, TFS(&diameter_3gpp_qos_signalling_ind_value), 0x10,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_max_bitrate_downl_ext,
            { "Maximum bitrate for downlink (extended)", "diameter.3gpp.qos.max_bitrate_downl_ext",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_guar_bitrate_downl_ext,
            { "Guaranteed bitrate for downlink (extended)", "diameter.3gpp.qos.guar_bitrate_downl_ext",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_max_bitrate_upl_ext,
            { "Maximum bitrate for uplink (extended)", "diameter.3gpp.qos.max_bitrate_upl_ext",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_guar_bitrate_upl_ext,
            { "Guaranteed bitrate for uplink (extended)", "diameter.3gpp.qos.guar_bitrate_upl_ext",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_pre_emption_vulnerability,
            { "Pre-emption vulnerability", "diameter.3gpp.qos.pre_emption_vulnerability",
            FT_BOOLEAN, SEP_DOT, TFS(&tfs_set_notset), 0x01,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_priority_level,
            { "Priority level", "diameter.3gpp.qos.priority_level",
            FT_UINT8, BASE_DEC, NULL, 0x3c,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_qos_pre_emption_capability,
            { "Pre-emption capability", "diameter.3gpp.qos.pre_emption_capability",
            FT_BOOLEAN, SEP_DOT, TFS(&tfs_set_notset), 0x40,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags,
            { "ULR Flags", "diameter.3gpp.ulr_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags_bit0,
            { "Single-Registration-Indication", "diameter.3gpp.ulr_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags_bit1,
            { "S6a/S6d-Indicator", "diameter.3gpp.ulr_flags_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags_bit2,
            { "Skip-Subscriber-Data", "diameter.3gpp.ulr_flags_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags_bit3,
            { "GPRS-Subscription-Data-Indicator", "diameter.3gpp.ulr_flags_bit3",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags_bit4,
            { "Node-Type-Indicator", "diameter.3gpp.ulr_flags_bit4",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags_bit5,
            { "Initial-Attach-Indicator", "diameter.3gpp.ulr_flags_bit5",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags_bit6,
            { "PS-LCS-Not-Supported-By-UE", "diameter.3gpp.ulr_flags_bit6",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ulr_flags_bit7,
            { "SMS-Only-Indication", "diameter.3gpp.ulr_flags_bit7",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ula_flags,
            { "ULA Flags", "diameter.3gpp.ula_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ula_flags_bit0,
            { "Separation Indication", "diameter.3gpp.ula_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ula_flags_bit1,
            { "MME Registered for SMS", "diameter.3gpp.ula_flags_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags,
            { "DSR Flags", "diameter.3gpp.dsr_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit0,
            { "Regional Subscription Withdrawal", "diameter.3gpp.dsr_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit1,
            { "Complete APN Configuration Profile Withdrawal", "diameter.3gpp.dsr_flags_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit2,
            { "Subscribed Charging Characteristics Withdrawal", "diameter.3gpp.dsr_flags_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit3,
            { "PDN subscription contexts Withdrawal", "diameter.3gpp.dsr_flags_bit3",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit4,
            { "STN-SR", "diameter.3gpp.dsr_flags_bit4",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit5,
            { "Complete PDP context list Withdrawal", "diameter.3gpp.dsr_flags_bit5",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit6,
            { "PDP contexts Withdrawal", "diameter.3gpp.dsr_flags_bit6",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit7,
            { "Roaming Restricted due to unsupported feature", "diameter.3gpp.dsr_flags_bit7",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit8,
            { "Trace Data Withdrawal", "diameter.3gpp.dsr_flags_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit9,
            { "CSG Deleted", "diameter.3gpp.dsr_flags_bit9",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit10,
            { "APN-OI-Replacement", "diameter.3gpp.dsr_flags_bit10",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit11,
            { "GMLC List Withdrawal", "diameter.3gpp.dsr_flags_bit11",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit12,
            { "LCS Withdrawal", "diameter.3gpp.dsr_flags_bit12",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit13,
            { "SMS Withdrawal", "diameter.3gpp.dsr_flags_bit13",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit14,
            { "Subscribed periodic RAU-TAU Timer Withdrawal", "diameter.3gpp.dsr_flags_bit14",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit15,
            { "Subscribed VSRVCC Withdrawal", "diameter.3gpp.dsr_flags_bit15",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit16,
            { "A-MSISDN Withdrawal", "diameter.3gpp.dsr_flags_bit16",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit17,
            { "ProSe Withdrawal", "diameter.3gpp.dsr_flags_bit17",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsr_flags_bit18,
            { "Reset-IDs", "diameter.3gpp.dsr_flags_bit18",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsa_flags,
            { "DSA Flags", "diameter.3gpp.dsa_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_dsa_flags_bit0,
            { "Network Node area restricted", "diameter.3gpp.dsa_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ida_flags,
            { "IDA Flags", "diameter.3gpp.ida_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ida_flags_bit0,
            { "Network Node area restricted", "diameter.3gpp.ida_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_pua_flags,
            { "PUA Flags", "diameter.3gpp.pua_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_pua_flags_bit0,
            { "Freeze M-TMSI", "diameter.3gpp.pua_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_pua_flags_bit1,
            { "Freeze P-TMSI", "diameter.3gpp.pua_flags_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags,
            { "NOR Flags", "diameter.3gpp.nor_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit0,
            { "Single-Registration-Indication", "diameter.3gpp.nor_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit1,
            { "SGSN area restricted", "diameter.3gpp.nor_flags_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit2,
            { "Ready for SM", "diameter.3gpp.nor_flags_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit3,
            { "UE Reachable", "diameter.3gpp.nor_flags_bit3",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit4,
            { "Delete all APN and PDN GW identity pairs", "diameter.3gpp.nor_flags_bit4",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit5,
            { "UE Reachable from SGSN", "diameter.3gpp.nor_flags_bit5",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit6,
            { "Ready for SM from MME", "diameter.3gpp.nor_flags_bit6",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit7,
            { "Homogeneous Support of IMS Voice Over PS Sessions", "diameter.3gpp.nor_flags_bit7",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit8,
            { "S6a/S6d-Indicator", "diameter.3gpp.nor_flags_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_nor_flags_bit9,
            { "Removal of MME Registration for SMS", "diameter.3gpp.nor_flags_bit9",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags,
            { "IDR Flags", "diameter.3gpp.idr_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit0,
            { "UE Reachability Request", "diameter.3gpp.idr_flags_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit1,
            { "T-ADS Data Request", "diameter.3gpp.idr_flags_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit2,
            { "EPS User State Request", "diameter.3gpp.idr_flags_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit3,
            { "EPS Location Information Request", "diameter.3gpp.idr_flags_bit3",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit4,
            { "Current Location Request", "diameter.3gpp.idr_flags_bit4",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit5,
            { "Local Time Zone Request", "diameter.3gpp.idr_flags_bit5",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit6,
            { "Remove SMS Registration", "diameter.3gpp.idr_flags_bit6",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit7,
            { "RAT-Type Requested", "diameter.3gpp.idr_flags_bit7",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_idr_flags_bit8,
            { "P-CSCF Restoration Request", "diameter.3gpp.idr_flags_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_ipv6addr,
            { "IPv6 Address", "diameter.3gpp.ipv6addr",
            FT_IPv6, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_abs_time_ofmbms_data_tfer,
            { "Absolute Time of MBMS Data Transfer", "diameter.3gpp.mbms_abs_time_ofmbms_data_tfer",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_udp_port ,
            { "UDP Port", "diameter.3gpp.udp_port",
            FT_UINT8, BASE_DEC, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_imeisv,
            { "IMEISV", "diameter.3gpp.imeisv",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_af_charging_identifier,
            { "AF-Charging-Identifier", "diameter.3gpp.af_charging_identifier",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_af_application_identifier,
            { "AF-Application-Identifier", "diameter.3gpp.af_application_identifier",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_charging_rule_name,
            { "Charging-Rule-Name", "diameter.3gpp.charging_rule_name",
            FT_STRING, BASE_NONE, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_event,
            { "MBMS-Bearer-Event", "diameter.3gpp.mbms_bearer_event",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_event_bit0,
            { "Bearer Terminated", "diameter.3gpp.mbms_bearer_event_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result,
            { "MBMS-Bearer-Result", "diameter.3gpp.mbms_bearer_result",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit0,
            { "Success", "diameter.3gpp.mbms_bearer_result_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit1,
            { "Authorization rejected", "diameter.3gpp.mbms_bearer_result_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit2,
            { "Resources exceeded", "diameter.3gpp.mbms_bearer_result_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit3,
            { "Unknown TMGI", "diameter.3gpp.mbms_bearer_result_bit3",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit4,
            { "TMGI not in use", "diameter.3gpp.mbms_bearer_result_bit4",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit5,
            { "Overlapping MBMS-Service-Area", "diameter.3gpp.mbms_bearer_result_bit5",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit6,
            { "Unknown Flow Identifier", "diameter.3gpp.mbms_bearer_result_bit6",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit7,
            { "QoS Authorization Rejected", "diameter.3gpp.mbms_bearer_result_bit7",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit8,
            { "Unknown MBMS-Service-Area", "diameter.3gpp.mbms_bearer_result_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit9,
            { "MBMS-Service-Area Authorization Rejected", "diameter.3gpp.mbms_bearer_result_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit10,
            { "MBMS-Start-Time", "diameter.3gpp.mbms_bearer_result_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_mbms_bearer_result_bit11,
            { "Invalid AVP combination", "diameter.3gpp.mbms_bearer_result_bit8",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_allocation_result,
            { "TMGI-Allocation-Result", "diameter.3gpp.tmgi_allocation_result",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_allocation_result_bit0,
            { "Success", "diameter.3gpp.tmgi_allocation_result_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_allocation_result_bit1,
            { "Authorization rejected", "diameter.3gpp.tmgi_allocation_result_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_allocation_result_bit2,
            { "Resources exceeded", "diameter.3gpp.tmgi_allocation_result_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_allocation_result_bit3,
            { "Unknown TMGI", "diameter.3gpp.tmgi_allocation_result_bit3",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_allocation_result_bit4,
            { "Too many TMGIs requested", "diameter.3gpp.tmgi_allocation_result_bit4",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_deallocation_result,
            { "TMGI-Deallocation-Result", "diameter.3gpp.tmgi_deallocation_result",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_deallocation_result_bit0,
            { "Success", "diameter.3gpp.tmgi_deallocation_result_bit0",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_deallocation_result_bit1,
            { "Authorization rejected", "diameter.3gpp.tmgi_deallocation_result_bit1",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_tmgi_deallocation_result_bit2,
            { "Unknown TMGI", "diameter.3gpp.tmgi_deallocation_result_bit2",
            FT_BOOLEAN, BASE_NONE, TFS(&tfs_set_notset), 0x0,
            NULL, HFILL }
        },
        { &hf_diameter_3gpp_sar_flags,
        { "SAR Flags", "diameter.3gpp.sar_flags",
            FT_UINT32, BASE_HEX, NULL, 0x0,
            NULL, HFILL }
        },

        { &hf_diameter_3gpp_sar_flags_flags_bit0,
        { "P-CSCF Restoration Indication", "diameter.3gpp.sar_flags_flags_bit0",
            FT_BOOLEAN, 32, TFS(&tfs_set_notset), 0x00000001,
            NULL, HFILL }
        },
};


    /* Setup protocol subtree array */
    static gint *ett[] = {
        &diameter_3gpp_path_ett,
        &diameter_3gpp_uar_flags_ett,
        &diameter_3gpp_feature_list_ett,
        &diameter_3gpp_tmgi_ett,
        &diameter_3gpp_cms_ett,
        &diameter_3gpp_qos_subscribed_ett,
        &diameter_3gpp_ulr_flags_ett,
        &diameter_3gpp_ula_flags_ett,
        &diameter_3gpp_dsr_flags_ett,
        &diameter_3gpp_dsa_flags_ett,
        &diameter_3gpp_ida_flags_ett,
        &diameter_3gpp_pua_flags_ett,
        &diameter_3gpp_nor_flags_ett,
        &diameter_3gpp_idr_flags_ett,
        &diameter_3gpp_mbms_bearer_event_ett,
        &diameter_3gpp_mbms_bearer_result_ett,
        &diameter_3gpp_tmgi_allocation_result_ett,
        &diameter_3gpp_tmgi_deallocation_result_ett,
        &diameter_3gpp_sar_flags_ett,
    };

    expert_module_t *expert_diameter_3gpp;

    static ei_register_info ei[] = {
        { &ei_diameter_3gpp_plmn_id_wrong_len,
        { "diameter_3gpp.plmn_id_wrong_len", PI_PROTOCOL, PI_ERROR, "PLMN Id should be 3 octets", EXPFILL } },
    };

    /* Required function calls to register the header fields and subtrees used */
    proto_diameter_3gpp = proto_register_protocol("Diameter 3GPP","Diameter3GPP", "diameter.3gpp");
    proto_register_field_array(proto_diameter_3gpp, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    expert_diameter_3gpp = expert_register_protocol(proto_diameter_3gpp);
    expert_register_field_array(expert_diameter_3gpp, ei, array_length(ei));

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
