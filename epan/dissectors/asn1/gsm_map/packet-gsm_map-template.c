/* XXX see bug 1852:
 *
 * packet-gsm_map.c: There are 1174 display filter fields registered.  Most are
 * prefixed appropriately as "gsm_map", but many others are prefixed as
 * "gsm_old", or even "gad", "gsm_ss", or with no prefix at all.  I don't know
 * if the ones with "gsm_old" are simply obsolete display filter fields or if
 * they should be prefixed as "gsm_map.old." or what.  Similar uncertainties
 * for the others. Someone more knowledgeable than I am with respect to this
 * dissector should provide a patch for it.
 */

/* packet-gsm_map-template.c
 * Routines for GSM MobileApplication packet dissection
 * including GSM SS.
 * Copyright 2004 - 2010 , Anders Broman <anders.broman [AT] ericsson.com>
 * Based on the dissector by:
 * Felix Fei <felix.fei [AT] utstar.com>
 * and Michael Lum <mlum [AT] telostech.com>
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 * References GSM MAP:
 * ETSI TS 129 002
 * Updated to ETSI TS 129 002 V7.5.0 (3GPP TS 29.002 V7.5.0 (2006-09) Release 7)
 * Updated to ETSI TS 129 002 V8.4.0 (3GPP TS 29.002 V8.1.0 (2007-06) Release 8)
 * References GSM SS
 * References: 3GPP TS 24.080
 */

#include "config.h"

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/stat_tap_ui.h>
#include <epan/tap.h>
#include <epan/oids.h>
#include <epan/expert.h>
#include <epan/proto_data.h>
#include <epan/conversation.h>
#include <wsutil/strtoi.h>

#include <epan/asn1.h>
#include "packet-ber.h"
#include "packet-per.h"
#include "packet-q931.h"
#include "packet-gsm_map.h"
#include "packet-gsm_a_common.h"
#include "packet-tcap.h"
#include "packet-e164.h"
#include "packet-e212.h"
#include "packet-smpp.h"
#include "packet-gsm_sms.h"
#include "packet-ranap.h"
#include "packet-isup.h"

#define PNAME  "GSM Mobile Application"
#define PSNAME "GSM_MAP"
#define PFNAME "gsm_map"

void proto_register_gsm_map(void);
void proto_reg_handoff_gsm_map(void);

/* Initialize the protocol and registered fields */
static int proto_gsm_map = -1;
static int proto_gsm_map_dialogue = -1;
static int proto_gsm_map_ms = -1;

static int hf_gsm_map_old_Component_PDU = -1;
static int hf_gsm_map_getPassword = -1;
static int hf_gsm_map_currentPassword = -1;
static int hf_gsm_map_extension = -1;
static int hf_gsm_map_nature_of_number = -1;
static int hf_gsm_map_number_plan = -1;
static int hf_gsm_map_address_digits = -1;
static int hf_gsm_map_TBCD_digits = -1;
static int hf_gsm_map_Ss_Status_unused = -1;
static int hf_gsm_map_Ss_Status_q_bit = -1;
static int hf_gsm_map_Ss_Status_p_bit = -1;
static int hf_gsm_map_Ss_Status_r_bit = -1;
static int hf_gsm_map_Ss_Status_a_bit = -1;
static int hf_gsm_map_notification_to_forwarding_party = -1;
static int hf_gsm_map_redirecting_presentation = -1;
static int hf_gsm_map_notification_to_calling_party = -1;
static int hf_gsm_map_forwarding_reason = -1;
static int hf_gsm_map_pdp_type_org = -1;
static int hf_gsm_map_etsi_pdp_type_number = -1;
static int hf_gsm_map_ietf_pdp_type_number = -1;
static int hf_gsm_map_ext_qos_subscribed_pri = -1;

static int hf_gsm_map_qos_traffic_cls = -1;
static int hf_gsm_map_qos_del_order = -1;
static int hf_gsm_map_qos_del_of_err_sdu = -1;
static int hf_gsm_map_qos_ber = -1;
static int hf_gsm_map_qos_sdu_err_rat = -1;
static int hf_gsm_map_qos_traff_hdl_pri = -1;
static int hf_gsm_map_qos_max_sdu = -1;
static int hf_gsm_map_max_brate_ulink = -1;
static int hf_gsm_map_max_brate_dlink = -1;
static int hf_gsm_map_qos_transfer_delay = -1;
static int hf_gsm_map_guaranteed_max_brate_ulink = -1;
static int hf_gsm_map_guaranteed_max_brate_dlink = -1;
static int hf_gsm_map_GSNAddress_IPv4 = -1;
static int hf_gsm_map_GSNAddress_IPv6 = -1;
static int hf_gsm_map_ranap_service_Handover = -1;
static int hf_gsm_map_IntegrityProtectionInformation = -1;
static int hf_gsm_map_EncryptionInformation = -1;
static int hf_gsm_map_ss_SS_UserData = -1;
static int hf_gsm_map_cbs_coding_grp = -1;
static int hf_gsm_map_cbs_coding_grp0_lang = -1;
static int hf_gsm_map_cbs_coding_grp1_lang = -1;
static int hf_gsm_map_cbs_coding_grp2_lang = -1;
static int hf_gsm_map_cbs_coding_grp3_lang = -1;
static int hf_gsm_map_cbs_coding_grp4_7_comp = -1;
static int hf_gsm_map_cbs_coding_grp4_7_class_ind = -1;
static int hf_gsm_map_cbs_coding_grp4_7_char_set = -1;
static int hf_gsm_map_cbs_coding_grp4_7_class = -1;
static int hf_gsm_map_cbs_coding_grp15_mess_code = -1;
static int hf_gsm_map_cbs_coding_grp15_class = -1;
static int hf_gsm_map_tmsi = -1;
static int hf_gsm_map_ie_tag = -1;
static int hf_gsm_map_len = -1;
static int hf_gsm_map_disc_par = -1;
static int hf_gsm_map_dlci = -1;
static int hf_gsm_apn_str = -1;
static int hf_gsm_map_ericsson_locationInformation_rat = -1;
static int hf_gsm_map_ericsson_locationInformation_lac = -1;
static int hf_gsm_map_ericsson_locationInformation_ci = -1;
static int hf_gsm_map_ericsson_locationInformation_sac = -1;
static int hf_gsm_map_ussd_string = -1;
static int hf_gsm_map_spare_bits = -1;
static int hf_gsm_map_qos_signalling_ind = -1;
static int hf_gsm_map_qos_source_stat_desc = - 1;
static int hf_gsm_map_qos_max_bitrate_upl_ext = -1;
static int hf_gsm_map_qos_max_bitrate_downl_ext = -1;
static int hf_gsm_map_qos_guar_bitrate_upl_ext = -1;
static int hf_gsm_map_qos_guar_bitrate_downl_ext = -1;
/*
static int hf_gsm_map_qos_max_bitrate_upl_ext2 = -1;
static int hf_gsm_map_qos_max_bitrate_downl_ext2 = -1;
static int hf_gsm_map_qos_guar_bitrate_upl_ext2 = -1;
static int hf_gsm_map_qos_guar_bitrate_downl_ext2 = -1;
*/
static int hf_gsm_map_earp_pci = -1;
static int hf_gsm_map_earp_pl = -1;
static int hf_gsm_map_earp_pvi = -1;

#include "packet-gsm_map-hf.c"

/* Initialize the subtree pointers */
static gint ett_gsm_map = -1;
static gint ett_gsm_map_InvokeId = -1;
static gint ett_gsm_map_InvokePDU = -1;
static gint ett_gsm_map_ReturnResultPDU = -1;
static gint ett_gsm_map_ReturnErrorPDU = -1;
static gint ett_gsm_map_ReturnResult_result = -1;
static gint ett_gsm_map_ReturnError_result = -1;
static gint ett_gsm_map_GSMMAPPDU = -1;
static gint ett_gsm_map_ext_qos_subscribed = -1;
static gint ett_gsm_map_pdptypenumber = -1;
static gint ett_gsm_map_RAIdentity = -1;
static gint ett_gsm_map_LAIFixedLength = -1;
static gint ett_gsm_map_isdn_address_string = -1;
static gint ett_gsm_map_geo_desc = -1;
static gint ett_gsm_map_LongSignalInfo = -1;
static gint ett_gsm_map_RadioResourceInformation =-1;
static gint ett_gsm_map_MSNetworkCapability =-1;
static gint ett_gsm_map_MSRadioAccessCapability = -1;
static gint ett_gsm_map_externalsignalinfo = -1;
static gint ett_gsm_map_cbs_data_coding = -1;
static gint ett_gsm_map_GlobalCellId = -1;
static gint ett_gsm_map_GeographicalInformation = -1;
static gint ett_gsm_map_apn_str = -1;
static gint ett_gsm_map_LocationNumber = -1;
static gint ett_gsm_map_ericsson_locationInformation = -1;
static gint ett_gsm_map_extension_data = -1;
static gint ett_gsm_map_tbcd_digits = -1;
static gint ett_gsm_map_ussd_string = -1;
static gint ett_gsm_map_ext2_qos_subscribed = -1;
static gint ett_gsm_map_ext3_qos_subscribed = -1;
static gint ett_gsm_map_e_utranCellGlobalIdentity = -1;
static gint ett_gsm_map_TA_id = -1;
static gint ett_gsm_map_GeodeticInformation = -1;

#include "packet-gsm_map-ett.c"

static expert_field ei_gsm_map_unknown_sequence3 = EI_INIT;
static expert_field ei_gsm_map_unknown_sequence = EI_INIT;
static expert_field ei_gsm_map_unknown_parameter = EI_INIT;
static expert_field ei_gsm_map_unknown_invokeData = EI_INIT;
static expert_field ei_gsm_map_undecoded = EI_INIT;

static dissector_handle_t       gsm_sms_handle; /* SMS TPDU */
static dissector_handle_t       ranap_handle;
static dissector_handle_t       dtap_handle;
static dissector_handle_t       map_handle;
static dissector_handle_t       bssap_handle;
static dissector_table_t        map_prop_arg_opcode_table; /* prorietary operation codes */
static dissector_table_t        map_prop_res_opcode_table; /* prorietary operation codes */
static dissector_table_t        map_prop_err_opcode_table; /* prorietary operation codes */
/* Preferenc settings default */
#define MAX_SSN 254
static range_t *global_ssn_range;
#define APPLICATON_CONTEXT_FROM_TRACE 0
static gint pref_application_context_version = APPLICATON_CONTEXT_FROM_TRACE;
static gboolean pref_ericsson_proprietary_ext = FALSE;

/* Global variables */
static guint32 opcode=0;
static guint32 errorCode;
static int application_context_version;
static guint ProtocolId;
static guint AccessNetworkProtocolId;
static int gsm_map_tap = -1;
static guint8 gsmmap_pdu_type = 0;
static guint8 gsm_map_pdu_size = 0;

#define SMS_ENCODING_NOT_SET    0
#define SMS_ENCODING_7BIT       1
#define SMS_ENCODING_8BIT       2
#define SMS_ENCODING_UCS2       3
#define SMS_ENCODING_7BIT_LANG  4
#define SMS_ENCODING_UCS2_LANG  5

static guint8 sms_encoding;

/* Forward declarations */
static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx);
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx);
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx);
const gchar* gsm_map_opr_code(guint32 val, proto_item *item);

typedef struct {
  struct tcap_private_t * tcap_private;
  sccp_msg_info_t *sccp_msg_info;
  tvbuff_t *signal_info_tvb;
} gsm_map_private_info_t;

typedef struct {
  wmem_tree_t *packets;
} gsm_map_conv_info_t;

static gsm_map_packet_info_t *gsm_map_get_packet_info(asn1_ctx_t *actx, gboolean store_conv_info)
{
  gsm_map_packet_info_t *gsm_map_pi = (gsm_map_packet_info_t*)p_get_proto_data(wmem_file_scope(), actx->pinfo, proto_gsm_map, 0);
  if (!gsm_map_pi) {
    gsm_map_private_info_t *gsm_map_priv = (gsm_map_private_info_t*)actx->value_ptr;
    gsm_map_pi = wmem_new0(wmem_file_scope(), gsm_map_packet_info_t);
    p_add_proto_data(wmem_file_scope(), actx->pinfo, proto_gsm_map, 0, gsm_map_pi);
    if (gsm_map_priv && gsm_map_priv->tcap_private) {
      gsm_map_pi->tcap_src_tid = gsm_map_priv->tcap_private->src_tid;
      if (store_conv_info) {
        conversation_t *conversation;
        gsm_map_conv_info_t *gsm_map_info;
        wmem_tree_key_t key[3];
        conversation = find_or_create_conversation(actx->pinfo);
        gsm_map_info = (gsm_map_conv_info_t *)conversation_get_proto_data(conversation, proto_gsm_map);
        if (!gsm_map_info) {
            gsm_map_info = wmem_new(wmem_file_scope(), gsm_map_conv_info_t);
            gsm_map_info->packets = wmem_tree_new(wmem_file_scope());
            conversation_add_proto_data(conversation, proto_gsm_map, gsm_map_info);
        }
        key[0].length = 1;
        key[0].key = &gsm_map_priv->tcap_private->src_tid;
        key[1].length = 1;
        key[1].key = &actx->pinfo->num;
        key[2].length = 0;
        key[2].key = NULL;
        wmem_tree_insert32_array(gsm_map_info->packets, key, (void *)gsm_map_pi);
      }
    }
  }
  return gsm_map_pi;
}

static gsm_map_packet_info_t *gsm_map_get_matching_tcap_info(asn1_ctx_t *actx)
{
  gsm_map_private_info_t *gsm_map_priv = (gsm_map_private_info_t*)actx->value_ptr;
  if (gsm_map_priv && gsm_map_priv->tcap_private) {
    conversation_t *conversation;
    gsm_map_conv_info_t *gsm_map_info;
    wmem_tree_key_t key[3];
    gsm_map_packet_info_t *gsm_map_pi;
    conversation = find_or_create_conversation(actx->pinfo);
    gsm_map_info = (gsm_map_conv_info_t *)conversation_get_proto_data(conversation, proto_gsm_map);
    if (!gsm_map_info) {
      gsm_map_info = wmem_new(wmem_file_scope(), gsm_map_conv_info_t);
      gsm_map_info->packets = wmem_tree_new(wmem_file_scope());
      conversation_add_proto_data(conversation, proto_gsm_map, gsm_map_info);
    }
    key[0].length = 1;
    key[0].key = &gsm_map_priv->tcap_private->src_tid;
    key[1].length = 1;
    key[1].key = &actx->pinfo->num;
    key[2].length = 0;
    key[2].key = NULL;
    gsm_map_pi = (gsm_map_packet_info_t*)wmem_tree_lookup32_array_le(gsm_map_info->packets, key);
    if (gsm_map_pi && gsm_map_pi->tcap_src_tid == gsm_map_priv->tcap_private->src_tid)
      return gsm_map_pi;
  }
  return NULL;
}

/* Value strings */

const value_string gsm_map_PDP_Type_Organisation_vals[] = {
  {  0, "ETSI" },
  {  1, "IETF" },
  { 0, NULL }
};

const value_string gsm_map_ietf_defined_pdp_vals[] = {
  {  0x21, "IPv4 Address" },
  {  0x57, "IPv6 Address" },
  { 0, NULL }
};

const value_string gsm_map_etsi_defined_pdp_vals[] = {
  {  1, "PPP" },
  { 0, NULL }
};

static const value_string gsm_map_tag_vals[] = {
  {  0x4, "Bearer Capability" },
  { 0, NULL }
};

static const value_string gsm_map_disc_par_vals[] = {
  {  0, "Not Transparent" },
  {  1, "Transparent" },
  { 0, NULL }
};

static const value_string gsm_map_ericsson_locationInformation_rat_vals[] = {
  { 0x0, "GSM" },
  { 0x1, "UMTS" },
  { 0x2, "LTE" },
  { 0xf, "No information" },
  { 0, NULL }
};


/* returns value in kb/s */
static guint
gsm_map_calc_bitrate(guint8 value){

  guint8 granularity;
  guint returnvalue;

  if (value == 0xff)
    return 0;

  granularity = value >> 6;
  returnvalue = value & 0x7f;
  switch (granularity){
  case 0:
    break;
  case 1:
    returnvalue = ((returnvalue - 0x40) << 3)+64;
    break;
  case 2:
    returnvalue = (returnvalue << 6)+576;
    break;
  case 3:
    returnvalue = (returnvalue << 6)+576;
    break;
  }
  return returnvalue;

}

static void
dissect_gsm_map_ext_qos_subscribed(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, asn1_ctx_t *actx){
  int offset = 0;
  proto_tree *subtree;
  guint8 octet;
  guint16 value;

  subtree = proto_item_add_subtree(actx->created_item, ett_gsm_map_ext_qos_subscribed);
  /*  OCTET 1:
    Allocation/Retention Priority (This octet encodes each priority level defined in
    23.107 as the binary value of the priority level, declaration in 29.060)
    Octets 2-9 are coded according to 3GPP TS 24.008[35] Quality of Service Octets
    6-13.
   */
  /* Allocation/Retention Priority */
  proto_tree_add_item(subtree, hf_gsm_map_ext_qos_subscribed_pri, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /* Quality of Service Octets 6-13.( Octet 2 - 9 Here) */

  /* Traffic class, octet 6 (see 3GPP TS 23.107) Bits 8 7 6 */
  proto_tree_add_item(subtree, hf_gsm_map_qos_traffic_cls, tvb, offset, 1, ENC_BIG_ENDIAN);
  /* Delivery order, octet 6 (see 3GPP TS 23.107) Bits 5 4 */
  proto_tree_add_item(subtree, hf_gsm_map_qos_del_order, tvb, offset, 1, ENC_BIG_ENDIAN);
  /* Delivery of erroneous SDUs, octet 6 (see 3GPP TS 23.107) Bits 3 2 1 */
  proto_tree_add_item(subtree, hf_gsm_map_qos_del_of_err_sdu, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /* Maximum SDU size, octet 7 (see 3GPP TS 23.107) */
  octet = tvb_get_guint8(tvb,offset);
  switch (octet){
  case 0:
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, octet, "Reserved");
    break;
  case 0x93:
    value = 1502;
    proto_tree_add_uint(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, value);
    break;
  case 0x98:
    value = 1510;
    proto_tree_add_uint(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, value);
    break;
  case 0x99:
    value = 1532;
    proto_tree_add_uint(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, value);
    break;
  default:
    if (octet<0x97){
      value = octet * 10;
      proto_tree_add_uint(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, value);
    }else{
      proto_tree_add_uint_format_value(subtree, hf_gsm_map_qos_max_sdu, tvb, offset, 1, octet, "0x%x not defined in TS 24.008", octet);
    }
  }
  offset++;

  /* Maximum bit rate for uplink, octet 8 */
  octet = tvb_get_guint8(tvb,offset);
  if (octet == 0 ){
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_max_brate_ulink, tvb, offset, 1, octet, "Reserved"  );
  }else{
    proto_tree_add_uint(subtree, hf_gsm_map_max_brate_ulink, tvb, offset, 1, gsm_map_calc_bitrate(octet));
  }
  offset++;
  /* Maximum bit rate for downlink, octet 9 (see 3GPP TS 23.107) */
  octet = tvb_get_guint8(tvb,offset);
  if (octet == 0 ){
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_max_brate_dlink, tvb, offset, 1, octet, "Reserved"  );
  }else{
    proto_tree_add_uint(subtree, hf_gsm_map_max_brate_dlink, tvb, offset, 1, gsm_map_calc_bitrate(octet));
  }
  offset++;
  /* Residual Bit Error Rate (BER), octet 10 (see 3GPP TS 23.107) Bits 8 7 6 5 */
  proto_tree_add_item(subtree, hf_gsm_map_qos_ber, tvb, offset, 1, ENC_BIG_ENDIAN);
  /* SDU error ratio, octet 10 (see 3GPP TS 23.107) */
  proto_tree_add_item(subtree, hf_gsm_map_qos_sdu_err_rat, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /* Transfer delay, octet 11 (See 3GPP TS 23.107) Bits 8 7 6 5 4 3 */
  proto_tree_add_item(subtree, hf_gsm_map_qos_transfer_delay, tvb, offset, 1, ENC_BIG_ENDIAN);
  /* Traffic handling priority, octet 11 (see 3GPP TS 23.107) Bits 2 1 */
  proto_tree_add_item(subtree, hf_gsm_map_qos_traff_hdl_pri, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;

  /*  Guaranteed bit rate for uplink, octet 12 (See 3GPP TS 23.107)
      Coding is identical to that of Maximum bit rate for uplink.
  */
  octet = tvb_get_guint8(tvb,offset);
  if (octet == 0 ){
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_guaranteed_max_brate_ulink, tvb, offset, 1, octet, "Subscribed guaranteed bit rate for uplink/reserved");
  }else{
    proto_tree_add_uint(subtree, hf_gsm_map_guaranteed_max_brate_ulink, tvb, offset, 1, gsm_map_calc_bitrate(octet));
  }
  offset++;

  /*  Guaranteed bit rate for downlink, octet 13(See 3GPP TS 23.107)
      Coding is identical to that of Maximum bit rate for uplink.
  */
  octet = tvb_get_guint8(tvb,offset);
  if (octet == 0 ){
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_guaranteed_max_brate_dlink, tvb, offset, 1, octet, "Subscribed guaranteed bit rate for downlink/reserved");
  }else{
    proto_tree_add_uint(subtree, hf_gsm_map_guaranteed_max_brate_dlink, tvb, offset, 1, gsm_map_calc_bitrate(octet));
  }

}

/*
Ext2-QoS-Subscribed ::= OCTET STRING (SIZE (1..3))
-- Octets 1-3 are coded according to 3GPP TS 24.008 [35] Quality of Service Octets 14-16.
-- If Quality of Service information is structured with 14 octet length, then
-- Octet 1 is coded according to 3GPP TS 24.008 [35] Quality of Service Octet 14.

*/

static const true_false_string gsm_map_qos_signalling_ind_value = {
    "Optimised for signalling traffic",
    "Not optimised for signalling traffic"
};
#if 0
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
#endif
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
#if 0
static guint32
qos_calc_ext2_bitrate(guint8 oct)
{
    if (oct <= 0x3d)
        return (256 + oct * 4);
    if (oct <= 0xa1)
        return (500 + (oct - 0x3d) * 10);
    if (oct <= 0xf6)
        return (1500 + (oct - 0xa1) * 100);

    return 10000;
}
#endif
static void
dissect_gsm_map_ext2_qos_subscribed(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, asn1_ctx_t *actx) {

    int offset = 0;
    proto_tree *subtree;
    const gchar *str;
    guint8 oct, tmp_oct;
    guint32 temp32;
    int length = tvb_reported_length(tvb);

    subtree = proto_item_add_subtree(actx->created_item, ett_gsm_map_ext2_qos_subscribed);

    /* Ocet 14 */
    oct = tvb_get_guint8(tvb, offset);
    proto_tree_add_bits_item(subtree, hf_gsm_map_spare_bits, tvb, (offset << 3), 3, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_map_qos_signalling_ind, tvb, offset, 1, ENC_BIG_ENDIAN);

    tmp_oct = oct & 7;
    if (tmp_oct == 0x01)
        str = "speech";
    else
        str = "unknown";

    proto_tree_add_uint_format_value(subtree, hf_gsm_map_qos_source_stat_desc, tvb,
        offset, 1, oct, "%s (%u)", str, tmp_oct);

    offset += 1;
    if (length == offset) {
        return;
    }

    /* Octet 15 */
    oct = tvb_get_guint8(tvb, offset);

    if (oct == 0x00)
        str = "Use the value indicated by the Maximum bit rate for downlink";
    else
    {
        temp32 = qos_calc_ext_bitrate(oct);
        if (temp32 % 1000 == 0)
            str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
        else
            str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
    }
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_qos_max_bitrate_downl_ext, tvb,
        offset, 1, oct, "%s (%u)", str, oct);

    offset += 1;
    if (length == offset) {
        return;
    }

    /* Octet 16 */
    oct = tvb_get_guint8(tvb, offset);

    if (oct == 0x00)
        str = "Use the value indicated by the Guaranteed bit rate for downlink";
    else
    {
        temp32 = qos_calc_ext_bitrate(oct);
        if (temp32 % 1000 == 0)
            str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
        else
            str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
    }
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_qos_guar_bitrate_downl_ext, tvb,
        offset, 1, oct, "%s (%u)", str, oct);

}

/*
Ext3-QoS-Subscribed ::= OCTET STRING (SIZE (1..2))
-- Octets 1-2 are coded according to 3GPP TS 24.008 [35] Quality of Service Octets 17-18.

*/
static void
dissect_gsm_map_ext3_qos_subscribed(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, asn1_ctx_t *actx) {

    int offset = 0;
    proto_tree *subtree;
    const gchar *str;
    guint8 oct;
    guint32 temp32;
    int length = tvb_reported_length(tvb);

    subtree = proto_item_add_subtree(actx->created_item, ett_gsm_map_ext3_qos_subscribed);

    /* Maximum bit rate for uplink (extended) Octet 17 */
    oct = tvb_get_guint8(tvb, offset);

    if (oct == 0x00)
        str = "Use the value indicated by the Maximum bit rate for uplink";
    else
    {
        temp32 = qos_calc_ext_bitrate(oct);
        if (temp32 % 1000 == 0)
            str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
        else
            str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
    }
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_qos_max_bitrate_upl_ext, tvb,
        offset, 1, oct, "%s (%u)", str, oct);

    offset += 1;
    if (length == offset) {
        return;
    }

    /* Guaranteed bit rate for uplink (extended) Octet 18 */
    oct = tvb_get_guint8(tvb, offset);

    if (oct == 0x00)
        str = "Use the value indicated by the Guaranteed bit rate for uplink";
    else
    {
        temp32 = qos_calc_ext_bitrate(oct);
        if (temp32 % 1000 == 0)
            str = wmem_strdup_printf(pinfo->pool, "%u Mbps", temp32 / 1000);
        else
            str = wmem_strdup_printf(pinfo->pool, "%u kbps", temp32);
    }
    proto_tree_add_uint_format_value(subtree, hf_gsm_map_qos_guar_bitrate_upl_ext, tvb,
        offset, 1, oct, "%s (%u)", str, oct);

    return;
}

static void
dissect_gsm_map_ext4_qos_subscribed(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree _U_, asn1_ctx_t *actx) {
    int offset = 0;
    proto_tree *subtree;

    subtree = proto_item_add_subtree(actx->created_item, ett_gsm_map_ext3_qos_subscribed);

    proto_tree_add_item(subtree, hf_gsm_map_earp_pvi, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_map_earp_pl, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(subtree, hf_gsm_map_earp_pci, tvb, offset, 1, ENC_BIG_ENDIAN);

}
#define  ELLIPSOID_POINT 0
#define  ELLIPSOID_POINT_WITH_UNCERT_CIRC 1
#define  ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE 3
#define  POLYGON 5
#define  ELLIPSOID_POINT_WITH_ALT 8
#define  ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID 9
#define  ELLIPSOID_ARC 10
/*
4 3 2 1
0 0 0 0 Ellipsoid Point
0 0 0 1 Ellipsoid point with uncertainty Circle
0 0 1 1 Ellipsoid point with uncertainty Ellipse
0 1 0 1 Polygon
1 0 0 0 Ellipsoid point with altitude
1 0 0 1 Ellipsoid point with altitude and uncertainty Ellipsoid
1 0 1 0 Ellipsoid Arc
other values reserved for future use
*/

/* TS 23 032 Table 2a: Coding of Type of Shape */
#if 0
static const value_string type_of_shape_vals[] = {
  { ELLIPSOID_POINT, "Ellipsoid Point"},
  { ELLIPSOID_POINT_WITH_UNCERT_CIRC, "Ellipsoid point with uncertainty Circle"},
  { ELLIPSOID_POINT_WITH_UNCERT_ELLIPSE, "Ellipsoid point with uncertainty Ellipse"},
  { POLYGON, "Polygon"},
  { ELLIPSOID_POINT_WITH_ALT, "Ellipsoid point with altitude"},
  { ELLIPSOID_POINT_WITH_ALT_AND_UNCERT_ELLIPSOID, "Ellipsoid point with altitude and uncertainty Ellipsoid"},
  { ELLIPSOID_ARC, "Ellipsoid Arc"},
  { 0, NULL }
};

/* 3GPP TS 23.032 7.3.1 */
static const value_string sign_of_latitude_vals[] = {
  { 0, "North"},
  { 1, "South"},
  { 0, NULL }
};

static const value_string dir_of_alt_vals[] = {
  { 0, "Altitude expresses height"},
  { 1, "Altitude expresses depth"},
  { 0, NULL }
};
#endif

static const value_string gsm_map_cbs_data_coding_scheme_coding_grp_vals[] = {
  { 0, "Coding Group 0(Language using the GSM 7 bit default alphabet)" },
  { 1, "Coding Group 1" },
  { 2, "Coding Group 2" },
  { 3, "Coding Group 3" },
  { 4, "General Data Coding indication" },
  { 5, "General Data Coding indication" },
  { 6, "General Data Coding indication" },
  { 7, "General Data Coding indication" },
  { 8, "Reserved" },
  { 9, "Message with User Data Header (UDH) structure" },
  { 10,"Reserved" },
  { 11,"Reserved" },
  { 12,"Reserved" },
  { 13,"Reserved" },
  { 14,"Defined by the WAP Forum" },
  { 15,"Data coding / message handling" },
  { 0, NULL}
};
static value_string_ext gsm_map_cbs_data_coding_scheme_coding_grp_vals_ext = VALUE_STRING_EXT_INIT(gsm_map_cbs_data_coding_scheme_coding_grp_vals);

/* Coding group 0
 * Bits 3..0 indicate the language:
 */
static const value_string gsm_map_cbs_coding_grp0_lang_vals[] = {
  { 0, "German"},
  { 1, "English"},
  { 2, "Italian"},
  { 3, "French"},
  { 4, "Spanish"},
  { 5, "Dutch"},
  { 6, "Swedish"},
  { 7, "Danish"},
  { 8, "Portuguese"},
  { 9, "Finnish"},
  { 10, "Norwegian"},
  { 11, "Greek"},
  { 12, "Turkish"},
  { 13, "Hungarian"},
  { 14, "Polish"},
  { 15, "Language unspecified"},
  { 0, NULL }
};
static value_string_ext gsm_map_cbs_coding_grp0_lang_vals_ext = VALUE_STRING_EXT_INIT(gsm_map_cbs_coding_grp0_lang_vals);

static const value_string gsm_map_cbs_coding_grp1_lang_vals[] = {
  { 0, "GSM 7 bit default alphabet; message preceded by language indication"},
  { 1, "UCS2; message preceded by language indication"},
  { 2, "Reserved"},
  { 3, "Reserved"},
  { 4, "Reserved"},
  { 5, "Reserved"},
  { 6, "Reserved"},
  { 7, "Reserved"},
  { 8, "Reserved"},
  { 9, "Reserved"},
  { 10, "Reserved"},
  { 11, "Reserved"},
  { 12, "Reserved"},
  { 13, "Reserved"},
  { 14, "Reserved"},
  { 15, "Reserved"},
  { 0, NULL }
};
static value_string_ext gsm_map_cbs_coding_grp1_lang_vals_ext = VALUE_STRING_EXT_INIT(gsm_map_cbs_coding_grp1_lang_vals);

static const value_string gsm_map_cbs_coding_grp2_lang_vals[] = {
  { 0, "Czech"},
  { 1, "Hebrew"},
  { 2, "Arabic"},
  { 3, "Russian"},
  { 4, "Icelandic"},
  { 5, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 6, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 7, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 8, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 9, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 10, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 11, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 12, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 13, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 14, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 15, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 0, NULL }
};
static value_string_ext gsm_map_cbs_coding_grp2_lang_vals_ext = VALUE_STRING_EXT_INIT(gsm_map_cbs_coding_grp2_lang_vals);

static const value_string gsm_map_cbs_coding_grp3_lang_vals[] = {
  { 0, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 1, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 2, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 3, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 4, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 5, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 6, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 7, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 8, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 9, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 10, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 11, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 12, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 13, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 14, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 15, "Reserved for other languages using the GSM 7 bit default alphabet, with unspecified handling at the MS"},
  { 0, NULL }
};
static value_string_ext gsm_map_cbs_coding_grp3_lang_vals_ext = VALUE_STRING_EXT_INIT(gsm_map_cbs_coding_grp3_lang_vals);

static const true_false_string gsm_map_cbs_coding_grp4_7_comp_vals = {
  "The text is compressed using the compression algorithm defined in 3GPP TS 23.042",
  "The text is uncompressed"
};

static const true_false_string gsm_map_cbs_coding_grp4_7_class_ind_vals = {
  "Bits 1 to 0 have a message class meaning",
  "Bits 1 to 0 are reserved and have no message class meaning"
};

/* Bits 3 and 2 indicate the character set being used, as follows: */

static const value_string gsm_map_cbs_coding_grp4_7_char_set_vals[] = {
  { 0, "GSM 7 bit default alphabet"},
  { 1, "8 bit data"},
  { 2, "UCS2 (16 bit)"},
  { 3, "Reserved"},
  { 0, NULL }
};

static const value_string gsm_map_cbs_coding_grp4_7_class_vals[] = {
  { 0, "Class 0"},
  { 1, "Class 1 Default meaning: ME-specific"},
  { 2, "Class 2 (U)SIM specific message"},
  { 3, "Class 3 Default meaning: TE-specific (see 3GPP TS 27.005"},
  { 0, NULL }
};

static const value_string gsm_map_cbs_coding_grp15_mess_code_vals[] = {
  { 0, "GSM 7 bit default alphabet"},
  { 1, "8 bit data"},
  { 0, NULL }
};

static const value_string gsm_map_cbs_coding_grp15_class_vals[] = {
  { 0, "GSM 7 bit default alphabet"},
  { 1, "8 bit data"},
  { 0, NULL }
};


/* 3GPP TS 23.038 version 7.0.0 Release 7 */
guint8
dissect_cbs_data_coding_scheme(tvbuff_t *tvb, packet_info *pinfo _U_, proto_tree *tree, guint16 offset)
{
  guint8 octet;
  guint8 coding_grp;
  guint8 character_set;

  octet = tvb_get_guint8(tvb,offset);
  coding_grp = octet >>4;
  proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp, tvb, offset, 1, ENC_BIG_ENDIAN);

  sms_encoding = SMS_ENCODING_NOT_SET;
  switch (coding_grp){
  case 0:
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp0_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
    sms_encoding = SMS_ENCODING_7BIT;
    break;
  case 1:
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp1_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((octet & 0x0f)== 0){
      sms_encoding = SMS_ENCODING_7BIT_LANG;
    }else{
      sms_encoding = SMS_ENCODING_UCS2_LANG;
    }
    break;
  case 2:
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp2_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
    sms_encoding = SMS_ENCODING_7BIT;
    break;
  case 3:
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp3_lang, tvb, offset, 1, ENC_BIG_ENDIAN);
    sms_encoding = SMS_ENCODING_7BIT;
    break;
    /* Coding_grp 01xx */
  case 4:
      /* FALLTHRU */
  case 5:
      /* FALLTHRU */
  case 6:
      /* FALLTHRU */
  case 7:
      /* FALLTHRU */
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp4_7_comp, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp4_7_class_ind, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp4_7_char_set, tvb, offset, 1, ENC_BIG_ENDIAN);
    if ((octet & 0x10)== 0x10){
      proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp4_7_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    }
    /* Bits 3 and 2 indicate the character set being used, */
    character_set = (octet&0x0c)>>2;
    switch (character_set){
    case 0:
      /* GSM 7 bit default alphabet */
      sms_encoding = SMS_ENCODING_7BIT;
      break;
    case 1:
      /* 8 bit data */
      sms_encoding = SMS_ENCODING_8BIT;
      break;
    case 2:
      /* UCS2 (16 bit) */
      sms_encoding = SMS_ENCODING_UCS2;
      break;
    case 3:
      /* Reserved */
      sms_encoding = SMS_ENCODING_NOT_SET;
      break;
    default:
      break;
    }
    break;
  case 8:
    /* Reserved coding groups */
    break;
  case 9:
    /* Message with User Data Header (UDH) structure:*/
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp4_7_char_set, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp4_7_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    character_set = (octet&0x0c)>>2;
    switch (character_set){
    case 0:
      /* GSM 7 bit default alphabet */
      sms_encoding = SMS_ENCODING_7BIT;
      break;
    case 1:
      /* 8 bit data */
      sms_encoding = SMS_ENCODING_8BIT;
      break;
    case 2:
      /* UCS2 (16 bit) */
      sms_encoding = SMS_ENCODING_UCS2;
      break;
    case 3:
      /* Reserved */
      sms_encoding = SMS_ENCODING_NOT_SET;
      break;
    default:
      break;
    }
    break;
  case 10:
    /* FALLTHRU */
  case 11:
    /* FALLTHRU */
  case 12:
    /* FALLTHRU */
  case 13:
    /* FALLTHRU */
    /* 1010..1101 Reserved coding groups */
    break;
  case 14:
    /* Defined by the WAP Forum
     * "Wireless Datagram Protocol Specification", Wireless Application Protocol Forum Ltd.
     */
    break;
  case 15:
    /* Data coding / message handling */
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp15_mess_code, tvb, offset, 1, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_gsm_map_cbs_coding_grp15_class, tvb, offset, 1, ENC_BIG_ENDIAN);
    character_set = (octet&0x04)>>2;
    if (character_set == 0){
      sms_encoding = SMS_ENCODING_7BIT;
    }else{
      sms_encoding = SMS_ENCODING_8BIT;
    }
    break;
  default:
    break;
  }

  return sms_encoding;
}
void
dissect_gsm_map_msisdn(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  guint8      octet;
  guint8      na;
  guint8      np;

  proto_tree_add_item(tree, hf_gsm_map_extension, tvb, 0,1,ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_gsm_map_nature_of_number, tvb, 0,1,ENC_BIG_ENDIAN);
  proto_tree_add_item(tree, hf_gsm_map_number_plan, tvb, 0,1,ENC_BIG_ENDIAN);

  if(tvb_reported_length(tvb)==1)
    return;

  octet = tvb_get_guint8(tvb,0);
  /* nature of address indicator */
  na = (octet & 0x70)>>4;
  /* numbering plan indicator */
  np = octet & 0x0f;
  switch(np){
  case 1:
      /* ISDN/Telephony Numbering Plan (Rec ITU-T E.164) */
      switch(na){
      case 1:
          /* international number */
          dissect_e164_msisdn(tvb, tree, 1, tvb_reported_length(tvb)-1, E164_ENC_BCD);
      break;
      default:
          proto_tree_add_item(tree, hf_gsm_map_address_digits, tvb, 1, -1, ENC_BCD_DIGITS_0_9);
          break;
      }
      break;
  case 6:
      /* land mobile numbering plan (ITU-T Rec E.212) */
      dissect_e212_imsi(tvb, pinfo, tree,  1, tvb_reported_length(tvb)-1, FALSE);
      break;
  default:
      proto_tree_add_item(tree, hf_gsm_map_address_digits, tvb, 1, -1, ENC_BCD_DIGITS_0_9);
      break;
  }

}

#include "packet-gsm_map-fn.c"

/* Specific translation for MAP V3 */
const value_string gsm_map_V1V2_opr_code_strings[] = {
  {  44, "forwardSM" },
  {  45, "sendRoutingInfoForSM" },
  {  46, "forwardSM" },
  { 0, NULL }
};
/* Generic translation for MAP operation */
const value_string gsm_map_opr_code_strings[] = {
#include "packet-gsm_map-table.c"
  { 0, NULL }
};

#if 0
static const value_string gsm_map_err_code_string_vals[] = {
#include "packet-gsm_map-table.c"
    { 0, NULL }
};
#endif


static const value_string gsm_map_nature_of_number_values[] = {
  { 0x00, "unknown" },
  { 0x01, "International Number" },
  { 0x02, "National Significant Number" },
  { 0x03, "Network Specific Number" },
  { 0x04, "Subscriber Number" },
  { 0x05, "Reserved" },
  { 0x06, "Abbreviated Number" },
  { 0x07, "Reserved for extension" },
  { 0, NULL }
};
static value_string_ext gsm_map_nature_of_number_values_ext = VALUE_STRING_EXT_INIT(gsm_map_nature_of_number_values);

static const value_string gsm_map_number_plan_values[] = {
  { 0x00, "unknown" },
  { 0x01, "ISDN/Telephony Numbering (Rec ITU-T E.164)" },
  { 0x02, "spare" },
  { 0x03, "Data Numbering (ITU-T Rec. X.121)" },
  { 0x04, "Telex Numbering (ITU-T Rec. F.69)" },
  { 0x05, "spare" },
  { 0x06, "Land Mobile Numbering (ITU-T Rec. E.212)" },
  { 0x07, "spare" },
  { 0x08, "National Numbering" },
  { 0x09, "Private Numbering" },
  { 0x0a, "spare" },
  { 0x0b, "spare" },
  { 0x0c, "spare" },
  { 0x0d, "spare" },
  { 0x0e, "spare" },
  { 0x0f, "Reserved for extension" },
  { 0, NULL }
};
static value_string_ext gsm_map_number_plan_values_ext = VALUE_STRING_EXT_INIT(gsm_map_number_plan_values);

static const true_false_string gsm_map_Ss_Status_q_bit_values = {
  "Quiescent",
  "Operative"
};
static const true_false_string gsm_map_Ss_Status_p_values = {
  "Provisioned",
  "Not Provisioned"
};
static const true_false_string gsm_map_Ss_Status_r_values = {
  "Registered",
  "Not Registered"
};
static const true_false_string gsm_map_Ss_Status_a_values = {
  "Active",
  "not Active"
};

/*
 * Translate the MAP operation code value to a text string
 * Take into account the MAP version for ForwardSM
 */
const gchar* gsm_map_opr_code(guint32 val, proto_item *item) {
  switch (val) {
  case 44: /*mt-forwardSM*/
    /* FALLTHRU */
  case 46: /*mo-forwardSM*/
    if (application_context_version < 3) {
      proto_item_set_text(item, "%s (%d)", val_to_str_const(val, gsm_map_V1V2_opr_code_strings, "Unknown GSM-MAP opcode"), val);
      return val_to_str_const(val, gsm_map_V1V2_opr_code_strings, "Unknown GSM-MAP opcode");
    }
    /* Else use the default map operation translation */
    /* FALLTHRU */
  default:
    return val_to_str_ext_const(val, &gsm_old_GSMMAPOperationLocalvalue_vals_ext, "Unknown GSM-MAP opcode");
    break;
  }
}

/* Prototype for a decoding function */
typedef int (* dissect_function_t)( gboolean,
                                    tvbuff_t *,
                                    int ,
                                    asn1_ctx_t *,
                                    proto_tree *,
                                    int);

/*
 * Dissect Multiple Choice Message
 * This function is used to decode a message, when several encoding may be used.
 * For exemple, in the last MAP version, the Cancel Location is defined like this:
 * CancelLocationArg ::= [3] IMPLICIT SEQUENCE
 * But in the previous MAP version, it was a CHOICE between a SEQUENCE and an IMSI
 * As ASN1 encoders (or software) still uses the old encoding, this function allows
 * the decoding of both versions.
 * Moreover, some optimizations (or bad practice ?) in ASN1 encoder, removes the
 * SEQUENCE tag, when only one parameter is present in the SEQUENCE.
 * This explain why the function expects 3 parameters:
 * - a [3] SEQUENCE corresponding the recent ASN1 MAP encoding
 * - a SEQUENCE for old style
 * - and a single parameter, for old version or optimizations
 *
 * The analyze of the first ASN1 tag, indicate what kind of decoding should be used,
 * if the decoding function is provided (so not a NULL function)
 */
static int dissect_mc_message(tvbuff_t *tvb,
                              int offset,
                              asn1_ctx_t *actx,
                              proto_tree *tree,
                              gboolean implicit_param _U_, dissect_function_t parameter, int hf_index_param _U_,
                              gboolean implicit_seq   _U_, dissect_function_t sequence,  int hf_index_seq   _U_,
                              gboolean implicit_seq3 _U_, dissect_function_t sequence3, int hf_index_seq3 _U_ )
{
  guint8 octet;
  gint8 bug_class;
  gboolean bug_pc, bug_ind_field;
  gint32 bug_tag;
  guint32 bug_len;

  octet = tvb_get_guint8(tvb,0);
  if ( (octet & 0xf) == 3) {
    /* XXX  asn2wrs can not yet handle tagged assignment yes so this
     * XXX is some conformance file magic to work around that bug
     */
    offset = get_ber_identifier(tvb, offset, &bug_class, &bug_pc, &bug_tag);
    offset = get_ber_length(tvb, offset, &bug_len, &bug_ind_field);
    if (sequence3 != NULL) {
      offset= (sequence3) (implicit_seq3, tvb, offset, actx, tree, hf_index_seq3);
    } else {
      proto_tree_add_expert(tree, actx->pinfo, &ei_gsm_map_unknown_sequence3, tvb, offset, -1);
    }
  } else if (octet == 0x30) {
    if (sequence != NULL) {
      offset= (sequence) (implicit_seq, tvb, 0, actx, tree, hf_index_seq);
    } else {
      proto_tree_add_expert(tree, actx->pinfo, &ei_gsm_map_unknown_sequence, tvb, offset, -1);
    }
  } else {
    if (parameter != NULL) {
      offset= (parameter) (implicit_param, tvb, offset, actx, tree, hf_index_param);
    } else {
      proto_tree_add_expert(tree, actx->pinfo, &ei_gsm_map_unknown_parameter, tvb, offset, -1);
    }
  }
  return offset;
}

static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx) {

  switch(opcode){
  case  2: /*updateLocation*/
    offset=dissect_gsm_map_ms_UpdateLocationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  3: /*cancelLocation*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_Identity, hf_gsm_map_ms_identity,
                              FALSE, dissect_gsm_map_Identity, hf_gsm_map_ms_identity,
                              TRUE , dissect_gsm_map_ms_CancelLocationArg, -1);/*undefined*/
    break;
  case  4: /*provideRoamingNumber*/
    offset=dissect_gsm_map_ch_ProvideRoamingNumberArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  5: /*noteSubscriberDataModified*/
    offset=dissect_gsm_map_ms_NoteSubscriberDataModifiedArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  6: /*resumeCallHandling*/
    offset=dissect_gsm_map_ch_ResumeCallHandlingArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  7: /*insertSubscriberData*/
    offset=dissect_gsm_map_ms_InsertSubscriberDataArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  8: /*deleteSubscriberData*/
    offset=dissect_gsm_map_ms_DeleteSubscriberDataArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  9: /*sendParameters*/
    offset = dissect_gsm_old_SendParametersArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  10: /*registerSS*/
    offset=dissect_gsm_map_ss_RegisterSS_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  11: /*eraseSS*/
    offset=dissect_gsm_map_ss_SS_ForBS_Code(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 12: /*activateSS*/
    offset=dissect_gsm_map_ss_SS_ForBS_Code(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 13: /*deactivateSS*/
    offset=dissect_gsm_map_ss_SS_ForBS_Code(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 14: /*interrogateSS*/
    offset=dissect_gsm_map_ss_SS_ForBS_Code(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 15: /*authenticationFailureReport*/
    offset=dissect_gsm_map_ms_AuthenticationFailureReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 16: /*SS-protocol notifySS*/
    offset=dissect_gsm_ss_NotifySS_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 17: /*registerPassword*/
    offset=dissect_gsm_map_SS_Code(FALSE, tvb, offset, actx, tree, hf_gsm_map_ss_Code);
    break;
  case 18: /*getPassword*/
    offset=dissect_gsm_old_GetPasswordArg(FALSE, tvb, offset, actx, tree, hf_gsm_map_getPassword);
    break;
  case 19: /* SS-Protocol processUnstructuredSS-Data (19) */
    offset=dissect_gsm_ss_SS_UserData(FALSE, tvb, offset, actx, tree, hf_gsm_map_ss_SS_UserData);
    break;
  case 20: /*releaseResources*/
    offset=dissect_gsm_map_ch_ReleaseResourcesArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 21: /*mt-ForwardSM-VGCS*/
    offset=dissect_gsm_map_sm_MT_ForwardSM_VGCS_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 22: /*sendRoutingInfo*/
      if (application_context_version == 3){
          offset=dissect_gsm_map_ch_SendRoutingInfoArg(FALSE, tvb, offset, actx, tree, -1);
      }else{
          offset = dissect_gsm_old_SendRoutingInfoArgV2(FALSE, tvb, offset, actx, tree, -1);
      }
    break;
  case 23: /*updateGprsLocation*/
    offset=dissect_gsm_map_ms_UpdateGprsLocationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 24: /*sendRoutingInfoForGprs*/
    offset=dissect_gsm_map_ms_SendRoutingInfoForGprsArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 25: /*failureReport*/
    offset=dissect_gsm_map_ms_FailureReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 26: /*noteMsPresentForGprs*/
    offset=dissect_gsm_map_ms_NoteMsPresentForGprsArg(FALSE, tvb, offset, actx, tree, -1);
    break;
    /* undefined 27 */
    /* reserved performHandover (28) */
  case 29: /*sendEndSignal*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, NULL, -1,
                              FALSE, dissect_gsm_old_Bss_APDU, -1,
                              TRUE , dissect_gsm_map_ms_SendEndSignal_Arg, -1);
    break;
    /* reserved performSubsequentHandover (30) */
  case 31: /*provideSIWFSNumber*/
    offset=dissect_gsm_old_ProvideSIWFSNumberArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 32: /*sIWFSSignallingModify*/
    offset=dissect_gsm_old_SIWFSSignallingModifyArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 33: /*processAccessSignalling*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, NULL, -1,
                              FALSE, dissect_gsm_old_Bss_APDU, -1,
                              TRUE , dissect_gsm_map_ms_ProcessAccessSignalling_Arg, -1);
    break;
  case 34: /*forwardAccessSignalling*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, NULL, -1,
                              FALSE, dissect_gsm_old_Bss_APDU, -1,
                              TRUE , dissect_gsm_map_ms_ForwardAccessSignalling_Arg, -1);
    break;
    /* reserved noteInternalHandover (35) */
  case 36: /*cancelVcsgLocation*/
    offset=dissect_gsm_map_ms_CancelVcsgLocationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 37: /*reset*/
      if (application_context_version == 1) {
          offset = dissect_gsm_old_ResetArgV1(FALSE, tvb, offset, actx, tree, -1);
      } else {
          offset = dissect_gsm_map_ms_ResetArg(FALSE, tvb, offset, actx, tree, -1);
      }
    break;
  case 38: /*forwardCheckSS-Indication*/
    return offset;
    break;
  case 39: /*prepareGroupCall*/
    offset=dissect_gsm_map_gr_PrepareGroupCallArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 40: /*sendGroupCallEndSignal*/
    offset = dissect_gsm_map_gr_SendGroupCallEndSignalArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 41: /*processGroupCallSignalling*/
    offset = dissect_gsm_map_gr_ProcessGroupCallSignallingArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 42: /*forwardGroupCallSignalling*/
    offset=dissect_gsm_map_gr_ForwardGroupCallSignallingArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 43: /*checkIMEI*/
    if (pref_ericsson_proprietary_ext) {
      offset=dissect_mc_message(tvb, offset, actx, tree,
                    FALSE, dissect_gsm_map_IMEI, hf_gsm_map_ms_imei,
                    FALSE, dissect_gsm_map_ericsson_EnhancedCheckIMEI_Arg, -1,
                    TRUE , NULL, -1); /* no [3] SEQUENCE */
    } else {
      offset=dissect_mc_message(tvb, offset, actx, tree,
                    FALSE, dissect_gsm_map_IMEI, hf_gsm_map_ms_imei,
                    FALSE, dissect_gsm_map_ms_CheckIMEI_Arg, -1,
                    TRUE , NULL, -1); /* no [3] SEQUENCE */
    }
    break;
  case 44: /*mt-forwardSM(v3) or ForwardSM(v1/v2)*/
    if (application_context_version == 3)
      offset=dissect_gsm_map_sm_MT_ForwardSM_Arg(FALSE, tvb, offset, actx, tree, -1);
    else {
      offset=dissect_gsm_old_ForwardSM_Arg(FALSE, tvb, offset, actx, tree, -1);
    }
    break;
  case 45: /*sendRoutingInfoForSM*/
    if (application_context_version < 2) {
      offset=dissect_gsm_old_RoutingInfoForSM_ArgV1(FALSE, tvb, offset, actx, tree, -1);
    } else {
      offset=dissect_gsm_map_sm_RoutingInfoForSM_Arg(FALSE, tvb, offset, actx, tree, -1);
    }
    break;
  case 46: /*mo-forwardSM(v3) or ForwardSM(v1/v2)*/
    if (application_context_version == 3)
      offset=dissect_gsm_map_sm_MO_ForwardSM_Arg(FALSE, tvb, offset, actx, tree, -1);
    else {
      offset=dissect_gsm_old_ForwardSM_Arg(FALSE, tvb, offset, actx, tree, -1);
    }
    break;
  case 47: /*reportSM-DeliveryStatus*/
    offset=dissect_gsm_map_sm_ReportSM_DeliveryStatusArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 48: /*noteSubscriberPresent*/
      offset = dissect_gsm_map_IMSI(FALSE, tvb, offset, actx, tree, hf_gsm_map_imsi);
      break;
      /* reserved alertServiceCentreWithoutResult (49)
     * ETS 300 599: December 2000 (GSM 09.02 version 4.19.1)
     * -- alertServiceCentreWithoutResult must not be used in
     * -- version greater 1
     */
  case 49:
    offset = dissect_gsm_map_sm_AlertServiceCentreArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 50: /*activateTraceMode*/
    offset=dissect_gsm_map_om_ActivateTraceModeArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 51: /*deactivateTraceMode*/
    offset=dissect_gsm_map_om_DeactivateTraceModeArg(FALSE, tvb, offset, actx, tree, -1);
    break;
    /* reserved traceSubscriberActivity (52) */

  case 53: /* UpdateVcsgLocation 53 */
    offset=dissect_gsm_map_ms_UpdateVcsgLocationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 54: /*beginSubscriberActivity*/
    offset=dissect_gsm_old_BeginSubscriberActivityArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 55: /*sendIdentification*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_TMSI, hf_gsm_map_tmsi,
                              FALSE, dissect_gsm_map_ms_SendIdentificationArg, -1,
                              TRUE,  NULL, -1);
    break;
  case 56: /*sendAuthenticationInfo*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_IMSI, hf_gsm_map_imsi,
                              FALSE, dissect_gsm_map_ms_SendAuthenticationInfoArg, -1,
                              TRUE,  NULL, -1);
    break;
  case 57: /*restoreData*/
    offset=dissect_gsm_map_ms_RestoreDataArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 58: /*sendIMSI*/
    offset = dissect_gsm_map_ISDN_AddressString(FALSE, tvb, offset, actx, tree, hf_gsm_map_msisdn);
    break;
  case 59: /*processUnstructuredSS-Request*/
    offset=dissect_gsm_map_ss_USSD_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 60: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_ss_USSD_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 61: /*unstructuredSS-Notify*/
    offset=dissect_gsm_map_ss_USSD_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 62: /*AnyTimeSubscriptionInterrogation*/
    offset=dissect_gsm_map_ms_AnyTimeSubscriptionInterrogationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 63: /*informServiceCentre*/
    offset=dissect_gsm_map_sm_InformServiceCentreArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 64: /*alertServiceCentre*/
    offset=dissect_gsm_map_sm_AlertServiceCentreArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 65: /*AnyTimeModification*/
    offset=dissect_gsm_map_ms_AnyTimeModificationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 66: /*readyForSM*/
    offset=dissect_gsm_map_sm_ReadyForSM_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 67: /*purgeMS*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_IMSI, hf_gsm_map_imsi,
                              FALSE, dissect_gsm_old_PurgeMSArgV2, -1, /*undefined*/
                              TRUE , dissect_gsm_map_ms_PurgeMS_Arg, -1);
    break;
  case 68: /*prepareHandover*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, NULL, -1,
                              FALSE, dissect_gsm_old_PrepareHO_ArgOld, -1,
                              TRUE, dissect_gsm_map_ms_PrepareHO_Arg, -1);
    break;
  case 69: /*prepareSubsequentHandover*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, NULL, -1,
                              FALSE, NULL, -1,
                              TRUE, dissect_gsm_map_ms_PrepareSubsequentHO_Arg, -1);
    break;
  case 70: /*provideSubscriberInfo*/
    offset=dissect_gsm_map_ms_ProvideSubscriberInfoArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 71: /*anyTimeInterrogation*/
    offset=dissect_gsm_map_ms_AnyTimeInterrogationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 72: /*ss-InvocationNotificatio*/
    offset=dissect_gsm_map_ss_SS_InvocationNotificationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 73: /*setReportingState*/
    offset=dissect_gsm_map_ch_SetReportingStateArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 74: /*statusReport*/
    offset=dissect_gsm_map_ch_StatusReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 75: /*remoteUserFree*/
    offset=dissect_gsm_map_ch_RemoteUserFreeArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 76: /*registerCC-Entry*/
    offset=dissect_gsm_map_ss_RegisterCC_EntryArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 77: /*eraseCC-Entry*/
    offset=dissect_gsm_map_ss_EraseCC_EntryArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 78: /*secureTransportClass1*/
  case 79: /*secureTransportClass1*/
  case 80: /*secureTransportClass1*/
  case 81: /*secureTransportClass1*/
    offset=dissect_gsm_old_SecureTransportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
    /* undefined 82 */
  case 83: /*provideSubscriberLocation*/
    offset=dissect_gsm_map_lcs_ProvideSubscriberLocation_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 84: /*sendGroupCallInfo*/
    offset=dissect_gsm_map_gr_SendGroupCallInfoArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 85: /*sendRoutingInfoForLCS*/
    offset=dissect_gsm_map_lcs_RoutingInfoForLCS_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 86: /*subscriberLocationReport*/
    offset=dissect_gsm_map_lcs_SubscriberLocationReport_Arg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 87: /*ist-Alert*/
    offset=dissect_gsm_map_ch_IST_AlertArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 88: /*ist-Command*/
    offset=dissect_gsm_map_ch_IST_CommandArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 89: /*noteMM-Event*/
    offset=dissect_gsm_map_ms_NoteMM_EventArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 108: /*SS-protocol lcs-PeriodicTriggeredInvoke*/
      offset = dissect_gsm_ss_LCS_PeriodicTriggeredInvokeArg(FALSE, tvb, offset, actx, tree, -1);
      break;
  case 109: /*SS-protocol lcs-PeriodicLocationCancellation*/
    offset=dissect_gsm_ss_LCS_PeriodicLocationCancellationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 110: /*SS-protocol lcs-LocationUpdate*/
    offset=dissect_gsm_ss_LCS_LocationUpdateArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 111: /*SS-protocol lcs-PeriodicLocationRequest*/
    offset=dissect_gsm_ss_LCS_PeriodicLocationRequestArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 112: /*SS-protocol lcs-AreaEventCancellation*/
    offset=dissect_gsm_ss_LCS_AreaEventCancellationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 113: /*SS-protocol lcs-AreaEventReport*/
    offset=dissect_gsm_ss_LCS_AreaEventReportArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 114: /*SS-protocol lcs-AreaEventRequest*/
    offset=dissect_gsm_ss_LCS_AreaEventRequestArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 115: /*SS-protocol lcs-MOLR*/
    offset=dissect_gsm_ss_LCS_MOLRArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 116: /*SS-protocol lcs-LocationNotification*/
    offset=dissect_gsm_ss_LocationNotificationArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 117: /*SS-protocol callDeflection*/
    offset=dissect_gsm_ss_CallDeflectionArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 118: /*SS-protocol userUserService*/
    offset=dissect_gsm_ss_UserUserServiceArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 119: /*SS-protocol accessRegisterCCEntry*/
    offset=dissect_gsm_ss_AccessRegisterCCEntryArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 120: /*SS-protocol forwardCUG-Info*/
    application_context_version = 3;
    offset=dissect_gsm_ss_ForwardCUG_InfoArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 121: /*SS-protocol splitMPTY no Argument*/
    break;
  case 122: /*SS-protocol retrieveMPTY no Argument*/
    break;
  case 123: /*SS-protocol holdMPTY no Argument*/
    break;
  case 124: /*SS-protocol buildMPTY no Argument*/
    break;
  case 125: /*SS-protocol forwardChargeAdvice*/
    offset=dissect_gsm_ss_ForwardChargeAdviceArg(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 126: /*SS-protocol explicitCT no Argument*/
    break;
  default:
    if(!dissector_try_uint_new(map_prop_arg_opcode_table, (guint8)opcode, tvb, actx->pinfo, tree, TRUE, actx->subtree.top_tree)){
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_gsm_map_unknown_invokeData,
                                     tvb, offset, -1, "Unknown invokeData %d", opcode);
    }
    offset+= tvb_reported_length_remaining(tvb,offset);
    break;
  }
  return offset;
}


static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx) {

  switch(opcode){
  case  2: /*updateLocation*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_IMSI, hf_gsm_map_imsi,
                              FALSE, dissect_gsm_map_ms_UpdateLocationRes, -1,
                              TRUE , NULL, -1);
    break;
  case  3: /*cancelLocation*/
    offset=dissect_gsm_map_ms_CancelLocationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  4: /*provideRoamingNumber*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_ISDN_AddressString, hf_gsm_map_msisdn,
                              FALSE, dissect_gsm_map_ch_ProvideRoamingNumberRes, -1,
                              TRUE , NULL, -1);/*undefined*/
    break;
  case  5: /*noteSubscriberDataModified*/
    offset=dissect_gsm_map_ms_NoteSubscriberDataModifiedRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  6: /*resumeCallHandling*/
    offset=dissect_gsm_map_ch_ResumeCallHandlingRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  7: /*insertSubscriberData*/
    offset=dissect_gsm_map_ms_InsertSubscriberDataRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  8: /*deleteSubscriberData*/
    offset=dissect_gsm_map_ms_DeleteSubscriberDataRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  9: /*sendParameters*/
    offset = dissect_gsm_old_SentParameterList(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  10: /*registerSS*/
    offset=dissect_gsm_map_ss_SS_Info(FALSE, tvb, offset, actx, tree, -1);
    break;
  case  11: /*eraseSS*/
    offset=dissect_gsm_map_ss_SS_Info(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 12: /*activateSS*/
    offset=dissect_gsm_map_ss_SS_Info(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 13: /*deactivateSS*/
    offset=dissect_gsm_map_ss_SS_Info(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 14: /*interrogateSS*/
    offset=dissect_gsm_map_ss_InterrogateSS_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 15: /*authenticationFailureReport*/
    offset=dissect_gsm_map_ms_AuthenticationFailureReportRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 17: /*registerPassword*/
    /* change hf_gsm_map_ss_Code to something with password */
    offset=dissect_gsm_old_NewPassword(FALSE, tvb, offset, actx, tree, hf_gsm_map_ss_Code);
    break;
  case 18: /*getPassword*/
    offset=dissect_gsm_old_CurrentPassword(FALSE, tvb, offset, actx, tree, hf_gsm_map_currentPassword);
    break;
  case 19: /* SS-Protocol processUnstructuredSS-Data (19) */
    offset=dissect_gsm_ss_SS_UserData(FALSE, tvb, offset, actx, tree, hf_gsm_map_ss_SS_UserData);
    break;
  case 20: /*releaseResources*/
    offset=dissect_gsm_map_ch_ReleaseResourcesRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 21: /*mt-ForwardSM-VGCS*/
    offset=dissect_gsm_map_sm_MT_ForwardSM_VGCS_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 22: /*sendRoutingInfo*/
      if (application_context_version == 3){
          /* If the tag is missing use SendRoutingInfoRes_U */
          offset=dissect_mc_message(tvb, offset, actx, tree,
                                    FALSE, NULL, -1,
                                    FALSE, dissect_gsm_map_ch_SendRoutingInfoRes_U, -1,
                                    TRUE , dissect_gsm_map_ch_SendRoutingInfoRes, -1);
      }else{
          offset=dissect_mc_message(tvb, offset, actx, tree,
                                    FALSE, dissect_gsm_map_IMSI, hf_gsm_map_imsi,
                                    FALSE, dissect_gsm_old_SendRoutingInfoResV2, -1,
                                    TRUE , dissect_gsm_map_ch_SendRoutingInfoRes, -1);
      }
    break;
  case 23: /*updateGprsLocation*/
    offset=dissect_gsm_map_ms_UpdateGprsLocationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 24: /*sendRoutingInfoForGprs*/
    offset=dissect_gsm_map_ms_SendRoutingInfoForGprsRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 25: /*failureReport*/
    offset=dissect_gsm_map_ms_FailureReportRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 26: /*noteMsPresentForGprs*/
    offset=dissect_gsm_map_ms_NoteMsPresentForGprsRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 29: /*sendEndSignal*/
      /* Taken from MAP-MobileServiceOperations{ 0 identified-organization (4) etsi (0) mobileDomain
       * (0) gsm-Network (1) modules (3) map-MobileServiceOperations (5) version9 (9) }
       */
    offset=dissect_gsm_map_ms_SendEndSignal_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 31: /*provideSIWFSNumber*/
    offset=dissect_gsm_old_ProvideSIWFSNumberRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 32: /*provideSIWFSSignallingModify*/
    offset=dissect_gsm_old_SIWFSSignallingModifyRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 36: /*cancelVcsgLocation*/
    offset=dissect_gsm_map_ms_CancelVcsgLocationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 39: /*prepareGroupCall*/
    offset=dissect_gsm_map_gr_PrepareGroupCallRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 40: /*sendGroupCallEndSignal*/
    offset=dissect_gsm_map_gr_SendGroupCallEndSignalRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 43: /*checkIMEI*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_ms_EquipmentStatus, hf_gsm_map_ms_equipmentStatus,
                              FALSE, dissect_gsm_map_ms_CheckIMEI_Res, -1,
                              TRUE,  NULL, -1);
    break;
  case 44: /*mt-forwardSM*/
    offset=dissect_gsm_map_sm_MT_ForwardSM_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 45: /*sendRoutingInfoForSM*/
    if (application_context_version < 3) {
      offset=dissect_gsm_old_RoutingInfoForSM_ResV2(FALSE, tvb, offset, actx, tree, -1);
    } else {
      offset=dissect_gsm_map_sm_RoutingInfoForSM_Res(FALSE, tvb, offset, actx, tree, -1);
    }
    break;
  case 46: /*mo-forwardSM*/
    offset=dissect_gsm_map_sm_MO_ForwardSM_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 47: /*reportSM-DeliveryStatus*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_ISDN_AddressString, hf_gsm_map_sm_storedMSISDN,
                              FALSE, dissect_gsm_map_sm_ReportSM_DeliveryStatusRes, -1,
                              FALSE, NULL, -1);/*undefined*/
    break;
  case 48: /*noteSubscriberPresent*/
    break;
  case 50: /*activateTraceMode*/
    offset=dissect_gsm_map_om_ActivateTraceModeRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 51: /*deactivateTraceMode*/
    offset=dissect_gsm_map_om_DeactivateTraceModeRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 53: /* UpdateVcsgLocation 53 */
    offset=dissect_gsm_map_ms_UpdateVcsgLocationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 55: /*sendIdentification */
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_IMSI, hf_gsm_map_imsi,
                              FALSE, dissect_gsm_old_SendIdentificationResV2, -1,/*undefined*/
                              TRUE,  dissect_gsm_map_ms_SendIdentificationRes, -1);
    break;
  case 56: /*sendAuthenticationInfo*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, NULL, -1,
                              FALSE, dissect_gsm_old_SendAuthenticationInfoResOld, -1,
                              TRUE , dissect_gsm_map_ms_SendAuthenticationInfoRes, -1);
    break;
  case 57: /*restoreData*/
    offset=dissect_gsm_map_ms_RestoreDataRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 58: /*sendIMSI*/
    offset=dissect_gsm_map_IMSI(FALSE, tvb, offset, actx, tree, hf_gsm_map_ms_imsi);
    break;
  case 59: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_ss_USSD_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 60: /*unstructuredSS-Request*/
    offset=dissect_gsm_map_ss_USSD_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 61: /*unstructuredSS-Notify*/
    /* TRUE ? */
    proto_tree_add_expert_format(tree, actx->pinfo, &ei_gsm_map_unknown_invokeData, tvb, offset, -1, "Unknown returnResultData blob");
    break;
  case 62: /*AnyTimeSubscriptionInterrogation*/
    offset=dissect_gsm_map_ms_AnyTimeSubscriptionInterrogationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 64: /*alertServiceCentre*/
    /* TRUE */
    break;
  case 65: /*AnyTimeModification*/
    offset=dissect_gsm_map_ms_AnyTimeModificationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 66: /*readyForSM*/
    offset=dissect_gsm_map_sm_ReadyForSM_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 67: /*purgeMS*/
    offset=dissect_gsm_map_ms_PurgeMS_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 68: /*prepareHandover*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, NULL, -1,
                              FALSE, dissect_gsm_old_PrepareHO_ResOld, -1,
                              TRUE , dissect_gsm_map_ms_PrepareHO_Res, -1);
    break;
  case 69: /*prepareSubsequentHandover*/
    offset=dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, NULL, -1,
                              FALSE, NULL, -1,
                              TRUE , dissect_gsm_map_ms_PrepareSubsequentHO_Res, -1);
    break;
  case 70: /*provideSubscriberInfo*/
    offset=dissect_gsm_map_ms_ProvideSubscriberInfoRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 71: /*anyTimeInterrogation*/
    offset=dissect_gsm_map_ms_AnyTimeInterrogationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 72: /*ss-InvocationNotificatio*/
    offset=dissect_gsm_map_ss_SS_InvocationNotificationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 73: /*setReportingState*/
    offset=dissect_gsm_map_ch_SetReportingStateRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 74: /*statusReport*/
    offset=dissect_gsm_map_ch_StatusReportRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 75: /*remoteUserFree*/
    offset=dissect_gsm_map_ch_RemoteUserFreeRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 76: /*registerCC-Entry*/
    offset=dissect_gsm_map_ss_RegisterCC_EntryRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 77: /*eraseCC-Entry*/
    offset=dissect_gsm_map_ss_EraseCC_EntryRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 78: /*secureTransportClass1*/
  case 79: /*secureTransportClass2*/
  case 80: /*secureTransportClass3*/
  case 81: /*secureTransportClass4*/
    offset=dissect_gsm_old_SecureTransportRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 83: /*provideSubscriberLocation*/
    offset=dissect_gsm_map_lcs_ProvideSubscriberLocation_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 84: /*sendGroupCallInfo*/
    offset=dissect_gsm_map_gr_SendGroupCallInfoRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 85: /*sendRoutingInfoForLCS*/
    offset=dissect_gsm_map_lcs_RoutingInfoForLCS_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 86: /*subscriberLocationReport*/
    offset=dissect_gsm_map_lcs_SubscriberLocationReport_Res(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 87: /*ist-Alert*/
    offset=dissect_gsm_map_ch_IST_AlertRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 88: /*ist-Command*/
    offset=dissect_gsm_map_ch_IST_CommandRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 89: /*noteMM-Event*/
    offset=dissect_gsm_map_ms_NoteMM_EventRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 108: /*SS-protocol LCS-PeriodicTriggeredInvokeRes*/
      offset = dissect_gsm_ss_LCS_PeriodicTriggeredInvokeRes(FALSE, tvb, offset, actx, tree, -1);
      break;
  case 109: /*SS-protocol lcs-PeriodicLocationCancellation*/
    /* No parameter */
    break;
  case 110: /*SS-protocol lcs-LocationUpdate*/
    offset=dissect_gsm_ss_LCS_LocationUpdateRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 111: /*SS-protocol lcs-PeriodicLocationRequest*/
    offset=dissect_gsm_ss_LCS_PeriodicLocationRequestRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 112: /*SS-protocol lcs-AreaEventCancellation*/
    break;
  case 113: /*SS-protocol lcs-AreaEventReport*/
    break;
  case 114: /*SS-protocol lcs-AreaEventRequest No RESULT data*/
    break;
  case 115: /*SS-protocol lcs-MOLR*/
    offset=dissect_gsm_ss_LCS_MOLRRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 116: /*SS-protocol lcs-LocationNotification*/
    offset=dissect_gsm_ss_LocationNotificationRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 117: /*SS-protocol callDeflection no RESULT*/
    break;
  case 118: /*SS-protocol userUserService no RESULT*/
    break;
  case 119: /*SS-protocol accessRegisterCCEntry*/
    offset=dissect_gsm_map_ss_RegisterCC_EntryRes(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 120: /*SS-protocol forwardCUG-Info*/
    /* No RETURN RESULT*/
    break;
  case 121: /*SS-protocol splitMPTY no RESULT*/
    break;
  case 122: /*SS-protocol retrieveMPTY no RESULT*/
    break;
  case 123: /*SS-protocol holdMPTY no RESULT*/
    break;
  case 124: /*SS-protocol buildMPTY no RESULT*/
    break;
  case 125: /*SS-protocol forwardChargeAdvice no RESULT*/
    break;
  case 126: /*SS-protocol explicitCT no RESULT*/
    break;

 default:
   if(!dissector_try_uint_new(map_prop_res_opcode_table, (guint8)opcode, tvb, actx->pinfo, tree, TRUE, actx->subtree.top_tree)){
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_gsm_map_unknown_invokeData,
                                     tvb, offset, -1, "Unknown returnResultData %d", opcode);
   }
   offset+= tvb_reported_length_remaining(tvb,offset);
   break;
  }
  return offset;
}



static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset, asn1_ctx_t *actx) {

  switch(errorCode){
  case 1: /* UnknownSubscriberParam */
    offset=dissect_gsm_map_er_UnknownSubscriberParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 4: /* SecureTransportErrorParam */
    offset=dissect_gsm_old_SecureTransportErrorParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 5: /* UnidentifiedSubParam */
    offset=dissect_gsm_map_er_UnidentifiedSubParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 6: /* AbsentSubscriberSM-Param */
    offset=dissect_gsm_map_er_AbsentSubscriberSM_Param(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 8: /* RoamingNotAllowedParam */
    offset=dissect_gsm_map_er_RoamingNotAllowedParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 9: /* IllegalSubscriberParam */
    offset=dissect_gsm_map_er_IllegalSubscriberParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 10: /* BearerServNotProvParam */
    offset=dissect_gsm_map_er_BearerServNotProvParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 11: /* TeleservNotProvParam */
    offset=dissect_gsm_map_er_TeleservNotProvParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 12: /* IllegalEquipmentParam */
    offset=dissect_gsm_map_er_IllegalEquipmentParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 13: /* CallBarredParam */
    offset=dissect_gsm_map_er_CallBarredParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 14: /* ForwardingViolationParam */
    offset=dissect_gsm_map_er_ForwardingViolationParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 15: /* CUG-RejectParam */
    offset=dissect_gsm_map_er_CUG_RejectParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 16: /* IllegalSS-OperationParam */
    offset=dissect_gsm_map_er_IllegalSS_OperationParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 17: /* SS-ErrorStatus */
    offset=dissect_gsm_map_ss_SS_Status(FALSE, tvb, offset, actx, tree, hf_gsm_map_ss_ss_Status);
    break;
  case 18: /* SS-NotAvailableParam */
    offset=dissect_gsm_map_er_SS_NotAvailableParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 19: /* SS-SubscriptionViolationParam */
    offset=dissect_gsm_map_er_SS_SubscriptionViolationParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 20: /* SS-IncompatibilityCause */
    offset=dissect_gsm_map_er_SS_IncompatibilityCause(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 21: /* FacilityNotSupParam */
    offset=dissect_gsm_map_er_FacilityNotSupParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 22: /* OngoingGroupCallParam */
      offset=dissect_gsm_map_er_OngoingGroupCallParam(FALSE, tvb, offset, actx, tree, -1);
      break;
  case 27: /* AbsentSubscriberParam */
    offset=dissect_gsm_map_er_AbsentSubscriberParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 28: /* IncompatibleTerminalParam */
    offset=dissect_gsm_map_er_IncompatibleTerminalParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 29: /* ShortTermDenialParam */
    offset=dissect_gsm_map_er_ShortTermDenialParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 30: /* LongTermDenialParam */
    offset=dissect_gsm_map_er_LongTermDenialParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 31: /* SubBusyForMT-SMS-Param */
    offset=dissect_gsm_map_er_SubBusyForMT_SMS_Param(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 32: /* SM-DeliveryFailureCause */
    offset = dissect_mc_message(tvb, offset, actx, tree,
                              FALSE, dissect_gsm_map_er_SM_EnumeratedDeliveryFailureCause, hf_gsm_map_er_sm_EnumeratedDeliveryFailureCause,
                              FALSE, dissect_gsm_map_er_SM_DeliveryFailureCause, -1,
                              FALSE, NULL, -1);

    break;
  case 33: /* MessageWaitListFullParam */
    offset=dissect_gsm_map_er_MessageWaitListFullParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 34: /* SystemFailureParam */
    offset=dissect_gsm_map_er_SystemFailureParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 35: /* DataMissingParam */
    offset=dissect_gsm_map_er_DataMissingParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 36: /* UnexpectedDataParam */
    offset=dissect_gsm_map_er_UnexpectedDataParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 37: /* PW-RegistrationFailureCause */
    offset=dissect_gsm_map_er_PW_RegistrationFailureCause(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 39: /* NoRoamingNbParam */
    offset=dissect_gsm_map_er_NoRoamingNbParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 40: /* TracingBufferFullParam */
    offset=dissect_gsm_map_er_TracingBufferFullParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 42: /* TargetCellOutsideGCA-Param */
    offset=dissect_gsm_map_er_TargetCellOutsideGCA_Param(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 44: /* NumberChangedParam */
    offset=dissect_gsm_map_er_NumberChangedParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 45: /* BusySubscriberParam */
    offset=dissect_gsm_map_er_BusySubscriberParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 46: /* NoSubscriberReplyParam */
    offset=dissect_gsm_map_er_NoSubscriberReplyParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 47: /* ForwardingFailedParam */
    offset=dissect_gsm_map_er_ForwardingFailedParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 48: /* OR-NotAllowedParam */
    offset=dissect_gsm_map_er_OR_NotAllowedParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 49: /* ATI-NotAllowedParam */
    offset=dissect_gsm_map_er_ATI_NotAllowedParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 50: /* NoGroupCallNbParam */
    offset=dissect_gsm_map_er_NoGroupCallNbParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 51: /* ResourceLimitationParam */
    offset=dissect_gsm_map_er_ResourceLimitationParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 52: /* UnauthorizedRequestingNetwork-Param */
    offset=dissect_gsm_map_er_UnauthorizedRequestingNetwork_Param(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 53: /* UnauthorizedLCSClient-Param */
    offset=dissect_gsm_map_er_UnauthorizedLCSClient_Param(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 54: /* PositionMethodFailure-Param */
    offset=dissect_gsm_map_er_PositionMethodFailure_Param(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 58: /* UnknownOrUnreachableLCSClient-Param */
    offset=dissect_gsm_map_er_UnknownOrUnreachableLCSClient_Param(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 59: /* MM-EventNotSupported-Param */
    offset=dissect_gsm_map_er_MM_EventNotSupported_Param(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 60: /* ATSI-NotAllowedParam */
    offset=dissect_gsm_map_er_ATSI_NotAllowedParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 61: /* ATM-NotAllowedParam */
    offset=dissect_gsm_map_er_ATM_NotAllowedParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  case 62: /* InformationNotAvailableParam */
    offset=dissect_gsm_map_er_InformationNotAvailableParam(FALSE, tvb, offset, actx, tree, -1);
    break;
  default:
    if(!dissector_try_uint_new(map_prop_err_opcode_table, (guint8)opcode, tvb, actx->pinfo, tree, TRUE, actx->subtree.top_tree)){
        proto_tree_add_expert_format(tree, actx->pinfo, &ei_gsm_map_unknown_invokeData,
                                     tvb, offset, -1, "Unknown returnErrorData %d", opcode);
    }
    offset+= tvb_reported_length_remaining(tvb,offset);
    break;
  }
  return offset;
}

/* Private extension container for PLMN Data */
static int dissect_gsm_mapext_PlmnContainer(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_gsm_old_PlmnContainer_U, NULL, "MAP Ext. Plmn Container");

  return dissect_gsm_old_PlmnContainer(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_gsm_map_ericsson_ext_ExtensionType(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
    proto_tree    *tree;
    asn1_ctx_t asn1_ctx;
    asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
    tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_gsm_map_ericsson_ExtensionType, NULL, "Ericsson Extension");
    return dissect_gsm_map_ericsson_ExtensionType(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_SriResExtension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_SriResExtension_U, NULL, "Nokia Extension");
  return dissect_NokiaMAP_Extensions_SriResExtension(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_CanLocArgExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_CanLocArgExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_CanLocArgExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_ATMargExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_ATMargExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_ATMargExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_DTMargExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_DTMargExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_DTMargExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_NumberPorted(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  return dissect_NokiaMAP_Extensions_NumberPorted(FALSE, tvb, 0, &asn1_ctx, parent_tree, -1);
}

static int dissect_NokiaMAP_ext_ATMresExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_ATMresExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_ATMresExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_AbsentSubscriberExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  asn1_ctx_t asn1_ctx;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  return dissect_NokiaMAP_Extensions_AbsentSubscriberExt(FALSE, tvb, 0, &asn1_ctx, parent_tree, -1);
}

static int dissect_NokiaMAP_ext_SriForSMArgExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_SriForSMArgExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_SriForSMArgExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_ReportSMDelStatArgExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_ReportSMDelStatArgExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_ReportSMDelStatArgExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_UdlArgExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_UdlArgExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_UdlArgExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_RoamNotAllowedExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_RoamNotAllowedExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_RoamNotAllowedExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_MO_ForwardSM_ArgExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_MO_ForwardSM_ArgExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_MO_ForwardSM_ArgExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_ErrOlcmInfoTableExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_ErrOlcmInfoTableExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_ErrOlcmInfoTableExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_RoutingCategoryExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_RoutingCategoryExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_RoutingCategoryExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_AnyTimeModArgExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_AnyTimeModArgExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_AnyTimeModArgExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_AccessTypeExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  return dissect_NokiaMAP_Extensions_AccessTypeExt(FALSE, tvb, 0, &asn1_ctx, parent_tree, -1);
}

static int dissect_NokiaMAP_ext_AccessSubscriptionListExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  return dissect_NokiaMAP_Extensions_AccessSubscriptionListExt(FALSE, tvb, 0, &asn1_ctx, parent_tree, -1);
}

static int dissect_NokiaMAP_ext_AllowedServiceData(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  return dissect_NokiaMAP_Extensions_AllowedServiceData(FALSE, tvb, 0, &asn1_ctx, parent_tree, -1);
}

static int dissect_NokiaMAP_ext_SriExtension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_SriExtension_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_SriExtension(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ExtraSignalInfo(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_ExtraSignalInfo_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_ExtraSignalInfo(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_SS_DataExtension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_SS_DataExtension_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_SS_DataExtension(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_HOExtension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_HO_Ext_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_HO_Ext(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_UlResExtension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_UlResExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_UlResExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}


static int dissect_NokiaMAP_ext_IsdArgExtension(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_IsdArgExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_IsdArgExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int dissect_NokiaMAP_ext_DsdArgExt(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data _U_) {
  proto_tree    *tree;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  /* create display subtree for the protocol */
  tree = proto_tree_add_subtree(parent_tree, tvb, 0, -1, ett_NokiaMAP_Extensions_DsdArgExt_U, NULL, "Nokia Extension");

  return dissect_NokiaMAP_Extensions_DsdArgExt(FALSE, tvb, 0, &asn1_ctx, tree, -1);
}

static int
dissect_gsm_map_GSMMAPPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset,
                          asn1_ctx_t *actx, proto_tree *tree, int hf_index _U_) {

  char *version_ptr;

  opcode = 0;
  if (pref_application_context_version == APPLICATON_CONTEXT_FROM_TRACE) {
    gsm_map_private_info_t *gsm_map_priv = (gsm_map_private_info_t*)actx->value_ptr;
    application_context_version = 0;
    if (gsm_map_priv && gsm_map_priv->tcap_private != NULL){
      if (gsm_map_priv->tcap_private->acv==TRUE ){
        version_ptr = strrchr((const char*)gsm_map_priv->tcap_private->oid,'.');
        if (version_ptr){
          ws_strtoi32(version_ptr + 1, NULL, &application_context_version);
        }
      }
    }
  }else{
    application_context_version = pref_application_context_version;
  }

  gsmmap_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
  /* Get the length and add 2 */
  gsm_map_pdu_size = tvb_get_guint8(tvb, offset+1)+2;

  col_set_str(actx->pinfo->cinfo, COL_INFO, val_to_str_const(gsmmap_pdu_type, gsm_old_Component_vals, "Unknown GSM-MAP Component"));
  col_append_str(actx->pinfo->cinfo, COL_INFO, " ");
  offset = dissect_gsm_old_Component(FALSE, tvb, 0, actx, tree, hf_gsm_map_old_Component_PDU);
/*
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              GSMMAPPDU_choice, hf_index, ett_gsm_map_GSMMAPPDU, NULL);
*/

  return offset;
}

static int
dissect_gsm_map(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
  proto_item  *item=NULL;
  proto_tree  *tree=NULL;
  /* Used for gsm_map TAP */
  static      gsm_map_tap_rec_t tap_rec;
  gint        op_idx;
  asn1_ctx_t asn1_ctx;
  gsm_map_private_info_t *gsm_map_priv;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM MAP");

  asn1_ctx.subtree.top_tree = parent_tree;

  gsm_map_priv = wmem_new0(pinfo->pool, gsm_map_private_info_t);
  gsm_map_priv->tcap_private = (struct tcap_private_t *)data;
  asn1_ctx.value_ptr = gsm_map_priv;

  /* create display subtree for the protocol */
  item = proto_tree_add_item(parent_tree, proto_gsm_map, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_gsm_map);

  dissect_gsm_map_GSMMAPPDU(FALSE, tvb, 0, &asn1_ctx, tree, -1);
  try_val_to_str_idx(opcode, gsm_map_opr_code_strings, &op_idx);

  if (op_idx != -1) {
    tap_rec.invoke = (gsmmap_pdu_type == 1) ? TRUE : FALSE;
    tap_rec.opcode = opcode;
    tap_rec.size = gsm_map_pdu_size;

    tap_queue_packet(gsm_map_tap, pinfo, &tap_rec);
  }

  return tvb_captured_length(tvb);
}

static int
dissect_gsm_map_sccp(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
  proto_item  *item=NULL;
  proto_tree  *tree=NULL;
  /* Used for gsm_map TAP */
  static      gsm_map_tap_rec_t tap_rec;
  gint        op_idx;
  asn1_ctx_t asn1_ctx;
  gsm_map_private_info_t *gsm_map_priv;

  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "GSM MAP");

  asn1_ctx.subtree.top_tree = parent_tree;

  gsm_map_priv = wmem_new0(pinfo->pool, gsm_map_private_info_t);
  gsm_map_priv->sccp_msg_info = (sccp_msg_info_t *)data;
  asn1_ctx.value_ptr = gsm_map_priv;

  /* create display subtree for the protocol */
  item = proto_tree_add_item(parent_tree, proto_gsm_map, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_gsm_map);

  dissect_gsm_map_GSMMAPPDU(FALSE, tvb, 0, &asn1_ctx, tree, -1);
  try_val_to_str_idx(opcode, gsm_map_opr_code_strings, &op_idx);

  if (op_idx != -1) {
    tap_rec.invoke = (gsmmap_pdu_type == 1) ? TRUE : FALSE;
    tap_rec.opcode = opcode;
    tap_rec.size = gsm_map_pdu_size;

    tap_queue_packet(gsm_map_tap, pinfo, &tap_rec);
  }

  return tvb_captured_length(tvb);
}

const value_string ssCode_vals[] = {
  { 0x00, "allSS - all SS" },
  { 0x10 ,"allLineIdentificationSS - all line identification SS" },
  { 0x11 ,"clip - calling line identification presentation" },
  { 0x12 ,"clir - calling line identification restriction" },
  { 0x13 ,"colp - connected line identification presentation" },
  { 0x14 ,"colr - connected line identification restriction" },
  { 0x15 ,"mci - malicious call identification" },
  { 0x18 ,"allNameIdentificationSS - all name identification SS" },
  { 0x19 ,"cnap - calling name presentation" },
  { 0x20 ,"allForwardingSS - all forwarding SS" },
  { 0x21 ,"cfu - call forwarding unconditional" },
  { 0x28 ,"allCondForwardingSS - all conditional forwarding SS" },
  { 0x29 ,"cfb - call forwarding busy" },
  { 0x2a ,"cfnry - call forwarding on no reply" },
  { 0x2b ,"cfnrc - call forwarding on mobile subscriber not reachable" },
  { 0x24 ,"cd - call deflection" },
  { 0x30 ,"allCallOfferingSS - all call offering SS includes also all forwarding SS" },
  { 0x31 ,"ect - explicit call transfer" },
  { 0x32 ,"mah - mobile access hunting" },
  { 0x40 ,"allCallCompletionSS - all Call completion SS" },
  { 0x41 ,"cw - call waiting" },
  { 0x42 ,"hold - call hold" },
  { 0x43 ,"ccbs-A - completion of call to busy subscribers, originating side" },
  { 0x44 ,"ccbs-B - completion of call to busy subscribers, destination side" },
  { 0x45 ,"mc - multicall" },
  { 0x50 ,"allMultiPartySS - all multiparty SS" },
  { 0x51 ,"multiPTY - multiparty" },
  { 0x60 ,"allCommunityOfInterestSS - all community of interest SS" },
  { 0x61 ,"cug - closed user group" },
  { 0x70 ,"allChargingSS - all charging SS" },
  { 0x71 ,"aoci - advice of charge information" },
  { 0x72 ,"aocc - advice of charge charging" },
  { 0x80 ,"allAdditionalInfoTransferSS - all additional information transfer SS" },
  { 0x81 ,"uus1 - UUS1 user-to-user signalling" },
  { 0x82 ,"uus2 - UUS2 user-to-user signalling" },
  { 0x83 ,"uus3 - UUS3 user-to-user signalling" },
  { 0x90 ,"allCallRestrictionSS - all Callrestriction SS" },
  { 0x91 ,"barringOfOutgoingCalls" },
  { 0x92 ,"baoc - barring of all outgoing calls" },
  { 0x93 ,"boic - barring of outgoing international calls" },
  { 0x94 ,"boicExHC - barring of outgoing international calls except those directed to the home PLMN" },
  { 0x99 ,"barringOfIncomingCalls" },
  { 0x9a ,"baic - barring of all incoming calls" },
  { 0x9b ,"bicRoam - barring of incoming calls when roaming outside home PLMN Country" },
  { 0xf0 ,"allPLMN-specificSS" },
  { 0xa0 ,"allCallPrioritySS - all call priority SS" },
  { 0xa1 ,"emlpp - enhanced Multilevel Precedence Pre-emption (EMLPP) service" },
  { 0xb0 ,"allLCSPrivacyException - all LCS Privacy Exception Classes" },
  { 0xb1 ,"universal - allow location by any LCS client" },
  { 0xb2 ,"callrelated - allow location by any value added LCS client to which a call is established from the target MS" },
  { 0xb3 ,"callunrelated - allow location by designated external value added LCS clients" },
  { 0xb4 ,"plmnoperator - allow location by designated PLMN operator LCS clients" },
  { 0xb5 ,"serviceType - allow location by LCS clients of a designated LCS service type" },
  { 0xc0 ,"allMOLR-SS - all Mobile Originating Location Request Classes" },
  { 0xc1 ,"basicSelfLocation - allow an MS to request its own location" },
  { 0xc2 ,"autonomousSelfLocation - allow an MS to perform self location without interaction with the PLMN for a predetermined period of time" },
  { 0xc3 ,"transferToThirdParty - allow an MS to request transfer of its location to another LCS client" },

  { 0xf1 ,"plmn-specificSS-1" },
  { 0xf2 ,"plmn-specificSS-2" },
  { 0xf3 ,"plmn-specificSS-3" },
  { 0xf4 ,"plmn-specificSS-4" },
  { 0xf5 ,"plmn-specificSS-5" },
  { 0xf6 ,"plmn-specificSS-6" },
  { 0xf7 ,"plmn-specificSS-7" },
  { 0xf8 ,"plmn-specificSS-8" },
  { 0xf9 ,"plmn-specificSS-9" },
  { 0xfa ,"plmn-specificSS-a" },
  { 0xfb ,"plmn-specificSS-b" },
  { 0xfc ,"plmn-specificSS-c" },
  { 0xfd ,"plmn-specificSS-d" },
  { 0xfe ,"plmn-specificSS-e" },
  { 0xff ,"plmn-specificSS-f" },
  { 0, NULL }
};

static const value_string Teleservice_vals[] = {
  { 0x00, "allTeleservices" },
  { 0x10, "allSpeechTransmissionServices" },
  { 0x11, "telephony" },
  { 0x12, "emergencyCalls" },
  { 0x20, "allShortMessageServices" },
  { 0x21, "shortMessageMT-PP" },
  { 0x22, "shortMessageMO-PP" },
  { 0x60, "allFacsimileTransmissionServices" },
  { 0x61, "facsimileGroup3AndAlterSpeech" },
  { 0x62, "automaticFacsimileGroup3" },
  { 0x63, "facsimileGroup4" },

  { 0x70, "allDataTeleservices" },
  { 0x80, "allTeleservices-ExceptSMS" },

  { 0x90, "allVoiceGroupCallServices" },
  { 0x91, "voiceGroupCall" },
  { 0x92, "voiceBroadcastCall" },

  { 0xd0, "allPLMN-specificTS" },
  { 0xd1, "plmn-specificTS-1" },
  { 0xd2, "plmn-specificTS-2" },
  { 0xd3, "plmn-specificTS-3" },
  { 0xd4, "plmn-specificTS-4" },
  { 0xd5, "plmn-specificTS-5" },
  { 0xd6, "plmn-specificTS-6" },
  { 0xd7, "plmn-specificTS-7" },
  { 0xd8, "plmn-specificTS-8" },
  { 0xd9, "plmn-specificTS-9" },
  { 0xda, "plmn-specificTS-A" },
  { 0xdb, "plmn-specificTS-B" },
  { 0xdc, "plmn-specificTS-C" },
  { 0xdd, "plmn-specificTS-D" },
  { 0xde, "plmn-specificTS-E" },
  { 0xdf, "plmn-specificTS-F" },
  { 0, NULL }
};

static const value_string Bearerservice_vals[] = {
  { 0x00, "allBearerServices" },
  { 0x10, "allDataCDA-Services" },
  { 0x11, "dataCDA-300bps" },
  { 0x12, "dataCDA-1200bps" },
  { 0x13, "dataCDA-1200-75bps" },
  { 0x14, "dataCDA-2400bps" },
  { 0x15, "dataCDA-4800bps" },
  { 0x16, "dataCDA-9600bps" },
  { 0x17, "general-dataCDA" },

  { 0x18, "allDataCDS-Services" },
  { 0x1A, "dataCDS-1200bps" },
  { 0x1C, "dataCDS-2400bps" },
  { 0x1D, "dataCDS-4800bps" },
  { 0x1E, "dataCDS-9600bps" },
  { 0x1F, "general-dataCDS" },

  { 0x20, "allPadAccessCA-Services" },
  { 0x21, "padAccessCA-300bps" },
  { 0x22, "padAccessCA-1200bps" },
  { 0x23, "padAccessCA-1200-75bps" },
  { 0x24, "padAccessCA-2400bps" },
  { 0x25, "padAccessCA-4800bps" },
  { 0x26, "padAccessCA-9600bps" },
  { 0x27, "general-padAccessCA" },

  { 0x28, "allDataPDS-Services" },
  { 0x2C, "dataPDS-2400bps" },
  { 0x2D, "dataPDS-4800bps" },
  { 0x2E, "dataPDS-9600bps" },
  { 0x2F, "general-dataPDS" },

  { 0x30, "allAlternateSpeech-DataCDA" },
  { 0x38, "allAlternateSpeech-DataCDS" },
  { 0x40, "allSpeechFollowedByDataCDA" },
  { 0x48, "allSpeechFollowedByDataCDS" },

  { 0x50, "allDataCircuitAsynchronous" },
  { 0x60, "allAsynchronousServices" },
  { 0x58, "allDataCircuitSynchronous" },
  { 0x68, "allSynchronousServices" },

  { 0xD0, "allPLMN-specificBS" },
  { 0xD1, "plmn-specificBS-1" },
  { 0xD2, "plmn-specificBS-2" },
  { 0xD3, "plmn-specificBS-3" },
  { 0xD4, "plmn-specificBS-4" },
  { 0xD5, "plmn-specificBS-5" },
  { 0xD6, "plmn-specificBS-6" },
  { 0xD7, "plmn-specificBS-7" },
  { 0xD8, "plmn-specificBS-8" },
  { 0xD9, "plmn-specificBS-9" },
  { 0xDA, "plmn-specificBS-A" },
  { 0xDB, "plmn-specificBS-B" },
  { 0xDC, "plmn-specificBS-C" },
  { 0xDD, "plmn-specificBS-D" },
  { 0xDE, "plmn-specificBS-E" },
  { 0xDF, "plmn-specificBS-F" },

  {  0, NULL }
};

/* ForwardingOptions

-- bit 8: notification to forwarding party
-- 0 no notification
-- 1 notification
*/
static const true_false_string notification_value  = {
  "Notification",
  "No notification"
};
/*
-- bit 7: redirecting presentation
-- 0 no presentation
-- 1 presentation
*/
static const true_false_string redirecting_presentation_value  = {
  "Presentation",
  "No presentation"
};
/*
-- bit 6: notification to calling party
-- 0 no notification
-- 1 notification
*/
/*
-- bit 5: 0 (unused)
-- bits 43: forwarding reason
-- 00 ms not reachable
-- 01 ms busy
-- 10 no reply
-- 11 unconditional when used in a SRI Result,
-- or call deflection when used in a RCH Argument
*/
static const value_string forwarding_reason_values[] = {
  { 0x0, "ms not reachable" },
  { 0x1, "ms busy" },
  { 0x2, "no reply" },
  { 0x3, "unconditional when used in a SRI Result or call deflection when used in a RCH Argument" },
  {  0, NULL }
};
/*
-- bits 21: 00 (unused)
*/

static const value_string pdp_type_org_values[] = {
  { 0x0, "ETSI" },
  { 0x1, "IETF" },
  { 0xf, "Empty PDP type" },
  {  0, NULL }
};

static const value_string etsi_pdp_type_number_values[] = {
  { 0x0, "Reserved, used in earlier version of this protocol" },
  { 0x1, "PPP" },
  {  0, NULL }
};

static const value_string ietf_pdp_type_number_values[] = {
  { 0x21, "IPv4 Address" },
  { 0x57, "IPv6 Address" },
  {  0, NULL }
};

/*
ChargingCharacteristics ::= OCTET STRING (SIZE (2))
-- Octets are coded according to 3GPP TS 32.015.
-- From 3GPP TS 32.015.
--
-- Descriptions for the bits of the flag set:
--
-- Bit 1: H (Hot billing) := '00000001'B
-- Bit 2: F (Flat rate) := '00000010'B
-- Bit 3: P (Prepaid service) := '00000100'B
-- Bit 4: N (Normal billing) := '00001000'B
-- Bit 5: - (Reserved, set to 0) := '00010000'B
-- Bit 6: - (Reserved, set to 0) := '00100000'B
-- Bit 7: - (Reserved, set to 0) := '01000000'B
-- Bit 8: - (Reserved, set to 0) := '10000000'B
*/
static const value_string chargingcharacteristics_values[] = {
  { 0x1, "H (Hot billing)" },
  { 0x2, "F (Flat rate)" },
  { 0x4, "P (Prepaid service)" },
  { 0x8, "N (Normal billing)" },
  {  0, NULL }
};

/* TAP STAT INFO */
typedef enum
{
  ID_COLUMN,
  OP_CODE_COLUMN,
  INVOKES_COLUMN,
  NUM_BYTES_FWD_COLUMN,
  AVG_BYTES_FWD_COLUMN,
  RET_RES_COLUMN,
  NUM_BYTES_REV_COLUMN,
  AVG_BYTES_REV_COLUMN,
  TOT_BYTES_COLUMN,
  AVG_BYTES_COLUMN
} gsm_a_stat_columns;

static stat_tap_table_item gsm_map_stat_fields[] = {
  {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "ID", "%d"},
  {TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "Operation Code", "%-25s"},
  {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Invokes", "%d"},
  {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Num Bytes", "%d"},
  {TABLE_ITEM_FLOAT, TAP_ALIGN_RIGHT, "Avg Bytes", "%1.2f"},
  {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Return Result", "%d"},
  {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Num Bytes", "%d"},
  {TABLE_ITEM_FLOAT, TAP_ALIGN_RIGHT, "Avg Bytes", "%1.2f"},
  {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Total Bytes", "%d"},
  {TABLE_ITEM_FLOAT, TAP_ALIGN_RIGHT, "Avg Bytes", "%1.2f"},
};

static void gsm_map_stat_init(stat_tap_table_ui* new_stat)
{
  const char *table_name = "GSM MAP Operation Statistics";
  int num_fields = sizeof(gsm_map_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table* table;
  guint i;
  stat_tap_table_item_type items[sizeof(gsm_map_stat_fields)/sizeof(stat_tap_table_item)];

  memset(items, 0, sizeof(items));

  items[ID_COLUMN].type = TABLE_ITEM_UINT;
  items[OP_CODE_COLUMN].type = TABLE_ITEM_STRING;
  items[INVOKES_COLUMN].type = TABLE_ITEM_UINT;
  items[NUM_BYTES_FWD_COLUMN].type = TABLE_ITEM_UINT;
  items[AVG_BYTES_FWD_COLUMN].type = TABLE_ITEM_FLOAT;
  items[RET_RES_COLUMN].type = TABLE_ITEM_UINT;
  items[NUM_BYTES_REV_COLUMN].type = TABLE_ITEM_UINT;
  items[AVG_BYTES_REV_COLUMN].type = TABLE_ITEM_FLOAT;
  items[TOT_BYTES_COLUMN].type = TABLE_ITEM_UINT;
  items[AVG_BYTES_COLUMN].type = TABLE_ITEM_FLOAT;

  table = stat_tap_find_table(new_stat, table_name);
  if (table) {
    if (new_stat->stat_tap_reset_table_cb) {
      new_stat->stat_tap_reset_table_cb(table);
    }
    return;
  }

  table = stat_tap_init_table(table_name, num_fields, 0, NULL);
  stat_tap_add_table(new_stat, table);

  /* Add a row for each value type */
  for (i = 0; i < GSM_MAP_MAX_NUM_OPR_CODES; i++)
  {
    const char *ocs = try_val_to_str(i, gsm_map_opr_code_strings);
    char *col_str;
    if (ocs) {
      col_str = g_strdup(ocs);
    } else {
      col_str = ws_strdup_printf("Unknown op code %d", i);
    }

    items[ID_COLUMN].value.uint_value = i;
    items[OP_CODE_COLUMN].value.string_value = col_str;
    stat_tap_init_table_row(table, i, num_fields, items);
  }
}

static tap_packet_status
gsm_map_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *gmtr_ptr, tap_flags_t flags _U_)
{
  stat_data_t* stat_data = (stat_data_t*)tapdata;
  const gsm_map_tap_rec_t *gmtr = (const gsm_map_tap_rec_t *)gmtr_ptr;
  stat_tap_table* table;
  stat_tap_table_item_type *invoke_data, *fwd_bytes_data, *result_data, *rev_bytes_data, *avg_data;
  guint invokes, fwd_bytes, results, rev_bytes;

  table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, 0);

  invoke_data = stat_tap_get_field_data(table, gmtr->opcode, INVOKES_COLUMN);
  fwd_bytes_data = stat_tap_get_field_data(table, gmtr->opcode, NUM_BYTES_FWD_COLUMN);
  result_data = stat_tap_get_field_data(table, gmtr->opcode, RET_RES_COLUMN);
  rev_bytes_data = stat_tap_get_field_data(table, gmtr->opcode, NUM_BYTES_REV_COLUMN);

  if (gmtr->invoke)
  {
    invoke_data->value.uint_value++;
    stat_tap_set_field_data(table, gmtr->opcode, INVOKES_COLUMN, invoke_data);

    fwd_bytes_data->value.uint_value += gmtr->size;
    stat_tap_set_field_data(table, gmtr->opcode, NUM_BYTES_FWD_COLUMN, fwd_bytes_data);
  }
  else
  {
    result_data->value.uint_value++;
    stat_tap_set_field_data(table, gmtr->opcode, RET_RES_COLUMN, result_data);

    rev_bytes_data->value.uint_value += gmtr->size;
    stat_tap_set_field_data(table, gmtr->opcode, NUM_BYTES_REV_COLUMN, rev_bytes_data);
  }

  invokes = invoke_data->value.uint_value;
  fwd_bytes = fwd_bytes_data->value.uint_value;
  results = result_data->value.uint_value;
  rev_bytes = rev_bytes_data->value.uint_value;

  if (gmtr->invoke)
  {
    avg_data = stat_tap_get_field_data(table, gmtr->opcode, AVG_BYTES_FWD_COLUMN);
    avg_data->value.float_value += (float) fwd_bytes / invokes;
    stat_tap_set_field_data(table, gmtr->opcode, AVG_BYTES_FWD_COLUMN, avg_data);
  }
  else
  {
    avg_data = stat_tap_get_field_data(table, gmtr->opcode, AVG_BYTES_REV_COLUMN);
    avg_data->value.float_value += (float) rev_bytes / results;
    stat_tap_set_field_data(table, gmtr->opcode, AVG_BYTES_REV_COLUMN, avg_data);
  }

  avg_data = stat_tap_get_field_data(table, gmtr->opcode, AVG_BYTES_COLUMN);
  avg_data->value.float_value += (float) (fwd_bytes + rev_bytes) / (invokes + results);
  stat_tap_set_field_data(table, gmtr->opcode, AVG_BYTES_COLUMN, avg_data);
  return TAP_PACKET_REDRAW;
}

static void
gsm_map_stat_reset(stat_tap_table* table)
{
  guint element;
  stat_tap_table_item_type* item_data;

  for (element = 0; element < table->num_elements; element++)
  {
    item_data = stat_tap_get_field_data(table, element, INVOKES_COLUMN);
    item_data->value.uint_value = 0;
    stat_tap_set_field_data(table, element, INVOKES_COLUMN, item_data);
  }
}

static void
gsm_map_stat_free_table_item(stat_tap_table* table _U_, guint row _U_, guint column, stat_tap_table_item_type* field_data)
{
  if (column != OP_CODE_COLUMN) return;
  g_free((char*)field_data->value.string_value);
}

/*--- proto_reg_handoff_gsm_map ---------------------------------------*/
static void range_delete_callback(guint32 ssn, gpointer ptr _U_)
{
  if (ssn) {
    delete_itu_tcap_subdissector(ssn, map_handle);
  }
}

static void range_add_callback(guint32 ssn, gpointer ptr _U_)
{
  if (ssn) {
   add_itu_tcap_subdissector(ssn, map_handle);
  }
}

void proto_reg_handoff_gsm_map(void) {

  static gboolean map_prefs_initialized = FALSE;
  static range_t *ssn_range;

  if (!map_prefs_initialized) {
    map_prefs_initialized = TRUE;
    ranap_handle = find_dissector_add_dependency("ranap", proto_gsm_map);
    dtap_handle = find_dissector_add_dependency("gsm_a_dtap", proto_gsm_map);
    gsm_sms_handle = find_dissector_add_dependency("gsm_sms", proto_gsm_map);
    bssap_handle = find_dissector_add_dependency("gsm_a_bssmap", proto_gsm_map);

    oid_add_from_string("itu(0) administration(2) japan(440)","0.2.440" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.1.3", map_handle, proto_gsm_map,"networkLocUpContext-v3");
    register_ber_oid_dissector_handle("0.4.0.0.1.0.1.2", map_handle, proto_gsm_map,"networkLocUpContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.1.1", map_handle, proto_gsm_map,"networkLocUpContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.2.3", map_handle, proto_gsm_map,"locationCancellationContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.2.2", map_handle, proto_gsm_map,"locationCancellationContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.2.1", map_handle, proto_gsm_map,"locationCancellationContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.3.3", map_handle, proto_gsm_map,"roamingNumberEnquiryContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.3.2", map_handle, proto_gsm_map,"roamingNumberEnquiryContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.3.1", map_handle, proto_gsm_map,"roamingNumberEnquiryContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.4.3", map_handle, proto_gsm_map,"istAlertingContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.5.3", map_handle, proto_gsm_map,"locationInfoRetrievalContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.5.2", map_handle, proto_gsm_map,"locationInfoRetrievalContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.5.1", map_handle, proto_gsm_map,"locationInfoRetrievalContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.6.4", map_handle, proto_gsm_map,"callControlTransferContext-v4" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.6.3", map_handle, proto_gsm_map,"callControlTransferContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.7.3", map_handle, proto_gsm_map,"reportingContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.8.3", map_handle, proto_gsm_map,"callCompletionContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.9.3", map_handle, proto_gsm_map,"serviceTerminationContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.10.2", map_handle, proto_gsm_map,"resetContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.10.1", map_handle, proto_gsm_map,"resetContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.11.3", map_handle, proto_gsm_map,"handoverControlContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.11.2", map_handle, proto_gsm_map,"handoverControlContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.11.1", map_handle, proto_gsm_map,"handoverControlContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.12.3", map_handle, proto_gsm_map,"sIWFSAllocationContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.13.3", map_handle, proto_gsm_map,"equipmentMngtContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.13.2", map_handle, proto_gsm_map,"equipmentMngtContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.13.1", map_handle, proto_gsm_map,"equipmentMngtContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.14.3", map_handle, proto_gsm_map,"infoRetrievalContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.14.2", map_handle, proto_gsm_map,"infoRetrievalContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.14.1", map_handle, proto_gsm_map,"infoRetrievalContext-v1" );
    /* fallback to infoRetrieval(14) version1(1) and not interVlrInfoRetrieval(15) version1(1) */
    /*register_ber_oid_dissector_handle("0.4.0.0.1.0.15.1", map_handle, proto_gsm_map,"map-ac interVlrInfoRetrieval(15) version1(1)" );*/
    register_ber_oid_dissector_handle("0.4.0.0.1.0.15.2", map_handle, proto_gsm_map,"interVlrInfoRetrievalContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.15.3", map_handle, proto_gsm_map,"interVlrInfoRetrievalContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.16.3", map_handle, proto_gsm_map,"subscriberDataMngtContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.16.2", map_handle, proto_gsm_map,"subscriberDataMngtContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.16.1", map_handle, proto_gsm_map,"subscriberDataMngtContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.17.3", map_handle, proto_gsm_map,"tracingContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.17.2", map_handle, proto_gsm_map,"tracingContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.17.1", map_handle, proto_gsm_map,"tracingContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.18.2", map_handle, proto_gsm_map,"networkFunctionalSsContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.18.1", map_handle, proto_gsm_map,"networkFunctionalSsContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.19.2", map_handle, proto_gsm_map,"networkUnstructuredSsContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.20.3", map_handle, proto_gsm_map,"shortMsgGatewayContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.20.2", map_handle, proto_gsm_map,"shortMsgGatewayContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.20.1", map_handle, proto_gsm_map,"shortMsgGatewayContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.21.3", map_handle, proto_gsm_map,"shortMsgMO-RelayContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.21.2", map_handle, proto_gsm_map,"shortMsgMO-RelayContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.21.1", map_handle, proto_gsm_map,"shortMsgRelayContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.22.3", map_handle, proto_gsm_map,"subscriberDataModificationNotificationContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.23.2", map_handle, proto_gsm_map,"shortMsgAlertContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.23.1", map_handle, proto_gsm_map,"shortMsgAlertContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.24.3", map_handle, proto_gsm_map,"mwdMngtContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.24.2", map_handle, proto_gsm_map,"mwdMngtContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.24.1", map_handle, proto_gsm_map,"mwdMngtContext-v1" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.25.3", map_handle, proto_gsm_map,"shortMsgMT-RelayContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.25.2", map_handle, proto_gsm_map,"shortMsgMT-RelayContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.26.2", map_handle, proto_gsm_map,"imsiRetrievalContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.27.2", map_handle, proto_gsm_map,"msPurgingContext-v2" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.27.3", map_handle, proto_gsm_map,"msPurgingContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.28.3", map_handle, proto_gsm_map,"subscriberInfoEnquiryContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.29.3", map_handle, proto_gsm_map,"anyTimeInfoEnquiryContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.31.3", map_handle, proto_gsm_map,"groupCallControlContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.32.3", map_handle, proto_gsm_map,"gprsLocationUpdateContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.33.4", map_handle, proto_gsm_map,"gprsLocationInfoRetrievalContext-v4" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.33.3", map_handle, proto_gsm_map,"gprsLocationInfoRetrievalContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.34.3", map_handle, proto_gsm_map,"failureReportContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.35.3", map_handle, proto_gsm_map,"gprsNotifyContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.36.3", map_handle, proto_gsm_map,"ss-InvocationNotificationContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.37.3", map_handle, proto_gsm_map,"locationSvcGatewayContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.38.3", map_handle, proto_gsm_map,"locationSvcEnquiryContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.39.3", map_handle, proto_gsm_map,"authenticationFailureReportContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.40.3", map_handle, proto_gsm_map,"secureTransportHandlingContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.41.3", map_handle, proto_gsm_map,"shortMsgMT-Relay-VGCS-Context-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.42.3", map_handle, proto_gsm_map,"mm-EventReportingContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.43.3", map_handle, proto_gsm_map,"anyTimeInfoHandlingContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.44.3", map_handle, proto_gsm_map,"resourceManagementContext-v3" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.45.3", map_handle, proto_gsm_map,"groupCallInfoRetrievalContext-v3" );
    /* Private extension container */
    register_ber_oid_dissector("1.3.12.2.1006.53.2.1.3", dissect_gsm_mapext_PlmnContainer, proto_gsm_map,"alcatel-E10-MAP-extension-PlmnContainer" );
    register_ber_oid_dissector("0.34.0",dissect_NokiaMAP_ext_IsdArgExtension,proto_gsm_map,"Nokia ISD Extension");
    register_ber_oid_dissector("0.34.1",dissect_NokiaMAP_ext_DsdArgExt,proto_gsm_map,"Nokia Dsd Extension");
    register_ber_oid_dissector("0.34.2",dissect_NokiaMAP_ext_UlResExtension,proto_gsm_map,"Nokia Location Update Extension");
    register_ber_oid_dissector("0.34.4",dissect_NokiaMAP_ext_SS_DataExtension,proto_gsm_map,"Nokia SS Data Extension");
    register_ber_oid_dissector("0.34.5",dissect_NokiaMAP_ext_SriExtension,proto_gsm_map,"Nokia SRI Request Extension");
    register_ber_oid_dissector("0.34.6",dissect_NokiaMAP_ExtraSignalInfo,proto_gsm_map,"Nokia ExtraSignalInfo Extension");
    register_ber_oid_dissector("0.34.7",dissect_NokiaMAP_ext_SriResExtension,proto_gsm_map,"Nokia SRI Response Extension");
    register_ber_oid_dissector("0.34.10",dissect_NokiaMAP_ext_CanLocArgExt,proto_gsm_map,"Nokia Cancel Location Extension");
    register_ber_oid_dissector("0.34.11",dissect_NokiaMAP_ext_ATMargExt,proto_gsm_map,"Nokia ATM Extension");
    register_ber_oid_dissector("0.34.12",dissect_NokiaMAP_ext_DTMargExt,proto_gsm_map,"Nokia DTM Extension");
    register_ber_oid_dissector("0.34.13",dissect_NokiaMAP_ext_NumberPorted,proto_gsm_map,"Nokia NumberPorted Extension");
    register_ber_oid_dissector("0.34.15",dissect_NokiaMAP_ext_HOExtension,proto_gsm_map,"Nokia HandOver Extension");
    register_ber_oid_dissector("0.34.16",dissect_NokiaMAP_ext_ATMresExt,proto_gsm_map,"Nokia ATMres Extension");
    register_ber_oid_dissector("0.34.17",dissect_NokiaMAP_ext_AbsentSubscriberExt,proto_gsm_map,"Nokia AbsentSubscriber Extension");
    register_ber_oid_dissector("0.34.18",dissect_NokiaMAP_ext_SriForSMArgExt,proto_gsm_map,"Nokia SriForSM Extension");
    register_ber_oid_dissector("0.34.19",dissect_NokiaMAP_ext_ReportSMDelStatArgExt,proto_gsm_map,"Nokia ReportSMDelStatt Extension");
    register_ber_oid_dissector("0.34.20",dissect_NokiaMAP_ext_UdlArgExt,proto_gsm_map,"Nokia Udl Extension");
    register_ber_oid_dissector("0.34.21",dissect_NokiaMAP_ext_RoamNotAllowedExt,proto_gsm_map,"Nokia RoamNotAllowed Extension");
    register_ber_oid_dissector("0.34.22",dissect_NokiaMAP_ext_MO_ForwardSM_ArgExt,proto_gsm_map,"Nokia MO-ForwardSM Extension");
    register_ber_oid_dissector("0.34.23",dissect_NokiaMAP_ext_ErrOlcmInfoTableExt,proto_gsm_map,"Nokia ErrOlcmInfoTable Extension");
    register_ber_oid_dissector("0.34.25",dissect_NokiaMAP_ext_RoutingCategoryExt,proto_gsm_map,"Nokia Routing Category Extension");
    register_ber_oid_dissector("0.34.26",dissect_NokiaMAP_ext_AnyTimeModArgExt,proto_gsm_map,"Nokia AnyTimeMod Extension");

    register_ber_oid_dissector("1.3.12.2.1107.3.66.1.1",dissect_NokiaMAP_ext_AccessTypeExt,proto_gsm_map,"Nokia AccessTypeExt Extension");
    register_ber_oid_dissector("1.3.12.2.1107.3.66.1.3",dissect_NokiaMAP_ext_AccessSubscriptionListExt,proto_gsm_map,"Nokia AccessSubscriptionListExt Extension");
    register_ber_oid_dissector("1.3.12.2.1107.3.66.1.6",dissect_NokiaMAP_ext_AllowedServiceData,proto_gsm_map,"Nokia AllowedServiceData Extension");

    register_ber_oid_dissector("1.2.826.0.1249.58.1.0",dissect_gsm_map_ericsson_ext_ExtensionType,proto_gsm_map,"Ericsson ExtensionType Extension");
  }
  else {
    range_foreach(ssn_range, range_delete_callback, NULL);
    wmem_free(wmem_epan_scope(), ssn_range);
  }

  ssn_range = range_copy(wmem_epan_scope(), global_ssn_range);
  range_foreach(ssn_range, range_add_callback, NULL);

}

/*--- proto_register_gsm_map -------------------------------------------*/
void proto_register_gsm_map(void) {
  module_t *gsm_map_module;
  expert_module_t* expert_gsm_map;

  /* List of fields */
  static hf_register_info hf[] = {
      { &hf_gsm_map_old_Component_PDU,
        { "Component", "gsm_map.old.Component",
          FT_UINT32, BASE_DEC, VALS(gsm_old_Component_vals), 0,
          NULL, HFILL }},
      { &hf_gsm_map_getPassword,
        { "getPassword", "gsm_map.getPassword",
          FT_UINT8, BASE_DEC, VALS(gsm_old_GetPasswordArg_vals), 0,
          NULL, HFILL }},
      { &hf_gsm_map_currentPassword,
        { "currentPassword", "gsm_map.currentPassword",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},
      { &hf_gsm_map_extension,
        { "Extension", "gsm_map.extension",
          FT_BOOLEAN, 8, TFS(&tfs_no_extension_extension), 0x80,
          NULL, HFILL }},
      { &hf_gsm_map_nature_of_number,
        { "Nature of number", "gsm_map.nature_of_number",
          FT_UINT8, BASE_HEX|BASE_EXT_STRING, &gsm_map_nature_of_number_values_ext, 0x70,
          NULL, HFILL }},
      { &hf_gsm_map_number_plan,
        { "Number plan", "gsm_map.number_plan",
          FT_UINT8, BASE_HEX|BASE_EXT_STRING, &gsm_map_number_plan_values_ext, 0x0f,
          NULL, HFILL }},
      { &hf_gsm_map_address_digits,
        { "Address digits", "gsm_map.address.digits",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},
      { &hf_gsm_map_TBCD_digits,
        { "TBCD digits", "gsm_map.tbcd_digits",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},
      { &hf_gsm_map_Ss_Status_unused,
        { "Unused", "gsm_map.unused",
          FT_UINT8, BASE_HEX, NULL, 0xf0,
          NULL, HFILL }},
      { &hf_gsm_map_Ss_Status_q_bit,
        { "Q bit", "gsm_map.ss_status_q_bit",
          FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_q_bit_values), 0x08,
          NULL, HFILL }},
      { &hf_gsm_map_Ss_Status_p_bit,
        { "P bit", "gsm_map.ss_status_p_bit",
          FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_p_values), 0x04,
          NULL, HFILL }},
      { &hf_gsm_map_Ss_Status_r_bit,
        { "R bit", "gsm_map.ss_status_r_bit",
          FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_r_values), 0x02,
          NULL, HFILL }},
      { &hf_gsm_map_Ss_Status_a_bit,
        { "A bit", "gsm_map.ss_status_a_bit",
          FT_BOOLEAN, 8, TFS(&gsm_map_Ss_Status_a_values), 0x01,
          NULL, HFILL }},
      { &hf_gsm_map_notification_to_forwarding_party,
        { "Notification to forwarding party", "gsm_map.notification_to_forwarding_party",
          FT_BOOLEAN, 8, TFS(&notification_value), 0x80,
          NULL, HFILL }},
      { &hf_gsm_map_redirecting_presentation,
        { "Redirecting presentation", "gsm_map.redirecting_presentation",
          FT_BOOLEAN, 8, TFS(&redirecting_presentation_value), 0x40,
          NULL, HFILL }},
      { &hf_gsm_map_notification_to_calling_party,
        { "Notification to calling party", "gsm_map.notification_to_calling_party",
          FT_BOOLEAN, 8, TFS(&notification_value), 0x20,
          NULL, HFILL }},
      { &hf_gsm_map_forwarding_reason,
        { "Forwarding reason", "gsm_map.forwarding_reason",
          FT_UINT8, BASE_HEX, VALS(forwarding_reason_values), 0x0c,
          NULL, HFILL }},
      { &hf_gsm_map_pdp_type_org,
        { "PDP Type Organization", "gsm_map.pdp_type_org",
          FT_UINT8, BASE_HEX, VALS(pdp_type_org_values), 0x0f,
          NULL, HFILL }},
      { &hf_gsm_map_etsi_pdp_type_number,
        { "PDP Type Number", "gsm_map.pdp_type_number",
          FT_UINT8, BASE_HEX, VALS(etsi_pdp_type_number_values), 0,
          "ETSI PDP Type Number", HFILL }},
      { &hf_gsm_map_ietf_pdp_type_number,
        { "PDP Type Number", "gsm_map.ietf_pdp_type_number",
          FT_UINT8, BASE_HEX, VALS(ietf_pdp_type_number_values), 0,
          "IETF PDP Type Number", HFILL }},
      { &hf_gsm_map_ext_qos_subscribed_pri,
        { "Allocation/Retention priority", "gsm_map.ext_qos_subscribed_pri",
          FT_UINT8, BASE_DEC, NULL, 0xff,
          NULL, HFILL }},
      { &hf_gsm_map_qos_traffic_cls,
        { "Traffic class", "gsm_map.qos.traffic_cls",
          FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_traffic_cls_vals), 0xe0,
          NULL, HFILL }},
      { &hf_gsm_map_qos_del_order,
        { "Delivery order", "gsm_map.qos.del_order",
          FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_traffic_cls_vals), 0x18,
          NULL, HFILL }},
      { &hf_gsm_map_qos_del_of_err_sdu,
        { "Delivery of erroneous SDUs", "gsm_map.qos.del_of_err_sdu",
          FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_del_of_err_sdu_vals), 0x03,
          NULL, HFILL }},
      { &hf_gsm_map_qos_ber,
        { "Residual Bit Error Rate (BER)", "gsm_map.qos.ber",
          FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_ber_vals), 0xf0,
          NULL, HFILL }},
      { &hf_gsm_map_qos_sdu_err_rat,
        { "SDU error ratio", "gsm_map.qos.sdu_err_rat",
          FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_sdu_err_rat_vals), 0x0f,
          NULL, HFILL }},
      { &hf_gsm_map_qos_traff_hdl_pri,
        { "Traffic handling priority", "gsm_map.qos.traff_hdl_pri",
          FT_UINT8, BASE_DEC, VALS(gsm_a_sm_qos_traff_hdl_pri_vals), 0x03,
          NULL, HFILL }},

      { &hf_gsm_map_qos_max_sdu,
        { "Maximum SDU size", "gsm_map.qos.max_sdu",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          NULL, HFILL }},
      { &hf_gsm_map_max_brate_ulink,
        { "Maximum bit rate for uplink in kbit/s", "gsm_map.qos.max_brate_ulink",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Maximum bit rate for uplink", HFILL }},
      { &hf_gsm_map_max_brate_dlink,
        { "Maximum bit rate for downlink in kbit/s", "gsm_map.qos.max_brate_dlink",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Maximum bit rate for downlink", HFILL }},
      { &hf_gsm_map_qos_transfer_delay,
        { "Transfer delay (Raw data see TS 24.008 for interpretation)", "gsm_map.qos.transfer_delay",
          FT_UINT8, BASE_DEC, NULL, 0xfc,
          "Transfer delay", HFILL }},
      { &hf_gsm_map_guaranteed_max_brate_ulink,
        { "Guaranteed bit rate for uplink in kbit/s", "gsm_map.qos.brate_ulink",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Guaranteed bit rate for uplink", HFILL }},
      { &hf_gsm_map_guaranteed_max_brate_dlink,
        { "Guaranteed bit rate for downlink in kbit/s", "gsm_map.qos.brate_dlink",
          FT_UINT32, BASE_DEC, NULL, 0x0,
          "Guaranteed bit rate for downlink", HFILL }},
      { &hf_gsm_map_GSNAddress_IPv4,
        { "GSN-Address IPv4",  "gsm_map.gsnaddress_ipv4",
          FT_IPv4, BASE_NONE, NULL, 0,
          "IPAddress IPv4", HFILL }},
      { &hf_gsm_map_GSNAddress_IPv6,
        { "GSN Address IPv6",  "gsm_map.gsnaddress_ipv6",
          FT_IPv6, BASE_NONE, NULL, 0,
          "IPAddress IPv6", HFILL }},
      { &hf_gsm_map_ranap_service_Handover,
        { "service-Handover", "gsm_map.ranap.service_Handover",
          FT_UINT32, BASE_DEC, VALS(ranap_Service_Handover_vals), 0,
          "gsm_map.ranap.Service_Handover", HFILL }},
      { &hf_gsm_map_IntegrityProtectionInformation,
        { "IntegrityProtectionInformation", "gsm_map.ranap.IntegrityProtectionInformation",
          FT_NONE, BASE_NONE, NULL, 0,
          "gsm_map.ranap.IntegrityProtectionInformation", HFILL }},
      { &hf_gsm_map_EncryptionInformation,
        { "EncryptionInformation", "gsm_map.ranap.EncryptionInformation",
          FT_NONE, BASE_NONE, NULL, 0,
          "gsm_map.ranap.EncryptionInformation", HFILL }},
      { &hf_gsm_map_ss_SS_UserData,
        { "SS-UserData", "gsm_ss.SS_UserData",
          FT_STRING, BASE_NONE, NULL, 0,
          "gsm_map.ss.SS_UserData", HFILL }},
      { &hf_gsm_map_cbs_coding_grp,
        { "Coding Group","gsm_map.cbs.coding_grp",
          FT_UINT8,BASE_DEC|BASE_EXT_STRING, &gsm_map_cbs_data_coding_scheme_coding_grp_vals_ext, 0xf0,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp0_lang,
        { "Language","gsm_map.cbs.coding_grp0_lang",
          FT_UINT8,BASE_DEC|BASE_EXT_STRING, &gsm_map_cbs_coding_grp0_lang_vals_ext, 0x0f,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp1_lang,
        { "Language","gsm_map.cbs.coding_grp1_lang",
          FT_UINT8,BASE_DEC|BASE_EXT_STRING, &gsm_map_cbs_coding_grp1_lang_vals_ext, 0x0f,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp2_lang,
        { "Language","gsm_map.cbs.coding_grp2_lang",
          FT_UINT8,BASE_DEC|BASE_EXT_STRING, &gsm_map_cbs_coding_grp2_lang_vals_ext, 0x0f,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp3_lang,
        { "Language","gsm_map.cbs.coding_grp3_lang",
          FT_UINT8,BASE_DEC|BASE_EXT_STRING, &gsm_map_cbs_coding_grp3_lang_vals_ext, 0x0f,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp4_7_comp,
        { "Compressed indicator","gsm_map.cbs.coding_grp4_7_comp",
          FT_BOOLEAN, 8, TFS(&gsm_map_cbs_coding_grp4_7_comp_vals), 0x20,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp4_7_class_ind,
        { "Message Class present","gsm_map.cbs.coding_grp4_7_class_ind",
          FT_BOOLEAN, 8, TFS(&gsm_map_cbs_coding_grp4_7_class_ind_vals), 0x10,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp4_7_char_set,
        { "Character set being used","gsm_map.cbs.coding_grp4_7_char_set",
          FT_UINT8,BASE_DEC, VALS(gsm_map_cbs_coding_grp4_7_char_set_vals), 0x0c,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp4_7_class,
        { "Message Class","gsm_map.cbs.coding_grp4_7_class",
          FT_UINT8,BASE_DEC, VALS(gsm_map_cbs_coding_grp4_7_class_vals), 0x03,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp15_mess_code,
        { "Message coding","gsm_map.cbs.cbs_coding_grp15_mess_code",
          FT_UINT8,BASE_DEC, VALS(gsm_map_cbs_coding_grp15_mess_code_vals), 0x04,
          NULL, HFILL }
      },
      { &hf_gsm_map_cbs_coding_grp15_class,
        { "Message Class","gsm_map.cbs.gsm_map_cbs_coding_grp15_class",
          FT_UINT8,BASE_DEC, VALS(gsm_map_cbs_coding_grp15_class_vals), 0x03,
          NULL, HFILL }
      },
      { &hf_gsm_map_tmsi,
        { "tmsi", "gsm_map.tmsi",
          FT_BYTES, BASE_NONE, NULL, 0,
          "gsm_map.TMSI", HFILL }},

      { &hf_gsm_map_ie_tag,
        { "Tag", "gsm_map.ie_tag",
          FT_UINT8, BASE_DEC, VALS(gsm_map_tag_vals), 0,
          "GSM 04.08 tag", HFILL }},
      { &hf_gsm_map_len,
        { "Length", "gsm_map.length",
          FT_UINT8, BASE_DEC, NULL, 0,
          NULL, HFILL }},
      { &hf_gsm_map_disc_par,
        { "Discrimination parameter", "gsm_map.disc_par",
          FT_UINT8, BASE_DEC, VALS(gsm_map_disc_par_vals), 0,
          NULL, HFILL }},
      { &hf_gsm_map_dlci,
        { "DLCI", "gsm_map.dlci",
          FT_UINT8, BASE_DEC, NULL, 0,
          "Data Link Connection Indicator", HFILL }},
      { &hf_gsm_apn_str,
        { "APN", "gsm_map.apn_str",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},
      { &hf_gsm_map_ericsson_locationInformation_rat,
        { "RAT", "gsm_map.ericsson.locationInformation.rat",
          FT_UINT8, BASE_DEC, VALS(gsm_map_ericsson_locationInformation_rat_vals), 0,
          "Radio Access Technology", HFILL }},
      { &hf_gsm_map_ericsson_locationInformation_lac,
        { "LAC", "gsm_map.ericsson.locationInformation.lac",
          FT_UINT16, BASE_DEC_HEX, NULL, 0,
          "Location Area Code", HFILL }},
      { &hf_gsm_map_ericsson_locationInformation_ci,
        { "CI", "gsm_map.ericsson.locationInformation.ci",
          FT_UINT16, BASE_DEC_HEX, NULL, 0,
          "Cell Identity", HFILL }},
      { &hf_gsm_map_ericsson_locationInformation_sac,
        { "SAC", "gsm_map.ericsson.locationInformation.sac",
          FT_UINT16, BASE_DEC_HEX, NULL, 0,
          "Service Area Code", HFILL }},
      { &hf_gsm_map_ussd_string,
        { "USSD String", "gsm_map.ussd_string",
          FT_STRING, BASE_NONE, NULL, 0,
          NULL, HFILL }},
    { &hf_gsm_map_spare_bits,
        { "Spare bit(s)", "gsm_map.spare_bits",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_gsm_map_qos_signalling_ind,
    { "Signalling indication", "gsm_map.qos.signalling_ind",
          FT_BOOLEAN, 8, TFS(&gsm_map_qos_signalling_ind_value), 0x10,
          NULL, HFILL }
    },
    { &hf_gsm_map_qos_source_stat_desc,
    { "Source statistics description", "gsm_map.qos.source_stat_desc",
          FT_UINT8, BASE_DEC, NULL, 0x0f,
          NULL, HFILL }
    },
    { &hf_gsm_map_qos_max_bitrate_upl_ext,
    { "Maximum bitrate for uplink (extended)", "gsm_map.qos.max_bitrate_upl_ext",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_gsm_map_qos_max_bitrate_downl_ext,
    { "Maximum bitrate for downlink (extended)", "gsm_map.qos.max_bitrate_downl_ext",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_gsm_map_qos_guar_bitrate_upl_ext,
    { "Guaranteed bitrate for uplink (extended)", "gsm_map.qos.guar_bitrate_upl_ext",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_gsm_map_qos_guar_bitrate_downl_ext,
    { "Guaranteed bitrate for downlink (extended)", "gsm_map.qos.guar_bitrate_downl_ext",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
/*
    { &hf_gsm_map_qos_max_bitrate_upl_ext2,
    { "Maximum bitrate for uplink (extended-2)", "gsm_map.qos.max_bitrate_upl_ext2",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_gsm_map_qos_max_bitrate_downl_ext2,
    { "Maximum bitrate for downlink (extended-2)", "gsm_map.qos.max_bitrate_downl_ext2",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_gsm_map_qos_guar_bitrate_upl_ext2,
    { "Guaranteed bitrate for uplink (extended-2)", "gsm_map.qos.guar_bitrate_upl_ext2",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
    { &hf_gsm_map_qos_guar_bitrate_downl_ext2,
    { "Guaranteed bitrate for downlink (extended-2)", "gsm_map.qos.guar_bitrate_downl_ext2",
          FT_UINT8, BASE_DEC, NULL, 0x0,
          NULL, HFILL }
    },
    */
    { &hf_gsm_map_earp_pvi,
    { "PVI Pre-emption Vulnerability", "gsm_map.EARP_pre_emption_par_vulnerability",
              FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x01,
              NULL, HFILL }
    },
    { &hf_gsm_map_earp_pl,
    { "PL Priority Level", "gsm_map.EARP_priority_level",
              FT_UINT8, BASE_DEC, NULL, 0x3C,
              NULL, HFILL }
    },
    { &hf_gsm_map_earp_pci,
    { "PCI Pre-emption Capability", "gsm_map.EARP_pre_emption_Capability",
            FT_BOOLEAN, 8, TFS(&tfs_disabled_enabled), 0x40,
            NULL, HFILL }
    },

#include "packet-gsm_map-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_gsm_map,
    &ett_gsm_map_InvokeId,
    &ett_gsm_map_InvokePDU,
    &ett_gsm_map_ReturnResultPDU,
    &ett_gsm_map_ReturnErrorPDU,
    &ett_gsm_map_ReturnResult_result,
    &ett_gsm_map_ReturnError_result,
    &ett_gsm_map_GSMMAPPDU,
    &ett_gsm_map_ext_qos_subscribed,
    &ett_gsm_map_pdptypenumber,
    &ett_gsm_map_RAIdentity,
    &ett_gsm_map_LAIFixedLength,
    &ett_gsm_map_isdn_address_string,
    &ett_gsm_map_geo_desc,
    &ett_gsm_map_LongSignalInfo,
    &ett_gsm_map_RadioResourceInformation,
    &ett_gsm_map_MSNetworkCapability,
    &ett_gsm_map_MSRadioAccessCapability,
    &ett_gsm_map_externalsignalinfo,
    &ett_gsm_map_cbs_data_coding,
    &ett_gsm_map_GlobalCellId,
    &ett_gsm_map_GeographicalInformation,
    &ett_gsm_map_apn_str,
    &ett_gsm_map_LocationNumber,
    &ett_gsm_map_ericsson_locationInformation,
    &ett_gsm_map_extension_data,
    &ett_gsm_map_tbcd_digits,
    &ett_gsm_map_ussd_string,
    &ett_gsm_map_ext2_qos_subscribed,
    &ett_gsm_map_ext3_qos_subscribed,
    &ett_gsm_map_e_utranCellGlobalIdentity,
    &ett_gsm_map_TA_id,
    &ett_gsm_map_GeodeticInformation,

#include "packet-gsm_map-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_gsm_map_unknown_sequence3, { "gsm_map.unknown.sequence3", PI_UNDECODED, PI_ERROR, "Unknown or not implemented [3] sequence", EXPFILL }},
     { &ei_gsm_map_unknown_sequence, { "gsm_map.unknown.sequence", PI_UNDECODED, PI_ERROR, "Unknown or not implemented sequence", EXPFILL }},
     { &ei_gsm_map_unknown_parameter, { "gsm_map.unknown.parameter", PI_UNDECODED, PI_ERROR, "Unknown or not implemented parameter", EXPFILL }},
     { &ei_gsm_map_unknown_invokeData, { "gsm_map.unknown.invokeData", PI_MALFORMED, PI_WARN, "Unknown invokeData", EXPFILL }},
     { &ei_gsm_map_undecoded, { "gsm_map.undecoded", PI_UNDECODED, PI_WARN, "If you want this decoded send the packet to Wireshark-dev", EXPFILL }},
  };

  static const enum_val_t application_context_modes[] = {
    {"Use Application Context from the trace", "Use application context from the trace", APPLICATON_CONTEXT_FROM_TRACE},
    {"Treat as AC 1", "Treat as AC 1", 1},
    {"Treat as AC 2", "Treat as AC 2", 2},
    {"Treat as AC 3", "Treat as AC 3", 3},
    {NULL, NULL, -1}
  };

  static tap_param gsm_map_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui gsm_map_stat_table = {
    REGISTER_STAT_GROUP_TELEPHONY_GSM,
    "MAP Operation",
    "gsm_map",
    "gsm_map,operation",
    gsm_map_stat_init,
    gsm_map_stat_packet,
    gsm_map_stat_reset,
    gsm_map_stat_free_table_item,
    NULL,
    sizeof(gsm_map_stat_fields)/sizeof(stat_tap_table_item), gsm_map_stat_fields,
    sizeof(gsm_map_stat_params)/sizeof(tap_param), gsm_map_stat_params,
    NULL,
    0
  };

  /* Register protocol */
  proto_gsm_map_ms = proto_gsm_map_dialogue = proto_gsm_map = proto_register_protocol(PNAME, PSNAME, PFNAME);

  map_handle = register_dissector("gsm_map", dissect_gsm_map, proto_gsm_map);
  register_dissector("gsm_map_sccp", dissect_gsm_map_sccp, proto_gsm_map);

  /* Register fields and subtrees */
  proto_register_field_array(proto_gsm_map, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_gsm_map = expert_register_protocol(proto_gsm_map);
  expert_register_field_array(expert_gsm_map, ei, array_length(ei));

  register_dissector_table("gsm_map.v3.arg.opcode", "GSM_MAP V3 Arg Opcodes", proto_gsm_map, FT_UINT8, BASE_DEC);
  register_dissector_table("gsm_map.v3.res.opcode", "GSM_MAP V3 Res Opcodes", proto_gsm_map, FT_UINT8, BASE_DEC);

  map_prop_arg_opcode_table = register_dissector_table("gsm_map.prop.arg.opcode", "GSM_MAP Proprietary Arg Opcodes", proto_gsm_map, FT_UINT8, BASE_DEC);
  map_prop_res_opcode_table = register_dissector_table("gsm_map.prop.res.opcode", "GSM_MAP Proprietary Res Opcodes", proto_gsm_map, FT_UINT8, BASE_DEC);
  map_prop_err_opcode_table = register_dissector_table("gsm_map.prop.err.opcode", "GSM_MAP Proprietary Err Opcodes", proto_gsm_map, FT_UINT8, BASE_DEC);

  gsm_map_tap = register_tap("gsm_map");

#include "packet-gsm_map-dis-tab.c"
  oid_add_from_string("ericsson-gsm-Map-Ext","1.2.826.0.1249.58.1.0" );
  oid_add_from_string("accessTypeNotAllowed-id","1.3.12.2.1107.3.66.1.2");
  /*oid_add_from_string("map-ac networkLocUp(1) version3(3)","0.4.0.0.1.0.1.3" );
   *
   * Register our configuration options, particularly our ssn:s
   * Set default SSNs
   */
  range_convert_str(wmem_epan_scope(), &global_ssn_range, "6-9,145,148-150", MAX_SSN);

  gsm_map_module = prefs_register_protocol(proto_gsm_map, proto_reg_handoff_gsm_map);

  prefs_register_range_preference(gsm_map_module, "tcap.ssn", "TCAP SSNs",
                                  "TCAP Subsystem numbers used for GSM MAP",
                                  &global_ssn_range, MAX_SSN);

  prefs_register_enum_preference(gsm_map_module, "application.context.version",
                                  "Application context version",
                                  "How to treat Application context",
                                  &pref_application_context_version, application_context_modes, APPLICATON_CONTEXT_FROM_TRACE);

  prefs_register_bool_preference(gsm_map_module, "ericsson.proprietary.extensions",
                                  "Dissect Ericsson proprietary extensions",
                                  "When enabled, dissector will use the non 3GPP standard extensions from Ericsson (that can override the standard ones)",
                                  &pref_ericsson_proprietary_ext);

  register_stat_tap_table_ui(&gsm_map_stat_table);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
