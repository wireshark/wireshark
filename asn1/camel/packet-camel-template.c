/* packet-camel-template.c
 * Routines for Camel
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Copyright 2005, Olivier Jacques <olivier.jacques@hp.com>
 * Copyright 2005, Javier Acuna <javier.acuna@sixbell.com>
 * Updated to ETSI TS 129 078 V6.4.0 (2004-3GPP TS 29.078 version 6.4.0 Release 6 1 12)
 * Copyright 2005-2010, Anders Broman <anders.broman@ericsson.com>
 * Updated to 3GPP TS 29.078 version 7.3.0 Release 7 (2006-06)
 * Built from the gsm-map dissector Copyright 2004, Anders Broman <anders.broman@ericsson.com>
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
 * References: ETSI 300 374
 */
/*
 * Indentation logic: this file is indented with 2 spaces indentation.
 *                    there are no tabs.
 */
#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/tap.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include <string.h>

#include "packet-ber.h"
#include "packet-camel.h"
#include "packet-q931.h"
#include "packet-e164.h"
#include "packet-isup.h"
#include "packet-gsm_map.h"
#include "packet-gsm_a_common.h"
#include "packet-inap.h"
#include "packet-tcap.h"
#include <epan/camel-persistentdata.h>
#include <epan/tcap-persistentdata.h>

#define PNAME  "Camel"
#define PSNAME "CAMEL"
#define PFNAME "camel"

/* Initialize the protocol and registered fields */
static int proto_camel = -1;
int date_format = 1; /*assume european date format */
int camel_tap = -1;
/* Global variables */
static guint32 opcode=0;
static guint32 errorCode=0;
static guint32 camel_ver = 0;
/* ROSE context */
static rose_ctx_t camel_rose_ctx;

static int hf_digit = -1;
static int hf_camel_extension_code_local = -1;
static int hf_camel_error_code_local = -1;
static int hf_camel_cause_indicator = -1;
static int hf_camel_PDPTypeNumber_etsi = -1;
static int hf_camel_PDPTypeNumber_ietf = -1;
static int hf_camel_PDPAddress_IPv4 = -1;
static int hf_camel_PDPAddress_IPv6 = -1;
static int hf_camel_cellGlobalIdOrServiceAreaIdFixedLength = -1;
static int hf_camel_RP_Cause = -1;
static int hf_camel_CAMEL_AChBillingChargingCharacteristics = -1;
static int hf_camel_CAMEL_FCIBillingChargingCharacteristics = -1;
static int hf_camel_CAMEL_FCIGPRSBillingChargingCharacteristics = -1;
static int hf_camel_CAMEL_FCISMSBillingChargingCharacteristics = -1;
static int hf_camel_CAMEL_SCIBillingChargingCharacteristics = -1;
static int hf_camel_CAMEL_SCIGPRSBillingChargingCharacteristics = -1;
static int hf_camel_CAMEL_CallResult = -1;

/* Used by camel-persistentdata.c */
int hf_camelsrt_SessionId=-1;
int hf_camelsrt_RequestNumber=-1;
int hf_camelsrt_Duplicate=-1;
int hf_camelsrt_RequestFrame=-1;
int hf_camelsrt_ResponseFrame=-1;
int hf_camelsrt_DeltaTime=-1;
int hf_camelsrt_SessionTime=-1;
int hf_camelsrt_DeltaTime31=-1;
int hf_camelsrt_DeltaTime75=-1;
int hf_camelsrt_DeltaTime65=-1;
int hf_camelsrt_DeltaTime22=-1;
int hf_camelsrt_DeltaTime35=-1;
int hf_camelsrt_DeltaTime80=-1;

#include "packet-camel-hf.c"

static struct camelsrt_info_t * gp_camelsrt_info;

/* Forward declarations */
static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);
static int dissect_camel_CAMEL_AChBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_camel_CAMEL_AChBillingChargingCharacteristicsV2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_camel_CAMEL_CallResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

gboolean gcamel_HandleSRT=FALSE;
extern gboolean gcamel_PersistentSRT;
extern gboolean gcamel_DisplaySRT;

/* Initialize the subtree pointers */
static gint ett_camel = -1;
static gint ett_camelisup_parameter = -1;
static gint ett_camel_AccessPointName = -1;
static gint ett_camel_pdptypenumber = -1;
static gint ett_camel_cause = -1;
static gint ett_camel_RPcause = -1;
static gint ett_camel_stat = -1;
static gint ett_camel_calledpartybcdnumber = -1;
static gint ett_camel_callingpartynumber = -1;
static gint ett_camel_locationnumber = -1;

#include "packet-camel-ett.c"


/* Preference settings default */
#define MAX_SSN 254
static range_t *global_ssn_range;
static dissector_handle_t  camel_handle;
static dissector_handle_t  camel_v1_handle;
static dissector_handle_t  camel_v2_handle;

/* Global variables */

static int application_context_version;
static guint8 PDPTypeOrganization;
static guint8 PDPTypeNumber;
const char *camel_obj_id = NULL;
gboolean is_ExtensionField =FALSE;

static int camel_opcode_type;
#define CAMEL_OPCODE_INVOKE        1
#define CAMEL_OPCODE_RETURN_RESULT 2
#define CAMEL_OPCODE_RETURN_ERROR  3
#define CAMEL_OPCODE_REJECT        4

static const value_string camel_Component_vals[] = {
  {   1, "invoke" },
  {   2, "returnResultLast" },
  {   3, "returnError" },
  {   4, "reject" },
  { 0, NULL }
};

static const true_false_string camel_extension_value = {
  "No Extension",
  "Extension"
};
#define EUROPEAN_DATE 1
#define AMERICAN_DATE 2
#define CAMEL_DATE_AND_TIME_LEN 20 /* 2*5 + 4 + 5 + 1 (HH:MM:SS;mm/dd/yyyy) */

static const enum_val_t date_options[] = {
  { "european",         "DD/MM/YYYY",       EUROPEAN_DATE },
  { "american",        "MM/DD/YYYY",        AMERICAN_DATE },
  { NULL, NULL, 0 }
};

static const value_string digit_value[] = {
    { 0,  "0"},
    { 1,  "1"},
    { 2,  "2"},
    { 3,  "3"},
    { 4,  "4"},
    { 5,  "5"},
    { 6,  "6"},
    { 7,  "7"},
    { 8,  "8"},
    { 9,  "9"},
    { 10, "spare"},
    { 11, "spare"},
    { 12, "spare"},
    { 13, "spare"},
    { 0,  NULL}};


static const value_string camel_nature_of_addr_indicator_values[] = {
  {   0x00,  "unknown" },
  {   0x01,  "International Number" },
  {   0x02,  "National Significant Number" },
  {   0x03,  "Network Specific Number" },
  {   0x04,  "Subscriber Number" },
  {   0x05,  "Reserved" },
  {   0x06,  "Abbreviated Number" },
  {   0x07,  "Reserved for extension" },
  { 0, NULL }
};
static const value_string camel_number_plan_values[] = {
  {   0x00,  "unknown" },
  {   0x01,  "ISDN/Telephony Numbering (Rec ITU-T E.164)" },
  {   0x02,  "spare" },
  {   0x03,  "Data Numbering (ITU-T Rec. X.121)" },
  {   0x04,  "Telex Numbering (ITU-T Rec. F.69)" },
  {   0x05,  "spare" },
  {   0x06,  "Land Mobile Numbering (ITU-T Rec. E.212)" },
  {   0x07,  "spare" },
  {   0x08,  "National Numbering" },
  {   0x09,  "Private Numbering" },
  {   0x0f,  "Reserved for extension" },
  { 0, NULL }
};

/* End includes from old" packet-camel.c */

static const value_string camel_RP_Cause_values[] = {
  { 1, "Unassigned (unallocated) number" },
  { 8, "Operator determined barring" },
  { 10, "Call barred" },
  { 11, "Reserved" },
  { 21, "Short message transfer rejected" },
  { 27, "Destination out of order" },
  { 28, "Unidentified subscriber" },
  { 29, "Facility Rejected" },
  { 30, "Unknown subscriber" },
  { 38, "Network out of order" },
  { 41, "Temporary failure" },
  { 42, "Congestion" },
  { 47, "Resources unavailable, unspecified" },
  { 50, "Requested facility not subscribed" },
  { 69, "Requested facility not implemented" },
  { 81, "Invalid short message transfer reference value" },
  { 95, "Semantically incorrect message" },
  { 96, "Invalid mandatory information" },
  { 97, " Message Type non-existent or not implemented" },
  { 98, "Message not compatible with short message protocol state" },
  { 99, "Information element non existent or not implemented" },
  { 111, "Protocol error, unspecified" },
  { 127, "Interworking, unspecified" },
  { 22,"Memory capacity exceeded" },
  { 0, NULL }
};

static const value_string camel_holdTreatmentIndicator_values[] = {
  {   0x01,  "acceptHoldRequest" },
  {   0x02,  "rejectHoldRequest" },
  { 0, NULL }
};
static const value_string camel_cwTreatmentIndicator_values[] = {
  {   0x01,  "acceptCw" },
  {   0x02,  "rejectCw" },
  { 0, NULL }
};
static const value_string camel_ectTreatmentIndicator_values[] = {
  {   0x01,  "acceptEctRequest" },
  {   0x02,  "rejectEctRequest" },
  { 0, NULL }
};

#include "packet-camel-val.h"

#include "packet-camel-table.c"

static char camel_number_to_char(int number)
{
   if (number < 10)
   return (char) (number + 48 ); /* this is ASCII specific */
   else
   return (char) (number + 55 );
}

/*
 * 24.011 8.2.5.4
 */
static guint8
dissect_RP_cause_ie(tvbuff_t *tvb, guint32 offset, _U_ guint len,
		    proto_tree *tree, int hf_cause_value, guint8 *cause_value)
{
  guint8	oct;
  guint32	curr_offset;
  static char a_bigbuf[1024];

  curr_offset = offset;
  oct = tvb_get_guint8(tvb, curr_offset);

  *cause_value = oct & 0x7f;

  other_decode_bitfield_value(a_bigbuf, oct, 0x7f, 8);
  proto_tree_add_uint_format(tree, hf_cause_value,
			     tvb, curr_offset, 1, *cause_value,
			     "%s : %s",
			     a_bigbuf,
			     val_to_str(*cause_value, camel_RP_Cause_values,
					"Unknown Cause (%u), treated as (41) \"Temporary failure\" for MO-SMS or (111) \"Protocol error,unspecified\" for MT-SMS"));
  curr_offset++;

  if ((oct & 0x80)) {
    oct = tvb_get_guint8(tvb, curr_offset);
    proto_tree_add_uint_format(tree, hf_cause_value,
			       tvb, curr_offset, 1, oct,
			       "Diagnostic : %u", oct);
    curr_offset++;
  }
  return(curr_offset - offset);
}

static int dissect_camel_InitialDPArgExtensionV2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

#include "packet-camel-fn.c"

#include "packet-camel-table2.c"


static guint8 camel_pdu_type = 0;
static guint8 camel_pdu_size = 0;


static int
dissect_camel_camelPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_,proto_tree *tree, int hf_index) {

    char *version_ptr;
    struct tcap_private_t * p_private_tcap;

    opcode = 0;
    application_context_version = 0;
    if (actx->pinfo->private_data != NULL){
        p_private_tcap=actx->pinfo->private_data;

        if (p_private_tcap->acv==TRUE ){
            version_ptr = strrchr(p_private_tcap->oid,'.');
            if (version_ptr)
                application_context_version = atoi(version_ptr+1);
        }
        gp_camelsrt_info->tcap_context=p_private_tcap->context;
        if (p_private_tcap->context)
            gp_camelsrt_info->tcap_session_id = ( (struct tcaphash_context_t *) (p_private_tcap->context))->session_id;
    }

    camel_pdu_type = tvb_get_guint8(tvb, offset)&0x0f;
    /* Get the length and add 2 */
    camel_pdu_size = tvb_get_guint8(tvb, offset+1)+2;

    /* Populate the info column with PDU type*/
    col_add_str(actx->pinfo->cinfo, COL_INFO, val_to_str(camel_pdu_type, camel_Component_vals, "Unknown Camel (%u)"));
    col_append_str(actx->pinfo->cinfo, COL_INFO, " ");

    is_ExtensionField =FALSE;
    offset = dissect_camel_ROS(TRUE, tvb, offset, actx, tree, hf_index);

    return offset;
}

static void
dissect_camel_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  proto_item    *item=NULL;
  proto_tree    *tree=NULL;
  proto_item  *stat_item=NULL;
  proto_tree  *stat_tree=NULL;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Camel-v1");

  camel_ver = 1;

  /* create display subtree for the protocol */
  if(parent_tree){
     item = proto_tree_add_item(parent_tree, proto_camel, tvb, 0, -1, ENC_NA);
     tree = proto_item_add_subtree(item, ett_camel);
  }
  /* camelsrt reset counter, and initialise global pointer
     to store service response time related data */
  gp_camelsrt_info=camelsrt_razinfo();

  dissect_camel_camelPDU(FALSE, tvb, 0, &asn1_ctx , tree, -1);

  /* If a Tcap context is associated to this transaction */
  if (gcamel_HandleSRT &&
      gp_camelsrt_info->tcap_context ) {
    if (gcamel_DisplaySRT && tree) {
      stat_item = proto_tree_add_text(tree, tvb, 0, 0, "Stat");
      stat_tree = proto_item_add_subtree(stat_item, ett_camel_stat);
    }
    camelsrt_call_matching(tvb, pinfo, stat_tree, gp_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, gp_camelsrt_info);
  }

}

static void
dissect_camel_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  proto_item    *item=NULL;
  proto_tree    *tree=NULL;
  proto_item  *stat_item=NULL;
  proto_tree  *stat_tree=NULL;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Camel-v2");

  camel_ver = 2;

  /* create display subtree for the protocol */
  if(parent_tree){
     item = proto_tree_add_item(parent_tree, proto_camel, tvb, 0, -1, ENC_NA);
     tree = proto_item_add_subtree(item, ett_camel);
  }
  /* camelsrt reset counter, and initialise global pointer
     to store service response time related data */
  gp_camelsrt_info=camelsrt_razinfo();

  dissect_camel_camelPDU(FALSE, tvb, 0, &asn1_ctx , tree, -1);

  /* If a Tcap context is associated to this transaction */
  if (gcamel_HandleSRT &&
      gp_camelsrt_info->tcap_context ) {
    if (gcamel_DisplaySRT && tree) {
      stat_item = proto_tree_add_text(tree, tvb, 0, 0, "Stat");
      stat_tree = proto_item_add_subtree(stat_item, ett_camel_stat);
    }
    camelsrt_call_matching(tvb, pinfo, stat_tree, gp_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, gp_camelsrt_info);
  }

}

static void
dissect_camel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  proto_item    *item=NULL;
  proto_tree    *tree=NULL;
  proto_item  *stat_item=NULL;
  proto_tree  *stat_tree=NULL;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Camel");

  /* Unknown camel version */
  camel_ver = 0;

  /* create display subtree for the protocol */
  if(parent_tree){
     item = proto_tree_add_item(parent_tree, proto_camel, tvb, 0, -1, ENC_NA);
     tree = proto_item_add_subtree(item, ett_camel);
  }
  /* camelsrt reset counter, and initialise global pointer
     to store service response time related data */
  gp_camelsrt_info=camelsrt_razinfo();
  dissect_camel_camelPDU(FALSE, tvb, 0, &asn1_ctx , tree, -1);

  /* If a Tcap context is associated to this transaction */
  if (gcamel_HandleSRT &&
      gp_camelsrt_info->tcap_context ) {
    if (gcamel_DisplaySRT && tree) {
      stat_item = proto_tree_add_text(tree, tvb, 0, 0, "Stat");
      stat_tree = proto_item_add_subtree(stat_item, ett_camel_stat);
    }
    camelsrt_call_matching(tvb, pinfo, stat_tree, gp_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, gp_camelsrt_info);
  }
}

/*--- proto_reg_handoff_camel ---------------------------------------*/
static void range_delete_callback(guint32 ssn)
{
  if (ssn) {
    delete_itu_tcap_subdissector(ssn, camel_handle);
  }
}

static void range_add_callback(guint32 ssn)
{
  if (ssn) {
    add_itu_tcap_subdissector(ssn, camel_handle);
  }
}

void proto_reg_handoff_camel(void) {
  static gboolean camel_prefs_initialized = FALSE;
  static range_t *ssn_range;

  if (!camel_prefs_initialized) {

    camel_prefs_initialized = TRUE;
    camel_handle = find_dissector("camel");
    camel_v1_handle = find_dissector("camel-v1");
    camel_v2_handle = find_dissector("camel-v2");


    register_ber_oid_dissector_handle("0.4.0.0.1.0.50.0",camel_v1_handle, proto_camel, "CAP-v1-gsmSSF-to-gsmSCF-AC" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.50.1",camel_v2_handle, proto_camel, "CAP-v2-gsmSSF-to-gsmSCF-AC" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.51.1",camel_v2_handle, proto_camel, "CAP-v2-assist-gsmSSF-to-gsmSCF-AC" );
    register_ber_oid_dissector_handle("0.4.0.0.1.0.52.1",camel_v2_handle, proto_camel, "CAP-v2-gsmSRF-to-gsmSCF-AC" );
    register_ber_oid_dissector_handle("0.4.0.0.1.21.3.50",camel_handle, proto_camel, "cap3-gprssf-scfAC" );
    register_ber_oid_dissector_handle("0.4.0.0.1.21.3.51",camel_handle, proto_camel, "cap3-gsmscf-gprsssfAC" );
    register_ber_oid_dissector_handle("0.4.0.0.1.21.3.61",camel_handle, proto_camel, "cap3-sms-AC" );
    register_ber_oid_dissector_handle("0.4.0.0.1.23.3.4",camel_handle, proto_camel, "capssf-scfGenericAC" );
    register_ber_oid_dissector_handle("0.4.0.0.1.23.3.61",camel_handle, proto_camel, "cap4-sms-AC" );


#include "packet-camel-dis-tab.c"
  } else {
    range_foreach(ssn_range, range_delete_callback);
    g_free(ssn_range);
  }

  ssn_range = range_copy(global_ssn_range);

  range_foreach(ssn_range, range_add_callback);

}

void proto_register_camel(void) {
  module_t *camel_module;
  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_camel_extension_code_local,
      { "local", "camel.extension_code_local",
        FT_INT32, BASE_DEC, NULL, 0,
        "Extension local code", HFILL }},
	{ &hf_camel_error_code_local,
      { "local", "camel.error_code_local",
        FT_INT32, BASE_DEC, VALS(camel_err_code_string_vals), 0,
        "ERROR code", HFILL }},
    { &hf_camel_cause_indicator, /* Currently not enabled */
      { "Cause indicator",  "camel.cause_indicator",
        FT_UINT8, BASE_DEC|BASE_EXT_STRING, &q850_cause_code_vals_ext, 0x7f,
        NULL, HFILL }},
    { &hf_digit,
      { "Digit Value",  "camel.digit_value",
        FT_UINT8, BASE_DEC, VALS(digit_value), 0, NULL, HFILL }},
    { &hf_camel_PDPTypeNumber_etsi,
      { "ETSI defined PDP Type Value",  "camel.PDPTypeNumber_etsi",
        FT_UINT8, BASE_HEX, VALS(gsm_map_etsi_defined_pdp_vals), 0,
        NULL, HFILL }},
    { &hf_camel_PDPTypeNumber_ietf,
      { "IETF defined PDP Type Value",  "camel.PDPTypeNumber_ietf",
        FT_UINT8, BASE_HEX, VALS(gsm_map_ietf_defined_pdp_vals), 0,
        NULL, HFILL }},
    { &hf_camel_PDPAddress_IPv4,
      { "PDPAddress IPv4",  "camel.PDPAddress_IPv4",
        FT_IPv4, BASE_NONE, NULL, 0,
        "IPAddress IPv4", HFILL }},
    { &hf_camel_PDPAddress_IPv6,
      { "PDPAddress IPv6",  "camel.PDPAddress_IPv6",
        FT_IPv6, BASE_NONE, NULL, 0,
        "IPAddress IPv6", HFILL }},
    { &hf_camel_cellGlobalIdOrServiceAreaIdFixedLength,
      { "CellGlobalIdOrServiceAreaIdFixedLength", "camel.CellGlobalIdOrServiceAreaIdFixedLength",
        FT_BYTES, BASE_NONE, NULL, 0,
        "LocationInformationGPRS/CellGlobalIdOrServiceAreaIdOrLAI", HFILL }},
    { &hf_camel_RP_Cause,
      { "RP Cause",  "camel.RP_Cause",
        FT_UINT8, BASE_DEC, NULL, 0,
	"RP Cause Value", HFILL }},

    { &hf_camel_CAMEL_AChBillingChargingCharacteristics,
      { "CAMEL-AChBillingChargingCharacteristics", "camel.CAMEL_AChBillingChargingCharacteristics",
        FT_UINT32, BASE_DEC,  VALS(camel_CAMEL_AChBillingChargingCharacteristics_vals), 0,
        NULL, HFILL }},

    { &hf_camel_CAMEL_FCIBillingChargingCharacteristics,
      { "CAMEL-FCIBillingChargingCharacteristics", "camel.CAMEL_FCIBillingChargingCharacteristics",
        FT_UINT32, BASE_DEC, VALS(camel_CAMEL_FCIBillingChargingCharacteristics_vals), 0,
        NULL, HFILL }},

    { &hf_camel_CAMEL_FCIGPRSBillingChargingCharacteristics,
      { "CAMEL-FCIGPRSBillingChargingCharacteristics", "camel.CAMEL_FCIGPRSBillingChargingCharacteristics",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},

    { &hf_camel_CAMEL_FCISMSBillingChargingCharacteristics,
      { "CAMEL-FCISMSBillingChargingCharacteristics", "camel.CAMEL_FCISMSBillingChargingCharacteristics",
        FT_UINT32, BASE_DEC, VALS(camel_CAMEL_FCISMSBillingChargingCharacteristics_vals), 0,
        NULL, HFILL }},

    { &hf_camel_CAMEL_SCIBillingChargingCharacteristics,
      { "CAMEL-SCIBillingChargingCharacteristics", "camel.CAMEL_SCIBillingChargingCharacteristics",
        FT_UINT32, BASE_DEC, VALS(camel_CAMEL_SCIBillingChargingCharacteristics_vals), 0,
        NULL, HFILL }},

    { &hf_camel_CAMEL_SCIGPRSBillingChargingCharacteristics,
      { "CAMEL-SCIGPRSBillingChargingCharacteristics", "camel.CAMEL_SCIGPRSBillingChargingCharacteristics",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CAMEL-FSCIGPRSBillingChargingCharacteristics", HFILL }},

    { &hf_camel_CAMEL_CallResult,
      { "CAMEL-CAMEL_CallResult", "camel.CAMEL_CallResult",
        FT_UINT32, BASE_DEC, VALS(camel_CAMEL_CallResult_vals), 0,
        "CAMEL-CallResult", HFILL }},

  /* Camel Service Response Time */
    { &hf_camelsrt_SessionId,
      { "Session Id",
        "camel.srt.session_id",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_camelsrt_RequestNumber,
      { "Request Number",
        "camel.srt.request_number",
        FT_UINT64, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_camelsrt_Duplicate,
      { "Request Duplicate",
        "camel.srt.duplicate",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        NULL, HFILL }
    },
    { &hf_camelsrt_RequestFrame,
      { "Requested Frame",
        "camel.srt.reqframe",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "SRT Request Frame", HFILL }
    },
    { &hf_camelsrt_ResponseFrame,
      { "Response Frame",
        "camel.srt.rspframe",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "SRT Response Frame", HFILL }
    },
    { &hf_camelsrt_DeltaTime,
      { "Service Response Time",
        "camel.srt.deltatime",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between Request and Response", HFILL }
    },
    { &hf_camelsrt_SessionTime,
      { "Session duration",
        "camel.srt.sessiontime",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "Duration of the TCAP session", HFILL }
    },
    { &hf_camelsrt_DeltaTime31,
      { "Service Response Time",
        "camel.srt.deltatime31",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between InitialDP and Continue", HFILL }
    },
    { &hf_camelsrt_DeltaTime65,
      { "Service Response Time",
        "camel.srt.deltatime65",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between InitialDPSMS and ContinueSMS", HFILL }
    },
    { &hf_camelsrt_DeltaTime75,
      { "Service Response Time",
        "camel.srt.deltatime75",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between InitialDPGPRS and ContinueGPRS", HFILL }
    },
    { &hf_camelsrt_DeltaTime35,
      { "Service Response Time",
        "camel.srt.deltatime35",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between ApplyCharginReport and ApplyCharging", HFILL }
    },
    { &hf_camelsrt_DeltaTime22,
      { "Service Response Time",
        "camel.srt.deltatime22",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between EventReport(Disconnect) and Release Call", HFILL }
    },
    { &hf_camelsrt_DeltaTime80,
      { "Service Response Time",
        "camel.srt.deltatime80",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "DeltaTime between EventReportGPRS and ContinueGPRS", HFILL }
    },

#ifdef REMOVED
#endif
#include "packet-camel-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_camel,
    &ett_camelisup_parameter,
    &ett_camel_AccessPointName,
    &ett_camel_pdptypenumber,
    &ett_camel_cause,
    &ett_camel_RPcause,
    &ett_camel_stat,
	&ett_camel_calledpartybcdnumber,
	&ett_camel_callingpartynumber,
	&ett_camel_locationnumber,

#include "packet-camel-ettarr.c"
  };
  /* Register protocol */
  proto_camel = proto_register_protocol(PNAME, PSNAME, PFNAME);

  register_dissector("camel", dissect_camel, proto_camel);
  register_dissector("camel-v1", dissect_camel_v1, proto_camel);
  register_dissector("camel-v2", dissect_camel_v2, proto_camel);

  proto_register_field_array(proto_camel, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  rose_ctx_init(&camel_rose_ctx);

  /* Register dissector tables */
  camel_rose_ctx.arg_local_dissector_table = register_dissector_table("camel.ros.local.arg",
                                                                      "CAMEL Operation Argument (local opcode)",
                                                                      FT_UINT32, BASE_HEX);
  camel_rose_ctx.res_local_dissector_table = register_dissector_table("camel.ros.local.res",
                                                                      "CAMEL Operation Result (local opcode)",
                                                                      FT_UINT32, BASE_HEX);
  camel_rose_ctx.err_local_dissector_table = register_dissector_table("camel.ros.local.err",
                                                                      "CAMEL Error (local opcode)",
                                                                      FT_UINT32, BASE_HEX);

  /* Register our configuration options, particularly our ssn:s */
  /* Set default SSNs */
  range_convert_str(&global_ssn_range, "6-9", MAX_SSN);

  camel_module = prefs_register_protocol(proto_camel, proto_reg_handoff_camel);

  prefs_register_enum_preference(camel_module, "date.format", "Date Format",
                                  "The date format: (DD/MM) or (MM/DD)",
                                  &date_format, date_options, FALSE);


  prefs_register_range_preference(camel_module, "tcap.ssn",
    "TCAP SSNs",
    "TCAP Subsystem numbers used for Camel",
    &global_ssn_range, MAX_SSN);

  prefs_register_bool_preference(camel_module, "srt",
				 "Service Response Time Analyse",
				 "Activate the analyse for Response Time",
				 &gcamel_HandleSRT);

  prefs_register_bool_preference(camel_module, "persistentsrt",
				 "Persistent stats for SRT",
				 "Statistics for Response Time",
				 &gcamel_PersistentSRT);

  /* Routine for statistic */
  register_init_routine(&camelsrt_init_routine);
  camel_tap=register_tap(PSNAME);
}

