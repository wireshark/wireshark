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

#include <stdlib.h>

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/oids.h>
#include <epan/tap.h>
#include <epan/srt_table.h>
#include <epan/stat_tap_ui.h>
#include <epan/asn1.h>
#include <epan/expert.h>

#include "packet-ber.h"
#include "packet-camel.h"
#include "packet-q931.h"
#include "packet-e164.h"
#include "packet-isup.h"
#include "packet-gsm_map.h"
#include "packet-gsm_a_common.h"
#include "packet-inap.h"
#include "packet-tcap.h"

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

/* When several Camel components are received in a single TCAP message,
   we have to use several buffers for the stored parameters
   because else this data are erased during TAP dissector call */
#define MAX_CAMEL_INSTANCE 10
static int camelsrt_global_current=0;
static struct camelsrt_info_t camelsrt_global_info[MAX_CAMEL_INSTANCE];

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

/* Used by persistent data */
static int hf_camelsrt_SessionId=-1;
static int hf_camelsrt_RequestNumber=-1;
static int hf_camelsrt_Duplicate=-1;
static int hf_camelsrt_RequestFrame=-1;
static int hf_camelsrt_ResponseFrame=-1;
static int hf_camelsrt_DeltaTime=-1;
static int hf_camelsrt_SessionTime=-1;
static int hf_camelsrt_DeltaTime31=-1;
static int hf_camelsrt_DeltaTime75=-1;
static int hf_camelsrt_DeltaTime65=-1;
static int hf_camelsrt_DeltaTime22=-1;
static int hf_camelsrt_DeltaTime35=-1;
static int hf_camelsrt_DeltaTime80=-1;

#include "packet-camel-hf.c"

static struct camelsrt_info_t * gp_camelsrt_info;

/* Forward declarations */
static int dissect_invokeData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);
static int dissect_returnResultData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);
static int dissect_returnErrorData(proto_tree *tree, tvbuff_t *tvb, int offset,asn1_ctx_t *actx);
static int dissect_camel_CAMEL_AChBillingChargingCharacteristics(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_camel_CAMEL_AChBillingChargingCharacteristicsV2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_camel_CAMEL_CallResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);
static int dissect_camel_EstablishTemporaryConnectionArgV2(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);

/* XXX - can we get rid of these and always do the SRT work? */
static gboolean gcamel_HandleSRT=FALSE;
static gboolean gcamel_PersistentSRT=FALSE;
static gboolean gcamel_DisplaySRT=FALSE;
gboolean gcamel_StatSRT=FALSE;

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
static gint ett_camel_additionalcallingpartynumber = -1;

#include "packet-camel-ett.c"

static expert_field ei_camel_unknown_invokeData = EI_INIT;
static expert_field ei_camel_unknown_returnResultData = EI_INIT;
static expert_field ei_camel_unknown_returnErrorData = EI_INIT;

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

/* Global hash tables*/
static GHashTable *srt_calls = NULL;
static guint32 camelsrt_global_SessionId=1;

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

const value_string  camelSRTtype_naming[]= {
  { CAMELSRT_SESSION,         "TCAP_Session" },
  { CAMELSRT_VOICE_INITIALDP, "InialDP/Continue" },
  { CAMELSRT_VOICE_ACR1,      "Slice1_ACR/ACH" },
  { CAMELSRT_VOICE_ACR2,      "Slice2_ACR/ACH" },
  { CAMELSRT_VOICE_ACR3,      "Slice3_ACR/ACH" },
  { CAMELSRT_VOICE_DISC,      "EvtRepBSCM/Release" },
  { CAMELSRT_SMS_INITIALDP,   "InitialDP/ContinueSMS" },
  { CAMELSRT_GPRS_INITIALDP,  "InitialDP/ContinueGPRS" },
  { CAMELSRT_GPRS_REPORT,     "EvtRepGPRS/ContinueGPRS" },
  { 0,NULL}
};

#if 0
static const true_false_string camel_extension_value = {
  "No Extension",
  "Extension"
};
#endif
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
  { 0,  NULL}

};


#if 0
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
#endif

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

/*
 * DEBUG fonctions
 */

#undef DEBUG_CAMELSRT
/* #define DEBUG_CAMELSRT */

#ifdef DEBUG_CAMELSRT
#include <stdio.h>
#include <stdarg.h>
static guint debug_level = 99;

static void dbg(guint level, char *fmt, ...) {
  va_list ap;

  if (level > debug_level) return;
  va_start(ap,fmt);
  vfprintf(stderr, fmt, ap);
  va_end(ap);
}
#endif

static void
camelstat_init(struct register_srt* srt _U_, GArray* srt_array, srt_gui_init_cb gui_callback, void* gui_data)
{
  srt_stat_table *camel_srt_table;
  gchar* tmp_str;
  guint32 i;

  camel_srt_table = init_srt_table("CAMEL Commands", NULL, srt_array, NB_CAMELSRT_CATEGORY, NULL, NULL, gui_callback, gui_data, NULL);
  for (i = 0; i < NB_CAMELSRT_CATEGORY; i++)
  {
    tmp_str = val_to_str_wmem(NULL,i,camelSRTtype_naming,"Unknown (%d)");
    init_srt_table_row(camel_srt_table, i, tmp_str);
    wmem_free(NULL, tmp_str);
  }
}

static gboolean
camelstat_packet(void *pcamel, packet_info *pinfo, epan_dissect_t *edt _U_, const void *psi)
{
  guint idx = 0;
  srt_stat_table *camel_srt_table;
  const struct camelsrt_info_t * pi=(const struct camelsrt_info_t *)psi;
  srt_data_t *data = (srt_data_t *)pcamel;
  int i;

  for (i=1; i<NB_CAMELSRT_CATEGORY; i++) {
    if ( pi->bool_msginfo[i] &&
         pi->msginfo[i].is_delta_time
         && pi->msginfo[i].request_available
         && !pi->msginfo[i].is_duplicate )
    {
      camel_srt_table = g_array_index(data->srt_array, srt_stat_table*, idx);
      add_srt_table_data(camel_srt_table, i, &pi->msginfo[i].req_time, pinfo);
    }
  } /* category */
  return TRUE;
}


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
  guint8 oct;
  guint32 curr_offset;

  curr_offset = offset;
  oct = tvb_get_guint8(tvb, curr_offset);

  *cause_value = oct & 0x7f;

  proto_tree_add_uint(tree, hf_cause_value, tvb, curr_offset, 1, oct);
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

/*
 * Functions needed for Hash-Table
 */

/* compare 2 keys */
static gint
camelsrt_call_equal(gconstpointer k1, gconstpointer k2)
{
  const struct camelsrt_call_info_key_t *key1 = (const struct camelsrt_call_info_key_t *) k1;
  const struct camelsrt_call_info_key_t *key2 = (const struct camelsrt_call_info_key_t *) k2;

  return (key1->SessionIdKey == key2->SessionIdKey) ;
}

/* calculate a hash key */
static guint
camelsrt_call_hash(gconstpointer k)
{
  const struct camelsrt_call_info_key_t *key = (const struct camelsrt_call_info_key_t *) k;
  return key->SessionIdKey;
}

/*
 * Find the dialog by Key and Time
 */
static struct camelsrt_call_t *
find_camelsrt_call(struct camelsrt_call_info_key_t *p_camelsrt_call_key)
{
  struct camelsrt_call_t *p_camelsrt_call = NULL;
  p_camelsrt_call = (struct camelsrt_call_t *)g_hash_table_lookup(srt_calls, p_camelsrt_call_key);

#ifdef DEBUG_CAMELSRT
  if(p_camelsrt_call) {
    dbg(10,"D%d ", p_camelsrt_call->session_id);
  } else {
    dbg(23,"Not in hash ");
  }
#endif

  return p_camelsrt_call;
}

/*
 * Initialize the data per call for the Service Response Time Statistics
 * Data are linked to a Camel operation in a TCAP transaction
 */
static void
raz_camelsrt_call (struct camelsrt_call_t *p_camelsrt_call)
{
  memset(p_camelsrt_call,0,sizeof(struct camelsrt_call_t));
}

/*
 * New record to create, to identify a new transaction
 */
static struct camelsrt_call_t *
new_camelsrt_call(struct camelsrt_call_info_key_t *p_camelsrt_call_key)
{
  struct camelsrt_call_info_key_t *p_new_camelsrt_call_key;
  struct camelsrt_call_t *p_new_camelsrt_call = NULL;

  /* Register the transaction in the hash table
     with the tcap transaction Id as main Key
     Once created, this entry will be updated later */

  p_new_camelsrt_call_key = wmem_new(wmem_file_scope(), struct camelsrt_call_info_key_t);
  p_new_camelsrt_call_key->SessionIdKey = p_camelsrt_call_key->SessionIdKey;
  p_new_camelsrt_call = wmem_new(wmem_file_scope(), struct camelsrt_call_t);
  raz_camelsrt_call(p_new_camelsrt_call);
  p_new_camelsrt_call->session_id = camelsrt_global_SessionId++;
#ifdef DEBUG_CAMELSRT
  dbg(10,"D%d ", p_new_camelsrt_call->session_id);
#endif
  /* store it */
  g_hash_table_insert(srt_calls, p_new_camelsrt_call_key, p_new_camelsrt_call);
  return p_new_camelsrt_call;
}

/*
 * Routine called when the TAP is initialized.
 * so hash table are (re)created
 */
static void
camelsrt_init_routine(void)
{
  /* create new hash-table for SRT */
  srt_calls = g_hash_table_new(camelsrt_call_hash, camelsrt_call_equal);
  /* Reset the session counter */
  camelsrt_global_SessionId=1;

  /* The Display of SRT is enable
   * 1) For wireshark only if Persistent Stat is enable
   * 2) For Tshark, if the SRT handling is enable
   */
  gcamel_DisplaySRT=gcamel_PersistentSRT || gcamel_HandleSRT&gcamel_StatSRT;
}

static void
camelsrt_cleanup_routine(void)
{
  /* free hash-table for SRT */
  g_hash_table_destroy(srt_calls);
}


/*
 * Update a record with the data of the Request
 */
static void
update_camelsrt_call(struct camelsrt_call_t *p_camelsrt_call, packet_info *pinfo,
                     guint msg_category)
{
  p_camelsrt_call->category[msg_category].req_num = pinfo->num;
  p_camelsrt_call->category[msg_category].rsp_num = 0;
  p_camelsrt_call->category[msg_category].responded = FALSE;
  p_camelsrt_call->category[msg_category].req_time = pinfo->abs_ts;
}

/*
 * Update the Camel session info, and close the session.
 * Then remove the associated context, if we do not have persistentSRT enable
 */
static void
camelsrt_close_call_matching(packet_info *pinfo,
                             struct camelsrt_info_t *p_camelsrt_info)
{
  struct camelsrt_call_t *p_camelsrt_call;
  struct camelsrt_call_info_key_t camelsrt_call_key;
  nstime_t delta;

  p_camelsrt_info->bool_msginfo[CAMELSRT_SESSION]=TRUE;
#ifdef DEBUG_CAMELSRT
  dbg(10,"\n Session end #%u\n", pinfo->num);
#endif
  /* look only for matching request, if matching conversation is available. */
  camelsrt_call_key.SessionIdKey = p_camelsrt_info->tcap_session_id;

#ifdef DEBUG_CAMELSRT
  dbg(11,"Search key %lu ",camelsrt_call_key.SessionIdKey);
#endif
  p_camelsrt_call = find_camelsrt_call(&camelsrt_call_key);
  if(p_camelsrt_call) {
#ifdef DEBUG_CAMELSRT
    dbg(12,"Found ");
#endif
    /* Calculate Service Response Time */
    nstime_delta(&delta, &pinfo->abs_ts, &p_camelsrt_call->category[CAMELSRT_SESSION].req_time);
    p_camelsrt_call->category[CAMELSRT_SESSION].responded = TRUE;
    p_camelsrt_info->msginfo[CAMELSRT_SESSION].request_available = TRUE;
    p_camelsrt_info->msginfo[CAMELSRT_SESSION].is_delta_time = TRUE;
    p_camelsrt_info->msginfo[CAMELSRT_SESSION].delta_time = delta; /* give it to tap */
    p_camelsrt_info->msginfo[CAMELSRT_SESSION].req_time = p_camelsrt_call->category[CAMELSRT_SESSION].req_time;

    if ( !gcamel_PersistentSRT ) {
      g_hash_table_remove(srt_calls, &camelsrt_call_key);
#ifdef DEBUG_CAMELSRT
      dbg(20,"remove hash ");
#endif
    } else {
#ifdef DEBUG_CAMELSRT
      dbg(20,"keep hash ");
#endif
    }
  } /* call reference found */
}

/*
 * Callback function for the TCAP dissector
 * This callback function is used to inform the camel layer, that the session
 * has been Closed or Aborted by a TCAP message without Camel component
 * So, we can close the context for camel session, and update the stats.
 */
static void
camelsrt_tcap_matching(tvbuff_t *tvb _U_, packet_info *pinfo,
                       proto_tree *tree _U_,
                       struct tcaphash_context_t *p_tcap_context)
{
  struct camelsrt_info_t *p_camelsrt_info;

#ifdef DEBUG_CAMELSRT
  dbg(11,"Camel_CallBack ");
#endif
  p_camelsrt_info=camelsrt_razinfo();

  p_camelsrt_info->tcap_context=p_tcap_context;
  if (p_tcap_context) {
#ifdef DEBUG_CAMELSRT
    dbg(11,"Close TCAP ");
#endif
    p_camelsrt_info->tcap_session_id = p_tcap_context->session_id;
    camelsrt_close_call_matching(pinfo, p_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, p_camelsrt_info);
  }
}

/*
 * Create the record identifiying the Camel session
 * As the Tcap session id given by the TCAP dissector is uniq, it will be
 * used as main key.
 */
static void
camelsrt_begin_call_matching(packet_info *pinfo,
                             struct camelsrt_info_t *p_camelsrt_info)
{
  struct camelsrt_call_t *p_camelsrt_call;
  struct camelsrt_call_info_key_t camelsrt_call_key;

  p_camelsrt_info->bool_msginfo[CAMELSRT_SESSION]=TRUE;

  /* prepare the key data */
  camelsrt_call_key.SessionIdKey = p_camelsrt_info->tcap_session_id;

  /* look up the request */
#ifdef DEBUG_CAMELSRT
  dbg(10,"\n Session begin #%u\n", pinfo->num);
  dbg(11,"Search key %lu ",camelsrt_call_key.SessionIdKey);
#endif
  p_camelsrt_call = (struct camelsrt_call_t *)g_hash_table_lookup(srt_calls, &camelsrt_call_key);
  if (p_camelsrt_call) {
    /* We have seen this request before -> do nothing */
#ifdef DEBUG_CAMELSRT
    dbg(22,"Already seen ");
#endif
  } else { /* p_camelsrt_call has not been found */
#ifdef DEBUG_CAMELSRT
    dbg(10,"New key %lu ",camelsrt_call_key.SessionIdKey);
#endif
    p_camelsrt_call = new_camelsrt_call(&camelsrt_call_key);
    p_camelsrt_call->tcap_context=(struct tcaphash_context_t *)p_camelsrt_info->tcap_context;
    update_camelsrt_call(p_camelsrt_call, pinfo,CAMELSRT_SESSION);

#ifdef DEBUG_CAMELSRT
    dbg(11,"Update Callback ");
#endif
    p_camelsrt_call->tcap_context->callback=camelsrt_tcap_matching;
  }
}

/*
 * Register the request, and try to find the response
 *
 */
static void
camelsrt_request_call_matching(tvbuff_t *tvb, packet_info *pinfo,
                               proto_tree *tree,
                               struct camelsrt_info_t *p_camelsrt_info,
                               guint srt_type )
{
  struct camelsrt_call_t *p_camelsrt_call;
  struct camelsrt_call_info_key_t camelsrt_call_key;
  proto_item *ti, *hidden_item;

#ifdef DEBUG_CAMELSRT
  dbg(10,"\n %s #%u\n", val_to_str_const(srt_type, camelSRTtype_naming, "Unk"),pinfo->num);
#endif

  /* look only for matching request, if matching conversation is available. */
  camelsrt_call_key.SessionIdKey = p_camelsrt_info->tcap_session_id;

#ifdef DEBUG_CAMELSRT
  dbg(11,"Search key %lu ", camelsrt_call_key.SessionIdKey);
#endif
  p_camelsrt_call = find_camelsrt_call(&camelsrt_call_key);
  if(p_camelsrt_call) {
#ifdef DEBUG_CAMELSRT
    dbg(12,"Found ");
#endif
    if (gcamel_DisplaySRT)
      proto_tree_add_uint(tree, hf_camelsrt_SessionId, tvb, 0,0, p_camelsrt_call->session_id);


    /* Hmm.. As there are several slices ApplyChargingReport/ApplyCharging
     * we will prepare the measurement for 3 slices with 3 categories */
    if (srt_type==CAMELSRT_VOICE_ACR1) {
      if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].req_num == 0) {
        srt_type=CAMELSRT_VOICE_ACR1;
      } else  if ( (p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].req_num == 0)
                   && (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num != 0)
                   && (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num < pinfo->num) ) {
        srt_type=CAMELSRT_VOICE_ACR2;
      } else  if ( (p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].req_num == 0)
                   && (p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num != 0)
                   && (p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num < pinfo->num) ) {
        srt_type=CAMELSRT_VOICE_ACR3;
      } else if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num != 0
                 && p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num > pinfo->num) {
        srt_type=CAMELSRT_VOICE_ACR1;
      } else  if ( p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num != 0
                   && p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num > pinfo->num) {
        srt_type=CAMELSRT_VOICE_ACR2;
      } else  if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num != 0
                  && p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].rsp_num > pinfo->num) {
        srt_type=CAMELSRT_VOICE_ACR3;
      }
#ifdef DEBUG_CAMELSRT
      dbg(70,"Request ACR %u ",srt_type);
      dbg(70,"ACR1 %u %u",p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].req_num, p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].rsp_num);
      dbg(70,"ACR2 %u %u",p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].req_num, p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].rsp_num);
      dbg(70,"ACR3 %u %u",p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].req_num, p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].rsp_num);
#endif
    } /* not ACR */
    p_camelsrt_info->bool_msginfo[srt_type]=TRUE;


    if (p_camelsrt_call->category[srt_type].req_num == 0) {
      /* We have not yet seen a request to that call, so this must be the first request
         remember its frame number. */
#ifdef DEBUG_CAMELSRT
      dbg(5,"Set reqlink #%u ", pinfo->num);
#endif
      update_camelsrt_call(p_camelsrt_call, pinfo, srt_type);
    } else {
      /* We have seen a request to this call - but was it *this* request? */
      if (p_camelsrt_call->category[srt_type].req_num != pinfo->num) {

        if (srt_type!=CAMELSRT_VOICE_DISC) {
          /* No, so it's a duplicate request. Mark it as such. */
#ifdef DEBUG_CAMELSRT
          dbg(21,"Display_duplicate with req %d ", p_camelsrt_call->category[srt_type].req_num);
#endif
          p_camelsrt_info->msginfo[srt_type].is_duplicate = TRUE;
          if (gcamel_DisplaySRT){
            hidden_item = proto_tree_add_uint(tree, hf_camelsrt_Duplicate, tvb, 0,0, 77);
                PROTO_ITEM_SET_HIDDEN(hidden_item);
          }

        } else {
          /* Ignore duplicate frame */
          if (pinfo->num > p_camelsrt_call->category[srt_type].req_num) {
            p_camelsrt_call->category[srt_type].req_num = pinfo->num;
#ifdef DEBUG_CAMELSRT
            dbg(5,"DISC Set reqlink #%u ", pinfo->num);
#endif
            update_camelsrt_call(p_camelsrt_call, pinfo, srt_type);
          } /* greater frame */
        } /* DISC */
      } /* req_num already seen */
    } /* req_num != 0 */

      /* add link to response frame, if available */
    if ( gcamel_DisplaySRT &&
         (p_camelsrt_call->category[srt_type].rsp_num != 0) &&
         (p_camelsrt_call->category[srt_type].req_num != 0) &&
         (p_camelsrt_call->category[srt_type].req_num == pinfo->num) ) {
#ifdef DEBUG_CAMELSRT
      dbg(20,"Display_framersplink %d ",p_camelsrt_call->category[srt_type].rsp_num);
#endif
      ti = proto_tree_add_uint_format(tree, hf_camelsrt_RequestFrame, tvb, 0, 0,
                                      p_camelsrt_call->category[srt_type].rsp_num,
                                      "Linked response %s in frame %u",
                                      val_to_str_const(srt_type, camelSRTtype_naming, "Unk"),
                                      p_camelsrt_call->category[srt_type].rsp_num);
      PROTO_ITEM_SET_GENERATED(ti);
    } /* frame valid */
  } /* call reference */
}

/*
 * Display the delta time between two messages in a field corresponding
 * to the category (hf_camelsrt_DeltaTimexx).
 */
static void
camelsrt_display_DeltaTime(proto_tree *tree, tvbuff_t *tvb, nstime_t *value_ptr,
                           guint category)
{
  proto_item *ti;

  if ( gcamel_DisplaySRT ) {
    switch(category) {
    case CAMELSRT_VOICE_INITIALDP:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime31, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;

    case CAMELSRT_VOICE_ACR1:
    case CAMELSRT_VOICE_ACR2:
    case CAMELSRT_VOICE_ACR3:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime22, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;

    case CAMELSRT_VOICE_DISC:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime35, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;

    case CAMELSRT_GPRS_INITIALDP:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime75, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;

    case CAMELSRT_GPRS_REPORT:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime80, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;

    case CAMELSRT_SMS_INITIALDP:
      ti = proto_tree_add_time(tree, hf_camelsrt_DeltaTime65, tvb, 0, 0, value_ptr);
      PROTO_ITEM_SET_GENERATED(ti);
      break;

    default:
      break;
    }
  }
}

/*
 * Check if the received message is a response to a previous request
 * registered is the camel session context.
 */
static void
camelsrt_report_call_matching(tvbuff_t *tvb, packet_info *pinfo,
                              proto_tree *tree,
                              struct camelsrt_info_t *p_camelsrt_info,
                              guint srt_type)
{
  struct camelsrt_call_t *p_camelsrt_call;
  struct camelsrt_call_info_key_t camelsrt_call_key;
  nstime_t delta;
  proto_item *ti, *hidden_item;

#ifdef DEBUG_CAMELSRT
  dbg(10,"\n %s #%u\n", val_to_str_const(srt_type, camelSRTtype_naming, "Unk"),pinfo->num);
#endif
  camelsrt_call_key.SessionIdKey = p_camelsrt_info->tcap_session_id;
  /* look only for matching request, if matching conversation is available. */

#ifdef DEBUG_CAMELSRT
  dbg(11,"Search key %lu ",camelsrt_call_key.SessionIdKey);
#endif
  p_camelsrt_call = find_camelsrt_call(&camelsrt_call_key);
  if(p_camelsrt_call) {
#ifdef DEBUG_CAMELSRT
    dbg(12,"Found, req=%d ",p_camelsrt_call->category[srt_type].req_num);
#endif
    if ( gcamel_DisplaySRT )
      proto_tree_add_uint(tree, hf_camelsrt_SessionId, tvb, 0,0, p_camelsrt_call->session_id);

    if (srt_type==CAMELSRT_VOICE_ACR1) {
      if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].req_num != 0
          && p_camelsrt_call->category[CAMELSRT_VOICE_ACR3].req_num < pinfo->num) {
        srt_type=CAMELSRT_VOICE_ACR1;
      } else  if ( p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].req_num != 0
                   && p_camelsrt_call->category[CAMELSRT_VOICE_ACR2].req_num < pinfo->num) {
        srt_type=CAMELSRT_VOICE_ACR2;
      } else  if (p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].req_num != 0
                  && p_camelsrt_call->category[CAMELSRT_VOICE_ACR1].req_num < pinfo->num) {
        srt_type=CAMELSRT_VOICE_ACR1;
      }
#ifdef DEBUG_CAMELSRT
      dbg(70,"Report ACR %u ",srt_type);
#endif
    } /* not ACR */
    p_camelsrt_info->bool_msginfo[srt_type]=TRUE;

    if (p_camelsrt_call->category[srt_type].rsp_num == 0) {
      if  ( (p_camelsrt_call->category[srt_type].req_num != 0)
            && (pinfo->num > p_camelsrt_call->category[srt_type].req_num) ){
        /* We have not yet seen a response to that call, so this must be the first response;
           remember its frame number only if response comes after request */
#ifdef DEBUG_CAMELSRT
        dbg(14,"Set reslink #%d req %u ",pinfo->num, p_camelsrt_call->category[srt_type].req_num);
#endif
        p_camelsrt_call->category[srt_type].rsp_num = pinfo->num;

      } else {
#ifdef DEBUG_CAMELSRT
        dbg(2,"badreslink #%u req %u ",pinfo->num, p_camelsrt_call->category[srt_type].req_num);
#endif
      } /* req_num != 0 */
    } else { /* rsp_num != 0 */
      /* We have seen a response to this call - but was it *this* response? */
      if (p_camelsrt_call->category[srt_type].rsp_num != pinfo->num) {
        /* No, so it's a duplicate response. Mark it as such. */
#ifdef DEBUG_CAMELSRT
        dbg(21,"Display_duplicate rsp=%d ", p_camelsrt_call->category[srt_type].rsp_num);
#endif
        p_camelsrt_info->msginfo[srt_type].is_duplicate = TRUE;
        if ( gcamel_DisplaySRT ){
          hidden_item = proto_tree_add_uint(tree, hf_camelsrt_Duplicate, tvb, 0,0, 77);
          PROTO_ITEM_SET_HIDDEN(hidden_item);
        }
      }
    } /* rsp_num != 0 */

    if ( (p_camelsrt_call->category[srt_type].req_num != 0) &&
         (p_camelsrt_call->category[srt_type].rsp_num != 0) &&
         (p_camelsrt_call->category[srt_type].rsp_num == pinfo->num) ) {

      p_camelsrt_call->category[srt_type].responded = TRUE;
      p_camelsrt_info->msginfo[srt_type].request_available = TRUE;
#ifdef DEBUG_CAMELSRT
      dbg(20,"Display_frameReqlink %d ",p_camelsrt_call->category[srt_type].req_num);
#endif
      /* Indicate the frame to which this is a reply. */
      if ( gcamel_DisplaySRT ) {
        ti = proto_tree_add_uint_format(tree, hf_camelsrt_ResponseFrame, tvb, 0, 0,
                                        p_camelsrt_call->category[srt_type].req_num,
                                        "Linked request %s in frame %u",
                                        val_to_str_const(srt_type, camelSRTtype_naming, "Unk"),
                                        p_camelsrt_call->category[srt_type].req_num);
        PROTO_ITEM_SET_GENERATED(ti);
      }
      /* Calculate Service Response Time */
      nstime_delta(&delta, &pinfo->abs_ts, &p_camelsrt_call->category[srt_type].req_time);

      p_camelsrt_info->msginfo[srt_type].is_delta_time = TRUE;
      p_camelsrt_info->msginfo[srt_type].delta_time = delta; /* give it to tap */
      p_camelsrt_info->msginfo[srt_type].req_time = p_camelsrt_call->category[srt_type].req_time;

      /* display Service Response Time and make it filterable */
      camelsrt_display_DeltaTime(tree, tvb, &delta, srt_type);

    } /*req_num != 0 && not duplicate */
  } /* call reference found */
}

/*
 * Service Response Time analyze, called just after the camel dissector
 * According to the camel operation, we
 * - open/close a context for the camel session
 * - look for a request, or look for the corresponding response
 */
void
camelsrt_call_matching(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
                       struct camelsrt_info_t *p_camelsrt_info)
{

#ifdef DEBUG_CAMELSRT
  dbg(10,"tcap_session #%d ", p_camelsrt_info->tcap_session_id);
#endif

  switch (p_camelsrt_info->opcode) {

  case 0:  /*InitialDP*/
    camelsrt_begin_call_matching(pinfo, p_camelsrt_info);
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                   CAMELSRT_VOICE_INITIALDP);
    break;
  case 60: /*InitialDPSMS*/
    camelsrt_begin_call_matching(pinfo, p_camelsrt_info);
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                   CAMELSRT_SMS_INITIALDP);
    break;
  case 78: /*InitialDPGPRS*/
    camelsrt_begin_call_matching(pinfo, p_camelsrt_info);
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                   CAMELSRT_GPRS_INITIALDP);
    break;

  case 23: /*RequestReportBCSMEvent*/
    break;

  case 63: /*RequestReportSMSEvent*/
    break;

  case 81: /*RequestReportGPRSEvent*/
    break;

  case 24: /*EventReportBCSMEvent*/
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                   CAMELSRT_VOICE_DISC );
    break;

  case 64: /*EventReportSMS*/
    /* Session has been explicity closed without TC_END */
    camelsrt_close_call_matching(pinfo, p_camelsrt_info);
    tcapsrt_close((struct tcaphash_context_t *)p_camelsrt_info->tcap_context, pinfo);
    break;

  case 80: /*EventReportGPRS*/
    camelsrt_begin_call_matching(pinfo, p_camelsrt_info);
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                   CAMELSRT_GPRS_REPORT);
    break;

  case 35: /*ApplyCharging*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                  CAMELSRT_VOICE_ACR1 );
    break;

  case 71: /*ApplyChargingGPRS*/
    break;

  case 36: /*ApplyChargingReport*/
    camelsrt_request_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                   CAMELSRT_VOICE_ACR1 );
    break;

  case 72: /*ApplyChargingReportGPRS*/
    break;

  case 31: /*Continue*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                      CAMELSRT_VOICE_INITIALDP);
    break;
  case 65: /*ContinueSMS*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                  CAMELSRT_SMS_INITIALDP);
    break;
  case 75: /*ContinueGPRS*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                  CAMELSRT_GPRS_INITIALDP);
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                  CAMELSRT_GPRS_REPORT);
    break;

  case 22: /*ReleaseCall*/
    camelsrt_report_call_matching(tvb, pinfo, tree, p_camelsrt_info,
                                      CAMELSRT_VOICE_DISC);
    /* Session has been closed by Network */
    camelsrt_close_call_matching(pinfo, p_camelsrt_info);
    break;

  case 66: /*ReleaseSMS*/
    /* Session has been closed by Network */
    camelsrt_close_call_matching(pinfo, p_camelsrt_info);
    tcapsrt_close((struct tcaphash_context_t *)p_camelsrt_info->tcap_context,pinfo);
    break;

  case 79: /*ReleaseGPRS*/
    /* Session has been closed by Network */
    camelsrt_close_call_matching(pinfo, p_camelsrt_info);
    break;
  } /* switch opcode */
}

/*
 * Initialize the Message Info used by the main dissector
 * Data are linked to a TCAP transaction
 */
struct camelsrt_info_t *
camelsrt_razinfo(void)
{
  struct camelsrt_info_t *p_camelsrt_info ;

  /* Global buffer for packet extraction */
  camelsrt_global_current++;
  if(camelsrt_global_current==MAX_CAMEL_INSTANCE){
    camelsrt_global_current=0;
  }

  p_camelsrt_info=&camelsrt_global_info[camelsrt_global_current];
  memset(p_camelsrt_info,0,sizeof(struct camelsrt_info_t));

  p_camelsrt_info->opcode=255;

  return p_camelsrt_info;
}


static guint8 camel_pdu_type = 0;
static guint8 camel_pdu_size = 0;


static int
dissect_camel_camelPDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, asn1_ctx_t *actx _U_,proto_tree *tree,
                        int hf_index, struct tcap_private_t * p_private_tcap) {

    char *version_ptr;

    opcode = 0;
    application_context_version = 0;
    if (p_private_tcap != NULL){
        if (p_private_tcap->acv==TRUE ){
            version_ptr = strrchr((const char *)p_private_tcap->oid,'.');
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

static int
dissect_camel_v1(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
  proto_item  *item;
  proto_tree  *tree = NULL, *stat_tree = NULL;
  struct tcap_private_t * p_private_tcap = (struct tcap_private_t*)data;
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

  dissect_camel_camelPDU(FALSE, tvb, 0, &asn1_ctx , tree, -1, p_private_tcap);

  /* If a Tcap context is associated to this transaction */
  if (gcamel_HandleSRT &&
      gp_camelsrt_info->tcap_context ) {
    if (gcamel_DisplaySRT && tree) {
      stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_camel_stat, NULL, "Stat");
    }
    camelsrt_call_matching(tvb, pinfo, stat_tree, gp_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, gp_camelsrt_info);
  }

  return tvb_captured_length(tvb);
}

static int
dissect_camel_v2(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
  proto_item  *item;
  proto_tree  *tree = NULL, *stat_tree = NULL;
  struct tcap_private_t * p_private_tcap = (struct tcap_private_t*)data;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Camel-v2");

  camel_ver = 2;

  /* create display subtree for the protocol */
  if(parent_tree){
     item = proto_tree_add_item(parent_tree, proto_camel, tvb, 0, -1, ENC_NA);
     tree = proto_item_add_subtree(item, ett_camel);
     proto_item_append_text(item, "-V2");
  }
  /* camelsrt reset counter, and initialise global pointer
     to store service response time related data */
  gp_camelsrt_info=camelsrt_razinfo();

  dissect_camel_camelPDU(FALSE, tvb, 0, &asn1_ctx , tree, -1, p_private_tcap);

  /* If a Tcap context is associated to this transaction */
  if (gcamel_HandleSRT &&
      gp_camelsrt_info->tcap_context ) {
    if (gcamel_DisplaySRT && tree) {
      stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_camel_stat, NULL, "Stat");
    }
    camelsrt_call_matching(tvb, pinfo, stat_tree, gp_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, gp_camelsrt_info);
  }

  return tvb_captured_length(tvb);
}

static int
dissect_camel(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree, void* data)
{
  proto_item  *item;
  proto_tree  *tree, *stat_tree = NULL;
  struct tcap_private_t * p_private_tcap = (struct tcap_private_t*)data;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "Camel");

  /* Unknown camel version */
  camel_ver = 0;

  /* create display subtree for the protocol */
  item = proto_tree_add_item(parent_tree, proto_camel, tvb, 0, -1, ENC_NA);
  tree = proto_item_add_subtree(item, ett_camel);

  /* camelsrt reset counter, and initialise global pointer
     to store service response time related data */
  gp_camelsrt_info=camelsrt_razinfo();
  dissect_camel_camelPDU(FALSE, tvb, 0, &asn1_ctx , tree, -1, p_private_tcap);

  /* If a Tcap context is associated to this transaction */
  if (gcamel_HandleSRT &&
      gp_camelsrt_info->tcap_context ) {
    if (gcamel_DisplaySRT && tree) {
      stat_tree = proto_tree_add_subtree(tree, tvb, 0, 0, ett_camel_stat, NULL, "Stat");
    }
    camelsrt_call_matching(tvb, pinfo, stat_tree, gp_camelsrt_info);
    tap_queue_packet(camel_tap, pinfo, gp_camelsrt_info);
  }

  return tvb_captured_length(tvb);
}

/* TAP STAT INFO */
typedef enum
{
  MESSAGE_TYPE_COLUMN = 0,
  COUNT_COLUMN
} camel_stat_columns;

static stat_tap_table_item camel_stat_fields[] = {{TABLE_ITEM_STRING, TAP_ALIGN_LEFT, "Message Type or Reason", "%-25s"}, {TABLE_ITEM_UINT, TAP_ALIGN_RIGHT, "Count", "%d"}};

static void camel_stat_init(stat_tap_table_ui* new_stat, new_stat_tap_gui_init_cb gui_callback, void* gui_data)
{
  int num_fields = sizeof(camel_stat_fields)/sizeof(stat_tap_table_item);
  stat_tap_table* table = new_stat_tap_init_table("CAMEL Message Counters", num_fields, 0, NULL, gui_callback, gui_data);
  int i;
  stat_tap_table_item_type items[sizeof(camel_stat_fields)/sizeof(stat_tap_table_item)];

  new_stat_tap_add_table(new_stat, table);

  items[MESSAGE_TYPE_COLUMN].type = TABLE_ITEM_STRING;
  items[COUNT_COLUMN].type = TABLE_ITEM_UINT;
  items[COUNT_COLUMN].value.uint_value = 0;

  /* Add a row for each value type */
  for (i = 0; i < camel_MAX_NUM_OPR_CODES; i++)
  {
    const char *ocs = try_val_to_str(i, camel_opr_code_strings);
    char *col_str;
    if (ocs) {
      col_str = g_strdup_printf("Request %s", ocs);
    } else {
      col_str = g_strdup_printf("Unknown op code %d", i);
    }

    items[MESSAGE_TYPE_COLUMN].value.string_value = col_str;
    new_stat_tap_init_table_row(table, i, num_fields, items);
  }
}

static gboolean
camel_stat_packet(void *tapdata, packet_info *pinfo _U_, epan_dissect_t *edt _U_, const void *csi_ptr)
{
  new_stat_data_t* stat_data = (new_stat_data_t*)tapdata;
  const struct camelsrt_info_t *csi = (const struct camelsrt_info_t *) csi_ptr;
  stat_tap_table* table;
  stat_tap_table_item_type* msg_data;
  guint i = 0;

  table = g_array_index(stat_data->stat_tap_data->tables, stat_tap_table*, i);
  if (csi->opcode >= table->num_elements)
    return FALSE;
  msg_data = new_stat_tap_get_field_data(table, csi->opcode, COUNT_COLUMN);
  msg_data->value.uint_value++;
  new_stat_tap_set_field_data(table, csi->opcode, COUNT_COLUMN, msg_data);

  return TRUE;
}

static void
camel_stat_reset(stat_tap_table* table)
{
  guint element;
  stat_tap_table_item_type* item_data;

  for (element = 0; element < table->num_elements; element++)
  {
    item_data = new_stat_tap_get_field_data(table, element, COUNT_COLUMN);
    item_data->value.uint_value = 0;
    new_stat_tap_set_field_data(table, element, COUNT_COLUMN, item_data);
  }
}

static void
camel_stat_free_table_item(stat_tap_table* table _U_, guint row _U_, guint column, stat_tap_table_item_type* field_data)
{
  if (column != MESSAGE_TYPE_COLUMN) return;
  g_free((char*)field_data->value.string_value);
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
        FT_UINT8, BASE_DEC, VALS(camel_RP_Cause_values), 0x7F,
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
    &ett_camel_additionalcallingpartynumber,

#include "packet-camel-ettarr.c"
  };

  static ei_register_info ei[] = {
     { &ei_camel_unknown_invokeData, { "camel.unknown.invokeData", PI_MALFORMED, PI_WARN, "Unknown invokeData", EXPFILL }},
     { &ei_camel_unknown_returnResultData, { "camel.unknown.returnResultData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL }},
     { &ei_camel_unknown_returnErrorData, { "camel.unknown.returnErrorData", PI_MALFORMED, PI_WARN, "Unknown returnResultData", EXPFILL }},
  };

  expert_module_t* expert_camel;

  static tap_param camel_stat_params[] = {
    { PARAM_FILTER, "filter", "Filter", NULL, TRUE }
  };

  static stat_tap_table_ui camel_stat_table = {
    REGISTER_STAT_GROUP_TELEPHONY_GSM,
    "CAMEL Messages and Response Status",
    PSNAME,
    "camel,counter",
    camel_stat_init,
    camel_stat_packet,
    camel_stat_reset,
    camel_stat_free_table_item,
    NULL,
    sizeof(camel_stat_fields)/sizeof(stat_tap_table_item), camel_stat_fields,
    sizeof(camel_stat_params)/sizeof(tap_param), camel_stat_params,
    NULL,
    0
  };

  /* Register protocol */
  proto_camel = proto_register_protocol(PNAME, PSNAME, PFNAME);

  camel_handle = register_dissector("camel", dissect_camel, proto_camel);
  camel_v1_handle = register_dissector("camel-v1", dissect_camel_v1, proto_camel);
  camel_v2_handle = register_dissector("camel-v2", dissect_camel_v2, proto_camel);

  proto_register_field_array(proto_camel, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
  expert_camel = expert_register_protocol(proto_camel);
  expert_register_field_array(expert_camel, ei, array_length(ei));

  rose_ctx_init(&camel_rose_ctx);

  /* Register dissector tables */
  camel_rose_ctx.arg_local_dissector_table = register_dissector_table("camel.ros.local.arg",
                                                                      "CAMEL Operation Argument (local opcode)", proto_camel,
                                                                      FT_UINT32, BASE_HEX);
  camel_rose_ctx.res_local_dissector_table = register_dissector_table("camel.ros.local.res",
                                                                      "CAMEL Operation Result (local opcode)", proto_camel,
                                                                      FT_UINT32, BASE_HEX);
  camel_rose_ctx.err_local_dissector_table = register_dissector_table("camel.ros.local.err",
                                                                      "CAMEL Error (local opcode)", proto_camel,
                                                                      FT_UINT32, BASE_HEX);

  /* Register our configuration options, particularly our SSNs */
  /* Set default SSNs */
  range_convert_str(&global_ssn_range, "146", MAX_SSN);

  camel_module = prefs_register_protocol(proto_camel, proto_reg_handoff_camel);

  prefs_register_enum_preference(camel_module, "date.format", "Date Format",
                                  "The date format: (DD/MM) or (MM/DD)",
                                  &date_format, date_options, FALSE);


  prefs_register_range_preference(camel_module, "tcap.ssn",
    "TCAP SSNs",
    "TCAP Subsystem numbers used for Camel",
    &global_ssn_range, MAX_SSN);

  prefs_register_bool_preference(camel_module, "srt",
                                 "Analyze Service Response Time",
                                 "Enable response time analysis",
                                 &gcamel_HandleSRT);

  prefs_register_bool_preference(camel_module, "persistentsrt",
                                 "Persistent stats for SRT",
                                 "Statistics for Response Time",
                                 &gcamel_PersistentSRT);

  /* Routine for statistic */
  register_init_routine(&camelsrt_init_routine);
  register_cleanup_routine(&camelsrt_cleanup_routine);
  camel_tap=register_tap(PSNAME);

  register_srt_table(proto_camel, PSNAME, 1, camelstat_packet, camelstat_init, NULL);
  register_stat_tap_table_ui(&camel_stat_table);
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
