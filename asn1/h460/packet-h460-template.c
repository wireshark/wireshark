/* packet-h460.c
 * Routines for H.460.x packet dissection
 * 2007  Tomas Kukosa
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>
#include <epan/oids.h>
#include <epan/asn1.h>

#include <string.h>

#include "packet-per.h"
#include "packet-h225.h"
#include "packet-h235.h"
#include "packet-h245.h"

#define PNAME  "H.460 Supplementary Services"
#define PSNAME "H.460"
#define PFNAME "h460"

/* Initialize the protocol and registered fields */
static int proto_h460 = -1;
#include "packet-h460-hf.c"

/* Initialize the subtree pointers */
#include "packet-h460-ett.c"

/* Subdissectors */
static dissector_handle_t q931_ie_handle = NULL; 
static dissector_handle_t h225_ras_handle = NULL; 

#include "packet-h460-fn.c"

static int
dissect_ies(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  int offset = 0;

  if (q931_ie_handle) {
    call_dissector(q931_ie_handle, tvb, pinfo, tree);
    offset += tvb_length_remaining(tvb, offset);
  }
  return offset;
}

static int 
dissect_ras(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  int offset = 0;

  if (h225_ras_handle) {
    call_dissector(h225_ras_handle, tvb, pinfo, tree);
    offset += tvb_length_remaining(tvb, offset);
  }
  return offset;
}

typedef struct _h460_feature_t {
  guint32 opt;
  const gchar *id;
  const gchar *name;
  new_dissector_t content_pdu;
  /*---*/
  const gchar *key_gd;
  const gchar *key_fd;
  const gchar *key_gm;
  const gchar *key_gi;
  dissector_handle_t content_hnd;
} h460_feature_t;

/* Fill in the items after content_pdu */
#define FFILL	NULL, NULL, NULL, NULL, NULL

/* options */
#define GD 0x01  /* present in H.225 GenericData */
#define FD 0x02  /* present in H.225 FeatureDescriptor */
#define GM 0x04  /* present in H.245 GenericMessage */
#define GI 0x08  /* present in H.245 GenericInformation */

static h460_feature_t h460_feature_tab[] = {
  /* H.460.3 */
  { GD|FD,  "2",   "Number Portability", NULL, FFILL },
  { GD|FD,  "2/1", "NumberPortabilityData", dissect_h460_2_NumberPortabilityInfo_PDU, FFILL },
  /* H.460.3 */
  { GD|FD,  "3",   "Circuit Status", NULL, FFILL },
  { GD|FD,  "3/1", "Circuit Status Map", dissect_h460_3_CircuitStatus_PDU, FFILL },
  /* H.460.4 */
  { GD|FD,  "4",   "CallPriorityDesignation", NULL, FFILL },
  { GD|FD,  "4/1", "CallPriorityRequest", dissect_h460_4_CallPriorityInfo_PDU, FFILL },
  { GD|FD,  "4/2", "CallPriorityConfirm", dissect_h460_4_CallPriorityInfo_PDU, FFILL },
  { GD|FD,  "4/3", "Country/InternationalNetworkCallOriginationRequest", dissect_h460_4_CountryInternationalNetworkCallOriginationIdentification_PDU, FFILL },
  { GD|FD,  "4/4", "Country/InternationalNetworkCallOriginationConfirm", dissect_h460_4_CountryInternationalNetworkCallOriginationIdentification_PDU, FFILL },
  /* H.460.5 */
  { GD|FD,  "5",   "DuplicateIEs", NULL, FFILL },
  { GD|FD,  "5/1", "IEsString", dissect_ies, FFILL },
  /* H.460.6 */
  { GD|FD,  "6",   "Extended Fast Connect", NULL, FFILL },
  { GD|FD,  "6/1", "EFC Proposal", NULL, FFILL },
  { GD|FD,  "6/2", "EFC Close All Media Channels", NULL, FFILL },
  { GD|FD,  "6/3", "EFC Request New Proposals", NULL, FFILL },
  { GD|FD,  "6/4", "EFC Require Symmetric Operation", NULL, FFILL },
  /* H.460.7 */
  { GD|FD,  "7",   "Digit Maps", NULL, FFILL },
  {    FD,  "7/1", "Digit Maps Length", NULL, FFILL },
  {    FD,  "7/2", "Digit Map Length for Overlapped Sending", NULL, FFILL },
  {    FD,  "7/3", "HTTP Digit Maps Download Capability", NULL, FFILL },
  { GD   ,  "7/1", "Start Timer", NULL, FFILL },
  { GD   ,  "7/2", "Short Timer", NULL, FFILL },
  { GD   ,  "7/3", "Long Timer", NULL, FFILL },
  { GD   ,  "7/4", "Digit Map String", NULL, FFILL },
  { GD   ,  "7/5",   "ToN Associated Digit Map", NULL, FFILL },
  { GD   ,  "7/5/1", "Type of Number", NULL, FFILL },
  { GD   ,  "7/5/2", "Digit Map Strings for ToN", NULL, FFILL },
  { GD   ,  "7/6", "Digit Map URL", NULL, FFILL },
  /* H.460.8 */
  { GD|FD,  "8",   "Querying for Alternate Routes", NULL, FFILL },
  { GD|FD,  "8/1", "Query Count", NULL, FFILL },
  { GD|FD,  "8/2", "Call Termination Cause", NULL, FFILL },
  /* H.460.9 */
  { GD|FD,  "9",   "QoS-monitoring Reporting", NULL, FFILL },
  { GD|FD,  "9/1", "qosMonitoringFinalOnly", NULL, FFILL },
  { GD|FD,  "9/2", "qosMonitoringReportData", dissect_h460_9_QosMonitoringReportData_PDU, FFILL },
  { GD|FD,  "9/3", "qosMonitoringExtendedRTPMetrics", dissect_h460_9_ExtendedRTPMetrics_PDU, FFILL },
  /* H.460.10 */
  { GD|FD, "10",   "Call Party Category", NULL, FFILL },
  { GD|FD, "10/1", "Call party category info", dissect_h460_10_CallPartyCategoryInfo_PDU, FFILL },
  /* H.460.11 */
  { GD|FD, "11",   "Delayed Call Establishment", NULL, FFILL },
  { GD|FD, "11/1", "Delay Point Indicator", NULL, FFILL },
  { GD|FD, "11/2", "Implicit DCE Release", NULL, FFILL },
  { GD|FD, "11/3", "Delay Point Reached", NULL, FFILL },
  { GD|FD, "11/4", "DCE Release", NULL, FFILL },
  /* H.460.12 */
  { GD|FD, "12",   "Glare Control Indicator", NULL, FFILL },
  { GD|FD, "12/1", "Glare Control Indicator Parameter", NULL, FFILL },
  /* H.460.13 */
  { GD|FD, "13",   "Called User Release Control", NULL, FFILL },
  { GD|FD, "13/1", "Called User Release Control", NULL, FFILL },
  /* H.460.14 */
  { GD|FD, "14",   "Multi-Level Precedence and Preemption", NULL, FFILL },
  { GD|FD, "14/1", "MLPP Information", dissect_h460_14_MLPPInfo_PDU, FFILL },
  /* H.460.15 */
  { GD|FD, "15",   "Call signalling transport channel suspension and redirection", NULL, FFILL },
  { GD|FD, "15/1", "Signalling channel suspend and redirect", dissect_h460_15_SignallingChannelData_PDU, FFILL },
  /* H.460.16 */
  { GD|FD, "16",   "Multiple-message Release Sequence", NULL, FFILL },
  { GD|FD, "16/1", "MMRS use required", NULL, FFILL },
  { GD|FD, "16/2", "MMRS procedure", NULL, FFILL },
  { GD|FD, "16/3", "MMRS additional IEs", dissect_ies, FFILL },
  /* H.460.17 */
  { GD|FD, "17",   "RAS over H.225.0", NULL, FFILL },
  { GD|FD, "17/1", "RAS message", dissect_ras, FFILL },
  /* H.460.18 */
  { GD|FD   , "18",   "Signalling Traversal", NULL, FFILL },
  { GD|FD   , "18/1", "IncomingCallIndication", dissect_h460_18_IncomingCallIndication_PDU, FFILL },
  { GD|FD   , "18/2", "LRQKeepAliveData", dissect_h460_18_LRQKeepAliveData_PDU, FFILL },
  {       GM, "0.0.8.460.18.0.1",   "Signalling Traversal", NULL, FFILL },
  {       GM, "0.0.8.460.18.0.1-1",   "connectionCorrelation", NULL, FFILL },
  {       GM, "0.0.8.460.18.0.1-1/1", "callIdentifier", NULL, FFILL },
  {       GM, "0.0.8.460.18.0.1-1/2", "answerCall", NULL, FFILL },
  /* H.460.19 */
  { GD|FD   , "19", "mediaNATFWTraversal", NULL, FFILL },
  { GD|FD   , "19/1", "supportTransmitMultiplexedMedia", NULL, FFILL },
  { GD|FD   , "19/2", "mediaTraversalServer", NULL, FFILL },
  {       GI, "0.0.8.460.19.0.1", "mediaNATFWTraversal", NULL, FFILL },
  {       GI, "0.0.8.460.19.0.1/1", "Traversal Parameters", dissect_h460_19_TraversalParameters_PDU, FFILL },
  /* H.460.20 */
  { GD|FD, "20",   "LocationSourceAddress", NULL, FFILL },
  { GD|FD, "20/1", "LocationSourceAddress", dissect_h225_ExtendedAliasAddress_PDU, FFILL },
  /* H.460.21 */
  { GD|FD, "21",   "Message Broadcast", NULL, FFILL },
  { GD|FD, "21/1", "MessageBroadcastParameter", dissect_h460_21_CapabilityAdvertisement_PDU, FFILL },
  /* H.460.22 */
  { GD|FD, "22",     "securityProtocolNegotiation", NULL, FFILL },
  { GD|FD, "22/1",   "tlsSecurityProtocol", NULL, FFILL },
  { GD|FD, "22/1/1", "priority", NULL, FFILL },
  { GD|FD, "22/1/2", "connectionAddress", NULL, FFILL },
  { GD|FD, "22/2",   "ipsecSecurityProtocol", NULL, FFILL },
  { GD|FD, "22/2/1", "priority", NULL, FFILL },
  { 0, NULL, NULL, NULL, FFILL },
};                                 

static h460_feature_t *find_ftr(const gchar *key) {
  h460_feature_t *ftr = NULL;
  h460_feature_t *f;

  for (f=h460_feature_tab; f->id; f++) {
    if (f->key_gd && !strcmp(key, f->key_gd)) { ftr = f; break; }
    if (f->key_fd && !strcmp(key, f->key_fd)) { ftr = f; break; }
    if (f->key_gm && !strcmp(key, f->key_gm)) { ftr = f; break; }
    if (f->key_gi && !strcmp(key, f->key_gi)) { ftr = f; break; }
  }
  return ftr;
}

/*--- dissect_h460_name -------------------------------------------*/
static int
dissect_h460_name(tvbuff_t *tvb _U_, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  int offset = 0;
  asn1_ctx_t *actx;
  h460_feature_t *ftr;

  actx = get_asn1_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(actx);
  if (tree) {
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, 0, 0, "*** DEBUG dissect_h460_name: %s", pinfo->match_string);*/
    ftr = find_ftr(pinfo->match_string);
    /* DEBUG */ /*proto_tree_add_text(tree, tvb, 0, 0, "*** DEBUG dissect_h460_name: ftr %s", (ftr)?ftr->name:"-none-");*/
    if (ftr) {
      proto_item_append_text(actx->created_item, " - %s", ftr->name);
      proto_item_append_text(proto_item_get_parent(proto_tree_get_parent(tree)), ": %s", ftr->name);
    } else {
      proto_item_append_text(actx->created_item, " - unknown(%s)", pinfo->match_string);
    }
  }

  return offset;
}

/*--- proto_register_h460 ----------------------------------------------*/
void proto_register_h460(void) {
  h460_feature_t *ftr;

  /* List of fields */
  static hf_register_info hf[] = {
#include "packet-h460-hfarr.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
#include "packet-h460-ettarr.c"
  };

  /* Register protocol */
  proto_h460 = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_h460, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  for (ftr=h460_feature_tab; ftr->id; ftr++) {
    if (ftr->opt & GD) ftr->key_gd = g_strdup_printf("GenericData/%s", ftr->id);
    if (ftr->opt & FD) ftr->key_fd = g_strdup_printf("FeatureDescriptor/%s", ftr->id);
    if (ftr->opt & GM) ftr->key_gm = g_strdup_printf("GenericMessage/%s", ftr->id);
    if (ftr->opt & GI) ftr->key_gi = g_strdup_printf("GenericInformation/%s", ftr->id);
    if (ftr->content_pdu) ftr->content_hnd = new_create_dissector_handle(ftr->content_pdu, proto_h460);
  }
}

/*--- proto_reg_handoff_h460 -------------------------------------------*/
void proto_reg_handoff_h460(void) 
{
  h460_feature_t *ftr;
  dissector_handle_t h460_name_handle;

  q931_ie_handle = find_dissector("q931.ie");
  h225_ras_handle = find_dissector("h225.ras");

  h460_name_handle = new_create_dissector_handle(dissect_h460_name, proto_h460);
  for (ftr=h460_feature_tab; ftr->id; ftr++) {
    if (ftr->key_gd) dissector_add_string("h225.gef.name", ftr->key_gd, h460_name_handle);
    if (ftr->key_fd) dissector_add_string("h225.gef.name", ftr->key_fd, h460_name_handle);
    if (ftr->key_gm) dissector_add_string("h245.gef.name", ftr->key_gm, h460_name_handle);
    if (ftr->key_gi) dissector_add_string("h245.gef.name", ftr->key_gi, h460_name_handle);
    if (ftr->content_hnd) {
      if (ftr->key_gd) dissector_add_string("h225.gef.content", ftr->key_gd, ftr->content_hnd);
      if (ftr->key_fd) dissector_add_string("h225.gef.content", ftr->key_fd, ftr->content_hnd);
      if (ftr->key_gm) dissector_add_string("h245.gef.content", ftr->key_gm, ftr->content_hnd);
      if (ftr->key_gi) dissector_add_string("h245.gef.content", ftr->key_gi, ftr->content_hnd);
    }
  }

}
