/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* ./packet-MAP_DialoguePDU.c                                                 */
/* ../../tools/asn2eth.py -X -b -e -p MAP_DialoguePDU -c MAP_DialoguePDU.cnf -s packet-MAP-DialoguePDU-template MAP_DialoguePDU.asn */

/* Input file: packet-MAP-DialoguePDU-template.c */

/* packet-MAP_DialoguePDU_asn1.c
 * Routines for MAP_DialoguePDU packet dissection
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/packet.h>
#include <epan/conversation.h>

#include <stdio.h>
#include <string.h>

#include "packet-ber.h"

#define PNAME  "MAP_DialoguePDU"
#define PSNAME "MAP_DialoguePDU"
#define PFNAME "MAP_DialoguePDU"

/* Initialize the protocol and registered fields */
int proto_MAP_DialoguePDU = -1;

/*--- Included file: packet-MAP_DialoguePDU-hf.c ---*/

static int hf_MAP_DialoguePDU_map_open = -1;      /* T_map_open */
static int hf_MAP_DialoguePDU_destinationReference = -1;  /* DestinationReference */
static int hf_MAP_DialoguePDU_originationReference = -1;  /* OriginationReference */
static int hf_MAP_DialoguePDU_map_accept = -1;    /* T_map_accept */
static int hf_MAP_DialoguePDU_map_close = -1;     /* T_map_close */
static int hf_MAP_DialoguePDU_map_refuse = -1;    /* T_map_refuse */
static int hf_MAP_DialoguePDU_reason = -1;        /* Reason */
static int hf_MAP_DialoguePDU_map_userAbort = -1;  /* T_map_userAbort */
static int hf_MAP_DialoguePDU_map_UserAbortChoice = -1;  /* MAP_UserAbortChoice */
static int hf_MAP_DialoguePDU_map_providerAbort = -1;  /* T_map_providerAbort */
static int hf_MAP_DialoguePDU_map_ProviderAbortReason = -1;  /* MAP_ProviderAbortReason */
static int hf_MAP_DialoguePDU_userSpecificReason = -1;  /* NULL */
static int hf_MAP_DialoguePDU_userResourceLimitation = -1;  /* NULL */
static int hf_MAP_DialoguePDU_resourceUnavailable = -1;  /* ResourceUnavailable */
static int hf_MAP_DialoguePDU_applicationProcedureCancellation = -1;  /* ApplicationProcedureCancellation */

/*--- End of included file: packet-MAP_DialoguePDU-hf.c ---*/


/* Initialize the subtree pointers */

/*--- Included file: packet-MAP_DialoguePDU-ett.c ---*/

static gint ett_MAP_DialoguePDU_MAP_DialoguePDU = -1;
static gint ett_MAP_DialoguePDU_T_map_open = -1;
static gint ett_MAP_DialoguePDU_T_map_accept = -1;
static gint ett_MAP_DialoguePDU_T_map_close = -1;
static gint ett_MAP_DialoguePDU_T_map_refuse = -1;
static gint ett_MAP_DialoguePDU_T_map_userAbort = -1;
static gint ett_MAP_DialoguePDU_T_map_providerAbort = -1;
static gint ett_MAP_DialoguePDU_MAP_OpenInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_AcceptInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_CloseInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_RefuseInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_UserAbortInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_UserAbortChoice = -1;
static gint ett_MAP_DialoguePDU_MAP_ProviderAbortInfo = -1;

/*--- End of included file: packet-MAP_DialoguePDU-ett.c ---*/



/*--- Included file: packet-MAP_DialoguePDU-fn.c ---*/

/*--- Fields for imported types ---*/



static int
dissect_MAP_DialoguePDU_DestinationReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_destinationReference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_DestinationReference(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_destinationReference);
}


static int
dissect_MAP_DialoguePDU_OriginationReference(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                    NULL);

  return offset;
}
static int dissect_originationReference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_OriginationReference(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_originationReference);
}

static const ber_sequence_t T_map_open_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationReference_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originationReference_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_T_map_open(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_map_open_sequence, hf_index, ett_MAP_DialoguePDU_T_map_open);

  return offset;
}
static int dissect_map_open_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_T_map_open(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_open);
}

static const ber_sequence_t T_map_accept_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_T_map_accept(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_map_accept_sequence, hf_index, ett_MAP_DialoguePDU_T_map_accept);

  return offset;
}
static int dissect_map_accept_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_T_map_accept(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_accept);
}

static const ber_sequence_t T_map_close_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_T_map_close(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_map_close_sequence, hf_index, ett_MAP_DialoguePDU_T_map_close);

  return offset;
}
static int dissect_map_close_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_T_map_close(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_close);
}


static const value_string Reason_vals[] = {
  {   0, "noReasonGiven" },
  {   1, "invalidDestinationReference" },
  {   2, "invalidOriginatingReference" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_Reason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_reason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_Reason(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_reason);
}

static const ber_sequence_t T_map_refuse_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_reason },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_T_map_refuse(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_map_refuse_sequence, hf_index, ett_MAP_DialoguePDU_T_map_refuse);

  return offset;
}
static int dissect_map_refuse_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_T_map_refuse(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_refuse);
}


static int
dissect_MAP_DialoguePDU_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  { proto_item *ti_tmp;
  ti_tmp = proto_tree_add_item(tree, hf_index, tvb, offset>>8, 0, FALSE);
  proto_item_append_text(ti_tmp, ": NULL");
  }

  return offset;
}
static int dissect_userSpecificReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_NULL(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_userSpecificReason);
}
static int dissect_userResourceLimitation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_NULL(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_userResourceLimitation);
}


static const value_string ResourceUnavailable_vals[] = {
  {   0, "shortTermResourceLimitation" },
  {   1, "longTermResourceLimitation" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_ResourceUnavailable(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_resourceUnavailable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_ResourceUnavailable(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_resourceUnavailable);
}


static const value_string ApplicationProcedureCancellation_vals[] = {
  {   0, "handoverCancellation" },
  {   1, "radioChannelRelease" },
  {   2, "networkPathRelease" },
  {   3, "callRelease" },
  {   4, "associatedProcedureFailure" },
  {   5, "tandemDialogueRelease" },
  {   6, "remoteOperationsFailure" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_ApplicationProcedureCancellation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_applicationProcedureCancellation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_ApplicationProcedureCancellation(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_applicationProcedureCancellation);
}


static const value_string MAP_UserAbortChoice_vals[] = {
  {   0, "userSpecificReason" },
  {   1, "userResourceLimitation" },
  {   2, "resourceUnavailable" },
  {   3, "applicationProcedureCancellation" },
  { 0, NULL }
};

static const ber_choice_t MAP_UserAbortChoice_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_userSpecificReason_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_userResourceLimitation_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_resourceUnavailable_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_applicationProcedureCancellation_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_UserAbortChoice(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              MAP_UserAbortChoice_choice, hf_index, ett_MAP_DialoguePDU_MAP_UserAbortChoice);

  return offset;
}
static int dissect_map_UserAbortChoice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_UserAbortChoice(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_UserAbortChoice);
}

static const ber_sequence_t T_map_userAbort_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_map_UserAbortChoice },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_T_map_userAbort(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_map_userAbort_sequence, hf_index, ett_MAP_DialoguePDU_T_map_userAbort);

  return offset;
}
static int dissect_map_userAbort_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_T_map_userAbort(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_userAbort);
}


static const value_string MAP_ProviderAbortReason_vals[] = {
  {   0, "abnormalDialogue" },
  {   1, "invalidPDU" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_MAP_ProviderAbortReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_map_ProviderAbortReason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_ProviderAbortReason(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_ProviderAbortReason);
}

static const ber_sequence_t T_map_providerAbort_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_map_ProviderAbortReason },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_T_map_providerAbort(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                T_map_providerAbort_sequence, hf_index, ett_MAP_DialoguePDU_T_map_providerAbort);

  return offset;
}
static int dissect_map_providerAbort_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_T_map_providerAbort(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_providerAbort);
}


static const value_string MAP_DialoguePDU_vals[] = {
  {   0, "map-open" },
  {   1, "map-accept" },
  {   2, "map-close" },
  {   3, "map-refuse" },
  {   4, "map-userAbort" },
  {   5, "map-providerAbort" },
  { 0, NULL }
};

static const ber_choice_t MAP_DialoguePDU_choice[] = {
  {   0, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_map_open_impl },
  {   1, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_map_accept_impl },
  {   2, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_map_close_impl },
  {   3, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_map_refuse_impl },
  {   4, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_map_userAbort_impl },
  {   5, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_map_providerAbort_impl },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_DialoguePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                              MAP_DialoguePDU_choice, hf_index, ett_MAP_DialoguePDU_MAP_DialoguePDU);

  return offset;
}

static const ber_sequence_t MAP_OpenInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationReference_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originationReference_impl },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_OpenInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                MAP_OpenInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_OpenInfo);

  return offset;
}

static const ber_sequence_t MAP_AcceptInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_AcceptInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                MAP_AcceptInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_AcceptInfo);

  return offset;
}

static const ber_sequence_t MAP_CloseInfo_sequence[] = {
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_CloseInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                MAP_CloseInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_CloseInfo);

  return offset;
}

static const ber_sequence_t MAP_RefuseInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_reason },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_RefuseInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                MAP_RefuseInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_RefuseInfo);

  return offset;
}

static const ber_sequence_t MAP_UserAbortInfo_sequence[] = {
  { BER_CLASS_CON, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_map_UserAbortChoice },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_UserAbortInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                MAP_UserAbortInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_UserAbortInfo);

  return offset;
}


static const value_string ResourceUnavailableReason_vals[] = {
  {   0, "shortTermResourceLimitation" },
  {   1, "longTermResourceLimitation" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_ResourceUnavailableReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string ProcedureCancellationReason_vals[] = {
  {   0, "handoverCancellation" },
  {   1, "radioChannelRelease" },
  {   2, "networkPathRelease" },
  {   3, "callRelease" },
  {   4, "associatedProcedureFailure" },
  {   5, "tandemDialogueRelease" },
  {   6, "remoteOperationsFailure" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_ProcedureCancellationReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}

static const ber_sequence_t MAP_ProviderAbortInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_map_ProviderAbortReason },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_ProviderAbortInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                MAP_ProviderAbortInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_ProviderAbortInfo);

  return offset;
}


/*--- End of included file: packet-MAP_DialoguePDU-fn.c ---*/


void
dissect_MAP_Dialogue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  dissect_MAP_DialoguePDU_MAP_DialoguePDU(FALSE, tvb, 0, pinfo, parent_tree, -1);
}

/*--- proto_register_MAP_DialoguePDU -------------------------------------------*/
void proto_register_MAP_DialoguePDU(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-MAP_DialoguePDU-hfarr.c ---*/

    { &hf_MAP_DialoguePDU_map_open,
      { "map-open", "MAP_DialoguePDU.map_open",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-open", HFILL }},
    { &hf_MAP_DialoguePDU_destinationReference,
      { "destinationReference", "MAP_DialoguePDU.destinationReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_MAP_DialoguePDU_originationReference,
      { "originationReference", "MAP_DialoguePDU.originationReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "", HFILL }},
    { &hf_MAP_DialoguePDU_map_accept,
      { "map-accept", "MAP_DialoguePDU.map_accept",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-accept", HFILL }},
    { &hf_MAP_DialoguePDU_map_close,
      { "map-close", "MAP_DialoguePDU.map_close",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-close", HFILL }},
    { &hf_MAP_DialoguePDU_map_refuse,
      { "map-refuse", "MAP_DialoguePDU.map_refuse",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-refuse", HFILL }},
    { &hf_MAP_DialoguePDU_reason,
      { "reason", "MAP_DialoguePDU.reason",
        FT_UINT32, BASE_DEC, VALS(Reason_vals), 0,
        "", HFILL }},
    { &hf_MAP_DialoguePDU_map_userAbort,
      { "map-userAbort", "MAP_DialoguePDU.map_userAbort",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-userAbort", HFILL }},
    { &hf_MAP_DialoguePDU_map_UserAbortChoice,
      { "map-UserAbortChoice", "MAP_DialoguePDU.map_UserAbortChoice",
        FT_UINT32, BASE_DEC, VALS(MAP_UserAbortChoice_vals), 0,
        "", HFILL }},
    { &hf_MAP_DialoguePDU_map_providerAbort,
      { "map-providerAbort", "MAP_DialoguePDU.map_providerAbort",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-providerAbort", HFILL }},
    { &hf_MAP_DialoguePDU_map_ProviderAbortReason,
      { "map-ProviderAbortReason", "MAP_DialoguePDU.map_ProviderAbortReason",
        FT_UINT32, BASE_DEC, VALS(MAP_ProviderAbortReason_vals), 0,
        "", HFILL }},
    { &hf_MAP_DialoguePDU_userSpecificReason,
      { "userSpecificReason", "MAP_DialoguePDU.userSpecificReason",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-UserAbortChoice/userSpecificReason", HFILL }},
    { &hf_MAP_DialoguePDU_userResourceLimitation,
      { "userResourceLimitation", "MAP_DialoguePDU.userResourceLimitation",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-UserAbortChoice/userResourceLimitation", HFILL }},
    { &hf_MAP_DialoguePDU_resourceUnavailable,
      { "resourceUnavailable", "MAP_DialoguePDU.resourceUnavailable",
        FT_UINT32, BASE_DEC, VALS(ResourceUnavailable_vals), 0,
        "MAP-UserAbortChoice/resourceUnavailable", HFILL }},
    { &hf_MAP_DialoguePDU_applicationProcedureCancellation,
      { "applicationProcedureCancellation", "MAP_DialoguePDU.applicationProcedureCancellation",
        FT_UINT32, BASE_DEC, VALS(ApplicationProcedureCancellation_vals), 0,
        "MAP-UserAbortChoice/applicationProcedureCancellation", HFILL }},

/*--- End of included file: packet-MAP_DialoguePDU-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-MAP_DialoguePDU-ettarr.c ---*/

    &ett_MAP_DialoguePDU_MAP_DialoguePDU,
    &ett_MAP_DialoguePDU_T_map_open,
    &ett_MAP_DialoguePDU_T_map_accept,
    &ett_MAP_DialoguePDU_T_map_close,
    &ett_MAP_DialoguePDU_T_map_refuse,
    &ett_MAP_DialoguePDU_T_map_userAbort,
    &ett_MAP_DialoguePDU_T_map_providerAbort,
    &ett_MAP_DialoguePDU_MAP_OpenInfo,
    &ett_MAP_DialoguePDU_MAP_AcceptInfo,
    &ett_MAP_DialoguePDU_MAP_CloseInfo,
    &ett_MAP_DialoguePDU_MAP_RefuseInfo,
    &ett_MAP_DialoguePDU_MAP_UserAbortInfo,
    &ett_MAP_DialoguePDU_MAP_UserAbortChoice,
    &ett_MAP_DialoguePDU_MAP_ProviderAbortInfo,

/*--- End of included file: packet-MAP_DialoguePDU-ettarr.c ---*/

  };

  /* Register protocol */
  proto_MAP_DialoguePDU = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("MAP_DialoguePDU", dissect_MAP_Dialogue, proto_MAP_DialoguePDU);
  /* Register fields and subtrees */
  proto_register_field_array(proto_MAP_DialoguePDU, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_MAP_DialoguePDU ---------------------------------------*/
void proto_reg_handoff_MAP_DialoguePDU(void) {
	register_ber_oid_dissector("0.4.0.0.1.1.1.1", dissect_MAP_Dialogue, proto_MAP_DialoguePDU, 
	  "itu-t(0) identified-organization(4) etsi(0) mobileDomain(0) gsm-Network(1) abstractSyntax(1) map-DialoguePDU(1) version1(1)");

}
