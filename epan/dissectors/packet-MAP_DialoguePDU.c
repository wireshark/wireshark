/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler    */
/* ./packet-MAP_DialoguePDU.c                                                 */
/* ../../tools/asn2eth.py -X -b -e -p MAP_DialoguePDU -c MAP_DialoguePDU.cnf -s packet-MAP-DialoguePDU-template MAP_DialoguePDU.asn */

/* Input file: packet-MAP-DialoguePDU-template.c */

#line 1 "packet-MAP-DialoguePDU-template.c"
/* packet-MAP_DialoguePDU_asn1.c
 * Routines for MAP_DialoguePDU packet dissection
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
#include "packet-gsm_map.h"

#define PNAME  "MAP_DialoguePDU"
#define PSNAME "MAP_DialoguePDU"
#define PFNAME "map_dialoguepdu"

/* Initialize the protocol and registered fields */
int proto_MAP_DialoguePDU = -1;

/*--- Included file: packet-MAP_DialoguePDU-hf.c ---*/
#line 1 "packet-MAP_DialoguePDU-hf.c"
static int hf_MAP_DialoguePDU_map_open = -1;      /* MAP_OpenInfo */
static int hf_MAP_DialoguePDU_map_accept = -1;    /* MAP_AcceptInfo */
static int hf_MAP_DialoguePDU_map_close = -1;     /* MAP_CloseInfo */
static int hf_MAP_DialoguePDU_map_refuse = -1;    /* MAP_RefuseInfo */
static int hf_MAP_DialoguePDU_map_userAbort = -1;  /* MAP_UserAbortInfo */
static int hf_MAP_DialoguePDU_map_providerAbort = -1;  /* MAP_ProviderAbortInfo */
static int hf_MAP_DialoguePDU_destinationReference = -1;  /* AddressString */
static int hf_MAP_DialoguePDU_originationReference = -1;  /* AddressString */
static int hf_MAP_DialoguePDU_extensionContainer = -1;  /* ExtensionContainer */
static int hf_MAP_DialoguePDU_reason = -1;        /* Reason */
static int hf_MAP_DialoguePDU_alternativeApplicationContext = -1;  /* OBJECT_IDENTIFIER */
static int hf_MAP_DialoguePDU_map_UserAbortChoice = -1;  /* MAP_UserAbortChoice */
static int hf_MAP_DialoguePDU_userSpecificReason = -1;  /* NULL */
static int hf_MAP_DialoguePDU_userResourceLimitation = -1;  /* NULL */
static int hf_MAP_DialoguePDU_resourceUnavailable = -1;  /* ResourceUnavailableReason */
static int hf_MAP_DialoguePDU_applicationProcedureCancellation = -1;  /* ProcedureCancellationReason */
static int hf_MAP_DialoguePDU_map_ProviderAbortReason = -1;  /* MAP_ProviderAbortReason */
static int hf_MAP_DialoguePDU_encapsulatedAC = -1;  /* OBJECT_IDENTIFIER */
static int hf_MAP_DialoguePDU_securityHeader = -1;  /* SecurityHeader */
static int hf_MAP_DialoguePDU_protectedPayload = -1;  /* ProtectedPayload */

/*--- End of included file: packet-MAP_DialoguePDU-hf.c ---*/
#line 46 "packet-MAP-DialoguePDU-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-MAP_DialoguePDU-ett.c ---*/
#line 1 "packet-MAP_DialoguePDU-ett.c"
static gint ett_MAP_DialoguePDU_MAP_DialoguePDU = -1;
static gint ett_MAP_DialoguePDU_MAP_OpenInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_AcceptInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_CloseInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_RefuseInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_UserAbortInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_UserAbortChoice = -1;
static gint ett_MAP_DialoguePDU_MAP_ProviderAbortInfo = -1;
static gint ett_MAP_DialoguePDU_MAP_ProtectedDialoguePDU = -1;

/*--- End of included file: packet-MAP_DialoguePDU-ett.c ---*/
#line 49 "packet-MAP-DialoguePDU-template.c"


/*--- Included file: packet-MAP_DialoguePDU-fn.c ---*/
#line 1 "packet-MAP_DialoguePDU-fn.c"
/*--- Fields for imported types ---*/

static int dissect_destinationReference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AddressString(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_destinationReference);
}
static int dissect_originationReference_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_AddressString(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_originationReference);
}
static int dissect_extensionContainer(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ExtensionContainer(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_extensionContainer);
}
static int dissect_securityHeader(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_SecurityHeader(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_securityHeader);
}
static int dissect_protectedPayload(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_gsm_map_ProtectedPayload(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_protectedPayload);
}


static const ber_sequence_t MAP_OpenInfo_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_destinationReference_impl },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_IMPLTAG, dissect_originationReference_impl },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_OpenInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MAP_OpenInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_OpenInfo);

  return offset;
}
static int dissect_map_open_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_OpenInfo(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_open);
}


static const ber_sequence_t MAP_AcceptInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_AcceptInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MAP_AcceptInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_AcceptInfo);

  return offset;
}
static int dissect_map_accept_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_AcceptInfo(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_accept);
}


static const ber_sequence_t MAP_CloseInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_CloseInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MAP_CloseInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_CloseInfo);

  return offset;
}
static int dissect_map_close_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_CloseInfo(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_close);
}


static const value_string MAP_DialoguePDU_Reason_vals[] = {
  {   0, "noReasonGiven" },
  {   1, "invalidDestinationReference" },
  {   2, "invalidOriginatingReference" },
  {   3, "encapsulatedAC-NotSupported" },
  {   4, "transportProtectionNotAdequate" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_Reason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_reason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_Reason(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_reason);
}



static int
dissect_MAP_DialoguePDU_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_alternativeApplicationContext(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_alternativeApplicationContext);
}
static int dissect_encapsulatedAC(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_encapsulatedAC);
}


static const ber_sequence_t MAP_RefuseInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_reason },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_alternativeApplicationContext },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_RefuseInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MAP_RefuseInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_RefuseInfo);

  return offset;
}
static int dissect_map_refuse_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_RefuseInfo(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_refuse);
}



static int
dissect_MAP_DialoguePDU_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_userSpecificReason_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_NULL(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_userSpecificReason);
}
static int dissect_userResourceLimitation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_NULL(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_userResourceLimitation);
}


static const value_string MAP_DialoguePDU_ResourceUnavailableReason_vals[] = {
  {   0, "shortTermResourceLimitation" },
  {   1, "longTermResourceLimitation" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_ResourceUnavailableReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_resourceUnavailable_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_ResourceUnavailableReason(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_resourceUnavailable);
}


static const value_string MAP_DialoguePDU_ProcedureCancellationReason_vals[] = {
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
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_applicationProcedureCancellation_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_ProcedureCancellationReason(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_applicationProcedureCancellation);
}


static const value_string MAP_DialoguePDU_MAP_UserAbortChoice_vals[] = {
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
                                 MAP_UserAbortChoice_choice, hf_index, ett_MAP_DialoguePDU_MAP_UserAbortChoice,
                                 NULL);

  return offset;
}
static int dissect_map_UserAbortChoice(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_UserAbortChoice(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_UserAbortChoice);
}


static const ber_sequence_t MAP_UserAbortInfo_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_map_UserAbortChoice },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_UserAbortInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MAP_UserAbortInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_UserAbortInfo);

  return offset;
}
static int dissect_map_userAbort_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_UserAbortInfo(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_userAbort);
}


static const value_string MAP_DialoguePDU_MAP_ProviderAbortReason_vals[] = {
  {   0, "abnormalDialogue" },
  {   1, "invalidPDU" },
  { 0, NULL }
};


static int
dissect_MAP_DialoguePDU_MAP_ProviderAbortReason(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_map_ProviderAbortReason(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_ProviderAbortReason(FALSE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_ProviderAbortReason);
}


static const ber_sequence_t MAP_ProviderAbortInfo_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_map_ProviderAbortReason },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_extensionContainer },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_ProviderAbortInfo(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MAP_ProviderAbortInfo_sequence, hf_index, ett_MAP_DialoguePDU_MAP_ProviderAbortInfo);

  return offset;
}
static int dissect_map_providerAbort_impl(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_MAP_DialoguePDU_MAP_ProviderAbortInfo(TRUE, tvb, offset, pinfo, tree, hf_MAP_DialoguePDU_map_providerAbort);
}


static const value_string MAP_DialoguePDU_MAP_DialoguePDU_vals[] = {
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
                                 MAP_DialoguePDU_choice, hf_index, ett_MAP_DialoguePDU_MAP_DialoguePDU,
                                 NULL);

  return offset;
}


static const ber_sequence_t MAP_ProtectedDialoguePDU_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_encapsulatedAC },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_securityHeader },
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_protectedPayload },
  { 0, 0, 0, NULL }
};

static int
dissect_MAP_DialoguePDU_MAP_ProtectedDialoguePDU(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   MAP_ProtectedDialoguePDU_sequence, hf_index, ett_MAP_DialoguePDU_MAP_ProtectedDialoguePDU);

  return offset;
}


/*--- End of included file: packet-MAP_DialoguePDU-fn.c ---*/
#line 51 "packet-MAP-DialoguePDU-template.c"

static void
dissect_MAP_Dialogue(tvbuff_t *tvb, packet_info *pinfo, proto_tree *parent_tree)
{
  dissect_MAP_DialoguePDU_MAP_DialoguePDU(FALSE, tvb, 0, pinfo, parent_tree, -1);
}

/*--- proto_register_MAP_DialoguePDU -------------------------------------------*/
void proto_register_MAP_DialoguePDU(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-MAP_DialoguePDU-hfarr.c ---*/
#line 1 "packet-MAP_DialoguePDU-hfarr.c"
    { &hf_MAP_DialoguePDU_map_open,
      { "map-open", "MAP_DialoguePDU.map_open",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-open", HFILL }},
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
    { &hf_MAP_DialoguePDU_map_userAbort,
      { "map-userAbort", "MAP_DialoguePDU.map_userAbort",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-userAbort", HFILL }},
    { &hf_MAP_DialoguePDU_map_providerAbort,
      { "map-providerAbort", "MAP_DialoguePDU.map_providerAbort",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-DialoguePDU/map-providerAbort", HFILL }},
    { &hf_MAP_DialoguePDU_destinationReference,
      { "destinationReference", "MAP_DialoguePDU.destinationReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MAP-OpenInfo/destinationReference", HFILL }},
    { &hf_MAP_DialoguePDU_originationReference,
      { "originationReference", "MAP_DialoguePDU.originationReference",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MAP-OpenInfo/originationReference", HFILL }},
    { &hf_MAP_DialoguePDU_extensionContainer,
      { "extensionContainer", "MAP_DialoguePDU.extensionContainer",
        FT_NONE, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_MAP_DialoguePDU_reason,
      { "reason", "MAP_DialoguePDU.reason",
        FT_UINT32, BASE_DEC, VALS(MAP_DialoguePDU_Reason_vals), 0,
        "MAP-RefuseInfo/reason", HFILL }},
    { &hf_MAP_DialoguePDU_alternativeApplicationContext,
      { "alternativeApplicationContext", "MAP_DialoguePDU.alternativeApplicationContext",
        FT_OID, BASE_NONE, NULL, 0,
        "MAP-RefuseInfo/alternativeApplicationContext", HFILL }},
    { &hf_MAP_DialoguePDU_map_UserAbortChoice,
      { "map-UserAbortChoice", "MAP_DialoguePDU.map_UserAbortChoice",
        FT_UINT32, BASE_DEC, VALS(MAP_DialoguePDU_MAP_UserAbortChoice_vals), 0,
        "MAP-UserAbortInfo/map-UserAbortChoice", HFILL }},
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
        FT_UINT32, BASE_DEC, VALS(MAP_DialoguePDU_ResourceUnavailableReason_vals), 0,
        "MAP-UserAbortChoice/resourceUnavailable", HFILL }},
    { &hf_MAP_DialoguePDU_applicationProcedureCancellation,
      { "applicationProcedureCancellation", "MAP_DialoguePDU.applicationProcedureCancellation",
        FT_UINT32, BASE_DEC, VALS(MAP_DialoguePDU_ProcedureCancellationReason_vals), 0,
        "MAP-UserAbortChoice/applicationProcedureCancellation", HFILL }},
    { &hf_MAP_DialoguePDU_map_ProviderAbortReason,
      { "map-ProviderAbortReason", "MAP_DialoguePDU.map_ProviderAbortReason",
        FT_UINT32, BASE_DEC, VALS(MAP_DialoguePDU_MAP_ProviderAbortReason_vals), 0,
        "MAP-ProviderAbortInfo/map-ProviderAbortReason", HFILL }},
    { &hf_MAP_DialoguePDU_encapsulatedAC,
      { "encapsulatedAC", "MAP_DialoguePDU.encapsulatedAC",
        FT_OID, BASE_NONE, NULL, 0,
        "MAP-ProtectedDialoguePDU/encapsulatedAC", HFILL }},
    { &hf_MAP_DialoguePDU_securityHeader,
      { "securityHeader", "MAP_DialoguePDU.securityHeader",
        FT_NONE, BASE_NONE, NULL, 0,
        "MAP-ProtectedDialoguePDU/securityHeader", HFILL }},
    { &hf_MAP_DialoguePDU_protectedPayload,
      { "protectedPayload", "MAP_DialoguePDU.protectedPayload",
        FT_BYTES, BASE_HEX, NULL, 0,
        "MAP-ProtectedDialoguePDU/protectedPayload", HFILL }},

/*--- End of included file: packet-MAP_DialoguePDU-hfarr.c ---*/
#line 64 "packet-MAP-DialoguePDU-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-MAP_DialoguePDU-ettarr.c ---*/
#line 1 "packet-MAP_DialoguePDU-ettarr.c"
    &ett_MAP_DialoguePDU_MAP_DialoguePDU,
    &ett_MAP_DialoguePDU_MAP_OpenInfo,
    &ett_MAP_DialoguePDU_MAP_AcceptInfo,
    &ett_MAP_DialoguePDU_MAP_CloseInfo,
    &ett_MAP_DialoguePDU_MAP_RefuseInfo,
    &ett_MAP_DialoguePDU_MAP_UserAbortInfo,
    &ett_MAP_DialoguePDU_MAP_UserAbortChoice,
    &ett_MAP_DialoguePDU_MAP_ProviderAbortInfo,
    &ett_MAP_DialoguePDU_MAP_ProtectedDialoguePDU,

/*--- End of included file: packet-MAP_DialoguePDU-ettarr.c ---*/
#line 69 "packet-MAP-DialoguePDU-template.c"
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
