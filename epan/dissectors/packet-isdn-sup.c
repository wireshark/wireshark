/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-isdn-sup.c                                                          */
/* ../../tools/asn2wrs.py -b -p isdn-sup -c ./isdn-sup.cnf -s ./packet-isdn-sup-template -D . -O ../../epan/dissectors Addressing-Data-Elements.asn Basic-Service-Elements.asn Embedded-Q931-Types.asn Diversion-Operations.asn */

/* Input file: packet-isdn-sup-template.c */

#line 1 "../../asn1/isdn-sup/packet-isdn-sup-template.c"
/* packet-isdn-sup-template.c
 * Routines for ETSI Integrated Services Digital Network (ISDN) 
 * supplementary services
 * Copyright 2013, Anders Broman <anders.broman@ericsson.com>
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

#include "config.h"

#include <glib.h>
#include <epan/packet.h>


#include "packet-ber.h"

#define PNAME  "ISDN supplementary services"
#define PSNAME "ISDN_SUP"
#define PFNAME "isdn_sup"

/* Initialize the protocol and registered fields */
static int proto_isdn_sup = -1;
static int hf_isdn_sup_operation = -1;

/* Global variables */

#if 0
/* ROSE context */
static rose_ctx_t isdn_sup_rose_ctx;
#endif

typedef struct _isdn_sup_op_t {
  gint32 opcode;
  new_dissector_t arg_pdu;
  new_dissector_t res_pdu;
} isdn_sup_op_t;

static const value_string isdn_sup_str_operation[] = {

/*--- Included file: packet-isdn-sup-table10.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-table10.c"
  {   7, "activationDiversion" },
  {   8, "deactivationDiversion" },
  {   9, "activationStatusNotificationDiv" },
  {  10, "deactivationStatusNotificationDiv" },
  {  11, "interrogationDiversion" },
  {  17, "interrogateServedUserNumbers" },
  {  12, "diversionInformation" },
  {  13, "callDeflection" },
  {  14, "callRerouteing" },
  {  18, "divertingLegInformation1" },
  {  15, "divertingLegInformation2" },
  {  19, "divertingLegInformation3" },

/*--- End of included file: packet-isdn-sup-table10.c ---*/
#line 59 "../../asn1/isdn-sup/packet-isdn-sup-template.c"
  {   0, NULL}
};

#if 0
static const value_string isdn_sup_str_error[] = {

/*--- Included file: packet-isdn-sup-table20.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-table20.c"
/* Unknown or empty loop list ERROR */

/*--- End of included file: packet-isdn-sup-table20.c ---*/
#line 65 "../../asn1/isdn-sup/packet-isdn-sup-template.c"
  {   0, NULL}
};
#endif
static int hf_isdn_sup = -1;


/*--- Included file: packet-isdn-sup-hf.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-hf.c"
static int hf_isdn_sup_ActivationDiversionArg_PDU = -1;  /* ActivationDiversionArg */
static int hf_isdn_sup_DeactivationDiversionArg_PDU = -1;  /* DeactivationDiversionArg */
static int hf_isdn_sup_ActivationStatusNotificationDivArg_PDU = -1;  /* ActivationStatusNotificationDivArg */
static int hf_isdn_sup_DeactivationStatusNotificationDivArg_PDU = -1;  /* DeactivationStatusNotificationDivArg */
static int hf_isdn_sup_InterrogationDiversionArg_PDU = -1;  /* InterrogationDiversionArg */
static int hf_isdn_sup_InterrogationDiversionRes_PDU = -1;  /* InterrogationDiversionRes */
static int hf_isdn_sup_InterrogateServedUserNumbersRes_PDU = -1;  /* InterrogateServedUserNumbersRes */
static int hf_isdn_sup_DiversionInformationArg_PDU = -1;  /* DiversionInformationArg */
static int hf_isdn_sup_CallDeflectionArg_PDU = -1;  /* CallDeflectionArg */
static int hf_isdn_sup_CallRerouteingArg_PDU = -1;  /* CallRerouteingArg */
static int hf_isdn_sup_DivertingLegInformation1Arg_PDU = -1;  /* DivertingLegInformation1Arg */
static int hf_isdn_sup_DivertingLegInformation2Arg_PDU = -1;  /* DivertingLegInformation2Arg */
static int hf_isdn_sup_DivertingLegInformation3Arg_PDU = -1;  /* DivertingLegInformation3Arg */
static int hf_isdn_sup_presentationAllowedAddress = -1;  /* AddressScreened */
static int hf_isdn_sup_presentationRestricted = -1;  /* NULL */
static int hf_isdn_sup_numberNotAvailableDueToInterworking = -1;  /* NULL */
static int hf_isdn_sup_presentationRestrictedAddress = -1;  /* AddressScreened */
static int hf_isdn_sup_presentationAllowedAddress_01 = -1;  /* Address */
static int hf_isdn_sup_presentationRestrictedAddress_01 = -1;  /* Address */
static int hf_isdn_sup_presentationAllowedNumber = -1;  /* NumberScreened */
static int hf_isdn_sup_presentationRestrictedNumber = -1;  /* NumberScreened */
static int hf_isdn_sup_presentationAllowedNumber_01 = -1;  /* PartyNumber */
static int hf_isdn_sup_presentationRestrictedNumber_01 = -1;  /* PartyNumber */
static int hf_isdn_sup_partyNumber = -1;          /* PartyNumber */
static int hf_isdn_sup_screeningIndicator = -1;   /* ScreeningIndicator */
static int hf_isdn_sup_partySubaddress = -1;      /* PartySubaddress */
static int hf_isdn_sup_unknownPartyNumber = -1;   /* NumberDigits */
static int hf_isdn_sup_publicPartyNumber = -1;    /* PublicPartyNumber */
static int hf_isdn_sup_nsapEncodedNumber = -1;    /* NsapEncodedNumber */
static int hf_isdn_sup_dataPartyNumber = -1;      /* NumberDigits */
static int hf_isdn_sup_telexPartyNumber = -1;     /* NumberDigits */
static int hf_isdn_sup_privatePartyNumber = -1;   /* PrivatePartyNumber */
static int hf_isdn_sup_nationalStandardPartyNumber = -1;  /* NumberDigits */
static int hf_isdn_sup_publicTypeOfNumber = -1;   /* PublicTypeOfNumber */
static int hf_isdn_sup_publicNumberDigits = -1;   /* NumberDigits */
static int hf_isdn_sup_privateTypeOfNumber = -1;  /* PrivateTypeOfNumber */
static int hf_isdn_sup_privateNumberDigits = -1;  /* NumberDigits */
static int hf_isdn_sup_userSpecifiedSubaddress = -1;  /* UserSpecifiedSubaddress */
static int hf_isdn_sup_nSAPSubaddress = -1;       /* NSAPSubaddress */
static int hf_isdn_sup_subaddressInformation = -1;  /* SubaddressInformation */
static int hf_isdn_sup_oddCountIndicator = -1;    /* BOOLEAN */
static int hf_isdn_sup_procedure = -1;            /* Procedure */
static int hf_isdn_sup_basicService = -1;         /* BasicService */
static int hf_isdn_sup_forwardedToAddress = -1;   /* Address */
static int hf_isdn_sup_servedUserNr = -1;         /* ServedUserNr */
static int hf_isdn_sup_noReplyTimer = -1;         /* NoReplyTimer */
static int hf_isdn_sup_forwardedToAddresss = -1;  /* Address */
static int hf_isdn_sup_diversionReason = -1;      /* DiversionReason */
static int hf_isdn_sup_servedUserSubaddress = -1;  /* PartySubaddress */
static int hf_isdn_sup_callingAddress = -1;       /* PresentedAddressScreened */
static int hf_isdn_sup_originalCalledNr = -1;     /* PresentedNumberUnscreened */
static int hf_isdn_sup_lastDivertingNr = -1;      /* PresentedNumberUnscreened */
static int hf_isdn_sup_lastDivertingReason = -1;  /* DiversionReason */
static int hf_isdn_sup_userInfo = -1;             /* Q931InformationElement */
static int hf_isdn_sup_deflectionAddress = -1;    /* Address */
static int hf_isdn_sup_presentationAllowedDivertedToUser = -1;  /* PresentationAllowedIndicator */
static int hf_isdn_sup_rerouteingReason = -1;     /* DiversionReason */
static int hf_isdn_sup_calledAddress = -1;        /* Address */
static int hf_isdn_sup_rerouteingCounter = -1;    /* DiversionCounter */
static int hf_isdn_sup_q931InfoElement = -1;      /* Q931InformationElement */
static int hf_isdn_sup_lastRerouteingNr = -1;     /* PresentedNumberUnscreened */
static int hf_isdn_sup_subscriptionOption = -1;   /* SubscriptionOption */
static int hf_isdn_sup_callingPartySubaddress = -1;  /* PartySubaddress */
static int hf_isdn_sup_divertedToNumber = -1;     /* PresentedNumberUnscreened */
static int hf_isdn_sup_diversionCounter = -1;     /* DiversionCounter */
static int hf_isdn_sup_divertingNr = -1;          /* PresentedNumberUnscreened */
static int hf_isdn_sup_IntResultList_item = -1;   /* IntResult */
static int hf_isdn_sup_individualNumber = -1;     /* PartyNumber */
static int hf_isdn_sup_allNumbers = -1;           /* NULL */
static int hf_isdn_sup_ServedUserNumberList_item = -1;  /* PartyNumber */

/*--- End of included file: packet-isdn-sup-hf.c ---*/
#line 71 "../../asn1/isdn-sup/packet-isdn-sup-template.c"


/* Initialize the subtree pointers */
static gint ett_isdn_sup = -1;


/*--- Included file: packet-isdn-sup-ett.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-ett.c"
static gint ett_isdn_sup_PresentedAddressScreened = -1;
static gint ett_isdn_sup_PresentedAddressUnscreened = -1;
static gint ett_isdn_sup_PresentedNumberScreened = -1;
static gint ett_isdn_sup_PresentedNumberUnscreened = -1;
static gint ett_isdn_sup_AddressScreened = -1;
static gint ett_isdn_sup_NumberScreened = -1;
static gint ett_isdn_sup_Address = -1;
static gint ett_isdn_sup_PartyNumber = -1;
static gint ett_isdn_sup_PublicPartyNumber = -1;
static gint ett_isdn_sup_PrivatePartyNumber = -1;
static gint ett_isdn_sup_PartySubaddress = -1;
static gint ett_isdn_sup_UserSpecifiedSubaddress = -1;
static gint ett_isdn_sup_ActivationDiversionArg = -1;
static gint ett_isdn_sup_DeactivationDiversionArg = -1;
static gint ett_isdn_sup_ActivationStatusNotificationDivArg = -1;
static gint ett_isdn_sup_DeactivationStatusNotificationDivArg = -1;
static gint ett_isdn_sup_InterrogationDiversionArg = -1;
static gint ett_isdn_sup_DiversionInformationArg = -1;
static gint ett_isdn_sup_CallDeflectionArg = -1;
static gint ett_isdn_sup_CallRerouteingArg = -1;
static gint ett_isdn_sup_DivertingLegInformation1Arg = -1;
static gint ett_isdn_sup_DivertingLegInformation2Arg = -1;
static gint ett_isdn_sup_IntResultList = -1;
static gint ett_isdn_sup_IntResult = -1;
static gint ett_isdn_sup_ServedUserNr = -1;
static gint ett_isdn_sup_ServedUserNumberList = -1;

/*--- End of included file: packet-isdn-sup-ett.c ---*/
#line 77 "../../asn1/isdn-sup/packet-isdn-sup-template.c"


/* Preference settings default */

/* Global variables */


/*--- Included file: packet-isdn-sup-fn.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-fn.c"


static int
dissect_isdn_sup_NumberDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string isdn_sup_PublicTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "internationalNumber" },
  {   2, "nationalNumber" },
  {   3, "networkSpecificNumber" },
  {   4, "subscriberNumber" },
  {   6, "abbreviatedNumber" },
  { 0, NULL }
};


static int
dissect_isdn_sup_PublicTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PublicPartyNumber_sequence[] = {
  { &hf_isdn_sup_publicTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PublicTypeOfNumber },
  { &hf_isdn_sup_publicNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PublicPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PublicPartyNumber_sequence, hf_index, ett_isdn_sup_PublicPartyNumber);

  return offset;
}



static int
dissect_isdn_sup_NsapEncodedNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string isdn_sup_PrivateTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "level2RegionalNumber" },
  {   2, "level1RegionalNumber" },
  {   3, "pTNSpecificNumber" },
  {   4, "localNumber" },
  {   6, "abbreviatedNumber" },
  { 0, NULL }
};


static int
dissect_isdn_sup_PrivateTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PrivatePartyNumber_sequence[] = {
  { &hf_isdn_sup_privateTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PrivateTypeOfNumber },
  { &hf_isdn_sup_privateNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PrivatePartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivatePartyNumber_sequence, hf_index, ett_isdn_sup_PrivatePartyNumber);

  return offset;
}


static const value_string isdn_sup_PartyNumber_vals[] = {
  {   0, "unknownPartyNumber" },
  {   1, "publicPartyNumber" },
  {   2, "nsapEncodedNumber" },
  {   3, "dataPartyNumber" },
  {   4, "telexPartyNumber" },
  {   5, "privatePartyNumber" },
  {   8, "nationalStandardPartyNumber" },
  { 0, NULL }
};

static const ber_choice_t PartyNumber_choice[] = {
  {   0, &hf_isdn_sup_unknownPartyNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NumberDigits },
  {   1, &hf_isdn_sup_publicPartyNumber, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_PublicPartyNumber },
  {   2, &hf_isdn_sup_nsapEncodedNumber, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NsapEncodedNumber },
  {   3, &hf_isdn_sup_dataPartyNumber, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NumberDigits },
  {   4, &hf_isdn_sup_telexPartyNumber, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NumberDigits },
  {   5, &hf_isdn_sup_privatePartyNumber, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_isdn_sup_PrivatePartyNumber },
  {   8, &hf_isdn_sup_nationalStandardPartyNumber, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NumberDigits },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PartyNumber_choice, hf_index, ett_isdn_sup_PartyNumber,
                                 NULL);

  return offset;
}


static const value_string isdn_sup_ScreeningIndicator_vals[] = {
  {   0, "userProvidedNotScreened" },
  {   1, "userProvidedVerifiedAndPassed" },
  {   2, "userProvidedVerifiedAndFailed" },
  {   3, "networkProvided" },
  { 0, NULL }
};


static int
dissect_isdn_sup_ScreeningIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_SubaddressInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_isdn_sup_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UserSpecifiedSubaddress_sequence[] = {
  { &hf_isdn_sup_subaddressInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_SubaddressInformation },
  { &hf_isdn_sup_oddCountIndicator, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_UserSpecifiedSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserSpecifiedSubaddress_sequence, hf_index, ett_isdn_sup_UserSpecifiedSubaddress);

  return offset;
}



static int
dissect_isdn_sup_NSAPSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string isdn_sup_PartySubaddress_vals[] = {
  {   0, "userSpecifiedSubaddress" },
  {   1, "nSAPSubaddress" },
  { 0, NULL }
};

static const ber_choice_t PartySubaddress_choice[] = {
  {   0, &hf_isdn_sup_userSpecifiedSubaddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_UserSpecifiedSubaddress },
  {   1, &hf_isdn_sup_nSAPSubaddress, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NSAPSubaddress },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PartySubaddress_choice, hf_index, ett_isdn_sup_PartySubaddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t AddressScreened_sequence[] = {
  { &hf_isdn_sup_partyNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartyNumber },
  { &hf_isdn_sup_screeningIndicator, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_ScreeningIndicator },
  { &hf_isdn_sup_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_AddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddressScreened_sequence, hf_index, ett_isdn_sup_AddressScreened);

  return offset;
}



static int
dissect_isdn_sup_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const value_string isdn_sup_PresentedAddressScreened_vals[] = {
  {   0, "presentationAllowedAddress" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedAddress" },
  { 0, NULL }
};

static const ber_choice_t PresentedAddressScreened_choice[] = {
  {   0, &hf_isdn_sup_presentationAllowedAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_isdn_sup_AddressScreened },
  {   1, &hf_isdn_sup_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   2, &hf_isdn_sup_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   3, &hf_isdn_sup_presentationRestrictedAddress, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_isdn_sup_AddressScreened },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PresentedAddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedAddressScreened_choice, hf_index, ett_isdn_sup_PresentedAddressScreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t Address_sequence[] = {
  { &hf_isdn_sup_partyNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartyNumber },
  { &hf_isdn_sup_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Address_sequence, hf_index, ett_isdn_sup_Address);

  return offset;
}





static const value_string isdn_sup_PresentedNumberUnscreened_vals[] = {
  {   0, "presentationAllowedNumber" },
  {   1, "presentationRestricted" },
  {   2, "numberNotAvailableDueToInterworking" },
  {   3, "presentationRestrictedNumber" },
  { 0, NULL }
};

static const ber_choice_t PresentedNumberUnscreened_choice[] = {
  {   0, &hf_isdn_sup_presentationAllowedNumber_01, BER_CLASS_CON, 0, 0, dissect_isdn_sup_PartyNumber },
  {   1, &hf_isdn_sup_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   2, &hf_isdn_sup_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_isdn_sup_NULL },
  {   3, &hf_isdn_sup_presentationRestrictedNumber_01, BER_CLASS_CON, 3, 0, dissect_isdn_sup_PartyNumber },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_PresentedNumberUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedNumberUnscreened_choice, hf_index, ett_isdn_sup_PresentedNumberUnscreened,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_PresentationAllowedIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string isdn_sup_BasicService_vals[] = {
  {   0, "allServices" },
  {   1, "speech" },
  {   2, "unrestrictedDigitalInformation" },
  {   3, "audio3k1Hz" },
  {   4, "unrestrictedDigitalInformationWithTonesAndAnnouncements" },
  {   5, "multirate" },
  {  32, "telephony3k1Hz" },
  {  33, "teletex" },
  {  34, "telefaxGroup4Class1" },
  {  35, "videotexSyntaxBased" },
  {  36, "videotelephony" },
  {  37, "telefaxGroup2-3" },
  {  38, "telephony7kHz" },
  {  39, "euroFileTransfer" },
  {  40, "fileTransferAndAccessManagement" },
  {  41, "videoconference" },
  {  42, "audioGraphicConference" },
  { 0, NULL }
};


static int
dissect_isdn_sup_BasicService(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_isdn_sup_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_isdn_sup_Q931InformationElement(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_APP, 0, TRUE, dissect_isdn_sup_OCTET_STRING);

  return offset;
}


static const value_string isdn_sup_Procedure_vals[] = {
  {   0, "cfu" },
  {   1, "cfb" },
  {   2, "cfnr" },
  { 0, NULL }
};


static int
dissect_isdn_sup_Procedure(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const value_string isdn_sup_ServedUserNr_vals[] = {
  {   0, "individualNumber" },
  {   1, "allNumbers" },
  { 0, NULL }
};

static const ber_choice_t ServedUserNr_choice[] = {
  {   0, &hf_isdn_sup_individualNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PartyNumber },
  {   1, &hf_isdn_sup_allNumbers , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NULL },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_ServedUserNr(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 ServedUserNr_choice, hf_index, ett_isdn_sup_ServedUserNr,
                                 NULL);

  return offset;
}



static int
dissect_isdn_sup_NoReplyTimer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t ActivationDiversionArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_forwardedToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { &hf_isdn_sup_noReplyTimer, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_NoReplyTimer },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_ActivationDiversionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActivationDiversionArg_sequence, hf_index, ett_isdn_sup_ActivationDiversionArg);

  return offset;
}


static const ber_sequence_t DeactivationDiversionArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DeactivationDiversionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeactivationDiversionArg_sequence, hf_index, ett_isdn_sup_DeactivationDiversionArg);

  return offset;
}


static const ber_sequence_t ActivationStatusNotificationDivArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_forwardedToAddresss, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_ActivationStatusNotificationDivArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ActivationStatusNotificationDivArg_sequence, hf_index, ett_isdn_sup_ActivationStatusNotificationDivArg);

  return offset;
}


static const ber_sequence_t DeactivationStatusNotificationDivArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DeactivationStatusNotificationDivArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DeactivationStatusNotificationDivArg_sequence, hf_index, ett_isdn_sup_DeactivationStatusNotificationDivArg);

  return offset;
}


static const ber_sequence_t InterrogationDiversionArg_sequence[] = {
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_InterrogationDiversionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   InterrogationDiversionArg_sequence, hf_index, ett_isdn_sup_InterrogationDiversionArg);

  return offset;
}


static const ber_sequence_t IntResult_sequence[] = {
  { &hf_isdn_sup_servedUserNr, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_ServedUserNr },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_procedure  , BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Procedure },
  { &hf_isdn_sup_forwardedToAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_IntResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   IntResult_sequence, hf_index, ett_isdn_sup_IntResult);

  return offset;
}


static const ber_sequence_t IntResultList_set_of[1] = {
  { &hf_isdn_sup_IntResultList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_IntResult },
};

static int
dissect_isdn_sup_IntResultList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 IntResultList_set_of, hf_index, ett_isdn_sup_IntResultList);

  return offset;
}



static int
dissect_isdn_sup_InterrogationDiversionRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_IntResultList(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t ServedUserNumberList_set_of[1] = {
  { &hf_isdn_sup_ServedUserNumberList_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartyNumber },
};

static int
dissect_isdn_sup_ServedUserNumberList(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 ServedUserNumberList_set_of, hf_index, ett_isdn_sup_ServedUserNumberList);

  return offset;
}



static int
dissect_isdn_sup_InterrogateServedUserNumbersRes(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_ServedUserNumberList(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string isdn_sup_DiversionReason_vals[] = {
  {   0, "unknown" },
  {   1, "cfu" },
  {   2, "cfb" },
  {   3, "cfnr" },
  {   4, "cdAlerting" },
  {   5, "cdImmediate" },
  { 0, NULL }
};


static int
dissect_isdn_sup_DiversionReason(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t DiversionInformationArg_sequence[] = {
  { &hf_isdn_sup_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_basicService, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_BasicService },
  { &hf_isdn_sup_servedUserSubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartySubaddress },
  { &hf_isdn_sup_callingAddress, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedAddressScreened },
  { &hf_isdn_sup_originalCalledNr, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { &hf_isdn_sup_lastDivertingNr, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { &hf_isdn_sup_lastDivertingReason, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_userInfo   , BER_CLASS_APP, 0, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Q931InformationElement },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DiversionInformationArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DiversionInformationArg_sequence, hf_index, ett_isdn_sup_DiversionInformationArg);

  return offset;
}


static const ber_sequence_t CallDeflectionArg_sequence[] = {
  { &hf_isdn_sup_deflectionAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { &hf_isdn_sup_presentationAllowedDivertedToUser, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_isdn_sup_PresentationAllowedIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_CallDeflectionArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallDeflectionArg_sequence, hf_index, ett_isdn_sup_CallDeflectionArg);

  return offset;
}



static int
dissect_isdn_sup_DiversionCounter(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const value_string isdn_sup_SubscriptionOption_vals[] = {
  {   0, "noNotification" },
  {   1, "notificationWithoutDivertedToNr" },
  {   2, "notificationWithDivertedToNr" },
  { 0, NULL }
};


static int
dissect_isdn_sup_SubscriptionOption(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t CallRerouteingArg_sequence[] = {
  { &hf_isdn_sup_rerouteingReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_calledAddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Address },
  { &hf_isdn_sup_rerouteingCounter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionCounter },
  { &hf_isdn_sup_q931InfoElement, BER_CLASS_APP, 0, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_Q931InformationElement },
  { &hf_isdn_sup_lastRerouteingNr, BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { &hf_isdn_sup_subscriptionOption, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_isdn_sup_SubscriptionOption },
  { &hf_isdn_sup_callingPartySubaddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_CallRerouteingArg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   CallRerouteingArg_sequence, hf_index, ett_isdn_sup_CallRerouteingArg);

  return offset;
}


static const ber_sequence_t DivertingLegInformation1Arg_sequence[] = {
  { &hf_isdn_sup_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_subscriptionOption, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_SubscriptionOption },
  { &hf_isdn_sup_divertedToNumber, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DivertingLegInformation1Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DivertingLegInformation1Arg_sequence, hf_index, ett_isdn_sup_DivertingLegInformation1Arg);

  return offset;
}


static const ber_sequence_t DivertingLegInformation2Arg_sequence[] = {
  { &hf_isdn_sup_diversionCounter, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionCounter },
  { &hf_isdn_sup_diversionReason, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_isdn_sup_DiversionReason },
  { &hf_isdn_sup_divertingNr, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { &hf_isdn_sup_originalCalledNr, BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_isdn_sup_PresentedNumberUnscreened },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_isdn_sup_DivertingLegInformation2Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DivertingLegInformation2Arg_sequence, hf_index, ett_isdn_sup_DivertingLegInformation2Arg);

  return offset;
}



static int
dissect_isdn_sup_DivertingLegInformation3Arg(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_isdn_sup_PresentationAllowedIndicator(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}

/*--- PDUs ---*/

static int dissect_ActivationDiversionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_ActivationDiversionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_ActivationDiversionArg_PDU);
  return offset;
}
static int dissect_DeactivationDiversionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DeactivationDiversionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DeactivationDiversionArg_PDU);
  return offset;
}
static int dissect_ActivationStatusNotificationDivArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_ActivationStatusNotificationDivArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_ActivationStatusNotificationDivArg_PDU);
  return offset;
}
static int dissect_DeactivationStatusNotificationDivArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DeactivationStatusNotificationDivArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DeactivationStatusNotificationDivArg_PDU);
  return offset;
}
static int dissect_InterrogationDiversionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_InterrogationDiversionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_InterrogationDiversionArg_PDU);
  return offset;
}
static int dissect_InterrogationDiversionRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_InterrogationDiversionRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_InterrogationDiversionRes_PDU);
  return offset;
}
static int dissect_InterrogateServedUserNumbersRes_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_InterrogateServedUserNumbersRes(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_InterrogateServedUserNumbersRes_PDU);
  return offset;
}
static int dissect_DiversionInformationArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DiversionInformationArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DiversionInformationArg_PDU);
  return offset;
}
static int dissect_CallDeflectionArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_CallDeflectionArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_CallDeflectionArg_PDU);
  return offset;
}
static int dissect_CallRerouteingArg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_CallRerouteingArg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_CallRerouteingArg_PDU);
  return offset;
}
static int dissect_DivertingLegInformation1Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DivertingLegInformation1Arg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DivertingLegInformation1Arg_PDU);
  return offset;
}
static int dissect_DivertingLegInformation2Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DivertingLegInformation2Arg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DivertingLegInformation2Arg_PDU);
  return offset;
}
static int dissect_DivertingLegInformation3Arg_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  offset = dissect_isdn_sup_DivertingLegInformation3Arg(FALSE, tvb, offset, &asn1_ctx, tree, hf_isdn_sup_DivertingLegInformation3Arg_PDU);
  return offset;
}


/*--- End of included file: packet-isdn-sup-fn.c ---*/
#line 84 "../../asn1/isdn-sup/packet-isdn-sup-template.c"

static const isdn_sup_op_t isdn_sup_op_tab[] = {

/*--- Included file: packet-isdn-sup-table11.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-table11.c"
  /* activationDiversion      */ {   7, dissect_ActivationDiversionArg_PDU, NULL },
  /* deactivationDiversion    */ {   8, dissect_DeactivationDiversionArg_PDU, NULL },
  /* activationStatusNotificationDiv */ {   9, dissect_ActivationStatusNotificationDivArg_PDU, NULL },
  /* deactivationStatusNotificationDiv */ {  10, dissect_DeactivationStatusNotificationDivArg_PDU, NULL },
  /* interrogationDiversion   */ {  11, dissect_InterrogationDiversionArg_PDU, dissect_InterrogationDiversionRes_PDU },
  /* interrogateServedUserNumbers */ {  17, NULL, dissect_InterrogateServedUserNumbersRes_PDU },
  /* diversionInformation     */ {  12, dissect_DiversionInformationArg_PDU, NULL },
  /* callDeflection           */ {  13, dissect_CallDeflectionArg_PDU, NULL },
  /* callRerouteing           */ {  14, dissect_CallRerouteingArg_PDU, NULL },
  /* divertingLegInformation1 */ {  18, dissect_DivertingLegInformation1Arg_PDU, NULL },
  /* divertingLegInformation2 */ {  15, dissect_DivertingLegInformation2Arg_PDU, NULL },
  /* divertingLegInformation3 */ {  19, dissect_DivertingLegInformation3Arg_PDU, NULL },

/*--- End of included file: packet-isdn-sup-table11.c ---*/
#line 87 "../../asn1/isdn-sup/packet-isdn-sup-template.c"
};

#if 0
static const isdn_sup_err_t isdn_sup_err_tab[] = {

/*--- Included file: packet-isdn-sup-table21.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-table21.c"
/* Unknown or empty loop list ERROR */

/*--- End of included file: packet-isdn-sup-table21.c ---*/
#line 92 "../../asn1/isdn-sup/packet-isdn-sup-template.c"
};
#endif

static const isdn_sup_op_t *get_op(gint32 opcode) {
  int i;

  /* search from the end to get the last occurence if the operation is redefined in some newer specification */
  for (i = array_length(isdn_sup_op_tab) - 1; i >= 0; i--)
    if (isdn_sup_op_tab[i].opcode == opcode)
      return &isdn_sup_op_tab[i];
  return NULL;
}

/*--- dissect_isdn_sup_arg ------------------------------------------------------*/
static int
dissect_isdn_sup_arg(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  int offset;
  rose_ctx_t *rctx;
  gint32 opcode = 0;
  const gchar *p;
  const isdn_sup_op_t *op_ptr;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rctx);
  if (rctx->d.pdu != 1)  /* invoke */
    return offset;
  if (rctx->d.code == 0) {  /* local */
    opcode = rctx->d.code_local;
  } else {
    return offset;
  }
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, tvb_length(tvb), ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_operation, tvb, 0, 0, opcode);
  p = match_strval(opcode, VALS(isdn_sup_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->arg_pdu)
    offset = op_ptr->arg_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(isdn_sup_tree, tvb, offset, -1, "UNSUPPORTED ARGUMENT TYPE (ETSI Sup)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}

/*--- dissect_isdn_sup_res -------------------------------------------------------*/
static int
dissect_isdn_sup_res(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_) {
  gint offset;
  rose_ctx_t *rctx;
  gint32 opcode = 0;
  const gchar *p;
  const isdn_sup_op_t *op_ptr;
  proto_item *ti;
  proto_tree *isdn_sup_tree;

  offset = 0;
  rctx = get_rose_ctx(pinfo->private_data);
  DISSECTOR_ASSERT(rctx);
  if (rctx->d.pdu != 2)  /* returnResult */
    return offset;
  if (rctx->d.code != 0)  /* local */
    return offset;
  opcode = rctx->d.code_local;
  op_ptr = get_op(opcode);
  if (!op_ptr)
    return offset;

  ti = proto_tree_add_item(tree, proto_isdn_sup, tvb, offset, tvb_length(tvb), ENC_NA);
  isdn_sup_tree = proto_item_add_subtree(ti, ett_isdn_sup);

  proto_tree_add_uint(isdn_sup_tree, hf_isdn_sup_operation, tvb, 0, 0, opcode);
  p = match_strval(opcode, VALS(isdn_sup_str_operation));
  if (p) {
    proto_item_append_text(ti, ": %s", p);
    proto_item_append_text(rctx->d.code_item, " - %s", p);
    if (rctx->apdu_depth >= 0)
      proto_item_append_text(proto_item_get_parent_nth(proto_tree_get_parent(tree), rctx->apdu_depth), " %s", p);
  }

  if (op_ptr->res_pdu)
    offset = op_ptr->res_pdu(tvb, pinfo, isdn_sup_tree, NULL);
  else
    if (tvb_length_remaining(tvb, offset) > 0) {
      proto_tree_add_text(isdn_sup_tree, tvb, offset, -1, "UNSUPPORTED RESULT TYPE (ETSI sup)");
      offset += tvb_length_remaining(tvb, offset);
    }

  return offset;
}




/*--- proto_reg_handoff_isdn_sup ---------------------------------------*/

void proto_reg_handoff_isdn_sup(void) {
  int i;
#if 0
  dissector_handle_t q931_handle;
#endif
  dissector_handle_t isdn_sup_arg_handle;
  dissector_handle_t isdn_sup_res_handle;

#if 0
  q931_handle = find_dissector("q931");
#endif

  isdn_sup_arg_handle = new_create_dissector_handle(dissect_isdn_sup_arg, proto_isdn_sup);
  isdn_sup_res_handle = new_create_dissector_handle(dissect_isdn_sup_res, proto_isdn_sup);
  for (i=0; i<(int)array_length(isdn_sup_op_tab); i++) {
    dissector_add_uint("q932.ros.etsi.local.arg", isdn_sup_op_tab[i].opcode, isdn_sup_arg_handle);
    dissector_add_uint("q932.ros.etsi.local.res", isdn_sup_op_tab[i].opcode, isdn_sup_res_handle);
  }

}

void proto_register_isdn_sup(void) {

	/* List of fields */
  static hf_register_info hf[] = {
    { &hf_isdn_sup,
      { "isdn_sup", "isdn_sup.1",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }
	},
    { &hf_isdn_sup_operation, 
	  { "Operation", "isdn_sup.operation",
        FT_UINT8, BASE_DEC, VALS(isdn_sup_str_operation), 0x0,
        NULL, HFILL }
	},

/*--- Included file: packet-isdn-sup-hfarr.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-hfarr.c"
    { &hf_isdn_sup_ActivationDiversionArg_PDU,
      { "ActivationDiversionArg", "isdn-sup.ActivationDiversionArg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DeactivationDiversionArg_PDU,
      { "DeactivationDiversionArg", "isdn-sup.DeactivationDiversionArg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_ActivationStatusNotificationDivArg_PDU,
      { "ActivationStatusNotificationDivArg", "isdn-sup.ActivationStatusNotificationDivArg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DeactivationStatusNotificationDivArg_PDU,
      { "DeactivationStatusNotificationDivArg", "isdn-sup.DeactivationStatusNotificationDivArg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_InterrogationDiversionArg_PDU,
      { "InterrogationDiversionArg", "isdn-sup.InterrogationDiversionArg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_InterrogationDiversionRes_PDU,
      { "InterrogationDiversionRes", "isdn-sup.InterrogationDiversionRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_InterrogateServedUserNumbersRes_PDU,
      { "InterrogateServedUserNumbersRes", "isdn-sup.InterrogateServedUserNumbersRes",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DiversionInformationArg_PDU,
      { "DiversionInformationArg", "isdn-sup.DiversionInformationArg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_CallDeflectionArg_PDU,
      { "CallDeflectionArg", "isdn-sup.CallDeflectionArg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_CallRerouteingArg_PDU,
      { "CallRerouteingArg", "isdn-sup.CallRerouteingArg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DivertingLegInformation1Arg_PDU,
      { "DivertingLegInformation1Arg", "isdn-sup.DivertingLegInformation1Arg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DivertingLegInformation2Arg_PDU,
      { "DivertingLegInformation2Arg", "isdn-sup.DivertingLegInformation2Arg",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_DivertingLegInformation3Arg_PDU,
      { "DivertingLegInformation3Arg", "isdn-sup.DivertingLegInformation3Arg",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_presentationAllowedAddress,
      { "presentationAllowedAddress", "isdn-sup.presentationAllowedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressScreened", HFILL }},
    { &hf_isdn_sup_presentationRestricted,
      { "presentationRestricted", "isdn-sup.presentationRestricted",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_numberNotAvailableDueToInterworking,
      { "numberNotAvailableDueToInterworking", "isdn-sup.numberNotAvailableDueToInterworking",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_presentationRestrictedAddress,
      { "presentationRestrictedAddress", "isdn-sup.presentationRestrictedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressScreened", HFILL }},
    { &hf_isdn_sup_presentationAllowedAddress_01,
      { "presentationAllowedAddress", "isdn-sup.presentationAllowedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_presentationRestrictedAddress_01,
      { "presentationRestrictedAddress", "isdn-sup.presentationRestrictedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_presentationAllowedNumber,
      { "presentationAllowedNumber", "isdn-sup.presentationAllowedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberScreened", HFILL }},
    { &hf_isdn_sup_presentationRestrictedNumber,
      { "presentationRestrictedNumber", "isdn-sup.presentationRestrictedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberScreened", HFILL }},
    { &hf_isdn_sup_presentationAllowedNumber_01,
      { "presentationAllowedNumber", "isdn-sup.presentationAllowedNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_isdn_sup_presentationRestrictedNumber_01,
      { "presentationRestrictedNumber", "isdn-sup.presentationRestrictedNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_isdn_sup_partyNumber,
      { "partyNumber", "isdn-sup.partyNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_screeningIndicator,
      { "screeningIndicator", "isdn-sup.screeningIndicator",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ScreeningIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_partySubaddress,
      { "partySubaddress", "isdn-sup.partySubaddress",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartySubaddress_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_unknownPartyNumber,
      { "unknownPartyNumber", "isdn-sup.unknownPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_publicPartyNumber,
      { "publicPartyNumber", "isdn-sup.publicPartyNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_nsapEncodedNumber,
      { "nsapEncodedNumber", "isdn-sup.nsapEncodedNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_dataPartyNumber,
      { "dataPartyNumber", "isdn-sup.dataPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_telexPartyNumber,
      { "telexPartyNumber", "isdn-sup.telexPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_privatePartyNumber,
      { "privatePartyNumber", "isdn-sup.privatePartyNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_nationalStandardPartyNumber,
      { "nationalStandardPartyNumber", "isdn-sup.nationalStandardPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_publicTypeOfNumber,
      { "publicTypeOfNumber", "isdn-sup.publicTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PublicTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_publicNumberDigits,
      { "publicNumberDigits", "isdn-sup.publicNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_privateTypeOfNumber,
      { "privateTypeOfNumber", "isdn-sup.privateTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PrivateTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_privateNumberDigits,
      { "privateNumberDigits", "isdn-sup.privateNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_isdn_sup_userSpecifiedSubaddress,
      { "userSpecifiedSubaddress", "isdn-sup.userSpecifiedSubaddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_nSAPSubaddress,
      { "nSAPSubaddress", "isdn-sup.nSAPSubaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_subaddressInformation,
      { "subaddressInformation", "isdn-sup.subaddressInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_oddCountIndicator,
      { "oddCountIndicator", "isdn-sup.oddCountIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_isdn_sup_procedure,
      { "procedure", "isdn-sup.procedure",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_Procedure_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_basicService,
      { "basicService", "isdn-sup.basicService",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_BasicService_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_forwardedToAddress,
      { "forwardedToAddress", "isdn-sup.forwardedToAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_servedUserNr,
      { "servedUserNr", "isdn-sup.servedUserNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_ServedUserNr_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_noReplyTimer,
      { "noReplyTimer", "isdn-sup.noReplyTimer",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_forwardedToAddresss,
      { "forwardedToAddresss", "isdn-sup.forwardedToAddresss",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_diversionReason,
      { "diversionReason", "isdn-sup.diversionReason",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_DiversionReason_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_servedUserSubaddress,
      { "servedUserSubaddress", "isdn-sup.servedUserSubaddress",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_isdn_sup_callingAddress,
      { "callingAddress", "isdn-sup.callingAddress",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedAddressScreened_vals), 0,
        "PresentedAddressScreened", HFILL }},
    { &hf_isdn_sup_originalCalledNr,
      { "originalCalledNr", "isdn-sup.originalCalledNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_lastDivertingNr,
      { "lastDivertingNr", "isdn-sup.lastDivertingNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_lastDivertingReason,
      { "lastDivertingReason", "isdn-sup.lastDivertingReason",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_isdn_sup_userInfo,
      { "userInfo", "isdn-sup.userInfo",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Q931InformationElement", HFILL }},
    { &hf_isdn_sup_deflectionAddress,
      { "deflectionAddress", "isdn-sup.deflectionAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_presentationAllowedDivertedToUser,
      { "presentationAllowedDivertedToUser", "isdn-sup.presentationAllowedDivertedToUser",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "PresentationAllowedIndicator", HFILL }},
    { &hf_isdn_sup_rerouteingReason,
      { "rerouteingReason", "isdn-sup.rerouteingReason",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_DiversionReason_vals), 0,
        "DiversionReason", HFILL }},
    { &hf_isdn_sup_calledAddress,
      { "calledAddress", "isdn-sup.calledAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_isdn_sup_rerouteingCounter,
      { "rerouteingCounter", "isdn-sup.rerouteingCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DiversionCounter", HFILL }},
    { &hf_isdn_sup_q931InfoElement,
      { "q931InfoElement", "isdn-sup.q931InfoElement",
        FT_BYTES, BASE_NONE, NULL, 0,
        "Q931InformationElement", HFILL }},
    { &hf_isdn_sup_lastRerouteingNr,
      { "lastRerouteingNr", "isdn-sup.lastRerouteingNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_subscriptionOption,
      { "subscriptionOption", "isdn-sup.subscriptionOption",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_SubscriptionOption_vals), 0,
        NULL, HFILL }},
    { &hf_isdn_sup_callingPartySubaddress,
      { "callingPartySubaddress", "isdn-sup.callingPartySubaddress",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartySubaddress_vals), 0,
        "PartySubaddress", HFILL }},
    { &hf_isdn_sup_divertedToNumber,
      { "divertedToNumber", "isdn-sup.divertedToNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_diversionCounter,
      { "diversionCounter", "isdn-sup.diversionCounter",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_divertingNr,
      { "divertingNr", "isdn-sup.divertingNr",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PresentedNumberUnscreened_vals), 0,
        "PresentedNumberUnscreened", HFILL }},
    { &hf_isdn_sup_IntResultList_item,
      { "IntResult", "isdn-sup.IntResult",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_individualNumber,
      { "individualNumber", "isdn-sup.individualNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_isdn_sup_allNumbers,
      { "allNumbers", "isdn-sup.allNumbers",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_isdn_sup_ServedUserNumberList_item,
      { "PartyNumber", "isdn-sup.PartyNumber",
        FT_UINT32, BASE_DEC, VALS(isdn_sup_PartyNumber_vals), 0,
        NULL, HFILL }},

/*--- End of included file: packet-isdn-sup-hfarr.c ---*/
#line 240 "../../asn1/isdn-sup/packet-isdn-sup-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_isdn_sup,


/*--- Included file: packet-isdn-sup-ettarr.c ---*/
#line 1 "../../asn1/isdn-sup/packet-isdn-sup-ettarr.c"
    &ett_isdn_sup_PresentedAddressScreened,
    &ett_isdn_sup_PresentedAddressUnscreened,
    &ett_isdn_sup_PresentedNumberScreened,
    &ett_isdn_sup_PresentedNumberUnscreened,
    &ett_isdn_sup_AddressScreened,
    &ett_isdn_sup_NumberScreened,
    &ett_isdn_sup_Address,
    &ett_isdn_sup_PartyNumber,
    &ett_isdn_sup_PublicPartyNumber,
    &ett_isdn_sup_PrivatePartyNumber,
    &ett_isdn_sup_PartySubaddress,
    &ett_isdn_sup_UserSpecifiedSubaddress,
    &ett_isdn_sup_ActivationDiversionArg,
    &ett_isdn_sup_DeactivationDiversionArg,
    &ett_isdn_sup_ActivationStatusNotificationDivArg,
    &ett_isdn_sup_DeactivationStatusNotificationDivArg,
    &ett_isdn_sup_InterrogationDiversionArg,
    &ett_isdn_sup_DiversionInformationArg,
    &ett_isdn_sup_CallDeflectionArg,
    &ett_isdn_sup_CallRerouteingArg,
    &ett_isdn_sup_DivertingLegInformation1Arg,
    &ett_isdn_sup_DivertingLegInformation2Arg,
    &ett_isdn_sup_IntResultList,
    &ett_isdn_sup_IntResult,
    &ett_isdn_sup_ServedUserNr,
    &ett_isdn_sup_ServedUserNumberList,

/*--- End of included file: packet-isdn-sup-ettarr.c ---*/
#line 247 "../../asn1/isdn-sup/packet-isdn-sup-template.c"
  };

  /* Register fields and subtrees */
  proto_register_field_array(proto_isdn_sup, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  /* Register protocol */
  proto_isdn_sup = proto_register_protocol(PNAME, PSNAME, PFNAME);

}
