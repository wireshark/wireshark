/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-q932.c                                                              */
/* ../../tools/asn2wrs.py -e -b -p q932 -c ./q932.cnf -s ./packet-q932-template -D . Addressing-Data-Elements.asn Network-Facility-Extension.asn Network-Protocol-Profile-component.asn Interpretation-component.asn */

/* Input file: packet-q932-template.c */

#line 1 "../../asn1/q932/packet-q932-template.c"
/* packet-q932.c
 * Routines for Q.932 packet dissection
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <epan/packet.h>
#include <epan/strutil.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-q932.h"

#define PNAME  "Q.932"
#define PSNAME "Q932"
#define PFNAME "q932"

/* Initialize the protocol and registered fields */
static int proto_q932 = -1;
static int hf_q932_ie_type = -1;
static int hf_q932_ie_len = -1;
static int hf_q932_ie_data = -1;
static int hf_q932_pp = -1;
static int hf_q932_nd = -1;

/*--- Included file: packet-q932-hf.c ---*/
#line 1 "../../asn1/q932/packet-q932-hf.c"
static int hf_q932_NetworkFacilityExtension_PDU = -1;  /* NetworkFacilityExtension */
static int hf_q932_NetworkProtocolProfile_PDU = -1;  /* NetworkProtocolProfile */
static int hf_q932_InterpretationComponent_PDU = -1;  /* InterpretationComponent */
static int hf_q932_presentationAlIowedAddress = -1;  /* AddressScreened */
static int hf_q932_presentationRestricted = -1;   /* NULL */
static int hf_q932_numberNotAvailableDueTolnterworking = -1;  /* NULL */
static int hf_q932_presentationRestrictedAddressScreened = -1;  /* AddressScreened */
static int hf_q932_presentationAllowedAddress = -1;  /* Address */
static int hf_q932_presentationRestrictedAddress = -1;  /* Address */
static int hf_q932_presentationAllowedNumberScreened = -1;  /* NumberScreened */
static int hf_q932_numberNotAvailableDueToInterworking = -1;  /* NULL */
static int hf_q932_presentationRestrictedNumberScreened = -1;  /* NumberScreened */
static int hf_q932_presentationAllowedNumber = -1;  /* PartyNumber */
static int hf_q932_presentationRestrictedNumber = -1;  /* PartyNumber */
static int hf_q932_partyNumber = -1;              /* PartyNumber */
static int hf_q932_screeninglndicator = -1;       /* ScreeningIndicator */
static int hf_q932_partySubaddress = -1;          /* PartySubaddress */
static int hf_q932_screeningIndicator = -1;       /* ScreeningIndicator */
static int hf_q932_unknownPartyNumber = -1;       /* NumberDigits */
static int hf_q932_publicPartyNumber = -1;        /* PublicPartyNumber */
static int hf_q932_nsapEncodedNumber = -1;        /* NsapEncodedNumber */
static int hf_q932_dataPartyNumber = -1;          /* NumberDigits */
static int hf_q932_telexPartyNumber = -1;         /* NumberDigits */
static int hf_q932_privatePartyNumber = -1;       /* PrivatePartyNumber */
static int hf_q932_nationalStandardPartyNumber = -1;  /* NumberDigits */
static int hf_q932_publicTypeOfNumber = -1;       /* PublicTypeOfNumber */
static int hf_q932_publicNumberDigits = -1;       /* NumberDigits */
static int hf_q932_privateTypeOfNumber = -1;      /* PrivateTypeOfNumber */
static int hf_q932_privateNumberDigits = -1;      /* NumberDigits */
static int hf_q932_userSpecifiedSubaddress = -1;  /* UserSpecifiedSubaddress */
static int hf_q932_nSAPSubaddress = -1;           /* NSAPSubaddress */
static int hf_q932_subaddressInformation = -1;    /* SubaddressInformation */
static int hf_q932_oddCountIndicator = -1;        /* BOOLEAN */
static int hf_q932_sourceEntity = -1;             /* EntityType */
static int hf_q932_sourceEntityAddress = -1;      /* AddressInformation */
static int hf_q932_destinationEntity = -1;        /* EntityType */
static int hf_q932_destinationEntityAddress = -1;  /* AddressInformation */

/*--- End of included file: packet-q932-hf.c ---*/
#line 49 "../../asn1/q932/packet-q932-template.c"

/* Initialize the subtree pointers */
static gint ett_q932 = -1;
static gint ett_q932_ie = -1;

/*--- Included file: packet-q932-ett.c ---*/
#line 1 "../../asn1/q932/packet-q932-ett.c"
static gint ett_q932_PresentedAddressScreened = -1;
static gint ett_q932_PresentedAddressUnscreened = -1;
static gint ett_q932_PresentedNumberScreened = -1;
static gint ett_q932_PresentedNumberUnscreened = -1;
static gint ett_q932_AddressScreened = -1;
static gint ett_q932_NumberScreened = -1;
static gint ett_q932_Address = -1;
static gint ett_q932_PartyNumber = -1;
static gint ett_q932_PublicPartyNumber = -1;
static gint ett_q932_PrivatePartyNumber = -1;
static gint ett_q932_PartySubaddress = -1;
static gint ett_q932_UserSpecifiedSubaddress = -1;
static gint ett_q932_NetworkFacilityExtension_U = -1;

/*--- End of included file: packet-q932-ett.c ---*/
#line 54 "../../asn1/q932/packet-q932-template.c"

/* Preferences */

/* ROSE context */
static rose_ctx_t q932_rose_ctx;

/* Subdissectors */
static dissector_handle_t q932_ros_handle; 

#define	Q932_IE_EXTENDED_FACILITY   0x0D
#define	Q932_IE_FACILITY            0x1C
#define	Q932_IE_NOTIFICATION_INDICATOR  0x27
#define	Q932_IE_INFORMATION_REQUEST 0x32
#define	Q932_IE_FEATURE_ACTIVATION  0x38
#define	Q932_IE_FEATURE_INDICATION  0x39
#define	Q932_IE_SERVICE_PROFILE_ID  0x3A
#define	Q932_IE_ENDPOINT_IDENTIFIER 0x3B
static const value_string q932_str_ie_type[] = {
  { Q932_IE_EXTENDED_FACILITY  , "Extended facility" },
  { Q932_IE_FACILITY           , "Facility" },
  { Q932_IE_NOTIFICATION_INDICATOR, "Notification indicator" },
  { Q932_IE_INFORMATION_REQUEST, "Information request" },
  { Q932_IE_FEATURE_ACTIVATION , "Feature activation" },
  { Q932_IE_FEATURE_INDICATION , "Feature indication" },
  { Q932_IE_SERVICE_PROFILE_ID , "Service profile identification" },
  { Q932_IE_ENDPOINT_IDENTIFIER, "Endpoint identifier" },
  { 0, NULL}
};

static const value_string str_pp[] = {
  { 0x11  , "Remote Operations Protocol" },
  { 0x12  , "CMIP Protocol" },
  { 0x13  , "ACSE Protocol" },
  { 0x1F  , "Networking extensions" },
  { 0, NULL}
};

static const value_string str_nd[] = {
  { 0x00  , "User suspended" },
  { 0x01  , "User resume" },
  { 0x02  , "Bearer service change" },
  { 0x04  , "Call completion delay" },
  { 0x03  , "Discriminator for extension to ASN.1 encoded component" },
  { 0x40  , "Discriminator for extension to ASN.1 encoded component for ISO" },
  { 0x42  , "Conference established" },
  { 0x43  , "Conference disconnected" },
  { 0x44  , "Other party added" },
  { 0x45  , "Isolated" },
  { 0x46  , "Reattached" },
  { 0x47  , "Other party isolated" },
  { 0x48  , "Other party reattached" },
  { 0x49  , "Other party split" },
  { 0x4A  , "Other party disconnected" },
  { 0x4B  , "Conference floating" },
  { 0x4C  , "Conference disconnected, pre-emption" },
  { 0x4F  , "Conference floating, served user pre-empted" },
  { 0x60  , "Call is a waiting call" },
  { 0x68  , "Diversion activated" },
  { 0x69  , "call transferred, alerting" },
  { 0x6A  , "call transferred, answered" },
  { 0x6E  , "reverse charging (whole call)" },
  { 0x6F  , "reverse charging (for the rest of the call)" },
  { 0x74  , "service profile update" },
  { 0x79  , "Remote hold" },
  { 0x7A  , "Remote retrieval" },
  { 0x7B  , "Call is diverting" },
  { 0, NULL}
};


/*--- Included file: packet-q932-fn.c ---*/
#line 1 "../../asn1/q932/packet-q932-fn.c"


static int
dissect_q932_NumberDigits(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string q932_PublicTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "internationalNumber" },
  {   2, "nationalNumber" },
  {   3, "networkSpecificNumber" },
  {   4, "subscriberNumber" },
  {   6, "abbreviatedNumber" },
  { 0, NULL }
};


static int
dissect_q932_PublicTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PublicPartyNumber_sequence[] = {
  { &hf_q932_publicTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_q932_PublicTypeOfNumber },
  { &hf_q932_publicNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_q932_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_PublicPartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PublicPartyNumber_sequence, hf_index, ett_q932_PublicPartyNumber);

  return offset;
}



static int
dissect_q932_NsapEncodedNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const value_string q932_PrivateTypeOfNumber_vals[] = {
  {   0, "unknown" },
  {   1, "level2RegionalNumber" },
  {   2, "level1RegionalNumber" },
  {   3, "pTNSpecificNumber" },
  {   4, "localNumber" },
  {   6, "abbreviatedNumber" },
  { 0, NULL }
};


static int
dissect_q932_PrivateTypeOfNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const ber_sequence_t PrivatePartyNumber_sequence[] = {
  { &hf_q932_privateTypeOfNumber, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_q932_PrivateTypeOfNumber },
  { &hf_q932_privateNumberDigits, BER_CLASS_UNI, BER_UNI_TAG_NumericString, BER_FLAGS_NOOWNTAG, dissect_q932_NumberDigits },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_PrivatePartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PrivatePartyNumber_sequence, hf_index, ett_q932_PrivatePartyNumber);

  return offset;
}


static const ber_choice_t PartyNumber_choice[] = {
  {   0, &hf_q932_unknownPartyNumber, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_q932_NumberDigits },
  {   1, &hf_q932_publicPartyNumber, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_q932_PublicPartyNumber },
  {   2, &hf_q932_nsapEncodedNumber, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_q932_NsapEncodedNumber },
  {   3, &hf_q932_dataPartyNumber, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_q932_NumberDigits },
  {   4, &hf_q932_telexPartyNumber, BER_CLASS_CON, 4, BER_FLAGS_IMPLTAG, dissect_q932_NumberDigits },
  {   5, &hf_q932_privatePartyNumber, BER_CLASS_CON, 5, BER_FLAGS_IMPLTAG, dissect_q932_PrivatePartyNumber },
  {   8, &hf_q932_nationalStandardPartyNumber, BER_CLASS_CON, 8, BER_FLAGS_IMPLTAG, dissect_q932_NumberDigits },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_q932_PartyNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PartyNumber_choice, hf_index, ett_q932_PartyNumber,
                                 NULL);

  return offset;
}



int
dissect_q932_ScreeningIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_q932_SubaddressInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_q932_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const ber_sequence_t UserSpecifiedSubaddress_sequence[] = {
  { &hf_q932_subaddressInformation, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_q932_SubaddressInformation },
  { &hf_q932_oddCountIndicator, BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_q932_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_UserSpecifiedSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   UserSpecifiedSubaddress_sequence, hf_index, ett_q932_UserSpecifiedSubaddress);

  return offset;
}



static int
dissect_q932_NSAPSubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_choice_t PartySubaddress_choice[] = {
  {   0, &hf_q932_userSpecifiedSubaddress, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_q932_UserSpecifiedSubaddress },
  {   1, &hf_q932_nSAPSubaddress , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_q932_NSAPSubaddress },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_q932_PartySubaddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PartySubaddress_choice, hf_index, ett_q932_PartySubaddress,
                                 NULL);

  return offset;
}


static const ber_sequence_t AddressScreened_sequence[] = {
  { &hf_q932_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_PartyNumber },
  { &hf_q932_screeninglndicator, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_q932_ScreeningIndicator },
  { &hf_q932_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_AddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   AddressScreened_sequence, hf_index, ett_q932_AddressScreened);

  return offset;
}



static int
dissect_q932_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_choice_t PresentedAddressScreened_choice[] = {
  {   0, &hf_q932_presentationAlIowedAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_q932_AddressScreened },
  {   1, &hf_q932_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_q932_NULL },
  {   2, &hf_q932_numberNotAvailableDueTolnterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_q932_NULL },
  {   3, &hf_q932_presentationRestrictedAddressScreened, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_q932_AddressScreened },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_q932_PresentedAddressScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedAddressScreened_choice, hf_index, ett_q932_PresentedAddressScreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t Address_sequence[] = {
  { &hf_q932_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_PartyNumber },
  { &hf_q932_partySubaddress, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_PartySubaddress },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_q932_Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Address_sequence, hf_index, ett_q932_Address);

  return offset;
}


static const ber_choice_t PresentedAddressUnscreened_choice[] = {
  {   0, &hf_q932_presentationAllowedAddress, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_q932_Address },
  {   1, &hf_q932_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_q932_NULL },
  {   2, &hf_q932_numberNotAvailableDueTolnterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_q932_NULL },
  {   3, &hf_q932_presentationRestrictedAddress, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_q932_Address },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_q932_PresentedAddressUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedAddressUnscreened_choice, hf_index, ett_q932_PresentedAddressUnscreened,
                                 NULL);

  return offset;
}


static const ber_sequence_t NumberScreened_sequence[] = {
  { &hf_q932_partyNumber    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_q932_PartyNumber },
  { &hf_q932_screeningIndicator, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_q932_ScreeningIndicator },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_NumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NumberScreened_sequence, hf_index, ett_q932_NumberScreened);

  return offset;
}


static const ber_choice_t PresentedNumberScreened_choice[] = {
  {   0, &hf_q932_presentationAllowedNumberScreened, BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_q932_NumberScreened },
  {   1, &hf_q932_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_q932_NULL },
  {   2, &hf_q932_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_q932_NULL },
  {   3, &hf_q932_presentationRestrictedNumberScreened, BER_CLASS_CON, 3, BER_FLAGS_IMPLTAG, dissect_q932_NumberScreened },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_q932_PresentedNumberScreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedNumberScreened_choice, hf_index, ett_q932_PresentedNumberScreened,
                                 NULL);

  return offset;
}


static const ber_choice_t PresentedNumberUnscreened_choice[] = {
  {   0, &hf_q932_presentationAllowedNumber, BER_CLASS_CON, 0, 0, dissect_q932_PartyNumber },
  {   1, &hf_q932_presentationRestricted, BER_CLASS_CON, 1, BER_FLAGS_IMPLTAG, dissect_q932_NULL },
  {   2, &hf_q932_numberNotAvailableDueToInterworking, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_q932_NULL },
  {   3, &hf_q932_presentationRestrictedNumber, BER_CLASS_CON, 3, 0, dissect_q932_PartyNumber },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_q932_PresentedNumberUnscreened(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 PresentedNumberUnscreened_choice, hf_index, ett_q932_PresentedNumberUnscreened,
                                 NULL);

  return offset;
}



int
dissect_q932_PresentationAllowedIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string q932_EntityType_vals[] = {
  {   0, "endPINX" },
  {   1, "anyTypeOfPINX" },
  { 0, NULL }
};


static int
dissect_q932_EntityType(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_q932_AddressInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_q932_PartyNumber(implicit_tag, tvb, offset, actx, tree, hf_index);

  return offset;
}


static const ber_sequence_t NetworkFacilityExtension_U_sequence[] = {
  { &hf_q932_sourceEntity   , BER_CLASS_CON, 0, BER_FLAGS_IMPLTAG, dissect_q932_EntityType },
  { &hf_q932_sourceEntityAddress, BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_q932_AddressInformation },
  { &hf_q932_destinationEntity, BER_CLASS_CON, 2, BER_FLAGS_IMPLTAG, dissect_q932_EntityType },
  { &hf_q932_destinationEntityAddress, BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL|BER_FLAGS_NOTCHKTAG, dissect_q932_AddressInformation },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_q932_NetworkFacilityExtension_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NetworkFacilityExtension_U_sequence, hf_index, ett_q932_NetworkFacilityExtension_U);

  return offset;
}



static int
dissect_q932_NetworkFacilityExtension(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 10, TRUE, dissect_q932_NetworkFacilityExtension_U);

  return offset;
}


static const value_string q932_NetworkProtocolProfile_U_vals[] = {
  {  19, "acse" },
  {  32, "dse" },
  { 0, NULL }
};


static int
dissect_q932_NetworkProtocolProfile_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_q932_NetworkProtocolProfile(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 18, TRUE, dissect_q932_NetworkProtocolProfile_U);

  return offset;
}


static const value_string q932_InterpretationComponent_U_vals[] = {
  {   0, "discardAnyUnrecognisedInvokePdu" },
  {   1, "clearCallIfAnyInvokePduNotRecognised" },
  {   2, "rejectAnyUnrecognisedInvokePdu" },
  { 0, NULL }
};


static int
dissect_q932_InterpretationComponent_U(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



static int
dissect_q932_InterpretationComponent(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_tagged_type(implicit_tag, actx, tree, tvb, offset,
                                      hf_index, BER_CLASS_CON, 11, TRUE, dissect_q932_InterpretationComponent_U);

  return offset;
}

/*--- PDUs ---*/

static void dissect_NetworkFacilityExtension_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_q932_NetworkFacilityExtension(FALSE, tvb, 0, &asn1_ctx, tree, hf_q932_NetworkFacilityExtension_PDU);
}
static void dissect_NetworkProtocolProfile_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_q932_NetworkProtocolProfile(FALSE, tvb, 0, &asn1_ctx, tree, hf_q932_NetworkProtocolProfile_PDU);
}
static void dissect_InterpretationComponent_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_q932_InterpretationComponent(FALSE, tvb, 0, &asn1_ctx, tree, hf_q932_InterpretationComponent_PDU);
}


/*--- End of included file: packet-q932-fn.c ---*/
#line 124 "../../asn1/q932/packet-q932-template.c"

/*--- dissect_q932_facility_ie -------------------------------------------------------*/
/*static*/ void
dissect_q932_facility_ie(tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int length) {
  gint8 class;
  gboolean pc;
  gint32 tag;
  guint32 len;
  int hoffset, eoffset;
  int ie_end;
  tvbuff_t *next_tvb;

  ie_end = offset + length;
  proto_tree_add_item(tree, hf_q932_pp, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  while (offset < ie_end) {
    hoffset = offset;
    offset = get_ber_identifier(tvb, offset, &class, &pc, &tag);
    offset = get_ber_length(tvb, offset, &len, NULL);
    eoffset = offset + len;
    next_tvb =  tvb_new_subset(tvb, hoffset, eoffset - hoffset, eoffset - hoffset);
    switch (class) {
      case BER_CLASS_CON:
        switch (tag) {
          case 10 :  /* Network Facility Extension */
            dissect_NetworkFacilityExtension_PDU(next_tvb, pinfo, tree);
            break;
          case 18 :  /* Network Protocol Profile */
            dissect_NetworkProtocolProfile_PDU(next_tvb, pinfo, tree);
            break;
          case 11 :  /* Interpretation Component */
            dissect_InterpretationComponent_PDU(next_tvb, pinfo, tree);
            break;
          /* ROSE APDU */
          case  1 :  /* invoke */
          case  2 :  /* returnResult */
          case  3 :  /* returnError */
          case  4 :  /* reject */
            q932_rose_ctx.apdu_depth = 1;
            pinfo->private_data = &q932_rose_ctx;
            call_dissector(q932_ros_handle, next_tvb, pinfo, tree);
            break;
          /* DSE APDU */
          case 12 :  /* begin */
          case 14 :  /* end */
          case 15 :  /* continue */
          case 17 :  /* abort */
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_text(tree, tvb, offset, len, "DSE APDU (not supported)");
            break;
          default:
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_text(tree, tvb, offset, len, "Unknown Component");
        }
        break;
      case BER_CLASS_APP:
        switch (tag) {
          /* ACSE APDU */
          case  0 :  /* aarq */
          case  1 :  /* aare */
          case  2 :  /* rlrq */
          case  3 :  /* rlre */
          case  4 :  /* abrt */
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_text(tree, tvb, offset, len, "ACSE APDU (not supported)");
            break;
          default:
            offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
            offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
            proto_tree_add_text(tree, tvb, offset, len, "Unknown Component");
        }
        break;
      default:
        offset = dissect_ber_identifier(pinfo, tree, tvb, hoffset, NULL, NULL, NULL);
        offset = dissect_ber_length(pinfo, tree, tvb, offset, NULL, NULL);
        proto_tree_add_text(tree, tvb, offset, len, "Unknown Component");
    }
    offset = eoffset;
  }
}

/*--- dissect_q932_ni_ie -------------------------------------------------------*/
static void
dissect_q932_ni_ie(tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int length) {
  int remain = length;
  guint8 octet = 0;
  guint32 value = 0;

  while ((remain > 0) && !(octet & 0x80)) {
    octet = tvb_get_guint8(tvb, offset++);
    remain--;
    value <<= 7;
    value |= octet & 0x7F;
  }
  proto_tree_add_uint(tree, hf_q932_nd, tvb, offset - (length - remain), length - remain, value);

  if (remain > 0) {
    proto_tree_add_text(tree, tvb, offset - remain, remain, "ASN.1 Encoded Data Structure(NOT IMPLEMENTED): %s", tvb_bytes_to_str(tvb, offset - remain, remain));
  }
}

/*--- dissect_q932_ie -------------------------------------------------------*/
static void
dissect_q932_ie(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  gint offset;
  proto_item *ti, *ti_ie;
  proto_tree *ie_tree;
  guint8 ie_type, ie_len;

  offset = 0;

  ti = proto_tree_add_item(tree, proto_q932, tvb, offset, -1, ENC_NA);
  PROTO_ITEM_SET_HIDDEN(ti);

  ie_type = tvb_get_guint8(tvb, offset);
  ie_len = tvb_get_guint8(tvb, offset + 1);

  ti_ie = proto_tree_add_text(tree, tvb, offset, -1, "%s",
            val_to_str(ie_type, VALS(q932_str_ie_type), "unknown (0x%02X)"));
  ie_tree = proto_item_add_subtree(ti_ie, ett_q932_ie); 
  proto_tree_add_item(ie_tree, hf_q932_ie_type, tvb, offset, 1, ENC_BIG_ENDIAN);
  proto_tree_add_item(ie_tree, hf_q932_ie_len, tvb, offset + 1, 1, ENC_BIG_ENDIAN);
  offset += 2;
  if (tvb_length_remaining(tvb, offset) <= 0)
    return;
  switch (ie_type) {
    case Q932_IE_FACILITY :
      dissect_q932_facility_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    case Q932_IE_NOTIFICATION_INDICATOR :
      dissect_q932_ni_ie(tvb, offset, pinfo, ie_tree, ie_len);
      break;
    default:
      if (ie_len > 0) {
        if (tree) proto_tree_add_item(ie_tree, hf_q932_ie_data, tvb, offset, ie_len, ENC_NA);
      }
  }
}

/*--- dissect_q932_apdu -----------------------------------------------------*/
static void
dissect_q932_apdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  call_dissector(q932_ros_handle, tvb, pinfo, tree);
}

/*--- proto_register_q932 ---------------------------------------------------*/
void proto_register_q932(void) {

  /* List of fields */
  static hf_register_info hf[] = {
    { &hf_q932_ie_type, { "Type", "q932.ie.type",
                          FT_UINT8, BASE_HEX, VALS(q932_str_ie_type), 0x0,
                          "Information Element Type", HFILL }},
    { &hf_q932_ie_len,  { "Length", "q932.ie.len",
                          FT_UINT8, BASE_DEC, NULL, 0x0,
                          "Information Element Length", HFILL }},
    { &hf_q932_ie_data, { "Data", "q932.ie.data",
                          FT_BYTES, BASE_NONE, NULL, 0x0,
                          NULL, HFILL }},
    { &hf_q932_pp,      { "Protocol profile", "q932.pp",
                          FT_UINT8, BASE_HEX, VALS(str_pp), 0x1F,
                          NULL, HFILL }},
    { &hf_q932_nd,      { "Notification description", "q932.nd",
                          FT_UINT8, BASE_HEX, VALS(str_nd), 0x0,
                          NULL, HFILL }},

/*--- Included file: packet-q932-hfarr.c ---*/
#line 1 "../../asn1/q932/packet-q932-hfarr.c"
    { &hf_q932_NetworkFacilityExtension_PDU,
      { "NetworkFacilityExtension", "q932.NetworkFacilityExtension",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_NetworkProtocolProfile_PDU,
      { "NetworkProtocolProfile", "q932.NetworkProtocolProfile",
        FT_UINT32, BASE_DEC, VALS(q932_NetworkProtocolProfile_U_vals), 0,
        NULL, HFILL }},
    { &hf_q932_InterpretationComponent_PDU,
      { "InterpretationComponent", "q932.InterpretationComponent",
        FT_UINT32, BASE_DEC, VALS(q932_InterpretationComponent_U_vals), 0,
        NULL, HFILL }},
    { &hf_q932_presentationAlIowedAddress,
      { "presentationAlIowedAddress", "q932.presentationAlIowedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressScreened", HFILL }},
    { &hf_q932_presentationRestricted,
      { "presentationRestricted", "q932.presentationRestricted",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_numberNotAvailableDueTolnterworking,
      { "numberNotAvailableDueTolnterworking", "q932.numberNotAvailableDueTolnterworking",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_presentationRestrictedAddressScreened,
      { "presentationRestrictedAddress", "q932.presentationRestrictedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "AddressScreened", HFILL }},
    { &hf_q932_presentationAllowedAddress,
      { "presentationAllowedAddress", "q932.presentationAllowedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_q932_presentationRestrictedAddress,
      { "presentationRestrictedAddress", "q932.presentationRestrictedAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "Address", HFILL }},
    { &hf_q932_presentationAllowedNumberScreened,
      { "presentationAllowedNumber", "q932.presentationAllowedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberScreened", HFILL }},
    { &hf_q932_numberNotAvailableDueToInterworking,
      { "numberNotAvailableDueToInterworking", "q932.numberNotAvailableDueToInterworking",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_presentationRestrictedNumberScreened,
      { "presentationRestrictedNumber", "q932.presentationRestrictedNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "NumberScreened", HFILL }},
    { &hf_q932_presentationAllowedNumber,
      { "presentationAllowedNumber", "q932.presentationAllowedNumber",
        FT_UINT32, BASE_DEC, VALS(q932_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_q932_presentationRestrictedNumber,
      { "presentationRestrictedNumber", "q932.presentationRestrictedNumber",
        FT_UINT32, BASE_DEC, VALS(q932_PartyNumber_vals), 0,
        "PartyNumber", HFILL }},
    { &hf_q932_partyNumber,
      { "partyNumber", "q932.partyNumber",
        FT_UINT32, BASE_DEC, VALS(q932_PartyNumber_vals), 0,
        NULL, HFILL }},
    { &hf_q932_screeninglndicator,
      { "screeninglndicator", "q932.screeninglndicator",
        FT_UINT32, BASE_DEC, VALS(q932_ScreeningIndicator_vals), 0,
        "ScreeningIndicator", HFILL }},
    { &hf_q932_partySubaddress,
      { "partySubaddress", "q932.partySubaddress",
        FT_UINT32, BASE_DEC, VALS(q932_PartySubaddress_vals), 0,
        NULL, HFILL }},
    { &hf_q932_screeningIndicator,
      { "screeningIndicator", "q932.screeningIndicator",
        FT_UINT32, BASE_DEC, VALS(q932_ScreeningIndicator_vals), 0,
        NULL, HFILL }},
    { &hf_q932_unknownPartyNumber,
      { "unknownPartyNumber", "q932.unknownPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_q932_publicPartyNumber,
      { "publicPartyNumber", "q932.publicPartyNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_nsapEncodedNumber,
      { "nsapEncodedNumber", "q932.nsapEncodedNumber",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_dataPartyNumber,
      { "dataPartyNumber", "q932.dataPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_q932_telexPartyNumber,
      { "telexPartyNumber", "q932.telexPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_q932_privatePartyNumber,
      { "privatePartyNumber", "q932.privatePartyNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_nationalStandardPartyNumber,
      { "nationalStandardPartyNumber", "q932.nationalStandardPartyNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_q932_publicTypeOfNumber,
      { "publicTypeOfNumber", "q932.publicTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(q932_PublicTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_q932_publicNumberDigits,
      { "publicNumberDigits", "q932.publicNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_q932_privateTypeOfNumber,
      { "privateTypeOfNumber", "q932.privateTypeOfNumber",
        FT_UINT32, BASE_DEC, VALS(q932_PrivateTypeOfNumber_vals), 0,
        NULL, HFILL }},
    { &hf_q932_privateNumberDigits,
      { "privateNumberDigits", "q932.privateNumberDigits",
        FT_STRING, BASE_NONE, NULL, 0,
        "NumberDigits", HFILL }},
    { &hf_q932_userSpecifiedSubaddress,
      { "userSpecifiedSubaddress", "q932.userSpecifiedSubaddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_nSAPSubaddress,
      { "nSAPSubaddress", "q932.nSAPSubaddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_subaddressInformation,
      { "subaddressInformation", "q932.subaddressInformation",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_q932_oddCountIndicator,
      { "oddCountIndicator", "q932.oddCountIndicator",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_q932_sourceEntity,
      { "sourceEntity", "q932.sourceEntity",
        FT_UINT32, BASE_DEC, VALS(q932_EntityType_vals), 0,
        "EntityType", HFILL }},
    { &hf_q932_sourceEntityAddress,
      { "sourceEntityAddress", "q932.sourceEntityAddress",
        FT_UINT32, BASE_DEC, VALS(q932_PartyNumber_vals), 0,
        "AddressInformation", HFILL }},
    { &hf_q932_destinationEntity,
      { "destinationEntity", "q932.destinationEntity",
        FT_UINT32, BASE_DEC, VALS(q932_EntityType_vals), 0,
        "EntityType", HFILL }},
    { &hf_q932_destinationEntityAddress,
      { "destinationEntityAddress", "q932.destinationEntityAddress",
        FT_UINT32, BASE_DEC, VALS(q932_PartyNumber_vals), 0,
        "AddressInformation", HFILL }},

/*--- End of included file: packet-q932-hfarr.c ---*/
#line 293 "../../asn1/q932/packet-q932-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {
    &ett_q932,
    &ett_q932_ie,

/*--- Included file: packet-q932-ettarr.c ---*/
#line 1 "../../asn1/q932/packet-q932-ettarr.c"
    &ett_q932_PresentedAddressScreened,
    &ett_q932_PresentedAddressUnscreened,
    &ett_q932_PresentedNumberScreened,
    &ett_q932_PresentedNumberUnscreened,
    &ett_q932_AddressScreened,
    &ett_q932_NumberScreened,
    &ett_q932_Address,
    &ett_q932_PartyNumber,
    &ett_q932_PublicPartyNumber,
    &ett_q932_PrivatePartyNumber,
    &ett_q932_PartySubaddress,
    &ett_q932_UserSpecifiedSubaddress,
    &ett_q932_NetworkFacilityExtension_U,

/*--- End of included file: packet-q932-ettarr.c ---*/
#line 300 "../../asn1/q932/packet-q932-template.c"
  };

  /* Register protocol and dissector */
  proto_q932 = proto_register_protocol(PNAME, PSNAME, PFNAME);
  register_dissector("q932.apdu", dissect_q932_apdu, proto_q932);

  /* Register fields and subtrees */
  proto_register_field_array(proto_q932, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

  rose_ctx_init(&q932_rose_ctx);

  /* Register dissector tables */
  q932_rose_ctx.arg_global_dissector_table = register_dissector_table("q932.ros.global.arg", "Q.932 Operation Argument (global opcode)", FT_STRING, BASE_NONE);
  q932_rose_ctx.res_global_dissector_table = register_dissector_table("q932.ros.global.res", "Q.932 Operation Result (global opcode)", FT_STRING, BASE_NONE);
  q932_rose_ctx.arg_local_dissector_table = register_dissector_table("q932.ros.local.arg", "Q.932 Operation Argument (local opcode)", FT_UINT32, BASE_HEX); 
  q932_rose_ctx.res_local_dissector_table = register_dissector_table("q932.ros.local.res", "Q.932 Operation Result (local opcode)", FT_UINT32, BASE_HEX); 
  q932_rose_ctx.err_global_dissector_table = register_dissector_table("q932.ros.global.err", "Q.932 Error (global opcode)", FT_STRING, BASE_NONE);
  q932_rose_ctx.err_local_dissector_table = register_dissector_table("q932.ros.local.err", "Q.932 Error (local opcode)", FT_UINT32, BASE_HEX); 
}

/*--- proto_reg_handoff_q932 ------------------------------------------------*/
void proto_reg_handoff_q932(void) {
  dissector_handle_t q932_ie_handle;

  q932_ie_handle = create_dissector_handle(dissect_q932_ie, proto_q932);
  /* Facility */
  dissector_add_uint("q931.ie", (0x00 << 8) | Q932_IE_FACILITY, q932_ie_handle); 
  /* Notification indicator */
  dissector_add_uint("q931.ie", (0x00 << 8) | Q932_IE_NOTIFICATION_INDICATOR, q932_ie_handle); 

  q932_ros_handle = find_dissector("q932.ros");
}

/*---------------------------------------------------------------------------*/
