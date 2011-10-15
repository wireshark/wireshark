/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Wireshark dissector compiler   */
/* packet-x509sat.c                                                           */
/* ../../tools/asn2wrs.py -b -r Syntax -p x509sat -c ./x509sat.cnf -s ./packet-x509sat-template -D . -O ../../epan/dissectors SelectedAttributeTypes.asn */

/* Input file: packet-x509sat-template.c */

#line 1 "../../asn1/x509sat/packet-x509sat-template.c"
/* packet-x509sat.c
 * Routines for X.509 Selected Attribute Types packet dissection
 *  Ronnie Sahlberg 2004
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
#include <epan/oids.h>
#include <epan/asn1.h>

#include "packet-ber.h"
#include "packet-p1.h"
#include "packet-x509sat.h"
#include "packet-x509if.h"

#define PNAME  "X.509 Selected Attribute Types"
#define PSNAME "X509SAT"
#define PFNAME "x509sat"

/* Initialize the protocol and registered fields */
static int proto_x509sat = -1;

/*--- Included file: packet-x509sat-hf.c ---*/
#line 1 "../../asn1/x509sat/packet-x509sat-hf.c"
static int hf_x509sat_DirectoryString_PDU = -1;   /* DirectoryString */
static int hf_x509sat_UniqueIdentifier_PDU = -1;  /* UniqueIdentifier */
static int hf_x509sat_CountryName_PDU = -1;       /* CountryName */
static int hf_x509sat_Guide_PDU = -1;             /* Guide */
static int hf_x509sat_EnhancedGuide_PDU = -1;     /* EnhancedGuide */
static int hf_x509sat_PostalAddress_PDU = -1;     /* PostalAddress */
static int hf_x509sat_TelephoneNumber_PDU = -1;   /* TelephoneNumber */
static int hf_x509sat_TelexNumber_PDU = -1;       /* TelexNumber */
static int hf_x509sat_FacsimileTelephoneNumber_PDU = -1;  /* FacsimileTelephoneNumber */
static int hf_x509sat_X121Address_PDU = -1;       /* X121Address */
static int hf_x509sat_InternationalISDNNumber_PDU = -1;  /* InternationalISDNNumber */
static int hf_x509sat_DestinationIndicator_PDU = -1;  /* DestinationIndicator */
static int hf_x509sat_PreferredDeliveryMethod_PDU = -1;  /* PreferredDeliveryMethod */
static int hf_x509sat_PresentationAddress_PDU = -1;  /* PresentationAddress */
static int hf_x509sat_ProtocolInformation_PDU = -1;  /* ProtocolInformation */
static int hf_x509sat_NameAndOptionalUID_PDU = -1;  /* NameAndOptionalUID */
static int hf_x509sat_CaseIgnoreListMatch_PDU = -1;  /* CaseIgnoreListMatch */
static int hf_x509sat_ObjectIdentifier_PDU = -1;  /* ObjectIdentifier */
static int hf_x509sat_OctetString_PDU = -1;       /* OctetString */
static int hf_x509sat_BitString_PDU = -1;         /* BitString */
static int hf_x509sat_Integer_PDU = -1;           /* Integer */
static int hf_x509sat_Boolean_PDU = -1;           /* Boolean */
static int hf_x509sat_SyntaxGeneralizedTime_PDU = -1;  /* SyntaxGeneralizedTime */
static int hf_x509sat_SyntaxUTCTime_PDU = -1;     /* SyntaxUTCTime */
static int hf_x509sat_SyntaxNumericString_PDU = -1;  /* SyntaxNumericString */
static int hf_x509sat_SyntaxPrintableString_PDU = -1;  /* SyntaxPrintableString */
static int hf_x509sat_SyntaxIA5String_PDU = -1;   /* SyntaxIA5String */
static int hf_x509sat_SyntaxBMPString_PDU = -1;   /* SyntaxBMPString */
static int hf_x509sat_SyntaxUniversalString_PDU = -1;  /* SyntaxUniversalString */
static int hf_x509sat_SyntaxUTF8String_PDU = -1;  /* SyntaxUTF8String */
static int hf_x509sat_SyntaxTeletexString_PDU = -1;  /* SyntaxTeletexString */
static int hf_x509sat_SyntaxT61String_PDU = -1;   /* SyntaxT61String */
static int hf_x509sat_SyntaxVideotexString_PDU = -1;  /* SyntaxVideotexString */
static int hf_x509sat_SyntaxGraphicString_PDU = -1;  /* SyntaxGraphicString */
static int hf_x509sat_SyntaxISO646String_PDU = -1;  /* SyntaxISO646String */
static int hf_x509sat_SyntaxVisibleString_PDU = -1;  /* SyntaxVisibleString */
static int hf_x509sat_SyntaxGeneralString_PDU = -1;  /* SyntaxGeneralString */
static int hf_x509sat_GUID_PDU = -1;              /* GUID */
static int hf_x509sat_teletexString = -1;         /* TeletexString */
static int hf_x509sat_printableString = -1;       /* PrintableString */
static int hf_x509sat_universalString = -1;       /* UniversalString */
static int hf_x509sat_bmpString = -1;             /* BMPString */
static int hf_x509sat_uTF8String = -1;            /* UTF8String */
static int hf_x509sat_objectClass = -1;           /* OBJECT_IDENTIFIER */
static int hf_x509sat_criteria = -1;              /* Criteria */
static int hf_x509sat_type = -1;                  /* CriteriaItem */
static int hf_x509sat_and = -1;                   /* SET_OF_Criteria */
static int hf_x509sat_and_item = -1;              /* Criteria */
static int hf_x509sat_or = -1;                    /* SET_OF_Criteria */
static int hf_x509sat_or_item = -1;               /* Criteria */
static int hf_x509sat_not = -1;                   /* Criteria */
static int hf_x509sat_equality = -1;              /* AttributeType */
static int hf_x509sat_substrings = -1;            /* AttributeType */
static int hf_x509sat_greaterOrEqual = -1;        /* AttributeType */
static int hf_x509sat_lessOrEqual = -1;           /* AttributeType */
static int hf_x509sat_approximateMatch = -1;      /* AttributeType */
static int hf_x509sat_subset = -1;                /* T_subset */
static int hf_x509sat_PostalAddress_item = -1;    /* DirectoryString */
static int hf_x509sat_telexNumber = -1;           /* PrintableString */
static int hf_x509sat_countryCode = -1;           /* PrintableString */
static int hf_x509sat_answerback = -1;            /* PrintableString */
static int hf_x509sat_telephoneNumber = -1;       /* TelephoneNumber */
static int hf_x509sat_parameters = -1;            /* G3FacsimileNonBasicParameters */
static int hf_x509sat_PreferredDeliveryMethod_item = -1;  /* PreferredDeliveryMethod_item */
static int hf_x509sat_pSelector = -1;             /* OCTET_STRING */
static int hf_x509sat_sSelector = -1;             /* OCTET_STRING */
static int hf_x509sat_tSelector = -1;             /* OCTET_STRING */
static int hf_x509sat_nAddresses = -1;            /* T_nAddresses */
static int hf_x509sat_nAddresses_item = -1;       /* OCTET_STRING */
static int hf_x509sat_nAddress = -1;              /* OCTET_STRING */
static int hf_x509sat_profiles = -1;              /* T_profiles */
static int hf_x509sat_profiles_item = -1;         /* OBJECT_IDENTIFIER */
static int hf_x509sat_dn = -1;                    /* DistinguishedName */
static int hf_x509sat_uid = -1;                   /* UniqueIdentifier */
static int hf_x509sat_matchingRuleUsed = -1;      /* OBJECT_IDENTIFIER */
static int hf_x509sat_attributeList = -1;         /* SEQUENCE_OF_AttributeValueAssertion */
static int hf_x509sat_attributeList_item = -1;    /* AttributeValueAssertion */
static int hf_x509sat_SubstringAssertion_item = -1;  /* SubstringAssertion_item */
static int hf_x509sat_initial = -1;               /* DirectoryString */
static int hf_x509sat_any = -1;                   /* DirectoryString */
static int hf_x509sat_final = -1;                 /* DirectoryString */
static int hf_x509sat_control = -1;               /* Attribute */
static int hf_x509sat_CaseIgnoreListMatch_item = -1;  /* DirectoryString */
static int hf_x509sat_OctetSubstringAssertion_item = -1;  /* OctetSubstringAssertion_item */
static int hf_x509sat_initial_substring = -1;     /* OCTET_STRING */
static int hf_x509sat_any_substring = -1;         /* OCTET_STRING */
static int hf_x509sat_finall_substring = -1;      /* OCTET_STRING */
static int hf_x509sat_ZonalSelect_item = -1;      /* AttributeType */
static int hf_x509sat_time = -1;                  /* T_time */
static int hf_x509sat_absolute = -1;              /* T_absolute */
static int hf_x509sat_startTime = -1;             /* GeneralizedTime */
static int hf_x509sat_endTime = -1;               /* GeneralizedTime */
static int hf_x509sat_periodic = -1;              /* SET_OF_Period */
static int hf_x509sat_periodic_item = -1;         /* Period */
static int hf_x509sat_notThisTime = -1;           /* BOOLEAN */
static int hf_x509sat_timeZone = -1;              /* TimeZone */
static int hf_x509sat_timesOfDay = -1;            /* SET_OF_DayTimeBand */
static int hf_x509sat_timesOfDay_item = -1;       /* DayTimeBand */
static int hf_x509sat_days = -1;                  /* T_days */
static int hf_x509sat_intDay = -1;                /* T_intDay */
static int hf_x509sat_intDay_item = -1;           /* INTEGER */
static int hf_x509sat_bitDay = -1;                /* T_bitDay */
static int hf_x509sat_dayOf = -1;                 /* XDayOf */
static int hf_x509sat_weeks = -1;                 /* T_weeks */
static int hf_x509sat_allWeeks = -1;              /* NULL */
static int hf_x509sat_intWeek = -1;               /* T_intWeek */
static int hf_x509sat_intWeek_item = -1;          /* INTEGER */
static int hf_x509sat_bitWeek = -1;               /* T_bitWeek */
static int hf_x509sat_months = -1;                /* T_months */
static int hf_x509sat_allMonths = -1;             /* NULL */
static int hf_x509sat_intMonth = -1;              /* T_intMonth */
static int hf_x509sat_intMonth_item = -1;         /* INTEGER */
static int hf_x509sat_bitMonth = -1;              /* T_bitMonth */
static int hf_x509sat_years = -1;                 /* T_years */
static int hf_x509sat_years_item = -1;            /* INTEGER */
static int hf_x509sat_first_dayof = -1;           /* NamedDay */
static int hf_x509sat_second_dayof = -1;          /* NamedDay */
static int hf_x509sat_third_dayof = -1;           /* NamedDay */
static int hf_x509sat_fourth_dayof = -1;          /* NamedDay */
static int hf_x509sat_fifth_dayof = -1;           /* NamedDay */
static int hf_x509sat_intNamedDays = -1;          /* T_intNamedDays */
static int hf_x509sat_bitNamedDays = -1;          /* T_bitNamedDays */
static int hf_x509sat_startDayTime = -1;          /* DayTime */
static int hf_x509sat_endDayTime = -1;            /* DayTime */
static int hf_x509sat_hour = -1;                  /* INTEGER */
static int hf_x509sat_minute = -1;                /* INTEGER */
static int hf_x509sat_second = -1;                /* INTEGER */
static int hf_x509sat_now = -1;                   /* NULL */
static int hf_x509sat_at = -1;                    /* GeneralizedTime */
static int hf_x509sat_between = -1;               /* T_between */
static int hf_x509sat_entirely = -1;              /* BOOLEAN */
static int hf_x509sat_localeID1 = -1;             /* OBJECT_IDENTIFIER */
static int hf_x509sat_localeID2 = -1;             /* DirectoryString */
/* named bits */
static int hf_x509sat_T_bitDay_sunday = -1;
static int hf_x509sat_T_bitDay_monday = -1;
static int hf_x509sat_T_bitDay_tuesday = -1;
static int hf_x509sat_T_bitDay_wednesday = -1;
static int hf_x509sat_T_bitDay_thursday = -1;
static int hf_x509sat_T_bitDay_friday = -1;
static int hf_x509sat_T_bitDay_saturday = -1;
static int hf_x509sat_T_bitWeek_week1 = -1;
static int hf_x509sat_T_bitWeek_week2 = -1;
static int hf_x509sat_T_bitWeek_week3 = -1;
static int hf_x509sat_T_bitWeek_week4 = -1;
static int hf_x509sat_T_bitWeek_week5 = -1;
static int hf_x509sat_T_bitMonth_january = -1;
static int hf_x509sat_T_bitMonth_february = -1;
static int hf_x509sat_T_bitMonth_march = -1;
static int hf_x509sat_T_bitMonth_april = -1;
static int hf_x509sat_T_bitMonth_may = -1;
static int hf_x509sat_T_bitMonth_june = -1;
static int hf_x509sat_T_bitMonth_july = -1;
static int hf_x509sat_T_bitMonth_august = -1;
static int hf_x509sat_T_bitMonth_september = -1;
static int hf_x509sat_T_bitMonth_october = -1;
static int hf_x509sat_T_bitMonth_november = -1;
static int hf_x509sat_T_bitMonth_december = -1;
static int hf_x509sat_T_bitNamedDays_sunday = -1;
static int hf_x509sat_T_bitNamedDays_monday = -1;
static int hf_x509sat_T_bitNamedDays_tuesday = -1;
static int hf_x509sat_T_bitNamedDays_wednesday = -1;
static int hf_x509sat_T_bitNamedDays_thursday = -1;
static int hf_x509sat_T_bitNamedDays_friday = -1;
static int hf_x509sat_T_bitNamedDays_saturday = -1;

/*--- End of included file: packet-x509sat-hf.c ---*/
#line 47 "../../asn1/x509sat/packet-x509sat-template.c"

/* Initialize the subtree pointers */

/*--- Included file: packet-x509sat-ett.c ---*/
#line 1 "../../asn1/x509sat/packet-x509sat-ett.c"
static gint ett_x509sat_DirectoryString = -1;
static gint ett_x509sat_Guide = -1;
static gint ett_x509sat_Criteria = -1;
static gint ett_x509sat_SET_OF_Criteria = -1;
static gint ett_x509sat_CriteriaItem = -1;
static gint ett_x509sat_EnhancedGuide = -1;
static gint ett_x509sat_PostalAddress = -1;
static gint ett_x509sat_TelexNumber = -1;
static gint ett_x509sat_FacsimileTelephoneNumber = -1;
static gint ett_x509sat_PreferredDeliveryMethod = -1;
static gint ett_x509sat_PresentationAddress = -1;
static gint ett_x509sat_T_nAddresses = -1;
static gint ett_x509sat_ProtocolInformation = -1;
static gint ett_x509sat_T_profiles = -1;
static gint ett_x509sat_NameAndOptionalUID = -1;
static gint ett_x509sat_MultipleMatchingLocalities = -1;
static gint ett_x509sat_SEQUENCE_OF_AttributeValueAssertion = -1;
static gint ett_x509sat_SubstringAssertion = -1;
static gint ett_x509sat_SubstringAssertion_item = -1;
static gint ett_x509sat_CaseIgnoreListMatch = -1;
static gint ett_x509sat_OctetSubstringAssertion = -1;
static gint ett_x509sat_OctetSubstringAssertion_item = -1;
static gint ett_x509sat_ZonalSelect = -1;
static gint ett_x509sat_TimeSpecification = -1;
static gint ett_x509sat_T_time = -1;
static gint ett_x509sat_T_absolute = -1;
static gint ett_x509sat_SET_OF_Period = -1;
static gint ett_x509sat_Period = -1;
static gint ett_x509sat_SET_OF_DayTimeBand = -1;
static gint ett_x509sat_T_days = -1;
static gint ett_x509sat_T_intDay = -1;
static gint ett_x509sat_T_bitDay = -1;
static gint ett_x509sat_T_weeks = -1;
static gint ett_x509sat_T_intWeek = -1;
static gint ett_x509sat_T_bitWeek = -1;
static gint ett_x509sat_T_months = -1;
static gint ett_x509sat_T_intMonth = -1;
static gint ett_x509sat_T_bitMonth = -1;
static gint ett_x509sat_T_years = -1;
static gint ett_x509sat_XDayOf = -1;
static gint ett_x509sat_NamedDay = -1;
static gint ett_x509sat_T_bitNamedDays = -1;
static gint ett_x509sat_DayTimeBand = -1;
static gint ett_x509sat_DayTime = -1;
static gint ett_x509sat_TimeAssertion = -1;
static gint ett_x509sat_T_between = -1;
static gint ett_x509sat_LocaleContextSyntax = -1;

/*--- End of included file: packet-x509sat-ett.c ---*/
#line 50 "../../asn1/x509sat/packet-x509sat-template.c"


/*--- Included file: packet-x509sat-fn.c ---*/
#line 1 "../../asn1/x509sat/packet-x509sat-fn.c"
/*--- Cyclic dependencies ---*/

/* Criteria -> Criteria/and -> Criteria */
/* Criteria -> Criteria */
int dissect_x509sat_Criteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_);




static int
dissect_x509sat_TeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_UniversalString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UniversalString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_BMPString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_UTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


const value_string x509sat_DirectoryString_vals[] = {
  {   0, "teletexString" },
  {   1, "printableString" },
  {   2, "universalString" },
  {   3, "bmpString" },
  {   4, "uTF8String" },
  { 0, NULL }
};

static const ber_choice_t DirectoryString_choice[] = {
  {   0, &hf_x509sat_teletexString, BER_CLASS_UNI, BER_UNI_TAG_TeletexString, BER_FLAGS_NOOWNTAG, dissect_x509sat_TeletexString },
  {   1, &hf_x509sat_printableString, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x509sat_PrintableString },
  {   2, &hf_x509sat_universalString, BER_CLASS_UNI, BER_UNI_TAG_UniversalString, BER_FLAGS_NOOWNTAG, dissect_x509sat_UniversalString },
  {   3, &hf_x509sat_bmpString   , BER_CLASS_UNI, BER_UNI_TAG_BMPString, BER_FLAGS_NOOWNTAG, dissect_x509sat_BMPString },
  {   4, &hf_x509sat_uTF8String  , BER_CLASS_UNI, BER_UNI_TAG_UTF8String, BER_FLAGS_NOOWNTAG, dissect_x509sat_UTF8String },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_DirectoryString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 DirectoryString_choice, hf_index, ett_x509sat_DirectoryString,
                                 NULL);

  return offset;
}



int
dissect_x509sat_UniqueIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



int
dissect_x509sat_CountryName(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}


static const value_string x509sat_CriteriaItem_vals[] = {
  {   0, "equality" },
  {   1, "substrings" },
  {   2, "greaterOrEqual" },
  {   3, "lessOrEqual" },
  {   4, "approximateMatch" },
  { 0, NULL }
};

static const ber_choice_t CriteriaItem_choice[] = {
  {   0, &hf_x509sat_equality    , BER_CLASS_CON, 0, 0, dissect_x509if_AttributeType },
  {   1, &hf_x509sat_substrings  , BER_CLASS_CON, 1, 0, dissect_x509if_AttributeType },
  {   2, &hf_x509sat_greaterOrEqual, BER_CLASS_CON, 2, 0, dissect_x509if_AttributeType },
  {   3, &hf_x509sat_lessOrEqual , BER_CLASS_CON, 3, 0, dissect_x509if_AttributeType },
  {   4, &hf_x509sat_approximateMatch, BER_CLASS_CON, 4, 0, dissect_x509if_AttributeType },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_CriteriaItem(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 CriteriaItem_choice, hf_index, ett_x509sat_CriteriaItem,
                                 NULL);

  return offset;
}


static const ber_sequence_t SET_OF_Criteria_set_of[1] = {
  { &hf_x509sat_and_item    , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509sat_Criteria },
};

static int
dissect_x509sat_SET_OF_Criteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Criteria_set_of, hf_index, ett_x509sat_SET_OF_Criteria);

  return offset;
}


const value_string x509sat_Criteria_vals[] = {
  {   0, "type" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t Criteria_choice[] = {
  {   0, &hf_x509sat_type        , BER_CLASS_CON, 0, 0, dissect_x509sat_CriteriaItem },
  {   1, &hf_x509sat_and         , BER_CLASS_CON, 1, 0, dissect_x509sat_SET_OF_Criteria },
  {   2, &hf_x509sat_or          , BER_CLASS_CON, 2, 0, dissect_x509sat_SET_OF_Criteria },
  {   3, &hf_x509sat_not         , BER_CLASS_CON, 3, 0, dissect_x509sat_Criteria },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_Criteria(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 Criteria_choice, hf_index, ett_x509sat_Criteria,
                                 NULL);

  return offset;
}


static const ber_sequence_t Guide_set[] = {
  { &hf_x509sat_objectClass , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509sat_OBJECT_IDENTIFIER },
  { &hf_x509sat_criteria    , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_x509sat_Criteria },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_Guide(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, actx, tree, tvb, offset,
                              Guide_set, hf_index, ett_x509sat_Guide);

  return offset;
}


static const value_string x509sat_T_subset_vals[] = {
  {   0, "baseObject" },
  {   1, "oneLevel" },
  {   2, "wholeSubtree" },
  { 0, NULL }
};


static int
dissect_x509sat_T_subset(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t EnhancedGuide_sequence[] = {
  { &hf_x509sat_objectClass , BER_CLASS_CON, 0, 0, dissect_x509sat_OBJECT_IDENTIFIER },
  { &hf_x509sat_criteria    , BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_x509sat_Criteria },
  { &hf_x509sat_subset      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509sat_T_subset },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_EnhancedGuide(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   EnhancedGuide_sequence, hf_index, ett_x509sat_EnhancedGuide);

  return offset;
}


static const ber_sequence_t PostalAddress_sequence_of[1] = {
  { &hf_x509sat_PostalAddress_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509sat_DirectoryString },
};

int
dissect_x509sat_PostalAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PostalAddress_sequence_of, hf_index, ett_x509sat_PostalAddress);

  return offset;
}



static int
dissect_x509sat_TelephoneNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const ber_sequence_t TelexNumber_sequence[] = {
  { &hf_x509sat_telexNumber , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x509sat_PrintableString },
  { &hf_x509sat_countryCode , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x509sat_PrintableString },
  { &hf_x509sat_answerback  , BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x509sat_PrintableString },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_TelexNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TelexNumber_sequence, hf_index, ett_x509sat_TelexNumber);

  return offset;
}


static const ber_sequence_t FacsimileTelephoneNumber_sequence[] = {
  { &hf_x509sat_telephoneNumber, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_x509sat_TelephoneNumber },
  { &hf_x509sat_parameters  , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_p1_G3FacsimileNonBasicParameters },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_FacsimileTelephoneNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   FacsimileTelephoneNumber_sequence, hf_index, ett_x509sat_FacsimileTelephoneNumber);

  return offset;
}



int
dissect_x509sat_X121Address(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



int
dissect_x509sat_InternationalISDNNumber(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



int
dissect_x509sat_DestinationIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}


static const value_string x509sat_PreferredDeliveryMethod_item_vals[] = {
  {   0, "any-delivery-method" },
  {   1, "mhs-delivery" },
  {   2, "physical-delivery" },
  {   3, "telex-delivery" },
  {   4, "teletex-delivery" },
  {   5, "g3-facsimile-delivery" },
  {   6, "g4-facsimile-delivery" },
  {   7, "ia5-terminal-delivery" },
  {   8, "videotex-delivery" },
  {   9, "telephone-delivery" },
  { 0, NULL }
};


static int
dissect_x509sat_PreferredDeliveryMethod_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t PreferredDeliveryMethod_sequence_of[1] = {
  { &hf_x509sat_PreferredDeliveryMethod_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509sat_PreferredDeliveryMethod_item },
};

int
dissect_x509sat_PreferredDeliveryMethod(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      PreferredDeliveryMethod_sequence_of, hf_index, ett_x509sat_PreferredDeliveryMethod);

  return offset;
}



static int
dissect_x509sat_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}


static const ber_sequence_t T_nAddresses_set_of[1] = {
  { &hf_x509sat_nAddresses_item, BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x509sat_OCTET_STRING },
};

static int
dissect_x509sat_T_nAddresses(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_nAddresses_set_of, hf_index, ett_x509sat_T_nAddresses);

  return offset;
}


static const ber_sequence_t PresentationAddress_sequence[] = {
  { &hf_x509sat_pSelector   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509sat_OCTET_STRING },
  { &hf_x509sat_sSelector   , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509sat_OCTET_STRING },
  { &hf_x509sat_tSelector   , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509sat_OCTET_STRING },
  { &hf_x509sat_nAddresses  , BER_CLASS_CON, 3, 0, dissect_x509sat_T_nAddresses },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_PresentationAddress(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   PresentationAddress_sequence, hf_index, ett_x509sat_PresentationAddress);

  return offset;
}


static const ber_sequence_t T_profiles_set_of[1] = {
  { &hf_x509sat_profiles_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509sat_OBJECT_IDENTIFIER },
};

static int
dissect_x509sat_T_profiles(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_profiles_set_of, hf_index, ett_x509sat_T_profiles);

  return offset;
}


static const ber_sequence_t ProtocolInformation_sequence[] = {
  { &hf_x509sat_nAddress    , BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_x509sat_OCTET_STRING },
  { &hf_x509sat_profiles    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_profiles },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_ProtocolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   ProtocolInformation_sequence, hf_index, ett_x509sat_ProtocolInformation);

  return offset;
}


static const ber_sequence_t NameAndOptionalUID_sequence[] = {
  { &hf_x509sat_dn          , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_DistinguishedName },
  { &hf_x509sat_uid         , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_UniqueIdentifier },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_NameAndOptionalUID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   NameAndOptionalUID_sequence, hf_index, ett_x509sat_NameAndOptionalUID);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeValueAssertion_sequence_of[1] = {
  { &hf_x509sat_attributeList_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeValueAssertion },
};

static int
dissect_x509sat_SEQUENCE_OF_AttributeValueAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeValueAssertion_sequence_of, hf_index, ett_x509sat_SEQUENCE_OF_AttributeValueAssertion);

  return offset;
}


static const ber_sequence_t MultipleMatchingLocalities_sequence[] = {
  { &hf_x509sat_matchingRuleUsed, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_OBJECT_IDENTIFIER },
  { &hf_x509sat_attributeList, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_SEQUENCE_OF_AttributeValueAssertion },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_MultipleMatchingLocalities(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   MultipleMatchingLocalities_sequence, hf_index, ett_x509sat_MultipleMatchingLocalities);

  return offset;
}


static const value_string x509sat_SubstringAssertion_item_vals[] = {
  {   0, "initial" },
  {   1, "any" },
  {   2, "final" },
  {   3, "control" },
  { 0, NULL }
};

static const ber_choice_t SubstringAssertion_item_choice[] = {
  {   0, &hf_x509sat_initial     , BER_CLASS_CON, 0, 0, dissect_x509sat_DirectoryString },
  {   1, &hf_x509sat_any         , BER_CLASS_CON, 1, 0, dissect_x509sat_DirectoryString },
  {   2, &hf_x509sat_final       , BER_CLASS_CON, 2, 0, dissect_x509sat_DirectoryString },
  {   3, &hf_x509sat_control     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509if_Attribute },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_SubstringAssertion_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 SubstringAssertion_item_choice, hf_index, ett_x509sat_SubstringAssertion_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t SubstringAssertion_sequence_of[1] = {
  { &hf_x509sat_SubstringAssertion_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509sat_SubstringAssertion_item },
};

int
dissect_x509sat_SubstringAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      SubstringAssertion_sequence_of, hf_index, ett_x509sat_SubstringAssertion);

  return offset;
}


static const ber_sequence_t CaseIgnoreListMatch_sequence_of[1] = {
  { &hf_x509sat_CaseIgnoreListMatch_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509sat_DirectoryString },
};

int
dissect_x509sat_CaseIgnoreListMatch(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      CaseIgnoreListMatch_sequence_of, hf_index, ett_x509sat_CaseIgnoreListMatch);

  return offset;
}


static const value_string x509sat_OctetSubstringAssertion_item_vals[] = {
  {   0, "initial" },
  {   1, "any" },
  {   2, "final" },
  { 0, NULL }
};

static const ber_choice_t OctetSubstringAssertion_item_choice[] = {
  {   0, &hf_x509sat_initial_substring, BER_CLASS_CON, 0, 0, dissect_x509sat_OCTET_STRING },
  {   1, &hf_x509sat_any_substring, BER_CLASS_CON, 1, 0, dissect_x509sat_OCTET_STRING },
  {   2, &hf_x509sat_finall_substring, BER_CLASS_CON, 2, 0, dissect_x509sat_OCTET_STRING },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_OctetSubstringAssertion_item(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 OctetSubstringAssertion_item_choice, hf_index, ett_x509sat_OctetSubstringAssertion_item,
                                 NULL);

  return offset;
}


static const ber_sequence_t OctetSubstringAssertion_sequence_of[1] = {
  { &hf_x509sat_OctetSubstringAssertion_item, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509sat_OctetSubstringAssertion_item },
};

int
dissect_x509sat_OctetSubstringAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      OctetSubstringAssertion_sequence_of, hf_index, ett_x509sat_OctetSubstringAssertion);

  return offset;
}


static const ber_sequence_t ZonalSelect_sequence_of[1] = {
  { &hf_x509sat_ZonalSelect_item, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509if_AttributeType },
};

int
dissect_x509sat_ZonalSelect(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, actx, tree, tvb, offset,
                                      ZonalSelect_sequence_of, hf_index, ett_x509sat_ZonalSelect);

  return offset;
}


const value_string x509sat_ZonalResult_vals[] = {
  {   0, "cannot-select-mapping" },
  {   2, "zero-mappings" },
  {   3, "multiple-mappings" },
  { 0, NULL }
};


int
dissect_x509sat_ZonalResult(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_x509sat_LanguageContextSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_absolute_sequence[] = {
  { &hf_x509sat_startTime   , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509sat_GeneralizedTime },
  { &hf_x509sat_endTime     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509sat_GeneralizedTime },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_absolute(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_absolute_sequence, hf_index, ett_x509sat_T_absolute);

  return offset;
}



static int
dissect_x509sat_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t DayTime_sequence[] = {
  { &hf_x509sat_hour        , BER_CLASS_CON, 0, 0, dissect_x509sat_INTEGER },
  { &hf_x509sat_minute      , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509sat_INTEGER },
  { &hf_x509sat_second      , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509sat_INTEGER },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_DayTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DayTime_sequence, hf_index, ett_x509sat_DayTime);

  return offset;
}


static const ber_sequence_t DayTimeBand_sequence[] = {
  { &hf_x509sat_startDayTime, BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509sat_DayTime },
  { &hf_x509sat_endDayTime  , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509sat_DayTime },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_DayTimeBand(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   DayTimeBand_sequence, hf_index, ett_x509sat_DayTimeBand);

  return offset;
}


static const ber_sequence_t SET_OF_DayTimeBand_set_of[1] = {
  { &hf_x509sat_timesOfDay_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_DayTimeBand },
};

static int
dissect_x509sat_SET_OF_DayTimeBand(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_DayTimeBand_set_of, hf_index, ett_x509sat_SET_OF_DayTimeBand);

  return offset;
}


static const ber_sequence_t T_intDay_set_of[1] = {
  { &hf_x509sat_intDay_item , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509sat_INTEGER },
};

static int
dissect_x509sat_T_intDay(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_intDay_set_of, hf_index, ett_x509sat_T_intDay);

  return offset;
}


static const asn_namedbit T_bitDay_bits[] = {
  {  0, &hf_x509sat_T_bitDay_sunday, -1, -1, "sunday", NULL },
  {  1, &hf_x509sat_T_bitDay_monday, -1, -1, "monday", NULL },
  {  2, &hf_x509sat_T_bitDay_tuesday, -1, -1, "tuesday", NULL },
  {  3, &hf_x509sat_T_bitDay_wednesday, -1, -1, "wednesday", NULL },
  {  4, &hf_x509sat_T_bitDay_thursday, -1, -1, "thursday", NULL },
  {  5, &hf_x509sat_T_bitDay_friday, -1, -1, "friday", NULL },
  {  6, &hf_x509sat_T_bitDay_saturday, -1, -1, "saturday", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509sat_T_bitDay(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_bitDay_bits, hf_index, ett_x509sat_T_bitDay,
                                    NULL);

  return offset;
}


static const value_string x509sat_T_intNamedDays_vals[] = {
  {   1, "sunday" },
  {   2, "monday" },
  {   3, "tuesday" },
  {   4, "wednesday" },
  {   5, "thursday" },
  {   6, "friday" },
  {   7, "saturday" },
  { 0, NULL }
};


static int
dissect_x509sat_T_intNamedDays(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}


static const asn_namedbit T_bitNamedDays_bits[] = {
  {  0, &hf_x509sat_T_bitNamedDays_sunday, -1, -1, "sunday", NULL },
  {  1, &hf_x509sat_T_bitNamedDays_monday, -1, -1, "monday", NULL },
  {  2, &hf_x509sat_T_bitNamedDays_tuesday, -1, -1, "tuesday", NULL },
  {  3, &hf_x509sat_T_bitNamedDays_wednesday, -1, -1, "wednesday", NULL },
  {  4, &hf_x509sat_T_bitNamedDays_thursday, -1, -1, "thursday", NULL },
  {  5, &hf_x509sat_T_bitNamedDays_friday, -1, -1, "friday", NULL },
  {  6, &hf_x509sat_T_bitNamedDays_saturday, -1, -1, "saturday", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509sat_T_bitNamedDays(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_bitNamedDays_bits, hf_index, ett_x509sat_T_bitNamedDays,
                                    NULL);

  return offset;
}


const value_string x509sat_NamedDay_vals[] = {
  {   0, "intNamedDays" },
  {   1, "bitNamedDays" },
  { 0, NULL }
};

static const ber_choice_t NamedDay_choice[] = {
  {   0, &hf_x509sat_intNamedDays, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_intNamedDays },
  {   1, &hf_x509sat_bitNamedDays, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_bitNamedDays },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_NamedDay(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 NamedDay_choice, hf_index, ett_x509sat_NamedDay,
                                 NULL);

  return offset;
}


const value_string x509sat_XDayOf_vals[] = {
  {   1, "first" },
  {   2, "second" },
  {   3, "third" },
  {   4, "fourth" },
  {   5, "fifth" },
  { 0, NULL }
};

static const ber_choice_t XDayOf_choice[] = {
  {   1, &hf_x509sat_first_dayof , BER_CLASS_CON, 1, 0, dissect_x509sat_NamedDay },
  {   2, &hf_x509sat_second_dayof, BER_CLASS_CON, 2, 0, dissect_x509sat_NamedDay },
  {   3, &hf_x509sat_third_dayof , BER_CLASS_CON, 3, 0, dissect_x509sat_NamedDay },
  {   4, &hf_x509sat_fourth_dayof, BER_CLASS_CON, 4, 0, dissect_x509sat_NamedDay },
  {   5, &hf_x509sat_fifth_dayof , BER_CLASS_CON, 5, 0, dissect_x509sat_NamedDay },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_XDayOf(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 XDayOf_choice, hf_index, ett_x509sat_XDayOf,
                                 NULL);

  return offset;
}


static const value_string x509sat_T_days_vals[] = {
  {   0, "intDay" },
  {   1, "bitDay" },
  {   2, "dayOf" },
  { 0, NULL }
};

static const ber_choice_t T_days_choice[] = {
  {   0, &hf_x509sat_intDay      , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_intDay },
  {   1, &hf_x509sat_bitDay      , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_bitDay },
  {   2, &hf_x509sat_dayOf       , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509sat_XDayOf },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_days(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_days_choice, hf_index, ett_x509sat_T_days,
                                 NULL);

  return offset;
}



static int
dissect_x509sat_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}


static const ber_sequence_t T_intWeek_set_of[1] = {
  { &hf_x509sat_intWeek_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509sat_INTEGER },
};

static int
dissect_x509sat_T_intWeek(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_intWeek_set_of, hf_index, ett_x509sat_T_intWeek);

  return offset;
}


static const asn_namedbit T_bitWeek_bits[] = {
  {  0, &hf_x509sat_T_bitWeek_week1, -1, -1, "week1", NULL },
  {  1, &hf_x509sat_T_bitWeek_week2, -1, -1, "week2", NULL },
  {  2, &hf_x509sat_T_bitWeek_week3, -1, -1, "week3", NULL },
  {  3, &hf_x509sat_T_bitWeek_week4, -1, -1, "week4", NULL },
  {  4, &hf_x509sat_T_bitWeek_week5, -1, -1, "week5", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509sat_T_bitWeek(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_bitWeek_bits, hf_index, ett_x509sat_T_bitWeek,
                                    NULL);

  return offset;
}


static const value_string x509sat_T_weeks_vals[] = {
  {   0, "allWeeks" },
  {   1, "intWeek" },
  {   2, "bitWeek" },
  { 0, NULL }
};

static const ber_choice_t T_weeks_choice[] = {
  {   0, &hf_x509sat_allWeeks    , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_x509sat_NULL },
  {   1, &hf_x509sat_intWeek     , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_intWeek },
  {   2, &hf_x509sat_bitWeek     , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_bitWeek },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_weeks(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_weeks_choice, hf_index, ett_x509sat_T_weeks,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_intMonth_set_of[1] = {
  { &hf_x509sat_intMonth_item, BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509sat_INTEGER },
};

static int
dissect_x509sat_T_intMonth(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_intMonth_set_of, hf_index, ett_x509sat_T_intMonth);

  return offset;
}


static const asn_namedbit T_bitMonth_bits[] = {
  {  0, &hf_x509sat_T_bitMonth_january, -1, -1, "january", NULL },
  {  1, &hf_x509sat_T_bitMonth_february, -1, -1, "february", NULL },
  {  2, &hf_x509sat_T_bitMonth_march, -1, -1, "march", NULL },
  {  3, &hf_x509sat_T_bitMonth_april, -1, -1, "april", NULL },
  {  4, &hf_x509sat_T_bitMonth_may, -1, -1, "may", NULL },
  {  5, &hf_x509sat_T_bitMonth_june, -1, -1, "june", NULL },
  {  6, &hf_x509sat_T_bitMonth_july, -1, -1, "july", NULL },
  {  7, &hf_x509sat_T_bitMonth_august, -1, -1, "august", NULL },
  {  8, &hf_x509sat_T_bitMonth_september, -1, -1, "september", NULL },
  {  9, &hf_x509sat_T_bitMonth_october, -1, -1, "october", NULL },
  { 10, &hf_x509sat_T_bitMonth_november, -1, -1, "november", NULL },
  { 11, &hf_x509sat_T_bitMonth_december, -1, -1, "december", NULL },
  { 0, NULL, 0, 0, NULL, NULL }
};

static int
dissect_x509sat_T_bitMonth(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    T_bitMonth_bits, hf_index, ett_x509sat_T_bitMonth,
                                    NULL);

  return offset;
}


static const value_string x509sat_T_months_vals[] = {
  {   0, "allMonths" },
  {   1, "intMonth" },
  {   2, "bitMonth" },
  { 0, NULL }
};

static const ber_choice_t T_months_choice[] = {
  {   0, &hf_x509sat_allMonths   , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_x509sat_NULL },
  {   1, &hf_x509sat_intMonth    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_intMonth },
  {   2, &hf_x509sat_bitMonth    , BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_bitMonth },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_months(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_months_choice, hf_index, ett_x509sat_T_months,
                                 NULL);

  return offset;
}


static const ber_sequence_t T_years_set_of[1] = {
  { &hf_x509sat_years_item  , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_x509sat_INTEGER },
};

static int
dissect_x509sat_T_years(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 T_years_set_of, hf_index, ett_x509sat_T_years);

  return offset;
}


static const ber_sequence_t Period_sequence[] = {
  { &hf_x509sat_timesOfDay  , BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_x509sat_SET_OF_DayTimeBand },
  { &hf_x509sat_days        , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509sat_T_days },
  { &hf_x509sat_weeks       , BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_x509sat_T_weeks },
  { &hf_x509sat_months      , BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_x509sat_T_months },
  { &hf_x509sat_years       , BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_x509sat_T_years },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_Period(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   Period_sequence, hf_index, ett_x509sat_Period);

  return offset;
}


static const ber_sequence_t SET_OF_Period_set_of[1] = {
  { &hf_x509sat_periodic_item, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_Period },
};

static int
dissect_x509sat_SET_OF_Period(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, actx, tree, tvb, offset,
                                 SET_OF_Period_set_of, hf_index, ett_x509sat_SET_OF_Period);

  return offset;
}


static const value_string x509sat_T_time_vals[] = {
  {   0, "absolute" },
  {   1, "periodic" },
  { 0, NULL }
};

static const ber_choice_t T_time_choice[] = {
  {   0, &hf_x509sat_absolute    , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_absolute },
  {   1, &hf_x509sat_periodic    , BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_x509sat_SET_OF_Period },
  { 0, NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_time(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 T_time_choice, hf_index, ett_x509sat_T_time,
                                 NULL);

  return offset;
}



static int
dissect_x509sat_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



int
dissect_x509sat_TimeZone(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}


static const ber_sequence_t TimeSpecification_sequence[] = {
  { &hf_x509sat_time        , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_x509sat_T_time },
  { &hf_x509sat_notThisTime , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_BOOLEAN },
  { &hf_x509sat_timeZone    , BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_TimeZone },
  { NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_TimeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   TimeSpecification_sequence, hf_index, ett_x509sat_TimeSpecification);

  return offset;
}


static const ber_sequence_t T_between_sequence[] = {
  { &hf_x509sat_startTime   , BER_CLASS_CON, 0, 0, dissect_x509sat_GeneralizedTime },
  { &hf_x509sat_endTime     , BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_x509sat_GeneralizedTime },
  { &hf_x509sat_entirely    , BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_x509sat_BOOLEAN },
  { NULL, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_between(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, actx, tree, tvb, offset,
                                   T_between_sequence, hf_index, ett_x509sat_T_between);

  return offset;
}


const value_string x509sat_TimeAssertion_vals[] = {
  {   0, "now" },
  {   1, "at" },
  {   2, "between" },
  { 0, NULL }
};

static const ber_choice_t TimeAssertion_choice[] = {
  {   0, &hf_x509sat_now         , BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_x509sat_NULL },
  {   1, &hf_x509sat_at          , BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_x509sat_GeneralizedTime },
  {   2, &hf_x509sat_between     , BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_x509sat_T_between },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_TimeAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 TimeAssertion_choice, hf_index, ett_x509sat_TimeAssertion,
                                 NULL);

  return offset;
}


const value_string x509sat_LocaleContextSyntax_vals[] = {
  {   0, "localeID1" },
  {   1, "localeID2" },
  { 0, NULL }
};

static const ber_choice_t LocaleContextSyntax_choice[] = {
  {   0, &hf_x509sat_localeID1   , BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_x509sat_OBJECT_IDENTIFIER },
  {   1, &hf_x509sat_localeID2   , BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_x509sat_DirectoryString },
  { 0, NULL, 0, 0, 0, NULL }
};

int
dissect_x509sat_LocaleContextSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_choice(actx, tree, tvb, offset,
                                 LocaleContextSyntax_choice, hf_index, ett_x509sat_LocaleContextSyntax,
                                 NULL);

  return offset;
}



static int
dissect_x509sat_ObjectIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_x509sat_OctetString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, actx, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}



static int
dissect_x509sat_BitString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, actx, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}



static int
dissect_x509sat_Integer(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, actx, tree, tvb, offset, hf_index,
                                                NULL);

  return offset;
}



static int
dissect_x509sat_Boolean(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, actx, tree, tvb, offset, hf_index, NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxGeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x509sat_SyntaxUTCTime(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_UTCTime(implicit_tag, actx, tree, tvb, offset, hf_index);

  return offset;
}



static int
dissect_x509sat_SyntaxNumericString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxPrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxIA5String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_IA5String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxBMPString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 351 "../../asn1/x509sat/x509sat.cnf"
	tvbuff_t	*wide_tvb = NULL;
	char		*string;

  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_BMPString,
                                            actx, tree, tvb, offset, hf_index,
                                            &wide_tvb);

#line 356 "../../asn1/x509sat/x509sat.cnf"
	if (! wide_tvb) {
		return offset;
	}
	string = tvb_get_ephemeral_faked_unicode (wide_tvb, 0, tvb_length(wide_tvb) / 2, FALSE);
	proto_item_append_text(actx->created_item, " %s", string);	


  return offset;
}



static int
dissect_x509sat_SyntaxUniversalString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UniversalString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxUTF8String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_UTF8String,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxTeletexString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxT61String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_TeletexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxVideotexString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VideotexString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxGraphicString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GraphicString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxISO646String(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxVisibleString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_VisibleString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_SyntaxGeneralString(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_GeneralString,
                                            actx, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_GUID(gboolean implicit_tag _U_, tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
#line 365 "../../asn1/x509sat/x509sat.cnf"
  gint8 class;
  gboolean pc;
  gint32 tag;
  guint32 len;
  e_guid_t uuid;

  if(!implicit_tag){
    offset=dissect_ber_identifier(actx->pinfo, tree, tvb, offset, &class, &pc, &tag);
    offset=dissect_ber_length(actx->pinfo, tree, tvb, offset, &len, NULL);
  } else {
    gint32 remaining=tvb_length_remaining(tvb, offset);
    len=remaining>0 ? remaining : 0;
  }

  tvb_get_ntohguid (tvb, offset, &uuid);
  actx->created_item = proto_tree_add_guid(tree, hf_index, tvb, offset, len, &uuid);


  return offset;
}

/*--- PDUs ---*/

static void dissect_DirectoryString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_DirectoryString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_DirectoryString_PDU);
}
static void dissect_UniqueIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_UniqueIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_UniqueIdentifier_PDU);
}
static void dissect_CountryName_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_CountryName(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_CountryName_PDU);
}
static void dissect_Guide_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_Guide(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_Guide_PDU);
}
static void dissect_EnhancedGuide_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_EnhancedGuide(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_EnhancedGuide_PDU);
}
static void dissect_PostalAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_PostalAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_PostalAddress_PDU);
}
static void dissect_TelephoneNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_TelephoneNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_TelephoneNumber_PDU);
}
static void dissect_TelexNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_TelexNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_TelexNumber_PDU);
}
static void dissect_FacsimileTelephoneNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_FacsimileTelephoneNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_FacsimileTelephoneNumber_PDU);
}
static void dissect_X121Address_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_X121Address(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_X121Address_PDU);
}
static void dissect_InternationalISDNNumber_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_InternationalISDNNumber(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_InternationalISDNNumber_PDU);
}
static void dissect_DestinationIndicator_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_DestinationIndicator(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_DestinationIndicator_PDU);
}
static void dissect_PreferredDeliveryMethod_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_PreferredDeliveryMethod(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_PreferredDeliveryMethod_PDU);
}
static void dissect_PresentationAddress_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_PresentationAddress(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_PresentationAddress_PDU);
}
static void dissect_ProtocolInformation_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_ProtocolInformation(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_ProtocolInformation_PDU);
}
static void dissect_NameAndOptionalUID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_NameAndOptionalUID(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_NameAndOptionalUID_PDU);
}
static void dissect_CaseIgnoreListMatch_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_CaseIgnoreListMatch(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_CaseIgnoreListMatch_PDU);
}
static void dissect_ObjectIdentifier_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_ObjectIdentifier(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_ObjectIdentifier_PDU);
}
static void dissect_OctetString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_OctetString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_OctetString_PDU);
}
static void dissect_BitString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_BitString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_BitString_PDU);
}
static void dissect_Integer_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_Integer(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_Integer_PDU);
}
static void dissect_Boolean_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_Boolean(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_Boolean_PDU);
}
static void dissect_SyntaxGeneralizedTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxGeneralizedTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxGeneralizedTime_PDU);
}
static void dissect_SyntaxUTCTime_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxUTCTime(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxUTCTime_PDU);
}
static void dissect_SyntaxNumericString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxNumericString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxNumericString_PDU);
}
static void dissect_SyntaxPrintableString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxPrintableString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxPrintableString_PDU);
}
static void dissect_SyntaxIA5String_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxIA5String(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxIA5String_PDU);
}
static void dissect_SyntaxBMPString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxBMPString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxBMPString_PDU);
}
static void dissect_SyntaxUniversalString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxUniversalString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxUniversalString_PDU);
}
static void dissect_SyntaxUTF8String_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxUTF8String(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxUTF8String_PDU);
}
static void dissect_SyntaxTeletexString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxTeletexString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxTeletexString_PDU);
}
static void dissect_SyntaxT61String_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxT61String(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxT61String_PDU);
}
static void dissect_SyntaxVideotexString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxVideotexString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxVideotexString_PDU);
}
static void dissect_SyntaxGraphicString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxGraphicString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxGraphicString_PDU);
}
static void dissect_SyntaxISO646String_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxISO646String(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxISO646String_PDU);
}
static void dissect_SyntaxVisibleString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxVisibleString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxVisibleString_PDU);
}
static void dissect_SyntaxGeneralString_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_SyntaxGeneralString(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_SyntaxGeneralString_PDU);
}
static void dissect_GUID_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_) {
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_BER, TRUE, pinfo);
  dissect_x509sat_GUID(FALSE, tvb, 0, &asn1_ctx, tree, hf_x509sat_GUID_PDU);
}


/*--- End of included file: packet-x509sat-fn.c ---*/
#line 52 "../../asn1/x509sat/packet-x509sat-template.c"


/*--- proto_register_x509sat ----------------------------------------------*/
void proto_register_x509sat(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-x509sat-hfarr.c ---*/
#line 1 "../../asn1/x509sat/packet-x509sat-hfarr.c"
    { &hf_x509sat_DirectoryString_PDU,
      { "DirectoryString", "x509sat.DirectoryString",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_UniqueIdentifier_PDU,
      { "UniqueIdentifier", "x509sat.UniqueIdentifier",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_CountryName_PDU,
      { "CountryName", "x509sat.CountryName",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_Guide_PDU,
      { "Guide", "x509sat.Guide",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_EnhancedGuide_PDU,
      { "EnhancedGuide", "x509sat.EnhancedGuide",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_PostalAddress_PDU,
      { "PostalAddress", "x509sat.PostalAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_TelephoneNumber_PDU,
      { "TelephoneNumber", "x509sat.TelephoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_TelexNumber_PDU,
      { "TelexNumber", "x509sat.TelexNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_FacsimileTelephoneNumber_PDU,
      { "FacsimileTelephoneNumber", "x509sat.FacsimileTelephoneNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_X121Address_PDU,
      { "X121Address", "x509sat.X121Address",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_InternationalISDNNumber_PDU,
      { "InternationalISDNNumber", "x509sat.InternationalISDNNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_DestinationIndicator_PDU,
      { "DestinationIndicator", "x509sat.DestinationIndicator",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_PreferredDeliveryMethod_PDU,
      { "PreferredDeliveryMethod", "x509sat.PreferredDeliveryMethod",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_PresentationAddress_PDU,
      { "PresentationAddress", "x509sat.PresentationAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_ProtocolInformation_PDU,
      { "ProtocolInformation", "x509sat.ProtocolInformation",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_NameAndOptionalUID_PDU,
      { "NameAndOptionalUID", "x509sat.NameAndOptionalUID",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_CaseIgnoreListMatch_PDU,
      { "CaseIgnoreListMatch", "x509sat.CaseIgnoreListMatch",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_ObjectIdentifier_PDU,
      { "ObjectIdentifier", "x509sat.ObjectIdentifier",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_OctetString_PDU,
      { "OctetString", "x509sat.OctetString",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_BitString_PDU,
      { "BitString", "x509sat.BitString",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_Integer_PDU,
      { "Integer", "x509sat.Integer",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_Boolean_PDU,
      { "Boolean", "x509sat.Boolean",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxGeneralizedTime_PDU,
      { "GeneralizedTime", "x509sat.GeneralizedTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxUTCTime_PDU,
      { "UTCTime", "x509sat.UTCTime",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxNumericString_PDU,
      { "NumericString", "x509sat.NumericString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxPrintableString_PDU,
      { "PrintableString", "x509sat.PrintableString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxIA5String_PDU,
      { "IA5String", "x509sat.IA5String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxBMPString_PDU,
      { "BMPString", "x509sat.BMPString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxUniversalString_PDU,
      { "UniversalString", "x509sat.UniversalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxUTF8String_PDU,
      { "UTF8String", "x509sat.UTF8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxTeletexString_PDU,
      { "TeletexString", "x509sat.TeletexString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxT61String_PDU,
      { "T61String", "x509sat.T61String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxVideotexString_PDU,
      { "VideotexString", "x509sat.VideotexString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxGraphicString_PDU,
      { "GraphicString", "x509sat.GraphicString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxISO646String_PDU,
      { "ISO646String", "x509sat.ISO646String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxVisibleString_PDU,
      { "VisibleString", "x509sat.VisibleString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SyntaxGeneralString_PDU,
      { "GeneralString", "x509sat.GeneralString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_GUID_PDU,
      { "GUID", "x509sat.GUID",
        FT_GUID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_teletexString,
      { "teletexString", "x509sat.teletexString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_printableString,
      { "printableString", "x509sat.printableString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_universalString,
      { "universalString", "x509sat.universalString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_bmpString,
      { "bmpString", "x509sat.bmpString",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_uTF8String,
      { "uTF8String", "x509sat.uTF8String",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_objectClass,
      { "objectClass", "x509sat.objectClass",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509sat_criteria,
      { "criteria", "x509sat.criteria",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_type,
      { "type", "x509sat.type",
        FT_UINT32, BASE_DEC, VALS(x509sat_CriteriaItem_vals), 0,
        "CriteriaItem", HFILL }},
    { &hf_x509sat_and,
      { "and", "x509sat.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Criteria", HFILL }},
    { &hf_x509sat_and_item,
      { "Criteria", "x509sat.Criteria",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_or,
      { "or", "x509sat.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Criteria", HFILL }},
    { &hf_x509sat_or_item,
      { "Criteria", "x509sat.Criteria",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_not,
      { "not", "x509sat.not",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        "Criteria", HFILL }},
    { &hf_x509sat_equality,
      { "equality", "x509sat.equality",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_x509sat_substrings,
      { "substrings", "x509sat.substrings",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_x509sat_greaterOrEqual,
      { "greaterOrEqual", "x509sat.greaterOrEqual",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_x509sat_lessOrEqual,
      { "lessOrEqual", "x509sat.lessOrEqual",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_x509sat_approximateMatch,
      { "approximateMatch", "x509sat.approximateMatch",
        FT_OID, BASE_NONE, NULL, 0,
        "AttributeType", HFILL }},
    { &hf_x509sat_subset,
      { "subset", "x509sat.subset",
        FT_INT32, BASE_DEC, VALS(x509sat_T_subset_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_PostalAddress_item,
      { "DirectoryString", "x509sat.DirectoryString",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_telexNumber,
      { "telexNumber", "x509sat.telexNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_x509sat_countryCode,
      { "countryCode", "x509sat.countryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_x509sat_answerback,
      { "answerback", "x509sat.answerback",
        FT_STRING, BASE_NONE, NULL, 0,
        "PrintableString", HFILL }},
    { &hf_x509sat_telephoneNumber,
      { "telephoneNumber", "x509sat.telephoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_parameters,
      { "parameters", "x509sat.parameters",
        FT_BYTES, BASE_NONE, NULL, 0,
        "G3FacsimileNonBasicParameters", HFILL }},
    { &hf_x509sat_PreferredDeliveryMethod_item,
      { "PreferredDeliveryMethod item", "x509sat.PreferredDeliveryMethod_item",
        FT_INT32, BASE_DEC, VALS(x509sat_PreferredDeliveryMethod_item_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_pSelector,
      { "pSelector", "x509sat.pSelector",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_x509sat_sSelector,
      { "sSelector", "x509sat.sSelector",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_x509sat_tSelector,
      { "tSelector", "x509sat.tSelector",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_x509sat_nAddresses,
      { "nAddresses", "x509sat.nAddresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_nAddresses_item,
      { "nAddresses item", "x509sat.nAddresses_item",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_x509sat_nAddress,
      { "nAddress", "x509sat.nAddress",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_x509sat_profiles,
      { "profiles", "x509sat.profiles",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_profiles_item,
      { "profiles item", "x509sat.profiles_item",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509sat_dn,
      { "dn", "x509sat.dn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "DistinguishedName", HFILL }},
    { &hf_x509sat_uid,
      { "uid", "x509sat.uid",
        FT_BYTES, BASE_NONE, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_x509sat_matchingRuleUsed,
      { "matchingRuleUsed", "x509sat.matchingRuleUsed",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509sat_attributeList,
      { "attributeList", "x509sat.attributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_OF_AttributeValueAssertion", HFILL }},
    { &hf_x509sat_attributeList_item,
      { "AttributeValueAssertion", "x509sat.AttributeValueAssertion",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_SubstringAssertion_item,
      { "SubstringAssertion item", "x509sat.SubstringAssertion_item",
        FT_UINT32, BASE_DEC, VALS(x509sat_SubstringAssertion_item_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_initial,
      { "initial", "x509sat.initial",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_x509sat_any,
      { "any", "x509sat.any",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_x509sat_final,
      { "final", "x509sat.final",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_x509sat_control,
      { "control", "x509sat.control",
        FT_NONE, BASE_NONE, NULL, 0,
        "Attribute", HFILL }},
    { &hf_x509sat_CaseIgnoreListMatch_item,
      { "DirectoryString", "x509sat.DirectoryString",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_OctetSubstringAssertion_item,
      { "OctetSubstringAssertion item", "x509sat.OctetSubstringAssertion_item",
        FT_UINT32, BASE_DEC, VALS(x509sat_OctetSubstringAssertion_item_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_initial_substring,
      { "initial", "x509sat.initial",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_x509sat_any_substring,
      { "any", "x509sat.any",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_x509sat_finall_substring,
      { "final", "x509sat.final",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING", HFILL }},
    { &hf_x509sat_ZonalSelect_item,
      { "AttributeType", "x509sat.AttributeType",
        FT_OID, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_time,
      { "time", "x509sat.time",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_time_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_absolute,
      { "absolute", "x509sat.absolute",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_startTime,
      { "startTime", "x509sat.startTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509sat_endTime,
      { "endTime", "x509sat.endTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509sat_periodic,
      { "periodic", "x509sat.periodic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_Period", HFILL }},
    { &hf_x509sat_periodic_item,
      { "Period", "x509sat.Period",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_notThisTime,
      { "notThisTime", "x509sat.notThisTime",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509sat_timeZone,
      { "timeZone", "x509sat.timeZone",
        FT_INT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_timesOfDay,
      { "timesOfDay", "x509sat.timesOfDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SET_OF_DayTimeBand", HFILL }},
    { &hf_x509sat_timesOfDay_item,
      { "DayTimeBand", "x509sat.DayTimeBand",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_days,
      { "days", "x509sat.days",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_days_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_intDay,
      { "intDay", "x509sat.intDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_intDay_item,
      { "intDay item", "x509sat.intDay_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509sat_bitDay,
      { "bitDay", "x509sat.bitDay",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_dayOf,
      { "dayOf", "x509sat.dayOf",
        FT_UINT32, BASE_DEC, VALS(x509sat_XDayOf_vals), 0,
        "XDayOf", HFILL }},
    { &hf_x509sat_weeks,
      { "weeks", "x509sat.weeks",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_weeks_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_allWeeks,
      { "allWeeks", "x509sat.allWeeks",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_intWeek,
      { "intWeek", "x509sat.intWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_intWeek_item,
      { "intWeek item", "x509sat.intWeek_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509sat_bitWeek,
      { "bitWeek", "x509sat.bitWeek",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_months,
      { "months", "x509sat.months",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_months_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_allMonths,
      { "allMonths", "x509sat.allMonths",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_intMonth,
      { "intMonth", "x509sat.intMonth",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_intMonth_item,
      { "intMonth item", "x509sat.intMonth_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509sat_bitMonth,
      { "bitMonth", "x509sat.bitMonth",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_years,
      { "years", "x509sat.years",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_years_item,
      { "years item", "x509sat.years_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509sat_first_dayof,
      { "first", "x509sat.first",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "NamedDay", HFILL }},
    { &hf_x509sat_second_dayof,
      { "second", "x509sat.second",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "NamedDay", HFILL }},
    { &hf_x509sat_third_dayof,
      { "third", "x509sat.third",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "NamedDay", HFILL }},
    { &hf_x509sat_fourth_dayof,
      { "fourth", "x509sat.fourth",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "NamedDay", HFILL }},
    { &hf_x509sat_fifth_dayof,
      { "fifth", "x509sat.fifth",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "NamedDay", HFILL }},
    { &hf_x509sat_intNamedDays,
      { "intNamedDays", "x509sat.intNamedDays",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_intNamedDays_vals), 0,
        NULL, HFILL }},
    { &hf_x509sat_bitNamedDays,
      { "bitNamedDays", "x509sat.bitNamedDays",
        FT_BYTES, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_startDayTime,
      { "startDayTime", "x509sat.startDayTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "DayTime", HFILL }},
    { &hf_x509sat_endDayTime,
      { "endDayTime", "x509sat.endDayTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "DayTime", HFILL }},
    { &hf_x509sat_hour,
      { "hour", "x509sat.hour",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509sat_minute,
      { "minute", "x509sat.minute",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509sat_second,
      { "second", "x509sat.second",
        FT_INT32, BASE_DEC, NULL, 0,
        "INTEGER", HFILL }},
    { &hf_x509sat_now,
      { "now", "x509sat.now",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_at,
      { "at", "x509sat.at",
        FT_STRING, BASE_NONE, NULL, 0,
        "GeneralizedTime", HFILL }},
    { &hf_x509sat_between,
      { "between", "x509sat.between",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_x509sat_entirely,
      { "entirely", "x509sat.entirely",
        FT_BOOLEAN, BASE_NONE, NULL, 0,
        "BOOLEAN", HFILL }},
    { &hf_x509sat_localeID1,
      { "localeID1", "x509sat.localeID1",
        FT_OID, BASE_NONE, NULL, 0,
        "OBJECT_IDENTIFIER", HFILL }},
    { &hf_x509sat_localeID2,
      { "localeID2", "x509sat.localeID2",
        FT_UINT32, BASE_DEC, VALS(x509sat_DirectoryString_vals), 0,
        "DirectoryString", HFILL }},
    { &hf_x509sat_T_bitDay_sunday,
      { "sunday", "x509sat.sunday",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509sat_T_bitDay_monday,
      { "monday", "x509sat.monday",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509sat_T_bitDay_tuesday,
      { "tuesday", "x509sat.tuesday",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509sat_T_bitDay_wednesday,
      { "wednesday", "x509sat.wednesday",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x509sat_T_bitDay_thursday,
      { "thursday", "x509sat.thursday",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x509sat_T_bitDay_friday,
      { "friday", "x509sat.friday",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x509sat_T_bitDay_saturday,
      { "saturday", "x509sat.saturday",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x509sat_T_bitWeek_week1,
      { "week1", "x509sat.week1",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509sat_T_bitWeek_week2,
      { "week2", "x509sat.week2",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509sat_T_bitWeek_week3,
      { "week3", "x509sat.week3",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509sat_T_bitWeek_week4,
      { "week4", "x509sat.week4",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x509sat_T_bitWeek_week5,
      { "week5", "x509sat.week5",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_january,
      { "january", "x509sat.january",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_february,
      { "february", "x509sat.february",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_march,
      { "march", "x509sat.march",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_april,
      { "april", "x509sat.april",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_may,
      { "may", "x509sat.may",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_june,
      { "june", "x509sat.june",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_july,
      { "july", "x509sat.july",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_august,
      { "august", "x509sat.august",
        FT_BOOLEAN, 8, NULL, 0x01,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_september,
      { "september", "x509sat.september",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_october,
      { "october", "x509sat.october",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_november,
      { "november", "x509sat.november",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509sat_T_bitMonth_december,
      { "december", "x509sat.december",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x509sat_T_bitNamedDays_sunday,
      { "sunday", "x509sat.sunday",
        FT_BOOLEAN, 8, NULL, 0x80,
        NULL, HFILL }},
    { &hf_x509sat_T_bitNamedDays_monday,
      { "monday", "x509sat.monday",
        FT_BOOLEAN, 8, NULL, 0x40,
        NULL, HFILL }},
    { &hf_x509sat_T_bitNamedDays_tuesday,
      { "tuesday", "x509sat.tuesday",
        FT_BOOLEAN, 8, NULL, 0x20,
        NULL, HFILL }},
    { &hf_x509sat_T_bitNamedDays_wednesday,
      { "wednesday", "x509sat.wednesday",
        FT_BOOLEAN, 8, NULL, 0x10,
        NULL, HFILL }},
    { &hf_x509sat_T_bitNamedDays_thursday,
      { "thursday", "x509sat.thursday",
        FT_BOOLEAN, 8, NULL, 0x08,
        NULL, HFILL }},
    { &hf_x509sat_T_bitNamedDays_friday,
      { "friday", "x509sat.friday",
        FT_BOOLEAN, 8, NULL, 0x04,
        NULL, HFILL }},
    { &hf_x509sat_T_bitNamedDays_saturday,
      { "saturday", "x509sat.saturday",
        FT_BOOLEAN, 8, NULL, 0x02,
        NULL, HFILL }},

/*--- End of included file: packet-x509sat-hfarr.c ---*/
#line 60 "../../asn1/x509sat/packet-x509sat-template.c"
  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509sat-ettarr.c ---*/
#line 1 "../../asn1/x509sat/packet-x509sat-ettarr.c"
    &ett_x509sat_DirectoryString,
    &ett_x509sat_Guide,
    &ett_x509sat_Criteria,
    &ett_x509sat_SET_OF_Criteria,
    &ett_x509sat_CriteriaItem,
    &ett_x509sat_EnhancedGuide,
    &ett_x509sat_PostalAddress,
    &ett_x509sat_TelexNumber,
    &ett_x509sat_FacsimileTelephoneNumber,
    &ett_x509sat_PreferredDeliveryMethod,
    &ett_x509sat_PresentationAddress,
    &ett_x509sat_T_nAddresses,
    &ett_x509sat_ProtocolInformation,
    &ett_x509sat_T_profiles,
    &ett_x509sat_NameAndOptionalUID,
    &ett_x509sat_MultipleMatchingLocalities,
    &ett_x509sat_SEQUENCE_OF_AttributeValueAssertion,
    &ett_x509sat_SubstringAssertion,
    &ett_x509sat_SubstringAssertion_item,
    &ett_x509sat_CaseIgnoreListMatch,
    &ett_x509sat_OctetSubstringAssertion,
    &ett_x509sat_OctetSubstringAssertion_item,
    &ett_x509sat_ZonalSelect,
    &ett_x509sat_TimeSpecification,
    &ett_x509sat_T_time,
    &ett_x509sat_T_absolute,
    &ett_x509sat_SET_OF_Period,
    &ett_x509sat_Period,
    &ett_x509sat_SET_OF_DayTimeBand,
    &ett_x509sat_T_days,
    &ett_x509sat_T_intDay,
    &ett_x509sat_T_bitDay,
    &ett_x509sat_T_weeks,
    &ett_x509sat_T_intWeek,
    &ett_x509sat_T_bitWeek,
    &ett_x509sat_T_months,
    &ett_x509sat_T_intMonth,
    &ett_x509sat_T_bitMonth,
    &ett_x509sat_T_years,
    &ett_x509sat_XDayOf,
    &ett_x509sat_NamedDay,
    &ett_x509sat_T_bitNamedDays,
    &ett_x509sat_DayTimeBand,
    &ett_x509sat_DayTime,
    &ett_x509sat_TimeAssertion,
    &ett_x509sat_T_between,
    &ett_x509sat_LocaleContextSyntax,

/*--- End of included file: packet-x509sat-ettarr.c ---*/
#line 65 "../../asn1/x509sat/packet-x509sat-template.c"
  };

  /* Register protocol */
  proto_x509sat = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509sat, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));


/*--- Included file: packet-x509sat-syn-reg.c ---*/
#line 1 "../../asn1/x509sat/packet-x509sat-syn-reg.c"
  /*--- Syntax registrations ---*/
  register_ber_syntax_dissector("BitString", proto_x509sat, dissect_BitString_PDU);
  register_ber_syntax_dissector("Boolean", proto_x509sat, dissect_Boolean_PDU);
  register_ber_syntax_dissector("CaseIgnoreListMatch", proto_x509sat, dissect_CaseIgnoreListMatch_PDU);
  register_ber_syntax_dissector("CountryName", proto_x509sat, dissect_CountryName_PDU);
  register_ber_syntax_dissector("DestinationIndicator", proto_x509sat, dissect_DestinationIndicator_PDU);
  register_ber_syntax_dissector("DirectoryString", proto_x509sat, dissect_DirectoryString_PDU);
  register_ber_syntax_dissector("EnhancedGuide", proto_x509sat, dissect_EnhancedGuide_PDU);
  register_ber_syntax_dissector("FacsimileTelephoneNumber", proto_x509sat, dissect_FacsimileTelephoneNumber_PDU);
  register_ber_syntax_dissector("GUID", proto_x509sat, dissect_GUID_PDU);
  register_ber_syntax_dissector("Guide", proto_x509sat, dissect_Guide_PDU);
  register_ber_syntax_dissector("InternationalISDNNumber", proto_x509sat, dissect_InternationalISDNNumber_PDU);
  register_ber_syntax_dissector("Integer", proto_x509sat, dissect_Integer_PDU);
  register_ber_syntax_dissector("NameAndOptionalUID", proto_x509sat, dissect_NameAndOptionalUID_PDU);
  register_ber_syntax_dissector("ObjectIdentifier", proto_x509sat, dissect_ObjectIdentifier_PDU);
  register_ber_syntax_dissector("OctetString", proto_x509sat, dissect_OctetString_PDU);
  register_ber_syntax_dissector("PostalAddress", proto_x509sat, dissect_PostalAddress_PDU);
  register_ber_syntax_dissector("PreferredDeliveryMethod", proto_x509sat, dissect_PreferredDeliveryMethod_PDU);
  register_ber_syntax_dissector("PresentationAddress", proto_x509sat, dissect_PresentationAddress_PDU);
  register_ber_syntax_dissector("BMPString", proto_x509sat, dissect_SyntaxBMPString_PDU);
  register_ber_syntax_dissector("GeneralizedTime", proto_x509sat, dissect_SyntaxGeneralizedTime_PDU);
  register_ber_syntax_dissector("GeneralString", proto_x509sat, dissect_SyntaxGeneralString_PDU);
  register_ber_syntax_dissector("GraphicString", proto_x509sat, dissect_SyntaxGraphicString_PDU);
  register_ber_syntax_dissector("IA5String", proto_x509sat, dissect_SyntaxIA5String_PDU);
  register_ber_syntax_dissector("ISO646String", proto_x509sat, dissect_SyntaxISO646String_PDU);
  register_ber_syntax_dissector("NumericString", proto_x509sat, dissect_SyntaxNumericString_PDU);
  register_ber_syntax_dissector("PrintableString", proto_x509sat, dissect_SyntaxPrintableString_PDU);
  register_ber_syntax_dissector("T61String", proto_x509sat, dissect_SyntaxT61String_PDU);
  register_ber_syntax_dissector("TeletexString", proto_x509sat, dissect_SyntaxTeletexString_PDU);
  register_ber_syntax_dissector("UniversalString", proto_x509sat, dissect_SyntaxUniversalString_PDU);
  register_ber_syntax_dissector("UTF8String", proto_x509sat, dissect_SyntaxUTF8String_PDU);
  register_ber_syntax_dissector("UTCTime", proto_x509sat, dissect_SyntaxUTCTime_PDU);
  register_ber_syntax_dissector("VideotexString", proto_x509sat, dissect_SyntaxVideotexString_PDU);
  register_ber_syntax_dissector("VisibleString", proto_x509sat, dissect_SyntaxVisibleString_PDU);
  register_ber_syntax_dissector("TelephoneNumber", proto_x509sat, dissect_TelephoneNumber_PDU);
  register_ber_syntax_dissector("TelexNumber", proto_x509sat, dissect_TelexNumber_PDU);
  register_ber_syntax_dissector("UniqueIdentifier", proto_x509sat, dissect_UniqueIdentifier_PDU);
  register_ber_syntax_dissector("X121Address", proto_x509sat, dissect_X121Address_PDU);

/*--- End of included file: packet-x509sat-syn-reg.c ---*/
#line 75 "../../asn1/x509sat/packet-x509sat-template.c"

}


/*--- proto_reg_handoff_x509sat -------------------------------------------*/
void proto_reg_handoff_x509sat(void) {

/*--- Included file: packet-x509sat-dis-tab.c ---*/
#line 1 "../../asn1/x509sat/packet-x509sat-dis-tab.c"
  register_ber_oid_dissector("2.5.4.0", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-objectClass");
  register_ber_oid_dissector("2.5.4.2", dissect_DirectoryString_PDU, proto_x509sat, "id-at-knowledgeInformation");
  register_ber_oid_dissector("2.5.4.3", dissect_DirectoryString_PDU, proto_x509sat, "id-at-commonName");
  register_ber_oid_dissector("2.5.4.4", dissect_DirectoryString_PDU, proto_x509sat, "id-at-surname");
  register_ber_oid_dissector("2.5.4.5", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-serialNumber");
  register_ber_oid_dissector("2.5.4.6", dissect_CountryName_PDU, proto_x509sat, "id-at-countryName");
  register_ber_oid_dissector("2.5.4.7", dissect_DirectoryString_PDU, proto_x509sat, "id-at-localityName");
  register_ber_oid_dissector("2.5.4.7.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveLocalityName");
  register_ber_oid_dissector("2.5.4.8", dissect_DirectoryString_PDU, proto_x509sat, "id-at-stateOrProvinceName");
  register_ber_oid_dissector("2.5.4.8.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveStateOrProvinceName");
  register_ber_oid_dissector("2.5.4.9", dissect_DirectoryString_PDU, proto_x509sat, "id-at-streetAddress");
  register_ber_oid_dissector("2.5.4.9.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveStreetAddress");
  register_ber_oid_dissector("2.5.4.10.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveOrganizationName");
  register_ber_oid_dissector("2.5.4.10", dissect_DirectoryString_PDU, proto_x509sat, "id-at-organizationName");
  register_ber_oid_dissector("2.5.4.11", dissect_DirectoryString_PDU, proto_x509sat, "id-at-organizationalUnitName");
  register_ber_oid_dissector("2.5.4.11.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveOrganizationalUnitName");
  register_ber_oid_dissector("2.5.4.12", dissect_DirectoryString_PDU, proto_x509sat, "id-at-title");
  register_ber_oid_dissector("2.5.4.13", dissect_DirectoryString_PDU, proto_x509sat, "id-at-description");
  register_ber_oid_dissector("2.5.4.14", dissect_Guide_PDU, proto_x509sat, "id-at-searchGuide");
  register_ber_oid_dissector("2.5.4.15", dissect_DirectoryString_PDU, proto_x509sat, "id-at-businessCategory");
  register_ber_oid_dissector("2.5.4.16", dissect_PostalAddress_PDU, proto_x509sat, "id-at-postalAddress");
  register_ber_oid_dissector("2.5.4.17", dissect_DirectoryString_PDU, proto_x509sat, "id-at-postalCode");
  register_ber_oid_dissector("2.5.4.17.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectivePostalCode");
  register_ber_oid_dissector("2.5.4.18", dissect_DirectoryString_PDU, proto_x509sat, "id-at-postOfficeBox");
  register_ber_oid_dissector("2.5.4.18.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectivePostOfficeBox");
  register_ber_oid_dissector("2.5.4.19", dissect_DirectoryString_PDU, proto_x509sat, "id-at-physicalDeliveryOfficeName");
  register_ber_oid_dissector("2.5.4.19.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectivePhysicalDeliveryOfficeName");
  register_ber_oid_dissector("2.5.4.20", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-telephoneNumber");
  register_ber_oid_dissector("2.5.4.20.1", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-collectiveTelephoneNumber");
  register_ber_oid_dissector("2.5.4.21", dissect_TelexNumber_PDU, proto_x509sat, "id-at-telexNumber");
  register_ber_oid_dissector("2.5.4.21.1", dissect_TelexNumber_PDU, proto_x509sat, "id-at-collectiveTelexNumber");
  register_ber_oid_dissector("2.5.4.23", dissect_FacsimileTelephoneNumber_PDU, proto_x509sat, "id-at-facsimileTelephoneNumber");
  register_ber_oid_dissector("2.5.4.23.1", dissect_FacsimileTelephoneNumber_PDU, proto_x509sat, "id-at-collectiveFacsimileTelephoneNumber");
  register_ber_oid_dissector("2.5.4.24", dissect_X121Address_PDU, proto_x509sat, "id-at-x121Address");
  register_ber_oid_dissector("2.5.4.25", dissect_InternationalISDNNumber_PDU, proto_x509sat, "id-at-internationalISDNNumber");
  register_ber_oid_dissector("2.5.4.25.1", dissect_InternationalISDNNumber_PDU, proto_x509sat, "id-at-collectiveInternationalISDNNumber");
  register_ber_oid_dissector("2.5.4.26", dissect_PostalAddress_PDU, proto_x509sat, "id-at-registeredAddress");
  register_ber_oid_dissector("2.5.4.27", dissect_DestinationIndicator_PDU, proto_x509sat, "id-at-destinationIndicator");
  register_ber_oid_dissector("2.5.4.28", dissect_PreferredDeliveryMethod_PDU, proto_x509sat, "id-at-preferredDeliveryMethod");
  register_ber_oid_dissector("2.5.4.29", dissect_PresentationAddress_PDU, proto_x509sat, "id-at-presentationAddress");
  register_ber_oid_dissector("2.5.4.30", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-supportedApplicationContext");
  register_ber_oid_dissector("2.5.4.35", dissect_OctetString_PDU, proto_x509sat, "id-at-userPassword");
  register_ber_oid_dissector("2.5.4.41", dissect_DirectoryString_PDU, proto_x509sat, "id-at-name");
  register_ber_oid_dissector("2.5.4.42", dissect_DirectoryString_PDU, proto_x509sat, "id-at-givenName");
  register_ber_oid_dissector("2.5.4.43", dissect_DirectoryString_PDU, proto_x509sat, "id-at-initials");
  register_ber_oid_dissector("2.5.4.44", dissect_DirectoryString_PDU, proto_x509sat, "id-at-generationQualifier");
  register_ber_oid_dissector("2.5.4.45", dissect_UniqueIdentifier_PDU, proto_x509sat, "id-at-uniqueIdedntifier");
  register_ber_oid_dissector("2.5.4.46", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-dnQualifier");
  register_ber_oid_dissector("2.5.4.47", dissect_EnhancedGuide_PDU, proto_x509sat, "id-at-enhancedSearchGuide");
  register_ber_oid_dissector("2.5.4.48", dissect_ProtocolInformation_PDU, proto_x509sat, "id-at-protocolInformation");
  register_ber_oid_dissector("2.5.4.50", dissect_NameAndOptionalUID_PDU, proto_x509sat, "id-at-uniqueMember");
  register_ber_oid_dissector("2.5.4.51", dissect_DirectoryString_PDU, proto_x509sat, "id-at-houseIdentifier");
  register_ber_oid_dissector("2.5.4.52", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-supportedAlgorithms");
  register_ber_oid_dissector("2.5.4.54", dissect_DirectoryString_PDU, proto_x509sat, "id-at-dmdName");
  register_ber_oid_dissector("2.5.4.65", dissect_DirectoryString_PDU, proto_x509sat, "id-at-pseudonym");
  register_ber_oid_dissector("2.5.4.66", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-communuicationsService");
  register_ber_oid_dissector("2.5.4.67", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-communuicationsNetwork");
  register_ber_oid_dissector("2.5.13.8", dissect_SyntaxNumericString_PDU, proto_x509sat, "id-mr-numericStringMatch");
  register_ber_oid_dissector("2.5.13.11", dissect_CaseIgnoreListMatch_PDU, proto_x509sat, "id-mr-caseIgnoreListMatch");
  register_ber_oid_dissector("2.5.13.16", dissect_BitString_PDU, proto_x509sat, "id-mr-bitStringMatch");
  register_ber_oid_dissector("2.5.13.26", dissect_SyntaxUTCTime_PDU, proto_x509sat, "id-mr-uTCTimeOrderingMatch");
  register_ber_oid_dissector("2.5.18.1", dissect_SyntaxGeneralizedTime_PDU, proto_x509sat, "id-oa-createTimeStamp");
  register_ber_oid_dissector("2.5.18.2", dissect_SyntaxGeneralizedTime_PDU, proto_x509sat, "id-oa-modifyTimeStamp");
  register_ber_oid_dissector("2.5.18.5", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-oa-administrativeRole");
  register_ber_oid_dissector("2.5.18.7", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-oa-collectiveExclusions");
  register_ber_oid_dissector("2.5.18.8", dissect_SyntaxGeneralizedTime_PDU, proto_x509sat, "id-oa-subschemaTimeStamp");
  register_ber_oid_dissector("2.5.18.9", dissect_Boolean_PDU, proto_x509sat, "id-oa-hasSubordinates");
  register_ber_oid_dissector("2.5.24.1", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-aca-accessControlScheme");
  register_ber_oid_dissector("2.6.5.2.8", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-mhs-supported-automatic-actions");
  register_ber_oid_dissector("2.6.5.2.10", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-mhs-supported-attributes");
  register_ber_oid_dissector("2.6.5.2.11", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-mhs-supported-matching-rules");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.45", dissect_DirectoryString_PDU, proto_x509sat, "id-at-releaseAuthorityName");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.51", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-cognizantAuthority");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.53", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-accountingCode");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.54", dissect_Boolean_PDU, proto_x509sat, "id-at-dualRoute");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.55", dissect_SyntaxGeneralizedTime_PDU, proto_x509sat, "id-at-effectiveDate");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.57", dissect_SyntaxGeneralizedTime_PDU, proto_x509sat, "id-at-expirationDate");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.58", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-hostOrgACP127");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.60", dissect_SyntaxGeneralizedTime_PDU, proto_x509sat, "id-at-lastRecapDate");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.62", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-lmf");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.63", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-longTitle");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.64", dissect_Boolean_PDU, proto_x509sat, "id-at-minimize");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.65", dissect_Boolean_PDU, proto_x509sat, "id-at-minimizeOverride");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.68", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-nationality");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.68.1", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-collectiveNationality");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.69", dissect_Boolean_PDU, proto_x509sat, "id-at-transferStation");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.70", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-plaNameACP127");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.72", dissect_Boolean_PDU, proto_x509sat, "id-at-plaReplace");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.73", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-primarySpellingACP127");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.74", dissect_Boolean_PDU, proto_x509sat, "id-at-publish");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.75", dissect_SyntaxGeneralizedTime_PDU, proto_x509sat, "id-at-recapDueDate");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.77", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-rI");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.81", dissect_Boolean_PDU, proto_x509sat, "id-at-section");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.82", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-serviceOrAgency");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.83", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-sHD");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.84", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-shortTitle");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.85", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-sigad");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.86", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-spot");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.87", dissect_Boolean_PDU, proto_x509sat, "id-at-tARE");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.94", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-aCPMobileTelephoneNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.95", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-aCPPagerTelephoneNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.96", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-tCC");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.97", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-tRC");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.106", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-accessCodes");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.107", dissect_SyntaxGraphicString_PDU, proto_x509sat, "id-at-accessSchema");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.109", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-aCPTelephoneFaxNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.115", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-gatewayType");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.116", dissect_ObjectIdentifier_PDU, proto_x509sat, "id-at-ghpType");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.118", dissect_DirectoryString_PDU, proto_x509sat, "id-at-mailDomains");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.119", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-militaryFacsimileNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.119.1", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-collectiveMilitaryFacsimileNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.120", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-militaryTelephoneNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.120.1", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-collectiveMilitaryTelephoneNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.122", dissect_SyntaxGraphicString_PDU, proto_x509sat, "id-at-networkSchema");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.124", dissect_DirectoryString_PDU, proto_x509sat, "id-at-operationName");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.125", dissect_DirectoryString_PDU, proto_x509sat, "id-at-positionNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.126", dissect_DirectoryString_PDU, proto_x509sat, "id-at-proprietaryMailboxes");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.127", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-secureFacsimileNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.127.1", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-collectiveSecureFacsimileNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.128", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-secureTelephoneNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.128.1", dissect_TelephoneNumber_PDU, proto_x509sat, "id-at-collectiveSecureTelephoneNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.129", dissect_DirectoryString_PDU, proto_x509sat, "id-at-serviceNumber");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.133", dissect_DirectoryString_PDU, proto_x509sat, "id-at-rank");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.143", dissect_DirectoryString_PDU, proto_x509sat, "id-at-adminConversion");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.144", dissect_SyntaxPrintableString_PDU, proto_x509sat, "id-at-tCCG");
  register_ber_oid_dissector("2.16.840.1.101.2.2.1.145", dissect_DirectoryString_PDU, proto_x509sat, "id-at-usdConversion");
  register_ber_oid_dissector("1.2.840.113549.1.9.1", dissect_SyntaxIA5String_PDU, proto_x509sat, "pkcs-9-at-emailAddress");
  register_ber_oid_dissector("1.2.840.113549.1.9.7", dissect_DirectoryString_PDU, proto_x509sat, "pkcs-9-at-challengePassword");
  register_ber_oid_dissector("1.2.840.113549.1.9.8", dissect_DirectoryString_PDU, proto_x509sat, "pkcs-9-at-unstructuredAddress");
  register_ber_oid_dissector("1.2.840.113549.1.9.13", dissect_DirectoryString_PDU, proto_x509sat, "pkcs-9-at-signingDescription");
  register_ber_oid_dissector("1.2.840.113549.1.9.20", dissect_SyntaxBMPString_PDU, proto_x509sat, "pkcs-9-at-friendlyName");
  register_ber_oid_dissector("1.2.840.113549.1.9.21", dissect_OctetString_PDU, proto_x509sat, "pkcs-9-at-localKeyId");
  register_ber_oid_dissector("1.2.840.113549.1.9.25.3", dissect_OctetString_PDU, proto_x509sat, "pkcs-9-at-randomNonce");
  register_ber_oid_dissector("1.2.840.113549.1.9.25.4", dissect_Integer_PDU, proto_x509sat, "pkcs-9-at-sequenceNumber");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.1", dissect_SyntaxGeneralizedTime_PDU, proto_x509sat, "pkcs-9-at-dateOfBirth");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.2", dissect_DirectoryString_PDU, proto_x509sat, "pkcs-9-at-placeOfBirth");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.3", dissect_SyntaxPrintableString_PDU, proto_x509sat, "pkcs-9-at-gender");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.4", dissect_SyntaxPrintableString_PDU, proto_x509sat, "pkcs-9-at-countryOfCitizenship");
  register_ber_oid_dissector("1.3.6.1.5.5.7.9.5", dissect_SyntaxPrintableString_PDU, proto_x509sat, "pkcs-9-at-countryOfResidence");
  register_ber_oid_dissector("0.9.2342.19200300.100.1.25", dissect_SyntaxIA5String_PDU, proto_x509sat, "dc");
  register_ber_oid_dissector("1.3.6.1.4.1.311.20.2", dissect_SyntaxBMPString_PDU, proto_x509sat, "id-ms-certificate-template-name");
  register_ber_oid_dissector("1.3.6.1.4.1.311.20.2.3", dissect_SyntaxUTF8String_PDU, proto_x509sat, "id-ms-user-principal-name");
  register_ber_oid_dissector("1.3.6.1.4.1.311.17.1", dissect_SyntaxBMPString_PDU, proto_x509sat, "id-ms-local-machine-keyset");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.1", dissect_Integer_PDU, proto_x509sat, "id-ms-ca-version");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.2", dissect_OctetString_PDU, proto_x509sat, "id-ms-previous-cert-hash");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.3", dissect_Integer_PDU, proto_x509sat, "id-ms-virtual-base");
  register_ber_oid_dissector("1.3.6.1.4.1.311.21.4", dissect_SyntaxUTCTime_PDU, proto_x509sat, "id-ms-next-publish");
  register_ber_oid_dissector("1.2.826.0.1063.7.0.0.0", dissect_Integer_PDU, proto_x509sat, "unknown-UK-organisation-defined-extension");
  register_ber_oid_dissector("1.2.826.0.1004.10.1.1", dissect_SyntaxIA5String_PDU, proto_x509sat, "nexor-originating-ua");
  register_ber_oid_dissector("2.6.1.6.3", dissect_Boolean_PDU, proto_x509sat, "id-sat-ipm-auto-discarded");
  register_ber_oid_dissector("1.3.6.1.1.16.4", dissect_GUID_PDU, proto_x509sat, "entryUUID");
  register_ber_oid_dissector("1.3.6.1.4.1.311.60.2.1.1", dissect_DirectoryString_PDU, proto_x509sat, "jurisdictionOfIncorporationLocalityName");
  register_ber_oid_dissector("1.3.6.1.4.1.311.60.2.1.2", dissect_DirectoryString_PDU, proto_x509sat, "jurisdictionOfIncorporationStateOrProvinceName");
  register_ber_oid_dissector("1.3.6.1.4.1.311.60.2.1.3", dissect_CountryName_PDU, proto_x509sat, "jurisdictionOfIncorporationCountryName");


/*--- End of included file: packet-x509sat-dis-tab.c ---*/
#line 82 "../../asn1/x509sat/packet-x509sat-template.c"

  /* OBJECT CLASSES */

  oid_add_from_string("top","2.5.6.0");
  oid_add_from_string("alias","2.5.6.1");
  oid_add_from_string("country","2.5.6.2");
  oid_add_from_string("locality","2.5.6.3");
  oid_add_from_string("organization","2.5.6.4");
  oid_add_from_string("organizationalUnit","2.5.6.5");
  oid_add_from_string("person","2.5.6.6");
  oid_add_from_string("organizationalPerson","2.5.6.7");
  oid_add_from_string("organizationalRole","2.5.6.8");
  oid_add_from_string("groupOfNames","2.5.6.9");
  oid_add_from_string("residentialPerson","2.5.6.10");
  oid_add_from_string("applicationProcess","2.5.6.11");
  oid_add_from_string("applicationEntity","2.5.6.12");
  oid_add_from_string("dSA","2.5.6.13");
  oid_add_from_string("device","2.5.6.14");
  oid_add_from_string("strongAuthenticationUser","2.5.6.15");
  oid_add_from_string("certificationAuthority","2.5.6.16");
  oid_add_from_string("certificationAuthorityV2","2.5.6.16.2");
  oid_add_from_string("groupOfUniqueNames","2.5.6.17");
  oid_add_from_string("userSecurityInformation","2.5.6.18");
  oid_add_from_string("cRLDistributionPoint","2.5.6.19");
  oid_add_from_string("dmd","2.5.6.20");
  oid_add_from_string("pkiUser","2.5.6.21");
  oid_add_from_string("pkiCA","2.5.6.22");
  
  oid_add_from_string("parent","2.5.6.28");
  oid_add_from_string("child","2.5.6.29");

  /* RFC 2247 */
  oid_add_from_string("dcObject","1.3.6.1.4.1.1446.344");
  oid_add_from_string("domain","0.9.2342.19200300.100.4.13");

}



