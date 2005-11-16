/* Do not modify this file.                                                   */
/* It is created automatically by the ASN.1 to Ethereal dissector compiler    */
/* .\packet-x509sat.c                                                         */
/* ../../tools/asn2eth.py -X -b -e -p x509sat -c x509sat.cnf -s packet-x509sat-template SelectedAttributeTypes.asn */

/* Input file: packet-x509sat-template.c */

/* packet-x509sat.c
 * Routines for X.509 Selected Attribute Types packet dissection
 *  Ronnie Sahlberg 2004
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
#include "packet-x509sat.h"
#include "packet-x509if.h"

#define PNAME  "X.509 Selected Attribute Types"
#define PSNAME "X509SAT"
#define PFNAME "x509sat"

/* Initialize the protocol and registered fields */
int proto_x509sat = -1;

/*--- Included file: packet-x509sat-hf.c ---*/

static int hf_x509sat_DirectoryString_PDU = -1;   /* DirectoryString */
static int hf_x509sat_UniqueIdentifier_PDU = -1;  /* UniqueIdentifier */
static int hf_x509sat_CountryName_PDU = -1;       /* CountryName */
static int hf_x509sat_Guide_PDU = -1;             /* Guide */
static int hf_x509sat_Criteria_PDU = -1;          /* Criteria */
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
static int hf_x509sat_NameAndOptionalUID_PDU = -1;  /* NameAndOptionalUID */
static int hf_x509sat_CaseIgnoreListMatch_PDU = -1;  /* CaseIgnoreListMatch */
static int hf_x509sat_DayTimeBand_PDU = -1;       /* DayTimeBand */
static int hf_x509sat_DayTime_PDU = -1;           /* DayTime */
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


/* Initialize the subtree pointers */

/*--- Included file: packet-x509sat-ett.c ---*/

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



/*--- Included file: packet-x509sat-fn.c ---*/

/*--- Cyclic dependencies ---*/

/* Criteria -> Criteria/and -> Criteria */
/* Criteria -> Criteria */
int dissect_x509sat_Criteria(gboolean implicit_tag, tvbuff_t *tvb, int offset, packet_info *pinfo, proto_tree *tree, int hf_index);

static int dissect_criteria(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_Criteria(FALSE, tvb, offset, pinfo, tree, hf_x509sat_criteria);
}
static int dissect_and_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_Criteria(FALSE, tvb, offset, pinfo, tree, hf_x509sat_and_item);
}
static int dissect_or_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_Criteria(FALSE, tvb, offset, pinfo, tree, hf_x509sat_or_item);
}
static int dissect_not(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_Criteria(FALSE, tvb, offset, pinfo, tree, hf_x509sat_not);
}


/*--- Fields for imported types ---*/

static int dissect_equality(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_equality);
}
static int dissect_substrings(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_substrings);
}
static int dissect_greaterOrEqual(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_greaterOrEqual);
}
static int dissect_lessOrEqual(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_lessOrEqual);
}
static int dissect_approximateMatch(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_approximateMatch);
}
static int dissect_dn(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_DistinguishedName(FALSE, tvb, offset, pinfo, tree, hf_x509sat_dn);
}
static int dissect_attributeList_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_x509sat_attributeList_item);
}
static int dissect_control(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_Attribute(FALSE, tvb, offset, pinfo, tree, hf_x509sat_control);
}
static int dissect_ZonalSelect_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509if_AttributeType(FALSE, tvb, offset, pinfo, tree, hf_x509sat_ZonalSelect_item);
}



int
dissect_x509sat_DirectoryString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
	offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);


  return offset;
}
static int dissect_PostalAddress_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_PostalAddress_item);
}
static int dissect_initial(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_initial);
}
static int dissect_any(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_any);
}
static int dissect_final(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_final);
}
static int dissect_CaseIgnoreListMatch_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_CaseIgnoreListMatch_item);
}
static int dissect_localeID2(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DirectoryString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_localeID2);
}



int
dissect_x509sat_UniqueIdentifier(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    NULL, hf_index, -1,
                                    NULL);

  return offset;
}
static int dissect_uid(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_UniqueIdentifier(FALSE, tvb, offset, pinfo, tree, hf_x509sat_uid);
}



int
dissect_x509sat_CountryName(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_OBJECT_IDENTIFIER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_object_identifier(implicit_tag, pinfo, tree, tvb, offset, hf_index, NULL);

  return offset;
}
static int dissect_objectClass(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_objectClass);
}
static int dissect_profiles_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_profiles_item);
}
static int dissect_matchingRuleUsed(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_matchingRuleUsed);
}
static int dissect_localeID1(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OBJECT_IDENTIFIER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_localeID1);
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
  {   0, BER_CLASS_CON, 0, 0, dissect_equality },
  {   1, BER_CLASS_CON, 1, 0, dissect_substrings },
  {   2, BER_CLASS_CON, 2, 0, dissect_greaterOrEqual },
  {   3, BER_CLASS_CON, 3, 0, dissect_lessOrEqual },
  {   4, BER_CLASS_CON, 4, 0, dissect_approximateMatch },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_CriteriaItem(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 CriteriaItem_choice, hf_index, ett_x509sat_CriteriaItem,
                                 NULL);

  return offset;
}
static int dissect_type(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_CriteriaItem(FALSE, tvb, offset, pinfo, tree, hf_x509sat_type);
}


static const ber_sequence_t SET_OF_Criteria_set_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_and_item },
};

static int
dissect_x509sat_SET_OF_Criteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Criteria_set_of, hf_index, ett_x509sat_SET_OF_Criteria);

  return offset;
}
static int dissect_and(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_SET_OF_Criteria(FALSE, tvb, offset, pinfo, tree, hf_x509sat_and);
}
static int dissect_or(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_SET_OF_Criteria(FALSE, tvb, offset, pinfo, tree, hf_x509sat_or);
}


const value_string x509sat_Criteria_vals[] = {
  {   0, "type" },
  {   1, "and" },
  {   2, "or" },
  {   3, "not" },
  { 0, NULL }
};

static const ber_choice_t Criteria_choice[] = {
  {   0, BER_CLASS_CON, 0, 0, dissect_type },
  {   1, BER_CLASS_CON, 1, 0, dissect_and },
  {   2, BER_CLASS_CON, 2, 0, dissect_or },
  {   3, BER_CLASS_CON, 3, 0, dissect_not },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509sat_Criteria(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 Criteria_choice, hf_index, ett_x509sat_Criteria,
                                 NULL);

  return offset;
}


static const ber_sequence_t Guide_set[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_objectClass },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_criteria },
  { 0, 0, 0, NULL }
};

static int
dissect_x509sat_Guide(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_x509sat_T_subset(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_subset(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_subset(FALSE, tvb, offset, pinfo, tree, hf_x509sat_subset);
}


static const ber_sequence_t EnhancedGuide_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_objectClass },
  { BER_CLASS_CON, 1, BER_FLAGS_NOTCHKTAG, dissect_criteria },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_subset },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_EnhancedGuide(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   EnhancedGuide_sequence, hf_index, ett_x509sat_EnhancedGuide);

  return offset;
}


static const ber_sequence_t PostalAddress_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_PostalAddress_item },
};

int
dissect_x509sat_PostalAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      PostalAddress_sequence_of, hf_index, ett_x509sat_PostalAddress);

  return offset;
}



static int
dissect_x509sat_TelephoneNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_telephoneNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_TelephoneNumber(FALSE, tvb, offset, pinfo, tree, hf_x509sat_telephoneNumber);
}



static int
dissect_x509sat_PrintableString(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}
static int dissect_telexNumber(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_telexNumber);
}
static int dissect_countryCode(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_countryCode);
}
static int dissect_answerback(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PrintableString(FALSE, tvb, offset, pinfo, tree, hf_x509sat_answerback);
}


static const ber_sequence_t TelexNumber_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_telexNumber },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_countryCode },
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_answerback },
  { 0, 0, 0, NULL }
};

static int
dissect_x509sat_TelexNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TelexNumber_sequence, hf_index, ett_x509sat_TelexNumber);

  return offset;
}


static const ber_sequence_t FacsimileTelephoneNumber_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_telephoneNumber },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_FacsimileTelephoneNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   FacsimileTelephoneNumber_sequence, hf_index, ett_x509sat_FacsimileTelephoneNumber);

  return offset;
}



int
dissect_x509sat_X121Address(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



int
dissect_x509sat_InternationalISDNNumber(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_NumericString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



int
dissect_x509sat_DestinationIndicator(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
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
dissect_x509sat_PreferredDeliveryMethod_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_PreferredDeliveryMethod_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_PreferredDeliveryMethod_item(FALSE, tvb, offset, pinfo, tree, hf_x509sat_PreferredDeliveryMethod_item);
}


static const ber_sequence_t PreferredDeliveryMethod_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_PreferredDeliveryMethod_item },
};

int
dissect_x509sat_PreferredDeliveryMethod(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      PreferredDeliveryMethod_sequence_of, hf_index, ett_x509sat_PreferredDeliveryMethod);

  return offset;
}



static int
dissect_x509sat_OCTET_STRING(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_octet_string(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                       NULL);

  return offset;
}
static int dissect_pSelector(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509sat_pSelector);
}
static int dissect_sSelector(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509sat_sSelector);
}
static int dissect_tSelector(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509sat_tSelector);
}
static int dissect_nAddresses_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509sat_nAddresses_item);
}
static int dissect_nAddress(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509sat_nAddress);
}
static int dissect_initial_substring(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509sat_initial_substring);
}
static int dissect_any_substring(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509sat_any_substring);
}
static int dissect_finall_substring(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OCTET_STRING(FALSE, tvb, offset, pinfo, tree, hf_x509sat_finall_substring);
}


static const ber_sequence_t T_nAddresses_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_nAddresses_item },
};

static int
dissect_x509sat_T_nAddresses(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_nAddresses_set_of, hf_index, ett_x509sat_T_nAddresses);

  return offset;
}
static int dissect_nAddresses(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_nAddresses(FALSE, tvb, offset, pinfo, tree, hf_x509sat_nAddresses);
}


static const ber_sequence_t PresentationAddress_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_pSelector },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_sSelector },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_tSelector },
  { BER_CLASS_CON, 3, 0, dissect_nAddresses },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_PresentationAddress(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   PresentationAddress_sequence, hf_index, ett_x509sat_PresentationAddress);

  return offset;
}


static const ber_sequence_t T_profiles_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_profiles_item },
};

static int
dissect_x509sat_T_profiles(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_profiles_set_of, hf_index, ett_x509sat_T_profiles);

  return offset;
}
static int dissect_profiles(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_profiles(FALSE, tvb, offset, pinfo, tree, hf_x509sat_profiles);
}


static const ber_sequence_t ProtocolInformation_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OCTETSTRING, BER_FLAGS_NOOWNTAG, dissect_nAddress },
  { BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_profiles },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_ProtocolInformation(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   ProtocolInformation_sequence, hf_index, ett_x509sat_ProtocolInformation);

  return offset;
}


static const ber_sequence_t NameAndOptionalUID_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_dn },
  { BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_uid },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_NameAndOptionalUID(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   NameAndOptionalUID_sequence, hf_index, ett_x509sat_NameAndOptionalUID);

  return offset;
}


static const ber_sequence_t SEQUENCE_OF_AttributeValueAssertion_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_attributeList_item },
};

static int
dissect_x509sat_SEQUENCE_OF_AttributeValueAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SEQUENCE_OF_AttributeValueAssertion_sequence_of, hf_index, ett_x509sat_SEQUENCE_OF_AttributeValueAssertion);

  return offset;
}
static int dissect_attributeList(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_SEQUENCE_OF_AttributeValueAssertion(FALSE, tvb, offset, pinfo, tree, hf_x509sat_attributeList);
}


static const ber_sequence_t MultipleMatchingLocalities_sequence[] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_matchingRuleUsed },
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_attributeList },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_MultipleMatchingLocalities(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
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
  {   0, BER_CLASS_CON, 0, 0, dissect_initial },
  {   1, BER_CLASS_CON, 1, 0, dissect_any },
  {   2, BER_CLASS_CON, 2, 0, dissect_final },
  {   3, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_control },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_SubstringAssertion_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 SubstringAssertion_item_choice, hf_index, ett_x509sat_SubstringAssertion_item,
                                 NULL);

  return offset;
}
static int dissect_SubstringAssertion_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_SubstringAssertion_item(FALSE, tvb, offset, pinfo, tree, hf_x509sat_SubstringAssertion_item);
}


static const ber_sequence_t SubstringAssertion_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_SubstringAssertion_item },
};

int
dissect_x509sat_SubstringAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      SubstringAssertion_sequence_of, hf_index, ett_x509sat_SubstringAssertion);

  return offset;
}


static const ber_sequence_t CaseIgnoreListMatch_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_CaseIgnoreListMatch_item },
};

int
dissect_x509sat_CaseIgnoreListMatch(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
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
  {   0, BER_CLASS_CON, 0, 0, dissect_initial_substring },
  {   1, BER_CLASS_CON, 1, 0, dissect_any_substring },
  {   2, BER_CLASS_CON, 2, 0, dissect_finall_substring },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_OctetSubstringAssertion_item(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 OctetSubstringAssertion_item_choice, hf_index, ett_x509sat_OctetSubstringAssertion_item,
                                 NULL);

  return offset;
}
static int dissect_OctetSubstringAssertion_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_OctetSubstringAssertion_item(FALSE, tvb, offset, pinfo, tree, hf_x509sat_OctetSubstringAssertion_item);
}


static const ber_sequence_t OctetSubstringAssertion_sequence_of[1] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_OctetSubstringAssertion_item },
};

int
dissect_x509sat_OctetSubstringAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
                                      OctetSubstringAssertion_sequence_of, hf_index, ett_x509sat_OctetSubstringAssertion);

  return offset;
}


static const ber_sequence_t ZonalSelect_sequence_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_ZonalSelect_item },
};

int
dissect_x509sat_ZonalSelect(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence_of(implicit_tag, pinfo, tree, tvb, offset,
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
dissect_x509sat_ZonalResult(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}



int
dissect_x509sat_LanguageContextSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_restricted_string(implicit_tag, BER_UNI_TAG_PrintableString,
                                            pinfo, tree, tvb, offset, hf_index,
                                            NULL);

  return offset;
}



static int
dissect_x509sat_GeneralizedTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_GeneralizedTime(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_startTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_x509sat_startTime);
}
static int dissect_endTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_x509sat_endTime);
}
static int dissect_at(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_GeneralizedTime(FALSE, tvb, offset, pinfo, tree, hf_x509sat_at);
}


static const ber_sequence_t T_absolute_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_startTime },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_endTime },
  { 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_absolute(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_absolute_sequence, hf_index, ett_x509sat_T_absolute);

  return offset;
}
static int dissect_absolute(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_absolute(FALSE, tvb, offset, pinfo, tree, hf_x509sat_absolute);
}



static int
dissect_x509sat_INTEGER(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_intDay_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_intDay_item);
}
static int dissect_intWeek_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_intWeek_item);
}
static int dissect_intMonth_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_intMonth_item);
}
static int dissect_years_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_years_item);
}
static int dissect_hour(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_hour);
}
static int dissect_minute(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_minute);
}
static int dissect_second(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_INTEGER(FALSE, tvb, offset, pinfo, tree, hf_x509sat_second);
}


static const ber_sequence_t DayTime_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_hour },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_minute },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_second },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_DayTime(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DayTime_sequence, hf_index, ett_x509sat_DayTime);

  return offset;
}
static int dissect_startDayTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DayTime(FALSE, tvb, offset, pinfo, tree, hf_x509sat_startDayTime);
}
static int dissect_endDayTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DayTime(FALSE, tvb, offset, pinfo, tree, hf_x509sat_endDayTime);
}


static const ber_sequence_t DayTimeBand_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_startDayTime },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_endDayTime },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_DayTimeBand(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   DayTimeBand_sequence, hf_index, ett_x509sat_DayTimeBand);

  return offset;
}
static int dissect_timesOfDay_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_DayTimeBand(FALSE, tvb, offset, pinfo, tree, hf_x509sat_timesOfDay_item);
}


static const ber_sequence_t SET_OF_DayTimeBand_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_timesOfDay_item },
};

static int
dissect_x509sat_SET_OF_DayTimeBand(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_DayTimeBand_set_of, hf_index, ett_x509sat_SET_OF_DayTimeBand);

  return offset;
}
static int dissect_timesOfDay(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_SET_OF_DayTimeBand(FALSE, tvb, offset, pinfo, tree, hf_x509sat_timesOfDay);
}


static const ber_sequence_t T_intDay_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_intDay_item },
};

static int
dissect_x509sat_T_intDay(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_intDay_set_of, hf_index, ett_x509sat_T_intDay);

  return offset;
}
static int dissect_intDay(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_intDay(FALSE, tvb, offset, pinfo, tree, hf_x509sat_intDay);
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
dissect_x509sat_T_bitDay(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    T_bitDay_bits, hf_index, ett_x509sat_T_bitDay,
                                    NULL);

  return offset;
}
static int dissect_bitDay(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_bitDay(FALSE, tvb, offset, pinfo, tree, hf_x509sat_bitDay);
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
dissect_x509sat_T_intNamedDays(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_intNamedDays(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_intNamedDays(FALSE, tvb, offset, pinfo, tree, hf_x509sat_intNamedDays);
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
dissect_x509sat_T_bitNamedDays(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    T_bitNamedDays_bits, hf_index, ett_x509sat_T_bitNamedDays,
                                    NULL);

  return offset;
}
static int dissect_bitNamedDays(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_bitNamedDays(FALSE, tvb, offset, pinfo, tree, hf_x509sat_bitNamedDays);
}


const value_string x509sat_NamedDay_vals[] = {
  {   0, "intNamedDays" },
  {   1, "bitNamedDays" },
  { 0, NULL }
};

static const ber_choice_t NamedDay_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_ENUMERATED, BER_FLAGS_NOOWNTAG, dissect_intNamedDays },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_bitNamedDays },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509sat_NamedDay(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 NamedDay_choice, hf_index, ett_x509sat_NamedDay,
                                 NULL);

  return offset;
}
static int dissect_first_dayof(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NamedDay(FALSE, tvb, offset, pinfo, tree, hf_x509sat_first_dayof);
}
static int dissect_second_dayof(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NamedDay(FALSE, tvb, offset, pinfo, tree, hf_x509sat_second_dayof);
}
static int dissect_third_dayof(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NamedDay(FALSE, tvb, offset, pinfo, tree, hf_x509sat_third_dayof);
}
static int dissect_fourth_dayof(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NamedDay(FALSE, tvb, offset, pinfo, tree, hf_x509sat_fourth_dayof);
}
static int dissect_fifth_dayof(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NamedDay(FALSE, tvb, offset, pinfo, tree, hf_x509sat_fifth_dayof);
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
  {   1, BER_CLASS_CON, 1, 0, dissect_first_dayof },
  {   2, BER_CLASS_CON, 2, 0, dissect_second_dayof },
  {   3, BER_CLASS_CON, 3, 0, dissect_third_dayof },
  {   4, BER_CLASS_CON, 4, 0, dissect_fourth_dayof },
  {   5, BER_CLASS_CON, 5, 0, dissect_fifth_dayof },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509sat_XDayOf(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 XDayOf_choice, hf_index, ett_x509sat_XDayOf,
                                 NULL);

  return offset;
}
static int dissect_dayOf(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_XDayOf(FALSE, tvb, offset, pinfo, tree, hf_x509sat_dayOf);
}


static const value_string x509sat_T_days_vals[] = {
  {   0, "intDay" },
  {   1, "bitDay" },
  {   2, "dayOf" },
  { 0, NULL }
};

static const ber_choice_t T_days_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_intDay },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_bitDay },
  {   2, BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG, dissect_dayOf },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_days(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_days_choice, hf_index, ett_x509sat_T_days,
                                 NULL);

  return offset;
}
static int dissect_days(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_days(FALSE, tvb, offset, pinfo, tree, hf_x509sat_days);
}



static int
dissect_x509sat_NULL(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_null(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_allWeeks(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NULL(FALSE, tvb, offset, pinfo, tree, hf_x509sat_allWeeks);
}
static int dissect_allMonths(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NULL(FALSE, tvb, offset, pinfo, tree, hf_x509sat_allMonths);
}
static int dissect_now(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_NULL(FALSE, tvb, offset, pinfo, tree, hf_x509sat_now);
}


static const ber_sequence_t T_intWeek_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_intWeek_item },
};

static int
dissect_x509sat_T_intWeek(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_intWeek_set_of, hf_index, ett_x509sat_T_intWeek);

  return offset;
}
static int dissect_intWeek(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_intWeek(FALSE, tvb, offset, pinfo, tree, hf_x509sat_intWeek);
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
dissect_x509sat_T_bitWeek(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    T_bitWeek_bits, hf_index, ett_x509sat_T_bitWeek,
                                    NULL);

  return offset;
}
static int dissect_bitWeek(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_bitWeek(FALSE, tvb, offset, pinfo, tree, hf_x509sat_bitWeek);
}


static const value_string x509sat_T_weeks_vals[] = {
  {   0, "allWeeks" },
  {   1, "intWeek" },
  {   2, "bitWeek" },
  { 0, NULL }
};

static const ber_choice_t T_weeks_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_allWeeks },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_intWeek },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_bitWeek },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_weeks(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_weeks_choice, hf_index, ett_x509sat_T_weeks,
                                 NULL);

  return offset;
}
static int dissect_weeks(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_weeks(FALSE, tvb, offset, pinfo, tree, hf_x509sat_weeks);
}


static const ber_sequence_t T_intMonth_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_intMonth_item },
};

static int
dissect_x509sat_T_intMonth(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_intMonth_set_of, hf_index, ett_x509sat_T_intMonth);

  return offset;
}
static int dissect_intMonth(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_intMonth(FALSE, tvb, offset, pinfo, tree, hf_x509sat_intMonth);
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
dissect_x509sat_T_bitMonth(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_bitstring(implicit_tag, pinfo, tree, tvb, offset,
                                    T_bitMonth_bits, hf_index, ett_x509sat_T_bitMonth,
                                    NULL);

  return offset;
}
static int dissect_bitMonth(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_bitMonth(FALSE, tvb, offset, pinfo, tree, hf_x509sat_bitMonth);
}


static const value_string x509sat_T_months_vals[] = {
  {   0, "allMonths" },
  {   1, "intMonth" },
  {   2, "bitMonth" },
  { 0, NULL }
};

static const ber_choice_t T_months_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_allMonths },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_intMonth },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_BITSTRING, BER_FLAGS_NOOWNTAG, dissect_bitMonth },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_months(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_months_choice, hf_index, ett_x509sat_T_months,
                                 NULL);

  return offset;
}
static int dissect_months(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_months(FALSE, tvb, offset, pinfo, tree, hf_x509sat_months);
}


static const ber_sequence_t T_years_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_NOOWNTAG, dissect_years_item },
};

static int
dissect_x509sat_T_years(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 T_years_set_of, hf_index, ett_x509sat_T_years);

  return offset;
}
static int dissect_years(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_years(FALSE, tvb, offset, pinfo, tree, hf_x509sat_years);
}


static const ber_sequence_t Period_sequence[] = {
  { BER_CLASS_CON, 0, BER_FLAGS_OPTIONAL, dissect_timesOfDay },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_days },
  { BER_CLASS_CON, 2, BER_FLAGS_OPTIONAL, dissect_weeks },
  { BER_CLASS_CON, 3, BER_FLAGS_OPTIONAL, dissect_months },
  { BER_CLASS_CON, 4, BER_FLAGS_OPTIONAL, dissect_years },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_Period(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   Period_sequence, hf_index, ett_x509sat_Period);

  return offset;
}
static int dissect_periodic_item(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_Period(FALSE, tvb, offset, pinfo, tree, hf_x509sat_periodic_item);
}


static const ber_sequence_t SET_OF_Period_set_of[1] = {
  { BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_periodic_item },
};

static int
dissect_x509sat_SET_OF_Period(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_set_of(implicit_tag, pinfo, tree, tvb, offset,
                                 SET_OF_Period_set_of, hf_index, ett_x509sat_SET_OF_Period);

  return offset;
}
static int dissect_periodic(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_SET_OF_Period(FALSE, tvb, offset, pinfo, tree, hf_x509sat_periodic);
}


static const value_string x509sat_T_time_vals[] = {
  {   0, "absolute" },
  {   1, "periodic" },
  { 0, NULL }
};

static const ber_choice_t T_time_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_absolute },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_SET, BER_FLAGS_NOOWNTAG, dissect_periodic },
  { 0, 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_time(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 T_time_choice, hf_index, ett_x509sat_T_time,
                                 NULL);

  return offset;
}
static int dissect_time(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_time(FALSE, tvb, offset, pinfo, tree, hf_x509sat_time);
}



static int
dissect_x509sat_BOOLEAN(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_boolean(implicit_tag, pinfo, tree, tvb, offset, hf_index);

  return offset;
}
static int dissect_notThisTime(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509sat_notThisTime);
}
static int dissect_entirely(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_BOOLEAN(FALSE, tvb, offset, pinfo, tree, hf_x509sat_entirely);
}



int
dissect_x509sat_TimeZone(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_integer(implicit_tag, pinfo, tree, tvb, offset, hf_index,
                                  NULL);

  return offset;
}
static int dissect_timeZone(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_TimeZone(FALSE, tvb, offset, pinfo, tree, hf_x509sat_timeZone);
}


static const ber_sequence_t TimeSpecification_sequence[] = {
  { BER_CLASS_ANY/*choice*/, -1/*choice*/, BER_FLAGS_NOOWNTAG|BER_FLAGS_NOTCHKTAG, dissect_time },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_notThisTime },
  { BER_CLASS_UNI, BER_UNI_TAG_INTEGER, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_timeZone },
  { 0, 0, 0, NULL }
};

int
dissect_x509sat_TimeSpecification(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   TimeSpecification_sequence, hf_index, ett_x509sat_TimeSpecification);

  return offset;
}


static const ber_sequence_t T_between_sequence[] = {
  { BER_CLASS_CON, 0, 0, dissect_startTime },
  { BER_CLASS_CON, 1, BER_FLAGS_OPTIONAL, dissect_endTime },
  { BER_CLASS_UNI, BER_UNI_TAG_BOOLEAN, BER_FLAGS_OPTIONAL|BER_FLAGS_NOOWNTAG, dissect_entirely },
  { 0, 0, 0, NULL }
};

static int
dissect_x509sat_T_between(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_sequence(implicit_tag, pinfo, tree, tvb, offset,
                                   T_between_sequence, hf_index, ett_x509sat_T_between);

  return offset;
}
static int dissect_between(packet_info *pinfo, proto_tree *tree, tvbuff_t *tvb, int offset) {
  return dissect_x509sat_T_between(FALSE, tvb, offset, pinfo, tree, hf_x509sat_between);
}


const value_string x509sat_TimeAssertion_vals[] = {
  {   0, "now" },
  {   1, "at" },
  {   2, "between" },
  { 0, NULL }
};

static const ber_choice_t TimeAssertion_choice[] = {
  {   0, BER_CLASS_UNI, BER_UNI_TAG_NULL, BER_FLAGS_NOOWNTAG, dissect_now },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_GeneralizedTime, BER_FLAGS_NOOWNTAG, dissect_at },
  {   2, BER_CLASS_UNI, BER_UNI_TAG_SEQUENCE, BER_FLAGS_NOOWNTAG, dissect_between },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509sat_TimeAssertion(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
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
  {   0, BER_CLASS_UNI, BER_UNI_TAG_OID, BER_FLAGS_NOOWNTAG, dissect_localeID1 },
  {   1, BER_CLASS_UNI, BER_UNI_TAG_PrintableString, BER_FLAGS_NOOWNTAG, dissect_localeID2 },
  { 0, 0, 0, 0, NULL }
};

int
dissect_x509sat_LocaleContextSyntax(gboolean implicit_tag _U_, tvbuff_t *tvb, int offset, packet_info *pinfo _U_, proto_tree *tree, int hf_index _U_) {
  offset = dissect_ber_choice(pinfo, tree, tvb, offset,
                                 LocaleContextSyntax_choice, hf_index, ett_x509sat_LocaleContextSyntax,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static void dissect_DirectoryString_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_DirectoryString(FALSE, tvb, 0, pinfo, tree, hf_x509sat_DirectoryString_PDU);
}
static void dissect_UniqueIdentifier_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_UniqueIdentifier(FALSE, tvb, 0, pinfo, tree, hf_x509sat_UniqueIdentifier_PDU);
}
static void dissect_CountryName_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_CountryName(FALSE, tvb, 0, pinfo, tree, hf_x509sat_CountryName_PDU);
}
static void dissect_Guide_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_Guide(FALSE, tvb, 0, pinfo, tree, hf_x509sat_Guide_PDU);
}
static void dissect_Criteria_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_Criteria(FALSE, tvb, 0, pinfo, tree, hf_x509sat_Criteria_PDU);
}
static void dissect_EnhancedGuide_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_EnhancedGuide(FALSE, tvb, 0, pinfo, tree, hf_x509sat_EnhancedGuide_PDU);
}
static void dissect_PostalAddress_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_PostalAddress(FALSE, tvb, 0, pinfo, tree, hf_x509sat_PostalAddress_PDU);
}
static void dissect_TelephoneNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_TelephoneNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_TelephoneNumber_PDU);
}
static void dissect_TelexNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_TelexNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_TelexNumber_PDU);
}
static void dissect_FacsimileTelephoneNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_FacsimileTelephoneNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_FacsimileTelephoneNumber_PDU);
}
static void dissect_X121Address_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_X121Address(FALSE, tvb, 0, pinfo, tree, hf_x509sat_X121Address_PDU);
}
static void dissect_InternationalISDNNumber_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_InternationalISDNNumber(FALSE, tvb, 0, pinfo, tree, hf_x509sat_InternationalISDNNumber_PDU);
}
static void dissect_DestinationIndicator_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_DestinationIndicator(FALSE, tvb, 0, pinfo, tree, hf_x509sat_DestinationIndicator_PDU);
}
static void dissect_PreferredDeliveryMethod_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_PreferredDeliveryMethod(FALSE, tvb, 0, pinfo, tree, hf_x509sat_PreferredDeliveryMethod_PDU);
}
static void dissect_PresentationAddress_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_PresentationAddress(FALSE, tvb, 0, pinfo, tree, hf_x509sat_PresentationAddress_PDU);
}
static void dissect_NameAndOptionalUID_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_NameAndOptionalUID(FALSE, tvb, 0, pinfo, tree, hf_x509sat_NameAndOptionalUID_PDU);
}
static void dissect_CaseIgnoreListMatch_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_CaseIgnoreListMatch(FALSE, tvb, 0, pinfo, tree, hf_x509sat_CaseIgnoreListMatch_PDU);
}
static void dissect_DayTimeBand_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_DayTimeBand(FALSE, tvb, 0, pinfo, tree, hf_x509sat_DayTimeBand_PDU);
}
static void dissect_DayTime_PDU(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree) {
  dissect_x509sat_DayTime(FALSE, tvb, 0, pinfo, tree, hf_x509sat_DayTime_PDU);
}


/*--- End of included file: packet-x509sat-fn.c ---*/



/*--- proto_register_x509sat ----------------------------------------------*/
void proto_register_x509sat(void) {

  /* List of fields */
  static hf_register_info hf[] = {

/*--- Included file: packet-x509sat-hfarr.c ---*/

    { &hf_x509sat_DirectoryString_PDU,
      { "DirectoryString", "x509sat.DirectoryString",
        FT_STRING, BASE_NONE, NULL, 0,
        "DirectoryString", HFILL }},
    { &hf_x509sat_UniqueIdentifier_PDU,
      { "UniqueIdentifier", "x509sat.UniqueIdentifier",
        FT_BYTES, BASE_HEX, NULL, 0,
        "UniqueIdentifier", HFILL }},
    { &hf_x509sat_CountryName_PDU,
      { "CountryName", "x509sat.CountryName",
        FT_STRING, BASE_NONE, NULL, 0,
        "CountryName", HFILL }},
    { &hf_x509sat_Guide_PDU,
      { "Guide", "x509sat.Guide",
        FT_NONE, BASE_NONE, NULL, 0,
        "Guide", HFILL }},
    { &hf_x509sat_Criteria_PDU,
      { "Criteria", "x509sat.Criteria",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        "Criteria", HFILL }},
    { &hf_x509sat_EnhancedGuide_PDU,
      { "EnhancedGuide", "x509sat.EnhancedGuide",
        FT_NONE, BASE_NONE, NULL, 0,
        "EnhancedGuide", HFILL }},
    { &hf_x509sat_PostalAddress_PDU,
      { "PostalAddress", "x509sat.PostalAddress",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PostalAddress", HFILL }},
    { &hf_x509sat_TelephoneNumber_PDU,
      { "TelephoneNumber", "x509sat.TelephoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "TelephoneNumber", HFILL }},
    { &hf_x509sat_TelexNumber_PDU,
      { "TelexNumber", "x509sat.TelexNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "TelexNumber", HFILL }},
    { &hf_x509sat_FacsimileTelephoneNumber_PDU,
      { "FacsimileTelephoneNumber", "x509sat.FacsimileTelephoneNumber",
        FT_NONE, BASE_NONE, NULL, 0,
        "FacsimileTelephoneNumber", HFILL }},
    { &hf_x509sat_X121Address_PDU,
      { "X121Address", "x509sat.X121Address",
        FT_STRING, BASE_NONE, NULL, 0,
        "X121Address", HFILL }},
    { &hf_x509sat_InternationalISDNNumber_PDU,
      { "InternationalISDNNumber", "x509sat.InternationalISDNNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "InternationalISDNNumber", HFILL }},
    { &hf_x509sat_DestinationIndicator_PDU,
      { "DestinationIndicator", "x509sat.DestinationIndicator",
        FT_STRING, BASE_NONE, NULL, 0,
        "DestinationIndicator", HFILL }},
    { &hf_x509sat_PreferredDeliveryMethod_PDU,
      { "PreferredDeliveryMethod", "x509sat.PreferredDeliveryMethod",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PreferredDeliveryMethod", HFILL }},
    { &hf_x509sat_PresentationAddress_PDU,
      { "PresentationAddress", "x509sat.PresentationAddress",
        FT_NONE, BASE_NONE, NULL, 0,
        "PresentationAddress", HFILL }},
    { &hf_x509sat_NameAndOptionalUID_PDU,
      { "NameAndOptionalUID", "x509sat.NameAndOptionalUID",
        FT_NONE, BASE_NONE, NULL, 0,
        "NameAndOptionalUID", HFILL }},
    { &hf_x509sat_CaseIgnoreListMatch_PDU,
      { "CaseIgnoreListMatch", "x509sat.CaseIgnoreListMatch",
        FT_UINT32, BASE_DEC, NULL, 0,
        "CaseIgnoreListMatch", HFILL }},
    { &hf_x509sat_DayTimeBand_PDU,
      { "DayTimeBand", "x509sat.DayTimeBand",
        FT_NONE, BASE_NONE, NULL, 0,
        "DayTimeBand", HFILL }},
    { &hf_x509sat_DayTime_PDU,
      { "DayTime", "x509sat.DayTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "DayTime", HFILL }},
    { &hf_x509sat_objectClass,
      { "objectClass", "x509sat.objectClass",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509sat_criteria,
      { "criteria", "x509sat.criteria",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        "", HFILL }},
    { &hf_x509sat_type,
      { "type", "x509sat.type",
        FT_UINT32, BASE_DEC, VALS(x509sat_CriteriaItem_vals), 0,
        "Criteria/type", HFILL }},
    { &hf_x509sat_and,
      { "and", "x509sat.and",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Criteria/and", HFILL }},
    { &hf_x509sat_and_item,
      { "Item", "x509sat.and_item",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        "Criteria/and/_item", HFILL }},
    { &hf_x509sat_or,
      { "or", "x509sat.or",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Criteria/or", HFILL }},
    { &hf_x509sat_or_item,
      { "Item", "x509sat.or_item",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        "Criteria/or/_item", HFILL }},
    { &hf_x509sat_not,
      { "not", "x509sat.not",
        FT_UINT32, BASE_DEC, VALS(x509sat_Criteria_vals), 0,
        "Criteria/not", HFILL }},
    { &hf_x509sat_equality,
      { "equality", "x509sat.equality",
        FT_STRING, BASE_NONE, NULL, 0,
        "CriteriaItem/equality", HFILL }},
    { &hf_x509sat_substrings,
      { "substrings", "x509sat.substrings",
        FT_STRING, BASE_NONE, NULL, 0,
        "CriteriaItem/substrings", HFILL }},
    { &hf_x509sat_greaterOrEqual,
      { "greaterOrEqual", "x509sat.greaterOrEqual",
        FT_STRING, BASE_NONE, NULL, 0,
        "CriteriaItem/greaterOrEqual", HFILL }},
    { &hf_x509sat_lessOrEqual,
      { "lessOrEqual", "x509sat.lessOrEqual",
        FT_STRING, BASE_NONE, NULL, 0,
        "CriteriaItem/lessOrEqual", HFILL }},
    { &hf_x509sat_approximateMatch,
      { "approximateMatch", "x509sat.approximateMatch",
        FT_STRING, BASE_NONE, NULL, 0,
        "CriteriaItem/approximateMatch", HFILL }},
    { &hf_x509sat_subset,
      { "subset", "x509sat.subset",
        FT_INT32, BASE_DEC, VALS(x509sat_T_subset_vals), 0,
        "EnhancedGuide/subset", HFILL }},
    { &hf_x509sat_PostalAddress_item,
      { "Item", "x509sat.PostalAddress_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "PostalAddress/_item", HFILL }},
    { &hf_x509sat_telexNumber,
      { "telexNumber", "x509sat.telexNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "TelexNumber/telexNumber", HFILL }},
    { &hf_x509sat_countryCode,
      { "countryCode", "x509sat.countryCode",
        FT_STRING, BASE_NONE, NULL, 0,
        "TelexNumber/countryCode", HFILL }},
    { &hf_x509sat_answerback,
      { "answerback", "x509sat.answerback",
        FT_STRING, BASE_NONE, NULL, 0,
        "TelexNumber/answerback", HFILL }},
    { &hf_x509sat_telephoneNumber,
      { "telephoneNumber", "x509sat.telephoneNumber",
        FT_STRING, BASE_NONE, NULL, 0,
        "FacsimileTelephoneNumber/telephoneNumber", HFILL }},
    { &hf_x509sat_PreferredDeliveryMethod_item,
      { "Item", "x509sat.PreferredDeliveryMethod_item",
        FT_INT32, BASE_DEC, VALS(x509sat_PreferredDeliveryMethod_item_vals), 0,
        "PreferredDeliveryMethod/_item", HFILL }},
    { &hf_x509sat_pSelector,
      { "pSelector", "x509sat.pSelector",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PresentationAddress/pSelector", HFILL }},
    { &hf_x509sat_sSelector,
      { "sSelector", "x509sat.sSelector",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PresentationAddress/sSelector", HFILL }},
    { &hf_x509sat_tSelector,
      { "tSelector", "x509sat.tSelector",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PresentationAddress/tSelector", HFILL }},
    { &hf_x509sat_nAddresses,
      { "nAddresses", "x509sat.nAddresses",
        FT_UINT32, BASE_DEC, NULL, 0,
        "PresentationAddress/nAddresses", HFILL }},
    { &hf_x509sat_nAddresses_item,
      { "Item", "x509sat.nAddresses_item",
        FT_BYTES, BASE_HEX, NULL, 0,
        "PresentationAddress/nAddresses/_item", HFILL }},
    { &hf_x509sat_nAddress,
      { "nAddress", "x509sat.nAddress",
        FT_BYTES, BASE_HEX, NULL, 0,
        "ProtocolInformation/nAddress", HFILL }},
    { &hf_x509sat_profiles,
      { "profiles", "x509sat.profiles",
        FT_UINT32, BASE_DEC, NULL, 0,
        "ProtocolInformation/profiles", HFILL }},
    { &hf_x509sat_profiles_item,
      { "Item", "x509sat.profiles_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "ProtocolInformation/profiles/_item", HFILL }},
    { &hf_x509sat_dn,
      { "dn", "x509sat.dn",
        FT_UINT32, BASE_DEC, NULL, 0,
        "NameAndOptionalUID/dn", HFILL }},
    { &hf_x509sat_uid,
      { "uid", "x509sat.uid",
        FT_BYTES, BASE_HEX, NULL, 0,
        "NameAndOptionalUID/uid", HFILL }},
    { &hf_x509sat_matchingRuleUsed,
      { "matchingRuleUsed", "x509sat.matchingRuleUsed",
        FT_STRING, BASE_NONE, NULL, 0,
        "MultipleMatchingLocalities/matchingRuleUsed", HFILL }},
    { &hf_x509sat_attributeList,
      { "attributeList", "x509sat.attributeList",
        FT_UINT32, BASE_DEC, NULL, 0,
        "MultipleMatchingLocalities/attributeList", HFILL }},
    { &hf_x509sat_attributeList_item,
      { "Item", "x509sat.attributeList_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "MultipleMatchingLocalities/attributeList/_item", HFILL }},
    { &hf_x509sat_SubstringAssertion_item,
      { "Item", "x509sat.SubstringAssertion_item",
        FT_UINT32, BASE_DEC, VALS(x509sat_SubstringAssertion_item_vals), 0,
        "SubstringAssertion/_item", HFILL }},
    { &hf_x509sat_initial,
      { "initial", "x509sat.initial",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubstringAssertion/_item/initial", HFILL }},
    { &hf_x509sat_any,
      { "any", "x509sat.any",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubstringAssertion/_item/any", HFILL }},
    { &hf_x509sat_final,
      { "final", "x509sat.final",
        FT_STRING, BASE_NONE, NULL, 0,
        "SubstringAssertion/_item/final", HFILL }},
    { &hf_x509sat_control,
      { "control", "x509sat.control",
        FT_NONE, BASE_NONE, NULL, 0,
        "SubstringAssertion/_item/control", HFILL }},
    { &hf_x509sat_CaseIgnoreListMatch_item,
      { "Item", "x509sat.CaseIgnoreListMatch_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "CaseIgnoreListMatch/_item", HFILL }},
    { &hf_x509sat_OctetSubstringAssertion_item,
      { "Item", "x509sat.OctetSubstringAssertion_item",
        FT_UINT32, BASE_DEC, VALS(x509sat_OctetSubstringAssertion_item_vals), 0,
        "OctetSubstringAssertion/_item", HFILL }},
    { &hf_x509sat_initial_substring,
      { "initial", "x509sat.initial",
        FT_BYTES, BASE_HEX, NULL, 0,
        "OctetSubstringAssertion/_item/initial", HFILL }},
    { &hf_x509sat_any_substring,
      { "any", "x509sat.any",
        FT_BYTES, BASE_HEX, NULL, 0,
        "OctetSubstringAssertion/_item/any", HFILL }},
    { &hf_x509sat_finall_substring,
      { "final", "x509sat.final",
        FT_BYTES, BASE_HEX, NULL, 0,
        "OctetSubstringAssertion/_item/final", HFILL }},
    { &hf_x509sat_ZonalSelect_item,
      { "Item", "x509sat.ZonalSelect_item",
        FT_STRING, BASE_NONE, NULL, 0,
        "ZonalSelect/_item", HFILL }},
    { &hf_x509sat_time,
      { "time", "x509sat.time",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_time_vals), 0,
        "TimeSpecification/time", HFILL }},
    { &hf_x509sat_absolute,
      { "absolute", "x509sat.absolute",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeSpecification/time/absolute", HFILL }},
    { &hf_x509sat_startTime,
      { "startTime", "x509sat.startTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509sat_endTime,
      { "endTime", "x509sat.endTime",
        FT_STRING, BASE_NONE, NULL, 0,
        "", HFILL }},
    { &hf_x509sat_periodic,
      { "periodic", "x509sat.periodic",
        FT_UINT32, BASE_DEC, NULL, 0,
        "TimeSpecification/time/periodic", HFILL }},
    { &hf_x509sat_periodic_item,
      { "Item", "x509sat.periodic_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeSpecification/time/periodic/_item", HFILL }},
    { &hf_x509sat_notThisTime,
      { "notThisTime", "x509sat.notThisTime",
        FT_BOOLEAN, 8, NULL, 0,
        "TimeSpecification/notThisTime", HFILL }},
    { &hf_x509sat_timeZone,
      { "timeZone", "x509sat.timeZone",
        FT_INT32, BASE_DEC, NULL, 0,
        "TimeSpecification/timeZone", HFILL }},
    { &hf_x509sat_timesOfDay,
      { "timesOfDay", "x509sat.timesOfDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Period/timesOfDay", HFILL }},
    { &hf_x509sat_timesOfDay_item,
      { "Item", "x509sat.timesOfDay_item",
        FT_NONE, BASE_NONE, NULL, 0,
        "Period/timesOfDay/_item", HFILL }},
    { &hf_x509sat_days,
      { "days", "x509sat.days",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_days_vals), 0,
        "Period/days", HFILL }},
    { &hf_x509sat_intDay,
      { "intDay", "x509sat.intDay",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Period/days/intDay", HFILL }},
    { &hf_x509sat_intDay_item,
      { "Item", "x509sat.intDay_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "Period/days/intDay/_item", HFILL }},
    { &hf_x509sat_bitDay,
      { "bitDay", "x509sat.bitDay",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Period/days/bitDay", HFILL }},
    { &hf_x509sat_dayOf,
      { "dayOf", "x509sat.dayOf",
        FT_UINT32, BASE_DEC, VALS(x509sat_XDayOf_vals), 0,
        "Period/days/dayOf", HFILL }},
    { &hf_x509sat_weeks,
      { "weeks", "x509sat.weeks",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_weeks_vals), 0,
        "Period/weeks", HFILL }},
    { &hf_x509sat_allWeeks,
      { "allWeeks", "x509sat.allWeeks",
        FT_NONE, BASE_NONE, NULL, 0,
        "Period/weeks/allWeeks", HFILL }},
    { &hf_x509sat_intWeek,
      { "intWeek", "x509sat.intWeek",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Period/weeks/intWeek", HFILL }},
    { &hf_x509sat_intWeek_item,
      { "Item", "x509sat.intWeek_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "Period/weeks/intWeek/_item", HFILL }},
    { &hf_x509sat_bitWeek,
      { "bitWeek", "x509sat.bitWeek",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Period/weeks/bitWeek", HFILL }},
    { &hf_x509sat_months,
      { "months", "x509sat.months",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_months_vals), 0,
        "Period/months", HFILL }},
    { &hf_x509sat_allMonths,
      { "allMonths", "x509sat.allMonths",
        FT_NONE, BASE_NONE, NULL, 0,
        "Period/months/allMonths", HFILL }},
    { &hf_x509sat_intMonth,
      { "intMonth", "x509sat.intMonth",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Period/months/intMonth", HFILL }},
    { &hf_x509sat_intMonth_item,
      { "Item", "x509sat.intMonth_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "Period/months/intMonth/_item", HFILL }},
    { &hf_x509sat_bitMonth,
      { "bitMonth", "x509sat.bitMonth",
        FT_BYTES, BASE_HEX, NULL, 0,
        "Period/months/bitMonth", HFILL }},
    { &hf_x509sat_years,
      { "years", "x509sat.years",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Period/years", HFILL }},
    { &hf_x509sat_years_item,
      { "Item", "x509sat.years_item",
        FT_INT32, BASE_DEC, NULL, 0,
        "Period/years/_item", HFILL }},
    { &hf_x509sat_first_dayof,
      { "first", "x509sat.first",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "XDayOf/first", HFILL }},
    { &hf_x509sat_second_dayof,
      { "second", "x509sat.second",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "XDayOf/second", HFILL }},
    { &hf_x509sat_third_dayof,
      { "third", "x509sat.third",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "XDayOf/third", HFILL }},
    { &hf_x509sat_fourth_dayof,
      { "fourth", "x509sat.fourth",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "XDayOf/fourth", HFILL }},
    { &hf_x509sat_fifth_dayof,
      { "fifth", "x509sat.fifth",
        FT_UINT32, BASE_DEC, VALS(x509sat_NamedDay_vals), 0,
        "XDayOf/fifth", HFILL }},
    { &hf_x509sat_intNamedDays,
      { "intNamedDays", "x509sat.intNamedDays",
        FT_UINT32, BASE_DEC, VALS(x509sat_T_intNamedDays_vals), 0,
        "NamedDay/intNamedDays", HFILL }},
    { &hf_x509sat_bitNamedDays,
      { "bitNamedDays", "x509sat.bitNamedDays",
        FT_BYTES, BASE_HEX, NULL, 0,
        "NamedDay/bitNamedDays", HFILL }},
    { &hf_x509sat_startDayTime,
      { "startDayTime", "x509sat.startDayTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "DayTimeBand/startDayTime", HFILL }},
    { &hf_x509sat_endDayTime,
      { "endDayTime", "x509sat.endDayTime",
        FT_NONE, BASE_NONE, NULL, 0,
        "DayTimeBand/endDayTime", HFILL }},
    { &hf_x509sat_hour,
      { "hour", "x509sat.hour",
        FT_INT32, BASE_DEC, NULL, 0,
        "DayTime/hour", HFILL }},
    { &hf_x509sat_minute,
      { "minute", "x509sat.minute",
        FT_INT32, BASE_DEC, NULL, 0,
        "DayTime/minute", HFILL }},
    { &hf_x509sat_second,
      { "second", "x509sat.second",
        FT_INT32, BASE_DEC, NULL, 0,
        "DayTime/second", HFILL }},
    { &hf_x509sat_now,
      { "now", "x509sat.now",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeAssertion/now", HFILL }},
    { &hf_x509sat_at,
      { "at", "x509sat.at",
        FT_STRING, BASE_NONE, NULL, 0,
        "TimeAssertion/at", HFILL }},
    { &hf_x509sat_between,
      { "between", "x509sat.between",
        FT_NONE, BASE_NONE, NULL, 0,
        "TimeAssertion/between", HFILL }},
    { &hf_x509sat_entirely,
      { "entirely", "x509sat.entirely",
        FT_BOOLEAN, 8, NULL, 0,
        "TimeAssertion/between/entirely", HFILL }},
    { &hf_x509sat_localeID1,
      { "localeID1", "x509sat.localeID1",
        FT_STRING, BASE_NONE, NULL, 0,
        "LocaleContextSyntax/localeID1", HFILL }},
    { &hf_x509sat_localeID2,
      { "localeID2", "x509sat.localeID2",
        FT_STRING, BASE_NONE, NULL, 0,
        "LocaleContextSyntax/localeID2", HFILL }},
    { &hf_x509sat_T_bitDay_sunday,
      { "sunday", "x509sat.sunday",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509sat_T_bitDay_monday,
      { "monday", "x509sat.monday",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509sat_T_bitDay_tuesday,
      { "tuesday", "x509sat.tuesday",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509sat_T_bitDay_wednesday,
      { "wednesday", "x509sat.wednesday",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509sat_T_bitDay_thursday,
      { "thursday", "x509sat.thursday",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x509sat_T_bitDay_friday,
      { "friday", "x509sat.friday",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x509sat_T_bitDay_saturday,
      { "saturday", "x509sat.saturday",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x509sat_T_bitWeek_week1,
      { "week1", "x509sat.week1",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509sat_T_bitWeek_week2,
      { "week2", "x509sat.week2",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509sat_T_bitWeek_week3,
      { "week3", "x509sat.week3",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509sat_T_bitWeek_week4,
      { "week4", "x509sat.week4",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509sat_T_bitWeek_week5,
      { "week5", "x509sat.week5",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_january,
      { "january", "x509sat.january",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_february,
      { "february", "x509sat.february",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_march,
      { "march", "x509sat.march",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_april,
      { "april", "x509sat.april",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_may,
      { "may", "x509sat.may",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_june,
      { "june", "x509sat.june",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_july,
      { "july", "x509sat.july",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_august,
      { "august", "x509sat.august",
        FT_BOOLEAN, 8, NULL, 0x01,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_september,
      { "september", "x509sat.september",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_october,
      { "october", "x509sat.october",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_november,
      { "november", "x509sat.november",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509sat_T_bitMonth_december,
      { "december", "x509sat.december",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509sat_T_bitNamedDays_sunday,
      { "sunday", "x509sat.sunday",
        FT_BOOLEAN, 8, NULL, 0x80,
        "", HFILL }},
    { &hf_x509sat_T_bitNamedDays_monday,
      { "monday", "x509sat.monday",
        FT_BOOLEAN, 8, NULL, 0x40,
        "", HFILL }},
    { &hf_x509sat_T_bitNamedDays_tuesday,
      { "tuesday", "x509sat.tuesday",
        FT_BOOLEAN, 8, NULL, 0x20,
        "", HFILL }},
    { &hf_x509sat_T_bitNamedDays_wednesday,
      { "wednesday", "x509sat.wednesday",
        FT_BOOLEAN, 8, NULL, 0x10,
        "", HFILL }},
    { &hf_x509sat_T_bitNamedDays_thursday,
      { "thursday", "x509sat.thursday",
        FT_BOOLEAN, 8, NULL, 0x08,
        "", HFILL }},
    { &hf_x509sat_T_bitNamedDays_friday,
      { "friday", "x509sat.friday",
        FT_BOOLEAN, 8, NULL, 0x04,
        "", HFILL }},
    { &hf_x509sat_T_bitNamedDays_saturday,
      { "saturday", "x509sat.saturday",
        FT_BOOLEAN, 8, NULL, 0x02,
        "", HFILL }},

/*--- End of included file: packet-x509sat-hfarr.c ---*/

  };

  /* List of subtrees */
  static gint *ett[] = {

/*--- Included file: packet-x509sat-ettarr.c ---*/

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

  };

  /* Register protocol */
  proto_x509sat = proto_register_protocol(PNAME, PSNAME, PFNAME);

  /* Register fields and subtrees */
  proto_register_field_array(proto_x509sat, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));

}


/*--- proto_reg_handoff_x509sat -------------------------------------------*/
void proto_reg_handoff_x509sat(void) {

/*--- Included file: packet-x509sat-dis-tab.c ---*/

  register_ber_oid_dissector("2.5.4.6", dissect_CountryName_PDU, proto_x509sat, "id-at-countryName");
  register_ber_oid_dissector("2.5.4.2", dissect_DirectoryString_PDU, proto_x509sat, "id-at-knowledgeInformation");
  register_ber_oid_dissector("2.5.4.10", dissect_DirectoryString_PDU, proto_x509sat, "id-at-organizationName");
  register_ber_oid_dissector("2.5.4.7.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveLocalityName");
  register_ber_oid_dissector("2.5.4.3", dissect_DirectoryString_PDU, proto_x509sat, "id-at-commonName");
  register_ber_oid_dissector("2.5.4.4", dissect_DirectoryString_PDU, proto_x509sat, "id-at-surname");
  register_ber_oid_dissector("2.5.4.42", dissect_DirectoryString_PDU, proto_x509sat, "id-at-givenName");
  register_ber_oid_dissector("2.5.4.43", dissect_DirectoryString_PDU, proto_x509sat, "id-at-initials");
  register_ber_oid_dissector("2.5.4.44", dissect_DirectoryString_PDU, proto_x509sat, "id-at-generationQualifier");
  register_ber_oid_dissector("2.5.4.51", dissect_DirectoryString_PDU, proto_x509sat, "id-at-houseIdentifier");
  register_ber_oid_dissector("2.5.4.54", dissect_DirectoryString_PDU, proto_x509sat, "id-at-dmdName");
  register_ber_oid_dissector("2.5.4.65", dissect_DirectoryString_PDU, proto_x509sat, "id-at-pseudonym");
  register_ber_oid_dissector("2.5.4.41", dissect_DirectoryString_PDU, proto_x509sat, "id-at-name");
  register_ber_oid_dissector("2.5.4.8.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveStateOrProvinceName");
  register_ber_oid_dissector("2.5.4.8", dissect_DirectoryString_PDU, proto_x509sat, "id-at-stateOrProvinceName");
  register_ber_oid_dissector("2.5.4.9", dissect_DirectoryString_PDU, proto_x509sat, "id-at-streetAddress");
  register_ber_oid_dissector("2.5.4.9.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveStreetAddress");
  register_ber_oid_dissector("2.5.4.10.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveOrganizationName");
  register_ber_oid_dissector("2.5.4.7", dissect_DirectoryString_PDU, proto_x509sat, "id-at-localityName");
  register_ber_oid_dissector("2.5.4.11", dissect_DirectoryString_PDU, proto_x509sat, "id-at-organizationalUnitName");
  register_ber_oid_dissector("2.5.4.11.1", dissect_DirectoryString_PDU, proto_x509sat, "id-at-collectiveOrganizationalUnitName");
  register_ber_oid_dissector("2.5.4.12", dissect_DirectoryString_PDU, proto_x509sat, "id-at-title");
  register_ber_oid_dissector("2.5.4.13", dissect_DirectoryString_PDU, proto_x509sat, "id-at-description");
  register_ber_oid_dissector("2.5.4.15", dissect_DirectoryString_PDU, proto_x509sat, "id-at-businessCategory");
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


/*--- End of included file: packet-x509sat-dis-tab.c ---*/

}



