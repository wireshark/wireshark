/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-atn-cm.c                                                            */
/* asn2wrs.py -u -L -p atn-cm -c ./atn-cm.cnf -s ./packet-atn-cm-template -D . -O ../.. atn-cm.asn */

/* Input file: packet-atn-cm-template.c */

#line 1 "./asn1/atn-cm/packet-atn-cm-template.c"
/* packet-atn-cm.c
 * By Mathias Guettler <guettler@web.de>
 * Copyright 2013
 *
 * Routines for ATN context management protocol packet disassembly.
 * ATN context management allows an aircraft
 * to log on to a ground facility.

 * details see:
 * http://en.wikipedia.org/wiki/CPDLC
 * http://members.optusnet.com.au/~cjr/introduction.htm

 * standards:
 * http://legacy.icao.int/anb/panels/acp/repository.cfm

 * note:
 * We are dealing with ATN/CPDLC aka ICAO Doc 9705 Ed2 here
 * (CPDLC may also be transmitted via ACARS/AOA aka "FANS-1/A ").


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

#include <epan/packet.h>
#include <epan/exceptions.h>
#include <epan/conversation.h>
#include "packet-ber.h"
#include "packet-per.h"
#include "packet-atn-ulcs.h"

#define ATN_CM_PROTO "ICAO Doc9705 CM"

void proto_register_atn_cm(void);
void proto_reg_handoff_atn_cm(void);


/*--- Included file: packet-atn-cm-hf.c ---*/
#line 1 "./asn1/atn-cm/packet-atn-cm-hf.c"
static int hf_atn_cm_CMAircraftMessage_PDU = -1;  /* CMAircraftMessage */
static int hf_atn_cm_CMGroundMessage_PDU = -1;    /* CMGroundMessage */
static int hf_atn_cm_cmLogonRequest = -1;         /* CMLogonRequest */
static int hf_atn_cm_cmContactResponse = -1;      /* CMContactResponse */
static int hf_atn_cm_cmAbortReason = -1;          /* CMAbortReason */
static int hf_atn_cm_cmLogonResponse = -1;        /* CMLogonResponse */
static int hf_atn_cm_cmUpdate = -1;               /* CMUpdate */
static int hf_atn_cm_cmContactRequest = -1;       /* CMContactRequest */
static int hf_atn_cm_cmForwardRequest = -1;       /* CMForwardRequest */
static int hf_atn_cm_cmForwardResponse = -1;      /* CMForwardResponse */
static int hf_atn_cm_longTsap = -1;               /* LongTsap */
static int hf_atn_cm_shortTsap = -1;              /* ShortTsap */
static int hf_atn_cm_aeQualifier = -1;            /* AEQualifier */
static int hf_atn_cm_apVersion = -1;              /* VersionNumber */
static int hf_atn_cm_apAddress = -1;              /* APAddress */
static int hf_atn_cm_facilityDesignation = -1;    /* FacilityDesignation */
static int hf_atn_cm_address = -1;                /* LongTsap */
static int hf_atn_cm_aircraftFlightIdentification = -1;  /* AircraftFlightIdentification */
static int hf_atn_cm_cMLongTSAP = -1;             /* LongTsap */
static int hf_atn_cm_groundInitiatedApplications = -1;  /* SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress */
static int hf_atn_cm_groundInitiatedApplications_item = -1;  /* AEQualifierVersionAddress */
static int hf_atn_cm_airOnlyInitiatedApplications = -1;  /* SEQUENCE_SIZE_1_256_OF_AEQualifierVersion */
static int hf_atn_cm_airOnlyInitiatedApplications_item = -1;  /* AEQualifierVersion */
static int hf_atn_cm_airportDeparture = -1;       /* Airport */
static int hf_atn_cm_airportDestination = -1;     /* Airport */
static int hf_atn_cm_dateTimeDepartureETD = -1;   /* DateTime */
static int hf_atn_cm_airInitiatedApplications = -1;  /* SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress */
static int hf_atn_cm_airInitiatedApplications_item = -1;  /* AEQualifierVersionAddress */
static int hf_atn_cm_groundOnlyInitiatedApplications = -1;  /* SEQUENCE_SIZE_1_256_OF_AEQualifierVersion */
static int hf_atn_cm_groundOnlyInitiatedApplications_item = -1;  /* AEQualifierVersion */
static int hf_atn_cm_year = -1;                   /* Year */
static int hf_atn_cm_month = -1;                  /* Month */
static int hf_atn_cm_day = -1;                    /* Day */
static int hf_atn_cm_date = -1;                   /* Date */
static int hf_atn_cm_time = -1;                   /* Time */
static int hf_atn_cm_rDP = -1;                    /* OCTET_STRING_SIZE_5 */
static int hf_atn_cm_aRS = -1;                    /* OCTET_STRING_SIZE_3 */
static int hf_atn_cm_locSysNselTsel = -1;         /* OCTET_STRING_SIZE_10_11 */
static int hf_atn_cm_hours = -1;                  /* Timehours */
static int hf_atn_cm_minutes = -1;                /* Timeminutes */

/*--- End of included file: packet-atn-cm-hf.c ---*/
#line 55 "./asn1/atn-cm/packet-atn-cm-template.c"


/*--- Included file: packet-atn-cm-ett.c ---*/
#line 1 "./asn1/atn-cm/packet-atn-cm-ett.c"
static gint ett_atn_cm_CMAircraftMessage = -1;
static gint ett_atn_cm_CMGroundMessage = -1;
static gint ett_atn_cm_APAddress = -1;
static gint ett_atn_cm_AEQualifierVersion = -1;
static gint ett_atn_cm_AEQualifierVersionAddress = -1;
static gint ett_atn_cm_CMContactRequest = -1;
static gint ett_atn_cm_CMLogonRequest = -1;
static gint ett_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress = -1;
static gint ett_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersion = -1;
static gint ett_atn_cm_CMLogonResponse = -1;
static gint ett_atn_cm_Date = -1;
static gint ett_atn_cm_DateTime = -1;
static gint ett_atn_cm_LongTsap = -1;
static gint ett_atn_cm_ShortTsap = -1;
static gint ett_atn_cm_Time = -1;

/*--- End of included file: packet-atn-cm-ett.c ---*/
#line 57 "./asn1/atn-cm/packet-atn-cm-template.c"
static gint ett_atn_cm = -1;


/*--- Included file: packet-atn-cm-fn.c ---*/
#line 1 "./asn1/atn-cm/packet-atn-cm-fn.c"


static int
dissect_atn_cm_AircraftFlightIdentification(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          2, 8, FALSE);

  return offset;
}



static int
dissect_atn_cm_OCTET_STRING_SIZE_5(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       5, 5, FALSE, NULL);

  return offset;
}



static int
dissect_atn_cm_OCTET_STRING_SIZE_3(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       3, 3, FALSE, NULL);

  return offset;
}



static int
dissect_atn_cm_OCTET_STRING_SIZE_10_11(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_octet_string(tvb, offset, actx, tree, hf_index,
                                       10, 11, FALSE, NULL);

  return offset;
}


static const per_sequence_t ShortTsap_sequence[] = {
  { &hf_atn_cm_aRS          , ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_OCTET_STRING_SIZE_3 },
  { &hf_atn_cm_locSysNselTsel, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_OCTET_STRING_SIZE_10_11 },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_ShortTsap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_ShortTsap, ShortTsap_sequence);

  return offset;
}


static const per_sequence_t LongTsap_sequence[] = {
  { &hf_atn_cm_rDP          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_OCTET_STRING_SIZE_5 },
  { &hf_atn_cm_shortTsap    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_ShortTsap },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_LongTsap(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_LongTsap, LongTsap_sequence);

  return offset;
}



static int
dissect_atn_cm_AEQualifier(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 255U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cm_VersionNumber(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 255U, NULL, FALSE);

  return offset;
}


static const value_string atn_cm_APAddress_vals[] = {
  {   0, "longTsap" },
  {   1, "shortTsap" },
  { 0, NULL }
};

static const per_choice_t APAddress_choice[] = {
  {   0, &hf_atn_cm_longTsap     , ASN1_NO_EXTENSIONS     , dissect_atn_cm_LongTsap },
  {   1, &hf_atn_cm_shortTsap    , ASN1_NO_EXTENSIONS     , dissect_atn_cm_ShortTsap },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cm_APAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cm_APAddress, APAddress_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t AEQualifierVersionAddress_sequence[] = {
  { &hf_atn_cm_aeQualifier  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_AEQualifier },
  { &hf_atn_cm_apVersion    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_VersionNumber },
  { &hf_atn_cm_apAddress    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_APAddress },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_AEQualifierVersionAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_AEQualifierVersionAddress, AEQualifierVersionAddress_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress_sequence_of[1] = {
  { &hf_atn_cm_groundInitiatedApplications_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_AEQualifierVersionAddress },
};

static int
dissect_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress, SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}


static const per_sequence_t AEQualifierVersion_sequence[] = {
  { &hf_atn_cm_aeQualifier  , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_AEQualifier },
  { &hf_atn_cm_apVersion    , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_VersionNumber },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_AEQualifierVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_AEQualifierVersion, AEQualifierVersion_sequence);

  return offset;
}


static const per_sequence_t SEQUENCE_SIZE_1_256_OF_AEQualifierVersion_sequence_of[1] = {
  { &hf_atn_cm_airOnlyInitiatedApplications_item, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_AEQualifierVersion },
};

static int
dissect_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersion(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_sequence_of(tvb, offset, actx, tree, hf_index,
                                                  ett_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersion, SEQUENCE_SIZE_1_256_OF_AEQualifierVersion_sequence_of,
                                                  1, 256, FALSE);

  return offset;
}



static int
dissect_atn_cm_FacilityDesignation(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          4, 8, FALSE);

  return offset;
}



static int
dissect_atn_cm_Airport(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_IA5String(tvb, offset, actx, tree, hf_index,
                                          4, 4, FALSE);

  return offset;
}



static int
dissect_atn_cm_Year(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1996U, 2095U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cm_Month(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 12U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cm_Day(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            1U, 31U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Date_sequence[] = {
  { &hf_atn_cm_year         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_Year },
  { &hf_atn_cm_month        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_Month },
  { &hf_atn_cm_day          , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_Day },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_Date(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_Date, Date_sequence);

  return offset;
}



static int
dissect_atn_cm_Timehours(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 23U, NULL, FALSE);

  return offset;
}



static int
dissect_atn_cm_Timeminutes(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_constrained_integer(tvb, offset, actx, tree, hf_index,
                                                            0U, 59U, NULL, FALSE);

  return offset;
}


static const per_sequence_t Time_sequence[] = {
  { &hf_atn_cm_hours        , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_Timehours },
  { &hf_atn_cm_minutes      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_Timeminutes },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_Time(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_Time, Time_sequence);

  return offset;
}


static const per_sequence_t DateTime_sequence[] = {
  { &hf_atn_cm_date         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_Date },
  { &hf_atn_cm_time         , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_Time },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_DateTime(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_DateTime, DateTime_sequence);

  return offset;
}


static const per_sequence_t CMLogonRequest_sequence[] = {
  { &hf_atn_cm_aircraftFlightIdentification, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_AircraftFlightIdentification },
  { &hf_atn_cm_cMLongTSAP   , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_LongTsap },
  { &hf_atn_cm_groundInitiatedApplications, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress },
  { &hf_atn_cm_airOnlyInitiatedApplications, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersion },
  { &hf_atn_cm_facilityDesignation, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_FacilityDesignation },
  { &hf_atn_cm_airportDeparture, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_Airport },
  { &hf_atn_cm_airportDestination, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_Airport },
  { &hf_atn_cm_dateTimeDepartureETD, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_DateTime },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_CMLogonRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_CMLogonRequest, CMLogonRequest_sequence);

  return offset;
}


static const value_string atn_cm_Response_vals[] = {
  {   0, "contactSuccess" },
  {   1, "contactNotSuccessful" },
  { 0, NULL }
};


static int
dissect_atn_cm_Response(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     2, NULL, FALSE, 0, NULL);

  return offset;
}



static int
dissect_atn_cm_CMContactResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_atn_cm_Response(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string atn_cm_CMAbortReason_vals[] = {
  {   0, "timer-expired" },
  {   1, "undefined-error" },
  {   2, "invalid-PDU" },
  {   3, "protocol-error" },
  {   4, "dialogue-acceptance-not-permitted" },
  {   5, "dialogue-end-not-accepted" },
  {   6, "communication-service-error" },
  {   7, "communication-service-failure" },
  {   8, "invalid-QOS-parameter" },
  {   9, "expected-PDU-missing" },
  { 0, NULL }
};


static int
dissect_atn_cm_CMAbortReason(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     10, NULL, TRUE, 0, NULL);

  return offset;
}


static const value_string atn_cm_CMAircraftMessage_vals[] = {
  {   0, "cmLogonRequest" },
  {   1, "cmContactResponse" },
  {   2, "cmAbortReason" },
  { 0, NULL }
};

static const per_choice_t CMAircraftMessage_choice[] = {
  {   0, &hf_atn_cm_cmLogonRequest, ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMLogonRequest },
  {   1, &hf_atn_cm_cmContactResponse, ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMContactResponse },
  {   2, &hf_atn_cm_cmAbortReason, ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMAbortReason },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cm_CMAircraftMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cm_CMAircraftMessage, CMAircraftMessage_choice,
                                 NULL);

  return offset;
}


static const per_sequence_t CMLogonResponse_sequence[] = {
  { &hf_atn_cm_airInitiatedApplications, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress },
  { &hf_atn_cm_groundOnlyInitiatedApplications, ASN1_NO_EXTENSIONS     , ASN1_OPTIONAL    , dissect_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersion },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_CMLogonResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_CMLogonResponse, CMLogonResponse_sequence);

  return offset;
}



static int
dissect_atn_cm_CMUpdate(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_atn_cm_CMLogonResponse(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const per_sequence_t CMContactRequest_sequence[] = {
  { &hf_atn_cm_facilityDesignation, ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_FacilityDesignation },
  { &hf_atn_cm_address      , ASN1_NO_EXTENSIONS     , ASN1_NOT_OPTIONAL, dissect_atn_cm_LongTsap },
  { NULL, 0, 0, NULL }
};

static int
dissect_atn_cm_CMContactRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_sequence(tvb, offset, actx, tree, hf_index,
                                   ett_atn_cm_CMContactRequest, CMContactRequest_sequence);

  return offset;
}



static int
dissect_atn_cm_CMForwardRequest(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_atn_cm_CMLogonRequest(tvb, offset, actx, tree, hf_index);

  return offset;
}


static const value_string atn_cm_CMForwardResponse_vals[] = {
  {   0, "success" },
  {   1, "incompatible-version" },
  {   2, "service-not-supported" },
  { 0, NULL }
};


static int
dissect_atn_cm_CMForwardResponse(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_enumerated(tvb, offset, actx, tree, hf_index,
                                     3, NULL, FALSE, 0, NULL);

  return offset;
}


static const value_string atn_cm_CMGroundMessage_vals[] = {
  {   0, "cmLogonResponse" },
  {   1, "cmUpdate" },
  {   2, "cmContactRequest" },
  {   3, "cmForwardRequest" },
  {   4, "cmAbortReason" },
  {   5, "cmForwardResponse" },
  { 0, NULL }
};

static const per_choice_t CMGroundMessage_choice[] = {
  {   0, &hf_atn_cm_cmLogonResponse, ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMLogonResponse },
  {   1, &hf_atn_cm_cmUpdate     , ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMUpdate },
  {   2, &hf_atn_cm_cmContactRequest, ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMContactRequest },
  {   3, &hf_atn_cm_cmForwardRequest, ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMForwardRequest },
  {   4, &hf_atn_cm_cmAbortReason, ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMAbortReason },
  {   5, &hf_atn_cm_cmForwardResponse, ASN1_EXTENSION_ROOT    , dissect_atn_cm_CMForwardResponse },
  { 0, NULL, 0, NULL }
};

static int
dissect_atn_cm_CMGroundMessage(tvbuff_t *tvb _U_, int offset _U_, asn1_ctx_t *actx _U_, proto_tree *tree _U_, int hf_index _U_) {
  offset = dissect_per_choice(tvb, offset, actx, tree, hf_index,
                                 ett_atn_cm_CMGroundMessage, CMGroundMessage_choice,
                                 NULL);

  return offset;
}

/*--- PDUs ---*/

static int dissect_CMAircraftMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_atn_cm_CMAircraftMessage(tvb, offset, &asn1_ctx, tree, hf_atn_cm_CMAircraftMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}
static int dissect_CMGroundMessage_PDU(tvbuff_t *tvb _U_, packet_info *pinfo _U_, proto_tree *tree _U_, void *data _U_) {
  int offset = 0;
  asn1_ctx_t asn1_ctx;
  asn1_ctx_init(&asn1_ctx, ASN1_ENC_PER, FALSE, pinfo);
  offset = dissect_atn_cm_CMGroundMessage(tvb, offset, &asn1_ctx, tree, hf_atn_cm_CMGroundMessage_PDU);
  offset += 7; offset >>= 3;
  return offset;
}


/*--- End of included file: packet-atn-cm-fn.c ---*/
#line 60 "./asn1/atn-cm/packet-atn-cm-template.c"
static int proto_atn_cm = -1;

static int
dissect_atn_cm(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    int   type;
    proto_tree *sub_tree;

    sub_tree = proto_tree_add_subtree(
      tree, tvb, 0, -1, ett_atn_cm, NULL, ATN_CM_PROTO);

    /* ti = proto_tree_add_item(tree, proto_atn_cm, tvb, 0, 0 , ENC_NA); */
    /* sub_tree = proto_item_add_subtree(ti, ett_atn_cm_pdu); */

    /* determine whether it is uplink or downlink */
    type = check_heur_msg_type(pinfo);

    switch(type){
        case um:
            dissect_CMGroundMessage_PDU(
              tvb,
              pinfo,
              sub_tree, NULL);
            break;
        case dm:
            dissect_CMAircraftMessage_PDU(
              tvb,
              pinfo,
              sub_tree, NULL);
            break;
        default:
            break;
    }
    return tvb_reported_length_remaining(tvb, 0);
}

static gboolean
dissect_atn_cm_heur(
    tvbuff_t *tvb,
    packet_info *pinfo,
    proto_tree *tree,
    void *data _U_)
{
    atn_conversation_t *volatile atn_cv = NULL;
    volatile gboolean is_atn_cm = FALSE;
    int type;

    /* determine whether it is uplink or downlink */
    type = check_heur_msg_type(pinfo);

    /* heuristically decode message */
    switch(type){
        case um:
            TRY {
                dissect_CMGroundMessage_PDU(
                  tvb,
                  pinfo,
                  NULL, NULL);
                /* no exception thrown: looks like it is a CM PDU */
                is_atn_cm = TRUE; }
            CATCH_ALL {
                is_atn_cm = FALSE; }
            ENDTRY;
            break;
        case dm:
            TRY {
                dissect_CMAircraftMessage_PDU(
                    tvb,
                    pinfo,
                    NULL, NULL);
                /* no exception thrown: looks like it is a CM PDU */
                is_atn_cm = TRUE;}
            CATCH_ALL {
                is_atn_cm = FALSE; }
            ENDTRY;
            break;
        default:
            break;
    }

    if (is_atn_cm  == TRUE) {
        /* note: */
        /* all subsequent PDU's belonging to this conversation are considered CM */
        /* if the first CM PDU has been decoded successfully */
        /* (This is done in "atn-ulcs" by using "call_dissector_with_data()") */

        /* DT: dstref present, srcref is always zero */
        if((pinfo->clnp_dstref) &&
            (!pinfo->clnp_srcref)){

          atn_cv = find_atn_conversation(
                &pinfo->dst,
                pinfo->clnp_dstref,
                &pinfo->src );
        }
        /* CR: srcref present, dstref is always zero */
        if((!pinfo->clnp_dstref) &&
            (pinfo->clnp_srcref)){

          atn_cv = find_atn_conversation(
                &pinfo->src,
                pinfo->clnp_srcref,
                &pinfo->dst );

        }
        /* CC: srcref and dstref present  */
        if((pinfo->clnp_dstref) &&
            (pinfo->clnp_srcref)){
            atn_cv = find_atn_conversation(
                &pinfo->src,
                pinfo->clnp_srcref,
                &pinfo->dst );
        }
        if(atn_cv){
            atn_cv->ae_qualifier = cma;
        }
        dissect_atn_cm(
            tvb,
            pinfo,
            tree,
            NULL);
    }

    return is_atn_cm;
}


void proto_register_atn_cm (void)
{
    static hf_register_info hf_atn_cm[] = {

/*--- Included file: packet-atn-cm-hfarr.c ---*/
#line 1 "./asn1/atn-cm/packet-atn-cm-hfarr.c"
    { &hf_atn_cm_CMAircraftMessage_PDU,
      { "CMAircraftMessage", "atn-cm.CMAircraftMessage",
        FT_UINT32, BASE_DEC, VALS(atn_cm_CMAircraftMessage_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cm_CMGroundMessage_PDU,
      { "CMGroundMessage", "atn-cm.CMGroundMessage",
        FT_UINT32, BASE_DEC, VALS(atn_cm_CMGroundMessage_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cm_cmLogonRequest,
      { "cmLogonRequest", "atn-cm.cmLogonRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_cmContactResponse,
      { "cmContactResponse", "atn-cm.cmContactResponse",
        FT_UINT32, BASE_DEC, VALS(atn_cm_Response_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cm_cmAbortReason,
      { "cmAbortReason", "atn-cm.cmAbortReason",
        FT_UINT32, BASE_DEC, VALS(atn_cm_CMAbortReason_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cm_cmLogonResponse,
      { "cmLogonResponse", "atn-cm.cmLogonResponse_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_cmUpdate,
      { "cmUpdate", "atn-cm.cmUpdate_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_cmContactRequest,
      { "cmContactRequest", "atn-cm.cmContactRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_cmForwardRequest,
      { "cmForwardRequest", "atn-cm.cmForwardRequest_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_cmForwardResponse,
      { "cmForwardResponse", "atn-cm.cmForwardResponse",
        FT_UINT32, BASE_DEC, VALS(atn_cm_CMForwardResponse_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cm_longTsap,
      { "longTsap", "atn-cm.longTsap_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_shortTsap,
      { "shortTsap", "atn-cm.shortTsap_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_aeQualifier,
      { "aeQualifier", "atn-cm.aeQualifier",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_apVersion,
      { "apVersion", "atn-cm.apVersion",
        FT_UINT32, BASE_DEC, NULL, 0,
        "VersionNumber", HFILL }},
    { &hf_atn_cm_apAddress,
      { "apAddress", "atn-cm.apAddress",
        FT_UINT32, BASE_DEC, VALS(atn_cm_APAddress_vals), 0,
        NULL, HFILL }},
    { &hf_atn_cm_facilityDesignation,
      { "facilityDesignation", "atn-cm.facilityDesignation",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_address,
      { "address", "atn-cm.address_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LongTsap", HFILL }},
    { &hf_atn_cm_aircraftFlightIdentification,
      { "aircraftFlightIdentification", "atn-cm.aircraftFlightIdentification",
        FT_STRING, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_cMLongTSAP,
      { "cMLongTSAP", "atn-cm.cMLongTSAP_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "LongTsap", HFILL }},
    { &hf_atn_cm_groundInitiatedApplications,
      { "groundInitiatedApplications", "atn-cm.groundInitiatedApplications",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress", HFILL }},
    { &hf_atn_cm_groundInitiatedApplications_item,
      { "AEQualifierVersionAddress", "atn-cm.AEQualifierVersionAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_airOnlyInitiatedApplications,
      { "airOnlyInitiatedApplications", "atn-cm.airOnlyInitiatedApplications",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_AEQualifierVersion", HFILL }},
    { &hf_atn_cm_airOnlyInitiatedApplications_item,
      { "AEQualifierVersion", "atn-cm.AEQualifierVersion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_airportDeparture,
      { "airportDeparture", "atn-cm.airportDeparture",
        FT_STRING, BASE_NONE, NULL, 0,
        "Airport", HFILL }},
    { &hf_atn_cm_airportDestination,
      { "airportDestination", "atn-cm.airportDestination",
        FT_STRING, BASE_NONE, NULL, 0,
        "Airport", HFILL }},
    { &hf_atn_cm_dateTimeDepartureETD,
      { "dateTimeDepartureETD", "atn-cm.dateTimeDepartureETD_element",
        FT_NONE, BASE_NONE, NULL, 0,
        "DateTime", HFILL }},
    { &hf_atn_cm_airInitiatedApplications,
      { "airInitiatedApplications", "atn-cm.airInitiatedApplications",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress", HFILL }},
    { &hf_atn_cm_airInitiatedApplications_item,
      { "AEQualifierVersionAddress", "atn-cm.AEQualifierVersionAddress_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_groundOnlyInitiatedApplications,
      { "groundOnlyInitiatedApplications", "atn-cm.groundOnlyInitiatedApplications",
        FT_UINT32, BASE_DEC, NULL, 0,
        "SEQUENCE_SIZE_1_256_OF_AEQualifierVersion", HFILL }},
    { &hf_atn_cm_groundOnlyInitiatedApplications_item,
      { "AEQualifierVersion", "atn-cm.AEQualifierVersion_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_year,
      { "year", "atn-cm.year",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_month,
      { "month", "atn-cm.month",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_day,
      { "day", "atn-cm.day",
        FT_UINT32, BASE_DEC, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_date,
      { "date", "atn-cm.date_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_time,
      { "time", "atn-cm.time_element",
        FT_NONE, BASE_NONE, NULL, 0,
        NULL, HFILL }},
    { &hf_atn_cm_rDP,
      { "rDP", "atn-cm.rDP",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_5", HFILL }},
    { &hf_atn_cm_aRS,
      { "aRS", "atn-cm.aRS",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_3", HFILL }},
    { &hf_atn_cm_locSysNselTsel,
      { "locSysNselTsel", "atn-cm.locSysNselTsel",
        FT_BYTES, BASE_NONE, NULL, 0,
        "OCTET_STRING_SIZE_10_11", HFILL }},
    { &hf_atn_cm_hours,
      { "hours", "atn-cm.hours",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Timehours", HFILL }},
    { &hf_atn_cm_minutes,
      { "minutes", "atn-cm.minutes",
        FT_UINT32, BASE_DEC, NULL, 0,
        "Timeminutes", HFILL }},

/*--- End of included file: packet-atn-cm-hfarr.c ---*/
#line 195 "./asn1/atn-cm/packet-atn-cm-template.c"
    };
    static gint *ett[] = {

/*--- Included file: packet-atn-cm-ettarr.c ---*/
#line 1 "./asn1/atn-cm/packet-atn-cm-ettarr.c"
    &ett_atn_cm_CMAircraftMessage,
    &ett_atn_cm_CMGroundMessage,
    &ett_atn_cm_APAddress,
    &ett_atn_cm_AEQualifierVersion,
    &ett_atn_cm_AEQualifierVersionAddress,
    &ett_atn_cm_CMContactRequest,
    &ett_atn_cm_CMLogonRequest,
    &ett_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersionAddress,
    &ett_atn_cm_SEQUENCE_SIZE_1_256_OF_AEQualifierVersion,
    &ett_atn_cm_CMLogonResponse,
    &ett_atn_cm_Date,
    &ett_atn_cm_DateTime,
    &ett_atn_cm_LongTsap,
    &ett_atn_cm_ShortTsap,
    &ett_atn_cm_Time,

/*--- End of included file: packet-atn-cm-ettarr.c ---*/
#line 198 "./asn1/atn-cm/packet-atn-cm-template.c"
      &ett_atn_cm
    };

    /* register CM application */
    proto_atn_cm = proto_register_protocol(
        ATN_CM_PROTO ,
        "ATN-CM",
        "atn-cm");

    proto_register_field_array(
        proto_atn_cm,
        hf_atn_cm,
        array_length(hf_atn_cm));

    proto_register_subtree_array(
        ett,
        array_length(ett));

    register_dissector(
        "atn-cm",
        dissect_atn_cm,
        proto_atn_cm);
}

void proto_reg_handoff_atn_cm(void)
{
    /* add session dissector to subdissector list*/
    heur_dissector_add(
        "atn-ulcs",
        dissect_atn_cm_heur,
        "ATN-CM over ATN-ULCS",
        "atn-cm-ulcs",
        proto_atn_cm, HEURISTIC_ENABLE);
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
