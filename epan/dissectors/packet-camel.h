/* Do not modify this file. Changes will be overwritten.                      */
/* Generated automatically by the ASN.1 to Wireshark dissector compiler       */
/* packet-camel.h                                                             */
/* asn2wrs.py -b -L -p camel -c ./camel.cnf -s ./packet-camel-template -D . -O ../.. CAP-object-identifiers.asn CAP-classes.asn CAP-datatypes.asn CAP-errorcodes.asn CAP-errortypes.asn CAP-operationcodes.asn CAP-GPRS-ReferenceNumber.asn CAP-gsmSCF-gsmSRF-ops-args.asn CAP-gsmSSF-gsmSCF-ops-args.asn CAP-gprsSSF-gsmSCF-ops-args.asn CAP-SMS-ops-args.asn CAP-U-ABORT-Data.asn CamelV2diff.asn ../ros/Remote-Operations-Information-Objects.asn ../ros/Remote-Operations-Generic-ROS-PDUs.asn */

/* Input file: packet-camel-template.h */

#line 1 "./asn1/camel/packet-camel-template.h"
/* packet-camel-template.h
 * Routines for Camel
 * Copyright 2004, Tim Endean <endeant@hotmail.com>
 * Copyright 2005, Olivier Jacques <olivier.jacques@hp.com>
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


#ifndef PACKET_CAMEL_H
#define PACKET_CAMEL_H

#include "ws_symbol_export.h"

void proto_reg_handoff_camel(void);
void proto_register_camel(void);

/* Defines for the camel taps */
#define	camel_MAX_NUM_OPR_CODES	256

WS_DLL_PUBLIC const value_string camel_opr_code_strings[];
/* #include "packet-camel-exp.h"*/

/** @file
*/
#define NB_CAMELSRT_CATEGORY 9+1 /**< Number of type of message */
/* for example TC_BEGIN with InitalDP, and TC_CONT with RequestReportBCSMEvent
   is a category, we want to measure the delay between the two messages */

#define CAMELSRT_SESSION 1

#define CAMELSRT_VOICE_INITIALDP 2
#define CAMELSRT_VOICE_ACR1 3
#define CAMELSRT_VOICE_ACR2 4
#define CAMELSRT_VOICE_ACR3 5
#define CAMELSRT_VOICE_DISC 6

#define CAMELSRT_GPRS_INITIALDP 7
#define CAMELSRT_GPRS_REPORT 8

#define CAMELSRT_SMS_INITIALDP 9

WS_DLL_PUBLIC const value_string  camelSRTtype_naming[];

/** If we have a request message and its response,
   (eg: ApplyCharging, ApplyChargingReport)
   the frames numbers are stored in this structure */

struct camelsrt_category_t {
  guint32 req_num;		/**< frame number request seen */
  guint32 rsp_num;		/**< frame number response seen */
  nstime_t req_time;	/**< arrival time of request */
  gboolean responded;	/**< true, if request has been responded */
};

/** List of stored parameters for a Camel dialogue
   All this parameters are linked to the hash table key below (use of Tid)
   In case of same Tid reused, the Camel parameters are chained.
   The right dialogue will be identified with the arrival time of the InitialDP */

struct camelsrt_call_t {
  guint32 session_id;    /**< Identify the session, with an internal number */
  struct tcaphash_context_t * tcap_context;
  struct camelsrt_category_t category[NB_CAMELSRT_CATEGORY];
};


/** The Key for the hash table is the TCAP origine transaction identifier
   of the TC_BEGIN containing the InitialDP */

struct camelsrt_call_info_key_t {
  guint32 SessionIdKey;
};

/** Info for a couple of messages (or category)
   The request must be available, not duplicated,
   and once the corresponding response received,
   we can deduce the Delta Time between Request/response */

struct camelsrt_msginfo_t {
  gboolean request_available;
  gboolean is_duplicate;
  gboolean is_delta_time;
  nstime_t req_time;
  nstime_t delta_time;
};

/** List of infos to store for the analyse */

struct camelsrt_info_t {
  guint32 tcap_session_id;
  void * tcap_context;
  guint8 opcode; /**< operation code of message received */
  guint8 bool_msginfo[NB_CAMELSRT_CATEGORY]; /**< category for the received message */
  struct camelsrt_msginfo_t msginfo[NB_CAMELSRT_CATEGORY];
};

/**
 * Initialize the Message Info used by the main dissector
 * Data are linked to a TCAP transaction
 */
struct camelsrt_info_t * camelsrt_razinfo(void);

/**
 * Service Response Time analyze, called just after the camel dissector
 * According to the camel operation, we
 * - open/close a context for the camel session
 * - look for a request, or look for the corresponding response
 */
void camelsrt_call_matching(tvbuff_t *tvb,
			    packet_info * pinfo _U_,
			    proto_tree *tree,
			    struct camelsrt_info_t * p_camel_info);

WS_DLL_PUBLIC gboolean gcamel_StatSRT;

#endif  /* PACKET_camel_H */
