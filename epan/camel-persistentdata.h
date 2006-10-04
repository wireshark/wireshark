/*
 * camel-persistentdata.h
 * Definitions for lists and hash tables used in wireshark's camel dissector
 * for calculation of delays in camel-transactions
 * Copyright 2006 Florent Drouin
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

#ifndef __camelsrt_HASH__
#define __camelsrt_HASH__

#include "epan/packet.h"
#include "epan/conversation.h"
#include "epan/dissectors/packet-camel.h"
#include "epan/tcap-persistentdata.h"

#define NB_CAMELSRT_CATEGORY 9+1 /* Number of type of message */
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

extern const value_string  camelSRTtype_naming[];

/* If we have a request message and its response,
   (eg: ApplyCharging, ApplyChargingReport)
   the frames numbers are stored in this structure */ 

struct camelsrt_category_t {
  guint32 req_num;	/* frame number request seen */
  guint32 rsp_num;	/* frame number response seen */
  nstime_t req_time;	/* arrival time of request */
  gboolean responded;	/* true, if request has been responded */
};

/* List of stored parameters for a Camel dialogue
   All this parameters are linked to the hash table key below (use of Tid)
   In case of same Tid reused, the Camel parameters are chained.
   The right dialogue will be identified with the arrival time of the InitialDP */

struct camelsrt_call_t {
  guint32 session_id;    /* Identify the session, with an internal number */
  struct tcaphash_context_t * tcap_context;
  struct camelsrt_category_t category[NB_CAMELSRT_CATEGORY];
};


/* The Key for the hash table is the TCAP origine transaction identifier 
   of the TC_BEGIN containing the InitialDP */

struct camelsrt_call_info_key_t {
  guint32 SessionIdKey;
};

/* Info for a couple of messages (or category)
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

/* List of infos to store for the analyse */

struct camelsrt_info_t { 
  guint32 tcap_session_id;
  void * tcap_context;
  guint8 opcode; /* operation code of message received */
  guint8 bool_msginfo[NB_CAMELSRT_CATEGORY]; /* category for the received message */
  struct camelsrt_msginfo_t msginfo[NB_CAMELSRT_CATEGORY];
};

void camelsrt_init_routine(void);

struct camelsrt_info_t * camelsrt_razinfo(void);

void camelsrt_call_matching(tvbuff_t *tvb,
			    packet_info * pinfo _U_,
			    proto_tree *tree,
			    struct camelsrt_info_t * p_camel_info);

#endif /* __camelsrt_HASH__*/
