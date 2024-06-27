/* Do not modify this file. Changes will be overwritten */
/* Generated Automatically                              */
/* packet-skinny.h                                      */

/* packet-skinny.h
 * Dissector for the Skinny Client Control Protocol
 *   (The "D-Channel"-Protocol for Cisco Systems' IP-Phones)
 *
 * Author: Diederik de Groot <ddegroot@user.sf.net>, Copyright 2014
 * Rewritten to support newer skinny protocolversions (V0-V22)
 * Based on previous versions/contributions:
 *  - Joerg Mayer <jmayer@loplof.de>, Copyright 2001
 *  - Paul E. Erkkila (pee@erkkila.org) - fleshed out the decode
 *    skeleton to report values for most message/message fields.
 *    Much help from Guy Harris on figuring out the wireshark api.
 *  - packet-aim.c by Ralf Hoelzer <ralf@well.com>, Copyright 2000
 *  - Wireshark - Network traffic analyzer,
 *    By Gerald Combs <gerald@wireshark.org>, Copyright 1998
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/*
 * Generated automatically Using (from wireshark base directory):
 *   cog.py -D xmlfile=tools/SkinnyProtocolOptimized.xml -d -c -o epan/dissectors/packet-skinny.h epan/dissectors/packet-skinny.h.in
 */

#include <epan/wmem_scopes.h>

/* request response tracking */
typedef struct _skinny_req_resp_t {
  uint32_t               request_frame;
  uint32_t               response_frame;
  nstime_t               request_time;
} skinny_req_resp_t;

/* begin conversation  info*/
typedef enum _skinny_message_type_t {
  SKINNY_MSGTYPE_EVENT    = 0,
  SKINNY_MSGTYPE_REQUEST  = 1,
  SKINNY_MSGTYPE_RESPONSE = 2,
} skinny_message_type_t;

typedef struct _skinny_conv_info_t {
  skinny_message_type_t   mtype;
  wmem_map_t            * pending_req_resp;
  wmem_map_t            * requests;
  wmem_map_t            * responses;
  int32_t                 lineId;
  //uint32_t                callId;
  //uint32_t                passThruId;
  //uint32_t                transactionId;
  //uint32_t                callState;
} skinny_conv_info_t;
/* end conversation info */

/* Containers for tapping relevant data */
/* WIP: will be (partially) replaced in favor of conversation, dependents: ui/voip_calls.c */
typedef struct _skinny_info_t
{
  uint32_t                messId;
  uint32_t                maxProtocolVersion;
  int32_t                 lineId;
  uint32_t                callId;
  uint32_t                passThroughPartyId;
  const char            * messageName;
  uint32_t                callState;
  bool                    hasCallInfo;
  char                  * callingParty;
  char                  * calledParty;
  int32_t                 mediaReceptionStatus;
  int32_t                 mediaTransmissionStatus;
  int32_t                 multimediaReceptionStatus;
  int32_t                 multimediaTransmissionStatus;
  int32_t                 multicastReceptionStatus;
  //skinny_conv_info_t    * skinny_conv;
  char                  * additionalInfo;
} skinny_info_t;

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
