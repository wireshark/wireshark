/** @file
 * Extenal definitions for EAP Extensible Authentication Protocol dissection
 * RFC 2284, RFC 3748
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __EAP_H__
#define __EAP_H__

#include "ws_symbol_export.h"
#include "value_string.h"

/* http://www.iana.org/assignments/eap-numbers */
#define EAP_REQUEST     1
#define EAP_RESPONSE    2
#define EAP_SUCCESS     3
#define EAP_FAILURE     4
#define EAP_INITIATE    5 /* [RFC5296] */
#define EAP_FINISH      6 /* [RFC5296] */

WS_DLL_PUBLIC const value_string eap_code_vals[];

#define EAP_TYPE_ID          1
#define EAP_TYPE_NOTIFY      2
#define EAP_TYPE_NAK         3
#define EAP_TYPE_MD5         4
#define EAP_TYPE_TLS        13
#define EAP_TYPE_LEAP       17
#define EAP_TYPE_SIM        18
#define EAP_TYPE_TTLS       21
#define EAP_TYPE_AKA        23
#define EAP_TYPE_PEAP       25
#define EAP_TYPE_MSCHAPV2   26
#define EAP_TYPE_MSAUTH_TLV 33
#define EAP_TYPE_FAST       43
#define EAP_TYPE_PAX        46
#define EAP_TYPE_PSK        47
#define EAP_TYPE_SAKE       48
#define EAP_TYPE_IKEV2      49
#define EAP_TYPE_AKA_PRIME  50
#define EAP_TYPE_GPSK       51
#define EAP_TYPE_TEAP       55
#define EAP_TYPE_EXT       254

WS_DLL_PUBLIC value_string_ext eap_type_vals_ext;

#define SIM_START 10
#define SIM_CHALLENGE 11
#define SIM_NOTIFICATION 12
#define SIM_RE_AUTHENTICATION 13
#define SIM_CLIENT_ERROR 14

WS_DLL_PUBLIC const value_string eap_sim_subtype_vals[];

#define AKA_CHALLENGE 1
#define AKA_AUTHENTICATION_REJECT 2
#define AKA_SYNCHRONIZATION_FAILURE 4
#define AKA_IDENTITY 5
#define AKA_NOTIFICATION 12
#define AKA_REAUTHENTICATION 13
#define AKA_CLIENT_ERROR 14

WS_DLL_PUBLIC const value_string eap_aka_subtype_vals[];

#define MS_CHAP_V2_CHALLENGE 1
#define MS_CHAP_V2_RESPONSE 2
#define MS_CHAP_V2_SUCCESS 3
#define MS_CHAP_V2_FAILURE 4
#define MS_CHAP_V2_CHANGE_PASSWORD 7

WS_DLL_PUBLIC const value_string eap_ms_chap_v2_opcode_vals[];

typedef enum {
  PROTO_DATA_EAP_DUPLICATE_ID,
  PROTO_DATA_EAP_FRAME_STATE,
  PROTO_DATA_EAP_TVB,
} proto_data_eap;

typedef struct _eap_vendor_context {
  uint32_t  vendor_type;
  uint32_t  vendor_id;
  uint8_t   eap_code;
  uint8_t   eap_identifier;
} eap_vendor_context;

#endif
