/* packet-sip.h
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SIP_H__
#define __PACKET_SIP_H__

#include <epan/packet.h>

typedef struct _sip_info_value_t
{
    const uint8_t   *request_method;
    unsigned  response_code;
    bool      resend;
    uint32_t  setup_time;
    /* added for VoIP calls analysis, see ui/voip_calls.c*/
    char     *tap_call_id;
    char     *tap_from_addr;
    char     *tap_to_addr;
    uint32_t  tap_cseq_number;
    char     *reason_phrase;
} sip_info_value_t;

typedef enum {
    SIP_PROTO_OTHER = 0,
    SIP_PROTO_SIP = 1,
    SIP_PROTO_Q850 = 2
} sip_reason_code_proto_t;

typedef struct _sip_reason_code_info_t
{
    sip_reason_code_proto_t    protocol_type_num;
    unsigned                   cause_value;
} sip_reason_code_info_t;

WS_DLL_PUBLIC const value_string sip_response_code_vals[];

extern void dfilter_store_sip_from_addr(tvbuff_t *tvb, proto_tree *tree,
    unsigned parameter_offset, unsigned parameter_len);

extern void dissect_sip_p_access_network_info_header(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, int start_offset, int line_end_offset);

#endif
