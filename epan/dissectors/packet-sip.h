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
    const guint8    *request_method;
    guint     response_code;
    gboolean  resend;
    guint32   setup_time;
    /* added for VoIP calls analysis, see ui/voip_calls.c*/
    gchar    *tap_call_id;
    gchar    *tap_from_addr;
    gchar    *tap_to_addr;
    guint32   tap_cseq_number;
    gchar    *reason_phrase;
} sip_info_value_t;

typedef enum {
    SIP_PROTO_OTHER = 0,
    SIP_PROTO_SIP = 1,
    SIP_PROTO_Q850 = 2
} sip_reason_code_proto_t;

typedef struct _sip_reason_code_info_t
{
    sip_reason_code_proto_t    protocol_type_num;
    guint                      cause_value;
} sip_reason_code_info_t;

WS_DLL_PUBLIC const value_string sip_response_code_vals[];

extern void dfilter_store_sip_from_addr(tvbuff_t *tvb, proto_tree *tree,
    guint parameter_offset, guint parameter_len);

#endif
