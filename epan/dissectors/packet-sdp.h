/* packet-sdp.h
 * Routines for SDP packet disassembly (RFC 2327)
 *
 * Jason Lango <jal@netapp.com>
 * Liberally copied from packet-http.c, by Guy Harris <guy@alum.mit.edu>
 * 2005 Alejandro Vaquero <alejandro.vaquero@verso.com>, add support for tap
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __PACKET_SDP_H__
#define __PACKET_SDP_H__

typedef struct _sdp_packet_info {
        char summary_str[50];      /* SDP summary string for VoIP calls graph analysis */
} sdp_packet_info;

enum sdp_exchange_type
{
	SDP_EXCHANGE_OFFER = 0,
	SDP_EXCHANGE_ANSWER_ACCEPT,
	SDP_EXCHANGE_ANSWER_REJECT
};

enum sdp_trace_id_hf_type
{
    SDP_TRACE_ID_HF_TYPE_STR = 0, /* */
    SDP_TRACE_ID_HF_TYPE_GUINT32 /* */
};

/*
 *  Information needed to set up a trace id in RTP(t ex SIP CallId )
 */
#define SDP_INFO_OFFSET 10 /* Max number of SDP data occurrences in a single frame */

typedef struct _sdp_setup_info {
    int  hf_id;                         /* Header field to use */
    enum sdp_trace_id_hf_type hf_type;  /* Indicates which of the following variables to use( add uint32_t etc as needed)*/
    bool add_hidden;
    bool is_osmux;
    union {
        char   *str;                    /* The trace id if the hf_type is str */
        uint32_t num;                    /* Numerical trace id */
    } trace_id;
} sdp_setup_info_t;

extern void setup_sdp_transport(tvbuff_t *tvb, packet_info *pinfo, enum sdp_exchange_type type, int request_frame, const bool delay, sdp_setup_info_t *setup_info);
/* Handles duplicate OFFER packets so they don't end up processed by dissect_sdp().  This can probably
 * be removed when all higher layer dissectors properly handle SDP themselves with setup_sdp_transport()
 */
extern void setup_sdp_transport_resend(int current_frame, int request_frame);

#endif /* __PACKET_SDP_H__ */
