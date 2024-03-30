/** @file
 *
 * VoIP calls summary addition for Wireshark
 *
 * Copyright 2004, Ericsson , Spain
 * By Francisco Alcoba <francisco.alcoba@ericsson.com>
 *
 * based on h323_calls.h
 * Copyright 2004, Iskratel, Ltd, Kranj
 * By Miha Jemec <m.jemec@iskratel.si>
 *
 * H323, RTP and Graph Support
 * By Alejandro Vaquero, alejandro.vaquero@verso.com
 * Copyright 2005, Verso Technologies Inc.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#ifndef __VOIP_CALLS_H__
#define __VOIP_CALLS_H__

#include <glib.h>

#include <stdio.h>

#include "epan/address.h"
#include "epan/packet.h"
#include "epan/guid-utils.h"
#include "epan/tap.h"
#include "epan/tap-voip.h"
#include "epan/sequence_analysis.h"

/** @file
 *  "VoIP Calls" dialog box common routines.
 *  @ingroup main_ui_group
 */

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/****************************************************************************/
extern const char *voip_call_state_name[8];

typedef enum _voip_protocol {
    VOIP_SIP,
    VOIP_ISUP,
    VOIP_H323,
    VOIP_MGCP,
    VOIP_AC_ISDN,
    VOIP_AC_CAS,
    MEDIA_T38,
    TEL_H248,
    TEL_SCCP,
    TEL_BSSMAP,
    TEL_RANAP,
    VOIP_UNISTIM,
    VOIP_SKINNY,
    VOIP_IAX2,
    VOIP_COMMON
} voip_protocol;

typedef enum _hash_indexes {
    SIP_HASH=0
} hash_indexes;

extern const char *voip_protocol_name[];

typedef enum _flow_show_options
{
    FLOW_ALL,
    FLOW_ONLY_INVITES
} flow_show_options;

/** defines specific SIP data */

typedef enum _sip_call_state {
    SIP_INVITE_SENT,
    SIP_200_REC,
    SIP_CANCEL_SENT
} sip_call_state;

typedef struct _sip_calls_info {
    char *call_identifier;
    uint32_t invite_cseq;
    sip_call_state sip_state;
} sip_calls_info_t;

/** defines specific ISUP data */
typedef struct _isup_calls_info {
    uint16_t cic;
    uint32_t opc, dpc;
    uint8_t ni;
} isup_calls_info_t;

/* defines specific H245 data */
typedef struct _h245_address {
    address h245_address;
    uint16_t h245_port;
} h245_address_t;

/** defines specific H323 data */
typedef struct _h323_calls_info {
    e_guid_t *guid;               /* Call ID to identify a H225 */
    GList*    h245_list;          /**< list of H245 Address and ports for tunneling off calls*/
    address   h225SetupAddr;      /**< we use the SETUP H225 IP to determine if packets are forward or reverse */
    bool      is_h245;
    bool      is_faststart_Setup; /**< if faststart field is included in Setup*/
    bool      is_faststart_Proc;  /**< if faststart field is included in Proce, Alerting, Progress or Connect*/
    bool      is_h245Tunneling;
    int32_t   q931_crv;
    int32_t   q931_crv2;
    unsigned  requestSeqNum;
} h323_calls_info_t;

/**< defines specific MGCP data */
typedef struct _mgcp_calls_info {
    char *endpointId;
    bool fromEndpoint; /**< true if the call was originated from the Endpoint, false for calls from MGC */
} mgcp_calls_info_t;

/** defines specific ACTRACE ISDN data */
typedef struct _actrace_isdn_calls_info {
    int32_t crv;
    int trunk;
} actrace_isdn_calls_info_t;

/** defines specific ACTRACE CAS data */
typedef struct _actrace_cas_calls_info {
    int32_t bchannel;
    int trunk;
} actrace_cas_calls_info_t;

/** defines specific SKINNY data */
typedef struct _skinny_calls_info {
    uint32_t callId;
} skinny_calls_info_t;

/** defines a voip call */
typedef struct _voip_calls_info {
    voip_call_state         call_state;
    voip_call_active_state  call_active_state;
    char                   *call_id;
    char                   *from_identity;
    char                   *to_identity;
    void *                  prot_info;
    void (*free_prot_info)(void *);
    address                 initial_speaker;
    uint32_t                npackets;
    voip_protocol           protocol;
    char                   *protocol_name;
    char                   *call_comment;
    uint16_t                call_num;
    /**> The frame_data struct holds the frame number and timing information needed. */
    frame_data             *start_fd;
    nstime_t                start_rel_ts;
    frame_data             *stop_fd;
    nstime_t                stop_rel_ts;
} voip_calls_info_t;

/**
 * structure that holds the information about all detected calls */
/* struct holding all information of the tap */
/*
 * XXX Most of these are private to voip_calls.c. We might want to
 * make them private.
 */
struct _h245_labels;
typedef struct _voip_calls_tapinfo {
    tap_reset_cb          tap_reset; /**< tap reset callback */
    tap_packet_cb         tap_packet; /**< tap per-packet callback */
    tap_draw_cb           tap_draw; /**< tap draw callback */
    void                 *tap_data; /**< data for tap callbacks */
    int                   ncalls; /**< number of call */
    GQueue*               callsinfos; /**< queue with all calls (voip_calls_info_t) */
    GHashTable*           callsinfo_hashtable[1]; /**< array of hashes per voip protocol (voip_calls_info_t); currently only the one for SIP is used */
    int                   npackets; /**< total number of packets of all calls */
    voip_calls_info_t    *filter_calls_fwd; /**< used as filter in some tap modes */
    int                   start_packets;
    int                   completed_calls;
    int                   rejected_calls;
    seq_analysis_info_t  *graph_analysis;
    epan_t               *session; /**< epan session */
    int                   nrtpstreams; /**< number of rtp streams */
    GList*                rtpstream_list; /**< list of rtpstream_info_t */
    uint32_t              rtp_evt_frame_num;
    uint8_t               rtp_evt;
    bool                  rtp_evt_end;
    char                 *sdp_summary;
    uint32_t              sdp_frame_num;
    uint32_t              mtp3_opc;
    uint32_t              mtp3_dpc;
    uint8_t               mtp3_ni;
    uint32_t              mtp3_frame_num;
    struct _h245_labels  *h245_labels; /**< H.245 labels */
    char                 *q931_calling_number;
    char                 *q931_called_number;
    uint8_t               q931_cause_value;
    int32_t               q931_crv;
    uint32_t              q931_frame_num;
    uint32_t              h225_frame_num;
    uint16_t              h225_call_num;
    int                   h225_cstype; /* XXX actually an enum */
    bool                  h225_is_faststart;
    uint32_t              sip_frame_num;
    uint32_t              actrace_frame_num;
    int32_t               actrace_trunk;
    int32_t               actrace_direction;
    flow_show_options     fs_option;
    uint32_t              redraw;
    bool                  apply_display_filter;
} voip_calls_tapinfo_t;

#if 0
#define VOIP_CALLS_DEBUG(...) { \
    char *VOIP_CALLS_DEBUG_MSG = ws_strdup_printf(__VA_ARGS__); \
    ws_warning("voip_calls: %s:%d %s", G_STRFUNC, __LINE__, VOIP_CALLS_DEBUG_MSG); \
    g_free(VOIP_CALLS_DEBUG_MSG); \
}
#else
#define VOIP_CALLS_DEBUG(...)
#endif

/****************************************************************************/
/* INTERFACE */

/**
 * Registers the voip_calls tap listeners (if not already done).
 * From that point on, the calls list will be updated with every redissection.
 * This function is also the entry point for the initialization routine of the tap system.
 * So whenever voip_calls.c is added to the list of WIRESHARK_TAP_SRCs, the tap will be registered on startup.
 * If not, it will be registered on demand by the voip_calls functions that need it.
 */
void voip_calls_init_all_taps(voip_calls_tapinfo_t *tap_id_base);

/**
 * Removes the voip_calls tap listener (if not already done)
 * From that point on, the voip calls list won't be updated any more.
 */
void voip_calls_remove_all_tap_listeners(voip_calls_tapinfo_t *tap_id_base);

/**
 * Cleans up memory of voip calls tap.
 */
void voip_calls_reset_all_taps(voip_calls_tapinfo_t *tapinfo);

/**
 * Frees one callsinfo
 */
void
voip_calls_free_callsinfo(voip_calls_info_t *callsinfo);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* __VOIP_CALLS_H__ */
