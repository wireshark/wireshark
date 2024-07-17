/* packet-transum.c
 * Routines for the TRANSUM response time analyzer post-dissector
 * By Paul Offord <paul.offord@advance7.com>
 * Copyright 2016 Advance Seven Limited
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

/* ToDo: Test handling of multiple SMB2 messages within a packet */
/* ToDo: Rework the Summarizer code (future release) */

#include "config.h"
#define WS_LOG_DOMAIN "transum"

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/ws_printf.h>
#include "packet-transum.h"
#include "preferences.h"
#include "extractors.h"
#include "decoders.h"
#include <wsutil/wslog.h>

void proto_register_transum(void);
void proto_reg_handoff_transum(void);

static dissector_handle_t transum_handle;

#define CAPTURE_CLIENT 0
#define CAPTURE_INTERMEDIATE 1
#define CAPTURE_SERVICE 2

#define RTE_TIME_SEC  1
#define RTE_TIME_MSEC 1000
#define RTE_TIME_USEC 1000000

/* The following are the field ids for the protocol values used by TRANSUM.
    Make sure they line up with ehf_of_interest order */
HF_OF_INTEREST_INFO hf_of_interest[HF_INTEREST_END_OF_LIST] = {
    { -1, "ip.proto" },
    { -1, "ipv6.nxt" },

    { -1, "tcp.analysis.retransmission" },
    { -1, "tcp.analysis.keep_alive" },
    { -1, "tcp.flags.syn" },
    { -1, "tcp.flags.ack" },
    { -1, "tcp.flags.reset" },
    { -1, "tcp.flags.urg" },
    { -1, "tcp.seq" },
    { -1, "tcp.srcport" },
    { -1, "tcp.dstport" },
    { -1, "tcp.stream" },
    { -1, "tcp.len" },

    { -1, "udp.srcport" },
    { -1, "udp.dstport" },
    { -1, "udp.stream" },
    { -1, "udp.length" },

    { -1, "tls.record.content_type" },

    { -1, "tds.type" },
    { -1, "tds.length" },

    { -1, "smb.mid" },

    { -1, "smb2.sesid" },
    { -1, "smb2.msg_id" },
    { -1, "smb2.cmd" },

    { -1, "dcerpc.ver" },
    { -1, "dcerpc.pkt_type" },
    { -1, "dcerpc.cn_call_id" },
    { -1, "dcerpc.cn_ctx_id" },

    { -1, "dns.id"},
};


static range_t *tcp_svc_port_range_values;

static range_t *udp_svc_port_range_values;

TSUM_PREFERENCES preferences;


static wmem_map_t *detected_tcp_svc;  /* this array is used to track services detected during the syn/syn-ack process */

static wmem_map_t *dcerpc_req_pkt_type;  /* used to indicate if a DCE-RPC pkt_type is a request */

static wmem_map_t *dcerpc_streams;  /* used to record TCP stream numbers that are carrying DCE-RPC data */

/*
This array contains calls and returns that have no true context_id
This is needed to overcome an apparent bug in Wireshark where
the field name of context id in parameters is the same as context id
in a message header
*/
static wmem_map_t *dcerpc_context_zero;

/*
    The rrpd_list holds information about all of the APDU Request-Response Pairs seen in the trace.
 */
static wmem_list_t *rrpd_list;

/*
    output_rrpd is a hash of pointers to RRPDs on the rrpd_list.  The index is the frame number.  This hash is
    used during Wireshark's second scan.  As each packet is processed, TRANSUM uses the packet's frame number to index into
    this hash to determine if we have RTE data for this particular packet, and if so the write_rte function is called.
 */
static wmem_map_t *output_rrpd;

/*
    The temp_rsp_rrpd_list holds RRPDs for APDUs where we have not yet seen the header information and so we can't
    fully qualify the identification of the RRPD (the identification being ip_proto:stream_no:session_id:msg_id).
    This only occurs when a) we are using one of the decode_based calculations (such as SMB2), and b) when we have
    TCP Reassembly enabled.  Once we receive a header packet for an APDU we migrate the entry from this array to the
    main rrpd_list.
 */
static wmem_list_t *temp_rsp_rrpd_list;  /* Reuse these for speed and efficient memory use - issue a warning if we run out */

/* Optimisation data - the following is used for various optimisation measures */
static int highest_tcp_stream_no;
static int highest_udp_stream_no;
wmem_map_t *tcp_stream_exceptions;


static int ett_transum;
static int ett_transum_header;
static int ett_transum_data;

static int proto_transum;

static int hf_tsum_status;
//static int hf_tsum_time_units;
static int hf_tsum_req_first_seg;
static int hf_tsum_req_last_seg;
static int hf_tsum_rsp_first_seg;
static int hf_tsum_rsp_last_seg;
static int hf_tsum_apdu_rsp_time;
static int hf_tsum_service_time;
static int hf_tsum_req_spread;
static int hf_tsum_rsp_spread;
static int hf_tsum_clip_filter;
static int hf_tsum_calculation;
static int hf_tsum_summary;
static int hf_tsum_req_search;
static int hf_tsum_rsp_search;

static const enum_val_t capture_position_vals[] = {
    { "TRACE_CAP_CLIENT", "Client", TRACE_CAP_CLIENT },
    { "TRACE_CAP_INTERMEDIATE", "Intermediate", TRACE_CAP_INTERMEDIATE },
    { "TRACE_CAP_SERVICE", "Service", TRACE_CAP_SERVICE },
    { NULL, NULL, 0}
};

static const value_string rrdp_calculation_vals[] = {
   { RTE_CALC_GTCP,       "Generic TCP"  },
   { RTE_CALC_SYN,        "SYN and SYN/ACK" },
   { RTE_CALC_DCERPC,     "DCE-RPC" },
   { RTE_CALC_SMB2,       "SMB2" },
   { RTE_CALC_GUDP,       "Generic UDP" },
   { RTE_CALC_DNS,        "DNS" },

   { 0,        NULL }
};

/*static const enum_val_t time_multiplier_vals[] = {
    { "RTE_TIME_SEC", "seconds", RTE_TIME_SEC },
    { "RTE_TIME_MSEC", "milliseconds", RTE_TIME_MSEC },
    { "RTE_TIME_USEC", "microseconds", RTE_TIME_USEC },
    { NULL, NULL, 0}
};*/

void add_detected_tcp_svc(uint16_t port)
{
    wmem_map_insert(detected_tcp_svc, GUINT_TO_POINTER(port), GUINT_TO_POINTER(port));
}


static void init_dcerpc_data(void)
{
    wmem_map_insert(dcerpc_req_pkt_type, GUINT_TO_POINTER(0), GUINT_TO_POINTER(1));
    wmem_map_insert(dcerpc_req_pkt_type, GUINT_TO_POINTER(11), GUINT_TO_POINTER(1));
    wmem_map_insert(dcerpc_req_pkt_type, GUINT_TO_POINTER(14), GUINT_TO_POINTER(1));

    wmem_map_insert(dcerpc_context_zero, GUINT_TO_POINTER(11), GUINT_TO_POINTER(11));
    wmem_map_insert(dcerpc_context_zero, GUINT_TO_POINTER(12), GUINT_TO_POINTER(12));
    wmem_map_insert(dcerpc_context_zero, GUINT_TO_POINTER(14), GUINT_TO_POINTER(14));
    wmem_map_insert(dcerpc_context_zero, GUINT_TO_POINTER(15), GUINT_TO_POINTER(15));
}

static void register_dcerpc_stream(uint32_t stream_no)
{
    wmem_map_insert(dcerpc_streams, GUINT_TO_POINTER(stream_no), GUINT_TO_POINTER(1));
}

/* This function should be called before any change to RTE data. */
static void null_output_rrpd_entries(RRPD *in_rrpd)
{
    wmem_map_remove(output_rrpd, GUINT_TO_POINTER(in_rrpd->req_first_frame));
    wmem_map_remove(output_rrpd, GUINT_TO_POINTER(in_rrpd->req_last_frame));
    wmem_map_remove(output_rrpd, GUINT_TO_POINTER(in_rrpd->rsp_first_frame));
    wmem_map_remove(output_rrpd, GUINT_TO_POINTER(in_rrpd->rsp_last_frame));
}

/* This function should be called after any change to RTE data. */
static void update_output_rrpd(RRPD *in_rrpd)
{
    if (preferences.rte_on_first_req)
        wmem_map_insert(output_rrpd, GUINT_TO_POINTER(in_rrpd->req_first_frame), in_rrpd);

    if (preferences.rte_on_last_req)
        wmem_map_insert(output_rrpd, GUINT_TO_POINTER(in_rrpd->req_last_frame), in_rrpd);

    if (preferences.rte_on_first_rsp)
        wmem_map_insert(output_rrpd, GUINT_TO_POINTER(in_rrpd->rsp_first_frame), in_rrpd);

    if (preferences.rte_on_last_rsp)
        wmem_map_insert(output_rrpd, GUINT_TO_POINTER(in_rrpd->rsp_last_frame), in_rrpd);
}

/* Return the index of the RRPD that has been appended */
static RRPD* append_to_rrpd_list(RRPD *in_rrpd)
{
    RRPD *next_rrpd = (RRPD*)wmem_memdup(wmem_file_scope(), in_rrpd, sizeof(RRPD));

    update_output_rrpd(next_rrpd);

    wmem_list_append(rrpd_list, next_rrpd);

    return next_rrpd;
}

static RRPD *find_latest_rrpd_dcerpc(RRPD *in_rrpd)
{
    RRPD *rrpd;
    wmem_list_frame_t* i;

    for (i = wmem_list_tail(rrpd_list); i != NULL; i = wmem_list_frame_prev(i))
    {
        rrpd = (RRPD*)wmem_list_frame_data(i);

        if (rrpd->calculation != RTE_CALC_DCERPC && rrpd->calculation != RTE_CALC_SYN)
            continue;

        /* if the input 5-tuple doesn't match the rrpd_list_entry 5-tuple -> go find the next list entry */
        if (rrpd->ip_proto == in_rrpd->ip_proto && rrpd->stream_no == in_rrpd->stream_no)
        {
            /* if we can match on session_id and msg_id must be a retransmission of the last request packet or the response */
            /* this logic works whether or not we are using reassembly */
            if (rrpd->session_id == in_rrpd->session_id && rrpd->msg_id == in_rrpd->msg_id)
                return rrpd;

            /* If this is a retransmission, we assume it relates to this rrpd_list entry.
               This is a bit of a kludge and not ideal but a compromise.*/
            /* ToDo: look at using TCP sequence number to allocate a retransmission to the correct APDU */
            if (in_rrpd->is_retrans)
                return rrpd;

            if (preferences.reassembly)
            {
                if (in_rrpd->c2s)
                {
                    /* if the input rrpd is for c2s and the one we have found already has response information, then the
                    in_rrpd represents a new RR Pair. */
                    if (rrpd->rsp_first_frame)
                        return NULL;

                    /* If the current rrpd_list entry doesn't have a msg_id then we assume we are mid Request APDU and so we have a match. */
                    if (!rrpd->msg_id)
                        return rrpd;
                }
                else  /* The in_rrpd relates to a packet going s2c */
                {
                    /* When reassembly is enabled, multi-packet response information is actually migrated from the temp_rsp_rrpd_list
                    to the rrpd_list and so we won't come through here. */
                    ;
                }
            }
            else /* we are not using reassembly */
            {
                if (in_rrpd->c2s)
                {
                    if (in_rrpd->msg_id)
                        /* if we have a message id this is a new Request APDU */
                        return NULL;
                    else  /* No msg_id */
                    {
                        return rrpd;  /* add this packet to the matching stream */
                    }
                }
                else  /* this packet is going s2c */
                {
                    if (!in_rrpd->msg_id && rrpd->rsp_first_frame)
                        /* we need to add this frame to the response APDU of the most recent rrpd_list entry that has already had response packets */
                        return rrpd;
                }
            }
        }  /* this is the end of the 5-tuple check */

        if (in_rrpd->c2s)
            in_rrpd->req_search_total++;
        else
            in_rrpd->rsp_search_total++;
    } /* end of the for loop */

    return NULL;
}

static RRPD *find_latest_rrpd_dns(RRPD *in_rrpd)
{
    RRPD *rrpd;
    wmem_list_frame_t* i;

    for (i = wmem_list_tail(rrpd_list); i != NULL; i = wmem_list_frame_prev(i))
    {
        rrpd = (RRPD*)wmem_list_frame_data(i);

        if (rrpd->calculation != RTE_CALC_DNS)
            continue;

        /* if the input 5-tuple doesn't match the rrpd_list_entry 5-tuple -> go find the next list entry */
        if (rrpd->ip_proto == in_rrpd->ip_proto && rrpd->stream_no == in_rrpd->stream_no)
        {
            if (rrpd->session_id == in_rrpd->session_id && rrpd->msg_id == in_rrpd->msg_id)
            {
                if (in_rrpd->c2s && rrpd->rsp_first_frame)
                    return NULL;  /* this is new */
                else
                    return rrpd;
            }
        }  /* this is the end of the 5-tuple check */

        if (in_rrpd->c2s)
            in_rrpd->req_search_total++;
        else
            in_rrpd->rsp_search_total++;
    } /* this is the end of the for loop */

    return NULL;
}

static RRPD *find_latest_rrpd_gtcp(RRPD *in_rrpd)
{
    RRPD *rrpd;
    wmem_list_frame_t* i;

    for (i = wmem_list_tail(rrpd_list); i != NULL; i = wmem_list_frame_prev(i))
    {
        rrpd = (RRPD*)wmem_list_frame_data(i);

        if (rrpd->calculation != RTE_CALC_GTCP && rrpd->calculation != RTE_CALC_SYN)
            continue;

        /* if the input 5-tuple doesn't match the rrpd_list_entry 5-tuple -> go find the next list entry */
        if (rrpd->ip_proto == in_rrpd->ip_proto && rrpd->stream_no == in_rrpd->stream_no)
        {
            if (in_rrpd->c2s && rrpd->rsp_first_frame)
                return NULL;  /* this is new */
            else
                return rrpd;
        }  /* this is the end of the 5-tuple check */

        if (in_rrpd->c2s)
            in_rrpd->req_search_total++;
        else
            in_rrpd->rsp_search_total++;
    } /* this is the end of the for loop */

    return NULL;
}

static RRPD *find_latest_rrpd_gudp(RRPD *in_rrpd)
{
    RRPD *rrpd;
    wmem_list_frame_t* i;

    for (i = wmem_list_tail(rrpd_list); i != NULL; i = wmem_list_frame_prev(i))
    {
        rrpd = (RRPD*)wmem_list_frame_data(i);

        if (rrpd->calculation != RTE_CALC_GUDP)
            continue;

        /* if the input 5-tuple doesn't match the rrpd_list_entry 5-tuple -> go find the next list entry */
        if (rrpd->ip_proto == in_rrpd->ip_proto && rrpd->stream_no == in_rrpd->stream_no)
        {
            if (in_rrpd->c2s && rrpd->rsp_first_frame)
                return NULL;  /* this is new */
            else
                return rrpd;
        }  /* this is the end of the 5-tuple check */

        if (in_rrpd->c2s)
            in_rrpd->req_search_total++;
        else
            in_rrpd->rsp_search_total++;
    } /* this is the end of the for loop */

    return NULL;
}

static RRPD *find_latest_rrpd_smb2(RRPD *in_rrpd)
{
    RRPD *rrpd;
    wmem_list_frame_t* i;

    for (i = wmem_list_tail(rrpd_list); i != NULL; i = wmem_list_frame_prev(i))
    {
        rrpd = (RRPD*)wmem_list_frame_data(i);

        if (rrpd->calculation != RTE_CALC_SMB2 && rrpd->calculation != RTE_CALC_SYN)
            continue;

        /* if the input 5-tuple doesn't match the rrpd_list_entry 5-tuple -> go find the next list entry */
        if (rrpd->ip_proto == in_rrpd->ip_proto && rrpd->stream_no == in_rrpd->stream_no)
        {
            /* if we can match on session_id and msg_id must be a retransmission of the last request packet or the response */
            /* this logic works whether or not we are using reassembly */
            if (rrpd->session_id == in_rrpd->session_id && rrpd->msg_id == in_rrpd->msg_id)
                return rrpd;

            /* If this is a retransmission, we assume it relates to this rrpd_list entry.
            This is a bit of a kludge and not ideal but a compromise.*/
            /* ToDo: look at using TCP sequence number to allocate a retransmission to the correct APDU */
            if (in_rrpd->is_retrans)
                return rrpd;

            if (preferences.reassembly)
            {
                if (in_rrpd->c2s)
                {
                    /* if the input rrpd is for c2s and the one we have found already has response information, then the
                    in_rrpd represents a new RR Pair. */
                    if (rrpd->rsp_first_frame)
                        return NULL;

                    /* If the current rrpd_list entry doesn't have a msg_id then we assume we are mid Request APDU and so we have a match. */
                    if (!rrpd->msg_id)
                        return rrpd;
                }
                else  /* The in_rrpd relates to a packet going s2c */
                {
                    /* When reassembly is enabled, multi-packet response information is actually migrated from the temp_rsp_rrpd_list
                    to the rrpd_list and so we won't come through here. */
                    ;
                }
            }
            else /* we are not using reassembly */
            {
                if (in_rrpd->c2s)
                {
                    if (in_rrpd->msg_id)
                        /* if we have a message id this is a new Request APDU */
                        return NULL;
                    else  /* No msg_id */
                    {
                        return rrpd;  /* add this packet to the matching stream */
                    }
                }
                else  /* this packet is going s2c */
                {
                    if (!in_rrpd->msg_id && rrpd->rsp_first_frame)
                        /* we need to add this frame to the response APDU of the most recent rrpd_list entry that has already had response packets */
                        return rrpd;
                }
            }
        }  /* this is the end of the 5-tuple check */

        if (in_rrpd->c2s)
            in_rrpd->req_search_total++;
        else
            in_rrpd->rsp_search_total++;
    } /* end of the for loop */

    return NULL;
}

static RRPD *find_latest_rrpd_syn(RRPD *in_rrpd)
{
    RRPD *rrpd;
    wmem_list_frame_t* i;

    for (i = wmem_list_tail(rrpd_list); i != NULL; i = wmem_list_frame_prev(i))
    {
        rrpd = (RRPD*)wmem_list_frame_data(i);

        if (rrpd->calculation != RTE_CALC_SYN)
            continue;

        /* if the input 5-tuple doesn't match the rrpd_list_entry 5-tuple -> go find the next list entry */
        if (rrpd->ip_proto == in_rrpd->ip_proto && rrpd->stream_no == in_rrpd->stream_no)
        {
            return rrpd;
        }  /* this is the end of the 5-tuple check */

        if (in_rrpd->c2s)
            in_rrpd->req_search_total++;
        else
            in_rrpd->rsp_search_total++;
    } /* this is the end of the for loop */

    return NULL;
}

static RRPD *find_latest_rrpd(RRPD *in_rrpd)
{
    /* Optimisation Code */
    if (in_rrpd->ip_proto == IP_PROTO_TCP && (int)in_rrpd->stream_no > highest_tcp_stream_no)
    {
        highest_tcp_stream_no = in_rrpd->stream_no;
        return NULL;
    }
    else if (in_rrpd->ip_proto == IP_PROTO_UDP && (int)in_rrpd->stream_no > highest_udp_stream_no)
    {
        highest_udp_stream_no = in_rrpd->stream_no;
        return NULL;
    }
    /* End of Optimisation Code */

    switch (in_rrpd->calculation)
    {
    case RTE_CALC_DCERPC:
        return find_latest_rrpd_dcerpc(in_rrpd);

    case RTE_CALC_DNS:
        return find_latest_rrpd_dns(in_rrpd);

    case RTE_CALC_GTCP:
        return find_latest_rrpd_gtcp(in_rrpd);

    case RTE_CALC_GUDP:
        return find_latest_rrpd_gudp(in_rrpd);

    case RTE_CALC_SMB2:
        return find_latest_rrpd_smb2(in_rrpd);

    case RTE_CALC_SYN:
        return find_latest_rrpd_syn(in_rrpd);
    }

    return NULL;
}

static void update_rrpd_list_entry(RRPD *match, RRPD *in_rrpd)
{
    null_output_rrpd_entries(match);

    if (preferences.debug_enabled)
    {
        match->req_search_total += in_rrpd->req_search_total;
        match->rsp_search_total += in_rrpd->rsp_search_total;
    }

    if (in_rrpd->c2s)
    {
        match->req_last_frame = in_rrpd->req_last_frame;
        match->req_last_rtime = in_rrpd->req_last_rtime;
        if (in_rrpd->msg_id)
        {
            match->session_id = in_rrpd->session_id;
            match->msg_id = in_rrpd->msg_id;
        }
    }
    else
    {
        if (!match->rsp_first_frame)
        {
            match->rsp_first_frame = in_rrpd->rsp_first_frame;
            match->rsp_first_rtime = in_rrpd->rsp_first_rtime;
        }
        match->rsp_last_frame = in_rrpd->rsp_last_frame;
        match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
    }

    update_output_rrpd(match);
}

/*
    This function processes a sub-packet that is going from client-to-service.
 */
static void update_rrpd_list_entry_req(RRPD *in_rrpd)
{
    RRPD *match;

    match = find_latest_rrpd(in_rrpd);

    if (match != NULL)
        update_rrpd_list_entry(match, in_rrpd);
    else
        append_to_rrpd_list(in_rrpd);
}

/*
    This function inserts an RRPD into the temp_rsp_rrpd_list.  If this is
    successful return a pointer to the entry, else return NULL.
 */
static RRPD* insert_into_temp_rsp_rrpd_list(RRPD *in_rrpd)
{
    RRPD *rrpd = (RRPD*)wmem_memdup(wmem_file_scope(), in_rrpd, sizeof(RRPD));

    wmem_list_append(temp_rsp_rrpd_list, rrpd);

    return rrpd;
}

static RRPD* find_temp_rsp_rrpd(RRPD *in_rrpd)
{
    wmem_list_frame_t *i;
    RRPD* rrpd;

    for (i = wmem_list_head(temp_rsp_rrpd_list); i; i = wmem_list_frame_next(i))
    {
        rrpd = (RRPD*)wmem_list_frame_data(i);
        if (rrpd->ip_proto == in_rrpd->ip_proto && rrpd->stream_no == in_rrpd->stream_no)
            return rrpd;
    }

    return NULL;
}

static void update_temp_rsp_rrpd(RRPD *temp_list, RRPD *in_rrpd)
{
    temp_list->rsp_last_frame = in_rrpd->rsp_last_frame;
    temp_list->rsp_last_rtime = in_rrpd->rsp_last_rtime;
}

/* This function migrates an entry from the temp_rsp_rrpd_list to the main rrpd_list. */
static void migrate_temp_rsp_rrpd(RRPD *main_list, RRPD *temp_list)
{
    update_rrpd_list_entry(main_list, temp_list);

    wmem_list_remove(temp_rsp_rrpd_list, temp_list);
}

static void update_rrpd_list_entry_rsp(RRPD *in_rrpd)
{
    RRPD *match, *temp_list;

    if (in_rrpd->decode_based)
    {
        if (preferences.reassembly)
        {
            if (in_rrpd->msg_id)
            {
                /* If we have a msg_id in the input RRPD we must have header information. */
                temp_list = find_temp_rsp_rrpd(in_rrpd);

                if (temp_list != NULL)
                {
                    update_temp_rsp_rrpd(temp_list, in_rrpd);

                    /* Migrate the temp_rsp_rrpd_list entry to the main rrpd_list */
                    match = find_latest_rrpd(in_rrpd);
                    if (match != NULL)
                        migrate_temp_rsp_rrpd(match, temp_list);
                }
                else
                {
                    match = find_latest_rrpd(in_rrpd);
                    /* There isn't an entry in the temp_rsp_rrpd_list so update the master rrpd_list entry */
                    if (match != NULL)
                        update_rrpd_list_entry(match, in_rrpd);
                }
            }
            else
            {
                /* Update an existing entry to the temp_rsp_rrpd_list or add a new one. */
                temp_list = find_temp_rsp_rrpd(in_rrpd);

                if (temp_list != NULL)
                    update_temp_rsp_rrpd(temp_list, in_rrpd);
                else
                {
                    /* If this is a retransmission we need to add it to the last completed rrpd_list entry for this stream */
                    if (in_rrpd->is_retrans)
                    {
                        match = find_latest_rrpd(in_rrpd);

                        if (match != NULL)
                            update_rrpd_list_entry(match, in_rrpd);
                        else
                            insert_into_temp_rsp_rrpd_list(in_rrpd);
                    }
                    else
                        /* As it's not a retransmission, just create a new entry on the temp list */
                        insert_into_temp_rsp_rrpd_list(in_rrpd);
                }
            }
        }
        else
        {
            /* Reassembly isn't set and so just go ahead and use the list function */
            match = find_latest_rrpd(in_rrpd);
            if (match != NULL)
                update_rrpd_list_entry(match, in_rrpd);
        }
    }
    else
    {
        /* if this isn't decode_based then just go ahead and update the RTE data */
        match = find_latest_rrpd(in_rrpd);
        if (match != NULL)
            update_rrpd_list_entry(match, in_rrpd);
    }

    return;
}


/*
    This function updates the RTE data of an RRPD on the rrpd_list.  The
    frame_no values in the input RRPD double up as a mask.  If the frame_no
    is > 0 then the frame_no value and rtime values are updated.  If the
    frame_no is 0 then that particular frame_no and rtime value is not updated.
 */
static void update_rrpd_rte_data(RRPD *in_rrpd)
{
    if (in_rrpd->c2s)
        update_rrpd_list_entry_req(in_rrpd);
    else
        update_rrpd_list_entry_rsp(in_rrpd);
}

bool is_dcerpc_context_zero(uint32_t pkt_type)
{
    return (wmem_map_lookup(dcerpc_context_zero, GUINT_TO_POINTER(pkt_type)) != NULL);
}

bool is_dcerpc_req_pkt_type(uint32_t pkt_type)
{
    return (wmem_map_lookup(dcerpc_req_pkt_type, GUINT_TO_POINTER(pkt_type)) != NULL);
}

static bool is_dcerpc_stream(uint32_t stream_no)
{
    return (wmem_map_lookup(dcerpc_streams, GUINT_TO_POINTER(stream_no)) != NULL);
}

/*
    This function initialises the global variables and populates the
    [tcp|udp]_svc_ports tables with information from the preference settings
 */
static void init_globals(void)
{
    if (!proto_is_protocol_enabled(find_protocol_by_id(proto_transum)))
        return;

    highest_tcp_stream_no = -1;
    highest_udp_stream_no = -1;

    /* Create and initialise some dynamic memory areas */
    tcp_stream_exceptions = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    detected_tcp_svc = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    rrpd_list = wmem_list_new(wmem_file_scope());
    temp_rsp_rrpd_list = wmem_list_new(wmem_file_scope());

    /* Indicate what fields we're interested in. */
    GArray *wanted_fields = g_array_sized_new(false, false, (unsigned)sizeof(int), HF_INTEREST_END_OF_LIST);
    for (int i = 0; i < HF_INTEREST_END_OF_LIST; i++)
    {
        if (hf_of_interest[i].hf != -1)
            g_array_append_val(wanted_fields, hf_of_interest[i].hf);
        else
            ws_warning("TRANSUM: unknown field %s", hf_of_interest[i].proto_name);
    }
    set_postdissector_wanted_hfids(transum_handle, wanted_fields);

    preferences.tcp_svc_ports = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    preferences.udp_svc_ports = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

    /* use the range values to populate the tcp_svc_ports list*/
    for (unsigned i = 0; i < tcp_svc_port_range_values->nranges; i++)
    {
        for (uint32_t j = tcp_svc_port_range_values->ranges[i].low; j <= tcp_svc_port_range_values->ranges[i].high; j++)
        {
            wmem_map_insert(preferences.tcp_svc_ports, GUINT_TO_POINTER(j), GUINT_TO_POINTER(RTE_CALC_GTCP));
        }
    }

    /* use the range values to populate the udp_svc_ports list*/
    for (unsigned i = 0; i < udp_svc_port_range_values->nranges; i++)
    {
        for (uint32_t j = udp_svc_port_range_values->ranges[i].low; j <= udp_svc_port_range_values->ranges[i].high; j++)
        {
            wmem_map_insert(preferences.udp_svc_ports, GUINT_TO_POINTER(j), GUINT_TO_POINTER(RTE_CALC_GUDP));
        }
    }

    /* create arrays to hold some DCE-RPC values */
    dcerpc_context_zero = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    dcerpc_req_pkt_type = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    dcerpc_streams      = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    init_dcerpc_data();

    wmem_map_insert(preferences.tcp_svc_ports, GUINT_TO_POINTER(445), GUINT_TO_POINTER(RTE_CALC_SMB2));
    wmem_map_insert(preferences.udp_svc_ports, GUINT_TO_POINTER(53), GUINT_TO_POINTER(RTE_CALC_DNS));
}

/* Undo capture file-specific initializations. */
static void cleanup_globals(void)
{
    /* Clear the list of wanted fields as it will be reinitialized. */
    set_postdissector_wanted_hfids(transum_handle, NULL);
}

/* This function adds the RTE data to the tree.  The summary ptr is currently
   not used but will be used for summariser information once this feature has
   been ported from the Lua code. */
static void write_rte(RRPD *in_rrpd, tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, char *summary)
{
    nstime_t rte_art;
    nstime_t rte_st;
    nstime_t rte_reqspread;
    nstime_t rte_rspspread;
    proto_tree *rte_tree;
    proto_item *pi;
    wmem_strbuf_t *temp_string = wmem_strbuf_new(pinfo->pool, "");

    if (in_rrpd->req_first_frame)
    {
        pi = proto_tree_add_item(tree, proto_transum, tvb, 0, 0, ENC_NA);
        rte_tree = proto_item_add_subtree(pi, ett_transum);

        nstime_delta(&rte_reqspread, &(in_rrpd->req_last_rtime), &(in_rrpd->req_first_rtime));
        if (in_rrpd->rsp_first_frame)
        {
            /* calculate the RTE times */
            nstime_delta(&rte_art, &(in_rrpd->rsp_last_rtime), &(in_rrpd->req_first_rtime));
            nstime_delta(&rte_st, &(in_rrpd->rsp_first_rtime), &(in_rrpd->req_last_rtime));
            nstime_delta(&rte_rspspread, &(in_rrpd->rsp_last_rtime), &(in_rrpd->rsp_first_rtime));

            pi = proto_tree_add_string(rte_tree, hf_tsum_status, tvb, 0, 0, "OK");
        }
        else
        {
            pi = proto_tree_add_string(rte_tree, hf_tsum_status, tvb, 0, 0, "Response missing");
        }
        proto_item_set_generated(pi);


        pi = proto_tree_add_uint(rte_tree, hf_tsum_req_first_seg, tvb, 0, 0, in_rrpd->req_first_frame);
        proto_item_set_generated(pi);
        pi = proto_tree_add_uint(rte_tree, hf_tsum_req_last_seg, tvb, 0, 0, in_rrpd->req_last_frame);
        proto_item_set_generated(pi);

        if (in_rrpd->rsp_first_frame)
        {
            pi = proto_tree_add_uint(rte_tree, hf_tsum_rsp_first_seg, tvb, 0, 0, in_rrpd->rsp_first_frame);
            proto_item_set_generated(pi);
            pi = proto_tree_add_uint(rte_tree, hf_tsum_rsp_last_seg, tvb, 0, 0, in_rrpd->rsp_last_frame);
            proto_item_set_generated(pi);

            pi = proto_tree_add_time(rte_tree, hf_tsum_apdu_rsp_time, tvb, 0, 0, &rte_art);
            proto_item_set_generated(pi);
            pi = proto_tree_add_time(rte_tree, hf_tsum_service_time, tvb, 0, 0, &rte_st);
            proto_item_set_generated(pi);
        }

        pi = proto_tree_add_time(rte_tree, hf_tsum_req_spread, tvb, 0, 0, &rte_reqspread);
        proto_item_set_generated(pi);

        if (in_rrpd->rsp_first_frame)
        {
            pi = proto_tree_add_time(rte_tree, hf_tsum_rsp_spread, tvb, 0, 0, &rte_rspspread);
            proto_item_set_generated(pi);
        }

        if (in_rrpd->ip_proto == IP_PROTO_TCP)
            wmem_strbuf_append_printf(temp_string, "tcp.stream==%d", in_rrpd->stream_no);
        else if (in_rrpd->ip_proto == IP_PROTO_UDP)
            wmem_strbuf_append_printf(temp_string, "udp.stream==%d", in_rrpd->stream_no);

        if (in_rrpd->rsp_first_frame)
            wmem_strbuf_append_printf(temp_string, " && frame.number>=%d && frame.number<=%d", in_rrpd->req_first_frame, in_rrpd->rsp_last_frame);
        else
            wmem_strbuf_append_printf(temp_string, " && frame.number>=%d && frame.number<=%d", in_rrpd->req_first_frame, in_rrpd->req_last_frame);

        if (in_rrpd->calculation == RTE_CALC_GTCP)
            wmem_strbuf_append_printf(temp_string, " && tcp.len>0");

        pi = proto_tree_add_string(rte_tree, hf_tsum_clip_filter, tvb, 0, 0, wmem_strbuf_get_str(temp_string));
        proto_item_set_generated(pi);

        pi = proto_tree_add_string(rte_tree, hf_tsum_calculation, tvb, 0, 0, val_to_str(in_rrpd->calculation, rrdp_calculation_vals, "Unknown calculation type: %d"));
        proto_item_set_generated(pi);

        if (in_rrpd->rsp_first_frame)
        {
            if (preferences.summarisers_enabled)
            {
                if (summary)
                {
                    pi = proto_tree_add_string(tree, hf_tsum_summary, tvb, 0, 0, summary);
                    proto_item_set_generated(pi);
                }
            }
        }

        if (preferences.debug_enabled)
        {
            pi = proto_tree_add_uint(rte_tree, hf_tsum_req_search, tvb, 0, 0, in_rrpd->req_search_total);
            proto_item_set_generated(pi);
            pi = proto_tree_add_uint(rte_tree, hf_tsum_rsp_search, tvb, 0, 0, in_rrpd->rsp_search_total);
            proto_item_set_generated(pi);
        }
    }
}

/*
    This function sets initial values in the current_pkt structure and checks
    the xxx_svc_port arrays to see if they contain a match for the source or
    destination port.  This function also adds tcp_svc_ports entries when it
    discovers DCE-RPC traffic.

    Returns the number of sub-packets to be processed.
*/
static void set_proto_values(packet_info *pinfo, proto_tree *tree, PKT_INFO* pkt_info, PKT_INFO* subpackets)
{
    uint32_t field_uint[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
    size_t field_value_count;  /* How many entries are there in the extracted field array */

    pkt_info->frame_number = pinfo->fd->num;   /* easy access to frame number */
    pkt_info->relative_time = pinfo->rel_ts;

    int number_sub_pkts_of_interest = 0; /* default */

    if (pinfo->ptype == PT_TCP)
        pkt_info->rrpd.ip_proto = IP_PROTO_TCP;
    else if (pinfo->ptype == PT_UDP)
        pkt_info->rrpd.ip_proto = IP_PROTO_UDP;

    if (pkt_info->rrpd.ip_proto == IP_PROTO_TCP)
    {
        number_sub_pkts_of_interest = decode_gtcp(pinfo, tree, pkt_info);
        /* decode_gtcp may return 0 but we need to keep processing because we
        calculate RTE figures for all SYNs and also we may detect DCE-RPC later
        (even though we don't currently have an entry in the tcp_svc_ports list). */

        /* Optimisation code */
        if (pkt_info->len || pkt_info->tcp_flags_syn)
        {
            if (pkt_info->ssl_content_type == 21)  /* this is an SSL Alert */
            {
                pkt_info->pkt_of_interest = false;
                return;
            }

            if ((int)pkt_info->rrpd.stream_no > highest_tcp_stream_no && !pkt_info->rrpd.c2s)
            {
                /* first packet on the stream is s2c and so add to exception list */
                if (wmem_map_lookup(tcp_stream_exceptions, GUINT_TO_POINTER(pkt_info->rrpd.stream_no)) == NULL)
                    wmem_map_insert(tcp_stream_exceptions, GUINT_TO_POINTER(pkt_info->rrpd.stream_no), GUINT_TO_POINTER(1));
            }

            if (wmem_map_lookup(tcp_stream_exceptions, GUINT_TO_POINTER(pkt_info->rrpd.stream_no)) != NULL)
            {
                if (pkt_info->rrpd.c2s)
                    wmem_map_remove(tcp_stream_exceptions, GUINT_TO_POINTER(pkt_info->rrpd.stream_no));
                else
                    pkt_info->pkt_of_interest = false;
            }
        }
        /* End of Optimisation Code */

        if (pkt_info->tcp_retran)
        {
            /* we may not want to continue with this packet if it's a retransmission */

            /* If this is a server-side trace we need to ignore client-to-service TCP retransmissions
            the rationale being that if we saw the original in the trace the service process saw it too */
            if (pkt_info->rrpd.c2s && preferences.capture_position == CAPTURE_SERVICE)
            {
                pkt_info->pkt_of_interest = false;
                return;
            }

            /* If this is a client-side trace we need to ignore service-to-client TCP retransmissions
            the rationale being that if we saw the original in the trace the client process saw it too */
            else if (!pkt_info->rrpd.c2s && preferences.capture_position == CAPTURE_CLIENT)
            {
                pkt_info->pkt_of_interest = false;
                return;
            }
        }

        /* We are not interested in TCP Keep-Alive */
        if (pkt_info->tcp_keep_alive)
        {
            pkt_info->pkt_of_interest = false;
            return;
        }

        if (pkt_info->len == 1)
        {
            if (preferences.orphan_ka_discard && pkt_info->tcp_flags_ack && pkt_info->rrpd.c2s)
            {
                pkt_info->pkt_of_interest = false;
                return;  /* It's a KEEP-ALIVE -> stop processing this packet */
            }
        }

        /* check if SYN */
        if (pkt_info->tcp_flags_syn)
            number_sub_pkts_of_interest = decode_syn(pinfo, tree, pkt_info);

        if (pkt_info->len > 0)
        {
            /* check if SMB2 */
            if (pkt_info->dstport == 445 || pkt_info->srcport == 445)
                number_sub_pkts_of_interest = decode_smb(pinfo, tree, pkt_info, subpackets);

            else
            {
                /* check if DCE-RPC */
                /* We need to set RTE_CALC_DCERPC even when we don't have header info. */
                if (is_dcerpc_stream(pkt_info->rrpd.stream_no))
                {
                    pkt_info->rrpd.calculation = RTE_CALC_DCERPC;
                    pkt_info->rrpd.decode_based = true;
                    pkt_info->pkt_of_interest = true;
                }

                if (!extract_uint(tree, hf_of_interest[HF_INTEREST_DCERPC_VER].hf, field_uint, &field_value_count))
                {
                    if (field_value_count)
                    {
                        if (pkt_info->rrpd.calculation != RTE_CALC_DCERPC)
                            register_dcerpc_stream(pkt_info->rrpd.stream_no);

                        number_sub_pkts_of_interest = decode_dcerpc(pinfo, tree, pkt_info);
                    }
                }
            }
        }

    }
    else if (pkt_info->rrpd.ip_proto == IP_PROTO_UDP)
    {
        /* It's UDP */
        number_sub_pkts_of_interest = decode_gudp(pinfo, tree, pkt_info);

        if (pkt_info->srcport == 53 || pkt_info->dstport == 53)
            number_sub_pkts_of_interest = decode_dns(pinfo, tree, pkt_info);
    }

    /* Set appropriate RTE values in the sub-packets */
    for (int i = 0; (i < number_sub_pkts_of_interest) && (i < MAX_SUBPKTS_PER_PACKET); i++)
    {
        if (pkt_info->rrpd.c2s)
        {
            subpackets[i].rrpd.req_first_frame = pkt_info->frame_number;
            subpackets[i].rrpd.req_first_rtime = pkt_info->relative_time;
            subpackets[i].rrpd.req_last_frame = pkt_info->frame_number;
            subpackets[i].rrpd.req_last_rtime = pkt_info->relative_time;

            subpackets[i].frame_number = pkt_info->frame_number;  /* this acts as a switch later */
        }
        else
        {
            subpackets[i].rrpd.rsp_first_frame = pkt_info->frame_number;
            subpackets[i].rrpd.rsp_first_rtime = pkt_info->relative_time;
            subpackets[i].rrpd.rsp_last_frame = pkt_info->frame_number;
            subpackets[i].rrpd.rsp_last_rtime = pkt_info->relative_time;

            subpackets[i].frame_number = pkt_info->frame_number;  /* this acts as a switch later */
        }
    }
}


/*
 * This function is called for each packet
 * Wireshark scans all the packets once and then once again as they are displayed
 * The pinfo.visited boolean is set to false; on the first scan
*/
static int dissect_transum(tvbuff_t *buffer, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    /* if (there is RTE info associated with this packet we need to output it */
    if (PINFO_FD_VISITED(pinfo))
    {
        RRPD *rrpd = (RRPD*)wmem_map_lookup(output_rrpd, GUINT_TO_POINTER(pinfo->num));

        if (rrpd)
        {
            if (tree)
            {
                /* Add the RTE data to the protocol decode tree if we output_flag is set */
                write_rte(rrpd, buffer, pinfo, tree, NULL);
            }
        }
    }
    else
    {
        PKT_INFO *sub_packet = wmem_alloc0_array(pinfo->pool, PKT_INFO, MAX_SUBPKTS_PER_PACKET);

        set_proto_values(pinfo, tree, &sub_packet[0], sub_packet);

        if (sub_packet[0].pkt_of_interest)
        {
            /* Loop to process each sub_packet and update the related RTE data */
            for (int i = 0; i < MAX_SUBPKTS_PER_PACKET; i++)
            {
                if (!sub_packet[i].frame_number)
                    break;

                update_rrpd_rte_data(&(sub_packet[i].rrpd));
            }
        }
    }

    return 0;
}

void
proto_register_transum(void)
{
    module_t *transum_module;

    static hf_register_info hf[] = {
        { &hf_tsum_status,
        { "RTE Status", "transum.status",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Indication of completeness of the RTE information", HFILL } },
#if 0
        { &hf_tsum_time_units,
        { "RTE Time Units", "transum.time_units",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Time units used (s, ms or us) for the RTE values", HFILL }
        },
#endif
        { &hf_tsum_req_first_seg,
        { "Req First Seg", "transum.firstreq",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "First Segment of an APDU Request", HFILL }
        },

        { &hf_tsum_req_last_seg,
        { "Req Last Seg", "transum.lastreq",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "Last Segment of an APDU Request", HFILL }
        },

        { &hf_tsum_rsp_first_seg,
        { "Rsp First Seg", "transum.firstrsp",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "First Segment of an APDU Response", HFILL }
        },

        { &hf_tsum_rsp_last_seg,
        { "Rsp Last Seg", "transum.lastrsp",
        FT_FRAMENUM, BASE_NONE, NULL, 0x0,
        "Last Segment of an APDU Response", HFILL }
        },

        { &hf_tsum_apdu_rsp_time,
        { "APDU Rsp Time", "transum.art",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "RTE APDU Response Time", HFILL }
        },

        { &hf_tsum_service_time,
        { "Service Time", "transum.st",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "RTE Service Time", HFILL }
        },

        { &hf_tsum_req_spread,
        { "Req Spread", "transum.reqspread",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "RTE Request Spread", HFILL }
        },

        { &hf_tsum_rsp_spread,
        { "Rsp Spread", "transum.rspspread",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        "RTE Response Spread", HFILL }
        },

        { &hf_tsum_clip_filter,
        { "Trace clip filter", "transum.clip_filter",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Filter expression to select the APDU Request-Response pair", HFILL }
        },

        { &hf_tsum_calculation,
        { "Calculation", "transum.calculation",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Basis of the RTE calculation", HFILL }
        },

        { &hf_tsum_summary,
        { "Summary", "transum.summary",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Summarizer information", HFILL }
        },

        { &hf_tsum_req_search,
        { "Req Search Count", "transum.req_search",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "rrpd_list search total for the request packets", HFILL }
        },

        { &hf_tsum_rsp_search,
        { "Rsp Search Counts", "transum.rsp_search",
        FT_UINT32, BASE_DEC, NULL, 0x0,
        "rrpd_list search total for the response packets", HFILL }
        }

    };

    /* Setup protocol subtree array */
    static int *ett[] = {
        &ett_transum,
        &ett_transum_header,
        &ett_transum_data
    };

    proto_transum = proto_register_protocol("TRANSUM RTE Data", "TRANSUM", "transum");

    /* Due to performance concerns of the dissector, it's disabled by default */
    proto_disable_by_default(proto_transum);


    /* Set User Preferences defaults */
    preferences.capture_position = TRACE_CAP_CLIENT;
    preferences.reassembly = true;

    range_convert_str(wmem_epan_scope(), &tcp_svc_port_range_values, "25, 80, 443, 1433", MAX_TCP_PORT);
    range_convert_str(wmem_epan_scope(), &udp_svc_port_range_values, "137-139", MAX_UDP_PORT);

    preferences.orphan_ka_discard = false;
    preferences.time_multiplier = RTE_TIME_SEC;
    preferences.rte_on_first_req = false;
    preferences.rte_on_last_req = true;
    preferences.rte_on_first_rsp = false;
    preferences.rte_on_last_rsp = false;

    preferences.debug_enabled = false;

    /* no start registering stuff */
    proto_register_field_array(proto_transum, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    transum_module = prefs_register_protocol(proto_transum, NULL);  /* ToDo: We need to rethink the NULL pointer so that a preference change causes a rescan */

    /* Register the preferences */
    prefs_register_obsolete_preference(transum_module, "tsumenabled");

    prefs_register_enum_preference(transum_module,
        "capture_position",
        "Capture position",
        "Position of the capture unit that produced this trace.  This setting affects the way TRANSUM handles TCP Retransmissions.  See the manual for details.",
        &preferences.capture_position,
        capture_position_vals,
        false);

    prefs_register_bool_preference(transum_module,
        "reassembly",
        "Subdissector reassembly enabled",
        "Set this to match to the TCP subdissector reassembly setting",
        &preferences.reassembly);

    prefs_register_range_preference(transum_module,
        "tcp_port_ranges",
        "Output RTE data for these TCP service ports",
        "Add and remove ports numbers separated by commas\nRanges are supported e.g. 25,80,2000-3000,5432",
        &tcp_svc_port_range_values,
        65536);

    prefs_register_range_preference(transum_module,
        "udp_port_ranges",
        "Output RTE data for these UDP service ports",
        "Add and remove ports numbers separated by commas\nRanges are supported e.g. 123,137-139,520-521,2049",
        &udp_svc_port_range_values,
        65536);

    prefs_register_bool_preference(transum_module,
        "orphan_ka_discard",
        "Discard orphaned TCP Keep-Alives",
        "Set this to discard any packet in the direction client to service,\nwith a 1-byte payload of 0x00 and the ACK flag set",
        &preferences.orphan_ka_discard);

    /* removed from this release
    prefs_register_enum_preference(transum_module,
    "time_multiplier",
    "Time units for RTE values",
    "Unit of time used for APDU Response Time, Service Time and Spread Time values.",
    &preferences.time_multiplier,
    time_multiplier_vals,
    false);
    */

    prefs_register_bool_preference(transum_module,
        "rte_on_first_req",
        "Add RTE data to the first request segment",
        "RTE data will be added to the first request packet",
        &preferences.rte_on_first_req);

    prefs_register_bool_preference(transum_module,
        "rte_on_last_req",
        "Add RTE data to the last request segment",
        "RTE data will be added to the last request packet",
        &preferences.rte_on_last_req);

    prefs_register_bool_preference(transum_module,
        "rte_on_first_rsp",
        "Add RTE data to the first response segment",
        "RTE data will be added to the first response packet",
        &preferences.rte_on_first_rsp);

    prefs_register_bool_preference(transum_module,
        "rte_on_last_rsp",
        "Add RTE data to the last response segment",
        "RTE data will be added to the last response packet",
        &preferences.rte_on_last_rsp);

    prefs_register_bool_preference(transum_module,
        "debug_enabled",
        "Enable debug info",
        "Set this only to troubleshoot problems",
        &preferences.debug_enabled);

    transum_handle = register_dissector("transum", dissect_transum, proto_transum);

    register_init_routine(init_globals);
    register_cleanup_routine(cleanup_globals);

    register_postdissector(transum_handle);

    output_rrpd = wmem_map_new_autoreset(wmem_epan_scope(), wmem_file_scope(), g_direct_hash, g_direct_equal);
}

void proto_reg_handoff_transum(void)
{
    /* Get the field id for each field we will need */
    for (int i = 0; i < HF_INTEREST_END_OF_LIST; i++)
    {
        hf_of_interest[i].hf = proto_registrar_get_id_byname(hf_of_interest[i].proto_name);
    }
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
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
