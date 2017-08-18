/* packet-transum.c
* Routines for the TRANSUM response time analyzer post-dissector
* By Paul Offord <paul.offord@advance7.com>
* Copyright 2016 Advance Seven Limited
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
*/

/* ToDo: Test handling of multiple SMB2 messages within a packet */
/* ToDo: Rework the Summarizer code (future release) */

#include "config.h"

#include <epan/proto.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include "packet-transum.h"
#include "preferences.h"
#include "extractors.h"
#include "decoders.h"

void proto_register_transum(void);
void proto_reg_handoff_transum(void);

static dissector_handle_t transum_handle;

#define CAPTURE_CLIENT 0
#define CAPTURE_INTERMEDIATE 1
#define CAPTURE_SERVICE 2

#define RTE_TIME_SEC  1
#define RTE_TIME_MSEC 1000
#define RTE_TIME_USEC 1000000

#define CONTINUE_PROCESSING TRUE

#define RRPD_REQUIRES_SUFFIX TRUE
#define RRPD_NEEDS_NO_SUFFIX FALSE;

#define SMB2_CMD_SESSION_SETUP 1

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

/*
This array contains calls and returns that have no TRUE context_id
This is needed to overcome an apparent bug in Wireshark where
the field name of context id in parameters is the same as context id
in a message header
*/
static wmem_map_t *dcerpc_context_zero;

#if 0
/* rrpd-related globals */
guint32 rrpd_suffix = 0;
#endif

/*
    The rrpd_list holds information about all of the APDU Request-Response Pairs seen in the trace.
 */
static wmem_list_t *rrpd_list = NULL;

/*
    output_rrpd is a hash of pointers to RRPDs on the rrpd_list.  The index is the frame number.  This hash is
    used during Wireshark's second scan.  As each packet is processed, TRANSUM uses the packet's frame number to index into
    this hash to determine if we have RTE data for this particular packet, and if so the write_rte function is called.
 */
static wmem_map_t *output_rrpd;

/*
    The temp_rsp_rrpd_list holds RRPDs for APDUs where we have not yet seen the header information and so we can't
    fully qualify the identification of the RRPD (the identification being ip_proto:stream_no:session_id:msg_id:suffix).
    This only occurs when a) we are using one of the decode_based calculations (such as SMB2), and b) when we have
    TCP Reassembly enabled.  Once we receive a header packet for an APDU we migrate the entry from this array to the
    main rrpd_list.
 */
static wmem_list_t *temp_rsp_rrpd_list = NULL;  /* Reuse these for speed and efficient memory use - issue a warning if we run out */

/*
 * GArray of the hfids of all fields we're interested in.
 */
GArray *wanted_fields;

static gint ett_transum = -1;
static gint ett_transum_header = -1;
static gint ett_transum_data = -1;

static int proto_transum = -1;

static int hf_tsum_status = -1;
//static int hf_tsum_time_units = -1;
static int hf_tsum_req_first_seg = -1;
static int hf_tsum_req_last_seg = -1;
static int hf_tsum_rsp_first_seg = -1;
static int hf_tsum_rsp_last_seg = -1;
static int hf_tsum_apdu_rsp_time = -1;
static int hf_tsum_service_time = -1;
static int hf_tsum_req_spread = -1;
static int hf_tsum_rsp_spread = -1;
static int hf_tsum_clip_filter = -1;
static int hf_tsum_calculation = -1;
static int hf_tsum_summary = -1;

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

void add_detected_tcp_svc(guint16 port)
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

    if (preferences.reassembly)
    {
        if (next_rrpd->msg_id)
            next_rrpd->state = RRPD_STATE_3;
        else
            next_rrpd->state = RRPD_STATE_1;
    }
    else
    {
        if (next_rrpd->msg_id)
            next_rrpd->state = RRPD_STATE_4;
        else
            next_rrpd->state = RRPD_STATE_2;
    }

    update_output_rrpd(next_rrpd);

    wmem_list_append(rrpd_list, next_rrpd);

    return next_rrpd;
}

/*
This function finds the latest entry in the rrpd_list that matches the
ip_proto, stream_no, session_id, msg_id and suffix values.

An input state value of 0 means that we don't care about state.

Returns the rrpd_list index value of the match or -1 if no match is found.
*/
static RRPD *find_latest_rrpd(RRPD *in_rrpd, int state)
{
    RRPD *rrpd_index = NULL, *rrpd;
    wmem_list_frame_t* i;

    for (i = wmem_list_tail(rrpd_list); i != NULL; i = wmem_list_frame_prev(i))
    {
        rrpd = (RRPD*)wmem_list_frame_data(i);
        if (rrpd->ip_proto == in_rrpd->ip_proto && rrpd->stream_no == in_rrpd->stream_no)
        {
            if (in_rrpd->decode_based)
            {
                /* If this is decode-based and we are checking for entries in RRPD_STATE_1 we need to match on ip_proto and stream_no alone. */
                if (state == RRPD_STATE_1)
                {
                    if (rrpd->session_id == 0 && rrpd->msg_id == 0 && rrpd->suffix == 1)
                    {
                        rrpd_index = rrpd;
                        break;
                    }
                }

                /* if this stream is decode_based we need to take into account the session_id, msg_id and suffix */
                if (rrpd->session_id == in_rrpd->session_id && rrpd->msg_id == in_rrpd->msg_id && rrpd->suffix == in_rrpd->suffix)
                {
                    if (state == RRPD_STATE_DONT_CARE || rrpd->state == state)
                    {
                        rrpd_index = rrpd;
                        break;
                    }
                }
            }
            else
            {
                /* if this stream is not decode_based we don't need to take into account the session_id, msg_id and suffix */
                if (state == RRPD_STATE_DONT_CARE || rrpd->state == state)
                {
                    rrpd_index = rrpd;
                    break;
                }
            }
        }
    }
    return rrpd_index;
}

static void update_rrpd_list_entry(RRPD *match, RRPD *in_rrpd)
{
    null_output_rrpd_entries(match);

    switch (match->state)
    {
    case RRPD_STATE_1:
        if (in_rrpd->c2s)
        {
            match->req_last_frame = in_rrpd->req_last_frame;
            match->req_last_rtime = in_rrpd->req_last_rtime;
            if (in_rrpd->msg_id)
            {
                match->session_id = in_rrpd->session_id;
                match->msg_id = in_rrpd->msg_id;
                match->suffix = in_rrpd->suffix;
                match->state = RRPD_STATE_3;
            }
        }
        else
        {
            match->rsp_first_frame = in_rrpd->rsp_first_frame;
            match->rsp_first_rtime = in_rrpd->rsp_first_rtime;
            match->rsp_last_frame = in_rrpd->rsp_last_frame;
            match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                match->state = RRPD_STATE_7;
            else
                match->state = RRPD_STATE_5;
        }
        break;

    case RRPD_STATE_2:
        if (in_rrpd->c2s)
        {
            match->req_last_frame = in_rrpd->req_last_frame;
            match->req_last_rtime = in_rrpd->req_last_rtime;
            if (in_rrpd->msg_id)
            {
                match->session_id = in_rrpd->session_id;
                match->msg_id = in_rrpd->msg_id;
                match->suffix = in_rrpd->suffix;
                match->state = RRPD_STATE_4;
            }
        }
        else
        {
            match->rsp_first_frame = in_rrpd->rsp_first_frame;
            match->rsp_first_rtime = in_rrpd->rsp_first_rtime;
            match->rsp_last_frame = in_rrpd->rsp_last_frame;
            match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                match->state = RRPD_STATE_8;
            else
                match->state = RRPD_STATE_6;
        }
        break;

    case RRPD_STATE_3:
        if (in_rrpd->c2s)
        {
            match->req_last_frame = in_rrpd->req_last_frame;
            match->req_last_rtime = in_rrpd->req_last_rtime;
            if (in_rrpd->msg_id)
            {
                match->session_id = in_rrpd->session_id;
                match->msg_id = in_rrpd->msg_id;
                match->suffix = in_rrpd->suffix;
                match->state = RRPD_STATE_3;
            }
        }
        else
        {
            match->rsp_first_frame = in_rrpd->rsp_first_frame;
            match->rsp_first_rtime = in_rrpd->rsp_first_rtime;
            match->rsp_last_frame = in_rrpd->rsp_last_frame;
            match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                match->state = RRPD_STATE_7;
            else
                match->state = RRPD_STATE_5;
        }
        break;

    case RRPD_STATE_4:
        if (in_rrpd->c2s)
        {
            match->req_last_frame = in_rrpd->req_last_frame;
            match->req_last_rtime = in_rrpd->req_last_rtime;
            if (in_rrpd->msg_id)
            {
                match->session_id = in_rrpd->session_id;
                match->msg_id = in_rrpd->msg_id;
                match->suffix = in_rrpd->suffix;
                match->state = RRPD_STATE_4;
            }
        }
        else
        {
            match->rsp_first_frame = in_rrpd->rsp_first_frame;
            match->rsp_first_rtime = in_rrpd->rsp_first_rtime;
            match->rsp_last_frame = in_rrpd->rsp_last_frame;
            match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                match->state = RRPD_STATE_8;
            else
                match->state = RRPD_STATE_6;
        }
        break;

    case RRPD_STATE_5:
        if (in_rrpd->c2s)
        {
            /*  we've change direction */
            ;
        }
        else
        {
            match->rsp_last_frame = in_rrpd->rsp_last_frame;
            match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                match->state = RRPD_STATE_7;
            else
                match->state = RRPD_STATE_5;
        }
        break;

    case RRPD_STATE_6:
        if (in_rrpd->c2s)
        {
            /*  we've change direction */
            ;
        }
        else
        {
            match->rsp_last_frame = in_rrpd->rsp_last_frame;
            match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                match->state = RRPD_STATE_8;
            else
                match->state = RRPD_STATE_6;
        }
        break;

    case RRPD_STATE_7:
        if (in_rrpd->c2s)
        {
            /*  we've change direction */
            ;
        }
        else
        {
            match->rsp_last_frame = in_rrpd->rsp_last_frame;
            match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
        }
        break;

    case RRPD_STATE_8:
        if (in_rrpd->c2s)
        {
            /*  we've change direction */
            ;
        }
        else
        {
            match->rsp_last_frame = in_rrpd->rsp_last_frame;
            match->rsp_last_rtime = in_rrpd->rsp_last_rtime;
        }
        break;
    }

    update_output_rrpd(match);
}

/*
    This function processes a sub-packet that is going from client-to-service.
 */
static void update_rrpd_list_entry_req(RRPD *in_rrpd)
{
    RRPD *match;

    if (in_rrpd->decode_based)
    {
        while (TRUE)
        {
            match = find_latest_rrpd(in_rrpd, RRPD_STATE_1);
            if (match != NULL)  /* Check to cover TCP Reassembly enabled */
            {
                update_rrpd_list_entry(match, in_rrpd);
                break;
            }

            match = find_latest_rrpd(in_rrpd, RRPD_STATE_4);
            if (match != NULL)
            {
                update_rrpd_list_entry(match, in_rrpd);
                break;
            }

            /* No entries and so add one */
            append_to_rrpd_list(in_rrpd);
            break;
        }
    }
    else
    {
        /*
        This is not a decode_based calculation and so a change from s2c to c2s
        means that this packets starts of a new APDU RR pair.
        */
        match = find_latest_rrpd(in_rrpd, RRPD_STATE_DONT_CARE);
        if (match != NULL)
        {
            if (match->state > RRPD_STATE_4 && in_rrpd->c2s)
            {
                append_to_rrpd_list(in_rrpd);
            }
            else
                /* no change of direction so just update the RTE data */
                update_rrpd_list_entry(match, in_rrpd);
        }
        else
        {
            append_to_rrpd_list(in_rrpd);
        }
    }
}

/*
    This function inserts an RRPD into the temp_rsp_rrpd_list.  If this is
    successful return the index of the entry.  If there is no space return -1.
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

    /* Update the state to 7 or 8 based on reassembly */
    if (preferences.reassembly)
        main_list->state = RRPD_STATE_7;
    else
        main_list->state = RRPD_STATE_8;
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
                    match = find_latest_rrpd(in_rrpd, RRPD_STATE_3);
                    if (match != NULL)
                        migrate_temp_rsp_rrpd(match, temp_list);
                }
                else
                {
                    match = find_latest_rrpd(in_rrpd, RRPD_STATE_3);
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
                    insert_into_temp_rsp_rrpd_list(in_rrpd);
            }
        }
        else
        {
            /* Reassembly isn't set and so just go ahead and use the list function */
            match = find_latest_rrpd(in_rrpd, RRPD_STATE_8);
            if (match != NULL)
                update_rrpd_list_entry(match, in_rrpd);
        }
    }
    else
    {
        /* if this isn't decode_based then just go ahead and update the RTE data */
        match = find_latest_rrpd(in_rrpd, RRPD_STATE_DONT_CARE);
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

#if 0
void set_pkt_rrpd(PKT_INFO *current_pkt, guint8 ip_proto, guint32 stream_no, guint64 session_id, guint64 msg_id, gboolean requires_suffix)
{
    current_pkt->rrpd.ip_proto = ip_proto;
    current_pkt->rrpd.stream_no = stream_no;
    current_pkt->rrpd.session_id = session_id;
    current_pkt->rrpd.msg_id = msg_id;

    if (requires_suffix)
        current_pkt->rrpd.suffix = ++rrpd_suffix;
    else
        current_pkt->rrpd.suffix = 0;
}
#endif

gboolean is_dcerpc_context_zero(guint32 pkt_type)
{
    return (wmem_map_lookup(dcerpc_context_zero, GUINT_TO_POINTER(pkt_type)) != NULL);
}

gboolean is_dcerpc_req_pkt_type(guint32 pkt_type)
{
    return (wmem_map_lookup(dcerpc_req_pkt_type, GUINT_TO_POINTER(pkt_type)) != NULL);
}


/*
    This function initialises the global variables and populates the
    [tcp|udp]_svc_ports tables with information from the preference settings
 */
static void init_globals(void)
{
    if (!proto_is_protocol_enabled(find_protocol_by_id(proto_transum)))
        return;

    /* Create and initialise some dynamic memory areas */
    detected_tcp_svc = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    rrpd_list = wmem_list_new(wmem_file_scope());
    temp_rsp_rrpd_list = wmem_list_new(wmem_file_scope());

    /* Indicate what fields we're interested in. */
    wanted_fields = g_array_new(FALSE, FALSE, (guint)sizeof(int));
    for (int i = 0; i < HF_INTEREST_END_OF_LIST; i++)
    {
        g_array_append_val(wanted_fields, hf_of_interest[i].hf);
    }
    set_postdissector_wanted_hfids(transum_handle, wanted_fields);

    preferences.tcp_svc_ports = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    preferences.udp_svc_ports = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);

    /* use the range values to populate the tcp_svc_ports list*/
    for (guint i = 0; i < tcp_svc_port_range_values->nranges; i++)
    {
        for (guint32 j = tcp_svc_port_range_values->ranges[i].low; j <= tcp_svc_port_range_values->ranges[i].high; j++)
        {
            wmem_map_insert(preferences.tcp_svc_ports, GUINT_TO_POINTER(j), GUINT_TO_POINTER(RTE_CALC_GTCP));
        }
    }

    /* use the range values to populate the udp_svc_ports list*/
    for (guint i = 0; i < udp_svc_port_range_values->nranges; i++)
    {
        for (guint32 j = udp_svc_port_range_values->ranges[i].low; j <= udp_svc_port_range_values->ranges[i].high; j++)
        {
            wmem_map_insert(preferences.udp_svc_ports, GUINT_TO_POINTER(j), GUINT_TO_POINTER(RTE_CALC_GUDP));
        }
    }

    /* create arrays to hold some DCE-RPC values */
    dcerpc_context_zero = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    dcerpc_req_pkt_type = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
    init_dcerpc_data();

    wmem_map_insert(preferences.tcp_svc_ports, GUINT_TO_POINTER(445), GUINT_TO_POINTER(RTE_CALC_SMB2));
    wmem_map_insert(preferences.udp_svc_ports, GUINT_TO_POINTER(53), GUINT_TO_POINTER(RTE_CALC_DNS));

    output_rrpd = wmem_map_new(wmem_file_scope(), g_direct_hash, g_direct_equal);
}

/* This function adds the RTE data to the tree.  The summary ptr is currently
   not used but will be used for summariser information once this feature has
   been ported from the LUA code. */
static void write_rte(RRPD *in_rrpd, tvbuff_t *tvb, proto_tree *tree, char *summary)
{
    nstime_t rte_art;
    nstime_t rte_st;
    nstime_t rte_reqspread;
    nstime_t rte_rspspread;
    proto_tree *rte_tree;
    proto_item *pi;
    wmem_strbuf_t *temp_string = wmem_strbuf_new(wmem_packet_scope(), "");

    if (in_rrpd->req_first_frame)
    {
        pi = proto_tree_add_item(tree, proto_transum, tvb, 0, -1, ENC_NA);
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
        PROTO_ITEM_SET_GENERATED(pi);


        pi = proto_tree_add_uint(rte_tree, hf_tsum_req_first_seg, tvb, 0, 0, in_rrpd->req_first_frame);
        PROTO_ITEM_SET_GENERATED(pi);
        pi = proto_tree_add_uint(rte_tree, hf_tsum_req_last_seg, tvb, 0, 0, in_rrpd->req_last_frame);
        PROTO_ITEM_SET_GENERATED(pi);

        if (in_rrpd->rsp_first_frame)
        {
            pi = proto_tree_add_uint(rte_tree, hf_tsum_rsp_first_seg, tvb, 0, 0, in_rrpd->rsp_first_frame);
            PROTO_ITEM_SET_GENERATED(pi);
            pi = proto_tree_add_uint(rte_tree, hf_tsum_rsp_last_seg, tvb, 0, 0, in_rrpd->rsp_last_frame);
            PROTO_ITEM_SET_GENERATED(pi);

            pi = proto_tree_add_time(rte_tree, hf_tsum_apdu_rsp_time, tvb, 0, 0, &rte_art);
            PROTO_ITEM_SET_GENERATED(pi);
            pi = proto_tree_add_time(rte_tree, hf_tsum_service_time, tvb, 0, 0, &rte_st);
            PROTO_ITEM_SET_GENERATED(pi);
        }

        pi = proto_tree_add_time(rte_tree, hf_tsum_req_spread, tvb, 0, 0, &rte_reqspread);
        PROTO_ITEM_SET_GENERATED(pi);

        if (in_rrpd->rsp_first_frame)
        {
            pi = proto_tree_add_time(rte_tree, hf_tsum_rsp_spread, tvb, 0, 0, &rte_rspspread);
            PROTO_ITEM_SET_GENERATED(pi);
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
        PROTO_ITEM_SET_GENERATED(pi);

        pi = proto_tree_add_string(rte_tree, hf_tsum_calculation, tvb, 0, 0, val_to_str(in_rrpd->calculation, rrdp_calculation_vals, "Unknown calculation type: %d"));
        PROTO_ITEM_SET_GENERATED(pi);

        if (in_rrpd->rsp_first_frame)
        {
            if (preferences.summarisers_enabled)
            {
                if (summary)
                {
                    pi = proto_tree_add_string(tree, hf_tsum_summary, tvb, 0, 0, summary);
                    PROTO_ITEM_SET_GENERATED(pi);
                }
            }
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
    guint32 field_uint[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
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

        if (pkt_info->tcp_retran)
        {
            /* we may not want to continue with this packet if it's a retransmission */

            /* If this is a server-side trace we need to ignore client-to-service TCP retransmissions
            the rationale being that if we saw the original in the trace the service process saw it too */
            if (pkt_info->rrpd.c2s && preferences.capture_position == CAPTURE_SERVICE)
            {
                pkt_info->pkt_of_interest = FALSE;
                return;
            }

            /* If this is a client-side trace we need to ignore service-to-client TCP retransmissions
            the rationale being that if we saw the original in the trace the client process saw it too */
            else if (!pkt_info->rrpd.c2s && preferences.capture_position == CAPTURE_CLIENT)
            {
                pkt_info->pkt_of_interest = FALSE;
                return;
            }
        }

        /* We are not interested in TCP Keep-Alive */
        if (pkt_info->tcp_keep_alive)
        {
            pkt_info->pkt_of_interest = FALSE;
            return;
        }

        if (pkt_info->len == 1)
        {
            if (preferences.orphan_ka_discard && pkt_info->tcp_flags_ack && pkt_info->rrpd.c2s)
            {
                pkt_info->pkt_of_interest = FALSE;
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

            /* check if DCE-RPC */
            else if (!extract_uint(tree, hf_of_interest[HF_INTEREST_DCERPC_VER].hf, field_uint, &field_value_count))
            {
                if (field_value_count)
                    number_sub_pkts_of_interest = decode_dcerpc(pinfo, tree, pkt_info);
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
 * The pinfo.visited boolean is set to FALSE; on the first scan
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
                write_rte(rrpd, buffer, tree, NULL);
            }
        }
    }
    else
    {
        PKT_INFO *sub_packet = wmem_alloc0_array(wmem_packet_scope(), PKT_INFO, MAX_SUBPKTS_PER_PACKET);

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
        "Filter expression to select the APDU Reqest-Response pair", HFILL }
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
        }
    };

    /* Setup protocol subtree array */
    static gint *ett[] = {
        &ett_transum,
        &ett_transum_header,
        &ett_transum_data
    };

    proto_transum = proto_register_protocol("TRANSUM RTE Data", "TRANSUM", "transum");

    /* Due to performance concerns of the dissector, it's disabled by default */
    proto_disable_by_default(proto_transum);


    /* Set User Preferences defaults */
    preferences.capture_position = TRACE_CAP_CLIENT;
    preferences.reassembly = TRUE;

    range_convert_str(wmem_epan_scope(), &tcp_svc_port_range_values, "25, 80, 443, 1433", MAX_TCP_PORT);
    range_convert_str(wmem_epan_scope(), &udp_svc_port_range_values, "137-139", MAX_UDP_PORT);

    preferences.orphan_ka_discard = FALSE;
    preferences.time_multiplier = RTE_TIME_SEC;
    preferences.rte_on_first_req = FALSE;
    preferences.rte_on_last_req = TRUE;
    preferences.rte_on_first_rsp = FALSE;
    preferences.rte_on_last_rsp = FALSE;

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
        FALSE);

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
    FALSE);
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

    transum_handle = register_dissector("transum", dissect_transum, proto_transum);

    register_init_routine(init_globals);

    register_postdissector(transum_handle);
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
