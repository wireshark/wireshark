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
#include <epan/dissectors/packet-tcp.h>
#include <epan/tap.h>
#include <wsutil/report_err.h>
#include "packet-transum.h"
#include "preferences.h"
#include "extractors.h"
#include "decoders.h"

void proto_reg_handoff_transum(void);


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

#define SIZEOF_TEMP_STRING 512
#define SIZEOF_SUMMARY 1024

/* The following are the field ids for the protocol values used by TRANSUM */
HF_OF_INTEREST hf_of_interest;

range_t *tcp_svc_port_range_values;

range_t *udp_svc_port_range_values;

TSUM_PREFERENCES preferences;


gboolean *detected_tcp_svc = NULL;  /* this array is used to track services detected during the syn/syn-ack process */

PKT_INFO *sub_packet = NULL;

gboolean *dcerpc_req_pkt_type = NULL;  /* used to indicate if a DCE-RPC pkt_type is a request */

/*
This array contains calls and returns that have no TRUE context_id
This is needed to overcome an apparent bug in Wireshark where
the field name of context id in parameters is the same as context id
in a message header
*/
gboolean *dcerpc_context_zero= NULL;

/* rrpd-related globals */

guint32 rrpd_suffix = 0;
guint32 dummy_msgid = 0xa7; /* This value is used for protocols that don't have msg_id such as GTCP, GUDP and SYN */

/*
    The rrpd_list is the master array that holds information about all of the APDU Request-Response Pairs seen in the
    trace.  Each time an entry is added to this list the next_free_rrpd index is incremented.  This index is used to
    accelerate appending entries to the rrpd_list and also as the start point for find operations as these start from the
    end of the list and search backwards through the list.
 */
RRPD *rrpd_list;
int next_free_rrpd = 0;

/*
    output_rrpd is an array of pointers to RRPDs on the rrpd_list.  The index into the array is frame number.  This array is
    used during Wireshark's second scan.  As each packet is processed, TRANSUM uses the packet's frame number to index into
    this array to determine if we have RTE data for this particular packet, and if so the write_rte function is called.
 */
RRPD *output_rrpd[MAX_PACKETS];

/*
    The temp_rsp_rrpd_list holds RRPDs for APDUs where we have not yet seen the header information and so we can't
    fully qualify the identification of the RRPD (the identification being ip_proto:stream_no:session_id:msg_id:suffix).
    This only occurs when a) we are using one of the decode_based calculations (such as SMB2), and b) when we have
    TCP Reassembly enabled.  Once we receive a header packet for an APDU we migrate the entry from this array to the
    main rrpd_list.
 */
RRPD *temp_rsp_rrpd_list;  /* Reuse these for speed and efficient memory use - issue a warning if we run out */


static gint ett_transum = -1;
static gint ett_transum_header = -1;
static gint ett_transum_data = -1;

int proto_transum = -1;

int hf_tsum = -1;
int hf_tsum_status = -1;
int hf_tsum_time_units = -1;
int hf_tsum_req_first_seg = -1;
int hf_tsum_req_last_seg = -1;
int hf_tsum_rsp_first_seg = -1;
int hf_tsum_rsp_last_seg = -1;
int hf_tsum_apdu_rsp_time = -1;
int hf_tsum_service_time = -1;
int hf_tsum_req_spread = -1;
int hf_tsum_rsp_spread = -1;
int hf_tsum_clip_filter = -1;
int hf_tsum_calculation = -1;
int hf_tsum_summary = -1;

static const enum_val_t capture_position_vals[] = {
    { "TRACE_CAP_CLIENT", "Client", TRACE_CAP_CLIENT },
    { "TRACE_CAP_INTERMEDIATE", "Intermediate", TRACE_CAP_INTERMEDIATE },
    { "TRACE_CAP_SERVICE", "Service", TRACE_CAP_SERVICE },
    { NULL, NULL, 0}
};

/*static const enum_val_t time_multiplier_vals[] = {
    { "RTE_TIME_SEC", "seconds", RTE_TIME_SEC },
    { "RTE_TIME_MSEC", "milliseconds", RTE_TIME_MSEC },
    { "RTE_TIME_USEC", "microseconds", RTE_TIME_USEC },
    { NULL, NULL, 0}
};*/

static int fake_tap = 0xa7a7a7a7;


static void init_detected_tcp_svc(void)
{
    for (int i = 0; i < 64 * 1024; i++)
        detected_tcp_svc[i] = FALSE;
}

void add_detected_tcp_svc(guint16 port)
{
    detected_tcp_svc[port] = TRUE;
}


static void init_dcerpc_data(void)
{
    for (int i = 0; i < 256; i++)
        dcerpc_req_pkt_type[i] = FALSE;

    dcerpc_req_pkt_type[0] = TRUE;
    dcerpc_req_pkt_type[11] = TRUE;
    dcerpc_req_pkt_type[14] = TRUE;

    for (int i = 0; i < 256; i++)
        dcerpc_context_zero[i] = FALSE;

    dcerpc_context_zero[11] = TRUE;
    dcerpc_context_zero[12] = TRUE;
    dcerpc_context_zero[14] = TRUE;
    dcerpc_context_zero[15] = TRUE;

    return;
}

static void clear_rrpd(RRPD *rrpd)
{
    memset(rrpd, 0x00, sizeof(RRPD));
}

static void init_rrpd_data(void)
{
    for (int i = 0; i < MAX_PACKETS; i++)
        output_rrpd[i] = NULL;

    return;
}

/* This function should be called before any change to RTE data. */
static void null_output_rrpd_entries(RRPD *in_rrpd)
{
    output_rrpd[in_rrpd->req_first_frame] = NULL;
    output_rrpd[in_rrpd->req_last_frame] = NULL;
    output_rrpd[in_rrpd->rsp_first_frame] = NULL;
    output_rrpd[in_rrpd->rsp_last_frame] = NULL;
}

/* This function should be called after any change to RTE data. */
static void update_output_rrpd(RRPD *in_rrpd)
{
    if (preferences.rte_on_first_req)
        output_rrpd[in_rrpd->req_first_frame] = in_rrpd;

    if (preferences.rte_on_last_req)
        output_rrpd[in_rrpd->req_last_frame] = in_rrpd;

    if (preferences.rte_on_first_rsp)
        output_rrpd[in_rrpd->rsp_first_frame] = in_rrpd;

    if (preferences.rte_on_last_rsp)
        output_rrpd[in_rrpd->rsp_last_frame] = in_rrpd;
}

/* Return the index of the RRPD that has been appended */
int append_to_rrpd_list(RRPD *in_rrpd)
{
    if (next_free_rrpd > MAX_RRPDS)
        next_free_rrpd = 0;

    memcpy(&(rrpd_list[next_free_rrpd]), in_rrpd, sizeof(RRPD));

    if (preferences.reassembly)
    {
        if (rrpd_list[next_free_rrpd].msg_id)
            rrpd_list[next_free_rrpd].state = RRPD_STATE_3;
        else
            rrpd_list[next_free_rrpd].state = RRPD_STATE_1;
    }
    else
    {
        if (rrpd_list[next_free_rrpd].msg_id)
            rrpd_list[next_free_rrpd].state = RRPD_STATE_4;
        else
            rrpd_list[next_free_rrpd].state = RRPD_STATE_2;
    }

    update_output_rrpd(&rrpd_list[next_free_rrpd]);

    next_free_rrpd++;

    return (next_free_rrpd - 1);
}

/*
This function finds the latest entry in the rrpd_list that matches the
ip_proto, stream_no, session_id, msg_id and suffix values.

An input state value of 0 means that we don't care about state.

Returns the rrpd_list index value of the match or -1 if no match is found.
*/
int find_latest_rrpd(RRPD *in_rrpd, int state)
{
    int i;
    int rrpd_index = -1;

    for (i = next_free_rrpd; i >= 0; i--)
    {
        if (rrpd_list[i].ip_proto == in_rrpd->ip_proto && rrpd_list[i].stream_no == in_rrpd->stream_no)
        {
            if (in_rrpd->decode_based)
            {
                /* If this is decode-based and we are checking for entries in RRPD_STATE_1 we need to match on ip_proto and stream_no alone. */
                if (state == RRPD_STATE_1)
                {
                    if (rrpd_list[i].session_id == 0 && rrpd_list[i].msg_id == 0 && rrpd_list[i].suffix == 1)
                    {
                        rrpd_index = i;
                        break;
                    }
                }

                /* if this stream is decode_based we need to take into account the session_id, msg_id and suffix */
                if (rrpd_list[i].session_id == in_rrpd->session_id && rrpd_list[i].msg_id == in_rrpd->msg_id && rrpd_list[i].suffix == in_rrpd->suffix)
                {
                    if (state == RRPD_STATE_DONT_CARE || rrpd_list[i].state == state)
                    {
                        rrpd_index = i;
                        break;
                    }
                }
            }
            else
            {
                /* if this stream is not decode_based we don't need to take into account the session_id, msg_id and suffix */
                if (state == RRPD_STATE_DONT_CARE || rrpd_list[i].state == state)
                {
                    rrpd_index = i;
                    break;
                }
            }
        }
    }
    return rrpd_index;
}

static void update_rrpd_list_entry(int match_index, RRPD *in_rrpd)
{
    null_output_rrpd_entries(&rrpd_list[match_index]);

    switch (rrpd_list[match_index].state)
    {
    case RRPD_STATE_1:
        if (in_rrpd->c2s)
        {
            rrpd_list[match_index].req_last_frame = in_rrpd->req_last_frame;
            rrpd_list[match_index].req_last_rtime = in_rrpd->req_last_rtime;
            if (in_rrpd->msg_id)
            {
                rrpd_list[match_index].session_id = in_rrpd->session_id;
                rrpd_list[match_index].msg_id = in_rrpd->msg_id;
                rrpd_list[match_index].suffix = in_rrpd->suffix;
                rrpd_list[match_index].state = RRPD_STATE_3;
            }
        }
        else
        {
            rrpd_list[match_index].rsp_first_frame = in_rrpd->rsp_first_frame;
            rrpd_list[match_index].rsp_first_rtime = in_rrpd->rsp_first_rtime;
            rrpd_list[match_index].rsp_last_frame = in_rrpd->rsp_last_frame;
            rrpd_list[match_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                rrpd_list[match_index].state = RRPD_STATE_7;
            else
                rrpd_list[match_index].state = RRPD_STATE_5;
        }
        break;

    case RRPD_STATE_2:
        if (in_rrpd->c2s)
        {
            rrpd_list[match_index].req_last_frame = in_rrpd->req_last_frame;
            rrpd_list[match_index].req_last_rtime = in_rrpd->req_last_rtime;
            if (in_rrpd->msg_id)
            {
                rrpd_list[match_index].session_id = in_rrpd->session_id;
                rrpd_list[match_index].msg_id = in_rrpd->msg_id;
                rrpd_list[match_index].suffix = in_rrpd->suffix;
                rrpd_list[match_index].state = RRPD_STATE_4;
            }
        }
        else
        {
            rrpd_list[match_index].rsp_first_frame = in_rrpd->rsp_first_frame;
            rrpd_list[match_index].rsp_first_rtime = in_rrpd->rsp_first_rtime;
            rrpd_list[match_index].rsp_last_frame = in_rrpd->rsp_last_frame;
            rrpd_list[match_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                rrpd_list[match_index].state = RRPD_STATE_8;
            else
                rrpd_list[match_index].state = RRPD_STATE_6;
        }
        break;

    case RRPD_STATE_3:
        if (in_rrpd->c2s)
        {
            rrpd_list[match_index].req_last_frame = in_rrpd->req_last_frame;
            rrpd_list[match_index].req_last_rtime = in_rrpd->req_last_rtime;
            if (in_rrpd->msg_id)
            {
                rrpd_list[match_index].session_id = in_rrpd->session_id;
                rrpd_list[match_index].msg_id = in_rrpd->msg_id;
                rrpd_list[match_index].suffix = in_rrpd->suffix;
                rrpd_list[match_index].state = RRPD_STATE_3;
            }
        }
        else
        {
            rrpd_list[match_index].rsp_first_frame = in_rrpd->rsp_first_frame;
            rrpd_list[match_index].rsp_first_rtime = in_rrpd->rsp_first_rtime;
            rrpd_list[match_index].rsp_last_frame = in_rrpd->rsp_last_frame;
            rrpd_list[match_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                rrpd_list[match_index].state = RRPD_STATE_7;
            else
                rrpd_list[match_index].state = RRPD_STATE_5;
        }
        break;

    case RRPD_STATE_4:
        if (in_rrpd->c2s)
        {
            rrpd_list[match_index].req_last_frame = in_rrpd->req_last_frame;
            rrpd_list[match_index].req_last_rtime = in_rrpd->req_last_rtime;
            if (in_rrpd->msg_id)
            {
                rrpd_list[match_index].session_id = in_rrpd->session_id;
                rrpd_list[match_index].msg_id = in_rrpd->msg_id;
                rrpd_list[match_index].suffix = in_rrpd->suffix;
                rrpd_list[match_index].state = RRPD_STATE_4;
            }
        }
        else
        {
            rrpd_list[match_index].rsp_first_frame = in_rrpd->rsp_first_frame;
            rrpd_list[match_index].rsp_first_rtime = in_rrpd->rsp_first_rtime;
            rrpd_list[match_index].rsp_last_frame = in_rrpd->rsp_last_frame;
            rrpd_list[match_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                rrpd_list[match_index].state = RRPD_STATE_8;
            else
                rrpd_list[match_index].state = RRPD_STATE_6;
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
            rrpd_list[match_index].rsp_last_frame = in_rrpd->rsp_last_frame;
            rrpd_list[match_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                rrpd_list[match_index].state = RRPD_STATE_7;
            else
                rrpd_list[match_index].state = RRPD_STATE_5;
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
            rrpd_list[match_index].rsp_last_frame = in_rrpd->rsp_last_frame;
            rrpd_list[match_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
            if (in_rrpd->msg_id)
                rrpd_list[match_index].state = RRPD_STATE_8;
            else
                rrpd_list[match_index].state = RRPD_STATE_6;
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
            rrpd_list[match_index].rsp_last_frame = in_rrpd->rsp_last_frame;
            rrpd_list[match_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
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
            rrpd_list[match_index].rsp_last_frame = in_rrpd->rsp_last_frame;
            rrpd_list[match_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
        }
        break;
    }

    update_output_rrpd(&rrpd_list[match_index]);
}

/*
    This function processes a sub-packet that is going from client-to-service.
 */
static void update_rrpd_list_entry_req(RRPD *in_rrpd)
{
    int match_index = -1;

    if (in_rrpd->decode_based)
    {
        while (TRUE)
        {
            match_index = find_latest_rrpd(in_rrpd, RRPD_STATE_1);
            if (match_index >= 0)  /* Check to cover TCP Reassembly enabled */
            {
                update_rrpd_list_entry(match_index, in_rrpd);
                break;
            }

            match_index = find_latest_rrpd(in_rrpd, RRPD_STATE_4);
            if (match_index >= 0)
            {
                update_rrpd_list_entry(match_index, in_rrpd);
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
        match_index = find_latest_rrpd(in_rrpd, RRPD_STATE_DONT_CARE);
        if (match_index >= 0)
        {
            if (rrpd_list[match_index].state > RRPD_STATE_4 && in_rrpd->c2s)
            {
                append_to_rrpd_list(in_rrpd);
            }
            else
                /* no change of direction so just update the RTE data */
                update_rrpd_list_entry(match_index, in_rrpd);
        }
        else
        {
            append_to_rrpd_list(in_rrpd);
        }
    }

    return;
}

/*
    This function inserts an RRPD into the temp_rsp_rrpd_list.  If this is
    successful return the index of the entry.  If there is no space return -1.
 */
int insert_into_temp_rsp_rrpd_list(RRPD *in_rrpd)
{
    int i;

    for (i = 0; i < SIZE_OF_TEMP_RSP_RRPD_LIST; i++)
    {
        if (temp_rsp_rrpd_list[i].ip_proto == 0)
            break;
    }

    if (temp_rsp_rrpd_list[i].ip_proto)
    {
        temp_rsp_rrpd_list[i] = *in_rrpd;
        return i;
    }

    return -1;
}

int find_temp_rsp_rrpd(RRPD *in_rrpd)
{
    int entry_index = -1;

    for (int i = 0; i < SIZE_OF_TEMP_RSP_RRPD_LIST; i++)
    {
        if (temp_rsp_rrpd_list[i].ip_proto == in_rrpd->ip_proto && temp_rsp_rrpd_list[i].stream_no == in_rrpd->stream_no)
        {
            entry_index = i;
            break;
        }
    }
    return entry_index;
}

static void update_temp_rsp_rrpd(int temp_list_index, RRPD *in_rrpd)
{
    temp_rsp_rrpd_list[temp_list_index].rsp_last_frame = in_rrpd->rsp_last_frame;
    temp_rsp_rrpd_list[temp_list_index].rsp_last_rtime = in_rrpd->rsp_last_rtime;
}

/* This function migrates an entry from the temp_rsp_rrpd_list to the main rrpd_list. */
static void migrate_temp_rsp_rrpd(int main_list_index, int temp_list_index)
{
    update_rrpd_list_entry(main_list_index, &(temp_rsp_rrpd_list[temp_list_index]));

    clear_rrpd(&temp_rsp_rrpd_list[temp_list_index]);

    /* Update the state to 7 or 8 based on reassembly */
    if (preferences.reassembly)
        rrpd_list[main_list_index].state = RRPD_STATE_7;
    else
        rrpd_list[main_list_index].state = RRPD_STATE_8;

    return;
}

static void update_rrpd_list_entry_rsp(RRPD *in_rrpd)
{
    int match_index = -1;

    if (in_rrpd->decode_based)
    {
        if (preferences.reassembly)
        {
            if (in_rrpd->msg_id)
            {
                /* If we have a msg_id in the input RRPD we must have header information. */
                int temp_list_index = find_temp_rsp_rrpd(in_rrpd);

                if (temp_list_index >= 0)
                {
                    update_temp_rsp_rrpd(temp_list_index, in_rrpd);

                    /* Migrate the temp_rsp_rrpd_list entry to the main rrpd_list */
                    match_index = find_latest_rrpd(in_rrpd, RRPD_STATE_3);
                    if (match_index >= 0)
                        migrate_temp_rsp_rrpd(match_index, temp_list_index);
                }
                else
                {
                    match_index = find_latest_rrpd(in_rrpd, RRPD_STATE_3);
                    /* There isn't an entry in the temp_rsp_rrpd_list so update the master rrpd_list entry */
                    if (match_index >= 0)
                        update_rrpd_list_entry(match_index, in_rrpd);
                }
            }
            else
            {
                /* Update an existing entry to the temp_rsp_rrpd_list or add a new one. */
                int temp_list_index = find_temp_rsp_rrpd(in_rrpd);

                if (temp_list_index >= 0)
                    update_temp_rsp_rrpd(temp_list_index, in_rrpd);
                else
                    insert_into_temp_rsp_rrpd_list(in_rrpd);
            }
        }
        else
        {
            /* Reassembly isn't set and so just go ahead and use the list function */
            match_index = find_latest_rrpd(in_rrpd, RRPD_STATE_8);
            if (match_index >= 0)
                update_rrpd_list_entry(match_index, in_rrpd);
        }
    }
    else
    {
        /* if this isn't decode_based then just go ahead and update the RTE data */
        match_index = find_latest_rrpd(in_rrpd, RRPD_STATE_DONT_CARE);
        update_rrpd_list_entry(match_index, in_rrpd);
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

/* This function initialises all of the sub_packets in the sub_packet array. */
static void init_sub_packet(void)
{
    for (int i = 0; i < MAX_SUBPKTS_PER_PACKET; i++)
    {
        sub_packet[i].frame_number = 0;
        sub_packet[i].relative_time.secs = 0;
        sub_packet[i].relative_time.nsecs = 0;

        sub_packet[i].tcp_retran = FALSE;
        sub_packet[i].tcp_keep_alive = FALSE;
        sub_packet[i].tcp_flags_syn = FALSE;
        sub_packet[i].tcp_flags_ack = FALSE;
        sub_packet[i].tcp_flags_reset = FALSE;
        sub_packet[i].tcp_flags_urg = FALSE;
        sub_packet[i].tcp_seq = 0;

        sub_packet[i].srcport = 0;
        sub_packet[i].dstport = 0;
        sub_packet[i].len = 0;

        sub_packet[i].tds_type = 0;
        sub_packet[i].tds_length = 0;

        sub_packet[i].smb2_msg_id = 0;
        sub_packet[i].smb2_sesid = 0;
        sub_packet[i].smb2_cmd = 0;

        sub_packet[i].smb_mid = 0;

        sub_packet[i].dcerpc_ver = 0;
        sub_packet[i].dcerpc_pkt_type = 0;
        sub_packet[i].dcerpc_cn_call_id = 0;
        sub_packet[i].dcerpc_cn_ctx_id = 0;

        sub_packet[i].dns_id = 0;

        sub_packet[i].pkt_of_interest = FALSE;
        sub_packet[i].rrpd.c2s = FALSE;
        sub_packet[i].rrpd.state = RRPD_STATE_INIT;

        clear_rrpd(&sub_packet[i].rrpd);
    }

    return;
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

    return;
}
#endif


/*
    This function initialises the global variables and populates the
    tcp_svc_port table with information from the preference settings
 */
static void init_globals(void)
{
    /* The following achives two things; a) we avoid double registering the fake tap
       and b) we discard the fake tap when the "TRANSUM enabled" preference is changed.

       We remove the tap when it is not needed as it has a performance impact.

       It's safe to call remove_tap_listener even if the tap listener doesn't exist.
       If it doesn't find &fake_tap on the queue of listeners it calls the actual freeing
       function with a pointer of NULL and the called function just returns. */
    remove_tap_listener(&fake_tap);

    if (!preferences.tsumenabled) return;

    /* Create and initialise some dynamic memory areas */
    detected_tcp_svc = (gboolean *)wmem_alloc0(wmem_file_scope(), (64 * 1024 * sizeof(gboolean)));
    sub_packet = (PKT_INFO *)wmem_alloc0(wmem_file_scope(), (MAX_SUBPKTS_PER_PACKET * sizeof(PKT_INFO)));
    rrpd_list = (RRPD *)wmem_alloc0(wmem_file_scope(), (MAX_RRPDS * sizeof(RRPD)));
    temp_rsp_rrpd_list = (RRPD *)wmem_alloc0(wmem_file_scope(), (SIZE_OF_TEMP_RSP_RRPD_LIST * sizeof(RRPD)));

    next_free_rrpd = 0;

    GString* fake_tap_filter = g_string_new("frame");

    /* ToDo: the following and the hf_of_interest mechanism above should be replaced by something array-based so that
    it is easier to extend. */
    g_string_append_printf(fake_tap_filter, " || eth.type");
    g_string_append_printf(fake_tap_filter, " || ip.proto");
    g_string_append_printf(fake_tap_filter, " || ipv6.nxt");
    g_string_append_printf(fake_tap_filter, " || tcp.srcport");
    g_string_append_printf(fake_tap_filter, " || tcp.dstport");
    g_string_append_printf(fake_tap_filter, " || tcp.stream");
    g_string_append_printf(fake_tap_filter, " || tcp.analysis.retransmission");
    g_string_append_printf(fake_tap_filter, " || tcp.analysis.keep_alive");
    g_string_append_printf(fake_tap_filter, " || tcp.len");
    g_string_append_printf(fake_tap_filter, " || tcp.flags.syn");
    g_string_append_printf(fake_tap_filter, " || tcp.flags.ack");
    g_string_append_printf(fake_tap_filter, " || tcp.flags.reset");
    g_string_append_printf(fake_tap_filter, " || tcp.urgent_pointer");
    g_string_append_printf(fake_tap_filter, " || tcp.seq");

    g_string_append_printf(fake_tap_filter, " || tds.type");
    g_string_append_printf(fake_tap_filter, " || tds.length");

    g_string_append_printf(fake_tap_filter, " || udp.srcport");
    g_string_append_printf(fake_tap_filter, " || udp.dstport");
    g_string_append_printf(fake_tap_filter, " || udp.stream");
    g_string_append_printf(fake_tap_filter, " || udp.length");

    g_string_append_printf(fake_tap_filter, " || smb2.msg_id");
    g_string_append_printf(fake_tap_filter, " || smb2.sesid");
    g_string_append_printf(fake_tap_filter, " || smb2.cmd");

    g_string_append_printf(fake_tap_filter, " || smb.mid");

    g_string_append_printf(fake_tap_filter, " || dcerpc.ver");
    g_string_append_printf(fake_tap_filter, " || dcerpc.pkt_type");
    g_string_append_printf(fake_tap_filter, " || dcerpc.cn_ctx_id");
    g_string_append_printf(fake_tap_filter, " || dcerpc.cn_call_id");

    g_string_append_printf(fake_tap_filter, " || dns.id");

    /* this fake tap is needed to force WS to pass a tree to the dissectors on
       the first scan which causes the dissectors to create display filter values
       which are then available to TRANSUM during the first scan */
    GString* error = register_tap_listener("frame",
        &fake_tap,
        fake_tap_filter->str,
        TL_REQUIRES_NOTHING,
        NULL, NULL, NULL); /* NULL pointers as this is a fake tap */

    if (error)
    {
        report_failure("register_tap_listener() failed");
        return;
    }

    g_string_free(fake_tap_filter, TRUE);

    /* use the range values to populate the tcp_svc_port list*/
    for (guint i = 0; i < tcp_svc_port_range_values->nranges; i++)
    {
        for (guint32 j = tcp_svc_port_range_values->ranges[i].low; j <= tcp_svc_port_range_values->ranges[i].high; j++)
        {
            preferences.tcp_svc_port[j] = RTE_CALC_GTCP;
        }
    }

    /* use the range values to populate the tcp_svc_port list*/
    for (guint i = 0; i < udp_svc_port_range_values->nranges; i++)
    {
        for (guint32 j = udp_svc_port_range_values->ranges[i].low; j <= udp_svc_port_range_values->ranges[i].high; j++)
        {
            preferences.udp_svc_port[j] = RTE_CALC_GUDP;
        }
    }

    init_detected_tcp_svc();
    init_dcerpc_data();

    preferences.tcp_svc_port[445] = RTE_CALC_SMB2;
    preferences.udp_svc_port[53] = RTE_CALC_DNS;

    init_rrpd_data();

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

    char *temp_string = (char *)wmem_alloc(wmem_packet_scope(), SIZEOF_TEMP_STRING);

    if (in_rrpd->req_first_frame)
    {
        nstime_delta(&rte_reqspread, &(in_rrpd->req_last_rtime), &(in_rrpd->req_first_rtime));

        if (in_rrpd->rsp_first_frame)
        {
            /* calculate the RTE times */
            nstime_delta(&rte_art, &(in_rrpd->rsp_last_rtime), &(in_rrpd->req_first_rtime));
            nstime_delta(&rte_st, &(in_rrpd->rsp_first_rtime), &(in_rrpd->req_last_rtime));
            nstime_delta(&rte_rspspread, &(in_rrpd->rsp_last_rtime), &(in_rrpd->rsp_first_rtime));

            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "OK");
        }
        else
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "Response missing");

        pi = proto_tree_add_item(tree, proto_transum, tvb, 0, -1, ENC_NA);
        rte_tree = proto_item_add_subtree(pi, ett_transum);

        pi = proto_tree_add_string(rte_tree, hf_tsum_status, tvb, 0, 0, temp_string);
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
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "tcp.stream==%d", in_rrpd->stream_no);
        else if (in_rrpd->ip_proto == IP_PROTO_UDP)
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "udp.stream==%d", in_rrpd->stream_no);

        if (in_rrpd->rsp_first_frame)
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "%s && frame.number>=%d && frame.number<=%d", temp_string, in_rrpd->req_first_frame, in_rrpd->rsp_last_frame);
        else
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "%s && frame.number>=%d && frame.number<=%d", temp_string, in_rrpd->req_first_frame, in_rrpd->req_last_frame);

        if (in_rrpd->calculation == RTE_CALC_GTCP)
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "%s && tcp.len>0", temp_string);

        pi = proto_tree_add_string(rte_tree, hf_tsum_clip_filter, tvb, 0, 0, temp_string);
        PROTO_ITEM_SET_GENERATED(pi);

        switch (in_rrpd->calculation)
        {
        case RTE_CALC_GTCP:
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "Generic TCP");
            break;

        case RTE_CALC_SYN:
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "SYN and SYN/ACK");
            break;

        case RTE_CALC_DCERPC:
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "DCE-RPC");
            break;

        case RTE_CALC_SMB2:
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "SMB2");
            break;

        case RTE_CALC_GUDP:
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "Generic UDP");
            break;

        case RTE_CALC_DNS:
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "DNS");
            break;

        default:
            g_snprintf(temp_string, SIZEOF_TEMP_STRING, "Unknown calculation type: %d", in_rrpd->calculation);
            break;
        }
        pi = proto_tree_add_string(rte_tree, hf_tsum_calculation, tvb, 0, 0, temp_string);
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
    the xxx_svc_port arrays to see if they conatin a match for the source or
    destination port.  This function also adds tcp_svc_port entries when it
    discovers DCE-RPC traffic.

    Returns the number of sub-packets to be processed.
*/
static void set_proto_values(packet_info *pinfo, proto_tree *tree)
{
    guint32 field_uint[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
    size_t field_value_count;  /* How many entries are there in the extracted field array */

    sub_packet[0].frame_number = pinfo->fd->num;   /* easy access to frame number */
    sub_packet[0].relative_time = pinfo->rel_ts;

    int number_sub_pkts_of_interest = 0; /* default */

    if (pinfo->ptype == PT_TCP)
        sub_packet[0].rrpd.ip_proto = IP_PROTO_TCP;
    else if (pinfo->ptype == PT_UDP)
        sub_packet[0].rrpd.ip_proto = IP_PROTO_UDP;

    if (sub_packet[0].rrpd.ip_proto == IP_PROTO_TCP)
    {
        number_sub_pkts_of_interest = decode_gtcp(pinfo, tree);
        /* decode_gtcp may return 0 but we need to keep processing because we
        calculate RTE figures for all SYNs and also we may detect DCE-RPC later
        (even though we don't currently have an entry in the tcp_svc_port list). */

        if (sub_packet[0].tcp_retran)
        {
            /* we may not want to continue with this packet if it's a retransmission */

            /* If this is a server-side trace we need to ignore client-to-service TCP retransmissions
            the rationale being that if we saw the original in the trace the service process saw it too */
            if (sub_packet[0].rrpd.c2s && preferences.capture_position == CAPTURE_SERVICE)
            {
                sub_packet[0].pkt_of_interest = FALSE;
                return;
            }

            /* If this is a client-side trace we need to ignore service-to-client TCP retransmissions
            the rationale being that if we saw the original in the trace the client process saw it too */
            else if (!sub_packet[0].rrpd.c2s && preferences.capture_position == CAPTURE_CLIENT)
            {
                sub_packet[0].pkt_of_interest = FALSE;
                return;
            }
        }

        /* We are not interested in TCP Keep-Alive */
        if (sub_packet[0].tcp_keep_alive)
        {
            sub_packet[0].pkt_of_interest = FALSE;
            return;
        }

        if (sub_packet[0].len == 1)
        {
            if (preferences.orphan_ka_discard && sub_packet[0].tcp_flags_ack && sub_packet[0].rrpd.c2s)
            {
                sub_packet[0].pkt_of_interest = FALSE;
                return;  /* It's a KEEP-ALIVE -> stop processing this packet */
            }
        }

        /* check if SYN */
        if (sub_packet[0].tcp_flags_syn)
            number_sub_pkts_of_interest = decode_syn(pinfo, tree);

        if (sub_packet[0].len > 0)
        {
            /* check if SMB2 */
            if (sub_packet[0].dstport == 445 || sub_packet[0].srcport == 445)
                number_sub_pkts_of_interest = decode_smb(pinfo, tree);

            /* check if DCE-RPC */
            else if (!extract_uint(tree, hf_of_interest.dcerpc_ver, field_uint, &field_value_count))
            {
                if (field_value_count)
                    number_sub_pkts_of_interest = decode_dcerpc(pinfo, tree);
            }
        }

    }
    else if (sub_packet[0].rrpd.ip_proto == IP_PROTO_UDP)
    {
        /* It's UDP */
        number_sub_pkts_of_interest = decode_gudp(pinfo, tree);

        if (sub_packet[0].srcport == 53 || sub_packet[0].dstport == 53)
            number_sub_pkts_of_interest = decode_dns(pinfo, tree);
    }

    /* Set appropriate RTE values in the sub-packets */
    for (int i = 0; i < number_sub_pkts_of_interest; i++)
    {
        if (sub_packet[0].rrpd.c2s)
        {
            sub_packet[i].rrpd.req_first_frame = sub_packet[0].frame_number;
            sub_packet[i].rrpd.req_first_rtime = sub_packet[0].relative_time;
            sub_packet[i].rrpd.req_last_frame = sub_packet[0].frame_number;
            sub_packet[i].rrpd.req_last_rtime = sub_packet[0].relative_time;

            sub_packet[i].frame_number = sub_packet[0].frame_number;  /* this acts as a switch later */
        }
        else
        {
            sub_packet[i].rrpd.rsp_first_frame = sub_packet[0].frame_number;
            sub_packet[i].rrpd.rsp_first_rtime = sub_packet[0].relative_time;
            sub_packet[i].rrpd.rsp_last_frame = sub_packet[0].frame_number;
            sub_packet[i].rrpd.rsp_last_rtime = sub_packet[0].relative_time;

            sub_packet[i].frame_number = sub_packet[0].frame_number;  /* this acts as a switch later */
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
    if (!preferences.tsumenabled) return 0;

    /* if (there is RTE info associated with this packet we need to output it */
    if (PINFO_FD_VISITED(pinfo))
    {
        RRPD *rrpd = output_rrpd[pinfo->num];

        if (rrpd)
            /* Add the RTE data to the protocol decode tree if we output_flag is set */
            write_rte(rrpd, buffer, tree, NULL);
    }
    else
    {
        init_sub_packet();

        set_proto_values(pinfo, tree);

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
    dissector_handle_t transum_handle;

    static hf_register_info hf[] = {
        { &hf_tsum,
        { "TRANSUM", "transum",
        FT_NONE, BASE_NONE, NULL, 0x0,
        "Post-dissector to generate RTE information", HFILL } },

        { &hf_tsum_status,
        { "RTE Status", "transum.status",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Indication of completeness of the RTE information", HFILL } },

        { &hf_tsum_time_units,
        { "RTE Time Units", "transum.time_units",
        FT_STRING, BASE_NONE, NULL, 0x0,
        "Time units used (s, ms or us) for the RTE values", HFILL }
        },

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

    proto_transum = proto_register_protocol(
        "TRANSUM RTE Data", /* name       */
        "TRANSUM",      /* short name */
        "transum"       /* abbrev     */
        );

    /* Set User Preferences defaults */
    preferences.tsumenabled = FALSE;
    preferences.capture_position = TRACE_CAP_CLIENT;
    preferences.reassembly = TRUE;

    tcp_svc_port_range_values = (range_t *)g_malloc((sizeof(guint) + (4 * sizeof(range_admin_t))));
    tcp_svc_port_range_values->nranges = 4;
    tcp_svc_port_range_values->ranges[0].low = 25;
    tcp_svc_port_range_values->ranges[0].high = 25;
    tcp_svc_port_range_values->ranges[1].low = 80;
    tcp_svc_port_range_values->ranges[1].high = 80;
    tcp_svc_port_range_values->ranges[2].low = 443;
    tcp_svc_port_range_values->ranges[2].high = 443;
    tcp_svc_port_range_values->ranges[3].low = 1433;
    tcp_svc_port_range_values->ranges[3].high = 1433;

    udp_svc_port_range_values = (range_t *)g_malloc((sizeof(guint) + (1 * sizeof(range_admin_t))));
    udp_svc_port_range_values->nranges = 1;
    udp_svc_port_range_values->ranges[0].low = 137;
    udp_svc_port_range_values->ranges[0].high = 139;

    preferences.orphan_ka_discard = FALSE;
    preferences.time_multiplier = RTE_TIME_SEC;
    preferences.rte_on_first_req = FALSE;
    preferences.rte_on_last_req = TRUE;
    preferences.rte_on_first_rsp = FALSE;
    preferences.rte_on_last_rsp = FALSE;

    /* create arrays to hold some DCE-RPC values */
    dcerpc_req_pkt_type = (gboolean *)wmem_alloc(wmem_epan_scope(), (256 * sizeof(gboolean)));
    dcerpc_context_zero = (gboolean *)wmem_alloc(wmem_epan_scope(), (256 * sizeof(gboolean)));

    /* no start registering stuff */
    proto_register_field_array(proto_transum, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));

    transum_module = prefs_register_protocol(proto_transum, NULL);  /* ToDo: We need to rethink the NULL pointer so that a preference change causes a rescan */

    /* Register the preferences */
    prefs_register_bool_preference(transum_module, "tsumenabled",
        "TRANSUM enabled",
        "Uncheck to bypass TRANSUM",
        &preferences.tsumenabled);

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

    transum_module = prefs_register_protocol(proto_transum, proto_reg_handoff_transum);
    register_init_routine(init_globals);

    register_postdissector(transum_handle);
}

void proto_reg_handoff_transum(void)
{
    /* Get the field id for each field we will need */
    hf_of_interest.ip_proto = proto_registrar_get_id_byname("ip.proto");
    hf_of_interest.ipv6_nxt = proto_registrar_get_id_byname("ipv6.nxt");
    hf_of_interest.tcp_retran = proto_registrar_get_id_byname("tcp.analysis.retransmission");
    hf_of_interest.tcp_keep_alive = proto_registrar_get_id_byname("tcp.analysis.keep_alive");
    hf_of_interest.tcp_flags_syn = proto_registrar_get_id_byname("tcp.flags.syn");
    hf_of_interest.tcp_flags_ack = proto_registrar_get_id_byname("tcp.flags.ack");
    hf_of_interest.tcp_flags_reset = proto_registrar_get_id_byname("tcp.flags.reset");
    hf_of_interest.tcp_flags_urg = proto_registrar_get_id_byname("tcp.flags.urg");
    hf_of_interest.tcp_seq = proto_registrar_get_id_byname("tcp.seq");
    hf_of_interest.tcp_srcport = proto_registrar_get_id_byname("tcp.srcport");
    hf_of_interest.tcp_dstport = proto_registrar_get_id_byname("tcp.dstport");
    hf_of_interest.tcp_stream = proto_registrar_get_id_byname("tcp.stream");
    hf_of_interest.tcp_len = proto_registrar_get_id_byname("tcp.len");

    hf_of_interest.udp_srcport = proto_registrar_get_id_byname("udp.srcport");
    hf_of_interest.udp_dstport = proto_registrar_get_id_byname("udp.dstport");
    hf_of_interest.udp_stream = proto_registrar_get_id_byname("udp.stream");
    hf_of_interest.udp_length = proto_registrar_get_id_byname("udp.length");

    hf_of_interest.tds_type = proto_registrar_get_id_byname("tds.type");
    hf_of_interest.tds_length = proto_registrar_get_id_byname("tds.length");

    hf_of_interest.smb_mid = proto_registrar_get_id_byname("smb.mid");

    hf_of_interest.smb2_ses_id = proto_registrar_get_id_byname("smb2.sesid");
    hf_of_interest.smb2_msg_id = proto_registrar_get_id_byname("smb2.msg_id");
    hf_of_interest.smb2_cmd = proto_registrar_get_id_byname("smb2.msg_cmd");

    hf_of_interest.dcerpc_ver = proto_registrar_get_id_byname("dcerpc.ver");
    hf_of_interest.dcerpc_pkt_type = proto_registrar_get_id_byname("dcerpc.pkt_type");
    hf_of_interest.dcerpc_cn_call_id = proto_registrar_get_id_byname("dcerpc.cn_call_id");
    hf_of_interest.dcerpc_cn_ctx_id = proto_registrar_get_id_byname("dcerpc.cn_ctx_id");

    hf_of_interest.dns_id = proto_registrar_get_id_byname("dns.id");

    if (!preferences.tsumenabled)
        proto_disable_by_default(proto_transum);
    proto_set_decoding(proto_transum, preferences.tsumenabled);
}
