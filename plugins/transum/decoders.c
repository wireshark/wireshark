/* decoders.c
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

#include "config.h"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>
#include "packet-transum.h"
#include "preferences.h"
#include "extractors.h"
#include "decoders.h"

extern void add_detected_tcp_svc(guint16 port);
extern TSUM_PREFERENCES preferences;
extern PKT_INFO *sub_packet;
extern gboolean *dcerpc_req_pkt_type;
extern gboolean *dcerpc_context_zero;
extern HF_OF_INTEREST hf_of_interest;


/* Returns the number of sub-packets of interest */
int decode_syn(packet_info *pinfo _U_, proto_tree *tree _U_)
{
    if (sub_packet[0].tcp_flags_ack)
        sub_packet[0].rrpd.c2s = FALSE;
    else
    {
        sub_packet[0].rrpd.c2s = TRUE;
        sub_packet[0].rrpd.state = RRPD_STATE_4;
        add_detected_tcp_svc(sub_packet[0].dstport);
    }

    sub_packet[0].rrpd.session_id = 1;
    sub_packet[0].rrpd.msg_id = 1;
    sub_packet[0].rrpd.suffix = 1;
    sub_packet[0].rrpd.decode_based = TRUE;
    sub_packet[0].rrpd.calculation = RTE_CALC_SYN;
    sub_packet[0].pkt_of_interest = TRUE;

    return 1;
}

/*
    This function sets basic information in the sub_packet entry.
    Because we don't expect multiple DCE-RPC messages in a single packet
    we only use sub_packet[0].

    Returns the number of sub-packets of interest, which in this case is always 1.
 */
int decode_dcerpc(packet_info *pinfo _U_, proto_tree *tree)
{
    guint32 field_uint[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
    size_t field_value_count;  /* How many entries are there in the extracted field array */
    guint32 dcerpc_cn_ctx_id = 0;

    if (!extract_uint(tree, hf_of_interest.dcerpc_ver, field_uint, &field_value_count))
    {
        if (field_value_count)
            sub_packet[0].dcerpc_ver = field_uint[0];
    }

    if (!extract_uint(tree, hf_of_interest.dcerpc_pkt_type, field_uint, &field_value_count))
    {
        if (field_value_count)
            sub_packet[0].dcerpc_pkt_type = field_uint[0];
    }

    if (field_value_count)
    {
        if (!extract_uint(tree, hf_of_interest.dcerpc_cn_ctx_id, field_uint, &field_value_count))
        {
            if (field_value_count)
                dcerpc_cn_ctx_id = field_uint[0];
        }

        if (dcerpc_context_zero[sub_packet[0].dcerpc_pkt_type])
        { /* This is needed to overcome an apparent Wireshark bug
             found in the LUA code - is this still true in C? */
            sub_packet[0].rrpd.session_id = 1;
        }
        else
        {
            if (dcerpc_cn_ctx_id)
                sub_packet[0].rrpd.session_id = dcerpc_cn_ctx_id;
            else
                sub_packet[0].rrpd.session_id = 1;
        }
        if (!extract_uint(tree, hf_of_interest.dcerpc_cn_call_id, field_uint, &field_value_count))
        {
            if (field_value_count)
                sub_packet[0].rrpd.msg_id = field_uint[0];
        }
    }
    else
    {
        /*
            we don't have header information and so by setting the session_id and msg_id to zero
            the rrpd functions will either create a new rrpd_list (or temp_rsp_rrpd_list) entry
            or update the last entry for this ip_proto:stream_no.
         */
        sub_packet[0].rrpd.session_id = 0;
        sub_packet[0].rrpd.msg_id = 0;
    }


    if (dcerpc_req_pkt_type[sub_packet[0].dcerpc_pkt_type])
    {
        sub_packet[0].rrpd.c2s = TRUE;
        preferences.tcp_svc_port[sub_packet[0].dstport] = RTE_CALC_DCERPC;  /* make sure we have this DCE-RPC service port set */
    }
    else
    {
        sub_packet[0].rrpd.c2s = FALSE;
        preferences.tcp_svc_port[sub_packet[0].srcport] = RTE_CALC_DCERPC;  /* make sure we have this DCE-RPC service port set */
    }

    sub_packet[0].rrpd.suffix = 1;
    sub_packet[0].rrpd.decode_based = TRUE;
    sub_packet[0].rrpd.calculation = RTE_CALC_DCERPC;
    sub_packet[0].pkt_of_interest = TRUE;

    return 1;
}

/* Returns the number of sub-packets of interest */
int decode_smb(packet_info *pinfo _U_, proto_tree *tree)
{
    guint32 field_uint[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
    size_t field_value_count;  /* How many entries are there in the extracted field array */

    guint64 ses_id[MAX_RETURNED_ELEMENTS];
    size_t ses_id_count;
    guint64 msg_id[MAX_RETURNED_ELEMENTS];
    size_t msg_id_count;

    /* set the direction information */
    if (sub_packet[0].dstport == 445)
        sub_packet[0].rrpd.c2s = TRUE;
    else
        sub_packet[0].rrpd.c2s = FALSE;

    extract_uint(tree, hf_of_interest.smb_mid, field_uint, &field_value_count);

    if (field_value_count)
    {
        sub_packet[0].rrpd.calculation = RTE_CALC_SMB1;
        sub_packet[0].pkt_of_interest = FALSE; /* can't process SMB1 at the moment */
        return 0;
    }
    else
    {
        /* Default in case we don't have header information */
        sub_packet[0].rrpd.session_id = 0;
        sub_packet[0].rrpd.msg_id = 0;
        sub_packet[0].rrpd.suffix = 1;
        sub_packet[0].rrpd.decode_based = TRUE;
        sub_packet[0].rrpd.calculation = RTE_CALC_SMB2;
        sub_packet[0].pkt_of_interest = TRUE;

        extract_si64(tree, hf_of_interest.smb2_msg_id, msg_id, &msg_id_count);
        if (msg_id_count)  /* test for header information */
        {
            extract_ui64(tree, hf_of_interest.smb2_ses_id, ses_id, &ses_id_count);

            for (size_t i = 0; i < msg_id_count; i++)
            {
                sub_packet[i].rrpd.c2s = sub_packet[0].rrpd.c2s;
                sub_packet[i].rrpd.ip_proto = sub_packet[0].rrpd.ip_proto;
                sub_packet[i].rrpd.stream_no = sub_packet[0].rrpd.stream_no;

                sub_packet[i].rrpd.session_id = ses_id[i];
                sub_packet[i].rrpd.msg_id = msg_id[i];
                sub_packet[i].rrpd.suffix = 1;

                sub_packet[i].rrpd.decode_based = TRUE;
                sub_packet[i].rrpd.calculation = RTE_CALC_SMB2;
                sub_packet[i].pkt_of_interest = TRUE;
            }
            return (int)msg_id_count;
        }
    }

    return 1;
}

/* Returns the number of sub-packets of interest */
int decode_gtcp(packet_info *pinfo, proto_tree *tree)
{
    guint32 field_uint[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
    gboolean field_bool[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
    size_t field_value_count;  /* How many entries are there in the extracted field array */

    if (!extract_uint(tree, hf_of_interest.tcp_stream, field_uint, &field_value_count))
        sub_packet[0].rrpd.stream_no = field_uint[0];

    sub_packet[0].srcport = pinfo->srcport;
    sub_packet[0].dstport = pinfo->destport;

    if (!extract_uint(tree, hf_of_interest.tcp_len, field_uint, &field_value_count))
        sub_packet[0].len = field_uint[0];

    if (!extract_bool(tree, hf_of_interest.tcp_flags_syn, field_bool, &field_value_count))
        sub_packet[0].tcp_flags_syn = field_bool[0];

    if (!extract_bool(tree, hf_of_interest.tcp_flags_ack, field_bool, &field_value_count))
        sub_packet[0].tcp_flags_ack = field_bool[0];

    if (!extract_bool(tree, hf_of_interest.tcp_flags_reset, field_bool, &field_value_count))
        sub_packet[0].tcp_flags_reset = field_bool[0];

    if (!extract_bool(tree, hf_of_interest.tcp_retran, field_bool, &field_value_count))
        sub_packet[0].tcp_retran = field_bool[0];

    if (!extract_bool(tree, hf_of_interest.tcp_keep_alive, field_bool, &field_value_count))
        sub_packet[0].tcp_keep_alive = field_bool[0];

    if ((preferences.tcp_svc_port[sub_packet[0].dstport] || preferences.tcp_svc_port[sub_packet[0].srcport]) && (sub_packet[0].len > 0))
    {
        if (preferences.tcp_svc_port[sub_packet[0].dstport])
            sub_packet[0].rrpd.c2s = TRUE;

        sub_packet[0].rrpd.session_id = 1;
        sub_packet[0].rrpd.msg_id = 1;
        sub_packet[0].rrpd.calculation = RTE_CALC_GTCP;
        sub_packet[0].rrpd.decode_based = FALSE;
        sub_packet[0].pkt_of_interest = TRUE;

        return 1;
    }

    return 0;
}

/* Returns the number of sub-packets of interest */
int decode_dns(packet_info *pinfo _U_, proto_tree *tree)
{
    guint32 field_uint[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
    size_t field_value_count;  /* How many entries are there in the extracted field array */

    if (!extract_uint(tree, hf_of_interest.dns_id, field_uint, &field_value_count))
        sub_packet[0].rrpd.msg_id = field_uint[0];

    sub_packet[0].rrpd.session_id = 1;
    sub_packet[0].rrpd.suffix = 1;  /* need to do something tricky here as dns.id gets reused */
    sub_packet[0].rrpd.decode_based = TRUE;
    sub_packet[0].rrpd.calculation = RTE_CALC_DNS;
    sub_packet[0].pkt_of_interest = TRUE;

    return 1;
}

/* Returns the number of sub-packets of interest */
int decode_gudp(packet_info *pinfo, proto_tree *tree)
{
    guint32 field_uint[MAX_RETURNED_ELEMENTS];  /* An extracted field array for unsigned integers */
    size_t field_value_count;  /* How many entries are there in the extracted field array */

    sub_packet[0].srcport = pinfo->srcport;
    sub_packet[0].dstport = pinfo->destport;

    if (!extract_uint(tree, hf_of_interest.udp_stream, field_uint, &field_value_count))
        sub_packet[0].rrpd.stream_no = field_uint[0];

    if (!extract_uint(tree, hf_of_interest.udp_length, field_uint, &field_value_count))
        sub_packet[0].len = field_uint[0];

    if (preferences.udp_svc_port[sub_packet[0].dstport] || preferences.udp_svc_port[sub_packet[0].srcport])
    {
        if (preferences.udp_svc_port[sub_packet[0].dstport])
            sub_packet[0].rrpd.c2s = TRUE;

        sub_packet[0].rrpd.session_id = 1;
        sub_packet[0].rrpd.msg_id = 1;
        sub_packet[0].rrpd.suffix = 1;
        sub_packet[0].rrpd.decode_based = FALSE;
        sub_packet[0].rrpd.calculation = RTE_CALC_GUDP;
        sub_packet[0].pkt_of_interest = TRUE;
    }

    return 1;
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
