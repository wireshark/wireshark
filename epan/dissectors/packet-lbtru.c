/* packet-lbtru.c
 * Routines for LBT-RU Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "config.h"
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/conversation.h>
#include <epan/to_str.h>
#include <epan/tap.h>
#include "packet-lbm.h"
#include "packet-lbtru.h"

void proto_register_lbtru(void);
void proto_reg_handoff_lbtru(void);

/* Protocol handle */
static int proto_lbtru = -1;

/* Dissector handle */
static dissector_handle_t lbtru_dissector_handle;

/* Tap handle */
static int lbtru_tap_handle = -1;

/*----------------------------------------------------------------------------*/
/* LBT-RU transport management.                                               */
/*----------------------------------------------------------------------------*/

static const address lbtru_null_address = ADDRESS_INIT_NONE;

static lbtru_transport_t * lbtru_transport_find(const address * source_address, guint16 source_port, guint32 session_id, guint32 frame)
{
    lbtru_transport_t * entry = NULL;
    wmem_tree_t * session_tree = NULL;
    conversation_t * conv = NULL;

    conv = find_conversation(frame, source_address, &lbtru_null_address, CONVERSATION_UDP, source_port, 0, 0);
    if (conv != NULL)
    {
        if (frame != 0)
        {
            if (conv->setup_frame == 0)
            {
                conv->setup_frame = frame;
            }
            if (frame > conv->last_frame)
            {
                conv->last_frame = frame;
            }
        }
        session_tree = (wmem_tree_t *) conversation_get_proto_data(conv, proto_lbtru);
        if (session_tree != NULL)
        {
            entry = (lbtru_transport_t *) wmem_tree_lookup32(session_tree, session_id);
        }
    }
    return (entry);
}

lbtru_transport_t * lbtru_transport_add(const address * source_address, guint16 source_port, guint32 session_id, guint32 frame)
{
    lbtru_transport_t * entry = NULL;
    wmem_tree_t * session_tree = NULL;
    conversation_t * conv = NULL;

    conv = find_conversation(frame, source_address, &lbtru_null_address, CONVERSATION_UDP, source_port, 0, 0);
    if (conv == NULL)
    {
        conv = conversation_new(frame, source_address, &lbtru_null_address, CONVERSATION_UDP, source_port, 0, 0);
    }
    if (frame != 0)
    {
        if (conv->setup_frame == 0)
        {
            conv->setup_frame = frame;
        }
        if (frame > conv->last_frame)
        {
            conv->last_frame = frame;
        }
    }
    session_tree = (wmem_tree_t *) conversation_get_proto_data(conv, proto_lbtru);
    if (session_tree == NULL)
    {
        session_tree = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_lbtru, (void *)session_tree);
    }
    entry = (lbtru_transport_t *) wmem_tree_lookup32(session_tree, session_id);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbtru_transport_t);
    copy_address_wmem(wmem_file_scope(), &(entry->source_address), source_address);
    entry->source_port = source_port;
    entry->session_id = session_id;
    entry->channel = lbm_channel_assign(LBM_CHANNEL_TRANSPORT_LBTRU);
    entry->next_client_id = 1;
    entry->client_list = wmem_list_new(wmem_file_scope());
    wmem_tree_insert32(session_tree, session_id, (void *) entry);
    return (entry);
}

static lbtru_client_transport_t * lbtru_client_transport_find(lbtru_transport_t * transport, const address * receiver_address, guint16 receiver_port, guint32 frame)
{
    lbtru_client_transport_t * entry = NULL;
    conversation_t * client_conv = NULL;

    if (transport == NULL)
    {
        return (NULL);
    }
    client_conv = find_conversation(frame, &(transport->source_address), receiver_address, CONVERSATION_UDP, transport->source_port, receiver_port, 0);
    if (client_conv != NULL)
    {
        wmem_tree_t * session_tree = NULL;

        session_tree = (wmem_tree_t *) conversation_get_proto_data(client_conv, proto_lbtru);
        if (session_tree != NULL)
        {
            entry = (lbtru_client_transport_t *) wmem_tree_lookup32(session_tree, transport->session_id);
        }
    }
    return (entry);
}

static lbtru_client_transport_t * lbtru_client_transport_add(lbtru_transport_t * transport, const address * receiver_address, guint16 receiver_port, guint32 frame)
{
    lbtru_client_transport_t * entry = NULL;
    conversation_t * client_conv = NULL;
    wmem_tree_t * session_tree = NULL;

    if (transport == NULL)
    {
        return (NULL);
    }
    entry = lbtru_client_transport_find(transport, receiver_address, receiver_port, frame);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new0(wmem_file_scope(), lbtru_client_transport_t);
    copy_address_wmem(wmem_file_scope(), &(entry->receiver_address), receiver_address);
    entry->receiver_port = receiver_port;
    entry->transport = transport;
    entry->id = transport->next_client_id++;
    entry->frame = wmem_tree_new(wmem_file_scope());
    entry->last_frame = NULL;
    entry->last_data_frame = NULL;
    entry->last_sm_frame = NULL;
    entry->last_nak_frame = NULL;
    entry->last_ncf_frame = NULL;
    entry->last_ack_frame = NULL;
    entry->last_creq_frame = NULL;
    entry->last_rst_frame = NULL;
    entry->data_sqn = wmem_tree_new(wmem_file_scope());
    entry->sm_sqn = wmem_tree_new(wmem_file_scope());
    entry->data_high_sqn = 0;
    entry->sm_high_sqn = 0;

    /* See if a conversation for this address/port pair exists. */
    client_conv = find_conversation(frame, &(transport->source_address), receiver_address, CONVERSATION_UDP, transport->source_port, receiver_port, 0);
    if (client_conv == NULL)
    {
        client_conv = conversation_new(frame, &(transport->source_address), receiver_address, CONVERSATION_UDP, transport->source_port, receiver_port, 0);
        session_tree = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(client_conv, proto_lbtru, (void *) session_tree);
    }
    else
    {
        session_tree = (wmem_tree_t *) conversation_get_proto_data(client_conv, proto_lbtru);
        if (session_tree == NULL)
        {
            session_tree = wmem_tree_new(wmem_file_scope());
            conversation_add_proto_data(client_conv, proto_lbtru, (void *) session_tree);
        }
    }
    wmem_tree_insert32(session_tree, transport->session_id, (void *) entry);

    /* Add this client to the transport. */
    wmem_list_append(transport->client_list, (void *) entry);
    return (entry);
}

static lbm_transport_sqn_t * lbtru_client_transport_sqn_find(lbtru_client_transport_t * client, guint8 type, guint32 sqn)
{
    lbm_transport_sqn_t * sqn_entry = NULL;

    switch (type)
    {
        case LBTRU_PACKET_TYPE_DATA:
            sqn_entry = (lbm_transport_sqn_t *) wmem_tree_lookup32(client->data_sqn, sqn);
            break;
        case LBTRU_PACKET_TYPE_SM:
            sqn_entry = (lbm_transport_sqn_t *) wmem_tree_lookup32(client->sm_sqn, sqn);
            break;
        case LBTRU_PACKET_TYPE_NAK:
        case LBTRU_PACKET_TYPE_NCF:
        case LBTRU_PACKET_TYPE_ACK:
        case LBTRU_PACKET_TYPE_CREQ:
        case LBTRU_PACKET_TYPE_RST:
        default:
            sqn_entry = NULL;
            break;
    }
    return (sqn_entry);
}

static lbm_transport_sqn_t * lbtru_client_transport_sqn_add(lbtru_client_transport_t * client, lbm_transport_frame_t * frame)
{
    wmem_tree_t * sqn_list = NULL;
    lbm_transport_sqn_t * sqn_entry = NULL;

    switch (frame->type)
    {
        case LBTRU_PACKET_TYPE_DATA:
            sqn_list = client->data_sqn;
            break;
        case LBTRU_PACKET_TYPE_SM:
            sqn_list = client->sm_sqn;
            break;
        case LBTRU_PACKET_TYPE_NAK:
        case LBTRU_PACKET_TYPE_NCF:
        case LBTRU_PACKET_TYPE_ACK:
        case LBTRU_PACKET_TYPE_CREQ:
        case LBTRU_PACKET_TYPE_RST:
        default:
            return (NULL);
            break;
    }

    /* Add the sqn. */
    sqn_entry = lbm_transport_sqn_add(sqn_list, frame);
    return (sqn_entry);
}

static lbm_transport_frame_t * lbtru_client_transport_frame_find(lbtru_client_transport_t * client, guint32 frame)
{
    return ((lbm_transport_frame_t *) wmem_tree_lookup32(client->frame, frame));
}

static lbm_transport_frame_t * lbtru_client_transport_frame_add(lbtru_client_transport_t * client, guint8 type, guint32 frame, guint32 sqn, gboolean retransmission)
{
    lbm_transport_sqn_t * dup_sqn_entry = NULL;
    lbm_transport_frame_t * frame_entry = NULL;

    /* Locate the frame. */
    frame_entry = lbtru_client_transport_frame_find(client, frame);
    if (frame_entry != NULL)
    {
        return (frame_entry);
    }
    frame_entry = lbm_transport_frame_add(client->frame, type, frame, sqn, retransmission);
    if (client->last_frame != NULL)
    {
        frame_entry->previous_frame = client->last_frame->frame;
        client->last_frame->next_frame = frame;
    }
    client->last_frame = frame_entry;
    switch (type)
    {
        case LBTRU_PACKET_TYPE_DATA:
            if (client->last_data_frame != NULL)
            {
                frame_entry->previous_type_frame = client->last_data_frame->frame;
                client->last_data_frame->next_type_frame = frame;
                /* Ideally, this frame's sqn is 1 more than the highest data sqn seen */
                if (frame_entry->sqn <= client->data_high_sqn)
                {
                    dup_sqn_entry = lbtru_client_transport_sqn_find(client, type, frame_entry->sqn);
                    if (!frame_entry->retransmission)
                    {
                        /* Out of order */
                        if (dup_sqn_entry != NULL)
                        {
                            frame_entry->duplicate = TRUE;
                        }
                        if (frame_entry->sqn != client->data_high_sqn)
                        {
                            frame_entry->ooo_gap = client->data_high_sqn - frame_entry->sqn;
                        }
                    }
                }
                else
                {
                    if (!frame_entry->retransmission)
                    {
                        if (frame_entry->sqn != (client->data_high_sqn + 1))
                        {
                            /* Gap */
                            frame_entry->sqn_gap = frame_entry->sqn - (client->last_data_frame->sqn + 1);
                        }
                    }
                }
            }
            if ((frame_entry->sqn > client->data_high_sqn) && !frame_entry->retransmission)
            {
                client->data_high_sqn = frame_entry->sqn;
            }
            client->last_data_frame = frame_entry;
            break;
        case LBTRU_PACKET_TYPE_SM:
            if (client->last_sm_frame != NULL)
            {
                frame_entry->previous_type_frame = client->last_sm_frame->frame;
                client->last_sm_frame->next_type_frame = frame;
                /* Ideally, this frame's sqn is 1 more than the highest SM sqn seen */
                if (frame_entry->sqn <= client->sm_high_sqn)
                {
                    /* Out of order */
                    dup_sqn_entry = lbtru_client_transport_sqn_find(client, type, frame_entry->sqn);
                    if (dup_sqn_entry != NULL)
                    {
                        frame_entry->duplicate = TRUE;
                    }
                    if (frame_entry->sqn != client->sm_high_sqn)
                    {
                        frame_entry->ooo_gap = client->sm_high_sqn - frame_entry->sqn;
                    }
                }
                else
                {
                    if (frame_entry->sqn != (client->sm_high_sqn + 1))
                    {
                        /* Gap */
                        frame_entry->sqn_gap = frame_entry->sqn - (client->sm_high_sqn + 1);
                    }
                }
            }
            if (frame_entry->sqn > client->sm_high_sqn)
            {
                client->sm_high_sqn = frame_entry->sqn;
            }
            client->last_sm_frame = frame_entry;
            break;
        case LBTRU_PACKET_TYPE_NAK:
            if (client->last_nak_frame != NULL)
            {
                frame_entry->previous_type_frame = client->last_nak_frame->frame;
                client->last_nak_frame->next_type_frame = frame;
            }
            client->last_nak_frame = frame_entry;
            break;
        case LBTRU_PACKET_TYPE_NCF:
            if (client->last_ncf_frame != NULL)
            {
                frame_entry->previous_type_frame = client->last_ncf_frame->frame;
                client->last_ncf_frame->next_type_frame = frame;
            }
            client->last_ncf_frame = frame_entry;
            break;
        case LBTRU_PACKET_TYPE_ACK:
            if (client->last_ack_frame != NULL)
            {
                frame_entry->previous_type_frame = client->last_ack_frame->frame;
                client->last_ack_frame->next_type_frame = frame;
            }
            client->last_ack_frame = frame_entry;
            break;
        case LBTRU_PACKET_TYPE_CREQ:
            if (client->last_creq_frame != NULL)
            {
                frame_entry->previous_type_frame = client->last_creq_frame->frame;
                client->last_creq_frame->next_type_frame = frame;
            }
            client->last_creq_frame = frame_entry;
            break;
        case LBTRU_PACKET_TYPE_RST:
            if (client->last_rst_frame != NULL)
            {
                frame_entry->previous_type_frame = client->last_rst_frame->frame;
                client->last_rst_frame->next_type_frame = frame;
            }
            client->last_rst_frame = frame_entry;
            break;
    }

    /* Add the sqn. */
    (void)lbtru_client_transport_sqn_add(client, frame_entry);
    return (frame_entry);
}

static char * lbtru_transport_source_string_format(const address * source_address, guint16 source_port, guint32 session_id)
{
    /* Returns a packet-scoped string. */
    char * bufptr = NULL;

    if (session_id == 0)
    {
        bufptr = wmem_strdup_printf(wmem_packet_scope(), "LBT-RU:%s:%" PRIu16, address_to_str(wmem_packet_scope(), source_address), source_port);
    }
    else
    {
        bufptr = wmem_strdup_printf(wmem_packet_scope(), "LBT-RU:%s:%" PRIu16 ":%08x", address_to_str(wmem_packet_scope(), source_address), source_port, session_id);
    }
    return (bufptr);
}

char * lbtru_transport_source_string(const address * source_address, guint16 source_port, guint32 session_id)
{
    /* Returns a file-scoped string. */
    return (wmem_strdup(wmem_file_scope(), lbtru_transport_source_string_format(source_address, source_port, session_id)));
}

static char * lbtru_transport_source_string_transport(lbtru_transport_t * transport)
{
    /* Returns a packet-scoped string. */
    return (lbtru_transport_source_string(&(transport->source_address), transport->source_port, transport->session_id));
}

/*----------------------------------------------------------------------------*/
/* Packet layouts.                                                            */
/*----------------------------------------------------------------------------*/

/* LBT-RU main header */
typedef struct
{
    lbm_uint8_t ver_type;
    lbm_uint8_t next_hdr;
    lbm_uint16_t flags_or_res;
} lbtru_hdr_t;
#define O_LBTRU_HDR_T_VER_TYPE OFFSETOF(lbtru_hdr_t, ver_type)
#define L_LBTRU_HDR_T_VER_TYPE SIZEOF(lbtru_hdr_t, ver_type)
#define O_LBTRU_HDR_T_NEXT_HDR OFFSETOF(lbtru_hdr_t, next_hdr)
#define L_LBTRU_HDR_T_NEXT_HDR SIZEOF(lbtru_hdr_t, next_hdr)
#define O_LBTRU_HDR_T_FLAGS_OR_RES OFFSETOF(lbtru_hdr_t, flags_or_res)
#define L_LBTRU_HDR_T_FLAGS_OR_RES SIZEOF(lbtru_hdr_t, flags_or_res)
#define L_LBTRU_HDR_T (gint) sizeof(lbtru_hdr_t)

#define LBTRU_VERSION 0x00
#define LBTRU_HDR_VER(x) (x >> 4)
#define LBTRU_HDR_TYPE(x) (x & 0x0F)
#define LBTRU_HDR_VER_VER_MASK 0xF0
#define LBTRU_HDR_VER_TYPE_MASK 0x0F

#define LBTRU_RETRANSMISSION_FLAG 0x4000

/* LBT-RU data header */
typedef struct
{
    lbm_uint32_t sqn;
    lbm_uint32_t trail_sqn;
} lbtru_data_hdr_t;
#define O_LBTRU_DATA_HDR_T_SQN OFFSETOF(lbtru_data_hdr_t, sqn)
#define L_LBTRU_DATA_HDR_T_SQN SIZEOF(lbtru_data_hdr_t, sqn)
#define O_LBTRU_DATA_HDR_T_TRAIL_SQN OFFSETOF(lbtru_data_hdr_t, trail_sqn)
#define L_LBTRU_DATA_HDR_T_TRAIL_SQN SIZEOF(lbtru_data_hdr_t, trail_sqn)
#define L_LBTRU_DATA_HDR_T (gint) (sizeof(lbtru_data_hdr_t))

/* LBT-RU Session Message header */
typedef struct
{
    lbm_uint32_t sm_sqn;
    lbm_uint32_t lead_sqn;
    lbm_uint32_t trail_sqn;
} lbtru_sm_hdr_t;
#define O_LBTRU_SM_HDR_T_SM_SQN OFFSETOF(lbtru_sm_hdr_t, sm_sqn)
#define L_LBTRU_SM_HDR_T_SM_SQN SIZEOF(lbtru_sm_hdr_t, sm_sqn)
#define O_LBTRU_SM_HDR_T_LEAD_SQN OFFSETOF(lbtru_sm_hdr_t, lead_sqn)
#define L_LBTRU_SM_HDR_T_LEAD_SQN SIZEOF(lbtru_sm_hdr_t, lead_sqn)
#define O_LBTRU_SM_HDR_T_TRAIL_SQN OFFSETOF(lbtru_sm_hdr_t, trail_sqn)
#define L_LBTRU_SM_HDR_T_TRAIL_SQN SIZEOF(lbtru_sm_hdr_t, trail_sqn)
#define L_LBTRU_SM_HDR_T (gint) (sizeof(lbtru_sm_hdr_t))

#define LBTRU_SM_SYN_FLAG 0x8000

/* LBT-RU NAK header */
typedef struct
{
    lbm_uint16_t num_naks;
    lbm_uint16_t format;
} lbtru_nak_hdr_t;
#define O_LBTRU_NAK_HDR_T_NUM_NAKS OFFSETOF(lbtru_nak_hdr_t, num_naks)
#define L_LBTRU_NAK_HDR_T_NUM_NAKS SIZEOF(lbtru_nak_hdr_t, num_naks)
#define O_LBTRU_NAK_HDR_T_FORMAT OFFSETOF(lbtru_nak_hdr_t, format)
#define L_LBTRU_NAK_HDR_T_FORMAT SIZEOF(lbtru_nak_hdr_t, format)
#define L_LBTRU_NAK_HDR_T (gint) (sizeof(lbtru_nak_hdr_t))

#define LBTRU_NAK_SELECTIVE_FORMAT 0x0
#define LBTRU_NAK_HDR_FORMAT_MASK 0x000F
#define LBTRU_NAK_HDR_FORMAT(x) (x & 0xF)

/* LBT-RU NAK Confirmation header */
typedef struct
{
    lbm_uint32_t trail_sqn;
    lbm_uint16_t num_ncfs;
    lbm_uint8_t reserved;
    lbm_uint8_t reason_format;
} lbtru_ncf_hdr_t;
#define O_LBTRU_NCF_HDR_T_TRAIL_SQN OFFSETOF(lbtru_ncf_hdr_t, trail_sqn)
#define L_LBTRU_NCF_HDR_T_TRAIL_SQN SIZEOF(lbtru_ncf_hdr_t, trail_sqn)
#define O_LBTRU_NCF_HDR_T_NUM_NCFS OFFSETOF(lbtru_ncf_hdr_t, num_ncfs)
#define L_LBTRU_NCF_HDR_T_NUM_NCFS SIZEOF(lbtru_ncf_hdr_t, num_ncfs)
#define O_LBTRU_NCF_HDR_T_RESERVED OFFSETOF(lbtru_ncf_hdr_t, reserved)
#define L_LBTRU_NCF_HDR_T_RESERVED SIZEOF(lbtru_ncf_hdr_t, reserved)
#define O_LBTRU_NCF_HDR_T_REASON_FORMAT OFFSETOF(lbtru_ncf_hdr_t, reason_format)
#define L_LBTRU_NCF_HDR_T_REASON_FORMAT SIZEOF(lbtru_ncf_hdr_t, reason_format)
#define L_LBTRU_NCF_HDR_T (gint) (sizeof(lbtru_ncf_hdr_t))

#define LBTRU_NCF_SELECTIVE_FORMAT 0x0
#define LBTRU_NCF_HDR_REASON(x) ((x & 0xF0) >> 4)
#define LBTRU_NCF_HDR_FORMAT(x) (x & 0xF)
#define LBTRU_NCF_HDR_REASON_MASK 0xF0
#define LBTRU_NCF_HDR_FORMAT_MASK 0x0F

/* LBT-RU ACK header */
typedef struct
{
    lbm_uint32_t ack_sqn;
} lbtru_ack_hdr_t;
#define O_LBTRU_ACK_HDR_T_ACK_SQN OFFSETOF(lbtru_ack_hdr_t, ack_sqn)
#define L_LBTRU_ACK_HDR_T_ACK_SQN SIZEOF(lbtru_ack_hdr_t, ack_sqn)
#define L_LBTRU_ACK_HDR_T (gint) (sizeof(lbtru_ack_hdr_t))

/* LBT-RU basic option header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t res;
} lbtru_basic_opt_t;
#define O_LBTRU_BASIC_OPT_T_NEXT_HDR OFFSETOF(lbtru_basic_opt_t, next_hdr)
#define L_LBTRU_BASIC_OPT_T_NEXT_HDR SIZEOF(lbtru_basic_opt_t, next_hdr)
#define O_LBTRU_BASIC_OPT_T_HDR_LEN OFFSETOF(lbtru_basic_opt_t, hdr_len)
#define L_LBTRU_BASIC_OPT_T_HDR_LEN SIZEOF(lbtru_basic_opt_t, hdr_len)
#define O_LBTRU_BASIC_OPT_T_RES OFFSETOF(lbtru_basic_opt_t, res)
#define L_LBTRU_BASIC_OPT_T_RES SIZEOF(lbtru_basic_opt_t, res)
#define L_LBTRU_BASIC_OPT_T (gint) (sizeof(lbtru_basic_opt_t))

/* LBT-RU Session ID option header */
typedef struct
{
    lbm_uint32_t session_id;
} lbtru_sid_opt_t;
#define O_LBTRU_SID_OPT_T_SESSION_ID OFFSETOF(lbtru_sid_opt_t, session_id)
#define L_LBTRU_SID_OPT_T_SESSION_ID SIZEOF(lbtru_sid_opt_t, session_id)
#define L_LBTRU_SID_OPT_T (gint) (sizeof(lbtru_sid_opt_t))

/* LBT-RU Client ID option header */
typedef struct
{
    lbm_uint32_t client_sid;
} lbtru_cid_opt_t;
#define O_LBTRU_CID_OPT_T_CLIENT_SID OFFSETOF(lbtru_cid_opt_t, client_sid)
#define L_LBTRU_CID_OPT_T_CLIENT_SID SIZEOF(lbtru_cid_opt_t, client_sid)
#define L_LBTRU_CID_OPT_T (gint) (sizeof(lbtru_cid_opt_t))

#define LBTRU_OPT_IGNORE 0x8000

#define LBTRU_NHDR_DATA 0x00
#define LBTRU_NHDR_SID 0x01
#define LBTRU_NHDR_CID 0x02

/*----------------------------------------------------------------------------*/
/* Value translation tables.                                                  */
/*----------------------------------------------------------------------------*/

static const value_string lbtru_packet_type[] =
{
    { LBTRU_PACKET_TYPE_DATA, "DATA" },
    { LBTRU_PACKET_TYPE_SM, "SM" },
    { LBTRU_PACKET_TYPE_NAK, "NAK" },
    { LBTRU_PACKET_TYPE_NCF, "NCF" },
    { LBTRU_PACKET_TYPE_ACK, "ACK" },
    { LBTRU_PACKET_TYPE_CREQ, "CREQ" },
    { LBTRU_PACKET_TYPE_RST, "RST" },
    { 0x0, NULL }
};

static const value_string lbtru_nak_format[] =
{
    { LBTRU_NAK_SELECTIVE_FORMAT, "Selective" },
    { 0x0, NULL }
};

static const value_string lbtru_ncf_format[] =
{
    { LBTRU_NCF_SELECTIVE_FORMAT, "Selective" },
    { 0x0, NULL }
};

static const value_string lbtru_ncf_reason[] =
{
    { LBTRU_NCF_REASON_NO_RETRY, "Do not retry" },
    { LBTRU_NCF_REASON_IGNORED, "NAK Ignored" },
    { LBTRU_NCF_REASON_RX_DELAY, "Retransmit Delay" },
    { LBTRU_NCF_REASON_SHED, "NAK Shed" },
    { 0x0, NULL }
};

static const value_string lbtru_creq_request[] =
{
    { LBTRU_CREQ_REQUEST_SYN, "SYN" },
    { 0x0, NULL }
};

static const value_string lbtru_rst_reason[] =
{
    { LBTRU_RST_REASON_DEFAULT, "Default" },
    { 0x0, NULL }
};

static const value_string lbtru_next_header[] =
{
    { LBTRU_NHDR_DATA, "DATA" },
    { LBTRU_NHDR_SID, "SID" },
    { LBTRU_NHDR_CID, "CID" },
    { 0x0, NULL }
};

/*----------------------------------------------------------------------------*/
/* Preferences.                                                               */
/*----------------------------------------------------------------------------*/

/* Preferences default values. */
#define LBTRU_DEFAULT_SOURCE_PORT_LOW    14380
#define LBTRU_DEFAULT_SOURCE_PORT_HIGH   14389
#define LBTRU_DEFAULT_RECEIVER_PORT_LOW  14360
#define LBTRU_DEFAULT_RECEIVER_PORT_HIGH 14379

/* Global preferences variables (altered by the preferences dialog). */
static guint32 global_lbtru_source_port_low = LBTRU_DEFAULT_SOURCE_PORT_LOW;
static guint32 global_lbtru_source_port_high = LBTRU_DEFAULT_SOURCE_PORT_HIGH;
static guint32 global_lbtru_receiver_port_low = LBTRU_DEFAULT_RECEIVER_PORT_LOW;
static guint32 global_lbtru_receiver_port_high = LBTRU_DEFAULT_RECEIVER_PORT_HIGH;
static gboolean global_lbtru_expert_separate_naks = FALSE;
static gboolean global_lbtru_expert_separate_ncfs = FALSE;
static gboolean global_lbtru_use_tag = FALSE;
static gboolean global_lbtru_sequence_analysis = FALSE;

/* Local preferences variables (used by the dissector). */
static guint32 lbtru_source_port_low = LBTRU_DEFAULT_SOURCE_PORT_LOW;
static guint32 lbtru_source_port_high = LBTRU_DEFAULT_SOURCE_PORT_HIGH;
static guint32 lbtru_receiver_port_low = LBTRU_DEFAULT_RECEIVER_PORT_LOW;
static guint32 lbtru_receiver_port_high = LBTRU_DEFAULT_RECEIVER_PORT_HIGH;
static gboolean lbtru_expert_separate_naks = FALSE;
static gboolean lbtru_expert_separate_ncfs = FALSE;
static gboolean lbtru_use_tag = FALSE;
static gboolean lbtru_sequence_analysis = FALSE;

/*----------------------------------------------------------------------------*/
/* Tag management.                                                            */
/*----------------------------------------------------------------------------*/
typedef struct
{
    char * name;
    guint32 source_port_low;
    guint32 source_port_high;
    guint32 receiver_port_low;
    guint32 receiver_port_high;
} lbtru_tag_entry_t;

static lbtru_tag_entry_t * lbtru_tag_entry = NULL;
static guint lbtru_tag_count = 0;

UAT_CSTRING_CB_DEF(lbtru_tag, name, lbtru_tag_entry_t)
UAT_DEC_CB_DEF(lbtru_tag, source_port_low, lbtru_tag_entry_t)
UAT_DEC_CB_DEF(lbtru_tag, source_port_high, lbtru_tag_entry_t)
UAT_DEC_CB_DEF(lbtru_tag, receiver_port_low, lbtru_tag_entry_t)
UAT_DEC_CB_DEF(lbtru_tag, receiver_port_high, lbtru_tag_entry_t)
static uat_field_t lbtru_tag_array[] =
{
    UAT_FLD_CSTRING(lbtru_tag, name, "Tag name", "Tag name"),
    UAT_FLD_DEC(lbtru_tag, source_port_low, "Source port low", "Source port low"),
    UAT_FLD_DEC(lbtru_tag, source_port_high, "Source port high", "Source port high"),
    UAT_FLD_DEC(lbtru_tag, receiver_port_low, "Receiver port low", "Receiver port low"),
    UAT_FLD_DEC(lbtru_tag, receiver_port_high, "Receiver port high", "Receiver port high"),
    UAT_END_FIELDS
};

/*----------------------------------------------------------------------------*/
/* UAT callback functions.                                                    */
/*----------------------------------------------------------------------------*/
static gboolean lbtru_tag_update_cb(void * record, char * * error_string)
{
    lbtru_tag_entry_t * tag = (lbtru_tag_entry_t *)record;

    if (tag->name == NULL)
    {
        *error_string = g_strdup("Tag name can't be empty");
        return FALSE;
    }
    else
    {
        g_strstrip(tag->name);
        if (tag->name[0] == 0)
        {
            *error_string = g_strdup("Tag name can't be empty");
            return FALSE;
        }
    }
    return TRUE;
}

static void * lbtru_tag_copy_cb(void * destination, const void * source, size_t length _U_)
{
    const lbtru_tag_entry_t * src = (const lbtru_tag_entry_t *)source;
    lbtru_tag_entry_t * dest = (lbtru_tag_entry_t *)destination;

    dest->name = g_strdup(src->name);
    dest->source_port_low = src->source_port_low;
    dest->source_port_high = src->source_port_high;
    dest->receiver_port_low = src->receiver_port_low;
    dest->receiver_port_high = src->receiver_port_high;
    return (dest);
}

static void lbtru_tag_free_cb(void * record)
{
    lbtru_tag_entry_t * tag = (lbtru_tag_entry_t *)record;

    if (tag->name != NULL)
    {
        g_free(tag->name);
        tag->name = NULL;
    }
}

static char * lbtru_tag_find(packet_info * pinfo)
{
    guint idx;
    lbtru_tag_entry_t * tag = NULL;

    if (!lbtru_use_tag)
    {
        return (NULL);
    }

    for (idx = 0; idx < lbtru_tag_count; ++idx)
    {
        tag = &(lbtru_tag_entry[idx]);
        if (((pinfo->destport >= tag->source_port_low)
             && (pinfo->destport <= tag->source_port_high)
             && (pinfo->srcport >= tag->receiver_port_low)
             && (pinfo->srcport <= tag->receiver_port_high))
            || ((pinfo->destport >= tag->receiver_port_low)
                && (pinfo->destport <= tag->receiver_port_high)
                && (pinfo->srcport >= tag->source_port_low)
                && (pinfo->srcport <= tag->source_port_high)))
        {
            /* One of ours. */
            return tag->name;
        }
    }
    return (NULL);
}

/*----------------------------------------------------------------------------*/
/* Handles of all types.                                                      */
/*----------------------------------------------------------------------------*/

/* Dissector tree handles */
static gint ett_lbtru = -1;
static gint ett_lbtru_channel = -1;
static gint ett_lbtru_hdr = -1;
static gint ett_lbtru_hdr_flags = -1;
static gint ett_lbtru_data = -1;
static gint ett_lbtru_sm = -1;
static gint ett_lbtru_nak = -1;
static gint ett_lbtru_nak_list = -1;
static gint ett_lbtru_ncf = -1;
static gint ett_lbtru_ncf_list = -1;
static gint ett_lbtru_ack = -1;
static gint ett_lbtru_opt = -1;
static gint ett_lbtru_opt_sid_flags = -1;
static gint ett_lbtru_opt_cid_flags = -1;
static gint ett_lbtru_transport = -1;
static gint ett_lbtru_transport_sqn = -1;

/* Dissector field handles */
static int hf_lbtru_channel = -1;
static int hf_lbtru_channel_id = -1;
static int hf_lbtru_channel_client = -1;
static int hf_lbtru_tag = -1;
static int hf_lbtru_hdr = -1;
static int hf_lbtru_hdr_ver = -1;
static int hf_lbtru_hdr_type = -1;
static int hf_lbtru_hdr_next_hdr = -1;
static int hf_lbtru_hdr_res = -1;
static int hf_lbtru_hdr_flags = -1;
static int hf_lbtru_hdr_flags_syn = -1;
static int hf_lbtru_hdr_flags_rx = -1;
static int hf_lbtru_hdr_request = -1;
static int hf_lbtru_hdr_reason = -1;
static int hf_lbtru_data = -1;
static int hf_lbtru_data_sqn = -1;
static int hf_lbtru_data_trail_sqn = -1;
static int hf_lbtru_sm = -1;
static int hf_lbtru_sm_sqn = -1;
static int hf_lbtru_sm_lead_sqn = -1;
static int hf_lbtru_sm_trail_sqn = -1;
static int hf_lbtru_nak = -1;
static int hf_lbtru_nak_num = -1;
static int hf_lbtru_nak_format = -1;
static int hf_lbtru_nak_list = -1;
static int hf_lbtru_nak_list_nak = -1;
static int hf_lbtru_ncf = -1;
static int hf_lbtru_ncf_trail_sqn = -1;
static int hf_lbtru_ncf_num = -1;
static int hf_lbtru_ncf_reserved = -1;
static int hf_lbtru_ncf_reason = -1;
static int hf_lbtru_ncf_format = -1;
static int hf_lbtru_ncf_list = -1;
static int hf_lbtru_ncf_list_ncf = -1;
static int hf_lbtru_ack = -1;
static int hf_lbtru_ack_sqn = -1;
static int hf_lbtru_opt_sid = -1;
static int hf_lbtru_opt_sid_next_hdr = -1;
static int hf_lbtru_opt_sid_hdr_len = -1;
static int hf_lbtru_opt_sid_flags = -1;
static int hf_lbtru_opt_sid_flags_ignore = -1;
static int hf_lbtru_opt_sid_session_id = -1;
static int hf_lbtru_opt_cid = -1;
static int hf_lbtru_opt_cid_next_hdr = -1;
static int hf_lbtru_opt_cid_hdr_len = -1;
static int hf_lbtru_opt_cid_flags = -1;
static int hf_lbtru_opt_cid_flags_ignore = -1;
static int hf_lbtru_opt_cid_client_id = -1;
static int hf_lbtru_opt_unknown = -1;
static int hf_lbtru_opt_unknown_next_hdr = -1;
static int hf_lbtru_opt_unknown_hdr_len = -1;
static int hf_lbtru_analysis = -1;
static int hf_lbtru_analysis_prev_frame = -1;
static int hf_lbtru_analysis_prev_data_frame = -1;
static int hf_lbtru_analysis_prev_sm_frame = -1;
static int hf_lbtru_analysis_prev_nak_frame = -1;
static int hf_lbtru_analysis_prev_ncf_frame = -1;
static int hf_lbtru_analysis_prev_ack_frame = -1;
static int hf_lbtru_analysis_prev_creq_frame = -1;
static int hf_lbtru_analysis_prev_rst_frame = -1;
static int hf_lbtru_analysis_next_frame = -1;
static int hf_lbtru_analysis_next_data_frame = -1;
static int hf_lbtru_analysis_next_sm_frame = -1;
static int hf_lbtru_analysis_next_nak_frame = -1;
static int hf_lbtru_analysis_next_ncf_frame = -1;
static int hf_lbtru_analysis_next_ack_frame = -1;
static int hf_lbtru_analysis_next_creq_frame = -1;
static int hf_lbtru_analysis_next_rst_frame = -1;
static int hf_lbtru_analysis_sqn = -1;
static int hf_lbtru_analysis_sqn_frame = -1;
static int hf_lbtru_analysis_data_retransmission = -1;
static int hf_lbtru_analysis_data_sqn_gap = -1;
static int hf_lbtru_analysis_data_ooo_gap = -1;
static int hf_lbtru_analysis_data_duplicate = -1;
static int hf_lbtru_analysis_sm_sqn_gap = -1;
static int hf_lbtru_analysis_sm_ooo_gap = -1;
static int hf_lbtru_analysis_sm_duplicate = -1;

/* Expert info handles */
static expert_field ei_lbtru_analysis_unknown_type = EI_INIT;
static expert_field ei_lbtru_analysis_unknown_header = EI_INIT;
static expert_field ei_lbtru_analysis_zero_length_header = EI_INIT;
static expert_field ei_lbtru_analysis_ack = EI_INIT;
static expert_field ei_lbtru_analysis_ncf = EI_INIT;
static expert_field ei_lbtru_analysis_ncf_ncf = EI_INIT;
static expert_field ei_lbtru_analysis_nak = EI_INIT;
static expert_field ei_lbtru_analysis_nak_nak = EI_INIT;
static expert_field ei_lbtru_analysis_sm = EI_INIT;
static expert_field ei_lbtru_analysis_sm_syn = EI_INIT;
static expert_field ei_lbtru_analysis_creq = EI_INIT;
static expert_field ei_lbtru_analysis_rst = EI_INIT;
static expert_field ei_lbtru_analysis_data_rx = EI_INIT;
static expert_field ei_lbtru_analysis_data_gap = EI_INIT;
static expert_field ei_lbtru_analysis_data_ooo = EI_INIT;
static expert_field ei_lbtru_analysis_data_dup = EI_INIT;
static expert_field ei_lbtru_analysis_sm_gap = EI_INIT;
static expert_field ei_lbtru_analysis_sm_ooo = EI_INIT;
static expert_field ei_lbtru_analysis_sm_dup = EI_INIT;

/*----------------------------------------------------------------------------*/
/* LBT-RU data payload dissection functions.                                  */
/*----------------------------------------------------------------------------*/
static int dissect_lbtru_data_contents(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, const char * tag_name, guint64 channel)
{
    tvbuff_t * next_tvb;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    return (lbmc_dissect_lbmc_packet(next_tvb, 0, pinfo, tree, tag_name, channel));
}

/*----------------------------------------------------------------------------*/
/* LBT-RU ACK packet dissection functions.                                    */
/*----------------------------------------------------------------------------*/
static int dissect_lbtru_ack(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, lbm_lbtru_tap_info_t * tap_info)
{
    proto_tree * ack_tree = NULL;
    proto_item * ack_item = NULL;
    proto_item * ack = NULL;

    ack_item = proto_tree_add_item(tree, hf_lbtru_ack, tvb, offset, L_LBTRU_ACK_HDR_T, ENC_NA);
    ack_tree = proto_item_add_subtree(ack_item, ett_lbtru_ack);
    ack = proto_tree_add_item(ack_tree, hf_lbtru_ack_sqn, tvb, offset + O_LBTRU_ACK_HDR_T_ACK_SQN, L_LBTRU_ACK_HDR_T_ACK_SQN, ENC_BIG_ENDIAN);
    expert_add_info(pinfo, ack, &ei_lbtru_analysis_ack);
    tap_info->sqn = tvb_get_ntohl(tvb, offset + O_LBTRU_ACK_HDR_T_ACK_SQN);
    return (L_LBTRU_ACK_HDR_T);
}

/*----------------------------------------------------------------------------*/
/* LBT-RU NAK confirmation packet dissection functions.                       */
/*----------------------------------------------------------------------------*/
static int dissect_lbtru_ncf_list(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, int ncf_count, int reason, lbm_lbtru_tap_info_t * tap_info)
{
    proto_tree * ncf_tree = NULL;
    proto_item * ncf_item = NULL;
    lbm_uint32_t ncf;
    int idx = 0;
    int len = 0;

    ncf_item = proto_tree_add_item(tree, hf_lbtru_ncf_list, tvb, offset, -1, ENC_NA);
    ncf_tree = proto_item_add_subtree(ncf_item, ett_lbtru_ncf_list);

    for (idx = 0; idx < ncf_count; idx++)
    {
        proto_item * sep_ncf_item = NULL;

        ncf = tvb_get_ntohl(tvb, offset + len);
        sep_ncf_item = proto_tree_add_item(ncf_tree, hf_lbtru_ncf_list_ncf, tvb, offset + len, sizeof(lbm_uint32_t), ENC_BIG_ENDIAN);
        if (lbtru_expert_separate_ncfs)
        {
            expert_add_info_format(pinfo, sep_ncf_item, &ei_lbtru_analysis_ncf_ncf, "NCF 0x%08x %s", ncf, val_to_str(reason, lbtru_ncf_reason, "Unknown (0x%02x)"));
        }
        tap_info->sqns[idx] = ncf;
        len += (int)sizeof(lbm_uint32_t);
    }
    proto_item_set_len(ncf_item, len);
    return (len);
}

static int dissect_lbtru_ncf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, lbm_lbtru_tap_info_t * tap_info)
{
    int len_dissected;
    guint8 reason_format;
    proto_tree * ncf_tree = NULL;
    proto_item * ncf_item = NULL;
    guint16 num_ncfs = 0;

    ncf_item = proto_tree_add_item(tree, hf_lbtru_ncf, tvb, offset, -1, ENC_NA);
    ncf_tree = proto_item_add_subtree(ncf_item, ett_lbtru_ncf);
    reason_format = tvb_get_guint8(tvb, offset + O_LBTRU_NCF_HDR_T_REASON_FORMAT);
    num_ncfs = tvb_get_ntohs(tvb, offset + O_LBTRU_NCF_HDR_T_NUM_NCFS);
    proto_tree_add_item(ncf_tree, hf_lbtru_ncf_trail_sqn, tvb, offset + O_LBTRU_NCF_HDR_T_TRAIL_SQN, L_LBTRU_NCF_HDR_T_TRAIL_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(ncf_tree, hf_lbtru_ncf_num, tvb, offset + O_LBTRU_NCF_HDR_T_NUM_NCFS, L_LBTRU_NCF_HDR_T_NUM_NCFS, ENC_BIG_ENDIAN);
    proto_tree_add_item(ncf_tree, hf_lbtru_ncf_reserved, tvb, offset + O_LBTRU_NCF_HDR_T_RESERVED, L_LBTRU_NCF_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    proto_tree_add_item(ncf_tree, hf_lbtru_ncf_reason, tvb, offset + O_LBTRU_NCF_HDR_T_REASON_FORMAT, L_LBTRU_NCF_HDR_T_REASON_FORMAT, ENC_BIG_ENDIAN);
    proto_tree_add_item(ncf_tree, hf_lbtru_ncf_format, tvb, offset + O_LBTRU_NCF_HDR_T_REASON_FORMAT, L_LBTRU_NCF_HDR_T_REASON_FORMAT, ENC_BIG_ENDIAN);
    len_dissected = L_LBTRU_NCF_HDR_T;
    if (!lbtru_expert_separate_ncfs)
    {
        expert_add_info_format(pinfo, ncf_item, &ei_lbtru_analysis_ncf, "NCF %s", val_to_str(LBTRU_NCF_HDR_REASON(reason_format), lbtru_ncf_reason, "Unknown (0x%02x)"));
    }
    tap_info->ncf_reason = LBTRU_NCF_HDR_REASON(reason_format);;
    tap_info->num_sqns = num_ncfs;
    tap_info->sqns = wmem_alloc_array(wmem_packet_scope(), guint32, num_ncfs);
    len_dissected += dissect_lbtru_ncf_list(tvb, offset + L_LBTRU_NCF_HDR_T, pinfo, ncf_tree, num_ncfs, LBTRU_NCF_HDR_REASON(reason_format), tap_info);
    proto_item_set_len(ncf_item, len_dissected);
    return (len_dissected);
}

/*----------------------------------------------------------------------------*/
/* LBT-RU NAK packet dissection functions.                                    */
/*----------------------------------------------------------------------------*/
static int dissect_lbtru_nak_list(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, int nak_count, lbm_lbtru_tap_info_t * tap_info)
{
    proto_tree * nak_tree = NULL;
    proto_item * nak_item = NULL;
    int idx = 0;
    int len = 0;

    nak_item = proto_tree_add_item(tree, hf_lbtru_nak_list, tvb, offset, -1, ENC_NA);
    nak_tree = proto_item_add_subtree(nak_item, ett_lbtru_nak_list);

    for (idx = 0; idx < nak_count; idx++)
    {
        proto_item * sep_nak_item = NULL;
        lbm_uint32_t nak;

        nak = tvb_get_ntohl(tvb, offset + len);
        sep_nak_item = proto_tree_add_item(nak_tree, hf_lbtru_nak_list_nak, tvb, offset + len, sizeof(lbm_uint32_t), ENC_BIG_ENDIAN);
        if (lbtru_expert_separate_naks)
        {
            expert_add_info_format(pinfo, sep_nak_item, &ei_lbtru_analysis_nak_nak, "NAK 0x%08x", nak);
        }
        tap_info->sqns[idx] = nak;
        len += (int)sizeof(lbm_uint32_t);
    }
    proto_item_set_len(nak_item, len);
    return (len);
}

static int dissect_lbtru_nak(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, lbm_lbtru_tap_info_t * tap_info)
{
    int len_dissected;
    proto_tree * nak_tree = NULL;
    proto_item * nak_item = NULL;
    guint16 num_naks = 0;

    nak_item = proto_tree_add_item(tree, hf_lbtru_nak, tvb, offset, -1, ENC_NA);
    nak_tree = proto_item_add_subtree(nak_item, ett_lbtru_nak);
    num_naks = tvb_get_ntohs(tvb, offset + O_LBTRU_NAK_HDR_T_NUM_NAKS);
    proto_tree_add_item(nak_tree, hf_lbtru_nak_num, tvb, offset + O_LBTRU_NAK_HDR_T_NUM_NAKS, L_LBTRU_NAK_HDR_T_NUM_NAKS, ENC_BIG_ENDIAN);
    proto_tree_add_item(nak_tree, hf_lbtru_nak_format, tvb, offset + O_LBTRU_NAK_HDR_T_FORMAT, L_LBTRU_NAK_HDR_T_FORMAT, ENC_BIG_ENDIAN);
    len_dissected = L_LBTRU_NAK_HDR_T;
    if (!lbtru_expert_separate_naks)
    {
        expert_add_info(pinfo, nak_item, &ei_lbtru_analysis_nak);
    }
    tap_info->num_sqns = num_naks;
    tap_info->sqns = wmem_alloc_array(wmem_packet_scope(), guint32, num_naks);
    len_dissected += dissect_lbtru_nak_list(tvb, offset + L_LBTRU_NAK_HDR_T, pinfo, nak_tree, num_naks, tap_info);
    proto_item_set_len(nak_item, len_dissected);
    return (len_dissected);
}

/*----------------------------------------------------------------------------*/
/* LBT-RU session message packet dissection function.                         */
/*----------------------------------------------------------------------------*/
static int dissect_lbtru_sm(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, int syn, lbm_lbtru_tap_info_t * tap_info)
{
    proto_tree * sm_tree = NULL;
    proto_item * sm_item = NULL;
    proto_item * sm_sqn = NULL;

    sm_item = proto_tree_add_item(tree, hf_lbtru_sm, tvb, offset, L_LBTRU_SM_HDR_T, ENC_NA);
    sm_tree = proto_item_add_subtree(sm_item, ett_lbtru_sm);
    sm_sqn = proto_tree_add_item(sm_tree, hf_lbtru_sm_sqn, tvb, offset + O_LBTRU_SM_HDR_T_SM_SQN, L_LBTRU_SM_HDR_T_SM_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(sm_tree, hf_lbtru_sm_lead_sqn, tvb, offset + O_LBTRU_SM_HDR_T_LEAD_SQN, L_LBTRU_SM_HDR_T_LEAD_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(sm_tree, hf_lbtru_sm_trail_sqn, tvb, offset + O_LBTRU_SM_HDR_T_TRAIL_SQN, L_LBTRU_SM_HDR_T_TRAIL_SQN, ENC_BIG_ENDIAN);
    if (syn)
    {
        expert_add_info(pinfo, sm_sqn, &ei_lbtru_analysis_sm_syn);
    }
    else
    {
        expert_add_info(pinfo, sm_sqn, &ei_lbtru_analysis_sm);
    }
    tap_info->sqn = tvb_get_ntohl(tvb, offset + O_LBTRU_SM_HDR_T_SM_SQN);
    return (L_LBTRU_SM_HDR_T);
}

/*----------------------------------------------------------------------------*/
/* LBT-RU data packet dissection functions.                                   */
/*----------------------------------------------------------------------------*/
static int dissect_lbtru_data(tvbuff_t * tvb, int offset, packet_info * pinfo _U_, proto_tree * tree, lbm_lbtru_tap_info_t * tap_info)
{
    proto_tree * data_tree = NULL;
    proto_item * data_item = NULL;

    data_item = proto_tree_add_item(tree, hf_lbtru_data, tvb, offset, L_LBTRU_DATA_HDR_T, ENC_NA);
    data_tree = proto_item_add_subtree(data_item, ett_lbtru_data);
    proto_tree_add_item(data_tree, hf_lbtru_data_sqn, tvb, offset + O_LBTRU_DATA_HDR_T_SQN, L_LBTRU_DATA_HDR_T_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(data_tree, hf_lbtru_data_trail_sqn, tvb, offset + O_LBTRU_DATA_HDR_T_TRAIL_SQN, L_LBTRU_DATA_HDR_T_TRAIL_SQN, ENC_BIG_ENDIAN);
    tap_info->sqn = tvb_get_ntohl(tvb, offset + O_LBTRU_DATA_HDR_T_SQN);
    return (L_LBTRU_DATA_HDR_T);
}

/*----------------------------------------------------------------------------*/
/* LBT-RU packet dissector.                                                   */
/*----------------------------------------------------------------------------*/
typedef struct
{
    proto_tree * tree;
    tvbuff_t * tvb;
    guint32 current_frame;
} lbtru_sqn_frame_list_callback_data_t;

static gboolean dissect_lbtru_sqn_frame_list_callback(const void *key _U_, void * frame, void * user_data)
{
    lbtru_sqn_frame_list_callback_data_t * cb_data = (lbtru_sqn_frame_list_callback_data_t *) user_data;
    proto_item * transport_item = NULL;
    lbm_transport_sqn_frame_t * sqn_frame = (lbm_transport_sqn_frame_t *) frame;

    if (sqn_frame->frame != cb_data->current_frame)
    {
        if (sqn_frame->retransmission)
        {
            transport_item = proto_tree_add_uint_format_value(cb_data->tree, hf_lbtru_analysis_sqn_frame, cb_data->tvb, 0, 0, sqn_frame->frame, "%" PRIu32 " (RX)", sqn_frame->frame);
        }
        else
        {
            transport_item = proto_tree_add_uint(cb_data->tree, hf_lbtru_analysis_sqn_frame, cb_data->tvb, 0, 0, sqn_frame->frame);
        }
        proto_item_set_generated(transport_item);
    }
    return (FALSE);
}

static int dissect_lbtru(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data _U_)
{
    proto_tree * lbtru_tree = NULL;
    proto_item * lbtru_item = NULL;
    static int * const flags_data[] =
    {
        &hf_lbtru_hdr_flags_rx,
        NULL
    };
    static int * const flags_sm[] =
    {
        &hf_lbtru_hdr_flags_syn,
        NULL
    };
    int ofs = 0;
    guint32 session_id = 0;
    char * tag_name = NULL;
    int dissected_len;
    int total_dissected_len = 0;
    proto_tree * header_tree = NULL;
    proto_item * header_item = NULL;
    proto_tree * transport_tree = NULL;
    proto_item * transport_item = NULL;
    gboolean from_source = TRUE;
    guint8 packet_type = 0;
    address source_address;
    address receiver_address;
    guint16 source_port = 0;
    guint16 receiver_port = 0;
    lbtru_transport_t * transport = NULL;
    lbtru_client_transport_t * client = NULL;
    guint64 channel = LBM_CHANNEL_NO_CHANNEL;
    proto_tree * channel_tree = NULL;
    proto_item * channel_item = NULL;
    guint8 ver_type = 0;
    guint8 next_hdr = 0;
    guint32 packet_sqn = 0;
    guint16 flags_or_res = 0;
    guint16 num_naks = 0;
    guint16 num_ncfs = 0;
    gboolean retransmission = FALSE;
    proto_item * fld_item = NULL;
    proto_item * ei_item = NULL;
    proto_item * type_item = NULL;
    proto_item * next_hdr_item = NULL;
    lbm_lbtru_tap_info_t * tapinfo = NULL;

    col_add_str(pinfo->cinfo, COL_PROTOCOL, "LBT-RU");
    if (lbtru_use_tag)
    {
        tag_name = lbtru_tag_find(pinfo);
    }
    col_clear(pinfo->cinfo, COL_INFO);
    if (tag_name != NULL)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "[Tag: %s]", tag_name);
    }
    col_set_fence(pinfo->cinfo, COL_INFO);

    ver_type = tvb_get_guint8(tvb, O_LBTRU_HDR_T_VER_TYPE);
    next_hdr = tvb_get_guint8(tvb, O_LBTRU_HDR_T_NEXT_HDR);
    flags_or_res = tvb_get_ntohs(tvb, O_LBTRU_HDR_T_FLAGS_OR_RES);
    packet_type = LBTRU_HDR_TYPE(ver_type);
    if (tag_name != NULL)
    {
        lbtru_item = proto_tree_add_protocol_format(tree, proto_lbtru, tvb, ofs, -1, "LBT-RU Protocol (Tag: %s): Version %u, Type %s", tag_name,
            LBTRU_HDR_VER(ver_type), val_to_str(LBTRU_HDR_TYPE(ver_type), lbtru_packet_type, "Unknown (0x%02x)"));
    }
    else
    {
        lbtru_item = proto_tree_add_protocol_format(tree, proto_lbtru, tvb, ofs, -1, "LBT-RU Protocol: Version %u, Type %s", LBTRU_HDR_VER(ver_type),
            val_to_str(LBTRU_HDR_TYPE(ver_type), lbtru_packet_type, "Unknown (0x%02x)"));
    }
    lbtru_tree = proto_item_add_subtree(lbtru_item, ett_lbtru);
    if (tag_name != NULL)
    {
        proto_item * item = NULL;
        item = proto_tree_add_string(lbtru_tree, hf_lbtru_tag, tvb, 0, 0, tag_name);
        proto_item_set_generated(item);
    }
    channel_item = proto_tree_add_item(lbtru_tree, hf_lbtru_channel, tvb, 0, 0, ENC_NA);
    proto_item_set_generated(channel_item);
    channel_tree = proto_item_add_subtree(channel_item, ett_lbtru_channel);

    tapinfo = wmem_new0(wmem_packet_scope(), lbm_lbtru_tap_info_t);
    tapinfo->type = packet_type;

    header_item = proto_tree_add_item(lbtru_tree, hf_lbtru_hdr, tvb, 0, -1, ENC_NA);
    header_tree = proto_item_add_subtree(header_item, ett_lbtru_hdr);
    proto_tree_add_item(header_tree, hf_lbtru_hdr_ver, tvb, O_LBTRU_HDR_T_VER_TYPE, L_LBTRU_HDR_T_VER_TYPE, ENC_BIG_ENDIAN);
    type_item = proto_tree_add_item(header_tree, hf_lbtru_hdr_type, tvb, O_LBTRU_HDR_T_VER_TYPE, L_LBTRU_HDR_T_VER_TYPE, ENC_BIG_ENDIAN);
    next_hdr_item = proto_tree_add_item(header_tree, hf_lbtru_hdr_next_hdr, tvb, O_LBTRU_HDR_T_NEXT_HDR, L_LBTRU_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    total_dissected_len = L_LBTRU_HDR_T_VER_TYPE + L_LBTRU_HDR_T_NEXT_HDR;
    ofs = L_LBTRU_HDR_T_VER_TYPE + L_LBTRU_HDR_T_NEXT_HDR;

    switch (packet_type)
    {
        case LBTRU_PACKET_TYPE_DATA:
            packet_sqn = tvb_get_ntohl(tvb, L_LBTRU_HDR_T + O_LBTRU_DATA_HDR_T_SQN);
            if ((flags_or_res & LBTRU_RETRANSMISSION_FLAG) != 0)
            {
                retransmission = TRUE;
                tapinfo->retransmission = TRUE;
            }
            if (retransmission)
            {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "DATA(RX) sqn 0x%x", packet_sqn);
            }
            else
            {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "DATA sqn 0x%x", packet_sqn);
            }
            from_source = TRUE;
            break;
        case LBTRU_PACKET_TYPE_SM:
            packet_sqn = tvb_get_ntohl(tvb, L_LBTRU_HDR_T + O_LBTRU_SM_HDR_T_SM_SQN);
            if ((flags_or_res & LBTRU_SM_SYN_FLAG) != 0)
            {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SM sqn 0x%x SYN", packet_sqn);
            }
            else
            {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SM sqn 0x%x", packet_sqn);
            }
            from_source = TRUE;
            break;
        case LBTRU_PACKET_TYPE_NAK:
            num_naks = tvb_get_ntohs(tvb, L_LBTRU_HDR_T + O_LBTRU_NAK_HDR_T_NUM_NAKS);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "NAK %" PRIu16 " naks", num_naks);
            from_source = FALSE;
            break;
        case LBTRU_PACKET_TYPE_NCF:
            num_ncfs = tvb_get_ntohs(tvb, L_LBTRU_HDR_T + O_LBTRU_NCF_HDR_T_NUM_NCFS);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "NCF %" PRIu16 " ncfs", num_ncfs);
            from_source = TRUE;
            break;
        case LBTRU_PACKET_TYPE_ACK:
            packet_sqn = tvb_get_ntohl(tvb, L_LBTRU_HDR_T + O_LBTRU_ACK_HDR_T_ACK_SQN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "ACK sqn 0x%x", packet_sqn);
            from_source = FALSE;
            break;
        case LBTRU_PACKET_TYPE_CREQ:
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "CREQ %s", val_to_str(flags_or_res, lbtru_creq_request, "Unknown (0x%02x)"));
            from_source = FALSE;
            break;
        case LBTRU_PACKET_TYPE_RST:
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "RST %s", val_to_str(flags_or_res, lbtru_rst_reason, "Unknown (0x%02x)"));
            from_source = TRUE;
            break;
        default:
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ",  "Unknown (0x%02x)", LBTRU_HDR_TYPE(ver_type));
            expert_add_info_format(pinfo, type_item, &ei_lbtru_analysis_unknown_type, "Unrecognized type 0x%02x", LBTRU_HDR_TYPE(ver_type));
            return (total_dissected_len);
            break;
    }

    /* Handle the flags_or_res field. */
    switch (packet_type)
    {
        case LBTRU_PACKET_TYPE_DATA:
            proto_tree_add_bitmask(header_tree, tvb, O_LBTRU_HDR_T_FLAGS_OR_RES, hf_lbtru_hdr_flags, ett_lbtru_hdr_flags, flags_data, ENC_BIG_ENDIAN);
            total_dissected_len += L_LBTRU_HDR_T_FLAGS_OR_RES;
            ofs += L_LBTRU_HDR_T_FLAGS_OR_RES;
            break;
        case LBTRU_PACKET_TYPE_NAK:
        case LBTRU_PACKET_TYPE_NCF:
        case LBTRU_PACKET_TYPE_ACK:
            proto_tree_add_item(header_tree, hf_lbtru_hdr_res, tvb, O_LBTRU_HDR_T_FLAGS_OR_RES, L_LBTRU_HDR_T_FLAGS_OR_RES, ENC_BIG_ENDIAN);
            total_dissected_len += L_LBTRU_HDR_T_FLAGS_OR_RES;
            ofs += L_LBTRU_HDR_T_FLAGS_OR_RES;
            break;
        case LBTRU_PACKET_TYPE_SM:
            proto_tree_add_bitmask(header_tree, tvb, O_LBTRU_HDR_T_FLAGS_OR_RES, hf_lbtru_hdr_flags, ett_lbtru_hdr_flags, flags_sm, ENC_BIG_ENDIAN);
            total_dissected_len += L_LBTRU_HDR_T_FLAGS_OR_RES;
            ofs += L_LBTRU_HDR_T_FLAGS_OR_RES;
            break;
        case LBTRU_PACKET_TYPE_CREQ:
            ei_item = proto_tree_add_item(header_tree, hf_lbtru_hdr_request, tvb, O_LBTRU_HDR_T_FLAGS_OR_RES, L_LBTRU_HDR_T_FLAGS_OR_RES, ENC_BIG_ENDIAN);
            expert_add_info_format(pinfo, ei_item, &ei_lbtru_analysis_creq, "CREQ %s", val_to_str(flags_or_res, lbtru_creq_request, "Unknown (0x%04x)"));
            total_dissected_len += L_LBTRU_HDR_T_FLAGS_OR_RES;
            ofs += L_LBTRU_HDR_T_FLAGS_OR_RES;
            break;
        case LBTRU_PACKET_TYPE_RST:
            ei_item = proto_tree_add_item(header_tree, hf_lbtru_hdr_reason, tvb, O_LBTRU_HDR_T_FLAGS_OR_RES, L_LBTRU_HDR_T_FLAGS_OR_RES, ENC_BIG_ENDIAN);
            expert_add_info_format(pinfo, ei_item, &ei_lbtru_analysis_rst, "RST %s", val_to_str(flags_or_res, lbtru_rst_reason, "Unknown (0x%04x)"));
            break;
        default:
            break;
    }

    /* Handle the packet-specific data */
    switch (packet_type)
    {
        case LBTRU_PACKET_TYPE_DATA:
            dissected_len = dissect_lbtru_data(tvb, L_LBTRU_HDR_T, pinfo, lbtru_tree, tapinfo);
            break;
        case LBTRU_PACKET_TYPE_SM:
            dissected_len = dissect_lbtru_sm(tvb, L_LBTRU_HDR_T, pinfo, lbtru_tree, (flags_or_res & LBTRU_SM_SYN_FLAG), tapinfo);
            break;
        case LBTRU_PACKET_TYPE_NAK:
            dissected_len = dissect_lbtru_nak(tvb, ofs, pinfo, lbtru_tree, tapinfo);
            break;
        case LBTRU_PACKET_TYPE_NCF:
            dissected_len = dissect_lbtru_ncf(tvb, ofs, pinfo, lbtru_tree, tapinfo);
            break;
        case LBTRU_PACKET_TYPE_ACK:
            dissected_len = dissect_lbtru_ack(tvb, ofs, pinfo, lbtru_tree, tapinfo);
            break;
        case LBTRU_PACKET_TYPE_CREQ:
            dissected_len = 0;
            tapinfo->creq_type = flags_or_res;
            break;
        case LBTRU_PACKET_TYPE_RST:
            dissected_len = 0;
            tapinfo->rst_type = flags_or_res;
            break;
        default:
            dissected_len = 0;
            break;
    }
    total_dissected_len += dissected_len;
    ofs += dissected_len;
    /* If we're doing sequence analysis, the tree goes here. */
    if (lbtru_sequence_analysis)
    {
        transport_item = proto_tree_add_item(lbtru_tree, hf_lbtru_analysis, tvb, 0, 0, ENC_NA);
        proto_item_set_generated(transport_item);
        transport_tree = proto_item_add_subtree(transport_item, ett_lbtru_transport);
    }
    while (next_hdr != LBTRU_NHDR_DATA)
    {
        proto_item * hdr_length_item;
        proto_tree * opt_tree = NULL;
        static int * const sid_flags[] =
        {
            &hf_lbtru_opt_sid_flags_ignore,
            NULL
        };
        static int * const cid_flags[] =
        {
            &hf_lbtru_opt_cid_flags_ignore,
            NULL
        };
        int hdrlen;
        guint8 cur_next_hdr;

        cur_next_hdr = tvb_get_guint8(tvb, ofs + O_LBTRU_BASIC_OPT_T_NEXT_HDR);
        hdrlen = (int)tvb_get_guint8(tvb, ofs + O_LBTRU_BASIC_OPT_T_HDR_LEN);
        switch (next_hdr)
        {
            case LBTRU_NHDR_SID:
                fld_item = proto_tree_add_item(lbtru_tree, hf_lbtru_opt_sid, tvb, ofs, L_LBTRU_BASIC_OPT_T + L_LBTRU_SID_OPT_T, ENC_NA);
                opt_tree = proto_item_add_subtree(fld_item, ett_lbtru_opt);
                next_hdr_item = proto_tree_add_item(opt_tree, hf_lbtru_opt_sid_next_hdr, tvb, ofs + O_LBTRU_BASIC_OPT_T_NEXT_HDR, L_LBTRU_BASIC_OPT_T_NEXT_HDR, ENC_BIG_ENDIAN);
                hdr_length_item = proto_tree_add_item(opt_tree, hf_lbtru_opt_sid_hdr_len, tvb, ofs + O_LBTRU_BASIC_OPT_T_HDR_LEN, L_LBTRU_BASIC_OPT_T_HDR_LEN, ENC_BIG_ENDIAN);
                if (hdrlen == 0)
                {
                    expert_add_info(pinfo, hdr_length_item, &ei_lbtru_analysis_zero_length_header);
                    return (total_dissected_len);
                }
                proto_tree_add_bitmask(opt_tree, tvb, ofs + O_LBTRU_BASIC_OPT_T_RES, hf_lbtru_opt_sid_flags, ett_lbtru_opt_sid_flags, sid_flags, ENC_BIG_ENDIAN);
                proto_tree_add_item(opt_tree, hf_lbtru_opt_sid_session_id, tvb, ofs + L_LBTRU_BASIC_OPT_T + O_LBTRU_SID_OPT_T_SESSION_ID, L_LBTRU_SID_OPT_T_SESSION_ID, ENC_BIG_ENDIAN);
                session_id = tvb_get_ntohl(tvb, ofs + L_LBTRU_BASIC_OPT_T + O_LBTRU_SID_OPT_T_SESSION_ID);
                break;
            case LBTRU_NHDR_CID:
                fld_item = proto_tree_add_item(lbtru_tree, hf_lbtru_opt_cid, tvb, ofs, L_LBTRU_BASIC_OPT_T + L_LBTRU_CID_OPT_T, ENC_NA);
                opt_tree = proto_item_add_subtree(fld_item, ett_lbtru_opt);
                next_hdr_item = proto_tree_add_item(opt_tree, hf_lbtru_opt_cid_next_hdr, tvb, ofs + O_LBTRU_BASIC_OPT_T_NEXT_HDR, L_LBTRU_BASIC_OPT_T_NEXT_HDR, ENC_BIG_ENDIAN);
                hdr_length_item = proto_tree_add_item(opt_tree, hf_lbtru_opt_cid_hdr_len, tvb, ofs + O_LBTRU_BASIC_OPT_T_HDR_LEN, L_LBTRU_BASIC_OPT_T_HDR_LEN, ENC_BIG_ENDIAN);
                if (hdrlen == 0)
                {
                    expert_add_info(pinfo, hdr_length_item, &ei_lbtru_analysis_zero_length_header);
                    return (total_dissected_len);
                }
                proto_tree_add_bitmask(opt_tree, tvb, ofs + O_LBTRU_BASIC_OPT_T_RES, hf_lbtru_opt_cid_flags, ett_lbtru_opt_cid_flags, cid_flags, ENC_BIG_ENDIAN);
                proto_tree_add_item(opt_tree, hf_lbtru_opt_cid_client_id, tvb, ofs + L_LBTRU_BASIC_OPT_T + O_LBTRU_CID_OPT_T_CLIENT_SID, L_LBTRU_CID_OPT_T_CLIENT_SID, ENC_BIG_ENDIAN);
                break;
            default:
                expert_add_info_format(pinfo, next_hdr_item, &ei_lbtru_analysis_unknown_header, "Unrecognized header 0x%02x", next_hdr);
                fld_item = proto_tree_add_item(lbtru_tree, hf_lbtru_opt_unknown, tvb, ofs, L_LBTRU_BASIC_OPT_T + L_LBTRU_CID_OPT_T, ENC_NA);
                opt_tree = proto_item_add_subtree(fld_item, ett_lbtru_opt);
                next_hdr_item = proto_tree_add_item(opt_tree, hf_lbtru_opt_unknown_next_hdr, tvb, ofs + O_LBTRU_BASIC_OPT_T_NEXT_HDR, L_LBTRU_BASIC_OPT_T_NEXT_HDR, ENC_BIG_ENDIAN);
                hdr_length_item = proto_tree_add_item(opt_tree, hf_lbtru_opt_unknown_hdr_len, tvb, ofs + O_LBTRU_BASIC_OPT_T_HDR_LEN, L_LBTRU_BASIC_OPT_T_HDR_LEN, ENC_BIG_ENDIAN);
                if (hdrlen == 0)
                {
                    expert_add_info(pinfo, hdr_length_item, &ei_lbtru_analysis_zero_length_header);
                    return (total_dissected_len);
                }
                break;
        }
        next_hdr = cur_next_hdr;
        ofs += hdrlen;
        total_dissected_len += hdrlen;
    }

    /* Find (or create) the transport and client entries */
    if (from_source)
    {
        copy_address_shallow(&source_address, &(pinfo->src));
        source_port = pinfo->srcport;
        copy_address_shallow(&receiver_address, &(pinfo->dst));
        receiver_port = pinfo->destport;
    }
    else
    {
        copy_address_shallow(&source_address, &(pinfo->dst));
        source_port = pinfo->destport;
        copy_address_shallow(&receiver_address, &(pinfo->src));
        receiver_port = pinfo->srcport;
    }
    if (pinfo->fd->visited == 0)
    {
        transport = lbtru_transport_add(&source_address, source_port, session_id, pinfo->num);
    }
    else
    {
        transport = lbtru_transport_find(&source_address, source_port, session_id, pinfo->num);
    }
    if (transport != NULL)
    {
        if (pinfo->fd->visited == 0)
        {
            client = lbtru_client_transport_add(transport, &receiver_address, receiver_port, pinfo->num);
            if (client != NULL)
            {
                if (lbtru_sequence_analysis)
                {
                    lbtru_client_transport_frame_add(client, packet_type, pinfo->num, packet_sqn, retransmission);
                }
            }
        }
        else
        {
            client = lbtru_client_transport_find(transport, &receiver_address, receiver_port, pinfo->num);
        }
        tapinfo->transport = lbtru_transport_source_string_transport(transport);
        channel = transport->channel;
        fld_item = proto_tree_add_uint64(channel_tree, hf_lbtru_channel_id, tvb, 0, 0, channel);
        proto_item_set_generated(fld_item);
        if (client != NULL)
        {
            fld_item = proto_tree_add_uint(channel_tree, hf_lbtru_channel_client, tvb, 0, 0, client->id);
            proto_item_set_generated(fld_item);
        }
    }
    proto_item_set_len(lbtru_item, total_dissected_len);
    if ((packet_type == LBTRU_PACKET_TYPE_DATA) && (next_hdr == LBTRU_NHDR_DATA))
    {
        total_dissected_len += dissect_lbtru_data_contents(tvb, ofs, pinfo, tree, tag_name, channel);
    }
    if (lbtru_sequence_analysis)
    {
        if ((transport != NULL) && (client != NULL))
        {
            lbm_transport_frame_t * frame = NULL;

            /* Fill in the tree */
            frame = lbtru_client_transport_frame_find(client, pinfo->num);
            if (frame != NULL)
            {
                lbm_transport_sqn_t * sqn = NULL;

                if (frame->previous_frame != 0)
                {
                    transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_prev_frame, tvb, 0, 0, frame->previous_frame);
                    proto_item_set_generated(transport_item);
                }
                if (frame->next_frame != 0)
                {
                    transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_next_frame, tvb, 0, 0, frame->next_frame);
                    proto_item_set_generated(transport_item);
                }
                switch (packet_type)
                {
                    case LBTRU_PACKET_TYPE_DATA:
                        if (frame->previous_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_prev_data_frame, tvb, 0, 0, frame->previous_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        if (frame->next_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_next_data_frame, tvb, 0, 0, frame->next_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        sqn = lbtru_client_transport_sqn_find(client, packet_type, packet_sqn);
                        if (sqn != NULL)
                        {
                            if (sqn->frame_count > 1)
                            {
                                proto_tree * frame_tree = NULL;
                                proto_item * frame_tree_item = NULL;
                                lbtru_sqn_frame_list_callback_data_t cb_data;

                                frame_tree_item = proto_tree_add_item(transport_tree, hf_lbtru_analysis_sqn, tvb, 0, 0, ENC_NA);
                                proto_item_set_generated(frame_tree_item);
                                frame_tree = proto_item_add_subtree(frame_tree_item, ett_lbtru_transport_sqn);
                                cb_data.tree = frame_tree;
                                cb_data.tvb = tvb;
                                cb_data.current_frame = pinfo->num;
                                wmem_tree_foreach(sqn->frame, dissect_lbtru_sqn_frame_list_callback, (void *) &cb_data);
                            }
                        }
                        if (frame->retransmission)
                        {
                            transport_item = proto_tree_add_boolean(transport_tree, hf_lbtru_analysis_data_retransmission, tvb, 0, 0, TRUE);
                            proto_item_set_generated(transport_item);
                            expert_add_info(pinfo, transport_item, &ei_lbtru_analysis_data_rx);
                        }
                        if (frame->sqn_gap != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_data_sqn_gap, tvb, 0, 0, frame->sqn_gap);
                            proto_item_set_generated(transport_item);
                            expert_add_info_format(pinfo, transport_item, &ei_lbtru_analysis_data_gap, "Data sequence gap (%" PRIu32 ")", frame->sqn_gap);

                        }
                        if (frame->ooo_gap != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_data_ooo_gap, tvb, 0, 0, frame->ooo_gap);
                            proto_item_set_generated(transport_item);
                            expert_add_info_format(pinfo, transport_item, &ei_lbtru_analysis_data_ooo, "Data sequence out of order gap (%" PRIu32 ")", frame->ooo_gap);
                        }
                        if (frame->duplicate)
                        {
                            transport_item = proto_tree_add_boolean(transport_tree, hf_lbtru_analysis_data_duplicate, tvb, 0, 0, TRUE);
                            proto_item_set_generated(transport_item);
                            expert_add_info(pinfo, transport_item, &ei_lbtru_analysis_data_dup);
                        }
                        break;
                    case LBTRU_PACKET_TYPE_SM:
                        if (frame->previous_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_prev_sm_frame, tvb, 0, 0, frame->previous_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        if (frame->next_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_next_sm_frame, tvb, 0, 0, frame->next_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        sqn = lbtru_client_transport_sqn_find(client, packet_type, packet_sqn);
                        if (sqn != NULL)
                        {
                            if (sqn->frame_count > 1)
                            {
                                proto_tree * frame_tree = NULL;
                                proto_item * frame_tree_item = NULL;
                                lbtru_sqn_frame_list_callback_data_t cb_data;

                                frame_tree_item = proto_tree_add_item(transport_tree, hf_lbtru_analysis_sqn, tvb, 0, 0, ENC_NA);
                                proto_item_set_generated(frame_tree_item);
                                frame_tree = proto_item_add_subtree(frame_tree_item, ett_lbtru_transport_sqn);
                                cb_data.tree = frame_tree;
                                cb_data.tvb = tvb;
                                cb_data.current_frame = pinfo->num;
                                wmem_tree_foreach(sqn->frame, dissect_lbtru_sqn_frame_list_callback, (void *) &cb_data);
                            }
                        }
                        if (frame->sqn_gap != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_sm_sqn_gap, tvb, 0, 0, frame->sqn_gap);
                            proto_item_set_generated(transport_item);
                            expert_add_info_format(pinfo, transport_item, &ei_lbtru_analysis_sm_gap, "SM sequence gap (%" PRIu32 ")", frame->sqn_gap);

                        }
                        if (frame->ooo_gap != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_sm_ooo_gap, tvb, 0, 0, frame->ooo_gap);
                            proto_item_set_generated(transport_item);
                            expert_add_info_format(pinfo, transport_item, &ei_lbtru_analysis_sm_ooo, "SM sequence out of order gap (%" PRIu32 ")", frame->ooo_gap);
                        }
                        if (frame->duplicate)
                        {
                            transport_item = proto_tree_add_boolean(transport_tree, hf_lbtru_analysis_sm_duplicate, tvb, 0, 0, TRUE);
                            proto_item_set_generated(transport_item);
                            expert_add_info(pinfo, transport_item, &ei_lbtru_analysis_sm_dup);
                        }
                        break;
                    case LBTRU_PACKET_TYPE_NAK:
                        if (frame->previous_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_prev_nak_frame, tvb, 0, 0, frame->previous_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        if (frame->next_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_next_nak_frame, tvb, 0, 0, frame->next_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        break;
                    case LBTRU_PACKET_TYPE_NCF:
                        if (frame->previous_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_prev_ncf_frame, tvb, 0, 0, frame->previous_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        if (frame->next_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_next_ncf_frame, tvb, 0, 0, frame->next_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        break;
                    case LBTRU_PACKET_TYPE_ACK:
                        if (frame->previous_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_prev_ack_frame, tvb, 0, 0, frame->previous_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        if (frame->next_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_next_ack_frame, tvb, 0, 0, frame->next_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        break;
                    case LBTRU_PACKET_TYPE_CREQ:
                        if (frame->previous_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_prev_creq_frame, tvb, 0, 0, frame->previous_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        if (frame->next_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_next_creq_frame, tvb, 0, 0, frame->next_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        break;
                    case LBTRU_PACKET_TYPE_RST:
                        if (frame->previous_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_prev_rst_frame, tvb, 0, 0, frame->previous_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        if (frame->next_type_frame != 0)
                        {
                            transport_item = proto_tree_add_uint(transport_tree, hf_lbtru_analysis_next_rst_frame, tvb, 0, 0, frame->next_type_frame);
                            proto_item_set_generated(transport_item);
                        }
                        break;
                    default:
                        break;
                }
            }
        }
    }
    if (tapinfo->transport != NULL)
    {
        tap_queue_packet(lbtru_tap_handle, pinfo, (void *) tapinfo);
    }
    return (total_dissected_len);
}

static gboolean test_lbtru_packet(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data)
{
    gboolean valid_packet = FALSE;

    /* Must be a UDP packet. */
    if (pinfo->ptype != PT_UDP)
    {
        return (FALSE);
    }
    /* Destination address must be IPV4 and 4 bytes in length. */
    if ((pinfo->dst.type != AT_IPv4) || (pinfo->dst.len != 4))
    {
        return (FALSE);
    }

    if (lbtru_use_tag)
    {
        if (lbtru_tag_find(pinfo) != NULL)
        {
            valid_packet = TRUE;
        }
    }
    else
    {
        /*
            Source port must be in the source port range and destination port must be in the receiver port range,
            or vice-versa.
        */
        if (((pinfo->destport >= lbtru_source_port_low)
             && (pinfo->destport <= lbtru_source_port_high)
             && (pinfo->srcport >= lbtru_receiver_port_low)
             && (pinfo->srcport <= lbtru_receiver_port_high))
            || ((pinfo->destport >= lbtru_receiver_port_low)
                && (pinfo->destport <= lbtru_receiver_port_high)
                && (pinfo->srcport >= lbtru_source_port_low)
                && (pinfo->srcport <= lbtru_source_port_high)))
        {
            /* One of ours. */
            valid_packet = TRUE;
        }
    }
    if (valid_packet)
    {
        dissect_lbtru(tvb, pinfo, tree, user_data);
        return (TRUE);
    }
    /* Not one of ours. */
    return (FALSE);
}

/* Register all the bits needed with the filtering engine */
void proto_register_lbtru(void)
{
    static hf_register_info hf[] =
    {
        { &hf_lbtru_channel,
            { "Channel", "lbtru.channel", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_channel_id,
            { "Channel ID", "lbtru.channel.channel", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_channel_client,
            { "Channel Client", "lbtru.channel.client", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_tag,
            { "Tag", "lbtru.tag", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_hdr,
            { "Header", "lbtru.hdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_hdr_ver,
            { "Version", "lbtru.hdr.ver", FT_UINT8, BASE_DEC, NULL, LBTRU_HDR_VER_VER_MASK, NULL, HFILL } },
        { &hf_lbtru_hdr_type,
            { "Type", "lbtru.hdr.type", FT_UINT8, BASE_HEX, VALS(lbtru_packet_type), LBTRU_HDR_VER_TYPE_MASK, NULL, HFILL } },
        { &hf_lbtru_hdr_next_hdr,
            { "Next Header", "lbtru.hdr.next_hdr", FT_UINT8, BASE_HEX, VALS(lbtru_next_header), 0x0, NULL, HFILL } },
        { &hf_lbtru_hdr_res,
            { "Reserved", "lbtru.hdr.res", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_hdr_flags,
            { "Flags", "lbtru.hdr.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_hdr_flags_rx,
            { "Retransmission", "lbtru.hdr.flags.rx", FT_BOOLEAN, L_LBTRU_HDR_T_FLAGS_OR_RES * 8, TFS(&tfs_set_notset), LBTRU_RETRANSMISSION_FLAG, NULL, HFILL } },
        { &hf_lbtru_hdr_flags_syn,
            { "SYN", "lbtru.hdr.flags.syn", FT_BOOLEAN, L_LBTRU_HDR_T_FLAGS_OR_RES * 8, TFS(&tfs_set_notset), LBTRU_SM_SYN_FLAG, NULL, HFILL } },
        { &hf_lbtru_hdr_request,
            { "Request", "lbtru.hdr.request", FT_UINT16, BASE_HEX, VALS(lbtru_creq_request), 0x0, NULL, HFILL } },
        { &hf_lbtru_hdr_reason,
            { "Reason", "lbtru.hdr.reason", FT_UINT16, BASE_HEX, VALS(lbtru_rst_reason), 0x0, NULL, HFILL } },
        { &hf_lbtru_data,
            { "Data Header", "lbtru.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_data_sqn,
            { "Sequence Number", "lbtru.data.sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_data_trail_sqn,
            { "Trailing Edge Sequence Number", "lbtru.data.trail", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_sm,
            { "Session Message Header", "lbtru.sm", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_sm_sqn,
            { "Sequence Number", "lbtru.sm.sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_sm_lead_sqn,
            { "Leading Edge Sequence Number", "lbtru.sm.lead", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_sm_trail_sqn,
            { "Trailing Edge Sequence Number", "lbtru.sm.trail", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_nak,
            { "NAK Header", "lbtru.nak", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_nak_num,
            { "Number of NAKs", "lbtru.nak.num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_nak_format,
            { "Format", "lbtru.nak.format", FT_UINT16, BASE_DEC, VALS(lbtru_nak_format), LBTRU_NAK_HDR_FORMAT_MASK, NULL, HFILL } },
        { &hf_lbtru_nak_list,
            { "NAK List", "lbtru.nak.list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_nak_list_nak,
            { "NAK", "lbtru.nak.list.nak", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_ncf,
            { "NAK Confirmation Header", "lbtru.ncf", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_ncf_trail_sqn,
            { "Trailing Edge Sequence Number", "lbtru.ncf.trail", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_ncf_num,
            { "Number of Individual NCFs", "lbtru.ncf.num", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_ncf_reserved,
            { "Reserved", "lbtru.ncf.reserved", FT_UINT8, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_ncf_reason,
            { "Reason", "lbtru.ncf.reason", FT_UINT8, BASE_HEX, VALS(lbtru_ncf_reason), LBTRU_NCF_HDR_REASON_MASK, NULL, HFILL } },
        { &hf_lbtru_ncf_format,
            { "Format", "lbtru.ncf.format", FT_UINT8, BASE_HEX, VALS(lbtru_ncf_format), LBTRU_NCF_HDR_FORMAT_MASK, NULL, HFILL } },
        { &hf_lbtru_ncf_list,
            { "NCF List", "lbtru.ncf.list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_ncf_list_ncf,
            { "NCF", "lbtru.ncf.list.ncf", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_ack,
            { "ACK Header", "lbtru.ack", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_ack_sqn,
            { "ACK Sequence Number", "lbtru.ack.sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_sid,
            { "SID Option", "lbtru.opt_sid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_sid_next_hdr,
            { "Next Header", "lbtru.opt_sid.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbtru_next_header), 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_sid_hdr_len,
            { "Header Length", "lbtru.opt_sid.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_sid_flags,
            { "Flags", "lbtru.opt_sid.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_sid_flags_ignore,
            { "Ignore", "lbtru.opt_sid.flags.ignore", FT_BOOLEAN, L_LBTRU_BASIC_OPT_T_RES * 8, &(tfs_set_notset), LBTRU_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbtru_opt_sid_session_id,
            { "Session ID", "lbtru.opt_sid.session_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_cid,
            { "CID Option", "lbtru.opt_cid", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_cid_next_hdr,
            { "Next Header", "lbtru.opt_cid.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbtru_next_header), 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_cid_hdr_len,
            { "Header Length", "lbtru.opt_cid.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_cid_flags,
            { "Flags", "lbtru.opt_cid.flags", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_cid_flags_ignore,
            { "Ignore", "lbtru.opt_cid.flags.ignore", FT_BOOLEAN, L_LBTRU_BASIC_OPT_T_RES * 8, &(tfs_set_notset), LBTRU_OPT_IGNORE, NULL, HFILL } },
        { &hf_lbtru_opt_cid_client_id,
            { "Client ID", "lbtru.opt_cid.client_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_unknown,
            { "Unknown Option", "lbtru.opt_unknown", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_unknown_next_hdr,
            { "Next Header", "lbtru.opt_unknown.next_hdr", FT_UINT8, BASE_DEC_HEX, VALS(lbtru_next_header), 0x0, NULL, HFILL } },
        { &hf_lbtru_opt_unknown_hdr_len,
            { "Header Length", "lbtru.opt_unknown.hdr_len", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis,
            { "Transport Analysis", "lbtru.analysis", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_prev_frame,
            { "Previous Transport Frame", "lbtru.analysis.prev_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_prev_data_frame,
            { "Previous Transport DATA Frame", "lbtru.analysis.prev_data_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_prev_sm_frame,
            { "Previous Transport SM Frame", "lbtru.analysis.prev_sm_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_prev_nak_frame,
            { "Previous Transport NAK Frame", "lbtru.analysis.prev_nak_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_prev_ncf_frame,
            { "Previous Transport NCF Frame", "lbtru.analysis.prev_ncf_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_prev_ack_frame,
            { "Previous Transport ACK Frame", "lbtru.analysis.prev_ack_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_prev_creq_frame,
            { "Previous Transport CREQ Frame", "lbtru.analysis.prev_creq_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_prev_rst_frame,
            { "Previous Transport RST Frame", "lbtru.analysis.prev_rst_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_next_frame,
            { "Next Transport Frame", "lbtru.analysis.next_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_next_data_frame,
            { "Next Transport DATA Frame", "lbtru.analysis.next_data_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_next_sm_frame,
            { "Next Transport SM Frame", "lbtru.analysis.next_sm_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_next_nak_frame,
            { "Next Transport NAK Frame", "lbtru.analysis.next_nak_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_next_ncf_frame,
            { "Next Transport NCF Frame", "lbtru.analysis.next_ncf_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_next_ack_frame,
            { "Next Transport ACK Frame", "lbtru.analysis.next_ack_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_next_creq_frame,
            { "Next Transport CREQ Frame", "lbtru.analysis.next_creq_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_next_rst_frame,
            { "Next Transport RST Frame", "lbtru.analysis.next_rst_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_sqn,
            { "SQN Also in", "lbtru.analysis.sqn", FT_NONE, BASE_NONE, NULL, 0x0, "Sequence number also appears in these frames", HFILL } },
        { &hf_lbtru_analysis_sqn_frame,
            { "Frame", "lbtru.analysis.sqn.frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_data_retransmission,
            { "Frame is a Data Retransmission", "lbtru.analysis.data_retransmission", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_data_sqn_gap,
            { "Gap in Data Sequence", "lbtru.analysis.data_sqn_gap", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_data_ooo_gap,
            { "Data Sequence Out of Order Gap", "lbtru.analysis.data_ooo_gap", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_data_duplicate,
            { "Duplicate Data Frame", "lbtru.analysis.data_duplicate", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_sm_sqn_gap,
            { "Gap in SM Sequence", "lbtru.analysis.sm_sqn_gap", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_sm_ooo_gap,
            { "SM Sequence Out of Order Gap", "lbtru.analysis.sm_ooo_gap", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtru_analysis_sm_duplicate,
            { "Duplicate SM Frame", "lbtru.analysis.sm_duplicate", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };
    static gint * ett[] =
    {
        &ett_lbtru,
        &ett_lbtru_channel,
        &ett_lbtru_hdr,
        &ett_lbtru_hdr_flags,
        &ett_lbtru_data,
        &ett_lbtru_sm,
        &ett_lbtru_nak,
        &ett_lbtru_nak_list,
        &ett_lbtru_ncf,
        &ett_lbtru_ncf_list,
        &ett_lbtru_ack,
        &ett_lbtru_opt,
        &ett_lbtru_opt_sid_flags,
        &ett_lbtru_opt_cid_flags,
        &ett_lbtru_transport,
        &ett_lbtru_transport_sqn,
    };
    static ei_register_info ei[] =
    {
        { &ei_lbtru_analysis_unknown_type, { "lbtru.analysis.unknown_type", PI_MALFORMED, PI_ERROR, "Unrecognized type", EXPFILL } },
        { &ei_lbtru_analysis_unknown_header, { "lbtru.analysis.unknown_header", PI_MALFORMED, PI_ERROR, "Unrecognized header", EXPFILL } },
        { &ei_lbtru_analysis_zero_length_header, { "lbtru.analysis.zero_length_header", PI_MALFORMED, PI_ERROR, "Zero-length header", EXPFILL } },
        { &ei_lbtru_analysis_ack, { "lbtru.analysis.ack", PI_SEQUENCE, PI_CHAT, "ACK", EXPFILL } },
        { &ei_lbtru_analysis_ncf, { "lbtru.analysis.ncf", PI_SEQUENCE, PI_NOTE, "NCF", EXPFILL } },
        { &ei_lbtru_analysis_ncf_ncf, { "lbtru.analysis.ncf.ncf", PI_SEQUENCE, PI_NOTE, "NCF", EXPFILL } },
        { &ei_lbtru_analysis_nak, { "lbtru.analysis.nak", PI_SEQUENCE, PI_WARN, "NAK", EXPFILL } },
        { &ei_lbtru_analysis_nak_nak, { "lbtru.analysis.nak.nak", PI_SEQUENCE, PI_WARN, "NAK", EXPFILL } },
        { &ei_lbtru_analysis_sm, { "lbtru.analysis.sm", PI_SEQUENCE, PI_CHAT, "SM", EXPFILL } },
        { &ei_lbtru_analysis_sm_syn, { "lbtru.analysis.sm.syn", PI_SEQUENCE, PI_CHAT, "SM SYN", EXPFILL } },
        { &ei_lbtru_analysis_creq, { "lbtru.analysis.creq", PI_SEQUENCE, PI_CHAT, "Connection REQuest", EXPFILL } },
        { &ei_lbtru_analysis_rst, { "lbtru.analysis.rst", PI_SEQUENCE, PI_CHAT, "ReSeT", EXPFILL } },
        { &ei_lbtru_analysis_data_rx, { "lbtru.analysis.data.rx", PI_SEQUENCE, PI_NOTE, "Data retransmission", EXPFILL } },
        { &ei_lbtru_analysis_data_gap, { "lbtru.analysis.data.gap", PI_SEQUENCE, PI_NOTE, "Data sequence gap", EXPFILL } },
        { &ei_lbtru_analysis_data_ooo, { "lbtru.analysis.data.ooo", PI_SEQUENCE, PI_NOTE, "Data sequence out of order", EXPFILL } },
        { &ei_lbtru_analysis_data_dup, { "lbtru.analysis.data.dup", PI_SEQUENCE, PI_NOTE, "Duplicate data", EXPFILL } },
        { &ei_lbtru_analysis_sm_gap, { "lbtru.analysis.sm.gap", PI_SEQUENCE, PI_NOTE, "SM sequence gap", EXPFILL } },
        { &ei_lbtru_analysis_sm_ooo, { "lbtru.analysis.sm.ooo", PI_SEQUENCE, PI_NOTE, "SM sequence out of order", EXPFILL } },
        { &ei_lbtru_analysis_sm_dup, { "lbtru.analysis.sm.dup", PI_SEQUENCE, PI_NOTE, "Duplicate SM", EXPFILL } },
    };
    module_t * lbtru_module;
    uat_t * tag_uat;
    expert_module_t * expert_lbtru;

    proto_lbtru = proto_register_protocol("LBT Reliable Unicast Protocol",
        "LBT-RU", "lbtru");

    proto_register_field_array(proto_lbtru, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lbtru = expert_register_protocol(proto_lbtru);
    expert_register_field_array(expert_lbtru, ei, array_length(ei));

    lbtru_module = prefs_register_protocol_subtree("29West", proto_lbtru, proto_reg_handoff_lbtru);
    prefs_register_uint_preference(lbtru_module,
        "source_port_low",
        "Source port range low (default " MAKESTRING(LBTRU_DEFAULT_SOURCE_PORT_LOW)")",
        "Set the low end of the LBT-RU source UDP port range (context transport_lbtru_port_low)",
        10,
        &global_lbtru_source_port_low);

    prefs_register_uint_preference(lbtru_module,
        "source_port_high",
        "Source port range high (default " MAKESTRING(LBTRU_DEFAULT_SOURCE_PORT_HIGH)")",
        "Set the high end of the LBT-RU source UDP port range (context transport_lbtru_port_high)",
        10,
        &global_lbtru_source_port_high);

    prefs_register_uint_preference(lbtru_module,
        "receiver_port_low",
        "Receiver port range low (default " MAKESTRING(LBTRU_DEFAULT_RECEIVER_PORT_LOW)")",
        "Set the low end of the LBT-RU receiver UDP port range (receiver transport_lbtru_port_low)",
        10,
        &global_lbtru_receiver_port_low);

    prefs_register_uint_preference(lbtru_module,
        "receiver_port_high",
        "Receiver port range high (default " MAKESTRING(LBTRU_DEFAULT_RECEIVER_PORT_HIGH)")",
        "Set the high end of the LBT-RU receiver UDP port range (receiver transport_lbtru_port_high)",
        10,
        &global_lbtru_receiver_port_high);

    lbtru_expert_separate_naks = global_lbtru_expert_separate_naks;
    prefs_register_bool_preference(lbtru_module,
        "expert_separate_naks",
        "Separate NAKs in Expert Info",
        "Separate multiple NAKs from a single packet into distinct Expert Info entries",
        &global_lbtru_expert_separate_naks);
    lbtru_expert_separate_ncfs = global_lbtru_expert_separate_ncfs;
    prefs_register_bool_preference(lbtru_module,
        "expert_separate_ncfs",
        "Separate NCFs in Expert Info",
        "Separate multiple NCFs from a single packet into distinct Expert Info entries",
        &global_lbtru_expert_separate_ncfs);

    lbtru_sequence_analysis = global_lbtru_sequence_analysis;
    prefs_register_bool_preference(lbtru_module,
        "sequence_analysis",
        "Perform Sequence Number Analysis",
        "Perform analysis on LBT-RU sequence numbers to determine out-of-order, gaps, loss, etc",
        &global_lbtru_sequence_analysis);

    prefs_register_bool_preference(lbtru_module,
        "use_lbtru_domain",
        "Use LBT-RU tag table",
        "Use table of LBT-RU tags to decode the packet instead of above values",
        &global_lbtru_use_tag);
    tag_uat = uat_new("LBT-RU tag definitions",
        sizeof(lbtru_tag_entry_t),
        "lbtru_domains",
        TRUE,
        (void * *)&lbtru_tag_entry,
        &lbtru_tag_count,
        UAT_AFFECTS_DISSECTION,
        NULL,
        lbtru_tag_copy_cb,
        lbtru_tag_update_cb,
        lbtru_tag_free_cb,
        NULL,
        NULL,
        lbtru_tag_array);
    prefs_register_uat_preference(lbtru_module,
        "tnw_lbtru_tags",
        "LBT-RU Tags",
        "A table to define LBT-RU tags",
        tag_uat);
}

/* The registration hand-off routine */
void proto_reg_handoff_lbtru(void)
{
    static gboolean already_registered = FALSE;

    if (!already_registered)
    {
        lbtru_dissector_handle = create_dissector_handle(dissect_lbtru, proto_lbtru);
        dissector_add_for_decode_as_with_preference("udp.port", lbtru_dissector_handle);
        heur_dissector_add("udp", test_lbtru_packet, "LBT Reliable Unicast over UDP", "lbtru_udp", proto_lbtru, HEURISTIC_ENABLE);
        lbtru_tap_handle = register_tap("lbm_lbtru");
    }

    /* Make sure the low source port is <= the high source port. If not, don't change them. */
    if (global_lbtru_source_port_low <= global_lbtru_source_port_high)
    {
        lbtru_source_port_low = global_lbtru_source_port_low;
        lbtru_source_port_high = global_lbtru_source_port_high;
    }

    /* Make sure the low receiver port is <= the high receiver port. If not, don't change them. */
    if (global_lbtru_receiver_port_low <= global_lbtru_receiver_port_high)
    {
        lbtru_receiver_port_low = global_lbtru_receiver_port_low;
        lbtru_receiver_port_high = global_lbtru_receiver_port_high;
    }

    lbtru_expert_separate_naks = global_lbtru_expert_separate_naks;
    lbtru_expert_separate_ncfs = global_lbtru_expert_separate_ncfs;

    lbtru_sequence_analysis = global_lbtru_sequence_analysis;

    lbtru_use_tag = global_lbtru_use_tag;

    already_registered = TRUE;
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
