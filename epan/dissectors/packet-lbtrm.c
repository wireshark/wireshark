/* packet-lbtrm.c
 * Routines for LBT-RM Packet dissection
 *
 * Copyright (c) 2005-2014 Informatica Corporation. All Rights Reserved.
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
#ifdef HAVE_ARPA_INET_H
    #include <arpa/inet.h>
#endif
#if HAVE_WINSOCK2_H
    #include <winsock2.h>
#endif
#include <glib.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/wmem/wmem.h>
#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/to_str.h>
#include <wsutil/inet_aton.h>
#include <wsutil/pint.h>
#include "packet-lbm.h"
#include "packet-lbtrm.h"

void proto_register_lbtrm(void);
void proto_reg_handoff_lbtrm(void);

/* Protocol handle */
static int proto_lbtrm = -1;

/* Dissector handle */
static dissector_handle_t lbtrm_dissector_handle;

/* Tap handle */
static int lbtrm_tap_handle = -1;

/*----------------------------------------------------------------------------*/
/* LBT-RM transport management.                                               */
/*----------------------------------------------------------------------------*/

static const address lbtrm_null_address = { AT_NONE, -1, 0, NULL };

static lbtrm_transport_t * lbtrm_transport_unicast_find(const address * source_address, guint16 source_port, guint32 session_id, guint32 frame)
{
    lbtrm_transport_t * transport = NULL;
    conversation_t * conv = NULL;
    wmem_tree_t * session_tree = NULL;

    conv = find_conversation(frame, source_address, &lbtrm_null_address, PT_UDP, source_port, 0, 0);
    if (conv != NULL)
    {
        if (frame > conv->last_frame)
        {
            conv->last_frame = frame;
        }
        session_tree = (wmem_tree_t *) conversation_get_proto_data(conv, proto_lbtrm);
        if (session_tree != NULL)
        {
            transport = (lbtrm_transport_t *) wmem_tree_lookup32(session_tree, session_id);
        }
    }
    return (transport);
}

static void lbtrm_transport_unicast_add(const address * source_address, guint16 source_port, guint32 session_id, guint32 frame, lbtrm_transport_t * transport)
{
    conversation_t * conv = NULL;
    wmem_tree_t * session_tree = NULL;
    lbtrm_transport_t * transport_entry = NULL;

    conv = find_conversation(frame, source_address, &lbtrm_null_address, PT_UDP, source_port, 0, 0);
    if (conv == NULL)
    {
        conv = conversation_new(frame, source_address, &lbtrm_null_address, PT_UDP, source_port, 0, 0);
    }
    session_tree = (wmem_tree_t *) conversation_get_proto_data(conv, proto_lbtrm);
    if (session_tree == NULL)
    {
        session_tree = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_lbtrm, (void *) session_tree);
    }
    transport_entry = (lbtrm_transport_t *) wmem_tree_lookup32(session_tree, session_id);
    if (transport_entry == NULL)
    {
        wmem_tree_insert32(session_tree, session_id, (void *) transport);
    }
}

static lbtrm_transport_t * lbtrm_transport_find(const address * source_address, guint16 source_port, guint32 session_id, const address * multicast_group, guint16 dest_port, guint32 frame)
{
    lbtrm_transport_t * entry = NULL;
    wmem_tree_t * session_tree = NULL;
    conversation_t * conv = NULL;

    conv = find_conversation(frame, source_address, multicast_group, PT_UDP, source_port, dest_port, 0);
    if (conv != NULL)
    {
        if (frame > conv->last_frame)
        {
            conv->last_frame = frame;
        }
        session_tree = (wmem_tree_t *) conversation_get_proto_data(conv, proto_lbtrm);
        if (session_tree != NULL)
        {
            entry = (lbtrm_transport_t *) wmem_tree_lookup32(session_tree, session_id);
        }
    }
    return (entry);
}

lbtrm_transport_t * lbtrm_transport_add(const address * source_address, guint16 source_port, guint32 session_id, const address * multicast_group, guint16 dest_port, guint32 frame)
{
    lbtrm_transport_t * entry;
    conversation_t * conv = NULL;
    wmem_tree_t * session_tree = NULL;

    conv = find_conversation(frame, source_address, multicast_group, PT_UDP, source_port, dest_port, 0);
    if (conv == NULL)
    {
        conv = conversation_new(frame, source_address, multicast_group, PT_UDP, source_port, dest_port, 0);
    }
    if (frame > conv->last_frame)
    {
        conv->last_frame = frame;
    }
    session_tree = (wmem_tree_t *) conversation_get_proto_data(conv, proto_lbtrm);
    if (session_tree == NULL)
    {
        session_tree = wmem_tree_new(wmem_file_scope());
        conversation_add_proto_data(conv, proto_lbtrm, (void *) session_tree);
    }
    entry = (lbtrm_transport_t *) wmem_tree_lookup32(session_tree, session_id);
    if (entry != NULL)
    {
        return (entry);
    }
    entry = wmem_new(wmem_file_scope(), lbtrm_transport_t);
    SE_COPY_ADDRESS(&(entry->source_address), source_address);
    entry->source_port = source_port;
    entry->session_id = session_id;
    SE_COPY_ADDRESS(&(entry->multicast_group), multicast_group);
    entry->dest_port = dest_port;
    entry->channel = lbm_channel_assign(LBM_CHANNEL_TRANSPORT_LBTRM);
    entry->frame = wmem_tree_new(wmem_file_scope());
    entry->last_frame = NULL;
    entry->last_data_frame = NULL;
    entry->last_sm_frame = NULL;
    entry->last_nak_frame = NULL;
    entry->last_ncf_frame = NULL;
    entry->data_sqn = wmem_tree_new(wmem_file_scope());
    entry->sm_sqn = wmem_tree_new(wmem_file_scope());
    entry->data_high_sqn = 0;
    entry->sm_high_sqn = 0;
    wmem_tree_insert32(session_tree, session_id, (void *) entry);
    lbtrm_transport_unicast_add(source_address, source_port, session_id, frame, entry);
    return (entry);
}

static lbm_transport_sqn_t * lbtrm_transport_sqn_find(lbtrm_transport_t * transport, guint8 type, guint32 sqn)
{
    lbm_transport_sqn_t * sqn_entry = NULL;

    switch (type)
    {
        case LBTRM_PACKET_TYPE_DATA:
            sqn_entry = (lbm_transport_sqn_t *) wmem_tree_lookup32(transport->data_sqn, sqn);
            break;
        case LBTRM_PACKET_TYPE_SM:
            sqn_entry = (lbm_transport_sqn_t *) wmem_tree_lookup32(transport->sm_sqn, sqn);
            break;
        case LBTRM_PACKET_TYPE_NAK:
        case LBTRM_PACKET_TYPE_NCF:
        default:
            sqn_entry = NULL;
            break;
    }
    return (sqn_entry);
}

static lbm_transport_sqn_t * lbtrm_transport_sqn_add(lbtrm_transport_t * transport, lbm_transport_frame_t * frame)
{
    wmem_tree_t * sqn_list = NULL;
    lbm_transport_sqn_t * sqn_entry = NULL;

    switch (frame->type)
    {
        case LBTRM_PACKET_TYPE_DATA:
            sqn_list = transport->data_sqn;
            break;
        case LBTRM_PACKET_TYPE_SM:
            sqn_list = transport->sm_sqn;
            break;
        case LBTRM_PACKET_TYPE_NAK:
        case LBTRM_PACKET_TYPE_NCF:
        default:
            return (NULL);
            break;
    }

    /* Add the sqn. */
    sqn_entry = lbm_transport_sqn_add(sqn_list, frame);
    return (sqn_entry);
}

static lbm_transport_frame_t * lbtrm_transport_frame_find(lbtrm_transport_t * transport, guint32 frame)
{
    return ((lbm_transport_frame_t *) wmem_tree_lookup32(transport->frame, frame));
}

static lbm_transport_frame_t * lbtrm_transport_frame_add(lbtrm_transport_t * transport, guint8 type, guint32 frame, guint32 sqn, gboolean retransmission)
{
    lbm_transport_sqn_t * dup_sqn_entry = NULL;
    lbm_transport_frame_t * frame_entry = NULL;

    /* Locate the frame. */
    frame_entry = lbtrm_transport_frame_find(transport, frame);
    if (frame_entry != NULL)
    {
        return (frame_entry);
    }
    frame_entry = lbm_transport_frame_add(transport->frame, type, frame, sqn, retransmission);
    if (transport->last_frame != NULL)
    {
        frame_entry->previous_frame = transport->last_frame->frame;
        transport->last_frame->next_frame = frame;
    }
    transport->last_frame = frame_entry;
    switch (type)
    {
        case LBTRM_PACKET_TYPE_DATA:
            if (transport->last_data_frame != NULL)
            {
                frame_entry->previous_type_frame = transport->last_data_frame->frame;
                transport->last_data_frame->next_type_frame = frame;
                /* Ideally, this frame's sqn is 1 more than the highest data sqn seen */
                if (frame_entry->sqn <= transport->data_high_sqn)
                {
                    dup_sqn_entry = lbtrm_transport_sqn_find(transport, type, frame_entry->sqn);
                    if (!frame_entry->retransmission)
                    {
                        /* Out of order */
                        if (dup_sqn_entry != NULL)
                        {
                            frame_entry->duplicate = TRUE;
                        }
                        if (frame_entry->sqn != transport->data_high_sqn)
                        {
                            frame_entry->ooo_gap = transport->data_high_sqn - frame_entry->sqn;
                        }
                    }
                }
                else
                {
                    if (!frame_entry->retransmission)
                    {
                        if (frame_entry->sqn != (transport->data_high_sqn + 1))
                        {
                            /* Gap */
                            frame_entry->sqn_gap = frame_entry->sqn - (transport->last_data_frame->sqn + 1);
                        }
                    }
                }
            }
            if ((frame_entry->sqn > transport->data_high_sqn) && !frame_entry->retransmission)
            {
                transport->data_high_sqn = frame_entry->sqn;
            }
            transport->last_data_frame = frame_entry;
            break;
        case LBTRM_PACKET_TYPE_SM:
            if (transport->last_sm_frame != NULL)
            {
                frame_entry->previous_type_frame = transport->last_sm_frame->frame;
                transport->last_sm_frame->next_type_frame = frame;
                /* Ideally, this frame's sqn is 1 more than the highest SM sqn seen */
                if (frame_entry->sqn <= transport->sm_high_sqn)
                {
                    /* Out of order */
                    dup_sqn_entry = lbtrm_transport_sqn_find(transport, type, frame_entry->sqn);
                    if (dup_sqn_entry != NULL)
                    {
                        frame_entry->duplicate = TRUE;
                    }
                    if (frame_entry->sqn != transport->sm_high_sqn)
                    {
                        frame_entry->ooo_gap = transport->sm_high_sqn - frame_entry->sqn;
                    }
                }
                else
                {
                    if (frame_entry->sqn != (transport->sm_high_sqn + 1))
                    {
                        /* Gap */
                        frame_entry->sqn_gap = frame_entry->sqn - (transport->sm_high_sqn + 1);
                    }
                }
            }
            if (frame_entry->sqn > transport->sm_high_sqn)
            {
                transport->sm_high_sqn = frame_entry->sqn;
            }
            transport->last_sm_frame = frame_entry;
            break;
        case LBTRM_PACKET_TYPE_NAK:
            if (transport->last_nak_frame != NULL)
            {
                frame_entry->previous_type_frame = transport->last_nak_frame->frame;
                transport->last_nak_frame->next_type_frame = frame;
            }
            transport->last_nak_frame = frame_entry;
            break;
        case LBTRM_PACKET_TYPE_NCF:
            if (transport->last_ncf_frame != NULL)
            {
                frame_entry->previous_type_frame = transport->last_ncf_frame->frame;
                transport->last_ncf_frame->next_type_frame = frame;
            }
            transport->last_ncf_frame = frame_entry;
            break;
    }

    /* Add the sqn. */
    (void)lbtrm_transport_sqn_add(transport, frame_entry);
    return (frame_entry);
}

static char * lbtrm_transport_source_string_format(const address * source_address, guint16 source_port, guint32 session_id, const address * multicast_group, guint16 dest_port)
{
    /* Returns a packet-scoped string. */
    return (wmem_strdup_printf(wmem_packet_scope(), "LBTRM:%s:%" G_GUINT16_FORMAT ":%08x:%s:%" G_GUINT16_FORMAT, address_to_str(wmem_packet_scope(), source_address), source_port, session_id,
            address_to_str(wmem_packet_scope(), multicast_group), dest_port));
}

char * lbtrm_transport_source_string(const address * source_address, guint16 source_port, guint32 session_id, const address * multicast_group, guint16 dest_port)
{
    /* Returns a file-scoped string. */
    return (wmem_strdup(wmem_file_scope(), lbtrm_transport_source_string_format(source_address, source_port, session_id, multicast_group, dest_port)));
}

static char * lbtrm_transport_source_string_transport(lbtrm_transport_t * transport)
{
    /* Returns a packet-scoped string. */
    return (lbtrm_transport_source_string_format(&(transport->source_address), transport->source_port, transport->session_id, &(transport->multicast_group), transport->dest_port));
}

/*----------------------------------------------------------------------------*/
/* Packet definitions.                                                        */
/*----------------------------------------------------------------------------*/

/* LBT-RM main header */
typedef struct
{
    lbm_uint8_t ver_type;
    lbm_uint8_t next_hdr;
    lbm_uint16_t ucast_port;
    lbm_uint32_t session_id;
} lbtrm_hdr_t;
#define O_LBTRM_HDR_T_VER_TYPE OFFSETOF(lbtrm_hdr_t, ver_type)
#define L_LBTRM_HDR_T_VER_TYPE SIZEOF(lbtrm_hdr_t, ver_type)
#define O_LBTRM_HDR_T_NEXT_HDR OFFSETOF(lbtrm_hdr_t, next_hdr)
#define L_LBTRM_HDR_T_NEXT_HDR SIZEOF(lbtrm_hdr_t, next_hdr)
#define O_LBTRM_HDR_T_UCAST_PORT OFFSETOF(lbtrm_hdr_t, ucast_port)
#define L_LBTRM_HDR_T_UCAST_PORT SIZEOF(lbtrm_hdr_t, ucast_port)
#define O_LBTRM_HDR_T_SESSION_ID OFFSETOF(lbtrm_hdr_t, session_id)
#define L_LBTRM_HDR_T_SESSION_ID SIZEOF(lbtrm_hdr_t, session_id)
#define L_LBTRM_HDR_T (gint) (sizeof(lbtrm_hdr_t))

#define LBTRM_VERSION 0x00
#define LBTRM_HDR_VER(x) (x >> 4)
#define LBTRM_HDR_TYPE(x) (x & 0x0F)
#define LBTRM_HDR_VER_MASK 0xF0
#define LBTRM_HDR_TYPE_MASK 0x0F

/* LBT-RM data header */
typedef struct
{
    lbm_uint32_t sqn;
    lbm_uint32_t trail_sqn;
    lbm_uint8_t flags_fec_type;
    lbm_uint8_t flags_tgsz;
    lbm_uint16_t fec_symbol;
} lbtrm_data_hdr_t;
#define O_LBTRM_DATA_HDR_T_SQN OFFSETOF(lbtrm_data_hdr_t, sqn)
#define L_LBTRM_DATA_HDR_T_SQN SIZEOF(lbtrm_data_hdr_t, sqn)
#define O_LBTRM_DATA_HDR_T_TRAIL_SQN OFFSETOF(lbtrm_data_hdr_t, trail_sqn)
#define L_LBTRM_DATA_HDR_T_TRAIL_SQN SIZEOF(lbtrm_data_hdr_t, trail_sqn)
#define O_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE OFFSETOF(lbtrm_data_hdr_t, flags_fec_type)
#define L_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE SIZEOF(lbtrm_data_hdr_t, flags_fec_type)
#define O_LBTRM_DATA_HDR_T_FLAGS_TGSZ OFFSETOF(lbtrm_data_hdr_t, flags_tgsz)
#define L_LBTRM_DATA_HDR_T_FLAGS_TGSZ SIZEOF(lbtrm_data_hdr_t, flags_tgsz)
#define O_LBTRM_DATA_HDR_T_FEC_SYMBOL OFFSETOF(lbtrm_data_hdr_t, fec_symbol)
#define L_LBTRM_DATA_HDR_T_FEC_SYMBOL SIZEOF(lbtrm_data_hdr_t, fec_symbol)
#define L_LBTRM_DATA_HDR_T (gint) (sizeof(lbtrm_data_hdr_t))

#define LBTRM_DATA_UNICAST_NAKS_FLAG 0x80
#define LBTRM_MULTICAST_NAKS_FLAG 0x40
#define LBTRM_DATA_RETRANSMISSION_FLAG 0x20
#define LBTRM_LATE_JOIN_FLAG 0x10
#define LBTRM_FEC_TYPE_MASK 0xF
#define LBTRM_DATA_FLAGS(x) (x >> 4)
#define LBTRM_DATA_FLAGS_MASK 0xF0

/* LBT-RM Session Message header */
typedef struct
{
    lbm_uint32_t sm_sqn;
    lbm_uint32_t lead_sqn;
    lbm_uint32_t trail_sqn;
    lbm_uint8_t flags_fec_type;
    lbm_uint8_t flags_tgsz;
    lbm_uint16_t reserved;
} lbtrm_sm_hdr_t;
#define O_LBTRM_SM_HDR_T_SM_SQN OFFSETOF(lbtrm_sm_hdr_t, sm_sqn)
#define L_LBTRM_SM_HDR_T_SM_SQN SIZEOF(lbtrm_sm_hdr_t, sm_sqn)
#define O_LBTRM_SM_HDR_T_LEAD_SQN OFFSETOF(lbtrm_sm_hdr_t, lead_sqn)
#define L_LBTRM_SM_HDR_T_LEAD_SQN SIZEOF(lbtrm_sm_hdr_t, lead_sqn)
#define O_LBTRM_SM_HDR_T_TRAIL_SQN OFFSETOF(lbtrm_sm_hdr_t, trail_sqn)
#define L_LBTRM_SM_HDR_T_TRAIL_SQN SIZEOF(lbtrm_sm_hdr_t, trail_sqn)
#define O_LBTRM_SM_HDR_T_FLAGS_FEC_TYPE OFFSETOF(lbtrm_sm_hdr_t, flags_fec_type)
#define L_LBTRM_SM_HDR_T_FLAGS_FEC_TYPE SIZEOF(lbtrm_sm_hdr_t, flags_fec_type)
#define O_LBTRM_SM_HDR_T_FLAGS_TGSZ OFFSETOF(lbtrm_sm_hdr_t, flags_tgsz)
#define L_LBTRM_SM_HDR_T_FLAGS_TGSZ SIZEOF(lbtrm_sm_hdr_t, flags_tgsz)
#define O_LBTRM_SM_HDR_T_RESERVED OFFSETOF(lbtrm_sm_hdr_t, reserved)
#define L_LBTRM_SM_HDR_T_RESERVED SIZEOF(lbtrm_sm_hdr_t, reserved)
#define L_LBTRM_SM_HDR_T (gint) (sizeof(lbtrm_sm_hdr_t))

#define LBTRM_SM_UNICAST_NAKS_FLAG 0x80
#define LBTRM_SM_FLAGS(x) (x >> 4)
#define LBTRM_SM_FLAGS_MASK 0xF0

/* LBT-RM NAK header */
typedef struct
{
    lbm_uint16_t num_naks;
    lbm_uint16_t format;
} lbtrm_nak_hdr_t;
#define O_LBTRM_NAK_HDR_T_NUM_NAKS OFFSETOF(lbtrm_nak_hdr_t, num_naks)
#define L_LBTRM_NAK_HDR_T_NUM_NAKS SIZEOF(lbtrm_nak_hdr_t, num_naks)
#define O_LBTRM_NAK_HDR_T_FORMAT OFFSETOF(lbtrm_nak_hdr_t, format)
#define L_LBTRM_NAK_HDR_T_FORMAT SIZEOF(lbtrm_nak_hdr_t, format)
#define L_LBTRM_NAK_HDR_T (gint) (sizeof(lbtrm_nak_hdr_t))

#define LBTRM_NAK_SELECTIVE_FORMAT 0x0
#define LBTRM_NAK_PARITY_FORMAT 0x1
#define LBTRM_NAK_HDR_FORMAT(x) (x & 0xF)
#define LBTRM_NAK_HDR_FORMAT_MASK 0x0F

/* LBT-RM NAK Confirmation */
typedef struct
{
    lbm_uint32_t trail_sqn;
    lbm_uint16_t num_ncfs;
    lbm_uint8_t reserved;
    lbm_uint8_t reason_format;
} lbtrm_ncf_hdr_t;
#define O_LBTRM_NCF_HDR_T_TRAIL_SQN OFFSETOF(lbtrm_ncf_hdr_t, trail_sqn)
#define L_LBTRM_NCF_HDR_T_TRAIL_SQN SIZEOF(lbtrm_ncf_hdr_t, trail_sqn)
#define O_LBTRM_NCF_HDR_T_NUM_NCFS OFFSETOF(lbtrm_ncf_hdr_t, num_ncfs)
#define L_LBTRM_NCF_HDR_T_NUM_NCFS SIZEOF(lbtrm_ncf_hdr_t, num_ncfs)
#define O_LBTRM_NCF_HDR_T_RESERVED OFFSETOF(lbtrm_ncf_hdr_t, reserved)
#define L_LBTRM_NCF_HDR_T_RESERVED SIZEOF(lbtrm_ncf_hdr_t, reserved)
#define O_LBTRM_NCF_HDR_T_REASON_FORMAT OFFSETOF(lbtrm_ncf_hdr_t, reason_format)
#define L_LBTRM_NCF_HDR_T_REASON_FORMAT SIZEOF(lbtrm_ncf_hdr_t, reason_format)
#define L_LBTRM_NCF_HDR_T (gint) (sizeof(lbtrm_ncf_hdr_t))

#define LBTRM_NCF_SELECTIVE_FORMAT 0x0
#define LBTRM_NCF_PARITY_FORMAT 0x1
#define LBTRM_NCF_HDR_REASON(x) ((x & 0xF0) >> 4)
#define LBTRM_NCF_HDR_FORMAT(x) (x & 0xF)
#define LBTRM_NCF_HDR_REASON_MASK 0xF0
#define LBTRM_NCF_HDR_FORMAT_MASK 0x0F

/* LBT-RM option header */
typedef struct
{
    lbm_uint8_t next_hdr;
    lbm_uint8_t hdr_len;
    lbm_uint16_t res;
} lbtrm_basic_opt_t;
#define O_LBTRM_BASIC_OPT_T_NEXT_HDR OFFSETOF(lbtrm_basic_opt_t, next_hdr)
#define L_LBTRM_BASIC_OPT_T_NEXT_HDR SIZEOF(lbtrm_basic_opt_t, next_hdr)
#define O_LBTRM_BASIC_OPT_T_HDR_LEN OFFSETOF(lbtrm_basic_opt_t, hdr_len)
#define L_LBTRM_BASIC_OPT_T_HDR_LEN SIZEOF(lbtrm_basic_opt_t, hdr_len)
#define O_LBTRM_BASIC_OPT_T_RES OFFSETOF(lbtrm_basic_opt_t, res)
#define L_LBTRM_BASIC_OPT_T_RES SIZEOF(lbtrm_basic_opt_t, res)
#define L_LBTRM_BASIC_OPT_T (gint) (sizeof(lbtrm_basic_opt_t))

#define LBTRM_NHDR_DATA 0x0

/*----------------------------------------------------------------------------*/
/* Value translation tables.                                                  */
/*----------------------------------------------------------------------------*/

static const value_string lbtrm_packet_type[] =
{
    { LBTRM_PACKET_TYPE_DATA, "DATA" },
    { LBTRM_PACKET_TYPE_SM, "SM" },
    { LBTRM_PACKET_TYPE_NAK, "NAK" },
    { LBTRM_PACKET_TYPE_NCF, "NCF" },
    { 0x0, NULL }
};

static const value_string lbtrm_nak_format[] =
{
    { LBTRM_NAK_SELECTIVE_FORMAT, "Selective" },
    { LBTRM_NAK_PARITY_FORMAT, "Parity" },
    { 0x0, NULL }
};

static const value_string lbtrm_ncf_format[] =
{
    { LBTRM_NCF_SELECTIVE_FORMAT, "Selective" },
    { LBTRM_NCF_PARITY_FORMAT, "Parity" },
    { 0x0, NULL }
};

static const value_string lbtrm_ncf_reason[] =
{
    { LBTRM_NCF_REASON_NO_RETRY, "Do not retry" },
    { LBTRM_NCF_REASON_IGNORED, "NAK Ignored" },
    { LBTRM_NCF_REASON_RX_DELAY, "Retransmit Delay" },
    { LBTRM_NCF_REASON_SHED, "NAK Shed" },
    { 0x0, NULL }
};

static const value_string lbtrm_next_header[] =
{
    { LBTRM_NHDR_DATA, "Data" },
    { 0x0, NULL }
};

/*----------------------------------------------------------------------------*/
/* Preferences.                                                               */
/*----------------------------------------------------------------------------*/

/* Preferences default values. */
#define LBTRM_DEFAULT_DPORT_LOW 14400
#define LBTRM_DEFAULT_DPORT_HIGH 14400
#define LBTRM_DEFAULT_SPORT_HIGH 14399
#define LBTRM_DEFAULT_SPORT_LOW 14390
#define LBTRM_DEFAULT_MC_ADDRESS_LOW "224.10.10.10"
#define LBTRM_DEFAULT_MC_ADDRESS_HIGH "224.10.10.14"
#define MIM_DEFAULT_INCOMING_DPORT 14401
#define MIM_DEFAULT_OUTGOING_DPORT 14401
#define MIM_DEFAULT_MC_INCOMING_ADDRESS "224.10.10.21"
#define MIM_DEFAULT_MC_OUTGOING_ADDRESS "224.10.10.21"

/* Global preferences variables (altered by the preferences dialog). */
static const char * global_lbtrm_mc_address_low = LBTRM_DEFAULT_MC_ADDRESS_LOW;
static const char * global_lbtrm_mc_address_high = LBTRM_DEFAULT_MC_ADDRESS_HIGH;
static guint32 global_lbtrm_dest_port_low = LBTRM_DEFAULT_DPORT_LOW;
static guint32 global_lbtrm_dest_port_high = LBTRM_DEFAULT_DPORT_HIGH;
static guint32 global_lbtrm_src_port_low = LBTRM_DEFAULT_SPORT_LOW;
static guint32 global_lbtrm_src_port_high = LBTRM_DEFAULT_SPORT_HIGH;
static guint32 global_mim_incoming_dest_port = MIM_DEFAULT_INCOMING_DPORT;
static guint32 global_mim_outgoing_dest_port = MIM_DEFAULT_OUTGOING_DPORT;
static const char * global_mim_incoming_mc_address = MIM_DEFAULT_MC_INCOMING_ADDRESS;
static const char * global_mim_outgoing_mc_address = MIM_DEFAULT_MC_OUTGOING_ADDRESS;
static gboolean global_lbtrm_expert_separate_naks = FALSE;
static gboolean global_lbtrm_expert_separate_ncfs = FALSE;
static gboolean global_lbtrm_use_tag = FALSE;
static gboolean global_lbtrm_sequence_analysis = FALSE;

/* Local preferences variables (used by the dissector). */
static guint32 lbtrm_mc_address_low_host = 0;
static guint32 lbtrm_mc_address_high_host = 0;
static guint32 lbtrm_dest_port_low = LBTRM_DEFAULT_DPORT_LOW;
static guint32 lbtrm_dest_port_high = LBTRM_DEFAULT_DPORT_HIGH;
static guint32 lbtrm_src_port_low = LBTRM_DEFAULT_SPORT_LOW;
static guint32 lbtrm_src_port_high = LBTRM_DEFAULT_SPORT_HIGH;
static guint32 mim_incoming_dest_port = MIM_DEFAULT_INCOMING_DPORT;
static guint32 mim_outgoing_dest_port = MIM_DEFAULT_OUTGOING_DPORT;
static guint32 mim_incoming_mc_address_host = 0;
static guint32 mim_outgoing_mc_address_host = 0;
static gboolean lbtrm_expert_separate_naks = FALSE;
static gboolean lbtrm_expert_separate_ncfs = FALSE;
static gboolean lbtrm_use_tag = FALSE;
static gboolean lbtrm_sequence_analysis = FALSE;

/*----------------------------------------------------------------------------*/
/* Tag management.                                                            */
/*----------------------------------------------------------------------------*/
typedef struct
{
    char * name;
    char * mc_address_low;
    guint32 mc_address_low_val_h;
    char * mc_address_high;
    guint32 mc_address_high_val_h;
    guint32 dport_low;
    guint32 dport_high;
    guint32 sport_low;
    guint32 sport_high;
    guint32 mim_incoming_dport;
    guint32 mim_outgoing_dport;
    char * mim_mc_incoming_address;
    guint32 mim_mc_incoming_address_val_h;
    char * mim_mc_outgoing_address;
    guint32 mim_mc_outgoing_address_val_h;
} lbtrm_tag_entry_t;

static lbtrm_tag_entry_t * lbtrm_tag_entry = NULL;
static guint lbtrm_tag_count = 0;

UAT_CSTRING_CB_DEF(lbtrm_tag, name, lbtrm_tag_entry_t)
UAT_IPV4_MC_CB_DEF(lbtrm_tag, mc_address_low, lbtrm_tag_entry_t)
UAT_IPV4_MC_CB_DEF(lbtrm_tag, mc_address_high, lbtrm_tag_entry_t)
UAT_DEC_CB_DEF(lbtrm_tag, dport_low, lbtrm_tag_entry_t)
UAT_DEC_CB_DEF(lbtrm_tag, dport_high, lbtrm_tag_entry_t)
UAT_DEC_CB_DEF(lbtrm_tag, sport_low, lbtrm_tag_entry_t)
UAT_DEC_CB_DEF(lbtrm_tag, sport_high, lbtrm_tag_entry_t)
UAT_DEC_CB_DEF(lbtrm_tag, mim_incoming_dport, lbtrm_tag_entry_t)
UAT_DEC_CB_DEF(lbtrm_tag, mim_outgoing_dport, lbtrm_tag_entry_t)
UAT_IPV4_MC_CB_DEF(lbtrm_tag, mim_mc_incoming_address, lbtrm_tag_entry_t)
UAT_IPV4_MC_CB_DEF(lbtrm_tag, mim_mc_outgoing_address, lbtrm_tag_entry_t)
static uat_field_t lbtrm_tag_array[] =
{
    UAT_FLD_CSTRING(lbtrm_tag, name, "Tag name", "Tag name"),
    UAT_FLD_IPV4_MC(lbtrm_tag, mc_address_low, "Multicast address low", "Multicast address low"),
    UAT_FLD_IPV4_MC(lbtrm_tag, mc_address_high, "Multicast address high", "Multicast address high"),
    UAT_FLD_DEC(lbtrm_tag, dport_low, "Destination port low", "Destination port low"),
    UAT_FLD_DEC(lbtrm_tag, dport_high, "Destination port high", "Destination port high"),
    UAT_FLD_DEC(lbtrm_tag, sport_low, "Source port low", "Source port low"),
    UAT_FLD_DEC(lbtrm_tag, sport_high, "Source port high", "Source port high"),
    UAT_FLD_DEC(lbtrm_tag, mim_incoming_dport, "MIM incoming destination port", "MIM incoming destination port"),
    UAT_FLD_DEC(lbtrm_tag, mim_outgoing_dport, "MIM outgoing destination port", "MIM outgoing destination port"),
    UAT_FLD_IPV4_MC(lbtrm_tag, mim_mc_incoming_address, "MIM incoming multicast address", "MIM incoming multicast address"),
    UAT_FLD_IPV4_MC(lbtrm_tag, mim_mc_outgoing_address, "MIM outgoing multicast address", "MIM outgoing multicast address"),
    UAT_END_FIELDS
};

/*----------------------------------------------------------------------------*/
/* UAT callback functions.                                                    */
/*----------------------------------------------------------------------------*/
static void lbtrm_tag_update_cb(void * record, const char * * error_string)
{
    lbtrm_tag_entry_t * tag = (lbtrm_tag_entry_t *)record;

    if (tag->name == NULL)
    {
        *error_string = g_strdup_printf("Tag name can't be empty");
    }
    else
    {
        g_strstrip(tag->name);
        if (tag->name[0] == 0)
        {
            *error_string = g_strdup_printf("Tag name can't be empty");
        }
    }
}

static void * lbtrm_tag_copy_cb(void * destination, const void * source, size_t length _U_)
{
    const lbtrm_tag_entry_t * src = (const lbtrm_tag_entry_t *)source;
    lbtrm_tag_entry_t * dest = (lbtrm_tag_entry_t *)destination;

    dest->name = g_strdup(src->name);
    dest->mc_address_low = g_strdup(src->mc_address_low);
    dest->mc_address_low_val_h = src->mc_address_low_val_h;
    dest->mc_address_high = g_strdup(src->mc_address_high);
    dest->mc_address_high_val_h = src->mc_address_high_val_h;
    dest->dport_low = src->dport_low;
    dest->dport_high = src->dport_high;
    dest->sport_low = src->sport_low;
    dest->sport_high = src->sport_high;
    dest->mim_incoming_dport = src->mim_incoming_dport;
    dest->mim_outgoing_dport = src->mim_outgoing_dport;
    dest->mim_mc_incoming_address = g_strdup(src->mim_mc_incoming_address);
    dest->mim_mc_incoming_address_val_h = src->mim_mc_incoming_address_val_h;
    dest->mim_mc_outgoing_address = g_strdup(src->mim_mc_outgoing_address);
    dest->mim_mc_outgoing_address_val_h = src->mim_mc_outgoing_address_val_h;
    return (dest);
}

static void lbtrm_tag_free_cb(void * record)
{
    lbtrm_tag_entry_t * tag = (lbtrm_tag_entry_t *)record;

    if (tag->name != NULL)
    {
        g_free(tag->name);
        tag->name = NULL;
    }
    if (tag->mc_address_low != NULL)
    {
        g_free(tag->mc_address_low);
        tag->mc_address_low = NULL;
    }
    if (tag->mc_address_high != NULL)
    {
        g_free(tag->mc_address_high);
        tag->mc_address_high = NULL;
    }
    if (tag->mim_mc_incoming_address != NULL)
    {
        g_free(tag->mim_mc_incoming_address);
        tag->mim_mc_incoming_address = NULL;
    }
    if (tag->mim_mc_outgoing_address != NULL)
    {
        g_free(tag->mim_mc_outgoing_address);
        tag->mim_mc_outgoing_address = NULL;
    }
}

static char * lbtrm_tag_find(packet_info * pinfo)
{
    guint idx;
    lbtrm_tag_entry_t * tag = NULL;
    guint32 dest_addr_h;

    if (!lbtrm_use_tag)
    {
        return (NULL);
    }

    dest_addr_h = pntoh32(pinfo->dst.data);
    for (idx = 0; idx < lbtrm_tag_count; ++idx)
    {
        tag = &(lbtrm_tag_entry[idx]);
        /* Is the destination a multicast address? */
        if (IN_MULTICAST(dest_addr_h))
        {
            /* Check the MC address. */
            if ((dest_addr_h >= tag->mc_address_low_val_h) && (dest_addr_h <= tag->mc_address_high_val_h))
            {
                /* It's in the LBT-RM multicast range. Check the ports. */
                if ((pinfo->destport >= tag->dport_low) && (pinfo->destport <= tag->dport_high))
                {
                    /* Must be one of ours. */
                    return (tag->name);
                }
            }
            else if ((dest_addr_h == tag->mim_mc_incoming_address_val_h) || (dest_addr_h == tag->mim_mc_outgoing_address_val_h))
            {
                /* Might be MIM. Check the port. */
                if (((dest_addr_h == tag->mim_mc_incoming_address_val_h) && (pinfo->destport == tag->mim_incoming_dport))
                    || ((dest_addr_h == tag->mim_mc_outgoing_address_val_h) && (pinfo->destport == tag->mim_outgoing_dport)))
                {
                    /* Must be one of ours. */
                    return (tag->name);
                }
            }
            /* Not ours. */
            continue;
        }
        else
        {
            /* Not multicast, might be a unicast UDP NAK. Check the destination port. */
            if ((pinfo->destport < tag->sport_low) || (pinfo->destport > tag->sport_high))
            {
                /* Wrong port. */
                continue;
            }
            /* One of ours, so handle it. */
            return (tag->name);
        }
    }
    /* Not one of ours. */
    return (NULL);
}

/*----------------------------------------------------------------------------*/
/* Handles of all types.                                                      */
/*----------------------------------------------------------------------------*/

/* Dissector tree handles */
static gint ett_lbtrm = -1;
static gint ett_lbtrm_hdr = -1;
static gint ett_lbtrm_hdr_ver_type = -1;
static gint ett_lbtrm_data = -1;
static gint ett_lbtrm_data_flags_fec_type = -1;
static gint ett_lbtrm_sm = -1;
static gint ett_lbtrm_sm_flags_fec_type = -1;
static gint ett_lbtrm_nak = -1;
static gint ett_lbtrm_nak_list = -1;
static gint ett_lbtrm_ncf = -1;
static gint ett_lbtrm_ncf_reason_format = -1;
static gint ett_lbtrm_ncf_list = -1;
static gint ett_lbtrm_transport = -1;
static gint ett_lbtrm_transport_sqn = -1;

/* Dissector field handles */
static int hf_lbtrm_channel = -1;
static int hf_lbtrm_tag = -1;
static int hf_lbtrm_hdr = -1;
static int hf_lbtrm_hdr_ver_type = -1;
static int hf_lbtrm_hdr_ver_type_ver = -1;
static int hf_lbtrm_hdr_ver_type_type = -1;
static int hf_lbtrm_hdr_next_hdr = -1;
static int hf_lbtrm_hdr_ucast_port = -1;
static int hf_lbtrm_hdr_session_id = -1;
static int hf_lbtrm_data = -1;
static int hf_lbtrm_data_sqn = -1;
static int hf_lbtrm_data_trail_sqn = -1;
static int hf_lbtrm_data_flags_fec_type = -1;
static int hf_lbtrm_data_flags_fec_type_ucast_naks = -1;
static int hf_lbtrm_data_flags_fec_type_rx = -1;
static int hf_lbtrm_data_flags_tgsz = -1;
static int hf_lbtrm_data_fec_symbol = -1;
static int hf_lbtrm_sm = -1;
static int hf_lbtrm_sm_sm_sqn = -1;
static int hf_lbtrm_sm_lead_sqn = -1;
static int hf_lbtrm_sm_trail_sqn = -1;
static int hf_lbtrm_sm_flags_fec_type = -1;
static int hf_lbtrm_sm_flags_fec_type_ucast_naks = -1;
static int hf_lbtrm_sm_flags_tgsz = -1;
static int hf_lbtrm_sm_reserved = -1;
static int hf_lbtrm_nak = -1;
static int hf_lbtrm_nak_num_naks = -1;
static int hf_lbtrm_nak_format = -1;
static int hf_lbtrm_nak_list = -1;
static int hf_lbtrm_nak_list_nak = -1;
static int hf_lbtrm_ncf = -1;
static int hf_lbtrm_ncf_trail_sqn = -1;
static int hf_lbtrm_ncf_num_ncfs = -1;
static int hf_lbtrm_ncf_reserved = -1;
static int hf_lbtrm_ncf_reason_format = -1;
static int hf_lbtrm_ncf_reason_format_reason = -1;
static int hf_lbtrm_ncf_reason_format_format = -1;
static int hf_lbtrm_ncf_list = -1;
static int hf_lbtrm_ncf_list_ncf = -1;
static int hf_lbtrm_analysis = -1;
static int hf_lbtrm_analysis_prev_frame = -1;
static int hf_lbtrm_analysis_prev_data_frame = -1;
static int hf_lbtrm_analysis_prev_sm_frame = -1;
static int hf_lbtrm_analysis_prev_nak_frame = -1;
static int hf_lbtrm_analysis_prev_ncf_frame = -1;
static int hf_lbtrm_analysis_next_frame = -1;
static int hf_lbtrm_analysis_next_data_frame = -1;
static int hf_lbtrm_analysis_next_sm_frame = -1;
static int hf_lbtrm_analysis_next_nak_frame = -1;
static int hf_lbtrm_analysis_next_ncf_frame = -1;
static int hf_lbtrm_analysis_sqn = -1;
static int hf_lbtrm_analysis_sqn_frame = -1;
static int hf_lbtrm_analysis_data_retransmission = -1;
static int hf_lbtrm_analysis_data_sqn_gap = -1;
static int hf_lbtrm_analysis_data_ooo_gap = -1;
static int hf_lbtrm_analysis_data_duplicate = -1;
static int hf_lbtrm_analysis_sm_sqn_gap = -1;
static int hf_lbtrm_analysis_sm_ooo_gap = -1;
static int hf_lbtrm_analysis_sm_duplicate = -1;

/* Expert info handles */
static expert_field ei_lbtrm_analysis_ncf = EI_INIT;
static expert_field ei_lbtrm_analysis_ncf_ncf = EI_INIT;
static expert_field ei_lbtrm_analysis_nak = EI_INIT;
static expert_field ei_lbtrm_analysis_nak_nak = EI_INIT;
static expert_field ei_lbtrm_analysis_sm = EI_INIT;
static expert_field ei_lbtrm_analysis_rx = EI_INIT;
static expert_field ei_lbtrm_analysis_invalid_value = EI_INIT;
static expert_field ei_lbtrm_analysis_data_rx = EI_INIT;
static expert_field ei_lbtrm_analysis_data_gap = EI_INIT;
static expert_field ei_lbtrm_analysis_data_ooo = EI_INIT;
static expert_field ei_lbtrm_analysis_data_dup = EI_INIT;
static expert_field ei_lbtrm_analysis_sm_gap = EI_INIT;
static expert_field ei_lbtrm_analysis_sm_ooo = EI_INIT;
static expert_field ei_lbtrm_analysis_sm_dup = EI_INIT;

/*----------------------------------------------------------------------------*/
/* LBT-RM data payload dissection functions.                                  */
/*----------------------------------------------------------------------------*/
static int dissect_lbtrm_data_contents(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, const char * tag_name, guint64 channel)
{
    tvbuff_t * next_tvb;

    next_tvb = tvb_new_subset_remaining(tvb, offset);
    return (lbmc_dissect_lbmc_packet(next_tvb, 0, pinfo, tree, tag_name, channel));
}

/*----------------------------------------------------------------------------*/
/* LBT-RM NAK confirmation packet dissection functions.                       */
/*----------------------------------------------------------------------------*/
static int dissect_lbtrm_ncf_list(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, int ncf_count, int reason, lbm_lbtrm_tap_info_t * tap_info)
{
    proto_tree * ncf_tree = NULL;
    proto_item * ncf_item = NULL;
    lbm_uint32_t ncf;
    int idx = 0;
    int len = 0;

    ncf_item = proto_tree_add_item(tree, hf_lbtrm_ncf_list, tvb, offset + len, (int)(sizeof(lbm_uint32_t) * ncf_count), ENC_NA);
    ncf_tree = proto_item_add_subtree(ncf_item, ett_lbtrm_ncf_list);

    for (idx = 0; idx < ncf_count; idx++)
    {
        proto_item * sep_ncf_item = NULL;

        ncf = tvb_get_ntohl(tvb, offset + len);
        sep_ncf_item = proto_tree_add_item(ncf_tree, hf_lbtrm_ncf_list_ncf, tvb, offset + len, sizeof(lbm_uint32_t), ENC_BIG_ENDIAN);
        if (lbtrm_expert_separate_ncfs)
        {
            expert_add_info_format(pinfo, sep_ncf_item, &ei_lbtrm_analysis_ncf_ncf, "NCF 0x%08x %s", ncf, val_to_str(reason, lbtrm_ncf_reason, "Unknown (0x%02x)"));
        }
        tap_info->sqns[idx] = ncf;
        len += 4;
    }
    return (len);
}

static int dissect_lbtrm_ncf(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, lbm_lbtrm_tap_info_t * tap_info)
{
    int len = 0;
    guint16 num_ncfs;
    guint8 reason;
    proto_tree * ncf_tree = NULL;
    proto_item * ncf_item = NULL;
    proto_tree * rf_tree = NULL;
    proto_item * rf_item = NULL;
    proto_item * reason_item = NULL;

    ncf_item = proto_tree_add_item(tree, hf_lbtrm_ncf, tvb, offset, -1, ENC_NA);
    ncf_tree = proto_item_add_subtree(ncf_item, ett_lbtrm_ncf);
    num_ncfs = tvb_get_ntohs(tvb, offset + O_LBTRM_NCF_HDR_T_NUM_NCFS);
    reason = tvb_get_guint8(tvb, offset + O_LBTRM_NCF_HDR_T_REASON_FORMAT);
    proto_tree_add_item(ncf_tree, hf_lbtrm_ncf_trail_sqn, tvb, offset + O_LBTRM_NCF_HDR_T_TRAIL_SQN, L_LBTRM_NCF_HDR_T_TRAIL_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(ncf_tree, hf_lbtrm_ncf_num_ncfs, tvb, offset + O_LBTRM_NCF_HDR_T_NUM_NCFS, L_LBTRM_NCF_HDR_T_NUM_NCFS, ENC_BIG_ENDIAN);
    proto_tree_add_item(ncf_tree, hf_lbtrm_ncf_reserved, tvb, offset + O_LBTRM_NCF_HDR_T_RESERVED, L_LBTRM_NCF_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    rf_item = proto_tree_add_none_format(ncf_tree, hf_lbtrm_ncf_reason_format, tvb, O_LBTRM_NCF_HDR_T_REASON_FORMAT, L_LBTRM_NCF_HDR_T_REASON_FORMAT,
        "Reason/Format: %s/%s", val_to_str(LBTRM_NCF_HDR_REASON(reason), lbtrm_ncf_reason, "Unknown (0x%02x)"),
        val_to_str(LBTRM_NCF_HDR_FORMAT(reason), lbtrm_ncf_format, "Unknown (0x%02x)"));
    rf_tree = proto_item_add_subtree(rf_item, ett_lbtrm_ncf_reason_format);
    reason_item = proto_tree_add_item(rf_tree, hf_lbtrm_ncf_reason_format_reason, tvb, offset + O_LBTRM_NCF_HDR_T_REASON_FORMAT, L_LBTRM_NCF_HDR_T_REASON_FORMAT, ENC_BIG_ENDIAN);
    proto_tree_add_item(rf_tree, hf_lbtrm_ncf_reason_format_format, tvb, offset + O_LBTRM_NCF_HDR_T_REASON_FORMAT, L_LBTRM_NCF_HDR_T_REASON_FORMAT, ENC_BIG_ENDIAN);
    len = L_LBTRM_NCF_HDR_T;
    if (!lbtrm_expert_separate_ncfs)
    {
        expert_add_info_format(pinfo, reason_item, &ei_lbtrm_analysis_ncf, "NCF %s", val_to_str(LBTRM_NCF_HDR_REASON(reason), lbtrm_ncf_reason, "Unknown (0x%02x)"));
    }
    tap_info->ncf_reason = LBTRM_NCF_HDR_REASON(reason);
    tap_info->num_sqns = num_ncfs;
    tap_info->sqns = wmem_alloc_array(wmem_packet_scope(), guint32, num_ncfs);
    len += dissect_lbtrm_ncf_list(tvb, offset + len, pinfo, ncf_tree, num_ncfs, LBTRM_NCF_HDR_REASON(reason), tap_info);
    proto_item_set_len(ncf_item, len);
    return (len);
}

/*----------------------------------------------------------------------------*/
/* LBT-RM NAK packet dissection functions.                                    */
/*----------------------------------------------------------------------------*/
static int dissect_lbtrm_nak_list(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, int nak_count, lbm_lbtrm_tap_info_t * tap_info)
{
    proto_tree * nak_tree = NULL;
    proto_item * nak_item = NULL;
    lbm_uint32_t nak;
    int idx = 0;
    int len = 0;

    nak_item = proto_tree_add_item(tree, hf_lbtrm_nak_list, tvb, offset + len, (int)(sizeof(lbm_uint32_t) * nak_count), ENC_NA);
    nak_tree = proto_item_add_subtree(nak_item, ett_lbtrm_nak_list);

    for (idx = 0; idx < nak_count; idx++)
    {
        proto_item * sep_nak_item = NULL;

        nak = tvb_get_ntohl(tvb, offset + len);
        sep_nak_item = proto_tree_add_item(nak_tree, hf_lbtrm_nak_list_nak, tvb, offset + len, sizeof(lbm_uint32_t), ENC_BIG_ENDIAN);
        if (lbtrm_expert_separate_naks)
        {
            expert_add_info_format(pinfo, sep_nak_item, &ei_lbtrm_analysis_nak_nak, "NAK 0x%08x", nak);
        }
        tap_info->sqns[idx] = nak;
        len += 4;
    }
    return (len);
}

static int dissect_lbtrm_nak(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, lbm_lbtrm_tap_info_t * tap_info)
{
    int len = 0;
    guint16 num_naks;
    proto_tree * nak_tree = NULL;
    proto_item * nak_item = NULL;

    nak_item = proto_tree_add_item(tree, hf_lbtrm_nak, tvb, offset, -1, ENC_NA);
    nak_tree = proto_item_add_subtree(nak_item, ett_lbtrm_nak);
    num_naks = tvb_get_ntohs(tvb, offset + O_LBTRM_NAK_HDR_T_NUM_NAKS);
    proto_tree_add_item(nak_tree, hf_lbtrm_nak_num_naks, tvb, offset + O_LBTRM_NAK_HDR_T_NUM_NAKS, L_LBTRM_NAK_HDR_T_NUM_NAKS, ENC_BIG_ENDIAN);
    proto_tree_add_item(nak_tree, hf_lbtrm_nak_format, tvb, offset + O_LBTRM_NAK_HDR_T_FORMAT, L_LBTRM_NAK_HDR_T_FORMAT, ENC_BIG_ENDIAN);
    len = L_LBTRM_NAK_HDR_T;
    if (!lbtrm_expert_separate_naks)
    {
        expert_add_info(pinfo, nak_item, &ei_lbtrm_analysis_nak);
    }
    tap_info->num_sqns = num_naks;
    tap_info->sqns = wmem_alloc_array(wmem_packet_scope(), guint32, num_naks);
    len += dissect_lbtrm_nak_list(tvb, offset + len, pinfo, nak_tree, num_naks, tap_info);
    proto_item_set_len(nak_item, len);
    return (len);
}

/*----------------------------------------------------------------------------*/
/* LBT-RM session message packet dissection functions.                        */
/*----------------------------------------------------------------------------*/
static int dissect_lbtrm_sm(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, guint32 * sequence, lbm_lbtrm_tap_info_t * tap_info)
{
    proto_tree * sm_tree = NULL;
    proto_item * sm_item = NULL;
    proto_tree * flags_tree =  NULL;
    proto_item * flags_item = NULL;
    proto_item * sm_sqn_item = NULL;
    guint8 flags;
    guint32 sqn;

    sm_item = proto_tree_add_item(tree, hf_lbtrm_sm, tvb, offset, L_LBTRM_SM_HDR_T, ENC_NA);
    sm_tree = proto_item_add_subtree(sm_item, ett_lbtrm_sm);
    sm_sqn_item = proto_tree_add_item(sm_tree, hf_lbtrm_sm_sm_sqn, tvb, offset + O_LBTRM_SM_HDR_T_SM_SQN, L_LBTRM_SM_HDR_T_SM_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(sm_tree, hf_lbtrm_sm_lead_sqn, tvb, offset + O_LBTRM_SM_HDR_T_LEAD_SQN, L_LBTRM_SM_HDR_T_LEAD_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(sm_tree, hf_lbtrm_sm_trail_sqn, tvb, offset + O_LBTRM_SM_HDR_T_TRAIL_SQN, L_LBTRM_SM_HDR_T_TRAIL_SQN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBTRM_SM_HDR_T_FLAGS_FEC_TYPE);
    flags_item = proto_tree_add_none_format(sm_tree, hf_lbtrm_sm_flags_fec_type, tvb, offset + O_LBTRM_SM_HDR_T_FLAGS_FEC_TYPE, L_LBTRM_SM_HDR_T_FLAGS_FEC_TYPE,
        "FEC Flags: 0x%02x", flags);
    flags_tree = proto_item_add_subtree(flags_item, ett_lbtrm_sm_flags_fec_type);
    proto_tree_add_item(flags_tree, hf_lbtrm_sm_flags_fec_type_ucast_naks, tvb, offset + O_LBTRM_SM_HDR_T_FLAGS_FEC_TYPE, L_LBTRM_SM_HDR_T_FLAGS_FEC_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(sm_tree, hf_lbtrm_sm_flags_tgsz, tvb, offset + O_LBTRM_SM_HDR_T_FLAGS_TGSZ, L_LBTRM_SM_HDR_T_FLAGS_TGSZ, ENC_BIG_ENDIAN);
    proto_tree_add_item(sm_tree, hf_lbtrm_sm_reserved, tvb, offset + O_LBTRM_SM_HDR_T_RESERVED, L_LBTRM_SM_HDR_T_RESERVED, ENC_BIG_ENDIAN);
    sqn = tvb_get_ntohl(tvb, offset + O_LBTRM_SM_HDR_T_SM_SQN);
    expert_add_info(pinfo, sm_sqn_item, &ei_lbtrm_analysis_sm);
    if (sequence != NULL)
    {
        *sequence = sqn;
    }
    tap_info->sqn = sqn;
    return (L_LBTRM_SM_HDR_T);
}

/*----------------------------------------------------------------------------*/
/* LBT-RM data packet dissection functions.                                   */
/*----------------------------------------------------------------------------*/
static int dissect_lbtrm_data(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, guint32 * sequence, gboolean * retransmission, lbm_lbtrm_tap_info_t * tap_info)
{
    proto_tree * data_tree = NULL;
    proto_item * data_item = NULL;
    proto_tree * flags_tree =  NULL;
    proto_item * flags_item = NULL;
    proto_item * sqn_item = NULL;
    guint8 flags;
    guint32 sqn;
    gboolean is_retransmission = FALSE;

    data_item = proto_tree_add_item(tree, hf_lbtrm_data, tvb, offset, L_LBTRM_DATA_HDR_T, ENC_NA);
    data_tree = proto_item_add_subtree(data_item, ett_lbtrm_data);
    sqn_item = proto_tree_add_item(data_tree, hf_lbtrm_data_sqn, tvb, offset + O_LBTRM_DATA_HDR_T_SQN, L_LBTRM_DATA_HDR_T_SQN, ENC_BIG_ENDIAN);
    proto_tree_add_item(data_tree, hf_lbtrm_data_trail_sqn, tvb, offset + O_LBTRM_DATA_HDR_T_TRAIL_SQN, L_LBTRM_DATA_HDR_T_TRAIL_SQN, ENC_BIG_ENDIAN);
    flags = tvb_get_guint8(tvb, offset + O_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE);
    flags_item = proto_tree_add_none_format(data_tree, hf_lbtrm_data_flags_fec_type, tvb, offset + O_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE, L_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE,
        "FEC Flags: 0x%02x", LBTRM_DATA_FLAGS(flags));
    flags_tree = proto_item_add_subtree(flags_item, ett_lbtrm_data_flags_fec_type);
    proto_tree_add_item(flags_tree, hf_lbtrm_data_flags_fec_type_ucast_naks, tvb, offset + O_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE, L_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(flags_tree, hf_lbtrm_data_flags_fec_type_rx, tvb, offset + O_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE, L_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE, ENC_BIG_ENDIAN);
    proto_tree_add_item(data_tree, hf_lbtrm_data_flags_tgsz, tvb, offset + O_LBTRM_DATA_HDR_T_FLAGS_TGSZ, L_LBTRM_DATA_HDR_T_FLAGS_TGSZ, ENC_BIG_ENDIAN);
    proto_tree_add_item(data_tree, hf_lbtrm_data_fec_symbol, tvb, offset + O_LBTRM_DATA_HDR_T_FEC_SYMBOL, L_LBTRM_DATA_HDR_T_FEC_SYMBOL, ENC_BIG_ENDIAN);
    sqn = tvb_get_ntohl(tvb, offset + O_LBTRM_DATA_HDR_T_SQN);
    if (sequence != NULL)
    {
        *sequence = sqn;
    }
    if ((flags & LBTRM_DATA_RETRANSMISSION_FLAG) != 0)
    {
        is_retransmission = TRUE;
        expert_add_info_format(pinfo, sqn_item, &ei_lbtrm_analysis_rx, "RX 0x%08x", sqn);
    }
    if (retransmission != NULL)
    {
        *retransmission = is_retransmission;
    }
    tap_info->retransmission = is_retransmission;
    tap_info->sqn = sqn;
    return (L_LBTRM_DATA_HDR_T);
}

/*----------------------------------------------------------------------------*/
/* LBT-RM packet dissector.                                                   */
/*----------------------------------------------------------------------------*/
typedef struct
{
    proto_tree * tree;
    tvbuff_t * tvb;
    guint32 current_frame;
} lbtrm_sqn_frame_list_callback_data_t;

static gboolean dissect_lbtrm_sqn_frame_list_callback(void * frame, void * user_data)
{
    lbtrm_sqn_frame_list_callback_data_t * cb_data = (lbtrm_sqn_frame_list_callback_data_t *) user_data;
    proto_item * transport_item = NULL;
    lbm_transport_sqn_frame_t * sqn_frame = (lbm_transport_sqn_frame_t *) frame;

    if (sqn_frame->frame != cb_data->current_frame)
    {
        if (sqn_frame->retransmission)
        {
            transport_item = proto_tree_add_uint_format_value(cb_data->tree, hf_lbtrm_analysis_sqn_frame, cb_data->tvb, 0, 0, sqn_frame->frame, "%" G_GUINT32_FORMAT " (RX)", sqn_frame->frame);
        }
        else
        {
            transport_item = proto_tree_add_uint(cb_data->tree, hf_lbtrm_analysis_sqn_frame, cb_data->tvb, 0, 0, sqn_frame->frame);
        }
        PROTO_ITEM_SET_GENERATED(transport_item);
    }
    return (FALSE);
}

static int dissect_lbtrm(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data _U_)
{
    proto_tree * lbtrm_tree = NULL;
    proto_item * lbtrm_item;
    int offset = 0;
    guint8 next_hdr = 0;
    char * tag_name = NULL;
    int dissected_len = 0;
    int total_dissected_len = 0;
    proto_tree * hdr_tree = NULL;
    proto_item * hdr_item = NULL;
    proto_tree * ver_type_tree = NULL;
    proto_item * ver_type_item = NULL;
    guint16 src_port = 0;
    guint32 session_id = 0;
    guint16 dest_port = 0;
    lbtrm_transport_t * transport = NULL;
    proto_tree * transport_tree = NULL;
    proto_item * transport_item = NULL;
    guint32 sequence = 0;
    gboolean retransmission = FALSE;
    guint8 packet_type = 0;
    guint64 channel = LBM_CHANNEL_NO_CHANNEL;
    guint8 ver_type = 0;
    guint8 flags_fec_type = 0;
    guint16 num_naks = 0;
    guint16 num_ncfs = 0;
    lbm_lbtrm_tap_info_t * tapinfo = NULL;
    proto_item * header_type_item = NULL;

    col_add_str(pinfo->cinfo, COL_PROTOCOL, "LBT-RM");
    col_clear(pinfo->cinfo, COL_INFO);
    if (lbtrm_use_tag)
    {
        tag_name = lbtrm_tag_find(pinfo);
    }
    if (tag_name != NULL)
    {
        col_add_fstr(pinfo->cinfo, COL_INFO, "[Tag: %s]", tag_name);
    }
    col_set_fence(pinfo->cinfo, COL_INFO);

    ver_type = tvb_get_guint8(tvb, O_LBTRM_HDR_T_VER_TYPE);
    packet_type = LBTRM_HDR_TYPE(ver_type);
    next_hdr = tvb_get_guint8(tvb, O_LBTRM_HDR_T_NEXT_HDR);
    src_port = tvb_get_ntohs(tvb, O_LBTRM_HDR_T_UCAST_PORT);
    session_id = tvb_get_ntohl(tvb, O_LBTRM_HDR_T_SESSION_ID);
    if (tag_name != NULL)
    {
        lbtrm_item = proto_tree_add_protocol_format(tree, proto_lbtrm, tvb, offset, -1, "LBT-RM Protocol (Tag: %s): Version %u, Type %s: Source Unicast Port %" G_GUINT16_FORMAT ", Session ID 0x%08x",
            tag_name, LBTRM_HDR_VER(ver_type), val_to_str(packet_type, lbtrm_packet_type, "Unknown (0x%02x)"),
            src_port, session_id);
    }
    else
    {
        lbtrm_item = proto_tree_add_protocol_format(tree, proto_lbtrm, tvb, offset, -1, "LBT-RM Protocol: Version %u, Type %s: Source Unicast Port %" G_GUINT16_FORMAT ", Session ID 0x%08x",
            LBTRM_HDR_VER(ver_type), val_to_str(packet_type, lbtrm_packet_type, "Unknown (0x%02x)"),
            src_port, session_id);
    }
    lbtrm_tree = proto_item_add_subtree(lbtrm_item, ett_lbtrm);

    /* Addresses are in network order, ports in host order. */
    dest_port = pinfo->destport;

    if (PINFO_FD_VISITED(pinfo) == 0)
    {
        /* First time through - add the info. */
        /* Note that this won't handle the case when a NAK occurs in the capture before any other packets for that transport. Oh well. */
        if (packet_type == LBTRM_PACKET_TYPE_NAK)
        {
            transport = lbtrm_transport_unicast_find(&(pinfo->dst), src_port, session_id, pinfo->fd->num);
        }
        else
        {
            transport = lbtrm_transport_add(&(pinfo->src), src_port, session_id, &(pinfo->dst), dest_port, pinfo->fd->num);
        }
    }
    else
    {
        if (packet_type == LBTRM_PACKET_TYPE_NAK)
        {
            transport = lbtrm_transport_unicast_find(&(pinfo->dst), src_port, session_id, pinfo->fd->num);
        }
        else
        {
            transport = lbtrm_transport_find(&(pinfo->src), src_port, session_id, &(pinfo->dst), dest_port, pinfo->fd->num);
        }
    }
    if (transport != NULL)
    {
        proto_item * item = NULL;

        channel = transport->channel;
        item = proto_tree_add_uint64(lbtrm_tree, hf_lbtrm_channel, tvb, 0, 0, channel);
        PROTO_ITEM_SET_GENERATED(item);
    }
    if (tag_name != NULL)
    {
        proto_item * item = NULL;

        item = proto_tree_add_string(lbtrm_tree, hf_lbtrm_tag, tvb, 0, 0, tag_name);
        PROTO_ITEM_SET_GENERATED(item);
    }
    tapinfo = wmem_new0(wmem_packet_scope(), lbm_lbtrm_tap_info_t);
    if (transport != NULL)
    {
        tapinfo->transport = lbtrm_transport_source_string_transport(transport);
    }
    tapinfo->type = packet_type;

    hdr_item = proto_tree_add_item(lbtrm_tree, hf_lbtrm_hdr, tvb, O_LBTRM_HDR_T_VER_TYPE, L_LBTRM_HDR_T, ENC_NA);
    hdr_tree = proto_item_add_subtree(hdr_item, ett_lbtrm_hdr);
    ver_type_item = proto_tree_add_none_format(hdr_tree, hf_lbtrm_hdr_ver_type, tvb, O_LBTRM_HDR_T_VER_TYPE, L_LBTRM_HDR_T_VER_TYPE, "Version/Type: Version %u, Type %s",
        LBTRM_HDR_VER(ver_type), val_to_str(packet_type, lbtrm_packet_type, "Unknown (0x%02x)"));
    ver_type_tree = proto_item_add_subtree(ver_type_item, ett_lbtrm_hdr_ver_type);
    proto_tree_add_item(ver_type_tree, hf_lbtrm_hdr_ver_type_ver, tvb, O_LBTRM_HDR_T_VER_TYPE, L_LBTRM_HDR_T_VER_TYPE, ENC_BIG_ENDIAN);
    header_type_item = proto_tree_add_item(ver_type_tree, hf_lbtrm_hdr_ver_type_type, tvb, O_LBTRM_HDR_T_VER_TYPE, L_LBTRM_HDR_T_VER_TYPE, ENC_BIG_ENDIAN);
    /* Setup the INFO column for this packet. */
    switch (packet_type)
    {
        case LBTRM_PACKET_TYPE_DATA:
            sequence = tvb_get_ntohl(tvb, L_LBTRM_HDR_T + O_LBTRM_DATA_HDR_T_SQN);
            flags_fec_type = tvb_get_guint8(tvb, L_LBTRM_HDR_T + O_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE);
            if ((flags_fec_type & LBTRM_DATA_RETRANSMISSION_FLAG) != 0)
            {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "DATA(RX) sqn 0x%x Port %" G_GUINT16_FORMAT " ID 0x%08x", sequence, src_port, session_id);
            }
            else
            {
                col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "DATA sqn 0x%x Port %" G_GUINT16_FORMAT " ID 0x%08x", sequence, src_port, session_id);
            }
            break;
        case LBTRM_PACKET_TYPE_SM:
            sequence = tvb_get_ntohl(tvb, L_LBTRM_HDR_T + O_LBTRM_SM_HDR_T_SM_SQN);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "SM sqn 0x%x Port %" G_GUINT16_FORMAT " ID 0x%08x", sequence, src_port, session_id);
            break;
        case LBTRM_PACKET_TYPE_NAK:
            num_naks = tvb_get_ntohs(tvb, L_LBTRM_HDR_T + O_LBTRM_NAK_HDR_T_NUM_NAKS);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "NAK %u naks Port %" G_GUINT16_FORMAT " ID 0x%08x", num_naks, src_port, session_id);
            break;
        case LBTRM_PACKET_TYPE_NCF:
            num_ncfs = tvb_get_ntohs(tvb, L_LBTRM_HDR_T + O_LBTRM_NCF_HDR_T_NUM_NCFS);
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "NCF %u ncfs Port %" G_GUINT16_FORMAT " ID 0x%08x", num_ncfs, src_port, session_id);
            break;
        default:
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, " ", "Unknown (0x%02x)", packet_type);
            expert_add_info_format(pinfo, header_type_item, &ei_lbtrm_analysis_invalid_value, "Unrecognized type 0x%02x", packet_type);
            break;
    }

    proto_tree_add_item(hdr_tree, hf_lbtrm_hdr_next_hdr, tvb, O_LBTRM_HDR_T_NEXT_HDR, L_LBTRM_HDR_T_NEXT_HDR, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_lbtrm_hdr_ucast_port, tvb, O_LBTRM_HDR_T_UCAST_PORT, L_LBTRM_HDR_T_UCAST_PORT, ENC_BIG_ENDIAN);
    proto_tree_add_item(hdr_tree, hf_lbtrm_hdr_session_id, tvb, O_LBTRM_HDR_T_SESSION_ID, L_LBTRM_HDR_T_SESSION_ID, ENC_BIG_ENDIAN);
    total_dissected_len = L_LBTRM_HDR_T;
    offset = L_LBTRM_HDR_T;
    switch (packet_type)
    {
        case LBTRM_PACKET_TYPE_DATA:
            dissected_len = dissect_lbtrm_data(tvb, offset, pinfo, lbtrm_tree, &sequence, &retransmission, tapinfo);
            break;
        case LBTRM_PACKET_TYPE_SM:
            dissected_len = dissect_lbtrm_sm(tvb, offset, pinfo, lbtrm_tree, &sequence, tapinfo);
            break;
        case LBTRM_PACKET_TYPE_NAK:
            dissected_len = dissect_lbtrm_nak(tvb, offset, pinfo, lbtrm_tree, tapinfo);
            break;
        case LBTRM_PACKET_TYPE_NCF:
            dissected_len = dissect_lbtrm_ncf(tvb, offset, pinfo, lbtrm_tree, tapinfo);
            break;
        default:
            return (total_dissected_len);
            break;
    }
    total_dissected_len += dissected_len;
    offset += dissected_len;
    while (next_hdr != LBTRM_NHDR_DATA)
    {
        guint8 hdrlen = 0;

        next_hdr = tvb_get_guint8(tvb, offset + O_LBTRM_BASIC_OPT_T_NEXT_HDR);
        hdrlen = tvb_get_guint8(tvb, offset + O_LBTRM_BASIC_OPT_T_HDR_LEN);
        if (hdrlen == 0)
        {
            break;
        }
        offset += hdrlen;
        total_dissected_len += hdrlen;
    }

    if (lbtrm_sequence_analysis)
    {
        if (pinfo->fd->flags.visited == 0)
        {
            if (transport != NULL)
            {
                lbtrm_transport_frame_add(transport, packet_type, pinfo->fd->num, sequence, retransmission);
            }
        }
        else
        {
            if (transport != NULL)
            {
                lbm_transport_frame_t * frame = NULL;

                /* Setup the tree */
                transport_item = proto_tree_add_item(lbtrm_tree, hf_lbtrm_analysis, tvb, 0, 0, ENC_NA);
                PROTO_ITEM_SET_GENERATED(transport_item);
                transport_tree = proto_item_add_subtree(transport_item, ett_lbtrm_transport);
                frame = lbtrm_transport_frame_find(transport, pinfo->fd->num);
                if (frame != NULL)
                {
                    lbm_transport_sqn_t * sqn = NULL;

                    if (frame->previous_frame != 0)
                    {
                        transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_prev_frame, tvb, 0, 0, frame->previous_frame);
                        PROTO_ITEM_SET_GENERATED(transport_item);
                    }
                    if (frame->next_frame != 0)
                    {
                        transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_next_frame, tvb, 0, 0, frame->next_frame);
                        PROTO_ITEM_SET_GENERATED(transport_item);
                    }
                    switch (packet_type)
                    {
                        case LBTRM_PACKET_TYPE_DATA:
                            if (frame->previous_type_frame != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_prev_data_frame, tvb, 0, 0, frame->previous_type_frame);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                            }
                            if (frame->next_type_frame != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_next_data_frame, tvb, 0, 0, frame->next_type_frame);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                            }
                            sqn = lbtrm_transport_sqn_find(transport, packet_type, sequence);
                            if (sqn != NULL)
                            {
                                if (sqn->frame_count > 1)
                                {
                                    proto_tree * frame_tree = NULL;
                                    proto_item * frame_tree_item = NULL;
                                    lbtrm_sqn_frame_list_callback_data_t cb_data;

                                    frame_tree_item = proto_tree_add_item(transport_tree, hf_lbtrm_analysis_sqn, tvb, 0, 0, ENC_NA);
                                    PROTO_ITEM_SET_GENERATED(frame_tree_item);
                                    frame_tree = proto_item_add_subtree(frame_tree_item, ett_lbtrm_transport_sqn);
                                    cb_data.tree = frame_tree;
                                    cb_data.tvb = tvb;
                                    cb_data.current_frame = pinfo->fd->num;
                                    wmem_tree_foreach(sqn->frame, dissect_lbtrm_sqn_frame_list_callback, (void *) &cb_data);
                                }
                            }
                            if (frame->retransmission)
                            {
                                transport_item = proto_tree_add_boolean(transport_tree, hf_lbtrm_analysis_data_retransmission, tvb, 0, 0, TRUE);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                                expert_add_info(pinfo, transport_item, &ei_lbtrm_analysis_data_rx);
                            }
                            if (frame->sqn_gap != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_data_sqn_gap, tvb, 0, 0, frame->sqn_gap);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                                expert_add_info_format(pinfo, transport_item, &ei_lbtrm_analysis_data_gap, "Data sequence gap (%" G_GUINT32_FORMAT ")", frame->sqn_gap);
                            }
                            if (frame->ooo_gap != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_data_ooo_gap, tvb, 0, 0, frame->ooo_gap);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                                expert_add_info_format(pinfo, transport_item, &ei_lbtrm_analysis_data_ooo, "Data sequence out of order gap (%" G_GUINT32_FORMAT ")", frame->ooo_gap);
                            }
                            if (frame->duplicate)
                            {
                                transport_item = proto_tree_add_boolean(transport_tree, hf_lbtrm_analysis_data_duplicate, tvb, 0, 0, TRUE);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                                expert_add_info(pinfo, transport_item, &ei_lbtrm_analysis_data_dup);
                            }
                            break;
                        case LBTRM_PACKET_TYPE_SM:
                            if (frame->previous_type_frame != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_prev_sm_frame, tvb, 0, 0, frame->previous_type_frame);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                            }
                            if (frame->next_type_frame != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_next_sm_frame, tvb, 0, 0, frame->next_type_frame);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                            }
                            sqn = lbtrm_transport_sqn_find(transport, packet_type, sequence);
                            if (sqn != NULL)
                            {
                                if (sqn->frame_count > 1)
                                {
                                    proto_tree * frame_tree = NULL;
                                    proto_item * frame_tree_item = NULL;
                                    lbtrm_sqn_frame_list_callback_data_t cb_data;

                                    frame_tree_item = proto_tree_add_item(transport_tree, hf_lbtrm_analysis_sqn, tvb, 0, 0, ENC_NA);
                                    PROTO_ITEM_SET_GENERATED(frame_tree_item);
                                    frame_tree = proto_item_add_subtree(frame_tree_item, ett_lbtrm_transport_sqn);
                                    cb_data.tree = frame_tree;
                                    cb_data.tvb = tvb;
                                    cb_data.current_frame = pinfo->fd->num;
                                    wmem_tree_foreach(sqn->frame, dissect_lbtrm_sqn_frame_list_callback, (void *) &cb_data);
                                }
                            }
                            if (frame->sqn_gap != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_sm_sqn_gap, tvb, 0, 0, frame->sqn_gap);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                                expert_add_info_format(pinfo, transport_item, &ei_lbtrm_analysis_sm_gap, "SM sequence gap (%" G_GUINT32_FORMAT ")", frame->sqn_gap);
                            }
                            if (frame->ooo_gap != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_sm_ooo_gap, tvb, 0, 0, frame->ooo_gap);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                                expert_add_info_format(pinfo, transport_item, &ei_lbtrm_analysis_sm_ooo, "SM sequence out of order gap (%" G_GUINT32_FORMAT ")", frame->ooo_gap);
                            }
                            if (frame->duplicate)
                            {
                                transport_item = proto_tree_add_boolean(transport_tree, hf_lbtrm_analysis_sm_duplicate, tvb, 0, 0, TRUE);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                                expert_add_info(pinfo, transport_item, &ei_lbtrm_analysis_sm_dup);
                            }
                            break;
                        case LBTRM_PACKET_TYPE_NAK:
                            if (frame->previous_type_frame != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_prev_nak_frame, tvb, 0, 0, frame->previous_type_frame);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                            }
                            if (frame->next_type_frame != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_next_nak_frame, tvb, 0, 0, frame->next_type_frame);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                            }
                            break;
                        case LBTRM_PACKET_TYPE_NCF:
                            if (frame->previous_type_frame != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_prev_ncf_frame, tvb, 0, 0, frame->previous_type_frame);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                            }
                            if (frame->next_type_frame != 0)
                            {
                                transport_item = proto_tree_add_uint(transport_tree, hf_lbtrm_analysis_next_ncf_frame, tvb, 0, 0, frame->next_type_frame);
                                PROTO_ITEM_SET_GENERATED(transport_item);
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
        }
    }
    if ((packet_type == LBTRM_PACKET_TYPE_DATA) && (next_hdr == LBTRM_NHDR_DATA))
    {
        total_dissected_len += dissect_lbtrm_data_contents(tvb, offset, pinfo, tree, tag_name, channel);
    }
    if (tapinfo->transport != NULL)
    {
        tap_queue_packet(lbtrm_tap_handle, pinfo, (void *) tapinfo);
    }
    return (total_dissected_len);
}

static gboolean test_lbtrm_packet(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data)
{
    guint32 dest_addr_h;
    gboolean valid_packet = FALSE;
    guint8 ver_type = 0;
    guint8 packet_type = 0;
    guint8 packet_ver = 0;
    guint8 next_hdr = 0;

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
    if (tvb_reported_length_remaining(tvb, 0) < L_LBTRM_HDR_T)
    {
        return (FALSE);
    }
    ver_type = tvb_get_guint8(tvb, O_LBTRM_HDR_T_VER_TYPE);
    packet_type = LBTRM_HDR_TYPE(ver_type);
    switch (packet_type)
    {
        case LBTRM_PACKET_TYPE_DATA:
        case LBTRM_PACKET_TYPE_SM:
        case LBTRM_PACKET_TYPE_NAK:
        case LBTRM_PACKET_TYPE_NCF:
            break;
        default:
            return (FALSE);
    }
    packet_ver = LBTRM_HDR_VER(ver_type);
    if (packet_ver != LBTRM_VERSION)
    {
        return (FALSE);
    }
    next_hdr = tvb_get_guint8(tvb, O_LBTRM_HDR_T_NEXT_HDR);
    if (next_hdr != LBTRM_NHDR_DATA)
    {
        return (FALSE);
    }
    if (lbtrm_use_tag)
    {
        if (lbtrm_tag_find(pinfo) != NULL)
        {
            valid_packet = TRUE;
        }
    }
    else
    {
        dest_addr_h = pntoh32(pinfo->dst.data);

        /* Is the destination a multicast address? */
        if (IN_MULTICAST(dest_addr_h))
        {
            /* Check the MC address. */
            if ((dest_addr_h >= lbtrm_mc_address_low_host) && (dest_addr_h <= lbtrm_mc_address_high_host))
            {
                /* It's in the LBT-RM multicast range. Check the ports. */
                if ((pinfo->destport >= lbtrm_dest_port_low) && (pinfo->destport <= lbtrm_dest_port_high))
                {
                    /* Must be one of ours. */
                    valid_packet = TRUE;
                }
            }
            else if ((dest_addr_h == mim_incoming_mc_address_host) || (dest_addr_h == mim_outgoing_mc_address_host))
            {
                /* Might be MIM. Check the port. */
                if (((dest_addr_h == mim_incoming_mc_address_host) && (pinfo->destport == mim_incoming_dest_port))
                    || ((dest_addr_h == mim_outgoing_mc_address_host) && (pinfo->destport == mim_outgoing_dest_port)))
                {
                    /* Must be one of ours. */
                    valid_packet = TRUE;
                }
            }
        }
        else
        {
            /* Not multicast, might be a unicast UDP NAK. Check the destination port. */
            if ((pinfo->destport >= lbtrm_src_port_low) && (pinfo->destport <= lbtrm_src_port_high))
            {
                valid_packet = TRUE;
            }
        }
    }
    if (valid_packet)
    {
        dissect_lbtrm(tvb, pinfo, tree, user_data);
        return (TRUE);
    }
    return (FALSE);
}

/* Register all the bits needed with the filtering engine */
void proto_register_lbtrm(void)
{
    static hf_register_info hf[] =
    {
        { &hf_lbtrm_channel,
            { "Channel ID", "lbtrm.channel", FT_UINT64, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_tag,
            { "Tag", "lbtrm.tag", FT_STRING, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_hdr,
            { "Header", "lbtrm.hdr", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_hdr_ver_type,
            { "Version/Type", "lbtrm.hdr.ver_type", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_hdr_ver_type_ver,
            { "Version", "lbtrm.hdr.ver_type.ver", FT_UINT8, BASE_DEC, NULL, LBTRM_HDR_VER_MASK, NULL, HFILL } },
        { &hf_lbtrm_hdr_ver_type_type,
            { "Type", "lbtrm.hdr.ver_type.type", FT_UINT8, BASE_HEX, VALS(lbtrm_packet_type), LBTRM_HDR_TYPE_MASK, NULL, HFILL } },
        { &hf_lbtrm_hdr_next_hdr,
            { "Next Header", "lbtrm.hdr.next_hdr", FT_UINT8, BASE_HEX, VALS(lbtrm_next_header), 0x0, NULL, HFILL } },
        { &hf_lbtrm_hdr_ucast_port,
            { "Source Unicast Port", "lbtrm.hdr.ucast_port", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_hdr_session_id,
            { "Session ID", "lbtrm.hdr.session_id", FT_UINT32, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_data,
            { "Data Header", "lbtrm.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_data_sqn,
            { "Sequence Number", "lbtrm.data.sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_data_trail_sqn,
            { "Trailing Edge Sequence Number", "lbtrm.data.trail_sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_data_flags_fec_type,
            { "FEC Flags", "lbtrm.data.flags_fec_type", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_data_flags_fec_type_ucast_naks,
            { "Unicast NAKs", "lbtrm.data.flags_fec_type.ucast_naks", FT_BOOLEAN, L_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE * 8, TFS(&tfs_set_notset), LBTRM_DATA_UNICAST_NAKS_FLAG, "Set if NAKs are sent via unicast", HFILL } },
        { &hf_lbtrm_data_flags_fec_type_rx,
            { "Retransmission", "lbtrm.data.flags_fec_type.rx", FT_BOOLEAN, L_LBTRM_DATA_HDR_T_FLAGS_FEC_TYPE * 8, TFS(&tfs_set_notset), LBTRM_DATA_RETRANSMISSION_FLAG, "Set if this is a retransmission", HFILL } },
        { &hf_lbtrm_data_flags_tgsz,
            { "TGSZ Flags", "lbtrm.data.flags_tgsz", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_data_fec_symbol,
            { "FEC Symbol", "lbtrm.data.fec_symbol", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_sm,
            { "Session Message Header", "lbtrm.sm", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_sm_sm_sqn,
            { "Sequence Number", "lbtrm.sm.sm_sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_sm_lead_sqn,
            { "Lead Sequence Number", "lbtrm.sm.lead_sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_sm_trail_sqn,
            { "Trail Sequence Number", "lbtrm.sm.trail_sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_sm_flags_fec_type,
            { "FEC Flags", "lbtrm.sm.flags_fec_type", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_sm_flags_fec_type_ucast_naks,
            { "Unicast NAKs", "lbtrm.sm.flags_fec_type.ucast_naks", FT_BOOLEAN, 8, TFS(&tfs_present_not_present), LBTRM_SM_UNICAST_NAKS_FLAG, "Set if NAKs are sent via unicast", HFILL } },
        { &hf_lbtrm_sm_flags_tgsz,
            { "TGSZ Flags", "lbtrm.sm.flags_tgsz", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_sm_reserved,
            { "Reserved", "lbtrm.sm.reserved", FT_UINT16, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_nak,
            { "NAK Header", "lbtrm.nak", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_nak_num_naks,
            { "Number of NAKs", "lbtrm.nak.num_naks", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_nak_format,
            { "Format", "lbtrm.nak.format", FT_UINT8, BASE_HEX, VALS(lbtrm_nak_format), LBTRM_NAK_HDR_FORMAT_MASK, NULL, HFILL } },
        { &hf_lbtrm_nak_list,
            { "NAK List", "lbtrm.nak.list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_nak_list_nak,
            { "NAK", "lbtrm.nak.list.nak", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_ncf,
            { "NAK Confirmation Header", "lbtrm.ncf", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_ncf_trail_sqn,
            { "Trailing Sequence Number", "lbtrm.ncf.trail_sqn", FT_UINT32, BASE_HEX_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_ncf_num_ncfs,
            { "Number of Individual NCFs", "lbtrm.ncf.num_ncfs", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_ncf_reserved,
            { "Reserved", "lbtrm.ncf.reserved", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_ncf_reason_format,
            { "Reason/Format", "lbtrm.ncf.reason_format", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_ncf_reason_format_reason,
            { "Reason", "lbtrm.ncf.reason", FT_UINT8, BASE_HEX, VALS(lbtrm_ncf_reason), LBTRM_NCF_HDR_REASON_MASK, NULL, HFILL } },
        { &hf_lbtrm_ncf_reason_format_format,
            { "Format", "lbtrm.ncf.format", FT_UINT8, BASE_HEX, VALS(lbtrm_ncf_format), LBTRM_NCF_HDR_FORMAT_MASK, NULL, HFILL } },
        { &hf_lbtrm_ncf_list,
            { "NCF List", "lbtrm.ncf.list", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_ncf_list_ncf,
            { "NCF", "lbtrm.ncf.list.ncf", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis,
            { "Transport Analysis", "lbtrm.transport", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_prev_frame,
            { "Previous Transport frame", "lbtrm.transport.prev_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_prev_data_frame,
            { "Previous Transport DATA frame", "lbtrm.transport.prev_data_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_prev_sm_frame,
            { "Previous Transport SM frame", "lbtrm.transport.prev_sm_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_prev_nak_frame,
            { "Previous Transport NAK frame", "lbtrm.transport.prev_nak_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_prev_ncf_frame,
            { "Previous Transport NCF frame", "lbtrm.transport.prev_ncf_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_next_frame,
            { "Next Transport frame", "lbtrm.transport.next_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_next_data_frame,
            { "Next Transport DATA frame", "lbtrm.transport.next_data_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_next_sm_frame,
            { "Next Transport SM frame", "lbtrm.transport.next_sm_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_next_nak_frame,
            { "Next Transport NAK frame", "lbtrm.transport.next_nak_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_next_ncf_frame,
            { "Next Transport NCF frame", "lbtrm.transport.next_ncf_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_sqn,
            { "SQN Also in", "lbtrm.transport.sqn", FT_NONE, BASE_NONE, NULL, 0x0, "Sequence number also appears in these frames", HFILL } },
        { &hf_lbtrm_analysis_sqn_frame,
            { "Frame", "lbtrm.transport.sqn.frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_data_retransmission,
            { "Frame is a Data Retransmission", "lbtrm.transport.data_retransmission", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_data_sqn_gap,
            { "Gap in Data Sequence", "lbtrm.transport.data_sqn_gap", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_data_ooo_gap,
            { "Data Sequence Out of Order Gap", "lbtrm.transport.data_ooo_gap", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_data_duplicate,
            { "Duplicate Data frame", "lbtrm.transport.data_duplicate", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_sm_sqn_gap,
            { "Gap in SM Sequence", "lbtrm.transport.sm_sqn_gap", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_sm_ooo_gap,
            { "SM Sequence Out of Order Gap", "lbtrm.transport.sm_ooo_gap", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_lbtrm_analysis_sm_duplicate,
            { "Duplicate SM frame", "lbtrm.transport.sm_duplicate", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
    };
    static gint * ett[] =
    {
        &ett_lbtrm,
        &ett_lbtrm_hdr,
        &ett_lbtrm_hdr_ver_type,
        &ett_lbtrm_data,
        &ett_lbtrm_data_flags_fec_type,
        &ett_lbtrm_sm,
        &ett_lbtrm_sm_flags_fec_type,
        &ett_lbtrm_nak,
        &ett_lbtrm_nak_list,
        &ett_lbtrm_ncf,
        &ett_lbtrm_ncf_reason_format,
        &ett_lbtrm_ncf_list,
        &ett_lbtrm_transport,
        &ett_lbtrm_transport_sqn
    };
    static ei_register_info ei[] =
    {
        { &ei_lbtrm_analysis_ncf, { "lbtrm.analysis.ncf", PI_SEQUENCE, PI_NOTE, "NCF", EXPFILL } },
        { &ei_lbtrm_analysis_ncf_ncf, { "lbtrm.analysis.ncf.ncf", PI_SEQUENCE, PI_NOTE, "NCF", EXPFILL } },
        { &ei_lbtrm_analysis_nak, { "lbtrm.analysis.nak", PI_SEQUENCE, PI_WARN, "NAK", EXPFILL } },
        { &ei_lbtrm_analysis_nak_nak, { "lbtrm.analysis.nak.nak", PI_SEQUENCE, PI_WARN, "NAK", EXPFILL } },
        { &ei_lbtrm_analysis_sm, { "lbtrm.analysis.sm", PI_SEQUENCE, PI_CHAT, "SM", EXPFILL } },
        { &ei_lbtrm_analysis_rx, { "lbtrm.analysis.rx", PI_SEQUENCE, PI_NOTE, "RX", EXPFILL } },
        { &ei_lbtrm_analysis_invalid_value, { "lbtrm.analysis.invalid_value", PI_MALFORMED, PI_ERROR, "Invalid value", EXPFILL } },
        { &ei_lbtrm_analysis_data_rx, { "lbtrm.analysis.data.rx", PI_SEQUENCE, PI_NOTE, "Data RX", EXPFILL } },
        { &ei_lbtrm_analysis_data_gap, { "lbtrm.analysis.data.gap", PI_SEQUENCE, PI_NOTE, "Data sequence gap", EXPFILL } },
        { &ei_lbtrm_analysis_data_ooo, { "lbtrm.analysis.data.ooo", PI_SEQUENCE, PI_NOTE, "Data out of order", EXPFILL } },
        { &ei_lbtrm_analysis_data_dup, { "lbtrm.analysis.data.dup", PI_SEQUENCE, PI_NOTE, "Duplicate data", EXPFILL } },
        { &ei_lbtrm_analysis_sm_gap, { "lbtrm.analysis.sm.gap", PI_SEQUENCE, PI_NOTE, "SM sequence gap", EXPFILL } },
        { &ei_lbtrm_analysis_sm_ooo, { "lbtrm.analysis.sm.ooo", PI_SEQUENCE, PI_NOTE, "SM out of order", EXPFILL } },
        { &ei_lbtrm_analysis_sm_dup, { "lbtrm.analysis.sm.dup", PI_SEQUENCE, PI_NOTE, "Duplicate SM", EXPFILL } },
    };
    module_t * lbtrm_module;
    struct in_addr addr;
    uat_t * tag_uat;
    expert_module_t * expert_lbtrm;

    proto_lbtrm = proto_register_protocol("LBT Reliable Multicast Protocol",
        "LBT-RM", "lbtrm");

    proto_register_field_array(proto_lbtrm, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_lbtrm = expert_register_protocol(proto_lbtrm);
    expert_register_field_array(expert_lbtrm, ei, array_length(ei));

    lbtrm_module = prefs_register_protocol_subtree("29West", proto_lbtrm, proto_reg_handoff_lbtrm);
    inet_aton(LBTRM_DEFAULT_MC_ADDRESS_LOW, &addr);
    lbtrm_mc_address_low_host = g_ntohl(addr.s_addr);
    prefs_register_string_preference(lbtrm_module,
        "mc_address_low",
        "Multicast address range low (default " LBTRM_DEFAULT_MC_ADDRESS_LOW ")",
        "Set the low end of the LBT-RM multicast address range (context transport_lbtrm_multicast_address_low)",
        &global_lbtrm_mc_address_low);

    inet_aton(LBTRM_DEFAULT_MC_ADDRESS_HIGH, &addr);
    lbtrm_mc_address_high_host = g_ntohl(addr.s_addr);
    prefs_register_string_preference(lbtrm_module,
        "mc_address_high",
        "Multicast address range high (default " LBTRM_DEFAULT_MC_ADDRESS_HIGH ")",
        "Set the high end of the LBT-RM multicast address range (context transport_lbtrm_multicast_address_high)",
        &global_lbtrm_mc_address_high);

    prefs_register_uint_preference(lbtrm_module,
        "dport_low",
        "Destination port range low (default " MAKESTRING(LBTRM_DEFAULT_DPORT_LOW)")",
        "Set the low end of the LBT-RM UDP destination port range (source transport_lbtrm_destination_port)",
        10,
        &global_lbtrm_dest_port_low);

    prefs_register_uint_preference(lbtrm_module,
        "dport_high",
        "Destination port range high (default " MAKESTRING(LBTRM_DEFAULT_DPORT_HIGH)")",
        "Set the high end of the LBT-RM UDP destination port range (source transport_lbtrm_destination_port)",
        10,
        &global_lbtrm_dest_port_high);

    prefs_register_uint_preference(lbtrm_module,
        "sport_low",
        "Source port range low (default " MAKESTRING(LBTRM_DEFAULT_SPORT_LOW)")",
        "Set the low end of the LBT-RM UDP source port range (context transport_lbtrm_source_port_low)",
        10,
        &global_lbtrm_src_port_low);

    prefs_register_uint_preference(lbtrm_module,
        "sport_high",
        "Source port range high (default " MAKESTRING(LBTRM_DEFAULT_SPORT_HIGH)")",
        "Set the high end of the LBT-RM UDP source port range (context transport_lbtrm_source_port_high)",
        10,
        &global_lbtrm_src_port_high);

    inet_aton(MIM_DEFAULT_MC_INCOMING_ADDRESS, &addr);
    mim_incoming_mc_address_host = g_ntohl(addr.s_addr);
    prefs_register_string_preference(lbtrm_module,
        "mim_incoming_address",
        "MIM incoming multicast address (default " MIM_DEFAULT_MC_INCOMING_ADDRESS ")",
        "Set the incoming MIM multicast address (context mim_incoming_address)",
        &global_mim_incoming_mc_address);

    inet_aton(MIM_DEFAULT_MC_OUTGOING_ADDRESS, &addr);
    mim_outgoing_mc_address_host = g_ntohl(addr.s_addr);
    prefs_register_string_preference(lbtrm_module,
        "mim_outgoing_address",
        "MIM outgoing multicast address (default " MIM_DEFAULT_MC_OUTGOING_ADDRESS ")",
        "Set the outgoing MIM multicast address (context mim_outgoing_address)",
        &global_mim_incoming_mc_address);

    prefs_register_uint_preference(lbtrm_module,
        "mim_incoming_dport",
        "MIM incoming port (default " MAKESTRING(MIM_DEFAULT_INCOMING_DPORT)")",
        "Set the incoming MIM UDP port (context mim_incoming_destination_port)",
        10,
        &global_mim_incoming_dest_port);

    prefs_register_uint_preference(lbtrm_module,
        "mim_outgoing_dport",
        "MIM outgoing port (default " MAKESTRING(MIM_DEFAULT_OUTGOING_DPORT)")",
        "Set the outgoing MIM UDP port (context mim_outgoing_destination_port)",
        10,
        &global_mim_outgoing_dest_port);

    lbtrm_expert_separate_naks = global_lbtrm_expert_separate_naks;
    prefs_register_bool_preference(lbtrm_module,
        "expert_separate_naks",
        "Separate NAKs in Expert Info",
        "Separate multiple NAKs from a single packet into distinct Expert Info entries",
        &global_lbtrm_expert_separate_naks);

    lbtrm_expert_separate_ncfs = global_lbtrm_expert_separate_ncfs;
    prefs_register_bool_preference(lbtrm_module,
        "expert_separate_ncfs",
        "Separate NCFs in Expert Info",
        "Separate multiple NCFs from a single packet into distinct Expert Info entries",
        &global_lbtrm_expert_separate_ncfs);

    lbtrm_sequence_analysis = global_lbtrm_sequence_analysis;
    prefs_register_bool_preference(lbtrm_module,
        "sequence_analysis",
        "Perform sequence Number Analysis",
        "Perform analysis on LBT-RM sequence numbers to determine out-of-order, gaps, loss, etc",
        &global_lbtrm_sequence_analysis);

    lbtrm_use_tag = global_lbtrm_use_tag;
    prefs_register_bool_preference(lbtrm_module,
        "use_lbtrm_domain",
        "Use LBT-RM tag table",
        "Use table of LBT-RM tags to decode the packet instead of above values",
        &global_lbtrm_use_tag);
    tag_uat = uat_new("LBT-RM tag definitions",
        sizeof(lbtrm_tag_entry_t),
        "lbtrm_domains",
        TRUE,
        (void * *)&lbtrm_tag_entry,
        &lbtrm_tag_count,
        UAT_AFFECTS_DISSECTION,
        NULL,
        lbtrm_tag_copy_cb,
        lbtrm_tag_update_cb,
        lbtrm_tag_free_cb,
        NULL,
        lbtrm_tag_array);
    prefs_register_uat_preference(lbtrm_module,
        "tnw_lbtrm_tags",
        "LBT-RM Tags",
        "A table to define LBT-RM tags",
        tag_uat);
}

/* The registration hand-off routine */
void proto_reg_handoff_lbtrm(void)
{
    static gboolean already_registered = FALSE;
    struct in_addr addr;
    guint32 dest_addr_h_low;
    guint32 dest_addr_h_high;

    if (!already_registered)
    {
        lbtrm_dissector_handle = new_create_dissector_handle(dissect_lbtrm, proto_lbtrm);
        dissector_add_for_decode_as("udp.port", lbtrm_dissector_handle);
        heur_dissector_add("udp", test_lbtrm_packet, proto_lbtrm);
        lbtrm_tap_handle = register_tap("lbtrm");
    }

    /* Make sure the low MC address is <= the high MC address. If not, don't change them. */
    inet_aton(global_lbtrm_mc_address_low, &addr);
    dest_addr_h_low = g_ntohl(addr.s_addr);
    inet_aton(global_lbtrm_mc_address_high, &addr);
    dest_addr_h_high = g_ntohl(addr.s_addr);
    if (dest_addr_h_low <= dest_addr_h_high)
    {
        lbtrm_mc_address_low_host = dest_addr_h_low;
        lbtrm_mc_address_high_host = dest_addr_h_high;
    }

    /* Make sure the low destination port is <= the high destination port. If not, don't change them. */
    if (global_lbtrm_dest_port_low <= global_lbtrm_dest_port_high)
    {
        lbtrm_dest_port_low = global_lbtrm_dest_port_low;
        lbtrm_dest_port_high = global_lbtrm_dest_port_high;
    }

    /* Make sure the low source port is <= the high source port. If not, don't change them. */
    if (global_lbtrm_src_port_low <= global_lbtrm_src_port_high)
    {
        lbtrm_src_port_low = global_lbtrm_src_port_low;
        lbtrm_src_port_high = global_lbtrm_src_port_high;
    }

    /* Add the dissector hooks for the MIM MC groups. */
    inet_aton(global_mim_incoming_mc_address, &addr);
    mim_incoming_mc_address_host = g_htonl(addr.s_addr);
    inet_aton(global_mim_outgoing_mc_address, &addr);
    mim_outgoing_mc_address_host = g_htonl(addr.s_addr);

    /* Add the dissector hooks for the MIM ports. */
    mim_incoming_dest_port = global_mim_incoming_dest_port;
    mim_outgoing_dest_port = global_mim_outgoing_dest_port;

    lbtrm_expert_separate_naks = global_lbtrm_expert_separate_naks;
    lbtrm_expert_separate_ncfs = global_lbtrm_expert_separate_ncfs;

    lbtrm_sequence_analysis = global_lbtrm_sequence_analysis;

    lbtrm_use_tag = global_lbtrm_use_tag;

    already_registered = TRUE;
}

/*
 * Editor modelines  -  http://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 4
 * tab-width: 4
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=4 tabstop=4 expandtab:
 * :indentSize=4:tabSize=4:noTabs=true:
 */
