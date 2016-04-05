/* packet-aeron.c
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

#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/expert.h>
#include <epan/uat.h>
#include <epan/tap.h>
#include <epan/conversation.h>
#include <epan/exceptions.h>
#include <epan/to_str.h>
#include <wsutil/inet_aton.h>
#include <wsutil/pint.h>

/* The Aeron protocol is defined at https://github.com/real-logic/Aeron/wiki/Protocol-Specification */

void proto_register_aeron(void);
void proto_reg_handoff_aeron(void);

/* Protocol handle */
static int proto_aeron = -1;

/* Dissector handles */
static dissector_handle_t aeron_dissector_handle;
static heur_dissector_list_t aeron_heuristic_subdissector_list;

/*----------------------------------------------------------------------------*/
/* Preferences.                                                               */
/*----------------------------------------------------------------------------*/

static gboolean aeron_sequence_analysis = FALSE;
static gboolean aeron_stream_analysis = FALSE;
static gboolean aeron_reassemble_fragments = FALSE;
static gboolean aeron_use_heuristic_subdissectors = FALSE;

/*----------------------------------------------------------------------------*/
/* Aeron position routines.                                                   */
/*----------------------------------------------------------------------------*/
typedef struct
{
    guint32 term_id;
    guint32 term_offset;
} aeron_pos_t;

static int aeron_pos_roundup(int offset)
{
    return ((offset+7) & 0xfffffff8);
}

static int aeron_pos_compare(const aeron_pos_t * pos1, const aeron_pos_t * pos2)
{
    /* Returns:
        < 0  if pos1 < pos2
        == 0 if pos1 == pos2
        > 0  if pos1 > pos2
    */
    if (pos1->term_id == pos2->term_id)
    {
        if (pos1->term_offset == pos2->term_offset)
        {
            return (0);
        }
        else
        {
            return ((pos1->term_offset < pos2->term_offset) ? -1 : 1);
        }
    }
    else
    {
        return ((pos1->term_id < pos2->term_id) ? -1 : 1);
    }
}

static guint32 aeron_pos_delta(const aeron_pos_t * pos1, const aeron_pos_t * pos2, guint32 term_size)
{
    const aeron_pos_t * p1;
    const aeron_pos_t * p2;
    guint64 p1_val;
    guint64 p2_val;
    guint64 delta;
    int rc;

    rc = aeron_pos_compare(pos1, pos2);
    if (rc >= 0)
    {
        p1 = pos1;
        p2 = pos2;
    }
    else
    {
        p1 = pos2;
        p2 = pos1;
    }
    p1_val = ((guint64) p1->term_id * term_size) + ((guint64) p1->term_offset);
    p2_val = ((guint64) p2->term_id * term_size) + ((guint64) p2->term_offset);
    delta = p1_val - p2_val;
    return ((guint32) (delta & G_GUINT64_CONSTANT(0x00000000ffffffff)));
}

static gboolean aeron_pos_add_length(aeron_pos_t * pos, guint32 length, guint32 term_length)
{
    guint32 next_term_offset;
    guint32 rounded_next_term_offset;

    next_term_offset = pos->term_offset + length;
    if (next_term_offset < pos->term_offset)
        return FALSE;  /* overflow */
    rounded_next_term_offset = aeron_pos_roundup(next_term_offset);
    if (rounded_next_term_offset < next_term_offset)
        return FALSE;  /* overflow */
    next_term_offset = rounded_next_term_offset;

    if (next_term_offset >= term_length)
    {
        pos->term_offset = 0;
        pos->term_id++;
    }
    else
    {
        pos->term_offset = next_term_offset;
    }
    return TRUE;
}

/*----------------------------------------------------------------------------*/
/* Aeron frame information management.                                        */
/*----------------------------------------------------------------------------*/
static wmem_tree_t * aeron_frame_info_tree = NULL;

struct aeron_frame_info_t_stct;
typedef struct aeron_frame_info_t_stct aeron_frame_info_t;

typedef struct
{
    aeron_frame_info_t * frame_info;        /* Frame (aeron_frame_info_t) containing the RX data */
    guint32 term_offset;                 /* Term offset of RX data */
    guint32 length;                      /* Length of RX data */
} aeron_rx_info_t;

typedef struct
{
    aeron_frame_info_t * frame_info;        /* Frame (aeron_frame_info_t) in which this NAK occurs */
    wmem_list_t * rx;                       /* List of RX frames for this NAK */
    guint32 flags;
    guint32 nak_term_offset;                /* Term offset specified by this NAK */
    guint32 nak_length;                     /* NAK length */
    guint32 unrecovered_length;             /* Number of bytes unrecovered via RX */
} aeron_nak_analysis_t;

typedef struct
{
    guint32 flags;
    guint32 flags2;
    aeron_pos_t high;
    aeron_pos_t completed;
    guint32 receiver_window;
    guint32 outstanding_bytes;
} aeron_stream_analysis_t;
#define AERON_STREAM_ANALYSIS_FLAGS_WINDOW_FULL      0x00000001
#define AERON_STREAM_ANALYSIS_FLAGS_IDLE_RX          0x00000002
#define AERON_STREAM_ANALYSIS_FLAGS_PACING_RX        0x00000004
#define AERON_STREAM_ANALYSIS_FLAGS_OOO              0x00000008
#define AERON_STREAM_ANALYSIS_FLAGS_OOO_GAP          0x00000010
#define AERON_STREAM_ANALYSIS_FLAGS_KEEPALIVE        0x00000020
#define AERON_STREAM_ANALYSIS_FLAGS_WINDOW_RESIZE    0x00000040
#define AERON_STREAM_ANALYSIS_FLAGS_OOO_SM           0x00000080
#define AERON_STREAM_ANALYSIS_FLAGS_KEEPALIVE_SM     0x00000100
#define AERON_STREAM_ANALYSIS_FLAGS_RX               0x00000200
#define AERON_STREAM_ANALYSIS_FLAGS_TERM_ID_CHANGE   0x00000400

#define AERON_STREAM_ANALYSIS_FLAGS2_RCV_VALID       0x00000001

typedef struct
{
    guint32 previous;
    guint32 next;
} aeron_frame_link_t;

struct aeron_msg_t_stct;
typedef struct aeron_msg_t_stct aeron_msg_t;

struct aeron_frame_info_t_stct
{
    guint32 frame;
    guint32 ofs;
    aeron_frame_link_t transport;
    aeron_frame_link_t stream;
    aeron_frame_link_t term;
    aeron_frame_link_t fragment;
    aeron_stream_analysis_t * stream_analysis;
    aeron_nak_analysis_t * nak_analysis;
    aeron_msg_t * message;
    wmem_list_t * rx;
    guint32 flags;
};
#define AERON_FRAME_INFO_FLAGS_RETRANSMISSION  0x00000001
#define AERON_FRAME_INFO_FLAGS_KEEPALIVE       0x00000002
#define AERON_FRAME_INFO_FLAGS_REASSEMBLED_MSG 0x00000004

static wmem_tree_key_t * aeron_frame_info_key_build(guint32 frame, guint32 ofs)
{
    wmem_tree_key_t * fkey;
    guint32 * key;

    fkey = wmem_alloc_array(wmem_packet_scope(), wmem_tree_key_t, 2);
    key = wmem_alloc_array(wmem_packet_scope(), guint32, 2);
    key[0] = frame;
    key[1] = ofs;
    fkey[0].length = 2;
    fkey[0].key = key;
    fkey[1].length = 0;
    fkey[1].key = NULL;
    return (fkey);
}

static aeron_frame_info_t * aeron_frame_info_lookup(wmem_tree_key_t * key)
{
    aeron_frame_info_t * fi;

    fi = (aeron_frame_info_t *) wmem_tree_lookup32_array(aeron_frame_info_tree, key);
    return (fi);
}

static aeron_frame_info_t * aeron_frame_info_find(guint32 frame, guint32 ofs)
{
    wmem_tree_key_t * key = aeron_frame_info_key_build(frame, ofs);
    return (aeron_frame_info_lookup(key));
}

static aeron_frame_info_t * aeron_frame_info_add(guint32 frame, guint32 ofs)
{
    aeron_frame_info_t * fi;
    wmem_tree_key_t * key = aeron_frame_info_key_build(frame, ofs);

    fi = aeron_frame_info_lookup(key);
    if (fi == NULL)
    {
        fi = wmem_new0(wmem_file_scope(), aeron_frame_info_t);
        fi->frame = frame;
        fi->ofs = ofs;
        if (aeron_sequence_analysis && aeron_stream_analysis)
        {
            fi->rx = wmem_list_new(wmem_file_scope());
        }
        wmem_tree_insert32_array(aeron_frame_info_tree, key, (void *) fi);
    }
    return (fi);
}

/*----------------------------------------------------------------------------*/
/* Aeron channel ID management.                                               */
/*----------------------------------------------------------------------------*/
static guint64 aeron_channel_id = 1;

static guint64 aeron_channel_id_assign(void)
{
    return (aeron_channel_id++);
}

static void aeron_channel_id_init(void)
{
    aeron_channel_id = 1;
}

/*----------------------------------------------------------------------------*/
/* Aeron transport, stream, term, and fragment structures.                    */
/*----------------------------------------------------------------------------*/
typedef struct
{
    address * addr1;
    address * addr2;
    port_type ptype;
    guint16 port1;
    guint16 port2;
} aeron_conversation_info_t;

struct aeron_transport_t_stct;
typedef struct aeron_transport_t_stct aeron_transport_t;

struct aeron_stream_t_stct;
typedef struct aeron_stream_t_stct aeron_stream_t;

struct aeron_term_t_stct;
typedef struct aeron_term_t_stct aeron_term_t;

struct aeron_fragment_t_stct;
typedef struct aeron_fragment_t_stct aeron_fragment_t;

struct aeron_transport_t_stct
{
    guint64 channel_id;
    wmem_map_t * stream;                    /* Map of all streams (aeron_stream_t) in this transport, keyed by stream ID */
    aeron_frame_info_t * last_frame;
    address addr1;
    address addr2;
    guint32 session_id;
    guint16 port1;
    guint16 port2;
};

struct aeron_stream_rcv_t_stct;
typedef struct aeron_stream_rcv_t_stct aeron_stream_rcv_t;

struct aeron_stream_rcv_t_stct
{
    address addr;                           /* Receiver's IP address */
    guint16 port;                           /* Receiver's (sending) port */
    aeron_pos_t completed;
    guint32 receiver_window;
};

struct aeron_stream_t_stct
{
    aeron_transport_t * transport;          /* Parent transport */
    wmem_map_t * term;                      /* Map of all terms (aeron_term_t) in this stream, keyed by term ID */
    wmem_list_t * rcv;                      /* List of receivers (aeron_stream_rcv_t) */
    guint32 rcv_count;
    aeron_frame_info_t * last_frame;
    guint32 stream_id;
    guint32 term_length;
    guint32 mtu;
    guint32 flags;
    aeron_pos_t high;
};
#define AERON_STREAM_FLAGS_HIGH_VALID 0x1

typedef struct
{
    aeron_term_t * term;                    /* Parent term */
    aeron_frame_info_t * frame_info;        /* Frame info (aeron_frame_info_t) in which this NAK occurred */
    guint32 term_offset;                    /* NAK term offset */
    guint32 length;                         /* Length of NAK */
} aeron_nak_t;

struct aeron_term_t_stct
{
    aeron_stream_t * stream;                /* Parent stream */
    wmem_map_t * fragment;                  /* Map of all fragments (aeron_fragment_t) in this term, keyed by term offset */
    wmem_tree_t * message;                  /* Tree of all fragmented messages (aeron_msg_t) in this term, keyed by lowest term offset */
    wmem_list_t * orphan_fragment;
    aeron_frame_info_t * last_frame;        /* Pointer to last frame seen for this term */
    wmem_list_t * nak;                      /* List of all NAKs (aeron_nak_t) in this term */
    guint32 term_id;
};

struct aeron_fragment_t_stct
{
    aeron_term_t * term;                    /* Parent term */
    wmem_list_t * frame;                    /* List of frames (aeron_frame_info_t) containing this fragment (term offset) */
    aeron_frame_info_t * first_frame;       /* First frame which contains this fragment (term offset) */
    aeron_frame_info_t * last_frame;        /* Last frame which contains this fragment (term offset) */
    aeron_frame_info_t * first_data_frame;  /* First frame which contains this fragment (term offset) as actual data (not as a KA) */
    guint32 term_offset;
    guint32 length;
    guint32 data_length;
    guint32 frame_count;
};

/*----------------------------------------------------------------------------*/
/* Aeron transport management.                                                */
/*----------------------------------------------------------------------------*/
static guint aeron_guint32_hash_func(gconstpointer key)
{
    guint32 value = *((const guint32 *) key);
    return ((guint) value);
}

static gboolean aeron_guint32_compare_func(gconstpointer lhs, gconstpointer rhs)
{
    guint32 key1 = *((const guint32 *) lhs);
    guint32 key2 = *((const guint32 *) rhs);
    return ((key1 == key2) ? TRUE : FALSE);
}

static aeron_transport_t * aeron_transport_add(const aeron_conversation_info_t * cinfo, guint32 session_id, guint32 frame)
{
    aeron_transport_t * transport;
    conversation_t * conv;
    wmem_map_t * session_map;

    conv = find_conversation(frame, cinfo->addr1, cinfo->addr2, cinfo->ptype, cinfo->port1, cinfo->port2, 0);
    if (conv == NULL)
    {
        conv = conversation_new(frame, cinfo->addr1, cinfo->addr2, cinfo->ptype, cinfo->port1, cinfo->port2, 0);
    }
    if (frame > conv->last_frame)
    {
        conv->last_frame = frame;
    }
    session_map = (wmem_map_t *) conversation_get_proto_data(conv, proto_aeron);
    if (session_map == NULL)
    {
        session_map = wmem_map_new(wmem_file_scope(), aeron_guint32_hash_func, aeron_guint32_compare_func);
        conversation_add_proto_data(conv, proto_aeron, (void *) session_map);
    }
    transport = (aeron_transport_t *) wmem_map_lookup(session_map, (const void *) &session_id);
    if (transport != NULL)
    {
        return (transport);
    }
    transport = wmem_new0(wmem_file_scope(), aeron_transport_t);
    transport->channel_id = aeron_channel_id_assign();
    transport->stream = wmem_map_new(wmem_file_scope(), aeron_guint32_hash_func, aeron_guint32_compare_func);
    transport->last_frame = NULL;
    copy_address_wmem(wmem_file_scope(), &(transport->addr1), cinfo->addr1);
    copy_address_wmem(wmem_file_scope(), &(transport->addr2), cinfo->addr2);
    transport->session_id = session_id;
    transport->port1 = cinfo->port1;
    transport->port2 = cinfo->port2;
    wmem_map_insert(session_map, (const void *) &(transport->session_id), (void *) transport);
    return (transport);
}

static aeron_stream_t * aeron_transport_stream_find(aeron_transport_t * transport, guint32 stream_id)
{
    aeron_stream_t * stream;

    stream = (aeron_stream_t *) wmem_map_lookup(transport->stream, (const void *) &stream_id);
    return (stream);
}

static aeron_stream_t * aeron_transport_stream_add(aeron_transport_t * transport, guint32 stream_id)
{
    aeron_stream_t * stream;

    stream = aeron_transport_stream_find(transport, stream_id);
    if (stream == NULL)
    {
        stream = wmem_new0(wmem_file_scope(), aeron_stream_t);
        stream->transport = transport;
        stream->term = wmem_map_new(wmem_file_scope(), aeron_guint32_hash_func, aeron_guint32_compare_func);
        stream->rcv = wmem_list_new(wmem_file_scope());
        stream->rcv_count = 0;
        stream->last_frame = NULL;
        stream->stream_id = stream_id;
        stream->term_length = 0;
        stream->mtu = 0;
        stream->flags = 0;
        stream->high.term_id = 0;
        stream->high.term_offset = 0;
        wmem_map_insert(transport->stream, (const void *) &(stream->stream_id), (void *) stream);
    }
    return (stream);
}

static void aeron_transport_frame_add(aeron_transport_t * transport, aeron_frame_info_t * finfo, guint32 flags)
{
    if (flags != 0)
    {
        finfo->flags = flags;
    }
    if (transport->last_frame != NULL)
    {
        finfo->transport.previous = transport->last_frame->frame;
        transport->last_frame->transport.next = finfo->frame;
    }
    finfo->transport.next = 0;
    transport->last_frame = finfo;
}

/*----------------------------------------------------------------------------*/
/* Aeron stream management.                                                   */
/*----------------------------------------------------------------------------*/
static aeron_term_t * aeron_stream_term_find(aeron_stream_t * stream, guint32 term_id)
{
    aeron_term_t * term;

    term = (aeron_term_t *) wmem_map_lookup(stream->term, (const void *) &term_id);
    return (term);
}

static aeron_term_t * aeron_stream_term_add(aeron_stream_t * stream, guint32 term_id)
{
    aeron_term_t * term;

    term = aeron_stream_term_find(stream, term_id);
    if (term == NULL)
    {
        term = wmem_new0(wmem_file_scope(), aeron_term_t);
        term->stream = stream;
        term->fragment = wmem_map_new(wmem_file_scope(), aeron_guint32_hash_func, aeron_guint32_compare_func);
        term->message = wmem_tree_new(wmem_file_scope());
        term->orphan_fragment = wmem_list_new(wmem_file_scope());
        term->nak = wmem_list_new(wmem_file_scope());
        term->term_id = term_id;
        wmem_map_insert(stream->term, (const void *) &(term->term_id), (void *) term);
    }
    return (term);
}

static aeron_stream_rcv_t * aeron_stream_rcv_find(aeron_stream_t * stream, const address * addr, guint16 port)
{
    wmem_list_frame_t * lf = wmem_list_head(stream->rcv);
    aeron_stream_rcv_t * rcv = NULL;

    while (lf != NULL)
    {
        aeron_stream_rcv_t * cur = (aeron_stream_rcv_t *) wmem_list_frame_data(lf);
        if (cur != NULL)
        {
            if ((cmp_address(&(cur->addr), addr) == 0) && (cur->port == port))
            {
                rcv = cur;
                break;
            }
        }
        lf = wmem_list_frame_next(lf);
    }
    return (rcv);
}

static aeron_stream_rcv_t * aeron_stream_rcv_add(aeron_stream_t * stream, const address * addr, guint16 port)
{
    aeron_stream_rcv_t * rcv;

    rcv = aeron_stream_rcv_find(stream, addr, port);
    if (rcv != NULL)
    {
        return (rcv);
    }
    rcv = wmem_new0(wmem_file_scope(), aeron_stream_rcv_t);
    copy_address_wmem(wmem_file_scope(), &(rcv->addr), addr);
    rcv->port = port;
    rcv->completed.term_id = 0;
    rcv->completed.term_offset = 0;
    rcv->receiver_window = 0;
    wmem_list_append(stream->rcv, (void *) rcv);
    stream->rcv_count++;
    return (rcv);
}

static void aeron_stream_frame_add(aeron_stream_t * stream, aeron_frame_info_t * finfo, guint32 flags)
{
    if (flags != 0)
    {
        finfo->flags = flags;
    }
    if (stream->last_frame != NULL)
    {
        finfo->stream.previous = stream->last_frame->frame;
        stream->last_frame->stream.next = finfo->frame;
    }
    finfo->stream.next = 0;
    stream->last_frame = finfo;
    aeron_transport_frame_add(stream->transport, finfo, 0);
}

/*----------------------------------------------------------------------------*/
/* Aeron term management.                                                     */
/*----------------------------------------------------------------------------*/
static aeron_fragment_t * aeron_term_fragment_find(aeron_term_t * term, guint32 term_offset)
{
    aeron_fragment_t * fragment;

    fragment = (aeron_fragment_t *) wmem_map_lookup(term->fragment, (const void *) &term_offset);
    return (fragment);
}

static aeron_fragment_t * aeron_term_fragment_add(aeron_term_t * term, guint32 term_offset, guint32 length, guint32 data_length)
{
    aeron_fragment_t * fragment;

    fragment = aeron_term_fragment_find(term, term_offset);
    if (fragment == NULL)
    {
        fragment = wmem_new0(wmem_file_scope(), aeron_fragment_t);
        fragment->term = term;
        fragment->frame = wmem_list_new(wmem_file_scope());
        fragment->first_frame = NULL;
        fragment->last_frame = NULL;
        fragment->first_data_frame = NULL;
        fragment->term_offset = term_offset;
        fragment->length = length;
        fragment->data_length = data_length;
        fragment->frame_count = 0;
        wmem_map_insert(term->fragment, (const void *) &(fragment->term_offset), (void *) fragment);
    }
    return (fragment);
}

static void aeron_term_frame_add(aeron_term_t * term, aeron_frame_info_t * finfo, guint32 flags)
{
    if (flags != 0)
    {
        finfo->flags = flags;
    }
    if (term->last_frame != NULL)
    {
        finfo->term.previous = term->last_frame->frame;
        term->last_frame->term.next = finfo->frame;
    }
    finfo->term.next = 0;
    term->last_frame = finfo;
    aeron_stream_frame_add(term->stream, finfo, 0);
}

/*----------------------------------------------------------------------------*/
/* Aeron fragment management.                                                 */
/*----------------------------------------------------------------------------*/
static void aeron_fragment_frame_add(aeron_fragment_t * fragment, aeron_frame_info_t * finfo, guint32 flags, guint32 length)
{
    if (flags != 0)
    {
        finfo->flags = flags;
    }
    wmem_list_append(fragment->frame, (void *) finfo);
    fragment->frame_count++;
    if (fragment->last_frame != NULL)
    {
        finfo->fragment.previous = fragment->last_frame->frame;
        fragment->last_frame->fragment.next = finfo->frame;
    }
    if (fragment->first_frame == NULL)
    {
        fragment->first_frame = finfo;
    }
    if (length != 0)
    {
        if (fragment->first_data_frame == NULL)
        {
            fragment->first_data_frame = finfo;
        }
    }
    finfo->fragment.next = 0;
    fragment->last_frame = finfo;
    aeron_term_frame_add(fragment->term, finfo, 0);
}

/*----------------------------------------------------------------------------*/
/* Utility functions.                                                         */
/*----------------------------------------------------------------------------*/
static gboolean aeron_is_address_multicast(const address * addr)
{
    const guint8 * addr_data = (const guint8 *) addr->data;

    switch (addr->type)
    {
        case AT_IPv4:
            if ((addr_data[0] & 0xf0) == 0xe0)
            {
                return (TRUE);
            }
            break;
        case AT_IPv6:
            if (addr_data[0] == 0xff)
            {
                return (TRUE);
            }
            break;
        default:
            break;
    }
    return (FALSE);
}

static char * aeron_format_transport_uri(const aeron_conversation_info_t * cinfo)
{
    wmem_strbuf_t * uri;

    uri = wmem_strbuf_new(wmem_packet_scope(), "aeron:");
    switch (cinfo->ptype)
    {
        case PT_UDP:
            wmem_strbuf_append(uri, "udp");
            break;
        default:
            wmem_strbuf_append(uri, "unknown");
            break;
    }
    wmem_strbuf_append_c(uri, '?');
    if (aeron_is_address_multicast(cinfo->addr2))
    {
        switch (cinfo->addr2->type)
        {
            case AT_IPv6:
                wmem_strbuf_append_printf(uri, "group=[%s]:%" G_GUINT16_FORMAT, address_to_str(wmem_packet_scope(), cinfo->addr2), cinfo->port2);
                break;
            case AT_IPv4:
            default:
                wmem_strbuf_append_printf(uri, "group=%s:%" G_GUINT16_FORMAT, address_to_str(wmem_packet_scope(), cinfo->addr2), cinfo->port2);
                break;
        }
    }
    else
    {
        switch (cinfo->addr2->type)
        {
            case AT_IPv6:
                wmem_strbuf_append_printf(uri, "remote=[%s]:%" G_GUINT16_FORMAT, address_to_str(wmem_packet_scope(), cinfo->addr2), cinfo->port2);
                break;
            case AT_IPv4:
            default:
                wmem_strbuf_append_printf(uri, "remote=%s:%" G_GUINT16_FORMAT, address_to_str(wmem_packet_scope(), cinfo->addr2), cinfo->port2);
                break;
        }
    }
    return (wmem_strbuf_finalize(uri));
}

/*----------------------------------------------------------------------------*/
/* Packet definitions.                                                        */
/*----------------------------------------------------------------------------*/

/* Basic frame offsets */
#define O_AERON_BASIC_FRAME_LENGTH 0
#define O_AERON_BASIC_VERSION 4
#define O_AERON_BASIC_FLAGS 5
#define O_AERON_BASIC_TYPE 6

#define HDR_LENGTH_MIN 12

/* Padding frame */
#define O_AERON_PAD_FRAME_LENGTH 0
#define O_AERON_PAD_VERSION 4
#define O_AERON_PAD_FLAGS 5
#define O_AERON_PAD_TYPE 6
#define O_AERON_PAD_TERM_OFFSET 8
#define O_AERON_PAD_SESSION_ID 12
#define O_AERON_PAD_STREAM_ID 16
#define O_AERON_PAD_TERM_ID 20
#define L_AERON_PAD_MIN 24

/* Data frame */
#define O_AERON_DATA_FRAME_LENGTH 0
#define O_AERON_DATA_VERSION 4
#define O_AERON_DATA_FLAGS 5
#define O_AERON_DATA_TYPE 6
#define O_AERON_DATA_TERM_OFFSET 8
#define O_AERON_DATA_SESSION_ID 12
#define O_AERON_DATA_STREAM_ID 16
#define O_AERON_DATA_TERM_ID 20
#define O_AERON_DATA_DATA 24
#define L_AERON_DATA_MIN 24

/* NAK frame */
#define O_AERON_NAK_FRAME_LENGTH 0
#define O_AERON_NAK_VERSION 4
#define O_AERON_NAK_FLAGS 5
#define O_AERON_NAK_TYPE 6
#define O_AERON_NAK_SESSION_ID 8
#define O_AERON_NAK_STREAM_ID 12
#define O_AERON_NAK_TERM_ID 16
#define O_AERON_NAK_TERM_OFFSET 20
#define O_AERON_NAK_LENGTH 24
#define L_AERON_NAK 28

/* Status message */
#define O_AERON_SM_FRAME_LENGTH 0
#define O_AERON_SM_VERSION 4
#define O_AERON_SM_FLAGS 5
#define O_AERON_SM_TYPE 6
#define O_AERON_SM_SESSION_ID 8
#define O_AERON_SM_STREAM_ID 12
#define O_AERON_SM_TERM_ID 16
#define O_AERON_SM_COMPLETED_TERM_OFFSET 20
#define O_AERON_SM_RECEIVER_WINDOW 24
#define O_AERON_SM_FEEDBACK 28
#define L_AERON_SM_MIN 28

/* Error header */
#define O_AERON_ERR_FRAME_LENGTH 0
#define O_AERON_ERR_VERSION 4
#define O_AERON_ERR_CODE 5
#define O_AERON_ERR_TYPE 6
#define O_AERON_ERR_OFFENDING_FRAME_LENGTH 8
#define O_AERON_ERR_OFFENDING_HEADER 12
#define O_AERON_ERR_TERM_ID 16
#define O_AERON_ERR_COMPLETED_TERM_OFFSET 20
#define O_AERON_ERR_RECEIVER_WINDOW 24
#define O_AERON_ERR_FEEDBACK 28
#define L_AERON_ERR_MIN 12

/* Setup frame */
#define O_AERON_SETUP_FRAME_LENGTH 0
#define O_AERON_SETUP_VERSION 4
#define O_AERON_SETUP_FLAGS 5
#define O_AERON_SETUP_TYPE 6
#define O_AERON_SETUP_TERM_OFFSET 8
#define O_AERON_SETUP_SESSION_ID 12
#define O_AERON_SETUP_STREAM_ID 16
#define O_AERON_SETUP_INITIAL_TERM_ID 20
#define O_AERON_SETUP_ACTIVE_TERM_ID 24
#define O_AERON_SETUP_TERM_LENGTH 28
#define O_AERON_SETUP_MTU 32
#define L_AERON_SETUP 36

#define HDR_TYPE_PAD 0x0000
#define HDR_TYPE_DATA 0x0001
#define HDR_TYPE_NAK 0x0002
#define HDR_TYPE_SM 0x0003
#define HDR_TYPE_ERR 0x0004
#define HDR_TYPE_SETUP 0x0005
#define HDR_TYPE_EXT 0xFFFF

#define DATA_FLAGS_BEGIN 0x80
#define DATA_FLAGS_END 0x40
#define DATA_FLAGS_COMPLETE (DATA_FLAGS_BEGIN | DATA_FLAGS_END)

#define STATUS_FLAGS_SETUP 0x80

/*----------------------------------------------------------------------------*/
/* Value translation tables.                                                  */
/*----------------------------------------------------------------------------*/

static const value_string aeron_frame_type[] =
{
    { HDR_TYPE_PAD,   "Pad" },
    { HDR_TYPE_DATA,  "Data" },
    { HDR_TYPE_NAK,   "NAK" },
    { HDR_TYPE_SM,    "Status" },
    { HDR_TYPE_ERR,   "Error" },
    { HDR_TYPE_SETUP, "Setup" },
    { HDR_TYPE_EXT,   "Extension" },
    { 0x0, NULL }
};

/*
    Aeron conversations:

    UDP unicast:
    - The URL specifies the subscriber address and UDP port, and the publisher "connects" to the single subscriber.
    - The publisher sends Pad, Data, and Setup frames to the subscriber address and port.
    - The subscriber sends NAK and SM frames to the publisher, using as the destination the address and port from
      which the Setup and Data frames were received
    - So the conversation is defined by [A(publisher),A(subscriber),P(publisher),P(subscriber),PT_UDP]

    UDP multicast:
    - The URL specifies the data multicast group and UDP port, and must be an odd-numbered address. The control multicast
      group is automatically set to be one greater than the data multicast group, and the same port is used.
    - The publisher sends Pad, Data, and Setup frames to the data multicast group and port.
    - The subscriber sends NAK and SM frames to the control multicast group and port.
    - So the conversation is defined by [ControlGroup,DataGroup,port,port,PT_UDP]

*/

static aeron_conversation_info_t * aeron_setup_conversation_info(const packet_info * pinfo, guint16 type)
{
    aeron_conversation_info_t * cinfo;
    int addr_len = pinfo->dst.len;

    cinfo = wmem_new0(wmem_packet_scope(), aeron_conversation_info_t);
    cinfo->ptype = pinfo->ptype;
    switch (pinfo->dst.type)
    {
        case AT_IPv4:
            {
                const guint8 * dst_addr = (const guint8 *) pinfo->dst.data;

                cinfo->addr1 = wmem_new0(wmem_packet_scope(), address);
                cinfo->addr2 = wmem_new0(wmem_packet_scope(), address);
                if (aeron_is_address_multicast(&(pinfo->dst)))
                {
                    guint8 * addr1;
                    guint8 * addr2;

                    addr1 = (guint8 *) wmem_memdup(wmem_packet_scope(), (const void *) dst_addr, (size_t) addr_len);
                    addr2 = (guint8 *) wmem_memdup(wmem_packet_scope(), (const void *) dst_addr, (size_t) addr_len);
                    if ((dst_addr[addr_len - 1] & 0x1) != 0)
                    {
                        /* Address is odd, so it's the data group (in addr2). Increment the last byte of addr1 for the control group. */
                        addr1[addr_len - 1]++;
                    }
                    else
                    {
                        /* Address is even, so it's the control group (in addr1). Decrement the last byte of addr2 for the data group. */
                        addr2[addr_len - 1]--;
                    }
                    set_address(cinfo->addr1, AT_IPv4, addr_len, (void *) addr1);
                    set_address(cinfo->addr2, AT_IPv4, addr_len, (void *) addr2);
                    cinfo->port1 = pinfo->destport;
                    cinfo->port2 = cinfo->port1;
                }
                else
                {
                    switch (type)
                    {
                        case HDR_TYPE_PAD:
                        case HDR_TYPE_DATA:
                        case HDR_TYPE_SETUP:
                            /* Destination is a receiver */
                            copy_address_wmem(wmem_packet_scope(), cinfo->addr1, &(pinfo->src));
                            cinfo->port1 = pinfo->srcport;
                            copy_address_wmem(wmem_packet_scope(), cinfo->addr2, &(pinfo->dst));
                            cinfo->port2 = pinfo->destport;
                            break;
                        case HDR_TYPE_NAK:
                        case HDR_TYPE_SM:
                            /* Destination is the source */
                            copy_address_wmem(wmem_packet_scope(), cinfo->addr1, &(pinfo->dst));
                            cinfo->port1 = pinfo->destport;
                            copy_address_wmem(wmem_packet_scope(), cinfo->addr2, &(pinfo->src));
                            cinfo->port2 = pinfo->srcport;
                            break;
                        default:
                            break;
                    }
                }
            }
            break;
        case AT_IPv6:
            {
                const guint8 * dst_addr = (const guint8 *) pinfo->dst.data;

                cinfo->addr1 = wmem_new0(wmem_packet_scope(), address);
                cinfo->addr2 = wmem_new0(wmem_packet_scope(), address);
                if (aeron_is_address_multicast(&(pinfo->dst)))
                {
                    guint8 * addr1;
                    guint8 * addr2;

                    addr1 = (guint8 *) wmem_memdup(wmem_packet_scope(), (const void *) dst_addr, (size_t) addr_len);
                    addr2 = (guint8 *) wmem_memdup(wmem_packet_scope(), (const void *) dst_addr, (size_t) addr_len);
                    if ((dst_addr[addr_len - 1] & 0x1) != 0)
                    {
                        /* Address is odd, so it's the data group (in addr2). Increment the last byte of addr1 for the control group. */
                        addr1[addr_len - 1]++;
                    }
                    else
                    {
                        /* Address is even, so it's the control group (in addr1). Decrement the last byte of addr2 for the data group. */
                        addr2[addr_len - 1]--;
                    }
                    set_address(cinfo->addr1, AT_IPv6, addr_len, (void *) addr1);
                    set_address(cinfo->addr2, AT_IPv6, addr_len, (void *) addr2);
                    cinfo->port1 = pinfo->destport;
                    cinfo->port2 = cinfo->port1;
                }
                else
                {
                    switch (type)
                    {
                        case HDR_TYPE_PAD:
                        case HDR_TYPE_DATA:
                        case HDR_TYPE_SETUP:
                            /* Destination is a receiver */
                            copy_address_wmem(wmem_packet_scope(), cinfo->addr1, &(pinfo->src));
                            cinfo->port1 = pinfo->srcport;
                            copy_address_wmem(wmem_packet_scope(), cinfo->addr2, &(pinfo->dst));
                            cinfo->port2 = pinfo->destport;
                            break;
                        case HDR_TYPE_NAK:
                        case HDR_TYPE_SM:
                            /* Destination is the source */
                            copy_address_wmem(wmem_packet_scope(), cinfo->addr1, &(pinfo->dst));
                            cinfo->port1 = pinfo->destport;
                            copy_address_wmem(wmem_packet_scope(), cinfo->addr2, &(pinfo->src));
                            cinfo->port2 = pinfo->srcport;
                            break;
                        default:
                            break;
                    }
                }
            }
            break;
        default:
            return (NULL);
    }
    return (cinfo);
}

/*----------------------------------------------------------------------------*/
/* Handles of all types.                                                      */
/*----------------------------------------------------------------------------*/

/* Dissector tree handles */
static gint ett_aeron = -1;
static gint ett_aeron_pad = -1;
static gint ett_aeron_data = -1;
static gint ett_aeron_data_flags = -1;
static gint ett_aeron_data_reassembly = -1;
static gint ett_aeron_nak = -1;
static gint ett_aeron_sm = -1;
static gint ett_aeron_sm_flags = -1;
static gint ett_aeron_err = -1;
static gint ett_aeron_setup = -1;
static gint ett_aeron_ext = -1;
static gint ett_aeron_sequence_analysis = -1;
static gint ett_aeron_sequence_analysis_retransmission_rx = -1;
static gint ett_aeron_sequence_analysis_nak_rx = -1;
static gint ett_aeron_sequence_analysis_term_offset = -1;
static gint ett_aeron_stream_analysis = -1;

/* Dissector field handles */
static int hf_aeron_channel_id = -1;
static int hf_aeron_pad = -1;
static int hf_aeron_pad_frame_length = -1;
static int hf_aeron_pad_version = -1;
static int hf_aeron_pad_flags = -1;
static int hf_aeron_pad_type = -1;
static int hf_aeron_pad_term_offset = -1;
static int hf_aeron_pad_session_id = -1;
static int hf_aeron_pad_stream_id = -1;
static int hf_aeron_pad_term_id = -1;
static int hf_aeron_data = -1;
static int hf_aeron_data_frame_length = -1;
static int hf_aeron_data_version = -1;
static int hf_aeron_data_flags = -1;
static int hf_aeron_data_flags_b = -1;
static int hf_aeron_data_flags_e = -1;
static int hf_aeron_data_type = -1;
static int hf_aeron_data_term_offset = -1;
static int hf_aeron_data_next_offset = -1;
static int hf_aeron_data_next_offset_term = -1;
static int hf_aeron_data_next_offset_first_frame = -1;
static int hf_aeron_data_session_id = -1;
static int hf_aeron_data_stream_id = -1;
static int hf_aeron_data_term_id = -1;
static int hf_aeron_data_reassembly = -1;
static int hf_aeron_data_reassembly_fragment = -1;
static int hf_aeron_nak = -1;
static int hf_aeron_nak_frame_length = -1;
static int hf_aeron_nak_version = -1;
static int hf_aeron_nak_flags = -1;
static int hf_aeron_nak_type = -1;
static int hf_aeron_nak_session_id = -1;
static int hf_aeron_nak_stream_id = -1;
static int hf_aeron_nak_term_id = -1;
static int hf_aeron_nak_term_offset = -1;
static int hf_aeron_nak_length = -1;
static int hf_aeron_sm = -1;
static int hf_aeron_sm_frame_length = -1;
static int hf_aeron_sm_version = -1;
static int hf_aeron_sm_flags = -1;
static int hf_aeron_sm_flags_s = -1;
static int hf_aeron_sm_type = -1;
static int hf_aeron_sm_session_id = -1;
static int hf_aeron_sm_stream_id = -1;
static int hf_aeron_sm_consumption_term_id = -1;
static int hf_aeron_sm_consumption_term_offset = -1;
static int hf_aeron_sm_receiver_window = -1;
static int hf_aeron_sm_feedback = -1;
static int hf_aeron_err = -1;
static int hf_aeron_err_frame_length = -1;
static int hf_aeron_err_version = -1;
static int hf_aeron_err_code = -1;
static int hf_aeron_err_type = -1;
static int hf_aeron_err_off_frame_length = -1;
static int hf_aeron_err_off_hdr = -1;
static int hf_aeron_err_string = -1;
static int hf_aeron_setup = -1;
static int hf_aeron_setup_frame_length = -1;
static int hf_aeron_setup_version = -1;
static int hf_aeron_setup_flags = -1;
static int hf_aeron_setup_type = -1;
static int hf_aeron_setup_term_offset = -1;
static int hf_aeron_setup_session_id = -1;
static int hf_aeron_setup_stream_id = -1;
static int hf_aeron_setup_initial_term_id = -1;
static int hf_aeron_setup_active_term_id = -1;
static int hf_aeron_setup_term_length = -1;
static int hf_aeron_setup_mtu = -1;
static int hf_aeron_sequence_analysis = -1;
static int hf_aeron_sequence_analysis_channel_prev_frame = -1;
static int hf_aeron_sequence_analysis_channel_next_frame = -1;
static int hf_aeron_sequence_analysis_stream_prev_frame = -1;
static int hf_aeron_sequence_analysis_stream_next_frame = -1;
static int hf_aeron_sequence_analysis_term_prev_frame = -1;
static int hf_aeron_sequence_analysis_term_next_frame = -1;
static int hf_aeron_sequence_analysis_term_offset = -1;
static int hf_aeron_sequence_analysis_term_offset_frame = -1;
static int hf_aeron_sequence_analysis_retransmission = -1;
static int hf_aeron_sequence_analysis_retransmission_rx = -1;
static int hf_aeron_sequence_analysis_retransmission_rx_frame = -1;
static int hf_aeron_sequence_analysis_keepalive = -1;
static int hf_aeron_sequence_analysis_nak_unrecovered = -1;
static int hf_aeron_sequence_analysis_nak_rx = -1;
static int hf_aeron_sequence_analysis_nak_rx_frame = -1;
static int hf_aeron_stream_analysis = -1;
static int hf_aeron_stream_analysis_high_term_id = -1;
static int hf_aeron_stream_analysis_high_term_offset = -1;
static int hf_aeron_stream_analysis_completed_term_id = -1;
static int hf_aeron_stream_analysis_completed_term_offset = -1;
static int hf_aeron_stream_analysis_outstanding_bytes = -1;

/* Expert info handles */
static expert_field ei_aeron_analysis_nak = EI_INIT;
static expert_field ei_aeron_analysis_window_full = EI_INIT;
static expert_field ei_aeron_analysis_idle_rx = EI_INIT;
static expert_field ei_aeron_analysis_pacing_rx = EI_INIT;
static expert_field ei_aeron_analysis_ooo = EI_INIT;
static expert_field ei_aeron_analysis_ooo_gap = EI_INIT;
static expert_field ei_aeron_analysis_keepalive = EI_INIT;
static expert_field ei_aeron_analysis_ooo_sm = EI_INIT;
static expert_field ei_aeron_analysis_keepalive_sm = EI_INIT;
static expert_field ei_aeron_analysis_window_resize = EI_INIT;
static expert_field ei_aeron_analysis_rx = EI_INIT;
static expert_field ei_aeron_analysis_term_id_change = EI_INIT;
static expert_field ei_aeron_analysis_invalid_pad_length = EI_INIT;
static expert_field ei_aeron_analysis_invalid_data_length = EI_INIT;
static expert_field ei_aeron_analysis_invalid_nak_length = EI_INIT;
static expert_field ei_aeron_analysis_invalid_sm_length = EI_INIT;
static expert_field ei_aeron_analysis_invalid_err_length = EI_INIT;
static expert_field ei_aeron_analysis_invalid_setup_length = EI_INIT;

/*----------------------------------------------------------------------------*/
/* Setup packet information                                                   */
/*----------------------------------------------------------------------------*/
typedef struct
{
    guint32 info_flags;
    guint32 stream_id;
    guint32 term_id;
    guint32 term_offset;
    guint32 length;
    guint32 data_length;
    guint32 receiver_window;
    guint32 nak_term_offset;
    guint32 nak_length;
    guint16 type;
    guint8 flags;
} aeron_packet_info_t;
#define AERON_PACKET_INFO_FLAGS_STREAM_ID_VALID   0x00000001
#define AERON_PACKET_INFO_FLAGS_TERM_ID_VALID     0x00000002
#define AERON_PACKET_INFO_FLAGS_TERM_OFFSET_VALID 0x00000004

static void aeron_frame_nak_rx_add(aeron_frame_info_t * nak_info, aeron_frame_info_t * rx_info, guint32 term_offset, guint32 length)
{
    if (nak_info->nak_analysis->unrecovered_length >= length)
    {
        wmem_list_frame_t * lf = wmem_list_head(nak_info->nak_analysis->rx);
        aeron_rx_info_t * rx = NULL;

        while (lf != NULL)
        {
            rx = (aeron_rx_info_t *) wmem_list_frame_data(lf);
            if (rx != NULL)
            {
                if ((rx->term_offset == term_offset) && (rx->length == length))
                {
                    /* Already have this RX */
                    return;
                }
            }
            lf = wmem_list_frame_next(lf);
        }
        /* This RX frame isn't in the list, so add it */
        rx = wmem_new0(wmem_file_scope(), aeron_rx_info_t);
        rx->frame_info = rx_info;
        rx->term_offset = term_offset;
        rx->length = length;
        wmem_list_append(nak_info->nak_analysis->rx, (void *) rx);
        nak_info->nak_analysis->unrecovered_length -= length;
        wmem_list_append(rx_info->rx, (void *) nak_info);
    }
}

static void aeron_frame_process_rx(aeron_packet_info_t * info, aeron_frame_info_t * finfo, aeron_term_t * term)
{
    wmem_list_frame_t * lf;

    lf = wmem_list_head(term->nak);
    while (lf != NULL)
    {
        aeron_nak_t * nak = (aeron_nak_t *) wmem_list_frame_data(lf);
        if (nak != NULL)
        {
            if (nak->frame_info->frame <= finfo->frame)
            {
                if ((nak->term_offset <= info->term_offset) && (nak->length >= info->length))
                {
                    /* This data frame falls entirely within the NAK range */
                    aeron_frame_nak_rx_add(nak->frame_info, finfo, info->term_offset, info->length);
                }
            }
        }
        lf = wmem_list_frame_next(lf);
    }
}

static void aeron_frame_nak_analysis_setup(aeron_packet_info_t * info, aeron_frame_info_t * finfo, aeron_term_t * term)
{
    aeron_nak_t * nak = wmem_new0(wmem_file_scope(), aeron_nak_t);
    nak->term = term;
    nak->frame_info = finfo;
    nak->term_offset = info->nak_term_offset;
    nak->length = info->nak_length;
    wmem_list_append(term->nak, (void *) nak);

    finfo->nak_analysis = wmem_new0(wmem_file_scope(), aeron_nak_analysis_t);
    finfo->nak_analysis->frame_info = finfo;
    finfo->nak_analysis->rx = wmem_list_new(wmem_file_scope());
    finfo->nak_analysis->nak_term_offset = info->nak_term_offset;
    finfo->nak_analysis->nak_length = info->nak_length;
    finfo->nak_analysis->unrecovered_length = info->nak_length;
}

/* return 0 for success and -1 for error */
static int aeron_frame_stream_analysis_setup(packet_info * pinfo, aeron_packet_info_t * info, aeron_frame_info_t * finfo, aeron_stream_t * stream, aeron_term_t * term, gboolean new_term)
{
    aeron_stream_rcv_t * rcv = NULL;
    /*  dp is the current data position (from this frame). */
    aeron_pos_t dp = { 0, 0 };
    /*
        pdp is the previous (high) data position (from the stream).
        pdpv is TRUE if pdp is valid (meaning we previously saw a data message).
    */
    aeron_pos_t pdp = stream->high;
    gboolean pdpv = ((stream->flags & AERON_STREAM_FLAGS_HIGH_VALID) != 0);
    /*  rp is the current receiver position (from this frame). */
    aeron_pos_t rp = { 0, 0 };
    /*
        prp is the previous (high) receiver completed position (from the stream receiver).
        prpv is TRUE if prp is valid (meaning we previously saw a status message).
    */
    aeron_pos_t prp = { 0, 0 };
    gboolean prpv = FALSE;
    guint32 cur_receiver_window = 0;
    /* Flags to be used when creating the fragment frame entry */
    guint32 frame_flags = 0;

    if (info->type == HDR_TYPE_SM)
    {
        /* Locate the receiver */
        rcv = aeron_stream_rcv_find(stream, &(pinfo->src), pinfo->srcport);
        if (rcv == NULL)
        {
            rcv = aeron_stream_rcv_add(stream, &(pinfo->src), pinfo->srcport);
        }
        else
        {
            prpv = TRUE;
            prp = rcv->completed;
            cur_receiver_window = rcv->receiver_window;
        }
    }
    switch (info->type)
    {
        case HDR_TYPE_DATA:
        case HDR_TYPE_PAD:
            dp.term_id = info->term_id;
            dp.term_offset = info->term_offset;
            if (!aeron_pos_add_length(&dp, info->length, stream->term_length))
                return -1;
            if (pdpv)
            {
                if (dp.term_id > stream->high.term_id)
                {
                    stream->high.term_id = dp.term_id;
                    stream->high.term_offset = dp.term_offset;
                }
                else if (dp.term_offset > stream->high.term_offset)
                {
                    stream->high.term_offset = dp.term_offset;
                }
            }
            else
            {
                stream->flags |= AERON_STREAM_FLAGS_HIGH_VALID;
                stream->high.term_id = dp.term_id;
                stream->high.term_offset = dp.term_offset;
            }
            break;
        case HDR_TYPE_SM:
            rp.term_id = info->term_id;
            rp.term_offset = info->term_offset;
            if (prpv)
            {
                if (rp.term_id > rcv->completed.term_id)
                {
                    rcv->completed.term_id = rp.term_id;
                    rcv->completed.term_offset = rp.term_offset;
                }
                else if (rp.term_offset > rcv->completed.term_offset)
                {
                    rcv->completed.term_offset = rp.term_offset;
                }
            }
            else
            {
                rcv->completed.term_id = rp.term_id;
                rcv->completed.term_offset = rp.term_offset;
            }
            rcv->receiver_window = info->receiver_window;
            break;
        default:
            break;
    }
    if (aeron_stream_analysis)
    {
        if ((stream->flags & AERON_STREAM_FLAGS_HIGH_VALID) != 0)
        {
            finfo->stream_analysis = wmem_new0(wmem_file_scope(), aeron_stream_analysis_t);
        }
    }
    if (finfo->stream_analysis != NULL)
    {
        switch (info->type)
        {
            case HDR_TYPE_DATA:
            case HDR_TYPE_SM:
            case HDR_TYPE_PAD:
                finfo->stream_analysis->high.term_id = stream->high.term_id;
                finfo->stream_analysis->high.term_offset = stream->high.term_offset;
                if (rcv != NULL)
                {
                    finfo->stream_analysis->flags2 |= AERON_STREAM_ANALYSIS_FLAGS2_RCV_VALID;
                    finfo->stream_analysis->completed.term_id = rcv->completed.term_id;
                    finfo->stream_analysis->completed.term_offset = rcv->completed.term_offset;
                    finfo->stream_analysis->receiver_window = rcv->receiver_window;
                    finfo->stream_analysis->outstanding_bytes = aeron_pos_delta(&(finfo->stream_analysis->high), &(finfo->stream_analysis->completed), stream->term_length);
                    if (finfo->stream_analysis->outstanding_bytes >= finfo->stream_analysis->receiver_window)
                    {
                        finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_WINDOW_FULL;
                    }
                }
                else
                {
                    finfo->stream_analysis->completed.term_id = 0;
                    finfo->stream_analysis->completed.term_offset = 0;
                    finfo->stream_analysis->receiver_window = 0;
                    finfo->stream_analysis->outstanding_bytes = 0;
                }
                break;
            default:
                break;
        }
        switch (info->type)
        {
            case HDR_TYPE_DATA:
            case HDR_TYPE_PAD:
                if (pdpv)
                {
                    /* We have a previous data position. */
                    int rc = aeron_pos_compare(&dp, &pdp);
                    if (rc == 0)
                    {
                        /* Data position is the same as previous data position. */
                        if (info->length == 0)
                        {
                            finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_KEEPALIVE;
                            frame_flags |= AERON_FRAME_INFO_FLAGS_KEEPALIVE;
                        }
                        else
                        {
                            if (prpv)
                            {
                                /* Previous receiver position is valid */
                                if (aeron_pos_compare(&dp, &prp) == 0)
                                {
                                    finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_IDLE_RX;
                                }
                                else
                                {
                                    finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_PACING_RX;
                                }
                            }
                            else
                            {
                                finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_IDLE_RX;
                            }
                            frame_flags |= AERON_FRAME_INFO_FLAGS_RETRANSMISSION;
                        }
                    }
                    else
                    {
                        aeron_pos_t expected_dp;
                        int erc;

                        expected_dp.term_id = pdp.term_id;
                        expected_dp.term_offset = pdp.term_offset;
                        if (!aeron_pos_add_length(&expected_dp, info->length, stream->term_length))
                            return -1;
                        erc = aeron_pos_compare(&expected_dp, &dp);
                        if (erc > 0)
                        {
                            /* Could be OOO - but for now assume it's a RX */
                            finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_RX;
                            frame_flags |= AERON_FRAME_INFO_FLAGS_RETRANSMISSION;
                            aeron_frame_process_rx(info, finfo, term);
                        }
                        else if (erc < 0)
                        {
                            finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_OOO_GAP;
                        }
                    }
                }
                if (new_term && (info->term_offset == 0))
                {
                    finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_TERM_ID_CHANGE;
                }
                break;
            case HDR_TYPE_SM:
                if (prpv)
                {
                    int rc = aeron_pos_compare(&rp, &prp);
                    if (rc == 0)
                    {
                        /* Completed term ID and term offset stayed the same. */
                       finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_KEEPALIVE_SM;
                    }
                    else if (rc < 0)
                    {
                        finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_OOO_SM;
                    }
                    if (cur_receiver_window != finfo->stream_analysis->receiver_window)
                    {
                        finfo->stream_analysis->flags |= AERON_STREAM_ANALYSIS_FLAGS_WINDOW_RESIZE;
                    }
                }
                break;
            default:
                break;
        }
    }
    if ((info->type == HDR_TYPE_DATA) || (info->type == HDR_TYPE_PAD))
    {
        aeron_fragment_t * fragment;

        fragment = aeron_term_fragment_find(term, info->term_offset);
        if (fragment == NULL)
        {
            fragment = aeron_term_fragment_add(term, info->term_offset, info->length, info->data_length);
        }
        aeron_fragment_frame_add(fragment, finfo, frame_flags, info->length);
    }
    else
    {
        aeron_term_frame_add(term, finfo, frame_flags);
    }

    return 0;
}

/* return 0 for success and -1 for error */
static int aeron_frame_info_setup(packet_info * pinfo, aeron_transport_t * transport, aeron_packet_info_t * info, aeron_frame_info_t * finfo)
{
    if (!transport || !aeron_sequence_analysis || !finfo || PINFO_FD_VISITED(pinfo))
        /* XXX - is it an error if transport, aeron_sequence_analysis or finfo are NULL? */
        return 0;

    if ((info->info_flags & AERON_PACKET_INFO_FLAGS_STREAM_ID_VALID) != 0)
    {
        aeron_stream_t * stream;

        stream = aeron_transport_stream_find(transport, info->stream_id);
        if (stream == NULL)
        {
            stream = aeron_transport_stream_add(transport, info->stream_id);
        }
        if ((info->info_flags & AERON_PACKET_INFO_FLAGS_TERM_ID_VALID) != 0)
        {
            aeron_term_t * term;
            gboolean new_term = FALSE;

            term = aeron_stream_term_find(stream, info->term_id);
            if (term == NULL)
            {
                term = aeron_stream_term_add(stream, info->term_id);
                new_term = TRUE;
            }
            if ((info->info_flags & AERON_PACKET_INFO_FLAGS_TERM_OFFSET_VALID) != 0)
            {
                if (aeron_frame_stream_analysis_setup(pinfo, info, finfo, stream, term, new_term) < 0)
                    return -1;
            }
            else
            {
                aeron_term_frame_add(term, finfo, 0);
                if (info->type == HDR_TYPE_NAK)
                {
                    aeron_frame_nak_analysis_setup(info, finfo, term);
                }
            }
        }
        else
        {
            aeron_stream_frame_add(stream, finfo, 0);
        }
    }
    else
    {
        aeron_transport_frame_add(transport, finfo, 0);
    }

    return 0;
}

static void aeron_sequence_report_frame(tvbuff_t * tvb, proto_tree * tree, aeron_frame_info_t * finfo)
{
    proto_item * item = NULL;

    if ((finfo->flags & AERON_FRAME_INFO_FLAGS_RETRANSMISSION) != 0)
    {
        item = proto_tree_add_uint_format_value(tree, hf_aeron_sequence_analysis_term_offset_frame, tvb, 0, 0, finfo->frame, "%" G_GUINT32_FORMAT " (RX)", finfo->frame);
    }
    else if ((finfo->flags & AERON_FRAME_INFO_FLAGS_KEEPALIVE) != 0)
    {
        item = proto_tree_add_uint_format_value(tree, hf_aeron_sequence_analysis_term_offset_frame, tvb, 0, 0, finfo->frame, "%" G_GUINT32_FORMAT " (KA)", finfo->frame);
    }
    else
    {
        item = proto_tree_add_uint(tree, hf_aeron_sequence_analysis_term_offset_frame, tvb, 0, 0, finfo->frame);
    }
    PROTO_ITEM_SET_GENERATED(item);
}

static void aeron_sequence_report(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, aeron_transport_t * transport, aeron_packet_info_t * info, aeron_frame_info_t * finfo)
{
    if (transport != NULL)
    {
        if (aeron_sequence_analysis && (finfo != NULL))
        {
            proto_tree * subtree;
            proto_item * item;

            item = proto_tree_add_item(tree, hf_aeron_sequence_analysis, tvb, 0, 0, ENC_NA);
            PROTO_ITEM_SET_GENERATED(item);
            subtree = proto_item_add_subtree(item, ett_aeron_sequence_analysis);
            if (finfo->transport.previous != 0)
            {
                item = proto_tree_add_uint(subtree, hf_aeron_sequence_analysis_channel_prev_frame, tvb, 0, 0, finfo->transport.previous);
                PROTO_ITEM_SET_GENERATED(item);
            }
            if (finfo->transport.next != 0)
            {
                item = proto_tree_add_uint(subtree, hf_aeron_sequence_analysis_channel_next_frame, tvb, 0, 0, finfo->transport.next);
                PROTO_ITEM_SET_GENERATED(item);
            }
            if ((info->info_flags & AERON_PACKET_INFO_FLAGS_STREAM_ID_VALID) != 0)
            {
                aeron_stream_t * stream;

                stream = aeron_transport_stream_find(transport, info->stream_id);
                if (stream != NULL)
                {
                    if (finfo->stream.previous != 0)
                    {
                        item = proto_tree_add_uint(subtree, hf_aeron_sequence_analysis_stream_prev_frame, tvb, 0, 0, finfo->stream.previous);
                        PROTO_ITEM_SET_GENERATED(item);
                    }
                    if (finfo->stream.next != 0)
                    {
                        item = proto_tree_add_uint(subtree, hf_aeron_sequence_analysis_stream_next_frame, tvb, 0, 0, finfo->stream.next);
                        PROTO_ITEM_SET_GENERATED(item);
                    }
                    if ((info->info_flags & AERON_PACKET_INFO_FLAGS_TERM_ID_VALID) != 0)
                    {
                        aeron_term_t * term;

                        term = aeron_stream_term_find(stream, info->term_id);
                        if (term != NULL)
                        {
                            if (finfo->term.previous != 0)
                            {
                                item = proto_tree_add_uint(subtree, hf_aeron_sequence_analysis_term_prev_frame, tvb, 0, 0, finfo->term.previous);
                                PROTO_ITEM_SET_GENERATED(item);
                            }
                            if (finfo->term.next != 0)
                            {
                                item = proto_tree_add_uint(subtree, hf_aeron_sequence_analysis_term_next_frame, tvb, 0, 0, finfo->term.next);
                                PROTO_ITEM_SET_GENERATED(item);
                            }
                            if ((info->info_flags & AERON_PACKET_INFO_FLAGS_TERM_OFFSET_VALID) != 0)
                            {
                                if ((info->type == HDR_TYPE_DATA) || (info->type == HDR_TYPE_PAD))
                                {
                                    aeron_fragment_t * fragment;

                                    fragment = aeron_term_fragment_find(term, info->term_offset);
                                    if (fragment != NULL)
                                    {
                                        proto_item * fei_item;
                                        gboolean rx = ((finfo->flags & AERON_FRAME_INFO_FLAGS_RETRANSMISSION) != 0);
                                        gboolean ka = ((finfo->flags & AERON_FRAME_INFO_FLAGS_KEEPALIVE) != 0);

                                        if (fragment->frame_count > 1)
                                        {
                                            proto_tree * frame_tree;
                                            proto_item * frame_item;
                                            wmem_list_frame_t * lf;

                                            frame_item = proto_tree_add_item(subtree, hf_aeron_sequence_analysis_term_offset, tvb, 0, 0, ENC_NA);
                                            PROTO_ITEM_SET_GENERATED(frame_item);
                                            frame_tree = proto_item_add_subtree(frame_item, ett_aeron_sequence_analysis_term_offset);
                                            lf = wmem_list_head(fragment->frame);
                                            while (lf != NULL)
                                            {
                                                aeron_frame_info_t * frag_frame = (aeron_frame_info_t *) wmem_list_frame_data(lf);
                                                if (frag_frame != NULL)
                                                {
                                                    if (frag_frame->frame != pinfo->num)
                                                    {
                                                        aeron_sequence_report_frame(tvb, frame_tree, frag_frame);
                                                    }
                                                }
                                                lf = wmem_list_frame_next(lf);
                                            }
                                        }
                                        fei_item = proto_tree_add_boolean(subtree, hf_aeron_sequence_analysis_retransmission, tvb, 0, 0, rx);
                                        PROTO_ITEM_SET_GENERATED(fei_item);
                                        if (rx)
                                        {
                                            if (wmem_list_count(finfo->rx) > 0)
                                            {
                                                proto_tree * rx_tree;
                                                proto_item * rx_item;
                                                wmem_list_frame_t * lf;

                                                rx_item = proto_tree_add_item(subtree, hf_aeron_sequence_analysis_retransmission_rx, tvb, 0, 0, ENC_NA);
                                                PROTO_ITEM_SET_GENERATED(rx_item);
                                                rx_tree = proto_item_add_subtree(rx_item, ett_aeron_sequence_analysis_retransmission_rx);
                                                lf = wmem_list_head(finfo->rx);
                                                while (lf != NULL)
                                                {
                                                    aeron_frame_info_t * nak = (aeron_frame_info_t *) wmem_list_frame_data(lf);
                                                    if (nak != NULL)
                                                    {
                                                        rx_item = proto_tree_add_uint(rx_tree, hf_aeron_sequence_analysis_retransmission_rx_frame, tvb, 0, 0, nak->frame);
                                                        PROTO_ITEM_SET_GENERATED(rx_item);
                                                    }
                                                    lf = wmem_list_frame_next(lf);
                                                }
                                            }
                                        }
                                        fei_item = proto_tree_add_boolean(subtree, hf_aeron_sequence_analysis_keepalive, tvb, 0, 0, ka);
                                        PROTO_ITEM_SET_GENERATED(fei_item);
                                    }
                                }
                            }
                            else if ((info->type == HDR_TYPE_NAK) && (finfo->nak_analysis != NULL))
                            {
                                proto_item * nak_item;

                                nak_item = proto_tree_add_uint(subtree, hf_aeron_sequence_analysis_nak_unrecovered, tvb, 0, 0, finfo->nak_analysis->unrecovered_length);
                                PROTO_ITEM_SET_GENERATED(nak_item);
                                if (wmem_list_count(finfo->nak_analysis->rx) > 0)
                                {
                                    proto_tree * rx_tree;
                                    proto_item * rx_item;
                                    wmem_list_frame_t * lf;

                                    rx_item = proto_tree_add_item(subtree, hf_aeron_sequence_analysis_nak_rx, tvb, 0, 0, ENC_NA);
                                    PROTO_ITEM_SET_GENERATED(rx_item);
                                    rx_tree = proto_item_add_subtree(rx_item, ett_aeron_sequence_analysis_nak_rx);
                                    lf = wmem_list_head(finfo->nak_analysis->rx);
                                    while (lf != NULL)
                                    {
                                        aeron_rx_info_t * rx = (aeron_rx_info_t *) wmem_list_frame_data(lf);
                                        if (rx != NULL)
                                        {
                                            rx_item = proto_tree_add_uint_format_value(rx_tree, hf_aeron_sequence_analysis_nak_rx_frame, tvb, 0, 0, rx->frame_info->frame,
                                                "%" G_GUINT32_FORMAT ", Term offset=%" G_GUINT32_FORMAT " (0x%08x), Length=%" G_GUINT32_FORMAT, rx->frame_info->frame, rx->term_offset, rx->term_offset, rx->length);
                                            PROTO_ITEM_SET_GENERATED(rx_item);
                                        }
                                        lf = wmem_list_frame_next(lf);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

static void aeron_stream_report(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, aeron_transport_t * transport, aeron_frame_info_t * finfo)
{
    if (transport != NULL)
    {
        if (aeron_sequence_analysis && aeron_stream_analysis && (finfo != NULL) && (finfo->stream_analysis != NULL))
        {
            proto_tree * subtree;
            proto_item * item;

            item = proto_tree_add_item(tree, hf_aeron_stream_analysis, tvb, 0, 0, ENC_NA);
            PROTO_ITEM_SET_GENERATED(item);
            subtree = proto_item_add_subtree(item, ett_aeron_stream_analysis);
            item = proto_tree_add_uint(subtree, hf_aeron_stream_analysis_high_term_id, tvb, 0, 0, finfo->stream_analysis->high.term_id);
            if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_TERM_ID_CHANGE) != 0)
            {
                expert_add_info(pinfo, item, &ei_aeron_analysis_term_id_change);
            }
            PROTO_ITEM_SET_GENERATED(item);
            item = proto_tree_add_uint(subtree, hf_aeron_stream_analysis_high_term_offset, tvb, 0, 0, finfo->stream_analysis->high.term_offset);
            PROTO_ITEM_SET_GENERATED(item);
            if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_IDLE_RX) != 0)
            {
                expert_add_info(pinfo, item, &ei_aeron_analysis_idle_rx);
            }
            if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_PACING_RX) != 0)
            {
                expert_add_info(pinfo, item, &ei_aeron_analysis_pacing_rx);
            }
            if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_OOO) != 0)
            {
                expert_add_info(pinfo, item, &ei_aeron_analysis_ooo);
            }
            if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_OOO_GAP) != 0)
            {
                expert_add_info(pinfo, item, &ei_aeron_analysis_ooo_gap);
            }
            if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_KEEPALIVE) != 0)
            {
                expert_add_info(pinfo, item, &ei_aeron_analysis_keepalive);
            }
            if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_RX) != 0)
            {
                expert_add_info(pinfo, item, &ei_aeron_analysis_rx);
            }
            if ((finfo->stream_analysis->flags2 & AERON_STREAM_ANALYSIS_FLAGS2_RCV_VALID) != 0)
            {
                item = proto_tree_add_uint(subtree, hf_aeron_stream_analysis_completed_term_id, tvb, 0, 0, finfo->stream_analysis->completed.term_id);
                PROTO_ITEM_SET_GENERATED(item);
                item = proto_tree_add_uint(subtree, hf_aeron_stream_analysis_completed_term_offset, tvb, 0, 0, finfo->stream_analysis->completed.term_offset);
                PROTO_ITEM_SET_GENERATED(item);
                if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_OOO_SM) != 0)
                {
                    expert_add_info(pinfo, item, &ei_aeron_analysis_ooo_sm);
                }
                if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_KEEPALIVE_SM) != 0)
                {
                    expert_add_info(pinfo, item, &ei_aeron_analysis_keepalive_sm);
                }
                item = proto_tree_add_uint(subtree, hf_aeron_stream_analysis_outstanding_bytes, tvb, 0, 0, finfo->stream_analysis->outstanding_bytes);
                PROTO_ITEM_SET_GENERATED(item);
                if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_WINDOW_FULL) != 0)
                {
                    expert_add_info(pinfo, item, &ei_aeron_analysis_window_full);
                }
            }
        }
    }
}

static void aeron_next_offset_report(tvbuff_t * tvb, proto_tree * tree, aeron_transport_t * transport, guint32 stream_id, guint32 term_id, guint32 term_offset, guint32 length)
{
    aeron_stream_t * stream;

    stream = aeron_transport_stream_find(transport, stream_id);
    if (stream != NULL)
    {
        aeron_term_t * term;
        if (stream->term_length == 0)
        {
            stream->term_length = length;
        }
        term = aeron_stream_term_find(stream, term_id);
        if (term != NULL)
        {
            aeron_fragment_t * fragment = aeron_term_fragment_find(term, term_offset);
            if (fragment != NULL)
            {
                guint32 next_offset = term_offset + length;
                guint32 next_offset_term_id = term_id;
                guint32 next_offset_first_frame = 0;
                aeron_term_t * next_offset_term = NULL;
                proto_item * item;

                if (next_offset >= stream->term_length)
                {
                    next_offset = 0;
                    next_offset_term_id++;
                }
                item = proto_tree_add_uint(tree, hf_aeron_data_next_offset, tvb, 0, 0, next_offset);
                PROTO_ITEM_SET_GENERATED(item);
                if (next_offset_term_id != term_id)
                {
                    next_offset_term = aeron_stream_term_find(stream, next_offset_term_id);
                    item = proto_tree_add_uint(tree, hf_aeron_data_next_offset_term, tvb, 0, 0, next_offset_term_id);
                    PROTO_ITEM_SET_GENERATED(item);
                }
                else
                {
                    next_offset_term = term;
                }
                if (next_offset_term != NULL)
                {
                    aeron_fragment_t * next_offset_fragment;
                    next_offset_fragment = aeron_term_fragment_find(next_offset_term, next_offset);
                    if (next_offset_fragment != NULL)
                    {
                        if (next_offset_fragment->first_frame != NULL)
                        {
                            next_offset_first_frame = next_offset_fragment->first_frame->frame;
                            item = proto_tree_add_uint(tree, hf_aeron_data_next_offset_first_frame, tvb, 0, 0, next_offset_first_frame);
                            PROTO_ITEM_SET_GENERATED(item);
                        }
                    }
                }
            }
        }
    }
}

static void aeron_info_stream_progress_report(packet_info * pinfo, guint16 msgtype, guint8 flags, guint32 term_id, guint32 term_offset, aeron_frame_info_t * finfo)
{
    const gchar * type_string = val_to_str_const((guint32) msgtype, aeron_frame_type, "Unknown");

    if (aeron_sequence_analysis && aeron_stream_analysis && (finfo != NULL) && (finfo->stream_analysis != NULL))
    {
        switch (msgtype)
        {
            case HDR_TYPE_PAD:
            case HDR_TYPE_DATA:
                if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_KEEPALIVE) != 0)
                {
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s-KA", type_string);
                }
                else
                {
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s (0x%08x:%" G_GUINT32_FORMAT ")",
                        type_string, term_id, term_offset);
                }
                break;
            case HDR_TYPE_SM:
                if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_KEEPALIVE_SM) != 0)
                {
                    col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s-KA", type_string);
                }
                else
                {
                    if (finfo->stream_analysis->high.term_id == finfo->stream_analysis->completed.term_id)
                    {
                        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s (%" G_GUINT32_FORMAT "/%" G_GUINT32_FORMAT " [%" G_GUINT32_FORMAT "])",
                            type_string, finfo->stream_analysis->high.term_offset, finfo->stream_analysis->completed.term_offset, finfo->stream_analysis->outstanding_bytes);
                    }
                    else
                    {
                        col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s (0x%08x:%" G_GUINT32_FORMAT "/0x%08x:%" G_GUINT32_FORMAT " [%" G_GUINT32_FORMAT "])",
                            type_string, finfo->stream_analysis->high.term_id, finfo->stream_analysis->high.term_offset, finfo->stream_analysis->completed.term_id, finfo->stream_analysis->completed.term_offset, finfo->stream_analysis->outstanding_bytes);
                    }
                }
                break;
        }
    }
    else
    {
        if ((msgtype == HDR_TYPE_SM) && ((flags & STATUS_FLAGS_SETUP) != 0))
        {
            col_append_sep_fstr(pinfo->cinfo, COL_INFO, ", ", "%s-SETUP", type_string);
        }
        else
        {
            col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", type_string);
        }
    }
}

/*----------------------------------------------------------------------------*/
/* Payload reassembly.                                                        */
/*----------------------------------------------------------------------------*/
struct aeron_msg_fragment_t_stct;
typedef struct aeron_msg_fragment_t_stct aeron_msg_fragment_t;

struct aeron_msg_t_stct
{
    wmem_list_t * fragment;
    aeron_term_t * term;
    tvbuff_t * reassembled_data;
    guint32 first_fragment_term_offset;
    guint32 next_expected_term_offset;
    guint32 length;                 /* Total message payload length */
    guint32 frame_length;           /* Total length of all message frames accumulated */
    guint32 fragment_count;         /* Number of fragments in this message */
    guint32 contiguous_length;      /* Number of contiguous frame bytes accumulated for this message */
    guint32 begin_frame;            /* Data frame in which the B flag was set */
    guint32 first_frame;            /* Lowest-numbered frame which is part of this message */
    guint32 end_frame;              /* Data frame in which the E flag was set */
    guint32 last_frame;             /* Highest-numbered frame which is part of this message */
    gboolean complete;
};

struct aeron_msg_fragment_t_stct
{
    gchar * data;
    guint32 term_offset;            /* Term offset for entire fragment */
    guint32 frame_length;           /* Length of entire frame/fragment */
    guint32 data_length;            /* Payload length */
    guint32 frame;                  /* Frame in which the fragment resides */
    gint frame_offset;              /* Offset into the frame for the entire Aeron message */
    guint8 flags;                   /* Frame data flags */
};

static void aeron_msg_fragment_add(aeron_msg_t * msg, aeron_msg_fragment_t * fragment)
{
    /* Add the fragment to the message */
    wmem_list_append(msg->fragment, (void *) fragment);
    /* Update the message */
    msg->length += fragment->data_length;
    msg->contiguous_length += fragment->data_length;
    msg->fragment_count++;
    if (msg->first_frame > fragment->frame)
    {
        msg->first_frame = fragment->frame;
    }
    if (msg->last_frame < fragment->frame)
    {
        msg->last_frame = fragment->frame;
    }
    msg->next_expected_term_offset += fragment->frame_length;
    if ((fragment->flags & DATA_FLAGS_END) == DATA_FLAGS_END)
    {
        gchar * buf;
        wmem_list_frame_t * lf;
        size_t ofs = 0;
        size_t accum_len = 0;
        guint32 last_frame_offset = 0;
        gboolean last_frame_found = FALSE;
        aeron_frame_info_t * finfo = NULL;

        msg->complete = TRUE;
        msg->end_frame = fragment->frame;
        buf = (gchar *) wmem_alloc(wmem_file_scope(), (size_t) msg->length);
        lf = wmem_list_head(msg->fragment);
        while (lf != NULL)
        {
            aeron_msg_fragment_t * cur_frag = (aeron_msg_fragment_t *) wmem_list_frame_data(lf);
            if (cur_frag != NULL)
            {
                if (cur_frag->frame == msg->last_frame)
                {
                    last_frame_offset = cur_frag->frame_offset;
                    last_frame_found = TRUE;
                }
                memcpy((void *) (buf + ofs), (void *) cur_frag->data, (size_t) cur_frag->data_length);
                ofs += (size_t) cur_frag->data_length;
                accum_len += (size_t) cur_frag->data_length;
            }
            lf = wmem_list_frame_next(lf);
        }
        DISSECTOR_ASSERT(accum_len == (size_t) msg->length);
        DISSECTOR_ASSERT(last_frame_found == TRUE);
        if (last_frame_found)
        {
            finfo = aeron_frame_info_find(msg->last_frame, last_frame_offset);
        }
        msg->reassembled_data = tvb_new_real_data(buf, msg->length, msg->length);
        DISSECTOR_ASSERT(finfo != NULL);
        if (finfo != NULL)
        {
            finfo->flags |= AERON_FRAME_INFO_FLAGS_REASSEMBLED_MSG;
            finfo->message = msg;
        }
    }
}

static gboolean aeron_msg_process_orphan_fragments_msg_cb(const void *key _U_, void * value, void * userdata)
{
    aeron_msg_t * msg = (aeron_msg_t *) value;
    aeron_term_t * term = (aeron_term_t *) userdata;
    gboolean frag_found = FALSE;
    wmem_list_frame_t * lf = NULL;
    aeron_msg_fragment_t * frag = NULL;

    if (msg->complete)
    {
        /* This message is complete, no need to check for orphans */
        return (FALSE);
    }
    /* Scan through the orphan fragments */
    while (TRUE)
    {
        lf = wmem_list_head(term->orphan_fragment);
        while (lf != NULL)
        {
            frag = (aeron_msg_fragment_t *) wmem_list_frame_data(lf);
            if (frag != NULL)
            {
                if (msg->next_expected_term_offset == frag->term_offset)
                {
                    /* Found one! Remove it from the orphan list, and add it to the message */
                    wmem_list_remove_frame(term->orphan_fragment, lf);
                    aeron_msg_fragment_add(msg, frag);
                    frag_found = TRUE;
                    break;
                }
            }
            lf = wmem_list_frame_next(lf);
        }
        if (!frag_found)
        {
            break;
        }
        frag_found = FALSE;
    }
    return (FALSE);
}

static void aeron_msg_process_orphan_fragments(aeron_term_t * term)
{
    /* If we have no orphan fragments to process, nothing to do. */
    if (wmem_list_count(term->orphan_fragment) == 0)
    {
        return;
    }
    wmem_tree_foreach(term->message, aeron_msg_process_orphan_fragments_msg_cb, (void *) term);
}

static aeron_msg_fragment_t * aeron_msg_fragment_create(tvbuff_t * tvb, int offset, packet_info * pinfo, aeron_packet_info_t * info)
{
    aeron_msg_fragment_t * frag;

    frag = wmem_new0(wmem_file_scope(), aeron_msg_fragment_t);
    frag->term_offset = info->term_offset;
    frag->frame_length = info->length;
    frag->data_length = info->data_length;
    frag->frame = pinfo->num;
    frag->frame_offset = offset;
    frag->data = (gchar *) tvb_memdup(wmem_file_scope(), tvb, frag->frame_offset + O_AERON_DATA_DATA, (size_t) frag->data_length);
    frag->flags = info->flags;
    return (frag);
}

static aeron_msg_fragment_t * aeron_msg_fragment_find(aeron_msg_t * message, aeron_packet_info_t * info)
{
    aeron_msg_fragment_t * frag = NULL;
    wmem_list_frame_t * lf;

    if (message->next_expected_term_offset < info->term_offset)
    {
        return (NULL);
    }
    lf = wmem_list_head(message->fragment);
    while (lf != NULL)
    {
        frag = (aeron_msg_fragment_t *) wmem_list_frame_data(lf);
        if (frag != NULL)
        {
            if (frag->term_offset == info->term_offset)
            {
                break;
            }
        }
        lf = wmem_list_frame_next(lf);
    }
    return (frag);
}

static aeron_msg_t * aeron_term_msg_find_le(aeron_term_t * term, guint32 term_offset)
{
    /* Return the last aeron_msg_t with starting_fragment_term_offset <= offset */
    aeron_msg_t * msg = (aeron_msg_t *) wmem_tree_lookup32_le(term->message, term_offset);
    return (msg);
}

static aeron_msg_t * aeron_term_msg_add(aeron_term_t * term, packet_info * pinfo, aeron_packet_info_t * info)
{
    aeron_msg_t * pos;
    aeron_msg_t * msg;

    pos = aeron_term_msg_find_le(term, info->term_offset);
    if ((pos != NULL) && (pos->first_fragment_term_offset == info->term_offset))
    {
        return (pos);
    }
    msg = wmem_new0(wmem_file_scope(), aeron_msg_t);
    msg->fragment = wmem_list_new(wmem_file_scope());
    msg->term = term;
    msg->reassembled_data = NULL;
    msg->first_fragment_term_offset = info->term_offset;
    msg->next_expected_term_offset = info->term_offset;
    msg->length = 0;
    msg->frame_length = 0;
    msg->fragment_count = 0;
    msg->contiguous_length = 0;
    msg->begin_frame = pinfo->num;
    msg->first_frame = pinfo->num;
    msg->end_frame = 0;
    msg->last_frame = 0;
    msg->complete = FALSE;
    wmem_tree_insert32(term->message, msg->first_fragment_term_offset, (void *) msg);
    return (msg);
}

static void aeron_msg_process(tvbuff_t * tvb, int offset, packet_info * pinfo, aeron_transport_t * transport, aeron_packet_info_t * info, aeron_frame_info_t * finfo _U_)
{
    if (aeron_reassemble_fragments && (PINFO_FD_VISITED(pinfo) == 0))
    {
        if ((info->flags & DATA_FLAGS_COMPLETE) != DATA_FLAGS_COMPLETE)
        {
            aeron_stream_t * stream = aeron_transport_stream_find(transport, info->stream_id);
            if (stream != NULL)
            {
                aeron_term_t * term = aeron_stream_term_find(stream, info->term_id);
                if (term != NULL)
                {
                    aeron_msg_t * msg = NULL;
                    aeron_msg_fragment_t * frag = NULL;

                    if ((info->flags & DATA_FLAGS_BEGIN) == DATA_FLAGS_BEGIN)
                    {
                        /* Beginning of a message. First see if this message already exists. */
                        msg = aeron_term_msg_find_le(term, info->term_offset);
                        if (msg != NULL)
                        {
                            if (msg->first_fragment_term_offset != info->term_offset)
                            {
                                /*
                                    A message start with a term offset:
                                        1) Between two existing messages for this term, or
                                        2) Less than the first message for this term
                                    Likely this was caused by an RX or out-of-order packet. Need to create a new one.
                                */
                                msg = NULL;
                            }
                        }
                        if (msg == NULL)
                        {
                            msg = aeron_term_msg_add(term, pinfo, info);
                        }
                    }
                    else
                    {
                        /* End of message, or middle of message. See if we already have a message with a smaller starting term offset */
                        msg = aeron_term_msg_find_le(term, info->term_offset);
                        if (msg != NULL)
                        {
                            /* Is this the next expexted term offset? */
                            if (msg->next_expected_term_offset == info->term_offset)
                            {
                                /* Yes - we can add the fragment to the message */
                            }
                            else
                            {
                                /* Do we already have this fragment? */
                                frag = aeron_msg_fragment_find(msg, info);
                                if (frag != NULL)
                                {
                                    /* Already have it, so nothing to do */
                                    return;
                                }
                                else
                                {
                                    /* Not the next fragment, so no known message associated with it. */
                                    msg = NULL;
                                }
                            }
                        }
                    }
                    /* Create the fragment */
                    frag = aeron_msg_fragment_create(tvb, offset, pinfo, info);
                    if (msg == NULL)
                    {
                        /* Add the fragment to the list of orphaned fragments */
                        wmem_list_append(term->orphan_fragment, (void *) frag);
                    }
                    else
                    {
                        /* Add the fragment to the message */
                        aeron_msg_fragment_add(msg, frag);
                    }
                    /* Process the orphan list */
                    aeron_msg_process_orphan_fragments(term);
                }
            }
        }
    }
}

/*----------------------------------------------------------------------------*/
/* Aeron pad message packet dissection functions.                             */
/*----------------------------------------------------------------------------*/
static int dissect_aeron_pad(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, aeron_conversation_info_t * cinfo, aeron_frame_info_t * finfo)
{
    proto_tree * subtree;
    proto_item * pad_item;
    proto_item * channel_item;
    proto_item * frame_length_item;
    guint32 frame_length;
    guint32 pad_length;
    aeron_transport_t * transport;
    guint32 session_id;
    guint32 stream_id;
    guint32 term_id;
    guint32 term_offset;
    int rounded_length;
    aeron_packet_info_t pktinfo;

    frame_length = tvb_get_letohl(tvb, offset + O_AERON_PAD_FRAME_LENGTH);
    rounded_length = (int) aeron_pos_roundup(frame_length);
    if (rounded_length < 0)
        return 0;
    term_offset = tvb_get_letohl(tvb, offset + O_AERON_PAD_TERM_OFFSET);
    session_id = tvb_get_letohl(tvb, offset + O_AERON_PAD_SESSION_ID);
    transport = aeron_transport_add(cinfo, session_id, pinfo->num);
    stream_id = tvb_get_letohl(tvb, offset + O_AERON_PAD_STREAM_ID);
    term_id = tvb_get_letohl(tvb, offset + O_AERON_PAD_TERM_ID);
    pad_length = frame_length - L_AERON_PAD_MIN;
    memset((void *) &pktinfo, 0, sizeof(aeron_packet_info_t));
    pktinfo.stream_id = stream_id;
    pktinfo.term_id = term_id;
    pktinfo.term_offset = term_offset;
    pktinfo.info_flags = AERON_PACKET_INFO_FLAGS_STREAM_ID_VALID | AERON_PACKET_INFO_FLAGS_TERM_ID_VALID | AERON_PACKET_INFO_FLAGS_TERM_OFFSET_VALID;
    pktinfo.length = frame_length;
    pktinfo.data_length = pad_length;
    pktinfo.type = HDR_TYPE_PAD;
    pktinfo.flags = tvb_get_guint8(tvb, offset + O_AERON_PAD_FLAGS);
    if (aeron_frame_info_setup(pinfo, transport, &pktinfo, finfo) < 0)
        return 0;

    aeron_info_stream_progress_report(pinfo, HDR_TYPE_PAD, pktinfo.flags, term_id, term_offset, finfo);
    pad_item = proto_tree_add_none_format(tree, hf_aeron_pad, tvb, offset, -1, "Pad Frame: Term 0x%x, Ofs %" G_GUINT32_FORMAT ", Len %" G_GUINT32_FORMAT "(%d)",
        term_id, term_offset, frame_length, rounded_length);
    subtree = proto_item_add_subtree(pad_item, ett_aeron_pad);
    channel_item = proto_tree_add_uint64(subtree, hf_aeron_channel_id, tvb, 0, 0, transport->channel_id);
    PROTO_ITEM_SET_GENERATED(channel_item);
    frame_length_item = proto_tree_add_item(subtree, hf_aeron_pad_frame_length, tvb, offset + O_AERON_PAD_FRAME_LENGTH, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_pad_version, tvb, offset + O_AERON_PAD_VERSION, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_pad_flags, tvb, offset + O_AERON_PAD_FLAGS, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_pad_type, tvb, offset + O_AERON_PAD_TYPE, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_pad_term_offset, tvb, offset + O_AERON_PAD_TERM_OFFSET, 4, ENC_LITTLE_ENDIAN);
    aeron_next_offset_report(tvb, subtree, transport, stream_id, term_id, term_offset, (guint32) rounded_length);
    proto_tree_add_item(subtree, hf_aeron_pad_session_id, tvb, offset + O_AERON_PAD_SESSION_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_pad_stream_id, tvb, offset + O_AERON_PAD_STREAM_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_pad_term_id, tvb, offset + O_AERON_PAD_TERM_ID, 4, ENC_LITTLE_ENDIAN);
    aeron_sequence_report(tvb, pinfo, subtree, transport, &pktinfo, finfo);
    aeron_stream_report(tvb, pinfo, subtree, transport, finfo);
    proto_item_set_len(pad_item, rounded_length);
    if (frame_length < L_AERON_PAD_MIN)
    {
        expert_add_info(pinfo, frame_length_item, &ei_aeron_analysis_invalid_pad_length);
        return (-rounded_length);
    }
    return (rounded_length);
}

/*----------------------------------------------------------------------------*/
/* Aeron data message packet dissection functions.                            */
/*----------------------------------------------------------------------------*/
static void dissect_aeron_reassembled_data(packet_info * pinfo, proto_tree * tree, aeron_frame_info_t * finfo)
{
    proto_item * frag_item;
    proto_tree * frag_tree;
    aeron_msg_t * msg;
    wmem_list_frame_t * lf;
    gboolean first_item = TRUE;
    guint32 msg_ofs = 0;

    if (finfo->message == NULL)
    {
        return;
    }
    msg = finfo->message;
    add_new_data_source(pinfo, msg->reassembled_data, "Reassembled Data");
    frag_item = proto_tree_add_none_format(tree,
        hf_aeron_data_reassembly,
        msg->reassembled_data,
        0,
        tvb_reported_length_remaining(msg->reassembled_data, 0),
        "%" G_GUINT32_FORMAT " Reassembled Fragments (%" G_GUINT32_FORMAT " bytes):",
        msg->fragment_count,
        msg->length);
    frag_tree = proto_item_add_subtree(frag_item, ett_aeron_data_reassembly);
    lf = wmem_list_head(msg->fragment);
    while (lf != NULL)
    {
        aeron_msg_fragment_t * frag = (aeron_msg_fragment_t *) wmem_list_frame_data(lf);
        if (frag != NULL)
        {
            proto_item * pi;
            pi = proto_tree_add_uint_format_value(frag_tree,
                hf_aeron_data_reassembly_fragment,
                msg->reassembled_data,
                msg_ofs,
                frag->data_length,
                frag->frame,
                "Frame: %" G_GUINT32_FORMAT ", payload: %" G_GUINT32_FORMAT "-%" G_GUINT32_FORMAT " (%" G_GUINT32_FORMAT " bytes)",
                frag->frame,
                msg_ofs,
                (msg_ofs + frag->data_length) - 1,
                frag->data_length);
            PROTO_ITEM_SET_GENERATED(pi);
            if (first_item)
            {
                proto_item_append_text(frag_item, " #%" G_GUINT32_FORMAT "(%" G_GUINT32_FORMAT ")", frag->frame, frag->data_length);
            }
            else
            {
                proto_item_append_text(frag_item, ", #%" G_GUINT32_FORMAT "(%" G_GUINT32_FORMAT ")", frag->frame, frag->data_length);
            }
            msg_ofs += frag->data_length;
            first_item = FALSE;
        }
        lf = wmem_list_frame_next(lf);
    }
    PROTO_ITEM_SET_GENERATED(frag_item);
}

static int dissect_aeron_data(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, aeron_conversation_info_t * cinfo, aeron_frame_info_t * finfo)
{
    proto_tree * subtree;
    proto_item * data_item;
    proto_item * channel_item;
    proto_item * frame_length_item;
    guint32 frame_length;
    static const int * flags[] =
    {
        &hf_aeron_data_flags_b,
        &hf_aeron_data_flags_e,
        NULL
    };
    aeron_transport_t * transport;
    guint32 session_id;
    guint32 stream_id;
    guint32 term_id;
    guint32 term_offset;
    guint32 data_length;
    int rounded_length = 0;
    aeron_packet_info_t pktinfo;
    guint32 offset_increment = 0;

    frame_length = tvb_get_letohl(tvb, offset + O_AERON_DATA_FRAME_LENGTH);
    if (frame_length == 0)
    {
        rounded_length = O_AERON_DATA_DATA;
        data_length = 0;
        offset_increment = 0;
    }
    else
    {
        offset_increment = aeron_pos_roundup(frame_length);
        rounded_length = (int) offset_increment;
        if (rounded_length < 0)
            return 0;
        data_length = frame_length - O_AERON_DATA_DATA;
    }
    term_offset = tvb_get_letohl(tvb, offset + O_AERON_DATA_TERM_OFFSET);
    session_id = tvb_get_letohl(tvb, offset + O_AERON_DATA_SESSION_ID);
    transport = aeron_transport_add(cinfo, session_id, pinfo->num);
    stream_id = tvb_get_letohl(tvb, offset + O_AERON_DATA_STREAM_ID);
    term_id = tvb_get_letohl(tvb, offset + O_AERON_DATA_TERM_ID);
    memset((void *) &pktinfo, 0, sizeof(aeron_packet_info_t));
    pktinfo.stream_id = stream_id;
    pktinfo.term_id = term_id;
    pktinfo.term_offset = term_offset;
    pktinfo.info_flags = AERON_PACKET_INFO_FLAGS_STREAM_ID_VALID | AERON_PACKET_INFO_FLAGS_TERM_ID_VALID | AERON_PACKET_INFO_FLAGS_TERM_OFFSET_VALID;
    pktinfo.length = frame_length;
    pktinfo.data_length = data_length;
    pktinfo.type = HDR_TYPE_DATA;
    pktinfo.flags = tvb_get_guint8(tvb, offset + O_AERON_DATA_FLAGS);
    if (aeron_frame_info_setup(pinfo, transport, &pktinfo, finfo) < 0)
        return 0;

    aeron_info_stream_progress_report(pinfo, HDR_TYPE_DATA, pktinfo.flags, term_id, term_offset, finfo);
    data_item = proto_tree_add_none_format(tree, hf_aeron_data, tvb, offset, -1, "Data Frame: Term 0x%x, Ofs %" G_GUINT32_FORMAT ", Len %" G_GUINT32_FORMAT "(%d)",
        (guint32) term_id, term_offset, frame_length, rounded_length);
    subtree = proto_item_add_subtree(data_item, ett_aeron_data);
    channel_item = proto_tree_add_uint64(subtree, hf_aeron_channel_id, tvb, 0, 0, transport->channel_id);
    PROTO_ITEM_SET_GENERATED(channel_item);
    frame_length_item = proto_tree_add_item(subtree, hf_aeron_data_frame_length, tvb, offset + O_AERON_DATA_FRAME_LENGTH, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_data_version, tvb, offset + O_AERON_DATA_VERSION, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(subtree, tvb, offset + O_AERON_DATA_FLAGS, hf_aeron_data_flags, ett_aeron_data_flags, flags, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_data_type, tvb, offset + O_AERON_DATA_TYPE, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_data_term_offset, tvb, offset + O_AERON_DATA_TERM_OFFSET, 4, ENC_LITTLE_ENDIAN);
    aeron_next_offset_report(tvb, subtree, transport, stream_id, term_id, term_offset, offset_increment);
    proto_tree_add_item(subtree, hf_aeron_data_session_id, tvb, offset + O_AERON_DATA_SESSION_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_data_stream_id, tvb, offset + O_AERON_DATA_STREAM_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_data_term_id, tvb, offset + O_AERON_DATA_TERM_ID, 4, ENC_LITTLE_ENDIAN);
    if (data_length > 0)
    {
        tvbuff_t * data_tvb = NULL;
        gboolean can_call_subdissector = FALSE;
        gboolean dissector_found = FALSE;
        heur_dtbl_entry_t * hdtbl_entry;

        aeron_msg_process(tvb, offset, pinfo, transport, &pktinfo, finfo);
        if ((pktinfo.flags & DATA_FLAGS_COMPLETE) == DATA_FLAGS_COMPLETE)
        {
            can_call_subdissector = TRUE;
        }
        if (finfo != NULL)
        {
            if ((finfo->flags & AERON_FRAME_INFO_FLAGS_REASSEMBLED_MSG) != 0)
            {
                dissect_aeron_reassembled_data(pinfo, subtree, finfo);
                data_tvb = finfo->message->reassembled_data;
                can_call_subdissector = TRUE;
            }
            else
            {
                data_tvb = tvb_new_subset_length(tvb, offset + O_AERON_DATA_DATA, data_length);
            }
        }
        else
        {
            data_tvb = tvb_new_subset_length(tvb, offset + O_AERON_DATA_DATA, data_length);
        }
        if (can_call_subdissector && aeron_use_heuristic_subdissectors)
        {
            dissector_found = dissector_try_heuristic(aeron_heuristic_subdissector_list, data_tvb, pinfo, subtree, &hdtbl_entry, NULL);
        }
        if (!dissector_found)
        {
            call_data_dissector(data_tvb, pinfo, subtree);
        }
    }
    aeron_sequence_report(tvb, pinfo, subtree, transport, &pktinfo, finfo);
    aeron_stream_report(tvb, pinfo, subtree, transport, finfo);
    proto_item_set_len(data_item, rounded_length);
    if ((frame_length != 0) && (frame_length < L_AERON_DATA_MIN))
    {
        expert_add_info(pinfo, frame_length_item, &ei_aeron_analysis_invalid_data_length);
        return (-rounded_length);
    }
    return (rounded_length);
}

/*----------------------------------------------------------------------------*/
/* Aeron NAK packet dissection functions.                                     */
/*----------------------------------------------------------------------------*/
static int dissect_aeron_nak(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, aeron_conversation_info_t * cinfo, aeron_frame_info_t * finfo)
{
    proto_tree * subtree;
    proto_item * nak_item;
    proto_item * frame_length_item;
    proto_item * channel_item;
    proto_item * nak_offset_item;
    guint32 frame_length;
    aeron_transport_t * transport;
    guint32 session_id;
    guint32 stream_id;
    guint32 term_id;
    guint32 nak_term_offset;
    guint32 nak_length;
    int rounded_length;
    aeron_packet_info_t pktinfo;

    frame_length = tvb_get_letohl(tvb, offset + O_AERON_NAK_FRAME_LENGTH);
    rounded_length = (int) aeron_pos_roundup(frame_length);
    if (rounded_length < 0)
        return 0;
    session_id = tvb_get_letohl(tvb, offset + O_AERON_NAK_SESSION_ID);
    transport = aeron_transport_add(cinfo, session_id, pinfo->num);
    stream_id = tvb_get_letohl(tvb, offset + O_AERON_NAK_STREAM_ID);
    term_id = tvb_get_letohl(tvb, offset + O_AERON_NAK_TERM_ID);
    nak_term_offset = tvb_get_letohl(tvb, offset + O_AERON_NAK_TERM_OFFSET);
    nak_length = tvb_get_letohl(tvb, offset + O_AERON_NAK_LENGTH);
    memset((void *) &pktinfo, 0, sizeof(aeron_packet_info_t));
    pktinfo.stream_id = stream_id;
    pktinfo.term_id = term_id;
    pktinfo.info_flags = AERON_PACKET_INFO_FLAGS_STREAM_ID_VALID | AERON_PACKET_INFO_FLAGS_TERM_ID_VALID;
    pktinfo.nak_term_offset = nak_term_offset;
    pktinfo.nak_length = nak_length;
    pktinfo.type = HDR_TYPE_NAK;
    pktinfo.flags = tvb_get_guint8(tvb, offset + O_AERON_NAK_FLAGS);
    if (aeron_frame_info_setup(pinfo, transport, &pktinfo, finfo) < 0)
        return 0;

    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "NAK");
    nak_item = proto_tree_add_none_format(tree, hf_aeron_nak, tvb, offset, -1, "NAK Frame: Term 0x%x, Ofs %" G_GUINT32_FORMAT ", Len %" G_GUINT32_FORMAT,
        term_id, nak_term_offset, nak_length);
    subtree = proto_item_add_subtree(nak_item, ett_aeron_nak);
    channel_item = proto_tree_add_uint64(subtree, hf_aeron_channel_id, tvb, 0, 0, transport->channel_id);
    PROTO_ITEM_SET_GENERATED(channel_item);
    frame_length_item = proto_tree_add_item(subtree, hf_aeron_nak_frame_length, tvb, offset + O_AERON_NAK_FRAME_LENGTH, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_nak_version, tvb, offset + O_AERON_NAK_VERSION, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_nak_flags, tvb, offset + O_AERON_NAK_FLAGS, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_nak_type, tvb, offset + O_AERON_NAK_TYPE, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_nak_session_id, tvb, offset + O_AERON_NAK_SESSION_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_nak_stream_id, tvb, offset + O_AERON_NAK_STREAM_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_nak_term_id, tvb, offset + O_AERON_NAK_TERM_ID, 4, ENC_LITTLE_ENDIAN);
    nak_offset_item = proto_tree_add_item(subtree, hf_aeron_nak_term_offset, tvb, offset + O_AERON_NAK_TERM_OFFSET, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_nak_length, tvb, offset + O_AERON_NAK_LENGTH, 4, ENC_LITTLE_ENDIAN);
    expert_add_info_format(pinfo, nak_offset_item, &ei_aeron_analysis_nak, "NAK offset %" G_GUINT32_FORMAT " length %" G_GUINT32_FORMAT, nak_term_offset, nak_length);
    aeron_sequence_report(tvb, pinfo, subtree, transport, &pktinfo, finfo);
    proto_item_set_len(nak_item, rounded_length);
    if (frame_length != L_AERON_NAK)
    {
        expert_add_info(pinfo, frame_length_item, &ei_aeron_analysis_invalid_nak_length);
        return (-rounded_length);
    }
    return (rounded_length);
}

/*----------------------------------------------------------------------------*/
/* Aeron status message packet dissection functions.                          */
/*----------------------------------------------------------------------------*/
static void aeron_window_resize_report(packet_info * pinfo, proto_item * item, aeron_frame_info_t * finfo)
{
    if (aeron_sequence_analysis && aeron_stream_analysis && (finfo != NULL) && (finfo->stream_analysis != NULL))
    {
        if ((finfo->stream_analysis->flags & AERON_STREAM_ANALYSIS_FLAGS_WINDOW_RESIZE) != 0)
        {
            expert_add_info(pinfo, item, &ei_aeron_analysis_window_resize);
        }
    }
}

static int dissect_aeron_sm(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, aeron_conversation_info_t * cinfo, aeron_frame_info_t * finfo)
{
    proto_tree * subtree;
    proto_item * sm_item;
    proto_item * frame_length_item;
    proto_item * item;
    proto_item * rcv_window_item;
    guint32 frame_length;
    static const int * flags[] =
    {
        &hf_aeron_sm_flags_s,
        NULL
    };
    guint32 feedback_length;
    aeron_transport_t * transport;
    guint32 session_id;
    guint32 stream_id;
    guint32 term_id;
    guint32 consumption_offset;
    guint32 rcv_window;
    int rounded_length;
    aeron_packet_info_t pktinfo;

    frame_length = tvb_get_letohl(tvb, offset + O_AERON_SM_FRAME_LENGTH);
    feedback_length = frame_length - O_AERON_SM_FEEDBACK;
    rounded_length = (int) aeron_pos_roundup(frame_length);
    if (rounded_length < 0)
        return 0;
    session_id = tvb_get_letohl(tvb, offset + O_AERON_SM_SESSION_ID);
    transport = aeron_transport_add(cinfo, session_id, pinfo->num);
    stream_id = tvb_get_letohl(tvb, offset + O_AERON_SM_STREAM_ID);
    term_id = tvb_get_letohl(tvb, offset + O_AERON_SM_TERM_ID);
    consumption_offset = tvb_get_letohl(tvb, offset + O_AERON_SM_COMPLETED_TERM_OFFSET);
    rcv_window = tvb_get_letohl(tvb, offset + O_AERON_SM_RECEIVER_WINDOW);
    memset((void *) &pktinfo, 0, sizeof(aeron_packet_info_t));
    pktinfo.stream_id = stream_id;
    pktinfo.info_flags = AERON_PACKET_INFO_FLAGS_STREAM_ID_VALID;
    pktinfo.flags = tvb_get_guint8(tvb, offset + O_AERON_SM_FLAGS);
    if ((pktinfo.flags & STATUS_FLAGS_SETUP) == 0)
    {
        pktinfo.term_id = term_id;
        pktinfo.term_offset = consumption_offset;
        pktinfo.info_flags |= (AERON_PACKET_INFO_FLAGS_TERM_ID_VALID | AERON_PACKET_INFO_FLAGS_TERM_OFFSET_VALID);
        pktinfo.receiver_window = rcv_window;
    }
    else
    {
        pktinfo.term_id = 0;
        pktinfo.term_offset = 0;
        pktinfo.receiver_window = 0;
    }
    pktinfo.length = 0;
    pktinfo.data_length = 0;
    pktinfo.type = HDR_TYPE_SM;
    if (aeron_frame_info_setup(pinfo, transport, &pktinfo, finfo) < 0)
        return 0;

    aeron_info_stream_progress_report(pinfo, HDR_TYPE_SM, pktinfo.flags, term_id, consumption_offset, finfo);
    sm_item = proto_tree_add_none_format(tree, hf_aeron_sm, tvb, offset, -1, "Status Message: Term 0x%x, ConsumptionOfs %" G_GUINT32_FORMAT ", RcvWindow %" G_GUINT32_FORMAT,
        term_id, consumption_offset, rcv_window);
    subtree = proto_item_add_subtree(sm_item, ett_aeron_sm);
    item = proto_tree_add_uint64(subtree, hf_aeron_channel_id, tvb, 0, 0, transport->channel_id);
    PROTO_ITEM_SET_GENERATED(item);
    frame_length_item = proto_tree_add_item(subtree, hf_aeron_sm_frame_length, tvb, offset + O_AERON_SM_FRAME_LENGTH, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_sm_version, tvb, offset + O_AERON_SM_VERSION, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_bitmask(subtree, tvb, offset + O_AERON_SM_FLAGS, hf_aeron_sm_flags, ett_aeron_sm_flags, flags, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_sm_type, tvb, offset + O_AERON_SM_TYPE, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_sm_session_id, tvb, offset + O_AERON_SM_SESSION_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_sm_stream_id, tvb, offset + O_AERON_SM_STREAM_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_sm_consumption_term_id, tvb, offset + O_AERON_SM_TERM_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_sm_consumption_term_offset, tvb, offset + O_AERON_SM_COMPLETED_TERM_OFFSET, 4, ENC_LITTLE_ENDIAN);
    rcv_window_item = proto_tree_add_item(subtree, hf_aeron_sm_receiver_window, tvb, offset + O_AERON_SM_RECEIVER_WINDOW, 4, ENC_LITTLE_ENDIAN);
    aeron_window_resize_report(pinfo, rcv_window_item, finfo);
    if (feedback_length > 0)
    {
        proto_tree_add_item(subtree, hf_aeron_sm_feedback, tvb, offset + O_AERON_SM_FEEDBACK, feedback_length, ENC_NA);
    }
    aeron_sequence_report(tvb, pinfo, subtree, transport, &pktinfo, finfo);
    aeron_stream_report(tvb, pinfo, subtree, transport, finfo);
    proto_item_set_len(sm_item, rounded_length);
    if (frame_length < L_AERON_SM_MIN)
    {
        expert_add_info(pinfo, frame_length_item, &ei_aeron_analysis_invalid_sm_length);
        return (-rounded_length);
    }
    return (rounded_length);
}

/*----------------------------------------------------------------------------*/
/* Aeron error packet dissection functions.                                   */
/*----------------------------------------------------------------------------*/
static int dissect_aeron_err(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree)
{
    proto_tree * subtree;
    proto_item * err_item;
    proto_item * frame_length_item;
    int rounded_length;
    guint32 bad_frame_length;
    gint string_length;
    guint32 frame_length;
    int ofs;

    frame_length = tvb_get_letohl(tvb, offset + O_AERON_ERR_FRAME_LENGTH);
    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Error");
    err_item = proto_tree_add_item(tree, hf_aeron_err, tvb, offset, -1, ENC_NA);
    subtree = proto_item_add_subtree(err_item, ett_aeron_err);
    frame_length_item = proto_tree_add_item(subtree, hf_aeron_err_frame_length, tvb, offset + O_AERON_ERR_FRAME_LENGTH, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_err_version, tvb, offset + O_AERON_ERR_VERSION, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_err_code, tvb, offset + O_AERON_ERR_CODE, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_err_type, tvb, offset + O_AERON_ERR_TYPE, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_err_off_frame_length, tvb, offset + O_AERON_ERR_OFFENDING_FRAME_LENGTH, 4, ENC_LITTLE_ENDIAN);
    bad_frame_length = tvb_get_letohl(tvb, offset + O_AERON_ERR_OFFENDING_FRAME_LENGTH);
    ofs = offset + O_AERON_ERR_OFFENDING_HEADER;
    proto_tree_add_item(subtree, hf_aeron_err_off_hdr, tvb, offset + ofs, bad_frame_length, ENC_NA);
    ofs += bad_frame_length;
    string_length = frame_length - ofs;
    if (string_length > 0)
    {
        proto_tree_add_item(subtree, hf_aeron_err_string, tvb, offset + ofs, string_length, ENC_ASCII|ENC_NA);
    }
    rounded_length = (int) aeron_pos_roundup(frame_length);
    if (rounded_length < 0)
        return 0;
    proto_item_set_len(err_item, rounded_length);
    if (frame_length < L_AERON_ERR_MIN)
    {
        expert_add_info(pinfo, frame_length_item, &ei_aeron_analysis_invalid_err_length);
        return (-rounded_length);
    }
    return (rounded_length);
}

/*----------------------------------------------------------------------------*/
/* Aeron setup packet dissection functions.                                   */
/*----------------------------------------------------------------------------*/
static void aeron_set_stream_mtu_term_length(packet_info * pinfo, aeron_transport_t * transport, guint32 stream_id, guint32 mtu, guint32 term_length)
{
    if (PINFO_FD_VISITED(pinfo) == 0)
    {
        aeron_stream_t * stream = aeron_transport_stream_find(transport, stream_id);
        if (stream != NULL)
        {
            stream->term_length = term_length;
            stream->mtu = mtu;
        }
    }
}

static int dissect_aeron_setup(tvbuff_t * tvb, int offset, packet_info * pinfo, proto_tree * tree, aeron_conversation_info_t * cinfo, aeron_frame_info_t * finfo)
{
    proto_tree * subtree;
    proto_item * setup_item;
    proto_item * frame_length_item;
    guint32 frame_length;
    proto_item * channel_item;
    aeron_transport_t * transport;
    guint32 session_id;
    guint32 stream_id;
    guint32 active_term_id;
    guint32 initial_term_id;
    guint32 term_offset;
    guint32 term_length;
    guint32 mtu;
    int rounded_length;
    aeron_packet_info_t pktinfo;

    frame_length = tvb_get_letohl(tvb, offset + O_AERON_SETUP_FRAME_LENGTH);
    rounded_length = (int) aeron_pos_roundup(frame_length);
    if (rounded_length < 0)
        return 0;
    term_offset = tvb_get_letohl(tvb, offset + O_AERON_SETUP_TERM_OFFSET);
    session_id = tvb_get_letohl(tvb, offset + O_AERON_SETUP_SESSION_ID);
    transport = aeron_transport_add(cinfo, session_id, pinfo->num);
    stream_id = tvb_get_letohl(tvb, offset + O_AERON_SETUP_STREAM_ID);
    initial_term_id = tvb_get_letohl(tvb, offset + O_AERON_SETUP_INITIAL_TERM_ID);
    active_term_id = tvb_get_letohl(tvb, offset + O_AERON_SETUP_ACTIVE_TERM_ID);
    memset((void *) &pktinfo, 0, sizeof(aeron_packet_info_t));
    pktinfo.stream_id = stream_id;
    pktinfo.term_id = active_term_id;
    pktinfo.term_offset = 0;
    pktinfo.info_flags = AERON_PACKET_INFO_FLAGS_STREAM_ID_VALID | AERON_PACKET_INFO_FLAGS_TERM_ID_VALID;
    pktinfo.length = 0;
    pktinfo.data_length = 0;
    pktinfo.receiver_window = 0;
    pktinfo.type = HDR_TYPE_SETUP;
    pktinfo.flags = 0;
    if (aeron_frame_info_setup(pinfo, transport, &pktinfo, finfo) < 0)
        return 0;
    term_length = tvb_get_letohl(tvb, offset + O_AERON_SETUP_TERM_LENGTH);
    mtu = tvb_get_letohl(tvb, offset + O_AERON_SETUP_MTU);
    aeron_set_stream_mtu_term_length(pinfo, transport, stream_id, mtu, term_length);

    col_append_sep_str(pinfo->cinfo, COL_INFO, ", ", "Setup");
    setup_item = proto_tree_add_none_format(tree, hf_aeron_setup, tvb, offset, -1, "Setup Frame: InitTerm 0x%x, ActiveTerm 0x%x, TermLen %" G_GUINT32_FORMAT ", Ofs %" G_GUINT32_FORMAT ", MTU %" G_GUINT32_FORMAT,
        initial_term_id, (guint32) active_term_id, term_length, term_offset, mtu);
    subtree = proto_item_add_subtree(setup_item, ett_aeron_setup);
    channel_item = proto_tree_add_uint64(subtree, hf_aeron_channel_id, tvb, 0, 0, transport->channel_id);
    PROTO_ITEM_SET_GENERATED(channel_item);
    frame_length_item = proto_tree_add_item(subtree, hf_aeron_setup_frame_length, tvb, offset + O_AERON_SETUP_FRAME_LENGTH, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_version, tvb, offset + O_AERON_SETUP_VERSION, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_flags, tvb, offset + O_AERON_SETUP_FLAGS, 1, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_type, tvb, offset + O_AERON_SETUP_TYPE, 2, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_term_offset, tvb, offset + O_AERON_SETUP_TERM_OFFSET, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_session_id, tvb, offset + O_AERON_SETUP_SESSION_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_stream_id, tvb, offset + O_AERON_SETUP_STREAM_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_initial_term_id, tvb, offset + O_AERON_SETUP_INITIAL_TERM_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_active_term_id, tvb, offset + O_AERON_SETUP_ACTIVE_TERM_ID, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_term_length, tvb, offset + O_AERON_SETUP_TERM_LENGTH, 4, ENC_LITTLE_ENDIAN);
    proto_tree_add_item(subtree, hf_aeron_setup_mtu, tvb, offset + O_AERON_SETUP_MTU, 4, ENC_LITTLE_ENDIAN);
    aeron_sequence_report(tvb, pinfo, subtree, transport, &pktinfo, finfo);
    proto_item_set_len(setup_item, rounded_length);
    if (frame_length != L_AERON_SETUP)
    {
        expert_add_info(pinfo, frame_length_item, &ei_aeron_analysis_invalid_setup_length);
        return (-rounded_length);
    }
    return (rounded_length);
}

/*----------------------------------------------------------------------------*/
/* Aeron packet dissector.                                                    */
/*----------------------------------------------------------------------------*/
static int dissect_aeron(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data _U_)
{
    int total_dissected_length = 0;
    guint16 frame_type;
    proto_tree * aeron_tree;
    proto_item * aeron_item;
    int dissected_length = 0;
    int offset = 0;
    int length_remaining;
    aeron_conversation_info_t * cinfo;

    /* Get enough information to determine the conversation info.
       Make sure that we don't throw an exception before we know that
       this packet contains our protocol. */
    if (tvb_captured_length_remaining(tvb, offset) < 2)
        return 0;
    frame_type = tvb_get_letohs(tvb, offset + O_AERON_BASIC_TYPE);
    cinfo = aeron_setup_conversation_info(pinfo, frame_type);
    if (!cinfo)
        return 0;

    col_add_str(pinfo->cinfo, COL_PROTOCOL, "Aeron");
    col_clear(pinfo->cinfo, COL_INFO);
    col_add_str(pinfo->cinfo, COL_INFO, aeron_format_transport_uri(cinfo));
    col_set_fence(pinfo->cinfo, COL_INFO);

    length_remaining = tvb_reported_length(tvb);
    aeron_item = proto_tree_add_protocol_format(tree, proto_aeron, tvb, offset, -1, "Aeron Protocol");
    aeron_tree = proto_item_add_subtree(aeron_item, ett_aeron);
    while (length_remaining > 0)
    {
        aeron_frame_info_t * finfo = NULL;

        if (aeron_sequence_analysis)
        {
            finfo = aeron_frame_info_add(pinfo->num, (guint32) offset);
        }
        frame_type = tvb_get_letohs(tvb, offset + O_AERON_BASIC_TYPE);
        cinfo = aeron_setup_conversation_info(pinfo, frame_type);
        switch (frame_type)
        {
            case HDR_TYPE_PAD:
                dissected_length = dissect_aeron_pad(tvb, offset, pinfo, aeron_tree, cinfo, finfo);
                break;
            case HDR_TYPE_DATA:
                dissected_length = dissect_aeron_data(tvb, offset, pinfo, aeron_tree, cinfo, finfo);
                break;
            case HDR_TYPE_NAK:
                dissected_length = dissect_aeron_nak(tvb, offset, pinfo, aeron_tree, cinfo, finfo);
                break;
            case HDR_TYPE_SM:
                dissected_length = dissect_aeron_sm(tvb, offset, pinfo, aeron_tree, cinfo, finfo);
                break;
            case HDR_TYPE_ERR:
                dissected_length = dissect_aeron_err(tvb, offset, pinfo, aeron_tree);
                break;
            case HDR_TYPE_SETUP:
                dissected_length = dissect_aeron_setup(tvb, offset, pinfo, aeron_tree, cinfo, finfo);
                break;
            case HDR_TYPE_EXT:
            default:
                return (total_dissected_length);
        }
        if (dissected_length <= 0)
        {
            total_dissected_length += -dissected_length;
            proto_item_set_len(aeron_item, total_dissected_length);
            return (total_dissected_length);
        }
        total_dissected_length += dissected_length;
        offset += dissected_length;
        length_remaining -= dissected_length;
        proto_item_set_len(aeron_item, total_dissected_length);
    }
    return (total_dissected_length);
}

static gboolean test_aeron_packet(tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree, void * user_data)
{
    guint8 ver;
    guint16 packet_type;
    gint length;
    gint length_remaining;
    int rc;

    length_remaining = tvb_captured_length_remaining(tvb, 0);
    if (length_remaining < HDR_LENGTH_MIN)
    {
        return (FALSE);
    }
    /* We know we have at least HDR_LENGTH_MIN (12) bytes captured */
    ver = tvb_get_guint8(tvb, O_AERON_BASIC_VERSION);
    if (ver != 0)
    {
        return (FALSE);
    }
    packet_type = tvb_get_letohs(tvb, O_AERON_BASIC_TYPE);
    switch (packet_type)
    {
        case HDR_TYPE_PAD:
        case HDR_TYPE_DATA:
        case HDR_TYPE_NAK:
        case HDR_TYPE_SM:
        case HDR_TYPE_ERR:
        case HDR_TYPE_SETUP:
        case HDR_TYPE_EXT:
            break;
        default:
            return (FALSE);
    }
    length = (gint) (tvb_get_letohl(tvb, O_AERON_BASIC_FRAME_LENGTH) & 0x7fffffff);
    if (!((packet_type == HDR_TYPE_DATA) && (length == 0)))
    {
        if (length < HDR_LENGTH_MIN)
        {
            return (FALSE);
        }
    }
    if (packet_type == HDR_TYPE_PAD)
    {
        /* Pad frames can't have a zero term offset */
        guint32 term_offset = tvb_get_letohl(tvb, O_AERON_PAD_TERM_OFFSET);
        if (term_offset == 0)
        {
            return (FALSE);
        }
    }
    else
    {
        if (length > length_remaining)
        {
            return (FALSE);
        }
    }
    rc = dissect_aeron(tvb, pinfo, tree, user_data);
    if (rc == 0)
    {
        return (FALSE);
    }
    return (TRUE);
}

static void aeron_init(void)
{
    aeron_channel_id_init();
}

/* Register all the bits needed with the filtering engine */
void proto_register_aeron(void)
{
    static hf_register_info hf[] =
    {
        { &hf_aeron_channel_id,
            { "Channel ID", "aeron.channel_id", FT_UINT64, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_pad,
            { "Pad Frame", "aeron.pad", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_pad_frame_length,
            { "Frame Length", "aeron.pad.frame_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_pad_version,
            { "Version", "aeron.pad.version", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_pad_flags,
            { "Flags", "aeron.pad.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_pad_type,
            { "Type", "aeron.pad.type", FT_UINT16, BASE_DEC_HEX, VALS(aeron_frame_type), 0x0, NULL, HFILL } },
        { &hf_aeron_pad_term_offset,
            { "Term Offset", "aeron.pad.term_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_pad_session_id,
            { "Session ID", "aeron.pad.session_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_pad_stream_id,
            { "Stream ID", "aeron.pad.stream_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_pad_term_id,
            { "Term ID", "aeron.pad.term_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data,
            { "Data Frame", "aeron.data", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_frame_length,
            { "Frame Length", "aeron.data.frame_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_version,
            { "Version", "aeron.data.version", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_flags,
            { "Flags", "aeron.data.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_flags_b,
            { "Begin Message", "aeron.data.flags.b", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DATA_FLAGS_BEGIN, NULL, HFILL } },
        { &hf_aeron_data_flags_e,
            { "End Message", "aeron.data.flags.e", FT_BOOLEAN, 8, TFS(&tfs_set_notset), DATA_FLAGS_END, NULL, HFILL } },
        { &hf_aeron_data_type,
            { "Type", "aeron.data.type", FT_UINT16, BASE_DEC_HEX, VALS(aeron_frame_type), 0x0, NULL, HFILL } },
        { &hf_aeron_data_term_offset,
            { "Term Offset", "aeron.data.term_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_next_offset,
            { "Next Offset", "aeron.data.next_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_next_offset_term,
            { "Next Offset Term", "aeron.data.next_offset_term", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_next_offset_first_frame,
            { "Next Offset First Frame", "aeron.data.next_offset_first_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_session_id,
            { "Session ID", "aeron.data.session_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_stream_id,
            { "Stream ID", "aeron.data.stream_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_term_id,
            { "Term ID", "aeron.data.term_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_reassembly,
            { "Reassembled Fragments", "aeron.data.reassembly", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_data_reassembly_fragment,
            { "Fragment", "aeron.data.reassembly.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak,
            { "NAK Frame", "aeron.nak", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak_frame_length,
            { "Frame Length", "aeron.nak.frame_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak_version,
            { "Version", "aeron.nak.version", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak_flags,
            { "Flags", "aeron.nak.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak_type,
            { "Type", "aeron.nak.type", FT_UINT16, BASE_DEC_HEX, VALS(aeron_frame_type), 0x0, NULL, HFILL } },
        { &hf_aeron_nak_session_id,
            { "Session ID", "aeron.nak.session_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak_stream_id,
            { "Stream ID", "aeron.nak.stream_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak_term_id,
            { "Term ID", "aeron.nak.term_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak_term_offset,
            { "Term Offset", "aeron.nak.term_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_nak_length,
            { "Length", "aeron.nak.length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm,
            { "Status Message", "aeron.sm", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_frame_length,
            { "Frame Length", "aeron.sm.frame_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_version,
            { "Version", "aeron.sm.version", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_flags,
            { "Flags", "aeron.sm.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_flags_s,
            { "Setup", "aeron.sm.flags.s", FT_BOOLEAN, 8, TFS(&tfs_set_notset), STATUS_FLAGS_SETUP, NULL, HFILL } },
        { &hf_aeron_sm_type,
            { "Type", "aeron.sm.type", FT_UINT16, BASE_DEC_HEX, VALS(aeron_frame_type), 0x0, NULL, HFILL } },
        { &hf_aeron_sm_session_id,
            { "Session ID", "aeron.sm.session_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_stream_id,
            { "Stream ID", "aeron.sm.stream_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_consumption_term_id,
            { "Consumption Term ID", "aeron.sm.consumption_term_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_consumption_term_offset,
            { "Consumption Term Offset", "aeron.sm.consumption_term_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_receiver_window,
            { "Receiver Window", "aeron.sm.receiver_window", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sm_feedback,
            { "Application-specific Feedback", "aeron.sm.feedback", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_err,
            { "Error Header", "aeron.err", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_err_frame_length,
            { "Frame Length", "aeron.err.frame_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_err_version,
            { "Version", "aeron.err.version", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_err_code,
            { "Error Code", "aeron.err.code", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_err_type,
            { "Type", "aeron.err.type", FT_UINT16, BASE_DEC_HEX, VALS(aeron_frame_type), 0x0, NULL, HFILL } },
        { &hf_aeron_err_off_frame_length,
            { "Offending Frame Length", "aeron.err.off_frame_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_err_off_hdr,
            { "Offending Header", "aeron.err.off_hdr", FT_BYTES, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_err_string,
            { "Error String", "aeron.err.string", FT_STRINGZ, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup,
            { "Setup Frame", "aeron.setup", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_frame_length,
            { "Frame Length", "aeron.setup.frame_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_version,
            { "Version", "aeron.setup.version", FT_UINT8, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_flags,
            { "Flags", "aeron.setup.flags", FT_UINT8, BASE_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_type,
            { "Type", "aeron.setup.type", FT_UINT16, BASE_DEC_HEX, VALS(aeron_frame_type), 0x0, NULL, HFILL } },
        { &hf_aeron_setup_term_offset,
            { "Term Offset", "aeron.setup.term_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_session_id,
            { "Session ID", "aeron.setup.session_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_stream_id,
            { "Stream ID", "aeron.setup.stream_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_initial_term_id,
            { "Initial Term ID", "aeron.setup.initial_term_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_active_term_id,
            { "Active Term ID", "aeron.setup.active_term_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_term_length,
            { "Term Length", "aeron.setup.term_length", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_setup_mtu,
            { "MTU", "aeron.setup.mtu", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis,
            { "Sequence Analysis", "aeron.sequence_analysis", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_channel_prev_frame,
            { "Previous Channel Frame", "aeron.sequence_analysis.prev_channel_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_channel_next_frame,
            { "Next Channel Frame", "aeron.sequence_analysis.next_channel_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_stream_prev_frame,
            { "Previous Stream Frame", "aeron.sequence_analysis.prev_stream_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_stream_next_frame,
            { "Next Stream Frame", "aeron.sequence_analysis.next_stream_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_term_prev_frame,
            { "Previous Term Frame", "aeron.sequence_analysis.prev_term_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_term_next_frame,
            { "Next Term Frame", "aeron.sequence_analysis.next_term_frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_term_offset,
            { "Offset also in", "aeron.sequence_analysis.term_offset", FT_NONE, BASE_NONE, NULL, 0x0, "Offset also appears in these frames", HFILL } },
        { &hf_aeron_sequence_analysis_term_offset_frame,
            { "Frame", "aeron.sequence_analysis.term_offset.frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_retransmission,
            { "Frame is a retransmission", "aeron.sequence_analysis.retransmission", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_retransmission_rx,
            { "List of NAK frames to which this retransmission applies", "aeron.sequence_analysis.retransmission.rx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_retransmission_rx_frame,
            { "Retransmission applies to frame", "aeron.sequence_analysis.retransmission.rx.frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_nak_unrecovered,
            { "Unrecovered Bytes", "aeron.sequence_analysis.nak_unrecovered", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_nak_rx,
            { "List of RX Frames for this NAK", "aeron.sequence_analysis.nak_rx", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_nak_rx_frame,
            { "RX Frame for this NAK", "aeron.sequence_analysis.nak_rx.frame", FT_FRAMENUM, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_sequence_analysis_keepalive,
            { "Frame is a keepalive", "aeron.sequence_analysis.keepalive", FT_BOOLEAN, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_stream_analysis,
            { "Stream Analysis", "aeron.stream_analysis", FT_NONE, BASE_NONE, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_stream_analysis_high_term_id,
            { "Highest sent term ID", "aeron.stream_analysis.high_term_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_stream_analysis_high_term_offset,
            { "Highest sent term offset", "aeron.stream_analysis.high_term_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_stream_analysis_completed_term_id,
            { "Completed term ID", "aeron.stream_analysis.completed_term_id", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_stream_analysis_completed_term_offset,
            { "Completed term offset", "aeron.stream_analysis.completed_term_offset", FT_UINT32, BASE_DEC_HEX, NULL, 0x0, NULL, HFILL } },
        { &hf_aeron_stream_analysis_outstanding_bytes,
            { "Outstanding bytes", "aeron.stream_analysis.outstanding_bytes", FT_UINT32, BASE_DEC, NULL, 0x0, NULL, HFILL } }
    };
    static gint * ett[] =
    {
        &ett_aeron,
        &ett_aeron_pad,
        &ett_aeron_data,
        &ett_aeron_data_flags,
        &ett_aeron_data_reassembly,
        &ett_aeron_nak,
        &ett_aeron_sm,
        &ett_aeron_sm_flags,
        &ett_aeron_err,
        &ett_aeron_setup,
        &ett_aeron_ext,
        &ett_aeron_sequence_analysis,
        &ett_aeron_sequence_analysis_retransmission_rx,
        &ett_aeron_sequence_analysis_nak_rx,
        &ett_aeron_sequence_analysis_term_offset,
        &ett_aeron_stream_analysis
    };
    static ei_register_info ei[] =
    {
        { &ei_aeron_analysis_nak, { "aeron.analysis.nak", PI_SEQUENCE, PI_NOTE, "NAK", EXPFILL } },
        { &ei_aeron_analysis_window_full, { "aeron.analysis.window_full", PI_SEQUENCE, PI_NOTE, "Receiver window is full", EXPFILL } },
        { &ei_aeron_analysis_idle_rx, { "aeron.analysis.idle_rx", PI_SEQUENCE, PI_NOTE, "This frame contains an Idle RX", EXPFILL } },
        { &ei_aeron_analysis_pacing_rx, { "aeron.analysis.pacing_rx", PI_SEQUENCE, PI_NOTE, "This frame contains a Pacing RX", EXPFILL } },
        { &ei_aeron_analysis_ooo, { "aeron.analysis.ooo", PI_SEQUENCE, PI_NOTE, "This frame contains Out-of-order data", EXPFILL } },
        { &ei_aeron_analysis_ooo_gap, { "aeron.analysis.ooo_gap", PI_SEQUENCE, PI_NOTE, "This frame is an Out-of-order gap", EXPFILL } },
        { &ei_aeron_analysis_keepalive, { "aeron.analysis.keepalive", PI_SEQUENCE, PI_NOTE, "This frame contains a Keepalive", EXPFILL } },
        { &ei_aeron_analysis_window_resize, { "aeron.analysis.window_resize", PI_SEQUENCE, PI_NOTE, "Receiver window resized", EXPFILL } },
        { &ei_aeron_analysis_ooo_sm, { "aeron.analysis.ooo_sm", PI_SEQUENCE, PI_NOTE, "This frame contains an Out-of-order SM", EXPFILL } },
        { &ei_aeron_analysis_keepalive_sm, { "aeron.analysis.keepalive_sm", PI_SEQUENCE, PI_NOTE, "This frame contains a Keepalive SM", EXPFILL } },
        { &ei_aeron_analysis_rx, { "aeron.analysis.rx", PI_SEQUENCE, PI_NOTE, "This frame contains a (likely) retransmission", EXPFILL } },
        { &ei_aeron_analysis_term_id_change, { "aeron.analysis.term_id_change", PI_SEQUENCE, PI_CHAT, "This frame contains a new term ID", EXPFILL } },
        { &ei_aeron_analysis_invalid_pad_length, { "aeron.analysis.invalid_pad_length", PI_MALFORMED, PI_ERROR, "Invalid pad frame length", EXPFILL } },
        { &ei_aeron_analysis_invalid_data_length, { "aeron.analysis.invalid_data_length", PI_MALFORMED, PI_ERROR, "Invalid data frame length", EXPFILL } },
        { &ei_aeron_analysis_invalid_nak_length, { "aeron.analysis.invalid_nak_length", PI_MALFORMED, PI_ERROR, "Invalid NAK frame length", EXPFILL } },
        { &ei_aeron_analysis_invalid_sm_length, { "aeron.analysis.invalid_sm_length", PI_MALFORMED, PI_ERROR, "Invalid SM frame length", EXPFILL } },
        { &ei_aeron_analysis_invalid_err_length, { "aeron.analysis.invalid_err_length", PI_MALFORMED, PI_ERROR, "Invalid error frame length", EXPFILL } },
        { &ei_aeron_analysis_invalid_setup_length, { "aeron.analysis.invalid_setup_length", PI_MALFORMED, PI_ERROR, "Invalid setup frame length", EXPFILL } }
    };
    module_t * aeron_module;
    expert_module_t * expert_aeron;

    proto_aeron = proto_register_protocol("Aeron Protocol", "Aeron", "aeron");

    proto_register_field_array(proto_aeron, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    expert_aeron = expert_register_protocol(proto_aeron);
    expert_register_field_array(expert_aeron, ei, array_length(ei));
    aeron_module = prefs_register_protocol(proto_aeron, proto_reg_handoff_aeron);
    aeron_heuristic_subdissector_list = register_heur_dissector_list("aeron_msg_payload", proto_aeron);

    prefs_register_bool_preference(aeron_module,
        "sequence_analysis",
        "Analyze transport sequencing",
        "Include next/previous frame for channel, stream, and term, and other transport sequence analysis.",
        &aeron_sequence_analysis);
    prefs_register_bool_preference(aeron_module,
        "stream_analysis",
        "Analyze stream sequencing",
        "Include stream analysis, tracking publisher and subscriber positions. Requires \"Analyze transport sequencing\".",
        &aeron_stream_analysis);
    prefs_register_bool_preference(aeron_module,
        "reassemble_fragments",
        "Reassemble fragmented data",
        "Reassemble fragmented data messages. Requires \"Analyze transport sequencing\" and \"Analyze stream sequencing\".",
        &aeron_reassemble_fragments);
    prefs_register_bool_preference(aeron_module,
        "use_heuristic_subdissectors",
        "Use heuristic sub-dissectors",
        "Use a registered heuristic sub-dissector to decode the payload data. Requires \"Analyze transport sequencing\", \"Analyze stream sequencing\", and \"Reassemble fragmented data\".",
        &aeron_use_heuristic_subdissectors);
    register_init_routine(aeron_init);
    aeron_frame_info_tree = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
}

/* The registration hand-off routine */
void proto_reg_handoff_aeron(void)
{
    aeron_dissector_handle = create_dissector_handle(dissect_aeron, proto_aeron);
    dissector_add_for_decode_as("udp.port", aeron_dissector_handle);
    heur_dissector_add("udp", test_aeron_packet, "Aeron over UDP", "aeron_udp", proto_aeron, HEURISTIC_DISABLE);
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
