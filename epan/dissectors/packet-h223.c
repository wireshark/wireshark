/* packet-h223.c
 * Routines for H.223 packet dissection
 * Copyright (c) 2004-5 MX Telecom Ltd <richardv@mxtelecom.com>
 *
 * $Id$
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
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 */

#ifdef HAVE_CONFIG_H
# include "config.h"
#endif

#include <glib.h>
#include <epan/emem.h>
#include <epan/bitswap.h>
#include <epan/circuit.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/stream.h>
#include <epan/reassemble.h>
#include <epan/golay.h>
#include <epan/iax2_codec_type.h>
#include <epan/dissectors/packet-frame.h>
#include <epan/asn1.h>
#include <epan/dissectors/packet-h245.h>

#include "packet-h223.h"

#include <string.h>

/* #define DEBUG_H223 */

/* debug the mux-pdu defragmentation code. warning: verbose output! */
/* #define DEBUG_H223_FRAGMENTATION */

#define PROTO_TAG_H223 "H223"

/* Wireshark ID of the H.223 protocol */
static int proto_h223 = -1;

/* The following hf_* variables are used to hold the Wireshark IDs of
 * our header fields; they are filled out when we call
 * proto_register_field_array() in proto_register_h223()
 */
static int hf_h223_non_h223_data = -1;
static int hf_h223_mux_stuffing_pdu = -1;
static int hf_h223_mux_pdu = -1;
static int hf_h223_mux_header = -1;
static int hf_h223_mux_rawhdr = -1;
static int hf_h223_mux_correctedhdr = -1;
static int hf_h223_mux_mc = -1;
static int hf_h223_mux_mpl = -1;
static int hf_h223_mux_deact = -1;
static int hf_h223_mux_vc = -1;
static int hf_h223_mux_extra = -1;
static int hf_h223_mux_hdlc2 = -1;
static int hf_h223_mux_fragments = -1;
static int hf_h223_mux_fragment = -1;
static int hf_h223_mux_fragment_overlap = -1;
static int hf_h223_mux_fragment_overlap_conflict = -1;
static int hf_h223_mux_fragment_multiple_tails = -1;
static int hf_h223_mux_fragment_too_long_fragment = -1;
static int hf_h223_mux_fragment_error = -1;
static int hf_h223_mux_fragment_count = -1;
static int hf_h223_mux_reassembled_in = -1;
static int hf_h223_mux_reassembled_length = -1;

static int hf_h223_al_fragments = -1;
static int hf_h223_al_fragment = -1;
static int hf_h223_al_fragment_overlap = -1;
static int hf_h223_al_fragment_overlap_conflict = -1;
static int hf_h223_al_fragment_multiple_tails = -1;
static int hf_h223_al_fragment_too_long_fragment = -1;
static int hf_h223_al_fragment_error = -1;
static int hf_h223_al_fragment_count = -1;
static int hf_h223_al_reassembled_in = -1;
static int hf_h223_al_reassembled_length = -1;

static int hf_h223_al1 = -1;
static int hf_h223_al1_framed = -1;
static int hf_h223_al2 = -1;
static int hf_h223_al2_sequenced = -1;
static int hf_h223_al2_unsequenced = -1;
static int hf_h223_al2_seqno = -1;
static int hf_h223_al2_crc = -1;
static int hf_h223_al2_crc_bad = -1;

static int hf_h223_al_payload = -1;

/* These are the ids of the subtrees that we may be creating */
static gint ett_h223 = -1;
static gint ett_h223_non_h223_data = -1;
static gint ett_h223_mux_stuffing_pdu = -1;
static gint ett_h223_mux_pdu = -1;
static gint ett_h223_mux_header = -1;
static gint ett_h223_mux_deact = -1;
static gint ett_h223_mux_vc = -1;
static gint ett_h223_mux_extra = -1;
static gint ett_h223_mux_fragments = -1;
static gint ett_h223_mux_fragment  = -1;
static gint ett_h223_al_fragments = -1;
static gint ett_h223_al_fragment  = -1;
static gint ett_h223_al1 = -1;
static gint ett_h223_al2 = -1;
static gint ett_h223_al_payload = -1;

/* These are the handles of our subdissectors */
static dissector_handle_t data_handle;
static dissector_handle_t srp_handle;

static const fragment_items h223_mux_frag_items _U_ = {
    &ett_h223_mux_fragment,
    &ett_h223_mux_fragments,
    &hf_h223_mux_fragments,
    &hf_h223_mux_fragment,
    &hf_h223_mux_fragment_overlap,
    &hf_h223_mux_fragment_overlap_conflict,
    &hf_h223_mux_fragment_multiple_tails,
    &hf_h223_mux_fragment_too_long_fragment,
    &hf_h223_mux_fragment_error,
    &hf_h223_mux_fragment_count,
    &hf_h223_mux_reassembled_in,
    &hf_h223_mux_reassembled_length,
    "fragments"
};

static const fragment_items h223_al_frag_items = {
    &ett_h223_al_fragment,
    &ett_h223_al_fragments,
    &hf_h223_al_fragments,
    &hf_h223_al_fragment,
    &hf_h223_al_fragment_overlap,
    &hf_h223_al_fragment_overlap_conflict,
    &hf_h223_al_fragment_multiple_tails,
    &hf_h223_al_fragment_too_long_fragment,
    &hf_h223_al_fragment_error,
    &hf_h223_al_fragment_count,
    &hf_h223_al_reassembled_in,
    &hf_h223_al_reassembled_length,
    "fragments"
};

/* this is a fudge to pass pdu_offset into add_h223_mux_element() */
static guint32 pdu_offset;

/***************************************************************************
 *
 * virtual circuit number handling
 *
 * we have to be able to manage more than one H.223 call at a time,
 * so have a hash which maps {call,vc} to an integer.
 */

typedef struct _h223_call_info h223_call_info;

typedef struct {
    const h223_call_info* call; /* h223 call */
    guint32 vc;                 /* child circuit */
} circuit_chain_key;

static GHashTable *circuit_chain_hashtable = NULL;
static guint circuit_chain_count = 1;

/* Hash Functions */
static gint
circuit_chain_equal(gconstpointer v, gconstpointer w)
{
    const circuit_chain_key *v1 = (const circuit_chain_key *)v;
    const circuit_chain_key *v2 = (const circuit_chain_key *)w;
    gint result;
    result = ( v1->call == v2->call &&
               v1->vc == v2 -> vc );
    return result;
}

static guint
circuit_chain_hash (gconstpointer v)
{
    const circuit_chain_key *key = (const circuit_chain_key *)v;
    guint hash_val = ((guint32)(unsigned long)(key->call))^(((guint32)key->vc) << 16);
    return hash_val;
}

static guint32
circuit_chain_lookup(const h223_call_info* call_info, guint32 child_vc)
{
    circuit_chain_key key, *new_key;
    guint32 circuit_id;
    key.call = call_info;
    key.vc = child_vc;
    circuit_id = GPOINTER_TO_UINT(g_hash_table_lookup( circuit_chain_hashtable, &key ));
    if( circuit_id == 0 ) {
        new_key = se_alloc(sizeof(circuit_chain_key));
        *new_key = key;
        circuit_id = ++circuit_chain_count;
        g_hash_table_insert(circuit_chain_hashtable, new_key, GUINT_TO_POINTER(circuit_id));
    }
    return circuit_id;
}

static void
circuit_chain_init(void)
{
    if (circuit_chain_hashtable)
        g_hash_table_destroy(circuit_chain_hashtable);
    circuit_chain_hashtable = g_hash_table_new(circuit_chain_hash, circuit_chain_equal);
    circuit_chain_count = 1;
}


/***************************************************************************
 *
 * Call information management
 *
 */

/* we keep information on each call in an h223_call_info structure
 *
 * We attach the h223_call_info structures to individual calls with
 * circuit_add_proto_data().
*/

typedef struct _h223_mux_element_listitem h223_mux_element_listitem;
struct _h223_mux_element_listitem {
    h223_mux_element          *me;
    guint32                    first_frame;
    guint32                    pdu_offset;
    h223_mux_element_listitem *next;
};

/* we have this information for each stream */
typedef struct {
    h223_mux_element_listitem* mux_table[16];
} h223_call_direction_data;


struct _h223_call_info {
    /* H.223 level: 0 for standard H223, 1, 2 or 3 for the enhanced protocols
       specified in the annexes
    */
    int h223_level;

    /* for H.223 streams over TCP (as opposed to IAX), this
       stores the source address and port of the first packet spotted,
       so that we can differentiate directions.
    */
    address srcaddress;
    guint32 srcport;

    h223_call_direction_data direction_data[2];
};

typedef struct _h223_lc_params_listitem h223_lc_params_listitem;
struct _h223_lc_params_listitem
{
    h223_lc_params         *lc_params;
    guint32                 first_frame;
    guint32                 last_frame;
    h223_lc_params_listitem *next;
};

typedef struct {
    h223_lc_params_listitem *lc_params[2];
    h223_call_info          *call_info;
} h223_vc_info;

static void
add_h223_mux_element(h223_call_direction_data *direct, guint8 mc, h223_mux_element *me, guint32 framenum)
{
    h223_mux_element_listitem *li;
    h223_mux_element_listitem **old_li_ptr;
    h223_mux_element_listitem *old_li;

    DISSECTOR_ASSERT(mc < 16);

    li = se_alloc(sizeof(h223_mux_element_listitem));
    old_li_ptr = &(direct->mux_table[mc]);
    old_li = *old_li_ptr;
    if( !old_li ) {
        direct->mux_table[mc] = li;
    } else {
        while( old_li->next ) {
            old_li_ptr = &(old_li->next);
            old_li = *old_li_ptr;
        }
        if( framenum < old_li->first_frame || (framenum == old_li->first_frame && pdu_offset < old_li->pdu_offset)  )
            return;
        else if ( framenum == old_li->first_frame && pdu_offset == old_li->pdu_offset )
            *old_li_ptr = li; /* replace the tail of the list with the new item, since */
                              /* a single h223 pdu has just set the same MC twice.. */
        else
            old_li->next = li;
    }
    li->first_frame = framenum;
    li->pdu_offset = pdu_offset;
    li->next = 0;
    li->me = me;
}

static h223_mux_element*
find_h223_mux_element(h223_call_direction_data* direct, guint8 mc, guint32 framenum, guint32 pkt_offset)
{
    h223_mux_element_listitem* li;

    DISSECTOR_ASSERT(mc < 16);

    li = direct->mux_table[mc];

    while( li && li->next && li->next->first_frame < framenum )
        li = li->next;
    while( li && li->next && li->next->first_frame == framenum && li->next->pdu_offset < pkt_offset )
        li = li->next;
    if( li ) {
        return li->me;
    } else {
        return NULL;
    }
}

static void
add_h223_lc_params(h223_vc_info* vc_info, int direction, h223_lc_params *lc_params, guint32 framenum )
{
    h223_lc_params_listitem *li = se_alloc(sizeof(h223_lc_params_listitem));
    h223_lc_params_listitem **old_li_ptr = &(vc_info->lc_params[direction ? 0 : 1]);
    h223_lc_params_listitem *old_li = *old_li_ptr;
    if( !old_li ) {
        vc_info->lc_params[direction ? 0 : 1] = li;
    } else {
        while( old_li->next ) {
            old_li_ptr = &(old_li->next);
            old_li = *old_li_ptr;
        }
        if( framenum < old_li->first_frame )
            return;
        else if( framenum == old_li->first_frame )
            *old_li_ptr = li;
        else {
            old_li->next = li;
            old_li->last_frame = framenum - 1;
        }
    }
    li->first_frame = framenum;
    li->last_frame = 0;
    li->next = 0;
    li->lc_params = lc_params;
}

static h223_lc_params*
find_h223_lc_params(h223_vc_info* vc_info, int direction, guint32 framenum)
{
    h223_lc_params_listitem* li = vc_info->lc_params[direction? 0 : 1];
    while( li && li->next && li->next->first_frame <= framenum )
        li = li->next;
    if( li )
        return li->lc_params;
    else
        return NULL;
}

static void
init_direction_data(h223_call_direction_data *direct)
{
    int i;
    h223_mux_element *mc0_element;

    for ( i = 0; i < 16; ++i )
        direct->mux_table[i] = NULL;

    /* set up MC 0 to contain just VC 0 */
    mc0_element = se_alloc(sizeof(h223_mux_element));
    add_h223_mux_element( direct, 0, mc0_element, 0 );
    mc0_element->sublist = NULL;
    mc0_element->vc = 0;
    mc0_element->repeat_count = 0; /* until closing flag */
    mc0_element->next = NULL;
}

static h223_vc_info*
h223_vc_info_new( h223_call_info* call_info )
{
    h223_vc_info *vc_info = se_alloc(sizeof(h223_vc_info));
    vc_info->lc_params[0] = vc_info->lc_params[1] = NULL;
    vc_info->call_info = call_info;
    return vc_info;
}

static void
init_logical_channel( guint32 start_frame, h223_call_info* call_info, int vc, int direction, h223_lc_params* params )
{
    guint32 circuit_id = circuit_chain_lookup(call_info, vc);
    circuit_t *subcircuit;
    h223_vc_info *vc_info;
    subcircuit = find_circuit( CT_H223, circuit_id, start_frame );

    if( subcircuit == NULL ) {
        subcircuit = circuit_new( CT_H223, circuit_id, start_frame );
#ifdef DEBUG_H223
        g_debug("%d: Created new circuit %d for call %p VC %d", start_frame, circuit_id, call_info, vc);
#endif
        vc_info = h223_vc_info_new( call_info );
        circuit_add_proto_data( subcircuit, proto_h223, vc_info );
    } else {
        vc_info = circuit_get_proto_data( subcircuit, proto_h223 );
    }
    add_h223_lc_params( vc_info, direction, params, start_frame );
}

/* create a brand-new h223_call_info structure */
static h223_call_info *
create_call_info( guint32 start_frame )
{
    h223_call_info *datax;
    h223_lc_params *vc0_params;

    datax = se_alloc(sizeof(h223_call_info));

    /* initialise the call info */
    init_direction_data(&datax -> direction_data[0]);
    init_direction_data(&datax -> direction_data[1]);

    /* FIXME shouldn't this be figured out dynamically? */
    datax -> h223_level = 2;

    vc0_params = se_alloc(sizeof(h223_lc_params));
    vc0_params->al_type = al1Framed;
    vc0_params->al_params = NULL;
    vc0_params->segmentable = TRUE;
    vc0_params->subdissector = srp_handle;
    init_logical_channel( start_frame, datax, 0, P2P_DIR_SENT, vc0_params );
    init_logical_channel( start_frame, datax, 0, P2P_DIR_RECV, vc0_params );
    return datax;
}

/* find or create call_info struct for calls over circuits (eg, IAX) */
static h223_call_info *
find_or_create_call_info_circ(packet_info * pinfo)
{
    h223_call_info *datax;
    circuit_t *circ = NULL;

    if(pinfo->ctype != CT_NONE)
        circ = find_circuit( pinfo->ctype, pinfo->circuit_id, pinfo->fd->num );
    if(circ == NULL)
        return NULL;

    datax = (h223_call_info *)circuit_get_proto_data(circ, proto_h223);

    if( datax == NULL ) {
        datax = create_call_info(pinfo->fd->num);

#ifdef DEBUG_H223
        g_debug("%u: Created new call %p for circuit %p ctype %d, id %u",
                pinfo->fd->num, datax, circ, pinfo->ctype, pinfo->circuit_id);
#endif
        circuit_add_proto_data(circ, proto_h223, datax);
    }

    /* work out what direction we're really going in */
    if( pinfo->p2p_dir < 0 || pinfo->p2p_dir > 1)
        pinfo->p2p_dir = P2P_DIR_SENT;

    return datax;
}

/* find or create call_info struct for calls over conversations (eg, RTP) */
static h223_call_info *
find_or_create_call_info_conv(packet_info * pinfo)
{
    h223_call_info *datax;
    conversation_t *conv;

    /* assume we're running atop TCP or RTP; use the conversation support */
    conv = find_conversation( pinfo->fd->num,
                              &pinfo->src,&pinfo->dst,
                              pinfo->ptype,
                              pinfo->srcport,pinfo->destport, 0 );

    /* both RTP and TCP track their conversations, so just assert here if
     * we can't find one */
    DISSECTOR_ASSERT(conv);

    datax = (h223_call_info *)conversation_get_proto_data(conv, proto_h223);

    if(datax == NULL && pinfo->ptype == PT_UDP ) {
        conversation_t *conv2;

        /* RTP tracks the two sides of the conversation totally separately;
         * this messes us up totally.
         *
         * Look for another converstation, going in the opposite direction.
         */
        conv2 = find_conversation( pinfo->fd->num,
                                  &pinfo->dst,&pinfo->src,
                                  pinfo->ptype,
                                  pinfo->destport,pinfo->srcport, 0 );
        if(conv2 != NULL)
            datax = (h223_call_info *)conversation_get_proto_data(conv2, proto_h223);

        if(datax != NULL) {
#ifdef DEBUG_H223
            g_debug("%u: Identified conv %p as reverse of conv %p with call %p and type=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u",
                    pinfo->fd->num, conv, conv2, datax, pinfo->ptype,
                    pinfo->dst.data[0], pinfo->dst.data[1], pinfo->dst.data[2], pinfo->dst.data[3],
                    pinfo->destport,
                    pinfo->src.data[0], pinfo->src.data[1], pinfo->src.data[2], pinfo->src.data[3],
                    pinfo->srcport);
#endif
            conversation_add_proto_data(conv, proto_h223, datax);
        }
    }

    /* we still haven't found any call data - create a new one for this
     * conversation */
    if(datax == NULL) {
        datax = create_call_info(pinfo->fd->num);

#ifdef DEBUG_H223
        g_debug("%u: Created new call %p for conv %p type=%u src=%u.%u.%u.%u:%u dst=%u.%u.%u.%u:%u",
                pinfo->fd->num, datax, conv, pinfo->ptype,
                pinfo->src.data[0], pinfo->src.data[1], pinfo->src.data[2], pinfo->src.data[3],
                pinfo->srcport,
                pinfo->dst.data[0], pinfo->dst.data[1], pinfo->dst.data[2], pinfo->dst.data[3],
                pinfo->destport);
#endif

        conversation_add_proto_data(conv, proto_h223, datax);
        /* add the source details so we can distinguish directions
         * in future */
        COPY_ADDRESS(&(datax -> srcaddress), &(pinfo->src));
        datax -> srcport = pinfo->srcport;
    }

    /* work out what direction we're really going in */
    if( ADDRESSES_EQUAL( &(pinfo->src), &(datax->srcaddress))
        && pinfo->srcport == datax->srcport )
        pinfo->p2p_dir = P2P_DIR_SENT;
    else
        pinfo->p2p_dir = P2P_DIR_RECV;

    return datax;
}

static h223_call_info *
find_or_create_call_info ( packet_info * pinfo )
{
    h223_call_info *datax;

    datax = find_or_create_call_info_circ(pinfo);
    if(datax == NULL)
        datax = find_or_create_call_info_conv(pinfo);
    return datax;
}

/* called from the h245 dissector to handle a MultiplexEntrySend message */
static void
h223_set_mc( packet_info* pinfo, guint8 mc, h223_mux_element* me )
{
    circuit_t *circ = find_circuit( pinfo->ctype, pinfo->circuit_id, pinfo->fd->num );
    h223_vc_info* vc_info;

    /* if this h245 pdu packet came from an h223 circuit, add the details on
     * the new mux entry */
    if(circ) {
        vc_info = circuit_get_proto_data(circ, proto_h223);
        add_h223_mux_element( &(vc_info->call_info->direction_data[pinfo->p2p_dir ? 0 : 1]), mc, me, pinfo->fd->num );
    }
}

/* called from the h245 dissector to handle an OpenLogicalChannelAck message */
static void
h223_add_lc( packet_info* pinfo, guint16 lc, h223_lc_params* params )
{
    circuit_t *circ = find_circuit( pinfo->ctype, pinfo->circuit_id, pinfo->fd->num );
    h223_vc_info* vc_info;

    /* if this h245 pdu packet came from an h223 circuit, add the details on
     * the new channel */
    if(circ) {
        vc_info = circuit_get_proto_data(circ, proto_h223);
        init_logical_channel( pinfo->fd->num, vc_info->call_info, lc, pinfo->p2p_dir, params );
    }
}

/************************************************************************************
 *
 * AL-PDU dissection
 */

static const guint8 crctable[256] = {
    0x00, 0x91, 0xe3, 0x72, 0x07, 0x96, 0xe4, 0x75, 0x0e, 0x9f, 0xed, 0x7c, 0x09, 0x98, 0xea, 0x7b,
    0x1c, 0x8d, 0xff, 0x6e, 0x1b, 0x8a, 0xf8, 0x69, 0x12, 0x83, 0xf1, 0x60, 0x15, 0x84, 0xf6, 0x67,
    0x38, 0xa9, 0xdb, 0x4a, 0x3f, 0xae, 0xdc, 0x4d, 0x36, 0xa7, 0xd5, 0x44, 0x31, 0xa0, 0xd2, 0x43,
    0x24, 0xb5, 0xc7, 0x56, 0x23, 0xb2, 0xc0, 0x51, 0x2a, 0xbb, 0xc9, 0x58, 0x2d, 0xbc, 0xce, 0x5f,
    0x70, 0xe1, 0x93, 0x02, 0x77, 0xe6, 0x94, 0x05, 0x7e, 0xef, 0x9d, 0x0c, 0x79, 0xe8, 0x9a, 0x0b,
    0x6c, 0xfd, 0x8f, 0x1e, 0x6b, 0xfa, 0x88, 0x19, 0x62, 0xf3, 0x81, 0x10, 0x65, 0xf4, 0x86, 0x17,
    0x48, 0xd9, 0xab, 0x3a, 0x4f, 0xde, 0xac, 0x3d, 0x46, 0xd7, 0xa5, 0x34, 0x41, 0xd0, 0xa2, 0x33,
    0x54, 0xc5, 0xb7, 0x26, 0x53, 0xc2, 0xb0, 0x21, 0x5a, 0xcb, 0xb9, 0x28, 0x5d, 0xcc, 0xbe, 0x2f,
    0xe0, 0x71, 0x03, 0x92, 0xe7, 0x76, 0x04, 0x95, 0xee, 0x7f, 0x0d, 0x9c, 0xe9, 0x78, 0x0a, 0x9b,
    0xfc, 0x6d, 0x1f, 0x8e, 0xfb, 0x6a, 0x18, 0x89, 0xf2, 0x63, 0x11, 0x80, 0xf5, 0x64, 0x16, 0x87,
    0xd8, 0x49, 0x3b, 0xaa, 0xdf, 0x4e, 0x3c, 0xad, 0xd6, 0x47, 0x35, 0xa4, 0xd1, 0x40, 0x32, 0xa3,
    0xc4, 0x55, 0x27, 0xb6, 0xc3, 0x52, 0x20, 0xb1, 0xca, 0x5b, 0x29, 0xb8, 0xcd, 0x5c, 0x2e, 0xbf,
    0x90, 0x01, 0x73, 0xe2, 0x97, 0x06, 0x74, 0xe5, 0x9e, 0x0f, 0x7d, 0xec, 0x99, 0x08, 0x7a, 0xeb,
    0x8c, 0x1d, 0x6f, 0xfe, 0x8b, 0x1a, 0x68, 0xf9, 0x82, 0x13, 0x61, 0xf0, 0x85, 0x14, 0x66, 0xf7,
    0xa8, 0x39, 0x4b, 0xda, 0xaf, 0x3e, 0x4c, 0xdd, 0xa6, 0x37, 0x45, 0xd4, 0xa1, 0x30, 0x42, 0xd3,
    0xb4, 0x25, 0x57, 0xc6, 0xb3, 0x22, 0x50, 0xc1, 0xba, 0x2b, 0x59, 0xc8, 0xbd, 0x2c, 0x5e, 0xcf };

static guint8 h223_al2_crc8bit( tvbuff_t *tvb ) {
    guint32 len = tvb_reported_length(tvb) - 1;
    const guint8* datax = tvb_get_ptr( tvb, 0, len );
    unsigned char crc = 0;
    guint32 pos = 0;
    DISSECTOR_ASSERT(tvb_reported_length(tvb) >= 1);
    while ( len-- )
        crc = crctable[crc^datax[pos++]];
    return crc;
}

static void
dissect_mux_al_pdu( tvbuff_t *tvb, packet_info *pinfo, proto_tree *vc_tree,
/*                  circuit_t* vc_circuit, */
                    h223_lc_params* lc_params )
{
    proto_tree *al_tree = NULL;
    proto_item *al_item, *hidden_item;
    proto_tree *al_subtree;
    proto_item *al_subitem = NULL;
    proto_item *tmp_item;
    tvbuff_t *next_tvb = NULL;
    dissector_handle_t subdissector = lc_params->subdissector;
    guint32 len = tvb_reported_length(tvb);

    guint8 calc_checksum;
    guint8 real_checksum;
    gboolean al2_sequenced = FALSE;
    int data_start;

    switch( lc_params->al_type ) {
        case al1Framed:
        case al1NotFramed:
            al_item = proto_tree_add_none_format(vc_tree, hf_h223_al1, tvb, 0, -1, "H.223 AL1 (%sframed)",
                                                 (lc_params->al_type==al1Framed)?"":"not ");
            al_tree = proto_item_add_subtree (al_item, ett_h223_al1);
            if(lc_params->al_type == al1Framed) {
                hidden_item = proto_tree_add_boolean(al_tree, hf_h223_al1_framed, tvb, 0, 1, TRUE );
                PROTO_ITEM_SET_HIDDEN(hidden_item);
            }
            next_tvb = tvb;
            al_subitem = proto_tree_add_item(al_tree, hf_h223_al_payload, next_tvb, 0, -1, ENC_NA);
            break;

        case al2WithSequenceNumbers:
            al2_sequenced = TRUE;
            /* fall-through */
        case al2WithoutSequenceNumbers:
            tmp_item = proto_tree_add_boolean(vc_tree, hf_h223_al2, tvb, 0, 0, TRUE );

            al_item = proto_tree_add_item(vc_tree,
                                          al2_sequenced?hf_h223_al2_sequenced:hf_h223_al2_unsequenced,
                                          tvb, 0, -1, ENC_NA);
            al_tree = proto_item_add_subtree (al_item, ett_h223_al2);

            PROTO_ITEM_SET_GENERATED(tmp_item);

            /* check minimum payload length */
            if(len < (al2_sequenced?2U:1U))
                THROW(BoundsError);

            data_start = 0;
            if( al2_sequenced ) {
                proto_tree_add_item(al_tree, hf_h223_al2_seqno, tvb, 0, 1, ENC_LITTLE_ENDIAN);
                data_start++;
            }

            next_tvb = tvb_new_subset( tvb, data_start, len-1-data_start, len-1-data_start );
            al_subitem = proto_tree_add_item(al_tree, hf_h223_al_payload, next_tvb, 0, -1, ENC_NA);

            calc_checksum = h223_al2_crc8bit(tvb);
            real_checksum = tvb_get_guint8(tvb, len - 1);

            if( calc_checksum == real_checksum ) {
                proto_tree_add_uint_format(al_tree, hf_h223_al2_crc, tvb, len - 1, 1, real_checksum,
                                           "CRC: 0x%02x (correct)", real_checksum );
            } else {
                proto_tree_add_uint_format(al_tree, hf_h223_al2_crc, tvb, len - 1, 1, real_checksum,
                                           "CRC: 0x%02x (incorrect, should be 0x%02x)", real_checksum, calc_checksum );
                tmp_item = proto_tree_add_boolean( al_tree, hf_h223_al2_crc_bad, tvb, len - 1, 1, TRUE );
                PROTO_ITEM_SET_GENERATED(tmp_item);

                /* don't pass pdus which fail checksums on to the subdissector */
                subdissector = data_handle;
            }
            break;
        default:
            call_dissector(data_handle, tvb, pinfo, vc_tree);
            return;
    }

    if (!subdissector)
        subdissector = data_handle;

    al_subtree = proto_item_add_subtree(al_subitem, ett_h223_al_payload);
    call_dissector(subdissector, next_tvb, pinfo, al_subtree);
}

/************************************************************************************
 *
 * MUX-PDU dissection
 */


/* dissect a fragment of a MUX-PDU which belongs to a particular VC
 *
 * tvb          buffer containing the MUX-PDU fragment
 * pinfo        info on the packet containing the last fragment of the MUX-PDU
 * pkt_offset   offset within the block from the superdissector where the
 *                fragment starts (must increase monotonically for constant pinfo->fd->num)
 * pdu_tree     dissection tree for the PDU; a single item will be added (with
 *              its own subtree)
 * vc           VC for this SDU
 * end_of_mux_sdu true if this is a segmentable VC and this is the last
 *              fragment in an SDU
 */
static void
dissect_mux_sdu_fragment(tvbuff_t *volatile next_tvb, packet_info *pinfo,
                         guint32 pkt_offset, proto_tree *pdu_tree,
                         h223_call_info* call_info, guint16 vc,
                         gboolean end_of_mux_sdu)
{
    /* update the circuit details before passing to a subdissector */
    guint32 orig_circuit = pinfo->circuit_id;
    guint32 orig_ctype = pinfo->ctype;
    pinfo->circuit_id=circuit_chain_lookup(call_info, vc);
    pinfo->ctype=CT_H223;

    TRY {
        circuit_t *subcircuit=find_circuit(pinfo->ctype,pinfo->circuit_id,pinfo->fd->num);
        proto_tree *vc_tree = NULL;
        proto_item *vc_item;
        h223_vc_info *vc_info = NULL;
        h223_lc_params *lc_params = NULL;

        if(pdu_tree) {
            vc_item = proto_tree_add_uint(pdu_tree, hf_h223_mux_vc, next_tvb, 0, tvb_reported_length(next_tvb), vc);
            vc_tree = proto_item_add_subtree (vc_item, ett_h223_mux_vc);
        }

        if( subcircuit == NULL ) {
            g_message( "Frame %d: Subcircuit id %d not found for call %p VC %d", pinfo->fd->num,
                       pinfo->circuit_id, (void *)call_info, vc );
        } else {
            vc_info = circuit_get_proto_data(subcircuit, proto_h223);
            if( vc_info != NULL ) {
                lc_params = find_h223_lc_params( vc_info, pinfo->p2p_dir, pinfo->fd->num );
            }
        }


        if( lc_params != NULL ) {
                if( lc_params->segmentable && lc_params->al_type != al1NotFramed ) {
                    stream_t *substream;
                    stream_pdu_fragment_t *frag;

                    substream = find_stream_circ(subcircuit,pinfo->p2p_dir);
                    if(substream == NULL )
                        substream = stream_new_circ(subcircuit,pinfo->p2p_dir);
                    frag = stream_find_frag(substream,pinfo->fd->num,pkt_offset);

                    if(frag == NULL ) {
#ifdef DEBUG_H223
                        g_debug("%d: New H.223 VC fragment: Parent circuit %d; subcircuit %d; offset %d; len %d, end %d",
                                pinfo->fd->num, orig_circuit, pinfo->circuit_id, pkt_offset, tvb_reported_length(next_tvb), end_of_mux_sdu);
#endif
                        frag = stream_add_frag(substream,pinfo->fd->num,pkt_offset,
                                               next_tvb,pinfo,!end_of_mux_sdu);
                    } else {
#ifdef DEBUG_H223
                        g_debug("%d: Found H.223 VC fragment: Parent circuit %d; subcircuit %d; offset %d; len %d, end %d",
                                pinfo->fd->num, orig_circuit, pinfo->circuit_id, pkt_offset, tvb_reported_length(next_tvb), end_of_mux_sdu);
#endif
                    }

                    next_tvb = stream_process_reassembled(
                        next_tvb, 0, pinfo,
                        "Reassembled H.223 AL-PDU",
                        frag, &h223_al_frag_items,
                        NULL, vc_tree);
                }

                if(next_tvb) {
                    /* fudge to pass pkt_offset down to add_h223_mux_element,
                     * should it be called */
                    pdu_offset = pkt_offset;
                    dissect_mux_al_pdu(next_tvb, pinfo, vc_tree,/* subcircuit,*/ lc_params );
                }
        } else {
            call_dissector(data_handle,next_tvb,pinfo,vc_tree);
        }
    }

    /* restore the original circuit details for future PDUs */
    FINALLY {
        pinfo->ctype=orig_ctype;
        pinfo->circuit_id=orig_circuit;
    }
    ENDTRY;
}

static guint32
mux_element_sublist_size( h223_mux_element* me )
{
    h223_mux_element *current_me = me->next;
    guint32 length = 0;
    while ( current_me ) {
        if ( current_me->sublist )
            length += current_me->repeat_count * mux_element_sublist_size( current_me->sublist );
        else
            length += current_me->repeat_count;
        current_me = current_me->next;
    }
    if ( length == 0 ) { /* should never happen, but to avoid infinite loops... */
        DISSECTOR_ASSERT_NOT_REACHED();
        length = 1;
    }
    return length;
}

/* dissect part of a MUX-PDU payload according to a multiplex list
 *
 * tvb          buffer containing entire mux-pdu payload
 * pinfo        info on the packet containing the last fragment of the MUX-PDU
 * pkt_offset   offset within the block from the superdissector where the
 *                MUX-PDU starts (must increase monotonically for constant
 *                pinfo->fd->num)
 * pdu_tree     dissection tree for the PDU
 * call_info    data structure for h223 call
 * me           top of mux list
 * offset       offset within tvb to start work
 * endOfMuxSdu  true if the end-of-sdu flag was set
 */
static guint32
dissect_mux_payload_by_me_list( tvbuff_t *tvb, packet_info *pinfo,
                                guint32 pkt_offset, proto_tree *pdu_tree,
                                h223_call_info* call_info,
                                h223_mux_element *me, guint32 offset,
                                gboolean endOfMuxSdu )
{
    guint32 len = tvb_reported_length(tvb);
    guint32 frag_len;
    guint32 sublist_len;
    int i;
    while ( me ) {
        if ( me->sublist ) {
            if ( me->repeat_count == 0 ) {
                for(sublist_len = mux_element_sublist_size( me->sublist );
                    offset + sublist_len <= len;
                    offset = dissect_mux_payload_by_me_list( tvb, pinfo, pkt_offset, pdu_tree,
                                                             call_info, me->sublist, offset, endOfMuxSdu ) );
            } else {
                for(i = 0; i < me->repeat_count; ++i)
                    offset = dissect_mux_payload_by_me_list( tvb, pinfo, pkt_offset, pdu_tree,
                                                             call_info, me->sublist, offset, endOfMuxSdu );
            }
        } else {
            if ( me->repeat_count == 0 )
                frag_len = len - offset;
            else
                frag_len = me->repeat_count;
            if(frag_len > 0) {
                tvbuff_t *next_tvb;
                next_tvb = tvb_new_subset(tvb, offset, frag_len, frag_len);
                dissect_mux_sdu_fragment( next_tvb, pinfo, pkt_offset + offset, pdu_tree,
                                          call_info, me->vc, (offset+frag_len==len) && endOfMuxSdu);
                offset += frag_len;
            }
        }
        me = me->next;
    }
    return offset;
}

/* dissect the payload of a MUX-PDU
 *
 * tvb          buffer containing entire mux-pdu payload
 * pinfo        info on the packet containing the last fragment of the MUX-PDU
 * pkt_offset   offset within the block from the superdissector where the
 *                MUX-PDU starts (must increase monotonically for constant
 *                pinfo->fd->num)
 * pdu_tree     dissection tree for the PDU
 * call_info    data structure for h223 call
 * mc           multiplex code for this PDU
 * endOfMuxSdu  true if the end-of-sdu flag was set
 */
static void
dissect_mux_payload( tvbuff_t *tvb, packet_info *pinfo, guint32 pkt_offset,
                     proto_tree *pdu_tree, h223_call_info *call_info,
                     guint8 mc, gboolean endOfMuxSdu )
{
    guint32 len = tvb_reported_length(tvb);

    h223_mux_element* me = find_h223_mux_element( &(call_info->direction_data[pinfo->p2p_dir ? 0 : 1]), mc, pinfo->fd->num, pkt_offset );

    if( me ) {
        dissect_mux_payload_by_me_list( tvb, pinfo, pkt_offset, pdu_tree, call_info, me, 0, endOfMuxSdu );
    } else {
        /* no entry found in mux-table. ignore packet and dissect as data */
        proto_tree *vc_tree = NULL;

        if(pdu_tree) {
            proto_item *vc_item = proto_tree_add_item(pdu_tree, hf_h223_mux_deact, tvb, 0, len, ENC_NA);
            vc_tree = proto_item_add_subtree(vc_item, ett_h223_mux_deact);
        }
        call_dissector(data_handle,tvb,pinfo,vc_tree);
    }
}

/* dissect a reassembled mux-pdu
 *
 * tvb          buffer containing mux-pdu, including header and closing flag
 * pinfo        packet info for packet containing the end of the mux-pdu
 * pkt_offset   offset within the block from the superdissector where the
 *                MUX-PDU starts (must increase monotonically for constant
 *                pinfo->fd->num)
 * h223_tree    dissection tree for h223 protocol; a single item will be added
 *              (with a sub-tree)
 * call_info    h223 info structure for this h223 call
 * pdu_no       index of this pdu within the call
 */
static void
dissect_mux_pdu( tvbuff_t *tvb, packet_info *pinfo, guint32 pkt_offset,
                 proto_tree *h223_tree, h223_call_info *call_info)
{
    guint32 offset = 0;
    /* actual (as opposed to reported) payload len */
    guint32 len;
    guint32 raw_hdr = 0, correct_hdr = 0;
    gint32  errors = 0;
    guint16 closing_flag = 0;
    guint8 mc = 0;
    guint8 mpl = 0;
    gboolean end_of_mux_sdu = FALSE;
    tvbuff_t *pdu_tvb;

    proto_item *pdu_item = NULL;
    proto_tree *pdu_tree = NULL;

#ifdef DEBUG_H223_FRAGMENTATION
    g_debug("%u: dissecting complete H.223 MUX-PDU, pkt_offset %u, len %u",
            pinfo->fd->num, pkt_offset, tvb_reported_length(tvb));
#endif

    switch(call_info->h223_level) {
        case 0: case 1:
            raw_hdr = tvb_get_guint8(tvb,0);
            mc = (guint8)((raw_hdr>>1) & 0xf);
            end_of_mux_sdu = raw_hdr & 1;
            offset++;
            /* closing flag is one byte long for h223 level 0, two for level 1 */
            len = mpl = tvb_length_remaining(tvb, offset)-(call_info->h223_level+1);

            /* XXX should ignore pdus with incorrect HECs */
            break;

        case 2:
            raw_hdr = tvb_get_letoh24(tvb,0);
            errors = golay_errors(raw_hdr);
            offset += 3;
            len = tvb_length_remaining(tvb,offset)-2;

            if(errors != -1) {
                correct_hdr = raw_hdr ^ (guint32)errors;

                mc = (guint8)(correct_hdr & 0xf);
                mpl = (guint8)((correct_hdr >> 4) & 0xff);

                /* we should never have been called if there's not enough data in
                 * available. */
                DISSECTOR_ASSERT(len >= mpl);

                closing_flag = tvb_get_ntohs(tvb,offset+len);
                end_of_mux_sdu = (closing_flag==(0xE14D ^ 0xFFFF));
            } else {
                mc = 0;
                mpl = len;
            }
            break;

        case 3:
            /* XXX not implemented */
        default:
            DISSECTOR_ASSERT_NOT_REACHED();
    }


    if( h223_tree ) {
        if( mpl == 0 ) {
            pdu_item = proto_tree_add_item (h223_tree, hf_h223_mux_stuffing_pdu, tvb, 0, -1, ENC_NA);
            pdu_tree = proto_item_add_subtree (pdu_item, ett_h223_mux_stuffing_pdu);
        } else {
            pdu_item = proto_tree_add_item (h223_tree, hf_h223_mux_pdu, tvb, 0, -1, ENC_NA);
            pdu_tree = proto_item_add_subtree (pdu_item, ett_h223_mux_pdu);
        }
    }

    if( pdu_tree ) {
        proto_item *item = proto_tree_add_item (pdu_tree, hf_h223_mux_header, tvb, 0, offset, ENC_NA);
        proto_tree *hdr_tree = proto_item_add_subtree (item, ett_h223_mux_header);

        switch(call_info->h223_level) {
            case 0: case 1:
                proto_tree_add_uint(hdr_tree,hf_h223_mux_mc,tvb,0,1,mc);
                break;

            case 2:
                if( errors == -1 ) {
                    proto_tree_add_uint_format(hdr_tree, hf_h223_mux_rawhdr, tvb,
                                               0, 3, raw_hdr,
                                               "Raw value: 0x%06x (uncorrectable errors)", raw_hdr );
                } else {
                    if( errors == 0 ) {
                        proto_tree_add_uint_format(hdr_tree, hf_h223_mux_rawhdr, tvb,
                                                   0, 3, raw_hdr,
                                                   "Raw value: 0x%06x (correct)", raw_hdr );
                    } else {
                        proto_tree_add_uint_format(hdr_tree, hf_h223_mux_rawhdr, tvb,
                                                   0, 3, raw_hdr,
                                                   "Raw value: 0x%06x (errors are 0x%06x)", raw_hdr, errors );
                    }
                    item = proto_tree_add_uint(hdr_tree,hf_h223_mux_correctedhdr,tvb,0,3,
                                               correct_hdr);
                    PROTO_ITEM_SET_GENERATED(item);
                    proto_tree_add_uint(hdr_tree,hf_h223_mux_mc,tvb,0,1,mc);
                    proto_tree_add_uint(hdr_tree,hf_h223_mux_mpl,tvb,0,2,mpl);
                }
                break;

            case 3:
                /* XXX not implemented */
            default:
                DISSECTOR_ASSERT_NOT_REACHED();
        }
    }

    if(mpl > 0) {
        pdu_tvb = tvb_new_subset(tvb, offset, len, mpl);
        if(errors != -1) {
            dissect_mux_payload(pdu_tvb,pinfo,pkt_offset+offset,pdu_tree,call_info,mc,end_of_mux_sdu);
        } else {
            call_dissector(data_handle,pdu_tvb,pinfo,pdu_tree);
        }
        offset += mpl;
    }

    /* any extra data in the PDU, beyond that indictated by the mpl, is
       dissected as data. */
    len -= mpl;
    if( len > 0 ) {
        tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, len, len);
        proto_tree *vc_tree = NULL;

        if( pdu_tree ) {
            proto_item *vc_item = proto_tree_add_item(pdu_tree, hf_h223_mux_extra, next_tvb, 0, len, ENC_NA);
            vc_tree = proto_item_add_subtree(vc_item, ett_h223_mux_deact);
        }
        call_dissector(data_handle,next_tvb,pinfo,vc_tree);

        offset += len;
    }

    /* add the closing HDLC flag */
    if( pdu_tree )
        proto_tree_add_item(pdu_tree,hf_h223_mux_hdlc2,tvb,offset,2,ENC_BIG_ENDIAN);
}


/************************************************************************************
 *
 * MUX-PDU delineation and defragmentation
 */

/* attempt to parse the header of a mux pdu */
static gboolean
attempt_mux_level0_header_parse(guint32 nbytes _U_, guint32 hdr _U_, guint32 *minlen _U_)
{
    /* level 0 isn't byte-aligned, so is a complete pain to implement */
    DISSECTOR_ASSERT_NOT_REACHED();
    return FALSE;
}

static gboolean
attempt_mux_level1_header_parse(guint32 nbytes, guint32 hdr, guint32 *minlen)
{
    /* this is untested */
    DISSECTOR_ASSERT_NOT_REACHED();

    if(nbytes < 2)
        return FALSE;

    hdr &= 0xffff;
    /* don't interpret a repeated hdlc as a header */
    if(hdr == 0xE14D)
        return FALSE;

    /* + 1 byte of header and 2 bytes of closing HDLC */
    *minlen = (guint8)((hdr >> 12) & 0xff) + 3;
    return TRUE;
}

static gboolean
attempt_mux_level2_3_header_parse(guint32 nbytes, guint32 hdr, guint32 *minlen)
{
    gint32 errors;

    if(nbytes < 3)
        return FALSE;

    /* + 3 bytes of header and 2 bytes of closing HDLC */
    *minlen = 5;

    /* bah, we get the header in the wrong order */
    hdr =
        ((hdr & 0xFF0000) >> 16) |
        (hdr & 0x00FF00) |
        ((hdr & 0x0000FF) << 16);

    errors = golay_errors(hdr);
    if(errors != -1) {
        hdr ^= errors;
        *minlen += ((hdr >> 4) & 0xff);
    }

    return TRUE;
}

static gboolean (* const attempt_mux_header_parse[])(guint32 nbytes, guint32 header_buf, guint32 *minlen) = {
    attempt_mux_level0_header_parse,
    attempt_mux_level1_header_parse,
    attempt_mux_level2_3_header_parse,
    attempt_mux_level2_3_header_parse
};

static gboolean
h223_mux_check_hdlc(int h223_level, guint32 nbytes, guint32 tail_buf)
{
    guint32 masked;

    switch(h223_level) {
        case 0:
            /* level 0 isn't byte-aligned, so is a complete pain to implement */
            DISSECTOR_ASSERT_NOT_REACHED();
            return FALSE;

        case 1:
            masked = tail_buf & 0xffff;
            return nbytes >= 2 && masked == 0xE14D;

        case 2: case 3:
            masked = tail_buf & 0xffff;
            return nbytes >= 2 && (masked == 0xE14D || masked == (0xE14D ^ 0xFFFF));

        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            return FALSE;
    }
}

/* read a pdu (or the start of a pdu) from the tvb, and dissect it
 *
 * returns the number of bytes processed, or the negative of the number of
 * extra bytes needed, or zero if we don't know yet
 */

static gint
dissect_mux_pdu_fragment( tvbuff_t *tvb, guint32 start_offset,
                          packet_info *pinfo, proto_tree *h223_tree,
                          h223_call_info *call_info)
{
    tvbuff_t *volatile next_tvb;
    volatile guint32 offset = start_offset;
    gboolean more_frags = TRUE;

    gboolean header_parsed = FALSE;
    guint32 header_buf = 0, tail_buf = 0;
    guint32 pdu_minlen = 0;
    void *pd_save;


#ifdef DEBUG_H223_FRAGMENTATION
    g_debug("%d: dissecting H.223 PDU, start_offset %u, %u bytes left",
            pinfo->fd->num,start_offset, tvb_reported_length_remaining( tvb, start_offset ));
#endif

    while( more_frags && offset < tvb_reported_length( tvb )) {
        guint8 byte = tvb_get_guint8(tvb, offset++);

        /* read a byte into the header buf, if necessary */
        if((offset-start_offset) <= 4) {
            header_buf <<= 8;
            header_buf |= byte;
        }

        /* read the byte into the tail buf */
        tail_buf <<= 8;
        tail_buf |= byte;

        /* if we haven't parsed the header yet, attempt to do so now */
        if(!header_parsed)
            /* this sets current_pdu_header parsed if current_pdu_read == 3 */
            header_parsed = (attempt_mux_header_parse[call_info->h223_level])
                (offset-start_offset,header_buf,&pdu_minlen);

        /* if we have successfully parsed the header, we have sufficient data,
         * and we have found the closing hdlc, we are done here */
        if(header_parsed && (offset-start_offset) >= pdu_minlen) {
            if(h223_mux_check_hdlc(call_info->h223_level,offset-start_offset,tail_buf)) {
                more_frags = FALSE;
            }
        }
    }

    if( more_frags ) {
        if(pdu_minlen <= (offset-start_offset)) {
            /* we haven't found the closing hdlc yet, but we don't know how
             * much more we need */
#ifdef DEBUG_H223_FRAGMENTATION
            g_debug("\tBailing, requesting more bytes");
#endif
            return 0;
        } else {
            guint32 needed = pdu_minlen-(offset-start_offset);
#ifdef DEBUG_H223_FRAGMENTATION
            g_debug("\tBailing, requesting %i-%i=%u more bytes", pdu_minlen,(offset-start_offset),needed);
#endif
            return - (gint) needed;
        }
    }

    /* create a tvb for the fragment */
    next_tvb = tvb_new_subset(tvb, start_offset, offset-start_offset,
                              offset-start_offset);


    /* we catch boundserrors on the pdu so that errors on an
     * individual pdu don't screw up the whole of the rest of the
     * stream */
    pd_save = pinfo->private_data;
    TRY {
        dissect_mux_pdu( next_tvb, pinfo, start_offset, h223_tree, call_info);
    }

    CATCH2(BoundsError,ReportedBoundsError) {
        /*  Restore the private_data structure in case one of the
         *  called dissectors modified it (and, due to the exception,
         *  was unable to restore it).
         */
        pinfo->private_data = pd_save;

        col_append_str(pinfo->cinfo, COL_INFO, "[Malformed Packet]");
        proto_tree_add_protocol_format(h223_tree, proto_malformed,
                                       tvb, 0, 0, "[Malformed Packet: %s]",
                                       pinfo->current_proto);
    }

    ENDTRY;

    return (offset-start_offset);
}

/************************************************************************************
 *
 * main dissector entry points
 */

/* dissects PDUs from the tvb
 *
 * Updates desegment_offset and desegment_len if the end of the data didn't
 * line up with the end of a pdu.
 */
static void
dissect_h223 (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    proto_tree *h223_tree = NULL;
    proto_item *h223_item = NULL;
    h223_call_info *call_info = NULL;
    guint32 offset = 0;

    /* set up the protocol and info fields in the summary pane */
    col_set_str (pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_H223);

    col_clear(pinfo->cinfo, COL_INFO);

    /* find or create the call_info for this call */
    call_info = find_or_create_call_info(pinfo);

    /* add the 'h223' tree to the main tree */
    if (tree) {
        h223_item = proto_tree_add_item (tree, proto_h223, tvb, 0, -1, ENC_NA);
        h223_tree = proto_item_add_subtree (h223_item, ett_h223);
    }

    while( offset < tvb_reported_length( tvb )) {
        int res = dissect_mux_pdu_fragment( tvb, offset, pinfo,
                                            h223_tree, call_info);
        if(res <= 0) {
            /* the end of the tvb held the start of a PDU */
            pinfo->desegment_offset = offset;

            /* if res != 0, we actually know how much more data we need for a
             * PDU.
             *
             * However, if we return that, it means that we get called twice
             * for the next packet; this makes it hard to tell how far throught
             * the stream we are and we have to start messing about with
             * getting the seqno from the superdissector's private data. So we
             * don't do that.
             *
             * pinfo->desegment_len = (res == 0 ? DESEGMENT_ONE_MORE_SEGMENT : -res);
             */
            pinfo -> desegment_len = DESEGMENT_ONE_MORE_SEGMENT;

            if(h223_item) {
                /* shrink the h223 protocol item such that it only includes the
                 * bits we dissected */
                proto_item_set_len(h223_item,offset);
            }

            if(offset == 0) {
                col_set_str(pinfo->cinfo, COL_INFO, "(No complete PDUs)");
            }
            return;
        }
        offset += res;
    }
}

/* H.223 specifies that the least-significant bit is transmitted first;
 * however this is at odds with IAX which transmits bytes with the
 * first-received bit as the MSB.
 *
 * This dissector swaps the ordering of the bits in each byte before using the
 * normal entry point.
 */
static void
dissect_h223_bitswapped (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
    tvbuff_t *reversed_tvb;
    guint8 *datax;
    guint len;
    guint i;

    len = tvb_length(tvb);
    datax = g_malloc(len);
    for( i=0; i<len; i++)
        datax[i]=BIT_SWAP(tvb_get_guint8(tvb,i));

    /*
     * Add the reversed tvbuff to the list of tvbuffs to which
     * the tvbuff we were handed refers, so it'll get
     * cleaned up when that tvbuff is cleaned up.
     */
    reversed_tvb = tvb_new_child_real_data(tvb, datax,len,tvb_reported_length(tvb));

    /* Add a freer */
    tvb_set_free_cb(reversed_tvb, g_free);

    /* Add the reversed data to the data source list. */
    add_new_data_source(pinfo, reversed_tvb, "Bit-swapped H.223 frame" );

    dissect_h223(reversed_tvb,pinfo,tree);
}

/******************************************************************************/

static void
h223_init_protocol (void)
{
    circuit_chain_init();
}


void proto_register_h223 (void)
{
    /* A header field is something you can search/filter on.
     *
     * We create a structure to register our fields. It consists of an
     * array of hf_register_info structures, each of which are of the format
     * {&(field id), {name, abbrev, type, display, strings, bitmask, blurb, HFILL}}.
     */

    static hf_register_info hf[] = {
        { &hf_h223_non_h223_data,
          { "Non-H.223 data", "h223.non-h223", FT_NONE, BASE_NONE, NULL, 0x0,
            "Initial data in stream, not a PDU", HFILL }},

        { &hf_h223_mux_stuffing_pdu,
          { "H.223 stuffing PDU", "h223.mux.stuffing", FT_NONE, BASE_NONE, NULL, 0x0,
            "Empty PDU used for stuffing when no data available", HFILL }},

        { &hf_h223_mux_pdu,
          { "H.223 MUX-PDU", "h223.mux", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_mux_header,
          { "Header", "h223.mux.header", FT_NONE, BASE_NONE, NULL, 0x0,
            "H.223 MUX header", HFILL }},

        { &hf_h223_mux_rawhdr,
          { "Raw value", "h223.mux.rawhdr", FT_UINT24, BASE_HEX, NULL, 0x0,
            "Raw header bytes", HFILL }},

        { &hf_h223_mux_correctedhdr,
          { "Corrected value", "h223.mux.correctedhdr", FT_UINT24, BASE_HEX, NULL, 0x0,
            "Corrected header bytes", HFILL }},

        { &hf_h223_mux_mc,
          { "Multiplex Code", "h223.mux.mc", FT_UINT8, BASE_DEC, NULL, 0x0,
            "H.223 MUX multiplex code", HFILL }},

        { &hf_h223_mux_mpl,
          { "Multiplex Payload Length", "h223.mux.mpl", FT_UINT8, BASE_DEC, NULL, 0x0,
            "H.223 MUX multiplex Payload Length", HFILL }},

        { &hf_h223_mux_deact,
          { "Deactivated multiplex table entry", "h223.mux.deactivated", FT_NONE, BASE_NONE, NULL, 0x0,
            "mpl refers to an entry in the multiplex table which is not active", HFILL }},

        { &hf_h223_mux_vc,
          { "H.223 virtual circuit", "h223.mux.vc", FT_UINT16, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_mux_extra,
          { "Extraneous data", "h223.mux.extra", FT_NONE, BASE_NONE, NULL, 0x0,
            "data beyond mpl", HFILL }},

        { &hf_h223_mux_hdlc2,
          { "HDLC flag", "h223.mux.hdlc", FT_UINT16, BASE_HEX, NULL, 0x0,
            "framing flag", HFILL }},

        /* fields for h.223-mux fragments */
        { &hf_h223_mux_fragment_overlap,
          { "Fragment overlap", "h223.mux.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }},

        { &hf_h223_mux_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap",     "h223.mux.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},

        { &hf_h223_mux_fragment_multiple_tails,
          { "Multiple tail fragments found",    "h223.mux.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},

        { &hf_h223_mux_fragment_too_long_fragment,
          { "Fragment too long",        "h223.mux.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},

        { &hf_h223_mux_fragment_error,
          { "Defragmentation error", "h223.mux.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }},

        { &hf_h223_mux_fragment_count,
          { "Fragment count", "h223.mux.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_mux_fragment,
          { "H.223 MUX-PDU Fragment", "h223.mux.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_mux_fragments,
          { "H.223 MUX-PDU Fragments", "h223.mux.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_mux_reassembled_in,
          { "MUX-PDU fragment, reassembled in frame", "h223.mux.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This H.223 MUX-PDU packet is reassembled in this frame", HFILL }},

        { &hf_h223_mux_reassembled_length,
          { "Reassembled H.223 MUX-PDU length", "h223.mux.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},

        /* fields for h.223-al fragments */
        { &hf_h223_al_fragment_overlap,
          { "Fragment overlap", "h223.al.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment overlaps with other fragments", HFILL }},

        { &hf_h223_al_fragment_overlap_conflict,
          { "Conflicting data in fragment overlap",     "h223.al.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Overlapping fragments contained conflicting data", HFILL }},

        { &hf_h223_al_fragment_multiple_tails,
          { "Multiple tail fragments found",    "h223.al.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Several tails were found when defragmenting the packet", HFILL }},

        { &hf_h223_al_fragment_too_long_fragment,
          { "Fragment too long",        "h223.al.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "Fragment contained data past end of packet", HFILL }},

        { &hf_h223_al_fragment_error,
          { "Defragmentation error", "h223.al.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "Defragmentation error due to illegal fragments", HFILL }},

        { &hf_h223_al_fragment_count,
          { "Fragment count", "h223.al.fragment.count", FT_UINT32, BASE_DEC, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_al_fragment,
          { "H.223 AL-PDU Fragment", "h223.al.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_al_fragments,
          { "H.223 AL-PDU Fragments", "h223.al.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_al_reassembled_in,
          { "AL-PDU fragment, reassembled in frame", "h223.al.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
            "This H.223 AL-PDU packet is reassembled in this frame", HFILL }},

        { &hf_h223_al_reassembled_length,
          { "Reassembled H.223 AL-PDU length", "h223.al.reassembled.length", FT_UINT32, BASE_DEC, NULL, 0x0,
            "The total length of the reassembled payload", HFILL }},

        /* h223-als */

        { &hf_h223_al1,
          { "H.223 AL1", "h223.al1", FT_NONE, BASE_NONE, NULL, 0x0,
            "H.223 AL-PDU using AL1", HFILL }},

        { &hf_h223_al1_framed,
          { "H.223 AL1 framing", "h223.al1.framed", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_al2,
          { "H.223 AL2", "h223.al2", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            "H.223 AL-PDU using AL2", HFILL }},

        { &hf_h223_al2_sequenced,
          { "H.223 sequenced AL2", "h223.sequenced_al2", FT_NONE, BASE_NONE, NULL, 0x0,
            "H.223 AL-PDU using AL2 with sequence numbers", HFILL }},

        { &hf_h223_al2_unsequenced,
          { "H.223 unsequenced AL2", "h223.unsequenced_al2", FT_NONE, BASE_NONE, NULL, 0x0,
            "H.223 AL-PDU using AL2 without sequence numbers", HFILL }},

        { &hf_h223_al2_seqno,
          { "Sequence Number", "h223.al2.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
            "H.223 AL2 sequence number", HFILL }},

        { &hf_h223_al2_crc,
          { "CRC", "h223.al2.crc", FT_UINT8, BASE_HEX, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_al2_crc_bad,
          { "Bad CRC","h223.al2.crc_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
            NULL, HFILL }},

        { &hf_h223_al_payload,
          { "H.223 AL Payload", "h223.al.payload", FT_NONE, BASE_NONE, NULL, 0x0,
            "H.223 AL-PDU Payload", HFILL }},

    };

    static gint *ett[] = {
        &ett_h223,
        &ett_h223_non_h223_data,
        &ett_h223_mux_stuffing_pdu,
        &ett_h223_mux_pdu,
        &ett_h223_mux_header,
        &ett_h223_mux_deact,
        &ett_h223_mux_vc,
        &ett_h223_mux_extra,
        &ett_h223_mux_fragments,
        &ett_h223_mux_fragment,
        &ett_h223_al_fragments,
        &ett_h223_al_fragment,
        &ett_h223_al1,
        &ett_h223_al2,
        &ett_h223_al_payload
    };

    proto_h223 =
        proto_register_protocol ("ITU-T Recommendation H.223", "H.223", "h223");

    proto_register_field_array (proto_h223, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_dissector("h223", dissect_h223, proto_h223);
    register_dissector("h223_bitswapped", dissect_h223_bitswapped, proto_h223);

    /* register our init routine to be called at the start of a capture,
       to clear out our hash tables etc */
    register_init_routine(&h223_init_protocol);

    h245_set_h223_set_mc_handle( &h223_set_mc );
    h245_set_h223_add_lc_handle( &h223_add_lc );
}

void proto_reg_handoff_h223(void)
{
    dissector_handle_t h223_bitswapped = find_dissector("h223_bitswapped");
    dissector_handle_t h223 = find_dissector("h223");
    data_handle = find_dissector("data");
    srp_handle = find_dissector("srp");

    dissector_add_handle("tcp.port", h223);
    dissector_add_handle("tcp.port", h223_bitswapped);
    dissector_add_string("rtp_dyn_payload_type","CLEARMODE", h223_bitswapped);
    dissector_add_uint("iax2.dataformat", AST_DATAFORMAT_H223_H245, h223_bitswapped);
}

/*
 * Editor modelines
 *
 * Local Variables:
 * c-basic-offset: 4
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * ex: set shiftwidth=4 tabstop=8 expandtab:
 * :indentSize=4:tabSize=8:noTabs=true:
 */
