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

#include <stdio.h>

#include <gmodule.h>
#include <glib.h>
#include <epan/emem.h>
#include <epan/bitswap.h>
#include <epan/circuit.h>
#include <epan/conversation.h>
#include <epan/packet.h>
#include <epan/stream.h>
#include <epan/reassemble.h>
#include <epan/iax2_codec_type.h>
#include <epan/dissectors/packet-frame.h>
#include <epan/dissectors/packet-h245.h>

#include "packet-h223.h"
#include "golay.h"

#include <string.h>

#define PROTO_TAG_H223	"H223"

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
static int hf_h223_mux_reassembled_in = -1;

static int hf_h223_al_fragments = -1;
static int hf_h223_al_fragment = -1;
static int hf_h223_al_fragment_overlap = -1;
static int hf_h223_al_fragment_overlap_conflict = -1;
static int hf_h223_al_fragment_multiple_tails = -1;
static int hf_h223_al_fragment_too_long_fragment = -1;
static int hf_h223_al_fragment_error = -1;
static int hf_h223_al_reassembled_in = -1;

static int hf_h223_al1 = -1;
static int hf_h223_al1_framed = -1;
static int hf_h223_al2 = -1;
static int hf_h223_al2_sequenced = -1;
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
static dissector_handle_t data_handle=NULL;
static dissector_handle_t srp_handle=NULL;
static dissector_handle_t h245dg_handle=NULL;

static const fragment_items h223_mux_frag_items = {
	&ett_h223_mux_fragment,
	&ett_h223_mux_fragments,
	&hf_h223_mux_fragments,
	&hf_h223_mux_fragment,
	&hf_h223_mux_fragment_overlap,
	&hf_h223_mux_fragment_overlap_conflict,
	&hf_h223_mux_fragment_multiple_tails,
	&hf_h223_mux_fragment_too_long_fragment,
	&hf_h223_mux_fragment_error,
	&hf_h223_mux_reassembled_in,
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
	&hf_h223_al_reassembled_in,
	"fragments"
};

static guint32 pdu_offset; /* offset of the last pdu to start being dissected in the last packet to start being dissected */

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
static gint circuit_chain_equal(gconstpointer v, gconstpointer w)
{
    const circuit_chain_key *v1 = (const circuit_chain_key *)v;
    const circuit_chain_key *v2 = (const circuit_chain_key *)w;
    gint result;
    result = ( v1->call == v2->call &&
	       v1->vc == v2 -> vc );
    return result;;
}

static guint circuit_chain_hash (gconstpointer v)
{
    const circuit_chain_key *key = (const circuit_chain_key *)v;
    guint hash_val = ((guint32)(key->call))^(((guint32)key->vc) << 16);
    return hash_val;
}

static guint32 circuit_chain_lookup(const h223_call_info* call_info,
				    guint32 child_vc)
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

static void circuit_chain_init(void)
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
    gboolean current_pdu_header_parsed;
    
    guint32 current_pdu_minlen;
    guint32 current_pdu_read;
    
    guint32 header_buf;
    guint32 tail_buf;
    
    gboolean first_pdu;
    
    h223_mux_element_listitem* mux_table[16];
} h223_call_direction_data;


struct _h223_call_info {
    /* H.223 specifies that the least-significant bit is transmitted first;
       however this is at odds with IAX which transmits the MSB first, so
       in general, all of our bytes are reversed. */
    gboolean bitswapped;
    
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

static void add_h223_mux_element(h223_call_direction_data *direct, guint8 mc, h223_mux_element *me, guint32 framenum)
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

static h223_mux_element* find_h223_mux_element(h223_call_direction_data* direct, guint8 mc, guint32 framenum)
{
    h223_mux_element_listitem* li;
    
    DISSECTOR_ASSERT(mc < 16);
    
    li = direct->mux_table[mc];
    
    while( li && li->next && li->next->first_frame < framenum )
        li = li->next;
    while( li && li->next && li->next->first_frame == framenum && li->next->pdu_offset < pdu_offset )
        li = li->next;
    if( li ) {
        return li->me;
    } else {
        return NULL;
    }
}

static void add_h223_lc_params(h223_vc_info* vc_info, int direction, h223_lc_params *lc_params, guint32 framenum )
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

static h223_lc_params* find_h223_lc_params(h223_vc_info* vc_info, int direction, guint32 framenum)
{
    h223_lc_params_listitem* li = vc_info->lc_params[direction? 0 : 1];
    while( li && li->next && li->next->first_frame <= framenum )
        li = li->next;
    if( li )
        return li->lc_params;
    else
        return NULL;
}

static void init_direction_data(h223_call_direction_data *direct)
{
    int i;
	h223_mux_element *mc0_element;
    direct -> first_pdu = TRUE;

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

static h223_vc_info* h223_vc_info_new( h223_call_info* call_info )
{
    h223_vc_info *vc_info = se_alloc(sizeof(h223_vc_info));
    vc_info->lc_params[0] = vc_info->lc_params[1] = NULL;
    vc_info->call_info = call_info;
    return vc_info;
}

static void init_logical_channel( packet_info* pinfo, h223_call_info* call_info, int vc, int direction, h223_lc_params* params )
{
    guint32 circuit_id = circuit_chain_lookup(call_info, vc);
    circuit_t *subcircuit;
    h223_vc_info *vc_info;
    subcircuit = find_circuit( CT_H223, circuit_id, pinfo->fd->num );

    if( subcircuit == NULL ) {
        subcircuit = circuit_new( CT_H223, circuit_id, pinfo->fd->num );
        vc_info = h223_vc_info_new( call_info );
        circuit_add_proto_data( subcircuit, proto_h223, vc_info );
    } else {
        vc_info = circuit_get_proto_data( subcircuit, proto_h223 );
    }
    add_h223_lc_params( vc_info, direction, params, pinfo->fd->num );
}

static void init_control_channels( packet_info* pinfo, h223_call_info* call_info )
{
    h223_lc_params *vc0_params = se_alloc(sizeof(h223_lc_params));
    vc0_params->al_type = al1Framed;
    vc0_params->al_params = NULL;
    vc0_params->segmentable = TRUE;
    vc0_params->subdissector = srp_handle;
    init_logical_channel( pinfo, call_info, 0, P2P_DIR_SENT, vc0_params );
    init_logical_channel( pinfo, call_info, 0, P2P_DIR_RECV, vc0_params );
}

static h223_call_info *find_or_create_call_info ( packet_info * pinfo )
{
    circuit_t *circ;
    conversation_t *conv = NULL;
    h223_call_info *data;

    /* look for a circuit (eg, IAX call) first */
    circ = find_circuit( pinfo->ctype, pinfo->circuit_id, pinfo->fd->num );
    if( circ == NULL ) {
	/* assume we're running atop TCP; use the converstion support */
	conv = find_conversation( pinfo->fd->num,
                                  &pinfo->src,&pinfo->dst,
				  pinfo->ptype,
				  pinfo->srcport,pinfo->destport, 0 );
	if( conv == NULL ) {
	    conv = conversation_new( pinfo->fd->num,
                                     &pinfo->src,&pinfo->dst,
				     pinfo->ptype,
				     pinfo->srcport,pinfo->destport, 0 );
	}
	
    }

    if( circ )
	data = (h223_call_info *)circuit_get_proto_data(circ, proto_h223);
    else
	data = (h223_call_info *)conversation_get_proto_data(conv, proto_h223);

    if( data == NULL ) {
	data = se_alloc(sizeof(h223_call_info));

	if( circ ) {
	    circuit_add_proto_data(circ, proto_h223, data);

	    /* circuit-switched H.223 conversations are bitswapped */
	    data -> bitswapped = TRUE;
	} else {
	    conversation_add_proto_data(conv, proto_h223, data);
	    /* add the source details so we can distinguish directions
	     * in future */
	    COPY_ADDRESS(&(data -> srcaddress), &(pinfo->src));
	    data -> srcport = pinfo->srcport;

	    /* packet-switched H.223 conversations are NOT bitswapped */
	    data -> bitswapped = FALSE;
	}

	/* initialise the call info */
        init_direction_data(&data -> direction_data[0]);
        init_direction_data(&data -> direction_data[1]);
        
	/* FIXME shouldn't this be figured out dynamically? */
	data -> h223_level = 2;

        init_control_channels( pinfo, data );
    }

    /* work out what direction we're really going in */
    if( circ ) {
        if( pinfo->p2p_dir < 0 || pinfo->p2p_dir > 1)
            pinfo->p2p_dir = P2P_DIR_SENT;
    } else {
	if( ADDRESSES_EQUAL( &(pinfo->src), &(data->srcaddress))
	    && pinfo->srcport == data->srcport )
	    pinfo->p2p_dir = P2P_DIR_SENT;
	else
	    pinfo->p2p_dir = P2P_DIR_RECV;
    }

    return data;
}

static void h223_set_mc( packet_info* pinfo, guint8 mc, h223_mux_element* me )
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

static void h223_add_lc( packet_info* pinfo, guint16 lc, h223_lc_params* params )
{
    circuit_t *circ = find_circuit( pinfo->ctype, pinfo->circuit_id, pinfo->fd->num );
    h223_vc_info* vc_info;

    /* if this h245 pdu packet came from an h223 circuit, add the details on
     * the new channel */
    if(circ) {
        vc_info = circuit_get_proto_data(circ, proto_h223);
        init_logical_channel( pinfo, vc_info->call_info, lc, pinfo->p2p_dir, params );
    }
}

/************************************************************************************
 *
 * AL-PDU dissection
 */

const guint8 crctable[256] = {
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
    const guint8* data = tvb_get_ptr( tvb, 0, len );
    unsigned char crc = 0;
    guint32 pos = 0;
    while ( len-- )
        crc = crctable[crc^data[pos++]];
    return crc;
}

static void dissect_mux_al_pdu( tvbuff_t *tvb,
                                packet_info *pinfo,
                                proto_tree *vc_tree,
/*                                circuit_t* vc_circuit, */
                                h223_lc_params* lc_params )
{
    proto_tree *al_tree = NULL;
    proto_item *al_item;
    proto_tree *al_subtree;
    proto_item *al_subitem = NULL;
    tvbuff_t *next_tvb = NULL;
    dissector_handle_t subdissector = lc_params->subdissector;
    guint32 len = tvb_reported_length(tvb);
    gboolean all_done = FALSE;

    guint8 calc_checksum;
    guint8 real_checksum;
    gboolean al2_sequenced;

    switch( lc_params->al_type ) {
    case al1Framed:
    case al1NotFramed:
        al_item = proto_tree_add_none_format(vc_tree, hf_h223_al1, tvb, 0, -1, "H.223 AL1 (%sframed)",
                (lc_params->al_type==al1Framed)?"":"not ");
        al_tree = proto_item_add_subtree (al_item, ett_h223_al1);
        if(lc_params->al_type == al1Framed)
            proto_tree_add_boolean_hidden(al_tree, hf_h223_al1_framed, tvb, 0, 1, TRUE );
        next_tvb = tvb;
        break;
    case al2WithoutSequenceNumbers:
    case al2WithSequenceNumbers:
        if( lc_params->al_type == al2WithoutSequenceNumbers ) {
            next_tvb = tvb_new_subset( tvb, 0, len-1, len-1 );
            al2_sequenced = FALSE;
        } else {
            next_tvb = tvb_new_subset( tvb, 1, len-2, len-2 );
            al2_sequenced = TRUE;
        }

        al_item = proto_tree_add_none_format(vc_tree, hf_h223_al2, tvb, 0, -1, "H223 AL2 (with%s sequence numbers)",
                al2_sequenced?"":"out" );
        al_tree = proto_item_add_subtree (al_item, ett_h223_al2);

        if( al2_sequenced ) {
            proto_tree_add_boolean_hidden(al_tree, hf_h223_al2_sequenced, tvb, 0, 1, TRUE );
            proto_tree_add_uint_format(al_tree, hf_h223_al2_seqno, tvb, 0, 1, tvb_get_guint8( tvb, 0 ),
                "Sequence number: %u", tvb_get_guint8( tvb, 0 ) );
        }

        calc_checksum = h223_al2_crc8bit(tvb);
        real_checksum = tvb_get_guint8(tvb, len - 1);
        if( calc_checksum == real_checksum ) {
            al_subitem = proto_tree_add_item(al_tree, hf_h223_al_payload, next_tvb, 0, -1, FALSE);
            proto_tree_add_uint_format(al_tree, hf_h223_al2_crc, tvb, len - 1, 1, real_checksum,
                "CRC: 0x%02x (correct)", real_checksum );
        } else {
            call_dissector(data_handle, tvb, pinfo, al_tree);
            proto_tree_add_boolean_hidden( al_tree, hf_h223_al2_crc_bad, tvb, len - 1, 1, TRUE );
            proto_tree_add_uint_format(al_tree, hf_h223_al2_crc, tvb, len - 1, 1, real_checksum,
                "CRC: 0x%02x (incorrect, should be 0x%02x)", real_checksum, calc_checksum );
            all_done = TRUE;
        }
        break;
    default:
        break;
    }

    if (!subdissector)
        subdissector = data_handle;

    if(next_tvb && al_tree && !al_subitem && !all_done)
        al_subitem = proto_tree_add_item(al_tree, hf_h223_al_payload, next_tvb, 0, -1, FALSE);

    if(next_tvb && al_subitem && !all_done) {
        al_subtree = proto_item_add_subtree(al_subitem, ett_h223_al_payload);
        call_dissector(subdissector, next_tvb, pinfo, al_subtree);
    } else if ( !all_done )
        call_dissector(data_handle, tvb, pinfo, vc_tree);
}

/************************************************************************************
 *
 * MUX-PDU dissection
 */


/* dissect a fragment of a MUX-PDU which belongs to a particular VC
 *
 * tvb	  	buffer containing the whole MUX-PDU
 * offset 	offset within the MUX-PDU of this fragment
 * pinfo	info on the packet containing the last fragment of the MUX-PDU
 * pkt_offset	offset within that packet of the start of the final fragment of
 * 		the MUX_PDU
 * pdu_tree	dissection tree for the PDU; a single item will be added (with
 * 		its own subtree)
 * vc		VC for this SDU
 * frag_len	length of the MUX-SDU fragment
 * end_of_mux_sdu true if this is a segmentable VC and this is the last
 * 		fragment in an SDU
 */
static void dissect_mux_sdu_fragment(tvbuff_t *tvb, guint32 offset,
                                    packet_info *pinfo,
                                    guint32 pkt_offset,
                                    proto_tree *pdu_tree,
                                    h223_call_info* call_info,
                                    guint16 vc, gint frag_len, gboolean end_of_mux_sdu)
{
    /* update the circuit details before passing to a subdissector */
    guint32 orig_circuit = pinfo->circuit_id;
    guint32 orig_ctype = pinfo->ctype;
    pinfo->circuit_id=circuit_chain_lookup(call_info, vc);
    pinfo->ctype=CT_H223;

    TRY {
        tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, frag_len, frag_len);
        circuit_t *subcircuit=find_circuit(pinfo->ctype,pinfo->circuit_id,pinfo->fd->num);
        dissector_handle_t subdissector = NULL;
        proto_tree *vc_tree = NULL;
        proto_item *vc_item;
        h223_vc_info *vc_info = NULL;
        h223_lc_params *lc_params = NULL;
        gboolean stuffing = ( vc == 0 && frag_len == 0 );

        if(pdu_tree && !stuffing) {
            vc_item = proto_tree_add_uint(pdu_tree, hf_h223_mux_vc, next_tvb, 0, frag_len, vc);
            vc_tree = proto_item_add_subtree (vc_item, ett_h223_mux_vc);
        }

        if( stuffing ) {
            next_tvb = NULL;
            subdissector = data_handle;
        } else if( subcircuit == NULL ) {
            g_message( "Frame %d: no subcircuit id %d found for circuit %d id %d, vc %d", pinfo->fd->num,
                       pinfo->circuit_id, orig_ctype, orig_circuit, vc );
            subdissector = data_handle;
        } else {
            vc_info = circuit_get_proto_data(subcircuit, proto_h223);
            if( vc_info != NULL ) {
                lc_params = find_h223_lc_params( vc_info, pinfo->p2p_dir, pinfo->fd->num );
            }
            if( lc_params == NULL ) {
                subdissector = data_handle;
            } else {
                if( lc_params->segmentable && lc_params->al_type != al1NotFramed ) {
                    stream_t *substream;
                    stream_pdu_fragment_t *frag;
                
                    substream = find_stream_circ(subcircuit,pinfo->p2p_dir);
                    if(substream == NULL )
                        substream = stream_new_circ(subcircuit,pinfo->p2p_dir);
                    frag = stream_find_frag(substream,pinfo->fd->num,offset+pkt_offset);
                    if(frag == NULL ) {
                        frag = stream_add_frag(substream,pinfo->fd->num,offset+pkt_offset,
                                               next_tvb,pinfo,!end_of_mux_sdu);
                    }
                    next_tvb = stream_process_reassembled(
                        next_tvb, 0, pinfo, 
                        "Reassembled H.223 AL-PDU",
                        frag, &h223_al_frag_items,
                        NULL, vc_tree);
                }
            }
        }

        if(next_tvb) {
            if(lc_params)
                dissect_mux_al_pdu(next_tvb, pinfo, vc_tree,/* subcircuit,*/ lc_params );
            else
                call_dissector(subdissector,next_tvb,pinfo,vc_tree);
        }
    }

    /* restore the original circuit details for future PDUs */
    FINALLY {
        pinfo->ctype=orig_ctype;
        pinfo->circuit_id=orig_circuit;
    }
    ENDTRY;
}

static guint32 mux_element_sublist_size( h223_mux_element* me )
{
    h223_mux_element *current_me = me;
    guint32 length = 0;
    while ( current_me ) {
	current_me = current_me->next;
	if ( current_me->sublist )
	    length += current_me->repeat_count * mux_element_sublist_size( current_me->sublist );
	else
	    length += current_me->repeat_count;
    }
    if ( length == 0 ) { /* should never happen, but to avoid infinite loops... */
	DISSECTOR_ASSERT_NOT_REACHED();
	length = 1;
    }
    return length;
}

static guint32 dissect_mux_payload_by_me_list( tvbuff_t *tvb, packet_info *pinfo, guint32 pkt_offset, proto_tree *pdu_tree,
                                               h223_call_info* call_info, h223_mux_element* me, guint32 offset, gboolean endOfMuxSdu )
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
	    dissect_mux_sdu_fragment( tvb, offset, pinfo, pkt_offset, pdu_tree,
	                              call_info, me->vc, frag_len, (offset+frag_len==len) && endOfMuxSdu);
	    offset += frag_len;
	}
	me = me->next;
    }
    return offset;
}

/* dissect the payload of a MUX-PDU */
static void dissect_mux_payload( tvbuff_t *tvb, packet_info *pinfo, guint32 pkt_offset, proto_tree *pdu_tree,
                                 h223_call_info* call_info, guint8 mc, gboolean endOfMuxSdu )
{
    guint32 len = tvb_reported_length(tvb);

    h223_mux_element* me = find_h223_mux_element( &(call_info->direction_data[pinfo->p2p_dir ? 0 : 1]), mc, pinfo->fd->num );

    if( me ) {
        dissect_mux_payload_by_me_list( tvb, pinfo, pkt_offset, pdu_tree, call_info, me, 0, endOfMuxSdu );
    } else {
        /* no entry found in mux-table. ignore packet and dissect as data */
        proto_tree *vc_tree = NULL;
            
        if(pdu_tree) {
            proto_item *vc_item = proto_tree_add_item(pdu_tree, hf_h223_mux_deact, tvb, 0, len, FALSE);
            vc_tree = proto_item_add_subtree(vc_item, ett_h223_mux_deact);
        }
        call_dissector(data_handle,tvb,pinfo,vc_tree);
    }
}

/* dissect a reassembled mux-pdu
 *
 * tvb		buffer containing mux-pdu, including header and closing flag
 * pinfo	packet info for packet containing the end of the mux-pdu
 * pkt_offset   offset within that packet of the start of the last fragment
 * h223_tree	dissection tree for h223 protocol; a single item will be added
 * 		(with a sub-tree)
 * call_info	h223 info structure for this h223 call
 * pdu_no	index of this pdu within the call
 */
static void dissect_mux_pdu( tvbuff_t *tvb, packet_info * pinfo,
                             guint32 pkt_offset,
                             proto_tree *h223_tree,
                             h223_call_info *call_info)
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
            correct_hdr = ((errors == -1) ? raw_hdr : raw_hdr ^ (guint32)errors);
    
            mc = (guint8)(correct_hdr & 0xf);
            mpl = (guint8)((correct_hdr >> 4) & 0xff);

            offset += 3;
            len = tvb_length_remaining(tvb,offset)-2;
            closing_flag = tvb_get_ntohs(tvb,offset+len);
            end_of_mux_sdu = (closing_flag==(0xE14D ^ 0xFFFF));
            break;

        case 3:
            /* XXX not implemented */
        default:
            len=0;
            DISSECTOR_ASSERT_NOT_REACHED();
    }

    
    if( h223_tree ) {
	if( mpl == 0 ) {
	    pdu_item = proto_tree_add_item (h223_tree, hf_h223_mux_stuffing_pdu, tvb, 0, -1, FALSE);
	    pdu_tree = proto_item_add_subtree (pdu_item, ett_h223_mux_stuffing_pdu);
	} else {
	    pdu_item = proto_tree_add_item (h223_tree, hf_h223_mux_pdu, tvb, 0, -1, FALSE);
	    pdu_tree = proto_item_add_subtree (pdu_item, ett_h223_mux_pdu);
	}
    }

    if( pdu_tree ) {
        proto_item *item = proto_tree_add_item (pdu_tree, hf_h223_mux_header, tvb, 0, offset, FALSE);
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
                } else if( errors == 0 ) {
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
                break;

            case 3:
                /* XXX not implemented */
            default:
                DISSECTOR_ASSERT_NOT_REACHED();
        }
    }

    pdu_tvb = tvb_new_subset(tvb, offset, len, mpl);
    dissect_mux_payload(pdu_tvb,pinfo,offset+pkt_offset,pdu_tree,call_info,mc,end_of_mux_sdu);
    offset += mpl;

    /* any extra data in the PDU, beyond that indictated by the mpl, is
       dissected as data. */
    len -= mpl;
    if( len > 0 ) {
	tvbuff_t *next_tvb = tvb_new_subset(tvb, offset, len, len);
        proto_tree *vc_tree = NULL;

	if( pdu_tree ) {
	    proto_item *vc_item = proto_tree_add_item(pdu_tree, hf_h223_mux_extra, next_tvb, 0, len, FALSE);
	    vc_tree = proto_item_add_subtree(vc_item, ett_h223_mux_deact);
	}
	call_dissector(data_handle,next_tvb,pinfo,vc_tree);

	offset += len;
    } 

    /* add the closing HDLC flag */
    if( pdu_tree )
	proto_tree_add_item(pdu_tree,hf_h223_mux_hdlc2,tvb,offset,2,FALSE);
}


/************************************************************************************
 *
 * MUX-PDU delineation and defragmentation
 */

/* attempt to parse the header of a mux pdu */
static void attempt_mux_level0_header_parse(h223_call_direction_data *dirdata)
{
    /* level 0 isn't byte-aligned, so is a complete pain to implement */
    DISSECTOR_ASSERT_NOT_REACHED();
    dirdata = dirdata;
}

static void attempt_mux_level1_header_parse(h223_call_direction_data *dirdata)
{
    guint32 hdr;
    
    if(dirdata->current_pdu_read != 2)
        return;

    hdr = dirdata->header_buf & 0xffff;
    /* don't interpret a repeated hdlc as a header */
    if(hdr == 0xE14D)
        return;

    /* + 1 byte of header and 2 bytes of closing HDLC */
    dirdata -> current_pdu_minlen = (guint8)((hdr >> 12) & 0xff) + 3;
    dirdata -> current_pdu_header_parsed = TRUE;
}

static void attempt_mux_level2_3_header_parse(h223_call_direction_data *dirdata)
{
    guint32 hdr;
    gint32 errors;
    
    if(dirdata->current_pdu_read != 3)
        return;

    /* + 3 bytes of header and 2 bytes of closing HDLC */
    dirdata -> current_pdu_minlen = 5;

    hdr = dirdata->header_buf;
    hdr =
        ((hdr & 0xFF0000) >> 16) |
        (hdr & 0x00FF00) |
        ((hdr & 0x0000FF) << 16);
    
    errors = golay_errors(hdr);
    if(errors != -1) {
        hdr ^= errors;
        dirdata -> current_pdu_minlen += ((hdr >> 4) & 0xff);
    }
    
    dirdata -> current_pdu_header_parsed = TRUE;
}

static void (* const attempt_mux_header_parse[])(h223_call_direction_data *dirdata) = {
    attempt_mux_level0_header_parse,
    attempt_mux_level1_header_parse,
    attempt_mux_level2_3_header_parse,
    attempt_mux_level2_3_header_parse
};

static gboolean h223_mux_check_hdlc(int h223_level, h223_call_direction_data *dirdata)
{
    guint32 masked;

    switch(h223_level) {
        case 0:
            /* level 0 isn't byte-aligned, so is a complete pain to implement */
            DISSECTOR_ASSERT_NOT_REACHED();
            return FALSE;
            break;

        case 1:
            masked = dirdata->tail_buf & 0xffff;
            return masked == 0xE14D;

        case 2: case 3:
            masked = dirdata->tail_buf & 0xffff;
            return masked == 0xE14D || masked == (0xE14D ^ 0xFFFF);

        default:
            DISSECTOR_ASSERT_NOT_REACHED();
            return FALSE;
    }
}

/* read a pdu (or the end of a pdu) from the tvb, and dissect it
 *
 * returns an offset to the next byte
 *
 * *pdu_found is set TRUE if a pdu was found, or FALSE if we reached the
 * end of the tvb without completing one.
 */

static guint32 dissect_mux_pdu_fragment( tvbuff_t *tvb, guint32 start_offset, packet_info * pinfo,
					 guint32* pkt_offset,
					 proto_tree *tree,
					 proto_tree **h223_tree_p,
					 h223_call_info *call_info,
					 gboolean *pdu_found)
{
    proto_item *h223_item = NULL;
    proto_tree *volatile h223_tree = *h223_tree_p;
    tvbuff_t *volatile next_tvb;
    volatile guint32 offset = start_offset;
    gboolean more_frags = TRUE;
	proto_tree *pdu_tree;

    h223_call_direction_data *dirdata = &call_info -> direction_data[pinfo->p2p_dir ? 0 : 1];

    dirdata -> current_pdu_read = 0;
    dirdata -> current_pdu_minlen = 0;
    dirdata -> current_pdu_header_parsed = FALSE;

    while( more_frags && offset < tvb_reported_length( tvb )) {
        guint8 byte = tvb_get_guint8(tvb, offset++);
        dirdata -> current_pdu_read++;
        
        /* read a byte into the header buf, if necessary */
        if(dirdata -> current_pdu_read <= 4) {
            dirdata -> header_buf <<= 8;
            dirdata -> header_buf |= byte;
        }

        /* read the byte into the tail buf */
        dirdata -> tail_buf <<= 8;
        dirdata -> tail_buf |= byte;

        /* if we haven't parsed the header yet, attempt to do so now */
        if(!dirdata -> current_pdu_header_parsed)
            /* this sets current_pdu_header parsed if current_pdu_read == 3 */
            (attempt_mux_header_parse[call_info->h223_level])(dirdata);

        if(dirdata -> current_pdu_read >= dirdata -> current_pdu_minlen) {
            if(h223_mux_check_hdlc(call_info->h223_level,dirdata)) {
                dirdata -> current_pdu_minlen = 0;
                dirdata -> current_pdu_read = 0;
                dirdata -> current_pdu_header_parsed = FALSE;
                more_frags = FALSE;
            }
        }
    }

    if( more_frags ) {
        /* offset = tvb_reported length now */
        pinfo->desegment_offset = offset - dirdata->current_pdu_read;
        if(dirdata->current_pdu_read > dirdata->current_pdu_minlen)
            pinfo->desegment_len = 1;
        else
            pinfo->desegment_len = dirdata->current_pdu_minlen - dirdata->current_pdu_read;
        return offset;
    }

    if(!*h223_tree_p) {
        /* add the 'h223' tree to the main tree */
        if (tree) {
            h223_item = proto_tree_add_item (tree, proto_h223, tvb, 0, -1, FALSE);
            h223_tree = proto_item_add_subtree (h223_item, ett_h223);
            *h223_tree_p = h223_tree;
        }
    }
    *pdu_found = TRUE;

    /* create a tvb for the fragment */
    next_tvb = tvb_new_subset(tvb, start_offset, offset-start_offset,
			      offset-start_offset);


    *pkt_offset += tvb_reported_length( next_tvb );

    /* the first PDU isn't real H.223 data. */
    if( dirdata->first_pdu ) {
        dirdata->first_pdu = FALSE;
        pdu_tree = NULL;
        if( h223_tree ) {
            proto_item *pdu_item = proto_tree_add_item (h223_tree, hf_h223_non_h223_data, tvb, 0, -1, FALSE);
            pdu_tree = proto_item_add_subtree (pdu_item, ett_h223_non_h223_data);
        }
        call_dissector(data_handle,tvb, pinfo, pdu_tree);
        return offset;
    }

    /* we catch boundserrors on the pdu so that errors on an
     * individual pdu don't screw up the whole of the rest of the
     * stream */
    pdu_offset = *pkt_offset - tvb_reported_length( next_tvb );
    TRY {
        dissect_mux_pdu( next_tvb, pinfo, *pkt_offset - tvb_reported_length( next_tvb ), h223_tree, call_info);
    }

    CATCH2(BoundsError,ReportedBoundsError) {
        if (check_col(pinfo->cinfo, COL_INFO))
            col_append_str(pinfo->cinfo, COL_INFO,
                           "[Malformed Packet]");
        proto_tree_add_protocol_format(h223_tree, proto_malformed,
                                       tvb, 0, 0, "[Malformed Packet: %s]", pinfo->current_proto);
    }

    ENDTRY;

    return offset;
}

/************************************************************************************
 *
 * main dissector entry point
 */
    
static void dissect_h223 (tvbuff_t * tvb, packet_info * pinfo, proto_tree * tree)
{
    proto_tree *h223_tree = NULL;
    h223_call_info *call_info = NULL;
    guint32 offset = 0;

    /* pkt_offset becomes different from offset if we reassemble a pdu:
     *
     * before: offset = a, pkt_offset = b
     * offset = dissect_h223_mux_pdu_fragment(ending fragment, offset, &pkt_offset)
     * after: offset = a + sizeof(ending frament), pkt_offset = b + sizeof(reassembled pdu)
     *
     * This lets us get a value "pkt_offset + offset_into_pdu" which will never decrease
     * as we walk through a packet
     */
    guint32 pkt_offset = 0;
    gboolean pdu_found = FALSE;

    if (check_col (pinfo->cinfo, COL_INFO))
	col_clear (pinfo->cinfo, COL_INFO);

    
    /* find or create the call_info for this call */
    call_info = find_or_create_call_info(pinfo);

    /* we may need to reverse the bit ordering before we go any further. */
    if( call_info -> bitswapped ) {
	tvbuff_t *reversed_tvb;
	guint8 *data;
	guint len;
	guint i;

	len = tvb_length(tvb);
	data = g_malloc(len);
	for( i=0; i<len; i++)
	    data[i]=BIT_SWAP(tvb_get_guint8(tvb,i));
	    

	reversed_tvb = tvb_new_real_data(data,len,tvb_reported_length(tvb));
	    
	/*
	 * Add the reversed tvbuff to the list of tvbuffs to which
	 * the tvbuff we were handed refers, so it'll get
	 * cleaned up when that tvbuff is cleaned up.
	 */
	tvb_set_child_real_data_tvbuff(tvb, reversed_tvb);


	/* Add a freer */
	tvb_set_free_cb(reversed_tvb, g_free);

	/* Add the reversed data to the data source list. */
	add_new_data_source(pinfo, reversed_tvb, "Bit-swapped H.223 frame" );

	tvb = reversed_tvb;
    }

    while( offset < tvb_reported_length( tvb )) {
	gboolean pdu_found_this_fragment = FALSE;
	offset = dissect_mux_pdu_fragment( tvb, offset, pinfo, &pkt_offset, tree,
					   &h223_tree, call_info,
					   &pdu_found_this_fragment );
	if( pdu_found_this_fragment )
	    pdu_found = TRUE;
    }

    if( !pdu_found && check_col (pinfo->cinfo, COL_INFO))
	col_set_str (pinfo->cinfo, COL_INFO, "(No complete PDUs)");
	
    /* set up the protocol and info fields in the summary pane */
    if (check_col (pinfo->cinfo, COL_PROTOCOL))
	col_set_str (pinfo->cinfo, COL_PROTOCOL, PROTO_TAG_H223);
}

static void h223_init_protocol (void)
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
	    "H.223 MUX-PDU", HFILL }},

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
	    "H.223 Virtual Circuit", HFILL }},
	
	{ &hf_h223_mux_extra,
	  { "Extraneous data", "h223.mux.extra", FT_NONE, BASE_DEC, NULL, 0x0,
	    "data beyond mpl", HFILL }},
	
	{ &hf_h223_mux_hdlc2,
	  { "HDLC flag", "h223.mux.hdlc", FT_UINT16, BASE_HEX, NULL, 0x0,
	    "framing flag", HFILL }},

	/* fields for h.223-mux fragments */
	{ &hf_h223_mux_fragment_overlap,
	  { "Fragment overlap",	"h223.mux.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Fragment overlaps with other fragments", HFILL }},
	
	{ &hf_h223_mux_fragment_overlap_conflict,
	  { "Conflicting data in fragment overlap",	"h223.mux.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Overlapping fragments contained conflicting data", HFILL }},
	
	{ &hf_h223_mux_fragment_multiple_tails,
	  { "Multiple tail fragments found",	"h223.mux.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Several tails were found when defragmenting the packet", HFILL }},
	
	{ &hf_h223_mux_fragment_too_long_fragment,
	  { "Fragment too long",	"h223.mux.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Fragment contained data past end of packet", HFILL }},
	
	{ &hf_h223_mux_fragment_error,
	  { "Defragmentation error", "h223.mux.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "Defragmentation error due to illegal fragments", HFILL }},
	
	{ &hf_h223_mux_fragment,
	  { "H.223 MUX-PDU Fragment", "h223.mux.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "H.223 MUX-PDU Fragment", HFILL }},
	
	{ &hf_h223_mux_fragments,
	  { "H.223 MUX-PDU Fragments", "h223.mux.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
	    "H.223 MUX-PDU Fragments", HFILL }},
	
	{ &hf_h223_mux_reassembled_in,
	  { "MUX-PDU fragment, reassembled in frame", "h223.mux.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "This H.223 MUX-PDU packet is reassembled in this frame", HFILL }},

        /* fields for h.223-al fragments */
	{ &hf_h223_al_fragment_overlap,
	  { "Fragment overlap",	"h223.al.fragment.overlap", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Fragment overlaps with other fragments", HFILL }},
	
	{ &hf_h223_al_fragment_overlap_conflict,
	  { "Conflicting data in fragment overlap",	"h223.al.fragment.overlap.conflict", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Overlapping fragments contained conflicting data", HFILL }},
	
	{ &hf_h223_al_fragment_multiple_tails,
	  { "Multiple tail fragments found",	"h223.al.fragment.multipletails", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Several tails were found when defragmenting the packet", HFILL }},
	
	{ &hf_h223_al_fragment_too_long_fragment,
	  { "Fragment too long",	"h223.al.fragment.toolongfragment", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "Fragment contained data past end of packet", HFILL }},
	
	{ &hf_h223_al_fragment_error,
	  { "Defragmentation error", "h223.al.fragment.error", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "Defragmentation error due to illegal fragments", HFILL }},
	
	{ &hf_h223_al_fragment,
	  { "H.223 AL-PDU Fragment", "h223.al.fragment", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "H.223 AL-PDU Fragment", HFILL }},
	
	{ &hf_h223_al_fragments,
	  { "H.223 AL-PDU Fragments", "h223.al.fragments", FT_NONE, BASE_NONE, NULL, 0x0,
	    "H.223 AL-PDU Fragments", HFILL }},
	
	{ &hf_h223_al_reassembled_in,
	  { "AL-PDU fragment, reassembled in frame", "h223.al.reassembled_in", FT_FRAMENUM, BASE_NONE, NULL, 0x0,
	    "This H.223 AL-PDU packet is reassembled in this frame", HFILL }},

        /* h223-als */

	{ &hf_h223_al1,
	  { "H.223 AL1", "h223.al1", FT_NONE, BASE_NONE, NULL, 0x0,
	    "H.223 AL-PDU using AL1", HFILL }},

	{ &hf_h223_al1_framed,
	  { "H.223 AL1 framing", "h223.al1.framed", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "", HFILL }},

	{ &hf_h223_al2,
	  { "H.223 AL2", "h223.al2", FT_NONE, BASE_NONE, NULL, 0x0,
	    "H.223 AL-PDU using AL2", HFILL }},

	{ &hf_h223_al2_sequenced,
	  { "H.223 AL2 sequenced", "h223.al2.sequenced", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "", HFILL }},

	{ &hf_h223_al2_seqno,
	  { "Sequence Number", "h223.al2.seqno", FT_UINT8, BASE_DEC, NULL, 0x0,
	    "H.223 AL2 sequence number", HFILL }},

	{ &hf_h223_al2_crc,
	  { "CRC", "h223.al2.crc", FT_UINT8, BASE_HEX, NULL, 0x0,
	    "CRC", HFILL }},

	{ &hf_h223_al2_crc_bad,
	  { "Bad CRC","h223.al2.crc_bad", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	    "", HFILL }},

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

    if (proto_h223 == -1) { /* execute protocol initialization only once */
    proto_h223 =
	proto_register_protocol ("ITU-T Recommendation H.223", "H.223", "h223");

    proto_register_field_array (proto_h223, hf, array_length (hf));
    proto_register_subtree_array (ett, array_length (ett));
    register_dissector("h223", dissect_h223, proto_h223);
	
    /* register our init routine to be called at the start of a capture,
       to clear out our hash tables etc */
    register_init_routine(&h223_init_protocol);
    }

    h245_set_h223_set_mc_handle( &h223_set_mc );
    h245_set_h223_add_lc_handle( &h223_add_lc );
}

void proto_reg_handoff_h223(void)
{
    dissector_handle_t h223 = find_dissector("h223");
    data_handle = find_dissector("data");
    h245dg_handle = find_dissector("h245dg");
    srp_handle = find_dissector("srp");

    dissector_add_handle("tcp.port", h223);
    dissector_add("iax2.dataformat", AST_DATAFORMAT_H223_H245, h223);
}
/* vim:set ts=8 et: */
