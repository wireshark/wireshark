/* stream.c
 *
 * Definititions for handling circuit-switched protocols
 * which are handled as streams, and don't have lengths
 * and IDs such as are required for reassemble.h
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
#include <epan/packet.h>
#include <epan/reassemble.h>
#include <epan/stream.h>
#include <epan/tvbuff.h>

/* number of streams to allocate memory for at once */
#define MEMCHUNK_STREAM_COUNT 20

/* ditto pdus */
#define MEMCHUNK_PDU_COUNT 100

/* ditto fragments */
#define MEMCHUNK_FRAGMENT_COUNT 100


typedef struct {
    fragment_data *fd_head;          /* the reassembled data, NULL
				      * until we add the last fragment */
    guint32 pdu_number;		     /* Number of this PDU within the stream */

    /* id of this pdu (globally unique) */
    guint32 id;
} stream_pdu_t;


struct stream_pdu_fragment
{
    guint32 len;	             /* the length of this fragment */
    stream_pdu_t *pdu;
    gboolean final_fragment;
};

struct stream {
    /* the key used to add this stream to stream_hash */
    struct stream_key *key;

    /* pdu to add the next fragment to, or NULL if we need to start
     * a new PDU.
     */
    stream_pdu_t *current_pdu;

    /* number of PDUs added to this stream so far */
    guint32 pdu_counter;

    /* the framenumber and offset of the last fragment added;
       used for sanity-checking */
    guint32 lastfrag_framenum;
    guint32 lastfrag_offset;
};


/*****************************************************************************
 *
 * Stream hash
 */

/* key */
typedef struct stream_key {
    /* streams can be attached to circuits or conversations, and we note
       that here */
    gboolean is_circuit;
    union {
	const struct circuit *circuit;
	const struct conversation *conv;
    } circ;
    int p2p_dir;
} stream_key_t;


/* hash func */
guint stream_hash_func(gconstpointer k)
{
    const stream_key_t *key = (const stream_key_t *)k;

    /* is_circuit is redundant to the circuit/conversation pointer */
    return ((guint)key->circ.circuit) ^ key->p2p_dir;
}

/* compare func */
gboolean stream_compare_func(gconstpointer a,
			     gconstpointer b)
{
    const stream_key_t *key1 = (const stream_key_t *)a;
    const stream_key_t *key2 = (const stream_key_t *)b;
    if( key1 -> p2p_dir != key2 -> p2p_dir ||
	key1-> is_circuit != key2 -> is_circuit )
	return FALSE;
    
    if( key1 -> is_circuit )
	return (key1 -> circ.circuit == key2 -> circ.circuit );
    else
	return (key1 -> circ.conv == key2 -> circ.conv );
}

/* memory pools */
static GMemChunk *stream_keys = NULL;
static GMemChunk *streams = NULL;


/* the hash table */
static GHashTable *stream_hash;


/* init/reset function, call from stream_init() */
static void init_stream_hash( void ) {
    if( stream_hash != NULL ) {
	g_hash_table_destroy( stream_hash );
	stream_hash = NULL;
    }

    if( stream_keys != NULL ) {
	g_mem_chunk_destroy( stream_keys );
	stream_keys = NULL;
    }

    if( streams != NULL ) {
	g_mem_chunk_destroy( streams );
	streams = NULL;
    }

    streams = g_mem_chunk_create(stream_t,
				 MEMCHUNK_STREAM_COUNT,
				 G_ALLOC_ONLY);

    stream_keys = g_mem_chunk_create(stream_key_t,
				     MEMCHUNK_STREAM_COUNT,
				     G_ALLOC_ONLY);

    stream_hash = g_hash_table_new(stream_hash_func,
				   stream_compare_func);
}


/* lookup function, returns null if not found */
static stream_t *stream_hash_lookup_circ( const struct circuit *circuit, int p2p_dir )
{
    stream_key_t key;
    key.is_circuit=TRUE;
    key.circ.circuit=circuit;
    key.p2p_dir=p2p_dir;
    return (stream_t *)g_hash_table_lookup(stream_hash, &key);
}

static stream_t *stream_hash_lookup_conv( const struct conversation *conv, int p2p_dir )
{
    stream_key_t key;
    key.is_circuit=FALSE;
    key.circ.conv = conv;
    key.p2p_dir=p2p_dir;
    return (stream_t *)g_hash_table_lookup(stream_hash, &key);
}


static stream_t *new_stream( stream_key_t *key )
{
    stream_t *val;
    
    val = g_mem_chunk_alloc(streams);
    val -> key = key;
    val -> pdu_counter = 0;
    val -> current_pdu = NULL;
    val -> lastfrag_framenum = 0;
    val -> lastfrag_offset = 0;
    g_hash_table_insert(stream_hash, key, val);

    return val;
}


/* insert function */
static stream_t *stream_hash_insert_circ( const struct circuit *circuit, int p2p_dir )
{
    stream_key_t *key;

    key = g_mem_chunk_alloc(stream_keys);
    key->is_circuit = TRUE;
    key->circ.circuit = circuit;
    key->p2p_dir = p2p_dir;

    return new_stream(key);
}

static stream_t *stream_hash_insert_conv( const struct conversation *conv, int p2p_dir )
{
    stream_key_t *key;

    key = g_mem_chunk_alloc(stream_keys);
    key->is_circuit = FALSE;
    key->circ.conv = conv;
    key->p2p_dir = p2p_dir;

    return new_stream(key);
}


/******************************************************************************
 *
 * PDU data
 */
static GMemChunk *pdus = NULL;

/* pdu counter, for generating unique pdu ids */
static guint32 pdu_counter;


static void stream_init_pdu_data(void)
{
    if( pdus != NULL ) {
	g_mem_chunk_destroy( pdus );
	pdus = NULL;
    }

    pdus = g_mem_chunk_create(stream_pdu_t,
			      MEMCHUNK_PDU_COUNT,
			      G_ALLOC_ONLY);
    pdu_counter = 0;
}


/* new pdu in this stream */
static stream_pdu_t *stream_new_pdu(stream_t *stream)
{
    stream_pdu_t *pdu;
    pdu = g_mem_chunk_alloc(pdus);
    pdu -> fd_head = NULL;
    pdu -> pdu_number = stream -> pdu_counter++;
    pdu -> id = pdu_counter++;
    return pdu;
}

/*****************************************************************************
 *
 * fragment hash
 */

/* key */
typedef struct fragment_key {
    const stream_t *stream;
    guint32 framenum;
    guint32 offset;
} fragment_key_t;


/* hash func */
guint fragment_hash_func(gconstpointer k)
{
    const fragment_key_t *key = (const fragment_key_t *)k;
    return ((guint)key->stream) + ((guint)key -> framenum) + ((guint)key->offset);
}

/* compare func */
gboolean fragment_compare_func(gconstpointer a,
			       gconstpointer b)
{
    const fragment_key_t *key1 = (const fragment_key_t *)a;
    const fragment_key_t *key2 = (const fragment_key_t *)b;
    return (key1 -> stream == key2 -> stream &&
	    key1 -> framenum == key2 -> framenum &&
	    key1 -> offset == key2 -> offset );
}
	    
/* memory pools */
static GMemChunk *fragment_keys = NULL;
static GMemChunk *fragment_vals = NULL;

/* the hash table */
static GHashTable *fragment_hash;


/* init/reset function, call from stream_init() */
static void init_fragment_hash( void ) {
    if( fragment_hash != NULL ) {
	g_hash_table_destroy( fragment_hash );
	fragment_hash = NULL;
    }

    if( fragment_vals != NULL ) {
	g_mem_chunk_destroy( fragment_vals );
	fragment_vals = NULL;
    }

    if( fragment_keys != NULL ) {
	g_mem_chunk_destroy( fragment_keys );
	fragment_keys = NULL;
    }

    fragment_keys = g_mem_chunk_create(fragment_key_t,
				       MEMCHUNK_FRAGMENT_COUNT,
				       G_ALLOC_ONLY);
    
    fragment_vals = g_mem_chunk_create(stream_pdu_fragment_t,
				       MEMCHUNK_FRAGMENT_COUNT,
				       G_ALLOC_ONLY);

    fragment_hash = g_hash_table_new(fragment_hash_func,
				     fragment_compare_func);
}


/* lookup function, returns null if not found */
static stream_pdu_fragment_t *fragment_hash_lookup( const stream_t *stream, guint32 framenum, guint32 offset )
{
    fragment_key_t key;
    stream_pdu_fragment_t *val;

    key.stream = stream;
    key.framenum = framenum;
    key.offset = offset;
    val = g_hash_table_lookup(fragment_hash, &key);

    return val;
}


/* insert function */
static stream_pdu_fragment_t *fragment_hash_insert( const stream_t *stream, guint32 framenum, guint32 offset,
						    guint32 length)
{
    fragment_key_t *key;
    stream_pdu_fragment_t *val;

    key = g_mem_chunk_alloc(fragment_keys);
    key->stream = stream;
    key->framenum = framenum;
    key->offset = offset;

    val = g_mem_chunk_alloc(fragment_vals);
    val->len = length;
    val->pdu = NULL;
    val->final_fragment = FALSE;

    g_hash_table_insert(fragment_hash, key, val);
    return val;
}

/*****************************************************************************/

/* fragmentation hash tables */
static GHashTable *stream_fragment_table = NULL;
static GHashTable *stream_reassembled_table = NULL;

/* Initialise a new stream. Call this when you first identify a distinct
 * stream. */
stream_t *stream_new_circ ( const struct circuit *circuit, int p2p_dir )
{
    stream_t * stream;

    /* we don't want to replace the previous data if we get called twice on the
       same circuit, so do a lookup first */
    stream = stream_hash_lookup_circ(circuit, p2p_dir);
    g_assert( stream == NULL );

    stream = stream_hash_insert_circ(circuit, p2p_dir);
    
    return stream;
}

stream_t *stream_new_conv ( const struct conversation *conv, int p2p_dir )
{
    stream_t * stream;

    /* we don't want to replace the previous data if we get called twice on the
       same conversation, so do a lookup first */
    stream = stream_hash_lookup_conv(conv, p2p_dir);
    g_assert( stream == NULL );

    stream = stream_hash_insert_conv(conv, p2p_dir);
    return stream;
}




/* retrieve a previously-created stream.
 *
 * Returns null if no matching stream was found.
 */
stream_t *find_stream_circ ( const struct circuit *circuit, int p2p_dir )
{
    return stream_hash_lookup_circ(circuit,p2p_dir);
}
stream_t *find_stream_conv ( const struct conversation *conv, int p2p_dir )
{
    return stream_hash_lookup_conv(conv,p2p_dir);
}


/* initialise the stream routines */
void stream_init( void )
{
    init_stream_hash();
    init_fragment_hash();
    stream_init_pdu_data();

    fragment_table_init(&stream_fragment_table);
    reassembled_table_init(&stream_reassembled_table);
}




/*****************************************************************************/

stream_pdu_fragment_t *stream_find_frag( stream_t *stream, guint32 framenum, guint32 offset )
{
    return fragment_hash_lookup( stream, framenum, offset );
}
    
stream_pdu_fragment_t *stream_add_frag( stream_t *stream, guint32 framenum, guint32 offset,
				tvbuff_t *tvb, packet_info *pinfo, gboolean more_frags )
{
    fragment_data *fd_head;
    stream_pdu_t *pdu;
    stream_pdu_fragment_t *frag_data;

    g_assert(stream);

    /* check that this fragment is at the end of the stream */
    g_assert( framenum > stream->lastfrag_framenum ||
	      (framenum == stream->lastfrag_framenum && offset > stream->lastfrag_offset));


    pdu = stream->current_pdu;
    if( pdu == NULL ) {
	/* start a new pdu */
	pdu = stream->current_pdu = stream_new_pdu(stream);
    }
	
    /* add it to the reassembly tables */
    fd_head = fragment_add_seq_next(tvb, 0, pinfo, pdu->id,
				    stream_fragment_table, stream_reassembled_table,
				    tvb_reported_length(tvb), more_frags);
    /* add it to our hash */
    frag_data = fragment_hash_insert( stream, framenum, offset, tvb_reported_length(tvb));
    frag_data -> pdu = pdu;

    if( fd_head != NULL ) {
	/* if this was the last fragment, update the pdu data.
	 */
	pdu -> fd_head = fd_head;
	
	/* start a new pdu next time */
	stream->current_pdu = NULL;

        frag_data -> final_fragment = TRUE;
    }

    /* stashing the framenum and offset permit future sanity checks */
    stream -> lastfrag_framenum = framenum;
    stream -> lastfrag_offset = offset;

    return frag_data;
}


tvbuff_t *stream_process_reassembled(
    tvbuff_t *tvb, int offset, packet_info *pinfo,
    char *name, const stream_pdu_fragment_t *frag,
    const struct _fragment_items *fit,
    gboolean *update_col_infop, proto_tree *tree)
{
    stream_pdu_t *pdu;
    g_assert(frag);
    pdu = frag->pdu;

    /* we handle non-terminal fragments ourselves, because
       reassemble.c messes them up */
    if(!frag->final_fragment) {
        if (pdu->fd_head != NULL && fit->hf_reassembled_in != NULL) {
            proto_tree_add_uint(tree,
                                *(fit->hf_reassembled_in), tvb,
                                0, 0, pdu->fd_head->reassembled_in);
        }
        return NULL;
    }

    return process_reassembled_data(tvb, offset, pinfo, name, pdu->fd_head,
                                    fit, update_col_infop, tree);
}
    
guint32 stream_get_frag_length( const stream_pdu_fragment_t *frag)
{
    g_assert( frag );
    return frag->len;
}

fragment_data *stream_get_frag_data( const stream_pdu_fragment_t *frag)
{
    g_assert( frag );
    return frag->pdu->fd_head;
}

guint32 stream_get_pdu_no( const stream_pdu_fragment_t *frag)
{
    g_assert( frag );
    return frag->pdu->pdu_number;
}
