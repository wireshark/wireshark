/* stream.h
 *
 * Definititions for handling circuit-switched protocols
 * which are handled as streams, and don't have lengths
 * and IDs such as are required for reassemble.h
 *
 * $Id$
 *
 * Ethereal - Network traffic analyzer
 * By Gerald Combs <gerald@ethereal.com>
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

#ifndef STREAM_H
#define STREAM_H

#include <epan/tvbuff.h>

extern struct _fragment_items;

/* A stream represents the concept of an arbitrary stream of data,
   divided up into frames for transmission, where the frames have
   little or no correspondence to the PDUs of the protocol being
   streamed, and those PDUs are just delineated by a magic number.

   For example, we stream H.223 over IAX2. IAX2 has no concept of
   H.223 PDUs and just divides the H.223 stream into 160-byte
   frames. H.223 PDUs are delineated by two-byte magic numbers (which
   may, of course, straddle an IAX2 frame boundary).

   Essentially we act as a wrapper to reassemble.h, by making up
   PDU ids and keeping some additional data on fragments to allow the
   PDUs to be defragmented again.
*/


/* A stream_t represents a stream. There might be one or two streams
   in a circuit, depending on whether that circuit is mono- or bi-directional.
*/
typedef struct stream stream_t;

/* Fragments in a PDU are represented using a stream_pdu_fragment_t,
   and placed in a linked-list with other fragments in the PDU.

   (They're also placed in a hash so we can find them again later)
*/
typedef struct stream_pdu_fragment stream_pdu_fragment_t;



struct circuit;
struct conversation;

/* initialise a new stream. Call this when you first identify a distinct
 * stream. The circit pointer is just used as a key to look up the stream. */
extern stream_t *stream_new_circ ( const struct circuit *circuit, int p2p_dir );
extern stream_t *stream_new_conv ( const struct conversation *conv, int p2p_dir );

/* retrieve a previously-created stream.
 *
 * Returns null if no matching stream was found.
 */
extern stream_t *find_stream_circ ( const struct circuit *circuit, int p2p_dir );
extern stream_t *find_stream_conv ( const struct conversation *conv, int p2p_dir );



/* see if we've seen this fragment before.
   
   The framenum and offset are just hash keys, so can be any values unique
   to this frame, but the idea is that you use the number of the frame being
   disassembled, and the byte-offset within that frame.
*/
extern stream_pdu_fragment_t *stream_find_frag( stream_t *stream, guint32 framenum, guint32 offset );

/* add a new fragment to the fragment tables for the stream. The framenum and
 * offset are keys allowing future access with stream_find_frag(), tvb is the
 * fragment to be added, and pinfo is the information for the frame containing
 * this fragment. more_frags should be set if this is the final fragment in the
 * PDU.
 *
 * * the fragment must be later in the stream than any previous fragment
 *   (ie, framenum.offset must be greater than those passed on the previous
 *   call)
 *
 * This essentially means that you can only add fragments on the first pass
 * through the stream.
 */
extern stream_pdu_fragment_t *stream_add_frag( stream_t *stream, guint32 framenum, guint32 offset,
					tvbuff_t *tvb, packet_info *pinfo, gboolean more_frags );

/* Get the length of a fragment previously found by stream_find_frag().
 */
extern guint32 stream_get_frag_length( const stream_pdu_fragment_t *frag);

/* Get a handle on the top of the chain of fragment_datas underlying this PDU
 * frag can be any fragment within a PDU, and it will always return the head of
 * the chain
 *
 * Returns NULL until the last fragment is added.
 */
extern struct _fragment_data *stream_get_frag_data( const stream_pdu_fragment_t *frag);

/*
 * Process reassembled data; if this is the last fragment, put the fragment
 * information into the protocol tree, and construct a tvbuff with the
 * reassembled data, otherwise just put a "reassembled in" item into the
 * protocol tree.
 */
extern tvbuff_t *stream_process_reassembled(
    tvbuff_t *tvb, int offset, packet_info *pinfo,
    char *name, const stream_pdu_fragment_t *frag,
    const struct _fragment_items *fit,
    gboolean *update_col_infop, proto_tree *tree);

/* Get the PDU number. PDUs are numbered from zero within a stream.
 * frag can be any fragment within a PDU.
 */
extern guint32 stream_get_pdu_no( const stream_pdu_fragment_t *frag);

/* initialise the stream routines */
void stream_init( void );

#endif /* STREAM_H */
